// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The virtio-fs device (virtio 1.2 section 5.11) that serves one share.
//!
//! [`VirtioFs`] puts an [`AuditFs`] over the fuse-backend-rs passthrough
//! behind boxcar's [`VirtioDevice`] trait:
//!
//! - device type 26; queue 0 is the high-priority queue (Linux sends FORGET
//!   and INTERRUPT there), queues 1 to `num_request_queues` (1 to
//!   [`MAX_REQUEST_QUEUES`], chosen by the VMM as the smaller of the vCPU
//!   count and 4) are the request queues, each at most [`QUEUE_MAX_SIZE`]
//!   entries; Linux spreads requests over them by CPU;
//! - the config space is `tag[36]`, the UTF-8 tag padded with NULs, then
//!   `num_request_queues`, a little-endian u32 at 0x24. It is read-only;
//! - the features are `VIRTIO_F_VERSION_1` and `VIRTIO_RING_F_EVENT_IDX`.
//!   There is no DAX and no shared-memory window, so every read and write
//!   the guest makes goes through FUSE, and so through the audit.
//!
//! Activation checks that every queue is usable, starts the content-hash
//! threads again if a reset stopped them ([`AuditFs::restart_hashing`]),
//! then starts one worker thread per request queue, named `fs-<tag>-q<N>`
//! after the request queue it serves; the first worker also serves the
//! high-priority queue. A
//! worker waits on its queues' eventfds and its kill eventfd with an
//! `EventManager` of its own, drains a queue when the driver kicks it, and
//! interrupts the guest when the driver wants to hear about used buffers.
//!
//! A request that cannot be parsed or answered is logged, at most once a
//! second from each place that logs it ([`boxcar_virtio::limited!`]), and
//! handed back with no reply bytes, and the queue goes on. A queue that
//! cannot be drained at all, because the driver corrupted it, is fatal for
//! that queue: the worker asks the driver for a reset (DEVICE_NEEDS_RESET)
//! and leaves the queue alone until it gets one.
//!
//! [`VirtioDevice::reset`], which runs when the driver writes status 0 and
//! when the VMM stops the VM, stops and joins the workers, waits for the
//! content hashes still being computed, and shuts the [`AuditFs`] down,
//! which records an `fs.close` for every file the guest left open. The VMM
//! must therefore reset the device before it closes the audit writer.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use boxcar_audit::AuditSink;
use boxcar_virtio::features::{EVENT_IDX, VERSION_1};
use boxcar_virtio::{drain_queue, ActivateError, ActivatedQueue, IrqTrigger, VirtioDevice};
use event_manager::{
    EventManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId, SubscriberOps,
};
use fuse_backend_rs::abi::fuse_abi::{InHeader, OutHeader};
use fuse_backend_rs::api::server::{MetricsHook, Server};
use fuse_backend_rs::passthrough::PassthroughFs;
use fuse_backend_rs::transport::{Reader, VirtioFsWriter, Writer};
use tracing::{error, warn};
use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

use crate::audit_fs::{AuditFs, AuditFsOptions};
use crate::share::{passthrough_config, FsShareConfig};

/// The virtio device ID of a file system device.
pub const DEVICE_TYPE: u32 = virtio_bindings::virtio_ids::VIRTIO_ID_FS;
/// The most request queues a device offers, besides the high-priority
/// queue.
pub const MAX_REQUEST_QUEUES: u16 = 4;
/// The largest size of every queue.
pub const QUEUE_MAX_SIZE: u16 = 1024;
/// The length of the config space's `tag` field.
pub const TAG_LEN: usize = 36;
/// The length of the config space: `tag`, then `num_request_queues`.
pub const CONFIG_SIZE: usize = TAG_LEN + 4;

/// The FUSE server over a share. The filesystem is behind an `Arc` so the
/// device keeps a handle on it to flush and shut it down: the server does
/// not give its filesystem back. fuse-backend-rs implements `FileSystem`
/// for `Arc<FS>` by forwarding every method.
pub type FsServer = Server<Arc<AuditFs<PassthroughFs<()>>>>;

/// Why a share cannot be served.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// The tag does not fit the config space, or holds a control character
    /// (Linux refuses a tag with a newline in it).
    #[error("share tag {0:?} must be 1 to 36 bytes of UTF-8 with no control characters")]
    InvalidTag(String),
    /// The passthrough takes its root as a `String`.
    #[error("share directory {} is not valid UTF-8", .0.display())]
    NonUtf8Dir(PathBuf),
    /// The directory does not exist, is not a directory, or cannot be
    /// opened.
    #[error("cannot open share directory {}", path.display())]
    OpenDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The passthrough filesystem could not be created.
    #[error("cannot serve share directory {}", path.display())]
    Passthrough {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The request queue count is 0 or over [`MAX_REQUEST_QUEUES`].
    #[error("{0} request queues: a virtio-fs device has 1 to {MAX_REQUEST_QUEUES}")]
    RequestQueues(u16),
}

/// A virtio-fs device serving one share through [`AuditFs`].
pub struct VirtioFs {
    tag: String,
    /// Request queues, besides the high-priority queue: 1 to
    /// [`MAX_REQUEST_QUEUES`].
    request_queues: u16,
    config: [u8; CONFIG_SIZE],
    fs: Arc<AuditFs<PassthroughFs<()>>>,
    server: Arc<FsServer>,
    metrics: Arc<OpcodeCounts>,
    /// The running workers; `None` when the device is not activated.
    workers: Option<Vec<WorkerHandle>>,
}

impl VirtioFs {
    /// A device serving `share` with `request_queues` request queues (1 to
    /// [`MAX_REQUEST_QUEUES`], one worker thread each), recording into
    /// `sink`.
    ///
    /// The share's directory is opened here (`O_PATH | O_DIRECTORY`) for
    /// the audit to hash closed files beneath; the passthrough itself
    /// imports the directory when the guest mounts it (`FUSE_INIT`).
    pub fn new(
        share: FsShareConfig,
        sink: AuditSink,
        opts: AuditFsOptions,
        request_queues: u16,
    ) -> Result<Self, FsError> {
        if request_queues == 0 || request_queues > MAX_REQUEST_QUEUES {
            return Err(FsError::RequestQueues(request_queues));
        }
        let config = config_space(&share.tag, request_queues)?;
        if share.host_dir.to_str().is_none() {
            return Err(FsError::NonUtf8Dir(share.host_dir));
        }
        let root = open_dir(&share.host_dir).map_err(|source| FsError::OpenDir {
            path: share.host_dir.clone(),
            source,
        })?;
        let inner = PassthroughFs::<()>::new(passthrough_config(&share)).map_err(|source| {
            FsError::Passthrough {
                path: share.host_dir.clone(),
                source,
            }
        })?;
        let fs = Arc::new(AuditFs::new(inner, &share, root, sink, opts));
        let server = Arc::new(Server::new(Arc::clone(&fs)));
        Ok(VirtioFs {
            metrics: Arc::new(OpcodeCounts::new(&share.tag)),
            tag: share.tag,
            request_queues,
            config,
            fs,
            server,
            workers: None,
        })
    }

    /// The share's tag.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The requests the device has seen, by opcode.
    pub fn metrics(&self) -> &OpcodeCounts {
        &self.metrics
    }

    /// Request queues, besides the high-priority queue.
    pub fn request_queues(&self) -> u16 {
        self.request_queues
    }

    /// How many threads hash closed files for the share: 0 after a reset,
    /// until the next activation starts them again.
    pub fn hash_threads(&self) -> usize {
        self.fs.hash_threads()
    }

    /// Answers every request the driver has made available on `queue`, as
    /// a worker does when the queue is kicked, and returns whether the
    /// driver wants an interrupt. An `Err` means the queue is unusable (see
    /// [`drain_queue`]).
    pub fn process_queue(
        &self,
        queue: &mut Queue,
        mem: &GuestMemoryMmap,
    ) -> Result<bool, virtio_queue::Error> {
        serve_queue(&self.server, &self.metrics, &self.tag, queue, mem)
    }
}

impl VirtioDevice for VirtioFs {
    fn device_type(&self) -> u32 {
        DEVICE_TYPE
    }

    fn num_queues(&self) -> usize {
        1 + usize::from(self.request_queues)
    }

    fn queue_max_size(&self, idx: usize) -> u16 {
        if idx < self.num_queues() {
            QUEUE_MAX_SIZE
        } else {
            0
        }
    }

    fn avail_features(&self) -> u64 {
        VERSION_1 | EVENT_IDX
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let Some(rest) = usize::try_from(offset)
            .ok()
            .and_then(|start| self.config.get(start..))
        else {
            return;
        };
        let n = rest.len().min(data.len());
        data[..n].copy_from_slice(&rest[..n]);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        boxcar_virtio::limited!(
            warn,
            tag = %self.tag,
            "virtio-fs: the driver wrote {} bytes at {offset:#x} of the read-only config space; \
             ignored",
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        queues: Vec<ActivatedQueue>,
        irq: Arc<IrqTrigger>,
        _driver_features: u64,
    ) -> Result<(), ActivateError> {
        if self.workers.is_some() {
            return Err(device_error("the device is already active".into()));
        }
        if queues.len() != self.num_queues() {
            return Err(device_error(format!(
                "{} queues handed over for a device with {}",
                queues.len(),
                self.num_queues()
            )));
        }
        // Draining a queue the driver never set up would write to guest
        // address 0.
        if let Some(index) = queues.iter().position(|q| !q.queue.is_valid(&*mem)) {
            return Err(device_error(format!(
                "queue {index} is not ready or does not fit in guest memory"
            )));
        }

        // A reset stopped the hash threads; closes are hashed off the
        // reply path again from this activation on.
        self.fs.restart_hashing();

        // Every worker is prepared before any thread starts, so that a
        // failure leaves nothing running.
        let mut queues = queues.into_iter().enumerate();
        let mut hiprio = queues.next();
        let mut prepared = Vec::with_capacity(usize::from(self.request_queues));
        for (index, queue) in queues {
            let mut served = Vec::with_capacity(2);
            served.extend(hiprio.take());
            served.push((index, queue));
            let name = format!("fs-{}-q{index}", self.tag);
            let worker = Worker {
                tag: self.tag.clone(),
                mem: Arc::clone(&mem),
                server: Arc::clone(&self.server),
                metrics: Arc::clone(&self.metrics),
                irq: Arc::clone(&irq),
                queues: served
                    .into_iter()
                    .map(|(index, q)| ServedQueue {
                        index,
                        queue: q.queue,
                        evt: q.evt,
                        failed: false,
                    })
                    .collect(),
                kill: new_eventfd()?,
                stopped: false,
            };
            prepared.push(PreparedWorker::new(name, worker)?);
        }

        let mut workers = Vec::with_capacity(prepared.len());
        for worker in prepared {
            match worker.spawn() {
                Ok(handle) => workers.push(handle),
                Err(err) => {
                    stop_workers(&self.tag, workers);
                    return Err(ActivateError::Io(err));
                }
            }
        }
        tracing::debug!(tag = %self.tag, "virtio-fs: activated, {} worker(s)", workers.len());
        self.workers = Some(workers);
        Ok(())
    }

    fn reset(&mut self) {
        let Some(workers) = self.workers.take() else {
            return;
        };
        stop_workers(&self.tag, workers);
        self.fs.flush_hashes();
        // The guest's filesystem is gone with the reset: every file it left
        // open gets its fs.close now.
        self.fs.shutdown();
        tracing::debug!(tag = %self.tag, "virtio-fs: reset");
    }
}

impl Drop for VirtioFs {
    fn drop(&mut self) {
        // No worker may outlive the device.
        self.reset();
    }
}

/// The config space for `tag` and `request_queues` request queues.
fn config_space(tag: &str, request_queues: u16) -> Result<[u8; CONFIG_SIZE], FsError> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > TAG_LEN || bytes.iter().any(u8::is_ascii_control) {
        return Err(FsError::InvalidTag(tag.to_owned()));
    }
    let mut config = [0; CONFIG_SIZE];
    config[..bytes.len()].copy_from_slice(bytes);
    config[TAG_LEN..].copy_from_slice(&u32::from(request_queues).to_le_bytes());
    Ok(config)
}

/// Opens `path` as a directory handle for `openat2`, without reading it.
fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    Ok(OwnedFd::from(dir))
}

fn new_eventfd() -> io::Result<EventFd> {
    EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)
}

fn device_error(message: String) -> ActivateError {
    ActivateError::Device(message.into())
}

// Serving a queue.

/// Drains `queue`, answering each request with `server`.
fn serve_queue(
    server: &FsServer,
    metrics: &OpcodeCounts,
    tag: &str,
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
) -> Result<bool, virtio_queue::Error> {
    drain_queue(queue, mem, |chain| {
        Ok::<_, virtio_queue::Error>(handle_request(server, metrics, tag, mem, chain))
    })
}

/// Answers the request in `chain` and returns how many bytes of reply it
/// wrote. A request that cannot be read or answered is logged and gets no
/// reply: that is one request's failure, not the device's.
fn handle_request(
    server: &FsServer,
    metrics: &OpcodeCounts,
    tag: &str,
    mem: &GuestMemoryMmap,
    chain: DescriptorChain<&GuestMemoryMmap>,
) -> u32 {
    let head = chain.head_index();
    let reader = match Reader::from_descriptor_chain(mem, chain.clone()) {
        Ok(reader) => reader,
        Err(err) => {
            boxcar_virtio::limited!(warn, tag, head, "virtio-fs: cannot read the request: {err}");
            return 0;
        }
    };
    let writer: Writer<'_, ()> = match VirtioFsWriter::new(mem, chain) {
        Ok(writer) => writer.into(),
        Err(err) => {
            boxcar_virtio::limited!(
                warn,
                tag,
                head,
                "virtio-fs: cannot use the reply buffer: {err}"
            );
            return 0;
        }
    };
    let hook: &dyn MetricsHook = metrics;
    match server.handle_message(reader, writer, None, Some(hook)) {
        // A reply fits in the chain's writable buffers; only a chain of
        // more than 4 GiB of them could hold a longer one.
        Ok(len) => u32::try_from(len).unwrap_or(u32::MAX),
        Err(err) => {
            boxcar_virtio::limited!(warn, tag, head, "virtio-fs: request not answered: {err}");
            0
        }
    }
}

/// One queue a worker serves.
struct ServedQueue {
    index: usize,
    queue: Queue,
    evt: EventFd,
    /// Draining it failed; it is not served again until the reset.
    failed: bool,
}

/// A worker's state, as the subscriber of its `EventManager`.
struct Worker {
    tag: String,
    mem: Arc<GuestMemoryMmap>,
    server: Arc<FsServer>,
    metrics: Arc<OpcodeCounts>,
    irq: Arc<IrqTrigger>,
    queues: Vec<ServedQueue>,
    kill: EventFd,
    /// The kill eventfd fired.
    stopped: bool,
}

impl Worker {
    fn fds(&self) -> Vec<RawFd> {
        let mut fds = vec![self.kill.as_raw_fd()];
        fds.extend(self.queues.iter().map(|q| q.evt.as_raw_fd()));
        fds
    }
}

impl MutEventSubscriber for Worker {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        let fd = events.fd();
        if fd == self.kill.as_raw_fd() {
            self.stopped = true;
            return;
        }
        if self.stopped {
            return;
        }
        let Some(served) = self.queues.iter_mut().find(|q| q.evt.as_raw_fd() == fd) else {
            return;
        };
        // Epoll is level-triggered: the kick is consumed even when the
        // queue is no longer served.
        if let Err(err) = served.evt.read() {
            if err.kind() != io::ErrorKind::WouldBlock {
                warn!(tag = %self.tag, "virtio-fs: queue {} eventfd: {err}", served.index);
            }
        }
        if served.failed {
            return;
        }
        match serve_queue(
            &self.server,
            &self.metrics,
            &self.tag,
            &mut served.queue,
            &self.mem,
        ) {
            Ok(true) => {
                if let Err(err) = self.irq.signal_used_queue() {
                    error!(tag = %self.tag, "virtio-fs: cannot interrupt the guest: {err}");
                }
            }
            Ok(false) => {}
            Err(err) => {
                error!(
                    tag = %self.tag,
                    "virtio-fs: queue {} cannot be drained: {err}; asking the driver to reset \
                     the device",
                    served.index
                );
                served.failed = true;
                if let Err(err) = self.irq.signal_needs_reset() {
                    error!(tag = %self.tag, "virtio-fs: cannot signal the reset request: {err}");
                }
            }
        }
    }

    /// The fds are registered by [`PreparedWorker::new`], which can report
    /// a failure.
    fn init(&mut self, _ops: &mut EventOps) {}
}

/// A worker whose `EventManager` is set up, and whose thread is not
/// started yet.
struct PreparedWorker {
    name: String,
    manager: EventManager<Worker>,
    id: SubscriberId,
    /// The device's end of the kill eventfd.
    kill: EventFd,
    irq: Arc<IrqTrigger>,
    tag: String,
}

impl PreparedWorker {
    fn new(name: String, worker: Worker) -> Result<Self, ActivateError> {
        let kill = worker.kill.try_clone()?;
        let irq = Arc::clone(&worker.irq);
        let tag = worker.tag.clone();
        let fds = worker.fds();
        let mut manager = EventManager::new().map_err(|e| ActivateError::Device(e.into()))?;
        let id = manager.add_subscriber(worker);
        let mut ops = manager
            .event_ops(id)
            .map_err(|e| ActivateError::Device(e.into()))?;
        for fd in fds {
            ops.add(Events::new_raw(fd, EventSet::IN))
                .map_err(|e| ActivateError::Device(e.into()))?;
        }
        Ok(PreparedWorker {
            name,
            manager,
            id,
            kill,
            irq,
            tag,
        })
    }

    fn spawn(self) -> io::Result<WorkerHandle> {
        let PreparedWorker {
            name,
            manager,
            id,
            kill,
            irq,
            tag,
        } = self;
        let thread = thread::Builder::new()
            .name(name.clone())
            .spawn(move || run_worker(manager, id, &irq, &tag))?;
        Ok(WorkerHandle { name, kill, thread })
    }
}

/// A worker thread: dispatches events until the kill eventfd fires.
fn run_worker(mut manager: EventManager<Worker>, id: SubscriberId, irq: &IrqTrigger, tag: &str) {
    let _panic = PanicGuard { irq, tag };
    loop {
        if let Err(err) = manager.run() {
            error!(
                tag,
                "virtio-fs: the worker cannot wait for events: {err}; asking the driver to \
                 reset the device"
            );
            if let Err(err) = irq.signal_needs_reset() {
                error!(tag, "virtio-fs: cannot signal the reset request: {err}");
            }
            return;
        }
        match manager.subscriber_mut(id) {
            Ok(worker) if !worker.stopped => {}
            _ => return,
        }
    }
}

/// Asks the driver for a reset when the worker thread panics, so the guest
/// learns that its queues are no longer served.
struct PanicGuard<'a> {
    irq: &'a IrqTrigger,
    tag: &'a str,
}

impl Drop for PanicGuard<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            error!(
                tag = self.tag,
                "virtio-fs: a worker panicked; asking the driver to reset the device"
            );
            if let Err(err) = self.irq.signal_needs_reset() {
                error!(
                    tag = self.tag,
                    "virtio-fs: cannot signal the reset request: {err}"
                );
            }
        }
    }
}

/// A running worker.
struct WorkerHandle {
    name: String,
    kill: EventFd,
    thread: JoinHandle<()>,
}

/// Stops every worker, then joins them. After this nothing touches guest
/// memory or raises an interrupt for the device.
fn stop_workers(tag: &str, workers: Vec<WorkerHandle>) {
    for worker in &workers {
        // A fresh eventfd written once cannot overflow, so this does not
        // fail and the join below returns.
        if let Err(err) = worker.kill.write(1) {
            error!(tag, "virtio-fs: cannot stop worker {}: {err}", worker.name);
        }
    }
    for worker in workers {
        if worker.thread.join().is_err() {
            error!(tag, "virtio-fs: worker {} panicked", worker.name);
        }
    }
}

// Counting opcodes.

/// Opcodes below this have a counter of their own; the rest share one.
const OPCODE_SLOTS: usize = 64;

/// The FUSE opcodes whose `AuditFs` methods record or track something:
/// every method the decorator writes out, rather than forwards (see
/// `audit_fs`). The server maps `RENAME2` to `rename`.
pub const AUDITED_OPCODES: [u32; 25] = [
    1,  // LOOKUP
    2,  // FORGET
    4,  // SETATTR
    6,  // SYMLINK
    8,  // MKNOD
    9,  // MKDIR
    10, // UNLINK
    11, // RMDIR
    12, // RENAME
    13, // LINK
    14, // OPEN
    15, // READ
    16, // WRITE
    18, // RELEASE
    21, // SETXATTR
    24, // REMOVEXATTR
    26, // INIT
    28, // READDIR
    34, // ACCESS
    35, // CREATE
    38, // DESTROY
    42, // BATCH_FORGET
    43, // FALLOCATE
    44, // READDIRPLUS
    45, // RENAME2
];

/// The FUSE opcodes `AuditFs` forwards without recording, deliberately:
/// they read (attributes, links, extended attributes, directory handles,
/// offsets) or carry no state the audit tracks (flushes, syncs, interrupts,
/// and the ioctl and poll the passthrough refuses). `SYNCFS` comes with
/// every `sync()` in the guest, init's before it reboots too; fuse-backend-rs
/// 0.14.0 has no `Opcode` for it and answers `ENOSYS` without reaching the
/// filesystem. With [`AUDITED_OPCODES`] these make up the opcodes the audit
/// models.
pub const UNRECORDED_OPCODES: [u32; 15] = [
    3,  // GETATTR
    5,  // READLINK
    17, // STATFS
    20, // FSYNC
    22, // GETXATTR
    23, // LISTXATTR
    25, // FLUSH
    27, // OPENDIR
    29, // RELEASEDIR
    30, // FSYNCDIR
    36, // INTERRUPT
    39, // IOCTL
    40, // POLL
    46, // LSEEK
    50, // SYNCFS
];

/// Whether the audit models `opcode`: records it ([`AUDITED_OPCODES`]) or
/// deliberately leaves it out ([`UNRECORDED_OPCODES`]).
fn is_modelled(opcode: u32) -> bool {
    AUDITED_OPCODES.contains(&opcode) || UNRECORDED_OPCODES.contains(&opcode)
}

/// Counts the requests a device sees by opcode, as the server's
/// [`MetricsHook`], and logs a warning the first time the guest uses an
/// opcode the audit does not model: one in neither [`AUDITED_OPCODES`] nor
/// [`UNRECORDED_OPCODES`]. Opcodes from 64 up are counted, and warned
/// about, together.
pub struct OpcodeCounts {
    tag: String,
    counts: [AtomicU64; OPCODE_SLOTS + 1],
    warned: [AtomicBool; OPCODE_SLOTS + 1],
}

impl OpcodeCounts {
    /// No requests seen yet, for the share `tag`.
    pub fn new(tag: &str) -> Self {
        OpcodeCounts {
            tag: tag.to_owned(),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            warned: std::array::from_fn(|_| AtomicBool::new(false)),
        }
    }

    /// Requests seen with `opcode`. From 64 up, every such opcode's count
    /// is the same shared count.
    pub fn count(&self, opcode: u32) -> u64 {
        self.counts[slot(opcode)].load(Ordering::Relaxed)
    }

    /// Counts one request with `opcode`. Returns whether it is to be
    /// logged: the first time an opcode the audit does not model is seen.
    fn note(&self, opcode: u32) -> bool {
        let slot = slot(opcode);
        self.counts[slot].fetch_add(1, Ordering::Relaxed);
        !is_modelled(opcode) && !self.warned[slot].swap(true, Ordering::Relaxed)
    }
}

impl MetricsHook for OpcodeCounts {
    fn collect(&self, ih: &InHeader) {
        if self.note(ih.opcode) {
            warn!(
                tag = %self.tag,
                "virtio-fs: the guest sent FUSE_{} ({}), which the audit does not model; \
                 further requests of this kind are only counted",
                opcode_name(ih.opcode),
                ih.opcode
            );
        }
    }

    /// fuse-backend-rs 0.14.0 always passes `None`: there is nothing to
    /// count.
    fn release(&self, _oh: Option<&OutHeader>) {}
}

fn slot(opcode: u32) -> usize {
    usize::try_from(opcode)
        .ok()
        .filter(|&n| n < OPCODE_SLOTS)
        .unwrap_or(OPCODE_SLOTS)
}

/// The name of a FUSE opcode, as in `linux/fuse.h` without `FUSE_`.
fn opcode_name(opcode: u32) -> &'static str {
    match opcode {
        1 => "LOOKUP",
        2 => "FORGET",
        3 => "GETATTR",
        4 => "SETATTR",
        5 => "READLINK",
        6 => "SYMLINK",
        8 => "MKNOD",
        9 => "MKDIR",
        10 => "UNLINK",
        11 => "RMDIR",
        12 => "RENAME",
        13 => "LINK",
        14 => "OPEN",
        15 => "READ",
        16 => "WRITE",
        17 => "STATFS",
        18 => "RELEASE",
        20 => "FSYNC",
        21 => "SETXATTR",
        22 => "GETXATTR",
        23 => "LISTXATTR",
        24 => "REMOVEXATTR",
        25 => "FLUSH",
        26 => "INIT",
        27 => "OPENDIR",
        28 => "READDIR",
        29 => "RELEASEDIR",
        30 => "FSYNCDIR",
        31 => "GETLK",
        32 => "SETLK",
        33 => "SETLKW",
        34 => "ACCESS",
        35 => "CREATE",
        36 => "INTERRUPT",
        37 => "BMAP",
        38 => "DESTROY",
        39 => "IOCTL",
        40 => "POLL",
        41 => "NOTIFY_REPLY",
        42 => "BATCH_FORGET",
        43 => "FALLOCATE",
        44 => "READDIRPLUS",
        45 => "RENAME2",
        46 => "LSEEK",
        47 => "COPY_FILE_RANGE",
        48 => "SETUPMAPPING",
        49 => "REMOVEMAPPING",
        50 => "SYNCFS",
        51 => "TMPFILE",
        52 => "STATX",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOKUP: u32 = 1;
    const GETATTR: u32 = 3;
    const OPEN: u32 = 14;
    const FLUSH: u32 = 25;
    const GETLK: u32 = 31;
    const COPY_FILE_RANGE: u32 = 47;

    #[test]
    fn every_opcode_is_counted_and_each_unmodelled_one_logged_once() {
        let counts = OpcodeCounts::new("root");
        assert!(!counts.note(LOOKUP), "lookups are audited");
        assert!(!counts.note(LOOKUP));
        assert!(!counts.note(GETATTR), "getattr is read-only: never logged");
        assert!(!counts.note(FLUSH), "flush is state-free: never logged");
        assert!(counts.note(GETLK), "the first getlk is logged");
        assert!(!counts.note(GETLK), "and only the first");
        assert!(counts.note(COPY_FILE_RANGE), "each opcode once");
        assert_eq!(counts.count(LOOKUP), 2);
        assert_eq!(counts.count(GETATTR), 1);
        assert_eq!(counts.count(FLUSH), 1);
        assert_eq!(counts.count(GETLK), 2);
        assert_eq!(counts.count(COPY_FILE_RANGE), 1);
        assert_eq!(counts.count(OPEN), 0);

        // Opcodes from 64 up share one counter and one warning.
        assert!(counts.note(4096));
        assert!(!counts.note(u32::MAX));
        assert_eq!(counts.count(64), 2);
        assert_eq!(counts.count(4096), 2);

        // The server calls it through the hook.
        let header = InHeader {
            opcode: OPEN,
            ..InHeader::default()
        };
        counts.collect(&header);
        counts.release(None);
        assert_eq!(counts.count(OPEN), 1);
    }

    #[test]
    fn the_unrecorded_opcodes_are_the_read_only_and_state_free_ones() {
        let names: Vec<&str> = UNRECORDED_OPCODES
            .iter()
            .map(|&op| opcode_name(op))
            .collect();
        assert_eq!(
            names,
            [
                "GETATTR",
                "READLINK",
                "STATFS",
                "FSYNC",
                "GETXATTR",
                "LISTXATTR",
                "FLUSH",
                "OPENDIR",
                "RELEASEDIR",
                "FSYNCDIR",
                "INTERRUPT",
                "IOCTL",
                "POLL",
                "LSEEK",
                "SYNCFS",
            ]
        );
        for op in UNRECORDED_OPCODES {
            assert!(
                !AUDITED_OPCODES.contains(&op),
                "{} is in both",
                opcode_name(op)
            );
        }
    }

    /// What a shell session can still be warned about: locks, mappings,
    /// server-side copies and whatever `linux/fuse.h` adds, which the audit
    /// would have to model before they go quiet.
    #[test]
    fn the_rest_is_still_logged() {
        let logged: Vec<u32> = (1..=52).filter(|&op| !is_modelled(op)).collect();
        assert_eq!(
            logged,
            [7, 19, 31, 32, 33, 37, 41, 47, 48, 49, 51, 52],
            "{:?}",
            logged.iter().map(|&op| opcode_name(op)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_audited_opcodes_have_their_names() {
        let names: Vec<&str> = AUDITED_OPCODES.iter().map(|&op| opcode_name(op)).collect();
        assert_eq!(
            names,
            [
                "LOOKUP",
                "FORGET",
                "SETATTR",
                "SYMLINK",
                "MKNOD",
                "MKDIR",
                "UNLINK",
                "RMDIR",
                "RENAME",
                "LINK",
                "OPEN",
                "READ",
                "WRITE",
                "RELEASE",
                "SETXATTR",
                "REMOVEXATTR",
                "INIT",
                "READDIR",
                "ACCESS",
                "CREATE",
                "DESTROY",
                "BATCH_FORGET",
                "FALLOCATE",
                "READDIRPLUS",
                "RENAME2",
            ]
        );
        assert_eq!(opcode_name(7), "UNKNOWN");
        assert!(!AUDITED_OPCODES.contains(&GETATTR));
    }

    #[test]
    fn the_config_space_is_the_padded_tag_and_the_queue_count() {
        let config = config_space("root", 1).unwrap();
        assert_eq!(&config[..4], b"root");
        assert!(config[4..TAG_LEN].iter().all(|&b| b == 0));
        assert_eq!(config[TAG_LEN..], 1u32.to_le_bytes());
        let four = config_space("root", 4).unwrap();
        assert_eq!(four[TAG_LEN..], 4u32.to_le_bytes());

        for bad in ["", "a\nb", "a\0b", &"x".repeat(37)] {
            assert!(
                matches!(config_space(bad, 1), Err(FsError::InvalidTag(_))),
                "{bad:?}"
            );
        }
        // 36 bytes of UTF-8, fewer characters.
        let tag = "é".repeat(18);
        assert_eq!(&config_space(&tag, 1).unwrap()[..TAG_LEN], tag.as_bytes());
    }
}
