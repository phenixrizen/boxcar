// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The virtio-vsock device (virtio 1.2 section 5.10) in front of a
//! [`VsockMuxer`].
//!
//! [`VirtioVsock`] is the guest's vsock device:
//!
//! - device type 19; queue 0 receives ([`RX_QUEUE`]), queue 1 transmits
//!   ([`TX_QUEUE`]) and queue 2 carries events ([`EVT_QUEUE`]), each at
//!   most [`QUEUE_MAX_SIZE`] entries;
//! - the features are `VIRTIO_F_VERSION_1` and `VIRTIO_RING_F_EVENT_IDX`
//!   and no others: stream sockets only, no `VIRTIO_VSOCK_F_SEQPACKET`;
//! - the config space is the guest's CID, a little-endian u64 (8 bytes,
//!   read-only); reads past it give zeros.
//!
//! [`VirtioVsock::new`] binds the host socket at [`VsockConfig::uds_path`]
//! (mode 0600, see [`bind_listener`]), where host processes reach guest
//! ports, and keeps it for the device's life: each activation's muxer
//! accepts on it. [`VirtioVsock::close_socket`], and dropping the device,
//! unlink it.
//!
//! # The vsock thread
//!
//! Activation builds a [`VsockMuxer`] and starts one thread, `vsock`,
//! which owns it. It waits with one level-triggered `EventManager` on the
//! three queues' eventfds, a kill eventfd, and the muxer's own epoll (which
//! watches the host socket and every connection's host end). Each wakeup,
//! in this order:
//!
//! 1. if the muxer's epoll is ready, the muxer handles its events: new host
//!    connections, `CONNECT` lines, data and hang-ups on host ends;
//! 2. if the driver kicked TX, every chain on the TX queue becomes a
//!    packet ([`VsockPacket::from_tx_virtq_chain`]) for the muxer
//!    (`send_pkt`), and goes back to the used ring with nothing written;
//! 3. while the muxer has packets for the guest and the RX queue a free
//!    chain, each chain gets one ([`VsockPacket::from_rx_virtq_chain`],
//!    `recv_pkt`) and goes back to the used ring with the header's and the
//!    data's length;
//! 4. the guest is interrupted if either queue's driver wants to hear of
//!    the buffers used.
//!
//! When the muxer still has packets for the guest after step 3 (no RX chain
//! is free, or the RX queue failed), the thread stops watching the muxer's
//! epoll until the driver kicks RX, which the device asked it to: a host end
//! with data waiting stays readable, and level-triggered readiness would
//! otherwise wake the thread at once, again and again, with nothing it
//! could do. The host ends wait meanwhile; vsock's flow control keeps the
//! guest from sending more than the device can buffer.
//!
//! The kicks of the event queue are taken and its buffers left alone: the
//! device sends no events. (The only one, a transport reset, is for live
//! migration.)
//!
//! A chain that does not hold a packet is used empty, and the queue goes
//! on. A ring the driver corrupted is fatal for its queue: the device asks
//! for a reset (DEVICE_NEEDS_RESET) and leaves the queue alone until it
//! gets one.
//!
//! [`VirtioDevice::reset`], on the driver's status-0 write and when the VMM
//! stops the VM, sets the thread's stop flag and fires the kill eventfd.
//! The thread then removes every connection, recording `vsock.close` for
//! each one a `vsock.connect` let through, drops the muxer, which closes the
//! host ends, and exits; the reset waits for it at most [`JOIN_LIMIT`]. A
//! thread that has not stopped by then (its records wait on a log that does
//! not drain) is left behind with a warning, and the stop flag keeps it from
//! the rings and the interrupt.

use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boxcar_audit::AuditSink;
use boxcar_virtio::features::{EVENT_IDX, VERSION_1};
use boxcar_virtio::{ActivateError, ActivatedQueue, IrqTrigger, VirtioDevice};
use event_manager::{
    EventManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId, SubscriberOps,
};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use virtio_vsock::packet::PKT_HEADER_SIZE;
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

use crate::defs::MAX_PKT_BUF_SIZE;
use crate::packet_ext::VsockPacket;
use crate::services::InternalServices;
use crate::unix::{bind_listener, VsockMuxer, VsockUnixError};
use crate::{VsockChannel, VsockEpollListener};

/// The virtio device ID of a vsock device.
pub const DEVICE_TYPE: u32 = virtio_bindings::virtio_ids::VIRTIO_ID_VSOCK;
/// The queue the guest receives packets on.
pub const RX_QUEUE: usize = 0;
/// The queue the guest transmits packets on.
pub const TX_QUEUE: usize = 1;
/// The queue the device would send events on.
pub const EVT_QUEUE: usize = 2;
/// The device's queues: RX, TX and events.
pub const NUM_QUEUES: usize = 3;
/// The largest size of each queue.
pub const QUEUE_MAX_SIZE: u16 = 256;
/// The guest's CID unless configured: the first one a guest may have.
pub const GUEST_CID: u64 = 3;
/// The config space: the guest's CID, a little-endian u64.
pub const CONFIG_LEN: usize = 8;
/// How long [`VirtioDevice::reset`] waits for the vsock thread to stop.
pub const JOIN_LIMIT: Duration = Duration::from_secs(5);

/// The largest packet payload either way, as a descriptor length.
const MAX_DATA_SIZE: u32 = MAX_PKT_BUF_SIZE as u32;

/// The guest's vsock address and what its connections may reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VsockConfig {
    /// The guest's CID: 3 or more, below 2^32 (the upper half of the
    /// config field is reserved).
    pub guest_cid: u64,
    /// The host socket: host processes connect here and send `CONNECT
    /// <port>\n` to reach a guest port, and a guest connection to an
    /// allowlisted port reaches `<uds_path>_<port>`.
    pub uds_path: PathBuf,
    /// The host ports, other than the internal ones, a guest connection
    /// may reach.
    pub allow_ports: Vec<u32>,
}

impl VsockConfig {
    /// The guest at [`GUEST_CID`], the host socket at `uds_path`, and no
    /// port allowlisted.
    pub fn new(uds_path: impl Into<PathBuf>) -> VsockConfig {
        VsockConfig {
            guest_cid: GUEST_CID,
            uds_path: uds_path.into(),
            allow_ports: Vec::new(),
        }
    }
}

/// Why the device could not be created.
#[derive(Debug, thiserror::Error)]
pub enum VsockDeviceError {
    /// The CID is reserved (0 to 2) or does not fit in 32 bits.
    #[error("guest CID {0} is not 3 or more and below 2^32")]
    Cid(u64),
    /// The host socket could not be bound.
    #[error("cannot bind the vsock socket {}", path.display())]
    Listener {
        path: PathBuf,
        #[source]
        source: VsockUnixError,
    },
}

/// The guest's vsock device, in front of a [`VsockMuxer`].
pub struct VirtioVsock {
    cfg: VsockConfig,
    /// The host socket, bound by `new`; each activation's muxer accepts on
    /// a clone of it.
    listener: UnixListener,
    /// Whether the socket's path was unlinked.
    unlinked: bool,
    services: Arc<dyn InternalServices>,
    audit: AuditSink,
    /// The vsock thread; `None` when the device is not activated.
    worker: Option<WorkerHandle>,
}

impl VirtioVsock {
    /// A device for the guest at `cfg.guest_cid`, whose muxer serves the
    /// internal ports through `services` and records into `audit`. The host
    /// socket is bound here.
    pub fn new(
        cfg: VsockConfig,
        services: Arc<dyn InternalServices>,
        audit: AuditSink,
    ) -> Result<VirtioVsock, VsockDeviceError> {
        if cfg.guest_cid < GUEST_CID || cfg.guest_cid > u64::from(u32::MAX) {
            return Err(VsockDeviceError::Cid(cfg.guest_cid));
        }
        let listener =
            bind_listener(&cfg.uds_path).map_err(|source| VsockDeviceError::Listener {
                path: cfg.uds_path.clone(),
                source,
            })?;
        Ok(VirtioVsock {
            cfg,
            listener,
            unlinked: false,
            services,
            audit,
            worker: None,
        })
    }

    /// The host socket's path.
    pub fn uds_path(&self) -> &Path {
        &self.cfg.uds_path
    }

    /// Unlinks the host socket, so that no host process can connect any
    /// more. Connections already made are the reset's to close. The VMM
    /// calls it as it stops, after the reset; dropping the device does it
    /// too.
    pub fn close_socket(&mut self) {
        if mem::replace(&mut self.unlinked, true) {
            return;
        }
        match fs::remove_file(&self.cfg.uds_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                "vsock: cannot remove {}: {error}",
                self.cfg.uds_path.display()
            ),
        }
    }
}

impl VirtioDevice for VirtioVsock {
    fn device_type(&self) -> u32 {
        DEVICE_TYPE
    }

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn queue_max_size(&self, idx: usize) -> u16 {
        if idx < NUM_QUEUES {
            QUEUE_MAX_SIZE
        } else {
            0
        }
    }

    fn avail_features(&self) -> u64 {
        VERSION_1 | EVENT_IDX
    }

    /// The CID, little-endian, and zeros past it.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        let config = self.cfg.guest_cid.to_le_bytes();
        let Some(rest) = usize::try_from(offset)
            .ok()
            .and_then(|start| config.get(start..))
        else {
            return;
        };
        let n = rest.len().min(data.len());
        data[..n].copy_from_slice(&rest[..n]);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        boxcar_virtio::limited!(
            warn,
            "virtio-vsock: the driver wrote {} bytes at {offset:#x} of the read-only config \
             space; ignored",
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
        if self.worker.is_some() {
            return Err(device_error("the device is already active".into()));
        }
        if queues.len() != NUM_QUEUES {
            return Err(device_error(format!(
                "{} queues handed over for a device with {NUM_QUEUES}",
                queues.len()
            )));
        }
        // Serving a queue the driver never set up would write to guest
        // address 0. The event queue is never served.
        for index in [RX_QUEUE, TX_QUEUE] {
            if !queues[index].queue.is_valid(&*mem) {
                return Err(device_error(format!(
                    "queue {index} is not ready or does not fit in guest memory"
                )));
            }
        }
        let mut queues = queues.into_iter();
        let (Some(rx), Some(tx), Some(evq)) = (queues.next(), queues.next(), queues.next()) else {
            return Err(device_error("the queues went missing".into()));
        };
        let muxer = VsockMuxer::new(
            &self.cfg,
            self.listener.try_clone()?,
            Arc::clone(&self.services),
            self.audit.clone(),
        )
        .map_err(|error| ActivateError::Device(error.into()))?;
        let worker = Worker {
            mem,
            irq,
            muxer,
            rx: Ring::new(RX_QUEUE, rx),
            tx: Ring::new(TX_QUEUE, tx),
            evq: evq.evt,
            kill: EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)?,
            stop: StopFlag::default(),
            muxer_watched: true,
        };
        self.worker = Some(spawn(worker)?);
        Ok(())
    }

    fn reset(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.stop();
        }
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        // No thread may outlive the device, nor its socket the VMM.
        self.reset();
        self.close_socket();
    }
}

fn device_error(message: String) -> ActivateError {
    ActivateError::Device(message.into())
}

// Moving packets.

/// Hands every chain the driver made available on the TX `queue` to
/// `muxer` as a packet, and returns each to the used ring with nothing
/// written. Returns whether the driver wants an interrupt.
///
/// It drains as `boxcar_virtio::drain_queue` does (notifications off while
/// it pops, then on again, and a chain offered meanwhile is taken), but
/// checks `stop` before every write to the ring: handing a packet to the
/// muxer can wait on the audit log, and a reset may come meanwhile. Once
/// `stop` is set it returns at once, touching the ring no more.
///
/// An `Err` means the ring is unusable: it announces chains that cannot be
/// popped, or its used ring or notification fields cannot be written.
fn transmit(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    muxer: &mut VsockMuxer,
    stop: &StopFlag,
) -> Result<bool, virtio_queue::Error> {
    // Consecutive passes that popped nothing though the ring said there was
    // more: once is a race with the driver, twice a broken ring.
    let mut idle_passes = 0;
    loop {
        if stop.is_set() {
            return Ok(false);
        }
        queue.disable_notification(mem)?;
        let mut used_any = false;
        loop {
            if stop.is_set() {
                return Ok(false);
            }
            let Some(mut chain) = queue.pop_descriptor_chain(mem) else {
                break;
            };
            let head = chain.head_index();
            match VsockPacket::from_tx_virtq_chain(mem, &mut chain, MAX_DATA_SIZE) {
                Ok(pkt) => {
                    if let Err(error) = muxer.send_pkt(&pkt) {
                        boxcar_virtio::limited!(
                            warn,
                            "virtio-vsock: a packet the guest sent was not taken: {error}"
                        );
                    }
                }
                Err(error) => boxcar_virtio::limited!(
                    warn,
                    "virtio-vsock: cannot read a packet the guest sent: {error}; dropped"
                ),
            }
            if stop.is_set() {
                return Ok(false);
            }
            queue.add_used(mem, head, 0)?;
            used_any = true;
        }
        if stop.is_set() {
            return Ok(false);
        }
        if !queue.enable_notification(mem)? {
            break;
        }
        idle_passes = if used_any { 0 } else { idle_passes + 1 };
        if idle_passes == 2 {
            return Err(virtio_queue::Error::InvalidAvailRingIndex);
        }
    }
    queue.needs_notification(mem)
}

/// Gives the guest the packets `muxer` has for it, one a chain, for as long
/// as there are both packets and chains on the RX `queue`. With packets left
/// and no chain, the driver is asked to notify the queue when it adds a
/// buffer. Returns how many chains were used, including any given back
/// empty because they held no packet. Once `stop` is set it touches the
/// ring no more. An `Err` means the ring is unusable: it announces chains
/// that cannot be popped, or its used ring cannot be written.
fn deliver(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    muxer: &mut VsockMuxer,
    stop: &StopFlag,
) -> Result<usize, virtio_queue::Error> {
    let mut used = 0;
    // Consecutive times the ring announced a buffer that could not be
    // popped: once is a race with the driver, twice a broken ring.
    let mut idle = 0;
    while !stop.is_set() && muxer.has_pending_rx() {
        let Some(mut chain) = queue.pop_descriptor_chain(mem) else {
            // Re-enabling notifications reports a buffer added since the
            // pop; take it now, as no kick may come for it.
            if !queue.enable_notification(mem)? {
                break;
            }
            idle += 1;
            if idle == 2 {
                return Err(virtio_queue::Error::InvalidAvailRingIndex);
            }
            continue;
        };
        idle = 0;
        let head = chain.head_index();
        let len = match VsockPacket::from_rx_virtq_chain(mem, &mut chain, MAX_DATA_SIZE) {
            Ok(mut pkt) => match muxer.recv_pkt(&mut pkt) {
                // The header, and as much data as the packet says.
                Ok(()) => PKT_HEADER_SIZE as u32 + pkt.len(),
                Err(_) => {
                    // Nothing after all: the chain goes back for the next
                    // packet.
                    queue.go_to_previous_position();
                    break;
                }
            },
            Err(error) => {
                boxcar_virtio::limited!(
                    warn,
                    "virtio-vsock: cannot use an RX buffer: {error}; it is returned empty"
                );
                0
            }
        };
        if stop.is_set() {
            break;
        }
        queue.add_used(mem, head, len)?;
        used += 1;
    }
    Ok(used)
}

// The vsock thread.

/// A queue the thread serves.
struct Ring {
    index: usize,
    queue: Queue,
    evt: EventFd,
    /// Serving it failed; it is left alone until the reset.
    failed: bool,
}

impl Ring {
    fn new(index: usize, activated: ActivatedQueue) -> Ring {
        Ring {
            index,
            queue: activated.queue,
            evt: activated.evt,
            failed: false,
        }
    }

    /// Stops serving the queue after `error`, and asks the driver for a
    /// reset, unless the device is being reset already (`stop`).
    fn fail(&mut self, irq: &IrqTrigger, stop: &StopFlag, error: virtio_queue::Error) {
        boxcar_virtio::limited!(
            error,
            "virtio-vsock: queue {} cannot be served: {error}; asking the driver to reset the \
             device",
            self.index
        );
        self.failed = true;
        if stop.is_set() {
            return;
        }
        if let Err(error) = irq.signal_needs_reset() {
            boxcar_virtio::limited!(
                error,
                "virtio-vsock: cannot signal the reset request: {error}"
            );
        }
    }
}

/// Takes a kick from `evt`, if there is one.
fn take_kick(evt: &EventFd, index: usize) {
    if let Err(error) = evt.read() {
        if error.kind() != io::ErrorKind::WouldBlock {
            boxcar_virtio::limited!(warn, "virtio-vsock: queue {index} eventfd: {error}");
        }
    }
}

/// Set by [`VirtioDevice::reset`] before it waits for the vsock thread.
/// From then on the thread writes to neither ring and raises no interrupt:
/// the queues and the interrupt are the driver's again, whether or not the
/// reset waited long enough to join the thread.
#[derive(Clone, Debug, Default)]
struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What one wait found. The `EventManager` hands each ready fd to this,
/// and the worker takes them in its order once the wait is over.
#[derive(Default)]
struct Ready(Vec<RawFd>);

impl MutEventSubscriber for Ready {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        self.0.push(events.fd());
    }

    /// The fds are registered by [`spawn`] and by the worker.
    fn init(&mut self, _ops: &mut EventOps) {}
}

/// The vsock thread's state.
struct Worker {
    mem: Arc<GuestMemoryMmap>,
    irq: Arc<IrqTrigger>,
    muxer: VsockMuxer,
    rx: Ring,
    tx: Ring,
    /// The event queue's kick: taken, and nothing more.
    evq: EventFd,
    kill: EventFd,
    /// Set when the device is reset: see [`StopFlag`].
    stop: StopFlag,
    /// Whether the muxer's epoll is watched: not while the muxer has
    /// packets for the guest and the guest no room for them.
    muxer_watched: bool,
}

impl Worker {
    /// Handles what one wait found. Returns `false` when the device is
    /// being reset (the kill eventfd fired, or the stop flag is set) and
    /// the thread is to stop.
    fn wakeup(
        &mut self,
        manager: &mut EventManager<Ready>,
        id: SubscriberId,
        ready: &[RawFd],
    ) -> bool {
        if self.stop.is_set() || ready.contains(&self.kill.as_raw_fd()) {
            return false;
        }
        let mut tx_kicked = false;
        let mut rx_kicked = false;
        let mut muxer_ready = false;
        for &fd in ready {
            if fd == self.tx.evt.as_raw_fd() {
                take_kick(&self.tx.evt, TX_QUEUE);
                tx_kicked = true;
            } else if fd == self.rx.evt.as_raw_fd() {
                take_kick(&self.rx.evt, RX_QUEUE);
                rx_kicked = true;
            } else if fd == self.evq.as_raw_fd() {
                take_kick(&self.evq, EVT_QUEUE);
            } else if fd == self.muxer.get_polled_fd() {
                muxer_ready = true;
            }
        }
        if muxer_ready {
            self.muxer.notify(EventSet::IN);
        }
        self.cycle(manager, id, tx_kicked, rx_kicked)
    }

    /// Steps 2 to 4 of the module docs, then watches the muxer's epoll or
    /// not. Returns `false`, having stopped short, when the stop flag was
    /// set meanwhile: handing packets to the muxer can wait on the audit
    /// log.
    fn cycle(
        &mut self,
        manager: &mut EventManager<Ready>,
        id: SubscriberId,
        tx_kicked: bool,
        rx_kicked: bool,
    ) -> bool {
        let mut interrupt = false;
        if tx_kicked && !self.tx.failed {
            match transmit(&mut self.tx.queue, &self.mem, &mut self.muxer, &self.stop) {
                Ok(notify) => interrupt |= notify,
                Err(error) => self.tx.fail(&self.irq, &self.stop, error),
            }
        }
        if self.stop.is_set() {
            return false;
        }
        if !self.rx.failed {
            match deliver(&mut self.rx.queue, &self.mem, &mut self.muxer, &self.stop) {
                Ok(0) => {}
                Ok(_) => match self.rx.queue.needs_notification(&*self.mem) {
                    Ok(notify) => interrupt |= notify,
                    Err(error) => self.rx.fail(&self.irq, &self.stop, error),
                },
                Err(error) => self.rx.fail(&self.irq, &self.stop, error),
            }
        }
        if self.stop.is_set() {
            return false;
        }
        if interrupt {
            if let Err(error) = self.irq.signal_used_queue() {
                boxcar_virtio::limited!(error, "virtio-vsock: cannot interrupt the guest: {error}");
            }
        }
        // Packets left for the guest mean it has no room for them: the host
        // ends wait for an RX kick (see the module docs). A kick resumes
        // them even when the muxer still has packets: some may have fit.
        let starved = self.muxer.has_pending_rx() && !rx_kicked;
        self.watch_muxer(manager, id, !starved);
        true
    }

    /// Starts or stops watching the muxer's epoll.
    fn watch_muxer(&mut self, manager: &mut EventManager<Ready>, id: SubscriberId, watch: bool) {
        if watch == self.muxer_watched {
            return;
        }
        let fd = self.muxer.get_polled_fd();
        let changed = manager.event_ops(id).and_then(|mut ops| {
            if watch {
                ops.add(Events::new_raw(fd, EventSet::IN))
            } else {
                ops.remove(Events::empty_raw(fd))
            }
        });
        match changed {
            Ok(()) => self.muxer_watched = watch,
            Err(error) => boxcar_virtio::limited!(
                warn,
                "virtio-vsock: cannot {} watching the muxer: {error}",
                if watch { "start" } else { "stop" }
            ),
        }
    }
}

/// Sets up the thread's `EventManager` for `worker`, so that a failure is
/// an activation error, then starts the thread.
fn spawn(worker: Worker) -> Result<WorkerHandle, ActivateError> {
    let manager_error = |error: event_manager::Error| ActivateError::Device(error.into());
    let kill = worker.kill.try_clone()?;
    let stop = worker.stop.clone();
    let mut manager = EventManager::new().map_err(manager_error)?;
    let id = manager.add_subscriber(Ready::default());
    let mut ops = manager.event_ops(id).map_err(manager_error)?;
    for fd in [
        worker.kill.as_raw_fd(),
        worker.rx.evt.as_raw_fd(),
        worker.tx.evt.as_raw_fd(),
        worker.evq.as_raw_fd(),
        worker.muxer.get_polled_fd(),
    ] {
        // Level-triggered: no EventSet::EDGE_TRIGGERED, here or anywhere.
        ops.add(Events::new_raw(fd, EventSet::IN))
            .map_err(manager_error)?;
    }
    let (stopped, done) = mpsc::channel::<()>();
    let thread = thread::Builder::new().name("vsock".into()).spawn(move || {
        // Dropped when the thread ends, however it ends.
        let _stopped = stopped;
        run(manager, id, worker);
    })?;
    Ok(WorkerHandle {
        kill,
        stop,
        done,
        thread,
    })
}

/// The vsock thread: waits and handles what it finds until the kill
/// eventfd fires, then closes every connection.
fn run(mut manager: EventManager<Ready>, id: SubscriberId, mut worker: Worker) {
    let irq = Arc::clone(&worker.irq);
    let stop = worker.stop.clone();
    let _panic = PanicGuard {
        irq: &irq,
        stop: &stop,
    };
    // Chains the driver queued before the thread started.
    let mut running = worker.cycle(&mut manager, id, true, true);
    while running {
        if let Err(error) = manager.run() {
            boxcar_virtio::limited!(
                error,
                "virtio-vsock: the vsock thread cannot wait for events: {error}; asking the \
                 driver to reset the device"
            );
            if !stop.is_set() {
                if let Err(error) = irq.signal_needs_reset() {
                    boxcar_virtio::limited!(
                        error,
                        "virtio-vsock: cannot signal the reset request: {error}"
                    );
                }
            }
            break;
        }
        let ready = match manager.subscriber_mut(id) {
            Ok(ready) => mem::take(&mut ready.0),
            Err(_) => break,
        };
        running = worker.wakeup(&mut manager, id, &ready);
    }
    // Every connection's end is recorded; dropping the worker closes the
    // host ends.
    worker.muxer.close_all();
}

/// Asks the driver for a reset when the vsock thread panics, so the guest
/// learns that its queues are no longer served.
struct PanicGuard<'a> {
    irq: &'a IrqTrigger,
    stop: &'a StopFlag,
}

impl Drop for PanicGuard<'_> {
    fn drop(&mut self) {
        if thread::panicking() && !self.stop.is_set() {
            boxcar_virtio::limited!(
                error,
                "virtio-vsock: the vsock thread panicked; asking the driver to reset the device"
            );
            if let Err(error) = self.irq.signal_needs_reset() {
                boxcar_virtio::limited!(
                    error,
                    "virtio-vsock: cannot signal the reset request: {error}"
                );
            }
        }
    }
}

/// The running vsock thread.
struct WorkerHandle {
    /// The device's end of the kill eventfd.
    kill: EventFd,
    /// The thread's stop flag.
    stop: StopFlag,
    /// Disconnected when the thread ends.
    done: Receiver<()>,
    thread: JoinHandle<()>,
}

impl WorkerHandle {
    /// Stops the thread and joins it, waiting at most [`JOIN_LIMIT`]. After
    /// this the thread writes to neither ring and raises no interrupt, even
    /// if it was left behind: the stop flag is set first.
    fn stop(self) {
        self.stop.set();
        // A fresh eventfd written once cannot overflow.
        if let Err(error) = self.kill.write(1) {
            boxcar_virtio::limited!(error, "virtio-vsock: cannot stop the vsock thread: {error}");
        }
        match self.done.recv_timeout(JOIN_LIMIT) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                if self.thread.join().is_err() {
                    boxcar_virtio::limited!(error, "virtio-vsock: the vsock thread panicked");
                }
            }
            Err(RecvTimeoutError::Timeout) => boxcar_virtio::limited!(
                warn,
                "virtio-vsock: the vsock thread did not stop within {JOIN_LIMIT:?}; leaving it \
                 behind"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Instant;

    use boxcar_audit::{LogReader, WriterConfig, WriterHandle};
    use boxcar_proto::SessionId;
    use boxcar_virtio::mmio::regs;
    use boxcar_virtio::status::{ACKNOWLEDGE, DRIVER, DRIVER_OK, FEATURES_OK};
    use boxcar_virtio::testing::{guest_memory, read_u32, write_u32, TEST_SLOT};
    use boxcar_virtio::{DeviceContext, MmioTransport};
    use tempfile::TempDir;
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::desc::split::{Descriptor as SplitDescriptor, VirtqUsedElem};
    use virtio_queue::desc::RawDescriptor;
    use virtio_queue::mock::MockSplitQueue;
    use vm_memory::{Bytes, GuestAddress};

    use super::*;
    use crate::defs::uapi;
    use crate::rules::port_socket_path;
    use crate::services::ConnMeta;

    /// Guest RAM for every test: 1 MiB at guest physical address 0.
    const GUEST_MEM_SIZE: usize = 0x10_0000;
    /// Size of every mock queue.
    const QUEUE_LEN: u16 = 16;
    /// Where the used ring of a mock queue goes, from its start, apart from
    /// the mock's own, which overlaps its available ring.
    const USED_RING_OFFSET: u64 = 0x800;
    /// Packet buffers, 0x2000 apart.
    const BUFFERS: u64 = 0x4_0000;
    /// An RX buffer as Linux posts it: the header and 4 KiB, in one
    /// descriptor.
    const RX_BUF_LEN: u32 = PKT_HEADER_SIZE as u32 + 4096;
    /// How long the vsock thread has to answer a kick.
    const THREAD_LIMIT: Duration = Duration::from_secs(5);
    /// The guest's ephemeral port in these tests.
    const GUEST_PORT: u32 = 40_000;

    /// Serves no internal port.
    struct NoServices;

    impl InternalServices for NoServices {
        fn connect(&self, _port: u32, _meta: ConnMeta) -> Option<UnixStream> {
            None
        }
    }

    /// A temporary directory with the vsock socket's path and an audit log.
    struct Session {
        dir: TempDir,
        sink: AuditSink,
        writer: WriterHandle,
    }

    impl Session {
        fn new() -> Session {
            let dir = TempDir::new().unwrap();
            let (sink, writer) =
                boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new()))
                    .unwrap();
            Session { dir, sink, writer }
        }

        fn uds_path(&self) -> PathBuf {
            self.dir.path().join("vsock.sock")
        }

        fn config(&self, allow_ports: &[u32]) -> VsockConfig {
            VsockConfig {
                allow_ports: allow_ports.to_vec(),
                ..VsockConfig::new(self.uds_path())
            }
        }

        fn device(&self, allow_ports: &[u32]) -> VirtioVsock {
            VirtioVsock::new(
                self.config(allow_ports),
                Arc::new(NoServices),
                self.sink.clone(),
            )
            .unwrap()
        }

        /// Closes the log and returns the `vsock.*` records' (type, data).
        fn vsock_records(self) -> Vec<(String, serde_json::Value)> {
            let Session { dir, sink, writer } = self;
            let session = writer.session_dir().to_owned();
            drop(sink);
            writer.close().unwrap();
            let records: Vec<boxcar_proto::Record> = LogReader::open(&session)
                .unwrap()
                .records()
                .map(Result::unwrap)
                .collect();
            drop(dir);
            records
                .into_iter()
                .filter(|r| r.kind.starts_with("vsock."))
                .map(|r| (r.kind, r.data))
                .collect()
        }
    }

    #[test]
    fn the_device_is_type_19_with_three_queues_and_the_cid_in_its_config() {
        let session = Session::new();
        let mut device = session.device(&[]);
        assert_eq!(device.device_type(), 19);
        assert_eq!(device.num_queues(), 3);
        for q in 0..3 {
            assert_eq!(device.queue_max_size(q), 256);
        }
        assert_eq!(device.queue_max_size(3), 0);
        // No SEQPACKET, no other feature.
        assert_eq!(device.avail_features(), VERSION_1 | EVENT_IDX);

        let read = |device: &VirtioVsock, offset: u64, len: usize| {
            let mut data = vec![0xaa; len];
            device.read_config(offset, &mut data);
            data
        };
        assert_eq!(read(&device, 0, 8), 3u64.to_le_bytes());
        assert_eq!(read(&device, 0, 4), [3, 0, 0, 0]);
        assert_eq!(read(&device, 4, 4), [0; 4]);
        assert_eq!(read(&device, 8, 4), [0; 4]);
        assert_eq!(read(&device, u64::MAX, 4), [0; 4]);
        // Read-only.
        device.write_config(0, &[9; 8]);
        assert_eq!(read(&device, 0, 8), 3u64.to_le_bytes());
        drop(device);

        let cfg = VsockConfig {
            guest_cid: 0xdead_beef,
            ..session.config(&[])
        };
        let device = VirtioVsock::new(cfg, Arc::new(NoServices), session.sink.clone()).unwrap();
        assert_eq!(read(&device, 0, 8), 0xdead_beef_u64.to_le_bytes());
    }

    #[test]
    fn a_reserved_or_oversized_cid_is_refused_before_the_socket_is_bound() {
        let session = Session::new();
        for cid in [0, 1, 2, 1 << 32] {
            let cfg = VsockConfig {
                guest_cid: cid,
                ..session.config(&[])
            };
            match VirtioVsock::new(cfg, Arc::new(NoServices), session.sink.clone()) {
                Err(VsockDeviceError::Cid(c)) => assert_eq!(c, cid),
                other => panic!("CID {cid}: {:?}", other.map(|_| ())),
            }
            assert!(!session.uds_path().exists());
        }
    }

    #[test]
    fn the_socket_is_0600_and_goes_with_the_device() {
        let session = Session::new();
        let path = session.uds_path();
        let mut device = session.device(&[]);
        assert_eq!(device.uds_path(), path);
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        // A second device cannot take the path.
        assert!(matches!(
            VirtioVsock::new(
                session.config(&[]),
                Arc::new(NoServices),
                session.sink.clone()
            ),
            Err(VsockDeviceError::Listener { .. })
        ));
        device.close_socket();
        assert!(!path.exists());
        // Idempotent, and dropping does it too.
        device.close_socket();
        drop(device);
        let device = session.device(&[]);
        assert!(path.exists());
        drop(device);
        assert!(!path.exists());
    }

    // Packets on mock queues.

    /// A packet header as the guest writes it, from its `port` to host
    /// `host_port`.
    fn header(host_port: u32, port: u32, op: u16, len: u32) -> [u8; PKT_HEADER_SIZE] {
        let mut h = [0u8; PKT_HEADER_SIZE];
        h[0..8].copy_from_slice(&GUEST_CID.to_le_bytes());
        h[8..16].copy_from_slice(&uapi::VSOCK_HOST_CID.to_le_bytes());
        h[16..20].copy_from_slice(&port.to_le_bytes());
        h[20..24].copy_from_slice(&host_port.to_le_bytes());
        h[24..28].copy_from_slice(&len.to_le_bytes());
        h[28..30].copy_from_slice(&uapi::VSOCK_TYPE_STREAM.to_le_bytes());
        h[30..32].copy_from_slice(&op.to_le_bytes());
        h[36..40].copy_from_slice(&(256u32 * 1024).to_le_bytes());
        h
    }

    /// (op, src_port, dst_port, len) of a header the device wrote.
    fn parse(h: &[u8]) -> (u16, u32, u32, u32) {
        let u32_at = |at: usize| u32::from_le_bytes(h[at..at + 4].try_into().unwrap());
        (
            u16::from_le_bytes([h[30], h[31]]),
            u32_at(16),
            u32_at(20),
            u32_at(24),
        )
    }

    fn buffer(n: u16) -> GuestAddress {
        GuestAddress(BUFFERS + 0x2000 * u64::from(n))
    }

    /// Where queue `q` lives.
    fn queue_start(q: usize) -> GuestAddress {
        GuestAddress(0x1_0000 * (q as u64 + 1))
    }

    /// The driver's view of queue `q`. Creating it zeroes the ring indexes,
    /// so each test creates it once, before offering.
    fn queue_mock(mem: &GuestMemoryMmap, q: usize) -> MockSplitQueue<'_, GuestMemoryMmap> {
        MockSplitQueue::create(mem, queue_start(q), QUEUE_LEN)
    }

    fn used_ring(q: usize) -> GuestAddress {
        GuestAddress(queue_start(q).0 + USED_RING_OFFSET)
    }

    /// The queue the device would be handed for `mock`, with our used ring.
    fn device_queue(mock: &MockSplitQueue<'_, GuestMemoryMmap>, q: usize) -> Queue {
        let mut queue: Queue = mock.create_queue().unwrap();
        let used = used_ring(q).0;
        queue.set_used_ring_address(Some(used as u32), Some((used >> 32) as u32));
        queue
    }

    fn used_idx(mem: &GuestMemoryMmap, q: usize) -> u16 {
        u16::from_le(mem.read_obj(GuestAddress(used_ring(q).0 + 2)).unwrap())
    }

    fn used_elem(mem: &GuestMemoryMmap, q: usize, index: u64) -> VirtqUsedElem {
        mem.read_obj(GuestAddress(used_ring(q).0 + 4 + 8 * index))
            .unwrap()
    }

    /// Offers a packet on the TX queue: the header in descriptor `head` and
    /// the data, if any, in the next.
    fn offer_tx(
        mem: &GuestMemoryMmap,
        mock: &MockSplitQueue<'_, GuestMemoryMmap>,
        head: u16,
        header: &[u8],
        data: &[u8],
    ) {
        let parts: Vec<&[u8]> = [header, data]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect();
        let descs: Vec<RawDescriptor> = parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let n = head + i as u16;
                mem.write_slice(part, buffer(n)).unwrap();
                let last = i + 1 == parts.len();
                RawDescriptor::from(SplitDescriptor::new(
                    buffer(n).0,
                    part.len() as u32,
                    if last { 0 } else { VRING_DESC_F_NEXT as u16 },
                    if last { 0 } else { n + 1 },
                ))
            })
            .collect();
        mock.add_desc_chains(&descs, head).unwrap();
    }

    /// Offers RX buffer `n`, one device-writable descriptor of
    /// [`RX_BUF_LEN`] bytes.
    fn offer_rx(mem: &GuestMemoryMmap, mock: &MockSplitQueue<'_, GuestMemoryMmap>, n: u16) {
        mem.write_slice(&[0xaa; RX_BUF_LEN as usize], buffer(n))
            .unwrap();
        mock.add_desc_chains(
            &[RawDescriptor::from(SplitDescriptor::new(
                buffer(n).0,
                RX_BUF_LEN,
                VRING_DESC_F_WRITE as u16,
                0,
            ))],
            n,
        )
        .unwrap();
    }

    /// The `used` RX buffer `n`: its header's (op, src_port, dst_port,
    /// len), and its payload.
    fn rx_packet(mem: &GuestMemoryMmap, n: u16, used: u32) -> ((u16, u32, u32, u32), Vec<u8>) {
        let mut bytes = vec![0u8; used as usize];
        mem.read_slice(&mut bytes, buffer(n)).unwrap();
        let fields = parse(&bytes[..PKT_HEADER_SIZE]);
        (fields, bytes[PKT_HEADER_SIZE..].to_vec())
    }

    // The device behind a transport, with its thread.

    /// A device in a transport, as the driver sees it, with the handles the
    /// VMM (ioeventfds, the irqfd) would otherwise hold.
    struct Driver {
        mem: Arc<GuestMemoryMmap>,
        transport: MmioTransport<VirtioVsock>,
        irq: Arc<IrqTrigger>,
        kicks: Vec<EventFd>,
    }

    impl Driver {
        fn new(device: VirtioVsock) -> Driver {
            let mem = guest_memory(GUEST_MEM_SIZE).unwrap();
            let ctx = DeviceContext::new(TEST_SLOT, device.num_queues()).unwrap();
            let irq = ctx.irq.clone();
            let kicks = ctx
                .queue_evts
                .iter()
                .map(|evt| evt.try_clone().unwrap())
                .collect();
            let transport = MmioTransport::new(device, mem.clone(), ctx);
            Driver {
                mem,
                transport,
                irq,
                kicks,
            }
        }

        fn read(&mut self, offset: u64) -> u32 {
            read_u32(&mut self.transport, offset)
        }

        fn write(&mut self, offset: u64, value: u32) {
            write_u32(&mut self.transport, offset, value)
        }

        fn set_status(&mut self, value: u8) {
            self.write(regs::STATUS, u32::from(value));
        }

        /// The Linux driver's handshake, taking every feature offered, with
        /// the three queues ready, up to DRIVER_OK.
        fn handshake(&mut self) {
            assert_eq!(self.read(regs::DEVICE_ID), 19);
            self.set_status(ACKNOWLEDGE);
            self.set_status(ACKNOWLEDGE | DRIVER);
            for sel in 0..2 {
                self.write(regs::DEVICE_FEATURES_SEL, sel);
                let offered = self.read(regs::DEVICE_FEATURES);
                self.write(regs::DRIVER_FEATURES_SEL, sel);
                self.write(regs::DRIVER_FEATURES, offered);
            }
            self.set_status(ACKNOWLEDGE | DRIVER | FEATURES_OK);
            for q in 0..NUM_QUEUES {
                let desc = queue_start(q).0;
                let avail = desc + 16 * u64::from(QUEUE_LEN);
                let used = used_ring(q).0;
                self.write(regs::QUEUE_SEL, q as u32);
                assert_eq!(self.read(regs::QUEUE_NUM_MAX), 256);
                self.write(regs::QUEUE_NUM, u32::from(QUEUE_LEN));
                for (low, addr) in [
                    (regs::QUEUE_DESC_LOW, desc),
                    (regs::QUEUE_DRIVER_LOW, avail),
                    (regs::QUEUE_DEVICE_LOW, used),
                ] {
                    self.write(low, addr as u32);
                    self.write(low + 4, (addr >> 32) as u32);
                }
                self.write(regs::QUEUE_READY, 1);
            }
            self.set_status(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
            assert_eq!(
                self.read(regs::STATUS),
                u32::from(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK)
            );
        }

        /// Waits for queue `q`'s used index to reach `want`.
        fn wait_used(&self, q: usize, want: u16) {
            let deadline = Instant::now() + THREAD_LIMIT;
            while used_idx(&self.mem, q) != want {
                assert!(
                    Instant::now() < deadline,
                    "queue {q}: used idx {} not {want}, needs reset {}",
                    used_idx(&self.mem, q),
                    self.irq.needs_reset.load(Ordering::SeqCst)
                );
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// The guest asks for an unlisted port and gets an RST; it asks for an
    /// allowlisted one, gets a RESPONSE and sends bytes; then the driver
    /// resets the device, which closes the connection and records its end.
    #[test]
    fn requests_are_answered_through_the_queues_and_a_reset_closes_every_connection() {
        let session = Session::new();
        let host = UnixListener::bind(port_socket_path(&session.uds_path(), 5000)).unwrap();
        let mut driver = Driver::new(session.device(&[5000]));
        driver.handshake();
        let mem = driver.mem.clone();
        let rx = queue_mock(&mem, RX_QUEUE);
        let tx = queue_mock(&mem, TX_QUEUE);
        for n in 0..2 {
            offer_rx(&mem, &rx, n);
        }

        offer_tx(
            &mem,
            &tx,
            0,
            &header(5001, GUEST_PORT, uapi::VSOCK_OP_REQUEST, 0),
            &[],
        );
        driver.kicks[TX_QUEUE].write(1).unwrap();
        driver.wait_used(TX_QUEUE, 1);
        driver.wait_used(RX_QUEUE, 1);
        let used = used_elem(&mem, RX_QUEUE, 0);
        assert_eq!((used.id(), used.len()), (0, PKT_HEADER_SIZE as u32));
        assert_eq!(
            rx_packet(&mem, 0, used.len()).0,
            (uapi::VSOCK_OP_RST, 5001, GUEST_PORT, 0)
        );

        offer_tx(
            &mem,
            &tx,
            1,
            &header(5000, GUEST_PORT, uapi::VSOCK_OP_REQUEST, 0),
            &[],
        );
        driver.kicks[TX_QUEUE].write(1).unwrap();
        driver.wait_used(TX_QUEUE, 2);
        driver.wait_used(RX_QUEUE, 2);
        let used = used_elem(&mem, RX_QUEUE, 1);
        assert_eq!(
            rx_packet(&mem, 1, used.len()).0,
            (uapi::VSOCK_OP_RESPONSE, 5000, GUEST_PORT, 0)
        );
        // Established: the guest's bytes, header and data in two
        // descriptors, reach the host socket.
        offer_tx(
            &mem,
            &tx,
            2,
            &header(5000, GUEST_PORT, uapi::VSOCK_OP_RW, 5),
            b"hello",
        );
        driver.kicks[TX_QUEUE].write(1).unwrap();
        driver.wait_used(TX_QUEUE, 3);
        let (mut stream, _) = host.accept().unwrap();
        stream.set_read_timeout(Some(THREAD_LIMIT)).unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");

        // The driver resets the device: the thread closes the connection and
        // is joined.
        driver.set_status(0);
        assert_eq!(driver.read(regs::STATUS), 0);
        assert_eq!(stream.read(&mut got).unwrap(), 0);
        drop(driver);
        assert!(!session.uds_path().exists());
        assert_eq!(
            session.vsock_records(),
            [
                (
                    "vsock.connect".to_owned(),
                    serde_json::json!({"port": 5001, "dir": "guest", "peer": "uds",
                        "src_port": GUEST_PORT, "verdict": "deny", "reason": "port"})
                ),
                (
                    "vsock.connect".to_owned(),
                    serde_json::json!({"port": 5000, "dir": "guest", "peer": "uds",
                        "src_port": GUEST_PORT, "verdict": "allow", "reason": null})
                ),
                (
                    "vsock.close".to_owned(),
                    serde_json::json!({"port": 5000, "dir": "guest", "tx": 5, "rx": 0})
                ),
            ]
        );
    }

    /// With data waiting on a host end and no RX buffer to put it in, the
    /// thread stops watching the muxer: its epoll stays readable, and a
    /// level-triggered wait on it would return at once, again and again. An
    /// RX kick brings it back. Driven by hand, without the thread.
    #[test]
    fn a_guest_without_rx_room_does_not_wake_the_thread_until_it_kicks_rx() {
        let session = Session::new();
        let host = UnixListener::bind(port_socket_path(&session.uds_path(), 5000)).unwrap();
        let mem = guest_memory(GUEST_MEM_SIZE).unwrap();
        let rx = queue_mock(&mem, RX_QUEUE);
        let tx = queue_mock(&mem, TX_QUEUE);
        let activated = |mock: &MockSplitQueue<'_, GuestMemoryMmap>, q: usize| ActivatedQueue {
            queue: device_queue(mock, q),
            evt: EventFd::new(EFD_NONBLOCK).unwrap(),
        };
        let (rx_q, tx_q) = (activated(&rx, RX_QUEUE), activated(&tx, TX_QUEUE));
        let rx_kick = rx_q.evt.try_clone().unwrap();
        let cfg = session.config(&[5000]);
        let listener = bind_listener(&cfg.uds_path).unwrap();
        let muxer =
            VsockMuxer::new(&cfg, listener, Arc::new(NoServices), session.sink.clone()).unwrap();
        let mut worker = Worker {
            mem: mem.clone(),
            irq: Arc::new(IrqTrigger::new().unwrap()),
            muxer,
            rx: Ring::new(RX_QUEUE, rx_q),
            tx: Ring::new(TX_QUEUE, tx_q),
            evq: EventFd::new(EFD_NONBLOCK).unwrap(),
            kill: EventFd::new(EFD_NONBLOCK).unwrap(),
            stop: StopFlag::default(),
            muxer_watched: true,
        };
        let mut manager = EventManager::new().unwrap();
        let id = manager.add_subscriber(Ready::default());
        {
            let mut ops = manager.event_ops(id).unwrap();
            for fd in [worker.rx.evt.as_raw_fd(), worker.muxer.get_polled_fd()] {
                ops.add(Events::new_raw(fd, EventSet::IN)).unwrap();
            }
        }
        let wait = |manager: &mut EventManager<Ready>, ms: i32| {
            manager.run_with_timeout(ms).unwrap();
            mem::take(&mut manager.subscriber_mut(id).unwrap().0)
        };

        // The guest connects, with one RX buffer for the answer.
        offer_rx(&mem, &rx, 0);
        offer_tx(
            &mem,
            &tx,
            0,
            &header(5000, GUEST_PORT, uapi::VSOCK_OP_REQUEST, 0),
            &[],
        );
        assert!(worker.cycle(&mut manager, id, true, false));
        assert_eq!(used_idx(&mem, RX_QUEUE), 1);
        assert!(worker.muxer_watched);

        // The host writes; the guest has no room.
        let (mut stream, _) = host.accept().unwrap();
        stream.write_all(b"data").unwrap();
        let ready = wait(&mut manager, 1000);
        assert_eq!(ready, [worker.muxer.get_polled_fd()]);
        assert!(worker.wakeup(&mut manager, id, &ready));
        assert!(!worker.muxer_watched);
        // Still readable, but nothing wakes the thread.
        assert!(wait(&mut manager, 100).is_empty());

        // The guest posts a buffer and kicks: the data lands.
        offer_rx(&mem, &rx, 1);
        rx_kick.write(1).unwrap();
        let ready = wait(&mut manager, 1000);
        assert_eq!(ready, [worker.rx.evt.as_raw_fd()]);
        assert!(worker.wakeup(&mut manager, id, &ready));
        assert!(worker.muxer_watched);
        assert_eq!(used_idx(&mem, RX_QUEUE), 2);
        let used = used_elem(&mem, RX_QUEUE, 1);
        assert_eq!(
            rx_packet(&mem, 1, used.len()),
            ((uapi::VSOCK_OP_RW, 5000, GUEST_PORT, 4), b"data".to_vec())
        );
        worker.muxer.close_all();
    }
}
