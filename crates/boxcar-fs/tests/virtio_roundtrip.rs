// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The virtio-fs device without KVM: FUSE requests placed in descriptor
//! chains of a mock split queue, answered by `AuditFs<PassthroughFs>` over a
//! temporary directory, and read back from guest memory; the config space;
//! and the device behind a virtio-mmio transport, where activation starts a
//! worker thread that serves a queue when its eventfd is kicked, and reset
//! joins it and closes what the guest left open.

use std::ffi::OsString;
use std::fs;
use std::mem::size_of;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use boxcar_audit::{spawn, verify_session, AuditSink, LogReader, WriterConfig, WriterHandle};
use boxcar_fs::device::{FsError, VirtioFs, QUEUE_MAX_SIZE};
use boxcar_fs::{AuditFsOptions, CachePolicyKind, FsShareConfig};
use boxcar_proto::{Attrib, Hash, HashStatus, Payload, SessionId};
use boxcar_virtio::features::{EVENT_IDX, VERSION_1};
use boxcar_virtio::mmio::regs;
use boxcar_virtio::status::{ACKNOWLEDGE, DEVICE_NEEDS_RESET, DRIVER, DRIVER_OK, FEATURES_OK};
use boxcar_virtio::testing::{guest_memory, read_u32, write_u32, TEST_SLOT};
use boxcar_virtio::{DeviceContext, IrqTrigger, MmioTransport, VirtioDevice};
use fuse_backend_rs::abi::fuse_abi::{
    EntryOut, InHeader, InitIn, InitOut, OpenIn, OpenOut, OutHeader,
};
use tempfile::TempDir;
use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
use virtio_queue::desc::split::{Descriptor as SplitDescriptor, VirtqUsedElem};
use virtio_queue::desc::RawDescriptor;
use virtio_queue::mock::MockSplitQueue;
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

/// Guest RAM for every test: 1 MiB at guest physical address 0.
const GUEST_MEM_SIZE: usize = 0x10_0000;
/// Size of every queue.
const QUEUE_LEN: u16 = 16;
/// Where the used ring of a mock queue goes. The mock sizes its available
/// ring in elements rather than bytes when it places the used ring after it,
/// so its own used ring overlaps the available ring's entries; a used ring
/// of our own keeps the two independent.
const USED_RING_OFFSET: u64 = 0x800;
/// Request buffers, 0x1000 apart.
const REQUESTS: u64 = 0x4_0000;
/// Reply buffers, 0x1000 apart.
const REPLIES: u64 = 0x8_0000;
/// Every reply buffer's length.
const REPLY_LEN: u32 = 0x1000;

/// FUSE opcodes.
const FUSE_LOOKUP: u32 = 1;
const FUSE_OPEN: u32 = 14;
const FUSE_INIT: u32 = 26;
/// The root inode.
const ROOT_ID: u64 = 1;

/// The file every lookup test finds in the share.
const HELLO: &str = "hello.txt";
const HELLO_BODY: &[u8] = b"hello, virtio-fs\n";

/// How long a worker thread has to answer a kick.
const WORKER_LIMIT: Duration = Duration::from_secs(5);

/// A share directory with `hello.txt` in it, and the audit session its
/// device records into.
struct Share {
    _dir: TempDir,
    root: PathBuf,
    sink: AuditSink,
    writer: WriterHandle,
    config: FsShareConfig,
}

impl Share {
    fn new(tag: &str) -> Share {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("share");
        fs::create_dir(&root).unwrap();
        fs::write(root.join(HELLO), HELLO_BODY).unwrap();
        let (sink, writer) =
            spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
        let config = FsShareConfig {
            tag: tag.into(),
            host_dir: root.clone(),
            guest_path: format!("/{tag}"),
            cache: CachePolicyKind::Auto,
        };
        Share {
            _dir: dir,
            root,
            sink,
            writer,
            config,
        }
    }

    fn device(&self) -> VirtioFs {
        VirtioFs::new(
            self.config.clone(),
            self.sink.clone(),
            AuditFsOptions::default(),
        )
        .expect("a virtio-fs device over the share")
    }

    /// Closes the log, verifies it, and returns its typed payloads without
    /// the checkpoints.
    fn payloads(self) -> Vec<Payload> {
        drop(self.sink);
        let session = self.writer.session_dir().to_owned();
        self.writer.close().unwrap();
        verify_session(&session).unwrap();
        LogReader::open(&session)
            .unwrap()
            .records()
            .map(|r| r.unwrap())
            .filter(|r| r.kind != "checkpoint")
            .map(|r| Payload::from_record(&r).unwrap())
            .collect()
    }
}

// Requests and replies in guest memory.

/// A FUSE request: the header, with `len` filled in, then `body`.
fn request(opcode: u32, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
    let header = InHeader {
        len: (size_of::<InHeader>() + body.len()) as u32,
        opcode,
        unique,
        nodeid,
        uid: 1000,
        gid: 1000,
        pid: 42,
        padding: 0,
    };
    let mut bytes = header.as_slice().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

/// FUSE_INIT from a 7.31 kernel.
fn init_request(unique: u64) -> Vec<u8> {
    let init = InitIn {
        major: 7,
        minor: 31,
        max_readahead: 0x2_0000,
        flags: 0,
    };
    request(FUSE_INIT, unique, 0, init.as_slice())
}

/// FUSE_LOOKUP of `name` in the root.
fn lookup_request(unique: u64, name: &str) -> Vec<u8> {
    let mut body = name.as_bytes().to_vec();
    body.push(0);
    request(FUSE_LOOKUP, unique, ROOT_ID, &body)
}

/// FUSE_OPEN of `nodeid`.
fn open_request(unique: u64, nodeid: u64, flags: u32) -> Vec<u8> {
    let open = OpenIn {
        flags,
        fuse_flags: 0,
    };
    request(FUSE_OPEN, unique, nodeid, open.as_slice())
}

fn request_addr(n: u16) -> GuestAddress {
    GuestAddress(REQUESTS + 0x1000 * u64::from(n))
}

fn reply_addr(n: u16) -> GuestAddress {
    GuestAddress(REPLIES + 0x1000 * u64::from(n))
}

/// Puts request `n` in guest memory and offers it on `mock` as a chain of
/// two descriptors, starting at descriptor `2 * n`: the request, readable,
/// then reply buffer `n`, writable.
fn offer(mem: &GuestMemoryMmap, mock: &MockSplitQueue<'_, GuestMemoryMmap>, n: u16, req: &[u8]) {
    mem.write_slice(req, request_addr(n)).unwrap();
    let head = 2 * n;
    mock.add_desc_chains(
        &[
            RawDescriptor::from(SplitDescriptor::new(
                request_addr(n).0,
                req.len() as u32,
                VRING_DESC_F_NEXT as u16,
                head + 1,
            )),
            RawDescriptor::from(SplitDescriptor::new(
                reply_addr(n).0,
                REPLY_LEN,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ],
        head,
    )
    .unwrap();
}

/// The reply in buffer `n`: its header and the object after it.
fn reply<T: ByteValued>(mem: &GuestMemoryMmap, n: u16) -> (OutHeader, T) {
    let out: OutHeader = mem.read_obj(reply_addr(n)).unwrap();
    let body = mem
        .read_obj(GuestAddress(
            reply_addr(n).0 + size_of::<OutHeader>() as u64,
        ))
        .unwrap();
    (out, body)
}

fn used_ring(mock: &MockSplitQueue<'_, GuestMemoryMmap>) -> GuestAddress {
    GuestAddress(mock.start().0 + USED_RING_OFFSET)
}

fn used_idx(mem: &GuestMemoryMmap, mock: &MockSplitQueue<'_, GuestMemoryMmap>) -> u16 {
    used_idx_at(mem, used_ring(mock))
}

fn used_idx_at(mem: &GuestMemoryMmap, used_ring: GuestAddress) -> u16 {
    u16::from_le(mem.read_obj(GuestAddress(used_ring.0 + 2)).unwrap())
}

fn used_elem(
    mem: &GuestMemoryMmap,
    mock: &MockSplitQueue<'_, GuestMemoryMmap>,
    index: u64,
) -> VirtqUsedElem {
    mem.read_obj(GuestAddress(used_ring(mock).0 + 4 + 8 * index))
        .unwrap()
}

/// The queue the device would be handed for `mock`, with our used ring.
fn device_queue(mock: &MockSplitQueue<'_, GuestMemoryMmap>) -> Queue {
    let mut queue: Queue = mock.create_queue().unwrap();
    let used = used_ring(mock).0;
    queue.set_used_ring_address(Some(used as u32), Some((used >> 32) as u32));
    queue
}

// The config space and identity.

#[test]
fn config_space_holds_the_tag_and_the_request_queue_count() {
    let share = Share::new("workspace");
    let device = share.device();

    assert_eq!(device.device_type(), 26);
    assert_eq!(device.num_queues(), 2, "hiprio and one request queue");
    assert_eq!(device.queue_max_size(0), QUEUE_MAX_SIZE);
    assert_eq!(device.queue_max_size(1), 1024);
    assert_eq!(device.avail_features(), VERSION_1 | EVENT_IDX);

    // tag[36]: the UTF-8 tag, NUL-padded.
    let mut tag = [0xaa; 36];
    device.read_config(0, &mut tag);
    assert_eq!(&tag[..9], b"workspace");
    assert!(tag[9..].iter().all(|&b| b == 0), "{tag:?}");

    // num_request_queues: u32 LE at 0x24.
    let mut queues = [0xaa; 4];
    device.read_config(0x24, &mut queues);
    assert_eq!(u32::from_le_bytes(queues), 1);

    // Byte by byte, as Linux reads the tag, the same 40 bytes.
    let bytes: Vec<u8> = (0..40)
        .map(|offset| {
            let mut b = [0xaa];
            device.read_config(offset, &mut b);
            b[0]
        })
        .collect();
    let mut expected = b"workspace".to_vec();
    expected.resize(36, 0);
    expected.extend_from_slice(&1u32.to_le_bytes());
    assert_eq!(bytes, expected);

    // Past the end the buffer is left alone, also when a read straddles it.
    let mut past = [0xaa; 4];
    device.read_config(40, &mut past);
    assert_eq!(past, [0xaa; 4]);
    let mut straddle = [0xaa; 4];
    device.read_config(38, &mut straddle);
    assert_eq!(straddle, [0, 0, 0xaa, 0xaa]);
    device.read_config(u64::MAX, &mut past);
    assert_eq!(past, [0xaa; 4]);

    drop(device);
    drop(share.payloads());
}

#[test]
fn a_tag_of_exactly_36_bytes_fills_the_field() {
    let tag = "t".repeat(36);
    let share = Share::new(&tag);
    let device = share.device();
    let mut field = [0; 40];
    device.read_config(0, &mut field);
    assert_eq!(&field[..36], tag.as_bytes());
    assert_eq!(&field[36..], 1u32.to_le_bytes());
    drop(device);
    drop(share.payloads());
}

#[test]
fn shares_the_device_cannot_serve_are_refused() {
    let share = Share::new("workspace");
    let with = |f: &dyn Fn(&mut FsShareConfig)| {
        let mut config = share.config.clone();
        f(&mut config);
        VirtioFs::new(config, share.sink.clone(), AuditFsOptions::default())
    };

    for tag in [String::new(), "t".repeat(37), "a\0b".to_owned()] {
        assert!(
            matches!(with(&|c| c.tag = tag.clone()), Err(FsError::InvalidTag(_))),
            "{tag:?}"
        );
    }
    let missing = share.root.join("missing");
    assert!(matches!(
        with(&|c| c.host_dir = missing.clone()),
        Err(FsError::OpenDir { .. })
    ));
    let file = share.root.join(HELLO);
    assert!(matches!(
        with(&|c| c.host_dir = file.clone()),
        Err(FsError::OpenDir { .. })
    ));
    let not_utf8 = share
        .root
        .join(PathBuf::from(OsString::from_vec(b"\xff".to_vec())));
    fs::create_dir(&not_utf8).unwrap();
    assert!(matches!(
        with(&|c| c.host_dir = not_utf8.clone()),
        Err(FsError::NonUtf8Dir(_))
    ));
    drop(share.payloads());
}

// Requests through the queue-processing function.

#[test]
fn fuse_init_and_lookup_round_trip_through_a_queue() {
    let share = Share::new("workspace");
    let device = share.device();
    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)]).unwrap();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock);

    offer(&mem, &mock, 0, &init_request(1));
    let notify = device.process_queue(&mut queue, &mem).unwrap();
    assert!(notify, "without EVENT_IDX every drain wants an interrupt");
    assert_eq!(used_idx(&mem, &mock), 1);
    let used = used_elem(&mem, &mock, 0);
    assert_eq!(used.id(), 0);
    let (out, init): (OutHeader, InitOut) = reply(&mem, 0);
    assert_eq!(out.error, 0);
    assert_eq!(out.unique, 1);
    assert!(used.len() > 0);
    assert_eq!(used.len(), out.len, "the used length is the reply's");
    assert_eq!(
        out.len as usize,
        size_of::<OutHeader>() + size_of::<InitOut>()
    );
    assert_eq!(init.major, 7);

    offer(&mem, &mock, 1, &lookup_request(2, HELLO));
    device.process_queue(&mut queue, &mem).unwrap();
    assert_eq!(used_idx(&mem, &mock), 2);
    let used = used_elem(&mem, &mock, 1);
    assert_eq!(used.id(), 2, "the second chain's head");
    let (out, entry): (OutHeader, EntryOut) = reply(&mem, 1);
    assert_eq!(out.error, 0);
    assert_eq!(out.unique, 2);
    assert_eq!(used.len(), out.len);
    assert_ne!(entry.nodeid, 0);
    assert_eq!(entry.attr.size, HELLO_BODY.len() as u64);

    // A lookup of a missing name is answered, with ENOENT.
    offer(&mem, &mock, 2, &lookup_request(3, "missing"));
    device.process_queue(&mut queue, &mem).unwrap();
    let (out, _): (OutHeader, EntryOut) = reply(&mem, 2);
    assert_eq!(out.error, -libc::ENOENT);

    // The metrics hook saw every request.
    assert_eq!(device.metrics().count(FUSE_INIT), 1);
    assert_eq!(device.metrics().count(FUSE_LOOKUP), 2);
    assert_eq!(device.metrics().count(FUSE_OPEN), 0);

    drop(device);
    let payloads = share.payloads();
    let mounts: Vec<_> = payloads
        .iter()
        .filter_map(|p| match p {
            Payload::FsMount(m) => Some(m),
            _ => None,
        })
        .collect();
    assert_eq!(mounts.len(), 1, "{payloads:?}");
    assert_eq!(mounts[0].mount, "workspace");
    assert_eq!(mounts[0].guest_path, "/workspace");
    assert_eq!(mounts[0].cache_policy, "auto");
}

#[test]
fn a_malformed_request_gets_an_empty_reply_and_the_queue_keeps_going() {
    let share = Share::new("workspace");
    let device = share.device();
    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)]).unwrap();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock);

    // A chain with no request in it at all: one writable buffer.
    mock.add_desc_chains(
        &[RawDescriptor::from(SplitDescriptor::new(
            reply_addr(0).0,
            REPLY_LEN,
            VRING_DESC_F_WRITE as u16,
            0,
        ))],
        0,
    )
    .unwrap();
    // A request whose header claims a body it does not have.
    let mut truncated = init_request(7);
    truncated.truncate(size_of::<InHeader>() + 4);
    offer(&mem, &mock, 1, &truncated);
    // And a good one after them.
    offer(&mem, &mock, 2, &init_request(8));

    device.process_queue(&mut queue, &mem).unwrap();
    assert_eq!(used_idx(&mem, &mock), 3, "every chain is returned");
    assert_eq!(used_elem(&mem, &mock, 0).len(), 0);
    assert_eq!(used_elem(&mem, &mock, 1).len(), 0);
    let good = used_elem(&mem, &mock, 2);
    assert_eq!(good.id(), 4);
    let (out, _): (OutHeader, InitOut) = reply(&mem, 2);
    assert_eq!(out.error, 0);
    assert_eq!(out.unique, 8);
    assert_eq!(good.len(), out.len);

    drop(device);
    drop(share.payloads());
}

#[test]
fn reset_before_activation_does_nothing() {
    let share = Share::new("workspace");
    let mut device = share.device();
    device.reset();
    device.reset();

    // The filesystem still answers.
    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)]).unwrap();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock);
    offer(&mem, &mock, 0, &init_request(1));
    device.process_queue(&mut queue, &mem).unwrap();
    let (out, _): (OutHeader, InitOut) = reply(&mem, 0);
    assert_eq!(out.error, 0);
    drop(device);
    drop(share.payloads());
}

// The device behind a virtio-mmio transport, with its worker thread.

type Transport = MmioTransport<VirtioFs>;

/// A device in a transport, as the driver sees it, with the handles the
/// VMM (ioeventfds, the irqfd) would otherwise hold.
struct Driver {
    mem: Arc<GuestMemoryMmap>,
    transport: Transport,
    irq: Arc<IrqTrigger>,
    kicks: Vec<EventFd>,
}

/// Where queue `q` behind the transport lives: the mock lays out the
/// descriptor table and the available ring from here, the used ring is
/// ours.
fn queue_start(q: u32) -> GuestAddress {
    GuestAddress(0x1_0000 * (u64::from(q) + 1))
}

/// Queue `q`'s descriptor table, available ring and used ring, where
/// [`queue_mock`] puts them.
fn ring_addrs(q: u32) -> (u64, u64, u64) {
    let start = queue_start(q).0;
    (
        start,
        start + 16 * u64::from(QUEUE_LEN),
        start + USED_RING_OFFSET,
    )
}

/// The driver's view of queue `q` behind the transport. Creating it zeroes
/// the ring indexes, so each test creates it once, before offering.
fn queue_mock(mem: &GuestMemoryMmap, q: u32) -> MockSplitQueue<'_, GuestMemoryMmap> {
    let mock = MockSplitQueue::create(mem, queue_start(q), QUEUE_LEN);
    let (desc, avail, used) = ring_addrs(q);
    assert_eq!(
        (
            mock.desc_table_addr().0,
            mock.avail_addr().0,
            used_ring(&mock).0
        ),
        (desc, avail, used)
    );
    mock
}

impl Driver {
    fn new(device: VirtioFs) -> Driver {
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

    fn status(&mut self) -> u32 {
        self.read(regs::STATUS)
    }

    fn set_status(&mut self, value: u8) {
        self.write(regs::STATUS, u32::from(value));
    }

    /// The Linux driver's handshake, accepting `VIRTIO_F_VERSION_1` only
    /// (so every drain interrupts), with the queues in `ready` marked
    /// ready, up to DRIVER_OK.
    fn handshake(&mut self, ready: &[u32]) {
        assert_eq!(self.read(regs::DEVICE_ID), 26);
        self.set_status(ACKNOWLEDGE);
        self.set_status(ACKNOWLEDGE | DRIVER);
        self.write(regs::DRIVER_FEATURES_SEL, 1);
        self.write(regs::DRIVER_FEATURES, 1);
        self.set_status(ACKNOWLEDGE | DRIVER | FEATURES_OK);
        assert_eq!(self.status(), u32::from(ACKNOWLEDGE | DRIVER | FEATURES_OK));
        for q in 0..2 {
            let (desc, avail, used) = ring_addrs(q);
            self.write(regs::QUEUE_SEL, q);
            assert_eq!(self.read(regs::QUEUE_NUM_MAX), u32::from(QUEUE_MAX_SIZE));
            self.write(regs::QUEUE_NUM, u32::from(QUEUE_LEN));
            for (low, addr) in [
                (regs::QUEUE_DESC_LOW, desc),
                (regs::QUEUE_DRIVER_LOW, avail),
                (regs::QUEUE_DEVICE_LOW, used),
            ] {
                self.write(low, addr as u32);
                self.write(low + 4, (addr >> 32) as u32);
            }
            if ready.contains(&q) {
                self.write(regs::QUEUE_READY, 1);
            }
        }
        self.set_status(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
    }

    /// Kicks queue `q` and waits for its used index to reach `want`.
    fn kick_and_wait(&self, q: u32, want: u16) {
        self.kicks[q as usize].write(1).unwrap();
        let deadline = Instant::now() + WORKER_LIMIT;
        let used = GuestAddress(ring_addrs(q).2);
        while used_idx_at(&self.mem, used) != want {
            assert!(
                Instant::now() < deadline,
                "queue {q} not served: used idx {}, needs reset {}",
                used_idx_at(&self.mem, used),
                self.irq.needs_reset.load(Ordering::SeqCst)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The names of this process's threads.
fn thread_names() -> Vec<String> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|task| fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .map(|name| name.trim_end().to_owned())
        .collect()
}

#[test]
fn a_worker_serves_the_kicked_queue_and_reset_closes_what_the_guest_left_open() {
    let share = Share::new("workspace");
    let mut driver = Driver::new(share.device());
    driver.handshake(&[0, 1]);
    let all_ok = u32::from(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
    assert_eq!(driver.status(), all_ok, "activated");

    // INIT and LOOKUP on the request queue, drained after one kick.
    let mem = driver.mem.clone();
    let mock = queue_mock(&mem, 1);
    offer(&mem, &mock, 0, &init_request(1));
    offer(&mem, &mock, 1, &lookup_request(2, HELLO));
    driver.kick_and_wait(1, 2);
    let (out, entry): (OutHeader, EntryOut) = reply(&mem, 1);
    assert_eq!(out.error, 0);

    // Then a truncating OPEN of what the lookup found.
    let flags = (libc::O_WRONLY | libc::O_TRUNC) as u32;
    offer(&mem, &mock, 2, &open_request(3, entry.nodeid, flags));
    driver.kick_and_wait(1, 3);
    let (out, opened): (OutHeader, OpenOut) = reply(&mem, 2);
    assert_eq!(out.error, 0);
    assert_ne!(opened.fh, 0);

    // The worker interrupted the guest and is named after the share.
    assert!(driver.irq.status.load(Ordering::SeqCst) & 1 != 0);
    assert!(driver.irq.evt.read().unwrap() >= 1);
    assert!(
        thread_names().iter().any(|n| n == "fs-workspace-q1"),
        "{:?}",
        thread_names()
    );

    // The hiprio queue is served by the same worker.
    let hiprio = queue_mock(&mem, 0);
    offer(&mem, &hiprio, 3, &lookup_request(4, "missing"));
    driver.kick_and_wait(0, 1);
    let (out, _): (OutHeader, EntryOut) = reply(&mem, 3);
    assert_eq!(out.error, -libc::ENOENT);

    // The driver resets the device with the file still open: reset joins
    // the worker and the open handle gets its close, hashed, before it
    // returns.
    driver.set_status(0);
    assert_eq!(driver.status(), 0);

    // The log is closed while the device is still alive, so the close
    // below was recorded by the reset, not by dropping the device.
    let payloads = share.payloads();
    drop(driver);
    let close = payloads
        .iter()
        .find_map(|p| match p {
            Payload::FsClose(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no fs.close in {payloads:?}"));
    assert_eq!(close.fh, opened.fh);
    assert_eq!(close.path, format!("/{HELLO}"));
    assert_eq!(close.attrib, Attrib::Handle);
    assert_eq!(close.hash_status, HashStatus::Ok, "O_TRUNC changed it");
    assert_eq!(close.blake3, Some(Hash::from_blake3(blake3::hash(b""))));
    assert!(matches!(payloads[0], Payload::FsMount(_)), "{payloads:?}");
}

#[test]
fn a_corrupt_queue_asks_for_a_reset_and_is_not_served_again() {
    let share = Share::new("corrupt");
    let mut driver = Driver::new(share.device());
    driver.handshake(&[0, 1]);

    // An available index a whole queue ahead of what the ring holds.
    let mem = driver.mem.clone();
    let mock = queue_mock(&mem, 1);
    offer(&mem, &mock, 0, &init_request(1));
    mock.avail().idx().store(u16::to_le(QUEUE_LEN + 1));
    driver.kicks[1].write(1).unwrap();

    let deadline = Instant::now() + WORKER_LIMIT;
    while driver.status() & u32::from(DEVICE_NEEDS_RESET) == 0 {
        assert!(Instant::now() < deadline, "no DEVICE_NEEDS_RESET");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        driver.irq.status.load(Ordering::SeqCst) & 2 != 0,
        "config change"
    );

    // The queue is left alone from now on, however often it is kicked.
    let before = used_idx(&mem, &mock);
    mock.avail().idx().store(u16::to_le(1));
    driver.kicks[1].write(1).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(used_idx(&mem, &mock), before);

    // Reset clears it, and a new handshake serves the queue again.
    driver.set_status(0);
    assert_eq!(driver.status(), 0);
    let used = used_ring(&mock);
    mem.write_obj(0u16, GuestAddress(used.0 + 2)).unwrap();
    mock.avail().idx().store(u16::to_le(0));
    driver.handshake(&[0, 1]);
    offer(&mem, &mock, 0, &init_request(9));
    driver.kick_and_wait(1, 1);
    let (out, _): (OutHeader, InitOut) = reply(&mem, 0);
    assert_eq!((out.error, out.unique), (0, 9));

    driver.set_status(0);
    drop(driver);
    drop(share.payloads());
}

#[test]
fn activation_with_a_queue_that_is_not_ready_fails() {
    // A tag of its own: the other tests' workers run in this process too.
    let share = Share::new("notready");
    let mut driver = Driver::new(share.device());
    driver.handshake(&[1]);
    assert_ne!(
        driver.status() & u32::from(DEVICE_NEEDS_RESET),
        0,
        "the hiprio queue was never made ready"
    );
    assert!(
        !thread_names().iter().any(|n| n == "fs-notready-q1"),
        "no worker started"
    );

    // After a reset the device activates normally.
    driver.set_status(0);
    driver.handshake(&[0, 1]);
    assert_eq!(
        driver.status(),
        u32::from(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK)
    );
    driver.set_status(0);
    drop(driver);
    drop(share.payloads());
}
