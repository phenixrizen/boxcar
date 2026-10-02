// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The virtio-net device (virtio 1.2 section 5.1) in front of [`NetStack`].
//!
//! [`VirtioNet`] is the guest's network card:
//!
//! - device type 1; queue 0 receives ([`RX_QUEUE`]) and queue 1 transmits
//!   ([`TX_QUEUE`]), each at most [`QUEUE_MAX_SIZE`] entries; there is no
//!   control queue;
//! - the features are `VIRTIO_F_VERSION_1`, `VIRTIO_RING_F_EVENT_IDX` and
//!   `VIRTIO_NET_F_MAC`, and no others: no checksum or segmentation
//!   offload, no mergeable receive buffers, no MTU. Every frame is one
//!   whole Ethernet frame of at most [`MAX_FRAME_LEN`] bytes, checksummed
//!   by whoever made it;
//! - the config space is the guest's MAC, 6 bytes, read-only; reads past it
//!   give zeros.
//!
//! Every frame on either queue comes after a 12-byte `virtio_net_hdr_v1`
//! ([`NET_HDR_LEN`]). On TX the device skips it. On RX it writes it, zeroed
//! but for `num_buffers`, which is 1, into the first bytes of one chain,
//! then the frame. A TX frame under [`MIN_FRAME_LEN`] bytes or over
//! [`MAX_FRAME_LEN`] (the header not counted) is dropped, and so is a frame
//! for the guest whose RX chain cannot hold it; each is counted
//! ([`NetCounts`]) and logged at most once a second.
//!
//! The device decides nothing: every frame goes to or comes from the
//! [`NetStack`], which holds the policy, the host sockets and the audit
//! records.
//!
//! # The net thread
//!
//! Activation starts one thread, `net`, which owns the stack. It waits with
//! one `EventManager` on the RX and TX queues' eventfds, a kill eventfd, a
//! timerfd, the device's policy wake ([`VirtioNet::policy_wake`], written
//! after a policy is swapped in, so that the poll below revokes what it
//! denies at once), and the host fds the stack asks for ([`FdChange`]).
//! Each wakeup, in this order:
//!
//! 1. if the driver kicked TX, every chain on the TX queue goes to the
//!    stack and back to the used ring;
//! 2. each ready host fd goes to [`NetStack::on_host_fd_event`];
//! 3. the stack is polled, once;
//! 4. frames for the guest go into free RX chains while there are both.
//!    With no chain free the rest stay in the stack's own bounded queue
//!    (the device keeps none of its own), and the driver is asked to kick
//!    RX when it adds a buffer;
//! 5. the guest is interrupted if either queue's driver wants to hear of
//!    the buffers used;
//! 6. the host fds are watched as the poll asked;
//! 7. the timer is armed for the poll's deadline, or for 1 ms from now if
//!    that has passed ([`REPOLL_DELAY`]), so that a deadline of "now"
//!    never spins the thread. So is it when the stack's queue for the
//!    guest was full and the guest took some: smoltcp waits for room.
//!
//! Readiness is level-triggered, never edge-triggered: the stack reads a
//! bounded number of datagrams for one event and counts on hearing again
//! about what it left.
//!
//! A chain that cannot be read or written is a dropped frame, and the queue
//! goes on. A ring the driver corrupted is fatal for its queue: the device
//! asks for a reset (DEVICE_NEEDS_RESET) and leaves the queue alone until
//! it gets one.
//!
//! [`VirtioDevice::reset`], on the driver's status-0 write and when the VMM
//! stops the VM, sets the thread's stop flag and fires the kill eventfd.
//! The thread then calls [`NetStack::shutdown`], which records the end of
//! every flow, drops the stack, which closes its host sockets, and exits;
//! the reset waits for it at most [`JOIN_LIMIT`]. The VMM must therefore
//! reset the device before it closes the audit writer. A thread that has
//! not stopped by then (its audit records wait on a log that does not
//! drain) is left behind with a warning, and the stop flag keeps it from
//! the rings and the interrupt: it checks the flag before every write to a
//! ring and before every interrupt, and once it is set does nothing but
//! shut the stack down.
//!
//! Flow ids come from one count the device keeps for its whole life
//! (shared with every stack it builds, a left-behind thread's included),
//! so they stay unique in the session's log across a guest's driver reset
//! and re-activation.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use boxcar_audit::AuditSink;
use boxcar_virtio::features::{EVENT_IDX, VERSION_1};
use boxcar_virtio::{ActivateError, ActivatedQueue, IrqTrigger, VirtioDevice};
use event_manager::{
    EventManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId, SubscriberOps,
};
use virtio_bindings::virtio_net::{virtio_net_hdr_v1, VIRTIO_NET_F_MAC};
use virtio_queue::{DescriptorChain, Queue, QueueOwnedT, QueueT, Reader, Writer};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};
use vmm_sys_util::timerfd::TimerFd;

use crate::config::{ConfigError, NetConfig};
use crate::policy::Policy;
use crate::stack::{FdChange, Interest, NetStack, QUEUE_CAP};
use crate::tcp::flow::FlowIds;

/// The virtio device ID of a network card.
pub const DEVICE_TYPE: u32 = virtio_bindings::virtio_ids::VIRTIO_ID_NET;
/// The queue the guest receives frames on.
pub const RX_QUEUE: usize = 0;
/// The queue the guest transmits frames on.
pub const TX_QUEUE: usize = 1;
/// The device's queues: RX and TX, no control queue.
pub const NUM_QUEUES: usize = 2;
/// The largest size of each queue.
pub const QUEUE_MAX_SIZE: u16 = 256;
/// `VIRTIO_NET_F_MAC` as a feature mask: the config space holds the MAC.
pub const NET_F_MAC: u64 = 1 << VIRTIO_NET_F_MAC;
/// The `virtio_net_hdr_v1` before every frame, both ways.
pub const NET_HDR_LEN: usize = 12;
/// The longest frame either way: 1500 bytes of IP and the Ethernet header.
pub const MAX_FRAME_LEN: usize = 1514;
/// The shortest frame the guest may send: an Ethernet header.
pub const MIN_FRAME_LEN: usize = 14;
/// How long [`VirtioDevice::reset`] waits for the net thread to stop.
pub const JOIN_LIMIT: Duration = Duration::from_secs(5);
/// How soon the thread polls again when the deadline the stack gave has
/// passed, or the guest made room in a full queue: never sooner, so that
/// it cannot spin.
pub const REPOLL_DELAY: Duration = Duration::from_millis(1);

const _: () = assert!(mem::size_of::<virtio_net_hdr_v1>() == NET_HDR_LEN);

/// The header before every frame the guest receives: no checksum or GSO
/// information, and the frame in `num_buffers` = 1 buffer (the device
/// MUST say 1 without mergeable buffers).
const RX_HEADER: [u8; NET_HDR_LEN] = {
    let mut header = [0; NET_HDR_LEN];
    header[mem::offset_of!(virtio_net_hdr_v1, num_buffers)] = 1;
    header
};

/// What the device dropped and passed, since it was created.
#[derive(Debug, Default)]
pub struct NetCounters {
    tx_frames: AtomicU64,
    tx_runt: AtomicU64,
    tx_oversize: AtomicU64,
    tx_chain_bad: AtomicU64,
    rx_frames: AtomicU64,
    rx_chain_short: AtomicU64,
    rx_chain_bad: AtomicU64,
}

/// A reading of [`NetCounters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetCounts {
    /// Guest frames handed to the stack.
    pub tx_frames: u64,
    /// Guest frames under [`MIN_FRAME_LEN`] bytes, dropped.
    pub tx_runt: u64,
    /// Guest frames over [`MAX_FRAME_LEN`] bytes, dropped.
    pub tx_oversize: u64,
    /// TX chains that could not be read (outside guest memory), dropped.
    pub tx_chain_bad: u64,
    /// Frames the guest was given.
    pub rx_frames: u64,
    /// Frames for the guest dropped because the RX chain they got was too
    /// small for the header and the frame.
    pub rx_chain_short: u64,
    /// Frames for the guest dropped because their RX chain could not be
    /// written (outside guest memory).
    pub rx_chain_bad: u64,
}

impl NetCounters {
    /// The counts now.
    pub fn snapshot(&self) -> NetCounts {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        NetCounts {
            tx_frames: get(&self.tx_frames),
            tx_runt: get(&self.tx_runt),
            tx_oversize: get(&self.tx_oversize),
            tx_chain_bad: get(&self.tx_chain_bad),
            rx_frames: get(&self.rx_frames),
            rx_chain_short: get(&self.rx_chain_short),
            rx_chain_bad: get(&self.rx_chain_bad),
        }
    }
}

fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The guest's network card, in front of a [`NetStack`].
pub struct VirtioNet {
    cfg: NetConfig,
    sink: AuditSink,
    policy: Arc<ArcSwap<Policy>>,
    /// Written by whoever swaps the policy ([`VirtioNet::policy_wake`]):
    /// the net thread wakes and polls its stack, which revokes what the
    /// new policy denies.
    wake: EventFd,
    /// The config space: the guest's MAC.
    mac: [u8; 6],
    /// The stack the next activation runs, built ahead so that a config the
    /// stack refuses fails [`VirtioNet::new`]. Each activation after a
    /// reset builds a new one.
    spare: Option<NetStack>,
    /// The flow ids of every stack the device builds: one count for the
    /// device's life.
    ids: FlowIds,
    counters: Arc<NetCounters>,
    /// The net thread; `None` when the device is not activated.
    worker: Option<WorkerHandle>,
}

impl VirtioNet {
    /// A network card at `cfg`'s guest MAC, whose stack forwards and
    /// records as `cfg`, `sink` and `policy` say (see [`NetStack::new`]).
    /// The stack is built here: a config it refuses, or DNS upstreams none
    /// of which can be given a socket, fail now.
    pub fn new(
        cfg: NetConfig,
        sink: AuditSink,
        policy: Arc<ArcSwap<Policy>>,
    ) -> Result<VirtioNet, ConfigError> {
        let ids = FlowIds::default();
        let spare =
            NetStack::with_flow_ids(cfg.clone(), sink.clone(), Arc::clone(&policy), ids.clone())?;
        let wake = EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)
            .map_err(|error| ConfigError::Wake(error.to_string()))?;
        Ok(VirtioNet {
            mac: cfg.guest_mac,
            cfg,
            sink,
            policy,
            wake,
            spare: Some(spare),
            ids,
            counters: Arc::new(NetCounters::default()),
            worker: None,
        })
    }

    /// What the device dropped and passed so far.
    pub fn counts(&self) -> NetCounts {
        self.counters.snapshot()
    }

    /// The eventfd to write after storing a new policy in the handle the
    /// stack reads: the net thread, if the device is active, wakes at once
    /// and polls its stack, which revokes what the new policy denies
    /// (`NetStack::poll`). Without the write, that waits for the thread's
    /// next wakeup. A clone shares the eventfd.
    pub fn policy_wake(&self) -> &EventFd {
        &self.wake
    }

    /// The stack for the next activation, counting flow ids on from the
    /// last.
    fn take_stack(&mut self) -> Result<NetStack, ConfigError> {
        match self.spare.take() {
            Some(stack) => Ok(stack),
            None => NetStack::with_flow_ids(
                self.cfg.clone(),
                self.sink.clone(),
                Arc::clone(&self.policy),
                self.ids.clone(),
            ),
        }
    }
}

impl VirtioDevice for VirtioNet {
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
        VERSION_1 | EVENT_IDX | NET_F_MAC
    }

    /// The MAC, and zeros past it.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        let Some(rest) = usize::try_from(offset)
            .ok()
            .and_then(|start| self.mac.get(start..))
        else {
            return;
        };
        let n = rest.len().min(data.len());
        data[..n].copy_from_slice(&rest[..n]);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        boxcar_virtio::limited!(
            warn,
            "virtio-net: the driver wrote {} bytes at {offset:#x} of the read-only config space; \
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
        // address 0.
        if let Some(index) = queues.iter().position(|q| !q.queue.is_valid(&*mem)) {
            return Err(device_error(format!(
                "queue {index} is not ready or does not fit in guest memory"
            )));
        }
        let mut queues = queues.into_iter();
        let (Some(rx), Some(tx)) = (queues.next(), queues.next()) else {
            return Err(device_error("the queues went missing".into()));
        };
        let stack = self
            .take_stack()
            .map_err(|error| ActivateError::Device(error.into()))?;
        let worker = Worker {
            mem,
            irq,
            stack,
            rx: Ring::new(RX_QUEUE, rx),
            tx: Ring::new(TX_QUEUE, tx),
            kill: EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)?,
            wake: self.wake.try_clone()?,
            timer: TimerFd::new().map_err(io::Error::from)?,
            counters: Arc::clone(&self.counters),
            stop: StopFlag::default(),
            watched: HashMap::new(),
            tokens: HashMap::new(),
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

impl Drop for VirtioNet {
    fn drop(&mut self) {
        // No thread may outlive the device.
        self.reset();
    }
}

fn device_error(message: String) -> ActivateError {
    ActivateError::Device(message.into())
}

// Moving frames.

/// Takes every frame the driver has queued on the TX queue, hands it to
/// `stack`, each frame without its header, and returns each to the used
/// ring with nothing written. Returns whether the driver wants an
/// interrupt.
///
/// It drains with [`boxcar_virtio::drain_queue_until`], stopping as soon as
/// `stop` is set: handing a frame to the stack can wait on the audit log,
/// and a reset may come meanwhile; once it has come the ring is touched no
/// more.
///
/// An `Err` means the ring is unusable: it announces chains that cannot be
/// popped, or its used ring or notification fields cannot be written.
pub(crate) fn transmit(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    stack: &mut NetStack,
    counters: &NetCounters,
    stop: &StopFlag,
) -> Result<bool, virtio_queue::Error> {
    let mut frame = Vec::with_capacity(MAX_FRAME_LEN);
    boxcar_virtio::drain_queue_until(
        queue,
        mem,
        || stop.is_set(),
        |chain| {
            hand_over(mem, chain, &mut frame, stack, counters);
            Ok::<u32, virtio_queue::Error>(0)
        },
    )
}

/// Gives `stack` the frame in a TX `chain`, or counts and logs why not.
/// `frame` is scratch space.
fn hand_over(
    mem: &GuestMemoryMmap,
    chain: DescriptorChain<&GuestMemoryMmap>,
    frame: &mut Vec<u8>,
    stack: &mut NetStack,
    counters: &NetCounters,
) {
    match read_tx(mem, chain, frame) {
        Ok(()) => {
            count(&counters.tx_frames);
            stack.push_guest_frame(frame);
        }
        Err(TxDrop::Runt(len)) => {
            count(&counters.tx_runt);
            boxcar_virtio::limited!(
                warn,
                "virtio-net: the guest sent a {len}-byte frame, shorter than an Ethernet \
                 header; dropped"
            );
        }
        Err(TxDrop::Oversize(len)) => {
            count(&counters.tx_oversize);
            boxcar_virtio::limited!(
                warn,
                "virtio-net: the guest sent a {len}-byte frame, longer than \
                 {MAX_FRAME_LEN}; dropped"
            );
        }
        Err(TxDrop::Unreadable(error)) => {
            count(&counters.tx_chain_bad);
            boxcar_virtio::limited!(
                warn,
                "virtio-net: cannot read a frame the guest sent: {error}; dropped"
            );
        }
    }
}

/// Why a guest frame was dropped.
enum TxDrop {
    /// Shorter than [`MIN_FRAME_LEN`]: the frame's length.
    Runt(usize),
    /// Longer than [`MAX_FRAME_LEN`]: the frame's length.
    Oversize(usize),
    /// The chain is not in guest memory, or ended early.
    Unreadable(String),
}

/// Reads the frame in a TX `chain` into `frame`, without the header.
fn read_tx(
    mem: &GuestMemoryMmap,
    chain: DescriptorChain<&GuestMemoryMmap>,
    frame: &mut Vec<u8>,
) -> Result<(), TxDrop> {
    let mut reader: Reader<'_> = chain
        .reader(mem)
        .map_err(|error| TxDrop::Unreadable(error.to_string()))?;
    let len = reader.available_bytes().saturating_sub(NET_HDR_LEN);
    if len < MIN_FRAME_LEN {
        return Err(TxDrop::Runt(len));
    }
    if len > MAX_FRAME_LEN {
        return Err(TxDrop::Oversize(len));
    }
    let unreadable = |error: io::Error| TxDrop::Unreadable(error.to_string());
    let mut header = [0; NET_HDR_LEN];
    reader.read_exact(&mut header).map_err(unreadable)?;
    frame.clear();
    frame.resize(len, 0);
    reader.read_exact(frame).map_err(unreadable)
}

/// Gives the guest the frames `stack` has for it, each with its header in
/// a chain of its own, for as long as there are both frames and chains on
/// the RX `queue`. With frames left and no chain, the driver is asked to
/// notify the queue when it adds a buffer, and the frames stay in the
/// stack's queue. Returns how many chains were used, including any given
/// back empty because the frame did not fit. Once `stop` is set it touches
/// the ring no more. An `Err` means the ring is unusable: it announces
/// chains that cannot be popped, or its used ring cannot be written.
pub(crate) fn deliver(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    stack: &mut NetStack,
    counters: &NetCounters,
    stop: &StopFlag,
) -> Result<usize, virtio_queue::Error> {
    let mut used = 0;
    // Consecutive times the ring announced a buffer that could not be
    // popped: once is a race with the driver, twice a broken ring.
    let mut idle = 0;
    while !stop.is_set() && stack.host_frames() > 0 {
        let Some(chain) = queue.pop_descriptor_chain(mem) else {
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
        let Some(frame) = stack.pop_host_frame() else {
            // Unreachable: the stack said it had a frame. The chain goes
            // back for the next one.
            queue.go_to_previous_position();
            break;
        };
        let len = write_rx(mem, chain, &frame, counters);
        queue.add_used(mem, head, len)?;
        used += 1;
    }
    Ok(used)
}

/// Writes the header and `frame` into an RX `chain`, and returns how many
/// bytes it wrote: none when the chain cannot hold both, and the frame is
/// dropped.
fn write_rx(
    mem: &GuestMemoryMmap,
    chain: DescriptorChain<&GuestMemoryMmap>,
    frame: &[u8],
    counters: &NetCounters,
) -> u32 {
    let mut writer: Writer<'_> = match chain.writer(mem) {
        Ok(writer) => writer,
        Err(error) => {
            count(&counters.rx_chain_bad);
            boxcar_virtio::limited!(
                warn,
                "virtio-net: cannot use an RX buffer: {error}; a frame for the guest is dropped"
            );
            return 0;
        }
    };
    let len = NET_HDR_LEN + frame.len();
    let room = writer.available_bytes();
    if room < len {
        count(&counters.rx_chain_short);
        boxcar_virtio::limited!(
            warn,
            "virtio-net: an RX buffer of {room} bytes cannot hold a {len}-byte frame and header; \
             the frame is dropped"
        );
        return 0;
    }
    let written = writer
        .write_all(&RX_HEADER)
        .and_then(|()| writer.write_all(frame));
    if let Err(error) = written {
        count(&counters.rx_chain_bad);
        boxcar_virtio::limited!(
            warn,
            "virtio-net: cannot write an RX buffer: {error}; a frame for the guest is dropped"
        );
        return 0;
    }
    count(&counters.rx_frames);
    // At most the header and a frame the link can carry.
    u32::try_from(len).unwrap_or(u32::MAX)
}

// The net thread.

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

    /// Takes the driver's kick, if there is one.
    fn take_kick(&self) {
        if let Err(error) = self.evt.read() {
            if error.kind() != io::ErrorKind::WouldBlock {
                boxcar_virtio::limited!(warn, "virtio-net: queue {} eventfd: {error}", self.index);
            }
        }
    }

    /// Stops serving the queue after `error`, and asks the driver for a
    /// reset, unless the device is being reset already (`stop`).
    fn fail(&mut self, irq: &IrqTrigger, stop: &StopFlag, error: virtio_queue::Error) {
        boxcar_virtio::limited!(
            error,
            "virtio-net: queue {} cannot be served: {error}; asking the driver to reset the \
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
                "virtio-net: cannot signal the reset request: {error}"
            );
        }
    }
}

/// Set by [`VirtioDevice::reset`] before it waits for the net thread. From
/// then on the thread writes to neither ring and raises no interrupt: the
/// queues and the interrupt are the driver's again, whether or not the
/// reset waited long enough to join the thread.
#[derive(Clone, Debug, Default)]
pub(crate) struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What one wait found. The `EventManager` hands each ready fd to this,
/// and the worker takes them in its order once the wait is over.
#[derive(Default)]
struct Ready(Vec<(RawFd, EventSet)>);

impl MutEventSubscriber for Ready {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        self.0.push((events.fd(), events.event_set()));
    }

    /// The fds are registered by [`spawn`] and by the worker.
    fn init(&mut self, _ops: &mut EventOps) {}
}

/// The net thread's state.
struct Worker {
    mem: Arc<GuestMemoryMmap>,
    irq: Arc<IrqTrigger>,
    stack: NetStack,
    rx: Ring,
    tx: Ring,
    kill: EventFd,
    /// The device's policy wake ([`VirtioNet::policy_wake`]): a poll is due.
    wake: EventFd,
    /// Armed for the stack's next deadline. It is only read after the wait
    /// found it readable, and it is not re-armed in between, so the read
    /// does not block.
    timer: TimerFd,
    counters: Arc<NetCounters>,
    /// Set when the device is reset: see [`StopFlag`].
    stop: StopFlag,
    /// The host fd watched for each of the stack's tokens.
    watched: HashMap<u64, RawFd>,
    /// The token of each watched host fd.
    tokens: HashMap<RawFd, u64>,
}

impl Worker {
    /// Handles what one wait found. Returns `false` when the device is
    /// being reset (the kill eventfd fired, or the stop flag is set) and
    /// the thread is to stop.
    fn wakeup(
        &mut self,
        manager: &mut EventManager<Ready>,
        id: SubscriberId,
        ready: &[(RawFd, EventSet)],
    ) -> bool {
        let kill = self.kill.as_raw_fd();
        if self.stop.is_set() || ready.iter().any(|&(fd, _)| fd == kill) {
            return false;
        }
        let mut tx_kicked = false;
        let mut host = Vec::new();
        for &(fd, set) in ready {
            if fd == self.tx.evt.as_raw_fd() {
                self.tx.take_kick();
                tx_kicked = true;
            } else if fd == self.rx.evt.as_raw_fd() {
                // Delivery runs at every wakeup; the kick only wakes it.
                self.rx.take_kick();
            } else if fd == self.timer.as_raw_fd() {
                if let Err(error) = self.timer.wait() {
                    boxcar_virtio::limited!(warn, "virtio-net: the timer: {error}");
                }
            } else if fd == self.wake.as_raw_fd() {
                // The poll every cycle makes is what was asked for.
                if let Err(error) = self.wake.read() {
                    boxcar_virtio::limited!(warn, "virtio-net: the policy wake: {error}");
                }
            } else if let Some(&token) = self.tokens.get(&fd) {
                // An error or a hang-up is both: the stack finds out which.
                let failed = set.intersects(EventSet::ERROR | EventSet::HANG_UP);
                let readable = failed || set.intersects(EventSet::IN | EventSet::READ_HANG_UP);
                let writable = failed || set.contains(EventSet::OUT);
                host.push((token, readable, writable));
            }
        }
        self.cycle(manager, id, tx_kicked, &host)
    }

    /// One turn of the loop: the steps of the module docs. Returns `false`,
    /// having stopped short, when the stop flag was set meanwhile: handing
    /// frames and fd events to the stack, and polling it, can wait on the
    /// audit log.
    fn cycle(
        &mut self,
        manager: &mut EventManager<Ready>,
        id: SubscriberId,
        tx_kicked: bool,
        host: &[(u64, bool, bool)],
    ) -> bool {
        let mut interrupt = false;
        if tx_kicked && !self.tx.failed {
            match transmit(
                &mut self.tx.queue,
                &self.mem,
                &mut self.stack,
                &self.counters,
                &self.stop,
            ) {
                Ok(notify) => interrupt |= notify,
                Err(error) => self.tx.fail(&self.irq, &self.stop, error),
            }
        }
        for &(token, readable, writable) in host {
            self.stack.on_host_fd_event(token, readable, writable);
        }
        let now = Instant::now();
        let outcome = self.stack.poll(now);
        let mut deadline = outcome.next_deadline;
        if self.stop.is_set() {
            return false;
        }
        if !self.rx.failed {
            let was_full = self.stack.host_frames() >= QUEUE_CAP;
            match deliver(
                &mut self.rx.queue,
                &self.mem,
                &mut self.stack,
                &self.counters,
                &self.stop,
            ) {
                Ok(0) => {}
                Ok(_) => {
                    deadline = after_delivery(deadline, was_full, now);
                    match self.rx.queue.needs_notification(&*self.mem) {
                        Ok(notify) => interrupt |= notify,
                        Err(error) => self.rx.fail(&self.irq, &self.stop, error),
                    }
                }
                Err(error) => self.rx.fail(&self.irq, &self.stop, error),
            }
        }
        if self.stop.is_set() {
            return false;
        }
        if interrupt {
            if let Err(error) = self.irq.signal_used_queue() {
                boxcar_virtio::limited!(error, "virtio-net: cannot interrupt the guest: {error}");
            }
        }
        match manager.event_ops(id) {
            Ok(mut ops) => self.watch(&mut ops, &outcome.fd_changes),
            Err(error) => {
                boxcar_virtio::limited!(
                    error,
                    "virtio-net: cannot change the watched fds: {error}"
                );
            }
        }
        self.arm(deadline);
        true
    }

    /// Starts, changes and stops watching host fds as `changes` say. A
    /// change with no interest stops watching its token's fd, if it was
    /// watched; the first change with interest for a token starts watching
    /// it; a later one changes what it is watched for. The stack asks to
    /// stop watching an fd before it closes it, and this relies on that:
    /// event-manager 0.4.2 keeps an fd it failed to remove (one already
    /// closed) in its table, and would refuse to watch that fd number
    /// again.
    fn watch(&mut self, ops: &mut EventOps, changes: &[FdChange]) {
        for change in changes {
            let FdChange {
                token,
                fd,
                interest,
            } = *change;
            match (self.watched.get(&token).copied(), event_set(interest)) {
                (None, None) => {}
                (Some(old), None) => self.unwatch(ops, token, old),
                (Some(old), Some(set)) if old == fd => {
                    if let Err(error) = ops.modify(Events::new_raw(fd, set)) {
                        boxcar_virtio::limited!(
                            warn,
                            "virtio-net: cannot change how host fd {fd} is watched: {error}"
                        );
                    }
                }
                (Some(old), Some(set)) => {
                    self.unwatch(ops, token, old);
                    self.start_watching(ops, token, fd, set);
                }
                (None, Some(set)) => self.start_watching(ops, token, fd, set),
            }
        }
    }

    fn start_watching(&mut self, ops: &mut EventOps, token: u64, fd: RawFd, set: EventSet) {
        // Not reached while the stack unwatches its fds before closing
        // them: an fd still watched for another token is that token's no
        // more.
        if let Some(stale) = self.tokens.get(&fd).copied() {
            self.unwatch(ops, stale, fd);
        }
        match ops.add(Events::new_raw(fd, set)) {
            Ok(()) => {
                self.watched.insert(token, fd);
                self.tokens.insert(fd, token);
            }
            Err(error) => boxcar_virtio::limited!(
                warn,
                "virtio-net: cannot watch host fd {fd} (token {token:#x}): {error}"
            ),
        }
    }

    fn unwatch(&mut self, ops: &mut EventOps, token: u64, fd: RawFd) {
        self.watched.remove(&token);
        self.tokens.remove(&fd);
        if let Err(error) = ops.remove(Events::empty_raw(fd)) {
            boxcar_virtio::limited!(
                warn,
                "virtio-net: cannot stop watching host fd {fd}: {error}"
            );
        }
    }

    /// Arms the timer for `deadline` (see [`timer_delay`]), or disarms it
    /// for none.
    fn arm(&mut self, deadline: Option<Instant>) {
        let armed = match timer_delay(deadline, Instant::now()) {
            None => self.timer.clear(),
            Some(after) => self.timer.reset(after, None),
        };
        if let Err(error) = armed {
            boxcar_virtio::limited!(
                error,
                "virtio-net: cannot arm the net thread's timer: {error}"
            );
        }
    }
}

/// The deadline after a delivery, from the poll's `deadline`: smoltcp
/// takes nothing while the guest's queue is full, so when it `was_full` at
/// the poll (`now`) and the guest has taken some since, the stack is polled
/// again as soon as the thread may.
fn after_delivery(deadline: Option<Instant>, was_full: bool, now: Instant) -> Option<Instant> {
    if was_full {
        Some(deadline.map_or(now, |at| at.min(now)))
    } else {
        deadline
    }
}

/// How long the timer runs for `deadline`, from `now`: until the deadline,
/// but [`REPOLL_DELAY`] for one that has passed, so that the thread never
/// spins on a deadline of "now"; `None` for no deadline.
fn timer_delay(deadline: Option<Instant>, now: Instant) -> Option<Duration> {
    let at = deadline?;
    Some(if at <= now { REPOLL_DELAY } else { at - now })
}

/// What to watch an fd for, or `None` to stop watching it.
fn event_set(interest: Interest) -> Option<EventSet> {
    let mut set = EventSet::empty();
    if interest.readable {
        set |= EventSet::IN;
    }
    if interest.writable {
        set |= EventSet::OUT;
    }
    (!set.is_empty()).then_some(set)
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
        worker.timer.as_raw_fd(),
        worker.wake.as_raw_fd(),
    ] {
        // Level-triggered: no EventSet::EDGE_TRIGGERED, here or anywhere.
        ops.add(Events::new_raw(fd, EventSet::IN))
            .map_err(manager_error)?;
    }
    let (stopped, done) = mpsc::channel::<()>();
    let thread = thread::Builder::new().name("net".into()).spawn(move || {
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

/// The net thread: waits and handles what it finds until the kill eventfd
/// fires, then shuts the stack down.
fn run(mut manager: EventManager<Ready>, id: SubscriberId, mut worker: Worker) {
    let irq = Arc::clone(&worker.irq);
    let stop = worker.stop.clone();
    let _panic = PanicGuard {
        irq: &irq,
        stop: &stop,
    };
    // Chains the driver queued before the thread started, and the first
    // poll, which asks for the DNS socket to be watched.
    let mut running = worker.cycle(&mut manager, id, true, &[]);
    while running {
        if let Err(error) = manager.run() {
            boxcar_virtio::limited!(
                error,
                "virtio-net: the net thread cannot wait for events: {error}; asking the driver \
                 to reset the device"
            );
            if !stop.is_set() {
                if let Err(error) = irq.signal_needs_reset() {
                    boxcar_virtio::limited!(
                        error,
                        "virtio-net: cannot signal the reset request: {error}"
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
    // Every flow's end is recorded; dropping the worker closes the sockets.
    worker.stack.shutdown();
}

/// Asks the driver for a reset when the net thread panics, so the guest
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
                "virtio-net: the net thread panicked; asking the driver to reset the device"
            );
            if let Err(error) = self.irq.signal_needs_reset() {
                boxcar_virtio::limited!(
                    error,
                    "virtio-net: cannot signal the reset request: {error}"
                );
            }
        }
    }
}

/// The running net thread.
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
            boxcar_virtio::limited!(error, "virtio-net: cannot stop the net thread: {error}");
        }
        match self.done.recv_timeout(JOIN_LIMIT) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                if self.thread.join().is_err() {
                    boxcar_virtio::limited!(error, "virtio-net: the net thread panicked");
                }
            }
            Err(RecvTimeoutError::Timeout) => boxcar_virtio::limited!(
                warn,
                "virtio-net: the net thread did not stop within {JOIN_LIMIT:?}; leaving it behind"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::UdpSocket;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    use boxcar_audit::{WriterConfig, WriterHandle};
    use boxcar_proto::SessionId;
    use boxcar_virtio::features::{EVENT_IDX, VERSION_1};
    use boxcar_virtio::mmio::regs;
    use boxcar_virtio::status::{ACKNOWLEDGE, DRIVER, DRIVER_OK, FEATURES_OK};
    use boxcar_virtio::testing::{guest_memory, read_u32, write_u32, TEST_SLOT};
    use boxcar_virtio::{DeviceContext, MmioTransport};
    use std::net::{Ipv4Addr, SocketAddrV4};

    use boxcar_audit::LogReader;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
        EthernetRepr, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
        TcpSeqNumber,
    };
    use tempfile::TempDir;
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::desc::split::{Descriptor as SplitDescriptor, VirtqUsedElem};
    use virtio_queue::desc::RawDescriptor;
    use virtio_queue::mock::MockSplitQueue;
    use virtio_queue::{Queue, QueueT};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::config::{GATEWAY_IP, GATEWAY_MAC, GUEST_IP, GUEST_MAC};

    /// Guest RAM for every test: 1 MiB at guest physical address 0.
    const GUEST_MEM_SIZE: usize = 0x10_0000;
    /// Size of every mock queue.
    const QUEUE_LEN: u16 = 16;
    /// Where the used ring of a mock queue goes, from its start. The mock
    /// places its own used ring over the end of its available ring; one of
    /// our own keeps the two apart.
    const USED_RING_OFFSET: u64 = 0x800;
    /// Frame buffers, 0x1000 apart.
    const BUFFERS: u64 = 0x4_0000;
    /// The length of a guest RX buffer: what Linux posts without mergeable
    /// buffers (1518 bytes of frame and the header), rounded up.
    const RX_BUF_LEN: u32 = 0x800;
    /// How long the net thread has to answer a kick.
    const THREAD_LIMIT: Duration = Duration::from_secs(5);

    /// An audit session, and the local socket the stack forwards DNS to,
    /// which nothing reads: no query leaves the host.
    struct Session {
        _dir: TempDir,
        sink: AuditSink,
        writer: WriterHandle,
        upstream: UdpSocket,
    }

    impl Session {
        fn new() -> Session {
            let dir = TempDir::new().unwrap();
            let (sink, writer) =
                boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new()))
                    .unwrap();
            Session {
                _dir: dir,
                sink,
                writer,
                upstream: UdpSocket::bind("127.0.0.1:0").unwrap(),
            }
        }

        fn config(&self) -> NetConfig {
            NetConfig {
                dns_upstreams: vec![self.upstream.local_addr().unwrap()],
                ..NetConfig::default()
            }
        }

        fn policy() -> Arc<ArcSwap<Policy>> {
            Arc::new(ArcSwap::from_pointee(Policy::default()))
        }

        fn stack(&self) -> NetStack {
            NetStack::new(self.config(), self.sink.clone(), Session::policy()).unwrap()
        }

        fn device(&self) -> VirtioNet {
            VirtioNet::new(self.config(), self.sink.clone(), Session::policy()).unwrap()
        }

        fn close(self) {
            drop(self.sink);
            self.writer.close().unwrap();
        }

        /// Closes the log and returns its records.
        fn records(self) -> Vec<boxcar_proto::Record> {
            let Session {
                _dir: dir,
                sink,
                writer,
                ..
            } = self;
            let session = writer.session_dir().to_owned();
            drop(sink);
            writer.close().unwrap();
            let records = LogReader::open(&session)
                .unwrap()
                .records()
                .map(Result::unwrap)
                .collect();
            drop(dir);
            records
        }
    }

    /// A stop flag that is not set: the thread goes on.
    fn going() -> StopFlag {
        StopFlag::default()
    }

    /// The guest's SYN from its `port` to `dst`, through the gateway.
    fn syn(port: u16, dst: SocketAddrV4) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port: port,
            dst_port: dst.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65_535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: GUEST_IP,
            dst_addr: *dst.ip(),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let eth = EthernetRepr {
            src_addr: EthernetAddress(GUEST_MAC),
            dst_addr: EthernetAddress(GATEWAY_MAC),
            ethertype: EthernetProtocol::Ipv4,
        };
        let mut buf = vec![0; eth.buffer_len() + ip.buffer_len() + tcp.buffer_len()];
        let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
        eth.emit(&mut frame);
        let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip.emit(&mut packet, &ChecksumCapabilities::default());
        tcp.emit(
            &mut TcpPacket::new_unchecked(packet.payload_mut()),
            &GUEST_IP.into(),
            &(*dst.ip()).into(),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    /// The guest asking who has the gateway's address, padded with zeros
    /// to `len` bytes if it is shorter.
    fn arp_request(len: usize) -> Vec<u8> {
        let arp = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress(GUEST_MAC),
            source_protocol_addr: GUEST_IP,
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: GATEWAY_IP,
        };
        let eth = EthernetRepr {
            src_addr: EthernetAddress(GUEST_MAC),
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
        };
        let mut buf = vec![0; eth.buffer_len() + arp.buffer_len()];
        let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
        eth.emit(&mut frame);
        arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
        if buf.len() < len {
            buf.resize(len, 0);
        }
        buf
    }

    /// Whether `frame` is the gateway's ARP reply to the guest.
    fn is_gateway_arp_reply(frame: &[u8]) -> bool {
        let Ok(eth) = EthernetFrame::new_checked(frame) else {
            return false;
        };
        let Ok(arp) = ArpPacket::new_checked(eth.payload()) else {
            return false;
        };
        eth.src_addr() == EthernetAddress(GATEWAY_MAC)
            && eth.dst_addr() == EthernetAddress(GUEST_MAC)
            && eth.ethertype() == EthernetProtocol::Arp
            && arp.operation() == ArpOperation::Reply
            && arp.source_hardware_addr() == GATEWAY_MAC
    }

    /// A virtio-net header, as the guest's driver writes it on TX: all
    /// zeros (no checksum offload, no GSO).
    fn tx_header() -> [u8; NET_HDR_LEN] {
        [0; NET_HDR_LEN]
    }

    fn buffer(n: u16) -> GuestAddress {
        GuestAddress(BUFFERS + 0x1000 * u64::from(n))
    }

    /// The queue the device would be handed for `mock`, with our used ring.
    fn device_queue(mock: &MockSplitQueue<'_, GuestMemoryMmap>) -> Queue {
        let mut queue: Queue = mock.create_queue().unwrap();
        let used = used_ring(mock).0;
        queue.set_used_ring_address(Some(used as u32), Some((used >> 32) as u32));
        queue
    }

    fn used_ring(mock: &MockSplitQueue<'_, GuestMemoryMmap>) -> GuestAddress {
        GuestAddress(mock.start().0 + USED_RING_OFFSET)
    }

    fn used_idx_at(mem: &GuestMemoryMmap, used_ring: GuestAddress) -> u16 {
        u16::from_le(mem.read_obj(GuestAddress(used_ring.0 + 2)).unwrap())
    }

    fn used_idx(mem: &GuestMemoryMmap, mock: &MockSplitQueue<'_, GuestMemoryMmap>) -> u16 {
        used_idx_at(mem, used_ring(mock))
    }

    fn used_elem_at(mem: &GuestMemoryMmap, used_ring: GuestAddress, index: u64) -> VirtqUsedElem {
        mem.read_obj(GuestAddress(used_ring.0 + 4 + 8 * index))
            .unwrap()
    }

    fn used_elem(
        mem: &GuestMemoryMmap,
        mock: &MockSplitQueue<'_, GuestMemoryMmap>,
        index: u64,
    ) -> VirtqUsedElem {
        used_elem_at(mem, used_ring(mock), index)
    }

    /// Offers `parts` on a TX queue as one chain of readable descriptors,
    /// one descriptor a part, from descriptor `head` on, each part in its
    /// own buffer from buffer `head` on.
    fn offer_tx(
        mem: &GuestMemoryMmap,
        mock: &MockSplitQueue<'_, GuestMemoryMmap>,
        head: u16,
        parts: &[&[u8]],
    ) {
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

    /// Offers RX buffer `n` (`len` bytes, device-writable) on an RX queue as
    /// a chain of one descriptor, descriptor `n`. The buffer is filled with
    /// 0xaa first, so what the device wrote shows.
    fn offer_rx(
        mem: &GuestMemoryMmap,
        mock: &MockSplitQueue<'_, GuestMemoryMmap>,
        n: u16,
        len: u32,
    ) {
        mem.write_slice(&vec![0xaa; len as usize], buffer(n))
            .unwrap();
        mock.add_desc_chains(
            &[RawDescriptor::from(SplitDescriptor::new(
                buffer(n).0,
                len,
                VRING_DESC_F_WRITE as u16,
                0,
            ))],
            n,
        )
        .unwrap();
    }

    /// The `len` bytes the device wrote into RX buffer `n`.
    fn rx_bytes(mem: &GuestMemoryMmap, n: u16, len: u32) -> Vec<u8> {
        let mut bytes = vec![0; len as usize];
        mem.read_slice(&mut bytes, buffer(n)).unwrap();
        bytes
    }

    /// Offers one RX chain of device-writable descriptors of `lens` bytes,
    /// from descriptor and buffer `head` on, each filled with 0xaa.
    fn offer_rx_chain(
        mem: &GuestMemoryMmap,
        mock: &MockSplitQueue<'_, GuestMemoryMmap>,
        head: u16,
        lens: &[u32],
    ) {
        let descs: Vec<RawDescriptor> = lens
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                let n = head + i as u16;
                mem.write_slice(&vec![0xaa; len as usize], buffer(n))
                    .unwrap();
                let last = i + 1 == lens.len();
                let next = if last { 0 } else { VRING_DESC_F_NEXT as u16 };
                RawDescriptor::from(SplitDescriptor::new(
                    buffer(n).0,
                    len,
                    VRING_DESC_F_WRITE as u16 | next,
                    if last { 0 } else { n + 1 },
                ))
            })
            .collect();
        mock.add_desc_chains(&descs, head).unwrap();
    }

    /// The bytes of the RX chain `offer_rx_chain(head, lens)` made, end to
    /// end.
    fn rx_chain_bytes(mem: &GuestMemoryMmap, head: u16, lens: &[u32]) -> Vec<u8> {
        lens.iter()
            .enumerate()
            .flat_map(|(i, &len)| rx_bytes(mem, head + i as u16, len))
            .collect()
    }

    /// The header the device puts before every frame it gives the guest:
    /// zeros, but `num_buffers` (the last two bytes) 1.
    const RX_HEADER: [u8; NET_HDR_LEN] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];

    fn new_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)]).unwrap()
    }

    // The device's identity.

    #[test]
    fn the_device_is_virtio_net_with_two_queues_a_mac_and_no_offloads() {
        let session = Session::new();
        let mut device = session.device();
        assert_eq!(device.device_type(), 1);
        assert_eq!(device.num_queues(), 2);
        assert_eq!(device.queue_max_size(RX_QUEUE), 256);
        assert_eq!(device.queue_max_size(TX_QUEUE), 256);
        assert_eq!(device.queue_max_size(2), 0);
        assert_eq!(
            device.avail_features(),
            VERSION_1 | EVENT_IDX | (1 << 5),
            "VERSION_1, EVENT_IDX and NET_F_MAC only"
        );

        let mut mac = [0xaa; 6];
        device.read_config(0, &mut mac);
        assert_eq!(mac, [0x02, 0x62, 0x6f, 0x78, 0x00, 0x01]);
        // Byte by byte, as Linux reads it.
        let bytes: Vec<u8> = (0..6)
            .map(|offset| {
                let mut b = [0xaa];
                device.read_config(offset, &mut b);
                b[0]
            })
            .collect();
        assert_eq!(bytes, GUEST_MAC);
        // Past the MAC, zeros, also when a read straddles its end.
        let mut past = [0xaa; 4];
        device.read_config(6, &mut past);
        assert_eq!(past, [0; 4]);
        let mut straddle = [0xaa; 4];
        device.read_config(4, &mut straddle);
        assert_eq!(straddle, [0x00, 0x01, 0, 0]);
        device.read_config(u64::MAX, &mut past);
        assert_eq!(past, [0; 4]);
        // The MAC cannot be written.
        device.write_config(0, &[0xff; 6]);
        device.read_config(0, &mut mac);
        assert_eq!(mac, GUEST_MAC);
        assert_eq!(NET_HDR_LEN, 12);
        drop(device);
        session.close();
    }

    // TX and RX on mock queues, without the thread.

    #[test]
    fn a_tx_chain_reaches_the_stack() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);

        // The header and the frame in one descriptor, then split across
        // two, as Linux may send them.
        let request = arp_request(0);
        let whole = [&tx_header()[..], &request[..]].concat();
        offer_tx(&mem, &mock, 0, &[&whole]);
        offer_tx(&mem, &mock, 2, &[&tx_header(), &request]);
        let notify = transmit(&mut queue, &mem, &mut stack, &counters, &going()).unwrap();
        assert!(notify, "without EVENT_IDX every drain wants an interrupt");

        assert_eq!(used_idx(&mem, &mock), 2, "both chains are given back");
        for (index, head) in [(0, 0), (1, 2)] {
            let used = used_elem(&mem, &mock, index);
            assert_eq!(used.id(), head);
            assert_eq!(used.len(), 0, "TX buffers are only read");
        }
        assert_eq!(counters.snapshot().tx_frames, 2);

        // The stack got both requests, without their headers: it answers
        // each with the gateway's MAC.
        let replies: Vec<Vec<u8>> = std::iter::from_fn(|| stack.pop_host_frame()).collect();
        assert_eq!(replies.len(), 2, "{replies:?}");
        for reply in &replies {
            assert!(is_gateway_arp_reply(reply), "{reply:?}");
        }
        drop(stack);
        session.close();
    }

    #[test]
    fn a_stack_frame_lands_in_an_rx_chain_with_the_header() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);

        stack.push_guest_frame(&arp_request(0));
        assert_eq!(stack.host_frames(), 1);
        offer_rx(&mem, &mock, 0, RX_BUF_LEN);
        let delivered = deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap();
        assert_eq!(delivered, 1);
        assert_eq!(stack.host_frames(), 0);

        assert_eq!(used_idx(&mem, &mock), 1);
        let used = used_elem(&mem, &mock, 0);
        assert_eq!(used.id(), 0);
        let len = used.len();
        let bytes = rx_bytes(&mem, 0, RX_BUF_LEN);
        assert_eq!(bytes[..NET_HDR_LEN], RX_HEADER, "zeroed, num_buffers 1");
        let frame = &bytes[NET_HDR_LEN..len as usize];
        assert!(is_gateway_arp_reply(frame), "{frame:?}");
        assert_eq!(len as usize, NET_HDR_LEN + frame.len());
        assert!(
            bytes[len as usize..].iter().all(|&b| b == 0xaa),
            "nothing written past the frame"
        );
        assert_eq!(counters.snapshot().rx_frames, 1);
        drop(stack);
        session.close();
    }

    #[test]
    fn rx_without_free_buffers_is_queued_then_delivered() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);
        queue.set_event_idx(true);

        // Three replies, no buffer: nothing moves, the frames stay in the
        // stack's own queue, and the driver is asked to say when it adds a
        // buffer (avail_event is where the device stopped).
        for _ in 0..3 {
            stack.push_guest_frame(&arp_request(0));
        }
        assert_eq!(
            deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap(),
            0
        );
        assert_eq!(stack.host_frames(), 3);
        assert_eq!(used_idx(&mem, &mock), 0);
        let avail_event = GuestAddress(used_ring(&mock).0 + 4 + 8 * u64::from(QUEUE_LEN));
        mem.write_obj(0xffffu16, avail_event).unwrap();
        assert_eq!(
            deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap(),
            0
        );
        assert_eq!(u16::from_le(mem.read_obj(avail_event).unwrap()), 0);

        // Two buffers: two frames, in order; the third waits.
        offer_rx(&mem, &mock, 0, RX_BUF_LEN);
        offer_rx(&mem, &mock, 1, RX_BUF_LEN);
        assert_eq!(
            deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap(),
            2
        );
        assert_eq!(stack.host_frames(), 1);
        assert_eq!(used_idx(&mem, &mock), 2);
        assert_eq!(u16::from_le(mem.read_obj(avail_event).unwrap()), 2);

        // One more: the last frame.
        offer_rx(&mem, &mock, 2, RX_BUF_LEN);
        assert_eq!(
            deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap(),
            1
        );
        assert_eq!(stack.host_frames(), 0);
        for n in 0..3u16 {
            let used = used_elem(&mem, &mock, u64::from(n));
            assert_eq!(used.id(), u32::from(n));
            let bytes = rx_bytes(&mem, n, used.len());
            assert_eq!(bytes[..NET_HDR_LEN], RX_HEADER);
            assert!(is_gateway_arp_reply(&bytes[NET_HDR_LEN..]), "frame {n}");
        }
        assert_eq!(counters.snapshot().rx_frames, 3);
        drop(stack);
        session.close();
    }

    #[test]
    fn an_rx_chain_too_short_for_the_frame_drops_it() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);

        stack.push_guest_frame(&arp_request(0));
        stack.push_guest_frame(&arp_request(0));
        // 12 bytes of header and 41 of the 42-byte reply.
        offer_rx(&mem, &mock, 0, (NET_HDR_LEN + 41) as u32);
        offer_rx(&mem, &mock, 1, RX_BUF_LEN);
        assert_eq!(
            deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap(),
            2
        );
        assert_eq!(stack.host_frames(), 0);
        let short = used_elem(&mem, &mock, 0);
        assert_eq!((short.id(), short.len()), (0, 0), "given back empty");
        assert!(
            rx_bytes(&mem, 0, (NET_HDR_LEN + 41) as u32)
                .iter()
                .all(|&b| b == 0xaa),
            "nothing written"
        );
        let good = used_elem(&mem, &mock, 1);
        assert_eq!(good.id(), 1);
        assert!(is_gateway_arp_reply(
            &rx_bytes(&mem, 1, good.len())[NET_HDR_LEN..]
        ));
        let counts = counters.snapshot();
        assert_eq!((counts.rx_chain_short, counts.rx_frames), (1, 1));
        drop(stack);
        session.close();
    }

    #[test]
    fn tx_frames_over_1514_or_under_14_bytes_are_dropped() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);

        // A header alone, a 13-byte runt, and a 1515-byte frame are dropped;
        // a 14-byte frame (an Ethernet header) and a 1514-byte ARP request
        // reach the stack.
        let runt = vec![0xff; 13];
        let header_only = Ethernet14::frame();
        let largest = arp_request(1514);
        let oversize = arp_request(1515);
        offer_tx(&mem, &mock, 0, &[&tx_header()]);
        offer_tx(&mem, &mock, 1, &[&tx_header(), &runt]);
        offer_tx(&mem, &mock, 3, &[&tx_header(), &header_only]);
        offer_tx(&mem, &mock, 5, &[&tx_header(), &oversize]);
        offer_tx(&mem, &mock, 7, &[&tx_header(), &largest]);
        transmit(&mut queue, &mem, &mut stack, &counters, &going()).unwrap();

        assert_eq!(used_idx(&mem, &mock), 5, "every chain is given back");
        let counts = counters.snapshot();
        assert_eq!(counts.tx_runt, 2, "{counts:?}");
        assert_eq!(counts.tx_oversize, 1, "{counts:?}");
        assert_eq!(counts.tx_frames, 2, "{counts:?}");
        // Only the 1514-byte request is answered.
        let replies: Vec<Vec<u8>> = std::iter::from_fn(|| stack.pop_host_frame()).collect();
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert!(is_gateway_arp_reply(&replies[0]));
        drop(stack);
        session.close();
    }

    /// The header may straddle RX descriptors and the frame span several:
    /// the guest's buffers are one byte stream. Chains of 5 + 10 + 20 + 200
    /// bytes (the header across the first two, the 42-byte frame across the
    /// last three) and 12 + 30 + 200.
    #[test]
    fn an_rx_header_and_frame_may_straddle_descriptors() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);

        stack.push_guest_frame(&arp_request(0));
        stack.push_guest_frame(&arp_request(0));
        let chains: [(u16, &[u32]); 2] = [(0, &[5, 10, 20, 200]), (4, &[12, 30, 200])];
        for (head, lens) in chains {
            offer_rx_chain(&mem, &mock, head, lens);
        }
        assert_eq!(
            deliver(&mut queue, &mem, &mut stack, &counters, &going()).unwrap(),
            2
        );
        for (index, (head, lens)) in chains.into_iter().enumerate() {
            let used = used_elem(&mem, &mock, index as u64);
            assert_eq!(used.id(), u32::from(head));
            let len = used.len() as usize;
            assert_eq!(len, NET_HDR_LEN + 42, "chain {head}");
            let bytes = rx_chain_bytes(&mem, head, lens);
            assert_eq!(bytes[..NET_HDR_LEN], RX_HEADER, "chain {head}");
            assert!(
                is_gateway_arp_reply(&bytes[NET_HDR_LEN..len]),
                "chain {head}"
            );
            assert!(
                bytes[len..].iter().all(|&b| b == 0xaa),
                "chain {head}: nothing past the frame"
            );
        }
        drop(stack);
        session.close();
    }

    /// The TX header may be split anywhere: 5 + 7 then the frame, or the
    /// header and the frame's first 3 bytes then the rest. Eight bytes in
    /// two descriptors, less than a header, is a runt.
    #[test]
    fn a_tx_header_may_be_split_mid_header() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
        let mut queue = device_queue(&mock);

        let request = arp_request(0);
        let header = tx_header();
        offer_tx(&mem, &mock, 0, &[&header[..5], &header[5..], &request]);
        offer_tx(&mem, &mock, 3, &[&[0; 4], &[0; 4]]);
        let first = [&header[..], &request[..3]].concat();
        offer_tx(&mem, &mock, 5, &[&first, &request[3..]]);
        transmit(&mut queue, &mem, &mut stack, &counters, &going()).unwrap();

        assert_eq!(used_idx(&mem, &mock), 3);
        for index in 0..3 {
            assert_eq!(used_elem(&mem, &mock, index).len(), 0);
        }
        let counts = counters.snapshot();
        assert_eq!((counts.tx_frames, counts.tx_runt), (2, 1), "{counts:?}");
        let replies: Vec<Vec<u8>> = std::iter::from_fn(|| stack.pop_host_frame()).collect();
        assert_eq!(replies.len(), 2, "{replies:?}");
        assert!(replies.iter().all(|r| is_gateway_arp_reply(r)));
        drop(stack);
        session.close();
    }

    /// Once the device is being reset, the thread's last steps leave both
    /// rings alone: no chain is popped or used, and the frames for the
    /// guest stay in the stack.
    #[test]
    fn with_the_stop_flag_set_no_ring_is_touched() {
        let session = Session::new();
        let mut stack = session.stack();
        let counters = NetCounters::default();
        let mem = new_mem();
        let tx = MockSplitQueue::create(&mem, GuestAddress(0x1_0000), QUEUE_LEN);
        let rx = MockSplitQueue::create(&mem, GuestAddress(0x2_0000), QUEUE_LEN);
        let (mut tx_queue, mut rx_queue) = (device_queue(&tx), device_queue(&rx));
        let stopped = StopFlag::default();
        stopped.set();

        offer_tx(&mem, &tx, 0, &[&tx_header(), &arp_request(0)]);
        assert!(!transmit(&mut tx_queue, &mem, &mut stack, &counters, &stopped).unwrap());
        assert_eq!(used_idx(&mem, &tx), 0);
        assert_eq!(tx_queue.next_avail(), 0, "not even popped");
        assert_eq!(stack.host_frames(), 0, "the stack got nothing");

        stack.push_guest_frame(&arp_request(0));
        offer_rx(&mem, &rx, 8, RX_BUF_LEN);
        assert_eq!(
            deliver(&mut rx_queue, &mem, &mut stack, &counters, &stopped).unwrap(),
            0
        );
        assert_eq!(used_idx(&mem, &rx), 0);
        assert_eq!(stack.host_frames(), 1);
        assert!(rx_bytes(&mem, 8, RX_BUF_LEN).iter().all(|&b| b == 0xaa));
        drop(stack);
        session.close();
    }

    /// A 14-byte frame: an Ethernet header with nothing after it.
    struct Ethernet14;

    impl Ethernet14 {
        fn frame() -> Vec<u8> {
            let mut frame = arp_request(0);
            frame.truncate(14);
            frame
        }
    }

    /// A deadline of "now", or one that has passed, waits 1 ms: the thread
    /// polls once a wakeup and never spins. A later one is kept; none
    /// disarms.
    #[test]
    fn a_deadline_that_has_passed_waits_1_ms() {
        let now = Instant::now();
        let ms = Duration::from_millis;
        assert_eq!(timer_delay(None, now), None);
        assert_eq!(timer_delay(Some(now), now), Some(ms(1)));
        assert_eq!(
            timer_delay(now.checked_sub(ms(50)), now),
            Some(ms(1)),
            "long past"
        );
        assert_eq!(timer_delay(Some(now + ms(30)), now), Some(ms(30)));
        assert_eq!(
            timer_delay(Some(now + Duration::from_nanos(10)), now),
            Some(Duration::from_nanos(10)),
            "a deadline just ahead is kept: it is not \"now\""
        );
    }

    /// The guest took frames from a full queue: smoltcp has been waiting
    /// for room, so the next poll comes at once (1 ms, by the floor above)
    /// whatever the stack's deadline. Otherwise the deadline stands.
    #[test]
    fn draining_a_full_queue_brings_the_next_poll_forward() {
        let now = Instant::now();
        let later = now + Duration::from_secs(5);
        assert_eq!(after_delivery(Some(later), true, now), Some(now));
        assert_eq!(after_delivery(None, true, now), Some(now));
        let earlier = now.checked_sub(Duration::from_millis(5));
        assert_eq!(after_delivery(earlier, true, now), earlier);
        assert_eq!(after_delivery(Some(later), false, now), Some(later));
        assert_eq!(after_delivery(None, false, now), None);
    }

    // The device behind a transport, with its thread.

    type Transport = MmioTransport<VirtioNet>;

    /// Where queue `q` behind the transport lives.
    fn queue_start(q: u32) -> GuestAddress {
        GuestAddress(0x1_0000 * (u64::from(q) + 1))
    }

    /// The driver's view of queue `q`. Creating it zeroes the ring indexes,
    /// so each test creates it once, before offering.
    fn queue_mock(mem: &GuestMemoryMmap, q: u32) -> MockSplitQueue<'_, GuestMemoryMmap> {
        let mock = MockSplitQueue::create(mem, queue_start(q), QUEUE_LEN);
        assert_eq!(
            (mock.desc_table_addr().0, mock.avail_addr().0),
            (
                queue_start(q).0,
                queue_start(q).0 + 16 * u64::from(QUEUE_LEN)
            )
        );
        mock
    }

    /// A device in a transport, as the driver sees it, with the handles the
    /// VMM (ioeventfds, the irqfd) would otherwise hold.
    struct Driver {
        mem: Arc<GuestMemoryMmap>,
        transport: Transport,
        irq: Arc<IrqTrigger>,
        kicks: Vec<EventFd>,
    }

    impl Driver {
        fn new(device: VirtioNet) -> Driver {
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
        /// both queues ready, up to DRIVER_OK.
        fn handshake(&mut self) {
            assert_eq!(self.read(regs::DEVICE_ID), 1);
            self.set_status(ACKNOWLEDGE);
            self.set_status(ACKNOWLEDGE | DRIVER);
            for sel in 0..2 {
                self.write(regs::DEVICE_FEATURES_SEL, sel);
                let offered = self.read(regs::DEVICE_FEATURES);
                self.write(regs::DRIVER_FEATURES_SEL, sel);
                self.write(regs::DRIVER_FEATURES, offered);
            }
            self.set_status(ACKNOWLEDGE | DRIVER | FEATURES_OK);
            for q in 0..2 {
                // Where `queue_mock` lays the rings out, and our used ring.
                let desc = queue_start(q).0;
                let avail = desc + 16 * u64::from(QUEUE_LEN);
                let used = desc + USED_RING_OFFSET;
                self.write(regs::QUEUE_SEL, q);
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

        /// Waits for the device to interrupt the guest, and takes the
        /// interrupt. The thread interrupts after it has used the buffers,
        /// later in the same turn.
        fn wait_interrupt(&self) {
            let deadline = Instant::now() + THREAD_LIMIT;
            while self.irq.evt.read().is_err() {
                assert!(Instant::now() < deadline, "no interrupt");
                thread::sleep(Duration::from_millis(5));
            }
            assert!(self.irq.status.load(Ordering::SeqCst) & 1 != 0, "used");
        }

        /// Waits for queue `q`'s used index to reach `want`.
        fn wait_used(&self, q: u32, want: u16) {
            let used = GuestAddress(queue_start(q).0 + USED_RING_OFFSET);
            let deadline = Instant::now() + THREAD_LIMIT;
            while used_idx_at(&self.mem, used) != want {
                assert!(
                    Instant::now() < deadline,
                    "queue {q}: used idx {} not {want}, needs reset {}",
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
    fn rx_stops_when_no_chain_is_free_and_resumes_on_kick() {
        let session = Session::new();
        let mut driver = Driver::new(session.device());
        driver.handshake();
        assert!(
            thread_names().iter().any(|n| n == "net"),
            "{:?}",
            thread_names()
        );
        let mem = driver.mem.clone();
        let rx = queue_mock(&mem, RX_QUEUE as u32);
        let tx = queue_mock(&mem, TX_QUEUE as u32);
        let rx_used = GuestAddress(queue_start(RX_QUEUE as u32).0 + USED_RING_OFFSET);

        // The guest asks for the gateway with no RX buffer posted: the TX
        // chain is used, and the answer has nowhere to go.
        offer_tx(&mem, &tx, 0, &[&tx_header(), &arp_request(0)]);
        driver.kicks[TX_QUEUE].write(1).unwrap();
        driver.wait_used(TX_QUEUE as u32, 1);
        driver.wait_interrupt();
        assert_eq!(used_idx_at(&mem, rx_used), 0);

        // A buffer alone does nothing: the thread sleeps (the stack has no
        // deadline) until the driver kicks RX, as the device asked it to.
        offer_rx(&mem, &rx, 8, RX_BUF_LEN);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(used_idx_at(&mem, rx_used), 0);
        // The kick: the answer lands, with its header.
        driver.kicks[RX_QUEUE].write(1).unwrap();
        driver.wait_used(RX_QUEUE as u32, 1);
        driver.wait_interrupt();
        let used = used_elem_at(&mem, rx_used, 0);
        assert_eq!(used.id(), 8);
        let bytes = rx_bytes(&mem, 8, used.len());
        assert_eq!(bytes[..NET_HDR_LEN], RX_HEADER);
        assert!(is_gateway_arp_reply(&bytes[NET_HDR_LEN..]));
        let counts = driver.transport.device().counts();
        assert_eq!((counts.tx_frames, counts.rx_frames), (1, 1));

        // The driver resets the device: the thread is stopped and joined.
        driver.set_status(0);
        assert_eq!(driver.read(regs::STATUS), 0);
        drop(driver);
        session.close();
    }

    /// A ring the driver corrupted is fatal for its queue: the device asks
    /// for a reset and goes on serving nothing from it.
    #[test]
    fn a_corrupt_tx_ring_asks_for_a_reset() {
        let session = Session::new();
        let mut driver = Driver::new(session.device());
        driver.handshake();
        let mem = driver.mem.clone();
        let tx = queue_mock(&mem, TX_QUEUE as u32);
        offer_tx(&mem, &tx, 0, &[&tx_header(), &arp_request(0)]);
        tx.avail().idx().store(u16::to_le(QUEUE_LEN + 1));
        driver.kicks[TX_QUEUE].write(1).unwrap();
        let deadline = Instant::now() + THREAD_LIMIT;
        while !driver.irq.needs_reset.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "no DEVICE_NEEDS_RESET");
            thread::sleep(Duration::from_millis(5));
        }
        driver.set_status(0);
        drop(driver);
        session.close();
    }

    /// Each activation builds a new stack, but flow ids count on across a
    /// driver reset: two denied SYNs, one per activation, are flows 1
    /// and 2. (The Task 9 review's probe.)
    #[test]
    fn flow_ids_count_on_across_a_reset_and_reactivation() {
        let session = Session::new();
        let mut driver = Driver::new(session.device());
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);
        for port in [40_000, 40_001] {
            let mem = driver.mem.clone();
            // The driver sets its rings up afresh, used rings included.
            for q in [RX_QUEUE, TX_QUEUE] {
                let used = queue_start(q as u32).0 + USED_RING_OFFSET;
                mem.write_obj(0u32, GuestAddress(used)).unwrap();
            }
            driver.handshake();
            let tx = queue_mock(&mem, TX_QUEUE as u32);
            offer_tx(&mem, &tx, 0, &[&tx_header(), &syn(port, dst)]);
            driver.kicks[TX_QUEUE].write(1).unwrap();
            // The SYN is decided, and recorded, before its chain is used.
            driver.wait_used(TX_QUEUE as u32, 1);
            driver.set_status(0);
        }
        drop(driver);
        let flows: Vec<(u64, String)> = session
            .records()
            .into_iter()
            .filter(|r| r.kind == "net.connect")
            .map(|r| {
                (
                    r.data["flow"].as_u64().unwrap(),
                    r.data["src"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            flows,
            [
                (1, "10.0.2.15:40000".to_owned()),
                (2, "10.0.2.15:40001".to_owned())
            ]
        );
    }
}
