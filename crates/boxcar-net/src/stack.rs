// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! [`NetStack`]: the gateway the guest sees, as one single-threaded state
//! machine over Ethernet frames.
//!
//! Every guest frame goes through the dispatcher first ([`classify`]):
//! ARP, DHCP and ICMP are answered here, deterministically, and what is not
//! carried is dropped and counted. Only TCP, and what smoltcp must learn
//! from ARP, reaches smoltcp. smoltcp's interface owns the gateway's MAC
//! and address, with any-IP on and a default route through itself, so it
//! takes TCP for every destination.
//!
//! Frames move through two queues, each holding at most [`QUEUE_CAP`]:
//! guest to stack, which smoltcp reads at the next
//! [`poll`](NetStack::poll), and stack to guest, which the dispatcher's
//! replies and smoltcp's output share and
//! [`pop_host_frame`](NetStack::pop_host_frame) drains. While the guest's
//! queue is full smoltcp reads nothing, so its answers cannot overflow it;
//! guest frames wait for it until their own queue fills, and then the
//! dispatcher drops new ones as `queue_full`.

use std::collections::hash_map::RandomState;
use std::collections::VecDeque;
use std::hash::BuildHasher;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use boxcar_audit::{AuditSink, EmitError};
use boxcar_proto::Payload;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, ETHERNET_HEADER_LEN};

use crate::audit::{self, DropReason, Drops};
use crate::config::{ConfigError, NetConfig, Policy};
use crate::frame::{classify, Dispatch};
use crate::{arp, dhcp, icmp};

/// The link's IP MTU, the guest's default for virtio-net.
pub const IP_MTU: usize = 1500;
/// Frames each queue holds before it refuses more: the guest-to-stack queue
/// between polls, the stack-to-guest queue until the device drains it.
pub const QUEUE_CAP: usize = 1024;

/// What the net thread does after a [`NetStack::poll`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PollOutcome {
    /// When to poll again even if nothing arrives; `None` to wait for a
    /// frame or a host fd.
    pub next_deadline: Option<Instant>,
    /// Host fds to start, change, or stop watching.
    pub fd_changes: Vec<FdChange>,
}

/// A host fd the stack wants watched, or no longer watched, and the token
/// [`NetStack::on_host_fd_event`] gets for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdChange {
    pub token: u64,
    pub fd: RawFd,
    pub interest: Interest,
}

/// What to watch an fd for. Neither means stop watching it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

/// The guest's side of the network: its gateway, DHCP server, and (with
/// smoltcp) the far end of its TCP connections.
pub struct NetStack {
    cfg: NetConfig,
    sink: AuditSink,
    policy: Arc<ArcSwap<Policy>>,
    pipe: Pipe,
    iface: Interface,
    sockets: SocketSet<'static>,
    drops: Drops,
    /// smoltcp's time zero.
    epoch: Instant,
}

impl NetStack {
    /// A stack for `cfg`, recording into `sink`, with `policy` deciding
    /// what the guest may reach. Fails when `cfg` does not
    /// [validate](NetConfig::validate).
    pub fn new(
        cfg: NetConfig,
        sink: AuditSink,
        policy: Arc<ArcSwap<Policy>>,
    ) -> Result<NetStack, ConfigError> {
        cfg.validate()?;
        let epoch = Instant::now();
        let mut pipe = Pipe::default();
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(cfg.gateway_mac)));
        // Seeds smoltcp's initial sequence numbers and ephemeral ports.
        config.random_seed = RandomState::new().hash_one(cfg.guest_mac);
        let mut iface = Interface::new(config, &mut pipe, SmolInstant::ZERO);
        let mut added = false;
        iface.update_ip_addrs(|addrs| {
            added = addrs
                .push(IpCidr::new(cfg.gateway.into(), cfg.netmask))
                .is_ok();
        });
        if !added {
            return Err(ConfigError::Interface("the gateway's address"));
        }
        // Any-IP takes packets for every address a route sends through one
        // of the interface's own addresses; the default route through the
        // gateway's own address makes that every address.
        iface
            .routes_mut()
            .add_default_ipv4_route(cfg.gateway)
            .map_err(|_| ConfigError::Interface("the default route"))?;
        iface.set_any_ip(true);
        Ok(NetStack {
            cfg,
            sink,
            policy,
            pipe,
            iface,
            sockets: SocketSet::new(Vec::new()),
            drops: Drops::new(),
            epoch,
        })
    }

    /// The policy in force now.
    pub fn policy(&self) -> Arc<Policy> {
        self.policy.load_full()
    }

    /// Takes one Ethernet frame the guest sent.
    pub fn push_guest_frame(&mut self, frame: &[u8]) {
        let now = Instant::now();
        match classify(frame, self.cfg.gateway) {
            Dispatch::Arp => {
                if let Some(reply) = arp::reply(&self.cfg, frame) {
                    self.send_to_guest(reply, now);
                }
                if let Some(learn) = arp::learning_frame(&self.cfg, frame) {
                    self.send_to_smoltcp(learn, now);
                }
            }
            Dispatch::Dhcp => match dhcp::answer(&self.cfg, frame) {
                dhcp::Answer::Reply { frame, record } => {
                    // Recorded only once the guest is sure to get it, and
                    // never dropped: a lease is two records a boot.
                    if self.send_to_guest(frame, now) {
                        self.record(Payload::NetDhcp(record));
                    }
                }
                dhcp::Answer::NotForUs => {}
                dhcp::Answer::Unanswered => self.drop_frame(DropReason::Dhcp, now),
            },
            // The DNS forwarder (M2 Task 6) answers these. Until it lands
            // they are dropped, and the guest's resolver times out.
            Dispatch::Dns { .. } => self.drop_frame(DropReason::DnsUnimplemented, now),
            // Likewise the UDP relay (M2 Task 8), under the egress policy.
            Dispatch::Udp { .. } => self.drop_frame(DropReason::UdpUnimplemented, now),
            Dispatch::Icmp { .. } => match icmp::reply(&self.cfg, frame) {
                Some(reply) => {
                    self.send_to_guest(reply, now);
                }
                None => self.drop_frame(DropReason::Icmp, now),
            },
            // smoltcp has no sockets yet, so it resets every connection;
            // the relay and its policy gate (M2 Task 7) come in front.
            Dispatch::TcpSyn { .. } | Dispatch::Tcp { .. } => {
                self.send_to_smoltcp(frame.to_vec(), now)
            }
            Dispatch::Ipv6 => self.drop_frame(DropReason::Ipv6, now),
            Dispatch::Other => self.drop_frame(DropReason::Other, now),
        }
    }

    /// The next frame for the guest, if any.
    pub fn pop_host_frame(&mut self) -> Option<Vec<u8>> {
        self.pipe.to_guest.pop_front()
    }

    /// Lets smoltcp take the frames queued for it and send what it has, and
    /// records the dropped-frame counts that have fallen due. `now` must
    /// come from the same clock as [`Instant::now`].
    ///
    /// smoltcp takes nothing while the guest's queue is full: what waits for
    /// it is taken at the first poll after the guest has drained some, so
    /// the device polls again once it has popped frames.
    pub fn poll(&mut self, now: Instant) -> PollOutcome {
        let stamp = self.smoltcp_time(now);
        self.iface.poll(stamp, &mut self.pipe, &mut self.sockets);
        let refused = std::mem::take(&mut self.pipe.refused);
        if let Some(counted) = self.drops.count_many(DropReason::QueueFull, refused, now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
        for counted in self.drops.flush(now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
        let smoltcp_due = self
            .iface
            .poll_delay(stamp, &self.sockets)
            .and_then(|delay| now.checked_add(delay.into()));
        let next_deadline = match (smoltcp_due, self.drops.next_due()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        PollOutcome {
            next_deadline,
            fd_changes: Vec::new(),
        }
    }

    /// A host fd the stack asked to watch through [`FdChange`] is ready.
    /// The stack watches none yet, so there is nothing to do.
    pub fn on_host_fd_event(&mut self, _token: u64, _readable: bool, _writable: bool) {}

    /// Records every dropped-frame count still held, due or not, so the
    /// drops of the stack's last second are not lost. The net thread (M2
    /// Task 9) calls it as it stops, before the audit log closes.
    pub fn shutdown(&mut self) {
        for counted in self.drops.flush_all(Instant::now()) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
    }

    /// `now` on smoltcp's clock: microseconds since the stack was made.
    fn smoltcp_time(&self, now: Instant) -> SmolInstant {
        let since = now.saturating_duration_since(self.epoch).as_micros();
        SmolInstant::from_micros(i64::try_from(since).unwrap_or(i64::MAX))
    }

    /// Queues `frame` for the guest, and says whether it was: a full queue
    /// drops it as `queue_full`.
    fn send_to_guest(&mut self, frame: Vec<u8>, now: Instant) -> bool {
        if self.pipe.to_guest.len() >= QUEUE_CAP {
            boxcar_virtio::limited!(warn, "net: the guest is not taking frames; dropping");
            self.drop_frame(DropReason::QueueFull, now);
            false
        } else {
            self.pipe.to_guest.push_back(frame);
            true
        }
    }

    fn send_to_smoltcp(&mut self, frame: Vec<u8>, now: Instant) {
        if self.pipe.to_stack.len() >= QUEUE_CAP {
            boxcar_virtio::limited!(warn, "net: the stack is not being polled; dropping");
            self.drop_frame(DropReason::QueueFull, now);
        } else {
            self.pipe.to_stack.push_back(frame);
        }
    }

    /// Records an event that must not be dropped, waiting for room in the
    /// log. A log that is closed (the session is ending) or has failed (the
    /// VMM stops on that) records nothing more.
    fn record(&self, payload: Payload) {
        match audit::emit(&self.sink, payload) {
            Ok(()) | Err(EmitError::Closed | EmitError::Failed) => {}
            Err(error @ EmitError::Checkpoint) => {
                boxcar_virtio::limited!(error, "net: audit record refused: {error}");
            }
        }
    }

    fn drop_frame(&mut self, reason: DropReason, now: Instant) {
        if let Some(counted) = self.drops.count(reason, now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
    }
}

/// smoltcp's device: two frame queues, one each way.
#[derive(Default)]
struct Pipe {
    /// Guest frames for smoltcp.
    to_stack: VecDeque<Vec<u8>>,
    /// Frames for the guest, from the dispatcher and from smoltcp.
    to_guest: VecDeque<Vec<u8>>,
    /// Frames smoltcp made that the full guest queue refused, since the
    /// stack last counted them.
    refused: u64,
}

impl phy::Device for Pipe {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    /// Nothing while the guest's queue is full: smoltcp answers a frame
    /// through the token that comes with it, and the guest has no room for
    /// the answer. The frame waits in its queue.
    fn receive(&mut self, _now: SmolInstant) -> Option<(RxToken, TxToken<'_>)> {
        if self.to_guest.len() >= QUEUE_CAP {
            return None;
        }
        let frame = self.to_stack.pop_front()?;
        Some((
            RxToken(frame),
            TxToken {
                queue: &mut self.to_guest,
                refused: &mut self.refused,
            },
        ))
    }

    /// Refused while the guest's queue is full, which holds smoltcp's
    /// output back until the guest takes some.
    fn transmit(&mut self, _now: SmolInstant) -> Option<TxToken<'_>> {
        if self.to_guest.len() >= QUEUE_CAP {
            return None;
        }
        Some(TxToken {
            queue: &mut self.to_guest,
            refused: &mut self.refused,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        // smoltcp's MTU is the whole Ethernet frame, header included.
        caps.max_transmission_unit = IP_MTU + ETHERNET_HEADER_LEN;
        caps
    }
}

struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    refused: &'a mut u64,
}

impl phy::TxToken for TxToken<'_> {
    /// Queues the frame `f` writes, unless the guest's queue is full, when
    /// it is counted and dropped. `receive` and `transmit` hand out no token
    /// for a full queue, so this is the second guard.
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        if self.queue.len() < QUEUE_CAP {
            self.queue.push_back(frame);
        } else {
            *self.refused = self.refused.saturating_add(1);
        }
        result
    }
}
