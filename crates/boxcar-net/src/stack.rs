// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! [`NetStack`]: the gateway the guest sees, as one single-threaded state
//! machine over Ethernet frames.
//!
//! Every guest frame goes through the dispatcher first ([`classify`]):
//! ARP, DHCP and ICMP are answered here, deterministically, DNS to the
//! gateway goes to the [forwarder](crate::dns), a TCP SYN to the
//! [relay](crate::tcp), which decides it before anything answers it, and
//! what is not carried is dropped and counted. Only the rest of TCP, and
//! what smoltcp must learn from ARP, reaches smoltcp. smoltcp's interface
//! owns the gateway's MAC and address, with any-IP on and a default route
//! through itself, so its sockets can be any destination; the relay makes
//! one for each connection it lets through.
//!
//! The stack's host fds are the forwarder's upstream socket (token
//! [`DNS_TOKEN`], asked for by the first [`poll`](NetStack::poll)) and one
//! socket for each relayed connection (tokens from
//! [`FLOW_TOKEN_BASE`](crate::FLOW_TOKEN_BASE)). The stack asks the net
//! thread to start, change and stop watching them through the
//! [`FdChange`]s each poll returns, and
//! [`on_host_fd_event`](NetStack::on_host_fd_event) handles their
//! readiness; the net thread polls again after handing events over. An fd
//! the stack is done with stays open until the poll after the one whose
//! outcome asked for it to be unwatched.
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
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use boxcar_audit::AuditSink;
use boxcar_proto::{NetDns, Payload};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, ETHERNET_HEADER_LEN};

use crate::audit::{self, DropReason, Drops};
use crate::config::{ConfigError, NetConfig};
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{self, ForwardError, Forwarder, Pending, Received};
use crate::dns::{self as dns, parse};
use crate::frame::{self, classify, Dispatch, DNS_PORT};
use crate::policy::{Policy, Verdict};
use crate::tcp::relay::{Ctx, Relay};
use crate::upstream::HostAddrs;
use crate::{arp, dhcp, icmp};

/// The link's IP MTU, the guest's default for virtio-net.
pub const IP_MTU: usize = 1500;
/// The token of the DNS forwarder's upstream socket in [`FdChange`].
pub const DNS_TOKEN: u64 = 1;
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
    /// The DNS upstream's socket, and the guest queries waiting on it.
    dns: Forwarder,
    /// The names DNS answers gave each address.
    dns_cache: DnsCache,
    /// Whether the net thread has been asked to watch the DNS socket.
    dns_watched: bool,
    /// The TCP relay: the guest's connections and their host sockets.
    tcp: Relay,
    /// smoltcp's time zero.
    epoch: Instant,
}

impl NetStack {
    /// A stack for `cfg`, recording into `sink`, with `policy` deciding
    /// what the guest may reach and resolve; the stack reads it at every
    /// decision, so whoever holds the handle may swap it. Fails when `cfg`
    /// does not [validate](NetConfig::validate), or when no DNS upstream
    /// can be given a socket.
    pub fn new(
        cfg: NetConfig,
        sink: AuditSink,
        policy: Arc<ArcSwap<Policy>>,
    ) -> Result<NetStack, ConfigError> {
        cfg.validate()?;
        let dns = Forwarder::connect(&cfg.dns_upstreams)
            .map_err(|error| ConfigError::DnsUpstream(error.to_string()))?;
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
        let tcp = Relay::new(cfg.tcp.clone(), HostAddrs::system());
        Ok(NetStack {
            cfg,
            sink,
            policy,
            pipe,
            iface,
            sockets: SocketSet::new(Vec::new()),
            drops: Drops::new(),
            dns,
            dns_cache: DnsCache::new(),
            dns_watched: false,
            tcp,
            epoch,
        })
    }

    /// The handle the stack reads its policy through; storing a new
    /// policy in it decides the next query or connection.
    pub fn policy(&self) -> Arc<ArcSwap<Policy>> {
        Arc::clone(&self.policy)
    }

    /// The names DNS answers to the guest gave `ip` that have not expired,
    /// the most recently answered first: for each answer, the name asked
    /// for comes before the CNAMEs that led to the address.
    pub fn dns_names(&self, ip: Ipv4Addr) -> Vec<String> {
        self.dns_cache.names_for(ip)
    }

    /// Replaces where the stack reads the host's own addresses, which the
    /// guest may not reach unless a rule names one exactly (by default,
    /// [`HostAddrs::system`]).
    pub fn set_host_addrs(&mut self, addrs: HostAddrs) {
        self.tcp.set_host_addrs(addrs);
    }

    /// The TCP connections the stack holds: those relayed or ending, and
    /// those waiting on their host connect.
    pub fn open_flows(&self) -> usize {
        self.tcp.open_flows()
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
            Dispatch::Dns { src, .. } => self.dns_query(frame, src, now),
            // The UDP relay (M2 Task 8) carries these, under the egress
            // policy. Until it lands they are dropped.
            Dispatch::Udp { .. } => self.drop_frame(DropReason::UdpUnimplemented, now),
            Dispatch::Icmp { .. } => match icmp::reply(&self.cfg, frame) {
                Some(reply) => {
                    self.send_to_guest(reply, now);
                }
                None => self.drop_frame(DropReason::Icmp, now),
            },
            Dispatch::TcpSyn { src, dst } => self.tcp_syn(frame, src, dst, now),
            // Segments of the relay's connections; smoltcp resets any other.
            Dispatch::Tcp { .. } => self.send_to_smoltcp(frame.to_vec(), now),
            Dispatch::Ipv6 => self.drop_frame(DropReason::Ipv6, now),
            Dispatch::Other => self.drop_frame(DropReason::Other, now),
        }
    }

    /// The next frame for the guest, if any.
    pub fn pop_host_frame(&mut self) -> Option<Vec<u8>> {
        self.pipe.to_guest.pop_front()
    }

    /// Lets smoltcp take the frames queued for it, moves the relayed
    /// connections' bytes, sends what all that queued, and records the
    /// dropped-frame counts that have fallen due. `now` must come from the
    /// same clock as [`Instant::now`].
    ///
    /// smoltcp takes nothing while the guest's queue is full: what waits for
    /// it is taken at the first poll after the guest has drained some, so
    /// the device polls again once it has popped frames. The net thread
    /// also polls after handing host fd events over.
    ///
    /// DNS queries whose time is up get SERVFAIL here, host connects whose
    /// time is up reset the guest, and gated connections whose time is up
    /// are denied, so `next_deadline` counts the next of each too. The
    /// first poll asks for the DNS socket to be watched. Host sockets the
    /// last outcome asked to be unwatched are closed first.
    pub fn poll(&mut self, now: Instant) -> PollOutcome {
        self.tcp.bury();
        for pending in self.dns.expire(now) {
            self.refuse(pending, dns::SERVFAIL, now);
        }
        let stamp = smoltcp_time(self.epoch, now);
        {
            let (tcp, mut cx) = self.split(now);
            tcp.expire(&mut cx);
        }
        self.iface.poll(stamp, &mut self.pipe, &mut self.sockets);
        {
            let (tcp, mut cx) = self.split(now);
            tcp.relay(&mut cx);
        }
        let refused = std::mem::take(&mut self.pipe.refused);
        if let Some(counted) = self.drops.count_many(DropReason::QueueFull, refused, now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
        for counted in self.drops.flush(now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
        let mut fd_changes = Vec::new();
        if !self.dns_watched {
            self.dns_watched = true;
            fd_changes.push(FdChange {
                token: DNS_TOKEN,
                fd: self.dns.fd(),
                interest: Interest {
                    readable: true,
                    writable: false,
                },
            });
        }
        fd_changes.extend(self.tcp.take_fd_changes());
        let smoltcp_due = self
            .iface
            .poll_delay(stamp, &self.sockets)
            .and_then(|delay| now.checked_add(delay.into()));
        let next_deadline = [
            smoltcp_due,
            self.drops.next_due(),
            self.dns.next_deadline(),
            self.tcp.next_deadline(now),
        ]
        .into_iter()
        .flatten()
        .min();
        PollOutcome {
            next_deadline,
            fd_changes,
        }
    }

    /// A host fd the stack asked to watch through [`FdChange`] is ready (an
    /// error or hang-up counts as both readable and writable). For the DNS
    /// socket ([`DNS_TOKEN`]), every answer waiting on it goes to the
    /// guest, and what answers nothing is counted as `dns_bogus`. For a
    /// relayed connection's socket, its connect completes or fails, or
    /// bytes move; what that queues for the guest goes at the next
    /// [`poll`](Self::poll), as do the watch changes it makes. Events for
    /// tokens the stack no longer uses are ignored.
    pub fn on_host_fd_event(&mut self, token: u64, readable: bool, writable: bool) {
        let now = Instant::now();
        if token != DNS_TOKEN {
            let (tcp, mut cx) = self.split(now);
            return tcp.host_event(&mut cx, token, readable, writable);
        }
        if !readable {
            return;
        }
        for received in self.dns.receive() {
            match received {
                Received::Answer(answer) => self.deliver(answer, now),
                Received::Bogus => self.drop_frame(DropReason::DnsBogus, now),
            }
        }
    }

    /// Records the DNS queries still waiting for the upstream as
    /// unanswered (SERVFAIL), ends every TCP connection (`net.close` with
    /// reason `shutdown`; the guest's side is reset), and records every
    /// dropped-frame count still held, due or not, so the stack's last
    /// second is not lost. The net thread (M2 Task 9) calls it as it stops,
    /// before the audit log closes, and then drops the stack, which closes
    /// the host sockets.
    pub fn shutdown(&mut self) {
        let now = Instant::now();
        for pending in self.dns.abandon() {
            self.record(dns_record(pending, dns::SERVFAIL, Vec::new()));
        }
        {
            let (tcp, mut cx) = self.split(now);
            tcp.shutdown(&mut cx);
        }
        for counted in self.drops.flush_all(now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
    }

    /// A guest SYN from `guest` to `dst`: the relay decides it on the
    /// policy and the names the DNS cache has for `dst`.
    fn tcp_syn(&mut self, frame: &[u8], guest: SocketAddrV4, dst: SocketAddrV4, now: Instant) {
        let names = self.dns_cache.names_for_at(*dst.ip(), now);
        let policy = self.policy.load();
        let (tcp, mut cx) = self.split(now);
        tcp.syn(&mut cx, frame, guest, dst, &policy, names);
    }

    /// The relay, and what it borrows from the rest of the stack.
    fn split(&mut self, now: Instant) -> (&mut Relay, Ctx<'_>) {
        let cx = Ctx {
            cfg: &self.cfg,
            sink: &self.sink,
            iface: &mut self.iface,
            pipe: &mut self.pipe,
            sockets: &mut self.sockets,
            drops: &mut self.drops,
            now,
            stamp: smoltcp_time(self.epoch, now),
        };
        (&mut self.tcp, cx)
    }

    /// A guest DNS message to the gateway, from `guest`. One shorter than a
    /// header is dropped as `dns`. Every other gets exactly one answer and
    /// one `net.dns`: FORMERR if it is not one plain query, NXDOMAIN if the
    /// policy denies the name, else the upstream's answer, or SERVFAIL if
    /// the query cannot be sent or waits too long.
    fn dns_query(&mut self, frame: &[u8], guest: SocketAddrV4, now: Instant) {
        let Some(message) = frame::udp_payload(frame) else {
            return self.drop_frame(DropReason::Other, now);
        };
        let Ok(header) = parse::Header::parse(message) else {
            return self.drop_frame(DropReason::Dns, now);
        };
        let (txid, question) = match parse::parse_query(message) {
            Ok(query) => query,
            Err(_) => {
                // Named in the record as well as it reads.
                let (qname, qtype) = match parse::read_question(message) {
                    Ok(q) if header.counts[0] == 1 => (parse::name_display(&q.name), q.qtype),
                    _ => (String::new(), 0),
                };
                let (verdict, rule) = self.policy.load().dns_rule(&qname);
                if let Some(reply) = dns::error_reply(message, dns::FORMERR) {
                    self.send_dns(guest, &reply, now);
                }
                return self.record(Payload::NetDns(NetDns {
                    txid: header.id,
                    qname,
                    qtype,
                    rcode: dns::FORMERR,
                    answers: Vec::new(),
                    verdict,
                    rule,
                }));
            }
        };
        let (verdict, rule) = self.policy.load().dns_rule(&question.name);
        let pending = Pending {
            txid,
            guest,
            question,
            query: message.to_vec(),
            verdict,
            rule,
        };
        if verdict == Verdict::Deny {
            return self.refuse(pending, dns::NXDOMAIN, now);
        }
        if let Err((pending, error)) = self.dns.forward(pending, now) {
            if let ForwardError::Send(error) = &error {
                boxcar_virtio::limited!(warn, "net: dns: {error}");
            }
            self.refuse(pending, dns::SERVFAIL, now);
        }
    }

    /// Answers a query with `rcode` and no records, and records it.
    fn refuse(&mut self, pending: Pending, rcode: u16, now: Instant) {
        if let Some(reply) = dns::error_reply(&pending.query, rcode) {
            self.send_dns(pending.guest, &reply, now);
        }
        self.record(dns_record(pending, rcode, Vec::new()));
    }

    /// Gives the guest the upstream's answer, without its AAAA answers and
    /// cut down if the link cannot carry it whole, caches the addresses it
    /// gives, and records it. An answer cut down gives the guest no
    /// address, so none is cached or recorded.
    fn deliver(&mut self, answer: forwarder::Answer, now: Instant) {
        let forwarder::Answer {
            pending,
            reply,
            answers,
        } = answer;
        let stripped = parse::strip_aaaa(&reply);
        let (message, whole) = if stripped.len() <= dns::MAX_MESSAGE {
            (Some(stripped), true)
        } else {
            (dns::truncated(&stripped), false)
        };
        let Some(message) = message else {
            // Unreachable: the forwarder takes only answers that read.
            return self.drop_frame(DropReason::DnsBogus, now);
        };
        let rcode = dns::rcode(&message).unwrap_or(dns::SERVFAIL);
        let mut addresses: Vec<Ipv4Addr> = Vec::new();
        if whole {
            for (name, ip, ttl) in &answers {
                self.dns_cache.insert_at(*ip, name, *ttl, now);
                if !addresses.contains(ip) {
                    addresses.push(*ip);
                }
            }
        }
        self.send_dns(pending.guest, &message, now);
        let addresses = addresses.iter().map(Ipv4Addr::to_string).collect();
        self.record(dns_record(pending, rcode, addresses));
    }

    /// Sends `message` to the guest's resolver at `guest` (by the guest's
    /// MAC), from the gateway's port 53.
    fn send_dns(&mut self, guest: SocketAddrV4, message: &[u8], now: Instant) {
        let server = SocketAddrV4::new(self.cfg.gateway, DNS_PORT);
        let built = frame::udp_frame(
            EthernetAddress(self.cfg.gateway_mac),
            EthernetAddress(self.cfg.guest_mac),
            server,
            guest,
            message,
        );
        // Every message here fits the link: built from a query that came
        // over it, or held to `dns::MAX_MESSAGE`.
        if let Some(built) = built {
            self.send_to_guest(built, now);
        }
    }

    /// Queues `frame` for the guest, and says whether it was: a full queue
    /// drops it as `queue_full`.
    fn send_to_guest(&mut self, frame: Vec<u8>, now: Instant) -> bool {
        if self.pipe.queue_for_guest(frame) {
            true
        } else {
            boxcar_virtio::limited!(warn, "net: the guest is not taking frames; dropping");
            self.drop_frame(DropReason::QueueFull, now);
            false
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

    /// Records an event that must not be dropped (see [`audit::record`]).
    fn record(&self, payload: Payload) {
        audit::record(&self.sink, payload);
    }

    fn drop_frame(&mut self, reason: DropReason, now: Instant) {
        if let Some(counted) = self.drops.count(reason, now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
    }
}

/// The `net.dns` for a query answered with `rcode`, giving `answers`.
///
/// It is made whether or not the guest's queue takes the answer (one it
/// refuses is counted as `queue_full`): the query was asked and decided,
/// and may have gone upstream, which the log must show either way.
fn dns_record(pending: Pending, rcode: u16, answers: Vec<String>) -> Payload {
    Payload::NetDns(NetDns {
        txid: pending.txid,
        qname: pending.question.name,
        qtype: pending.question.qtype,
        rcode,
        answers,
        verdict: pending.verdict,
        rule: pending.rule,
    })
}

/// `now` on smoltcp's clock: microseconds since `epoch`, the stack's time
/// zero.
fn smoltcp_time(epoch: Instant, now: Instant) -> SmolInstant {
    let since = now.saturating_duration_since(epoch).as_micros();
    SmolInstant::from_micros(i64::try_from(since).unwrap_or(i64::MAX))
}

/// smoltcp's device: two frame queues, one each way, and the relay's slot
/// for a parked SYN.
#[derive(Default)]
pub(crate) struct Pipe {
    /// Guest frames for smoltcp.
    to_stack: VecDeque<Vec<u8>>,
    /// Frames for the guest, from the dispatcher and from smoltcp.
    to_guest: VecDeque<Vec<u8>>,
    /// Frames smoltcp made that the full guest queue refused, since the
    /// stack last counted them.
    refused: u64,
    /// A guest SYN the relay hands smoltcp ahead of the queue.
    injected: Option<Vec<u8>>,
}

impl Pipe {
    /// Queues `frame` for the guest, unless its queue is full; says which.
    pub(crate) fn queue_for_guest(&mut self, frame: Vec<u8>) -> bool {
        if self.to_guest.len() >= QUEUE_CAP {
            return false;
        }
        self.to_guest.push_back(frame);
        true
    }

    /// Makes `frame` the next frame smoltcp receives, ahead of the queue
    /// and even while the guest's queue is full (a SYN to a listening
    /// socket gets no answer through its token; the SYN-ACK waits for
    /// egress).
    pub(crate) fn inject(&mut self, frame: Vec<u8>) {
        self.injected = Some(frame);
    }

    /// Forgets an injected frame smoltcp did not take.
    pub(crate) fn clear_injected(&mut self) {
        self.injected = None;
    }
}

impl phy::Device for Pipe {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    /// An injected frame first. Otherwise nothing while the guest's queue
    /// is full: smoltcp answers a frame through the token that comes with
    /// it, and the guest has no room for the answer. The frame waits in
    /// its queue.
    fn receive(&mut self, _now: SmolInstant) -> Option<(RxToken, TxToken<'_>)> {
        if let Some(frame) = self.injected.take() {
            return Some((
                RxToken(frame),
                TxToken {
                    queue: &mut self.to_guest,
                    refused: &mut self.refused,
                },
            ));
        }
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

pub(crate) struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub(crate) struct TxToken<'a> {
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
