// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! [`NetStack`]: the gateway the guest sees, as one single-threaded state
//! machine over Ethernet frames.
//!
//! Every guest frame goes through the dispatcher first ([`classify`]):
//! ARP, DHCP and ICMP are answered here, deterministically, DNS to the
//! gateway goes to the [forwarder](crate::dns), a TCP SYN to the
//! [TCP relay](crate::tcp), which decides it before anything answers it,
//! other UDP to the [UDP relay](crate::udp), and what is not carried is
//! dropped and counted. Only the rest of TCP, and what smoltcp must learn
//! from ARP, reaches smoltcp. smoltcp's interface owns the gateway's MAC
//! and address, with any-IP on and a default route through itself, so its
//! sockets can be any destination; the TCP relay makes one for each
//! connection it lets through. TCP connections and UDP flows take their
//! ids from one count.
//!
//! The stack's host fds are the forwarder's upstream socket (token
//! [`DNS_TOKEN`], asked for by the first [`poll`](NetStack::poll)), one
//! socket for each relayed connection (tokens from
//! [`TCP_TOKEN_BASE`]), and one for each UDP
//! mapping (tokens from [`UDP_TOKEN_BASE`]). The
//! stack asks the net thread to start, change and stop watching them
//! through the [`FdChange`]s each poll returns, and
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
use crate::tcp::flow::FlowIds;
use crate::tcp::relay::Relay;
use crate::tcp::TCP_TOKEN_BASE;
use crate::udp::{UdpRelay, UDP_TOKEN_BASE};
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
    /// The UDP relay: the guest's mappings and their host sockets.
    udp: UdpRelay,
    /// The flow ids, which TCP and UDP share.
    ids: FlowIds,
    /// The host's own addresses, which the guest may not reach.
    host_addrs: HostAddrs,
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
        NetStack::with_flow_ids(cfg, sink, policy, FlowIds::default())
    }

    /// [`NetStack::new`], giving out flow ids from `ids`, whose clones share
    /// one count: the device hands every stack it builds the same one.
    pub(crate) fn with_flow_ids(
        cfg: NetConfig,
        sink: AuditSink,
        policy: Arc<ArcSwap<Policy>>,
        ids: FlowIds,
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
        let tcp = Relay::new(cfg.tcp.clone());
        let udp = UdpRelay::new(cfg.udp.clone());
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
            udp,
            ids,
            host_addrs: HostAddrs::system(),
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
        self.host_addrs = addrs;
    }

    /// The TCP connections the stack holds: those relayed or ending, and
    /// those waiting on their host connect.
    pub fn open_flows(&self) -> usize {
        self.tcp.open_flows()
    }

    /// The UDP mappings the stack holds: the 5-tuples the policy allowed,
    /// each with its host socket.
    pub fn udp_mappings(&self) -> usize {
        self.udp.len()
    }

    /// Takes one Ethernet frame the guest sent.
    ///
    /// TCP, UDP and ICMP (DNS included) must come from the guest's own
    /// address, or they are dropped as `src_spoof` before anything handles
    /// them; DHCP, which the gateway answers itself, may come from any
    /// address (a client starts from `0.0.0.0`, and one that asks for an
    /// address it no longer has is told so).
    pub fn push_guest_frame(&mut self, frame: &[u8]) {
        let now = Instant::now();
        let dispatch = classify(frame, self.cfg.gateway);
        if self.spoofed(&dispatch) {
            return self.drop_frame(DropReason::SrcSpoof, now);
        }
        match dispatch {
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
            Dispatch::Udp { src, dst } => self.udp_datagram(frame, src, dst, now),
            Dispatch::Icmp { .. } => match icmp::reply(&self.cfg, frame) {
                Some(reply) => {
                    self.send_to_guest(reply, now);
                }
                None => self.drop_frame(DropReason::Icmp, now),
            },
            Dispatch::TcpSyn { src, dst } => self.tcp_syn(frame, src, dst, now),
            // Segments of the relay's connections; smoltcp resets any other.
            // A reset for a connect still under way goes no further.
            // The relay notes where the guest's stream ends.
            Dispatch::Tcp { src, dst } => {
                if frame::tcp_reset_flag(frame) {
                    let Parts { tcp, mut cx, .. } = self.split(now);
                    if tcp.guest_rst(&mut cx, src, dst) {
                        return;
                    }
                }
                if let Some(fin) = frame::tcp_fin_position(frame) {
                    self.tcp.guest_fin_at(src, dst, fin);
                }
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

    /// How many frames wait for the guest: at most [`QUEUE_CAP`]. The
    /// device takes one only when it has a buffer for it, and leaves the
    /// rest here.
    pub fn host_frames(&self) -> usize {
        self.pipe.to_guest.len()
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
    /// time is up reset the guest, gated connections whose time is up are
    /// denied, and UDP mappings idle too long are closed, so
    /// `next_deadline` counts the next of each too. The first poll asks for
    /// the DNS socket to be watched. Host sockets the last outcome asked to
    /// be unwatched are closed first.
    pub fn poll(&mut self, now: Instant) -> PollOutcome {
        self.tcp.bury();
        self.udp.bury();
        for pending in self.dns.expire(now) {
            self.refuse(pending, dns::SERVFAIL, now);
        }
        let stamp = smoltcp_time(self.epoch, now);
        {
            let Parts {
                tcp, udp, mut cx, ..
            } = self.split(now);
            tcp.expire(&mut cx);
            udp.expire(&mut cx);
        }
        self.iface.poll(stamp, &mut self.pipe, &mut self.sockets);
        {
            let Parts { tcp, mut cx, .. } = self.split(now);
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
        fd_changes.extend(self.udp.take_fd_changes());
        let smoltcp_due = self
            .iface
            .poll_delay(stamp, &self.sockets)
            .and_then(|delay| now.checked_add(delay.into()));
        let next_deadline = [
            smoltcp_due,
            self.drops.next_due(),
            self.dns.next_deadline(),
            self.tcp.next_deadline(now),
            self.udp.next_deadline(now),
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
    /// [`poll`](Self::poll), as do the watch changes it makes. For a UDP
    /// mapping's socket, every datagram waiting on it is queued for the
    /// guest. Events for tokens the stack no longer uses are ignored.
    ///
    /// The fds must be watched level-triggered, never edge-triggered: one
    /// event reads a bounded number of datagrams from a UDP socket (64), and
    /// the TCP relay stops reading or writing when the guest or the host
    /// has no room, so readiness the stack left unhandled must be reported
    /// again at the next wait.
    pub fn on_host_fd_event(&mut self, token: u64, readable: bool, writable: bool) {
        let now = Instant::now();
        match owner(token) {
            Owner::Udp => {
                let Parts { udp, mut cx, .. } = self.split(now);
                return udp.host_event(&mut cx, token, readable);
            }
            Owner::Tcp => {
                let Parts { tcp, mut cx, .. } = self.split(now);
                return tcp.host_event(&mut cx, token, readable, writable);
            }
            Owner::Dns if readable => {}
            Owner::Dns | Owner::Nobody => return,
        }
        for received in self.dns.receive() {
            match received {
                Received::Answer(answer) => self.deliver(answer, now),
                Received::Bogus => self.drop_frame(DropReason::DnsBogus, now),
            }
        }
    }

    /// Records the DNS queries still waiting for the upstream as
    /// unanswered (SERVFAIL), ends every TCP connection and UDP mapping
    /// (`net.close` with reason `shutdown`; the guest's side of a TCP
    /// connection is reset), and records every dropped-frame count still
    /// held, due or not, so the stack's last second is not lost. The net
    /// thread (M2 Task 9) calls it as it stops, before the audit log
    /// closes, and then drops the stack, which closes the host sockets.
    pub fn shutdown(&mut self) {
        let now = Instant::now();
        for pending in self.dns.abandon() {
            self.record(dns_record(pending, dns::SERVFAIL, Vec::new()));
        }
        {
            let Parts {
                tcp, udp, mut cx, ..
            } = self.split(now);
            tcp.shutdown(&mut cx);
            udp.shutdown(&mut cx);
        }
        for counted in self.drops.flush_all(now) {
            audit::try_emit(&self.sink, Payload::NetDrop(counted));
        }
    }

    /// A guest SYN from `guest` to `dst`: the relay decides it on the
    /// policy and the names the DNS cache has for `dst`.
    fn tcp_syn(&mut self, frame: &[u8], guest: SocketAddrV4, dst: SocketAddrV4, now: Instant) {
        let names = self.dns_cache.names_for_at(*dst.ip(), now);
        let Parts { tcp, mut cx, .. } = self.split(now);
        tcp.syn(&mut cx, frame, guest, dst, names);
    }

    /// A guest UDP datagram from `guest` to `dst` (not DHCP, and not DNS
    /// to the gateway): the UDP relay carries it, deciding a new 5-tuple
    /// on the policy and the names the DNS cache has for `dst`.
    fn udp_datagram(&mut self, frame: &[u8], guest: SocketAddrV4, dst: SocketAddrV4, now: Instant) {
        let Some(payload) = frame::udp_payload(frame) else {
            // Unreachable: the frame was classified as UDP.
            return self.drop_frame(DropReason::Other, now);
        };
        let Parts {
            udp,
            dns_cache,
            mut cx,
            ..
        } = self.split(now);
        udp.datagram(&mut cx, guest, dst, payload, || {
            dns_cache.names_for_at(*dst.ip(), now)
        });
    }

    /// Whether `dispatch` is IP traffic the stack carries or answers (DHCP
    /// aside) from a source other than the guest's address.
    fn spoofed(&self, dispatch: &Dispatch) -> bool {
        let src = match dispatch {
            Dispatch::Dns { src, .. }
            | Dispatch::Udp { src, .. }
            | Dispatch::TcpSyn { src, .. }
            | Dispatch::Tcp { src, .. } => *src.ip(),
            Dispatch::Icmp { src, .. } => *src,
            Dispatch::Arp | Dispatch::Dhcp | Dispatch::Ipv6 | Dispatch::Other => return false,
        };
        src != self.cfg.guest_ip
    }

    /// The relays, the DNS cache, and what the relays borrow from the
    /// rest of the stack.
    fn split(&mut self, now: Instant) -> Parts<'_> {
        let cx = Ctx {
            cfg: &self.cfg,
            sink: &self.sink,
            policy: self.policy.load_full(),
            iface: &mut self.iface,
            pipe: &mut self.pipe,
            sockets: &mut self.sockets,
            drops: &mut self.drops,
            ids: &mut self.ids,
            host_addrs: &mut self.host_addrs,
            now,
            stamp: smoltcp_time(self.epoch, now),
        };
        Parts {
            tcp: &mut self.tcp,
            udp: &mut self.udp,
            dns_cache: &self.dns_cache,
            cx,
        }
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

/// What a host fd's token is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Dns,
    /// A TCP flow's host socket: [`TCP_TOKEN_BASE`](crate::TCP_TOKEN_BASE)
    /// up to [`UDP_TOKEN_BASE`].
    Tcp,
    /// A UDP mapping's host socket: [`UDP_TOKEN_BASE`] on.
    Udp,
    Nobody,
}

fn owner(token: u64) -> Owner {
    if token == DNS_TOKEN {
        Owner::Dns
    } else if token >= UDP_TOKEN_BASE {
        Owner::Udp
    } else if token >= TCP_TOKEN_BASE {
        Owner::Tcp
    } else {
        Owner::Nobody
    }
}

/// The stack, split for a relay's call.
struct Parts<'a> {
    tcp: &'a mut Relay,
    udp: &'a mut UdpRelay,
    dns_cache: &'a DnsCache,
    cx: Ctx<'a>,
}

/// What a relay (TCP or UDP) borrows from the rest of the stack for one
/// call.
pub(crate) struct Ctx<'a> {
    pub(crate) cfg: &'a NetConfig,
    pub(crate) sink: &'a AuditSink,
    /// The policy as it stands now.
    pub(crate) policy: Arc<Policy>,
    pub(crate) iface: &'a mut Interface,
    pub(crate) pipe: &'a mut Pipe,
    pub(crate) sockets: &'a mut SocketSet<'static>,
    pub(crate) drops: &'a mut Drops,
    /// The flow ids, which TCP and UDP share.
    pub(crate) ids: &'a mut FlowIds,
    /// The host's own addresses, which the guest may not reach.
    pub(crate) host_addrs: &'a mut HostAddrs,
    /// Now, on the stack's clock and on smoltcp's.
    pub(crate) now: Instant,
    pub(crate) stamp: SmolInstant,
}

impl Ctx<'_> {
    /// Records an event that must not be dropped (see [`audit::record`]).
    pub(crate) fn record(&self, payload: Payload) {
        audit::record(self.sink, payload);
    }

    /// Counts a guest frame dropped for `reason`.
    pub(crate) fn drop_frame(&mut self, reason: DropReason) {
        if let Some(counted) = self.drops.count(reason, self.now) {
            audit::try_emit(self.sink, Payload::NetDrop(counted));
        }
    }

    /// Queues `frame` for the guest, and says whether it was: a full queue
    /// drops it as `queue_full`.
    pub(crate) fn send_to_guest(&mut self, frame: Vec<u8>) -> bool {
        if self.pipe.queue_for_guest(frame) {
            return true;
        }
        self.guest_full()
    }

    /// Queues for the guest (by its MAC) a UDP datagram from `src` to
    /// `dst` carrying `payload`, and says whether it was: with the guest's
    /// queue full it is dropped as `queue_full` before a frame is built,
    /// and a payload too long for one IPv4 packet is not sent.
    pub(crate) fn udp_to_guest(
        &mut self,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> bool {
        if !self.pipe.has_room() {
            return self.guest_full();
        }
        let built = frame::udp_frame(
            EthernetAddress(self.cfg.gateway_mac),
            EthernetAddress(self.cfg.guest_mac),
            src,
            dst,
            payload,
        );
        built.is_some_and(|built| self.send_to_guest(built))
    }

    /// Drops a frame for the guest as `queue_full`; always `false`.
    fn guest_full(&mut self) -> bool {
        boxcar_virtio::limited!(warn, "net: the guest is not taking frames; dropping");
        self.drop_frame(DropReason::QueueFull);
        false
    }
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
        if !self.has_room() {
            return false;
        }
        self.to_guest.push_back(frame);
        true
    }

    /// Whether the guest's queue takes another frame.
    pub(crate) fn has_room(&self) -> bool {
        self.to_guest.len() < QUEUE_CAP
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{ErrorKind, Read};
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::rc::Rc;
    use std::time::Duration;

    use boxcar_audit::WriterConfig;
    use boxcar_proto::SessionId;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, EthernetRepr,
        IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    /// The guest's ARP request for the gateway, which teaches smoltcp the
    /// guest's MAC.
    fn arp(cfg: &NetConfig) -> Vec<u8> {
        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress(cfg.guest_mac),
            source_protocol_addr: cfg.guest_ip,
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: cfg.gateway,
        };
        let eth = EthernetRepr {
            src_addr: EthernetAddress(cfg.guest_mac),
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
        };
        let mut buf = vec![0; eth.buffer_len() + repr.buffer_len()];
        let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
        eth.emit(&mut frame);
        repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
        buf
    }

    /// A guest TCP segment.
    fn segment(
        cfg: &NetConfig,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        control: TcpControl,
        (seq, ack): (u32, Option<u32>),
        payload: &[u8],
    ) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: src.port(),
            dst_port: dst.port(),
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: ack.map(|ack| TcpSeqNumber(ack as i32)),
            window_len: 65_535,
            window_scale: None,
            max_seg_size: (control == TcpControl::Syn).then_some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: *src.ip(),
            dst_addr: *dst.ip(),
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        };
        frame::ipv4_frame(
            EthernetAddress(cfg.guest_mac),
            EthernetAddress(cfg.gateway_mac),
            &ip,
            |buf| {
                repr.emit(
                    &mut TcpPacket::new_unchecked(buf),
                    &(*src.ip()).into(),
                    &(*dst.ip()).into(),
                    &ChecksumCapabilities::default(),
                )
            },
        )
    }

    /// The sequence number of a SYN-ACK the stack sent, if `frame` is one.
    fn syn_ack(frame: &[u8]) -> Option<u32> {
        let eth = EthernetFrame::new_checked(frame).ok()?;
        let ip = Ipv4Packet::new_checked(eth.payload()).ok()?;
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        (tcp.syn() && tcp.ack()).then_some(tcp.seq_number().0 as u32)
    }

    /// A ClientHello naming `name`, in one record.
    fn hello(name: &str) -> Vec<u8> {
        let with_len = |body: Vec<u8>| {
            let mut out = (body.len() as u16).to_be_bytes().to_vec();
            out.extend(body);
            out
        };
        let mut entry = vec![0];
        entry.extend(with_len(name.as_bytes().to_vec()));
        let mut extension = 0_u16.to_be_bytes().to_vec();
        extension.extend(with_len(with_len(entry)));
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend(with_len(extension));
        let mut handshake = vec![1, 0];
        handshake.extend(with_len(body));
        let mut record = vec![22, 3, 1];
        record.extend(with_len(handshake));
        record
    }

    /// The gate's `net.tls{allow}` is in the log's channel before the
    /// first held byte is written to the host: when the record is made,
    /// the host has received nothing.
    #[test]
    fn the_gate_records_its_pass_before_any_byte_goes_on() {
        let dir = tempfile::TempDir::new().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new()))
                .unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = NetConfig {
            dns_upstreams: vec![upstream.local_addr().unwrap()],
            ..NetConfig::default()
        };
        let policy = Policy::parse(&["allow example.com", "allow 127.0.0.0/8"]).unwrap();
        let mut stack =
            NetStack::new(cfg.clone(), sink, Arc::new(ArcSwap::from_pointee(policy))).unwrap();
        stack
            .dns_cache
            .insert(Ipv4Addr::LOCALHOST, "example.com", 60);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(server) = listener.local_addr().unwrap() else {
            panic!("not IPv4");
        };
        let guest = SocketAddrV4::new(cfg.guest_ip, 40_000);
        stack.poll(Instant::now());
        stack.push_guest_frame(&arp(&cfg));
        while stack.pop_host_frame().is_some() {}

        // The SYN, the host connect, the SYN-ACK.
        let syn = segment(&cfg, guest, server, TcpControl::Syn, (1000, None), &[]);
        stack.push_guest_frame(&syn);
        stack.poll(Instant::now());
        let mut isn = None;
        for _ in 0..2000 {
            stack.on_host_fd_event(TCP_TOKEN_BASE + 1, false, true);
            stack.poll(Instant::now());
            while let Some(frame) = stack.pop_host_frame() {
                isn = isn.or(syn_ack(&frame));
            }
            if isn.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let ack = isn.expect("a SYN-ACK").wrapping_add(1);
        let (mut peer, _) = listener.accept().unwrap();
        let ack_frame = segment(
            &cfg,
            guest,
            server,
            TcpControl::None,
            (1001, Some(ack)),
            &[],
        );
        stack.push_guest_frame(&ack_frame);
        stack.poll(Instant::now());

        // The hello: the gate passes it, recording first.
        let at_record: Rc<Cell<Option<bool>>> = Rc::default();
        let seen = Rc::clone(&at_record);
        let probe = peer.try_clone().unwrap();
        probe.set_nonblocking(true).unwrap();
        crate::audit::tests::RECORDED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |payload| {
                if matches!(payload, Payload::NetTls(_)) {
                    let mut byte = [0];
                    let empty = matches!(probe.peek(&mut byte),
                        Err(e) if e.kind() == ErrorKind::WouldBlock);
                    seen.set(Some(empty));
                }
            }));
        });
        let hello = hello("example.com");
        let data = segment(
            &cfg,
            guest,
            server,
            TcpControl::Psh,
            (1001, Some(ack)),
            &hello,
        );
        stack.push_guest_frame(&data);
        stack.poll(Instant::now());
        crate::audit::tests::RECORDED.with(|hook| hook.borrow_mut().take());
        assert_eq!(
            at_record.get(),
            Some(true),
            "net.tls was recorded, with nothing at the host yet"
        );
        let mut got = vec![0; hello.len()];
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, hello, "and then the hello went on");
        drop(stack);
        writer.close().unwrap();
    }

    /// Each host fd token goes to the part of the stack that made it. A
    /// TCP flow whose id is past 2^32 (where the token spaces once met)
    /// is still TCP's.
    #[test]
    fn tokens_route_to_their_owner() {
        use crate::tcp::{FlowId, FLOW_ID_LIMIT};
        assert_eq!(owner(DNS_TOKEN), Owner::Dns);
        assert_eq!(owner(FlowId(1).token()), Owner::Tcp);
        assert_eq!(owner(FlowId((1 << 32) + 7).token()), Owner::Tcp);
        assert_eq!(owner(FlowId(FLOW_ID_LIMIT - 1).token()), Owner::Tcp);
        assert_eq!(owner(UDP_TOKEN_BASE + 7), Owner::Udp);
        assert_eq!(owner(UDP_TOKEN_BASE + (FLOW_ID_LIMIT - 1)), Owner::Udp);
        assert_eq!(owner(0), Owner::Nobody);
        assert_eq!(owner(TCP_TOKEN_BASE - 1), Owner::Nobody);
    }

    /// A UDP mapping's `net.udp{allow}` is in the log's channel before its
    /// first datagram goes to the host.
    #[test]
    fn a_mapping_is_recorded_before_its_first_datagram_goes_on() {
        let dir = tempfile::TempDir::new().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new()))
                .unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = NetConfig {
            dns_upstreams: vec![upstream.local_addr().unwrap()],
            ..NetConfig::default()
        };
        let policy = Policy::parse(&["allow 127.0.0.0/8"]).unwrap();
        let mut stack =
            NetStack::new(cfg.clone(), sink, Arc::new(ArcSwap::from_pointee(policy))).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(at) = server.local_addr().unwrap() else {
            panic!("not IPv4");
        };
        let probe = server.try_clone().unwrap();
        probe.set_nonblocking(true).unwrap();
        let at_record: Rc<Cell<Option<bool>>> = Rc::default();
        let seen = Rc::clone(&at_record);
        crate::audit::tests::RECORDED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |payload| {
                if matches!(payload, Payload::NetUdp(_)) {
                    let mut byte = [0];
                    let empty = matches!(probe.peek(&mut byte),
                        Err(e) if e.kind() == ErrorKind::WouldBlock);
                    seen.set(Some(empty));
                }
            }));
        });
        let guest = SocketAddrV4::new(cfg.guest_ip, 40_000);
        let datagram = frame::udp_frame(
            EthernetAddress(cfg.guest_mac),
            EthernetAddress(cfg.gateway_mac),
            guest,
            at,
            b"first",
        )
        .unwrap();
        stack.push_guest_frame(&datagram);
        crate::audit::tests::RECORDED.with(|hook| hook.borrow_mut().take());
        assert_eq!(
            at_record.get(),
            Some(true),
            "net.udp was recorded, with nothing at the server yet"
        );
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut got = [0; 16];
        let n = server.recv(&mut got).unwrap();
        assert_eq!(&got[..n], b"first", "and then the datagram went on");
        drop(stack);
        writer.close().unwrap();
    }
}
