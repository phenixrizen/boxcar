// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The UDP relay: NAT for the guest's datagrams, one connected host socket
//! for each 5-tuple the policy allows.
//!
//! # Deciding a tuple
//!
//! The first datagram of a 5-tuple (the guest's address and port, the
//! destination's, UDP) is decided as a TCP SYN is, but for domain rules
//! ([`upstream::decide_udp`]): one of the host's own addresses is denied
//! (`builtin:host-local`) unless a rule names it exactly, and then the
//! policy's [`egress_udp`](crate::Policy::egress_udp) decides, on the
//! names the DNS cache holds for the destination. A domain `allow` admits no UDP:
//! nothing in a datagram shows a name to check, as the TCP relay's gate
//! checks one, so it is passed over, and domain denials, network rules and
//! the default decide. When passing it over leaves the flow denied, the
//! rule text is `builtin:udp-needs-cidr`. DNS to the gateway never comes
//! here (the [forwarder](crate::dns) answers it); UDP to the gateway's
//! other ports is denied as `builtin:guest-net`, as is the rest of the
//! guest's network.
//!
//! # Mappings
//!
//! An allowed tuple gets a mapping: a host `UdpSocket` bound to
//! `0.0.0.0:0`, non-blocking, and connected to the destination, so the
//! host's kernel hands it only what the destination sends (what reached it
//! in the moment between its bind and its connect is thrown away). The
//! guest's datagrams go to that socket as they come; one it does not take
//! is dropped (`udp_send`), never queued. What the destination sends back
//! is read when the socket is ready, at most [`READS_PER_EVENT`] datagrams
//! at a time (a socket with more stays ready), and each goes to the guest
//! from the destination's address and port, unless it is too long for one
//! datagram on the link (over [`MAX_PAYLOAD`] bytes: `udp_oversize`), as
//! nothing here fragments, or the guest's queue is full (`queue_full`).
//! The host kernel's port unreachable for an earlier datagram
//! (`ECONNREFUSED` on the socket) is read and dropped, and the mapping
//! stays.
//!
//! There are at most [`UdpLimits::mapping_cap`] mappings: a new one evicts
//! the one idle longest (by its last datagram either way). A mapping no
//! datagram has used either way for [`UdpLimits::idle_timeout`] is closed
//! by the next poll. An evicted mapping's socket stays open until the poll
//! after the next (see below), so while [`UdpLimits::parked_cap`] of them
//! wait for the next poll, a new tuple that would evict another is dropped
//! (`udp_table_full`), undecided as far as the log goes. However many
//! tuples come between two polls, the relay holds at most `mapping_cap +
//! 2 × parked_cap` host sockets (open, waiting for a poll, closing at the
//! next), and at most `2 × (mapping_cap + parked_cap)` when a poll also
//! closed idle mappings.
//!
//! # Records
//!
//! One `net.udp` for each mapping, made before its first datagram goes on,
//! and one `net.close` when it ends: `idle`, `evicted`, or `shutdown` when
//! the stack stops. A denied tuple gets one `net.udp` too, and is then
//! remembered for [`REFUSAL_MEMORY`] (at most [`REFUSALS`] tuples, the
//! least recently used forgotten first): its datagrams in that time are
//! counted (`udp_denied`), not recorded. A tuple whose host socket could
//! not be made gets its `net.udp`, a `net.close` with the reason, and is
//! remembered the same way (its datagrams counted as `udp_send`). A policy
//! swap forgets every remembered tuple, so each is decided again.
//!
//! # Host sockets
//!
//! Each mapping's socket is watched for readability through an
//! [`FdChange`] whose token is [`UDP_TOKEN_BASE`] plus the mapping's flow
//! id. A mapping that ends is unwatched first, and its socket closes at
//! the start of the poll after the one whose outcome carried the
//! unwatching.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boxcar_proto::{NetUdp, Payload};
use smoltcp::wire::{IPV4_HEADER_LEN, UDP_HEADER_LEN};

use crate::audit::{close_record, DropReason};
use crate::policy::{Policy, Verdict};
use crate::stack::{Ctx, FdChange, Interest, IP_MTU};
use crate::tcp::{FlowId, FLOW_ID_LIMIT, MAX_TIMEOUT, TCP_TOKEN_BASE};
use crate::upstream;

/// The [`FdChange`] token of flow 0's host socket, were it a UDP mapping;
/// mapping `n`'s is this plus `n`. TCP flows' tokens are below it, from
/// [`TCP_TOKEN_BASE`], 2^62 below. The two stay apart because flow ids
/// stay below 2^62 ([`FLOW_ID_LIMIT`]).
pub const UDP_TOKEN_BASE: u64 = 2 << 62;
const _: () = assert!(
    UDP_TOKEN_BASE - TCP_TOKEN_BASE == FLOW_ID_LIMIT
        && FLOW_ID_LIMIT == 1 << 62
        && TCP_TOKEN_BASE > crate::stack::DNS_TOKEN
        && UDP_TOKEN_BASE.checked_add(FLOW_ID_LIMIT).is_some()
);

/// The longest payload of a datagram to the guest: one IPv4 packet the
/// size of the link's MTU, less its headers (1472 bytes).
pub const MAX_PAYLOAD: usize = IP_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// The most datagrams one readiness event of a mapping's socket reads;
/// a socket with more stays ready, and the net thread comes back to it.
pub const READS_PER_EVENT: usize = 64;

/// How many refused tuples the relay remembers.
pub const REFUSALS: usize = 1024;

/// How long a refused tuple is remembered, from its refusal.
pub const REFUSAL_MEMORY: Duration = Duration::from_secs(60);

/// The relay's bounds. The defaults are production's; tests lower them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpLimits {
    /// Mappings held at once; at the cap, the one idle longest (by its
    /// last datagram either way) is evicted for a new one.
    pub mapping_cap: usize,
    /// How long a mapping may go without a datagram either way before it
    /// is closed.
    pub idle_timeout: Duration,
    /// Evicted mappings' sockets that may wait for the next poll to close
    /// them; past it, with the table at its cap, a new tuple's datagram is
    /// dropped (`udp_table_full`) rather than evict another.
    pub parked_cap: usize,
}

impl Default for UdpLimits {
    fn default() -> Self {
        UdpLimits {
            mapping_cap: 1024,
            idle_timeout: Duration::from_secs(60),
            parked_cap: 256,
        }
    }
}

impl UdpLimits {
    /// What is wrong with these bounds, if anything: the caps must be at
    /// least one, and the idle timeout more than zero and at most
    /// [`MAX_TIMEOUT`].
    pub fn check(&self) -> Result<(), &'static str> {
        if self.mapping_cap == 0 {
            return Err("udp.mapping_cap must be at least 1");
        }
        if self.parked_cap == 0 {
            return Err("udp.parked_cap must be at least 1");
        }
        if self.idle_timeout.is_zero() || self.idle_timeout > MAX_TIMEOUT {
            return Err("udp.idle_timeout must be more than zero and at most a day");
        }
        Ok(())
    }
}

/// The guest's address and port, and the destination's.
type Tuple = (SocketAddrV4, SocketAddrV4);

/// What a mapping's host socket is watched for: replies.
const READABLE: Interest = Interest {
    readable: true,
    writable: false,
};

/// One allowed 5-tuple and the host socket that carries it.
#[derive(Debug)]
struct Mapping {
    guest: SocketAddrV4,
    dst: SocketAddrV4,
    /// The names the DNS cache gave `dst` when the first datagram came:
    /// what a policy swapped in decides the mapping on again.
    names: Vec<String>,
    /// Bound to `0.0.0.0:0` and connected to `dst`.
    socket: UdpSocket,
    /// When its first datagram was decided.
    opened: Instant,
    /// When its last datagram went either way.
    last_active: Instant,
    /// Payload bytes the guest sent that went to the host.
    tx: u64,
    /// Payload bytes the destination sent that went to the guest.
    rx: u64,
}

/// The UDP relay's state: its mappings, the tuples it refused lately, and
/// the host sockets it is done with.
#[derive(Debug)]
pub(crate) struct UdpRelay {
    limits: UdpLimits,
    mappings: BTreeMap<FlowId, Mapping>,
    by_tuple: HashMap<Tuple, FlowId>,
    /// Each mapping by its last datagram, the idlest first.
    idle: BTreeSet<(Instant, FlowId)>,
    refused: Refused,
    /// Watch changes for the next outcome.
    fd_changes: Vec<FdChange>,
    /// Host sockets whose unwatching the next outcome carries.
    graveyard: Vec<UdpSocket>,
    /// Host sockets whose unwatching the last outcome carried: closed at
    /// the start of the next poll.
    buried: Vec<UdpSocket>,
    /// Where replies are read, one at a time: a byte longer than the
    /// longest the guest can be given, so a longer one shows (the kernel
    /// cuts a datagram down to the buffer).
    scratch: Vec<u8>,
}

impl UdpRelay {
    pub(crate) fn new(limits: UdpLimits) -> UdpRelay {
        UdpRelay {
            limits,
            mappings: BTreeMap::new(),
            by_tuple: HashMap::new(),
            idle: BTreeSet::new(),
            refused: Refused::new(REFUSALS),
            fd_changes: Vec::new(),
            graveyard: Vec::new(),
            buried: Vec::new(),
            scratch: vec![0; MAX_PAYLOAD + 1],
        }
    }

    /// Mappings held.
    pub(crate) fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Closes the host sockets whose unwatching the last outcome carried.
    pub(crate) fn bury(&mut self) {
        self.buried.clear();
    }

    /// The watch changes for this outcome. The host sockets they unwatch
    /// close at the next [`bury`](Self::bury).
    pub(crate) fn take_fd_changes(&mut self) -> Vec<FdChange> {
        self.buried.append(&mut self.graveyard);
        std::mem::take(&mut self.fd_changes)
    }

    /// When the relay next needs a poll: at once while host sockets wait
    /// to be closed, else when the idlest mapping falls idle.
    pub(crate) fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.buried.is_empty() {
            return Some(now);
        }
        let (last, _) = self.idle.first()?;
        last.checked_add(self.limits.idle_timeout)
    }

    /// A guest datagram from `guest` to `dst` carrying `payload`. A tuple
    /// with a mapping sends it on; a tuple refused lately drops it; a new
    /// tuple is decided on the current policy and `names` (the names the
    /// guest knows `dst` by, asked for only then), recorded, and given a
    /// mapping if allowed, unless the table is full and the most evicted
    /// sockets already wait to close (`udp_table_full`, not recorded).
    pub(crate) fn datagram(
        &mut self,
        cx: &mut Ctx,
        guest: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
        names: impl FnOnce() -> Vec<String>,
    ) {
        let tuple = (guest, dst);
        if let Some(&id) = self.by_tuple.get(&tuple) {
            return self.send(cx, id, payload);
        }
        if let Some(reason) = self.refused.check(&cx.policy, tuple, cx.now) {
            return cx.drop_frame(reason);
        }
        let names = names();
        let (verdict, rule) = upstream::decide_udp(cx.host_addrs, &cx.policy, dst, &names, cx.now);
        if verdict == Verdict::Allow
            && self.mappings.len() >= self.limits.mapping_cap
            && self.graveyard.len() >= self.limits.parked_cap
        {
            // Not decided as far as the log goes: the next datagram is.
            return cx.drop_frame(DropReason::UdpTableFull);
        }
        let id = cx.ids.next();
        cx.record(Payload::NetUdp(NetUdp {
            flow: id.0,
            src: guest,
            dst,
            names: names.clone(),
            verdict,
            rule,
        }));
        if verdict == Verdict::Deny {
            return self.refused.insert(tuple, DropReason::UdpDenied, cx.now);
        }
        let socket = match open(dst) {
            Ok(socket) => socket,
            Err(error) => {
                boxcar_virtio::limited!(warn, "net: udp: no host socket for {dst}: {error}");
                let reason = upstream::close_reason(&error);
                cx.record(close_record(id, 0, 0, cx.now, cx.now, reason));
                return self.refused.insert(tuple, DropReason::UdpSend, cx.now);
            }
        };
        if self.mappings.len() >= self.limits.mapping_cap {
            self.evict(cx);
        }
        self.fd_changes.push(FdChange {
            token: token(id),
            fd: socket.as_raw_fd(),
            interest: READABLE,
        });
        self.mappings.insert(
            id,
            Mapping {
                guest,
                dst,
                names,
                socket,
                opened: cx.now,
                last_active: cx.now,
                tx: 0,
                rx: 0,
            },
        );
        self.by_tuple.insert(tuple, id);
        self.idle.insert((cx.now, id));
        self.send(cx, id, payload);
    }

    /// A mapping's host socket is ready: every datagram waiting on it goes
    /// to the guest, or is dropped if it is too long for the link. Events
    /// for mappings that have gone are ignored.
    pub(crate) fn host_event(&mut self, cx: &mut Ctx, token: u64, readable: bool) {
        let Some(id) = from_token(token) else {
            return;
        };
        let Some(mapping) = self.mappings.get_mut(&id) else {
            return;
        };
        if !readable {
            return;
        }
        let mut heard = false;
        for _ in 0..READS_PER_EVENT {
            let n = match mapping.socket.recv(&mut self.scratch) {
                Ok(n) => n,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                // The host's ICMP errors for earlier datagrams, port
                // unreachable above all: read, and nothing more.
                Err(error) if is_icmp_error(&error) => continue,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    boxcar_virtio::limited!(warn, "net: udp: flow {id}: {error}");
                    break;
                }
            };
            heard = true;
            let Some(payload) = self.scratch.get(..n).filter(|_| n <= MAX_PAYLOAD) else {
                cx.drop_frame(DropReason::UdpOversize);
                continue;
            };
            if cx.udp_to_guest(mapping.dst, mapping.guest, payload) {
                mapping.rx = mapping.rx.saturating_add(count(n));
            }
        }
        if heard {
            touch(&mut self.idle, id, mapping, cx.now);
        }
    }

    /// Closes every mapping no datagram has used for the idle timeout.
    pub(crate) fn expire(&mut self, cx: &mut Ctx) {
        while let Some(&(last, id)) = self.idle.first() {
            let due = last.checked_add(self.limits.idle_timeout);
            if due.is_none_or(|due| due > cx.now) {
                break;
            }
            self.idle.remove(&(last, id));
            self.close(cx, id, "idle");
        }
    }

    /// For a policy swapped in (`cx.policy` is the new one): closes every
    /// mapping that it denies, decided as the first datagram was
    /// ([`upstream::decide_udp`]), on the names the guest knew the
    /// destination by then, and records each as `net.close{reason:
    /// "policy"}`, in id order. Its tuple is decided afresh at its next
    /// datagram. A mapping the new policy still allows is left as it is.
    pub(crate) fn revoke(&mut self, cx: &mut Ctx) {
        let policy = Arc::clone(&cx.policy);
        let denied: Vec<FlowId> = self
            .mappings
            .iter()
            .filter(|(_, mapping)| {
                upstream::decide_udp(cx.host_addrs, &policy, mapping.dst, &mapping.names, cx.now).0
                    == Verdict::Deny
            })
            .map(|(id, _)| *id)
            .collect();
        for id in denied {
            self.close(cx, id, "policy");
        }
    }

    /// Closes every mapping, recording each as `shutdown`, for the stack
    /// stopping. The host sockets close when the stack is dropped.
    pub(crate) fn shutdown(&mut self, cx: &mut Ctx) {
        let ids: Vec<FlowId> = self.mappings.keys().copied().collect();
        for id in ids {
            self.close(cx, id, "shutdown");
        }
    }

    /// Sends a guest datagram on mapping `id`'s host socket, or drops it
    /// (`udp_send`).
    fn send(&mut self, cx: &mut Ctx, id: FlowId, payload: &[u8]) {
        let Some(mapping) = self.mappings.get_mut(&id) else {
            return;
        };
        touch(&mut self.idle, id, mapping, cx.now);
        match send_datagram(&mapping.socket, payload) {
            Ok(()) => mapping.tx = mapping.tx.saturating_add(count(payload.len())),
            Err(error) => {
                if error.kind() != ErrorKind::WouldBlock {
                    boxcar_virtio::limited!(debug, "net: udp: flow {id}: {error}");
                }
                cx.drop_frame(DropReason::UdpSend);
            }
        }
    }

    /// Makes room for a new mapping: closes the one idle longest.
    fn evict(&mut self, cx: &mut Ctx) {
        if let Some((_, id)) = self.idle.pop_first() {
            self.close(cx, id, "evicted");
        }
    }

    /// Ends mapping `id` for `reason`: records it, and unwatches its host
    /// socket and puts it in the graveyard.
    fn close(&mut self, cx: &mut Ctx, id: FlowId, reason: &str) {
        let Some(mapping) = self.mappings.remove(&id) else {
            return;
        };
        self.idle.remove(&(mapping.last_active, id));
        self.by_tuple.remove(&(mapping.guest, mapping.dst));
        cx.record(close_record(
            id,
            mapping.tx,
            mapping.rx,
            mapping.opened,
            cx.now,
            reason,
        ));
        self.fd_changes.push(FdChange {
            token: token(id),
            fd: mapping.socket.as_raw_fd(),
            interest: Interest::default(),
        });
        self.graveyard.push(mapping.socket);
    }
}

/// A non-blocking host socket on an ephemeral port, connected to `dst`
/// and holding nothing from anyone else.
fn open(dst: SocketAddrV4) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_nonblocking(true)?;
    connect_only_to(socket, dst)
}

/// The most datagrams [`connect_only_to`] throws away before it gives up
/// on a socket.
const STALE_LIMIT: usize = 1024;

/// Connects the non-blocking `socket` to `dst`, then throws away whatever
/// is queued on it. From the connect on, the kernel hands the socket only
/// what `dst` sends; what reached it while it was bound and not yet
/// connected (anyone's) stays queued, and would read as a reply from
/// `dst`. Nothing has been sent from it yet, so nothing queued is one.
fn connect_only_to(socket: UdpSocket, dst: SocketAddrV4) -> io::Result<UdpSocket> {
    socket.connect(dst)?;
    let mut sink = [0; 1];
    for _ in 0..STALE_LIMIT {
        match socket.recv(&mut sink) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(socket),
            Err(error) if is_icmp_error(&error) || error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("flooded before its first datagram"))
}

/// Sends one datagram. An ICMP error the host had for an earlier datagram
/// (port unreachable) is reported by the next call on the socket, which
/// then sends nothing; the datagram is sent again once in that case.
fn send_datagram(socket: &UdpSocket, payload: &[u8]) -> io::Result<()> {
    match socket.send(payload) {
        Err(error) if is_icmp_error(&error) => socket.send(payload).map(drop),
        sent => sent.map(drop),
    }
}

/// Whether `error` is an ICMP error the host's kernel reported on a
/// connected socket, for a datagram already sent.
fn is_icmp_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
    )
}

/// Marks mapping `id` as used at `now`.
fn touch(idle: &mut BTreeSet<(Instant, FlowId)>, id: FlowId, mapping: &mut Mapping, now: Instant) {
    idle.remove(&(mapping.last_active, id));
    mapping.last_active = mapping.last_active.max(now);
    idle.insert((mapping.last_active, id));
}

/// The token of mapping `id`'s host socket.
fn token(id: FlowId) -> u64 {
    UDP_TOKEN_BASE.saturating_add(id.0)
}

/// The mapping a host socket's token is for, if it is a mapping's.
fn from_token(token: u64) -> Option<FlowId> {
    token
        .checked_sub(UDP_TOKEN_BASE)
        .filter(|id| *id < FLOW_ID_LIMIT)
        .map(FlowId)
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The tuples the relay refused lately, and what their datagrams are
/// dropped as: at most a cap of them, each for [`REFUSAL_MEMORY`] from its
/// refusal, the least recently used forgotten first at the cap, and all of
/// them when the policy is swapped.
#[derive(Debug)]
struct Refused {
    cap: usize,
    /// The policy they were refused under.
    under: Option<Arc<Policy>>,
    entries: HashMap<Tuple, Refusal>,
    /// Each tuple by its last use, the least recent first.
    order: BTreeMap<u64, Tuple>,
    /// The last use stamp given.
    stamp: u64,
}

#[derive(Debug)]
struct Refusal {
    at: Instant,
    used: u64,
    reason: DropReason,
}

impl Refused {
    fn new(cap: usize) -> Refused {
        Refused {
            cap,
            under: None,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            stamp: 0,
        }
    }

    /// What `tuple`'s datagrams are dropped as, if it was refused under
    /// `policy` less than [`REFUSAL_MEMORY`] before `now`; a hit makes it
    /// the most recently used. A policy other than the one the tuples were
    /// refused under forgets them all first.
    fn check(&mut self, policy: &Arc<Policy>, tuple: Tuple, now: Instant) -> Option<DropReason> {
        if !self
            .under
            .as_ref()
            .is_some_and(|under| Arc::ptr_eq(under, policy))
        {
            self.entries.clear();
            self.order.clear();
            self.under = Some(Arc::clone(policy));
        }
        let entry = self.entries.get_mut(&tuple)?;
        self.order.remove(&entry.used);
        if now.saturating_duration_since(entry.at) >= REFUSAL_MEMORY {
            self.entries.remove(&tuple);
            return None;
        }
        self.stamp = self.stamp.saturating_add(1);
        entry.used = self.stamp;
        self.order.insert(self.stamp, tuple);
        Some(entry.reason)
    }

    /// Remembers that `tuple` was refused at `now`, its datagrams to be
    /// dropped as `reason`, forgetting the least recently used at the cap.
    /// (Made after a [`check`](Self::check) under the same policy.)
    fn insert(&mut self, tuple: Tuple, reason: DropReason, now: Instant) {
        if let Some(old) = self.entries.remove(&tuple) {
            self.order.remove(&old.used);
        }
        while self.entries.len() >= self.cap {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.stamp = self.stamp.saturating_add(1);
        self.entries.insert(
            tuple,
            Refusal {
                at: now,
                used: self.stamp,
                reason,
            },
        );
        self.order.insert(self.stamp, tuple);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(port: u16) -> Tuple {
        (
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), port),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9),
        )
    }

    #[test]
    fn the_defaults_are_production_bounds() {
        let limits = UdpLimits::default();
        assert_eq!(limits.mapping_cap, 1024);
        assert_eq!(limits.idle_timeout, Duration::from_secs(60));
        assert_eq!(limits.parked_cap, 256);
        assert_eq!(READS_PER_EVENT, 64);
        assert_eq!(limits.check(), Ok(()));
        assert_eq!(MAX_PAYLOAD, 1472);
        assert_eq!(REFUSALS, 1024);
        assert_eq!(REFUSAL_MEMORY, Duration::from_secs(60));
        assert_eq!(UDP_TOKEN_BASE, 2 << 62);
        assert_eq!(TCP_TOKEN_BASE, 1 << 62);
        for broken in [
            UdpLimits {
                mapping_cap: 0,
                ..UdpLimits::default()
            },
            UdpLimits {
                idle_timeout: Duration::ZERO,
                ..UdpLimits::default()
            },
            UdpLimits {
                parked_cap: 0,
                ..UdpLimits::default()
            },
            UdpLimits {
                idle_timeout: MAX_TIMEOUT + Duration::from_secs(1),
                ..UdpLimits::default()
            },
        ] {
            assert!(broken.check().is_err(), "{broken:?}");
        }
    }

    #[test]
    fn tokens_name_their_mapping() {
        assert_eq!(token(FlowId(7)), UDP_TOKEN_BASE + 7);
        assert_eq!(from_token(UDP_TOKEN_BASE + 7), Some(FlowId(7)));
        assert_eq!(from_token(TCP_TOKEN_BASE + 7), None);
        // The last id there can be: the spaces do not meet, and nothing
        // saturates.
        let last = FlowId(FLOW_ID_LIMIT - 1);
        assert!(last.token() < UDP_TOKEN_BASE);
        assert_eq!(from_token(last.token()), None);
        assert_eq!(FlowId::from_token(last.token()), Some(last));
        assert_eq!(token(last), UDP_TOKEN_BASE + (FLOW_ID_LIMIT - 1));
        assert!(token(last) < u64::MAX);
        assert_eq!(FlowId::from_token(token(FlowId(7))), None);
        assert_eq!(from_token(crate::DNS_TOKEN), None);
    }

    /// What reached a socket between its bind and its connect is thrown
    /// away; what the destination sends after comes through.
    #[test]
    fn what_reached_a_socket_before_its_connect_is_thrown_away() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let at = socket.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger.send_to(b"forged", at).unwrap();
        stranger.send_to(b"forged too", at).unwrap();
        // Both are queued before the connect.
        let mut byte = [0; 1];
        let start = Instant::now();
        while socket.peek(&mut byte).is_err() {
            assert!(start.elapsed() < Duration::from_secs(5), "nothing queued");
        }
        let dst = UdpSocket::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(dst_at) = dst.local_addr().unwrap() else {
            panic!("not IPv4");
        };
        let socket = connect_only_to(socket, dst_at).unwrap();
        let mut buf = [0; 16];
        assert!(
            matches!(socket.recv(&mut buf), Err(e) if e.kind() == ErrorKind::WouldBlock),
            "the stranger's datagrams are gone"
        );
        dst.send_to(b"reply", at).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.set_nonblocking(false).unwrap();
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
    }

    #[test]
    fn a_refusal_is_remembered_for_a_minute_from_it() {
        let policy = Arc::new(Policy::default());
        let t0 = Instant::now();
        let mut refused = Refused::new(4);
        assert_eq!(refused.check(&policy, tuple(1), t0), None);
        refused.insert(tuple(1), DropReason::UdpDenied, t0);
        let at = |s| t0 + Duration::from_secs(s);
        assert_eq!(
            refused.check(&policy, tuple(1), at(59)),
            Some(DropReason::UdpDenied)
        );
        // Hits do not lengthen it.
        assert_eq!(refused.check(&policy, tuple(1), at(60)), None);
        assert_eq!(refused.entries.len(), 0, "forgotten");
        assert_eq!(refused.check(&policy, tuple(1), at(61)), None);
    }

    #[test]
    fn at_the_cap_the_least_recently_used_refusal_goes() {
        let policy = Arc::new(Policy::default());
        let t0 = Instant::now();
        let mut refused = Refused::new(3);
        assert_eq!(refused.check(&policy, tuple(1), t0), None);
        for port in 1..=3 {
            refused.insert(tuple(port), DropReason::UdpDenied, t0);
        }
        // Tuple 1 is used again, so tuple 2 is the least recently used.
        assert!(refused.check(&policy, tuple(1), t0).is_some());
        refused.insert(tuple(4), DropReason::UdpSend, t0);
        assert_eq!(refused.entries.len(), 3);
        assert_eq!(refused.check(&policy, tuple(2), t0), None, "forgotten");
        for (port, reason) in [
            (1, DropReason::UdpDenied),
            (3, DropReason::UdpDenied),
            (4, DropReason::UdpSend),
        ] {
            assert_eq!(refused.check(&policy, tuple(port), t0), Some(reason));
        }
        // Refused again, a tuple is remembered once.
        refused.insert(tuple(4), DropReason::UdpDenied, t0);
        assert_eq!(refused.entries.len(), 3);
        assert_eq!(refused.order.len(), 3);
    }

    #[test]
    fn another_policy_forgets_every_refusal() {
        let first = Arc::new(Policy::default());
        let t0 = Instant::now();
        let mut refused = Refused::new(4);
        assert_eq!(refused.check(&first, tuple(1), t0), None);
        refused.insert(tuple(1), DropReason::UdpDenied, t0);
        assert!(refused.check(&Arc::clone(&first), tuple(1), t0).is_some());
        // An equal policy, but another one: swapped in.
        let second = Arc::new(Policy::default());
        assert_eq!(refused.check(&second, tuple(1), t0), None);
        assert_eq!(refused.entries.len(), 0);
    }
}
