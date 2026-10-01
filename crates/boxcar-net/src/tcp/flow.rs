// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The relay's tables: the flows it carries and the host connects under
//! way, by id and by the guest's (source, destination) pair, each bounded.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smoltcp::iface::SocketHandle;

use super::TCP_TOKEN_BASE;
use crate::stack::Interest;

/// Flow ids stay below this (2^62), which keeps the TCP and UDP token
/// spaces apart.
pub const FLOW_ID_LIMIT: u64 = 1 << 62;

/// A flow's id: unique within a stack, counted from 1 in the order flows
/// are decided. TCP connections and UDP mappings share the count (each
/// decided SYN and each first datagram of a UDP 5-tuple takes the next
/// id), so a protocol's ids have gaps. A flow's records carry it, and its
/// host socket's [`FdChange`](crate::FdChange) token is derived from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowId(pub u64);

impl FlowId {
    /// The token of this TCP flow's host socket.
    pub fn token(self) -> u64 {
        TCP_TOKEN_BASE.saturating_add(self.0)
    }

    /// The TCP flow a host socket's token is for, if it is a TCP flow's.
    pub fn from_token(token: u64) -> Option<FlowId> {
        token
            .checked_sub(TCP_TOKEN_BASE)
            .filter(|id| *id < FLOW_ID_LIMIT)
            .map(FlowId)
    }
}

/// The flow ids a stack gives out, counted from 1. TCP connections and
/// UDP flows (each decided SYN and each first datagram of a 5-tuple) share
/// the count, so within a session an id names one flow of either kind.
///
/// Clones share one count. The virtio-net device keeps one for its whole
/// life and hands it to every stack it builds, so the ids go on rising
/// across a guest's driver reset (each activation builds a new stack), and
/// even past a net thread the device had to leave behind.
#[derive(Clone, Debug, Default)]
pub(crate) struct FlowIds {
    last: Arc<AtomicU64>,
}

impl FlowIds {
    /// The next id.
    pub(crate) fn next(&self) -> FlowId {
        // 2^62 ids are never given out, so the count cannot wrap.
        let id = self.last.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        debug_assert!(id < FLOW_ID_LIMIT, "flow ids stay below 2^62");
        FlowId(id)
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Where a flow is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowState {
    /// Holding the guest's first bytes, unforwarded, until the gate
    /// decides on the name they show.
    Gating,
    /// Moving bytes both ways.
    Relaying,
    /// Over, for this `net.close` reason (already recorded): its smoltcp
    /// socket is sending the guest a reset, and then the flow goes. A flow
    /// that ended because the guest sent data after its FIN keeps its host
    /// socket until the host has the bytes from before the FIN, then ends
    /// it with a FIN.
    Ending(&'static str),
}

/// A gated flow's first bytes, and by when they must show a name.
#[derive(Debug)]
pub struct GateBuf {
    /// When a flow that has shown no name is denied.
    pub deadline: Instant,
    /// The guest's first bytes, taken out of the smoltcp socket as they
    /// come (up to the gate's limit), and not forwarded: a pass moves them
    /// to the flow's [`tail`](Flow::tail), ahead of what follows.
    pub seen: Vec<u8>,
    /// How many of them have been read for a name: they are read again
    /// only when more have come.
    pub parsed: usize,
    /// What they were last read as: `tls` or `http`.
    pub kind: &'static str,
}

impl GateBuf {
    pub(crate) fn new(deadline: Instant) -> GateBuf {
        GateBuf {
            deadline,
            seen: Vec::new(),
            parsed: 0,
            kind: "tls",
        }
    }
}

/// A connection the guest made, carried by a host socket.
pub struct Flow {
    pub id: FlowId,
    /// The guest's address and port.
    pub guest: SocketAddrV4,
    /// Where the guest connected to.
    pub dst: SocketAddrV4,
    /// The names the DNS cache gave `dst` when the SYN came.
    pub names: Vec<String>,
    /// The host socket; `None` once the flow is ending.
    pub host: Option<TcpStream>,
    pub state: FlowState,
    /// Bytes the guest sent that went to the host.
    pub tx: u64,
    /// Bytes the host sent that went to the guest.
    pub rx: u64,
    /// When the guest's SYN was decided.
    pub opened: Instant,
    /// What the gate holds, while the flow is [`FlowState::Gating`].
    pub gate: Option<GateBuf>,
    /// Guest bytes taken out of the smoltcp socket and not yet written to
    /// the host, written ahead of what the socket still holds: the gated
    /// bytes after a pass, and what the guest sent before its FIN (taken
    /// out at once, so that the end of smoltcp's TIME-WAIT, which empties
    /// its buffer, cannot lose them).
    pub tail: Vec<u8>,
    /// The smoltcp socket that is the guest's far end.
    pub(crate) socket: SocketHandle,
    /// When the last byte moved, either way.
    pub(crate) last_active: Instant,
    /// What the net thread watches the host socket for.
    pub(crate) watched: Interest,
    /// The host socket may have bytes to read: it was reported readable
    /// and has not refused a read since.
    pub(crate) host_readable: bool,
    /// The host socket may take bytes: it has not refused a write since
    /// it was last reported writable.
    pub(crate) host_writable: bool,
    /// The host sent its FIN (a read gave 0), which went on to the guest.
    pub(crate) host_eof: bool,
    /// The guest's FIN went on to the host (`shutdown(Write)`).
    pub(crate) host_shut: bool,
    /// The guest sent its FIN.
    pub(crate) guest_fin: bool,
    /// The guest sent a reset for this connection: a socket that closes
    /// without both FINs was reset, not timed out.
    pub(crate) guest_rst: bool,
    /// The sequence number of the guest's first data byte (its initial
    /// sequence number, from the parked SYN, plus one).
    pub(crate) first_seq: u32,
    /// Bytes taken out of the smoltcp socket so far, modulo 2^32: with
    /// `first_seq`, the sequence number of the next byte it holds.
    pub(crate) taken: u32,
    /// Where the guest's FIN sits in the sequence space, from the first
    /// FIN segment the dispatcher saw for this connection.
    pub(crate) fin_at: Option<u32>,
    /// The bytes before the guest's FIN have been taken out of the socket:
    /// anything it receives from now on came after the FIN.
    pub(crate) fin_taken: bool,
}

impl Flow {
    /// A flow for the connect `pending` made, carried by `socket`.
    pub(crate) fn new(
        pending: Pending,
        socket: SocketHandle,
        now: Instant,
        gate_timeout: Duration,
    ) -> Flow {
        // `TcpLimits::check` keeps the timeout to a day.
        let deadline = now.checked_add(gate_timeout).unwrap_or(now);
        let gate = pending.gated.then(|| GateBuf::new(deadline));
        // The parked frame was classified as a TCP SYN, so it reads.
        let isn = crate::frame::tcp_seq(&pending.syn).unwrap_or(0);
        Flow {
            id: pending.id,
            guest: pending.guest,
            dst: pending.dst,
            names: pending.names,
            host: Some(pending.host),
            state: if gate.is_some() {
                FlowState::Gating
            } else {
                FlowState::Relaying
            },
            tx: 0,
            rx: 0,
            opened: pending.opened,
            gate,
            tail: Vec::new(),
            socket,
            last_active: now,
            watched: pending.watched,
            host_readable: true,
            host_writable: true,
            host_eof: false,
            host_shut: false,
            guest_fin: false,
            guest_rst: false,
            first_seq: isn.wrapping_add(1),
            taken: 0,
            fin_at: None,
            fin_taken: false,
        }
    }

    pub(crate) fn ending(&self) -> bool {
        matches!(self.state, FlowState::Ending(_))
    }
}

impl fmt::Debug for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flow")
            .field("id", &self.id)
            .field("guest", &self.guest)
            .field("dst", &self.dst)
            .field("state", &self.state)
            .field("tx", &self.tx)
            .field("rx", &self.rx)
            .finish_non_exhaustive()
    }
}

/// A guest SYN waiting on its host connect.
pub struct Pending {
    pub id: FlowId,
    pub guest: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub names: Vec<String>,
    /// The host socket, connecting.
    pub host: TcpStream,
    /// The guest's SYN frame, fed to smoltcp when the connect succeeds and
    /// answered with a reset when it fails.
    pub syn: Vec<u8>,
    /// When the SYN was decided.
    pub opened: Instant,
    /// Whether a domain rule allowed it: the flow will be gated.
    pub gated: bool,
    /// What the net thread watches the host socket for.
    pub(crate) watched: Interest,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("id", &self.id)
            .field("guest", &self.guest)
            .field("dst", &self.dst)
            .finish_non_exhaustive()
    }
}

/// The flows and the connects under way, each table bounded, with the
/// guest's (source, destination) pairs they hold.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowId, Flow>,
    pending: BTreeMap<FlowId, Pending>,
    by_pair: HashMap<(SocketAddrV4, SocketAddrV4), FlowId>,
    flow_cap: usize,
    pending_cap: usize,
}

impl FlowTable {
    /// Tables of at most `flow_cap` flows and `pending_cap` connects.
    pub fn new(flow_cap: usize, pending_cap: usize) -> FlowTable {
        FlowTable {
            flows: HashMap::new(),
            pending: BTreeMap::new(),
            by_pair: HashMap::new(),
            flow_cap,
            pending_cap,
        }
    }

    /// Flows held, ending ones included.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Connects under way.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether a flow or a connect holds the guest's `guest` → `dst`.
    pub fn knows(&self, guest: SocketAddrV4, dst: SocketAddrV4) -> bool {
        self.by_pair.contains_key(&(guest, dst))
    }

    /// The flow or connect that holds the guest's `guest` → `dst`.
    pub fn id_of(&self, guest: SocketAddrV4, dst: SocketAddrV4) -> Option<FlowId> {
        self.by_pair.get(&(guest, dst)).copied()
    }

    /// Whether a new flow needs another evicted first.
    pub fn is_full(&self) -> bool {
        self.flows.len() >= self.flow_cap
    }

    /// Whether a new connect must wait.
    pub fn pending_full(&self) -> bool {
        self.pending.len() >= self.pending_cap
    }

    /// Holds a connect, or gives it back if the table is full.
    pub fn add_pending(&mut self, pending: Pending) -> Result<(), Pending> {
        if self.pending_full() {
            return Err(pending);
        }
        self.by_pair
            .insert((pending.guest, pending.dst), pending.id);
        self.pending.insert(pending.id, pending);
        Ok(())
    }

    pub fn pending(&self, id: FlowId) -> Option<&Pending> {
        self.pending.get(&id)
    }

    /// Takes a connect out, forgetting its pair.
    pub fn take_pending(&mut self, id: FlowId) -> Option<Pending> {
        let pending = self.pending.remove(&id)?;
        self.by_pair.remove(&(pending.guest, pending.dst));
        Some(pending)
    }

    /// The connects started `timeout` or longer before `now`, oldest first.
    pub fn timed_out(&self, now: Instant, timeout: Duration) -> Vec<FlowId> {
        self.pending
            .values()
            .filter(|p| now.saturating_duration_since(p.opened) >= timeout)
            .map(|p| p.id)
            .collect()
    }

    /// When the next connect times out, if one is under way.
    pub fn next_timeout(&self, timeout: Duration) -> Option<Instant> {
        self.pending
            .values()
            .filter_map(|p| p.opened.checked_add(timeout))
            .min()
    }

    /// Holds a flow, or gives it back if the table is full: evict one
    /// first.
    pub fn insert(&mut self, flow: Flow) -> Result<(), Box<Flow>> {
        if self.is_full() {
            return Err(Box::new(flow));
        }
        self.by_pair.insert((flow.guest, flow.dst), flow.id);
        self.flows.insert(flow.id, flow);
        Ok(())
    }

    pub fn get(&self, id: FlowId) -> Option<&Flow> {
        self.flows.get(&id)
    }

    pub fn get_mut(&mut self, id: FlowId) -> Option<&mut Flow> {
        self.flows.get_mut(&id)
    }

    /// Takes a flow out, forgetting its pair.
    pub fn remove(&mut self, id: FlowId) -> Option<Flow> {
        let flow = self.flows.remove(&id)?;
        self.by_pair.remove(&(flow.guest, flow.dst));
        Some(flow)
    }

    /// Every flow.
    pub fn flows_mut(&mut self) -> impl Iterator<Item = &mut Flow> {
        self.flows.values_mut()
    }

    /// The flow to evict for a new one: one already ending if there is
    /// one, else the one whose last byte moved longest ago (the oldest of
    /// those that tie).
    pub fn victim(&self) -> Option<FlowId> {
        self.flows
            .values()
            .min_by_key(|flow| (!flow.ending(), flow.last_active, flow.id))
            .map(|flow| flow.id)
    }

    /// Takes everything out, in id order: the connects, then the flows.
    pub fn drain(&mut self) -> (Vec<Pending>, Vec<Flow>) {
        self.by_pair.clear();
        let pending = std::mem::take(&mut self.pending).into_values().collect();
        let mut flows: Vec<Flow> = self.flows.drain().map(|(_, flow)| flow).collect();
        flows.sort_by_key(|flow| flow.id);
        (pending, flows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_of_the_ids_share_one_count() {
        let ids = FlowIds::default();
        let other = ids.clone();
        assert_eq!(ids.next(), FlowId(1));
        assert_eq!(other.next(), FlowId(2));
        assert_eq!(ids.next(), FlowId(3));
        assert_eq!(
            FlowIds::default().next(),
            FlowId(1),
            "a new count starts at 1"
        );
    }
    use std::net::{Ipv4Addr, TcpListener};

    fn addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), port)
    }

    fn far() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443)
    }

    /// A connected loopback stream, to stand for a host socket.
    fn stream() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        TcpStream::connect(listener.local_addr().unwrap()).unwrap()
    }

    fn pending(id: u64, port: u16, opened: Instant) -> Pending {
        Pending {
            id: FlowId(id),
            guest: addr(port),
            dst: far(),
            names: Vec::new(),
            host: stream(),
            syn: Vec::new(),
            opened,
            gated: false,
            watched: Interest::default(),
        }
    }

    fn flow(id: u64, port: u16, last_active: Instant) -> Flow {
        let mut flow = Flow::new(
            pending(id, port, last_active),
            SocketHandle::default(),
            last_active,
            Duration::from_secs(5),
        );
        flow.host = None;
        flow
    }

    #[test]
    fn tokens_map_to_flows() {
        assert_eq!(FlowId(1).token(), (1 << 62) + 1);
        assert_eq!(FlowId::from_token((1 << 62) + 7), Some(FlowId(7)));
        assert_eq!(FlowId::from_token(1), None, "the DNS socket's");
        assert_eq!(
            FlowId::from_token(crate::UDP_TOKEN_BASE + 7),
            None,
            "a UDP mapping's"
        );
        assert_eq!(FlowId(u64::MAX).token(), u64::MAX);
    }

    #[test]
    fn both_tables_are_bounded_and_know_their_pairs() {
        let now = Instant::now();
        let mut table = FlowTable::new(2, 2);
        table.add_pending(pending(1, 1, now)).unwrap();
        table.add_pending(pending(2, 2, now)).unwrap();
        assert!(table.pending_full());
        let refused = table.add_pending(pending(3, 3, now)).unwrap_err();
        assert_eq!(refused.id, FlowId(3));
        assert!(table.knows(addr(1), far()) && table.knows(addr(2), far()));
        assert!(!table.knows(addr(3), far()));
        assert!(!table.knows(addr(1), SocketAddrV4::new(*far().ip(), 80)));

        let first = table.take_pending(FlowId(1)).unwrap();
        assert!(!table.knows(addr(1), far()), "forgotten while it moves");
        table
            .insert(Flow::new(
                first,
                SocketHandle::default(),
                now,
                Duration::ZERO,
            ))
            .unwrap();
        assert!(table.knows(addr(1), far()));
        table.insert(flow(4, 4, now)).unwrap();
        assert!(table.is_full());
        assert!(table.insert(flow(5, 5, now)).is_err());
        assert_eq!(table.len(), 2);
        assert_eq!(table.pending_len(), 1);

        table.remove(FlowId(4)).unwrap();
        assert!(!table.knows(addr(4), far()));
        let (pending, flows) = table.drain();
        assert_eq!(pending.len(), 1);
        assert_eq!(flows.len(), 1);
        assert!(!table.knows(addr(1), far()) && !table.knows(addr(2), far()));
    }

    #[test]
    fn the_victim_is_an_ending_flow_or_the_idlest() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut table = FlowTable::new(8, 8);
        assert_eq!(table.victim(), None);
        table.insert(flow(1, 1, at(30))).unwrap();
        table.insert(flow(2, 2, at(10))).unwrap();
        table.insert(flow(3, 3, at(10))).unwrap();
        table.insert(flow(4, 4, at(20))).unwrap();
        assert_eq!(table.victim(), Some(FlowId(2)), "idlest, then oldest");
        table.get_mut(FlowId(1)).unwrap().state = FlowState::Ending("gate");
        assert_eq!(table.victim(), Some(FlowId(1)), "an ending flow first");
    }

    #[test]
    fn connects_time_out_in_order() {
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let mut table = FlowTable::new(8, 8);
        let timeout = Duration::from_secs(10);
        assert_eq!(table.next_timeout(timeout), None);
        table.add_pending(pending(1, 1, at(0))).unwrap();
        table.add_pending(pending(2, 2, at(3))).unwrap();
        assert_eq!(table.next_timeout(timeout), Some(at(10)));
        assert!(table.timed_out(at(9), timeout).is_empty());
        assert_eq!(table.timed_out(at(10), timeout), [FlowId(1)]);
        assert_eq!(table.timed_out(at(13), timeout), [FlowId(1), FlowId(2)]);
    }
}
