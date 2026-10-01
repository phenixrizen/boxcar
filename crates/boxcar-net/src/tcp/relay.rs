// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The relay's work: deciding a guest's SYN, connecting for it, handing
//! the parked SYN to a smoltcp socket once the host connect is made,
//! gating, moving bytes, and ending flows.
//!
//! # Accepting a parked SYN
//!
//! smoltcp 0.14 has no call that takes a SYN for a socket; a listening
//! socket takes it from the interface's ingress. When a host connect
//! succeeds, the relay makes a socket listen on the destination's address
//! and port (the interface's any-IP answers for every address), puts it in
//! a socket set of its own, has the device (`Pipe::inject`) hand the
//! parked SYN to `Interface::poll_ingress_single` ahead of every queued
//! frame, and checks that the socket went to SYN-RECEIVED. Only then does
//! the socket join the stack's set; its SYN-ACK goes with the next egress.
//! With a set of one socket, no other listening socket can take the SYN,
//! and no socket in the stack's set ever listens: guest SYNs never reach
//! smoltcp otherwise (those for a pair a flow holds are dropped), and one
//! that a reset in SYN-RECEIVED sent back to listening is ended as reset.
//!
//! # Moving bytes
//!
//! Guest to host: what the smoltcp socket received is written to the host
//! socket straight from its buffer, and dequeued only as far as the write
//! took it; when the host refuses (`WouldBlock`) the rest waits there, the
//! guest's window closes as the buffer fills, and the host socket is
//! watched for writability. Host to guest: the host socket is read
//! straight into the smoltcp socket's send buffer, as far as it has room;
//! while it has none the host socket is not watched for readability (so a
//! level-triggered poller does not spin), and it is read again when the
//! guest's acknowledgements free room. A host socket is watched only for
//! what the relay waits on, and not at all while a flow is gated.
//!
//! The guest's FIN, once the bytes before it have been written, is a
//! `shutdown(Write)` on the host socket; the host's EOF closes the smoltcp
//! socket, which sends its FIN after the bytes before it. A flow ends
//! (`fin`) when both have gone and smoltcp is done. A reset from the guest
//! resets the host socket (`reset`); a reset or error from the host aborts
//! the smoltcp socket, which resets the guest (`reset`, `error`).
//!
//! # Closing host sockets
//!
//! A host socket the relay is done with is asked to be unwatched (an
//! [`FdChange`] with no interest) and moved to a graveyard. The graveyard
//! is closed at the start of the poll after the one whose outcome carried
//! the unwatching, so the net thread has stopped watching an fd before it
//! closes (and before its number can be used again).

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddrV4, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Instant;

use boxcar_audit::AuditSink;
use boxcar_proto::{NetClose, NetConnect, NetTls, Payload};
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::socket::{tcp, Socket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::EthernetAddress;

use super::flow::{Flow, FlowId, FlowState, FlowTable, GateBuf, Pending};
use super::{TcpLimits, SOCKET_BUFFER};
use crate::audit::{self, DropReason, Drops};
use crate::config::NetConfig;
use crate::frame;
use crate::http_host::{self, Request};
use crate::policy::{self, Policy, Rule, Target, Verdict};
use crate::sni::{self, Hello};
use crate::stack::{FdChange, Interest, Pipe};
use crate::upstream::{self, ConnectTarget, HostAddrs, Progress, BUILTIN_HOST_LOCAL};

/// What the relay borrows from the stack for one call.
pub(crate) struct Ctx<'a> {
    pub(crate) cfg: &'a NetConfig,
    pub(crate) sink: &'a AuditSink,
    pub(crate) iface: &'a mut Interface,
    pub(crate) pipe: &'a mut Pipe,
    pub(crate) sockets: &'a mut SocketSet<'static>,
    pub(crate) drops: &'a mut Drops,
    /// Now, on the stack's clock and on smoltcp's.
    pub(crate) now: Instant,
    pub(crate) stamp: SmolInstant,
}

impl Ctx<'_> {
    fn record(&self, payload: Payload) {
        audit::record(self.sink, payload);
    }

    fn drop_frame(&mut self, reason: DropReason) {
        if let Some(counted) = self.drops.count(reason, self.now) {
            audit::try_emit(self.sink, Payload::NetDrop(counted));
        }
    }

    /// Refuses the guest's `syn` with an RST+ACK from where it was sent.
    fn reset_guest(&mut self, syn: &[u8]) {
        let reset = frame::tcp_reset(
            syn,
            EthernetAddress(self.cfg.gateway_mac),
            EthernetAddress(self.cfg.guest_mac),
        );
        if let Some(reset) = reset {
            if !self.pipe.queue_for_guest(reset) {
                boxcar_virtio::limited!(warn, "net: the guest is not taking frames; dropping");
                self.drop_frame(DropReason::QueueFull);
            }
        }
    }

    /// Sends everything smoltcp has to send, as far as the guest's queue
    /// takes it.
    fn flush(&mut self) {
        while self.iface.poll_egress(self.stamp, self.pipe, self.sockets)
            != smoltcp::iface::PollResult::None
        {}
    }

    fn socket(&mut self, flow: &Flow) -> &mut tcp::Socket<'static> {
        // A flow's handle is in the set from its accept until the flow is
        // taken out of the table.
        self.sockets.get_mut::<tcp::Socket>(flow.socket)
    }
}

/// The TCP relay's state: its flows and connects, and the host fds it is
/// done with.
#[derive(Debug)]
pub(crate) struct Relay {
    limits: TcpLimits,
    table: FlowTable,
    /// The last flow id given.
    last_id: u64,
    host_addrs: HostAddrs,
    /// Ending flows: their reset is on its way to the guest.
    ending: Vec<FlowId>,
    /// Watch changes for the next outcome.
    fd_changes: Vec<FdChange>,
    /// Host sockets whose unwatching the next outcome carries.
    graveyard: Vec<TcpStream>,
    /// Host sockets whose unwatching the last outcome carried: closed at
    /// the start of the next poll.
    buried: Vec<TcpStream>,
    /// When the next gated flow runs out of time.
    gate_due: Option<Instant>,
}

/// What one look at a flow came to.
enum Step {
    /// Still open.
    Open,
    /// Over for this reason, with nothing left to send the guest: the
    /// flow can go at once.
    Done(&'static str),
    /// To be aborted for this reason: both sides reset.
    Abort(&'static str),
}

/// What the gate made of a flow's first bytes.
enum GateStep {
    Wait,
    Pass(Payload),
    Deny(Payload),
}

impl Relay {
    pub(crate) fn new(limits: TcpLimits, host_addrs: HostAddrs) -> Relay {
        Relay {
            table: FlowTable::new(limits.flow_cap, limits.pending_cap),
            limits,
            last_id: 0,
            host_addrs,
            ending: Vec::new(),
            fd_changes: Vec::new(),
            graveyard: Vec::new(),
            buried: Vec::new(),
            gate_due: None,
        }
    }

    pub(crate) fn set_host_addrs(&mut self, addrs: HostAddrs) {
        self.host_addrs = addrs;
    }

    /// Flows and connects held.
    pub(crate) fn open_flows(&self) -> usize {
        self.table.len() + self.table.pending_len()
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
    /// to be closed (their unwatching has gone out, and they close at the
    /// start of the next poll), else when a connect or a gate next runs
    /// out of time.
    pub(crate) fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.buried.is_empty() {
            return Some(now);
        }
        [
            self.table.next_timeout(self.limits.connect_timeout),
            self.gate_due,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Decides the guest's SYN `frame`, from `guest` to `dst`, which the
    /// guest knows by `names`: a retransmit of one being handled is
    /// dropped; a denied one is reset at once; an allowed one waits on a
    /// host connect.
    pub(crate) fn syn(
        &mut self,
        cx: &mut Ctx,
        frame: &[u8],
        guest: SocketAddrV4,
        dst: SocketAddrV4,
        policy: &Policy,
        names: Vec<String>,
    ) {
        // A retransmit: the first is waiting on its connect or answered.
        if self.table.knows(guest, dst) {
            return;
        }
        let (verdict, rule, gate) =
            if upstream::host_local(&mut self.host_addrs, policy, dst, cx.now) {
                (Verdict::Deny, Some(BUILTIN_HOST_LOCAL.to_owned()), None)
            } else {
                let (verdict, rule) = policy.egress(dst, &names);
                (verdict, rule, gate_pattern(policy.egress_rule(dst, &names)))
            };
        if verdict == Verdict::Allow && self.table.pending_full() {
            // Not decided as far as the log goes: the guest sends it again.
            return cx.drop_frame(DropReason::TcpPendingFull);
        }
        self.last_id = self.last_id.saturating_add(1);
        let id = FlowId(self.last_id);
        cx.record(Payload::NetConnect(NetConnect {
            flow: id.0,
            proto: "tcp".to_owned(),
            src: guest,
            dst,
            names: names.clone(),
            verdict,
            rule,
        }));
        if verdict == Verdict::Deny {
            return cx.reset_guest(frame);
        }
        let host = match upstream::connect(ConnectTarget::Host(dst)) {
            Ok(host) => host,
            Err(error) => {
                cx.reset_guest(frame);
                let reason = upstream::close_reason(&error);
                return cx.record(close_record(id, 0, 0, cx.now, cx.now, reason));
            }
        };
        let watched = Interest {
            readable: false,
            writable: true,
        };
        self.fd_changes.push(FdChange {
            token: id.token(),
            fd: host.as_raw_fd(),
            interest: watched,
        });
        let pending = Pending {
            id,
            guest,
            dst,
            names,
            host,
            syn: frame.to_vec(),
            opened: cx.now,
            gate,
            watched,
        };
        if let Err(mut pending) = self.table.add_pending(pending) {
            // Not reached: the table had room above.
            cx.reset_guest(&pending.syn);
            cx.record(close_record(id, 0, 0, pending.opened, cx.now, "error"));
            self.discard(id, pending.host, &mut pending.watched, false);
        }
    }

    /// A host socket the net thread watches is ready.
    pub(crate) fn host_event(&mut self, cx: &mut Ctx, token: u64, readable: bool, writable: bool) {
        let Some(id) = FlowId::from_token(token) else {
            return;
        };
        if self.table.pending(id).is_some() {
            return self.connecting(cx, id);
        }
        // An event for a flow that has gone is stale.
        let Some(flow) = self.table.get_mut(id) else {
            return;
        };
        flow.host_readable |= readable;
        flow.host_writable |= writable;
        self.pump_one(cx, id);
    }

    /// Resets the guest for every connect that has taken too long.
    pub(crate) fn expire(&mut self, cx: &mut Ctx) {
        for id in self.table.timed_out(cx.now, self.limits.connect_timeout) {
            if let Some(mut pending) = self.table.take_pending(id) {
                cx.reset_guest(&pending.syn);
                cx.record(close_record(id, 0, 0, pending.opened, cx.now, "timeout"));
                self.discard(id, pending.host, &mut pending.watched, false);
            }
        }
    }

    /// Moves what can move on every flow, gates, sends what that queued,
    /// and lets go of the flows that are over. Runs after smoltcp has
    /// taken the guest's frames.
    pub(crate) fn relay(&mut self, cx: &mut Ctx) {
        let mut records = Vec::new();
        let mut over = Vec::new();
        let mut gate_due: Option<Instant> = None;
        for flow in self.table.flows_mut() {
            let socket = cx.sockets.get_mut::<tcp::Socket>(flow.socket);
            match pump(flow, socket, self.limits.gate_limit, cx.now, &mut records) {
                Step::Open => {
                    watch(&mut self.fd_changes, flow, socket);
                    if let Some(gate) = &flow.gate {
                        gate_due = Some(gate_due.map_or(gate.deadline, |d| d.min(gate.deadline)));
                    }
                }
                step => over.push((flow.id, step)),
            }
        }
        self.gate_due = gate_due;
        for record in records {
            cx.record(record);
        }
        for (id, step) in over {
            self.end(cx, id, step);
        }
        // The data, FINs and resets the relay queued go now.
        cx.iface.poll(cx.stamp, cx.pipe, cx.sockets);
        self.reap(cx);
    }

    /// Ends every flow and connect, recording each as `shutdown`, for the
    /// stack stopping. The host sockets close when the stack is dropped.
    pub(crate) fn shutdown(&mut self, cx: &mut Ctx) {
        let (pending, flows) = self.table.drain();
        for mut pending in pending {
            cx.record(close_record(
                pending.id,
                0,
                0,
                pending.opened,
                cx.now,
                "shutdown",
            ));
            self.discard(pending.id, pending.host, &mut pending.watched, false);
        }
        let mut handles = Vec::with_capacity(flows.len());
        for mut flow in flows {
            if !flow.ending() {
                cx.record(close_record(
                    flow.id,
                    flow.tx,
                    flow.rx,
                    flow.opened,
                    cx.now,
                    "shutdown",
                ));
                cx.socket(&flow).abort();
            }
            if let Some(host) = flow.host.take() {
                self.discard(flow.id, host, &mut flow.watched, true);
            }
            handles.push(flow.socket);
        }
        // The guest's resets, as far as its queue takes them.
        cx.flush();
        for handle in handles {
            cx.sockets.remove(handle);
        }
        self.ending.clear();
    }

    /// A connect's fd is ready: it succeeded, failed, or neither yet.
    fn connecting(&mut self, cx: &mut Ctx, id: FlowId) {
        let Some(pending) = self.table.pending(id) else {
            return;
        };
        match upstream::progress(&pending.host) {
            Progress::Waiting => {}
            Progress::Done => self.accept(cx, id),
            Progress::Failed(error) => {
                if let Some(mut pending) = self.table.take_pending(id) {
                    cx.reset_guest(&pending.syn);
                    let reason = upstream::close_reason(&error);
                    cx.record(close_record(id, 0, 0, pending.opened, cx.now, reason));
                    self.discard(id, pending.host, &mut pending.watched, false);
                }
            }
        }
    }

    /// The host connect for `id` is made: gives the guest its SYN-ACK
    /// through a smoltcp socket that takes the parked SYN.
    fn accept(&mut self, cx: &mut Ctx, id: FlowId) {
        let Some(mut pending) = self.table.take_pending(id) else {
            return;
        };
        let Some(socket) = take_syn(cx, &pending) else {
            // smoltcp would not take the SYN (a destination port of 0).
            cx.reset_guest(&pending.syn);
            cx.record(close_record(id, 0, 0, pending.opened, cx.now, "error"));
            return self.discard(id, pending.host, &mut pending.watched, true);
        };
        if self.table.is_full() {
            self.evict(cx);
        }
        let handle = cx.sockets.add(socket);
        let flow = Flow::new(pending, handle, cx.now, self.limits.gate_timeout);
        if let Err(mut flow) = self.table.insert(flow) {
            // Not reached: eviction made room.
            cx.sockets.remove(handle);
            if let Some(host) = flow.host.take() {
                self.discard(id, host, &mut flow.watched, true);
            }
            return cx.record(close_record(id, 0, 0, flow.opened, cx.now, "error"));
        }
        self.pump_one(cx, id);
    }

    /// Makes room for a new flow: takes out an ending flow, or aborts the
    /// one idle longest (`evicted`), sending its reset if the guest has
    /// room for it.
    fn evict(&mut self, cx: &mut Ctx) {
        let Some(id) = self.table.victim() else {
            return;
        };
        let Some(mut flow) = self.table.remove(id) else {
            return;
        };
        if !flow.ending() {
            cx.record(close_record(
                id,
                flow.tx,
                flow.rx,
                flow.opened,
                cx.now,
                "evicted",
            ));
            cx.socket(&flow).abort();
            if let Some(host) = flow.host.take() {
                self.discard(id, host, &mut flow.watched, true);
            }
        }
        cx.flush();
        cx.sockets.remove(flow.socket);
        self.ending.retain(|ending| *ending != id);
    }

    /// Moves what can move on one flow, and ends it if it is over.
    fn pump_one(&mut self, cx: &mut Ctx, id: FlowId) {
        let mut records = Vec::new();
        let Some(flow) = self.table.get_mut(id) else {
            return;
        };
        let socket = cx.sockets.get_mut::<tcp::Socket>(flow.socket);
        let step = pump(flow, socket, self.limits.gate_limit, cx.now, &mut records);
        if let Step::Open = step {
            watch(&mut self.fd_changes, flow, socket);
        }
        for record in records {
            cx.record(record);
        }
        self.end(cx, id, step);
    }

    /// Ends a flow a step says is over.
    fn end(&mut self, cx: &mut Ctx, id: FlowId, step: Step) {
        match step {
            Step::Open => {}
            // Nothing left for the guest: the flow goes now.
            Step::Done(reason) => {
                let Some(mut flow) = self.table.remove(id) else {
                    return;
                };
                cx.record(close_record(
                    id,
                    flow.tx,
                    flow.rx,
                    flow.opened,
                    cx.now,
                    reason,
                ));
                cx.sockets.remove(flow.socket);
                if let Some(host) = flow.host.take() {
                    self.discard(id, host, &mut flow.watched, reason != "fin");
                }
            }
            // Both sides reset; the flow goes once the guest's reset has.
            Step::Abort(reason) => {
                let Some(flow) = self.table.get_mut(id) else {
                    return;
                };
                cx.record(close_record(
                    id,
                    flow.tx,
                    flow.rx,
                    flow.opened,
                    cx.now,
                    reason,
                ));
                cx.sockets.get_mut::<tcp::Socket>(flow.socket).abort();
                flow.state = FlowState::Ending(reason);
                flow.gate = None;
                if let Some(host) = flow.host.take() {
                    discard(
                        &mut self.fd_changes,
                        &mut self.graveyard,
                        id,
                        host,
                        &mut flow.watched,
                        true,
                    );
                }
                self.ending.push(id);
            }
        }
    }

    /// Takes out the ending flows whose reset has gone to the guest.
    fn reap(&mut self, cx: &mut Ctx) {
        let table = &mut self.table;
        self.ending.retain(|id| {
            let Some(flow) = table.get(*id) else {
                return false;
            };
            // After an abort smoltcp forgets the connection once it has
            // sent the reset.
            let sent = cx
                .sockets
                .get::<tcp::Socket>(flow.socket)
                .remote_endpoint()
                .is_none();
            if sent {
                cx.sockets.remove(flow.socket);
                table.remove(*id);
            }
            !sent
        });
    }

    /// Unwatches and lets go of a host socket.
    fn discard(&mut self, id: FlowId, host: TcpStream, watched: &mut Interest, reset: bool) {
        discard(
            &mut self.fd_changes,
            &mut self.graveyard,
            id,
            host,
            watched,
            reset,
        );
    }
}

/// The pattern a flow allowed by `rule` is gated on: that of an allowing
/// domain rule.
fn gate_pattern(rule: Option<&Rule>) -> Option<String> {
    match rule {
        Some(Rule {
            verdict: Verdict::Allow,
            target: Target::Domain { pattern, .. },
            ..
        }) => Some(pattern.clone()),
        _ => None,
    }
}

/// A smoltcp socket that has taken `pending`'s SYN: listening on the
/// destination, alone in a set of its own, fed the SYN ahead of every
/// queued frame. `None` if it did not go to SYN-RECEIVED.
fn take_syn(cx: &mut Ctx, pending: &Pending) -> Option<tcp::Socket<'static>> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
    );
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    socket.listen(pending.dst).ok()?;
    let mut alone = SocketSet::new(Vec::with_capacity(1));
    let handle = alone.add(socket);
    cx.pipe.inject(pending.syn.clone());
    cx.iface.poll_ingress_single(cx.stamp, cx.pipe, &mut alone);
    cx.pipe.clear_injected();
    match alone.remove(handle) {
        Socket::Tcp(socket) if socket.state() == tcp::State::SynReceived => Some(socket),
        _ => None,
    }
}

/// Unwatches `host` if it is watched, and puts it in the graveyard,
/// set to reset its connection when it closes if `reset`.
fn discard(
    fd_changes: &mut Vec<FdChange>,
    graveyard: &mut Vec<TcpStream>,
    id: FlowId,
    host: TcpStream,
    watched: &mut Interest,
    reset: bool,
) {
    if *watched != Interest::default() {
        fd_changes.push(FdChange {
            token: id.token(),
            fd: host.as_raw_fd(),
            interest: Interest::default(),
        });
        *watched = Interest::default();
    }
    if reset {
        upstream::reset_on_close(&host);
    }
    graveyard.push(host);
}

/// Asks for `flow`'s host socket to be watched for what the relay waits
/// on, if that changed.
fn watch(fd_changes: &mut Vec<FdChange>, flow: &mut Flow, socket: &tcp::Socket) {
    let wanted = match (&flow.host, flow.state) {
        (Some(_), FlowState::Relaying) => Interest {
            // Data the guest's socket has room for.
            readable: !flow.host_eof && !flow.host_readable && socket.may_send(),
            // Room for the guest's data that waits.
            writable: !flow.host_writable && socket.can_recv(),
        },
        _ => Interest::default(),
    };
    if wanted != flow.watched {
        if let Some(host) = &flow.host {
            fd_changes.push(FdChange {
                token: flow.id.token(),
                fd: host.as_raw_fd(),
                interest: wanted,
            });
        }
        flow.watched = wanted;
    }
}

/// Looks at one flow: what smoltcp says of the guest's side, the gate,
/// and the bytes that can move each way. Records made go in `records`.
fn pump(
    flow: &mut Flow,
    socket: &mut tcp::Socket,
    gate_limit: usize,
    now: Instant,
    records: &mut Vec<Payload>,
) -> Step {
    use tcp::State;
    if flow.ending() {
        return Step::Open;
    }
    let state = socket.state();
    if matches!(
        state,
        State::CloseWait | State::LastAck | State::Closing | State::TimeWait
    ) {
        flow.guest_fin = true;
    }
    // A reset from the guest closes the socket, or in SYN-RECEIVED sends
    // it back to listening. (Closed after both FINs is the end of a
    // graceful close.)
    if state == State::Listen || (state == State::Closed && !(flow.guest_fin && flow.host_eof)) {
        return Step::Done("reset");
    }
    if flow.state == FlowState::Gating {
        let Some(held) = flow.gate.as_mut() else {
            // Not reached: a gated flow has its gate.
            return Step::Abort("error");
        };
        match gate(flow.id, held, flow.guest_fin, socket, gate_limit, now) {
            GateStep::Wait => return Step::Open,
            GateStep::Pass(record) => {
                records.push(record);
                flow.state = FlowState::Relaying;
                flow.gate = None;
            }
            GateStep::Deny(record) => {
                records.push(record);
                return Step::Abort("gate");
            }
        }
    }
    let Some(host) = flow.host.as_mut() else {
        return Step::Open;
    };
    // Guest to host, as far as the host takes it: what it refuses stays in
    // the socket, whose window closes as it fills.
    while flow.host_writable && socket.can_recv() {
        match socket.recv(|data| io_step(host.write(data))) {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                flow.tx = flow.tx.saturating_add(n as u64);
                flow.last_active = now;
            }
            Ok(Err(error)) if error.kind() == ErrorKind::WouldBlock => flow.host_writable = false,
            Ok(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
            Ok(Err(error)) => return Step::Abort(host_failure(&error)),
        }
    }
    // The guest's FIN, after what it sent before it.
    if flow.guest_fin && !flow.host_shut && socket.recv_queue() == 0 {
        flow.host_shut = true;
        // A host that has reset already says so on the next read.
        let _ = host.shutdown(Shutdown::Write);
    }
    // Host to guest, as far as the socket has room.
    while flow.host_readable && !flow.host_eof && socket.can_send() {
        match socket.send(|room| io_step(host.read(room))) {
            Ok(Ok(0)) => {
                flow.host_eof = true;
                // The FIN follows what is queued.
                socket.close();
            }
            Ok(Ok(n)) => {
                flow.rx = flow.rx.saturating_add(n as u64);
                flow.last_active = now;
            }
            Ok(Err(error)) if error.kind() == ErrorKind::WouldBlock => flow.host_readable = false,
            Ok(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
            Ok(Err(error)) => return Step::Abort(host_failure(&error)),
            Err(_) => break,
        }
    }
    let done = matches!(socket.state(), State::TimeWait | State::Closed);
    if flow.guest_fin && flow.host_eof && flow.host_shut && done {
        return Step::Done("fin");
    }
    Step::Open
}

/// An I/O result as smoltcp's buffer closures take it: how many bytes to
/// dequeue or enqueue, and the result.
fn io_step(result: io::Result<usize>) -> (usize, io::Result<usize>) {
    match result {
        Ok(n) => (n, Ok(n)),
        Err(error) => (0, Err(error)),
    }
}

/// The `net.close` reason for a host socket that failed with `error`.
fn host_failure(error: &io::Error) -> &'static str {
    match error.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            "reset"
        }
        _ => "error",
    }
}

/// Reads the name a gated flow's first bytes show and decides on it: a
/// name that matches the allowing rule's pattern passes; one that does
/// not, or none, is denied. Bytes that may yet show a name wait, until
/// they reach `limit`, the guest sends its FIN, or the gate's time is up.
fn gate(
    id: FlowId,
    gate: &mut GateBuf,
    guest_fin: bool,
    socket: &mut tcp::Socket,
    limit: usize,
    now: Instant,
) -> GateStep {
    let held = socket.recv_queue().min(limit);
    gate.seen.resize(held, 0);
    let read = socket.peek_slice(&mut gate.seen).unwrap_or(0);
    gate.seen.truncate(read);
    let (kind, shown) = read_name(&gate.seen);
    let Shown { name, alpn } = match shown {
        Some(shown) => shown,
        None => {
            let stuck = read >= limit || guest_fin || now >= gate.deadline;
            if !stuck {
                return GateStep::Wait;
            }
            Shown {
                name: None,
                alpn: Vec::new(),
            }
        }
    };
    let pass = name
        .as_deref()
        .is_some_and(|name| policy::name_matches(&gate.pattern, name));
    let verdict = if pass { Verdict::Allow } else { Verdict::Deny };
    let record = tls_record(id, kind, name, alpn, verdict);
    if pass {
        GateStep::Pass(record)
    } else {
        GateStep::Deny(record)
    }
}

/// What a gated flow's first bytes showed: the name they ask for, if any,
/// and the ALPN protocols a ClientHello offered.
#[derive(Debug, PartialEq, Eq)]
struct Shown {
    name: Option<String>,
    alpn: Vec<String>,
}

impl Shown {
    fn name(name: Option<String>) -> Option<Shown> {
        Some(Shown {
            name,
            alpn: Vec::new(),
        })
    }
}

/// The kind of a flow's first bytes (`tls` or `http`), and what they show,
/// or `None` while more may show it. Bytes that are not a ClientHello are
/// read as a plain HTTP request, unless they begin like a TLS handshake
/// record, which makes them a malformed hello. A flow that has sent
/// nothing counts as `tls`.
fn read_name(seen: &[u8]) -> (&'static str, Option<Shown>) {
    match sni::parse_client_hello(seen) {
        Hello::Tls { sni, alpn } => ("tls", Some(Shown { name: sni, alpn })),
        Hello::NeedMore => ("tls", None),
        Hello::NotTls if seen.first() == Some(&sni::CONTENT_HANDSHAKE) => {
            ("tls", Shown::name(None))
        }
        Hello::NotTls => match http_host::parse_request(seen) {
            Request::Host(host) => ("http", Shown::name(Some(host))),
            Request::NeedMore => ("http", None),
            Request::Invalid => ("http", Shown::name(None)),
        },
    }
}

fn tls_record(
    id: FlowId,
    kind: &str,
    sni: Option<String>,
    alpn: Vec<String>,
    verdict: Verdict,
) -> Payload {
    Payload::NetTls(NetTls {
        flow: id.0,
        kind: kind.to_owned(),
        sni,
        alpn,
        verdict,
    })
}

fn close_record(
    id: FlowId,
    tx: u64,
    rx: u64,
    opened: Instant,
    now: Instant,
    reason: &str,
) -> Payload {
    let dur_ms = now.saturating_duration_since(opened).as_millis();
    Payload::NetClose(NetClose {
        flow: id.0,
        tx,
        rx,
        dur_ms: u64::try_from(dur_ms).unwrap_or(u64::MAX),
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(kind: &'static str, name: Option<&str>) -> (&'static str, Option<Shown>) {
        (kind, Shown::name(name.map(str::to_owned)))
    }

    #[test]
    fn first_bytes_are_read_as_tls_or_http() {
        assert_eq!(read_name(b""), ("tls", None), "nothing yet");
        assert_eq!(read_name(&[22, 3]), ("tls", None));
        assert_eq!(
            read_name(&[22, 9, 9, 9, 9]),
            named("tls", None),
            "a broken hello"
        );
        assert_eq!(read_name(b"GET / HT"), ("http", None));
        assert_eq!(
            read_name(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            named("http", Some("a.example"))
        );
        assert_eq!(read_name(b"SSH-2.0-OpenSSH_9.6\r\n"), named("http", None));
        assert_eq!(read_name(&[0, 1, 2]), named("http", None));
    }

    #[test]
    fn host_failures_are_resets_or_errors() {
        for (kind, reason) in [
            (ErrorKind::ConnectionReset, "reset"),
            (ErrorKind::BrokenPipe, "reset"),
            (ErrorKind::ConnectionAborted, "reset"),
            (ErrorKind::TimedOut, "error"),
            (ErrorKind::Other, "error"),
        ] {
            assert_eq!(host_failure(&io::Error::from(kind)), reason, "{kind:?}");
        }
    }

    #[test]
    fn only_an_allowing_domain_rule_gates() {
        let policy = Policy::parse(&[
            "allow example.com",
            "deny evil.example",
            "allow 192.0.2.0/24",
        ])
        .unwrap();
        let pattern = |i: usize| gate_pattern(policy.rules.get(i));
        assert_eq!(pattern(0).as_deref(), Some("example.com"));
        assert_eq!(pattern(1), None);
        assert_eq!(pattern(2), None);
        assert_eq!(gate_pattern(None), None);
    }

    #[test]
    fn durations_are_whole_milliseconds() {
        let t0 = Instant::now();
        let Payload::NetClose(close) = close_record(
            FlowId(3),
            1,
            2,
            t0,
            t0 + std::time::Duration::from_micros(2_500),
            "fin",
        ) else {
            panic!("not a close");
        };
        assert_eq!((close.flow, close.tx, close.rx, close.dur_ms), (3, 1, 2, 2));
        let Payload::NetClose(close) = close_record(FlowId(3), 0, 0, t0, t0, "fin") else {
            panic!("not a close");
        };
        assert_eq!(close.dur_ms, 0);
    }
}
