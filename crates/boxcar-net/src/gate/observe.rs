// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The observer's channel: how the net thread hands the plaintext of an
//! inspected flow to the `gate-observe` thread without ever waiting on it.
//!
//! The net thread sends [`Message`]s with `try_send`. When the channel is
//! full the chunk is dropped: the flow notes it ([`Observed::lost`]), the
//! stack counts it (`net.drop{reason:"observe"}`), and the next message
//! for that flow and direction is a [`Message::Lost`], so the observer
//! knows the stream it holds has a hole from there on and marks it
//! degraded. Nothing on the net thread blocks on this channel, ever.
//!
//! The last [`CONTROL_RESERVE`] places are kept for `Open` and `Close`, so
//! plaintext filling the channel never costs a flow its beginning or its
//! end. A flow whose `Open` still finds no room is not observed: its
//! plaintext is counted dropped from then on. A `Close` that finds no room
//! leaves its flow with the observer, which holds at most
//! [`MAX_OBSERVED`] and records the oldest as it stands to make room.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddrV4;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_audit::AuditSink;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};

use crate::dump::DumpDir;

use super::exchange::Observation;

/// The most plaintext bytes one message carries.
pub const CHUNK_MAX: usize = 64 * 1024;
/// How many messages the channel holds.
pub const CHANNEL_CAP: usize = 4096;
/// The places at the channel's end only `Open` and `Close` may take.
pub const CONTROL_RESERVE: usize = 1024;
/// The most flows the observer holds open; past it the oldest is recorded
/// as it stands and let go. Above the TCP flow cap, so only flows whose
/// `Close` was lost are ever let go this way.
pub const MAX_OBSERVED: usize = 8192;

/// Which way plaintext moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From the guest to the host: a request.
    ToHost,
    /// From the host to the guest: a response.
    ToGuest,
}

impl Direction {
    /// As the dump names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::ToHost => "c2s",
            Direction::ToGuest => "s2c",
        }
    }

    fn index(self) -> usize {
        match self {
            Direction::ToHost => 0,
            Direction::ToGuest => 1,
        }
    }
}

/// What the observer hears about an inspected flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// An inspected flow's plaintext begins: a TLS flow once both
    /// handshakes are done, a plain HTTP flow at its first byte.
    Open {
        flow: u64,
        dst: SocketAddrV4,
        /// The server name, or the `Host`, the flow asked for.
        name: Option<String>,
        /// The application protocol TLS chose, if any (`h2`, `http/1.1`).
        alpn: Option<String>,
        /// Whether the flow was TLS (ended here) or plain HTTP.
        tls: bool,
    },
    /// Plaintext, in order within its direction.
    Data {
        flow: u64,
        dir: Direction,
        bytes: Vec<u8>,
    },
    /// A chunk was dropped before this: the direction's stream has a hole.
    Lost { flow: u64, dir: Direction },
    /// The flow ended; nothing more comes for it.
    Close { flow: u64 },
}

impl Message {
    pub fn flow(&self) -> u64 {
        match self {
            Message::Open { flow, .. }
            | Message::Data { flow, .. }
            | Message::Lost { flow, .. }
            | Message::Close { flow } => *flow,
        }
    }
}

/// The net thread's end of the channel.
#[derive(Clone, Debug)]
pub struct Observer {
    tx: Sender<Message>,
    /// How many messages may wait before plaintext is refused.
    data_limit: usize,
}

/// What a send came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// Queued.
    Ok,
    /// Dropped: the channel was full. The caller counts it and marks the
    /// flow so a `Lost` goes before its next chunk.
    Dropped,
    /// The observer is gone; nothing is queued.
    Closed,
}

impl Observer {
    /// A channel of [`CHANNEL_CAP`] messages: the sender for the net
    /// thread, the receiver for the observer.
    pub fn channel() -> (Observer, Receiver<Message>) {
        Observer::with_capacity(CHANNEL_CAP)
    }

    /// [`channel`](Self::channel) with a capacity of its own (tests).
    pub fn with_capacity(cap: usize) -> (Observer, Receiver<Message>) {
        let (tx, rx) = crossbeam_channel::bounded(cap);
        let data_limit = cap.saturating_sub(CONTROL_RESERVE.min(cap / 4));
        (Observer { tx, data_limit }, rx)
    }

    /// Queues `msg` without waiting: plaintext (`Data`, `Lost`) only below
    /// the control reserve, `Open` and `Close` while there is any room.
    pub fn send(&self, msg: Message) -> Sent {
        let control = matches!(msg, Message::Open { .. } | Message::Close { .. });
        if !control && self.tx.len() >= self.data_limit {
            return Sent::Dropped;
        }
        match self.tx.try_send(msg) {
            Ok(()) => Sent::Ok,
            Err(TrySendError::Full(_)) => Sent::Dropped,
            Err(TrySendError::Disconnected(_)) => Sent::Closed,
        }
    }

    /// How many messages wait.
    pub fn queued(&self) -> usize {
        self.tx.len()
    }
}

/// A flow's observation on the net thread: the `Lost` owed in each
/// direction, and the bytes that went and did not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// A chunk was dropped in this direction since the last message sent
    /// for it: a `Lost` goes before the next chunk.
    lost: [bool; 2],
    /// Plaintext bytes handed to the observer, each way.
    pub sent: [u64; 2],
    /// Plaintext bytes dropped, each way.
    pub dropped: [u64; 2],
    /// The observer is gone: nothing more is sent, and what would have
    /// been is counted dropped.
    closed: bool,
    /// The flow's `Open` found no room: its plaintext is all dropped.
    refused: bool,
}

impl Observed {
    /// Hands `bytes` to the observer as chunks of at most [`CHUNK_MAX`],
    /// after a `Lost` if one is owed. Returns how many bytes were dropped
    /// (the caller counts them); the dropped bytes are the tail. Never
    /// waits.
    pub fn data(&mut self, observer: &Observer, flow: u64, dir: Direction, bytes: &[u8]) -> u64 {
        if bytes.is_empty() {
            return 0;
        }
        let i = dir.index();
        // Unannounced, or the observer gone (its receiver lives as long as
        // a sender does, so only a thread that died drops it): counted.
        if self.refused || self.closed {
            self.dropped[i] = self.dropped[i].saturating_add(bytes.len() as u64);
            return bytes.len() as u64;
        }
        if self.lost[i] {
            match observer.send(Message::Lost { flow, dir }) {
                Sent::Ok => self.lost[i] = false,
                Sent::Dropped => {
                    self.dropped[i] = self.dropped[i].saturating_add(bytes.len() as u64);
                    return bytes.len() as u64;
                }
                Sent::Closed => {
                    self.closed = true;
                    self.dropped[i] = self.dropped[i].saturating_add(bytes.len() as u64);
                    return bytes.len() as u64;
                }
            }
        }
        let mut sent = 0;
        for chunk in bytes.chunks(CHUNK_MAX) {
            match observer.send(Message::Data {
                flow,
                dir,
                bytes: chunk.to_vec(),
            }) {
                Sent::Ok => sent += chunk.len(),
                Sent::Dropped => {
                    self.lost[i] = true;
                    break;
                }
                Sent::Closed => {
                    self.closed = true;
                    break;
                }
            }
        }
        let dropped = (bytes.len() - sent) as u64;
        self.sent[i] = self.sent[i].saturating_add(sent as u64);
        self.dropped[i] = self.dropped[i].saturating_add(dropped);
        dropped
    }

    /// Whether a chunk has been lost in `dir` and not yet told.
    pub fn lost(&self, dir: Direction) -> bool {
        self.lost[dir.index()]
    }

    /// Announces the flow (`msg` is its `Open`). Whether the observer will
    /// hear of it: if not, its plaintext is counted dropped from here.
    pub fn open(&mut self, observer: &Observer, msg: Message) -> bool {
        match observer.send(msg) {
            Sent::Ok => true,
            Sent::Dropped => {
                self.refused = true;
                false
            }
            Sent::Closed => {
                self.closed = true;
                false
            }
        }
    }

    /// Tells the observer the flow is over. A `Close` that cannot be
    /// queued is dropped: the observer ends the flow at the VM's stop, or
    /// sooner past [`MAX_OBSERVED`].
    pub fn close(&mut self, observer: &Observer, flow: u64) -> Sent {
        if self.closed {
            return Sent::Closed;
        }
        let sent = observer.send(Message::Close { flow });
        if sent == Sent::Closed {
            self.closed = true;
        }
        sent
    }
}

/// The `gate-observe` thread, which takes the channel's messages for as
/// long as a sender lives.
pub struct ObserverThread {
    done: mpsc::Receiver<()>,
    thread: JoinHandle<()>,
}

impl ObserverThread {
    /// Starts the thread on `rx`, recording into `sink`. It ends when
    /// every [`Observer`] is gone and the channel is drained.
    pub fn spawn(
        rx: Receiver<Message>,
        sink: AuditSink,
        trace_id: String,
        dump: Option<DumpDir>,
    ) -> io::Result<ObserverThread> {
        let (stopped, done) = mpsc::channel::<()>();
        let thread = thread::Builder::new()
            .name("gate-observe".into())
            .spawn(move || {
                // Dropped when the thread ends, however it ends.
                let _stopped = stopped;
                run(rx, &sink, &trace_id, dump.as_ref());
            })?;
        Ok(ObserverThread { done, thread })
    }

    /// Waits at most `limit` for the thread to end, then joins it; a thread
    /// still busy is left behind. Whether it was joined.
    pub fn join(self, limit: Duration) -> bool {
        match self.done.recv_timeout(limit) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => self.thread.join().is_ok(),
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        }
    }
}

/// The observer's work: each open flow's HTTP exchanges
/// ([`Observation`]), whose records go into the log with the blocking
/// emit (a full writer stalls this thread, never the net thread). At the
/// end, when the senders are gone, what is still open is recorded as it
/// stands.
fn run(rx: Receiver<Message>, sink: &AuditSink, trace_id: &str, dump: Option<&DumpDir>) {
    let mut flows: HashMap<u64, Observation> = HashMap::new();
    let mut out = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Message::Open {
                flow,
                dst,
                name,
                alpn,
                tls,
            }) => {
                if flows.len() >= MAX_OBSERVED {
                    if let Some(oldest) = flows.keys().min().copied() {
                        if let Some(mut observation) = flows.remove(&oldest) {
                            observation.close(Instant::now(), &mut out);
                        }
                    }
                }
                flows.insert(
                    flow,
                    Observation::new(flow, dst, name, alpn.as_deref(), tls, trace_id)
                        .with_dump(dump.cloned()),
                );
            }
            Ok(Message::Data { flow, dir, bytes }) => {
                if let Some(observation) = flows.get_mut(&flow) {
                    observation.data(dir, &bytes, Instant::now(), &mut out);
                }
            }
            Ok(Message::Lost { flow, dir }) => {
                if let Some(observation) = flows.get_mut(&flow) {
                    observation.lost(dir, Instant::now(), &mut out);
                }
            }
            Ok(Message::Close { flow }) => {
                if let Some(mut observation) = flows.remove(&flow) {
                    observation.close(Instant::now(), &mut out);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        for emit in out.drain(..) {
            crate::audit::record_in_span(sink, emit.payload, emit.span);
        }
    }
    let now = Instant::now();
    for (_, mut observation) in flows.drain() {
        observation.close(now, &mut out);
    }
    for emit in out.drain(..) {
        crate::audit::record_in_span(sink, emit.payload, emit.span);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn dst() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 443)
    }

    fn open_msg(flow: u64) -> Message {
        Message::Open {
            flow,
            dst: dst(),
            name: None,
            alpn: None,
            tls: true,
        }
    }

    /// Plaintext stops at the control reserve; `Open` and `Close` still
    /// go in it.
    #[test]
    fn opens_and_closes_keep_room_that_plaintext_cannot_take() {
        let (observer, rx) = Observer::with_capacity(16);
        let mut observed = Observed::default();
        assert!(observed.open(&observer, open_msg(1)));
        let mut queued = 1;
        while observed.data(&observer, 1, Direction::ToHost, b"x") == 0 {
            queued += 1;
        }
        assert_eq!(
            queued,
            16 - 4,
            "the reserve is a quarter of a small channel"
        );
        let mut other = Observed::default();
        assert!(other.open(&observer, open_msg(2)));
        assert_eq!(observed.close(&observer, 1), Sent::Ok);
        drop(rx);
    }

    /// A flow whose `Open` found no room is not observed: its plaintext is
    /// counted dropped, all of it.
    #[test]
    fn a_refused_open_drops_the_flows_plaintext() {
        let (observer, _rx) = Observer::with_capacity(4);
        for flow in 0..4 {
            assert_eq!(observer.send(open_msg(flow)), Sent::Ok);
        }
        let mut observed = Observed::default();
        assert!(!observed.open(&observer, open_msg(9)));
        assert_eq!(observed.data(&observer, 9, Direction::ToGuest, b"abc"), 3);
        assert_eq!(observed.dropped, [0, 3]);
    }

    /// Chunks go in order and in pieces of at most `CHUNK_MAX`.
    #[test]
    fn data_goes_in_bounded_chunks_in_order() {
        let (observer, rx) = Observer::channel();
        let mut flow = Observed::default();
        let bytes: Vec<u8> = (0..(CHUNK_MAX * 2 + 10)).map(|i| i as u8).collect();
        assert_eq!(flow.data(&observer, 7, Direction::ToHost, &bytes), 0);
        let mut got = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Message::Data {
                    flow: 7,
                    dir: Direction::ToHost,
                    bytes,
                } => {
                    assert!(bytes.len() <= CHUNK_MAX);
                    got.extend(bytes);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, bytes);
        assert_eq!(flow.sent, [bytes.len() as u64, 0]);
    }

    /// A full channel drops the chunk and the rest of its bytes, counts
    /// them, and owes a `Lost` in that direction, which goes before the
    /// next chunk once there is room. Nothing waits.
    #[test]
    fn a_full_channel_drops_counts_and_owes_a_lost() {
        let (observer, rx) = Observer::with_capacity(2);
        let mut flow = Observed::default();
        assert_eq!(flow.data(&observer, 1, Direction::ToHost, b"aa"), 0);
        assert_eq!(flow.data(&observer, 1, Direction::ToGuest, b"bb"), 0);
        // Full: dropped whole, at once.
        assert_eq!(flow.data(&observer, 1, Direction::ToHost, b"cc"), 2);
        assert!(flow.lost(Direction::ToHost));
        assert!(!flow.lost(Direction::ToGuest));
        assert_eq!(flow.dropped, [2, 0]);
        // Still full: a Lost cannot go either, the bytes are dropped.
        assert_eq!(flow.data(&observer, 1, Direction::ToHost, b"dd"), 2);
        assert_eq!(flow.dropped, [4, 0]);
        // Room again: the Lost goes first, then the chunk.
        assert_eq!(
            rx.try_recv().unwrap(),
            Message::Data {
                flow: 1,
                dir: Direction::ToHost,
                bytes: b"aa".to_vec()
            }
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            Message::Data {
                flow: 1,
                dir: Direction::ToGuest,
                bytes: b"bb".to_vec()
            }
        );
        assert_eq!(flow.data(&observer, 1, Direction::ToHost, b"ee"), 0);
        assert!(!flow.lost(Direction::ToHost));
        assert_eq!(
            rx.try_recv().unwrap(),
            Message::Lost {
                flow: 1,
                dir: Direction::ToHost
            }
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            Message::Data {
                flow: 1,
                dir: Direction::ToHost,
                bytes: b"ee".to_vec()
            }
        );
        assert_eq!(flow.sent, [4, 2]);
        // The other direction never lost anything.
        assert_eq!(flow.data(&observer, 1, Direction::ToGuest, b"ff"), 0);
        assert_eq!(
            rx.try_recv().unwrap(),
            Message::Data {
                flow: 1,
                dir: Direction::ToGuest,
                bytes: b"ff".to_vec()
            }
        );
    }

    /// A chunk larger than the channel's room is dropped from the first
    /// piece that does not fit; the pieces before went.
    #[test]
    fn a_long_chunk_is_cut_where_the_room_ends() {
        let (observer, rx) = Observer::with_capacity(2);
        let mut flow = Observed::default();
        let bytes = vec![1; CHUNK_MAX * 3];
        assert_eq!(
            flow.data(&observer, 2, Direction::ToGuest, &bytes),
            CHUNK_MAX as u64
        );
        assert_eq!(rx.len(), 2);
        assert_eq!(flow.sent, [0, 2 * CHUNK_MAX as u64]);
        assert!(flow.lost(Direction::ToGuest));
    }

    /// An observer that is gone takes nothing, and what it did not take
    /// is counted dropped: its receiver outlives every sender unless its
    /// thread died.
    #[test]
    fn a_gone_observer_takes_nothing_and_its_bytes_are_counted() {
        let (observer, rx) = Observer::channel();
        drop(rx);
        let mut flow = Observed::default();
        assert_eq!(flow.data(&observer, 3, Direction::ToHost, b"x"), 1);
        assert_eq!(flow.data(&observer, 3, Direction::ToGuest, b"yz"), 2);
        assert_eq!(flow.sent, [0, 0]);
        assert_eq!(flow.dropped, [1, 2]);
        assert_eq!(flow.close(&observer, 3), Sent::Closed);
    }

    /// The thread ends once every sender is gone, and is joined; what it
    /// read of a flow is in the log.
    #[test]
    fn the_thread_ends_with_its_senders() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, writer) = boxcar_audit::spawn(boxcar_audit::WriterConfig::new(
            dir.path().join("data"),
            boxcar_proto::SessionId::new(),
        ))
        .unwrap();
        let session_dir = writer.session_dir().to_path_buf();
        let (observer, rx) = Observer::channel();
        let thread = ObserverThread::spawn(rx, sink, "trace-test".into(), None).unwrap();
        assert_eq!(
            observer.send(Message::Open {
                flow: 1,
                dst: dst(),
                name: None,
                alpn: None,
                tls: true
            }),
            Sent::Ok
        );
        let mut flow = Observed::default();
        flow.data(
            &observer,
            1,
            Direction::ToHost,
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        );
        flow.data(
            &observer,
            1,
            Direction::ToGuest,
            b"HTTP/1.1 204 No Content\r\n\r\n",
        );
        flow.close(&observer, 1);
        drop(observer);
        assert!(thread.join(Duration::from_secs(5)));
        writer.close().unwrap();
        let kinds: Vec<String> = boxcar_audit::LogReader::open(&session_dir)
            .map(|r| r.records().map(|r| r.unwrap().kind).collect())
            .unwrap_or_default();
        assert!(
            kinds.contains(&"http.request".to_owned())
                && kinds.contains(&"http.response".to_owned()),
            "{kinds:?}"
        );
    }

    #[test]
    fn open_and_close_carry_the_flow() {
        let (observer, rx) = Observer::channel();
        let open = Message::Open {
            flow: 9,
            dst: dst(),
            name: Some("api.example".into()),
            alpn: Some("h2".into()),
            tls: true,
        };
        assert_eq!(observer.send(open.clone()), Sent::Ok);
        let mut flow = Observed::default();
        assert_eq!(flow.close(&observer, 9), Sent::Ok);
        assert_eq!(rx.try_recv().unwrap(), open);
        assert_eq!(rx.try_recv().unwrap().flow(), 9);
        assert_eq!(observer.queued(), 0);
    }
}
