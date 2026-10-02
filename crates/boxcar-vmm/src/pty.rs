// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The PTY hub: the service on vsock port 1025 (`boxcar.pty`), which takes
//! the session's terminal from the guest's init and shares it among its
//! clients: `boxcar run`'s own stdout ([`out`]) and stdin ([`input`]), in
//! the same process, and every control connection that attached with
//! `pty.attach` ([`raw`]).
//!
//! Init connects once its session's PTY is open, from guest port 1022, and
//! sends one header line, `{"v":1,"session":"main","rows":R,"cols":C}`
//! ([`PtyHeader`], at most 1 KiB); the stream is then the terminal's bytes
//! both ways. The hub takes one connection in the VMM's life (a later one,
//! after the guest re-activated its vsock driver, is refused as
//! `reactivated`; one that came while the hub could not be set up is
//! refused as `no_service`, and the next may still be taken).
//!
//! **The guest never waits on a viewer.** The hub's thread reads the guest's
//! stream as fast as it comes, into a [`SCROLLBACK`] (256 KiB) ring and onto
//! each client's queue, and never waits on a client: a client with more
//! than [`BACKLOG_MAX`] (1 MiB) of output waiting is detached
//! ([`End::Slow`]), and a control connection then hears
//! `{"v":1,"event":"pty.detached","reason":"slow"}`. With no client at all
//! the hub still reads, into the ring.
//!
//! A client ([`PtyHub::attach`]) gets the newest bytes of the ring it asks
//! for (its replay), then everything the session prints from then on: the
//! two are taken under one lock, so nothing is missed or repeated between
//! them. A read-write client ([`Mode::Rw`]) also gets an [`Input`]: what it
//! sends goes into one input queue of at most [`INPUT_MAX`] (64 KiB), which
//! the hub's thread writes to the guest as the stream takes it; what does
//! not fit is dropped and counted ([`PtyHub::input_dropped`]), never waited
//! for (`boxcar run`'s own stdin waits for room instead,
//! [`Input::send_all`]). [`PtyHub::resize`] sends the terminal's new size to
//! init over the guest control channel: the latest size asked for wins, and
//! a size the terminal has already is not sent again.
//!
//! When the guest closes its side (init does once the session has ended and
//! its PTY is drained), the hub has read everything: it closes its own side
//! at once, which init waits for before it reboots, and every client's
//! output ends ([`End::SessionEnded`]). A client that attaches after that
//! gets its replay, then the end: the ring stays until the VMM is gone. The
//! stop sequence closes the hub's stream ([`PtyHub::close`]), so the
//! clients end with the VM.

pub mod input;
pub mod out;
pub mod raw;

use std::collections::VecDeque;
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use boxcar_proto::guest::{decode, HostMsg, LineBuf, PtyHeader, MAX_PTY_HEADER};
use boxcar_vsock::{ConnMeta, Deny};
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

use crate::console::Ring;
use crate::guest_ctl::{GuestCtlHandle, SendError, REACTIVATED};
use crate::services::Service;

pub use boxcar_proto::control::PTY_SESSION as SESSION;

/// A piece of the session's output, as a client gets it: shared by every
/// client it goes to.
pub type Bytes = Arc<[u8]>;

/// The scrollback the hub keeps of the session's output, for replays.
pub const SCROLLBACK: usize = 256 * 1024;

/// The most output a client may leave waiting; past it, it is detached.
pub const BACKLOG_MAX: usize = 1 << 20;

/// The most input waiting for the guest, from every client together.
pub const INPUT_MAX: usize = 64 * 1024;

/// Bytes read from the guest at a time.
const READ_CHUNK: usize = 32 * 1024;

/// Reads from the guest before the hub's thread looks at the input again.
const READS_PER_TURN: usize = 8;

/// Input bytes the hub's thread takes from the queue at a time.
const WRITE_CHUNK: usize = 16 * 1024;

/// How long [`Input::send_all`] waits for room before it looks again.
const ROOM_STEP: Duration = Duration::from_millis(100);

/// A client of the hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(u64);

/// How a client attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// It may type into the session: it gets an [`Input`].
    Rw,
    /// It only reads.
    Ro,
}

/// Where the session's terminal is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtyState {
    /// Init has not connected it (nor sent its header) yet.
    Waiting,
    /// The session's output comes through the hub.
    Live,
    /// The guest closed its side (the session ended), the stream failed,
    /// or the VM stopped.
    Ended,
}

/// Why a client's output ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The session's terminal ended.
    SessionEnded,
    /// The client left more than [`BACKLOG_MAX`] waiting.
    Slow,
    /// It was detached ([`PtyHub::detach`]), or dropped its output.
    Detached,
}

/// Input from a client that the session's terminal no longer takes: the
/// session ended, or the client was detached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the session's terminal takes no more input from this client")]
pub struct Closed;

/// The session's terminal, shared by its clients. Cheap to clone: the VMM,
/// its handles and each control connection attached hold one.
#[derive(Clone)]
pub struct PtyHub {
    shared: Arc<Shared>,
}

/// The hub, as its thread, its clients' inputs and its handles share it.
struct Shared {
    /// Where `resize` goes.
    guest: GuestCtlHandle,
    /// Set once the one connection of the VMM's life is taken.
    taken: AtomicBool,
    /// Wakes the hub's thread: input is waiting.
    wake: EventFd,
    state: Mutex<State>,
    /// Told when the input queue has room again and when the terminal
    /// ends.
    changed: Condvar,
    totals: Arc<Totals>,
    /// A copy of the hub's end of the stream, for [`PtyHub::close`]; let
    /// go once the terminal ends.
    stream: Mutex<Option<UnixStream>>,
}

/// What clients read without the hub's lock.
#[derive(Default)]
struct Totals {
    /// Bytes of the session's output the hub has read.
    received: AtomicU64,
    /// Input that did not fit the queue, or came after the guest stopped
    /// taking it.
    input_dropped: AtomicU64,
    /// Input read-only clients sent.
    ro_discarded: AtomicU64,
}

struct State {
    phase: PtyState,
    ring: Ring,
    clients: Vec<Client>,
    next_id: u64,
    /// Input waiting for the hub's thread, at most [`INPUT_MAX`].
    input: VecDeque<u8>,
    /// The size init has: the header's, then each one sent.
    sent: Option<(u16, u16)>,
    /// The size last asked for.
    wanted: Option<(u16, u16)>,
}

/// A client, as the hub holds it.
struct Client {
    id: u64,
    tx: mpsc::Sender<Bytes>,
    shared: Arc<ClientShared>,
}

impl Client {
    /// Queues `chunk` for the client, unless that would leave it more than
    /// [`BACKLOG_MAX`] behind or it is gone. Returns whether it stays.
    fn offer(&self, chunk: &Bytes) -> bool {
        let len = chunk.len();
        let backlog = &self.shared.backlog;
        if backlog.load(Ordering::Acquire).saturating_add(len) > BACKLOG_MAX {
            self.shared.finish(End::Slow);
            return false;
        }
        backlog.fetch_add(len, Ordering::AcqRel);
        if self.tx.send(Arc::clone(chunk)).is_err() {
            backlog.fetch_sub(len, Ordering::AcqRel);
            self.shared.finish(End::Detached);
            return false;
        }
        true
    }
}

/// A client, as its output and input see it.
struct ClientShared {
    /// Bytes queued and not received yet.
    backlog: AtomicUsize,
    end: Mutex<Option<End>>,
    /// Where in the session's output (a count of bytes) the client starts:
    /// its replay's first byte.
    start: u64,
    totals: Arc<Totals>,
}

impl ClientShared {
    /// The client ends for `end`, unless it ended already.
    fn finish(&self, end: End) {
        let mut slot = self.end.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(end);
        }
    }

    fn end(&self) -> Option<End> {
        *self.end.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether its input is no longer taken: the session ended or it was
    /// detached. A client detached for being slow may still type until its
    /// connection closes.
    fn input_closed(&self) -> bool {
        matches!(self.end(), Some(End::SessionEnded | End::Detached))
    }
}

/// A client's view of the session's output: its replay, then each piece the
/// session prints, until its [`End`]. Bounded: see [`BACKLOG_MAX`].
pub struct Output {
    rx: mpsc::Receiver<Bytes>,
    client: Arc<ClientShared>,
}

impl Output {
    /// The next piece, waiting for it; `None` at the end.
    pub fn recv(&self) -> Option<Bytes> {
        let bytes = self.rx.recv().ok()?;
        self.took(&bytes);
        Some(bytes)
    }

    /// The next piece, waiting at most `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Bytes, RecvTimeoutError> {
        let bytes = self.rx.recv_timeout(timeout)?;
        self.took(&bytes);
        Ok(bytes)
    }

    /// The next piece, if one is waiting.
    pub fn try_recv(&self) -> Result<Bytes, TryRecvError> {
        let bytes = self.rx.try_recv()?;
        self.took(&bytes);
        Ok(bytes)
    }

    /// Why the output ended (or will, once what is queued is received).
    pub fn end(&self) -> Option<End> {
        self.client.end()
    }

    /// Where in the session's output this client started: a count of
    /// bytes, its replay included.
    pub fn start(&self) -> u64 {
        self.client.start
    }

    /// How much of the session's output the hub has read so far.
    pub fn session_bytes(&self) -> u64 {
        self.client.totals.received.load(Ordering::Acquire)
    }

    fn took(&self, bytes: &Bytes) {
        self.client.backlog.fetch_sub(bytes.len(), Ordering::AcqRel);
    }
}

/// A read-write client's way to type into the session.
pub struct Input {
    shared: Arc<Shared>,
    client: Arc<ClientShared>,
}

impl Input {
    /// Queues as much of `bytes` as the input queue has room for, without
    /// waiting; the rest is dropped and counted. Returns how many were
    /// taken.
    pub fn send(&self, bytes: &[u8]) -> Result<usize, Closed> {
        let taken = self.queue(bytes)?;
        let dropped = bytes.len() - taken;
        if dropped > 0 {
            self.shared
                .totals
                .input_dropped
                .fetch_add(dropped as u64, Ordering::Relaxed);
        }
        Ok(taken)
    }

    /// Queues all of `bytes`, waiting for room as long as it takes: for
    /// input that must not be lost, such as `boxcar run`'s piped stdin.
    pub fn send_all(&self, mut bytes: &[u8]) -> Result<(), Closed> {
        loop {
            let taken = self.queue(bytes)?;
            bytes = &bytes[taken..];
            if bytes.is_empty() {
                return Ok(());
            }
            let state = self.shared.lock();
            if state.input.len() >= INPUT_MAX && !self.closed(&state) {
                let _ = self
                    .shared
                    .changed
                    .wait_timeout(state, ROOM_STEP)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
    }

    fn closed(&self, state: &State) -> bool {
        state.phase == PtyState::Ended || self.client.input_closed()
    }

    /// Appends what fits to the queue and wakes the hub's thread.
    fn queue(&self, bytes: &[u8]) -> Result<usize, Closed> {
        let taken = {
            let mut state = self.shared.lock();
            if self.closed(&state) {
                return Err(Closed);
            }
            let taken = bytes.len().min(INPUT_MAX - state.input.len());
            state.input.extend(&bytes[..taken]);
            taken
        };
        if taken > 0 {
            self.shared.wake();
        }
        Ok(taken)
    }
}

impl PtyHub {
    /// A hub whose resizes go to `guest`; idle until its
    /// [`service`](PtyHub::service) takes init's connection.
    pub fn new(guest: GuestCtlHandle) -> io::Result<PtyHub> {
        Ok(PtyHub {
            shared: Arc::new(Shared {
                guest,
                taken: AtomicBool::new(false),
                wake: EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)?,
                state: Mutex::new(State {
                    phase: PtyState::Waiting,
                    ring: Ring::new(SCROLLBACK),
                    clients: Vec::new(),
                    next_id: 1,
                    input: VecDeque::new(),
                    sent: None,
                    wanted: None,
                }),
                changed: Condvar::new(),
                totals: Arc::new(Totals::default()),
                stream: Mutex::new(None),
            }),
        })
    }

    /// The service for port 1025: takes the first connection, and refuses
    /// every later one as [`REACTIVATED`].
    pub fn service(&self) -> Service {
        let hub = self.clone();
        Arc::new(move |meta| hub.connect(meta, UnixStream::pair))
    }

    /// A guest connection to 1025, on the vsock thread: the hub on a new
    /// stream pair from `pair` the first time, `reactivated` after;
    /// `no_service`, leaving the next connection free, when the hub cannot
    /// be set up.
    pub(crate) fn connect(
        &self,
        meta: ConnMeta,
        pair: impl FnOnce() -> io::Result<(UnixStream, UnixStream)>,
    ) -> Result<UnixStream, Deny> {
        let shared = &self.shared;
        if shared.taken.load(Ordering::Acquire) {
            boxcar_virtio::limited!(
                warn,
                "pty hub: refused a connection from guest port {}: the session's terminal \
                 was taken already",
                meta.guest_port
            );
            return Err(Deny::Refused(REACTIVATED));
        }
        let refused = |error: io::Error| {
            boxcar_virtio::limited!(
                warn,
                "pty hub: cannot take the session's terminal from guest port {}: {error}",
                meta.guest_port
            );
            Deny::NoService
        };
        let (ours, theirs) = pair().map_err(refused)?;
        let copy = theirs.try_clone().map_err(refused)?;
        *shared.stream_slot() = Some(copy);
        let hub = Arc::clone(shared);
        let spawned = thread::Builder::new()
            .name("pty-hub".into())
            .spawn(move || serve(&hub, theirs));
        if let Err(error) = spawned {
            *shared.stream_slot() = None;
            return Err(refused(error));
        }
        shared.taken.store(true, Ordering::Release);
        Ok(ours)
    }

    /// Where the session's terminal is.
    pub fn state(&self) -> PtyState {
        self.shared.lock().phase
    }

    /// Attaches a client: the newest `replay_bytes` of the scrollback (at
    /// most [`SCROLLBACK`]), then the session's output as it comes; an
    /// [`Input`] for a [`Mode::Rw`] client. A client may attach before the
    /// terminal opens (it then gets the session's output from its first
    /// byte) and after it ended (its replay, then the end).
    pub fn attach(&self, mode: Mode, replay_bytes: usize) -> (ClientId, Output, Option<Input>) {
        let shared = &self.shared;
        let (id, rx, client) = {
            let mut state = shared.lock();
            let id = state.next_id;
            state.next_id += 1;
            let replay = state.ring.tail(replay_bytes.min(SCROLLBACK));
            let received = shared.totals.received.load(Ordering::Acquire);
            let client = Arc::new(ClientShared {
                backlog: AtomicUsize::new(replay.len()),
                end: Mutex::new(None),
                start: received.saturating_sub(replay.len() as u64),
                totals: Arc::clone(&shared.totals),
            });
            let (tx, rx) = mpsc::channel();
            if !replay.is_empty() {
                let _ = tx.send(Bytes::from(replay));
            }
            if state.phase == PtyState::Ended {
                // The replay, then the end.
                client.finish(End::SessionEnded);
            } else {
                state.clients.push(Client {
                    id,
                    tx,
                    shared: Arc::clone(&client),
                });
            }
            (id, rx, client)
        };
        let input = (mode == Mode::Rw).then(|| Input {
            shared: Arc::clone(shared),
            client: Arc::clone(&client),
        });
        (ClientId(id), Output { rx, client }, input)
    }

    /// Detaches a client: its output ends once what is queued is received,
    /// and its input is no longer taken. Nothing for one that is gone.
    pub fn detach(&self, id: ClientId) {
        let client = {
            let mut state = self.shared.lock();
            let index = state.clients.iter().position(|client| client.id == id.0);
            index.map(|index| state.clients.swap_remove(index))
        };
        if let Some(client) = client {
            client.shared.finish(End::Detached);
        }
    }

    /// Asks for the terminal to be `rows` by `cols`: sent to init as
    /// `resize` unless it has that size already; before the terminal
    /// opens, sent once it does (when it opens at another size). The latest
    /// size asked for wins. Fails, keeping the size to send next time, when
    /// init cannot be told.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), SendError> {
        let mut state = self.shared.lock();
        state.wanted = Some((rows, cols));
        if state.phase != PtyState::Live {
            return Ok(());
        }
        self.shared.send_size(&mut state)
    }

    /// Bytes of the session's output the hub has read.
    pub fn received(&self) -> u64 {
        self.shared.totals.received.load(Ordering::Acquire)
    }

    /// Input bytes dropped: past [`INPUT_MAX`], or after the guest stopped
    /// taking input.
    pub fn input_dropped(&self) -> u64 {
        self.shared.totals.input_dropped.load(Ordering::Relaxed)
    }

    /// Input bytes read-only clients sent, and the hub discarded.
    pub fn ro_discarded(&self) -> u64 {
        self.shared.totals.ro_discarded.load(Ordering::Relaxed)
    }

    /// Counts `len` bytes a read-only client sent.
    pub(crate) fn discard(&self, len: usize) {
        self.shared
            .totals
            .ro_discarded
            .fetch_add(len as u64, Ordering::Relaxed);
    }

    /// The clients attached now.
    pub fn clients(&self) -> usize {
        self.shared.lock().clients.len()
    }

    /// Ends the session's terminal from the host's side: the hub's stream
    /// is shut down, so its thread reads what is left and ends, and so do
    /// the clients; a terminal init never opened ends at once. The stop
    /// sequence calls it: it logs nothing and waits on nothing.
    pub fn close(&self) {
        if let Some(stream) = self.shared.stream_slot().take() {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        if self.shared.lock().phase == PtyState::Waiting {
            self.shared.end();
        }
    }

    /// Waits, at most `timeout`, for the terminal to end; returns whether
    /// it has.
    pub fn wait_ended(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.shared.lock();
        while state.phase != PtyState::Ended {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stream_slot(&self) -> MutexGuard<'_, Option<UnixStream>> {
        self.stream.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wake(&self) {
        // A full eventfd is awake already.
        let _ = self.wake.write(1);
    }

    /// Sends the size asked for last, unless init has it.
    fn send_size(&self, state: &mut State) -> Result<(), SendError> {
        let Some((rows, cols)) = state.wanted else {
            return Ok(());
        };
        if state.sent == Some((rows, cols)) {
            return Ok(());
        }
        self.guest.send(HostMsg::Resize { rows, cols })?;
        state.sent = Some((rows, cols));
        Ok(())
    }

    /// The terminal opened at `rows` by `cols`.
    fn open(&self, rows: u16, cols: u16) {
        let mut state = self.lock();
        state.phase = PtyState::Live;
        state.sent = Some((rows, cols));
        if let Err(error) = self.send_size(&mut state) {
            boxcar_virtio::limited!(debug, "pty hub: the size asked for is not sent: {error}");
        }
    }

    /// The session printed `bytes`: into the ring and onto every client's
    /// queue, under the lock that attaching takes.
    fn deliver(&self, bytes: &[u8]) {
        let mut state = self.lock();
        state.ring.push(bytes);
        self.totals
            .received
            .fetch_add(bytes.len() as u64, Ordering::AcqRel);
        if state.clients.is_empty() {
            return;
        }
        let chunk = Bytes::from(bytes);
        state.clients.retain(|client| client.offer(&chunk));
    }

    /// Takes up to [`WRITE_CHUNK`] bytes of input into `out`; drops them
    /// all, counted, when the guest takes no more.
    fn take_input(&self, out: &mut Vec<u8>, guest_takes_input: bool) {
        let mut state = self.lock();
        if state.input.is_empty() {
            return;
        }
        if guest_takes_input {
            let len = state.input.len().min(WRITE_CHUNK);
            out.extend(state.input.drain(..len));
        } else {
            let len = state.input.len();
            state.input.clear();
            self.totals
                .input_dropped
                .fetch_add(len as u64, Ordering::Relaxed);
        }
        drop(state);
        self.changed.notify_all();
    }

    /// The terminal has ended: every client's output ends, and input is no
    /// longer taken.
    fn end(&self) {
        {
            let mut state = self.lock();
            state.phase = PtyState::Ended;
            for client in state.clients.drain(..) {
                client.shared.finish(End::SessionEnded);
            }
            let left = state.input.len();
            state.input.clear();
            self.totals
                .input_dropped
                .fetch_add(left as u64, Ordering::Relaxed);
        }
        self.changed.notify_all();
        *self.stream_slot() = None;
    }
}

/// The hub's thread: the header, then the session's output to the clients
/// and their input to the session until the guest closes; then the hub's
/// own side closes.
fn serve(shared: &Shared, mut stream: UnixStream) {
    let Some((header, rest)) = read_header(&mut stream) else {
        let _ = stream.shutdown(Shutdown::Both);
        shared.end();
        return;
    };
    if let Err(error) = stream.set_nonblocking(true) {
        boxcar_virtio::limited!(
            warn,
            "pty hub: cannot serve the session's terminal: {error}"
        );
        let _ = stream.shutdown(Shutdown::Both);
        shared.end();
        return;
    }
    shared.open(header.rows, header.cols);
    if !rest.is_empty() {
        shared.deliver(&rest);
    }
    pump(shared, &stream);
    // Everything the guest sent is in: init may reboot.
    shared.end();
    let _ = stream.shutdown(Shutdown::Write);
}

/// Reads the header line; returns it with what came after it, or `None`
/// (with a warning) when the stream does not start with one.
fn read_header(stream: &mut UnixStream) -> Option<(PtyHeader, Vec<u8>)> {
    let mut lines = LineBuf::new(MAX_PTY_HEADER);
    let mut buf = [0u8; 512];
    let line = loop {
        if let Some(line) = lines.next_line() {
            break line;
        }
        match stream.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => {
                if lines.push(&buf[..n]).is_err() {
                    boxcar_virtio::limited!(warn, "pty hub: no header line; closing");
                    return None;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    };
    match decode::<PtyHeader>(&line) {
        Ok(header) if header.v == 1 => {
            tracing::debug!(
                "pty hub: session {:?}, {} by {}",
                header.session,
                header.rows,
                header.cols
            );
            Some((header, lines.take_rest()))
        }
        Ok(header) => {
            boxcar_virtio::limited!(warn, "pty hub: header version {}; closing", header.v);
            None
        }
        Err(error) => {
            boxcar_virtio::limited!(warn, "pty hub: a bad header line: {error}; closing");
            None
        }
    }
}

/// Moves bytes both ways until the guest closes its side or the stream
/// fails. Never waits on a client: the session's output goes onto their
/// queues, and their input comes from the hub's own.
fn pump(shared: &Shared, stream: &UnixStream) {
    let fd = stream.as_raw_fd();
    let mut buf = vec![0u8; READ_CHUNK];
    // Input taken from the queue, and how much of it the guest took.
    let mut out = Vec::with_capacity(WRITE_CHUNK);
    let mut sent = 0;
    let mut guest_takes_input = true;
    loop {
        if sent == out.len() {
            out.clear();
            sent = 0;
            shared.take_input(&mut out, guest_takes_input);
        }
        let mut events = libc::POLLIN;
        if sent < out.len() {
            events |= libc::POLLOUT;
        }
        if let Err(error) = poll(fd, events, shared.wake.as_raw_fd()) {
            boxcar_virtio::limited!(warn, "pty hub: poll failed: {error}; closing");
            return;
        }
        let _ = shared.wake.read();
        for _ in 0..READS_PER_TURN {
            match (&*stream).read(&mut buf) {
                Ok(0) => return,
                Ok(n) => shared.deliver(&buf[..n]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }
        while sent < out.len() {
            match send_nowait(fd, &out[sent..]) {
                Ok(n) => sent += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    // The guest takes no more input: what is typed from
                    // now on is dropped.
                    guest_takes_input = false;
                    shared
                        .totals
                        .input_dropped
                        .fetch_add((out.len() - sent) as u64, Ordering::Relaxed);
                    sent = out.len();
                }
            }
        }
    }
}

/// Polls `fd` for `events` and `wake` for input, until either is ready.
fn poll(fd: RawFd, events: libc::c_short, wake: RawFd) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd,
            events,
            revents: 0,
        },
        libc::pollfd {
            fd: wake,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is an array of two initialized pollfds.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// `send(2)` that never blocks and never raises `SIGPIPE`.
fn send_nowait(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: sends at most `bytes.len()` bytes from `bytes`.
    let n = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
pub(crate) mod testing {
    //! A hub on a VM that was never built, and the guest's ends of its
    //! channels, for the hub's tests and its clients'.

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};

    use boxcar_audit::WriterHandle;
    use boxcar_proto::guest::{decode, encode, GuestMsg, HostMsg};
    use boxcar_vsock::{ConnMeta, InternalServices};

    use super::{Output, PtyHub};
    use crate::lifecycle::{test_handle, VmmHandle};

    /// The header init sends: a 24 by 80 terminal.
    pub(crate) const HEADER: &[u8] = b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n";

    /// How long a test waits for anything.
    pub(crate) const LIMIT: Duration = Duration::from_secs(10);

    /// A handle on a VM that was never built, with its hub at port 1025
    /// and its guest control channel at 1024.
    pub(crate) struct Fixture {
        _tmp: tempfile::TempDir,
        pub(crate) handle: VmmHandle,
        pub(crate) hub: PtyHub,
        writer: Option<WriterHandle>,
    }

    impl Fixture {
        pub(crate) fn new() -> Fixture {
            let tmp = tempfile::tempdir().unwrap();
            let (handle, writer) = test_handle(tmp.path());
            let hub = handle.pty().expect("the test handle has a hub");
            Fixture {
                _tmp: tmp,
                handle,
                hub,
                writer: Some(writer),
            }
        }

        /// Init's terminal stream, as the vsock device would hold it: port
        /// 1025 from guest port 1022, the header sent.
        pub(crate) fn guest(&self) -> UnixStream {
            let mut stream = self
                .handle
                .services()
                .connect(1025, ConnMeta { guest_port: 1022 })
                .unwrap();
            stream.set_read_timeout(Some(LIMIT)).unwrap();
            stream.write_all(HEADER).unwrap();
            stream
        }

        /// Init's control channel: port 1024 from guest port 1023, its
        /// hello said and the config read.
        pub(crate) fn init(&self) -> FakeInit {
            let stream = self
                .handle
                .services()
                .connect(1024, ConnMeta { guest_port: 1023 })
                .unwrap();
            stream.set_read_timeout(Some(LIMIT)).unwrap();
            let mut init = FakeInit {
                out: stream.try_clone().unwrap(),
                lines: BufReader::new(stream),
            };
            let hello = GuestMsg::Hello {
                init_version: "test".into(),
                guest_mono_ns: 1,
                guest_real_ns: 1,
            };
            init.out.write_all(&encode(&hello).unwrap()).unwrap();
            assert!(matches!(init.recv(), HostMsg::Config(_)));
            init
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(writer) = self.writer.take() {
                let _ = writer.close();
            }
        }
    }

    /// The init end of the guest control channel.
    pub(crate) struct FakeInit {
        lines: BufReader<UnixStream>,
        out: UnixStream,
    }

    impl FakeInit {
        /// The next message the VMM sent.
        pub(crate) fn recv(&mut self) -> HostMsg {
            let mut line = Vec::new();
            self.lines.read_until(b'\n', &mut line).unwrap();
            decode(&line).unwrap()
        }
    }

    /// Waits until `cond` holds, for at most [`LIMIT`].
    pub(crate) fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + LIMIT;
        while !cond() {
            assert!(Instant::now() < deadline, "never: {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The next `n` bytes of `output`.
    pub(crate) fn read_n(output: &Output, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < n {
            match output.recv_timeout(LIMIT) {
                Ok(bytes) => got.extend_from_slice(&bytes),
                Err(RecvTimeoutError::Timeout) => panic!("only {got:?} of {n} bytes"),
                Err(RecvTimeoutError::Disconnected) => panic!("ended after {got:?} of {n} bytes"),
            }
        }
        assert_eq!(got.len(), n, "more than asked for: {got:?}");
        got
    }

    /// Everything `output` has until its end.
    pub(crate) fn read_to_end(output: &Output) -> Vec<u8> {
        let mut got = Vec::new();
        loop {
            match output.recv_timeout(LIMIT) {
                Ok(bytes) => got.extend_from_slice(&bytes),
                Err(RecvTimeoutError::Timeout) => panic!("no end after {} bytes", got.len()),
                Err(RecvTimeoutError::Disconnected) => return got,
            }
        }
    }

    /// `len` bytes that never repeat in a short period: a gap or a
    /// duplicate in a copy of them shows.
    pub(crate) fn pattern(len: usize) -> Vec<u8> {
        let mut x: u32 = 0x2545_f491;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    use boxcar_proto::guest::HostMsg;
    use boxcar_vsock::{ConnMeta, Deny, InternalServices};

    use super::testing::{pattern, read_n, read_to_end, wait_until, Fixture, LIMIT};
    use super::*;

    /// A client gets the replay it asked for, then what the session prints
    /// from then on, with nothing missing in between and nothing twice.
    #[test]
    fn replay_then_live_bytes_arrive_in_order() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut guest = fixture.guest();
        guest.write_all(b"one two ").unwrap();
        wait_until("8 bytes in", || hub.received() == 8);
        let (_, output, input) = hub.attach(Mode::Ro, 4);
        assert!(input.is_none());
        guest.write_all(b"three").unwrap();
        assert_eq!(read_n(&output, 9), b"two three");
        // A replay is at most what the scrollback has.
        let (_, all, _) = hub.attach(Mode::Ro, usize::MAX);
        guest.write_all(b"!").unwrap();
        assert_eq!(read_n(&all, 14), b"one two three!");
        drop((output, all));

        // While the session prints, a client that attaches in the middle
        // gets one unbroken run of the stream: its replay, then the rest.
        let printed = pattern(600_000);
        let mut whole = b"one two three!".to_vec();
        whole.extend_from_slice(&printed);
        let mut to_hub = guest.try_clone().unwrap();
        let session = thread::spawn(move || {
            for chunk in printed.chunks(997) {
                to_hub.write_all(chunk).unwrap();
            }
            to_hub.shutdown(Shutdown::Write).unwrap();
        });
        wait_until("some of it in", || hub.received() > 200_000);
        let (_, middle, _) = hub.attach(Mode::Ro, 50_000);
        let got = read_to_end(&middle);
        session.join().unwrap();
        assert!(got.len() >= 50_000, "{}", got.len());
        assert!(
            whole.ends_with(&got),
            "{} bytes that are not the stream's last",
            got.len()
        );
        assert_eq!(middle.end(), Some(End::SessionEnded));
    }

    /// A client that does not read is detached once it has more than
    /// [`BACKLOG_MAX`] waiting; the hub keeps reading the guest all along
    /// (3 MiB, well past what the sockets hold), and the other clients get
    /// every byte.
    #[test]
    fn a_slow_client_is_detached_and_the_guest_keeps_running() {
        const PRINTED: usize = 3 << 20;
        let fixture = Fixture::new();
        let hub = fixture.hub.clone();
        let mut guest = fixture.guest();
        let (_, slow, _) = hub.attach(Mode::Ro, 0);
        let (_, steady, _) = hub.attach(Mode::Ro, 0);
        let reader = thread::spawn(move || {
            let got = read_to_end(&steady);
            (got.len(), steady.end())
        });
        // Nothing the guest writes waits on a client.
        let mut to_hub = guest.try_clone().unwrap();
        let session = thread::spawn(move || to_hub.write_all(&vec![b'x'; PRINTED]).unwrap());
        session.join().unwrap();
        wait_until("all of it in", || hub.received() == PRINTED as u64);
        assert_eq!(slow.end(), Some(End::Slow));
        let kept = read_to_end(&slow).len();
        assert!(kept > 0 && kept <= BACKLOG_MAX, "{kept}");
        assert_eq!(hub.clients(), 1);

        // A client that attaches now gets the session's output.
        let (_, late, _) = hub.attach(Mode::Ro, 0);
        guest.write_all(b"after").unwrap();
        assert_eq!(read_n(&late, 5), b"after");
        guest.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            reader.join().unwrap(),
            (PRINTED + 5, Some(End::SessionEnded))
        );
    }

    /// Only a read-write client gets an input; what it sends reaches the
    /// session.
    #[test]
    fn input_from_an_ro_client_is_refused() {
        let fixture = Fixture::new();
        let mut guest = fixture.guest();
        let (_, _, none) = fixture.hub.attach(Mode::Ro, 0);
        assert!(none.is_none());
        let (_, _, input) = fixture.hub.attach(Mode::Rw, 0);
        let input = input.expect("a read-write client's input");
        assert_eq!(input.send(b"ls\r").unwrap(), 3);
        let mut got = [0u8; 3];
        guest.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ls\r");
    }

    /// A size goes to init once per change, the latest asked for winning:
    /// asking for the size the terminal has sends nothing.
    #[test]
    fn resize_is_forwarded_once_per_change() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut init = fixture.init();
        let _guest = fixture.guest();
        wait_until("the terminal open", || hub.state() == PtyState::Live);
        // The header's size: nothing to send.
        hub.resize(24, 80).unwrap();
        hub.resize(40, 120).unwrap();
        hub.resize(40, 120).unwrap();
        hub.resize(24, 80).unwrap();
        hub.resize(40, 120).unwrap();
        let ping = fixture.handle.guest_ctl().ping().unwrap();
        let mut got = Vec::new();
        loop {
            match init.recv() {
                HostMsg::Ping { id } if id == ping => break,
                msg => got.push(msg),
            }
        }
        let resize = |rows, cols| HostMsg::Resize { rows, cols };
        assert_eq!(
            got,
            [resize(40, 120), resize(24, 80), resize(40, 120)],
            "{got:?}"
        );
    }

    /// A size asked for before init has opened the terminal is sent once it
    /// has, unless it is the size the terminal opened with.
    #[test]
    fn a_resize_before_the_terminal_opens_is_sent_when_it_does() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut init = fixture.init();
        hub.resize(40, 120).unwrap();
        hub.resize(30, 100).unwrap();
        assert_eq!(hub.state(), PtyState::Waiting);
        let _guest = fixture.guest();
        assert_eq!(
            init.recv(),
            HostMsg::Resize {
                rows: 30,
                cols: 100
            }
        );

        let fixture = Fixture::new();
        let mut init = fixture.init();
        fixture.hub.resize(24, 80).unwrap();
        let _guest = fixture.guest();
        wait_until("the terminal open", || {
            fixture.hub.state() == PtyState::Live
        });
        let ping = fixture.handle.guest_ctl().ping().unwrap();
        assert_eq!(init.recv(), HostMsg::Ping { id: ping });
    }

    /// Once the guest closes its side, the hub closes its own (init waits
    /// for that before it reboots); a client that attaches later gets its
    /// replay, then the end at once, and cannot type.
    #[test]
    fn late_attach_after_guest_eof_gets_replay_then_eof() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut guest = fixture.guest();
        let (_, before, _) = hub.attach(Mode::Ro, 0);
        guest.write_all(b"last words").unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        guest.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        assert_eq!(read_to_end(&before), b"last words");
        assert_eq!(before.end(), Some(End::SessionEnded));
        assert_eq!(hub.state(), PtyState::Ended);

        let (_, late, input) = hub.attach(Mode::Rw, 1024);
        assert_eq!(read_to_end(&late), b"last words");
        assert_eq!(late.end(), Some(End::SessionEnded));
        assert!(input.unwrap().send(b"x").is_err());
        assert_eq!(hub.clients(), 0);
        // One connection in the VMM's life.
        assert_eq!(
            fixture
                .handle
                .services()
                .connect(1025, ConnMeta { guest_port: 1022 })
                .err(),
            Some(Deny::Refused("reactivated"))
        );
    }

    /// The input queue holds at most [`INPUT_MAX`] bytes: what does not fit
    /// is dropped and counted, at once, never waited for.
    #[test]
    fn input_queue_is_bounded() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let (_, _, input) = hub.attach(Mode::Rw, 0);
        let input = input.unwrap();
        let typed = pattern(100 * 1024);
        // The terminal is not open yet: nothing drains the queue.
        let started = Instant::now();
        assert_eq!(input.send(&typed).unwrap(), INPUT_MAX);
        assert_eq!(input.send(b"more").unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(hub.input_dropped(), (typed.len() - INPUT_MAX + 4) as u64);
        // Once it opens, the session gets what was queued, in order.
        let mut guest = fixture.guest();
        let mut got = vec![0u8; INPUT_MAX];
        guest.read_exact(&mut got).unwrap();
        assert!(got == typed[..INPUT_MAX], "not the first {INPUT_MAX} bytes");
        guest
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut more = [0u8; 1];
        assert!(guest.read(&mut more).is_err(), "{more:?}");
        // With room again, input is taken.
        assert_eq!(input.send(b"ok").unwrap(), 2);
        guest.set_read_timeout(Some(LIMIT)).unwrap();
        let mut ok = [0u8; 2];
        guest.read_exact(&mut ok).unwrap();
        assert_eq!(&ok, b"ok");
    }

    /// A client that detaches ends its output; the others go on.
    #[test]
    fn a_detached_client_ends_and_the_others_go_on() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut guest = fixture.guest();
        let (gone, leaving, input) = hub.attach(Mode::Rw, 0);
        let (_, staying, _) = hub.attach(Mode::Ro, 0);
        hub.detach(gone);
        hub.detach(gone);
        assert_eq!(read_to_end(&leaving), b"");
        assert_eq!(leaving.end(), Some(End::Detached));
        assert!(input.unwrap().send(b"x").is_err());
        guest.write_all(b"still here").unwrap();
        assert_eq!(read_n(&staying, 10), b"still here");
        assert_eq!(hub.clients(), 1);
    }

    /// A connection that came while the hub could not be set up is refused
    /// as `no_service`, and the next is taken; only after that is one
    /// `reactivated`.
    #[test]
    fn a_failed_setup_leaves_the_port_to_the_next_connection() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let meta = ConnMeta { guest_port: 1022 };
        let no_fds = || Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        assert_eq!(hub.connect(meta, no_fds).err(), Some(Deny::NoService));
        assert_eq!(hub.state(), PtyState::Waiting);
        let stream = hub.connect(meta, UnixStream::pair).unwrap();
        assert_eq!(
            hub.connect(meta, UnixStream::pair).err(),
            Some(Deny::Refused("reactivated"))
        );
        drop(stream);
    }

    /// A stream that does not start with a header line is closed, and the
    /// session's terminal is over: clients end rather than wait.
    #[test]
    fn a_stream_without_a_header_line_is_closed() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let (_, output, _) = hub.attach(Mode::Ro, 0);
        let mut stream = fixture
            .handle
            .services()
            .connect(1025, ConnMeta { guest_port: 1022 })
            .unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        stream.write_all(b"not a header\nhi").unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        assert_eq!(read_to_end(&output), b"");
        assert_eq!(hub.state(), PtyState::Ended);
    }

    /// The stop sequence closes the hub's stream: its clients end.
    #[test]
    fn closing_the_hub_ends_its_clients() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut guest = fixture.guest();
        let (_, output, _) = hub.attach(Mode::Ro, 0);
        guest.write_all(b"partway").unwrap();
        assert_eq!(read_n(&output, 7), b"partway");
        hub.close();
        assert_eq!(read_to_end(&output), b"");
        assert!(hub.wait_ended(LIMIT));
        assert_eq!(hub.state(), PtyState::Ended);
    }
}
