// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! One control connection, on a thread of its own: the hello, line framing
//! with the [`MAX_LINE`] cap, the rate limit, and dispatch to [`Ops`].
//!
//! The socket is non-blocking and the thread polls it together with an
//! eventfd that wakes it. Nothing it writes ever blocks: every line goes
//! into the connection's outbox and is sent as far as the socket takes it,
//! the rest when the socket is writable again. So the server can queue an
//! event on any connection from another thread, and shut every connection
//! down, without waiting on a client. A client that leaves more than
//! [`OUTBOX_MAX`] bytes unread is cut off.
//!
//! The one thing that waits for the client is a stream the connection
//! forwards from another thread, the audit subscription: it queues through
//! [`Conn::send_paced`], which waits while the client has [`PACE_HIGH_WATER`]
//! bytes or more unread, so that a replay of a long log goes at the pace of
//! the client and never reaches [`OUTBOX_MAX`]. A client that takes no byte
//! for the stall limit is cut off instead of waited for for ever.
//!
//! Lines are read in chunks into a buffer that grows only as far as the
//! cap: a line longer than [`MAX_LINE`] is refused with `bad_request` as
//! soon as the cap is passed, and the connection is closed without reading
//! the rest. A line that is not a request is answered with an error and the
//! connection stays open. Each connection may make [`RATE_PER_SEC`]
//! requests a second, in bursts of up to [`BURST`]; a request over that
//! budget is answered `rate_limited` and dropped.

use std::io::{self, Read};
use std::mem;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use boxcar_audit::{AuditSink, Priority, Submission};
use boxcar_proto::control::{
    parse_request, to_line, ErrorBody, ErrorCode, Hello, Request, Response, StateEvent, StopParams,
    VmState, MAX_LINE,
};
use boxcar_proto::{ControlStop, Payload, Ring};
use serde::Serialize;
use serde_json::Value;
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

use super::ops::{ConnCtx, Ops, RawUpgrade};

/// Requests a connection may make per second, on average.
pub(crate) const RATE_PER_SEC: f64 = 100.0;
/// Requests a connection may make at once.
pub(crate) const BURST: f64 = 100.0;
/// The most bytes a connection may leave unread before it is cut off: room
/// for two responses of the largest size.
pub(crate) const OUTBOX_MAX: usize = 2 * (MAX_LINE + 1);
/// How many unread bytes make [`Conn::send_paced`] wait: half the cap, so
/// that what other threads queue meanwhile (responses, events) still fits.
pub(crate) const PACE_HIGH_WATER: usize = OUTBOX_MAX / 2;
/// How long [`Conn::send_paced`] waits for a client that takes no byte
/// before it cuts the client off.
pub(crate) const PACE_STALL: Duration = Duration::from_secs(30);
/// The longest [`Conn::send_paced`] sleeps between looks at the connection:
/// a connection that closes wakes no one that waits on the outbox's lock.
const PACE_TICK: Duration = Duration::from_millis(100);
/// How much is read from the socket at a time.
const READ_CHUNK: usize = 64 * 1024;
/// The longest line over the rate budget whose id is still read for its
/// `rate_limited` response: any ordinary request, and nothing that costs
/// a real parse.
const RATE_LIMITED_ID_MAX: usize = 4096;
/// How long a connection the server closes (a line over the cap) gets to
/// take what it was sent, such as the error that says why.
const LINGER: Duration = Duration::from_secs(1);

/// A connection's socket and what is waiting to be sent on it.
pub(crate) struct Conn {
    stream: UnixStream,
    /// Wakes the connection's thread: output is waiting, or it must close.
    wake: EventFd,
    out: Mutex<Outbox>,
    /// Signalled when the client takes bytes, for [`Conn::send_paced`].
    drained: Condvar,
    closing: AtomicBool,
}

/// The bytes a connection has not sent yet, whole lines only.
#[derive(Default)]
struct Outbox {
    buf: Vec<u8>,
    /// How much of `buf` is sent.
    sent: usize,
    /// Every byte the connection has sent, over its whole life.
    taken: u64,
    /// The last state event queued, so none is sent twice.
    state: Option<VmState>,
    /// The connection is a raw byte stream now: no more lines.
    raw: bool,
}

impl Outbox {
    fn pending(&self) -> usize {
        self.buf.len() - self.sent
    }
}

impl Conn {
    /// Takes `stream`, makes it non-blocking, and queues `hello` as its
    /// first line, before the connection is published to the server or
    /// its thread starts, so nothing the server sends can come before it.
    pub(crate) fn new(stream: UnixStream, hello: &Hello) -> io::Result<Conn> {
        stream.set_nonblocking(true)?;
        let conn = Conn {
            stream,
            wake: EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)?,
            out: Mutex::new(Outbox::default()),
            drained: Condvar::new(),
            closing: AtomicBool::new(false),
        };
        {
            let mut out = conn.lock();
            conn.queue(&mut out, hello);
            conn.flush(&mut out);
        }
        Ok(conn)
    }

    fn lock(&self) -> MutexGuard<'_, Outbox> {
        self.out.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `message` as a line and sends what the socket takes now.
    fn send<T: Serialize>(&self, message: &T) {
        let mut out = self.lock();
        self.queue(&mut out, message);
        self.flush(&mut out);
    }

    /// Queues `message` as a line, unless the connection is raw. A client
    /// that has left [`OUTBOX_MAX`] bytes unread is cut off instead.
    fn queue<T: Serialize>(&self, out: &mut Outbox, message: &T) {
        match to_line(message) {
            Ok(line) => self.queue_line(out, &line),
            Err(error) => tracing::error!("control: cannot send a message: {error}"),
        }
    }

    fn queue_line(&self, out: &mut Outbox, line: &[u8]) {
        if out.raw {
            return;
        }
        if out.pending() + line.len() > OUTBOX_MAX {
            tracing::debug!(
                "control: a client left {} bytes unread; closing",
                out.pending()
            );
            self.close();
            return;
        }
        out.buf.extend_from_slice(line);
    }

    /// Queues the state event for `state` unless one for it, or for a later
    /// state, was queued already, and sends what the socket takes. Called
    /// from outside the connection's thread, which it wakes to send the
    /// rest.
    pub(crate) fn send_state(&self, state: VmState) {
        let mut out = self.lock();
        self.queue_state(&mut out, state);
        self.flush(&mut out);
        if out.pending() > 0 {
            self.wake();
        }
    }

    /// Queues `event` as a line, from outside the connection's thread,
    /// without sending anything here: the connection's thread, woken, sends
    /// it. Never waits (`pty.detached` for a watched attach).
    pub(crate) fn send_event<T: Serialize>(&self, event: &T) {
        {
            let mut out = self.lock();
            self.queue(&mut out, event);
        }
        self.wake();
    }

    /// Queues `message` as a line from outside the connection's thread, as
    /// [`send_event`](Self::send_event) does, but first waits while the
    /// client has [`PACE_HIGH_WATER`] bytes or more unread, for a stream
    /// that is forwarded from another thread and is rather late than lost.
    /// Returns whether the line was queued: `false` when the connection
    /// is closing (or raw), or when the client took no byte for `stall` and
    /// was cut off (it reconnects and asks for what it missed), or the
    /// message cannot be a line.
    pub(crate) fn send_paced<T: Serialize>(&self, message: &T, stall: Duration) -> bool {
        let line = match to_line(message) {
            Ok(line) => line,
            Err(error) => {
                // Dropping it would leave a hole in the stream.
                tracing::error!("control: cannot send a message: {error}; closing");
                self.close();
                return false;
            }
        };
        let mut out = self.lock();
        let mut progress = (out.taken, Instant::now());
        loop {
            if self.is_closing() || out.raw {
                return false;
            }
            // An empty outbox takes any line: they all fit the cap.
            if out.pending() == 0 || out.pending() + line.len() <= PACE_HIGH_WATER {
                break;
            }
            if out.taken != progress.0 {
                progress = (out.taken, Instant::now());
            }
            let left = stall.saturating_sub(progress.1.elapsed());
            if left.is_zero() {
                drop(out);
                tracing::debug!("control: a client took nothing for {stall:?}; closing");
                self.close();
                return false;
            }
            out = self
                .drained
                .wait_timeout(out, left.min(PACE_TICK))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        self.queue_line(&mut out, &line);
        self.flush(&mut out);
        if out.pending() > 0 {
            self.wake();
        }
        true
    }

    fn queue_state(&self, out: &mut Outbox, state: VmState) {
        if out.raw || out.state.is_some_and(|sent| sent >= state) {
            return;
        }
        out.state = Some(state);
        self.queue(out, &StateEvent::new(state));
    }

    /// Sends what the socket takes without waiting; the connection's thread
    /// sends the rest when the socket is writable. A failed send closes the
    /// connection.
    fn flush(&self, out: &mut Outbox) {
        while out.sent < out.buf.len() {
            match send_nowait(self.stream.as_raw_fd(), &out.buf[out.sent..]) {
                Ok(n) => {
                    out.sent += n;
                    out.taken += n as u64;
                    self.drained.notify_all();
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::debug!("control: send failed: {e}");
                    out.buf.clear();
                    out.sent = 0;
                    self.close();
                    return;
                }
            }
        }
        if out.sent == out.buf.len() {
            out.buf.clear();
            out.sent = 0;
        } else if out.sent > out.buf.len() / 2 {
            out.buf.drain(..out.sent);
            out.sent = 0;
        }
    }

    #[cfg(test)]
    pub(crate) fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    fn wake(&self) {
        if let Err(error) = self.wake.write(1) {
            tracing::warn!("control: cannot wake a connection: {error}");
        }
    }

    /// Ends the connection: the socket is shut down both ways, which ends
    /// any read or write on it, and the thread is woken to notice.
    pub(crate) fn close(&self) {
        self.closing.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
        self.wake();
        self.drained.notify_all();
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// Waits up to [`LINGER`] for the client to take what is queued,
    /// unless the connection is closed first.
    fn linger(&self) {
        let deadline = Instant::now() + LINGER;
        loop {
            {
                let mut out = self.lock();
                self.flush(&mut out);
                if out.pending() == 0 {
                    return;
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if self.is_closing() || left.is_zero() {
                return;
            }
            if poll_two(
                self.stream.as_raw_fd(),
                libc::POLLOUT,
                &self.wake,
                Some(left),
            )
            .is_err()
            {
                return;
            }
            let _ = self.wake.read();
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

/// Polls `fd` for `events` and `wake` for input, for up to `timeout`
/// (forever when `None`). Returns `fd`'s returned events; 0 on a timeout.
pub(crate) fn poll_two(
    fd: RawFd,
    events: libc::c_short,
    wake: &EventFd,
    timeout: Option<Duration>,
) -> io::Result<libc::c_short> {
    let mut fds = [
        libc::pollfd {
            fd,
            events,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = timeout.map_or(-1, |t| {
        // Rounded up, so a short wait is not a busy loop.
        libc::c_int::try_from(t.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX)
    });
    loop {
        // SAFETY: `fds` is an array of two initialized pollfds.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if ret >= 0 {
            return Ok(fds[0].revents);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A token bucket: [`RATE_PER_SEC`] tokens a second, at most [`BURST`].
#[derive(Debug)]
pub(crate) struct RateLimit {
    tokens: f64,
    last: Instant,
}

impl RateLimit {
    pub(crate) fn new(now: Instant) -> RateLimit {
        RateLimit {
            tokens: BURST,
            last: now,
        }
    }

    /// Whether a request at `now` is within the budget; takes a token if so.
    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * RATE_PER_SEC).min(BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// What the connection does after a line.
enum Flow {
    Continue,
    /// Close, after letting the client take what it was sent.
    Close,
    /// Hand the socket over, with the bytes read past the request.
    Upgrade(RawUpgrade, Vec<u8>),
}

/// Everything one connection's thread works with.
pub(crate) struct Session {
    pub(crate) conn: Arc<Conn>,
    pub(crate) ctx: ConnCtx,
    pub(crate) ops: Arc<dyn Ops>,
    pub(crate) audit: AuditSink,
}

impl Session {
    /// Serves the connection until the client goes, the line cap is
    /// passed, an op takes the socket over, or the server closes it.
    pub(crate) fn serve(mut self) {
        let mut reader = LineReader::new();
        let mut limit = RateLimit::new(Instant::now());
        let mut chunk = vec![0u8; READ_CHUNK];
        // The hello is in the outbox already (`Conn::new`): the first pass
        // polls for output and sends what the socket did not take then.
        let flow = loop {
            if self.conn.is_closing() {
                break Flow::Continue;
            }
            let events = if self.conn.lock().pending() > 0 {
                libc::POLLIN | libc::POLLOUT
            } else {
                libc::POLLIN
            };
            if let Err(error) =
                poll_two(self.conn.stream.as_raw_fd(), events, &self.conn.wake, None)
            {
                tracing::warn!("control: poll failed: {error}");
                break Flow::Continue;
            }
            let _ = self.conn.wake.read();
            {
                let mut out = self.conn.lock();
                self.conn.flush(&mut out);
            }
            match self.read(&mut chunk, &mut reader, &mut limit) {
                Ok(Flow::Continue) => {}
                Ok(flow) => break flow,
                Err(error) => {
                    if error.kind() != io::ErrorKind::UnexpectedEof {
                        tracing::debug!("control: read failed: {error}");
                    }
                    break Flow::Continue;
                }
            }
        };
        match flow {
            Flow::Continue => {}
            Flow::Close => self.conn.linger(),
            Flow::Upgrade(upgrade, pending) => self.upgrade(upgrade, pending),
        }
        // Closing, not just shutting the socket down: what forwards a stream
        // into this connection from another thread (the audit
        // subscriptions) stops when it sees it, and is joined as `self.ctx`
        // drops.
        self.conn.close();
    }

    /// Reads what the socket has and handles each complete line. EOF is an
    /// `UnexpectedEof` error.
    fn read(
        &mut self,
        chunk: &mut [u8],
        reader: &mut LineReader,
        limit: &mut RateLimit,
    ) -> io::Result<Flow> {
        loop {
            let n = match (&self.conn.stream).read(chunk) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Flow::Continue),
                Err(e) => return Err(e),
            };
            let mut bytes = &chunk[..n];
            while let Some(step) = reader.next(&mut bytes) {
                let flow = match step {
                    Step::Line(line) => self.line(&line, limit),
                    Step::TooLong => {
                        tracing::debug!("control: a line over {MAX_LINE} bytes; closing");
                        let error = ErrorBody::new(
                            ErrorCode::BadRequest,
                            format!("the line is over {MAX_LINE} bytes; closing"),
                        );
                        self.conn.send(&Response::failure(0, error));
                        Flow::Close
                    }
                };
                match flow {
                    Flow::Continue => {}
                    Flow::Upgrade(upgrade, _) => {
                        return Ok(Flow::Upgrade(upgrade, reader.take_rest(bytes)))
                    }
                    Flow::Close => return Ok(Flow::Close),
                }
            }
        }
    }

    /// Handles one line: a request within the budget is served, anything
    /// else answered with an error. Blank lines are skipped. The budget is
    /// checked before the line is parsed, so a flood of long lines costs no
    /// parsing; a line over it is answered `rate_limited` with its id when
    /// it is short enough to read cheaply ([`RATE_LIMITED_ID_MAX`]), 0
    /// otherwise.
    fn line(&mut self, line: &[u8], limit: &mut RateLimit) -> Flow {
        if line.iter().all(u8::is_ascii_whitespace) {
            return Flow::Continue;
        }
        if !limit.allow(Instant::now()) {
            let id = if line.len() <= RATE_LIMITED_ID_MAX {
                match parse_request(line) {
                    Ok(request) => request.id,
                    Err(error) => error.id.unwrap_or(0),
                }
            } else {
                0
            };
            let error = ErrorBody::new(
                ErrorCode::RateLimited,
                format!("over {RATE_PER_SEC} requests a second; the request was dropped"),
            );
            self.conn.send(&Response::failure(id, error));
            return Flow::Continue;
        }
        let request = match parse_request(line) {
            Ok(request) => request,
            Err(error) => {
                self.conn.send(&error.into_response());
                return Flow::Continue;
            }
        };
        match request.op.as_str() {
            "status" => {
                let result = serde_json::to_value(self.ops.status()).map_err(|error| {
                    ErrorBody::new(ErrorCode::Internal, format!("status: {error}"))
                });
                self.respond(request.id, result);
                Flow::Continue
            }
            "stop" => {
                self.stop(&request);
                Flow::Continue
            }
            _ => {
                let result = self.ops.dispatch(&mut self.ctx, &request);
                let upgrade = self.ctx.raw_upgrade.take();
                match (result, upgrade) {
                    (Ok(value), Some(upgrade)) => {
                        // The response, then raw, under one outbox lock: no
                        // event can be queued between the two, where the
                        // client would read it as raw bytes.
                        let mut out = self.conn.lock();
                        self.conn.queue(&mut out, &response(request.id, Ok(value)));
                        out.raw = true;
                        self.conn.flush(&mut out);
                        Flow::Upgrade(upgrade, Vec::new())
                    }
                    (result, _) => {
                        self.respond(request.id, result);
                        // Streams the op started begin only now, so that
                        // nothing of them comes before the response.
                        self.ctx.audit.release();
                        Flow::Continue
                    }
                }
            }
        }
    }

    /// `stop`: recorded as `control.stop`, then the response and, when the
    /// stop was accepted, `stopping`. The outbox stays locked from before
    /// the stop to after both lines are queued, so a `stopping` the server
    /// sends every client because of this stop comes after the response,
    /// and only once.
    fn stop(&self, request: &Request) {
        let params: StopParams = match serde_json::from_value(request.params.clone()) {
            Ok(params) => params,
            Err(error) => {
                let error =
                    ErrorBody::new(ErrorCode::BadRequest, format!("stop parameters: {error}"));
                self.conn.send(&Response::failure(request.id, error));
                return;
            }
        };
        record(
            &self.audit,
            Payload::ControlStop(ControlStop {
                by_pid: self.ctx.peer_pid,
                mode: params.mode,
            }),
        );
        let mut out = self.conn.lock();
        let result = self.ops.stop(params);
        let accepted = result.is_ok();
        self.conn.queue(&mut out, &response(request.id, result));
        if accepted {
            self.conn.queue_state(&mut out, VmState::Stopping);
        }
        self.conn.flush(&mut out);
    }

    fn respond(&self, id: u64, result: Result<Value, ErrorBody>) {
        self.conn.send(&response(id, result));
    }

    /// Sends the response that came before the upgrade, then runs the
    /// handler on the socket. The server can still shut it down.
    fn upgrade(&self, upgrade: RawUpgrade, pending: Vec<u8>) {
        self.conn.linger();
        {
            let mut out = self.conn.lock();
            out.raw = true;
            if out.pending() > 0 || self.conn.is_closing() {
                return;
            }
        }
        let stream = match self.conn.stream.try_clone() {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!("control: cannot hand a connection over: {error}");
                return;
            }
        };
        if let Err(error) = stream.set_nonblocking(false) {
            tracing::warn!("control: cannot hand a connection over: {error}");
            return;
        }
        upgrade.run(stream, pending);
    }
}

/// The response for `result`; one too large to send becomes an `internal`
/// error.
fn response(id: u64, result: Result<Value, ErrorBody>) -> Response {
    let response = match result {
        Ok(value) => Response::success(id, value),
        Err(error) => Response::failure(id, error),
    };
    match to_line(&response) {
        Ok(_) => response,
        Err(error) => Response::failure(
            id,
            ErrorBody::new(ErrorCode::Internal, format!("the response: {error}")),
        ),
    }
}

/// Emits a control record. One that cannot be recorded is logged: the
/// writer has failed or closed, and the VM is stopping either way.
pub(crate) fn record(audit: &AuditSink, payload: Payload) {
    let kind = payload.kind();
    let submission = Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload,
        span: None,
        priority: Priority::Normal,
    };
    if let Err(error) = audit.emit(submission) {
        tracing::warn!("cannot record {kind}: {error}");
    }
}

/// What [`LineReader::next`] found.
#[derive(Debug, PartialEq)]
enum Step {
    Line(Vec<u8>),
    /// The line passed [`MAX_LINE`] bytes.
    TooLong,
}

/// Splits a byte stream into lines of at most [`MAX_LINE`] bytes, not
/// counting the newline, holding at most that much of a partial line.
#[derive(Debug, Default)]
struct LineReader {
    partial: Vec<u8>,
}

impl LineReader {
    fn new() -> LineReader {
        LineReader::default()
    }

    /// The next complete line from what is left of `bytes`, consuming it,
    /// or `None` once `bytes` is used up (a partial line is kept for the
    /// next call). `TooLong` as soon as a line passes the cap.
    fn next(&mut self, bytes: &mut &[u8]) -> Option<Step> {
        if bytes.is_empty() {
            return None;
        }
        match bytes.iter().position(|&b| b == b'\n') {
            Some(end) => {
                if self.partial.len() + end > MAX_LINE {
                    return Some(Step::TooLong);
                }
                let mut line = mem::take(&mut self.partial);
                line.extend_from_slice(&bytes[..end]);
                *bytes = &bytes[end + 1..];
                Some(Step::Line(line))
            }
            None => {
                if self.partial.len() + bytes.len() > MAX_LINE {
                    return Some(Step::TooLong);
                }
                self.partial.extend_from_slice(bytes);
                *bytes = &[];
                None
            }
        }
    }

    /// The bytes after the last complete line: the partial line and what
    /// is left of `bytes`.
    fn take_rest(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut rest = mem::take(&mut self.partial);
        rest.extend_from_slice(bytes);
        rest
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use serde_json::json;

    use super::*;

    /// The lines a client reads from `stream` until the server closes it.
    fn lines(stream: UnixStream) -> Vec<Value> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        BufReader::new(stream)
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect()
    }

    /// The hello is queued when the connection is made, before the server
    /// can reach it, so a state event sent before the connection's thread
    /// runs, or the server closing it then, still comes after the hello.
    #[test]
    fn the_hello_comes_before_an_event_sent_before_serve_runs() {
        let hello = Hello::new("boxcar/test", "s", Vec::new());
        let (server, client) = UnixStream::pair().unwrap();
        let conn = Conn::new(server, &hello).unwrap();
        conn.send_state(VmState::Stopping);
        conn.send_state(VmState::Stopped);
        conn.close();
        let got = lines(client);
        assert_eq!(
            got,
            [
                serde_json::to_value(&hello).unwrap(),
                json!({"v": 1, "event": "state", "state": "stopping"}),
                json!({"v": 1, "event": "state", "state": "stopped"}),
            ]
        );
    }

    /// Ops for a session whose requests never get past the rate limit.
    struct Unreached;

    impl Ops for Unreached {
        fn status(&self) -> boxcar_proto::control::Status {
            unreachable!("over the budget")
        }

        fn stop(&self, _: StopParams) -> Result<Value, ErrorBody> {
            unreachable!("over the budget")
        }

        fn dispatch(&self, _: &mut ConnCtx, _: &Request) -> Result<Value, ErrorBody> {
            unreachable!("over the budget")
        }
    }

    /// Over the budget, a line is answered before it is parsed: a long one
    /// with id 0, since reading its id would mean parsing it, a short one
    /// with its own id. Neither reaches the ops.
    #[test]
    fn a_line_over_the_budget_is_refused_before_it_is_parsed() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = crate::lifecycle::test_handle(tmp.path());
        let (server, client) = UnixStream::pair().unwrap();
        let hello = Hello::new("boxcar/test", "s", Vec::new());
        let mut session = Session {
            conn: Arc::new(Conn::new(server, &hello).unwrap()),
            ctx: ConnCtx::new(1, 0),
            ops: Arc::new(Unreached),
            audit: handle.audit().clone(),
        };
        // No tokens, and none coming: `last` is in the future.
        let mut spent = RateLimit {
            tokens: 0.0,
            last: Instant::now() + Duration::from_secs(3600),
        };
        let pad = "x".repeat(RATE_LIMITED_ID_MAX);
        let long =
            serde_json::to_vec(&json!({"v": 1, "id": 500, "op": "status", "p": pad})).unwrap();
        let short = br#"{"v":1,"id":501,"op":"status"}"#;
        assert!(matches!(session.line(&long, &mut spent), Flow::Continue));
        assert!(matches!(session.line(short, &mut spent), Flow::Continue));
        session.conn.close();

        let got = lines(client);
        assert_eq!(got[0]["event"], "hello");
        let refused: Vec<(u64, &Value)> = got[1..]
            .iter()
            .map(|r| (r["id"].as_u64().unwrap(), &r["error"]["code"]))
            .collect();
        assert_eq!(
            refused,
            [(0, &json!("rate_limited")), (501, &json!("rate_limited"))]
        );
        assert_eq!(
            got[2]["error"]["message"],
            "over 100 requests a second; the request was dropped"
        );
        writer.close().unwrap();
    }

    /// Ops whose `raw` upgrades the connection.
    struct Upgrading;

    impl Ops for Upgrading {
        fn status(&self) -> boxcar_proto::control::Status {
            unreachable!("not asked")
        }

        fn stop(&self, _: StopParams) -> Result<Value, ErrorBody> {
            unreachable!("not asked")
        }

        fn dispatch(&self, conn: &mut ConnCtx, _: &Request) -> Result<Value, ErrorBody> {
            conn.raw_upgrade = Some(RawUpgrade::new(|_, _| {}));
            Ok(json!({"raw": true}))
        }
    }

    /// The connection is raw from the moment the upgrading response is
    /// queued, under the same lock: a state event sent before the handler
    /// takes over is not queued behind the response, where the client
    /// would read it as raw bytes.
    #[test]
    fn no_event_comes_between_an_upgrading_response_and_the_raw_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = crate::lifecycle::test_handle(tmp.path());
        let (server, client) = UnixStream::pair().unwrap();
        let hello = Hello::new("boxcar/test", "s", Vec::new());
        let mut session = Session {
            conn: Arc::new(Conn::new(server, &hello).unwrap()),
            ctx: ConnCtx::new(1, 0),
            ops: Arc::new(Upgrading),
            audit: handle.audit().clone(),
        };
        let mut limit = RateLimit::new(Instant::now());
        let flow = session.line(br#"{"v":1,"id":7,"op":"raw"}"#, &mut limit);
        assert!(matches!(flow, Flow::Upgrade(..)));
        session.conn.send_state(VmState::Stopping);
        session.conn.close();
        let got = lines(client);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[1]["result"], json!({"raw": true}));
        writer.close().unwrap();
    }

    /// A connection with its thread serving it (`Unreached` ops: it reads
    /// no request), and the client's end.
    struct Served {
        conn: Arc<Conn>,
        client: UnixStream,
        thread: Option<std::thread::JoinHandle<()>>,
        // Keeps the audit writer the session holds a sink of.
        _tmp: tempfile::TempDir,
        writer: Option<boxcar_audit::WriterHandle>,
    }

    impl Served {
        fn new() -> Served {
            let tmp = tempfile::tempdir().unwrap();
            let (handle, writer) = crate::lifecycle::test_handle(tmp.path());
            let (server, client) = UnixStream::pair().unwrap();
            let hello = Hello::new("boxcar/test", "s", Vec::new());
            let conn = Arc::new(Conn::new(server, &hello).unwrap());
            let session = Session {
                conn: conn.clone(),
                ctx: ConnCtx::new(1, 0),
                ops: Arc::new(Unreached),
                audit: handle.audit().clone(),
            };
            let thread = std::thread::spawn(move || session.serve());
            Served {
                conn,
                client,
                thread: Some(thread),
                _tmp: tmp,
                writer: Some(writer),
            }
        }

        /// The connection's thread has ended.
        fn ended(&mut self) {
            self.thread.take().unwrap().join().unwrap();
        }
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.conn.close();
            if let Some(writer) = self.writer.take() {
                let _ = writer.close();
            }
        }
    }

    /// An event line of about `len` bytes, numbered `n`.
    fn numbered(n: u64, len: usize) -> Value {
        json!({"v": 1, "event": "x", "n": n, "pad": "p".repeat(len)})
    }

    /// What is queued the ordinary way (a response, an event) is never
    /// waited for: past the outbox's cap, a client that has not read it is
    /// cut off, and the outbox never holds more than the cap.
    #[test]
    fn outbox_cap_closes_a_slow_subscriber_connection() {
        let hello = Hello::new("boxcar/test", "s", Vec::new());
        let (server, client) = UnixStream::pair().unwrap();
        let conn = Conn::new(server, &hello).unwrap();
        // No thread serves this connection, so nothing is ever sent: every
        // byte queued stays in the outbox.
        let line = to_line(&numbered(0, 60 * 1024)).unwrap().len();
        let mut queued = 0;
        while !conn.is_closing() {
            conn.send_event(&numbered(queued, 60 * 1024));
            queued += 1;
            assert!(conn.lock().pending() <= OUTBOX_MAX);
            assert!(queued <= (OUTBOX_MAX / line) as u64 + 2, "never cut off");
        }
        // The one that would pass the cap was not queued.
        assert_eq!(queued as usize, OUTBOX_MAX / line + 1, "{line}");
        // What it was sent before is all it gets, then the end.
        let got = lines(client);
        assert_eq!(got.len(), 1, "only the hello, which was sent at once");
    }

    /// A paced stream (`send_paced`) goes at the client's own speed: while
    /// the client reads nothing the producer waits, with the outbox under
    /// the high-water mark; once it reads, every line arrives, in order,
    /// and the connection is not cut off.
    #[test]
    fn a_paced_stream_goes_at_the_clients_pace() {
        const LINES: u64 = 300;
        const LEN: usize = 24 * 1024;
        let served = Served::new();
        let producer = std::thread::spawn({
            let conn = served.conn.clone();
            move || {
                for n in 0..LINES {
                    assert!(conn.send_paced(&numbered(n, LEN), Duration::from_secs(20)));
                }
            }
        });
        // The client reads nothing: the socket fills, then the outbox,
        // up to the mark, and there the producer waits.
        let started = Instant::now();
        while served.conn.lock().pending() <= PACE_HIGH_WATER / 2 {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "never backed up"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        for _ in 0..50 {
            assert!(served.conn.lock().pending() <= PACE_HIGH_WATER);
            std::thread::sleep(Duration::from_millis(4));
        }
        assert!(!producer.is_finished(), "it should be waiting");

        // Now it reads, slowly, and gets every line.
        let mut reader = std::io::BufReader::new(served.client.try_clone().unwrap());
        reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut hello = String::new();
        reader.read_line(&mut hello).unwrap();
        for n in 0..LINES {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let got: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(got["n"], n);
            if n % 16 == 0 {
                assert!(served.conn.lock().pending() <= PACE_HIGH_WATER);
            }
        }
        producer.join().unwrap();
        assert!(!served.conn.is_closing());
    }

    /// A paced stream does not wait for ever for a client that takes
    /// nothing: after the stall limit it cuts the client off and says so,
    /// with the outbox never past the high-water mark, and the
    /// connection's thread ends.
    #[test]
    fn a_paced_stream_cuts_off_a_client_that_takes_nothing() {
        let mut served = Served::new();
        let stall = Duration::from_millis(300);
        let started = Instant::now();
        let mut sent = 0;
        while served.conn.send_paced(&numbered(sent, 16 * 1024), stall) {
            sent += 1;
            assert!(served.conn.lock().pending() <= PACE_HIGH_WATER);
            assert!(sent < 1000, "never cut off");
        }
        let waited = started.elapsed();
        assert!(waited >= stall, "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        assert!(served.conn.is_closing());
        // More than the high-water mark went out (the socket's own buffer
        // holds some), and less than it and the socket's buffers can hold.
        assert!(sent as usize * 16 * 1024 > PACE_HIGH_WATER);
        // Nothing more is taken once it is closed.
        assert!(!served.conn.send_paced(&numbered(0, 1), stall));
        served.ended();
        // The client reads what it was sent, then the end.
        let got = lines(served.client.try_clone().unwrap());
        assert!(got.len() as u64 <= sent + 1, "{} of {sent}", got.len());
    }

    /// A producer waiting for room is let go when the connection closes,
    /// well before the stall limit.
    #[test]
    fn a_waiting_paced_send_returns_when_the_connection_closes() {
        let served = Served::new();
        let producer = std::thread::spawn({
            let conn = served.conn.clone();
            move || {
                let mut n = 0;
                while conn.send_paced(&numbered(n, 32 * 1024), Duration::from_secs(3600)) {
                    n += 1;
                }
            }
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(!producer.is_finished(), "it should be waiting");
        let closed = Instant::now();
        served.conn.close();
        producer.join().unwrap();
        assert!(
            closed.elapsed() < Duration::from_secs(2),
            "{:?}",
            closed.elapsed()
        );
    }

    #[test]
    fn the_budget_is_a_burst_of_100_then_100_a_second() {
        let start = Instant::now();
        let mut limit = RateLimit::new(start);
        assert!((0..100).all(|_| limit.allow(start)));
        assert!(!limit.allow(start));
        assert!(!limit.allow(start + Duration::from_millis(5)));
        assert!(limit.allow(start + Duration::from_millis(15)));
        assert!(!limit.allow(start + Duration::from_millis(15)));
        // A second refills the whole burst, and never more.
        let later = start + Duration::from_secs(5);
        assert!((0..100).all(|_| limit.allow(later)));
        assert!(!limit.allow(later));
    }

    #[test]
    fn lines_are_split_and_capped_without_holding_more_than_the_cap() {
        let mut reader = LineReader::new();
        let mut bytes: &[u8] = b"one\ntwo\nthr";
        assert_eq!(reader.next(&mut bytes), Some(Step::Line(b"one".to_vec())));
        assert_eq!(reader.next(&mut bytes), Some(Step::Line(b"two".to_vec())));
        assert_eq!(reader.next(&mut bytes), None);
        let mut bytes: &[u8] = b"ee\n";
        assert_eq!(reader.next(&mut bytes), Some(Step::Line(b"three".to_vec())));
        assert_eq!(reader.next(&mut bytes), None);

        // Exactly the cap, then one byte over it with and without a newline.
        let mut reader = LineReader::new();
        let full = vec![b'x'; MAX_LINE];
        let mut bytes: &[u8] = &full;
        assert_eq!(reader.next(&mut bytes), None);
        let mut newline: &[u8] = b"\n";
        assert_eq!(reader.next(&mut newline), Some(Step::Line(full.clone())));
        let mut bytes: &[u8] = &full;
        assert_eq!(reader.next(&mut bytes), None);
        let mut one_more: &[u8] = b"x";
        assert_eq!(reader.next(&mut one_more), Some(Step::TooLong));
        assert_eq!(reader.partial.len(), MAX_LINE, "the byte over was not kept");
        let mut reader = LineReader::new();
        let mut over: Vec<u8> = vec![b'x'; MAX_LINE + 1];
        over.push(b'\n');
        let mut bytes: &[u8] = &over;
        assert_eq!(reader.next(&mut bytes), Some(Step::TooLong));
    }
}
