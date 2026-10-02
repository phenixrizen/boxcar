// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the control ops do: [`Ops`], and the VMM's implementation,
//! [`VmmOps`].
//!
//! The connection serves `status` with [`Ops::status`] and `stop` with
//! [`Ops::stop`] once its parameters parse; every other op goes to
//! [`Ops::dispatch`]: the VMM's serves `pty.attach`, `pty.watch` and
//! `pty.resize` (the hello's capability `pty`) and `audit.subscribe` (the
//! capability `audit`), where later ops (`policy.*`) are added.
//!
//! ## `pty.attach`
//!
//! `{"v":1,"id":N,"op":"pty.attach","session":"main","mode":"rw"|"ro",
//! "replay_bytes":R}` attaches the connection to the session's terminal
//! (the PTY hub, [`crate::pty`]). The response is
//! `{"raw":true,"attach_id":"<32 hex digits>"}`, the id 128 random bits;
//! after that line the connection carries the terminal's raw bytes both
//! ways and nothing else, no line or event: the newest `R` bytes of the
//! hub's 256 KiB scrollback come first (`replay_bytes` is 0 when absent and
//! is capped at the scrollback), then the session's output as it comes,
//! with nothing missed or repeated between the two. With `rw`, what the
//! client sends is typed into the session (bytes past the hub's 64 KiB
//! input queue are dropped, never waited for); with `ro` it is discarded.
//! A client that leaves more than 1 MiB of output unread, or takes no byte
//! for 30 s, is detached as slow: its stream ends after the last byte it
//! took, and the connection is closed; the reason goes to the connections
//! that watch the attach (`pty.watch`), and is not heard otherwise. When
//! the session's terminal ends, the stream ends after its last byte, and
//! the connection is closed. A client may close its sending side and keep
//! reading.
//!
//! Errors: `bad_request` for parameters that do not parse (no `session`, a
//! `mode` other than `rw` or `ro`, a `replay_bytes` that is not an unsigned
//! integer); `not_found` for a `session` other than `main`;
//! `invalid_state` before the guest's init has opened the session's
//! terminal, and on a VM without the vsock device. Once the terminal has
//! ended, an attach gets its replay, then the end.
//!
//! ## `pty.watch`
//!
//! `{"v":1,"id":N,"op":"pty.watch","attach_id":"<hex>"}` (with
//! `"session":"main"`, optionally), on any other control connection,
//! answers `{}` and makes that connection hear the attach's end for being
//! slow: `{"v":1,"event":"pty.detached","attach_id":"<hex>",
//! "reason":"slow"}`, queued on its outbox without waiting and sent before
//! the attached stream is closed (the two connections are not ordered with
//! each other: a client that reads the stream's end first should wait a
//! moment for the event). Every connection is the VMM's own user's.
//! Watching twice from one connection changes nothing. Errors:
//! `bad_request` (no `attach_id`), `not_found` (an `attach_id` the server
//! does not have, one whose attach has ended, or a session other than
//! `main`), `invalid_state` (a VM without the vsock device).
//!
//! ## `pty.resize`
//!
//! `{"v":1,"id":N,"op":"pty.resize","session":"main","rows":R,"cols":C}`
//! asks for the session's terminal to be `R` rows by `C` columns (each 1
//! to 65535), and answers `{}`. The size goes to the guest unless the
//! terminal has it already; the latest size asked for, by any client,
//! wins. Errors: `bad_request` (a size out of range, or parameters that do
//! not parse), `not_found` (another `session`), `invalid_state` (the
//! terminal is not open, or has ended), `busy` (the guest control channel
//! has too much waiting).
//!
//! ## `audit.subscribe`
//!
//! `{"v":1,"id":N,"op":"audit.subscribe","from_seq":S,"types":["net."],
//! "pid":P}` streams the session's audit records to the connection: those
//! already in the log with a seq of `S` or more (1 when `from_seq` is absent,
//! as is 0), then the ones the VMM makes, in seq order, with none missed or
//! repeated between the two. `types` are type prefixes (`"net."` takes every
//! `net.*`, `"fs.write"` that type; absent or empty takes every type), `pid`
//! takes the records attributed to that guest process; a record must pass
//! both. The response is `{"next_seq":N,"sub":K}`: `N` is the seq the log's
//! next record had when the subscription began (the records below it come
//! from the log, the others live; an `S` of `N` or more waits for the live
//! ones), `K` the subscription's id, counting from 1 on the connection. Then,
//! until the connection closes:
//!
//! - `{"v":1,"event":"audit","sub":K,"rec":{...}}`: one record, as the log
//!   has it, `rec` being the log's own line.
//! - `{"v":1,"event":"audit.lagged","sub":K,"resume_seq":R}`: the client
//!   read too slowly for the VMM to hold the live records for it, and it
//!   was dropped from the live stream. The records from `R` on follow: read
//!   back from the log, then live again. Nothing is missed; the events
//!   before this one were delivered.
//!
//! The VMM does not wait for a client. A client that has a lot unread (1 MiB)
//! is waited for by its subscription only, which falls behind and lags as
//! above; one that takes no byte for 30 s is disconnected, and reconnects
//! with `from_seq`. A connection holds at most 4 subscriptions, which end
//! with it. The subscription's events stop, with the connection left open,
//! when the log ends (the VM is stopping). Errors: `bad_request` (parameters
//! that do not parse: `types` more than 32 entries, or an empty one or one
//! over 64 bytes), `busy` (4 subscriptions already), `invalid_state` (the
//! audit log is closed or has failed), `internal` (the log cannot be read).

use std::fmt;
use std::os::unix::net::UnixStream;

use std::sync::{Arc, Weak};
use std::time::Duration;

use boxcar_proto::control::{
    ErrorBody, ErrorCode, PtyAttachParams, PtyAttached, PtyDetached, PtyMode, PtyResizeParams,
    PtyWatchParams, Request, Status, StopMode, StopParams, PTY_SESSION,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use super::audit::{self, AuditSubs, Limits};
use super::conn::Conn;
use crate::guest_ctl::SendError;
use crate::lifecycle::{StopReason, VmmHandle, GRACEFUL_STOP_MARGIN};
use crate::pty::{raw, Mode, PtyHub, PtyState, Watcher, SCROLLBACK};

/// The ops a control connection serves.
pub trait Ops: Send + Sync {
    /// `status`.
    fn status(&self) -> Status;
    /// `stop`, with its parameters. The result is the response's `result`.
    ///
    /// It must return promptly: start the stop and return, never wait on
    /// the guest or on the stop sequence. The connection calls it holding
    /// its outbox lock (so the response comes before the `stopping` the
    /// stop causes), and the stop sequence's `notify_state` takes that
    /// lock: a `stop` that waited for the VM to stop would deadlock it.
    fn stop(&self, params: StopParams) -> Result<Value, ErrorBody>;
    /// Any op other than `status` and `stop`: `unknown_op` for one it does
    /// not serve. An op that turns the connection into a raw byte stream
    /// sets `conn.raw_upgrade` and succeeds.
    fn dispatch(&self, conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody>;
    /// The op families beyond `status` and `stop` that `dispatch` serves,
    /// named in the hello's `capabilities`.
    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }
}

/// One control connection, as the ops see it.
pub struct ConnCtx {
    /// The peer's process id and user id, from `SO_PEERCRED`.
    pub peer_pid: u32,
    pub peer_uid: u32,
    /// Set by an op that turns the connection into a raw byte stream
    /// after its response (`pty.attach`).
    pub raw_upgrade: Option<RawUpgrade>,
    /// How events from elsewhere reach this connection (`pty.watch`,
    /// `audit.subscribe`).
    pub events: Option<ConnEvents>,
    /// The audit subscriptions this connection holds.
    pub(crate) audit: AuditSubs,
}

impl ConnCtx {
    /// A connection of the peer with these credentials, with no way to
    /// hear events yet.
    pub fn new(peer_pid: u32, peer_uid: u32) -> ConnCtx {
        ConnCtx {
            peer_pid,
            peer_uid,
            raw_upgrade: None,
            events: None,
            audit: AuditSubs::default(),
        }
    }
}

/// A connection's way to hear events from elsewhere: each is queued on its
/// outbox, and its own thread sends it. Never waits, except for a stream
/// that forwards a log into the connection and so goes at the client's pace
/// (`send_paced`). Holds the connection weakly: one that has
/// gone hears nothing.
#[derive(Clone)]
pub struct ConnEvents {
    conn: Weak<Conn>,
}

impl ConnEvents {
    pub(crate) fn new(conn: &Arc<Conn>) -> ConnEvents {
        ConnEvents {
            conn: Arc::downgrade(conn),
        }
    }

    /// Queues `event`, waiting while the client has a lot unread: see
    /// [`Conn::send_paced`]. `false` when the connection is gone, closing,
    /// or has just cut the client off for taking nothing for `stall`.
    pub(crate) fn send_paced<T: serde::Serialize>(&self, event: &T, stall: Duration) -> bool {
        self.conn
            .upgrade()
            .is_some_and(|conn| conn.send_paced(event, stall))
    }

    /// Whether the connection is still there and not closing.
    pub(crate) fn is_open(&self) -> bool {
        self.conn.upgrade().is_some_and(|conn| !conn.is_closing())
    }

    /// Closes the connection, if it is there.
    pub(crate) fn close(&self) {
        if let Some(conn) = self.conn.upgrade() {
            conn.close();
        }
    }
}

impl Watcher for ConnEvents {
    fn detached(&self, attach_id: &str, reason: &str) -> bool {
        let Some(conn) = self.conn.upgrade() else {
            return false;
        };
        conn.send_event(&PtyDetached::new(attach_id, reason));
        true
    }

    fn key(&self) -> usize {
        self.conn.as_ptr() as usize
    }
}

/// What takes over a connection that an op turned into a raw byte stream.
/// Once the op's response is sent, the connection stops reading lines,
/// gets no more events, and runs the handler on its thread with the socket
/// (blocking) and the bytes the client sent after the request's line. The
/// connection ends when the handler returns; when the VM stops, the socket
/// is shut down under it.
pub struct RawUpgrade {
    handler: Box<dyn FnOnce(UnixStream, Vec<u8>) + Send>,
}

impl RawUpgrade {
    pub fn new(handler: impl FnOnce(UnixStream, Vec<u8>) + Send + 'static) -> RawUpgrade {
        RawUpgrade {
            handler: Box::new(handler),
        }
    }

    pub(crate) fn run(self, stream: UnixStream, pending: Vec<u8>) {
        (self.handler)(stream, pending);
    }
}

impl fmt::Debug for RawUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawUpgrade")
    }
}

/// The VMM's ops, over its [`VmmHandle`].
pub struct VmmOps {
    handle: VmmHandle,
    audit: Limits,
}

impl VmmOps {
    pub fn new(handle: VmmHandle) -> VmmOps {
        VmmOps {
            handle,
            audit: Limits::default(),
        }
    }

    /// Audit subscriptions with smaller limits than the defaults, so that
    /// a test reaches them.
    #[cfg(test)]
    pub(crate) fn with_audit_limits(mut self, queue: usize, stall: Duration) -> VmmOps {
        self.audit = Limits { queue, stall };
        self
    }
}

impl Ops for VmmOps {
    fn status(&self) -> Status {
        self.handle.status()
    }

    /// `graceful` (the default), while a session runs: init is asked to
    /// end it, with `timeout_ms` (5000 by default) between `SIGHUP` and
    /// `SIGTERM` and `SIGKILL`, and the VM stops when the guest resets, or
    /// [`GRACEFUL_STOP_MARGIN`] after that at the latest (see
    /// [`VmmHandle::request_graceful_stop`]). `force`, or no session to end:
    /// the VM stops at once. Either way the run exits 0.
    fn stop(&self, params: StopParams) -> Result<Value, ErrorBody> {
        let graceful = params.mode == StopMode::Graceful
            && self
                .handle
                .request_graceful_stop(params.effective_timeout_ms(), GRACEFUL_STOP_MARGIN);
        if !graceful {
            self.handle.request_stop(StopReason::Requested);
        }
        Ok(json!({"accepted": true}))
    }

    /// `pty.attach`, `pty.watch` and `pty.resize`: see the module docs.
    fn dispatch(&self, conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody> {
        match req.op.as_str() {
            "pty.attach" => self.pty_attach(conn, req),
            "pty.watch" => self.pty_watch(conn, req),
            "pty.resize" => self.pty_resize(req),
            "audit.subscribe" => audit::subscribe(self.handle.audit(), conn, req, self.audit),
            _ => Err(ErrorBody::unknown_op(&req.op)),
        }
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["pty".to_owned(), "audit".to_owned()]
    }
}

impl VmmOps {
    /// The hub of the terminal `session` names.
    fn terminal(&self, session: &str) -> Result<PtyHub, ErrorBody> {
        if session != PTY_SESSION {
            return Err(ErrorBody::new(
                ErrorCode::NotFound,
                format!("no session {session:?}: the session is {PTY_SESSION:?}"),
            ));
        }
        self.handle.pty().ok_or_else(|| {
            ErrorBody::new(
                ErrorCode::InvalidState,
                "the VM has no vsock device, so its session has no terminal",
            )
        })
    }

    fn pty_attach(&self, conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody> {
        let params: PtyAttachParams = params(req)?;
        let hub = self.terminal(&params.session)?;
        if hub.state() == PtyState::Waiting {
            return Err(not_open());
        }
        let mode = match params.mode {
            PtyMode::Rw => Mode::Rw,
            PtyMode::Ro => Mode::Ro,
        };
        let replay = usize::try_from(params.replay_bytes)
            .unwrap_or(usize::MAX)
            .min(SCROLLBACK);
        let (id, output, input) = hub.attach(mode, replay);
        let attached = raw::Attached::new(hub.clone(), id);
        let attach_id = hub.name(&output).map_err(|error| {
            ErrorBody::new(
                ErrorCode::Internal,
                format!("cannot name the attach: {error}"),
            )
        })?;
        conn.raw_upgrade = Some(RawUpgrade::new(move |stream, pending| {
            raw::serve(attached, output, input, stream, pending)
        }));
        let result = PtyAttached {
            raw: true,
            attach_id,
        };
        serde_json::to_value(result)
            .map_err(|error| ErrorBody::new(ErrorCode::Internal, format!("the result: {error}")))
    }

    fn pty_watch(&self, conn: &ConnCtx, req: &Request) -> Result<Value, ErrorBody> {
        let params: PtyWatchParams = params(req)?;
        let hub = self.terminal(params.session.as_deref().unwrap_or(PTY_SESSION))?;
        let events = conn.events.clone().ok_or_else(|| {
            ErrorBody::new(ErrorCode::Internal, "this connection cannot hear events")
        })?;
        hub.watch(&params.attach_id, Arc::new(events))
            .map_err(|error| ErrorBody::new(ErrorCode::NotFound, error.to_string()))?;
        Ok(json!({}))
    }

    fn pty_resize(&self, req: &Request) -> Result<Value, ErrorBody> {
        let params: PtyResizeParams = params(req)?;
        params
            .check()
            .map_err(|message| ErrorBody::new(ErrorCode::BadRequest, message))?;
        let hub = self.terminal(&params.session)?;
        match hub.state() {
            PtyState::Waiting => return Err(not_open()),
            PtyState::Ended => {
                return Err(ErrorBody::new(
                    ErrorCode::InvalidState,
                    "the session's terminal has ended",
                ))
            }
            PtyState::Live => {}
        }
        hub.resize(params.rows, params.cols)
            .map_err(|error| match error {
                SendError::Full => ErrorBody::new(ErrorCode::Busy, error.to_string()),
                SendError::NotConnected => {
                    ErrorBody::new(ErrorCode::InvalidState, error.to_string())
                }
                SendError::TooLong => ErrorBody::new(ErrorCode::Internal, error.to_string()),
            })?;
        Ok(json!({}))
    }
}

/// The request's parameters as `T`, or `bad_request`.
pub(super) fn params<T: DeserializeOwned>(req: &Request) -> Result<T, ErrorBody> {
    serde_json::from_value(req.params.clone()).map_err(|error| {
        ErrorBody::new(
            ErrorCode::BadRequest,
            format!("{} parameters: {error}", req.op),
        )
    })
}

/// The error for a terminal init has not opened yet.
fn not_open() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::InvalidState,
        "the session's terminal is not open yet: the guest's init has not connected it",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use boxcar_audit::{Priority, Submission};
    use boxcar_proto::control::{to_line, ErrorCode, Hello, VmState};
    use boxcar_proto::guest::HostMsg;
    use boxcar_proto::{Attrib, FsIo, NetDrop, OpResult, Payload, Record, Ring, Subject};

    use super::*;
    use crate::control::conn::{Conn, Session};
    use crate::pty::testing::{wait_until, Fixture, LIMIT};
    use crate::pty::PtyState;

    #[test]
    fn the_vmm_ops_report_the_handle_and_stop_it() {
        let fixture = Fixture::new();
        let handle = fixture.handle.clone();
        let ops = VmmOps::new(handle.clone());
        assert_eq!(ops.status(), handle.status());
        assert_eq!(ops.capabilities(), ["pty", "audit"]);

        let mut conn = ConnCtx::new(1, 0);
        let other = Request::new(1, "pty.detach", Value::Null);
        assert_eq!(
            ops.dispatch(&mut conn, &other).unwrap_err().code,
            ErrorCode::UnknownOp
        );
        // No parameters at all: not an attach.
        let bare = Request::new(2, "pty.attach", Value::Null);
        assert_eq!(
            ops.dispatch(&mut conn, &bare).unwrap_err().code,
            ErrorCode::BadRequest
        );
        assert!(conn.raw_upgrade.is_none());

        let force = StopParams {
            mode: StopMode::Force,
            timeout_ms: None,
        };
        assert_eq!(ops.stop(force).unwrap(), json!({"accepted": true}));
        assert_eq!(handle.state(), VmState::Stopping);
    }

    /// A client of the VMM's ops over one end of a socket pair, the
    /// connection's own thread serving the other, past its hello.
    struct Wire {
        reader: BufReader<UnixStream>,
        writer: UnixStream,
        hello: Value,
        next_id: u64,
        thread: Option<JoinHandle<()>>,
    }

    impl Wire {
        fn new(fixture: &Fixture) -> Wire {
            Wire::with_ops(fixture, VmmOps::new(fixture.handle.clone()))
        }

        fn with_ops(fixture: &Fixture, ops: VmmOps) -> Wire {
            let (server, client) = UnixStream::pair().unwrap();
            let ops: Arc<dyn Ops> = Arc::new(ops);
            let hello = Hello::new("boxcar/test", "session", ops.capabilities());
            let conn = Arc::new(Conn::new(server, &hello).unwrap());
            let session = Session {
                ctx: ConnCtx {
                    events: Some(ConnEvents::new(&conn)),
                    ..ConnCtx::new(1, 0)
                },
                conn,
                ops,
                audit: fixture.handle.audit().clone(),
            };
            let thread = thread::spawn(move || session.serve());
            client.set_read_timeout(Some(LIMIT)).unwrap();
            let mut wire = Wire {
                writer: client.try_clone().unwrap(),
                reader: BufReader::new(client),
                hello: Value::Null,
                next_id: 1,
                thread: Some(thread),
            };
            wire.hello = wire.line();
            wire
        }

        fn line(&mut self) -> Value {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        }

        /// Sends `op` with `params` (and `then`, raw, right behind the
        /// line) and returns the response.
        fn request_then(&mut self, op: &str, params: Value, then: &[u8]) -> Value {
            let id = self.next_id;
            self.next_id += 1;
            let mut bytes = to_line(&Request::new(id, op, params)).unwrap();
            bytes.extend_from_slice(then);
            self.writer.write_all(&bytes).unwrap();
            let response = self.line();
            assert_eq!(response["id"], id, "{response}");
            response
        }

        fn request(&mut self, op: &str, params: Value) -> Value {
            self.request_then(op, params, b"")
        }

        /// The raw bytes until the server closes the connection.
        fn read_to_end(&mut self) -> Vec<u8> {
            let mut rest = Vec::new();
            self.reader.read_to_end(&mut rest).unwrap();
            rest
        }

        /// The connection's thread has ended.
        fn ended(&mut self) {
            self.thread.take().unwrap().join().unwrap();
        }
    }

    fn code(response: &Value) -> &str {
        assert_eq!(response["ok"], false, "{response}");
        response["error"]["code"].as_str().unwrap()
    }

    fn attach(mode: &str, replay: u64) -> Value {
        json!({"session": "main", "mode": mode, "replay_bytes": replay})
    }

    /// `pty.attach` answers `{"raw":true}`, then the connection is the
    /// terminal: the replay, the session's output as it comes, and what the
    /// client types (including what it sent right behind the request) to
    /// the session; when the session ends, the stream does.
    #[test]
    fn attach_upgrades_to_raw() {
        let fixture = Fixture::new();
        let mut guest = fixture.guest();
        guest.write_all(b"before ").unwrap();
        wait_until("7 bytes in", || fixture.hub.received() == 7);
        let mut wire = Wire::new(&fixture);
        assert_eq!(wire.hello["capabilities"], json!(["pty", "audit"]));
        let response = wire.request_then("pty.attach", attach("rw", 100), b"early ");
        assert_eq!(response["result"]["raw"], true, "{response}");
        let id = response["result"]["attach_id"].as_str().unwrap();
        assert_eq!(id.len(), 32, "{response}");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{response}");
        let mut replay = [0u8; 7];
        wire.reader.read_exact(&mut replay).unwrap();
        assert_eq!(&replay, b"before ");
        guest.write_all(b"live").unwrap();
        let mut live = [0u8; 4];
        wire.reader.read_exact(&mut live).unwrap();
        assert_eq!(&live, b"live");
        wire.writer.write_all(b"typed\r").unwrap();
        let mut typed = [0u8; 12];
        guest.read_exact(&mut typed).unwrap();
        assert_eq!(&typed, b"early typed\r");
        // The session ends: the stream ends after its last byte, and the
        // connection with it.
        guest.write_all(b" bye").unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        assert_eq!(wire.read_to_end(), b" bye");
        wire.ended();
        assert_eq!(fixture.hub.clients(), 0);
    }

    /// Before init has opened the session's terminal there is nothing to
    /// attach to or resize: `invalid_state`, and the connection stays a
    /// control connection. Parameters are checked first.
    #[test]
    fn attach_before_init_is_invalid_state() {
        let fixture = Fixture::new();
        let mut wire = Wire::new(&fixture);
        assert_eq!(fixture.hub.state(), PtyState::Waiting);
        assert_eq!(
            code(&wire.request("pty.attach", attach("rw", 0))),
            "invalid_state"
        );
        assert_eq!(
            code(&wire.request(
                "pty.resize",
                json!({"session": "main", "rows": 40, "cols": 120})
            )),
            "invalid_state"
        );
        assert_eq!(
            code(&wire.request(
                "pty.attach",
                json!({"session": "other", "mode": "rw", "replay_bytes": 0})
            )),
            "not_found"
        );
        for params in [
            json!({"session": "main", "mode": "write"}),
            json!({"session": "main"}),
            json!({"mode": "ro"}),
            json!({"session": "main", "mode": "ro", "replay_bytes": "all"}),
        ] {
            assert_eq!(
                code(&wire.request("pty.attach", params.clone())),
                "bad_request",
                "{params}"
            );
        }
        assert_eq!(wire.request("status", Value::Null)["ok"], true);
        assert_eq!(fixture.hub.clients(), 0);
    }

    /// `pty.resize` takes rows and cols from 1 to 65535 for the session
    /// `main`, and forwards the size to init.
    #[test]
    fn resize_validates() {
        let fixture = Fixture::new();
        let mut init = fixture.init();
        let _guest = fixture.guest();
        wait_until("the terminal open", || {
            fixture.hub.state() == PtyState::Live
        });
        let mut wire = Wire::new(&fixture);
        for params in [
            json!({"session": "main", "rows": 0, "cols": 80}),
            json!({"session": "main", "rows": 24, "cols": 0}),
            json!({"session": "main", "rows": 65536, "cols": 80}),
            json!({"session": "main", "rows": 24, "cols": -1}),
            json!({"session": "main", "rows": "24", "cols": 80}),
            json!({"session": "main", "rows": 24}),
            json!({"rows": 24, "cols": 80}),
        ] {
            assert_eq!(
                code(&wire.request("pty.resize", params.clone())),
                "bad_request",
                "{params}"
            );
        }
        assert_eq!(
            code(&wire.request(
                "pty.resize",
                json!({"session": "other", "rows": 40, "cols": 120})
            )),
            "not_found"
        );
        let ok = wire.request(
            "pty.resize",
            json!({"session": "main", "rows": 40, "cols": 120}),
        );
        assert_eq!(ok["result"], json!({}), "{ok}");
        assert_eq!(
            init.recv(),
            HostMsg::Resize {
                rows: 40,
                cols: 120
            }
        );
        let edge = wire.request(
            "pty.resize",
            json!({"session": "main", "rows": 65535, "cols": 1}),
        );
        assert_eq!(edge["result"], json!({}), "{edge}");
        assert_eq!(
            init.recv(),
            HostMsg::Resize {
                rows: 65535,
                cols: 1
            }
        );
    }

    /// A read-only attach gets the output; what its client sends is
    /// discarded, and counted.
    #[test]
    fn an_ro_attach_discards_its_input() {
        let fixture = Fixture::new();
        let mut guest = fixture.guest();
        wait_until("the terminal open", || {
            fixture.hub.state() == PtyState::Live
        });
        let mut wire = Wire::new(&fixture);
        let response = wire.request("pty.attach", attach("ro", 0));
        assert_eq!(response["result"]["raw"], true, "{response}");
        wire.writer.write_all(b"rm -rf /\r").unwrap();
        wait_until("discarded", || fixture.hub.ro_discarded() == 9);
        guest.write_all(b"out").unwrap();
        let mut out = [0u8; 3];
        wire.reader.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"out");
        guest
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut typed = [0u8; 1];
        assert!(guest.read(&mut typed).is_err(), "{typed:?}");
    }

    /// A client that reads nothing while the session prints 4 MiB is
    /// detached: the guest never waits on it, its raw stream carries only
    /// the session's bytes and then ends, and the connection that watches
    /// the attach (`pty.watch`) hears why.
    #[test]
    fn a_slow_attach_ends_its_stream_and_its_watcher_hears_why() {
        const PRINTED: usize = 4 << 20;
        let fixture = Fixture::new();
        let mut guest = fixture.guest();
        wait_until("the terminal open", || {
            fixture.hub.state() == PtyState::Live
        });
        let mut attached = Wire::new(&fixture);
        let response = attached.request("pty.attach", attach("rw", 0));
        let id = response["result"]["attach_id"].as_str().unwrap().to_owned();
        let mut watcher = Wire::new(&fixture);
        let watched = watcher.request("pty.watch", json!({"attach_id": id}));
        assert_eq!(watched["result"], json!({}), "{watched}");
        guest.write_all(&vec![b'x'; PRINTED]).unwrap();
        wait_until("all of it in", || fixture.hub.received() == PRINTED as u64);
        wait_until("detached", || fixture.hub.clients() == 0);
        assert_eq!(
            watcher.line(),
            json!({"v": 1, "event": "pty.detached", "attach_id": id, "reason": "slow"})
        );
        let raw = attached.read_to_end();
        assert!(!raw.is_empty() && raw.len() < PRINTED, "{}", raw.len());
        assert!(
            raw.iter().all(|&b| b == b'x'),
            "the raw stream is not only the session's"
        );
        attached.ended();
        // The watcher stays a control connection; the attach has ended.
        assert_eq!(watcher.request("status", Value::Null)["ok"], true);
        let again = watcher.request("pty.watch", json!({"attach_id": id}));
        assert_eq!(code(&again), "not_found");
    }

    /// `pty.watch` takes an `attach_id` (and the session, `main`, if
    /// named): an unknown one is not found, and parameters that do not
    /// parse are a bad request.
    #[test]
    fn watch_validates() {
        let fixture = Fixture::new();
        let _guest = fixture.guest();
        wait_until("the terminal open", || {
            fixture.hub.state() == PtyState::Live
        });
        let mut wire = Wire::new(&fixture);
        assert_eq!(
            code(&wire.request("pty.watch", json!({"attach_id": "0".repeat(32)}))),
            "not_found"
        );
        assert_eq!(code(&wire.request("pty.watch", json!({}))), "bad_request");
        assert_eq!(
            code(&wire.request("pty.watch", json!({"attach_id": 7}))),
            "bad_request"
        );
        let mut attached = Wire::new(&fixture);
        let id = attached.request("pty.attach", attach("ro", 0))["result"]["attach_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            code(&wire.request("pty.watch", json!({"session": "other", "attach_id": id}))),
            "not_found"
        );
        let ok = wire.request("pty.watch", json!({"session": "main", "attach_id": id}));
        assert_eq!(ok["result"], json!({}), "{ok}");
    }

    /// The writer of an attached connection does not wait on its client
    /// for ever: one that takes nothing for the stall limit (30 s; shorter
    /// here) is detached as slow, its stream closed, and its watcher told,
    /// while the hub still holds less than the client's 1 MiB for it.
    #[test]
    fn a_client_that_takes_nothing_is_cut_off_after_the_stall_limit() {
        let fixture = Fixture::new();
        let hub = &fixture.hub;
        let mut guest = fixture.guest();
        wait_until("the terminal open", || hub.state() == PtyState::Live);
        let (id, output, input) = hub.attach(Mode::Rw, 0);
        let name = hub.name(&output).unwrap();
        let watcher = Arc::new(crate::pty::testing::Recorder::default());
        hub.watch(&name, watcher.clone()).unwrap();
        let (server, client) = UnixStream::pair().unwrap();
        let attached = raw::Attached::with_stall_limit(hub.clone(), id, Duration::from_millis(300));
        let serving =
            thread::spawn(move || raw::serve(attached, output, input, server, Vec::new()));
        // More than the sockets hold, less than the hub keeps for it.
        guest.write_all(&vec![b'y'; 700 * 1024]).unwrap();
        wait_until("cut off", || hub.clients() == 0);
        let mut client = client;
        client.set_read_timeout(Some(LIMIT)).unwrap();
        let mut raw_bytes = Vec::new();
        client.read_to_end(&mut raw_bytes).unwrap();
        assert!(raw_bytes.iter().all(|&b| b == b'y'));
        drop(client);
        serving.join().unwrap();
        assert_eq!(*watcher.0.lock().unwrap(), [(name, "slow".to_owned())]);
    }

    /// An `fs.write` of `fh` = `n`, attributed to `pid`, with a path
    /// padded to `pad` bytes more, to make the record as big as a test needs.
    fn fs_event(n: u64, pid: u32, pad: usize) -> Submission {
        Submission {
            ring: Ring::Host,
            ts_guest_ns: None,
            subject: Some(Subject {
                pid,
                uid: 1000,
                gid: 1000,
            }),
            payload: Payload::FsWrite(FsIo {
                mount: "workspace".into(),
                path: format!("/file-{n:06}-{}", "p".repeat(pad)),
                fh: n,
                offset: 0,
                len: 1,
                result: OpResult::ok(),
                attrib: Attrib::Caller,
            }),
            span: None,
            priority: Priority::Normal,
        }
    }

    /// A `net.drop` of `count` = `n` attributed to `pid`.
    fn net_event(n: u64, pid: u32) -> Submission {
        Submission {
            payload: Payload::NetDrop(NetDrop {
                reason: "ipv6".into(),
                count: n,
            }),
            ..fs_event(n, pid, 0)
        }
    }

    /// The seq of the last record once the writer has written everything
    /// emitted so far (checkpoints included), by a round trip through its
    /// channel.
    fn written(sink: &boxcar_audit::AuditSink) -> u64 {
        drop(
            sink.subscribe(u64::MAX, boxcar_audit::Filter::default())
                .unwrap(),
        );
        sink.next_seq() - 1
    }

    /// The `rec` of an `audit` event for subscription `sub`, which `event`
    /// must be.
    fn rec_of(event: &Value, sub: u64) -> Record {
        assert_eq!(event["v"], 1, "{event}");
        assert_eq!(event["event"], "audit", "{event}");
        assert_eq!(event["sub"], sub, "{event}");
        serde_json::from_value(event["rec"].clone()).expect("a record")
    }

    /// `audit.subscribe` streams what the log has, then what it gets, each
    /// record once and in order, each event naming its subscription, after
    /// the response and nothing before it; a connection holds four and the
    /// fifth is `busy`; the connection serves other ops meanwhile.
    #[test]
    fn subscribe_streams_events_and_caps_at_four() {
        let fixture = Fixture::new();
        let sink = fixture.handle.audit().clone();
        for n in 0..5 {
            sink.emit(fs_event(n, 42, 0)).unwrap();
        }
        let mut wire = Wire::new(&fixture);
        assert_eq!(wire.hello["capabilities"], json!(["pty", "audit"]));

        // The response comes first, though the log has records to send.
        let response = wire.request("audit.subscribe", json!({}));
        assert_eq!(response["ok"], true, "{response}");
        let next_seq = response["result"]["next_seq"].as_u64().unwrap();
        assert_eq!(response["result"]["sub"], 1, "{response}");
        assert!(next_seq > 5, "{response}");
        // Replay: every record of the log, from seq 1.
        for want in 1..next_seq {
            let record = rec_of(&wire.line(), 1);
            assert_eq!(record.seq, want);
        }
        // Then live ones, as they are made.
        for n in 5..8 {
            sink.emit(fs_event(n, 42, 0)).unwrap();
        }
        for want in next_seq..next_seq + 3 {
            let record = rec_of(&wire.line(), 1);
            assert_eq!((record.seq, record.kind.as_str()), (want, "fs.write"));
        }

        // Three more, from beyond the end, so that they stay quiet.
        for want in 2..=4 {
            let response = wire.request("audit.subscribe", json!({"from_seq": 1_000_000}));
            assert_eq!(response["result"]["sub"], want, "{response}");
            assert_eq!(response["result"]["next_seq"], next_seq + 3, "{response}");
        }
        let fifth = wire.request("audit.subscribe", json!({}));
        assert_eq!(code(&fifth), "busy", "{fifth}");
        assert!(
            fifth["error"]["message"].as_str().unwrap().contains("4"),
            "{fifth}"
        );

        // The connection goes on serving, and the one live subscription
        // goes on streaming.
        assert_eq!(wire.request("status", Value::Null)["ok"], true);
        sink.emit(fs_event(8, 42, 0)).unwrap();
        assert_eq!(rec_of(&wire.line(), 1).seq, next_seq + 3);
        assert_eq!(wire.request("status", Value::Null)["ok"], true);
    }

    /// `types` and `pid` choose the records, in the replay and live alike.
    #[test]
    fn a_subscription_gets_only_the_records_it_asked_for() {
        let fixture = Fixture::new();
        let sink = fixture.handle.audit().clone();
        sink.emit(fs_event(0, 10, 0)).unwrap(); // 1
        sink.emit(net_event(1, 10)).unwrap(); // 2
        sink.emit(net_event(2, 20)).unwrap(); // 3
        let mut nets = Wire::new(&fixture);
        let mut pid20 = Wire::new(&fixture);
        let response = nets.request("audit.subscribe", json!({"types": ["net."]}));
        assert_eq!(response["result"]["next_seq"], 4, "{response}");
        pid20.request("audit.subscribe", json!({"pid": 20, "from_seq": 0}));
        sink.emit(fs_event(3, 20, 0)).unwrap(); // 4
        sink.emit(net_event(4, 20)).unwrap(); // 5
        sink.emit(net_event(5, 30)).unwrap(); // 6
        sink.emit(fs_event(6, 10, 0)).unwrap(); // 7
        let seqs = |wire: &mut Wire, n: usize| -> Vec<u64> {
            (0..n).map(|_| rec_of(&wire.line(), 1).seq).collect()
        };
        assert_eq!(seqs(&mut nets, 4), [2, 3, 5, 6]);
        assert_eq!(seqs(&mut pid20, 3), [3, 4, 5]);
        // Both at once.
        let mut both = Wire::new(&fixture);
        both.request("audit.subscribe", json!({"types": ["net."], "pid": 20}));
        assert_eq!(seqs(&mut both, 2), [3, 5]);
    }

    /// Parameters that are not an `audit.subscribe`'s are a bad request,
    /// and cost the connection nothing.
    #[test]
    fn subscribe_validates() {
        let fixture = Fixture::new();
        let mut wire = Wire::new(&fixture);
        let many: Vec<String> = (0..33).map(|n| format!("t{n}.")).collect();
        for params in [
            json!({"from_seq": -1}),
            json!({"from_seq": "1"}),
            json!({"pid": "x"}),
            json!({"pid": -2}),
            json!({"types": "net."}),
            json!({"types": [""]}),
            json!({"types": ["x".repeat(65)]}),
            json!({ "types": many }),
        ] {
            let response = wire.request("audit.subscribe", params.clone());
            assert_eq!(code(&response), "bad_request", "{params}: {response}");
        }
        // None of them used up one of the four.
        for want in 1..=4 {
            let response = wire.request("audit.subscribe", json!({"from_seq": 1_000_000}));
            assert_eq!(response["result"]["sub"], want, "{response}");
        }
        // Extremes that are fine.
        let mut other = Wire::new(&fixture);
        let exact = json!({"types": ["x".repeat(64)], "from_seq": u64::MAX, "pid": u32::MAX});
        assert_eq!(other.request("audit.subscribe", exact)["ok"], true);
    }

    /// The log's writer has closed: there is nothing to subscribe to, and a
    /// subscription that was running ends its events there, the connection
    /// staying open.
    #[test]
    fn a_closed_log_refuses_subscriptions_and_ends_running_ones() {
        let mut fixture = Fixture::new();
        let sink = fixture.handle.audit().clone();
        sink.emit(fs_event(0, 1, 0)).unwrap();
        let mut running = Wire::new(&fixture);
        let next_seq = running.request("audit.subscribe", json!({"from_seq": 2}))["result"]
            ["next_seq"]
            .as_u64()
            .unwrap();
        assert_eq!(next_seq, 2);
        fixture.close_audit();
        // The closing checkpoint is the last record, and the last event.
        let record = rec_of(&running.line(), 1);
        assert_eq!((record.seq, record.kind.as_str()), (2, "checkpoint"));
        assert_eq!(running.request("status", Value::Null)["ok"], true);

        let mut late = Wire::new(&fixture);
        let response = late.request("audit.subscribe", json!({}));
        assert_eq!(code(&response), "invalid_state", "{response}");
    }

    /// A client that reads nothing while the log runs far ahead holds the
    /// writer up not at all: it is waited for by its own subscription, which
    /// the writer drops when its queue is full. When the client reads, it is
    /// told (`audit.lagged`, with the seq the stream resumes from), and
    /// gets every record it missed from the log, none twice.
    #[test]
    fn a_stalled_subscriber_never_holds_up_the_writer_and_catches_up() {
        const EVENTS: u64 = 3000;
        let fixture = Fixture::new();
        let sink = fixture.handle.audit().clone();
        let ops =
            VmmOps::new(fixture.handle.clone()).with_audit_limits(16, Duration::from_secs(60));
        let mut wire = Wire::with_ops(&fixture, ops);
        let response = wire.request("audit.subscribe", json!({}));
        assert_eq!(response["result"]["next_seq"], 1, "{response}");
        // About 7 MB: far more than the socket and the outbox hold.
        for n in 0..EVENTS {
            sink.emit(fs_event(n, 5, 2000)).unwrap();
        }
        // All written, with nobody reading.
        let last = written(&sink);

        let mut next = 1;
        let mut lagged = Vec::new();
        while next <= last {
            let event = wire.line();
            if event["event"] == "audit.lagged" {
                assert_eq!(event["sub"], 1, "{event}");
                let resume = event["resume_seq"].as_u64().unwrap();
                assert_eq!(resume, next, "the stream resumes where it was");
                lagged.push(resume);
            } else {
                let record = rec_of(&event, 1);
                assert_eq!(record.seq, next);
                next += 1;
            }
        }
        assert!(!lagged.is_empty(), "the subscriber never lagged");
        // It is live again.
        sink.emit(fs_event(EVENTS, 5, 0)).unwrap();
        loop {
            let event = wire.line();
            if event["event"] == "audit" {
                assert_eq!(rec_of(&event, 1).seq, last + 1);
                break;
            }
        }
    }

    /// A subscriber that takes not one byte for the stall limit is cut off
    /// (to reconnect with `from_seq`), with what it was sent still readable,
    /// and the writer never held up; the connection's thread, forwarders
    /// included, ends.
    #[test]
    fn a_subscriber_that_takes_nothing_is_cut_off() {
        const EVENTS: u64 = 3000;
        let fixture = Fixture::new();
        let sink = fixture.handle.audit().clone();
        let ops =
            VmmOps::new(fixture.handle.clone()).with_audit_limits(16, Duration::from_millis(300));
        let mut wire = Wire::with_ops(&fixture, ops);
        wire.request("audit.subscribe", json!({}));
        for n in 0..EVENTS {
            sink.emit(fs_event(n, 5, 2000)).unwrap();
        }
        written(&sink);
        // Nothing read for longer than the stall limit.
        thread::sleep(Duration::from_millis(1500));
        let rest = wire.read_to_end();
        assert!(!rest.is_empty(), "what was sent before the cut is readable");
        assert!(
            rest.len() < (EVENTS as usize) * 2000 / 2,
            "everything came: {} bytes",
            rest.len()
        );
        wire.ended();
    }

    /// The connection ends its subscriptions with it: its thread is not
    /// held up by their forwarders, quiet ones or ones waiting on a client.
    #[test]
    fn closing_a_connection_ends_its_subscriptions() {
        let fixture = Fixture::new();
        let sink = fixture.handle.audit().clone();
        let mut wire = Wire::new(&fixture);
        for _ in 0..3 {
            wire.request("audit.subscribe", json!({"from_seq": 1_000_000}));
        }
        // One with a client that reads nothing, and a lot to send.
        wire.request("audit.subscribe", json!({}));
        for n in 0..3000 {
            sink.emit(fs_event(n, 5, 2000)).unwrap();
        }
        thread::sleep(Duration::from_millis(200));
        wire.writer.shutdown(Shutdown::Both).unwrap();
        let (done, ended) = std::sync::mpsc::channel();
        let thread = wire.thread.take().unwrap();
        thread::spawn(move || {
            thread.join().unwrap();
            let _ = done.send(());
        });
        ended
            .recv_timeout(Duration::from_secs(5))
            .expect("the connection's thread did not end");
    }
}
