// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the control ops do: [`Ops`], and the VMM's implementation,
//! [`VmmOps`].
//!
//! The connection serves `status` with [`Ops::status`] and `stop` with
//! [`Ops::stop`] once its parameters parse; every other op goes to
//! [`Ops::dispatch`]: the VMM's serves `pty.attach` and `pty.resize` (the
//! hello's capability `pty`), where later ops (`audit.*`, `policy.*`) are
//! added.
//!
//! ## `pty.attach`
//!
//! `{"v":1,"id":N,"op":"pty.attach","session":"main","mode":"rw"|"ro",
//! "replay_bytes":R}` attaches the connection to the session's terminal
//! (the PTY hub, [`crate::pty`]). The response is `{"raw":true}`; after
//! that line the connection carries the terminal's raw bytes both ways, and
//! no more lines or events, but one: the newest `R` bytes of the hub's
//! 256 KiB scrollback come first (`replay_bytes` is 0 when absent and is
//! capped at the scrollback), then the session's output as it comes, with
//! nothing missed or repeated between the two. With `rw`, what the client
//! sends is typed into the session (bytes past the hub's 64 KiB input
//! queue are dropped, never waited for); with `ro` it is discarded. A
//! client that leaves more than 1 MiB of output unread is detached: its
//! stream ends with the line `{"v":1,"event":"pty.detached","reason":
//! "slow"}`, and the connection is closed. When the session's terminal
//! ends, the stream ends after its last byte, and the connection is
//! closed. A client may close its sending side and keep reading.
//!
//! Errors: `bad_request` for parameters that do not parse (no `session`, a
//! `mode` other than `rw` or `ro`, a `replay_bytes` that is not an unsigned
//! integer); `not_found` for a `session` other than `main`;
//! `invalid_state` before the guest's init has opened the session's
//! terminal, and on a VM without the vsock device. Once the terminal has
//! ended, an attach gets its replay, then the end.
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

use std::fmt;
use std::os::unix::net::UnixStream;

use boxcar_proto::control::{
    ErrorBody, ErrorCode, PtyAttachParams, PtyMode, PtyResizeParams, Request, Status, StopMode,
    StopParams, PTY_SESSION,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::guest_ctl::SendError;
use crate::lifecycle::{StopReason, VmmHandle, GRACEFUL_STOP_MARGIN};
use crate::pty::{raw, Mode, PtyHub, PtyState, SCROLLBACK};

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
}

impl VmmOps {
    pub fn new(handle: VmmHandle) -> VmmOps {
        VmmOps { handle }
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

    /// `pty.attach` and `pty.resize`: see the module docs.
    fn dispatch(&self, conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody> {
        match req.op.as_str() {
            "pty.attach" => self.pty_attach(conn, req),
            "pty.resize" => self.pty_resize(req),
            _ => Err(ErrorBody::unknown_op(&req.op)),
        }
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["pty".to_owned()]
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
        let attached = raw::Attached::new(hub, id);
        conn.raw_upgrade = Some(RawUpgrade::new(move |stream, pending| {
            raw::serve(attached, output, input, stream, pending)
        }));
        Ok(json!({"raw": true}))
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
fn params<T: DeserializeOwned>(req: &Request) -> Result<T, ErrorBody> {
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

    use boxcar_proto::control::{to_line, ErrorCode, Hello, PtyDetached, VmState};
    use boxcar_proto::guest::HostMsg;

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
        assert_eq!(ops.capabilities(), ["pty"]);

        let mut conn = ConnCtx {
            peer_pid: 1,
            peer_uid: 0,
            raw_upgrade: None,
        };
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
            let (server, client) = UnixStream::pair().unwrap();
            let ops: Arc<dyn Ops> = Arc::new(VmmOps::new(fixture.handle.clone()));
            let hello = Hello::new("boxcar/test", "session", ops.capabilities());
            let session = Session {
                conn: Arc::new(Conn::new(server, &hello).unwrap()),
                ctx: ConnCtx {
                    peer_pid: 1,
                    peer_uid: 0,
                    raw_upgrade: None,
                },
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
        assert_eq!(wire.hello["capabilities"], json!(["pty"]));
        let response = wire.request_then("pty.attach", attach("rw", 100), b"early ");
        assert_eq!(response["result"], json!({"raw": true}), "{response}");
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
        assert_eq!(response["result"], json!({"raw": true}), "{response}");
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
    /// detached: the guest never waits on it, and once it does read, its
    /// stream ends with `pty.detached` (reason `slow`) after its last raw
    /// byte.
    #[test]
    fn a_slow_attach_gets_the_detached_event_then_the_end() {
        const PRINTED: usize = 4 << 20;
        let fixture = Fixture::new();
        let mut guest = fixture.guest();
        wait_until("the terminal open", || {
            fixture.hub.state() == PtyState::Live
        });
        let mut wire = Wire::new(&fixture);
        let response = wire.request("pty.attach", attach("rw", 0));
        assert_eq!(response["result"], json!({"raw": true}), "{response}");
        guest.write_all(&vec![b'x'; PRINTED]).unwrap();
        wait_until("all of it in", || fixture.hub.received() == PRINTED as u64);
        wait_until("detached", || fixture.hub.clients() == 0);
        let got = wire.read_to_end();
        let event = to_line(&PtyDetached::slow()).unwrap();
        assert!(
            got.ends_with(&event),
            "{:?}",
            &got[got.len().saturating_sub(80)..]
        );
        let raw = &got[..got.len() - event.len()];
        assert!(!raw.is_empty() && raw.len() < PRINTED);
        assert!(raw.iter().all(|&b| b == b'x'));
        wire.ended();
    }
}
