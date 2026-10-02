// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The control protocol, version 1: how a client (`boxcar status`,
//! `boxcar stop`, conductor) drives a running VMM.
//!
//! The VMM listens on a Unix stream socket, `<state>/control.sock` (mode
//! 0600, in a 0700 state directory), and serves only peers with its own uid.
//! Every message is one line of UTF-8 JSON, at most [`MAX_LINE`] bytes not
//! counting its newline. The server speaks first, with a [`Hello`]; then
//! the client sends [`Request`]s, each answered by one [`Response`] with the
//! same `id`. The server may also send events, `{"v":1,"event":"<name>",
//! ...}`, such as [`StateEvent`], at any time between responses.
//!
//! ```text
//! <- {"v":1,"event":"hello","protocol":"boxcar.control","versions":[1],...}
//! -> {"v":1,"id":1,"op":"status"}
//! <- {"v":1,"id":1,"ok":true,"result":{"state":"running",...}}
//! -> {"v":1,"id":2,"op":"stop","mode":"graceful"}
//! <- {"v":1,"id":2,"ok":true,"result":{"accepted":true}}
//! <- {"v":1,"event":"state","state":"stopping"}
//! <- {"v":1,"event":"state","state":"stopped"}
//! ```
//!
//! A request's fields other than `v`, `id` and `op` are its parameters.
//! Unknown fields are ignored everywhere, and a client ignores events it
//! does not know. Errors carry one of the [`ErrorCode`]s.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `protocol` of the [`Hello`].
pub const PROTOCOL: &str = "boxcar.control";
/// The protocol version this crate speaks: the `v` of every message.
pub const VERSION: u32 = 1;
/// The longest line either side sends or accepts, in bytes, not counting
/// the newline that ends it: 1 MiB.
pub const MAX_LINE: usize = 1 << 20;
/// The name of the control socket in the VMM's state directory.
pub const SOCKET_NAME: &str = "control.sock";
/// How long a graceful stop waits for the guest when the request names no
/// `timeout_ms`.
pub const DEFAULT_STOP_TIMEOUT_MS: u64 = 5000;

/// A request: `{"v":1,"id":N,"op":"<op>", ...params}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    /// Chosen by the client; the response carries it back.
    pub id: u64,
    pub op: String,
    /// Every other field of the request, as an object.
    #[serde(flatten)]
    pub params: Value,
}

impl Request {
    /// A version-1 request for `op` with the fields of `params`, which is an
    /// object or null (no parameters).
    pub fn new(id: u64, op: impl Into<String>, params: Value) -> Request {
        Request {
            v: VERSION,
            id,
            op: op.into(),
            params,
        }
    }
}

/// The answer to one request: `{"v":1,"id":N,"ok":true,"result":{...}}` or
/// `{"v":1,"id":N,"ok":false,"error":{"code":"...","message":"..."}}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    /// The request's `id`, or 0 when the request had none that could be
    /// read, or was a long line dropped unread for being over the rate
    /// limit.
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    /// The request `id` succeeded with `result`.
    pub fn success(id: u64, result: Value) -> Response {
        Response {
            v: VERSION,
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// The request `id` failed with `error`.
    pub fn failure(id: u64, error: ErrorBody) -> Response {
        Response {
            v: VERSION,
            id,
            ok: false,
            result: None,
            error: Some(error),
        }
    }

    /// The outcome as a `Result`: the result (null when the server sent
    /// none), or the error (an `internal` one when the server sent none).
    pub fn into_result(self) -> Result<Value, ErrorBody> {
        if self.ok {
            Ok(self.result.unwrap_or(Value::Null))
        } else {
            Err(self.error.unwrap_or_else(|| {
                ErrorBody::new(ErrorCode::Internal, "the server failed without saying why")
            }))
        }
    }
}

/// Why a request failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    /// For people; clients act on `code`.
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
        ErrorBody {
            code,
            message: message.into(),
        }
    }

    /// `unknown_op`, for an op the server does not serve.
    pub fn unknown_op(op: &str) -> ErrorBody {
        ErrorBody::new(ErrorCode::UnknownOp, format!("no op {op:?}"))
    }
}

impl fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// The error codes, exactly these; on the wire in snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The line is too long, not UTF-8, not a JSON object, lacks `v`, `id`
    /// or `op`, or has parameters that do not fit the op.
    BadRequest,
    /// `v` is not [`VERSION`].
    UnsupportedVersion,
    /// The server has no such op.
    UnknownOp,
    /// The op cannot be done in the VM's current state.
    InvalidState,
    /// What the op names does not exist.
    NotFound,
    /// The server cannot take the op now.
    Busy,
    /// The connection sent more than its budget of requests; the request
    /// was dropped.
    RateLimited,
    /// The server failed.
    Internal,
}

impl ErrorCode {
    /// The wire name, such as `bad_request`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::UnknownOp => "unknown_op",
            ErrorCode::InvalidState => "invalid_state",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Busy => "busy",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The server's first line on every connection it accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub v: u32,
    /// `"hello"`.
    pub event: String,
    /// [`PROTOCOL`].
    pub protocol: String,
    /// The versions the server speaks: `[1]`.
    pub versions: Vec<u32>,
    /// `boxcar/<version>`.
    pub server: String,
    pub session_id: String,
    /// The op families the server serves beyond `status` and `stop`, such
    /// as `pty`, `audit` and `policy.net`.
    pub capabilities: Vec<String>,
}

impl Hello {
    /// The hello of `server` (`boxcar/<version>`) for `session_id`.
    pub fn new(server: &str, session_id: &str, capabilities: Vec<String>) -> Hello {
        Hello {
            v: VERSION,
            event: "hello".to_owned(),
            protocol: PROTOCOL.to_owned(),
            versions: vec![VERSION],
            server: server.to_owned(),
            session_id: session_id.to_owned(),
            capabilities,
        }
    }
}

/// Where the VM is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    /// Built; the vCPUs have not started.
    Booting,
    /// The vCPUs run.
    Running,
    /// A stop trigger fired; the stop sequence runs.
    Stopping,
    /// The stop sequence has run.
    Stopped,
}

/// `{"v":1,"event":"state","state":"..."}`: the VM entered `state`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEvent {
    pub v: u32,
    /// `"state"`.
    pub event: String,
    pub state: VmState,
}

impl StateEvent {
    pub fn new(state: VmState) -> StateEvent {
        StateEvent {
            v: VERSION,
            event: "state".to_owned(),
            state,
        }
    }
}

/// How the guest's session ended, as its init reported it: the exit code of
/// the session's process, or the signal that killed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOutcome {
    /// The exit code, when the process exited.
    pub code: Option<i32>,
    /// The signal number, when a signal killed the process.
    pub signal: Option<i32>,
}

/// The result of `status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub state: VmState,
    pub session_id: String,
    /// The VMM's process id.
    pub pid: u32,
    /// Milliseconds since the VM was built.
    pub uptime_ms: u64,
    pub vcpus: u8,
    pub mem_mib: u64,
    pub guest: GuestStatus,
    pub audit: AuditStatus,
    /// The virtio devices present, by slot name in slot order, such as
    /// `fs:root` and `fs:workspace`.
    pub devices: Vec<String>,
}

/// What the guest's init has reported. The default is nothing yet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestStatus {
    /// Whether init has said hello over the guest control channel.
    pub init_ready: bool,
    /// The session's process id in the guest, once it started.
    pub session_pid: Option<u32>,
    /// How the session ended, once it did.
    pub exit: Option<SessionOutcome>,
}

/// The session's audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStatus {
    /// The sequence number the writer gives the next record it writes.
    pub next_seq: u64,
    /// Whether the writer has failed, which stops the VM.
    pub failed: bool,
}

/// The parameters of `stop`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopParams {
    /// `graceful` when absent.
    #[serde(default)]
    pub mode: StopMode,
    /// How long a graceful stop waits for the guest;
    /// [`DEFAULT_STOP_TIMEOUT_MS`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl StopParams {
    /// `timeout_ms`, or [`DEFAULT_STOP_TIMEOUT_MS`] when it is absent.
    pub fn effective_timeout_ms(&self) -> u64 {
        self.timeout_ms.unwrap_or(DEFAULT_STOP_TIMEOUT_MS)
    }
}

/// How to stop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopMode {
    /// Ask the guest to end its session first.
    #[default]
    Graceful,
    /// Stop the vCPUs at once.
    Force,
}

/// The session's terminal the `pty.*` ops name: the only one, `main`.
pub const PTY_SESSION: &str = "main";

/// The parameters of `pty.attach`: `{"session":"main","mode":"rw"|"ro",
/// "replay_bytes":N}`. The response is `{"raw":true}`, after which the
/// connection is the terminal's bytes, both ways (see
/// [`PtyMode`]); `replay_bytes` (0 when absent) of the terminal's latest
/// output come first, at most the server's scrollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyAttachParams {
    /// [`PTY_SESSION`].
    pub session: String,
    pub mode: PtyMode,
    #[serde(default)]
    pub replay_bytes: u64,
}

/// How a client attaches to the session's terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PtyMode {
    /// Read and write: what the client sends is typed into the session.
    Rw,
    /// Read only: what the client sends is discarded.
    Ro,
}

/// The parameters of `pty.resize`: `{"session":"main","rows":R,"cols":C}`,
/// each of `rows` and `cols` from 1 to 65535. The response is `{}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyResizeParams {
    /// [`PTY_SESSION`].
    pub session: String,
    pub rows: u16,
    pub cols: u16,
}

impl PtyResizeParams {
    /// Whether the size is one a terminal can have: neither side 0.
    pub fn check(&self) -> Result<(), String> {
        if self.rows == 0 || self.cols == 0 {
            return Err(format!(
                "a terminal of {} by {}: rows and cols are 1 to 65535",
                self.rows, self.cols
            ));
        }
        Ok(())
    }
}

/// The reason of a [`PtyDetached`] whose client fell too far behind.
pub const PTY_DETACHED_SLOW: &str = "slow";

/// `{"v":1,"event":"pty.detached","reason":"slow"}`: the server detached
/// the client from the session's terminal. It is the last line of an
/// attached connection, after its last raw byte; the server then closes
/// the connection. `slow`: the client left more of the terminal's output
/// unread than the server keeps for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyDetached {
    pub v: u32,
    /// `"pty.detached"`.
    pub event: String,
    pub reason: String,
}

impl PtyDetached {
    /// The client fell too far behind: [`PTY_DETACHED_SLOW`].
    pub fn slow() -> PtyDetached {
        PtyDetached {
            v: VERSION,
            event: "pty.detached".to_owned(),
            reason: PTY_DETACHED_SLOW.to_owned(),
        }
    }
}

/// The one line `boxcar run --ready-fd N` writes to fd N once the control
/// socket is bound: `{"ready":true,"control":"<path>","session_id":"<id>"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ready {
    pub ready: bool,
    /// The control socket's path.
    pub control: String,
    pub session_id: String,
}

/// Why a line is not a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestError {
    /// The line's `id`, when it had one that could be read, so that the
    /// error response can carry it.
    pub id: Option<u64>,
    pub code: ErrorCode,
    pub message: String,
}

impl RequestError {
    fn new(id: Option<u64>, code: ErrorCode, message: impl Into<String>) -> RequestError {
        RequestError {
            id,
            code,
            message: message.into(),
        }
    }

    /// The error response for the line.
    pub fn into_response(self) -> Response {
        Response::failure(
            self.id.unwrap_or(0),
            ErrorBody::new(self.code, self.message),
        )
    }
}

/// Parses one line, with or without its newline, into a request: at most
/// [`MAX_LINE`] bytes, UTF-8, a JSON object with `v` equal to [`VERSION`],
/// an unsigned integer `id` and a string `op`. `unsupported_version` for
/// another `v`, `bad_request` for everything else.
pub fn parse_line(line: &[u8]) -> Result<Request, ErrorCode> {
    parse_request(line).map_err(|error| error.code)
}

/// [`parse_line`], with the id of the line and a message when it is not a
/// request.
pub fn parse_request(line: &[u8]) -> Result<Request, RequestError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let bad = |id, message: &str| RequestError::new(id, ErrorCode::BadRequest, message);
    if line.len() > MAX_LINE {
        return Err(RequestError::new(
            None,
            ErrorCode::BadRequest,
            format!("the line is over {MAX_LINE} bytes"),
        ));
    }
    let text = std::str::from_utf8(line).map_err(|_| bad(None, "the line is not UTF-8"))?;
    let value: Value = serde_json::from_str(text).map_err(|error| {
        RequestError::new(
            None,
            ErrorCode::BadRequest,
            format!("the line is not JSON: {error}"),
        )
    })?;
    let Value::Object(mut fields) = value else {
        return Err(bad(None, "a request is a JSON object"));
    };
    let id = fields.get("id").and_then(Value::as_u64);
    match fields.get("v") {
        None => return Err(bad(id, "the request has no \"v\"")),
        Some(v) => match v.as_u64() {
            Some(v) if v == u64::from(VERSION) => {}
            Some(v) => {
                return Err(RequestError::new(
                    id,
                    ErrorCode::UnsupportedVersion,
                    format!("version {v} is not supported; this server speaks {VERSION}"),
                ))
            }
            None => return Err(bad(id, "\"v\" is not an unsigned integer")),
        },
    }
    let Some(id) = id else {
        return Err(bad(None, "the request has no unsigned integer \"id\""));
    };
    let op = match fields.remove("op") {
        Some(Value::String(op)) => op,
        Some(_) => return Err(bad(Some(id), "\"op\" is not a string")),
        None => return Err(bad(Some(id), "the request has no \"op\"")),
    };
    fields.remove("v");
    fields.remove("id");
    Ok(Request {
        v: VERSION,
        id,
        op,
        params: Value::Object(fields),
    })
}

/// A message that cannot be sent as a line.
#[derive(Debug, thiserror::Error)]
pub enum LineError {
    #[error("the message is {0} bytes, over the {MAX_LINE}-byte line limit")]
    TooLong(usize),
    #[error("the message does not serialize: {0}")]
    Json(#[from] serde_json::Error),
}

/// `message` as one line: its JSON and a newline, refused when the JSON is
/// over [`MAX_LINE`] bytes. Both sides send through it, so no message the
/// other side would refuse leaves.
pub fn to_line<T: Serialize>(message: &T) -> Result<Vec<u8>, LineError> {
    let mut line = serde_json::to_vec(message)?;
    if line.len() > MAX_LINE {
        return Err(LineError::TooLong(line.len()));
    }
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn line(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn parse_line_rejects_oversize_bad_version_and_missing_fields() {
        let good = parse_line(br#"{"v":1,"id":7,"op":"status"}"#).unwrap();
        assert_eq!((good.v, good.id, good.op.as_str()), (1, 7, "status"));
        assert_eq!(good.params, json!({}));
        // The terminating newline is not part of the line.
        assert_eq!(
            parse_line(b"{\"v\":1,\"id\":7,\"op\":\"status\"}\n").unwrap(),
            good
        );

        // At most MAX_LINE bytes, not counting the newline.
        let pad = |len: usize| {
            let base = line(&json!({"v": 1, "id": 1, "op": "status", "pad": ""}));
            let fill = "x".repeat(len - base.len());
            line(&json!({"v": 1, "id": 1, "op": "status", "pad": fill}))
        };
        let full = pad(MAX_LINE);
        assert_eq!(full.len(), MAX_LINE);
        assert!(parse_line(&full).is_ok());
        let mut with_newline = full.clone();
        with_newline.push(b'\n');
        assert!(parse_line(&with_newline).is_ok());
        assert_eq!(parse_line(&pad(MAX_LINE + 1)), Err(ErrorCode::BadRequest));

        let bad: [&[u8]; 13] = [
            b"",
            b"not json",
            b"[1,2]",
            b"\"status\"",
            b"{\"v\":1,\"id\":1,\"op\":\"st\xffatus\"}",
            br#"{"id":1,"op":"status"}"#,
            br#"{"v":"1","id":1,"op":"status"}"#,
            br#"{"v":1,"op":"status"}"#,
            br#"{"v":1,"id":-1,"op":"status"}"#,
            br#"{"v":1,"id":"1","op":"status"}"#,
            br#"{"v":1,"id":1}"#,
            br#"{"v":1,"id":1,"op":7}"#,
            br#"{"v":1,"id":1,"op":"status"} trailing"#,
        ];
        for bytes in bad {
            assert_eq!(
                parse_line(bytes),
                Err(ErrorCode::BadRequest),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
        for version in [0, 2, 99] {
            let request = line(&json!({"v": version, "id": 1, "op": "status"}));
            assert_eq!(parse_line(&request), Err(ErrorCode::UnsupportedVersion));
        }
    }

    /// The error response carries the request's id whenever it can be
    /// read, so a client waiting on that id gets its answer.
    #[test]
    fn a_refused_request_keeps_its_id() {
        let cases: [(&[u8], Option<u64>, ErrorCode); 5] = [
            (
                br#"{"v":2,"id":9,"op":"status"}"#,
                Some(9),
                ErrorCode::UnsupportedVersion,
            ),
            (br#"{"v":1,"id":9}"#, Some(9), ErrorCode::BadRequest),
            (br#"{"id":9,"op":"status"}"#, Some(9), ErrorCode::BadRequest),
            (br#"{"v":1,"op":"status"}"#, None, ErrorCode::BadRequest),
            (b"{", None, ErrorCode::BadRequest),
        ];
        for (bytes, id, code) in cases {
            let error = parse_request(bytes).unwrap_err();
            assert_eq!((error.id, error.code), (id, code), "{error:?}");
            let response = serde_json::to_value(error.into_response()).unwrap();
            assert_eq!(response["id"], json!(id.unwrap_or(0)));
            assert_eq!(response["ok"], json!(false));
            assert_eq!(response["error"]["code"], json!(code.as_str()));
        }
    }

    #[test]
    fn request_params_are_the_other_fields_and_unknown_ones_are_kept() {
        let request =
            parse_line(br#"{"v":1,"id":3,"op":"stop","mode":"force","extra":[1]}"#).unwrap();
        assert_eq!(request.params, json!({"mode": "force", "extra": [1]}));
        let params: StopParams = serde_json::from_value(request.params.clone()).unwrap();
        assert_eq!(params.mode, StopMode::Force);
        assert_eq!(params.effective_timeout_ms(), DEFAULT_STOP_TIMEOUT_MS);

        // And back: the parameters sit beside v, id and op.
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"v": 1, "id": 3, "op": "stop", "mode": "force", "extra": [1]})
        );
        assert_eq!(
            serde_json::to_value(Request::new(4, "status", Value::Null)).unwrap(),
            json!({"v": 1, "id": 4, "op": "status"})
        );
    }

    #[test]
    fn error_codes_serialize_snake_case() {
        let codes = [
            (ErrorCode::BadRequest, "bad_request"),
            (ErrorCode::UnsupportedVersion, "unsupported_version"),
            (ErrorCode::UnknownOp, "unknown_op"),
            (ErrorCode::InvalidState, "invalid_state"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::Busy, "busy"),
            (ErrorCode::RateLimited, "rate_limited"),
            (ErrorCode::Internal, "internal"),
        ];
        for (code, name) in codes {
            assert_eq!(serde_json::to_value(code).unwrap(), json!(name));
            assert_eq!(
                serde_json::from_value::<ErrorCode>(json!(name)).unwrap(),
                code
            );
            assert_eq!(code.as_str(), name);
        }
        assert!(serde_json::from_value::<ErrorCode>(json!("BadRequest")).is_err());
    }

    #[test]
    fn responses_have_a_result_or_an_error() {
        let ok = Response::success(5, json!({"accepted": true}));
        assert_eq!(
            serde_json::to_value(&ok).unwrap(),
            json!({"v": 1, "id": 5, "ok": true, "result": {"accepted": true}})
        );
        let failed = Response::failure(6, ErrorBody::unknown_op("nope"));
        assert_eq!(
            serde_json::to_value(&failed).unwrap(),
            json!({
                "v": 1, "id": 6, "ok": false,
                "error": {"code": "unknown_op", "message": "no op \"nope\""},
            })
        );
        assert_eq!(ok.into_result(), Ok(json!({"accepted": true})));
        assert_eq!(failed.into_result().unwrap_err().code, ErrorCode::UnknownOp);
    }

    #[test]
    fn hello_round_trips() {
        let hello = Hello::new(
            "boxcar/0.1.0",
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            vec!["pty".into()],
        );
        let wire = json!({
            "v": 1,
            "event": "hello",
            "protocol": "boxcar.control",
            "versions": [1],
            "server": "boxcar/0.1.0",
            "session_id": "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            "capabilities": ["pty"],
        });
        assert_eq!(serde_json::to_value(&hello).unwrap(), wire);
        assert_eq!(serde_json::from_value::<Hello>(wire).unwrap(), hello);
    }

    /// The wire shape of `status`, `state` and the ready line; unknown
    /// fields from a newer server are ignored.
    #[test]
    fn status_state_and_ready_have_their_wire_shapes() {
        let status = Status {
            state: VmState::Running,
            session_id: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".into(),
            pid: 42,
            uptime_ms: 1500,
            vcpus: 2,
            mem_mib: 512,
            guest: GuestStatus {
                init_ready: true,
                session_pid: Some(7),
                exit: Some(SessionOutcome {
                    code: Some(3),
                    signal: None,
                }),
            },
            audit: AuditStatus {
                next_seq: 12,
                failed: false,
            },
            devices: vec!["fs:root".into(), "fs:workspace".into()],
        };
        let mut wire = json!({
            "state": "running",
            "session_id": "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            "pid": 42,
            "uptime_ms": 1500,
            "vcpus": 2,
            "mem_mib": 512,
            "guest": {"init_ready": true, "session_pid": 7, "exit": {"code": 3, "signal": null}},
            "audit": {"next_seq": 12, "failed": false},
            "devices": ["fs:root", "fs:workspace"],
        });
        assert_eq!(serde_json::to_value(&status).unwrap(), wire);
        wire["new_field"] = json!(1);
        assert_eq!(serde_json::from_value::<Status>(wire).unwrap(), status);

        for (state, name) in [
            (VmState::Booting, "booting"),
            (VmState::Running, "running"),
            (VmState::Stopping, "stopping"),
            (VmState::Stopped, "stopped"),
        ] {
            assert_eq!(
                serde_json::to_value(StateEvent::new(state)).unwrap(),
                json!({"v": 1, "event": "state", "state": name})
            );
        }
        assert!(VmState::Booting < VmState::Running && VmState::Stopping < VmState::Stopped);

        let ready = Ready {
            ready: true,
            control: "/run/user/1000/boxcar/s/control.sock".into(),
            session_id: "s".into(),
        };
        assert_eq!(
            String::from_utf8(to_line(&ready).unwrap()).unwrap(),
            "{\"ready\":true,\"control\":\"/run/user/1000/boxcar/s/control.sock\",\"session_id\":\"s\"}\n"
        );
    }

    #[test]
    fn stop_params_default_to_graceful_with_the_default_timeout() {
        let params: StopParams = serde_json::from_value(json!({})).unwrap();
        assert_eq!(params, StopParams::default());
        assert_eq!(params.mode, StopMode::Graceful);
        assert_eq!(params.effective_timeout_ms(), 5000);
        let params: StopParams =
            serde_json::from_value(json!({"mode": "force", "timeout_ms": 10})).unwrap();
        assert_eq!(
            (params.mode, params.effective_timeout_ms()),
            (StopMode::Force, 10)
        );
        assert!(serde_json::from_value::<StopParams>(json!({"mode": "later"})).is_err());
        assert_eq!(
            serde_json::to_value(StopParams::default()).unwrap(),
            json!({"mode": "graceful"})
        );
    }

    /// `pty.attach` and `pty.resize` parameters, and `pty.detached`, on the
    /// wire; a mode or a size outside the protocol does not parse or does
    /// not check.
    #[test]
    fn pty_params_and_events_have_their_wire_shapes() {
        let attach: PtyAttachParams =
            serde_json::from_value(json!({"session": "main", "mode": "ro", "replay_bytes": 64}))
                .unwrap();
        assert_eq!(
            attach,
            PtyAttachParams {
                session: PTY_SESSION.into(),
                mode: PtyMode::Ro,
                replay_bytes: 64
            }
        );
        let rw: PtyAttachParams =
            serde_json::from_value(json!({"session": "main", "mode": "rw", "extra": 1})).unwrap();
        assert_eq!((rw.mode, rw.replay_bytes), (PtyMode::Rw, 0));
        for bad in [
            json!({"session": "main", "mode": "write"}),
            json!({"session": "main"}),
            json!({"mode": "rw"}),
            json!({"session": "main", "mode": "rw", "replay_bytes": -1}),
        ] {
            assert!(
                serde_json::from_value::<PtyAttachParams>(bad.clone()).is_err(),
                "{bad}"
            );
        }

        let resize: PtyResizeParams =
            serde_json::from_value(json!({"session": "main", "rows": 40, "cols": 120})).unwrap();
        assert_eq!((resize.rows, resize.cols), (40, 120));
        assert_eq!(resize.check(), Ok(()));
        let edge: PtyResizeParams =
            serde_json::from_value(json!({"session": "main", "rows": 1, "cols": 65535})).unwrap();
        assert_eq!(edge.check(), Ok(()));
        let zero: PtyResizeParams =
            serde_json::from_value(json!({"session": "main", "rows": 0, "cols": 80})).unwrap();
        assert!(zero.check().is_err());
        for bad in [
            json!({"session": "main", "rows": 65536, "cols": 80}),
            json!({"session": "main", "rows": 24}),
            json!({"session": "main", "rows": -1, "cols": 80}),
        ] {
            assert!(
                serde_json::from_value::<PtyResizeParams>(bad.clone()).is_err(),
                "{bad}"
            );
        }

        assert_eq!(
            String::from_utf8(to_line(&PtyDetached::slow()).unwrap()).unwrap(),
            "{\"v\":1,\"event\":\"pty.detached\",\"reason\":\"slow\"}\n"
        );
    }

    /// Every message leaves as one line under the cap; one over it is
    /// refused rather than sent.
    #[test]
    fn to_line_caps_every_message_at_max_line() {
        let small = to_line(&StateEvent::new(VmState::Stopped)).unwrap();
        assert_eq!(small.last(), Some(&b'\n'));
        assert_eq!(small.iter().filter(|&&b| b == b'\n').count(), 1);

        let filler = |len: usize| {
            let base = serde_json::to_vec(&Response::success(1, json!(""))).unwrap();
            Response::success(1, json!("x".repeat(len - base.len())))
        };
        assert_eq!(to_line(&filler(MAX_LINE)).unwrap().len(), MAX_LINE + 1);
        let error = to_line(&filler(MAX_LINE + 1)).unwrap_err();
        assert!(matches!(error, LineError::TooLong(n) if n == MAX_LINE + 1));
        assert_eq!(
            error.to_string(),
            "the message is 1048577 bytes, over the 1048576-byte line limit"
        );
        // A line to_line produced parses back.
        let request = Request::new(1, "status", json!({"pad": "x".repeat(1000)}));
        assert_eq!(parse_line(&to_line(&request).unwrap()).unwrap(), request);
    }
}
