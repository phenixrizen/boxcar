// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the control ops do: [`Ops`], and the VMM's implementation,
//! [`VmmOps`].
//!
//! The connection serves `status` with [`Ops::status`] and `stop` with
//! [`Ops::stop`] once its parameters parse; every other op goes to
//! [`Ops::dispatch`], where later ops (`pty.*`, `audit.*`, `policy.*`) are
//! added.

use std::fmt;
use std::os::unix::net::UnixStream;

use boxcar_proto::control::{ErrorBody, Request, Status, StopMode, StopParams};
use serde_json::{json, Value};

use crate::lifecycle::{StopReason, VmmHandle, GRACEFUL_STOP_MARGIN};

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

    fn dispatch(&self, _conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody> {
        Err(ErrorBody::unknown_op(&req.op))
    }
}

#[cfg(test)]
mod tests {
    use boxcar_proto::control::{ErrorCode, VmState};

    use super::*;

    #[test]
    fn the_vmm_ops_report_the_handle_and_stop_it() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = crate::lifecycle::test_handle(tmp.path());
        let ops = VmmOps::new(handle.clone());
        assert_eq!(ops.status(), handle.status());
        assert!(ops.capabilities().is_empty());

        let mut conn = ConnCtx {
            peer_pid: 1,
            peer_uid: 0,
            raw_upgrade: None,
        };
        let other = Request::new(1, "pty.attach", Value::Null);
        assert_eq!(
            ops.dispatch(&mut conn, &other).unwrap_err().code,
            ErrorCode::UnknownOp
        );

        let force = StopParams {
            mode: StopMode::Force,
            timeout_ms: None,
        };
        assert_eq!(ops.stop(force).unwrap(), json!({"accepted": true}));
        assert_eq!(handle.state(), VmState::Stopping);
        writer.close().unwrap();
    }
}
