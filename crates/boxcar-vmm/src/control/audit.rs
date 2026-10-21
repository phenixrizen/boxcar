// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `audit.subscribe`: a connection's live view of the session's audit log.
//!
//! The op subscribes in band with the audit writer (see
//! [`boxcar_audit::AuditSink::subscribe`]), answers with where the log's
//! end was, and starts one forwarder thread for the subscription, which
//! reads [`Subscription::next_timeout`] and queues each item on the
//! connection's outbox with [`ConnEvents::send_paced`]. The thread starts
//! only once the response is queued (the connection's thread releases it
//! right after), so no event comes before the response.
//!
//! The writer never waits for the connection, and the connection never
//! waits for the writer: a client that reads slower than the log is written
//! is paced (the forwarder waits for room in the outbox, so its queue fills
//! and the writer drops it, and the client is told with `audit.lagged` and
//! gets what it missed from the log), and one that reads nothing for the
//! stall limit is cut off, to reconnect with `from_seq`.
//!
//! A connection holds at most [`MAX_AUDIT_SUBSCRIPTIONS`] subscriptions,
//! until it closes: the forwarders stop and are joined with it.
//!
//! `audit.verify` checks a stretch of the log on disk against the writer's
//! head: it asks the writer for the head in band
//! ([`boxcar_audit::AuditSink::head`]), then walks the log with
//! [`boxcar_audit::verify_range`] on the connection's own thread, as every op
//! runs. The walk looks at the connection's closing flag before each
//! record: the server's shutdown closes every connection, so a stopping VMM
//! never waits on a walk.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boxcar_audit::{
    verify_range, AuditSink, Filter, HeadError, Item, Next, RangeError, RangeLimits, Subscription,
    DEFAULT_QUEUE,
};
use boxcar_proto::control::{
    AuditEvent, AuditLagged, AuditSubscribeParams, AuditSubscribed, AuditVerify, AuditVerifyParams,
    ErrorBody, ErrorCode, Request, MAX_AUDIT_SUBSCRIPTIONS, MAX_AUDIT_VERIFY_MESSAGE,
};
use boxcar_proto::limits::truncate_utf8;
use serde_json::Value;

use super::conn::{Conn, PACE_STALL};
use super::ops::{params, ConnCtx, ConnEvents};

/// How long a forwarder waits for a record before it looks at whether its
/// connection has gone. A replay looks as often as
/// [`boxcar_audit::REPLAY_YIELD`] records passed over.
const TICK: Duration = Duration::from_millis(50);

/// How far a subscription may fall behind, and how long a client may take
/// nothing: the defaults, which tests turn down.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// The records a subscription's queue holds before the writer drops it.
    pub(crate) queue: usize,
    /// How long a client may take no byte before it is cut off.
    pub(crate) stall: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            queue: DEFAULT_QUEUE,
            stall: PACE_STALL,
        }
    }
}

/// A connection's audit subscriptions.
#[derive(Default)]
pub(crate) struct AuditSubs {
    /// The id of the latest subscription: they count from 1.
    last_id: u64,
    forwarders: Vec<Forwarder>,
    /// Forwarders waiting for the response to be queued.
    unreleased: Vec<Sender<()>>,
}

struct Forwarder {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AuditSubs {
    /// How many subscriptions are running. One whose log has ended is not.
    fn running(&mut self) -> usize {
        self.forwarders
            .retain(|forwarder| forwarder.thread.as_ref().is_some_and(|t| !t.is_finished()));
        self.forwarders.len()
    }

    /// Lets the forwarders started since the last call begin.
    pub(crate) fn release(&mut self) {
        for go in self.unreleased.drain(..) {
            // A forwarder that is already gone has nothing to be released.
            let _ = go.send(());
        }
    }
}

impl Drop for AuditSubs {
    /// Stops the forwarders and waits for them. Each looks at its flag
    /// within [`TICK`], or as soon as its connection, which closes before
    /// this, wakes it from waiting for the client.
    fn drop(&mut self) {
        for forwarder in &self.forwarders {
            forwarder.stop.store(true, Ordering::Release);
        }
        self.unreleased.clear();
        for forwarder in &mut self.forwarders {
            if let Some(thread) = forwarder.thread.take() {
                if thread.join().is_err() {
                    tracing::error!("control: an audit forwarder panicked");
                }
            }
        }
    }
}

/// `audit.subscribe`: see the module docs and [`super::ops`].
pub(crate) fn subscribe(
    audit: &AuditSink,
    ctx: &mut ConnCtx,
    req: &Request,
    limits: Limits,
) -> Result<Value, ErrorBody> {
    let params: AuditSubscribeParams = params(req)?;
    params
        .check()
        .map_err(|message| ErrorBody::new(ErrorCode::BadRequest, message))?;
    let events = ctx
        .events
        .clone()
        .ok_or_else(|| ErrorBody::new(ErrorCode::Internal, "this connection cannot hear events"))?;
    if ctx.audit.running() >= MAX_AUDIT_SUBSCRIPTIONS {
        return Err(ErrorBody::new(
            ErrorCode::Busy,
            format!(
                "a connection holds at most {MAX_AUDIT_SUBSCRIPTIONS} audit subscriptions; \
                 close one (or the connection) first"
            ),
        ));
    }
    let filter = Filter {
        kinds: params.types,
        pid: params.pid,
        min_score: params.min_score,
    };
    let subscription = audit
        .subscribe_with_queue(params.from_seq.unwrap_or(1), filter, limits.queue)
        .map_err(|error| {
            let code = if error.kind() == std::io::ErrorKind::BrokenPipe {
                ErrorCode::InvalidState
            } else {
                ErrorCode::Internal
            };
            ErrorBody::new(code, format!("cannot subscribe to the audit log: {error}"))
        })?;
    let next_seq = subscription.next_seq();
    let sub = ctx.audit.last_id + 1;
    let stop = Arc::new(AtomicBool::new(false));
    let (go, released) = mpsc::channel();
    let thread = thread::Builder::new()
        .name("audit-forward".into())
        .spawn({
            let stop = Arc::clone(&stop);
            move || {
                boxcar_confine::at_thread_start();
                forward(subscription, sub, &events, &stop, &released, limits.stall)
            }
        })
        .map_err(|error| {
            ErrorBody::new(
                ErrorCode::Internal,
                format!("cannot start the audit forwarder: {error}"),
            )
        })?;
    ctx.audit.last_id = sub;
    ctx.audit.forwarders.push(Forwarder {
        stop,
        thread: Some(thread),
    });
    ctx.audit.unreleased.push(go);
    serde_json::to_value(AuditSubscribed { next_seq, sub })
        .map_err(|error| ErrorBody::new(ErrorCode::Internal, format!("the result: {error}")))
}

/// The forwarder thread of one subscription: waits to be released, then
/// moves each item to the connection until the log ends, the connection
/// goes, or `stop` is set.
fn forward(
    mut subscription: Subscription,
    sub: u64,
    events: &ConnEvents,
    stop: &AtomicBool,
    released: &mpsc::Receiver<()>,
    stall: Duration,
) {
    if released.recv().is_err() {
        return;
    }
    while !stop.load(Ordering::Acquire) {
        let sent = match subscription.next_timeout(TICK) {
            Ok(Next::Item(Item::Record(record))) => {
                events.send_paced(&AuditEvent::new(sub, &*record), stall)
            }
            Ok(Next::Item(Item::Lagged { resume_seq })) => {
                events.send_paced(&AuditLagged::new(sub, resume_seq), stall)
            }
            Ok(Next::Idle) => events.is_open(),
            // The log has ended: the VM is stopping, and the server says so
            // and closes the connection.
            Ok(Next::End) => return,
            Err(error) => {
                // The stream cannot go on, and a client must not read on
                // as if it did: ending the connection says so. Debug, not
                // warn: this thread is joined by the connection's, which the
                // stop sequence joins, and a stalled stderr must not hold
                // the stop (the writer's failure, the usual cause, is
                // logged by the writer itself).
                tracing::debug!("control: audit subscription {sub} failed: {error}; closing");
                events.close();
                return;
            }
        };
        if !sent {
            return;
        }
    }
}

/// `audit.verify`: see the module docs and [`super::ops`]. `limits` bound
/// the stretch one call checks.
pub(crate) fn verify(
    audit: &AuditSink,
    ctx: &ConnCtx,
    req: &Request,
    limits: RangeLimits,
) -> Result<Value, ErrorBody> {
    let params: AuditVerifyParams = if req.params.is_null() {
        AuditVerifyParams::default()
    } else {
        params(req)?
    };
    // A closed writer has no head, and a failed one none it can vouch for:
    // it published its failure before its rollback.
    let head = audit.head().map_err(|error: HeadError| {
        ErrorBody::new(
            ErrorCode::InvalidState,
            format!("cannot verify the audit log: {error}"),
        )
    })?;
    // A connection that cannot hear events is one a test made: nothing
    // closes it.
    let conn = ctx.events.as_ref().and_then(ConnEvents::conn);
    let open = AtomicBool::new(false);
    let closing = conn.as_deref().map_or(&open, Conn::closing_flag);
    let from_seq = params.from_seq.unwrap_or(1);
    let report = verify_range(
        &head.session_dir,
        from_seq,
        (head.seq, head.hash),
        limits,
        closing,
    )
    .map_err(refusal)?;
    serde_json::to_value(AuditVerify {
        from_seq: report.from_seq,
        from_prev: report.from_prev,
        to_seq: report.to_seq,
        to_hash: report.to_hash,
        head_seq: head.seq,
        head_hash: head.hash,
        checkpoints: report.checkpoints,
        more: report.more,
    })
    .map_err(|error| ErrorBody::new(ErrorCode::Internal, format!("the result: {error}")))
}

/// The error `audit.verify` answers a walk that did not finish with.
fn refusal(error: RangeError) -> ErrorBody {
    match error {
        RangeError::PastHead { from_seq, head_seq } => ErrorBody::new(
            ErrorCode::BadRequest,
            format!("from_seq {from_seq} is past the head of the audit log, seq {head_seq}"),
        ),
        RangeError::Cancelled => ErrorBody::new(ErrorCode::InvalidState, "the session is stopping"),
        RangeError::Break(error) => ErrorBody::new(
            ErrorCode::Internal,
            truncate_utf8(&error.to_string(), MAX_AUDIT_VERIFY_MESSAGE).0,
        ),
    }
}

#[cfg(test)]
mod tests {
    use boxcar_audit::VerifyError;
    use boxcar_proto::control::MAX_LINE;

    use super::*;

    /// A break is `internal`, with the verifier's message cut to 512 bytes
    /// on a character boundary; a cancelled walk is the session stopping,
    /// and a `from_seq` past the head a bad request.
    #[test]
    fn a_walk_that_did_not_finish_is_refused_by_its_kind() {
        let short = refusal(RangeError::Break(VerifyError::Gap {
            expected_seq: 3,
            got_seq: 4,
        }));
        assert_eq!(short.code, ErrorCode::Internal);
        assert_eq!(short.message, "sequence gap: expected seq 3, got seq 4");
        let long = refusal(RangeError::Break(VerifyError::Layout {
            reason: "é".repeat(MAX_LINE),
        }));
        assert_eq!(long.code, ErrorCode::Internal);
        assert!(long.message.len() <= MAX_AUDIT_VERIFY_MESSAGE);
        assert!(long.message.len() > MAX_AUDIT_VERIFY_MESSAGE - 4);
        assert!(long.message.ends_with('…'), "{}", long.message);

        let stopping = refusal(RangeError::Cancelled);
        assert_eq!(
            (stopping.code, stopping.message.as_str()),
            (ErrorCode::InvalidState, "the session is stopping")
        );
        let past = refusal(RangeError::PastHead {
            from_seq: 9,
            head_seq: 8,
        });
        assert_eq!(past.code, ErrorCode::BadRequest);
        assert!(past.message.contains("9") && past.message.contains("8"));
    }
}
