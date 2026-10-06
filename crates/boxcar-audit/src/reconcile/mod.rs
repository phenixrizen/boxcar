// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The reconciler: a subscriber to the session's log that joins what the
//! two rings say and writes `finding` records back into the same log.
//!
//! It reads every record in seq order ([`AuditSink::subscribe`] from 1),
//! keeps the state of `state` (the processes and threads ring 1 reported,
//! the flows ring 0 relays, what the sensor said about itself, the DNS
//! cache, the clock pairing), and applies the rules of `rules`: each
//! finding names its category, score and rule, says in words what it saw,
//! and lists the records it read as evidence. `docs/reconciler.md` is the
//! rule book. Findings are emitted with the blocking `emit`, at
//! `Priority::Critical` from a score of 70; the reconciler skips its own
//! findings when they come back round.
//!
//! Joins: a filesystem effect joins a process through the thread the FUSE
//! header named, which ring 1's fork and exec records (threads included)
//! tie to a process whose life, widened by [`JOIN_WINDOW_NS`] on both
//! sides, covers the effect's host time; a TCP flow joins the
//! `proc.tcp_connect` with the same 4-tuple within the window, either
//! order. An effect with no process waits [`PENDING_NS`] for a late exec
//! before it is `unattributed_effect`. Timers (the sensor's silence, the
//! wait) run on a [`Clock`] the tests pause; the records' own `ts_host_ns`
//! orders everything else.
//!
//! Tool spans (`spans`): a `tool.open` from the gate opens one, the
//! `tool.close` in the agent's next request closes it, and the processes
//! and effects between them are attributed to it; the span's membership
//! is written as `span.effects` at close and, for a span still open, at
//! `vmm.stop`. Findings inside a span carry its id, and the [`SpanIndex`]
//! the control socket's `span.list` reads is kept current.
//!
//! The thread ends with the log (the subscription's end), at `vmm.stop`
//! after a last tick, or when [`ReconcilerHandle::finish`] asks.

pub mod clock;
mod dns;
mod paths;
mod rules;
pub mod spans;
mod state;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_proto::{Finding, Payload, Record, Ring, SpanEffects, SpanRef};

use crate::sink::{AuditSink, Priority, Submission};
use crate::subscribe::{Item, Next};
use crate::Filter;
pub use clock::{Clock, ManualClock, SystemClock};
pub use spans::SpanIndex;
use spans::Spans;
use state::State;

/// How often the timers are looked at while nothing arrives.
pub const TICK: Duration = Duration::from_secs(1);
/// How far apart, in host time, an effect and the process record it
/// belongs to may be.
pub const JOIN_WINDOW_NS: u64 = 500 * 1_000_000;
/// How long an effect with no process waits for a late exec.
pub const PENDING_NS: u64 = 2 * 1_000_000_000;
/// Without a heartbeat for this long while ring 0 is active, the sensor is
/// silent.
pub const SILENCE_NS: u64 = 3 * 1_000_000_000;
/// How long after `session.start` the sensor must have reported.
pub const ATTACH_DEADLINE_NS: u64 = 5 * 1_000_000_000;
/// A clock pairing with a round trip over this is unsure.
pub const SYNC_RTT_UNSURE_NS: u64 = 2 * 1_000_000;
/// Without a `sync` for this long while ring 1 is alive, the pairing is stale.
pub const SYNC_STALE_NS: u64 = 30 * 1_000_000_000;
/// How long after a subscription gap findings stay low in confidence.
pub const LAG_UNSURE_NS: u64 = 60 * 1_000_000_000;
/// What a low-confidence finding loses.
pub const LOW_CONFIDENCE_PENALTY: u8 = 20;
/// Findings scoring this or more are written through to disk at once.
pub const CRITICAL_SCORE: u8 = 70;

/// How the reconciler is set up.
pub struct ReconcileConfig {
    /// Whether the VM runs a sensor: without one, its silence is no finding.
    pub sensor_expected: bool,
    pub clock: Arc<dyn Clock>,
    /// The index `span.list` reads, kept current when given.
    pub spans: Option<SpanIndex>,
}

/// The reconciler's state machine: feed it records and ticks, take the
/// findings and the span records. [`Reconciler::spawn`] runs it on a
/// thread off the log.
pub struct Reconciler {
    cfg: ReconcileConfig,
    state: State,
    spans: Spans,
}

impl Reconciler {
    pub fn new(cfg: ReconcileConfig) -> Reconciler {
        let spans = Spans::new(cfg.spans.clone());
        Reconciler {
            cfg,
            state: State::default(),
            spans,
        }
    }

    /// Reads one record and returns the findings it leads to.
    pub fn observe(&mut self, record: &Record) -> Vec<Finding> {
        if record.kind == "finding" || record.kind.starts_with("span.") {
            return Vec::new();
        }
        rules::observe(&mut self.state, &mut self.spans, &self.cfg, record)
    }

    /// Looks at the timers at host time `now_ns`.
    pub fn on_tick(&mut self, now_ns: u64) -> Vec<Finding> {
        rules::on_tick(&mut self.state, &mut self.spans, &self.cfg, now_ns)
    }

    /// The `span.effects` records made since the last call: a span's
    /// membership at its close, or at `vmm.stop` while still open.
    pub fn take_records(&mut self) -> Vec<SpanEffects> {
        self.spans.take_records()
    }

    /// The session's id, once a record has shown it: the trace id of the
    /// spans.
    pub fn session_id(&self) -> Option<&str> {
        self.state.session_id.as_deref()
    }

    /// The subscription saw a gap (it lagged and resumed): what it did not
    /// see cannot be joined, so findings stay low in confidence for a while.
    pub fn on_gap(&mut self, now_ns: u64) {
        self.state.lag_until = now_ns + LAG_UNSURE_NS;
    }

    /// Whether `vmm.stop` has been seen.
    pub fn stopped(&self) -> bool {
        self.state.stopped
    }

    /// Starts the reconciler on a thread named `reconcile`, subscribed to
    /// `sink` from the first record.
    pub fn spawn(sink: AuditSink, cfg: ReconcileConfig) -> io::Result<ReconcilerHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("reconcile".into())
            .spawn(move || run(sink, cfg, &flag))?;
        Ok(ReconcilerHandle {
            stop,
            thread: Some(thread),
        })
    }
}

/// The thread's body.
fn run(sink: AuditSink, cfg: ReconcileConfig, stop: &AtomicBool) {
    let clock = Arc::clone(&cfg.clock);
    let mut reconciler = Reconciler::new(cfg);
    let Ok(mut subscription) = sink.subscribe(1, Filter::default()) else {
        return;
    };
    while !stop.load(Ordering::SeqCst) {
        let findings = match subscription.next_timeout(TICK) {
            Ok(Next::Item(Item::Record(record))) => reconciler.observe(&record),
            Ok(Next::Item(Item::Lagged { .. })) => {
                reconciler.on_gap(clock.now_ns());
                Vec::new()
            }
            Ok(Next::Idle) => reconciler.on_tick(clock.now_ns()),
            Ok(Next::End) | Err(_) => break,
        };
        if emit_all(&sink, &mut reconciler, findings).is_err() {
            return;
        }
        if reconciler.stopped() {
            let findings = reconciler.on_tick(clock.now_ns());
            let _ = emit_all(&sink, &mut reconciler, findings);
            break;
        }
    }
}

/// Writes the findings and the span records made so far into the log.
fn emit_all(
    sink: &AuditSink,
    reconciler: &mut Reconciler,
    findings: Vec<Finding>,
) -> Result<(), crate::EmitError> {
    let trace_id = reconciler.session_id().unwrap_or_default().to_owned();
    for finding in findings {
        emit(sink, finding, &trace_id)?;
    }
    for effects in reconciler.take_records() {
        emit_span(sink, effects, &trace_id)?;
    }
    Ok(())
}

/// Writes one finding into the log; waits for room. One inside a span
/// carries the span in its envelope too.
fn emit(sink: &AuditSink, finding: Finding, trace_id: &str) -> Result<(), crate::EmitError> {
    let priority = if finding.score >= CRITICAL_SCORE {
        Priority::Critical
    } else {
        Priority::Normal
    };
    let span = finding.span_id.as_ref().map(|span_id| SpanRef {
        trace_id: trace_id.to_owned(),
        span_id: span_id.clone(),
    });
    sink.emit(Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload: Payload::Finding(finding),
        span,
        priority,
    })
}

/// Writes one `span.effects` into the log; waits for room.
fn emit_span(
    sink: &AuditSink,
    effects: SpanEffects,
    trace_id: &str,
) -> Result<(), crate::EmitError> {
    let span = SpanRef {
        trace_id: trace_id.to_owned(),
        span_id: effects.span_id.clone(),
    };
    sink.emit(Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload: Payload::SpanEffects(effects),
        span: Some(span),
        priority: Priority::Normal,
    })
}

/// The running reconciler.
pub struct ReconcilerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ReconcilerHandle {
    /// Asks the thread to end and waits up to `timeout` for it. Returns
    /// whether it ended; one still running is left to end with the log.
    pub fn finish(mut self, timeout: Duration) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        let Some(thread) = self.thread.take() else {
            return true;
        };
        let deadline = Instant::now() + timeout;
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        thread.join().is_ok()
    }
}
