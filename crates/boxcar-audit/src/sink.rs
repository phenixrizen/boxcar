// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The producer side of the log: [`AuditSink`] hands typed events to the
//! session's writer thread over a bounded channel.
//!
//! There are two ways in, chosen by what losing the event would cost:
//!
//! - [`AuditSink::emit`] waits while the channel is full. It is for events
//!   that are never sampled: writes, creates, unlinks, renames, setattr,
//!   verdicts, denials.
//! - [`AuditSink::try_emit`] never waits. When the channel is full the event
//!   is dropped and counted, and the next checkpoint reports the count. It is
//!   for events that may be sampled, such as reads.
//!
//! Once the writer is closed both refuse every event: `emit` returns
//! [`EmitError::Closed`] and `try_emit` returns `false`. While it is closing,
//! `try_emit` refuses too rather than wait. Both also refuse a
//! [`Payload::Checkpoint`], which only the writer may make. A refusal is
//! never counted as a drop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, TryLockError};

use boxcar_proto::{Payload, Ring, SpanRef, Subject};
use crossbeam_channel::{Sender, TrySendError};

/// How soon a record must be on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    /// Synced at the next checkpoint, at most `checkpoint_interval` later.
    Normal,
    /// Synced (`fdatasync`) right after the record is written.
    Critical,
}

/// One event for the log. The writer fills in the rest of the record: the
/// sequence number, both host timestamps, the source (from the payload's
/// kind), and the chain fields.
#[derive(Clone, Debug, PartialEq)]
pub struct Submission {
    pub ring: Ring,
    /// The guest's clock, for an event reported from inside the guest.
    pub ts_guest_ns: Option<u64>,
    /// The guest process the event is attributed to.
    pub subject: Option<Subject>,
    pub payload: Payload,
    pub span: Option<SpanRef>,
    pub priority: Priority,
}

/// Why [`AuditSink::emit`] did not take an event. Either way the event was
/// not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    /// The writer is closed.
    #[error("the audit log writer is closed")]
    Closed,
    /// The event is a checkpoint. The writer makes those itself, from the
    /// records it has written; a submitted one could not verify.
    #[error("checkpoint records are made by the audit log writer, not submitted")]
    Checkpoint,
}

/// What the sinks share with the writer.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    /// Events `try_emit` dropped because the channel was full.
    pub(crate) dropped: AtomicU64,
    /// Set once, by [`Shared::close`]. Each send holds the read lock across
    /// the send itself, so the write lock is granted only when no send is in
    /// flight.
    closed: RwLock<bool>,
}

impl Shared {
    /// Stops the sinks and returns once no send is in flight. From then on
    /// nothing new enters the channel, so a drain after this sees every event
    /// that was ever accepted. The writer thread must keep draining while
    /// this waits, or an `emit` blocked on a full channel would never finish.
    pub(crate) fn close(&self) {
        *self.closed.write().unwrap_or_else(PoisonError::into_inner) = true;
    }
}

/// Sends events to one session's log. Clones are cheap and all feed the same
/// writer.
#[derive(Clone)]
pub struct AuditSink {
    tx: Sender<Submission>,
    shared: Arc<Shared>,
}

impl AuditSink {
    pub(crate) fn new(tx: Sender<Submission>, shared: Arc<Shared>) -> Self {
        AuditSink { tx, shared }
    }

    /// Sends an event, waiting while the channel is full. For events that
    /// must never be dropped.
    pub fn emit(&self, s: Submission) -> Result<(), EmitError> {
        if matches!(s.payload, Payload::Checkpoint(_)) {
            return Err(EmitError::Checkpoint);
        }
        let closed = self
            .shared
            .closed
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if *closed {
            return Err(EmitError::Closed);
        }
        self.tx.send(s).map_err(|_| EmitError::Closed)
    }

    /// Sends an event if the channel has room, without waiting, and says
    /// whether it was accepted. On a full channel the event is dropped and
    /// counted in [`dropped`](Self::dropped). A checkpoint, or an event sent
    /// while the writer is closed or closing, is refused and not counted.
    pub fn try_emit(&self, s: Submission) -> bool {
        if matches!(s.payload, Payload::Checkpoint(_)) {
            return false;
        }
        // `try_read`, not `read`: while `Shared::close` waits for the write
        // lock, std's RwLock makes new readers wait as well. A `try_emit`
        // that meets that is racing close, so it counts as closed.
        let closed = match self.shared.closed.try_read() {
            Ok(closed) => closed,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return false,
        };
        if *closed {
            return false;
        }
        match self.tx.try_send(s) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                // Relaxed is enough: the writer's final read comes after
                // `Shared::close`, whose lock orders it after every send.
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// How many events [`try_emit`](Self::try_emit) has dropped so far.
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::TryLockError;
    use std::thread;
    use std::time::Duration;

    use boxcar_proto::{FsIo, OpResult};
    use crossbeam_channel::bounded;

    use super::*;

    fn event(n: u64) -> Submission {
        Submission {
            ring: Ring::Host,
            ts_guest_ns: None,
            subject: None,
            payload: Payload::FsRead(FsIo {
                mount: "workspace".into(),
                path: "/f".into(),
                fh: n,
                offset: 0,
                len: 1,
                result: OpResult::ok(),
            }),
            span: None,
            priority: Priority::Normal,
        }
    }

    #[test]
    fn try_emit_does_not_wait_while_close_waits_out_a_blocked_emit() {
        let (tx, rx) = bounded(1);
        let shared = Arc::new(Shared::default());
        let sink = AuditSink::new(tx, shared.clone());
        sink.emit(event(0)).unwrap(); // the channel is now full

        // An emit that waits for room, holding the gate's read lock.
        let blocked = thread::spawn({
            let sink = sink.clone();
            move || sink.emit(event(1)).is_ok()
        });
        while let Ok(guard) = shared.closed.try_write() {
            drop(guard);
            thread::sleep(Duration::from_millis(1));
        }

        // Close waits for that emit, with the write lock requested.
        let closer = thread::spawn({
            let shared = shared.clone();
            move || shared.close()
        });
        loop {
            match shared.closed.try_read() {
                Err(TryLockError::WouldBlock) => break,
                _ => thread::sleep(Duration::from_millis(1)),
            }
        }

        // try_emit must answer at once: refused, and not counted as a drop.
        let (answer, answered) = bounded(1);
        thread::spawn({
            let sink = sink.clone();
            move || answer.send(sink.try_emit(event(2))).unwrap()
        });
        let accepted = answered
            .recv_timeout(Duration::from_secs(5))
            .expect("try_emit waited for close");
        assert!(!accepted);
        assert_eq!(sink.dropped(), 0);

        // Draining lets the blocked emit finish, accepted, and close with it.
        assert_eq!(rx.recv().unwrap().payload, event(0).payload);
        assert_eq!(rx.recv().unwrap().payload, event(1).payload);
        assert!(blocked.join().unwrap(), "the blocked emit was accepted");
        closer.join().unwrap();
        assert_eq!(sink.emit(event(3)), Err(EmitError::Closed));
        assert!(!sink.try_emit(event(4)));
        assert_eq!(sink.dropped(), 0);
    }
}
