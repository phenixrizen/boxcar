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
//! [`SinkClosed`] and `try_emit` returns `false`, and neither counts a drop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

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

/// The writer is closed; the event was not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the audit log writer is closed")]
pub struct SinkClosed;

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
    pub fn emit(&self, s: Submission) -> Result<(), SinkClosed> {
        let closed = self
            .shared
            .closed
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if *closed {
            return Err(SinkClosed);
        }
        self.tx.send(s).map_err(|_| SinkClosed)
    }

    /// Sends an event if the channel has room, without waiting, and says
    /// whether it was accepted. On a full channel the event is dropped and
    /// counted in [`dropped`](Self::dropped).
    pub fn try_emit(&self, s: Submission) -> bool {
        let closed = self
            .shared
            .closed
            .read()
            .unwrap_or_else(PoisonError::into_inner);
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
