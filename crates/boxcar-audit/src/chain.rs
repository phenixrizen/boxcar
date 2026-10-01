// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Sequence numbers and the hash chain. [`Chainer`] turns a
//! [`PartialRecord`] into the next [`Record`] of a session: seq one past the
//! last, `prev` the last record's hash, and `hash` from
//! [`Record::compute_hash`].

use boxcar_proto::{
    genesis_prev, Hash, Record, Ring, SessionId, Source, SpanRef, Subject, SCHEMA_VERSION,
};
use serde_json::Value;

/// A record before the chain places it: every field except `v`, `seq`,
/// `prev` and `hash`, which [`Chainer::next`] fills in.
#[derive(Clone, Debug, PartialEq)]
pub struct PartialRecord {
    pub session_id: SessionId,
    pub ring: Ring,
    pub src: Source,
    /// The dotted event type, the record's `type`.
    pub kind: String,
    pub ts_host_ns: u64,
    pub ts_mono_ns: u64,
    pub ts_guest_ns: Option<u64>,
    pub subject: Option<Subject>,
    pub data: Value,
    pub span: Option<SpanRef>,
}

/// Assigns sequence numbers and links each record to the one before it.
#[derive(Clone, Debug)]
pub struct Chainer {
    prev: Hash,
    seq: u64,
}

impl Chainer {
    /// The chain of a new session: the first record gets seq 1 and the
    /// session's genesis `prev`.
    pub fn genesis(session_id: &SessionId) -> Self {
        Chainer {
            prev: genesis_prev(session_id),
            seq: 0,
        }
    }

    /// The chain of an existing log whose last record has `seq` and
    /// `last_hash`.
    pub fn resume(seq: u64, last_hash: Hash) -> Self {
        Chainer {
            prev: last_hash,
            seq,
        }
    }

    /// Chains the next record.
    pub fn next(&mut self, partial: PartialRecord) -> Record {
        let mut record = Record {
            v: SCHEMA_VERSION,
            session_id: partial.session_id,
            seq: self.seq + 1,
            ring: partial.ring,
            src: partial.src,
            kind: partial.kind,
            ts_host_ns: partial.ts_host_ns,
            ts_mono_ns: partial.ts_mono_ns,
            ts_guest_ns: partial.ts_guest_ns,
            subject: partial.subject,
            data: partial.data,
            span: partial.span,
            prev: self.prev,
            hash: Hash([0; 32]),
        };
        record.hash = record.compute_hash();
        self.seq = record.seq;
        self.prev = record.hash;
        record
    }

    /// The seq of the last record chained; 0 before the first.
    pub fn last_seq(&self) -> u64 {
        self.seq
    }

    /// The hash the next record takes as its `prev`: the last record's hash,
    /// or the genesis hash before the first.
    pub fn last_hash(&self) -> Hash {
        self.prev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn partial(session: &SessionId, n: u64) -> PartialRecord {
        PartialRecord {
            session_id: session.clone(),
            ring: Ring::Host,
            src: Source::Vmm,
            kind: "vmm.stop".into(),
            ts_host_ns: n,
            ts_mono_ns: n,
            ts_guest_ns: None,
            subject: None,
            data: json!({"n": n}),
            span: None,
        }
    }

    #[test]
    fn records_count_from_one_and_link_to_the_one_before() {
        let session = SessionId::new();
        let mut chain = Chainer::genesis(&session);
        assert_eq!(chain.last_seq(), 0);
        assert_eq!(chain.last_hash(), genesis_prev(&session));

        let first = chain.next(partial(&session, 1));
        let second = chain.next(partial(&session, 2));
        assert_eq!((first.v, first.seq, second.seq), (SCHEMA_VERSION, 1, 2));
        assert_eq!(first.prev, genesis_prev(&session));
        assert_eq!(second.prev, first.hash);
        assert_eq!(first.hash, first.compute_hash());
        assert_eq!(second.hash, second.compute_hash());
        assert_eq!((chain.last_seq(), chain.last_hash()), (2, second.hash));
    }

    #[test]
    fn a_resumed_chain_continues_where_the_log_ended() {
        let session = SessionId::new();
        let mut whole = Chainer::genesis(&session);
        let first = whole.next(partial(&session, 1));
        let second = whole.next(partial(&session, 2));

        let mut resumed = Chainer::resume(first.seq, first.hash);
        assert_eq!(resumed.next(partial(&session, 2)), second);
    }
}
