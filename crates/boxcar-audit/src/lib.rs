// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Single-writer, hash-chained audit log: writer, reader, and verifier.
//!
//! Every component of a session records into one append-only log of JSON
//! lines, each a `boxcar_proto::Record` chained to the one before it by
//! blake3. This crate is the only place records are made:
//!
//! - [`sink`]: [`AuditSink`], cloned into every producer, sends typed
//!   [`Submission`]s over a bounded channel.
//! - [`writer`]: [`spawn`] starts the session's one writer thread, which
//!   stamps time, assigns gap-free sequence numbers, chains, writes, rotates
//!   segments, and checkpoints.
//! - [`chain`]: [`Chainer`], the sequence and hash rule on its own.
//! - [`reader`]: [`LogReader`] reads a session back as typed records.
//! - [`verify`]: [`verify_session`] and [`verify_jsonl`] check a log from its
//!   raw bytes.
//!
//! The session directory layout, rotation and torn-tail recovery live in the
//! private `segment` module, checkpoints and `checkpoints.jsonl` in
//! `checkpoint`.

pub mod chain;
mod checkpoint;
pub mod reader;
mod segment;
pub mod sink;
pub mod verify;
pub mod writer;

pub use chain::{Chainer, PartialRecord};
pub use reader::LogReader;
pub use segment::{Fdatasync, Syncer};
pub use sink::{AuditSink, Priority, SinkClosed, Submission};
pub use verify::{verify_jsonl, verify_session, VerifyError, VerifyReport};
pub use writer::{spawn, spawn_with_syncer, CloseStats, WriterConfig, WriterHandle};
