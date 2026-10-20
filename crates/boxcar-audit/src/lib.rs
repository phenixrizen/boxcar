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
//! - [`reader`]: [`LogReader`] reads a session back as typed records, and
//!   a [`Filter`] picks some of them.
//! - [`subscribe`]: [`AuditSink::subscribe`] streams the records of a log
//!   from a seq on, past its end into the live ones, with recovery for a
//!   subscriber that falls behind.
//! - [`verify`]: [`verify_session`] and [`verify_jsonl`] check a log from its
//!   raw bytes, and tell a tail cut mid-write ([`Incomplete`]) from a
//!   break.
//!
//! The session directory layout, rotation and torn-tail recovery live in the
//! private `segment` module, checkpoints and `checkpoints.jsonl` in
//! `checkpoint`.

/// The directory under a data directory that holds the sessions' logs:
/// `<data_dir>/sessions/<session_id>/`. The writer makes it, and the CLI
/// looks there.
pub const SESSIONS_DIR: &str = "sessions";

pub mod chain;
mod checkpoint;
pub mod export;
pub mod reader;
pub mod reconcile;
mod segment;
pub mod sink;
pub mod subscribe;
pub mod verify;
pub mod writer;

pub use chain::{Chainer, PartialRecord};
pub use reader::{Filter, LogReader, Records};
pub use reconcile::{
    Clock, Declared, DeclaredArgs, ExecKey, ManualClock, PolicyIndicators, RawArgv,
    ReconcileConfig, Reconciler, ReconcilerHandle, SpanIndex, SystemClock,
};
pub use segment::{Fdatasync, Syncer};
pub use sink::{AuditSink, EmitError, Priority, Submission};
pub use subscribe::{Item, Next, Subscription, DEFAULT_QUEUE, REPLAY_YIELD};
pub use verify::{
    read_verified, verify_jsonl, verify_session, Incomplete, IncompleteKind, VerifyError,
    VerifyReport,
};
pub use writer::{spawn, spawn_with_syncer, CloseStats, WriteFailure, WriterConfig, WriterHandle};

/// Makes the directory a writer for `session_id` under `data_dir` writes
/// to (`<data_dir>/sessions/<session_id>`, mode 0700 all the way down) and
/// syncs its parent, before the writer starts: a caller that confines
/// itself to the paths it will use (`boxcar run`, with Landlock) needs the
/// directory to exist first. The writer takes an existing empty directory
/// as a new session.
pub fn prepare_session_dir(
    data_dir: &std::path::Path,
    session_id: &boxcar_proto::SessionId,
) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let dir = data_dir.join(SESSIONS_DIR).join(session_id.as_str());
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(segment::DIR_MODE)
        .create(&dir)?;
    if let Some(parent) = dir.parent() {
        segment::Syncer::sync_dir(&segment::Fdatasync, parent)?;
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use boxcar_proto::SessionId;

    use super::*;

    /// A writer started on a prepared directory takes it as a new session,
    /// and writes where it was prepared.
    #[test]
    fn a_prepared_session_directory_is_the_writers() {
        let data = tempfile::tempdir().unwrap();
        let id = SessionId::new();
        let dir = prepare_session_dir(data.path(), &id).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let (_sink, writer) = spawn(WriterConfig::new(data.path(), id)).unwrap();
        assert_eq!(writer.session_dir(), dir);
        writer.close().unwrap();
        assert!(dir.join("meta.json").exists());
    }
}
