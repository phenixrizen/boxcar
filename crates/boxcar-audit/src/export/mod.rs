// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Exporting a verified log: as one OpenTelemetry trace in OTLP/JSON
//! ([`otlp`]), or as OCSF 1.9.0 events in JSON lines ([`ocsf`]).
//!
//! A [`Log`] is read once, in the verification walk
//! ([`crate::verify::read_verified`]), so an export holds the very bytes
//! that were hashed: a broken chain exports nothing, and an incomplete one
//! exports the records that verified. Both forms are built from the `Log`
//! alone, in a fixed order, so the same log exported twice by the same
//! version gives the same bytes: no clock, host, environment or exporter
//! version enters them. Every span, event and OCSF event carries the `seq`
//! and hash of the record it comes from.

pub mod ocsf;
pub mod otlp;

use std::collections::BTreeMap;
use std::path::Path;

use boxcar_proto::audit::KINDS;
use boxcar_proto::{Payload, Record, SessionId};

use crate::verify::{read_verified, VerifyError, VerifyReport};

/// Why a log could not be exported.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The chain is broken, or the path is no log.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// A record verified but its `data` does not fit its kind: a log this
    /// version cannot read, not a cut.
    #[error("seq {seq}: {kind}: {message}")]
    Payload {
        seq: u64,
        kind: String,
        message: String,
    },
}

/// One record of a [`Log`], with its typed payload: `None` for a kind this
/// version does not know (a newer log's), which every form skips.
pub struct Entry {
    pub record: Record,
    pub payload: Option<Payload>,
}

/// A verified log, read once, ready to export.
pub struct Log {
    /// What verifying it found; `incomplete` set when its tail was cut.
    pub report: VerifyReport,
    /// Its records that verified, in seq order.
    pub entries: Vec<Entry>,
}

impl Log {
    /// Reads and verifies the log at `path`: a session directory, or one
    /// `.jsonl` file.
    pub fn read(path: &Path) -> Result<Log, ExportError> {
        let (report, records) = read_verified(path)?;
        let entries = records
            .into_iter()
            .map(|record| {
                let payload = if KINDS.contains(&record.kind.as_str()) {
                    Some(
                        Payload::from_record(&record).map_err(|e| ExportError::Payload {
                            seq: record.seq,
                            kind: record.kind.clone(),
                            message: e.to_string(),
                        })?,
                    )
                } else {
                    None
                };
                Ok(Entry { record, payload })
            })
            .collect::<Result<_, ExportError>>()?;
        Ok(Log { report, entries })
    }

    /// The session the log is of, from its first record.
    pub fn session_id(&self) -> Option<&SessionId> {
        self.entries.first().map(|entry| &entry.record.session_id)
    }

    /// The boxcar version that wrote the log, from its `vmm.start`.
    pub fn version(&self) -> Option<&str> {
        self.entries.iter().find_map(|entry| match &entry.payload {
            Some(Payload::VmmStart(start)) => Some(start.version.as_str()),
            _ => None,
        })
    }
}

/// How many records of each kind an export left out, by kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Skipped(pub BTreeMap<String, u64>);

impl Skipped {
    pub fn add(&mut self, kind: &str) {
        *self.0.entry(kind.to_owned()).or_default() += 1;
    }

    /// All of them.
    pub fn total(&self) -> u64 {
        self.0.values().sum()
    }
}

impl std::fmt::Display for Skipped {
    /// `checkpoint 2, vmm.start 1`, by kind.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for (kind, count) in &self.0 {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "{kind} {count}")?;
            first = false;
        }
        Ok(())
    }
}

/// The guest directory each share is mounted at, by its tag, from the log's
/// `fs.mount` records, to turn a share's path into the guest's.
#[derive(Default)]
pub(crate) struct Mounts(BTreeMap<String, String>);

impl Mounts {
    pub(crate) fn learn(&mut self, payload: &Payload) {
        if let Payload::FsMount(mount) = payload {
            self.0.insert(mount.mount.clone(), mount.guest_path.clone());
        }
    }

    /// `path` on the share `mount` as the guest names it: the share's guest
    /// directory joined to it; `path` itself for a share the log never
    /// mounted.
    pub(crate) fn guest_path(&self, mount: &str, path: &str) -> String {
        match self.0.get(mount) {
            Some(dir) if dir == "/" => path.to_owned(),
            Some(dir) if path == "/" => dir.clone(),
            Some(dir) => format!("{}{}", dir.trim_end_matches('/'), path),
            None => path.to_owned(),
        }
    }
}

/// The last component of a guest path: `x` for `/a/x`, `/` for `/`.
pub(crate) fn file_name(path: &str) -> &str {
    match path.trim_end_matches('/').rsplit('/').next() {
        Some("") | None => "/",
        Some(name) => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_path_becomes_the_guests() {
        let mut mounts = Mounts::default();
        mounts.0.insert("root".into(), "/".into());
        mounts.0.insert("workspace".into(), "/workspace".into());
        assert_eq!(mounts.guest_path("root", "/etc/x"), "/etc/x");
        assert_eq!(mounts.guest_path("workspace", "/a/b"), "/workspace/a/b");
        assert_eq!(mounts.guest_path("workspace", "/"), "/workspace");
        assert_eq!(mounts.guest_path("other", "/a"), "/a");
        assert_eq!(file_name("/workspace/a/b"), "b");
        assert_eq!(file_name("/"), "/");
        assert_eq!(file_name("/workspace/"), "workspace");
    }
}
