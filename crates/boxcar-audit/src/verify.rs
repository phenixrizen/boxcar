// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The verifier: checks that a log is exactly what the writer wrote, from the
//! raw bytes on disk.
//!
//! Each line is parsed as a plain `serde_json::Value`, never as the typed
//! [`Record`](boxcar_proto::Record). `Record` ignores unknown keys and reads
//! an explicit `"subject": null` as absent, so hashing a typed record would
//! accept a line with an injected key or null. The verifier removes the
//! top-level `hash` from the parsed object, serializes the rest with
//! serde_json (keys sorted, no whitespace), and requires, line by line:
//!
//! ```text
//! seq  == the previous seq + 1                      (1 for the first record)
//! prev == the previous record's hash                (genesis_prev(session_id) for the first)
//! hash == blake3(prev_bytes || canonical_json)
//! ```
//!
//! plus `v == 1` and the session's id on every record, and, for each
//! checkpoint record, the `root_hash` and `records_since` of the records
//! since the previous checkpoint. The first failure is reported, checked in
//! that order, so a changed value is a [`VerifyError::Chain`] at its record,
//! a removed or reordered record a [`VerifyError::Gap`].
//!
//! For a session directory it also checks `meta.json` against the segment
//! files, and `checkpoints.jsonl` against the checkpoint records: that is
//! what catches a log cut off cleanly at a record boundary.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use boxcar_proto::{genesis_prev, Checkpoint, Hash, SessionId};
use serde_json::{Map, Value};

use crate::checkpoint::{IndexEntry, INDEX_FILE};
use crate::segment::{list_segments, numbered_from_one, read_meta, segment_name, META_FILE};

/// What a verified log holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    /// Records, checkpoints included.
    pub records: u64,
    pub segments: u32,
    /// Checkpoint records.
    pub checkpoints: u32,
    /// The last record's seq; 0 for an empty log.
    pub last_seq: u64,
    /// The last record's hash; the genesis hash for an empty log.
    pub last_hash: Hash,
}

/// The first thing wrong with a log.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// A file of the log could not be read.
    #[error("{}: {}", .0.display(), .1)]
    Io(PathBuf, #[source] io::Error),
    /// A line is not a record of this log: not JSON, a field missing or of
    /// the wrong type, an unsupported `v`, another session's id, or a line
    /// cut short. `line` counts from 1 within segment `segment`.
    #[error("segment {segment} line {line}: {reason}")]
    Parse {
        segment: u32,
        line: u64,
        reason: String,
    },
    /// The record at `seq` does not continue the chain. Either its `prev` is
    /// not the previous record's hash, or its `hash` is not the hash of its
    /// contents. `expected` is what the chain requires, `got` what the line
    /// says.
    #[error("chain broken at seq {seq}: expected {expected}, got {got}")]
    Chain { seq: u64, expected: Hash, got: Hash },
    /// A record is missing, repeated, or out of order.
    #[error("sequence gap: expected seq {expected_seq}, got seq {got_seq}")]
    Gap { expected_seq: u64, got_seq: u64 },
    /// A checkpoint's `root_hash` is not the root of the records since the
    /// previous checkpoint.
    #[error("checkpoint at seq {seq}: expected root_hash {expected}, got {got}")]
    Checkpoint { seq: u64, expected: Hash, got: Hash },
    /// A checkpoint's `records_since` is not the number of records since the
    /// previous checkpoint.
    #[error("checkpoint at seq {seq}: expected records_since {expected}, got {got}")]
    CheckpointCount { seq: u64, expected: u64, got: u64 },
    /// The first record's `prev` is not the genesis hash of its session.
    #[error("the first record does not start the chain: expected prev {expected}, got {got}")]
    Genesis { expected: Hash, got: Hash },
    /// `checkpoints.jsonl` does not list the log's checkpoint records
    /// exactly, in order.
    #[error("checkpoints.jsonl line {line}: {reason}")]
    CheckpointFile { line: u64, reason: String },
    /// The directory is not laid out as the writer leaves a session:
    /// `meta.json` missing or wrong, or segment files missing. Also a
    /// standalone file with no records.
    #[error("{reason}")]
    Layout { reason: String },
}

/// Verifies a session directory: every segment in order as one chain, then
/// `meta.json` and `checkpoints.jsonl` against it.
pub fn verify_session(session_dir: &Path) -> Result<VerifyReport, VerifyError> {
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |e| VerifyError::Io(path, e)
    };
    let layout = |reason: String| VerifyError::Layout { reason };

    fs::metadata(session_dir).map_err(io_err(session_dir))?;
    let meta = read_meta(session_dir).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => layout(format!(
            "{}: no {META_FILE}, so not a session directory",
            session_dir.display()
        )),
        io::ErrorKind::InvalidData => layout(e.to_string()),
        _ => VerifyError::Io(session_dir.join(META_FILE), e),
    })?;
    if meta.v != 1 {
        return Err(layout(format!(
            "{META_FILE}: unsupported version {}",
            meta.v
        )));
    }

    let segments = list_segments(session_dir).map_err(io_err(session_dir))?;
    if !numbered_from_one(&segments) {
        let missing = (1..)
            .zip(segments.iter().copied())
            .find(|&(want, n)| want != n)
            .map_or(1, |(want, _)| want);
        return Err(layout(format!("{} is missing", segment_name(missing))));
    }
    let count = segments.len() as u32;
    if count == 0 || count != meta.segments {
        return Err(layout(format!(
            "{META_FILE} lists {} segments, the directory has {count}",
            meta.segments
        )));
    }

    let mut walk = Walk::new(Some(meta.session_id));
    for n in 1..=count {
        walk.segment(&session_dir.join(segment_name(n)), n)?;
    }
    check_index(session_dir, &walk)?;
    Ok(walk.report(count))
}

/// Verifies one `.jsonl` file on its own, as a whole chain: its first record
/// must be seq 1 of the session it names, starting from that session's
/// genesis hash. There is no `meta.json` or `checkpoints.jsonl` to check.
pub fn verify_jsonl(path: &Path) -> Result<VerifyReport, VerifyError> {
    let mut walk = Walk::new(None);
    walk.segment(path, 1)?;
    if walk.next_seq == 1 {
        return Err(VerifyError::Layout {
            reason: format!("{}: no records", path.display()),
        });
    }
    Ok(walk.report(1))
}

/// One line of a log as its bytes say, before any check against its
/// neighbours. Recovery keeps a line only if it passes the same checks the
/// verifier makes, from this.
pub(crate) struct RawLine {
    pub(crate) seq: u64,
    pub(crate) prev: Hash,
    /// The `hash` the line states.
    pub(crate) hash: Hash,
    /// What the line hashes to: blake3 over `prev`'s raw bytes and the
    /// canonical JSON of the line without `hash`.
    pub(crate) computed: Hash,
    /// Every field but `hash`.
    fields: Map<String, Value>,
}

impl RawLine {
    /// Parses a line (without its newline) and hashes it. Fails if it is not
    /// a JSON object with `seq`, `prev` and `hash` of the right types.
    pub(crate) fn parse(bytes: &[u8]) -> Result<RawLine, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
        let Value::Object(mut fields) = value else {
            return Err("not a JSON object".into());
        };
        let hash = hash_field(fields.remove("hash").as_ref(), "hash")?;
        let prev = hash_field(fields.get("prev"), "prev")?;
        let seq = fields
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or("missing or invalid `seq`")?;
        let canonical = serde_json::to_vec(&fields).map_err(|e| e.to_string())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&prev.0);
        hasher.update(&canonical);
        Ok(RawLine {
            seq,
            prev,
            hash,
            computed: Hash::from_blake3(hasher.finalize()),
            fields,
        })
    }

    fn session_id(&self) -> Option<&str> {
        self.fields.get("session_id").and_then(Value::as_str)
    }

    /// The checks that mean something only once the line is known to be
    /// authentic: `v` is 1, `session_id` is `session`, `type` is a string,
    /// and a checkpoint's `data` has a checkpoint's fields. Returns the
    /// checkpoint if the line is one.
    pub(crate) fn check_envelope(&self, session: &str) -> Result<Option<Checkpoint>, String> {
        match self.fields.get("v").and_then(Value::as_u64) {
            Some(1) => {}
            Some(v) => return Err(format!("unsupported schema version {v}")),
            None => return Err("missing or invalid `v`".into()),
        }
        match self.session_id() {
            Some(id) if id == session => {}
            Some(id) => return Err(format!("session_id {id} is not the log's {session}")),
            None => return Err("missing or invalid `session_id`".into()),
        }
        let kind = self
            .fields
            .get("type")
            .and_then(Value::as_str)
            .ok_or("missing or invalid `type`")?;
        if kind != "checkpoint" {
            return Ok(None);
        }
        let data = self.fields.get("data").cloned().unwrap_or(Value::Null);
        serde_json::from_value(data)
            .map(Some)
            .map_err(|e| format!("checkpoint data: {e}"))
    }
}

fn hash_field(value: Option<&Value>, name: &str) -> Result<Hash, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid `{name}`"))?;
    text.parse().map_err(|e| format!("`{name}`: {e}"))
}

/// The state of a walk down one chain.
struct Walk {
    /// The session every record must name. A standalone file takes it from
    /// its first record.
    session: Option<SessionId>,
    next_seq: u64,
    /// The previous record's hash, or the genesis hash.
    prev: Hash,
    /// blake3 over the raw hashes of the records since the last checkpoint.
    window: blake3::Hasher,
    since: u64,
    /// The checkpoint records seen, as `checkpoints.jsonl` should list them.
    checkpoints: Vec<IndexEntry>,
}

impl Walk {
    fn new(session: Option<SessionId>) -> Self {
        let prev = session.as_ref().map_or(Hash([0; 32]), genesis_prev);
        Walk {
            session,
            next_seq: 1,
            prev,
            window: blake3::Hasher::new(),
            since: 0,
            checkpoints: Vec::new(),
        }
    }

    /// Walks the lines of one segment file, numbered `segment`.
    fn segment(&mut self, path: &Path, segment: u32) -> Result<(), VerifyError> {
        let io_err = |e| VerifyError::Io(path.to_owned(), e);
        let mut reader = BufReader::with_capacity(1 << 20, File::open(path).map_err(io_err)?);
        let mut buf = Vec::new();
        let mut offset = 0;
        for line in 1.. {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf).map_err(io_err)?;
            if n == 0 {
                break;
            }
            let Some(body) = buf.strip_suffix(b"\n") else {
                return Err(VerifyError::Parse {
                    segment,
                    line,
                    reason: "no newline at the end: a torn write, or a cut file".into(),
                });
            };
            self.line(segment, line, offset, body)?;
            offset += n as u64;
        }
        Ok(())
    }

    fn line(
        &mut self,
        segment: u32,
        line: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), VerifyError> {
        let parse = |reason: String| VerifyError::Parse {
            segment,
            line,
            reason,
        };
        let raw = RawLine::parse(bytes).map_err(parse)?;
        if self.session.is_none() {
            let id: SessionId = raw
                .session_id()
                .and_then(|id| id.parse().ok())
                .ok_or_else(|| parse("missing or invalid `session_id`".into()))?;
            self.prev = genesis_prev(&id);
            self.session = Some(id);
        }

        if raw.seq != self.next_seq {
            return Err(VerifyError::Gap {
                expected_seq: self.next_seq,
                got_seq: raw.seq,
            });
        }
        if raw.prev != self.prev {
            return Err(if self.next_seq == 1 {
                VerifyError::Genesis {
                    expected: self.prev,
                    got: raw.prev,
                }
            } else {
                VerifyError::Chain {
                    seq: raw.seq,
                    expected: self.prev,
                    got: raw.prev,
                }
            });
        }
        if raw.hash != raw.computed {
            return Err(VerifyError::Chain {
                seq: raw.seq,
                expected: raw.computed,
                got: raw.hash,
            });
        }

        let session = self.session.as_ref().map_or("", SessionId::as_str);
        match raw.check_envelope(session).map_err(parse)? {
            Some(checkpoint) => {
                let root = Hash::from_blake3(self.window.finalize());
                if checkpoint.root_hash != root {
                    return Err(VerifyError::Checkpoint {
                        seq: raw.seq,
                        expected: root,
                        got: checkpoint.root_hash,
                    });
                }
                if checkpoint.records_since != self.since {
                    return Err(VerifyError::CheckpointCount {
                        seq: raw.seq,
                        expected: self.since,
                        got: checkpoint.records_since,
                    });
                }
                self.checkpoints
                    .push(IndexEntry::new(raw.seq, segment, offset, &checkpoint));
                self.window = blake3::Hasher::new();
                self.since = 0;
            }
            None => {
                self.window.update(&raw.hash.0);
                self.since += 1;
            }
        }
        self.next_seq += 1;
        self.prev = raw.hash;
        Ok(())
    }

    fn report(&self, segments: u32) -> VerifyReport {
        VerifyReport {
            records: self.next_seq - 1,
            segments,
            checkpoints: self.checkpoints.len() as u32,
            last_seq: self.next_seq - 1,
            last_hash: self.prev,
        }
    }
}

/// Checks that `checkpoints.jsonl` lists exactly the checkpoint records the
/// walk saw, in order, with the right segment, offset and fields. A missing
/// file lists none.
fn check_index(session_dir: &Path, walk: &Walk) -> Result<(), VerifyError> {
    let path = session_dir.join(INDEX_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(VerifyError::Io(path, e)),
    };
    let seen = &walk.checkpoints;
    let last_seq = walk.next_seq - 1;
    let mut lines = 0;
    for (line, text) in (1..).zip(bytes.split_inclusive(|&b| b == b'\n')) {
        lines = line;
        let bad = |reason: String| VerifyError::CheckpointFile { line, reason };
        let body = text
            .strip_suffix(b"\n")
            .ok_or_else(|| bad("no newline at the end".into()))?;
        let entry: IndexEntry = serde_json::from_slice(body)
            .map_err(|e| bad(format!("not a checkpoint entry: {e}")))?;
        let Some(record) = seen.get(line as usize - 1) else {
            return Err(bad(if entry.seq > last_seq {
                format!(
                    "names a checkpoint at seq {}, past the end of the log at seq {last_seq}",
                    entry.seq
                )
            } else {
                format!(
                    "names a checkpoint at seq {}, but the log has only {} checkpoints",
                    entry.seq,
                    seen.len()
                )
            }));
        };
        if let Some(reason) = mismatch(&entry, record) {
            return Err(bad(reason));
        }
    }
    match seen.get(lines as usize) {
        Some(missing) => Err(VerifyError::CheckpointFile {
            line: lines + 1,
            reason: format!("the checkpoint at seq {} is not listed", missing.seq),
        }),
        None => Ok(()),
    }
}

/// How an index entry differs from the checkpoint record it should describe.
fn mismatch(entry: &IndexEntry, record: &IndexEntry) -> Option<String> {
    if entry.seq != record.seq {
        return Some(format!(
            "names a checkpoint at seq {}, but the log's checkpoint here is at seq {}",
            entry.seq, record.seq
        ));
    }
    let fields = [
        (
            "segment",
            entry.segment.to_string(),
            record.segment.to_string(),
        ),
        (
            "offset",
            entry.offset.to_string(),
            record.offset.to_string(),
        ),
        (
            "root_hash",
            entry.root_hash.to_string(),
            record.root_hash.to_string(),
        ),
        (
            "records_since",
            entry.records_since.to_string(),
            record.records_since.to_string(),
        ),
        (
            "dropped",
            entry.dropped.to_string(),
            record.dropped.to_string(),
        ),
    ];
    fields
        .into_iter()
        .find(|(_, got, want)| got != want)
        .map(|(name, got, want)| {
            format!(
                "the checkpoint at seq {}: {name} is {got}, the log has {want}",
                entry.seq
            )
        })
}
