// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The verifier: checks that a log is exactly what the writer wrote, from the
//! raw bytes on disk.
//!
//! Each line is parsed as a plain `serde_json::Value`, never as the typed
//! [`Record`]. `Record` ignores unknown keys and reads
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
//! A line with the same key twice in one object, at any depth, is not a
//! record ([`VerifyError::Parse`]). serde_json keeps the last of duplicate
//! keys, so a key injected before the real one would hash like the original,
//! while a reader that keeps the first would see the injected value.
//!
//! For a session directory it also checks `meta.json` against the segment
//! files, and `checkpoints.jsonl` against the checkpoint records: that is
//! what catches a log cut off cleanly at a record boundary.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use boxcar_proto::{genesis_prev, Checkpoint, Hash, Record, SessionId};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

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
    /// a JSON object with `seq`, `prev` and `hash` of the right types, or if
    /// any object in it has a key twice.
    pub(crate) fn parse(bytes: &[u8]) -> Result<RawLine, String> {
        let StrictValue(value) =
            serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
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

/// A JSON value parsed exactly as `serde_json::Value` parses it, except that
/// an object with the same key twice, at any depth, is an error.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

/// serde_json's own `Value` visitor, with the duplicate-key check added.
struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        StrictValue::deserialize(deserializer).map(|StrictValue(value)| value)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format_args!("duplicate key `{key}`")));
            }
            let StrictValue(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// A line (without its newline) as a typed [`Record`], parsed as strictly as
/// [`RawLine::parse`] parses it: an object with the same key twice, at any
/// depth, is an error. The reader's way in, which does not hash.
pub(crate) fn parse_record(bytes: &[u8]) -> Result<Record, String> {
    let StrictValue(value) =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    serde_json::from_value(value).map_err(|e| format!("not a record: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strict(text: &str) -> Result<Value, serde_json::Error> {
        serde_json::from_str::<StrictValue>(text).map(|StrictValue(value)| value)
    }

    #[test]
    fn strict_parsing_matches_serde_json_on_lines_without_duplicates() {
        for text in [
            r#"{"a":1,"b":[1,-2,3.5,1e300,18446744073709551615,-9223372036854775808],"c":{"d":null,"e":true,"f":"x\u00e9\n","g":{}},"h":[]}"#,
            r#"[{"k":1},{"k":2},[{"k":3}]]"#,
            r#"{"big":18446744073709551616,"neg":-9223372036854775809,"nested":{"deep":[{"a":{"b":{"c":[0]}}}]}}"#,
            r#""just a string""#,
            "null",
            "  {\"spaced\" : [ 1 , 2 ] }  ",
            "{\"path\":\"/naïve-日本語-\\\"<>&\\\"-\u{2028}-tab\\t-😀\",\"ts\":9007199254740993}",
        ] {
            let lenient: Value = serde_json::from_str(text).unwrap();
            assert_eq!(strict(text).unwrap(), lenient, "{text}");
            assert_eq!(
                serde_json::to_vec(&strict(text).unwrap()).unwrap(),
                serde_json::to_vec(&lenient).unwrap(),
                "{text}: same canonical bytes"
            );
        }
    }

    #[test]
    fn a_key_twice_in_one_object_is_rejected_at_every_depth() {
        for text in [
            r#"{"a":1,"a":1}"#,
            r#"{"a":1,"b":2,"a":3}"#,
            r#"{"data":{"path":"/x","path":"/y"}}"#,
            r#"{"list":[{"k":1},{"k":2,"k":3}]}"#,
            r#"[[{"deep":{"x":0,"x":0}}]]"#,
        ] {
            let err = strict(text).unwrap_err().to_string();
            assert!(err.contains("duplicate key"), "{text}: {err}");
            assert!(
                serde_json::from_str::<Value>(text).is_ok(),
                "serde_json alone accepts {text}"
            );
        }
        // The same key in different objects is fine.
        assert!(strict(r#"{"a":{"k":1},"b":{"k":1},"k":[{"k":1}]}"#).is_ok());
    }
}
