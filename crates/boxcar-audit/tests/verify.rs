// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The verifier against tampered logs. Each test writes a real session (or
//! chains a standalone file with `Chainer`), alters it the way an attacker or
//! a broken disk would, and checks that the verifier names the first break.
//! The tails a crash leaves are incomplete, not broken (`tests/crash.rs`);
//! the tests here also check that a tail which only looks like one, or
//! two of them at once, stays a break.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use boxcar_audit::{
    spawn, verify_jsonl, verify_session, Chainer, Incomplete, IncompleteKind, PartialRecord,
    Priority, Submission, VerifyError, WriterConfig,
};
use boxcar_proto::limits::MAX_RECORD_BYTES;
use boxcar_proto::{
    genesis_prev, Attrib, Checkpoint, FsIo, Hash, OpResult, Payload, Record, Ring, SessionId,
    Subject,
};
use serde_json::{json, Value};
use tempfile::TempDir;

fn event(n: u64) -> Submission {
    Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: Some(Subject {
            pid: 42,
            uid: 1000,
            gid: 1000,
        }),
        payload: Payload::FsWrite(FsIo {
            mount: "workspace".into(),
            path: format!("/file-{n:06}.txt"),
            path_b64: None,
            fh: n,
            offset: 0,
            len: 1,
            result: OpResult::ok(),
            attrib: Attrib::Caller,
        }),
        span: None,
        priority: Priority::Normal,
    }
}

/// Writes `events` events into a fresh session and returns its directory.
fn session(tmp: &TempDir, events: u64, tune: impl FnOnce(&mut WriterConfig)) -> PathBuf {
    let mut cfg = WriterConfig::new(tmp.path(), SessionId::new());
    tune(&mut cfg);
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..events {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
    dir
}

fn segment(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("events.{n:06}.jsonl"))
}

/// The number of segment files in a session.
fn segment_count(dir: &Path) -> u32 {
    fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            let name = e.as_ref().unwrap().file_name();
            name.to_str().unwrap().starts_with("events.")
        })
        .count() as u32
}

fn append(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// Where the last line of a file that ends in a newline starts.
fn last_line_start(bytes: &[u8]) -> usize {
    let body = bytes.strip_suffix(b"\n").unwrap();
    body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)
}

fn incomplete(kind: IncompleteKind, segment: u32, offset: u64, bytes: u64) -> Option<Incomplete> {
    Some(Incomplete {
        kind,
        segment,
        offset,
        bytes,
    })
}

/// The start of a record's line, as a write cut short leaves it.
const PARTIAL: &[u8] = br#"{"v":1,"seq":7"#;

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    fs::write(path, text).unwrap();
}

/// Restores a file's bytes when dropped, so one test can try many tamperings.
struct Restore(PathBuf, Vec<u8>);

impl Restore {
    fn new(path: &Path) -> Self {
        Restore(path.to_owned(), fs::read(path).unwrap())
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        fs::write(&self.0, &self.1).unwrap();
    }
}

#[test]
fn a_duplicated_key_is_not_a_record() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 20, |_| {});
    let file = segment(&dir, 1);
    let index = dir.join("checkpoints.jsonl");

    // Each tampering puts a second copy of a key before the real one.
    // serde_json keeps the last of duplicate keys, so a last-wins parse sees
    // the original record (and the original hash), while a first-wins reader
    // would see the injected value.
    for (what, anchor, injected) in [
        ("a top-level key", "{", r#""data":{"injected":true},"#),
        ("a key inside data", r#""data":{"#, r#""path":"/injected","#),
    ] {
        let _restore = (Restore::new(&file), Restore::new(&index));
        let mut lines = read_lines(&file);
        let original: Value = serde_json::from_str(&lines[4]).unwrap();
        let at = lines[4].find(anchor).unwrap() + anchor.len();
        lines[4].insert_str(at, injected);
        write_lines(&file, &lines);
        let last_wins: Value = serde_json::from_str(&lines[4]).unwrap();
        assert_eq!(
            last_wins, original,
            "{what}: invisible to a last-wins parse"
        );

        // checkpoints.jsonl is not hashed, so the attacker also moves the
        // offsets of the checkpoints after the longer line.
        let entries: Vec<String> = read_lines(&index)
            .iter()
            .map(|line| {
                let mut entry: Value = serde_json::from_str(line).unwrap();
                let offset = entry["offset"].as_u64().unwrap() + injected.len() as u64;
                entry["offset"] = offset.into();
                entry.to_string()
            })
            .collect();
        write_lines(&index, &entries);
        assert!(
            verify_jsonl(&file).is_err(),
            "{what}: the segment alone is not accepted"
        );

        match verify_session(&dir) {
            Err(VerifyError::Parse {
                segment: 1,
                line: 5,
                reason,
            }) => assert!(reason.contains("duplicate"), "{what}: {reason}"),
            other => panic!("{what}: expected a parse error at line 5, got {other:?}"),
        }
    }
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
}

#[test]
fn an_injected_key_or_null_breaks_the_chain() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 20, |_| {});
    let file = segment(&dir, 1);

    // Keys the typed `Record` cannot see: an unknown one, and explicit nulls
    // for optional fields it reads back as `None`.
    for (key, value) in [
        ("injected", json!(1)),
        ("span", Value::Null),
        ("ts_guest_ns", Value::Null),
    ] {
        let _restore = Restore::new(&file);
        let mut lines = read_lines(&file);
        let mut obj: Value = serde_json::from_str(&lines[4]).unwrap();
        obj.as_object_mut().unwrap().insert(key.into(), value);
        lines[4] = obj.to_string();
        write_lines(&file, &lines);

        // Re-hashing the typed view would accept the tampered line...
        let typed: Record = serde_json::from_str(&lines[4]).unwrap();
        assert_eq!(typed.compute_hash(), typed.hash, "{key}: blind to it");
        // ...the verifier hashes the raw line and does not.
        match verify_session(&dir) {
            Err(VerifyError::Chain { seq: 5, .. }) => {}
            other => panic!("{key}: expected a chain break at seq 5, got {other:?}"),
        }
    }

    // Reordered keys are the same canonical record and still verify.
    let mut lines = read_lines(&file);
    let obj: Value = serde_json::from_str(&lines[4]).unwrap();
    lines[4] = obj.to_string();
    write_lines(&file, &lines);
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
}

#[test]
fn a_deleted_or_reordered_record_is_a_gap() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 20, |_| {});
    let file = segment(&dir, 1);
    {
        let _restore = Restore::new(&file);
        let mut lines = read_lines(&file);
        lines.remove(9);
        write_lines(&file, &lines);
        match verify_session(&dir) {
            Err(VerifyError::Gap {
                expected_seq: 10,
                got_seq: 11,
            }) => {}
            other => panic!("expected a gap at seq 10, got {other:?}"),
        }
    }
    let mut lines = read_lines(&file);
    lines.swap(9, 10);
    write_lines(&file, &lines);
    match verify_session(&dir) {
        Err(VerifyError::Gap {
            expected_seq: 10,
            got_seq: 11,
        }) => {}
        other => panic!("expected a gap at seq 10, got {other:?}"),
    }
}

#[test]
fn the_first_record_must_start_from_genesis() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 5, |_| {});
    let meta: Value = serde_json::from_slice(&fs::read(dir.join("meta.json")).unwrap()).unwrap();
    let id: SessionId = meta["session_id"].as_str().unwrap().parse().unwrap();

    let file = segment(&dir, 1);
    let mut lines = read_lines(&file);
    let mut obj: Value = serde_json::from_str(&lines[0]).unwrap();
    obj["prev"] = json!(Hash([0; 32]).to_string());
    lines[0] = obj.to_string();
    write_lines(&file, &lines);

    match verify_session(&dir) {
        Err(VerifyError::Genesis { expected, got }) => {
            assert_eq!(expected, genesis_prev(&id));
            assert_eq!(got, Hash([0; 32]));
        }
        other => panic!("expected a genesis error, got {other:?}"),
    }
}

/// A standalone chained file: three events, then a checkpoint built by
/// `checkpoint` from the three events' hashes.
fn forged_file(dir: &Path, checkpoint: impl FnOnce(&[Hash]) -> Checkpoint) -> PathBuf {
    let session: SessionId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse().unwrap();
    let mut chain = Chainer::genesis(&session);
    let partial = |payload: Payload| {
        let (kind, data) = payload.into_parts();
        PartialRecord {
            session_id: session.clone(),
            ring: Ring::Host,
            src: payload.source(),
            kind,
            ts_host_ns: 1_790_000_000_000_000_000,
            ts_mono_ns: 1_000,
            ts_guest_ns: None,
            subject: None,
            data,
            span: None,
        }
    };
    let mut records: Vec<Record> = (0..3)
        .map(|n| chain.next(partial(event(n).payload)))
        .collect();
    let hashes: Vec<Hash> = records.iter().map(|r| r.hash).collect();
    records.push(chain.next(partial(Payload::Checkpoint(checkpoint(&hashes)))));

    let path = dir.join("forged.jsonl");
    let lines: Vec<String> = records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    write_lines(&path, &lines);
    path
}

fn root_of(hashes: &[Hash]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for hash in hashes {
        hasher.update(&hash.0);
    }
    Hash::from_blake3(hasher.finalize())
}

#[test]
fn checkpoint_fields_are_recomputed_from_the_chain() {
    let tmp = TempDir::new().unwrap();

    let honest = forged_file(tmp.path(), |hashes| Checkpoint {
        records_since: 3,
        dropped: 0,
        root_hash: root_of(hashes),
    });
    let report = verify_jsonl(&honest).unwrap();
    assert_eq!((report.records, report.checkpoints), (4, 1));

    // Correctly chained, so only the checkpoint arithmetic can catch these.
    let wrong_root = Hash::from_blake3(blake3::hash(b"not the records"));
    let path = forged_file(tmp.path(), |_| Checkpoint {
        records_since: 3,
        dropped: 0,
        root_hash: wrong_root,
    });
    match verify_jsonl(&path) {
        Err(VerifyError::Checkpoint { seq, expected, got }) => {
            assert_eq!(seq, 4);
            assert_eq!(got, wrong_root);
            assert_ne!(expected, wrong_root);
        }
        other => panic!("expected a checkpoint error, got {other:?}"),
    }

    let path = forged_file(tmp.path(), |hashes| Checkpoint {
        records_since: 2,
        dropped: 0,
        root_hash: root_of(hashes),
    });
    match verify_jsonl(&path) {
        Err(VerifyError::CheckpointCount {
            seq: 4,
            expected: 3,
            got: 2,
        }) => {}
        other => panic!("expected a records_since error, got {other:?}"),
    }
}

#[test]
fn checkpoints_jsonl_must_match_the_chain() {
    let tmp = TempDir::new().unwrap();
    // Checkpoints at seq 6, 12, and the final one at 15.
    let dir = session(&tmp, 12, |cfg| cfg.checkpoint_every = 5);
    let index = dir.join("checkpoints.jsonl");
    assert_eq!(read_lines(&index).len(), 3);

    type Tamper = fn(&mut Vec<String>);
    let tamperings: [(&str, u64, Tamper); 4] = [
        ("an offset moved", 2, |lines| {
            let mut entry: Value = serde_json::from_str(&lines[1]).unwrap();
            entry["offset"] = json!(entry["offset"].as_u64().unwrap() + 1);
            lines[1] = entry.to_string();
        }),
        ("a root hash changed", 1, |lines| {
            let mut entry: Value = serde_json::from_str(&lines[0]).unwrap();
            entry["root_hash"] = json!(Hash([7; 32]).to_string());
            lines[0] = entry.to_string();
        }),
        // Not the last line: without it, the log ends in a checkpoint the
        // index does not list, as a crash leaves it (tests/crash.rs).
        ("a line lost", 2, |lines| {
            lines.remove(1);
        }),
        ("a line added", 4, |lines| {
            let last = lines.last().unwrap().clone();
            lines.push(last);
        }),
    ];
    for (what, bad_line, tamper) in tamperings {
        let _restore = Restore::new(&index);
        let mut lines = read_lines(&index);
        tamper(&mut lines);
        write_lines(&index, &lines);
        match verify_session(&dir) {
            Err(VerifyError::CheckpointFile { line, .. }) => assert_eq!(line, bad_line, "{what}"),
            other => panic!("{what}: expected a checkpoints.jsonl error, got {other:?}"),
        }
    }
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
}

#[test]
fn a_truncated_log_is_caught_by_its_checkpoint_file() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 20, |_| {});
    let file = segment(&dir, 1);

    // Cut the last three records at line boundaries: what is left is a valid
    // chain, but checkpoints.jsonl still names the final checkpoint.
    let mut lines = read_lines(&file);
    lines.truncate(lines.len() - 3);
    write_lines(&file, &lines);
    match verify_session(&dir) {
        Err(VerifyError::CheckpointFile { line: 1, reason }) => {
            assert!(reason.contains("seq 21"), "{reason}")
        }
        other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
    }
}

#[test]
fn missing_segments_and_meta_are_layout_errors() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 100, |cfg| cfg.segment_max_bytes = 4096);
    let count = fs::read_dir(&dir)
        .unwrap()
        .filter(|e| {
            let name = e.as_ref().unwrap().file_name();
            name.to_str().unwrap().starts_with("events.")
        })
        .count() as u32;
    assert!(count > 3);

    for (what, path) in [
        ("the last segment", segment(&dir, count)),
        ("a middle segment", segment(&dir, 2)),
        ("meta.json", dir.join("meta.json")),
    ] {
        let _restore = Restore::new(&path);
        fs::remove_file(&path).unwrap();
        match verify_session(&dir) {
            Err(VerifyError::Layout { .. }) => {}
            other => panic!("{what} removed: expected a layout error, got {other:?}"),
        }
    }
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
}

#[test]
fn an_unterminated_last_line_is_incomplete_only_at_the_end_of_the_newest_segment() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 100, |cfg| cfg.segment_max_bytes = 4096);
    let count = segment_count(&dir);
    assert!(count > 2);
    let newest = segment(&dir, count);
    let len = fs::metadata(&newest).unwrap().len();

    // At the end of the newest segment: a write cut short.
    for bytes in [1, PARTIAL.len(), MAX_RECORD_BYTES] {
        let _restore = Restore::new(&newest);
        let mut partial = PARTIAL.to_vec();
        partial.resize(bytes, b'x');
        append(&newest, &partial);
        let report = verify_session(&dir).unwrap();
        assert_eq!(
            report.incomplete,
            incomplete(IncompleteKind::PartialLine, count, len, bytes as u64),
            "{bytes} bytes"
        );
    }

    // Longer than any record, or in a segment before the newest: a break.
    for (file, line, bytes) in [
        (
            count,
            read_lines(&newest).len() as u64 + 1,
            MAX_RECORD_BYTES + 1,
        ),
        (
            1,
            read_lines(&segment(&dir, 1)).len() as u64 + 1,
            PARTIAL.len(),
        ),
        (
            count - 1,
            read_lines(&segment(&dir, count - 1)).len() as u64 + 1,
            1,
        ),
    ] {
        let path = segment(&dir, file);
        let _restore = Restore::new(&path);
        let mut partial = PARTIAL.to_vec();
        partial.resize(bytes, b'x');
        append(&path, &partial);
        match verify_session(&dir) {
            Err(VerifyError::Parse {
                segment,
                line: at,
                reason,
            }) => {
                assert_eq!((segment, at), (file, line), "{reason}");
                assert!(reason.contains("no newline"), "{reason}");
            }
            other => panic!("segment {file}: expected a parse error, got {other:?}"),
        }
    }
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
}

#[test]
fn verify_jsonl_reports_a_partial_last_line() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 5, |_| {});
    let file = segment(&dir, 1);
    let len = fs::metadata(&file).unwrap().len();
    append(&file, PARTIAL);
    let report = verify_jsonl(&file).unwrap();
    assert_eq!(
        report.incomplete,
        incomplete(IncompleteKind::PartialLine, 1, len, PARTIAL.len() as u64)
    );
    assert_eq!((report.records, report.last_seq), (6, 6));

    // A partial line and nothing before it names no session to check.
    let alone = tmp.path().join("partial.jsonl");
    fs::write(&alone, PARTIAL).unwrap();
    assert!(matches!(
        verify_jsonl(&alone),
        Err(VerifyError::Layout { .. })
    ));
}

#[test]
fn two_cut_tails_at_once_are_a_break() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 100, |cfg| cfg.segment_max_bytes = 4096);
    let count = segment_count(&dir);
    let newest = segment(&dir, count);
    let extra = segment(&dir, count + 1);
    let index = dir.join("checkpoints.jsonl");
    let lines = fs::read(&index).unwrap();
    let last = last_line_start(&lines);

    type Cut = fn(&Path, &Path, &Path, &[u8], usize);
    let cuts: [(&str, Cut); 5] = [
        (
            "a partial line, and the last checkpoint unindexed",
            |newest, _, index, lines, last| {
                append(newest, PARTIAL);
                fs::write(index, &lines[..last]).unwrap();
            },
        ),
        (
            "a partial line, and a partial index line",
            |newest, _, index, lines, last| {
                append(newest, PARTIAL);
                fs::write(index, &lines[..last + 5]).unwrap();
            },
        ),
        (
            "a rotation cut short, and the last checkpoint unindexed",
            |_, extra, index, lines, last| {
                fs::write(extra, "").unwrap();
                fs::write(index, &lines[..last]).unwrap();
            },
        ),
        (
            "a rotation cut short, and a partial index line",
            |_, extra, index, lines, last| {
                fs::write(extra, "").unwrap();
                fs::write(index, &lines[..last + 5]).unwrap();
            },
        ),
        (
            "a rotation cut short, and a partial line before it",
            |newest, extra, _, _, _| {
                fs::write(extra, "").unwrap();
                append(newest, PARTIAL);
            },
        ),
    ];
    for (what, cut) in cuts {
        let _restore = (Restore::new(&newest), Restore::new(&index));
        cut(&newest, &extra, &index, &lines, last);
        let result = verify_session(&dir);
        let _ = fs::remove_file(&extra);
        match result {
            Err(VerifyError::CheckpointFile { .. } | VerifyError::Parse { .. }) => {}
            other => panic!("{what}: expected a break, got {other:?}"),
        }
    }
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
}

#[test]
fn a_partial_index_line_must_start_its_checkpoint_s_line() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 20, |cfg| cfg.checkpoint_every = 5);
    let index = dir.join("checkpoints.jsonl");
    let lines = fs::read(&index).unwrap();
    let last = last_line_start(&lines);
    let _restore = Restore::new(&index);

    // The start of the last checkpoint's line, with one byte changed.
    let mut changed = lines[..last + 30].to_vec();
    changed[last + 10] ^= 0x01;
    fs::write(&index, &changed).unwrap();
    match verify_session(&dir) {
        Err(VerifyError::CheckpointFile { reason, .. }) => {
            assert!(reason.contains("not the start of the line"), "{reason}")
        }
        other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
    }

    // A partial line after every checkpoint's line: there is none for it
    // to start.
    let mut extra = lines.clone();
    extra.extend_from_slice(&lines[last..last + 30]);
    fs::write(&index, &extra).unwrap();
    match verify_session(&dir) {
        Err(VerifyError::CheckpointFile { reason, .. }) => {
            assert!(reason.contains("no newline"), "{reason}")
        }
        other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
    }
}

#[test]
fn only_the_last_line_of_the_newest_segment_may_be_an_unindexed_checkpoint() {
    let tmp = TempDir::new().unwrap();
    // Checkpoints at seq 6, 12, and the final one at 15.
    let dir = session(&tmp, 12, |cfg| cfg.checkpoint_every = 5);
    let index = dir.join("checkpoints.jsonl");
    let lines = read_lines(&index);

    // Not the last checkpoint: the index skips one.
    {
        let _restore = Restore::new(&index);
        write_lines(&index, &[lines[0].clone(), lines[2].clone()]);
        assert!(matches!(
            verify_session(&dir),
            Err(VerifyError::CheckpointFile { line: 2, .. })
        ));
    }
    // Two checkpoints unlisted.
    {
        let _restore = Restore::new(&index);
        write_lines(&index, &lines[..1]);
        match verify_session(&dir) {
            Err(VerifyError::CheckpointFile { line: 2, reason }) => {
                assert!(reason.contains("seq 12 is not listed"), "{reason}")
            }
            other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
        }
    }
    // The last checkpoint, but a later segment exists and meta.json lists
    // it: a seal lists its checkpoint before it makes the next segment.
    let meta_path = dir.join("meta.json");
    let _restore = (Restore::new(&index), Restore::new(&meta_path));
    let mut meta: Value = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    meta["segments"] = json!(2);
    fs::write(&meta_path, meta.to_string()).unwrap();
    fs::write(segment(&dir, 2), "").unwrap();
    assert_eq!(
        verify_session(&dir).unwrap().incomplete,
        None,
        "a rotation done"
    );
    write_lines(&index, &lines[..2]);
    let result = verify_session(&dir);
    fs::remove_file(segment(&dir, 2)).unwrap();
    match result {
        Err(VerifyError::CheckpointFile { line: 3, reason }) => {
            assert!(reason.contains("seq 15 is not listed"), "{reason}")
        }
        other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
    }
}

#[test]
fn an_extra_segment_must_be_empty() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 100, |cfg| cfg.segment_max_bytes = 4096);
    let count = segment_count(&dir);
    let extra = segment(&dir, count + 1);

    fs::write(&extra, "").unwrap();
    let report = verify_session(&dir).unwrap();
    assert_eq!(
        report.incomplete,
        incomplete(IncompleteKind::Rotation, count + 1, 0, 0)
    );
    assert_eq!(report.segments, count);

    // Anything in it, even a line that continues the chain, is a break, as
    // is a second extra segment.
    let last = read_lines(&segment(&dir, count)).pop().unwrap();
    for (what, content) in [("a byte", "x".to_owned()), ("a line", format!("{last}\n"))] {
        fs::write(&extra, &content).unwrap();
        match verify_session(&dir) {
            Err(VerifyError::Layout { reason }) => {
                assert!(reason.contains("not empty"), "{what}: {reason}")
            }
            other => panic!("{what}: expected a layout error, got {other:?}"),
        }
    }
    fs::write(&extra, "").unwrap();
    fs::write(segment(&dir, count + 2), "").unwrap();
    assert!(matches!(
        verify_session(&dir),
        Err(VerifyError::Layout { .. })
    ));
}

#[test]
fn an_index_line_past_the_end_stays_a_break() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 20, |_| {});
    let file = segment(&dir, 1);
    let bytes = fs::read(&file).unwrap();

    // Cut inside the final checkpoint's line, which the index lists: a
    // partial line, but the index names a record that is not there.
    let last = last_line_start(&bytes);
    fs::write(&file, &bytes[..last + 20]).unwrap();
    match verify_session(&dir) {
        Err(VerifyError::CheckpointFile { line: 1, reason }) => {
            assert!(reason.contains("past the end"), "{reason}")
        }
        other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
    }
}

#[test]
fn verify_jsonl_checks_one_file_on_its_own() {
    let tmp = TempDir::new().unwrap();
    let dir = session(&tmp, 100, |cfg| cfg.segment_max_bytes = 4096);

    let first = read_lines(&segment(&dir, 1));
    let report = verify_jsonl(&segment(&dir, 1)).unwrap();
    assert_eq!(report.records, first.len() as u64);
    assert_eq!(report.segments, 1);
    assert_eq!(report.checkpoints, 1, "a sealed segment ends in one");
    assert_eq!(report.last_seq, first.len() as u64);

    // Any later segment does not start the chain.
    match verify_jsonl(&segment(&dir, 2)) {
        Err(VerifyError::Gap {
            expected_seq: 1,
            got_seq,
        }) => assert_eq!(got_seq, first.len() as u64 + 1),
        other => panic!("expected a gap at seq 1, got {other:?}"),
    }

    let empty = tmp.path().join("empty.jsonl");
    fs::write(&empty, "").unwrap();
    assert!(matches!(
        verify_jsonl(&empty),
        Err(VerifyError::Layout { .. })
    ));
    assert!(matches!(
        verify_jsonl(&tmp.path().join("missing.jsonl")),
        Err(VerifyError::Io(..))
    ));
}
