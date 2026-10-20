// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `verify_range` against real sessions, and the writer's head it checks
//! them against (`AuditSink::head`): where a range starts (inside a
//! checkpoint's window, on a checkpoint, across a segment rotation), what
//! it sees of a break before and after `from_seq`, that it reads nothing
//! past the head, the stretch limits, and cancellation.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use boxcar_audit::{
    spawn, spawn_with_syncer, verify_range, verify_session, HeadError, LogReader, Priority,
    RangeError, RangeLimits, RangeReport, Submission, Syncer, VerifyError, WriterConfig,
};
use boxcar_proto::{genesis_prev, Attrib, FsIo, Hash, OpResult, Payload, Record, Ring, SessionId};
use tempfile::TempDir;

fn event(n: u64) -> Submission {
    Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
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

/// A closed session of `events` events, a checkpoint after every 10
/// records (and `tune`'s changes), its directory, and its last seq and
/// hash, the head a range is checked against.
fn session(
    tmp: &TempDir,
    events: u64,
    tune: impl FnOnce(&mut WriterConfig),
) -> (PathBuf, (u64, Hash)) {
    let mut cfg = WriterConfig::new(tmp.path(), SessionId::new());
    cfg.checkpoint_every = 10;
    cfg.checkpoint_interval = Duration::from_secs(3600);
    tune(&mut cfg);
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..events {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();
    assert_eq!(verify_session(&dir).unwrap().incomplete, None);
    (dir, (stats.last_seq, stats.last_hash))
}

fn records(dir: &Path) -> Vec<Record> {
    LogReader::open(dir)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .collect()
}

fn range(dir: &Path, from_seq: u64, head: (u64, Hash)) -> Result<RangeReport, RangeError> {
    verify_range(
        dir,
        from_seq,
        head,
        RangeLimits::default(),
        &AtomicBool::new(false),
    )
}

/// The verify error a range ended in.
fn broken(result: Result<RangeReport, RangeError>) -> VerifyError {
    match result {
        Err(RangeError::Break(error)) => error,
        other => panic!("not a break: {other:?}"),
    }
}

fn segment(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("events.{n:06}.jsonl"))
}

/// Rewrites the line of the record at `seq`, wherever it is, with `change`.
fn rewrite(dir: &Path, seq: u64, change: impl Fn(&str) -> String) {
    for n in 1.. {
        let path = segment(dir, n);
        let text = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let needle = format!("\"seq\":{seq},");
        if let Some(line) = lines.iter_mut().find(|l| l.contains(&needle)) {
            let changed = change(line);
            assert_ne!(&changed, line, "the change changed nothing");
            *line = changed;
            let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
            fs::write(&path, text).unwrap();
            return;
        }
    }
}

/// Changes a digit of a record's path, keeping the hash it stores.
fn tamper(dir: &Path, seq: u64) {
    rewrite(dir, seq, |line| line.replacen("/file-0", "/file-9", 1));
}

/// A range from anywhere in a checkpoint's window, from a checkpoint, or
/// from the start, checks the records from there to the head, with the
/// stored hash of the record before as `from_prev`, and counts the
/// checkpoints among them.
#[test]
fn a_range_starts_inside_a_checkpoints_window_or_on_a_checkpoint() {
    let tmp = TempDir::new().unwrap();
    // 45 events: checkpoints at 11, 22, 33, 44, and the closing one at 50.
    let (dir, head) = session(&tmp, 45, |_| {});
    let log = records(&dir);
    assert_eq!(head.0, 50);
    let checkpoints: Vec<u64> = log
        .iter()
        .filter(|r| r.kind == "checkpoint")
        .map(|r| r.seq)
        .collect();
    assert_eq!(checkpoints, [11, 22, 33, 44, 50]);

    for from_seq in [1, 2, 11, 12, 15, 21, 22, 23, 44, 45, 50] {
        let report = range(&dir, from_seq, head).unwrap();
        let from_prev = match from_seq {
            1 => genesis_prev(&log[0].session_id),
            n => log[n as usize - 2].hash,
        };
        let count = checkpoints.iter().filter(|&&c| c >= from_seq).count() as u64;
        assert_eq!(
            report,
            RangeReport {
                from_seq,
                from_prev,
                to_seq: 50,
                to_hash: head.1,
                checkpoints: count,
                more: false,
            },
            "from {from_seq}"
        );
    }
    // 0 is the start, as 1 is.
    assert_eq!(range(&dir, 0, head).unwrap().from_seq, 1);
    // Past the head: nothing to check.
    assert!(matches!(
        range(&dir, 51, head),
        Err(RangeError::PastHead {
            from_seq: 51,
            head_seq: 50
        })
    ));
}

/// Stretch by stretch, under the limits: each one names the stored hash
/// it starts from, which is the hash the one before ended at, and the last
/// one reaches the head.
#[test]
fn stretches_chain_and_end_at_the_head() {
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 45, |_| {});
    for limits in [
        RangeLimits {
            records: 7,
            bytes: u64::MAX,
        },
        RangeLimits {
            records: u64::MAX,
            bytes: 1000,
        },
        RangeLimits {
            records: 1,
            bytes: 1,
        },
    ] {
        let mut from_seq = 1;
        let mut held = genesis_prev(&records(&dir)[0].session_id);
        let mut stretches = 0;
        let mut checkpoints = 0;
        loop {
            let report =
                verify_range(&dir, from_seq, head, limits, &AtomicBool::new(false)).unwrap();
            assert_eq!(report.from_seq, from_seq, "{limits:?}");
            assert_eq!(report.from_prev, held, "{limits:?}: from {from_seq}");
            assert!(report.to_seq >= from_seq, "one record at least");
            if limits.records < u64::MAX {
                assert!(report.to_seq - from_seq < limits.records);
            }
            stretches += 1;
            checkpoints += report.checkpoints;
            held = report.to_hash;
            from_seq = report.to_seq + 1;
            if !report.more {
                assert_eq!((report.to_seq, report.to_hash), head);
                break;
            }
        }
        assert_eq!(checkpoints, 5, "{limits:?}");
        assert!(stretches > 1, "{limits:?}");
        if limits.records == 1 {
            assert_eq!(stretches, 50);
        }
    }
}

/// Segments sealed at a few hundred bytes: a range that starts in one
/// segment and ends in another, one that starts on a segment's sealing
/// checkpoint, and one that starts on the first record of a segment.
#[test]
fn a_range_reads_across_a_segment_rotation() {
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 60, |cfg| cfg.segment_max_bytes = 2500);
    assert!(segment(&dir, 3).exists(), "several segments");
    let log = records(&dir);
    let first_of_two = {
        let text = fs::read_to_string(segment(&dir, 2)).unwrap();
        let first: Record = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        first.seq
    };
    let sealing = first_of_two - 1;
    assert_eq!(log[sealing as usize - 1].kind, "checkpoint");
    for from_seq in [2, 3, sealing - 1, sealing, first_of_two, first_of_two + 1] {
        let report = range(&dir, from_seq, head).unwrap();
        assert_eq!(report.from_prev, log[from_seq as usize - 2].hash);
        assert_eq!((report.to_seq, report.more), (head.0, false));
    }
}

/// The records before `from_seq` are not checked, only their stored
/// hashes kept: a change to one that keeps its hash is not seen from after
/// it, and is seen from it or from before it. A changed stored hash in the
/// window shows at the checkpoint that closes it.
#[test]
fn a_break_before_from_seq_is_not_seen_and_one_after_it_is() {
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 45, |_| {});
    tamper(&dir, 15);
    for from_seq in [1, 12, 15] {
        assert!(
            matches!(
                broken(range(&dir, from_seq, head)),
                VerifyError::Chain { seq: 15, .. }
            ),
            "from {from_seq}"
        );
    }
    for from_seq in [16, 20, 22] {
        range(&dir, from_seq, head).unwrap_or_else(|e| panic!("from {from_seq}: {e}"));
    }

    // A stored hash changed in the window: the checkpoint's root says so.
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 45, |_| {});
    let other = Hash([7; 32]);
    rewrite(&dir, 14, |line| {
        let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["hash"] = serde_json::to_value(other).unwrap();
        serde_json::to_string(&record).unwrap()
    });
    assert!(matches!(
        broken(range(&dir, 16, head)),
        VerifyError::Checkpoint { seq: 22, .. }
    ));
    // From the record after it, its link to the changed hash breaks.
    assert!(matches!(
        broken(range(&dir, 15, head)),
        VerifyError::Chain { seq: 15, expected, .. } if expected == other
    ));
}

/// A line that is not a record, past the start, is named by its segment
/// and line number, though the walk started mid-segment.
#[test]
fn a_line_that_is_not_a_record_is_named_by_its_line() {
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 45, |_| {});
    rewrite(&dir, 30, |line| line.replacen('{', "{\"seq\":30,", 1));
    match broken(range(&dir, 25, head)) {
        VerifyError::Parse { segment, line, .. } => assert_eq!((segment, line), (1, 30)),
        other => panic!("{other}"),
    }
}

/// The index lines of the checkpoints a range checks must list them: a
/// changed field, a missing line, and one that names a record that is not
/// a checkpoint are breaks. One that names a checkpoint before the range,
/// where the range starts, must name that checkpoint.
#[test]
fn the_index_must_list_the_checkpoints_in_the_range() {
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 45, |_| {});
    let index = dir.join("checkpoints.jsonl");
    let original = fs::read_to_string(&index).unwrap();
    let lines: Vec<&str> = original.lines().collect();
    assert_eq!(lines.len(), 5);
    let write = |lines: &[String]| {
        fs::write(
            &index,
            lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
        )
        .unwrap()
    };
    let owned: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();

    // The checkpoint at 33: a field changed.
    let mut changed = owned.clone();
    changed[2] = changed[2].replacen("\"dropped\":0", "\"dropped\":1", 1);
    write(&changed);
    let error = broken(range(&dir, 23, head));
    assert!(
        matches!(&error, VerifyError::CheckpointFile { line: 3, reason } if reason.contains("dropped")),
        "{error}"
    );
    // Not in this range, nor where it starts.
    range(&dir, 45, head).unwrap();
    let short = RangeLimits {
        records: 10,
        bytes: u64::MAX,
    };
    let report = verify_range(&dir, 12, head, short, &AtomicBool::new(false)).unwrap();
    assert_eq!((report.to_seq, report.more), (21, true));
    // Where a range starts, its line must name the checkpoint as it is.
    for from_seq in [34, 40] {
        let error = broken(range(&dir, from_seq, head));
        assert!(
            matches!(error, VerifyError::CheckpointFile { line: 3, .. }),
            "{error}"
        );
    }

    // The line for 33 missing: 44's line comes where 33's should.
    let mut missing = owned.clone();
    missing.remove(2);
    write(&missing);
    let error = broken(range(&dir, 30, head));
    assert!(
        matches!(&error, VerifyError::CheckpointFile { line: 3, reason } if reason.contains("seq 44")),
        "{error}"
    );
    // The last line missing: nothing comes after.
    let mut cut = owned.clone();
    cut.pop();
    write(&cut);
    let error = broken(range(&dir, 45, head));
    assert!(
        matches!(&error, VerifyError::CheckpointFile { line: 5, reason } if reason.contains("not listed")),
        "{error}"
    );
    write(&owned);
    range(&dir, 1, head).unwrap();
}

/// Nothing past the head is read: records, checkpoints and index lines the
/// writer appends meanwhile, or damage past the head, change nothing.
#[test]
fn nothing_past_the_head_is_read() {
    let tmp = TempDir::new().unwrap();
    let (dir, last) = session(&tmp, 45, |_| {});
    let log = records(&dir);
    let head = (33, log[32].hash);
    let report = range(&dir, 1, head).unwrap();
    assert_eq!(
        (report.to_seq, report.more, report.checkpoints),
        (33, false, 3)
    );

    // Damage past the head: a record, the index line of a later checkpoint,
    // a line appended whole and one appended in part.
    tamper(&dir, 40);
    let index = dir.join("checkpoints.jsonl");
    let text = fs::read_to_string(&index).unwrap();
    let damaged = text.replacen("\"seq\":44,", "\"seq\":45,", 1);
    assert_ne!(damaged, text);
    fs::write(&index, damaged).unwrap();
    let mut file = OpenOptions::new().append(true).open(&index).unwrap();
    file.write_all(b"{\"seq\":999}\n{\"seq\":1000,\"segm")
        .unwrap();
    for from_seq in [1, 20, 33] {
        let report = range(&dir, from_seq, head).unwrap();
        assert_eq!((report.to_seq, report.to_hash), head);
    }
    // To the old end of the log, it is all seen.
    assert!(matches!(
        broken(range(&dir, 34, last)),
        VerifyError::Chain { seq: 40, .. }
    ));
}

/// A live writer: its head, then more records and checkpoints than the
/// head knows of, and the range checks to the head it was given.
#[test]
fn a_live_writer_answers_its_head_and_goes_on() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = WriterConfig::new(tmp.path(), SessionId::new());
    cfg.checkpoint_every = 10;
    cfg.checkpoint_interval = Duration::from_secs(3600);
    let (sink, writer) = spawn(cfg).unwrap();
    for n in 0..25 {
        sink.emit(event(n)).unwrap();
    }
    let head = sink.head().unwrap();
    assert_eq!(head.session_dir, writer.session_dir());
    // 25 events and two checkpoints, every one in the file.
    assert_eq!(head.seq, 27);
    for n in 25..60 {
        sink.emit(event(n)).unwrap();
    }
    let report = range(&head.session_dir, 1, (head.seq, head.hash)).unwrap();
    assert_eq!((report.to_seq, report.to_hash), (head.seq, head.hash));
    assert_eq!(report.checkpoints, 2);
    let later = sink.head().unwrap();
    assert!(later.seq > head.seq + 35, "{later:?}");
    let report = range(&later.session_dir, head.seq + 1, (later.seq, later.hash)).unwrap();
    assert_eq!(report.from_prev, head.hash);
    assert_eq!(report.to_seq, later.seq);

    // An empty log's head is the genesis hash at seq 0.
    let tmp = TempDir::new().unwrap();
    let id = SessionId::new();
    let (empty, empty_writer) = spawn(WriterConfig::new(tmp.path(), id.clone())).unwrap();
    let head = empty.head().unwrap();
    assert_eq!((head.seq, head.hash), (0, genesis_prev(&id)));
    empty_writer.close().unwrap();

    // A closed writer has no head.
    writer.close().unwrap();
    assert_eq!(sink.head(), Err(HeadError::Closed));
}

/// Fails every sync, as a broken disk would.
struct BrokenDisk;

impl Syncer for BrokenDisk {
    fn sync(&self, _: &File) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }
}

/// A failed writer answers no head: the failure is what the caller gets.
#[test]
fn a_failed_writer_answers_no_head() {
    let tmp = TempDir::new().unwrap();
    let cfg = WriterConfig::new(tmp.path(), SessionId::new());
    let (sink, writer) = spawn_with_syncer(cfg, BrokenDisk).unwrap();
    sink.emit(event(0)).unwrap();
    sink.emit(Submission {
        priority: Priority::Critical,
        ..event(1)
    })
    .unwrap();
    let failure = loop {
        if let Some(failure) = sink.failure() {
            break failure;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(sink.head(), Err(HeadError::Failed(failure.clone())));
    assert_eq!(
        HeadError::Failed(failure.clone()).to_string(),
        format!("the audit log writer failed: {failure}")
    );
    assert!(writer.close().is_err());
    assert_eq!(sink.head(), Err(HeadError::Failed(failure)));
}

/// The record at the head must carry the head's hash.
#[test]
fn the_head_must_be_the_record_there() {
    let tmp = TempDir::new().unwrap();
    let (dir, (seq, hash)) = session(&tmp, 20, |_| {});
    let other = Hash([9; 32]);
    let error = broken(range(&dir, 1, (seq, other)));
    assert!(
        matches!(error, VerifyError::Chain { seq: s, expected, got } if s == seq && expected == other && got == hash),
        "{error}"
    );
    // A head past the end of the log.
    let error = broken(range(&dir, 1, (seq + 5, hash)));
    assert!(matches!(error, VerifyError::Layout { .. }), "{error}");
}

/// A set cancel flag stops the walk before the next record: here before
/// the first, so the break further on is never reached.
#[test]
fn a_cancelled_walk_stops_before_the_next_record() {
    let tmp = TempDir::new().unwrap();
    let (dir, head) = session(&tmp, 45, |_| {});
    tamper(&dir, 2);
    let cancel = AtomicBool::new(true);
    for from_seq in [1, 20] {
        assert!(matches!(
            verify_range(&dir, from_seq, head, RangeLimits::default(), &cancel),
            Err(RangeError::Cancelled)
        ));
    }
}
