// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The audit writer end to end, on real files in a temporary directory:
//! sequencing under concurrent producers, rotation, tamper evidence, torn
//! tails, the fsync policy, checkpoints, and back-pressure. Every result is
//! read back through `LogReader` and checked with `verify_session`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boxcar_audit::{
    spawn, spawn_with_syncer, verify_session, LogReader, Priority, SinkClosed, Submission, Syncer,
    VerifyError, WriterConfig,
};
use boxcar_proto::{FsIo, Hash, OpResult, Payload, Record, Ring, SessionId, Subject};
use serde_json::Value;
use tempfile::TempDir;

const HOUR: Duration = Duration::from_secs(3600);

/// A writer config for a fresh session under `data_dir`, with the defaults.
fn config(data_dir: &Path) -> WriterConfig {
    WriterConfig::new(data_dir, SessionId::new())
}

/// A filesystem event whose `fh` is `n`, so tests can tell events apart.
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
            fh: n,
            offset: n * 4096,
            len: 4096,
            result: OpResult::ok(),
        }),
        span: None,
        priority: Priority::Normal,
    }
}

fn critical(n: u64) -> Submission {
    Submission {
        priority: Priority::Critical,
        ..event(n)
    }
}

/// The `n` of a record written from `event(n)`.
fn event_number(r: &Record) -> u64 {
    r.data["fh"].as_u64().expect("an event record")
}

fn is_checkpoint(r: &Record) -> bool {
    r.kind == "checkpoint"
}

/// Every record of a session, in log order.
fn read_records(session_dir: &Path) -> Vec<Record> {
    LogReader::open(session_dir)
        .unwrap()
        .records()
        .collect::<io::Result<_>>()
        .unwrap()
}

fn seqs(records: &[Record]) -> Vec<u64> {
    records.iter().map(|r| r.seq).collect()
}

fn one_to(n: usize) -> Vec<u64> {
    (1..=n as u64).collect()
}

/// The segment files of a session, in order.
fn segment_files(session_dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(session_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.starts_with("events.") && name.ends_with(".jsonl")
        })
        .collect();
    files.sort();
    files
}

/// The lines of a file, newline excluded, each with the offset it starts at.
fn lines_with_offsets(path: &Path) -> Vec<(u64, Vec<u8>)> {
    let bytes = fs::read(path).unwrap();
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push((start as u64, bytes[start..i].to_vec()));
            start = i + 1;
        }
    }
    assert_eq!(
        start,
        bytes.len(),
        "{} ends in a partial line",
        path.display()
    );
    lines
}

fn parse(line: &[u8]) -> Record {
    serde_json::from_slice(line).unwrap()
}

fn meta(session_dir: &Path) -> Value {
    serde_json::from_slice(&fs::read(session_dir.join("meta.json")).unwrap()).unwrap()
}

fn truncate(path: &Path, len: u64) {
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(len)
        .unwrap();
}

/// Checks each checkpoint record against its own recomputation, done here
/// from the rule and not with the library: `root_hash` is blake3 over the raw
/// 32-byte hashes of the records since the previous checkpoint, and
/// `records_since` counts them. Returns the checkpoints' seqs.
fn check_checkpoints(records: &[Record]) -> Vec<u64> {
    let mut window = blake3::Hasher::new();
    let mut since = 0u64;
    let mut found = Vec::new();
    for r in records {
        if is_checkpoint(r) {
            let root = Hash::from_blake3(window.finalize());
            assert_eq!(
                r.data["root_hash"],
                Value::String(root.to_string()),
                "root_hash of the checkpoint at seq {}",
                r.seq
            );
            assert_eq!(
                r.data["records_since"], since,
                "records_since of the checkpoint at seq {}",
                r.seq
            );
            window = blake3::Hasher::new();
            since = 0;
            found.push(r.seq);
        } else {
            window.update(&r.hash.0);
            since += 1;
        }
    }
    found
}

// (a) Gap-free seq under 8 producer threads.

#[test]
fn seq_is_gap_free_under_eight_concurrent_producers() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = spawn(config(tmp.path())).unwrap();
    let dir = writer.session_dir().to_path_buf();

    let producers: Vec<_> = (0..8u64)
        .map(|t| {
            let sink = sink.clone();
            thread::spawn(move || {
                for i in 0..1000 {
                    sink.emit(event(t * 1000 + i)).unwrap();
                }
            })
        })
        .collect();
    for producer in producers {
        producer.join().unwrap();
    }
    // `sink` is still alive: close must not wait for every clone to drop.
    let stats = writer.close().unwrap();

    let records = read_records(&dir);
    assert_eq!(seqs(&records), one_to(records.len()), "seq 1, 2, 3, ...");

    let events: Vec<&Record> = records.iter().filter(|r| !is_checkpoint(r)).collect();
    assert_eq!(events.len(), 8000);
    let mut seen = vec![false; 8000];
    let mut last_of = [None::<u64>; 8];
    for r in &events {
        let n = event_number(r);
        assert!(!seen[n as usize], "event {n} written twice");
        seen[n as usize] = true;
        let producer = (n / 1000) as usize;
        assert!(
            last_of[producer] < Some(n),
            "producer {producer}'s events are out of order at {n}"
        );
        last_of[producer] = Some(n);
    }
    assert!(seen.iter().all(|&s| s), "every event is in the log");

    let checkpoints = check_checkpoints(&records);
    assert!(
        is_checkpoint(records.last().unwrap()),
        "close ends the log with a checkpoint"
    );
    assert_eq!(stats.records, records.len() as u64);
    assert_eq!(stats.last_seq, records.len() as u64);
    assert_eq!(stats.last_hash, records.last().unwrap().hash);
    assert_eq!(stats.dropped, 0);

    let report = verify_session(&dir).unwrap();
    assert_eq!(report.records, records.len() as u64);
    assert_eq!(report.segments, 1);
    assert_eq!(report.checkpoints as usize, checkpoints.len());
    assert_eq!(report.last_seq, stats.last_seq);
    assert_eq!(report.last_hash, stats.last_hash);
}

// (b) Rotation.

#[test]
fn rotation_keeps_one_chain_across_segments() {
    const MAX: u64 = 64 * 1024;
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.segment_max_bytes = MAX;
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..10_000 {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();

    let files = segment_files(&dir);
    assert!(files.len() > 1, "10k records over 64 KiB segments rotate");
    assert_eq!(meta(&dir)["segments"], files.len() as u64);
    for (i, file) in files.iter().enumerate() {
        let name = file.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, format!("events.{:06}.jsonl", i + 1));
    }
    for file in &files[..files.len() - 1] {
        let size = fs::metadata(file).unwrap().len();
        assert!(size >= MAX, "sealed only once it reaches the limit: {size}");
        assert!(size < MAX + 2048, "and sealed right then: {size}");
        let (_, last) = lines_with_offsets(file).pop().unwrap();
        assert!(
            is_checkpoint(&parse(&last)),
            "{} ends with a checkpoint",
            file.display()
        );
    }

    // The chain runs straight through each segment boundary.
    let mut previous: Option<Record> = None;
    for file in &files {
        let lines = lines_with_offsets(file);
        let first = parse(&lines[0].1);
        if let Some(previous) = &previous {
            assert_eq!(first.prev, previous.hash, "{}", file.display());
            assert_eq!(first.seq, previous.seq + 1, "{}", file.display());
        }
        previous = Some(parse(&lines[lines.len() - 1].1));
    }

    let records = read_records(&dir);
    assert_eq!(seqs(&records), one_to(records.len()));
    assert_eq!(records.iter().filter(|r| !is_checkpoint(r)).count(), 10_000);
    check_checkpoints(&records);

    let report = verify_session(&dir).unwrap();
    assert_eq!(report.segments as usize, files.len());
    assert_eq!(report.records, records.len() as u64);
    assert_eq!(
        (report.last_seq, report.last_hash),
        (stats.last_seq, stats.last_hash)
    );
}

// (c) One flipped byte.

#[test]
fn a_flipped_byte_fails_verification_at_that_record() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.segment_max_bytes = 16 * 1024;
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..1000 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();
    verify_session(&dir).unwrap();

    // An event record in the middle of a middle segment.
    let files = segment_files(&dir);
    let file = &files[files.len() / 2];
    let lines = lines_with_offsets(file);
    let (offset, line) = lines[lines.len() / 2..]
        .iter()
        .find(|(_, line)| !is_checkpoint(&parse(line)))
        .unwrap();
    let target = parse(line);

    // Flip the low bit of the first digit of its path: '0' becomes '1'.
    let digit = line.windows(6).position(|w| w == b"/file-").unwrap() + 6;
    let mut bytes = fs::read(file).unwrap();
    bytes[*offset as usize + digit] ^= 0x01;
    fs::write(file, bytes).unwrap();

    match verify_session(&dir) {
        Err(VerifyError::Chain { seq, .. }) => assert_eq!(seq, target.seq),
        other => panic!(
            "expected a chain break at seq {}, got {other:?}",
            target.seq
        ),
    }
}

#[test]
fn every_one_byte_flip_of_a_record_is_caught_at_that_record() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = spawn(config(tmp.path())).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..30 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    let file = segment_files(&dir).remove(0);
    let original = fs::read(&file).unwrap();
    let line_no = 15u64;
    let (offset, line) = lines_with_offsets(&file).swap_remove(line_no as usize - 1);
    let seq = parse(&line).seq;

    for i in 0..line.len() {
        let mut tampered = original.clone();
        tampered[offset as usize + i] ^= 0x01;
        fs::write(&file, &tampered).unwrap();
        // A changed value breaks the hash; a changed `seq` digit is a gap
        // at this record; anything else no longer parses. Never later.
        match verify_session(&dir) {
            Err(VerifyError::Chain { seq: at, .. }) => assert_eq!(at, seq, "byte {i}"),
            Err(VerifyError::Gap {
                expected_seq: at, ..
            }) => assert_eq!(at, seq, "byte {i}"),
            Err(VerifyError::Parse {
                segment: 1, line, ..
            }) => assert_eq!(line, line_no, "byte {i}"),
            other => panic!(
                "byte {i} ({:?} -> {:?}): expected a break at seq {seq}, got {other:?}",
                char::from(line[i]),
                char::from(line[i] ^ 0x01)
            ),
        }
    }
    fs::write(&file, &original).unwrap();
    verify_session(&dir).unwrap();
}

// (d) Torn tail.

#[test]
fn a_torn_tail_is_cut_and_the_chain_resumes() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.checkpoint_every = 16;
    let (sink, writer) = spawn(cfg.clone()).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..100 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();
    assert_eq!(meta(&dir)["recovered_from_seq"], Value::Null);

    // Checkpoints fall at seq 17, 34, 51, 68, ...: seq 60 is event 56. Tear
    // the segment in the middle of its line, cutting three checkpoints that
    // checkpoints.jsonl already lists.
    let file = segment_files(&dir).remove(0);
    let (offset, line) = lines_with_offsets(&file).swap_remove(59);
    assert_eq!(parse(&line).seq, 60);
    assert_eq!(event_number(&parse(&line)), 56);
    truncate(&file, offset + line.len() as u64 / 2);
    assert!(verify_session(&dir).is_err(), "a torn log does not verify");

    let (sink, writer) = spawn(cfg).unwrap();
    assert_eq!(writer.session_dir(), dir);
    for n in 100..130 {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();

    assert_eq!(meta(&dir)["recovered_from_seq"], 59);
    let records = read_records(&dir);
    assert_eq!(seqs(&records), one_to(records.len()));
    let events: Vec<u64> = records
        .iter()
        .filter(|r| !is_checkpoint(r))
        .map(event_number)
        .collect();
    let expected: Vec<u64> = (0..56).chain(100..130).collect();
    assert_eq!(events, expected, "the cut events are gone, the rest follow");
    // The first checkpoint after the resume also covers the records that
    // were written before the cut but after the last surviving checkpoint.
    check_checkpoints(&records);

    let report = verify_session(&dir).unwrap();
    assert_eq!(report.last_seq, stats.last_seq);
    assert_eq!(report.last_hash, stats.last_hash);
}

#[test]
fn recovery_does_not_keep_a_complete_but_corrupted_record() {
    let tmp = TempDir::new().unwrap();
    let cfg = config(tmp.path());
    let (sink, writer) = spawn(cfg.clone()).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..20 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    // Seq 20 (event 19) still parses and has the right seq and prev, but a
    // digit of its path changed, so its hash no longer matches. The final
    // checkpoint after it chains correctly onto the stated hash.
    let file = segment_files(&dir).remove(0);
    let (offset, line) = lines_with_offsets(&file).swap_remove(19);
    assert_eq!(parse(&line).seq, 20);
    let digit = line.windows(6).position(|w| w == b"/file-").unwrap() + 6;
    let mut bytes = fs::read(&file).unwrap();
    bytes[offset as usize + digit] ^= 0x01;
    fs::write(&file, bytes).unwrap();

    let (sink, writer) = spawn(cfg).unwrap();
    for n in 100..103 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    assert_eq!(meta(&dir)["recovered_from_seq"], 19);
    let events: Vec<u64> = read_records(&dir)
        .iter()
        .filter(|r| !is_checkpoint(r))
        .map(event_number)
        .collect();
    assert_eq!(events, (0..19).chain(100..103).collect::<Vec<_>>());
    verify_session(&dir).unwrap();
}

#[test]
fn a_torn_first_line_resumes_from_the_previous_segment() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.segment_max_bytes = 4096;
    let (sink, writer) = spawn(cfg.clone()).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..100 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    let files = segment_files(&dir);
    assert!(files.len() > 2);
    let last = files.last().unwrap();
    let (_, first) = lines_with_offsets(last).swap_remove(0);
    let first_seq = parse(&first).seq;
    truncate(last, first.len() as u64 / 2);

    let (sink, writer) = spawn(cfg).unwrap();
    for n in 100..110 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    assert_eq!(meta(&dir)["recovered_from_seq"], first_seq - 1);
    let records = read_records(&dir);
    assert_eq!(seqs(&records), one_to(records.len()));
    let tail: Vec<u64> = records
        .iter()
        .filter(|r| !is_checkpoint(r))
        .map(event_number)
        .skip_while(|&n| n < 100)
        .collect();
    assert_eq!(tail, (100..110).collect::<Vec<_>>());
    check_checkpoints(&records);
    verify_session(&dir).unwrap();
}

#[test]
fn a_lost_checkpoint_line_is_rebuilt_on_reopen() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.checkpoint_every = 10;
    let (sink, writer) = spawn(cfg.clone()).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..25 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    // As if the process died after the checkpoint record was synced but
    // before its line reached checkpoints.jsonl.
    let index = dir.join("checkpoints.jsonl");
    let text = fs::read_to_string(&index).unwrap();
    let kept: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
    assert_eq!(text.lines().count(), 3);
    fs::write(&index, kept).unwrap();
    assert!(matches!(
        verify_session(&dir),
        Err(VerifyError::CheckpointFile { .. })
    ));

    let (sink, writer) = spawn(cfg).unwrap();
    for n in 25..30 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    assert_eq!(meta(&dir)["recovered_from_seq"], Value::Null, "nothing cut");
    let report = verify_session(&dir).unwrap();
    assert_eq!(report.checkpoints, 4);
}

#[test]
fn a_session_has_one_writer_at_a_time() {
    let tmp = TempDir::new().unwrap();
    let cfg = config(tmp.path());
    let (_sink, writer) = spawn(cfg.clone()).unwrap();
    let err = spawn(cfg.clone())
        .err()
        .expect("a second writer is refused");
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock, "{err}");
    writer.close().unwrap();
    let (_sink, writer) = spawn(cfg).unwrap();
    writer.close().unwrap();
}

// (e) Critical records are synced at once.

/// Records the file size at every sync the segment writer asks for.
#[derive(Clone, Default)]
struct SyncLog(Arc<Mutex<Vec<u64>>>);

impl Syncer for SyncLog {
    fn sync(&self, file: &File) -> io::Result<()> {
        self.0.lock().unwrap().push(file.metadata()?.len());
        file.sync_data()
    }
}

#[test]
fn a_critical_record_is_synced_on_its_own() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.checkpoint_every = u64::MAX;
    cfg.checkpoint_interval = HOUR;
    let syncs = SyncLog::default();
    let (sink, writer) = spawn_with_syncer(cfg, syncs.clone()).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..3 {
        sink.emit(event(n)).unwrap();
    }
    sink.emit(critical(3)).unwrap();
    for n in 4..6 {
        sink.emit(event(n)).unwrap();
    }
    sink.emit(critical(6)).unwrap();
    sink.emit(event(7)).unwrap();
    writer.close().unwrap();

    let lines = lines_with_offsets(&segment_files(&dir)[0]);
    assert_eq!(lines.len(), 9, "8 events and the final checkpoint");
    assert!(is_checkpoint(&parse(&lines[8].1)));
    let end_of = |seq: usize| {
        let (offset, line) = &lines[seq - 1];
        offset + line.len() as u64 + 1
    };
    assert_eq!(
        *syncs.0.lock().unwrap(),
        [end_of(4), end_of(7), end_of(9)],
        "one fdatasync right after each critical record (seq 4 and 7), while the \
         file still ended with it; none for normal records; one for the final checkpoint"
    );
    verify_session(&dir).unwrap();
}

// (f) Checkpoints.

#[test]
fn checkpoints_fall_every_n_records_and_cover_them() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.checkpoint_every = 10;
    cfg.checkpoint_interval = HOUR;
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..35 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    let records = read_records(&dir);
    assert_eq!(check_checkpoints(&records), [11, 22, 33, 39]);
    let since: Vec<&Value> = records
        .iter()
        .filter(|r| is_checkpoint(r))
        .map(|r| &r.data["records_since"])
        .collect();
    assert_eq!(since, [10, 10, 10, 5]);
    for r in records.iter().filter(|r| is_checkpoint(r)) {
        assert_eq!(r.data["dropped"], 0);
        assert_eq!(r.src, boxcar_proto::Source::Vmm);
        assert_eq!(r.ring, Ring::Host);
    }

    // checkpoints.jsonl names each checkpoint record by seq, segment and the
    // byte offset its line starts at, and repeats its fields.
    let lines = lines_with_offsets(&segment_files(&dir)[0]);
    let index: Vec<Value> = fs::read_to_string(dir.join("checkpoints.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(index.len(), 4);
    for (entry, seq) in index.iter().zip([11u64, 22, 33, 39]) {
        let (offset, line) = &lines[seq as usize - 1];
        let r = parse(line);
        assert_eq!(entry["seq"], seq);
        assert_eq!(entry["segment"], 1);
        assert_eq!(entry["offset"], *offset);
        for field in ["root_hash", "records_since", "dropped"] {
            assert_eq!(entry[field], r.data[field], "{field} of seq {seq}");
        }
    }

    let report = verify_session(&dir).unwrap();
    assert_eq!(report.checkpoints, 4);
}

#[test]
fn a_checkpoint_follows_the_interval_without_waiting_for_close() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.checkpoint_every = 1_000_000;
    cfg.checkpoint_interval = Duration::from_millis(50);
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..3 {
        sink.emit(event(n)).unwrap();
    }

    let give_up = Instant::now() + Duration::from_secs(10);
    let checkpoint = loop {
        if let Some(r) = read_records(&dir).into_iter().find(is_checkpoint) {
            break r;
        }
        assert!(Instant::now() < give_up, "no checkpoint within 10 s");
        thread::sleep(Duration::from_millis(10));
    };
    assert!(checkpoint.seq > 1);
    assert_eq!(checkpoint.data["records_since"], checkpoint.seq - 1);

    writer.close().unwrap();
    check_checkpoints(&read_records(&dir));
    verify_session(&dir).unwrap();
}

// Back-pressure: droppable events count their drops, never-drop events wait.

/// Holds the writer inside its first sync until the test opens the gate.
#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<(u32, bool)>, Condvar)>);

impl Gate {
    fn wait_until_entered(&self) {
        let (lock, cv) = &*self.0;
        let _entered = cv.wait_while(lock.lock().unwrap(), |s| s.0 == 0).unwrap();
    }

    fn open(&self) {
        let (lock, cv) = &*self.0;
        lock.lock().unwrap().1 = true;
        cv.notify_all();
    }
}

impl Syncer for Gate {
    fn sync(&self, file: &File) -> io::Result<()> {
        let (lock, cv) = &*self.0;
        let mut state = lock.lock().unwrap();
        state.0 += 1;
        cv.notify_all();
        drop(cv.wait_while(state, |s| !s.1).unwrap());
        file.sync_data()
    }
}

/// Opens the gate when dropped. Declared after the writer handle, it drops
/// first, so a failed assertion ends the test instead of leaving the handle's
/// drop waiting on a writer parked in the gate.
struct OpenOnDrop(Gate);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

#[test]
fn droppable_events_count_drops_and_never_drop_events_wait() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.channel_capacity = 4;
    cfg.checkpoint_every = u64::MAX;
    cfg.checkpoint_interval = HOUR;
    let gate = Gate::default();
    let (sink, writer) = spawn_with_syncer(cfg, gate.clone()).unwrap();
    let _open_on_exit = OpenOnDrop(gate.clone());
    let dir = writer.session_dir().to_path_buf();

    // The writer takes the critical record and blocks in its fdatasync.
    sink.emit(critical(0)).unwrap();
    gate.wait_until_entered();

    for n in 1..=4 {
        assert!(sink.try_emit(event(n)), "room for event {n}");
    }
    for n in 5..=7 {
        assert!(!sink.try_emit(event(n)), "the channel is full at event {n}");
    }
    assert_eq!(sink.dropped(), 3);

    let returned = Arc::new(AtomicBool::new(false));
    let blocked = thread::spawn({
        let sink = sink.clone();
        let returned = returned.clone();
        move || {
            sink.emit(event(8)).unwrap();
            returned.store(true, Ordering::SeqCst);
        }
    });
    thread::sleep(Duration::from_millis(200));
    assert!(
        !returned.load(Ordering::SeqCst),
        "emit waits for room instead of dropping"
    );

    gate.open();
    blocked.join().unwrap();
    let stats = writer.close().unwrap();
    assert_eq!(stats.dropped, 3);

    let records = read_records(&dir);
    let events: Vec<u64> = records
        .iter()
        .filter(|r| !is_checkpoint(r))
        .map(event_number)
        .collect();
    assert_eq!(events, [0, 1, 2, 3, 4, 8]);
    let last = records.last().unwrap();
    assert!(is_checkpoint(last));
    assert_eq!(last.data["dropped"], 3, "the checkpoint reports the drops");

    // After close the sink refuses everything, and refusals are not drops.
    assert_eq!(sink.emit(event(9)), Err(SinkClosed));
    assert!(!sink.try_emit(event(10)));
    assert_eq!(sink.dropped(), 3);
    verify_session(&dir).unwrap();
}

#[test]
fn dropping_the_handle_finishes_the_log() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = spawn(config(tmp.path())).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..5 {
        sink.emit(event(n)).unwrap();
    }
    drop(writer);

    assert_eq!(sink.emit(event(5)), Err(SinkClosed));
    let records = read_records(&dir);
    assert_eq!(records.len(), 6);
    assert!(is_checkpoint(&records[5]));
    verify_session(&dir).unwrap();
}

// The reader.

#[test]
fn the_reader_seeks_by_seq_and_finds_the_last_record() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(tmp.path());
    cfg.segment_max_bytes = 16 * 1024;
    cfg.checkpoint_every = 100;
    let (sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..2000 {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();
    assert!(segment_files(&dir).len() > 3);

    let mut reader = LogReader::open(&dir).unwrap();
    // 101 is a checkpoint; the others land in various segments.
    for target in [
        1,
        2,
        101,
        102,
        555,
        1234,
        stats.last_seq - 1,
        stats.last_seq,
    ] {
        reader.seek_seq(target).unwrap();
        let next: Vec<u64> = reader.records().take(3).map(|r| r.unwrap().seq).collect();
        let want: Vec<u64> = (target..=stats.last_seq).take(3).collect();
        assert_eq!(next, want, "after seek_seq({target})");
    }
    reader.seek_seq(stats.last_seq + 1).unwrap();
    assert!(reader.records().next().is_none(), "nothing past the end");

    let last = reader.last().unwrap().unwrap();
    assert_eq!((last.seq, last.hash), (stats.last_seq, stats.last_hash));
    assert!(is_checkpoint(&last));
}

#[test]
fn the_reader_names_the_segment_and_line_of_a_bad_line() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = spawn(config(tmp.path())).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..50 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();

    let file = segment_files(&dir).remove(0);
    let (offset, _) = lines_with_offsets(&file).swap_remove(19);
    let mut bytes = fs::read(&file).unwrap();
    bytes[offset as usize] = b'x';
    fs::write(&file, bytes).unwrap();

    let reader = LogReader::open(&dir).unwrap();
    let results: Vec<io::Result<Record>> = reader.records().collect();
    assert_eq!(
        results.len(),
        20,
        "19 records, then the error, then nothing"
    );
    assert!(results[..19].iter().all(|r| r.is_ok()));
    let err = results[19].as_ref().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("segment 1 line 20"),
        "names the segment and line: {err}"
    );
}

#[test]
fn a_new_session_has_its_files_in_place() {
    let tmp = TempDir::new().unwrap();
    let cfg = config(tmp.path());
    let id = cfg.session_id.clone();
    let (_sink, writer) = spawn(cfg).unwrap();
    let dir = writer.session_dir().to_path_buf();
    assert_eq!(dir, tmp.path().join("sessions").join(id.as_str()));
    assert!(dir.join("events.000001.jsonl").is_file());
    assert!(dir.join("checkpoints.jsonl").is_file());

    let meta = meta(&dir);
    assert_eq!(meta["v"], 1);
    assert_eq!(meta["session_id"], id.as_str());
    assert_eq!(meta["segments"], 1);
    assert_eq!(meta["recovered_from_seq"], Value::Null);
    assert!(meta["created_ts_host_ns"].as_u64().unwrap() > 1_700_000_000_000_000_000);
    assert_eq!(meta["boxcar_version"], env!("CARGO_PKG_VERSION"));
    writer.close().unwrap();
}
