// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Logs cut by a crash, and what `verify_session` says of them.
//!
//! A process killed while it writes its log keeps every `write(2)` that
//! completed and loses the rest. Each test here has a real process write a
//! session and die at one point of the writer's work, then checks the files
//! it left, and that they verify as incomplete, of the right kind, or as
//! intact where the cut fell on a record boundary. The test binary runs
//! itself again for that, as a child with [`SCENARIO`] in its environment
//! naming what it writes and where it dies; the parent checks the signal
//! that ended it. Each limit is armed once the child's setup is written:
//!
//! - A write cut short: `RLIMIT_FSIZE`. The write that crosses it is cut
//!   there, the next one gets `SIGXFSZ`, and its default action ends the
//!   child.
//! - The other points: a [`Syncer`] that syncs, then sends the process
//!   `SIGKILL`. After a checkpoint's sync, before its line in the index;
//!   after the directory sync that makes a new segment's name durable,
//!   before `meta.json` lists it; after the one for a new session's first
//!   `meta.json`, before its first segment.
//!
//! The states no signal can reach reliably are made by truncating the files:
//! the index's last line cut at each byte, and the writer's rollback after
//! a failed index append, halfway.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boxcar_audit::{
    spawn, spawn_with_syncer, verify_session, AuditSink, Filter, Incomplete, IncompleteKind,
    Priority, Submission, Syncer, VerifyError, VerifyReport, WriterConfig,
};
use boxcar_proto::{
    genesis_prev, Attrib, FsIo, OpResult, Payload, Record, Ring, SessionId, Subject,
};
use serde_json::Value;
use tempfile::TempDir;

/// The child's scenario: what it writes, and where it dies.
const SCENARIO: &str = "BOXCAR_AUDIT_CRASH";
/// The data directory the child writes its session under.
const DATA_DIR: &str = "BOXCAR_AUDIT_CRASH_DATA_DIR";
/// The id of the session the child writes.
const SESSION: &str = "BOXCAR_AUDIT_CRASH_SESSION";
/// The child's exit code when it outlived its scenario.
const SURVIVED: i32 = 70;
/// The file, in the child's data directory, that holds the length of its
/// newest segment once the setup is written.
const SETUP_LEN: &str = "setup-len";

const HOUR: Duration = Duration::from_secs(3600);
/// Events written before a limit is armed. They fill the first segment and
/// start the second with a few records and a checkpoint, so the second
/// holds more bytes than `checkpoints.jsonl`, which the file size limit
/// must not cut.
const SETUP: u64 = 18;
/// Events written after: a checkpoint by count, an event, and the closing
/// checkpoint, all in the second segment.
const TAIL: u64 = 5;
/// Events written after the setup that fill the second segment.
const FILL: u64 = 20;

/// The children's writer: a checkpoint every 4 records, a segment sealed at
/// 8 KiB, and no checkpoint by time.
fn config(data_dir: &Path, session: &SessionId) -> WriterConfig {
    let mut cfg = WriterConfig::new(data_dir, session.clone());
    cfg.checkpoint_every = 4;
    cfg.checkpoint_interval = HOUR;
    cfg.segment_max_bytes = 8 * 1024;
    cfg
}

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

/// Sends events `range` and returns once the writer has written them: it
/// answers a subscription between two records, after it flushed the
/// segment.
fn write_events(sink: &AuditSink, range: Range<u64>) {
    for n in range {
        sink.emit(event(n)).unwrap();
    }
    drop(sink.subscribe(u64::MAX, Filter::default()).unwrap());
}

fn session_dir(data_dir: &Path, session: &SessionId) -> PathBuf {
    data_dir.join("sessions").join(session.as_str())
}

/// The segment files of a session, in order.
fn segment_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
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

fn newest_segment(dir: &Path) -> PathBuf {
    segment_files(dir).pop().expect("a segment")
}

/// `meta.json`'s `segments`, if it can be read.
fn meta_segments(dir: &Path) -> Option<u64> {
    let meta: Value = serde_json::from_slice(&fs::read(dir.join("meta.json")).ok()?).ok()?;
    meta["segments"].as_u64()
}

/// The whole lines of a file, newline excluded, each with the offset it
/// starts at; a partial line after the last newline is left out.
fn whole_lines(bytes: &[u8]) -> Vec<(u64, &[u8])> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push((start as u64, &bytes[start..i]));
            start = i + 1;
        }
    }
    lines
}

fn parse(line: &[u8]) -> Record {
    serde_json::from_slice(line).unwrap()
}

/// The entries of `checkpoints.jsonl`, whole lines only.
fn index_entries(dir: &Path) -> Vec<Value> {
    let bytes = fs::read(dir.join("checkpoints.jsonl")).unwrap();
    whole_lines(&bytes)
        .into_iter()
        .map(|(_, line)| serde_json::from_slice(line).unwrap())
        .collect()
}

fn incomplete(kind: IncompleteKind, segment: u32, offset: u64, bytes: u64) -> Option<Incomplete> {
    Some(Incomplete {
        kind,
        segment,
        offset,
        bytes,
    })
}

/// The number of a segment file: 2 for `events.000002.jsonl`.
fn number(segment: &Path) -> u32 {
    let name = segment.file_name().unwrap().to_str().unwrap();
    name["events.".len()..name.len() - ".jsonl".len()]
        .parse()
        .unwrap()
}

// The child's side.

/// Where a [`KillAt`] ends the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    /// After a segment sync that leaves a checkpoint as the segment's last
    /// line: the sync before the checkpoint's line in the index.
    CheckpointSynced,
    /// After a directory sync once there is a segment `meta.json` does not
    /// list: the new segment's name made durable, before `meta.json` names
    /// it.
    SegmentMade,
    /// After a directory sync once `meta.json` exists and no segment does:
    /// a new session's first `meta.json` made durable, before its first
    /// segment.
    MetaMade,
}

/// Syncs for real; once armed, sends the process `SIGKILL` right after the
/// first sync at its [`Point`].
#[derive(Clone)]
struct KillAt {
    point: Point,
    armed: Arc<AtomicBool>,
}

impl KillAt {
    fn new(point: Point) -> Self {
        KillAt {
            point,
            armed: Arc::default(),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }
}

impl Syncer for KillAt {
    fn sync(&self, file: &File) -> io::Result<()> {
        file.sync_data()?;
        if self.point == Point::CheckpointSynced && self.armed() && ends_in_checkpoint(file) {
            die();
        }
        Ok(())
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        File::open(dir)?.sync_all()?;
        let here = match self.point {
            Point::CheckpointSynced => false,
            Point::SegmentMade => {
                meta_segments(dir).is_some_and(|listed| segment_files(dir).len() as u64 > listed)
            }
            Point::MetaMade => dir.join("meta.json").exists() && segment_files(dir).is_empty(),
        };
        if here && self.armed() {
            die();
        }
        Ok(())
    }
}

/// Whether the segment `file` (open for appending only) ends in a
/// checkpoint record's line.
fn ends_in_checkpoint(file: &File) -> bool {
    let Ok(bytes) = fs::read(format!("/proc/self/fd/{}", file.as_raw_fd())) else {
        return false;
    };
    whole_lines(&bytes).last().is_some_and(|(start, line)| {
        *start as usize + line.len() + 1 == bytes.len() && parse(line).kind == "checkpoint"
    })
}

fn die() -> ! {
    // SAFETY: plain system calls. SIGKILL to this process ends every thread
    // of it before the call returns to this one.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
        libc::_exit(SURVIVED)
    }
}

/// Sets this process's file size limit, `RLIMIT_FSIZE`, to `bytes`.
fn limit_file_size(bytes: u64) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit read or write the one rlimit given.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit), 0);
        limit.rlim_cur = bytes;
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
}

/// In a child this test binary started, runs the scenario its environment
/// names and never returns. Anywhere else, returns at once.
fn child_takes_over() {
    let Ok(scenario) = env::var(SCENARIO) else {
        return;
    };
    // SAFETY: plain system calls on this process: no core dump (SIGXFSZ
    // dumps one by default), SIGXFSZ's default action and not blocked,
    // and SIGALRM's end for a child that hangs.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
        libc::signal(libc::SIGXFSZ, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGXFSZ);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, ptr::null_mut());
        libc::alarm(60);
    }
    let data_dir = PathBuf::from(env::var_os(DATA_DIR).unwrap());
    let session: SessionId = env::var(SESSION).unwrap().parse().unwrap();
    let cfg = config(&data_dir, &session);
    match scenario.split_once('=') {
        Some(("write_cut", bytes)) => {
            let (sink, writer) = spawn(cfg).unwrap();
            write_events(&sink, 0..SETUP);
            let len = fs::metadata(newest_segment(writer.session_dir()))
                .unwrap()
                .len();
            fs::write(data_dir.join(SETUP_LEN), len.to_string()).unwrap();
            limit_file_size(len + bytes.parse::<u64>().unwrap());
            write_events(&sink, SETUP..SETUP + TAIL);
            eprintln!("closed: {:?}", writer.close());
        }
        _ if scenario == "checkpoint_synced" => {
            let syncer = KillAt::new(Point::CheckpointSynced);
            let (sink, writer) = spawn_with_syncer(cfg, syncer.clone()).unwrap();
            write_events(&sink, 0..SETUP);
            syncer.arm();
            write_events(&sink, SETUP..SETUP + TAIL);
            eprintln!("closed: {:?}", writer.close());
        }
        _ if scenario == "segment_made" => {
            let syncer = KillAt::new(Point::SegmentMade);
            let (sink, writer) = spawn_with_syncer(cfg, syncer.clone()).unwrap();
            write_events(&sink, 0..SETUP);
            syncer.arm();
            write_events(&sink, SETUP..SETUP + FILL);
            eprintln!("closed: {:?}", writer.close());
        }
        _ if scenario == "meta_made" => {
            let syncer = KillAt::new(Point::MetaMade);
            syncer.arm();
            let spawned = spawn_with_syncer(cfg, syncer);
            eprintln!("spawned: {:?}", spawned.map(|_| ()));
        }
        _ => panic!("no scenario {scenario}"),
    }
    // SAFETY: ends the process at once, as the scenario should have.
    unsafe { libc::_exit(SURVIVED) }
}

// The parent's side.

/// How a child ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Signal(i32),
    Code(i32),
}

/// Runs the test `test` again in a child, which runs `scenario` on a new
/// session under `data_dir`. Returns how the child ended, what it printed,
/// and the session's directory.
fn run_child(test: &str, scenario: &str, data_dir: &Path) -> (Ended, String, PathBuf) {
    let session = SessionId::new();
    let output = Command::new(env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(SCENARIO, scenario)
        .env(DATA_DIR, data_dir)
        .env(SESSION, session.as_str())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let ended = match output.status.signal() {
        Some(signal) => Ended::Signal(signal),
        None => Ended::Code(output.status.code().unwrap_or(-1)),
    };
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (ended, printed, session_dir(data_dir, &session))
}

/// The child's setup and tail written here, whole: the newest segment's
/// length after the setup, and where each of the tail's lines starts and
/// how long it is without its newline.
fn reference_tail(data_dir: &Path) -> (u64, Vec<(u64, u64)>) {
    let session = SessionId::new();
    let (sink, writer) = spawn(config(data_dir, &session)).unwrap();
    let dir = writer.session_dir().to_owned();
    write_events(&sink, 0..SETUP);
    let newest = newest_segment(&dir);
    assert!(number(&newest) > 1, "the setup fills the first segment");
    let setup_len = fs::metadata(&newest).unwrap().len();
    let index_len = fs::metadata(dir.join("checkpoints.jsonl")).unwrap().len();
    assert!(
        index_len < setup_len,
        "the file size limit cuts the segment, not the index: {index_len} {setup_len}"
    );
    write_events(&sink, SETUP..SETUP + TAIL);
    writer.close().unwrap();
    assert_eq!(
        newest_segment(&dir),
        newest,
        "the tail stays in one segment"
    );

    let bytes = fs::read(&newest).unwrap();
    let tail = whole_lines(&bytes)
        .into_iter()
        .filter(|(start, _)| *start >= setup_len)
        .map(|(start, line)| (start, line.len() as u64))
        .collect();
    (setup_len, tail)
}

/// The seq of the last whole record of a session, from its files.
fn last_whole_seq(dir: &Path) -> u64 {
    segment_files(dir)
        .iter()
        .rev()
        .find_map(|file| {
            let bytes = fs::read(file).unwrap();
            whole_lines(&bytes).last().map(|(_, line)| parse(line).seq)
        })
        .unwrap_or(0)
}

/// Each write the child makes after its setup may be cut, at any byte:
/// at the start of each line of the tail, after its first byte, in its
/// middle, and short of only its newline. A cut on a record boundary
/// leaves an intact log; anywhere else, a partial line.
#[test]
fn a_write_cut_short_leaves_a_partial_line_or_a_record_boundary() {
    child_takes_over();
    let tmp = TempDir::new().unwrap();
    let (setup_len, tail) = reference_tail(&tmp.path().join("reference"));
    assert!(tail.len() >= 5, "{tail:?}");
    // Each cut, and whether it falls on a record boundary.
    let mut cuts = BTreeMap::new();
    for &(start, len) in &tail {
        let at = start - setup_len;
        cuts.insert(at, true);
        for inside in [at + 1, at + len / 2, at + len] {
            cuts.insert(inside, false);
        }
    }
    assert_eq!(cuts.len(), 4 * tail.len());

    for (cut, boundary) in cuts {
        let data_dir = tmp.path().join(format!("cut-{cut}"));
        let (ended, printed, dir) = run_child(
            "a_write_cut_short_leaves_a_partial_line_or_a_record_boundary",
            &format!("write_cut={cut}"),
            &data_dir,
        );
        assert_eq!(
            ended,
            Ended::Signal(libc::SIGXFSZ),
            "cut at {cut}: {printed}"
        );

        let child_setup: u64 = fs::read_to_string(data_dir.join(SETUP_LEN))
            .unwrap()
            .parse()
            .unwrap();
        let newest = newest_segment(&dir);
        let bytes = fs::read(&newest).unwrap();
        assert_eq!(
            bytes.len() as u64,
            child_setup + cut,
            "cut at {cut}: the segment ends at the limit"
        );
        let line_start = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1) as u64;
        let expected = (line_start < bytes.len() as u64).then(|| Incomplete {
            kind: IncompleteKind::PartialLine,
            segment: number(&newest),
            offset: line_start,
            bytes: bytes.len() as u64 - line_start,
        });
        assert_eq!(expected.is_none(), boundary, "cut at {cut}: {expected:?}");

        let report = verify_session(&dir).unwrap_or_else(|e| panic!("cut at {cut}: {e}"));
        assert_eq!(report.incomplete, expected, "cut at {cut}");
        assert_eq!(report.last_seq, last_whole_seq(&dir), "cut at {cut}");
    }
}

/// Killed between a checkpoint's sync and its line in the index: the
/// checkpoint is the segment's last line, and the index lists every
/// checkpoint before it.
#[test]
fn a_kill_after_a_checkpoint_sync_leaves_it_unindexed() {
    child_takes_over();
    let tmp = TempDir::new().unwrap();
    let (ended, printed, dir) = run_child(
        "a_kill_after_a_checkpoint_sync_leaves_it_unindexed",
        "checkpoint_synced",
        tmp.path(),
    );
    assert_eq!(ended, Ended::Signal(libc::SIGKILL), "{printed}");

    let newest = newest_segment(&dir);
    let bytes = fs::read(&newest).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'), "no partial line");
    let (offset, line) = *whole_lines(&bytes).last().unwrap();
    let checkpoint = parse(line);
    assert_eq!(checkpoint.kind, "checkpoint");
    let index = index_entries(&dir);
    assert!(index.last().unwrap()["seq"].as_u64().unwrap() < checkpoint.seq);

    let report = verify_session(&dir).unwrap();
    assert_eq!(
        report.incomplete,
        incomplete(
            IncompleteKind::UnindexedCheckpoint,
            number(&newest),
            offset,
            0
        )
    );
    assert_eq!(report.last_seq, checkpoint.seq);
    assert_eq!(report.checkpoints as usize, index.len() + 1);
}

/// Killed once a new segment's name is durable, before `meta.json`
/// lists it: the new segment is empty, and the one before ends in a
/// checkpoint the index lists.
#[test]
fn a_kill_after_a_new_segment_leaves_a_rotation_cut_short() {
    child_takes_over();
    let tmp = TempDir::new().unwrap();
    let (ended, printed, dir) = run_child(
        "a_kill_after_a_new_segment_leaves_a_rotation_cut_short",
        "segment_made",
        tmp.path(),
    );
    assert_eq!(ended, Ended::Signal(libc::SIGKILL), "{printed}");

    let files = segment_files(&dir);
    let listed = meta_segments(&dir).unwrap() as usize;
    assert!(listed >= 2, "{listed}");
    assert_eq!(files.len(), listed + 1);
    assert_eq!(fs::metadata(&files[listed]).unwrap().len(), 0);
    let bytes = fs::read(&files[listed - 1]).unwrap();
    let (_, line) = *whole_lines(&bytes).last().unwrap();
    let sealed = parse(line);
    assert_eq!(sealed.kind, "checkpoint");
    assert_eq!(index_entries(&dir).last().unwrap()["seq"], sealed.seq);

    let report = verify_session(&dir).unwrap();
    assert_eq!(
        report.incomplete,
        incomplete(IncompleteKind::Rotation, listed as u32 + 1, 0, 0)
    );
    assert_eq!(report.segments as usize, listed);
    assert_eq!(report.last_seq, sealed.seq);
}

/// Killed once a new session's `meta.json` is durable, before its
/// first segment: no segment, no index, no record.
#[test]
fn a_kill_after_a_new_session_s_meta_json_leaves_no_segment() {
    child_takes_over();
    let tmp = TempDir::new().unwrap();
    let (ended, printed, dir) = run_child(
        "a_kill_after_a_new_session_s_meta_json_leaves_no_segment",
        "meta_made",
        tmp.path(),
    );
    assert_eq!(ended, Ended::Signal(libc::SIGKILL), "{printed}");

    assert_eq!(meta_segments(&dir), Some(1));
    assert!(segment_files(&dir).is_empty());
    assert!(!dir.join("checkpoints.jsonl").exists());

    let report = verify_session(&dir).unwrap();
    let session: SessionId = dir.file_name().unwrap().to_str().unwrap().parse().unwrap();
    assert_eq!(
        report,
        VerifyReport {
            records: 0,
            segments: 0,
            checkpoints: 0,
            last_seq: 0,
            last_hash: genesis_prev(&session),
            incomplete: incomplete(IncompleteKind::NoSegment, 1, 0, 0),
        }
    );
}

// States made by truncating the files.

/// A closed session, written here as the children write theirs: it ends in
/// the closing checkpoint, which the index lists last. Returns the session
/// directory, the newest segment, and the closing checkpoint's offset and
/// seq.
fn closed_session(data_dir: &Path) -> (PathBuf, PathBuf, u64, u64) {
    let (sink, writer) = spawn(config(data_dir, &SessionId::new())).unwrap();
    let dir = writer.session_dir().to_owned();
    write_events(&sink, 0..SETUP + TAIL);
    writer.close().unwrap();
    let newest = newest_segment(&dir);
    let bytes = fs::read(&newest).unwrap();
    let (offset, line) = *whole_lines(&bytes).last().unwrap();
    let last = parse(line);
    assert_eq!(last.kind, "checkpoint");
    assert_eq!(index_entries(&dir).last().unwrap()["seq"], last.seq);
    (dir, newest, offset, last.seq)
}

/// Where the index's last line starts.
fn last_index_line(index: &[u8]) -> usize {
    let body = index.strip_suffix(b"\n").unwrap();
    body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)
}

fn truncate(path: &Path, len: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(len)
        .unwrap();
}

/// The index's last line, the closing checkpoint's, cut at each byte:
/// none of it is a checkpoint with no index line, part of it a partial
/// index line, all of it an intact log.
#[test]
fn the_index_s_last_line_cut_at_each_byte() {
    let tmp = TempDir::new().unwrap();
    let (dir, newest, offset, seq) = closed_session(tmp.path());
    let segment = number(&newest);
    let path = dir.join("checkpoints.jsonl");
    let index = fs::read(&path).unwrap();
    let start = last_index_line(&index);

    for len in start..=index.len() {
        fs::write(&path, &index[..len]).unwrap();
        let cut = (len - start) as u64;
        let expected = if len == start {
            incomplete(IncompleteKind::UnindexedCheckpoint, segment, offset, 0)
        } else if len == index.len() {
            None
        } else {
            incomplete(IncompleteKind::PartialIndexLine, segment, offset, cut)
        };
        let report = verify_session(&dir).unwrap_or_else(|e| panic!("{cut} bytes: {e}"));
        assert_eq!(report.incomplete, expected, "{cut} bytes of the line");
        assert_eq!(report.last_seq, seq);
    }
}

/// The writer's failure path after an index append that failed partway:
/// it cuts the index first, then the segment, so a kill at any point of it
/// leaves a state a crash leaves. The old order, the segment first, left an
/// index line whose checkpoint is gone between the two, which is a break.
#[test]
fn the_rollback_of_a_failed_index_append_leaves_a_crash_s_state_at_each_step() {
    let tmp = TempDir::new().unwrap();
    let (dir, newest, offset, seq) = closed_session(tmp.path());
    let segment = number(&newest);
    let path = dir.join("checkpoints.jsonl");
    let index = fs::read(&path).unwrap();
    let start = last_index_line(&index);
    let half = start + (index.len() - start) / 2;

    // As the failed append left it: part of the checkpoint's index line.
    fs::write(&path, &index[..half]).unwrap();
    let report = verify_session(&dir).unwrap();
    assert_eq!(
        report.incomplete,
        incomplete(
            IncompleteKind::PartialIndexLine,
            segment,
            offset,
            (half - start) as u64
        )
    );

    // The index cut back to its last whole line: the checkpoint has none.
    fs::write(&path, &index[..start]).unwrap();
    let report = verify_session(&dir).unwrap();
    assert_eq!(
        report.incomplete,
        incomplete(IncompleteKind::UnindexedCheckpoint, segment, offset, 0)
    );
    assert_eq!(report.last_seq, seq);

    // Then the segment, back to the record before the checkpoint: intact.
    truncate(&newest, offset);
    let report = verify_session(&dir).unwrap();
    assert_eq!(report.incomplete, None);
    assert_eq!(report.last_seq, seq - 1);

    // The old order's halfway state: the segment cut, the index not yet.
    fs::write(&path, &index[..half]).unwrap();
    match verify_session(&dir) {
        Err(VerifyError::CheckpointFile { reason, .. }) => {
            assert!(reason.contains("no newline"), "{reason}")
        }
        other => panic!("expected a checkpoints.jsonl error, got {other:?}"),
    }
}
