// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit verify`, run as a subprocess against sessions written with
//! the library: exit codes and stdout for intact and damaged logs.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use boxcar_audit::{spawn, CloseStats, Priority, Submission, WriterConfig};
use boxcar_proto::{Attrib, FsIo, OpResult, Payload, Ring, SessionId};
use serde_json::Value;

/// A scratch directory under Cargo's per-target test tmpdir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("audit-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Writes 20 events into a fresh session: 21 records with the final
/// checkpoint.
fn write_session(scratch: &Scratch) -> (PathBuf, CloseStats) {
    let (sink, writer) = spawn(WriterConfig::new(&scratch.0, SessionId::new())).unwrap();
    let dir = writer.session_dir().to_path_buf();
    for n in 0..20u64 {
        sink.emit(Submission {
            ring: Ring::Host,
            ts_guest_ns: None,
            subject: None,
            payload: Payload::FsWrite(FsIo {
                mount: "workspace".into(),
                path: format!("/file-{n:06}.txt"),
                fh: n,
                offset: 0,
                len: 1,
                result: OpResult::ok(),
                attrib: Attrib::Caller,
            }),
            span: None,
            priority: Priority::Normal,
        })
        .unwrap();
    }
    (dir, writer.close().unwrap())
}

fn boxcar<I: AsRef<OsStr>>(args: impl IntoIterator<Item = I>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn segment_1(dir: &Path) -> PathBuf {
    dir.join("events.000001.jsonl")
}

/// Flips the low bit of the first path digit of the record at `seq`.
fn corrupt_record(dir: &Path, seq: usize) {
    let path = segment_1(dir);
    let text = fs::read_to_string(&path).unwrap();
    let offset: usize = text.lines().take(seq - 1).map(|l| l.len() + 1).sum();
    let digit = offset + text.lines().nth(seq - 1).unwrap().find("/file-").unwrap() + 6;
    let mut bytes = text.into_bytes();
    bytes[digit] ^= 0x01;
    fs::write(&path, bytes).unwrap();
}

#[test]
fn an_intact_session_prints_ok_and_exits_0() {
    let scratch = Scratch::new("ok");
    let (dir, stats) = write_session(&scratch);
    assert_eq!(stats.last_seq, 21);

    let output = boxcar([OsStr::new("audit"), "verify".as_ref(), dir.as_os_str()]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "ok: 21 records, 1 segments, last seq 21\n");

    // A single segment file is verified on its own.
    let output = boxcar([
        OsStr::new("audit"),
        "verify".as_ref(),
        segment_1(&dir).as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "ok: 21 records, 1 segments, last seq 21\n");
}

#[test]
fn json_output_is_one_object() {
    let scratch = Scratch::new("json");
    let (dir, stats) = write_session(&scratch);

    let output = boxcar([
        OsStr::new("audit"),
        "verify".as_ref(),
        dir.as_os_str(),
        "--json".as_ref(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 1, "{text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["records"], 21);
    assert_eq!(report["segments"], 1);
    assert_eq!(report["checkpoints"], 1);
    assert_eq!(report["last_seq"], 21);
    assert_eq!(report["last_hash"], stats.last_hash.to_string());
}

#[test]
fn a_corrupted_record_prints_the_break_and_exits_1() {
    let scratch = Scratch::new("corrupt");
    let (dir, _) = write_session(&scratch);
    corrupt_record(&dir, 10);

    let output = boxcar([OsStr::new("audit"), "verify".as_ref(), dir.as_os_str()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = stdout(&output);
    assert!(text.starts_with("fail: "), "{text}");
    assert!(text.contains("seq 10"), "{text}");
    assert!(
        text.contains("expected b3:") && text.contains("got b3:"),
        "{text}"
    );

    let output = boxcar([
        OsStr::new("audit"),
        "verify".as_ref(),
        dir.as_os_str(),
        "--json".as_ref(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 1, "{text}");
    let error: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"], "chain");
    assert_eq!(error["seq"], 10);
    for field in ["expected", "got"] {
        assert!(error[field].as_str().unwrap().starts_with("b3:"), "{error}");
    }
    assert!(error["message"].as_str().unwrap().contains("seq 10"));
}

#[test]
fn a_missing_record_prints_the_gap_and_exits_1() {
    let scratch = Scratch::new("gap");
    let (dir, _) = write_session(&scratch);
    let path = segment_1(&dir);
    let text = fs::read_to_string(&path).unwrap();
    let kept: String = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 9)
        .map(|(_, l)| format!("{l}\n"))
        .collect();
    fs::write(&path, kept).unwrap();

    let output = boxcar([OsStr::new("audit"), "verify".as_ref(), dir.as_os_str()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = stdout(&output);
    assert!(text.contains("expected seq 10, got seq 11"), "{text}");

    let output = boxcar([
        OsStr::new("audit"),
        "verify".as_ref(),
        dir.as_os_str(),
        "--json".as_ref(),
    ]);
    let error: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(error["error"], "gap");
    assert_eq!(error["expected_seq"], 10);
    assert_eq!(error["got_seq"], 11);
}

#[test]
fn a_path_that_is_not_a_log_exits_1() {
    let scratch = Scratch::new("missing");
    let output = boxcar([
        OsStr::new("audit"),
        "verify".as_ref(),
        scratch.0.join("nope.jsonl").as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).starts_with("fail: "));

    // A directory that is not a session (no meta.json).
    let output = boxcar([
        OsStr::new("audit"),
        "verify".as_ref(),
        scratch.0.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stdout(&output).starts_with("fail: "));
}
