// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit verify`, run as a subprocess against sessions written with
//! the library: exit codes and stdout for intact, incomplete and damaged
//! logs.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use boxcar_audit::{spawn, CloseStats, Priority, Submission, WriterConfig};
use boxcar_proto::{genesis_prev, Attrib, FsIo, OpResult, Payload, Ring, SessionId};
use serde_json::{json, Value};

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
                path_b64: None,
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

/// The offset of the last line of a file that ends in a newline.
fn last_line_offset(path: &Path) -> u64 {
    let bytes = fs::read(path).unwrap();
    let body = bytes.strip_suffix(b"\n").unwrap();
    body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1) as u64
}

/// Each tail a crash can leave, made by editing a written session's files:
/// `verify` prints how much verified and what is cut, exits 4, and says the
/// same as one JSON object.
#[test]
fn an_incomplete_log_says_where_it_is_cut_and_exits_4() {
    /// Cuts the session in `dir`; returns the words for the cut and its
    /// `incomplete` object.
    type Cut = fn(&Path) -> (String, Value);
    let cuts: [Cut; 5] = [
        |dir| {
            let offset = fs::metadata(segment_1(dir)).unwrap().len();
            let mut bytes = fs::read(segment_1(dir)).unwrap();
            bytes.extend_from_slice(br#"{"v":1,"seq":22"#);
            fs::write(segment_1(dir), bytes).unwrap();
            (
                format!("a partial line of 15 bytes at segment 1 offset {offset}"),
                json!({"kind": "partial_line", "segment": 1, "offset": offset, "bytes": 15}),
            )
        },
        |dir| {
            fs::write(dir.join("checkpoints.jsonl"), "").unwrap();
            let offset = last_line_offset(&segment_1(dir));
            (
                format!(
                    "the checkpoint at segment 1 offset {offset} has no line in checkpoints.jsonl"
                ),
                json!({"kind": "unindexed_checkpoint", "segment": 1, "offset": offset, "bytes": 0}),
            )
        },
        |dir| {
            let index = dir.join("checkpoints.jsonl");
            let bytes = fs::read(&index).unwrap();
            fs::write(&index, &bytes[..10]).unwrap();
            let offset = last_line_offset(&segment_1(dir));
            (
                format!(
                    "checkpoints.jsonl ends in 10 bytes of the line for the checkpoint at \
                     segment 1 offset {offset}"
                ),
                json!({"kind": "partial_index_line", "segment": 1, "offset": offset, "bytes": 10}),
            )
        },
        |dir| {
            fs::write(dir.join("events.000002.jsonl"), "").unwrap();
            (
                "events.000002.jsonl is empty and not in meta.json".to_owned(),
                json!({"kind": "rotation", "segment": 2, "offset": 0, "bytes": 0}),
            )
        },
        |dir| {
            fs::remove_file(segment_1(dir)).unwrap();
            fs::remove_file(dir.join("checkpoints.jsonl")).unwrap();
            (
                "meta.json lists events.000001.jsonl, which does not exist".to_owned(),
                json!({"kind": "no_segment", "segment": 1, "offset": 0, "bytes": 0}),
            )
        },
    ];

    for (i, cut) in cuts.into_iter().enumerate() {
        let scratch = Scratch::new(&format!("incomplete-{i}"));
        let (dir, stats) = write_session(&scratch);
        let (what, incomplete) = cut(&dir);
        let kind = incomplete["kind"].clone();
        // What verified: the whole session, but none of it without a
        // segment.
        let (records, segments, checkpoints, last_hash) = if kind == "no_segment" {
            let session: SessionId = dir.file_name().unwrap().to_str().unwrap().parse().unwrap();
            (0, 0, 0, genesis_prev(&session))
        } else {
            (21, 1, 1, stats.last_hash)
        };

        let output = boxcar([OsStr::new("audit"), "verify".as_ref(), dir.as_os_str()]);
        assert_eq!(output.status.code(), Some(4), "{kind}: {output:?}");
        assert_eq!(
            stdout(&output),
            format!(
                "incomplete: {records} records verified, {segments} segments, last seq \
                 {records}; the tail is cut ({what}), cause unknown\n"
            ),
            "{kind}"
        );

        let output = boxcar([
            OsStr::new("audit"),
            "verify".as_ref(),
            dir.as_os_str(),
            "--json".as_ref(),
        ]);
        assert_eq!(output.status.code(), Some(4), "{kind}: {output:?}");
        let text = stdout(&output);
        assert_eq!(text.lines().count(), 1, "{kind}: {text}");
        let report: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            report,
            json!({
                "ok": false,
                "incomplete": incomplete,
                "records": records,
                "segments": segments,
                "checkpoints": checkpoints,
                "last_seq": records,
                "last_hash": last_hash,
            }),
            "{kind}"
        );
    }
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
