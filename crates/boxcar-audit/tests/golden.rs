// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The golden session `proto/testdata/audit-v1.jsonl`: a short chained log
//! built from fixed inputs with `Chainer`, committed so that other
//! implementations (the Go consumer first) can check their verifier against
//! it. It carries the cases decoders get wrong: an integer above 2^53, a
//! path with escaped and raw non-ASCII characters, and a checkpoint.
//!
//! `BOXCAR_BLESS=1 cargo test -p boxcar-audit --test golden` rewrites the
//! file from `golden_records` after a deliberate change.

use std::fs;
use std::path::PathBuf;

use boxcar_audit::{verify_jsonl, Chainer, PartialRecord};
use boxcar_proto::{
    ArtifactRef, Attrib, Checkpoint, FsClose, FsMount, FsOpen, Hash, HashStatus, OpResult, Payload,
    Record, Ring, SessionId, SpanRef, Subject, VmmStart, VmmStop,
};

/// The RFC 9562 UUIDv7 example, as in the proto crate's pinned vector.
const SESSION: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
/// 2^53 + 1: the smallest integer a float64 cannot hold.
const BEYOND_F64: u64 = 9_007_199_254_740_993;
/// A path JSON must escape (`"`, `\`, a tab), with raw non-ASCII and the
/// characters other encoders like to escape (`<>&`, U+2028).
const AWKWARD_PATH: &str = "/naïve-日本語-\"<>&\"-\u{2028}-back\\slash-tab\t-😀.txt";

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto/testdata/audit-v1.jsonl")
}

fn b3(bytes: &[u8]) -> Hash {
    Hash::from_blake3(blake3::hash(bytes))
}

fn subject() -> Option<Subject> {
    Some(Subject {
        pid: 1234,
        uid: 1000,
        gid: 1000,
    })
}

fn awkward_close() -> Payload {
    Payload::FsClose(FsClose {
        mount: "workspace".into(),
        path: AWKWARD_PATH.into(),
        path_at_open: AWKWARD_PATH.into(),
        fh: 7,
        bytes_read: 0,
        bytes_written: 12,
        size: Some(12),
        blake3: Some(b3(b"hello world\n")),
        hash_status: HashStatus::Ok,
        open_seq: Some(3),
        attrib: Attrib::Caller,
    })
}

/// The golden session. Timestamps are fixed: record `seq` has
/// `ts_host_ns = 2^53 - 3 + seq`, so the `fs.close` at seq 4 holds 2^53 + 1.
fn golden_records() -> Vec<Record> {
    let session: SessionId = SESSION.parse().unwrap();
    let mut chain = Chainer::genesis(&session);
    let mut records: Vec<Record> = Vec::new();
    let mut push = |payload: Payload, subject: Option<Subject>, span: Option<SpanRef>| {
        let seq = records.len() as u64 + 1;
        let (kind, data) = payload.into_parts();
        let record = chain.next(PartialRecord {
            session_id: session.clone(),
            ring: Ring::Host,
            src: payload.source(),
            kind,
            ts_host_ns: BEYOND_F64 - 4 + seq,
            ts_mono_ns: 5_000_000_000 + seq * 1_000_000,
            ts_guest_ns: None,
            subject,
            data,
            span,
        });
        records.push(record);
        records.last().unwrap().hash
    };

    let h1 = push(
        Payload::VmmStart(VmmStart {
            version: "0.1.0".into(),
            kernel: ArtifactRef {
                path: "/var/lib/boxcar/vmlinux".into(),
                blake3: b3(b"kernel"),
            },
            initramfs: Some(ArtifactRef {
                path: "/var/lib/boxcar/initramfs.cpio".into(),
                blake3: b3(b"initramfs"),
            }),
            cmdline: "console=ttyS0 reboot=k panic=1".into(),
            vcpus: 2,
            mem_mib: 512,
            shares: Vec::new(),
        }),
        None,
        None,
    );
    let h2 = push(
        Payload::FsMount(FsMount {
            mount: "workspace".into(),
            guest_path: "/workspace".into(),
            host_root: "/home/agent/ws".into(),
            cache_policy: "auto".into(),
        }),
        None,
        None,
    );
    let h3 = push(
        Payload::FsOpen(FsOpen {
            mount: "workspace".into(),
            path: "/src/main.rs".into(),
            fh: 7,
            flags: 0o102,
            flags_decoded: vec!["O_RDWR".into(), "O_CREAT".into()],
            exec: false,
            result: OpResult::ok(),
        }),
        subject(),
        Some(SpanRef {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
            span_id: "00f067aa0ba902b7".into(),
        }),
    );
    let h4 = push(awkward_close(), subject(), None);

    // The checkpoint's root is computed here from the rule, not by the
    // library: blake3 over the raw hashes of the four records before it.
    let mut window = blake3::Hasher::new();
    for hash in [h1, h2, h3, h4] {
        window.update(&hash.0);
    }
    push(
        Payload::Checkpoint(Checkpoint {
            records_since: 4,
            dropped: 0,
            root_hash: Hash::from_blake3(window.finalize()),
        }),
        None,
        None,
    );
    push(
        Payload::VmmStop(VmmStop {
            reason: "guest_reset".into(),
            exit_code: Some(0),
            console_dropped_bytes: 0,
            stdin_dropped_bytes: 0,
        }),
        None,
        None,
    );
    records
}

fn golden_text() -> String {
    golden_records()
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect()
}

#[test]
fn the_golden_session_verifies() {
    let report = verify_jsonl(&golden_path()).unwrap();
    assert_eq!(report.records, 6);
    assert_eq!(report.segments, 1);
    assert_eq!(report.checkpoints, 1);
    assert_eq!(report.last_seq, 6);
    assert_eq!(report.last_hash, golden_records()[5].hash);
}

#[test]
fn golden_records_parse_back_with_their_exact_integers() {
    let text = fs::read_to_string(golden_path()).unwrap();
    let records: Vec<Record> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let kinds: Vec<&str> = records.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "vmm.start",
            "fs.mount",
            "fs.open",
            "fs.close",
            "checkpoint",
            "vmm.stop"
        ]
    );

    let close = &records[3];
    assert_eq!(close.ts_host_ns, BEYOND_F64);
    assert!(text.contains(r#""ts_host_ns":9007199254740993"#));
    assert_ne!(
        close.ts_host_ns as f64 as u64, BEYOND_F64,
        "a float64 decoder would read a different number"
    );
    assert_eq!(close.subject, subject());
    assert_eq!(Payload::from_record(close).unwrap(), awkward_close());
    assert_eq!(records[2].subject, subject());
    assert!(records[2].span.is_some());

    // JSON escapes `"`, `\` and the tab; everything else stays raw UTF-8.
    let line = text.lines().nth(3).unwrap();
    assert!(
        line.contains(r#"-\"<>&\"-"#) && line.contains("back\\\\slash") && line.contains(r"tab\t")
    );
    assert!(line.contains('\u{2028}') && line.contains("日本語") && line.contains('😀'));
}

#[test]
fn the_golden_file_is_what_the_chainer_produces() {
    let expected = golden_text();
    if std::env::var_os("BOXCAR_BLESS").is_some() {
        fs::write(golden_path(), &expected).unwrap();
    }
    let actual = fs::read_to_string(golden_path()).unwrap();
    assert!(
        actual == expected,
        "proto/testdata/audit-v1.jsonl is not what golden_records() produces; after a \
         deliberate change rerun with BOXCAR_BLESS=1\n--- file\n{actual}--- chainer\n{expected}"
    );
}
