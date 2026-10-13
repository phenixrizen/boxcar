// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The golden sensor frames, `proto/testdata/sensor-v1.jsonl` (written by
//! `cargo xtask schema`): one record of each `proc.*` type as JSON lines.
//! Every line is a frame the stream accepts, and framed it comes back the
//! same.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use boxcar_proto::sensor::{encode, is_sensor_kind, Decoder, SensorFrame, MAX_FRAME};

const KINDS: [&str; 12] = [
    "proc.exec",
    "proc.fork",
    "proc.exit",
    "proc.connect_attempt",
    "proc.tcp_connect",
    "proc.memfd",
    "proc.file_open",
    "proc.lsm_deny",
    "proc.heartbeat",
    "proc.sensor_status",
    "proc.tls_io",
    "proc.tls_attach",
];

fn golden() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto/testdata/sensor-v1.jsonl");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_line_is_a_frame_of_a_distinct_proc_type_and_frames_round_trip() {
    let mut seen = BTreeSet::new();
    for (n, line) in golden().lines().enumerate() {
        let frame: SensorFrame =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {e}", n + 1));
        frame
            .check()
            .unwrap_or_else(|e| panic!("line {}: {e}", n + 1));
        assert!(is_sensor_kind(frame.payload.kind()), "line {}", n + 1);
        assert!(line.len() <= MAX_FRAME, "line {}", n + 1);
        assert!(
            seen.insert(frame.payload.kind().to_owned()),
            "line {}: {} twice",
            n + 1,
            frame.payload.kind()
        );
        let bytes = encode(&frame).unwrap();
        let mut decoder = Decoder::new();
        decoder.feed(&bytes);
        assert_eq!(decoder.next_frame().unwrap(), Some(frame), "line {}", n + 1);
        assert!(decoder.is_empty());
    }
    let want: BTreeSet<String> = KINDS.iter().map(|k| k.to_string()).collect();
    assert_eq!(seen, want);
}
