// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit`: working with audit logs.

use std::io::{self, Write};
use std::process::ExitCode;

use boxcar_audit::{verify_jsonl, verify_session, VerifyError, VerifyReport};
use serde_json::{json, Value};

use crate::cli::{AuditCommand, VerifyArgs};

pub fn run(command: AuditCommand) -> anyhow::Result<ExitCode> {
    match command {
        AuditCommand::Verify(args) => verify(&args),
    }
}

/// `boxcar audit verify <path> [--json]`. A directory is verified as a
/// session, anything else as a single `.jsonl` file. Prints the summary and
/// exits 0 when the log is intact; prints its first break and exits 1
/// otherwise.
fn verify(args: &VerifyArgs) -> anyhow::Result<ExitCode> {
    let result = if args.path.is_dir() {
        verify_session(&args.path)
    } else {
        verify_jsonl(&args.path)
    };
    let mut out = io::stdout().lock();
    match (&result, args.json) {
        (Ok(report), false) => writeln!(
            out,
            "ok: {} records, {} segments, last seq {}",
            report.records, report.segments, report.last_seq
        )?,
        (Ok(report), true) => writeln!(out, "{}", report_json(report))?,
        (Err(error), false) => writeln!(out, "fail: {error}")?,
        (Err(error), true) => writeln!(out, "{}", error_json(error))?,
    }
    out.flush()?;
    Ok(match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    })
}

fn report_json(report: &VerifyReport) -> Value {
    json!({
        "ok": true,
        "records": report.records,
        "segments": report.segments,
        "checkpoints": report.checkpoints,
        "last_seq": report.last_seq,
        "last_hash": report.last_hash,
    })
}

/// The error's kind and fields, plus `ok: false` and the message.
fn error_json(error: &VerifyError) -> Value {
    let mut fields = match error {
        VerifyError::Io(path, e) => json!({
            "error": "io",
            "path": path.display().to_string(),
            "reason": e.to_string(),
        }),
        VerifyError::Parse {
            segment,
            line,
            reason,
        } => json!({"error": "parse", "segment": segment, "line": line, "reason": reason}),
        VerifyError::Chain { seq, expected, got } => {
            json!({"error": "chain", "seq": seq, "expected": expected, "got": got})
        }
        VerifyError::Gap {
            expected_seq,
            got_seq,
        } => json!({"error": "gap", "expected_seq": expected_seq, "got_seq": got_seq}),
        VerifyError::Checkpoint { seq, expected, got } => {
            json!({"error": "checkpoint", "seq": seq, "expected": expected, "got": got})
        }
        VerifyError::CheckpointCount { seq, expected, got } => {
            json!({"error": "checkpoint_count", "seq": seq, "expected": expected, "got": got})
        }
        VerifyError::Genesis { expected, got } => {
            json!({"error": "genesis", "seq": 1, "expected": expected, "got": got})
        }
        VerifyError::CheckpointFile { line, reason } => {
            json!({"error": "checkpoint_file", "line": line, "reason": reason})
        }
        VerifyError::Layout { reason } => json!({"error": "layout", "reason": reason}),
    };
    fields["ok"] = json!(false);
    fields["message"] = json!(error.to_string());
    fields
}
