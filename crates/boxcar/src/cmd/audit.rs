// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit`: working with audit logs.

use std::io::{self, Write};
use std::process::ExitCode;

use boxcar_audit::{verify_jsonl, verify_session, VerifyError, VerifyReport};
use serde_json::{json, Value};

use crate::cli::{AuditCommand, VerifyArgs};

/// `boxcar audit verify`'s exit code for a broken log.
const BROKEN_EXIT: u8 = 1;
/// `boxcar audit verify`'s exit code for an incomplete log: what is there
/// verifies, but its tail was cut mid-write.
const INCOMPLETE_EXIT: u8 = 4;

pub fn run(command: AuditCommand) -> anyhow::Result<ExitCode> {
    match command {
        AuditCommand::Verify(args) => verify(&args),
    }
}

/// `boxcar audit verify <path> [--json]`. A directory is verified as a
/// session, anything else as a single `.jsonl` file. Prints the summary and
/// exits 0 when the log is intact; prints what verified and where the tail
/// is cut, and exits 4, when it is incomplete; prints its first break and
/// exits 1 otherwise.
fn verify(args: &VerifyArgs) -> anyhow::Result<ExitCode> {
    let result = if args.path.is_dir() {
        verify_session(&args.path)
    } else {
        verify_jsonl(&args.path)
    };
    let mut out = io::stdout().lock();
    match (&result, args.json) {
        (Ok(report), false) => match &report.incomplete {
            None => writeln!(
                out,
                "ok: {} records, {} segments, last seq {}",
                report.records, report.segments, report.last_seq
            )?,
            // A crash and a deliberate cut leave the same tails.
            Some(cut) => writeln!(
                out,
                "incomplete: {} records verified, {} segments, last seq {}; the tail is cut \
                 ({cut}), cause unknown",
                report.records, report.segments, report.last_seq
            )?,
        },
        (Ok(report), true) => writeln!(out, "{}", report_json(report))?,
        (Err(error), false) => writeln!(out, "fail: {error}")?,
        (Err(error), true) => writeln!(out, "{}", error_json(error))?,
    }
    out.flush()?;
    Ok(match result {
        Ok(report) if report.incomplete.is_some() => ExitCode::from(INCOMPLETE_EXIT),
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(BROKEN_EXIT),
    })
}

/// The report, with `ok: false` and where the tail is cut when it is.
fn report_json(report: &VerifyReport) -> Value {
    let mut fields = json!({
        "ok": true,
        "records": report.records,
        "segments": report.segments,
        "checkpoints": report.checkpoints,
        "last_seq": report.last_seq,
        "last_hash": report.last_hash,
    });
    if let Some(cut) = &report.incomplete {
        fields["ok"] = json!(false);
        fields["incomplete"] = json!({
            "kind": cut.kind.as_str(),
            "segment": cut.segment,
            "offset": cut.offset,
            "bytes": cut.bytes,
        });
    }
    fields
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
