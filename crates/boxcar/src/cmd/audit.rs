// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit`: working with audit logs.

use std::io::{self, Write};
use std::process::ExitCode;

use std::fs;

use boxcar_audit::export::{ocsf, otlp, ExportError, Log};
use boxcar_audit::{verify_jsonl, verify_session, VerifyError, VerifyReport};
use serde_json::{json, Value};

use crate::cli::{AuditCommand, ExportArgs, ExportFormat, VerifyArgs};
use crate::cmd::image::native_roots;
use crate::otlp::{post, Endpoint, Outcome, DEADLINE};

/// `boxcar audit verify`'s exit code for a broken log.
const BROKEN_EXIT: u8 = 1;
/// `boxcar audit verify`'s exit code for an incomplete log: what is there
/// verifies, but its tail was cut mid-write.
const INCOMPLETE_EXIT: u8 = 4;
/// A usage error.
const USAGE_EXIT: u8 = 2;

pub fn run(command: AuditCommand) -> anyhow::Result<ExitCode> {
    match command {
        AuditCommand::Verify(args) => verify(&args),
        AuditCommand::Export(args) => export(&args),
    }
}

/// `boxcar audit export PATH --format otlp|ocsf [--out FILE]
/// [--otlp-endpoint URL]`: the export to FILE, stdout, or a collector; a
/// summary line on stderr.
fn export(args: &ExportArgs) -> anyhow::Result<ExitCode> {
    let endpoint = match (&args.otlp_endpoint, args.format) {
        (None, _) => None,
        (Some(_), ExportFormat::Ocsf) => {
            super::tell("error: --otlp-endpoint needs --format otlp");
            return Ok(ExitCode::from(USAGE_EXIT));
        }
        (Some(url), ExportFormat::Otlp) => match Endpoint::parse(url) {
            Ok(endpoint) => Some(endpoint),
            Err(error) => {
                super::tell(&format!("error: {error}"));
                return Ok(ExitCode::from(USAGE_EXIT));
            }
        },
    };
    let log = match Log::read(&args.path) {
        Ok(log) => log,
        Err(ExportError::Verify(error)) => {
            // stdout carries the export alone.
            super::tell(&format!("fail: {error}"));
            return Ok(ExitCode::from(BROKEN_EXIT));
        }
        Err(error) => {
            super::tell(&format!("error: {error}"));
            return Ok(ExitCode::from(BROKEN_EXIT));
        }
    };
    let (bytes, summary) = match args.format {
        ExportFormat::Otlp => {
            let (bytes, s) = otlp::export(&log);
            let unpaired = if s.unpaired > 0 {
                format!(" ({} unpaired)", s.unpaired)
            } else {
                String::new()
            };
            let traces = usize::from(s.spans > 0);
            let summary = format!(
                "otlp: {traces} trace, {} spans, {} events from {} records{unpaired}",
                s.spans, s.events, s.records
            );
            (bytes, summary)
        }
        ExportFormat::Ocsf => {
            let (bytes, s) = ocsf::export(&log);
            let summary = format!(
                "ocsf: {} events from {} records, {} skipped ({})",
                s.events,
                s.records,
                s.skipped.total(),
                s.skipped
            );
            (bytes, summary)
        }
    };
    if let Some(cut) = &log.report.incomplete {
        super::tell(&format!(
            "incomplete: the log's tail is cut ({cut}); exported the {} records that verified",
            log.report.records
        ));
    }
    match &args.out {
        Some(path) => {
            fs::write(path, &bytes).map_err(|e| anyhow::anyhow!("--out {}: {e}", path.display()))?
        }
        None if endpoint.is_none() => {
            let mut out = io::stdout().lock();
            out.write_all(&bytes)?;
            out.flush()?;
        }
        None => {}
    }
    super::tell(&summary);
    if let Some(endpoint) = endpoint {
        let roots = native_roots()?;
        match post(&endpoint, &bytes, &roots, DEADLINE) {
            Ok(Outcome::Accepted(None)) => super::tell(&format!("sent to {}", endpoint.as_str())),
            Ok(Outcome::Accepted(Some(message))) => super::tell(&format!(
                "sent to {}; the collector says: {message}",
                endpoint.as_str()
            )),
            Ok(Outcome::Refused(why)) => {
                super::tell(&format!("error: {}: {why}", endpoint.as_str()));
                return Ok(ExitCode::from(BROKEN_EXIT));
            }
            Err(error) => {
                super::tell(&format!("error: {}: {error}", endpoint.as_str()));
                return Ok(ExitCode::from(BROKEN_EXIT));
            }
        }
    }
    Ok(if log.report.incomplete.is_some() {
        ExitCode::from(INCOMPLETE_EXIT)
    } else {
        ExitCode::SUCCESS
    })
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
