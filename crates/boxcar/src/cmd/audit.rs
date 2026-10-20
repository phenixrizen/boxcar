// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit`: working with audit logs.
//!
//! `verify PATH` checks a log on disk. `verify --control PATH` asks a
//! running session's VMM to check its log against the audit writer's head
//! (`audit.verify`), one stretch per request, and chains the stretches: each
//! must start from the hash the one before ended at.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use std::fs;

use anyhow::Context;
use boxcar_audit::export::{ocsf, otlp, ExportError, Log};
use boxcar_audit::{verify_jsonl, verify_session, VerifyError, VerifyReport};
use boxcar_proto::control::{AuditVerify, AuditVerifyParams, ErrorCode};
use boxcar_proto::Hash;
use serde_json::{json, Value};

use crate::cli::{AuditCommand, ExportArgs, ExportFormat};
use crate::client::Client;
use crate::cmd::image::native_roots;
use crate::otlp::{post, Endpoint, Outcome, DEADLINE};

/// `boxcar audit verify`'s exit code for a broken log.
const BROKEN_EXIT: u8 = 1;
/// `boxcar audit verify`'s exit code for an incomplete log: what is there
/// verifies, but its tail was cut mid-write.
const INCOMPLETE_EXIT: u8 = 4;
/// The exit code of a usage error, as clap's.
const USAGE_EXIT: u8 = 2;
/// The capability a server's hello lists when it serves `audit.verify`.
const VERIFY: &str = "audit.verify";

pub fn run(command: AuditCommand) -> anyhow::Result<ExitCode> {
    match command {
        AuditCommand::Verify(args) => match (&args.control, &args.path) {
            (Some(control), _) => verify_live(control, args.from_seq, args.json),
            (None, Some(path)) => verify(path, args.json),
            // clap requires one of the two.
            (None, None) => {
                crate::cmd::tell("error: audit verify needs a log's PATH or --control");
                Ok(ExitCode::from(USAGE_EXIT))
            }
        },
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
fn verify(path: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let result = if path.is_dir() {
        verify_session(path)
    } else {
        verify_jsonl(path)
    };
    let mut out = io::stdout().lock();
    match (&result, json) {
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

/// `boxcar audit verify --control <socket> [--from-seq N] [--json]`: asks
/// the session's VMM to verify its log from `from_seq` (1 by default),
/// `audit.verify` after `audit.verify`, until a stretch reaches the
/// writer's head. Each stretch after the first must start from the hash
/// the one before ended at (its `from_prev`). Prints `ok: verified seq
/// <from>..<head> against the writer's head <hash>` and exits 0; prints
/// `fail: ...` and exits 1 at a break the VMM found or a stretch that does
/// not chain; says why and exits 1 when the session cannot verify (its
/// writer closed or failed, or its VMM is older than `audit.verify`).
fn verify_live(control: &Path, from_seq: Option<u64>, json: bool) -> anyhow::Result<ExitCode> {
    let mut client = Client::connect(control)?;
    if !client.can(VERIFY) {
        return refused(
            json,
            "unsupported",
            &format!(
                "this session's VMM cannot verify its log while it runs (its hello lists no \
                 {VERIFY}); verify its session directory once the run has ended"
            ),
        );
    }
    let first = from_seq.unwrap_or(1).max(1);
    let mut next = first;
    let mut held: Option<Hash> = None;
    let (mut checkpoints, mut stretches) = (0u64, 0u64);
    let last = loop {
        let params = serde_json::to_value(AuditVerifyParams {
            from_seq: Some(next),
        })
        .context("the parameters")?;
        let reply = match client.request(VERIFY, params)? {
            Ok(result) => result,
            // A break the VMM found in the log, or a log it cannot read.
            Err(error) if error.code == ErrorCode::Internal => {
                return failed(json, "break", &error.message)
            }
            Err(error) => return refused(json, error.code.as_str(), &format!("{VERIFY}: {error}")),
        };
        let reply: AuditVerify = serde_json::from_value(reply)
            .context("the server sent a malformed audit.verify result")?;
        if let Err(problem) = chains(&reply, next, held) {
            return failed(json, "chain", &problem);
        }
        stretches += 1;
        checkpoints += reply.checkpoints;
        held = Some(reply.to_hash);
        next = reply.to_seq.saturating_add(1);
        if !reply.more {
            break reply;
        }
    };
    let mut out = io::stdout().lock();
    if json {
        let summary = json!({
            "ok": true,
            "from_seq": first,
            "to_seq": last.to_seq,
            "head_seq": last.head_seq,
            "head_hash": last.head_hash,
            "checkpoints": checkpoints,
            "stretches": stretches,
        });
        writeln!(out, "{summary}")?;
    } else {
        writeln!(
            out,
            "ok: verified seq {first}..{} against the writer's head {}",
            last.head_seq, last.head_hash
        )?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// Whether `reply`, the answer to an `audit.verify` from `asked`, is a
/// stretch that follows the one before, which ended at the hash `held`
/// (none before the first): it starts where it was asked to, from that
/// hash, and ends within the head, at the head itself when there is no
/// more.
fn chains(reply: &AuditVerify, asked: u64, held: Option<Hash>) -> Result<(), String> {
    if reply.from_seq != asked {
        return Err(format!(
            "the session verified from seq {}, not from seq {asked} as asked",
            reply.from_seq
        ));
    }
    if let Some(held) = held {
        if reply.from_prev != held {
            return Err(format!(
                "the stretch from seq {asked} does not chain: it starts from {}, and the \
                 stretch before it ended at {held}",
                reply.from_prev
            ));
        }
    }
    if reply.to_seq < reply.from_seq || reply.to_seq > reply.head_seq {
        return Err(format!(
            "the session verified seq {}..{}, not a stretch up to its head at seq {}",
            reply.from_seq, reply.to_seq, reply.head_seq
        ));
    }
    let at_head = reply.to_seq == reply.head_seq;
    if reply.more == at_head {
        return Err(format!(
            "the session says more: {} for a stretch that ends at seq {}, its head being seq {}",
            reply.more, reply.to_seq, reply.head_seq
        ));
    }
    if at_head && reply.to_hash != reply.head_hash {
        return Err(format!(
            "the stretch ends at the writer's head, seq {}, with the hash {}, not the head's {}",
            reply.to_seq, reply.to_hash, reply.head_hash
        ));
    }
    Ok(())
}

/// Ends a live verify that found the log broken: `fail: <message>` on
/// stdout, or with `json` the error as one object; exit 1.
fn failed(json: bool, kind: &str, message: &str) -> anyhow::Result<ExitCode> {
    let mut out = io::stdout().lock();
    if json {
        writeln!(
            out,
            "{}",
            json!({"ok": false, "error": kind, "message": message})
        )?;
    } else {
        writeln!(out, "fail: {message}")?;
    }
    out.flush()?;
    Ok(ExitCode::from(BROKEN_EXIT))
}

/// Ends a live verify the session could not do: `error: <message>` on
/// stderr, or with `json` the error as one object on stdout; exit 1.
fn refused(json: bool, kind: &str, message: &str) -> anyhow::Result<ExitCode> {
    if json {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "{}",
            json!({"ok": false, "error": kind, "message": message})
        )?;
        out.flush()?;
    } else {
        crate::cmd::tell(&format!("error: {message}"));
    }
    Ok(ExitCode::from(BROKEN_EXIT))
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
