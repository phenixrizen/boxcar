// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar status`: a running VM's status, from its control socket.

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::{anyhow, Context};
use boxcar_proto::control::{GuestStatus, Status};
use serde_json::Value;

use crate::cli::StatusArgs;
use crate::client;

/// Prints the status of the session `args` names: the object the socket
/// returned with `--json`, a table otherwise.
pub fn run(args: &StatusArgs) -> anyhow::Result<ExitCode> {
    let session = &args.session;
    let mut client = client::connect(session.control.as_deref(), session.session_id.as_deref())?;
    let result = client
        .request("status", Value::Null)?
        .map_err(|error| anyhow!("status: {error}"))?;
    let mut out = io::stdout().lock();
    if args.json {
        writeln!(out, "{result}")?;
    } else {
        let status: Status =
            serde_json::from_value(result).context("the server sent a malformed status")?;
        out.write_all(table(&status).as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// The status as a two-column table.
fn table(status: &Status) -> String {
    let devices = if status.devices.is_empty() {
        "none".to_owned()
    } else {
        status.devices.join(", ")
    };
    let audit = if status.audit.failed {
        format!("next seq {}, failed", status.audit.next_seq)
    } else {
        format!("next seq {}", status.audit.next_seq)
    };
    let state = serde_json::to_value(status.state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let rows = [
        ("session", status.session_id.clone()),
        ("state", state),
        ("pid", status.pid.to_string()),
        ("uptime", uptime(status.uptime_ms)),
        ("vcpus", status.vcpus.to_string()),
        ("memory", format!("{} MiB", status.mem_mib)),
        ("devices", devices),
        ("guest", guest(&status.guest)),
        ("audit", audit),
    ];
    rows.iter()
        .map(|(name, value)| format!("{name:<8} {value}\n"))
        .collect()
}

/// What the guest's init reported, in a few words.
fn guest(guest: &GuestStatus) -> String {
    let mut text = if guest.init_ready {
        "init ready".to_owned()
    } else {
        "init not ready".to_owned()
    };
    if let Some(pid) = guest.session_pid {
        text.push_str(&format!(", session pid {pid}"));
    }
    if let Some(exit) = guest.exit {
        text.push_str(&match (exit.code, exit.signal) {
            (Some(code), _) => format!(", session exited {code}"),
            (None, Some(signal)) => format!(", session killed by signal {signal}"),
            (None, None) => ", session ended".to_owned(),
        });
    }
    text
}

/// `ms` as `1h 2m 3s`, `2m 3.4s` or `3.4s`.
fn uptime(ms: u64) -> String {
    let secs = ms / 1000;
    let tenths = ms % 1000 / 100;
    let (hours, minutes, secs) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}.{tenths}s")
    } else {
        format!("{secs}.{tenths}s")
    }
}

#[cfg(test)]
mod tests {
    use boxcar_proto::control::{AuditStatus, SessionOutcome, VmState};

    use super::*;

    #[test]
    fn uptime_reads_as_hours_minutes_and_seconds() {
        assert_eq!(uptime(0), "0.0s");
        assert_eq!(uptime(1_250), "1.2s");
        assert_eq!(uptime(61_500), "1m 1.5s");
        assert_eq!(uptime(3_723_900), "1h 2m 3s");
    }

    #[test]
    fn the_table_has_one_row_per_field() {
        let status = Status {
            state: VmState::Stopping,
            session_id: "s".into(),
            pid: 9,
            uptime_ms: 500,
            vcpus: 1,
            mem_mib: 256,
            guest: GuestStatus {
                init_ready: true,
                session_pid: Some(12),
                exit: Some(SessionOutcome {
                    code: None,
                    signal: Some(9),
                }),
            },
            audit: AuditStatus {
                next_seq: 4,
                failed: true,
            },
            devices: Vec::new(),
        };
        assert_eq!(
            table(&status),
            "session  s\n\
             state    stopping\n\
             pid      9\n\
             uptime   0.5s\n\
             vcpus    1\n\
             memory   256 MiB\n\
             devices  none\n\
             guest    init ready, session pid 12, session killed by signal 9\n\
             audit    next seq 4, failed\n"
        );
    }
}
