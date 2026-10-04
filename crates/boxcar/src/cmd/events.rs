// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar events`: a running session's audit records, streamed from its
//! control socket as JSON lines.
//!
//! It sends `audit.subscribe`, then prints each `audit` event's `rec`
//! exactly as the server sent it, one line on stdout, and each
//! `audit.lagged` as `{"event":"audit.lagged","resume_seq":N}` on stderr,
//! until the server closes the connection (the VM stopped) or a stop
//! signal comes.
//!
//! The stop signals are blocked and read from a signalfd on a thread of
//! its own, which shuts the connection down: the read the command waits in
//! then ends like the server's own close. `SIGINT` is a clean end (exit 0);
//! the others exit 128 plus the signal, as `boxcar run` and `boxcar attach`
//! do. A stdout that closes (`| head`) is a clean end too.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context};
use boxcar_proto::control::AuditSubscribeParams;
use boxcar_vmm::lifecycle::{block_stop_signals, SignalFd};
use serde_json::value::RawValue;

use crate::cli::EventsArgs;
use crate::client::{self, Message};

/// What one line the server sent means to this command.
#[derive(Debug, PartialEq, Eq)]
enum Line {
    /// A record, as the JSON text the server sent.
    Record(String),
    Lagged(u64),
    /// Anything else: an event this command does not know (the `state`
    /// events), which a client ignores.
    Other,
}

/// Reads `line`, which must be a JSON object. Only the top level is
/// parsed: the record stays the text the server sent.
fn classify(line: &[u8]) -> anyhow::Result<Line> {
    let fields: BTreeMap<&str, &RawValue> =
        serde_json::from_slice(line).context("the server sent a line that is not an object")?;
    let event = fields
        .get("event")
        .and_then(|raw| serde_json::from_str::<&str>(raw.get()).ok());
    match event {
        Some("audit") => {
            let rec = fields
                .get("rec")
                .context("an audit event without a rec")?
                .get();
            Ok(Line::Record(rec.to_owned()))
        }
        Some("audit.lagged") => {
            let resume = fields
                .get("resume_seq")
                .and_then(|raw| raw.get().parse::<u64>().ok())
                .context("an audit.lagged event without a resume_seq")?;
            Ok(Line::Lagged(resume))
        }
        _ => Ok(Line::Other),
    }
}

/// Subscribes to the session `args` names and prints what it streams.
pub fn run(args: &EventsArgs) -> anyhow::Result<ExitCode> {
    let params = AuditSubscribeParams {
        from_seq: args.from,
        types: args.types.clone(),
        pid: args.pid,
        min_score: args.min_score,
    };
    params
        .check()
        .map_err(|message| anyhow::anyhow!("events: {message}"))?;
    // Before any thread starts: the stop signals reach only the signalfd.
    block_stop_signals().context("cannot block the stop signals")?;
    let signals = SignalFd::new().context("cannot read signals")?;

    let session = &args.session;
    let mut client = client::connect(session.control.as_deref(), session.session_id.as_deref())?;
    if let Err(error) = client.request("audit.subscribe", serde_json::to_value(&params)?)? {
        bail!("audit.subscribe: {error}");
    }
    // The records come when they come.
    client.set_timeout(None)?;

    let caught = Arc::new(AtomicI32::new(0));
    let socket = client.shutdown_handle()?;
    thread::Builder::new()
        .name("events-signals".into())
        .spawn({
            let caught = Arc::clone(&caught);
            move || {
                if let Some(signal) = wait_for_signal(&signals) {
                    caught.store(signal, Ordering::Release);
                    // Ends the read the main thread is in.
                    let _ = socket.shutdown(Shutdown::Both);
                }
            }
        })
        .context("cannot start the signal thread")?;

    let mut out = Printer::new();
    // What the request read past before its response: nothing, from this
    // server, but an event that came first is not lost.
    for message in client.take_pending() {
        if let Message::Event { body, .. } = message {
            let line = serde_json::to_vec(&body)?;
            if !out.print(&classify(&line)?) {
                return Ok(ExitCode::SUCCESS);
            }
        }
    }
    while let Some(line) = client.next_line()? {
        if !out.print(&classify(&line)?) {
            return Ok(ExitCode::SUCCESS);
        }
    }
    Ok(match caught.load(Ordering::Acquire) {
        0 | libc::SIGINT => ExitCode::SUCCESS,
        signal => ExitCode::from(u8::try_from(128 + signal).unwrap_or(1)),
    })
}

/// Where the lines go: records to stdout, lag reports to stderr.
struct Printer {
    stdout: io::Stdout,
}

impl Printer {
    fn new() -> Printer {
        Printer {
            stdout: io::stdout(),
        }
    }

    /// Prints `line`; `false` when stdout is closed, which ends the
    /// command quietly. Any other failure to write ends it as well: there
    /// is nowhere to say so.
    fn print(&mut self, line: &Line) -> bool {
        match line {
            Line::Record(rec) => {
                // Stdout is line buffered: each record leaves with its
                // newline, so a live stream is not held back.
                let mut out = self.stdout.lock();
                writeln!(out, "{rec}").is_ok()
            }
            Line::Lagged(resume_seq) => {
                // Stderr may be closed: that is no reason to stop.
                let _ = writeln!(
                    io::stderr(),
                    "{{\"event\":\"audit.lagged\",\"resume_seq\":{resume_seq}}}"
                );
                true
            }
            Line::Other => true,
        }
    }
}

/// Waits for a stop signal on `signals` and returns its number; `None` if
/// the wait itself fails.
fn wait_for_signal(signals: &SignalFd) -> Option<i32> {
    loop {
        let mut fd = libc::pollfd {
            fd: signals.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd; waits for ever.
        let ret = unsafe { libc::poll(&mut fd, 1, -1) };
        if ret < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        match signals.read() {
            Ok(Some(signal)) => return Some(signal),
            Ok(None) => {}
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_stays_the_text_the_server_sent() {
        // Not in key order, and with spacing a Value would not keep.
        let rec = r#"{"v":1,  "seq":7,"type":"net.drop","data":{"b":1,"a":[1, 2]}}"#;
        let line = format!(r#"{{"v":1,"event":"audit","sub":1,"rec":{rec}}}"#);
        assert_eq!(
            classify(line.as_bytes()).unwrap(),
            Line::Record(rec.to_owned())
        );
    }

    #[test]
    fn lag_reports_and_other_events_are_told_apart() {
        assert_eq!(
            classify(br#"{"v":1,"event":"audit.lagged","sub":1,"resume_seq":16385}"#).unwrap(),
            Line::Lagged(16385)
        );
        assert_eq!(
            classify(br#"{"v":1,"event":"state","state":"stopping"}"#).unwrap(),
            Line::Other
        );
        assert_eq!(
            classify(br#"{"v":1,"event":"somethingnew","rec":1}"#).unwrap(),
            Line::Other
        );
        for bad in [
            &br#"[1]"#[..],
            b"nope",
            br#"{"event":"audit"}"#,
            br#"{"event":"audit.lagged","resume_seq":"x"}"#,
            br#"{"event":"audit.lagged"}"#,
        ] {
            assert!(classify(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
