// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest control channel: JSON lines between the guest's init and the
//! VMM on vsock port 1024 (`boxcar.ctl`), and the header line init sends
//! first on the terminal stream, port 1025 (`boxcar.pty`).
//!
//! Every message is one line of JSON, at most [`MAX_LINE`] bytes not
//! counting the newline that ends it, tagged by its `t` field. Init speaks
//! first, with `hello`; the VMM answers with the session's `config`; init
//! starts the session and says `session.started`, and once the session has
//! ended, `session.exited`.
//!
//! ```text
//! -> {"t":"hello","init_version":"0.1.0","guest_mono_ns":..,"guest_real_ns":..}
//! <- {"t":"config","argv":["/bin/sh","-l"],"env":[["PATH","/usr/bin:/bin"]],...}
//! -> {"t":"session.started","pid":212}
//! <- {"t":"resize","rows":40,"cols":120}
//! -> {"t":"session.exited","code":7,"signal":null}
//! ```
//!
//! Guest to host: [`GuestMsg`]; host to guest: [`HostMsg`]. Unknown fields
//! are ignored; an unknown `t` is an error, which the reader skips.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The longest line either side sends or accepts, in bytes, not counting
/// the newline that ends it: 64 KiB.
pub const MAX_LINE: usize = 64 * 1024;

/// The longest header line on the terminal stream, newline included.
pub const MAX_PTY_HEADER: usize = 1024;

/// What init tells the VMM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum GuestMsg {
    /// Init is up and connected; its first message. The clocks are the
    /// guest's `CLOCK_MONOTONIC` and `CLOCK_REALTIME`, in nanoseconds.
    #[serde(rename = "hello")]
    Hello {
        init_version: String,
        guest_mono_ns: u64,
        guest_real_ns: u64,
    },
    /// The session's process started, with this pid in the guest.
    #[serde(rename = "session.started")]
    SessionStarted { pid: u32 },
    /// The session's process ended: its exit code, or the signal that
    /// killed it; both `null` only when init could not tell.
    #[serde(rename = "session.exited")]
    SessionExited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// The answer to a [`HostMsg::Ping`] with the same `id`.
    #[serde(rename = "pong")]
    Pong { id: u64, guest_mono_ns: u64 },
    /// A line for the host's log.
    #[serde(rename = "log")]
    Log { level: LogLevel, msg: String },
}

/// The level of a [`GuestMsg::Log`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

/// What the VMM tells init.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum HostMsg {
    /// The session to run: the answer to `hello`.
    #[serde(rename = "config")]
    Config(SessionConfig),
    /// The session's terminal changed size.
    #[serde(rename = "resize")]
    Resize { rows: u16, cols: u16 },
    /// Send this signal to the session's process group.
    #[serde(rename = "signal")]
    Signal { sig: i32 },
    /// End the session: `SIGTERM`, and `SIGKILL` after `grace_ms`; then
    /// the guest reboots.
    #[serde(rename = "shutdown")]
    Shutdown { grace_ms: u64 },
    /// Answer with a [`GuestMsg::Pong`] of the same `id`.
    #[serde(rename = "ping")]
    Ping { id: u64 },
}

/// The session init runs: the fields of [`HostMsg::Config`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// The command and its arguments; the program is looked for on the
    /// session's `PATH` unless it holds a `/`.
    pub argv: Vec<String>,
    /// The session's whole environment, in order, as `[name, value]`
    /// pairs.
    pub env: Vec<(String, String)>,
    /// Where the session starts: an absolute path.
    pub cwd: String,
    /// Who the session runs as.
    pub uid: u32,
    pub gid: u32,
    /// The guest's hostname.
    pub hostname: String,
    /// The terminal type, the session's `TERM` when `env` has none.
    pub term: String,
    /// The terminal's size.
    pub rows: u16,
    pub cols: u16,
    /// Kernel settings init writes before the session starts, beside its
    /// own fixed ones: `[name, value]` with dotted names, such as
    /// `["vm.overcommit_memory", "1"]`.
    pub sysctls: Vec<(String, String)>,
}

/// What a session runs when no command is given: a login shell.
pub const DEFAULT_ARGV: [&str; 2] = ["/bin/sh", "-l"];

/// The session's `PATH` by default.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

impl SessionConfig {
    /// `argv` as `uid` and `gid`, with the defaults: the environment
    /// `PATH` ([`DEFAULT_PATH`]), `HOME` (`/workspace`, or `/root` for root),
    /// `TERM` (`xterm-256color`) and `LANG` (`C.UTF-8`); starting in
    /// `/workspace`; hostname `boxcar`; a terminal of 24 by 80; no extra
    /// kernel settings.
    pub fn for_user(argv: Vec<String>, uid: u32, gid: u32) -> SessionConfig {
        let home = if uid == 0 { "/root" } else { "/workspace" };
        let term = "xterm-256color";
        let env = [
            ("PATH", DEFAULT_PATH),
            ("HOME", home),
            ("TERM", term),
            ("LANG", "C.UTF-8"),
        ];
        SessionConfig {
            argv,
            env: env
                .iter()
                .map(|&(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            cwd: "/workspace".to_owned(),
            uid,
            gid,
            hostname: "boxcar".to_owned(),
            term: term.to_owned(),
            rows: 24,
            cols: 80,
            sysctls: Vec::new(),
        }
    }
}

/// The first line on the terminal stream, from init:
/// `{"v":1,"session":"main","rows":R,"cols":C}`. The stream is the
/// session's terminal bytes, both ways, after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyHeader {
    /// 1.
    pub v: u32,
    /// The session's name: `main`.
    pub session: String,
    /// The terminal's size when the session started.
    pub rows: u16,
    pub cols: u16,
}

impl PtyHeader {
    /// The header of the session `main` on a terminal of `rows` by `cols`.
    pub fn main(rows: u16, cols: u16) -> PtyHeader {
        PtyHeader {
            v: 1,
            session: "main".to_owned(),
            rows,
            cols,
        }
    }
}

/// Why a line is not a message.
#[derive(Debug, thiserror::Error)]
pub enum GuestProtoError {
    /// The line, newline not counted, is this many bytes: over the limit.
    #[error("a line of {0} bytes, over the limit")]
    TooLong(usize),
    /// Not JSON, not a message, or a message of an unknown type.
    #[error("not a message: {0}")]
    Json(#[from] serde_json::Error),
}

/// `msg` as one line: its JSON and a newline.
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    // The messages are structs, strings and numbers: they always serialize.
    let mut line = serde_json::to_vec(msg).unwrap_or_default();
    line.push(b'\n');
    line
}

/// The message in `line`, with or without its newline: at most
/// [`MAX_LINE`] bytes not counting it.
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, GuestProtoError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    if line.len() > MAX_LINE {
        return Err(GuestProtoError::TooLong(line.len()));
    }
    Ok(serde_json::from_slice(line)?)
}

/// Bytes read from a stream, cut into lines. A partial line may grow to the
/// limit and no further, so a reader holds at most one line of the limit
/// and what one read brought.
#[derive(Debug)]
pub struct LineBuf {
    buf: Vec<u8>,
    limit: usize,
}

impl LineBuf {
    /// A buffer for lines of at most `limit` bytes, newline not counted.
    pub fn new(limit: usize) -> LineBuf {
        LineBuf {
            buf: Vec::new(),
            limit,
        }
    }

    /// Appends what a read brought. Fails, holding the bytes still, when the
    /// line they leave unfinished is over the limit: the stream has lost its
    /// framing and must be closed.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), GuestProtoError> {
        self.buf.extend_from_slice(bytes);
        let partial = match self.buf.iter().rposition(|&b| b == b'\n') {
            Some(newline) => self.buf.len() - newline - 1,
            None => self.buf.len(),
        };
        if partial > self.limit {
            return Err(GuestProtoError::TooLong(partial));
        }
        Ok(())
    }

    /// The next whole line, without its newline. A whole line over the
    /// limit is returned too; [`decode`] refuses it.
    pub fn next_line(&mut self) -> Option<Vec<u8>> {
        let newline = self.buf.iter().position(|&b| b == b'\n')?;
        let mut line: Vec<u8> = self.buf.drain(..=newline).collect();
        line.pop();
        Some(line)
    }

    /// Whether no byte is held.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Takes every byte held, the start of an unfinished line included:
    /// what followed a header line on a stream that is not lines after it.
    pub fn take_rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&a| a.to_owned()).collect()
    }

    fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn config() -> SessionConfig {
        SessionConfig {
            argv: strings(&["/bin/sh", "-l"]),
            env: pairs(&[("PATH", "/usr/bin:/bin"), ("HOME", "/workspace")]),
            cwd: "/workspace".into(),
            uid: 1000,
            gid: 1001,
            hostname: "boxcar".into(),
            term: "xterm-256color".into(),
            rows: 24,
            cols: 80,
            sysctls: pairs(&[("vm.overcommit_memory", "1")]),
        }
    }

    /// Every message, with the exact JSON it travels as: the wire table.
    fn guest_cases() -> Vec<(GuestMsg, Value)> {
        vec![
            (
                GuestMsg::Hello {
                    init_version: "0.1.0".into(),
                    guest_mono_ns: 1_500_000_000,
                    guest_real_ns: 1_700_000_000_000_000_000,
                },
                json!({"t": "hello", "init_version": "0.1.0", "guest_mono_ns": 1_500_000_000u64,
                       "guest_real_ns": 1_700_000_000_000_000_000u64}),
            ),
            (
                GuestMsg::SessionStarted { pid: 42 },
                json!({"t": "session.started", "pid": 42}),
            ),
            (
                GuestMsg::SessionExited {
                    code: Some(7),
                    signal: None,
                },
                json!({"t": "session.exited", "code": 7, "signal": null}),
            ),
            (
                GuestMsg::SessionExited {
                    code: None,
                    signal: Some(9),
                },
                json!({"t": "session.exited", "code": null, "signal": 9}),
            ),
            (
                GuestMsg::Pong {
                    id: 3,
                    guest_mono_ns: 9,
                },
                json!({"t": "pong", "id": 3, "guest_mono_ns": 9}),
            ),
            (
                GuestMsg::Log {
                    level: LogLevel::Warn,
                    msg: "resolver: no /etc".into(),
                },
                json!({"t": "log", "level": "warn", "msg": "resolver: no /etc"}),
            ),
        ]
    }

    fn host_cases() -> Vec<(HostMsg, Value)> {
        vec![
            (
                HostMsg::Config(config()),
                json!({
                    "t": "config",
                    "argv": ["/bin/sh", "-l"],
                    "env": [["PATH", "/usr/bin:/bin"], ["HOME", "/workspace"]],
                    "cwd": "/workspace",
                    "uid": 1000,
                    "gid": 1001,
                    "hostname": "boxcar",
                    "term": "xterm-256color",
                    "rows": 24,
                    "cols": 80,
                    "sysctls": [["vm.overcommit_memory", "1"]],
                }),
            ),
            (
                HostMsg::Resize {
                    rows: 40,
                    cols: 120,
                },
                json!({"t": "resize", "rows": 40, "cols": 120}),
            ),
            (HostMsg::Signal { sig: 2 }, json!({"t": "signal", "sig": 2})),
            (
                HostMsg::Shutdown { grace_ms: 5000 },
                json!({"t": "shutdown", "grace_ms": 5000}),
            ),
            (HostMsg::Ping { id: 11 }, json!({"t": "ping", "id": 11})),
        ]
    }

    #[test]
    fn every_message_round_trips_as_one_json_line() {
        for (msg, wire) in guest_cases() {
            let line = encode(&msg);
            assert_eq!(line.last(), Some(&b'\n'), "{msg:?}");
            assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
            let value: Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(value, wire, "{msg:?}");
            assert_eq!(decode::<GuestMsg>(&line).unwrap(), msg);
            // Without its newline too.
            assert_eq!(decode::<GuestMsg>(&line[..line.len() - 1]).unwrap(), msg);
        }
        for (msg, wire) in host_cases() {
            let line = encode(&msg);
            assert_eq!(line.last(), Some(&b'\n'), "{msg:?}");
            let value: Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(value, wire, "{msg:?}");
            assert_eq!(decode::<HostMsg>(&line).unwrap(), msg);
        }
    }

    #[test]
    fn the_names_are_the_constraints() {
        let names: Vec<String> = guest_cases()
            .iter()
            .map(|(_, wire)| wire["t"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "hello",
                "session.started",
                "session.exited",
                "session.exited",
                "pong",
                "log"
            ]
        );
        let names: Vec<String> = host_cases()
            .iter()
            .map(|(_, wire)| wire["t"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["config", "resize", "signal", "shutdown", "ping"]);
        for (level, name) in [
            (LogLevel::Error, "error"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Info, "info"),
            (LogLevel::Debug, "debug"),
        ] {
            assert_eq!(serde_json::to_value(level).unwrap(), json!(name));
        }
    }

    /// A `log` line padded to exactly `len` bytes, newline not counted.
    fn log_line(len: usize) -> Vec<u8> {
        let empty = encode(&GuestMsg::Log {
            level: LogLevel::Info,
            msg: String::new(),
        });
        let pad = len - (empty.len() - 1);
        let line = encode(&GuestMsg::Log {
            level: LogLevel::Info,
            msg: "x".repeat(pad),
        });
        assert_eq!(line.len(), len + 1);
        line
    }

    #[test]
    fn a_line_of_64_kib_is_read_and_one_byte_more_is_not() {
        assert_eq!(MAX_LINE, 64 * 1024);
        let line = log_line(MAX_LINE);
        assert!(decode::<GuestMsg>(&line).is_ok());
        assert!(decode::<GuestMsg>(&line[..MAX_LINE]).is_ok());
        let line = log_line(MAX_LINE + 1);
        assert!(matches!(
            decode::<GuestMsg>(&line),
            Err(GuestProtoError::TooLong(n)) if n == MAX_LINE + 1
        ));
    }

    #[test]
    fn unknown_fields_are_ignored_and_unknown_types_refused() {
        let msg: GuestMsg =
            decode(br#"{"t":"session.started","pid":5,"cgroup":"/session"}"#).unwrap();
        assert_eq!(msg, GuestMsg::SessionStarted { pid: 5 });
        let msg: HostMsg = decode(br#"{"t":"ping","id":1,"later":[1,2]}"#).unwrap();
        assert_eq!(msg, HostMsg::Ping { id: 1 });
        for bad in [
            &br#"{"t":"reboot"}"#[..],
            br#"{"pid":5}"#,
            br#"{"t":"session_started","pid":5}"#,
            br#"{"t":"session.started"}"#,
            br#"{"t":"log","level":"loud","msg":"x"}"#,
            b"not json",
            b"",
            b"\xff\xfe",
        ] {
            assert!(
                matches!(decode::<GuestMsg>(bad), Err(GuestProtoError::Json(_))),
                "{bad:?}"
            );
        }
        // A host message is not a guest message, nor the other way round.
        assert!(decode::<GuestMsg>(&encode(&HostMsg::Ping { id: 1 })).is_err());
        assert!(decode::<HostMsg>(&encode(&GuestMsg::SessionStarted { pid: 1 })).is_err());
    }

    #[test]
    fn a_line_buffer_gives_whole_lines_across_reads() {
        let mut lines = LineBuf::new(MAX_LINE);
        lines.push(b"{\"t\":\"ping\",").unwrap();
        assert_eq!(lines.next_line(), None);
        lines
            .push(b"\"id\":1}\n{\"t\":\"ping\",\"id\":2}\n{\"t\"")
            .unwrap();
        assert_eq!(lines.next_line().unwrap(), br#"{"t":"ping","id":1}"#);
        assert_eq!(lines.next_line().unwrap(), br#"{"t":"ping","id":2}"#);
        assert_eq!(lines.next_line(), None);
        lines.push(b":\"ping\",\"id\":3}\n").unwrap();
        let line = lines.next_line().unwrap();
        assert_eq!(decode::<HostMsg>(&line).unwrap(), HostMsg::Ping { id: 3 });
        assert!(lines.is_empty());
        // What follows a header line is the stream's own.
        lines.push(b"{\"v\":1}\nraw\x1b[0m").unwrap();
        assert_eq!(lines.next_line().unwrap(), b"{\"v\":1}");
        assert_eq!(lines.take_rest(), b"raw\x1b[0m");
        assert!(lines.is_empty());
    }

    /// A partial line may grow to the limit, not past it: the reader
    /// cannot be made to hold more than one line of the limit.
    #[test]
    fn a_line_buffer_refuses_a_line_over_its_limit() {
        let mut lines = LineBuf::new(8);
        lines.push(b"12345678").unwrap();
        assert!(matches!(lines.push(b"9"), Err(GuestProtoError::TooLong(9))));
        let mut lines = LineBuf::new(8);
        lines.push(b"12345678\n123").unwrap();
        assert_eq!(lines.next_line().unwrap(), b"12345678");
        assert!(lines.push(b"456789").is_err());
    }

    /// The defaults for a user: a login shell's environment, the
    /// workspace, 24 by 80.
    #[test]
    fn the_session_defaults_for_a_user() {
        let cfg = SessionConfig::for_user(strings(&DEFAULT_ARGV), 1000, 1001);
        assert_eq!(cfg.argv, ["/bin/sh", "-l"]);
        assert_eq!((cfg.uid, cfg.gid), (1000, 1001));
        assert_eq!(cfg.cwd, "/workspace");
        assert_eq!(cfg.hostname, "boxcar");
        assert_eq!(cfg.term, "xterm-256color");
        assert_eq!((cfg.rows, cfg.cols), (24, 80));
        assert!(cfg.sysctls.is_empty());
        assert_eq!(
            cfg.env,
            pairs(&[
                (
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ),
                ("HOME", "/workspace"),
                ("TERM", "xterm-256color"),
                ("LANG", "C.UTF-8"),
            ])
        );
        let root = SessionConfig::for_user(strings(&["sh"]), 0, 0);
        assert!(root.env.contains(&("HOME".into(), "/root".into())));
    }

    #[test]
    fn the_pty_header_is_one_line_of_its_own() {
        let header = PtyHeader::main(24, 80);
        let line = encode(&header);
        assert_eq!(
            line,
            b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n"
        );
        assert_eq!(decode::<PtyHeader>(&line).unwrap(), header);
        assert!(line.len() <= MAX_PTY_HEADER);
    }
}
