// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The control channel, init's side (vsock port 1024): `hello`, the
//! session's config, the reports, and the host's requests while the
//! session runs ([`supervise`]).
//!
//! Init connects from guest port 1023 and says `hello`; the VMM answers
//! with the session's config, which init waits [`CONFIG_DEADLINE`] for.
//! Once the session runs, init reports `session.started`, and the poll loop
//! relays the terminal and serves the host: `resize` sets the PTY's size,
//! `signal` signals the session's process group, `ping` gets a `pong`, and
//! `shutdown` ends the session (`SIGTERM` to its process group, then
//! `SIGKILL` after the grace, at most [`MAX_GRACE`]). A channel the host
//! closes while the session runs is taken as `shutdown` with
//! [`LOST_HOST_GRACE`].
//!
//! When the session has ended, [`finish`] drains its terminal to the
//! stream and closes it, reports `session.exited`, sweeps the processes left
//! (as M1 does), and waits, at most [`ACK_DEADLINE`], for the host to close
//! its side of both streams: the VMM closes the control channel once the
//! report is recorded, the relay the terminal once it has written it all.
//! Only then does init reboot, so the report and the last output are not
//! lost to the reset.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use boxcar_proto::guest::{decode, encode, GuestMsg, HostMsg, LineBuf, SessionConfig, MAX_LINE};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::console::{Failed, Step};
use crate::pty::{self, poll, pollfd, Relay, DRAIN_LIMIT};
use crate::reaper::{Ended, Reaper};
use crate::vsock::{self, set_nonblocking, CTL_PORT, CTL_SOURCE_PORT};

/// How long init waits for the session's config after `hello`.
pub const CONFIG_DEADLINE: Duration = Duration::from_secs(10);

/// How long init waits, before it reboots, for the host to close its side
/// of the streams: the sign that it took the report and the output.
pub const ACK_DEADLINE: Duration = Duration::from_secs(2);

/// The longest grace a `shutdown` gets.
pub const MAX_GRACE: Duration = Duration::from_secs(60);

/// The grace when the host closed the channel while the session ran.
pub const LOST_HOST_GRACE: u64 = 5000;

/// The bytes of `pong` and `log` lines that may wait for the host.
const OUTBOX_CAP: usize = 256 * 1024;

/// Bytes read from the channel at a time.
const READ_CHUNK: usize = 8192;

/// `hello`: this init's version and the guest's clocks.
pub fn hello() -> GuestMsg {
    GuestMsg::Hello {
        init_version: env!("CARGO_PKG_VERSION").to_owned(),
        guest_mono_ns: clock_ns(libc::CLOCK_MONOTONIC),
        guest_real_ns: clock_ns(libc::CLOCK_REALTIME),
    }
}

/// The clock `clock` in nanoseconds; 0 when it cannot be read.
fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime stores one timespec through its argument, which
    // points at `now`, alive for the call.
    if unsafe { libc::clock_gettime(clock, &mut now) } != 0 {
        return 0;
    }
    let secs = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// `session.exited` for how the session ended; both `null` when init did
/// not see it end.
pub fn exit_report(ended: Option<Ended>) -> GuestMsg {
    let (code, signal) = match ended {
        Some(Ended::Exited(code)) => (Some(code), None),
        Some(Ended::Killed(signal)) => (None, Some(signal)),
        None => (None, None),
    };
    GuestMsg::SessionExited { code, signal }
}

/// The grace of a `shutdown` of `grace_ms`, at most [`MAX_GRACE`].
pub fn shutdown_grace(grace_ms: u64) -> Duration {
    Duration::from_millis(grace_ms).min(MAX_GRACE)
}

/// Refuses a config init cannot run: no command, the all-ones uid or gid
/// (which `setresuid` and `setresgid` read as "leave this id alone": the
/// session would stay root), a hostname the kernel refuses (empty, over 64
/// bytes or holding a NUL), a working directory that is not absolute.
pub fn check_config(config: &SessionConfig) -> Result<(), Failed> {
    if config.argv.is_empty() {
        return Err(Failed::new("config", "argv is empty"));
    }
    for (what, id) in [("uid", config.uid), ("gid", config.gid)] {
        if id == u32::MAX {
            return Err(Failed::new("config", format!("{what} {id} is not usable")));
        }
    }
    let host = config.hostname.as_bytes();
    if host.is_empty() || host.len() > 64 || host.contains(&0) {
        return Err(Failed::new(
            "config",
            format!("hostname {:?} is not one", config.hostname),
        ));
    }
    if !config.cwd.starts_with('/') || config.cwd.contains('\0') {
        return Err(Failed::new(
            "config",
            format!("cwd {:?} is not an absolute path", config.cwd),
        ));
    }
    Ok(())
}

/// Lines waiting for the host.
pub struct Outbox {
    buf: Vec<u8>,
    cap: usize,
}

impl Outbox {
    pub fn new(cap: usize) -> Outbox {
        Outbox {
            buf: Vec::new(),
            cap,
        }
    }

    /// Queues `msg`'s line, unless it would take the outbox past its cap:
    /// then it is dropped whole. Returns whether it was queued.
    pub fn push(&mut self, msg: &GuestMsg) -> bool {
        let line = encode(msg);
        if self.buf.len() + line.len() > self.cap {
            return false;
        }
        self.buf.extend_from_slice(&line);
        true
    }

    /// Queues a report (`session.started`, `session.exited`), whatever the
    /// cap: there are two in init's life.
    pub fn push_report(&mut self, msg: &GuestMsg) {
        self.buf.extend_from_slice(&encode(msg));
    }

    /// Writes what is queued to `to` until it is all written or `to` would
    /// block, partial writes included.
    pub fn write_to(&mut self, to: &mut impl Write) -> io::Result<()> {
        let mut sent = 0;
        let result = loop {
            if sent == self.buf.len() {
                break Ok(());
            }
            match to.write(&self.buf[sent..]) {
                Ok(0) => break Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => sent += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        self.buf.drain(..sent);
        result
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// The control channel.
pub struct Ctl {
    stream: File,
    lines: LineBuf,
    /// Messages read with the config, for the loop.
    pending: VecDeque<HostMsg>,
    out: Outbox,
    /// The host closed its side, or reading failed.
    eof: bool,
    /// Writing failed: nothing more reaches the host.
    broken: bool,
}

impl Ctl {
    /// Connects to the VMM from guest port 1023 and queues `hello`.
    pub fn connect() -> Result<Ctl, Failed> {
        let fd = vsock::connect(CTL_SOURCE_PORT, CTL_PORT)?;
        set_nonblocking(fd.as_raw_fd()).step("O_NONBLOCK on the control channel")?;
        let mut ctl = Ctl::over(fd);
        ctl.out.push_report(&hello());
        Ok(ctl)
    }

    /// The channel over `fd`, which is non-blocking.
    fn over(fd: OwnedFd) -> Ctl {
        Ctl {
            stream: File::from(fd),
            lines: LineBuf::new(MAX_LINE),
            pending: VecDeque::new(),
            out: Outbox::new(OUTBOX_CAP),
            eof: false,
            broken: false,
        }
    }

    /// Sends `hello` and waits for the session's config until `deadline`;
    /// any other message before it is dropped, and those after it wait for
    /// the loop.
    pub fn receive_config(&mut self, deadline: Instant) -> Result<SessionConfig, Failed> {
        loop {
            self.flush();
            let mut msgs = self.read().into_iter();
            for msg in msgs.by_ref() {
                if let HostMsg::Config(config) = msg {
                    self.pending.extend(msgs);
                    return Ok(config);
                }
            }
            if self.eof {
                return Err(Failed::new("config", "the host closed the control channel"));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Failed::new(
                    "config",
                    format!("none from the host within {} s", CONFIG_DEADLINE.as_secs()),
                ));
            }
            let mut fds = [pollfd(self.stream.as_raw_fd(), self.events())];
            poll(&mut fds, Some(left)).step("poll")?;
        }
    }

    /// The events to wait for: input until the host closes, output while
    /// lines wait.
    fn events(&self) -> pty::Events {
        let mut events = 0;
        if !self.eof {
            events |= libc::POLLIN;
        }
        if !self.out.is_empty() && !self.broken {
            events |= libc::POLLOUT;
        }
        events
    }

    /// Queues `msg` (dropped when the outbox is full) and sends what it can.
    pub fn send(&mut self, msg: &GuestMsg) {
        self.out.push(msg);
        self.flush();
    }

    /// Queues the report `msg`, whatever the outbox holds, and sends what it
    /// can.
    pub fn report(&mut self, msg: &GuestMsg) {
        self.out.push_report(msg);
        self.flush();
    }

    /// Sends what waits, without blocking.
    fn flush(&mut self) {
        if self.broken {
            return;
        }
        if self.out.write_to(&mut self.stream).is_err() {
            self.broken = true;
        }
    }

    /// What the host sent, as far as it is here; marks the end of the
    /// channel when the host closed its side, reading failed, or a line was
    /// over the limit. A line that is not a message is dropped.
    fn read(&mut self) -> Vec<HostMsg> {
        let mut msgs: Vec<HostMsg> = self.pending.drain(..).collect();
        let mut buf = [0u8; READ_CHUNK];
        while !self.eof {
            match self.stream.read(&mut buf) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    if self.lines.push(&buf[..n]).is_err() {
                        self.eof = true;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => self.eof = true,
            }
        }
        while let Some(line) = self.lines.next_line() {
            if let Ok(msg) = decode::<HostMsg>(&line) {
                msgs.push(msg);
            }
        }
        msgs
    }

    /// Sends what waits, waiting until `deadline` for the host to take it.
    fn flush_until(&mut self, deadline: Instant) {
        loop {
            self.flush();
            if self.out.is_empty() || self.broken {
                return;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let mut fds = [pollfd(self.stream.as_raw_fd(), libc::POLLOUT)];
            if poll(&mut fds, Some(left)).is_err() {
                return;
            }
        }
    }
}

/// A `shutdown` under way.
struct Ending {
    /// When the session's process group gets `SIGKILL`.
    kill_at: Instant,
    killed: bool,
}

/// Signals the session's process group (`session`, its leader's pid).
/// One that is gone is fine.
fn signal_group(session: Pid, signal: Signal) {
    let _ = kill(Pid::from_raw(-session.as_raw()), signal);
}

/// Starts ending the session: `SIGTERM` to its process group now,
/// `SIGKILL` after the grace.
fn begin_ending(session: Pid, grace_ms: u64) -> Ending {
    signal_group(session, Signal::SIGTERM);
    Ending {
        kill_at: Instant::now() + shutdown_grace(grace_ms),
        killed: false,
    }
}

/// PID 1's loop while the session runs: relays its terminal, serves the
/// host's requests, reaps every child, and returns how the session ended.
pub fn supervise(
    ctl: &mut Ctl,
    relay: &mut Relay,
    reaper: &Reaper,
    session: Pid,
) -> Result<Ended, Failed> {
    let mut ended = None;
    let mut ending: Option<Ending> = None;
    loop {
        reaper.reap(session, &mut ended)?;
        if let Some(how) = ended {
            return Ok(how);
        }
        if ctl.eof && ending.is_none() {
            ending = Some(begin_ending(session, LOST_HOST_GRACE));
        }
        if let Some(end) = &mut ending {
            if !end.killed && Instant::now() >= end.kill_at {
                signal_group(session, Signal::SIGKILL);
                end.killed = true;
            }
        }
        let timeout = if ctl.pending.is_empty() {
            ending
                .as_ref()
                .filter(|end| !end.killed)
                .map(|end| end.kill_at.saturating_duration_since(Instant::now()))
        } else {
            // Messages that came with the config are served at once.
            Some(Duration::ZERO)
        };
        let (master, master_events) = relay.master_poll();
        let (stream, stream_events) = relay.stream_poll();
        let mut fds = [
            pollfd(ctl.stream.as_raw_fd(), ctl.events()),
            pollfd(master, master_events),
            pollfd(stream, stream_events),
            pollfd(reaper.fd(), libc::POLLIN),
        ];
        poll(&mut fds, timeout).step("poll")?;
        if fds[0].revents != 0 || !ctl.pending.is_empty() {
            ctl.flush();
            for msg in ctl.read() {
                match msg {
                    HostMsg::Resize { rows, cols } => {
                        if let Err(errno) = relay.resize(rows, cols) {
                            ctl.send(&log_warn(format!("TIOCSWINSZ: {errno}")));
                        }
                    }
                    HostMsg::Signal { sig } => match Signal::try_from(sig) {
                        Ok(signal) => signal_group(session, signal),
                        Err(_) => ctl.send(&log_warn(format!("no signal {sig}"))),
                    },
                    HostMsg::Shutdown { grace_ms } => {
                        if ending.is_none() {
                            ending = Some(begin_ending(session, grace_ms));
                        }
                    }
                    HostMsg::Ping { id } => ctl.send(&GuestMsg::Pong {
                        id,
                        guest_mono_ns: clock_ns(libc::CLOCK_MONOTONIC),
                    }),
                    // There is one session.
                    HostMsg::Config(_) => {}
                }
            }
        }
        relay.on_ready(fds[1].revents, fds[2].revents);
        if fds[3].revents != 0 {
            reaper.drain()?;
        }
    }
}

/// A `log` at level `warn`.
fn log_warn(msg: String) -> GuestMsg {
    GuestMsg::Log {
        level: boxcar_proto::guest::LogLevel::Warn,
        msg,
    }
}

/// Once the session has ended (`how`): its terminal drained to the stream
/// and closed, the report, the sweep, then the wait for the host to close
/// its side of both streams. See the module docs.
pub fn finish(
    ctl: &mut Ctl,
    relay: &mut Relay,
    reaper: &Reaper,
    session: Pid,
    how: Ended,
) -> Result<Ended, Failed> {
    relay.drain(Instant::now() + DRAIN_LIMIT);
    relay.close_stream_output();
    ctl.report(&exit_report(Some(how)));
    ctl.flush_until(Instant::now() + ACK_DEADLINE);
    let started = Instant::now();
    let how = reaper.sweep(session, how)?;
    wait_for_host(ctl, relay, started + ACK_DEADLINE);
    Ok(how)
}

/// Waits until `deadline` for the host to close its side of the control
/// channel and of the terminal stream, reading and dropping what it still
/// sends.
fn wait_for_host(ctl: &mut Ctl, relay: &mut Relay, deadline: Instant) {
    loop {
        let _ = ctl.read();
        let ctl_done = ctl.eof || ctl.broken;
        let pty_done = relay.read_until_closed();
        if ctl_done && pty_done {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        let ctl_events = if ctl_done { 0 } else { libc::POLLIN };
        let pty_events = if pty_done { 0 } else { libc::POLLIN };
        let mut fds = [
            pollfd(ctl.stream.as_raw_fd(), ctl_events),
            pollfd(relay.stream_fd(), pty_events),
        ];
        if poll(&mut fds, Some(left)).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use boxcar_proto::guest::{decode, GuestMsg, SessionConfig};

    use super::*;
    use crate::reaper::Ended;

    #[test]
    fn how_the_session_ended_is_its_exit_report() {
        assert_eq!(
            exit_report(Some(Ended::Exited(7))),
            GuestMsg::SessionExited {
                code: Some(7),
                signal: None
            }
        );
        assert_eq!(
            exit_report(Some(Ended::Killed(15))),
            GuestMsg::SessionExited {
                code: None,
                signal: Some(15)
            }
        );
        assert_eq!(
            exit_report(None),
            GuestMsg::SessionExited {
                code: None,
                signal: None
            }
        );
    }

    #[test]
    fn hello_names_this_init_and_its_clocks() {
        match hello() {
            GuestMsg::Hello {
                init_version,
                guest_mono_ns,
                guest_real_ns,
            } => {
                assert_eq!(init_version, env!("CARGO_PKG_VERSION"));
                assert!(guest_mono_ns > 0);
                // After 2020.
                assert!(guest_real_ns > 1_577_836_800_000_000_000);
            }
            other => panic!("{other:?}"),
        }
    }

    fn config() -> SessionConfig {
        SessionConfig {
            argv: vec!["/bin/sh".into(), "-l".into()],
            env: Vec::new(),
            cwd: "/workspace".into(),
            uid: 1000,
            gid: 1000,
            hostname: "boxcar".into(),
            term: "xterm-256color".into(),
            rows: 24,
            cols: 80,
            sysctls: Vec::new(),
        }
    }

    /// What init cannot run is refused before anything starts: no command,
    /// the all-ones id (which leaves setresuid's id alone), a hostname the
    /// kernel would refuse, a working directory that is not absolute.
    #[test]
    fn a_config_init_cannot_run_is_refused() {
        assert!(check_config(&config()).is_ok());
        type Change = fn(&mut SessionConfig);
        let cases: [(&str, Change); 6] = [
            ("argv", |c| c.argv.clear()),
            ("uid", |c| c.uid = u32::MAX),
            ("gid", |c| c.gid = u32::MAX),
            ("hostname", |c| c.hostname = "x".repeat(65)),
            ("hostname", |c| c.hostname.clear()),
            ("cwd", |c| c.cwd = "workspace".into()),
        ];
        for (what, change) in cases {
            let mut cfg = config();
            change(&mut cfg);
            let failed = check_config(&cfg).unwrap_err();
            assert!(failed.to_string().contains(what), "{what}: {failed}");
        }
    }

    /// Lines wait in the outbox for the socket, which may take part of
    /// one; the outbox is bounded.
    #[test]
    fn the_outbox_sends_whole_lines_through_partial_writes() {
        struct Trickle(Vec<u8>);
        impl std::io::Write for Trickle {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let n = buf.len().min(3);
                self.0.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut out = Outbox::new(1024);
        assert!(out.push(&GuestMsg::SessionStarted { pid: 7 }));
        assert!(out.push(&GuestMsg::Pong {
            id: 1,
            guest_mono_ns: 2
        }));
        let mut sink = Trickle(Vec::new());
        while !out.is_empty() {
            out.write_to(&mut sink).unwrap();
        }
        let lines: Vec<&[u8]> = sink.0.split_inclusive(|&b| b == b'\n').collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            decode::<GuestMsg>(lines[0]).unwrap(),
            GuestMsg::SessionStarted { pid: 7 }
        );

        // Full: a line that does not fit is dropped whole.
        let mut out = Outbox::new(40);
        assert!(out.push(&GuestMsg::SessionStarted { pid: 7 }));
        assert!(!out.push(&GuestMsg::SessionStarted { pid: 8 }));
        // A report is queued whatever the cap.
        out.push_report(&GuestMsg::SessionStarted { pid: 9 });
        let mut sent = Vec::new();
        out.write_to(&mut sent).unwrap();
        assert_eq!(
            sent,
            b"{\"t\":\"session.started\",\"pid\":7}\n{\"t\":\"session.started\",\"pid\":9}\n"
        );
    }

    /// What the host sends with the config is kept for the loop, in order;
    /// what it sent before is dropped.
    #[test]
    fn messages_after_the_config_wait_for_the_loop() {
        use boxcar_proto::guest::{encode, HostMsg};
        use std::io::Write;
        use std::os::fd::OwnedFd;
        use std::time::{Duration, Instant};

        let (ours, mut host) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let mut ctl = Ctl::over(OwnedFd::from(ours));
        let mut lines = encode(&HostMsg::Ping { id: 1 });
        lines.extend(encode(&HostMsg::Config(config())));
        lines.extend(encode(&HostMsg::Resize {
            rows: 40,
            cols: 120,
        }));
        lines.extend(encode(&HostMsg::Ping { id: 2 }));
        host.write_all(&lines).unwrap();
        let got = ctl
            .receive_config(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(got, config());
        assert_eq!(
            ctl.read(),
            [
                HostMsg::Resize {
                    rows: 40,
                    cols: 120
                },
                HostMsg::Ping { id: 2 }
            ]
        );
        // The host closing its side is the end of the channel.
        drop(host);
        assert!(ctl.read().is_empty());
        assert!(ctl.eof);
    }

    /// The deadline init gives a shutdown: the host's grace, at most a
    /// minute.
    #[test]
    fn the_shutdown_grace_is_bounded() {
        use std::time::Duration;
        assert_eq!(shutdown_grace(5000), Duration::from_secs(5));
        assert_eq!(shutdown_grace(0), Duration::ZERO);
        assert_eq!(shutdown_grace(u64::MAX), Duration::from_secs(60));
    }
}
