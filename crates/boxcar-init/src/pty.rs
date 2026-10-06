// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session's terminal in `vsock` mode: a PTY whose slave is the
//! session's controlling terminal, and whose master init relays to the
//! terminal stream (vsock port 1025) and back.
//!
//! [`open`] makes the PTY at the config's size, the slave the session
//! user's; [`spawn`] forks the session onto it (a session of its own with
//! the slave as its controlling terminal, then M1's drop to the user and
//! exec, [`crate::session::spawn_child`]). [`Relay`] moves the bytes, each
//! way through a [`Pipe`] of [`PIPE_CAP`] bytes: while the stream takes no
//! more, the master is not read and the session blocks on its terminal;
//! while the master takes no more, the stream is not read. When the stream
//! is gone the session's output is read and dropped, so the session never
//! blocks on a host that left. Once the session has ended,
//! [`Relay::drain`] reads the master until `EIO` (no slave left open) and
//! sends it all, for as long as the host keeps taking bytes: it gives up
//! only when the host has taken none for [`DRAIN_LIMIT`] ([`HostDeadline`]),
//! so a slow host gets everything and a dead one holds init up for 2 s.
//! The master is read for at most [`DRAIN_LIMIT`] of waiting on it alone
//! and [`DRAIN_READ_MAX`] bytes, which bounds a process the session left
//! behind that holds the slave and keeps writing.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use boxcar_proto::guest::{encode, PtyHeader, SessionConfig};
use nix::errno::Errno;
use nix::pty::{openpty, Winsize};
use nix::unistd::Pid;

use crate::console::{warn, Failed, Step};
use crate::session::{self, ChildPlan, ChildTty, Exec, Session};
use crate::vsock::{close_output, set_nonblocking};

/// The bytes each way may hold while the other side is not taking them.
pub const PIPE_CAP: usize = 64 * 1024;

/// How long, once the session has ended, init waits for a host that takes
/// none of the session's last output, and for a master that has none to
/// give and is not at its end.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(2);

/// The most bytes init reads from the master once the session has ended:
/// far more than the session can have left there (its writes wait for
/// room), so only processes it left behind are cut short.
pub const DRAIN_READ_MAX: usize = 1 << 20;

/// A terminal's size when none is given.
const DEFAULT_SIZE: (u16, u16) = (24, 80);

/// The group of terminals.
const TTY_GID: libc::gid_t = 5;

/// The terminal stream's header line for a terminal of `rows` by `cols`.
pub fn header_line(rows: u16, cols: u16) -> Vec<u8> {
    // Some 45 bytes: never over the line limit.
    encode(&PtyHeader::main(rows, cols)).unwrap_or_default()
}

/// The window size of `rows` by `cols`, or 24 by 80 when either is 0.
pub fn winsize(rows: u16, cols: u16) -> Winsize {
    let (ws_row, ws_col) = if rows == 0 || cols == 0 {
        DEFAULT_SIZE
    } else {
        (rows, cols)
    };
    Winsize {
        ws_row,
        ws_col,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// The session's environment: the config's, in order, as `NAME=value`
/// strings, then `TERM` from the config's terminal when the environment
/// has none. A variable whose name is empty or holds `=`, or that holds a
/// NUL byte, cannot be passed and is left out, with a warning.
pub fn session_env(config: &SessionConfig) -> Vec<CString> {
    let mut env = Vec::with_capacity(config.env.len() + 1);
    for (name, value) in &config.env {
        if name.is_empty() || name.contains('=') {
            warn(&format!("session environment: {name:?} is not a name"));
            continue;
        }
        match CString::new(format!("{name}={value}")) {
            Ok(var) => env.push(var),
            Err(_) => warn(&format!("session environment: {name} holds a NUL byte")),
        }
    }
    let has_term = env.iter().any(|var| var.as_bytes().starts_with(b"TERM="));
    if !has_term {
        if let Ok(term) = CString::new(format!("TERM={}", config.term)) {
            env.push(term);
        }
    }
    // With a session CA, the variables that point the runtimes at it,
    // unless the config set them itself.
    if config.ca_pem.is_some() {
        for (name, value) in crate::trust::ENV {
            let set = env
                .iter()
                .any(|var| var.as_bytes().starts_with(format!("{name}=").as_bytes()));
            if !set {
                if let Ok(var) = CString::new(format!("{name}={value}")) {
                    env.push(var);
                }
            }
        }
    }
    env
}

/// The `PATH` of `env` (the first, which is what the session sees), which
/// the command is looked for on; init's own when `env` has none.
pub fn search_path(env: &[CString]) -> &str {
    // The first, as the session's `getenv("PATH")` finds it.
    let path = env
        .iter()
        .find_map(|var| var.to_str().ok()?.strip_prefix("PATH="));
    match path {
        Some(path) => path,
        None => session::session_path(),
    }
}

/// A PTY for the session.
pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// Opens a PTY of `rows` by `cols` whose slave belongs to `uid` (group
/// `tty`, as `login` leaves it); both ends close on exec.
pub fn open(rows: u16, cols: u16, uid: u32) -> Result<Pty, Failed> {
    let pty = openpty(&winsize(rows, cols), None).step("openpty")?;
    for fd in [&pty.master, &pty.slave] {
        // SAFETY: fcntl with integer arguments only.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(Failed::new("FD_CLOEXEC on the PTY", Errno::last()));
        }
    }
    // SAFETY: fchown takes integer arguments only.
    if unsafe { libc::fchown(pty.slave.as_raw_fd(), uid, TTY_GID) } != 0 {
        // The session still has the slave on 0, 1 and 2.
        warn(&format!("fchown the PTY slave: {}", Errno::last()));
    }
    Ok(Pty {
        master: pty.master,
        slave: pty.slave,
    })
}

/// Forks the session onto `pty`: see the module docs. Returns its pid, which
/// is also its process group's and its session's.
pub fn spawn(
    session: &Session,
    exec: &Exec,
    cwd: &CStr,
    pty: &Pty,
    join_cgroup: bool,
) -> Result<Pid, Failed> {
    session::spawn_child(&ChildPlan {
        session,
        exec,
        tty: ChildTty::Pty {
            slave: pty.slave.as_fd(),
            master: pty.master.as_fd(),
        },
        cwd,
        cwd_step: "chdir",
        join_cgroup,
    })
}

/// Bytes on their way from one side to the other, at most a capacity.
pub struct Pipe {
    buf: Vec<u8>,
    cap: usize,
}

impl Pipe {
    pub fn new(cap: usize) -> Pipe {
        Pipe {
            buf: Vec::with_capacity(cap),
            cap,
        }
    }

    /// Bytes it can still take.
    pub fn room(&self) -> usize {
        self.cap - self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Bytes it holds.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Drops what it holds.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// One read from `from`, of at most its room: the bytes read, or `None`
    /// at the end of `from`. `WouldBlock` is `Some(0)`.
    pub fn fill_from(&mut self, from: &mut impl Read) -> io::Result<Option<usize>> {
        let room = self.room();
        if room == 0 {
            return Ok(Some(0));
        }
        let start = self.buf.len();
        self.buf.resize(start + room, 0);
        let read = loop {
            match from.read(&mut self.buf[start..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                read => break read,
            }
        };
        let n = *read.as_ref().unwrap_or(&0);
        self.buf.truncate(start + n);
        match read {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(n)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(Some(0)),
            Err(error) => Err(error),
        }
    }

    /// Writes what it holds to `to` until it is empty or `to` would block,
    /// partial writes included.
    pub fn drain_to(&mut self, to: &mut impl Write) -> io::Result<()> {
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
}

/// A deadline that moves with the host: it passes `limit` after the last
/// time the host took a byte, so a host that keeps taking them, however
/// slowly, never meets it, and one that takes none meets it `limit` after
/// it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostDeadline {
    last: Instant,
    limit: Duration,
}

impl HostDeadline {
    /// A deadline `limit` after `now`.
    pub fn new(now: Instant, limit: Duration) -> HostDeadline {
        HostDeadline { last: now, limit }
    }

    /// The host took a byte at `now`.
    pub fn progress(&mut self, now: Instant) {
        self.last = self.last.max(now);
    }

    /// When the host last took a byte.
    pub fn last(&self) -> Instant {
        self.last
    }

    /// Whether it has passed at `now`.
    pub fn passed(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last) >= self.limit
    }

    /// How long until it passes, from `now`.
    pub fn left(&self, now: Instant) -> Duration {
        (self.last + self.limit).saturating_duration_since(now)
    }
}

/// How [`Relay::drain`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Drained {
    /// Bytes of the session's output init held and could not send: the
    /// host took none for [`DRAIN_LIMIT`], or it is gone. (What was still
    /// on the master then is not counted.)
    pub undelivered: usize,
    /// When the host last took a byte.
    pub last_progress: Instant,
}

/// The relay between the PTY's master and the terminal stream: see the
/// module docs.
pub struct Relay {
    master: File,
    stream: Option<File>,
    /// The session's output, on its way to the stream.
    pub(crate) to_stream: Pipe,
    /// The host's input, on its way to the session.
    to_master: Pipe,
    /// No slave is left open (`EIO`), or the master failed.
    master_eof: bool,
    /// The master takes no more input.
    master_broken: bool,
    /// The host closed its side, or the stream failed.
    stream_eof: bool,
    /// The stream takes no more: the host is gone.
    stream_broken: bool,
}

/// The poll events of a side.
pub type Events = libc::c_short;

impl Relay {
    /// A relay between `master` and `stream`, both made non-blocking; with
    /// no stream (the host did not take the terminal) the session's output
    /// is read and dropped.
    pub fn new(master: OwnedFd, stream: Option<OwnedFd>) -> Relay {
        for fd in std::iter::once(&master).chain(stream.as_ref()) {
            if let Err(errno) = set_nonblocking(fd.as_raw_fd()) {
                warn(&format!("O_NONBLOCK on the session's terminal: {errno}"));
            }
        }
        Relay {
            master: File::from(master),
            stream_broken: stream.is_none(),
            stream_eof: stream.is_none(),
            stream: stream.map(File::from),
            to_stream: Pipe::new(PIPE_CAP),
            to_master: Pipe::new(PIPE_CAP),
            master_eof: false,
            master_broken: false,
        }
    }

    /// Whether the master is to be read: a slave is left, and the stream's
    /// pipe has room.
    pub fn wants_master_input(&self) -> bool {
        !self.master_eof && self.to_stream.room() > 0
    }

    /// The master's descriptor and the events to wait for on it.
    pub fn master_poll(&self) -> (libc::c_int, Events) {
        let mut events = 0;
        if self.wants_master_input() {
            events |= libc::POLLIN;
        }
        if !self.to_master.is_empty() && !self.master_broken {
            events |= libc::POLLOUT;
        }
        (self.master.as_raw_fd(), events)
    }

    /// The stream's descriptor and the events to wait for on it (-1 when
    /// there is no stream).
    pub fn stream_poll(&self) -> (libc::c_int, Events) {
        let Some(stream) = &self.stream else {
            return (-1, 0);
        };
        let mut events = 0;
        if !self.stream_eof && self.to_master.room() > 0 {
            events |= libc::POLLIN;
        }
        if !self.to_stream.is_empty() && !self.stream_broken {
            events |= libc::POLLOUT;
        }
        (stream.as_raw_fd(), events)
    }

    /// Moves what the master and the stream are ready for, as `revents`
    /// say.
    pub fn on_ready(&mut self, master: Events, stream: Events) {
        if master != 0 {
            self.read_master();
            self.write_master();
        }
        if stream != 0 {
            self.read_stream();
        }
        // Whatever was read from the master goes out now.
        self.write_stream();
        if master != 0 || stream != 0 {
            self.write_master();
        }
    }

    /// Reads what the master has and the stream's pipe has room for;
    /// returns the bytes read.
    fn read_master(&mut self) -> usize {
        if !self.wants_master_input() {
            return 0;
        }
        let read = match self.to_stream.fill_from(&mut self.master) {
            Ok(Some(n)) => n,
            // EIO: no slave is left open; anything else ends the reads too.
            Ok(None) | Err(_) => {
                self.master_eof = true;
                0
            }
        };
        if self.stream_broken {
            // Nowhere to go: dropped, so the session never blocks on it.
            self.to_stream.clear();
        }
        read
    }

    fn write_master(&mut self) {
        if self.to_master.is_empty() || self.master_broken {
            return;
        }
        if self.to_master.drain_to(&mut self.master).is_err() {
            self.master_broken = true;
            self.to_master.clear();
        }
    }

    fn read_stream(&mut self) {
        let Some(stream) = &mut self.stream else {
            return;
        };
        if self.stream_eof || self.to_master.room() == 0 {
            return;
        }
        match self.to_master.fill_from(stream) {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => self.stream_eof = true,
        }
        if self.master_broken {
            self.to_master.clear();
        }
    }

    /// Sends what the stream takes; returns the bytes it took.
    fn write_stream(&mut self) -> usize {
        let Some(stream) = &mut self.stream else {
            self.to_stream.clear();
            return 0;
        };
        if self.stream_broken {
            self.to_stream.clear();
            return 0;
        }
        let before = self.to_stream.len();
        if self.to_stream.drain_to(stream).is_err() {
            self.stream_broken = true;
            self.to_stream.clear();
            return 0;
        }
        before - self.to_stream.len()
    }

    /// Sets the terminal's size; the kernel tells the session (`SIGWINCH`).
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), Errno> {
        let size = winsize(rows, cols);
        // SAFETY: TIOCSWINSZ reads one winsize through its argument, which
        // points at `size`, alive for the call.
        if unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &size) } != 0 {
            return Err(Errno::last());
        }
        Ok(())
    }

    /// Once the session has ended: reads the master until `EIO` and sends
    /// everything to the stream, giving up only when the host has taken no
    /// byte for `limit`; reads the master for at most `limit` of waiting
    /// on it alone and [`DRAIN_READ_MAX`] bytes. See the module docs.
    pub fn drain(&mut self, limit: Duration) -> Drained {
        let mut host = HostDeadline::new(Instant::now(), limit);
        let mut read_wait = Duration::ZERO;
        let mut read_total = 0usize;
        loop {
            let reading = !self.master_eof && read_wait < limit && read_total < DRAIN_READ_MAX;
            if reading {
                read_total += self.read_master();
            }
            let sent = self.write_stream();
            let now = Instant::now();
            if sent > 0 {
                host.progress(now);
            }
            let reading = !self.master_eof && read_wait < limit && read_total < DRAIN_READ_MAX;
            if self.to_stream.is_empty() && (!reading || self.stream_broken) {
                return Drained {
                    undelivered: 0,
                    last_progress: host.last(),
                };
            }
            if !self.to_stream.is_empty() && host.passed(now) {
                return Drained {
                    undelivered: self.to_stream.len(),
                    last_progress: host.last(),
                };
            }
            let master_events = if reading && self.to_stream.room() > 0 {
                libc::POLLIN
            } else {
                0
            };
            let stream_events = if self.to_stream.is_empty() {
                0
            } else {
                libc::POLLOUT
            };
            // Waiting on the master alone counts against its budget;
            // waiting on the host does not.
            let on_master_alone = self.to_stream.is_empty();
            let timeout = if on_master_alone {
                limit.saturating_sub(read_wait)
            } else {
                host.left(now)
            };
            let mut fds = [
                pollfd(self.master.as_raw_fd(), master_events),
                pollfd(self.stream_fd(), stream_events),
            ];
            if poll(&mut fds, Some(timeout)).is_err() {
                return Drained {
                    undelivered: self.to_stream.len(),
                    last_progress: host.last(),
                };
            }
            if on_master_alone {
                read_wait += now.elapsed();
            }
        }
    }

    /// Closes the sending side of the stream: the host reads its end, and
    /// answers by closing its own once it has written everything out.
    pub fn close_stream_output(&mut self) {
        if let Some(stream) = &self.stream {
            close_output(stream.as_raw_fd());
        }
    }

    /// Reads what the host still sends, and drops it; returns whether the
    /// host has closed its side (or there is no stream).
    pub fn read_until_closed(&mut self) -> bool {
        let Some(stream) = &mut self.stream else {
            return true;
        };
        let mut scratch = [0u8; 4096];
        while !self.stream_eof {
            match stream.read(&mut scratch) {
                Ok(0) => self.stream_eof = true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => self.stream_eof = true,
            }
        }
        self.stream_eof
    }

    /// The stream's descriptor, -1 without one.
    pub fn stream_fd(&self) -> libc::c_int {
        self.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}

/// A `pollfd` for `fd` and `events`; skipped by `poll` (fd -1) when there
/// are none.
pub fn pollfd(fd: libc::c_int, events: Events) -> libc::pollfd {
    libc::pollfd {
        fd: if events == 0 { -1 } else { fd },
        events,
        revents: 0,
    }
}

/// `poll(2)` for at most `timeout` (rounded up to the millisecond), or for
/// as long as it takes; an interrupted poll is not an error.
pub fn poll(fds: &mut [libc::pollfd], timeout: Option<Duration>) -> Result<(), Errno> {
    let ms = match timeout {
        None => -1,
        Some(left) => {
            libc::c_int::try_from(left.as_nanos().div_ceil(1_000_000)).unwrap_or(libc::c_int::MAX)
        }
    };
    let count = libc::nfds_t::try_from(fds.len()).unwrap_or(0);
    // SAFETY: poll reads and writes `count` pollfds, which `fds` holds.
    if unsafe { libc::poll(fds.as_mut_ptr(), count, ms) } < 0 {
        return match Errno::last() {
            Errno::EINTR => Ok(()),
            errno => Err(errno),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use boxcar_proto::guest::SessionConfig;

    use super::*;

    #[test]
    fn the_header_line_names_the_session_and_its_size() {
        assert_eq!(
            header_line(24, 80),
            b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n"
        );
    }

    #[test]
    fn the_window_size_is_the_configs_or_24_by_80() {
        let size = winsize(40, 120);
        assert_eq!((size.ws_row, size.ws_col), (40, 120));
        assert_eq!((size.ws_xpixel, size.ws_ypixel), (0, 0));
        let size = winsize(0, 0);
        assert_eq!((size.ws_row, size.ws_col), (24, 80));
    }

    fn config(env: &[(&str, &str)]) -> SessionConfig {
        SessionConfig {
            argv: vec!["/bin/sh".into()],
            env: env
                .iter()
                .map(|&(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            cwd: "/workspace".into(),
            uid: 1000,
            gid: 1000,
            hostname: "boxcar".into(),
            term: "xterm-256color".into(),
            rows: 24,
            cols: 80,
            sysctls: Vec::new(),
            ca_pem: None,
        }
    }

    fn texts(env: &[std::ffi::CString]) -> Vec<&str> {
        env.iter().map(|s| s.to_str().unwrap()).collect()
    }

    /// The environment is the config's, in order; `TERM` comes from the
    /// config's terminal when the environment has none; a variable that
    /// cannot be one is left out.
    #[test]
    fn the_environment_is_the_configs() {
        let env = session_env(&config(&[
            ("PATH", "/bin"),
            ("TERM", "vt100"),
            ("A", "b=c"),
        ]));
        assert_eq!(texts(&env), ["PATH=/bin", "TERM=vt100", "A=b=c"]);
        let env = session_env(&config(&[("PATH", "/bin")]));
        assert_eq!(texts(&env), ["PATH=/bin", "TERM=xterm-256color"]);
        let env = session_env(&config(&[
            ("", "x"),
            ("A=B", "x"),
            ("N\0UL", "x"),
            ("V", "nul\0"),
            ("OK", ""),
        ]));
        assert_eq!(texts(&env), ["OK=", "TERM=xterm-256color"]);
    }

    /// With a CA in the config, the runtimes' variables name the
    /// certificate and the bundle, after the config's own, which win.
    #[test]
    fn session_env_names_the_bundle_when_the_config_has_a_ca() {
        let mut with_ca = config(&[("PATH", "/bin")]);
        with_ca.ca_pem =
            Some("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".into());
        let env = session_env(&with_ca);
        assert_eq!(
            texts(&env),
            [
                "PATH=/bin",
                "TERM=xterm-256color",
                "NODE_EXTRA_CA_CERTS=/run/boxcar/ca.pem",
                "SSL_CERT_FILE=/run/boxcar/ca-bundle.pem",
                "CURL_CA_BUNDLE=/run/boxcar/ca-bundle.pem",
                "REQUESTS_CA_BUNDLE=/run/boxcar/ca-bundle.pem",
                "GIT_SSL_CAINFO=/run/boxcar/ca-bundle.pem",
            ]
        );
        // The config's own value stays, and is not repeated.
        let mut own = config(&[("SSL_CERT_FILE", "/etc/mine.pem")]);
        own.ca_pem = with_ca.ca_pem.clone();
        let own_env = session_env(&own);
        let env = texts(&own_env);
        assert_eq!(env[0], "SSL_CERT_FILE=/etc/mine.pem");
        assert_eq!(
            env.iter()
                .filter(|v| v.starts_with("SSL_CERT_FILE="))
                .count(),
            1
        );
        assert!(env.contains(&"NODE_EXTRA_CA_CERTS=/run/boxcar/ca.pem"));
        // Without a CA, nothing is added.
        let plain = session_env(&config(&[("PATH", "/bin")]));
        assert_eq!(texts(&plain), ["PATH=/bin", "TERM=xterm-256color"]);
    }

    /// The session's PATH is the one its environment gives, else init's.
    #[test]
    fn the_search_path_is_the_environments() {
        let env = session_env(&config(&[("PATH", "/opt/bin:/bin")]));
        assert_eq!(search_path(&env), "/opt/bin:/bin");
        // Two PATHs: the first, which the session's getenv finds.
        let env = session_env(&config(&[("PATH", "/first"), ("PATH", "/second")]));
        assert_eq!(search_path(&env), "/first");
        let env = session_env(&config(&[]));
        assert_eq!(search_path(&env), crate::session::session_path());
    }

    #[test]
    fn a_pipe_holds_at_most_its_capacity_and_drains_through_partial_writes() {
        let mut pipe = Pipe::new(8);
        assert_eq!(pipe.room(), 8);
        let mut src: &[u8] = b"0123456789";
        assert_eq!(pipe.fill_from(&mut src).unwrap(), Some(8));
        assert_eq!(pipe.room(), 0);
        struct Two(Vec<u8>);
        impl std::io::Write for Two {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let n = buf.len().min(2);
                self.0.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut out = Two(Vec::new());
        pipe.drain_to(&mut out).unwrap();
        assert_eq!(out.0, b"01234567");
        assert!(pipe.is_empty());
        // The end of the source.
        let mut empty: &[u8] = b"";
        assert_eq!(pipe.fill_from(&mut empty).unwrap(), None);
    }

    /// When the session has ended, what it wrote last is read from the
    /// master until EIO (no slave left) and goes to the stream whole.
    #[test]
    fn the_master_is_drained_to_eio_into_the_stream() {
        let pty = nix::pty::openpty(&winsize(24, 80), None).unwrap();
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        theirs
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        nix::unistd::write(&pty.slave, b"last line\n").unwrap();
        drop(pty.slave);
        let mut relay = Relay::new(pty.master, Some(OwnedFd::from(ours)));
        let started = Instant::now();
        let drained = relay.drain(DRAIN_LIMIT);
        assert_eq!(drained.undelivered, 0);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        relay.close_stream_output();
        let mut got = Vec::new();
        theirs.read_to_end(&mut got).unwrap();
        // The terminal turns the newline into CR LF.
        assert_eq!(got, b"last line\r\n");
    }

    /// While the stream takes nothing more, the master is not read: the
    /// session blocks on its terminal.
    #[test]
    fn a_full_pipe_stops_the_reads_from_the_master() {
        let pty = nix::pty::openpty(&winsize(24, 80), None).unwrap();
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let mut relay = Relay::new(pty.master, Some(OwnedFd::from(ours)));
        assert!(relay.wants_master_input());
        relay
            .to_stream
            .fill_from(&mut &vec![b'x'; PIPE_CAP][..])
            .unwrap();
        assert!(!relay.wants_master_input());
    }

    /// The host's deadline moves with each byte it takes.
    #[test]
    fn the_host_deadline_counts_from_the_last_byte_taken() {
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let mut host = HostDeadline::new(t0, Duration::from_millis(2000));
        assert!(!host.passed(ms(1999)));
        assert_eq!(host.left(ms(500)), Duration::from_millis(1500));
        host.progress(ms(1500));
        assert!(!host.passed(ms(3000)));
        assert!(!host.passed(ms(3499)));
        assert!(host.passed(ms(3500)));
        assert_eq!(host.last(), ms(1500));
        // A progress older than the last one changes nothing.
        host.progress(ms(100));
        assert_eq!(host.last(), ms(1500));
        assert_eq!(host.left(ms(9000)), Duration::ZERO);
    }

    /// A small send buffer on `stream`, so that the drain is paced by the
    /// host's reads.
    fn small_send_buffer(stream: &UnixStream) {
        use std::os::fd::AsRawFd;
        let size: libc::c_int = 4096;
        // SAFETY: setsockopt reads one int of the size given.
        let rc = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);
    }

    /// A host that reads slowly but steadily gets everything, though the
    /// drain takes several times its limit: the limit counts from the last
    /// byte it took.
    #[test]
    fn a_slow_host_gets_all_of_the_drain() {
        const TOTAL: usize = 96 * 1024;
        let limit = Duration::from_millis(200);
        let pty = nix::pty::openpty(&winsize(24, 80), None).unwrap();
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        small_send_buffer(&ours);
        let slave = pty.slave;
        let writer = std::thread::spawn(move || {
            let data = vec![b'x'; TOTAL];
            let mut sent = 0;
            while sent < TOTAL {
                sent += nix::unistd::write(&slave, &data[sent..]).unwrap();
            }
            // The session's end: no slave left.
        });
        // 4 KiB every 30 ms: about 0.7 s for it all, against 200 ms.
        let reader = std::thread::spawn(move || {
            let mut got = 0;
            let mut buf = [0u8; 4096];
            loop {
                match theirs.read(&mut buf) {
                    Ok(0) => return got,
                    Ok(n) => got += n,
                    Err(e) => panic!("{e}"),
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let mut relay = Relay::new(pty.master, Some(OwnedFd::from(ours)));
        let started = Instant::now();
        let drained = relay.drain(limit);
        let took = started.elapsed();
        writer.join().unwrap();
        relay.close_stream_output();
        drop(relay);
        let got = reader.join().unwrap();
        assert_eq!(drained.undelivered, 0, "after {took:?}");
        assert!(
            took > limit * 2,
            "the drain was not paced by the host: {took:?}"
        );
        assert_eq!(got, TOTAL);
    }

    /// A host that takes nothing holds the drain up for its limit, and what
    /// init could not send is counted.
    #[test]
    fn a_host_that_takes_nothing_ends_the_drain_at_its_limit() {
        let limit = Duration::from_millis(200);
        let pty = nix::pty::openpty(&winsize(24, 80), None).unwrap();
        let (ours, _theirs) = UnixStream::pair().unwrap();
        small_send_buffer(&ours);
        let slave = pty.slave;
        let writer = std::thread::spawn(move || {
            let data = vec![b'x'; 64 * 1024];
            // Blocks once the PTY and the pipe are full: fine, the master
            // goes away under it.
            let _ = nix::unistd::write(&slave, &data);
            let _ = nix::unistd::write(&slave, &data);
        });
        let mut relay = Relay::new(pty.master, Some(OwnedFd::from(ours)));
        let started = Instant::now();
        let drained = relay.drain(limit);
        let took = started.elapsed();
        assert!(drained.undelivered > 0, "{drained:?}");
        assert!(took >= limit, "{took:?}");
        assert!(took < limit * 5, "{took:?}");
        drop(relay);
        writer.join().unwrap();
    }
}
