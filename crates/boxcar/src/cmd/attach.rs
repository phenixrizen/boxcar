// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar attach`: a running session's terminal, from this one.
//!
//! Two connections to the session's control socket: one asks `pty.attach`
//! and becomes the terminal's raw bytes, both ways; the other sends
//! `pty.resize` with this terminal's size, at the start and on every
//! `SIGWINCH`, and hears the server's events. The terminal is in raw mode
//! while attached ([`RawModeGuard`]), restored on every way out: the stop
//! signals and `SIGWINCH` are blocked and read from a signalfd, so a
//! signal ends the attach like a detach does, and a panic restores it
//! too.
//!
//! Ctrl-P then Ctrl-Q within a second detaches ([`DetachKeys`]); the two
//! keys are not sent. A server that detaches the client for being slow
//! ends the stream with the `pty.detached` line, which is not printed
//! ([`DetachedTail`]).

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use boxcar_proto::control::{to_line, PtyDetached, PTY_SESSION};
use boxcar_vmm::lifecycle::{block_signals, block_stop_signals, SignalFd, STOP_SIGNALS};
use boxcar_vmm::stdin::{stdin_is_tty, RawModeGuard};
use serde_json::json;

use crate::cli::AttachArgs;
use crate::client::{self, Client, Message, Sender};
use crate::cmd::run::stdin_terminal_size;
use crate::cmd::tell;

/// Ctrl-P: the first detach key.
const CTRL_P: u8 = 0x10;
/// Ctrl-Q: the second.
const CTRL_Q: u8 = 0x11;
/// How soon after Ctrl-P the Ctrl-Q must come.
const DETACH_WINDOW: Duration = Duration::from_secs(1);

/// The exit code when the server detached this client for being slow.
const SLOW_EXIT: u8 = 3;

/// Bytes moved at a time.
const CHUNK: usize = 16 * 1024;

/// Why the attach ended, when something other than the stream's end ended
/// it. The first to be set wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The detach keys.
    Detached,
    /// A stop signal, by number.
    Signal(i32),
    /// The server detached this client for being slow.
    Slow,
}

/// What the threads tell the main one, which copies the stream.
struct Ending {
    outcome: Mutex<Option<Outcome>>,
    /// The attached stream, shut down to end the copy.
    stream: UnixStream,
}

impl Ending {
    /// Ends the attach for `outcome`, unless something ended it first.
    fn end(&self, outcome: Outcome) {
        let mut slot = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(outcome);
        }
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn outcome(&self) -> Option<Outcome> {
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Attaches to the session `args` names; see the `attach` command's help.
pub fn run(args: &AttachArgs) -> anyhow::Result<ExitCode> {
    // Before any thread starts: they reach only this command's signalfd.
    block_stop_signals().context("cannot block the stop signals")?;
    block_signals(&[libc::SIGWINCH]).context("cannot block SIGWINCH")?;
    let mut signals: Vec<i32> = STOP_SIGNALS.to_vec();
    signals.push(libc::SIGWINCH);
    let signals = SignalFd::with(&signals).context("cannot read signals")?;

    let session = &args.session;
    let mut attached = client::connect(session.control.as_deref(), session.session_id.as_deref())?;
    let mut control = Client::connect(attached.path())?;
    let mode = if args.ro { "ro" } else { "rw" };
    let params = json!({"session": PTY_SESSION, "mode": mode, "replay_bytes": args.replay});
    attached
        .request("pty.attach", params)?
        .map_err(|error| anyhow!("attach: {error}"))?;
    let (stream, pending) = attached
        .into_raw()
        .context("cannot read the session's terminal")?;

    let tty = stdin_is_tty();
    if tty {
        if let Some(size) = stdin_terminal_size() {
            // A size the server refuses leaves the session's as it is.
            let _ = control.request("pty.resize", resize_params(size))?;
        }
    }
    control.set_timeout(None)?;
    let sender = control.sender()?;
    let ending = Arc::new(Ending {
        outcome: Mutex::new(None),
        stream: stream.try_clone()?,
    });
    let to_session = stream.try_clone()?;
    let stdin = File::from(io::stdin().as_fd().try_clone_to_owned()?);

    let terminal = RawModeGuard::enter().context("cannot put the terminal in raw mode")?;
    {
        let ending = Arc::clone(&ending);
        let ro = args.ro;
        thread::Builder::new()
            .name("attach-stdin".into())
            .spawn(move || forward_input(stdin, &to_session, ro, &ending))?;
    }
    {
        let ending = Arc::clone(&ending);
        thread::Builder::new()
            .name("attach-signals".into())
            .spawn(move || watch_signals(&signals, sender, tty, &ending))?;
    }
    {
        let ending = Arc::clone(&ending);
        thread::Builder::new()
            .name("attach-control".into())
            .spawn(move || watch_control(control, &ending))?;
    }
    let copied = copy_out(&stream, &pending, &mut io::stdout().lock());
    // Back to the terminal as it was before anything is said.
    drop(terminal);

    match (ending.outcome(), copied) {
        (Some(Outcome::Detached), _) => Ok(ExitCode::SUCCESS),
        (Some(Outcome::Signal(signo)), _) => Ok(ExitCode::from(
            u8::try_from(128 + signo.clamp(0, 127)).unwrap_or(1),
        )),
        (Some(Outcome::Slow), _) | (None, Ok(true)) => {
            tell(
                "boxcar: detached: the session's output came faster than this terminal took it \
                 (the VMM keeps at most 1 MiB for each client)",
            );
            Ok(ExitCode::from(SLOW_EXIT))
        }
        (None, Ok(false)) => Ok(ExitCode::SUCCESS),
        (None, Err(error)) => Err(error).context("the session's terminal"),
    }
}

/// The parameters of `pty.resize` for a terminal of `size` (rows, cols).
fn resize_params(size: (u16, u16)) -> serde_json::Value {
    json!({"session": PTY_SESSION, "rows": size.0, "cols": size.1})
}

/// The stream to `out`: `pending` first, then what comes, until the stream
/// ends. Returns whether it ended with the server's `pty.detached` line,
/// which is not written out.
fn copy_out(stream: &UnixStream, pending: &[u8], out: &mut impl Write) -> io::Result<bool> {
    let mut tail = DetachedTail::new(to_line(&PtyDetached::slow()).map_err(io::Error::other)?);
    let ready = tail.push(pending);
    out.write_all(&ready)?;
    out.flush()?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        match (&*stream).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let ready = tail.push(&buf[..n]);
                out.write_all(&ready)?;
                out.flush()?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // A server that closes with input it did not read resets the
            // connection: an end as well.
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
            Err(error) => return Err(error),
        }
    }
    let (rest, slow) = tail.finish();
    out.write_all(&rest)?;
    out.flush()?;
    Ok(slow)
}

/// Stdin to the session, but for the detach keys, which end the attach;
/// in read-only mode only the keys count. At the end of stdin, the
/// session's side of the stream is closed for sending: the output goes on.
fn forward_input(mut stdin: File, to_session: &UnixStream, ro: bool, ending: &Ending) {
    let mut keys = DetachKeys::default();
    let mut buf = vec![0u8; CHUNK];
    let send = |bytes: &[u8]| -> bool {
        if ro || bytes.is_empty() {
            return true;
        }
        let mut to_session = to_session;
        to_session.write_all(bytes).is_ok()
    };
    loop {
        // While a Ctrl-P waits for its Ctrl-Q, stdin is read with a
        // deadline: a lone Ctrl-P is sent once the window has passed.
        if let Some(deadline) = keys.deadline() {
            let left = deadline.saturating_duration_since(Instant::now());
            if !readable(&stdin, left) {
                if let Some(byte) = keys.expire(Instant::now()) {
                    if !send(&[byte]) {
                        return;
                    }
                }
                continue;
            }
        }
        let n = match stdin.read(&mut buf) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if n == 0 {
            if let Some(byte) = keys.release() {
                let _ = send(&[byte]);
            }
            let _ = to_session.shutdown(Shutdown::Write);
            return;
        }
        let (forward, detach) = keys.feed(&buf[..n], Instant::now());
        if !send(&forward) {
            return;
        }
        if detach {
            ending.end(Outcome::Detached);
            return;
        }
    }
}

/// Whether `file` has input within `timeout` (or an error or its end).
fn readable(file: &File, timeout: Duration) -> bool {
    let mut pollfd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Rounded up, so a short wait is not a busy loop.
    let ms =
        libc::c_int::try_from(timeout.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX);
    // SAFETY: poll reads and writes the one pollfd it is given.
    unsafe { libc::poll(&mut pollfd, 1, ms) != 0 }
}

/// The signals: `SIGWINCH` resizes the session's terminal (when this one
/// is a terminal); a stop signal ends the attach.
fn watch_signals(signals: &SignalFd, mut sender: Sender, tty: bool, ending: &Ending) {
    loop {
        let mut pollfd = libc::pollfd {
            fd: signals.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll reads and writes the one pollfd it is given.
        if unsafe { libc::poll(&mut pollfd, 1, -1) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return;
        }
        loop {
            match signals.read() {
                Ok(Some(libc::SIGWINCH)) => {
                    if let Some(size) = stdin_terminal_size().filter(|_| tty) {
                        // Its response is read, and ignored, by
                        // `watch_control`.
                        if sender.send("pty.resize", resize_params(size)).is_err() {
                            return;
                        }
                    }
                }
                Ok(Some(signo)) => {
                    ending.end(Outcome::Signal(signo));
                    return;
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
}

/// The control connection's events: a `pty.detached` there ends the
/// attach; anything else (the responses to resizes, `state`) is left to
/// the stream, which ends when the session or the VM does.
fn watch_control(mut control: Client, ending: &Ending) {
    loop {
        match control.next_message() {
            Ok(Some(Message::Event { name, .. })) if name == "pty.detached" => {
                ending.end(Outcome::Slow);
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return,
        }
    }
}

/// Watches typed input for the detach keys: Ctrl-P, then Ctrl-Q within
/// [`DETACH_WINDOW`]. A Ctrl-P is held back until what follows it shows
/// whether it is one: Ctrl-Q in time detaches and neither key is sent;
/// anything else, or the window passing, sends it after all.
#[derive(Debug, Default)]
struct DetachKeys {
    /// When the held Ctrl-P came.
    held: Option<Instant>,
}

impl DetachKeys {
    /// Feeds `bytes` read at `now`: what to send, and whether they
    /// complete the detach keys (nothing after them is sent).
    fn feed(&mut self, bytes: &[u8], now: Instant) -> (Vec<u8>, bool) {
        let mut send = Vec::with_capacity(bytes.len() + 1);
        for &byte in bytes {
            if let Some(at) = self.held.take() {
                let in_time = now
                    .checked_duration_since(at)
                    .is_some_and(|gap| gap <= DETACH_WINDOW);
                if byte == CTRL_Q && in_time {
                    return (send, true);
                }
                send.push(CTRL_P);
            }
            if byte == CTRL_P {
                self.held = Some(now);
            } else {
                send.push(byte);
            }
        }
        (send, false)
    }

    /// When the held Ctrl-P's window ends.
    fn deadline(&self) -> Option<Instant> {
        self.held.map(|at| at + DETACH_WINDOW)
    }

    /// The held Ctrl-P, to send, once its window has passed at `now`.
    fn expire(&mut self, now: Instant) -> Option<u8> {
        match self.deadline() {
            Some(deadline) if now >= deadline => self.release(),
            _ => None,
        }
    }

    /// The held Ctrl-P, to send now (the input ended).
    fn release(&mut self) -> Option<u8> {
        self.held.take().map(|_| CTRL_P)
    }
}

/// Holds back the end of the stream for as long as it could be the
/// server's `pty.detached` line: only the line at the very end of the
/// stream is the server's; the same bytes anywhere else are the session's.
struct DetachedTail {
    line: Vec<u8>,
    held: Vec<u8>,
}

impl DetachedTail {
    fn new(line: Vec<u8>) -> DetachedTail {
        DetachedTail {
            line,
            held: Vec::new(),
        }
    }

    /// Takes `bytes`; returns what can be written out now.
    fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(bytes);
        let longest = self.line.len().min(self.held.len());
        let keep = (0..=longest)
            .rev()
            .find(|&len| self.line.starts_with(&self.held[self.held.len() - len..]))
            .unwrap_or(0);
        self.held.drain(..self.held.len() - keep).collect()
    }

    /// At the stream's end: what is left to write out, and whether the
    /// stream ended with the line.
    fn finish(self) -> (Vec<u8>, bool) {
        if self.held == self.line {
            (Vec::new(), true)
        } else {
            (self.held, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_p_then_ctrl_q_detaches_and_neither_is_sent() {
        let t0 = Instant::now();
        let mut keys = DetachKeys::default();
        assert_eq!(keys.feed(b"ls\x10\x11rm", t0), (b"ls".to_vec(), true));
        // Across two reads, within the window.
        let mut keys = DetachKeys::default();
        assert_eq!(keys.feed(b"a\x10", t0), (b"a".to_vec(), false));
        assert_eq!(keys.deadline(), Some(t0 + DETACH_WINDOW));
        assert_eq!(
            keys.feed(b"\x11", t0 + Duration::from_millis(999)),
            (Vec::new(), true)
        );
        // Too late: both are sent.
        let mut keys = DetachKeys::default();
        assert_eq!(keys.feed(b"\x10", t0), (Vec::new(), false));
        assert_eq!(
            keys.feed(b"\x11", t0 + Duration::from_millis(1001)),
            (b"\x10\x11".to_vec(), false)
        );
    }

    #[test]
    fn a_ctrl_p_not_followed_by_ctrl_q_is_sent() {
        let t0 = Instant::now();
        let mut keys = DetachKeys::default();
        assert_eq!(keys.feed(b"\x10x", t0), (b"\x10x".to_vec(), false));
        // Two in a row: the first is sent, the second held.
        assert_eq!(keys.feed(b"\x10\x10", t0), (b"\x10".to_vec(), false));
        assert_eq!(keys.feed(b"\x11", t0), (Vec::new(), true));
        // Held until the window passes, then sent alone.
        let mut keys = DetachKeys::default();
        assert_eq!(keys.feed(b"\x10", t0), (Vec::new(), false));
        assert_eq!(keys.expire(t0 + Duration::from_millis(500)), None);
        assert_eq!(keys.expire(t0 + DETACH_WINDOW), Some(CTRL_P));
        assert_eq!(keys.deadline(), None);
        // Or when the input ends.
        assert_eq!(keys.feed(b"\x10", t0), (Vec::new(), false));
        assert_eq!(keys.release(), Some(CTRL_P));
        assert_eq!(keys.release(), None);
    }

    #[test]
    fn only_the_line_at_the_end_of_the_stream_is_the_servers() {
        let line = b"{\"v\":1,\"event\":\"pty.detached\",\"reason\":\"slow\"}\n".to_vec();
        assert_eq!(to_line(&PtyDetached::slow()).unwrap(), line);
        // At the end, in pieces: held back, and not written out.
        let mut tail = DetachedTail::new(line.clone());
        let mut out = tail.push(b"output then ");
        out.extend(tail.push(&line[..10]));
        out.extend(tail.push(&line[10..]));
        assert_eq!(out, b"output then ");
        assert_eq!(tail.finish(), (Vec::new(), true));
        // Followed by more: the session's, written out.
        let mut tail = DetachedTail::new(line.clone());
        let mut out = tail.push(&line);
        out.extend(tail.push(b"more"));
        let (rest, slow) = tail.finish();
        out.extend(rest);
        assert!(!slow);
        assert_eq!(out, [line.as_slice(), b"more"].concat());
        // A start of it at the end: written out at the end.
        let mut tail = DetachedTail::new(line.clone());
        let out = tail.push(b"ab{\"v\":1");
        assert_eq!(out, b"ab");
        assert_eq!(tail.finish(), (b"{\"v\":1".to_vec(), false));
    }
}
