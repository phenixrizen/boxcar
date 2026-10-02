// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`'s stdin to the session: the input of its own read-write
//! client of the hub ([`forward`]).
//!
//! From a pipe or a file, what is read goes to the session as it is read,
//! waiting for room in the hub's input queue ([`Input::send_all`]): piped
//! input is never dropped; its end becomes end-of-file characters (`^D`,
//! two when the input did not end a line), so a shell reading it ends.
//!
//! From a terminal (which `boxcar run` puts in raw mode, as M1's console
//! does) each read is looked at for the escape first: Ctrl-] twice within a
//! second stops the VM instead, as on the console (the run exits 130), and
//! the escape does not reach the session. Then it is queued without
//! waiting ([`Input::send`]): what the queue has no room for (a session
//! that reads nothing, a large paste) is dropped and counted, so that the
//! reads, and the escape, never stop.
//!
//! A terminal is read only while `boxcar run` is in its foreground process
//! group. The thread blocks `SIGTTIN` and `SIGTTOU` for itself, waits for
//! input in short steps, and looks again at the foreground before each
//! read. It does not end when the process is in the background (a run
//! started there, or a job the shell moved there): it waits, reading
//! nothing, so that it never takes input meant for the shell nor is stopped
//! by `SIGTTIN`, and it goes on when `fg` brings the process back (the
//! terminal is made raw again by [`RawModeGuard`](crate::stdin::RawModeGuard)
//! and the job-control thread, see [`start_job_control`]). The session goes
//! on meanwhile; its output still goes to stdout.
//!
//! [`start_job_control`]: crate::stdin::start_job_control

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::Input;
use crate::lifecycle::{StopReason, VmmHandle};
use crate::stdin::{block_job_control_signals, is_foreground, stdin_is_tty, EscapeDetector};

/// How long the thread waits for terminal input before it looks again at
/// whether the process is still in the foreground.
const FOREGROUND_STEP: Duration = Duration::from_millis(200);

/// Bytes read at a time.
const CHUNK: usize = 16 * 1024;

/// End-of-file, as a terminal in canonical mode reads it (`VEOF`).
const EOF_CHAR: u8 = 0x04;

/// What goes to the session.
pub struct LocalInput {
    /// Read until its end.
    pub reader: Box<dyn Read + Send>,
    /// It is a terminal: watch for the escape, and send nothing at its end.
    pub tty: bool,
    /// The terminal's descriptor, to wait on and to look at the foreground
    /// of; `None` for a reader that is not one.
    terminal: Option<RawFd>,
}

impl LocalInput {
    /// What `reader` gives, a terminal's when `tty` (not one with a
    /// foreground: a test's).
    pub fn new(reader: Box<dyn Read + Send>, tty: bool) -> LocalInput {
        LocalInput {
            reader,
            tty,
            terminal: None,
        }
    }

    /// The process's stdin, read through a descriptor of its own (std's
    /// lock and buffer stay out of it).
    pub fn stdin() -> io::Result<LocalInput> {
        let file = File::from(io::stdin().as_fd().try_clone_to_owned()?);
        let tty = stdin_is_tty();
        let terminal = tty.then(|| file.as_raw_fd());
        Ok(LocalInput {
            reader: Box::new(file),
            tty,
            terminal,
        })
    }

    /// Waits, a step at a time, until the terminal has input and this
    /// process is in its foreground; false only when the terminal cannot
    /// be waited on. In the background it only sleeps a step and looks
    /// again: the terminal is the shell's, and polling it would return at
    /// once whenever the user types for the shell.
    fn wait_in_foreground(&self) -> bool {
        let Some(fd) = self.terminal else {
            return true;
        };
        loop {
            if !is_foreground(fd) {
                thread::sleep(FOREGROUND_STEP);
                continue;
            }
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = libc::c_int::try_from(FOREGROUND_STEP.as_millis()).unwrap_or(libc::c_int::MAX);
            // SAFETY: poll reads and writes the one pollfd it is given.
            match unsafe { libc::poll(&mut pollfd, 1, ms) } {
                0 => {}
                n if n > 0 => {
                    if is_foreground(fd) {
                        return true;
                    }
                }
                _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                _ => return false,
            }
        }
    }
}

/// Starts forwarding `input` to the session through `to`; `handle` stops
/// the VM on the escape. The thread ends at the input's end, the escape, or
/// when the session takes no more.
pub fn forward(input: LocalInput, to: Input, handle: VmmHandle) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("pty-stdin".into())
        .spawn(move || forward_all(input, &to, &handle))
}

fn forward_all(mut input: LocalInput, to: &Input, handle: &VmmHandle) {
    // A read from the background then fails (EIO) rather than stopping the
    // process; only this thread's mask changes.
    let _ = block_job_control_signals();
    let mut escape = EscapeDetector::default();
    let mut last = None;
    let mut buf = vec![0u8; CHUNK];
    loop {
        if !input.wait_in_foreground() {
            return;
        }
        let n = match input.reader.read(&mut buf) {
            Ok(0) => {
                if !input.tty {
                    let eof: &[u8] = match last {
                        Some(b'\n') | None => &[EOF_CHAR],
                        Some(_) => &[EOF_CHAR, EOF_CHAR],
                    };
                    let _ = to.send_all(eof);
                }
                return;
            }
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // The process moved to the background since the look, and the
            // read failed instead of stopping it: wait for the foreground
            // again. (A hung-up terminal fails the same way, but from the
            // foreground: that is the end.)
            Err(error)
                if error.raw_os_error() == Some(libc::EIO)
                    && input.terminal.is_some_and(|fd| !is_foreground(fd)) =>
            {
                continue
            }
            Err(_) => return,
        };
        let bytes = &buf[..n];
        let sent = if input.tty {
            if escape.feed(bytes, Instant::now()) {
                handle.request_stop(StopReason::ConsoleEscape);
                return;
            }
            to.send(bytes).map(drop)
        } else {
            to.send_all(bytes)
        };
        if sent.is_err() {
            return;
        }
        last = bytes.last().copied();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::lifecycle::VmState;
    use crate::pty::testing::{pattern, Fixture, LIMIT};
    use crate::pty::Mode;

    /// Piped input goes to the session as it is, then an end-of-file
    /// character, so that a shell reading it ends.
    #[test]
    fn piped_input_reaches_the_session_then_an_eof_character() {
        let fixture = Fixture::new();
        let (_, _, input) = fixture.hub.attach(Mode::Rw, 0);
        let local = LocalInput::new(Box::new(Cursor::new(b"echo hi\nexit".to_vec())), false);
        forward(local, input.unwrap(), fixture.handle.clone()).unwrap();
        let mut guest = fixture.guest();
        let want = b"echo hi\nexit\x04\x04";
        let mut got = vec![0u8; want.len()];
        guest.read_exact(&mut got).unwrap();
        assert_eq!(got, want);
    }

    /// Piped input waits for room in the hub's queue: nothing is dropped,
    /// however much there is.
    #[test]
    fn piped_input_over_the_queue_waits_for_room() {
        let fixture = Fixture::new();
        let (_, _, input) = fixture.hub.attach(Mode::Rw, 0);
        let mut typed = pattern(300 * 1024);
        typed.push(b'\n');
        let local = LocalInput::new(Box::new(Cursor::new(typed.clone())), false);
        forward(local, input.unwrap(), fixture.handle.clone()).unwrap();
        // Only once the queue is full does the terminal open.
        std::thread::sleep(Duration::from_millis(100));
        let mut guest = fixture.guest();
        let mut got = vec![0u8; typed.len() + 1];
        guest.read_exact(&mut got).unwrap();
        assert!(got[..typed.len()] == typed[..], "not every byte, in order");
        assert_eq!(got[typed.len()], 0x04);
        assert_eq!(fixture.hub.input_dropped(), 0);
    }

    /// From a terminal, Ctrl-] twice stops the VM, as on the console, and
    /// does not reach the session.
    #[test]
    fn a_double_escape_from_a_terminal_stops_the_vm() {
        let fixture = Fixture::new();
        // Typed in reads: a line, then the escape, then more.
        struct Typed(Vec<&'static [u8]>);
        impl Read for Typed {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    // A terminal that stays open: nothing more, for a while.
                    std::thread::sleep(Duration::from_secs(1));
                    return Ok(0);
                }
                let next = self.0.remove(0);
                buf[..next.len()].copy_from_slice(next);
                Ok(next.len())
            }
        }
        let (_, _, input) = fixture.hub.attach(Mode::Rw, 0);
        let local = LocalInput::new(Box::new(Typed(vec![b"ls\r", b"\x1d\x1d", b"after"])), true);
        let mut guest = fixture.guest();
        forward(local, input.unwrap(), fixture.handle.clone()).unwrap();
        // What came before the escape reached the session; the escape did
        // not.
        let mut got = [0u8; 3];
        guest.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ls\r");
        let deadline = Instant::now() + LIMIT;
        while fixture.handle.state() != VmState::Stopping {
            assert!(Instant::now() < deadline, "the escape did not stop the VM");
            std::thread::sleep(Duration::from_millis(5));
        }
        // The input has ended: nothing more reaches the session.
        guest
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut more = [0u8; 1];
        assert!(guest.read(&mut more).is_err(), "{more:?}");
    }

    /// From a terminal, the escape is seen before anything is queued, and
    /// input the queue has no room for is dropped (counted), not waited
    /// on: a session that reads nothing cannot take the escape away, even
    /// after a 1 MiB paste.
    #[test]
    fn a_paste_the_session_does_not_take_cannot_hold_back_the_escape() {
        let fixture = Fixture::new();
        // Connected, and never reading.
        let _guest = fixture.guest();
        struct Pasted(Vec<Vec<u8>>);
        impl Read for Pasted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    std::thread::sleep(Duration::from_secs(1));
                    return Ok(0);
                }
                let next = self.0.remove(0);
                buf[..next.len()].copy_from_slice(&next);
                Ok(next.len())
            }
        }
        let mut reads: Vec<Vec<u8>> = pattern(1 << 20)
            .chunks(16 * 1024)
            .map(|chunk| {
                chunk
                    .iter()
                    .map(|&b| if b == 0x1d { b'.' } else { b })
                    .collect()
            })
            .collect();
        reads.push(b"\x1d\x1d".to_vec());
        let (_, _, input) = fixture.hub.attach(Mode::Rw, 0);
        let local = LocalInput::new(Box::new(Pasted(reads)), true);
        forward(local, input.unwrap(), fixture.handle.clone()).unwrap();
        let deadline = Instant::now() + LIMIT;
        while fixture.handle.state() != VmState::Stopping {
            assert!(
                Instant::now() < deadline,
                "the escape was held back behind the paste"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(fixture.hub.input_dropped() > 0);
    }
}
