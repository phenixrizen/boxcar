// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`'s stdin to the session: the input of its own read-write
//! client of the hub ([`forward`]).
//!
//! What is read goes to the session as it is read, waiting for room in the
//! hub's input queue ([`Input::send_all`]): piped input is never dropped.
//! From a terminal (which `boxcar run` puts in raw mode, as M1's console
//! does) Ctrl-] twice within a second stops the VM instead, as on the
//! console (the run exits 130), and the escape does not reach the session;
//! from a pipe or a file, its end becomes end-of-file characters (`^D`, two
//! when the input did not end a line), so a shell reading it ends.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use super::Input;
use crate::lifecycle::{StopReason, VmmHandle};
use crate::stdin::{stdin_is_tty, EscapeDetector};

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
}

impl LocalInput {
    /// The process's stdin, read through a descriptor of its own (std's
    /// lock and buffer stay out of it).
    pub fn stdin() -> io::Result<LocalInput> {
        let fd = io::stdin().as_fd().try_clone_to_owned()?;
        Ok(LocalInput {
            reader: Box::new(File::from(fd)),
            tty: stdin_is_tty(),
        })
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
    let mut escape = EscapeDetector::default();
    let mut last = None;
    let mut buf = vec![0u8; CHUNK];
    loop {
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
            Err(_) => return,
        };
        let bytes = &buf[..n];
        if input.tty && escape.feed(bytes, Instant::now()) {
            handle.request_stop(StopReason::ConsoleEscape);
            return;
        }
        if to.send_all(bytes).is_err() {
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
        let local = LocalInput {
            reader: Box::new(Cursor::new(b"echo hi\nexit".to_vec())),
            tty: false,
        };
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
        let local = LocalInput {
            reader: Box::new(Cursor::new(typed.clone())),
            tty: false,
        };
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
        let local = LocalInput {
            reader: Box::new(Typed(vec![b"ls\r", b"\x1d\x1d", b"after"])),
            tty: true,
        };
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
}
