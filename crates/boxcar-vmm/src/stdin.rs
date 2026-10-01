// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// The input flow control follows Firecracker
// (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/devices/legacy/serial.rs (the MutEventSubscriber impl of
// SerialWrapper: read up to the FIFO's free space, drop stdin interest when
// the FIFO is full, take it back on the buffer-ready event, detach on EOF) at
// commit 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text
// referred to above is in LICENSE-BSD-3-Clause. Adapted: the subscriber is
// separate from the device, which it reaches through an Arc<Mutex>; the
// caller registers its descriptors; the Ctrl-] escape and the raw-mode
// terminal guard are boxcar's.

//! Host stdin to the guest's serial console, and the host terminal.
//!
//! When stdin is a TTY and the console goes to stdout, the VMM puts the
//! terminal in raw mode ([`RawModeGuard`]) and forwards what is typed to
//! COM1 ([`StdinSubscriber`]). Ctrl-C then reaches the guest; pressing
//! Ctrl-] twice within a second stops the VM instead.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use event_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

use crate::devices::SerialDevice;
use crate::lifecycle::{StopReason, VmmHandle};

/// Ctrl-], the console escape.
pub const ESCAPE_BYTE: u8 = 0x1d;
/// How close together the two escape presses must be.
pub const ESCAPE_WINDOW: Duration = Duration::from_secs(1);

/// Whether a Ctrl-] at `now` makes a double press with the one at
/// `previous`: there was one, and it was at most [`ESCAPE_WINDOW`] earlier.
pub fn is_double_press(previous: Option<Instant>, now: Instant) -> bool {
    previous
        .and_then(|previous| now.checked_duration_since(previous))
        .is_some_and(|gap| gap <= ESCAPE_WINDOW)
}

/// Watches the input for two Ctrl-] in a row within [`ESCAPE_WINDOW`].
#[derive(Debug, Default)]
pub struct EscapeDetector {
    /// When the last byte, a Ctrl-], arrived; `None` after any other byte.
    last: Option<Instant>,
}

impl EscapeDetector {
    /// Feeds `bytes` read at `now`. Returns true when they complete a double
    /// press; the detector then starts over.
    pub fn feed(&mut self, bytes: &[u8], now: Instant) -> bool {
        for &byte in bytes {
            if byte != ESCAPE_BYTE {
                self.last = None;
            } else if is_double_press(self.last, now) {
                self.last = None;
                return true;
            } else {
                self.last = Some(now);
            }
        }
        false
    }
}

/// Whether stdin is a terminal.
pub fn stdin_is_tty() -> bool {
    // SAFETY: isatty has no preconditions.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Stdin as a [`Terminal`], without taking std's stdin lock (the panic hook
/// must not wait on it).
struct StdinTty;

// SAFETY: STDIN_FILENO is open for the life of the process.
unsafe impl Terminal for StdinTty {
    fn tty_fd(&self) -> RawFd {
        libc::STDIN_FILENO
    }
}

/// Set while the terminal is in raw mode, so exactly one of the guard and
/// the panic hook restores it.
static RAW_MODE: AtomicBool = AtomicBool::new(false);

fn restore_terminal() {
    if RAW_MODE.swap(false, Ordering::SeqCst) {
        if let Err(error) = StdinTty.set_canon_mode() {
            tracing::warn!("cannot restore the terminal: {error}");
        }
    }
}

/// Restores the terminal before the previous hook prints the panic.
fn install_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
    });
}

/// The host terminal in raw mode (no line editing, no echo, no signals from
/// Ctrl-C). Dropping it restores canonical mode; so does a panic anywhere
/// in the process.
pub struct RawModeGuard {
    _private: (),
}

impl RawModeGuard {
    /// Puts stdin's terminal in raw mode. `None` when stdin is not a TTY.
    pub fn enter() -> io::Result<Option<RawModeGuard>> {
        if !stdin_is_tty() {
            return Ok(None);
        }
        install_panic_hook();
        StdinTty
            .set_raw_mode()
            .map_err(|error| io::Error::from_raw_os_error(error.errno()))?;
        RAW_MODE.store(true, Ordering::SeqCst);
        Ok(Some(RawModeGuard { _private: () }))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Bytes read from stdin at a time: the whole 16550A receive FIFO.
const READ_CHUNK: usize = 64;

/// Forwards stdin to COM1 on the main loop. Reads no more than the FIFO has
/// room for; when it is full, stops watching stdin until the guest has read
/// the FIFO empty (the serial's buffer-ready event).
pub(crate) struct StdinSubscriber {
    serial: Arc<Mutex<SerialDevice>>,
    buffer_ready: EventFd,
    /// Whether stdin is in the epoll set.
    watching: bool,
    /// Stdin reached EOF or failed; it is never watched again.
    closed: bool,
    escape: EscapeDetector,
    handle: VmmHandle,
}

impl StdinSubscriber {
    pub(crate) fn new(serial: Arc<Mutex<SerialDevice>>, handle: VmmHandle) -> io::Result<Self> {
        let buffer_ready = lock(&serial).buffer_ready_evt().try_clone()?;
        Ok(StdinSubscriber {
            serial,
            buffer_ready,
            watching: true,
            closed: false,
            escape: EscapeDetector::default(),
            handle,
        })
    }

    /// Stdin and the buffer-ready eventfd. The caller registers both.
    pub(crate) fn fds(&self) -> [RawFd; 2] {
        [libc::STDIN_FILENO, self.buffer_ready.as_raw_fd()]
    }

    fn unwatch(&mut self, ops: &mut EventOps) {
        if self.watching {
            self.watching = false;
            if let Err(error) = ops.remove(Events::new_raw(libc::STDIN_FILENO, EventSet::IN)) {
                tracing::warn!("cannot stop watching stdin: {error}");
            }
        }
    }

    fn watch(&mut self, ops: &mut EventOps) {
        if self.watching || self.closed {
            return;
        }
        match ops.add(Events::new_raw(libc::STDIN_FILENO, EventSet::IN)) {
            Ok(()) | Err(event_manager::Error::FdAlreadyRegistered) => self.watching = true,
            Err(error) => {
                tracing::warn!("cannot watch stdin again: {error}");
                self.closed = true;
            }
        }
    }

    fn close(&mut self, ops: &mut EventOps) {
        self.unwatch(ops);
        self.closed = true;
    }

    fn on_stdin(&mut self, ops: &mut EventOps) {
        let room = lock(&self.serial).fifo_capacity().min(READ_CHUNK);
        if room == 0 {
            self.unwatch(ops);
            return;
        }
        let mut buf = [0u8; READ_CHUNK];
        // SAFETY: reads at most `room` bytes into `buf`, which holds more.
        let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), room) };
        let count = match usize::try_from(n) {
            Ok(0) => {
                tracing::debug!("stdin reached EOF; no more console input");
                self.close(ops);
                return;
            }
            Ok(count) => count,
            Err(_) => {
                let error = io::Error::last_os_error();
                if !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    tracing::warn!("cannot read stdin, no more console input: {error}");
                    self.close(ops);
                }
                return;
            }
        };
        let bytes = &buf[..count];
        if self.escape.feed(bytes, Instant::now()) {
            self.handle.request_stop(StopReason::ConsoleEscape);
        }
        let full = {
            let mut serial = lock(&self.serial);
            serial.enqueue(bytes);
            serial.fifo_capacity() == 0
        };
        if full {
            self.unwatch(ops);
        }
    }
}

impl MutEventSubscriber for StdinSubscriber {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        if events.fd() == self.buffer_ready.as_raw_fd() {
            let _ = self.buffer_ready.read();
            self.watch(ops);
        } else if events.fd() == libc::STDIN_FILENO {
            self.on_stdin(ops);
        }
    }

    /// Registration happens in the caller; see [`StdinSubscriber::fds`].
    fn init(&mut self, _ops: &mut EventOps) {}
}

fn lock(serial: &Mutex<SerialDevice>) -> std::sync::MutexGuard<'_, SerialDevice> {
    serial.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn double_press_needs_a_previous_press_within_one_second() {
        let t0 = Instant::now();
        assert!(!is_double_press(None, t0));
        assert!(is_double_press(Some(t0), t0));
        assert!(is_double_press(Some(t0), t0 + 300 * MS));
        assert!(is_double_press(Some(t0), t0 + ESCAPE_WINDOW));
        assert!(!is_double_press(Some(t0), t0 + ESCAPE_WINDOW + MS));
        // A clock that went backwards is not a double press.
        assert!(!is_double_press(Some(t0 + 10 * MS), t0));
    }

    #[test]
    fn detector_fires_on_the_second_ctrl_bracket_in_a_row() {
        let t0 = Instant::now();
        let mut detector = EscapeDetector::default();
        assert!(!detector.feed(&[ESCAPE_BYTE], t0));
        assert!(detector.feed(&[ESCAPE_BYTE], t0 + 500 * MS));

        // It starts over after firing.
        assert!(!detector.feed(&[ESCAPE_BYTE], t0 + 600 * MS));
        assert!(detector.feed(&[ESCAPE_BYTE], t0 + 700 * MS));

        // Both presses in one read count too.
        let mut detector = EscapeDetector::default();
        assert!(detector.feed(&[b'a', ESCAPE_BYTE, ESCAPE_BYTE], t0));
    }

    #[test]
    fn detector_ignores_slow_or_interrupted_presses() {
        let t0 = Instant::now();
        let mut detector = EscapeDetector::default();
        assert!(!detector.feed(&[ESCAPE_BYTE], t0));
        assert!(!detector.feed(&[ESCAPE_BYTE], t0 + 1500 * MS));
        // That second press starts a new window.
        assert!(detector.feed(&[ESCAPE_BYTE], t0 + 2000 * MS));

        // Another key in between breaks the pair.
        let mut detector = EscapeDetector::default();
        assert!(!detector.feed(&[ESCAPE_BYTE], t0));
        assert!(!detector.feed(b"x", t0 + 100 * MS));
        assert!(!detector.feed(&[ESCAPE_BYTE], t0 + 200 * MS));
        assert!(!detector.feed(b"ls\r", t0 + 300 * MS));
    }
}
