// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// The input flow control began as Firecracker's
// (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/devices/legacy/serial.rs (the MutEventSubscriber impl of
// SerialWrapper: queue stdin for the FIFO, take the buffer-ready event when
// the guest has read it empty, detach on EOF) at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: the subscriber is separate from
// the device, which it reaches through an Arc<Mutex>; the caller registers
// its descriptors; stdin is never unwatched, so that what does not fit the
// FIFO waits in a holding buffer instead of stopping the reads; the Ctrl-]
// escape and the raw-mode terminal guard are boxcar's.

//! Host stdin to the guest's serial console, and the host terminal.
//!
//! When stdin is a TTY and the console goes to stdout, the VMM puts the
//! terminal in raw mode ([`RawModeGuard`]) and forwards what is typed to
//! COM1 ([`StdinSubscriber`]). Ctrl-C then reaches the guest; pressing
//! Ctrl-] twice within a second stops the VM instead, whatever the guest is
//! doing: the escape is detected on every byte read, before the serial
//! FIFO is looked at, so a guest that has stopped reading its console
//! cannot take the escape away.
//!
//! A paste of more than about 4 KiB into the console loses its oldest bytes
//! when the guest reads slower than the host types, by design (the M2
//! decision: input waits in a 4 KiB holding buffer behind the 64-byte
//! FIFO, and the newest wins). The count of dropped bytes goes into
//! `vmm.stop` as `stdin_dropped_bytes`; it is never logged, because a log
//! write to a stalled stderr would park the main loop that must hear the
//! escape.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::panic;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use event_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::EventFd;

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

/// The terminal's settings from before raw mode: there while the terminal
/// is in raw mode, so that exactly one of the guard and the panic hook
/// restores them.
static SAVED: Mutex<Option<libc::termios>> = Mutex::new(None);

/// Stdin's terminal settings (std's stdin lock stays out of it: the panic
/// hook must not wait on it).
fn stdin_termios() -> io::Result<libc::termios> {
    // SAFETY: termios is plain data; all zeroes is valid.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes one termios into `termios`, alive for the
    // call.
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(termios)
}

fn set_stdin_termios(termios: &libc::termios) -> io::Result<()> {
    // SAFETY: tcsetattr reads one termios from `termios`.
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `termios` in raw mode, as [`RawModeGuard`] sets it: no line editing, no
/// echo, no signals from Ctrl-C or Ctrl-Z and no flow control from Ctrl-S
/// or Ctrl-Q, so that every key reaches the reader (`boxcar attach`'s
/// Ctrl-Q, and a guest program's Ctrl-S); output processing stays.
pub fn raw_termios(mut termios: libc::termios) -> libc::termios {
    termios.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
    termios.c_iflag &= !libc::IXON;
    termios
}

fn restore_terminal() {
    let saved = SAVED.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(saved) = saved {
        if let Err(error) = set_stdin_termios(&saved) {
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

/// The host terminal in raw mode ([`raw_termios`]: no line editing, no
/// echo, no signals from Ctrl-C, no flow control). Dropping it restores the
/// settings the terminal had; so does a panic anywhere in the process.
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
        let mut saved = SAVED.lock().unwrap_or_else(PoisonError::into_inner);
        let before = match *saved {
            // In raw mode already: what it had before that is restored.
            Some(before) => before,
            None => stdin_termios()?,
        };
        set_stdin_termios(&raw_termios(before))?;
        *saved = Some(before);
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

/// How much input waits for room in the receive FIFO.
const HOLD_CAP: usize = 4096;

/// Forwards stdin to COM1 on the main loop.
///
/// Every byte read is first run through the [`EscapeDetector`]; a double
/// Ctrl-] stops the VM and the chunk is dropped. Only then is the input
/// queued for the guest: what the receive FIFO has room for goes in, the
/// rest waits in a [`HOLD_CAP`]-byte holding buffer that the serial's
/// buffer-ready event (the guest has read the FIFO empty) drains. Stdin
/// stays watched throughout: a guest that has stopped reading, so that the
/// FIFO is full, must not make Ctrl-] Ctrl-] stop working, which is how a
/// wedged guest is stopped. When the holding buffer is full too, the oldest
/// held bytes are dropped for the newest, and counted in a counter the VMM
/// reads for `vmm.stop`. The subscriber logs nothing about input: it runs on
/// the main loop, which a blocked write to a stalled stderr would park.
pub(crate) struct StdinSubscriber {
    serial: Arc<Mutex<SerialDevice>>,
    buffer_ready: EventFd,
    /// Stdin reached EOF or failed; it is never watched again.
    closed: bool,
    escape: EscapeDetector,
    handle: VmmHandle,
    /// Input the FIFO had no room for, oldest first.
    held: VecDeque<u8>,
    /// Input bytes dropped from `held` so far; shared with the VMM.
    dropped_input: Arc<AtomicU64>,
}

impl StdinSubscriber {
    /// A subscriber for `serial` that adds the bytes it has to drop to
    /// `dropped_input`.
    pub(crate) fn new(
        serial: Arc<Mutex<SerialDevice>>,
        handle: VmmHandle,
        dropped_input: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        let buffer_ready = lock(&serial).buffer_ready_evt().try_clone()?;
        Ok(StdinSubscriber {
            serial,
            buffer_ready,
            closed: false,
            escape: EscapeDetector::default(),
            handle,
            held: VecDeque::with_capacity(HOLD_CAP),
            dropped_input,
        })
    }

    /// Stdin and the buffer-ready eventfd. The caller registers both.
    pub(crate) fn fds(&self) -> [RawFd; 2] {
        [libc::STDIN_FILENO, self.buffer_ready.as_raw_fd()]
    }

    fn close(&mut self, ops: &mut EventOps) {
        if !self.closed {
            self.closed = true;
            if let Err(error) = ops.remove(Events::new_raw(libc::STDIN_FILENO, EventSet::IN)) {
                tracing::warn!("cannot stop watching stdin: {error}");
            }
        }
    }

    /// What was typed at `now`: the escape detector sees it before anything
    /// else does; then it goes to the guest, or waits for room.
    fn on_input(&mut self, bytes: &[u8], now: Instant) {
        if self.escape.feed(bytes, now) {
            self.handle.request_stop(StopReason::ConsoleEscape);
            return;
        }
        let taken = {
            let mut serial = lock(&self.serial);
            // Older input first: new input goes in only behind an empty
            // holding buffer.
            drain_held(&mut self.held, &mut serial);
            if self.held.is_empty() {
                serial.enqueue(bytes)
            } else {
                0
            }
        };
        self.hold(&bytes[taken..]);
    }

    /// The guest has read the receive FIFO empty: the held input goes in.
    fn on_buffer_ready(&mut self) {
        drain_held(&mut self.held, &mut lock(&self.serial));
    }

    /// Appends `bytes` to the holding buffer, dropping the oldest held
    /// bytes (or the front of `bytes`) beyond [`HOLD_CAP`].
    fn hold(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let keep = bytes.len().min(HOLD_CAP);
        let from_bytes = bytes.len() - keep;
        let from_held = (self.held.len() + keep).saturating_sub(HOLD_CAP);
        self.held.drain(..from_held);
        self.held.extend(&bytes[from_bytes..]);
        let dropped = from_bytes + from_held;
        if dropped > 0 {
            // Counted, not logged: see the type's docs. A plain add cannot
            // wrap in the life of a process (2^64 bytes of typing).
            self.dropped_input.fetch_add(
                u64::try_from(dropped).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }

    fn on_stdin(&mut self, ops: &mut EventOps) {
        if self.closed {
            return;
        }
        let mut buf = [0u8; READ_CHUNK];
        // SAFETY: reads at most `buf.len()` bytes into `buf`.
        let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(n) {
            Ok(0) => {
                tracing::debug!("stdin reached EOF; no more console input");
                self.close(ops);
            }
            Ok(count) => self.on_input(&buf[..count], Instant::now()),
            Err(_) => {
                let error = io::Error::last_os_error();
                if !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    tracing::warn!("cannot read stdin, no more console input: {error}");
                    self.close(ops);
                }
            }
        }
    }
}

impl MutEventSubscriber for StdinSubscriber {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        if events.fd() == self.buffer_ready.as_raw_fd() {
            let _ = self.buffer_ready.read();
            self.on_buffer_ready();
        } else if events.fd() == libc::STDIN_FILENO {
            self.on_stdin(ops);
        }
    }

    /// Registration happens in the caller; see [`StdinSubscriber::fds`].
    fn init(&mut self, _ops: &mut EventOps) {}
}

/// Moves as much of `held` into the FIFO as fits, oldest first.
fn drain_held(held: &mut VecDeque<u8>, serial: &mut SerialDevice) {
    while !held.is_empty() {
        let room = serial.fifo_capacity();
        if room == 0 {
            return;
        }
        let (front, _) = held.as_slices();
        let taken = serial.enqueue(&front[..front.len().min(room)]);
        if taken == 0 {
            return;
        }
        held.drain(..taken);
    }
}

fn lock(serial: &Mutex<SerialDevice>) -> std::sync::MutexGuard<'_, SerialDevice> {
    serial.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// Raw mode leaves nothing to the line discipline that a reader needs:
    /// no line editing, echo or signals, and Ctrl-S and Ctrl-Q are input,
    /// not flow control; everything else, output processing included, is
    /// as it was.
    #[test]
    fn raw_mode_lets_every_key_through_and_keeps_the_rest() {
        // SAFETY: termios is plain data; all zeroes is valid.
        let mut cooked: libc::termios = unsafe { std::mem::zeroed() };
        cooked.c_iflag = libc::ICRNL | libc::IXON | libc::IUTF8;
        cooked.c_oflag = libc::OPOST | libc::ONLCR;
        cooked.c_cflag = libc::CS8 | libc::CREAD;
        cooked.c_lflag = libc::ISIG | libc::ICANON | libc::ECHO | libc::ECHOE | libc::IEXTEN;
        let raw = raw_termios(cooked);
        assert_eq!(raw.c_iflag, libc::ICRNL | libc::IUTF8);
        assert_eq!(raw.c_oflag, cooked.c_oflag);
        assert_eq!(raw.c_cflag, cooked.c_cflag);
        assert_eq!(raw.c_lflag, libc::ECHOE | libc::IEXTEN);
    }

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

    use boxcar_virtio::bus::BusDevice;

    use crate::console::ConsoleWriter;
    use crate::lifecycle::{test_handle, VmState};

    /// A subscriber on a UART whose console goes nowhere, with no real stdin.
    struct Rig {
        subscriber: StdinSubscriber,
        dropped: Arc<AtomicU64>,
        serial: Arc<Mutex<SerialDevice>>,
        handle: VmmHandle,
        _audit: boxcar_audit::WriterHandle,
        _dir: tempfile::TempDir,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let (handle, audit) = test_handle(dir.path());
        let (sink, _writer) = ConsoleWriter::spawn_with(std::io::sink()).unwrap();
        let serial = Arc::new(Mutex::new(SerialDevice::new(sink).unwrap()));
        let dropped = Arc::new(AtomicU64::new(0));
        let subscriber =
            StdinSubscriber::new(serial.clone(), handle.clone(), dropped.clone()).unwrap();
        Rig {
            subscriber,
            dropped,
            serial,
            handle,
            _audit: audit,
            _dir: dir,
        }
    }

    impl Rig {
        /// Fills the receive FIFO, as a guest that has stopped reading does.
        fn fill_fifo(&self) {
            let mut serial = lock(&self.serial);
            let room = serial.fifo_capacity();
            assert_eq!(serial.enqueue(&vec![b'.'; room]), room);
            assert_eq!(serial.fifo_capacity(), 0);
        }

        /// The guest reads `count` bytes of the receive FIFO.
        fn guest_reads(&self, count: usize) -> Vec<u8> {
            let mut serial = lock(&self.serial);
            (0..count)
                .map(|_| {
                    let mut byte = [0u8];
                    serial.read(0, &mut byte);
                    byte[0]
                })
                .collect()
        }
    }

    #[test]
    fn escape_is_detected_while_the_fifo_is_full() {
        // Two Ctrl-] in separate reads, 200 ms apart.
        let mut rig = rig();
        rig.fill_fifo();
        let t0 = Instant::now();
        rig.subscriber.on_input(&[ESCAPE_BYTE], t0);
        assert_eq!(rig.handle.state(), VmState::Booting);
        rig.subscriber.on_input(&[ESCAPE_BYTE], t0 + 200 * MS);
        assert_eq!(rig.handle.state(), VmState::Stopping);

        // Both in one read.
        let mut rig = rig_with_full_fifo();
        rig.subscriber.on_input(&[ESCAPE_BYTE, ESCAPE_BYTE], t0);
        assert_eq!(rig.handle.state(), VmState::Stopping);
    }

    fn rig_with_full_fifo() -> Rig {
        let rig = rig();
        rig.fill_fifo();
        rig
    }

    #[test]
    fn escape_is_detected_while_the_holding_buffer_is_full_and_dropping() {
        let mut rig = rig_with_full_fifo();
        let t0 = Instant::now();
        // Far more than the FIFO and the holding buffer hold.
        for _ in 0..(HOLD_CAP / READ_CHUNK) * 3 {
            rig.subscriber.on_input(&[b'x'; READ_CHUNK], t0);
        }
        assert!(rig.dropped.load(Ordering::Relaxed) > 0);
        assert_eq!(rig.handle.state(), VmState::Booting);
        rig.subscriber.on_input(&[ESCAPE_BYTE], t0 + 10 * MS);
        rig.subscriber.on_input(&[ESCAPE_BYTE], t0 + 20 * MS);
        assert_eq!(rig.handle.state(), VmState::Stopping);
    }

    #[test]
    fn the_chunk_that_completes_the_escape_is_not_forwarded() {
        let mut rig = rig();
        let t0 = Instant::now();
        rig.subscriber.on_input(&[ESCAPE_BYTE], t0);
        rig.subscriber.on_input(b"a\x1d\x1db", t0 + 10 * MS);
        assert_eq!(rig.handle.state(), VmState::Stopping);
        // The first press went to the guest like any key; the second chunk,
        // which fired the detector, did not.
        assert_eq!(rig.guest_reads(1), [ESCAPE_BYTE]);
        assert_eq!(lock(&rig.serial).fifo_capacity(), 64);
    }

    #[test]
    fn bytes_the_fifo_cannot_take_wait_in_order_for_the_guest_to_read() {
        let mut rig = rig();
        let t0 = Instant::now();
        // 60 bytes fit; of 10 more, 4 go in and 6 are held.
        rig.subscriber.on_input(&[b'a'; 60], t0);
        rig.subscriber.on_input(b"0123456789", t0);
        assert_eq!(lock(&rig.serial).fifo_capacity(), 0);
        assert_eq!(rig.subscriber.held.len(), 6);
        // Later input queues behind them.
        rig.subscriber.on_input(b"XY", t0);
        assert_eq!(rig.subscriber.held.len(), 8);

        // The guest reads the FIFO empty; the buffer-ready event drains the
        // holding buffer, in order.
        assert_eq!(rig.guest_reads(64), [&[b'a'; 60][..], b"0123"].concat());
        let event = lock(&rig.serial).buffer_ready_evt().try_clone().unwrap();
        assert!(event.read().is_ok());
        rig.subscriber.on_buffer_ready();
        assert!(rig.subscriber.held.is_empty());
        assert_eq!(rig.guest_reads(8), b"456789XY");
        assert_eq!(rig.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn held_bytes_go_in_ahead_of_new_input_once_the_fifo_has_room() {
        let mut rig = rig();
        let t0 = Instant::now();
        rig.subscriber.on_input(&[b'a'; 60], t0);
        rig.subscriber.on_input(b"0123456789", t0);
        assert_eq!(rig.subscriber.held.len(), 6);

        // The guest reads some, but not all: no buffer-ready event yet.
        assert_eq!(rig.guest_reads(10), [b'a'; 10]);
        rig.subscriber.on_input(b"XY", t0);
        assert!(rig.subscriber.held.is_empty());
        assert_eq!(rig.guest_reads(54), [&[b'a'; 50][..], b"0123"].concat());
        assert_eq!(rig.guest_reads(8), b"456789XY");
    }

    #[test]
    fn the_holding_buffer_drops_its_oldest_bytes_and_counts_them() {
        let mut rig = rig_with_full_fifo();
        let t0 = Instant::now();
        let input: Vec<u8> = (0..HOLD_CAP + 100).map(|i| (i % 200) as u8 + 1).collect();
        for chunk in input.chunks(READ_CHUNK) {
            rig.subscriber.on_input(chunk, t0);
        }
        assert_eq!(rig.subscriber.held.len(), HOLD_CAP);
        assert_eq!(rig.dropped.load(Ordering::Relaxed), 100);
        // What is kept is the newest input.
        let kept: Vec<u8> = rig.subscriber.held.iter().copied().collect();
        assert_eq!(kept, input[100..]);

        // The guest reads the FIFO empty and gets the held bytes after the
        // 64 that filled it.
        let _ = rig.guest_reads(64);
        rig.subscriber.on_buffer_ready();
        assert_eq!(rig.guest_reads(64), input[100..164]);
        assert_eq!(rig.subscriber.held.len(), HOLD_CAP - 64);
    }
}
