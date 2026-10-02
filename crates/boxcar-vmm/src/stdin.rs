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
//! COM1 (`StdinSubscriber`). Ctrl-C then reaches the guest; pressing
//! Ctrl-] twice within a second stops the VM instead, whatever the guest is
//! doing: the escape is detected on every byte read, before the serial
//! FIFO is looked at, so a guest that has stopped reading its console
//! cannot take the escape away.
//!
//! The terminal is the process's only while it is in the terminal's
//! foreground process group: [`RawModeGuard::enter`] does not touch it from
//! the background (a write of its settings there would stop the process
//! with `SIGTTOU`, the VM with it), and with [`start_job_control`] running a
//! stop (Ctrl-Z, `kill -TSTP`) hands it back to the shell as it was, a
//! continue in the foreground (`fg`) takes it again, and one in the
//! background (`bg`) leaves it to the shell.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use event_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::timerfd::TimerFd;

use crate::devices::SerialDevice;
use crate::lifecycle::{block_signals, SignalFd, StopReason, VmmHandle};

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
    isatty(libc::STDIN_FILENO)
}

fn isatty(fd: RawFd) -> bool {
    // SAFETY: isatty has no preconditions.
    unsafe { libc::isatty(fd) == 1 }
}

/// Whether this process may use the terminal `fd`: it is in the
/// terminal's foreground process group, or the terminal is not its
/// controlling terminal (`tcgetpgrp` says `ENOTTY`), where job control does
/// not apply. A process in another group of the terminal's session is in
/// the background: reading the terminal would stop it (`SIGTTIN`), and so
/// would changing its settings (`SIGTTOU`).
pub fn is_foreground(fd: RawFd) -> bool {
    // SAFETY: tcgetpgrp takes a descriptor and no pointer.
    let group = unsafe { libc::tcgetpgrp(fd) };
    if group < 0 {
        return io::Error::last_os_error().raw_os_error() == Some(libc::ENOTTY);
    }
    // SAFETY: getpgrp takes no arguments and cannot fail.
    group == unsafe { libc::getpgrp() }
}

fn job_control_sigset(signals: &[i32]) -> io::Result<libc::sigset_t> {
    vmm_sys_util::signal::create_sigset(signals)
        .map_err(|error| io::Error::from_raw_os_error(error.errno()))
}

/// Blocks `SIGTTIN` and `SIGTTOU` on the calling thread, and only there: a
/// read of the terminal from the background then fails with `EIO` instead
/// of stopping the whole process (and the VM with it). The threads that
/// read stdin call it; the others keep the shell's job control (a
/// background write to a terminal with `tostop` still stops the process).
pub fn block_job_control_signals() -> io::Result<()> {
    let set = job_control_sigset(&[libc::SIGTTIN, libc::SIGTTOU])?;
    // SAFETY: `set` is a valid sigset and the old mask is not requested.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

/// `SIGTTIN` and `SIGTTOU` blocked on the calling thread for as long as
/// this lives, so that the terminal calls made under it never stop the
/// process. (The kernel lets a background process through, for `SIGTTOU`,
/// when it is blocked: the look at the foreground comes first, and again
/// after the write.)
struct JobSignalsBlocked(libc::sigset_t);

impl JobSignalsBlocked {
    fn new() -> io::Result<Self> {
        let set = job_control_sigset(&[libc::SIGTTIN, libc::SIGTTOU])?;
        // SAFETY: zeroed is a valid sigset to be written by pthread_sigmask.
        let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `set` is valid; the old mask is written into `old`.
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(JobSignalsBlocked(old))
    }
}

impl Drop for JobSignalsBlocked {
    fn drop(&mut self) {
        // SAFETY: the mask pthread_sigmask wrote in `new`.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

fn get_termios(fd: RawFd) -> io::Result<libc::termios> {
    // SAFETY: termios is plain data; all zeroes is valid.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes one termios into `termios`, alive for the
    // call.
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(termios)
}

fn set_termios(fd: RawFd, termios: &libc::termios) -> io::Result<()> {
    // SAFETY: tcsetattr reads one termios from `termios`.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `termios` in raw mode, as [`RawModeGuard`] sets it: no line editing, no
/// echo, no signals from Ctrl-C or Ctrl-Z, and no flow control either way:
/// Ctrl-S and Ctrl-Q reach the reader (`boxcar attach`'s Ctrl-Q, a guest
/// program's Ctrl-S) instead of pausing output (`IXON`), and the terminal
/// sends no XOFF of its own when its input fills (`IXOFF`). Output
/// processing stays.
pub fn raw_termios(mut termios: libc::termios) -> libc::termios {
    termios.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
    termios.c_iflag &= !(libc::IXON | libc::IXOFF);
    termios
}

/// Whether `termios` is what [`raw_termios`] makes of some settings.
fn is_raw(termios: &libc::termios) -> bool {
    termios.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG) == 0
        && termios.c_iflag & (libc::IXON | libc::IXOFF) == 0
}

/// A terminal call that failed because there is no terminal to use any
/// more (`ENOTTY`, or `EIO`: a hung-up terminal, or a background process
/// of an orphaned group): not an error of this process's, which then does
/// not take the terminal.
fn unusable(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EIO | libc::ENOTTY))
}

/// A terminal this process puts in raw mode, and what it wants of it.
///
/// The process's stdin terminal is the one instance, [`STDIN_TTY`]; the
/// tests make others on a PTY pair of their own.
struct Tty {
    fd: RawFd,
    state: Mutex<TtyState>,
}

struct TtyState {
    /// The settings from before raw mode: there while this process has the
    /// terminal in raw mode, so that exactly one of the guard, the stop and
    /// the panic hook restores them.
    saved: Option<libc::termios>,
    /// A [`RawModeGuard`] is alive: the terminal is to be raw whenever
    /// this process is in its foreground.
    wanted: bool,
}

/// Stdin's terminal (std's stdin lock stays out of it: the panic hook must
/// not wait on it).
static STDIN_TTY: Tty = Tty::new(libc::STDIN_FILENO);

impl Tty {
    const fn new(fd: RawFd) -> Tty {
        Tty {
            fd,
            state: Mutex::new(TtyState {
                saved: None,
                wanted: false,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, TtyState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Puts the terminal in raw mode, if this process is in its
    /// foreground. False when it is not, or when the terminal cannot be
    /// used ([`unusable`]): nothing is changed then, and it is not an
    /// error. True when the terminal is raw.
    ///
    /// The process looks at the foreground right before it writes the
    /// settings, and again right after: the settings are written with
    /// `SIGTTOU` blocked (a background write would otherwise stop the
    /// process, and the VM with it), which makes the kernel let a
    /// background process through, so a process that moved to the
    /// background in between gives the settings back at once.
    ///
    /// The settings it saves are the terminal's as they are now: when it
    /// takes the terminal again after a stop, the shell may have changed
    /// them. A terminal that is raw already, and that this process put
    /// there, is left alone.
    fn take(&self, state: &mut TtyState) -> io::Result<bool> {
        let _blocked = JobSignalsBlocked::new()?;
        if !is_foreground(self.fd) {
            return Ok(false);
        }
        let current = match get_termios(self.fd) {
            Ok(termios) => termios,
            Err(error) if unusable(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        if state.saved.is_some() && is_raw(&current) {
            return Ok(true);
        }
        match set_termios(self.fd, &raw_termios(current)) {
            Ok(()) => {}
            Err(error) if unusable(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
        if !is_foreground(self.fd) {
            // Moved to the background between the look and the write: the
            // terminal is the shell's, as it was.
            let _ = set_termios(self.fd, &current);
            return Ok(false);
        }
        state.saved = Some(current);
        Ok(true)
    }

    /// Puts the terminal's saved settings back, unless the process is in
    /// the background by now: the shell has the terminal then (it took it
    /// back when the job stopped), and what this process left there is
    /// left to it. The settings stay saved in that case, for the day this
    /// process takes the terminal again.
    fn give_back(&self, state: &mut TtyState) {
        let Some(saved) = state.saved else {
            return;
        };
        if !is_foreground(self.fd) {
            return;
        }
        state.saved = None;
        let Ok(_blocked) = JobSignalsBlocked::new() else {
            return;
        };
        match set_termios(self.fd, &saved) {
            Err(error) if !unusable(&error) => {
                tracing::warn!("cannot restore the terminal: {error}");
            }
            _ => {}
        }
    }

    /// A guard for the terminal: raw now when this process is in its
    /// foreground. When it is not, `wait` says whether it gets a guard
    /// anyway, to take the terminal when it is brought to the foreground
    /// (see [`Tty::refresh`]), or `None`. `None` for a descriptor that is
    /// not a terminal.
    fn hold(&'static self, wait: bool) -> io::Result<Option<RawModeGuard>> {
        if !isatty(self.fd) {
            return Ok(None);
        }
        let mut state = self.lock();
        if !self.take(&mut state)? && !wait {
            return Ok(None);
        }
        state.wanted = true;
        Ok(Some(RawModeGuard { tty: self }))
    }

    /// The guard is gone (or the process panics): the terminal goes back
    /// to its settings and is no longer wanted raw.
    fn release(&self) {
        let mut state = self.lock();
        state.wanted = false;
        self.give_back(&mut state);
        state.saved = None;
    }

    /// The terminal goes back to its settings, but is still wanted raw: a
    /// job-control stop is about to hand it to the shell.
    fn suspend(&self) {
        let mut state = self.lock();
        self.give_back(&mut state);
    }

    /// Takes the terminal for raw mode when it is wanted and this process
    /// is in the foreground, and it is not raw: after a stop and a
    /// continue, whose settings the shell has just changed; when a run that
    /// began in the background is brought to the foreground; after the
    /// shell wrote its own settings a moment after it continued the job. A
    /// raw terminal, and a process in the background, are left alone.
    fn refresh(&self) {
        let mut state = self.lock();
        if !state.wanted {
            return;
        }
        if let Err(error) = self.take(&mut state) {
            tracing::debug!("cannot put the terminal in raw mode: {error}");
        }
    }

    /// A `SIGTSTP`: gives the terminal back to the shell as it was, then
    /// stops the whole process as the signal's default action does, so that
    /// the shell sees a stopped job. Returns once the process is
    /// continued.
    fn stop(&self) {
        if tstp_ignored() {
            // Inherited as ignored: nothing stops, so nothing changes.
            return;
        }
        self.suspend();
        stop_process();
    }

    /// Waits up to `wait` for a signal on `signals` (`SIGTSTP`, `SIGCONT`),
    /// and handles what came; looks at the foreground afterwards, in any
    /// case, as the shell's `fg` need not send a `SIGCONT` the process
    /// sees first. True when a stop was handled.
    fn job_control_step(&self, signals: &SignalFd, wait: Duration) -> io::Result<bool> {
        let mut pollfd = libc::pollfd {
            fd: signals.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: poll reads and writes the one pollfd it is given.
        if unsafe { libc::poll(&mut pollfd, 1, ms) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        let mut stopped = false;
        while let Some(signo) = signals.read()? {
            if signo == libc::SIGTSTP {
                self.stop();
                stopped = true;
            }
        }
        self.refresh();
        Ok(stopped)
    }
}

/// Whether `SIGTSTP` is ignored by this process (inherited so from a
/// parent that is not a job-control shell).
fn tstp_ignored() -> bool {
    // SAFETY: sigaction is plain data; all zeroes is valid.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: with a null new action, sigaction only reads the current one
    // into `action`.
    let rc = unsafe { libc::sigaction(libc::SIGTSTP, std::ptr::null(), &mut action) };
    rc == 0 && action.sa_sigaction == libc::SIG_IGN
}

/// Stops the process the way an unhandled `SIGTSTP` does: the calling
/// thread has the signal unblocked and raises it at itself (the other
/// threads have it blocked, for the signalfd), and the kernel stops every
/// thread. Returns once the process is continued, or at once when the
/// signal's default action is not to stop (an orphaned process group).
fn stop_process() {
    let Ok(set) = job_control_sigset(&[libc::SIGTSTP]) else {
        return;
    };
    // SAFETY: zeroed is a valid sigset to be written by pthread_sigmask.
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is valid; the old mask is written into `old`.
    if unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, &mut old) } != 0 {
        return;
    }
    // SAFETY: raise has no preconditions; with the default action, the
    // process is stopped inside it.
    unsafe { libc::raise(libc::SIGTSTP) };
    // SAFETY: `old` is the mask pthread_sigmask wrote above.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
}

/// How long the job-control thread waits for a signal before it looks at
/// the foreground.
const JOB_CONTROL_STEP: Duration = Duration::from_millis(200);

/// Starts the thread that does the terminal's job control, for a process
/// whose stdin is a terminal (otherwise it does nothing): `boxcar run` and
/// `boxcar attach` call it before they start any thread.
///
/// Ctrl-Z (with the terminal cooked), `kill -TSTP` and the like stop the
/// process by default and leave the terminal as it is, which is raw while a
/// [`RawModeGuard`] is alive. So `SIGTSTP` and `SIGCONT` are blocked here,
/// on the calling thread and every thread it starts afterwards, and read
/// from a signalfd by the new thread, as `SIGWINCH` is. On `SIGTSTP` it
/// gives the terminal back as it was, then stops the process the way the
/// signal's default action does (the shell sees the job stopped, and has a
/// cooked terminal, whatever it does or does not save); on `SIGCONT`, and
/// every `JOB_CONTROL_STEP` besides, it takes the terminal again if
/// this process is in the foreground and a guard wants it raw. A run
/// started in the background, or one stopped and then sent to the
/// background with `bg`, takes the terminal when `fg` brings it back.
pub fn start_job_control() -> io::Result<()> {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if !stdin_is_tty() || STARTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let started = (|| {
        block_signals(&[libc::SIGTSTP, libc::SIGCONT])?;
        let signals = SignalFd::with(&[libc::SIGTSTP, libc::SIGCONT])?;
        thread::Builder::new()
            .name("job-control".into())
            .spawn(move || {
                while STDIN_TTY
                    .job_control_step(&signals, JOB_CONTROL_STEP)
                    .is_ok()
                {}
            })
            .map(drop)
    })();
    if started.is_err() {
        STARTED.store(false, Ordering::SeqCst);
    }
    started
}

/// Restores the terminal before the previous hook prints the panic.
fn install_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            STDIN_TTY.release();
            previous(info);
        }));
    });
}

/// The host terminal in raw mode ([`raw_termios`]: no line editing, no
/// echo, no signals from Ctrl-C, no flow control), while this process is in
/// its foreground. Dropping it restores the settings the terminal had; so
/// does a panic anywhere in the process. With [`start_job_control`] running,
/// a stop of the process gives the terminal back too, and a continue in the
/// foreground takes it again.
pub struct RawModeGuard {
    tty: &'static Tty,
}

impl RawModeGuard {
    /// Puts stdin's terminal in raw mode, if this process is in its
    /// foreground. `None` when stdin is not a terminal, or this process is
    /// not in its foreground, or the terminal cannot be used (`EIO`,
    /// `ENOTTY`): nothing is changed then. The foreground is looked at
    /// here, with `SIGTTOU` blocked around the write, so that a process
    /// that moved to the background is neither stopped nor changes the
    /// shell's terminal.
    pub fn enter() -> io::Result<Option<RawModeGuard>> {
        install_panic_hook();
        STDIN_TTY.hold(false)
    }

    /// Like [`RawModeGuard::enter`], but a process in the background gets
    /// a guard as well (`None` only when stdin is not a terminal): the
    /// terminal stays the shell's, and the process takes it, raw, when it is
    /// brought to the foreground ([`start_job_control`] must be running).
    pub fn enter_when_foreground() -> io::Result<Option<RawModeGuard>> {
        install_panic_hook();
        STDIN_TTY.hold(true)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.tty.release();
    }
}

/// Bytes read from stdin at a time: the whole 16550A receive FIFO.
const READ_CHUNK: usize = 64;

/// How much input waits for room in the receive FIFO.
const HOLD_CAP: usize = 4096;

/// How often a [`StdinSubscriber`] that left stdin unread in the
/// background looks at the foreground again.
const FOREGROUND_RECHECK: Duration = Duration::from_millis(200);

/// Whether this process is in the foreground of its stdin terminal, or
/// stdin is not a terminal: what the subscriber asks before every read.
fn stdin_in_foreground() -> bool {
    is_foreground(libc::STDIN_FILENO)
}

/// Forwards stdin to COM1 on the main loop.
///
/// Stdin is read only while this process is in the foreground of its
/// terminal (the rule the `pty-stdin` thread follows too): a read from the
/// background would stop the process with `SIGTTIN`, so the first line a
/// user typed for the shell after `kill -TSTP` and `bg`, or a run started
/// with `&`, would stop the VM. In the background the input is left where
/// it is, stdin is not watched (a level-triggered wait would spin), and a
/// timer looks at the foreground every [`FOREGROUND_RECHECK`]; when the
/// process is in the foreground again, stdin is watched and read as
/// before, the escape included.
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
    /// The descriptor read: stdin, or a test's pipe.
    stdin: RawFd,
    /// Whether this process may read `stdin` now: in the foreground of its
    /// terminal. A test's says what the test wants.
    foreground: Box<dyn Fn() -> bool + Send>,
    /// Fires while `stdin` is left unwatched in the background.
    recheck: TimerFd,
    /// `stdin` is not watched: it was readable while the process was in
    /// the background.
    unwatched: bool,
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
        Self::reading(
            libc::STDIN_FILENO,
            Box::new(stdin_in_foreground),
            serial,
            handle,
            dropped_input,
        )
    }

    /// [`new`](Self::new), reading `stdin` while `foreground` says this
    /// process may.
    pub(crate) fn reading(
        stdin: RawFd,
        foreground: Box<dyn Fn() -> bool + Send>,
        serial: Arc<Mutex<SerialDevice>>,
        handle: VmmHandle,
        dropped_input: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        let buffer_ready = lock(&serial).buffer_ready_evt().try_clone()?;
        Ok(StdinSubscriber {
            serial,
            buffer_ready,
            stdin,
            foreground,
            recheck: TimerFd::new()?,
            unwatched: false,
            closed: false,
            escape: EscapeDetector::default(),
            handle,
            held: VecDeque::with_capacity(HOLD_CAP),
            dropped_input,
        })
    }

    /// Stdin, the buffer-ready eventfd and the foreground timer. The
    /// caller registers them all.
    pub(crate) fn fds(&self) -> [RawFd; 3] {
        [
            self.stdin,
            self.buffer_ready.as_raw_fd(),
            self.recheck.as_raw_fd(),
        ]
    }

    fn close(&mut self, ops: &mut EventOps) {
        if !self.closed {
            self.closed = true;
            if !self.unwatched {
                if let Err(error) = ops.remove(Events::new_raw(self.stdin, EventSet::IN)) {
                    tracing::warn!("cannot stop watching stdin: {error}");
                }
            }
            self.unwatched = false;
            let _ = self.recheck.clear();
        }
    }

    /// Stdin is readable, and this process is in the background: leaves it
    /// unread and unwatched, and starts looking at the foreground.
    fn leave_unread(&mut self, ops: &mut EventOps) {
        if self.unwatched {
            return;
        }
        if let Err(error) = ops.remove(Events::new_raw(self.stdin, EventSet::IN)) {
            tracing::warn!("cannot stop watching stdin: {error}");
            return;
        }
        self.unwatched = true;
        if let Err(error) = self
            .recheck
            .reset(FOREGROUND_RECHECK, Some(FOREGROUND_RECHECK))
        {
            tracing::warn!("cannot arm the foreground timer: {error}");
        }
    }

    /// The foreground timer fired: watches stdin again if the process is
    /// back in the foreground.
    fn on_recheck(&mut self, ops: &mut EventOps) {
        if let Err(error) = self.recheck.wait() {
            tracing::debug!("the foreground timer: {error}");
        }
        if !self.unwatched || self.closed {
            let _ = self.recheck.clear();
            return;
        }
        if !(self.foreground)() {
            return;
        }
        match ops.add(Events::new_raw(self.stdin, EventSet::IN)) {
            Ok(()) => {
                self.unwatched = false;
                let _ = self.recheck.clear();
            }
            Err(error) => tracing::warn!("cannot watch stdin again: {error}"),
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
        if !(self.foreground)() {
            return self.leave_unread(ops);
        }
        let mut buf = [0u8; READ_CHUNK];
        // SAFETY: reads at most `buf.len()` bytes into `buf`.
        let n = unsafe { libc::read(self.stdin, buf.as_mut_ptr().cast(), buf.len()) };
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
        } else if events.fd() == self.recheck.as_raw_fd() {
            self.on_recheck(ops);
        } else if events.fd() == self.stdin {
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

fn lock(serial: &Mutex<SerialDevice>) -> MutexGuard<'_, SerialDevice> {
    serial.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// A terminal pair, both ends.
    fn openpty() -> (RawFd, RawFd) {
        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty writes two new descriptors; the name, termios and
        // winsize arguments may be null.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0);
        (master, slave)
    }

    /// A process may use a terminal when it is in the terminal's foreground
    /// process group, or when the terminal is not its controlling one (job
    /// control does not apply there). A process in another group of the
    /// terminal's session is in the background: with `SIGTTIN` blocked
    /// ([`block_job_control_signals`]) its read fails with `EIO` instead of
    /// stopping it.
    #[test]
    fn a_process_outside_the_terminals_foreground_group_is_in_the_background() {
        let (master, slave) = openpty();
        // Not this process's controlling terminal.
        assert!(is_foreground(slave));
        // SAFETY: the child calls only async-signal-safe functions (the
        // syscalls is_foreground and block_job_control_signals make, fork,
        // waitpid, read) and leaves with _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: as above.
            unsafe {
                if libc::setsid() < 0 || libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                    libc::_exit(10);
                }
                // The session's leader, its group the terminal's foreground.
                if !is_foreground(slave) {
                    libc::_exit(11);
                }
                let grandchild = libc::fork();
                if grandchild == 0 {
                    // Another group of the session: the background.
                    if libc::setpgid(0, 0) < 0 {
                        libc::_exit(12);
                    }
                    if is_foreground(slave) {
                        libc::_exit(13);
                    }
                    if block_job_control_signals().is_err() {
                        libc::_exit(14);
                    }
                    let mut byte = 0u8;
                    let n = libc::read(slave, (&mut byte as *mut u8).cast(), 1);
                    let eio = n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EIO);
                    libc::_exit(if eio { 0 } else { 15 });
                }
                let mut status = 0;
                libc::waitpid(grandchild, &mut status, 0);
                libc::_exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    16
                });
            }
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "{status:#x}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the child said where it failed"
        );
        // SAFETY: both are descriptors openpty made, closed once.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    /// The terminal's settings are the same, field for field.
    fn same_settings(a: &libc::termios, b: &libc::termios) -> bool {
        a.c_iflag == b.c_iflag
            && a.c_oflag == b.c_oflag
            && a.c_cflag == b.c_cflag
            && a.c_lflag == b.c_lflag
            && a.c_cc == b.c_cc
    }

    /// A [`Tty`] for `fd`, as the guard needs it (for as long as the
    /// process lives).
    fn leak_tty(fd: RawFd) -> &'static Tty {
        Box::leak(Box::new(Tty::new(fd)))
    }

    /// Forks a child that runs `body` and leaves with its result as its
    /// exit code (99 if it panicked). `SIGALRM` ends it after 30 s, and so
    /// does the end of its parent. The child makes libc calls and uses the
    /// module's own code, which allocates nothing on these paths.
    fn fork_child(body: impl FnOnce() -> i32) -> libc::pid_t {
        // SAFETY: the child runs `body` and leaves with _exit, never
        // returning into the test harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: plain system calls.
            unsafe {
                libc::alarm(30);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }
            let code = panic::catch_unwind(panic::AssertUnwindSafe(body)).unwrap_or(99);
            // SAFETY: as above.
            unsafe { libc::_exit(code) };
        }
        child
    }

    /// The exit code of `child` (128 plus the signal that ended it).
    fn wait_child(child: libc::pid_t) -> i32 {
        let mut status = 0;
        // SAFETY: waits for a child forked by `fork_child`.
        unsafe { libc::waitpid(child, &mut status, 0) };
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        }
    }

    /// The calling process becomes a session leader whose controlling
    /// terminal is `terminal` (its group the foreground), like a shell.
    fn become_a_shell(terminal: RawFd) -> bool {
        // SAFETY: plain system calls.
        unsafe { libc::setsid() >= 0 && libc::ioctl(terminal, libc::TIOCSCTTY, 0) >= 0 }
    }

    /// Waits up to `limit` for `condition`.
    fn within(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        while !condition() {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(10 * MS);
        }
        true
    }

    /// In the foreground (here: a terminal that is nobody's controlling
    /// terminal, where job control does not apply) the guard puts the
    /// terminal in raw mode, and dropping it gives back exactly the
    /// settings it had.
    #[test]
    fn enter_in_the_foreground_takes_the_terminal_and_drop_restores_it_exactly() {
        let (master, slave) = openpty();
        let before = get_termios(slave).unwrap();
        assert!(!is_raw(&before));
        let tty = leak_tty(slave);
        let guard = tty
            .hold(false)
            .unwrap()
            .expect("a terminal that is in the foreground is taken");
        let raw = get_termios(slave).unwrap();
        assert!(is_raw(&raw));
        assert!(same_settings(&raw, &raw_termios(before)));
        assert!(tty.lock().wanted);
        drop(guard);
        assert!(same_settings(&get_termios(slave).unwrap(), &before));
        assert!(!tty.lock().wanted);
        // Not a terminal: no guard, with or without waiting.
        let mut pipe = [0; 2];
        // SAFETY: pipe writes two new descriptors.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let not_a_tty = leak_tty(pipe[0]);
        assert!(not_a_tty.hold(false).unwrap().is_none());
        assert!(not_a_tty.hold(true).unwrap().is_none());
        // SAFETY: descriptors the test opened, closed once.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            libc::close(master);
            libc::close(slave);
        }
    }

    /// A process in the background of its controlling terminal does not
    /// take it: `enter` gives `None` (and a guard that waits, with `wait`,
    /// holds nothing), the settings stay as they were, and the process is
    /// not stopped by `SIGTTOU`: its exit is seen, not a stop.
    #[test]
    fn a_process_in_the_background_does_not_take_the_terminal_and_is_not_stopped() {
        let (master, slave) = openpty();
        let before = get_termios(slave).unwrap();
        let shell = fork_child(|| {
            if !become_a_shell(slave) {
                return 10;
            }
            let job = fork_child(|| {
                // SAFETY: plain system call.
                if unsafe { libc::setpgid(0, 0) } < 0 {
                    return 12;
                }
                // Another group of the session: the background.
                if is_foreground(slave) {
                    return 13;
                }
                let tty = leak_tty(slave);
                if !matches!(tty.hold(false), Ok(None)) {
                    return 14;
                }
                match tty.hold(true) {
                    Ok(Some(guard)) => {
                        if tty.lock().saved.is_some() {
                            return 15;
                        }
                        drop(guard);
                    }
                    _ => return 16,
                }
                match get_termios(slave) {
                    Ok(now) if same_settings(&now, &before) => 0,
                    _ => 17,
                }
            });
            let mut status = 0;
            // SAFETY: waits for the job forked above, stops included.
            unsafe { libc::waitpid(job, &mut status, libc::WUNTRACED) };
            if libc::WIFSTOPPED(status) {
                // SAFETY: the job is ours.
                unsafe { libc::kill(job, libc::SIGKILL) };
                return 20;
            }
            if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                21
            }
        });
        let code = wait_child(shell);
        assert_eq!(code, 0, "the job said where it failed (20: stopped)");
        // SAFETY: both are descriptors openpty made, closed once.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    /// A stop gives the terminal back as it was and a continue takes it
    /// again, with a shell's moves played by a session leader: a job that
    /// starts in the background wants the terminal and takes it when it is
    /// brought to the foreground; `SIGTSTP` stops it, by that signal, with
    /// the terminal cooked; `bg` (the shell takes the terminal back, then
    /// `SIGCONT`) leaves it alone; `fg` takes it again.
    #[test]
    fn a_stop_gives_the_terminal_back_and_a_continue_in_the_foreground_takes_it_again() {
        let (master, slave) = openpty();
        let shell = fork_child(|| {
            if !become_a_shell(slave) || block_job_control_signals().is_err() {
                return 10;
            }
            let Ok(before) = get_termios(slave) else {
                return 10;
            };
            let job = fork_child(|| {
                // SAFETY: plain system call.
                if unsafe { libc::setpgid(0, 0) } < 0 {
                    return 30;
                }
                if block_signals(&[libc::SIGTSTP, libc::SIGCONT]).is_err() {
                    return 31;
                }
                let Ok(signals) = SignalFd::with(&[libc::SIGTSTP, libc::SIGCONT]) else {
                    return 32;
                };
                let tty = leak_tty(slave);
                // Started in the background, wanting the terminal.
                let Ok(Some(_guard)) = tty.hold(true) else {
                    return 33;
                };
                loop {
                    if tty.job_control_step(&signals, 50 * MS).is_err() {
                        return 34;
                    }
                }
            });
            // SAFETY: plain system calls on the job forked above.
            unsafe { libc::setpgid(job, job) };
            let raw = || get_termios(slave).is_ok_and(|termios| is_raw(&termios));
            let cooked =
                || get_termios(slave).is_ok_and(|termios| same_settings(&termios, &before));
            // The terminal's foreground group, as the shell hands it over.
            let hand_to = |group: libc::pid_t| {
                // SAFETY: SIGTTOU is blocked here, as a shell's is.
                unsafe { libc::tcsetpgrp(slave, group) == 0 }
            };
            // In the background the job leaves the terminal alone.
            thread::sleep(300 * MS);
            if !cooked() {
                return 11;
            }
            // `fg`: raw within a step, with no signal at all.
            // SAFETY: plain system call.
            let own = unsafe { libc::getpgrp() };
            if !hand_to(job) || !within(Duration::from_secs(3), raw) {
                return 12;
            }
            // `kill -TSTP`: stopped by that signal, and the terminal is
            // already cooked when the shell sees the stop.
            // SAFETY: the job is ours.
            unsafe { libc::kill(job, libc::SIGTSTP) };
            let mut status = 0;
            // SAFETY: waits for the job, stops included.
            unsafe { libc::waitpid(job, &mut status, libc::WUNTRACED) };
            if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTSTP {
                return 13;
            }
            if !cooked() {
                return 14;
            }
            // `bg`: the shell takes the terminal, the job continues, and
            // leaves the terminal alone (for several steps).
            // SAFETY: the job is ours.
            if !hand_to(own) || unsafe { libc::kill(job, libc::SIGCONT) } != 0 {
                return 15;
            }
            thread::sleep(400 * MS);
            if !cooked() {
                return 16;
            }
            // Running, not stopped again.
            // SAFETY: waits for the job without blocking, stops included.
            let again = unsafe { libc::waitpid(job, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            if again != 0 {
                return 17;
            }
            // `fg`: the terminal, then the continue the shell sends.
            // SAFETY: the job is ours.
            if !hand_to(job) || unsafe { libc::kill(job, libc::SIGCONT) } != 0 {
                return 18;
            }
            if !within(Duration::from_secs(3), raw) {
                return 19;
            }
            // SAFETY: the job is ours.
            unsafe {
                libc::kill(job, libc::SIGKILL);
                libc::waitpid(job, &mut status, 0);
            }
            0
        });
        let code = wait_child(shell);
        assert_eq!(code, 0, "the shell said where it failed (see the test)");
        // SAFETY: both are descriptors openpty made, closed once.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    /// A stop hands the terminal back and a refresh takes it again, from
    /// the settings the shell left meanwhile (not the old ones); once the
    /// guard is gone, nothing takes it.
    #[test]
    fn a_suspended_terminal_is_taken_again_from_the_settings_the_shell_left() {
        let (master, slave) = openpty();
        let before = get_termios(slave).unwrap();
        let tty = leak_tty(slave);
        let guard = tty.hold(false).unwrap().unwrap();
        assert!(is_raw(&get_termios(slave).unwrap()));

        tty.suspend();
        assert!(same_settings(&get_termios(slave).unwrap(), &before));
        // The shell's own settings while the job is stopped.
        let mut shells = before;
        shells.c_lflag ^= libc::ECHOK;
        set_termios(slave, &shells).unwrap();
        tty.refresh();
        let now = get_termios(slave).unwrap();
        assert!(is_raw(&now));
        assert!(same_settings(&now, &raw_termios(shells)));
        // A shell that writes its settings a moment after the continue is
        // heard on the next look, and a raw terminal is left alone.
        set_termios(slave, &shells).unwrap();
        tty.refresh();
        assert!(is_raw(&get_termios(slave).unwrap()));
        tty.refresh();
        assert!(is_raw(&get_termios(slave).unwrap()));

        drop(guard);
        assert!(same_settings(&get_termios(slave).unwrap(), &shells));
        tty.refresh();
        assert!(same_settings(&get_termios(slave).unwrap(), &shells));
        // SAFETY: both are descriptors openpty made, closed once.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    /// Raw mode leaves nothing to the line discipline that a reader needs:
    /// no line editing, echo or signals, and Ctrl-S and Ctrl-Q are input,
    /// not flow control; everything else, output processing included, is
    /// as it was.
    #[test]
    fn raw_mode_lets_every_key_through_and_keeps_the_rest() {
        // SAFETY: termios is plain data; all zeroes is valid.
        let mut cooked: libc::termios = unsafe { std::mem::zeroed() };
        cooked.c_iflag = libc::ICRNL | libc::IXON | libc::IXOFF | libc::IUTF8;
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

    /// A subscriber on a pipe standing in for stdin, in a real event
    /// loop, whose foreground is whatever the test says.
    struct Piped {
        manager: event_manager::EventManager<Box<dyn MutEventSubscriber>>,
        id: event_manager::SubscriberId,
        writer: std::fs::File,
        reader_fd: RawFd,
        foreground: Arc<AtomicBool>,
        serial: Arc<Mutex<SerialDevice>>,
        _handle: VmmHandle,
        _audit: boxcar_audit::WriterHandle,
        _dir: tempfile::TempDir,
    }

    fn piped(foreground: bool) -> Piped {
        use event_manager::SubscriberOps;
        use std::os::fd::FromRawFd;
        let dir = tempfile::tempdir().unwrap();
        let (handle, audit) = test_handle(dir.path());
        let (sink, _writer) = ConsoleWriter::spawn_with(std::io::sink()).unwrap();
        let serial = Arc::new(Mutex::new(SerialDevice::new(sink).unwrap()));
        let mut fds = [0 as RawFd; 2];
        // SAFETY: pipe2 writes two descriptors into the array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (reader_fd, writer_fd) = (fds[0], fds[1]);
        // SAFETY: the write end is ours, just made, and owned once.
        let writer = unsafe { std::fs::File::from_raw_fd(writer_fd) };
        let foreground = Arc::new(AtomicBool::new(foreground));
        let says = Arc::clone(&foreground);
        let subscriber = StdinSubscriber::reading(
            reader_fd,
            Box::new(move || says.load(Ordering::SeqCst)),
            serial.clone(),
            handle.clone(),
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        let watched = subscriber.fds();
        let mut manager = event_manager::EventManager::new().unwrap();
        let id = manager.add_subscriber(Box::new(subscriber) as Box<dyn MutEventSubscriber>);
        let mut ops = manager.event_ops(id).unwrap();
        for fd in watched {
            ops.add(Events::new_raw(fd, EventSet::IN)).unwrap();
        }
        Piped {
            manager,
            id,
            writer,
            reader_fd,
            foreground,
            serial,
            _handle: handle,
            _audit: audit,
            _dir: dir,
        }
    }

    impl Piped {
        /// Dispatches what is ready within `ms`; how many events there were.
        fn run(&mut self, ms: i32) -> usize {
            self.manager.run_with_timeout(ms).unwrap()
        }

        /// Whether the pipe still holds unread bytes.
        fn pipe_has_input(&self) -> bool {
            let mut fd = libc::pollfd {
                fd: self.reader_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized pollfd, no wait.
            unsafe { libc::poll(&mut fd, 1, 0) == 1 }
        }

        /// What the guest finds in the receive FIFO.
        fn fifo(&self) -> Vec<u8> {
            let mut serial = lock(&self.serial);
            let mut out = Vec::new();
            while serial.fifo_capacity() < 64 {
                let mut byte = [0u8];
                serial.read(0, &mut byte);
                out.push(byte[0]);
            }
            out
        }
    }

    /// Runs the loop until `done`, failing after 5 s.
    fn run_until(piped: &mut Piped, what: &str, mut done: impl FnMut(&Piped) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(piped) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            piped.run(200);
        }
    }

    /// Runs the loop until nothing is ready any more, failing after 5 s:
    /// nothing watched is left readable, so the loop does not spin.
    fn run_until_quiet(piped: &mut Piped) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while piped.run(200) > 0 {
            assert!(Instant::now() < deadline, "the loop never went quiet");
        }
    }

    /// In the background, input is left in stdin unread (so the kernel
    /// never stops the process for reading it) and stdin is not watched
    /// (so the loop does not spin); back in the foreground, the timer sees
    /// it and the input is read and forwarded as before.
    #[test]
    fn stdin_is_read_only_in_the_foreground() {
        use std::io::Write as _;
        let mut piped = piped(false);
        piped.writer.write_all(b"ls\n").unwrap();
        // Stdin is readable: left alone, and unwatched from now on.
        assert!(piped.run(1000) >= 1);
        assert!(piped.pipe_has_input(), "read in the background");
        assert!(piped.fifo().is_empty());
        // Only the timer fires now (every 200 ms); stdin stays unread, and
        // the loop does not spin on it.
        let fired = piped.run(500);
        assert!((1..=4).contains(&fired), "{fired} events");
        assert!(piped.pipe_has_input());
        assert!(piped.fifo().is_empty());

        // Back in the foreground: within a timer step stdin is watched and
        // read.
        piped.foreground.store(true, Ordering::SeqCst);
        run_until(&mut piped, "the input to be read", |piped| {
            !piped.pipe_has_input()
        });
        assert_eq!(piped.fifo(), b"ls\n");
        // And it goes on being read at once while in the foreground.
        piped.writer.write_all(b"x").unwrap();
        run_until(&mut piped, "the next input", |piped| {
            !piped.pipe_has_input()
        });
        assert_eq!(piped.fifo(), b"x");
        run_until_quiet(&mut piped);
    }

    /// In the foreground the escape still stops the VM, and EOF ends the
    /// reading for good: nothing is left watched.
    #[test]
    fn a_piped_stdin_in_the_foreground_forwards_escape_and_eof() {
        use std::io::Write as _;
        let mut piped = piped(true);
        piped.writer.write_all(b"hi").unwrap();
        run_until(&mut piped, "the input to be read", |piped| {
            !piped.pipe_has_input()
        });
        assert_eq!(piped.fifo(), b"hi");
        piped.writer.write_all(&[ESCAPE_BYTE, ESCAPE_BYTE]).unwrap();
        run_until(&mut piped, "the escape", |piped| {
            piped._handle.state() == VmState::Stopping
        });
        assert!(piped.fifo().is_empty(), "the escape is not forwarded");
        drop(std::mem::replace(
            &mut piped.writer,
            tempfile::tempfile().unwrap(),
        ));
        run_until_quiet(&mut piped);
        let _ = piped.id;
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
