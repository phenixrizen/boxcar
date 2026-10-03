// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! How init ends: how the session ended, on the console; a bounded wait for
//! the console to send it; `sync`; a reboot, which the VMM sees as the guest
//! resetting and ends the VM on.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::reboot::{reboot, RebootMode};
use nix::unistd::sync;

use crate::console::{write_console, CONSOLE};
use crate::reaper::Ended;

/// How long [`reboot_now`] waits at most for the console to send what it
/// holds.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(2);

/// How often it looks at the console's output queue meanwhile.
pub const DRAIN_STEP: Duration = Duration::from_millis(10);

/// The console line for how the session ended: `boxcar: session exited
/// <code>` or `boxcar: session killed by signal <n>`.
pub fn exit_line(ended: Ended) -> String {
    match ended {
        Ended::Exited(code) => format!("boxcar: session exited {code}\n"),
        Ended::Killed(signal) => format!("boxcar: session killed by signal {signal}\n"),
    }
}

/// Reports how the session ended on the console and reboots. Never returns.
pub fn finish(ended: Ended) -> ! {
    let _ = write_console(exit_line(ended).as_bytes());
    reboot_now()
}

/// What the console says when the session outlived `SIGKILL`.
pub const UNENDED_LINE: &str = "boxcar: the session did not end after SIGKILL\n";

/// Says on the console that the session did not end (`vsock` mode, a
/// session stuck in the kernel past `SIGKILL`) and reboots. Never returns.
pub fn finish_unended() -> ! {
    let _ = write_console(UNENDED_LINE.as_bytes());
    reboot_now()
}

/// Drains the console, flushes filesystems and reboots. Never returns.
///
/// If the reboot syscall itself fails (it cannot for PID 1 in the initial
/// namespace), the error goes to the console and init exits, which panics the
/// kernel: loud and terminal, rather than a hang.
pub fn reboot_now() -> ! {
    drain(CONSOLE);
    sync();
    let Err(errno) = reboot(RebootMode::RB_AUTOBOOT);
    let _ = write_console(format!("boxcar-init: reboot failed: {errno}\n").as_bytes());
    std::process::exit(1)
}

/// How a wait for a terminal to send its output ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Drained {
    /// Everything written has gone to the device.
    Empty,
    /// The node could not be opened or is not a terminal: nothing to wait on.
    Unknown,
    /// Output was still queued after [`DRAIN_LIMIT`]: a flow-stopped or
    /// stalled console, which must not hold up the reboot.
    TimedOut,
}

/// Waits until the terminal at `path` has sent everything written to it, or
/// [`DRAIN_LIMIT`] has passed.
///
/// A write to a tty only queues the bytes; the serial driver sends them from
/// its interrupt, so a reboot right after the write can drop them. Unlike
/// `tcdrain`, which waits as long as the queue does, this looks at the queue
/// (`TIOCOUTQ`) every [`DRAIN_STEP`] and gives up at the limit. Best effort:
/// a node that cannot be opened or is not a terminal returns at once.
fn drain(path: &str) -> Drained {
    let Ok(file) = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(path)
    else {
        return Drained::Unknown;
    };
    wait_for_empty(
        || queued(&file),
        Instant::now,
        thread::sleep,
        DRAIN_LIMIT,
        DRAIN_STEP,
    )
}

/// The bytes in the output queue of the terminal `file` (`TIOCOUTQ`), or
/// `None` when it is not a terminal or the call fails.
fn queued(file: &File) -> Option<u32> {
    let mut n: libc::c_int = 0;
    // SAFETY: TIOCOUTQ stores one int through its argument, which points at
    // `n`, alive for the call.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCOUTQ, &mut n) };
    if rc == 0 {
        u32::try_from(n).ok()
    } else {
        None
    }
}

/// Asks `queued` how much output is left until it says 0, sleeping `step`
/// between asks, and gives up once `limit` has passed on `now`. `None` from
/// `queued` ends the wait at once.
fn wait_for_empty(
    mut queued: impl FnMut() -> Option<u32>,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
    limit: Duration,
    step: Duration,
) -> Drained {
    let start = now();
    loop {
        match queued() {
            None => return Drained::Unknown,
            Some(0) => return Drained::Empty,
            Some(_) if now().saturating_duration_since(start) >= limit => return Drained::TimedOut,
            Some(_) => sleep(step),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A clock that moves only when the wait sleeps.
    struct FakeClock {
        start: Instant,
        elapsed: Cell<Duration>,
        sleeps: Cell<u32>,
    }

    impl FakeClock {
        fn new() -> Self {
            FakeClock {
                start: Instant::now(),
                elapsed: Cell::new(Duration::ZERO),
                sleeps: Cell::new(0),
            }
        }

        /// `wait_for_empty` with this clock, the real limit and step, and
        /// the queue sizes `queue` returns in turn (the last one forever).
        fn wait(&self, queue: &[Option<u32>]) -> Drained {
            let mut asks = queue.iter().copied();
            let last = queue.last().copied().flatten();
            wait_for_empty(
                || asks.next().unwrap_or(last),
                || self.start + self.elapsed.get(),
                |step| {
                    self.elapsed.set(self.elapsed.get() + step);
                    self.sleeps.set(self.sleeps.get() + 1);
                },
                DRAIN_LIMIT,
                DRAIN_STEP,
            )
        }
    }

    #[test]
    fn an_empty_queue_ends_the_wait_at_once() {
        let clock = FakeClock::new();
        assert_eq!(clock.wait(&[Some(0)]), Drained::Empty);
        assert_eq!(clock.sleeps.get(), 0);
    }

    #[test]
    fn the_wait_ends_when_the_queue_empties() {
        let clock = FakeClock::new();
        assert_eq!(
            clock.wait(&[Some(30), Some(20), Some(10), Some(0)]),
            Drained::Empty
        );
        assert_eq!(clock.sleeps.get(), 3);
        assert_eq!(clock.elapsed.get(), DRAIN_STEP * 3);
    }

    #[test]
    fn a_queue_that_never_empties_is_given_up_on_at_the_limit() {
        let clock = FakeClock::new();
        assert_eq!(clock.wait(&[Some(5)]), Drained::TimedOut);
        assert_eq!(clock.elapsed.get(), DRAIN_LIMIT);
        assert_eq!(clock.sleeps.get(), 200);
    }

    #[test]
    fn a_node_that_is_not_a_terminal_ends_the_wait_at_once() {
        let clock = FakeClock::new();
        assert_eq!(clock.wait(&[Some(9), None]), Drained::Unknown);
        assert_eq!(clock.sleeps.get(), 1);
    }

    /// The drain before a reboot must never stop the reboot: a node that is
    /// not a terminal, or no node at all, returns at once.
    #[test]
    fn drain_ignores_a_missing_or_non_terminal_console() {
        assert_eq!(drain("/dev/null"), Drained::Unknown);
        assert_eq!(drain("/nonexistent/console"), Drained::Unknown);
    }

    #[test]
    fn the_exit_line_gives_the_code_or_the_signal() {
        assert_eq!(exit_line(Ended::Exited(0)), "boxcar: session exited 0\n");
        assert_eq!(exit_line(Ended::Exited(7)), "boxcar: session exited 7\n");
        assert_eq!(
            exit_line(Ended::Killed(9)),
            "boxcar: session killed by signal 9\n"
        );
    }
}
