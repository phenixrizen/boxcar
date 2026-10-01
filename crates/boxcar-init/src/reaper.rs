// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! PID 1's wait for the session: a single-threaded `poll` over a signalfd
//! for `SIGCHLD`, reaping every child, the session and the orphans the
//! kernel hands to init alike.
//!
//! Once the session has ended, the processes it left behind would keep the
//! VM up for as long as they run, so they are asked to stop (`SIGTERM`) and,
//! after [`GRACE`], made to (`SIGKILL`). Init returns when no child is left,
//! or, should some outlive even `SIGKILL` (stuck in the kernel), after
//! [`KILL_WAIT`] with `boxcar-init: reaper: stragglers remain, rebooting` on
//! the console.

use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{kill, SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::unistd::Pid;

use crate::console::{warn, write_console, Failed, Step};
use crate::session::Terminal;

/// How long the processes the session leaves behind have between `SIGTERM`
/// and `SIGKILL`.
pub const GRACE: Duration = Duration::from_secs(2);

/// How long init waits, after `SIGKILL`, for the last of them before it
/// reboots anyway.
pub const KILL_WAIT: Duration = Duration::from_secs(10);

/// What init says when it stops waiting for them.
const GAVE_UP: &[u8] = b"boxcar-init: reaper: stragglers remain, rebooting\n";

/// How the session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited with this status.
    Exited(i32),
    /// This signal killed it.
    Killed(i32),
}

/// The signalfd init waits on.
pub struct Reaper {
    signals: SignalFd,
}

impl Reaper {
    /// Blocks `SIGCHLD`, so that it queues for the signalfd instead of being
    /// delivered, and opens the signalfd. Before the fork, so that a child
    /// that ends at once is still seen.
    pub fn new() -> Result<Reaper, Failed> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGCHLD);
        mask.thread_block().step("block SIGCHLD")?;
        let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
            .step("signalfd SIGCHLD")?;
        Ok(Reaper { signals })
    }

    /// Step 8: reaps children until `session` has ended and none is left,
    /// and returns how the session ended. As soon as the session has ended,
    /// init takes the foreground of `terminal` back, before it writes a
    /// line of its own.
    pub fn wait(&self, session: Pid, terminal: &Terminal) -> Result<Ended, Failed> {
        let mut ended = None;
        let mut phase = Phase::Session;
        loop {
            let left = reap_ready(session, &mut ended, wait_any).step("waitpid")?;
            // The phase moves on from Session at the first reap that saw
            // the session end, so this runs once.
            if ended.is_some() && phase == Phase::Session {
                terminal.take_foreground();
            }
            if left == Left::None {
                return ended.ok_or_else(|| {
                    Failed::new("waitpid", "no child is left and the session was not seen")
                });
            }
            if let Some(how) = ended {
                let (next, action) = phase.after_session(Instant::now());
                phase = next;
                match action {
                    Action::Wait => {}
                    Action::Signal(signal) => signal_all(signal),
                    Action::GiveUp => {
                        let _ = write_console(GAVE_UP);
                        return Ok(how);
                    }
                }
            }
            let mut fds = [PollFd::new(self.signals.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, phase.timeout(Instant::now())) {
                Ok(_) | Err(Errno::EINTR) => {}
                Err(errno) => return Err(Failed::new("poll", errno)),
            }
            // SIGCHLDs coalesce, so their count means nothing: empty the
            // signalfd and let the next reap take every child that ended.
            loop {
                match self.signals.read_signal() {
                    Ok(Some(_)) | Err(Errno::EINTR) => {}
                    Ok(None) => break,
                    Err(errno) => return Err(Failed::new("read signalfd", errno)),
                }
            }
        }
    }
}

/// Where the wait is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The session runs: wait for as long as it does.
    Session,
    /// The session has ended and the rest were sent `SIGTERM`; at
    /// `deadline` they get `SIGKILL`.
    Terminating { deadline: Instant },
    /// `SIGKILL` was sent: wait for the last of them until `deadline`.
    Killing { deadline: Instant },
}

/// What the wait does next, once the session has ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    /// Keep reaping.
    Wait,
    /// Send this to every process but init.
    Signal(Signal),
    /// Stop waiting: what is left survived `SIGKILL` for [`KILL_WAIT`].
    GiveUp,
}

impl Phase {
    /// With the session ended and children left: the next phase, and what
    /// to do now.
    fn after_session(self, now: Instant) -> (Phase, Action) {
        match self {
            Phase::Session => (
                Phase::Terminating {
                    deadline: now + GRACE,
                },
                Action::Signal(Signal::SIGTERM),
            ),
            Phase::Terminating { deadline } if now >= deadline => (
                Phase::Killing {
                    deadline: now + KILL_WAIT,
                },
                Action::Signal(Signal::SIGKILL),
            ),
            Phase::Killing { deadline } if now >= deadline => (self, Action::GiveUp),
            phase => (phase, Action::Wait),
        }
    }

    /// How long to wait for the next `SIGCHLD`: until the phase's deadline
    /// (rounded up to the millisecond, so that it has passed when the poll
    /// times out), and while the session runs for as long as it takes.
    fn timeout(self, now: Instant) -> PollTimeout {
        match self {
            Phase::Terminating { deadline } | Phase::Killing { deadline } => {
                let left = deadline.saturating_duration_since(now);
                PollTimeout::try_from(left.as_nanos().div_ceil(1_000_000))
                    .unwrap_or(PollTimeout::MAX)
            }
            Phase::Session => PollTimeout::NONE,
        }
    }
}

/// Sends `signal` to every process but init (`kill(-1, ..)`). None left to
/// signal is fine; any other failure gets a warning.
fn signal_all(signal: Signal) {
    match kill(Pid::from_raw(-1), signal) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(errno) => warn(&format!("kill -1 {signal}: {errno}")),
    }
}

/// Whether children are left after a reap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Left {
    Some,
    None,
}

/// Reaps every child that has ended, taking each from `wait`
/// (`waitpid(-1, WNOHANG)`), and records in `ended` how `session` ended
/// when it is among them. Returns whether children are left.
fn reap_ready(
    session: Pid,
    ended: &mut Option<Ended>,
    mut wait: impl FnMut() -> Result<Option<(Pid, Ended)>, Errno>,
) -> Result<Left, Errno> {
    loop {
        match wait() {
            Ok(Some((pid, how))) => {
                if pid == session {
                    *ended = Some(how);
                }
            }
            Ok(None) => return Ok(Left::Some),
            Err(Errno::EINTR) => {}
            Err(Errno::ECHILD) => return Ok(Left::None),
            Err(errno) => return Err(errno),
        }
    }
}

/// `waitpid(-1, WNOHANG)`: one child that has ended, reaped, with how it
/// ended; `None` while children are left but none has ended. Called on
/// libc directly because nix fails the call, after the child is already
/// reaped, when a real-time signal killed it.
fn wait_any() -> Result<Option<(Pid, Ended)>, Errno> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid stores the status through the pointer, which points at
    // `status`, alive for the call.
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    match pid {
        0 => Ok(None),
        pid if pid < 0 => Err(Errno::last()),
        // Without WUNTRACED or WCONTINUED, only children that ended.
        pid if libc::WIFEXITED(status) => Ok(Some((
            Pid::from_raw(pid),
            Ended::Exited(libc::WEXITSTATUS(status)),
        ))),
        pid => Ok(Some((
            Pid::from_raw(pid),
            Ended::Killed(libc::WTERMSIG(status)),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: Pid = Pid::from_raw(42);

    /// `reap_ready` over `script`, one `wait` result per call.
    fn reap(
        script: Vec<Result<Option<(Pid, Ended)>, Errno>>,
        ended: &mut Option<Ended>,
    ) -> (Result<Left, Errno>, usize) {
        let mut script = script.into_iter();
        let mut calls = 0;
        let left = reap_ready(SESSION, ended, || {
            calls += 1;
            script.next().expect("reap_ready waited past the script")
        });
        (left, calls)
    }

    fn orphan(pid: i32, code: i32) -> Result<Option<(Pid, Ended)>, Errno> {
        Ok(Some((Pid::from_raw(pid), Ended::Exited(code))))
    }

    #[test]
    fn every_ready_child_is_reaped_and_the_session_is_remembered() {
        let mut ended = None;
        let (left, calls) = reap(
            vec![
                orphan(7, 1),
                Ok(Some((SESSION, Ended::Exited(3)))),
                orphan(8, 0),
                Ok(None),
            ],
            &mut ended,
        );
        assert_eq!(left, Ok(Left::Some));
        assert_eq!(calls, 4);
        assert_eq!(ended, Some(Ended::Exited(3)));
    }

    #[test]
    fn orphans_do_not_count_as_the_session() {
        let mut ended = None;
        let (left, _) = reap(vec![orphan(7, 0), orphan(9, 0), Ok(None)], &mut ended);
        assert_eq!(left, Ok(Left::Some));
        assert_eq!(ended, None);
    }

    #[test]
    fn no_children_left_ends_the_reap() {
        let mut ended = None;
        let (left, _) = reap(
            vec![
                Ok(Some((SESSION, Ended::Killed(9)))),
                orphan(7, 0),
                Err(Errno::ECHILD),
            ],
            &mut ended,
        );
        assert_eq!(left, Ok(Left::None));
        assert_eq!(ended, Some(Ended::Killed(9)));
    }

    #[test]
    fn an_interrupted_wait_is_retried_and_other_errors_returned() {
        let mut ended = None;
        let (left, calls) = reap(vec![Err(Errno::EINTR), Ok(None)], &mut ended);
        assert_eq!((left, calls), (Ok(Left::Some), 2));
        let (left, _) = reap(vec![Err(Errno::EINVAL)], &mut ended);
        assert_eq!(left, Err(Errno::EINVAL));
    }

    /// A clock for the phases: `at(ms)` is `ms` milliseconds after the
    /// session ended.
    fn clock() -> impl Fn(u64) -> Instant {
        let start = Instant::now();
        move |ms| start + Duration::from_millis(ms)
    }

    fn millis(ms: u32) -> PollTimeout {
        PollTimeout::try_from(ms).unwrap()
    }

    #[test]
    fn the_session_ending_sends_sigterm_and_starts_the_grace() {
        let at = clock();
        assert_eq!(
            Phase::Session.after_session(at(0)),
            (
                Phase::Terminating { deadline: at(2000) },
                Action::Signal(Signal::SIGTERM)
            )
        );
    }

    /// The whole sweep on the clock: SIGTERM at once, SIGKILL after the
    /// grace, and giving up KILL_WAIT after that, waiting in between.
    #[test]
    fn the_sweep_sends_sigterm_then_sigkill_then_gives_up() {
        let at = clock();
        let mut phase = Phase::Session;
        let mut actions = Vec::new();
        for ms in [0, 1, 1999, 2000, 2001, 11_999, 12_000] {
            let (next, action) = phase.after_session(at(ms));
            phase = next;
            actions.push((ms, action, phase.timeout(at(ms))));
        }
        assert_eq!(
            actions,
            [
                (0, Action::Signal(Signal::SIGTERM), millis(2000)),
                (1, Action::Wait, millis(1999)),
                (1999, Action::Wait, millis(1)),
                (2000, Action::Signal(Signal::SIGKILL), millis(10_000)),
                (2001, Action::Wait, millis(9999)),
                (11_999, Action::Wait, millis(1)),
                (12_000, Action::GiveUp, PollTimeout::ZERO),
            ]
        );
        assert_eq!(GRACE, Duration::from_secs(2));
        assert_eq!(KILL_WAIT, Duration::from_secs(10));
    }

    #[test]
    fn sigkill_is_sent_only_once_and_giving_up_repeats() {
        let at = clock();
        let killing = Phase::Killing {
            deadline: at(10_000),
        };
        assert_eq!(killing.after_session(at(5000)), (killing, Action::Wait));
        assert_eq!(killing.after_session(at(10_000)), (killing, Action::GiveUp));
        assert_eq!(killing.after_session(at(20_000)), (killing, Action::GiveUp));
    }

    #[test]
    fn the_poll_waits_for_ever_only_while_the_session_runs() {
        let at = clock();
        assert_eq!(Phase::Session.timeout(at(0)), PollTimeout::NONE);
        let deadline = at(0) + Duration::from_micros(1500);
        for phase in [Phase::Terminating { deadline }, Phase::Killing { deadline }] {
            assert_eq!(phase.timeout(at(0)), millis(2), "{phase:?}");
            assert_eq!(phase.timeout(deadline), PollTimeout::ZERO, "{phase:?}");
            assert_eq!(phase.timeout(at(5000)), PollTimeout::ZERO, "{phase:?}");
        }
    }

    #[test]
    fn the_give_up_line() {
        assert_eq!(
            GAVE_UP,
            b"boxcar-init: reaper: stragglers remain, rebooting\n"
        );
    }
}
