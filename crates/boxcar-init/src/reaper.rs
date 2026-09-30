// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! PID 1's wait for the session: a single-threaded `poll` over a signalfd
//! for `SIGCHLD`, reaping every child, the session and the orphans the
//! kernel hands to init alike.
//!
//! Once the session has ended, the processes it left behind would keep the
//! VM up for as long as they run, so they are asked to stop (`SIGTERM`) and,
//! after [`GRACE`], made to (`SIGKILL`). Init returns when no child is left.

use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{kill, SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::unistd::Pid;

use crate::console::{warn, Failed, Step};

/// How long the processes the session leaves behind have between `SIGTERM`
/// and `SIGKILL`.
pub const GRACE: Duration = Duration::from_secs(2);

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
    /// and returns how the session ended.
    pub fn wait(&self, session: Pid) -> Result<Ended, Failed> {
        let mut ended = None;
        let mut phase = Phase::Session;
        loop {
            if reap_ready(session, &mut ended, wait_any).step("waitpid")? == Left::None {
                return ended.ok_or_else(|| {
                    Failed::new("waitpid", "no child is left and the session was not seen")
                });
            }
            if ended.is_some() {
                let (next, signal) = phase.after_session(Instant::now());
                if let Some(signal) = signal {
                    signal_all(signal);
                }
                phase = next;
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
    /// `SIGKILL` was sent: wait for the last of them.
    Killing,
}

impl Phase {
    /// With the session ended and children left: the next phase, and the
    /// signal to send every other process now, if any.
    fn after_session(self, now: Instant) -> (Phase, Option<Signal>) {
        match self {
            Phase::Session => (
                Phase::Terminating {
                    deadline: now + GRACE,
                },
                Some(Signal::SIGTERM),
            ),
            Phase::Terminating { deadline } if now >= deadline => {
                (Phase::Killing, Some(Signal::SIGKILL))
            }
            phase => (phase, None),
        }
    }

    /// How long to wait for the next `SIGCHLD`: until the deadline while
    /// terminating (rounded up to the millisecond, so that it has passed
    /// when the poll times out), and otherwise for as long as it takes.
    fn timeout(self, now: Instant) -> PollTimeout {
        match self {
            Phase::Terminating { deadline } => {
                let left = deadline.saturating_duration_since(now);
                PollTimeout::try_from(left.as_nanos().div_ceil(1_000_000))
                    .unwrap_or(PollTimeout::MAX)
            }
            Phase::Session | Phase::Killing => PollTimeout::NONE,
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

    #[test]
    fn the_session_ending_sends_sigterm_and_starts_the_grace() {
        let now = Instant::now();
        assert_eq!(
            Phase::Session.after_session(now),
            (
                Phase::Terminating {
                    deadline: now + GRACE
                },
                Some(Signal::SIGTERM)
            )
        );
    }

    #[test]
    fn sigkill_follows_at_the_deadline_and_only_once() {
        let now = Instant::now();
        let terminating = Phase::Terminating { deadline: now };
        let before = now - Duration::from_millis(1);
        assert_eq!(terminating.after_session(before), (terminating, None));
        assert_eq!(
            terminating.after_session(now),
            (Phase::Killing, Some(Signal::SIGKILL))
        );
        assert_eq!(Phase::Killing.after_session(now), (Phase::Killing, None));
    }

    #[test]
    fn the_poll_waits_for_ever_except_until_the_deadline() {
        let now = Instant::now();
        assert_eq!(Phase::Session.timeout(now), PollTimeout::NONE);
        assert_eq!(Phase::Killing.timeout(now), PollTimeout::NONE);
        let deadline = now + Duration::from_micros(1500);
        let terminating = Phase::Terminating { deadline };
        assert_eq!(terminating.timeout(now), PollTimeout::from(2u8));
        assert_eq!(terminating.timeout(deadline), PollTimeout::ZERO);
        assert_eq!(
            terminating.timeout(deadline + Duration::from_secs(1)),
            PollTimeout::ZERO
        );
    }
}
