// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session: the command init runs on the serial console, as the host
//! user, in a session of its own with `/dev/ttyS0` as its controlling
//! terminal.
//!
//! Everything the child needs is prepared before the fork ([`Exec`]), so
//! that between `fork` and `execve` it only makes system calls on memory
//! that already exists. Init is single-threaded, which is what makes the
//! fork safe at all.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::{iter, ptr};

use boxcar_proto::guestcmd;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::prctl;
use nix::sys::signal::SigSet;
use nix::sys::stat::Mode;
use nix::unistd::{
    chdir, dup2_stderr, dup2_stdin, dup2_stdout, fork, getpid, setgroups, setresgid, setresuid,
    setsid, ForkResult, Gid, Pid, Uid,
};

use crate::console::{warn, write_console, Failed, StackLine, Step};
use crate::mounts::ensure_dir;

/// What runs when the command line names no command: a login shell, which
/// reads `/etc/profile`.
pub const DEFAULT_ARGV: [&str; 2] = ["/bin/sh", "-l"];

/// The session's whole environment.
pub const ENV: [&CStr; 4] = [
    c"HOME=/workspace",
    c"TERM=xterm-256color",
    c"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    c"USER=agent",
];

/// The serial console, which becomes the session's terminal.
const TTY: &CStr = c"/dev/ttyS0";

/// Where the session starts.
const WORKDIR: &CStr = c"/workspace";

/// The cgroups init creates: `system` for init's own helpers, `session` for
/// the session and everything it starts.
pub const CGROUPS: [&str; 2] = ["/sys/fs/cgroup/system", "/sys/fs/cgroup/session"];

/// The file the session child writes its pid to, to join its cgroup.
const SESSION_PROCS: &CStr = c"/sys/fs/cgroup/session/cgroup.procs";

/// The exit status of a session child that could not start its command.
pub const SPAWN_FAILED: i32 = 127;

/// Who the session runs as, and what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub uid: Uid,
    pub gid: Gid,
    pub argv: Vec<String>,
}

impl Session {
    /// The session the `boxcar.*` keys describe: `boxcar.uid` and
    /// `boxcar.gid`, both required, and the command from `boxcar.cmd`
    /// ([`guestcmd::decode`]) or else [`DEFAULT_ARGV`].
    pub fn from_cmdline(args: &BTreeMap<String, String>) -> Result<Session, Failed> {
        let uid = id(args, "uid")?;
        let gid = id(args, "gid")?;
        let argv = match args.get("cmd") {
            Some(cmd) => guestcmd::decode(cmd).step("boxcar.cmd")?,
            None => DEFAULT_ARGV.map(str::to_owned).to_vec(),
        };
        Ok(Session {
            uid: Uid::from_raw(uid),
            gid: Gid::from_raw(gid),
            argv,
        })
    }
}

/// `boxcar.<key>`, a uid or gid in decimal. The all-ones id is refused: to
/// `setresuid` and `setresgid` it means "leave this id alone", which would
/// keep the session root.
fn id(args: &BTreeMap<String, String>, key: &str) -> Result<u32, Failed> {
    let step = format!("boxcar.{key}");
    let value = args.get(key).ok_or_else(|| Failed::new(&step, "not set"))?;
    match value.parse::<u32>() {
        Ok(u32::MAX) => Err(Failed::new(&step, format!("{value:?} is not a usable id"))),
        Ok(id) => Ok(id),
        Err(e) => Err(Failed::new(&step, format!("{value:?}: {e}"))),
    }
}

/// The session's command, ready for `execve` without allocating: the
/// argument strings and the NULL-terminated pointer arrays of the arguments
/// and of [`ENV`] are all built before the fork.
pub struct Exec {
    argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    env_ptrs: Vec<*const libc::c_char>,
}

impl Exec {
    /// `argv` with the environment [`ENV`]. Fails when `argv` is empty or an
    /// argument holds a NUL byte, which `execve` cannot pass.
    pub fn new(argv: &[String]) -> Result<Exec, Failed> {
        if argv.is_empty() {
            return Err(Failed::new("session command", "empty"));
        }
        let argv = argv
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .step("session command")?;
        Ok(Exec {
            argv_ptrs: pointers(argv.iter().map(CString::as_c_str)),
            env_ptrs: pointers(ENV.into_iter()),
            argv,
        })
    }

    /// The program: the first argument.
    fn program(&self) -> &CStr {
        &self.argv[0]
    }

    /// Runs the program in this process, which returns only if that failed.
    fn exec(&self) -> Errno {
        // SAFETY: the path and every pointer of both arrays point at C
        // strings that `self` owns or that are static, and both arrays end
        // with a null pointer.
        unsafe {
            libc::execve(
                self.program().as_ptr(),
                self.argv_ptrs.as_ptr(),
                self.env_ptrs.as_ptr(),
            );
        }
        Errno::last()
    }
}

/// Pointers to each of `strings`, then a null pointer.
fn pointers<'a>(strings: impl Iterator<Item = &'a CStr>) -> Vec<*const libc::c_char> {
    strings
        .map(CStr::as_ptr)
        .chain(iter::once(ptr::null()))
        .collect()
}

/// Step 6: creates [`CGROUPS`]. Returns whether the session can join its
/// cgroup: without `cgroup2` mounted there is none, which gets a warning.
pub fn create_cgroups(cgroup2: bool) -> Result<bool, Failed> {
    if !cgroup2 {
        warn("cgroup2 is not mounted: the session stays in the root cgroup");
        return Ok(false);
    }
    for dir in CGROUPS {
        ensure_dir(dir, 0o755)?;
    }
    Ok(true)
}

/// Step 7: forks the session child and returns its pid. The child sets
/// itself up ([`setup`]) and execs the command; if it cannot, it says why
/// on the console (`boxcar-init: session: <step>: <error>`) and exits with
/// [`SPAWN_FAILED`].
pub fn spawn(session: &Session, exec: &Exec, join_cgroup: bool) -> Result<Pid, Failed> {
    let signals = CleanSignals {
        unblocked: SigSet::empty(),
        sigrtmax: libc::SIGRTMAX(),
    };
    // SAFETY: init is single-threaded, so the child is a whole copy of it
    // with no lock held by a thread that is gone. The child only makes
    // system calls on memory prepared before the fork, then execs or exits.
    match unsafe { fork() }.step("fork")? {
        ForkResult::Parent { child } => Ok(child),
        ForkResult::Child => child(session, exec, join_cgroup, &signals),
    }
}

/// What the child needs, gathered before the fork, to hand the command the
/// signal state of a fresh process: every signal unblocked and at its
/// default action.
struct CleanSignals {
    /// The empty mask.
    unblocked: SigSet,
    /// The highest signal number.
    sigrtmax: libc::c_int,
}

/// A step of the child that failed.
struct ChildFailure {
    step: &'static str,
    errno: Errno,
    /// Whether stderr is the session's terminal yet. Before it is, the
    /// child is still root and reports on `/dev/console`; after, it may no
    /// longer open that and reports on stderr.
    on_tty: bool,
}

/// The session child, from `fork` to `execve`. Never returns.
fn child(session: &Session, exec: &Exec, join_cgroup: bool, signals: &CleanSignals) -> ! {
    let failure = match setup(session, join_cgroup, signals) {
        Ok(()) => ChildFailure {
            step: "execve",
            errno: exec.exec(),
            on_tty: true,
        },
        Err(failure) => failure,
    };
    let mut line = StackLine::new();
    let _ = write!(line, "boxcar-init: session: {}", failure.step);
    if failure.step == "execve" {
        let _ = write!(line, " {}", exec.program().to_str().unwrap_or("?"));
    }
    let _ = write!(line, ": {}", failure.errno);
    let bytes = line.finish();
    if failure.on_tty {
        let _ = nix::unistd::write(std::io::stderr(), bytes);
    } else {
        let _ = write_console(bytes);
    }
    // SAFETY: _exit ends the process at once, running nothing of init's.
    unsafe { libc::_exit(SPAWN_FAILED) }
}

/// The child's setup, in order: a new session; `/dev/ttyS0` as its
/// controlling terminal and as stdin, stdout and stderr; the `session`
/// cgroup; an empty capability bounding set and ambient set; no
/// supplementary groups; the session's gid and uid, real, effective and
/// saved; no new privileges; `/workspace`; then every signal back at its
/// default action and unblocked, since an ignored signal and the mask both
/// survive exec (Rust ignores SIGPIPE in init, and init blocks SIGCHLD for
/// its signalfd).
fn setup(session: &Session, join_cgroup: bool, signals: &CleanSignals) -> Result<(), ChildFailure> {
    let fail = |step: &'static str, on_tty: bool| {
        move |errno: Errno| ChildFailure {
            step,
            errno,
            on_tty,
        }
    };
    setsid().map_err(fail("setsid", false))?;
    // Not O_CLOEXEC: should it land on 0, 1 or 2, dup2 onto itself would
    // leave the flag set and exec would close it.
    let tty = open(TTY, OFlag::O_RDWR | OFlag::O_NOCTTY, Mode::empty())
        .map_err(fail("open /dev/ttyS0", false))?;
    // SAFETY: TIOCSCTTY takes an int by value; 0 refuses to take the
    // terminal from another session.
    if unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCSCTTY, 0) } != 0 {
        return Err(fail("TIOCSCTTY /dev/ttyS0", false)(Errno::last()));
    }
    dup2_stdin(&tty).map_err(fail("dup2 stdin", false))?;
    dup2_stdout(&tty).map_err(fail("dup2 stdout", false))?;
    dup2_stderr(&tty).map_err(fail("dup2 stderr", false))?;
    if tty.as_raw_fd() > 2 {
        drop(tty);
    } else {
        // It is one of 0, 1 and 2 now: keep it open.
        let _ = tty.into_raw_fd();
    }
    if join_cgroup {
        join_session_cgroup().map_err(fail("join the session cgroup", true))?;
    }
    // While still root (dropping needs CAP_SETPCAP). With both sets empty
    // and no inheritable capabilities, no exec grants one again, even when
    // the session's uid is 0.
    drop_bounding_set().map_err(fail("PR_CAPBSET_DROP", true))?;
    clear_ambient_set().map_err(fail("PR_CAP_AMBIENT_CLEAR_ALL", true))?;
    setgroups(&[]).map_err(fail("setgroups", true))?;
    setresgid(session.gid, session.gid, session.gid).map_err(fail("setresgid", true))?;
    setresuid(session.uid, session.uid, session.uid).map_err(fail("setresuid", true))?;
    prctl::set_no_new_privs().map_err(fail("PR_SET_NO_NEW_PRIVS", true))?;
    chdir(WORKDIR).map_err(fail("chdir /workspace", true))?;
    reset_signals(signals.sigrtmax).map_err(fail("reset signal actions", true))?;
    signals
        .unblocked
        .thread_set_mask()
        .map_err(fail("unblock all signals", true))
}

/// Empties the capability bounding set: `PR_CAPBSET_DROP` for each
/// capability from 0 until the kernel answers `EINVAL`, for the first one
/// past the last it knows.
fn drop_bounding_set() -> Result<(), Errno> {
    // The capability sets are 64 bits wide.
    for cap in 0..64 {
        // SAFETY: prctl with integer arguments only.
        let rc = unsafe {
            libc::prctl(
                libc::PR_CAPBSET_DROP,
                cap as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if rc != 0 {
            return match Errno::last() {
                Errno::EINVAL if cap > 0 => Ok(()),
                errno => Err(errno),
            };
        }
    }
    Ok(())
}

/// Empties the ambient capability set.
fn clear_ambient_set() -> Result<(), Errno> {
    // SAFETY: prctl with integer arguments only; the kernel requires the
    // unused ones to be 0.
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Sets every signal from 1 to `sigrtmax` back to its default action,
/// SIGKILL and SIGSTOP aside (they cannot be changed). libc refuses, with
/// `EINVAL`, the few real-time signals it keeps for itself, which init
/// never changes; that is not a failure.
fn reset_signals(sigrtmax: libc::c_int) -> Result<(), Errno> {
    for signal in 1..=sigrtmax {
        if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            continue;
        }
        // SAFETY: SIG_DFL installs no handler; this only changes the
        // action of `signal` in this process.
        if unsafe { libc::signal(signal, libc::SIG_DFL) } == libc::SIG_ERR {
            match Errno::last() {
                Errno::EINVAL => {}
                errno => return Err(errno),
            }
        }
    }
    Ok(())
}

/// Writes this process's pid to the `session` cgroup's `cgroup.procs`.
fn join_session_cgroup() -> Result<(), Errno> {
    let mut pid = StackLine::new();
    let _ = write!(pid, "{}", getpid());
    let pid = pid.finish();
    let procs = open(
        SESSION_PROCS,
        OFlag::O_WRONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    if nix::unistd::write(&procs, pid)? != pid.len() {
        return Err(Errno::EIO);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&a| a.to_owned()).collect()
    }

    #[test]
    fn without_a_command_the_session_is_a_login_shell() {
        let session = Session::from_cmdline(&args(&[
            ("mode", "console"),
            ("uid", "1000"),
            ("gid", "1001"),
        ]))
        .unwrap();
        assert_eq!(
            session,
            Session {
                uid: Uid::from_raw(1000),
                gid: Gid::from_raw(1001),
                argv: strings(&["/bin/sh", "-l"]),
            }
        );
    }

    #[test]
    fn the_command_comes_from_boxcar_cmd() {
        let argv = strings(&["/bin/sh", "-c", "echo hi > /workspace/a.txt"]);
        let cmd = guestcmd::encode(&argv);
        let session =
            Session::from_cmdline(&args(&[("uid", "0"), ("gid", "0"), ("cmd", &cmd)])).unwrap();
        assert_eq!(session.argv, argv);
        assert_eq!(session.uid, Uid::from_raw(0));
    }

    #[test]
    fn a_bad_command_is_refused() {
        let failed =
            Session::from_cmdline(&args(&[("uid", "1"), ("gid", "1"), ("cmd", "!!")])).unwrap_err();
        assert!(failed.to_string().starts_with("boxcar.cmd: "), "{failed}");
    }

    #[test]
    fn uid_and_gid_are_required_decimal_ids() {
        for (pairs, step) in [
            (&[("gid", "1")][..], "boxcar.uid"),
            (&[("uid", "1")][..], "boxcar.gid"),
            (&[("uid", ""), ("gid", "1")][..], "boxcar.uid"),
            (&[("uid", "x"), ("gid", "1")][..], "boxcar.uid"),
            (&[("uid", "-1"), ("gid", "1")][..], "boxcar.uid"),
            (&[("uid", "1"), ("gid", "4294967296")][..], "boxcar.gid"),
        ] {
            let failed = Session::from_cmdline(&args(pairs)).unwrap_err();
            assert!(
                failed.to_string().starts_with(&format!("{step}: ")),
                "{pairs:?}: {failed}"
            );
        }
    }

    /// To setresuid, -1 means "leave this id alone": the session would
    /// stay root.
    #[test]
    fn the_all_ones_id_is_refused() {
        for (pairs, step) in [
            (&[("uid", "4294967295"), ("gid", "1")][..], "boxcar.uid"),
            (&[("uid", "1"), ("gid", "4294967295")][..], "boxcar.gid"),
        ] {
            let failed = Session::from_cmdline(&args(pairs)).unwrap_err();
            assert!(
                failed.to_string().starts_with(&format!("{step}: ")),
                "{failed}"
            );
        }
    }

    #[test]
    fn the_environment_is_exactly_the_four_variables() {
        let env: Vec<&str> = ENV.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            env,
            [
                "HOME=/workspace",
                "TERM=xterm-256color",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "USER=agent",
            ]
        );
    }

    #[test]
    fn the_pointer_arrays_point_at_the_strings_and_end_in_null() {
        let exec = Exec::new(&strings(&["/bin/sh", "-c", "exit 7"])).unwrap();
        assert_eq!(exec.program(), c"/bin/sh");
        let argv: Vec<&CStr> = exec.argv.iter().map(CString::as_c_str).collect();
        for (strings, ptrs) in [(&argv[..], &exec.argv_ptrs), (&ENV[..], &exec.env_ptrs)] {
            assert_eq!(ptrs.len(), strings.len() + 1);
            for (s, &p) in strings.iter().zip(ptrs.iter()) {
                assert_eq!(p, s.as_ptr());
            }
            assert!(ptrs[strings.len()].is_null());
        }
        let argv: Vec<&str> = exec.argv.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(argv, ["/bin/sh", "-c", "exit 7"]);
    }

    /// Whether `signal`'s action in this process is the default one.
    fn is_default(signal: libc::c_int) -> bool {
        // SAFETY: a zeroed sigaction is a valid out-parameter, and a null
        // new action only reads the current one.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_DFL
        }
    }

    /// Rust ignores SIGPIPE in every program, init included, and an ignored
    /// signal stays ignored across execve. In a child, so that the test
    /// harness keeps its own dispositions.
    #[test]
    fn reset_signals_restores_the_default_of_ignored_signals() {
        // SAFETY: the child makes only async-signal-safe calls, then _exits.
        match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                let code = unsafe {
                    libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                    libc::signal(libc::SIGUSR1, libc::SIG_IGN);
                    libc::signal(libc::SIGRTMIN() + 1, libc::SIG_IGN);
                    let reset = reset_signals(libc::SIGRTMAX()).is_ok();
                    let defaults = [libc::SIGPIPE, libc::SIGUSR1, libc::SIGRTMIN() + 1]
                        .into_iter()
                        .all(is_default);
                    match (reset, defaults) {
                        (true, true) => 0,
                        (false, _) => 1,
                        (true, false) => 2,
                    }
                };
                // SAFETY: ends the child without running the harness.
                unsafe { libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).unwrap();
                assert_eq!(
                    status,
                    nix::sys::wait::WaitStatus::Exited(child, 0),
                    "1: reset_signals failed, 2: a signal is still ignored"
                );
            }
        }
    }

    #[test]
    fn an_argument_with_a_nul_or_no_argument_is_refused() {
        assert!(Exec::new(&strings(&["/bin/sh", "a\0b"])).is_err());
        assert!(Exec::new(&[]).is_err());
    }
}
