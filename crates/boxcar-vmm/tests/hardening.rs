// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The seccomp filter and the Landlock domain, each in a forked child: a
//! filter or a domain cannot be taken back, and the child starts with one
//! thread, so each test knows exactly which threads ran before.
//!
//! A child reports through its exit code: 0 when everything went as the
//! test expects, 77 when the kernel cannot run the test (no Landlock, or
//! no `LANDLOCK_RESTRICT_SELF_TSYNC`), anything else when something went
//! wrong; a signal that ends it comes back as 128 plus its number.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::panic;
use std::path::Path;
use std::thread;
use std::time::Duration;

use boxcar_vmm::hardening::domain::{self, LandlockStatus, Options, Reach, Rule};
use boxcar_vmm::hardening::seccomp::{self, SeccompMode};

/// The exit code of a child the kernel cannot run.
const SKIP: i32 = 77;

fn fork_child(body: impl FnOnce() -> i32) -> libc::pid_t {
    // SAFETY: the child runs only `body` and exits with `_exit`.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // SAFETY: plain calls with no pointers.
        unsafe {
            libc::alarm(30);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }
        let code = panic::catch_unwind(panic::AssertUnwindSafe(body)).unwrap_or(99);
        // SAFETY: ends the child without running the parent's destructors.
        unsafe { libc::_exit(code) };
    }
    child
}

fn wait_child(child: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: `status` is a valid out pointer.
    unsafe { libc::waitpid(child, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    }
}

/// Runs `body` in a forked child and returns how it ended, or `None` after
/// saying why when the kernel could not run it.
fn in_child(test: &str, body: impl FnOnce() -> i32) -> Option<i32> {
    match wait_child(fork_child(body)) {
        SKIP => {
            eprintln!("{test}: skipped: this kernel cannot run it");
            None
        }
        code => Some(code),
    }
}

fn pipe() -> (File, File) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` has room for both ends.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: pipe2 just made both, and nothing else owns them.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    (File::from(read), File::from(write))
}

/// A call off the allowlist, harmless anywhere else.
fn off_the_list() -> libc::c_long {
    // SAFETY: getppid takes no arguments.
    unsafe { libc::syscall(libc::SYS_getppid) }
}

/// A call off the list kills the whole process with `SIGSYS`.
#[test]
fn a_call_off_the_list_kills_the_process() {
    let code = in_child("a_call_off_the_list_kills_the_process", || {
        seccomp::install(SeccompMode::Enforce).unwrap();
        off_the_list();
        1
    });
    assert_eq!(code, Some(128 + libc::SIGSYS));
}

/// In `log`, the same call returns, and the process goes on.
#[test]
fn in_log_a_call_off_the_list_returns() {
    let code = in_child("in_log_a_call_off_the_list_returns", || {
        seccomp::install(SeccompMode::Log).unwrap();
        i32::from(off_the_list() <= 0)
    });
    assert_eq!(code, Some(0));
}

/// A thread that ran before the filter has it too (`TSYNC`): released
/// after the install, its call off the list kills the process.
#[test]
fn a_thread_that_ran_before_the_filter_has_it() {
    let code = in_child("a_thread_that_ran_before_the_filter_has_it", || {
        let (mut wait, mut release) = pipe();
        let sibling = thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = wait.read(&mut byte);
            off_the_list();
        });
        seccomp::install(SeccompMode::Enforce).unwrap();
        release.write_all(b"!").unwrap();
        let _ = sibling.join();
        1
    });
    assert_eq!(code, Some(128 + libc::SIGSYS));
}

/// Threads start under the filter: `clone3` is answered `ENOSYS`, and
/// glibc falls back to `clone`, which the filter allows for threads.
#[test]
fn threads_start_under_the_filter() {
    let code = in_child("threads_start_under_the_filter", || {
        seccomp::install(SeccompMode::Enforce).unwrap();
        // SAFETY: with a null argument and a zero size, a kernel that ran
        // clone3 would refuse it; the filter answers first.
        let res = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
        if res != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return 2;
        }
        let threads: Vec<_> = (0..4).map(|n| thread::spawn(move || n * 2)).collect();
        let sum: i32 = threads.into_iter().map(|t| t.join().unwrap_or(-100)).sum();
        i32::from(sum != 12)
    });
    assert_eq!(code, Some(0));
}

/// A thread whose name says its role, started once the process list is in,
/// is confined to that role's list at its start, through the hook the mode
/// sets: a virtio-fs queue cannot open a socket, and the process dies for it.
#[test]
fn a_thread_is_confined_to_its_role() {
    let code = in_child("a_thread_is_confined_to_its_role", || {
        seccomp::set_mode(SeccompMode::Enforce);
        seccomp::install(SeccompMode::Enforce).unwrap();
        let worker = thread::Builder::new()
            .name("fs-root-q1".into())
            .spawn(|| {
                boxcar_confine::at_thread_start();
                // SAFETY: plain arguments; the filter answers first.
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) }
            })
            .unwrap();
        let _ = worker.join();
        1
    });
    assert_eq!(code, Some(128 + libc::SIGSYS));
}

/// The same under `log`: the call returns and the thread goes on.
#[test]
fn in_log_a_thread_off_its_role_goes_on() {
    let code = in_child("in_log_a_thread_off_its_role_goes_on", || {
        seccomp::set_mode(SeccompMode::Log);
        seccomp::install(SeccompMode::Log).unwrap();
        let worker = thread::Builder::new()
            .name("fs-root-q1".into())
            .spawn(|| {
                boxcar_confine::at_thread_start();
                // SAFETY: plain arguments.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                if fd >= 0 {
                    // SAFETY: a descriptor this thread opened.
                    unsafe { libc::close(fd) };
                }
                fd >= 0
            })
            .unwrap();
        i32::from(!worker.join().unwrap_or(false))
    });
    assert_eq!(code, Some(0));
}

/// A thread's role takes nothing from another's: the net thread keeps its
/// sockets and loses files, which the queue thread keeps. A thread with no
/// role (a vCPU's name) is left to the process list. The net thread's open
/// fails (`EACCES`) and the process goes on.
#[test]
fn each_role_keeps_its_own_calls() {
    let code = in_child("each_role_keeps_its_own_calls", || {
        seccomp::set_mode(SeccompMode::Enforce);
        seccomp::install(SeccompMode::Enforce).unwrap();
        let opens = |name: &str| {
            thread::Builder::new()
                .name(name.into())
                .spawn(|| {
                    boxcar_confine::at_thread_start();
                    File::open("/proc/self/stat").is_ok()
                })
                .unwrap()
                .join()
                .unwrap_or(false)
        };
        let sockets = |name: &str| {
            thread::Builder::new()
                .name(name.into())
                .spawn(|| {
                    boxcar_confine::at_thread_start();
                    // SAFETY: plain arguments.
                    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                    if fd >= 0 {
                        // SAFETY: a descriptor this thread opened.
                        unsafe { libc::close(fd) };
                    }
                    fd >= 0
                })
                .unwrap()
                .join()
                .unwrap_or(false)
        };
        if !opens("fs-workspace-q1") || !sockets("net") || !opens("vcpu0") || !sockets("vcpu0") {
            return 2;
        }
        // The net thread, given a file: the open fails, the process goes on.
        if opens("net") {
            return 3;
        }
        0
    });
    assert_eq!(code, Some(0));
}

/// glibc's own lazy read on a thread that opens no files: the open fails
/// with `EACCES` and the thread, and the process, go on.
#[test]
fn a_role_without_files_gets_eacces_for_an_open() {
    let code = in_child("a_role_without_files_gets_eacces_for_an_open", || {
        seccomp::set_mode(SeccompMode::Enforce);
        seccomp::install(SeccompMode::Enforce).unwrap();
        let worker = thread::Builder::new()
            .name("net".into())
            .spawn(|| {
                boxcar_confine::at_thread_start();
                // SAFETY: a valid path and flags; the filter answers first.
                let fd = unsafe {
                    libc::openat(
                        libc::AT_FDCWD,
                        c"/proc/sys/vm/overcommit_memory".as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC,
                    )
                };
                let errno = io::Error::last_os_error().raw_os_error();
                if fd >= 0 {
                    // SAFETY: a descriptor this thread opened.
                    unsafe { libc::close(fd) };
                    return 2;
                }
                if errno == Some(libc::EACCES) {
                    0
                } else {
                    3
                }
            })
            .unwrap();
        worker.join().unwrap_or(4)
    });
    assert_eq!(code, Some(0));
}

/// A thread started before the process list is in keeps that list alone
/// once it comes, by `TSYNC`, and the install does not fail for it: its
/// role's filter is not added first. The thread says when it has started
/// (its hook ran with no process list to add a role to), and the install
/// waits for that: a thread scheduled late would otherwise start under
/// the list and take its role's filter, which the test is not about.
#[test]
fn a_thread_started_before_the_process_list_keeps_it_alone() {
    let code = in_child(
        "a_thread_started_before_the_process_list_keeps_it_alone",
        || {
            seccomp::set_mode(SeccompMode::Enforce);
            let (mut wait, mut release) = pipe();
            let (mut started, mut start) = pipe();
            let early = thread::Builder::new()
                .name("fs-root-q1".into())
                .spawn(move || {
                    boxcar_confine::at_thread_start();
                    start.write_all(b"!").unwrap();
                    let mut byte = [0u8; 1];
                    let _ = wait.read(&mut byte);
                    // On the process list, which allows a socket; its role's
                    // list, had it been added, would not.
                    // SAFETY: plain arguments.
                    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                    if fd >= 0 {
                        // SAFETY: a descriptor this thread opened.
                        unsafe { libc::close(fd) };
                    }
                    fd >= 0
                })
                .unwrap();
            let mut byte = [0u8; 1];
            started.read_exact(&mut byte).unwrap();
            if seccomp::install(SeccompMode::Enforce).is_err() {
                return 2;
            }
            release.write_all(b"!").unwrap();
            i32::from(!early.join().unwrap_or(false))
        },
    );
    assert_eq!(code, Some(0));
}

/// A process, unlike a thread, cannot be started: `fork` is a `clone`
/// without `CLONE_THREAD`.
#[test]
fn a_process_cannot_be_started() {
    let code = in_child("a_process_cannot_be_started", || {
        seccomp::install(SeccompMode::Enforce).unwrap();
        // SAFETY: if the fork went through, the grandchild exits at once.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: ends the grandchild.
            unsafe { libc::_exit(0) };
        }
        3
    });
    assert_eq!(code, Some(128 + libc::SIGSYS));
}

/// `abort` under the filter ends the process as an abort, not as a kill:
/// its `tgkill` to itself is allowed.
#[test]
fn abort_is_an_abort() {
    let code = in_child("abort_is_an_abort", || {
        seccomp::install(SeccompMode::Enforce).unwrap();
        // SAFETY: ends the child.
        unsafe { libc::abort() }
    });
    assert_eq!(code, Some(128 + libc::SIGABRT));
}

/// Opens `path` for reading: 0 when it opens, the errno when it does not.
fn open_errno(path: &Path) -> i32 {
    match File::open(path) {
        Ok(_) => 0,
        Err(error) => error.raw_os_error().unwrap_or(-1),
    }
}

/// A directory with a file in it, and another file outside it.
fn inside_and_outside() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let allowed = root.path().join("allowed");
    fs::create_dir(&allowed).unwrap();
    let inside = allowed.join("in");
    let outside = root.path().join("out");
    fs::write(&inside, "in").unwrap();
    fs::write(&outside, "out").unwrap();
    (root, inside, outside)
}

/// Applies a domain that allows only the directory holding `inside`,
/// exiting the child as skipped when the kernel has no Landlock.
fn confine_to(inside: &Path, options: Options) -> Result<LandlockStatus, domain::DomainError> {
    let allowed = inside.parent().unwrap();
    let status = domain::apply(&[Rule::new(allowed, Reach::Tree)], options)?;
    if status == LandlockStatus::Unsupported {
        // SAFETY: ends the child as skipped.
        unsafe { libc::_exit(SKIP) };
    }
    Ok(status)
}

/// A thread started after the domain cannot open a file outside it, and
/// can open one inside.
#[test]
fn a_thread_started_after_the_domain_is_confined() {
    let (_root, inside, outside) = inside_and_outside();
    let code = in_child("a_thread_started_after_the_domain_is_confined", move || {
        confine_to(&inside, Options::default()).unwrap();
        let worker = thread::spawn(move || (open_errno(&outside), open_errno(&inside)));
        match worker.join() {
            Ok((libc::EACCES, 0)) => 0,
            Ok(_) => 4,
            Err(_) => 5,
        }
    });
    if let Some(code) = code {
        assert_eq!(code, 0);
    }
}

/// With `LANDLOCK_RESTRICT_SELF_TSYNC` (ABI 8), a thread that ran before
/// the domain is confined too.
#[test]
fn a_thread_that_ran_before_the_domain_is_confined_with_tsync() {
    let (_root, inside, outside) = inside_and_outside();
    let code = in_child(
        "a_thread_that_ran_before_the_domain_is_confined_with_tsync",
        move || {
            if domain::kernel_abi() < 8 {
                return SKIP;
            }
            let (mut wait, mut release) = pipe();
            let sibling = thread::spawn(move || {
                let mut byte = [0u8; 1];
                let _ = wait.read(&mut byte);
                open_errno(&outside)
            });
            confine_to(&inside, Options::default()).unwrap();
            release.write_all(b"!").unwrap();
            match sibling.join() {
                Ok(libc::EACCES) => 0,
                Ok(_) => 6,
                Err(_) => 7,
            }
        },
    );
    if let Some(code) = code {
        assert_eq!(code, 0);
    }
}

/// Without TSYNC, the domain waits for a thread that ran before it to
/// end, then applies.
#[test]
fn without_tsync_the_domain_waits_for_other_threads_to_end() {
    let (_root, inside, _outside) = inside_and_outside();
    let code = in_child(
        "without_tsync_the_domain_waits_for_other_threads_to_end",
        move || {
            let _sibling = thread::spawn(|| thread::sleep(Duration::from_millis(200)));
            let options = Options {
                tsync: false,
                thread_wait: Duration::from_secs(5),
            };
            // `apply` returns only once this is the only thread (the
            // domain then refuses `/proc/self/task` itself).
            match confine_to(&inside, options) {
                Ok(_) => 0,
                Err(_) => 9,
            }
        },
    );
    if let Some(code) = code {
        assert_eq!(code, 0);
    }
}

/// Without TSYNC, a thread that outlives the wait fails the domain, and
/// the process is left as it was.
#[test]
fn without_tsync_a_thread_that_does_not_end_fails_the_domain() {
    let (_root, inside, outside) = inside_and_outside();
    let code = in_child(
        "without_tsync_a_thread_that_does_not_end_fails_the_domain",
        move || {
            if domain::kernel_abi() < 2 {
                return SKIP;
            }
            let (mut wait, _keep) = pipe();
            let _sibling = thread::spawn(move || {
                let mut byte = [0u8; 1];
                let _ = wait.read(&mut byte);
            });
            let options = Options {
                tsync: false,
                thread_wait: Duration::from_millis(100),
            };
            match confine_to(&inside, options) {
                Err(domain::DomainError::Threads { threads: 2, .. }) => {
                    i32::from(open_errno(&outside) != 0) * 10
                }
                _ => 11,
            }
        },
    );
    if let Some(code) = code {
        assert_eq!(code, 0);
    }
}
