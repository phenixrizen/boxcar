// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `RawModeGuard::enter` looks at the foreground right before it writes the
//! raw settings and again right after. This test makes the process move to
//! the background exactly between the two: the terminal must come back as
//! it was, the guard must be `None`, and the process must not be stopped.
//!
//! The move is made by interposing `tcsetattr`: this test binary defines
//! the symbol, so the VMM's calls (through the `libc` crate) land here
//! first and go on to the real one through `dlsym(RTLD_NEXT, ..)`. The job
//! arms the interposer once; on that write it asks the forked "shell" (the
//! session leader, with `SIGTTOU` blocked as a shell has it) to take the
//! terminal back, waits for its word, and then performs the write, which
//! the kernel lets through because `Tty::take` blocks `SIGTTOU` around it.
//!
//! The control in the same harness: a plain `tcsetattr` from the background
//! with `SIGTTOU` unblocked is stopped by the kernel, so the harness really
//! puts the job in the background of a controlling terminal.

use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::raw::{c_int, c_void};
use std::panic;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use boxcar_vmm::stdin::{block_job_control_signals, is_foreground, RawModeGuard};

type TcsetattrFn = unsafe extern "C" fn(c_int, c_int, *const libc::termios) -> c_int;

/// Armed: on the next `tcsetattr`, hand the terminal to the shell first.
static HAND_OVER: AtomicBool = AtomicBool::new(false);
/// The job's end of the pipes to the shell: the request, and the shell's
/// acknowledgement.
static REQUEST_FD: AtomicI32 = AtomicI32::new(-1);
static ACK_FD: AtomicI32 = AtomicI32::new(-1);

/// The C library's `tcsetattr`, which this binary's definition shadows.
fn real_tcsetattr() -> TcsetattrFn {
    // SAFETY: a NUL-terminated literal; dlsym only reads it.
    let symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, c"tcsetattr".as_ptr()) };
    assert!(!symbol.is_null(), "no tcsetattr after this one");
    // SAFETY: the symbol is libc's tcsetattr, which has this signature.
    unsafe { std::mem::transmute::<*mut c_void, TcsetattrFn>(symbol) }
}

/// The interposed `tcsetattr`: every write of terminal settings in this
/// binary comes here. Armed ([`HAND_OVER`]), it moves this process to the
/// background first.
///
/// # Safety
///
/// As `tcsetattr(3)`: `termios` points to a readable `termios`.
#[no_mangle]
pub unsafe extern "C" fn tcsetattr(
    fd: c_int,
    actions: c_int,
    termios: *const libc::termios,
) -> c_int {
    if HAND_OVER.swap(false, Ordering::SeqCst) {
        let request = REQUEST_FD.load(Ordering::SeqCst);
        let ack = ACK_FD.load(Ordering::SeqCst);
        let mut byte = [0u8; 1];
        // SAFETY: both descriptors are the pipes the job set up; one byte
        // each way.
        unsafe {
            libc::write(request, b"!".as_ptr().cast(), 1);
            libc::read(ack, byte.as_mut_ptr().cast(), 1);
        }
    }
    // SAFETY: the caller's contract is tcsetattr's.
    unsafe { real_tcsetattr()(fd, actions, termios) }
}

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

/// A pipe, as its two ends.
fn pipe() -> (File, File) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two new descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both are ours, just made, owned once each.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    (File::from(read), File::from(write))
}

/// Forks a child that runs `body` and leaves with its result as its exit
/// code (99 if it panicked). `SIGALRM` ends it after 30 s, and so does the
/// end of its parent.
fn fork_child(body: impl FnOnce() -> i32) -> libc::pid_t {
    // SAFETY: the child runs `body` and leaves with _exit, never returning
    // into the test harness.
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

/// The calling process becomes a session leader whose controlling terminal
/// is `terminal`, like a shell.
fn become_a_shell(terminal: RawFd) -> bool {
    // SAFETY: plain system calls.
    unsafe { libc::setsid() >= 0 && libc::ioctl(terminal, libc::TIOCSCTTY, 0) >= 0 }
}

fn get_termios(fd: RawFd) -> Option<libc::termios> {
    // SAFETY: termios is plain data; all zeroes is valid.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes one termios into `termios`.
    (unsafe { libc::tcgetattr(fd, &mut termios) } == 0).then_some(termios)
}

/// The fields `tcsetattr` writes, equal.
fn same_settings(a: &libc::termios, b: &libc::termios) -> bool {
    a.c_iflag == b.c_iflag
        && a.c_oflag == b.c_oflag
        && a.c_cflag == b.c_cflag
        && a.c_lflag == b.c_lflag
        && a.c_cc == b.c_cc
}

/// What the job's exit code means. The shell adds 50 to a code of its own.
const JOB_OK: i32 = 0;
const JOB_NOT_FOREGROUND: i32 = 11;
const JOB_WAS_RAW_ALREADY: i32 = 12;
const JOB_GOT_A_GUARD: i32 = 13;
const JOB_ENTER_FAILED: i32 = 14;
const JOB_SETTINGS_CHANGED: i32 = 15;
const JOB_STILL_FOREGROUND: i32 = 16;
const JOB_HANDOVER_UNUSED: i32 = 17;
const SHELL_SAW_A_STOP: i32 = 20;

/// Runs `job` in a job of a shell's session on `slave`, started in the
/// foreground when `foreground` says so, with the shell handing the
/// terminal back to itself on the job's request. Returns the job's exit
/// code as the shell reports it, or [`SHELL_SAW_A_STOP`] when the job was
/// stopped by a signal instead.
fn in_a_job(slave: RawFd, foreground: bool, job: impl FnOnce() -> i32) -> i32 {
    let (request_read, request_write) = pipe();
    let (ack_read, ack_write) = pipe();
    let (go_read, go_write) = pipe();
    let shell = fork_child(move || {
        if !become_a_shell(slave) || block_job_control_signals().is_err() {
            return 51;
        }
        let (request_read, mut go_write, mut ack_write) = (request_read, go_write, ack_write);
        // The job's ends, as raw descriptors: the shell closes its copies
        // once the job has them, so that it never waits on itself.
        let (request_write, ack_read, go_read) = (
            request_write.into_raw_fd(),
            ack_read.into_raw_fd(),
            go_read.into_raw_fd(),
        );
        let child = fork_child(move || {
            // SAFETY: plain system call: a group of its own.
            if unsafe { libc::setpgid(0, 0) } < 0 {
                return 61;
            }
            // The shell blocked the job-control signals for itself; the
            // job has the default mask, as a program started by a shell.
            // SAFETY: a zeroed sigset is valid to fill; pthread_sigmask
            // reads the set it is given.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGTTOU);
                libc::sigaddset(&mut set, libc::SIGTTIN);
                if libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) != 0 {
                    return 60;
                }
            }
            REQUEST_FD.store(request_write, Ordering::SeqCst);
            ACK_FD.store(ack_read, Ordering::SeqCst);
            // Wait for the shell to have placed this job.
            let mut byte = [0u8; 1];
            // SAFETY: the pipe's read end, the job's own from here.
            let mut go_read = unsafe { File::from_raw_fd(go_read) };
            if go_read.read_exact(&mut byte).is_err() {
                return 62;
            }
            job()
        });
        // SAFETY: the shell's copies of the job's descriptors, closed once;
        // then plain system calls on the child's group and the terminal.
        unsafe {
            libc::close(request_write);
            libc::close(ack_read);
            libc::close(go_read);
            libc::setpgid(child, child);
            if foreground {
                libc::tcsetpgrp(slave, child);
            }
        }
        if go_write.write_all(b"g").is_err() {
            return 52;
        }
        // Until the job ends or is stopped, answer its one request for the
        // terminal, if it makes one: a stopped job keeps its end of the
        // pipe, so the shell cannot just wait for the request.
        // SAFETY: plain system call.
        let own = unsafe { libc::getpgrp() };
        let mut status = 0;
        loop {
            // SAFETY: a non-blocking wait for the job, stops included.
            let waited =
                unsafe { libc::waitpid(child, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            if waited == child {
                break;
            }
            let mut fd = libc::pollfd {
                fd: request_read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized pollfd.
            if unsafe { libc::poll(&mut fd, 1, 50) } == 1 && fd.revents & libc::POLLIN != 0 {
                let mut byte = [0u8; 1];
                let mut request_read = &request_read;
                if request_read.read_exact(&mut byte).is_ok() {
                    // SAFETY: SIGTTOU is blocked here, as a shell's is.
                    unsafe { libc::tcsetpgrp(slave, own) };
                    let _ = ack_write.write_all(b"a");
                }
            }
        }
        if libc::WIFSTOPPED(status) {
            // SAFETY: the job is ours.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::waitpid(child, &mut status, 0);
            }
            return SHELL_SAW_A_STOP;
        }
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            53
        }
    });
    wait_child(shell)
}

/// The process moves to the background between the foreground check and
/// the raw-mode write: `enter` gives no guard, puts the settings back field
/// for field, and the process is not stopped.
#[test]
fn moving_to_the_background_during_the_write_restores_the_terminal() {
    let (master, slave) = openpty();
    let code = in_a_job(slave, true, || {
        if !is_foreground(slave) {
            return JOB_NOT_FOREGROUND;
        }
        // SAFETY: the guard works on stdin; make the terminal that.
        if unsafe { libc::dup2(slave, libc::STDIN_FILENO) } < 0 {
            return 63;
        }
        let Some(before) = get_termios(libc::STDIN_FILENO) else {
            return 64;
        };
        if before.c_lflag & libc::ICANON == 0 {
            return JOB_WAS_RAW_ALREADY;
        }
        HAND_OVER.store(true, Ordering::SeqCst);
        let entered = RawModeGuard::enter();
        if HAND_OVER.load(Ordering::SeqCst) {
            return JOB_HANDOVER_UNUSED;
        }
        match entered {
            Ok(None) => {}
            Ok(Some(_)) => return JOB_GOT_A_GUARD,
            Err(_) => return JOB_ENTER_FAILED,
        }
        if is_foreground(libc::STDIN_FILENO) {
            return JOB_STILL_FOREGROUND;
        }
        match get_termios(libc::STDIN_FILENO) {
            Some(after) if same_settings(&after, &before) => JOB_OK,
            _ => JOB_SETTINGS_CHANGED,
        }
    });
    assert_eq!(code, JOB_OK, "the job (or the shell) said where it failed");
    // SAFETY: both are descriptors openpty made, closed once.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// The control: the same harness stops a job that writes the terminal's
/// settings from the background without blocking `SIGTTOU`, so the
/// background above is the kernel's, not the test's say-so.
#[test]
fn a_plain_write_from_the_background_is_stopped_by_the_kernel() {
    let (master, slave) = openpty();
    let code = in_a_job(slave, false, || {
        if is_foreground(slave) {
            return JOB_STILL_FOREGROUND;
        }
        let Some(settings) = get_termios(slave) else {
            return 64;
        };
        // Straight to the kernel, SIGTTOU unblocked: stopped here.
        let rc = unsafe { real_tcsetattr()(slave, libc::TCSANOW, &settings) };
        if rc == 0 {
            65
        } else {
            66
        }
    });
    assert_eq!(code, SHELL_SAW_A_STOP, "the kernel did not stop the job");
    // SAFETY: both are descriptors openpty made, closed once.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// Unused outside the interposer's error path; keeps the C string type in
/// scope for it.
#[allow(dead_code)]
fn symbol_name() -> &'static CStr {
    c"tcsetattr"
}
