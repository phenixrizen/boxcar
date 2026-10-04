// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Starting the sensor: `/boxcar-sensor` from the initramfs, opened before
//! the root is switched (after it, the initramfs is out of reach) and run
//! from that descriptor once the cgroups exist, as a child of init in the
//! `system` cgroup, with the session cgroup's id as its argument. It keeps
//! root and its capabilities; the session, which drops both, cannot touch
//! it (the sensor's own guards see to the rest).
//!
//! Attaching takes a moment (the kernel's BTF, nine programs). Init waits
//! for the sensor to say it is ready, a byte on a pipe it hands the sensor
//! as `--ready-fd`, for up to [`READY_WAIT`] before it starts the session,
//! so the session's first exec is already seen. A sensor that is not ready
//! in time, or dies, gets a warning and the session starts anyway.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{fork, ForkResult, Pid};

use crate::console::{warn, Failed};
use crate::session::CGROUPS;

/// Where the initramfs has the sensor.
pub const SENSOR_PATH: &str = "/boxcar-sensor";

/// The cgroup init's helpers run in, and the session's.
const SYSTEM_PROCS: &CStr = c"/sys/fs/cgroup/system/cgroup.procs";

/// How long init waits for the sensor's ready byte before the session
/// starts without it.
pub const READY_WAIT: Duration = Duration::from_secs(3);

/// Opens the sensor binary, to run it after the root is switched. `None`,
/// with a warning, when the initramfs has none.
pub fn open_binary() -> Option<OwnedFd> {
    match open(
        SENSOR_PATH,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(errno) => {
            warn(&format!(
                "sensor: {SENSOR_PATH}: {errno}; running without ring 1"
            ));
            None
        }
    }
}

/// The session cgroup's id: the inode of its directory.
pub fn session_cgroup_id() -> Result<u64, Failed> {
    fs::metadata(CGROUPS[1])
        .map(|meta| meta.ino())
        .map_err(|e| Failed::new(&format!("stat {}", CGROUPS[1]), e))
}

/// Starts the sensor from `binary` for the session cgroup, or says why it
/// could not. Never fatal: the session runs without ring 1.
pub fn start(binary: OwnedFd, cgroups: bool) -> Option<Pid> {
    if !cgroups {
        warn("sensor: no cgroup2, so no session cgroup to watch; running without ring 1");
        return None;
    }
    let cgroup = match session_cgroup_id() {
        Ok(id) => id,
        Err(failed) => {
            warn(&format!("sensor: {failed}; running without ring 1"));
            return None;
        }
    };
    match spawn(binary, cgroup) {
        Ok(pid) => Some(pid),
        Err(failed) => {
            warn(&format!("sensor: {failed}; running without ring 1"));
            None
        }
    }
}

/// The sensor's arguments: the session cgroup's id, and the descriptor
/// the ready pipe's write end is on.
fn argv(session_cgroup: u64, ready_fd: libc::c_int) -> Result<[CString; 3], Failed> {
    let cgroup = CString::new(format!("--session-cgroup={session_cgroup}"))
        .map_err(|_| Failed::new("sensor argv", Errno::EINVAL))?;
    let ready = CString::new(format!("--ready-fd={ready_fd}"))
        .map_err(|_| Failed::new("sensor argv", Errno::EINVAL))?;
    Ok([c"boxcar-sensor".to_owned(), cgroup, ready])
}

/// Forks the sensor, waits for its ready byte, and returns its pid. The
/// child joins the `system` cgroup, keeps the pipe's write end across the
/// exec (its number is in the arguments) and execs `binary`; it inherits
/// init's console for its messages.
fn spawn(binary: OwnedFd, session_cgroup: u64) -> Result<Pid, Failed> {
    // Everything the child needs, before the fork: it allocates nothing.
    let (ready_read, ready_write) = ready_pipe()?;
    let argv = argv(session_cgroup, ready_write.as_raw_fd())?;
    let argv_ptrs: [*const libc::c_char; 4] = [
        argv[0].as_ptr(),
        argv[1].as_ptr(),
        argv[2].as_ptr(),
        std::ptr::null(),
    ];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: init is single-threaded; the child only makes system calls on
    // memory prepared above, then execs or exits.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(ready_write);
            wait_ready(&ready_read, child);
            Ok(child)
        }
        Ok(ForkResult::Child) => {
            join_system_cgroup();
            // SAFETY: fcntl and fexecve take descriptors and, for fexecve, two
            // NULL-ended arrays of NUL-ended strings, all prepared before the
            // fork. The write end loses close-on-exec so the sensor finds it
            // where the arguments say; everything else closes with the exec.
            unsafe {
                if libc::fcntl(ready_write.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                    libc::_exit(126);
                }
                libc::fexecve(binary.as_raw_fd(), argv_ptrs.as_ptr(), envp.as_ptr());
                libc::_exit(127)
            }
        }
        Err(errno) => Err(Failed::new("fork the sensor", errno)),
    }
}

/// A close-on-exec pipe: the read end for init, the write end for the child.
fn ready_pipe() -> Result<(OwnedFd, OwnedFd), Failed> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills the two-element array given.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Failed::new("pipe for the sensor", Errno::last()));
    }
    // SAFETY: two new descriptors nothing else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Waits up to [`READY_WAIT`] for the sensor's byte, or for the pipe to
/// close (the sensor ended); either way the session goes on.
fn wait_ready(ready: &OwnedFd, child: Pid) {
    let deadline = Instant::now() + READY_WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            warn(&format!(
                "sensor: pid {child} not ready after {} s; the session starts without ring 1's \
                 first moments",
                READY_WAIT.as_secs()
            ));
            return;
        }
        let mut poll = [libc::pollfd {
            fd: ready.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let timeout = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        // SAFETY: poll reads and writes the one pollfd given.
        let ready_count = unsafe { libc::poll(poll.as_mut_ptr(), 1, timeout) };
        if ready_count < 0 {
            if Errno::last() == Errno::EINTR {
                continue;
            }
            warn(&format!(
                "sensor: poll: {}; the session starts now",
                Errno::last()
            ));
            return;
        }
        if ready_count == 0 {
            continue;
        }
        let mut byte = [0u8; 1];
        // SAFETY: read fills at most one byte of the array given.
        let n = unsafe { libc::read(ready.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        if n == 1 {
            return;
        }
        warn(&format!(
            "sensor: pid {child} ended before it was ready; the session starts without ring 1"
        ));
        return;
    }
}

/// Puts this process in the `system` cgroup; best effort, in the child.
fn join_system_cgroup() {
    // SAFETY: open and write take the pointers and lengths given; the
    // strings are NUL-ended and live for the calls.
    unsafe {
        let fd = libc::open(SYSTEM_PROCS.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            // "0" is this process.
            libc::write(fd, c"0".as_ptr().cast(), 1);
            libc::close(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arguments_name_the_cgroup_and_the_ready_pipe() {
        let args = argv(4242, 7).unwrap();
        assert_eq!(args[0].to_str().unwrap(), "boxcar-sensor");
        assert_eq!(args[1].to_str().unwrap(), "--session-cgroup=4242");
        assert_eq!(args[2].to_str().unwrap(), "--ready-fd=7");
    }

    /// A byte on the pipe ends the wait at once; a closed pipe too; a
    /// silent one lasts the whole wait (not tested: 3 s).
    #[test]
    fn the_wait_ends_on_a_byte_or_a_closed_pipe() {
        let (read, write) = ready_pipe().unwrap();
        // SAFETY: write takes the buffer and length given.
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), c"1".as_ptr().cast(), 1) },
            1
        );
        let started = Instant::now();
        wait_ready(&read, Pid::from_raw(77));
        assert!(started.elapsed() < Duration::from_secs(1));

        let (read, write) = ready_pipe().unwrap();
        drop(write);
        let started = Instant::now();
        wait_ready(&read, Pid::from_raw(77));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
