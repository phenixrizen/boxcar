// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Starting the sensor: `/boxcar-sensor` from the initramfs, opened before
//! the root is switched (after it, the initramfs is out of reach) and run
//! from that descriptor once the cgroups exist, as a child of init in the
//! `system` cgroup, with the session cgroup's id as its argument. It keeps
//! root and its capabilities; the session, which drops both, cannot touch
//! it (the sensor's own guards see to the rest).

use std::ffi::{CStr, CString};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

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

/// The sensor's arguments.
fn argv(session_cgroup: u64) -> Result<[CString; 2], Failed> {
    let flag = CString::new(format!("--session-cgroup={session_cgroup}"))
        .map_err(|_| Failed::new("sensor argv", Errno::EINVAL))?;
    Ok([c"boxcar-sensor".to_owned(), flag])
}

/// Forks the sensor and returns its pid. The child joins the `system`
/// cgroup and execs `binary`; it inherits init's console for its messages.
fn spawn(binary: OwnedFd, session_cgroup: u64) -> Result<Pid, Failed> {
    // Everything the child needs, before the fork: it allocates nothing.
    let argv = argv(session_cgroup)?;
    let argv_ptrs: [*const libc::c_char; 3] =
        [argv[0].as_ptr(), argv[1].as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: init is single-threaded; the child only makes system calls on
    // memory prepared above, then execs or exits.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => Ok(child),
        Ok(ForkResult::Child) => {
            join_system_cgroup();
            // SAFETY: fexecve takes the open descriptor and two NULL-ended
            // arrays of NUL-ended strings, all prepared before the fork.
            unsafe {
                libc::fexecve(binary.as_raw_fd(), argv_ptrs.as_ptr(), envp.as_ptr());
                libc::_exit(127)
            }
        }
        Err(errno) => Err(Failed::new("fork the sensor", errno)),
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
    fn the_arguments_name_the_cgroup() {
        let args = argv(4242).unwrap();
        assert_eq!(args[0].to_str().unwrap(), "boxcar-sensor");
        assert_eq!(args[1].to_str().unwrap(), "--session-cgroup=4242");
    }
}
