// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Probes for the gated tests, run from a copy of this binary inside the
//! session: `probe-bpf` makes one `bpf()` call, `probe-kill` sends `SIGKILL`
//! to the sensor. Each prints `ok` or the error's name and exits 0 or 1,
//! so a test can read what the guest refused and look for the record.

use std::fs;
use std::process::ExitCode;

/// `bpf(BPF_MAP_CREATE)` of the smallest array map.
pub fn bpf() -> ExitCode {
    // bpf_attr for BPF_MAP_CREATE: map_type, key_size, value_size,
    // max_entries, map_flags, as the first five u32 of the union.
    let attr: [u32; 5] = [2, 4, 4, 1, 0];
    // SAFETY: the syscall reads `attr` for the size given and no more.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            0 as libc::c_long,
            attr.as_ptr(),
            std::mem::size_of_val(&attr) as libc::c_uint,
        )
    };
    report(fd >= 0)
}

/// `kill(pid, SIGKILL)` of the sensor: `pid` as given, or found by its
/// name in `/proc`.
pub fn kill(pid: Option<&String>) -> ExitCode {
    let pid = match pid.map(|p| p.parse::<i32>()) {
        Some(Ok(pid)) => pid,
        Some(Err(_)) => {
            println!("error: the pid is not a number");
            return ExitCode::FAILURE;
        }
        None => match sensor_pid() {
            Some(pid) => pid,
            None => {
                println!("error: no boxcar-sensor process found");
                return ExitCode::FAILURE;
            }
        },
    };
    // SAFETY: kill takes two integers.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    report(rc == 0)
}

/// The pid of a process named `boxcar-sensor` other than this one.
fn sensor_pid() -> Option<i32> {
    let me = std::process::id();
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() == "boxcar-sensor" {
            return i32::try_from(pid).ok();
        }
    }
    None
}

/// Prints the outcome and makes the exit code: `ok`, or the errno's name.
fn report(ok: bool) -> ExitCode {
    if ok {
        println!("ok");
        return ExitCode::SUCCESS;
    }
    let error = std::io::Error::last_os_error();
    let name = match error.raw_os_error() {
        Some(libc::EPERM) => "EPERM".to_owned(),
        Some(libc::EACCES) => "EACCES".to_owned(),
        Some(libc::ESRCH) => "ESRCH".to_owned(),
        Some(libc::ENOSYS) => "ENOSYS".to_owned(),
        Some(libc::EINVAL) => "EINVAL".to_owned(),
        Some(n) => format!("errno {n}"),
        None => error.to_string(),
    };
    println!("{name}");
    ExitCode::FAILURE
}
