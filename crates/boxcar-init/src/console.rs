// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! How init reports and how it ends: text on `/dev/console`, then a reboot.
//!
//! PID 1 must never return or exit on its own (the kernel panics if it does),
//! so every failure goes through [`die`], which reports on the console and
//! reboots. Nothing here unwraps a syscall result.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;

use nix::sys::reboot::{reboot, RebootMode};
use nix::sys::termios::tcdrain;
use nix::unistd::sync;

/// The console node the initramfs carries.
const CONSOLE: &str = "/dev/console";

/// Writes all of `bytes` to `path`, opened write-only for this one call.
///
/// `O_NOCTTY` keeps a terminal device from becoming the controlling terminal
/// of PID 1.
pub fn write_to(path: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(path)?;
    file.write_all(bytes)
}

/// Writes all of `bytes` to `/dev/console`.
pub fn write_console(bytes: &[u8]) -> io::Result<()> {
    write_to(CONSOLE, bytes)
}

/// Waits until the terminal at `path` has sent everything written to it.
///
/// A write to a tty only queues the bytes; the serial driver sends them from
/// its interrupt, so a reboot right after the write can drop them. Best
/// effort: when `path` cannot be opened or is not a terminal (`tcdrain`
/// fails with `ENOTTY`, as in a namespace without a real console), this
/// returns at once and the caller carries on.
fn drain(path: &str) {
    if let Ok(file) = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(path)
    {
        let _ = tcdrain(&file);
    }
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

/// Reports `msg` on the console as `boxcar-init: <msg>` and reboots. Never
/// returns. If the console cannot be written the report is lost; the reboot
/// still happens.
pub fn die(msg: &str) -> ! {
    let _ = write_console(format!("boxcar-init: {msg}\n").as_bytes());
    reboot_now()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drain before a reboot must never stop the reboot: a node that is
    /// not a terminal, or no node at all, returns at once.
    #[test]
    fn drain_ignores_a_missing_or_non_terminal_console() {
        drain("/dev/null");
        drain("/nonexistent/console");
    }
}
