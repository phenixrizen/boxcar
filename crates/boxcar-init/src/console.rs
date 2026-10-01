// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! How init reports: text on `/dev/console`.
//!
//! PID 1 must never return or exit on its own (the kernel panics if it does),
//! so every failure goes through [`die`], which reports on the console and
//! reboots through [`crate::shutdown::reboot_now`]. A step that may fail
//! without stopping the boot reports through [`warn`] instead. Nothing here
//! unwraps a syscall result.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;

use crate::shutdown::reboot_now;

/// The console node: in the initramfs, and in devtmpfs once that is mounted.
pub const CONSOLE: &str = "/dev/console";

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

/// Reports `msg` on the console as `boxcar-init: warning: <msg>` and returns:
/// for a best-effort step that failed. If the console cannot be written the
/// warning is lost.
pub fn warn(msg: &str) {
    let _ = write_console(format!("boxcar-init: warning: {msg}\n").as_bytes());
}

/// Reports `msg` on the console as `boxcar-init: <msg>` and reboots. Never
/// returns. If the console cannot be written the report is lost; the reboot
/// still happens.
pub fn die(msg: &str) -> ! {
    let _ = write_console(format!("boxcar-init: {msg}\n").as_bytes());
    reboot_now()
}

/// A step that failed: what init was doing, and the error. It displays as
/// `<step>: <error>`, which [`die`] prints after `boxcar-init: `.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failed {
    step: String,
    error: String,
}

impl Failed {
    pub fn new(step: &str, error: impl fmt::Display) -> Self {
        Failed {
            step: step.to_owned(),
            error: error.to_string(),
        }
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.step, self.error)
    }
}

/// Names the step an error comes from: `mount(..).step("mount /proc")?`.
pub trait Step<T> {
    fn step(self, step: &str) -> Result<T, Failed>;
}

impl<T, E: fmt::Display> Step<T> for Result<T, E> {
    fn step(self, step: &str) -> Result<T, Failed> {
        self.map_err(|error| Failed::new(step, error))
    }
}

/// A line of text in a fixed buffer, for where nothing may be allocated: the
/// panic hook, and the session child between `fork` and `execve`. Text past
/// the capacity is dropped, and [`StackLine::finish`] always ends the line
/// with a newline.
pub struct StackLine {
    buf: [u8; Self::CAPACITY],
    len: usize,
}

impl StackLine {
    /// Bytes of buffer, one of which is kept for the newline.
    pub const CAPACITY: usize = 512;

    pub fn new() -> Self {
        Self {
            buf: [0; Self::CAPACITY],
            len: 0,
        }
    }

    /// The text so far plus a newline.
    pub fn finish(&mut self) -> &[u8] {
        self.buf[self.len] = b'\n';
        &self.buf[..=self.len]
    }
}

impl fmt::Write for StackLine {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = Self::CAPACITY - 1 - self.len;
        let n = s.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn a_failed_step_reads_step_colon_error() {
        let failed = Failed::new("mount virtiofs on /newroot", "ENODEV: No such device");
        assert_eq!(
            failed.to_string(),
            "mount virtiofs on /newroot: ENODEV: No such device"
        );
    }

    #[test]
    fn step_names_the_error_and_keeps_the_value() {
        let err: Result<(), nix::Error> = Err(nix::Error::ENOENT);
        assert_eq!(
            err.step("chdir /workspace").unwrap_err().to_string(),
            "chdir /workspace: ENOENT: No such file or directory"
        );
        let ok: Result<u8, nix::Error> = Ok(7);
        assert_eq!(ok.step("unused"), Ok(7));
    }

    #[test]
    fn stack_line_holds_text_and_adds_the_newline() {
        let mut line = StackLine::new();
        write!(line, "a {} b", 1).unwrap();
        assert_eq!(line.finish(), b"a 1 b\n");
    }

    #[test]
    fn stack_line_truncates_but_still_ends_in_a_newline() {
        let mut line = StackLine::new();
        let long = "x".repeat(StackLine::CAPACITY * 2);
        write!(line, "{long}").unwrap();
        let bytes = line.finish();
        assert_eq!(bytes.len(), StackLine::CAPACITY);
        assert!(bytes.ends_with(b"x\n"));
    }
}
