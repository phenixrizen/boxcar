// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The static PID 1 that runs inside the guest.
//!
//! This is the M1 bring-up init. It mounts `/proc`, reads the `boxcar.*` keys
//! of the kernel command line and dispatches on `boxcar.mode`. Only `hello`
//! exists so far: print a marker on the console and reboot, which proves the
//! whole boot path from the VMM to a Rust PID 1 and back.

mod cmdline;
mod console;

use std::fmt::{self, Write as _};
use std::panic;

use console::{die, reboot_now, write_console, write_to};
use nix::mount::{mount, MsFlags};

/// What `hello` mode prints. Task 9's boot test looks for this line.
const HELLO: &[u8] = b"BOXCAR_INIT_HELLO\n";

fn main() {
    install_panic_hook();
    if let Err(e) = mount_proc() {
        die(&format!("mount /proc: {e}"));
    }
    let args = match cmdline::read() {
        Ok(args) => args,
        Err(e) => die(&format!("read /proc/cmdline: {e}")),
    };
    match args.get("mode").map(String::as_str) {
        Some("hello") => hello(),
        Some(mode) => die(&format!("unknown mode {mode:?}")),
        None => die("unknown mode (boxcar.mode is not set)"),
    }
}

/// Mounts `proc` at `/proc`, which the initramfs carries as an empty directory.
fn mount_proc() -> nix::Result<()> {
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
}

/// `hello` mode: the marker on the console, then a reboot.
fn hello() -> ! {
    if let Err(e) = write_console(HELLO) {
        die(&format!("write /dev/console: {e}"));
    }
    reboot_now()
}

/// Sends a panic to `/dev/kmsg` and `/dev/console`, then aborts.
///
/// Both writes are best effort: at the time of a panic nothing can be relied
/// on, `/dev/kmsg` is not in the initramfs at all, and there is nobody to
/// report a failure to. The message is formatted into a buffer on the stack
/// so the hook asks the allocator for nothing itself.
fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let mut line = StackLine::new();
        let _ = write!(line, "boxcar-init: panic");
        if let Some(location) = info.location() {
            let _ = write!(
                line,
                " at {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        }
        if let Some(message) = info.payload_as_str() {
            let _ = write!(line, ": {message}");
        }
        let bytes = line.finish();
        let _ = write_to("/dev/kmsg", bytes);
        let _ = write_console(bytes);
        std::process::abort()
    }));
}

/// A line of text in a fixed buffer. Text past the capacity is dropped, and
/// [`StackLine::finish`] always ends the line with a newline.
struct StackLine {
    buf: [u8; Self::CAPACITY],
    len: usize,
}

impl StackLine {
    /// Bytes of buffer, one of which is kept for the newline.
    const CAPACITY: usize = 512;

    fn new() -> Self {
        Self {
            buf: [0; Self::CAPACITY],
            len: 0,
        }
    }

    /// The text so far plus a newline.
    fn finish(&mut self) -> &[u8] {
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
