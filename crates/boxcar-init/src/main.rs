// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The static PID 1 that runs inside the guest.
//!
//! It mounts the kernel's API filesystems, reads the `boxcar.*` keys of the
//! kernel command line and dispatches on `boxcar.mode`:
//!
//! - `hello` prints a marker on the console and reboots, which proves the
//!   whole boot path from the VMM to a Rust PID 1 and back.
//! - `console` runs the session: it mounts the `root` and `workspace`
//!   virtio-fs shares, makes the root share `/`, hardens the kernel
//!   settings, makes `/dev/ttyS0` its own controlling terminal, runs the
//!   session command (`boxcar.cmd`, or a login shell) in the foreground of
//!   it as `boxcar.uid` and `boxcar.gid`, reaps until no child is left,
//!   reports how the session ended and reboots.
//!
//! Every fatal step reports `boxcar-init: <step>: <error>` on the console
//! and reboots; PID 1 never exits on its own.

mod cmdline;
mod console;
mod mounts;
mod reaper;
mod search;
mod session;
mod shutdown;
mod sysctl;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::panic;

use console::{die, write_console, write_to, Failed, StackLine, Step};
use nix::unistd::sethostname;
use reaper::{Ended, Reaper};
use session::{Exec, Session, Terminal};
use shutdown::reboot_now;

/// What `hello` mode prints. Task 9's boot test looks for this line.
const HELLO: &[u8] = b"BOXCAR_INIT_HELLO\n";

/// The guest's hostname in `console` mode.
const HOSTNAME: &str = "boxcar";

fn main() {
    install_panic_hook();
    if let Err(failed) = mounts::mount_early() {
        die(&failed.to_string());
    }
    let args = match cmdline::read() {
        Ok(args) => args,
        Err(e) => die(&format!("read /proc/cmdline: {e}")),
    };
    match args.get("mode").map(String::as_str) {
        Some("hello") => hello(),
        Some("console") => console(&args),
        Some(mode) => die(&format!("unknown mode {mode:?}")),
        None => die("unknown mode (boxcar.mode is not set)"),
    }
}

/// `hello` mode: the marker on the console, then a reboot.
fn hello() -> ! {
    if let Err(e) = write_console(HELLO) {
        die(&format!("write /dev/console: {e}"));
    }
    reboot_now()
}

/// `console` mode: the session, then how it ended on the console and a
/// reboot.
fn console(args: &BTreeMap<String, String>) -> ! {
    match run_session(args) {
        Ok(ended) => shutdown::finish(ended),
        Err(failed) => die(&failed.to_string()),
    }
}

/// The steps of `console` mode after the early mounts, up to the session's
/// end.
fn run_session(args: &BTreeMap<String, String>) -> Result<Ended, Failed> {
    // Everything the command line says is checked before anything is
    // mounted, and the command is ready for exec before the fork.
    let session = Session::from_cmdline(args)?;
    let mut exec = Exec::new(&session.argv)?;

    mounts::mount_shares()?;
    let mounted = mounts::mount_api()?;
    mounts::switch_root()?;
    // In the root the session sees, and before the fork: the search
    // allocates.
    exec.resolve();

    sethostname(HOSTNAME).step(&format!("sethostname {HOSTNAME}"))?;
    sysctl::apply();
    let join_cgroup = session::create_cgroups(mounted.cgroup2)?;

    let terminal = Terminal::claim()?;
    let reaper = Reaper::new()?;
    let pid = session::spawn(&session, &exec, &terminal, join_cgroup)?;
    reaper.wait(pid, &terminal)
}

/// Sends a panic to `/dev/kmsg` and `/dev/console`, then aborts.
///
/// Both writes are best effort: at the time of a panic nothing can be relied
/// on, and there is nobody to report a failure to. The message is formatted
/// into a buffer on the stack so the hook asks the allocator for nothing
/// itself.
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
