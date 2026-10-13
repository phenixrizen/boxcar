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
//!   virtio-fs shares, makes the root share `/`, points the resolver at the
//!   gateway when the VM has a network card (`boxcar.net=1`; the kernel has
//!   configured `eth0` from `ip=` by then), hardens the kernel settings,
//!   makes `/dev/ttyS0` its own controlling terminal, runs the
//!   session command (`boxcar.cmd`, or a login shell) in the foreground of
//!   it as `boxcar.uid` and `boxcar.gid`, reaps until no child is left,
//!   reports how the session ended and reboots.
//! - `vsock` runs the session the VMM configures over the guest control
//!   channel: the same mounts and settings as `console`, then it connects
//!   the control channel (vsock port 1024, from port 1023) and says
//!   `hello`, takes the session's config (command, user, environment,
//!   working directory, hostname, terminal size, extra settings), connects
//!   the terminal stream (port 1025, from port 1022), and runs the session
//!   on a PTY of its own whose master it relays to the stream, serving the
//!   host's requests meanwhile ([`ctl::supervise`]). When the session has
//!   ended it drains the PTY, reports the end over the channel, sweeps the
//!   processes left, waits for the host to take both, writes how the
//!   session ended on the console and reboots. The serial console carries
//!   only init's and the kernel's lines; `/dev/ttyS0` stays nobody's
//!   terminal.
//!
//! Every fatal step reports `boxcar-init: <step>: <error>` on the console
//! and reboots; PID 1 never exits on its own.

mod cmdline;
mod console;
mod ctl;
mod mounts;
mod pty;
mod reaper;
mod resolver;
mod search;
mod sensor;
mod session;
mod shutdown;
mod sysctl;
mod vsock;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::panic;

use std::ffi::CString;
use std::time::Instant;

use boxcar_proto::guest::GuestMsg;
use console::{die, warn, write_console, write_to, Failed, StackLine, Step};
use nix::unistd::{sethostname, Gid, Uid};
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
        Some("vsock") => vsock_mode(&args),
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
    let exec = Exec::new(&session.argv)?;

    mounts::mount_shares()?;
    let mounted = mounts::mount_api()?;
    mounts::switch_root()?;
    if cmdline::net_enabled(args) {
        // The session can run without it: a warning, not a reboot.
        if let Err(failed) = resolver::set_up() {
            warn(&format!("resolver: {failed}"));
        }
    }

    sethostname(HOSTNAME).step(&format!("sethostname {HOSTNAME}"))?;
    sysctl::apply();
    let join_cgroup = session::create_cgroups(mounted.cgroup2)?;

    let terminal = Terminal::claim()?;
    let reaper = Reaper::new()?;
    let pid = session::spawn(&session, &exec, &terminal, join_cgroup)?;
    reaper.wait(pid, &terminal)
}

/// `vsock` mode: the session the VMM configures, then how it ended on the
/// console and a reboot. Without a config from the host there is no
/// session: a console line, and the reboot.
fn vsock_mode(args: &BTreeMap<String, String>) -> ! {
    match run_vsock_session(args) {
        Ok(Some(ended)) => shutdown::finish(ended),
        Ok(None) => shutdown::finish_unended(),
        Err(VsockFailure::NoConfig(failed)) => {
            let _ = write_console(format!("boxcar-init: ctl: {failed}\n").as_bytes());
            shutdown::finish(Ended::Exited(1))
        }
        Err(VsockFailure::Failed(failed)) => die(&failed.to_string()),
    }
}

/// Why `vsock` mode stopped before the session ended.
enum VsockFailure {
    /// The host sent no config.
    NoConfig(Failed),
    /// A step failed.
    Failed(Failed),
}

impl From<Failed> for VsockFailure {
    fn from(failed: Failed) -> Self {
        VsockFailure::Failed(failed)
    }
}

/// The steps of `vsock` mode after the early mounts, up to the session's
/// end (`None`: it outlived `SIGKILL`), its report and the sweep.
fn run_vsock_session(args: &BTreeMap<String, String>) -> Result<Option<Ended>, VsockFailure> {
    mounts::mount_shares()?;
    let mounted = mounts::mount_api()?;
    // The sensor comes from the initramfs, which the root switch puts out of
    // reach: hold it open across the switch and run it once the cgroups are
    // there.
    let sensor = if cmdline::sensor_enabled(args) {
        sensor::open_binary()
    } else {
        None
    };
    mounts::switch_root()?;
    if cmdline::net_enabled(args) {
        // The session can run without it: a warning, not a reboot.
        if let Err(failed) = resolver::set_up() {
            warn(&format!("resolver: {failed}"));
        }
    }
    sysctl::apply();
    let join_cgroup = session::create_cgroups(mounted.cgroup2)?;
    if let Some(binary) = sensor {
        // Before the session, so its first exec is seen; before the control
        // channel, so the host sees the sensor's stream and init's hello in
        // the order they matter. Never fatal.
        sensor::start(binary, join_cgroup);
    }

    let mut ctl = ctl::Ctl::connect()?;
    let config = ctl
        .receive_config(Instant::now() + ctl::CONFIG_DEADLINE)
        .map_err(VsockFailure::NoConfig)?;
    // From here the host hears why init stops (its stderr shows it), not
    // only the console.
    run_configured(&mut ctl, &config, join_cgroup).map_err(|failed| {
        ctl.tell_host(&failed);
        VsockFailure::Failed(failed)
    })
}

/// `vsock` mode with the session's `config`: the session, run to its end
/// and reported.
fn run_configured(
    ctl: &mut ctl::Ctl,
    config: &boxcar_proto::guest::SessionConfig,
    join_cgroup: bool,
) -> Result<Option<Ended>, Failed> {
    ctl::check_config(config)?;
    sethostname(&config.hostname).step(&format!("sethostname {}", config.hostname))?;
    sysctl::apply_config(&config.sysctls);

    // Everything the child needs, before the fork.
    let env = pty::session_env(config);
    let path = pty::search_path(&env).to_owned();
    let exec = Exec::with_env(&config.argv, env, &path)?;
    let cwd = CString::new(config.cwd.as_str()).step("config cwd")?;
    let user = Session {
        uid: Uid::from_raw(config.uid),
        gid: Gid::from_raw(config.gid),
        argv: config.argv.clone(),
    };

    // The session runs without its terminal reaching the host when the
    // host does not take it: its output is dropped.
    let stream = match vsock::connect(vsock::PTY_SOURCE_PORT, vsock::PTY_PORT) {
        Ok(stream) => {
            let header = pty::header_line(config.rows, config.cols);
            match nix::unistd::write(&stream, &header) {
                Ok(n) if n == header.len() => Some(stream),
                Ok(_) => {
                    warn("pty: the header line went out short; no terminal for the host");
                    None
                }
                Err(errno) => {
                    warn(&format!("pty: header: {errno}; no terminal for the host"));
                    None
                }
            }
        }
        Err(failed) => {
            warn(&format!("pty: {failed}; no terminal for the host"));
            None
        }
    };
    let terminal = pty::open(config.rows, config.cols, config.uid)?;
    let reaper = Reaper::new()?;
    let pid = pty::spawn(&user, &exec, &cwd, &terminal, join_cgroup)?;
    let pty::Pty { master, slave } = terminal;
    // Only the session holds the slave now: once it and what it started
    // are gone, the master reads EIO.
    drop(slave);
    ctl.report(&GuestMsg::SessionStarted {
        pid: u32::try_from(pid.as_raw()).unwrap_or(0),
    });
    let mut relay = pty::Relay::new(master, stream);
    let how = ctl::supervise(ctl, &mut relay, &reaper, pid)?;
    ctl::finish(ctl, &mut relay, &reaper, pid, how)
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
