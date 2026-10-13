// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The harness the end-to-end tests share (`kvm_m2`, `kvm_m3`): the guest
//! artifacts from the environment, a scratch directory, `boxcar run` started
//! and watched, the other commands against its control socket, and the
//! verified log. Every item is `pub` for the test files that include this
//! module; `dead_code` is allowed because each file uses a different part.

#![allow(dead_code)]

use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, str};

use boxcar_audit::{verify_session, LogReader};
use boxcar_proto::Record;
use boxcar_vmm::kvm::kvm_available;

/// How long one run may take, boot to exit.
pub const LIMIT: Duration = Duration::from_secs(60);
/// How long the host gets to reach example.com before the network tests
/// skip.
pub const REACH_LIMIT: Duration = Duration::from_secs(5);

/// The artifact `var` names, or `None` when it is unset.
pub fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The guest artifacts `boxcar run` boots.
pub struct Guest {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub rootfs: PathBuf,
}

/// The guest, or `None` after printing why `test` skips.
pub fn guest_or_skip(test: &str) -> Option<Guest> {
    let (Some(kernel), Some(initramfs), Some(rootfs)) = (
        artifact("BOXCAR_TEST_KERNEL"),
        artifact("BOXCAR_TEST_INITRAMFS"),
        artifact("BOXCAR_TEST_ROOTFS"),
    ) else {
        eprintln!(
            "skipping {test}: BOXCAR_TEST_KERNEL, BOXCAR_TEST_INITRAMFS and \
             BOXCAR_TEST_ROOTFS must all be set"
        );
        return None;
    };
    if let Err(reason) = kvm_available() {
        eprintln!("skipping {test}: {reason}");
        return None;
    }
    Some(Guest {
        kernel,
        initramfs,
        rootfs,
    })
}

/// [`guest_or_skip`], for a test that reaches example.com.
pub fn networked_guest_or_skip(test: &str) -> Option<Guest> {
    let guest = guest_or_skip(test)?;
    if env::var_os("BOXCAR_TEST_NET").is_some_and(|value| value == "0") {
        eprintln!("skipping {test}: BOXCAR_TEST_NET=0");
        return None;
    }
    if let Err(reason) = example_com_reachable() {
        eprintln!("skipping {test}: {reason}");
        return None;
    }
    Some(guest)
}

/// Whether this host opens a TCP connection to example.com:80 (IPv4, as
/// the guest's network is) within [`REACH_LIMIT`].
pub fn example_com_reachable() -> Result<(), String> {
    let addr = ("example.com", 80)
        .to_socket_addrs()
        .map_err(|error| format!("this host cannot resolve example.com: {error}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or("example.com has no IPv4 address from this host")?;
    TcpStream::connect_timeout(&addr, REACH_LIMIT)
        .map(drop)
        .map_err(|error| format!("this host cannot reach {addr} within {REACH_LIMIT:?}: {error}"))
}

/// A scratch directory for one run: `workspace/`, `audit/`, the console
/// log and boxcar's own output.
pub struct Scratch {
    pub dir: tempfile::TempDir,
}

impl Scratch {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("workspace")).unwrap();
        Scratch { dir }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

/// A `boxcar run` under way, with its output going to files in the scratch
/// directory.
pub struct Running<'a> {
    pub child: Child,
    pub scratch: &'a Scratch,
    pub started: Instant,
    pub command: Vec<String>,
    /// How long the run may take before it is killed: [`LIMIT`] unless
    /// [`Running::with_limit`] says more (an agent's run takes minutes).
    pub limit: Duration,
}

/// What a `boxcar run` left behind.
pub struct Run {
    pub status: ExitStatus,
    pub elapsed: Duration,
    pub console: String,
    /// The session's terminal.
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// The session directory, from boxcar's `audit:` line.
    pub fn session_dir(&self) -> PathBuf {
        let line = self.stderr.lines().find_map(|l| l.strip_prefix("audit: "));
        PathBuf::from(line.unwrap_or_else(|| panic!("no audit line:\n{}", self.stderr)))
    }

    /// The session's records, once the log is verified.
    pub fn records(&self) -> Vec<Record> {
        let dir = self.session_dir();
        let report = verify_session(&dir).unwrap();
        eprintln!("verify: {report:?}");
        LogReader::open(&dir)
            .unwrap()
            .records()
            .map(Result::unwrap)
            .collect()
    }

    /// Every output, for a failed assertion.
    pub fn describe(&self) -> String {
        format!(
            "{}; after {:?}\nstderr:\n{}\nstdout:\n{}\nconsole:\n{}",
            self.status, self.elapsed, self.stderr, self.stdout, self.console
        )
    }
}

/// Starts `boxcar run` with `flags` before the `--` and `command` after it.
pub fn start<'a>(
    guest: &Guest,
    scratch: &'a Scratch,
    flags: &[&str],
    command: &[&str],
) -> Running<'a> {
    start_env(guest, scratch, flags, command, &[])
}

/// [`start`] with `env` set in `boxcar run`'s own environment (not the
/// session's: that is `--env`).
pub fn start_env<'a>(
    guest: &Guest,
    scratch: &'a Scratch,
    flags: &[&str],
    command: &[&str],
    env: &[(&str, &Path)],
) -> Running<'a> {
    let child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .envs(env.iter().map(|(name, value)| (*name, *value)))
        .arg("run")
        .arg("--kernel")
        .arg(&guest.kernel)
        .arg("--initramfs")
        .arg(&guest.initramfs)
        .arg("--rootfs")
        .arg(&guest.rootfs)
        .arg("--workspace")
        .arg(scratch.path("workspace"))
        .arg("--audit-dir")
        .arg(scratch.path("audit"))
        .arg("--console-log")
        .arg(scratch.path("console.log"))
        .args(flags)
        .arg("--")
        .args(command)
        .stdin(Stdio::null())
        .stdout(File::create(scratch.path("stdout.log")).unwrap())
        .stderr(File::create(scratch.path("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    Running {
        child,
        scratch,
        started: Instant::now(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
        limit: LIMIT,
    }
}

impl Running<'_> {
    /// The session's output so far.
    pub fn stdout(&self) -> String {
        read_lossy(&self.scratch.path("stdout.log"))
    }

    pub fn stderr(&self) -> String {
        read_lossy(&self.scratch.path("stderr.log"))
    }

    /// Fails the test if the run has taken longer than [`LIMIT`].
    /// The run with `limit` as its time limit.
    pub fn with_limit(mut self, limit: Duration) -> Self {
        self.limit = limit;
        self
    }

    pub fn check_time(&mut self) {
        if self.started.elapsed() > self.limit {
            let _ = self.child.kill();
            let _ = self.child.wait();
            panic!(
                "boxcar run -- {:?} did not get there within {:?}; console:\n{}\nstderr:\n{}",
                self.command,
                self.limit,
                read_lossy(&self.scratch.path("console.log")),
                self.stderr()
            );
        }
    }

    /// Waits for `what` to be true of the run, polling.
    pub fn until(&mut self, what: &str, mut done: impl FnMut(&Running<'_>) -> bool) {
        while !done(self) {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "boxcar run -- {:?} exited ({status}) before {what}; stderr:\n{}\nstdout:\n{}",
                    self.command,
                    self.stderr(),
                    self.stdout()
                );
            }
            self.check_time();
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// The control socket's path, from boxcar's `control:` line, once it
    /// is printed.
    pub fn control(&mut self) -> PathBuf {
        let mut found = None;
        self.until("the control line", |run| {
            found = run
                .stderr()
                .lines()
                .find_map(|l| l.strip_prefix("control: ").map(PathBuf::from));
            found.is_some()
        });
        found.unwrap()
    }

    /// Waits for the run to end.
    pub fn finish(mut self) -> Run {
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            self.check_time();
            thread::sleep(Duration::from_millis(20));
        };
        Run {
            status,
            elapsed: self.started.elapsed(),
            console: read_lossy(&self.scratch.path("console.log")),
            stdout: self.stdout(),
            stderr: self.stderr(),
        }
    }
}

/// Runs `boxcar run` to its end.
pub fn boxcar_run(guest: &Guest, scratch: &Scratch, flags: &[&str], command: &[&str]) -> Run {
    start(guest, scratch, flags, command).finish()
}

/// Runs another `boxcar` command (`status`, `stop`, `events`, `policy`)
/// against `control`.
pub fn boxcar(args: &[&str], control: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(args)
        .arg("--control")
        .arg(control)
        .output()
        .unwrap()
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The file at `path` as text, empty when it is not there.
pub fn read_lossy(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

/// The records of type `kind`.
pub fn of_kind<'a>(records: &'a [Record], kind: &str) -> Vec<&'a Record> {
    records.iter().filter(|r| r.kind == kind).collect()
}

/// The IPv4 address this host resolves example.com to, for a test that
/// connects by address.
pub fn example_com_ipv4() -> Option<Ipv4Addr> {
    ("example.com", 80)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
}
