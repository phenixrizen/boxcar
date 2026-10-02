// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The M2 end-to-end tests: the `boxcar` binary runs real VMs on KVM with
//! the guest kernel, the initramfs and the Alpine rootfs, and the other
//! commands (`status`, `stop`, `events`, `policy`) drive them over the
//! control socket while they run. The tests read what is left behind: exit
//! codes, the session's output, and the verified audit log.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible (`cargo xtask test-kvm m2` checks and sets them). The
//! tests that reach the network also skip when `BOXCAR_TEST_NET=0`, and
//! when this host cannot open a connection to example.com (`cargo xtask
//! test-kvm m2` sets `BOXCAR_TEST_NET=1` only when it resolves).

#![cfg(feature = "kvm-tests")]

use std::fs::{self, File};
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, str};

use boxcar_audit::{verify_session, LogReader};
use boxcar_proto::Record;
use boxcar_vmm::kvm::kvm_available;
use serde_json::Value;

/// How long one run may take, boot to exit.
const LIMIT: Duration = Duration::from_secs(60);
/// How long the host gets to reach example.com before the network tests
/// skip.
const REACH_LIMIT: Duration = Duration::from_secs(5);

/// The artifact `var` names, or `None` when it is unset.
fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The guest artifacts `boxcar run` boots.
struct Guest {
    kernel: PathBuf,
    initramfs: PathBuf,
    rootfs: PathBuf,
}

/// The guest, or `None` after printing why `test` skips.
fn guest_or_skip(test: &str) -> Option<Guest> {
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
fn networked_guest_or_skip(test: &str) -> Option<Guest> {
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
fn example_com_reachable() -> Result<(), String> {
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
struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("workspace")).unwrap();
        Scratch { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

/// A `boxcar run` under way, with its output going to files in the scratch
/// directory.
struct Running<'a> {
    child: Child,
    scratch: &'a Scratch,
    started: Instant,
    command: Vec<String>,
}

/// What a `boxcar run` left behind.
struct Run {
    status: ExitStatus,
    elapsed: Duration,
    console: String,
    /// The session's terminal.
    stdout: String,
    stderr: String,
}

impl Run {
    /// The session directory, from boxcar's `audit:` line.
    fn session_dir(&self) -> PathBuf {
        let line = self.stderr.lines().find_map(|l| l.strip_prefix("audit: "));
        PathBuf::from(line.unwrap_or_else(|| panic!("no audit line:\n{}", self.stderr)))
    }

    /// The session's records, once the log is verified.
    fn records(&self) -> Vec<Record> {
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
    fn describe(&self) -> String {
        format!(
            "{}; after {:?}\nstderr:\n{}\nstdout:\n{}\nconsole:\n{}",
            self.status, self.elapsed, self.stderr, self.stdout, self.console
        )
    }
}

/// Starts `boxcar run` with `flags` before the `--` and `command` after it.
fn start<'a>(guest: &Guest, scratch: &'a Scratch, flags: &[&str], command: &[&str]) -> Running<'a> {
    let child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
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
    }
}

impl Running<'_> {
    /// The session's output so far.
    fn stdout(&self) -> String {
        read_lossy(&self.scratch.path("stdout.log"))
    }

    fn stderr(&self) -> String {
        read_lossy(&self.scratch.path("stderr.log"))
    }

    /// Fails the test if the run has taken longer than [`LIMIT`].
    fn check_time(&mut self) {
        if self.started.elapsed() > LIMIT {
            let _ = self.child.kill();
            let _ = self.child.wait();
            panic!(
                "boxcar run -- {:?} did not get there within {LIMIT:?}; console:\n{}\nstderr:\n{}",
                self.command,
                read_lossy(&self.scratch.path("console.log")),
                self.stderr()
            );
        }
    }

    /// Waits for `what` to be true of the run, polling.
    fn until(&mut self, what: &str, mut done: impl FnMut(&Running<'_>) -> bool) {
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
    fn control(&mut self) -> PathBuf {
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
    fn finish(mut self) -> Run {
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
fn boxcar_run(guest: &Guest, scratch: &Scratch, flags: &[&str], command: &[&str]) -> Run {
    start(guest, scratch, flags, command).finish()
}

/// Runs another `boxcar` command (`status`, `stop`, `events`, `policy`)
/// against `control`.
fn boxcar(args: &[&str], control: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(args)
        .arg("--control")
        .arg(control)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The file at `path` as text, empty when it is not there.
fn read_lossy(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

/// The records of type `kind`.
fn of_kind<'a>(records: &'a [Record], kind: &str) -> Vec<&'a Record> {
    records.iter().filter(|r| r.kind == kind).collect()
}

/// What example.com's page says: present in `wget -qO-`'s output.
const EXAMPLE_PAGE: &str = "Example Domain";

/// (a) `--allow example.com -- wget -qO- http://example.com`: the page comes
/// back and the run exits 0; the log has the query, the connection allowed
/// by the rule, the name the gate saw, and the close. (No lease: the guest
/// takes its address from the kernel command line and asks for none.)
#[test]
fn an_allowed_download_succeeds_and_is_recorded() {
    let Some(guest) = networked_guest_or_skip("an_allowed_download_succeeds_and_is_recorded")
    else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &["--allow", "example.com"],
        &["wget", "-qO-", "http://example.com"],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains(EXAMPLE_PAGE), "{}", run.describe());

    let records = run.records();
    let dns = of_kind(&records, "net.dns");
    assert!(
        dns.iter()
            .any(|r| r.data["qname"] == "example.com" && r.data["verdict"] == "allow"),
        "{dns:?}"
    );
    let connects = of_kind(&records, "net.connect");
    let allowed = connects
        .iter()
        .find(|r| r.data["verdict"] == "allow")
        .unwrap_or_else(|| panic!("no allowed connect in {connects:?}"));
    assert_eq!(allowed.data["rule"], "allow example.com", "{allowed:?}");
    assert_eq!(allowed.data["proto"], "tcp");
    assert!(allowed.data["dst"].as_str().unwrap().ends_with(":80"));
    let flow = allowed.data["flow"].as_u64().unwrap();
    let gated = of_kind(&records, "net.tls");
    assert!(
        gated
            .iter()
            .any(|r| r.data["flow"] == flow && r.data["sni"] == "example.com"),
        "no gate pass for flow {flow}: {gated:?}"
    );
    let closes = of_kind(&records, "net.close");
    assert!(
        closes.iter().any(|r| r.data["flow"] == flow),
        "no close for flow {flow}: {closes:?}"
    );
}

/// (b) A name the policy does not allow: the download fails (the name does
/// not resolve: NXDOMAIN) and the log says the query was denied.
#[test]
fn a_download_the_policy_denies_fails_and_is_recorded() {
    let Some(guest) = networked_guest_or_skip("a_download_the_policy_denies_fails_and_is_recorded")
    else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &[],
        &["wget", "-qO-", "http://blocked.example"],
    );
    assert_ne!(run.status.code(), Some(0), "{}", run.describe());
    assert!(!run.stdout.contains(EXAMPLE_PAGE));
    let records = run.records();
    let denied = of_kind(&records, "net.dns");
    assert!(
        denied
            .iter()
            .any(|r| r.data["qname"] == "blocked.example" && r.data["verdict"] == "deny"),
        "{denied:?}"
    );
    assert!(
        of_kind(&records, "net.connect")
            .iter()
            .all(|r| r.data["verdict"] == "deny"),
        "a connection was allowed"
    );
}

/// (c) The session's exit code is the run's.
#[test]
fn the_sessions_exit_code_is_the_runs() {
    let Some(guest) = guest_or_skip("the_sessions_exit_code_is_the_runs") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(&guest, &scratch, &[], &["/bin/sh", "-c", "exit 7"]);
    assert_eq!(run.status.code(), Some(7), "{}", run.describe());
    let records = run.records();
    let exits = of_kind(&records, "session.exit");
    assert_eq!(exits.len(), 1, "{exits:?}");
    assert_eq!(exits[0].data["code"], 7);
}

/// (d) `boxcar status` during a run says `running`; `boxcar stop` ends it,
/// the run exits 0, and the log has the `control.stop`.
#[test]
fn status_and_stop_drive_a_running_vm() {
    let Some(guest) = guest_or_skip("status_and_stop_drive_a_running_vm") else {
        return;
    };
    let scratch = Scratch::new();
    let mut running = start(
        &guest,
        &scratch,
        &[],
        &["/bin/sh", "-c", "echo UP; sleep 30"],
    );
    let control = running.control();
    running.until("the session to be up", |run| run.stdout().contains("UP"));

    let status = boxcar(&["status", "--json"], &control);
    assert!(status.status.success(), "{}", text(&status.stderr));
    let status: Value = serde_json::from_str(text(&status.stdout).trim()).unwrap();
    assert_eq!(status["state"], "running", "{status}");
    assert_eq!(status["guest"]["init_ready"], true, "{status}");
    assert!(status["guest"]["session_pid"].is_u64(), "{status}");
    let devices: Vec<&str> = status["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    assert_eq!(devices, ["fs:root", "fs:workspace", "net", "vsock"]);

    let stopped = boxcar(&["stop"], &control);
    assert!(stopped.status.success(), "{}", text(&stopped.stderr));
    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();
    let stops = of_kind(&records, "control.stop");
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert_eq!(stops[0].data["mode"], "graceful");
    assert!(stops[0].data["by_pid"].as_u64().unwrap() > 0);
    // The graceful stop ended the session by a signal.
    let exits = of_kind(&records, "session.exit");
    assert_eq!(exits.len(), 1, "{exits:?}");
    assert!(exits[0].data["signal"].is_i64(), "{exits:?}");
}

/// (e) `boxcar events --type net.` on a running session prints the
/// network's records from the start: the query, the connection, the gate's
/// pass and the close, each as a line of the log, and ends when the VM
/// does.
#[test]
fn events_streams_the_network_records_of_a_running_session() {
    let Some(guest) =
        networked_guest_or_skip("events_streams_the_network_records_of_a_running_session")
    else {
        return;
    };
    let scratch = Scratch::new();
    let mut running = start(
        &guest,
        &scratch,
        &["--allow", "example.com"],
        &[
            "/bin/sh",
            "-c",
            "wget -qO- http://example.com && echo GOT; sleep 5",
        ],
    );
    let control = running.control();
    running.until("the download", |run| run.stdout().contains("GOT"));
    // From the start, with the network's records only; ends with the VM.
    let events = boxcar(&["events", "--type", "net."], &control);
    assert!(events.status.success(), "{}", text(&events.stderr));
    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());

    let lines: Vec<Record> = text(&events.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}")))
        .collect();
    assert!(!lines.is_empty(), "no events");
    assert!(
        lines.iter().all(|r| r.kind.starts_with("net.")),
        "{lines:?}"
    );
    for kind in ["net.dns", "net.connect", "net.tls", "net.close"] {
        assert!(
            lines.iter().any(|r| r.kind == kind),
            "no {kind} in {lines:?}"
        );
    }
    // Each line is the log's own record.
    let records = run.records();
    for line in &lines {
        let logged = records
            .iter()
            .find(|r| r.seq == line.seq)
            .unwrap_or_else(|| panic!("seq {} is not in the log", line.seq));
        assert_eq!(logged, line);
    }
}

/// (f) `boxcar policy allow` during a run: a download the policy denied
/// succeeds once the name is allowed, and the log has the `policy.changed`
/// between the denied query and the allowed one.
#[test]
fn policy_allow_during_a_run_lets_the_next_download_through() {
    let Some(guest) =
        networked_guest_or_skip("policy_allow_during_a_run_lets_the_next_download_through")
    else {
        return;
    };
    let scratch = Scratch::new();
    let script = "wget -qO- http://example.com > /dev/null 2>&1 || echo FIRST_FAILED; \
                  sleep 6; \
                  wget -qO- http://example.com > /dev/null 2>&1 && echo SECOND_OK";
    let mut running = start(&guest, &scratch, &[], &["/bin/sh", "-c", script]);
    let control = running.control();
    running.until("the first download to fail", |run| {
        run.stdout().contains("FIRST_FAILED")
    });

    let shown = boxcar(&["policy", "show", "--json"], &control);
    assert!(shown.status.success(), "{}", text(&shown.stderr));
    let before: Value = serde_json::from_str(text(&shown.stdout).trim()).unwrap();
    assert_eq!(before["net"]["allow"], Value::Array(Vec::new()), "{before}");
    assert_eq!(before["version"], 1);

    let allowed = boxcar(&["policy", "allow", "example.com"], &control);
    assert!(allowed.status.success(), "{}", text(&allowed.stderr));
    assert_eq!(text(&allowed.stdout), "policy version 2\n");

    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("SECOND_OK"), "{}", run.describe());
    let records = run.records();
    let changed = of_kind(&records, "policy.changed");
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert_eq!(changed[0].data["version"], 2);
    let verdicts: Vec<(u64, &str)> = of_kind(&records, "net.dns")
        .iter()
        .filter(|r| r.data["qname"] == "example.com")
        .map(|r| (r.seq, r.data["verdict"].as_str().unwrap()))
        .collect();
    assert!(
        verdicts
            .iter()
            .any(|(seq, v)| *v == "deny" && *seq < changed[0].seq),
        "{verdicts:?}"
    );
    assert!(
        verdicts
            .iter()
            .any(|(seq, v)| *v == "allow" && *seq > changed[0].seq),
        "{verdicts:?}"
    );
}

/// The whole `str` module is used by `text`; keep the import honest.
#[allow(dead_code)]
fn utf8(bytes: &[u8]) -> Option<&str> {
    str::from_utf8(bytes).ok()
}
