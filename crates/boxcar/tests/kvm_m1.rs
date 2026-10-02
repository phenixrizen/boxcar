// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The M1 end-to-end tests: the `boxcar` binary itself runs `boxcar run
//! ... -- CMD` on KVM with the guest kernel, the initramfs and the Alpine
//! rootfs, the console in a file, a fresh audit directory and a fresh
//! workspace, and the tests read what it leaves behind: its exit code, the
//! console, its stdout, the workspace and the session's audit log.
//!
//! `boxcar run` with shares now has the vsock device, and runs the session
//! in vsock mode: the session's terminal goes to stdout, the serial console
//! to `--console-log`, and the run exits with the session's code. The
//! tests about M1's console session itself (the exit code shown on the
//! console with the run exiting 0, init's exec failure on the console, the
//! serial console's last line) run with `--no-vsock`, which keeps it; each
//! has a vsock counterpart.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible (`cargo xtask test-kvm m1` checks and sets them). Relative
//! paths are taken from the workspace root, where `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, io};

use boxcar_audit::{verify_session, LogReader};
use boxcar_proto::Record;
use boxcar_vmm::kvm::kvm_available;

/// How long one run may take, boot to exit.
const LIMIT: Duration = Duration::from_secs(30);

/// How many times the console-drain test runs its command.
const MARK_RUNS: usize = 40;

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

    fn workspace(&self) -> PathBuf {
        self.path("workspace")
    }
}

/// What a `boxcar run` left behind.
struct Run {
    status: ExitStatus,
    elapsed: Duration,
    console: String,
    /// The session's terminal, in vsock mode.
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

/// `boxcar run ... -- <command>` in `scratch`, with stdin at /dev/null, the
/// console in `console.log`, stdout in `stdout.log`, the audit log under
/// `audit/` and `workspace/` as the workspace. A run past [`LIMIT`] is
/// killed and fails the test.
fn boxcar_run(guest: &Guest, scratch: &Scratch, command: &[&str]) -> Run {
    boxcar_run_with(guest, scratch, &[], command, &[])
}

/// [`boxcar_run`] in M1's console mode: `--no-vsock`.
fn boxcar_run_console(guest: &Guest, scratch: &Scratch, command: &[&str]) -> Run {
    boxcar_run_with(guest, scratch, &["--no-vsock"], command, &[])
}

/// [`boxcar_run`] with the flags `flags` before the `--`, and the
/// variables `env` set for boxcar.
fn boxcar_run_with(
    guest: &Guest,
    scratch: &Scratch,
    flags: &[&str],
    command: &[&str],
    env: &[(&str, String)],
) -> Run {
    let console = scratch.path("console.log");
    let stderr = scratch.path("stderr.log");
    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .arg("run")
        .arg("--kernel")
        .arg(&guest.kernel)
        .arg("--initramfs")
        .arg(&guest.initramfs)
        .arg("--rootfs")
        .arg(&guest.rootfs)
        .arg("--workspace")
        .arg(scratch.workspace())
        .arg("--audit-dir")
        .arg(scratch.path("audit"))
        .arg("--console-log")
        .arg(&console)
        .args(flags)
        .arg("--")
        .args(command)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(File::create(scratch.path("stdout.log")).unwrap())
        .stderr(File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "boxcar run -- {command:?} did not exit within {LIMIT:?}; console:\n{}",
                read_lossy(&console)
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    Run {
        status,
        elapsed: start.elapsed(),
        console: read_lossy(&console),
        stdout: read_lossy(&scratch.path("stdout.log")),
        stderr: read_lossy(&stderr),
    }
}

/// The file at `path` as text, empty when it is not there.
fn read_lossy(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

/// The records of type `kind` about `path` on the share `mount`.
fn about<'a>(records: &'a [Record], kind: &str, mount: &str, path: &str) -> Vec<&'a Record> {
    records
        .iter()
        .filter(|r| r.kind == kind && r.data["mount"] == mount && r.data["path"] == path)
        .collect()
}

/// (a) A command writes a file in the workspace: boxcar exits 0 in time,
/// the file is on the host, and the verified log holds its creation and
/// its close, with the bytes written and the blake3 of what is on disk.
#[test]
fn a_command_writes_a_file_the_audit_log_hashes() {
    let Some(guest) = guest_or_skip("kvm_m1 write") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &["/bin/sh", "-c", "echo M1_OK > /workspace/out.txt"],
    );
    eprintln!("kvm_m1 write: {} after {:?}", run.status, run.elapsed);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.elapsed < LIMIT, "{}", run.describe());
    assert!(
        run.console.contains("boxcar: session exited 0"),
        "{}",
        run.describe()
    );

    let written = fs::read(scratch.workspace().join("out.txt")).unwrap();
    assert!(
        String::from_utf8_lossy(&written).contains("M1_OK"),
        "{written:?}"
    );

    let records = run.records();
    let creates = about(&records, "fs.create", "workspace", "/out.txt");
    assert_eq!(creates.len(), 1, "{creates:?}");
    assert_eq!(creates[0].data["result"]["ok"], true, "{:?}", creates[0]);
    let closes = about(&records, "fs.close", "workspace", "/out.txt");
    assert_eq!(closes.len(), 1, "{closes:?}");
    let close = closes[0];
    eprintln!("kvm_m1 write: {close:?}");
    assert_eq!(close.data["bytes_written"].as_u64(), Some(6), "{close:?}");
    assert_eq!(
        close.data["blake3"],
        format!("b3:{}", blake3::hash(&written).to_hex()),
        "{close:?}"
    );
    let subject = close.subject.as_ref().expect("the close has a subject");
    assert!(subject.pid > 1, "{subject:?}");
}

/// (b) M1's console session does not pass the command's exit code on:
/// boxcar exits 0, and the console says how the session ended
/// (`--no-vsock`).
#[test]
fn the_exit_code_shows_on_the_console_and_boxcar_exits_0() {
    let Some(guest) = guest_or_skip("kvm_m1 exit") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run_console(&guest, &scratch, &["/bin/sh", "-c", "exit 7"]);
    eprintln!("kvm_m1 exit: {} after {:?}", run.status, run.elapsed);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(
        run.console.contains("boxcar: session exited 7"),
        "{}",
        run.describe()
    );
    run.records();
}

/// With the vsock device the session's exit code is the run's, and its
/// output is on stdout, not on the console.
#[test]
fn the_sessions_exit_code_is_the_runs() {
    let Some(guest) = guest_or_skip("kvm_m1 vsock exit") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(&guest, &scratch, &["/bin/sh", "-c", "echo hi; exit 7"]);
    eprintln!("kvm_m1 vsock exit: {} after {:?}", run.status, run.elapsed);
    assert_eq!(run.status.code(), Some(7), "{}", run.describe());
    assert_eq!(run.stdout.trim_end(), "hi", "{}", run.describe());
    assert!(!run.console.contains("hi\r"), "{}", run.describe());
    let records = run.records();
    let exit: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind == "session.exit")
        .collect();
    assert_eq!(exit.len(), 1, "{exit:?}");
    assert_eq!(exit[0].data["code"], 7, "{exit:?}");
}

/// (c) Reading a file of the root share is recorded, whatever the answer,
/// with the guest process that asked.
#[test]
fn reading_etc_shadow_is_recorded_with_its_guest_pid() {
    let Some(guest) = guest_or_skip("kvm_m1 shadow") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(&guest, &scratch, &["/bin/sh", "-c", "cat /etc/shadow"]);
    eprintln!("kvm_m1 shadow: {} after {:?}", run.status, run.elapsed);
    // The run exits with cat's code: 1 when the session may not read it.
    assert!(
        matches!(run.status.code(), Some(0 | 1)),
        "{}",
        run.describe()
    );

    let records = run.records();
    let opens = about(&records, "fs.open", "root", "/etc/shadow");
    assert!(!opens.is_empty(), "no fs.open of /etc/shadow");
    for open in opens {
        eprintln!("kvm_m1 shadow: {open:?}");
        let subject = open.subject.as_ref().expect("the open has a subject");
        assert!(subject.pid > 1, "{subject:?}");
    }
}

/// A bare command name is found through the session's PATH.
#[test]
fn a_command_is_found_through_path() {
    let Some(guest) = guest_or_skip("kvm_m1 path") else {
        return;
    };
    let scratch = Scratch::new();
    fs::write(scratch.workspace().join("from-the-host.txt"), b"hi\n").unwrap();
    let run = boxcar_run(&guest, &scratch, &["ls", "/workspace"]);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(
        run.stdout.contains("from-the-host.txt"),
        "{}",
        run.describe()
    );
    assert!(
        run.console.contains("boxcar: session exited 0"),
        "{}",
        run.describe()
    );
}

/// A command found nowhere: init says so, and the session exits 127 as a
/// shell's would. On M1's console (`--no-vsock`) both show on the console
/// and the run exits 0; in vsock mode the failure is on the session's
/// terminal (stdout) and the run exits 127.
#[test]
fn a_missing_command_exits_127() {
    let Some(guest) = guest_or_skip("kvm_m1 missing") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run_console(&guest, &scratch, &["boxcar-no-such-command", "arg"]);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    for line in [
        "boxcar-init: exec: boxcar-no-such-command: ENOENT",
        "boxcar: session exited 127",
    ] {
        assert!(run.console.contains(line), "{line}: {}", run.describe());
    }

    let scratch = Scratch::new();
    let run = boxcar_run(&guest, &scratch, &["boxcar-no-such-command", "arg"]);
    assert_eq!(run.status.code(), Some(127), "{}", run.describe());
    assert!(
        run.stdout
            .contains("boxcar-init: exec: boxcar-no-such-command: ENOENT"),
        "{}",
        run.describe()
    );
    assert!(
        run.console.contains("boxcar: session exited 127"),
        "{}",
        run.describe()
    );
}

/// The command's last line reaches the console every time: the session's
/// exit must not hang up the terminal before the serial port has sent it
/// (M1's console session, `--no-vsock`).
#[test]
fn the_last_line_of_a_command_is_never_lost() {
    let Some(guest) = guest_or_skip("kvm_m1 mark") else {
        return;
    };
    let mut lost = Vec::new();
    for run_no in 1..=MARK_RUNS {
        let scratch = Scratch::new();
        let run = boxcar_run_console(&guest, &scratch, &["/bin/sh", "-c", "echo MARK_END"]);
        assert_eq!(run.status.code(), Some(0), "{}", run.describe());
        if !run.console.contains("MARK_END") {
            eprintln!("kvm_m1 mark: run {run_no} lost it:\n{}", run.console);
            lost.push(run_no);
        }
    }
    eprintln!(
        "kvm_m1 mark: MARK_END in {} of {MARK_RUNS} runs",
        MARK_RUNS - lost.len()
    );
    assert!(lost.is_empty(), "lost in runs {lost:?}");
}

/// How many times the PTY hub's last-line test runs its command.
const HUB_MARK_RUNS: usize = 20;

/// The same in vsock mode: init drains the session's PTY to the terminal
/// stream and waits for the PTY hub to have read it before it reboots, and
/// `boxcar run` writes out what its own client of the hub holds before it
/// exits, so the last line is on stdout every time.
#[test]
fn the_last_line_reaches_stdout_through_the_pty_hub() {
    let Some(guest) = guest_or_skip("kvm_m1 hub mark") else {
        return;
    };
    let mut lost = Vec::new();
    for run_no in 1..=HUB_MARK_RUNS {
        let scratch = Scratch::new();
        let run = boxcar_run(&guest, &scratch, &["/bin/sh", "-c", "echo MARK_END"]);
        assert_eq!(run.status.code(), Some(0), "{}", run.describe());
        if run.stdout != "MARK_END\r\n" {
            eprintln!("kvm_m1 hub mark: run {run_no} got {:?}", run.stdout);
            lost.push(run_no);
        }
    }
    eprintln!(
        "kvm_m1 hub mark: MARK_END in {} of {HUB_MARK_RUNS} runs",
        HUB_MARK_RUNS - lost.len()
    );
    assert!(lost.is_empty(), "lost in runs {lost:?}");
}

/// The reviewer's stdout probe as a test: stdout is a non-blocking pipe
/// (`EAGAIN` once full) whose reader stalls a second while the session
/// prints 300,000 bytes, then reads slowly. Every byte arrives, in order,
/// and the run exits 0: the PTY hub takes the session's output as it comes
/// (300,000 bytes is under the 1 MiB it keeps for a client), the stdout
/// writer waits out `EAGAIN`, and `boxcar run` writes out what it holds
/// before it exits.
#[test]
fn a_slow_non_blocking_stdout_gets_all_of_the_session() {
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd};

    let Some(guest) = guest_or_skip("kvm_m1 slow stdout") else {
        return;
    };
    let scratch = Scratch::new();
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors into `fds`.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both are new descriptors that nothing else owns.
    let (read_end, write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: fcntl with integer arguments only.
    unsafe {
        let flags = libc::fcntl(fds[1], libc::F_GETFL);
        assert_eq!(
            libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    let script = "head -c 300000 /dev/zero | tr '\\0' x; echo; echo END_OF_OUTPUT";
    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .arg("run")
        .arg("--kernel")
        .arg(&guest.kernel)
        .arg("--initramfs")
        .arg(&guest.initramfs)
        .arg("--rootfs")
        .arg(&guest.rootfs)
        .arg("--workspace")
        .arg(scratch.workspace())
        .arg("--audit-dir")
        .arg(scratch.path("audit"))
        .arg("--console-log")
        .arg(scratch.path("console.log"))
        .args(["--", "/bin/sh", "-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::from(write_end))
        .stderr(File::create(scratch.path("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1));
    let mut reader = File::from(read_end);
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("{e}"),
        }
        thread::sleep(Duration::from_millis(5));
        assert!(start.elapsed() < LIMIT, "no end within {LIMIT:?}");
    }
    let status = child.wait().unwrap();
    let stderr = read_lossy(&scratch.path("stderr.log"));
    let xs = got.iter().filter(|&&b| b == b'x').count();
    eprintln!(
        "kvm_m1 slow stdout: {status} after {:?}, {} bytes, {xs} x",
        start.elapsed(),
        got.len()
    );
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_eq!(xs, 300_000, "{stderr}");
    let text = String::from_utf8_lossy(&got);
    assert!(text.ends_with("x\r\nEND_OF_OUTPUT\r\n"), "{stderr}");
}

/// A loop of 200 file writes in the workspace, then `AFTER`.
const WRITE_LOOP: [&str; 3] = [
    "/bin/sh",
    "-c",
    "for i in $(seq 200); do echo $i > /workspace/f$i; done; echo AFTER",
];

/// Files in the workspace.
fn workspace_files(scratch: &Scratch) -> usize {
    fs::read_dir(scratch.workspace()).unwrap().count()
}

/// The audit log fails in the middle of a command, as it would on a full
/// disk: boxcar stops the VM, exits 3 and says why, the command does not
/// finish, and the log it leaves verifies up to its last good record.
///
/// The failure comes from `BOXCAR_TEST_FAIL_AUDIT_AFTER=<n>`, which a
/// `kvm-tests` build of boxcar honours: the log checkpoints after every
/// record, and the first `n` syncs succeed while every later one fails with
/// ENOSPC. A clean run of the same command first counts the records the
/// boot makes before the loop, so that `n` lands about 10 files into it
/// (each file is an `fs.create` and an `fs.close`): the writer runs behind
/// the guest, and the 190 files left are the margin by which it may.
#[test]
fn an_audit_log_failure_stops_the_vm_and_exits_3() {
    let Some(guest) = guest_or_skip("kvm_m1 audit failure") else {
        return;
    };
    let scratch = Scratch::new();
    let clean = boxcar_run(&guest, &scratch, &WRITE_LOOP);
    assert_eq!(clean.status.code(), Some(0), "{}", clean.describe());
    assert!(clean.stdout.contains("AFTER"), "{}", clean.describe());
    assert_eq!(workspace_files(&scratch), 200);
    let boot = clean
        .records()
        .iter()
        .filter(|r| r.kind != "checkpoint")
        .position(|r| r.kind == "fs.create" && r.data["path"] == "/f1")
        .expect("the clean run created /f1");

    let ok_syncs = boot + 20;
    let scratch = Scratch::new();
    let env = [("BOXCAR_TEST_FAIL_AUDIT_AFTER", ok_syncs.to_string())];
    let run = boxcar_run_with(&guest, &scratch, &[], &WRITE_LOOP, &env);
    eprintln!(
        "kvm_m1 audit failure: {} after {:?}; the boot makes {boot} records",
        run.status, run.elapsed
    );
    assert_eq!(run.status.code(), Some(3), "{}", run.describe());
    assert!(!run.stdout.contains("AFTER"), "{}", run.describe());

    // Every record is followed by its checkpoint, so sync n + 1 is the one
    // after record n + 1, the checkpoint at seq 2n + 2.
    let n = ok_syncs as u64;
    let line = run
        .stderr
        .lines()
        .find(|l| l.starts_with("audit log failed: "))
        .unwrap_or_else(|| panic!("no failure line: {}", run.describe()));
    eprintln!("kvm_m1 audit failure: {line}");
    let segment = run.session_dir().join("events.000001.jsonl");
    let reason = io::Error::from_raw_os_error(libc::ENOSPC);
    assert_eq!(
        line,
        format!(
            "audit log failed: cannot sync {} at seq {}: {reason}",
            segment.display(),
            2 * n + 2
        ),
        "{}",
        run.describe()
    );

    // The unsynced checkpoint was taken back: the log verifies and ends
    // with the last record the writer wrote whole.
    let records = run.records();
    let last = records.last().unwrap();
    assert_eq!(last.seq, 2 * n + 1, "{last:?}");
    assert_ne!(last.kind, "checkpoint", "{last:?}");
    let events = records.iter().filter(|r| r.kind != "checkpoint").count();
    assert_eq!(events as u64, n + 1);

    // The loop was cut short: its writes failed with EIO or the VM had
    // stopped before it got to them.
    let creates = records.iter().filter(|r| r.kind == "fs.create").count();
    let files = workspace_files(&scratch);
    eprintln!("kvm_m1 audit failure: {creates} creates recorded, {files} files on the host");
    assert!(creates > 0, "the failure came before the loop");
    assert!(files < 200, "{files} files");
    assert!(
        !records.iter().any(|r| r.kind == "vmm.stop"),
        "vmm.stop was refused"
    );
}
