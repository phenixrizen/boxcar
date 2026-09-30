// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The M1 end-to-end tests: the `boxcar` binary itself runs `boxcar run
//! ... -- CMD` on KVM with the guest kernel, the initramfs and the Alpine
//! rootfs, the console in a file, a fresh audit directory and a fresh
//! workspace, and the tests read what it leaves behind: its exit code, the
//! console, the workspace and the session's audit log.
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

    /// Both outputs, for a failed assertion.
    fn describe(&self) -> String {
        format!(
            "{}; after {:?}\nstderr:\n{}\nconsole:\n{}",
            self.status, self.elapsed, self.stderr, self.console
        )
    }
}

/// `boxcar run ... -- <command>` in `scratch`, with stdin at /dev/null, the
/// console in `console.log`, the audit log under `audit/` and `workspace/`
/// as the workspace. A run past [`LIMIT`] is killed and fails the test.
fn boxcar_run(guest: &Guest, scratch: &Scratch, command: &[&str]) -> Run {
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
        .arg("--")
        .args(command)
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

/// (b) M1 does not pass the command's exit code on: boxcar exits 0, and
/// the console says how the session ended.
#[test]
fn the_exit_code_shows_on_the_console_and_boxcar_exits_0() {
    let Some(guest) = guest_or_skip("kvm_m1 exit") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(&guest, &scratch, &["/bin/sh", "-c", "exit 7"]);
    eprintln!("kvm_m1 exit: {} after {:?}", run.status, run.elapsed);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(
        run.console.contains("boxcar: session exited 7"),
        "{}",
        run.describe()
    );
    run.records();
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
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());

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
        run.console.contains("from-the-host.txt"),
        "{}",
        run.describe()
    );
    assert!(
        run.console.contains("boxcar: session exited 0"),
        "{}",
        run.describe()
    );
}

/// A command found nowhere: the console says so, and the session exits
/// 127 as a shell's would.
#[test]
fn a_missing_command_exits_127() {
    let Some(guest) = guest_or_skip("kvm_m1 missing") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(&guest, &scratch, &["boxcar-no-such-command", "arg"]);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    for line in [
        "boxcar-init: exec: boxcar-no-such-command: ENOENT",
        "boxcar: session exited 127",
    ] {
        assert!(run.console.contains(line), "{line}: {}", run.describe());
    }
}

/// The command's last line reaches the console every time: the session's
/// exit must not hang up the terminal before the serial port has sent it.
#[test]
fn the_last_line_of_a_command_is_never_lost() {
    let Some(guest) = guest_or_skip("kvm_m1 mark") else {
        return;
    };
    let mut lost = Vec::new();
    for run_no in 1..=MARK_RUNS {
        let scratch = Scratch::new();
        let run = boxcar_run(&guest, &scratch, &["/bin/sh", "-c", "echo MARK_END"]);
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
