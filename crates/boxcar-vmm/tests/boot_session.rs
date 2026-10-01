// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session over vsock: init in vsock mode with the Alpine rootfs and
//! the vsock device, the guest control channel on port 1024 and the
//! transitional PTY relay on 1025 writing the session's terminal to a file.
//!
//! What it proves:
//!
//! - init connects the control channel and the terminal from privileged
//!   ports, gets its config, and runs the session on a PTY: what the
//!   session prints reaches the relay's output;
//! - the session's exit code comes back as the run's (7), a session killed
//!   by a signal as 128 plus it (137), and the log has `session.start`
//!   (argv, pid) and `session.exit` (code or signal);
//! - a graceful stop through the control socket (`boxcar stop`) asks init
//!   to end the session: `SIGTERM`, `session.exit{signal:15}`, and the VM
//!   ends within the grace plus 3 s, exiting 0 as a requested stop.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::{Record, SessionId};
use boxcar_vmm::guest_ctl::SessionConfig;
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::lifecycle::exit_code_for;
use boxcar_vmm::pty_relay;
use boxcar_vmm::vmm::{ConsoleOut, ControlConfig, StopReason, VmConfig, VmExit, Vmm};
use boxcar_vsock::VsockConfig;

const TEST: &str = "boot_session";
/// Boot, the session, and the stop.
const LIMIT: Duration = Duration::from_secs(60);
/// The graceful stop's grace, the control protocol's default.
const GRACE_MS: u64 = 5000;
/// What the VMM adds to the grace before it stops the VM itself.
const MARGIN: Duration = Duration::from_secs(3);

/// The artifact `var` names, or `None` when it is unset.
fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The kernel, initramfs and rootfs, or `None` after printing why the test
/// skips.
fn guest_or_skip(test: &str) -> Option<(PathBuf, PathBuf, PathBuf)> {
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
    Some((kernel, initramfs, rootfs))
}

fn share(tag: &str, host_dir: PathBuf, guest_path: &str, cache: CachePolicyKind) -> FsShareConfig {
    FsShareConfig {
        tag: tag.into(),
        host_dir,
        guest_path: guest_path.into(),
        cache,
    }
}

/// One run's scratch directory and what it left behind.
struct Run {
    dir: tempfile::TempDir,
    session_dir: PathBuf,
    exit: VmExit,
    elapsed: Duration,
    /// When `Vmm::run` returned.
    stopped_at: Instant,
}

impl Run {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn text(&self, name: &str) -> String {
        String::from_utf8_lossy(&fs::read(self.path(name)).unwrap_or_default()).into_owned()
    }

    fn describe(&self) -> String {
        format!(
            "{:?} after {:?}\nsession:\n{}\nconsole:\n{}",
            self.exit,
            self.elapsed,
            self.text("session.out"),
            self.text("console.log")
        )
    }

    /// The session's records, once the log is verified.
    fn records(&self) -> Vec<Record> {
        let report = verify_session(&self.session_dir).unwrap();
        eprintln!("{TEST}: {report:?}");
        LogReader::open(&self.session_dir)
            .unwrap()
            .records()
            .map(Result::unwrap)
            .collect()
    }
}

/// Boots `argv` as the session in vsock mode, with the relay writing to
/// `session.out` and the control socket in `state/`; `during` runs beside
/// the VM with its handle and the control socket's path. A watchdog stops
/// a VM that does not end within [`LIMIT`].
fn run(
    argv: &[&str],
    during: impl FnOnce(boxcar_vmm::vmm::VmmHandle, PathBuf) + Send + 'static,
) -> Option<Run> {
    let (kernel, initramfs, rootfs) = guest_or_skip(TEST)?;
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let state = dir.path().join("state");

    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let argv: Vec<String> = argv.iter().map(|&a| a.to_owned()).collect();
    let cfg = VmConfig {
        cmdline_extra: vec!["boxcar.mode=vsock".into()],
        console: ConsoleOut::File(dir.path().join("console.log")),
        stdin: false,
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        vsock: Some(VsockConfig::new(state.join("vsock.sock"))),
        session: SessionConfig::for_user(argv, uid, gid),
        control: Some(ControlConfig {
            state_dir: state.clone(),
            session_id: SessionId::new(),
        }),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let out = File::create(dir.path().join("session.out")).unwrap();
    pty_relay::register(&vmm.handle().services(), Box::new(out), None, vmm.handle()).unwrap();
    let control = vmm.control_path().unwrap().to_owned();

    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let beside = {
        let handle = vmm.handle();
        thread::spawn(move || during(handle, control))
    };
    let started = Instant::now();
    let exit = vmm.run().unwrap();
    let stopped_at = Instant::now();
    let elapsed = started.elapsed();
    drop(done);
    watchdog.join().unwrap();
    beside.join().unwrap();
    writer.close().unwrap();
    let run = Run {
        dir,
        session_dir,
        exit,
        elapsed,
        stopped_at,
    };
    eprintln!("{TEST}: {}", run.describe());
    Some(run)
}

/// The records of type `kind`.
fn of_kind<'a>(records: &'a [Record], kind: &str) -> Vec<&'a Record> {
    records.iter().filter(|r| r.kind == kind).collect()
}

#[test]
fn the_session_exit_code_and_output_come_back() {
    let Some(run) = run(&["/bin/sh", "-c", "echo SESSION_HI; exit 7"], |_, _| {}) else {
        return;
    };
    assert!(
        matches!(
            run.exit,
            VmExit::GuestReset {
                session: Some(boxcar_vmm::vmm::SessionOutcome {
                    code: Some(7),
                    signal: None
                })
            }
        ),
        "{}",
        run.describe()
    );
    assert_eq!(exit_code_for(&run.exit), 7);
    assert!(
        run.text("session.out").contains("SESSION_HI"),
        "{}",
        run.describe()
    );
    // The serial console has init's exit line, not the session's output.
    assert!(
        run.text("console.log").contains("boxcar: session exited 7"),
        "{}",
        run.describe()
    );
    assert!(
        !run.text("console.log").contains("SESSION_HI"),
        "{}",
        run.describe()
    );

    let records = run.records();
    let start = of_kind(&records, "session.start");
    assert_eq!(start.len(), 1, "{start:?}");
    assert_eq!(
        start[0].data["argv"],
        serde_json::json!(["/bin/sh", "-c", "echo SESSION_HI; exit 7"])
    );
    assert_eq!(start[0].data["cwd"], "/workspace");
    assert!(start[0].data["pid"].as_u64().unwrap() > 1, "{:?}", start[0]);
    let exit = of_kind(&records, "session.exit");
    assert_eq!(exit.len(), 1, "{exit:?}");
    assert_eq!(exit[0].data, serde_json::json!({"code": 7, "signal": null}));
    let stop = of_kind(&records, "vmm.stop");
    assert_eq!(stop[0].data["exit_code"], 7, "{stop:?}");
    assert!(
        start[0].seq < exit[0].seq && exit[0].seq < stop[0].seq,
        "{start:?} {exit:?} {stop:?}"
    );

    // Both channels from init's privileged ports.
    let connects: Vec<(u64, u64)> = of_kind(&records, "vsock.connect")
        .iter()
        .filter(|r| r.data["verdict"] == "allow")
        .map(|r| {
            (
                r.data["port"].as_u64().unwrap(),
                r.data["src_port"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(connects, [(1024, 1023), (1025, 1022)], "{records:?}");
}

#[test]
fn a_session_killed_by_a_signal_exits_128_plus_it() {
    let Some(run) = run(&["/bin/sh", "-c", "kill -9 $$"], |_, _| {}) else {
        return;
    };
    assert_eq!(exit_code_for(&run.exit), 137, "{}", run.describe());
    let records = run.records();
    let exit = of_kind(&records, "session.exit");
    assert_eq!(exit.len(), 1, "{exit:?}");
    assert_eq!(exit[0].data, serde_json::json!({"code": null, "signal": 9}));
}

/// Speaks the control protocol: waits for the session to start, asks for a
/// graceful stop, and returns when it was asked.
fn graceful_stop(
    handle: boxcar_vmm::vmm::VmmHandle,
    control: PathBuf,
    asked: mpsc::Sender<Instant>,
) {
    let deadline = Instant::now() + LIMIT;
    while handle.status().guest.session_pid.is_none() {
        if Instant::now() > deadline {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let stream = UnixStream::connect(&control).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut lines = BufReader::new(stream.try_clone().unwrap());
    let mut hello = String::new();
    lines.read_line(&mut hello).unwrap();
    assert!(hello.contains("\"hello\""), "{hello}");
    let request = format!(
        "{{\"v\":1,\"id\":1,\"op\":\"stop\",\"mode\":\"graceful\",\"timeout_ms\":{GRACE_MS}}}\n"
    );
    let _ = asked.send(Instant::now());
    (&stream).write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    lines.read_line(&mut response).unwrap();
    assert!(response.contains("\"ok\":true"), "{response}");
}

#[test]
fn a_graceful_stop_ends_the_session_with_sigterm() {
    let (asked_tx, asked) = mpsc::channel();
    let Some(run) = run(&["sleep", "100"], move |handle, control| {
        graceful_stop(handle, control, asked_tx)
    }) else {
        return;
    };
    let asked = asked.recv().expect("the stop was never asked for");
    let took = run.stopped_at.saturating_duration_since(asked);
    eprintln!("{TEST}: the VM stopped {took:?} after the stop was asked for");
    assert_eq!(
        run.exit,
        VmExit::StopRequested(StopReason::Requested),
        "{}",
        run.describe()
    );
    assert_eq!(exit_code_for(&run.exit), 0);
    assert!(
        took < Duration::from_millis(GRACE_MS) + MARGIN,
        "{took:?}; {}",
        run.describe()
    );
    let records = run.records();
    let exit = of_kind(&records, "session.exit");
    assert_eq!(exit.len(), 1, "{}", run.describe());
    assert_eq!(
        exit[0].data,
        serde_json::json!({"code": null, "signal": 15})
    );
    assert_eq!(of_kind(&records, "control.stop").len(), 1);
    let stop = of_kind(&records, "vmm.stop");
    assert_eq!(stop[0].data["reason"], "stop_requested", "{stop:?}");
    assert_eq!(stop[0].data["exit_code"], 0, "{stop:?}");
}
