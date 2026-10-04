// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest sensor on a real guest: init in vsock mode with the Alpine
//! rootfs starts `boxcar-sensor` from the initramfs before the session, the
//! sensor attaches its programs and streams ring 1 to the VMM's port 1026.
//!
//! What it proves:
//!
//! - the sensor connects, attaches every program (`proc.sensor_status` says
//!   `attached`, `btf_ok`, nine programs), heartbeats, and `status.sensor`
//!   says so while the VM runs; init waited for it, so the session's own
//!   exec is the first thing ring 1 reports about the session;
//! - the host's ping right after the config is answered, and the log holds
//!   the clocks' pairing as a `sync` record;
//! - what the session does shows up as ring 1 records with the guest's
//!   clock and the thread as `subject`: the shell's fork, the exec of `ls`
//!   with its argv and the shell as parent, the exits;
//! - a root session cannot signal the sensor: `kill` gets `EPERM` from the
//!   sensor's guard and the refusal is recorded (`proc.lsm_deny`), after
//!   which the sensor still heartbeats;
//! - `bpf()` from the session, root or not, gets `EPERM` and is recorded
//!   (`proc.lsm_deny{hook:"bpf"}`): the kernel asks the LSM before it looks
//!   at capabilities, so the guard sees every call;
//! - with the sensor off (`boxcar.sensor=0`, `boxcar run --no-sensor`)
//!   there is no ring 1 and `status.sensor` is `off`.
//!
//! The probe tests run a copy of the sensor binary from the workspace share
//! (`boxcar-sensor probe-kill`, `probe-bpf`); they skip when
//! `target/x86_64-unknown-linux-musl/guest/boxcar-sensor` has not been built
//! (`cargo xtask initramfs` builds it). A uid 0 session has no capabilities,
//! so it cannot write into the workspace the host user owns; its probes
//! report on the serial console.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};

use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::control::SensorState;
use boxcar_proto::{Record, Ring, SessionId, Source};
use boxcar_vmm::guest_ctl::SessionConfig;
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::lifecycle::VmmHandle;
use boxcar_vmm::vmm::{ConsoleOut, ControlConfig, StopReason, VmConfig, VmExit, Vmm};
use boxcar_vsock::VsockConfig;

const TEST: &str = "boot_sensor";
/// Boot, the session, and the stop.
const LIMIT: Duration = Duration::from_secs(90);
/// Where `cargo xtask initramfs` leaves the sensor binary.
const SENSOR_BINARY: &str = "target/x86_64-unknown-linux-musl/guest/boxcar-sensor";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn artifact(var: &str) -> Option<PathBuf> {
    let value = env::var_os(var)?;
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        workspace_root().join(path)
    };
    path.is_file().then_some(path)
}

fn guest_or_skip() -> Option<(PathBuf, PathBuf, PathBuf)> {
    if let Err(why) = kvm_available() {
        eprintln!("{TEST}: skipped: {why}");
        return None;
    }
    let (Some(kernel), Some(initramfs), Some(rootfs)) = (
        artifact("BOXCAR_TEST_KERNEL"),
        artifact("BOXCAR_TEST_INITRAMFS"),
        env::var_os("BOXCAR_TEST_ROOTFS")
            .map(PathBuf::from)
            .map(|p| {
                if p.is_absolute() {
                    p
                } else {
                    workspace_root().join(p)
                }
            }),
    ) else {
        eprintln!("{TEST}: skipped: BOXCAR_TEST_KERNEL, BOXCAR_TEST_INITRAMFS or BOXCAR_TEST_ROOTFS is not set");
        return None;
    };
    if !rootfs.is_dir() {
        eprintln!("{TEST}: skipped: {} is not a directory", rootfs.display());
        return None;
    }
    Some((kernel, initramfs, rootfs))
}

/// The sensor binary to copy into the workspace as the probe, if built.
fn sensor_binary_or_skip() -> Option<Vec<u8>> {
    let path = workspace_root().join(SENSOR_BINARY);
    match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            eprintln!(
                "{TEST}: skipped: {}: {e} (run `cargo xtask initramfs`)",
                path.display()
            );
            None
        }
    }
}

fn share(tag: &str, host_dir: PathBuf, guest_path: &str, cache: CachePolicyKind) -> FsShareConfig {
    FsShareConfig {
        tag: tag.into(),
        host_dir,
        guest_path: guest_path.into(),
        cache,
    }
}

/// How a run is set up.
struct Options<'a> {
    argv: &'a [&'a str],
    /// The session's uid and gid; the invoking user's when `None`.
    user: Option<(u32, u32)>,
    sensor: bool,
    /// Files put in the workspace before the boot: name, bytes, mode.
    workspace_files: Vec<(&'a str, Vec<u8>, u32)>,
}

/// One run's scratch directory and what it left behind.
struct Run {
    dir: tempfile::TempDir,
    session_dir: PathBuf,
    exit: VmExit,
}

impl Run {
    fn text(&self, name: &str) -> String {
        String::from_utf8_lossy(&fs::read(self.dir.path().join(name)).unwrap_or_default())
            .into_owned()
    }

    fn workspace_text(&self, name: &str) -> String {
        self.text(&format!("workspace/{name}"))
    }

    fn describe(&self) -> String {
        format!(
            "{:?}\nconsole:\n{}\nout:\n{}",
            self.exit,
            self.text("console.log"),
            self.workspace_text("out.txt")
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

/// Boots a VM with `options`; `during` runs beside it with the handle. A
/// watchdog stops a VM that does not end within [`LIMIT`].
fn run(options: Options<'_>, during: impl FnOnce(VmmHandle) + Send + 'static) -> Option<Run> {
    let (kernel, initramfs, rootfs) = guest_or_skip()?;
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    for (name, bytes, mode) in &options.workspace_files {
        let path = workspace.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
    }
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let state = dir.path().join("state");

    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = options
        .user
        .unwrap_or_else(|| unsafe { (libc::getuid(), libc::getgid()) });
    let argv: Vec<String> = options.argv.iter().map(|&a| a.to_owned()).collect();
    let cfg = VmConfig {
        cmdline_extra: if options.sensor {
            vec!["boxcar.mode=vsock".into()]
        } else {
            vec!["boxcar.mode=vsock".into(), "boxcar.sensor=0".into()]
        },
        console: ConsoleOut::File(dir.path().join("console.log")),
        stdin: false,
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        vsock: Some(VsockConfig::new(state.join("vsock.sock"))),
        sensor: options.sensor,
        session: SessionConfig::for_user(argv, uid, gid),
        control: Some(ControlConfig {
            state_dir: state.clone(),
            session_id: SessionId::new(),
        }),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = {
        let handle = handle.clone();
        thread::spawn(move || {
            if finished.recv_timeout(LIMIT).is_err() {
                handle.request_stop(StopReason::Requested);
            }
        })
    };
    let beside = thread::spawn(move || during(handle));
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    beside.join().unwrap();
    writer.close().unwrap();
    let run = Run {
        dir,
        session_dir,
        exit,
    };
    eprintln!("{TEST}: {}", run.describe());
    Some(run)
}

fn of_kind<'a>(records: &'a [Record], kind: &str) -> Vec<&'a Record> {
    records.iter().filter(|r| r.kind == kind).collect()
}

/// Waits until `cond` holds of the sensor's status, within `wait`.
fn wait_for_sensor(
    handle: &VmmHandle,
    wait: Duration,
    cond: impl Fn(&SensorState, u64) -> bool,
) -> bool {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        let sensor = handle.status().sensor;
        if cond(&sensor.state, sensor.heartbeats) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn the_sensor_attaches_heartbeats_and_reports_the_sessions_processes() {
    let (seen_tx, seen) = mpsc::channel();
    let Some(run) = run(
        Options {
            argv: &["/bin/sh", "-c", "ls -l / > /dev/null; sleep 3; exit 0"],
            user: None,
            sensor: true,
            workspace_files: Vec::new(),
        },
        move |handle| {
            let attached = wait_for_sensor(&handle, Duration::from_secs(30), |state, beats| {
                *state == SensorState::Attached && beats >= 1
            });
            let _ = seen_tx.send((attached, handle.status().sensor));
        },
    ) else {
        return;
    };
    let (attached, status) = seen.recv().unwrap();
    assert!(
        attached,
        "the sensor never reported attached with a heartbeat: {status:?}\n{}",
        run.describe()
    );
    assert!(
        matches!(run.exit, VmExit::GuestReset { .. }),
        "{}",
        run.describe()
    );

    let records = run.records();
    let status = of_kind(&records, "proc.sensor_status");
    assert_eq!(status.len(), 1, "{}", run.describe());
    let status = status[0];
    assert_eq!(status.ring, Ring::Guest);
    assert_eq!(status.src, Source::Sensor);
    assert!(status.ts_guest_ns.is_some());
    assert_eq!(status.data["phase"], "attached", "{status:?}");
    assert_eq!(status.data["btf_ok"], true, "{status:?}");
    assert_eq!(
        status.data["programs"].as_array().unwrap().len(),
        9,
        "{status:?}"
    );
    assert!(status.data["pid"].as_u64().unwrap() > 1, "{status:?}");
    assert!(status.data.get("reason").is_none(), "{status:?}");

    let heartbeats = of_kind(&records, "proc.heartbeat");
    assert!(
        heartbeats.len() >= 2,
        "{} heartbeats\n{}",
        heartbeats.len(),
        run.describe()
    );
    assert_eq!(heartbeats[0].data["ringbuf_drops"], 0);

    // The host pinged init once the config was sent and init answered: the
    // clocks are paired in the log, from the host's side.
    let syncs = of_kind(&records, "sync");
    assert!(!syncs.is_empty(), "no sync record\n{}", run.describe());
    assert_eq!(syncs[0].ring, Ring::Host, "{:?}", syncs[0]);
    assert_eq!(syncs[0].data["method"], "vsock_rtt", "{:?}", syncs[0]);
    assert!(
        syncs[0].data["rtt_ns"].as_u64().unwrap() < 5_000_000_000,
        "{:?}",
        syncs[0]
    );
    assert!(
        syncs[0].data["guest_mono_ns"].as_u64().unwrap() > 0,
        "{:?}",
        syncs[0]
    );

    // Init waited for the sensor before the session: the shell's own exec is
    // the first ring 1 record of the session, before anything it did.
    let session_pid = of_kind(&records, "session.start")[0].data["pid"]
        .as_u64()
        .unwrap();
    let execs = of_kind(&records, "proc.exec");
    let shell = execs
        .iter()
        .find(|r| r.data["tgid"] == session_pid)
        .unwrap_or_else(|| {
            panic!(
                "no exec of the shell (pid {session_pid}) among {execs:?}\n{}",
                run.describe()
            )
        });
    assert_eq!(shell.data["argv"][0], "/bin/sh", "{shell:?}");
    // The shell forked `ls` and `sleep`; `ls` ran with its arguments and the
    // shell as its parent, and ended as the last of its process.
    let ls = execs
        .iter()
        .find(|r| r.data["argv"][0] == "ls")
        .unwrap_or_else(|| panic!("no exec of ls among {execs:?}\n{}", run.describe()));
    assert_eq!(ls.data["argv"], serde_json::json!(["ls", "-l", "/"]));
    assert_eq!(ls.data["ppid"], session_pid, "{ls:?}");
    assert_eq!(ls.data["filename"], "/bin/ls", "{ls:?}");
    // The exec is in the session's cgroup, the one the sensor filters on.
    assert_eq!(
        ls.data["cgroup_id"], status.data["session_cgroup_id"],
        "{ls:?}"
    );
    let ls_pid = ls.data["tgid"].as_u64().unwrap();
    assert_eq!(
        ls.subject.unwrap().pid as u64,
        ls.data["tid"].as_u64().unwrap()
    );
    assert!(
        of_kind(&records, "proc.fork")
            .iter()
            .any(|r| r.data["child_pid"] == ls_pid && r.data["parent_tgid"] == session_pid),
        "no fork of ls by the shell\n{}",
        run.describe()
    );
    assert!(
        of_kind(&records, "proc.exit")
            .iter()
            .any(|r| r.data["tgid"] == ls_pid && r.data["group_dead"] == true),
        "no exit of ls\n{}",
        run.describe()
    );
    for record in records.iter().filter(|r| r.kind.starts_with("proc.")) {
        assert_eq!(record.ring, Ring::Guest, "{record:?}");
        assert_eq!(record.src, Source::Sensor, "{record:?}");
        assert!(record.ts_guest_ns.is_some(), "{record:?}");
    }
}

#[test]
fn a_root_session_cannot_signal_the_sensor_and_its_bpf_is_recorded() {
    let Some(sensor) = sensor_binary_or_skip() else {
        return;
    };
    // A uid 0 session has no capabilities, so it cannot write into the
    // workspace the host user owns: the probes report on the serial console,
    // which root may open.
    let Some(run) = run(
        Options {
            argv: &[
                "/bin/sh",
                "-c",
                "exec >/dev/console 2>&1; sleep 3; \
                 /workspace/boxcar-sensor probe-kill; \
                 /workspace/boxcar-sensor probe-bpf; \
                 sleep 2; exit 0",
            ],
            user: Some((0, 0)),
            sensor: true,
            workspace_files: vec![("boxcar-sensor", sensor, 0o755)],
        },
        |_| {},
    ) else {
        return;
    };
    let console = run.text("console.log");
    let answers: Vec<&str> = console
        .lines()
        .map(str::trim)
        .filter(|line| {
            *line == "ok" || line.starts_with('E') && line.len() <= 8 || line.starts_with("error")
        })
        .collect();
    assert_eq!(answers, ["EPERM", "EPERM"], "{}", run.describe());
    let records = run.records();
    let denies = of_kind(&records, "proc.lsm_deny");
    let kills: Vec<_> = denies
        .iter()
        .filter(|r| r.data["hook"] == "task_kill")
        .collect();
    assert_eq!(kills.len(), 1, "{denies:?}\n{}", run.describe());
    assert_eq!(kills[0].data["detail"], 9, "{:?}", kills[0]);
    assert_eq!(kills[0].subject.unwrap().uid, 0);
    let bpfs: Vec<_> = denies.iter().filter(|r| r.data["hook"] == "bpf").collect();
    assert_eq!(bpfs.len(), 1, "{denies:?}\n{}", run.describe());
    // BPF_MAP_CREATE is command 0.
    assert_eq!(bpfs[0].data["detail"], 0, "{:?}", bpfs[0]);
    // The sensor went on after the refusal.
    let last_beat = of_kind(&records, "proc.heartbeat")
        .last()
        .map(|r| r.seq)
        .unwrap_or(0);
    assert!(
        last_beat > kills[0].seq,
        "no heartbeat after the refusal\n{}",
        run.describe()
    );
}

#[test]
fn bpf_from_an_unprivileged_session_is_refused_and_recorded() {
    let Some(sensor) = sensor_binary_or_skip() else {
        return;
    };
    let Some(run) = run(
        Options {
            argv: &[
                "/bin/sh",
                "-c",
                "sleep 3; /workspace/boxcar-sensor probe-bpf > /workspace/out.txt 2>&1; exit 0",
            ],
            user: None,
            sensor: true,
            workspace_files: vec![("boxcar-sensor", sensor, 0o755)],
        },
        |_| {},
    ) else {
        return;
    };
    assert_eq!(
        run.workspace_text("out.txt"),
        "EPERM\n",
        "{}",
        run.describe()
    );
    let records = run.records();
    let denies = of_kind(&records, "proc.lsm_deny");
    assert_eq!(denies.len(), 1, "{denies:?}\n{}", run.describe());
    assert_eq!(denies[0].data["hook"], "bpf", "{:?}", denies[0]);
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    assert_eq!(denies[0].subject.unwrap().uid, uid, "{:?}", denies[0]);
}

#[test]
fn no_sensor_means_no_ring_1() {
    let (seen_tx, seen) = mpsc::channel();
    let Some(run) = run(
        Options {
            argv: &["/bin/sh", "-c", "sleep 2; ls > /dev/null; exit 0"],
            user: None,
            sensor: false,
            workspace_files: Vec::new(),
        },
        move |handle| {
            thread::sleep(Duration::from_secs(1));
            let _ = seen_tx.send(handle.status().sensor);
        },
    ) else {
        return;
    };
    let status = seen.recv().unwrap();
    assert_eq!(status.state, SensorState::Off, "{status:?}");
    assert_eq!(status.heartbeats, 0);
    let records = run.records();
    assert!(
        !records.iter().any(|r| r.kind.starts_with("proc.")),
        "{}",
        run.describe()
    );
    assert!(
        !records
            .iter()
            .any(|r| r.ring == Ring::Guest && r.src == Source::Sensor),
        "{}",
        run.describe()
    );
    assert!(
        matches!(run.exit, VmExit::GuestReset { .. }),
        "{}",
        run.describe()
    );
}
