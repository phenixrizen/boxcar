// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The first real boot: the guest kernel and the hello initramfs, with no
//! filesystem shares. The init prints `BOXCAR_INIT_HELLO` on the console and
//! reboots through the i8042, so the VM must end in `GuestReset`, and the
//! session log must hold a verifiable `vmm.start` and `vmm.stop`. The same
//! boot with the `root` and `workspace` shares attached must end the same
//! way, with the guest's virtiofs driver finding both tags. Another test
//! stops a guest that never ends on its own through `VmmHandle`.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL` and
//! `BOXCAR_TEST_INITRAMFS` are set and `/dev/kvm` is accessible. Relative
//! paths are taken from the workspace root, where `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};

use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::SessionId;
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::vmm::{ConsoleOut, StopReason, VmConfig, VmExit, Vmm};

const TEST: &str = "boot_hello";
const HELLO: &str = "BOXCAR_INIT_HELLO";
const LIMIT: Duration = Duration::from_secs(10);

/// The artifact `var` names, or `None` when it is unset.
fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The kernel and initramfs, or `None` after printing why `test` skips.
fn guest_or_skip(test: &str) -> Option<(PathBuf, PathBuf)> {
    let (Some(kernel), Some(initramfs)) = (
        artifact("BOXCAR_TEST_KERNEL"),
        artifact("BOXCAR_TEST_INITRAMFS"),
    ) else {
        eprintln!("skipping {test}: BOXCAR_TEST_KERNEL and BOXCAR_TEST_INITRAMFS must both be set");
        return None;
    };
    if let Err(reason) = kvm_available() {
        eprintln!("skipping {test}: {reason}");
        return None;
    }
    Some((kernel, initramfs))
}

/// The session's record types, in order, after checking the log verifies.
fn record_kinds(session_dir: &Path) -> Vec<String> {
    let report = verify_session(session_dir).unwrap();
    assert!(report.records >= 2, "{report:?}");
    LogReader::open(session_dir)
        .unwrap()
        .records()
        .map(|record| record.unwrap().kind)
        .collect()
}

#[test]
fn hello_init_prints_its_marker_and_resets_the_guest() {
    let Some((kernel, initramfs)) = guest_or_skip(TEST) else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let session_id = SessionId::new();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path(), session_id.clone())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");

    let cfg = VmConfig {
        cmdline_extra: vec!["boxcar.mode=hello".into()],
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();

    // A watchdog stops a guest that neither resets nor shuts down.
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });

    let started = Instant::now();
    let exit = vmm.run().unwrap();
    let elapsed = started.elapsed();
    drop(done);
    watchdog.join().unwrap();
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?} after {elapsed:?}");
    // The guest's tty ends lines with CRLF: look for the marker as a substring.
    assert!(
        output.contains(HELLO),
        "no {HELLO} on the console:\n{output}"
    );
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?} after {elapsed:?}; console:\n{output}"
    );
    assert!(elapsed < LIMIT, "took {elapsed:?}");

    let kinds = record_kinds(&session_dir);
    let start = kinds.iter().position(|k| k == "vmm.start");
    let stop = kinds.iter().position(|k| k == "vmm.stop");
    assert!(
        matches!((start, stop), (Some(a), Some(b)) if a < b),
        "{kinds:?}"
    );
}

/// The hello boot with both shares: the hello init mounts neither, so the
/// guest only probes the two virtio-fs devices, which must not change how
/// it ends. `--debug-boot`'s kernel messages show the probe.
#[test]
fn hello_boots_with_the_root_and_workspace_shares_attached() {
    const TEST: &str = "boot_hello_with_shares";
    let Some((kernel, initramfs)) = guest_or_skip(TEST) else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let (rootfs, workspace) = (dir.path().join("rootfs"), dir.path().join("workspace"));
    fs::create_dir(&rootfs).unwrap();
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");
    let share = |tag: &str, host_dir, guest_path: &str, cache| FsShareConfig {
        tag: tag.into(),
        host_dir,
        guest_path: guest_path.into(),
        cache,
    };
    let cfg = VmConfig {
        cmdline_extra: vec!["boxcar.mode=hello".into()],
        debug_boot: true,
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}");
    for line in [
        "virtio-mmio: Registering device virtio-mmio.0 at 0xc0000000-0xc0000fff, IRQ 5.",
        "virtio-mmio: Registering device virtio-mmio.1 at 0xc0001000-0xc0001fff, IRQ 6.",
        "virtiofs virtio0: discovered new tag: root",
        "virtiofs virtio1: discovered new tag: workspace",
        HELLO,
    ] {
        assert!(
            output.contains(line),
            "no {line:?} on the console:\n{output}"
        );
    }
    assert!(!output.contains("probe of"), "a probe failed:\n{output}");
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?}; console:\n{output}"
    );

    let kinds = record_kinds(&session_dir);
    assert_eq!(
        kinds.first().map(String::as_str),
        Some("vmm.start"),
        "{kinds:?}"
    );
    assert!(kinds.contains(&"vmm.stop".to_owned()), "{kinds:?}");
}

/// The hello boot with no shares: virtio-fs's slots 0 and 1 stay empty and
/// the command line lists no `virtio_mmio.device=`, so the guest finds no
/// virtio-mmio device at all. `--debug-boot`'s kernel messages would show a
/// probe.
#[test]
fn hello_boots_with_no_shares_and_probes_no_virtio_device() {
    const TEST: &str = "boot_hello_no_virtio";
    let Some((kernel, initramfs)) = guest_or_skip(TEST) else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path(), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");
    let cfg = VmConfig {
        cmdline_extra: vec!["boxcar.mode=hello".into()],
        debug_boot: true,
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}");
    assert!(
        output.contains(HELLO),
        "no {HELLO} on the console:\n{output}"
    );
    // The kernel logs "Registering device" for each virtio_mmio.device=
    // entry it is given, and a failed probe by name.
    for absent in ["virtio-mmio: Registering device", "virtiofs", "probe of"] {
        assert!(
            !output.contains(absent),
            "{absent:?} on the console:\n{output}"
        );
    }
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?}; console:\n{output}"
    );

    let kinds = record_kinds(&session_dir);
    assert_eq!(
        kinds.first().map(String::as_str),
        Some("vmm.start"),
        "{kinds:?}"
    );
}

/// A guest with no init panics and, with `panic=0`, spins forever: two vCPUs,
/// one running and one parked, must both be kicked out when the handle asks.
#[test]
fn request_stop_ends_a_guest_that_never_stops() {
    const TEST: &str = "request_stop";
    let Some((kernel, initramfs)) = guest_or_skip(TEST) else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path(), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");
    let cfg = VmConfig {
        vcpus: 2,
        cmdline_extra: vec!["rdinit=/none".into(), "panic=0".into()],
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let handle = vmm.handle();

    // Ask for the stop once the guest has panicked, and time how long the
    // stop takes from then.
    let (asked, asked_at) = mpsc::channel();
    let stopper = thread::spawn(move || {
        let deadline = Instant::now() + LIMIT;
        while Instant::now() < deadline {
            let output = fs::read(&console).unwrap_or_default();
            if String::from_utf8_lossy(&output).contains("Kernel panic") {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        asked.send(Instant::now()).unwrap();
        handle.request_stop(StopReason::Requested);
    });

    let exit = vmm.run().unwrap();
    let stopped = Instant::now();
    stopper.join().unwrap();
    writer.close().unwrap();
    let latency = stopped - asked_at.recv().unwrap();
    eprintln!("{TEST}: {exit:?}, {latency:?} after the request");

    assert_eq!(exit, VmExit::StopRequested(StopReason::Requested));
    assert!(latency < Duration::from_secs(2), "took {latency:?}");
    let kinds = record_kinds(&session_dir);
    assert!(kinds.contains(&"vmm.stop".to_owned()), "{kinds:?}");
}
