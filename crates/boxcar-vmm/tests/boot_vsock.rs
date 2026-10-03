// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The vsock device on a real guest: the console init with the Alpine
//! rootfs and the vsock device in slot 3, and a session that lists the
//! guest's virtio drivers, shows which device the vsock transport bound,
//! says `DONE`, and sleeps until the test stops the VM.
//!
//! What it proves:
//!
//! - the guest kernel probes the device: its `vmw_vsock_virtio_transport`
//!   driver is registered and bound to a virtio device;
//! - while the VM runs, the host socket `<state>/vsock.sock` exists, mode
//!   0600, in the state directory the VMM made (0700);
//! - a host process that connects to it and asks for guest port 1024
//!   (`CONNECT 1024\n`), where nothing in the guest listens, is closed on
//!   within 5 s without an `OK` line: the muxer took the command and sent
//!   the guest a request, the guest's kernel answered with a reset, and the
//!   muxer closed the host end. (With no answer at all the host end would
//!   stay open: the muxer only drops a host connection on the guest's
//!   reset.)
//! - such a refused host connection leaves no `vsock.*` record: host
//!   connections are recorded only once the guest accepts them;
//! - the socket is gone once the VM has stopped;
//! - a VM whose build fails after the vsock device was attached leaves
//!   neither the socket nor the state directory the device made for it.
//!
//! What it does not prove: a guest-initiated connection. The console init
//! opens none, and the Alpine rootfs has no tool that speaks AF_VSOCK; the
//! guest control channel (Task 11) is the first. The rules on guest
//! connections are covered without a guest in `boxcar-vsock`'s tests.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};

use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::{guestcmd, Record, SessionId};
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::vmm::{ConsoleOut, StopReason, VmConfig, VmExit, Vmm, VmmError};
use boxcar_vsock::VsockConfig;

const TEST: &str = "boot_vsock";
/// Boot and the session's listing.
const BOOT_LIMIT: Duration = Duration::from_secs(60);
/// How long the host connection may stay open before the guest's reset.
const RESET_LIMIT: Duration = Duration::from_secs(5);
/// The vsock transport's driver, as the guest kernel names it.
const DRIVER: &str = "vmw_vsock_virtio_transport";

/// What the session runs: the drivers, the devices bound to the vsock
/// transport, `DONE`, and a sleep the test cuts short.
const SESSION: [&str; 3] = [
    "/bin/sh",
    "-c",
    "ls /sys/bus/virtio/drivers/; \
     for d in /sys/bus/virtio/drivers/vmw_vsock_virtio_transport/virtio*; do echo BOUND $d; done; \
     echo DONE; sleep 60",
];

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
fn guest_or_skip() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let (Some(kernel), Some(initramfs), Some(rootfs)) = (
        artifact("BOXCAR_TEST_KERNEL"),
        artifact("BOXCAR_TEST_INITRAMFS"),
        artifact("BOXCAR_TEST_ROOTFS"),
    ) else {
        eprintln!(
            "skipping {TEST}: BOXCAR_TEST_KERNEL, BOXCAR_TEST_INITRAMFS and \
             BOXCAR_TEST_ROOTFS must all be set"
        );
        return None;
    };
    if let Err(reason) = kvm_available() {
        eprintln!("skipping {TEST}: {reason}");
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

/// What the test saw while the VM ran.
#[derive(Debug)]
struct Probe {
    /// The socket's mode, and its directory's.
    modes: (u32, u32),
    /// What the host connection read before it was closed on.
    answer: Vec<u8>,
    /// How long it stayed open after the command.
    open_for: Duration,
}

/// Waits for `DONE` on the console, then looks at the socket and asks it
/// for guest port 1024.
fn probe(console: &Path, uds: &Path) -> Result<Probe, String> {
    let deadline = Instant::now() + BOOT_LIMIT;
    loop {
        let output = fs::read(console).unwrap_or_default();
        if String::from_utf8_lossy(&output).contains("DONE") {
            break;
        }
        if Instant::now() > deadline {
            return Err("no DONE on the console".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let meta = fs::symlink_metadata(uds).map_err(|e| format!("{}: {e}", uds.display()))?;
    if !meta.file_type().is_socket() {
        return Err(format!("{} is not a socket", uds.display()));
    }
    let dir = uds.parent().ok_or("the socket has no directory")?;
    let dir_mode = fs::metadata(dir)
        .map_err(|e| e.to_string())?
        .permissions()
        .mode();
    let modes = (meta.permissions().mode() & 0o7777, dir_mode & 0o7777);

    let mut stream = UnixStream::connect(uds).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(RESET_LIMIT))
        .map_err(|e| e.to_string())?;
    let asked = Instant::now();
    stream
        .write_all(b"CONNECT 1024\n")
        .map_err(|e| format!("write: {e}"))?;
    let mut answer = Vec::new();
    match stream.read_to_end(&mut answer) {
        Ok(_) => Ok(Probe {
            modes,
            answer,
            open_for: asked.elapsed(),
        }),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Err(format!(
            "the host connection was still open after {RESET_LIMIT:?}, having read {answer:?}"
        )),
        Err(e) => Err(format!("read: {e}")),
    }
}

#[test]
fn the_guest_probes_the_vsock_device_and_resets_a_host_connect_to_a_closed_port() {
    let Some((kernel, initramfs, rootfs)) = guest_or_skip() else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");
    // The state directory, which the VMM makes: as `boxcar run` passes it.
    let uds = dir.path().join("state").join("vsock.sock");

    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let argv = SESSION.map(String::from);
    let cfg = VmConfig {
        cmdline_extra: vec![
            "boxcar.mode=console".into(),
            format!("boxcar.uid={uid}"),
            format!("boxcar.gid={gid}"),
            format!("boxcar.cmd={}", guestcmd::encode(&argv)),
        ],
        console: ConsoleOut::File(console.clone()),
        stdin: false,
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        vsock: Some(VsockConfig::new(&uds)),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    assert!(
        vmm.handle().status().devices.iter().any(|d| d == "vsock"),
        "{:?}",
        vmm.handle().status().devices
    );

    // The probe stops the VM when it is done; a watchdog stops one that
    // hangs.
    let handle = vmm.handle();
    let (probe_console, probe_uds) = (console.clone(), uds.clone());
    let prober = thread::spawn(move || {
        let probe = probe(&probe_console, &probe_uds);
        handle.request_stop(StopReason::Requested);
        probe
    });
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(BOOT_LIMIT * 2).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    let probe = prober.join().unwrap();
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}, {probe:?}\n{output}");
    assert!(
        matches!(exit, VmExit::StopRequested(StopReason::Requested)),
        "{exit:?}; console:\n{output}"
    );
    assert!(output.contains(DRIVER), "no {DRIVER} driver:\n{output}");
    // The glob matched a device: the transport is bound to one.
    let bound = format!("BOUND /sys/bus/virtio/drivers/{DRIVER}/virtio");
    assert!(
        output
            .lines()
            .any(|line| line.contains(&bound) && !line.contains('*')),
        "the vsock transport bound no device:\n{output}"
    );
    assert!(output.contains("DONE"), "no DONE:\n{output}");

    let probe = probe.unwrap_or_else(|why| panic!("{why}; console:\n{output}"));
    assert_eq!(probe.modes, (0o600, 0o700), "{probe:?}");
    assert!(
        !String::from_utf8_lossy(&probe.answer).contains("OK"),
        "{probe:?}"
    );
    assert!(probe.answer.is_empty(), "{probe:?}");
    assert!(probe.open_for < RESET_LIMIT, "{probe:?}");
    assert!(!uds.exists(), "the socket outlived the VM");

    let report = verify_session(&session_dir).unwrap();
    eprintln!("{TEST}: {report:?}");
    let records: Vec<Record> = LogReader::open(&session_dir)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .collect();
    let vsock: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind.starts_with("vsock."))
        .collect();
    assert!(vsock.is_empty(), "{vsock:?}");
}

/// A VM that fails to build after its vsock device was attached (here, at
/// the kernel command line, which is too long) leaves neither the socket nor
/// the state directory the device made for it.
#[test]
fn a_build_that_fails_after_the_vsock_device_leaves_nothing_behind() {
    let Some((kernel, initramfs, _rootfs)) = guest_or_skip() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let state = dir.path().join("state");
    let uds = state.join("vsock.sock");
    let cfg = VmConfig {
        cmdline_extra: vec!["x".repeat(4096)],
        console: ConsoleOut::File(dir.path().join("console.log")),
        stdin: false,
        initramfs: Some(initramfs),
        vsock: Some(VsockConfig::new(&uds)),
        ..VmConfig::new(kernel, sink)
    };
    match Vmm::new(cfg) {
        Ok(_) => panic!("a 4 KiB command line was accepted"),
        Err(VmmError::Arch(_)) => {}
        Err(error) => panic!("{error}"),
    }
    assert!(!uds.exists(), "the socket outlived the failed build");
    assert!(
        !state.exists(),
        "the state directory outlived the failed build"
    );
    writer.close().unwrap();
}
