// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! SMP boots: with four vCPUs the guest kernel must bring up all of them
//! (`nproc` and the `processor` lines of `/proc/cpuinfo` both say 4), and
//! with two vCPUs both busy a stop requested from another thread must end
//! `Vmm::run` within a second. So must a stop while the application
//! processors have never been started: `maxcpus=1` keeps the guest from
//! sending them INIT and SIPI, so they sit in `KVM_RUN` in their reset
//! state until the kick reaches them.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};

use boxcar_audit::WriterConfig;
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::{guestcmd, SessionId};
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::vmm::{ConsoleOut, StopReason, VmConfig, VmExit, Vmm};

const TEST: &str = "boot_smp";
const LIMIT: Duration = Duration::from_secs(30);
/// How long the guest runs its session, once the session has said it is
/// running, before the stop is requested.
const SETTLE: Duration = Duration::from_secs(1);
/// How long `Vmm::run` may take to return after the stop is requested.
const STOP_WITHIN: Duration = Duration::from_secs(1);

/// The artifact `var` names, or `None` when it is unset.
fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The kernel, initramfs and rootfs, or `None` after printing why `test`
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

/// A console-mode VM of `vcpus` vCPUs over the Alpine rootfs and an empty
/// workspace in `dir` that runs the shell command `script` as its session,
/// with `extra` after the other kernel arguments and the console in
/// `dir/console.log`.
fn config(
    vcpus: u8,
    script: &str,
    extra: &[&str],
    dir: &Path,
    guest: (PathBuf, PathBuf, PathBuf),
    sink: boxcar_audit::AuditSink,
) -> VmConfig {
    let (kernel, initramfs, rootfs) = guest;
    let workspace = dir.join("workspace");
    fs::create_dir(&workspace).unwrap();
    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let argv = ["/bin/sh", "-c", script].map(String::from);
    VmConfig {
        vcpus,
        cmdline_extra: vec![
            "boxcar.mode=console".into(),
            format!("boxcar.uid={uid}"),
            format!("boxcar.gid={gid}"),
            format!("boxcar.cmd={}", guestcmd::encode(&argv)),
        ]
        .into_iter()
        .chain(extra.iter().map(|&arg| arg.to_owned()))
        .collect(),
        console: ConsoleOut::File(dir.join("console.log")),
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        ..VmConfig::new(kernel, sink)
    }
}

/// The console lines that are exactly `want`, ignoring the guest tty's CR.
fn lines_equal(console: &str, want: &str) -> usize {
    console
        .lines()
        .filter(|line| line.trim_end_matches('\r') == want)
        .count()
}

#[test]
fn four_vcpus_all_come_up_in_the_guest() {
    let Some(guest) = guest_or_skip(TEST) else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let console = dir.path().join("console.log");
    let script = "nproc; grep -c ^processor /proc/cpuinfo";
    let vmm = Vmm::new(config(4, script, &[], dir.path(), guest, sink)).unwrap();

    // A watchdog stops a guest that neither resets nor shuts down, which is
    // what a vCPU that never comes up would leave.
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
    // `nproc` and the `/proc/cpuinfo` count each print a line of just 4.
    assert_eq!(lines_equal(&output, "4"), 2, "console:\n{output}");
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?} after {elapsed:?}; console:\n{output}"
    );
}

/// Runs `vmm` on this thread while a helper thread waits for the guest's
/// session to print a line of just `marker` on the console `console`, lets it
/// run for [`SETTLE`], and asks the VM to stop; so the stop comes while the
/// session runs, however long the boot took. The helper gives up waiting
/// for the marker after [`LIMIT`] and stops the VM anyway. Returns how the VM
/// ended and how long `run` took to return from the request.
fn run_and_stop(vmm: Vmm, console: &Path, marker: &str) -> (VmExit, Duration) {
    let handle = vmm.handle();
    let (requested, requested_at) = mpsc::channel::<Instant>();
    let (console, marker) = (console.to_owned(), marker.to_owned());
    let stopper = thread::spawn(move || {
        let waiting = Instant::now();
        while waiting.elapsed() < LIMIT {
            let output = fs::read(&console).unwrap_or_default();
            if lines_equal(&String::from_utf8_lossy(&output), &marker) > 0 {
                thread::sleep(SETTLE);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let at = Instant::now();
        handle.request_stop(StopReason::Requested);
        requested.send(at).unwrap();
    });
    let exit = vmm.run().unwrap();
    let returned = Instant::now();
    stopper.join().unwrap();
    (exit, returned.duration_since(requested_at.recv().unwrap()))
}

/// Boots `vcpus` vCPUs running `script` with `extra` on the kernel command
/// line, stops them [`SETTLE`] after the session prints `marker`, and checks
/// that `run` returned within [`STOP_WITHIN`] of the request and that the
/// console holds `marker` once. Skips (and returns early) when the guest
/// artifacts or KVM are missing.
fn stop_within_a_second(vcpus: u8, script: &str, extra: &[&str], marker: &str) {
    let Some(guest) = guest_or_skip(TEST) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let console = dir.path().join("console.log");
    let vmm = Vmm::new(config(vcpus, script, extra, dir.path(), guest, sink)).unwrap();

    let (exit, took) = run_and_stop(vmm, &console, marker);
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}; run returned {took:?} after the stop request");
    assert_eq!(lines_equal(&output, marker), 1, "console:\n{output}");
    assert_eq!(
        exit,
        VmExit::StopRequested(StopReason::Requested),
        "console:\n{output}"
    );
    assert!(
        took < STOP_WITHIN,
        "run took {took:?} to return after the stop request; console:\n{output}"
    );
}

#[test]
fn a_stop_under_load_on_two_vcpus_returns_within_a_second() {
    // `echo busy` shows the shell got past starting the two loads.
    stop_within_a_second(
        2,
        "yes > /dev/null & yes > /dev/null & echo busy; sleep 30",
        &[],
        "busy",
    );
}

#[test]
fn a_stop_returns_within_a_second_while_the_other_vcpus_never_started() {
    // With `maxcpus=1` the guest runs on the first vCPU alone: `nproc`
    // says 1, and the other three have not seen INIT or SIPI when the stop
    // comes.
    stop_within_a_second(4, "nproc; sleep 30", &["maxcpus=1"], "1");
}
