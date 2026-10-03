// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The M1 session boot: the console init with the `root` share (the guest
//! rootfs) and a fresh `workspace` share runs a `boxcar.cmd` that writes
//! `/workspace/a.txt` as the invoking user and prints its own ignored and
//! blocked signals and capability bounding set. The VM must end in
//! `GuestReset` with `boxcar: session exited 0` on the console, the session
//! must ignore and block no signal and have an empty bounding set, the file
//! must be on the host, and the session log must verify and hold the file's
//! `fs.close` with its size, its blake3 and a guest pid.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{env, fs};

use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::{guestcmd, Record, SessionId};
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::vmm::{ConsoleOut, StopReason, VmConfig, VmExit, Vmm};

const TEST: &str = "boot_console";
const LIMIT: Duration = Duration::from_secs(30);

/// What the session runs: the write the audit must see, then the lines of
/// `/proc/self/status` [`status_field`] reads back from the console.
///
/// `grep` must not be the last command: busybox ash ignores SIGQUIT itself
/// and execs a last command without forking, which then inherits that.
/// Nothing waits for the console after it: the terminal belongs to init,
/// so the shell's exit does not hang it up and discard what the serial
/// port has not sent yet.
const SESSION: &str = "echo hi > /workspace/a.txt; \
     grep -E '^(SigIgn|SigBlk|CapBnd):' /proc/self/status; true";

/// The value of `field` in the `/proc/<pid>/status` lines on the console
/// (`SigIgn:\t0000000000001000`), if one is there.
fn status_field<'a>(console: &'a str, field: &str) -> Option<&'a str> {
    console.lines().find_map(|line| {
        let value = line.trim_end_matches('\r').strip_prefix(field)?;
        Some(value.strip_prefix(':')?.trim())
    })
}

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

#[test]
fn a_session_command_writes_a_file_the_audit_hashes() {
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

    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let argv = ["/bin/sh", "-c", SESSION].map(String::from);
    let cfg = VmConfig {
        cmdline_extra: vec![
            "boxcar.mode=console".into(),
            format!("boxcar.uid={uid}"),
            format!("boxcar.gid={gid}"),
            format!("boxcar.cmd={}", guestcmd::encode(&argv)),
        ],
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share(
                "workspace",
                workspace.clone(),
                "/workspace",
                CachePolicyKind::Auto,
            ),
        ],
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
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}");
    // The guest's tty ends lines with CRLF: match substrings.
    assert!(
        output.contains("boxcar: session exited 0"),
        "no exit line on the console:\n{output}"
    );
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?}; console:\n{output}"
    );
    // Rust sets SIGPIPE to SIG_IGN in init, and an ignored signal or a
    // blocked mask survives execve: the session must start with neither.
    // Nor may it keep a capability it could regain.
    for field in ["SigIgn", "SigBlk", "CapBnd"] {
        eprintln!("{TEST}: {field}: {:?}", status_field(&output, field));
        assert_eq!(
            status_field(&output, field),
            Some("0000000000000000"),
            "{field}; console:\n{output}"
        );
    }
    assert_eq!(fs::read(workspace.join("a.txt")).unwrap(), b"hi\n");

    let report = verify_session(&session_dir).unwrap();
    eprintln!("{TEST}: {report:?}");
    let closes: Vec<Record> = LogReader::open(&session_dir)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .filter(|record| record.kind == "fs.close" && record.data["path"] == "/a.txt")
        .collect();
    assert_eq!(closes.len(), 1, "{closes:?}");
    let close = &closes[0];
    assert_eq!(close.data["mount"], "workspace", "{close:?}");
    assert_eq!(close.data["bytes_written"].as_u64(), Some(3), "{close:?}");
    assert_eq!(
        close.data["blake3"],
        format!("b3:{}", blake3::hash(b"hi\n").to_hex()),
        "{close:?}"
    );
    let subject = close.subject.as_ref().expect("the close has a subject");
    assert!(subject.pid > 1, "{subject:?}");
    assert_eq!((subject.uid, subject.gid), (uid, gid), "{subject:?}");
}
