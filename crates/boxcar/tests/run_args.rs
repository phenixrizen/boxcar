// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`'s filesystem flags, run as a subprocess: what is required,
//! what conflicts, and what is refused before a session starts. None of
//! these boot a VM.

use std::path::Path;
use std::process::{Command, Output};

fn boxcar(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn rootfs_is_required_unless_no_fs() {
    let output = boxcar(&["run", "--kernel", "vmlinux"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("--rootfs"), "{}", stderr(&output));
}

#[test]
fn no_fs_conflicts_with_the_share_flags() {
    for flag in ["--rootfs", "--workspace"] {
        let output = boxcar(&["run", "--kernel", "vmlinux", "--no-fs", flag, "/tmp"]);
        assert_eq!(output.status.code(), Some(2), "{flag}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("cannot be used with"),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn audit_level_takes_normal_or_verbose() {
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--no-fs",
        "--audit-level",
        "loud",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("normal") && text.contains("verbose"),
        "{text}"
    );
}

#[test]
fn a_missing_rootfs_is_refused_before_a_session_starts() {
    let scratch = tempfile::tempdir().unwrap();
    let audit = scratch.path().join("audit");
    let missing = scratch.path().join("no-such-rootfs");
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        missing.to_str().unwrap(),
        "--audit-dir",
        audit.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no-such-rootfs"),
        "{}",
        stderr(&output)
    );
    assert!(!Path::new(&audit).exists(), "no session was started");
}

#[test]
fn a_rootfs_that_is_a_file_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("rootfs");
    std::fs::write(&file, b"").unwrap();
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        file.to_str().unwrap(),
        "--audit-dir",
        scratch.path().join("audit").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not a directory"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_share_whose_path_is_not_utf8_is_refused_before_a_session_starts() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let scratch = tempfile::tempdir().unwrap();
    let dir = scratch
        .path()
        .join(OsString::from_vec(b"root\xff".to_vec()));
    std::fs::create_dir(&dir).unwrap();
    let audit = scratch.path().join("audit");
    let output = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["run", "--kernel", "vmlinux", "--rootfs"])
        .arg(&dir)
        .arg("--audit-dir")
        .arg(&audit)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not valid UTF-8"),
        "{}",
        stderr(&output)
    );
    assert!(!audit.exists(), "no session was started");
}
