// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`'s flags, run as a subprocess: what is required, what
//! conflicts, what is refused before a session starts, and where sessions
//! go by default. None of these boot a VM.

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

#[test]
fn a_command_conflicts_with_no_fs() {
    let output = boxcar(&["run", "--kernel", "vmlinux", "--no-fs", "--", "ls"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("cannot be used with"),
        "{}",
        stderr(&output)
    );
}

/// With `--no-vsock` the command travels on the kernel command line, which
/// takes 2048 bytes.
#[test]
fn a_command_line_too_long_is_refused_before_a_session_starts() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let audit = scratch.path().join("audit");
    let script = "echo x; ".repeat(300);
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        rootfs.to_str().unwrap(),
        "--audit-dir",
        audit.to_str().unwrap(),
        "--no-vsock",
        "--",
        "/bin/sh",
        "-c",
        &script,
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("error: command line too long ("), "{text}");
    assert!(text.contains(" bytes > 2048)"), "{text}");
    assert!(!audit.exists(), "no session was started");
}

/// With the vsock device the command travels in the control channel's
/// config: a command the kernel command line could not hold is fine, one
/// over the channel's 64 KiB is refused before a session starts.
#[test]
fn a_command_over_the_control_channels_limit_is_refused_before_a_session_starts() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let audit = scratch.path().join("audit");
    let script = "echo x; ".repeat(9000);
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        rootfs.to_str().unwrap(),
        "--audit-dir",
        audit.to_str().unwrap(),
        "--",
        "/bin/sh",
        "-c",
        &script,
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("error: the session's config: ")
            && text.contains("over the control channel's limit of 65536"),
        "{text}"
    );
    assert!(!audit.exists(), "no session was started");
}

/// `--console-log` and `--console-stdout` say different things.
#[test]
fn console_log_conflicts_with_console_stdout() {
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--no-fs",
        "--console-log",
        "/tmp/c.log",
        "--console-stdout",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("cannot be used with"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_audit_dir_inside_a_share_is_refused_before_anything_is_created() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let audit = rootfs.join("var/boxcar");
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        rootfs.to_str().unwrap(),
        "--audit-dir",
        audit.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let rootfs = rootfs.canonicalize().unwrap();
    assert!(
        stderr(&output).contains(&format!(
            "error: audit dir {} is inside share {}",
            rootfs.join("var/boxcar").display(),
            rootfs.display()
        )),
        "{}",
        stderr(&output)
    );
    assert!(!rootfs.join("var").exists(), "nothing was created");
}

/// `boxcar run` without `--audit-dir`, up to the point where it fails for
/// want of a kernel: where it put the session, from its `audit:` line.
fn default_session_dir(env: &[(&str, &Path)]) -> String {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_boxcar"));
    command
        .args(["run", "--kernel", "/nonexistent/vmlinux", "--rootfs"])
        .arg(&rootfs)
        .env_remove("XDG_DATA_HOME");
    for (var, value) in env {
        command.env(var, value);
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    stderr(&output)
        .lines()
        .find_map(|line| line.strip_prefix("audit: "))
        .unwrap_or_else(|| panic!("no audit line: {}", stderr(&output)))
        .to_owned()
}

#[test]
fn sessions_go_under_the_xdg_data_home_by_default() {
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().canonicalize().unwrap();
    let session = default_session_dir(&[("XDG_DATA_HOME", &data_dir)]);
    let sessions = data_dir.join("boxcar/sessions");
    assert!(
        Path::new(&session).starts_with(&sessions),
        "{session} is not under {}",
        sessions.display()
    );
}

#[test]
fn without_xdg_data_home_sessions_go_under_the_home_directory() {
    let home = tempfile::tempdir().unwrap();
    let home_dir = home.path().canonicalize().unwrap();
    let session = default_session_dir(&[("HOME", &home_dir)]);
    let sessions = home_dir.join(".local/share/boxcar/sessions");
    assert!(
        Path::new(&session).starts_with(&sessions),
        "{session} is not under {}",
        sessions.display()
    );
}

#[test]
fn a_separator_with_no_command_is_refused() {
    let output = boxcar(&["run", "--kernel", "vmlinux", "--rootfs", "/tmp", "--"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("after `--`"),
        "{}",
        stderr(&output)
    );
}

/// An old session's workspace may be shared again: the run gets past the
/// audit dir check, and fails only for want of a kernel.
#[test]
fn an_old_session_workspace_can_be_shared_again() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    let audit = scratch.path().join("audit");
    let old = audit.join("sessions/01a0f42e-4fdf-74e9-95de-4e59c0ac45eb/workspace");
    std::fs::create_dir(&rootfs).unwrap();
    std::fs::create_dir_all(&old).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["run", "--kernel", "/nonexistent/vmlinux", "--rootfs"])
        .arg(&rootfs)
        .arg("--audit-dir")
        .arg(&audit)
        .arg("--workspace")
        .arg(&old)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let old = old.canonicalize().unwrap();
    assert!(
        stderr(&output).contains(&format!("workspace: {}", old.display())),
        "{}",
        stderr(&output)
    );
}

/// A session's directory holds its logs: sharing it is refused before a
/// session starts.
#[test]
fn a_session_dir_as_the_workspace_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    let audit = scratch.path().join("audit");
    let old = audit.join("sessions/01a0f42e-4fdf-74e9-95de-4e59c0ac45eb");
    std::fs::create_dir(&rootfs).unwrap();
    std::fs::create_dir_all(&old).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["run", "--kernel", "/nonexistent/vmlinux", "--rootfs"])
        .arg(&rootfs)
        .arg("--audit-dir")
        .arg(&audit)
        .arg("--workspace")
        .arg(&old)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let (old, audit) = (old.canonicalize().unwrap(), audit.canonicalize().unwrap());
    assert!(
        stderr(&output).contains(&format!(
            "error: share {} would expose audit logs under {}",
            old.display(),
            audit.display()
        )),
        "{}",
        stderr(&output)
    );
    let sessions = std::fs::read_dir(audit.join("sessions")).unwrap().count();
    assert_eq!(sessions, 1, "no session was started");
}

/// A policy rule that does not parse exits 2, as a usage error does, naming
/// the flag and its value, before a session starts.
#[test]
fn a_bad_allow_rule_exits_2_before_a_session_starts() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let audit = scratch.path().join("audit");
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        rootfs.to_str().unwrap(),
        "--audit-dir",
        audit.to_str().unwrap(),
        "--allow",
        "example.com",
        "--allow",
        "example.com:99999",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "error: --allow \"example.com:99999\": \"99999\" is not a port from 1 to 65535"
        ),
        "{}",
        stderr(&output)
    );
    assert!(!audit.exists(), "no session was started");
}

/// The same for a line of `--policy-file`: the file and the line.
#[test]
fn a_bad_policy_file_line_exits_2_naming_the_file_and_line() {
    let scratch = tempfile::tempdir().unwrap();
    let rootfs = scratch.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let audit = scratch.path().join("audit");
    let policy = scratch.path().join("team.policy");
    std::fs::write(
        &policy,
        "# rules\nallow example.com\nallow 10.0.0.0/8 extra\n",
    )
    .unwrap();
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--rootfs",
        rootfs.to_str().unwrap(),
        "--audit-dir",
        audit.to_str().unwrap(),
        "--policy-file",
        policy.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(&format!(
            "error: --policy-file {} line 3: allow takes one target",
            policy.display()
        )),
        "{}",
        stderr(&output)
    );
    assert!(!audit.exists(), "no session was started");
}

/// Without shares the VM has no network unless `--net` asks for one: the
/// policy and DNS flags are then refused as a usage error, not ignored.
#[test]
fn network_policy_flags_without_a_network_exit_2() {
    let scratch = tempfile::tempdir().unwrap();
    let audit = scratch.path().join("audit");
    let policy = scratch.path().join("team.policy");
    std::fs::write(&policy, "allow example.com\n").unwrap();
    for flag in [
        ["--allow", "example.com"],
        ["--deny", "example.com"],
        ["--policy-file", policy.to_str().unwrap()],
        ["--dns", "9.9.9.9"],
    ] {
        let output = boxcar(&[
            "run",
            "--kernel",
            "/nonexistent/vmlinux",
            "--no-fs",
            "--audit-dir",
            audit.to_str().unwrap(),
            flag[0],
            flag[1],
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{flag:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("error: network policy flags need --net"),
            "{flag:?}: {}",
            stderr(&output)
        );
        assert!(!audit.exists(), "{flag:?}: no session was started");
    }

    // With --net they are the network's: the run gets past them and fails
    // only for want of a kernel.
    let output = boxcar(&[
        "run",
        "--kernel",
        "/nonexistent/vmlinux",
        "--no-fs",
        "--net",
        "--audit-dir",
        audit.to_str().unwrap(),
        "--allow",
        "example.com",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("need --net"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("/nonexistent/vmlinux"),
        "{}",
        stderr(&output)
    );
}

/// Without shares the VM has no vsock device unless `--vsock` asks for
/// one: `--vsock-allow` is then refused as a usage error, not ignored.
#[test]
fn vsock_allow_without_a_vsock_device_exits_2() {
    let scratch = tempfile::tempdir().unwrap();
    let audit = scratch.path().join("audit");
    let output = boxcar(&[
        "run",
        "--kernel",
        "/nonexistent/vmlinux",
        "--no-fs",
        "--audit-dir",
        audit.to_str().unwrap(),
        "--vsock-allow",
        "5000",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("error: --vsock-allow needs --vsock"),
        "{}",
        stderr(&output)
    );
    assert!(!audit.exists(), "no session was started");
}

/// An internal port cannot be allowlisted: it is the VMM's.
#[test]
fn vsock_allow_refuses_an_internal_port() {
    let output = boxcar(&[
        "run",
        "--kernel",
        "vmlinux",
        "--no-fs",
        "--vsock",
        "--vsock-allow",
        "1025",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("internal"), "{}", stderr(&output));
}
