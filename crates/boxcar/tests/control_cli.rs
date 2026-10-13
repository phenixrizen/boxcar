// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar status` and `boxcar stop` against a fake control server in the
//! test, how they find a session, and `boxcar run --ready-fd` refusing a
//! descriptor it cannot use. No KVM needed.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boxcar_proto::control::{
    to_line, AuditStatus, GuestStatus, Hello, Response, StateEvent, Status, VmState,
};
use serde_json::{json, Value};

const SESSION: &str = "01999a8e-1c2d-7e3f-8a4b-5c6d7e8f9a0b";

fn status() -> Status {
    Status {
        sensor: Default::default(),
        state: VmState::Running,
        session_id: SESSION.into(),
        pid: 4242,
        uptime_ms: 61_500,
        vcpus: 2,
        mem_mib: 512,
        guest: GuestStatus {
            init_ready: false,
            session_pid: None,
            exit: None,
        },
        audit: AuditStatus {
            next_seq: 17,
            failed: false,
        },
        devices: vec!["fs:root".into(), "fs:workspace".into()],
    }
}

/// Sends one line; the client may be gone, which is its business.
fn send(stream: &mut UnixStream, line: Vec<u8>) {
    let _ = stream.write_all(&line);
}

/// A fake control server at `path`. Each connection gets the hello; it
/// answers `status` with [`status`], and `stop` with `accepted`, then
/// `stopping` and `stopped`, and then stops serving. Every request it got
/// comes back from the handle.
fn fake_server(path: &Path) -> JoinHandle<Vec<Value>> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let mut requests = Vec::new();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            send(
                &mut stream,
                to_line(&Hello::new("boxcar/fake", SESSION, Vec::new())).unwrap(),
            );
            let reader = BufReader::new(stream.try_clone().unwrap());
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let request: Value = serde_json::from_str(&line).unwrap();
                let id = request["id"].as_u64().unwrap();
                requests.push(request.clone());
                match request["op"].as_str().unwrap() {
                    "status" => {
                        let result = serde_json::to_value(status()).unwrap();
                        send(
                            &mut stream,
                            to_line(&Response::success(id, result)).unwrap(),
                        );
                    }
                    "stop" => {
                        send(
                            &mut stream,
                            to_line(&Response::success(id, json!({"accepted": true}))).unwrap(),
                        );
                        send(
                            &mut stream,
                            to_line(&StateEvent::new(VmState::Stopping)).unwrap(),
                        );
                        send(
                            &mut stream,
                            to_line(&StateEvent::new(VmState::Stopped)).unwrap(),
                        );
                        return requests;
                    }
                    other => panic!("unexpected op {other}"),
                }
            }
        }
        requests
    })
}

/// `boxcar ARGS` with `XDG_RUNTIME_DIR` set to `runtime`.
fn boxcar(runtime: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(args)
        .env("XDG_RUNTIME_DIR", runtime)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn ok(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

/// A private runtime directory, as `boxcar run` would leave it: one
/// directory per session under `boxcar/`.
struct Runtime {
    dir: tempfile::TempDir,
}

impl Runtime {
    fn new() -> Runtime {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("boxcar");
        fs::create_dir(&sessions).unwrap();
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700)).unwrap();
        Runtime { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The control socket path of session `id`, its directory created.
    fn socket(&self, id: &str) -> PathBuf {
        let dir = self.dir.path().join("boxcar").join(id);
        fs::create_dir(&dir).unwrap();
        dir.join("control.sock")
    }
}

#[test]
fn status_and_stop_against_a_fake_server() {
    let runtime = Runtime::new();
    let socket = runtime.socket(SESSION);
    let server = fake_server(&socket);
    let control = socket.to_str().unwrap();

    let json = boxcar(runtime.path(), &["status", "--json", "--control", control]);
    ok(&json);
    let printed: Value = serde_json::from_str(stdout(&json).trim()).unwrap();
    assert_eq!(printed, serde_json::to_value(status()).unwrap());

    let table = boxcar(runtime.path(), &["status", "--control", control]);
    ok(&table);
    let text = stdout(&table);
    for expected in [
        SESSION,
        "running",
        "4242",
        "1m 1.5s",
        "fs:root, fs:workspace",
        "17",
    ] {
        assert!(text.contains(expected), "no {expected:?} in:\n{text}");
    }

    let stop = boxcar(
        runtime.path(),
        &[
            "stop",
            "--force",
            "--timeout-ms",
            "250",
            "--control",
            control,
        ],
    );
    ok(&stop);
    let requests = server.join().unwrap();
    let ops: Vec<&str> = requests.iter().map(|r| r["op"].as_str().unwrap()).collect();
    assert_eq!(ops, ["status", "status", "stop"]);
    let stop = requests.last().unwrap();
    assert_eq!(stop["mode"], "force");
    assert_eq!(stop["timeout_ms"], 250);
    assert_eq!(stop["v"], 1);
}

/// `boxcar stop` without `--force` asks for a graceful stop with the
/// default timeout, and finds the one running session on its own.
#[test]
fn a_lone_session_is_found_without_naming_it() {
    let runtime = Runtime::new();
    let server = fake_server(&runtime.socket(SESSION));
    // A session whose VMM is gone left its socket behind: not running.
    let stale = runtime.socket("01999a8e-0000-7000-8000-000000000000");
    drop(UnixListener::bind(&stale).unwrap());

    ok(&boxcar(runtime.path(), &["status"]));
    ok(&boxcar(runtime.path(), &["stop"]));
    let requests = server.join().unwrap();
    let stop = requests.last().unwrap();
    assert_eq!(stop["op"], "stop");
    assert_eq!(stop["mode"], "graceful");
    assert_eq!(stop.get("timeout_ms"), None);
}

#[test]
fn a_session_is_found_by_a_unique_prefix_of_its_id() {
    let runtime = Runtime::new();
    let server = fake_server(&runtime.socket(SESSION));
    let other = "01999b00-1c2d-7e3f-8a4b-5c6d7e8f9a0b";
    let _other_server = fake_server(&runtime.socket(other));

    // Two sessions run: one must be named, and the error names both.
    let two = boxcar(runtime.path(), &["status"]);
    assert_eq!(two.status.code(), Some(1), "{}", stderr(&two));
    assert!(
        stderr(&two).contains(&format!(
            "2 sessions are running ({SESSION}, {other}); pass --control or a session id"
        )),
        "{}",
        stderr(&two)
    );
    let ambiguous = boxcar(runtime.path(), &["status", "01999"]);
    assert_eq!(ambiguous.status.code(), Some(1));
    assert!(
        stderr(&ambiguous).contains("matches 2 sessions"),
        "{}",
        stderr(&ambiguous)
    );
    let unknown = boxcar(runtime.path(), &["status", "0123"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(
        stderr(&unknown).contains("no session 0123"),
        "{}",
        stderr(&unknown)
    );

    let found = boxcar(runtime.path(), &["status", "--json", "01999a"]);
    ok(&found);
    let printed: Value = serde_json::from_str(stdout(&found).trim()).unwrap();
    assert_eq!(printed["session_id"], SESSION);
    ok(&boxcar(runtime.path(), &["stop", SESSION]));
    assert_eq!(server.join().unwrap().len(), 2);
}

/// `--control` and a session id name the same thing: not both.
#[test]
fn control_and_a_session_id_conflict() {
    let runtime = Runtime::new();
    let output = boxcar(runtime.path(), &["status", "--control", "/x", SESSION]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// A server that answers `stop` with an error: `boxcar stop` says so and
/// exits 1.
#[test]
fn a_refused_stop_fails() {
    let runtime = Runtime::new();
    let socket = runtime.socket(SESSION);
    let listener = UnixListener::bind(&socket).unwrap();
    let (done, finished) = mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        send(
            &mut stream,
            to_line(&Hello::new("boxcar/fake", SESSION, Vec::new())).unwrap(),
        );
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let id = serde_json::from_str::<Value>(&line).unwrap()["id"]
            .as_u64()
            .unwrap();
        let error = boxcar_proto::control::ErrorBody::new(
            boxcar_proto::control::ErrorCode::InvalidState,
            "not now",
        );
        send(&mut stream, to_line(&Response::failure(id, error)).unwrap());
        let _ = finished.recv_timeout(Duration::from_secs(10));
    });
    let output = boxcar(
        runtime.path(),
        &["stop", "--control", socket.to_str().unwrap()],
    );
    drop(done);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("invalid_state: not now"),
        "{}",
        stderr(&output)
    );
}

/// `--ready-fd` must name an open descriptor boxcar can write, other than
/// its own stdin, stdout and stderr: anything else is refused before a
/// session starts.
#[test]
fn an_unusable_ready_fd_is_refused_before_a_session_starts() {
    let runtime = Runtime::new();
    let audit = runtime.path().join("audit");
    for (fd, why) in [
        ("99", "not open"),
        ("1", "boxcar's own stdout"),
        ("-3", "not open"),
    ] {
        let output = boxcar(
            runtime.path(),
            &[
                "run",
                "--kernel",
                "/nonexistent/vmlinux",
                "--no-fs",
                "--audit-dir",
                audit.to_str().unwrap(),
                &format!("--ready-fd={fd}"),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{fd}: {}", stderr(&output));
        assert!(
            stderr(&output).contains(&format!("--ready-fd {fd}: {why}")),
            "{fd}: {}",
            stderr(&output)
        );
        assert!(!audit.exists(), "{fd}: no session was started");
    }
}
