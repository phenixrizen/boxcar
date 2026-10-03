// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar events` against a fake control server in the test: the request
//! it sends, the records and lag reports it prints, and how it ends (the
//! server closing, a closed stdout, a stop signal, a refusal). No KVM needed.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_proto::control::{
    to_line, AuditEvent, AuditLagged, ErrorBody, ErrorCode, Hello, Response, StateEvent, VmState,
};
use boxcar_proto::Record;
use serde_json::{json, Value};

const SESSION: &str = "01999a8e-1c2d-7e3f-8a4b-5c6d7e8f9a0b";

/// How long a test waits for the command to end.
const LIMIT: Duration = Duration::from_secs(20);

/// A record with seq `seq`, as the log would hold it.
fn record(seq: u64) -> Record {
    serde_json::from_value(json!({
        "v": 1,
        "session_id": SESSION,
        "seq": seq,
        "ring": 0,
        "src": "net",
        "type": "net.drop",
        "ts_host_ns": 1_000 + seq,
        "ts_mono_ns": 2_000 + seq,
        "subject": {"pid": 7, "uid": 1000, "gid": 1000},
        "data": {"reason": "ipv6", "count": seq},
        "prev": format!("b3:{}", "0".repeat(64)),
        "hash": format!("b3:{}", "1".repeat(64)),
    }))
    .unwrap()
}

/// The record's line as the server writes it: the struct's own key order,
/// which a `Value` would sort.
fn text(record: &Record) -> String {
    serde_json::to_string(record).unwrap()
}

/// A fake control server at `path`: it sends the hello, reads one request,
/// hands the connection and the request to `script`, and returns the
/// request. Signals on `got_request` once it has it.
fn fake_server(
    path: &Path,
    got_request: mpsc::Sender<()>,
    script: impl FnOnce(&mut UnixStream, &Value) + Send + 'static,
) -> JoinHandle<Value> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let hello = Hello::new("boxcar/fake", SESSION, vec!["audit".to_owned()]);
        stream.write_all(&to_line(&hello).unwrap()).unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        let _ = got_request.send(());
        script(&mut stream, &request);
        request
    })
}

fn respond(stream: &mut UnixStream, request: &Value, result: Value) {
    let id = request["id"].as_u64().unwrap();
    stream
        .write_all(&to_line(&Response::success(id, result)).unwrap())
        .unwrap();
}

fn events(control: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_boxcar"));
    command
        .arg("events")
        .args(args)
        .arg("--control")
        .arg(control);
    command
}

/// The command's end, waiting at most [`LIMIT`] for it.
fn wait(child: Child) -> Output {
    let (done, ended) = mpsc::channel();
    let pid = child.id();
    thread::spawn(move || {
        let _ = done.send(child.wait_with_output());
    });
    match ended.recv_timeout(LIMIT) {
        Ok(output) => output.unwrap(),
        Err(_) => {
            // SAFETY: kills the child this test started.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            panic!("`boxcar events` did not end in {LIMIT:?}");
        }
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn events_streams_from_a_fake_server() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let (got, _) = mpsc::channel();
    let sent = [record(5), record(6), record(7)];
    let server = fake_server(&socket, got, {
        let sent = sent.clone();
        move |stream, request| {
            respond(stream, request, json!({"next_seq": 6, "sub": 1}));
            let mut lines = Vec::new();
            lines.extend(to_line(&AuditEvent::new(1, &sent[0])).unwrap());
            lines.extend(to_line(&AuditLagged::new(1, 6)).unwrap());
            lines.extend(to_line(&AuditEvent::new(1, &sent[1])).unwrap());
            // Not a record, and not for this command.
            lines.extend(to_line(&StateEvent::new(VmState::Stopping)).unwrap());
            lines.extend(to_line(&AuditEvent::new(1, &sent[2])).unwrap());
            stream.write_all(&lines).unwrap();
            // The VM stops: the connection closes.
        }
    });

    let output = events(
        &socket,
        &[
            "--from", "5", "--type", "net.", "--type", "fs.write", "--pid", "7",
        ],
    )
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    // Each record as one line, exactly as the server sent it.
    let want: String = sent.iter().map(|r| text(r) + "\n").collect();
    assert_eq!(stdout(&output), want);
    // The lag report, on stderr, in the shape the command documents.
    assert_eq!(
        stderr(&output),
        "{\"event\":\"audit.lagged\",\"resume_seq\":6}\n"
    );
    // And the request is the one its arguments name.
    assert_eq!(
        server.join().unwrap(),
        json!({
            "v": 1, "id": 1, "op": "audit.subscribe",
            "from_seq": 5, "types": ["net.", "fs.write"], "pid": 7,
        })
    );
}

/// Without arguments it asks for everything from the start: no parameters
/// at all, which the server reads as `from_seq` 1.
#[test]
fn events_asks_for_everything_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let (got, _) = mpsc::channel();
    let server = fake_server(&socket, got, |stream, request| {
        respond(stream, request, json!({"next_seq": 1, "sub": 1}));
    });
    let output = events(&socket, &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        server.join().unwrap(),
        json!({"v": 1, "id": 1, "op": "audit.subscribe"})
    );
}

/// `boxcar events | head`: once stdout is closed the command ends quietly,
/// exit 0, with nothing on stderr, even though the server goes on sending.
#[test]
fn events_exits_quietly_on_epipe() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let (got, _) = mpsc::channel();
    let server = fake_server(&socket, got, |stream, request| {
        respond(stream, request, json!({"next_seq": 1, "sub": 1}));
        // For as long as the client reads, which it does until it ends.
        let started = Instant::now();
        let mut seq = 1;
        while started.elapsed() < LIMIT {
            let line = to_line(&AuditEvent::new(1, &record(seq))).unwrap();
            if stream.write_all(&line).is_err() {
                return;
            }
            seq += 1;
            thread::sleep(Duration::from_millis(2));
        }
        panic!("the client never closed the connection");
    });

    let mut child = events(&socket, &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // `head -n 1`: the first line, then the reader goes away.
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert_eq!(first, text(&record(1)) + "\n");
    let output = wait(child);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    // The command hung up, which ended the server's loop.
    server.join().unwrap();
}

/// Ctrl-C ends it cleanly while it waits for the next record; SIGTERM
/// ends it as a signal does, 128 plus its number.
#[test]
fn events_ends_on_a_stop_signal() {
    for (signal, code) in [(libc::SIGINT, 0), (libc::SIGTERM, 128 + libc::SIGTERM)] {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("control.sock");
        let (got, got_request) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let server = fake_server(&socket, got, move |stream, request| {
            respond(stream, request, json!({"next_seq": 1, "sub": 1}));
            stream
                .write_all(&to_line(&AuditEvent::new(1, &record(1))).unwrap())
                .unwrap();
            // Silent, with the connection open, until the command is gone.
            let _ = released.recv_timeout(LIMIT);
        });
        let mut child = events(&socket, &[])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        got_request.recv_timeout(LIMIT).unwrap();
        // It has printed the first record: it is waiting for the next.
        let mut first = String::new();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        stdout.read_line(&mut first).unwrap();
        assert_eq!(first, text(&record(1)) + "\n");
        // SAFETY: signals the child this test started.
        unsafe { libc::kill(child.id() as i32, signal) };
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).unwrap();
        let output = wait(child);
        assert_eq!(output.status.code(), Some(code), "signal {signal}");
        assert_eq!(rest, "");
        drop(release);
        server.join().unwrap();
    }
}

/// A refused subscription (a fifth on a connection, or a bad request) is
/// an error: exit 1, and the server's code and message on stderr.
#[test]
fn events_fails_when_the_server_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let (got, _) = mpsc::channel();
    let server = fake_server(&socket, got, |stream, request| {
        let id = request["id"].as_u64().unwrap();
        let error = ErrorBody::new(ErrorCode::Busy, "4 subscriptions already");
        stream
            .write_all(&to_line(&Response::failure(id, error)).unwrap())
            .unwrap();
    });
    let output = events(&socket, &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("audit.subscribe: busy: 4 subscriptions already"),
        "{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");
    server.join().unwrap();
}

/// A server that sends something that is not the protocol, or no server at
/// all, or arguments the server would refuse: exit 1 and a message.
#[test]
fn events_fails_on_connection_errors_and_bad_arguments() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nobody.sock");
    let output = events(&missing, &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("cannot connect"),
        "{}",
        stderr(&output)
    );

    let socket = tmp.path().join("control.sock");
    let (got, _) = mpsc::channel();
    let server = fake_server(&socket, got, |stream, request| {
        respond(stream, request, json!({"next_seq": 1, "sub": 1}));
        stream.write_all(b"this is not json\n").unwrap();
    });
    let output = events(&socket, &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not an object"),
        "{}",
        stderr(&output)
    );
    server.join().unwrap();

    // Refused before it connects: the same limits the server has.
    for bad in [&["--type", ""][..], &["--type", &"x".repeat(65)]] {
        let output = events(&missing, bad).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{bad:?}");
        assert!(stderr(&output).contains("events:"), "{}", stderr(&output));
    }
}
