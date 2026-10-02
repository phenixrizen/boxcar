// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar attach` against a fake control server in the test: the two
//! connections, `pty.attach` turning one into the terminal's raw bytes,
//! the detach keys, a read-only attach and a detach for being slow. No KVM
//! needed.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boxcar_proto::control::{to_line, Hello, PtyDetached, Response};
use serde_json::{json, Value};

const SESSION: &str = "01999a8e-1c2d-7e3f-8a4b-5c6d7e8f9a0b";

/// What the fake server does with an attached connection.
#[derive(Clone, Copy)]
enum Terminal {
    /// Sends back what it gets, until the client closes its side; then
    /// closes.
    Echo,
    /// Sends some output, then `pty.detached` (slow), then closes.
    DetachSlow,
}

/// What the fake server saw.
#[derive(Debug, Default)]
struct Seen {
    /// Every request, from every connection.
    requests: Vec<Value>,
    /// The raw bytes the attached connection got.
    typed: Vec<u8>,
}

/// A fake control server at `path`: each connection gets the hello, then
/// `pty.attach` is answered `{"raw":true}` and the connection becomes the
/// `terminal`, and `pty.resize` is answered `{}`. Reports what it saw on
/// the channel as each connection ends.
fn fake_server(path: &Path, terminal: Terminal) -> mpsc::Receiver<Seen> {
    let listener = UnixListener::bind(path).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let tx = tx.clone();
            thread::spawn(move || {
                let _ = tx.send(serve(stream, terminal));
            });
        }
    });
    rx
}

fn serve(mut stream: UnixStream, terminal: Terminal) -> Seen {
    let mut seen = Seen::default();
    let hello = Hello::new("boxcar/fake", SESSION, vec!["pty".into()]);
    let _ = stream.write_all(&to_line(&hello).unwrap());
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return seen,
            Ok(_) => {}
        }
        let request: Value = serde_json::from_str(&line).unwrap();
        let id = request["id"].as_u64().unwrap();
        let op = request["op"].as_str().unwrap().to_owned();
        seen.requests.push(request);
        match op.as_str() {
            "pty.attach" => {
                let response = to_line(&Response::success(id, json!({"raw": true}))).unwrap();
                let _ = stream.write_all(&response);
                match terminal {
                    Terminal::Echo => {
                        let mut buf = [0u8; 4096];
                        loop {
                            match reader.read(&mut buf) {
                                Ok(0) | Err(_) => return seen,
                                Ok(n) => {
                                    seen.typed.extend_from_slice(&buf[..n]);
                                    let _ = stream.write_all(&buf[..n]);
                                }
                            }
                        }
                    }
                    Terminal::DetachSlow => {
                        let _ = stream.write_all(b"partial output");
                        let _ = stream.write_all(&to_line(&PtyDetached::slow()).unwrap());
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return seen;
                    }
                }
            }
            "pty.resize" => {
                let _ = stream.write_all(&to_line(&Response::success(id, json!({}))).unwrap());
            }
            other => panic!("unexpected op {other}"),
        }
    }
}

/// `boxcar attach ARGS --control SOCKET` with `stdin` piped in.
fn attach(socket: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .arg("attach")
        .args(args)
        .arg("--control")
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin).unwrap();
    drop(input);
    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let output = child.wait_with_output().unwrap();
        let _ = done.send(());
        output
    });
    finished
        .recv_timeout(Duration::from_secs(20))
        .expect("boxcar attach did not exit");
    waiter.join().unwrap()
}

fn describe(output: &Output) -> String {
    format!(
        "{}\nstdout:\n{:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The `pty.attach` request among what the server saw.
fn attach_request(seen: &[Seen]) -> &Value {
    seen.iter()
        .flat_map(|seen| &seen.requests)
        .find(|request| request["op"] == "pty.attach")
        .expect("no pty.attach")
}

/// Every connection the server saw, once each has ended.
fn connections(rx: &mpsc::Receiver<Seen>, count: usize) -> Vec<Seen> {
    (0..count)
        .map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap())
        .collect()
}

/// What is typed reaches the session and what the session sends comes
/// out; at the end of the input the client closes its side and keeps
/// reading, and the end of the stream ends `boxcar attach` with 0.
#[test]
fn attach_round_trips_bytes_against_a_fake_server() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let seen = fake_server(&socket, Terminal::Echo);
    let output = attach(&socket, &[], b"hello, session\n");
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    assert_eq!(output.stdout, b"hello, session\n", "{}", describe(&output));
    let seen = connections(&seen, 2);
    let request = attach_request(&seen);
    assert_eq!(request["session"], "main");
    assert_eq!(request["mode"], "rw");
    assert_eq!(request["replay_bytes"], 65536);
    let typed: Vec<u8> = seen.iter().flat_map(|seen| seen.typed.clone()).collect();
    assert_eq!(typed, b"hello, session\n");
}

/// Ctrl-P then Ctrl-Q detaches: `boxcar attach` exits 0, and neither key
/// nor anything after them is sent.
#[test]
fn the_detach_keys_end_the_attach_and_are_not_sent() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let seen = fake_server(&socket, Terminal::Echo);
    let output = attach(&socket, &[], b"ab\x10\x11cd");
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    let seen = connections(&seen, 2);
    let typed: Vec<u8> = seen.iter().flat_map(|seen| seen.typed.clone()).collect();
    assert_eq!(typed, b"ab", "{}", describe(&output));
}

/// A Ctrl-P that is not followed by Ctrl-Q is sent after all, with what
/// followed it.
#[test]
fn a_lone_ctrl_p_is_sent() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let seen = fake_server(&socket, Terminal::Echo);
    let output = attach(&socket, &[], b"a\x10b\x10");
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    let seen = connections(&seen, 2);
    let typed: Vec<u8> = seen.iter().flat_map(|seen| seen.typed.clone()).collect();
    assert_eq!(typed, b"a\x10b\x10", "{}", describe(&output));
}

/// `--ro` attaches read-only and sends nothing; `--replay` sets the
/// replay.
#[test]
fn a_read_only_attach_sends_no_input() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let seen = fake_server(&socket, Terminal::Echo);
    let output = attach(&socket, &["--ro", "--replay", "0"], b"typed");
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    assert_eq!(output.stdout, b"", "{}", describe(&output));
    let seen = connections(&seen, 2);
    let request = attach_request(&seen);
    assert_eq!(request["mode"], "ro");
    assert_eq!(request["replay_bytes"], 0);
    assert!(seen.iter().all(|seen| seen.typed.is_empty()));
}

/// Detached for being slow: what came before is printed, the event line
/// is not, and `boxcar attach` says so and exits 3.
#[test]
fn a_slow_detach_exits_3() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let _seen = fake_server(&socket, Terminal::DetachSlow);
    let output = attach(&socket, &[], b"");
    assert_eq!(output.status.code(), Some(3), "{}", describe(&output));
    assert_eq!(output.stdout, b"partial output", "{}", describe(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("detached"), "{stderr}");
}

/// A terminal's settings: input, output, control and local flags.
fn termios_flags(fd: i32) -> (u32, u32, u32, u32) {
    // SAFETY: termios is plain data; all zeroes is valid.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes one termios into `t`, alive for the call.
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut t) }, 0);
    (t.c_iflag, t.c_oflag, t.c_cflag, t.c_lflag)
}

/// From a real terminal: in raw mode the keys reach `boxcar attach`
/// (Ctrl-Q included, which a terminal with flow control on would take for
/// itself), the detach keys detach, and the terminal is left as it was.
#[test]
fn the_detach_keys_work_from_a_terminal_and_it_is_restored() {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let seen = fake_server(&socket, Terminal::Echo);
    let (mut master, slave) = {
        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty writes two new descriptors; the name, termios and
        // winsize arguments may be null.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: both are new descriptors that nothing else owns.
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    };
    let slave_fd = std::os::fd::AsRawFd::as_raw_fd(&slave);
    let before = termios_flags(slave_fd);
    assert_ne!(
        before.0 & libc::IXON,
        0,
        "the test needs a terminal with flow control on"
    );
    let child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .arg("attach")
        .arg("--control")
        .arg(&socket)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Once it is attached (its terminal in raw mode), type, then detach.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while termios_flags(slave_fd) == before {
        assert!(std::time::Instant::now() < deadline, "never in raw mode");
        thread::sleep(Duration::from_millis(10));
    }
    master.write_all(b"ab").unwrap();
    thread::sleep(Duration::from_millis(200));
    master.write_all(b"\x10\x11").unwrap();
    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let output = child.wait_with_output().unwrap();
        let _ = done.send(());
        output
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("Ctrl-P Ctrl-Q from a terminal did not detach");
    let output = waiter.join().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    assert_eq!(
        termios_flags(slave_fd),
        before,
        "the terminal was not restored"
    );
    let seen = connections(&seen, 2);
    let typed: Vec<u8> = seen.iter().flat_map(|seen| seen.typed.clone()).collect();
    assert_eq!(typed, b"ab", "{}", describe(&output));
}

/// No server: a connection error, exit 1.
#[test]
fn no_server_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let output = attach(&tmp.path().join("control.sock"), &[], b"");
    assert_eq!(output.status.code(), Some(1), "{}", describe(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
}
