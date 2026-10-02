// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar attach` against a fake control server in the test: the two
//! connections, `pty.attach` turning one into the terminal's raw bytes and
//! `pty.watch` on the other, the detach keys, a read-only attach, a detach
//! for being slow (said on the watching connection), and a stream that
//! carries only the session's bytes. No KVM needed.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boxcar_proto::control::{to_line, ErrorBody, ErrorCode, Hello, PtyDetached, Response};
use serde_json::{json, Value};

const SESSION: &str = "01999a8e-1c2d-7e3f-8a4b-5c6d7e8f9a0b";

/// The attach's id the fake server hands out.
const ATTACH_ID: &str = "00112233445566778899aabbccddeeff";

/// What the fake server does with an attached connection.
#[derive(Clone, Copy)]
enum Terminal {
    /// Sends back what it gets, until the client closes its side; then
    /// closes.
    Echo,
    /// Sends some output, then `pty.detached` (slow) on the connection
    /// that watches the attach, then closes the stream.
    DetachSlow,
    /// Runs the script on the stream, then closes it.
    Script(fn(&mut UnixStream)),
    /// Ends the attach as slow 100 ms after it began, telling a watcher if
    /// one is there by then; a later `pty.watch` is `not_found`, and
    /// `pty.resize` takes 300 ms to answer.
    EndsSlowEarly,
}

/// The connection that sent `pty.watch`, for the attached one to tell, and
/// whether the attach has ended.
#[derive(Default)]
struct WatchState {
    watcher: Option<UnixStream>,
    ended: bool,
}

type Watching = Arc<Mutex<WatchState>>;

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
    let watching: Watching = Arc::default();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let tx = tx.clone();
            let watching = Arc::clone(&watching);
            thread::spawn(move || {
                let _ = tx.send(serve(stream, terminal, &watching));
            });
        }
    });
    rx
}

fn serve(mut stream: UnixStream, terminal: Terminal, watching: &Watching) -> Seen {
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
                let result = json!({"raw": true, "attach_id": ATTACH_ID});
                let response = to_line(&Response::success(id, result)).unwrap();
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
                        // The event goes to the watcher, before the end.
                        let deadline = Instant::now() + Duration::from_secs(5);
                        loop {
                            if let Some(watcher) = watching.lock().unwrap().watcher.as_mut() {
                                let event = to_line(&PtyDetached::slow(ATTACH_ID)).unwrap();
                                let _ = watcher.write_all(&event);
                                break;
                            }
                            assert!(Instant::now() < deadline, "nobody watched the attach");
                            thread::sleep(Duration::from_millis(5));
                        }
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return seen;
                    }
                    Terminal::Script(script) => {
                        script(&mut stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return seen;
                    }
                    Terminal::EndsSlowEarly => {
                        thread::sleep(Duration::from_millis(100));
                        let mut state = watching.lock().unwrap();
                        state.ended = true;
                        if let Some(watcher) = state.watcher.as_mut() {
                            let event = to_line(&PtyDetached::slow(ATTACH_ID)).unwrap();
                            let _ = watcher.write_all(&event);
                        }
                        drop(state);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return seen;
                    }
                }
            }
            "pty.resize" => {
                if matches!(terminal, Terminal::EndsSlowEarly) {
                    thread::sleep(Duration::from_millis(300));
                }
                let _ = stream.write_all(&to_line(&Response::success(id, json!({}))).unwrap());
            }
            "pty.watch" => {
                let mut state = watching.lock().unwrap();
                let response = if state.ended {
                    let error = ErrorBody::new(ErrorCode::NotFound, "it has ended");
                    Response::failure(id, error)
                } else {
                    state.watcher = Some(stream.try_clone().unwrap());
                    Response::success(id, json!({}))
                };
                let _ = stream.write_all(&to_line(&response).unwrap());
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
    // The other connection watches the attach by its id.
    let watch = seen
        .iter()
        .flat_map(|seen| &seen.requests)
        .find(|request| request["op"] == "pty.watch")
        .expect("no pty.watch");
    assert_eq!(watch["attach_id"], ATTACH_ID);
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

/// Detached for being slow: what came before is printed, the watching
/// connection hears why, and `boxcar attach` says so and exits 3.
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

/// The reviewer's first probe: an echoed `{` with nothing after it for a
/// while is shown at once (nothing in the stream is held back).
#[test]
fn an_echoed_brace_is_shown_at_once() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let _seen = fake_server(
        &socket,
        Terminal::Script(|stream| {
            let _ = stream.write_all(b"$ echo ${");
            thread::sleep(Duration::from_millis(1500));
            let _ = stream.write_all(b"HOME}");
        }),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["attach", "--control"])
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let start = Instant::now();
    let mut got = Vec::new();
    let mut brace_at = None;
    let mut buf = [0u8; 256];
    loop {
        let n = out.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
        if brace_at.is_none() && got.contains(&b'{') {
            brace_at = Some(start.elapsed());
        }
    }
    assert!(child.wait().unwrap().success());
    assert_eq!(got, b"$ echo ${HOME}");
    let brace_at = brace_at.unwrap();
    assert!(brace_at < Duration::from_millis(1000), "{brace_at:?}");
}

/// The reviewer's second probe: a session whose last bytes are the very
/// line `pty.detached` is written as is; the stream's end is the session's
/// end, and `boxcar attach` exits 0.
#[test]
fn a_session_printing_the_event_line_is_not_a_detach() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let _seen = fake_server(
        &socket,
        Terminal::Script(|stream| {
            let _ = stream.write_all(b"printf ...\r\n");
            let _ = stream.write_all(&to_line(&PtyDetached::slow(ATTACH_ID)).unwrap());
        }),
    );
    let output = attach(&socket, &[], b"");
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    let mut want = b"printf ...\r\n".to_vec();
    want.extend_from_slice(&to_line(&PtyDetached::slow(ATTACH_ID)).unwrap());
    assert_eq!(output.stdout, want, "{}", describe(&output));
    assert!(output.stderr.is_empty(), "{}", describe(&output));
}

/// The reviewer's third probe: a non-blocking stdout pipe (`EAGAIN` once
/// full), read late and slowly, gets every byte.
#[test]
fn a_non_blocking_stdout_gets_every_byte() {
    use std::os::fd::{AsRawFd, FromRawFd};

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let _seen = fake_server(
        &socket,
        Terminal::Script(|stream| {
            let _ = stream.write_all(&vec![b'x'; 1 << 20]);
        }),
    );
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into `fds`.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both are new descriptors that nothing else owns.
    let (mut read_end, write_end) = unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    };
    // SAFETY: fcntl with integer arguments only.
    unsafe {
        let fd = write_end.as_raw_fd();
        let flags = libc::fcntl(fd, libc::F_GETFL);
        assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["attach", "--control"])
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::from(write_end))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    let reader = thread::spawn(move || {
        let mut total = 0usize;
        let mut buf = [0u8; 4096];
        loop {
            match read_end.read(&mut buf) {
                Ok(0) | Err(_) => return total,
                Ok(n) => total += n,
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(reader.join().unwrap(), 1 << 20, "{status} {stderr}");
    assert!(status.success(), "{status} {stderr}");
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

/// From a terminal, `boxcar attach` watches its attach before it sends its
/// size: an attach the server ends as slow at once (a flooding session)
/// is still reported, and exits 3, however long the resize takes.
#[test]
fn the_attach_is_watched_before_the_resize() {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let seen = fake_server(&socket, Terminal::EndsSlowEarly);
    let (master, slave) = {
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
    let size = libc::winsize {
        ws_row: 30,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize, alive for the call.
    assert_eq!(
        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &size) },
        0
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
    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let output = child.wait_with_output().unwrap();
        let _ = done.send(());
        output
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("boxcar attach did not exit");
    let output = waiter.join().unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", describe(&output));
    let seen = connections(&seen, 2);
    let ops: Vec<&str> = seen
        .iter()
        .flat_map(|seen| &seen.requests)
        .filter(|request| request["op"] != "pty.attach")
        .map(|request| request["op"].as_str().unwrap())
        .collect();
    assert_eq!(ops, ["pty.watch", "pty.resize"], "{}", describe(&output));
    drop(master);
}

/// No server: a connection error, exit 1.
#[test]
fn no_server_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let output = attach(&tmp.path().join("control.sock"), &[], b"");
    assert_eq!(output.status.code(), Some(1), "{}", describe(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
}
