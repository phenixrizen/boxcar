// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Attaching to the session's terminal over the control socket: init in
//! vsock mode with the Alpine rootfs runs a login shell, and the test
//! process speaks the control protocol to the VM's socket (with
//! `boxcar_proto`'s types, as any client would), not through the CLI.
//!
//! What it proves:
//!
//! - the hello names the `pty` capability, and `pty.attach` turns the
//!   connection into the session's terminal: what the client types runs in
//!   the shell (`stty size` says 24 80, the size init opened it at), and
//!   what the shell prints comes back;
//! - `pty.resize` from another connection resizes it (`stty size` then
//!   says 40 120), and `exit` ends the session and the VM with code 0;
//! - a second, read-only attach sees the same bytes as the first from
//!   when it attached, and what it types never reaches the session (the
//!   hub counts it as discarded).
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_audit::WriterConfig;
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_proto::control::{to_line, Hello, Request, Response};
use boxcar_proto::SessionId;
use boxcar_vmm::guest_ctl::SessionConfig;
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::lifecycle::exit_code_for;
use boxcar_vmm::pty::out::{self, OutWait, Target};
use boxcar_vmm::pty::Mode;
use boxcar_vmm::vmm::{ConsoleOut, ControlConfig, StopReason, VmConfig, VmExit, Vmm, VmmHandle};
use boxcar_vsock::VsockConfig;
use serde_json::{json, Value};

const TEST: &str = "boot_attach";
/// Boot, the session, and the stop.
const LIMIT: Duration = Duration::from_secs(60);
/// How long the test waits for the shell to show something.
const SHOW: Duration = Duration::from_secs(20);

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

/// A control connection, past its hello.
struct Control {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    hello: Hello,
    next_id: u64,
}

impl Control {
    fn connect(path: &Path) -> Control {
        let stream = UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let hello: Hello = serde_json::from_str(&line).unwrap();
        Control {
            reader,
            writer: stream,
            hello,
            next_id: 1,
        }
    }

    /// Sends `op` with `params`, and returns the response, past any event.
    fn request(&mut self, op: &str, params: Value) -> Response {
        let id = self.next_id;
        self.next_id += 1;
        self.writer
            .write_all(&to_line(&Request::new(id, op, params)).unwrap())
            .unwrap();
        loop {
            let mut line = String::new();
            assert!(self.reader.read_line(&mut line).unwrap() > 0, "closed");
            let value: Value = serde_json::from_str(&line).unwrap();
            if value.get("event").is_some() {
                continue;
            }
            let response: Response = serde_json::from_value(value).unwrap();
            assert_eq!(response.id, id);
            return response;
        }
    }
}

/// A connection attached to the session's terminal, its output collected
/// by a thread until the stream ends.
struct Attached {
    to_session: UnixStream,
    got: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl Attached {
    /// Attaches over a new connection to `path`, trying again while init
    /// has not opened the terminal yet (`invalid_state`).
    fn new(path: &Path, mode: &str, replay: u64) -> Attached {
        let deadline = Instant::now() + LIMIT;
        loop {
            let mut control = Control::connect(path);
            assert!(
                control.hello.capabilities.iter().any(|c| c == "pty"),
                "{:?}",
                control.hello
            );
            let params = json!({"session": "main", "mode": mode, "replay_bytes": replay});
            let response = control.request("pty.attach", params);
            if response.ok {
                assert_eq!(response.result, Some(json!({"raw": true})));
                let got = Arc::new(Mutex::new(control.reader.buffer().to_vec()));
                let mut stream = control.reader.into_inner();
                stream.set_read_timeout(None).unwrap();
                let collected = Arc::clone(&got);
                let reader = thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => collected.lock().unwrap().extend_from_slice(&buf[..n]),
                        }
                    }
                });
                return Attached {
                    to_session: control.writer,
                    got,
                    reader: Some(reader),
                };
            }
            let error = response.error.unwrap();
            assert_eq!(error.code.as_str(), "invalid_state", "{error}");
            assert!(Instant::now() < deadline, "the terminal never opened");
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Types `bytes`; a stream that has ended (the VM stopped) takes
    /// nothing, which the assertions on the output then show.
    fn send(&self, bytes: &[u8]) {
        let _ = (&self.to_session).write_all(bytes);
    }

    fn got(&self) -> Vec<u8> {
        self.got.lock().unwrap().clone()
    }

    /// The output's lines, without their carriage returns.
    fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.got())
            .split('\n')
            .map(|line| line.trim_end_matches('\r').to_owned())
            .collect()
    }

    /// Waits up to [`SHOW`] for a line that is exactly `line`.
    fn shows(&self, line: &str) -> bool {
        self.shows_within(line, SHOW)
    }

    /// Waits up to `timeout` for a line that is exactly `line`.
    fn shows_within(&self, line: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.lines().iter().any(|l| l == line) {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for the stream's end; returns everything it had.
    fn until_end(mut self) -> Vec<u8> {
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
        self.got()
    }
}

/// What runs beside the VM gets.
struct Beside {
    handle: VmmHandle,
    /// The control socket.
    control: PathBuf,
}

/// One run's scratch directory and how it ended.
struct Run {
    dir: tempfile::TempDir,
    exit: VmExit,
}

impl Run {
    fn text(&self, name: &str) -> String {
        String::from_utf8_lossy(&fs::read(self.dir.path().join(name)).unwrap_or_default())
            .into_owned()
    }

    fn describe(&self) -> String {
        format!(
            "{:?}\nsession:\n{}\nconsole:\n{}",
            self.exit,
            self.text("session.out"),
            self.text("console.log")
        )
    }
}

/// Boots `argv` as the session in vsock mode, the console in
/// `console.log`, the control socket in `state/`, and a client of the hub
/// in this process writing the session's terminal to `session.out` (for
/// the failure messages); `during` runs beside the VM and returns what it
/// saw. A watchdog stops a VM that does not end within [`LIMIT`].
fn run<T: Send + 'static>(
    argv: &[&str],
    during: impl FnOnce(Beside) -> T + Send + 'static,
) -> Option<(Run, T)> {
    let (kernel, initramfs, rootfs) = guest_or_skip(TEST)?;
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let state = dir.path().join("state");
    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let argv: Vec<String> = argv.iter().map(|&a| a.to_owned()).collect();
    let cfg = VmConfig {
        cmdline_extra: vec!["boxcar.mode=vsock".into()],
        console: ConsoleOut::File(dir.path().join("console.log")),
        stdin: false,
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        vsock: Some(VsockConfig::new(state.join("vsock.sock"))),
        session: SessionConfig::for_user(argv, uid, gid),
        control: Some(ControlConfig {
            state_dir: state.clone(),
            session_id: SessionId::new(),
        }),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let hub = vmm.handle().pty().expect("the hub, with the vsock device");
    let (_, output, _) = hub.attach(Mode::Ro, 0);
    let out = File::create(dir.path().join("session.out")).unwrap();
    let writer_out = out::spawn(output, Target::file(out), None).unwrap();
    let control = vmm.control_path().unwrap().to_owned();

    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let beside = {
        let beside = Beside {
            handle: vmm.handle(),
            control,
        };
        thread::spawn(move || during(beside))
    };
    let exit = vmm.run().unwrap();
    assert_eq!(writer_out.wait(Duration::from_secs(2)), OutWait::Done);
    drop(done);
    watchdog.join().unwrap();
    let saw = beside.join().unwrap();
    writer.close().unwrap();
    let run = Run { dir, exit };
    eprintln!("{TEST}: {}", run.describe());
    Some((run, saw))
}

/// What the read-write test saw.
#[derive(Debug, Default)]
struct Typed {
    size_at_start: bool,
    attached: bool,
    resized: Option<Response>,
    size_after: bool,
    output: Vec<u8>,
}

/// A client attaches read-write, runs `stty size` and `echo` in the login
/// shell, resizes the terminal from a second connection, sees the new size,
/// and ends the session with `exit`: the VM exits 0.
#[test]
fn an_attached_client_types_into_the_session_and_resizes_it() {
    let Some((run, saw)) = run(&["/bin/sh", "-l"], |beside| {
        let mut saw = Typed::default();
        let attached = Attached::new(&beside.control, "rw", 0);
        attached.send(b"stty size; echo ATTACHED\n");
        saw.size_at_start = attached.shows("24 80");
        saw.attached = attached.shows("ATTACHED");
        let mut control = Control::connect(&beside.control);
        saw.resized = Some(control.request(
            "pty.resize",
            json!({"session": "main", "rows": 40, "cols": 120}),
        ));
        // The size goes over the control channel, the command over the
        // terminal: ask again until the shell sees the new size.
        for _ in 0..5 {
            attached.send(b"stty size\n");
            if attached.shows_within("40 120", Duration::from_secs(2)) {
                saw.size_after = true;
                break;
            }
        }
        attached.send(b"exit\n");
        saw.output = attached.until_end();
        if !(saw.size_at_start && saw.attached && saw.size_after) {
            beside.handle.request_stop(StopReason::Requested);
        }
        saw
    }) else {
        return;
    };
    let output = String::from_utf8_lossy(&saw.output);
    assert!(
        saw.size_at_start,
        "no `24 80`:\n{output}\n{}",
        run.describe()
    );
    assert!(saw.attached, "no `ATTACHED`:\n{output}\n{}", run.describe());
    let resized = saw.resized.as_ref().unwrap();
    assert!(resized.ok, "{resized:?}");
    assert_eq!(resized.result, Some(json!({})));
    assert!(saw.size_after, "no `40 120`:\n{output}\n{}", run.describe());
    assert!(
        matches!(
            run.exit,
            VmExit::GuestReset {
                session: Some(boxcar_vmm::vmm::SessionOutcome { code: Some(0), .. })
            }
        ),
        "{}",
        run.describe()
    );
    assert_eq!(exit_code_for(&run.exit), 0);
}

/// What the two-client test saw.
#[derive(Debug, Default)]
struct Two {
    rw: Vec<u8>,
    ro: Vec<u8>,
    discarded: u64,
}

/// A second client attaches read-only: it sees the same bytes as the
/// read-write one from when it attached, and what it types is discarded.
#[test]
fn a_second_read_only_attach_sees_the_same_bytes_and_cannot_type() {
    let Some((run, saw)) = run(&["/bin/sh", "-l"], |beside| {
        let rw = Attached::new(&beside.control, "rw", 0);
        let ro = Attached::new(&beside.control, "ro", 0);
        ro.send(b"echo FROM_RO\n");
        let hub = beside.handle.pty().unwrap();
        let deadline = Instant::now() + SHOW;
        while hub.ro_discarded() < 13 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        // Time for anything the read-only client typed to show, were it
        // typed.
        thread::sleep(Duration::from_millis(500));
        rw.send(b"echo FROM_RW; exit\n");
        Two {
            rw: rw.until_end(),
            ro: ro.until_end(),
            discarded: hub.ro_discarded(),
        }
    }) else {
        return;
    };
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let lines = |bytes: &[u8]| -> Vec<String> {
        text(bytes)
            .split('\n')
            .map(|line| line.trim_end_matches('\r').to_owned())
            .collect()
    };
    for (name, got) in [("rw", &saw.rw), ("ro", &saw.ro)] {
        assert!(
            lines(got).iter().any(|line| line == "FROM_RW"),
            "{name}: no FROM_RW:\n{}\n{}",
            text(got),
            run.describe()
        );
        assert!(
            !text(got).contains("FROM_RO"),
            "{name}: the read-only input reached the session:\n{}",
            text(got)
        );
    }
    assert!(
        saw.rw.ends_with(&saw.ro),
        "the read-only client's bytes are not the read-write one's last:\nrw:\n{}\nro:\n{}",
        text(&saw.rw),
        text(&saw.ro)
    );
    assert_eq!(saw.discarded, 13);
    assert_eq!(exit_code_for(&run.exit), 0, "{}", run.describe());
}
