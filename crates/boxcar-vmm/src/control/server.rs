// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The control socket's listener: [`ControlServer`].
//!
//! [`ControlServer::bind`] creates the state directory (mode 0700, every
//! level it creates) unless it exists, refuses one that is not a directory
//! of the VMM's user that only that user can enter, binds `control.sock`
//! in it, makes the socket 0600, and starts the accept thread. The modes
//! are set, not left to the umask, which is 0 once the shares are
//! imported; the socket only has the umask's mode until the `chmod`, inside
//! a directory nobody else can enter.
//!
//! The accept thread reads each peer's credentials (`SO_PEERCRED`). A peer
//! whose uid is not the VMM's is closed at once, before the hello, and
//! recorded as `control.connect{verdict:"deny"}`; any other is recorded as
//! `allow` and served on a thread of its own (see `conn`).
//!
//! [`ControlServer::shutdown`], which the VMM's stop sequence calls before
//! it records `vmm.stop`, stops accepting, unlinks the socket, sends every
//! connection `stopped` as far as its socket takes it without waiting,
//! shuts every socket down and joins every thread, then removes the state
//! directory if it is empty. Dropping the server does the same.

use std::fs::{self, DirBuilder};
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boxcar_audit::AuditSink;
use boxcar_proto::control::{Hello, VmState, SOCKET_NAME};
use boxcar_proto::{ControlConnect, Payload, Verdict};
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

use super::conn::{poll_two, record, Conn, Session};
use super::ops::{ConnCtx, Ops};
use super::peercred::peer_cred;
use crate::lifecycle::VmmHandle;

/// The mode of the state directory, and of every directory `bind` creates.
const DIR_MODE: u32 = 0o700;
/// The mode of the socket.
const SOCKET_MODE: u32 = 0o600;
/// How long the accept thread waits before it tries again when the process
/// is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// The control socket of one VM, and the threads that serve it.
pub struct ControlServer {
    path: PathBuf,
    state_dir: PathBuf,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

/// What the server shares with its accept thread.
struct Shared {
    closing: AtomicBool,
    /// Wakes the accept thread to see `closing`.
    wake: EventFd,
    conns: Mutex<Vec<Served>>,
}

impl Shared {
    fn conns(&self) -> MutexGuard<'_, Vec<Served>> {
        self.conns.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A connection and the thread that serves it.
struct Served {
    conn: Arc<Conn>,
    thread: JoinHandle<()>,
}

/// How the accept path is set up.
#[derive(Default)]
pub(crate) struct Options {
    /// Test hook: the peer uid the accept path sees in place of the one
    /// `SO_PEERCRED` reports, since a test cannot connect as another user.
    #[cfg(test)]
    pub(crate) peer_uid: Option<u32>,
}

impl Options {
    #[cfg(test)]
    fn peer_uid(&self, uid: u32) -> u32 {
        self.peer_uid.unwrap_or(uid)
    }

    #[cfg(not(test))]
    fn peer_uid(&self, uid: u32) -> u32 {
        uid
    }
}

/// What the accept thread hands each connection.
struct Accept {
    listener: UnixListener,
    shared: Arc<Shared>,
    ops: Arc<dyn Ops>,
    audit: AuditSink,
    hello: Hello,
    /// The VMM's uid: the only one served.
    uid: u32,
    options: Options,
}

impl ControlServer {
    /// Binds `<state_dir>/control.sock` for the VM of `handle`, served by
    /// `ops`, and starts accepting. Returns the server and the socket's
    /// path.
    pub fn bind(
        state_dir: &Path,
        handle: VmmHandle,
        ops: Arc<dyn Ops>,
    ) -> io::Result<(ControlServer, PathBuf)> {
        ControlServer::bind_with(state_dir, handle, ops, Options::default())
    }

    pub(crate) fn bind_with(
        state_dir: &Path,
        handle: VmmHandle,
        ops: Arc<dyn Ops>,
        options: Options,
    ) -> io::Result<(ControlServer, PathBuf)> {
        make_state_dir(state_dir)?;
        let path = state_dir.join(SOCKET_NAME);
        let listener = UnixListener::bind(&path)?;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))
            .and_then(|()| listener.set_nonblocking(true))
        {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        let shared = Arc::new(Shared {
            closing: AtomicBool::new(false),
            wake: EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)?,
            conns: Mutex::new(Vec::new()),
        });
        let server = format!("boxcar/{}", env!("CARGO_PKG_VERSION"));
        let accept = Accept {
            listener,
            shared: shared.clone(),
            hello: Hello::new(&server, handle.session_id(), ops.capabilities()),
            ops,
            audit: handle.audit().clone(),
            uid: current_uid(),
            options,
        };
        let thread = thread::Builder::new()
            .name("control-accept".into())
            .spawn(move || accept.run());
        let thread = match thread {
            Ok(thread) => thread,
            Err(error) => {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
        };
        let server = ControlServer {
            path: path.clone(),
            state_dir: state_dir.to_owned(),
            shared,
            accept: Some(thread),
        };
        tracing::debug!("control socket: {}", path.display());
        Ok((server, path))
    }

    /// The socket's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Tells every connection that the VM entered `state`, without waiting
    /// on any client. A connection hears each state once.
    pub fn notify_state(&self, state: VmState) {
        for served in self.shared.conns().iter() {
            served.conn.send_state(state);
        }
    }

    /// Closes the socket and every connection; see the module docs.
    pub fn shutdown(mut self) {
        self.close();
    }

    fn close(&mut self) {
        let Some(accept) = self.accept.take() else {
            return;
        };
        self.shared.closing.store(true, Ordering::Release);
        if let Err(error) = self.shared.wake.write(1) {
            tracing::warn!("control: cannot wake the accept thread: {error}");
        }
        if accept.join().is_err() {
            tracing::error!("control: the accept thread panicked");
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("cannot remove {}: {e}", self.path.display()),
        }
        let served = mem::take(&mut *self.shared.conns());
        for one in &served {
            one.conn.send_state(VmState::Stopped);
            one.conn.close();
        }
        for one in served {
            if one.thread.join().is_err() {
                tracing::error!("control: a connection thread panicked");
            }
        }
        // Only when empty: anything else in it is not the server's.
        let _ = fs::remove_dir(&self.state_dir);
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.close();
    }
}

impl Accept {
    fn run(self) {
        loop {
            if self.shared.closing.load(Ordering::Acquire) {
                return;
            }
            if let Err(error) = poll_two(
                self.listener.as_raw_fd(),
                libc::POLLIN,
                &self.shared.wake,
                None,
            ) {
                tracing::error!("control: poll failed: {error}; no longer accepting");
                return;
            }
            let _ = self.shared.wake.read();
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => self.admit(stream),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                        ) => {}
                    Err(e) => {
                        // Out of descriptors, most likely: the connection
                        // waits in the backlog until one is free.
                        tracing::warn!("control: accept failed: {e}");
                        thread::sleep(ACCEPT_BACKOFF);
                        break;
                    }
                }
            }
        }
    }

    /// Serves `stream` if its peer is the VMM's user; closes it at once
    /// otherwise. Either way the connection is recorded.
    fn admit(&self, stream: UnixStream) {
        let (pid, uid) = match peer_cred(&stream) {
            Ok((pid, uid, _gid)) => (pid, self.options.peer_uid(uid)),
            Err(error) => {
                tracing::warn!("control: cannot read a peer's credentials: {error}");
                return;
            }
        };
        if uid != self.uid {
            // Closed before anything is sent, then recorded.
            drop(stream);
            let verdict = Verdict::Deny;
            record(
                &self.audit,
                Payload::ControlConnect(ControlConnect { pid, uid, verdict }),
            );
            return;
        }
        let verdict = Verdict::Allow;
        record(
            &self.audit,
            Payload::ControlConnect(ControlConnect { pid, uid, verdict }),
        );
        // The hello is queued here, before the connection is in
        // `shared.conns` where `notify_state` and `close` reach it.
        let conn = match Conn::new(stream, &self.hello) {
            Ok(conn) => Arc::new(conn),
            Err(error) => {
                tracing::warn!("control: cannot set up a connection: {error}");
                return;
            }
        };
        let session = Session {
            conn: conn.clone(),
            ctx: ConnCtx {
                peer_pid: pid,
                peer_uid: uid,
                raw_upgrade: None,
            },
            ops: self.ops.clone(),
            audit: self.audit.clone(),
        };
        let thread = thread::Builder::new()
            .name("control-conn".into())
            .spawn(move || session.serve());
        let thread = match thread {
            Ok(thread) => thread,
            Err(error) => {
                tracing::warn!("control: cannot start a connection thread: {error}");
                return;
            }
        };
        let mut conns = self.shared.conns();
        let (done, live): (Vec<Served>, Vec<Served>) = mem::take(&mut *conns)
            .into_iter()
            .partition(|served| served.thread.is_finished());
        *conns = live;
        conns.push(Served { conn, thread });
        drop(conns);
        for served in done {
            let _ = served.thread.join();
        }
    }
}

/// Creates `dir` with mode 0700 unless it exists, then checks that it is
/// a directory (not a link to one) of this user that only this user can
/// enter.
fn make_state_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    let refuse = |why: String| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: {why}", dir.display()),
        ))
    };
    if !meta.is_dir() {
        return refuse("not a directory".into());
    }
    if meta.uid() != current_uid() {
        return refuse(format!("owned by uid {}, not this user", meta.uid()));
    }
    if meta.mode() & 0o077 != 0 {
        return refuse(format!(
            "mode {:o} lets other users in; it must be 0700",
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, Instant};

    use boxcar_audit::{LogReader, WriterHandle};
    use boxcar_proto::control::{
        AuditStatus, ErrorBody, GuestStatus, Request, Status, StopMode, StopParams, MAX_LINE,
    };
    use boxcar_proto::Record;
    use serde_json::{json, Value};

    use super::*;
    use crate::control::ops::{ConnCtx, RawUpgrade};

    /// Ops that answer from a fixed status and remember each stop.
    struct FakeOps {
        stops: Mutex<Vec<StopParams>>,
    }

    fn fake_status() -> Status {
        Status {
            state: VmState::Running,
            session_id: "fake".into(),
            pid: 7,
            uptime_ms: 1234,
            vcpus: 1,
            mem_mib: 512,
            guest: GuestStatus {
                init_ready: false,
                session_pid: None,
                exit: None,
            },
            audit: AuditStatus {
                next_seq: 3,
                failed: false,
            },
            devices: vec!["fs:root".into(), "fs:workspace".into()],
        }
    }

    impl Ops for FakeOps {
        fn status(&self) -> Status {
            fake_status()
        }

        fn stop(&self, params: StopParams) -> Result<Value, ErrorBody> {
            self.stops.lock().unwrap().push(params);
            Ok(json!({"accepted": true}))
        }

        /// `echo` answers with its parameters; `raw` turns the connection
        /// into a byte stream that echoes what it gets, once, upper-cased.
        fn dispatch(&self, conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody> {
            match req.op.as_str() {
                "echo" => Ok(req.params.clone()),
                "raw" => {
                    conn.raw_upgrade = Some(RawUpgrade::new(|mut stream, pending| {
                        let mut got = pending;
                        while got.len() < 3 {
                            let mut buf = [0u8; 16];
                            let n = stream.read(&mut buf).unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            got.extend_from_slice(&buf[..n]);
                        }
                        let _ = stream.write_all(&got.to_ascii_uppercase());
                    }));
                    Ok(json!({"raw": true}))
                }
                _ => Err(ErrorBody::unknown_op(&req.op)),
            }
        }
    }

    /// A server over [`FakeOps`] in a fresh state directory, with an audit
    /// log of its own.
    struct Fixture {
        _tmp: tempfile::TempDir,
        state_dir: PathBuf,
        path: PathBuf,
        server: Option<ControlServer>,
        ops: Arc<FakeOps>,
        handle: VmmHandle,
        writer: Option<WriterHandle>,
    }

    impl Fixture {
        fn new(options: Options) -> Fixture {
            let tmp = tempfile::tempdir().unwrap();
            let (handle, writer) = crate::lifecycle::test_handle(&tmp.path().join("audit"));
            let ops = Arc::new(FakeOps {
                stops: Mutex::new(Vec::new()),
            });
            let state_dir = tmp.path().join("run/boxcar/session");
            let (server, path) =
                ControlServer::bind_with(&state_dir, handle.clone(), ops.clone(), options).unwrap();
            assert_eq!(path, state_dir.join("control.sock"));
            Fixture {
                _tmp: tmp,
                state_dir,
                path,
                server: Some(server),
                ops,
                handle,
                writer: Some(writer),
            }
        }

        fn server(&self) -> &ControlServer {
            self.server.as_ref().unwrap()
        }

        /// The records of the audit log, once it is closed.
        fn records(&mut self) -> Vec<Record> {
            let writer = self.writer.take().unwrap();
            let dir = writer.session_dir().to_path_buf();
            writer.close().unwrap();
            LogReader::open(&dir)
                .unwrap()
                .records()
                .map(Result::unwrap)
                .collect()
        }

        fn control_records(&mut self) -> Vec<(String, Value)> {
            self.records()
                .into_iter()
                .filter(|r| r.kind.starts_with("control."))
                .map(|r| (r.kind, r.data))
                .collect()
        }
    }

    /// A client: one line at a time, with a timeout so a test cannot hang.
    struct Client {
        reader: BufReader<UnixStream>,
        writer: UnixStream,
    }

    impl Client {
        fn connect(path: &Path) -> Client {
            let stream = UnixStream::connect(path).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            Client {
                writer: stream.try_clone().unwrap(),
                reader: BufReader::new(stream),
            }
        }

        /// The next line, or `None` once the server closed the connection.
        fn line(&mut self) -> Option<Value> {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => None,
                Ok(_) => Some(serde_json::from_str(&line).unwrap()),
                // A server that closes with bytes it did not read resets
                // the connection: closed as well.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                Err(e) => panic!("reading from the control socket: {e}"),
            }
        }

        fn send(&mut self, bytes: &[u8]) {
            self.writer.write_all(bytes).unwrap();
        }

        fn send_json(&mut self, value: Value) {
            let mut line = serde_json::to_vec(&value).unwrap();
            line.push(b'\n');
            self.send(&line);
        }

        /// Sends `value` and returns the next line.
        fn request(&mut self, value: Value) -> Value {
            self.send_json(value);
            self.line().expect("a response")
        }

        /// Reads past the hello.
        fn hello(mut self) -> Client {
            let hello = self.line().expect("a hello");
            assert_eq!(hello["event"], "hello");
            self
        }
    }

    fn error_code(response: &Value) -> &str {
        assert_eq!(response["ok"], false, "{response}");
        response["error"]["code"].as_str().unwrap()
    }

    fn uid() -> u32 {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }
    }

    /// The hello comes first, unasked, even when the client sends a
    /// request before reading anything; the connection is recorded.
    #[test]
    fn hello_is_sent_first() {
        let mut fixture = Fixture::new(Options::default());
        let mut client = Client::connect(&fixture.path);
        client.send_json(json!({"v": 1, "id": 1, "op": "status"}));
        assert_eq!(
            client.line().unwrap(),
            json!({
                "v": 1,
                "event": "hello",
                "protocol": "boxcar.control",
                "versions": [1],
                "server": format!("boxcar/{}", env!("CARGO_PKG_VERSION")),
                "session_id": fixture.handle.session_id(),
                "capabilities": [],
            })
        );
        let response = client.line().unwrap();
        assert_eq!(
            (response["id"].as_u64(), &response["ok"]),
            (Some(1), &json!(true))
        );

        fixture.server.take().unwrap().shutdown();
        assert_eq!(
            fixture.control_records(),
            [(
                "control.connect".to_owned(),
                json!({"pid": std::process::id(), "uid": uid(), "verdict": "allow"})
            )]
        );
    }

    #[test]
    fn status_and_stop_dispatch() {
        let mut fixture = Fixture::new(Options::default());
        let mut client = Client::connect(&fixture.path).hello();
        let mut watcher = Client::connect(&fixture.path).hello();

        let status = client.request(json!({"v": 1, "id": 10, "op": "status"}));
        assert_eq!(
            status,
            json!({"v": 1, "id": 10, "ok": true, "result": serde_json::to_value(fake_status()).unwrap()})
        );

        let stop = client
            .request(json!({"v": 1, "id": 11, "op": "stop", "mode": "force", "timeout_ms": 100}));
        assert_eq!(
            stop,
            json!({"v": 1, "id": 11, "ok": true, "result": {"accepted": true}})
        );
        assert_eq!(
            client.line().unwrap(),
            json!({"v": 1, "event": "state", "state": "stopping"})
        );
        assert_eq!(
            *fixture.ops.stops.lock().unwrap(),
            [StopParams {
                mode: StopMode::Force,
                timeout_ms: Some(100)
            }]
        );
        // A stop with no parameters is graceful.
        let again = client.request(json!({"v": 1, "id": 12, "op": "stop"}));
        assert_eq!(again["result"], json!({"accepted": true}));
        assert_eq!(fixture.ops.stops.lock().unwrap()[1], StopParams::default());
        let bad = client.request(json!({"v": 1, "id": 13, "op": "stop", "mode": "soon"}));
        assert_eq!(
            (error_code(&bad), bad["id"].as_u64()),
            ("bad_request", Some(13))
        );

        // The VMM's stop sequence tells every client; the one that asked
        // heard `stopping` already and does not hear it twice.
        fixture.server().notify_state(VmState::Stopping);
        assert_eq!(watcher.line().unwrap()["state"], "stopping");
        fixture.server.take().unwrap().shutdown();
        for client in [&mut client, &mut watcher] {
            assert_eq!(
                client.line().unwrap(),
                json!({"v": 1, "event": "state", "state": "stopped"})
            );
            assert_eq!(client.line(), None);
        }
        assert!(!fixture.path.exists(), "the socket is unlinked");
        assert!(
            !fixture.state_dir.exists(),
            "the empty state dir is removed"
        );

        let pid = std::process::id();
        let records = fixture.control_records();
        let stops: Vec<&Value> = records
            .iter()
            .filter(|(kind, _)| kind == "control.stop")
            .map(|(_, data)| data)
            .collect();
        assert_eq!(
            stops,
            [
                &json!({"by_pid": pid, "mode": "force"}),
                &json!({"by_pid": pid, "mode": "graceful"})
            ]
        );
    }

    #[test]
    fn unknown_op_and_bad_json_produce_errors_without_closing() {
        let fixture = Fixture::new(Options::default());
        let mut client = Client::connect(&fixture.path).hello();

        let unknown = client.request(json!({"v": 1, "id": 5, "op": "nope"}));
        assert_eq!(
            (error_code(&unknown), unknown["id"].as_u64()),
            ("unknown_op", Some(5))
        );
        client.send(b"not json\n");
        assert_eq!(error_code(&client.line().unwrap()), "bad_request");
        client.send(b"{\"v\":1,\"id\":6,\"op\":\"st\xffatus\"}\n");
        assert_eq!(error_code(&client.line().unwrap()), "bad_request");
        let version = client.request(json!({"v": 2, "id": 7, "op": "status"}));
        assert_eq!(
            (error_code(&version), version["id"].as_u64()),
            ("unsupported_version", Some(7))
        );
        let no_id = client.request(json!({"v": 1, "op": "status"}));
        assert_eq!(
            (error_code(&no_id), no_id["id"].as_u64()),
            ("bad_request", Some(0))
        );
        // Blank lines are skipped; unknown fields are ignored.
        client.send(b"\n\r\n");
        let echo = client.request(json!({"v": 1, "id": 8, "op": "echo", "x": [1]}));
        assert_eq!(echo["result"], json!({"x": [1]}));
        let status = client.request(json!({"v": 1, "id": 9, "op": "status", "extra": true}));
        assert_eq!(status["ok"], true);
        // A line split across writes is one line.
        client.send(br#"{"v":1,"id":10,"#);
        thread::sleep(Duration::from_millis(20));
        client.send(b"\"op\":\"status\"}\n");
        assert_eq!(client.line().unwrap()["id"], 10);
    }

    #[test]
    fn oversized_lines_and_floods_are_refused() {
        let fixture = Fixture::new(Options::default());

        // 2 MiB with no newline: refused at the cap, then closed, without
        // the server reading the rest.
        let mut big = Client::connect(&fixture.path).hello();
        let mut writer = big.writer.try_clone().unwrap();
        let sender = thread::spawn(move || {
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..32 {
                if writer.write_all(&chunk).is_err() {
                    return;
                }
            }
        });
        let refused = big.line().unwrap();
        assert_eq!(
            (error_code(&refused), refused["id"].as_u64()),
            ("bad_request", Some(0))
        );
        assert_eq!(big.line(), None);
        sender.join().unwrap();

        // A line of exactly MAX_LINE bytes is fine. A response over the cap
        // is not sent: the echo of that line becomes an internal error.
        let mut full = Client::connect(&fixture.path).hello();
        let padded = |op: &str| {
            let base = serde_json::to_vec(&json!({"v": 1, "id": 1, "op": op, "p": ""})).unwrap();
            let line = json!({"v": 1, "id": 1, "op": op, "p": "y".repeat(MAX_LINE - base.len())});
            assert_eq!(serde_json::to_vec(&line).unwrap().len(), MAX_LINE);
            line
        };
        assert_eq!(full.request(padded("status"))["ok"], true);
        let echoed = full.request(padded("echo"));
        assert_eq!(
            (error_code(&echoed), echoed["id"].as_u64()),
            ("internal", Some(1))
        );

        // 150 requests in one burst: the first 100 are served, and the rest
        // are refused, at least one of them, without closing.
        let mut flood = Client::connect(&fixture.path).hello();
        let burst: Vec<u8> = (0..150)
            .flat_map(|id| {
                let mut line =
                    serde_json::to_vec(&json!({"v": 1, "id": id, "op": "status"})).unwrap();
                line.push(b'\n');
                line
            })
            .collect();
        flood.send(&burst);
        let responses: Vec<Value> = (0..150).map(|_| flood.line().unwrap()).collect();
        let ids: Vec<u64> = responses
            .iter()
            .map(|r| r["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, (0..150).collect::<Vec<u64>>());
        assert!(responses[..100].iter().all(|r| r["ok"] == true));
        let limited = responses
            .iter()
            .filter(|r| r["ok"] == false && r["error"]["code"] == "rate_limited")
            .count();
        assert!(limited >= 1, "no request was rate limited");
        assert_eq!(
            limited + responses.iter().filter(|r| r["ok"] == true).count(),
            150
        );
        // The budget refills.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            flood.request(json!({"v": 1, "id": 999, "op": "status"}))["ok"],
            true
        );
    }

    /// A peer whose uid is not the VMM's is closed before the hello, and
    /// recorded as denied. `SO_PEERCRED` cannot be made to lie, so the test
    /// hook makes the accept path see another uid.
    #[test]
    fn a_peer_with_another_uid_is_refused() {
        let other = uid().wrapping_add(1);
        let mut fixture = Fixture::new(Options {
            peer_uid: Some(other),
        });
        let mut client = Client::connect(&fixture.path);
        assert_eq!(client.line(), None, "closed before the hello");
        fixture.server.take().unwrap().shutdown();
        assert_eq!(
            fixture.control_records(),
            [(
                "control.connect".to_owned(),
                json!({"pid": std::process::id(), "uid": other, "verdict": "deny"})
            )]
        );
    }

    /// Sets the process umask for as long as it lives.
    struct Umask(libc::mode_t);

    impl Umask {
        fn set(mask: libc::mode_t) -> Umask {
            // SAFETY: umask only swaps the process file mode creation mask.
            Umask(unsafe { libc::umask(mask) })
        }
    }

    impl Drop for Umask {
        fn drop(&mut self) {
            // SAFETY: as above, putting the old mask back.
            unsafe { libc::umask(self.0) };
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// The VMM runs with umask 0 once the shares are imported: the modes
    /// are set, not left to the umask. Every directory bind creates is 0700.
    #[test]
    fn socket_and_dir_modes_are_0600_and_0700_under_umask_0() {
        let fixture = {
            let _umask = Umask::set(0);
            Fixture::new(Options::default())
        };
        assert!(fs::symlink_metadata(&fixture.path)
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(mode(&fixture.path), 0o600);
        assert_eq!(mode(&fixture.state_dir), 0o700);
        assert_eq!(mode(fixture.state_dir.parent().unwrap()), 0o700);
        assert_eq!(
            mode(fixture.state_dir.parent().unwrap().parent().unwrap()),
            0o700
        );
    }

    fn close_on_exec(fd: std::os::fd::RawFd) -> bool {
        // SAFETY: F_GETFD only reads the descriptor's flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl: {}", io::Error::last_os_error());
        flags & libc::FD_CLOEXEC != 0
    }

    /// No descriptor of the server leaks into a process the VMM starts.
    #[test]
    fn the_wake_eventfds_are_close_on_exec() {
        let fixture = Fixture::new(Options::default());
        assert!(close_on_exec(fixture.server().shared.wake.as_raw_fd()));
        let (stream, _peer) = UnixStream::pair().unwrap();
        let hello = Hello::new("boxcar/test", "s", Vec::new());
        let conn = Conn::new(stream, &hello).unwrap();
        assert!(close_on_exec(conn.wake_fd()));
    }

    /// A state directory others can enter is refused.
    #[test]
    fn a_state_dir_others_can_reach_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = crate::lifecycle::test_handle(&tmp.path().join("audit"));
        let state_dir = tmp.path().join("open");
        fs::create_dir(&state_dir).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let ops = Arc::new(FakeOps {
            stops: Mutex::new(Vec::new()),
        });
        let error = ControlServer::bind(&state_dir, handle, ops).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(!state_dir.join("control.sock").exists());
        writer.close().unwrap();
    }

    /// The stop sequence never waits on a client: one that does not read,
    /// with the socket full of responses it did not take, is cut off.
    #[test]
    fn shutdown_does_not_wait_on_a_client_that_does_not_read() {
        let mut fixture = Fixture::new(Options::default());
        let mut client = Client::connect(&fixture.path).hello();
        let burst: Vec<u8> = (0..4000)
            .flat_map(|id| {
                let mut line =
                    serde_json::to_vec(&json!({"v": 1, "id": id, "op": "status"})).unwrap();
                line.push(b'\n');
                line
            })
            .collect();
        client.send(&burst);
        thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        fixture.server.take().unwrap().shutdown();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        // What it does read still ends.
        while client.line().is_some() {}
        drop(fixture.records());
    }

    /// An op can turn its connection into a raw byte stream: the response
    /// first, then the bytes, including any sent right behind the request.
    #[test]
    fn a_raw_upgrade_hands_the_stream_over_after_the_response() {
        let fixture = Fixture::new(Options::default());
        let mut client = Client::connect(&fixture.path).hello();
        client.send(b"{\"v\":1,\"id\":1,\"op\":\"raw\"}\nab");
        assert_eq!(client.line().unwrap()["result"], json!({"raw": true}));
        client.send(b"c");
        let mut echoed = [0u8; 3];
        client.reader.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ABC");
        // Raw connections hear no events, and still end with the server.
        fixture.server().notify_state(VmState::Stopping);
        drop(fixture);
        assert_eq!(client.line(), None);
    }
}
