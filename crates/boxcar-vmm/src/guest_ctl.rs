// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest control channel: the VMM's service on vsock port 1024
//! (`boxcar.ctl`), and what the guest's init reports through it.
//!
//! Init connects once it has mounted the root and says `hello`; the VMM
//! answers with the session's [`SessionConfig`] (the command, its user, its
//! environment and terminal size). Init starts the session and reports
//! `session.started` with its pid, recorded as `session.start`; once the
//! session has ended, `session.exited` with its exit code or the signal
//! that killed it, recorded as `session.exit` and kept for the VM's exit
//! code (see [`crate::lifecycle`]). The messages are
//! [`boxcar_proto::guest`]'s JSON lines, at most 64 KiB each.
//!
//! The VMM takes one connection in its life ([`GuestCtl::service`]): guest
//! root can rebind the vsock driver, which re-activates the device and lets
//! a privileged guest port connect again, so a later connection is refused
//! (`vsock.connect` with reason `reactivated`) rather than taken for a fresh
//! init.
//!
//! The channel runs on two threads: one reads init's lines (a line over the
//! limit loses the framing and closes the channel; a line that is not a
//! message is skipped), the other writes what the VMM sends
//! ([`GuestCtlHandle::send`], which never waits: the stop sequence and the
//! control socket's ops use it). Once init's exit report is recorded and
//! kept, the VMM closes its sending side: init waits for that before it
//! reboots, so the report is in when the reset arrives. What the guest
//! sends is logged rate-limited; nothing here logs on the stop path.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_audit::{AuditSink, Priority, Submission};
use boxcar_proto::control::{GuestStatus, SessionOutcome};
use boxcar_proto::guest::{
    decode, encode, GuestMsg, GuestProtoError, HostMsg, LineBuf, LogLevel, MAX_LINE,
};
use boxcar_proto::{Payload, Ring, SessionExit, SessionStart, Subject};
use boxcar_vsock::{ConnMeta, Deny};

use crate::services::Service;

pub use boxcar_proto::guest::SessionConfig;

/// The reason a connection after the first is refused with.
pub const REACTIVATED: &str = "reactivated";

/// How long the stop sequence waits for the channel's threads to end once
/// the vsock device is closed.
pub const CLOSE_DEADLINE: Duration = Duration::from_secs(1);

/// Lines waiting for the writer; past this, [`GuestCtlHandle::send`] fails.
const OUTBOX: usize = 64;

/// Bytes read from the channel at a time.
const READ_CHUNK: usize = 8192;

/// The most of a guest log line the host logs, in bytes.
const LOG_MAX: usize = 1024;

/// Whether `session` can be sent and run: a command, ids other than the
/// all-ones one (which `setresuid` reads as "leave alone"), an absolute
/// working directory, and a config line within the channel's limit. The
/// error says what is wrong, as a user should see it.
pub fn check_session(session: &SessionConfig) -> Result<(), String> {
    if session.argv.is_empty() {
        return Err("the session has no command".into());
    }
    if session.uid == u32::MAX || session.gid == u32::MAX {
        return Err(format!(
            "the session's uid {} and gid {}: 4294967295 is not a usable id",
            session.uid, session.gid
        ));
    }
    if !session.cwd.starts_with('/') {
        return Err(format!(
            "the session's working directory {:?} is not absolute",
            session.cwd
        ));
    }
    let len = encode(&HostMsg::Config(session.clone())).len() - 1;
    if len > MAX_LINE {
        return Err(format!(
            "the session's config is {len} bytes, over the control channel's limit of \
             {MAX_LINE}: the command or its environment is too long"
        ));
    }
    Ok(())
}

/// Why a message was not sent.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// Init is not connected, or the channel has closed.
    #[error("the guest control channel is not connected")]
    NotConnected,
    /// The writer has its 64 lines waiting: init is not reading.
    #[error("the guest control channel is full")]
    Full,
}

/// The guest control channel: see the module docs.
pub struct GuestCtl {
    session: SessionConfig,
    audit: AuditSink,
    /// Set once the one connection of the VMM's life is taken.
    taken: AtomicBool,
    next_ping: AtomicU64,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    status: GuestStatus,
    /// The writer's queue, while the channel is open.
    outbox: Option<SyncSender<Vec<u8>>>,
    /// The VMM's end of the channel, to shut down.
    stream: Option<UnixStream>,
    /// The ping sent last and not answered yet.
    ping: Option<u64>,
    /// The reader and the writer, each with the receiver its end is told on.
    threads: Vec<(JoinHandle<()>, Receiver<()>)>,
}

impl GuestCtl {
    /// A channel that sends `session` to init and records into `audit`;
    /// idle until its [`service`](GuestCtl::service) takes init's
    /// connection.
    pub fn new(session: SessionConfig, audit: AuditSink) -> Arc<GuestCtl> {
        Arc::new(GuestCtl {
            session,
            audit,
            taken: AtomicBool::new(false),
            next_ping: AtomicU64::new(0),
            state: Mutex::new(State::default()),
        })
    }

    /// The service for port 1024: takes the first connection, and refuses
    /// every later one as [`REACTIVATED`].
    pub fn service(self: &Arc<Self>) -> Service {
        let ctl = Arc::clone(self);
        Arc::new(move |meta| ctl.accept(meta))
    }

    /// A handle that sends to init.
    pub fn handle(self: &Arc<Self>) -> GuestCtlHandle {
        GuestCtlHandle {
            ctl: Arc::clone(self),
        }
    }

    /// What init has reported.
    pub fn status(&self) -> GuestStatus {
        self.lock().status.clone()
    }

    /// How the session ended, once init reported it.
    pub fn exit(&self) -> Option<SessionOutcome> {
        self.lock().status.exit
    }

    /// Whether init has started the session and not reported its end.
    pub fn session_running(&self) -> bool {
        let status = &self.lock().status;
        status.init_ready && status.session_pid.is_some() && status.exit.is_none()
    }

    /// Whether a ping went unanswered so far.
    pub fn ping_outstanding(&self) -> bool {
        self.lock().ping.is_some()
    }

    /// Shuts the channel down and waits, until `deadline` from now, for its
    /// threads to end. Returns whether they did; a thread still running at
    /// the deadline is left to end on its own. Logs nothing: the stop
    /// sequence calls it.
    pub fn close(&self, deadline: Duration) -> bool {
        let deadline = Instant::now() + deadline;
        let threads = {
            let mut state = self.lock();
            if let Some(stream) = state.stream.take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
            state.outbox = None;
            std::mem::take(&mut state.threads)
        };
        let mut all = true;
        for (thread, done) in threads {
            let left = deadline.saturating_duration_since(Instant::now());
            match done.recv_timeout(left) {
                // Told, or its sender dropped as it ended (a panic too).
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = thread.join();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => all = false,
            }
        }
        all
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Init's connection, on the vsock thread: one in the VMM's life.
    fn accept(self: &Arc<Self>, meta: ConnMeta) -> Result<UnixStream, Deny> {
        if self.taken.swap(true, Ordering::SeqCst) {
            boxcar_virtio::limited!(
                warn,
                "guest control channel: refused a connection from guest port {}: init's \
                 was taken already, and the guest re-activated its vsock device",
                meta.guest_port
            );
            return Err(Deny::Refused(REACTIVATED));
        }
        match self.open() {
            Ok(ours) => Ok(ours),
            Err(error) => {
                // Not taken after all: init may try again.
                self.taken.store(false, Ordering::SeqCst);
                boxcar_virtio::limited!(
                    warn,
                    "guest control channel: cannot take init's connection: {error}"
                );
                Err(Deny::NoService)
            }
        }
    }

    /// Makes the stream pair and starts the threads on the VMM's end;
    /// returns the end the vsock device gets.
    fn open(self: &Arc<Self>) -> io::Result<UnixStream> {
        let (ours, theirs) = UnixStream::pair()?;
        let reader = theirs.try_clone()?;
        let writer = theirs.try_clone()?;
        let (outbox, lines) = mpsc::sync_channel(OUTBOX);
        let (reader_done, reader_end) = mpsc::channel();
        let (writer_done, writer_end) = mpsc::channel();
        let write_thread = thread::Builder::new()
            .name("guest-ctl-tx".into())
            .spawn(move || {
                write_lines(writer, &lines);
                let _ = writer_done.send(());
            })?;
        let ctl = Arc::clone(self);
        let read_thread = thread::Builder::new()
            .name("guest-ctl-rx".into())
            .spawn(move || {
                ctl.read_lines(reader);
                let _ = reader_done.send(());
            });
        let mut state = self.lock();
        state.outbox = Some(outbox);
        state.stream = Some(theirs);
        // A writer without a reader ends once its queue is dropped.
        state.threads.push((write_thread, writer_end));
        match read_thread {
            Ok(thread) => state.threads.push((thread, reader_end)),
            Err(error) => {
                state.outbox = None;
                return Err(error);
            }
        }
        Ok(ours)
    }

    /// The reader: init's lines until the channel closes.
    fn read_lines(&self, mut stream: UnixStream) {
        let mut lines = LineBuf::new(MAX_LINE);
        let mut buf = vec![0u8; READ_CHUNK];
        'read: loop {
            let n = match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if lines.push(&buf[..n]).is_err() {
                too_long(&stream);
                break;
            }
            while let Some(line) = lines.next_line() {
                match decode::<GuestMsg>(&line) {
                    Ok(msg) => self.on_message(msg, &stream),
                    Err(GuestProtoError::TooLong(_)) => {
                        too_long(&stream);
                        break 'read;
                    }
                    Err(error) => boxcar_virtio::limited!(
                        warn,
                        "guest control channel: skipped a line that is not a message: {error}"
                    ),
                }
            }
        }
        let mut state = self.lock();
        // The writer ends once what is queued is written, or fails.
        state.outbox = None;
        state.stream = None;
    }

    fn on_message(&self, msg: GuestMsg, stream: &UnixStream) {
        match msg {
            GuestMsg::Hello { init_version, .. } => self.on_hello(&init_version),
            GuestMsg::SessionStarted { pid } => self.on_started(pid),
            GuestMsg::SessionExited { code, signal } => {
                if self.on_exited(SessionOutcome { code, signal }) {
                    // The report is recorded and kept: init may reboot.
                    let _ = stream.shutdown(Shutdown::Write);
                }
            }
            GuestMsg::Pong { id, .. } => {
                let mut state = self.lock();
                if state.ping == Some(id) {
                    state.ping = None;
                }
            }
            GuestMsg::Log { level, msg } => log_guest(level, &msg),
        }
    }

    fn on_hello(&self, init_version: &str) {
        {
            let mut state = self.lock();
            if state.status.init_ready {
                drop(state);
                boxcar_virtio::limited!(warn, "guest control channel: a second hello, ignored");
                return;
            }
            state.status.init_ready = true;
        }
        let version: String = init_version.chars().take(64).collect();
        tracing::debug!("guest control channel: init {version:?} is ready");
        let config = encode(&HostMsg::Config(self.session.clone()));
        if self.queue(config).is_err() {
            boxcar_virtio::limited!(warn, "guest control channel: cannot send the config");
        }
    }

    fn on_started(&self, pid: u32) {
        {
            let mut state = self.lock();
            if !state.status.init_ready || state.status.session_pid.is_some() {
                drop(state);
                boxcar_virtio::limited!(
                    warn,
                    "guest control channel: a session start out of turn (pid {pid}), ignored"
                );
                return;
            }
            state.status.session_pid = Some(pid);
        }
        let session = &self.session;
        self.record(
            pid,
            Payload::SessionStart(SessionStart {
                argv: session.argv.clone(),
                cwd: session.cwd.clone(),
                uid: session.uid,
                gid: session.gid,
                pid,
            }),
        );
    }

    /// Records the session's end and then keeps it: once [`GuestCtl::exit`]
    /// says how the session ended, `session.exit` is in the log's queue.
    /// Returns whether the report was taken.
    fn on_exited(&self, outcome: SessionOutcome) -> bool {
        let pid = {
            let state = self.lock();
            match state.status.session_pid {
                Some(pid) if state.status.exit.is_none() => pid,
                _ => {
                    drop(state);
                    boxcar_virtio::limited!(
                        warn,
                        "guest control channel: a session end out of turn, ignored"
                    );
                    return false;
                }
            }
        };
        self.record(
            pid,
            Payload::SessionExit(SessionExit {
                code: outcome.code,
                signal: outcome.signal,
            }),
        );
        self.lock().status.exit = Some(outcome);
        true
    }

    /// Records `payload`, reported by init about the session `pid`. Waits
    /// for room in the log: a session record is never dropped.
    fn record(&self, pid: u32, payload: Payload) {
        let submission = Submission {
            ring: Ring::Guest,
            ts_guest_ns: None,
            subject: Some(Subject {
                pid,
                uid: self.session.uid,
                gid: self.session.gid,
            }),
            payload,
            span: None,
            priority: Priority::Normal,
        };
        // A closed or failed log stops the VM by itself.
        let _ = self.audit.emit(submission);
    }

    /// Queues a line for the writer, without waiting.
    fn queue(&self, line: Vec<u8>) -> Result<(), SendError> {
        let state = self.lock();
        let outbox = state.outbox.as_ref().ok_or(SendError::NotConnected)?;
        outbox.try_send(line).map_err(|error| match error {
            TrySendError::Full(_) => SendError::Full,
            TrySendError::Disconnected(_) => SendError::NotConnected,
        })
    }
}

/// Says that a line over the limit closed the channel, and closes it.
fn too_long(stream: &UnixStream) {
    boxcar_virtio::limited!(
        warn,
        "guest control channel: a line over {MAX_LINE} bytes; closing the channel"
    );
    let _ = stream.shutdown(Shutdown::Both);
}

/// The writer: each queued line, whole, until the queue is dropped or a
/// write fails.
fn write_lines(mut stream: UnixStream, lines: &Receiver<Vec<u8>>) {
    while let Ok(line) = lines.recv() {
        if stream.write_all(&line).is_err() {
            break;
        }
    }
}

/// Logs a line init sent, at its level, cut to [`LOG_MAX`] bytes; at most
/// a line a second for each level.
fn log_guest(level: LogLevel, msg: &str) {
    let mut end = msg.len().min(LOG_MAX);
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    let msg = msg[..end].escape_debug();
    match level {
        LogLevel::Error => boxcar_virtio::limited!(error, "guest: {msg}"),
        LogLevel::Warn => boxcar_virtio::limited!(warn, "guest: {msg}"),
        LogLevel::Info => boxcar_virtio::limited!(info, "guest: {msg}"),
        LogLevel::Debug => boxcar_virtio::limited!(debug, "guest: {msg}"),
    }
}

/// Sends to init: the stop sequence's `shutdown`, the terminal's `resize`.
/// Cheap to clone.
#[derive(Clone)]
pub struct GuestCtlHandle {
    ctl: Arc<GuestCtl>,
}

impl GuestCtlHandle {
    /// Queues `msg` for init without waiting; fails when init is not
    /// connected or is not reading.
    pub fn send(&self, msg: HostMsg) -> Result<(), SendError> {
        self.ctl.queue(encode(&msg))
    }

    /// Sends a ping and returns its id; the matching pong clears it (see
    /// [`GuestCtl::ping_outstanding`]).
    pub fn ping(&self) -> Result<u64, SendError> {
        let id = self.ctl.next_ping.fetch_add(1, Ordering::Relaxed) + 1;
        // Before the send, so that a pong cannot come first.
        let previous = self.ctl.lock().ping.replace(id);
        if let Err(error) = self.send(HostMsg::Ping { id }) {
            self.ctl.lock().ping = previous;
            return Err(error);
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use boxcar_audit::{LogReader, WriterConfig};
    use boxcar_proto::control::{GuestStatus, SessionOutcome};
    use boxcar_proto::guest::{decode, encode, GuestMsg, HostMsg, LogLevel, MAX_LINE};
    use boxcar_proto::{Record, SessionId};
    use boxcar_vsock::{ConnMeta, Deny};

    use super::*;

    const LIMIT: Duration = Duration::from_secs(5);

    fn session() -> SessionConfig {
        SessionConfig {
            argv: vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            cwd: "/workspace".into(),
            uid: 1000,
            gid: 1000,
            hostname: "boxcar".into(),
            term: "xterm-256color".into(),
            rows: 24,
            cols: 80,
            sysctls: Vec::new(),
        }
    }

    /// The init end of a channel: what the muxer would hold, as the guest.
    struct FakeInit {
        lines: BufReader<UnixStream>,
        out: UnixStream,
    }

    impl FakeInit {
        fn connect(ctl: &Arc<GuestCtl>) -> FakeInit {
            let stream = (ctl.service())(ConnMeta { guest_port: 1023 }).unwrap();
            stream.set_read_timeout(Some(LIMIT)).unwrap();
            FakeInit {
                out: stream.try_clone().unwrap(),
                lines: BufReader::new(stream),
            }
        }

        fn send(&mut self, msg: &GuestMsg) {
            self.out.write_all(&encode(msg)).unwrap();
        }

        fn recv(&mut self) -> HostMsg {
            let mut line = Vec::new();
            self.lines.read_until(b'\n', &mut line).unwrap();
            decode(&line).unwrap()
        }

        /// Reads until the VMM closes its side, and returns what came.
        fn until_eof(&mut self) -> Vec<u8> {
            let mut rest = Vec::new();
            self.lines.read_to_end(&mut rest).unwrap();
            rest
        }
    }

    /// Waits until `cond` holds of the channel's status.
    fn wait_for(ctl: &Arc<GuestCtl>, what: &str, cond: impl Fn(&GuestStatus) -> bool) {
        let deadline = Instant::now() + LIMIT;
        while !cond(&ctl.status()) {
            assert!(Instant::now() < deadline, "{what}: {:?}", ctl.status());
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn records(dir: &std::path::Path) -> Vec<Record> {
        LogReader::open(dir)
            .unwrap()
            .records()
            .map(Result::unwrap)
            .filter(|r| r.kind.starts_with("session."))
            .collect()
    }

    #[test]
    fn hello_then_config_then_session_lifecycle_over_a_socket_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(tmp.path(), SessionId::new())).unwrap();
        let session_dir = writer.session_dir().to_path_buf();
        let ctl = GuestCtl::new(session(), sink);
        let handle = ctl.handle();
        assert_eq!(
            ctl.status(),
            GuestStatus {
                init_ready: false,
                session_pid: None,
                exit: None
            }
        );
        // Nothing to send to before init connects.
        assert!(handle.send(HostMsg::Ping { id: 1 }).is_err());

        let mut init = FakeInit::connect(&ctl);
        init.send(&GuestMsg::Hello {
            init_version: "0.1.0".into(),
            guest_mono_ns: 1,
            guest_real_ns: 2,
        });
        assert_eq!(init.recv(), HostMsg::Config(session()));
        wait_for(&ctl, "init ready", |s| s.init_ready);

        init.send(&GuestMsg::SessionStarted { pid: 42 });
        wait_for(&ctl, "session pid", |s| s.session_pid == Some(42));
        assert!(ctl.session_running());

        // The host's messages reach init in order; a ping is answered.
        handle
            .send(HostMsg::Resize {
                rows: 40,
                cols: 120,
            })
            .unwrap();
        let id = handle.ping().unwrap();
        assert_eq!(
            init.recv(),
            HostMsg::Resize {
                rows: 40,
                cols: 120
            }
        );
        assert_eq!(init.recv(), HostMsg::Ping { id });
        assert!(ctl.ping_outstanding());
        init.send(&GuestMsg::Pong {
            id,
            guest_mono_ns: 3,
        });
        init.send(&GuestMsg::Log {
            level: LogLevel::Warn,
            msg: "a warning from init".into(),
        });
        let deadline = Instant::now() + LIMIT;
        while ctl.ping_outstanding() {
            assert!(Instant::now() < deadline, "the pong was not seen");
            std::thread::sleep(Duration::from_millis(5));
        }

        // The exit is stored and recorded before the VMM closes its side,
        // which tells init it may reboot.
        init.send(&GuestMsg::SessionExited {
            code: Some(7),
            signal: None,
        });
        assert_eq!(init.until_eof(), b"");
        let outcome = SessionOutcome {
            code: Some(7),
            signal: None,
        };
        assert_eq!(ctl.exit(), Some(outcome));
        assert_eq!(ctl.status().exit, Some(outcome));
        assert!(!ctl.session_running());
        drop(init);
        assert!(ctl.close(LIMIT), "the channel's threads ended");

        writer.close().unwrap();
        let records = records(&session_dir);
        let kinds: Vec<&str> = records.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["session.start", "session.exit"]);
        assert_eq!(
            records[0].data,
            serde_json::json!({
                "argv": ["/bin/sh", "-c", "exit 7"],
                "cwd": "/workspace",
                "uid": 1000,
                "gid": 1000,
                "pid": 42,
            })
        );
        assert_eq!(
            records[1].data,
            serde_json::json!({"code": 7, "signal": null})
        );
        for record in &records {
            assert_eq!(record.ring, boxcar_proto::Ring::Guest, "{record:?}");
            let subject = record.subject.unwrap();
            assert_eq!((subject.pid, subject.uid, subject.gid), (42, 1000, 1000));
        }
    }

    /// One connection a VMM life: after a driver rebind, a second init
    /// (or guest root posing as one) is refused, and recorded as such.
    #[test]
    fn a_second_connection_is_refused_as_reactivated() {
        let tmp = tempfile::tempdir().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(tmp.path(), SessionId::new())).unwrap();
        let ctl = GuestCtl::new(session(), sink);
        let service = ctl.service();
        let first = service(ConnMeta { guest_port: 1023 }).unwrap();
        match service(ConnMeta { guest_port: 1023 }) {
            Err(Deny::Refused(reason)) => assert_eq!(reason, "reactivated"),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a second connection was taken"),
        }
        // Even once the first is gone.
        drop(first);
        assert!(ctl.close(LIMIT));
        assert!(matches!(
            service(ConnMeta { guest_port: 1023 }),
            Err(Deny::Refused("reactivated"))
        ));
        writer.close().unwrap();
    }

    /// A line over 64 KiB loses the framing: the channel is closed, and
    /// nothing in it counted.
    #[test]
    fn an_oversized_line_closes_the_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(tmp.path(), SessionId::new())).unwrap();
        let ctl = GuestCtl::new(session(), sink);
        let mut init = FakeInit::connect(&ctl);
        let mut long = br#"{"t":"hello","init_version":""#.to_vec();
        long.resize(MAX_LINE + 1, b'x');
        // The VMM may close before it has read it all.
        let _ = init.out.write_all(&long);
        assert_eq!(init.until_eof(), b"");
        assert!(ctl.close(LIMIT));
        assert!(!ctl.status().init_ready);
        assert!(
            init.out.write_all(b"{}\n").is_err() || {
                // A write may still land in the buffer; the next one fails.
                std::thread::sleep(Duration::from_millis(50));
                init.out.write_all(b"{}\n").is_err()
            }
        );
        writer.close().unwrap();
    }

    /// A line that is not a message is skipped: the channel goes on.
    #[test]
    fn a_line_that_is_not_a_message_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(tmp.path(), SessionId::new())).unwrap();
        let ctl = GuestCtl::new(session(), sink);
        let mut init = FakeInit::connect(&ctl);
        init.out
            .write_all(b"not json\n{\"t\":\"reboot\"}\n")
            .unwrap();
        init.send(&GuestMsg::Hello {
            init_version: "0.1.0".into(),
            guest_mono_ns: 1,
            guest_real_ns: 2,
        });
        assert_eq!(init.recv(), HostMsg::Config(session()));
        // A session report before hello would have been ignored; a second
        // hello is.
        init.send(&GuestMsg::Hello {
            init_version: "0.1.0".into(),
            guest_mono_ns: 1,
            guest_real_ns: 2,
        });
        init.send(&GuestMsg::SessionStarted { pid: 7 });
        wait_for(&ctl, "session pid", |s| s.session_pid == Some(7));
        drop(init);
        assert!(ctl.close(LIMIT));
        writer.close().unwrap();
    }

    /// The config line must fit the channel's limit; the CLI checks it
    /// before a session starts.
    #[test]
    fn a_config_over_64_kib_is_refused() {
        assert!(check_session(&session()).is_ok());
        let mut big = session();
        big.argv.push("y".repeat(MAX_LINE));
        let error = check_session(&big).unwrap_err();
        assert!(error.contains("65536"), "{error}");
        let mut empty = session();
        empty.argv.clear();
        assert!(check_session(&empty).is_err());
        let mut root = session();
        root.uid = u32::MAX;
        assert!(check_session(&root).is_err());
    }
}
