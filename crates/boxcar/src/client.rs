// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The client side of the control socket: where each session's socket is,
//! how `boxcar status`, `boxcar stop` and `boxcar attach` find one, and a
//! connection that speaks the protocol (and becomes a raw byte stream after
//! `pty.attach`).
//!
//! Every session's state directory is `<root>/<session_id>/`, its socket
//! `control.sock` in it. The root is `$XDG_RUNTIME_DIR/boxcar` when
//! `XDG_RUNTIME_DIR` is an absolute UTF-8 path to a directory this user can
//! write, short enough for a socket path under it; otherwise
//! `/tmp/boxcar-<uid>`. `boxcar run` creates the root mode 0700; a root that
//! is not this user's own, or that others can enter, is refused, by `run`
//! and by the lookups alike.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use boxcar_proto::control::{
    to_line, ErrorBody, Hello, Request, Response, MAX_LINE, PROTOCOL, SOCKET_NAME, VERSION,
};
use serde_json::Value;

/// How long the client waits for the hello and for each response.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// How many messages [`Client::request`] keeps for [`Client::next_message`]
/// while it waits for its response: a server that sends more events than
/// this before answering is not one to wait for.
pub const MAX_PENDING: usize = 1024;
/// The longest socket path `bind` and `connect` take, without the NUL.
const MAX_SOCKET_PATH: usize = 107;
/// A session id's length: a hyphenated UUID.
const SESSION_ID_LEN: usize = 36;

/// The sessions root for `XDG_RUNTIME_DIR` = `xdg` and user `uid`, where
/// `usable` says whether a directory exists and this user can write it.
fn sessions_root_for(xdg: Option<OsString>, uid: u32, usable: impl Fn(&Path) -> bool) -> PathBuf {
    let xdg_root = xdg
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute() && dir.to_str().is_some() && usable(dir))
        .map(|dir| dir.join("boxcar"))
        .filter(|root| socket_path_fits(root));
    xdg_root.unwrap_or_else(|| PathBuf::from(format!("/tmp/boxcar-{uid}")))
}

/// Whether a session's socket under `root` fits in a socket address.
fn socket_path_fits(root: &Path) -> bool {
    let longest = root.join("x".repeat(SESSION_ID_LEN)).join(SOCKET_NAME);
    longest.as_os_str().as_bytes().len() <= MAX_SOCKET_PATH
}

/// Whether `dir` is a directory this user can write and enter.
fn writable_dir(dir: &Path) -> bool {
    let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is a NUL-terminated string; access only reads it.
    dir.is_dir() && unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) } == 0
}

fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// The directory that holds one state directory per session (see the
/// module docs). Nothing is created.
pub fn sessions_root() -> PathBuf {
    sessions_root_for(
        std::env::var_os("XDG_RUNTIME_DIR"),
        current_uid(),
        writable_dir,
    )
}

/// [`sessions_root`], created mode 0700 if it is not there, once it is
/// known to be this user's own and private.
pub fn ensure_sessions_root() -> anyhow::Result<PathBuf> {
    let root = sessions_root();
    match DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("cannot create {}", root.display())),
    }
    check_private_dir(&root)?;
    Ok(root)
}

/// Refuses `dir` unless it is a directory (not a link to one) of this
/// user that only this user can enter.
fn check_private_dir(dir: &Path) -> anyhow::Result<()> {
    let meta = fs::symlink_metadata(dir).with_context(|| format!("{}", dir.display()))?;
    if !meta.is_dir() {
        bail!("{}: not a directory", dir.display());
    }
    if meta.uid() != current_uid() {
        bail!(
            "{}: owned by uid {}, not this user",
            dir.display(),
            meta.uid()
        );
    }
    if meta.mode() & 0o077 != 0 {
        bail!(
            "{}: mode {:o} lets other users in; it must be 0700",
            dir.display(),
            meta.mode() & 0o7777
        );
    }
    Ok(())
}

/// A session with a control socket under the root.
struct Session {
    id: String,
    socket: PathBuf,
}

/// The sessions under `root` that have a control socket, by id.
fn sessions(root: &Path) -> anyhow::Result<Vec<Session>> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot list {}", root.display())),
    };
    check_private_dir(root)?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot list {}", root.display()))?;
        let Ok(id) = entry.file_name().into_string() else {
            continue;
        };
        let socket = entry.path().join(SOCKET_NAME);
        if socket.exists() {
            found.push(Session { id, socket });
        }
    }
    found.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(found)
}

/// Connects to the session `control` or `session_id` names: `--control`
/// itself; else the session whose id is or starts with `session_id`; else
/// the one session whose VMM answers, when exactly one does.
pub fn connect(control: Option<&Path>, session_id: Option<&str>) -> anyhow::Result<Client> {
    if let Some(path) = control {
        return Client::connect(path);
    }
    let root = sessions_root();
    let sessions = sessions(&root)?;
    if let Some(prefix) = session_id {
        let matching: Vec<&Session> = sessions
            .iter()
            .filter(|session| session.id.starts_with(prefix))
            .collect();
        return match matching.as_slice() {
            [] => bail!("no session {prefix} under {}", root.display()),
            [session] => Client::connect(&session.socket),
            many => bail!(
                "{prefix} matches {} sessions: {}",
                many.len(),
                many.iter()
                    .map(|session| session.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
    }
    // A socket left by a VMM that is gone refuses the connection.
    let live: Vec<(String, (&Path, UnixStream))> = sessions
        .iter()
        .filter_map(|session| {
            let stream = UnixStream::connect(&session.socket).ok()?;
            Some((session.id.clone(), (session.socket.as_path(), stream)))
        })
        .collect();
    let (socket, stream) = only_one(live)?;
    Client::from_stream(stream, socket)
}

/// The one running session of `live`, by id: an error when there is none,
/// and one that names them all when there are several.
fn only_one<T>(mut live: Vec<(String, T)>) -> anyhow::Result<T> {
    match live.len() {
        0 => bail!("no session found; pass --control or a session id"),
        1 => Ok(live.remove(0).1),
        n => bail!(
            "{n} sessions are running ({}); pass --control or a session id",
            live.iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// What the server sent: an event, or the response to a request.
#[derive(Debug)]
pub enum Message {
    Event { name: String, body: Value },
    Response(Response),
}

/// A connection to a control socket, past its hello.
pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    path: PathBuf,
    /// Shared with its [`Sender`]s.
    next_id: Arc<AtomicU64>,
    /// What [`Client::request`] read past while it waited for its response,
    /// in order: [`Client::next_message`] returns these first, so no event
    /// is lost to a request.
    pending: VecDeque<Message>,
}

/// Sends requests on a [`Client`]'s connection without waiting for their
/// responses, which the client's [`Client::next_message`] reads: for a
/// thread other than the one that reads.
pub struct Sender {
    writer: UnixStream,
    path: PathBuf,
    next_id: Arc<AtomicU64>,
}

impl Sender {
    /// Sends `op` with `params` (an object, or null for none); returns the
    /// request's id.
    pub fn send(&mut self, op: &str, params: Value) -> anyhow::Result<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        send_request(&mut self.writer, &self.path, id, op, params)?;
        Ok(id)
    }
}

fn send_request(
    writer: &mut UnixStream,
    path: &Path,
    id: u64,
    op: &str,
    params: Value,
) -> anyhow::Result<()> {
    let line = to_line(&Request::new(id, op, params))?;
    writer
        .write_all(&line)
        .with_context(|| format!("cannot send {op} to {}", path.display()))
}

impl Client {
    /// Connects to the socket at `path` and reads its hello.
    pub fn connect(path: &Path) -> anyhow::Result<Client> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("cannot connect to {}", path.display()))?;
        Client::from_stream(stream, path)
    }

    fn from_stream(stream: UnixStream, path: &Path) -> anyhow::Result<Client> {
        stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
        let writer = stream.try_clone()?;
        let mut client = Client {
            reader: BufReader::new(stream),
            writer,
            path: path.to_owned(),
            next_id: Arc::new(AtomicU64::new(1)),
            pending: VecDeque::new(),
        };
        let line = client.read_line()?.ok_or_else(|| {
            anyhow!(
                "{} closed the connection before its hello: is it this user's session?",
                path.display()
            )
        })?;
        let hello: Hello = serde_json::from_slice(&line)
            .with_context(|| format!("{} is not a boxcar control socket", path.display()))?;
        if hello.event != "hello" || hello.protocol != PROTOCOL {
            bail!("{} is not a boxcar control socket", path.display());
        }
        if !hello.versions.contains(&VERSION) {
            bail!(
                "{} speaks control protocol versions {:?}, not {VERSION}",
                path.display(),
                hello.versions
            );
        }
        Ok(client)
    }

    /// How long a read waits; `None` waits forever.
    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_ref().set_read_timeout(timeout)
    }

    /// The control socket's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A [`Sender`] on this connection.
    pub fn sender(&self) -> io::Result<Sender> {
        Ok(Sender {
            writer: self.writer.try_clone()?,
            path: self.path.clone(),
            next_id: Arc::clone(&self.next_id),
        })
    }

    /// The connection as a raw byte stream, once an op has turned it into
    /// one (`pty.attach`): the socket, with no read timeout, and the bytes
    /// already read past the op's response, which come first.
    pub fn into_raw(self) -> io::Result<(UnixStream, Vec<u8>)> {
        let pending = self.reader.buffer().to_vec();
        let stream = self.reader.into_inner();
        stream.set_read_timeout(None)?;
        Ok((stream, pending))
    }

    /// Sends `op` with `params` (an object, or null for none) and returns
    /// its result. What comes before the response (events, other
    /// responses) is kept for [`Client::next_message`].
    pub fn request(&mut self, op: &str, params: Value) -> anyhow::Result<Result<Value, ErrorBody>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        send_request(&mut self.writer, &self.path, id, op, params)?;
        loop {
            match self.read_message()? {
                None => bail!(
                    "{} closed the connection before answering",
                    self.path.display()
                ),
                Some(Message::Response(response)) if response.id == id => {
                    return Ok(response.into_result())
                }
                Some(other) => {
                    if self.pending.len() >= MAX_PENDING {
                        bail!(
                            "{} sent over {MAX_PENDING} messages before answering {op}",
                            self.path.display()
                        );
                    }
                    self.pending.push_back(other);
                }
            }
        }
    }

    /// A handle on the connection's socket, to end it from another thread:
    /// `shutdown`ing it makes a read in progress return the end of the
    /// stream.
    pub fn shutdown_handle(&self) -> io::Result<UnixStream> {
        self.writer.try_clone()
    }

    /// What a request read past while it waited for its response, in order,
    /// and not yet returned by [`next_message`](Self::next_message).
    pub fn take_pending(&mut self) -> Vec<Message> {
        self.pending.drain(..).collect()
    }

    /// The next line the server sent, raw (without its newline), or `None`
    /// once it closed the connection. Whatever [`request`](Self::request)
    /// read past is not in it: see [`take_pending`](Self::take_pending).
    pub fn next_line(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_line()
    }

    /// The next message (what a request read past first), or `None` once
    /// the server closed the connection.
    pub fn next_message(&mut self) -> anyhow::Result<Option<Message>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(message));
        }
        self.read_message()
    }

    /// The next message on the wire.
    fn read_message(&mut self) -> anyhow::Result<Option<Message>> {
        let Some(line) = self.read_line()? else {
            return Ok(None);
        };
        let value: Value = serde_json::from_slice(&line)
            .with_context(|| format!("{} sent a line that is not JSON", self.path.display()))?;
        if let Some(name) = value.get("event").and_then(Value::as_str) {
            return Ok(Some(Message::Event {
                name: name.to_owned(),
                body: value.clone(),
            }));
        }
        let response = serde_json::from_value(value)
            .with_context(|| format!("{} sent a malformed response", self.path.display()))?;
        Ok(Some(Message::Response(response)))
    }

    /// The next line without its newline, at most [`MAX_LINE`] bytes, or
    /// `None` at the end of the stream (a reset is an end too).
    fn read_line(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        loop {
            let buf = match self.reader.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(None),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    bail!("{} did not answer in time", self.path.display())
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("cannot read {}", self.path.display()))
                }
            };
            if buf.is_empty() {
                return Ok(None);
            }
            let (take, end) = match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (i, true),
                None => (buf.len(), false),
            };
            if line.len() + take > MAX_LINE {
                bail!("{} sent a line over {MAX_LINE} bytes", self.path.display());
            }
            line.extend_from_slice(&buf[..take]);
            self.reader.consume(if end { take + 1 } else { take });
            if end {
                return Ok(Some(line));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    /// A client of a server that answers its first request after `events`
    /// events, past its hello.
    fn client_of_a_chatty_server(events: usize) -> Client {
        use std::io::Read;
        let (server, client) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut server = server;
            let hello = Hello::new("boxcar/test", "s", Vec::new());
            server.write_all(&to_line(&hello).unwrap()).unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while byte[0] != b'\n' {
                server.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let mut out = Vec::new();
            for n in 0..events {
                let event = serde_json::json!({"v": 1, "event": "audit.lagged", "n": n});
                out.extend_from_slice(&to_line(&event).unwrap());
            }
            let ok = Response::success(1, serde_json::json!({"next_seq": 1}));
            out.extend_from_slice(&to_line(&ok).unwrap());
            // The client may have given up on it.
            let _ = server.write_all(&out);
        });
        Client::from_stream(client, Path::new("/test")).unwrap()
    }

    /// A request keeps the events that come before its response, for
    /// `next_message`, but not without limit: a server that sends more than
    /// 1024 before answering is an error that names the cap.
    #[test]
    fn a_request_keeps_at_most_1024_events_ahead_of_its_response() {
        let mut client = client_of_a_chatty_server(MAX_PENDING);
        let result = client.request("audit.subscribe", Value::Null).unwrap();
        assert_eq!(result.unwrap(), serde_json::json!({"next_seq": 1}));
        let pending = client.take_pending();
        assert_eq!(pending.len(), MAX_PENDING);
        let Message::Event { body, .. } = &pending[1023] else {
            panic!("not an event")
        };
        assert_eq!(body["n"], 1023, "in order");

        let mut client = client_of_a_chatty_server(MAX_PENDING + 1);
        let error = client
            .request("audit.subscribe", Value::Null)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("over 1024 messages before answering audit.subscribe"),
            "{error}"
        );
    }

    #[test]
    fn the_root_is_under_xdg_runtime_dir_when_it_is_usable() {
        let yes = |_: &Path| true;
        assert_eq!(
            sessions_root_for(os("/run/user/1000"), 1000, yes),
            PathBuf::from("/run/user/1000/boxcar")
        );
        // Unset, relative, not writable, or too long for a socket path.
        let fallback = PathBuf::from("/tmp/boxcar-1000");
        assert_eq!(sessions_root_for(None, 1000, yes), fallback);
        assert_eq!(sessions_root_for(os("run/user"), 1000, yes), fallback);
        assert_eq!(sessions_root_for(os(""), 1000, yes), fallback);
        assert_eq!(
            sessions_root_for(os("/run/user/1000"), 1000, |_| false),
            fallback
        );
        let long = format!("/{}", "d".repeat(60));
        assert_eq!(sessions_root_for(os(&long), 1000, yes), fallback);
        // The longest that fits: root, a session id and `control.sock` in
        // 107 bytes.
        let fits = format!(
            "/{}",
            "d".repeat(107 - 1 - "/boxcar".len() - 1 - 36 - 1 - 12)
        );
        assert_eq!(
            sessions_root_for(os(&fits), 1000, yes),
            PathBuf::from(&fits).join("boxcar")
        );
        let over = format!("{fits}d");
        assert_eq!(sessions_root_for(os(&over), 1000, yes), fallback);
    }

    #[test]
    fn without_an_id_exactly_one_running_session_is_chosen() {
        let none: Vec<(String, u8)> = Vec::new();
        assert_eq!(
            only_one(none).unwrap_err().to_string(),
            "no session found; pass --control or a session id"
        );
        assert_eq!(only_one(vec![("a".to_owned(), 7)]).unwrap(), 7);
        let two = vec![("01aa".to_owned(), 1), ("01bb".to_owned(), 2)];
        assert_eq!(
            only_one(two).unwrap_err().to_string(),
            "2 sessions are running (01aa, 01bb); pass --control or a session id"
        );
    }

    #[test]
    fn a_root_others_can_enter_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("boxcar");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        check_private_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let error = check_private_dir(&root).unwrap_err().to_string();
        assert!(error.contains("mode 750 lets other users in"), "{error}");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let error = check_private_dir(&link).unwrap_err().to_string();
        assert!(error.contains("not a directory"), "{error}");
    }
}
