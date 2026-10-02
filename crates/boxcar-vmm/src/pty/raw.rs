// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A control connection attached to the session's terminal: what
//! `pty.attach` turns it into ([`serve`], run by the connection's
//! [`RawUpgrade`](crate::control::RawUpgrade)).
//!
//! The connection carries raw bytes both ways from then on. The client's
//! bytes go to the session through its [`Input`] (a read-write client's,
//! never waited for: past the hub's input queue they are dropped and
//! counted), or are discarded and counted (a read-only client's). The
//! session's output goes to the client on a thread of its own, which waits
//! on the client as long as it takes: the hub does not wait for it, and
//! detaches a client that falls [`BACKLOG_MAX`](super::BACKLOG_MAX)
//! behind. Its stream then ends with one line, `{"v":1,"event":
//! "pty.detached","reason":"slow"}`, and the connection is closed; when the
//! session's terminal ends, the stream ends after its last byte.
//!
//! The client may close its sending side and keep reading. The connection
//! ends when it is closed for good: by the client, by the server (when the
//! VM stops), or after the stream's end; the client is then detached.

use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread;

use boxcar_proto::control::{to_line, PtyDetached};

use super::{ClientId, End, Input, Output, PtyHub};

/// Bytes read from the client at a time.
const READ_CHUNK: usize = 16 * 1024;

/// A client attached for a control connection: detached when dropped, so
/// that one whose connection never became raw (the client went before the
/// response) does not stay.
pub struct Attached {
    hub: PtyHub,
    id: ClientId,
}

impl Attached {
    pub fn new(hub: PtyHub, id: ClientId) -> Attached {
        Attached { hub, id }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.hub.detach(self.id);
    }
}

/// Serves the attached connection `stream`, whose client sent `pending`
/// right behind its request, until it ends (see the module docs).
pub fn serve(
    attached: Attached,
    output: Output,
    input: Option<Input>,
    stream: UnixStream,
    pending: Vec<u8>,
) {
    let typed = |bytes: &[u8]| match &input {
        // A session that takes no more: the bytes go nowhere, and the
        // client is not held up.
        Some(input) => {
            let _ = input.send(bytes);
        }
        None => attached.hub.discard(bytes.len()),
    };
    if !pending.is_empty() {
        typed(&pending);
    }
    let to_client = match stream.try_clone() {
        Ok(stream) => stream,
        Err(error) => {
            boxcar_virtio::limited!(warn, "pty attach: cannot serve the connection: {error}");
            return;
        }
    };
    let writer = thread::Builder::new()
        .name("pty-attach".into())
        .spawn(move || write_out(&to_client, &output));
    let writer = match writer {
        Ok(writer) => writer,
        Err(error) => {
            boxcar_virtio::limited!(warn, "pty attach: cannot serve the connection: {error}");
            return;
        }
    };
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        match (&stream).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => typed(&buf[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    // The client sends no more; it may still read, until the connection is
    // closed for good.
    wait_hangup(stream.as_raw_fd());
    drop(attached);
    let _ = writer.join();
}

/// The session's output to the client until it ends, the client is
/// detached for being slow (then the `pty.detached` line), or the client
/// is gone; then the connection is shut down.
fn write_out(stream: &UnixStream, output: &Output) {
    let fd = stream.as_raw_fd();
    while let Some(bytes) = output.recv() {
        // Detached: what is queued is dropped, the line comes next.
        if output.end() == Some(End::Slow) {
            break;
        }
        if send_all(fd, &bytes).is_err() {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    }
    if output.end() == Some(End::Slow) {
        if let Ok(line) = to_line(&PtyDetached::slow()) {
            let _ = send_all(fd, &line);
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// Writes all of `bytes` to the (blocking) socket `fd`, without
/// `SIGPIPE`.
fn send_all(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        // SAFETY: sends at most `bytes.len()` bytes from `bytes`.
        let n = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
        match usize::try_from(n) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(_) => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

/// Waits until the socket `fd` is closed both ways (`POLLHUP`, or an
/// error).
fn wait_hangup(fd: RawFd) {
    let mut pollfd = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    loop {
        // SAFETY: poll reads and writes the one pollfd it is given.
        let rc = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if rc > 0 || (rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted) {
            return;
        }
    }
}
