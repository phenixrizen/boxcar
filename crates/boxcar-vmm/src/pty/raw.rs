// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A control connection attached to the session's terminal: what
//! `pty.attach` turns it into ([`serve`], run by the connection's
//! [`RawUpgrade`](crate::control::RawUpgrade)).
//!
//! The connection carries raw bytes both ways from then on, and nothing
//! else. The client's bytes go to the session through its [`Input`] (a
//! read-write client's, never waited for: past the hub's input queue they
//! are dropped and counted), or are discarded and counted (a read-only
//! client's). The session's output goes to the client on a thread of its
//! own, which waits on the client, but not for ever: the hub does not wait
//! for it and detaches a client that falls
//! [`BACKLOG_MAX`](super::BACKLOG_MAX) behind, and the writer itself
//! detaches one that takes no byte for [`STALL_LIMIT`] (30 s). Either way
//! it is detached as slow: the stream ends after the last byte the client
//! took, and the connections that watch the attach (`pty.watch`) hear
//! `pty.detached` (reason `slow`); the writer tells them before it closes
//! the stream, and never from the hub's thread. When the session's
//! terminal ends, the stream ends after its last byte.
//!
//! The client may close its sending side and keep reading. The connection
//! ends when it is closed for good: by the client, by the server (when the
//! VM stops), or after the stream's end; the client is then detached.

use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::{Duration, Instant};

use super::{ClientId, End, Input, Output, PtyHub};

/// Bytes read from the client at a time.
const READ_CHUNK: usize = 16 * 1024;

/// How long the writer lets a client take no byte before it detaches it as
/// slow.
pub const STALL_LIMIT: Duration = Duration::from_secs(30);

/// How often the writer looks at its client's end while it waits.
const STEP: Duration = Duration::from_millis(100);

/// A client attached for a control connection: detached when dropped, so
/// that one whose connection never became raw (the client went before the
/// response) does not stay.
pub struct Attached {
    hub: PtyHub,
    id: ClientId,
    stall_limit: Duration,
}

impl Attached {
    pub fn new(hub: PtyHub, id: ClientId) -> Attached {
        Attached::with_stall_limit(hub, id, STALL_LIMIT)
    }

    /// [`Attached::new`] with another stall limit than [`STALL_LIMIT`].
    pub fn with_stall_limit(hub: PtyHub, id: ClientId, stall_limit: Duration) -> Attached {
        Attached {
            hub,
            id,
            stall_limit,
        }
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
    let hub = attached.hub.clone();
    let (id, stall_limit) = (attached.id, attached.stall_limit);
    let writer = thread::Builder::new()
        .name("pty-attach".into())
        .spawn(move || write_out(&to_client, &output, &hub, id, stall_limit));
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

/// How a write to the client ended early.
enum Halt {
    /// The client is detached as slow.
    Slow,
    /// The client is gone.
    Gone,
}

/// The session's output to the client until it ends, the client is
/// detached as slow (then its watchers are told), or the client is gone;
/// then the connection is shut down.
fn write_out(stream: &UnixStream, output: &Output, hub: &PtyHub, id: ClientId, stall: Duration) {
    let fd = stream.as_raw_fd();
    loop {
        if output.end() == Some(End::Slow) {
            break;
        }
        match output.recv_timeout(STEP) {
            Ok(bytes) => match send_all(fd, &bytes, output, stall) {
                Ok(()) => {}
                Err(Halt::Slow) => {
                    hub.detach_slow(id);
                    break;
                }
                Err(Halt::Gone) => break,
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    // What is still queued for a slow client is dropped; its watchers hear
    // why before the stream ends.
    output.notify_detached();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Writes all of `bytes` to the socket `fd`, waiting for room in steps of
/// [`STEP`], without `SIGPIPE`. Gives up when the client is detached as
/// slow meanwhile, or takes nothing for `stall`, or is gone.
fn send_all(fd: RawFd, mut bytes: &[u8], output: &Output, stall: Duration) -> Result<(), Halt> {
    let mut last = Instant::now();
    while !bytes.is_empty() {
        if output.end() == Some(End::Slow) {
            return Err(Halt::Slow);
        }
        if last.elapsed() >= stall {
            return Err(Halt::Slow);
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let wait = stall.saturating_sub(last.elapsed()).min(STEP);
        let ms =
            libc::c_int::try_from(wait.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX);
        // SAFETY: poll reads and writes the one pollfd it is given.
        if unsafe { libc::poll(&mut pollfd, 1, ms) } <= 0 {
            continue;
        }
        // SAFETY: sends at most `bytes.len()` bytes from `bytes`.
        let n = unsafe {
            libc::send(
                fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        match usize::try_from(n) {
            Ok(0) => return Err(Halt::Gone),
            Ok(n) => {
                bytes = &bytes[n..];
                last = Instant::now();
            }
            Err(_) => {
                let error = io::Error::last_os_error();
                if !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    return Err(Halt::Gone);
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
