// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The transitional PTY relay: the service on vsock port 1025
//! (`boxcar.pty`) that `boxcar run` registers, which copies the session's
//! terminal to its own stdout and, for an interactive run, its stdin to the
//! session.
//!
//! **Replaced by Task 12's PTY hub** (`crate::pty`), which keeps a
//! scrollback, serves `boxcar attach` clients over the control socket, and
//! forwards resizes; nothing else depends on this module, and the hub takes
//! its place at the same port with the same [`register`] call shape.
//!
//! Init connects once its session's PTY is open, from guest port 1022, and
//! sends one header line, `{"v":1,"session":"main","rows":R,"cols":C}`
//! ([`PtyHeader`]); the stream is then the terminal's bytes both ways. The
//! relay takes one connection in the VMM's life (a later one, after the
//! guest re-activated its vsock driver, is refused as `reactivated`; one
//! that came while the relay could not be set up is refused as
//! `no_service`, and the next may still be taken). It writes what the
//! session prints to its output as it comes, and once the guest closes its
//! side (init does after the session ends and the PTY is drained), flushes
//! the output and closes its own side: init waits for that before it
//! reboots, so the session's last line is written before the VM stops.
//!
//! Every byte the guest sends is written out, in order. A write the output
//! cannot take yet (`EAGAIN` from a non-blocking pipe or terminal, or a
//! full blocking one) is waited on, never dropped; meanwhile the relay
//! reads nothing more from the stream, so the guest's side fills and init
//! stops reading the session's PTY. Only an output that fails for good (its
//! reader is gone) is given up on; the rest of the stream is then read and
//! dropped, so the guest never blocks on it. [`RelayHandle::wait`] lets
//! `boxcar run` finish writing what the relay holds before it exits.
//!
//! Input ([`RelayInput`]), when there is any, goes to the session as it is
//! read. From a terminal (which `boxcar run` puts in raw mode, as M1's
//! console does) Ctrl-] twice within a second stops the VM instead, as on
//! the console; from a pipe or a file, its end becomes end-of-file
//! characters (`^D`, two when the input did not end a line), so a shell
//! reading it ends.
//!
//! Nothing here is on the stop path; its threads end when the stream does.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use boxcar_proto::guest::{decode, LineBuf, PtyHeader, MAX_PTY_HEADER};
use boxcar_vsock::services::PTY_PORT;
use boxcar_vsock::{ConnMeta, Deny};

use crate::guest_ctl::REACTIVATED;
use crate::lifecycle::{StopReason, VmmHandle};
use crate::services::{RegisterError, ServiceRegistry};
use crate::stdin::{stdin_is_tty, EscapeDetector};

/// Bytes moved at a time.
const CHUNK: usize = 16 * 1024;

/// End-of-file, as a terminal in canonical mode reads it (`VEOF`).
const EOF_CHAR: u8 = 0x04;

/// How long an output with no descriptor to wait on is left before a write
/// it would not take is tried again.
const WOULD_BLOCK_RETRY: Duration = Duration::from_millis(2);

/// The longest single wait for the output to take more; the wait goes on
/// after it.
const POLL_STEP: Duration = Duration::from_millis(500);

/// What the relay forwards to the session.
pub struct RelayInput {
    /// Read until its end.
    pub reader: Box<dyn Read + Send>,
    /// It is a terminal: watch for the escape, and send nothing at its end.
    pub tty: bool,
}

impl RelayInput {
    /// The process's stdin, read through a descriptor of its own (std's
    /// lock and buffer stay out of it).
    pub fn stdin() -> io::Result<RelayInput> {
        let fd = io::stdin().as_fd().try_clone_to_owned()?;
        Ok(RelayInput {
            reader: Box::new(File::from(fd)),
            tty: stdin_is_tty(),
        })
    }
}

/// Where the session's terminal goes.
pub struct RelayOutput {
    writer: Box<dyn Write + Send>,
    /// The writer's descriptor, to wait on when it would block.
    fd: Option<RawFd>,
}

impl RelayOutput {
    /// A file, pipe or terminal: a write it cannot take yet is waited on
    /// with `poll`.
    pub fn file(file: File) -> RelayOutput {
        let fd = Some(file.as_raw_fd());
        RelayOutput {
            writer: Box::new(file),
            fd,
        }
    }

    /// Any writer: a write it cannot take yet (`WouldBlock`) is tried again
    /// a little later.
    pub fn writer(writer: impl Write + Send + 'static) -> RelayOutput {
        RelayOutput {
            writer: Box::new(writer),
            fd: None,
        }
    }

    /// The process's stdout, written through a descriptor of its own, as
    /// the console writes it.
    pub fn stdout() -> io::Result<RelayOutput> {
        let fd = io::stdout().as_fd().try_clone_to_owned()?;
        Ok(RelayOutput::file(File::from(fd)))
    }

    /// Writes all of `bytes`, waiting while the output cannot take them, and
    /// counts each byte taken in `written`. Fails only when the output fails
    /// for good.
    fn write_all(&mut self, mut bytes: &[u8], written: &AtomicU64) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.writer.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    bytes = &bytes[n..];
                    written.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait_writable(),
                Err(error) => return Err(error),
            }
        }
        loop {
            match self.writer.flush() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait_writable(),
                done => return done,
            }
        }
    }

    /// Waits until the output may take more (or fails, which the next write
    /// says).
    fn wait_writable(&self) {
        let Some(fd) = self.fd else {
            thread::sleep(WOULD_BLOCK_RETRY);
            return;
        };
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = libc::c_int::try_from(POLL_STEP.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: poll reads and writes the one pollfd it is given.
        unsafe { libc::poll(&mut pollfd, 1, ms) };
    }
}

/// How far the relay is: shared by its thread and [`RelayHandle`].
#[derive(Default)]
struct Progress {
    /// The guest's terminal was taken.
    connected: AtomicBool,
    /// Bytes the output took.
    written: AtomicU64,
    /// The stream ended and everything is written (or the output failed).
    done: AtomicBool,
}

/// Lets the caller wait for the relay to have written out what it holds.
#[derive(Clone)]
pub struct RelayHandle {
    progress: Arc<Progress>,
}

impl RelayHandle {
    /// Waits until the relay has written everything the guest sent, for as
    /// long as the output keeps taking bytes: it gives up once `idle` passes
    /// with none taken. Returns at once when the guest never connected, and
    /// returns whether the relay is done. `boxcar run` calls it once the VM
    /// has stopped, before it exits.
    pub fn wait(&self, idle: Duration) -> bool {
        let progress = &self.progress;
        if !progress.connected.load(Ordering::Acquire) {
            return true;
        }
        let mut written = progress.written.load(Ordering::Relaxed);
        let mut deadline = Instant::now() + idle;
        loop {
            if progress.done.load(Ordering::Acquire) {
                return true;
            }
            let now = Instant::now();
            let seen = progress.written.load(Ordering::Relaxed);
            if seen != written {
                written = seen;
                deadline = now + idle;
            } else if now >= deadline {
                return false;
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(10)),
            );
        }
    }
}

/// What the one connection gets.
struct Parts {
    out: RelayOutput,
    input: Option<RelayInput>,
    handle: VmmHandle,
}

/// The relay's service.
struct Relay {
    /// Until a connection takes them.
    parts: Arc<Mutex<Option<Parts>>>,
    /// Set once a connection took them: every later one is `reactivated`.
    taken: AtomicBool,
    progress: Arc<Progress>,
}

impl Relay {
    /// A guest connection to 1025: the relay on a new stream pair from
    /// `pair` the first time, `reactivated` after; `no_service`, leaving the
    /// next connection free, when the relay cannot be set up.
    fn connect(
        &self,
        meta: ConnMeta,
        pair: impl FnOnce() -> io::Result<(UnixStream, UnixStream)>,
    ) -> Result<UnixStream, Deny> {
        if self.taken.load(Ordering::Acquire) {
            boxcar_virtio::limited!(
                warn,
                "pty relay: refused a connection from guest port {}: the session's was taken \
                 already",
                meta.guest_port
            );
            return Err(Deny::Refused(REACTIVATED));
        }
        let refused = |error: io::Error| {
            boxcar_virtio::limited!(
                warn,
                "pty relay: cannot take the session's terminal from guest port {}: {error}",
                meta.guest_port
            );
            Deny::NoService
        };
        let (ours, theirs) = pair().map_err(refused)?;
        // The thread takes the parts once it runs: a thread that cannot be
        // started leaves them for the next connection.
        let parts = Arc::clone(&self.parts);
        let progress = Arc::clone(&self.progress);
        thread::Builder::new()
            .name("pty-relay-out".into())
            .spawn(move || {
                let taken = parts.lock().unwrap_or_else(PoisonError::into_inner).take();
                if let Some(parts) = taken {
                    relay(theirs, parts, &progress);
                }
                progress.done.store(true, Ordering::Release);
            })
            .map_err(refused)?;
        self.taken.store(true, Ordering::Release);
        self.progress.connected.store(true, Ordering::Release);
        Ok(ours)
    }
}

/// Registers the relay at port 1025 of `services`: the session's terminal
/// goes to `out`, and `input`, if any, to the session; `handle` stops the
/// VM on the escape. The handle returned waits for the output.
pub fn register(
    services: &ServiceRegistry,
    out: RelayOutput,
    input: Option<RelayInput>,
    handle: VmmHandle,
) -> Result<RelayHandle, RegisterError> {
    let progress = Arc::new(Progress::default());
    let relay = Relay {
        parts: Arc::new(Mutex::new(Some(Parts { out, input, handle }))),
        taken: AtomicBool::new(false),
        progress: Arc::clone(&progress),
    };
    services.register(
        PTY_PORT,
        Arc::new(move |meta| relay.connect(meta, UnixStream::pair)),
    )?;
    Ok(RelayHandle { progress })
}

/// The output side: the header, then the session's bytes to the output
/// until the guest closes; then the relay's own side closes.
fn relay(mut stream: UnixStream, parts: Parts, progress: &Progress) {
    let Parts {
        mut out,
        input,
        handle,
    } = parts;
    let Some(rest) = read_header(&mut stream) else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    if let Some(input) = input {
        match stream.try_clone() {
            Ok(to_guest) => {
                let spawned = thread::Builder::new()
                    .name("pty-relay-in".into())
                    .spawn(move || forward_input(to_guest, input, &handle));
                if let Err(error) = spawned {
                    boxcar_virtio::limited!(warn, "pty relay: no input to the session: {error}");
                }
            }
            Err(error) => {
                boxcar_virtio::limited!(warn, "pty relay: no input to the session: {error}")
            }
        }
    }
    let mut writing = write_out(&mut out, &rest, progress);
    let mut buf = vec![0u8; CHUNK];
    loop {
        // While the output is not taking the last chunk, nothing more is
        // read: the guest's side fills, and the session blocks on its tty.
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) if writing => writing = write_out(&mut out, &buf[..n], progress),
            // An output that failed for good: the rest is read and dropped,
            // so the guest never blocks on it.
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    // Everything is written: init may reboot.
    let _ = stream.shutdown(Shutdown::Write);
}

/// Reads the header line; returns what came after it, or `None` (with a
/// warning) when the stream does not start with one.
fn read_header(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut lines = LineBuf::new(MAX_PTY_HEADER);
    let mut buf = [0u8; 512];
    let line = loop {
        if let Some(line) = lines.next_line() {
            break line;
        }
        match stream.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => {
                if lines.push(&buf[..n]).is_err() {
                    boxcar_virtio::limited!(warn, "pty relay: no header line; closing");
                    return None;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    };
    match decode::<PtyHeader>(&line) {
        Ok(header) if header.v == 1 => {
            tracing::debug!(
                "pty relay: session {:?}, {} by {}",
                header.session,
                header.rows,
                header.cols
            );
            Some(lines.take_rest())
        }
        Ok(header) => {
            boxcar_virtio::limited!(warn, "pty relay: header version {}; closing", header.v);
            None
        }
        Err(error) => {
            boxcar_virtio::limited!(warn, "pty relay: a bad header line: {error}; closing");
            None
        }
    }
}

/// Writes all of `bytes`, waiting for the output as long as it takes;
/// returns whether the output still takes them.
fn write_out(out: &mut RelayOutput, bytes: &[u8], progress: &Progress) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match out.write_all(bytes, &progress.written) {
        Ok(()) => true,
        Err(error) => {
            boxcar_virtio::limited!(
                warn,
                "pty relay: cannot write the session's output, dropping the rest: {error}"
            );
            false
        }
    }
}

/// The input side: what is read goes to the session; see the module docs.
fn forward_input(mut to_guest: UnixStream, mut input: RelayInput, handle: &VmmHandle) {
    let mut escape = EscapeDetector::default();
    let mut last = None;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match input.reader.read(&mut buf) {
            Ok(0) => {
                if !input.tty {
                    let eof: &[u8] = match last {
                        Some(b'\n') | None => &[EOF_CHAR],
                        Some(_) => &[EOF_CHAR, EOF_CHAR],
                    };
                    let _ = to_guest.write_all(eof);
                }
                return;
            }
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let bytes = &buf[..n];
        if input.tty && escape.feed(bytes, Instant::now()) {
            handle.request_stop(StopReason::ConsoleEscape);
            return;
        }
        if to_guest.write_all(bytes).is_err() {
            return;
        }
        last = bytes.last().copied();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use boxcar_vsock::{ConnMeta, Deny, InternalServices};

    use super::*;
    use crate::lifecycle::{test_handle, VmState};
    use crate::services::ServiceRegistry;

    const LIMIT: Duration = Duration::from_secs(5);

    /// An output that keeps what it is given.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn guest(registry: &ServiceRegistry) -> UnixStream {
        let stream = registry
            .connect(1025, ConnMeta { guest_port: 1022 })
            .unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        stream
    }

    #[test]
    fn the_header_then_the_session_bytes_reach_the_output() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let registry = ServiceRegistry::new();
        let out = Shared::default();
        register(&registry, RelayOutput::writer(out.clone()), None, handle).unwrap();

        let mut stream = guest(&registry);
        stream
            .write_all(b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\nhi\r\n")
            .unwrap();
        stream.write_all(b"\x1b[1mbold\x1b[0m $ ").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        // The relay closes its side once it has written everything: what
        // init waits for before it reboots.
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        assert_eq!(
            out.0.lock().unwrap().as_slice(),
            b"hi\r\n\x1b[1mbold\x1b[0m $ "
        );
        // One connection a VMM life.
        assert!(matches!(
            registry.connect(1025, ConnMeta { guest_port: 1022 }),
            Err(Deny::Refused("reactivated"))
        ));
        writer.close().unwrap();
    }

    #[test]
    fn a_stream_without_a_header_line_is_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let registry = ServiceRegistry::new();
        let out = Shared::default();
        register(&registry, RelayOutput::writer(out.clone()), None, handle).unwrap();
        let mut stream = guest(&registry);
        stream.write_all(b"not a header\nhi").unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert!(out.0.lock().unwrap().is_empty());
        writer.close().unwrap();
    }

    /// Piped input goes to the session as it is, then an end-of-file
    /// character, so that a shell reading it ends.
    #[test]
    fn piped_input_reaches_the_session_then_an_eof_character() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let registry = ServiceRegistry::new();
        let input = RelayInput {
            reader: Box::new(Cursor::new(b"echo hi\nexit".to_vec())),
            tty: false,
        };
        register(
            &registry,
            RelayOutput::writer(Shared::default()),
            Some(input),
            handle,
        )
        .unwrap();
        let mut stream = guest(&registry);
        stream
            .write_all(b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n")
            .unwrap();
        let want = b"echo hi\nexit\x04\x04";
        let mut got = vec![0u8; want.len()];
        stream.read_exact(&mut got).unwrap();
        assert_eq!(got, want);
        writer.close().unwrap();
    }

    /// From a terminal, Ctrl-] twice stops the VM, as on the console, and
    /// does not reach the session.
    #[test]
    fn a_double_escape_from_a_terminal_stops_the_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let registry = ServiceRegistry::new();
        // Typed in two reads: a line, then the escape.
        struct Typed(Vec<&'static [u8]>);
        impl Read for Typed {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    // A terminal that stays open: nothing more, for a while.
                    std::thread::sleep(Duration::from_secs(1));
                    return Ok(0);
                }
                let next = self.0.remove(0);
                buf[..next.len()].copy_from_slice(next);
                Ok(next.len())
            }
        }
        let input = RelayInput {
            reader: Box::new(Typed(vec![b"ls\r", b"\x1d\x1d", b"after"])),
            tty: true,
        };
        register(
            &registry,
            RelayOutput::writer(Shared::default()),
            Some(input),
            handle.clone(),
        )
        .unwrap();
        let mut stream = guest(&registry);
        stream
            .write_all(b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n")
            .unwrap();
        // What came before the escape reached the session; the escape did
        // not.
        let mut got = [0u8; 3];
        stream.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ls\r");
        let deadline = Instant::now() + LIMIT;
        while handle.state() != VmState::Stopping {
            assert!(Instant::now() < deadline, "the escape did not stop the VM");
            std::thread::sleep(Duration::from_millis(5));
        }
        // The input side has ended: nothing more reaches the session.
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut more = [0u8; 1];
        assert!(stream.read(&mut more).is_err(), "{more:?}");
        writer.close().unwrap();
    }

    /// A pipe, its write end non-blocking and its buffer one page.
    fn small_non_blocking_pipe() -> (File, File) {
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both are new descriptors that nothing else owns.
        let (read, write) = unsafe {
            (
                <File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]),
                <File as std::os::fd::FromRawFd>::from_raw_fd(fds[1]),
            )
        };
        // SAFETY: fcntl with integer arguments only.
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 4096);
            let flags = libc::fcntl(fds[1], libc::F_GETFL);
            assert_eq!(
                libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
        }
        (read, write)
    }

    /// The reviewer's probe as a test: a non-blocking stdout (`EAGAIN`
    /// once full) read slowly gets every byte the session wrote, in order;
    /// meanwhile the relay reads nothing more from the stream, so the
    /// guest's writes wait.
    #[test]
    fn a_non_blocking_output_read_slowly_gets_every_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let registry = ServiceRegistry::new();
        let (mut read_end, write_end) = small_non_blocking_pipe();
        let relay = register(&registry, RelayOutput::file(write_end), None, handle).unwrap();

        let mut payload: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        payload.extend_from_slice(b"END_OF_OUTPUT");
        let stream = guest(&registry);
        let mut to_relay = stream.try_clone().unwrap();
        let sent = payload.clone();
        let guest_side = std::thread::spawn(move || {
            to_relay
                .write_all(b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n")
                .unwrap();
            to_relay.write_all(&sent).unwrap();
            to_relay.shutdown(std::net::Shutdown::Write).unwrap();
        });
        // A slow reader: 1 KiB at a time, a pause between.
        let reader = std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match read_end.read(&mut buf) {
                    Ok(0) => return got,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) => panic!("{e}"),
                }
                std::thread::sleep(Duration::from_micros(500));
            }
        });
        guest_side.join().unwrap();
        assert!(relay.wait(LIMIT), "the relay did not finish");
        let got = reader.join().unwrap();
        assert_eq!(got.len(), payload.len());
        assert!(got == payload, "the bytes came out of order");
        // And the relay closed its side once it had written them.
        let mut rest = Vec::new();
        let mut stream = stream;
        stream.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        writer.close().unwrap();
    }

    /// An output whose reader is gone fails for good: the rest of the stream
    /// is read and dropped, so the guest never blocks, and the relay ends.
    #[test]
    fn an_output_whose_reader_left_does_not_block_the_guest() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let registry = ServiceRegistry::new();
        let (read_end, write_end) = small_non_blocking_pipe();
        drop(read_end);
        let relay = register(&registry, RelayOutput::file(write_end), None, handle).unwrap();
        let mut stream = guest(&registry);
        stream
            .write_all(b"{\"v\":1,\"session\":\"main\",\"rows\":24,\"cols\":80}\n")
            .unwrap();
        stream.write_all(&vec![b'x'; 1 << 20]).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(relay.wait(LIMIT));
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        writer.close().unwrap();
    }

    /// A connection that came while the relay could not be set up is
    /// refused as `no_service`, and the next is taken; only after that is
    /// one `reactivated`.
    #[test]
    fn a_failed_setup_leaves_the_port_to_the_next_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let progress = Arc::new(Progress::default());
        let relay = Relay {
            parts: Arc::new(Mutex::new(Some(Parts {
                out: RelayOutput::writer(Shared::default()),
                input: None,
                handle,
            }))),
            taken: AtomicBool::new(false),
            progress: Arc::clone(&progress),
        };
        let meta = ConnMeta { guest_port: 1022 };
        let no_fds = || Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        assert_eq!(relay.connect(meta, no_fds).err(), Some(Deny::NoService));
        assert!(!progress.connected.load(Ordering::Acquire));
        // Nothing connected: nothing to wait for.
        assert!(RelayHandle {
            progress: Arc::clone(&progress)
        }
        .wait(Duration::ZERO));
        let stream = relay.connect(meta, UnixStream::pair).unwrap();
        assert!(progress.connected.load(Ordering::Acquire));
        assert_eq!(
            relay.connect(meta, UnixStream::pair).err(),
            Some(Deny::Refused("reactivated"))
        );
        drop(stream);
        writer.close().unwrap();
    }
}
