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
//! guest re-activated its vsock driver, is refused as `reactivated`). It
//! writes what the session prints to its output as it comes, and once the
//! guest closes its side (init does after the session ends and the PTY is
//! drained), flushes the output and closes its own side: init waits for
//! that before it reboots, so the session's last line is written before
//! the VM stops.
//!
//! Input ([`RelayInput`]), when there is any, goes to the session as it is
//! read. From a terminal (which `boxcar run` puts in raw mode, as M1's
//! console does) Ctrl-] twice within a second stops the VM instead, as on
//! the console; from a pipe or a file, its end becomes end-of-file
//! characters (`^D`, two when the input did not end a line), so a shell
//! reading it ends.
//!
//! The output is written with blocking writes: a host stdout that stalls
//! stops the relay reading the stream, which stops init reading the PTY,
//! which blocks the session on its terminal. Nothing here is on the stop
//! path; its threads end when the stream does.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Instant;

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

/// The process's stdout, written unbuffered through a descriptor of its
/// own, as the console writes it.
pub fn stdout() -> io::Result<Box<dyn Write + Send>> {
    let fd = io::stdout().as_fd().try_clone_to_owned()?;
    Ok(Box::new(File::from(fd)))
}

/// What the one connection gets.
struct Parts {
    out: Box<dyn Write + Send>,
    input: Option<RelayInput>,
    handle: VmmHandle,
}

/// Registers the relay at port 1025 of `services`: the session's terminal
/// goes to `out`, and `input`, if any, to the session; `handle` stops the
/// VM on the escape.
pub fn register(
    services: &ServiceRegistry,
    out: Box<dyn Write + Send>,
    input: Option<RelayInput>,
    handle: VmmHandle,
) -> Result<(), RegisterError> {
    let parts = Mutex::new(Some(Parts { out, input, handle }));
    services.register(
        PTY_PORT,
        Arc::new(move |meta| {
            let taken = parts.lock().unwrap_or_else(PoisonError::into_inner).take();
            match taken {
                Some(parts) => open(parts, meta),
                None => {
                    boxcar_virtio::limited!(
                        warn,
                        "pty relay: refused a connection from guest port {}: the session's \
                         was taken already",
                        meta.guest_port
                    );
                    Err(Deny::Refused(REACTIVATED))
                }
            }
        }),
    )
}

/// Starts the relay on a new stream pair; returns the vsock device's end.
fn open(parts: Parts, meta: ConnMeta) -> Result<UnixStream, Deny> {
    let pair = UnixStream::pair().and_then(|(ours, theirs)| {
        thread::Builder::new()
            .name("pty-relay-out".into())
            .spawn(move || relay(theirs, parts))
            .map(|_| ours)
    });
    pair.map_err(|error| {
        boxcar_virtio::limited!(
            warn,
            "pty relay: cannot take the session's terminal from guest port {}: {error}",
            meta.guest_port
        );
        Deny::NoService
    })
}

/// The output side: the header, then the session's bytes to the output
/// until the guest closes; then the relay's own side closes.
fn relay(mut stream: UnixStream, parts: Parts) {
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
    let mut writing = write_out(&mut out, &rest);
    let mut buf = vec![0u8; CHUNK];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            // A stdout that is gone loses the rest, which is still read: the
            // guest must not block on it.
            Ok(n) if writing => writing = write_out(&mut out, &buf[..n]),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = out.flush();
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

/// Writes `bytes` and flushes; returns whether the output still takes them.
fn write_out(out: &mut Box<dyn Write + Send>, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(error) => {
            boxcar_virtio::limited!(
                warn,
                "pty relay: cannot write the session's output: {error}"
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
        register(&registry, Box::new(out.clone()), None, handle).unwrap();

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
        register(&registry, Box::new(out.clone()), None, handle).unwrap();
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
        register(&registry, Box::new(Shared::default()), Some(input), handle).unwrap();
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
            Box::new(Shared::default()),
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
}
