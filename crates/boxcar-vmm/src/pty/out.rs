// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session's terminal to a host output: `boxcar run`'s stdout, a
//! client of the hub in the same process ([`spawn`]).
//!
//! A thread takes the client's [`Output`] and writes it to the [`Target`]
//! in order, at most [`WRITE_PIECE`] (4 KiB, `PIPE_BUF`) at a time. Before
//! each write it waits (`poll`, in [`POLL_STEP`]s) for the target to take
//! more, and it waits again on `EAGAIN` (a non-blocking stdout): it never
//! sits inside a write a stalled reader holds up, so it can always be
//! stopped ([`OutHandle::stop`]); a socket is written with `MSG_DONTWAIT`.
//! Only a target that fails for good (its reader is gone) ends the
//! writing; the writer then lets its output go, and the hub forgets it.
//!
//! The writer is the hub's primary client ([`PtyHub::attach_primary`]):
//! while it is behind, the hub holds the session back, so it is never
//! detached and nothing is skipped for it.
//!
//! [`Target::write_until`] is the same piecewise, stoppable write, for a
//! caller that writes on its own thread (`boxcar attach`).
//!
//! Once the VM has stopped, `boxcar run` waits for the writer to finish
//! ([`OutHandle::wait_with`]) for as long as stdout keeps taking bytes: a
//! byte written, and a byte stdout's reader takes from its queue, both
//! count, so a reader however slow is seen. The queue is measured on a copy
//! of the target's descriptor: `FIONREAD` on a pipe, the send queue on a
//! socket (`SIOCOUTQ`; `FIONREAD` there is the receive queue) and the output
//! queue on a terminal (`TIOCOUTQ`). The wait gives up after an idle
//! limit with no progress, at a cap, or when asked to; the writer is then
//! stopped and what was not delivered is counted exactly, after it stopped.
//! The copies of the descriptor go once the writer is done, so a pipe's
//! reader sees its end.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::{Output, Totals};

#[cfg(doc)]
use super::PtyHub;

/// The most bytes given to one `write`: `PIPE_BUF`. A pipe that polls
/// writable takes a write this size whole, and a smaller write shows
/// progress sooner.
pub const WRITE_PIECE: usize = 4096;

/// The longest single wait for the target to take more, or for the next
/// piece of output; the writer looks at its stop flag between them.
pub const POLL_STEP: Duration = Duration::from_millis(50);

/// How long a target with no descriptor to wait on is left before a write
/// it would not take is tried again.
const WOULD_BLOCK_RETRY: Duration = Duration::from_millis(2);

/// How often [`OutHandle::wait_with`] looks at the writer's progress.
const WAIT_STEP: Duration = Duration::from_millis(10);

/// `SIOCOUTQ` (linux/sockios.h): a socket's unsent bytes. The same number
/// as `TIOCOUTQ`, which the libc crate has.
const SIOCOUTQ: libc::Ioctl = libc::TIOCOUTQ;

/// How a target's queue is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueueKind {
    /// A pipe: `FIONREAD`, the bytes in it.
    Pipe,
    /// A socket: `SIOCOUTQ`, its send queue.
    Socket,
    /// A terminal: `TIOCOUTQ`, its output queue.
    Tty,
    /// Anything else (a file): no queue.
    None,
}

impl QueueKind {
    /// The kind of `fd`.
    pub(crate) fn of(fd: RawFd) -> QueueKind {
        // SAFETY: stat is plain data; all zeroes is valid.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes one stat into `stat`, alive for the call.
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return QueueKind::None;
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFIFO => QueueKind::Pipe,
            libc::S_IFSOCK => QueueKind::Socket,
            // SAFETY: isatty has no preconditions.
            libc::S_IFCHR if unsafe { libc::isatty(fd) } == 1 => QueueKind::Tty,
            _ => QueueKind::None,
        }
    }
}

/// The bytes waiting in `fd`'s queue for its reader, measured as `kind`
/// says, or `None` when there is no queue to measure.
pub(crate) fn queued(fd: RawFd, kind: QueueKind) -> Option<u64> {
    let request = match kind {
        QueueKind::Pipe => libc::FIONREAD,
        QueueKind::Socket => SIOCOUTQ,
        QueueKind::Tty => libc::TIOCOUTQ,
        QueueKind::None => return None,
    };
    let mut len: libc::c_int = 0;
    // SAFETY: each request stores one int through the pointer, which
    // points at `len`, alive for the call.
    let rc = unsafe { libc::ioctl(fd, request, &mut len) };
    if rc == 0 {
        u64::try_from(len).ok()
    } else {
        None
    }
}

/// Where the session's terminal goes.
pub struct Target {
    writer: Box<dyn Write + Send>,
    /// The writer's descriptor, to wait on.
    fd: Option<RawFd>,
    kind: QueueKind,
}

impl Target {
    /// A file, pipe, socket or terminal.
    pub fn file(file: File) -> Target {
        let fd = file.as_raw_fd();
        Target {
            writer: Box::new(file),
            fd: Some(fd),
            kind: QueueKind::of(fd),
        }
    }

    /// Any writer: a write it does not take (`WouldBlock`) is tried again a
    /// little later.
    pub fn writer(writer: impl Write + Send + 'static) -> Target {
        Target {
            writer: Box::new(writer),
            fd: None,
            kind: QueueKind::None,
        }
    }

    /// The process's stdout, written through a descriptor of its own.
    pub fn stdout() -> io::Result<Target> {
        let fd = io::stdout().as_fd().try_clone_to_owned()?;
        Ok(Target::file(File::from(fd)))
    }

    /// Waits up to [`POLL_STEP`] for the target to take more; true when it
    /// may (or failed, which the write then says).
    fn writable(&self) -> bool {
        let Some(fd) = self.fd else {
            return true;
        };
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = libc::c_int::try_from(POLL_STEP.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: poll reads and writes the one pollfd it is given.
        unsafe { libc::poll(&mut pollfd, 1, ms) > 0 }
    }

    fn write(&mut self, piece: &[u8]) -> io::Result<usize> {
        match (self.kind, self.fd) {
            (QueueKind::Socket, Some(fd)) => {
                // SAFETY: sends at most `piece.len()` bytes from `piece`.
                let n = unsafe {
                    libc::send(
                        fd,
                        piece.as_ptr().cast(),
                        piece.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                usize::try_from(n).map_err(|_| io::Error::last_os_error())
            }
            _ => self.writer.write(piece),
        }
    }

    /// Writes all of `bytes` as the writer's thread does: at most
    /// [`WRITE_PIECE`] at a time, each after a poll for room in
    /// [`POLL_STEP`]s, and again on `EAGAIN`, so it never sits in a write
    /// a stalled reader holds up. `Ok(true)` once written, `Ok(false)` as
    /// soon as `stop` is set (looked at between the steps), and an error
    /// when the target fails for good.
    pub fn write_until(&mut self, bytes: &[u8], stop: &AtomicBool) -> io::Result<bool> {
        let written = AtomicU64::new(0);
        match self.put(bytes, stop, &written) {
            Ok(()) => Ok(true),
            Err(Halt::Stopped) => Ok(false),
            Err(Halt::Failed(error)) => Err(error),
        }
    }

    /// Writes all of `bytes` (see [`Target::write_until`]), counting each
    /// byte taken in `written`.
    fn put(
        &mut self,
        mut bytes: &[u8],
        stop: &AtomicBool,
        written: &AtomicU64,
    ) -> Result<(), Halt> {
        while !bytes.is_empty() {
            if stop.load(Ordering::Acquire) {
                return Err(Halt::Stopped);
            }
            if !self.writable() {
                continue;
            }
            let piece = &bytes[..bytes.len().min(WRITE_PIECE)];
            match self.write(piece) {
                Ok(0) => return Err(Halt::Failed(io::ErrorKind::WriteZero.into())),
                Ok(n) => {
                    bytes = &bytes[n..];
                    written.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.fd.is_none() {
                        thread::sleep(WOULD_BLOCK_RETRY);
                    }
                }
                Err(error) => return Err(Halt::Failed(error)),
            }
        }
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(Halt::Stopped);
            }
            match self.writer.flush() {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(WOULD_BLOCK_RETRY);
                }
                Err(error) => return Err(Halt::Failed(error)),
            }
        }
    }
}

/// How a write ended early.
enum Halt {
    /// It was asked to stop.
    Stopped,
    /// The target failed for good.
    Failed(io::Error),
}

/// How the writer's thread ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Finish {
    /// The output ended and everything it had is written.
    Done,
    /// The target failed for good.
    Failed,
    /// It was asked to stop.
    Stopped,
}

/// How far the writer is: shared by its thread and its handle.
struct Progress {
    /// Bytes the target took.
    written: AtomicU64,
    stop: AtomicBool,
    finished: Mutex<Option<Finish>>,
    finished_changed: Condvar,
    /// A copy of the target's descriptor, to see its reader take bytes; let
    /// go once the writer is done (a pipe's reader sees its end only when
    /// every writer has closed).
    queue: Mutex<Option<(OwnedFd, QueueKind)>>,
}

impl Progress {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn finished(&self) -> Option<Finish> {
        *self.lock_finished()
    }

    fn lock_finished(&self) -> MutexGuard<'_, Option<Finish>> {
        self.finished.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_queue(&self) -> MutexGuard<'_, Option<(OwnedFd, QueueKind)>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How [`OutHandle::wait_with`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutWait {
    /// The session's output ended and all of it the writer got is written
    /// (or the guest never opened the terminal).
    Done,
    /// The target failed for good: its reader is gone.
    Failed,
    /// The target took nothing for the idle time.
    Stalled,
    /// The wait reached its cap.
    Capped,
    /// The caller asked it to stop (a second stop signal), or the writer
    /// was stopped.
    Stopped,
}

/// What the wait does at `now`: it started at `start` and the target last
/// took a byte at `progress`; it goes on (until the time returned, at the
/// latest) while `idle` has not passed since `progress` and `cap` has not
/// passed since `start`.
pub fn wait_step(
    now: Instant,
    start: Instant,
    progress: Instant,
    idle: Duration,
    cap: Duration,
) -> Result<Instant, OutWait> {
    let stall = progress.max(start).checked_add(idle);
    let end = start.checked_add(cap);
    if end.is_some_and(|end| now >= end) {
        Err(OutWait::Capped)
    } else if stall.is_some_and(|stall| now >= stall) {
        Err(OutWait::Stalled)
    } else {
        Ok(match (stall, end) {
            (Some(stall), Some(end)) => stall.min(end),
            (Some(at), None) | (None, Some(at)) => at,
            (None, None) => now + WAIT_STEP,
        })
    }
}

/// The writer, seen from outside: wait for it, stop it, count.
pub struct OutHandle {
    progress: Arc<Progress>,
    /// Where in the session's output the writer started.
    start: u64,
    totals: Arc<Totals>,
}

/// Starts writing `output` (the hub's primary client's, as `boxcar run`
/// attaches it) to `target`.
pub fn spawn(output: Output, target: Target) -> io::Result<OutHandle> {
    let queue = target.fd.and_then(|fd| {
        // SAFETY: `fd` is the descriptor `target` owns, open until it is
        // dropped; it is only duplicated here.
        let copy = unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .ok()?;
        Some((copy, target.kind))
    });
    let progress = Arc::new(Progress {
        written: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        finished: Mutex::new(None),
        finished_changed: Condvar::new(),
        queue: Mutex::new(queue),
    });
    let handle = OutHandle {
        progress: Arc::clone(&progress),
        start: output.start(),
        totals: Arc::clone(&output.client.totals),
    };
    thread::Builder::new()
        .name("pty-stdout".into())
        .spawn(move || {
            // The target goes with `write_out`'s return.
            let finish = write_out(&output, target, &progress);
            *progress.lock_queue() = None;
            *progress.lock_finished() = Some(finish);
            progress.finished_changed.notify_all();
        })?;
    Ok(handle)
}

/// The writer's thread: each piece of the output to the target until the
/// output ends, the target fails, or the writer is asked to stop.
fn write_out(output: &Output, mut target: Target, progress: &Progress) -> Finish {
    loop {
        if progress.stopping() {
            return Finish::Stopped;
        }
        match output.recv_timeout(POLL_STEP) {
            Ok(bytes) => match target.put(&bytes, &progress.stop, &progress.written) {
                Ok(()) => {}
                Err(Halt::Stopped) => return Finish::Stopped,
                Err(Halt::Failed(_)) => return Finish::Failed,
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Finish::Done,
        }
    }
}

impl OutHandle {
    /// [`OutHandle::wait_with`] with no cap and nothing to stop it.
    pub fn wait(&self, idle: Duration) -> OutWait {
        self.wait_with(idle, Duration::MAX, || false)
    }

    /// Waits until the writer has written everything the session printed
    /// (the session's output ended), for as long as the target keeps taking
    /// bytes: it gives up once `idle` passes with none taken (written to
    /// it, or taken by its reader from its queue), once `cap` has passed,
    /// or as soon as `stop` says so (asked every few milliseconds).
    /// `boxcar run` calls it once the VM has stopped, when the stop
    /// sequence has closed the hub, so the output has ended (at once when
    /// the guest never opened the terminal); then [`OutHandle::stop`], then
    /// [`OutHandle::undelivered`].
    pub fn wait_with(
        &self,
        idle: Duration,
        cap: Duration,
        mut stop: impl FnMut() -> bool,
    ) -> OutWait {
        let progress = &self.progress;
        let start = Instant::now();
        let mut last = start;
        let mut written = self.written();
        let mut queued = self.queued();
        loop {
            match progress.finished() {
                Some(Finish::Done) => return OutWait::Done,
                Some(Finish::Failed) => return OutWait::Failed,
                Some(Finish::Stopped) => return OutWait::Stopped,
                None => {}
            }
            if stop() {
                return OutWait::Stopped;
            }
            let now = Instant::now();
            let seen = self.written();
            let queue = self.queued();
            // A byte written, or one the reader took from the queue.
            let drained = matches!((queued, queue), (Some(before), Some(after)) if after < before);
            if seen != written || drained {
                last = now;
            }
            written = seen;
            queued = queue;
            match wait_step(now, start, last, idle, cap) {
                Ok(until) => thread::sleep(until.saturating_duration_since(now).min(WAIT_STEP)),
                Err(ended) => return ended,
            }
        }
    }

    /// Asks the writer to stop, and waits up to `grace` for it to have;
    /// returns whether it has (or had finished). It stops within a
    /// [`POLL_STEP`] unless a write is in the kernel's hands, which only a
    /// terminal held mid-write keeps it in.
    pub fn stop(&self, grace: Duration) -> bool {
        let progress = &self.progress;
        progress.stop.store(true, Ordering::Release);
        let deadline = Instant::now() + grace;
        let mut finished = progress.lock_finished();
        while finished.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            finished = progress
                .finished_changed
                .wait_timeout(finished, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }

    /// Bytes the target has taken.
    pub fn written(&self) -> u64 {
        self.progress.written.load(Ordering::Relaxed)
    }

    /// Bytes of the session's output, from where the writer started, that
    /// the target has not taken: what the writer holds, and what came after
    /// it stopped. Exact once the writer has stopped (and the terminal
    /// ended); while a write is under way its bytes count as not delivered.
    pub fn undelivered(&self) -> u64 {
        let offered = self
            .totals
            .received
            .load(Ordering::Acquire)
            .saturating_sub(self.start);
        offered.saturating_sub(self.written())
    }

    /// The bytes waiting in the target for its reader, when it says.
    fn queued(&self) -> Option<u64> {
        let queue = self.progress.lock_queue();
        let (fd, kind) = queue.as_ref()?;
        queued(fd.as_raw_fd(), *kind)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::pty::testing::{pattern, wait_until, Fixture, LIMIT};
    use crate::pty::Mode;

    /// A pipe, its write end non-blocking and its buffer one page.
    fn small_non_blocking_pipe() -> (File, File) {
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both are new descriptors that nothing else owns.
        let (read, write) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
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

    /// A pipe of one page, blocking.
    fn small_pipe() -> (File, File) {
        let (read, write) = small_non_blocking_pipe();
        // SAFETY: fcntl with integer arguments only.
        unsafe {
            let fd = write.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFL);
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK), 0);
        }
        (read, write)
    }

    /// Reads `read_end` to its end, `step` bytes at a time with `pause`
    /// between.
    fn slow_reader(
        mut read_end: File,
        step: usize,
        pause: Duration,
    ) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = vec![0u8; step];
            loop {
                match read_end.read(&mut buf) {
                    Ok(0) => return got,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) => panic!("{e}"),
                }
                thread::sleep(pause);
            }
        })
    }

    /// The reviewer's probe as a test: a non-blocking stdout (`EAGAIN`
    /// once full) read slowly gets every byte the session wrote, in order,
    /// and its reader sees the end once the writer is done. The writer is
    /// the hub's primary client, as `boxcar run`'s is: 3 MB, three times
    /// its limit, is held back for it, never skipped.
    #[test]
    fn a_non_blocking_output_read_slowly_gets_every_byte() {
        let fixture = Fixture::new();
        let (read_end, write_end) = small_non_blocking_pipe();
        let (_, output, _) = fixture.hub.attach_primary(Mode::Ro).unwrap();
        let writer = spawn(output, Target::file(write_end)).unwrap();
        let mut printed = pattern(3_000_000);
        printed.extend_from_slice(b"END_OF_OUTPUT");
        let mut guest = fixture.guest();
        let sent = printed.clone();
        let session = thread::spawn(move || {
            guest.write_all(&sent).unwrap();
            guest.shutdown(Shutdown::Write).unwrap();
        });
        let reader = slow_reader(read_end, 16 * 1024, Duration::from_micros(500));
        session.join().unwrap();
        assert_eq!(writer.wait(LIMIT), OutWait::Done);
        let got = reader.join().unwrap();
        assert_eq!(got.len(), printed.len());
        assert!(got == printed, "the bytes came out of order");
        assert_eq!(writer.undelivered(), 0);
    }

    /// The re-review's probe as a test: a steady consumer of 5 KiB/s on a
    /// plain (blocking) pipe. A whole page takes it a long time, but every
    /// byte it takes from the pipe counts: the wait follows it to the end,
    /// and it gets everything.
    #[test]
    fn a_slow_steady_reader_keeps_the_wait_going_to_the_end() {
        const PAYLOAD: usize = 6 * 1024;
        let fixture = Fixture::new();
        let (read_end, write_end) = small_pipe();
        let (_, output, _) = fixture.hub.attach(Mode::Ro, 0);
        let writer = spawn(output, Target::file(write_end)).unwrap();
        let mut guest = fixture.guest();
        guest.write_all(&[b'z'; PAYLOAD]).unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        // 256 bytes every 50 ms: 5 KiB/s, about 1.2 s in all.
        let reader = slow_reader(read_end, 256, Duration::from_millis(50));
        // An idle limit far below a page's time at this pace (0.8 s).
        let ended = writer.wait_with(Duration::from_millis(300), LIMIT, || false);
        assert_eq!(ended, OutWait::Done);
        assert_eq!(writer.undelivered(), 0);
        assert_eq!(writer.written(), PAYLOAD as u64);
        assert_eq!(reader.join().unwrap().len(), PAYLOAD);
    }

    /// A reader that stops: the wait gives up after the idle time; once the
    /// writer has stopped, the count of what was not delivered is exact,
    /// and the pipe's reader sees the end after what was written.
    #[test]
    fn a_reader_that_stops_leaves_the_wait_stalled_with_the_exact_count() {
        const PAYLOAD: usize = 20 * 1024;
        let fixture = Fixture::new();
        let (mut read_end, write_end) = small_pipe();
        let (_, output, _) = fixture.hub.attach(Mode::Ro, 0);
        let writer = spawn(output, Target::file(write_end)).unwrap();
        let mut guest = fixture.guest();
        guest.write_all(&[b'z'; PAYLOAD]).unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        wait_until("all of it in", || fixture.hub.received() == PAYLOAD as u64);

        assert_eq!(writer.wait_with(LIMIT, LIMIT, || true), OutWait::Stopped);
        let started = Instant::now();
        let ended = writer.wait_with(Duration::from_millis(200), LIMIT, || false);
        assert_eq!(ended, OutWait::Stalled);
        assert!(started.elapsed() < Duration::from_secs(2));
        // The writer never waits inside a write: it stops at once.
        assert!(writer.stop(Duration::from_secs(1)));
        let written = writer.written();
        assert!(written > 0 && written <= 4096, "{written}");
        assert_eq!(writer.undelivered(), PAYLOAD as u64 - written);
        // Stopped, it has let the pipe go: its reader gets what was
        // written, then the end.
        let mut got = Vec::new();
        read_end.read_to_end(&mut got).unwrap();
        assert_eq!(got.len() as u64, written);
    }

    /// The wait's ends, in time: the idle limit counts from the last
    /// progress (or the start), the cap from the start, whichever is first.
    #[test]
    fn the_wait_ends_at_the_idle_limit_or_the_cap() {
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let (idle, cap) = (Duration::from_millis(2000), Duration::from_millis(30_000));
        assert_eq!(wait_step(ms(0), t0, t0, idle, cap), Ok(ms(2000)));
        assert_eq!(wait_step(ms(1999), t0, t0, idle, cap), Ok(ms(2000)));
        assert_eq!(
            wait_step(ms(2000), t0, t0, idle, cap),
            Err(OutWait::Stalled)
        );
        // Progress moves the idle limit on.
        assert_eq!(wait_step(ms(2500), t0, ms(1500), idle, cap), Ok(ms(3500)));
        // But never past the cap, however steady the progress.
        assert_eq!(
            wait_step(ms(29_000), t0, ms(28_900), idle, cap),
            Ok(ms(30_000))
        );
        assert_eq!(
            wait_step(ms(30_000), t0, ms(29_999), idle, cap),
            Err(OutWait::Capped)
        );
        // No cap: the idle limit alone.
        assert_eq!(wait_step(ms(10), t0, t0, idle, Duration::MAX), Ok(ms(2000)));
    }

    /// An output whose reader is gone fails for good: the writer ends, and
    /// the guest never waits on it.
    #[test]
    fn an_output_whose_reader_left_ends_the_writer() {
        let fixture = Fixture::new();
        let (read_end, write_end) = small_non_blocking_pipe();
        drop(read_end);
        let (_, output, _) = fixture.hub.attach(Mode::Ro, 0);
        let writer = spawn(output, Target::file(write_end)).unwrap();
        let mut guest = fixture.guest();
        guest.write_all(&vec![b'x'; 1 << 20]).unwrap();
        assert_eq!(writer.wait(LIMIT), OutWait::Failed);
        guest.write_all(&vec![b'x'; 1 << 20]).unwrap();
        wait_until("the hub forgot it", || fixture.hub.clients() == 0);
    }

    /// `write_until`, which `boxcar attach` writes its stdout with: it
    /// waits through a full pipe, and ends as soon as it is told to stop,
    /// with what the pipe took counted, never inside a write.
    #[test]
    fn a_write_can_be_stopped_while_the_target_takes_nothing() {
        let (mut read_end, write_end) = small_pipe();
        let mut target = Target::file(write_end);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopper = std::sync::Arc::clone(&stop);
        let started = Instant::now();
        let writing = thread::spawn(move || target.write_until(&[b'q'; 64 * 1024], &stopper));
        thread::sleep(Duration::from_millis(200));
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert!(!writing.join().unwrap().unwrap(), "not stopped");
        assert!(started.elapsed() < Duration::from_secs(2));
        // The pipe took one page; the target is gone with the thread.
        let mut got = Vec::new();
        read_end.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), 4096);
        // A target that takes everything: written.
        let file = tempfile::tempfile().unwrap();
        let mut target = Target::file(file);
        let never = std::sync::atomic::AtomicBool::new(false);
        assert!(target.write_until(&[b'q'; 64 * 1024], &never).unwrap());
    }

    /// A socket's backlog is its send queue (`SIOCOUTQ`): `FIONREAD` on the
    /// writer's end sees the wrong queue, which stays empty however much
    /// waits for the reader.
    #[test]
    fn a_socket_stdout_is_measured_by_its_send_queue() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        (&ours).write_all(&[7u8; 1000]).unwrap();
        let fd = ours.as_raw_fd();
        assert_eq!(QueueKind::of(fd), QueueKind::Socket);
        assert!(queued(fd, QueueKind::Socket).unwrap() >= 1000);
        assert_eq!(
            queued(fd, QueueKind::Pipe),
            Some(0),
            "FIONREAD is the receive queue"
        );
        let mut got = [0u8; 1000];
        theirs.read_exact(&mut got).unwrap();
        assert_eq!(queued(fd, QueueKind::Socket), Some(0));

        let (read_end, write_end) = small_pipe();
        assert_eq!(QueueKind::of(write_end.as_raw_fd()), QueueKind::Pipe);
        (&write_end).write_all(&[1u8; 100]).unwrap();
        assert_eq!(queued(write_end.as_raw_fd(), QueueKind::Pipe), Some(100));
        drop(read_end);
        let file = tempfile::tempfile().unwrap();
        assert_eq!(QueueKind::of(file.as_raw_fd()), QueueKind::None);
    }

    /// A writer with no descriptor (a test's buffer) is waited on with a
    /// short retry, and gets everything.
    #[test]
    fn any_writer_gets_the_session() {
        #[derive(Clone, Default)]
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let fixture = Fixture::new();
        let out = Shared::default();
        let (_, output, _) = fixture.hub.attach(Mode::Ro, 0);
        let writer = spawn(output, Target::writer(out.clone())).unwrap();
        let mut guest = fixture.guest();
        guest.write_all(b"hi\r\n\x1b[1mbold\x1b[0m $ ").unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        assert_eq!(writer.wait(LIMIT), OutWait::Done);
        assert_eq!(
            out.0.lock().unwrap().as_slice(),
            b"hi\r\n\x1b[1mbold\x1b[0m $ "
        );
    }

    /// The guest never connected: once the stop sequence has closed the
    /// hub, there is nothing to wait for.
    #[test]
    fn nothing_to_wait_for_when_the_guest_never_connected() {
        let fixture = Fixture::new();
        let (_, output, _) = fixture.hub.attach(Mode::Ro, 0);
        let writer = spawn(output, Target::writer(std::io::sink())).unwrap();
        fixture.hub.close();
        assert_eq!(writer.wait(LIMIT), OutWait::Done);
        assert_eq!(writer.undelivered(), 0);
    }
}
