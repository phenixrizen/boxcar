// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest's console output, decoupled from the vCPUs.
//!
//! The UART used to write each byte the guest sent to the host's stdout on
//! the vCPU thread, under the serial mutex. A host stdout that stalled (a
//! pipe whose reader is paused, a terminal held by XOFF) then parked that
//! vCPU in `write_all`, which the stop sequence's kick cannot free, and the
//! VM could not be stopped.
//!
//! Now the UART writes into a [`ConsoleSink`]: a bounded ring of
//! [`RING_CAPACITY`] bytes behind a short mutex. A write copies into the
//! ring and returns; it never waits on the host. When the ring is full the
//! oldest bytes are dropped, so the newest output survives, and counted. One
//! thread, `console`, drains the ring to the target ([`ConsoleOut`]) with
//! ordinary blocking writes; the VM is never affected by how slow, stalled
//! or broken the target is. The stop sequence calls
//! [`ConsoleWriter::flush_and_join`] to let the thread deliver what it can,
//! within a deadline, and to learn how many bytes never got out.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How many bytes of console output the ring holds.
pub const RING_CAPACITY: usize = 256 * 1024;

/// The most the writer thread writes at a time.
const CHUNK: usize = 64 * 1024;

/// How long the writer thread lets output collect before it writes it. The
/// guest's UART sends one byte per port write: without this the thread
/// would be woken, and would write, once for each of them, and waking a
/// parked thread costs the vCPU thread that does it (an IPI to an idle CPU,
/// dear under virtualization) more than the write it replaces. A millisecond
/// is far below what a person notices on a console.
const COALESCE: Duration = Duration::from_millis(1);

/// How long the writer thread sleeps before it retries a target that
/// answered `WouldBlock` (a non-blocking pipe, which another process may
/// have switched to that mode).
const WOULD_BLOCK_RETRY: Duration = Duration::from_millis(2);

/// Where the guest's serial console output goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsoleOut {
    /// The host's standard output.
    Stdio,
    /// A file, created or truncated when the VM is built.
    File(PathBuf),
}

impl ConsoleOut {
    /// Opens the stream: a duplicate of stdout's descriptor, or the file
    /// (created or truncated). Stdout is written unbuffered through its own
    /// descriptor, so that the writer thread never holds std's stdout lock
    /// (which a stalled write would keep for as long as it stalls); a
    /// process with no stdout descriptor falls back to std's handle, which
    /// discards what is written to a closed stdout.
    fn open(&self) -> io::Result<Box<dyn Write + Send>> {
        Ok(match self {
            ConsoleOut::Stdio => match io::stdout().as_fd().try_clone_to_owned() {
                Ok(fd) => Box::new(File::from(fd)),
                Err(_) => Box::new(io::stdout()),
            },
            ConsoleOut::File(path) => Box::new(File::create(path)?),
        })
    }
}

/// What [`ConsoleWriter::flush_and_join`] reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsoleStats {
    /// Console bytes the guest wrote that were not written to the target:
    /// the oldest bytes dropped when the ring overflowed, the bytes of
    /// writes that failed, and, when the writer was stuck at the deadline,
    /// everything it had not delivered (the write it was stuck in
    /// included, which may have been partly written).
    pub dropped_bytes: u64,
}

/// The ring, and its overflow rule.
struct Ring {
    bytes: VecDeque<u8>,
    capacity: usize,
}

impl Ring {
    fn new(capacity: usize) -> Self {
        Ring {
            // Allocated once: a push never allocates under the mutex.
            bytes: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Appends `data`; when it does not all fit, drops the oldest bytes
    /// (the ring's own first, then the front of `data` itself when it is
    /// longer than the ring). Returns how many it dropped.
    fn push(&mut self, data: &[u8]) -> usize {
        let keep = data.len().min(self.capacity);
        let from_data = data.len() - keep;
        let from_ring = (self.bytes.len() + keep).saturating_sub(self.capacity);
        self.bytes.drain(..from_ring);
        self.bytes.extend(&data[from_data..]);
        from_data + from_ring
    }

    /// Moves up to `max` of the oldest bytes into `out`.
    fn take(&mut self, out: &mut Vec<u8>, max: usize) -> usize {
        let count = self.bytes.len().min(max);
        out.extend(self.bytes.drain(..count));
        count
    }
}

struct State {
    ring: Ring,
    dropped: u64,
    /// Bytes the writer thread took from the ring and has not finished
    /// writing.
    in_flight: usize,
    /// The writer thread waits on `Shared::wake`.
    parked: bool,
    /// Set by [`ConsoleWriter::flush_and_join`] (and its drop): the thread
    /// exits once the ring is empty.
    stop: bool,
    /// The writer thread has exited, or was given up on: later writes are
    /// discarded.
    finished: bool,
}

struct Shared {
    state: Mutex<State>,
    /// The writer thread waits here for bytes or the stop.
    wake: Condvar,
    /// `flush_and_join` waits here for `finished`.
    done: Condvar,
    /// `flush_and_join` stopped waiting for a writer stuck in the target:
    /// the thread, if it ever returns from the write, must just exit.
    abandoned: AtomicBool,
}

impl Shared {
    fn new(capacity: usize) -> Self {
        Shared {
            state: Mutex::new(State {
                ring: Ring::new(capacity),
                dropped: 0,
                in_flight: 0,
                parked: false,
                stop: false,
                finished: false,
            }),
            wake: Condvar::new(),
            done: Condvar::new(),
            abandoned: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add_dropped(state: &mut State, count: usize) {
        state.dropped = state
            .dropped
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    }
}

/// What the UART writes the guest's output into. Cheap to clone; every
/// clone feeds the same ring.
#[derive(Clone)]
pub struct ConsoleSink {
    shared: Arc<Shared>,
}

impl Write for ConsoleSink {
    /// Copies `buf` into the ring and returns at once, whatever the target
    /// is doing. Always takes all of `buf`: what does not fit pushes the
    /// oldest bytes out, which are counted. Never fails and never panics.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let notify = {
            let mut state = self.shared.lock();
            if state.finished {
                // The VM is stopped; nobody drains the ring any more.
                return Ok(buf.len());
            }
            let dropped = state.ring.push(buf);
            Shared::add_dropped(&mut state, dropped);
            state.parked
        };
        if notify {
            self.shared.wake.notify_one();
        }
        Ok(buf.len())
    }

    /// Does nothing: delivery is the writer thread's business, and the
    /// UART's per-byte flush must not wait for it.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The `console` thread, and the handle the stop sequence uses to end it.
pub struct ConsoleWriter {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl ConsoleWriter {
    /// Opens `out` and starts the writer thread. The sink goes to the UART;
    /// the writer stays with the VMM, which ends it with
    /// [`flush_and_join`](Self::flush_and_join).
    pub fn spawn(out: ConsoleOut) -> io::Result<(ConsoleSink, ConsoleWriter)> {
        Self::spawn_with(out.open()?)
    }

    /// Like [`spawn`](Self::spawn), for any target.
    pub fn spawn_with(
        target: impl Write + Send + 'static,
    ) -> io::Result<(ConsoleSink, ConsoleWriter)> {
        Self::spawn_sized(target, RING_CAPACITY)
    }

    fn spawn_sized(
        target: impl Write + Send + 'static,
        capacity: usize,
    ) -> io::Result<(ConsoleSink, ConsoleWriter)> {
        let shared = Arc::new(Shared::new(capacity));
        let thread = {
            let shared = shared.clone();
            thread::Builder::new()
                .name("console".into())
                .spawn(move || drain(&shared, target))?
        };
        Ok((
            ConsoleSink {
                shared: shared.clone(),
            },
            ConsoleWriter {
                shared,
                thread: Some(thread),
            },
        ))
    }

    /// Ends the writer: it delivers what is in the ring, and this waits up
    /// to `deadline` for that. If it finishes, the thread is joined. If the
    /// target is stuck and it does not, the thread is detached (it ends
    /// with the process, or when its write returns), and everything it
    /// had not delivered is counted as dropped. Returns the count of bytes
    /// that were never written to the target.
    ///
    /// It logs nothing, not even a stall or a panicked thread: it runs in
    /// the stop sequence, and the log's stderr may be the very sink that is
    /// stalled, which would hold the stop for as long as the stall lasts.
    /// The count is the report; it goes into `vmm.stop`.
    pub fn flush_and_join(mut self, deadline: Duration) -> ConsoleStats {
        let end = Instant::now().checked_add(deadline);
        let mut state = self.shared.lock();
        state.stop = true;
        if state.parked {
            self.shared.wake.notify_one();
        }
        while !state.finished {
            let left = match end {
                Some(end) => end.saturating_duration_since(Instant::now()),
                None => Duration::from_secs(3600),
            };
            if left.is_zero() {
                break;
            }
            state = self
                .shared
                .done
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let thread = self.thread.take();
        if state.finished {
            let stats = ConsoleStats {
                dropped_bytes: state.dropped,
            };
            drop(state);
            if let Some(thread) = thread {
                // A panic here has already been printed by the panic hook,
                // on the writer thread; the stop must not log it again.
                let _ = thread.join();
            }
            return stats;
        }

        // Stuck in a write to the target. A thread cannot be interrupted
        // out of one, so it is left behind: detached, to end with the
        // process, and told to exit if the write ever returns.
        self.shared.abandoned.store(true, Ordering::SeqCst);
        let undelivered = state.ring.bytes.len() + state.in_flight;
        state.ring.bytes.clear();
        state.in_flight = 0;
        state.finished = true;
        Shared::add_dropped(&mut state, undelivered);
        let stats = ConsoleStats {
            dropped_bytes: state.dropped,
        };
        drop(state);
        drop(thread);
        stats
    }
}

impl Drop for ConsoleWriter {
    /// A writer dropped without `flush_and_join` (the VM never ran, or
    /// building it failed) lets the thread deliver what it has and exit; it
    /// does not wait for it.
    fn drop(&mut self) {
        if self.thread.is_some() {
            let mut state = self.shared.lock();
            state.stop = true;
            if state.parked {
                self.shared.wake.notify_one();
            }
        }
    }
}

/// The writer thread: delivers the ring to `target` until it is told to
/// stop and the ring is empty.
fn drain(shared: &Shared, mut target: impl Write) {
    let mut chunk = Vec::with_capacity(CHUNK);
    let mut reported = false;
    loop {
        chunk.clear();
        {
            let mut state = shared.lock();
            while state.ring.bytes.is_empty() {
                if state.stop {
                    state.finished = true;
                    drop(state);
                    shared.done.notify_all();
                    return;
                }
                state.parked = true;
                state = shared
                    .wake
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
                state.parked = false;
            }
            if !state.stop {
                // Not parked while it sleeps, so a push does not wake it.
                drop(state);
                thread::sleep(COALESCE);
                state = shared.lock();
            }
            state.in_flight = state.ring.take(&mut chunk, CHUNK);
        }

        // Outside the lock: this is where a stalled target stalls.
        let result =
            write_out(&mut target, &chunk, &shared.abandoned).and_then(|()| target.flush());

        if shared.abandoned.load(Ordering::SeqCst) {
            return;
        }
        let failure = {
            let mut state = shared.lock();
            state.in_flight = 0;
            result
                .err()
                .inspect(|_| Shared::add_dropped(&mut state, chunk.len()))
        };
        // Outside the lock: the log may be as stalled as the target, and a
        // vCPU thread pushing into the ring must never wait on that.
        if let Some(error) = failure {
            if !reported {
                reported = true;
                tracing::warn!("console: cannot write the guest's output, dropping it: {error}");
            }
        }
    }
}

/// `write_all`, except that a target answering `WouldBlock` is waited on
/// (the std version would fail the whole write), until `abandoned`.
fn write_out(target: &mut impl Write, mut buf: &[u8], abandoned: &AtomicBool) -> io::Result<()> {
    while !buf.is_empty() {
        match target.write(buf) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => buf = &buf[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if abandoned.load(Ordering::SeqCst) {
                    return Err(error);
                }
                thread::sleep(WOULD_BLOCK_RETRY);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    use super::*;

    /// A target that keeps what it is given, and stalls in `write` while the
    /// test holds `gate`: a paused pipe reader.
    #[derive(Clone, Default)]
    struct Target {
        gate: Arc<Mutex<()>>,
        got: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Target {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _gate = self.gate.lock().unwrap();
            self.got.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Target {
        fn got(&self) -> Vec<u8> {
            self.got.lock().unwrap().clone()
        }
    }

    /// `len` bytes that repeat every 251, so a lost or reordered byte shows.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn console_sink_never_blocks_when_the_target_stalls() {
        let target = Target::default();
        let stall = target.gate.lock().unwrap();
        let (mut sink, writer) = ConsoleWriter::spawn_with(target.clone()).unwrap();

        let data = pattern(1 << 20);
        let sent = data.clone();
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let start = Instant::now();
            for piece in sent.chunks(4096) {
                sink.write_all(piece).unwrap();
            }
            let _ = done.send(start.elapsed());
        });
        let elapsed = finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the sink blocked on a stalled target");
        assert!(elapsed < Duration::from_secs(2), "1 MiB took {elapsed:?}");

        drop(stall);
        let stats = writer.flush_and_join(Duration::from_secs(10));
        let got = target.got();
        assert!(stats.dropped_bytes > 0);
        // Every byte is delivered or counted...
        assert_eq!(got.len() as u64 + stats.dropped_bytes, 1 << 20);
        // ...and the newest bytes survive: the ring was full at the end, so
        // the last RING_CAPACITY bytes of the delivery are the last
        // RING_CAPACITY bytes written. (What came before them depends on
        // when the thread first took from the ring, so it is not checked.)
        assert!(got.len() >= RING_CAPACITY);
        assert_eq!(
            got[got.len() - RING_CAPACITY..],
            data[data.len() - RING_CAPACITY..]
        );
    }

    #[test]
    fn flush_and_join_delivers_everything_when_the_target_keeps_up() {
        let target = Target::default();
        let (mut sink, writer) = ConsoleWriter::spawn_with(target.clone()).unwrap();
        let data = pattern(200_000);
        let mut rest = &data[..];
        for size in [1, 7, 4096, 65_536].iter().cycle() {
            let (piece, tail) = rest.split_at((*size).min(rest.len()));
            sink.write_all(piece).unwrap();
            rest = tail;
            if rest.is_empty() {
                break;
            }
        }
        let stats = writer.flush_and_join(Duration::from_secs(5));
        assert_eq!(stats, ConsoleStats { dropped_bytes: 0 });
        assert_eq!(target.got(), data);
    }

    /// A pipe nobody reads, full, with a blocking write end: what stderr is
    /// when it shares a sink with a stalled reader (`2>&1 | slow`), or a
    /// terminal held by XOFF. A write to it blocks until `read_end` is
    /// drained. `read_end` must stay open for the test.
    fn full_pipe() -> (File, File) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the descriptors are new and owned here.
        let (read_end, write_end) =
            unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        set_nonblocking(&write_end, true);
        let mut writer = &write_end;
        loop {
            match writer.write(&[b'.'; 4096]) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        set_nonblocking(&write_end, false);
        (write_end, read_end)
    }

    fn set_nonblocking(file: &File, on: bool) {
        // SAFETY: fcntl on a descriptor `file` owns.
        unsafe {
            let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
            let flags = if on {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            assert_eq!(libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags), 0);
        }
    }

    /// Reads everything in the pipe, so that a blocked writer goes on.
    fn drain_pipe(read_end: &File) {
        set_nonblocking(read_end, true);
        let mut reader = read_end;
        let mut buf = [0u8; 8192];
        while matches!(reader.read(&mut buf), Ok(n) if n > 0) {}
    }

    /// A subscriber that logs every event into `log`, as the CLI's does
    /// into stderr.
    fn logging_to(log: File) -> impl tracing::Subscriber + Send + Sync {
        tracing_subscriber::fmt()
            .with_writer(Mutex::new(log))
            .with_ansi(false)
            .finish()
    }

    /// The stop sequence logs nothing: with the console target stalled and
    /// stderr stalled too (a pipe nobody reads), `flush_and_join` still
    /// returns at its deadline, which a warning about the stall, written to
    /// that stderr, would have kept it from.
    #[test]
    fn a_stalled_console_and_a_stalled_log_do_not_hold_the_stop() {
        let (log, reader) = full_pipe();
        let subscriber = logging_to(log);
        let target = Target::default();
        let stall = target.gate.lock().unwrap();
        let (mut sink, writer) = ConsoleWriter::spawn_with(target.clone()).unwrap();
        sink.write_all(&pattern(1000)).unwrap();

        let (done, finished) = mpsc::channel();
        let stopper = thread::spawn(move || {
            tracing::subscriber::with_default(subscriber, || {
                let start = Instant::now();
                let stats = writer.flush_and_join(Duration::from_secs(2));
                let _ = done.send((start.elapsed(), stats));
            });
        });
        let received = finished.recv_timeout(Duration::from_secs(3));
        // Let a blocked stop, if there is one, go on, so the test ends.
        drain_pipe(&reader);
        drop(stall);
        stopper.join().unwrap();
        let (elapsed, stats) = received.expect("the stop waited on a write to the log");
        assert!(elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(3));
        assert_eq!(stats.dropped_bytes, 1000);
    }

    /// The writer thread reports a failed target outside its lock, so a
    /// blocked log write cannot hold the vCPU threads that push into the
    /// ring.
    #[test]
    fn a_blocked_log_write_does_not_hold_the_ring() {
        let (log, reader) = full_pipe();
        let subscriber = logging_to(log);
        let shared = Arc::new(Shared::new(RING_CAPACITY));
        let mut sink = ConsoleSink {
            shared: shared.clone(),
        };
        sink.write_all(b"lost").unwrap();
        shared.lock().stop = true;
        // `drain` fails to write, reports it to the blocked log, and so
        // stays in the logging call.
        let drainer = {
            let shared = shared.clone();
            thread::spawn(move || {
                tracing::subscriber::with_default(subscriber, || drain(&shared, Broken));
            })
        };
        // Wait until it has taken the bytes and counted them dropped.
        let counted = |shared: &Shared| shared.state.try_lock().is_ok_and(|s| s.dropped >= 4);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !counted(&shared) {
            // A writer that logs under its lock never lets go of it.
            assert!(
                Instant::now() < deadline,
                "the writer never reported the failed write, or holds the lock while it does"
            );
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(100));

        let (done, finished) = mpsc::channel();
        let pusher = thread::spawn(move || {
            sink.write_all(b"more").unwrap();
            let _ = done.send(());
        });
        let pushed = finished.recv_timeout(Duration::from_secs(3));
        drain_pipe(&reader);
        pusher.join().unwrap();
        drainer.join().unwrap();
        pushed.expect("a ring write waited for the writer's log call");
    }

    #[test]
    fn a_full_ring_drops_the_oldest_bytes_and_counts_them() {
        let mut ring = Ring::new(8);
        let contents = |ring: &Ring| ring.bytes.iter().copied().collect::<Vec<u8>>();

        assert_eq!(ring.push(b"abcdef"), 0);
        assert_eq!(ring.push(b""), 0);
        assert_eq!(contents(&ring), b"abcdef");
        // Room for 2 of the 4: the 2 oldest bytes go.
        assert_eq!(ring.push(b"ghij"), 2);
        assert_eq!(contents(&ring), b"cdefghij");
        // Longer than the ring: it keeps only the newest 8 of them, and
        // everything that was in it is gone.
        assert_eq!(ring.push(b"0123456789ABCDEFGHIJ"), 8 + 12);
        assert_eq!(contents(&ring), b"CDEFGHIJ");
        // Exactly full is not an overflow.
        let mut ring = Ring::new(4);
        assert_eq!(ring.push(b"abcd"), 0);
        assert_eq!(ring.push(b"e"), 1);
        assert_eq!(contents(&ring), b"bcde");

        let mut out = Vec::new();
        assert_eq!(ring.take(&mut out, 3), 3);
        assert_eq!(out, b"bcd");
        assert_eq!(contents(&ring), b"e");
    }

    /// A writer that cannot deliver gives up at the deadline instead of
    /// holding the stop sequence, and says what it left undelivered.
    #[test]
    fn flush_and_join_detaches_a_writer_stuck_in_a_write() {
        let target = Target::default();
        let stall = target.gate.lock().unwrap();
        let (mut sink, writer) = ConsoleWriter::spawn_with(target.clone()).unwrap();
        sink.write_all(&pattern(1000)).unwrap();

        let start = Instant::now();
        let stats = writer.flush_and_join(Duration::from_millis(300));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        // Whether the thread had taken the 1000 bytes yet or not, none got
        // out, and all of them are counted.
        assert_eq!(stats.dropped_bytes, 1000);
        assert!(target.got().is_empty());

        // A later write is discarded, not queued behind the stuck thread.
        sink.write_all(b"late").unwrap();
        drop(stall);
        // The detached thread finishes its write and ends; "late" never
        // reaches it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while target.got().len() < 1000 {
            assert!(Instant::now() < deadline, "the detached thread is stuck");
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(50));
        assert_eq!(target.got(), pattern(1000));
    }

    /// A target that fails every write: the sink does not.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failing_target_loses_the_output_but_never_fails_the_sink() {
        let (mut sink, writer) = ConsoleWriter::spawn_with(Broken).unwrap();
        for _ in 0..10 {
            sink.write_all(&[b'x'; 1000]).unwrap();
            sink.flush().unwrap();
        }
        let stats = writer.flush_and_join(Duration::from_secs(5));
        assert_eq!(stats.dropped_bytes, 10_000);
    }

    /// Interrupted writes are retried, a target that is not ready is waited
    /// on, and short writes continue where they left off.
    #[test]
    fn interrupted_and_short_writes_are_retried_and_a_busy_target_is_waited_on() {
        struct Fussy {
            got: Arc<Mutex<Vec<u8>>>,
            calls: u32,
        }
        impl Write for Fussy {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                match self.calls % 4 {
                    1 => Err(io::ErrorKind::Interrupted.into()),
                    2 => Err(io::ErrorKind::WouldBlock.into()),
                    _ => {
                        // Three bytes at a time.
                        let count = buf.len().min(3);
                        self.got.lock().unwrap().extend_from_slice(&buf[..count]);
                        Ok(count)
                    }
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let got = Arc::new(Mutex::new(Vec::new()));
        let target = Fussy {
            got: got.clone(),
            calls: 0,
        };
        let (mut sink, writer) = ConsoleWriter::spawn_with(target).unwrap();
        sink.write_all(b"hello, console").unwrap();
        let stats = writer.flush_and_join(Duration::from_secs(10));
        assert_eq!(stats.dropped_bytes, 0);
        assert_eq!(*got.lock().unwrap(), b"hello, console");
    }

    #[test]
    fn a_write_after_the_writer_is_joined_is_accepted_and_discarded() {
        let target = Target::default();
        let (mut sink, writer) = ConsoleWriter::spawn_with(target.clone()).unwrap();
        sink.write_all(b"before").unwrap();
        let stats = writer.flush_and_join(Duration::from_secs(5));
        assert_eq!(stats, ConsoleStats::default());
        assert_eq!(sink.write(b"after").unwrap(), 5);
        assert_eq!(target.got(), b"before");
    }

    /// A writer dropped without `flush_and_join` still delivers what it has.
    #[test]
    fn a_dropped_writer_lets_its_thread_drain_and_exit() {
        let target = Target::default();
        let (mut sink, writer) = ConsoleWriter::spawn_with(target.clone()).unwrap();
        sink.write_all(b"unsent").unwrap();
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while target.got() != b"unsent" {
            assert!(Instant::now() < deadline, "nothing was delivered");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn the_console_file_gets_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let (mut sink, writer) = ConsoleWriter::spawn(ConsoleOut::File(path.clone())).unwrap();
        sink.write_all(b"login: ").unwrap();
        sink.write_all(b"root\r\n").unwrap();
        let stats = writer.flush_and_join(Duration::from_secs(5));
        assert_eq!(stats, ConsoleStats::default());
        assert_eq!(std::fs::read(&path).unwrap(), b"login: root\r\n");
    }

    /// A file that cannot be created is the caller's error, as before.
    #[test]
    fn an_unopenable_console_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-dir").join("console.log");
        assert!(ConsoleWriter::spawn(ConsoleOut::File(path)).is_err());
    }
}
