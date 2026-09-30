// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The writer thread: one per session, and the only place records are made.
//!
//! For each submission it receives, the thread stamps `ts_host_ns`
//! (`CLOCK_REALTIME`) and `ts_mono_ns` (`CLOCK_MONOTONIC`), assigns the next
//! seq, links the record to the last hash, hashes it, and appends the line.
//! It drains the channel in batches and flushes its buffer after each batch,
//! so readers see records within one batch of their arrival.
//!
//! Durability: a [`Priority::Critical`] record is `fdatasync`ed right after
//! it is written; everything else is synced by the next checkpoint (see
//! `checkpoint`), which comes after `checkpoint_every` records or
//! `checkpoint_interval`, whichever is first. A segment that reaches
//! `segment_max_bytes` is sealed with a checkpoint and the next one started.
//! [`WriterHandle::close`] drains every accepted event, writes a final
//! checkpoint, and syncs.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_proto::{Hash, Payload, Record, Ring, SessionId, SpanRef, Subject};
use crossbeam_channel::{at, bounded, never, select, Receiver, Sender};

use crate::chain::{Chainer, PartialRecord};
use crate::checkpoint::{CheckpointIndex, IndexEntry, Window};
use crate::segment::{Fdatasync, SegmentWriter, Syncer};
use crate::sink::{AuditSink, Priority, Shared, Submission};

/// Most submissions written between two buffer flushes.
const MAX_BATCH: usize = 1024;

/// Where and how a session's log is written.
#[derive(Clone, Debug)]
pub struct WriterConfig {
    /// The log goes to `<data_dir>/sessions/<session_id>/`.
    pub data_dir: PathBuf,
    pub session_id: SessionId,
    /// Checkpoint after this many records. Default 1024.
    pub checkpoint_every: u64,
    /// Checkpoint at most this long after the oldest record no checkpoint
    /// covers yet. Default 2 s.
    pub checkpoint_interval: Duration,
    /// Seal a segment once it holds this many bytes. Default 256 MiB.
    pub segment_max_bytes: u64,
    /// Events the channel holds before `emit` waits and `try_emit` drops.
    /// Default 65536.
    pub channel_capacity: usize,
}

impl WriterConfig {
    /// A config with the defaults.
    pub fn new(data_dir: impl Into<PathBuf>, session_id: SessionId) -> Self {
        WriterConfig {
            data_dir: data_dir.into(),
            session_id,
            checkpoint_every: 1024,
            checkpoint_interval: Duration::from_secs(2),
            segment_max_bytes: 256 * 1024 * 1024,
            channel_capacity: 65536,
        }
    }

    fn validate(&self) -> io::Result<()> {
        for (name, value) in [
            ("checkpoint_every", self.checkpoint_every),
            ("segment_max_bytes", self.segment_max_bytes),
            ("channel_capacity", self.channel_capacity as u64),
        ] {
            if value == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("audit writer: {name} must be at least 1"),
                ));
            }
        }
        Ok(())
    }
}

/// What a writer did, reported by [`WriterHandle::close`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseStats {
    /// Records this writer appended, checkpoints included. Less than
    /// `last_seq` when it resumed an existing log.
    pub records: u64,
    /// Events `try_emit` dropped while this writer ran.
    pub dropped: u64,
    pub last_seq: u64,
    pub last_hash: Hash,
}

/// Owns the writer thread. Dropping it closes the writer as
/// [`close`](Self::close) does, logging any error.
pub struct WriterHandle {
    session_dir: PathBuf,
    shared: Arc<Shared>,
    /// Dropping it tells the thread to finish.
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<io::Result<CloseStats>>>,
}

impl WriterHandle {
    /// `<data_dir>/sessions/<session_id>`.
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    /// Stops the sinks, waits for sends in flight, drains the channel,
    /// writes a final checkpoint, syncs, and joins the thread. Events every
    /// sink accepted are in the log when this returns `Ok`; afterwards the
    /// sinks refuse everything.
    pub fn close(mut self) -> io::Result<CloseStats> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> io::Result<CloseStats> {
        let Some(thread) = self.thread.take() else {
            return Err(io::Error::other("the audit writer is already closed"));
        };
        // The thread keeps draining while this waits out blocked sends.
        self.shared.close();
        drop(self.stop.take());
        thread
            .join()
            .map_err(|_| io::Error::other("the audit writer thread panicked"))?
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        if self.thread.is_some() {
            if let Err(e) = self.shutdown() {
                tracing::error!(
                    session_dir = %self.session_dir.display(),
                    "closing the audit log failed: {e}"
                );
            }
        }
    }
}

/// Starts the writer for `cfg.session_id`, creating the session directory,
/// or resuming the log in it after torn-tail recovery.
pub fn spawn(cfg: WriterConfig) -> io::Result<(AuditSink, WriterHandle)> {
    spawn_with_syncer(cfg, Fdatasync)
}

/// [`spawn`], with `syncer` making the segment files durable in place of
/// `fdatasync`.
pub fn spawn_with_syncer<S: Syncer + Send + 'static>(
    cfg: WriterConfig,
    syncer: S,
) -> io::Result<(AuditSink, WriterHandle)> {
    cfg.validate()?;
    let session_dir = cfg.data_dir.join("sessions").join(cfg.session_id.as_str());
    let (segments, resume) = SegmentWriter::open_or_create(&session_dir, &cfg.session_id, syncer)?;
    let index = CheckpointIndex::open(&session_dir, segments.segment(), &resume.checkpoints)?;

    let (tx, rx) = bounded(cfg.channel_capacity);
    let (stop, stopped) = bounded(0);
    let shared = Arc::new(Shared::default());
    let pending_since = (!resume.window.is_empty()).then(Instant::now);
    let writer = Writer {
        session_id: cfg.session_id,
        chain: Chainer::resume(resume.last_seq, resume.last_hash),
        segments,
        index,
        window: resume.window,
        pending_since,
        checkpoint_every: cfg.checkpoint_every,
        checkpoint_interval: cfg.checkpoint_interval,
        segment_max_bytes: cfg.segment_max_bytes,
        shared: shared.clone(),
        dropped_reported: 0,
        written: 0,
    };
    let thread = thread::Builder::new()
        .name("audit-writer".into())
        .spawn(move || writer.run(rx, stopped))?;

    let handle = WriterHandle {
        session_dir,
        shared: shared.clone(),
        stop: Some(stop),
        thread: Some(thread),
    };
    Ok((AuditSink::new(tx, shared), handle))
}

struct Writer<S: Syncer> {
    session_id: SessionId,
    chain: Chainer,
    segments: SegmentWriter<S>,
    index: CheckpointIndex,
    /// The records no checkpoint covers yet.
    window: Window,
    /// When the oldest of them was written.
    pending_since: Option<Instant>,
    checkpoint_every: u64,
    checkpoint_interval: Duration,
    segment_max_bytes: u64,
    shared: Arc<Shared>,
    /// `shared.dropped` as the last checkpoint reported it.
    dropped_reported: u64,
    /// Records this writer appended.
    written: u64,
}

impl<S: Syncer> Writer<S> {
    fn run(mut self, rx: Receiver<Submission>, stop: Receiver<()>) -> io::Result<CloseStats> {
        let result = self.serve(rx, stop);
        if let Err(e) = &result {
            tracing::error!(session = %self.session_id, "the audit log writer failed: {e}");
        }
        result
    }

    fn serve(
        &mut self,
        mut rx: Receiver<Submission>,
        stop: Receiver<()>,
    ) -> io::Result<CloseStats> {
        loop {
            let deadline = self
                .pending_since
                .and_then(|t| t.checked_add(self.checkpoint_interval));
            let timer = deadline.map_or_else(never, at);
            let mut sinks_gone = false;
            let mut stopping = false;
            select! {
                recv(rx) -> msg => match msg {
                    Ok(first) => self.batch(first, &rx)?,
                    Err(_) => sinks_gone = true,
                },
                recv(stop) -> _ => stopping = true,
                recv(timer) -> _ => {}
            }
            if stopping {
                break;
            }
            if sinks_gone {
                // Every sink is gone and the channel is empty: wait for close
                // without spinning on the dead channel.
                rx = never();
            }
            if deadline.is_some_and(|d| d <= Instant::now()) && !self.window.is_empty() {
                self.checkpoint()?;
            }
        }
        // The sinks are closed, so the channel holds all there will ever be.
        while let Ok(submission) = rx.try_recv() {
            self.write(submission)?;
        }
        self.finish()
    }

    fn batch(&mut self, first: Submission, rx: &Receiver<Submission>) -> io::Result<()> {
        self.write(first)?;
        for _ in 1..MAX_BATCH {
            match rx.try_recv() {
                Ok(submission) => self.write(submission)?,
                Err(_) => break,
            }
        }
        self.segments.flush()
    }

    /// Writes one submission. It is never a checkpoint: the sink refuses those.
    fn write(&mut self, s: Submission) -> io::Result<()> {
        let record = self.chain_next(s.ring, s.ts_guest_ns, s.subject, &s.payload, s.span);
        self.append(&record)?;
        self.window.push(&record.hash);
        self.pending_since.get_or_insert_with(Instant::now);
        if s.priority == Priority::Critical {
            self.segments.sync()?;
        }
        if self.window.len() >= self.checkpoint_every {
            self.checkpoint()?;
        }
        if self.segments.len() >= self.segment_max_bytes {
            self.seal()?;
        }
        Ok(())
    }

    fn chain_next(
        &mut self,
        ring: Ring,
        ts_guest_ns: Option<u64>,
        subject: Option<Subject>,
        payload: &Payload,
        span: Option<SpanRef>,
    ) -> Record {
        let (kind, data) = payload.into_parts();
        self.chain.next(PartialRecord {
            session_id: self.session_id.clone(),
            ring,
            src: payload.source(),
            kind,
            ts_host_ns: realtime_ns(),
            ts_mono_ns: monotonic_ns(),
            ts_guest_ns,
            subject,
            data,
            span,
        })
    }

    /// Appends a record's line; returns its segment and offset.
    fn append(&mut self, record: &Record) -> io::Result<(u32, u64)> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let at = self.segments.append(&line)?;
        self.written += 1;
        Ok(at)
    }

    /// Chains a checkpoint over the window, syncs it to disk, then lists it
    /// in `checkpoints.jsonl`.
    fn checkpoint(&mut self) -> io::Result<()> {
        let dropped = self.shared.dropped.load(Ordering::Relaxed);
        let checkpoint = self
            .window
            .take(dropped.saturating_sub(self.dropped_reported));
        let payload = Payload::Checkpoint(checkpoint.clone());
        let record = self.chain_next(Ring::Host, None, None, &payload, None);
        let (segment, offset) = self.append(&record)?;
        self.segments.sync()?;
        self.index
            .append(&IndexEntry::new(record.seq, segment, offset, &checkpoint))?;
        self.dropped_reported = dropped;
        self.pending_since = None;
        Ok(())
    }

    /// Ends the current segment with a checkpoint and starts the next. The
    /// index is synced first, so every sealed segment is listed durably.
    fn seal(&mut self) -> io::Result<()> {
        if !self.window.is_empty() {
            self.checkpoint()?;
        }
        self.index.sync()?;
        self.segments.rotate()
    }

    /// The final checkpoint, for whatever the last one does not cover.
    fn finish(&mut self) -> io::Result<CloseStats> {
        let dropped = self.shared.dropped.load(Ordering::Relaxed);
        if !self.window.is_empty() || dropped > self.dropped_reported {
            self.checkpoint()?;
        }
        self.segments.sync()?;
        self.index.sync()?;
        Ok(CloseStats {
            records: self.written,
            dropped,
            last_seq: self.chain.last_seq(),
            last_hash: self.chain.last_hash(),
        })
    }
}

/// `CLOCK_REALTIME` in nanoseconds since the Unix epoch.
pub(crate) fn realtime_ns() -> u64 {
    clock_ns(libc::CLOCK_REALTIME)
}

/// `CLOCK_MONOTONIC` in nanoseconds.
fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the whole call, and it
    // is the only memory clock_gettime writes.
    let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
    if rc != 0 {
        // Only an invalid clock id fails, and both ids here are valid. A zero
        // timestamp stays visible in the record; this says why.
        let error = io::Error::last_os_error();
        tracing::warn!(clock, %error, "clock_gettime failed; stamping 0");
        return 0;
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}
