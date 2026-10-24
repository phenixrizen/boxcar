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
//!
//! Subscribers: a subscription request travels in the same channel as the
//! events, so the thread handles it between two records: it flushes the
//! current segment, registers the subscriber and answers with the seq of
//! the next record. Each record it makes after that, checkpoints included,
//! goes to every subscriber whose filter takes it, through a bounded queue
//! with `try_send`: the thread never waits for a subscriber, and drops one
//! whose queue is full (see [`crate::subscribe`]).
//!
//! The chain's head: a request for it ([`AuditSink::head`]) travels in the
//! channel too. Between two records the thread flushes the current segment
//! and answers with the last record's seq and hash and the session
//! directory ([`Head`]): every record up to the head, and every
//! `checkpoints.jsonl` line for a checkpoint up to it, is then in the
//! files a reader opens. A failure answers no head.
//!
//! Failure: the first I/O error, or a panic, ends the thread. It is
//! published as a [`WriteFailure`] (the file, what was being done to it, and
//! the seq being written) before anything else happens, so that from then on
//! every sink refuses events with
//! [`EmitError::Failed`](crate::EmitError::Failed), including one waiting
//! for room, and the failure eventfd ([`AuditSink::failure_event`]) becomes
//! readable. Then the thread drops what it still buffers and cuts the
//! current segment back to the end of the last record the log is
//! consistent after: a checkpoint that could not be synced or listed, and
//! so is not in `checkpoints.jsonl`, is taken back out, as is a line only
//! partly written. What is left verifies.
//!
//! The rollback cuts a partial line off `checkpoints.jsonl` first, then
//! the segment. A process killed between the two leaves a segment that ends
//! in a checkpoint the index does not list, as a crash between a
//! checkpoint's sync and its index line does, which the verifier reports
//! as incomplete. The other order would leave an index line whose
//! checkpoint is gone, which no crash leaves.

use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boxcar_proto::{Hash, Payload, Record, Ring, SessionId, SpanRef, Subject, VmmAuditLimit};
use crossbeam_channel::{at, bounded, never, select, Receiver, Sender};
use vmm_sys_util::eventfd::EventFd;

use crate::chain::{Chainer, PartialRecord};
use crate::checkpoint::{CheckpointIndex, IndexEntry, Window};
use crate::segment::{on, Fdatasync, FileError, FileResult, SegmentWriter, Syncer};
use crate::sink::{AuditSink, Msg, Priority, Shared, Submission};
use crate::subscribe::{SubscribeAck, SubscribeRequest, Subscribers};

/// Most submissions written between two buffer flushes.
const MAX_BATCH: usize = 1024;

/// Default total for a session's event segments and checkpoint index: 8 GiB.
/// Zero disables the total.
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Room held for `vmm.audit_limit`, the checkpoint that covers it and the
/// checkpoint's index entry. The size test below keeps this above their
/// widest serialized forms.
pub const QUOTA_RESERVE: u64 = 2048;

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
    /// Most bytes in all event segments and `checkpoints.jsonl`. Default
    /// 8 GiB; 0 means unlimited.
    pub max_bytes: u64,
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
            max_bytes: DEFAULT_MAX_BYTES,
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
        if self.max_bytes != 0 && self.max_bytes < QUOTA_RESERVE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("audit writer: max_bytes must be 0 or at least {QUOTA_RESERVE}"),
            ));
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

/// The chain's head, as [`AuditSink::head`] gets it from the writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// The last record's seq; 0 for an empty log.
    pub seq: u64,
    /// The last record's hash; the genesis hash for an empty log.
    pub hash: Hash,
    /// `<data_dir>/sessions/<session_id>`.
    pub session_dir: PathBuf,
}

/// Why the writer thread stopped: what it was doing, to which file, while
/// it wrote which record. From then on every sink refuses events with
/// [`EmitError::Failed`](crate::EmitError::Failed).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cannot {op} {} at seq {seq}: {message}", path.display())]
pub struct WriteFailure {
    /// What the writer was doing to the file: `write to`, `sync`, `create`,
    /// `replace` or `append to`.
    pub op: &'static str,
    /// The segment, `meta.json` or `checkpoints.jsonl`.
    pub path: PathBuf,
    /// The seq of the last record the writer had chained: the one it was
    /// writing, or the last one a failed flush or sync covered.
    pub seq: u64,
    pub kind: io::ErrorKind,
    /// The OS error number, when the error has one.
    pub errno: Option<i32>,
    /// The error's own text.
    pub message: String,
}

impl WriteFailure {
    fn new(e: FileError, seq: u64) -> Self {
        WriteFailure {
            op: e.op,
            path: e.path,
            seq,
            kind: e.error.kind(),
            errno: e.error.raw_os_error(),
            message: e.error.to_string(),
        }
    }
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

    /// Why the writer thread failed, once it has.
    pub fn failure(&self) -> Option<WriteFailure> {
        self.shared.failure.get().cloned()
    }

    /// See [`AuditSink::failure_event`].
    pub fn failure_event(&self) -> &EventFd {
        &self.shared.failure_evt
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

/// [`spawn`], with `syncer` making the log durable in place of
/// [`Fdatasync`]: every segment sync and every directory sync.
pub fn spawn_with_syncer<S: Syncer + Send + 'static>(
    cfg: WriterConfig,
    syncer: S,
) -> io::Result<(AuditSink, WriterHandle)> {
    cfg.validate()?;
    let session_dir = cfg
        .data_dir
        .join(crate::SESSIONS_DIR)
        .join(cfg.session_id.as_str());
    let (segments, resume) = SegmentWriter::open_or_create(&session_dir, &cfg.session_id, syncer)?;
    let index = CheckpointIndex::open(
        &session_dir,
        segments.segment(),
        &resume.checkpoints,
        segments.syncer(),
    )?;

    if !resume.terminal
        && cfg.max_bytes != 0
        && segments
            .total_len()
            .saturating_add(index.len())
            .saturating_add(QUOTA_RESERVE)
            > cfg.max_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "audit writer: existing log leaves no room below max_bytes {}",
                cfg.max_bytes
            ),
        ));
    }

    let (tx, rx) = bounded::<Msg>(cfg.channel_capacity);
    let (stop, stopped) = bounded(0);
    let shared = Arc::new(Shared::new(resume.last_seq + 1)?);
    let terminal = resume.terminal;
    let pending_since = (!resume.window.is_empty()).then(Instant::now);
    let consistent_len = segments.len();
    let writer = Writer {
        session_id: cfg.session_id,
        session_dir: session_dir.clone(),
        subscribers: Subscribers::default(),
        chain: Chainer::resume(resume.last_seq, resume.last_hash),
        segments,
        index,
        window: resume.window,
        pending_since,
        checkpoint_every: cfg.checkpoint_every,
        checkpoint_interval: cfg.checkpoint_interval,
        segment_max_bytes: cfg.segment_max_bytes,
        max_bytes: cfg.max_bytes,
        shared: shared.clone(),
        dropped_reported: 0,
        written: 0,
        consistent_len,
        unanswered: None,
        quota_pending: None,
    };
    if terminal {
        shared.close();
    }
    let builder = thread::Builder::new().name("audit-writer".into());
    let thread = if terminal {
        drop(rx);
        builder.spawn(move || {
            boxcar_confine::at_thread_start();
            writer.wait_closed(stopped)
        })?
    } else {
        builder.spawn(move || {
            boxcar_confine::at_thread_start();
            writer.run(rx, stopped)
        })?
    };

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
    session_dir: PathBuf,
    /// Who gets each record as it is made.
    subscribers: Subscribers,
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
    max_bytes: u64,
    shared: Arc<Shared>,
    /// `shared.dropped` as the last checkpoint reported it.
    dropped_reported: u64,
    /// Records this writer appended.
    written: u64,
    /// The length of the current segment after the last record the log is
    /// consistent after: every checkpoint before it is listed in
    /// `checkpoints.jsonl`. A failure cuts the segment back to it.
    consistent_len: u64,
    /// A head request whose flush failed: kept until the failure is
    /// published, so that its requester hears a failure, not a close.
    unanswered: Option<Sender<Head>>,
    /// The aggregate bytes an operation needed when it met the limit, and
    /// whether its current submission was accepted but not written.
    quota_pending: Option<(u64, u64)>,
}

impl<S: Syncer> Writer<S> {
    fn wait_closed(self, stop: Receiver<()>) -> io::Result<CloseStats> {
        let held = self;
        let _ = stop.recv();
        Ok(CloseStats {
            records: 0,
            dropped: 0,
            last_seq: held.chain.last_seq(),
            last_hash: held.chain.last_hash(),
        })
    }

    fn run(mut self, rx: Receiver<Msg>, stop: Receiver<()>) -> io::Result<CloseStats> {
        // Keeps the channel connected until the failure is published, so a
        // sink waiting for room is refused as `Failed`, not `Closed`.
        let held = rx.clone();
        // A panic ends the writer as an I/O error does, so that the sinks
        // fail closed rather than read it as a clean close.
        let served = panic::catch_unwind(AssertUnwindSafe(|| self.serve(rx, stop)));
        let failure = match served {
            Ok(Ok(stats)) => return Ok(stats),
            Ok(Err(error)) => WriteFailure::new(error, self.chain.last_seq()),
            Err(_) => WriteFailure {
                op: "write to",
                path: self.segments.path().to_owned(),
                seq: self.chain.last_seq(),
                kind: io::ErrorKind::Other,
                errno: None,
                message: "the audit writer thread panicked".to_owned(),
            },
        };
        self.shared.fail(failure.clone());
        drop(held);
        drop(self.unanswered.take());
        // The index first: killed between the two, the log is left as a
        // crash between a checkpoint's sync and its index line leaves it.
        self.index.roll_back();
        let kept = self.segments.roll_back(self.consistent_len);
        tracing::error!(
            session = %self.session_id,
            segment = %self.segments.path().display(),
            kept_bytes = kept,
            "the audit log writer failed: {failure}"
        );
        Err(io::Error::new(failure.kind, failure))
    }

    fn serve(&mut self, mut rx: Receiver<Msg>, stop: Receiver<()>) -> FileResult<CloseStats> {
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
                self.finish_quota(&rx)?;
            }
        }
        // The sinks are closed, so the channel holds all there will ever be.
        while let Ok(msg) = rx.try_recv() {
            self.handle(msg)?;
            self.finish_quota(&rx)?;
        }
        self.finish()
    }

    fn batch(&mut self, first: Msg, rx: &Receiver<Msg>) -> FileResult<()> {
        self.handle(first)?;
        self.finish_quota(rx)?;
        for _ in 1..MAX_BATCH {
            match rx.try_recv() {
                Ok(msg) => {
                    self.handle(msg)?;
                    self.finish_quota(rx)?;
                }
                Err(_) => break,
            }
        }
        self.segments.flush()
    }

    fn handle(&mut self, msg: Msg) -> FileResult<()> {
        match msg {
            Msg::Event(submission) => self.write(submission),
            Msg::Subscribe(request) => self.subscribe(request),
            Msg::Head(reply) => self.head(reply),
        }
    }

    /// Answers a head request between two records. The segment is flushed
    /// first, so every record up to the head is in the file its reader
    /// opens; a checkpoint's index line is appended before the checkpoint
    /// is done, so those are there too.
    fn head(&mut self, reply: Sender<Head>) -> FileResult<()> {
        if let Err(error) = self.segments.flush() {
            self.unanswered = Some(reply);
            return Err(error);
        }
        let head = Head {
            seq: self.chain.last_seq(),
            hash: self.chain.last_hash(),
            session_dir: self.session_dir.clone(),
        };
        // A requester that is gone before its answer needs none.
        let _ = reply.send(head);
        Ok(())
    }

    /// Registers a subscriber between two records. The segment is flushed
    /// first, so every record below the seq it is told is in the file its
    /// reader opens; every record after it is sent to the subscriber.
    fn subscribe(&mut self, request: SubscribeRequest) -> FileResult<()> {
        self.segments.flush()?;
        let ack = SubscribeAck {
            next_seq: self.chain.last_seq() + 1,
            session_dir: self.session_dir.clone(),
        };
        // A subscriber that is gone before its answer is not registered.
        if request.reply.send(ack).is_ok() {
            self.subscribers.add(request);
        }
        Ok(())
    }

    /// Writes one submission. It is never a checkpoint: the sink refuses those.
    fn write(&mut self, s: Submission) -> FileResult<()> {
        let (record, chain) =
            self.prepare_next(s.ring, s.ts_guest_ns, s.subject, &s.payload, s.span);
        let line = self.line(&record)?;
        if !self.has_room(line.len() as u64, QUOTA_RESERVE) {
            self.quota_pending = Some((line.len() as u64, 1));
            return Ok(());
        }
        self.commit(chain, &record, &line)?;
        self.consistent_len = self.segments.len();
        self.window.push(&record.hash);
        self.pending_since.get_or_insert_with(Instant::now);
        self.subscribers.publish(record);
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

    fn prepare_next(
        &self,
        ring: Ring,
        ts_guest_ns: Option<u64>,
        subject: Option<Subject>,
        payload: &Payload,
        span: Option<SpanRef>,
    ) -> (Record, Chainer) {
        let (kind, data) = payload.into_parts();
        let mut chain = self.chain.clone();
        let record = chain.next(PartialRecord {
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
        });
        (record, chain)
    }

    fn commit(&mut self, chain: Chainer, record: &Record, line: &[u8]) -> FileResult<(u32, u64)> {
        self.chain = chain;
        self.shared
            .next_seq
            .store(record.seq + 1, Ordering::Relaxed);
        self.append_line(line)
    }

    fn line(&self, record: &Record) -> FileResult<Vec<u8>> {
        let mut line = serde_json::to_vec(record)
            .map_err(|e| on("write to", self.segments.path())(e.into()))?;
        line.push(b'\n');
        Ok(line)
    }

    /// Appends a serialized record; returns its segment and offset.
    fn append_line(&mut self, line: &[u8]) -> FileResult<(u32, u64)> {
        let at = self.segments.append(line)?;
        self.written += 1;
        Ok(at)
    }

    fn has_room(&self, bytes: u64, reserve: u64) -> bool {
        self.max_bytes == 0
            || self
                .segments
                .total_len()
                .saturating_add(self.index.len())
                .saturating_add(bytes)
                .saturating_add(reserve)
                <= self.max_bytes
    }

    /// Chains a checkpoint over the window, syncs it to disk, then lists it
    /// in `checkpoints.jsonl`. Only then is the log consistent after it.
    fn checkpoint(&mut self) -> FileResult<()> {
        let (record, chain, checkpoint, line, index_bytes) = self.next_checkpoint()?;
        let bytes = (line.len() as u64).saturating_add(index_bytes);
        if !self.has_room(bytes, QUOTA_RESERVE) {
            self.quota_pending = Some((bytes, 0));
            return Ok(());
        }
        self.commit_checkpoint(record, chain, checkpoint, &line)
    }

    fn next_checkpoint(
        &self,
    ) -> FileResult<(Record, Chainer, boxcar_proto::Checkpoint, Vec<u8>, u64)> {
        let dropped = self.shared.dropped.load(Ordering::Relaxed);
        let mut window = self.window.clone();
        let checkpoint = window.take(dropped.saturating_sub(self.dropped_reported));
        let payload = Payload::Checkpoint(checkpoint.clone());
        let (record, chain) = self.prepare_next(Ring::Host, None, None, &payload, None);
        let line = self.line(&record)?;
        let entry = IndexEntry::new(
            record.seq,
            self.segments.segment(),
            self.segments.len(),
            &checkpoint,
        );
        let index_bytes = self.index.entry_len(&entry)?;
        Ok((record, chain, checkpoint, line, index_bytes))
    }

    fn commit_checkpoint(
        &mut self,
        record: Record,
        chain: Chainer,
        checkpoint: boxcar_proto::Checkpoint,
        line: &[u8],
    ) -> FileResult<()> {
        let (segment, offset) = self.commit(chain, &record, line)?;
        self.segments.sync()?;
        self.index
            .append(&IndexEntry::new(record.seq, segment, offset, &checkpoint))?;
        self.consistent_len = self.segments.len();
        self.window = Window::default();
        self.dropped_reported = self.dropped_reported.saturating_add(checkpoint.dropped);
        self.pending_since = None;
        self.subscribers.publish(record);
        Ok(())
    }

    fn checkpoint_without_reserve(&mut self) -> FileResult<()> {
        let (record, chain, checkpoint, line, _) = self.next_checkpoint()?;
        self.commit_checkpoint(record, chain, checkpoint, &line)
    }

    fn finish_quota(&mut self, rx: &Receiver<Msg>) -> FileResult<()> {
        let Some((next_record_bytes, current_pending)) = self.quota_pending.take() else {
            return Ok(());
        };
        let pending_records = current_pending.saturating_add(self.shared.close_and_drain(rx));
        self.quota_reached(next_record_bytes, pending_records)
    }

    /// Writes the terminal limit record and the checkpoint that covers it,
    /// then ends the writer through its ordinary failure path so the VMM's
    /// audit eventfd stops the session.
    fn quota_reached(&mut self, next_record_bytes: u64, pending_records: u64) -> FileResult<()> {
        let written_bytes = self.segments.total_len().saturating_add(self.index.len());
        let payload = Payload::VmmAuditLimit(VmmAuditLimit {
            max_bytes: self.max_bytes,
            written_bytes,
            next_record_bytes,
            pending_records,
        });
        let (record, chain) = self.prepare_next(Ring::Host, None, None, &payload, None);
        let line = self.line(&record)?;
        self.commit(chain, &record, &line)?;
        self.consistent_len = self.segments.len();
        self.window.push(&record.hash);
        self.pending_since.get_or_insert_with(Instant::now);
        self.subscribers.publish(record);
        self.checkpoint_without_reserve()?;
        self.segments.sync()?;
        self.index.sync()?;
        debug_assert!(
            self.max_bytes == 0
                || self.segments.total_len().saturating_add(self.index.len()) <= self.max_bytes
        );
        Err(FileError {
            op: "write to",
            path: self.segments.path().to_owned(),
            error: io::Error::new(
                io::ErrorKind::StorageFull,
                format!("audit log byte limit {} reached", self.max_bytes),
            ),
        })
    }

    /// Ends the current segment with a checkpoint and starts the next. The
    /// index is synced first, so every sealed segment is listed durably.
    fn seal(&mut self) -> FileResult<()> {
        if !self.window.is_empty() {
            self.checkpoint()?;
            if self.quota_pending.is_some() {
                return Ok(());
            }
        }
        self.index.sync()?;
        self.segments.rotate()?;
        self.consistent_len = 0;
        Ok(())
    }

    /// The final checkpoint, for whatever the last one does not cover.
    fn finish(&mut self) -> FileResult<CloseStats> {
        let dropped = self.shared.dropped.load(Ordering::Relaxed);
        if !self.window.is_empty() || dropped > self.dropped_reported {
            self.checkpoint_without_reserve()?;
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

#[cfg(test)]
mod tests {
    use boxcar_proto::{Checkpoint, Source};

    use super::*;

    fn partial(session_id: &SessionId, payload: &Payload) -> PartialRecord {
        let (kind, data) = payload.into_parts();
        PartialRecord {
            session_id: session_id.clone(),
            ring: Ring::Host,
            src: Source::Vmm,
            kind,
            ts_host_ns: u64::MAX,
            ts_mono_ns: u64::MAX,
            ts_guest_ns: None,
            subject: None,
            data,
            span: None,
        }
    }

    #[test]
    fn the_session_limit_reserve_holds_its_terminal_entries() {
        let session_id = SessionId::new();
        let mut chain = Chainer::resume(u64::MAX - 2, Hash([0xff; 32]));
        let limit = Payload::VmmAuditLimit(VmmAuditLimit {
            max_bytes: u64::MAX,
            written_bytes: u64::MAX,
            next_record_bytes: u64::MAX,
            pending_records: u64::MAX,
        });
        let limit = chain.next(partial(&session_id, &limit));
        let checkpoint = Payload::Checkpoint(Checkpoint {
            records_since: u64::MAX,
            dropped: u64::MAX,
            root_hash: Hash([0xff; 32]),
        });
        let checkpoint = chain.next(partial(&session_id, &checkpoint));
        let bytes = serde_json::to_vec(&limit).unwrap().len()
            + 1
            + serde_json::to_vec(&checkpoint).unwrap().len()
            + 1
            + serde_json::to_vec(&IndexEntry::new(
                u64::MAX,
                u32::MAX,
                u64::MAX,
                &Checkpoint {
                    records_since: u64::MAX,
                    dropped: u64::MAX,
                    root_hash: Hash([0xff; 32]),
                },
            ))
            .unwrap()
            .len()
            + 1;
        assert!(bytes <= QUOTA_RESERVE as usize, "{bytes}");
    }
}
