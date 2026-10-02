// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Content hashes for `fs.close`, computed off the FUSE reply path.
//!
//! `release` hands a [`HashJob`] to the [`HashWorker`] and replies at once.
//! One of the worker's two threads opens the file again, beneath the share
//! root, hashes it with blake3, and records the `fs.close`:
//!
//! - it opens with `openat2(root, rel_path)` and `RESOLVE_BENEATH |
//!   RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, so a guest that swapped a
//!   path component for a symlink after the close cannot make the host read
//!   anything outside the share. The flags are `O_RDONLY | O_CLOEXEC |
//!   O_NOFOLLOW | O_NONBLOCK`: `O_NONBLOCK` because a guest can also replace
//!   the file with a FIFO, and a blocking open of a FIFO would hang the
//!   thread until something writes to it.
//! - it `fstat`s before and after reading. The file must still be the host
//!   file the guest closed (same `st_dev` and `st_ino`) and a regular file;
//!   its size and mtime must not change while it is read, and exactly its
//!   size must be read.
//! - the fstat checks catch only a change made while the file is read. A
//!   change made after the close but before the hash starts, through
//!   another handle, is caught by `Generations`: from the close on, the
//!   job watches its file, every write, truncate, fallocate or create that
//!   reaches the file moves the file's generation, and a hash whose file's
//!   generation moved is `raced`, not `ok`.
//!
//! `hash_status` says how that went: `ok` (with `blake3` and `size`), `raced`
//! (the file changed after the close, or the path now names another file),
//! `gone` (the path no longer exists), `skipped_size` (larger than
//! `hash_max_bytes`, with `size`), or `error` (anything else, such as a path
//! that now crosses a symlink or leaves the share).
//!
//! The job queue is bounded, and when it is full `release` waits for room.
//! That bounded wait on the reply path is deliberate: dropping hashes when
//! the queue is full would let a guest dodge them by flooding closes, while
//! waiting slows down only the guest doing the flooding. It is the same
//! back-pressure `emit` applies to every never-drop event.
//!
//! If no worker thread could be started, jobs are hashed inline on the
//! thread that submits them. That is a degenerate case, logged at error
//! level, not a mode of operation.
//!
//! A worker that panics dies, but the job it held still counts as done, so
//! [`HashWorker::flush`] cannot wait for it forever, and its close is still
//! recorded, with `hash_status` `error` and no hash; `flush` also returns
//! once every worker has stopped, leaving any jobs still queued unhashed.
//!
//! [`HashWorker::shutdown`] (a device reset) stops the threads; a later
//! [`HashWorker::restart`] (the next activation) starts them again, so a
//! guest that resets its virtio-fs driver mid-session does not leave the
//! closes hashed inline for the rest of the session.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

use boxcar_proto::{FsClose, Hash, HashStatus, Payload, Subject};
use crossbeam_channel::{bounded, Receiver, Sender};

use crate::events::Events;
use crate::path_map::FileId;

/// Threads hashing closed files.
const THREADS: usize = 2;
/// Jobs queued before `release` waits.
const QUEUE: usize = 1024;

/// `struct open_how` from `linux/openat2.h`: three u64s.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// One closed file to hash.
#[derive(Debug)]
pub struct HashJob {
    /// The file's path under the share root, without a leading `/`.
    pub rel_path: CString,
    /// The host file the guest closed, when known. A path that now names a
    /// different file is not hashed.
    pub expected: Option<FileId>,
    /// Whom the close is attributed to.
    pub subject: Subject,
    /// The record to complete: everything but `size`, `blake3` and
    /// `hash_status`.
    pub close: FsClose,
    /// The file's generation as of the close; a hash made after it moved is
    /// `raced`.
    pub(crate) watch: Option<Watch>,
}

/// A file as [`Generations`] tells files apart: by its host identity when
/// that is known, else by its inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FileKey {
    Host(FileId),
    Inode(u64),
}

impl FileKey {
    pub(crate) fn of(ino: u64, host: Option<FileId>) -> Self {
        host.map_or(FileKey::Inode(ino), FileKey::Host)
    }
}

/// Content changes to the files whose close is waiting to be hashed.
///
/// Only files a queued hash [`watch`](Generations::watch)es are tracked:
/// an entry lives from the first close that queues a hash of the file
/// until the last such hash is done, so the table holds at most as many
/// files as there are jobs.
#[derive(Debug, Default)]
pub(crate) struct Generations {
    files: Mutex<HashMap<FileKey, Tracked>>,
}

#[derive(Debug)]
struct Tracked {
    generation: u64,
    /// Queued hashes watching the file.
    watchers: u32,
}

impl Generations {
    fn lock(&self) -> MutexGuard<'_, HashMap<FileKey, Tracked>> {
        // Every update leaves the table consistent.
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The file's content may have changed. Moves its generation if a hash
    /// of it is pending; otherwise nothing is tracked.
    pub(crate) fn changed(&self, key: FileKey) {
        if let Some(tracked) = self.lock().get_mut(&key) {
            tracked.generation = tracked.generation.wrapping_add(1);
        }
    }

    /// Starts watching the file for a hash about to be queued.
    pub(crate) fn watch(self: &Arc<Self>, key: FileKey) -> Watch {
        let mut files = self.lock();
        let tracked = files.entry(key).or_insert(Tracked {
            generation: 0,
            watchers: 0,
        });
        tracked.watchers += 1;
        Watch {
            files: Arc::clone(self),
            key,
            generation: tracked.generation,
        }
    }
}

/// One queued hash's watch on its file. Dropping it stops watching.
#[derive(Debug)]
pub(crate) struct Watch {
    files: Arc<Generations>,
    key: FileKey,
    generation: u64,
}

impl Watch {
    /// Whether nothing changed the file since the watch began.
    fn unchanged(&self) -> bool {
        self.files
            .lock()
            .get(&self.key)
            .is_some_and(|tracked| tracked.generation == self.generation)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let mut files = self.files.lock();
        if let Some(tracked) = files.get_mut(&self.key) {
            tracked.watchers = tracked.watchers.saturating_sub(1);
            if tracked.watchers == 0 {
                files.remove(&self.key);
            }
        }
    }
}

/// What hashing one file found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashOutcome {
    pub size: Option<u64>,
    pub blake3: Option<Hash>,
    pub status: HashStatus,
}

impl HashOutcome {
    fn status(status: HashStatus) -> Self {
        HashOutcome {
            size: None,
            blake3: None,
            status,
        }
    }

    fn sized(status: HashStatus, size: u64) -> Self {
        HashOutcome {
            size: Some(size),
            ..Self::status(status)
        }
    }
}

/// How a job's file is hashed: [`hash_file`], except in tests.
pub(crate) type HashFn = fn(&OwnedFd, &CString, Option<FileId>, u64) -> HashOutcome;

/// Jobs and threads, counted under one lock.
#[derive(Debug, Default)]
struct Counts {
    /// Jobs submitted and not yet finished.
    pending: u64,
    /// Of those, jobs being hashed on a submitting thread.
    inline: u64,
    /// Worker threads still running.
    alive: usize,
}

/// What the threads share.
struct Shared {
    root: OwnedFd,
    max_bytes: u64,
    events: Arc<Events>,
    hash: HashFn,
    counts: Mutex<Counts>,
    /// Signalled whenever a job finishes or a worker stops.
    changed: Condvar,
}

impl Shared {
    fn counts(&self) -> MutexGuard<'_, Counts> {
        // Every update leaves the counts consistent.
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hashes the job's file and records its close. A panic on the way
    /// (the hash function's, or the record's) records the close as
    /// `error`, so a handle the guest released never goes unrecorded.
    fn run(&self, job: HashJob, inline: bool) {
        // Counts the job as finished however this ends, a panic included,
        // and records the close itself if the panic came first.
        let mut finished = Finished {
            shared: self,
            inline,
            unrecorded: Some((job.subject, job.close.clone())),
        };
        let mut outcome = (self.hash)(&self.root, &job.rel_path, job.expected, self.max_bytes);
        let moved = job.watch.as_ref().is_some_and(|watch| !watch.unchanged());
        if outcome.status == HashStatus::Ok && moved {
            // The content read is not the content the closer left.
            outcome = HashOutcome {
                size: outcome.size,
                blake3: None,
                status: HashStatus::Raced,
            };
        }
        let close = FsClose {
            size: outcome.size,
            blake3: outcome.blake3,
            hash_status: outcome.status,
            ..job.close
        };
        // Recorded: the guard has nothing to record.
        finished.unrecorded = None;
        self.events
            .record(Some(job.subject), Payload::FsClose(close));
    }
}

/// Counts one job as finished when dropped, and records its close as
/// `error` if it was not recorded (the thread panicked on the way).
struct Finished<'a> {
    shared: &'a Shared,
    inline: bool,
    unrecorded: Option<(Subject, FsClose)>,
}

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        if let Some((subject, close)) = self.unrecorded.take() {
            let close = FsClose {
                size: None,
                blake3: None,
                hash_status: HashStatus::Error,
                ..close
            };
            self.shared
                .events
                .record(Some(subject), Payload::FsClose(close));
        }
        let mut counts = self.shared.counts();
        counts.pending = counts.pending.saturating_sub(1);
        if self.inline {
            counts.inline = counts.inline.saturating_sub(1);
        }
        self.shared.changed.notify_all();
    }
}

/// Counts one worker as stopped when dropped, whether its thread returns
/// or unwinds.
struct Alive<'a>(&'a Shared);

impl Drop for Alive<'_> {
    fn drop(&mut self) {
        let mut counts = self.0.counts();
        counts.alive = counts.alive.saturating_sub(1);
        self.0.changed.notify_all();
    }
}

/// The hashing threads of one share.
pub struct HashWorker {
    shared: Arc<Shared>,
    /// The share's tag, which names the threads.
    tag: String,
    /// `None` once shut down, or when no thread could be started; jobs are
    /// then hashed on the caller's thread.
    tx: Mutex<Option<Sender<HashJob>>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl HashWorker {
    /// Starts the threads, named `fs-<tag>-hash<N>`, which hash with `hash`
    /// ([`hash_file`], except in tests). `root` is the share's host
    /// directory; files larger than `max_bytes` are not hashed.
    pub(crate) fn with_hash(
        tag: &str,
        root: OwnedFd,
        max_bytes: u64,
        events: Arc<Events>,
        hash: HashFn,
    ) -> Self {
        let shared = Arc::new(Shared {
            root,
            max_bytes,
            events,
            hash,
            counts: Mutex::new(Counts::default()),
            changed: Condvar::new(),
        });
        let (tx, threads) = start_threads(&shared, tag);
        HashWorker {
            shared,
            tag: tag.to_owned(),
            tx: Mutex::new(tx),
            threads: Mutex::new(threads),
        }
    }

    /// Starts the threads again after [`shutdown`](Self::shutdown); does
    /// nothing while they run. Jobs submitted from now on go to them.
    pub fn restart(&self) {
        let mut tx = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
        if tx.is_some() {
            return;
        }
        let mut threads = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
        // Threads of a run that ended on their own (a panic) are joined
        // here, so none is left behind.
        for thread in threads.drain(..) {
            if thread.join().is_err() {
                tracing::error!(tag = self.tag, "a hash thread panicked");
            }
        }
        let (sender, started) = start_threads(&self.shared, &self.tag);
        *threads = started;
        *tx = sender;
    }

    /// How many hash threads are running.
    pub fn threads_alive(&self) -> usize {
        self.shared.counts().alive
    }

    /// Queues a job, waiting while the queue is full (see the module docs).
    /// With no worker left to take it, the job is hashed on this thread.
    pub fn submit(&self, job: HashJob) {
        self.shared.counts().pending += 1;
        let tx = self
            .tx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let job = match tx {
            Some(tx) => match tx.send(job) {
                Ok(()) => return,
                // Every worker has stopped.
                Err(returned) => returned.into_inner(),
            },
            None => job,
        };
        self.shared.counts().inline += 1;
        self.shared.run(job, true);
    }

    /// Returns once every job submitted so far has been recorded, or, if
    /// every worker has stopped, once no job is left that anything will
    /// finish.
    pub fn flush(&self) {
        let mut counts = self.shared.counts();
        while counts.pending > 0 && (counts.alive > 0 || counts.inline > 0) {
            counts = self
                .shared
                .changed
                .wait(counts)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if counts.pending > 0 {
            tracing::error!(
                jobs = counts.pending,
                "every hash thread has stopped; queued closes were not recorded"
            );
        }
    }

    /// Finishes the queued jobs and stops the threads. Jobs submitted later
    /// are hashed on the caller's thread.
    pub fn shutdown(&self) {
        drop(
            self.tx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        let threads =
            std::mem::take(&mut *self.threads.lock().unwrap_or_else(PoisonError::into_inner));
        for thread in threads {
            if thread.join().is_err() {
                tracing::error!("a hash thread panicked");
            }
        }
    }
}

impl Drop for HashWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Starts [`THREADS`] threads named `fs-<tag>-hash<N>` serving a new queue,
/// and returns its sender (`None` when no thread could be started: jobs
/// are then hashed inline, which is logged) and the threads.
fn start_threads(
    shared: &Arc<Shared>,
    tag: &str,
) -> (Option<Sender<HashJob>>, Vec<JoinHandle<()>>) {
    let (tx, rx) = bounded::<HashJob>(QUEUE);
    let mut threads = Vec::with_capacity(THREADS);
    for n in 0..THREADS {
        let (worker, rx) = (Arc::clone(shared), rx.clone());
        // Counted before it starts, so no flush can see it missing.
        shared.counts().alive += 1;
        let spawned = thread::Builder::new()
            .name(format!("fs-{tag}-hash{n}"))
            .spawn(move || serve(&worker, &rx));
        match spawned {
            Ok(handle) => threads.push(handle),
            Err(error) => {
                shared.counts().alive -= 1;
                tracing::error!(tag, "starting a hash thread failed: {error}");
            }
        }
    }
    if threads.is_empty() {
        tracing::error!(tag, "no hash thread started; closes are hashed inline");
    }
    ((!threads.is_empty()).then_some(tx), threads)
}

fn serve(shared: &Shared, rx: &Receiver<HashJob>) {
    let _alive = Alive(shared);
    // Ends when every sender is gone and the queue is empty.
    for job in rx.iter() {
        shared.run(job, false);
    }
}

/// Hashes `rel_path` under `root`. See the module docs for the checks.
pub fn hash_file(
    root: &OwnedFd,
    rel_path: &CString,
    expected: Option<FileId>,
    max_bytes: u64,
) -> HashOutcome {
    let file = match open_beneath(root, rel_path) {
        Ok(file) => file,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            return HashOutcome::status(HashStatus::Gone)
        }
        Err(e) => {
            tracing::debug!(path = ?rel_path, "reopening a closed file to hash it failed: {e}");
            return HashOutcome::status(HashStatus::Error);
        }
    };
    let Ok(before) = fstat(&file) else {
        return HashOutcome::status(HashStatus::Error);
    };
    let size = u64::try_from(before.st_size).unwrap_or(0);
    let id = FileId {
        dev: before.st_dev,
        ino: before.st_ino,
    };
    if expected.is_some_and(|expected| expected != id) {
        return HashOutcome::sized(HashStatus::Raced, size);
    }
    if before.st_mode & libc::S_IFMT != libc::S_IFREG {
        return HashOutcome::status(HashStatus::Error);
    }
    if size > max_bytes {
        return HashOutcome::sized(HashStatus::SkippedSize, size);
    }
    let mut hasher = blake3::Hasher::new();
    // Never read more than the limit, even from a file growing under us.
    if let Err(e) = hasher.update_reader((&file).take(max_bytes)) {
        tracing::debug!(path = ?rel_path, "reading a closed file to hash it failed: {e}");
        return HashOutcome::sized(HashStatus::Error, size);
    }
    let Ok(after) = fstat(&file) else {
        return HashOutcome::sized(HashStatus::Error, size);
    };
    let unchanged = after.st_size == before.st_size
        && after.st_mtime == before.st_mtime
        && after.st_mtime_nsec == before.st_mtime_nsec
        && hasher.count() == size;
    if !unchanged {
        return HashOutcome::sized(HashStatus::Raced, size);
    }
    HashOutcome {
        size: Some(size),
        blake3: Some(Hash::from_blake3(hasher.finalize())),
        status: HashStatus::Ok,
    }
}

/// `openat2(root, rel_path)` for reading, resolved strictly beneath `root`
/// and through no symlink.
fn open_beneath(root: &OwnedFd, rel_path: &CString) -> io::Result<File> {
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `rel_path` is a NUL-terminated string and `how` a valid
    // `open_how` of the size passed; both outlive the call, and the kernel
    // only reads them.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            rel_path.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(fd).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))?;
    // SAFETY: openat2 just returned this descriptor, and nothing else owns
    // it.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn fstat(file: &File) -> io::Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();
    // SAFETY: `st` is valid, writable memory for one stat64, the only memory
    // fstat64 writes.
    let rc = unsafe { libc::fstat64(file.as_raw_fd(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat64 succeeded, so it filled in `st`.
    Ok(unsafe { st.assume_init() })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::time::Duration;

    use boxcar_audit::{spawn, LogReader, WriterConfig, WriterHandle};
    use boxcar_proto::{Attrib, SessionId};
    use tempfile::TempDir;

    use super::*;

    const MAX: u64 = 1024;

    fn root(dir: &TempDir) -> OwnedFd {
        OwnedFd::from(File::open(dir.path()).unwrap())
    }

    fn path(p: &str) -> CString {
        CString::new(p).unwrap()
    }

    fn id_of(p: &std::path::Path) -> FileId {
        let meta = fs::metadata(p).unwrap();
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    #[test]
    fn an_unchanged_file_hashes() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("d/f"), b"content").unwrap();
        let id = id_of(&dir.path().join("d/f"));
        let outcome = hash_file(&root(&dir), &path("d/f"), Some(id), MAX);
        assert_eq!(
            outcome,
            HashOutcome {
                size: Some(7),
                blake3: Some(Hash::from_blake3(blake3::hash(b"content"))),
                status: HashStatus::Ok,
            }
        );
        let unknown = hash_file(&root(&dir), &path("d/f"), None, MAX);
        assert_eq!(unknown.status, HashStatus::Ok);
    }

    #[test]
    fn a_missing_file_is_gone() {
        let dir = TempDir::new().unwrap();
        let outcome = hash_file(&root(&dir), &path("nothing"), None, MAX);
        assert_eq!(outcome, HashOutcome::status(HashStatus::Gone));
    }

    #[test]
    fn a_path_naming_another_file_raced() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a"), b"a").unwrap();
        fs::write(dir.path().join("b"), b"bb").unwrap();
        let other = id_of(&dir.path().join("b"));
        let outcome = hash_file(&root(&dir), &path("a"), Some(other), MAX);
        assert_eq!(outcome, HashOutcome::sized(HashStatus::Raced, 1));
    }

    #[test]
    fn symlinks_and_escapes_are_refused() {
        let dir = TempDir::new().unwrap();
        let share = dir.path().join("share");
        fs::create_dir(&share).unwrap();
        fs::write(dir.path().join("outside"), b"secret").unwrap();
        fs::write(share.join("inside"), b"x").unwrap();
        symlink("inside", share.join("link")).unwrap();
        fs::create_dir(share.join("sub")).unwrap();
        symlink("..", share.join("sub/up")).unwrap();
        let root = OwnedFd::from(File::open(&share).unwrap());
        for p in ["link", "../outside", "sub/up/inside", "/etc/passwd"] {
            let outcome = hash_file(&root, &path(p), None, MAX);
            assert_eq!(outcome, HashOutcome::status(HashStatus::Error), "{p}");
        }
    }

    #[test]
    fn a_fifo_or_directory_is_not_read() {
        let dir = TempDir::new().unwrap();
        let fifo = path(dir.path().join("fifo").to_str().unwrap());
        // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        fs::create_dir(dir.path().join("d")).unwrap();
        for p in ["fifo", "d"] {
            let outcome = hash_file(&root(&dir), &path(p), None, MAX);
            assert_eq!(outcome, HashOutcome::status(HashStatus::Error), "{p}");
        }
    }

    #[test]
    fn a_file_over_the_limit_is_skipped() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("big"), vec![1; 17]).unwrap();
        fs::write(dir.path().join("fits"), vec![1; 16]).unwrap();
        let outcome = hash_file(&root(&dir), &path("big"), None, 16);
        assert_eq!(outcome, HashOutcome::sized(HashStatus::SkippedSize, 17));
        let outcome = hash_file(&root(&dir), &path("fits"), None, 16);
        assert_eq!(outcome.status, HashStatus::Ok);
    }

    /// A worker for `dir` hashing with `hash`, and its audit log.
    fn worker(dir: &TempDir, hash: HashFn) -> (Arc<HashWorker>, WriterHandle) {
        let (sink, writer) =
            spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
        let events = Arc::new(Events::new(sink, "t".into()));
        let worker = HashWorker::with_hash("t", root(dir), MAX, events, hash);
        (Arc::new(worker), writer)
    }

    fn job(rel_path: &str, fh: u64) -> HashJob {
        HashJob {
            rel_path: path(rel_path),
            expected: None,
            subject: Subject {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            close: FsClose {
                mount: "t".into(),
                path: format!("/{rel_path}"),
                path_b64: None,
                path_at_open: format!("/{rel_path}"),
                fh,
                bytes_read: 0,
                bytes_written: 1,
                size: None,
                blake3: None,
                hash_status: HashStatus::NotHashed,
                open_seq: None,
                attrib: Attrib::Caller,
                ts_release_ns: 0,
            },
            watch: None,
        }
    }

    /// Fails the test instead of hanging it when `flush` does not return.
    fn flush_within(worker: &Arc<HashWorker>, limit: Duration) {
        let (done, flushed) = bounded(1);
        let worker = Arc::clone(worker);
        thread::spawn(move || {
            worker.flush();
            let _ = done.send(());
        });
        flushed.recv_timeout(limit).expect("flush returned");
    }

    /// The close records in the log, as `(fh, hash_status)`.
    fn closes(writer: WriterHandle) -> Vec<(u64, HashStatus)> {
        let session = writer.session_dir().to_owned();
        writer.close().unwrap();
        LogReader::open(&session)
            .unwrap()
            .records()
            .map(Result::unwrap)
            .filter_map(|r| match Payload::from_record(&r) {
                Ok(Payload::FsClose(c)) => Some((c.fh, c.hash_status)),
                _ => None,
            })
            .collect()
    }

    fn boom_or_hash(
        root: &OwnedFd,
        rel_path: &CString,
        expected: Option<FileId>,
        max: u64,
    ) -> HashOutcome {
        if rel_path.as_bytes() == b"boom" {
            panic!("hashing boom panicked");
        }
        hash_file(root, rel_path, expected, max)
    }

    #[test]
    fn a_job_that_panics_still_counts_as_finished() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("fine"), b"x").unwrap();
        let (worker, writer) = worker(&dir, boom_or_hash);
        worker.submit(job("boom", 1));
        flush_within(&worker, Duration::from_secs(10));
        // The other worker still hashes.
        worker.submit(job("fine", 2));
        flush_within(&worker, Duration::from_secs(10));
        assert_eq!(worker.shared.counts().pending, 0);
        worker.shutdown();
        // The job that panicked is recorded all the same, as `error`.
        assert_eq!(
            closes(writer),
            [(1, HashStatus::Error), (2, HashStatus::Ok)]
        );
    }

    #[test]
    fn generations_track_a_file_only_while_a_hash_watches_it() {
        let generations = Arc::new(Generations::default());
        let file = FileKey::Host(FileId { dev: 1, ino: 2 });
        let other = FileKey::Inode(9);
        // A change nothing watches is not remembered.
        generations.changed(file);
        assert!(generations.lock().is_empty());

        let first = generations.watch(file);
        assert!(first.unchanged());
        generations.changed(other);
        assert!(first.unchanged(), "another file's change");
        generations.changed(file);
        assert!(!first.unchanged());
        // A second close of the file watches from its own close.
        let second = generations.watch(file);
        assert!(second.unchanged());
        assert!(!first.unchanged());

        drop(first);
        assert_eq!(generations.lock().len(), 1);
        drop(second);
        assert!(
            generations.lock().is_empty(),
            "the last watch takes the entry away"
        );
    }

    static GATE: Mutex<bool> = Mutex::new(false);
    static GATE_OPENED: Condvar = Condvar::new();

    /// Waits until the gate opens, then panics.
    fn panic_after_the_gate(_: &OwnedFd, _: &CString, _: Option<FileId>, _: u64) -> HashOutcome {
        let mut open = GATE.lock().unwrap();
        while !*open {
            open = GATE_OPENED.wait(open).unwrap();
        }
        drop(open);
        panic!("hashing panicked");
    }

    #[test]
    fn flush_returns_once_every_worker_has_stopped() {
        let dir = TempDir::new().unwrap();
        let (worker, writer) = worker(&dir, panic_after_the_gate);
        // Each worker takes one job and panics on it; the third job is
        // still queued when the last one dies.
        for fh in 1..=3 {
            worker.submit(job("f", fh));
        }
        *GATE.lock().unwrap() = true;
        GATE_OPENED.notify_all();
        flush_within(&worker, Duration::from_secs(10));
        {
            let counts = worker.shared.counts();
            assert_eq!((counts.pending, counts.alive), (1, 0), "{counts:?}");
        }
        worker.shutdown();
        // The two jobs the workers died on are recorded as `error` (in the
        // order the threads died); the queued one is not.
        let mut recorded = closes(writer);
        recorded.sort_unstable_by_key(|(fh, _)| *fh);
        assert_eq!(recorded, [(1, HashStatus::Error), (2, HashStatus::Error)]);
    }
}
