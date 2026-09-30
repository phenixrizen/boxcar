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
//!
//! `hash_status` says how that went: `ok` (with `blake3` and `size`), `raced`
//! (the file changed, or the path now names another file), `gone` (the path
//! no longer exists), `skipped_size` (larger than `hash_max_bytes`, with
//! `size`), or `error` (anything else, such as a path that now crosses a
//! symlink or leaves the share).
//!
//! The job queue is bounded. When it is full, `release` waits for room: the
//! close is a never-drop event, and this is the same back-pressure `emit`
//! applies to the audit channel.

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

/// What the threads share.
struct Shared {
    root: OwnedFd,
    max_bytes: u64,
    events: Arc<Events>,
    /// Jobs submitted and not yet recorded.
    pending: Mutex<u64>,
    idle: Condvar,
}

impl Shared {
    fn pending(&self) -> MutexGuard<'_, u64> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hashes the job's file and records its close.
    fn run(&self, job: HashJob) {
        let outcome = hash_file(&self.root, &job.rel_path, job.expected, self.max_bytes);
        let close = FsClose {
            size: outcome.size,
            blake3: outcome.blake3,
            hash_status: outcome.status,
            ..job.close
        };
        self.events
            .record(Some(job.subject), Payload::FsClose(close));
        let mut pending = self.pending();
        *pending = pending.saturating_sub(1);
        if *pending == 0 {
            self.idle.notify_all();
        }
    }
}

/// The hashing threads of one share.
pub struct HashWorker {
    shared: Arc<Shared>,
    /// `None` once shut down, or when no thread could be started; jobs are
    /// then hashed on the caller's thread.
    tx: Mutex<Option<Sender<HashJob>>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl HashWorker {
    /// Starts the threads, named `fs-<tag>-hash<N>`. `root` is the share's
    /// host directory; files larger than `max_bytes` are not hashed.
    pub(crate) fn new(tag: &str, root: OwnedFd, max_bytes: u64, events: Arc<Events>) -> Self {
        let shared = Arc::new(Shared {
            root,
            max_bytes,
            events,
            pending: Mutex::new(0),
            idle: Condvar::new(),
        });
        let (tx, rx) = bounded::<HashJob>(QUEUE);
        let mut threads = Vec::with_capacity(THREADS);
        for n in 0..THREADS {
            let (shared, rx) = (Arc::clone(&shared), rx.clone());
            let spawned = thread::Builder::new()
                .name(format!("fs-{tag}-hash{n}"))
                .spawn(move || serve(&shared, &rx));
            match spawned {
                Ok(handle) => threads.push(handle),
                Err(error) => tracing::error!(tag, "starting a hash thread failed: {error}"),
            }
        }
        if threads.is_empty() {
            tracing::error!(tag, "no hash thread started; closes are hashed inline");
        }
        let tx = (!threads.is_empty()).then_some(tx);
        HashWorker {
            shared,
            tx: Mutex::new(tx),
            threads: Mutex::new(threads),
        }
    }

    /// Queues a job, waiting while the queue is full.
    pub fn submit(&self, job: HashJob) {
        *self.shared.pending() += 1;
        let tx = self
            .tx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let job = match tx {
            Some(tx) => match tx.send(job) {
                Ok(()) => return,
                Err(returned) => returned.into_inner(),
            },
            None => job,
        };
        self.shared.run(job);
    }

    /// Returns once every job submitted so far has been recorded.
    pub fn flush(&self) {
        let mut pending = self.shared.pending();
        while *pending > 0 {
            pending = self
                .shared
                .idle
                .wait(pending)
                .unwrap_or_else(PoisonError::into_inner);
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

fn serve(shared: &Shared, rx: &Receiver<HashJob>) {
    // Ends when every sender is gone and the queue is empty.
    for job in rx.iter() {
        shared.run(job);
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
}
