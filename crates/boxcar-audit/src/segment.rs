// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session directory and its segment files: layout, appending, rotation,
//! and torn-tail recovery.
//!
//! ```text
//! <data_dir>/sessions/<session_id>/
//!   meta.json            {"v":1,"session_id":..,"created_ts_host_ns":..,"boxcar_version":..,
//!                         "segments":N,"recovered_from_seq":null|N}
//!   events.000001.jsonl  the log, one record per line; the highest number is
//!   events.000002.jsonl  the segment being written
//!   checkpoints.jsonl    one line per checkpoint record (see `checkpoint`)
//! ```
//!
//! A segment is sealed once it holds `segment_max_bytes` or more: the writer
//! ends it with a checkpoint, syncs it, and starts the next one. The chain
//! runs on across segments; the first record of a segment names the last
//! record of the one before as its `prev`.
//!
//! Every directory the writer creates gets mode [`DIR_MODE`] and every file
//! [`FILE_MODE`], whatever the process umask: `PassthroughFs::import` sets
//! the umask to 0 for the whole process, and the log must not become
//! writable by others once a share is imported.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use boxcar_proto::{genesis_prev, Hash, SessionId};
use serde::{Deserialize, Serialize};

use crate::checkpoint::{IndexEntry, Window};
use crate::verify::RawLine;
use crate::writer::realtime_ns;

pub(crate) const META_FILE: &str = "meta.json";
const META_TMP: &str = "meta.json.tmp";
/// The mode of every directory the writer creates, the session's included.
pub(crate) const DIR_MODE: u32 = 0o700;
/// The mode of every file the writer creates.
pub(crate) const FILE_MODE: u32 = 0o600;
const WRITE_BUFFER: usize = 256 * 1024;

/// Makes a segment's written bytes durable. The writer calls it for every
/// segment sync, so a test can observe exactly when the log is synced.
pub trait Syncer {
    fn sync(&self, file: &File) -> io::Result<()>;
}

/// The real [`Syncer`]: `fdatasync(2)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fdatasync;

impl Syncer for Fdatasync {
    fn sync(&self, file: &File) -> io::Result<()> {
        file.sync_data()
    }
}

/// `meta.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Meta {
    pub(crate) v: u8,
    pub(crate) session_id: SessionId,
    pub(crate) created_ts_host_ns: u64,
    pub(crate) boxcar_version: String,
    /// How many segment files the session has.
    pub(crate) segments: u32,
    /// Set when the writer last cut a torn tail: the seq of the last record
    /// it kept, after which the chain resumed.
    pub(crate) recovered_from_seq: Option<u64>,
}

/// `events.000001.jsonl` for 1.
pub(crate) fn segment_name(n: u32) -> String {
    format!("events.{n:06}.jsonl")
}

/// The number of a segment file name, which must be spelled exactly as
/// [`segment_name`] spells it.
fn segment_number(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("events.")?.strip_suffix(".jsonl")?;
    let n: u32 = digits.parse().ok()?;
    (n > 0 && segment_name(n) == name).then_some(n)
}

/// The segment numbers present in `dir`, ascending.
pub(crate) fn list_segments(dir: &Path) -> io::Result<Vec<u32>> {
    let mut numbers = Vec::new();
    for entry in fs::read_dir(dir)? {
        if let Some(n) = entry?.file_name().to_str().and_then(segment_number) {
            numbers.push(n);
        }
    }
    numbers.sort_unstable();
    Ok(numbers)
}

/// Whether `numbers` is exactly 1, 2, ..., N.
pub(crate) fn numbered_from_one(numbers: &[u32]) -> bool {
    numbers.iter().zip(1..).all(|(&n, want)| n == want)
}

pub(crate) fn read_meta(dir: &Path) -> io::Result<Meta> {
    let path = dir.join(META_FILE);
    let bytes = fs::read(&path)?;
    serde_json::from_slice(&bytes).map_err(|e| invalid_data(format!("{}: {e}", path.display())))
}

/// Replaces `meta.json` atomically: a temporary file, synced, renamed over
/// the old one, then the directory synced.
fn write_meta(dir: &Path, meta: &Meta) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(meta)?;
    bytes.push(b'\n');
    let tmp = dir.join(META_TMP);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, dir.join(META_FILE))?;
    sync_dir(dir)
}

/// Makes the directory's entries (new, renamed or removed names) durable.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub(crate) fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The last complete line of a file and the offset it starts at, without its
/// newline. A partial line after the last newline is ignored.
pub(crate) fn last_line(path: &Path) -> io::Result<Option<(u64, Vec<u8>)>> {
    const CHUNK: u64 = 64 * 1024;
    let file = File::open(path)?;
    let mut newlines = Vec::with_capacity(2);
    let mut chunk = vec![0; CHUNK as usize];
    let mut pos = file.metadata()?.len();
    while pos > 0 && newlines.len() < 2 {
        let start = pos.saturating_sub(CHUNK);
        let buf = &mut chunk[..(pos - start) as usize];
        file.read_exact_at(buf, start)?;
        for (i, &byte) in buf.iter().enumerate().rev() {
            if byte == b'\n' {
                newlines.push(start + i as u64);
                if newlines.len() == 2 {
                    break;
                }
            }
        }
        pos = start;
    }
    let Some(&end) = newlines.first() else {
        return Ok(None);
    };
    let start = newlines.get(1).map_or(0, |p| p + 1);
    let mut line = vec![0; (end - start) as usize];
    file.read_exact_at(&mut line, start)?;
    Ok(Some((start, line)))
}

/// Where the log stands after `open_or_create`.
pub(crate) struct Resume {
    /// The last record's seq, 0 for an empty log.
    pub(crate) last_seq: u64,
    /// The last record's hash, the genesis hash for an empty log.
    pub(crate) last_hash: Hash,
    /// The records after the last checkpoint.
    pub(crate) window: Window,
    /// The checkpoint records in the last segment, in order.
    pub(crate) checkpoints: Vec<IndexEntry>,
}

/// Appends records to the session's current segment and rotates segments.
/// It holds an exclusive lock on the session directory for as long as it
/// lives, so a session has one writer at a time.
pub struct SegmentWriter<S: Syncer = Fdatasync> {
    dir: PathBuf,
    meta: Meta,
    syncer: S,
    /// The current segment's number.
    number: u32,
    out: BufWriter<File>,
    /// Bytes in the current segment, buffered ones included.
    len: u64,
    /// Whether bytes were appended since the last sync.
    dirty: bool,
    _lock: File,
}

impl<S: Syncer> SegmentWriter<S> {
    /// Opens the session in `dir` for appending, creating it if it does not
    /// exist.
    ///
    /// For an existing session this performs torn-tail recovery on the last
    /// segment: it keeps the longest prefix of complete lines that parse and
    /// continue the chain (the right `seq`, the right `prev`, and a `hash`
    /// that matches the line), truncates the file after that prefix, and
    /// records the seq of the last kept record in `meta.json` as
    /// `recovered_from_seq` when anything was cut.
    pub fn open_or_create(
        dir: &Path,
        session_id: &SessionId,
        syncer: S,
    ) -> io::Result<(Self, Resume)> {
        if !dir.exists() {
            // The mode applies to every directory created on the way.
            DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(dir)?;
            if let Some(parent) = dir.parent() {
                sync_dir(parent)?;
            }
        }
        let lock = File::open(dir)?;
        lock.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{}: the session already has a writer", dir.display()),
            ),
            TryLockError::Error(e) => e,
        })?;

        let segments = list_segments(dir)?;
        let meta = match read_meta(dir) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound && segments.is_empty() => {
                return Self::create(dir, session_id, syncer, lock);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(invalid_data(format!(
                    "{}: segment files but no {META_FILE}",
                    dir.display()
                )));
            }
            Err(e) => return Err(e),
        };
        if meta.v != 1 || meta.session_id != *session_id {
            return Err(invalid_data(format!(
                "{}: {META_FILE} is for session {} (v{}), not {session_id} (v1)",
                dir.display(),
                meta.session_id,
                meta.v
            )));
        }
        Self::recover(dir, meta, &segments, syncer, lock)
    }

    fn create(
        dir: &Path,
        session_id: &SessionId,
        syncer: S,
        lock: File,
    ) -> io::Result<(Self, Resume)> {
        // meta.json first: a crash before the segment exists leaves a
        // session that `recover` can finish.
        let meta = Meta {
            v: 1,
            session_id: session_id.clone(),
            created_ts_host_ns: realtime_ns(),
            boxcar_version: env!("CARGO_PKG_VERSION").to_owned(),
            segments: 1,
            recovered_from_seq: None,
        };
        write_meta(dir, &meta)?;
        let file = create_segment(dir, 1)?;
        let writer = SegmentWriter::new(dir, meta, syncer, 1, file, 0, lock);
        let resume = Resume {
            last_seq: 0,
            last_hash: genesis_prev(session_id),
            window: Window::default(),
            checkpoints: Vec::new(),
        };
        Ok((writer, resume))
    }

    fn recover(
        dir: &Path,
        mut meta: Meta,
        segments: &[u32],
        syncer: S,
        lock: File,
    ) -> io::Result<(Self, Resume)> {
        let found = segments.len() as u32;
        if !numbered_from_one(segments) {
            return Err(invalid_data(format!(
                "{}: segment files are not numbered 1 to {found}",
                dir.display()
            )));
        }
        // A crash can leave meta.json one segment behind (the next segment
        // is created before meta.json names it), or leave a new session
        // without its first segment. Anything else is not the writer's doing.
        let number = match found {
            0 if meta.segments == 1 => {
                create_segment(dir, 1)?;
                1
            }
            n if n > 0 && (n == meta.segments || n == meta.segments + 1) => n,
            n => {
                return Err(invalid_data(format!(
                    "{}: {META_FILE} lists {} segments, found {n}",
                    dir.display(),
                    meta.segments
                )));
            }
        };

        // Where the chain stands before the last segment.
        let session = meta.session_id.as_str().to_owned();
        let (mut next_seq, mut prev) = if number == 1 {
            (1, genesis_prev(&meta.session_id))
        } else {
            let path = dir.join(segment_name(number - 1));
            let (_, line) = last_line(&path)?
                .ok_or_else(|| invalid_data(format!("{}: empty sealed segment", path.display())))?;
            let raw = RawLine::parse(&line)
                .ok()
                .filter(|raw| raw.hash == raw.computed)
                .filter(|raw| matches!(raw.check_envelope(&session), Ok(Some(_))))
                .ok_or_else(|| {
                    invalid_data(format!(
                        "{}: does not end with an intact checkpoint record; cannot resume",
                        path.display()
                    ))
                })?;
            (raw.seq + 1, raw.hash)
        };

        // Keep the longest prefix of the last segment that continues it.
        let path = dir.join(segment_name(number));
        let mut reader = BufReader::with_capacity(1 << 20, File::open(&path)?);
        let mut window = Window::default();
        let mut checkpoints = Vec::new();
        let mut kept = 0u64;
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)?;
            let Some(body) = line.strip_suffix(b"\n") else {
                break; // end of file, or a partial line
            };
            let Ok(raw) = RawLine::parse(body) else {
                break;
            };
            if raw.seq != next_seq || raw.prev != prev || raw.hash != raw.computed {
                break;
            }
            match raw.check_envelope(&session) {
                Ok(Some(checkpoint)) => {
                    checkpoints.push(IndexEntry::new(raw.seq, number, kept, &checkpoint));
                    window = Window::default();
                }
                Ok(None) => window.push(&raw.hash),
                Err(_) => break,
            }
            next_seq += 1;
            prev = raw.hash;
            kept += n as u64;
        }
        drop(reader);

        let file = OpenOptions::new().append(true).open(&path)?;
        let len = file.metadata()?.len();
        let mut rewrite_meta = meta.segments != number;
        if kept < len {
            file.set_len(kept)?;
            syncer.sync(&file)?;
            meta.recovered_from_seq = Some(next_seq - 1);
            rewrite_meta = true;
            tracing::warn!(
                path = %path.display(),
                cut_bytes = len - kept,
                last_kept_seq = next_seq - 1,
                "cut a torn tail from the audit log"
            );
        }
        meta.segments = number;
        if rewrite_meta {
            write_meta(dir, &meta)?;
        }

        let writer = SegmentWriter::new(dir, meta, syncer, number, file, kept, lock);
        let resume = Resume {
            last_seq: next_seq - 1,
            last_hash: prev,
            window,
            checkpoints,
        };
        Ok((writer, resume))
    }

    fn new(
        dir: &Path,
        meta: Meta,
        syncer: S,
        number: u32,
        file: File,
        len: u64,
        lock: File,
    ) -> Self {
        SegmentWriter {
            dir: dir.to_owned(),
            meta,
            syncer,
            number,
            out: BufWriter::with_capacity(WRITE_BUFFER, file),
            len,
            dirty: false,
            _lock: lock,
        }
    }

    /// Appends one line (newline included) to the current segment and
    /// returns the segment number and the offset the line starts at. The
    /// bytes may stay buffered until [`flush`](Self::flush).
    pub fn append(&mut self, line: &[u8]) -> io::Result<(u32, u64)> {
        let at = self.len;
        self.out.write_all(line)?;
        self.len += line.len() as u64;
        self.dirty = true;
        Ok((self.number, at))
    }

    /// Hands buffered bytes to the kernel, so readers see them.
    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Flushes and syncs the current segment, if anything was appended since
    /// the last sync.
    pub fn sync(&mut self) -> io::Result<()> {
        self.out.flush()?;
        if self.dirty {
            self.syncer.sync(self.out.get_ref())?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Bytes in the current segment.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// The current segment's number.
    pub fn segment(&self) -> u32 {
        self.number
    }

    /// Syncs the current segment and starts the next one. The caller seals
    /// the segment with a checkpoint first.
    pub fn rotate(&mut self) -> io::Result<()> {
        self.sync()?;
        let next = self.number + 1;
        let file = create_segment(&self.dir, next)?;
        self.meta.segments = next;
        write_meta(&self.dir, &self.meta)?;
        self.out = BufWriter::with_capacity(WRITE_BUFFER, file);
        self.number = next;
        self.len = 0;
        Ok(())
    }
}

/// Creates segment `n`, which must not exist yet, and makes its name durable.
fn create_segment(dir: &Path, n: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(dir.join(segment_name(n)))?;
    sync_dir(dir)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_names_have_one_spelling() {
        assert_eq!(segment_name(1), "events.000001.jsonl");
        assert_eq!(segment_name(1_234_567), "events.1234567.jsonl");
        assert_eq!(segment_number("events.000001.jsonl"), Some(1));
        assert_eq!(segment_number("events.000042.jsonl"), Some(42));
        assert_eq!(segment_number("events.1234567.jsonl"), Some(1_234_567));
        for other in [
            "events.1.jsonl",
            "events.000000.jsonl",
            "events.00001.jsonl",
            "events.0000001.jsonl",
            "events.+00001.jsonl",
            "events.000001.jsonl.tmp",
            "meta.json",
            "checkpoints.jsonl",
        ] {
            assert_eq!(segment_number(other), None, "{other}");
        }
        assert!(numbered_from_one(&[1, 2, 3]));
        assert!(numbered_from_one(&[]));
        assert!(!numbered_from_one(&[1, 3]));
        assert!(!numbered_from_one(&[2]));
    }

    #[test]
    fn last_line_ignores_a_partial_line_and_crosses_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        for (content, want) in [
            (&b""[..], None),
            (b"no newline", None),
            (b"one\n", Some((0, &b"one"[..]))),
            (b"one\ntwo\n", Some((4, &b"two"[..]))),
            (b"one\ntwo\npart", Some((4, &b"two"[..]))),
            (b"\n", Some((0, &b""[..]))),
        ] {
            fs::write(&path, content).unwrap();
            let got = last_line(&path).unwrap();
            let got = got.as_ref().map(|(at, line)| (*at, line.as_slice()));
            assert_eq!(got, want, "{:?}", String::from_utf8_lossy(content));
        }

        // A last line longer than the 64 KiB read chunk.
        let long = vec![b'x'; 200_000];
        let mut content = b"first\n".to_vec();
        content.extend_from_slice(&long);
        content.push(b'\n');
        fs::write(&path, &content).unwrap();
        assert_eq!(last_line(&path).unwrap(), Some((6, long)));
    }
}
