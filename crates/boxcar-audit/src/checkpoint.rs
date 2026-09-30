// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Checkpoints, and `checkpoints.jsonl`, the index that lists them.
//!
//! A checkpoint is a `checkpoint` record in the chain itself, so it is hashed
//! and linked like any other record. It summarizes the records written since
//! the previous checkpoint (that checkpoint itself excluded):
//!
//! ```text
//! root_hash     = blake3(hash_1 || hash_2 || ... || hash_n)   the raw 32-byte hashes
//! records_since = n
//! dropped       = events try_emit dropped since the previous checkpoint
//! ```
//!
//! The writer checkpoints every `checkpoint_every` records or
//! `checkpoint_interval` after the oldest record not yet covered, whichever
//! comes first, and also when it seals a segment and when it closes.
//!
//! A checkpoint is written in this order: the record is appended to the
//! segment and the segment is `fdatasync`ed, then its line is appended to
//! `checkpoints.jsonl`. The index therefore never names a record that is not
//! on disk. A crash can at worst lose index lines for checkpoints in the last
//! segment, and [`CheckpointIndex::open`] rebuilds those from the segment.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use boxcar_proto::{Checkpoint, Hash};
use serde::{Deserialize, Serialize};

use crate::segment::{on, sync_dir, FileResult, FILE_MODE};

pub(crate) const INDEX_FILE: &str = "checkpoints.jsonl";

/// One line of `checkpoints.jsonl`: where a checkpoint record is, and the
/// fields it carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IndexEntry {
    /// The checkpoint record's seq.
    pub(crate) seq: u64,
    /// The segment that holds it.
    pub(crate) segment: u32,
    /// The byte offset in that segment at which its line starts.
    pub(crate) offset: u64,
    pub(crate) root_hash: Hash,
    pub(crate) records_since: u64,
    pub(crate) dropped: u64,
}

impl IndexEntry {
    pub(crate) fn new(seq: u64, segment: u32, offset: u64, checkpoint: &Checkpoint) -> Self {
        IndexEntry {
            seq,
            segment,
            offset,
            root_hash: checkpoint.root_hash,
            records_since: checkpoint.records_since,
            dropped: checkpoint.dropped,
        }
    }
}

/// The records since the previous checkpoint, as much as the next one needs:
/// how many there are, and a running blake3 over their raw hashes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Window {
    hasher: blake3::Hasher,
    len: u64,
}

impl Window {
    pub(crate) fn push(&mut self, hash: &Hash) {
        self.hasher.update(&hash.0);
        self.len += 1;
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The checkpoint that closes this window, leaving the window empty.
    pub(crate) fn take(&mut self, dropped: u64) -> Checkpoint {
        let checkpoint = Checkpoint {
            records_since: self.len,
            dropped,
            root_hash: Hash::from_blake3(self.hasher.finalize()),
        };
        *self = Window::default();
        checkpoint
    }
}

/// `checkpoints.jsonl`, open for appending.
pub(crate) struct CheckpointIndex {
    path: PathBuf,
    file: File,
    /// The file's length after the last line appended whole.
    len: u64,
}

impl CheckpointIndex {
    /// Opens the index of the session in `dir` and makes it agree with the
    /// log, whose last segment is `segment` and holds the checkpoint records
    /// `in_last_segment` (found by recovery, in order).
    ///
    /// Lines for earlier segments are kept up to the first one that does not
    /// parse; the writer made them durable before it started `segment`.
    /// Everything after is replaced by `in_last_segment`: that drops lines
    /// torn by a crash or naming records a torn tail took with it, and adds
    /// lines a crash kept from being written.
    pub(crate) fn open(
        dir: &Path,
        segment: u32,
        in_last_segment: &[IndexEntry],
    ) -> io::Result<Self> {
        let path = dir.join(INDEX_FILE);
        let (existing, created) = match fs::read(&path) {
            Ok(bytes) => (bytes, false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), true),
            Err(e) => return Err(e),
        };

        let mut keep = 0;
        let mut last_seq = 0;
        for line in existing.split_inclusive(|&b| b == b'\n') {
            let Some(body) = line.strip_suffix(b"\n") else {
                break;
            };
            match serde_json::from_slice::<IndexEntry>(body) {
                Ok(entry) if entry.segment < segment && entry.seq > last_seq => {
                    keep += line.len();
                    last_seq = entry.seq;
                }
                _ => break,
            }
        }
        let mut wanted = existing[..keep].to_vec();
        for entry in in_last_segment {
            wanted.extend(serde_json::to_vec(entry)?);
            wanted.push(b'\n');
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&path)?;
        if created {
            sync_dir(dir)?;
        }
        if wanted != existing {
            file.set_len(keep as u64)?;
            (&file).write_all(&wanted[keep..])?;
            file.sync_data()?;
            tracing::warn!(
                path = %path.display(),
                kept = keep,
                rebuilt = in_last_segment.len(),
                "rebuilt the tail of the checkpoint index from the log"
            );
        }
        Ok(CheckpointIndex {
            path,
            file,
            len: wanted.len() as u64,
        })
    }

    /// Appends one line with a single write.
    pub(crate) fn append(&mut self, entry: &IndexEntry) -> FileResult<()> {
        let append = on("append to", &self.path);
        let mut line = serde_json::to_vec(entry).map_err(|e| append(e.into()))?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .map_err(on("append to", &self.path))?;
        self.len += line.len() as u64;
        Ok(())
    }

    pub(crate) fn sync(&self) -> FileResult<()> {
        self.file.sync_data().map_err(on("sync", &self.path))
    }

    /// After a failure: cuts off whatever an append that failed left after
    /// the last whole line. Best effort: a failure to cut is logged.
    pub(crate) fn roll_back(&mut self) {
        let cut = self.file.metadata().and_then(|m| {
            if m.len() > self.len {
                self.file.set_len(self.len)?;
            }
            Ok(m.len().saturating_sub(self.len))
        });
        match cut {
            Ok(0) => {}
            Ok(bytes) => tracing::warn!(
                path = %self.path.display(),
                cut_bytes = bytes,
                "cut a partial line off the checkpoint index"
            ),
            Err(error) => tracing::error!(
                path = %self.path.display(),
                "cannot cut a partial line off the checkpoint index: {error}"
            ),
        }
    }
}

/// The entries of a session's `checkpoints.jsonl` up to the first line that
/// does not parse, or none if the file cannot be read. Only for skipping
/// ahead, so a damaged index costs speed, not correctness.
pub(crate) fn read_index(dir: &Path) -> Vec<IndexEntry> {
    let Ok(bytes) = fs::read(dir.join(INDEX_FILE)) else {
        return Vec::new();
    };
    bytes
        .split_inclusive(|&b| b == b'\n')
        .map_while(|line| {
            let body = line.strip_suffix(b"\n")?;
            serde_json::from_slice(body).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_roots_the_raw_hashes_in_order_and_starts_over() {
        let hashes = [Hash([1; 32]), Hash([2; 32]), Hash([3; 32])];
        let mut window = Window::default();
        for hash in &hashes {
            window.push(hash);
        }
        assert_eq!(window.len(), 3);

        let mut concatenated = Vec::new();
        for hash in &hashes {
            concatenated.extend_from_slice(&hash.0);
        }
        let checkpoint = window.take(5);
        assert_eq!(checkpoint.records_since, 3);
        assert_eq!(checkpoint.dropped, 5);
        assert_eq!(
            checkpoint.root_hash,
            Hash::from_blake3(blake3::hash(&concatenated))
        );

        assert!(window.is_empty());
        let empty = window.take(0);
        assert_eq!(empty.records_since, 0);
        assert_eq!(empty.root_hash, Hash::from_blake3(blake3::hash(b"")));
    }

    #[test]
    fn index_lines_keep_the_documented_field_order() {
        let entry = IndexEntry {
            seq: 1025,
            segment: 1,
            offset: 409_600,
            root_hash: Hash([0xab; 32]),
            records_since: 1024,
            dropped: 2,
        };
        let line = serde_json::to_string(&entry).unwrap();
        assert_eq!(
            line,
            format!(
                r#"{{"seq":1025,"segment":1,"offset":409600,"root_hash":"b3:{}","records_since":1024,"dropped":2}}"#,
                "ab".repeat(32)
            )
        );
    }
}
