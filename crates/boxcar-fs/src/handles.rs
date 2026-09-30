// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Open file handles: what each was opened as, by whom, and what went
//! through it, from `open` or `create` until `release`.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use boxcar_proto::Subject;

/// One open handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleEntry {
    pub ino: u64,
    /// The path the handle was opened at.
    pub path_at_open: String,
    /// The `open(2)` flags.
    pub flags: u32,
    /// The guest process that opened it: whom a request without a usable
    /// caller of its own is attributed to.
    pub opener: Subject,
    /// The `seq` of the record that opened the handle. The sink does not
    /// report the seq it is given, so this is not known yet.
    pub open_seq: Option<u64>,
    pub bytes_read: u64,
    pub bytes_written: u64,
    /// Something was written through the handle.
    pub wrote: bool,
    /// The handle came from `create`.
    pub created: bool,
    /// The file was truncated through the handle, or opened with `O_TRUNC`.
    pub truncated: bool,
}

impl HandleEntry {
    /// Whether the content may have changed through this handle, so the
    /// close is worth hashing.
    pub fn changed(&self) -> bool {
        self.wrote || self.created || self.truncated
    }
}

/// The open handles of one share, by FUSE file handle.
#[derive(Debug, Default)]
pub struct HandleTable {
    handles: Mutex<HashMap<u64, HandleEntry>>,
}

impl HandleTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, HandleEntry>> {
        // Every update leaves the map consistent, so a panic elsewhere while
        // it was held does not make it unusable.
        self.handles.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn insert(&self, fh: u64, entry: HandleEntry) {
        self.lock().insert(fh, entry);
    }

    /// Applies `f` to the handle, if it is open.
    pub fn update<R>(&self, fh: u64, f: impl FnOnce(&mut HandleEntry) -> R) -> Option<R> {
        self.lock().get_mut(&fh).map(f)
    }

    /// Removes the handle and returns what it recorded.
    pub fn take(&self, fh: u64) -> Option<HandleEntry> {
        self.lock().remove(&fh)
    }

    /// Forgets every handle, as after the guest unmounts.
    pub fn clear(&self) {
        self.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> HandleEntry {
        HandleEntry {
            ino: 2,
            path_at_open: "/f".into(),
            flags: 0,
            opener: Subject {
                pid: 1,
                uid: 2,
                gid: 3,
            },
            open_seq: None,
            bytes_read: 0,
            bytes_written: 0,
            wrote: false,
            created: false,
            truncated: false,
        }
    }

    #[test]
    fn handles_live_from_insert_to_take() {
        let table = HandleTable::new();
        assert!(table.is_empty());
        table.insert(7, entry());
        let opener = table.update(7, |e| {
            e.bytes_written += 3;
            e.wrote = true;
            e.opener
        });
        assert_eq!(opener, Some(entry().opener));
        assert_eq!(table.update(8, |e| e.ino), None);
        let taken = table.take(7).unwrap();
        assert_eq!(taken.bytes_written, 3);
        assert!(taken.changed());
        assert!(table.take(7).is_none());
        table.insert(9, entry());
        table.clear();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn a_handle_changed_the_file_if_it_wrote_created_or_truncated() {
        assert!(!entry().changed());
        for set in [
            |e: &mut HandleEntry| e.wrote = true,
            |e: &mut HandleEntry| e.created = true,
            |e: &mut HandleEntry| e.truncated = true,
        ] {
            let mut e = entry();
            set(&mut e);
            assert!(e.changed());
        }
    }
}
