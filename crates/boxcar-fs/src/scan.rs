// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The boot scan: what a session's `denied` paths and refused programs
//! are, by host identity.
//!
//! Names alone do not hold a denied file. A hard link made before the
//! session, or on a case-insensitive host filesystem a case variant, names
//! the same file another way. So before the shares' devices start, when
//! the policy denies anything or refuses any program, the shares' host
//! directories are walked once, as one set (the root share and the
//! workspace can be on one host filesystem, and share hard links):
//!
//! - the identity (`st_dev`, `st_ino`) of every entry whose guest path is
//!   denied (so of everything beneath a denied directory), with the glob
//!   that denied it;
//! - the identity of every directory on the way to one (a *holding*
//!   directory, which may not be renamed, so the paths of denied entries
//!   never change), with that glob;
//! - the identity of every regular file an `[exec] deny` glob names, with
//!   the glob.
//!
//! The walk follows no symlink and stops at [`MAX_ENTRIES`] in all. A
//! directory it cannot read fails the scan: the passthrough's lookups need
//! only search permission, so an entry beneath it could be reached without
//! the scan having seen it. The sets are fixed for the session: `denied`
//! has no exceptions, and nothing can be created or renamed onto a denied
//! path.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::path_map::FileId;
use crate::rules::{guest_path, PathRules};

/// The most entries a session's scan reads, all shares together.
pub const MAX_ENTRIES: usize = 4_000_000;

/// Why the shares could not be scanned.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(
        "the policy needs the shares scanned for what it denies or refuses to run, and they \
         have more than {limit} entries"
    )]
    TooMany { limit: usize },
    #[error(
        "the policy needs {} scanned for what it denies or refuses to run, and it cannot be read",
        dir.display()
    )]
    Unreadable {
        dir: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// What a session's denied paths and refused programs are, by identity.
#[derive(Debug, Default)]
pub struct DeniedIds {
    /// Every denied entry, with the glob that denied it.
    denied: HashMap<FileId, String>,
    /// Every directory on the way to a denied entry, with the glob that
    /// denied the first one found beneath it.
    holding: HashMap<FileId, String>,
    /// Every regular file an `[exec] deny` glob names, with the glob.
    exec: HashMap<FileId, String>,
}

impl DeniedIds {
    /// The glob that denied `id`, if it is denied.
    pub fn denied(&self, id: FileId) -> Option<&str> {
        self.denied.get(&id).map(String::as_str)
    }

    /// When `id` is a directory on the way to a denied entry, the glob
    /// that denied one beneath it.
    pub fn holds(&self, id: FileId) -> Option<&str> {
        self.holding.get(&id).map(String::as_str)
    }

    /// The `[exec] deny` glob that named `id`, if one did.
    pub fn exec(&self, id: FileId) -> Option<&str> {
        self.exec.get(&id).map(String::as_str)
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.denied.is_empty() && self.exec.is_empty()
    }

    /// How many entries are denied.
    pub fn denied_len(&self) -> usize {
        self.denied.len()
    }
}

/// A directory waiting to be read: its host path, its share-relative
/// path, and its place in `dirs`.
struct Pending {
    host: PathBuf,
    relative: Vec<u8>,
    index: usize,
}

/// Scans `shares`, each a host directory and the guest directory it is
/// served at, for what `rules` deny and refuse to run. Nothing is read when
/// they deny and refuse nothing.
pub fn scan(shares: &[(&Path, &str)], rules: &PathRules) -> Result<DeniedIds, ScanError> {
    scan_with_limit(shares, rules, MAX_ENTRIES)
}

pub(crate) fn scan_with_limit(
    shares: &[(&Path, &str)],
    rules: &PathRules,
    limit: usize,
) -> Result<DeniedIds, ScanError> {
    let mut ids = DeniedIds::default();
    if !rules.scans() {
        return Ok(ids);
    }
    let mut seen = 0usize;
    for (host_dir, guest_dir) in shares {
        scan_share(&mut ids, &mut seen, host_dir, guest_dir, rules, limit)?;
    }
    Ok(ids)
}

fn scan_share(
    ids: &mut DeniedIds,
    seen: &mut usize,
    host_dir: &Path,
    guest_dir: &str,
    rules: &PathRules,
    limit: usize,
) -> Result<(), ScanError> {
    let unreadable = |dir: &Path, source| ScanError::Unreadable {
        dir: dir.to_owned(),
        source,
    };
    let root = fs::symlink_metadata(host_dir).map_err(|e| unreadable(host_dir, e))?;
    // Each directory read, with its parent's place: a denied entry marks
    // its way up as holding.
    let mut dirs: Vec<(FileId, Option<usize>)> = vec![(id_of(&root), None)];
    if let Some(glob) = rules.denied(&guest_path(guest_dir, b"/")) {
        ids.denied.insert(id_of(&root), glob.to_owned());
    }
    let mut pending = vec![Pending {
        host: host_dir.to_owned(),
        relative: Vec::new(),
        index: 0,
    }];
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir.host).map_err(|e| unreadable(&dir.host, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| unreadable(&dir.host, e))?;
            *seen += 1;
            if *seen > limit {
                return Err(ScanError::TooMany { limit });
            }
            // `DirEntry::metadata` does not follow a symlink. An entry gone
            // since the listing is not there to hold.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let mut relative = dir.relative.clone();
            relative.push(b'/');
            relative.extend_from_slice(entry.file_name().as_bytes());
            let guest = guest_path(guest_dir, &relative);
            let id = id_of(&meta);
            if let Some(glob) = rules.denied(&guest) {
                ids.denied.insert(id, glob.to_owned());
                mark_holding(&mut ids.holding, &dirs, dir.index, glob);
            }
            if meta.is_file() {
                if let Some(glob) = rules.exec_named(&guest) {
                    ids.exec.insert(id, glob.to_owned());
                }
            }
            if meta.is_dir() {
                dirs.push((id, Some(dir.index)));
                pending.push(Pending {
                    host: entry.path(),
                    relative,
                    index: dirs.len() - 1,
                });
            }
        }
    }
    Ok(())
}

/// Marks `index` and the directories above it as holding, for `glob`, up
/// to the first already marked.
fn mark_holding(
    holding: &mut HashMap<FileId, String>,
    dirs: &[(FileId, Option<usize>)],
    index: usize,
    glob: &str,
) {
    let mut at = Some(index);
    while let Some(index) = at {
        let (id, parent) = dirs[index];
        if holding.contains_key(&id) {
            return;
        }
        holding.insert(id, glob.to_owned());
        at = parent;
    }
}

fn id_of(meta: &fs::Metadata) -> FileId {
    FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;
    use crate::rules::PathSpec;

    fn rules(denied: &[&str], exec: &[&str]) -> PathRules {
        let spec = PathSpec {
            writable: vec!["/**".to_owned()],
            denied: denied.iter().map(|s| (*s).to_owned()).collect(),
            exec_deny: exec.iter().map(|s| (*s).to_owned()).collect(),
        };
        PathRules::new(&spec, &[], &[]).unwrap()
    }

    fn id(path: &Path) -> FileId {
        id_of(&fs::symlink_metadata(path).unwrap())
    }

    /// A denied directory and all it holds, a denied file elsewhere, the
    /// directories on the way to each, and a refused program; nothing else.
    #[test]
    fn denied_entries_the_way_to_them_and_refused_programs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("a/secrets/deep")).unwrap();
        fs::write(root.join("a/secrets/deep/key"), "k").unwrap();
        fs::write(root.join("a/secrets/top"), "t").unwrap();
        fs::create_dir_all(root.join("b/c")).unwrap();
        fs::write(root.join("b/c/.env"), "e").unwrap();
        fs::write(root.join("b/c/ok"), "o").unwrap();
        // A hard link made before the session, under a name no glob has.
        fs::hard_link(root.join("b/c/.env"), root.join("b/alias")).unwrap();
        fs::create_dir_all(root.join("bin/nc")).unwrap();
        fs::write(root.join("tools_nc"), "x").unwrap();
        fs::create_dir_all(root.join("tools")).unwrap();
        fs::write(root.join("tools/nc"), "#!").unwrap();

        let r = rules(&["/workspace/a/secrets", "**/.env"], &["**/nc"]);
        let ids = scan(&[(root, "/workspace")], &r).unwrap();
        for path in [
            "a/secrets",
            "a/secrets/deep",
            "a/secrets/deep/key",
            "a/secrets/top",
        ] {
            assert_eq!(
                ids.denied(id(&root.join(path))),
                Some("/workspace/a/secrets"),
                "{path}"
            );
        }
        assert_eq!(ids.denied(id(&root.join("b/c/.env"))), Some("**/.env"));
        // The alias is the same file.
        assert_eq!(ids.denied(id(&root.join("b/alias"))), Some("**/.env"));
        assert_eq!(ids.denied(id(&root.join("b/c/ok"))), None);
        assert_eq!(ids.denied_len(), 5);
        for path in ["", "a", "b", "b/c"] {
            assert!(ids.holds(id(&root.join(path))).is_some(), "{path:?} holds");
        }
        assert_eq!(ids.holds(id(&root.join("b/c"))), Some("**/.env"));
        assert_eq!(ids.holds(id(&root.join("b/c/ok"))), None);
        // A program is a regular file: a directory named nc is not one.
        assert_eq!(ids.exec(id(&root.join("tools/nc"))), Some("**/nc"));
        assert_eq!(ids.exec(id(&root.join("bin/nc"))), None);
        assert_eq!(ids.exec(id(&root.join("tools_nc"))), None);
    }

    /// The shares are one set: a hard link between them is the same file.
    #[test]
    fn the_shares_are_one_set() {
        let host = tempfile::tempdir().unwrap();
        let rootfs = host.path().join("rootfs");
        let workspace = host.path().join("workspace");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join(".env"), "e").unwrap();
        fs::hard_link(workspace.join(".env"), rootfs.join("etc/env")).unwrap();
        let ids = scan(
            &[(&rootfs, "/"), (&workspace, "/workspace")],
            &rules(&["/workspace/.env"], &[]),
        )
        .unwrap();
        assert_eq!(
            ids.denied(id(&rootfs.join("etc/env"))),
            Some("/workspace/.env")
        );
    }

    /// A symlink is an entry of its own, never followed.
    #[test]
    fn symlinks_are_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join(".env"), "x").unwrap();
        symlink(outside.path(), root.join("out")).unwrap();
        symlink("x", root.join(".env")).unwrap();
        let ids = scan(&[(root, "/")], &rules(&["**/.env"], &[])).unwrap();
        assert_eq!(ids.denied_len(), 1);
        assert_eq!(ids.denied(id(&root.join(".env"))), Some("**/.env"));
        assert_eq!(ids.denied(id(&outside.path().join(".env"))), None);
    }

    /// A share root that is itself denied is denied whole.
    #[test]
    fn a_denied_share_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f"), "f").unwrap();
        let ids = scan(&[(dir.path(), "/workspace")], &rules(&["/workspace"], &[])).unwrap();
        assert_eq!(ids.denied(id(dir.path())), Some("/workspace"));
        assert_eq!(ids.denied(id(&dir.path().join("f"))), Some("/workspace"));
    }

    /// A directory the scan cannot read fails it, naming the directory.
    #[test]
    fn an_unreadable_directory_fails_the_scan() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads everything
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join(".env"), "e").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o111)).unwrap();
        let failed = scan(&[(dir.path(), "/")], &rules(&["**/.env"], &[]));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        match failed {
            Err(ScanError::Unreadable { dir, .. }) => assert_eq!(dir, locked),
            other => panic!("{other:?}"),
        }
    }

    /// Past the limit, all shares counted, the scan fails; with nothing
    /// denied or refused nothing is read at all.
    #[test]
    fn the_limit_and_nothing_to_scan() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("f{i}")), "f").unwrap();
        }
        let r = rules(&["/x"], &[]);
        let refused = scan_with_limit(&[(dir.path(), "/")], &r, 9).unwrap_err();
        assert!(
            matches!(refused, ScanError::TooMany { limit: 9 }),
            "{refused}"
        );
        assert!(scan_with_limit(&[(dir.path(), "/")], &r, 10).is_ok());
        let twice = [(dir.path(), "/"), (dir.path(), "/workspace")];
        assert!(scan_with_limit(&twice, &r, 19).is_err());
        let gone = Path::new("/nonexistent/share");
        let none = scan_with_limit(&[(gone, "/")], &PathRules::allow_all(), 0);
        assert!(none.unwrap().is_empty());
        let only_writable = PathRules::new(
            &PathSpec {
                writable: vec!["/workspace/**".to_owned()],
                ..PathSpec::default()
            },
            &[],
            &[],
        )
        .unwrap();
        assert!(scan_with_limit(&[(gone, "/")], &only_writable, 0)
            .unwrap()
            .is_empty());
    }
}
