// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Paths for FUSE inodes, kept without a syscall.
//!
//! FUSE names files by inode; a record names them by path. [`PathMap`]
//! mirrors what the guest kernel knows: every reply that hands the kernel an
//! inode (lookup, create, mkdir, mknod, symlink, link, and each readdirplus
//! entry) inserts it under its parent and name and counts one lookup, and
//! `forget` gives lookups back. A node leaves the map when its count reaches
//! zero, exactly when the kernel can no longer name it. Renames and unlinks
//! the guest makes update the map; changes made on the host behind the
//! guest's back are seen only when the guest looks the name up again.
//!
//! An unlinked node stays until it is forgotten, since it may still be open:
//! it keeps its last name, for the close record, and is marked deleted.
//!
//! A node usually has one name. A hard link the guest looks up adds another
//! (an alias); when the primary name goes away an alias takes its place, and
//! only a node with no name left is deleted.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use boxcar_proto::limits::{truncate_utf8, MAX_PATH};

/// The share root's inode, which FUSE fixes at 1.
pub const ROOT_INO: u64 = 1;

/// Longest chain of parents [`PathMap::path`] follows before giving up.
const MAX_DEPTH: usize = 4096;

/// A path as a record carries it: the text, and, when the bytes were not
/// UTF-8, the bytes themselves in base64 (`path_b64`). The text is the
/// lossy form (`U+FFFD` for each bad byte), cut to [`MAX_PATH`] bytes with
/// a trailing `…`; the base64 covers at most the first [`MAX_PATH`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathText {
    pub path: String,
    pub path_b64: Option<String>,
}

impl PathText {
    /// The record form of the path `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> PathText {
        let (path, path_b64) = match std::str::from_utf8(bytes) {
            Ok(text) => (truncate_utf8(text, MAX_PATH).0, None),
            Err(_) => {
                let lossy = String::from_utf8_lossy(bytes);
                let raw = &bytes[..bytes.len().min(MAX_PATH)];
                (
                    truncate_utf8(&lossy, MAX_PATH).0,
                    Some(STANDARD.encode(raw)),
                )
            }
        };
        PathText { path, path_b64 }
    }

    /// A path that is UTF-8 already.
    pub fn utf8(path: impl Into<String>) -> PathText {
        PathText {
            path: truncate_utf8(&path.into(), MAX_PATH).0,
            path_b64: None,
        }
    }
}

/// A host file's identity: `st_dev` and `st_ino`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug)]
struct Node {
    parent: u64,
    name: Box<[u8]>,
    /// Lookups the kernel holds on this inode.
    nlookup: u64,
    /// No name refers to this inode any more.
    deleted: bool,
    /// Other names of this inode (hard links), besides `(parent, name)`.
    aliases: Vec<(u64, Box<[u8]>)>,
    /// The host file this inode was when last looked up.
    host: Option<FileId>,
}

impl Node {
    fn is_named(&self, parent: u64, name: &[u8]) -> bool {
        self.parent == parent && *self.name == *name
    }

    fn has_alias(&self, parent: u64, name: &[u8]) -> bool {
        self.aliases
            .iter()
            .any(|(p, n)| *p == parent && **n == *name)
    }

    /// The name `(parent, name)` became `(new_parent, new)`.
    fn rename(&mut self, parent: u64, name: &[u8], new_parent: u64, new: &[u8]) {
        if self.is_named(parent, name) {
            self.parent = new_parent;
            self.name = new.into();
        } else if let Some(alias) = self
            .aliases
            .iter_mut()
            .find(|(p, n)| *p == parent && **n == *name)
        {
            *alias = (new_parent, new.into());
        } else {
            self.aliases.push((new_parent, new.into()));
        }
    }
}

/// Inode to path, and (parent, name) to inode, for one share.
#[derive(Debug)]
pub struct PathMap {
    nodes: HashMap<u64, Node>,
    /// parent → name → inode, for every name of every node.
    names: HashMap<u64, HashMap<Box<[u8]>, u64>>,
}

impl Default for PathMap {
    fn default() -> Self {
        Self::new()
    }
}

fn is_dot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// Where walking up from an inode ended.
enum Walk<'a> {
    /// At the root; the names from the root down.
    Rooted(Vec<&'a [u8]>),
    /// At an inode the map does not know, with the names below it.
    Unknown(u64, Vec<&'a [u8]>),
    /// More than `MAX_DEPTH` parents.
    TooDeep,
}

impl PathMap {
    /// A map that knows only the root.
    pub fn new() -> Self {
        let mut map = PathMap {
            nodes: HashMap::new(),
            names: HashMap::new(),
        };
        map.reset();
        map
    }

    /// Forgets everything but the root, as after the guest unmounts.
    pub fn reset(&mut self) {
        self.nodes.clear();
        self.names.clear();
        self.nodes.insert(
            ROOT_INO,
            Node {
                parent: ROOT_INO,
                name: Box::default(),
                nlookup: 1,
                deleted: false,
                aliases: Vec::new(),
                host: None,
            },
        );
    }

    /// The kernel looked up `name` in `parent` and got `ino`: one more
    /// lookup of `ino`, which is now known by that name.
    ///
    /// `.` and `..` name no new path: a lookup through them only counts. The
    /// root is permanent and is never counted.
    pub fn insert(&mut self, parent: u64, name: &[u8], ino: u64) {
        if ino == ROOT_INO {
            return;
        }
        if is_dot(name) {
            if let Some(node) = self.nodes.get_mut(&ino) {
                node.nlookup = node.nlookup.saturating_add(1);
            }
            return;
        }
        let previous = self
            .names
            .entry(parent)
            .or_default()
            .insert(name.into(), ino);
        if let Some(other) = previous.filter(|&other| other != ino) {
            // The name now leads somewhere else, so it no longer names that
            // node: the host replaced the file behind the guest's back.
            self.detach(other, parent, name);
        }
        match self.nodes.get_mut(&ino) {
            Some(node) => {
                node.nlookup = node.nlookup.saturating_add(1);
                if node.deleted {
                    node.parent = parent;
                    node.name = name.into();
                    node.deleted = false;
                } else if !node.is_named(parent, name) && !node.has_alias(parent, name) {
                    node.aliases.push((parent, name.into()));
                }
            }
            None => {
                self.nodes.insert(
                    ino,
                    Node {
                        parent,
                        name: name.into(),
                        nlookup: 1,
                        deleted: false,
                        aliases: Vec::new(),
                        host: None,
                    },
                );
            }
        }
    }

    /// Records which host file `ino` is, from the attributes of a reply.
    pub fn set_host_id(&mut self, ino: u64, id: FileId) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.host = Some(id);
        }
    }

    /// The host file `ino` was when last looked up, if known.
    pub fn host_id(&self, ino: u64) -> Option<FileId> {
        self.nodes.get(&ino).and_then(|n| n.host)
    }

    /// The kernel gave back `n` lookups of `ino`. At zero the node goes.
    pub fn forget(&mut self, ino: u64, n: u64) {
        if ino == ROOT_INO {
            return;
        }
        let Some(node) = self.nodes.get_mut(&ino) else {
            return;
        };
        node.nlookup = node.nlookup.saturating_sub(n);
        if node.nlookup > 0 {
            return;
        }
        let Some(node) = self.nodes.remove(&ino) else {
            return;
        };
        self.unname(node.parent, &node.name, ino);
        for (parent, name) in &node.aliases {
            self.unname(*parent, name, ino);
        }
    }

    /// `old` in `old_parent` was renamed to `new` in `new_parent`, replacing
    /// whatever `new` named.
    pub fn rename(&mut self, old_parent: u64, old: &[u8], new_parent: u64, new: &[u8]) {
        let moved = self.inode_of(old_parent, old);
        if moved.is_some() && moved == self.inode_of(new_parent, new) {
            // Two names of one inode: rename(2) leaves both in place.
            return;
        }
        let moved = self.take_name(old_parent, old);
        if let Some(replaced) = self.take_name(new_parent, new) {
            self.detach(replaced, new_parent, new);
        }
        if let Some(ino) = moved {
            self.names
                .entry(new_parent)
                .or_default()
                .insert(new.into(), ino);
            if let Some(node) = self.nodes.get_mut(&ino) {
                node.rename(old_parent, old, new_parent, new);
            }
        }
    }

    /// `a` in `a_parent` and `b` in `b_parent` swapped places
    /// (`RENAME_EXCHANGE`).
    pub fn exchange(&mut self, a_parent: u64, a: &[u8], b_parent: u64, b: &[u8]) {
        let x = self.take_name(a_parent, a);
        let y = self.take_name(b_parent, b);
        if x.is_some() && x == y {
            // One inode under both names: nothing changes.
            self.restore_name(a_parent, a, x);
            self.restore_name(b_parent, b, y);
            return;
        }
        self.restore_name(b_parent, b, x);
        self.restore_name(a_parent, a, y);
        if let Some(node) = x.and_then(|x| self.nodes.get_mut(&x)) {
            node.rename(a_parent, a, b_parent, b);
        }
        if let Some(node) = y.and_then(|y| self.nodes.get_mut(&y)) {
            node.rename(b_parent, b, a_parent, a);
        }
    }

    /// `name` in `parent` was unlinked or removed. The node it named stays,
    /// under its last name, until it is forgotten.
    pub fn mark_deleted(&mut self, parent: u64, name: &[u8]) {
        if let Some(ino) = self.take_name(parent, name) {
            self.detach(ino, parent, name);
        }
    }

    /// Whether no name refers to `ino` any more.
    pub fn is_deleted(&self, ino: u64) -> bool {
        self.nodes.get(&ino).is_some_and(|n| n.deleted)
    }

    /// The path of `ino` relative to the share root, starting with `/`; the
    /// root is `/`. When the walk up meets an inode the map does not know,
    /// the path starts at that inode, written `<ino:N>`; when it goes deeper
    /// than 4096 parents it is `<ino:N>` of `ino` itself. Names that are not
    /// UTF-8 are converted lossily; [`path_text`](Self::path_text) keeps
    /// their bytes as well.
    pub fn path(&self, ino: u64) -> String {
        String::from_utf8_lossy(&self.raw_path(ino)).into_owned()
    }

    /// [`path`](Self::path) as a record carries it, with the raw bytes when
    /// they are not UTF-8, cut to the record's limit.
    pub fn path_text(&self, ino: u64) -> PathText {
        PathText::from_bytes(&self.raw_path(ino))
    }

    /// The path of `name` in the directory at `parent`, as a record carries
    /// it, for a name the map does not hold (yet).
    pub fn child_text(&self, parent: u64, name: &[u8]) -> PathText {
        let mut bytes = self.raw_path(parent);
        if bytes != b"/" {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(name);
        PathText::from_bytes(&bytes)
    }

    /// The bytes of [`path`](Self::path), before any conversion.
    fn raw_path(&self, ino: u64) -> Vec<u8> {
        match self.walk(ino) {
            Walk::Rooted(parts) if parts.is_empty() => b"/".to_vec(),
            Walk::Rooted(parts) => {
                let mut path = Vec::new();
                for part in parts {
                    path.push(b'/');
                    path.extend_from_slice(part);
                }
                path
            }
            Walk::Unknown(unknown, parts) => {
                let mut path = format!("<ino:{unknown}>").into_bytes();
                for part in parts {
                    path.push(b'/');
                    path.extend_from_slice(part);
                }
                path
            }
            Walk::TooDeep => format!("<ino:{ino}>").into_bytes(),
        }
    }

    /// The raw bytes of `ino`'s path relative to the share root, without the
    /// leading `/`, for opening it on the host. `None` for the root, and when
    /// the path is not fully known.
    pub fn relative_path(&self, ino: u64) -> Option<Vec<u8>> {
        let Walk::Rooted(parts) = self.walk(ino) else {
            return None;
        };
        if parts.is_empty() {
            return None;
        }
        Some(parts.join(&b'/'))
    }

    /// Every inode the map knows, the root included, in ascending order.
    pub fn inodes(&self) -> Vec<u64> {
        let mut inodes: Vec<u64> = self.nodes.keys().copied().collect();
        inodes.sort_unstable();
        inodes
    }

    fn walk(&self, ino: u64) -> Walk<'_> {
        let mut parts = Vec::new();
        let mut at = ino;
        for _ in 0..MAX_DEPTH {
            if at == ROOT_INO {
                parts.reverse();
                return Walk::Rooted(parts);
            }
            let Some(node) = self.nodes.get(&at) else {
                parts.reverse();
                return Walk::Unknown(at, parts);
            };
            parts.push(&*node.name);
            at = node.parent;
        }
        Walk::TooDeep
    }

    fn inode_of(&self, parent: u64, name: &[u8]) -> Option<u64> {
        self.names.get(&parent)?.get(name).copied()
    }

    /// Removes the name and returns the inode it named.
    fn take_name(&mut self, parent: u64, name: &[u8]) -> Option<u64> {
        let names = self.names.get_mut(&parent)?;
        let ino = names.remove(name);
        if names.is_empty() {
            self.names.remove(&parent);
        }
        ino
    }

    fn restore_name(&mut self, parent: u64, name: &[u8], ino: Option<u64>) {
        if let Some(ino) = ino {
            self.names
                .entry(parent)
                .or_default()
                .insert(name.into(), ino);
        }
    }

    /// Removes the name if it still names `ino`.
    fn unname(&mut self, parent: u64, name: &[u8], ino: u64) {
        if self.inode_of(parent, name) == Some(ino) {
            self.take_name(parent, name);
        }
    }

    /// `(parent, name)` no longer names `ino`: an alias takes over as its
    /// name, or, with none left, it is deleted.
    fn detach(&mut self, ino: u64, parent: u64, name: &[u8]) {
        let Some(node) = self.nodes.get_mut(&ino) else {
            return;
        };
        if node.is_named(parent, name) {
            match node.aliases.pop() {
                Some((p, n)) => {
                    node.parent = p;
                    node.name = n;
                }
                None => node.deleted = true,
            }
        } else {
            node.aliases
                .retain(|(p, n)| !(*p == parent && **n == *name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record's path: the lossy text, and the bytes in base64 only when
    /// they are not UTF-8; both held to the path limit.
    #[test]
    fn path_text_keeps_the_bytes_of_a_name_that_is_not_utf8() {
        use base64::Engine as _;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut map = PathMap::new();
        map.insert(ROOT_INO, b"d", 2);
        map.insert(2, b"a\xff", 3);
        map.insert(ROOT_INO, "caf\u{e9}".as_bytes(), 4);

        assert_eq!(map.path_text(ROOT_INO), PathText::utf8("/"));
        assert_eq!(map.path_text(2), PathText::utf8("/d"));
        assert_eq!(
            map.path_text(4),
            PathText::utf8("/caf\u{e9}"),
            "UTF-8 is not bytes"
        );
        assert_eq!(
            map.path_text(3),
            PathText {
                path: "/d/a\u{fffd}".into(),
                path_b64: Some(b64(b"/d/a\xff")),
            }
        );
        assert_eq!(map.path(3), "/d/a\u{fffd}");
        // A child that is not in the map yet, under a parent that is.
        assert_eq!(map.child_text(ROOT_INO, b"new"), PathText::utf8("/new"));
        assert_eq!(map.child_text(2, b"new"), PathText::utf8("/d/new"));
        assert_eq!(
            map.child_text(3, b"x"),
            PathText {
                path: "/d/a\u{fffd}/x".into(),
                path_b64: Some(b64(b"/d/a\xff/x")),
            }
        );
        assert_eq!(
            map.child_text(2, b"\xfe"),
            PathText {
                path: "/d/\u{fffd}".into(),
                path_b64: Some(b64(b"/d/\xfe")),
            }
        );
        // Under an inode the map does not know.
        assert_eq!(map.child_text(9, b"a"), PathText::utf8("<ino:9>/a"));

        // Both forms are held to the limit.
        let long = PathText::from_bytes(&[b'x'; 2 * MAX_PATH]);
        assert!(long.path.len() <= MAX_PATH && long.path.ends_with('\u{2026}'));
        assert_eq!(long.path_b64, None);
        let mut raw = vec![0xff_u8; 2 * MAX_PATH];
        raw[0] = b'/';
        let long = PathText::from_bytes(&raw);
        assert!(long.path.len() <= MAX_PATH && long.path.ends_with('\u{2026}'));
        assert_eq!(long.path_b64, Some(b64(&raw[..MAX_PATH])));
    }

    const D: u64 = 2;
    const F: u64 = 3;
    const G: u64 = 4;

    /// /d (2), /d/f (3), /g (4).
    fn tree() -> PathMap {
        let mut map = PathMap::new();
        map.insert(ROOT_INO, b"d", D);
        map.insert(D, b"f", F);
        map.insert(ROOT_INO, b"g", G);
        map
    }

    #[test]
    fn the_root_is_slash_and_permanent() {
        let mut map = PathMap::new();
        assert_eq!(map.path(ROOT_INO), "/");
        assert_eq!(map.relative_path(ROOT_INO), None);
        map.forget(ROOT_INO, u64::MAX);
        map.insert(ROOT_INO, b"..", ROOT_INO);
        assert_eq!(map.inodes(), [ROOT_INO]);
    }

    #[test]
    fn paths_walk_up_to_the_root() {
        let map = tree();
        assert_eq!(map.path(D), "/d");
        assert_eq!(map.path(F), "/d/f");
        assert_eq!(map.relative_path(F).as_deref(), Some(&b"d/f"[..]));
        assert_eq!(map.inodes(), [ROOT_INO, D, F, G]);
    }

    #[test]
    fn unknown_inodes_and_ancestors_are_named_by_number() {
        let mut map = PathMap::new();
        assert_eq!(map.path(9), "<ino:9>");
        map.insert(7, b"child", 8);
        assert_eq!(map.path(8), "<ino:7>/child");
        assert_eq!(map.relative_path(8), None);
    }

    #[test]
    fn a_cycle_stops_at_the_depth_cap() {
        let mut map = PathMap::new();
        map.insert(6, b"a", 5);
        map.insert(5, b"b", 6);
        assert_eq!(map.path(5), "<ino:5>");
        assert_eq!(map.relative_path(5), None);
    }

    #[test]
    fn names_that_are_not_utf8_are_lossy_in_paths_and_exact_on_the_host() {
        let mut map = PathMap::new();
        map.insert(ROOT_INO, b"caf\xe9", 2);
        assert_eq!(map.path(2), "/caf\u{fffd}");
        assert_eq!(map.relative_path(2).as_deref(), Some(&b"caf\xe9"[..]));
    }

    #[test]
    fn forget_removes_at_zero() {
        let mut map = tree();
        map.insert(D, b"f", F);
        map.forget(F, 1);
        assert_eq!(map.path(F), "/d/f");
        map.forget(F, 1);
        assert_eq!(map.path(F), "<ino:3>");
        assert_eq!(map.inodes(), [ROOT_INO, D, G]);
        // The name is free for the next inode.
        map.insert(D, b"f", 9);
        assert_eq!(map.path(9), "/d/f");
        map.forget(42, 1);
    }

    #[test]
    fn dot_lookups_count_without_renaming() {
        let mut map = tree();
        map.insert(F, b"..", D);
        assert_eq!(map.path(D), "/d");
        map.forget(D, 1);
        assert_eq!(map.path(D), "/d", "one lookup is left");
        map.forget(D, 1);
        assert_eq!(map.path(D), "<ino:2>");
    }

    #[test]
    fn renaming_a_directory_moves_its_children() {
        let mut map = tree();
        map.rename(ROOT_INO, b"d", ROOT_INO, b"e");
        assert_eq!(map.path(F), "/e/f");
        map.rename(D, b"f", ROOT_INO, b"top");
        assert_eq!(map.path(F), "/top");
        // Renaming over a name deletes what it named.
        map.rename(ROOT_INO, b"top", ROOT_INO, b"g");
        assert_eq!(map.path(F), "/g");
        assert!(map.is_deleted(G));
        assert_eq!(map.path(G), "/g", "a deleted node keeps its last name");
        map.mark_deleted(ROOT_INO, b"g");
        assert!(map.is_deleted(F));
    }

    #[test]
    fn exchange_swaps_two_names() {
        let mut map = tree();
        map.exchange(D, b"f", ROOT_INO, b"g");
        assert_eq!(map.path(F), "/g");
        assert_eq!(map.path(G), "/d/f");
        assert!(!map.is_deleted(F) && !map.is_deleted(G));
        map.mark_deleted(ROOT_INO, b"g");
        assert!(map.is_deleted(F));
        assert!(!map.is_deleted(G));
    }

    #[test]
    fn unlink_marks_deleted_until_forgotten() {
        let mut map = tree();
        map.mark_deleted(D, b"f");
        assert!(map.is_deleted(F));
        assert_eq!(map.path(F), "/d/f");
        // A new file under the old name is a different node.
        map.insert(D, b"f", 9);
        assert_eq!(map.path(9), "/d/f");
        assert!(!map.is_deleted(9));
        map.forget(F, 1);
        assert_eq!(map.inodes(), [ROOT_INO, D, G, 9]);
        assert_eq!(
            map.path(9),
            "/d/f",
            "forgetting the old node keeps the new name"
        );
    }

    #[test]
    fn a_hard_link_keeps_the_file_named_until_its_last_name_goes() {
        let mut map = tree();
        map.insert(ROOT_INO, b"hard", F);
        assert_eq!(map.path(F), "/d/f", "the first name stays primary");
        map.mark_deleted(D, b"f");
        assert!(!map.is_deleted(F));
        assert_eq!(map.path(F), "/hard");
        map.rename(ROOT_INO, b"hard", D, b"back");
        assert_eq!(map.path(F), "/d/back");
        map.mark_deleted(D, b"back");
        assert!(map.is_deleted(F));
        map.forget(F, 2);
        assert_eq!(map.inodes(), [ROOT_INO, D, G]);
    }

    #[test]
    fn renaming_one_link_onto_another_changes_nothing() {
        let mut map = tree();
        map.insert(ROOT_INO, b"hard", F);
        map.rename(D, b"f", ROOT_INO, b"hard");
        assert_eq!(map.path(F), "/d/f");
        assert!(!map.is_deleted(F));
    }

    #[test]
    fn a_name_looked_up_again_after_host_changes_follows_the_new_inode() {
        let mut map = tree();
        // The host replaced /g behind the guest's back.
        map.insert(ROOT_INO, b"g", 10);
        assert_eq!(map.path(10), "/g");
        assert!(map.is_deleted(G));
        // And the guest sees a deleted file under its name again.
        map.insert(ROOT_INO, b"again", G);
        assert!(!map.is_deleted(G));
        assert_eq!(map.path(G), "/again");
    }

    #[test]
    fn host_ids_follow_the_node() {
        let mut map = tree();
        let id = FileId { dev: 8, ino: 1234 };
        map.set_host_id(F, id);
        assert_eq!(map.host_id(F), Some(id));
        assert_eq!(map.host_id(G), None);
        map.set_host_id(99, id);
        assert_eq!(map.host_id(99), None);
        map.reset();
        assert_eq!(map.inodes(), [ROOT_INO]);
    }
}
