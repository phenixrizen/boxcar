// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! An overlay of boxcar's own for image sessions: the cached image tree
//! read-only below, a per-session directory above, both on the host, and
//! the guest shown their union. `AuditFs` sits above it as it sits above
//! the passthrough.
//!
//! - **Lookup and readdir** merge the two: an upper entry hides a lower
//!   one of the same name; a whiteout above (an empty file `.wh.<name>`,
//!   the OCI layer convention the unpacker already reads) hides a lower
//!   entry; an opaque mark above (`.wh..wh..opq` in a directory) hides
//!   everything below that directory. Names beginning with `.wh.` are the
//!   overlay's own: never shown, never made.
//! - **Reads** go to whichever layer holds the entry. **Writes** copy up
//!   first: a lower file opened for writing (or truncated, or whose
//!   attributes or xattrs change) is copied to the upper directory with
//!   its data, mode, times and user xattrs (the ownership override among
//!   them), its parent directories made above as shells; then the request
//!   goes to the copy. What is created is created above.
//! - **Rename** works within the upper layer: a lower source is copied up
//!   first, a directory with its whole lower subtree (less what is whited
//!   out), then marked opaque; the old name gets a whiteout where a lower
//!   entry remains. So `rename(2)` never answers `EXDEV`.
//! - **Unlink and rmdir** remove the upper entry and leave a whiteout
//!   where a lower one remains; `rmdir` refuses a directory that is not
//!   empty in the merge.
//! - **Modes.** The cache stores every entry readable by its owner and
//!   lists the image's modes of the rest (`image.json`'s `modes`); the
//!   overlay shows those modes, for the lower entry and for its copy
//!   (which keeps the readable mode on the host, so the copy-up can go
//!   on beneath it), until the guest sets a mode of its own.
//!
//! Each layer is a filesystem of its own (a `PassthroughFs` over its
//! directory) with inode numbers of its own; the overlay keeps a table
//! from its inodes to the layers', and from its handles to the layers'.
//! A copy-up is reported through a hook, for the audit above to record.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use fuse_backend_rs::abi::fuse_abi::{stat64, statvfs64, CreateIn};
use fuse_backend_rs::abi::virtio_fs::RemovemappingOne;
use fuse_backend_rs::api::filesystem::{
    Context, DirEntry, Entry, FileLock, FileSystem, FsOptions, GetxattrReply, IoctlData,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, ROOT_ID,
};
use fuse_backend_rs::transport::FsCacheReqHandler;

/// The prefix of a whiteout's name: `.wh.<name>` hides `<name>` below.
pub const WHITEOUT_PREFIX: &[u8] = b".wh.";
/// The name of an opaque mark: a directory holding it shows nothing of
/// the layer below.
pub const OPAQUE_MARK: &[u8] = b".wh..wh..opq";

/// `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT`.
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const RENAME_WHITEOUT: u32 = 4;

/// Bytes a directory listing is read in at a time.
const LIST_CHUNK: u32 = 64 * 1024;

/// The context of the overlay's own lookups on a layer (the layers take
/// root's credentials from `AuditFs` anyway).
const ROOT_CTX: Context = Context {
    uid: 0,
    gid: 0,
    pid: 0,
};

/// A filesystem the overlay can sit over.
pub trait Layer: FileSystem<Inode = u64, Handle = u64> + Send + Sync {}
impl<F: FileSystem<Inode = u64, Handle = u64> + Send + Sync> Layer for F {}

/// Which layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Which {
    Lower,
    Upper,
}

/// A node's presence in one layer: the layer's inode and how many lookups
/// the overlay owes it.
#[derive(Clone, Copy, Debug)]
struct Side {
    ino: u64,
    lookups: u64,
}

/// One overlay inode.
#[derive(Clone, Debug)]
struct Node {
    parent: u64,
    name: Vec<u8>,
    lower: Option<Side>,
    upper: Option<Side>,
    /// The kernel's lookups of this inode not yet forgotten.
    lookups: u64,
    dir: bool,
    /// A directory above that hides everything below it.
    opaque: bool,
}

impl Node {
    /// The layer whose attributes the guest sees.
    fn primary(&self) -> Option<(Which, u64)> {
        if let Some(upper) = self.upper {
            Some((Which::Upper, upper.ino))
        } else {
            self.lower.map(|lower| (Which::Lower, lower.ino))
        }
    }
}

/// The inode table.
struct Nodes {
    by_ino: HashMap<u64, Node>,
    by_name: HashMap<(u64, Vec<u8>), u64>,
    next: u64,
}

impl Nodes {
    fn new() -> Nodes {
        let mut by_ino = HashMap::new();
        by_ino.insert(
            ROOT_ID,
            Node {
                parent: ROOT_ID,
                name: Vec::new(),
                lower: Some(Side {
                    ino: ROOT_ID,
                    lookups: 0,
                }),
                upper: Some(Side {
                    ino: ROOT_ID,
                    lookups: 0,
                }),
                lookups: 1,
                dir: true,
                opaque: false,
            },
        );
        Nodes {
            by_ino,
            by_name: HashMap::new(),
            next: ROOT_ID + 1,
        }
    }

    fn get(&self, ino: u64) -> io::Result<&Node> {
        self.by_ino.get(&ino).ok_or_else(|| errno(libc::ENOENT))
    }

    fn get_mut(&mut self, ino: u64) -> io::Result<&mut Node> {
        self.by_ino.get_mut(&ino).ok_or_else(|| errno(libc::ENOENT))
    }

    /// The path of `ino` from the root, components joined by `/`, empty
    /// for the root.
    fn path_of(&self, ino: u64) -> io::Result<Vec<u8>> {
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut at = ino;
        while at != ROOT_ID {
            let node = self.get(at)?;
            parts.push(&node.name);
            at = node.parent;
            if parts.len() > 4096 {
                return Err(errno(libc::ELOOP));
            }
        }
        parts.reverse();
        Ok(parts.join(&b'/'))
    }

    /// Whether `ino` is `ancestor` or beneath it.
    fn beneath(&self, ino: u64, ancestor: u64) -> bool {
        let mut at = ino;
        loop {
            if at == ancestor {
                return true;
            }
            if at == ROOT_ID {
                return false;
            }
            match self.by_ino.get(&at) {
                Some(node) => at = node.parent,
                None => return false,
            }
        }
    }
}

/// An open file or directory.
enum Opened {
    File { which: Which, ino: u64, handle: u64 },
    Dir(Vec<Listed>),
}

/// One entry of a listing.
#[derive(Clone, Debug)]
struct Listed {
    name: Vec<u8>,
    ino: u64,
    type_: u32,
}

/// Told of each copy-up: the path from the root and the bytes copied.
pub type CopyUpHook = Box<dyn Fn(&[u8], u64) + Send + Sync>;

/// The overlay: `lower` read-only, `upper` for the session.
pub struct OverlayFs<L: Layer, U: Layer> {
    lower: L,
    upper: U,
    /// The layers' directories on the host, for the copy-up.
    lower_root: OwnedFd,
    upper_root: OwnedFd,
    /// The image's modes of entries the cache stores otherwise, by path
    /// from the root, shown until the guest sets the entry's mode.
    modes: Mutex<HashMap<Vec<u8>, u32>>,
    nodes: Mutex<Nodes>,
    handles: Mutex<HashMap<u64, Opened>>,
    next_handle: AtomicU64,
    copy_up_hook: Option<CopyUpHook>,
}

impl<L: Layer, U: Layer> OverlayFs<L, U> {
    /// An overlay of `upper` (a filesystem over `upper_root`) over
    /// `lower` (one over `lower_root`); `modes` as `image.json` lists
    /// them.
    pub fn new(
        lower: L,
        lower_root: OwnedFd,
        upper: U,
        upper_root: OwnedFd,
        modes: &[(String, u32)],
    ) -> OverlayFs<L, U> {
        OverlayFs {
            lower,
            upper,
            lower_root,
            upper_root,
            modes: Mutex::new(
                modes
                    .iter()
                    .map(|(path, mode)| (path.as_bytes().to_vec(), *mode & 0o7777))
                    .collect(),
            ),
            nodes: Mutex::new(Nodes::new()),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            copy_up_hook: None,
        }
    }

    /// Tells `hook` of every copy-up.
    pub fn with_copy_up_hook(mut self, hook: CopyUpHook) -> Self {
        self.copy_up_hook = Some(hook);
        self
    }

    fn layer(&self, which: Which) -> &dyn FileSystem<Inode = u64, Handle = u64> {
        match which {
            Which::Lower => &self.lower,
            Which::Upper => &self.upper,
        }
    }

    fn nodes(&self) -> std::sync::MutexGuard<'_, Nodes> {
        self.nodes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn handles(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Opened>> {
        self.handles.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The node, copied out of the table.
    fn node(&self, ino: u64) -> io::Result<Node> {
        self.nodes().get(ino).cloned()
    }

    /// The layer and layer inode whose attributes `ino` shows. A node
    /// whose lower side a directory copy-up hid has its copy above,
    /// adopted here.
    fn primary(&self, ino: u64) -> io::Result<(Which, u64)> {
        let node = self.node(ino)?;
        if let Some(primary) = node.primary() {
            return Ok(primary);
        }
        let parent = self
            .node(node.parent)?
            .upper
            .ok_or_else(|| errno(libc::ENOENT))?;
        let name = cstring(&node.name)?;
        let found = self
            .layer_lookup(&ROOT_CTX, Which::Upper, parent.ino, &name)?
            .ok_or_else(|| errno(libc::ENOENT))?;
        let mut nodes = self.nodes();
        let node = nodes.get_mut(ino)?;
        match node.upper {
            Some(side) => {
                drop(nodes);
                self.upper.forget(&ROOT_CTX, found.inode, 1);
                Ok((Which::Upper, side.ino))
            }
            None => {
                node.upper = Some(Side {
                    ino: found.inode,
                    lookups: 1,
                });
                Ok((Which::Upper, found.inode))
            }
        }
    }

    fn modes(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, u32>> {
        self.modes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `st` as the guest sees it: the image's mode for an entry the cache
    /// stores otherwise.
    fn present(&self, ino: u64, _which: Which, st: &mut stat64) {
        let modes = self.modes();
        if modes.is_empty() {
            return;
        }
        if let Ok(path) = self.nodes().path_of(ino) {
            if let Some(mode) = modes.get(&path) {
                st.st_mode = (st.st_mode & libc::S_IFMT) | mode;
            }
        }
    }

    /// Whether the upper layer holds a whiteout of `name` in its
    /// directory `upper_parent`.
    fn whited_out(&self, ctx: &Context, upper_parent: u64, name: &[u8]) -> io::Result<bool> {
        let wh = cstring(&whiteout_name(name))?;
        match self.upper.lookup(ctx, upper_parent, &wh) {
            Ok(entry) => {
                if entry.inode != 0 {
                    self.upper.forget(ctx, entry.inode, 1);
                }
                Ok(entry.inode != 0)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Whether the upper directory `upper_dir` holds the opaque mark.
    fn is_opaque(&self, ctx: &Context, upper_dir: u64) -> io::Result<bool> {
        let mark = cstring(OPAQUE_MARK)?;
        match self.upper.lookup(ctx, upper_dir, &mark) {
            Ok(entry) => {
                if entry.inode != 0 {
                    self.upper.forget(ctx, entry.inode, 1);
                }
                Ok(entry.inode != 0)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Makes an empty file `name` in the upper directory `upper_parent`
    /// (a whiteout or an opaque mark); one there already is fine.
    fn make_mark(&self, ctx: &Context, upper_parent: u64, name: &[u8]) -> io::Result<()> {
        let name = cstring(name)?;
        match self
            .upper
            .mknod(ctx, upper_parent, &name, libc::S_IFREG | 0o600, 0, 0)
        {
            Ok(entry) => {
                if entry.inode != 0 {
                    self.upper.forget(ctx, entry.inode, 1);
                }
                Ok(())
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Removes the whiteout of `name` from the upper directory, if any.
    fn drop_whiteout(&self, ctx: &Context, upper_parent: u64, name: &[u8]) -> io::Result<()> {
        let wh = cstring(&whiteout_name(name))?;
        match self.upper.unlink(ctx, upper_parent, &wh) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// A lookup on one layer: `None` for a negative answer.
    fn layer_lookup(
        &self,
        ctx: &Context,
        which: Which,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Option<Entry>> {
        match self.layer(which).lookup(ctx, parent, name) {
            Ok(entry) if entry.inode == 0 => Ok(None),
            Ok(entry) => Ok(Some(entry)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The entry the guest gets for `ino` from the layer entry `found`.
    fn entry_for(&self, ino: u64, which: Which, mut found: Entry) -> Entry {
        self.present(ino, which, &mut found.attr);
        found.inode = ino;
        found.generation = 0;
        found
    }

    /// [`FileSystem::lookup`]: the merge of the two layers at `name`.
    fn do_lookup(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        let name_bytes = name.to_bytes();
        if is_reserved(name_bytes) || name_bytes == b"." || name_bytes == b".." {
            return Err(errno(libc::ENOENT));
        }
        let parent_node = self.node(parent)?;
        if !parent_node.dir {
            return Err(errno(libc::ENOTDIR));
        }
        // Known already: one more lookup, the attributes as they are now.
        let known = self
            .nodes()
            .by_name
            .get(&(parent, name_bytes.to_vec()))
            .copied();
        if let Some(ino) = known {
            let (which, layer_ino) = self.primary(ino)?;
            let (mut attr, attr_timeout) = self.layer(which).getattr(ctx, layer_ino, None)?;
            self.present(ino, which, &mut attr);
            self.nodes().get_mut(ino)?.lookups += 1;
            return Ok(Entry {
                inode: ino,
                generation: 0,
                attr,
                attr_flags: 0,
                attr_timeout,
                entry_timeout: attr_timeout,
            });
        }
        // Above first.
        let mut upper: Option<Entry> = None;
        let mut opaque = false;
        if let Some(side) = parent_node.upper {
            upper = self.layer_lookup(ctx, Which::Upper, side.ino, name)?;
            match &upper {
                Some(found) => {
                    if is_dir(&found.attr) {
                        opaque = self.is_opaque(ctx, found.inode)?;
                    }
                }
                None => {
                    if self.whited_out(ctx, side.ino, name_bytes)? {
                        return Err(errno(libc::ENOENT));
                    }
                }
            }
        }
        // Below, where the parent merges and nothing above hides it.
        let mut lower: Option<Entry> = None;
        let merges = !parent_node.opaque
            && match &upper {
                Some(found) => is_dir(&found.attr) && !opaque,
                None => true,
            };
        if merges {
            if let Some(side) = parent_node.lower {
                lower = self.layer_lookup(ctx, Which::Lower, side.ino, name)?;
                if let (Some(found), Some(above)) = (&lower, &upper) {
                    // A directory above merges only with a directory below.
                    if !is_dir(&found.attr) || !is_dir(&above.attr) {
                        self.lower.forget(ctx, found.inode, 1);
                        lower = None;
                    }
                }
            }
        }
        let (which, found) = match (&upper, &lower) {
            (Some(found), _) => (Which::Upper, *found),
            (None, Some(found)) => (Which::Lower, *found),
            (None, None) => return Err(errno(libc::ENOENT)),
        };
        let dir = is_dir(&found.attr);
        let node = Node {
            parent,
            name: name_bytes.to_vec(),
            lower: lower.as_ref().map(|e| Side {
                ino: e.inode,
                lookups: 1,
            }),
            upper: upper.as_ref().map(|e| Side {
                ino: e.inode,
                lookups: 1,
            }),
            lookups: 1,
            dir,
            opaque,
        };
        let ino = {
            let mut nodes = self.nodes();
            let key = (parent, name_bytes.to_vec());
            if let Some(&ino) = nodes.by_name.get(&key) {
                // Another thread got here first: its node, the layer
                // lookups of this one given back.
                drop(nodes);
                if let Some(e) = &lower {
                    self.lower.forget(ctx, e.inode, 1);
                }
                if let Some(e) = &upper {
                    self.upper.forget(ctx, e.inode, 1);
                }
                self.nodes().get_mut(ino)?.lookups += 1;
                return Ok(self.entry_for(ino, which, found));
            }
            let ino = nodes.next;
            nodes.next += 1;
            nodes.by_ino.insert(ino, node);
            nodes.by_name.insert(key, ino);
            ino
        };
        Ok(self.entry_for(ino, which, found))
    }

    /// The node at `name` in `parent`, looked up if the table does not
    /// have it (the kernel looks up before it acts on a name, so it is
    /// there in practice); `None` where nothing is.
    fn child(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Option<u64>> {
        let key = (parent, name.to_bytes().to_vec());
        if let Some(&ino) = self.nodes().by_name.get(&key) {
            return Ok(Some(ino));
        }
        match self.do_lookup(ctx, parent, name) {
            Ok(entry) => Ok(Some(entry.inode)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Drops `n` of the kernel's lookups of `ino`; at zero, the node goes
    /// and the layers are told.
    fn do_forget(&self, ctx: &Context, ino: u64, n: u64) {
        if ino == ROOT_ID {
            return;
        }
        let gone = {
            let mut nodes = self.nodes();
            let Some(node) = nodes.by_ino.get_mut(&ino) else {
                return;
            };
            node.lookups = node.lookups.saturating_sub(n);
            if node.lookups > 0 {
                return;
            }
            let node = nodes.by_ino.remove(&ino).expect("just seen");
            let key = (node.parent, node.name.clone());
            if nodes.by_name.get(&key) == Some(&ino) {
                nodes.by_name.remove(&key);
            }
            node
        };
        if let Some(side) = gone.lower {
            if side.lookups > 0 {
                self.lower.forget(ctx, side.ino, side.lookups);
            }
        }
        if let Some(side) = gone.upper {
            if side.lookups > 0 {
                self.upper.forget(ctx, side.ino, side.lookups);
            }
        }
    }

    /// The upper inode of `ino`, copied up first where it has none: its
    /// parents as shells, then itself (a directory as a shell, a file
    /// with its data).
    fn ensure_upper(&self, ctx: &Context, ino: u64) -> io::Result<u64> {
        let node = self.node(ino)?;
        if let Some(side) = node.upper {
            return Ok(side.ino);
        }
        if ino == ROOT_ID {
            return Err(errno(libc::ENOENT));
        }
        let upper_parent = self.ensure_upper(ctx, node.parent)?;
        let name = cstring(&node.name)?;
        // The copy may be there already (a directory copied up whole).
        let found = match self.layer_lookup(ctx, Which::Upper, upper_parent, &name)? {
            Some(found) => found,
            None => {
                let path = self.nodes().path_of(ino)?;
                let bytes = self.copy_entry(&path)?;
                if let Some(hook) = &self.copy_up_hook {
                    hook(&path, bytes);
                }
                self.layer_lookup(ctx, Which::Upper, upper_parent, &name)?
                    .ok_or_else(|| errno(libc::ENOENT))?
            }
        };
        let mut nodes = self.nodes();
        let node = nodes.get_mut(ino)?;
        match node.upper {
            Some(side) => {
                // Another thread copied it up meanwhile.
                drop(nodes);
                self.upper.forget(ctx, found.inode, 1);
                Ok(side.ino)
            }
            None => {
                node.upper = Some(Side {
                    ino: found.inode,
                    lookups: 1,
                });
                Ok(found.inode)
            }
        }
    }

    /// Copies the lower entry at `path` to the same path above, through
    /// host descriptors beneath each root (the parent above is there
    /// already). The bytes copied.
    fn copy_entry(&self, path: &[u8]) -> io::Result<u64> {
        let (parent, name) = match path.iter().rposition(|b| *b == b'/') {
            Some(at) => (&path[..at], &path[at + 1..]),
            None => (&b""[..], path),
        };
        let lower_dir = open_dir_beneath(&self.lower_root, parent)?;
        let upper_dir = open_dir_beneath(&self.upper_root, parent)?;
        copy_one(&lower_dir, &upper_dir, &cstring(name)?)
    }

    /// Copies up everything below the directory `ino` that the merge
    /// shows and the upper layer does not hold yet, then marks the upper
    /// directory opaque: nothing below it is looked at again. The upper
    /// inode.
    fn copy_up_tree(&self, ctx: &Context, ino: u64) -> io::Result<u64> {
        let upper_ino = self.ensure_upper(ctx, ino)?;
        let path = self.nodes().path_of(ino)?;
        let lower_dir = open_dir_beneath(&self.lower_root, &path)?;
        let upper_dir = open_dir_beneath(&self.upper_root, &path)?;
        let mut bytes = 0;
        self.copy_dir_contents(&lower_dir, &upper_dir, &mut bytes)?;
        if let Some(hook) = &self.copy_up_hook {
            hook(&path, bytes);
        }
        self.make_mark(ctx, upper_ino, OPAQUE_MARK)?;
        // Below is hidden now: the nodes beneath are done with their
        // lower side.
        let to_forget = {
            let mut nodes = self.nodes();
            let beneath: Vec<u64> = nodes
                .by_ino
                .keys()
                .copied()
                .filter(|&n| n != ino && nodes.beneath(n, ino))
                .collect();
            let mut out = Vec::new();
            for n in beneath {
                if let Some(side) = nodes.by_ino.get_mut(&n).and_then(|node| node.lower.take()) {
                    out.push(side);
                }
            }
            if let Some(node) = nodes.by_ino.get_mut(&ino) {
                node.opaque = true;
                if let Some(side) = node.lower.take() {
                    out.push(side);
                }
            }
            out
        };
        for side in to_forget {
            if side.lookups > 0 {
                self.lower.forget(ctx, side.ino, side.lookups);
            }
        }
        Ok(upper_ino)
    }

    /// The lower directory `lower_dir`'s entries into `upper_dir`, where
    /// the upper does not hold or hide them, recursively.
    fn copy_dir_contents(
        &self,
        lower_dir: &OwnedFd,
        upper_dir: &OwnedFd,
        bytes: &mut u64,
    ) -> io::Result<()> {
        if exists_at(upper_dir, &cstring(OPAQUE_MARK)?)? {
            return Ok(());
        }
        for name in list_dir_fd(upper_dir, lower_dir)? {
            let cname = cstring(&name)?;
            if exists_at(upper_dir, &cstring(&whiteout_name(&name))?)? {
                continue;
            }
            let lower_st = fstatat_nofollow(lower_dir, &cname)?;
            match fstatat_nofollow(upper_dir, &cname) {
                Ok(upper_st) => {
                    // Only a directory over a directory merges.
                    if is_dir_mode(lower_st.st_mode) && is_dir_mode(upper_st.st_mode) {
                        let ld = open_dir_at(lower_dir, &cname)?;
                        let ud = open_dir_at(upper_dir, &cname)?;
                        self.copy_dir_contents(&ld, &ud, bytes)?;
                    }
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    *bytes += copy_one(lower_dir, upper_dir, &cname)?;
                    if is_dir_mode(lower_st.st_mode) {
                        let ld = open_dir_at(lower_dir, &cname)?;
                        let ud = open_dir_at(upper_dir, &cname)?;
                        self.copy_dir_contents(&ld, &ud, bytes)?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Whether the lower layer holds `name` in `parent`, as the merge
    /// would show it were nothing above.
    fn lower_has(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<bool> {
        let node = self.node(parent)?;
        if node.opaque {
            return Ok(false);
        }
        let Some(side) = node.lower else {
            return Ok(false);
        };
        match self.layer_lookup(ctx, Which::Lower, side.ino, name)? {
            Some(found) => {
                self.lower.forget(ctx, found.inode, 1);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Whether the merge shows `name` in `parent`.
    fn merge_has(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<bool> {
        match self.do_lookup(ctx, parent, name) {
            Ok(entry) => {
                self.do_forget(ctx, entry.inode, 1);
                Ok(true)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Every entry of one layer's directory, as the layer lists it.
    fn list_layer(&self, ctx: &Context, which: Which, ino: u64) -> io::Result<Vec<Listed>> {
        let layer = self.layer(which);
        let (handle, _) = layer.opendir(ctx, ino, libc::O_RDONLY as u32)?;
        let handle = handle.unwrap_or(0);
        let mut out: Vec<Listed> = Vec::new();
        let mut offset = 0;
        let result = loop {
            let mut got = 0;
            let mut last = offset;
            let read = layer.readdir(ctx, ino, handle, LIST_CHUNK, offset, &mut |entry| {
                out.push(Listed {
                    name: entry.name.to_vec(),
                    ino: entry.ino,
                    type_: entry.type_,
                });
                last = entry.offset;
                got += 1;
                Ok(entry.name.len() + 24)
            });
            if let Err(error) = read {
                break Err(error);
            }
            if got == 0 || last == offset {
                break Ok(());
            }
            offset = last;
        };
        let _ = layer.releasedir(ctx, ino, 0, handle);
        result?;
        Ok(out)
    }

    /// The merge of the directory `ino`: the upper entries, then the
    /// lower ones nothing above hides; neither `.` nor `..`, nor the
    /// overlay's own marks.
    fn list_merged(&self, ctx: &Context, ino: u64) -> io::Result<Vec<Listed>> {
        let node = self.node(ino)?;
        if !node.dir {
            return Err(errno(libc::ENOTDIR));
        }
        let mut out = Vec::new();
        let mut names = std::collections::HashSet::new();
        let mut whiteouts = std::collections::HashSet::new();
        let mut opaque = node.opaque;
        if let Some(side) = node.upper {
            for entry in self.list_layer(ctx, Which::Upper, side.ino)? {
                if entry.name == b"." || entry.name == b".." {
                    continue;
                }
                if entry.name == OPAQUE_MARK {
                    opaque = true;
                    continue;
                }
                if let Some(hidden) = entry.name.strip_prefix(WHITEOUT_PREFIX) {
                    whiteouts.insert(hidden.to_vec());
                    continue;
                }
                names.insert(entry.name.clone());
                out.push(entry);
            }
        }
        if !opaque {
            if let Some(side) = node.lower {
                for entry in self.list_layer(ctx, Which::Lower, side.ino)? {
                    if entry.name == b"."
                        || entry.name == b".."
                        || is_reserved(&entry.name)
                        || names.contains(&entry.name)
                        || whiteouts.contains(&entry.name)
                    {
                        continue;
                    }
                    out.push(entry);
                }
            }
        }
        Ok(out)
    }

    /// Removes the overlay's marks from the upper directory `upper_dir`,
    /// before it is removed or renamed over.
    fn clear_marks(&self, ctx: &Context, upper_dir: u64) -> io::Result<()> {
        for entry in self.list_layer(ctx, Which::Upper, upper_dir)? {
            if is_reserved(&entry.name) {
                self.upper.unlink(ctx, upper_dir, &cstring(&entry.name)?)?;
            }
        }
        Ok(())
    }

    /// A node for what was just made above at `name` in `parent`.
    fn adopt_upper(
        &self,
        parent: u64,
        name: &CStr,
        found: Entry,
        opaque: bool,
    ) -> io::Result<Entry> {
        let dir = is_dir(&found.attr);
        let ino = {
            let mut nodes = self.nodes();
            let ino = nodes.next;
            nodes.next += 1;
            nodes.by_ino.insert(
                ino,
                Node {
                    parent,
                    name: name.to_bytes().to_vec(),
                    lower: None,
                    upper: Some(Side {
                        ino: found.inode,
                        lookups: 1,
                    }),
                    lookups: 1,
                    dir,
                    opaque,
                },
            );
            nodes
                .by_name
                .insert((parent, name.to_bytes().to_vec()), ino);
            ino
        };
        Ok(self.entry_for(ino, Which::Upper, found))
    }

    /// Before something is made at `name` in `parent`: the name must be
    /// the guest's to use and free in the merge; the parent above, and
    /// any whiteout of the name gone. The upper parent, and whether a
    /// lower entry stays hidden beneath the new one.
    fn before_making(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<(u64, bool)> {
        if is_reserved(name.to_bytes()) {
            return Err(errno(libc::EPERM));
        }
        if self.merge_has(ctx, parent, name)? {
            return Err(errno(libc::EEXIST));
        }
        let upper_parent = self.ensure_upper(ctx, parent)?;
        self.drop_whiteout(ctx, upper_parent, name.to_bytes())?;
        let hides_lower = self.lower_has(ctx, parent, name)?;
        Ok((upper_parent, hides_lower))
    }

    /// The layer and layer handle behind `handle`.
    fn file_handle(&self, handle: u64) -> io::Result<(Which, u64, u64)> {
        match self.handles().get(&handle) {
            Some(Opened::File { which, ino, handle }) => Ok((*which, *ino, *handle)),
            _ => Err(errno(libc::EBADF)),
        }
    }

    fn new_handle(&self, opened: Opened) -> u64 {
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles().insert(id, opened);
        id
    }

    /// The listing behind a directory handle, `.` and `..` first.
    fn dir_handle(&self, handle: u64) -> io::Result<Vec<Listed>> {
        match self.handles().get(&handle) {
            Some(Opened::Dir(entries)) => Ok(entries.clone()),
            _ => Err(errno(libc::EBADF)),
        }
    }

    fn do_rename(
        &self,
        ctx: &Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
            return Err(errno(libc::EINVAL));
        }
        if is_reserved(oldname.to_bytes()) {
            return Err(errno(libc::ENOENT));
        }
        if is_reserved(newname.to_bytes()) {
            return Err(errno(libc::EPERM));
        }
        let src = self
            .child(ctx, olddir, oldname)?
            .ok_or_else(|| errno(libc::ENOENT))?;
        let dst = self.child(ctx, newdir, newname)?;
        if flags & RENAME_NOREPLACE != 0 && dst.is_some() {
            return Err(errno(libc::EEXIST));
        }
        let src_node = self.node(src)?;
        if let Some(dst) = dst {
            if dst == src {
                return Ok(());
            }
            let dst_node = self.node(dst)?;
            if src_node.dir && !dst_node.dir {
                return Err(errno(libc::ENOTDIR));
            }
            if !src_node.dir && dst_node.dir {
                return Err(errno(libc::EISDIR));
            }
            if dst_node.dir && !self.list_merged(ctx, dst)?.is_empty() {
                return Err(errno(libc::ENOTEMPTY));
            }
        }
        if src_node.dir && self.nodes().beneath(newdir, src) {
            return Err(errno(libc::EINVAL));
        }
        // Whether something below stays at the old name, before anything
        // moves.
        let lower_at_old = self.lower_has(ctx, olddir, oldname)?;
        // The source above, whole (a directory with its lower subtree, and
        // then opaque, so a lower directory at the new name cannot merge
        // into it); both directories above.
        if src_node.dir {
            self.copy_up_tree(ctx, src)?;
        } else {
            self.ensure_upper(ctx, src)?;
        }
        let old_upper = self.ensure_upper(ctx, olddir)?;
        let new_upper = self.ensure_upper(ctx, newdir)?;
        if let Some(dst) = dst {
            let dst_node = self.node(dst)?;
            if let Some(side) = dst_node.upper {
                if dst_node.dir {
                    self.clear_marks(ctx, side.ino)?;
                }
            }
        }
        self.drop_whiteout(ctx, new_upper, newname.to_bytes())?;
        self.upper
            .rename(ctx, old_upper, oldname, new_upper, newname, flags)?;
        if lower_at_old {
            self.make_mark(ctx, old_upper, &whiteout_name(oldname.to_bytes()))?;
        }
        // The image's modes follow the move.
        {
            let (old_path, new_path) = {
                let nodes = self.nodes();
                (
                    child_path(&nodes.path_of(olddir)?, oldname.to_bytes()),
                    child_path(&nodes.path_of(newdir)?, newname.to_bytes()),
                )
            };
            let mut modes = self.modes();
            let moved: Vec<(Vec<u8>, u32)> = modes
                .iter()
                .filter(|(path, _)| {
                    *path == &old_path
                        || (path.starts_with(&old_path) && path.get(old_path.len()) == Some(&b'/'))
                })
                .map(|(path, mode)| (path.clone(), *mode))
                .collect();
            for (path, mode) in moved {
                modes.remove(&path);
                let mut renamed = new_path.clone();
                renamed.extend_from_slice(&path[old_path.len()..]);
                modes.insert(renamed, mode);
            }
        }
        let opaque = src_node.dir;
        let to_forget = {
            let mut nodes = self.nodes();
            let old_key = (olddir, oldname.to_bytes().to_vec());
            if nodes.by_name.get(&old_key) == Some(&src) {
                nodes.by_name.remove(&old_key);
            }
            let new_key = (newdir, newname.to_bytes().to_vec());
            nodes.by_name.insert(new_key, src);
            let mut out = None;
            if let Some(node) = nodes.by_ino.get_mut(&src) {
                node.parent = newdir;
                node.name = newname.to_bytes().to_vec();
                if node.dir {
                    node.opaque = opaque;
                } else {
                    // Its lower side, if any, stays at the old name.
                    out = node.lower.take();
                }
            }
            out
        };
        if let Some(side) = to_forget {
            if side.lookups > 0 {
                self.lower.forget(ctx, side.ino, side.lookups);
            }
        }
        Ok(())
    }
}

impl<L: Layer, U: Layer> FileSystem for OverlayFs<L, U> {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let lower = self.lower.init(capable)?;
        let upper = self.upper.init(capable)?;
        Ok(lower & upper)
    }

    fn destroy(&self) {
        self.lower.destroy();
        self.upper.destroy();
    }

    fn lookup(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(ctx, parent, name)
    }

    fn forget(&self, ctx: &Context, inode: u64, count: u64) {
        self.do_forget(ctx, inode, count);
    }

    fn batch_forget(&self, ctx: &Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.do_forget(ctx, inode, count);
        }
    }

    fn getattr(
        &self,
        ctx: &Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        let (which, layer_ino, layer_handle) = match handle.and_then(|h| self.file_handle(h).ok()) {
            Some((which, ino, handle)) => (which, ino, Some(handle)),
            None => {
                let (which, ino) = self.primary(inode)?;
                (which, ino, None)
            }
        };
        let (mut attr, timeout) = self.layer(which).getattr(ctx, layer_ino, layer_handle)?;
        self.present(inode, which, &mut attr);
        Ok((attr, timeout))
    }

    fn setattr(
        &self,
        ctx: &Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        let upper = self.ensure_upper(ctx, inode)?;
        let upper_handle = handle
            .and_then(|h| self.file_handle(h).ok())
            .filter(|(which, _, _)| *which == Which::Upper)
            .map(|(_, _, h)| h);
        let result = self.upper.setattr(ctx, upper, attr, upper_handle, valid)?;
        if valid.contains(SetattrValid::MODE) {
            // The guest's own mode from now on.
            if let Ok(path) = self.nodes().path_of(inode) {
                self.modes().remove(&path);
            }
        }
        let (mut attr, timeout) = result;
        self.present(inode, Which::Upper, &mut attr);
        Ok((attr, timeout))
    }

    fn readlink(&self, ctx: &Context, inode: u64) -> io::Result<Vec<u8>> {
        let (which, ino) = self.primary(inode)?;
        self.layer(which).readlink(ctx, ino)
    }

    fn symlink(
        &self,
        ctx: &Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Entry> {
        let (upper_parent, _) = self.before_making(ctx, parent, name)?;
        let found = self.upper.symlink(ctx, linkname, upper_parent, name)?;
        self.adopt_upper(parent, name, found, false)
    }

    fn mknod(
        &self,
        ctx: &Context,
        inode: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let (upper_parent, _) = self.before_making(ctx, inode, name)?;
        let found = self
            .upper
            .mknod(ctx, upper_parent, name, mode, rdev, umask)?;
        self.adopt_upper(inode, name, found, false)
    }

    fn mkdir(
        &self,
        ctx: &Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let (upper_parent, hides_lower) = self.before_making(ctx, parent, name)?;
        let found = self.upper.mkdir(ctx, upper_parent, name, mode, umask)?;
        // A lower directory the name hid stays hidden.
        if hides_lower {
            self.make_mark(ctx, found.inode, OPAQUE_MARK)?;
        }
        self.adopt_upper(parent, name, found, hides_lower)
    }

    fn unlink(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
        if is_reserved(name.to_bytes()) {
            return Err(errno(libc::ENOENT));
        }
        let ino = self
            .child(ctx, parent, name)?
            .ok_or_else(|| errno(libc::ENOENT))?;
        let node = self.node(ino)?;
        if node.dir {
            return Err(errno(libc::EISDIR));
        }
        let upper_parent = self.ensure_upper(ctx, parent)?;
        if node.upper.is_some() {
            self.upper.unlink(ctx, upper_parent, name)?;
        }
        if self.lower_has(ctx, parent, name)? {
            self.make_mark(ctx, upper_parent, &whiteout_name(name.to_bytes()))?;
        }
        let mut nodes = self.nodes();
        let key = (parent, name.to_bytes().to_vec());
        if nodes.by_name.get(&key) == Some(&ino) {
            nodes.by_name.remove(&key);
        }
        Ok(())
    }

    fn rmdir(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
        if is_reserved(name.to_bytes()) {
            return Err(errno(libc::ENOENT));
        }
        let ino = self
            .child(ctx, parent, name)?
            .ok_or_else(|| errno(libc::ENOENT))?;
        let node = self.node(ino)?;
        if !node.dir {
            return Err(errno(libc::ENOTDIR));
        }
        if !self.list_merged(ctx, ino)?.is_empty() {
            return Err(errno(libc::ENOTEMPTY));
        }
        let upper_parent = self.ensure_upper(ctx, parent)?;
        if let Some(side) = node.upper {
            self.clear_marks(ctx, side.ino)?;
            self.upper.rmdir(ctx, upper_parent, name)?;
        }
        if self.lower_has(ctx, parent, name)? {
            self.make_mark(ctx, upper_parent, &whiteout_name(name.to_bytes()))?;
        }
        let mut nodes = self.nodes();
        let key = (parent, name.to_bytes().to_vec());
        if nodes.by_name.get(&key) == Some(&ino) {
            nodes.by_name.remove(&key);
        }
        Ok(())
    }

    fn rename(
        &self,
        ctx: &Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.do_rename(ctx, olddir, oldname, newdir, newname, flags)
    }

    fn link(&self, ctx: &Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        let upper = self.ensure_upper(ctx, inode)?;
        let (upper_parent, _) = self.before_making(ctx, newparent, newname)?;
        let found = self.upper.link(ctx, upper, upper_parent, newname)?;
        self.adopt_upper(newparent, newname, found, false)
    }

    fn open(
        &self,
        ctx: &Context,
        inode: u64,
        flags: u32,
        fuse_flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions, Option<u32>)> {
        let writes = (flags & libc::O_ACCMODE as u32) != libc::O_RDONLY as u32
            || flags & (libc::O_TRUNC | libc::O_APPEND) as u32 != 0;
        let (which, layer_ino) = if writes {
            (Which::Upper, self.ensure_upper(ctx, inode)?)
        } else {
            self.primary(inode)?
        };
        let (handle, opts, out_flags) =
            self.layer(which).open(ctx, layer_ino, flags, fuse_flags)?;
        let id = self.new_handle(Opened::File {
            which,
            ino: layer_ino,
            handle: handle.unwrap_or(0),
        });
        Ok((Some(id), opts, out_flags))
    }

    fn create(
        &self,
        ctx: &Context,
        parent: u64,
        name: &CStr,
        args: CreateIn,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions, Option<u32>)> {
        let (upper_parent, _) = self.before_making(ctx, parent, name)?;
        let (found, handle, opts, out_flags) = self.upper.create(ctx, upper_parent, name, args)?;
        let layer_ino = found.inode;
        let entry = self.adopt_upper(parent, name, found, false)?;
        let id = self.new_handle(Opened::File {
            which: Which::Upper,
            ino: layer_ino,
            handle: handle.unwrap_or(0),
        });
        Ok((entry, Some(id), opts, out_flags))
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .read(ctx, ino, handle, w, size, offset, lock_owner, flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
        fuse_flags: u32,
    ) -> io::Result<usize> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which).write(
            ctx,
            ino,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            flags,
            fuse_flags,
        )
    }

    fn flush(&self, ctx: &Context, _inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which).flush(ctx, ino, handle, lock_owner)
    }

    fn fsync(&self, ctx: &Context, _inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which).fsync(ctx, ino, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .fallocate(ctx, ino, handle, mode, offset, length)
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        ctx: &Context,
        _inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        let (which, ino, layer_handle) = self.file_handle(handle)?;
        self.handles().remove(&handle);
        self.layer(which).release(
            ctx,
            ino,
            flags,
            layer_handle,
            flush,
            flock_release,
            lock_owner,
        )
    }

    fn statfs(&self, ctx: &Context, _inode: u64) -> io::Result<statvfs64> {
        self.upper.statfs(ctx, ROOT_ID)
    }

    fn setxattr(
        &self,
        ctx: &Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        let upper = self.ensure_upper(ctx, inode)?;
        self.upper.setxattr(ctx, upper, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: &Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        let (which, ino) = self.primary(inode)?;
        self.layer(which).getxattr(ctx, ino, name, size)
    }

    fn listxattr(&self, ctx: &Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        let (which, ino) = self.primary(inode)?;
        self.layer(which).listxattr(ctx, ino, size)
    }

    fn removexattr(&self, ctx: &Context, inode: u64, name: &CStr) -> io::Result<()> {
        let upper = self.ensure_upper(ctx, inode)?;
        self.upper.removexattr(ctx, upper, name)
    }

    fn opendir(
        &self,
        ctx: &Context,
        inode: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        let node = self.node(inode)?;
        if !node.dir {
            return Err(errno(libc::ENOTDIR));
        }
        let (which, ino) = self.primary(inode)?;
        let (own, _) = self.layer(which).getattr(ctx, ino, None)?;
        let parent_ino = if inode == ROOT_ID {
            own.st_ino
        } else {
            let (pwhich, pino) = self.primary(node.parent)?;
            self.layer(pwhich).getattr(ctx, pino, None)?.0.st_ino
        };
        let mut entries = vec![
            Listed {
                name: b".".to_vec(),
                ino: own.st_ino,
                type_: libc::DT_DIR as u32,
            },
            Listed {
                name: b"..".to_vec(),
                ino: parent_ino,
                type_: libc::DT_DIR as u32,
            },
        ];
        entries.extend(self.list_merged(ctx, inode)?);
        let id = self.new_handle(Opened::Dir(entries));
        Ok((Some(id), OpenOptions::empty()))
    }

    fn readdir(
        &self,
        _ctx: &Context,
        _inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> io::Result<usize>,
    ) -> io::Result<()> {
        let entries = self.dir_handle(handle)?;
        for (i, listed) in entries.iter().enumerate().skip(offset as usize) {
            let entry = DirEntry {
                ino: listed.ino,
                offset: i as u64 + 1,
                type_: listed.type_,
                name: &listed.name,
            };
            if add_entry(entry)? == 0 {
                break;
            }
        }
        Ok(())
    }

    fn readdirplus(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> io::Result<usize>,
    ) -> io::Result<()> {
        let entries = self.dir_handle(handle)?;
        for (i, listed) in entries.iter().enumerate().skip(offset as usize) {
            let dots = listed.name == b"." || listed.name == b"..";
            let looked_up = if dots {
                Entry::default()
            } else {
                match self.do_lookup(ctx, inode, &cstring(&listed.name)?) {
                    Ok(entry) => entry,
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                    Err(error) => return Err(error),
                }
            };
            let entry = DirEntry {
                ino: if dots {
                    listed.ino
                } else {
                    looked_up.attr.st_ino
                },
                offset: i as u64 + 1,
                type_: listed.type_,
                name: &listed.name,
            };
            if add_entry(entry, looked_up)? == 0 {
                // The kernel keeps no reference to an entry it did not take.
                if !dots {
                    self.do_forget(ctx, inode_of_name(self, inode, &listed.name), 1);
                }
                break;
            }
        }
        Ok(())
    }

    fn fsyncdir(&self, ctx: &Context, inode: u64, datasync: bool, _handle: u64) -> io::Result<()> {
        let node = self.node(inode)?;
        let Some(side) = node.upper else {
            return Ok(());
        };
        let (handle, _) = self.upper.opendir(ctx, side.ino, libc::O_RDONLY as u32)?;
        let handle = handle.unwrap_or(0);
        let result = self.upper.fsyncdir(ctx, side.ino, datasync, handle);
        let _ = self.upper.releasedir(ctx, side.ino, 0, handle);
        result
    }

    fn releasedir(&self, _ctx: &Context, _inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        match self.handles().remove(&handle) {
            Some(Opened::Dir(_)) => Ok(()),
            Some(opened) => {
                self.handles().insert(handle, opened);
                Err(errno(libc::EBADF))
            }
            None => Err(errno(libc::EBADF)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        _ctx: &Context,
        _inode: u64,
        _handle: u64,
        _foffset: u64,
        _len: u64,
        _flags: u64,
        _moffset: u64,
        _vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        Err(errno(libc::ENOSYS))
    }

    fn removemapping(
        &self,
        _ctx: &Context,
        _inode: u64,
        _requests: Vec<RemovemappingOne>,
        _vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        Err(errno(libc::ENOSYS))
    }

    fn access(&self, ctx: &Context, inode: u64, mask: u32) -> io::Result<()> {
        let (which, ino) = self.primary(inode)?;
        self.layer(which).access(ctx, ino, mask)
    }

    fn lseek(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which).lseek(ctx, ino, handle, offset, whence)
    }

    fn getlk(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        owner: u64,
        lock: FileLock,
        flags: u32,
    ) -> io::Result<FileLock> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .getlk(ctx, ino, handle, owner, lock, flags)
    }

    fn setlk(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        owner: u64,
        lock: FileLock,
        flags: u32,
    ) -> io::Result<()> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .setlk(ctx, ino, handle, owner, lock, flags)
    }

    fn setlkw(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        owner: u64,
        lock: FileLock,
        flags: u32,
    ) -> io::Result<()> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .setlkw(ctx, ino, handle, owner, lock, flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        flags: u32,
        cmd: u32,
        data: IoctlData,
        out_size: u32,
    ) -> io::Result<IoctlData<'_>> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .ioctl(ctx, ino, handle, flags, cmd, data, out_size)
    }

    fn bmap(&self, _ctx: &Context, _inode: u64, _block: u64, _blocksize: u32) -> io::Result<u64> {
        Err(errno(libc::ENOSYS))
    }

    fn poll(
        &self,
        ctx: &Context,
        _inode: u64,
        handle: u64,
        khandle: u64,
        flags: u32,
        events: u32,
    ) -> io::Result<u32> {
        let (which, ino, handle) = self.file_handle(handle)?;
        self.layer(which)
            .poll(ctx, ino, handle, khandle, flags, events)
    }

    fn notify_reply(&self) -> io::Result<()> {
        Ok(())
    }

    fn id_remap(&self, _ctx: &mut Context) -> io::Result<()> {
        Ok(())
    }
}

/// The overlay inode at `name` in `parent`, where the table has it.
fn inode_of_name<L: Layer, U: Layer>(fs: &OverlayFs<L, U>, parent: u64, name: &[u8]) -> u64 {
    fs.nodes()
        .by_name
        .get(&(parent, name.to_vec()))
        .copied()
        .unwrap_or(0)
}

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| errno(libc::EINVAL))
}

/// Whether `name` is the overlay's own (a whiteout or the opaque mark).
fn is_reserved(name: &[u8]) -> bool {
    name.starts_with(WHITEOUT_PREFIX)
}

fn whiteout_name(name: &[u8]) -> Vec<u8> {
    let mut out = WHITEOUT_PREFIX.to_vec();
    out.extend_from_slice(name);
    out
}

fn is_dir(attr: &stat64) -> bool {
    is_dir_mode(attr.st_mode)
}

fn is_dir_mode(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR
}

fn child_path(path: &[u8], name: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        name.to_vec()
    } else {
        let mut out = path.to_vec();
        out.push(b'/');
        out.extend_from_slice(name);
        out
    }
}

/// `struct open_how` from `linux/openat2.h`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// `openat2` beneath `root`, through no link.
fn openat2(root: &OwnedFd, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: flags as u32 as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    for _ in 0..8 {
        // SAFETY: openat2 reads `how` for the size given and the path.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd >= 0 {
            // SAFETY: a descriptor openat2 just gave, owned here.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
    }
    Err(errno(libc::EAGAIN))
}

/// The directory at `path` (empty for the root itself) beneath `root`.
fn open_dir_beneath(root: &OwnedFd, path: &[u8]) -> io::Result<OwnedFd> {
    let path = if path.is_empty() { b"." } else { path };
    openat2(
        root,
        &cstring(path)?,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
}

/// The directory `name` in `dir`, through no link.
fn open_dir_at(dir: &OwnedFd, name: &CStr) -> io::Result<OwnedFd> {
    openat(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

fn openat(
    dir: &OwnedFd,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    // SAFETY: a plain openat with a valid directory descriptor and C string.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor openat just gave, owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fstatat_nofollow(dir: &OwnedFd, name: &CStr) -> io::Result<stat64> {
    // SAFETY: fstatat64 writes one stat64.
    let mut st: stat64 = unsafe { std::mem::zeroed() };
    check(unsafe {
        libc::fstatat64(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(st)
}

fn exists_at(dir: &OwnedFd, name: &CStr) -> io::Result<bool> {
    match fstatat_nofollow(dir, name) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

fn fchmod(fd: &OwnedFd, mode: u32) -> io::Result<()> {
    // SAFETY: fchmod on a descriptor we own.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) })
}

/// The names in the directory `dir` (a descriptor opened for reading),
/// `.` and `..` left out, the overlay's own marks left out. `_keep` is
/// unused: the two descriptors are passed so a caller cannot swap them.
fn list_dir_fd(_keep: &OwnedFd, dir: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    // SAFETY: dup of a descriptor we own; fdopendir takes the duplicate.
    let dup = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes ownership of `dup`; closedir below releases it.
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `dup` is still ours when fdopendir failed.
        unsafe { libc::close(dup) };
        return Err(error);
    }
    // SAFETY: rewinddir and readdir on the stream just opened.
    unsafe { libc::rewinddir(stream) };
    let mut out = Vec::new();
    loop {
        // SAFETY: readdir on an open stream; a null answer ends it.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `d_name` is NUL-terminated within the entry.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        if name == b"." || name == b".." || is_reserved(&name) {
            continue;
        }
        out.push(name);
    }
    // SAFETY: the stream is ours; closedir closes `dup` with it.
    unsafe { libc::closedir(stream) };
    out.sort();
    Ok(out)
}

/// Copies the entry `name` of `lower_dir` into `upper_dir`: a directory
/// as an empty shell, a file with its data, a symlink with its target;
/// then its user xattrs, its mode and its times. The bytes of data
/// copied.
fn copy_one(lower_dir: &OwnedFd, upper_dir: &OwnedFd, name: &CStr) -> io::Result<u64> {
    let st = fstatat_nofollow(lower_dir, name)?;
    let mode = st.st_mode & 0o7777;
    let times = [
        libc::timespec {
            tv_sec: st.st_atime,
            tv_nsec: st.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: st.st_mtime,
            tv_nsec: st.st_mtime_nsec,
        },
    ];
    match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {
            // SAFETY: mkdirat with a valid directory descriptor and name.
            check(unsafe { libc::mkdirat(upper_dir.as_raw_fd(), name.as_ptr(), 0o700) })?;
            let src = open_dir_at(lower_dir, name)?;
            let dst = open_dir_at(upper_dir, name)?;
            copy_xattrs(&src, &dst)?;
            fchmod(&dst, mode)?;
            // SAFETY: futimens with two timespecs.
            check(unsafe { libc::futimens(dst.as_raw_fd(), times.as_ptr()) })?;
            Ok(0)
        }
        libc::S_IFREG => {
            let src = openat(
                lower_dir,
                name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?;
            let dst = openat(
                upper_dir,
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )?;
            let bytes = copy_data(&src, &dst)?;
            copy_xattrs(&src, &dst)?;
            fchmod(&dst, mode)?;
            // SAFETY: futimens with two timespecs.
            check(unsafe { libc::futimens(dst.as_raw_fd(), times.as_ptr()) })?;
            Ok(bytes)
        }
        libc::S_IFLNK => {
            let mut target = vec![0u8; libc::PATH_MAX as usize + 1];
            // SAFETY: readlinkat writes at most `target.len()` bytes.
            let n = unsafe {
                libc::readlinkat(
                    lower_dir.as_raw_fd(),
                    name.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            target.truncate(n as usize);
            let target = cstring(&target)?;
            // SAFETY: symlinkat with two C strings and a directory descriptor.
            check(unsafe {
                libc::symlinkat(target.as_ptr(), upper_dir.as_raw_fd(), name.as_ptr())
            })?;
            // SAFETY: utimensat on the link itself.
            check(unsafe {
                libc::utimensat(
                    upper_dir.as_raw_fd(),
                    name.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
            Ok(0)
        }
        _ => Err(errno(libc::EOPNOTSUPP)),
    }
}

/// `src`'s data into `dst`, by `copy_file_range` where the filesystems
/// allow, by reads and writes otherwise.
fn copy_data(src: &OwnedFd, dst: &OwnedFd) -> io::Result<u64> {
    let mut total = 0u64;
    loop {
        // SAFETY: copy_file_range with null offsets uses and advances the
        // descriptors' own.
        let n = unsafe {
            libc::copy_file_range(
                src.as_raw_fd(),
                std::ptr::null_mut(),
                dst.as_raw_fd(),
                std::ptr::null_mut(),
                1 << 30,
                0,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::EXDEV | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
                    if total == 0 =>
                {
                    copy_by_hand(src, dst)
                }
                _ => Err(error),
            };
        }
        if n == 0 {
            return Ok(total);
        }
        total += n as u64;
    }
}

fn copy_by_hand(src: &OwnedFd, dst: &OwnedFd) -> io::Result<u64> {
    use std::io::{Read, Write};
    let mut from = std::fs::File::from(src.try_clone()?);
    let mut to = std::fs::File::from(dst.try_clone()?);
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        to.write_all(&buf[..n])?;
        total += n as u64;
    }
}

/// `src`'s xattrs onto `dst`: every `user.*` one (the ownership override
/// among them); what the host refuses for other namespaces is left.
fn copy_xattrs(src: &OwnedFd, dst: &OwnedFd) -> io::Result<()> {
    // SAFETY: flistxattr with a null buffer answers the size needed.
    let size = unsafe { libc::flistxattr(src.as_raw_fd(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::EOPNOTSUPP) => Ok(()),
            _ => Err(error),
        };
    }
    let mut names = vec![0u8; size as usize];
    // SAFETY: flistxattr writes at most `names.len()` bytes.
    let size = unsafe { libc::flistxattr(src.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    names.truncate(size as usize);
    let mut value = vec![0u8; 64 * 1024];
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let cname = cstring(name)?;
        // SAFETY: fgetxattr writes at most `value.len()` bytes.
        let n = unsafe {
            libc::fgetxattr(
                src.as_raw_fd(),
                cname.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if n < 0 {
            continue;
        }
        // SAFETY: fsetxattr reads `n` bytes of the value.
        let rc = unsafe {
            libc::fsetxattr(
                dst.as_raw_fd(),
                cname.as_ptr(),
                value.as_ptr().cast(),
                n as usize,
                0,
            )
        };
        if rc < 0 && name.starts_with(b"user.") {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
