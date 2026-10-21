// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Applying a layer's entries into a tree beneath a directory. Every path
//! operation resolves the entry's parent with `openat2(root, parent,
//! RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` (the root is `/` for the
//! resolution, so an absolute symlink inside the image resolves inside
//! the tree, and nothing can leave it) and then acts on the final name
//! with an `*at` call that never follows a link. Whiteouts are applied in
//! a pass of their own, before the layer's entries, so the result does
//! not depend on the order of the archive.
//!
//! The tree is the pulling user's: each entry's owner, its special mode
//! bits and, for a device node, its numbers go into the ownership
//! override (`user.boxcar.stat`, [`boxcar_fs::ownership`]) on the file,
//! which the guest is shown in their place; a device node is an empty
//! regular file carrying the override. FIFOs are not made.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;

use boxcar_fs::ownership::{DevKind, Override, XATTR};

use super::framer::{Entry, Framer, Kind};

/// `struct open_how` from `linux/openat2.h`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// How often a resolution the kernel saw raced (`EAGAIN`) is retried.
const RETRIES: usize = 8;

/// The mode of a directory the archive implies but does not name.
const IMPLIED_DIR_MODE: u32 = 0o755;

/// Opening a directory just made, to set its override.
const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// The special mode bits (setuid, setgid, sticky).
const SPECIAL_BITS: u32 = 0o7000;

/// What the guest is to see of `entry`: its owner, its special bits and,
/// for a device node, its kind and numbers.
fn override_of(entry: &Entry, dev: Option<DevKind>) -> Override {
    Override {
        uid: Some(entry.uid),
        gid: Some(entry.gid),
        special: entry.mode & SPECIAL_BITS,
        dev: dev.map(|kind| (kind, libc::makedev(entry.dev.0, entry.dev.1))),
    }
}

/// Writes `over` as the file's `user.boxcar.stat`. A filesystem without
/// user xattrs cannot hold the cache.
fn set_override(fd: RawFd, over: &Override) -> io::Result<()> {
    let name = CString::new(XATTR).expect("the xattr's name has no NUL");
    let text = over.encode();
    // SAFETY: fsetxattr reads the NUL-terminated name and `text.len()`
    // bytes of the value.
    let rc = unsafe { libc::fsetxattr(fd, name.as_ptr(), text.as_ptr().cast(), text.len(), 0) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
            io::Error::other(
                "the cache's filesystem has no user xattrs, which the ownership override \
                 (`user.boxcar.stat`) needs",
            )
        } else {
            error
        });
    }
    Ok(())
}

/// The mode directories have while the tree is built; their own modes
/// are applied once every layer is in, so none blocks its children.
const BUILDING_DIR_MODE: libc::mode_t = 0o700;

/// The most the unpacker keeps in memory about the tree: directory paths
/// whose modes wait for the end, and the paths of skipped entries. A
/// layer may declare any number of either, with names of any length.
pub const MAX_METADATA: u64 = 64 * 1024 * 1024;
/// What one kept path costs past its bytes: its vector's header and the
/// map's or list's slot.
const ENTRY_COST: u64 = 64;

const WHITEOUT: &[u8] = b".wh.";
const OPAQUE: &[u8] = b".wh..wh..opq";

/// A tree being built from layers.
pub struct Unpacker {
    root: OwnedFd,
    /// The root's path as the kernel gives it, which a directory's starts
    /// with.
    root_path: Vec<u8>,
    /// Directory modes, applied once every layer is in, by the directory's
    /// own path from the root: the one the kernel gives, through no link,
    /// so a layer's path that reached it through a link names the same
    /// directory. A later entry for a directory wins, and a directory
    /// that goes is forgotten.
    dir_modes: BTreeMap<Vec<u8>, u32>,
    /// The image's modes of the regular files stored with another (owner
    /// read forced on), by the file's own path; forgotten as directory
    /// modes are when the file goes.
    file_modes: BTreeMap<Vec<u8>, u32>,
    skipped: Vec<String>,
    /// What may still be kept in memory, against [`MAX_METADATA`].
    metadata_left: u64,
}

/// What unpacking left out: FIFOs, by path.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Finished {
    /// Paths of the device nodes and FIFOs not made.
    pub skipped: Vec<String>,
    /// Paths whose mode in the tree is not the image's, with the image's:
    /// the tree stores every entry readable by its owner (a file with
    /// owner read, a directory with owner read, write and search), so a
    /// copy can read it all without touching the tree. Sorted by path.
    pub modes: Vec<(String, u32)>,
}

/// The mode a regular file is stored with: the image's, owner read forced.
pub fn stored_file_mode(mode: u32) -> u32 {
    mode | 0o400
}

/// The mode a directory is stored with: the image's, owner read, write
/// and search forced.
pub fn stored_dir_mode(mode: u32) -> u32 {
    mode | 0o700
}

impl Unpacker {
    /// A tree at `root`, an existing empty directory.
    pub fn new(root: &Path) -> io::Result<Unpacker> {
        let file = File::open(root)?;
        if !file.metadata()?.is_dir() {
            return Err(malformed(format!("{} is not a directory", root.display())));
        }
        let root = OwnedFd::from(file);
        let root_path = fd_path(&root)?;
        Ok(Unpacker {
            root,
            root_path,
            dir_modes: BTreeMap::new(),
            file_modes: BTreeMap::new(),
            skipped: Vec::new(),
            metadata_left: MAX_METADATA,
        })
    }

    /// An unpacker keeping at most `bytes` of paths in memory.
    #[cfg(test)]
    pub fn with_metadata_budget(root: &Path, bytes: u64) -> io::Result<Unpacker> {
        let mut unpacker = Unpacker::new(root)?;
        unpacker.metadata_left = bytes;
        Ok(unpacker)
    }

    /// Takes `bytes` of the metadata budget for a kept path.
    fn keep(&mut self, bytes: usize) -> io::Result<()> {
        match self.metadata_left.checked_sub(bytes as u64 + ENTRY_COST) {
            Some(left) => {
                self.metadata_left = left;
                Ok(())
            }
            None => Err(io::Error::other(
                "the image's directories and skipped entries take more than 64 MiB to record",
            )),
        }
    }

    /// Records the mode the directory at `path` will get at the end.
    fn remember_mode(&mut self, path: Vec<u8>, mode: u32) -> io::Result<()> {
        if !self.dir_modes.contains_key(&path) {
            self.keep(path.len())?;
        }
        self.dir_modes.insert(path, mode);
        Ok(())
    }

    /// Records the implied mode for a directory a path implied, unless
    /// an entry gave it one.
    fn remember_implied(&mut self, path: Vec<u8>) -> io::Result<()> {
        if !self.dir_modes.contains_key(&path) {
            self.remember_mode(path, IMPLIED_DIR_MODE)?;
        }
        Ok(())
    }

    /// Records the image's mode of the file at `path`, stored readable.
    fn remember_file_mode(&mut self, path: Vec<u8>, mode: u32) -> io::Result<()> {
        if !self.file_modes.contains_key(&path) {
            self.keep(path.len())?;
        }
        self.file_modes.insert(path, mode);
        Ok(())
    }

    /// Forgets the modes of everything beneath `path`, and of `path`
    /// itself when `itself`: what stood there is gone, and whatever takes
    /// the name (a link, say) must not inherit the mode. The work is in
    /// what is forgotten, not in what is kept.
    fn forget_modes(&mut self, path: &[u8], itself: bool) {
        let mut gone = Vec::new();
        for map in [&mut self.dir_modes, &mut self.file_modes] {
            if itself && !path.is_empty() {
                gone.extend(map.remove_entry(path));
            }
            if path.is_empty() {
                gone.extend(std::mem::take(map));
            } else {
                let mut from = path.to_vec();
                from.push(b'/');
                let mut to = path.to_vec();
                to.push(b'/' + 1);
                let keys: Vec<Vec<u8>> = map.range(from..to).map(|(k, _)| k.clone()).collect();
                for key in keys {
                    gone.extend(map.remove_entry(&key));
                }
            }
        }
        for (key, _) in gone {
            self.metadata_left += key.len() as u64 + ENTRY_COST;
        }
    }

    /// A new entry takes the name: a file's recorded mode there, if any,
    /// is forgotten. Costs a lookup of the path only while there are
    /// records to forget.
    fn forget_file_mode(&mut self, parent_fd: &OwnedFd, name: &CStr) -> io::Result<()> {
        if !self.file_modes.is_empty() {
            let path = self.canonical_in(parent_fd, name)?;
            self.forget_modes(&path, true);
        }
        Ok(())
    }

    /// The path of the directory `fd` is, from the root and through no
    /// link, as the kernel gives it: empty for the root itself.
    fn canonical(&self, fd: &OwnedFd) -> io::Result<Vec<u8>> {
        let path = fd_path(fd)?;
        let rest = path
            .strip_prefix(self.root_path.as_slice())
            .ok_or_else(|| io::Error::other("a directory of the tree is not beneath its root"))?;
        Ok(rest.strip_prefix(b"/").unwrap_or(rest).to_vec())
    }

    /// The path of `name` in the directory `dir` is.
    fn canonical_in(&self, dir: &OwnedFd, name: &CStr) -> io::Result<Vec<u8>> {
        Ok(beneath(&self.canonical(dir)?, name.to_bytes()))
    }

    /// The first pass over a layer: its whiteouts, applied to the tree as
    /// it stands; nothing else is written.
    pub fn whiteouts<R: Read>(&mut self, framer: &mut Framer<'_, R>) -> io::Result<()> {
        while let Some(entry) = framer.next()? {
            let comps = components(&entry.path)?;
            let Some((name, parent)) = comps.split_last() else {
                continue;
            };
            if name.as_slice() == OPAQUE {
                self.make_opaque(parent)?;
            } else if let Some(target) = name.strip_prefix(WHITEOUT) {
                match target {
                    b"" | b"." => {}
                    b".." => return Err(malformed("a whiteout of `..`")),
                    target => self.remove_in(parent, target)?,
                }
            }
        }
        Ok(())
    }

    /// The second pass over a layer: its entries, whiteouts skipped.
    pub fn entries<R: Read>(&mut self, framer: &mut Framer<'_, R>) -> io::Result<()> {
        while let Some(entry) = framer.next()? {
            let comps = components(&entry.path)?;
            let Some((name, parent)) = comps.split_last() else {
                // The root itself: its owner, and nothing else of it.
                if entry.kind == Kind::Dir {
                    set_override(self.root.as_raw_fd(), &override_of(&entry, None))?;
                }
                continue;
            };
            if name.starts_with(WHITEOUT) {
                continue;
            }
            let name = cstr(name)?;
            match entry.kind {
                Kind::Dir => {
                    let parent_fd = self.parent_fd(parent)?;
                    let path = self.canonical_in(&parent_fd, &name)?;
                    // Something else stood there and went: its records go.
                    // A directory that was there keeps its children's.
                    if make_dir(&parent_fd, &name)? {
                        self.forget_modes(&path, true);
                    }
                    self.remember_mode(path, entry.mode)?;
                    let dir = openat(&parent_fd, &name, DIR_FLAGS, 0)?;
                    set_override(dir.as_raw_fd(), &override_of(&entry, None))?;
                }
                Kind::File => {
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        let path = self.canonical_in(&parent_fd, &name)?;
                        self.forget_modes(&path, true);
                    } else {
                        self.forget_file_mode(&parent_fd, &name)?;
                    }
                    let fd = openat(
                        &parent_fd,
                        &name,
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )?;
                    let mut file = File::from(fd);
                    io::copy(&mut framer.data(), &mut file)?;
                    self.store_file(&parent_fd, &name, &file.into(), &entry, None)?;
                }
                Kind::Symlink => {
                    let target = cstr(&entry.link)?;
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        let path = self.canonical_in(&parent_fd, &name)?;
                        self.forget_modes(&path, true);
                    } else {
                        self.forget_file_mode(&parent_fd, &name)?;
                    }
                    check(unsafe {
                        libc::symlinkat(target.as_ptr(), parent_fd.as_raw_fd(), name.as_ptr())
                    })?;
                }
                Kind::Hardlink => {
                    let target = components(&entry.link)?;
                    let Some((target_name, target_parent)) = target.split_last() else {
                        return Err(malformed("a hardlink to the root"));
                    };
                    let target_name = cstr(target_name)?;
                    let target_parent_fd = match self.open_dir(target_parent) {
                        Ok(fd) => fd,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                            ) =>
                        {
                            return Err(missing_target())
                        }
                        Err(error) => return Err(error),
                    };
                    match stat_at(&target_parent_fd, &target_name)? {
                        None => return Err(missing_target()),
                        Some(mode) if mode & libc::S_IFMT == libc::S_IFDIR => {
                            return Err(malformed("a hardlink to a directory"))
                        }
                        Some(_) => {}
                    }
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        let path = self.canonical_in(&parent_fd, &name)?;
                        self.forget_modes(&path, true);
                    } else {
                        self.forget_file_mode(&parent_fd, &name)?;
                    }
                    check(unsafe {
                        libc::linkat(
                            target_parent_fd.as_raw_fd(),
                            target_name.as_ptr(),
                            parent_fd.as_raw_fd(),
                            name.as_ptr(),
                            0,
                        )
                    })?;
                    // The inode's image mode is the target's record; the
                    // new name gets one too, so it survives the target's
                    // replacement.
                    if !self.file_modes.is_empty() {
                        let target_path = self.canonical_in(&target_parent_fd, &target_name)?;
                        if let Some(mode) = self.file_modes.get(&target_path).copied() {
                            let path = self.canonical_in(&parent_fd, &name)?;
                            self.remember_file_mode(path, mode)?;
                        }
                    }
                }
                Kind::CharDevice | Kind::BlockDevice => {
                    // An empty regular file stands for the node; the
                    // override says which device.
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        let path = self.canonical_in(&parent_fd, &name)?;
                        self.forget_modes(&path, true);
                    } else {
                        self.forget_file_mode(&parent_fd, &name)?;
                    }
                    let fd = openat(
                        &parent_fd,
                        &name,
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )?;
                    let kind = match entry.kind {
                        Kind::CharDevice => DevKind::Char,
                        _ => DevKind::Block,
                    };
                    self.store_file(&parent_fd, &name, &fd, &entry, Some(kind))?;
                }
                Kind::Fifo => {
                    let path = display(&comps);
                    self.keep(path.len())?;
                    self.skipped.push(path);
                }
            }
        }
        Ok(())
    }

    /// A regular file just written (or standing for a device of `dev`):
    /// its override (while the file is still writable: a user xattr needs
    /// write permission on the inode, whatever the descriptor), its stored
    /// mode, and the image's remembered where that differs.
    fn store_file(
        &mut self,
        parent_fd: &OwnedFd,
        name: &CStr,
        fd: &OwnedFd,
        entry: &Entry,
        dev: Option<DevKind>,
    ) -> io::Result<()> {
        set_override(fd.as_raw_fd(), &override_of(entry, dev))?;
        let stored = stored_file_mode(entry.mode);
        check(unsafe { libc::fchmod(fd.as_raw_fd(), stored as libc::mode_t) })?;
        self.forget_file_mode(parent_fd, name)?;
        if stored != entry.mode {
            let path = self.canonical_in(parent_fd, name)?;
            self.remember_file_mode(path, entry.mode)?;
        }
        Ok(())
    }

    /// After the last layer: `tmp` and `workspace` at the root when
    /// missing, directory modes deepest first, each stored readable.
    /// Answers what was skipped and the modes the tree does not show.
    pub fn finish(mut self) -> io::Result<Finished> {
        for (name, mode) in [("tmp", 0o1777u32), ("workspace", IMPLIED_DIR_MODE)] {
            let cname = cstr(name.as_bytes())?;
            if stat_at(&self.root, &cname)?.is_none() {
                check(unsafe {
                    libc::mkdirat(self.root.as_raw_fd(), cname.as_ptr(), BUILDING_DIR_MODE)
                })?;
                self.remember_mode(name.as_bytes().to_vec(), mode)?;
            }
        }
        let mut dirs: Vec<(Vec<u8>, u32)> =
            std::mem::take(&mut self.dir_modes).into_iter().collect();
        dirs.sort_by_key(|(path, _)| std::cmp::Reverse(depth(path)));
        let mut modes: Vec<(String, u32)> = std::mem::take(&mut self.file_modes)
            .into_iter()
            .map(|(path, mode)| (String::from_utf8_lossy(&path).into_owned(), mode))
            .collect();
        for (path, mode) in dirs {
            // The parent resolved in the root, then the name itself with
            // nothing followed: a later layer may have put a link there.
            let (parent, name) = match path.iter().rposition(|b| *b == b'/') {
                Some(at) => (&path[..at], &path[at + 1..]),
                None => (&path[..0], &path[..]),
            };
            let parent_fd = match self.open_path(parent) {
                Ok(fd) => fd,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            };
            let fd = match openat(
                &parent_fd,
                &cstr(name)?,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            ) {
                Ok(fd) => fd,
                // Replaced by a later layer's file or link, or whited out.
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOENT) | Some(libc::ENOTDIR) | Some(libc::ELOOP)
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            };
            let stored = stored_dir_mode(mode);
            chmod_fd(&fd, stored)?;
            if stored != mode {
                modes.push((String::from_utf8_lossy(&path).into_owned(), mode));
            }
        }
        modes.sort();
        Ok(Finished {
            skipped: self.skipped,
            modes,
        })
    }

    /// The directory `comps` names, resolved in the root; `O_PATH`.
    fn open_dir(&self, comps: &[Vec<u8>]) -> io::Result<OwnedFd> {
        self.open_path(&comps.join(&b'/'))
    }

    /// The directory at `path` (components joined by `/`, empty for the
    /// root), resolved in the root; `O_PATH`.
    fn open_path(&self, path: &[u8]) -> io::Result<OwnedFd> {
        let path = if path.is_empty() {
            CString::new(".").expect("no NUL")
        } else {
            cstr(path)?
        };
        openat2(
            &self.root,
            &path,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    }

    /// [`open_dir`](Self::open_dir), a file in the way an error that
    /// names it.
    fn open_parent(&self, comps: &[Vec<u8>]) -> io::Result<OwnedFd> {
        self.open_dir(comps).map_err(|error| {
            if error.kind() == io::ErrorKind::NotADirectory {
                malformed("a path's parent is not a directory")
            } else {
                error
            }
        })
    }

    /// The directory an entry goes in, made (with its missing parents)
    /// when the archive implies it.
    fn parent_fd(&mut self, parent: &[Vec<u8>]) -> io::Result<OwnedFd> {
        match self.open_parent(parent) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            other => return other,
        }
        for depth in 1..=parent.len() {
            match self.open_parent(&parent[..depth]) {
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let above = self.open_parent(&parent[..depth - 1])?;
            let name = cstr(&parent[depth - 1])?;
            match check(unsafe {
                libc::mkdirat(above.as_raw_fd(), name.as_ptr(), BUILDING_DIR_MODE)
            }) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                Err(error) => return Err(error),
            }
            let path = self.canonical_in(&above, &name)?;
            self.remember_implied(path)?;
        }
        self.open_parent(parent)
    }

    /// `.wh..wh..opq` in `parent`: everything in it goes.
    fn make_opaque(&mut self, parent: &[Vec<u8>]) -> io::Result<()> {
        let dir = match self.open_dir(parent) {
            Ok(fd) => fd,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        // Readable: directories are 0o700 while the tree is built.
        let readable = openat2(
            &self.root,
            &self_path(parent)?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let path = self.canonical(&dir)?;
        drop(dir);
        for child in children(readable)? {
            let _ = remove_at(&self.open_dir(parent)?, &child)?;
        }
        self.forget_modes(&path, false);
        Ok(())
    }

    /// `.wh.<target>` in `parent`: `target` goes, whatever it is.
    fn remove_in(&mut self, parent: &[Vec<u8>], target: &[u8]) -> io::Result<()> {
        let dir = match self.open_dir(parent) {
            Ok(fd) => fd,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let target = cstr(target)?;
        match remove_at(&dir, &target)? {
            Removed::Nothing => {}
            Removed::Dir => {
                let path = self.canonical_in(&dir, &target)?;
                self.forget_modes(&path, true);
            }
            Removed::File => self.forget_file_mode(&dir, &target)?,
        }
        Ok(())
    }
}

/// Deletes a directory tree we own, whatever modes its layers set: each
/// directory is opened without following links, given mode `0o700`, read
/// and emptied, then removed.
pub fn delete_tree(parent: &Path, name: &str) -> io::Result<()> {
    let parent = OwnedFd::from(File::open(parent)?);
    delete_tree_at(&parent, &cstr(name.as_bytes())?)
}

/// Deletes the directory `name` in `parent` and everything beneath it,
/// holding three descriptors at a time whatever the depth: each directory
/// is entered by name and left through `..`, which from a directory
/// reached through no link is its parent. A tree deeper than the
/// descriptor limit, or than PATH_MAX, goes like any other.
fn delete_tree_at(parent: &OwnedFd, name: &CStr) -> io::Result<()> {
    let mut current = enter(parent, name)?;
    // Each level: the directory's name in its parent, and the children
    // not yet removed.
    let mut levels: Vec<(CString, Vec<CString>)> =
        vec![(name.to_owned(), children(reopen(&current)?)?)];
    loop {
        let Some((_, pending)) = levels.last_mut() else {
            return Ok(());
        };
        match pending.pop() {
            Some(child) => match stat_at(&current, &child)? {
                None => {}
                Some(mode) if mode & libc::S_IFMT == libc::S_IFDIR => {
                    let next = enter(&current, &child)?;
                    let kids = children(reopen(&next)?)?;
                    current = next;
                    levels.push((child, kids));
                }
                Some(_) => {
                    check(unsafe { libc::unlinkat(current.as_raw_fd(), child.as_ptr(), 0) })?
                }
            },
            None => {
                let (dir_name, _) = levels.pop().expect("a level");
                let above = if levels.is_empty() {
                    None
                } else {
                    Some(openat(
                        &current,
                        c"..",
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        0,
                    )?)
                };
                drop(current);
                let up = above.as_ref().unwrap_or(parent);
                check(unsafe {
                    libc::unlinkat(up.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR)
                })?;
                match above {
                    Some(up) => current = up,
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Opens the directory `name` in `parent` for listing, made ours to
/// delete first (0o700) whatever mode a layer gave it.
fn enter(parent: &OwnedFd, name: &CStr) -> io::Result<OwnedFd> {
    let opath = openat(
        parent,
        name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    chmod_fd(&opath, 0o700)?;
    drop(opath);
    openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

/// A second descriptor for the directory `dir`, for a listing, which
/// consumes one.
fn reopen(dir: &OwnedFd) -> io::Result<OwnedFd> {
    openat(
        dir,
        c".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
}

/// Removes `name` in `parent`: a directory whole, anything else unlinked,
/// nothing when it is not there. Answers whether a directory went.
fn remove_at(parent: &OwnedFd, name: &CStr) -> io::Result<Removed> {
    match stat_at(parent, name)? {
        None => Ok(Removed::Nothing),
        Some(mode) if mode & libc::S_IFMT == libc::S_IFDIR => {
            delete_tree_at(parent, name)?;
            Ok(Removed::Dir)
        }
        Some(_) => {
            check(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) })?;
            Ok(Removed::File)
        }
    }
}

/// What `remove_at` took away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Removed {
    Nothing,
    /// A regular file, a link, or another non-directory.
    File,
    Dir,
}

/// Makes room for a new entry at `name`: whatever is there goes. Answers
/// whether a directory went.
fn replace_slot(parent: &OwnedFd, name: &CStr) -> io::Result<bool> {
    Ok(remove_at(parent, name)? == Removed::Dir)
}

/// A directory at `name`: made, or kept when one is there; anything else
/// there is replaced. Answers whether something else stood there.
fn make_dir(parent: &OwnedFd, name: &CStr) -> io::Result<bool> {
    let replaced = match stat_at(parent, name)? {
        Some(mode) if mode & libc::S_IFMT == libc::S_IFDIR => return Ok(false),
        Some(_) => {
            check(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) })?;
            true
        }
        None => false,
    };
    check(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), BUILDING_DIR_MODE) })?;
    Ok(replaced)
}

/// The names in the directory `dir` (consumed), `.` and `..` left out.
pub(super) fn children(dir: OwnedFd) -> io::Result<Vec<CString>> {
    // SAFETY: fdopendir takes the descriptor over; closedir releases it.
    let stream = unsafe { libc::fdopendir(dir.into_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: a stream fdopendir gave; readdir's entry lives until the
        // next call, and is copied out here.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    // SAFETY: the stream is closed once.
    unsafe { libc::closedir(stream) };
    Ok(names)
}

/// The mode of `name` in `parent`, a link itself not followed; none when
/// there is nothing there.
fn stat_at(parent: &OwnedFd, name: &CStr) -> io::Result<Option<libc::mode_t>> {
    // SAFETY: a zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    match check(unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }) {
        Ok(()) => Ok(Some(st.st_mode)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// `chmod` through the descriptor's `/proc` link: works on an `O_PATH`
/// descriptor, so a directory we cannot open for reading can still be
/// given a mode.
fn chmod_fd(fd: &OwnedFd, mode: u32) -> io::Result<()> {
    let path = cstr(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
    check(unsafe { libc::chmod(path.as_ptr(), mode as libc::mode_t) })
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

/// `openat2(root, path, flags, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`.
fn openat2(root: &OwnedFd, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: flags as u32 as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    for attempt in 0.. {
        // SAFETY: the raw syscall with a valid descriptor, C string and
        // open_how of the size the kernel expects.
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
            // SAFETY: a descriptor the kernel just gave, owned here.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EAGAIN) && attempt < RETRIES {
            continue;
        }
        return Err(error);
    }
    unreachable!("the loop returns")
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The components of an entry's path: a leading `/` or `./` stripped,
/// `.` and empty components dropped; `..` and a NUL refused; none for a
/// path that names the root.
fn components(path: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if path.contains(&0) {
        return Err(malformed("a path with a NUL byte"));
    }
    let mut out = Vec::new();
    for part in path.split(|b| *b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return Err(malformed("a path with a `..` component")),
            part => out.push(part.to_vec()),
        }
    }
    Ok(out)
}

fn self_path(comps: &[Vec<u8>]) -> io::Result<CString> {
    if comps.is_empty() {
        Ok(CString::new(".").expect("no NUL"))
    } else {
        cstr(&comps.join(&b'/'))
    }
}

fn cstr(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| malformed("a path with a NUL byte"))
}

fn display(comps: &[Vec<u8>]) -> String {
    String::from_utf8_lossy(&comps.join(&b'/')).into_owned()
}

fn missing_target() -> io::Error {
    malformed("a hardlink to a missing target")
}

/// `name` beneath the directory at `dir` (empty for the root).
fn beneath(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(dir.len() + 1 + name.len());
    if !dir.is_empty() {
        path.extend_from_slice(dir);
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// How deep `path` is: components, the root 0.
fn depth(path: &[u8]) -> usize {
    if path.is_empty() {
        0
    } else {
        path.iter().filter(|b| **b == b'/').count() + 1
    }
}

/// The path of what `fd` is, as the kernel gives it.
fn fd_path(fd: &OwnedFd) -> io::Result<Vec<u8>> {
    let link = cstr(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: a NUL-terminated path and a buffer of the length given.
    let n = unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize >= buf.len() {
        return Err(io::Error::other(
            "a directory's path is longer than PATH_MAX",
        ));
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn malformed(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::testutil::*;
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tar::EntryType;

    /// Applies `layers` in order into a fresh tree; the tree's directory
    /// and what unpacking skipped.
    fn unpack(layers: &[Vec<u8>]) -> (tempfile::TempDir, Finished) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let skipped = unpack_into(&root, layers).unwrap();
        (tmp, skipped)
    }

    fn unpack_into(root: &Path, layers: &[Vec<u8>]) -> io::Result<Finished> {
        let mut unpacker = Unpacker::new(root)?;
        let entries = Cell::new(u64::MAX);
        for layer in layers {
            let mut framer = Framer::new(&layer[..], &entries);
            unpacker.whiteouts(&mut framer)?;
            framer.finish()?;
            let mut framer = Framer::new(&layer[..], &entries);
            unpacker.entries(&mut framer)?;
            framer.finish()?;
        }
        unpacker.finish()
    }

    /// Unpacking `layers` fails, with `what` in the error.
    fn refused(layers: &[Vec<u8>], what: &str) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let err = unpack_into(&root, layers).unwrap_err();
        assert!(err.to_string().contains(what), "{what}: {err}");
    }

    /// The tree without the `tmp` and `workspace` finish adds.
    fn without_defaults(root: &Path) -> std::collections::BTreeMap<String, String> {
        let mut l = listing(root);
        l.remove("tmp");
        l.remove("workspace");
        l
    }

    #[test]
    fn files_directories_links_and_modes_land() {
        let layer = layer(&[
            dir("etc/", 0o755),
            file("etc/motd", 0o644, b"hello"),
            file("usr/bin/su", 0o4755, b"#!"),
            symlink("etc/alt", "/etc/motd"),
            hardlink("etc/motd2", "etc/motd"),
            dir("ro/", 0o555),
            file("ro/inside", 0o600, b"x"),
        ]);
        let (tmp, skipped) = unpack(&[layer]);
        let root = tmp.path().join("rootfs");
        let l = without_defaults(&root);
        assert_eq!(l["etc"], "dir 755");
        assert_eq!(l["usr"], format!("dir {:o}", IMPLIED_DIR_MODE));
        assert_eq!(l["usr/bin/su"].split(' ').nth(1), Some("4755"));
        assert_eq!(l["etc/alt"], "symlink -> /etc/motd");
        assert!(
            l["etc/motd"].starts_with("file 644 \"hello\" nlink=2"),
            "{}",
            l["etc/motd"]
        );
        assert_eq!(l["etc/motd"], l["etc/motd2"]);
        // Stored with the owner's bits on; the image's mode is listed.
        assert_eq!(l["ro"], "dir 755");
        assert!(l.contains_key("ro/inside"), "{l:?}");
        assert_eq!(skipped.skipped, Vec::<String>::new());
        assert_eq!(skipped.modes, [("ro".to_owned(), 0o555)]);
        // The finish adds tmp (1777) and workspace.
        let all = listing(&root);
        assert_eq!(all["tmp"], "dir 1777");
        assert_eq!(all["workspace"], format!("dir {:o}", IMPLIED_DIR_MODE));
    }

    #[test]
    fn nothing_escapes_the_tree() {
        // A sentinel beside the tree: it must not change, and nothing may
        // appear beside it.
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (layer(&[file("../escape", 0o644, b"x")]), ".."),
            (layer(&[file("a/../../escape", 0o644, b"x")]), ".."),
            (layer(&[hardlink("h", "../../etc/passwd")]), ".."),
            (layer(&[pax_file(b".wh...", b"")]), ".."),
            (layer(&[pax_file(b"a\0b", b"x")]), "NUL"),
        ];
        for (layer, what) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("rootfs");
            fs::create_dir(&root).unwrap();
            fs::write(tmp.path().join("sentinel"), b"keep").unwrap();
            let err = unpack_into(&root, &[layer]).unwrap_err();
            assert!(err.to_string().contains(what), "{what}: {err}");
            let mut beside: Vec<_> = fs::read_dir(tmp.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            beside.sort();
            assert_eq!(beside, ["rootfs", "sentinel"]);
            assert_eq!(fs::read(tmp.path().join("sentinel")).unwrap(), b"keep");
        }
    }

    #[test]
    fn absolute_symlinks_resolve_inside_the_tree() {
        // `/etc` of the host is not touched: the link's target is the
        // tree's own `etc`.
        let layer = layer(&[
            dir("etc/", 0o755),
            symlink("l", "/etc"),
            file("l/passwd", 0o644, b"inside"),
            symlink("up", "../../../.."),
            file("up/top", 0o644, b"clamped"),
            file("/abs/olute", 0o644, b"stripped"),
            file("./dotted", 0o644, b"stripped too"),
        ]);
        let (tmp, _) = unpack(&[layer]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["etc/passwd"], "file 644 \"inside\"");
        assert_eq!(l["top"], "file 644 \"clamped\"");
        assert_eq!(l["abs/olute"], "file 644 \"stripped\"");
        assert_eq!(l["dotted"], "file 644 \"stripped too\"");
        assert!(
            !Path::new("/etc/passwd").exists() || fs::read("/etc/passwd").unwrap() != b"inside"
        );
    }

    #[test]
    fn a_hardlink_needs_a_target_inside_and_may_link_a_symlink() {
        refused(&[layer(&[hardlink("h", "missing")])], "missing");
        // Through an absolute symlink that points outside: inside the
        // tree there is no such file.
        refused(
            &[layer(&[symlink("l", "/etc/passwd"), hardlink("h", "l/x")])],
            "missing",
        );
        let layer = layer(&[symlink("l", "nowhere"), hardlink("h", "l")]);
        let (tmp, _) = unpack(&[layer]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["h"], "symlink -> nowhere");
    }

    #[test]
    fn whiteouts_remove_what_lower_layers_put_whatever_their_order() {
        let lower = layer(&[
            dir("d/", 0o755),
            file("d/old", 0o644, b"old"),
            file("foo", 0o644, b"lower foo"),
            dir("gone/", 0o755),
            file("gone/x", 0o644, b"x"),
        ]);
        // A whiteout after and before the layer's own entry: foo stays.
        for upper in [
            layer(&[
                file("foo", 0o644, b"new foo"),
                pax_file(b".wh.foo", b""),
                pax_file(b".wh.gone", b""),
            ]),
            layer(&[
                pax_file(b".wh.foo", b""),
                pax_file(b".wh.gone", b""),
                file("foo", 0o644, b"new foo"),
            ]),
        ] {
            let (tmp, _) = unpack(&[lower.clone(), upper]);
            let l = without_defaults(&tmp.path().join("rootfs"));
            assert_eq!(l["foo"], "file 644 \"new foo\"");
            assert!(!l.contains_key("gone"), "{l:?}");
            assert!(!l.contains_key("gone/x"), "{l:?}");
            assert!(!l.contains_key(".wh.foo"), "{l:?}");
            assert_eq!(l["d/old"], "file 644 \"old\"");
        }
        // A whiteout of a missing name is nothing.
        let (tmp, _) = unpack(&[lower.clone(), layer(&[pax_file(b".wh.nothing", b"")])]);
        assert_eq!(without_defaults(&tmp.path().join("rootfs")).len(), 5);
    }

    #[test]
    fn an_opaque_directory_keeps_only_this_layers_children_whatever_their_order() {
        let lower = layer(&[
            dir("d/", 0o755),
            file("d/old", 0o644, b"old"),
            dir("d/sub/", 0o755),
            file("d/sub/deep", 0o644, b"deep"),
        ]);
        for upper in [
            layer(&[
                pax_file(b"d/.wh..wh..opq", b""),
                file("d/new", 0o644, b"new"),
                file("d/sub/fresh", 0o644, b"fresh"),
            ]),
            layer(&[
                file("d/new", 0o644, b"new"),
                file("d/sub/fresh", 0o644, b"fresh"),
                pax_file(b"d/.wh..wh..opq", b""),
            ]),
        ] {
            let (tmp, _) = unpack(&[lower.clone(), upper]);
            let l = without_defaults(&tmp.path().join("rootfs"));
            let keys: Vec<&str> = l.keys().map(String::as_str).collect();
            assert_eq!(keys, ["d", "d/new", "d/sub", "d/sub/fresh"], "{l:?}");
        }
    }

    #[test]
    fn an_entry_replaces_what_was_there() {
        let lower = layer(&[
            dir("d/", 0o755),
            file("d/x", 0o644, b"x"),
            file("f", 0o644, b"f"),
            symlink("s", "f"),
        ]);
        let upper = layer(&[
            file("d", 0o644, b"now a file"),
            dir("f/", 0o755),
            file("f/inside", 0o644, b"i"),
            dir("s/", 0o700),
        ]);
        let (tmp, _) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["d"], "file 644 \"now a file\"");
        assert_eq!(l["f"], "dir 755");
        assert_eq!(l["f/inside"], "file 644 \"i\"");
        assert_eq!(l["s"], "dir 700");
        assert!(!l.contains_key("d/x"));
    }

    #[test]
    fn devices_become_stand_ins_with_the_override_and_fifos_are_skipped() {
        let layer = layer(&[
            device(EntryType::Char, "dev/null", 0o666, 1, 3),
            device(EntryType::Block, "dev/sda", 0o660, 8, 0),
            special(EntryType::Fifo, "run/fifo"),
            file("ok", 0o644, b"ok"),
        ]);
        let (tmp, skipped) = unpack(&[layer]);
        assert_eq!(skipped.skipped, ["run/fifo".to_owned()]);
        assert_eq!(skipped.modes, Vec::<(String, u32)>::new());
        let root = tmp.path().join("rootfs");
        let l = without_defaults(&root);
        assert!(l.contains_key("ok"));
        assert_eq!(l["dev/null"], "file 666 \"\"");
        assert_eq!(l["dev/sda"], "file 660 \"\"");
        assert!(!l.contains_key("run/fifo"));
        assert_eq!(
            override_text(&root.join("dev/null")).as_deref(),
            Some("uid=0 gid=0 dev=c:1:3")
        );
        assert_eq!(
            override_text(&root.join("dev/sda")).as_deref(),
            Some("uid=0 gid=0 dev=b:8:0")
        );
    }

    #[test]
    fn owners_special_bits_and_the_root_land_in_the_override() {
        let first = layer(&[
            dir("./", 0o755),
            dir_as("home/", 0o755, 1000, 1000),
            file_as("home/f", 0o640, 1000, 7, b"x"),
            file("usr/bin/su", 0o4755, b"#!"),
            symlink("l", "home/f"),
            hardlink("home/g", "home/f"),
        ]);
        let (tmp, _) = unpack(std::slice::from_ref(&first));
        let root = tmp.path().join("rootfs");
        for (path, want) in [
            ("", "uid=0 gid=0"),
            ("home", "uid=1000 gid=1000"),
            ("home/f", "uid=1000 gid=7"),
            // The link shares the inode, and so the override.
            ("home/g", "uid=1000 gid=7"),
            ("usr/bin/su", "uid=0 gid=0 mode=4000"),
        ] {
            assert_eq!(
                override_text(&root.join(path)).as_deref(),
                Some(want),
                "{path}"
            );
        }
        // An implied directory and a symlink carry none.
        assert_eq!(override_text(&root.join("usr")), None);
        assert_eq!(override_text(&root.join("l")), None);
        // A later layer's entry replaces the owner, as it does the mode.
        let later = layer(&[file_as("home/f", 0o640, 0, 0, b"y")]);
        let (tmp, _) = unpack(&[first, later]);
        let root = tmp.path().join("rootfs");
        assert_eq!(
            override_text(&root.join("home/f")).as_deref(),
            Some("uid=0 gid=0")
        );
    }

    #[test]
    fn the_root_entry_and_empty_names_are_nothing() {
        let layer = layer(&[
            dir("./", 0o700),
            dir(".", 0o700),
            pax_file(b"", b""),
            file("a", 0o644, b"a"),
        ]);
        let (tmp, _) = unpack(&[layer]);
        let root = tmp.path().join("rootfs");
        let l = without_defaults(&root);
        assert_eq!(l.keys().collect::<Vec<_>>(), ["a"]);
        assert_ne!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_parent_that_is_a_file_is_refused() {
        refused(
            &[layer(&[
                file("f", 0o644, b"f"),
                file("f/child", 0o644, b"c"),
            ])],
            "not a directory",
        );
    }

    #[test]
    fn restrictive_directory_modes_do_not_block_their_children_or_deletion() {
        let layer = layer(&[
            dir("locked/", 0o000),
            file("locked/secret", 0o600, b"s"),
            dir("locked/deeper/", 0o555),
            file("locked/deeper/x", 0o644, b"x"),
        ]);
        let (tmp, finished) = unpack(&[layer]);
        let root = tmp.path().join("rootfs");
        assert_eq!(
            fs::metadata(root.join("locked"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            finished.modes,
            [
                ("locked".to_owned(), 0o000),
                ("locked/deeper".to_owned(), 0o555)
            ]
        );
        delete_tree(tmp.path(), "rootfs").unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn mode_records_survive_a_repeated_directory_and_follow_hardlinks_and_whiteouts() {
        // A layer that repeats a directory keeps the children's records.
        let lower = layer(&[
            dir("d/", 0o755),
            dir("d/sub/", 0o555),
            file("d/f", 0o000, b"f"),
        ]);
        let upper = layer(&[dir("d/", 0o755)]);
        let (tmp, finished) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["d/sub"], "dir 755");
        assert_eq!(l["d/f"], "file 400 \"f\"");
        assert_eq!(
            finished.modes,
            [("d/f".to_owned(), 0o000), ("d/sub".to_owned(), 0o555)]
        );
        // A hardlink to an unreadable file carries its record, so the mode
        // survives the target's replacement.
        let lower = layer(&[file("a", 0o000, b"x"), hardlink("b", "a")]);
        let upper = layer(&[file("a", 0o644, b"y")]);
        let (tmp, finished) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["a"], "file 644 \"y\"");
        assert_eq!(l["b"], "file 400 \"x\"");
        assert_eq!(finished.modes, [("b".to_owned(), 0o000)]);
        // A whiteout of an unreadable file forgets its record, so a later
        // directory of that name is not given the file's mode.
        let lower = layer(&[file("a", 0o000, b"x")]);
        let middle = layer(&[file(".wh.a", 0o644, b"")]);
        let upper = layer(&[dir("a/", 0o755)]);
        let (_tmp, finished) = unpack(&[lower.clone(), middle.clone()]);
        assert_eq!(finished.modes, []);
        let (tmp, finished) = unpack(&[lower, middle, upper]);
        assert_eq!(finished.modes, []);
        assert_eq!(without_defaults(&tmp.path().join("rootfs"))["a"], "dir 755");
    }

    #[test]
    fn unreadable_entries_are_stored_readable_and_their_modes_listed() {
        // A file no one may read, a directory no one may enter and one no
        // one may search: stored with the owner's bits on, so a copy can
        // read them, and listed with the image's modes.
        let lower = layer(&[
            file("etc/shadow", 0o000, b"root:*:"),
            dir("locked/", 0o000),
            file("locked/inside", 0o644, b"i"),
            dir("nosearch/", 0o444),
            file("nosearch/f", 0o200, b"w"),
            file("gone", 0o000, b"g"),
            file("under/x", 0o000, b"x"),
        ]);
        // A later layer replaces one with a readable file and whites out
        // the other's directory: neither stays listed.
        let upper = layer(&[file("gone", 0o644, b"g2"), file(".wh.under", 0o644, b"")]);
        let (tmp, finished) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["etc/shadow"], "file 400 \"root:*:\"");
        assert_eq!(l["locked"], "dir 700");
        assert_eq!(l["locked/inside"], "file 644 \"i\"");
        assert_eq!(l["nosearch"], "dir 744");
        assert_eq!(l["nosearch/f"], "file 600 \"w\"");
        assert_eq!(l["gone"], "file 644 \"g2\"");
        assert!(!l.contains_key("under"));
        assert_eq!(
            finished.modes,
            [
                ("etc/shadow".to_owned(), 0o000),
                ("locked".to_owned(), 0o000),
                ("nosearch".to_owned(), 0o444),
                ("nosearch/f".to_owned(), 0o200),
            ]
        );
        // The same tree twice gives the same list.
        let (_, again) = unpack(&[layer(&[
            file("etc/shadow", 0o000, b"root:*:"),
            dir("locked/", 0o000),
        ])]);
        assert_eq!(
            again.modes,
            [
                ("etc/shadow".to_owned(), 0o000),
                ("locked".to_owned(), 0o000)
            ]
        );
    }

    #[test]
    fn a_directorys_mode_is_forgotten_when_it_goes_and_never_set_through_a_link() {
        // A later layer puts a symlink where a locked directory was: the
        // link's target keeps its own mode.
        let lower = layer(&[dir("a/", 0o755), file("a/x", 0o644, b"x"), dir("z/", 0o000)]);
        let upper = layer(&[symlink("z", "a")]);
        let (tmp, _) = unpack(&[lower, upper]);
        let root = tmp.path().join("rootfs");
        assert_eq!(
            fs::metadata(root.join("a")).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert_eq!(fs::read(root.join("z/x")).unwrap(), b"x");
        // A directory whited out and implied again gets the implied mode,
        // not the one it had.
        let lower = layer(&[dir("d/", 0o700), file("d/old", 0o644, b"o")]);
        let upper = layer(&[file(".wh.d", 0o644, b""), file("d/new", 0o644, b"n")]);
        let (tmp, _) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l["d"], format!("dir {IMPLIED_DIR_MODE:o}"));
        assert_eq!(l.keys().collect::<Vec<_>>(), ["d", "d/new"]);
        // A file replacing a directory: the directory's mode, and its
        // children's, are gone with it.
        let lower = layer(&[dir("e/", 0o000), dir("e/sub/", 0o000)]);
        let upper = layer(&[file("e", 0o644, b"f")]);
        let (tmp, _) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l.len(), 1);
        assert_eq!(l["e"], "file 644 \"f\"");
    }

    #[test]
    fn a_mode_given_through_a_link_belongs_to_the_directory_it_reached() {
        // Layer 1 gives `z/sub` its mode while `z` points at `a`; layer 2
        // points `z` at `b`. The mode is `a/sub`'s, and `b/sub` keeps its own.
        let lower = layer(&[
            dir("a/", 0o755),
            dir("b/", 0o755),
            dir("b/sub/", 0o700),
            symlink("z", "a"),
            dir("z/sub/", 0o777),
        ]);
        let upper = layer(&[symlink("z", "b")]);
        let (tmp, _) = unpack(&[lower, upper]);
        let root = tmp.path().join("rootfs");
        let mode = |p: &str| fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("a/sub"), 0o777);
        assert_eq!(mode("b/sub"), 0o700);
        assert_eq!(fs::read_link(root.join("z")).unwrap(), Path::new("b"));
        // A whiteout through the link removes what the link reaches, and
        // its mode record with it; the other directory keeps its mode.
        let lower = layer(&[
            dir("a/", 0o755),
            dir("a/sub/", 0o707),
            dir("b/", 0o755),
            dir("b/sub/", 0o700),
            symlink("z", "a"),
        ]);
        let upper = layer(&[file(".wh.z", 0o644, b""), symlink("z", "b")]);
        let (tmp, _) = unpack(&[lower, upper]);
        let root = tmp.path().join("rootfs");
        let mode = |p: &str| fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("a/sub"), 0o707);
        assert_eq!(mode("b/sub"), 0o700);
        let lower = layer(&[dir("a/", 0o755), dir("a/sub/", 0o707), symlink("z", "a")]);
        let upper = layer(&[file("z/.wh.sub", 0o644, b"")]);
        let (tmp, _) = unpack(&[lower, upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l.keys().collect::<Vec<_>>(), ["a", "z"]);
    }

    #[test]
    fn forgetting_what_is_not_there_costs_nothing_much() {
        // Many directories remembered, then as many whiteouts of names that
        // never existed: the work is in what is forgotten, not in what is
        // kept, so this is quick; a scan of every record for every whiteout
        // would not be.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let mut unpacker = Unpacker::new(&root).unwrap();
        let count = 200_000;
        for i in 0..count {
            unpacker
                .remember_mode(format!("d{i}").into_bytes(), 0o755)
                .unwrap();
        }
        let started = std::time::Instant::now();
        for i in 0..count {
            unpacker.forget_modes(format!("n{i}").as_bytes(), true);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(unpacker.dir_modes.len(), count);
        // Forgetting a subtree takes only its records, and gives their
        // budget back; the root's whole clears everything.
        unpacker.remember_mode(b"d1/x".to_vec(), 0o755).unwrap();
        unpacker.remember_mode(b"d1/x/y".to_vec(), 0o755).unwrap();
        unpacker.remember_mode(b"d10".to_vec(), 0o700).unwrap();
        unpacker.forget_modes(b"d1", true);
        assert_eq!(unpacker.dir_modes.len(), count - 1);
        assert_eq!(unpacker.dir_modes.get(&b"d10"[..]), Some(&0o700));
        unpacker.forget_modes(b"", false);
        assert_eq!(unpacker.dir_modes.len(), 0);
        assert_eq!(unpacker.metadata_left, MAX_METADATA);
    }

    #[test]
    fn the_metadata_budget_charges_whole_paths() {
        // Two thousand directories beneath a path a thousand deep: each
        // record is the whole path, not its last component.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let deep = (0..1000).map(|_| "d").collect::<Vec<_>>().join("/");
        let entries: Vec<Vec<u8>> = (0..2000)
            .map(|i| pax_file(format!("{deep}/{i}/f").as_bytes(), b""))
            .collect();
        let deep_layer = layer(&entries);
        let entries_left = Cell::new(u64::MAX);
        let mut unpacker = Unpacker::with_metadata_budget(&root, 1024 * 1024).unwrap();
        let mut framer = Framer::new(&deep_layer[..], &entries_left);
        let err = unpacker.entries(&mut framer).unwrap_err();
        assert!(err.to_string().contains("64 MiB to record"), "{err}");
        // Forgetting gives the budget back: a tree made and whited out
        // again and again stays within it.
        let root2 = tmp.path().join("rootfs2");
        fs::create_dir(&root2).unwrap();
        let mut unpacker = Unpacker::with_metadata_budget(&root2, 64 * 1024).unwrap();
        for round in 0..20 {
            let make: Vec<Vec<u8>> = (0..200)
                .map(|i| dir(&format!("r{round}/{i}/"), 0o755))
                .collect();
            let made = layer(&make);
            let mut framer = Framer::new(&made[..], &entries_left);
            unpacker.entries(&mut framer).unwrap();
            let gone = layer(&[file(&format!(".wh.r{round}"), 0o644, b"")]);
            let mut framer = Framer::new(&gone[..], &entries_left);
            unpacker.whiteouts(&mut framer).unwrap();
        }
    }

    #[test]
    fn what_the_unpacker_keeps_in_memory_is_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let long = "n".repeat(90);
        let entries: Vec<Vec<u8>> = (0..64)
            .map(|i| special(EntryType::Fifo, &format!("{long}{i:02}")))
            .collect();
        let fifos = layer(&entries);
        let mut unpacker = Unpacker::with_metadata_budget(&root, 2048).unwrap();
        let entries_left = Cell::new(u64::MAX);
        let mut framer = Framer::new(&fifos[..], &entries_left);
        let err = unpacker.entries(&mut framer).unwrap_err();
        assert!(err.to_string().contains("64 MiB to record"), "{err}");
        // Directories count too, and so do implied ones.
        let entries: Vec<Vec<u8>> = (0..64)
            .map(|i| dir(&format!("{long}{i:02}/"), 0o755))
            .collect();
        let dirs = layer(&entries);
        let mut unpacker = Unpacker::with_metadata_budget(&root, 2048).unwrap();
        let mut framer = Framer::new(&dirs[..], &entries_left);
        assert!(unpacker.entries(&mut framer).is_err());
        let entries: Vec<Vec<u8>> = (0..64)
            .map(|i| file(&format!("{long}{i:02}/f"), 0o644, b""))
            .collect();
        let implied = layer(&entries);
        let mut unpacker = Unpacker::with_metadata_budget(&root, 2048).unwrap();
        let mut framer = Framer::new(&implied[..], &entries_left);
        assert!(unpacker.entries(&mut framer).is_err());
        // Within the budget, the same layers unpack.
        let mut unpacker = Unpacker::with_metadata_budget(&root, MAX_METADATA).unwrap();
        let mut framer = Framer::new(&fifos[..], &entries_left);
        unpacker.entries(&mut framer).unwrap();
    }

    #[test]
    fn a_tree_deeper_than_path_max_is_deleted_with_few_descriptors() {
        // Built with *at calls, a tree can be deeper than any path; it is
        // deleted level by level, with no descriptor kept per level.
        let tmp = tempfile::tempdir().unwrap();
        let root = OwnedFd::from(File::open(tmp.path()).unwrap());
        let depth = 2500;
        let name = cstr(b"d").unwrap();
        check(unsafe { libc::mkdirat(root.as_raw_fd(), c"deep".as_ptr(), 0o700) }).unwrap();
        let mut cur = openat(&root, c"deep", libc::O_RDONLY | libc::O_DIRECTORY, 0).unwrap();
        for level in 0..depth {
            check(unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), 0o700) }).unwrap();
            // A locked directory and a file at every tenth level.
            if level % 10 == 0 {
                let file = openat(
                    &cur,
                    c"f",
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )
                .unwrap();
                drop(file);
                check(unsafe { libc::mkdirat(cur.as_raw_fd(), c"locked".as_ptr(), 0o000) })
                    .unwrap();
            }
            cur = openat(&cur, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0).unwrap();
        }
        drop(cur);
        // The descriptor bound itself is checked by the binary-level test
        // that prunes such a tree under `ulimit -n 64`; counting this
        // process's descriptors here would race other tests' files.
        delete_tree(tmp.path(), "deep").unwrap();
        assert!(!tmp.path().join("deep").exists());
    }

    #[test]
    fn whiteouts_apply_in_archive_order_against_the_tree_as_it_stands() {
        // As Docker's applier does: a whiteout that removes a link and one
        // that reaches through it depend on their order, and the order is
        // the archive's.
        let lower = || {
            layer(&[
                dir("b/", 0o755),
                file("b/file", 0o644, b"x"),
                symlink("a", "b"),
            ])
        };
        let upper = layer(&[file(".wh.a", 0o644, b""), file("a/.wh.file", 0o644, b"")]);
        let (tmp, _) = unpack(&[lower(), upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l.keys().collect::<Vec<_>>(), ["b", "b/file"]);
        let upper = layer(&[file("a/.wh.file", 0o644, b""), file(".wh.a", 0o644, b"")]);
        let (tmp, _) = unpack(&[lower(), upper]);
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert_eq!(l.keys().collect::<Vec<_>>(), ["b"]);
    }

    #[test]
    fn the_same_layers_give_the_same_tree() {
        let layers = [
            layer(&[
                dir("d/", 0o755),
                file("d/a", 0o644, b"a"),
                symlink("d/l", "a"),
                hardlink("d/h", "d/a"),
            ]),
            layer(&[pax_file(b"d/.wh.a", b""), file("d/b", 0o600, b"b")]),
        ];
        let (one, _) = unpack(&layers);
        let (two, _) = unpack(&layers);
        let strip = |l: std::collections::BTreeMap<String, String>| -> Vec<String> {
            l.into_iter()
                .map(|(k, v)| format!("{k}: {}", v.split(" ino=").next().unwrap()))
                .collect()
        };
        assert_eq!(
            strip(listing(&one.path().join("rootfs"))),
            strip(listing(&two.path().join("rootfs")))
        );
    }
}
