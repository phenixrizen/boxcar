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

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;

use super::framer::{Framer, Kind};

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

/// The mode directories have while the tree is built; their own modes
/// are applied once every layer is in, so none blocks its children.
const BUILDING_DIR_MODE: libc::mode_t = 0o700;

/// The most the unpacker keeps in memory about the tree: directory paths
/// whose modes wait for the end, and the paths of skipped entries. A
/// layer may declare any number of either, with names of any length.
pub const MAX_METADATA: u64 = 64 * 1024 * 1024;
/// What one kept path costs past its bytes.
const ENTRY_COST: u64 = 32;

const WHITEOUT: &[u8] = b".wh.";
const OPAQUE: &[u8] = b".wh..wh..opq";

/// A tree being built from layers.
pub struct Unpacker {
    root: OwnedFd,
    /// Directory modes, applied once every layer is in; a later entry for
    /// the same directory wins, and a directory that goes is forgotten.
    dir_modes: BTreeMap<Vec<Vec<u8>>, u32>,
    skipped: Vec<String>,
    /// What may still be kept in memory, against [`MAX_METADATA`].
    metadata_left: u64,
}

/// What unpacking left out: devices and FIFOs, by path.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Skipped(pub Vec<String>);

impl Unpacker {
    /// A tree at `root`, an existing empty directory.
    pub fn new(root: &Path) -> io::Result<Unpacker> {
        let file = File::open(root)?;
        if !file.metadata()?.is_dir() {
            return Err(malformed(format!("{} is not a directory", root.display())));
        }
        Ok(Unpacker {
            root: OwnedFd::from(file),
            dir_modes: BTreeMap::new(),
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

    /// Records the mode `comps` will get at the end.
    fn remember_mode(&mut self, comps: Vec<Vec<u8>>, mode: u32) -> io::Result<()> {
        if !self.dir_modes.contains_key(&comps) {
            self.keep(comps.iter().map(Vec::len).sum())?;
        }
        self.dir_modes.insert(comps, mode);
        Ok(())
    }

    /// Forgets the modes of everything beneath `comps`, and of `comps`
    /// itself when `itself`: what stood there is gone, and whatever takes
    /// the name (a link, say) must not inherit the mode.
    fn forget_modes(&mut self, comps: &[Vec<u8>], itself: bool) {
        self.dir_modes.retain(|path, _| {
            let beneath = path.len() > comps.len() && path[..comps.len()] == *comps;
            let same = path.as_slice() == comps;
            !(beneath || (itself && same))
        });
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
                self.forget_modes(parent, false);
            } else if let Some(target) = name.strip_prefix(WHITEOUT) {
                match target {
                    b"" | b"." => {}
                    b".." => return Err(malformed("a whiteout of `..`")),
                    target => {
                        self.remove_in(parent, target)?;
                        let mut gone = parent.to_vec();
                        gone.push(target.to_vec());
                        self.forget_modes(&gone, true);
                    }
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
                continue;
            };
            if name.starts_with(WHITEOUT) {
                continue;
            }
            let name = cstr(name)?;
            match entry.kind {
                Kind::Dir => {
                    let parent_fd = self.parent_fd(parent)?;
                    if make_dir(&parent_fd, &name)? {
                        self.forget_modes(&comps, true);
                    }
                    self.remember_mode(comps.clone(), entry.mode)?;
                }
                Kind::File => {
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        self.forget_modes(&comps, true);
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
                    check(unsafe { libc::fchmod(file.as_raw_fd(), entry.mode as libc::mode_t) })?;
                }
                Kind::Symlink => {
                    let target = cstr(&entry.link)?;
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        self.forget_modes(&comps, true);
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
                            return Err(missing_target(&entry.link))
                        }
                        Err(error) => return Err(error),
                    };
                    match stat_at(&target_parent_fd, &target_name)? {
                        None => return Err(missing_target(&entry.link)),
                        Some(mode) if mode & libc::S_IFMT == libc::S_IFDIR => {
                            return Err(malformed("a hardlink to a directory"))
                        }
                        Some(_) => {}
                    }
                    let parent_fd = self.parent_fd(parent)?;
                    if replace_slot(&parent_fd, &name)? {
                        self.forget_modes(&comps, true);
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
                }
                Kind::CharDevice | Kind::BlockDevice | Kind::Fifo => {
                    let path = display(&comps);
                    self.keep(path.len())?;
                    self.skipped.push(path);
                }
            }
        }
        Ok(())
    }

    /// After the last layer: `tmp` and `workspace` at the root when
    /// missing, directory modes deepest first. Answers what was skipped.
    pub fn finish(mut self) -> io::Result<Skipped> {
        for (name, mode) in [("tmp", 0o1777u32), ("workspace", IMPLIED_DIR_MODE)] {
            let cname = cstr(name.as_bytes())?;
            if stat_at(&self.root, &cname)?.is_none() {
                check(unsafe {
                    libc::mkdirat(self.root.as_raw_fd(), cname.as_ptr(), BUILDING_DIR_MODE)
                })?;
                self.remember_mode(vec![name.as_bytes().to_vec()], mode)?;
            }
        }
        let mut dirs: Vec<(Vec<Vec<u8>>, u32)> =
            std::mem::take(&mut self.dir_modes).into_iter().collect();
        dirs.sort_by_key(|(comps, _)| std::cmp::Reverse(comps.len()));
        for (comps, mode) in dirs {
            // The parent resolved in the root, then the name itself with
            // nothing followed: a later layer may have put a link there.
            let Some((name, parent)) = comps.split_last() else {
                continue;
            };
            let parent_fd = match self.open_dir(parent) {
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
            chmod_fd(&fd, mode)?;
        }
        Ok(Skipped(self.skipped))
    }

    /// The directory `comps` names, resolved in the root; `O_PATH`.
    fn open_dir(&self, comps: &[Vec<u8>]) -> io::Result<OwnedFd> {
        let path = if comps.is_empty() {
            CString::new(".").expect("no NUL")
        } else {
            cstr(&comps.join(&b'/'))?
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
                malformed(format!("{} is not a directory", display(comps)))
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
            if !self.dir_modes.contains_key(&parent[..depth]) {
                self.remember_mode(parent[..depth].to_vec(), IMPLIED_DIR_MODE)?;
            }
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
        drop(dir);
        for child in children(readable)? {
            remove_at(&self.open_dir(parent)?, &child)?;
        }
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
        remove_at(&dir, &cstr(target)?)?;
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

fn delete_tree_at(parent: &OwnedFd, name: &CStr) -> io::Result<()> {
    let opath = openat(
        parent,
        name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    // Ours to delete, whatever mode a layer gave it.
    chmod_fd(&opath, 0o700)?;
    drop(opath);
    let dir = openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    let dir_fd = openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    for child in children(dir)? {
        remove_at(&dir_fd, &child)?;
    }
    drop(dir_fd);
    check(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) })
}

/// Removes `name` in `parent`: a directory whole, anything else unlinked,
/// nothing when it is not there. Answers whether a directory went.
fn remove_at(parent: &OwnedFd, name: &CStr) -> io::Result<bool> {
    match stat_at(parent, name)? {
        None => Ok(false),
        Some(mode) if mode & libc::S_IFMT == libc::S_IFDIR => {
            delete_tree_at(parent, name)?;
            Ok(true)
        }
        Some(_) => {
            check(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) })?;
            Ok(false)
        }
    }
}

/// Makes room for a new entry at `name`: whatever is there goes. Answers
/// whether a directory went.
fn replace_slot(parent: &OwnedFd, name: &CStr) -> io::Result<bool> {
    remove_at(parent, name)
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
fn children(dir: OwnedFd) -> io::Result<Vec<CString>> {
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

fn missing_target(link: &[u8]) -> io::Error {
    malformed(format!(
        "a hardlink to a missing target `{}`",
        String::from_utf8_lossy(link)
    ))
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
    fn unpack(layers: &[Vec<u8>]) -> (tempfile::TempDir, Skipped) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let skipped = unpack_into(&root, layers).unwrap();
        (tmp, skipped)
    }

    fn unpack_into(root: &Path, layers: &[Vec<u8>]) -> io::Result<Skipped> {
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
        assert_eq!(l["ro"], "dir 555");
        assert!(l.contains_key("ro/inside"), "{l:?}");
        assert_eq!(skipped, Skipped::default());
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
    fn devices_and_fifos_are_skipped_and_listed() {
        let layer = layer(&[
            special(EntryType::Char, "dev/null"),
            special(EntryType::Block, "dev/sda"),
            special(EntryType::Fifo, "run/fifo"),
            file("ok", 0o644, b"ok"),
        ]);
        let (tmp, skipped) = unpack(&[layer]);
        assert_eq!(
            skipped,
            Skipped(vec!["dev/null".into(), "dev/sda".into(), "run/fifo".into()])
        );
        let l = without_defaults(&tmp.path().join("rootfs"));
        assert!(l.contains_key("ok"));
        assert!(!l.contains_key("dev/null"));
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
        let (tmp, _) = unpack(&[layer]);
        let root = tmp.path().join("rootfs");
        assert_eq!(
            fs::metadata(root.join("locked"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0
        );
        delete_tree(tmp.path(), "rootfs").unwrap();
        assert!(!root.exists());
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
