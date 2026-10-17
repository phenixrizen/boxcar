// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The per-session copy of a cached tree: the copy itself, the boot paths
//! made in it before the guest boots, and the modes set last.
//!
//! The cache is never opened for writing by a run: the cached tree is
//! walked with directory descriptors, `readdir` and `fstatat`, so no path
//! is resolved and no link is followed on either side; names are acted on
//! with `*at` calls; the walk descends by name and ascends through `..`,
//! so three descriptors a side serve whatever the depth. A regular file
//! is reflinked (`FICLONE`) where the filesystem can, copied otherwise;
//! hardlink groups stay groups within the copy and never reach the cache.
//!
//! Every directory of the copy is 0o700 until the end: the boot paths
//! (what init would write to the root share at boot: mount points, the
//! working directory, `/etc/resolv.conf`, the trust store) are made
//! first, then every directory gets its stored mode and every path in the
//! image's `modes` its image mode, deepest first, on the name itself with
//! nothing followed.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use super::unpack::{children, delete_tree};

/// The most links a path may go through before it is refused, as init's
/// resolver has it.
const MAX_LINKS: usize = 40;

/// `FICLONE`: `_IOW(0x94, 9, int)`.
const FICLONE: libc::c_ulong = 0x4004_9409;

/// `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

/// What the guest mounts at boot over the root share: nothing the host
/// makes beneath these would be seen.
const MOUNTED: [&str; 4] = ["/run", "/dev", "/proc", "/sys"];
/// Where the workspace share is mounted.
const WORKSPACE: &str = "/workspace";
/// The mount points init moves or mounts onto; made when the image lacks
/// them.
const MOUNT_POINTS: [&str; 4] = ["dev", "proc", "sys", "run"];
/// What init's resolver gives the guest, and the trust store its plan
/// touches, as the guest sees them.
const RESOLV_CONF: &str = "/etc/resolv.conf";
const TRUST_STORE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Whether to try `FICLONE` first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reflink {
    Try,
    /// For tests of the copying path on a filesystem that reflinks.
    Never,
}

/// What `copy_tree` leaves for the end: the directories' stored modes.
#[derive(Debug, Default)]
pub struct Copied {
    /// Every directory of the copy (the root as the empty path) with the
    /// mode the cache stores for it.
    dirs: Vec<(Vec<u8>, u32)>,
    /// Entries of a kind the unpacker never makes, not copied.
    pub skipped: usize,
}

/// Why a copy, a boot path or a mode could not be made.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("copying the image's tree: {0}")]
    Copy(#[source] io::Error),
    #[error(
        "an entry of the cached tree cannot be read: the image was cached by an earlier boxcar; \
         `boxcar image rm` it and pull it again"
    )]
    Unreadable,
    #[error("preparing the tree for the boot: {0}")]
    Prepare(#[source] io::Error),
    #[error("the image's working directory is under a filesystem the guest mounts")]
    WorkingDirMounted,
    #[error("the image's working directory leads through too many links, or above /")]
    WorkingDirUnresolvable,
    #[error("setting the tree's modes: {0}")]
    Modes(#[source] io::Error),
}

/// Copies the cached tree at `source` to `dest` (which must not exist;
/// its parent must). Every directory of the copy is left 0o700 for
/// [`prepare_boot_paths`] and [`set_modes`]. On failure the partial copy
/// is removed.
pub fn copy_tree(source: &Path, dest: &Path, reflink: Reflink) -> Result<Copied, SessionError> {
    let mut created = false;
    match copy_tree_inner(source, dest, reflink, &mut created) {
        Ok(copied) => Ok(copied),
        Err(error) => {
            // Only what this copy made goes: a `dest` that was there
            // already is someone else's.
            if created {
                if let (Some(parent), Some(name)) = (dest.parent(), dest.file_name()) {
                    let _ = delete_tree(parent, &name.to_string_lossy());
                }
            }
            Err(if error.get_ref().is_some_and(|e| e.is::<Unreadable>()) {
                SessionError::Unreadable
            } else {
                SessionError::Copy(error)
            })
        }
    }
}

/// The marker of a source entry its owner cannot read.
#[derive(Debug)]
struct Unreadable;

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an unreadable entry")
    }
}

impl std::error::Error for Unreadable {}

/// An error from the source side: a refusal to read is the cache's older
/// modes, said so.
fn from_source(error: io::Error) -> io::Error {
    if error.raw_os_error() == Some(libc::EACCES) {
        io::Error::new(io::ErrorKind::PermissionDenied, Unreadable)
    } else {
        error
    }
}

fn copy_tree_inner(
    source: &Path,
    dest: &Path,
    reflink: Reflink,
    created: &mut bool,
) -> io::Result<Copied> {
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let src_root = OwnedFd::from(File::open(source).map_err(from_source)?);
    let root_mode = fstat(&src_root)?.st_mode & 0o7777;
    let (dest_parent, dest_name) = match (dest.parent(), dest.file_name()) {
        (Some(parent), Some(name)) => (parent, cstr(name.as_encoded_bytes())?),
        _ => return Err(io::Error::other("the copy needs a parent and a name")),
    };
    let dest_parent_fd = OwnedFd::from(File::open(dest_parent)?);
    check(unsafe { libc::mkdirat(dest_parent_fd.as_raw_fd(), dest_name.as_ptr(), 0o700) })?;
    *created = true;
    let dst_root = openat(&dest_parent_fd, &dest_name, dir_flags, 0)?;
    drop(dest_parent_fd);

    let mut copied = Copied::default();
    copied.dirs.push((Vec::new(), u32::from(root_mode)));
    // Hardlink groups: the first path of each inode seen with more links.
    let mut groups: HashMap<(u64, u64), Vec<u8>> = HashMap::new();
    // The path of the current directory from the copy's root.
    let mut path: Vec<u8> = Vec::new();
    let mut cur_src = openat(&src_root, c".", dir_flags, 0).map_err(from_source)?;
    let mut cur_dst = openat(&dst_root, c".", dir_flags, 0)?;
    let mut levels: Vec<Vec<CString>> =
        vec![children(reopen(&cur_src).map_err(from_source)?).map_err(from_source)?];
    loop {
        let Some(pending) = levels.last_mut() else {
            break;
        };
        let Some(name) = pending.pop() else {
            levels.pop();
            if levels.is_empty() {
                break;
            }
            // Up one level on both sides, through `..` of directories
            // reached through no link.
            cur_src = openat(&cur_src, c"..", dir_flags, 0).map_err(from_source)?;
            cur_dst = openat(&cur_dst, c"..", dir_flags, 0)?;
            truncate_path(&mut path);
            continue;
        };
        let st = fstatat(&cur_src, &name).map_err(from_source)?;
        let mode = u32::from(st.st_mode & 0o7777);
        let kind = st.st_mode & libc::S_IFMT;
        let child_path = beneath(&path, name.to_bytes());
        if kind == libc::S_IFDIR {
            check(unsafe { libc::mkdirat(cur_dst.as_raw_fd(), name.as_ptr(), 0o700) })?;
            let next_src = openat(&cur_src, &name, dir_flags, 0).map_err(from_source)?;
            let next_dst = openat(&cur_dst, &name, dir_flags, 0)?;
            let kids = children(reopen(&next_src).map_err(from_source)?).map_err(from_source)?;
            copied.dirs.push((child_path.clone(), mode));
            cur_src = next_src;
            cur_dst = next_dst;
            path = child_path;
            levels.push(kids);
        } else if kind == libc::S_IFREG {
            let key = (st.st_dev as u64, st.st_ino as u64);
            if st.st_nlink > 1 {
                if let Some(first) = groups.get(&key) {
                    let first = cstr(first)?;
                    check(unsafe {
                        libc::linkat(
                            dst_root.as_raw_fd(),
                            first.as_ptr(),
                            cur_dst.as_raw_fd(),
                            name.as_ptr(),
                            0,
                        )
                    })?;
                    continue;
                }
                groups.insert(key, child_path.clone());
            }
            copy_file(&cur_src, &cur_dst, &name, mode, st.st_size as u64, reflink)?;
        } else if kind == libc::S_IFLNK {
            let target = readlinkat(&cur_src, &name).map_err(from_source)?;
            check(unsafe { libc::symlinkat(target.as_ptr(), cur_dst.as_raw_fd(), name.as_ptr()) })?;
        } else {
            copied.skipped += 1;
        }
    }
    Ok(copied)
}

/// Copies the regular file `name` from `src_dir` into `dst_dir`: a reflink
/// where the filesystem can, `copy_file_range` or plain reads and writes
/// otherwise; then its stored `mode`.
fn copy_file(
    src_dir: &OwnedFd,
    dst_dir: &OwnedFd,
    name: &CStr,
    mode: u32,
    size: u64,
    reflink: Reflink,
) -> io::Result<()> {
    let src = openat(
        src_dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .map_err(from_source)?;
    let dst = openat(
        dst_dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    let cloned = reflink == Reflink::Try
        && unsafe { libc::ioctl(dst.as_raw_fd(), FICLONE, src.as_raw_fd()) } == 0;
    if !cloned {
        copy_data(&src, &dst, size)?;
    }
    check(unsafe { libc::fchmod(dst.as_raw_fd(), mode as libc::mode_t) })
}

/// The data of `src` into `dst`: `copy_file_range` while the kernel does
/// it, reads and writes when it will not.
fn copy_data(src: &OwnedFd, dst: &OwnedFd, size: u64) -> io::Result<()> {
    let mut left = size;
    while left > 0 {
        let chunk = left.min(1 << 30) as usize;
        // SAFETY: two descriptors we hold, null offsets (the files' own).
        let n = unsafe {
            libc::copy_file_range(
                src.as_raw_fd(),
                std::ptr::null_mut(),
                dst.as_raw_fd(),
                std::ptr::null_mut(),
                chunk,
                0,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::EXDEV | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL) => {
                    copy_by_hand(src, dst)
                }
                _ => Err(error),
            };
        }
        if n == 0 {
            // Shorter than stat said: what is there is what is copied.
            break;
        }
        left -= n as u64;
    }
    Ok(())
}

fn copy_by_hand(src: &OwnedFd, dst: &OwnedFd) -> io::Result<()> {
    use std::io::{Read, Write};
    let mut reader = File::from(dup(src)?);
    let mut writer = File::from(dup(dst)?);
    // From the start: copy_file_range may have moved both offsets.
    check(unsafe { libc::lseek(reader.as_raw_fd(), 0, libc::SEEK_SET) } as libc::c_int)?;
    check(unsafe { libc::lseek(writer.as_raw_fd(), 0, libc::SEEK_SET) } as libc::c_int)?;
    check(unsafe { libc::ftruncate(writer.as_raw_fd(), 0) })?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return writer.flush();
        }
        writer.write_all(&buf[..n])?;
    }
}

/// Where the session's filesystems meet the host: the copy's root and the
/// workspace's host directory.
pub struct Layout<'a> {
    pub root: &'a Path,
    pub workspace: &'a Path,
}

/// What the session needs made before init runs.
pub struct BootNeeds<'a> {
    /// The session's working directory, as the guest will see it.
    pub cwd: &'a str,
    /// Whether the session has a network: init then gives it a resolver.
    pub net: bool,
    /// Whether the session inspects: init then installs the session CA.
    pub inspect: bool,
}

/// Makes in the copy (and the workspace) what init would otherwise write
/// to the root share at boot, in an order where what is made first is
/// there for what is decided next: the mount points, the working
/// directory, `/etc/resolv.conf`, the trust store. Every directory of
/// the copy is still 0o700.
pub fn prepare_boot_paths(layout: &Layout<'_>, needs: &BootNeeds<'_>) -> Result<(), SessionError> {
    let root = OwnedFd::from(File::open(layout.root).map_err(SessionError::Prepare)?);
    for point in MOUNT_POINTS {
        mkdir_missing(&root, Path::new(point), 0o755).map_err(SessionError::Prepare)?;
    }
    make_working_dir(&root, layout, needs.cwd)?;
    if needs.net {
        touch_where_it_leads(&root, RESOLV_CONF).map_err(SessionError::Prepare)?;
    }
    if needs.inspect {
        touch_where_it_leads(&root, TRUST_STORE).map_err(SessionError::Prepare)?;
    }
    Ok(())
}

/// The working directory, where the guest will see it: judged by where the
/// path leads once the copy's links are followed.
fn make_working_dir(root: &OwnedFd, layout: &Layout<'_>, cwd: &str) -> Result<(), SessionError> {
    let led = follow(root, cwd).map_err(|_| SessionError::WorkingDirUnresolvable)?;
    let leads = led.path.as_path();
    if MOUNTED.iter().any(|mounted| leads.starts_with(mounted)) {
        return Err(SessionError::WorkingDirMounted);
    }
    if let Ok(rest) = leads.strip_prefix(WORKSPACE) {
        // The workspace share is mounted there: made in its host directory.
        std::fs::create_dir_all(layout.workspace.join(rest)).map_err(SessionError::Prepare)?;
        return Ok(());
    }
    let rel = leads.strip_prefix("/").unwrap_or(leads);
    mkdir_missing(root, rel, 0o755).map_err(SessionError::Prepare)
}

/// Creates the file `path` (as the guest sees it), empty and 0o644, where
/// it leads once links are followed, when nothing is there and its
/// directory is: as init's resolver and trust plan `Touch` it. A path
/// leading under `/run` is init's tmpfs; a loop or an escape is left to
/// init to refuse.
fn touch_where_it_leads(root: &OwnedFd, path: &str) -> io::Result<()> {
    let Ok(led) = follow(root, path) else {
        return Ok(());
    };
    if led.exists || led.path.starts_with("/run") {
        return Ok(());
    }
    let (Some(parent), Some(name)) = (led.path.parent(), led.path.file_name()) else {
        return Ok(());
    };
    let parent = parent.strip_prefix("/").unwrap_or(parent);
    let dir = match open_dir(root, parent) {
        Ok(dir) => dir,
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
    let name = cstr(name.as_encoded_bytes())?;
    match openat(
        &dir,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o644,
    ) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

/// `mkdir -p` of `rel` beneath `root`, each component resolved through no
/// link; what is there stays.
fn mkdir_missing(root: &OwnedFd, rel: &Path, mode: u32) -> io::Result<()> {
    let mut dir = openat(
        root,
        c".",
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    for component in rel.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = cstr(name.as_encoded_bytes())?;
        match check(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) })
        {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        dir = openat(
            &dir,
            &name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
    }
    Ok(())
}

/// The directory `rel` beneath `root`, through no link.
fn open_dir(root: &OwnedFd, rel: &Path) -> io::Result<OwnedFd> {
    if rel.as_os_str().is_empty() {
        return openat(
            root,
            c".",
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        );
    }
    openat2(
        root,
        &cstr(rel.as_os_str().as_encoded_bytes())?,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
}

/// Where a path leads once links are followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Followed {
    /// Absolute within the tree, with no `.`, `..` or link in it.
    pub path: PathBuf,
    /// Whether something is there.
    pub exists: bool,
}

/// What is at a path of the tree.
enum Kind {
    Missing,
    Link,
    Other,
}

fn kind_at(root: &OwnedFd, rel: &Path) -> io::Result<Kind> {
    if rel.as_os_str().is_empty() {
        return Ok(Kind::Other);
    }
    let path = cstr(rel.as_os_str().as_encoded_bytes())?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated relative path and a stat buffer; the final
    // name is not followed. Components above it are, but `follow` resolves
    // them itself first, so none is a link when this is asked.
    let rc = unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            path.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR) => Ok(Kind::Missing),
            _ => Err(error),
        };
    }
    Ok(if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        Kind::Link
    } else {
        Kind::Other
    })
}

/// Where the absolute `path` leads in the tree at `root`, as init's
/// resolver follows a path: each component in turn, a link's target
/// (against the link's directory, or the root) put in its place. Refused
/// when it takes more than [`MAX_LINKS`] links, when a `..` would go above
/// the root, or when a lookup fails other than for want of a file.
pub fn follow(root: &OwnedFd, path: &str) -> Result<Followed, String> {
    enum Part {
        Root,
        Parent,
        Name(std::ffi::OsString),
    }
    fn parts(path: &Path) -> impl DoubleEndedIterator<Item = Part> + '_ {
        path.components().filter_map(|component| match component {
            Component::RootDir | Component::Prefix(_) => Some(Part::Root),
            Component::ParentDir => Some(Part::Parent),
            Component::Normal(name) => Some(Part::Name(name.to_owned())),
            Component::CurDir => None,
        })
    }
    let mut pending: std::collections::VecDeque<Part> = parts(Path::new(path)).collect();
    let mut resolved = PathBuf::from("/");
    let mut links = 0;
    let mut exists = true;
    while let Some(part) = pending.pop_front() {
        match part {
            Part::Root => resolved = PathBuf::from("/"),
            Part::Parent => {
                if !resolved.pop() {
                    return Err("leads above /".to_owned());
                }
            }
            Part::Name(name) => {
                let next = resolved.join(&name);
                let rel = next.strip_prefix("/").unwrap_or(&next).to_path_buf();
                let kind = if exists {
                    kind_at(root, &rel).map_err(|error| format!("lstat: {error}"))?
                } else {
                    Kind::Missing
                };
                match kind {
                    Kind::Link => {
                        links += 1;
                        if links > MAX_LINKS {
                            return Err(format!("takes more than {MAX_LINKS} links"));
                        }
                        let target = read_link_at(root, &rel)
                            .map_err(|error| format!("readlink: {error}"))?;
                        for part in parts(Path::new(&target)).rev() {
                            pending.push_front(part);
                        }
                    }
                    Kind::Other => resolved = next,
                    Kind::Missing => {
                        resolved = next;
                        exists = false;
                    }
                }
            }
        }
    }
    Ok(Followed {
        path: resolved,
        exists,
    })
}

fn read_link_at(root: &OwnedFd, rel: &Path) -> io::Result<PathBuf> {
    let path = cstr(rel.as_os_str().as_encoded_bytes())?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: a NUL-terminated path and a buffer of the length given.
    let n = unsafe {
        libc::readlinkat(
            root.as_raw_fd(),
            path.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// Sets the copy's modes, deepest first: every directory's stored mode,
/// and every path of `modes` its image mode in place of the stored one,
/// files included. The parent is resolved in the copy's root (a cached
/// tree's paths are within `PATH_MAX`: the unpacker refuses deeper), the
/// name opened with nothing followed; a name that is not there, or is a
/// link, is skipped.
pub fn set_modes(
    root: &Path,
    copied: &Copied,
    modes: &[(String, u32)],
) -> Result<(), SessionError> {
    let root_fd = OwnedFd::from(File::open(root).map_err(SessionError::Modes)?);
    let mut all: HashMap<Vec<u8>, u32> = copied.dirs.iter().cloned().collect();
    for (path, mode) in modes {
        all.insert(path.as_bytes().to_vec(), *mode);
    }
    let mut entries: Vec<(Vec<u8>, u32)> = all.into_iter().collect();
    entries.sort_by(|a, b| depth(&b.0).cmp(&depth(&a.0)).then_with(|| a.0.cmp(&b.0)));
    for (path, mode) in entries {
        set_mode(&root_fd, &path, mode).map_err(SessionError::Modes)?;
    }
    Ok(())
}

fn set_mode(root: &OwnedFd, path: &[u8], mode: u32) -> io::Result<()> {
    let fd = if path.is_empty() {
        openat(
            root,
            c".",
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?
    } else {
        let (parent, name) = match path.iter().rposition(|b| *b == b'/') {
            Some(at) => (&path[..at], &path[at + 1..]),
            None => (&path[..0], path),
        };
        let parent_fd = match open_dir(root, Path::new(std::ffi::OsStr::from_bytes(parent))) {
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
        match openat(
            &parent_fd,
            &cstr(name)?,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    };
    if fstat(&fd)?.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Ok(());
    }
    let proc_path = cstr(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
    check(unsafe { libc::chmod(proc_path.as_ptr(), mode as libc::mode_t) })
}

fn depth(path: &[u8]) -> usize {
    if path.is_empty() {
        0
    } else {
        path.iter().filter(|b| **b == b'/').count() + 1
    }
}

fn beneath(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(dir.len() + 1 + name.len());
    if !dir.is_empty() {
        path.extend_from_slice(dir);
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

fn truncate_path(path: &mut Vec<u8>) {
    match path.iter().rposition(|b| *b == b'/') {
        Some(at) => path.truncate(at),
        None => path.clear(),
    }
}

fn cstr(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::other("a path with a NUL byte"))
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st)
}

fn fstatat(dir: &OwnedFd, name: &CStr) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(st)
}

fn readlinkat(dir: &OwnedFd, name: &CStr) -> io::Result<CString> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    cstr(&buf)
}

fn dup(fd: &OwnedFd) -> io::Result<OwnedFd> {
    Ok(fd.try_clone()?)
}

fn reopen(dir: &OwnedFd) -> io::Result<OwnedFd> {
    openat(
        dir,
        c".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
}

fn openat(
    dir: &OwnedFd,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS`: the path resolved beneath `root`, through no
/// link at all.
fn openat2(root: &OwnedFd, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    for _ in 0..8 {
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
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
    }
    Err(io::Error::from_raw_os_error(libc::EAGAIN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::framer::Framer;
    use crate::oci::testutil::{self, dir, file, hardlink, layer, listing, symlink};
    use crate::oci::unpack::{Finished, Unpacker};
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// A cached tree made by the unpacker from `layers`, as the pull would.
    fn cached(root: &Path, layers: &[Vec<u8>]) -> Finished {
        fs::create_dir(root).unwrap();
        let mut unpacker = Unpacker::new(root).unwrap();
        let entries = Cell::new(u64::MAX);
        for layer in layers {
            let mut framer = Framer::new(&layer[..], &entries);
            unpacker.whiteouts(&mut framer).unwrap();
            framer.finish().unwrap();
            let mut framer = Framer::new(&layer[..], &entries);
            unpacker.entries(&mut framer).unwrap();
            framer.finish().unwrap();
        }
        unpacker.finish().unwrap()
    }

    fn copy_all(src: &Path, dst: &Path, modes: &[(String, u32)], reflink: Reflink) -> Copied {
        let copied = copy_tree(src, dst, reflink).unwrap();
        set_modes(dst, &copied, modes).unwrap();
        copied
    }

    /// A listing with inode numbers taken out, so two trees compare.
    fn shape(root: &Path) -> Vec<(String, String)> {
        listing(root)
            .into_iter()
            .map(|(k, v)| (k, v.split(" ino=").next().unwrap().to_owned()))
            .collect()
    }

    fn inodes(root: &Path) -> std::collections::BTreeSet<u64> {
        let mut out = std::collections::BTreeSet::new();
        fn walk(dir: &Path, out: &mut std::collections::BTreeSet<u64>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let meta = entry.metadata().unwrap();
                out.insert(meta.ino());
                if meta.is_dir() {
                    walk(&entry.path(), out);
                }
            }
        }
        walk(root, &mut out);
        out
    }

    fn image_layers() -> Vec<Vec<u8>> {
        vec![layer(&[
            dir("etc/", 0o755),
            file("etc/motd", 0o644, b"hello"),
            file("etc/shadow", 0o000, b"root:*:"),
            file("usr/bin/su", 0o4755, b"#!su"),
            symlink("etc/alt", "/etc/motd"),
            symlink("rel", "etc/../etc/motd"),
            symlink("dangling", "/nowhere"),
            symlink("out", "/etc/passwd"),
            hardlink("etc/motd2", "etc/motd"),
            dir("ro/", 0o555),
            file("ro/inside", 0o600, b"x"),
            dir("locked/", 0o000),
            file("locked/secret", 0o600, b"s"),
            dir("sticky/", 0o1777),
            dir("deep/a/b/c/", 0o700),
            file("deep/a/b/c/d", 0o400, b"d"),
        ])]
    }

    #[test]
    fn the_copy_is_the_image_tree_and_the_cache_is_untouched() {
        for reflink in [Reflink::Try, Reflink::Never] {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("rootfs");
            let finished = cached(&src, &image_layers());
            let before = listing(&src);
            let dst = tmp.path().join("copy");
            let copied = copy_all(&src, &dst, &finished.modes, reflink);
            assert_eq!(copied.skipped, 0);
            // The copy has the image's modes where the cache stores readable
            // ones; opened up afterwards so the listing can look inside.
            let mode = |p: &str| {
                fs::symlink_metadata(dst.join(p))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777
            };
            assert_eq!(mode("etc/shadow"), 0o000);
            assert_eq!(mode("ro"), 0o555);
            assert_eq!(mode("locked"), 0o000);
            for (p, m) in [("etc/shadow", 0o400), ("ro", 0o755), ("locked", 0o700)] {
                fs::set_permissions(dst.join(p), fs::Permissions::from_mode(m)).unwrap();
            }
            let l = listing(&dst);
            assert_eq!(l["sticky"], "dir 1777");
            assert_eq!(l["usr/bin/su"], "file 4755 \"#!su\"");
            assert_eq!(l["etc/alt"], "symlink -> /etc/motd");
            assert_eq!(l["rel"], "symlink -> etc/../etc/motd");
            assert_eq!(l["dangling"], "symlink -> /nowhere");
            assert_eq!(l["out"], "symlink -> /etc/passwd");
            assert!(
                l["etc/motd"].starts_with("file 644 \"hello\" nlink=2"),
                "{}",
                l["etc/motd"]
            );
            assert_eq!(
                l["etc/motd"], l["etc/motd2"],
                "the pair is a pair in the copy"
            );
            assert_eq!(l["deep/a/b/c/d"], "file 400 \"d\"");
            assert_eq!(l["tmp"], "dir 1777");
            // With those three back at the cache's stored modes, the shapes agree.
            assert_eq!(shape(&dst), shape(&src));
            assert_eq!(finished.modes.len(), 3);
            // Nothing in the cache changed, and no inode is shared.
            assert_eq!(listing(&src), before);
            assert!(inodes(&src).is_disjoint(&inodes(&dst)));
            // A write in the copy leaves the cache's bytes alone.
            fs::write(dst.join("etc/motd"), b"changed").unwrap();
            assert_eq!(fs::read(src.join("etc/motd")).unwrap(), b"hello");
            assert_eq!(fs::read(src.join("etc/motd2")).unwrap(), b"hello");
            assert_eq!(
                fs::read(dst.join("etc/motd2")).unwrap(),
                b"changed",
                "through the copy's own link"
            );
            // Again into the same place: refused, the first copy intact.
            let err = copy_tree(&src, &dst, reflink).unwrap_err();
            assert!(matches!(err, SessionError::Copy(_)), "{err}");
            assert_eq!(fs::read(dst.join("etc/motd")).unwrap(), b"changed");
        }
    }

    #[test]
    fn a_failed_copy_leaves_nothing_and_an_unreadable_entry_names_the_cure() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("rootfs");
        cached(&src, &image_layers());
        // A tree cached by an earlier boxcar: an entry its owner cannot read.
        fs::set_permissions(src.join("etc/shadow"), fs::Permissions::from_mode(0o000)).unwrap();
        let dst = tmp.path().join("copy");
        let err = copy_tree(&src, &dst, Reflink::Try).unwrap_err();
        assert!(matches!(err, SessionError::Unreadable), "{err}");
        assert!(err.to_string().contains("boxcar image rm"));
        assert!(!dst.exists(), "the partial copy is gone");
        fs::set_permissions(src.join("etc/shadow"), fs::Permissions::from_mode(0o400)).unwrap();
        // A destination that cannot be written into.
        let parent = tmp.path().join("ro-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        let err = copy_tree(&src, &parent.join("copy"), Reflink::Try).unwrap_err();
        assert!(matches!(err, SessionError::Copy(_)), "{err}");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }

    #[test]
    fn a_tree_deeper_than_path_max_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("rootfs");
        fs::create_dir(&src).unwrap();
        let root = OwnedFd::from(File::open(&src).unwrap());
        // Within PATH_MAX, as the unpacker keeps a cached tree, and far
        // deeper than a descriptor limit would allow one descriptor a level.
        let depth = 1900;
        let name = cstr(b"d").unwrap();
        let mut cur = openat(&root, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0).unwrap();
        for level in 0..depth {
            check(unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), 0o755) }).unwrap();
            if level % 100 == 0 {
                let f = openat(
                    &cur,
                    c"f",
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o644,
                )
                .unwrap();
                drop(f);
            }
            cur = openat(&cur, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0).unwrap();
        }
        drop(cur);
        let dst = tmp.path().join("copy");
        let copied = copy_tree(&src, &dst, Reflink::Try).unwrap();
        assert_eq!(copied.dirs.len(), depth + 1);
        set_modes(&dst, &copied, &[]).unwrap();
        // The bottom is there.
        let bottom: PathBuf = std::iter::repeat_n("d", depth).collect();
        let deepest = OwnedFd::from(File::open(&dst).unwrap());
        open_dir(&deepest, &bottom).unwrap();
        assert!(open_dir(&deepest, &bottom).is_ok() || bottom.as_os_str().len() > 4000);
        delete_tree(tmp.path(), "copy").unwrap();
        delete_tree(tmp.path(), "rootfs").unwrap();
    }

    fn prepared(
        layers: &[Vec<u8>],
        cwd: &str,
        net: bool,
        inspect: bool,
    ) -> Result<(tempfile::TempDir, PathBuf, PathBuf), SessionError> {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("rootfs");
        let finished = cached(&src, layers);
        let dst = tmp.path().join("copy");
        let workspace = tmp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let copied = copy_tree(&src, &dst, Reflink::Try).unwrap();
        prepare_boot_paths(
            &Layout {
                root: &dst,
                workspace: &workspace,
            },
            &BootNeeds { cwd, net, inspect },
        )?;
        set_modes(&dst, &copied, &finished.modes).unwrap();
        Ok((tmp, dst, workspace))
    }

    #[test]
    fn the_boot_paths_are_made_where_missing_and_left_where_present() {
        // An image with nothing init needs: everything is made.
        let bare = vec![layer(&[file("bin/sh", 0o755, b"#!")])];
        let (_tmp, dst, _) = prepared(&bare, "/workspace", true, true).unwrap();
        let l = listing(&dst);
        for point in ["dev", "proc", "sys", "run"] {
            assert_eq!(l[point], "dir 755", "{point}");
        }
        assert_eq!(l["tmp"], "dir 1777");
        assert_eq!(l["workspace"], "dir 755");
        assert!(
            !l.contains_key("etc/resolv.conf"),
            "no /etc, so nothing to touch: {l:?}"
        );
        assert!(!l.contains_key("etc/ssl/certs/ca-certificates.crt"));
        // An image with /etc and /etc/ssl/certs: the files are made, empty.
        let with_etc = vec![layer(&[
            dir("etc/", 0o555),
            dir("etc/ssl/certs/", 0o755),
            dir("dev/", 0o755),
            file("dev/keep", 0o644, b"k"),
        ])];
        let (_tmp, dst, _) = prepared(&with_etc, "/workspace", true, true).unwrap();
        let l = listing(&dst);
        assert_eq!(l["etc/resolv.conf"], "file 644 \"\"");
        assert_eq!(l["etc/ssl/certs/ca-certificates.crt"], "file 644 \"\"");
        assert_eq!(l["etc"], "dir 555", "made inside, then locked");
        assert_eq!(l["dev/keep"], "file 644 \"k\"", "what is there stays");
        // Without a network or inspection, nothing is touched there.
        let (_tmp, dst, _) = prepared(&with_etc, "/workspace", false, false).unwrap();
        let l = listing(&dst);
        assert!(!l.contains_key("etc/resolv.conf"));
        assert!(!l.contains_key("etc/ssl/certs/ca-certificates.crt"));
        // Present: left as it is.
        let present = vec![layer(&[
            dir("etc/", 0o755),
            file("etc/resolv.conf", 0o644, b"nameserver 1.1.1.1\n"),
        ])];
        let (_tmp, dst, _) = prepared(&present, "/workspace", true, false).unwrap();
        assert_eq!(
            fs::read(dst.join("etc/resolv.conf")).unwrap(),
            b"nameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn resolv_conf_is_followed_as_init_follows_it() {
        // A link into /run: init's tmpfs, nothing made.
        let into_run = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf"),
        ])];
        let (_tmp, dst, _) = prepared(&into_run, "/workspace", true, false).unwrap();
        let l = listing(&dst);
        assert_eq!(
            l["etc/resolv.conf"],
            "symlink -> ../run/systemd/resolve/stub-resolv.conf"
        );
        assert!(!l.contains_key("run/systemd"));
        // A link to a file elsewhere whose directory exists: made there.
        let elsewhere = vec![layer(&[
            dir("etc/", 0o755),
            dir("var/lib/resolv/", 0o755),
            symlink("etc/resolv.conf", "/var/lib/resolv/resolv.conf"),
        ])];
        let (_tmp, dst, _) = prepared(&elsewhere, "/workspace", true, false).unwrap();
        assert_eq!(listing(&dst)["var/lib/resolv/resolv.conf"], "file 644 \"\"");
        // A link to a missing directory: nothing made; init fails as today.
        let missing_dir = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "/var/missing/resolv.conf"),
        ])];
        let (_tmp, dst, _) = prepared(&missing_dir, "/workspace", true, false).unwrap();
        assert!(!listing(&dst).contains_key("var"));
        // A loop: left to init.
        let loop_ = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "/etc/a"),
            symlink("etc/a", "/etc/resolv.conf"),
        ])];
        let (_tmp, dst, _) = prepared(&loop_, "/workspace", true, false).unwrap();
        let mut keys: Vec<String> = listing(&dst).into_keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "dev",
                "etc",
                "etc/a",
                "etc/resolv.conf",
                "proc",
                "run",
                "sys",
                "tmp",
                "workspace"
            ]
        );
        // A link to a file beneath the working directory, absent in the
        // image: the directory first, then the file in it.
        let under_cwd = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "/srv/app/resolv.conf"),
        ])];
        let (_tmp, dst, _) = prepared(&under_cwd, "/srv/app", true, false).unwrap();
        let l = listing(&dst);
        assert_eq!(l["srv/app"], "dir 755");
        assert_eq!(l["srv/app/resolv.conf"], "file 644 \"\"");
    }

    #[test]
    fn the_working_directory_is_made_where_the_guest_will_see_it() {
        let image = || {
            vec![layer(&[
                dir("etc/", 0o755),
                symlink("app", "/workspace"),
                symlink("var/run", "/run"),
                dir("ro/", 0o555),
            ])]
        };
        // Under /workspace, as written: in the workspace's host directory.
        let (_tmp, dst, workspace) = prepared(&image(), "/workspace/app", false, false).unwrap();
        assert!(workspace.join("app").is_dir());
        assert!(!dst.join("workspace/app").exists());
        // Under /workspace through a link: the same.
        let (_tmp, dst, workspace) = prepared(&image(), "/app/project/x", false, false).unwrap();
        assert!(workspace.join("project/x").is_dir());
        assert!(!dst.join("app").is_dir());
        // Elsewhere: in the copy, parents included; a 0o555 parent gets it
        // before its mode.
        let (_tmp, dst, _) = prepared(&image(), "/ro/sub/dir", false, false).unwrap();
        let l = listing(&dst);
        assert_eq!(l["ro"], "dir 555");
        assert_eq!(l["ro/sub/dir"], "dir 755");
        // Under a filesystem the guest mounts, as written or through a link:
        // refused.
        for cwd in ["/run/app", "/var/run/app", "/dev/x", "/proc/1", "/sys/fs"] {
            let err = prepared(&image(), cwd, false, false).err().unwrap();
            assert!(
                matches!(err, SessionError::WorkingDirMounted),
                "{cwd}: {err}"
            );
        }
        // A loop, or above the root: refused.
        let looped = vec![layer(&[symlink("l", "/l")])];
        let err = prepared(&looped, "/l/x", false, false).err().unwrap();
        assert!(matches!(err, SessionError::WorkingDirUnresolvable), "{err}");
        let err = prepared(&image(), "/../x", false, false).err().unwrap();
        assert!(matches!(err, SessionError::WorkingDirUnresolvable), "{err}");
        // /workspace itself, the default: nothing to make.
        let (_tmp, _, workspace) = prepared(&image(), "/workspace", false, false).unwrap();
        assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);
    }

    #[test]
    fn modes_are_set_last_deepest_first_with_the_images_winning() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("rootfs");
        let finished = cached(
            &src,
            &[layer(&[
                dir("a/", 0o000),
                dir("a/b/", 0o555),
                file("a/b/c", 0o000, b"c"),
                file("a/b/d", 0o644, b"d"),
            ])],
        );
        assert_eq!(
            finished.modes,
            [
                ("a".to_owned(), 0o000),
                ("a/b".to_owned(), 0o555),
                ("a/b/c".to_owned(), 0o000)
            ]
        );
        let dst = tmp.path().join("copy");
        let copied = copy_tree(&src, &dst, Reflink::Try).unwrap();
        // Before the modes: everything 0o700, readable.
        assert_eq!(
            fs::metadata(dst.join("a")).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::read(dst.join("a/b/c")).unwrap(), b"c");
        set_modes(&dst, &copied, &finished.modes).unwrap();
        let mode = |p: &str| {
            fs::symlink_metadata(dst.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("a"), 0o000);
        fs::set_permissions(dst.join("a"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(mode("a/b"), 0o555);
        assert_eq!(mode("a/b/c"), 0o000);
        assert_eq!(mode("a/b/d"), 0o644);
        assert_eq!(
            mode(""),
            fs::metadata(&src).unwrap().permissions().mode() & 0o7777
        );
        // A path of `modes` that is gone, or a link, is skipped.
        let copied = copy_tree(&src, &tmp.path().join("copy2"), Reflink::Try).unwrap();
        let dst2 = tmp.path().join("copy2");
        fs::remove_file(dst2.join("a/b/c")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dst2.join("a/b/c")).unwrap();
        set_modes(&dst2, &copied, &finished.modes).unwrap();
        assert_eq!(
            fs::metadata("/etc/passwd").unwrap().permissions().mode() & 0o7777,
            0o644,
            "the link's target is untouched"
        );
        let _ = testutil::listing;
    }
}
