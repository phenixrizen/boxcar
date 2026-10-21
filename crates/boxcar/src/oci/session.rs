// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What an image session's root needs before the guest boots.
//!
//! The session's root share is an overlay ([`boxcar_fs::overlay`]): the
//! cached tree read-only below, the session's own directory above. The
//! cache is never written by a run; what the session changes is copied up
//! into its directory as it changes it.
//!
//! Init writes to the root share at boot (mount points, the working
//! directory, `/etc/resolv.conf`, the trust store), and a policy keeping
//! writes out of the root share would stand between init and its setup;
//! so the host makes those paths first, through the overlay itself, so
//! that a directory made above a lower one is its shell (owner and all)
//! and the image's links lead where the guest will see them lead.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

/// The most links a path may go through before it is refused, as init's
/// resolver has it.
const MAX_LINKS: usize = 40;

/// What the guest mounts at boot over the root share (the tmpfs and the
/// kernel filesystems), named as the image names them: `mount(2)` follows a
/// link there, so each lands where its path leads, and nothing the host
/// makes beneath that place would be seen.
const MOUNTED: [&str; 4] = ["/run", "/dev", "/proc", "/sys"];
/// Where the workspace share is mounted.
const WORKSPACE: &str = "/workspace";
/// What init's resolver gives the guest, and the trust store its plan
/// touches, as the guest sees them.
const RESOLV_CONF: &str = "/etc/resolv.conf";
const TRUST_STORE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Why a boot path could not be made.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("preparing the root for the boot: {0}")]
    Prepare(#[source] io::Error),
    #[error("the image's working directory is under a filesystem the guest mounts")]
    WorkingDirMounted,
    #[error("the image's working directory leads through too many links, or above /")]
    WorkingDirUnresolvable,
    #[error(
        "the image's /workspace is a link that leads to nothing, or to a file: the workspace \
         share could not be mounted there"
    )]
    WorkspaceMount,
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

/// What is mounted at a place of the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mount {
    Workspace,
    Kernel,
}

/// Makes in the merge of `lower` (the cached tree) and `upper` (the
/// session's directory) what init would otherwise write to the root share
/// at boot, in an order where what is made first is there for what is
/// decided next: the mount points, the working directory,
/// `/etc/resolv.conf`, the trust store. `modes` are the image's modes of
/// the entries the cache stores otherwise, as the overlay shows them. The
/// working directory in the workspace is made in `workspace`, its host
/// directory.
pub fn prepare_boot_paths(
    lower: &Path,
    upper: &Path,
    modes: &[(String, u32)],
    workspace: &Path,
    needs: &BootNeeds<'_>,
) -> Result<(), SessionError> {
    use boxcar_fs::{passthrough_config, CachePolicyKind, FsShareConfig, OverlayFs};
    use fuse_backend_rs::passthrough::PassthroughFs;
    let layer = |dir: &Path| -> io::Result<PassthroughFs> {
        let fs = PassthroughFs::<()>::new(passthrough_config(&FsShareConfig {
            tag: "root".into(),
            host_dir: dir.to_path_buf(),
            guest_path: "/".into(),
            cache: CachePolicyKind::Always,
            lower: None,
        }))?;
        fs.import()?;
        Ok(fs)
    };
    let open = |dir: &Path| File::open(dir).map(OwnedFd::from);
    let fs = OverlayFs::new(
        layer(lower).map_err(SessionError::Prepare)?,
        open(lower).map_err(SessionError::Prepare)?,
        layer(upper).map_err(SessionError::Prepare)?,
        open(upper).map_err(SessionError::Prepare)?,
        modes,
    );
    let view = merged::View::new(&fs, workspace)?;
    for (at, exists) in &view.kernel_at {
        if !exists {
            merged::mkdir_missing(&fs, at).map_err(SessionError::Prepare)?;
        }
    }
    let led =
        merged::follow(&fs, &view, needs.cwd).map_err(|_| SessionError::WorkingDirUnresolvable)?;
    match view.mount_at(&led.path) {
        Some(Mount::Kernel) => return Err(SessionError::WorkingDirMounted),
        Some(Mount::Workspace) => {
            let rest = view.in_workspace(&led.path).unwrap_or(Path::new(""));
            std::fs::create_dir_all(workspace.join(rest)).map_err(SessionError::Prepare)?;
        }
        None => merged::mkdir_missing(&fs, &led.path).map_err(SessionError::Prepare)?,
    }
    if needs.net {
        merged::touch_where_it_leads(&fs, &view, RESOLV_CONF).map_err(SessionError::Prepare)?;
    }
    if needs.inspect {
        merged::touch_where_it_leads(&fs, &view, TRUST_STORE).map_err(SessionError::Prepare)?;
    }
    Ok(())
}

/// `openat2`'s resolve flags: beneath the root, through no magic link.
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

/// The most bytes [`read_within`] reads.
const READ_WITHIN_MAX: u64 = 1024 * 1024;

/// The contents of `path` (relative) resolved beneath `root` as the guest
/// would resolve it: a symlink is followed, but only within the tree.
/// At most [`READ_WITHIN_MAX`] bytes; a file past that is an error.
pub fn read_within(root: &Path, path: &str) -> io::Result<Vec<u8>> {
    let root = OwnedFd::from(File::open(root)?);
    let file = openat2(
        &root,
        &merged::cstr(path.as_bytes())?,
        libc::O_RDONLY | libc::O_CLOEXEC,
        RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    )?;
    use std::io::Read as _;
    let mut out = Vec::new();
    File::from(file)
        .take(READ_WITHIN_MAX + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > READ_WITHIN_MAX {
        return Err(io::Error::other(format!("{path} is over 1 MiB")));
    }
    Ok(out)
}

/// `openat2` beneath `root` with the `resolve` flags given.
fn openat2(root: &OwnedFd, path: &CStr, flags: libc::c_int, resolve: u64) -> io::Result<OwnedFd> {
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
        resolve,
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

/// The guest's view through the overlay, resolved with the overlay's own
/// lookups: links followed within the merge, the mounts applied where
/// they land.
mod merged {
    use super::{Mount, SessionError, MAX_LINKS, MOUNTED, WORKSPACE};
    use fuse_backend_rs::abi::fuse_abi::CreateIn;
    use fuse_backend_rs::api::filesystem::{Context, Entry, FileSystem, ROOT_ID};
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Path, PathBuf};

    type Fs = dyn FileSystem<Inode = u64, Handle = u64>;

    const CTX: Context = Context {
        uid: 0,
        gid: 0,
        pid: 0,
    };

    /// The guest's view of its root: the merge, with init's mounts applied
    /// where init applies them. `mount(2)` follows a link at a mount
    /// point, so the workspace share lands where the image's `/workspace`
    /// leads, and the tmpfs and the kernel filesystems where `/run`,
    /// `/dev`, `/proc` and `/sys` lead; beneath the workspace's place the
    /// workspace's host directory is what the guest sees, beneath a kernel
    /// filesystem's nothing of the image is.
    pub struct View<'a> {
        /// The workspace's host directory.
        workspace: &'a Path,
        /// Where the workspace share lands; none while the view is being
        /// made.
        workspace_at: Option<PathBuf>,
        /// Where each kernel filesystem lands, and whether the directory
        /// is there already.
        pub kernel_at: Vec<(PathBuf, bool)>,
    }

    /// Where a path leads once the links are followed.
    pub struct Followed {
        /// Absolute within the merge, with no `.`, `..` or link in it.
        pub path: PathBuf,
        /// Whether something is there.
        pub exists: bool,
    }

    impl<'a> View<'a> {
        /// The view of the merge `fs` with the workspace at `workspace`:
        /// the mount points followed, as `mount(2)` will follow them. An
        /// image whose `/workspace` is a link to nothing, or to a file, is
        /// refused: the share could not be mounted there.
        pub fn new(fs: &Fs, workspace: &'a Path) -> Result<View<'a>, SessionError> {
            let mut view = View {
                workspace,
                workspace_at: None,
                kernel_at: Vec::new(),
            };
            let led = follow(fs, &view, WORKSPACE).map_err(|_| SessionError::WorkspaceMount)?;
            if led.path != Path::new(WORKSPACE) {
                // A link: what it leads to must be a directory already.
                if !led.exists || !is_dir(fs, &led.path)? {
                    return Err(SessionError::WorkspaceMount);
                }
            }
            view.workspace_at = Some(led.path);
            for point in MOUNTED {
                // A loop or an escape: init will refuse the mount; the
                // literal place bounds the view meanwhile.
                let led = follow(fs, &view, point).unwrap_or(Followed {
                    path: PathBuf::from(point),
                    exists: false,
                });
                view.kernel_at.push((led.path, led.exists));
            }
            Ok(view)
        }

        /// What the guest has mounted at or above `path`, if anything.
        pub fn mount_at(&self, path: &Path) -> Option<Mount> {
            if let Some(at) = &self.workspace_at {
                if path.starts_with(at) {
                    return Some(Mount::Workspace);
                }
            }
            if self.kernel_at.iter().any(|(at, _)| path.starts_with(at)) {
                return Some(Mount::Kernel);
            }
            None
        }

        /// `path` relative to where the workspace share lands.
        pub fn in_workspace<'p>(&self, path: &'p Path) -> Option<&'p Path> {
            self.workspace_at
                .as_deref()
                .and_then(|at| path.strip_prefix(at).ok())
        }
    }

    pub(super) fn cstr(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn lookup(fs: &Fs, parent: u64, name: &[u8]) -> io::Result<Option<Entry>> {
        match fs.lookup(&CTX, parent, &cstr(name)?) {
            Ok(entry) if entry.inode == 0 => Ok(None),
            Ok(entry) => Ok(Some(entry)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The inode at the absolute `path` of normal components, through no
    /// link, or `None` where a component is missing.
    fn walk(fs: &Fs, path: &Path) -> io::Result<Option<u64>> {
        let mut at = ROOT_ID;
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            match lookup(fs, at, name.as_bytes())? {
                Some(entry) => at = entry.inode,
                None => return Ok(None),
            }
        }
        Ok(Some(at))
    }

    fn is_dir(fs: &Fs, path: &Path) -> Result<bool, SessionError> {
        let Some(ino) = walk(fs, path).map_err(SessionError::Prepare)? else {
            return Ok(false);
        };
        let (attr, _) = fs.getattr(&CTX, ino, None).map_err(SessionError::Prepare)?;
        Ok(attr.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }

    /// What is at a path.
    enum Kind {
        Missing,
        Link(Vec<u8>),
        Dir,
        /// A file, or anything else that is neither a link nor a directory.
        Other,
    }

    /// What the merge has at `name` in the directory at `dir` (absolute,
    /// resolved).
    fn kind_in_merge(fs: &Fs, dir: &Path, name: &[u8]) -> io::Result<Kind> {
        let Some(parent) = walk(fs, dir)? else {
            return Ok(Kind::Missing);
        };
        let Some(entry) = lookup(fs, parent, name)? else {
            return Ok(Kind::Missing);
        };
        Ok(match entry.attr.st_mode & libc::S_IFMT {
            libc::S_IFLNK => Kind::Link(fs.readlink(&CTX, entry.inode)?),
            libc::S_IFDIR => Kind::Dir,
            _ => Kind::Other,
        })
    }

    /// What the workspace's host directory has at `rel`.
    fn kind_in_workspace(workspace: &Path, rel: &Path) -> io::Result<Kind> {
        let path = workspace.join(rel);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Ok(Kind::Link(
                std::fs::read_link(&path)?.into_os_string().into_vec(),
            )),
            Ok(meta) if meta.is_dir() => Ok(Kind::Dir),
            Ok(_) => Ok(Kind::Other),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(Kind::Missing)
            }
            Err(error) => Err(error),
        }
    }

    enum Part {
        Root,
        Parent,
        Name(Vec<u8>),
    }

    fn parts(path: &[u8]) -> Vec<Part> {
        let mut out = Vec::new();
        if path.starts_with(b"/") {
            out.push(Part::Root);
        }
        for part in path.split(|b| *b == b'/') {
            match part {
                b"" | b"." => {}
                b".." => out.push(Part::Parent),
                name => out.push(Part::Name(name.to_vec())),
            }
        }
        out
    }

    /// Where the absolute `path` leads in the guest's `view`, as init's
    /// resolver follows a path: each component in turn, a link's target
    /// (against the link's directory, or the root) put in its place.
    /// Beneath the place the workspace share lands, the workspace's host
    /// directory is what the guest sees, so its entries are looked up and
    /// its links followed there; beneath a place a kernel filesystem
    /// lands nothing of the image is seen, so the rest is taken as
    /// written; a `..` that leaves either resumes the lookups. Refused
    /// when it takes more than [`MAX_LINKS`] links, when a `..` would go
    /// above the root, or when a lookup fails other than for want of a
    /// file.
    pub fn follow(fs: &Fs, view: &View<'_>, path: &str) -> Result<Followed, String> {
        let mut pending: std::collections::VecDeque<Part> = parts(path.as_bytes()).into();
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
                    let next = resolved.join(std::ffi::OsStr::from_bytes(&name));
                    let kind = match view.mount_at(&next) {
                        // Nothing of the image is seen there: taken as
                        // written. Not a missing component: a `..` that
                        // leaves the mount resumes the lookups.
                        Some(Mount::Kernel) => {
                            resolved = next;
                            continue;
                        }
                        // The workspace's host directory is what the guest
                        // sees; the mount point itself is there.
                        Some(Mount::Workspace) => match view.in_workspace(&next) {
                            Some(rest) if !rest.as_os_str().is_empty() && exists => {
                                kind_in_workspace(view.workspace, rest)
                                    .map_err(|error| format!("lstat: {error}"))?
                            }
                            Some(_) if !exists => Kind::Missing,
                            _ => {
                                resolved = next;
                                continue;
                            }
                        },
                        None if exists => kind_in_merge(fs, &resolved, &name)
                            .map_err(|error| format!("lookup: {error}"))?,
                        None => Kind::Missing,
                    };
                    match kind {
                        Kind::Link(target) => {
                            links += 1;
                            if links > MAX_LINKS {
                                return Err(format!("takes more than {MAX_LINKS} links"));
                            }
                            for part in parts(&target).into_iter().rev() {
                                pending.push_front(part);
                            }
                        }
                        Kind::Dir | Kind::Other => resolved = next,
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

    /// Makes the directories of the absolute `path` that are not there.
    pub fn mkdir_missing(fs: &Fs, path: &Path) -> io::Result<()> {
        let mut at = ROOT_ID;
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            at = match lookup(fs, at, name.as_bytes())? {
                Some(entry) => entry.inode,
                None => fs.mkdir(&CTX, at, &cstr(name.as_bytes())?, 0o755, 0)?.inode,
            };
        }
        Ok(())
    }

    /// Makes an empty file where `path` leads, unless something is there,
    /// or a mount will cover it, or its directory is missing.
    pub fn touch_where_it_leads(fs: &Fs, view: &View<'_>, path: &str) -> io::Result<()> {
        let Ok(led) = follow(fs, view, path) else {
            return Ok(());
        };
        if led.exists || view.mount_at(&led.path).is_some() {
            return Ok(());
        }
        let (Some(parent), Some(name)) = (led.path.parent(), led.path.file_name()) else {
            return Ok(());
        };
        let Some(dir) = walk(fs, parent)? else {
            return Ok(());
        };
        let args = CreateIn {
            flags: (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u32,
            mode: libc::S_IFREG | 0o644,
            umask: 0,
            fuse_flags: 0,
        };
        match fs.create(&CTX, dir, &cstr(name.as_bytes())?, args) {
            Ok((entry, handle, _, _)) => {
                if let Some(handle) = handle {
                    let _ = fs.release(&CTX, entry.inode, args.flags, handle, false, false, None);
                }
                Ok(())
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::framer::Framer;
    use crate::oci::testutil::{dir, file, layer, symlink};
    use crate::oci::unpack::{Finished, Unpacker};
    use boxcar_fs::{passthrough_config, CachePolicyKind, FsShareConfig, OverlayFs};
    use fuse_backend_rs::api::filesystem::{Context, FileSystem, ROOT_ID};
    use fuse_backend_rs::passthrough::PassthroughFs;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::PathBuf;

    const CTX: Context = Context {
        uid: 0,
        gid: 0,
        pid: 0,
    };

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

    /// A session prepared from `layers`: the cached tree below, an empty
    /// directory above, the boot paths made in the merge.
    struct Prepared {
        _tmp: tempfile::TempDir,
        lower: PathBuf,
        upper: PathBuf,
        workspace: PathBuf,
        modes: Vec<(String, u32)>,
    }

    fn prepared(
        layers: &[Vec<u8>],
        cwd: &str,
        net: bool,
        inspect: bool,
    ) -> Result<Prepared, SessionError> {
        let tmp = tempfile::tempdir().unwrap();
        let lower = tmp.path().join("rootfs");
        let finished = cached(&lower, layers);
        let upper = tmp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        let workspace = tmp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        prepare_boot_paths(
            &lower,
            &upper,
            &finished.modes,
            &workspace,
            &BootNeeds { cwd, net, inspect },
        )?;
        Ok(Prepared {
            _tmp: tmp,
            lower,
            upper,
            workspace,
            modes: finished.modes,
        })
    }

    fn overlay(
        lower: &Path,
        upper: &Path,
        modes: &[(String, u32)],
    ) -> OverlayFs<PassthroughFs, PassthroughFs> {
        let layer = |dir: &Path| {
            let fs = PassthroughFs::<()>::new(passthrough_config(&FsShareConfig {
                tag: "root".into(),
                host_dir: dir.to_path_buf(),
                guest_path: "/".into(),
                cache: CachePolicyKind::Always,
                lower: None,
            }))
            .unwrap();
            fs.import().unwrap();
            fs
        };
        let open = |dir: &Path| OwnedFd::from(File::open(dir).unwrap());
        OverlayFs::new(layer(lower), open(lower), layer(upper), open(upper), modes)
    }

    type Fs = OverlayFs<PassthroughFs, PassthroughFs>;

    impl Prepared {
        /// The merge as the guest will see it: each path with its kind,
        /// mode and content, as `testutil::listing` says them.
        fn merged(&self) -> BTreeMap<String, String> {
            let fs = overlay(&self.lower, &self.upper, &self.modes);
            let mut out = BTreeMap::new();
            walk(&fs, ROOT_ID, "", &mut out);
            out
        }
    }

    fn walk(fs: &Fs, dir: u64, prefix: &str, out: &mut BTreeMap<String, String>) {
        let (handle, _) = fs.opendir(&CTX, dir, libc::O_RDONLY as u32).unwrap();
        let handle = handle.unwrap();
        let mut names = Vec::new();
        fs.readdir(&CTX, dir, handle, 1 << 16, 0, &mut |entry| {
            let name = String::from_utf8(entry.name.to_vec()).unwrap();
            if name != "." && name != ".." {
                names.push(name);
            }
            Ok(1)
        })
        .unwrap();
        fs.releasedir(&CTX, dir, 0, handle).unwrap();
        for name in names {
            let entry = fs
                .lookup(&CTX, dir, &CString::new(name.as_str()).unwrap())
                .unwrap();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let mode = entry.attr.st_mode & 0o7777;
            let what = match entry.attr.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    walk(fs, entry.inode, &rel, out);
                    format!("dir {mode:o}")
                }
                libc::S_IFLNK => {
                    let target = fs.readlink(&CTX, entry.inode).unwrap();
                    format!("symlink -> {}", String::from_utf8_lossy(&target))
                }
                libc::S_IFREG => {
                    let (handle, _, _) = fs
                        .open(&CTX, entry.inode, libc::O_RDONLY as u32, 0)
                        .unwrap();
                    let handle = handle.unwrap();
                    let mut sink = tempfile::tempfile().unwrap();
                    let mut offset = 0;
                    loop {
                        let n = fs
                            .read(&CTX, entry.inode, handle, &mut sink, 4096, offset, None, 0)
                            .unwrap();
                        if n == 0 {
                            break;
                        }
                        offset += n as u64;
                    }
                    fs.release(
                        &CTX,
                        entry.inode,
                        libc::O_RDONLY as u32,
                        handle,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
                    sink.seek(SeekFrom::Start(0)).unwrap();
                    let mut data = Vec::new();
                    sink.read_to_end(&mut data).unwrap();
                    format!("file {mode:o} {:?}", String::from_utf8_lossy(&data))
                }
                _ => "special".to_owned(),
            };
            out.insert(rel, what);
        }
    }

    #[test]
    fn the_boot_paths_are_made_where_missing_and_left_where_present() {
        // An image with nothing init needs: everything is made, above.
        let bare = vec![layer(&[file("bin/sh", 0o755, b"#!")])];
        let p = prepared(&bare, "/workspace", true, true).unwrap();
        let l = p.merged();
        for point in ["dev", "proc", "sys", "run"] {
            assert_eq!(l[point], "dir 755", "{point}");
            assert!(p.upper.join(point).is_dir(), "{point} is made above");
            assert!(
                !p.lower.join(point).exists(),
                "{point} never touches the cache"
            );
        }
        assert_eq!(l["tmp"], "dir 1777");
        assert_eq!(l["workspace"], "dir 755");
        assert!(
            !l.contains_key("etc/resolv.conf"),
            "no /etc, so nothing to touch: {l:?}"
        );
        assert!(!l.contains_key("etc/ssl/certs/ca-certificates.crt"));
        // An image with /etc and /etc/ssl/certs: the files are made, empty,
        // in shells of the image's directories.
        let with_etc = vec![layer(&[
            dir("etc/", 0o555),
            dir("etc/ssl/certs/", 0o755),
            dir("dev/", 0o755),
            file("dev/keep", 0o644, b"k"),
        ])];
        let p = prepared(&with_etc, "/workspace", true, true).unwrap();
        let l = p.merged();
        assert_eq!(l["etc/resolv.conf"], "file 644 \"\"");
        assert_eq!(l["etc/ssl/certs/ca-certificates.crt"], "file 644 \"\"");
        assert_eq!(l["etc"], "dir 555", "shown with the image's mode");
        assert_eq!(l["dev/keep"], "file 644 \"k\"", "what is there stays");
        assert!(p.upper.join("etc/resolv.conf").is_file());
        assert!(!p.upper.join("dev/keep").exists(), "a shell, not a copy");
        // Without a network or inspection, nothing is touched there.
        let p = prepared(&with_etc, "/workspace", false, false).unwrap();
        let l = p.merged();
        assert!(!l.contains_key("etc/resolv.conf"));
        assert!(!l.contains_key("etc/ssl/certs/ca-certificates.crt"));
        assert!(!p.upper.join("etc").exists());
        // Present: left as it is, below.
        let present = vec![layer(&[
            dir("etc/", 0o755),
            file("etc/resolv.conf", 0o644, b"nameserver 1.1.1.1\n"),
        ])];
        let p = prepared(&present, "/workspace", true, false).unwrap();
        assert_eq!(
            p.merged()["etc/resolv.conf"],
            "file 644 \"nameserver 1.1.1.1\\n\""
        );
        assert!(!p.upper.join("etc").exists());
    }

    #[test]
    fn resolv_conf_is_followed_as_init_follows_it() {
        // A link into /run: init's tmpfs, nothing made.
        let into_run = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf"),
        ])];
        let p = prepared(&into_run, "/workspace", true, false).unwrap();
        let l = p.merged();
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
        let p = prepared(&elsewhere, "/workspace", true, false).unwrap();
        assert_eq!(p.merged()["var/lib/resolv/resolv.conf"], "file 644 \"\"");
        // A link to a missing directory: nothing made; init fails as today.
        let missing_dir = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "/var/missing/resolv.conf"),
        ])];
        let p = prepared(&missing_dir, "/workspace", true, false).unwrap();
        assert!(!p.merged().contains_key("var"));
        // A loop: left to init.
        let loop_ = vec![layer(&[
            dir("etc/", 0o755),
            symlink("etc/resolv.conf", "/etc/a"),
            symlink("etc/a", "/etc/resolv.conf"),
        ])];
        let p = prepared(&loop_, "/workspace", true, false).unwrap();
        let mut keys: Vec<String> = p.merged().into_keys().collect();
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
        let p = prepared(&under_cwd, "/srv/app", true, false).unwrap();
        let l = p.merged();
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
        let p = prepared(&image(), "/workspace/app", false, false).unwrap();
        assert!(p.workspace.join("app").is_dir());
        assert!(!p.upper.join("workspace").exists());
        // Under /workspace through a link: the same.
        let p = prepared(&image(), "/app/project/x", false, false).unwrap();
        assert!(p.workspace.join("project/x").is_dir());
        assert!(!p.upper.join("app").exists());
        // Elsewhere: in the merge, parents included; a 0o555 parent is
        // shown so, and still takes it (its shell is the host's to write).
        let p = prepared(&image(), "/ro/sub/dir", false, false).unwrap();
        let l = p.merged();
        assert_eq!(l["ro"], "dir 555");
        assert_eq!(l["ro/sub/dir"], "dir 755");
        assert!(p.upper.join("ro/sub/dir").is_dir());
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
        let p = prepared(&image(), "/workspace", false, false).unwrap();
        assert_eq!(fs::read_dir(&p.workspace).unwrap().count(), 0);
        // What the image has beneath /workspace is hidden by the mount: a
        // link there is not followed, and the directory goes where the
        // guest will see it.
        let hidden = vec![layer(&[
            dir("opt/app/", 0o755),
            symlink("workspace/app", "/opt/app"),
        ])];
        let p = prepared(&hidden, "/workspace/app/build", false, false).unwrap();
        assert!(p.workspace.join("app/build").is_dir());
        assert!(!p.upper.join("opt").exists());
        // Leaving the mount through `..` resumes the lookups: the link after
        // it is followed, for the working directory and for the resolver's
        // file alike.
        let leaving = vec![layer(&[
            dir("srv/", 0o755),
            dir("etc/", 0o755),
            symlink("app", "/srv"),
            symlink("dns", "/srv/resolv.conf"),
            symlink("etc/resolv.conf", "/workspace/../dns"),
        ])];
        let p = prepared(&leaving, "/workspace/../app/build", true, false).unwrap();
        let l = p.merged();
        assert_eq!(l["srv/build"], "dir 755");
        assert_eq!(l["srv/resolv.conf"], "file 644 \"\"");
        assert!(!l.contains_key("app/build"));
        assert_eq!(fs::read_dir(&p.workspace).unwrap().count(), 0);
        // Links inside the workspace are the guest's too: followed there,
        // before a `..` decides where the path leaves the share.
        let tmp = tempfile::tempdir().unwrap();
        let lower = tmp.path().join("rootfs");
        let finished = cached(
            &lower,
            &[layer(&[dir("srv/", 0o755), symlink("app", "/srv")])],
        );
        let upper = tmp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(workspace.join("actual/nested")).unwrap();
        std::os::unix::fs::symlink("actual/nested", workspace.join("alias")).unwrap();
        prepare_boot_paths(
            &lower,
            &upper,
            &finished.modes,
            &workspace,
            &BootNeeds {
                cwd: "/workspace/alias/../../app/build",
                net: false,
                inspect: false,
            },
        )
        .unwrap();
        assert!(
            workspace.join("app/build").is_dir(),
            "where the guest arrives"
        );
        assert!(
            !upper.join("srv/build").exists(),
            "not through the image's /app"
        );
        // A link inside the workspace that leads out of it through `..`
        // leaves the share where the link's directory is, not where the
        // host would land.
        prepare_boot_paths(
            &lower,
            &upper,
            &finished.modes,
            &workspace,
            &BootNeeds {
                cwd: "/workspace/alias/../../../app/out",
                net: false,
                inspect: false,
            },
        )
        .unwrap();
        assert!(upper.join("srv/out").is_dir(), "through the image's /app");
        assert!(!tmp.path().join("app").exists(), "never outside the share");
        // The image's /workspace is a link: init mounts the share where it
        // leads, so that is where the working directory goes, whether the
        // path says /workspace or the link's target.
        let linked = || vec![layer(&[dir("srv/", 0o755), symlink("workspace", "srv")])];
        for cwd in ["/workspace/build", "/srv/build"] {
            let p = prepared(&linked(), cwd, true, false).unwrap();
            assert!(p.workspace.join("build").is_dir(), "{cwd}");
            assert!(!p.upper.join("srv").exists(), "{cwd}");
        }
        // A /workspace link to nothing, or to a file: the mount would fail.
        for bad in [
            vec![layer(&[symlink("workspace", "nowhere")])],
            vec![layer(&[file("f", 0o644, b"f"), symlink("workspace", "f")])],
        ] {
            let err = prepared(&bad, "/workspace", false, false).err().unwrap();
            assert!(matches!(err, SessionError::WorkspaceMount), "{err}");
        }
        // A kernel filesystem's mount point that is a link: the filesystem
        // lands where it leads, and that place is made when missing.
        let moved = vec![layer(&[
            dir("var/run/", 0o755),
            symlink("run", "var/run"),
            symlink("dev", "devices"),
        ])];
        for cwd in ["/run/x", "/var/run/x", "/dev/x", "/devices/x"] {
            let err = prepared(&moved, cwd, false, false).err().unwrap();
            assert!(
                matches!(err, SessionError::WorkingDirMounted),
                "{cwd}: {err}"
            );
        }
        let p = prepared(&moved, "/workspace", false, false).unwrap();
        let l = p.merged();
        assert_eq!(l["devices"], "dir 755", "made where /dev leads");
        assert_eq!(l["dev"], "symlink -> devices");
        // A file whited out and its name reused for the working directory:
        // the directory gets no mode of the file's.
        let reused = vec![
            layer(&[file("a", 0o000, b"x")]),
            layer(&[file(".wh.a", 0o644, b"")]),
        ];
        let p = prepared(&reused, "/a", false, false).unwrap();
        assert_eq!(p.merged()["a"], "dir 755");
    }
}
