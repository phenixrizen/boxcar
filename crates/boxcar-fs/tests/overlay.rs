// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The overlay over two passthroughs, driven through the `FileSystem`
//! trait as the FUSE server would: a lower tree and an upper directory in
//! a temp dir, every operation checked against both the guest's view and
//! what the host directories hold.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use boxcar_fs::{passthrough_config, CachePolicyKind, FsShareConfig, OverlayFs};
use fuse_backend_rs::abi::fuse_abi::CreateIn;
use fuse_backend_rs::api::filesystem::{Context, Entry, FileSystem, SetattrValid, ROOT_ID};
use fuse_backend_rs::passthrough::PassthroughFs;
use tempfile::TempDir;

const CTX: Context = Context {
    uid: 0,
    gid: 0,
    pid: 1,
};

type Fs = OverlayFs<PassthroughFs, PassthroughFs>;

struct Over {
    _dir: TempDir,
    lower: PathBuf,
    upper: PathBuf,
    fs: Fs,
}

fn share_config(root: &Path) -> FsShareConfig {
    FsShareConfig {
        tag: "root".into(),
        host_dir: root.to_path_buf(),
        guest_path: "/".into(),
        cache: CachePolicyKind::Always,
        lower: None,
    }
}

fn layer(root: &Path) -> PassthroughFs {
    let fs = PassthroughFs::<()>::new(passthrough_config(&share_config(root))).unwrap();
    fs.import().unwrap();
    fs
}

fn open_dir(path: &Path) -> OwnedFd {
    OwnedFd::from(File::open(path).unwrap())
}

/// A lower tree and an empty upper directory, the overlay over them.
fn overlay(modes: &[(String, u32)]) -> Over {
    let dir = TempDir::new().unwrap();
    let lower = dir.path().join("lower");
    let upper = dir.path().join("upper");
    fs::create_dir(&lower).unwrap();
    fs::create_dir(&upper).unwrap();
    // The lower tree: a, d/x, d/y, gone, shadowed.
    fs::write(lower.join("a"), b"la").unwrap();
    fs::create_dir(lower.join("d")).unwrap();
    fs::write(lower.join("d/x"), b"lx").unwrap();
    fs::write(lower.join("d/y"), b"ly").unwrap();
    fs::write(lower.join("gone"), b"lg").unwrap();
    fs::write(lower.join("shadowed"), b"lower").unwrap();
    let fs = OverlayFs::new(
        layer(&lower),
        open_dir(&lower),
        layer(&upper),
        open_dir(&upper),
        modes,
    );
    Over {
        _dir: dir,
        lower,
        upper,
        fs,
    }
}

/// The upper of [`overlay`] with entries of its own: b, d/.wh.y,
/// .wh.gone, shadowed.
fn overlay_with_upper() -> Over {
    let over = overlay(&[]);
    fs::write(over.upper.join("b"), b"ub").unwrap();
    fs::create_dir(over.upper.join("d")).unwrap();
    fs::write(over.upper.join("d/.wh.y"), b"").unwrap();
    fs::write(over.upper.join(".wh.gone"), b"").unwrap();
    fs::write(over.upper.join("shadowed"), b"upper").unwrap();
    over
}

fn cstr(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn lookup(fs: &Fs, parent: u64, name: &str) -> std::io::Result<Entry> {
    fs.lookup(&CTX, parent, &cstr(name))
}

fn ino(fs: &Fs, parent: u64, name: &str) -> u64 {
    lookup(fs, parent, name).expect(name).inode
}

fn errno(result: std::io::Result<impl std::fmt::Debug>) -> i32 {
    result.unwrap_err().raw_os_error().unwrap()
}

/// The names a directory lists, `.` and `..` left out, sorted.
fn names(fs: &Fs, dir: u64) -> Vec<String> {
    let (handle, _) = fs.opendir(&CTX, dir, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let mut out = Vec::new();
    fs.readdir(&CTX, dir, handle, 4096, 0, &mut |entry| {
        let name = String::from_utf8(entry.name.to_vec()).unwrap();
        if name != "." && name != ".." {
            out.push(name);
        }
        Ok(1)
    })
    .unwrap();
    fs.releasedir(&CTX, dir, 0, handle).unwrap();
    out.sort();
    out
}

fn read_all(fs: &Fs, ino: u64) -> Vec<u8> {
    let (handle, _, _) = fs.open(&CTX, ino, libc::O_RDONLY as u32, 0).unwrap();
    let handle = handle.unwrap();
    let mut sink = tempfile::tempfile().unwrap();
    let mut offset = 0;
    loop {
        let n = fs
            .read(&CTX, ino, handle, &mut sink, 4096, offset, None, 0)
            .unwrap();
        if n == 0 {
            break;
        }
        offset += n as u64;
    }
    fs.release(&CTX, ino, libc::O_RDONLY as u32, handle, false, false, None)
        .unwrap();
    sink.seek(SeekFrom::Start(0)).unwrap();
    let mut out = Vec::new();
    sink.read_to_end(&mut out).unwrap();
    out
}

fn payload(data: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(data).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

/// Writes `data` at `offset` through an open-for-writing of the file.
fn write_at(fs: &Fs, ino: u64, data: &[u8], offset: u64) {
    let flags = libc::O_RDWR as u32;
    let (handle, _, _) = fs.open(&CTX, ino, flags, 0).unwrap();
    let handle = handle.unwrap();
    let n = fs
        .write(
            &CTX,
            ino,
            handle,
            &mut payload(data),
            data.len() as u32,
            offset,
            None,
            false,
            flags,
            0,
        )
        .unwrap();
    assert_eq!(n, data.len());
    fs.release(&CTX, ino, flags, handle, false, false, None)
        .unwrap();
}

fn create(fs: &Fs, parent: u64, name: &str) -> std::io::Result<Entry> {
    let args = CreateIn {
        flags: (libc::O_WRONLY | libc::O_CREAT) as u32,
        mode: libc::S_IFREG | 0o644,
        umask: 0,
        fuse_flags: 0,
    };
    let (entry, handle, _, _) = fs.create(&CTX, parent, &cstr(name), args)?;
    fs.release(
        &CTX,
        entry.inode,
        args.flags,
        handle.unwrap(),
        false,
        false,
        None,
    )?;
    Ok(entry)
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = cstr(name);
    // SAFETY: setxattr reads the two C strings and `value.len()` bytes.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr: {}", std::io::Error::last_os_error());
}

fn get_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = cstr(name);
    let mut buf = [0u8; 256];
    // SAFETY: getxattr writes at most `buf.len()` bytes.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    usize::try_from(n).ok().map(|n| buf[..n].to_vec())
}

#[test]
fn the_merge_shows_both_layers_the_upper_first_and_what_whiteouts_hide_not_at_all() {
    let over = overlay_with_upper();
    let fs = &over.fs;
    assert_eq!(names(fs, ROOT_ID), ["a", "b", "d", "shadowed"]);
    let d = ino(fs, ROOT_ID, "d");
    assert_eq!(names(fs, d), ["x"]);
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "a")), b"la");
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "b")), b"ub");
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "shadowed")), b"upper");
    assert_eq!(read_all(fs, ino(fs, d, "x")), b"lx");
    assert_eq!(errno(lookup(fs, ROOT_ID, "gone")), libc::ENOENT);
    assert_eq!(errno(lookup(fs, d, "y")), libc::ENOENT);
    // The overlay's own names are nobody's.
    assert_eq!(errno(lookup(fs, ROOT_ID, ".wh.gone")), libc::ENOENT);
    assert_eq!(errno(create(fs, ROOT_ID, ".wh.z")), libc::EPERM);
    assert_eq!(
        errno(fs.mkdir(&CTX, ROOT_ID, &cstr(".wh.z"), 0o755, 0)),
        libc::EPERM
    );
    // A lookup is counted, and a forgotten entry can be looked up again.
    let a = ino(fs, ROOT_ID, "a");
    assert_eq!(ino(fs, ROOT_ID, "a"), a);
    fs.forget(&CTX, a, 2);
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "a")), b"la");
}

#[test]
fn an_opaque_directory_shows_nothing_below_it() {
    let over = overlay(&[]);
    fs::create_dir(over.upper.join("d")).unwrap();
    fs::write(over.upper.join("d/.wh..wh..opq"), b"").unwrap();
    fs::write(over.upper.join("d/z"), b"uz").unwrap();
    let fs = &over.fs;
    let d = ino(fs, ROOT_ID, "d");
    assert_eq!(names(fs, d), ["z"]);
    assert_eq!(errno(lookup(fs, d, "x")), libc::ENOENT);
}

#[test]
fn a_write_copies_the_file_up_with_its_xattrs_mode_and_times() {
    let over = overlay(&[]);
    let lower_a = over.lower.join("a");
    fs::set_permissions(&lower_a, fs::Permissions::from_mode(0o640)).unwrap();
    set_xattr(&lower_a, "user.boxcar.stat", b"uid=7 gid=7");
    let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    File::open(&lower_a)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(then))
        .unwrap();
    let fs = &over.fs;
    let a = ino(fs, ROOT_ID, "a");
    // Reading copies nothing.
    assert_eq!(read_all(fs, a), b"la");
    assert!(!over.upper.join("a").exists());
    // An attribute change copies the file up as it is.
    fs.setxattr(&CTX, a, &cstr("user.note"), b"n", 0).unwrap();
    let upper_a = over.upper.join("a");
    assert_eq!(fs::read(&upper_a).unwrap(), b"la");
    assert_eq!(fs::metadata(&upper_a).unwrap().mode() & 0o7777, 0o640);
    assert_eq!(
        get_xattr(&upper_a, "user.boxcar.stat").as_deref(),
        Some(&b"uid=7 gid=7"[..])
    );
    assert_eq!(get_xattr(&upper_a, "user.note").as_deref(), Some(&b"n"[..]));
    assert_eq!(fs::metadata(&upper_a).unwrap().modified().unwrap(), then);
    // A write goes to the copy; the lower file is untouched.
    write_at(fs, a, b"LA", 0);
    assert_eq!(read_all(fs, a), b"LA");
    assert_eq!(fs::read(&upper_a).unwrap(), b"LA");
    assert_eq!(fs::read(&lower_a).unwrap(), b"la");
    // A file deeper down takes its parents up as shells.
    let d = ino(fs, ROOT_ID, "d");
    let x = ino(fs, d, "x");
    write_at(fs, x, b"LX", 0);
    assert_eq!(fs::read(over.upper.join("d/x")).unwrap(), b"LX");
    assert!(!over.upper.join("d/y").exists(), "a shell, not a copy");
    assert_eq!(names(fs, d), ["x", "y"], "the shell still merges");
    assert_eq!(read_all(fs, ino(fs, d, "y")), b"ly");
    // Truncation through setattr copies up too.
    let y = ino(fs, d, "y");
    let mut attr = fs.getattr(&CTX, y, None).unwrap().0;
    attr.st_size = 1;
    fs.setattr(&CTX, y, attr, None, SetattrValid::SIZE).unwrap();
    assert_eq!(fs::read(over.upper.join("d/y")).unwrap(), b"l");
    assert_eq!(read_all(fs, y), b"l");
}

#[test]
fn what_is_made_and_removed_lands_above_with_whiteouts_where_the_lower_layer_shows() {
    let over = overlay(&[]);
    let fs = &over.fs;
    // Made above.
    let n = create(fs, ROOT_ID, "n").unwrap();
    assert!(over.upper.join("n").is_file());
    assert!(!over.lower.join("n").exists());
    write_at(fs, n.inode, b"new", 0);
    assert_eq!(fs::read(over.upper.join("n")).unwrap(), b"new");
    // A lower file removed: a whiteout, the lower file untouched.
    fs.unlink(&CTX, ROOT_ID, &cstr("a")).unwrap();
    assert!(over.upper.join(".wh.a").exists());
    assert!(over.lower.join("a").exists());
    assert_eq!(errno(lookup(fs, ROOT_ID, "a")), libc::ENOENT);
    assert_eq!(names(fs, ROOT_ID), ["d", "gone", "n", "shadowed"]);
    // Made again over the whiteout: the whiteout goes.
    create(fs, ROOT_ID, "a").unwrap();
    assert!(!over.upper.join(".wh.a").exists());
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "a")), b"");
    // An upper-only file removed: no whiteout needed.
    fs.unlink(&CTX, ROOT_ID, &cstr("n")).unwrap();
    assert!(!over.upper.join("n").exists());
    assert!(!over.upper.join(".wh.n").exists());
    // Directories: made above, removed only when empty in the merge.
    fs.mkdir(&CTX, ROOT_ID, &cstr("e"), 0o755, 0).unwrap();
    assert!(over.upper.join("e").is_dir());
    fs.rmdir(&CTX, ROOT_ID, &cstr("e")).unwrap();
    assert!(!over.upper.join("e").exists());
    assert_eq!(errno(fs.rmdir(&CTX, ROOT_ID, &cstr("d"))), libc::ENOTEMPTY);
    let d = ino(fs, ROOT_ID, "d");
    fs.unlink(&CTX, d, &cstr("x")).unwrap();
    fs.unlink(&CTX, d, &cstr("y")).unwrap();
    assert_eq!(names(fs, d), Vec::<String>::new());
    fs.rmdir(&CTX, ROOT_ID, &cstr("d")).unwrap();
    assert!(over.upper.join(".wh.d").exists());
    assert!(!over.upper.join("d").exists(), "its whiteouts went with it");
    assert_eq!(errno(lookup(fs, ROOT_ID, "d")), libc::ENOENT);
    assert!(over.lower.join("d/x").exists());
    // A directory made over a whited-out lower one hides it.
    fs.mkdir(&CTX, ROOT_ID, &cstr("d"), 0o755, 0).unwrap();
    assert!(over.upper.join("d/.wh..wh..opq").exists());
    let d = ino(fs, ROOT_ID, "d");
    assert_eq!(names(fs, d), Vec::<String>::new());
    assert_eq!(errno(lookup(fs, d, "x")), libc::ENOENT);
    // Something already in the merge cannot be made again.
    assert_eq!(errno(create(fs, ROOT_ID, "gone")), libc::EEXIST);
    assert_eq!(
        errno(fs.mkdir(&CTX, ROOT_ID, &cstr("shadowed"), 0o755, 0)),
        libc::EEXIST
    );
}

#[test]
fn renames_stay_above_and_never_answer_exdev() {
    let over = overlay_with_upper();
    let fs = &over.fs;
    // A lower file: copied up, the old name whited out.
    fs.rename(&CTX, ROOT_ID, &cstr("a"), ROOT_ID, &cstr("a2"), 0)
        .unwrap();
    assert_eq!(fs::read(over.upper.join("a2")).unwrap(), b"la");
    assert!(over.upper.join(".wh.a").exists());
    assert_eq!(errno(lookup(fs, ROOT_ID, "a")), libc::ENOENT);
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "a2")), b"la");
    assert!(over.lower.join("a").exists());
    // A lower directory: its subtree copied up (less what is whited out),
    // marked opaque, the old name whited out.
    let d = ino(fs, ROOT_ID, "d");
    let x = ino(fs, d, "x");
    fs.rename(&CTX, ROOT_ID, &cstr("d"), ROOT_ID, &cstr("d2"), 0)
        .unwrap();
    assert_eq!(fs::read(over.upper.join("d2/x")).unwrap(), b"lx");
    assert!(!over.upper.join("d2/y").exists(), "y was whited out");
    assert!(over.upper.join("d2/.wh..wh..opq").exists());
    assert!(over.upper.join(".wh.d").exists());
    assert_eq!(errno(lookup(fs, ROOT_ID, "d")), libc::ENOENT);
    let d2 = ino(fs, ROOT_ID, "d2");
    assert_eq!(d2, d, "the same node under its new name");
    assert_eq!(names(fs, d2), ["x"]);
    assert_eq!(errno(lookup(fs, d2, "y")), libc::ENOENT);
    assert_eq!(ino(fs, d2, "x"), x);
    write_at(fs, x, b"LX", 0);
    assert_eq!(fs::read(over.upper.join("d2/x")).unwrap(), b"LX");
    assert_eq!(fs::read(over.lower.join("d/x")).unwrap(), b"lx");
    // Over an existing name: replaced; over a lower one: shadowed.
    fs.rename(&CTX, ROOT_ID, &cstr("b"), ROOT_ID, &cstr("shadowed"), 0)
        .unwrap();
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "shadowed")), b"ub");
    assert_eq!(errno(lookup(fs, ROOT_ID, "b")), libc::ENOENT);
    fs.rename(&CTX, ROOT_ID, &cstr("a2"), ROOT_ID, &cstr("gone"), 0)
        .unwrap();
    assert_eq!(read_all(fs, ino(fs, ROOT_ID, "gone")), b"la");
    // NOREPLACE holds against the merge; a directory onto a file does not go.
    create(fs, ROOT_ID, "f").unwrap();
    assert_eq!(
        errno(fs.rename(&CTX, ROOT_ID, &cstr("f"), ROOT_ID, &cstr("gone"), 1)),
        libc::EEXIST
    );
    assert_eq!(
        errno(fs.rename(&CTX, ROOT_ID, &cstr("d2"), ROOT_ID, &cstr("gone"), 0)),
        libc::ENOTDIR
    );
    // Into a lower directory: the directory comes up as a shell first.
    let over2 = overlay(&[]);
    let fs2 = &over2.fs;
    let d = ino(fs2, ROOT_ID, "d");
    fs2.rename(&CTX, ROOT_ID, &cstr("a"), d, &cstr("a"), 0)
        .unwrap();
    assert_eq!(fs::read(over2.upper.join("d/a")).unwrap(), b"la");
    assert_eq!(names(fs2, d), ["a", "x", "y"]);
    assert_eq!(names(fs2, ROOT_ID), ["d", "gone", "shadowed"]);
    // Renaming a directory into itself is refused.
    let d = ino(fs2, ROOT_ID, "d");
    assert_eq!(
        errno(fs2.rename(&CTX, ROOT_ID, &cstr("d"), d, &cstr("inner"), 0)),
        libc::EINVAL
    );
}

#[test]
fn a_hard_link_copies_the_file_up_and_links_above() {
    let over = overlay(&[]);
    let fs = &over.fs;
    let a = ino(fs, ROOT_ID, "a");
    let linked = fs.link(&CTX, a, ROOT_ID, &cstr("a-link")).unwrap();
    assert_ne!(linked.inode, 0);
    let upper_a = fs::metadata(over.upper.join("a")).unwrap();
    let upper_link = fs::metadata(over.upper.join("a-link")).unwrap();
    assert_eq!(upper_a.ino(), upper_link.ino());
    assert_eq!(read_all(fs, linked.inode), b"la");
    assert_eq!(names(fs, ROOT_ID), ["a", "a-link", "d", "gone", "shadowed"]);
}

#[test]
fn lower_modes_are_shown_as_the_image_has_them_and_follow_the_copy() {
    let modes = vec![("gone".to_owned(), 0o000), ("d".to_owned(), 0o555)];
    let over = overlay(&modes);
    fs::set_permissions(over.lower.join("gone"), fs::Permissions::from_mode(0o400)).unwrap();
    // As the cache stores a 0o555 directory: readable, whatever the umask.
    fs::set_permissions(over.lower.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
    let fs = &over.fs;
    let gone = lookup(fs, ROOT_ID, "gone").unwrap();
    assert_eq!(gone.attr.st_mode & 0o7777, 0o000);
    assert_eq!(
        fs.getattr(&CTX, gone.inode, None).unwrap().0.st_mode & 0o7777,
        0o000
    );
    let d = lookup(fs, ROOT_ID, "d").unwrap();
    assert_eq!(d.attr.st_mode & 0o7777, 0o555);
    // Copied up (a time change is enough), the copy keeps the readable
    // mode on the host and is still shown with the image's.
    let mut attr = fs.getattr(&CTX, gone.inode, None).unwrap().0;
    attr.st_mtime = 1_000_000_000;
    attr.st_mtime_nsec = 0;
    fs.setattr(&CTX, gone.inode, attr, None, SetattrValid::MTIME)
        .unwrap();
    assert_eq!(
        fs::metadata(over.upper.join("gone")).unwrap().mode() & 0o7777,
        0o400
    );
    assert_eq!(
        fs.getattr(&CTX, gone.inode, None).unwrap().0.st_mode & 0o7777,
        0o000
    );
    // A shell keeps its readable mode too, and is shown with the image's.
    let x = ino(fs, d.inode, "x");
    write_at(fs, x, b"X", 0);
    assert_eq!(
        fs::metadata(over.upper.join("d")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs.getattr(&CTX, d.inode, None).unwrap().0.st_mode & 0o7777,
        0o555
    );
    // The guest's own mode wins from then on.
    let mut attr = fs.getattr(&CTX, gone.inode, None).unwrap().0;
    attr.st_mode = (attr.st_mode & libc::S_IFMT) | 0o644;
    let (shown, _) = fs
        .setattr(&CTX, gone.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_eq!(shown.st_mode & 0o7777, 0o644);
    assert_eq!(
        fs.getattr(&CTX, gone.inode, None).unwrap().0.st_mode & 0o7777,
        0o644
    );
    // The modes follow a rename.
    fs.rename(&CTX, ROOT_ID, &cstr("d"), ROOT_ID, &cstr("d2"), 0)
        .unwrap();
    let d2 = ino(fs, ROOT_ID, "d2");
    assert_eq!(
        fs.getattr(&CTX, d2, None).unwrap().0.st_mode & 0o7777,
        0o555
    );
}

#[test]
fn readdirplus_looks_each_entry_up() {
    let over = overlay_with_upper();
    let fs = &over.fs;
    let (handle, _) = fs.opendir(&CTX, ROOT_ID, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let mut seen = Vec::new();
    fs.readdirplus(&CTX, ROOT_ID, handle, 4096, 0, &mut |dir_entry, entry| {
        let name = String::from_utf8(dir_entry.name.to_vec()).unwrap();
        if name != "." && name != ".." {
            assert_ne!(entry.inode, 0, "{name}");
            assert_eq!(entry.attr.st_ino, dir_entry.ino, "{name}");
            seen.push((name, entry.inode));
        }
        Ok(1)
    })
    .unwrap();
    fs.releasedir(&CTX, ROOT_ID, 0, handle).unwrap();
    let mut listed: Vec<&str> = seen.iter().map(|(n, _)| n.as_str()).collect();
    listed.sort_unstable();
    assert_eq!(listed, ["a", "b", "d", "shadowed"]);
    for (name, inode) in &seen {
        assert_eq!(ino(fs, ROOT_ID, name), *inode);
        fs.forget(&CTX, *inode, 2);
    }
}

#[test]
fn a_copy_up_is_reported_with_its_path_and_bytes() {
    use std::sync::{Arc, Mutex};
    let dir = TempDir::new().unwrap();
    let lower = dir.path().join("lower");
    let upper = dir.path().join("upper");
    fs::create_dir(&lower).unwrap();
    fs::create_dir(&upper).unwrap();
    fs::create_dir(lower.join("etc")).unwrap();
    fs::write(lower.join("etc/motd"), b"hello").unwrap();
    type Seen = Arc<Mutex<Vec<(Vec<u8>, u64)>>>;
    let seen: Seen = Arc::default();
    let hook = {
        let seen = Arc::clone(&seen);
        Box::new(move |path: &[u8], bytes: u64| {
            seen.lock().unwrap().push((path.to_vec(), bytes));
        })
    };
    let fs = OverlayFs::new(
        layer(&lower),
        open_dir(&lower),
        layer(&upper),
        open_dir(&upper),
        &[],
    )
    .with_copy_up_hook(hook);
    let etc = ino(&fs, ROOT_ID, "etc");
    let motd = ino(&fs, etc, "motd");
    write_at(&fs, motd, b"H", 0);
    assert_eq!(
        *seen.lock().unwrap(),
        [(b"etc".to_vec(), 0), (b"etc/motd".to_vec(), 5)]
    );
}
