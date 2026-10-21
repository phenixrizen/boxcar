// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Building tar layers for the tests, valid and otherwise, and reading a
//! tree back as something to compare.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use tar::{EntryType, Header};

/// A header for `path` of `kind` with `size` bytes and `mode`, checksummed.
pub fn header(kind: EntryType, path: &str, size: u64, mode: u32) -> Header {
    let mut h = Header::new_gnu();
    h.set_entry_type(kind);
    // The name bytes as given: tar's `set_path` would refuse the absolute
    // and `..` names the tests throw at the unpacker.
    assert!(
        path.len() <= 100,
        "a test path over 100 bytes goes through pax_file"
    );
    h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
    h.set_size(size);
    h.set_mode(mode);
    h.set_cksum();
    h
}

/// `data` padded to a multiple of 512.
pub fn padded(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.resize(data.len().next_multiple_of(512), 0);
    out
}

/// A regular file entry.
pub fn file(path: &str, mode: u32, data: &[u8]) -> Vec<u8> {
    let mut out = header(EntryType::Regular, path, data.len() as u64, mode)
        .as_bytes()
        .to_vec();
    out.extend(padded(data));
    out
}

/// A directory entry.
pub fn dir(path: &str, mode: u32) -> Vec<u8> {
    header(EntryType::Directory, path, 0, mode)
        .as_bytes()
        .to_vec()
}

/// A regular file entry owned by `uid:gid`.
pub fn file_as(path: &str, mode: u32, uid: u32, gid: u32, data: &[u8]) -> Vec<u8> {
    let mut h = header(EntryType::Regular, path, data.len() as u64, mode);
    h.set_uid(u64::from(uid));
    h.set_gid(u64::from(gid));
    h.set_cksum();
    let mut out = h.as_bytes().to_vec();
    out.extend(padded(data));
    out
}

/// A directory entry owned by `uid:gid`.
pub fn dir_as(path: &str, mode: u32, uid: u32, gid: u32) -> Vec<u8> {
    let mut h = header(EntryType::Directory, path, 0, mode);
    h.set_uid(u64::from(uid));
    h.set_gid(u64::from(gid));
    h.set_cksum();
    h.as_bytes().to_vec()
}

/// A device entry of `kind` (`Char` or `Block`) with `major:minor`.
pub fn device(kind: EntryType, path: &str, mode: u32, major: u32, minor: u32) -> Vec<u8> {
    let mut h = header(kind, path, 0, mode);
    h.set_device_major(major).unwrap();
    h.set_device_minor(minor).unwrap();
    h.set_cksum();
    h.as_bytes().to_vec()
}

/// The ownership override's text on `path` (not following a link), if any.
pub fn override_text(path: &Path) -> Option<String> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = std::ffi::CString::new(boxcar_fs::ownership::XATTR).unwrap();
    let mut text = [0u8; 256];
    // SAFETY: lgetxattr writes at most `text.len()` bytes into `text`.
    let len = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            text.as_mut_ptr().cast(),
            text.len(),
        )
    };
    usize::try_from(len)
        .ok()
        .map(|len| String::from_utf8(text[..len].to_vec()).unwrap())
}

/// A symlink entry.
pub fn symlink(path: &str, target: &str) -> Vec<u8> {
    let mut h = header(EntryType::Symlink, path, 0, 0o777);
    h.set_link_name(target).unwrap();
    h.set_cksum();
    h.as_bytes().to_vec()
}

/// A hardlink entry.
pub fn hardlink(path: &str, target: &str) -> Vec<u8> {
    let mut h = header(EntryType::Link, path, 0, 0o644);
    h.set_link_name(target).unwrap();
    h.set_cksum();
    h.as_bytes().to_vec()
}

/// A device or FIFO entry.
pub fn special(kind: EntryType, path: &str) -> Vec<u8> {
    header(kind, path, 0, 0o644).as_bytes().to_vec()
}

/// One PAX record, `len key=value\n` with `len` counting itself.
pub fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body_len = 1 + key.len() + 1 + value.len() + 1;
    let mut len = body_len + 1;
    while len.to_string().len() + body_len != len {
        len += 1;
    }
    let mut out = format!("{len} {key}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// An extension entry of `kind` holding `data`.
pub fn extension(kind: EntryType, data: &[u8]) -> Vec<u8> {
    let mut out = header(kind, "././@PaxHeader", data.len() as u64, 0o644)
        .as_bytes()
        .to_vec();
    out.extend(padded(data));
    out
}

/// A file whose path is given by a PAX record (any length, any bytes).
pub fn pax_file(path: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = extension(EntryType::XHeader, &pax_record("path", path));
    out.extend(file("x", 0o644, data));
    out
}

/// The end-of-archive blocks.
pub fn end() -> Vec<u8> {
    vec![0u8; 1024]
}

/// `entries` concatenated and ended: one layer.
pub fn layer(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = entries.concat();
    out.extend(end());
    out
}

/// What a tree holds, in a form to compare: path → kind, mode and content
/// (bytes of a file, target of a symlink, the inode number of a hardlinked
/// file's group as `ino:` so links to one file compare equal).
pub fn listing(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    walk(root, root, &mut out).unwrap();
    out
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> io::Result<()> {
    let mut names: Vec<_> = fs::read_dir(dir)?.map(|e| e.unwrap().path()).collect();
    names.sort();
    for path in names {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mode = meta.permissions().mode() & 0o7777;
        let ft = meta.file_type();
        let what = if ft.is_dir() {
            walk(root, &path, out)?;
            format!("dir {mode:o}")
        } else if ft.is_symlink() {
            format!("symlink -> {}", fs::read_link(&path)?.to_string_lossy())
        } else if ft.is_file() {
            let mut data = Vec::new();
            fs::File::open(&path)?.read_to_end(&mut data)?;
            let links = if meta.nlink() > 1 {
                format!(" nlink={} ino={}", meta.nlink(), meta.ino())
            } else {
                String::new()
            };
            format!("file {mode:o} {:?}{links}", String::from_utf8_lossy(&data))
        } else {
            "special".to_owned()
        };
        out.insert(rel, what);
    }
    Ok(())
}
