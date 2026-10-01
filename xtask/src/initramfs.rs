// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask initramfs`: build the guest init and pack the initramfs.
//!
//! The initramfs is a newc cpio archive with the static `boxcar-init` as
//! `/init`, empty mount points and the two device nodes init needs before
//! anything is mounted. It is reproducible: fixed entry order, sequential
//! inode numbers, mtime 0, root ownership, so the same init binary always
//! packs to the same bytes.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use cpio::newc::{self, Builder};

/// The target triple of the guest init.
const TARGET: &str = "x86_64-unknown-linux-musl";

/// `S_IFDIR`, `S_IFREG` and `S_IFCHR`: the file type bits of a cpio mode.
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFCHR: u32 = 0o020_000;

/// The directories, first in the archive. `dev` precedes the device nodes.
const DIRS: [&str; 5] = ["dev", "proc", "sys", "run", "newroot"];

/// The character devices, last before the trailer: (name, permissions, major,
/// minor).
const DEVICES: [(&str, u32, u32, u32); 2] =
    [("dev/console", 0o600, 5, 1), ("dev/null", 0o666, 1, 3)];

/// Builds the guest init and writes `target/guest/initramfs.cpio`.
pub fn run() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;

    let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    build.args(build_init_args()).current_dir(root);
    let status = build.status().context("failed to start cargo build")?;
    ensure!(
        status.success(),
        "cargo build of boxcar-init failed: {status}"
    );

    let init_path = root.join("target").join(TARGET).join("guest/boxcar-init");
    let init = fs::read(&init_path).with_context(|| format!("read {}", init_path.display()))?;
    ensure!(
        u32::try_from(init.len()).is_ok(),
        "{} is larger than a cpio entry can hold",
        init_path.display()
    );

    let archive = build_initramfs(&init);
    let out_dir = root.join("target/guest");
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let out_path = out_dir.join("initramfs.cpio");
    fs::write(&out_path, &archive).with_context(|| format!("write {}", out_path.display()))?;

    println!(
        "initramfs: {} bytes, blake3 {}",
        archive.len(),
        blake3::hash(&archive).to_hex()
    );
    Ok(())
}

/// The arguments after `cargo` that build the static guest init.
fn build_init_args() -> Vec<OsString> {
    [
        "build",
        "-p",
        "boxcar-init",
        "--target",
        TARGET,
        "--profile",
        "guest",
    ]
    .map(OsString::from)
    .to_vec()
}

/// The newc archive for a given init binary.
///
/// Entries, in this order: the directories `dev`, `proc`, `sys`, `run` and
/// `newroot` (mode 0755), `init` (mode 0755, the binary), the character
/// devices `dev/console` (0600, 5:1) and `dev/null` (0666, 1:3), then the
/// `TRAILER!!!` entry. Inode numbers count up from 1; the trailer keeps the
/// cpio crate's 0. Every entry has uid 0, gid 0, mtime 0 and nlink 1, the
/// directories too (the kernel only looks at nlink for regular files).
///
/// # Panics
///
/// If `init_binary` is 4 GiB or larger, which a cpio entry cannot describe;
/// [`run`] checks that first.
pub fn build_initramfs(init_binary: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino = 0;
    let mut entry = |name: &str, mode: u32| {
        ino += 1;
        Builder::new(name).ino(ino).mode(mode).nlink(1)
    };

    for name in DIRS {
        out = append(out, entry(name, S_IFDIR | 0o755), &[]);
    }
    out = append(out, entry("init", S_IFREG | 0o755), init_binary);
    for (name, permissions, major, minor) in DEVICES {
        let device = entry(name, S_IFCHR | permissions)
            .rdev_major(major)
            .rdev_minor(minor);
        out = append(out, device, &[]);
    }
    newc::trailer(out).expect("writing to a Vec cannot fail")
}

/// Appends one entry with `data` as its content to `out`.
fn append(out: Vec<u8>, entry: Builder, data: &[u8]) -> Vec<u8> {
    let size = u32::try_from(data.len()).expect("entry data is smaller than 4 GiB");
    let mut writer = entry.write(out, size);
    writer
        .write_all(data)
        .expect("writing to a Vec cannot fail");
    writer.finish().expect("writing to a Vec cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Not a multiple of 4 bytes, so the archive has to pad the file data.
    const STUB: &[u8] = b"\x7fELF-stub";

    /// One archive entry as `cpio::newc::Reader` reads it back.
    #[derive(Debug, PartialEq)]
    struct Parsed {
        name: String,
        mode: u32,
        ino: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        mtime: u32,
        rdev: (u32, u32),
        data: Vec<u8>,
    }

    /// Every entry before the trailer, in archive order.
    fn parse(archive: &[u8]) -> Vec<Parsed> {
        let mut rest = archive;
        let mut out = Vec::new();
        loop {
            let mut reader = cpio::newc::Reader::new(rest).unwrap();
            let entry = reader.entry();
            if entry.is_trailer() {
                return out;
            }
            let mut parsed = Parsed {
                name: entry.name().to_owned(),
                mode: entry.mode(),
                ino: entry.ino(),
                uid: entry.uid(),
                gid: entry.gid(),
                nlink: entry.nlink(),
                mtime: entry.mtime(),
                rdev: (entry.rdev_major(), entry.rdev_minor()),
                data: Vec::new(),
            };
            reader.read_to_end(&mut parsed.data).unwrap();
            rest = reader.finish().unwrap();
            out.push(parsed);
        }
    }

    #[test]
    fn init_is_built_static_with_the_guest_profile() {
        let args: Vec<_> = build_init_args()
            .into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "build",
                "-p",
                "boxcar-init",
                "--target",
                "x86_64-unknown-linux-musl",
                "--profile",
                "guest"
            ]
        );
    }

    #[test]
    fn archive_starts_with_newc_magic_and_ends_with_the_trailer() {
        let archive = build_initramfs(STUB);
        assert_eq!(&archive[..6], b"070701");
        // The trailer name, its NUL, and the three pad bytes that bring the
        // 110-byte header plus 11 name bytes up to a multiple of 4.
        assert!(
            archive.ends_with(b"TRAILER!!!\0\0\0\0"),
            "no trailer at the end"
        );
        assert_eq!(archive.len() % 4, 0);
    }

    #[test]
    fn entries_come_in_the_fixed_order_with_exact_modes_and_devices() {
        let got: Vec<_> = parse(&build_initramfs(STUB))
            .into_iter()
            .map(|e| (e.name, e.mode, e.ino, e.rdev))
            .collect();
        let expected: Vec<(String, u32, u32, (u32, u32))> = [
            ("dev", 0o040755, 1, (0, 0)),
            ("proc", 0o040755, 2, (0, 0)),
            ("sys", 0o040755, 3, (0, 0)),
            ("run", 0o040755, 4, (0, 0)),
            ("newroot", 0o040755, 5, (0, 0)),
            ("init", 0o100755, 6, (0, 0)),
            ("dev/console", 0o020600, 7, (5, 1)),
            ("dev/null", 0o020666, 8, (1, 3)),
        ]
        .into_iter()
        .map(|(name, mode, ino, rdev)| (name.to_owned(), mode, ino, rdev))
        .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn init_carries_the_binary_and_nothing_else_has_data() {
        for entry in parse(&build_initramfs(STUB)) {
            let want: &[u8] = if entry.name == "init" { STUB } else { b"" };
            assert_eq!(entry.data, want, "{}", entry.name);
        }
    }

    #[test]
    fn every_entry_is_root_owned_at_time_zero_with_one_link() {
        for entry in parse(&build_initramfs(STUB)) {
            assert_eq!(
                (entry.uid, entry.gid, entry.mtime, entry.nlink),
                (0, 0, 0, 1),
                "{}",
                entry.name
            );
        }
    }

    #[test]
    fn same_input_gives_the_same_bytes() {
        assert_eq!(build_initramfs(STUB), build_initramfs(STUB));
    }
}
