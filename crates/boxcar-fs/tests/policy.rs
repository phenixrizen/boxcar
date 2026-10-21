// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The path rules against `AuditFs` over a real `PassthroughFs`: the table
//! of attempts on denied, read-only and refused paths, each refused before
//! it reaches the host with one `fs.denied{reason: "policy"}`, and the same
//! requests allowed with no rules. The share is the workspace, served at
//! `/workspace`, laid out before the boot scan:
//!
//! ```text
//! secrets/key                denied: /workspace/secrets
//! app/.env                   denied: **/.env
//! app/main.rs                writable
//! app/hold/.env              denied; app/hold holds it
//! app/vault/                 the literal prefix of /workspace/app/vault/**
//! app/conf_alias             a hard link of etc/conf, made before the session
//! app/env_alias              a hard link of app/.env, in a writable place
//! alias, .ENV                hard links of app/.env (the second stands for
//!                            a case variant on a case-insensitive host)
//! link_to_secrets -> secrets
//! etc/conf                   not writable
//! tools/nc, tools/nc_hard    [exec] deny **/nc; nc_hard is a hard link
//! tools/ok                   runnable
//! ```
//!
//! `app`, `tmp` and `tools` are writable.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use boxcar_audit::{spawn, verify_session, LogReader, WriterConfig, WriterHandle};
use boxcar_fs::scan::scan;
use boxcar_fs::{
    passthrough_config, AuditFs, AuditFsOptions, CachePolicyKind, FsShareConfig, LiveRules,
    PathRules, PathSpec,
};
use boxcar_proto::{FsDenied, Payload, Record, SessionId};
use fuse_backend_rs::abi::fuse_abi::{stat64, CreateIn};
use fuse_backend_rs::api::filesystem::{Context, Entry, FileSystem, SetattrValid, ROOT_ID};
use fuse_backend_rs::passthrough::PassthroughFs;
use tempfile::TempDir;

const GUEST: Context = Context {
    uid: 1000,
    gid: 1000,
    pid: 42,
};

/// `__FMODE_EXEC`: the kernel sets it in the open flags of an `execve`.
const FMODE_EXEC: u32 = 0x20;

type Fs = AuditFs<PassthroughFs>;

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The rules of these tests.
fn spec() -> PathSpec {
    PathSpec {
        writable: strings(&[
            "/workspace/app/**",
            "/workspace/tmp/**",
            "/workspace/tools/**",
        ]),
        denied: strings(&["/workspace/secrets", "**/.env", "/workspace/app/vault/**"]),
        exec_deny: strings(&["**/nc"]),
    }
}

/// The share's tree, made on the host before the session.
fn lay_out(root: &std::path::Path) {
    fs::create_dir_all(root.join("secrets")).unwrap();
    fs::write(root.join("secrets/key"), "key").unwrap();
    fs::create_dir_all(root.join("app/hold")).unwrap();
    fs::create_dir_all(root.join("app/vault")).unwrap();
    fs::write(root.join("app/.env"), "TOKEN=1").unwrap();
    fs::write(root.join("app/main.rs"), "fn main() {}").unwrap();
    fs::write(root.join("app/hold/.env"), "held").unwrap();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("etc/conf"), "conf").unwrap();
    fs::hard_link(root.join("etc/conf"), root.join("app/conf_alias")).unwrap();
    fs::hard_link(root.join("app/.env"), root.join("app/env_alias")).unwrap();
    fs::hard_link(root.join("app/.env"), root.join("alias")).unwrap();
    fs::hard_link(root.join("app/.env"), root.join(".ENV")).unwrap();
    symlink("secrets", root.join("link_to_secrets")).unwrap();
    fs::create_dir_all(root.join("tools")).unwrap();
    fs::write(root.join("tools/nc"), "#!/bin/sh\n").unwrap();
    fs::hard_link(root.join("tools/nc"), root.join("tools/nc_hard")).unwrap();
    fs::write(root.join("tools/ok"), "#!/bin/sh\n").unwrap();
    fs::create_dir_all(root.join("tmp")).unwrap();
}

/// The workspace share under `rules`, scanned at its boot.
struct Share {
    dir: TempDir,
    root: PathBuf,
    fs: Arc<Fs>,
    writer: WriterHandle,
    rules: LiveRules,
}

impl Share {
    fn new(rules: PathRules) -> Share {
        let dir = TempDir::new().unwrap();
        let log = WriterConfig::new(dir.path().join("data"), SessionId::new());
        let (sink, writer) = spawn(log).expect("start the audit writer");
        let root = dir.path().join("share");
        fs::create_dir(&root).unwrap();
        lay_out(&root);
        let config = FsShareConfig {
            tag: "workspace".into(),
            host_dir: root.clone(),
            guest_path: "/workspace".into(),
            cache: CachePolicyKind::Auto,
            lower: None,
        };
        let inner = PassthroughFs::<()>::new(passthrough_config(&config)).unwrap();
        inner.import().unwrap();
        let fd = OwnedFd::from(File::open(&root).unwrap());
        let live: LiveRules = Arc::new(ArcSwap::from_pointee(rules));
        let denied = Arc::new(scan(&[(root.as_path(), "/workspace")], &live.load()).unwrap());
        let fs = AuditFs::new(inner, &config, fd, sink, AuditFsOptions::default())
            .with_rules(Arc::clone(&live), denied);
        Share {
            dir,
            root,
            fs: Arc::new(fs),
            writer,
            rules: live,
        }
    }

    fn policed() -> Share {
        Share::new(PathRules::new(&spec(), &[], &[]).unwrap())
    }

    fn records(self) -> Vec<Record> {
        self.fs.flush_hashes();
        let session = self.writer.session_dir().to_owned();
        self.writer.close().expect("close the audit writer");
        assert_eq!(
            verify_session(&session)
                .expect("the session verifies")
                .incomplete,
            None
        );
        let records = LogReader::open(&session)
            .unwrap()
            .records()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        drop(self.fs);
        drop(self.dir);
        records
            .into_iter()
            .filter(|r| r.kind != "checkpoint")
            .collect()
    }

    fn denials(self) -> Vec<FsDenied> {
        self.records()
            .iter()
            .filter_map(|r| match Payload::from_record(r).unwrap() {
                Payload::FsDenied(denied) => Some(denied),
                _ => None,
            })
            .collect()
    }
}

fn cstr(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn lookup(fs: &Fs, parent: u64, name: &str) -> io::Result<Entry> {
    fs.lookup(&GUEST, parent, &cstr(name))
}

fn ino(fs: &Fs, parent: u64, name: &str) -> u64 {
    lookup(fs, parent, name)
        .unwrap_or_else(|e| panic!("lookup {name}: {e}"))
        .inode
}

fn open(fs: &Fs, ino: u64, flags: u32) -> io::Result<u64> {
    fs.open(&GUEST, ino, flags, 0)
        .map(|(handle, _, _)| handle.expect("a handle"))
}

fn create(fs: &Fs, parent: u64, name: &str, flags: u32) -> io::Result<Entry> {
    let args = CreateIn {
        flags,
        mode: libc::S_IFREG | 0o644,
        umask: 0o022,
        fuse_flags: 0,
    };
    fs.create(&GUEST, parent, &cstr(name), args)
        .map(|(entry, _, _, _)| entry)
}

fn payload(data: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(data).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

fn write(fs: &Fs, ino: u64, fh: u64, data: &[u8]) -> io::Result<usize> {
    fs.write(
        &GUEST,
        ino,
        fh,
        &mut payload(data),
        data.len() as u32,
        0,
        None,
        false,
        libc::O_WRONLY as u32,
        0,
    )
}

fn zero_stat() -> stat64 {
    // SAFETY: stat64 is plain data; all-zero is a valid value.
    unsafe { std::mem::zeroed() }
}

fn errno<T: std::fmt::Debug>(result: io::Result<T>) -> i32 {
    match result {
        Ok(value) => panic!("allowed: {value:?}"),
        Err(e) => e.raw_os_error().expect("an errno"),
    }
}

/// The inodes `readdirplus` of `dir` hands the kernel, by name.
fn listed(fs: &Fs, dir: u64) -> Vec<(String, u64)> {
    let (handle, _) = fs.opendir(&GUEST, dir, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap_or(0);
    let mut entries = Vec::new();
    fs.readdirplus(&GUEST, dir, handle, 64 * 1024, 0, &mut |dirent, entry| {
        entries.push((
            String::from_utf8_lossy(dirent.name).into_owned(),
            entry.inode,
        ));
        Ok(1)
    })
    .unwrap();
    entries.retain(|(name, _)| name != "." && name != "..");
    entries.sort();
    entries
}

/// One row of the table: what is tried, the op and path its record names
/// (an empty path for an id never handed out), the errno and the glob, and
/// the errno it got.
struct Attempt {
    what: &'static str,
    op: &'static str,
    path: &'static str,
    errno: i32,
    rule: Option<&'static str>,
    got: i32,
}

/// Every attempt in the table is refused with its errno, recorded once as
/// `fs.denied{reason: "policy", rule}`, and changes nothing on the host.
#[test]
fn the_table_of_attempts_is_refused() {
    let share = Share::policed();
    let fs = &share.fs;
    let app = ino(fs, ROOT_ID, "app");
    let etc = ino(fs, ROOT_ID, "etc");
    let tools = ino(fs, ROOT_ID, "tools");
    let main = ino(fs, app, "main.rs");
    let conf = ino(fs, etc, "conf");
    const EACCES: i32 = libc::EACCES;
    const EROFS: i32 = libc::EROFS;
    let rw_create = (libc::O_RDWR | libc::O_CREAT) as u32;
    let mut table: Vec<Attempt> = Vec::new();
    let mut attempt = |what, op, path, (errno, rule): (i32, Option<&'static str>), got| {
        table.push(Attempt {
            what,
            op,
            path,
            errno,
            rule,
            got,
        });
    };

    // Lookups: by a denied name, by an alias made before the session, by a
    // case variant; a symlink into a denied directory is a name of its
    // own, and the guest follows it to a lookup of the real path.
    attempt(
        "a denied directory",
        "lookup",
        "/secrets",
        (EACCES, Some("/workspace/secrets")),
        errno(lookup(fs, ROOT_ID, "secrets")),
    );
    attempt(
        "a denied file",
        "lookup",
        "/app/.env",
        (EACCES, Some("**/.env")),
        errno(lookup(fs, app, ".env")),
    );
    attempt(
        "a hard link of a denied file",
        "lookup",
        "/alias",
        (EACCES, Some("**/.env")),
        errno(lookup(fs, ROOT_ID, "alias")),
    );
    attempt(
        "a case variant of a denied file",
        "lookup",
        "/.ENV",
        (EACCES, Some("**/.env")),
        errno(lookup(fs, ROOT_ID, ".ENV")),
    );
    assert!(lookup(fs, ROOT_ID, "link_to_secrets").is_ok());
    attempt(
        "through a symlink into a denied directory",
        "lookup",
        "/secrets",
        (EACCES, Some("/workspace/secrets")),
        errno(lookup(fs, ROOT_ID, "secrets")),
    );

    // Making a denied path, or one outside writable.
    attempt(
        "create onto a denied name",
        "create",
        "/app/.env",
        (EACCES, Some("**/.env")),
        errno(create(fs, app, ".env", rw_create)),
    );
    attempt(
        "create, truncating, through a hard link of a denied file",
        "create",
        "/app/env_alias",
        (EACCES, Some("**/.env")),
        errno(create(
            fs,
            app,
            "env_alias",
            rw_create | libc::O_TRUNC as u32,
        )),
    );
    attempt(
        "create outside writable",
        "create",
        "/etc/new",
        (EROFS, None),
        errno(create(fs, etc, "new", rw_create)),
    );
    attempt(
        "mkdir onto a denied name",
        "mkdir",
        "/secrets",
        (EACCES, Some("/workspace/secrets")),
        errno(fs.mkdir(&GUEST, ROOT_ID, &cstr("secrets"), 0o755, 0o022)),
    );
    attempt(
        "mkdir outside writable",
        "mkdir",
        "/etc/d",
        (EROFS, None),
        errno(fs.mkdir(&GUEST, etc, &cstr("d"), 0o755, 0o022)),
    );
    let sub = fs
        .mkdir(&GUEST, app, &cstr("sub"), 0o755, 0o022)
        .unwrap()
        .inode;
    attempt(
        "mknod onto a denied name",
        "mknod",
        "/app/sub/.env",
        (EACCES, Some("**/.env")),
        errno(fs.mknod(&GUEST, sub, &cstr(".env"), libc::S_IFIFO | 0o644, 0, 0o022)),
    );
    attempt(
        "symlink onto a denied name",
        "symlink",
        "/app/.env",
        (EACCES, Some("**/.env")),
        errno(fs.symlink(&GUEST, &cstr("main.rs"), app, &cstr(".env"))),
    );
    attempt(
        "link onto a denied name",
        "link",
        "/app/.env",
        (EACCES, Some("**/.env")),
        errno(fs.link(&GUEST, main, app, &cstr(".env"))),
    );
    attempt(
        "link of a read-only file",
        "link",
        "/app/conf2",
        (EROFS, None),
        errno(fs.link(&GUEST, conf, app, &cstr("conf2"))),
    );
    attempt(
        "link outside writable",
        "link",
        "/etc/main",
        (EROFS, None),
        errno(fs.link(&GUEST, main, etc, &cstr("main"))),
    );

    // Renames onto, out of, and of what holds denied entries.
    attempt(
        "rename onto a denied name",
        "rename",
        "/app/main.rs",
        (EACCES, Some("**/.env")),
        errno(fs.rename(&GUEST, app, &cstr("main.rs"), app, &cstr(".env"), 0)),
    );
    attempt(
        "rename out of a denied name",
        "rename",
        "/app/.env",
        (EACCES, Some("**/.env")),
        errno(fs.rename(&GUEST, app, &cstr(".env"), app, &cstr("plain"), 0)),
    );
    attempt(
        "rename of a denied directory",
        "rename",
        "/secrets",
        (EACCES, Some("/workspace/secrets")),
        errno(fs.rename(&GUEST, ROOT_ID, &cstr("secrets"), ROOT_ID, &cstr("open"), 0)),
    );
    attempt(
        "rename of a directory holding denied entries",
        "rename",
        "/app/hold",
        (EACCES, Some("**/.env")),
        errno(fs.rename(&GUEST, app, &cstr("hold"), app, &cstr("open"), 0)),
    );
    attempt(
        "rename of a denied glob's literal prefix",
        "rename",
        "/app/vault",
        (EACCES, Some("/workspace/app/vault/**")),
        errno(fs.rename(&GUEST, app, &cstr("vault"), app, &cstr("open"), 0)),
    );
    attempt(
        "exchange with a denied name",
        "rename",
        "/app/main.rs",
        (EACCES, Some("**/.env")),
        errno(fs.rename(
            &GUEST,
            app,
            &cstr("main.rs"),
            app,
            &cstr(".env"),
            libc::RENAME_EXCHANGE,
        )),
    );
    attempt(
        "rename outside writable",
        "rename",
        "/etc/conf",
        (EROFS, None),
        errno(fs.rename(&GUEST, etc, &cstr("conf"), app, &cstr("conf"), 0)),
    );

    // Removing.
    attempt(
        "unlink of a denied file",
        "unlink",
        "/app/.env",
        (EACCES, Some("**/.env")),
        errno(fs.unlink(&GUEST, app, &cstr(".env"))),
    );
    attempt(
        "unlink of a hard link of a denied file",
        "unlink",
        "/app/env_alias",
        (EACCES, Some("**/.env")),
        errno(fs.unlink(&GUEST, app, &cstr("env_alias"))),
    );
    attempt(
        "unlink outside writable",
        "unlink",
        "/etc/conf",
        (EROFS, None),
        errno(fs.unlink(&GUEST, etc, &cstr("conf"))),
    );
    attempt(
        "rmdir of a denied directory",
        "rmdir",
        "/secrets",
        (EACCES, Some("/workspace/secrets")),
        errno(fs.rmdir(&GUEST, ROOT_ID, &cstr("secrets"))),
    );

    // Changing a read-only file: by write, truncation, attributes, space,
    // xattrs.
    attempt(
        "open for writing outside writable",
        "open",
        "/etc/conf",
        (EROFS, None),
        errno(open(fs, conf, libc::O_WRONLY as u32)),
    );
    attempt(
        "open with O_TRUNC outside writable",
        "open",
        "/etc/conf",
        (EROFS, None),
        errno(open(fs, conf, (libc::O_RDONLY | libc::O_TRUNC) as u32)),
    );
    attempt(
        "setattr outside writable",
        "setattr",
        "/etc/conf",
        (EROFS, None),
        {
            let mut attr = zero_stat();
            attr.st_size = 0;
            errno(fs.setattr(&GUEST, conf, attr, None, SetattrValid::SIZE))
        },
    );
    attempt(
        "fallocate outside writable",
        "fallocate",
        "/etc/conf",
        (EROFS, None),
        {
            let fh = open(fs, conf, libc::O_RDONLY as u32).unwrap();
            errno(fs.fallocate(&GUEST, conf, fh, 0, 0, 4096))
        },
    );
    attempt(
        "setxattr outside writable",
        "setxattr",
        "/etc/conf",
        (EROFS, None),
        errno(fs.setxattr(&GUEST, conf, &cstr("user.x"), b"1", 0)),
    );
    attempt(
        "removexattr outside writable",
        "removexattr",
        "/etc/conf",
        (EROFS, None),
        errno(fs.removexattr(&GUEST, conf, &cstr("user.x"))),
    );
    // A hard link of a read-only file in a writable place, made before the
    // session: once both names are known, it is read-only by either.
    let conf_alias = ino(fs, app, "conf_alias");
    assert_eq!(conf_alias, conf, "one inode");
    attempt(
        "writing a read-only file through its hard link",
        "open",
        "/etc/conf",
        (EROFS, None),
        errno(open(fs, conf_alias, libc::O_WRONLY as u32)),
    );
    // The share's directories themselves are not what their `/**` globs
    // name.
    let tmp = ino(fs, ROOT_ID, "tmp");
    attempt(
        "setattr of /workspace/tmp itself",
        "setattr",
        "/tmp",
        (EROFS, None),
        {
            let mut attr = zero_stat();
            attr.st_mode = 0o700;
            errno(fs.setattr(&GUEST, tmp, attr, None, SetattrValid::MODE))
        },
    );

    // A refused program: by a hard link the scan found, before its own
    // name is known; by its name; read for a loader or a copy; renamed;
    // linked.
    let nc_hard = ino(fs, tools, "nc_hard");
    attempt(
        "exec through a hard link the scan found",
        "exec",
        "/tools/nc_hard",
        (EACCES, Some("**/nc")),
        errno(open(fs, nc_hard, libc::O_RDONLY as u32 | FMODE_EXEC)),
    );
    let nc = ino(fs, tools, "nc");
    assert_eq!(nc, nc_hard, "one inode");
    attempt(
        "exec of a refused program",
        "exec",
        "/tools/nc_hard",
        (EACCES, Some("**/nc")),
        errno(open(fs, nc, libc::O_RDONLY as u32 | FMODE_EXEC)),
    );
    attempt(
        "a read of it, for a loader or a copy",
        "open",
        "/tools/nc_hard",
        (EACCES, Some("**/nc")),
        errno(open(fs, nc, libc::O_RDONLY as u32)),
    );
    attempt(
        "a rename of it",
        "rename",
        "/tools/nc",
        (EACCES, Some("**/nc")),
        errno(fs.rename(&GUEST, tools, &cstr("nc"), tools, &cstr("x"), 0)),
    );
    attempt(
        "a link of it",
        "link",
        "/tools/y",
        (EACCES, Some("**/nc")),
        errno(fs.link(&GUEST, nc, tools, &cstr("y"))),
    );

    // The node-id gate: an id the kernel was never handed.
    let unknown = fs.known_inodes().into_iter().max().unwrap() + 1000;
    attempt(
        "getattr of an id never handed out",
        "getattr",
        "",
        (EACCES, None),
        errno(fs.getattr(&GUEST, unknown, None)),
    );
    attempt(
        "opendir of an id never handed out",
        "opendir",
        "",
        (EACCES, None),
        errno(fs.opendir(&GUEST, unknown, libc::O_RDONLY as u32)),
    );
    attempt(
        "readlink of an id never handed out",
        "readlink",
        "",
        (EACCES, None),
        errno(fs.readlink(&GUEST, unknown)),
    );
    attempt(
        "getxattr of an id never handed out",
        "getxattr",
        "",
        (EACCES, None),
        errno(fs.getxattr(&GUEST, unknown, &cstr("user.x"), 0).map(|_| ())),
    );
    attempt(
        "open of an id never handed out",
        "open",
        "",
        (EACCES, None),
        errno(open(fs, unknown, libc::O_RDONLY as u32)),
    );

    // What is allowed stays allowed: reading, the program next door,
    // writing where writable, a symlink pointing into the denied
    // directory.
    let ok = ino(fs, tools, "ok");
    assert!(open(fs, ok, libc::O_RDONLY as u32 | FMODE_EXEC).is_ok());
    assert!(open(fs, conf, libc::O_RDONLY as u32).is_ok());
    let fh = open(fs, main, libc::O_WRONLY as u32).unwrap();
    assert_eq!(write(fs, main, fh, b"fn main() { }").unwrap(), 13);
    assert!(fs
        .symlink(&GUEST, &cstr("../secrets"), app, &cstr("s"))
        .is_ok());
    assert!(create(fs, app, "new.rs", rw_create).is_ok());

    // Nothing reached the host.
    let root = share.root.clone();
    assert_eq!(
        fs::read_to_string(root.join("app/.env")).unwrap(),
        "TOKEN=1"
    );
    assert_eq!(fs::read_to_string(root.join("etc/conf")).unwrap(), "conf");
    for present in [
        "secrets/key",
        "app/hold/.env",
        "app/env_alias",
        "app/vault",
        "tools/nc",
    ] {
        assert!(root.join(present).exists(), "{present}");
    }
    for absent in [
        "etc/new",
        "etc/d",
        "app/sub/.env",
        "app/conf2",
        "etc/main",
        "app/plain",
        "open",
        "app/open",
        "app/conf",
        "tools/x",
        "tools/y",
    ] {
        assert!(!root.join(absent).exists(), "{absent}");
    }

    for row in &table {
        assert_eq!(row.got, row.errno, "{}", row.what);
    }
    let denials = share.denials();
    let got: Vec<(String, String, i32, Option<String>)> = denials
        .iter()
        .map(|d| (d.op.clone(), d.path.clone(), d.errno, d.rule.clone()))
        .collect();
    // An id never handed out has no path: its record names it `<ino:N>`.
    let want: Vec<(String, String, i32, Option<String>)> = table
        .iter()
        .map(|row| {
            let path = if row.path.is_empty() {
                format!("<ino:{unknown}>")
            } else {
                row.path.to_owned()
            };
            (
                row.op.to_owned(),
                path,
                row.errno,
                row.rule.map(str::to_owned),
            )
        })
        .collect();
    assert_eq!(got, want);
    assert!(denials
        .iter()
        .all(|d| d.reason.as_deref() == Some("policy") && d.mount == "workspace"));
}

/// `readdirplus` lists a denied entry by name with no inode, whether its
/// name or its identity is denied, and never teaches the path map it.
#[test]
fn readdirplus_withholds_denied_inodes() {
    let share = Share::policed();
    let fs = &share.fs;
    let entries = listed(fs, ROOT_ID);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            ".ENV",
            "alias",
            "app",
            "etc",
            "link_to_secrets",
            "secrets",
            "tmp",
            "tools"
        ]
    );
    for (name, inode) in &entries {
        let withheld = matches!(name.as_str(), ".ENV" | "alias" | "secrets");
        assert_eq!(*inode == 0, withheld, "{name}");
    }
    let app = ino(fs, ROOT_ID, "app");
    let in_app = listed(fs, app);
    for (name, inode) in &in_app {
        let withheld = matches!(name.as_str(), ".env" | "env_alias");
        assert_eq!(*inode == 0, withheld, "{name}");
    }
    // Every inode the kernel was handed is one the map knows.
    let known = fs.known_inodes();
    for (_, inode) in entries.iter().chain(&in_app) {
        if *inode != 0 {
            assert!(known.contains(inode));
        }
    }
    assert!(share.denials().is_empty(), "a listing refuses nothing");
}

/// `..` and `.` are judged by where they lead: back to an allowed
/// directory they are allowed; a share whose root is denied refuses even
/// `.`.
#[test]
fn dots_are_judged_by_where_they_lead() {
    let share = Share::policed();
    let fs = &share.fs;
    let app = ino(fs, ROOT_ID, "app");
    assert_eq!(ino(fs, app, ".."), ROOT_ID);
    assert_eq!(ino(fs, app, "."), app);
    drop(share);

    let denied_root = PathSpec {
        writable: strings(&["/**"]),
        denied: strings(&["/workspace"]),
        exec_deny: Vec::new(),
    };
    let share = Share::new(PathRules::new(&denied_root, &[], &[]).unwrap());
    assert_eq!(errno(lookup(&share.fs, ROOT_ID, "app")), libc::EACCES);
    assert_eq!(errno(lookup(&share.fs, ROOT_ID, ".")), libc::EACCES);
    let denials = share.denials();
    assert_eq!(denials.len(), 2);
    assert!(denials
        .iter()
        .all(|d| d.rule.as_deref() == Some("/workspace")));
}

/// An exec exception lifts `[exec] deny` for what it matches, the scan's
/// identity included; a writable exception lets a handle write, and once
/// it is gone the same handle is refused at its next write.
#[test]
fn exceptions_come_and_go_with_the_rules() {
    let share = Share::policed();
    let fs = &share.fs;
    let tools = ino(fs, ROOT_ID, "tools");
    let etc = ino(fs, ROOT_ID, "etc");
    let nc = ino(fs, tools, "nc");
    let conf = ino(fs, etc, "conf");

    share.rules.store(Arc::new(
        PathRules::new(
            &spec(),
            &strings(&["/workspace/etc/**"]),
            &strings(&["/workspace/tools/*"]),
        )
        .unwrap(),
    ));
    assert!(open(fs, nc, libc::O_RDONLY as u32 | FMODE_EXEC).is_ok());
    let fh = open(fs, conf, libc::O_WRONLY as u32).unwrap();
    assert_eq!(write(fs, conf, fh, b"new!").unwrap(), 4);

    share
        .rules
        .store(Arc::new(PathRules::new(&spec(), &[], &[]).unwrap()));
    assert_eq!(errno(write(fs, conf, fh, b"more")), libc::EROFS);
    assert_eq!(
        errno(open(fs, nc, libc::O_RDONLY as u32 | FMODE_EXEC)),
        libc::EACCES
    );
    assert_eq!(
        fs::read_to_string(share.root.join("etc/conf")).unwrap(),
        "new!"
    );
    let ops: Vec<String> = share.denials().into_iter().map(|d| d.op).collect();
    assert_eq!(ops, ["write", "exec"]);
}

/// With no rules, the same requests are allowed and nothing is refused:
/// nothing is scanned for.
#[test]
fn with_no_rules_nothing_is_refused() {
    let share = Share::new(PathRules::allow_all());
    let fs = &share.fs;
    let app = ino(fs, ROOT_ID, "app");
    let etc = ino(fs, ROOT_ID, "etc");
    let tools = ino(fs, ROOT_ID, "tools");
    assert!(lookup(fs, ROOT_ID, "secrets").is_ok());
    assert!(lookup(fs, ROOT_ID, "alias").is_ok());
    let env = ino(fs, app, ".env");
    let fh = open(fs, env, libc::O_WRONLY as u32).unwrap();
    assert_eq!(write(fs, env, fh, b"x").unwrap(), 1);
    assert!(create(fs, etc, "new", (libc::O_RDWR | libc::O_CREAT) as u32).is_ok());
    let nc = ino(fs, tools, "nc");
    assert!(open(fs, nc, libc::O_RDONLY as u32 | FMODE_EXEC).is_ok());
    assert!(fs
        .rename(&GUEST, app, &cstr("hold"), app, &cstr("open"), 0)
        .is_ok());
    assert!(fs
        .rename(&GUEST, tools, &cstr("nc"), tools, &cstr("x"), 0)
        .is_ok());
    assert!(listed(fs, ROOT_ID).iter().all(|(_, inode)| *inode != 0));
    assert!(fs.getattr(&GUEST, ROOT_ID, None).is_ok());
    assert!(share.denials().is_empty());
}

/// `opendir` passes on only what reads a directory: with `O_TMPFILE` and a
/// write mode it still opens the directory, whose listing reads, and makes
/// no unnamed host file. With rules or without.
#[test]
fn opendir_takes_only_a_directory_reads_flags() {
    for share in [Share::policed(), Share::new(PathRules::allow_all())] {
        let fs = &share.fs;
        let app = ino(fs, ROOT_ID, "app");
        let flags = (libc::O_TMPFILE | libc::O_RDWR) as u32;
        let (handle, _) = fs.opendir(&GUEST, app, flags).unwrap();
        let mut names = 0;
        fs.readdir(&GUEST, app, handle.unwrap_or(0), 64 * 1024, 0, &mut |_| {
            names += 1;
            Ok(1)
        })
        .expect("a directory handle lists");
        assert!(names > 2);
    }
}
