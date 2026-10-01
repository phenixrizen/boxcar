// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The decorator is transparent: one script of calls, covering every method
//! of fuse-backend-rs 0.14.0's `FileSystem` trait, runs against a bare
//! `PassthroughFs` and against `AuditFs<PassthroughFs>` over twin temporary
//! directories, and every step must end the same way on both sides.
//!
//! A step's outcome is `Ok` with a projection of the reply that does not
//! depend on which twin served it (inode and handle numbers, modes, sizes,
//! bytes; never host inode numbers or times), or `Err` with the errno. A
//! method the decorator failed to forward falls back to the trait's default,
//! which is ENOSYS (or an empty reply) on the decorator's side only: that is
//! a mismatch. A method the passthrough does not implement is ENOSYS (ENOTTY
//! for ioctl) on both sides, which matches.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use boxcar_audit::{spawn, verify_session, WriterConfig};
use boxcar_fs::{
    passthrough_config, AuditFs, AuditFsOptions, AuditLevel, CachePolicyKind, FsShareConfig,
};
use boxcar_proto::SessionId;
use fuse_backend_rs::abi::fuse_abi::{stat64, CreateIn};
use fuse_backend_rs::abi::virtio_fs::RemovemappingOne;
use fuse_backend_rs::api::filesystem::{
    Context, Entry, FileLock, FileSystem, FsOptions, GetxattrReply, IoctlData, ListxattrReply,
    SetattrValid, ROOT_ID,
};
use fuse_backend_rs::passthrough::PassthroughFs;
use fuse_backend_rs::transport::FsCacheReqHandler;
use tempfile::TempDir;

/// Every method of `FileSystem` in fuse-backend-rs 0.14.0, in trait order.
/// The script must exercise each; `every_method_is_exercised` checks it.
const METHODS: [&str; 45] = [
    "init",
    "destroy",
    "lookup",
    "forget",
    "batch_forget",
    "getattr",
    "setattr",
    "readlink",
    "symlink",
    "mknod",
    "mkdir",
    "unlink",
    "rmdir",
    "rename",
    "link",
    "open",
    "create",
    "read",
    "write",
    "flush",
    "fsync",
    "fallocate",
    "release",
    "statfs",
    "setxattr",
    "getxattr",
    "listxattr",
    "removexattr",
    "opendir",
    "readdir",
    "readdirplus",
    "fsyncdir",
    "releasedir",
    "setupmapping",
    "removemapping",
    "access",
    "lseek",
    "getlk",
    "setlk",
    "setlkw",
    "ioctl",
    "bmap",
    "poll",
    "notify_reply",
    "id_remap",
];

/// What the guest sends: a guest user, as the decorator sees it.
const GUEST: Context = Context {
    uid: 1000,
    gid: 1000,
    pid: 42,
};

/// What the decorator must pass down for `GUEST`: the same pid, with the
/// credentials squashed to root so the passthrough never switches ids.
const SQUASHED: Context = Context {
    uid: 0,
    gid: 0,
    pid: 42,
};

/// The capabilities offered to `init`: everything except the bits the
/// decorator masks, so both sides get the same input.
fn offered() -> FsOptions {
    FsOptions::all()
        - FsOptions::WRITEBACK_CACHE
        - FsOptions::MAP_ALIGNMENT
        - FsOptions::PERFILE_DAX
}

type Outcome = Result<String, i32>;

/// The steps of one run, each labelled with the method it called first.
#[derive(Default)]
struct Run {
    steps: Vec<(String, Outcome)>,
}

impl Run {
    /// Records `result` under `label`, projected by `show`, and hands the
    /// value back so later steps can use it.
    fn step<T>(
        &mut self,
        label: &str,
        result: io::Result<T>,
        show: impl FnOnce(&T) -> String,
    ) -> Option<T> {
        let outcome = match &result {
            Ok(value) => Ok(show(value)),
            Err(e) => Err(e.raw_os_error().unwrap_or(-1)),
        };
        self.steps.push((label.to_owned(), outcome));
        result.ok()
    }

    /// Records a method that returns nothing.
    fn unit(&mut self, label: &str) {
        self.steps.push((label.to_owned(), Ok(String::new())));
    }
}

fn cstr(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn show_stat(st: &stat64) -> String {
    format!(
        "mode={:o} size={} nlink={}",
        st.st_mode, st.st_size, st.st_nlink
    )
}

fn show_entry(e: &Entry) -> String {
    format!(
        "ino={} gen={} {} flags={} attr_timeout={:?} entry_timeout={:?}",
        e.inode,
        e.generation,
        show_stat(&e.attr),
        e.attr_flags,
        e.attr_timeout,
        e.entry_timeout
    )
}

/// A reader holding `data`, the way the server hands over a write payload.
fn payload(data: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(data).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

fn contents(mut file: File) -> Vec<u8> {
    let mut out = Vec::new();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_to_end(&mut out).unwrap();
    out
}

/// A DAX window that maps nothing. The passthrough opens the file and hands
/// the fd over; accepting it is enough to tell a forwarded call from ENOSYS.
struct NoWindow;

impl FsCacheReqHandler for NoWindow {
    fn map(&mut self, _: u64, _: u64, _: u64, _: u64, _: RawFd) -> io::Result<()> {
        Ok(())
    }

    fn unmap(&mut self, _: Vec<RemovemappingOne>) -> io::Result<()> {
        Ok(())
    }
}

fn lock() -> FileLock {
    FileLock {
        start: 0,
        end: 100,
        lock_type: libc::F_WRLCK as u32,
        pid: 42,
    }
}

/// The share every run starts from. Modes are set explicitly: the process
/// umask is not stable while tests run, because `PassthroughFs::import`
/// clears it for the whole process.
fn populate(root: &Path) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("file"), b"hello").unwrap();
    fs::set_permissions(root.join("file"), fs::Permissions::from_mode(0o644)).unwrap();
}

/// The script: every trait method at least once, with inputs chosen so that
/// most calls succeed and the rest fail for a reason both sides share.
fn exercise<F: FileSystem<Inode = u64, Handle = u64>>(
    fs: &F,
    ctx: &Context,
) -> Vec<(String, Outcome)> {
    let mut run = Run::default();
    let r = &mut run;
    let rw = libc::O_RDWR as u32;

    r.step("init", fs.init(offered()), |o| format!("{:x}", o.bits()));
    let file = r
        .step(
            "lookup file",
            fs.lookup(ctx, ROOT_ID, &cstr("file")),
            show_entry,
        )
        .map_or(0, |e| e.inode);
    r.step(
        "lookup missing",
        fs.lookup(ctx, ROOT_ID, &cstr("missing")),
        show_entry,
    );
    r.step("getattr file", fs.getattr(ctx, file, None), |(st, t)| {
        format!("{} {t:?}", show_stat(st))
    });

    // SAFETY: stat64 is plain data; all-zero is a valid value.
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = libc::S_IFREG | 0o640;
    r.step(
        "setattr file mode",
        fs.setattr(ctx, file, attr, None, SetattrValid::MODE),
        |(st, _)| show_stat(st),
    );
    r.step("readlink file", fs.readlink(ctx, file), |t| {
        format!("{t:?}")
    });
    let link = r
        .step(
            "symlink link",
            fs.symlink(ctx, &cstr("file"), ROOT_ID, &cstr("link")),
            show_entry,
        )
        .map_or(0, |e| e.inode);
    r.step("readlink link", fs.readlink(ctx, link), |t| {
        format!("{t:?}")
    });
    r.step(
        "mknod fifo",
        fs.mknod(ctx, ROOT_ID, &cstr("fifo"), libc::S_IFIFO | 0o644, 0, 0o022),
        show_entry,
    );
    let dir = r
        .step(
            "mkdir dir",
            fs.mkdir(ctx, ROOT_ID, &cstr("dir"), 0o755, 0o022),
            show_entry,
        )
        .map_or(0, |e| e.inode);
    r.step(
        "link dir/hard",
        fs.link(ctx, file, dir, &cstr("hard")),
        show_entry,
    );
    r.step(
        "rename dir/hard to hard2",
        fs.rename(ctx, dir, &cstr("hard"), ROOT_ID, &cstr("hard2"), 0),
        |_| String::new(),
    );
    r.step(
        "unlink hard2",
        fs.unlink(ctx, ROOT_ID, &cstr("hard2")),
        |_| String::new(),
    );
    r.step(
        "unlink missing",
        fs.unlink(ctx, ROOT_ID, &cstr("missing")),
        |_| String::new(),
    );

    let fh = r
        .step("open file", fs.open(ctx, file, rw, 0), |(h, o, p)| {
            format!("{h:?} {:x} {p:?}", o.bits())
        })
        .and_then(|(h, _, _)| h)
        .unwrap_or(0);
    let mut sink = tempfile::tempfile().unwrap();
    let read = fs.read(ctx, file, fh, &mut sink, 64, 0, None, rw);
    r.step("read file", read, |n| {
        format!("{n} {:?}", contents(sink.try_clone().unwrap()))
    });
    let write = fs.write(
        ctx,
        file,
        fh,
        &mut payload(b"HEL"),
        3,
        0,
        None,
        false,
        rw,
        0,
    );
    r.step("write file", write, |n| n.to_string());
    r.step("flush file", fs.flush(ctx, file, fh, 0), |_| String::new());
    r.step("fsync file", fs.fsync(ctx, file, false, fh), |_| {
        String::new()
    });
    r.step(
        "fallocate file",
        fs.fallocate(ctx, file, fh, 0, 0, 4096),
        |_| String::new(),
    );
    r.step(
        "lseek file",
        fs.lseek(ctx, file, fh, 0, libc::SEEK_END as u32),
        |o| o.to_string(),
    );
    r.step("getlk file", fs.getlk(ctx, file, fh, 1, lock(), 0), |l| {
        format!("{} {} {}", l.start, l.end, l.lock_type)
    });
    r.step("setlk file", fs.setlk(ctx, file, fh, 1, lock(), 0), |_| {
        String::new()
    });
    r.step(
        "setlkw file",
        fs.setlkw(ctx, file, fh, 1, lock(), 0),
        |_| String::new(),
    );
    r.step(
        "ioctl file",
        fs.ioctl(ctx, file, fh, 0, 0, IoctlData::default(), 0),
        |d| format!("{} {:?}", d.result, d.data),
    );
    r.step("bmap file", fs.bmap(ctx, file, 0, 512), |b| b.to_string());
    r.step("poll file", fs.poll(ctx, file, fh, fh, 0, 0), |e| {
        e.to_string()
    });
    r.step(
        "setupmapping file",
        fs.setupmapping(ctx, file, fh, 0, 4096, 0, 0, &mut NoWindow),
        |_| String::new(),
    );
    let unmap = vec![RemovemappingOne {
        moffset: 0,
        len: 4096,
    }];
    r.step(
        "removemapping file",
        fs.removemapping(ctx, file, unmap, &mut NoWindow),
        |_| String::new(),
    );
    r.step(
        "release file",
        fs.release(ctx, file, rw, fh, false, false, None),
        |_| String::new(),
    );
    r.step(
        "release file again",
        fs.release(ctx, file, rw, fh, false, false, None),
        |_| String::new(),
    );
    r.step(
        "getattr file after writes",
        fs.getattr(ctx, file, None),
        |(st, _)| show_stat(st),
    );

    let args = CreateIn {
        flags: rw | libc::O_CREAT as u32,
        mode: libc::S_IFREG | 0o644,
        umask: 0o022,
        fuse_flags: 0,
    };
    let created = r.step(
        "create new",
        fs.create(ctx, ROOT_ID, &cstr("new"), args),
        |(e, h, o, p)| format!("{} {h:?} {:x} {p:?}", show_entry(e), o.bits()),
    );
    if let Some((entry, Some(h), _, _)) = created {
        r.step(
            "release new",
            fs.release(ctx, entry.inode, rw, h, false, false, None),
            |_| String::new(),
        );
    }
    let excl = CreateIn {
        flags: args.flags | libc::O_EXCL as u32,
        ..args
    };
    r.step(
        "create new exclusively",
        fs.create(ctx, ROOT_ID, &cstr("new"), excl),
        |_| String::new(),
    );
    r.step("statfs", fs.statfs(ctx, ROOT_ID), |s| {
        format!("{} {}", s.f_bsize, s.f_namemax)
    });

    let name = cstr("user.boxcar");
    r.step(
        "setxattr file",
        fs.setxattr(ctx, file, &name, b"v1", 0),
        |_| String::new(),
    );
    let show_get = |g: &GetxattrReply| match g {
        GetxattrReply::Value(v) => format!("value {v:?}"),
        GetxattrReply::Count(n) => format!("count {n}"),
    };
    r.step("getxattr file", fs.getxattr(ctx, file, &name, 64), show_get);
    r.step(
        "getxattr file size",
        fs.getxattr(ctx, file, &name, 0),
        show_get,
    );
    let show_list = |l: &ListxattrReply| match l {
        ListxattrReply::Names(v) => format!("names {v:?}"),
        ListxattrReply::Count(n) => format!("count {n}"),
    };
    r.step("listxattr file", fs.listxattr(ctx, file, 256), show_list);
    r.step("listxattr file size", fs.listxattr(ctx, file, 0), show_list);
    r.step("removexattr file", fs.removexattr(ctx, file, &name), |_| {
        String::new()
    });
    r.step(
        "removexattr file again",
        fs.removexattr(ctx, file, &name),
        |_| String::new(),
    );

    let dh = r
        .step(
            "opendir root",
            fs.opendir(ctx, ROOT_ID, libc::O_RDONLY as u32),
            |(h, o)| format!("{h:?} {:x}", o.bits()),
        )
        .and_then(|(h, _)| h)
        .unwrap_or(0);
    let mut names = Vec::new();
    let listed = fs.readdir(ctx, ROOT_ID, dh, 4096, 0, &mut |d| {
        names.push((d.name.to_vec(), d.type_));
        Ok(1)
    });
    names.sort();
    r.step("readdir root", listed, |_| format!("{names:?}"));
    let mut plus = Vec::new();
    let listed = fs.readdirplus(ctx, ROOT_ID, dh, 4096, 0, &mut |d, e| {
        plus.push((d.name.to_vec(), d.type_, e.inode));
        Ok(1)
    });
    plus.sort();
    r.step("readdirplus root", listed, |_| format!("{plus:?}"));
    r.step(
        "fsyncdir root",
        fs.fsyncdir(ctx, ROOT_ID, false, dh),
        |_| String::new(),
    );
    r.step(
        "releasedir root",
        fs.releasedir(ctx, ROOT_ID, 0, dh),
        |_| String::new(),
    );

    r.step(
        "access file read",
        fs.access(ctx, file, libc::R_OK as u32),
        |_| String::new(),
    );
    r.step(
        "access file exec",
        fs.access(ctx, file, libc::X_OK as u32),
        |_| String::new(),
    );
    r.step("rmdir dir", fs.rmdir(ctx, ROOT_ID, &cstr("dir")), |_| {
        String::new()
    });
    r.step(
        "rmdir dir again",
        fs.rmdir(ctx, ROOT_ID, &cstr("dir")),
        |_| String::new(),
    );
    r.step(
        "rename exchange new and link",
        fs.rename(
            ctx,
            ROOT_ID,
            &cstr("new"),
            ROOT_ID,
            &cstr("link"),
            libc::RENAME_EXCHANGE,
        ),
        |_| String::new(),
    );
    r.step("readlink new after exchange", fs.readlink(ctx, link), |t| {
        format!("{t:?}")
    });

    fs.forget(ctx, file, u64::MAX);
    r.unit("forget file");
    r.step(
        "getattr file after forget",
        fs.getattr(ctx, file, None),
        |(st, _)| show_stat(st),
    );
    fs.batch_forget(ctx, vec![(link, u64::MAX)]);
    r.unit("batch_forget link");
    r.step(
        "getattr link after batch_forget",
        fs.getattr(ctx, link, None),
        |(st, _)| show_stat(st),
    );

    r.step("notify_reply", fs.notify_reply(), |_| String::new());
    // Neither side may rewrite the context: the passthrough has no mapping,
    // and the decorator keeps the guest's ids for the audit subject.
    let mut remapped = *ctx;
    r.step("id_remap", fs.id_remap(&mut remapped), |_| {
        let same = (remapped.uid, remapped.gid, remapped.pid) == (ctx.uid, ctx.gid, ctx.pid);
        if same { "unchanged" } else { "rewritten" }.to_owned()
    });
    let lookup = r
        .step(
            "lookup new before destroy",
            fs.lookup(ctx, ROOT_ID, &cstr("new")),
            show_entry,
        )
        .map_or(0, |e| e.inode);
    fs.destroy();
    r.unit("destroy");
    r.step(
        "getattr new after destroy",
        fs.getattr(ctx, lookup, None),
        |(st, _)| show_stat(st),
    );
    r.step(
        "getattr root after destroy",
        fs.getattr(ctx, ROOT_ID, None),
        |(st, _)| format!("mode={:o}", st.st_mode),
    );

    run.steps
}

fn share(root: &Path) -> FsShareConfig {
    FsShareConfig {
        tag: "workspace".into(),
        host_dir: root.to_owned(),
        guest_path: "/workspace".into(),
        cache: CachePolicyKind::Auto,
    }
}

fn passthrough(root: &Path) -> PassthroughFs {
    let fs = PassthroughFs::<()>::new(passthrough_config(&share(root))).unwrap();
    fs.import().unwrap();
    fs
}

/// Runs the script on a bare passthrough called with `reference_ctx` and on
/// the decorator called with `audited_ctx`, and returns the reference run
/// and every step whose outcome differs.
fn compare(
    reference_ctx: &Context,
    audited_ctx: &Context,
) -> (Vec<(String, Outcome)>, Vec<String>) {
    let dir = TempDir::new().unwrap();
    let (bare_root, audited_root) = (dir.path().join("bare"), dir.path().join("audited"));
    for root in [&bare_root, &audited_root] {
        fs::create_dir(root).unwrap();
        populate(root);
    }

    let reference = exercise(&passthrough(&bare_root), reference_ctx);

    let (sink, writer) =
        spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let opts = AuditFsOptions {
        level: AuditLevel::Verbose,
        ..AuditFsOptions::default()
    };
    let root_fd = OwnedFd::from(File::open(&audited_root).unwrap());
    let audited = AuditFs::new(
        passthrough(&audited_root),
        &share(&audited_root),
        root_fd,
        sink,
        opts,
    );
    let decorated = exercise(&audited, audited_ctx);
    audited.flush_hashes();
    drop(audited);
    let session = writer.session_dir().to_owned();
    writer.close().unwrap();
    verify_session(&session).expect("the decorator's session verifies");

    assert_eq!(
        reference.len(),
        decorated.len(),
        "both runs took the same steps"
    );
    let mismatches = reference
        .iter()
        .zip(&decorated)
        .filter(|(a, b)| a != b)
        .map(|((label, a), (_, b))| format!("{label}: passthrough {a:?}, decorator {b:?}"))
        .collect();
    (reference, mismatches)
}

fn method_of(label: &str) -> &str {
    label.split(' ').next().unwrap_or(label)
}

/// Both sides get the same context, which needs no squashing.
#[test]
fn the_decorator_matches_the_passthrough_on_every_method() {
    let (_, mismatches) = compare(&SQUASHED, &SQUASHED);
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// A guest user whose ids are not this process's, so that switching to them
/// would need privilege: without the squash the decorator's creates fail.
fn foreign_guest() -> Context {
    // SAFETY: getters with no arguments and no failure modes.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let pick = |own: u32| {
        [1000, 2000, 3000]
            .into_iter()
            .find(|&id| id != own)
            .unwrap_or(1000)
    };
    Context {
        uid: pick(uid),
        gid: pick(gid),
        pid: 42,
    }
}

/// The decorator gets a guest user's context and must behave exactly like
/// the passthrough given the squashed one.
#[test]
fn the_decorator_given_a_guest_user_matches_the_passthrough_given_root() {
    let (_, mismatches) = compare(&SQUASHED, &foreign_guest());
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The script reaches every method of the trait, and the calls that should
/// succeed on the passthrough do, so the comparison is not vacuous.
#[test]
fn every_method_is_exercised() {
    let (reference, _) = compare(&SQUASHED, &SQUASHED);
    for method in METHODS {
        assert!(
            reference
                .iter()
                .any(|(label, _)| method_of(label) == method),
            "the script never calls {method}"
        );
    }
    let outcome = |label: &str| {
        reference
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, o)| o.clone())
            .unwrap_or_else(|| panic!("no step {label}"))
    };
    for label in [
        "init",
        "lookup file",
        "setattr file mode",
        "symlink link",
        "mknod fifo",
        "mkdir dir",
        "link dir/hard",
        "rename dir/hard to hard2",
        "open file",
        "read file",
        "write file",
        "fallocate file",
        "setupmapping file",
        "removemapping file",
        "release file",
        "create new",
        "setxattr file",
        "getxattr file",
        "readdirplus root",
        "rmdir dir",
        "rename exchange new and link",
    ] {
        assert!(outcome(label).is_ok(), "{label}: {:?}", outcome(label));
    }
    assert_eq!(outcome("id_remap"), Ok("unchanged".to_owned()));
    let enosys = Err(libc::ENOSYS);
    for label in [
        "getlk file",
        "setlk file",
        "setlkw file",
        "bmap file",
        "poll file",
        "notify_reply",
    ] {
        assert_eq!(
            outcome(label),
            enosys,
            "{label} is not implemented by the passthrough"
        );
    }
    assert_eq!(outcome("ioctl file"), Err(libc::ENOTTY));
    assert_eq!(outcome("lookup missing"), Err(libc::ENOENT));
    assert_eq!(outcome("getattr file after forget"), Err(libc::EBADF));
    assert_eq!(outcome("getattr new after destroy"), Err(libc::EBADF));
    assert_eq!(
        outcome("read file"),
        Ok(format!("5 {:?}", b"hello".to_vec()))
    );
    let names = outcome("readdir root").unwrap();
    for name in ["file", "fifo", "link", "new"] {
        assert!(
            names.contains(&format!("{:?}", name.as_bytes())),
            "{name} listed: {names}"
        );
    }
}

/// A filesystem that implements every method, succeeds, and remembers each
/// call with the credentials it came with. Through the decorator it shows
/// which methods were forwarded (a method left to the trait default never
/// arrives, or arrives as another: the default `batch_forget` calls
/// `forget`) and that each arrived squashed. This covers the methods the
/// passthrough does not implement, where the comparison above cannot tell a
/// forwarded call from the default.
#[derive(Default)]
struct Probe {
    calls: std::sync::Mutex<Vec<Call>>,
}

/// A method the probe saw, with the `(uid, gid, pid)` it was called with
/// when it takes a context.
type Call = (&'static str, Option<(u32, u32, i32)>);

impl Probe {
    fn saw(&self, method: &'static str, ctx: Option<&Context>) {
        let ids = ctx.map(|c| (c.uid, c.gid, c.pid));
        self.calls.lock().unwrap().push((method, ids));
    }
}

fn probe_entry(inode: u64) -> Entry {
    Entry {
        inode,
        ..Entry::default()
    }
}

fn zero_stat() -> stat64 {
    // SAFETY: stat64 is plain data; all-zero is a valid value.
    unsafe { std::mem::zeroed() }
}

impl FileSystem for Probe {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, _: FsOptions) -> io::Result<FsOptions> {
        self.saw("init", None);
        Ok(FsOptions::empty())
    }
    fn destroy(&self) {
        self.saw("destroy", None);
    }
    fn lookup(&self, ctx: &Context, _: u64, _: &std::ffi::CStr) -> io::Result<Entry> {
        self.saw("lookup", Some(ctx));
        Ok(probe_entry(2))
    }
    fn forget(&self, ctx: &Context, _: u64, _: u64) {
        self.saw("forget", Some(ctx));
    }
    fn batch_forget(&self, ctx: &Context, _: Vec<(u64, u64)>) {
        self.saw("batch_forget", Some(ctx));
    }
    fn getattr(
        &self,
        ctx: &Context,
        _: u64,
        _: Option<u64>,
    ) -> io::Result<(stat64, std::time::Duration)> {
        self.saw("getattr", Some(ctx));
        Ok((zero_stat(), std::time::Duration::ZERO))
    }
    fn setattr(
        &self,
        ctx: &Context,
        _: u64,
        _: stat64,
        _: Option<u64>,
        _: SetattrValid,
    ) -> io::Result<(stat64, std::time::Duration)> {
        self.saw("setattr", Some(ctx));
        Ok((zero_stat(), std::time::Duration::ZERO))
    }
    fn readlink(&self, ctx: &Context, _: u64) -> io::Result<Vec<u8>> {
        self.saw("readlink", Some(ctx));
        Ok(Vec::new())
    }
    fn symlink(
        &self,
        ctx: &Context,
        _: &std::ffi::CStr,
        _: u64,
        _: &std::ffi::CStr,
    ) -> io::Result<Entry> {
        self.saw("symlink", Some(ctx));
        Ok(probe_entry(4))
    }
    fn mknod(
        &self,
        ctx: &Context,
        _: u64,
        _: &std::ffi::CStr,
        _: u32,
        _: u32,
        _: u32,
    ) -> io::Result<Entry> {
        self.saw("mknod", Some(ctx));
        Ok(probe_entry(5))
    }
    fn mkdir(
        &self,
        ctx: &Context,
        _: u64,
        _: &std::ffi::CStr,
        _: u32,
        _: u32,
    ) -> io::Result<Entry> {
        self.saw("mkdir", Some(ctx));
        Ok(probe_entry(6))
    }
    fn unlink(&self, ctx: &Context, _: u64, _: &std::ffi::CStr) -> io::Result<()> {
        self.saw("unlink", Some(ctx));
        Ok(())
    }
    fn rmdir(&self, ctx: &Context, _: u64, _: &std::ffi::CStr) -> io::Result<()> {
        self.saw("rmdir", Some(ctx));
        Ok(())
    }
    fn rename(
        &self,
        ctx: &Context,
        _: u64,
        _: &std::ffi::CStr,
        _: u64,
        _: &std::ffi::CStr,
        _: u32,
    ) -> io::Result<()> {
        self.saw("rename", Some(ctx));
        Ok(())
    }
    fn link(&self, ctx: &Context, _: u64, _: u64, _: &std::ffi::CStr) -> io::Result<Entry> {
        self.saw("link", Some(ctx));
        Ok(probe_entry(2))
    }
    fn open(
        &self,
        ctx: &Context,
        _: u64,
        _: u32,
        _: u32,
    ) -> io::Result<(
        Option<u64>,
        fuse_backend_rs::api::filesystem::OpenOptions,
        Option<u32>,
    )> {
        self.saw("open", Some(ctx));
        Ok((
            Some(1),
            fuse_backend_rs::api::filesystem::OpenOptions::empty(),
            None,
        ))
    }
    fn create(
        &self,
        ctx: &Context,
        _: u64,
        _: &std::ffi::CStr,
        _: CreateIn,
    ) -> io::Result<(
        Entry,
        Option<u64>,
        fuse_backend_rs::api::filesystem::OpenOptions,
        Option<u32>,
    )> {
        self.saw("create", Some(ctx));
        Ok((
            probe_entry(3),
            Some(2),
            fuse_backend_rs::api::filesystem::OpenOptions::empty(),
            None,
        ))
    }
    fn read(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: &mut dyn fuse_backend_rs::api::filesystem::ZeroCopyWriter,
        _: u32,
        _: u64,
        _: Option<u64>,
        _: u32,
    ) -> io::Result<usize> {
        self.saw("read", Some(ctx));
        Ok(0)
    }
    fn write(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: &mut dyn fuse_backend_rs::api::filesystem::ZeroCopyReader,
        _: u32,
        _: u64,
        _: Option<u64>,
        _: bool,
        _: u32,
        _: u32,
    ) -> io::Result<usize> {
        self.saw("write", Some(ctx));
        Ok(0)
    }
    fn flush(&self, ctx: &Context, _: u64, _: u64, _: u64) -> io::Result<()> {
        self.saw("flush", Some(ctx));
        Ok(())
    }
    fn fsync(&self, ctx: &Context, _: u64, _: bool, _: u64) -> io::Result<()> {
        self.saw("fsync", Some(ctx));
        Ok(())
    }
    fn fallocate(&self, ctx: &Context, _: u64, _: u64, _: u32, _: u64, _: u64) -> io::Result<()> {
        self.saw("fallocate", Some(ctx));
        Ok(())
    }
    fn release(
        &self,
        ctx: &Context,
        _: u64,
        _: u32,
        _: u64,
        _: bool,
        _: bool,
        _: Option<u64>,
    ) -> io::Result<()> {
        self.saw("release", Some(ctx));
        Ok(())
    }
    fn statfs(
        &self,
        ctx: &Context,
        _: u64,
    ) -> io::Result<fuse_backend_rs::abi::fuse_abi::statvfs64> {
        self.saw("statfs", Some(ctx));
        // SAFETY: statvfs64 is plain data; all-zero is a valid value.
        Ok(unsafe { std::mem::zeroed() })
    }
    fn setxattr(
        &self,
        ctx: &Context,
        _: u64,
        _: &std::ffi::CStr,
        _: &[u8],
        _: u32,
    ) -> io::Result<()> {
        self.saw("setxattr", Some(ctx));
        Ok(())
    }
    fn getxattr(
        &self,
        ctx: &Context,
        _: u64,
        _: &std::ffi::CStr,
        _: u32,
    ) -> io::Result<GetxattrReply> {
        self.saw("getxattr", Some(ctx));
        Ok(GetxattrReply::Count(0))
    }
    fn listxattr(&self, ctx: &Context, _: u64, _: u32) -> io::Result<ListxattrReply> {
        self.saw("listxattr", Some(ctx));
        Ok(ListxattrReply::Count(0))
    }
    fn removexattr(&self, ctx: &Context, _: u64, _: &std::ffi::CStr) -> io::Result<()> {
        self.saw("removexattr", Some(ctx));
        Ok(())
    }
    fn opendir(
        &self,
        ctx: &Context,
        _: u64,
        _: u32,
    ) -> io::Result<(Option<u64>, fuse_backend_rs::api::filesystem::OpenOptions)> {
        self.saw("opendir", Some(ctx));
        Ok((
            Some(9),
            fuse_backend_rs::api::filesystem::OpenOptions::empty(),
        ))
    }
    fn readdir(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: u32,
        _: u64,
        _: &mut dyn FnMut(fuse_backend_rs::api::filesystem::DirEntry) -> io::Result<usize>,
    ) -> io::Result<()> {
        self.saw("readdir", Some(ctx));
        Ok(())
    }
    fn readdirplus(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: u32,
        _: u64,
        _: &mut dyn FnMut(fuse_backend_rs::api::filesystem::DirEntry, Entry) -> io::Result<usize>,
    ) -> io::Result<()> {
        self.saw("readdirplus", Some(ctx));
        Ok(())
    }
    fn fsyncdir(&self, ctx: &Context, _: u64, _: bool, _: u64) -> io::Result<()> {
        self.saw("fsyncdir", Some(ctx));
        Ok(())
    }
    fn releasedir(&self, ctx: &Context, _: u64, _: u32, _: u64) -> io::Result<()> {
        self.saw("releasedir", Some(ctx));
        Ok(())
    }
    fn setupmapping(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
        _: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        self.saw("setupmapping", Some(ctx));
        Ok(())
    }
    fn removemapping(
        &self,
        ctx: &Context,
        _: u64,
        _: Vec<RemovemappingOne>,
        _: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        self.saw("removemapping", Some(ctx));
        Ok(())
    }
    fn access(&self, ctx: &Context, _: u64, _: u32) -> io::Result<()> {
        self.saw("access", Some(ctx));
        Ok(())
    }
    fn lseek(&self, ctx: &Context, _: u64, _: u64, _: u64, _: u32) -> io::Result<u64> {
        self.saw("lseek", Some(ctx));
        Ok(0)
    }
    fn getlk(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: u64,
        lock: FileLock,
        _: u32,
    ) -> io::Result<FileLock> {
        self.saw("getlk", Some(ctx));
        Ok(lock)
    }
    fn setlk(&self, ctx: &Context, _: u64, _: u64, _: u64, _: FileLock, _: u32) -> io::Result<()> {
        self.saw("setlk", Some(ctx));
        Ok(())
    }
    fn setlkw(&self, ctx: &Context, _: u64, _: u64, _: u64, _: FileLock, _: u32) -> io::Result<()> {
        self.saw("setlkw", Some(ctx));
        Ok(())
    }
    fn ioctl(
        &self,
        ctx: &Context,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
        _: IoctlData,
        _: u32,
    ) -> io::Result<IoctlData<'_>> {
        self.saw("ioctl", Some(ctx));
        Ok(IoctlData::default())
    }
    fn bmap(&self, ctx: &Context, _: u64, _: u64, _: u32) -> io::Result<u64> {
        self.saw("bmap", Some(ctx));
        Ok(0)
    }
    fn poll(&self, ctx: &Context, _: u64, _: u64, _: u64, _: u32, _: u32) -> io::Result<u32> {
        self.saw("poll", Some(ctx));
        Ok(0)
    }
    fn notify_reply(&self) -> io::Result<()> {
        self.saw("notify_reply", None);
        Ok(())
    }
    fn id_remap(&self, ctx: &mut Context) -> io::Result<()> {
        self.saw("id_remap", Some(ctx));
        Ok(())
    }
}

/// Every method, called once through the decorator in trait order, reaches
/// the wrapped filesystem as itself, with the guest's pid and root's ids.
#[test]
fn every_method_reaches_the_wrapped_filesystem_squashed() {
    let dir = TempDir::new().unwrap();
    let (sink, writer) =
        spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let root_fd = OwnedFd::from(File::open(dir.path()).unwrap());
    let fs = AuditFs::new(
        Probe::default(),
        &share(dir.path()),
        root_fd,
        sink,
        AuditFsOptions::default(),
    );
    let ctx = &GUEST;
    let name = cstr("n");
    let rw = libc::O_RDWR as u32;
    let args = CreateIn {
        flags: rw,
        mode: 0o644,
        umask: 0,
        fuse_flags: 0,
    };
    let mut ok = Vec::new();
    ok.push(fs.init(FsOptions::empty()).is_ok());
    fs.destroy();
    ok.push(fs.lookup(ctx, ROOT_ID, &name).is_ok());
    fs.forget(ctx, 2, 1);
    fs.batch_forget(ctx, vec![(2, 1)]);
    ok.push(fs.getattr(ctx, 2, None).is_ok());
    ok.push(
        fs.setattr(ctx, 2, zero_stat(), None, SetattrValid::empty())
            .is_ok(),
    );
    ok.push(fs.readlink(ctx, 2).is_ok());
    ok.push(fs.symlink(ctx, &name, ROOT_ID, &name).is_ok());
    ok.push(fs.mknod(ctx, ROOT_ID, &name, libc::S_IFIFO, 0, 0).is_ok());
    ok.push(fs.mkdir(ctx, ROOT_ID, &name, 0o755, 0).is_ok());
    ok.push(fs.unlink(ctx, ROOT_ID, &name).is_ok());
    ok.push(fs.rmdir(ctx, ROOT_ID, &name).is_ok());
    ok.push(fs.rename(ctx, ROOT_ID, &name, ROOT_ID, &name, 0).is_ok());
    ok.push(fs.link(ctx, 2, ROOT_ID, &name).is_ok());
    ok.push(fs.open(ctx, 2, rw, 0).is_ok());
    ok.push(fs.create(ctx, ROOT_ID, &name, args).is_ok());
    ok.push(
        fs.read(
            ctx,
            2,
            1,
            &mut tempfile::tempfile().unwrap(),
            1,
            0,
            None,
            rw,
        )
        .is_ok(),
    );
    ok.push(
        fs.write(ctx, 2, 1, &mut payload(b"x"), 1, 0, None, false, rw, 0)
            .is_ok(),
    );
    ok.push(fs.flush(ctx, 2, 1, 0).is_ok());
    ok.push(fs.fsync(ctx, 2, false, 1).is_ok());
    ok.push(fs.fallocate(ctx, 2, 1, 0, 0, 1).is_ok());
    ok.push(fs.release(ctx, 2, rw, 1, false, false, None).is_ok());
    ok.push(fs.statfs(ctx, ROOT_ID).is_ok());
    ok.push(fs.setxattr(ctx, 2, &name, b"v", 0).is_ok());
    ok.push(fs.getxattr(ctx, 2, &name, 0).is_ok());
    ok.push(fs.listxattr(ctx, 2, 0).is_ok());
    ok.push(fs.removexattr(ctx, 2, &name).is_ok());
    ok.push(fs.opendir(ctx, ROOT_ID, 0).is_ok());
    ok.push(fs.readdir(ctx, ROOT_ID, 9, 4096, 0, &mut |_| Ok(1)).is_ok());
    ok.push(
        fs.readdirplus(ctx, ROOT_ID, 9, 4096, 0, &mut |_, _| Ok(1))
            .is_ok(),
    );
    ok.push(fs.fsyncdir(ctx, ROOT_ID, false, 9).is_ok());
    ok.push(fs.releasedir(ctx, ROOT_ID, 0, 9).is_ok());
    ok.push(
        fs.setupmapping(ctx, 2, 1, 0, 1, 0, 0, &mut NoWindow)
            .is_ok(),
    );
    ok.push(fs.removemapping(ctx, 2, Vec::new(), &mut NoWindow).is_ok());
    ok.push(fs.access(ctx, 2, 0).is_ok());
    ok.push(fs.lseek(ctx, 2, 1, 0, 0).is_ok());
    ok.push(fs.getlk(ctx, 2, 1, 0, lock(), 0).is_ok());
    ok.push(fs.setlk(ctx, 2, 1, 0, lock(), 0).is_ok());
    ok.push(fs.setlkw(ctx, 2, 1, 0, lock(), 0).is_ok());
    ok.push(fs.ioctl(ctx, 2, 1, 0, 0, IoctlData::default(), 0).is_ok());
    ok.push(fs.bmap(ctx, 2, 0, 512).is_ok());
    ok.push(fs.poll(ctx, 2, 1, 1, 0, 0).is_ok());
    ok.push(fs.notify_reply().is_ok());
    let mut remapped = *ctx;
    ok.push(fs.id_remap(&mut remapped).is_ok());
    assert_eq!(
        (remapped.uid, remapped.gid, remapped.pid),
        (1000, 1000, 42),
        "the guest's ids are kept for the audit"
    );
    assert!(ok.iter().all(|&ok| ok), "every call succeeded: {ok:?}");

    let calls = std::mem::take(&mut *fs.inner().calls.lock().unwrap());
    fs.flush_hashes();
    drop(fs);
    writer.close().unwrap();
    let methods: Vec<&str> = calls.iter().map(|(m, _)| *m).collect();
    assert_eq!(
        methods, METHODS,
        "each method arrived as itself, once, in order"
    );
    for (method, ids) in calls {
        if let Some(ids) = ids {
            assert_eq!(ids, (0, 0, 42), "{method} arrived squashed");
        }
    }
}
