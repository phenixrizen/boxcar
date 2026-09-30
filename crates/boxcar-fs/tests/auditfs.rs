// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `AuditFs` over a real `PassthroughFs` on a temporary directory, driven
//! through the `FileSystem` trait the way the FUSE server drives it. Every
//! assertion is on real records: the audit writer writes a session, the
//! session is verified, and `LogReader` reads it back.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boxcar_audit::{
    spawn, spawn_with_syncer, verify_session, LogReader, Syncer, WriterConfig, WriterHandle,
};
use boxcar_fs::{
    passthrough_config, AuditFs, AuditFsOptions, AuditLevel, CachePolicyKind, FsShareConfig,
};
use boxcar_proto::{
    Attrib, FsClose, FsCreate, FsDenied, FsIo, FsOpen, Hash, HashStatus, OpResult, Payload, Record,
    SessionId, Subject,
};
use fuse_backend_rs::abi::fuse_abi::{
    CreateIn, InHeader, Opcode, OpenIn, OpenOut, OutHeader, WRITE_CACHE,
};
use fuse_backend_rs::api::filesystem::{
    Context, Entry, FileSystem, FsOptions, SetattrValid, ROOT_ID,
};
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::passthrough::PassthroughFs;
use fuse_backend_rs::transport::{Reader, VirtioFsWriter, Writer};
use tempfile::TempDir;
use virtio_bindings::bindings::virtio_ring::VRING_DESC_F_WRITE;
use virtio_queue::desc::{split::Descriptor as SplitDescriptor, RawDescriptor};
use virtio_queue::mock::MockSplitQueue;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// The guest process every request comes from unless a test says otherwise.
const GUEST: Context = Context {
    uid: 1000,
    gid: 1000,
    pid: 42,
};

const GUEST_SUBJECT: Subject = Subject {
    pid: 42,
    uid: 1000,
    gid: 1000,
};

/// The production hashing limit.
const HASH_MAX: u64 = 64 * 1024 * 1024;

/// `__FMODE_EXEC`: the kernel sets it in the open flags of an `execve`.
const FMODE_EXEC: u32 = 0x20;

/// The flags every file in these tests is created and written with.
const RW_CREATE: u32 = (libc::O_RDWR | libc::O_CREAT) as u32;

type Fs = AuditFs<PassthroughFs>;

/// One share served by `AuditFs<PassthroughFs>`, with its own audit session.
struct Share {
    dir: TempDir,
    root: PathBuf,
    fs: Arc<Fs>,
    writer: WriterHandle,
}

/// A disk that refuses every sync.
struct FullDisk;

impl Syncer for FullDisk {
    fn sync(&self, _: &File) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }
}

impl Share {
    fn new(level: AuditLevel, hash_max_bytes: u64) -> Share {
        let dir = TempDir::new().unwrap();
        let log = WriterConfig::new(dir.path().join("data"), SessionId::new());
        let (sink, writer) = spawn(log).expect("start the audit writer");
        Share::with_log(dir, level, hash_max_bytes, sink, writer)
    }

    /// A share whose audit log fails at its first record: every record is
    /// checkpointed, and every sync fails.
    fn failing_log() -> Share {
        let dir = TempDir::new().unwrap();
        let mut log = WriterConfig::new(dir.path().join("data"), SessionId::new());
        log.checkpoint_every = 1;
        let (sink, writer) = spawn_with_syncer(log, FullDisk).expect("start the audit writer");
        Share::with_log(dir, AuditLevel::Normal, HASH_MAX, sink, writer)
    }

    fn with_log(
        dir: TempDir,
        level: AuditLevel,
        hash_max_bytes: u64,
        sink: boxcar_audit::AuditSink,
        writer: WriterHandle,
    ) -> Share {
        let root = dir.path().join("share");
        fs::create_dir(&root).unwrap();
        let config = share_config(&root);
        let inner = PassthroughFs::<()>::new(passthrough_config(&config)).unwrap();
        inner.import().unwrap();
        let opts = AuditFsOptions {
            level,
            hash_max_bytes,
        };
        let fs = AuditFs::new(inner, &config, root_fd(&root), sink, opts);
        Share {
            dir,
            root,
            fs: Arc::new(fs),
            writer,
        }
    }

    fn normal() -> Share {
        Share::new(AuditLevel::Normal, HASH_MAX)
    }

    /// Waits for queued hashes, closes the log, verifies its chain, and
    /// returns every record but the checkpoints, in log order.
    fn records(self) -> Vec<Record> {
        self.fs.flush_hashes();
        let session = self.writer.session_dir().to_owned();
        self.writer.close().expect("close the audit writer");
        verify_session(&session).expect("the session verifies");
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

    /// The typed payloads of [`records`](Self::records), with their subjects.
    fn events(self) -> Vec<(Payload, Option<Subject>)> {
        self.records()
            .iter()
            .map(|r| (Payload::from_record(r).expect("a typed payload"), r.subject))
            .collect()
    }
}

fn share_config(root: &Path) -> FsShareConfig {
    FsShareConfig {
        tag: "workspace".into(),
        host_dir: root.to_owned(),
        guest_path: "/workspace".into(),
        cache: CachePolicyKind::Auto,
    }
}

fn root_fd(root: &Path) -> OwnedFd {
    OwnedFd::from(File::open(root).expect("open the share root"))
}

fn cstr(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn create_args(flags: u32) -> CreateIn {
    CreateIn {
        flags,
        mode: libc::S_IFREG | 0o644,
        umask: 0o022,
        fuse_flags: 0,
    }
}

fn create(fs: &Fs, ctx: &Context, parent: u64, name: &str) -> (Entry, u64) {
    let (entry, handle, _, _) = fs
        .create(ctx, parent, &cstr(name), create_args(RW_CREATE))
        .expect("create");
    (entry, handle.expect("create returns a handle"))
}

fn lookup(fs: &Fs, parent: u64, name: &str) -> Entry {
    fs.lookup(&GUEST, parent, &cstr(name)).expect("lookup")
}

fn open(fs: &Fs, ino: u64, flags: u32) -> u64 {
    let (handle, _, _) = fs.open(&GUEST, ino, flags, 0).expect("open");
    handle.expect("open returns a handle")
}

/// A reader holding `data`, as the FUSE server hands a write's payload to
/// the filesystem.
fn payload(data: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(data).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

fn write_as(
    fs: &Fs,
    ctx: &Context,
    ino: u64,
    fh: u64,
    data: &[u8],
    offset: u64,
    fuse_flags: u32,
) -> usize {
    let size = data.len() as u32;
    let delayed = fuse_flags & WRITE_CACHE != 0;
    fs.write(
        ctx,
        ino,
        fh,
        &mut payload(data),
        size,
        offset,
        None,
        delayed,
        RW_CREATE,
        fuse_flags,
    )
    .expect("write")
}

fn write(fs: &Fs, ino: u64, fh: u64, data: &[u8]) -> usize {
    write_as(fs, &GUEST, ino, fh, data, 0, 0)
}

fn release_as(fs: &Fs, ctx: &Context, ino: u64, fh: u64) {
    fs.release(ctx, ino, RW_CREATE, fh, false, false, None)
        .expect("release");
}

fn release(fs: &Fs, ino: u64, fh: u64) {
    release_as(fs, &GUEST, ino, fh);
}

fn b3(data: &[u8]) -> Hash {
    Hash::from_blake3(blake3::hash(data))
}

fn closes(events: &[(Payload, Option<Subject>)]) -> Vec<(FsClose, Option<Subject>)> {
    events
        .iter()
        .filter_map(|(p, s)| match p {
            Payload::FsClose(c) => Some((c.clone(), *s)),
            _ => None,
        })
        .collect()
}

fn close_of(events: &[(Payload, Option<Subject>)], fh: u64) -> (FsClose, Option<Subject>) {
    let mut found = closes(events).into_iter().filter(|(c, _)| c.fh == fh);
    let close = found.next().expect("an fs.close for the handle");
    assert!(found.next().is_none(), "one fs.close per handle");
    close
}

/// The events other than `fs.close`, whose order the hash workers decide.
fn in_order(events: &[(Payload, Option<Subject>)]) -> Vec<Payload> {
    events
        .iter()
        .filter(|(p, _)| !matches!(p, Payload::FsClose(_)))
        .map(|(p, _)| p.clone())
        .collect()
}

fn failed(errno: i32) -> OpResult {
    OpResult::errno(errno)
}

/// (a) create, write, release: `fs.create`, then an `fs.close` carrying the
/// bytes written, the content hash, and the caller.
#[test]
fn create_write_release_records_the_create_then_a_hashed_close() {
    let share = Share::normal();
    let (entry, fh) = create(&share.fs, &GUEST, ROOT_ID, "a.txt");
    assert_eq!(write(&share.fs, entry.inode, fh, b"hi\n"), 3);
    release(&share.fs, entry.inode, fh);
    assert_eq!(fs::read(share.root.join("a.txt")).unwrap(), b"hi\n");

    let events = share.events();
    let kinds: Vec<&str> = events.iter().map(|(p, _)| p.kind()).collect();
    assert_eq!(kinds, ["fs.create", "fs.close"]);
    assert_eq!(
        events[0],
        (
            Payload::FsCreate(FsCreate {
                mount: "workspace".into(),
                path: "/a.txt".into(),
                fh,
                mode: libc::S_IFREG | 0o644,
                flags: RW_CREATE,
                result: OpResult::ok(),
            }),
            Some(GUEST_SUBJECT)
        )
    );
    let (close, subject) = close_of(&events, fh);
    assert_eq!(
        close,
        FsClose {
            mount: "workspace".into(),
            path: "/a.txt".into(),
            path_at_open: "/a.txt".into(),
            fh,
            bytes_read: 0,
            bytes_written: 3,
            size: Some(3),
            blake3: Some(b3(b"hi\n")),
            hash_status: HashStatus::Ok,
            open_seq: None,
            attrib: Attrib::Caller,
        }
    );
    assert_eq!(subject.map(|s| s.pid), Some(42));
    assert_eq!(subject, Some(GUEST_SUBJECT));
}

/// (b) mkdir, create, rename, unlink, rmdir: each record carries the path at
/// the time of the operation, a close reports both the path it was opened at
/// and the path it has now, and a directory rename moves its children.
#[test]
fn mkdir_rename_unlink_record_the_paths_of_the_moment() {
    let share = Share::normal();
    let fs = &share.fs;
    let d = fs
        .mkdir(&GUEST, ROOT_ID, &cstr("d"), 0o755, 0o022)
        .expect("mkdir");
    let (x, fh_x) = create(fs, &GUEST, d.inode, "x");
    write(fs, x.inode, fh_x, b"abc");
    let (w, fh_w) = create(fs, &GUEST, d.inode, "w");
    fs.rename(&GUEST, d.inode, &cstr("x"), ROOT_ID, &cstr("y"), 0)
        .expect("rename the file");
    release(fs, x.inode, fh_x);
    // Hashing happens after the reply; let it finish before the file moves.
    fs.flush_hashes();
    fs.rename(&GUEST, ROOT_ID, &cstr("d"), ROOT_ID, &cstr("e"), 0)
        .expect("rename the directory");
    release(fs, w.inode, fh_w);
    fs.flush_hashes();
    fs.unlink(&GUEST, ROOT_ID, &cstr("y")).expect("unlink y");
    fs.unlink(&GUEST, d.inode, &cstr("w")).expect("unlink w");
    fs.rmdir(&GUEST, ROOT_ID, &cstr("e")).expect("rmdir");
    let again = fs.rmdir(&GUEST, ROOT_ID, &cstr("e"));
    assert_eq!(again.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    assert_eq!(fs::read_dir(&share.root).unwrap().count(), 0);

    let events = share.events();
    let mount = || "workspace".to_string();
    use boxcar_proto::{FsMkdir, FsPathOp, FsRename};
    let rename = |from: &str, to: &str| {
        Payload::FsRename(FsRename {
            mount: mount(),
            from: from.into(),
            to: to.into(),
            flags: 0,
            result: OpResult::ok(),
        })
    };
    let path_op = |path: &str, result: OpResult| FsPathOp {
        mount: mount(),
        path: path.into(),
        result,
    };
    let order = in_order(&events);
    assert_eq!(order.len(), 9, "{order:#?}");
    assert_eq!(
        order[0],
        Payload::FsMkdir(FsMkdir {
            mount: mount(),
            path: "/d".into(),
            mode: 0o755,
            result: OpResult::ok(),
        })
    );
    assert!(matches!(&order[1], Payload::FsCreate(c) if c.path == "/d/x"));
    assert!(matches!(&order[2], Payload::FsCreate(c) if c.path == "/d/w"));
    assert_eq!(order[3], rename("/d/x", "/y"));
    assert_eq!(order[4], rename("/d", "/e"));
    assert_eq!(order[5], Payload::FsUnlink(path_op("/y", OpResult::ok())));
    assert_eq!(order[6], Payload::FsUnlink(path_op("/e/w", OpResult::ok())));
    assert_eq!(order[7], Payload::FsRmdir(path_op("/e", OpResult::ok())));
    assert_eq!(
        order[8],
        Payload::FsRmdir(path_op("/e", failed(libc::ENOENT)))
    );

    let (close_x, _) = close_of(&events, fh_x);
    assert_eq!(
        (close_x.path_at_open.as_str(), close_x.path.as_str()),
        ("/d/x", "/y")
    );
    assert_eq!(close_x.blake3, Some(b3(b"abc")));
    let (close_w, _) = close_of(&events, fh_w);
    assert_eq!(
        (close_w.path_at_open.as_str(), close_w.path.as_str()),
        ("/d/w", "/e/w")
    );
    assert_eq!(close_w.hash_status, HashStatus::Ok);
    assert_eq!(close_w.blake3, Some(b3(b"")));
}

/// (c) readdirplus entries are lookups: they are in the path map until the
/// kernel forgets them, by `forget` or `batch_forget`, and then they are not.
#[test]
fn readdirplus_entries_count_as_lookups_until_forgotten() {
    let share = Share::normal();
    fs::write(share.root.join("f1"), b"1").unwrap();
    fs::write(share.root.join("f2"), b"2").unwrap();
    fs::create_dir(share.root.join("sub")).unwrap();
    let fs = &share.fs;

    let (dh, _) = fs
        .opendir(&GUEST, ROOT_ID, libc::O_RDONLY as u32)
        .expect("opendir");
    let dh = dh.expect("opendir returns a handle");
    let list = |seen: &mut Vec<(Vec<u8>, u64)>| {
        fs.readdirplus(&GUEST, ROOT_ID, dh, 4096, 0, &mut |dirent, entry| {
            seen.push((dirent.name.to_vec(), entry.inode));
            Ok(1)
        })
        .expect("readdirplus");
    };
    let mut seen = Vec::new();
    list(&mut seen);
    seen.sort();
    let names: Vec<&[u8]> = seen.iter().map(|(n, _)| n.as_slice()).collect();
    assert_eq!(names, [&b"f1"[..], b"f2", b"sub"]);
    let mut known = vec![ROOT_ID];
    known.extend(seen.iter().map(|(_, ino)| *ino));
    known.sort();
    assert_eq!(fs.known_inodes(), known);

    // A second listing is a second lookup of each entry.
    list(&mut Vec::new());
    for (_, ino) in &seen {
        fs.forget(&GUEST, *ino, 1);
    }
    assert_eq!(fs.known_inodes(), known, "one lookup each is still held");
    fs.batch_forget(&GUEST, seen.iter().map(|(_, ino)| (*ino, 1)).collect());
    assert_eq!(fs.known_inodes(), [ROOT_ID]);
    for (_, ino) in &seen {
        let gone = fs.getattr(&GUEST, *ino, None).unwrap_err();
        assert_eq!(
            gone.raw_os_error(),
            Some(libc::EBADF),
            "the passthrough forgot the inode at the same count"
        );
    }
    fs.releasedir(&GUEST, ROOT_ID, 0, dh).expect("releasedir");
    drop(share.events());
}

/// A directory `sub` (inode 5) whose listing has `.` and `..` in it, which
/// the passthrough never returns (it filters them out itself).
struct Dotted;

impl FileSystem for Dotted {
    type Inode = u64;
    type Handle = u64;

    fn lookup(&self, _: &Context, _: u64, _: &std::ffi::CStr) -> io::Result<Entry> {
        Ok(Entry {
            inode: 5,
            ..Entry::default()
        })
    }

    fn readdirplus(
        &self,
        _: &Context,
        _: u64,
        _: u64,
        _: u32,
        _: u64,
        add_entry: &mut dyn FnMut(
            fuse_backend_rs::api::filesystem::DirEntry,
            Entry,
        ) -> io::Result<usize>,
    ) -> io::Result<()> {
        let names: [(&[u8], u64); 4] = [(b".", 5), (b"..", 1), (b"a", 7), (b"b", 8)];
        for (offset, (name, inode)) in names.into_iter().enumerate() {
            let dirent = fuse_backend_rs::api::filesystem::DirEntry {
                ino: inode,
                offset: offset as u64 + 1,
                type_: libc::DT_REG as u32,
                name,
            };
            let entry = Entry {
                inode,
                ..Entry::default()
            };
            if add_entry(dirent, entry)? == 0 {
                break;
            }
        }
        Ok(())
    }
}

/// `.` and `..` in a readdirplus reply are not lookups, and neither is an
/// entry that did not fit in the reply.
#[test]
fn readdirplus_counts_only_the_entries_the_reply_carries() {
    let dir = TempDir::new().unwrap();
    let (sink, writer) =
        spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let config = share_config(dir.path());
    let opts = AuditFsOptions::default();
    let fs = AuditFs::new(Dotted, &config, root_fd(dir.path()), sink, opts);
    let sub = fs.lookup(&GUEST, ROOT_ID, &cstr("sub")).unwrap();
    let mut names = Vec::new();
    fs.readdirplus(&GUEST, sub.inode, 1, 4096, 0, &mut |dirent, _| {
        names.push(dirent.name.to_vec());
        // The reply is full before "b".
        Ok(if dirent.name == b"b" { 0 } else { 1 })
    })
    .unwrap();
    assert_eq!(names, [&b"."[..], b"..", b"a", b"b"]);
    assert_eq!(fs.known_inodes(), [ROOT_ID, 5, 7]);
    fs.forget(&GUEST, 7, 1);
    fs.forget(&GUEST, 5, 1);
    assert_eq!(fs.known_inodes(), [ROOT_ID], "`.` held no lookup of sub");
    drop(fs);
    writer.close().unwrap();
}

/// A filesystem whose files vanish between lookup and open: every `open`
/// fails with ENOENT, which a passthrough over a live directory cannot be
/// made to do (it reopens its `O_PATH` fd, and that works on a deleted file).
struct Vanishing;

impl FileSystem for Vanishing {
    type Inode = u64;
    type Handle = u64;

    fn lookup(&self, _: &Context, _: u64, _: &std::ffi::CStr) -> io::Result<Entry> {
        Ok(Entry {
            inode: 5,
            ..Entry::default()
        })
    }

    fn open(
        &self,
        _: &Context,
        _: u64,
        _: u32,
        _: u32,
    ) -> io::Result<(
        Option<u64>,
        fuse_backend_rs::api::filesystem::OpenOptions,
        Option<u32>,
    )> {
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }
}

/// (d) a failed open of a missing file is recorded with its errno.
#[test]
fn a_failed_open_of_a_missing_file_is_recorded() {
    let dir = TempDir::new().unwrap();
    let (sink, writer) =
        spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let config = share_config(dir.path());
    let fs = AuditFs::new(
        Vanishing,
        &config,
        root_fd(dir.path()),
        sink,
        AuditFsOptions::default(),
    );
    let entry = fs.lookup(&GUEST, ROOT_ID, &cstr("gone.txt")).unwrap();
    let err = fs
        .open(&GUEST, entry.inode, libc::O_RDONLY as u32, 0)
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    fs.flush_hashes();
    let session = writer.session_dir().to_owned();
    writer.close().unwrap();
    let records: Vec<Record> = LogReader::open(&session)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .filter(|r| r.kind != "checkpoint")
        .collect();
    assert_eq!(records.len(), 1, "{records:#?}");
    assert_eq!(records[0].subject, Some(GUEST_SUBJECT));
    let Payload::FsOpen(open) = Payload::from_record(&records[0]).unwrap() else {
        panic!("not an fs.open: {:?}", records[0]);
    };
    assert_eq!(
        open,
        FsOpen {
            mount: "workspace".into(),
            path: "/gone.txt".into(),
            fh: 0,
            flags: libc::O_RDONLY as u32,
            flags_decoded: vec!["O_RDONLY".into()],
            exec: false,
            result: failed(libc::ENOENT),
        }
    );
    assert!(!open.result.ok);
    assert_eq!(open.result.err.as_deref(), Some("ENOENT"));
}

/// Failed opens and creates through the passthrough are recorded too.
#[test]
fn failed_opens_and_creates_through_the_passthrough_are_recorded() {
    let share = Share::normal();
    fs::write(share.root.join("plain"), b"x").unwrap();
    let plain = lookup(&share.fs, ROOT_ID, "plain");
    let flags = (libc::O_RDONLY | libc::O_DIRECTORY) as u32;
    let err = share.fs.open(&GUEST, plain.inode, flags, 0).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
    let excl = RW_CREATE | libc::O_EXCL as u32;
    let err = share
        .fs
        .create(&GUEST, ROOT_ID, &cstr("plain"), create_args(excl))
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));

    let events = share.events();
    assert_eq!(events.len(), 2, "{events:#?}");
    match &events[0].0 {
        Payload::FsOpen(open) => {
            assert_eq!(open.path, "/plain");
            assert_eq!(open.flags_decoded, ["O_RDONLY", "O_DIRECTORY"]);
            assert_eq!(open.result, failed(libc::ENOTDIR));
        }
        other => panic!("not an fs.open: {other:?}"),
    }
    match &events[1].0 {
        Payload::FsCreate(create) => {
            assert_eq!(create.path, "/plain");
            assert_eq!(create.fh, 0);
            assert_eq!(create.result, failed(libc::EEXIST));
        }
        other => panic!("not an fs.create: {other:?}"),
    }
}

/// Ids that are not this process's, so that switching to them needs
/// privilege.
fn foreign_ids() -> (u32, u32) {
    // SAFETY: getters with no arguments and no failure modes.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let pick = |own: u32| [1000, 2000, 3000].into_iter().find(|&id| id != own);
    (pick(uid).unwrap(), pick(gid).unwrap())
}

/// (e) as an unprivileged process, a create on behalf of a guest user
/// succeeds: the passthrough never tries to switch credentials. The same
/// request straight to the passthrough fails, which is what the squash
/// prevents.
#[test]
fn an_unprivileged_process_creates_for_any_guest_user() {
    // SAFETY: a getter with no arguments and no failure modes.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root, so credential switching would succeed anyway");
        return;
    }
    let (uid, gid) = foreign_ids();
    let guest = Context { uid, gid, pid: 42 };
    let share = Share::normal();

    let bare_dir = TempDir::new().unwrap();
    let bare =
        PassthroughFs::<()>::new(passthrough_config(&share_config(bare_dir.path()))).unwrap();
    bare.import().unwrap();
    let refused = bare
        .create(&guest, ROOT_ID, &cstr("f"), create_args(RW_CREATE))
        .unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(libc::EPERM));

    let (entry, fh) = create(&share.fs, &guest, ROOT_ID, "f");
    write_as(&share.fs, &guest, entry.inode, fh, b"ok", 0, 0);
    release_as(&share.fs, &guest, entry.inode, fh);
    let meta = fs::metadata(share.root.join("f")).unwrap();
    // SAFETY: a getter with no arguments and no failure modes.
    assert_eq!(
        meta.uid(),
        unsafe { libc::geteuid() },
        "created as the host user"
    );

    let events = share.events();
    let subject = Subject { pid: 42, uid, gid };
    assert_eq!(events[0].1, Some(subject));
    assert!(matches!(&events[0].0, Payload::FsCreate(c) if c.result.ok));
    assert_eq!(close_of(&events, fh).1, Some(subject));
}

/// (f) a file over `hash_max_bytes` is closed without a hash.
#[test]
fn a_file_over_the_hash_limit_closes_with_skipped_size() {
    let share = Share::new(AuditLevel::Normal, 16);
    let (entry, fh) = create(&share.fs, &GUEST, ROOT_ID, "big");
    write(&share.fs, entry.inode, fh, &[7; 32]);
    release(&share.fs, entry.inode, fh);
    let (small, small_fh) = create(&share.fs, &GUEST, ROOT_ID, "small");
    write(&share.fs, small.inode, small_fh, &[7; 16]);
    release(&share.fs, small.inode, small_fh);

    let events = share.events();
    let (close, _) = close_of(&events, fh);
    assert_eq!(close.hash_status, HashStatus::SkippedSize);
    assert_eq!(close.size, Some(32));
    assert_eq!(close.blake3, None);
    assert_eq!(close.bytes_written, 32);
    let (close, _) = close_of(&events, small_fh);
    assert_eq!(close.hash_status, HashStatus::Ok, "the limit is inclusive");
    assert_eq!(close.blake3, Some(b3(&[7; 16])));
}

/// A handle nothing was written through closes at once, unhashed; one whose
/// file was unlinked while open closes as gone.
#[test]
fn close_without_writes_is_not_hashed_and_an_unlinked_file_is_gone() {
    let share = Share::normal();
    fs::write(share.root.join("read-only"), b"data").unwrap();
    let ro = lookup(&share.fs, ROOT_ID, "read-only");
    let fh_ro = open(&share.fs, ro.inode, libc::O_RDONLY as u32);
    let mut sink = tempfile::tempfile().unwrap();
    let n = share
        .fs
        .read(
            &GUEST,
            ro.inode,
            fh_ro,
            &mut sink,
            64,
            0,
            None,
            libc::O_RDONLY as u32,
        )
        .expect("read");
    assert_eq!(n, 4);
    release(&share.fs, ro.inode, fh_ro);

    let (tmp, fh_tmp) = create(&share.fs, &GUEST, ROOT_ID, "tmp");
    write(&share.fs, tmp.inode, fh_tmp, b"scratch");
    share.fs.unlink(&GUEST, ROOT_ID, &cstr("tmp")).unwrap();
    release(&share.fs, tmp.inode, fh_tmp);

    let events = share.events();
    let (close, subject) = close_of(&events, fh_ro);
    assert_eq!(close.hash_status, HashStatus::NotHashed);
    assert_eq!((close.bytes_read, close.bytes_written), (4, 0));
    assert_eq!((close.size, close.blake3), (None, None));
    assert_eq!(subject, Some(GUEST_SUBJECT));
    let (close, _) = close_of(&events, fh_tmp);
    assert_eq!(close.hash_status, HashStatus::Gone);
    assert_eq!(close.path, "/tmp");
    assert_eq!(close.blake3, None);
}

/// A truncate through a handle is a content change: the close is hashed even
/// though nothing was written.
#[test]
fn a_truncate_through_a_handle_makes_the_close_hashed() {
    let share = Share::normal();
    fs::write(share.root.join("log"), b"old contents").unwrap();
    let log = lookup(&share.fs, ROOT_ID, "log");
    let fh = open(&share.fs, log.inode, libc::O_RDWR as u32);
    // SAFETY: stat64 is plain data; all-zero is a valid value.
    let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 0;
    share
        .fs
        .setattr(&GUEST, log.inode, attr, Some(fh), SetattrValid::SIZE)
        .expect("truncate");
    release(&share.fs, log.inode, fh);

    let events = share.events();
    let setattr = events
        .iter()
        .find_map(|(p, _)| match p {
            Payload::FsSetattr(s) => Some(s.clone()),
            _ => None,
        })
        .expect("an fs.setattr");
    assert_eq!(setattr.path, "/log");
    assert_eq!(setattr.set.size, Some(0));
    assert_eq!(setattr.set.mode, None);
    assert!(setattr.result.ok);
    let (close, _) = close_of(&events, fh);
    assert_eq!(close.hash_status, HashStatus::Ok);
    assert_eq!((close.size, close.blake3), (Some(0), Some(b3(b""))));
}

/// Reads and writes are attributed to the opener when the request has no
/// usable caller: pid 0, or a write-back from the page cache. At the verbose
/// level each one is an event.
#[test]
fn io_without_a_usable_caller_is_attributed_to_the_opener() {
    let share = Share::new(AuditLevel::Verbose, HASH_MAX);
    let kernel = Context {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let flusher = Context {
        pid: 7,
        uid: 0,
        gid: 0,
    };
    let (entry, fh) = create(&share.fs, &GUEST, ROOT_ID, "f");
    write_as(&share.fs, &kernel, entry.inode, fh, b"ab", 0, 0);
    write_as(&share.fs, &flusher, entry.inode, fh, b"cd", 2, WRITE_CACHE);
    write_as(&share.fs, &flusher, entry.inode, fh, b"ef", 4, 0);
    let mut sink = tempfile::tempfile().unwrap();
    share
        .fs
        .read(&kernel, entry.inode, fh, &mut sink, 6, 0, None, RW_CREATE)
        .expect("read");
    release_as(&share.fs, &kernel, entry.inode, fh);

    let events = share.events();
    let io: Vec<(&str, u64, Option<u32>, Attrib)> = events
        .iter()
        .filter_map(|(p, s)| {
            let pid = s.map(|s| s.pid);
            match p {
                Payload::FsWrite(FsIo { offset, attrib, .. }) => {
                    Some(("write", *offset, pid, *attrib))
                }
                Payload::FsRead(FsIo { offset, attrib, .. }) => {
                    Some(("read", *offset, pid, *attrib))
                }
                _ => None,
            }
        })
        .collect();
    assert_eq!(
        io,
        [
            ("write", 0, Some(42), Attrib::Handle),
            ("write", 2, Some(42), Attrib::Handle),
            ("write", 4, Some(7), Attrib::Caller),
            ("read", 0, Some(42), Attrib::Handle),
        ]
    );
    let (close, subject) = close_of(&events, fh);
    assert_eq!(close.attrib, Attrib::Handle);
    assert_eq!(subject, Some(GUEST_SUBJECT));
    assert_eq!((close.bytes_written, close.bytes_read), (6, 6));
    assert_eq!(close.blake3, Some(b3(b"abcdef")));
}

/// A file written and never released: the guest's filesystem went away
/// (unmount, driver unbind, a guest panic, the VM stopping) with it open.
fn leave_open(share: &Share) -> (u64, u64, u64) {
    let (entry, fh) = create(&share.fs, &GUEST, ROOT_ID, "unsaved.txt");
    write(&share.fs, entry.inode, fh, b"unsaved\n");
    fs::write(share.root.join("ro"), b"r").unwrap();
    let ro = lookup(&share.fs, ROOT_ID, "ro");
    let fh_ro = open(&share.fs, ro.inode, libc::O_RDONLY as u32);
    (entry.inode, fh, fh_ro)
}

/// The closes of the handles `leave_open` left open.
fn assert_left_open_closed(events: &[(Payload, Option<Subject>)], fh: u64, fh_ro: u64) {
    let (close, subject) = close_of(events, fh);
    assert_eq!(close.path, "/unsaved.txt");
    assert_eq!(close.bytes_written, 8);
    assert_eq!(close.hash_status, HashStatus::Ok);
    assert_eq!(close.blake3, Some(b3(b"unsaved\n")));
    assert_eq!(close.size, Some(8));
    assert_eq!(close.attrib, Attrib::Handle, "no request: the opener");
    assert_eq!(subject, Some(GUEST_SUBJECT));
    let (close, _) = close_of(events, fh_ro);
    assert_eq!(close.hash_status, HashStatus::NotHashed);
    assert_eq!(close.attrib, Attrib::Handle);
}

/// `destroy` closes and hashes every handle still open before the
/// passthrough lets go of its files.
#[test]
fn destroy_closes_the_handles_left_open() {
    let share = Share::normal();
    let (ino, fh, fh_ro) = leave_open(&share);
    share.fs.destroy();
    assert_eq!(share.fs.known_inodes(), [ROOT_ID]);
    // A late release finds nothing left to close.
    let _ = share
        .fs
        .release(&GUEST, ino, RW_CREATE, fh, false, false, None);
    let events = share.events();
    assert_left_open_closed(&events, fh, fh_ro);
}

/// `shutdown` does the same, for a VM stopped with files open.
#[test]
fn shutdown_closes_the_handles_left_open() {
    let share = Share::normal();
    let (_, fh, fh_ro) = leave_open(&share);
    share.fs.shutdown();
    let events = share.events();
    assert_left_open_closed(&events, fh, fh_ro);
}

/// And so does dropping the filesystem while the log is still open.
#[test]
fn dropping_the_filesystem_closes_the_handles_left_open() {
    let share = Share::normal();
    let (_, fh, fh_ro) = leave_open(&share);
    let Share {
        dir,
        root: _,
        fs,
        writer,
    } = share;
    drop(fs);
    let session = writer.session_dir().to_owned();
    writer.close().unwrap();
    verify_session(&session).unwrap();
    let events: Vec<(Payload, Option<Subject>)> = LogReader::open(&session)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .filter(|r| r.kind != "checkpoint")
        .map(|r| (Payload::from_record(&r).unwrap(), r.subject))
        .collect();
    drop(dir);
    assert_left_open_closed(&events, fh, fh_ro);
}

/// Symlink, link, mknod, setxattr, removexattr, fallocate and setattr each
/// record what they did.
#[test]
fn other_mutations_are_recorded() {
    let share = Share::normal();
    let fs = &share.fs;
    let (file, fh) = create(fs, &GUEST, ROOT_ID, "file");
    fs.fallocate(&GUEST, file.inode, fh, 0, 0, 4096)
        .expect("fallocate");
    fs.symlink(&GUEST, &cstr("file"), ROOT_ID, &cstr("sym"))
        .expect("symlink");
    fs.link(&GUEST, file.inode, ROOT_ID, &cstr("hard"))
        .expect("link");
    fs.mknod(
        &GUEST,
        ROOT_ID,
        &cstr("fifo"),
        libc::S_IFIFO | 0o666,
        0,
        0o022,
    )
    .expect("mknod");
    fs.setxattr(&GUEST, file.inode, &cstr("user.k"), b"v", 0)
        .expect("setxattr");
    fs.removexattr(&GUEST, file.inode, &cstr("user.k"))
        .expect("removexattr");
    // SAFETY: stat64 is plain data; all-zero is a valid value.
    let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = libc::S_IFREG | 0o600;
    fs.setattr(&GUEST, file.inode, attr, None, SetattrValid::MODE)
        .expect("chmod");
    release(fs, file.inode, fh);
    let mode = fs::metadata(share.root.join("file"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let events = share.events();
    let order = in_order(&events);
    let kinds: Vec<&str> = order.iter().map(Payload::kind).collect();
    assert_eq!(
        kinds,
        [
            "fs.create",
            "fs.fallocate",
            "fs.symlink",
            "fs.link",
            "fs.mknod",
            "fs.xattr",
            "fs.xattr",
            "fs.setattr"
        ]
    );
    use boxcar_proto::{FsFallocate, FsLink, FsMknod, FsSymlink, FsXattr};
    let mount = || "workspace".to_string();
    assert_eq!(
        order[1],
        Payload::FsFallocate(FsFallocate {
            mount: mount(),
            path: "/file".into(),
            offset: 0,
            len: 4096,
            mode: 0,
            result: OpResult::ok(),
        })
    );
    assert_eq!(
        order[2],
        Payload::FsSymlink(FsSymlink {
            mount: mount(),
            path: "/sym".into(),
            target: "file".into(),
            result: OpResult::ok(),
        })
    );
    assert_eq!(
        order[3],
        Payload::FsLink(FsLink {
            mount: mount(),
            path: "/hard".into(),
            target_path: "/file".into(),
            result: OpResult::ok(),
        })
    );
    assert_eq!(
        order[4],
        Payload::FsMknod(FsMknod {
            mount: mount(),
            path: "/fifo".into(),
            mode: libc::S_IFIFO | 0o644,
            rdev: 0,
            result: OpResult::ok(),
        })
    );
    let xattr = |op: &str| {
        Payload::FsXattr(FsXattr {
            mount: mount(),
            path: "/file".into(),
            name: "user.k".into(),
            op: op.into(),
            result: OpResult::ok(),
        })
    };
    assert_eq!(order[5], xattr("set"));
    assert_eq!(order[6], xattr("remove"));
    match &order[7] {
        Payload::FsSetattr(s) => {
            assert_eq!(s.path, "/file");
            assert_eq!(s.set.mode, Some(0o600));
            assert_eq!(s.set.size, None);
        }
        other => panic!("not an fs.setattr: {other:?}"),
    }
}

fn is_eio<T: std::fmt::Debug>(result: io::Result<T>) -> bool {
    match result {
        Err(e) => e.raw_os_error() == Some(libc::EIO),
        Ok(v) => panic!("succeeded: {v:?}"),
    }
}

/// Once the audit log has failed, nothing the guest changes could be
/// recorded, so every change is refused with EIO and reaches no host file;
/// reads are still served.
#[test]
fn once_the_log_fails_changes_are_refused_with_eio_and_reads_still_work() {
    let share = Share::failing_log();
    fs::write(share.root.join("data"), b"old contents").unwrap();
    fs::create_dir(share.root.join("dir")).unwrap();
    let fs = &share.fs;
    let data = lookup(fs, ROOT_ID, "data");
    let dir = lookup(fs, ROOT_ID, "dir");
    // The fs.open is the first record, and its checkpoint fails the log.
    let rw = open(fs, data.inode, libc::O_RDWR as u32);
    let deadline = Instant::now() + Duration::from_secs(10);
    while share.writer.failure().is_none() {
        assert!(Instant::now() < deadline, "the audit log did not fail");
        std::thread::sleep(Duration::from_millis(5));
    }

    let name = cstr("new");
    assert!(is_eio(fs.write(
        &GUEST,
        data.inode,
        rw,
        &mut payload(b"new"),
        3,
        0,
        None,
        false,
        RW_CREATE,
        0
    )));
    assert!(is_eio(fs.create(
        &GUEST,
        ROOT_ID,
        &name,
        create_args(RW_CREATE)
    )));
    for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_RDONLY | libc::O_TRUNC] {
        assert!(
            is_eio(fs.open(&GUEST, data.inode, flags as u32, 0)),
            "{flags:#o}"
        );
    }
    assert!(is_eio(fs.unlink(&GUEST, ROOT_ID, &cstr("data"))));
    assert!(is_eio(fs.rmdir(&GUEST, ROOT_ID, &cstr("dir"))));
    assert!(is_eio(fs.rename(
        &GUEST,
        ROOT_ID,
        &cstr("data"),
        dir.inode,
        &name,
        0
    )));
    assert!(is_eio(fs.mkdir(&GUEST, ROOT_ID, &name, 0o755, 0o022)));
    assert!(is_eio(fs.mknod(
        &GUEST,
        ROOT_ID,
        &name,
        libc::S_IFIFO | 0o644,
        0,
        0o022
    )));
    assert!(is_eio(fs.symlink(&GUEST, &cstr("data"), ROOT_ID, &name)));
    assert!(is_eio(fs.link(&GUEST, data.inode, ROOT_ID, &name)));
    // SAFETY: stat64 is plain data; all-zero is a valid value.
    let attr: libc::stat64 = unsafe { std::mem::zeroed() };
    assert!(is_eio(fs.setattr(
        &GUEST,
        data.inode,
        attr,
        Some(rw),
        SetattrValid::SIZE
    )));
    assert!(is_eio(fs.fallocate(&GUEST, data.inode, rw, 0, 0, 4096)));
    assert!(is_eio(fs.setxattr(
        &GUEST,
        data.inode,
        &cstr("user.k"),
        b"v",
        0
    )));
    assert!(is_eio(fs.removexattr(&GUEST, data.inode, &cstr("user.k"))));

    // Nothing reached the host.
    assert_eq!(fs::read(share.root.join("data")).unwrap(), b"old contents");
    assert!(share.root.join("dir").is_dir());
    let mut names: Vec<_> = fs::read_dir(&share.root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["data", "dir"]);

    // Reads are still served, through a new read-only handle and the old
    // read-write one.
    let ro = open(fs, data.inode, libc::O_RDONLY as u32);
    for fh in [ro, rw] {
        let mut out = tempfile::tempfile().unwrap();
        let n = fs
            .read(&GUEST, data.inode, fh, &mut out, 64, 0, None, 0)
            .expect("read");
        assert_eq!(n, 12);
        let mut back = String::new();
        out.seek(SeekFrom::Start(0)).unwrap();
        out.read_to_string(&mut back).unwrap();
        assert_eq!(back, "old contents");
    }
    release(fs, data.inode, ro);
    release(fs, data.inode, rw);
}

/// Lookups are recorded only when refused for lack of permission; at the
/// verbose level a missing name is recorded too.
#[test]
fn refused_lookups_are_recorded_as_denied() {
    for level in [AuditLevel::Normal, AuditLevel::Verbose] {
        let share = Share::new(level, HASH_MAX);
        let locked = share.root.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("secret"), b"s").unwrap();
        let dir = lookup(&share.fs, ROOT_ID, "locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let denied = share.fs.lookup(&GUEST, dir.inode, &cstr("secret"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let missing = share.fs.lookup(&GUEST, ROOT_ID, &cstr("missing"));
        assert_eq!(missing.unwrap_err().raw_os_error(), Some(libc::ENOENT));
        // SAFETY: a getter with no arguments and no failure modes.
        let root = unsafe { libc::geteuid() } == 0;

        let events = share.events();
        let mut expected = Vec::new();
        if !root {
            assert_eq!(denied.unwrap_err().raw_os_error(), Some(libc::EACCES));
            expected.push(FsDenied {
                mount: "workspace".into(),
                path: "/locked/secret".into(),
                op: "lookup".into(),
                errno: libc::EACCES,
            });
        }
        if matches!(level, AuditLevel::Verbose) {
            expected.push(FsDenied {
                mount: "workspace".into(),
                path: "/missing".into(),
                op: "lookup".into(),
                errno: libc::ENOENT,
            });
        }
        let got: Vec<FsDenied> = events
            .iter()
            .filter_map(|(p, _)| match p {
                Payload::FsDenied(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(got, expected);
        assert_eq!(got.len(), events.len(), "nothing else is recorded");
    }
}

/// `init` never lets the guest turn on the write-back cache or DAX, whatever
/// the kernel offers, and records the mount once.
#[test]
fn init_masks_writeback_and_dax_and_records_the_mount() {
    let share = Share::normal();
    let host_root = share.root.to_str().unwrap().to_owned();
    let offered = FsOptions::all();
    let wanted = share.fs.init(offered).expect("init");
    for bit in [
        FsOptions::WRITEBACK_CACHE,
        FsOptions::MAP_ALIGNMENT,
        FsOptions::PERFILE_DAX,
    ] {
        assert!(!wanted.contains(bit), "{bit:?} negotiated");
    }
    assert!(wanted.contains(FsOptions::DO_READDIRPLUS));

    let events = share.events();
    assert_eq!(
        events,
        [(
            Payload::FsMount(boxcar_proto::FsMount {
                mount: "workspace".into(),
                guest_path: "/workspace".into(),
                host_root,
                cache_policy: "auto".into(),
            }),
            None
        )]
    );
}

/// Where the exec bit comes from: the kernel puts `__FMODE_EXEC` (0x20) in
/// the open flags of an `execve`, and the FUSE server must pass the flags to
/// `FileSystem::open` unchanged for `exec` to be recorded. This drives a real
/// FUSE_OPEN message through fuse-backend-rs's `Server` to find out.
#[test]
fn the_exec_bit_reaches_the_trait_through_the_fuse_server() {
    const GUEST_MEM: usize = 64 * 1024;
    const REQUEST: u64 = 0x1000;
    const REPLY: u64 = 0x2000;

    let share = Share::normal();
    fs::write(share.root.join("tool"), b"#!/bin/sh\n").unwrap();
    let tool = lookup(&share.fs, ROOT_ID, "tool");

    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM)]).unwrap();
    let queue = MockSplitQueue::new(&mem, 16);
    let len = size_of::<InHeader>() + size_of::<OpenIn>();
    let header = InHeader {
        len: len as u32,
        opcode: Opcode::Open as u32,
        unique: 1,
        nodeid: tool.inode,
        uid: 1000,
        gid: 1000,
        pid: 42,
        padding: 0,
    };
    let flags = libc::O_RDONLY as u32 | FMODE_EXEC;
    mem.write_obj(header, GuestAddress(REQUEST)).unwrap();
    let body = GuestAddress(REQUEST + size_of::<InHeader>() as u64);
    mem.write_obj(
        OpenIn {
            flags,
            fuse_flags: 0,
        },
        body,
    )
    .unwrap();
    let chain = queue
        .build_desc_chain(&[
            RawDescriptor::from(SplitDescriptor::new(REQUEST, len as u32, 0, 0)),
            RawDescriptor::from(SplitDescriptor::new(
                REPLY,
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ])
        .unwrap();
    let reader = Reader::from_descriptor_chain(&mem, chain.clone()).unwrap();
    let writer: Writer<'_, ()> = VirtioFsWriter::new(&mem, chain).unwrap().into();
    let server = Server::new(Arc::clone(&share.fs));
    server
        .handle_message(reader, writer, None, None)
        .expect("the server handles FUSE_OPEN");
    let out: OutHeader = mem.read_obj(GuestAddress(REPLY)).unwrap();
    assert_eq!(out.error, 0);
    let reply = GuestAddress(REPLY + size_of::<OutHeader>() as u64);
    let opened: OpenOut = mem.read_obj(reply).unwrap();
    drop(server);
    release(&share.fs, tool.inode, opened.fh);

    let events = share.events();
    let recorded = events
        .iter()
        .find_map(|(p, _)| match p {
            Payload::FsOpen(o) => Some(o.clone()),
            _ => None,
        })
        .expect("an fs.open");
    assert_eq!(recorded.flags, flags, "the server passed the flags through");
    assert!(recorded.exec, "exec is recorded from __FMODE_EXEC");
    assert_eq!(recorded.fh, opened.fh);
    assert_eq!(recorded.path, "/tool");

    // And a plain open is not an exec.
    let share = Share::normal();
    fs::write(share.root.join("data"), b"").unwrap();
    let data = lookup(&share.fs, ROOT_ID, "data");
    let fh = open(&share.fs, data.inode, libc::O_RDONLY as u32);
    release(&share.fs, data.inode, fh);
    let events = share.events();
    assert!(matches!(&events[0].0, Payload::FsOpen(o) if !o.exec));
}

/// The decoded flags name each flag set, access mode first.
#[test]
fn open_flags_are_decoded() {
    let share = Share::normal();
    fs::write(share.root.join("f"), b"").unwrap();
    let f = lookup(&share.fs, ROOT_ID, "f");
    let flags =
        (libc::O_WRONLY | libc::O_APPEND | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            as u32;
    let fh = open(&share.fs, f.inode, flags);
    release(&share.fs, f.inode, fh);
    let events = share.events();
    match &events[0].0 {
        Payload::FsOpen(open) => assert_eq!(
            open.flags_decoded,
            ["O_WRONLY", "O_TRUNC", "O_APPEND", "O_NOFOLLOW", "O_CLOEXEC"]
        ),
        other => panic!("not an fs.open: {other:?}"),
    }
    // O_TRUNC changed the content: the close is hashed.
    let (close, _) = close_of(&events, fh);
    assert_eq!(close.hash_status, HashStatus::Ok);
}

/// Reading the share back through `read` returns what was written, so the
/// reply data passes through the decorator untouched.
#[test]
fn replies_pass_through_unchanged() {
    let share = Share::normal();
    let (entry, fh) = create(&share.fs, &GUEST, ROOT_ID, "f");
    write(&share.fs, entry.inode, fh, b"payload");
    let mut sink = tempfile::tempfile().unwrap();
    let n = share
        .fs
        .read(&GUEST, entry.inode, fh, &mut sink, 64, 0, None, RW_CREATE)
        .unwrap();
    assert_eq!(n, 7);
    let mut read = Vec::new();
    sink.seek(SeekFrom::Start(0)).unwrap();
    sink.read_to_end(&mut read).unwrap();
    assert_eq!(read, b"payload");
    let (attr, _) = share.fs.getattr(&GUEST, entry.inode, Some(fh)).unwrap();
    assert_eq!(attr.st_size, 7);
    assert_eq!(attr.st_ino, entry.attr.st_ino);
    release(&share.fs, entry.inode, fh);
    drop(share.events());
}
