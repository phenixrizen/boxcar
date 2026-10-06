// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Attaching the TLS probes to the files that export OpenSSL's functions.
//! Each program the session runs (the `filename` of its `proc.exec`) is
//! tried once; so is every `libssl.so*` a session process has mapped,
//! found in `/proc/<tgid>/maps` shortly after its exec (the loader needs a
//! moment) and at each heartbeat while it lives. The outcome for each path
//! is reported once as `proc.tls_attach`; after [`MAX_PATHS`] paths
//! nothing more is tried, which is reported once as well. A probe on a
//! file reaches every process that maps it, now or later, and the
//! programs keep the session filter.
//!
//! Reading a file for its symbols goes through the shares and takes a
//! moment, so it is done on a thread of its own ([`Resolver`]): the
//! sensor's event loop never waits on it, and its events keep their
//! order against ring 0's. Only the attach itself, a syscall with the
//! offsets found, is done on the loop, when the resolver's pipe says a
//! result is in.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use aya::programs::uprobe::{UProbeAttachLocation, UProbeScope};
use aya::programs::UProbe;
use aya::Ebpf;
use boxcar_proto::sensor::SensorFrame;
use boxcar_proto::{Payload, ProcTlsAttach};
use object::{Object, ObjectSection, ObjectSymbol};

use crate::status::cut;

/// The most paths tried in a session.
pub const MAX_PATHS: usize = 64;
/// How long after a process's exec its maps are first looked at.
pub const FIRST_SWEEP: Duration = Duration::from_millis(50);
/// How often a live process's maps are looked at after that.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// The most processes followed at once.
const MAX_TGIDS: usize = 4096;
/// The most bytes of a file read for its symbols.
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Where the four functions sit in a file, as offsets from its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offsets {
    pub write: u64,
    pub read: u64,
    /// The `_ex` forms are newer; a runtime may lack them.
    pub write_ex: Option<u64>,
    pub read_ex: Option<u64>,
}

/// A path's symbols, found or not.
struct Resolved {
    path: PathBuf,
    offsets: Result<Offsets, String>,
}

/// The thread that reads files for their symbols, and the pipe it writes
/// a byte to for each result.
struct Resolver {
    requests: Sender<PathBuf>,
    results: Receiver<Resolved>,
    wake_read: OwnedFd,
    /// The thread's id, for the status: its reads are the sensor's.
    tid: u32,
}

impl Resolver {
    fn start() -> io::Result<Resolver> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: pipe2 fills the two descriptors given.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are ours, just made.
        let (wake_read, wake_write) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (requests, paths) = mpsc::channel::<PathBuf>();
        let (done, results) = mpsc::channel::<Resolved>();
        let (tid_tx, tid_rx) = mpsc::channel::<u32>();
        thread::Builder::new()
            .name("tls-resolve".into())
            .spawn(move || {
                // SAFETY: gettid takes nothing and cannot fail.
                let tid = unsafe { libc::gettid() };
                let _ = tid_tx.send(u32::try_from(tid).unwrap_or(0));
                for path in paths {
                    let offsets = resolve(&path);
                    if done.send(Resolved { path, offsets }).is_err() {
                        return;
                    }
                    // SAFETY: a one-byte write to our pipe; a full pipe
                    // (EAGAIN) is fine, the reader is already told.
                    unsafe { libc::write(wake_write.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
                }
            })?;
        let tid = tid_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| io::Error::other("the resolver thread did not start"))?;
        Ok(Resolver {
            requests,
            results,
            wake_read,
            tid,
        })
    }

    /// Takes every byte off the pipe.
    fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: a read into our buffer, for its size.
            let n = unsafe { libc::read(self.wake_read.as_raw_fd(), buf.as_mut_ptr().cast(), 64) };
            if n <= 0 {
                return;
            }
        }
    }
}

/// The paths tried, the processes to sweep, and the resolver.
pub struct Attacher {
    tried: HashSet<PathBuf>,
    limit_reported: bool,
    /// Each live process seen, and when its maps are next looked at.
    tgids: HashMap<u32, Instant>,
    resolver: Option<Resolver>,
}

impl Attacher {
    /// Starts the resolver thread. Without one (its pipe or thread could
    /// not be made) nothing is ever attached, and the first path says so.
    pub fn new() -> Attacher {
        Attacher {
            tried: HashSet::new(),
            limit_reported: false,
            tgids: HashMap::new(),
            resolver: Resolver::start().ok(),
        }
    }

    /// The descriptor that is readable when a result is in.
    pub fn wake_fd(&self) -> RawFd {
        self.resolver
            .as_ref()
            .map_or(-1, |r| r.wake_read.as_raw_fd())
    }

    /// The sensor's threads the attacher runs: the resolver's.
    pub fn threads(&self) -> Vec<u32> {
        self.resolver.iter().map(|r| r.tid).collect()
    }

    /// A process the session started: its maps are looked at shortly.
    pub fn saw(&mut self, tgid: u32, now: Instant) {
        if self.tgids.len() >= MAX_TGIDS && !self.tgids.contains_key(&tgid) {
            return;
        }
        self.tgids.insert(tgid, now + FIRST_SWEEP);
    }

    /// A process ended: nothing more to look at.
    pub fn gone(&mut self, tgid: u32) {
        self.tgids.remove(&tgid);
    }

    /// When the next sweep is due, if any process waits for one.
    pub fn next_due(&self) -> Option<Instant> {
        self.tgids.values().min().copied()
    }

    /// Asks for `path`'s symbols, once. The frame to send now, if any:
    /// the limit, once, or the want of a resolver; the path's own outcome
    /// comes from [`Attacher::resolved`].
    pub fn consider(&mut self, path: &Path, ts_guest_ns: u64) -> Option<SensorFrame> {
        if self.tried.contains(path) {
            return None;
        }
        if self.tried.len() >= MAX_PATHS {
            if self.limit_reported {
                return None;
            }
            self.limit_reported = true;
            return Some(frame(path, Err("limit".to_owned()), ts_guest_ns));
        }
        self.tried.insert(path.to_owned());
        let Some(resolver) = &self.resolver else {
            return Some(frame(path, Err("no resolver".to_owned()), ts_guest_ns));
        };
        if resolver.requests.send(path.to_owned()).is_err() {
            return Some(frame(path, Err("resolver gone".to_owned()), ts_guest_ns));
        }
        None
    }

    /// Attaches the programs to each path the resolver has answered for,
    /// and returns their frames. Called when [`Attacher::wake_fd`] is
    /// readable.
    pub fn resolved(&mut self, mut ebpf: Option<&mut Ebpf>, ts_guest_ns: u64) -> Vec<SensorFrame> {
        let Some(resolver) = &self.resolver else {
            return Vec::new();
        };
        resolver.drain();
        let mut frames = Vec::new();
        while let Ok(Resolved { path, offsets }) = resolver.results.try_recv() {
            let result = match (offsets, ebpf.as_deref_mut()) {
                (Err(error), _) => Err(error),
                (Ok(_), None) => Err("the programs are not loaded".to_owned()),
                (Ok(offsets), Some(ebpf)) => attach_all(ebpf, &path, offsets),
            };
            frames.push(frame(&path, result, ts_guest_ns));
        }
        frames
    }

    /// Looks at the maps of the processes whose sweep is due, and asks for
    /// every `libssl.so*` they map. A process whose maps cannot be read has
    /// ended. The frames to send now, if any (see [`Attacher::consider`]).
    pub fn sweep(&mut self, now: Instant, ts_guest_ns: u64) -> Vec<SensorFrame> {
        let due: Vec<u32> = self
            .tgids
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(tgid, _)| *tgid)
            .collect();
        let mut frames = Vec::new();
        for tgid in due {
            let Ok(maps) = fs::read_to_string(format!("/proc/{tgid}/maps")) else {
                self.tgids.remove(&tgid);
                continue;
            };
            self.tgids.insert(tgid, now + SWEEP_INTERVAL);
            for path in libssl_paths(&maps) {
                frames.extend(self.consider(&path, ts_guest_ns));
            }
        }
        frames
    }
}

impl Default for Attacher {
    fn default() -> Attacher {
        Attacher::new()
    }
}

/// Reads `path` and finds the four functions: `SSL_write` and `SSL_read`
/// must be there, exported or in the symbol table.
pub fn resolve(path: &Path) -> Result<Offsets, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("stat: {error}"))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(format!("{size} bytes: too large to read for symbols"));
    }
    let data = fs::read(path).map_err(|error| format!("read: {error}"))?;
    let obj = object::File::parse(&*data).map_err(|error| format!("not an object: {error}"))?;
    let find = |name: &str| -> Result<Option<u64>, String> {
        let Some(sym) = obj
            .dynamic_symbols()
            .chain(obj.symbols())
            .find(|sym| sym.name().is_ok_and(|n| n == name) && sym.address() != 0)
        else {
            return Ok(None);
        };
        let translate = matches!(
            obj.kind(),
            object::ObjectKind::Dynamic | object::ObjectKind::Executable
        );
        if !translate {
            return Ok(Some(sym.address()));
        }
        let index = sym
            .section_index()
            .ok_or_else(|| format!("{name}: not in a section"))?;
        let section = obj
            .section_by_index(index)
            .map_err(|error| format!("{name}: {error}"))?;
        let (file_offset, _) = section
            .file_range()
            .ok_or_else(|| format!("{name}: its section has no bytes in the file"))?;
        Ok(Some(sym.address() - section.address() + file_offset))
    };
    let write = find("SSL_write")?.ok_or_else(|| "SSL_write: not exported".to_owned())?;
    let read = find("SSL_read")?.ok_or_else(|| "SSL_read: not exported".to_owned())?;
    Ok(Offsets {
        write,
        read,
        write_ex: find("SSL_write_ex")?,
        read_ex: find("SSL_read_ex")?,
    })
}

/// Attaches every TLS program to `path` at its offsets. Ok when the
/// `SSL_write` and `SSL_read` probes took; the error otherwise.
fn attach_all(ebpf: &mut Ebpf, path: &Path, offsets: Offsets) -> Result<(), String> {
    attach_one(ebpf, "ssl_write", offsets.write, path)?;
    attach_one(ebpf, "ssl_read", offsets.read, path)?;
    attach_one(ebpf, "ssl_read_ret", offsets.read, path)?;
    if let Some(write_ex) = offsets.write_ex {
        let _ = attach_one(ebpf, "ssl_write_ex", write_ex, path);
    }
    if let Some(read_ex) = offsets.read_ex {
        let _ = attach_one(ebpf, "ssl_read_ex", read_ex, path);
        let _ = attach_one(ebpf, "ssl_read_ex_ret", read_ex, path);
    }
    Ok(())
}

fn attach_one(ebpf: &mut Ebpf, name: &str, offset: u64, path: &Path) -> Result<(), String> {
    let program = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("{name} is not in the object"))?;
    let program: &mut UProbe = program
        .try_into()
        .map_err(|error| format!("{name}: not a uprobe: {error}"))?;
    program
        .attach(
            UProbeAttachLocation::AbsoluteOffset(offset),
            path,
            UProbeScope::AllProcesses,
        )
        .map(|_| ())
        .map_err(|error| format!("{name}: {error}"))
}

/// The `libssl.so*` files a process maps, from its `/proc/<tgid>/maps`
/// text, each once.
pub fn libssl_paths(maps: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for line in maps.lines() {
        // address perms offset dev inode [path]: the path is the first
        // field that starts with a slash.
        let Some(at) = line.find(" /") else {
            continue;
        };
        let path = line[at + 1..].trim_end();
        let name = path.rsplit('/').next().unwrap_or(path);
        if !name.starts_with("libssl.so") {
            continue;
        }
        let path = PathBuf::from(path);
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// The `proc.tls_attach` frame for one path.
fn frame(path: &Path, result: Result<(), String>, ts_guest_ns: u64) -> SensorFrame {
    SensorFrame {
        ts_guest_ns,
        subject: None,
        payload: Payload::ProcTlsAttach(ProcTlsAttach {
            path: cut_path(path),
            ok: result.is_ok(),
            error: result.err().map(|error| cut(&error)),
        }),
    }
}

/// The path as text, within the record's limit.
fn cut_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let mut end = text.len().min(boxcar_proto::limits::MAX_PATH);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
5648d0a00000-5648d0a1d000 r--p 00000000 08:01 1234 /bin/busybox
7f3a1c000000-7f3a1c020000 r--p 00000000 08:01 5678 /lib/libssl.so.3
7f3a1c020000-7f3a1c0a0000 r-xp 00020000 08:01 5678 /lib/libssl.so.3
7f3a1c200000-7f3a1c300000 r-xp 00000000 08:01 9012 /lib/libcrypto.so.3
7f3a1c400000-7f3a1c401000 rw-p 00000000 00:00 0
7f3a1c500000-7f3a1c501000 rw-p 00000000 00:00 0 [stack]
7f3a1c600000-7f3a1c620000 r--p 00000000 08:01 3456 /usr/lib/libssl.so.1.1
";

    /// Waits for the resolver's pipe to say a result is in.
    fn wait_wake(attacher: &Attacher) {
        let mut fds = [libc::pollfd {
            fd: attacher.wake_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: poll reads and writes the one pollfd given.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 1, 5000) };
        assert_eq!(ready, 1, "the resolver answered within 5 s");
    }

    #[test]
    fn maps_lines_name_libssl() {
        assert_eq!(
            libssl_paths(MAPS),
            [
                PathBuf::from("/lib/libssl.so.3"),
                PathBuf::from("/usr/lib/libssl.so.1.1")
            ],
            "each library once, nothing else"
        );
        assert!(libssl_paths("").is_empty());
        assert!(libssl_paths("garbage\n[vdso]\n").is_empty());
    }

    #[test]
    fn a_path_is_tried_once() {
        let mut attacher = Attacher::new();
        assert!(attacher.wake_fd() >= 0, "a resolver");
        let threads = attacher.threads();
        assert_eq!(threads.len(), 1, "the resolver's thread is named");
        assert_ne!(threads[0], std::process::id(), "and is not the main thread");
        // A file that is not there: the resolver says so, once.
        let path = Path::new("/nonexistent/libssl.so.3");
        assert!(
            attacher.consider(path, 1).is_none(),
            "the outcome comes later"
        );
        wait_wake(&attacher);
        let frames = attacher.resolved(None, 2);
        assert_eq!(frames.len(), 1);
        let Payload::ProcTlsAttach(attach) = &frames[0].payload else {
            unreachable!()
        };
        assert!(!attach.ok);
        assert!(
            attach.error.as_deref().unwrap_or("").starts_with("stat:"),
            "{attach:?}"
        );
        assert_eq!(attach.path, "/nonexistent/libssl.so.3");
        assert_eq!(frames[0].ts_guest_ns, 2);
        // A second look says nothing.
        assert!(attacher.consider(path, 3).is_none());
        assert!(attacher.resolved(None, 4).is_empty());
        // A file that is no object.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"not an ELF").unwrap();
        assert!(attacher.consider(tmp.path(), 5).is_none());
        wait_wake(&attacher);
        let frames = attacher.resolved(None, 6);
        let Payload::ProcTlsAttach(attach) = &frames[0].payload else {
            unreachable!()
        };
        assert!(attach
            .error
            .as_deref()
            .unwrap_or("")
            .starts_with("not an object:"));
    }

    #[test]
    fn the_limit_is_64_paths_then_one_error() {
        let mut attacher = Attacher::new();
        for n in 0..MAX_PATHS {
            attacher.tried.insert(PathBuf::from(format!("/p{n}")));
        }
        let over = attacher
            .consider(Path::new("/one-more"), 1)
            .expect("the limit is reported");
        let Payload::ProcTlsAttach(attach) = over.payload else {
            unreachable!()
        };
        assert!(!attach.ok);
        assert_eq!(attach.error.as_deref(), Some("limit"));
        assert_eq!(attach.path, "/one-more");
        assert!(
            attacher.limit_reported && attacher.tried.len() == MAX_PATHS,
            "the path over the limit is not tried"
        );
        assert!(
            attacher.consider(Path::new("/two-more"), 2).is_none(),
            "said once"
        );
    }

    #[test]
    fn processes_are_swept_shortly_after_exec_then_every_second() {
        let start = Instant::now();
        let mut attacher = Attacher::new();
        assert_eq!(attacher.next_due(), None);
        attacher.saw(42, start);
        assert_eq!(attacher.next_due(), Some(start + FIRST_SWEEP));
        // A process that has gone (no maps to read) is forgotten.
        let frames = attacher.sweep(start + FIRST_SWEEP, 1);
        assert!(frames.is_empty());
        assert_eq!(attacher.next_due(), None);
        // This process is alive: its maps are read, and it is looked at
        // again a second later.
        let me = std::process::id();
        attacher.saw(me, start);
        attacher.sweep(start + FIRST_SWEEP, 1);
        assert_eq!(
            attacher.next_due(),
            Some(start + FIRST_SWEEP + SWEEP_INTERVAL)
        );
        attacher.gone(me);
        assert_eq!(attacher.next_due(), None);
    }

    /// The host's own OpenSSL, when it has one: its functions resolve to
    /// offsets inside the file, the entry and the `_ex` forms apart.
    #[test]
    fn symbols_are_resolved_from_a_shared_object() {
        let candidates = [
            "/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib64/libssl.so.3",
            "/lib/libssl.so.3",
        ];
        let Some(path) = candidates.iter().find(|p| Path::new(p).is_file()) else {
            eprintln!("skipped: no libssl.so.3 on this host");
            return;
        };
        let offsets = resolve(Path::new(path)).unwrap();
        let size = fs::metadata(path).unwrap().len();
        assert!(offsets.write > 0 && offsets.write < size);
        assert!(offsets.read > 0 && offsets.read < size);
        assert_ne!(offsets.write, offsets.read);
        assert!(offsets
            .write_ex
            .is_some_and(|o| o > 0 && o != offsets.write));
        assert!(offsets.read_ex.is_some_and(|o| o > 0 && o != offsets.read));
        // A program with no such symbols says which is missing first.
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap();
        let error = resolve(Path::new(shell)).unwrap_err();
        assert!(error.starts_with("SSL_write:"), "{error}");
    }

    #[test]
    fn the_frame_carries_the_outcome() {
        let ok = frame(Path::new("/lib/libssl.so.3"), Ok(()), 7);
        assert_eq!(ok.ts_guest_ns, 7);
        assert!(ok.subject.is_none());
        let Payload::ProcTlsAttach(attach) = ok.payload else {
            unreachable!()
        };
        assert!(attach.ok && attach.error.is_none());
        assert_eq!(attach.path, "/lib/libssl.so.3");
        let long = "x".repeat(boxcar_proto::limits::MAX_SUMMARY + 50);
        let bad = frame(Path::new("/bin/busybox"), Err(long), 8);
        let Payload::ProcTlsAttach(attach) = bad.payload else {
            unreachable!()
        };
        assert!(!attach.ok);
        assert_eq!(
            attach.error.map(|e| e.len()),
            Some(boxcar_proto::limits::MAX_SUMMARY)
        );
    }
}
