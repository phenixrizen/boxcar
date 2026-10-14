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

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use aya::programs::uprobe::{UProbeAttachLocation, UProbeScope};
use aya::programs::UProbe;
use aya::Ebpf;
use boxcar_proto::sensor::SensorFrame;
use boxcar_proto::{Payload, ProcTlsAttach};
use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::FileHeader;
use object::read::ReadRef;
use object::{Endianness, Object, ObjectSection, ObjectSymbol};

use crate::status::cut;

/// The most paths tried in a session.
pub const MAX_PATHS: usize = 64;
/// How long after a process's exec its maps are first looked at.
pub const FIRST_SWEEP: Duration = Duration::from_millis(50);
/// How often a live process's maps are looked at after that.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// The most processes followed at once.
const MAX_TGIDS: usize = 4096;
/// The largest file looked at for symbols.
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// The most bytes read out of a file for its symbols: its headers, its
/// symbol tables and their names together, all the resolver holds of it
/// at once, however large the file. A runtime with OpenSSL linked in
/// (Node's 120 MB binary) needs about 25 MiB.
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
/// The most of a name read; a longer one is refused, as object's own
/// cache does.
const MAX_NAME_READ: u64 = 4096;
/// How much of a name is read at a time, so a short one costs a short
/// read.
const NAME_CHUNK: u64 = 256;
/// The most bytes read from a file for its symbols, kept or not: what one
/// candidate may cost the shares and the resolver's time, whatever its
/// layout.
const MAX_IO_BYTES: u64 = 256 * 1024 * 1024;
/// The most names read from a file. A runtime's tables hold a couple of
/// hundred thousand at most (Node's, about 180,000).
const MAX_NAMES: u64 = 262_144;
/// What every read costs past its bytes: the allocator's header for its
/// buffer and its slot in the list of reads, that list's growth included.
const ENTRY_COST: u64 = 96;
/// The most sections a file may declare to be parsed for its symbols:
/// what object keeps for each section is not a read, so it is bounded by
/// count. Libraries and programs have a few dozen.
const MAX_SECTIONS: usize = 4096;

/// Where the four functions sit in a file, as offsets from its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offsets {
    pub write: u64,
    pub read: u64,
    /// The `_ex` forms are newer; a runtime may lack them.
    pub write_ex: Option<u64>,
    pub read_ex: Option<u64>,
}

/// A path's symbols, found or not, with the file they were read from:
/// the programs attach to that file, whatever the path names by then.
struct Resolved {
    path: PathBuf,
    offsets: Result<(Offsets, File), String>,
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
                    let offsets = resolve_file(&path);
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
                // Through the descriptor: the file read, not whatever the
                // path names now.
                (Ok((offsets, file)), Some(ebpf)) => attach_all(
                    ebpf,
                    Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd())),
                    offsets,
                ),
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
#[cfg(test)]
fn resolve(path: &Path) -> Result<Offsets, String> {
    resolve_file(path).map(|(offsets, _)| offsets)
}

/// `path`'s file, opened once: its links followed to the real path first
/// (a program is often reached through one), then opened without
/// following a link or waiting on what is not a file. Only a regular file
/// of at most [`MAX_FILE_BYTES`] is taken: a path the guest swapped for a
/// device or a pipe is refused, never read or waited on.
fn open_regular(path: &Path) -> Result<File, String> {
    let real = fs::canonicalize(path).map_err(|error| format!("resolve: {error}"))?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&real)
        .map_err(|error| format!("open: {error}"))?;
    let meta = file.metadata().map_err(|error| format!("stat: {error}"))?;
    if !meta.is_file() {
        return Err("not a regular file".to_owned());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{} bytes: too large to read for symbols",
            meta.len()
        ));
    }
    Ok(file)
}

/// Reads `path` and finds the four functions (`SSL_write` and `SSL_read`
/// must be there, exported or in the symbol table), with the file they
/// were read from. Only the parts of the file the symbols need are read,
/// within [`MAX_READ_BYTES`].
fn resolve_file(path: &Path) -> Result<(Offsets, File), String> {
    let file = open_regular(path)?;
    let len = file
        .metadata()
        .map_err(|error| format!("stat: {error}"))?
        .len();
    let (offsets, over) = {
        let data = Budgeted::new(&file, len);
        (symbols(&data), data.over.get())
    };
    if let Some(over) = over {
        return Err(over.to_string());
    }
    offsets.map(|offsets| (offsets, file))
}

/// A file read on demand for object's parser, each read kept in a buffer
/// of its own for the parse and charged against [`MAX_READ_BYTES`] before
/// it is made: past the budget a read fails and nothing more is read.
/// Nothing is rehashed or copied, so what it holds is what it charged. A
/// range read twice gives the same bytes, so what [`section_count`]
/// checks is what object parses, whatever a writer does to the file.
struct Budgeted<'f> {
    file: &'f File,
    len: u64,
    /// Every range read, by offset and size, owned here until drop.
    ranges: RefCell<BTreeMap<(u64, u64), *mut [u8]>>,
    /// Every name read, owned here until drop.
    names: RefCell<Vec<*mut [u8]>>,
    /// Bytes it may still hold.
    left: Cell<u64>,
    /// Bytes it may still read, kept or not.
    io_left: Cell<u64>,
    /// Names it may still read.
    names_left: Cell<u64>,
    /// Which budget ran out, if one did.
    over: Cell<Option<Over>>,
}

/// A budget a resolve ran out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Over {
    Memory,
    Reads,
    Names,
}

impl std::fmt::Display for Over {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Over::Memory => write!(
                f,
                "its symbols take more than {} MiB to read",
                MAX_READ_BYTES >> 20
            ),
            Over::Reads => write!(
                f,
                "its symbols take more than {} MiB of reads",
                MAX_IO_BYTES >> 20
            ),
            Over::Names => write!(f, "it has more than {MAX_NAMES} names to read"),
        }
    }
}

impl<'f> Budgeted<'f> {
    fn new(file: &'f File, len: u64) -> Budgeted<'f> {
        Budgeted {
            file,
            len,
            ranges: RefCell::new(BTreeMap::new()),
            names: RefCell::new(Vec::new()),
            left: Cell::new(MAX_READ_BYTES),
            io_left: Cell::new(MAX_IO_BYTES),
            names_left: Cell::new(MAX_NAMES),
            over: Cell::new(None),
        }
    }

    fn charge(&self, bytes: u64) -> Result<(), ()> {
        self.spend(&self.left, bytes, Over::Memory)
    }

    /// Takes `amount` from `budget`, or marks it run out.
    fn spend(&self, budget: &Cell<u64>, amount: u64, over: Over) -> Result<(), ()> {
        match budget.get().checked_sub(amount) {
            Some(left) => {
                budget.set(left);
                Ok(())
            }
            None => {
                self.over.set(Some(over));
                Err(())
            }
        }
    }

    fn refund(&self, bytes: u64) {
        self.left.set(self.left.get().saturating_add(bytes));
    }

    /// Reads up to `buf.len()` bytes at `offset`, fewer only at the end
    /// of the file.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ()> {
        self.spend(&self.io_left, buf.len() as u64, Over::Reads)?;
        let mut done = 0;
        while done < buf.len() {
            match self.file.read_at(&mut buf[done..], offset + done as u64) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(()),
            }
        }
        Ok(done)
    }
}

impl Drop for Budgeted<'_> {
    fn drop(&mut self) {
        let ranges = std::mem::take(self.ranges.get_mut());
        let names = std::mem::take(self.names.get_mut());
        for owned in ranges.into_values().chain(names) {
            // SAFETY: each pointer came from `Box::into_raw` and is freed
            // here once; no slice lent from it outlives `self`.
            drop(unsafe { Box::from_raw(owned) });
        }
    }
}

/// `owned`'s bytes, lent for as long as the store that owns it.
///
/// # Safety
///
/// `owned` came from `Box::into_raw`, is held by a [`Budgeted`] that frees
/// it only when dropped, and is never written again.
unsafe fn lend<'a>(owned: *mut [u8]) -> &'a [u8] {
    // SAFETY: as the caller promises.
    unsafe { &*owned }
}

impl<'a> ReadRef<'a> for &'a Budgeted<'_> {
    fn len(self) -> Result<u64, ()> {
        Ok(self.len)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        if size == 0 {
            return Ok(&[]);
        }
        if let Some(&owned) = self.ranges.borrow().get(&(offset, size)) {
            // SAFETY: an owned read of this store, never written again.
            return Ok(unsafe { lend(owned) });
        }
        if offset.checked_add(size).is_none_or(|end| end > self.len) {
            return Err(());
        }
        self.charge(size.saturating_add(ENTRY_COST))?;
        let mut bytes = vec![0; usize::try_from(size).map_err(|_| ())?].into_boxed_slice();
        if self.read_at(&mut bytes, offset)? != bytes.len() {
            return Err(());
        }
        let owned = Box::into_raw(bytes);
        self.ranges.borrow_mut().insert((offset, size), owned);
        // SAFETY: just made from a box and kept by this store.
        Ok(unsafe { lend(owned) })
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        if range.start > range.end || range.end > self.len {
            return Err(());
        }
        self.spend(&self.names_left, 1, Over::Names)?;
        let most = (range.end - range.start).min(MAX_NAME_READ);
        self.charge(most + ENTRY_COST)?;
        let mut bytes = Vec::new();
        let end = loop {
            let from = bytes.len();
            let chunk = NAME_CHUNK.min(most - from as u64) as usize;
            if chunk == 0 {
                return Err(());
            }
            bytes.resize(from + chunk, 0);
            let read = self.read_at(&mut bytes[from..], range.start + from as u64)?;
            bytes.truncate(from + read);
            if let Some(at) = bytes[from..].iter().position(|&b| b == delimiter) {
                break from + at;
            }
            if read < chunk {
                return Err(());
            }
        };
        bytes.truncate(end);
        self.refund(most - end as u64);
        let owned = Box::into_raw(bytes.into_boxed_slice());
        self.names.borrow_mut().push(owned);
        // SAFETY: just made from a box and kept by this store.
        Ok(unsafe { lend(owned) })
    }
}

/// How many sections the ELF file `data` declares, from its header (and
/// its first section header, where the count is too large for the
/// header): read before object parses the rest. Anything but ELF is
/// refused here, before object's generic parser (which other crates'
/// features can widen to more formats) allocates anything for it.
fn section_count<'a, R: ReadRef<'a>>(data: R) -> Result<usize, String> {
    fn count<'a, H: FileHeader, R: ReadRef<'a>>(data: R) -> object::read::Result<usize> {
        let header = H::parse(data)?;
        header.shnum(header.endian()?, data)
    }
    let counted = match object::FileKind::parse(data) {
        Ok(object::FileKind::Elf32) => count::<FileHeader32<Endianness>, R>(data),
        Ok(object::FileKind::Elf64) => count::<FileHeader64<Endianness>, R>(data),
        _ => return Err("not an object: not ELF".to_owned()),
    };
    counted.map_err(|error| format!("not an object: {error}"))
}

/// The four functions' offsets in the object `data`, its symbols read
/// once: the dynamic ones first, then the symbol table.
fn symbols<'a, R: ReadRef<'a>>(data: R) -> Result<Offsets, String> {
    const NAMES: [&str; 4] = ["SSL_write", "SSL_read", "SSL_write_ex", "SSL_read_ex"];
    let sections = section_count(data)?;
    if sections > MAX_SECTIONS {
        return Err(format!(
            "{sections} sections: more than {MAX_SECTIONS} to parse for symbols"
        ));
    }
    let file_len = data.len().unwrap_or(0);
    let obj = object::File::parse(data).map_err(|error| format!("not an object: {error}"))?;
    let mut found = [None; 4];
    for sym in obj.dynamic_symbols().chain(obj.symbols()) {
        if sym.address() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else {
            continue;
        };
        if let Some(at) = NAMES.iter().position(|n| *n == name) {
            found[at].get_or_insert((sym.address(), sym.section_index()));
            if found.iter().all(Option::is_some) {
                break;
            }
        }
    }
    let translate = matches!(
        obj.kind(),
        object::ObjectKind::Dynamic | object::ObjectKind::Executable
    );
    let offset = |at: usize| -> Result<Option<u64>, String> {
        let Some((address, index)) = found[at] else {
            return Ok(None);
        };
        if !translate {
            return Ok(Some(address));
        }
        let name = NAMES[at];
        let index = index.ok_or_else(|| format!("{name}: not in a section"))?;
        let section = obj
            .section_by_index(index)
            .map_err(|error| format!("{name}: {error}"))?;
        let (file_offset, size) = section
            .file_range()
            .ok_or_else(|| format!("{name}: its section has no bytes in the file"))?;
        let offset = address
            .checked_sub(section.address())
            .filter(|within| *within < size)
            .and_then(|within| file_offset.checked_add(within))
            .filter(|offset| *offset < file_len)
            .ok_or_else(|| format!("{name}: outside its section"))?;
        Ok(Some(offset))
    };
    let write = offset(0)?.ok_or_else(|| "SSL_write: not exported".to_owned())?;
    let read = offset(1)?.ok_or_else(|| "SSL_read: not exported".to_owned())?;
    Ok(Offsets {
        write,
        read,
        write_ex: offset(2)?,
        read_ex: offset(3)?,
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

/// A test-only allocator that keeps, per thread, what the thread holds
/// and the most it held: what a resolve really takes, cache entries and
/// object's own allocations included.
#[cfg(test)]
mod meter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static HELD: Cell<usize> = const { Cell::new(0) };
        static PEAK: Cell<usize> = const { Cell::new(0) };
    }

    pub struct Meter;

    // SAFETY: every call goes to the system allocator with the caller's
    // arguments; the counting only touches this thread's cells.
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's layout, as GlobalAlloc requires.
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                held(layout.size() as isize);
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` came from `alloc` with this layout.
            unsafe { System.dealloc(ptr, layout) };
            held(-(layout.size() as isize));
        }
    }

    fn held(change: isize) {
        let _ = HELD.try_with(|held| {
            let now = held.get().saturating_add_signed(change);
            held.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    /// `f`'s result and the most this thread held while it ran, past what
    /// it held before.
    pub fn peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
        let before = HELD.with(Cell::get);
        PEAK.with(|peak| peak.set(before));
        let out = f();
        (out, PEAK.with(Cell::get).saturating_sub(before))
    }
}

#[cfg(test)]
#[global_allocator]
static METER: meter::Meter = meter::Meter;

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
            attach
                .error
                .as_deref()
                .unwrap_or("")
                .starts_with("resolve:"),
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
        // Above any pid_max (at most 2^22): no such process, ever.
        let gone = u32::MAX - 1;
        attacher.saw(gone, start);
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
        // Through a link, the file it names.
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("libssl.so.3");
        std::os::unix::fs::symlink(path, &link).unwrap();
        assert_eq!(resolve(&link).unwrap(), offsets);
    }

    /// A file whose symbol table claims hundreds of MiB (sparse, so it
    /// costs nothing on disk) is refused once its reads pass the budget,
    /// never read into memory whole.
    #[test]
    fn a_symbol_table_past_the_read_budget_is_refused() {
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap();
        let mut elf = fs::read(fs::canonicalize(shell).unwrap()).unwrap();
        let word = |at: usize| usize::from(u16::from_le_bytes([elf[at], elf[at + 1]]));
        let (entry, count) = (word(0x3a), word(0x3c));
        let headers = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
        const SHT_DYNSYM: u32 = 11;
        let at = (0..count)
            .map(|n| headers + n * entry)
            .find(|&at| u32::from_le_bytes(elf[at + 4..at + 8].try_into().unwrap()) == SHT_DYNSYM)
            .expect("a dynamic symbol table");
        let (offset, size): (u64, u64) = (16 << 20, 24 * (16 << 20));
        elf[at + 0x18..at + 0x20].copy_from_slice(&offset.to_le_bytes());
        elf[at + 0x20..at + 0x28].copy_from_slice(&size.to_le_bytes());
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("libssl.so.3");
        fs::write(&path, &elf).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(offset + size)
            .unwrap();
        let (result, peak) = meter::peak(|| resolve(&path));
        let error = result.unwrap_err();
        assert!(error.contains("more than 64 MiB"), "{error}");
        assert!(peak < (MAX_READ_BYTES + (1 << 20)) as usize, "{peak}");
    }

    /// A file that declares more sections than a program has (counted in
    /// its first section header, the form for counts past 65535) is
    /// refused before it is parsed, and the resolver holds next to
    /// nothing for it.
    #[test]
    fn a_file_with_too_many_sections_is_refused_before_parsing() {
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap();
        let mut elf = fs::read(fs::canonicalize(shell).unwrap()).unwrap();
        let count: u64 = 100_000;
        let headers: u64 = 16 << 20;
        elf[0x28..0x30].copy_from_slice(&headers.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&0u16.to_le_bytes());
        elf[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes());
        elf.resize(headers as usize + 64, 0);
        let first = headers as usize;
        elf[first + 0x20..first + 0x28].copy_from_slice(&count.to_le_bytes());
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("libssl.so.3");
        fs::write(&path, &elf).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(headers + count * 64)
            .unwrap();
        let (result, peak) = meter::peak(|| resolve(&path));
        let error = result.unwrap_err();
        assert!(error.contains("more than 4096 to parse"), "{error}");
        assert!(peak < 1 << 20, "{peak}");
    }

    /// A symbol table of 600,000 symbols, each with an address and a name
    /// of its own (short names, so the reads are many and small): the
    /// resolver stops at the budget, and what it holds at its peak, every
    /// buffer and its list of reads included, stays within it.
    #[test]
    fn many_small_names_stay_within_the_budget() {
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap();
        let mut elf = fs::read(fs::canonicalize(shell).unwrap()).unwrap();
        let word = |elf: &[u8], at: usize| usize::from(u16::from_le_bytes([elf[at], elf[at + 1]]));
        let (entry, count) = (word(&elf, 0x3a), word(&elf, 0x3c));
        let headers = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
        const SHT_DYNSYM: u32 = 11;
        let dynsym = (0..count)
            .map(|n| headers + n * entry)
            .find(|&at| u32::from_le_bytes(elf[at + 4..at + 8].try_into().unwrap()) == SHT_DYNSYM)
            .expect("a dynamic symbol table");
        let link = u32::from_le_bytes(elf[dynsym + 0x28..dynsym + 0x2c].try_into().unwrap());
        let dynstr = headers + link as usize * entry;
        let symbols: u64 = 600_000;
        elf.resize(elf.len().next_multiple_of(8), 0);
        let table = elf.len() as u64;
        for n in 0..symbols {
            let mut sym = [0u8; 24];
            sym[0..4].copy_from_slice(&(1 + 2 * n as u32).to_le_bytes());
            sym[4] = 0x12;
            sym[6..8].copy_from_slice(&1u16.to_le_bytes());
            sym[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
            elf.extend_from_slice(&sym);
        }
        let names = elf.len() as u64;
        elf.push(0);
        for _ in 0..symbols {
            elf.extend_from_slice(b"a\0");
        }
        let set = |elf: &mut Vec<u8>, at: usize, value: u64| {
            elf[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        set(&mut elf, dynsym + 0x18, table);
        set(&mut elf, dynsym + 0x20, symbols * 24);
        set(&mut elf, dynstr + 0x18, names);
        set(&mut elf, dynstr + 0x20, 1 + 2 * symbols);
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("libssl.so.3");
        fs::write(&path, &elf).unwrap();
        let (result, peak) = meter::peak(|| resolve(&path));
        let error = result.unwrap_err();
        assert_eq!(error, format!("it has more than {MAX_NAMES} names to read"));
        assert!(peak < MAX_READ_BYTES as usize, "{peak}");
        // What it read, kept or not, is a part of the reads' budget: a
        // short name is a short read.
        let file = File::open(&path).unwrap();
        let data = Budgeted::new(&file, elf.len() as u64);
        assert!(super::symbols(&data).is_err());
        let read = MAX_IO_BYTES - data.io_left.get();
        assert!(read < 100 << 20, "{read}");
    }

    /// A symbol whose address lies outside its section (the library's
    /// `SSL_write` moved below `.text`) is refused, never translated into
    /// a wrapped offset or a panic.
    #[test]
    fn a_symbol_outside_its_section_is_refused() {
        let Some(path) = host_libssl() else {
            eprintln!("skipped: no libssl on this host");
            return;
        };
        let mut elf = fs::read(fs::canonicalize(path).unwrap()).unwrap();
        let at = {
            let obj = object::File::parse(&*elf).unwrap();
            let sym = obj
                .dynamic_symbols()
                .find(|s| s.name() == Ok("SSL_write"))
                .unwrap();
            let (table, _) = obj
                .section_by_name(".dynsym")
                .unwrap()
                .file_range()
                .unwrap();
            table as usize + sym.index().0 * 24
        };
        elf[at + 8..at + 16].copy_from_slice(&1u64.to_le_bytes());
        let tmp = tempfile::tempdir().unwrap();
        let moved = tmp.path().join("libssl.so.3");
        fs::write(&moved, &elf).unwrap();
        assert_eq!(
            resolve(&moved).unwrap_err(),
            "SSL_write: outside its section"
        );
    }

    /// A range read twice gives the bytes of its first read: a header
    /// rewritten on disk between the section check and the parse (to
    /// declare a million sections) is not what object parses.
    #[test]
    fn the_parse_sees_the_header_the_check_saw() {
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap();
        let elf = fs::read(fs::canonicalize(shell).unwrap()).unwrap();
        let declared = usize::from(u16::from_le_bytes([elf[0x3c], elf[0x3d]]));
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("libssl.so.3");
        fs::write(&path, &elf).unwrap();
        let file = File::open(&path).unwrap();
        let data = Budgeted::new(&file, elf.len() as u64);
        assert_eq!(section_count(&data).unwrap(), declared);
        let mut changed = elf.clone();
        changed[0x3c..0x3e].copy_from_slice(&0u16.to_le_bytes());
        let first = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
        changed[first + 0x20..first + 0x28].copy_from_slice(&1_000_000u64.to_le_bytes());
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all_at(&changed[..first + 64], 0)
            .unwrap();
        assert_eq!(section_count(&data).unwrap(), declared);
        let obj = object::File::parse(&data).unwrap();
        // object leaves out section 0, the null one.
        assert_eq!(obj.sections().count(), declared - 1);
    }

    /// A file in another object format (Mach-O, which object can parse
    /// when other crates ask for it) is refused before it is parsed, and
    /// the resolver holds next to nothing for it.
    #[test]
    fn only_elf_is_parsed() {
        let mut macho = vec![0u8; 4096];
        macho[0..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        macho[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("libssl.so.3");
        fs::write(&path, &macho).unwrap();
        let (result, peak) = meter::peak(|| resolve(&path));
        assert_eq!(result.unwrap_err(), "not an object: not ELF");
        assert!(peak < 1 << 16, "{peak}");
    }

    /// The host's OpenSSL, 3 or 1.1, when it has one.
    fn host_libssl() -> Option<&'static str> {
        [
            "/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib64/libssl.so.3",
            "/lib/libssl.so.3",
            "/lib/x86_64-linux-gnu/libssl.so.1.1",
            "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        ]
        .into_iter()
        .find(|p| Path::new(p).is_file())
    }

    /// The host's OpenSSL resolves within a small part of the budget.
    #[test]
    fn a_library_resolves_within_a_small_part_of_the_budget() {
        let Some(path) = host_libssl() else {
            eprintln!("skipped: no libssl on this host");
            return;
        };
        let (result, peak) = meter::peak(|| resolve(Path::new(path)));
        assert!(result.is_ok(), "{result:?}");
        assert!(peak < 16 << 20, "{peak}");
    }

    /// A path that names a device or a pipe is refused at once: never read
    /// without end, never waited on.
    #[test]
    fn only_a_regular_file_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let zero = tmp.path().join("libssl.so.3");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        let fifo = tmp.path().join("libssl.so.1.1");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid C string, and mkfifo makes a node.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send((resolve(&zero), resolve(&fifo)));
        });
        let (zero, fifo) = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the resolver waited");
        assert_eq!(zero.unwrap_err(), "not a regular file");
        assert_eq!(fifo.unwrap_err(), "not a regular file");
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
