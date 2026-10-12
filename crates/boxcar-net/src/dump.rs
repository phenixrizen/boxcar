// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Dump mode (`boxcar run --dump DIR`): a debugging aid beside the audit
//! log, after bitvessel's `DebugNet`. Nothing in it is hashed or chained.
//!
//! - `frames.pcap`: every frame the guest sent and every frame the stack
//!   gave it, as pcap 2.4 (little endian, microsecond timestamps,
//!   Ethernet), cut after the frame's headers ([`headers_len`]): a TCP
//!   payload is not written, plain HTTP's credentials included; each
//!   record keeps the frame's original length. With `--dump-payloads`
//!   ([`DumpDir::with_payloads`]) the frames the gate sends the guest on
//!   a flow whose TLS it ended are written whole ([`GateTls`]): the
//!   gate's own TLS records, ciphertext whose keys never leave the VMM.
//!   What the guest sends is cut whatever it looks like, and so is every
//!   other flow's payload, a plain HTTP flow's included.
//!   The net thread copies each frame into a bounded channel
//!   with `try_send`; the `dump` thread writes them. A frame the channel
//!   had no room for is dropped and counted (`net.drop{reason:"dump"}`):
//!   the net thread never waits on the dump.
//! - `http/<flow>-<stream>.req` and `.resp`: each decoded exchange of an
//!   inspected flow, written by the observer thread: the start line, the
//!   headers as the observer keeps them (a credential header's value never
//!   reaches it), a blank line, the decoded body, with a JSON body's
//!   secret-looking fields and a form body's credential fields scrubbed.
//!   The raw plaintext is not written: it would hold the credentials the
//!   records never do.
//! - `http/<flow>-<stream>.ws`: the messages of an exchange upgraded to
//!   WebSocket, one after another, each as a line naming the direction
//!   (`c2s`, `s2c`) and the size, then the text (scrubbed as a JSON body
//!   is) for a text message.
//!
//! The directory is made mode 0700, every file 0600, and it may be
//! neither a share nor inside one, nor hold one: the audit directory's
//! rule.

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddrV4;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use boxcar_proto::redact::{scrub_target, scrub_text};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

use crate::http::headers::is_credential;
use crate::http::SseParser;

/// How many frames may wait for the `dump` thread.
pub const FRAME_QUEUE: usize = 4096;
/// The pcap snapshot length: the most of a frame a record could hold
/// (records hold a frame's headers, [`headers_len`]).
pub const SNAPLEN: u32 = 65535;
/// The pcap global header's magic, for microsecond timestamps.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
/// `LINKTYPE_ETHERNET`.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// The most bytes of a head or a body written to an exchange file.
pub const EXCHANGE_FILE_LIMIT: usize = 16 * 1024 * 1024;

/// The dump directory, checked and made.
#[derive(Clone, Debug)]
pub struct DumpDir {
    path: PathBuf,
    /// `frames.pcap` keeps TLS connections' payloads (`--dump-payloads`).
    payloads: bool,
}

impl DumpDir {
    /// Makes `dir` (mode 0700) unless it exists, and refuses one that is a
    /// share, is inside one, or holds one. `shares` are the shares' paths,
    /// resolved. The directory itself is resolved through its parent, so a
    /// link into a share is found. An existing directory must be empty:
    /// each run's dump is its own, and nothing already in it (a link to
    /// another file, say) is ever written through.
    pub fn prepare(dir: &Path, shares: &[&Path]) -> io::Result<DumpDir> {
        let resolved = resolve(dir)?;
        for share in shares {
            if resolved.starts_with(share) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "dump dir {} is inside share {}",
                        resolved.display(),
                        share.display()
                    ),
                ));
            }
            if share.starts_with(&resolved) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "share {} is inside dump dir {}",
                        share.display(),
                        resolved.display()
                    ),
                ));
            }
        }
        match fs::create_dir(&resolved) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !fs::symlink_metadata(&resolved)?.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("dump dir {} is not a directory", resolved.display()),
                    ));
                }
                if fs::read_dir(&resolved)?.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("dump dir {} is not empty", resolved.display()),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        fs::set_permissions(&resolved, fs::Permissions::from_mode(0o700))?;
        // Made here, so it is a directory and not a link to one.
        let http = resolved.join("http");
        fs::create_dir(&http)?;
        fs::set_permissions(&http, fs::Permissions::from_mode(0o700))?;
        Ok(DumpDir {
            path: resolved,
            payloads: false,
        })
    }

    /// The dump with `frames.pcap` keeping the payloads of TLS
    /// flows' gate side when `payloads` ([`GateTls`]).
    pub fn with_payloads(mut self, payloads: bool) -> DumpDir {
        self.payloads = payloads;
        self
    }

    /// Whether `frames.pcap` keeps TLS connections' payloads.
    pub fn payloads(&self) -> bool {
        self.payloads
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `frames.pcap`.
    pub fn frames(&self) -> PathBuf {
        self.path.join("frames.pcap")
    }

    /// `http/<flow>-<stream>.req` or `.resp`.
    pub fn exchange_file(&self, flow: u64, stream: u32, request: bool) -> PathBuf {
        let ext = if request { "req" } else { "resp" };
        self.path
            .join("http")
            .join(format!("{flow}-{stream}.{ext}"))
    }

    /// `http/<flow>-<stream>.ws`.
    pub fn ws_file(&self, flow: u64, stream: u32) -> PathBuf {
        self.path.join("http").join(format!("{flow}-{stream}.ws"))
    }
}

/// `dir` as an absolute path with its existing part's links resolved: the
/// directory itself may not exist yet.
fn resolve(dir: &Path) -> io::Result<PathBuf> {
    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    if let Ok(real) = fs::canonicalize(&absolute) {
        return Ok(real);
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the dump dir has no parent"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the dump dir has no name"))?;
    if name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the dump dir ends in a directory that does not exist",
        ));
    }
    Ok(fs::canonicalize(parent)?.join(name))
}

/// A new file of the dump, created 0600. Nothing may be there already,
/// and a link is never followed.
pub fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

// --- the frames

/// One frame on its way to the `dump` thread.
struct Frame {
    at: SystemTime,
    /// The frame's headers ([`headers_len`]); in payload mode, the whole
    /// of a frame to the guest.
    bytes: Vec<u8>,
    /// The whole frame's length.
    len: usize,
    /// The stack sent it to the guest.
    to_guest: bool,
}

/// What the `dump` thread is told, in order.
enum Item {
    Frame(Frame),
    /// The gate ended this connection's TLS (payload mode).
    GateTls(ConnKey),
}

/// The net thread's end of the frame dump. Cheap to clone: every stack of
/// the device feeds the same file.
#[derive(Clone)]
pub struct FrameDump {
    tx: Sender<Item>,
    /// Frames to the guest go whole to the thread, which cuts them
    /// ([`GateTls`]).
    payloads: bool,
}

impl FrameDump {
    /// Opens `frames.pcap` in `dir`, writes its header, and starts the
    /// `dump` thread that writes the frames.
    pub fn start(dir: &DumpDir) -> io::Result<(FrameDump, DumpThread)> {
        let mut file = create(&dir.frames())?;
        file.write_all(&pcap_header())?;
        let (tx, rx) = bounded(FRAME_QUEUE);
        let payloads = dir.payloads();
        let thread = thread::Builder::new()
            .name("dump".into())
            .spawn(move || write_frames(rx, file, payloads.then(GateTls::default)))?;
        Ok((FrameDump { tx, payloads }, DumpThread { thread }))
    }

    /// Queues a frame the guest sent for the file, cut to its headers,
    /// and says whether there was room; the caller counts one there was
    /// not. Never waits.
    pub fn push_from_guest(&self, bytes: &[u8]) -> bool {
        self.push(bytes, headers_len(bytes), false)
    }

    /// Queues a frame the stack sent the guest: whole in payload mode,
    /// for the thread to cut ([`GateTls`]), else cut to its headers.
    pub fn push_to_guest(&self, bytes: &[u8]) -> bool {
        let kept = if self.payloads {
            bytes.len()
        } else {
            headers_len(bytes)
        };
        self.push(bytes, kept, true)
    }

    fn push(&self, bytes: &[u8], kept: usize, to_guest: bool) -> bool {
        let frame = Frame {
            at: SystemTime::now(),
            bytes: bytes[..kept].to_vec(),
            len: bytes.len(),
            to_guest,
        };
        match self.tx.try_send(Item::Frame(frame)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// The gate ended the TLS of the connection between `guest` and
    /// `remote`: in payload mode, what it sends the guest on it is kept.
    /// With no room to say so, it is cut like the rest.
    pub fn gate_tls(&self, guest: SocketAddrV4, remote: SocketAddrV4) {
        if self.payloads {
            let _ = self.tx.try_send(Item::GateTls(conn_key(guest, remote)));
        }
    }
}

/// The `dump` thread, which ends when every [`FrameDump`] is gone and the
/// queue is drained.
pub struct DumpThread {
    thread: JoinHandle<()>,
}

impl DumpThread {
    /// Waits at most `limit` for the thread to end, then joins it; one
    /// still busy is left behind. Whether it was joined.
    pub fn join(self, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        while !self.thread.is_finished() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.thread.join().is_ok()
    }
}

/// The thread's body: each frame as a pcap record, cut by `gate` in
/// payload mode. A write that fails ends the file; the frames keep being
/// taken so the queue drains.
fn write_frames(rx: Receiver<Item>, file: File, mut gate: Option<GateTls>) {
    let mut out = io::BufWriter::new(file);
    let mut failed = false;
    for item in rx {
        let frame = match item {
            Item::Frame(frame) => frame,
            Item::GateTls(key) => {
                if let Some(gate) = gate.as_mut() {
                    gate.mark(key);
                }
                continue;
            }
        };
        let kept = match gate.as_mut() {
            Some(gate) => gate.kept_len(&frame.bytes, frame.to_guest),
            None => frame.bytes.len(),
        };
        if failed {
            continue;
        }
        if out
            .write_all(&pcap_record(frame.at, &frame.bytes[..kept], frame.len))
            .is_err()
        {
            failed = true;
        }
    }
    let _ = out.flush();
}

/// The pcap 2.4 global header: microsecond timestamps, Ethernet.
pub fn pcap_header() -> [u8; 24] {
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&2u16.to_le_bytes());
    header[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone 0 and sigfigs 0 are already zero.
    header[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
    header[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    header
}

/// One pcap record: its 16-byte header, then `frame` (the part of a frame
/// `len` long that is kept), cut at [`SNAPLEN`].
pub fn pcap_record(at: SystemTime, frame: &[u8], len: usize) -> Vec<u8> {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = u32::try_from(since.as_secs()).unwrap_or(u32::MAX);
    let kept = frame.len().min(SNAPLEN as usize);
    let mut out = Vec::with_capacity(16 + kept);
    out.extend_from_slice(&secs.to_le_bytes());
    out.extend_from_slice(&since.subsec_micros().to_le_bytes());
    out.extend_from_slice(&(kept as u32).to_le_bytes());
    out.extend_from_slice(&(len.max(kept).min(u32::MAX as usize) as u32).to_le_bytes());
    out.extend_from_slice(&frame[..kept]);
    out
}

/// The most connections payload mode remembers as the gate's TLS; past
/// it the oldest goes, and its later frames are cut.
const MAX_GATE_TLS: usize = 4096;

/// A TCP connection by its two ends, the lesser first: the same either
/// way.
type ConnKey = (([u8; 16], u16), ([u8; 16], u16));

/// The key of the connection between `a` and `b`.
fn conn_key(a: SocketAddrV4, b: SocketAddrV4) -> ConnKey {
    let end = |addr: SocketAddrV4| {
        let mut ip = [0u8; 16];
        ip[..4].copy_from_slice(&addr.ip().octets());
        (ip, addr.port())
    };
    let (a, b) = (end(a), end(b));
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Payload mode's view: the connections whose TLS the gate ended, as the
/// relay said ([`FrameDump::gate_tls`]). A frame to the guest on one of
/// them is written whole: its payload is the gate's own TLS records. Every
/// other frame is cut as [`headers_len`] cuts it, and the guest's own
/// frames always are, whatever they hold. The guest opening a connection
/// on the same ends again (its SYN) forgets the earlier one.
#[derive(Debug, Default)]
pub struct GateTls {
    conns: HashSet<ConnKey>,
    order: VecDeque<ConnKey>,
}

impl GateTls {
    /// The gate ended the TLS of connection `key`.
    pub fn mark(&mut self, key: ConnKey) {
        if self.conns.insert(key) {
            self.order.push_back(key);
        }
        while self.order.len() > MAX_GATE_TLS {
            if let Some(oldest) = self.order.pop_front() {
                self.conns.remove(&oldest);
            }
        }
    }

    /// How much of `frame` payload mode keeps.
    pub fn kept_len(&mut self, frame: &[u8], to_guest: bool) -> usize {
        let headers = headers_len(frame);
        let Some(segment) = tcp_segment(frame) else {
            return headers;
        };
        if !to_guest {
            if segment.flags & (TCP_SYN | TCP_ACK) == TCP_SYN && self.conns.remove(&segment.key) {
                self.order.retain(|key| *key != segment.key);
            }
            return headers;
        }
        if self.conns.contains(&segment.key) && !segment.payload.is_empty() {
            segment.payload.end
        } else {
            headers
        }
    }
}

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// A TCP segment's connection, flags, and where its payload lies in the
/// frame (to the IP length's end, Ethernet padding left out).
struct Segment {
    key: ConnKey,
    flags: u8,
    payload: std::ops::Range<usize>,
}

/// The TCP segment `frame` carries over IPv4 or IPv6, if it does and its
/// headers fit.
fn tcp_segment(frame: &[u8]) -> Option<Segment> {
    const ETH: usize = 14;
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    let (src, dst, l4, end) = match ethertype {
        0x0800 => {
            let ihl = usize::from(frame.get(ETH)? & 0x0f) * 4;
            if ihl < 20 || *frame.get(ETH + 9)? != 6 {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([
                *frame.get(ETH + 2)?,
                *frame.get(ETH + 3)?,
            ]));
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src[..4].copy_from_slice(frame.get(ETH + 12..ETH + 16)?);
            dst[..4].copy_from_slice(frame.get(ETH + 16..ETH + 20)?);
            (src, dst, ETH + ihl, ETH + total)
        }
        0x86dd => {
            if *frame.get(ETH + 6)? != 6 {
                return None;
            }
            let len = usize::from(u16::from_be_bytes([
                *frame.get(ETH + 4)?,
                *frame.get(ETH + 5)?,
            ]));
            let src: [u8; 16] = frame.get(ETH + 8..ETH + 24)?.try_into().ok()?;
            let dst: [u8; 16] = frame.get(ETH + 24..ETH + 40)?.try_into().ok()?;
            (src, dst, ETH + 40, ETH + 40 + len)
        }
        _ => return None,
    };
    let tcp = frame.get(l4..l4 + 20)?;
    let ports = (
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
    );
    let start = l4 + usize::from(tcp[12] >> 4) * 4;
    let end = end.min(frame.len());
    if start > frame.len() {
        return None;
    }
    let (a, b) = ((src, ports.0), (dst, ports.1));
    Some(Segment {
        key: if a <= b { (a, b) } else { (b, a) },
        flags: tcp[13],
        payload: start..end.max(start),
    })
}

/// The UDP ports whose payload the frame dump keeps: DNS and DHCP, which
/// the gateway answers itself.
const KEPT_UDP_PORTS: [u16; 3] = [53, 67, 68];

/// How much of an Ethernet frame the frame dump keeps: the Ethernet,
/// IPv4 or IPv6, and TCP, UDP or ICMP headers, without the payload after
/// them. ARP is kept whole, and so is UDP to or from ports 53, 67 and 68
/// (DNS and DHCP).
/// A frame too short for what its headers say is kept to its Ethernet
/// header.
pub fn headers_len(frame: &[u8]) -> usize {
    const ETH: usize = 14;
    let ether_short = frame.len().min(ETH);
    if frame.len() < ETH {
        return frame.len();
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let (proto, l4) = match ethertype {
        0x0806 => return frame.len(),
        0x0800 => {
            let Some(&vihl) = frame.get(ETH) else {
                return ether_short;
            };
            let ihl = usize::from(vihl & 0x0f) * 4;
            match frame.get(ETH + 9) {
                Some(&proto) if ihl >= 20 => (proto, ETH + ihl),
                _ => return ether_short,
            }
        }
        0x86dd => match frame.get(ETH + 6) {
            Some(&next) => (next, ETH + 40),
            None => return ether_short,
        },
        _ => return ether_short,
    };
    let len = match proto {
        6 => match frame.get(l4 + 12) {
            Some(&offset) => l4 + usize::from(offset >> 4) * 4,
            None => return ether_short,
        },
        17 => {
            let ports = frame.get(l4..l4 + 4).map(|p| {
                [
                    u16::from_be_bytes([p[0], p[1]]),
                    u16::from_be_bytes([p[2], p[3]]),
                ]
            });
            match ports {
                Some(ports) if ports.iter().any(|p| KEPT_UDP_PORTS.contains(p)) => {
                    return frame.len()
                }
                _ => l4 + 8,
            }
        }
        1 | 58 => l4 + 8,
        _ => l4,
    };
    if len > frame.len() {
        ether_short
    } else {
        len
    }
}

// --- the exchanges

/// Writes one decoded exchange side: `head` (the start line and the
/// header lines, each ending in CRLF), a blank line, and `body` scrubbed
/// by `content_type` ([`scrubbed_body`]), each cut at
/// [`EXCHANGE_FILE_LIMIT`].
pub fn write_exchange(
    dir: &DumpDir,
    flow: u64,
    stream: u32,
    request: bool,
    head: &str,
    content_type: Option<&str>,
    body: Result<&[u8], u64>,
) -> io::Result<()> {
    let mut file = create(&dir.exchange_file(flow, stream, request))?;
    let head = &head.as_bytes()[..head.len().min(EXCHANGE_FILE_LIMIT)];
    file.write_all(head)?;
    file.write_all(b"\r\n")?;
    match body {
        Ok(body) => file.write_all(&scrubbed_body(content_type, body))?,
        Err(bytes) => writeln!(
            file,
            "[{bytes} bytes not written: the body was not kept whole]"
        )?,
    }
    file.flush()
}

/// Appends one WebSocket message to the exchange's `.ws` file: a line
/// with the direction and the size, then, for a text message, the text
/// scrubbed as a JSON body is, cut at [`EXCHANGE_FILE_LIMIT`].
pub fn append_ws(
    dir: &DumpDir,
    flow: u64,
    stream: u32,
    direction: &str,
    text: bool,
    payload: &[u8],
) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(dir.ws_file(flow, stream))?;
    writeln!(
        file,
        "{direction} {} {}",
        if text { "text" } else { "binary" },
        payload.len()
    )?;
    if text {
        // A text message: JSON when it parses, text otherwise.
        file.write_all(&scrubbed_body(None, payload))?;
        file.write_all(b"\n")?;
    }
    file.flush()
}

/// The form fields whose values are credentials, besides the names
/// [`is_credential`] knows with `-` for `_`.
const FORM_SECRETS: [&str; 10] = [
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "api_key",
    "apikey",
    "secret",
    "code",
];

/// `body` as the dump writes it, never as it came: scrubbed by its
/// content type, cut at [`EXCHANGE_FILE_LIMIT`] first.
///
/// - JSON: by key and in every string (`redact::scrub_deep`, the audit
///   log's rule for tool arguments).
/// - An event stream, or newline-delimited JSON: line by line, each
///   `data:` payload (or line) that is JSON as JSON, the rest as text.
/// - A form (`application/x-www-form-urlencoded`, an OAuth token
///   exchange's shape): a credential field's value replaced, the others
///   scrubbed as text.
/// - Markup (HTML, XML): not written, as the free-text scrub cannot read
///   an element or an attribute as a key; one line says how many bytes
///   it was.
/// - Other text (`text/*`, JavaScript; or no type, valid UTF-8): through
///   `redact::scrub_text`.
/// - Anything else: not written; one line says how many bytes it was.
pub fn scrubbed_body(content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    let body = &body[..body.len().min(EXCHANGE_FILE_LIMIT)];
    let kind = content_type.unwrap_or("").trim().to_ascii_lowercase();
    let json_kind = kind == "application/json" || kind.ends_with("+json");
    if json_kind || kind.is_empty() {
        if let Some(clean) = json_text(body) {
            return clean.into_bytes();
        }
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return format!(
            "[{} bytes of {} not written]\n",
            body.len(),
            if kind.is_empty() { "binary" } else { &kind }
        )
        .into_bytes();
    };
    if kind == "text/event-stream" {
        return events(body).into_bytes();
    }
    if kind == "application/x-ndjson"
        || kind == "application/jsonl"
        || kind == "application/json-seq"
    {
        return lines(text).into_bytes();
    }
    if kind == "application/x-www-form-urlencoded" {
        let fields: Vec<String> = text
            .split('&')
            .map(|field| match field.split_once('=') {
                Some((name, _)) if form_name(name).is_none_or(|name| form_secret(&name)) => {
                    format!("{name}=[redacted]")
                }
                Some((name, value)) => format!("{name}={}", scrub_text(value)),
                None => scrub_text(field),
            })
            .collect();
        return fields.join("&").into_bytes();
    }
    let markup = kind == "text/html"
        || kind == "text/xml"
        || kind == "application/xml"
        || kind.ends_with("+xml");
    let textual = json_kind
        || kind.is_empty()
        || kind.starts_with("text/")
        || kind == "application/javascript";
    if textual && !markup {
        return scrub_text(text).into_bytes();
    }
    format!("[{} bytes of {kind} not written]\n", body.len()).into_bytes()
}

/// `bytes` as JSON scrubbed by key and in every string, its streamed
/// fragments by their size only ([`without_fragments`]), if it is JSON.
fn json_text(bytes: &[u8]) -> Option<String> {
    let mut value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    without_fragments(&mut value);
    boxcar_proto::redact::scrub_deep(&mut value);
    Some(value.to_string())
}

/// A streamed piece of a reply (anything under a `delta`, Anthropic's
/// `partial_json`) is a fragment: a secret split across fragments is in
/// none of them whole, where no scrub finds it. The dump writes each
/// fragment's strings as their size; the whole values, where a reply
/// gives them (a call's arguments when it is done, the full response),
/// are written scrubbed.
fn without_fragments(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key == "delta" || key == "partial_json" {
                    sizes(child);
                } else {
                    without_fragments(child);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(without_fragments),
        _ => {}
    }
}

/// Every string in `value` but a `type` replaced by its size.
fn sizes(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = format!("[{} bytes]", text.len());
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key != "type" {
                    sizes(child);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(sizes),
        _ => {}
    }
}

/// An event stream, event by event as the observer reads it (`data:`
/// lines joined): each event's data scrubbed as JSON when it is JSON, its
/// size alone when it is not (`[DONE]` aside), so that one event's JSON
/// split over several `data:` lines is never read as loose text.
fn events(body: &[u8]) -> String {
    let mut parser = SseParser::new();
    let mut events = Vec::new();
    parser.feed(body, &mut events);
    parser.finish(&mut events);
    let mut out = String::with_capacity(body.len());
    for event in events {
        if let Some(name) = &event.event {
            out.push_str(&format!("event: {}\n", scrub_text(name)));
        }
        if let Some(id) = &event.id {
            out.push_str(&format!("id: {}\n", scrub_text(id)));
        }
        if !event.data.is_empty() {
            let data = match json_text(event.data.as_bytes()) {
                Some(clean) => clean,
                None if event.data.trim() == "[DONE]" => "[DONE]".to_owned(),
                None => format!("[{} bytes]", event.data.len()),
            };
            out.push_str(&format!("data: {data}\n"));
        }
        out.push('\n');
    }
    if parser.overflowed() {
        out.push_str("[a line past the event limit was not written]\n");
    }
    out
}

/// JSON lines, line by line: a line that is JSON scrubbed as JSON, any
/// other written as its size.
fn lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        let end = &line[content.len()..];
        if !content.trim().is_empty() {
            match json_text(content.trim().as_bytes()) {
                Some(clean) => out.push_str(&clean),
                None => out.push_str(&format!("[{} bytes]", content.len())),
            }
        }
        out.push_str(end);
    }
    out
}

/// A form field's name decoded as `application/x-www-form-urlencoded`
/// reads it (`+` a space, `%XX` a byte); `None` when it does not decode,
/// and its value is then taken for a credential's.
fn form_name(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            b'%' => {
                let hex = name.get(at + 1..at + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                at += 3;
            }
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Whether a form field's name names a credential.
fn form_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FORM_SECRETS.contains(&lower.as_str()) || is_credential(&lower.replace('_', "-"))
}

/// Headers whose value is a URL, scrubbed as a request target is.
pub const URL_HEADERS: [&str; 4] = ["location", "content-location", "referer", "origin"];

/// The head text of a request or response as the dump writes it: the
/// start line, then each header as `name: value`, each line ending in
/// CRLF. `headers` are the observer's, which never hold a credential's
/// value; each value is also scrubbed as free text, and a header that
/// carries a URL ([`URL_HEADERS`]) as a request target is (its query
/// values kept only when short, plain and under an ordinary name).
pub fn head_text<'a>(
    start_line: &str,
    headers: impl Iterator<Item = (&'a str, &'a [u8])>,
) -> String {
    let mut text = String::with_capacity(256);
    text.push_str(start_line);
    text.push_str("\r\n");
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value);
        text.push_str(name);
        text.push_str(": ");
        if URL_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            text.push_str(&scrub_target(value.trim()));
        } else {
            text.push_str(&scrub_text(&value));
        }
        text.push_str("\r\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    #[test]
    fn the_pcap_header_and_records_are_well_formed() {
        let header = pcap_header();
        assert_eq!(u32_at(&header, 0), 0xa1b2_c3d4);
        assert_eq!(u16::from_le_bytes([header[4], header[5]]), 2);
        assert_eq!(u16::from_le_bytes([header[6], header[7]]), 4);
        assert_eq!(u32_at(&header, 8), 0, "thiszone");
        assert_eq!(u32_at(&header, 12), 0, "sigfigs");
        assert_eq!(u32_at(&header, 16), 65535);
        assert_eq!(u32_at(&header, 20), 1, "Ethernet");

        let at = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let frame = [0xab; 60];
        let record = pcap_record(at, &frame, frame.len());
        assert_eq!(record.len(), 16 + 60);
        assert_eq!(u32_at(&record, 0), 1_700_000_000);
        assert_eq!(u32_at(&record, 4), 123_456, "microseconds");
        assert_eq!(u32_at(&record, 8), 60, "included");
        assert_eq!(u32_at(&record, 12), 60, "original");
        assert_eq!(&record[16..], &frame);

        // Over the snapshot length the record is cut and says so.
        let long = vec![1u8; SNAPLEN as usize + 10];
        let record = pcap_record(at, &long, long.len());
        assert_eq!(u32_at(&record, 8), SNAPLEN);
        assert_eq!(u32_at(&record, 12), SNAPLEN + 10);
        assert_eq!(record.len(), 16 + SNAPLEN as usize);

        // A frame cut to its headers keeps its original length.
        let record = pcap_record(at, &frame[..54], 1514);
        assert_eq!(u32_at(&record, 8), 54);
        assert_eq!(u32_at(&record, 12), 1514);
    }

    /// An Ethernet frame holding IPv4 with `proto`, then `l4` and `payload`.
    fn ipv4(proto: u8, l4: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[9] = proto;
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(l4);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn frames_are_kept_to_their_headers() {
        let mut tcp = [0u8; 20];
        tcp[12] = 5 << 4;
        let payload = b"GET / HTTP/1.1\r\nAuthorization: x\r\n\r\n";
        let frame = ipv4(6, &tcp, payload);
        assert_eq!(headers_len(&frame), 54);

        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(headers_len(&ipv4(17, &udp, b"quic")), 42);
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        let dns = ipv4(17, &udp, b"query");
        assert_eq!(headers_len(&dns), dns.len());

        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0u8; 28]);
        assert_eq!(headers_len(&arp), arp.len());

        // A TCP header longer than the frame: only Ethernet is kept.
        let mut bad = [0u8; 20];
        bad[12] = 15 << 4;
        assert_eq!(headers_len(&ipv4(6, &bad, b"")), 14);
        assert_eq!(headers_len(&[1, 2, 3]), 3);
    }

    /// A TCP/IPv4 frame from `src` to `dst` (address' last byte, port)
    /// with `flags`, its IP length set, padded as Ethernet pads.
    fn tcp4(src: (u8, u16), dst: (u8, u16), flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 2, src.0]);
        ip[16..20].copy_from_slice(&[10, 0, 2, dst.0]);
        frame.extend_from_slice(&ip);
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&src.1.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst.1.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(payload);
        frame.resize(frame.len().max(60), 0);
        frame
    }

    fn addr(last: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 2, last), port)
    }

    /// Payload mode keeps what the gate sends the guest on a connection
    /// whose TLS it ended, and nothing the guest sends.
    #[test]
    fn payload_mode_keeps_the_gates_tls_only() {
        const SYN: u8 = 0x02;
        const PSH_ACK: u8 = 0x18;
        let guest = (15, 40000);
        let host = (2, 443);
        let hello = [0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
        let reply = [0x16, 0x03, 0x03, 0x00, 0x02, 9, 9];
        let mut gate = GateTls::default();
        gate.kept_len(&tcp4(guest, host, SYN, b""), false);
        // Before the relay says the gate ended its TLS: cut.
        assert_eq!(gate.kept_len(&tcp4(host, guest, PSH_ACK, &reply), true), 54);
        gate.mark(conn_key(addr(15, 40000), addr(2, 443)));
        // The guest's own bytes are cut, however TLS they look.
        assert_eq!(
            gate.kept_len(&tcp4(guest, host, PSH_ACK, &hello), false),
            54
        );
        // The gate's are kept, to the IP length's end.
        assert_eq!(
            gate.kept_len(&tcp4(host, guest, PSH_ACK, &reply), true),
            54 + 7
        );
        // Another connection: cut.
        let other = (15, 40001);
        assert_eq!(gate.kept_len(&tcp4(host, other, PSH_ACK, &reply), true), 54);
        // The guest opening the same ends again forgets the gate's TLS.
        gate.kept_len(&tcp4(guest, host, SYN, b""), false);
        assert_eq!(gate.kept_len(&tcp4(host, guest, PSH_ACK, &reply), true), 54);
    }

    #[test]
    fn payload_mode_writes_the_gates_payloads_to_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[])
            .unwrap()
            .with_payloads(true);
        let (dump, thread) = FrameDump::start(&dir).unwrap();
        let hello = [0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
        let reply = [0x16, 0x03, 0x03, 0x00, 0x02, 9, 9];
        let (guest, host) = ((15, 40000), (2, 443));
        assert!(dump.push_from_guest(&tcp4(guest, host, 0x02, b"")));
        dump.gate_tls(addr(15, 40000), addr(2, 443));
        assert!(dump.push_from_guest(&tcp4(guest, host, 0x18, &hello)));
        assert!(dump.push_to_guest(&tcp4(host, guest, 0x18, &reply)));
        drop(dump);
        assert!(thread.join(Duration::from_secs(5)));
        let bytes = fs::read(dir.frames()).unwrap();
        let mut at = 24;
        let mut kept = Vec::new();
        while at + 16 <= bytes.len() {
            let included = u32_at(&bytes, at + 8) as usize;
            kept.push(included);
            at += 16 + included;
        }
        assert_eq!(kept, [54, 54, 61]);
        assert_eq!(&bytes[bytes.len() - 7..], &reply);
    }

    #[test]
    fn random_frames_never_panic() {
        use proptest::prelude::*;
        proptest!(|(frame in proptest::collection::vec(any::<u8>(), 0..128))| {
            prop_assert!(headers_len(&frame) <= frame.len());
            let mut gate = GateTls::default();
            prop_assert!(gate.kept_len(&frame, true) <= frame.len());
            prop_assert!(gate.kept_len(&frame, false) <= frame.len());
        });
    }

    #[test]
    fn frames_land_in_the_file_in_order_with_the_header_first() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let (dump, thread) = FrameDump::start(&dir).unwrap();
        assert!(dump.push_from_guest(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]));
        assert!(dump.push_from_guest(&[0xff; 20]));
        drop(dump);
        assert!(thread.join(Duration::from_secs(5)));
        let mut bytes = Vec::new();
        File::open(dir.frames())
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(&bytes[..24], &pcap_header());
        assert_eq!(u32_at(&bytes, 24 + 8), 14);
        assert_eq!(
            &bytes[24 + 16..24 + 16 + 14],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        );
        let second = 24 + 16 + 14;
        // An unknown ethertype: the Ethernet header is kept, the rest not.
        assert_eq!(u32_at(&bytes, second + 8), 14);
        assert_eq!(u32_at(&bytes, second + 12), 20);
        assert_eq!(bytes.len(), second + 16 + 14);
        let mode = fs::metadata(dir.frames()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_full_channel_drops_and_counts() {
        // A queue nobody drains: once it is full, `push` says so at once
        // and never waits.
        let (tx, rx) = bounded::<Item>(2);
        let dump = FrameDump {
            tx,
            payloads: false,
        };
        assert!(dump.push_from_guest(&[0; 14]));
        assert!(dump.push_from_guest(&[0; 14]));
        let start = std::time::Instant::now();
        assert!(!dump.push_from_guest(&[0; 14]), "the third has no room");
        assert!(start.elapsed() < Duration::from_millis(100));
        drop(rx);
        assert!(!dump.push_from_guest(&[0; 14]), "nobody to take it");
    }

    #[test]
    fn the_dump_dir_may_not_be_a_share() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("workspace");
        fs::create_dir(&share).unwrap();
        let share = fs::canonicalize(&share).unwrap();
        let inside = DumpDir::prepare(&share.join("dump"), &[&share]);
        assert!(inside.is_err(), "inside a share");
        let same = DumpDir::prepare(&share, &[&share]);
        assert!(same.is_err(), "the share itself");
        let above = DumpDir::prepare(tmp.path(), &[&share]);
        assert!(above.is_err(), "holding a share");
        let beside = DumpDir::prepare(&tmp.path().join("dump"), &[&share]).unwrap();
        assert!(beside.path().is_dir());
        assert!(beside.path().join("http").is_dir());
        // Again: the directory now holds the first run's dump, so no.
        assert!(DumpDir::prepare(&tmp.path().join("dump"), &[&share]).is_err());
        // An existing empty directory is fine.
        fs::create_dir(tmp.path().join("empty")).unwrap();
        DumpDir::prepare(&tmp.path().join("empty"), &[&share]).unwrap();
        // A file in the way is not.
        fs::write(tmp.path().join("file"), b"x").unwrap();
        assert!(DumpDir::prepare(&tmp.path().join("file"), &[]).is_err());
    }

    #[test]
    fn dump_files_never_write_through_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::write(&elsewhere, b"keep").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.exchange_file(1, 1, true)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.ws_file(1, 1)).unwrap();
        assert!(write_exchange(&dir, 1, 1, true, "GET / HTTP/1.1\r\n", None, Ok(b"")).is_err());
        assert!(append_ws(&dir, 1, 1, "c2s", true, b"{}").is_err());
        assert_eq!(fs::read(&elsewhere).unwrap(), b"keep");
    }

    #[test]
    fn exchange_files_hold_the_head_and_the_scrubbed_body() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let head = head_text(
            "POST /v1/messages HTTP/1.1",
            [
                ("host", &b"api.example"[..]),
                ("content-type", &b"application/json"[..]),
            ]
            .into_iter(),
        );
        write_exchange(
            &dir,
            7,
            1,
            true,
            &head,
            Some("application/json"),
            Ok(b"{\"model\":\"m\",\"api_key\":\"sk-123\"}"),
        )
        .unwrap();
        let text = fs::read_to_string(dir.exchange_file(7, 1, true)).unwrap();
        assert!(text.starts_with(
            "POST /v1/messages HTTP/1.1\r\nhost: api.example\r\ncontent-type: application/json\r\n\r\n"
        ));
        assert!(text.contains("\"model\":\"m\""), "{text}");
        assert!(!text.contains("sk-123"), "the key is scrubbed: {text}");
        let mode = fs::metadata(dir.exchange_file(7, 1, true))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn websocket_messages_are_appended_scrubbed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        append_ws(
            &dir,
            3,
            1,
            "c2s",
            true,
            b"{\"type\":\"response.create\",\"api_key\":\"sk-1\"}",
        )
        .unwrap();
        append_ws(&dir, 3, 1, "s2c", false, &[1, 2, 3]).unwrap();
        let text = fs::read_to_string(dir.ws_file(3, 1)).unwrap();
        assert!(text.starts_with("c2s text 43\n{"), "{text}");
        assert!(text.contains("\"type\":\"response.create\"") && !text.contains("sk-1"));
        assert!(text.ends_with("\ns2c binary 3\n"), "{text}");
    }

    /// Markup is written as its size: an element or an attribute named
    /// for a credential is no key the free-text scrub knows.
    #[test]
    fn markup_bodies_are_written_as_their_size() {
        let cases = [
            (
                "application/xml",
                &b"<login><password>sample-pass</password></login>"[..],
            ),
            (
                "application/soap+xml",
                b"<a><token>sample-token</token></a>",
            ),
            ("text/xml", b"<a><secret>sample-secret</secret></a>"),
            (
                "text/html",
                b"<input name=\"password\" value=\"sample-pass\">",
            ),
        ];
        for (kind, body) in cases {
            let text = String::from_utf8(scrubbed_body(Some(kind), body)).unwrap();
            assert_eq!(
                text,
                format!("[{} bytes of {kind} not written]\n", body.len())
            );
        }
    }

    /// A URL in a header loses its credential query values as a request
    /// target does.
    #[test]
    fn url_headers_are_scrubbed_as_targets() {
        let headers = [
            (
                "location",
                &b"https://client.example/cb?code=a1b2c3d4e5f6a7b8c9d0&state=s1"[..],
            ),
            ("referer", &b"https://app.example/p?sig=abc&page=2"[..]),
            ("content-type", &b"text/html"[..]),
        ];
        let text = head_text("HTTP/1.1 302", headers.into_iter());
        assert!(!text.contains("a1b2c3d4e5f6a7b8c9d0"), "{text}");
        assert!(!text.contains("sig=abc"), "{text}");
        assert!(text.contains("page=2"), "{text}");
        assert!(text.contains("content-type: text/html\r\n"), "{text}");
    }

    /// A secret split across streamed fragments is in none of them in
    /// the dump: fragments are written as their size.
    #[test]
    fn streamed_fragments_are_written_as_their_size() {
        let mut sse = String::new();
        for part in ["{\\\"password\\\": \\\"", "demo-pass", "\\\"}"] {
            sse.push_str(&format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{part}\"}}}}\n\n"
            ));
        }
        let out =
            String::from_utf8(scrubbed_body(Some("text/event-stream"), sse.as_bytes())).unwrap();
        assert!(!out.contains("demo-pass"), "{out}");
        assert!(out.contains("\"type\":\"input_json_delta\""), "{out}");
        assert!(out.contains("[9 bytes]"), "{out}");
        let ws = br#"{"type":"response.function_call_arguments.delta","delta":"demo-pass"}"#;
        let out = String::from_utf8(scrubbed_body(None, ws)).unwrap();
        assert!(!out.contains("demo-pass"), "{out}");
    }

    #[test]
    fn bodies_are_scrubbed_by_their_content_type() {
        let form = b"grant_type=refresh_token&refresh_token=rt-secret-1&client_id=app";
        let out = scrubbed_body(Some("application/x-www-form-urlencoded"), form);
        assert_eq!(
            &*out,
            &b"grant_type=refresh_token&refresh_token=[redacted]&client_id=app"[..]
        );
        let json = b"{\"access_token\":\"at-1\",\"ok\":true}";
        let out = scrubbed_body("application/json; charset=utf-8".split(';').next(), json);
        assert!(!String::from_utf8_lossy(&out).contains("at-1"));
        assert!(String::from_utf8_lossy(&out).contains("\"ok\":true"));
        let bad_json = b"{not json, \"token\": \"t-1\"";
        let out = scrubbed_body(Some("application/json"), bad_json);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "{not json, \"token\": \"[redacted]\""
        );
        let nested = br#"{"input":{"command":"curl -H 'Authorization: Bearer q1' u"}}"#;
        let out = String::from_utf8(scrubbed_body(Some("application/json"), nested)).unwrap();
        assert!(!out.contains("q1"), "{out}");
        let sse = b"event: ping\ndata: {\"type\":\"ping\"}\r\n\nevent: delta\ndata: {\"partial_json\":\"{\\\"command\\\": \\\"x --token=abc\\\"}\"}\n\n";
        let out = String::from_utf8(scrubbed_body(Some("text/event-stream"), sse)).unwrap();
        assert!(
            out.starts_with("event: ping\ndata: {\"type\":\"ping\"}\n\nevent: delta\n"),
            "{out}"
        );
        assert!(!out.contains("abc"), "{out}");
        // One event's JSON over several `data:` lines is read whole.
        let split = "event: e\ndata: {\"type\":\"response.function_call_arguments.delta\",\ndata: \"delta\":\"demo-pass\"}\n\ndata: not json demo-pass\n\ndata: [DONE]\n\n";
        let out =
            String::from_utf8(scrubbed_body(Some("text/event-stream"), split.as_bytes())).unwrap();
        assert!(!out.contains("demo-pass"), "{out}");
        assert!(out.contains("data: [DONE]\n"), "{out}");
        assert!(out.contains("data: [18 bytes]\n"), "{out}");
        // A field name is read decoded: `%70assword` is `password`.
        let form = b"user=me&%70assword=hunter2&bad%zz=v&q=a+b";
        let out = scrubbed_body(Some("application/x-www-form-urlencoded"), form);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "user=me&%70assword=[redacted]&bad%zz=[redacted]&q=a+b"
        );
        let lines = b"{\"a\":1}\nnot json demo-pass\n";
        let out = String::from_utf8(scrubbed_body(Some("application/x-ndjson"), lines)).unwrap();
        assert_eq!(out, "{\"a\":1}\n[18 bytes]\n");
        assert_eq!(scrubbed_body(None, b"raw"), b"raw");
        assert_eq!(
            scrubbed_body(Some("text/plain"), b"key=sk-ant-0123456789"),
            b"key=[redacted]"
        );
        assert_eq!(
            scrubbed_body(Some("application/octet-stream"), b"x"),
            b"[1 bytes of application/octet-stream not written]\n"
        );
        assert_eq!(
            scrubbed_body(None, &[0xff, 0xfe]),
            b"[2 bytes of binary not written]\n"
        );
    }
}
