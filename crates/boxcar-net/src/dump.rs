// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Dump mode (`boxcar run --dump DIR`): a debugging aid beside the audit
//! log, after bitvessel's `DebugNet`. Nothing in it is hashed or chained.
//!
//! - `frames.pcap`: every frame the guest sent and every frame the stack
//!   gave it, as pcap 2.4 (little endian, microsecond timestamps,
//!   Ethernet), cut after the frame's headers ([`headers_len`]): a TCP
//!   payload is not written, plain HTTP's credentials included; each
//!   record keeps the frame's original length. Well-formed ARP packets,
//!   DNS messages, and DHCP messages with plausible headers are kept
//!   whole. With `--dump-payloads`
//!   ([`DumpDir::with_payloads`]) a frame the stack sends the guest on a
//!   flow whose TLS the gate is ending at that moment is written whole
//!   (the stack records that state when it queues the frame,
//!   [`FrameDump::push_to_guest`]): the gate's own TLS records,
//!   ciphertext whose keys never leave the VMM. What the guest sends is
//!   cut whatever it looks like, and so is every other flow's payload, a
//!   plain HTTP flow's included.
//!   The net thread copies each frame into a bounded channel
//!   with `try_send`; the `dump` thread writes them. A frame the channel
//!   had no room for is dropped and counted (`net.drop{reason:"dump"}`):
//!   the net thread never waits on the dump.
//! - `http/<flow>-<stream>.req` and `.resp`: each decoded exchange of an
//!   inspected flow, written by the observer thread: the start line, the
//!   headers as the observer keeps them (a credential header's value never
//!   reaches it), a blank line, the decoded body. JSON, event streams,
//!   markup and forms are recognized by shape as well as content type;
//!   other text takes the free-text scrubber and other bodies are represented
//!   by size.
//!   The raw plaintext is not written: it would hold the credentials the
//!   records never do.
//! - `http/<flow>-<stream>.ws`: the messages of an exchange upgraded to
//!   WebSocket, one after another, each as a line naming the direction
//!   (`c2s`, `s2c`) and the size, then a scrubbed representation for a text
//!   message. A JSON message keeps its structure and sizes its string payloads.
//!
//! The directory is made mode 0700, every file 0600, and it may be
//! neither a share nor inside one, nor hold one: the audit directory's
//! rule.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use boxcar_proto::redact::{scrub_target, scrub_text};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use smoltcp::wire::{
    ArpHardware, ArpPacket, ArpRepr, DhcpOpCode, DhcpPacket, EthernetFrame, EthernetProtocol,
    IpProtocol, Ipv4Packet, UdpPacket,
};

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
    /// flows' gate side when `payloads` ([`FrameDump::push_to_guest`]).
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
    /// of a frame the gate sent on a flow whose TLS it ends.
    bytes: Vec<u8>,
    /// The whole frame's length.
    len: usize,
}

/// The net thread's end of the frame dump. Cheap to clone: every stack of
/// the device feeds the same file.
#[derive(Clone)]
pub struct FrameDump {
    tx: Sender<Frame>,
    /// `--dump-payloads`: the gate's TLS records are kept.
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
        let thread = thread::Builder::new().name("dump".into()).spawn(move || {
            boxcar_confine::at_thread_start();
            write_frames(rx, file)
        })?;
        Ok((FrameDump { tx, payloads }, DumpThread { thread }))
    }

    /// Whether the gate's TLS records are kept (`--dump-payloads`).
    pub fn payloads(&self) -> bool {
        self.payloads
    }

    /// Queues a frame the guest sent for the file, cut to its headers
    /// whatever it holds, and says whether there was room; the caller
    /// counts one there was not. Never waits.
    pub fn push_from_guest(&self, bytes: &[u8]) -> bool {
        self.push(bytes, headers_len(bytes))
    }

    /// Queues a frame the stack sent the guest: whole in payload mode
    /// when `gate_tls` (the caller found it on a flow whose TLS the gate
    /// is ending), else cut to its headers.
    pub fn push_to_guest(&self, bytes: &[u8], gate_tls: bool) -> bool {
        let kept = if self.payloads && gate_tls {
            bytes.len()
        } else {
            headers_len(bytes)
        };
        self.push(bytes, kept)
    }

    fn push(&self, bytes: &[u8], kept: usize) -> bool {
        let frame = Frame {
            at: SystemTime::now(),
            bytes: bytes[..kept].to_vec(),
            len: bytes.len(),
        };
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

/// The `dump` thread, which ends when every [`FrameDump`] is gone and the
/// queue is drained.
pub struct DumpThread {
    thread: JoinHandle<()>,
}

/// How a bounded worker-thread join ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadJoin {
    /// The thread ended and joined normally.
    Joined,
    /// The thread was still running at the deadline.
    TimedOut,
    /// The thread ended by panicking.
    Panicked,
}

impl DumpThread {
    /// Waits at most `limit` for the thread to end, then distinguishes a
    /// clean join from a timeout or panic. A busy thread is left behind.
    pub fn join(self, limit: Duration) -> ThreadJoin {
        let deadline = std::time::Instant::now() + limit;
        while !self.thread.is_finished() {
            if std::time::Instant::now() >= deadline {
                return ThreadJoin::TimedOut;
            }
            thread::sleep(Duration::from_millis(10));
        }
        match self.thread.join() {
            Ok(()) => ThreadJoin::Joined,
            Err(_) => ThreadJoin::Panicked,
        }
    }

    #[cfg(test)]
    pub(crate) fn blocked() -> (DumpThread, std::sync::mpsc::Sender<()>) {
        let (release, wait) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = wait.recv();
        });
        (DumpThread { thread }, release)
    }
}

/// The thread's body: each frame as a pcap record. A write that fails
/// ends the file; the frames keep being taken so the queue drains.
fn write_frames(rx: Receiver<Frame>, file: File) {
    let mut out = io::BufWriter::new(file);
    let mut failed = false;
    for frame in rx {
        if failed {
            continue;
        }
        if out
            .write_all(&pcap_record(frame.at, &frame.bytes, frame.len))
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

/// The two ends of the TCP/IPv4 segment `frame` carries, source first,
/// if it carries one whose headers fit.
pub fn tcp_ends(frame: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4)> {
    const ETH: usize = 14;
    if frame.get(12..14)? != [0x08, 0x00] {
        return None;
    }
    let ihl = usize::from(frame.get(ETH)? & 0x0f) * 4;
    if ihl < 20 || *frame.get(ETH + 9)? != 6 {
        return None;
    }
    let ip = |at: usize| -> Option<Ipv4Addr> {
        let b: [u8; 4] = frame.get(at..at + 4)?.try_into().ok()?;
        Some(Ipv4Addr::from(b))
    };
    let tcp = frame.get(ETH + ihl..ETH + ihl + 4)?;
    Some((
        SocketAddrV4::new(ip(ETH + 12)?, u16::from_be_bytes([tcp[0], tcp[1]])),
        SocketAddrV4::new(ip(ETH + 16)?, u16::from_be_bytes([tcp[2], tcp[3]])),
    ))
}

const DNS_PORT: u16 = 53;
const DHCP_PORTS: [u16; 2] = [67, 68];
const DHCP_MAGIC: u32 = 0x6382_5363;

/// How much of an Ethernet frame the frame dump keeps: the Ethernet,
/// IPv4 or IPv6, and TCP, UDP or ICMP headers, without the payload after
/// them. A well-formed, exactly sized ARP packet is kept whole, as is a
/// well-formed UDP datagram to or from port 53 whose payload parses as DNS,
/// or ports 67 and 68 whose payload has a plausible DHCP header.
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
        0x0806 => return arp_len(frame).unwrap_or(ether_short),
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
            if let Some(len) = kept_udp_len(frame) {
                return len;
            }
            l4 + 8
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

/// The length of an Ethernet/IPv4 ARP packet, when `frame` is exactly one.
fn arp_len(frame: &[u8]) -> Option<usize> {
    const ARP_FRAME_LEN: usize = 14 + 28;
    if frame.len() != ARP_FRAME_LEN {
        return None;
    }
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Arp {
        return None;
    }
    let packet = ArpPacket::new_checked(eth.payload()).ok()?;
    matches!(ArpRepr::parse(&packet), Ok(ArpRepr::EthernetIpv4 { .. })).then_some(ARP_FRAME_LEN)
}

/// The end of a UDP DNS or DHCP message that reads as that protocol.
fn kept_udp_len(frame: &[u8]) -> Option<usize> {
    const ETH: usize = 14;
    let eth = EthernetFrame::new_checked(frame).ok()?;
    let (l4, payload) = match eth.ethertype() {
        EthernetProtocol::Ipv4 => {
            let packet = Ipv4Packet::new_checked(eth.payload()).ok()?;
            // A fragment is no whole datagram, whatever its first bytes say.
            if packet.next_header() != IpProtocol::Udp
                || packet.more_frags()
                || packet.frag_offset() != 0
            {
                return None;
            }
            (ETH + usize::from(packet.header_len()), packet.payload())
        }
        EthernetProtocol::Ipv6 => {
            let packet = eth.payload();
            if packet.first()? >> 4 != 6 || packet.get(6) != Some(&17) {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            (ETH + 40, packet.get(40..40 + payload_len)?)
        }
        _ => return None,
    };
    let udp = UdpPacket::new_checked(payload).ok()?;
    let ports = [udp.src_port(), udp.dst_port()];
    let message = udp.payload();
    let dns = ports.contains(&DNS_PORT) && plausible_dns(message);
    let dhcp = ports.iter().any(|port| DHCP_PORTS.contains(port)) && plausible_dhcp(message);
    (dns || dhcp).then_some(l4 + usize::from(udp.len()))
}

/// Whether `message` is one complete DNS wire message: every question and
/// record named by its header fits, and there are no bytes after them.
fn plausible_dns(message: &[u8]) -> bool {
    let Some(counts) = message.get(4..12) else {
        return false;
    };
    let count = |at: usize| usize::from(u16::from_be_bytes([counts[at], counts[at + 1]]));
    let mut at = 12;
    for _ in 0..count(0) {
        let Some(end) = dns_name_end(message, at).and_then(|end| end.checked_add(4)) else {
            return false;
        };
        at = end;
    }
    let records = count(2) + count(4) + count(6);
    for _ in 0..records {
        let Some(name_end) = dns_name_end(message, at) else {
            return false;
        };
        let Some(fixed) = message.get(name_end..name_end + 10) else {
            return false;
        };
        let data_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let Some(end) = name_end
            .checked_add(10)
            .and_then(|start| start.checked_add(data_len))
        else {
            return false;
        };
        at = end;
    }
    at == message.len()
}

/// The first byte after a DNS name at `at`, following backward compression
/// pointers to check their targets. A name is at most 255 wire bytes and 64
/// pointers.
fn dns_name_end(message: &[u8], at: usize) -> Option<usize> {
    let mut cursor = at;
    let mut end = None;
    let mut bytes = 0usize;
    let mut pointers = 0usize;
    loop {
        let &label = message.get(cursor)?;
        match label {
            0 => return Some(end.unwrap_or(cursor + 1)),
            0xc0..=0xff => {
                let &low = message.get(cursor + 1)?;
                let pointer = (usize::from(label & 0x3f) << 8) | usize::from(low);
                if pointer >= cursor || pointers == 64 {
                    return None;
                }
                end.get_or_insert(cursor + 2);
                pointers += 1;
                bytes += 2;
                cursor = pointer;
            }
            1..=63 => {
                let next = cursor.checked_add(1 + usize::from(label))?;
                message.get(cursor + 1..next)?;
                bytes += 1 + usize::from(label);
                cursor = next;
            }
            _ => return None,
        }
        if bytes > 255 {
            return None;
        }
    }
}

/// Whether `message` has the fixed fields of a DHCP message carried over
/// Ethernet. Options are left to the DHCP reader.
fn plausible_dhcp(message: &[u8]) -> bool {
    let Ok(packet) = DhcpPacket::new_checked(message) else {
        return false;
    };
    matches!(packet.opcode(), DhcpOpCode::Request | DhcpOpCode::Reply)
        && packet.hardware_type() == ArpHardware::Ethernet
        && packet.hardware_len() == 6
        && packet.magic_number() == DHCP_MAGIC
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
        Ok(body) => write_scrubbed_body(&mut file, content_type, body, false)?,
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
        // What the client sends is a whole message; what the server sends
        // may be a piece of a reply.
        let clean = if direction == "c2s" {
            scrubbed_body(None, payload)
        } else {
            scrubbed_stream_body(payload)
        };
        file.write_all(&clean)?;
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

/// `body` as the dump writes it, never as it came: scrubbed by its shape
/// and content type, cut at [`EXCHANGE_FILE_LIMIT`] first.
///
/// - JSON: by key and in every string (`redact::scrub_deep`, the audit
///   log's rule for tool arguments).
/// - An event stream, or newline-delimited JSON: line by line, each
///   `data:` payload (or line) that is JSON as JSON, the rest by size.
/// - A form (`application/x-www-form-urlencoded`, an OAuth token
///   exchange's shape): a credential field's value replaced, the others
///   scrubbed as text.
/// - Markup (HTML, XML): not written, as the free-text scrub cannot read
///   an element or an attribute as a key; one line says how many bytes
///   it was.
/// - Other text (`text/*`, JavaScript; or no type, valid UTF-8): through
///   `redact::scrub_text`. JSON, event streams, forms and markup are
///   recognized by shape before this fallback, even without their type.
/// - Anything else: not written; one line says how many bytes it was.
pub fn scrubbed_body(content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    scrubbed_body_with(content_type, body, false)
}

/// A WebSocket text message as the dump writes it. A JSON message is one
/// streamed item, so its string payloads are represented by size.
fn scrubbed_stream_body(body: &[u8]) -> Vec<u8> {
    scrubbed_body_with(None, body, true)
}

fn scrubbed_body_with(content_type: Option<&str>, body: &[u8], streamed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing to a Vec cannot fail.
    write_scrubbed_body(&mut out, content_type, body, streamed).expect("Vec write");
    out
}

fn write_scrubbed_body<W: Write>(
    out: &mut W,
    content_type: Option<&str>,
    body: &[u8],
    streamed: bool,
) -> io::Result<()> {
    let body = &body[..body.len().min(EXCHANGE_FILE_LIMIT)];
    let kind = content_type.unwrap_or("").trim().to_ascii_lowercase();
    let json_kind = kind == "application/json" || kind.ends_with("+json");
    // A stream's label decides before its shape: one event or line of it
    // is still a piece.
    let lines_kind = kind == "application/x-ndjson"
        || kind == "application/jsonl"
        || kind == "application/json-seq";
    if kind == "text/event-stream" || lines_kind {
        let Ok(text) = std::str::from_utf8(body) else {
            return writeln!(out, "[{} bytes of {kind} not written]", body.len());
        };
        return if lines_kind {
            out.write_all(lines(text).as_bytes())
        } else {
            write_events(out, body)
        };
    }
    if let Some(clean) = json_text(body, streamed) {
        return out.write_all(clean.as_bytes());
    }
    if json_kind {
        // Said to be JSON and not: its member names cannot be read.
        return writeln!(out, "[{} bytes of {kind} that is not JSON]", body.len());
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return writeln!(
            out,
            "[{} bytes of {} not written]",
            body.len(),
            if kind.is_empty() { "binary" } else { &kind }
        );
    };
    if looks_like_event_stream(text) {
        return write_events(out, body);
    }
    if kind == "application/x-www-form-urlencoded" || looks_like_form(text) {
        return out.write_all(form(text).as_bytes());
    }
    let markup_kind = kind == "text/html"
        || kind == "text/xml"
        || kind == "application/xml"
        || kind.ends_with("+xml");
    let markup = markup_kind || looks_like_markup(text);
    let textual = json_kind
        || kind.is_empty()
        || kind.starts_with("text/")
        || kind == "application/javascript";
    if textual && !markup {
        return out.write_all(scrub_text(text).as_bytes());
    }
    let description = if kind.is_empty() { "markup" } else { &kind };
    writeln!(out, "[{} bytes of {description} not written]", body.len())
}

/// `bytes` as JSON scrubbed by key and in every string, if it is JSON.
/// In a streamed item, every string is written by its size, whatever field
/// carries it, but those of [`STREAM_WHOLE`]: a secret split across
/// streamed pieces is in none of them whole, where no scrub finds it.
fn json_text(bytes: &[u8], streamed: bool) -> Option<String> {
    let mut value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    if streamed {
        size_stream_strings(&mut value, false);
    }
    boxcar_proto::redact::scrub_deep(&mut value);
    Some(value.to_string())
}

/// The fields of a streamed item that come whole, never in pieces: what
/// the item is and what it belongs to (its kind, ids, model, role, how it
/// ended). A tool's `name` is not one: Chat Completions streams it. They stay readable, scrubbed as the rest
/// of a JSON body is.
const STREAM_WHOLE: [&str; 10] = [
    "type",
    "object",
    "id",
    "item_id",
    "call_id",
    "model",
    "role",
    "status",
    "stop_reason",
    "finish_reason",
];

/// String payloads in one streamed item, written by their size; those of
/// [`STREAM_WHOLE`] kept so the sequence stays readable.
fn size_stream_strings(value: &mut serde_json::Value, keep: bool) {
    match value {
        serde_json::Value::String(text) if !keep => {
            *text = format!("[{} bytes]", text.len());
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                size_stream_strings(child, STREAM_WHOLE.contains(&key.as_str()));
            }
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .for_each(|item| size_stream_strings(item, false)),
        _ => {}
    }
}

/// Whether `text` has the line shape of a server-sent event stream.
fn looks_like_event_stream(text: &str) -> bool {
    // Every line a field (a name of field characters, then `:` or
    // nothing), a comment or blank, and at least one `data` field. Names
    // other than the four the format defines are ignored by a reader, as
    // here.
    let mut data = false;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let field = line.split_once(':').map_or(line, |(field, _)| field);
        if field.is_empty()
            || !field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return false;
        }
        data |= field == "data";
    }
    data
}

/// Whether `text` has form fields with names that can be read without
/// ambiguity. Values may contain any UTF-8 accepted by the form format.
fn looks_like_form(text: &str) -> bool {
    let name_ok = |name: &str| {
        !name.is_empty()
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.' | b'%' | b'+' | b'[' | b']')
            })
    };
    let mut pairs = false;
    for field in text.split('&') {
        match field.split_once('=') {
            Some((name, _)) if name_ok(name) => pairs = true,
            Some(_) => return false,
            None if field.is_empty() || name_ok(field) => {}
            None => return false,
        }
    }
    pairs
}

/// Whether `text` holds markup: an HTML or XML element anywhere.
fn looks_like_markup(text: &str) -> bool {
    // An element's or a declaration's start anywhere (`<a`, `</a`, `<!`,
    // `<?`): a preamble before it changes nothing.
    text.as_bytes().windows(2).any(|pair| {
        pair[0] == b'<' && (pair[1].is_ascii_alphabetic() || matches!(pair[1], b'!' | b'?' | b'/'))
    })
}

fn form(text: &str) -> String {
    text.split('&')
        .map(|field| match field.split_once('=') {
            Some((name, _)) if form_name(name).is_none_or(|name| form_secret(&name)) => {
                format!("{name}=[redacted]")
            }
            Some((name, value)) => format!("{name}={}", scrub_text(value)),
            None => scrub_text(field),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Writes an event stream event by event as the observer reads it (`data:`
/// lines joined). Each event's data is scrubbed as JSON when it is JSON,
/// and written as its size when it is not (`[DONE]` aside), so that one
/// event's JSON split over several `data:` lines is never read as loose
/// text. At most one completed event waits to be written.
fn write_events<W: Write>(out: &mut W, body: &[u8]) -> io::Result<()> {
    let mut parser = SseParser::new();
    let mut parsed = Vec::with_capacity(1);
    for line in body.split_inclusive(|byte| matches!(*byte, b'\n' | b'\r')) {
        parser.feed(line, &mut parsed);
        debug_assert!(parsed.len() <= 1);
        if let Some(event) = parsed.pop() {
            write_event(out, event)?;
        }
    }
    parser.finish(&mut parsed);
    debug_assert!(parsed.len() <= 1);
    if let Some(event) = parsed.pop() {
        write_event(out, event)?;
    }
    if parser.overflowed() {
        out.write_all(b"[a line past the event limit was not written]\n")?;
    }
    Ok(())
}

fn write_event<W: Write>(out: &mut W, event: crate::http::SseEvent) -> io::Result<()> {
    if let Some(name) = &event.event {
        writeln!(out, "event: {}", scrub_text(name))?;
    }
    if let Some(id) = &event.id {
        writeln!(out, "id: {}", scrub_text(id))?;
    }
    if !event.data.is_empty() {
        let data = match json_text(event.data.as_bytes(), true) {
            Some(clean) => clean,
            None if event.data.trim() == "[DONE]" => "[DONE]".to_owned(),
            None => format!("[{} bytes]", event.data.len()),
        };
        writeln!(out, "data: {data}")?;
    }
    writeln!(out)
}

/// JSON lines, line by line: a line that is JSON scrubbed as JSON, any
/// other written as its size.
fn lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        let end = &line[content.len()..];
        if !content.trim().is_empty() {
            match json_text(content.trim().as_bytes(), true) {
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
    lower
        .split(['[', ']'])
        .filter(|part| !part.is_empty())
        .any(|part| FORM_SECRETS.contains(&part) || is_credential(&part.replace('_', "-")))
}

/// Headers whose value is a URL, scrubbed as a request target is.
pub const URL_HEADERS: [&str; 5] = [
    "location",
    "content-location",
    "referer",
    "origin",
    "destination",
];

/// A `Link` value with each angle-bracketed URI reference scrubbed as a
/// request target and the rest scrubbed as text.
fn link_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(open) = rest.find('<') {
        let Some(close) = rest[open + 1..].find('>').map(|at| open + 1 + at) else {
            break;
        };
        out.push_str(&scrub_text(&rest[..open + 1]));
        out.push_str(&scrub_target(&rest[open + 1..close]));
        out.push('>');
        rest = &rest[close + 1..];
    }
    out.push_str(&scrub_text(rest));
    out
}

/// A `Refresh` value with its `url = URI-reference` value scrubbed as a
/// request target and the delay and separators scrubbed as text.
fn refresh_text(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let Some(after) = lower.match_indices("url").find_map(|(at, _)| {
        let before = lower[..at].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
            return None;
        }
        let mut after = at + 3;
        while lower
            .as_bytes()
            .get(after)
            .is_some_and(u8::is_ascii_whitespace)
        {
            after += 1;
        }
        (lower.as_bytes().get(after) == Some(&b'=')).then_some(after + 1)
    }) else {
        return scrub_text(value);
    };
    let mut start = after;
    while value
        .as_bytes()
        .get(start)
        .is_some_and(u8::is_ascii_whitespace)
    {
        start += 1;
    }
    let quote = value
        .as_bytes()
        .get(start)
        .copied()
        .filter(|b| matches!(b, b'\'' | b'"'));
    let target_start = start + usize::from(quote.is_some());
    let target_end = quote
        .and_then(|quote| {
            value.as_bytes()[target_start..]
                .iter()
                .position(|&byte| byte == quote)
                .map(|end| target_start + end)
        })
        .unwrap_or(value.len());
    let mut out = scrub_text(&value[..target_start]);
    out.push_str(&scrub_target(&value[target_start..target_end]));
    out.push_str(&scrub_text(&value[target_end..]));
    out
}

/// The head text of a request or response as the dump writes it: the
/// start line, then each header as `name: value`, each line ending in
/// CRLF. `headers` are the observer's, which never hold a credential's
/// value; each value is also scrubbed as free text. A header that carries a
/// URL ([`URL_HEADERS`]) is scrubbed as a request target, as are URI
/// references inside `Link` and `Refresh` values.
pub fn head_text<'a>(
    start_line: &str,
    headers: impl Iterator<Item = (&'a str, &'a [u8])>,
) -> String {
    let mut text = String::with_capacity(256);
    text.push_str(start_line);
    text.push_str("\r\n");
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value);
        let lower = name.to_ascii_lowercase();
        text.push_str(name);
        text.push_str(": ");
        if URL_HEADERS.contains(&lower.as_str()) {
            text.push_str(&scrub_target(value.trim()));
        } else if lower == "link" {
            text.push_str(&link_text(&value));
        } else if lower == "refresh" {
            text.push_str(&refresh_text(&value));
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
        ip[2..4].copy_from_slice(&(20 + l4.len() as u16 + payload.len() as u16).to_be_bytes());
        ip[9] = proto;
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(l4);
        frame.extend_from_slice(payload);
        frame
    }

    fn udp4(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&src.to_be_bytes());
        udp[2..4].copy_from_slice(&dst.to_be_bytes());
        udp[4..6].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        ipv4(17, &udp, payload)
    }

    #[test]
    fn frames_are_kept_to_their_headers() {
        let mut tcp = [0u8; 20];
        tcp[12] = 5 << 4;
        let payload = b"GET / HTTP/1.1\r\nAuthorization: x\r\n\r\n";
        let frame = ipv4(6, &tcp, payload);
        assert_eq!(headers_len(&frame), 54);

        assert_eq!(headers_len(&udp4(40000, 443, b"quic")), 42);
        let dns = udp4(40000, 53, &[0; 12]);
        assert_eq!(headers_len(&dns), dns.len());

        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[
            0, 1, 8, 0, 6, 4, 0, 1, 0, 1, 2, 3, 4, 5, 10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 10, 0, 2, 2,
        ]);
        assert_eq!(headers_len(&arp), arp.len());

        // A TCP header longer than the frame: only Ethernet is kept.
        let mut bad = [0u8; 20];
        bad[12] = 15 << 4;
        assert_eq!(headers_len(&ipv4(6, &bad, b"")), 14);
        assert_eq!(headers_len(&[1, 2, 3]), 3);
    }

    #[test]
    fn only_well_formed_service_frames_are_kept_whole() {
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[
            0, 1, 8, 0, 6, 4, 0, 1, 0, 1, 2, 3, 4, 5, 10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 10, 0, 2, 2,
        ]);
        let mut oversized_arp = arp.clone();
        oversized_arp.push(1);
        assert_eq!(headers_len(&oversized_arp), 14);
        let mut malformed_arp = arp;
        malformed_arp[14..42].fill(0);
        assert_eq!(headers_len(&malformed_arp), 14);

        let dns = udp4(40_000, DNS_PORT, &[0; 12]);
        assert_eq!(headers_len(&dns), dns.len());
        assert_eq!(headers_len(&udp4(40_000, DNS_PORT, b"short")), 42);
        let mut trailing = vec![0; 12];
        trailing.extend_from_slice(b"tail");
        assert_eq!(headers_len(&udp4(40_000, DNS_PORT, &trailing)), 42);
        // A fragment is no whole datagram, whatever its first bytes say.
        let mut fragment = udp4(40_000, DNS_PORT, &[0; 12]);
        fragment[14 + 6] |= 0x20;
        assert_eq!(headers_len(&fragment), 42);

        let mut dhcp = vec![0u8; 240];
        dhcp[0] = 1;
        dhcp[1] = 1;
        dhcp[2] = 6;
        dhcp[236..240].copy_from_slice(&DHCP_MAGIC.to_be_bytes());
        let message = udp4(68, 67, &dhcp);
        assert_eq!(headers_len(&message), message.len());
        dhcp[236..240].fill(0);
        assert_eq!(headers_len(&udp4(68, 67, &dhcp)), 42);
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

    /// Payload mode keeps a frame to the guest whole only when the
    /// stack found it on a flow whose TLS the gate ends; the guest's are
    /// always cut.
    #[test]
    fn payload_mode_keeps_the_gates_tls_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[])
            .unwrap()
            .with_payloads(true);
        let (dump, thread) = FrameDump::start(&dir).unwrap();
        let hello = [0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
        let reply = [0x16, 0x03, 0x03, 0x00, 0x02, 9, 9];
        let (guest, host) = ((15, 40000), (2, 443));
        assert!(dump.push_from_guest(&tcp4(guest, host, 0x18, &hello)));
        assert!(dump.push_to_guest(&tcp4(host, guest, 0x18, &reply), true));
        assert!(dump.push_to_guest(&tcp4(host, guest, 0x18, &reply), false));
        drop(dump);
        assert_eq!(thread.join(Duration::from_secs(5)), ThreadJoin::Joined);
        let bytes = fs::read(dir.frames()).unwrap();
        let mut at = 24;
        let mut kept = Vec::new();
        while at + 16 <= bytes.len() {
            let included = u32_at(&bytes, at + 8) as usize;
            kept.push(included);
            at += 16 + included;
        }
        // The padded 60-byte minimum: the gate's 61-byte frame whole.
        assert_eq!(kept, [54, 61, 54]);
        assert_eq!(
            tcp_ends(&tcp4(host, guest, 0x18, &reply)),
            Some((addr(2, 443), addr(15, 40000)))
        );
    }

    #[test]
    fn without_payload_mode_the_gates_frames_are_cut_too() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let (dump, thread) = FrameDump::start(&dir).unwrap();
        let reply = [0x16, 0x03, 0x03, 0x00, 0x02, 9, 9];
        assert!(dump.push_to_guest(&tcp4((2, 443), (15, 40000), 0x18, &reply), true));
        drop(dump);
        assert_eq!(thread.join(Duration::from_secs(5)), ThreadJoin::Joined);
        let bytes = fs::read(dir.frames()).unwrap();
        assert_eq!(u32_at(&bytes, 24 + 8), 54);
    }

    #[test]
    fn random_frames_never_panic() {
        use proptest::prelude::*;
        proptest!(|(frame in proptest::collection::vec(any::<u8>(), 0..128))| {
            prop_assert!(headers_len(&frame) <= frame.len());
            let _ = tcp_ends(&frame);
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
        assert_eq!(thread.join(Duration::from_secs(5)), ThreadJoin::Joined);
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
        let (tx, rx) = bounded::<Frame>(2);
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

    #[derive(Default)]
    struct WriteSizes {
        total: usize,
        largest: usize,
    }

    impl std::io::Write for WriteSizes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.total += bytes.len();
            self.largest = self.largest.max(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn many_tiny_events_are_written_incrementally() {
        let body = b"data: {}\n\n".repeat(20_000);
        let mut writes = WriteSizes::default();
        write_scrubbed_body(&mut writes, Some("text/event-stream"), &body, false).unwrap();
        assert_eq!(writes.total, body.len());
        assert!(writes.largest < 1024, "largest write: {}", writes.largest);
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

    #[test]
    fn uri_reference_headers_scrub_query_values() {
        let headers = [
            ("Link", &b"</next?sig=abc>; rel=next"[..]),
            ("link", &b"<//cdn.example/item?key=k1>; rel=preload"[..]),
            ("Refresh", &b"0; url=?code=c1&view=full"[..]),
            ("Destination", &b"/copy?state=s1&part=2"[..]),
        ];
        let text = head_text("HTTP/1.1 200", headers.into_iter());
        for value in ["sig=abc", "key=k1", "code=c1", "state=s1"] {
            assert!(!text.contains(value), "{text}");
        }
        assert!(text.contains("view=full"), "{text}");
        assert!(text.contains("part=2"), "{text}");
    }

    #[test]
    fn streamed_strings_are_written_as_their_size() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let mut sse = String::new();
        for part in ["{\\\"password\\\": \\\"", "demo-pass", "\\\"}"] {
            sse.push_str(&format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"piece\":{{\"type\":\"input_json_delta\",\"content\":\"{part}\"}}}}\n\n"
            ));
        }
        write_exchange(
            &dir,
            4,
            1,
            false,
            "HTTP/1.1 200\r\n",
            Some("text/event-stream"),
            Ok(sse.as_bytes()),
        )
        .unwrap();
        let out = fs::read_to_string(dir.exchange_file(4, 1, false)).unwrap();
        assert!(!out.contains("demo-pass"), "{out}");
        assert!(out.contains("\"type\":\"input_json_delta\""), "{out}");
        assert!(out.contains("[9 bytes]"), "{out}");
        let ws = br#"{"type":"response.output.delta","piece":"demo-pass"}"#;
        append_ws(&dir, 4, 2, "s2c", true, ws).unwrap();
        let out = fs::read_to_string(dir.ws_file(4, 2)).unwrap();
        assert!(!out.contains("demo-pass"), "{out}");
        assert!(out.contains("\"type\":\"response.output.delta\""), "{out}");
        assert!(out.contains("\"piece\":\"[9 bytes]\""), "{out}");
        // What an item is stays readable; its pieces do not.
        let ws = br#"{"type":"response.output_text.delta","item_id":"msg_1","model":"m-1","delta":"demo-pass"}"#;
        append_ws(&dir, 4, 3, "s2c", true, ws).unwrap();
        let out = fs::read_to_string(dir.ws_file(4, 3)).unwrap();
        assert!(out.contains("\"item_id\":\"msg_1\""), "{out}");
        assert!(out.contains("\"model\":\"m-1\""), "{out}");
        assert!(out.contains("\"delta\":\"[9 bytes]\""), "{out}");
    }

    #[test]
    fn shapes_are_read_as_their_readers_read_them() {
        // A tool's name streamed in pieces is sized like any piece.
        let chunk = br#"{"object":"chat.completion.chunk","choices":[{"delta":{"tool_calls":[{"function":{"name":"plain-value"}}]}}]}"#;
        let out = String::from_utf8(scrubbed_body(Some("application/x-ndjson"), chunk)).unwrap();
        assert!(!out.contains("plain-value"), "{out}");
        assert!(
            out.contains("\"object\":\"chat.completion.chunk\""),
            "{out}"
        );
        // Said to be JSON and not: only its size.
        let broken = b"{\"pass\\u0077ord\": \"plain-value\"";
        let out = String::from_utf8(scrubbed_body(Some("application/json"), broken)).unwrap();
        assert!(!out.contains("plain-value"), "{out}");
        // A field the format does not define is still an event stream.
        let sse = b"x-note: 1\ndata: {\"type\":\"t\",\"piece\":\"plain-value\"}\n\n";
        let out = String::from_utf8(scrubbed_body(Some("text/plain"), sse)).unwrap();
        assert!(!out.contains("plain-value"), "{out}");
        assert!(out.contains("\"type\":\"t\""), "{out}");
        // A form with a bare field is still a form.
        let out =
            String::from_utf8(scrubbed_body(None, b"flag&user[password]=plain-value")).unwrap();
        assert!(!out.contains("plain-value"), "{out}");
        // Markup after a preamble is markup.
        let page = b"note: <form><input name=password value=plain-value></form>";
        let out = String::from_utf8(scrubbed_body(Some("text/plain"), page)).unwrap();
        assert!(!out.contains("plain-value"), "{out}");
    }

    #[test]
    fn a_websocket_request_is_scrubbed_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let request = br#"{"type":"response.create","input":"say hello","api_key":"plain-value"}"#;
        append_ws(&dir, 4, 2, "c2s", true, request).unwrap();
        let out = fs::read_to_string(dir.ws_file(4, 2)).unwrap();
        assert!(out.contains("\"input\":\"say hello\""), "{out}");
        assert!(!out.contains("plain-value"), "{out}");
    }

    #[test]
    fn untyped_bodies_are_scrubbed_by_shape() {
        let markup = b"<login><password>plain-value</password></login>";
        for kind in [None, Some("text/plain"), Some("application/octet-stream")] {
            let out = String::from_utf8(scrubbed_body(kind, markup)).unwrap();
            assert!(!out.contains("plain-value"), "{out}");
            assert!(out.contains(&format!("[{} bytes", markup.len())), "{out}");
        }

        let event = b"event: update\ndata: {\"type\":\"update\",\"piece\":\"plain-value\"}\n\n";
        let out = String::from_utf8(scrubbed_body(Some("text/plain"), event)).unwrap();
        assert!(out.contains("event: update"), "{out}");
        assert!(out.contains("\"type\":\"update\""), "{out}");
        assert!(!out.contains("plain-value"), "{out}");

        let json = br#"{"type":"update","password":"plain-value"}"#;
        let out = String::from_utf8(scrubbed_body(Some("text/plain"), json)).unwrap();
        assert!(out.contains("\"type\":\"update\""), "{out}");
        assert!(!out.contains("plain-value"), "{out}");

        let form = scrubbed_body(
            Some("text/plain"),
            b"user[name]=me&user[password]=plain-value",
        );
        assert_eq!(form, b"user[name]=me&user[password]=[redacted]".as_slice());

        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        append_ws(&dir, 8, 1, "s2c", true, markup).unwrap();
        let out = fs::read_to_string(dir.ws_file(8, 1)).unwrap();
        assert!(!out.contains("plain-value"), "{out}");
        assert!(out.contains(&format!("[{} bytes", markup.len())), "{out}");
    }

    #[test]
    fn bracketed_form_names_are_recognized() {
        let form = b"user[password]=plain-value&password[]=second&account%5Bpassword%5D=third&profile[name]=boxcar";
        let out = scrubbed_body(Some("application/x-www-form-urlencoded"), form);
        assert_eq!(
            out,
            b"user[password]=[redacted]&password[]=[redacted]&account%5Bpassword%5D=[redacted]&profile[name]=boxcar".as_slice()
        );
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
        // Said to be JSON and not: only its size.
        let bad_json = b"{not json, \"token\": \"t-1\"";
        let out = scrubbed_body(Some("application/json"), bad_json);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "[25 bytes of application/json that is not JSON]\n"
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
