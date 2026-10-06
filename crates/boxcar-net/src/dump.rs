// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Dump mode (`boxcar run --dump DIR`): a debugging aid beside the audit
//! log, after bitvessel's `DebugNet`. Nothing in it is hashed or chained.
//!
//! - `frames.pcap`: every frame the guest sent and every frame the stack
//!   gave it, as pcap 2.4 (little endian, microsecond timestamps,
//!   Ethernet). The net thread copies each frame into a bounded channel
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

use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

use crate::http::headers::is_credential;

/// How many frames may wait for the `dump` thread.
pub const FRAME_QUEUE: usize = 4096;
/// The pcap snapshot length: every frame is kept whole.
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
}

impl DumpDir {
    /// Makes `dir` (mode 0700) unless it exists, and refuses one that is a
    /// share, is inside one, or holds one. `shares` are the shares' paths,
    /// resolved. The directory itself is resolved through its parent, so a
    /// link into a share is found.
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
                if !resolved.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("dump dir {} is not a directory", resolved.display()),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        fs::set_permissions(&resolved, fs::Permissions::from_mode(0o700))?;
        let http = resolved.join("http");
        match fs::create_dir(&http) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        fs::set_permissions(&http, fs::Permissions::from_mode(0o700))?;
        Ok(DumpDir { path: resolved })
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

/// A file of the dump, created 0600 and truncated.
pub fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

// --- the frames

/// One frame on its way to the `dump` thread.
struct Frame {
    at: SystemTime,
    bytes: Vec<u8>,
}

/// The net thread's end of the frame dump. Cheap to clone: every stack of
/// the device feeds the same file.
#[derive(Clone)]
pub struct FrameDump {
    tx: Sender<Frame>,
}

impl FrameDump {
    /// Opens `frames.pcap` in `dir`, writes its header, and starts the
    /// `dump` thread that writes the frames.
    pub fn start(dir: &DumpDir) -> io::Result<(FrameDump, DumpThread)> {
        let mut file = create(&dir.frames())?;
        file.write_all(&pcap_header())?;
        let (tx, rx) = bounded(FRAME_QUEUE);
        let thread = thread::Builder::new()
            .name("dump".into())
            .spawn(move || write_frames(rx, file))?;
        Ok((FrameDump { tx }, DumpThread { thread }))
    }

    /// Queues a frame for the file, and says whether there was room; the
    /// caller counts one there was not. Never waits.
    pub fn push(&self, bytes: &[u8]) -> bool {
        let frame = Frame {
            at: SystemTime::now(),
            bytes: bytes.to_vec(),
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

/// The thread's body: each frame as a pcap record. A write that fails
/// ends the file; the frames keep being taken so the queue drains.
fn write_frames(rx: Receiver<Frame>, file: File) {
    let mut out = io::BufWriter::new(file);
    let mut failed = false;
    for frame in rx {
        if failed {
            continue;
        }
        if out.write_all(&pcap_record(frame.at, &frame.bytes)).is_err() {
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

/// One pcap record: its 16-byte header, then the frame, cut at
/// [`SNAPLEN`].
pub fn pcap_record(at: SystemTime, frame: &[u8]) -> Vec<u8> {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = u32::try_from(since.as_secs()).unwrap_or(u32::MAX);
    let kept = frame.len().min(SNAPLEN as usize);
    let mut out = Vec::with_capacity(16 + kept);
    out.extend_from_slice(&secs.to_le_bytes());
    out.extend_from_slice(&since.subsec_micros().to_le_bytes());
    out.extend_from_slice(&(kept as u32).to_le_bytes());
    out.extend_from_slice(&(frame.len().min(u32::MAX as usize) as u32).to_le_bytes());
    out.extend_from_slice(&frame[..kept]);
    out
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
    body: &[u8],
) -> io::Result<()> {
    let mut file = create(&dir.exchange_file(flow, stream, request))?;
    let head = &head.as_bytes()[..head.len().min(EXCHANGE_FILE_LIMIT)];
    file.write_all(head)?;
    file.write_all(b"\r\n")?;
    let body = scrubbed_body(content_type, body);
    file.write_all(&body[..body.len().min(EXCHANGE_FILE_LIMIT)])?;
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
        .mode(0o600)
        .open(dir.ws_file(flow, stream))?;
    writeln!(
        file,
        "{direction} {} {}",
        if text { "text" } else { "binary" },
        payload.len()
    )?;
    if text {
        let body = scrubbed_body(Some("application/json"), payload);
        file.write_all(&body[..body.len().min(EXCHANGE_FILE_LIMIT)])?;
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

/// `body` as the dump writes it: a JSON body with its secret-looking
/// fields scrubbed (`redact::scrub`, the audit log's rule), a form body
/// (`application/x-www-form-urlencoded`, an OAuth token exchange's shape)
/// with its credential fields' values replaced, anything else as it is.
pub fn scrubbed_body<'a>(content_type: Option<&str>, body: &'a [u8]) -> Cow<'a, [u8]> {
    let kind = content_type.unwrap_or("").to_ascii_lowercase();
    if kind == "application/json" || kind.ends_with("+json") {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) {
            boxcar_proto::redact::scrub(&mut value);
            return Cow::Owned(value.to_string().into_bytes());
        }
        return Cow::Borrowed(body);
    }
    if kind == "application/x-www-form-urlencoded" {
        let text = String::from_utf8_lossy(body);
        let fields: Vec<String> = text
            .split('&')
            .map(|field| match field.split_once('=') {
                Some((name, _)) if form_secret(name) => format!("{name}=[redacted]"),
                _ => field.to_owned(),
            })
            .collect();
        return Cow::Owned(fields.join("&").into_bytes());
    }
    Cow::Borrowed(body)
}

/// Whether a form field's name names a credential.
fn form_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FORM_SECRETS.contains(&lower.as_str()) || is_credential(&lower.replace('_', "-"))
}

/// The head text of a request or response as the dump writes it: the
/// start line, then each header as `name: value`, each line ending in
/// CRLF. `headers` are the observer's, which never hold a credential's
/// value.
pub fn head_text<'a>(
    start_line: &str,
    headers: impl Iterator<Item = (&'a str, &'a [u8])>,
) -> String {
    let mut text = String::with_capacity(256);
    text.push_str(start_line);
    text.push_str("\r\n");
    for (name, value) in headers {
        text.push_str(name);
        text.push_str(": ");
        text.push_str(&String::from_utf8_lossy(value));
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
        let record = pcap_record(at, &frame);
        assert_eq!(record.len(), 16 + 60);
        assert_eq!(u32_at(&record, 0), 1_700_000_000);
        assert_eq!(u32_at(&record, 4), 123_456, "microseconds");
        assert_eq!(u32_at(&record, 8), 60, "included");
        assert_eq!(u32_at(&record, 12), 60, "original");
        assert_eq!(&record[16..], &frame);

        // Over the snapshot length the record is cut and says so.
        let long = vec![1u8; SNAPLEN as usize + 10];
        let record = pcap_record(at, &long);
        assert_eq!(u32_at(&record, 8), SNAPLEN);
        assert_eq!(u32_at(&record, 12), SNAPLEN + 10);
        assert_eq!(record.len(), 16 + SNAPLEN as usize);
    }

    #[test]
    fn frames_land_in_the_file_in_order_with_the_header_first() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DumpDir::prepare(&tmp.path().join("dump"), &[]).unwrap();
        let (dump, thread) = FrameDump::start(&dir).unwrap();
        assert!(dump.push(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]));
        assert!(dump.push(&[0xff; 20]));
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
        assert_eq!(u32_at(&bytes, second + 8), 20);
        assert_eq!(bytes.len(), second + 16 + 20);
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
        let dump = FrameDump { tx };
        assert!(dump.push(&[0; 14]));
        assert!(dump.push(&[0; 14]));
        let start = std::time::Instant::now();
        assert!(!dump.push(&[0; 14]), "the third has no room");
        assert!(start.elapsed() < Duration::from_millis(100));
        drop(rx);
        assert!(!dump.push(&[0; 14]), "nobody to take it");
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
        // Again: an existing directory is fine.
        DumpDir::prepare(&tmp.path().join("dump"), &[&share]).unwrap();
        // A file in the way is not.
        fs::write(tmp.path().join("file"), b"x").unwrap();
        assert!(DumpDir::prepare(&tmp.path().join("file"), &[]).is_err());
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
            b"{\"model\":\"m\",\"api_key\":\"sk-123\"}",
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
        let bad_json = b"{not json";
        assert_eq!(
            &*scrubbed_body(Some("application/json"), bad_json),
            &bad_json[..]
        );
        let sse = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
        assert_eq!(&*scrubbed_body(Some("text/event-stream"), sse), &sse[..]);
        assert_eq!(&*scrubbed_body(None, b"raw"), &b"raw"[..]);
    }
}
