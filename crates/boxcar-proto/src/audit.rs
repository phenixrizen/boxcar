// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The audit record envelope and the typed payloads that fill it.
//!
//! Everything boxcar observes becomes one [`Record`], written as one line of
//! JSON. The envelope is flat: `type` and `data` sit at the top level beside
//! the sequence number, timestamps, and chain fields, so a reader can filter
//! and page a log without knowing any event type. [`Payload`] is the typed
//! view of `type` plus `data` for the event kinds this crate defines. It
//! converts to and from `(kind, Value)`, and readers never need it.
//!
//! # The hash chain
//!
//! Each record commits to the one before it:
//!
//! ```text
//! hash = blake3(prev_bytes || canonical_json)
//! ```
//!
//! `prev_bytes` is the 32 raw bytes of the record's `prev`, which is the
//! previous record's `hash`, or `genesis_prev` for the first record of a
//! session. `canonical_json` is `serde_json::to_vec` of the record converted
//! to a `serde_json::Value` with the `hash` key removed: no whitespace, and
//! every object key sorted at every depth, because serde_json's default `Map`
//! is a `BTreeMap`. Nothing in the workspace may enable serde_json's
//! `preserve_order` feature. The pinned vector in this module's tests fails
//! if one does.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ids::SessionId;

mod errno;
mod payloads;

pub use payloads::{
    ArtifactRef, Attrib, Checkpoint, ControlConnect, ControlStop, FsClose, FsCreate, FsDenied,
    FsFallocate, FsIo, FsLink, FsMkdir, FsMknod, FsMount, FsOpen, FsPathOp, FsRename, FsSetattr,
    FsSymlink, FsXattr, HashStatus, NetClose, NetConnect, NetDhcp, NetDns, NetDrop, NetTls, NetUdp,
    OpResult, SetAttr, ShareRef, Verdict, VmmStart, VmmStop,
};

/// The value of a record's `v` field.
pub const SCHEMA_VERSION: u8 = 1;

/// Which side of the VM boundary made an observation. On the wire this is the
/// JSON integer `0` or `1`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ring {
    /// Seen by the host: the VMM, its devices, the gateway.
    Host = 0,
    /// Reported by code running inside the guest.
    Guest = 1,
}

impl Serialize for Ring {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Ring {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u8::deserialize(deserializer)? {
            0 => Ok(Ring::Host),
            1 => Ok(Ring::Guest),
            other => Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(other.into()),
                &"0 (host) or 1 (guest)",
            )),
        }
    }
}

/// The component that produced a record. On the wire, the lowercase name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Vmm,
    Fs,
    Net,
    Vsock,
    Pty,
    Guest,
    Sensor,
    Reconciler,
    Gateway,
    Control,
}

impl Source {
    /// The source of an event kind this crate defines a payload for:
    /// `vmm.*` and `checkpoint` come from the VMM, `fs.*` from the filesystem
    /// device, `net.*` from the network stack, `control.*` from the control
    /// socket. `None` for every other kind; later milestones add theirs.
    pub fn from_kind(kind: &str) -> Option<Source> {
        if kind == "checkpoint" || kind.starts_with("vmm.") {
            Some(Source::Vmm)
        } else if kind.starts_with("fs.") {
            Some(Source::Fs)
        } else if kind.starts_with("net.") {
            Some(Source::Net)
        } else if kind.starts_with("control.") {
            Some(Source::Control)
        } else {
            None
        }
    }
}

/// The guest identity an event is attributed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Where an event sits in a trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanRef {
    pub trace_id: String,
    pub span_id: String,
}

/// A blake3 digest. On the wire it is a string: `b3:` followed by 64
/// lowercase hex digits. Parsing accepts nothing else, so a hash has exactly
/// one text form and the canonical JSON that covers it is unambiguous.
///
/// Encoding and decoding are done here, without the `hex` crate and without
/// blake3, so this type works when the crate is built without the `hash`
/// feature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

const HASH_PREFIX: &str = "b3:";
const HASH_HEX_LEN: usize = 64;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

impl Hash {
    #[cfg(feature = "hash")]
    pub fn from_blake3(hash: blake3::Hash) -> Hash {
        Hash(*hash.as_bytes())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write as _;
        f.write_str(HASH_PREFIX)?;
        for byte in self.0 {
            f.write_char(char::from(HEX_DIGITS[usize::from(byte >> 4)]))?;
            f.write_char(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]))?;
        }
        Ok(())
    }
}

/// Shows the digest as its wire text, not as 32 integers.
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

/// The text is not `b3:` followed by 64 lowercase hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseHashError {
    #[error("hash must start with \"b3:\"")]
    MissingPrefix,
    #[error("hash must have 64 hex digits after \"b3:\", found {0} bytes")]
    BadLength(usize),
    #[error("hash must be lowercase hex digits after \"b3:\"")]
    BadDigit,
}

fn hex_value(digit: u8) -> Result<u8, ParseHashError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(ParseHashError::BadDigit),
    }
}

impl FromStr for Hash {
    type Err = ParseHashError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let digits = text
            .strip_prefix(HASH_PREFIX)
            .ok_or(ParseHashError::MissingPrefix)?;
        if digits.len() != HASH_HEX_LEN {
            return Err(ParseHashError::BadLength(digits.len()));
        }
        let mut bytes = [0u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(digits.as_bytes().chunks_exact(2)) {
            *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }
        Ok(Hash(bytes))
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;

        impl de::Visitor<'_> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string of `b3:` and 64 lowercase hex digits")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Hash, E> {
                text.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(HashVisitor)
    }
}

/// One audit record: one line of a session's log.
///
/// The JSON field names are these field names, except that `kind` is `type`.
/// Unset optional fields are left out of the JSON, never written as `null`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// The schema version, [`SCHEMA_VERSION`].
    pub v: u8,
    pub session_id: SessionId,
    /// The record's position in the session, counting from 1 with no gaps.
    /// Only the log writer assigns it.
    pub seq: u64,
    pub ring: Ring,
    pub src: Source,
    /// The dotted event type, such as `fs.open`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Host wall-clock time (`CLOCK_REALTIME`) in nanoseconds since the Unix
    /// epoch, taken when the writer received the event. This is the only
    /// timestamp that joins events across rings.
    pub ts_host_ns: u64,
    /// Host `CLOCK_MONOTONIC` in nanoseconds, taken at the same moment.
    pub ts_mono_ns: u64,
    /// The guest's own clock, for events reported from inside the guest. It
    /// orders ring 1 events among themselves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_guest_ns: Option<u64>,
    /// The guest process the event is attributed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    /// The payload. Its shape is decided by `kind`; see [`Payload`] for the
    /// kinds this crate defines.
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<SpanRef>,
    /// The `hash` of the previous record, or `genesis_prev` for the first.
    pub prev: Hash,
    /// This record's hash, from `Record::compute_hash`.
    pub hash: Hash,
}

impl Record {
    /// The canonical JSON the hash covers: this record as a
    /// `serde_json::Value` with the `hash` key removed, written with no
    /// whitespace and with every object key sorted, at every depth.
    pub fn canonical_bytes_without_hash(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("a Record always converts to a Value");
        if let Value::Object(fields) = &mut value {
            fields.remove("hash");
        }
        serde_json::to_vec(&value).expect("a Value always serializes")
    }

    /// `blake3(prev_bytes || canonical_json)`, where `prev_bytes` is the 32
    /// raw bytes of `self.prev` and `canonical_json` is
    /// [`canonical_bytes_without_hash`](Self::canonical_bytes_without_hash).
    #[cfg(feature = "hash")]
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.prev.0);
        hasher.update(&self.canonical_bytes_without_hash());
        Hash::from_blake3(hasher.finalize())
    }
}

/// The `prev` of a session's first record: the blake3 of the session id's
/// UTF-8 text.
#[cfg(feature = "hash")]
pub fn genesis_prev(session_id: &SessionId) -> Hash {
    Hash::from_blake3(blake3::hash(session_id.as_str().as_bytes()))
}

/// The typed payloads: one variant per event kind this crate defines.
///
/// Adjacently tagged, so it serializes as `{"type": "fs.open", "data": {...}}`,
/// which are the two fields a [`Record`] carries at its top level. New kinds
/// are additive, and a consumer ignores kinds it does not know.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Payload {
    #[serde(rename = "vmm.start")]
    VmmStart(VmmStart),
    #[serde(rename = "vmm.stop")]
    VmmStop(VmmStop),
    #[serde(rename = "fs.mount")]
    FsMount(FsMount),
    #[serde(rename = "fs.open")]
    FsOpen(FsOpen),
    #[serde(rename = "fs.create")]
    FsCreate(FsCreate),
    #[serde(rename = "fs.close")]
    FsClose(FsClose),
    #[serde(rename = "fs.read")]
    FsRead(FsIo),
    #[serde(rename = "fs.write")]
    FsWrite(FsIo),
    #[serde(rename = "fs.unlink")]
    FsUnlink(FsPathOp),
    #[serde(rename = "fs.rmdir")]
    FsRmdir(FsPathOp),
    #[serde(rename = "fs.mkdir")]
    FsMkdir(FsMkdir),
    #[serde(rename = "fs.mknod")]
    FsMknod(FsMknod),
    #[serde(rename = "fs.symlink")]
    FsSymlink(FsSymlink),
    #[serde(rename = "fs.link")]
    FsLink(FsLink),
    #[serde(rename = "fs.rename")]
    FsRename(FsRename),
    #[serde(rename = "fs.setattr")]
    FsSetattr(FsSetattr),
    #[serde(rename = "fs.fallocate")]
    FsFallocate(FsFallocate),
    #[serde(rename = "fs.xattr")]
    FsXattr(FsXattr),
    #[serde(rename = "fs.denied")]
    FsDenied(FsDenied),
    #[serde(rename = "fs.readdir")]
    FsReaddir(FsPathOp),
    #[serde(rename = "checkpoint")]
    Checkpoint(Checkpoint),
    #[serde(rename = "control.connect")]
    ControlConnect(ControlConnect),
    #[serde(rename = "control.stop")]
    ControlStop(ControlStop),
    #[serde(rename = "net.dhcp")]
    NetDhcp(NetDhcp),
    #[serde(rename = "net.dns")]
    NetDns(NetDns),
    #[serde(rename = "net.connect")]
    NetConnect(NetConnect),
    #[serde(rename = "net.tls")]
    NetTls(NetTls),
    #[serde(rename = "net.close")]
    NetClose(NetClose),
    #[serde(rename = "net.drop")]
    NetDrop(NetDrop),
    #[serde(rename = "net.udp")]
    NetUdp(NetUdp),
}

impl Payload {
    /// The dotted event type, the `type` of the record that carries this
    /// payload.
    pub fn kind(&self) -> &'static str {
        match self {
            Payload::VmmStart(_) => "vmm.start",
            Payload::VmmStop(_) => "vmm.stop",
            Payload::FsMount(_) => "fs.mount",
            Payload::FsOpen(_) => "fs.open",
            Payload::FsCreate(_) => "fs.create",
            Payload::FsClose(_) => "fs.close",
            Payload::FsRead(_) => "fs.read",
            Payload::FsWrite(_) => "fs.write",
            Payload::FsUnlink(_) => "fs.unlink",
            Payload::FsRmdir(_) => "fs.rmdir",
            Payload::FsMkdir(_) => "fs.mkdir",
            Payload::FsMknod(_) => "fs.mknod",
            Payload::FsSymlink(_) => "fs.symlink",
            Payload::FsLink(_) => "fs.link",
            Payload::FsRename(_) => "fs.rename",
            Payload::FsSetattr(_) => "fs.setattr",
            Payload::FsFallocate(_) => "fs.fallocate",
            Payload::FsXattr(_) => "fs.xattr",
            Payload::FsDenied(_) => "fs.denied",
            Payload::FsReaddir(_) => "fs.readdir",
            Payload::Checkpoint(_) => "checkpoint",
            Payload::ControlConnect(_) => "control.connect",
            Payload::ControlStop(_) => "control.stop",
            Payload::NetDhcp(_) => "net.dhcp",
            Payload::NetDns(_) => "net.dns",
            Payload::NetConnect(_) => "net.connect",
            Payload::NetTls(_) => "net.tls",
            Payload::NetClose(_) => "net.close",
            Payload::NetDrop(_) => "net.drop",
            Payload::NetUdp(_) => "net.udp",
        }
    }

    /// The source of the record that carries this payload: the VMM for
    /// `vmm.*` and `checkpoint`, the filesystem device for `fs.*`, the
    /// network stack for `net.*`, the control socket for `control.*`, as
    /// [`Source::from_kind`] says. A new variant does not compile until it
    /// is given one.
    pub fn source(&self) -> Source {
        match self {
            Payload::VmmStart(_) | Payload::VmmStop(_) | Payload::Checkpoint(_) => Source::Vmm,
            Payload::FsMount(_)
            | Payload::FsOpen(_)
            | Payload::FsCreate(_)
            | Payload::FsClose(_)
            | Payload::FsRead(_)
            | Payload::FsWrite(_)
            | Payload::FsUnlink(_)
            | Payload::FsRmdir(_)
            | Payload::FsMkdir(_)
            | Payload::FsMknod(_)
            | Payload::FsSymlink(_)
            | Payload::FsLink(_)
            | Payload::FsRename(_)
            | Payload::FsSetattr(_)
            | Payload::FsFallocate(_)
            | Payload::FsXattr(_)
            | Payload::FsDenied(_)
            | Payload::FsReaddir(_) => Source::Fs,
            Payload::ControlConnect(_) | Payload::ControlStop(_) => Source::Control,
            Payload::NetDhcp(_)
            | Payload::NetDns(_)
            | Payload::NetConnect(_)
            | Payload::NetTls(_)
            | Payload::NetClose(_)
            | Payload::NetDrop(_)
            | Payload::NetUdp(_) => Source::Net,
        }
    }

    /// The record's `type` and `data` for this payload, such as
    /// `("fs.open", {...})`.
    pub fn into_parts(&self) -> (String, Value) {
        let mut tagged = serde_json::to_value(self).expect("a Payload always converts to a Value");
        (self.kind().to_owned(), tagged["data"].take())
    }

    /// The typed payload of a record, rebuilt from its `type` and `data`.
    ///
    /// An unknown `type`, or `data` that does not fit it, is an error. Readers
    /// of a log must not depend on this: they work on [`Record`] and treat
    /// `data` as opaque.
    pub fn from_record(r: &Record) -> Result<Payload, serde_json::Error> {
        let mut tagged = Map::with_capacity(2);
        tagged.insert("type".to_owned(), Value::String(r.kind.clone()));
        tagged.insert("data".to_owned(), r.data.clone());
        serde_json::from_value(Value::Object(tagged))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use crate::control::StopMode;
    use serde_json::json;

    const SESSION: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

    /// The 30 wire names of the typed payloads, in schema order.
    const KINDS: [&str; 30] = [
        "vmm.start",
        "vmm.stop",
        "fs.mount",
        "fs.open",
        "fs.create",
        "fs.close",
        "fs.read",
        "fs.write",
        "fs.unlink",
        "fs.rmdir",
        "fs.mkdir",
        "fs.mknod",
        "fs.symlink",
        "fs.link",
        "fs.rename",
        "fs.setattr",
        "fs.fallocate",
        "fs.xattr",
        "fs.denied",
        "fs.readdir",
        "checkpoint",
        "control.connect",
        "control.stop",
        "net.dhcp",
        "net.dns",
        "net.connect",
        "net.tls",
        "net.close",
        "net.drop",
        "net.udp",
    ];

    fn session() -> SessionId {
        SESSION.parse().unwrap()
    }

    /// The `b3:` text of a hash whose 32 bytes all equal `fill`.
    fn b3(fill: u8) -> String {
        format!("b3:{}", format!("{fill:02x}").repeat(32))
    }

    fn artifact(path: &str, fill: u8) -> ArtifactRef {
        ArtifactRef {
            path: path.into(),
            blake3: Hash([fill; 32]),
        }
    }

    /// A record with an all-zero `prev` and `hash`, for tests that do not hash.
    fn record(kind: &str, src: Source, data: Value) -> Record {
        Record {
            v: SCHEMA_VERSION,
            session_id: session(),
            seq: 1,
            ring: Ring::Host,
            src,
            kind: kind.to_owned(),
            ts_host_ns: 1_700_000_000_000_000_000,
            ts_mono_ns: 42_000_000_000,
            ts_guest_ns: None,
            subject: None,
            data,
            span: None,
            prev: Hash([0; 32]),
            hash: Hash([0; 32]),
        }
    }

    /// One payload per variant, in schema order, paired with the exact `data`
    /// JSON it must produce. This table is the wire schema: a Go reader mirrors
    /// these names.
    fn cases() -> Vec<(Payload, Value)> {
        vec![
            (
                Payload::VmmStart(VmmStart {
                    version: "0.1.0".into(),
                    kernel: artifact("/k/vmlinux", 0x11),
                    initramfs: Some(artifact("/k/initramfs.cpio", 0x22)),
                    cmdline: "console=ttyS0 quiet".into(),
                    vcpus: 2,
                    mem_mib: 512,
                    shares: vec![
                        ShareRef {
                            tag: "root".into(),
                            host_root: "/k/rootfs".into(),
                        },
                        ShareRef {
                            tag: "workspace".into(),
                            host_root: "/tmp/ws".into(),
                        },
                    ],
                }),
                json!({
                    "version": "0.1.0",
                    "kernel": {"path": "/k/vmlinux", "blake3": b3(0x11)},
                    "initramfs": {"path": "/k/initramfs.cpio", "blake3": b3(0x22)},
                    "cmdline": "console=ttyS0 quiet",
                    "vcpus": 2,
                    "mem_mib": 512,
                    "shares": [
                        {"tag": "root", "host_root": "/k/rootfs"},
                        {"tag": "workspace", "host_root": "/tmp/ws"},
                    ],
                }),
            ),
            (
                Payload::VmmStop(VmmStop {
                    reason: "guest_reset".into(),
                    exit_code: Some(0),
                    console_dropped_bytes: 4096,
                    stdin_dropped_bytes: 100,
                }),
                json!({
                    "reason": "guest_reset",
                    "exit_code": 0,
                    "console_dropped_bytes": 4096,
                    "stdin_dropped_bytes": 100,
                }),
            ),
            (
                Payload::FsMount(FsMount {
                    mount: "workspace".into(),
                    guest_path: "/workspace".into(),
                    host_root: "/tmp/ws".into(),
                    cache_policy: "auto".into(),
                }),
                json!({
                    "mount": "workspace",
                    "guest_path": "/workspace",
                    "host_root": "/tmp/ws",
                    "cache_policy": "auto",
                }),
            ),
            (
                Payload::FsOpen(FsOpen {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    fh: 7,
                    flags: 0o102,
                    flags_decoded: vec!["O_RDWR".into(), "O_CREAT".into()],
                    exec: false,
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "fh": 7,
                    "flags": 66,
                    "flags_decoded": ["O_RDWR", "O_CREAT"],
                    "exec": false,
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsCreate(FsCreate {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    fh: 8,
                    mode: 0o644,
                    flags: 0o101,
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "fh": 8,
                    "mode": 420,
                    "flags": 65,
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsClose(FsClose {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    path_at_open: "/a/old.txt".into(),
                    fh: 8,
                    bytes_read: 0,
                    bytes_written: 3,
                    size: Some(3),
                    blake3: Some(Hash([0xab; 32])),
                    hash_status: HashStatus::Ok,
                    open_seq: Some(41),
                    attrib: Attrib::Caller,
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "path_at_open": "/a/old.txt",
                    "fh": 8,
                    "bytes_read": 0,
                    "bytes_written": 3,
                    "size": 3,
                    "blake3": b3(0xab),
                    "hash_status": "ok",
                    "open_seq": 41,
                    "attrib": "caller",
                }),
            ),
            (
                Payload::FsRead(FsIo {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    fh: 7,
                    offset: 4096,
                    len: 512,
                    result: OpResult::ok(),
                    attrib: Attrib::Caller,
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "fh": 7,
                    "offset": 4096,
                    "len": 512,
                    "result": {"ok": true},
                    "attrib": "caller",
                }),
            ),
            (
                Payload::FsWrite(FsIo {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    fh: 7,
                    offset: 0,
                    len: 3,
                    result: OpResult::errno(28),
                    attrib: Attrib::Handle,
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "fh": 7,
                    "offset": 0,
                    "len": 3,
                    "result": {"ok": false, "errno": 28, "err": "ENOSPC"},
                    "attrib": "handle",
                }),
            ),
            (
                Payload::FsUnlink(FsPathOp {
                    mount: "workspace".into(),
                    path: "/a/old".into(),
                    result: OpResult::ok(),
                }),
                json!({"mount": "workspace", "path": "/a/old", "result": {"ok": true}}),
            ),
            (
                Payload::FsRmdir(FsPathOp {
                    mount: "workspace".into(),
                    path: "/a".into(),
                    result: OpResult::errno(39),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a",
                    "result": {"ok": false, "errno": 39, "err": "ENOTEMPTY"},
                }),
            ),
            (
                Payload::FsMkdir(FsMkdir {
                    mount: "workspace".into(),
                    path: "/a/d".into(),
                    mode: 0o755,
                    result: OpResult::ok(),
                }),
                json!({"mount": "workspace", "path": "/a/d", "mode": 493, "result": {"ok": true}}),
            ),
            (
                Payload::FsMknod(FsMknod {
                    mount: "root".into(),
                    path: "/dev/null".into(),
                    mode: 0o020666,
                    rdev: 259,
                    result: OpResult::errno(1),
                }),
                json!({
                    "mount": "root",
                    "path": "/dev/null",
                    "mode": 8630,
                    "rdev": 259,
                    "result": {"ok": false, "errno": 1, "err": "EPERM"},
                }),
            ),
            (
                Payload::FsSymlink(FsSymlink {
                    mount: "workspace".into(),
                    path: "/a/link".into(),
                    target: "/etc/passwd".into(),
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/link",
                    "target": "/etc/passwd",
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsLink(FsLink {
                    mount: "workspace".into(),
                    path: "/a/hard".into(),
                    target_path: "/a/b.txt".into(),
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/hard",
                    "target_path": "/a/b.txt",
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsRename(FsRename {
                    mount: "workspace".into(),
                    from: "/a/x".into(),
                    to: "/a/y".into(),
                    flags: 2,
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "from": "/a/x",
                    "to": "/a/y",
                    "flags": 2,
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsSetattr(FsSetattr {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    set: SetAttr {
                        mode: Some(0o600),
                        size: Some(0),
                        ..SetAttr::default()
                    },
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "set": {"mode": 384, "size": 0},
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsFallocate(FsFallocate {
                    mount: "workspace".into(),
                    path: "/a/big".into(),
                    offset: 0,
                    len: 1 << 20,
                    mode: 0,
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/big",
                    "offset": 0,
                    "len": 1048576,
                    "mode": 0,
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsXattr(FsXattr {
                    mount: "workspace".into(),
                    path: "/a/b.txt".into(),
                    name: "user.k".into(),
                    op: "set".into(),
                    result: OpResult::ok(),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a/b.txt",
                    "name": "user.k",
                    "op": "set",
                    "result": {"ok": true},
                }),
            ),
            (
                Payload::FsDenied(FsDenied {
                    mount: "root".into(),
                    path: "/etc/shadow".into(),
                    op: "lookup".into(),
                    errno: 13,
                }),
                json!({"mount": "root", "path": "/etc/shadow", "op": "lookup", "errno": 13}),
            ),
            (
                Payload::FsReaddir(FsPathOp {
                    mount: "root".into(),
                    path: "/".into(),
                    result: OpResult::ok(),
                }),
                json!({"mount": "root", "path": "/", "result": {"ok": true}}),
            ),
            (
                Payload::Checkpoint(Checkpoint {
                    records_since: 1024,
                    dropped: 0,
                    root_hash: Hash([0x33; 32]),
                }),
                json!({"records_since": 1024, "dropped": 0, "root_hash": b3(0x33)}),
            ),
            (
                Payload::ControlConnect(ControlConnect {
                    pid: 4242,
                    uid: 1000,
                    verdict: Verdict::Allow,
                }),
                json!({"pid": 4242, "uid": 1000, "verdict": "allow"}),
            ),
            (
                Payload::ControlStop(ControlStop {
                    by_pid: 4242,
                    mode: StopMode::Graceful,
                }),
                json!({"by_pid": 4242, "mode": "graceful"}),
            ),
            (
                Payload::NetDhcp(NetDhcp {
                    op: "offer".into(),
                    yiaddr: Ipv4Addr::new(10, 0, 2, 15),
                }),
                json!({"op": "offer", "yiaddr": "10.0.2.15"}),
            ),
            (
                Payload::NetDns(NetDns {
                    txid: 0xbeef,
                    qname: "example.com".into(),
                    qtype: 1,
                    rcode: 0,
                    answers: vec!["93.184.215.14".into(), "93.184.215.15".into()],
                    verdict: Verdict::Allow,
                    rule: Some("allow example.com".into()),
                }),
                json!({
                    "txid": 48879,
                    "qname": "example.com",
                    "qtype": 1,
                    "rcode": 0,
                    "answers": ["93.184.215.14", "93.184.215.15"],
                    "verdict": "allow",
                    "rule": "allow example.com",
                }),
            ),
            (
                Payload::NetConnect(NetConnect {
                    flow: 7,
                    proto: "tcp".into(),
                    src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 43210),
                    dst: SocketAddrV4::new(Ipv4Addr::new(93, 184, 215, 14), 443),
                    names: vec!["example.com".into()],
                    verdict: Verdict::Allow,
                    rule: Some("allow example.com:443".into()),
                }),
                json!({
                    "flow": 7,
                    "proto": "tcp",
                    "src": "10.0.2.15:43210",
                    "dst": "93.184.215.14:443",
                    "names": ["example.com"],
                    "verdict": "allow",
                    "rule": "allow example.com:443",
                }),
            ),
            (
                Payload::NetTls(NetTls {
                    flow: 7,
                    kind: "tls".into(),
                    sni: Some("example.com".into()),
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    verdict: Verdict::Allow,
                }),
                json!({
                    "flow": 7,
                    "kind": "tls",
                    "sni": "example.com",
                    "alpn": ["h2", "http/1.1"],
                    "verdict": "allow",
                }),
            ),
            (
                Payload::NetClose(NetClose {
                    flow: 7,
                    tx: 517,
                    rx: 10_485_760,
                    dur_ms: 1250,
                    reason: "fin".into(),
                }),
                json!({"flow": 7, "tx": 517, "rx": 10485760, "dur_ms": 1250, "reason": "fin"}),
            ),
            (
                Payload::NetDrop(NetDrop {
                    reason: "ipv6".into(),
                    count: 12,
                }),
                json!({"reason": "ipv6", "count": 12}),
            ),
            (
                Payload::NetUdp(NetUdp {
                    flow: 8,
                    src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 5353),
                    dst: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 123),
                    verdict: Verdict::Deny,
                }),
                json!({
                    "flow": 8,
                    "src": "10.0.2.15:5353",
                    "dst": "192.0.2.1:123",
                    "verdict": "deny",
                }),
            ),
        ]
    }

    /// The other values of the control payloads' enums.
    #[test]
    fn control_payloads_spell_deny_and_force() {
        let deny = Payload::ControlConnect(ControlConnect {
            pid: 1,
            uid: 1001,
            verdict: Verdict::Deny,
        });
        assert_eq!(
            deny.into_parts(),
            (
                "control.connect".to_owned(),
                json!({"pid": 1, "uid": 1001, "verdict": "deny"})
            )
        );
        let force = Payload::ControlStop(ControlStop {
            by_pid: 1,
            mode: StopMode::Force,
        });
        assert_eq!(force.into_parts().1, json!({"by_pid": 1, "mode": "force"}));
    }

    /// Payloads whose optional fields are unset. `Option`s that the schema
    /// does not mark skip-if-none travel as explicit nulls.
    fn unset_optional_cases() -> Vec<(Payload, Value)> {
        vec![
            (
                Payload::VmmStart(VmmStart {
                    version: "0.1.0".into(),
                    kernel: artifact("/k/vmlinux", 0x11),
                    initramfs: None,
                    cmdline: String::new(),
                    vcpus: 1,
                    mem_mib: 128,
                    shares: Vec::new(),
                }),
                json!({
                    "version": "0.1.0",
                    "kernel": {"path": "/k/vmlinux", "blake3": b3(0x11)},
                    "initramfs": null,
                    "cmdline": "",
                    "vcpus": 1,
                    "mem_mib": 128,
                }),
            ),
            (
                Payload::VmmStop(VmmStop {
                    reason: "vcpu_error".into(),
                    exit_code: None,
                    console_dropped_bytes: 0,
                    stdin_dropped_bytes: 0,
                }),
                json!({
                    "reason": "vcpu_error",
                    "exit_code": null,
                    "console_dropped_bytes": 0,
                    "stdin_dropped_bytes": 0,
                }),
            ),
            (
                Payload::FsClose(FsClose {
                    mount: "root".into(),
                    path: "/bin/sh".into(),
                    path_at_open: "/bin/sh".into(),
                    fh: 1,
                    bytes_read: 1024,
                    bytes_written: 0,
                    size: None,
                    blake3: None,
                    hash_status: HashStatus::NotHashed,
                    open_seq: None,
                    attrib: Attrib::Handle,
                }),
                json!({
                    "mount": "root",
                    "path": "/bin/sh",
                    "path_at_open": "/bin/sh",
                    "fh": 1,
                    "bytes_read": 1024,
                    "bytes_written": 0,
                    "size": null,
                    "blake3": null,
                    "hash_status": "not_hashed",
                    "open_seq": null,
                    "attrib": "handle",
                }),
            ),
            (
                Payload::FsSetattr(FsSetattr {
                    mount: "workspace".into(),
                    path: "/a".into(),
                    set: SetAttr {
                        atime: Some(1_700_000_000),
                        mtime: Some(-1),
                        ..SetAttr::default()
                    },
                    result: OpResult::errno(1),
                }),
                json!({
                    "mount": "workspace",
                    "path": "/a",
                    "set": {"atime": 1700000000, "mtime": -1},
                    "result": {"ok": false, "errno": 1, "err": "EPERM"},
                }),
            ),
            (
                Payload::NetDns(NetDns {
                    txid: 1,
                    qname: "blocked.example".into(),
                    qtype: 28,
                    rcode: 3,
                    answers: Vec::new(),
                    verdict: Verdict::Deny,
                    rule: None,
                }),
                json!({
                    "txid": 1,
                    "qname": "blocked.example",
                    "qtype": 28,
                    "rcode": 3,
                    "answers": [],
                    "verdict": "deny",
                    "rule": null,
                }),
            ),
            (
                Payload::NetConnect(NetConnect {
                    flow: 9,
                    proto: "tcp".into(),
                    src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 40000),
                    dst: SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 22),
                    names: Vec::new(),
                    verdict: Verdict::Deny,
                    rule: None,
                }),
                json!({
                    "flow": 9,
                    "proto": "tcp",
                    "src": "10.0.2.15:40000",
                    "dst": "10.1.2.3:22",
                    "names": [],
                    "verdict": "deny",
                    "rule": null,
                }),
            ),
            (
                // A plain HTTP request with no Host to read.
                Payload::NetTls(NetTls {
                    flow: 9,
                    kind: "http".into(),
                    sni: None,
                    alpn: Vec::new(),
                    verdict: Verdict::Deny,
                }),
                json!({"flow": 9, "kind": "http", "sni": null, "alpn": [], "verdict": "deny"}),
            ),
        ]
    }

    // (a) Every Payload variant round-trips through into_parts -> Record ->
    // from_record.

    #[test]
    fn every_payload_variant_round_trips_through_a_record() {
        let all = cases();
        let kinds: Vec<&str> = all.iter().map(|(p, _)| p.kind()).collect();
        assert_eq!(kinds, KINDS, "one case per variant, in schema order");

        for (payload, want_data) in all.iter().chain(&unset_optional_cases()) {
            let (kind, data) = payload.into_parts();
            assert_eq!(kind, payload.kind());
            assert_eq!(&data, want_data, "{kind}: wire shape of data");

            let rec = record(&kind, payload.source(), data);
            assert_eq!(&Payload::from_record(&rec).unwrap(), payload, "{kind}");

            // And through the bytes a reader would find in the log.
            let line = serde_json::to_string(&rec).unwrap();
            let parsed: Record = serde_json::from_str(&line).unwrap();
            assert_eq!(parsed, rec, "{kind}");
            assert_eq!(&Payload::from_record(&parsed).unwrap(), payload, "{kind}");
        }
    }

    #[test]
    fn payloads_serialize_adjacently_tagged_as_type_and_data() {
        for (payload, data) in cases() {
            assert_eq!(
                serde_json::to_value(&payload).unwrap(),
                json!({"type": payload.kind(), "data": data}),
                "{}",
                payload.kind()
            );
            assert!(data.is_object(), "{}: data is an object", payload.kind());
        }
    }

    /// `console_dropped_bytes` and `stdin_dropped_bytes` came after the first
    /// logs: a `vmm.stop` without them reads as no dropped bytes.
    #[test]
    fn a_vmm_stop_without_the_dropped_byte_counts_reads_as_zero() {
        let rec = record(
            "vmm.stop",
            Source::Vmm,
            json!({"reason": "guest_reset", "exit_code": 0}),
        );
        match Payload::from_record(&rec).unwrap() {
            Payload::VmmStop(stop) => {
                assert_eq!(stop.console_dropped_bytes, 0);
                assert_eq!(stop.stdin_dropped_bytes, 0);
            }
            other => panic!("not a vmm.stop: {other:?}"),
        }
    }

    /// `shares` came after the first logs: a `vmm.start` without it (no
    /// shares, or written before it existed) still reads, as no shares.
    #[test]
    fn a_vmm_start_without_shares_reads_as_none() {
        let data = json!({
            "version": "0.1.0",
            "kernel": {"path": "/k/vmlinux", "blake3": b3(0x11)},
            "initramfs": null,
            "cmdline": "",
            "vcpus": 1,
            "mem_mib": 128,
        });
        let rec = record("vmm.start", Source::Vmm, data);
        match Payload::from_record(&rec).unwrap() {
            Payload::VmmStart(start) => assert!(start.shares.is_empty()),
            other => panic!("not a vmm.start: {other:?}"),
        }
    }

    #[test]
    fn a_payload_belongs_to_the_source_of_its_kind_family() {
        for (payload, _) in cases() {
            let expected = if payload.kind().starts_with("fs.") {
                Source::Fs
            } else if payload.kind().starts_with("net.") {
                Source::Net
            } else if payload.kind().starts_with("control.") {
                Source::Control
            } else {
                Source::Vmm
            };
            assert_eq!(payload.source(), expected, "{}", payload.kind());
            assert_eq!(Source::from_kind(payload.kind()), Some(expected));
        }
        assert_eq!(Source::from_kind("vmm.start"), Some(Source::Vmm));
        assert_eq!(Source::from_kind("fs.open"), Some(Source::Fs));
        assert_eq!(Source::from_kind("checkpoint"), Some(Source::Vmm));
        assert_eq!(Source::from_kind("control.stop"), Some(Source::Control));
        assert_eq!(Source::from_kind("net.drop"), Some(Source::Net));
        for other in [
            "vsock.open",
            "proc.exec",
            "finding",
            "",
            "vmm",
            "fs",
            "fsx.open",
            "checkpoints",
            "control",
            "controls.stop",
            "net",
            "network.drop",
        ] {
            assert_eq!(Source::from_kind(other), None, "{other:?}");
        }
    }

    #[test]
    fn from_record_rejects_unknown_kinds_and_malformed_data() {
        let unknown = record("proc.exec", Source::Guest, json!({}));
        assert!(Payload::from_record(&unknown).is_err());
        let missing_fields = record("fs.open", Source::Fs, json!({"mount": "root"}));
        assert!(Payload::from_record(&missing_fields).is_err());
        let not_an_object = record("vmm.stop", Source::Vmm, json!("stopped"));
        assert!(Payload::from_record(&not_an_object).is_err());
    }

    #[test]
    fn canonical_form_drops_only_the_top_level_hash_key() {
        let mut rec = record(
            "fs.write",
            Source::Fs,
            json!({"hash": "user data, not the chain field"}),
        );
        rec.hash = Hash([0xee; 32]);
        let text = String::from_utf8(rec.canonical_bytes_without_hash()).unwrap();
        assert!(
            text.contains(r#""data":{"hash":"user data, not the chain field"}"#),
            "a `hash` key inside data stays covered: {text}"
        );
        assert!(
            !text.contains(&b3(0xee)),
            "the record's own hash is gone: {text}"
        );
        assert!(text.starts_with(r#"{"data":"#) && text.ends_with(r#""v":1}"#));
    }

    #[test]
    fn integers_keep_every_bit_through_json() {
        let mut rec = record("vmm.stop", Source::Vmm, json!({"n": u64::MAX}));
        rec.seq = u64::MAX;
        rec.ts_host_ns = u64::MAX;
        rec.ts_guest_ns = Some(u64::MAX - 1);
        let text = String::from_utf8(rec.canonical_bytes_without_hash()).unwrap();
        assert!(text.contains(r#""seq":18446744073709551615"#), "{text}");
        assert!(
            text.contains(r#""ts_guest_ns":18446744073709551614"#),
            "{text}"
        );
        let back: Record = serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.data["n"].as_u64(), Some(u64::MAX));
    }

    // (b) The hash does not depend on the order keys were inserted in.

    #[cfg(feature = "hash")]
    #[test]
    fn compute_hash_ignores_the_order_keys_were_inserted_in() {
        let mut one = Map::new();
        one.insert("zeta".into(), json!(1));
        one.insert(
            "alpha".into(),
            json!({"y": 1, "x": {"b": true, "a": false}}),
        );
        one.insert("mid".into(), json!([{"q": 1, "p": 2}]));

        let mut other = Map::new();
        other.insert("mid".into(), json!([{"p": 2, "q": 1}]));
        other.insert(
            "alpha".into(),
            json!({"x": {"a": false, "b": true}, "y": 1}),
        );
        other.insert("zeta".into(), json!(1));

        let mut a = record("vmm.stop", Source::Vmm, Value::Object(one));
        let mut b = record("vmm.stop", Source::Vmm, Value::Object(other));
        a.prev = genesis_prev(&session());
        b.prev = genesis_prev(&session());

        assert_eq!(
            a.canonical_bytes_without_hash(),
            b.canonical_bytes_without_hash()
        );
        assert_eq!(a.compute_hash(), b.compute_hash());

        // Sorted at every depth, no whitespace.
        let text = String::from_utf8(a.canonical_bytes_without_hash()).unwrap();
        assert!(
            text.contains(
                r#""data":{"alpha":{"x":{"a":false,"b":true},"y":1},"mid":[{"p":2,"q":1}],"zeta":1}"#
            ),
            "{text}"
        );
    }

    #[cfg(feature = "hash")]
    #[test]
    fn the_hash_covers_every_field_except_hash_itself() {
        let mut base = record("vmm.stop", Source::Vmm, json!({"reason": "test"}));
        base.prev = genesis_prev(&session());
        let expected = base.compute_hash();

        // `hash` is the one field that must not matter.
        let mut other = base.clone();
        other.hash = Hash([0xee; 32]);
        assert_eq!(other.compute_hash(), expected);

        type Mutation = fn(&mut Record);
        let mutations: [(&str, Mutation); 13] = [
            ("v", |r| r.v = 2),
            ("session_id", |r| r.session_id = SessionId::new()),
            ("seq", |r| r.seq = 2),
            ("ring", |r| r.ring = Ring::Guest),
            ("src", |r| r.src = Source::Fs),
            ("type", |r| r.kind = "vmm.start".into()),
            ("ts_host_ns", |r| r.ts_host_ns += 1),
            ("ts_mono_ns", |r| r.ts_mono_ns += 1),
            ("ts_guest_ns", |r| r.ts_guest_ns = Some(0)),
            ("subject", |r| {
                r.subject = Some(Subject {
                    pid: 1,
                    uid: 0,
                    gid: 0,
                })
            }),
            ("data", |r| r.data = json!({"reason": "other"})),
            ("span", |r| {
                r.span = Some(SpanRef {
                    trace_id: "t".into(),
                    span_id: "s".into(),
                })
            }),
            ("prev", |r| r.prev = Hash([1; 32])),
        ];
        for (field, mutate) in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(
                changed.compute_hash(),
                expected,
                "changing {field} must change the hash"
            );
        }
    }

    // (c) Hash text format.

    #[test]
    fn hash_text_is_b3_plus_64_lowercase_hex_and_parses_back() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        bytes[0] = 0x00;
        bytes[31] = 0xff;
        let hash = Hash(bytes);

        let text = hash.to_string();
        assert_eq!(text.len(), 3 + 64);
        assert!(text.starts_with("b3:"));
        assert!(text[3..]
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(&text[3..5], "00");
        assert_eq!(&text[65..], "ff");

        assert_eq!(text.parse::<Hash>().unwrap().0, bytes);

        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(serde_json::from_str::<Hash>(&json).unwrap(), hash);

        // Debug shows the digest, not 32 integers, so failures are readable.
        assert_eq!(format!("{hash:?}"), format!("Hash({text})"));
    }

    #[test]
    fn hash_parsing_is_strict() {
        let zeros = "0".repeat(64);
        assert!(format!("b3:{zeros}").parse::<Hash>().is_ok());
        assert_eq!("".parse::<Hash>(), Err(ParseHashError::MissingPrefix));
        assert_eq!(zeros.parse::<Hash>(), Err(ParseHashError::MissingPrefix));
        assert_eq!(
            format!("B3:{zeros}").parse::<Hash>(),
            Err(ParseHashError::MissingPrefix)
        );
        assert_eq!("b3:".parse::<Hash>(), Err(ParseHashError::BadLength(0)));
        assert_eq!(
            format!("b3:{}", &zeros[1..]).parse::<Hash>(),
            Err(ParseHashError::BadLength(63))
        );
        assert_eq!(
            format!("b3:{zeros}0").parse::<Hash>(),
            Err(ParseHashError::BadLength(65))
        );
        // Uppercase hex is not the canonical text, so it is rejected.
        assert_eq!(
            format!("b3:{}", "A".repeat(64)).parse::<Hash>(),
            Err(ParseHashError::BadDigit)
        );
        assert_eq!(
            format!("b3:{}g", &zeros[1..]).parse::<Hash>(),
            Err(ParseHashError::BadDigit)
        );
        // 64 bytes, but the last two are one two-byte char.
        assert_eq!(
            format!("b3:{}é", &zeros[2..]).parse::<Hash>(),
            Err(ParseHashError::BadDigit)
        );
        for bad in ["42", "null", "[]", "{}"] {
            assert!(serde_json::from_str::<Hash>(bad).is_err(), "{bad}");
        }
    }

    #[cfg(feature = "hash")]
    #[test]
    fn from_blake3_keeps_the_digest_bytes() {
        let digest = blake3::hash(b"boxcar");
        let hash = Hash::from_blake3(digest);
        assert_eq!(hash.0, *digest.as_bytes());
        // blake3's own hex encoder agrees with ours.
        assert_eq!(hash.to_string(), format!("b3:{}", digest.to_hex()));
    }

    // (d) Genesis.

    #[cfg(feature = "hash")]
    #[test]
    fn genesis_prev_is_blake3_of_the_session_id_bytes() {
        let id = session();
        assert_eq!(
            genesis_prev(&id).0,
            *blake3::hash(SESSION.as_bytes()).as_bytes()
        );
        assert_ne!(genesis_prev(&id), genesis_prev(&SessionId::new()));
    }

    // (e) The pinned vector. It fixes the canonical form: any change to field
    // names, key order, number or hash text, or to what the hash covers,
    // fails here. The expected values were built without this crate: Python's
    // `json.dumps(sort_keys=True, separators=(",", ":"))` for the canonical
    // JSON, and the blake3 crate over `prev_bytes || canonical_json` for the
    // hashes.

    #[cfg(feature = "hash")]
    #[test]
    fn pinned_vector_fixes_the_canonical_form_and_the_hash() {
        let mut rec = record(
            "vmm.stop",
            Source::Vmm,
            json!({"reason": "test", "exit_code": 0}),
        );
        rec.prev = genesis_prev(&session());

        let canonical = String::from_utf8(rec.canonical_bytes_without_hash()).unwrap();
        assert_eq!(
            canonical,
            r#"{"data":{"exit_code":0,"reason":"test"},"prev":"b3:73eaf8331d52a5f6d699b4125bd16ba4032c60a53e4589a0a04eadc7be0db101","ring":0,"seq":1,"session_id":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f","src":"vmm","ts_host_ns":1700000000000000000,"ts_mono_ns":42000000000,"type":"vmm.stop","v":1}"#,
            "canonical JSON changed; if keys are not sorted, check that no crate enables serde_json's preserve_order"
        );

        // hash = blake3(prev_bytes || canonical_json), prev as 32 raw bytes.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&rec.prev.0);
        hasher.update(canonical.as_bytes());
        assert_eq!(
            hasher.finalize().to_hex().as_str(),
            "3e3f371ad26d87aff2c94a851825fbab8f0f41a1eb4557450197671c69a5a154"
        );
        assert_eq!(
            rec.compute_hash().to_string(),
            "b3:3e3f371ad26d87aff2c94a851825fbab8f0f41a1eb4557450197671c69a5a154"
        );

        // A finished record survives the disk: parse it back and re-verify.
        rec.hash = rec.compute_hash();
        let line = serde_json::to_string(&rec).unwrap();
        let parsed: Record = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, rec);
        assert_eq!(parsed.compute_hash(), parsed.hash);
    }

    // (f) Ring.

    #[test]
    fn ring_serializes_as_the_integers_0_and_1() {
        assert_eq!(serde_json::to_string(&Ring::Host).unwrap(), "0");
        assert_eq!(serde_json::to_string(&Ring::Guest).unwrap(), "1");
        assert_eq!(serde_json::to_value(Ring::Guest).unwrap(), json!(1));
        assert_eq!(serde_json::from_str::<Ring>("0").unwrap(), Ring::Host);
        assert_eq!(serde_json::from_str::<Ring>("1").unwrap(), Ring::Guest);
        assert_eq!(Ring::Host as u8, 0);
        assert_eq!(Ring::Guest as u8, 1);
        for bad in ["2", "255", "-1", "\"0\"", "\"host\"", "0.0", "true", "null"] {
            assert!(serde_json::from_str::<Ring>(bad).is_err(), "{bad}");
        }

        let rec = serde_json::to_value(record("vmm.stop", Source::Vmm, json!({}))).unwrap();
        assert!(rec["ring"].is_u64(), "ring is a JSON integer in a record");
        assert_eq!(rec["ring"], json!(0));
    }

    // Envelope shape.

    #[test]
    fn optional_envelope_fields_are_omitted_when_unset_and_kept_when_set() {
        let bare = serde_json::to_value(record("vmm.stop", Source::Vmm, json!({}))).unwrap();
        let keys: Vec<&str> = bare
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "data",
                "hash",
                "prev",
                "ring",
                "seq",
                "session_id",
                "src",
                "ts_host_ns",
                "ts_mono_ns",
                "type",
                "v",
            ],
            "`type` is the wire name of `kind`; unset optionals are absent, not null"
        );

        let mut full = record("vmm.stop", Source::Vmm, json!({}));
        full.ts_guest_ns = Some(7);
        full.subject = Some(Subject {
            pid: 1,
            uid: 2,
            gid: 3,
        });
        full.span = Some(SpanRef {
            trace_id: "t".into(),
            span_id: "s".into(),
        });
        let v = serde_json::to_value(&full).unwrap();
        assert_eq!(v["ts_guest_ns"], json!(7));
        assert_eq!(v["subject"], json!({"pid": 1, "uid": 2, "gid": 3}));
        assert_eq!(v["span"], json!({"trace_id": "t", "span_id": "s"}));
        assert_eq!(serde_json::from_value::<Record>(v).unwrap(), full);
    }

    #[test]
    fn a_line_without_optional_fields_parses() {
        let line = format!(
            r#"{{"v":1,"session_id":"{SESSION}","seq":9,"ring":1,"src":"guest","type":"proc.exec","ts_host_ns":5,"ts_mono_ns":6,"data":{{"argv":["ls"]}},"prev":"{}","hash":"{}"}}"#,
            b3(1),
            b3(2)
        );
        let rec: Record = serde_json::from_str(&line).unwrap();
        assert_eq!(rec.v, 1);
        assert_eq!(rec.seq, 9);
        assert_eq!(rec.ring, Ring::Guest);
        assert_eq!(rec.src, Source::Guest);
        assert_eq!(rec.kind, "proc.exec");
        assert_eq!(rec.data, json!({"argv": ["ls"]}));
        assert_eq!(rec.ts_guest_ns, None);
        assert_eq!(rec.subject, None);
        assert_eq!(rec.span, None);
        assert_eq!((rec.prev, rec.hash), (Hash([1; 32]), Hash([2; 32])));
        // Readers never need the typed enum: an unknown kind is still a Record.
        assert!(Payload::from_record(&rec).is_err());
    }

    #[test]
    fn sources_serialize_as_lowercase_strings() {
        for (source, name) in [
            (Source::Vmm, "vmm"),
            (Source::Fs, "fs"),
            (Source::Net, "net"),
            (Source::Vsock, "vsock"),
            (Source::Pty, "pty"),
            (Source::Guest, "guest"),
            (Source::Sensor, "sensor"),
            (Source::Reconciler, "reconciler"),
            (Source::Gateway, "gateway"),
            (Source::Control, "control"),
        ] {
            assert_eq!(serde_json::to_value(source).unwrap(), json!(name));
            assert_eq!(
                serde_json::from_value::<Source>(json!(name)).unwrap(),
                source
            );
        }
        assert!(serde_json::from_value::<Source>(json!("VMM")).is_err());
        assert!(serde_json::from_value::<Source>(json!("proc")).is_err());
    }

    #[test]
    fn hash_status_and_attrib_use_snake_case_names() {
        for (status, name) in [
            (HashStatus::Ok, "ok"),
            (HashStatus::Raced, "raced"),
            (HashStatus::Gone, "gone"),
            (HashStatus::SkippedSize, "skipped_size"),
            (HashStatus::NotHashed, "not_hashed"),
            (HashStatus::Error, "error"),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), json!(name));
            assert_eq!(
                serde_json::from_value::<HashStatus>(json!(name)).unwrap(),
                status
            );
        }
        for (attrib, name) in [(Attrib::Caller, "caller"), (Attrib::Handle, "handle")] {
            assert_eq!(serde_json::to_value(attrib).unwrap(), json!(name));
            assert_eq!(
                serde_json::from_value::<Attrib>(json!(name)).unwrap(),
                attrib
            );
        }
    }

    #[test]
    fn op_result_omits_what_it_does_not_have() {
        assert_eq!(
            serde_json::to_value(OpResult::ok()).unwrap(),
            json!({"ok": true})
        );
        assert_eq!(
            serde_json::to_value(OpResult::errno(13)).unwrap(),
            json!({"ok": false, "errno": 13, "err": "EACCES"})
        );
        // A number with no Linux name still records the number.
        assert_eq!(
            serde_json::to_value(OpResult::errno(9999)).unwrap(),
            json!({"ok": false, "errno": 9999})
        );
        let parsed: OpResult = serde_json::from_value(json!({"ok": true})).unwrap();
        assert_eq!(parsed, OpResult::ok());
    }

    #[test]
    fn set_attr_serializes_only_the_fields_that_were_set() {
        assert_eq!(serde_json::to_value(SetAttr::default()).unwrap(), json!({}));
        let all = SetAttr {
            mode: Some(0o600),
            uid: Some(1000),
            gid: Some(100),
            size: Some(10),
            atime: Some(1),
            mtime: Some(-2),
        };
        assert_eq!(
            serde_json::to_value(&all).unwrap(),
            json!({"mode": 384, "uid": 1000, "gid": 100, "size": 10, "atime": 1, "mtime": -2})
        );
        let back: SetAttr = serde_json::from_value(json!({"mtime": 5})).unwrap();
        assert_eq!(
            back,
            SetAttr {
                mtime: Some(5),
                ..SetAttr::default()
            }
        );
    }
}
