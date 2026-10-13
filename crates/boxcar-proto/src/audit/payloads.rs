// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The typed payloads of [`Payload`](super::Payload): what goes in `data`.
//!
//! Field names are the wire names. `Option` fields that the schema marks
//! skip-if-none are omitted from the JSON when unset; every other `Option` is
//! written as an explicit `null`.
//!
//! Every `fs.*` payload with a `path` has a `path_b64` beside it, set only
//! when the name was not valid UTF-8: `path` then holds the lossy form and
//! `path_b64` the raw bytes in base64. The other names a payload carries
//! (`path_at_open`, `target_path`, `from`, `to`, `target`) are lossy only.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

use super::errno::name as errno_name;
use super::{Hash, Ring};
use crate::control::StopMode;

/// How one operation ended. Present on every filesystem event that performs
/// an operation, so readers can filter failures without knowing the event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OpResult {
    pub ok: bool,
    /// The Linux errno of a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    /// The symbolic name of `errno`, such as `EACCES`, when Linux defines one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

impl OpResult {
    /// The operation succeeded.
    pub fn ok() -> Self {
        OpResult {
            ok: true,
            errno: None,
            err: None,
        }
    }

    /// The operation failed with the Linux errno `e` (a positive number).
    /// `err` is filled with the errno's name when Linux defines one.
    pub fn errno(e: i32) -> Self {
        OpResult {
            ok: false,
            errno: Some(e),
            err: errno_name(e).map(str::to_owned),
        }
    }
}

/// A file the VMM loaded, identified by where it was and what it held.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ArtifactRef {
    pub path: String,
    pub blake3: Hash,
}

/// A directory the VM was given over virtio-fs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ShareRef {
    /// The share's tag, such as `root` or `workspace`.
    pub tag: String,
    /// The host directory it serves.
    pub host_root: String,
}

/// `vmm.start`: the VM was built and is about to run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VmmStart {
    /// The boxcar version.
    pub version: String,
    pub kernel: ArtifactRef,
    pub initramfs: Option<ArtifactRef>,
    pub cmdline: String,
    pub vcpus: u32,
    pub mem_mib: u64,
    /// The virtio-fs shares, in slot order. Omitted when there are none,
    /// and read as none when absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<ShareRef>,
}

/// `vmm.stop`: the VM stopped.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VmmStop {
    pub reason: String,
    pub exit_code: Option<i32>,
    /// Console bytes the guest wrote that the host never wrote out: the
    /// oldest bytes the console's ring dropped when the host's stdout (or
    /// the console file) fell behind, bytes a failed write lost, and what
    /// was still undelivered when the stop sequence gave up waiting for a
    /// stalled writer. 0 when the console kept up. Absent in logs written
    /// before it existed, and read as 0.
    #[serde(default)]
    pub console_dropped_bytes: u64,
    /// Bytes typed at the console that the host dropped because the guest
    /// was not reading them: the oldest input beyond what the serial FIFO
    /// and the host's 4 KiB holding buffer could take. 0 for a run with no
    /// console input. Absent in logs written before it existed, and read
    /// as 0.
    #[serde(default)]
    pub stdin_dropped_bytes: u64,
}

/// `fs.mount`: a virtio-fs share was attached.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsMount {
    /// The share's tag, such as `root` or `workspace`.
    pub mount: String,
    /// Where the guest mounts it.
    pub guest_path: String,
    /// The host directory it serves.
    pub host_root: String,
    pub cache_policy: String,
}

/// `fs.open`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsOpen {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub fh: u64,
    /// The raw `open(2)` flags.
    pub flags: u32,
    /// Names of the flags set in `flags`, such as `O_RDWR` and `O_CREAT`.
    pub flags_decoded: Vec<String>,
    /// The open is for `execve`.
    pub exec: bool,
    pub result: OpResult,
}

/// `fs.create`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsCreate {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub fh: u64,
    pub mode: u32,
    pub flags: u32,
    pub result: OpResult,
}

/// Whether the content of a closed file was hashed, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HashStatus {
    /// Hashed; `blake3` is set.
    Ok,
    /// The file changed while it was being hashed.
    Raced,
    /// The file no longer exists.
    Gone,
    /// Larger than the hashing limit.
    SkippedSize,
    /// Nothing was written through the handle, so there is nothing to hash.
    NotHashed,
    Error,
}

/// Whose identity a record carries as its `subject`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Attrib {
    /// The process that made the request.
    Caller,
    /// The process that opened the handle, when the request itself has no
    /// usable caller (pid 0, or a write-back from the page cache).
    Handle,
}

/// `fs.close`: a handle was released.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsClose {
    pub mount: String,
    /// The path at close time.
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    /// The path when the handle was opened; differs after a rename.
    pub path_at_open: String,
    pub fh: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    /// The file size at close, when it was measured.
    pub size: Option<u64>,
    /// The content hash, when `hash_status` is `ok`.
    pub blake3: Option<Hash>,
    pub hash_status: HashStatus,
    /// The `seq` of the record that opened this handle, when known.
    pub open_seq: Option<u64>,
    pub attrib: Attrib,
    /// Host `CLOCK_REALTIME`, nanoseconds since the epoch, when the guest
    /// released the handle: the producer's time, before the hash that
    /// completes the record, which can come a while later. 0 in logs
    /// written before it existed.
    #[serde(default)]
    pub ts_release_ns: u64,
}

/// `fs.read` and `fs.write`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsIo {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub fh: u64,
    pub offset: u64,
    pub len: u32,
    pub result: OpResult,
    /// Whose identity the record's `subject` is: the caller's, or the
    /// handle opener's when the request had no usable caller (pid 0, or a
    /// write-back from the page cache).
    pub attrib: Attrib,
}

/// `fs.unlink`, `fs.rmdir`, and `fs.readdir`: an operation on one path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsPathOp {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub result: OpResult,
}

/// `fs.mkdir`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsMkdir {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub mode: u32,
    pub result: OpResult,
}

/// `fs.mknod`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsMknod {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub mode: u32,
    pub rdev: u32,
    pub result: OpResult,
}

/// `fs.symlink`: `path` is the new link and `target` what it points to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsSymlink {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub target: String,
    pub result: OpResult,
}

/// `fs.link`: `path` is the new name and `target_path` the file it links to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsLink {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub target_path: String,
    pub result: OpResult,
}

/// `fs.rename`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsRename {
    pub mount: String,
    pub from: String,
    pub to: String,
    /// The `renameat2(2)` flags.
    pub flags: u32,
    pub result: OpResult,
}

/// The attributes a `setattr` asked to change. Unset fields were not part of
/// the request and are omitted from the JSON.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SetAttr {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atime: Option<i64>,
    /// Seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
}

/// `fs.setattr`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsSetattr {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub set: SetAttr,
    pub result: OpResult,
}

/// `fs.fallocate`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsFallocate {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub offset: u64,
    pub len: u64,
    pub mode: u32,
    pub result: OpResult,
}

/// `fs.xattr`: an extended attribute was set or removed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsXattr {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    pub name: String,
    /// `set` or `remove`.
    pub op: String,
    pub result: OpResult,
}

/// `fs.denied`: an operation was refused for lack of permission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsDenied {
    pub mount: String,
    pub path: String,
    /// `path` as base64 of its raw bytes, set when the name was not valid
    /// UTF-8 (`path` then holds the lossy form, `U+FFFD` for each bad
    /// byte); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    /// The refused operation: `lookup`, `access`, `open`, and so on.
    pub op: String,
    pub errno: i32,
}

/// `checkpoint`: a summary the log writer chains in periodically, so a reader
/// can check a stretch of the log against one hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Checkpoint {
    /// Records written since the previous checkpoint.
    pub records_since: u64,
    /// Droppable events that were dropped because the audit channel was full.
    pub dropped: u64,
    /// blake3 over the raw hashes of the records since the previous
    /// checkpoint.
    pub root_hash: Hash,
}

/// Whether something was let through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
}

/// `control.connect`: a process connected to the control socket. It is
/// served (`allow`) only when its uid is the VMM's; otherwise the
/// connection is closed before the hello (`deny`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ControlConnect {
    /// The peer's process id and user id, from `SO_PEERCRED`.
    pub pid: u32,
    pub uid: u32,
    pub verdict: Verdict,
}

/// `control.stop`: a control client asked the VM to stop.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ControlStop {
    /// The client's process id.
    pub by_pid: u32,
    pub mode: StopMode,
}

/// `policy.changed`: a control client replaced the session's policy (the
/// control socket's `policy.update`): the network rules, the vsock
/// allowlist, or both. The new policy decides every later query,
/// connection and datagram, and what was open and it denies is closed
/// (`net.close{reason:"policy"}`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PolicyChanged {
    /// The client's process id.
    pub by_pid: u32,
    /// The policy's version from now on: 1 is the policy the VM started
    /// with, and each update adds one. `policy.get` reports it.
    pub version: u64,
}

/// `net.dhcp`: the network stack answered a guest DHCP message with the
/// session's static lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetDhcp {
    /// `offer`, the answer to a DISCOVER, or `ack`, the answer to a REQUEST.
    pub op: String,
    /// The address the reply leases to the guest.
    pub yiaddr: Ipv4Addr,
}

/// `net.dns`: a guest DNS query, the policy's verdict on its name, and the
/// answer the guest got.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetDns {
    /// The transaction id the guest gave the query.
    pub txid: u16,
    /// The name asked for.
    pub qname: String,
    /// The query type, by its DNS number: 1 is A, 28 is AAAA.
    pub qtype: u16,
    /// The response code the guest got, by its DNS number: 0 is NOERROR,
    /// 2 SERVFAIL, 3 NXDOMAIN.
    pub rcode: u16,
    /// The addresses the answer gave, as text.
    pub answers: Vec<String>,
    pub verdict: Verdict,
    /// The policy rule that decided, as written; `null` when the policy's
    /// default did.
    pub rule: Option<String>,
}

/// `net.connect`: a guest connection attempt and the policy's verdict on it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetConnect {
    /// The flow's id, unique within the session. The flow's `net.tls` and
    /// `net.close` carry it too.
    pub flow: u64,
    /// The transport, such as `tcp`.
    pub proto: String,
    /// The guest's address and source port.
    pub src: SocketAddrV4,
    /// The address and port the guest asked for.
    pub dst: SocketAddrV4,
    /// The names the guest's DNS answers gave `dst`'s address, newest first.
    pub names: Vec<String>,
    pub verdict: Verdict,
    /// The policy rule that decided, as written; `null` when the policy's
    /// default did.
    pub rule: Option<String>,
}

/// `net.tls`: the gate's reading of a flow's first bytes, the name they
/// asked for, and whether the flow was let through on it. The gate reads
/// the flows a domain rule allowed: a TLS ClientHello's server name, or a
/// plain HTTP request's `Host`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetTls {
    /// The `flow` of the flow's `net.connect`.
    pub flow: u64,
    /// What the first bytes were read as: `tls` (a ClientHello, bytes that
    /// began like one, or none at all) or `http` (anything else, read as a
    /// plain HTTP request).
    pub kind: String,
    /// The name asked for: for `tls`, the server name the ClientHello named;
    /// for `http`, the request's `Host` (lowercase, without its port).
    /// `null` when there was none to read.
    pub sni: Option<String>,
    /// The ALPN protocols the ClientHello offered, in its order; empty for
    /// `http`.
    pub alpn: Vec<String>,
    pub verdict: Verdict,
}

/// `net.close`: a flow ended.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetClose {
    /// The `flow` of the flow's `net.connect` or `net.udp`.
    pub flow: u64,
    /// Payload bytes the guest sent.
    pub tx: u64,
    /// Payload bytes the guest received.
    pub rx: u64,
    /// How long the flow lasted, in milliseconds.
    pub dur_ms: u64,
    /// Why it ended, such as `fin`, `rst`, `timeout`, `evicted` or `idle`.
    pub reason: String,
}

/// `net.drop`: the network stack dropped guest frames. Made at most once a
/// second for each reason, counting every drop since the last.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetDrop {
    /// Why, such as `ipv6` or `icmp`.
    pub reason: String,
    /// Frames dropped for this reason since the last `net.drop` for it.
    pub count: u64,
}

/// `net.udp`: the first datagram of a guest UDP flow, and the policy's
/// verdict on it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NetUdp {
    /// The flow's id, unique within the session (TCP and UDP flows share
    /// one count); its `net.close` carries it.
    pub flow: u64,
    /// The guest's address and source port.
    pub src: SocketAddrV4,
    /// The address and port the guest sent to.
    pub dst: SocketAddrV4,
    /// The names the guest's DNS answers gave `dst`'s address, newest first.
    pub names: Vec<String>,
    pub verdict: Verdict,
    /// The policy rule that decided, as written; `null` when the policy's
    /// default did.
    pub rule: Option<String>,
}

/// `vsock.connect`: a vsock connection between the guest and the host, and
/// whether it was let through.
///
/// A guest connection to an internal port (1024, 1025, 1026) is served by
/// the VMM only from a guest source port below 1024, and only the first
/// such connection to each port; a guest connection to any other port
/// reaches the host socket `<uds>_<port>` only when the port is
/// allowlisted. A host connection, through the vsock socket, is recorded
/// once the guest accepts it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VsockConnect {
    /// The port connected to: the host port for a guest connection, the
    /// guest port for a host one.
    pub port: u32,
    /// Who connected: `guest` or `host`.
    pub dir: String,
    /// The other end: for a guest connection, `internal` (a VMM service)
    /// or `uds` (the host socket `<uds>_<port>`); for a host connection,
    /// `guest`.
    pub peer: String,
    /// The connecting side's port: the guest's source port, or the port the
    /// VMM gave a host connection.
    pub src_port: u32,
    pub verdict: Verdict,
    /// Why a connection was refused: `unprivileged` (an internal port from
    /// a guest source port of 1024 or more), `duplicate` (an internal port
    /// that was already connected), `no_service` (an internal port nothing
    /// serves), `port` (a port that is not allowlisted), or the reason the
    /// service at an internal port gave, such as `reactivated` (the guest
    /// control channel takes one connection in the VMM's life, and this is
    /// a later one, after the guest re-activated its vsock driver). `null`
    /// when it was let through.
    pub reason: Option<String>,
}

/// `vsock.close`: a vsock connection that a `vsock.connect` let through
/// ended.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VsockClose {
    /// The `port` of the connection's `vsock.connect`.
    pub port: u32,
    /// The `dir` of the connection's `vsock.connect`.
    pub dir: String,
    /// Payload bytes the guest sent.
    pub tx: u64,
    /// Payload bytes the guest received.
    pub rx: u64,
}

/// `session.start`: the guest's init started the session the VMM's config
/// asked for. Reported by init (ring 1); the record's subject is the
/// session's process.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionStart {
    /// The command, as the config gave it.
    pub argv: Vec<String>,
    /// Where it started.
    pub cwd: String,
    /// Who it runs as.
    pub uid: u32,
    pub gid: u32,
    /// Its process id in the guest.
    pub pid: u32,
}

/// `session.exit`: the session's process ended, as init reported it: its
/// exit code, or the signal that killed it. Both are `null` only when init
/// could not tell.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

/// `sync`: a pairing of the guest's clock with the host's. The VMM pings
/// init over the control channel and times the pong: the guest's
/// `CLOCK_MONOTONIC` when it answered, against the host's at the round
/// trip's midpoint. `ts_host_ns` stays the one timestamp that joins events
/// across rings; this says how far the guest's clock stands from the host's,
/// and how surely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ClockSync {
    /// How the pair was taken: `vsock_rtt`.
    pub method: String,
    /// The guest's `CLOCK_MONOTONIC` when it answered, in nanoseconds.
    pub guest_mono_ns: u64,
    /// The host's `CLOCK_MONOTONIC` at the round trip's midpoint.
    pub host_mono_ns: u64,
    /// `host_mono_ns` minus `guest_mono_ns`.
    pub offset_ns: i64,
    /// The round trip, in nanoseconds: the pairing is no surer than this.
    pub rtt_ns: u64,
}

/// `proc.exec`: a process in the session ran a new program, reported by the
/// sensor after a successful `execve`. The `subject` is the thread that
/// called it, which is the process's leader from then on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcExec {
    /// The calling thread's id and its process's.
    pub tid: u32,
    pub tgid: u32,
    /// The parent process's id.
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// The program, as the kernel resolved it.
    pub filename: String,
    /// The arguments, at most 256 and 16 KiB in all.
    pub argv: Vec<String>,
    /// Whether `argv` was cut to fit.
    pub argv_truncated: bool,
    /// The process's start time on the guest's clock: with `tgid`, the
    /// process's identity across pid reuse.
    pub start_ns: u64,
    /// The cgroup the process is in: the session's.
    pub cgroup_id: u64,
}

/// `proc.fork`: a process in the session made a new process, or a new
/// thread (`thread`): the reconciler needs both, since the filesystem
/// records name the thread that acted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcFork {
    pub parent_tid: u32,
    pub parent_tgid: u32,
    /// The new process's id (its leader thread's, the same), or the new
    /// thread's id.
    pub child_pid: u32,
    /// The new task's start time on the guest's clock.
    pub child_start_ns: u64,
    pub uid: u32,
    pub gid: u32,
    /// Whether the new task is a thread of the parent's process rather than
    /// a process of its own.
    #[serde(default)]
    pub thread: bool,
}

/// `proc.exit`: a thread in the session ended. `group_dead` when it was the
/// last of its process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcExit {
    pub tid: u32,
    pub tgid: u32,
    /// The kernel's exit code word: the status `wait` reports, signal
    /// included.
    pub exit_code: i32,
    pub group_dead: bool,
    /// The process's start time, as `proc.exec` and `proc.fork` gave it.
    pub start_ns: u64,
}

/// `proc.connect_attempt`: a process asked to connect a socket (the LSM's
/// `socket_connect`), with the destination as it asked for it. `dst` and
/// `dst_port` are set for IPv4 and IPv6; another family carries only its
/// number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcConnectAttempt {
    pub tid: u32,
    pub tgid: u32,
    /// The address family, as `AF_INET` is 2 and `AF_INET6` 10.
    pub family: u16,
    /// The socket's transport, such as `tcp` or `udp`.
    pub proto: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
}

/// `proc.tcp_connect`: the kernel sent a connection's first segment: the
/// full 4-tuple once the source port was chosen, which is what joins the
/// flow ring 0 relays (`net.connect`) to the process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcTcpConnect {
    pub tid: u32,
    pub tgid: u32,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
}

/// `proc.memfd`: a process made an anonymous memory file (`memfd_create`):
/// a place to hold or run bytes the audited filesystem never sees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcMemfd {
    pub tid: u32,
    pub tgid: u32,
    /// The name given, at most 256 bytes.
    pub name: String,
    pub flags: u32,
}

/// `proc.file_open`: one open in `sample`, with the path the kernel
/// resolved. The only sampled record of ring 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcFileOpen {
    pub tid: u32,
    pub tgid: u32,
    pub path: String,
    /// The open's `f_flags`.
    pub flags: u32,
    /// The sampling: this record stands for `sample` opens.
    pub sample: u32,
}

/// `proc.lsm_deny`: the sensor's self-protection refused something. `hook`
/// is `bpf` (a `bpf()` call by a process other than the sensor, `detail`
/// its command number) or `task_kill` (a signal to the sensor, `detail` the
/// signal number).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcLsmDeny {
    pub tid: u32,
    pub tgid: u32,
    pub hook: String,
    pub detail: i64,
}

/// `proc.heartbeat`: the sensor is alive, once a second. The counters are
/// since it started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcHeartbeat {
    /// Since the sensor started, on the guest's clock.
    pub uptime_ns: u64,
    /// Events the sensor took from the kernel's ring buffer.
    pub events_emitted: u64,
    /// Events the kernel could not place in the ring buffer: lost.
    pub ringbuf_drops: u64,
    /// Frames written to the stream, heartbeats included.
    pub frames_sent: u64,
}

/// `proc.sensor_status`: what the sensor could attach, sent once it has
/// tried, and again if that changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcSensorStatus {
    pub phase: SensorPhase,
    /// Every program the sensor carries, attached or not.
    pub programs: Vec<ProgramStatus>,
    /// The guest kernel's release string.
    pub kernel_release: String,
    /// Whether the kernel offers its BTF (`/sys/kernel/btf/vmlinux`).
    pub btf_ok: bool,
    /// The session cgroup the sensor filters on.
    pub session_cgroup_id: u64,
    /// The sensor's own process id in the guest, which the guards protect.
    #[serde(default)]
    pub pid: u32,
    /// Why the sensor is degraded, when a single reason covers it (such as
    /// `no_programs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// How much of the sensor runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SensorPhase {
    /// Every program is attached.
    Attached,
    /// Some program is not; `programs` says which, and the reconciler
    /// skips the rules that need it.
    Degraded,
}

/// One of the sensor's programs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProgramStatus {
    pub name: String,
    pub attached: bool,
    /// Why it is not attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `finding`: the reconciler's conclusion from records of both rings, with
/// the records it read as evidence. Never sampled; a score of 70 or more
/// is written through to disk at once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Finding {
    pub category: FindingCategory,
    /// 0 to 100: how strongly the evidence says the agent hid something.
    pub score: u8,
    /// The rule that fired, by name (see docs/reconciler.md).
    pub rule: String,
    /// What was seen, in words; at most 512 bytes.
    pub summary: String,
    /// The records the rule read, newest last.
    pub evidence: Vec<Evidence>,
    /// The span the finding belongs to (M4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Whether a join or clock the rule relied on was weak: the score was
    /// lowered for it.
    pub low_confidence: bool,
}

/// The kinds of finding; see the design's section 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    UnattributedEffect,
    SensorSilence,
    IntentEffectMismatch,
    IndicatorRemoval,
    OffBookChannel,
    OrphanedWork,
    NetworkAnomaly,
    PrivilegeProbe,
    PolicyDenial,
}

/// A record a finding rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Evidence {
    pub seq: u64,
    pub ring: Ring,
}
