// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The typed payloads of [`Payload`](super::Payload): what goes in `data`.
//!
//! Field names are the wire names. `Option` fields that the schema marks
//! skip-if-none are omitted from the JSON when unset; every other `Option` is
//! written as an explicit `null`.

use std::net::{Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

use super::errno::name as errno_name;
use super::Hash;
use crate::control::StopMode;

/// How one operation ended. Present on every filesystem event that performs
/// an operation, so readers can filter failures without knowing the event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub struct ArtifactRef {
    pub path: String,
    pub blake3: Hash,
}

/// A directory the VM was given over virtio-fs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShareRef {
    /// The share's tag, such as `root` or `workspace`.
    pub tag: String,
    /// The host directory it serves.
    pub host_root: String,
}

/// `vmm.start`: the VM was built and is about to run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub struct FsOpen {
    pub mount: String,
    pub path: String,
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
pub struct FsCreate {
    pub mount: String,
    pub path: String,
    pub fh: u64,
    pub mode: u32,
    pub flags: u32,
    pub result: OpResult,
}

/// Whether the content of a closed file was hashed, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct FsClose {
    pub mount: String,
    /// The path at close time.
    pub path: String,
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
}

/// `fs.read` and `fs.write`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsIo {
    pub mount: String,
    pub path: String,
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
pub struct FsPathOp {
    pub mount: String,
    pub path: String,
    pub result: OpResult,
}

/// `fs.mkdir`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsMkdir {
    pub mount: String,
    pub path: String,
    pub mode: u32,
    pub result: OpResult,
}

/// `fs.mknod`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsMknod {
    pub mount: String,
    pub path: String,
    pub mode: u32,
    pub rdev: u32,
    pub result: OpResult,
}

/// `fs.symlink`: `path` is the new link and `target` what it points to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsSymlink {
    pub mount: String,
    pub path: String,
    pub target: String,
    pub result: OpResult,
}

/// `fs.link`: `path` is the new name and `target_path` the file it links to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsLink {
    pub mount: String,
    pub path: String,
    pub target_path: String,
    pub result: OpResult,
}

/// `fs.rename`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub struct FsSetattr {
    pub mount: String,
    pub path: String,
    pub set: SetAttr,
    pub result: OpResult,
}

/// `fs.fallocate`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsFallocate {
    pub mount: String,
    pub path: String,
    pub offset: u64,
    pub len: u64,
    pub mode: u32,
    pub result: OpResult,
}

/// `fs.xattr`: an extended attribute was set or removed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsXattr {
    pub mount: String,
    pub path: String,
    pub name: String,
    /// `set` or `remove`.
    pub op: String,
    pub result: OpResult,
}

/// `fs.denied`: an operation was refused for lack of permission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FsDenied {
    pub mount: String,
    pub path: String,
    /// The refused operation: `lookup`, `access`, `open`, and so on.
    pub op: String,
    pub errno: i32,
}

/// `checkpoint`: a summary the log writer chains in periodically, so a reader
/// can check a stretch of the log against one hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
}

/// `control.connect`: a process connected to the control socket. It is
/// served (`allow`) only when its uid is the VMM's; otherwise the
/// connection is closed before the hello (`deny`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControlConnect {
    /// The peer's process id and user id, from `SO_PEERCRED`.
    pub pid: u32,
    pub uid: u32,
    pub verdict: Verdict,
}

/// `control.stop`: a control client asked the VM to stop.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControlStop {
    /// The client's process id.
    pub by_pid: u32,
    pub mode: StopMode,
}

/// `net.dhcp`: the network stack answered a guest DHCP message with the
/// session's static lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetDhcp {
    /// `offer`, the answer to a DISCOVER, or `ack`, the answer to a REQUEST.
    pub op: String,
    /// The address the reply leases to the guest.
    pub yiaddr: Ipv4Addr,
}

/// `net.dns`: a guest DNS query, the policy's verdict on its name, and the
/// answer the guest got.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub struct NetDrop {
    /// Why, such as `ipv6` or `icmp`.
    pub reason: String,
    /// Frames dropped for this reason since the last `net.drop` for it.
    pub count: u64,
}

/// `net.udp`: the first datagram of a guest UDP flow, and the policy's
/// verdict on it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetUdp {
    /// The flow's id, unique within the session; its `net.close` carries it.
    pub flow: u64,
    /// The guest's address and source port.
    pub src: SocketAddrV4,
    /// The address and port the guest sent to.
    pub dst: SocketAddrV4,
    pub verdict: Verdict,
}
