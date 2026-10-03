# boxcar design

Status: accepted 2026-09-29. This is the design the implementation plans argue
from. Where a plan and this document disagree, this document wins until it is
amended here.

## 1. Purpose

boxcar runs AI coding agents (Claude Code, Codex, and similar) inside KVM
microVMs and produces a complete, trustworthy record of what each agent did:
every file operation, every network connection and DNS query, every process,
and every model tool call, joined into one timeline. The record must hold up
even if the agent gains root inside the guest.

It succeeds bitvessel, a 2017 Go fork of Google's novm whose founding idea was
serving a VM's root filesystem from the host instead of a disk image. That idea
is kept. The rest is rebuilt in Rust on rust-vmm crates.

Conductor (github.com/phenixrizen/conductor) will drive boxcar as a child
process to run agent sessions in isolates. boxcar is designed so conductor is
just a client of its control protocol; nothing in boxcar depends on conductor.

## 2. Goals and non-goals

Goals:

- Boot a guest from a directory (later an OCI image) with no disk images.
- Record every externally visible effect of the guest at the host boundary,
  where the guest cannot alter the record.
- Attribute effects to guest processes and to the model's stated intent.
- Detect when the guest's own reporting, or the model's stated intent, diverges
  from what the host observed.
- Enforce policy (egress allowlist, writable paths, exec deny list) from the
  same hooks that record.
- Keep the whole runtime in one process with one trust boundary, runnable
  unprivileged apart from access to `/dev/kvm`.
- Expose a small, versioned, language-neutral control protocol.

Non-goals:

- General-purpose virtualization. Only Linux guests we build, only x86_64,
  only KVM, no legacy devices, no PCI at first, no GPU.
- Perfect visibility inside the guest. Ring 1 is best effort by design.
- Running the agent loop outside the guest. The agent runs inside.

## 3. Threat model

The agent is semi-adversarial: it may try to hide its actions, exfiltrate data,
or tamper with monitoring. It may obtain root inside the guest. The host, the
runtime process, and the model gateway are trusted. The model provider is
trusted for transport but its output is data.

Consequences: ring 0 must never depend on guest cooperation; ring 1 is
corroboration, not the record; the API key never enters the guest; the guest
cannot reach host services except the ones the runtime deliberately exposes.

## 4. Architecture

One host process per isolate, the VMM, plus two small guest binaries.

| Component | Where | Role |
|---|---|---|
| VMM core | host | KVM VM, guest memory, one thread per vCPU, Firecracker-style x86 boot (MPTable, virtio-mmio devices on the kernel command line, no ACPI, no PCI) |
| Filesystem device | host | virtio-fs served in-process by fuse-backend-rs. `AuditFs` wraps the passthrough filesystem and records every operation with the guest pid, uid, and gid the FUSE header carries |
| Network device | host | virtio-net whose backend is a user-mode TCP/IP stack on smoltcp. Guest TCP and UDP terminate in the VMM and are relayed to host sockets. DNS, DHCP, and ICMP-to-gateway are answered by the VMM |
| vsock device | host | virtio-vsock with a Unix-socket muxer (Firecracker's hybrid protocol). Carries the guest control channel, the agent's PTY, and the sensor stream on privileged ports |
| Model gateway | host | HTTP proxy the agent is pointed at. Holds the real API key, strips any key the agent sends, records every request and response, and extracts tool_use and tool_result blocks into spans. Speaks the Anthropic Messages API and OpenAI-compatible chat and responses APIs |
| Guest kernel | guest | Linux 6.18 LTS built from Firecracker's microvm config plus a fragment: virtio-fs, vsock, BPF LSM, BTF, lockdown integrity, no modules, no io_uring |
| Guest init | guest | Static Rust PID 1 in the initramfs. Mounts the rootfs, starts the sensor, drops privileges, execs the agent under a PTY forwarded over vsock |
| Guest sensor | guest | Aya eBPF programs on exec, fork, exit, connect, plus self-protection. Streams events over vsock with a heartbeat |
| Audit log | host | Single writer per session. Append-only JSON lines, blake3 hash-chained, checkpointed, verifiable |
| Reconciler | host | Joins the intent, process, and effect streams and emits findings |
| Policy | host | TOML per session, enforced in the network stack, the filesystem decorator, and the sensor's LSM hooks |
| Control protocol | host | Unix socket, JSON lines, versioned. Status, stop, PTY attach and resize, audit subscribe, policy update |

## 5. The two rings

**Ring 0 (host, tamper-proof).** Everything that leaves the guest passes
through a virtio queue the VMM services. The filesystem, network, vsock, PTY,
and gateway events are observed by host code the guest cannot modify. The
rootfs being served over virtio-fs rather than a block device is what makes
this semantic: the VMM sees `open("/etc/passwd", O_RDWR)` by pid 142, not a
sector write. The same holds for the network because the VMM terminates the
guest's TCP itself.

**Ring 1 (guest, best effort).** A small eBPF sensor started by init before
privileges drop reports process lineage: exec with argv, fork, exit, connect
with the full 4-tuple. It lives in the initramfs, not on the audited
filesystem. The agent runs without CAP_BPF, CAP_PERFMON, or CAP_SYS_ADMIN, the
kernel is locked down, and an LSM program denies `bpf()` to everyone but the
sensor. Ring 1 can still be silenced by a guest kernel compromise. That
silence is itself detectable.

**Why both.** Ring 0 alone answers "what happened" but not "which command did
it". Ring 1 alone cannot be trusted. Together, disagreement between them, or
between either and the model's stated intent, is the signal that the agent is
hiding its trail.

## 6. Event model

Every record shares an envelope: schema version, session id, gap-free
sequence number assigned by the single writer, ring, source, dotted type,
host realtime and monotonic timestamps, optional guest timestamp, optional
subject (guest pid, uid, gid), the payload, an optional span reference, and
the hash chain fields. The host receive time is the only cross-ring join
key; guest timestamps order ring 1 internally.

The FUSE header's pid is the guest thread id in the guest's pid namespace,
not the thread group id. The reconciler maps thread ids to processes using
ring 1 fork and exec events.

Type families: `vmm.*`, `fs.*`, `net.*`, `vsock.*`, `session.*`, `control.*`,
`policy.*`, `proc.*` (ring 1), `llm.*` and `tool.*` (gateway), `finding`,
`checkpoint`, `sync`. New types are additive; consumers ignore unknown types.

Limits: paths 4096 bytes, argv 256 elements and 16 KiB, summaries 512 bytes.
Bodies over 8 KiB are hashed, never inlined. Environment values are never
logged. The gateway strips authentication headers structurally before the
recorder sees bytes. Writes, creates, unlinks, renames, setattr, verdicts,
spans, and findings are never sampled. Reads may be sampled and drops are
counted in checkpoints.

## 7. Joins and findings

Joins: a file or network effect joins a process by guest pid within the
process's exec-to-exit interval, keyed by pid plus start time so pid reuse is
safe. A network flow joins a process by 4-tuple within a short window using
the sensor's connect event. A process joins a span by time containment plus
ancestry from the agent harness's tool executor pid. A span inherits the
worst finding score beneath it.

Finding categories, rules-based and explainable, each carrying evidence
references back into the same log:

| Category | Trigger |
|---|---|
| unattributed_effect | effect from a pid with no live process record |
| sensor_silence | no heartbeat while ring 0 is active |
| intent_effect_mismatch | declared tool arguments differ from observed argv; a tool result claims a write ring 0 never saw; a tool result omits a connection ring 0 saw |
| indicator_removal | unlink or truncate of shell history, logs, or the sensor and init paths |
| off_book_channel | memfd_create, unlinked-open files, tmpfs writes |
| orphaned_work | a process outlives its span |
| network_anomaly | connect with no prior DNS, DNS volume or entropy spike, server name resolving elsewhere than the destination, policy denials |
| privilege_probe | LSM denials for bpf, module load, ptrace, mount |

## 8. One agent action, end to end

1. The model's reply passes through the gateway with a tool_use block. A span
   opens.
2. The agent execs curl. The sensor reports pid, parent, and argv, attached
   to the span by ancestry and time.
3. curl resolves a name and connects. The network stack logs the DNS query
   and the TCP connect with the TLS server name. The sensor's connect event
   supplies the pid for the flow.
4. curl writes a file. The filesystem decorator logs create, write, and close
   with the same pid and hashes the content.
5. The agent sends the tool_result back through the gateway. The span
   closes with every effect nested under it.

If the sensor was silenced, steps 3 and 4 still appear with pids but without
argv, and the heartbeat gap is a finding.

## 9. Guest identity

The host process is unprivileged, so the passthrough filesystem cannot switch
uid per request. The decorator passes uid 0 to the inner filesystem and
records the real guest identity in the audit record. The guest agent therefore
runs as the host user's uid and gid and owns what it creates. chown, device
nodes, and security xattrs return EPERM inside the guest until an ownership
override xattr lands.

## 10. Control protocol and the conductor seam

A Unix socket in the session's state directory, peer-credential checked, JSON
lines with a `v` field and per-message size limits. The server sends a hello
naming its protocol versions and capabilities. Conductor launches boxcar with
`--ready-fd` and reads the socket path from it, forwards the agent PTY through
`pty.attach` and `pty.resize`, subscribes to audit events with prefix filters,
and receives findings as pushed events. The full log stays on disk in the
session directory for conductor's audit route to page through.

## 11. Decisions

| Decision | Choice | Why |
|---|---|---|
| License | Apache-2.0 with a CLA and DCO sign-off | Matches rust-vmm and Firecracker, carries a patent grant, keeps relicensing possible. Monetize the hosted product and conductor, not the runtime |
| Language and base | Rust on rust-vmm crates | The pieces a port of bitvessel would translate are exactly what rust-vmm provides |
| Boot | Firecracker legacy path, virtio-mmio, no PCI, no ACPI | Simplest boot we fully control. ACPI via the acpi_tables crate is plan B |
| Virtio device layer | Owned in-tree, seeded from rust-vmm virtio-device and Firecracker with attribution | The upstream crate is unpublished and its repo archived. Production VMMs own this layer too |
| Version pins | vm-memory 0.17.1 and matching crates | Forced by fuse-backend-rs 0.14. Kata pins the same way. Exit when fuse-backend-rs publishes on 0.18 or by forking it |
| Filesystem | virtio-fs in-process, no DAX | DAX would bypass the audit surface |
| Network | user-mode stack in the VMM, no TAP | Events with semantics, policy in the data path, no root |
| Console | 16550 serial for the kernel log; agent PTY over vsock | Avoids writing a virtio-console device |
| Gateway | Anthropic Messages plus OpenAI chat and responses from the start | Claude Code first, Codex and most others second |
| Guest kernel | 6.18 LTS built in a Docker container | The dev host's toolchain is too old for BTF |
| Sensor | Aya on a pinned nightly, bindings generated from our kernel's BTF | No CO-RE from Rust yet; we control the kernel so drift is a build check |
| Log | Hash-chained from milestone 1 | Cheap, and the writer is the single serialization point anyway |

## 12. Milestones

1. Shell on the serial console with an audited virtio-fs rootfs.
2. User-mode networking, vsock, the agent PTY, control protocol v1.
3. Guest sensor and reconciler.
4. Gateway, spans, Claude Code running inside.
5. OCI images, policy files, exporters, hardening, docs.

Conductor integration is a separate plan in the conductor repository after
milestone 2.

## 13. Open questions

- Ownership fidelity inside the guest without a privileged host process.
- Whether the overlay filesystem's whiteout handling needs CAP_MKNOD.
- ptp_kvm availability on nested-virtualization hosts for clock pairing.
- Which agents' harnesses expose a stable tool-executor process shape for
  span ancestry.
