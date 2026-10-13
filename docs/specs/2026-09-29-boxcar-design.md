# boxcar design

Status: accepted 2026-09-29; amended 2026-10-06 (section 14: the model gateway
became the model traffic gate). This is the design the implementation plans
argue from. Where a plan and this document disagree, this document wins until
it is amended here.

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
or tamper with monitoring. It may obtain root inside the guest. The host and the
runtime process are trusted. The model provider is trusted for transport but
its output is data.

Consequences: ring 0 must never depend on guest cooperation; ring 1 is
corroboration, not the record; boxcar never holds the agent's credential (the
agent's own login stays in the guest, and the record of what it asked the
model is taken on the host, where the guest cannot alter it); the guest cannot
reach host services except the ones the runtime deliberately exposes.

## 4. Architecture

One host process per isolate, the VMM, plus two small guest binaries.

| Component | Where | Role |
|---|---|---|
| VMM core | host | KVM VM, guest memory, one thread per vCPU, Firecracker-style x86 boot (MPTable, virtio-mmio devices on the kernel command line, no ACPI, no PCI) |
| Filesystem device | host | virtio-fs served in-process by fuse-backend-rs. `AuditFs` wraps the passthrough filesystem and records every operation with the guest pid, uid, and gid the FUSE header carries |
| Network device | host | virtio-net whose backend is a user-mode TCP/IP stack on smoltcp. Guest TCP and UDP terminate in the VMM and are relayed to host sockets. DNS, DHCP, and ICMP-to-gateway are answered by the VMM |
| vsock device | host | virtio-vsock with a Unix-socket muxer (Firecracker's hybrid protocol). Carries the guest control channel, the agent's PTY, and the sensor stream on privileged ports |
| Model traffic gate | host | Part of the network stack. For a destination the policy marks `inspect`, the stack ends the guest's TLS itself with a certificate from a per-session CA the guest trusts, opens its own verified TLS connection to the real host, relays the plaintext byte for byte both ways, and observes it: HTTP/1.1 and HTTP/2 requests and responses become `http.*` records, and the model APIs it knows (Anthropic Messages, OpenAI chat and responses, the latter also over WebSocket) become `llm.*` and `tool.*` records whose tool_use and tool_result blocks define spans. Authentication headers are removed structurally before anything records or stores a byte. The agent keeps its own credential; boxcar never sees it as data and never injects one |
| Guest kernel | guest | Linux 6.18 LTS built from Firecracker's microvm config plus a fragment: virtio-fs, vsock, BPF LSM, BTF, lockdown integrity, no modules, no io_uring |
| Guest init | guest | Static Rust PID 1 in the initramfs. Mounts the rootfs, installs the session CA in the guest's trust store, starts the sensor, drops privileges, execs the agent under a PTY forwarded over vsock |
| Guest sensor | guest | Aya eBPF programs on exec, fork, exit, connect, plus self-protection, and, where the agent's runtime exports OpenSSL's read and write functions, the size and time of each TLS write and read. Streams events over vsock with a heartbeat |
| Audit log | host | Single writer per session. Append-only JSON lines, blake3 hash-chained, checkpointed, verifiable |
| Reconciler | host | Joins the intent, process, and effect streams and emits findings |
| Policy | host | TOML per session, enforced in the network stack, the filesystem decorator, and the sensor's LSM hooks |
| Control protocol | host | Unix socket, JSON lines, versioned. Status, stop, PTY attach and resize, audit subscribe, policy update |

## 5. The two rings

**Ring 0 (host, tamper-proof).** Everything that leaves the guest passes
through a virtio queue the VMM services. The filesystem, network, vsock, PTY,
and gate events are observed by host code the guest cannot modify. The
rootfs being served over virtio-fs rather than a block device is what makes
this semantic: the VMM sees `open("/etc/passwd", O_RDWR)` by pid 142, not a
sector write. The same holds for the network because the VMM terminates the
guest's TCP itself, and for model traffic because the TLS session the agent
opens to an inspected host ends in the VMM, which holds the only key that
signed the certificate the agent accepted.

**Ring 1 (guest, best effort).** A small eBPF sensor started by init before
privileges drop reports process lineage: exec with argv, fork, exit, connect
with the full 4-tuple, and, for runtimes that export OpenSSL's functions, the
size and time of each TLS write and read. It lives in the initramfs, not on the audited
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
`policy.*`, `proc.*` (ring 1), `http.*`, `llm.*` and `tool.*` (gate),
`finding` and `span.*` (reconciler), `checkpoint`, `sync`. New types are
additive; consumers ignore unknown types.

Limits: paths 4096 bytes, argv 256 elements and 16 KiB, summaries 512 bytes.
Bodies over 8 KiB are hashed, never inlined. Environment values are never
logged. The gate strips authentication headers structurally before the
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

1. The model's reply passes through the gate with a tool_use block. A span
   opens.
2. The agent execs curl. The sensor reports pid, parent, and argv, attached
   to the span by ancestry and time.
3. curl resolves a name and connects. The network stack logs the DNS query
   and the TCP connect with the TLS server name. The sensor's connect event
   supplies the pid for the flow.
4. curl writes a file. The filesystem decorator logs create, write, and close
   with the same pid and hashes the content.
5. The agent sends the tool_result back through the gate. The span
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
| Model traffic | A TLS-terminating gate in the network stack with a per-session CA, not an HTTP proxy the agent is pointed at | Agents run on account logins as often as on API keys, so boxcar holds no credential; the gate sees every provider and every runtime the same way and keeps the record in ring 0 (section 14) |
| Model APIs | Anthropic Messages plus OpenAI chat and responses from the start | Claude Code first, Codex and most others second |
| In-guest TLS capture | Corroboration only, where the runtime exports OpenSSL's functions | The native Claude Code build (Bun, BoringSSL compiled in, no symbols) and Codex (rustls) give a probe nothing to attach to (section 14) |
| Guest kernel | 6.18 LTS built in a Docker container | The dev host's toolchain is too old for BTF |
| Sensor | Aya on a pinned nightly, bindings generated from our kernel's BTF | No CO-RE from Rust yet; we control the kernel so drift is a build check |
| Log | Hash-chained from milestone 1 | Cheap, and the writer is the single serialization point anyway |

## 12. Milestones

1. Shell on the serial console with an audited virtio-fs rootfs.
2. User-mode networking, vsock, the agent PTY, control protocol v1.
3. Guest sensor and reconciler.
4. Model traffic gate, spans, Claude Code and Codex running inside.
5. OCI images, policy files, exporters, hardening, docs.

Conductor integration is a separate plan in the conductor repository after
milestone 2.

## 13. Open questions

- Ownership fidelity inside the guest without a privileged host process.
- Whether the overlay filesystem's whiteout handling needs CAP_MKNOD.
- ptp_kvm availability on nested-virtualization hosts for clock pairing.
- Which agents' harnesses expose a stable tool-executor process shape for
  span ancestry.
- Content encodings beyond gzip, deflate and brotli in model responses
  (zstd), and an agent that pins its provider's certificate: both fail
  closed and visibly, neither is observed.

## 14. Amendments

### 2026-10-06: the model traffic gate replaces the model gateway

The design had an HTTP proxy on the host (`10.0.2.2:8080`) that the agent
was pointed at, which held the real API key and injected it. That shape
assumes an API key. Claude Code and Codex are as often run on account
logins (OAuth tokens the agent refreshes itself), where there is no key to
hold and the agent's own session is what authenticates it; a proxy that
rewrote credentials would have to hold the user's login, and an agent whose
base URL is overridden may not accept its account login at all.

In-guest capture of the plaintext, groundcover's approach, was considered
as the replacement: uprobes on the TLS library's read and write functions.
groundcover's documentation supports it for OpenSSL, Go's `crypto/tls`,
Node.js and Java (through their agent) and says it is "unsupported for
binaries which have been compiled without debug symbols". The native Claude
Code build is a Bun executable with BoringSSL compiled in and no symbols
for it; Codex's binary uses rustls, whose plaintext boundary is generic,
inlined Rust with no stable symbol. Neither gives a probe an address. The
approach therefore cannot be the record; it is kept as corroboration for
runtimes that do export the functions, Node among them.

What changes:

- The network stack gains a gate for destinations the policy marks
  `inspect`. It ends the guest's TLS with a leaf certificate signed by a CA
  made for the session (the key never leaves the VMM), connects to the real
  host with its own verified TLS, and relays the plaintext unchanged in
  both directions. Init installs the CA in the guest's trust store and the
  runtime variables that name it. An agent that pins its certificate fails
  closed and visibly.
- The gate observes HTTP/1.1 and HTTP/2 (HPACK decoded passively, content
  decoded for gzip, deflate and brotli, SSE split into events, WebSocket
  frames read) and records `http.*` for every inspected exchange, and
  `llm.*` and `tool.*` for the model APIs it knows. It never modifies a
  byte of the stream and never injects a credential. Authentication headers
  are removed structurally before any record or dump is made.
- The sensor adds TLS write and read events (`proc.tls_io`) for a process
  whose executable or loaded library exports OpenSSL's functions, so that
  the reconciler can name the process behind a model request. It is
  corroboration, like the rest of ring 1.
- A dump mode (`boxcar run --dump DIR`), after bitvessel's `DebugNet`,
  writes the guest's frames as a pcap, the decrypted streams of inspected
  flows, and each decoded HTTP exchange, for inspection by hand.
- The `gateway` source becomes `gate`. Milestone 4 is "model traffic gate,
  spans, Claude Code and Codex running inside".

What does not change: the two rings and what each may be trusted for, the
event envelope, the span model and the finding categories, the policy's
place in the data path, and that the agent runs inside.
