# M1: Shell on Console with Audited Rootfs — Implementation Plan
**Goal:** `boxcar run` boots our own Linux 6.18 guest on KVM from a rootfs directory served over virtio-fs, drops into an interactive shell on the serial console, and streams every file operation with the guest pid into a hash-chained audit log that `boxcar audit verify` checks.

**Architecture:** A Cargo workspace. `boxcar-proto` holds the audit record schema; `boxcar-audit` is the single-writer chained log; `boxcar-vmm` owns KVM, memory, Firecracker-style x86 boot, vCPU threads, buses, serial, and shutdown; `boxcar-virtio` is our own virtio device trait and virtio-mmio transport; `boxcar-fs` wraps fuse-backend-rs's passthrough filesystem in an `AuditFs` decorator and exposes it as a virtio-fs device; `boxcar-init` is the static guest PID 1; `xtask` builds the guest kernel (in Docker), the initramfs, and the Alpine rootfs.

**Tech Stack:** Rust 1.96 stable, rust-vmm crates pinned to the vm-memory 0.17.1 set, fuse-backend-rs 0.14, blake3, serde, clap. Linux 6.18 guest built in a `debian:trixie` container.

**Spec:** `docs/specs/2026-09-29-boxcar-design.md`. Roadmap for all milestones: `docs/plans/2026-09-30-boxcar-roadmap.md`.

## Global Constraints

- Rust `1.96.0` (rust-toolchain.toml), edition 2021, `rust-version = "1.96"` on every crate. Workspace at the repo root with `resolver = "2"`, members `crates/*` and `xtask`.
- **Pinned versions, exact, in `[workspace.dependencies]`:** `vm-memory = "=0.17.1"` (features `backend-mmap`, `backend-atomic`), `virtio-queue = "=0.17.0"`, `virtio-bindings = "=0.2.7"`, `virtio-vsock = "=0.11.0"`, `fuse-backend-rs = "=0.14.0"` with `default-features = false, features = ["virtiofs"]`, `kvm-ioctls = "=0.25.0"`, `kvm-bindings = "=0.14.1"` (feature `fam-wrappers`), `linux-loader = "=0.13.2"` with `default-features = false, features = ["elf"]`, `vm-superio = "=0.8.2"`, `event-manager = "=0.4.2"`, `vm-allocator = "=0.1.4"`, `vmm-sys-util = "=0.15.0"`, `blake3 = "1.8"`, `serde = "1"` (derive), `serde_json = "1"`, `clap = "4"` (derive), `tracing = "0.1"`, `tracing-subscriber = "0.3"` (env-filter), `crossbeam-channel = "0.5"`, `uuid = "1"` (features `v7`, `serde`), `hex = "0.4"`, `base64 = "0.22"`, `libc = "0.2"`, `thiserror = "2"`, `anyhow = "1"` (binaries and xtask only), `nix = "0.31"` (guest only), `cpio = "0.4"` (xtask only), `tempfile = "3"` (dev).
- **No git dependencies and no `[patch]` sections.** `Cargo.lock` must contain no `git+` source. `cargo tree -d` must show no duplicate rust-vmm crate.
- Every new source file starts with `// SPDX-License-Identifier: Apache-2.0` and `// Copyright 2026 The boxcar Authors`. A file ported from Firecracker, Cloud Hypervisor, or rust-vmm keeps that project's original header above ours, names the source repository, path, and commit in a comment, and gets an entry in `NOTICE`.
- Commands are argv arrays. Never build a shell string from user input.
- Every commit: `git commit -s` (which appends `Signed-off-by` last), subject `area: short summary` (the subjects given in each task are used verbatim), and the body's trailer block contains these two lines exactly:
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01Xm6wxRmFTbEVJQ7zrfbuJX`
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace` (or `cargo test --workspace`), and `cargo deny check` must pass at the end of every task. Test output must be pristine: no warnings.
- Tests that need `/dev/kvm` live behind a `kvm-tests` cargo feature and skip with a printed reason (not fail) when `/dev/kvm` is missing or unreadable, or when `BOXCAR_TEST_KERNEL`, `BOXCAR_TEST_INITRAMFS`, or `BOXCAR_TEST_ROOTFS` (whichever the test needs) is unset.
- Audit record envelope (from the spec, exact field names): `v` (u8, 1), `session_id` (UUIDv7 string), `seq` (u64, gap-free, assigned only by the writer), `ring` (integer 0 or 1), `src` (one of `vmm fs net vsock pty guest sensor reconciler gateway control`), `type` (dotted string), `ts_host_ns` (u64, CLOCK_REALTIME), `ts_mono_ns` (u64, CLOCK_MONOTONIC), optional `ts_guest_ns`, optional `subject` `{pid, uid, gid}`, `data` (object), optional `span` `{trace_id, span_id}`, `prev` and `hash` (strings `b3:` + 64 lowercase hex chars). `hash = blake3(prev_bytes || canonical_json(record_without_hash))` where `prev_bytes` is the 32 raw bytes of `prev` and canonical JSON is serde_json output of a `Value` with all object keys sorted and no whitespace. Genesis `prev = blake3(session_id as UTF-8 bytes)`.
- Guest physical layout (exact): GDT `0x500`, IDT `0x520`, zero page `0x7000`, boot stack pointer `0x8ff0`, PML4 `0x9000`, PDPTE `0xa000`, PDE `0xb000`, kernel cmdline `0x20000` (max 2048 bytes), MPTable `0x9fc00`, kernel load `0x100000`, virtio-mmio slots 4 KiB each from `0xC000_0000` with GSIs `5..=23`, KVM TSS `0xFFFB_D000`, RAM above `0x1_0000_0000` when memory exceeds 3 GiB. E820: `[0, 0x9fc00)` RAM, `[0x9fc00, 0x100000)` RESERVED, `[0x100000, min(mem, 3 GiB))` RAM, `[4 GiB, 4 GiB + (mem − 3 GiB))` RAM if mem > 3 GiB. `E820_RAM = 1`, `E820_RESERVED = 2`.
- Fixed device slot order: slot 0 virtio-fs tag `root` GSI 5, slot 1 virtio-fs tag `workspace` GSI 6 (slots 2 and 3 reserved for net and vsock in M2).
- Guest kernel: Linux 6.18 LTS from Firecracker's `resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config` plus `guest/kernel/boxcar.fragment`; built in a digest-pinned `debian:trixie` container; the build fails if any fragment line is missing from the final `.config`.

## Review Focus

1. **A `FileSystem` method the decorator forgot.** fuse-backend-rs defaults every trait method to ENOSYS, so a missed forward silently breaks an operation. Expected: the `forward!` macro covers every method and the differential test in Task 11 compares the wrapped and unwrapped filesystem method by method.
2. **Credential handling.** The inner passthrough filesystem calls `setresuid` for any non-zero uid and fails in an unprivileged process. Expected: `AuditFs` passes uid 0 and gid 0 inward and records the real guest identity in the audit record only (Task 11).
3. **Lost wakeups on virtio queues.** Expected: `drain_queue` re-enables notifications and re-checks the ring before returning (Task 10); the device worker loops until the queue is empty.
4. **Audit backpressure stalling filesystem operations.** Expected: a bounded channel of 65536 with blocking send only for never-drop events; verbose-only read and write events; the seq gap-free test with concurrent producers (Task 4).
5. **PID 1 panics are kernel panics.** Expected: init is a single-threaded poll loop with no `unwrap` on fallible syscalls, a panic hook that writes to `/dev/kmsg`, and `panic=1` on the kernel command line (Tasks 7 and 13).
6. **Blind boot debugging.** Expected: every boot constant comes from Firecracker's `arch/x86_64` with unit tests ported alongside (Task 8), and `--debug-boot` adds `earlyprintk=serial,ttyS0,115200` (Task 9).

## File Structure

| Path | Responsibility |
|---|---|
| `Cargo.toml`, `deny.toml`, `.cargo/config.toml`, `.github/workflows/ci.yml` | workspace, pins, license policy, CI |
| `crates/boxcar-proto/src/{lib,audit,limits,redact,ids}.rs` | audit record envelope, typed payloads, limits, redaction, session ids |
| `crates/boxcar-audit/src/{lib,sink,writer,chain,segment,checkpoint,reader,verify}.rs` | single-writer chained log, reader, verifier |
| `crates/boxcar-vmm/src/{lib,kvm,memory,cmdline,vcpu,kick,bus,stdin,lifecycle,vmm}.rs`, `src/arch/x86_64/{mod,layout,boot,mptable,mpspec,regs,gdt,msr,cpuid,interrupts}.rs`, `src/devices/{mod,legacy}.rs` | KVM, memory, boot, vCPUs, buses, serial and i8042, run loop, shutdown |
| `crates/boxcar-virtio/src/{lib,device,config,mmio,irq,context,slots,queue,features,testing}.rs` | virtio device trait, virtio-mmio transport, IRQ trigger, slot allocation, queue helpers, mocks |
| `crates/boxcar-fs/src/{lib,audit_fs,forward,path_map,handles,hasher,events,share,device}.rs` | AuditFs decorator and virtio-fs device |
| `crates/boxcar-init/src/{main,cmdline,mounts,sysctl,session,reaper,shutdown}.rs` | guest PID 1 |
| `crates/boxcar/src/{main,cli}.rs`, `src/cmd/{doctor,run,audit}.rs`, `tests/kvm_m1.rs` | CLI and gated end-to-end tests |
| `xtask/src/{main,kernel,initramfs,rootfs,test_kvm}.rs` | guest artifact builders and the gated test runner |
| `guest/kernel/{Dockerfile,build.sh,VERSION,boxcar.fragment,README.md,base/microvm-kernel-ci-x86_64-6.18.config}` | guest kernel build |

---

### Task 1: Workspace bootstrap, pins, license policy, CI

**Files:**
- Create: `Cargo.toml`, `.cargo/config.toml`, `deny.toml`, `.github/workflows/ci.yml`
- Create: `crates/{boxcar,boxcar-proto,boxcar-audit,boxcar-vmm,boxcar-virtio,boxcar-fs,boxcar-init}/Cargo.toml` and a placeholder `src/lib.rs` or `src/main.rs` for each
- Create: `xtask/Cargo.toml`, `xtask/src/main.rs`

**Requirements:**
- Root `Cargo.toml`: `[workspace] resolver = "2"`, `members = ["crates/*", "xtask"]`, `[workspace.package] edition = "2021"`, `license = "Apache-2.0"`, `rust-version = "1.96"`, `repository = "https://github.com/phenixrizen/boxcar"`, and the full `[workspace.dependencies]` pin table from Global Constraints. Add a `[profile.guest]` that inherits `release` with `opt-level = "s"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`.
- Each crate's `Cargo.toml` uses `edition.workspace = true`, `license.workspace = true`, `rust-version.workspace = true`, `repository.workspace = true`, and declares only the dependencies it needs, all via `{ workspace = true }`. Dependencies per crate: `boxcar-proto` → serde, serde_json, uuid, base64, thiserror, plus blake3 as an optional dependency behind a default-on feature (`[features] default = ["hash"]`, `hash = ["dep:blake3"]`) so the crate builds for musl without a C compiler; everything that needs blake3 (`Hash::from_blake3`, `compute_hash`, `genesis_prev`) is gated on `hash`, while the serde types and the `Hash` newtype's hand-rolled hex serialization are not. `boxcar-audit` → boxcar-proto, serde_json, blake3, crossbeam-channel, thiserror, tracing, libc; dev tempfile. `boxcar-virtio` → vm-memory, virtio-queue, virtio-bindings, vmm-sys-util, kvm-ioctls, kvm-bindings, vm-allocator, thiserror, tracing. `boxcar-fs` → boxcar-proto, boxcar-audit, boxcar-virtio, fuse-backend-rs, vm-memory, virtio-queue, virtio-bindings, vmm-sys-util, blake3, libc, thiserror, tracing; dev tempfile, virtio-vsock (pin-set canary for Task 2). `boxcar-vmm` → boxcar-proto, boxcar-audit, boxcar-virtio, boxcar-fs, kvm-ioctls, kvm-bindings, vm-memory, linux-loader, vm-superio, event-manager, vm-allocator, vmm-sys-util, blake3, libc, thiserror, tracing; `[features] kvm-tests = []`. `boxcar` (bin) → clap, anyhow, tracing, tracing-subscriber, serde_json, boxcar-proto, boxcar-audit, boxcar-vmm, boxcar-fs; `[features] kvm-tests = []`. `boxcar-init` (bin) → boxcar-proto with `default-features = false`, nix (features `mount`, `fs`, `process`, `signal`, `term`, `user`, `reboot`, `poll`, `ioctl`), libc. `xtask` (bin) → anyhow, clap, cpio, blake3, hex.
- `boxcar-init` must build for `x86_64-unknown-linux-musl` with only pure-Rust dependencies (no `musl-gcc` needed).
- Placeholder sources: the license header, a one-line crate doc comment, and for binaries a clap `Parser` with `--version` only. `boxcar --version` prints `boxcar 0.1.0`.
- `.cargo/config.toml`: `[alias] xtask = "run -p xtask --"`.
- `deny.toml`: `[licenses] allow = ["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "ISC", "Unicode-3.0", "Unlicense", "CC0-1.0", "Zlib", "MPL-2.0"]` (trim to what resolves; the allowlist is a ceiling, not a target), `[bans] multiple-versions = "deny"` with `skip` entries only where a transitive crate forces a duplicate and a comment explains it, and `deny = [{ name = "aws-lc-sys" }]`; `[sources] unknown-git = "deny"`, `unknown-registry = "deny"`.
- `.github/workflows/ci.yml`: on push and pull_request, `ubuntu-latest`, steps: checkout, `dtolnay/rust-toolchain` reading `rust-toolchain.toml`, cache, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo install cargo-deny --locked` then `cargo deny check`, and `cargo build -p boxcar-init --target x86_64-unknown-linux-musl --profile guest`.

**Steps:**
- [ ] Write the root manifest, the crate manifests, and the placeholder sources.
- [ ] Run `cargo build --workspace` (first build compiles every pinned dependency; several minutes). Fix any resolution error by adjusting features, never by adding a git source.
- [ ] Run `cargo build -p boxcar-init --target x86_64-unknown-linux-musl --profile guest` and confirm `file target/x86_64-unknown-linux-musl/guest/boxcar-init` reports `statically linked`.
- [ ] Run `cargo deny check` and `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`; fix until clean.
- [ ] Confirm `grep -c 'git+' Cargo.lock` prints `0` and `cargo tree -d | grep -E 'vm-memory|virtio-queue|virtio-bindings|kvm-|vmm-sys-util'` prints nothing.
- [ ] Commit: `build: workspace, pinned rust-vmm set, deny policy, CI`.

**Verify:** `cargo build --workspace && cargo deny check && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`; `cargo run -p boxcar -- --version` prints `boxcar 0.1.0`; `Cargo.lock` has no `git+` source.

---

### Task 2: Dependency sanity check (pin-set canary)

**Files:**
- Modify: `crates/boxcar-fs/src/lib.rs` (add a `#[cfg(test)] mod dep_check`)

**Requirements:**
- A unit test proves the crates.io `virtio-queue 0.17.0` descriptor chain type is the one fuse-backend-rs and virtio-vsock consume: build a `vm_memory::GuestMemoryMmap<()>` of 64 KiB, construct a split queue and one descriptor chain using virtio-queue's `mock` module (enable its `test-utils` feature as a dev-dependency feature), then call `fuse_backend_rs::transport::Reader::from_descriptor_chain(&mem, chain.clone())` and `virtio_vsock::packet::VsockPacket::from_tx_virtq_chain(&mem, &mut chain, 4096)`. Both calls may return `Err` for a chain that is not a valid FUSE or vsock request; the test asserts only that they compile and return without panicking. Document in the module comment that this test exists to catch a future pin change that splits the queue types.

**Steps:**
- [ ] Write the failing (non-compiling) test, run `cargo test -p boxcar-fs dep_check`, and confirm it fails to compile only because the module is missing, not because of a type mismatch.
- [ ] Add the dev-dependency features, make it compile and pass.
- [ ] Commit: `fs: pin-set canary for virtio-queue type unification`.

**Verify:** `cargo test -p boxcar-fs dep_check` passes; no rust-vmm crate appears as a duplicated root line in `cargo tree -d` (dependents listed under a duplicated transitive crate do not count) and `cargo deny check bans` passes.

---

### Task 3: Audit record schema (`boxcar-proto`)

**Files:**
- Create: `crates/boxcar-proto/src/{audit,limits,redact,ids}.rs`; modify `src/lib.rs` to re-export.

**Interfaces:**
```rust
// ids.rs
pub struct SessionId(String);            // Uuid::now_v7().to_string(); Display; FromStr validates a UUID
impl SessionId { pub fn new() -> Self; pub fn as_str(&self) -> &str; }

// audit.rs
pub const SCHEMA_VERSION: u8 = 1;
#[repr(u8)] pub enum Ring { Host = 0, Guest = 1 }         // serializes as integer 0 / 1
pub enum Source { Vmm, Fs, Net, Vsock, Pty, Guest, Sensor, Reconciler, Gateway, Control }  // lowercase strings
pub struct Subject { pub pid: u32, pub uid: u32, pub gid: u32 }
pub struct SpanRef { pub trace_id: String, pub span_id: String }
pub struct Hash(pub [u8; 32]);   // Serialize as "b3:<64 hex>", Deserialize parses it; Display; from_blake3(blake3::Hash)
pub struct Record {
    pub v: u8, pub session_id: SessionId, pub seq: u64, pub ring: Ring, pub src: Source,
    #[serde(rename = "type")] pub kind: String,
    pub ts_host_ns: u64, pub ts_mono_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")] pub ts_guest_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")] pub subject: Option<Subject>,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")] pub span: Option<SpanRef>,
    pub prev: Hash, pub hash: Hash,
}
impl Record {
    /// Serializes without `hash`, sorts keys, hashes prev bytes || canonical json.
    pub fn compute_hash(&self) -> Hash;
    pub fn canonical_bytes_without_hash(&self) -> Vec<u8>;
}
pub fn genesis_prev(session_id: &SessionId) -> Hash;   // blake3(session_id.as_str().as_bytes())

/// Typed payloads. Adjacently tagged so `to_value` yields {"type": "...", "data": {...}}.
#[serde(tag = "type", content = "data")]
pub enum Payload { VmmStart(VmmStart), VmmStop(VmmStop), FsMount(FsMount), FsOpen(FsOpen), FsCreate(FsCreate), FsClose(FsClose), FsRead(FsIo), FsWrite(FsIo), FsUnlink(FsPathOp), FsRmdir(FsPathOp), FsMkdir(FsMkdir), FsMknod(FsMknod), FsSymlink(FsSymlink), FsLink(FsLink), FsRename(FsRename), FsSetattr(FsSetattr), FsFallocate(FsFallocate), FsXattr(FsXattr), FsDenied(FsDenied), FsReaddir(FsPathOp), Checkpoint(Checkpoint) }
// serde renames: "vmm.start", "vmm.stop", "fs.mount", "fs.open", "fs.create", "fs.close", "fs.read", "fs.write", "fs.unlink", "fs.rmdir", "fs.mkdir", "fs.mknod", "fs.symlink", "fs.link", "fs.rename", "fs.setattr", "fs.fallocate", "fs.xattr", "fs.denied", "fs.readdir", "checkpoint"
impl Payload {
    pub fn kind(&self) -> &'static str;                 // the dotted name
    pub fn source(&self) -> Source;                      // vmm.* → Vmm, fs.* → Fs, checkpoint → Vmm
    pub fn into_parts(&self) -> (String, serde_json::Value);   // ("fs.open", {...})
    pub fn from_record(r: &Record) -> Result<Payload, serde_json::Error>;
}
pub struct OpResult { pub ok: bool, #[skip_if_none] pub errno: Option<i32>, #[skip_if_none] pub err: Option<String> }
impl OpResult { pub fn ok() -> Self; pub fn errno(e: i32) -> Self /* err = errno name, e.g. "EACCES" */ }
pub struct ArtifactRef { pub path: String, pub blake3: Hash }
pub struct VmmStart { pub version: String, pub kernel: ArtifactRef, pub initramfs: Option<ArtifactRef>, pub cmdline: String, pub vcpus: u32, pub mem_mib: u64 }
pub struct VmmStop { pub reason: String, pub exit_code: Option<i32> }
pub struct FsMount { pub mount: String, pub guest_path: String, pub host_root: String, pub cache_policy: String }
pub struct FsOpen { pub mount: String, pub path: String, pub fh: u64, pub flags: u32, pub flags_decoded: Vec<String>, pub exec: bool, pub result: OpResult }
pub struct FsCreate { pub mount: String, pub path: String, pub fh: u64, pub mode: u32, pub flags: u32, pub result: OpResult }
pub enum HashStatus { Ok, Raced, Gone, SkippedSize, NotHashed, Error }     // snake_case strings
pub enum Attrib { Caller, Handle }                                          // "caller" | "handle"
pub struct FsClose { pub mount: String, pub path: String, pub path_at_open: String, pub fh: u64, pub bytes_read: u64, pub bytes_written: u64, pub size: Option<u64>, pub blake3: Option<Hash>, pub hash_status: HashStatus, pub open_seq: Option<u64>, pub attrib: Attrib }
pub struct FsIo { pub mount: String, pub path: String, pub fh: u64, pub offset: u64, pub len: u32, pub result: OpResult, pub attrib: Attrib }
pub struct FsPathOp { pub mount: String, pub path: String, pub result: OpResult }
pub struct FsMkdir { pub mount: String, pub path: String, pub mode: u32, pub result: OpResult }
pub struct FsMknod { pub mount: String, pub path: String, pub mode: u32, pub rdev: u32, pub result: OpResult }
pub struct FsSymlink { pub mount: String, pub path: String, pub target: String, pub result: OpResult }
pub struct FsLink { pub mount: String, pub path: String, pub target_path: String, pub result: OpResult }
pub struct FsRename { pub mount: String, pub from: String, pub to: String, pub flags: u32, pub result: OpResult }
pub struct SetAttr { pub mode: Option<u32>, pub uid: Option<u32>, pub gid: Option<u32>, pub size: Option<u64>, pub atime: Option<i64>, pub mtime: Option<i64> }   // all skip_if_none
pub struct FsSetattr { pub mount: String, pub path: String, pub set: SetAttr, pub result: OpResult }
pub struct FsFallocate { pub mount: String, pub path: String, pub offset: u64, pub len: u64, pub mode: u32, pub result: OpResult }
pub struct FsXattr { pub mount: String, pub path: String, pub name: String, pub op: String /* "set" | "remove" */, pub result: OpResult }
pub struct FsDenied { pub mount: String, pub path: String, pub op: String /* "lookup" | "access" | "open" | ... */, pub errno: i32 }
pub struct Checkpoint { pub records_since: u64, pub dropped: u64, pub root_hash: Hash }

// limits.rs
pub const MAX_PATH: usize = 4096; pub const MAX_ARGV_ELEMS: usize = 256; pub const MAX_ARGV_BYTES: usize = 16384;
pub const MAX_SUMMARY: usize = 512; pub const INLINE_MAX: usize = 8192; pub const MAX_RECORD_BYTES: usize = 65536;
pub fn truncate_utf8(s: &str, max: usize) -> (String, bool);   // cuts on a char boundary, appends "…" when cut

// redact.rs
pub fn scrub(v: &mut serde_json::Value);   // any object key matching (case-insensitive) api_key, api-key, x-api-key, authorization, secret, token, bearer, password → value "[redacted]"; recursive
```

**Requirements:**
- `Ring` serializes as the integer `0`/`1` (not a string). `Source`, `HashStatus`, `Attrib` serialize as lowercase or snake_case strings.
- `Record::compute_hash` follows the Global Constraints rule exactly. Key sorting comes from converting to `serde_json::Value` (serde_json's default `Map` is ordered by key); do not enable `preserve_order`.
- `Payload::from_record` rebuilds the adjacently tagged object from `kind` and `data` and deserializes. Unknown `kind` is an error here, but readers of the log must never need `Payload`; they work on `Record`.
- Every payload struct derives `Serialize, Deserialize, Clone, Debug, PartialEq`.

**Steps:**
- [ ] Write failing tests in `crates/boxcar-proto/src/audit.rs` (`#[cfg(test)]`): (a) round-trip every `Payload` variant through `into_parts` → `Record` → `from_record`; (b) `compute_hash` is identical for two `Record`s whose `data` objects were built with keys inserted in different orders; (c) `hash` string format is `b3:` + 64 lowercase hex, and parsing it back yields the same bytes; (d) `genesis_prev` equals `blake3(session_id bytes)`; (e) a hand-computed vector: a fixed `Record` (fixed session id, seq 1, fixed timestamps) whose canonical bytes you print once, then assert the exact hash hex in the test (this pins the canonical form); (f) `Ring` serializes as `0`/`1`.
- [ ] Write failing tests for `limits::truncate_utf8` (cuts before a multi-byte char, never splits it; no cut when short) and `redact::scrub` (nested keys, case-insensitivity, non-matching keys untouched).
- [ ] Run `cargo test -p boxcar-proto` and confirm they fail for the expected reason (missing items).
- [ ] Implement, run until green with pristine output.
- [ ] Commit: `proto: audit record envelope, typed payloads, limits, redaction`.

**Verify:** `cargo test -p boxcar-proto` green; clippy and fmt clean.

---

### Task 4: Chained audit log writer, reader, verifier, and `boxcar audit verify`

**Files:**
- Create: `crates/boxcar-audit/src/{sink,writer,chain,segment,checkpoint,reader,verify}.rs`; modify `src/lib.rs`.
- Create: `crates/boxcar/src/cli.rs`, `crates/boxcar/src/cmd/mod.rs`, `crates/boxcar/src/cmd/audit.rs`; modify `crates/boxcar/src/main.rs`.

**Interfaces:**
```rust
// sink.rs
pub enum Priority { Normal, Critical }   // Critical forces fdatasync right after the record is written
pub struct Submission { pub ring: Ring, pub ts_guest_ns: Option<u64>, pub subject: Option<Subject>, pub payload: Payload, pub span: Option<SpanRef>, pub priority: Priority }
#[derive(Clone)] pub struct AuditSink { /* crossbeam Sender<Submission>, plus an Arc<AtomicU64> dropped counter */ }
impl AuditSink {
    pub fn emit(&self, s: Submission) -> Result<(), EmitError>;    // blocking send; for never-drop events. EmitError::{Closed, Checkpoint} (a producer may not submit Payload::Checkpoint)
    pub fn try_emit(&self, s: Submission) -> bool;                  // never waits (try_read on the close gate); increments dropped only when the channel is full
    pub fn dropped(&self) -> u64;
}

// writer.rs
pub struct WriterConfig { pub data_dir: PathBuf, pub session_id: SessionId, pub checkpoint_every: u64 /* 1024 */, pub checkpoint_interval: Duration /* 2 s */, pub segment_max_bytes: u64 /* 256 MiB */, pub channel_capacity: usize /* 65536 */ }
pub struct WriterHandle { /* join handle + shutdown */ }
impl WriterHandle { pub fn session_dir(&self) -> &Path; pub fn close(self) -> io::Result<CloseStats>; }   // drains channel, writes a final checkpoint, fdatasync, joins
pub struct CloseStats { pub records: u64, pub dropped: u64, pub last_seq: u64, pub last_hash: Hash }
pub fn spawn(cfg: WriterConfig) -> io::Result<(AuditSink, WriterHandle)>;
// The writer thread: recv → stamp ts_host_ns (CLOCK_REALTIME) and ts_mono_ns (CLOCK_MONOTONIC) → seq += 1 → prev = last hash → compute hash → append line → BufWriter flush after each drained batch → checkpoint policy.

// chain.rs
pub struct Chainer { prev: Hash, seq: u64 }
impl Chainer { pub fn genesis(session_id: &SessionId) -> Self; pub fn resume(seq: u64, last_hash: Hash) -> Self; pub fn next(&mut self, partial: RecordWithoutSeqAndHash) -> Record; }

// segment.rs — layout under <data_dir>/sessions/<session_id>/
//   meta.json         {"v":1,"session_id":...,"created_ts_host_ns":...,"boxcar_version":...,"segments":N,"recovered_from_seq":null|N}
//   events.000001.jsonl, events.000002.jsonl, ...   (current = highest number; a new segment starts when the current exceeds segment_max_bytes; the chain continues across segments)
//   checkpoints.jsonl {"seq":..,"segment":..,"offset":..,"root_hash":"b3:..","records_since":..,"dropped":..}
pub struct SegmentWriter { ... }  // open_or_create(dir) performs torn-tail recovery on the last segment (see below)

// checkpoint.rs — every `checkpoint_every` records or `checkpoint_interval`, whichever first:
//   root_hash = blake3 over the concatenated raw hash bytes of every record since the previous checkpoint;
//   append a Payload::Checkpoint record to the chain (it is itself chained), then a line to checkpoints.jsonl, then fdatasync the segment.

// reader.rs
pub struct LogReader { ... }
impl LogReader { pub fn open(session_dir: &Path) -> io::Result<Self>; pub fn records(&self) -> impl Iterator<Item = io::Result<Record>> + '_; pub fn seek_seq(&mut self, seq: u64) -> io::Result<()>; pub fn last(&self) -> io::Result<Option<Record>>; }
// Reader parses each line as Record (untyped data). A line that fails to parse is an error with segment+line number.

// verify.rs
pub struct VerifyReport { pub records: u64, pub segments: u32, pub checkpoints: u32, pub last_seq: u64, pub last_hash: Hash }
pub enum VerifyError { Io(..), Parse { segment: u32, line: u64, .. }, Chain { seq: u64, expected: Hash, got: Hash }, Gap { expected_seq: u64, got_seq: u64 }, Checkpoint { seq: u64, expected: Hash, got: Hash }, Genesis { .. } }
pub fn verify_session(session_dir: &Path) -> Result<VerifyReport, VerifyError>;
```
Torn-tail recovery (writer startup on an existing session dir): read the last segment line by line; keep the longest prefix of lines that parse and whose `hash` equals the recomputed hash with the correct `prev`; truncate the file after that prefix; resume the chain from its last record; write `recovered_from_seq` to `meta.json` when anything was cut.

CLI: `boxcar audit verify <session-dir> [--json]`. Exit 0 and print `ok: <records> records, <segments> segments, last seq <n>` on success; exit 1 and print the first break (`seq`, `expected`, `got`, or the gap) on failure. `--json` prints the report or error as one JSON object.

**Steps:**
- [ ] Write failing tests in `crates/boxcar-audit/tests/writer.rs` using `tempfile`: (a) gap-free seq under 8 producer threads emitting 1000 events each: after `close`, the reader yields seq 1..=8000+checkpoints with no gaps and `verify_session` passes; (b) 10k records with `segment_max_bytes = 64 KiB` produce more than one segment and `verify_session` passes across them; (c) flipping one byte inside a mid-file record makes `verify_session` fail with `VerifyError::Chain` at that record's seq (or `Parse` if the flip breaks JSON), never later; (d) torn tail: write records, truncate the last segment mid-line, reopen with `spawn` on the same dir, emit more, close, and `verify_session` passes with `meta.json.recovered_from_seq` set; (e) `Priority::Critical` records are followed by a checkpoint-free fsync (assert via a counter on a test hook or by checking the record is present after `close` without a final checkpoint — keep this assertion honest; if you cannot observe fsync, assert the ordering guarantee instead and say so in the report); (f) checkpoint records appear in the chain at the configured interval and their `root_hash` verifies.
- [ ] Run `cargo test -p boxcar-audit` and confirm failure for the expected reason.
- [ ] Implement sink, chain, segment, checkpoint, writer, reader, verify; make tests green.
- [ ] Add the `boxcar audit verify` subcommand; add `crates/boxcar/tests/audit_cli.rs` that writes a session with the library and runs the binary with `assert_cmd`-free `std::process::Command` on `env!("CARGO_BIN_EXE_boxcar")`, asserting exit codes and stdout for the ok and corrupted cases.
- [ ] Commit in two steps: `audit: hash-chained single-writer log, reader, verifier` and `cli: boxcar audit verify`.

**Verify:** `cargo test -p boxcar-audit -p boxcar` green; `cargo run -p boxcar -- audit verify <dir>` on a test session prints `ok: ...`.

---

### Task 5: `boxcar doctor` and the KVM smoke test

**Files:**
- Create: `crates/boxcar-vmm/src/kvm.rs`, `crates/boxcar-vmm/tests/smoke.rs`, `crates/boxcar/src/cmd/doctor.rs`; modify `crates/boxcar-vmm/src/lib.rs`, `crates/boxcar/src/cli.rs`, `crates/boxcar/src/cmd/mod.rs`.

**Interfaces:**
```rust
// kvm.rs
pub struct KvmContext { pub kvm: kvm_ioctls::Kvm }
pub const REQUIRED_CAPS: &[kvm_ioctls::Cap] = &[Cap::Irqchip, Cap::UserMemory, Cap::SetTssAddr, Cap::Pit2, Cap::PitState2, Cap::Ioeventfd, Cap::Irqfd, Cap::ImmediateExit, Cap::ExtCpuid, Cap::MpState];
impl KvmContext { pub fn open() -> Result<Self, KvmError>; /* asserts get_api_version() == 12 */ pub fn missing_caps(&self) -> Vec<Cap>; pub fn max_vcpus(&self) -> usize; }
pub enum KvmError { Open(io::Error) /* includes a hint: "run: sudo modprobe kvm_amd (or kvm_intel); sudo setfacl -m u:$USER:rw /dev/kvm" */, ApiVersion(i32), MissingCaps(Vec<Cap>) }
```
`boxcar doctor` prints one line per check with `OK` or `FAIL` and a fix-it hint on failure, then exits non-zero if any required check failed: `/dev/kvm` readable and writable; KVM API version 12; each required cap; `docker info` succeeds (argv `["docker", "info", "--format", "{{.ServerVersion}}"]`); musl target installed (`rustup target list --installed` contains `x86_64-unknown-linux-musl`); `target/guest/vmlinux` and `target/guest/initramfs.cpio` present (reported as `MISSING (run: cargo xtask kernel / initramfs)`, not a failure). `pahole` in PATH is informational only.

Smoke test (`tests/smoke.rs`, `#![cfg(feature = "kvm-tests")]`, skips with a printed reason if `/dev/kvm` is not accessible): create a VM, one 4 KiB region at guest address 0x1000 registered with `set_user_memory_region`, write real-mode code `ba f8 03 b0 4b ee f4` (`mov dx,0x3f8; mov al,'K'; out dx,al; hlt`), set sregs `cs.base = 0, cs.selector = 0`, regs `rip = 0x1000, rflags = 2`, run the vCPU, assert the first exit is `VcpuExit::IoOut(0x3f8, [b'K'])` and the next is `VcpuExit::Hlt`.

**Steps:**
- [ ] Write the smoke test first; run `cargo test -p boxcar-vmm --features kvm-tests --test smoke` and confirm it fails because `KvmContext` does not exist.
- [ ] Implement `kvm.rs`; make the smoke test pass on this machine (`/dev/kvm` is available). Also confirm the test skips cleanly when run with `BOXCAR_FAKE_NO_KVM=1` (add that env check to the skip logic for testability).
- [ ] Implement `doctor`; run `cargo run -p boxcar -- doctor` and capture the output in the report.
- [ ] Commit: `vmm: KVM context and smoke test; cli: doctor`.

**Verify:** smoke test passes with `--features kvm-tests`; `boxcar doctor` prints all OK except the guest artifacts marked MISSING.

---

### Task 6: Guest kernel build (`cargo xtask kernel`)

**Files:**
- Create: `guest/kernel/Dockerfile`, `guest/kernel/build.sh`, `guest/kernel/VERSION`, `guest/kernel/boxcar.fragment`, `guest/kernel/README.md`, `guest/kernel/base/microvm-kernel-ci-x86_64-6.18.config`, `xtask/src/kernel.rs`; modify `xtask/src/main.rs`, `NOTICE`.

**Requirements:**
- `VERSION` holds `KERNEL_VERSION=6.18.<latest stable y at implementation time>` and `KERNEL_SHA256=<sha256 of linux-6.18.y.tar.xz from https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc>`, and `FIRECRACKER_COMMIT=<the main commit the base config was copied from>`.
- `base/microvm-kernel-ci-x86_64-6.18.config` is copied verbatim from Firecracker `resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config` at `FIRECRACKER_COMMIT`; add a NOTICE entry naming it.
- `boxcar.fragment` (exact lines): `CONFIG_EXPERT=y`, `CONFIG_ACPI=n`, `CONFIG_PCI=n`, `CONFIG_MODULES=n`, `CONFIG_X86_MPPARSE=y`, `CONFIG_KVM_GUEST=y`, `CONFIG_PARAVIRT=y`, `CONFIG_PTP_1588_CLOCK_KVM=y`, `CONFIG_VIRTIO=y`, `CONFIG_VIRTIO_MMIO=y`, `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`, `CONFIG_FUSE_FS=y`, `CONFIG_VIRTIO_FS=y`, `CONFIG_FUSE_DAX=n`, `CONFIG_VIRTIO_NET=y`, `CONFIG_VSOCKETS=y`, `CONFIG_VIRTIO_VSOCKETS=y`, `CONFIG_VIRTIO_CONSOLE=n`, `CONFIG_SERIAL_8250=y`, `CONFIG_SERIAL_8250_CONSOLE=y`, `CONFIG_BLK_DEV_INITRD=y`, `CONFIG_DEVTMPFS=y`, `CONFIG_TMPFS=y`, `CONFIG_UNIX98_PTYS=y`, `CONFIG_IP_PNP=y`, `CONFIG_IP_PNP_DHCP=y`, `CONFIG_CGROUPS=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_JIT_ALWAYS_ON=y`, `CONFIG_BPF_LSM=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_KPROBES=y`, `CONFIG_KPROBE_EVENTS=y`, `CONFIG_FTRACE=y`, `CONFIG_FUNCTION_TRACER=y`, `CONFIG_DYNAMIC_FTRACE=y`, `CONFIG_DEBUG_INFO_DWARF5=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_SECURITY=y`, `CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_SECURITY_LOCKDOWN_LSM=y`, `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`, `CONFIG_SECURITY_YAMA=y`, `CONFIG_LSM="landlock,lockdown,yama,bpf"`, `CONFIG_DEVMEM=n`, `CONFIG_PROC_KCORE=n`, `CONFIG_IO_URING=n`. If merging reveals that a line needs a dependency to take effect (for example `CONFIG_DEBUG_INFO_NONE=n` so DWARF5 applies, or `CONFIG_DEBUG_INFO=y`), add the dependency line to the fragment and note it in README.
- `Dockerfile`: `FROM debian:trixie@sha256:<digest you resolve with docker pull + inspect at implementation time>`; installs `build-essential flex bison bc libelf-dev libssl-dev dwarves python3 xz-utils cpio kmod rsync ca-certificates curl`; verifies `pahole --version` is at least 1.22 at image build time.
- `build.sh` (runs inside the container with `/src` = `guest/kernel`, `/out` = `target/guest`, `/cache` = a named Docker volume `boxcar-kernel-cache`): download the tarball into `/cache` if missing, verify `KERNEL_SHA256`, extract into `/cache/linux-<ver>`, copy the base config to `.config`, run `scripts/kconfig/merge_config.sh -m .config /src/boxcar.fragment`, `make olddefconfig`, then verify every fragment line: for `CONFIG_X=y` and `CONFIG_X="..."` lines the exact line must be present in `.config`; for `CONFIG_X=n` lines either `# CONFIG_X is not set` must be present or the symbol must be absent; print `fragment: all N applied` or list the misses and exit 1. Then `make -j"$(nproc)" vmlinux`, verify `readelf -S vmlinux | grep -q '\.BTF'`, `objcopy --only-keep-debug vmlinux /out/vmlinux.debug`, `objcopy --strip-debug vmlinux /out/vmlinux`, re-verify `.BTF` survived in `/out/vmlinux`, copy `.config` to `/out/kernel.config` and `System.map` to `/out/System.map`.
- `cargo xtask kernel [--native] [--jobs N]`: default builds the image (`docker build -t boxcar-kernel-builder guest/kernel`) and runs it with the three mounts as argv arrays; `--native` runs `build.sh` directly and first checks `pahole --version >= 1.22` and `libelf` headers, printing the Docker instructions otherwise. Prints the blake3 of `target/guest/vmlinux` at the end.

**Steps:**
- [ ] Resolve the current 6.18.y version, its sha256, the debian digest, and the Firecracker commit; write `VERSION`, `Dockerfile`, `README.md`, and download the base config.
- [ ] Write `build.sh` and `xtask kernel`; add a unit test in `xtask/src/kernel.rs` for the fragment-verification function (given a fragment and a `.config` text, it reports misses correctly for `=y`, `="str"`, and `=n` cases).
- [ ] Run `cargo xtask kernel` (expect 10 to 30 minutes on this machine). Fix fragment dependencies until `fragment: all N applied`.
- [ ] Commit: `guest: 6.18 kernel build in Docker with boxcar fragment`.

**Verify:** `file target/guest/vmlinux` reports `ELF 64-bit LSB executable, x86-64`; `readelf -S target/guest/vmlinux | grep -c '\.BTF'` is at least 1; `grep -c '^CONFIG_VIRTIO_FS=y' target/guest/kernel.config` is 1; `grep -E '^CONFIG_(ACPI|PCI|MODULES|IO_URING)=' target/guest/kernel.config` prints nothing.

---

### Task 7: Guest init hello mode and `cargo xtask initramfs`

**Files:**
- Create: `crates/boxcar-init/src/cmdline.rs`, `xtask/src/initramfs.rs`; modify `crates/boxcar-init/src/main.rs`, `xtask/src/main.rs`.

**Requirements:**
- `cmdline.rs`: `pub fn parse(s: &str) -> BTreeMap<String, String>` splits on whitespace outside double quotes, keeps only tokens with a `boxcar.` prefix, strips the prefix, and stores `key=value` (a token without `=` maps to an empty string). `pub fn read() -> io::Result<BTreeMap<String, String>>` reads `/proc/cmdline`.
- `main.rs` (PID 1): install a panic hook that writes the panic message to `/dev/kmsg` and `/dev/console` (best effort) before aborting; mount `proc` at `/proc` (`MS_NOSUID|MS_NOEXEC|MS_NODEV`); read the cmdline; if `mode` is `hello`: write `BOXCAR_INIT_HELLO\n` to `/dev/console`, `sync()`, then `reboot(RB_AUTOBOOT)`. Any other mode prints `boxcar-init: unknown mode` and reboots (Task 13 adds `console`). Never `unwrap` a syscall result; on error write the message to `/dev/console` and reboot.
- `xtask initramfs`: run `cargo build -p boxcar-init --target x86_64-unknown-linux-musl --profile guest` as an argv array; then write `target/guest/initramfs.cpio` in newc format with the `cpio` crate: directories `dev`, `proc`, `sys`, `run`, `newroot` (mode 0755), file `init` (mode 0755, the built binary), char device `dev/console` (mode 0600, major 5, minor 1), char device `dev/null` (mode 0666, major 1, minor 3), then the trailer. Reproducible: entries in that fixed order, `ino` sequential from 1, `mtime` 0, uid and gid 0, `nlink` 1. Print `initramfs: <bytes> bytes, blake3 <hex>`.

**Steps:**
- [ ] Write failing unit tests for `cmdline::parse` (prefix filtering, quoted values with spaces, token without `=`, duplicate key keeps the last).
- [ ] Implement `cmdline.rs` and `main.rs`; `cargo test -p boxcar-init` green (the tests run on the host; they do not need PID 1).
- [ ] Implement `xtask initramfs`; add a unit test that builds a tiny archive into a `Vec<u8>` with a stub file and asserts the newc magic `070701` at offset 0 and the `TRAILER!!!` name near the end.
- [ ] Run `cargo xtask initramfs`.
- [ ] Commit: `init: PID 1 hello mode; xtask: reproducible initramfs`.

**Verify:** `cpio -itv < target/guest/initramfs.cpio` lists `init` with mode `-rwxr-xr-x` and `dev/console` with `crw-------` and `5, 1`; `readelf -l target/x86_64-unknown-linux-musl/guest/boxcar-init | grep -c INTERP` prints `0` (a static-pie; `file` 5.38 misreports it as dynamically linked); running `cargo xtask initramfs` twice prints the same blake3.

---

### Task 8: x86_64 boot setup (memory layout, E820, boot_params, MPTable, page tables, registers, MSRs, CPUID, cmdline)

**Files:**
- Create: `crates/boxcar-vmm/src/arch/x86_64/{mod,layout,boot,mptable,mpspec,regs,gdt,msr,cpuid,interrupts}.rs`, `crates/boxcar-vmm/src/{memory,cmdline}.rs`; modify `src/lib.rs`, `NOTICE`.

**Requirements:**
- Port from Firecracker `src/vmm/src/arch/x86_64/` at a pinned commit (record it in each file header and NOTICE): `layout.rs` constants (use the values in Global Constraints), `mptable.rs` with its tests, `mpspec.rs` (the bindgen output for `mpspec_def.h`), `regs.rs` (`setup_regs`, `setup_sregs`, `setup_fpu`, GDT/IDT/page tables with the constants above), `gdt.rs`, `msr.rs` (the boot MSR list: `MSR_IA32_SYSENTER_CS/ESP/EIP`, `MSR_STAR`, `MSR_CSTAR`, `MSR_KERNEL_GS_BASE`, `MSR_SYSCALL_MASK`, `MSR_LSTAR` all 0, `MSR_IA32_TSC` 0, `MSR_IA32_MISC_ENABLE = MSR_IA32_MISC_ENABLE_FAST_STRING`, `MSR_MTRRdefType = (1 << 11) | 6`), `interrupts.rs` (`set_lint`: LVT0 ExtINT, LVT1 NMI). Keep the Amazon and Chromium OS headers.
- `cpuid.rs`: a `patch_cpuid(cpuid: &mut CpuId, vcpu_id: u8, num_cpus: u8)` in the Cloud Hypervisor style operating on `kvm_bindings::CpuId` entries: leaf 1 EBX apic id `[31:24] = vcpu_id`, `[23:16] = num_cpus`, `[15:8] = 8`; ECX bit 31 (hypervisor) set; EDX bit 28 (HTT) set when `num_cpus > 1`; leaf 6 ECX bit 3 cleared; leaf 0xA zeroed; leaves 0xB and 0x1F: EDX = vcpu_id and level types 1 (thread) at subleaf 0, 2 (core) at subleaf 1, with EBX counts `1` and `num_cpus`; AMD leaf 0x8000_0008 ECX `[7:0] = num_cpus − 1`, leaf 0x8000_001E EAX = vcpu_id; leave KVM leaves `0x4000_0000..=0x4000_00FF` untouched.
- `boot.rs`: `pub fn configure_system(mem: &GuestMemoryMmap, cmdline_addr: GuestAddress, cmdline_size: usize, initrd: Option<InitrdConfig { address: GuestAddress, size: usize }>, num_cpus: u8) -> Result<()>` writes the MPTable at `0x9fc00` and `boot_params` at `0x7000` via `linux_loader::configurator::linux::LinuxBootConfigurator::write_bootparams` with `type_of_loader = 0xff`, `boot_flag = 0xaa55`, `header = 0x53726448`, `kernel_alignment = 0x0100_0000`, `cmd_line_ptr`, `cmdline_size`, `ramdisk_image`, `ramdisk_size`, and the E820 entries from Global Constraints (`add_e820_entry` as in Firecracker).
- `memory.rs`: `pub fn arch_memory_regions(size: u64) -> Vec<(GuestAddress, usize)>` (one region below 3 GiB, a second from 4 GiB when needed); `pub fn create_guest_memory(size: u64) -> Result<GuestMemoryMmap>`; `pub fn initrd_load_addr(mem: &GuestMemoryMmap, initrd_size: usize) -> Result<GuestAddress>` = `align_down(min(mem_end, 3 GiB) − size, 4096)` and must be above the kernel's last loaded byte (the caller passes `kernel_end`).
- `cmdline.rs`: `pub fn build_cmdline(base: &str, extra: &[&str], devices: &[MmioDeviceEntry { size: u32, base: u64, gsi: u32 }]) -> Result<linux_loader::cmdline::Cmdline>` using `Cmdline::new(2048)`, `insert_str`, and `add_virtio_mmio_device(size, GuestAddress(base), gsi, None)`, which produces `virtio_mmio.device=4K@0xc0000000:5`.

**Steps:**
- [ ] Port the Firecracker unit tests first (mptable signature and checksum tests, regs tests for GDT/IDT/page tables, the E820 layout test for 512 MiB, 3 GiB, 5 GiB) and add: `patch_cpuid` on a synthetic `CpuId` asserts the exact EBX/ECX/EDX bits; `build_cmdline` output contains `virtio_mmio.device=4K@0xc0000000:5` and `virtio_mmio.device=4K@0xc0001000:6` for two devices and rejects a cmdline over 2048 bytes; `initrd_load_addr` for a 512 MiB guest and a 2 MiB initrd equals `0x1fe00000`.
- [ ] Run `cargo test -p boxcar-vmm` and confirm failure for the expected reason.
- [ ] Port and implement; make green (all of this runs without KVM on a `GuestMemoryMmap`).
- [ ] Commit: `vmm: x86_64 boot setup ported from Firecracker with tests`.

**Verify:** `cargo test -p boxcar-vmm` green without `/dev/kvm`; NOTICE lists the ported files and commit.

---

### Task 9: vCPU run loop, kick, buses, serial, i8042, stdin, shutdown, and `boxcar run --no-fs` booting the hello init

**Files:**
- Create: `crates/boxcar-vmm/src/{vcpu,kick,stdin,lifecycle,vmm}.rs`, `crates/boxcar-vmm/src/devices/{mod,legacy}.rs`, `crates/boxcar/src/cmd/run.rs`; modify `crates/boxcar-vmm/src/lib.rs`, `crates/boxcar/src/cli.rs`, `NOTICE`.

**Execute this task after Task 10.** The PIO and MMIO buses are `boxcar_virtio::bus::{Bus, BusDevice}` from Task 10; do not create a bus in this crate.

**Interfaces:**
```rust
// buses: two boxcar_virtio::bus::Bus instances (PIO and MMIO). Unmapped PIO reads fill 0xff; unmapped writes are ignored; port 0x80 is a no-op.

// vmm.rs
pub struct VmConfig { pub kernel: PathBuf, pub initramfs: Option<PathBuf>, pub mem_mib: u64 /* default 512 */, pub vcpus: u8 /* default 1 */, pub cmdline_extra: Vec<String>, pub debug_boot: bool, pub console: ConsoleOut /* Stdio | File(PathBuf) */, pub audit: AuditSink }   // Task 12 adds fs_shares
pub struct Vmm { .. }
impl Vmm { pub fn new(cfg: VmConfig) -> Result<Vmm, VmmError>; pub fn run(self) -> Result<VmExit, VmmError>; pub fn handle(&self) -> VmmHandle; }
pub struct VmmHandle { .. }  impl VmmHandle { pub fn request_stop(&self, reason: StopReason); }
pub enum VmExit { GuestReset, GuestShutdown, StopRequested(StopReason), VcpuError(String) }
pub const BASE_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 pci=off nomodule 8250.nr_uarts=1 i8042.noaux i8042.nomux i8042.dumbkbd lockdown=integrity random.trust_cpu=on quiet loglevel=4 rdinit=/init";
// debug_boot replaces "quiet loglevel=4" with "earlyprintk=serial,ttyS0,115200 loglevel=7"
```
- Boot order in `Vmm::new`: `KvmContext::open` → raise `RLIMIT_NOFILE` soft to hard → `create_vm` → `set_tss_address(0xFFFB_D000)` → `create_irq_chip` → `create_pit2(kvm_pit_config { flags: KVM_PIT_SPEAKER_DUMMY, .. })` → guest memory + `set_user_memory_region` per region → `linux_loader::loader::elf::Elf::load(&mem, None, &mut File, Some(GuestAddress(0x100000)))` → initramfs at `initrd_load_addr` via `mem.read_exact_volatile_from` (or `read_volatile_from` loop) → devices (this task: serial and i8042 only; the MMIO bus exists but is empty) → cmdline (`BASE_CMDLINE`, extras, device entries) written at `0x20000` → `configure_system` → vCPUs (`create_vcpu`, `patch_cpuid` + `set_cpuid2`, `set_msrs`, `set_fpu`, `set_regs` (BSP only: `rip = entry`, `rsp = rbp = 0x8ff0`, `rsi = 0x7000`, `rflags = 2`), `set_sregs` (BSP only), `set_lint`) → emit a `Payload::VmmStart` audit record (kernel path and blake3, initramfs blake3, cmdline, vcpus, mem_mib).
- `vcpu.rs`: one `std::thread` per vCPU running `VcpuFd::run()` in a loop and dispatching: `IoIn/IoOut` → PIO bus; `MmioRead/MmioWrite` → MMIO bus; `Hlt` → log once, continue; `Shutdown` → `VmExit::GuestReset`; `SystemEvent(..)` → `VmExit::GuestShutdown`; `FailEntry`/`InternalError` → dump `get_regs`/`get_sregs` at error level and return `VcpuError`; `Err(EINTR)`/`Err(EAGAIN)` → check the stop flag and continue. Report exits to the main thread over a channel.
- `kick.rs`: capture `*mut kvm_run` from `VcpuFd::get_kvm_run()` per thread; register a no-op handler for `SIGRTMIN()` with `vmm_sys_util::signal::register_signal_handler`; `VcpuKicker::kick()` writes `immediate_exit = 1` with `write_volatile` then `pthread_kill(tid, SIGRTMIN())`. Port the pattern from Firecracker/Cloud Hypervisor and cite it.
- `devices/legacy.rs`: COM1 at PIO `0x3f8..=0x3ff` via `vm_superio::Serial::with_events(EventFdTrigger, ConsoleEvents, out)` behind `Arc<Mutex>` with the trigger's `EventFd` registered as an irqfd on GSI 4; i8042 at PIO `0x60..=0x64` via `vm_superio::I8042Device::new(EventFdTrigger(reset_evt))`. `EventFdTrigger(EventFd)` implements `vm_superio::Trigger`. Serial output goes to stdout or a file per `ConsoleOut`.
- `stdin.rs`: on the main thread's `event_manager::EventManager`, a subscriber for stdin that reads up to the serial's free FIFO capacity and calls `enqueue_raw_bytes`; when the FIFO is full it drops stdin interest and re-adds it when the serial's `in_buffer_empty` event fires. Put the host TTY in raw mode with `vmm_sys_util::terminal::Terminal::set_raw_mode` only when stdin is a TTY; restore it in a guard on every exit path and in a panic hook. Pressing Ctrl-] twice within one second requests a stop.
- `lifecycle.rs`: stop triggers: i8042 reset event, `Shutdown`/`SystemEvent` exits, vCPU error, `SIGTERM`/`SIGINT` via a signalfd on the main thread, `VmmHandle::request_stop`. Sequence: set state `Stopping` → kick and join every vCPU → close devices → emit `Payload::VmmStop { reason, exit_code }` through the sink, then the caller (`boxcar run`) calls `WriterHandle::close()` (drains, final checkpoint, fsync) → restore the terminal → return `VmExit`.
- `boxcar run`: flags `--kernel PATH` (required), `--initramfs PATH`, `--mem-mib N` (512), `--vcpus N` (1), `--no-fs`, `--cmdline-extra STR` (repeatable), `--debug-boot`, `--audit-dir DIR` (default `./boxcar-data`; creates `<dir>/sessions/<session_id>/`), `--console-log PATH` (serial output to a file instead of stdout). Prints `session: <id>` and `audit: <session-dir>` to stderr before boot. Exit code 0 on `GuestReset` or `GuestShutdown`, 1 on `VcpuError`, 130 on Ctrl-C.

**Steps:**
- [ ] Unit tests without KVM: `BASE_CMDLINE` composition with `--debug-boot`; the Ctrl-] double-press detector as a pure function over timestamps; the serial device behind `Arc<Mutex>` receives bytes written through the PIO bus at 0x3f8 and the i8042 reset write (0xFE to 0x64) fires the reset EventFd.
- [ ] Implement in the order legacy devices → vcpu + kick → stdin → lifecycle → vmm → CLI.
- [ ] KVM boot: `cargo run -p boxcar -- run --kernel target/guest/vmlinux --initramfs target/guest/initramfs.cpio --no-fs --cmdline-extra boxcar.mode=hello`. Expected: the kernel banner on the terminal, then `BOXCAR_INIT_HELLO`, then the guest reboots through the i8042 and boxcar exits 0 within 3 seconds with `guest reset` on stderr, and the terminal is back to cooked mode. If the kernel prints nothing, use `--debug-boot`; if it still prints nothing, dump the BSP registers after the first exit and compare with Firecracker's expected values.
- [ ] Add `crates/boxcar-vmm/tests/boot_hello.rs` behind `kvm-tests` that runs the same boot with the console captured to a file and asserts `BOXCAR_INIT_HELLO` appears and the VM exits `GuestReset` within 10 seconds; it skips unless `BOXCAR_TEST_KERNEL` and `BOXCAR_TEST_INITRAMFS` are set.
- [ ] Commit in steps: `vmm: buses, serial, i8042`; `vmm: vcpu threads, kick, lifecycle`; `cli: boxcar run boots the hello init`.

**Verify:** the KVM boot above exits 0 in under 3 seconds with `BOXCAR_INIT_HELLO` printed; `cargo test -p boxcar-vmm --features kvm-tests` green with the env vars set; a session dir contains `vmm.start` and `vmm.stop` records and `boxcar audit verify` passes on it.

---

### Task 10: `boxcar-virtio`: device trait, virtio-mmio transport, IRQ trigger, slots, queue helpers, mocks

**Files:**
- Create: `crates/boxcar-virtio/src/{bus,device,config,mmio,irq,context,slots,queue,features,testing}.rs`; modify `src/lib.rs`, `NOTICE`.

**Interfaces:**
```rust
// bus.rs (port Firecracker src/vmm/src/devices/bus.rs with its tests; keep the header): BTreeMap<BusRange, Arc<Mutex<dyn BusDevice>>>
pub trait BusDevice: Send { fn read(&mut self, offset: u64, data: &mut [u8]); fn write(&mut self, offset: u64, data: &[u8]); }
pub struct Bus { .. }
impl Bus { pub fn new() -> Self; pub fn insert(&mut self, dev: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<(), BusError /* Overlap */>; pub fn read(&self, addr: u64, data: &mut [u8]) -> bool; pub fn write(&self, addr: u64, data: &[u8]) -> bool; }
// read/write return false when no device covers addr; callers decide what unmapped means (the VMM fills 0xff on unmapped PIO reads).

// device.rs
pub struct ActivatedQueue { pub queue: virtio_queue::Queue, pub evt: vmm_sys_util::eventfd::EventFd }
pub trait VirtioDevice: Send {
    fn device_type(&self) -> u32;
    fn num_queues(&self) -> usize;
    fn queue_max_size(&self, idx: usize) -> u16;
    fn avail_features(&self) -> u64;                 // must include VIRTIO_F_VERSION_1 (bit 32) and VIRTIO_RING_F_EVENT_IDX (bit 29)
    fn read_config(&self, offset: u64, data: &mut [u8]);
    fn write_config(&mut self, offset: u64, data: &[u8]);
    /// Called once, on the vCPU thread, when DRIVER_OK is set. Must only hand the queues to a worker and return.
    fn activate(&mut self, mem: Arc<GuestMemoryMmap>, queues: Vec<ActivatedQueue>, irq: Arc<IrqTrigger>, driver_features: u64) -> Result<(), ActivateError>;
    /// Called on a status-0 write. Must be a no-op when the device is not activated.
    fn reset(&mut self);
    fn queue_notify(&mut self, _idx: u32) {}         // fallback when ioeventfd is absent
}
// config.rs
pub struct VirtioConfig { pub device_features: u64, pub driver_features: u64, pub device_features_select: u32, pub driver_features_select: u32, pub queue_select: u32, pub device_status: u8, pub interrupt_status: Arc<AtomicU8>, pub config_generation: u32, pub queues: Vec<Queue>, pub queue_evts: Vec<EventFd>, pub activated: bool }
pub mod status { pub const ACKNOWLEDGE: u8 = 1; pub const DRIVER: u8 = 2; pub const DRIVER_OK: u8 = 4; pub const FEATURES_OK: u8 = 8; pub const DEVICE_NEEDS_RESET: u8 = 64; pub const FAILED: u8 = 128; }
// mmio.rs — virtio 1.2 §4.2.2 register map, version 2, vendor id 0, magic 0x74726976:
//   0x000 MagicValue, 0x004 Version, 0x008 DeviceID, 0x00c VendorID, 0x010 DeviceFeatures, 0x014 DeviceFeaturesSel,
//   0x020 DriverFeatures, 0x024 DriverFeaturesSel, 0x030 QueueSel, 0x034 QueueNumMax, 0x038 QueueNum, 0x044 QueueReady,
//   0x050 QueueNotify, 0x060 InterruptStatus, 0x064 InterruptACK, 0x070 Status, 0x080/0x084 QueueDescLow/High,
//   0x090/0x094 QueueDriverLow/High, 0x0a0/0x0a4 QueueDeviceLow/High, 0x0fc ConfigGeneration, 0x100.. device config
pub struct MmioTransport<D: VirtioDevice> { .. }
impl<D: VirtioDevice> MmioTransport<D> { pub fn new(device: D, mem: Arc<GuestMemoryMmap>, ctx: DeviceContext) -> Self; pub fn device(&self) -> &D; pub fn device_mut(&mut self) -> &mut D; }
impl<D: VirtioDevice> bus::BusDevice for MmioTransport<D> { .. }   // the transport is inserted straight into the MMIO Bus
// Status write semantics: writing 0 → reset (queues and config back to defaults, device.reset()); a write that sets DRIVER_OK while !activated → build ActivatedQueue list from cfg.queues/queue_evts (queues get event_idx enabled if negotiated), call device.activate exactly once; on Err set DEVICE_NEEDS_RESET and log.
// irq.rs
pub struct IrqTrigger { pub evt: EventFd, pub status: Arc<AtomicU8> }
impl IrqTrigger { pub fn signal_used_queue(&self) -> io::Result<()> /* fetch_or(0x1) then write(1) */; pub fn signal_config_change(&self) -> io::Result<()> /* fetch_or(0x2) then write(1) */; }
// context.rs
pub struct MmioSlot { pub base: u64, pub size: u64, pub gsi: u32 }
pub struct DeviceContext { pub slot: MmioSlot, pub irq: Arc<IrqTrigger>, pub queue_evts: Vec<EventFd>, pub kill_evt: EventFd }
impl DeviceContext { pub fn new(slot: MmioSlot, num_queues: usize) -> io::Result<Self>; pub fn register(&self, vm: &kvm_ioctls::VmFd) -> io::Result<()> /* register_ioevent at slot.base + 0x50 with datamatch = queue index for each queue; register_irqfd(irq.evt, slot.gsi) */; }
// slots.rs
pub struct SlotAllocator { .. }  // AddressAllocator(0xC000_0000, 0x1000_0000) + IdAllocator(5, 23); alloc() -> MmioSlot with size 0x1000, deterministic in call order
// queue.rs
pub fn drain_queue<F, E>(queue: &mut Queue, mem: &GuestMemoryMmap, mut f: F) -> Result<bool, E> where F: FnMut(DescriptorChain<&GuestMemoryMmap>) -> Result<u32, E>;
// loop { queue.disable_notification(mem); while let Some(chain) = queue.pop_descriptor_chain(mem) { let len = f(chain)?; queue.add_used(mem, head, len) }; if !queue.enable_notification(mem)? { break } }  return Ok(queue.needs_notification(mem)?)
// features.rs: VIRTIO_F_VERSION_1, VIRTIO_RING_F_EVENT_IDX constants from virtio-bindings re-exported with names
// testing.rs: a `DummyDevice` (type 0xffff, 2 queues, config space of 8 bytes) and helpers to build a MmioTransport over a GuestMemoryMmap without KVM (DeviceContext::new works without a VmFd; only register needs one)
```

**Requirements:**
- Seed the transport and config from rust-vmm's `virtio-device` at tag `virtio-queue-v0.17.0` (files `src/lib.rs`, `src/mmio.rs`, `src/virtio_config.rs`, Apache-2.0 OR MIT) and Firecracker's `src/vmm/src/devices/virtio/transport/mmio.rs`; keep their headers, name the sources and commits, and add NOTICE entries. Adapt freely; this crate is ours.
- The transport never blocks: `activate` on the vCPU thread hands queues to the device and returns.

**Steps:**
- [ ] Write failing tests in `crates/boxcar-virtio/tests/mmio.rs` over a `GuestMemoryMmap` and `DummyDevice`: (a) reads at 0x000/0x004/0x008/0x00c return the magic, 2, 0xffff, 0; (b) feature selector: select 1 then read 0x010 returns the high 32 bits (VERSION_1 bit set); driver features written through select 0 and 1 round-trip; (c) the status handshake ACKNOWLEDGE → DRIVER → FEATURES_OK → DRIVER_OK calls `activate` exactly once with the right number of queues and the negotiated features; (d) a status-0 write before activation does not call `reset` on the device; after activation it calls `reset` and clears the status; (e) queue registers: after QueueSel, QueueNum, Desc/Driver/Device low+high, QueueReady=1, the `Queue`'s stored addresses and size match; (f) InterruptACK clears the acked bits from `interrupt_status`; (g) config space reads at 0x100.. hit `read_config` with the right offset; (h) `drain_queue` with a mock queue (virtio-queue `test-utils`) processes every chain, adds used entries, and returns `true` when the driver wants a notification and `false` after `needs_notification` says no; (i) `Bus` insert/overlap/read/write/unmapped semantics (the ported Firecracker bus tests).
- [ ] Port and implement; make green.
- [ ] Commit: `virtio: device trait, virtio-mmio transport, irq and slot helpers`.

**Verify:** `cargo test -p boxcar-virtio` green without KVM; NOTICE updated.

---

### Task 11: `AuditFs` decorator over the passthrough filesystem

**Files:**
- Create: `crates/boxcar-fs/src/{audit_fs,forward,path_map,handles,hasher,events,share}.rs`, `crates/boxcar-fs/tests/{auditfs,differential}.rs`; modify `src/lib.rs`.

**Interfaces:**
```rust
// share.rs
pub struct FsShareConfig { pub tag: String /* "root" | "workspace" */, pub host_dir: PathBuf, pub guest_path: String, pub cache: CachePolicyKind /* Always for root, Auto for workspace */ }
pub fn passthrough_config(share: &FsShareConfig) -> fuse_backend_rs::passthrough::Config;   // root_dir = host_dir, cache_policy per share, writeback = false, xattr = true, do_import = true, entry/attr timeouts 5 s (Always) or 1 s (Auto)
// audit_fs.rs
pub enum AuditLevel { Normal, Verbose }
pub struct AuditFsOptions { pub level: AuditLevel, pub hash_max_bytes: u64 /* 64 MiB */ }
pub struct AuditFs<F: FileSystem<Inode = u64, Handle = u64>> { .. }
impl<F> AuditFs<F> { pub fn new(inner: F, share: &FsShareConfig, host_root_fd: OwnedFd, sink: AuditSink, opts: AuditFsOptions) -> Self; }
impl<F> FileSystem for AuditFs<F> { type Inode = u64; type Handle = u64; /* every method via forward! */ }
// path_map.rs
pub struct PathMap { .. }  // ino → { parent, name: Box<[u8]>, nlookup: u64, deleted: bool }, plus (parent, name) → ino; root ino 1 = "/"
impl PathMap { pub fn insert(&mut self, parent: u64, name: &[u8], ino: u64); pub fn forget(&mut self, ino: u64, n: u64); pub fn rename(&mut self, old_parent: u64, old: &[u8], new_parent: u64, new: &[u8]); pub fn mark_deleted(&mut self, parent: u64, name: &[u8]); pub fn path(&self, ino: u64) -> String /* walks parents, depth cap 4096, fallback "<ino:N>" */; }
// handles.rs
pub struct HandleEntry { pub ino: u64, pub path_at_open: String, pub flags: u32, pub opener: Subject, pub open_seq: Option<u64>, pub bytes_read: u64, pub bytes_written: u64, pub wrote: bool, pub created: bool, pub truncated: bool }
pub struct HandleTable { .. }  // fh → HandleEntry
// hasher.rs
pub struct HashWorker { .. }   // 2 threads, crossbeam channel of HashJob { rel_path, expected_size, ... , sink, close_payload_template }
// opens with openat2(host_root_fd, rel_path, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) via libc::syscall(SYS_openat2), fstat before and after blake3::Hasher::update_reader, hash_status: Ok | Raced (size or mtime changed) | Gone | SkippedSize (> hash_max_bytes) | Error; then emits Payload::FsClose
```

**Requirements:**
- **Credential squash:** every call into the inner filesystem receives `Context { uid: 0, gid: 0, pid: ctx.pid, ..ctx }`; the real `ctx.{pid,uid,gid}` goes into `Subject`. Reply attributes are passed through unchanged.
- `init`: mask `FsOptions::WRITEBACK_CACHE` (and any DAX/map-alignment bits) out of the negotiated options; emit `fs.mount`.
- Event mapping (Normal level): `lookup` emits `fs.denied {op:"lookup"}` only on EACCES/EPERM (Verbose: also ENOENT as `fs.denied`); `readdirplus` wraps `add_entry` so every returned entry is inserted into `PathMap` with `nlookup += 1` (skip `.` and `..`); `forget`/`batch_forget` decrement and remove at 0; `open` records a handle and emits `fs.open` with `flags_decoded` (`O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND/O_EXCL/O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC/O_PATH`) and `exec = flags & 0x20 != 0` (`__FMODE_EXEC`; write a test that documents whether fuse-backend-rs exposes this bit; if it does not, `exec` is always false and the report says so); `create` inserts the node and handle, emits `fs.create`; `read`/`write` update handle counters (Verbose: emit `fs.read`/`fs.write`); when `ctx.pid == 0` or the write carries `FUSE_WRITE_CACHE`, attribute to the opener with `attrib = Handle`; `release` takes the handle: if `wrote || created || truncated` queue a hash job, else emit `fs.close` immediately with `hash_status = NotHashed`; `unlink`/`rmdir` mark deleted and emit; `rename` (including `RENAME_EXCHANGE`) updates the map and emits; `mkdir`/`mknod`/`symlink`/`link` insert and emit; `setattr` emits with the `SetAttr` fields that were valid (a size change marks the open handle `truncated` when a handle is passed); `fallocate` emits; `setxattr`/`removexattr` emit `fs.xattr`; `access` emits `fs.denied {op:"access"}` on EACCES only; every other method forwards silently. Every mutating op records `OpResult`. Failed opens and creates are always recorded.
- `forward.rs`: a `forward!` macro that implements every method of `fuse_backend_rs::api::filesystem::FileSystem` (0.14.0) by delegating to the inner filesystem with the squashed context, so no method falls back to ENOSYS. The audited methods override the macro's version explicitly.
- Never block the FUSE reply path on hashing or on the audit channel for droppable events: use `emit` (blocking) only for the never-drop set (open, create, close, unlink, rmdir, rename, mkdir, mknod, symlink, link, setattr, fallocate, xattr, denied, mount) and `try_emit` for `fs.read`/`fs.write`/`fs.readdir`.

**Steps:**
- [ ] Write failing tests in `tests/auditfs.rs` with a tempdir, `PassthroughFs::<()>::new(cfg)` + `import()`, and `Context { pid: 42, uid: 1000, gid: 1000 }` calling trait methods directly: (a) `create` + `write` + `release` yields an `fs.create`, then `fs.close` with `bytes_written == 3`, `blake3` equal to `blake3::hash(b"hi\n")`, `subject.pid == 42`, `attrib == Caller` (collect records through the writer into a session dir and read them back with `LogReader`, or through a test sink; either way assert on real `Record`s); (b) `mkdir` + `rename` + `unlink` produce the right paths; (c) `readdirplus` followed by `forget` of every entry leaves `PathMap` empty except root; (d) a failed `open` of a missing file yields `fs.open` with `result.ok == false, err == "ENOENT"`; (e) the process is unprivileged and `create` succeeds (proves the squash works); (f) a file larger than `hash_max_bytes` (set it to 16 bytes in the test) closes with `SkippedSize`.
- [ ] Write `tests/differential.rs`: over twin tempdirs, exercise every `FileSystem` method that `PassthroughFs` implements (enumerate them from the 0.14.0 docs: init, destroy, lookup, forget, batch_forget, getattr, setattr, readlink, symlink, mknod, mkdir, unlink, rmdir, rename, link, open, create, read, write, flush, fsync, fallocate, release, statfs, setxattr, getxattr, listxattr, removexattr, opendir, readdir, readdirplus, fsyncdir, releasedir, access, lseek, copyfilerange, getlk, setlk, setlkw, bmap, ioctl, poll, notify_reply) on both `PassthroughFs` and `AuditFs<PassthroughFs>` with identical inputs and assert identical `Result` shapes (Ok vs the same errno). A method the decorator forgot shows up as ENOSYS on one side only.
- [ ] Run and confirm failures for the expected reason; implement path_map, handles, hasher, events, forward, audit_fs; make green.
- [ ] Commit: `fs: AuditFs decorator with path map, handle attribution, content hashing`.

**Verify:** `cargo test -p boxcar-fs` green without KVM and as an unprivileged user; the differential test reports zero mismatches.

---

### Task 12: virtio-fs device and VMM wiring of the `root` and `workspace` shares

**Files:**
- Create: `crates/boxcar-fs/src/device.rs`, `crates/boxcar-fs/tests/virtio_roundtrip.rs`; modify `crates/boxcar-vmm/src/vmm.rs`, `crates/boxcar-vmm/src/devices/mod.rs`, `crates/boxcar/src/cmd/run.rs`.

**Interfaces:**
```rust
// device.rs
pub struct VirtioFs { .. }   // implements boxcar_virtio::VirtioDevice: device_type 26; queues: 0 hiprio + num_request_queues request queues (1 in M1), queue_max_size 1024;
// config space: tag[36] NUL-padded UTF-8 at 0x0, num_request_queues: u32 LE at 0x24; avail_features = VERSION_1 | EVENT_IDX
pub type FsServer = fuse_backend_rs::api::server::Server<AuditFs<PassthroughFs<()>>>;
impl VirtioFs { pub fn new(share: FsShareConfig, sink: AuditSink, opts: AuditFsOptions) -> Result<Self, FsError>; }
// activate: for each request queue (and the hiprio queue sharing the first worker), spawn thread "fs-<tag>-q<N>" running its own event_manager::EventManager subscribed to the queue's EventFd and the kill_evt; on a queue event: drain_queue(queue, mem, |chain| { let r = Reader::from_descriptor_chain(mem, chain.clone())?; let w: Writer<'_, ()> = VirtioFsWriter::new(mem, chain)?.into(); Ok(server.handle_message(r, w, None, Some(&hook))? as u32) }) and signal_used_queue when it returns true.
// hook: a MetricsHook counting opcodes (collect(&InHeader) / release(Option<&OutHeader>)) and logging at warn once per unmodeled opcode.
// reset: no-op when not activated; otherwise write kill_evt, join workers, clear state.
```
- VMM wiring: `VmConfig.fs_shares` in fixed order (`root` then `workspace`); for each, allocate a slot from `SlotAllocator` (slot 0 → base `0xC000_0000` GSI 5; slot 1 → base `0xC000_1000` GSI 6), build `DeviceContext`, `register` ioeventfds and the irqfd, wrap in `MmioTransport`, insert into the MMIO bus, and append the cmdline entry. Emit `fs.mount` on `init`.
- `boxcar run`: `--rootfs DIR` (required unless `--no-fs`) and `--workspace DIR` (default: a fresh tempdir under the session dir, printed to stderr) become the two shares; `--audit-level normal|verbose`.

**Steps:**
- [ ] Write `tests/virtio_roundtrip.rs` without KVM: build a `GuestMemoryMmap`, a mock request queue (virtio-queue `test-utils`), place a FUSE_INIT request (`fuse_in_header` + `fuse_init_in` with major 7, minor 31+) in a descriptor chain with a writable reply descriptor, run the device's queue-processing function once, and assert the used ring has one entry with `len > 0` and the reply `fuse_out_header.error == 0`; then a FUSE_LOOKUP of a file created in the share's tempdir asserts `error == 0` and the `fuse_entry_out.attr.size` matches. Also assert the config space reads `tag` and `num_request_queues` correctly.
- [ ] Implement `device.rs` and the wiring; make green.
- [ ] KVM check: `cargo run -p boxcar -- run --kernel target/guest/vmlinux --initramfs target/guest/initramfs.cpio --rootfs /tmp/empty --workspace /tmp/ws --cmdline-extra boxcar.mode=hello`; expected: the kernel probes `virtio_mmio` devices (visible with `--debug-boot`: lines mentioning `virtio_mmio virtio-mmio.0` and `virtiofs`), the hello init still prints and the VM exits 0, and the session's audit log contains two `fs.mount` records after the guest mounts (it does not in hello mode; assert only that boot still works and no device error is logged).
- [ ] Commit: `fs: virtio-fs device; vmm: wire root and workspace shares`.

**Verify:** `cargo test -p boxcar-fs` green; the KVM hello boot still exits 0 with the two devices present.

---

### Task 13: Init console mode, sysctls, shell on ttyS0, Alpine rootfs, and the M1 demo

**Files:**
- Create: `crates/boxcar-init/src/{mounts,sysctl,session,reaper,shutdown}.rs`, `crates/boxcar-proto/src/guestcmd.rs`, `xtask/src/rootfs.rs`; modify `crates/boxcar-init/src/main.rs`, `crates/boxcar-proto/src/lib.rs`, `xtask/src/main.rs`.

The `cmd` codec is shared with the host CLI (Task 14), so it lives in `boxcar-proto`: `pub mod guestcmd { pub fn encode(argv: &[String]) -> String; pub fn decode(s: &str) -> Result<Vec<String>, GuestCmdError>; }` using the `base64` crate's `URL_SAFE_NO_PAD` engine over a JSON array of strings, with unit tests in `boxcar-proto` (round trip, invalid base64, valid base64 that is not a JSON array, empty array rejected). `boxcar-init` depends on `boxcar-proto` with `default-features = false`.

**Requirements (init `console` mode, in order):**
1. Mount `proc`, `sysfs` at `/sys`, `devtmpfs` at `/dev` (in the initramfs); parse the cmdline (`mode`, `uid`, `gid`, `cmd`).
2. `mount("root", "/newroot", "virtiofs", MS_NOATIME, None)`; create `/newroot/workspace` if missing; `mount("workspace", "/newroot/workspace", "virtiofs", MS_NOATIME, None)`.
3. Move `/dev`, `/proc`, `/sys` into `/newroot` with `MS_MOVE`; mount `devpts` at `/newroot/dev/pts` (`newinstance,ptmxmode=0666,mode=0620,gid=5`), `tmpfs` at `/newroot/dev/shm` and `/newroot/run`, `tracefs` at `/newroot/sys/kernel/tracing`, `cgroup2` at `/newroot/sys/fs/cgroup`, `bpf` at `/newroot/sys/fs/bpf`. `/tmp` stays on virtio-fs.
4. `chdir("/newroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`, `chdir("/")`.
5. `sethostname("boxcar")`; sysctls via `/proc/sys`: `kernel/kptr_restrict=2`, `kernel/dmesg_restrict=1`, `kernel/unprivileged_bpf_disabled=1`, `kernel/perf_event_paranoid=3`, `kernel/yama/ptrace_scope=1`, `net/ipv6/conf/all/disable_ipv6=1` (each best effort with a logged warning if the path is missing).
6. Create cgroup directories `/sys/fs/cgroup/system` and `/sys/fs/cgroup/session`.
7. Spawn the session: `fork`; child: `setsid`, open `/dev/ttyS0` read-write, `ioctl(TIOCSCTTY)`, `dup2` onto 0/1/2, write the child pid into `/sys/fs/cgroup/session/cgroup.procs`, `setgroups(&[])`, `setresgid(gid)`, `setresuid(uid)`, `prctl(PR_SET_NO_NEW_PRIVS, 1)`, `chdir("/workspace")`, set env `HOME=/workspace TERM=xterm-256color PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin USER=agent`, then `execve` the command: if `cmd` is present, `boxcar_proto::guestcmd::decode` it; otherwise `["/bin/sh", "-l"]`.
8. PID 1 loop: single-threaded `poll` over a `signalfd` for `SIGCHLD` (block the signal first); on readable, `waitpid(-1, WNOHANG)` in a loop; when the session child exits, remember its status; continue reaping until no children remain.
9. `sync()`, then `reboot(RB_AUTOBOOT)`. Exit status is reported in M2 over vsock; in M1 the console shows it via `echo "boxcar: session exited <code>"` written by init to `/dev/console` before reboot.
- Every syscall result is checked; on any fatal error init writes `boxcar-init: <step>: <error>` to `/dev/console` and reboots.
- `xtask rootfs alpine [--version 3.22.1]`: downloads `alpine-minirootfs-<ver>-x86_64.tar.gz` from `https://dl-cdn.alpinelinux.org/alpine/v<major.minor>/releases/x86_64/` plus its `.sha256`, verifies, extracts into `target/guest/rootfs-alpine/` as the current user with `tar` as an argv array (`--no-same-owner --no-same-permissions` are fine), and writes `target/guest/rootfs-alpine/etc/boxcar-rootfs.json` with the version and hash. Pin the default version and hash in `xtask/src/rootfs.rs`.

**Steps:**
- [ ] Unit tests on the host for the pure pieces: `guestcmd` encode/decode in `boxcar-proto` (round trip, invalid base64, valid base64 that is not a JSON array, empty array), the env construction, and the sysctl path/value table.
- [ ] Implement mounts, sysctl, session, reaper, shutdown, and `main.rs` console mode; `cargo xtask initramfs`; `cargo xtask rootfs alpine`.
- [ ] KVM demo: `cargo run -p boxcar -- run --kernel target/guest/vmlinux --initramfs target/guest/initramfs.cpio --rootfs target/guest/rootfs-alpine --workspace /tmp/ws --audit-dir /tmp/bxaudit`. In the shell: `id` (uid equals the host uid), `cat /proc/mounts | grep virtiofs` (two lines), `echo hi > /workspace/a.txt`, `exit`. Expected: boxcar exits 0; `jq -c 'select(.type=="fs.close" and .data.path=="/a.txt")' /tmp/bxaudit/sessions/*/events.*.jsonl` shows `bytes_written: 3`, `blake3` equal to `b3sum /tmp/ws/a.txt` (or `blake3::hash` of the bytes), and `subject.pid > 1`; `boxcar audit verify /tmp/bxaudit/sessions/<id>` passes.
- [ ] Commit in steps: `init: console mode with rootfs mounts, sysctls, session spawn, reaper`; `xtask: alpine rootfs`.

**Verify:** the demo above, captured in the report with the actual `jq` output and the verify line.

---

### Task 14: CLI finish, `-- CMD`, and the gated M1 end-to-end tests

**Files:**
- Create: `crates/boxcar/tests/kvm_m1.rs`, `xtask/src/test_kvm.rs`; modify `crates/boxcar/src/cmd/run.rs`, `crates/boxcar/src/cli.rs`, `xtask/src/main.rs`, `README.md`, `CONTRIBUTING.md`.

**Requirements:**
- `boxcar run ... -- CMD [ARGS...]` encodes the argv as base64url JSON into `boxcar.cmd=` on the kernel command line (reject if the encoded cmdline would exceed 2048 bytes with a clear error). With `--` present and no TTY needed, the run is non-interactive: stdin is not put in raw mode.
- Default `--audit-dir` is `$XDG_DATA_HOME/boxcar` or `~/.local/share/boxcar`; `--workspace` defaults to a fresh `workspace/` under the session dir.
- `cargo xtask test-kvm m1`: checks `/dev/kvm` and the three artifacts, exports `BOXCAR_TEST_KERNEL`, `BOXCAR_TEST_INITRAMFS`, `BOXCAR_TEST_ROOTFS`, and runs `cargo test -p boxcar-vmm -p boxcar --features boxcar-vmm/kvm-tests,boxcar/kvm-tests -- --test-threads=1`; prints a skip message and exits 0 when prerequisites are missing.
- `crates/boxcar/tests/kvm_m1.rs` (feature `kvm-tests`, skips without the env vars): (a) `run -- /bin/sh -c 'echo M1_OK > /workspace/out.txt'` exits 0 within 30 s and `/workspace/out.txt` contains `M1_OK`; the session log has `fs.create`/`fs.close` for `/out.txt` with `bytes_written == 6` and a blake3 matching the file; `verify_session` passes; (b) `run -- /bin/sh -c 'exit 7'` exits 0 (M1 does not propagate the guest exit code) and the console log contains `boxcar: session exited 7`; (c) `run -- /bin/sh -c 'cat /etc/shadow'` records an `fs.open` for `/etc/shadow` (whatever its result) with a `subject.pid > 1`.
- README: a Quick start section with the four commands (`cargo xtask kernel`, `cargo xtask initramfs`, `cargo xtask rootfs alpine`, `cargo run -p boxcar -- run ...`) and the `boxcar audit verify` line.

**Steps:**
- [ ] Unit test that `boxcar run -- CMD` builds a `boxcar.cmd=` value that `boxcar_proto::guestcmd::decode` round-trips, and that an over-long command line is rejected with the clear error (the codec already lives in `boxcar-proto` from Task 13).
- [ ] Implement, then run `cargo xtask test-kvm m1` and paste the output in the report.
- [ ] Commit: `cli: -- CMD, defaults, gated M1 e2e tests`.

**Verify:** `cargo xtask test-kvm m1` green on this machine; the full KVM-free suite and `cargo deny check` green; README quick start works from a clean `target/`.
