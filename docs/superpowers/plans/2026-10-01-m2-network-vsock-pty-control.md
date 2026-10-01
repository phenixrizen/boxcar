# M2: Network, vsock, Agent PTY, Control Protocol v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After M2, `boxcar run` gives the guest a user-mode network with DNS, an egress allowlist, and connection-level audit events; a vsock device carrying a guest control channel, the agent's PTY, and host-side services; an interactive agent session attachable from another terminal; a versioned control protocol on a Unix socket that conductor can drive; and the guest's exit code propagated to the host.

**Architecture:** Two new device crates. `boxcar-net` is a frame-level user-mode stack on smoltcp inside the VMM: a dispatcher answers ARP, DHCP, and gateway ICMP itself, forwards DNS to the host resolver with a cache, terminates guest TCP with a deferred-SYN relay to host sockets under a policy allowlist, and relays UDP by NAT. `boxcar-vsock` is a port of Cloud Hypervisor's connection state machine and Unix muxer with an internal-services hook. Init gains a vsock control client and runs the agent under a PTY relayed over vsock to a `PtyHub` in the VMM. A control server on a Unix socket exposes status, stop, PTY attach and resize, audit subscription with replay, and policy updates. Fixed virtio slots are assigned by a table so device order never depends on which devices are enabled.

**Tech Stack:** Rust 1.96, the M1 pinned rust-vmm set (vm-memory 0.17.1, virtio-queue 0.17.0, virtio-vsock 0.11.0), smoltcp 0.14, socket2 0.5, arc-swap 1, proptest 1 (dev), schemars 0.8 (schema generation), nix 0.31 (guest PTY), the M1 crates.

**Spec:** `docs/superpowers/specs/2026-09-29-boxcar-design.md`. Roadmap: `docs/superpowers/plans/2026-09-30-boxcar-roadmap.md` (M2 section). M1 plan for the interfaces this builds on: `docs/superpowers/plans/2026-09-30-m1-shell-audited-rootfs.md`. M1 debt carried into M2 is listed in the M1 execution ledger's final-review triage; the items that must land are folded into Tasks 1, 4, 13, and 14 below.

## Global Constraints

- Everything in the M1 plan's Global Constraints still binds: Rust `1.96.0`, edition 2021, the exact pin table (now adding `smoltcp = "0.14"` with `default-features = false, features = ["std", "log", "medium-ethernet", "proto-ipv4", "proto-dhcpv4", "socket-tcp", "socket-udp", "socket-raw"]`, `socket2 = "0.5"` (feature `all`), `arc-swap = "1"`, `proptest = "1"` (dev), `schemars = "0.8"`, `virtio-vsock = "=0.11.0"` (already pinned), `vsock = "0.5"` is NOT used on the host), no git dependencies, no `[patch]`, license headers, ported-file provenance plus NOTICE entries, argv-array commands, `git commit -s` with the two trailer lines (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01Xm6wxRmFTbEVJQ7zrfbuJX`), task commit subjects used verbatim, fmt/clippy `-D warnings`/test/deny clean at the end of every task, `kvm-tests` gating with a printed skip reason.
- **Fixed virtio slot table** (exact): slot 0 = virtio-fs `root` at `0xC000_0000` GSI 5, slot 1 = virtio-fs `workspace` at `0xC000_1000` GSI 6, slot 2 = virtio-net at `0xC000_2000` GSI 7, slot 3 = virtio-vsock at `0xC000_3000` GSI 8. A disabled device leaves its slot empty; the kernel command line lists only present devices.
- **Guest network** (exact): guest IP `10.0.2.15/24`, gateway, DNS and DHCP server `10.0.2.2`, guest MAC `02:62:6f:78:00:01`, gateway MAC `02:62:6f:78:00:02`, DHCP lease 24 h, hostname `boxcar`. Guest-side kernel parameter `ip=10.0.2.15::10.0.2.2:255.255.255.0:boxcar:eth0:off:10.0.2.2` is appended when the net device is present. IPv6 is dropped; the guest sysctl `net.ipv6.conf.all.disable_ipv6=1` stays.
- **Policy v1** (exact): rules are `domain[:port]` (exact or `*.suffix`), `cidr[:port]`, with `default = deny | allow`; built-in deny for `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16` unless a rule explicitly allows the exact CIDR; the gateway `10.0.2.2` is always reachable for DNS/DHCP and (M4) the gateway service. Policy is hot-swapped through `arc_swap::ArcSwap<Policy>`.
- **vsock** (exact): guest CID 3, host CID 2. Guest→host ports: 1024 `boxcar.ctl` (JSON lines), 1025 `boxcar.pty` (one JSON header line then raw bytes), 1026 `boxcar.sensor` (reserved for M3, length-prefixed frames). Internal ports accept only a guest source port below 1024 and only the first connection per port; any other guest→host port lands on `<state>/vsock.sock_<port>` only if allowlisted, else RST and an audited denial. Host→guest uses Firecracker's hybrid protocol on `<state>/vsock.sock`: `CONNECT <port>\n` → `OK <port>\n`.
- **Control protocol v1** (exact): Unix stream socket `<state>/control.sock`, mode 0600 inside a 0700 state dir (default `$XDG_RUNTIME_DIR/boxcar/<session_id>/`, fallback `/tmp/boxcar-<uid>/<session_id>/`), `SO_PEERCRED` uid must equal the VMM's uid, UTF-8 JSON lines, 1 MiB max line. Server-first `{"v":1,"event":"hello","protocol":"boxcar.control","versions":[1],"server":"boxcar/<version>","session_id":"...","capabilities":["pty","audit","policy.net"]}`. Request `{"v":1,"id":<u64>,"op":"<op>",...}`; response `{"v":1,"id":N,"ok":true,"result":{...}}` or `{"v":1,"id":N,"ok":false,"error":{"code":"...","message":"..."}}`; event `{"v":1,"event":"<name>",...}`. Error codes exactly: `bad_request unsupported_version unknown_op invalid_state not_found busy rate_limited internal`. Every message type has a size cap and a test. Unknown fields are ignored; unknown events tolerated.
- **Guest ↔ VMM messages** (`boxcar-proto::guest`, JSON lines on vsock 1024, 64 KiB max): guest→host `hello{init_version, guest_mono_ns, guest_real_ns}`, `session.started{pid}`, `session.exited{code: Option<i32>, signal: Option<i32>}`, `pong{id, guest_mono_ns}`, `log{level, msg}`; host→guest `config{argv, env, cwd, uid, gid, hostname, term, rows, cols, sysctls}`, `resize{rows, cols}`, `signal{sig}`, `shutdown{grace_ms}`, `ping{id}`.
- **Audit record types added in M2** (exact `type` strings): `net.dhcp`, `net.dns`, `net.connect`, `net.tls`, `net.close`, `net.drop`, `net.udp`, `vsock.connect`, `vsock.close`, `session.start`, `session.exit`, `policy.changed`, `control.connect`, `control.stop`, `sync`. `fs.close` gains `ts_release_ns` (producer time). A new optional `path_b64` field appears on every `fs.*` payload with a `path` when the name was not valid UTF-8.
- Every file or socket the VMM creates after the shares are imported is created with an explicit mode (the process umask is 0 after `PassthroughFs::import`): sockets 0600, directories 0700, logs 0600.
- Exit codes of `boxcar run` (exact): the guest session's exit code when init reported one; 128+signal when the session was killed by a signal; 0 on a clean reset with no session report; 1 on `VcpuError`; 3 on `AuditFailed`; 128+signal for a host stop signal.

## Review Focus

1. **A guest that floods the network stack** (SYN flood to many destinations, DNS query storms). Expected: bounded tables (flow table cap 4096, DNS cache cap 4096, pending-SYN cap 256), oldest-evicted, counters in `net.drop`, and host sockets never exceeding the cap. Pinned in Task 7's `flow_table_evicts_oldest_at_cap` and Task 6's `dns_cache_is_bounded`.
2. **A host connect that hangs** (destination black-holed). Expected: the deferred SYN gets a 10 s connect timeout, then RST to the guest and `net.close{reason:"timeout"}`, with no thread or socket leaked. Pinned in Task 7's `connect_timeout_resets_the_guest_side`.
3. **A guest that opens the internal vsock ports itself** (an agent connecting to 2:1024 as an unprivileged user, or a second connection as root). Expected: refused with RST and `vsock.connect{verdict:"deny"}`; the real init connection (source port < 1024, first) keeps working. Pinned in Task 10's `internal_ports_accept_only_the_first_privileged_connection`.
4. **A viewer that stops reading the PTY stream** (a slow `boxcar attach`). Expected: the hub's per-client queue is bounded, a stalled client is detached with `pty.detached{reason:"slow"}`, and the guest PTY never blocks on a client. Pinned in Task 12's `a_slow_client_is_detached_and_the_guest_keeps_running`.
5. **A control client that sends a 2 MiB line or a flood of requests.** Expected: the line is refused with `bad_request` and the connection closed; more than 100 requests per second gets `rate_limited`; the VM is unaffected. Pinned in Task 3's `oversized_lines_and_floods_are_refused`.

## File Structure

| Path | Responsibility |
|---|---|
| `crates/boxcar-vmm/src/devices/{mod,slots}.rs` | the fixed slot table, device enablement, cmdline assembly from present devices |
| `crates/boxcar-vmm/src/{console,stdin}.rs` | decoupled console writer thread with a bounded ring; escape scanning independent of the serial FIFO |
| `crates/boxcar-vmm/src/control/{mod,server,conn,ops,peercred}.rs` | control socket server, per-connection loop, op dispatch, SO_PEERCRED |
| `crates/boxcar-vmm/src/{pty,guest_ctl,services}.rs` | PtyHub, the guest control channel, the internal vsock service registry |
| `crates/boxcar-proto/src/{control,guest}.rs` | control v1 and guest message types with size caps |
| `crates/boxcar-net/src/{lib,config,stack,frame,arp,dhcp,icmp,dns/{mod,parse,forwarder,cache},policy,tcp/{mod,flow,relay},sni,http_host,udp,upstream,audit,device}.rs` | the user-mode network stack and the virtio-net device |
| `crates/boxcar-vsock/src/{lib,csm/{mod,connection,txbuf},unix/{mod,muxer,muxer_killq,muxer_rxq},packet_ext,device,services}.rs` | the vsock port and device |
| `crates/boxcar-audit/src/{subscribe,reader}.rs` | live subscriptions with replay and lag recovery; reader filters and strict duplicate-key parsing |
| `crates/boxcar-init/src/{vsock,ctl,pty,session,main}.rs` | init v2: control client, PTY session, relay, exit report, graceful shutdown |
| `crates/boxcar/src/cmd/{run,status,stop,attach,events,policy}.rs`, `src/client.rs` | CLI commands and the control client |
| `xtask/src/{schema,test_kvm}.rs`, `proto/schema/*.json`, `proto/testdata/*.jsonl` | schema generation and golden vectors |
| `docs/{control-protocol,audit-events,networking,perf}.md` | protocol and event documentation |

---

### Task 1: Fixed slot table, device enablement, and exit-code plumbing

**Files:**
- Create: `crates/boxcar-vmm/src/devices/slots.rs`
- Modify: `crates/boxcar-vmm/src/devices/mod.rs`, `crates/boxcar-vmm/src/vmm.rs` (the `cmdline_size` helper and `Vmm::new` device step), `crates/boxcar-vmm/src/lifecycle.rs` (`VmExit`), `crates/boxcar/src/cmd/run.rs` (exit mapping), `crates/boxcar-virtio/src/slots.rs`
- Test: `crates/boxcar-vmm/src/devices/slots.rs` unit tests, `crates/boxcar-vmm/tests/boot_hello.rs` (extend)

**Interfaces:**
- Consumes: `boxcar_virtio::slots::SlotAllocator` (M1 Task 10), `boxcar_vmm::devices::FsDevices` and `FS_TAGS` (M1 Task 12), `VmExit::{GuestReset, GuestShutdown, StopRequested, VcpuError, AuditFailed}` (M1).
- Produces:
```rust
// devices/slots.rs
pub enum SlotId { FsRoot = 0, FsWorkspace = 1, Net = 2, Vsock = 3 }
pub struct Slot { pub id: SlotId, pub base: u64, pub gsi: u32, pub size: u64 /* 0x1000 */ }
pub const SLOT_TABLE: [Slot; 4];                      // the exact table from Global Constraints
pub fn slot(id: SlotId) -> Slot;
pub struct DeviceSet { pub fs: bool, pub net: bool, pub vsock: bool }
pub fn present_slots(set: &DeviceSet) -> Vec<Slot>;    // in slot order, only enabled devices
// boxcar_virtio::slots: SlotAllocator gains `reserve(base, gsi) -> Result<MmioSlot, SlotError>` so the VMM asks for exact slots instead of the next free one.
// lifecycle.rs: VmExit::GuestReset { session: Option<SessionOutcome> }; pub struct SessionOutcome { pub code: Option<i32>, pub signal: Option<i32> }   (Task 11 fills it; this task adds the field with None)
// vmm.rs: pub fn cmdline_size(cfg: &VmConfig, set: &DeviceSet) -> Result<usize>  uses present_slots so the CLI's 2048 check matches Vmm::new exactly.
```

- [ ] **Step 1: Write the failing tests.** In `slots.rs`: `the_table_matches_the_constraints` (bases `0xC000_0000 + i*0x1000`, GSIs 5..=8), `present_slots_keeps_fixed_positions` (`DeviceSet{fs:false, net:true, vsock:true}` yields slots 2 and 3 with their fixed bases, not 0 and 1). In `vmm.rs`: `cmdline_size_uses_only_present_slots` (with `fs:false`, the cmdline contains no `virtio_mmio.device=` entries for slots 0 and 1). In `lifecycle.rs`: `run_exit_code_maps_session_outcome` as a pure function `exit_code_for(&VmExit) -> i32` with the table from Global Constraints (7 → 7, signal 9 → 137, none → 0, VcpuError → 1, AuditFailed → 3).
- [ ] **Step 2: Run** `cargo test -p boxcar-vmm slots cmdline_size exit_code` and confirm the expected compile failures.
- [ ] **Step 3: Implement** `slots.rs`, `SlotAllocator::reserve`, the `DeviceSet` plumbing through `VmConfig` (`net: Option<NetConfig>` and `vsock: Option<VsockConfig>` are added by Tasks 9 and 10; this task adds `DeviceSet` derived from `fs_shares.is_empty()` only), `VmExit::GuestReset { session: None }`, and `exit_code_for` used by `run.rs`.
- [ ] **Step 4: Run** `cargo test -p boxcar-vmm`, then the gated `boot_hello` and `boot_console` tests with the env vars (`--no-fs` boot must still work and the two-share boot must still probe slots 0 and 1).
- [ ] **Step 5: Commit** `vmm: fixed slot table and session outcome in VmExit`.

**Verify:** `cargo test -p boxcar-vmm` green; gated boots green; `grep -n '0xC000_2000' crates/boxcar-vmm/src/devices/slots.rs` shows the net slot.

---

### Task 2: SMP bring-up

**Files:**
- Modify: `crates/boxcar-vmm/src/vcpu.rs` (AP start), `crates/boxcar-vmm/src/arch/x86_64/cpuid.rs` (if a topology bit is wrong under SMP), `crates/boxcar/src/cmd/run.rs` (`--vcpus` default stays 1)
- Test: `crates/boxcar-vmm/tests/boot_smp.rs` (gated)

**Interfaces:**
- Consumes: `patch_cpuid(cpuid, vcpu_id, num_cpus)`, the MPTable writer, `VcpuSet::spawn`, the kick (M1 Tasks 8 and 9).
- Produces: nothing new; `--vcpus N` works for N in 1..=max.

- [ ] **Step 1: Write the failing gated test** `boot_smp.rs`: boot with `vcpus = 4` and `boxcar.cmd = ["/bin/sh","-c","nproc; grep -c ^processor /proc/cpuinfo"]` over the Alpine rootfs; assert the console log contains lines `4` twice. Second test: boot with `vcpus = 2` and `["/bin/sh","-c","yes > /dev/null & yes > /dev/null & sleep 30"]`, call `VmmHandle::request_stop(StopReason::Control)` after 2 s, and assert `run()` returns within 1 s of the request (measure with `Instant`).
- [ ] **Step 2: Run** with the env vars; confirm failure (APs do not come up, or stop takes too long) or success. If it already passes, keep the test and note it in the report.
- [ ] **Step 3: Fix** what fails: APs start by calling `run()` and block in KVM until the BSP's INIT/SIPI (the in-kernel LAPIC handles this; if the AP thread returns `Hlt` or `Shutdown` immediately, inspect the MPTable CPU entries and the per-vCPU `patch_cpuid` apic ids). Make sure the kick reaches an AP blocked in `KVM_RUN` before SIPI (it does through `immediate_exit` plus the signal; verify).
- [ ] **Step 4: Run** the gated tests again and the KVM-free suite.
- [ ] **Step 5: Commit** `vmm: SMP bring-up with per-vCPU topology`.

**Verify:** `nproc` prints 4 in the guest; stop under load completes within 1 s.

---

### Task 3: Control protocol v1 types and server (hello, status, stop), `boxcar status/stop`, `--ready-fd`

**Files:**
- Create: `crates/boxcar-proto/src/control.rs`, `crates/boxcar-vmm/src/control/{mod,server,conn,ops,peercred}.rs`, `crates/boxcar/src/client.rs`, `crates/boxcar/src/cmd/{status,stop}.rs`
- Modify: `crates/boxcar-proto/src/lib.rs`, `crates/boxcar-vmm/src/{lib,vmm,lifecycle}.rs`, `crates/boxcar/src/{cli,main}.rs`, `crates/boxcar/src/cmd/{mod,run}.rs`
- Test: `crates/boxcar-proto/src/control.rs` unit tests, `crates/boxcar-vmm/src/control/server.rs` unit tests (KVM-free, over a real Unix socket), `crates/boxcar/tests/control_cli.rs`

**Interfaces:**
```rust
// boxcar-proto/src/control.rs
pub const PROTOCOL: &str = "boxcar.control"; pub const VERSION: u32 = 1; pub const MAX_LINE: usize = 1 << 20;
#[derive(Serialize, Deserialize)] pub struct Request { pub v: u32, pub id: u64, pub op: String, #[serde(flatten)] pub params: serde_json::Value }
pub struct Response { pub v: u32, pub id: u64, pub ok: bool, #[serde(skip_serializing_if = "Option::is_none")] pub result: Option<Value>, #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<ErrorBody> }
pub struct ErrorBody { pub code: ErrorCode, pub message: String }
pub enum ErrorCode { BadRequest, UnsupportedVersion, UnknownOp, InvalidState, NotFound, Busy, RateLimited, Internal }   // snake_case
pub struct Hello { pub v: u32, pub event: String /* "hello" */, pub protocol: String, pub versions: Vec<u32>, pub server: String, pub session_id: String, pub capabilities: Vec<String> }
pub struct Status { pub state: VmState /* booting|running|stopping|stopped */, pub session_id: String, pub pid: u32, pub uptime_ms: u64, pub vcpus: u8, pub mem_mib: u64, pub guest: GuestStatus { init_ready: bool, session_pid: Option<u32>, exit: Option<SessionOutcome> }, pub audit: AuditStatus { next_seq: u64, failed: bool }, pub devices: Vec<String> }
pub struct StopParams { pub mode: StopMode /* graceful|force */, pub timeout_ms: Option<u64> }
pub fn parse_line(line: &[u8]) -> Result<Request, ErrorCode>;   // enforces MAX_LINE, v == 1, UTF-8, required fields

// boxcar-vmm/src/control/server.rs
pub struct ControlServer { .. }
impl ControlServer { pub fn bind(state_dir: &Path, handle: VmmHandle, ops: Arc<dyn Ops>) -> io::Result<(ControlServer, PathBuf)>; /* creates <state>/control.sock mode 0600 in a 0700 dir; spawns the accept thread */ pub fn shutdown(self); }
pub trait Ops: Send + Sync { fn status(&self) -> Status; fn stop(&self, p: StopParams) -> Result<Value, ErrorBody>; fn dispatch(&self, conn: &mut ConnCtx, req: &Request) -> Result<Value, ErrorBody>; /* later tasks add pty/audit/policy ops here */ }
pub struct ConnCtx { pub peer_pid: u32, pub peer_uid: u32, pub raw_upgrade: Option<RawUpgrade> /* Task 12 */ }
// peercred.rs: pub fn peer_cred(stream: &UnixStream) -> io::Result<(u32 /*pid*/, u32 /*uid*/, u32 /*gid*/)> via libc::getsockopt(SO_PEERCRED)
// Per connection: a thread with a BufReader; a line over MAX_LINE → respond bad_request and close; more than 100 requests in any 1 s window → rate_limited; peer uid != getuid() → close immediately and audit `control.connect{verdict:"deny"}`.
// `--ready-fd N`: after bind, write `{"ready":true,"control":"<path>","session_id":"<id>"}\n` to fd N and close it.
// boxcar status [--control PATH | SESSION_ID]: prints the Status as JSON (`--json`) or a short table. boxcar stop [--force] [--timeout-ms N] [--control PATH | SESSION_ID]: sends stop, waits for the `state` event `stopped` or the socket closing.
// Session discovery: `<runtime_dir>/boxcar/<session_id>/control.sock`; `SESSION_ID` may be a unique prefix.
```

- [ ] **Step 1: Write the failing tests.** proto: `parse_line_rejects_oversize_bad_version_and_missing_fields`, `error_codes_serialize_snake_case`, `hello_round_trips`. server (KVM-free, using a fake `Ops` and a tempdir state dir): `hello_is_sent_first`, `status_and_stop_dispatch`, `unknown_op_and_bad_json_produce_errors_without_closing`, `oversized_lines_and_floods_are_refused` (a 2 MiB line → `bad_request` then EOF; 150 requests in a burst → at least one `rate_limited`), `a_peer_with_another_uid_is_refused` (simulate by injecting the peer uid through a test hook on `ConnCtx`), `socket_and_dir_modes_are_0600_and_0700_under_umask_0`. CLI: `status_and_stop_against_a_fake_server` (spawn a tiny server in the test).
- [ ] **Step 2: Run** and confirm the expected failures.
- [ ] **Step 3: Implement** types, server, peercred, ops wiring into `Vmm` (`Vmm::new` binds the server after devices, before vCPUs start; `VmmHandle` exposes `status()` and `request_stop`), `--ready-fd`, the CLI commands and client.
- [ ] **Step 4: Run** `cargo test -p boxcar-proto -p boxcar-vmm -p boxcar`; then a KVM check: `boxcar run ... --ready-fd 3 3>ready.json -- /bin/sh -c 'sleep 30'` in the background, `boxcar status $(jq -r .session_id ready.json)` shows `running`, `boxcar stop <id>` ends the VM with exit 0.
- [ ] **Step 5: Commit** in two steps: `proto: control protocol v1 types` and `vmm, cli: control server with status and stop`.

**Verify:** `socat - UNIX-CONNECT:$S` receives the hello line first and answers a status request; `boxcar stop` stops a running VM.

---

### Task 4: Decoupled console writer and an always-reachable escape

**Files:**
- Create: `crates/boxcar-vmm/src/console.rs`
- Modify: `crates/boxcar-vmm/src/devices/legacy.rs`, `crates/boxcar-vmm/src/stdin.rs`, `crates/boxcar-vmm/src/lifecycle.rs`
- Test: `crates/boxcar-vmm/src/console.rs` unit tests, `crates/boxcar-vmm/src/stdin.rs` unit tests

**Interfaces:**
```rust
pub struct ConsoleWriter { .. }   // a bounded ring (256 KiB) drained by one thread "console" to the ConsoleOut target
impl ConsoleWriter { pub fn spawn(out: ConsoleOut) -> io::Result<(ConsoleSink, ConsoleWriter)>; pub fn flush_and_join(self, deadline: Duration) -> ConsoleStats { dropped_bytes: u64 }; }
#[derive(Clone)] pub struct ConsoleSink { .. }  // impl Write: never blocks; on overflow drops the oldest bytes and counts them; `vm_superio::Serial` writes into this
// stdin.rs: the escape detector runs on every byte read from stdin BEFORE the FIFO-space check; when the FIFO is full the subscriber keeps reading stdin into a 4 KiB holding buffer (dropping on overflow with a count) so Ctrl-] Ctrl-] always stops the VM.
```

- [ ] **Step 1: Write the failing tests.** `console_sink_never_blocks_when_the_target_stalls` (a `Write` target that blocks on a `Mutex` held by the test; 1 MiB written into the sink returns promptly; after release the writer thread drains what fits and `dropped_bytes > 0`), `flush_and_join_delivers_everything_when_the_target_keeps_up`, `escape_is_detected_while_the_fifo_is_full` (feed the stdin subscriber a full FIFO state and the bytes `\x1d\x1d` within one second; assert the stop request fires).
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement**; the serial device's output goes through `ConsoleSink`; the stop sequence calls `flush_and_join(2 s)` after device close and before `vmm.stop`, recording `dropped_bytes` in the `vmm.stop` payload (`data.console_dropped_bytes`, additive).
- [ ] **Step 4: Run** `cargo test -p boxcar-vmm` and the gated `boot_console` test; then a manual check: `boxcar run ... -- yes | head -c 100000000` with stdout piped to `sleep 60` (a stalled reader) and `boxcar stop <id>` from another terminal must still stop the VM within 3 s.
- [ ] **Step 5: Commit** `vmm: non-blocking console writer; escape works under a full FIFO`.

**Verify:** the stalled-reader check stops within 3 s; `vmm.stop` carries `console_dropped_bytes`.

---

### Task 5: `boxcar-net` wire layer: frames, ARP, DHCP, ICMP to the gateway

**Files:**
- Create: `crates/boxcar-net/Cargo.toml`, `crates/boxcar-net/src/{lib,config,stack,frame,arp,dhcp,icmp,audit}.rs`
- Modify: root `Cargo.toml` (pins), `NOTICE` (if any code is ported)
- Test: `crates/boxcar-net/tests/wire.rs`

**Interfaces:**
```rust
pub struct NetConfig { pub guest_ip: Ipv4Addr /*10.0.2.15*/, pub gateway: Ipv4Addr /*10.0.2.2*/, pub netmask: u8 /*24*/, pub guest_mac: [u8;6], pub gateway_mac: [u8;6], pub hostname: String, pub dns_upstreams: Vec<SocketAddr> /* from /etc/resolv.conf, fallback 1.1.1.1:53 */ }
pub struct NetStack { .. }
impl NetStack { pub fn new(cfg: NetConfig, sink: AuditSink, policy: Arc<ArcSwap<Policy>> /* Task 6; a placeholder allow-all until then */) -> Self;
    pub fn push_guest_frame(&mut self, frame: &[u8]);            // one Ethernet frame from the guest
    pub fn pop_host_frame(&mut self) -> Option<Vec<u8>>;         // next frame for the guest, if any
    pub fn poll(&mut self, now: Instant) -> PollOutcome { next_deadline: Option<Instant>, fd_changes: Vec<FdChange> };
    pub fn on_host_fd_event(&mut self, token: u64, readable: bool, writable: bool);  // Task 7+
}
// frame.rs: pub enum Dispatch { Arp, Dhcp, Dns, Udp, Icmp, TcpSyn, Tcp, Ipv6, Other } pub fn classify(frame: &[u8]) -> Dispatch   (bounds-checked; proptest-fuzzed)
// arp.rs: answers who-has for the gateway and proxy-ARPs for every other address in the /24 except the guest's own, replying with gateway_mac; passes the guest's ARP to smoltcp too so it learns the guest MAC
// dhcp.rs: DISCOVER→OFFER and REQUEST→ACK with a static lease (yiaddr guest_ip, router/dns gateway, mask /24, lease 86400, hostname) built with smoltcp::wire::DhcpRepr; audit `net.dhcp{op, yiaddr}`
// icmp.rs: echo to the gateway answered locally; all other ICMP dropped with `net.drop{reason:"icmp"}` (the host has no unprivileged ICMP here)
// audit.rs: pub fn emit(sink: &AuditSink, payload: Payload) / try_emit for droppable (`net.drop`)
// boxcar-proto gains Payload variants NetDhcp, NetDns, NetConnect, NetTls, NetClose, NetDrop, NetUdp with the structs: NetDhcp{op, yiaddr}; NetDns{txid, qname, qtype, rcode, answers: Vec<String>, verdict, rule}; NetConnect{flow, proto, src: SocketAddrV4, dst: SocketAddrV4, names: Vec<String>, verdict, rule}; NetTls{flow, sni, alpn: Vec<String>}; NetClose{flow, tx: u64, rx: u64, dur_ms: u64, reason}; NetDrop{reason, count: u64}; NetUdp{flow, src, dst, verdict}.
```

- [ ] **Step 1: Write the failing tests** in `tests/wire.rs` with hand-built frames via `smoltcp::wire`: `dhcp_discover_gets_an_offer_for_the_guest_ip` (yiaddr 10.0.2.15, router 10.0.2.2), `dhcp_request_gets_an_ack`, `arp_for_the_gateway_and_for_any_other_host_is_answered_with_the_gateway_mac`, `icmp_echo_to_the_gateway_is_answered_and_to_others_is_dropped_with_an_event`, `ipv6_frames_are_dropped_with_an_event`, and a proptest `classify_never_panics_on_arbitrary_bytes`.
- [ ] **Step 2: Run** `cargo test -p boxcar-net` and confirm the expected failures.
- [ ] **Step 3: Implement** the crate with smoltcp configured as a `Device` over two `VecDeque<Vec<u8>>` (guest→stack, stack→guest), `Interface` with `set_any_ip(true)` and a default route to the gateway (the interface's own address), and the dispatcher in front of it. Add the proto payloads with their wire-table test rows.
- [ ] **Step 4: Run** `cargo test -p boxcar-net -p boxcar-proto`, clippy, fmt, deny.
- [ ] **Step 5: Commit** `net: wire layer with ARP, DHCP, and gateway ICMP`.

**Verify:** all wire tests green; `cargo deny check` accepts smoltcp's 0BSD license (add it to the allowlist in this task if missing).

---

### Task 6: DNS forwarder with a bounded cache, and policy v1

**Files:**
- Create: `crates/boxcar-net/src/dns/{mod,parse,forwarder,cache}.rs`, `crates/boxcar-net/src/policy.rs`
- Modify: `crates/boxcar-net/src/{stack,frame}.rs`
- Test: `crates/boxcar-net/tests/dns.rs`, `crates/boxcar-net/src/policy.rs` unit tests

**Interfaces:**
```rust
// dns/parse.rs: pub struct Question { pub name: String, pub qtype: u16 } pub fn parse_query(payload: &[u8]) -> Result<(u16 /*txid*/, Question), DnsError>; pub fn parse_answers(payload: &[u8]) -> Result<Vec<(String, Ipv4Addr, u32 /*ttl*/)>, DnsError>; pub fn strip_aaaa(payload: &[u8]) -> Vec<u8>   — all bounds-checked, compression pointers limited to 64 hops, proptest-fuzzed
// dns/forwarder.rs: one non-blocking UDP socket to the upstream; txid remapping; 5 s timeout producing SERVFAIL back to the guest; at most 256 in flight
// dns/cache.rs: pub struct DnsCache { .. } with `insert(ip, name, ttl)`, `names_for(ip) -> Vec<String>`, bounded to 4096 entries, LRU eviction, TTL expiry
// policy.rs:
pub struct Policy { pub default: Verdict, pub rules: Vec<Rule> }
pub enum Rule { Domain { pattern: String /* "example.com" or "*.example.com" */, port: Option<u16> }, Cidr { net: Ipv4Net, port: Option<u16> } }
pub enum Verdict { Allow, Deny }
impl Policy { pub fn parse(lines: &[String]) -> Result<Policy, PolicyError>; /* "allow example.com:443", "deny 10.0.0.0/8", "default deny" */
             pub fn egress(&self, dst: SocketAddrV4, names: &[String]) -> (Verdict, Option<String> /* rule text */); /* built-in private-range deny unless an exact-CIDR allow rule exists */
             pub fn dns(&self, qname: &str) -> Verdict; /* a denied name gets NXDOMAIN */ }
```

- [ ] **Step 1: Write the failing tests.** `a_denied_name_gets_nxdomain_and_an_event`, `an_allowed_query_is_forwarded_and_the_answer_cached` (a fake upstream UDP server on 127.0.0.1 in the test), `aaaa_answers_are_stripped`, `dns_cache_is_bounded` (insert 5000, assert ≤ 4096 and the oldest gone), `forwarder_times_out_with_servfail`, policy: `private_ranges_are_denied_unless_exactly_allowed`, `domain_rules_match_exact_and_suffix`, `port_qualified_rules`, proptest `parse_query_never_panics`.
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the crate's tests plus the workspace checks.
- [ ] **Step 5: Commit** `net: DNS forwarder with cache; policy v1`.

**Verify:** `cargo test -p boxcar-net` green; the proptest runs 256 cases by default without panics.

---

### Task 7: TCP relay with deferred SYN, backpressure, SNI/Host gate, and bounded tables

**Files:**
- Create: `crates/boxcar-net/src/tcp/{mod,flow,relay}.rs`, `crates/boxcar-net/src/{sni,http_host,upstream}.rs`
- Modify: `crates/boxcar-net/src/{stack,frame}.rs`
- Test: `crates/boxcar-net/tests/tcp.rs` (a two-interface harness: a second smoltcp `Interface` plays the guest over a frame pipe; a host echo server on 127.0.0.1 is explicitly allowed by the test policy)

**Interfaces:**
```rust
// tcp/flow.rs: pub struct FlowId(u64); pub struct Flow { id, guest: SocketAddrV4, dst: SocketAddrV4, names: Vec<String>, host: Option<TcpStream>, state: FlowState, tx: u64, rx: u64, opened: Instant, gate: Option<GateBuf> }
// FlowTable bounded to 4096 flows (oldest idle evicted with `net.close{reason:"evicted"}`); pending (deferred) SYNs bounded to 256; a connect that has not completed in 10 s → RST to the guest and `net.close{reason:"timeout"}`.
// tcp/relay.rs: deferred SYN: on an allowed SYN, start a non-blocking socket2 connect to dst (or an InternalServices target, Task 10/M4), park the SYN, drop SYN retransmits while pending; on connect success create a smoltcp tcp::Socket (256 KiB buffers, nagle off, ack delay None), listen(dst endpoint), feed the parked SYN through poll_ingress_single; on failure synthesize RST+ACK. Relay with backpressure both ways; FIN→shutdown(Write); RST→abort.
// sni.rs: pub enum Hello { NeedMore, Tls { sni: Option<String>, alpn: Vec<String> }, NotTls } pub fn parse_client_hello(buf: &[u8]) -> Hello   (hand-rolled, bounds-checked, proptest-fuzzed)
// http_host.rs: pub fn parse_host(buf: &[u8]) -> Option<String>  for plain port-80 requests
// Gate: for flows allowed by a Domain rule, buffer the first guest bytes (≤ 16 KiB, ≤ 5 s) without forwarding; parse SNI or Host; if the name does not match the rule (or is absent), RST both sides and emit `net.tls{verdict:"deny"}`/`net.connect{verdict:"deny", rule}`; otherwise emit `net.tls{sni, alpn}` and forward.
// Audit: `net.connect{flow, proto:"tcp", src (guest ip:port), dst, names, verdict, rule}` at SYN; `net.tls` at gate pass; `net.close{flow, tx, rx, dur_ms, reason}`.
```

- [ ] **Step 1: Write the failing tests.** `an_allowed_connection_echoes_10_mib_intact`, `a_denied_destination_gets_rst_and_an_event`, `sni_mismatch_resets_both_sides`, `sni_match_is_logged_and_forwarded`, `plain_http_host_is_gated`, `connect_timeout_resets_the_guest_side` (connect to a black-holed address: use a TCP listener with a full backlog or a non-routable 10.255.255.1 explicitly allowed; assert RST within 11 s and the `timeout` close event; keep this test under 15 s), `flow_table_evicts_oldest_at_cap` (lower the cap to 8 in a test config), `backpressure_when_the_host_stops_reading` (a host peer that never reads; the guest's send window closes; nothing is lost when it resumes), proptest `parse_client_hello_never_panics`, plus a fixture test with a real ClientHello captured from `openssl s_client` (commit the bytes as a test constant).
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p boxcar-net` (the harness runs without KVM).
- [ ] **Step 5: Commit** `net: TCP relay with deferred SYN, SNI gate, bounded tables`.

**Verify:** 10 MiB echo intact; timeout test under 15 s; `net.*` events present in the test sink.

---

### Task 8: UDP NAT relay and IPv6 drop

**Files:**
- Create: `crates/boxcar-net/src/udp.rs`
- Modify: `crates/boxcar-net/src/{stack,frame}.rs`
- Test: `crates/boxcar-net/tests/udp.rs`

**Interfaces:**
```rust
// udp.rs: 5-tuple → connected host UdpSocket; 60 s idle expiry; bounded to 1024 mappings; policy `egress()` applies (UDP flows need an explicit allow rule; DNS to the gateway is handled by Task 6, not here); audit `net.udp{flow, src, dst, verdict}` on first packet and `net.close{reason:"idle"}` on expiry.
```

- [ ] **Step 1: Write the failing tests.** `an_allowed_udp_flow_round_trips_to_a_local_echo`, `default_deny_drops_udp_with_an_event`, `idle_mappings_expire` (inject time).
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the crate's tests.
- [ ] **Step 5: Commit** `net: UDP NAT relay`.

**Verify:** `cargo test -p boxcar-net` green.

---

### Task 9: virtio-net device, the net thread, VMM wiring, and the first guest download

**Files:**
- Create: `crates/boxcar-net/src/device.rs`, `crates/boxcar-vmm/src/devices/net.rs`
- Modify: `crates/boxcar-vmm/src/{vmm,devices/mod}.rs`, `crates/boxcar/src/cmd/run.rs` (`--net`, `--allow RULE` repeatable, `--policy-file PATH`, `--dns UPSTREAM`), `crates/boxcar-init/src/mounts.rs` (write `/run/boxcar/resolv.conf` with `nameserver 10.0.2.2` and bind-mount it over `/etc/resolv.conf`)
- Test: `crates/boxcar-net/src/device.rs` unit tests (mock queues), `crates/boxcar-vmm/tests/boot_net.rs` (gated)

**Interfaces:**
```rust
// device.rs: pub struct VirtioNet implements boxcar_virtio::VirtioDevice: type 1; queues rx=0 tx=1 size 256; features VERSION_1 | EVENT_IDX | NET_F_MAC; config mac[6]; every frame carries a 12-byte virtio_net_hdr_v1 (zeroed on RX, num_buffers 1; skipped on TX).
// activate spawns the "net" thread: an EventManager over the rx/tx queue eventfds, the kill eventfd, a timerfd armed from NetStack::poll().next_deadline, and the host fds NetStack asks for through FdChange { token, fd, interest }. TX: drain the tx queue → push_guest_frame. RX: pop_host_frame into free rx chains; if none are free, keep a bounded pending queue (1024 frames) and retry when the rx ioeventfd fires (enable_notification on the rx queue).
// VMM: slot 2 from the table; cmdline gains `ip=10.0.2.15::10.0.2.2:255.255.255.0:boxcar:eth0:off:10.0.2.2`; `VmConfig.net: Option<NetConfig>` and `policy: Arc<ArcSwap<Policy>>` shared with the control server (Task 13).
// CLI: `--net` enables the device (default on when shares are present; `--no-net` disables); `--allow RULE` adds allow rules; `--policy-file` reads one rule per line; `default deny` unless the file says otherwise.
```

- [ ] **Step 1: Write the failing tests.** Unit: `a_tx_chain_reaches_the_stack`, `a_stack_frame_lands_in_an_rx_chain_with_the_header`, `rx_without_free_buffers_is_queued_then_delivered`. Gated `boot_net.rs`: boot Alpine with `--allow example.com` and the command `["/bin/sh","-c","ip -4 addr show eth0; wget -qO- http://example.com | head -c 100; wget -qO- https://blocked.example 2>&1; echo DONE"]`; assert the console shows `10.0.2.15`, a response from example.com, a failure for blocked.example, and `DONE`; assert the session log has `net.dhcp`, `net.dns` for example.com, `net.connect{verdict:"allow"}` to port 80, and `net.connect{verdict:"deny"}` for blocked.example (or `net.dns{verdict:"deny"}` if the name is denied at DNS; the policy allows only example.com so the DNS for blocked.example should be NXDOMAIN — assert that).
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement** the device, thread, wiring, CLI, and the init resolv.conf change; rebuild the initramfs.
- [ ] **Step 4: Run** the unit tests, then the gated test with the env vars (network access from this machine is required; skip with a reason if `BOXCAR_TEST_NET=0`).
- [ ] **Step 5: Commit** in two steps: `net: virtio-net device and net thread` and `vmm, cli, init: wire the network with policy flags`.

**Verify:** the gated test passes; `boxcar run --allow example.com -- wget -qO- http://example.com` prints the page.

---

### Task 10: `boxcar-vsock`: the Cloud Hypervisor port, the device, internal services, and the privileged-port rule

**Files:**
- Create: `crates/boxcar-vsock/Cargo.toml`, `crates/boxcar-vsock/src/{lib,csm/{mod,connection,txbuf},unix/{mod,muxer,muxer_killq,muxer_rxq},packet_ext,device,services}.rs`, `crates/boxcar-vmm/src/devices/vsock.rs`
- Modify: root `Cargo.toml`, `NOTICE`, `crates/boxcar-vmm/src/{vmm,devices/mod}.rs`, `crates/boxcar/src/cmd/run.rs` (`--vsock-allow PORT` repeatable)
- Test: ported Cloud Hypervisor unit tests over plain buffers, `crates/boxcar-vsock/tests/muxer.rs`, `crates/boxcar-vmm/tests/boot_vsock.rs` (gated)

**Interfaces:**
```rust
// Port from cloud-hypervisor virtio-devices/src/vsock/{mod.rs, csm/*, unix/*} at a pinned commit (record it in each header and NOTICE; keep Intel/Amazon Apache-2.0 and Chromium BSD-3 headers). Drop packet.rs: use virtio_vsock::packet::VsockPacket<'_, B> (0.11) with packet_ext.rs adapting data slices to vm-memory 0.17 (VolatileSlice via ReadVolatile/WriteVolatile).
pub trait InternalServices: Send + Sync { fn connect(&self, port: u32, meta: ConnMeta { guest_port: u32 }) -> Option<UnixStream>; }   // tried first for guest→host; the service gets one end of a UnixStream::pair
pub struct VsockConfig { pub guest_cid: u64 /* 3 */, pub uds_path: PathBuf /* <state>/vsock.sock */, pub allow_ports: Vec<u32> }
pub struct VirtioVsock implements VirtioDevice: type 19; queues rx=0 tx=1 evt=2 size 256; config guest_cid u64 LE.
// Rules: internal ports (1024, 1025, 1026) accept only a guest source port < 1024 and only the first connection per port (a later one gets RST and `vsock.connect{verdict:"deny", reason:"duplicate"|"unprivileged"}`); other ports → `<uds>_<port>` if allowlisted else RST + `vsock.connect{verdict:"deny", reason:"port"}`; host→guest CONNECT <port> on <uds> as Firecracker.
// Audit: `vsock.connect{port, dir, peer, src_port, verdict}` and `vsock.close{port, dir, tx, rx}`.
// VMM: slot 3; `VmConfig.vsock: Option<VsockConfig>`; the ServiceRegistry (boxcar-vmm/src/services.rs) implements InternalServices and registers the guest control channel (Task 11) and the PTY hub (Task 12).
```

- [ ] **Step 1: Port the Cloud Hypervisor unit tests first** (csm connection state machine, txbuf, muxer rxq/killq) adapted to `VsockPacket::new(&mut hdr, Some(&mut data))` over plain buffers; add `internal_ports_accept_only_the_first_privileged_connection` and `an_allowlisted_port_lands_on_the_suffixed_socket` in `tests/muxer.rs` (UDS pairs, no guest memory). Run: expected to fail to compile.
- [ ] **Step 2: Port and implement** the crate, the device, and the VMM wiring.
- [ ] **Step 3: Gated test `boot_vsock.rs`:** boot Alpine with `--vsock-allow 5000`, a host listener on `<state>/vsock.sock_5000` in the test, and the guest command `["/bin/sh","-c","echo ping | socat - VSOCK-CONNECT:2:5000"]` (Alpine needs `socat`: the test rootfs lacks it; use `/bin/sh` with `/dev/vsock`? Not available. Instead the test uses `boxcar-init`'s own control connection in Task 11; for THIS task the gated check is host→guest: the test sends `CONNECT 1024\n` on `<state>/vsock.sock` and asserts `OK 1024` is NOT returned because nothing listens in the guest yet (RST), and that an unprivileged guest connect is impossible to script without socat; so assert the device probes (dmesg shows `vmw_vsock_virtio_transport`) and the muxer socket exists with mode 0600). Keep the test honest about what it proves.
- [ ] **Step 4: Run** everything; commit `vsock: Cloud Hypervisor port with internal services and the privileged-port rule`.

**Verify:** ported tests green; the guest kernel probes the vsock device; `<state>/vsock.sock` exists with mode 0600.

---

### Task 11: Guest control channel and init v2: PTY session, relay, exit report, graceful shutdown

**Files:**
- Create: `crates/boxcar-proto/src/guest.rs`, `crates/boxcar-vmm/src/{guest_ctl,services}.rs`, `crates/boxcar-init/src/{vsock,ctl,pty}.rs`
- Modify: `crates/boxcar-init/src/{main,session,reaper,shutdown}.rs`, `crates/boxcar-vmm/src/{vmm,lifecycle}.rs`, `crates/boxcar/src/cmd/run.rs`, `crates/boxcar-init/Cargo.toml` (nix features `socket`, `term`, `pty`)
- Test: `crates/boxcar-proto/src/guest.rs` unit tests, `crates/boxcar-vmm/src/guest_ctl.rs` unit tests (over UnixStream pairs), `crates/boxcar-vmm/tests/boot_session.rs` (gated)

**Interfaces:**
```rust
// boxcar-proto/src/guest.rs: #[serde(tag = "t")] enum GuestMsg { Hello{init_version, guest_mono_ns, guest_real_ns}, SessionStarted{pid}, SessionExited{code: Option<i32>, signal: Option<i32>}, Pong{id, guest_mono_ns}, Log{level, msg} }  and  enum HostMsg { Config{argv, env: Vec<(String,String)>, cwd, uid, gid, hostname, term, rows, cols, sysctls: Vec<(String,String)>}, Resize{rows, cols}, Signal{sig}, Shutdown{grace_ms}, Ping{id} }; MAX_LINE 64 KiB; parse helpers with size enforcement.
// init: mode `vsock` (set by boxcar run when the vsock device is present; `console` stays for --no-vsock): connect AF_VSOCK to (2, 1024) binding source port 1023 as root, send Hello, receive Config; connect (2, 1025) from source port 1022 and send the pty header line; openpty; child: setsid-free as in M1 (init keeps the tty discipline? no: for a PTY the child does setsid + TIOCSCTTY on the slave), dup2 the slave, drop privileges exactly as M1, execve. PID 1 poll loop adds the ctl stream, the PTY master, and the pty stream: master→pty stream and pty stream→master relay with partial writes handled; Resize → TIOCSWINSZ; Signal → kill(session pgid); Shutdown → SIGTERM the session, wait grace_ms, then proceed to the M1 sweep and reboot; on session exit: drain the master until EIO, send SessionExited, then the M1 sweep, sync, reboot. Ping → Pong.
// VMM guest_ctl.rs: the internal service for port 1024: reads GuestMsg lines, sends Config (built from VmConfig: argv from boxcar.cmd or ["/bin/sh","-l"], env, cwd "/workspace", uid/gid, hostname, term "xterm-256color", rows/cols from the attached terminal or 24x80), stores SessionStarted/SessionExited in VmmHandle state (Status.guest), emits `session.start{argv, cwd, uid, gid, pid}` and `session.exit{code, signal}`; the SessionExited outcome lands in VmExit::GuestReset{session}.
// boxcar run: when vsock is present, the cmdline uses `boxcar.mode=vsock` and no longer passes boxcar.cmd/uid/gid (they travel in Config); exit code per the Global Constraints table.
```

- [ ] **Step 1: Write the failing tests.** proto: round trips and size limits. guest_ctl: `hello_then_config_then_session_lifecycle_over_a_socket_pair` (a fake init on the other end). Gated `boot_session.rs`: `-- /bin/sh -c 'exit 7'` → `boxcar run` exits 7; `-- /bin/sh -c 'kill -9 $$'` → exits 137; `session.start` and `session.exit{code:7}` present in the log; a `Shutdown` triggered by `boxcar stop` (graceful) while `sleep 100` runs ends the VM within `grace_ms + 3 s` with `session.exit{signal:15}`.
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement**; rebuild the initramfs.
- [ ] **Step 4: Run** unit and gated tests.
- [ ] **Step 5: Commit** in two steps: `proto, vmm: guest control channel` and `init: vsock mode with a PTY session and exit report`.

**Verify:** exit codes 7 and 137 propagate; graceful stop works.

---

### Task 12: PtyHub, `pty.attach`/`pty.resize`, `boxcar attach`, and interactive `run` through the hub

**Files:**
- Create: `crates/boxcar-vmm/src/pty.rs`, `crates/boxcar/src/cmd/attach.rs`
- Modify: `crates/boxcar-vmm/src/control/{ops,conn}.rs`, `crates/boxcar-vmm/src/services.rs`, `crates/boxcar/src/cmd/run.rs`, `crates/boxcar/src/client.rs`
- Test: `crates/boxcar-vmm/src/pty.rs` unit tests, `crates/boxcar/tests/attach_cli.rs` (against a fake server), `crates/boxcar-vmm/tests/boot_attach.rs` (gated)

**Interfaces:**
```rust
pub struct PtyHub { .. }   // the internal service for port 1025; holds the guest pty stream, a 256 KiB scrollback ring, and clients
pub struct ClientId(u64); pub enum Mode { Rw, Ro }
impl PtyHub { pub fn attach(&self, mode: Mode, replay_bytes: usize) -> (ClientId, Receiver<Bytes> /* bounded 1 MiB backlog */, Sender<Bytes> /* input, Rw only */); pub fn detach(&self, id); pub fn resize(&self, rows, cols) /* forwards HostMsg::Resize via guest_ctl; last writer wins */; }
// Backpressure: when a client's backlog exceeds 1 MiB it is detached and the control connection gets `{"v":1,"event":"pty.detached","reason":"slow"}`; when every client is detached the hub keeps consuming the guest stream into the ring (the guest never blocks on viewers).
// control ops: `pty.attach{session:"main", mode:"rw"|"ro", replay_bytes}` → `{raw:true}` then the connection is raw bytes both ways (RawUpgrade in ConnCtx); `pty.resize{session, rows, cols}` → `{}`.
// boxcar attach [--ro] [--control PATH | SESSION_ID]: raw terminal, two connections (one raw stream, one for resize on SIGWINCH), detach keys ctrl-p ctrl-q. boxcar run (interactive, no `--`): attaches in-process through the same hub and sends the size at start and on SIGWINCH; the serial console goes to `<state>/console.log` by default when vsock is present.
```

- [ ] **Step 1: Write the failing tests.** `replay_then_live_bytes_arrive_in_order`, `a_slow_client_is_detached_and_the_guest_keeps_running`, `input_from_an_ro_client_is_refused`, `resize_is_forwarded_once_per_change`; CLI: `attach_round_trips_bytes_against_a_fake_server`. Gated `boot_attach.rs`: boot `-- /bin/sh -l` in vsock mode with the console to a file, attach via the library API, send `stty size; echo ATTACHED\n`, assert `24 80` and `ATTACHED` come back, resize to 40x120, send `stty size\n`, assert `40 120`, send `exit\n`, assert the VM exits 0.
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** unit, CLI, and gated tests; manual check from two terminals.
- [ ] **Step 5: Commit** `vmm, cli: PTY hub, attach, and interactive run over vsock`.

**Verify:** `boxcar run ... -- /bin/sh -l` is interactive; `boxcar attach <id>` from a second terminal mirrors output and can type.

---

### Task 13: `audit.subscribe` with replay and lag recovery, reader filters, `policy.get/update`, schemas, docs

**Files:**
- Create: `crates/boxcar-audit/src/subscribe.rs`, `crates/boxcar/src/cmd/{events,policy}.rs`, `xtask/src/schema.rs`, `docs/control-protocol.md`, `docs/audit-events.md`
- Modify: `crates/boxcar-audit/src/{writer,reader}.rs`, `crates/boxcar-vmm/src/control/ops.rs`, `crates/boxcar-proto/src/control.rs`, `xtask/src/main.rs`, `proto/schema/`, `proto/testdata/`
- Test: `crates/boxcar-audit/tests/subscribe.rs`, `crates/boxcar-audit/src/reader.rs` unit tests, `crates/boxcar/tests/events_cli.rs`

**Interfaces:**
```rust
// writer.rs gains a publish hook: after chaining and writing a record, broadcast an Arc<Record> to live subscribers through a bounded per-subscriber queue (16k); the writer never blocks on a subscriber.
// subscribe.rs: pub struct Subscription { .. } impl Subscription { pub fn new(dir, from_seq: u64, filter: Filter, live: Receiver<Arc<Record>>) } — replays from the file for seq < S (the seq the writer reported at subscribe time), then drains the live queue; on overflow emits `audit.lagged{resume_seq}` and resumes from the file.
// reader.rs: Filter { kinds: Vec<String> /* prefixes */, pid: Option<u32>, min_score: Option<u8> }; LogReader::records_from(seq); strict duplicate-key rejection on the reader path too (reuse verify's RawLine).
// control ops: `audit.subscribe{from_seq?, types?[prefixes], pid?}` → `{next_seq}` then `audit{sub, rec}` events on that connection until it closes; `policy.get` → `{net:{default, allow[], deny[]}, vsock:{allow_ports[]}}`; `policy.update{net?, vsock?}` → `{policy_version}` and emits `policy.changed{by_pid, version}`.
// CLI: `boxcar events [--from SEQ] [--type PREFIX]... [SESSION_ID]` streams records as JSON lines; `boxcar policy allow RULE` / `deny RULE` / `show`.
// xtask schema: `cargo xtask schema` writes `proto/schema/{control-v1,audit-v1,guest-v1}.json` with schemars and refreshes `proto/testdata/control-v1.jsonl`; CI fails if `git diff --exit-code proto/` after running it.
```

- [ ] **Step 1: Write the failing tests.** `replay_then_live_without_gaps`, `a_lagged_subscriber_gets_resume_seq_and_recovers`, `filters_by_prefix_and_pid`, `reader_rejects_duplicate_keys`, `policy_update_flips_a_live_verdict_and_records_policy_changed` (through the ops with a fake stack policy handle); CLI: `events_streams_from_a_fake_server`.
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement**, generate schemas, write the two docs (every op and every `type` string listed with fields).
- [ ] **Step 4: Run** tests; `cargo xtask schema && git diff --exit-code proto/`.
- [ ] **Step 5: Commit** in two steps: `audit: live subscriptions with replay and lag recovery` and `cli, docs: events and policy commands; schemas`.

**Verify:** `boxcar events --from 0 <id> | head` prints seq 1..; `boxcar policy allow api.github.com:443` changes a subsequent connect's verdict.

---

### Task 14: virtio-fs multiqueue, hash-worker restart, producer timestamps, non-UTF-8 names, and the M1 debt bundle

**Files:**
- Modify: `crates/boxcar-fs/src/{device,audit_fs,hasher,events,path_map}.rs`, `crates/boxcar-proto/src/audit/payloads.rs`, `crates/boxcar-proto/src/ids.rs`, `guest/kernel/build.sh`, `.github/workflows/ci.yml`, `crates/boxcar-audit/src/segment.rs` (export the `sessions` constant), `crates/boxcar/src/cmd/run.rs`
- Test: `crates/boxcar-fs/tests/{virtio_roundtrip,auditfs}.rs`, `docs/perf.md`

**Interfaces:**
- `VirtioFs::new(.., num_request_queues: u16)` with `min(vcpus, 4)` from the VMM; one worker per request queue; hiprio on the first.
- `AuditFs::restart_hashing()` called on re-activation so a mid-session reset does not leave hashing inline.
- `FsClose` gains `ts_release_ns: u64` (CLOCK_REALTIME at release, producer side); every `fs.*` payload with `path` gains `path_b64: Option<String>` (`skip_serializing_if` none) populated when the raw name was not valid UTF-8, with `path` holding the lossy form.
- `SessionId` loses its `Default` impl; `boxcar_audit::SESSIONS_DIR` is the single `"sessions"` constant used by the writer and the CLI's audit-dir check.
- `build.sh`'s `.BTF` check becomes `readelf -S vmlinux | grep -Eq '\] \.BTF +'`.
- CI pins `cargo-deny` to `0.20.2` and action refs to SHAs.

- [ ] **Step 1: Write the failing tests.** `four_request_queues_serve_requests_concurrently` (mock queues), `reactivation_restarts_the_hash_threads` (reset then activate; a close is hashed off-thread again), `fs_close_carries_the_release_time` (within the test's clock bounds), `a_non_utf8_name_gets_path_b64` (create a file named `b"a\xff"` through the decorator; assert `path == "/a\u{fffd}"` and `path_b64 == Some(base64("/a\xff"))`), `session_id_has_no_default` (compile-fail doc test or a static assertion), and the existing suites.
- [ ] **Step 2: Run** and confirm failures.
- [ ] **Step 3: Implement**; measure `tar -xf` of the Alpine tarball and an `npm ci`-sized tree copy inside the guest with 1 and 4 queues; record in `docs/perf.md`.
- [ ] **Step 4: Run** the suites and the gated `boot_console` test.
- [ ] **Step 5: Commit** in two steps: `fs: multiqueue, hash restart, release timestamps, non-UTF-8 names` and `build, proto, audit: M1 debt (BTF grep, CI pins, SessionId default, sessions constant)`.

**Verify:** `docs/perf.md` has the two timings; the non-UTF-8 test passes.

---

### Task 15: M2 gated end-to-end suite, `cargo xtask test-kvm m2`, and docs

**Files:**
- Create: `crates/boxcar/tests/kvm_m2.rs`, `docs/networking.md`
- Modify: `xtask/src/test_kvm.rs`, `README.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml` (document the KVM job gate `vars.HAS_KVM`)

**Requirements:**
- `cargo xtask test-kvm m2` runs the M1 suite plus `kvm_m2.rs` and the gated `boot_{smp,net,vsock,session,attach}.rs` with `--test-threads=1 --nocapture`, exporting `BOXCAR_TEST_NET=1` only when `example.com` resolves from the host.
- `kvm_m2.rs` drives the real binary: (a) `--allow example.com -- wget -qO- http://example.com` exits 0 with the page in the console log and `net.connect{verdict:"allow"}` in the session log; (b) `-- wget -qO- http://blocked.example` fails and the log has a deny; (c) `-- /bin/sh -c 'exit 7'` exits 7; (d) `boxcar status` during a run shows `running` and `boxcar stop` ends it with exit 0 and a `control.stop` record; (e) `boxcar events --type net. <id>` after (a) prints at least the DHCP, DNS, connect, and close records; (f) `boxcar policy allow blocked.example` during a run makes a second wget succeed and records `policy.changed`.
- README: a "Networking and policy" section with `--allow`, `--policy-file`, the built-in private-range deny, and the audit events; an "Attach" section; the exit-code table. CONTRIBUTING: `cargo xtask test-kvm m2`.

- [ ] **Step 1: Write the failing e2e tests** (they skip without the artifacts; with them they fail until the runner exists).
- [ ] **Step 2: Implement** the runner and docs.
- [ ] **Step 3: Run** `cargo xtask test-kvm m2` and paste the output in the report.
- [ ] **Step 4: Commit** `cli, xtask, docs: M2 e2e suite and documentation`.

**Verify:** `cargo xtask test-kvm m2` green on this machine; README sections present.
