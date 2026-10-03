# M3: guest sensor and reconciler

**Goal:** After M3, a session's log carries two rings. Ring 1 is a small eBPF sensor in the guest, started by init from the initramfs before privileges drop, reporting process lineage (exec with argv, fork, exit), connection attempts with the full 4-tuple, `memfd_create`, sampled file opens, and the denials of its own self-protection, over vsock port 1026 with a heartbeat. Ring 0 is unchanged. A reconciler thread on the host consumes the log in sequence order, joins effects to processes and flows to processes, and writes `finding` records back into the same chained log. A `sync` record pairs the guest clock with the host's. `curl` to a blocked host inside the guest yields a finding whose evidence points at records in both rings.

**Architecture:** Three new crates in the roadmap's shape. `boxcar-sensor-common` (`no_std`, `repr(C)` events) is shared by `boxcar-sensor-ebpf` (the programs, built for `bpfel-unknown-none` on a pinned nightly by the userspace crate's `build.rs`, excluded from the workspace) and `boxcar-sensor` (static musl userspace that loads and attaches the programs, drains the ring buffer, frames records and heartbeats to vsock 1026). On the host, `SensorIngest` is one more internal vsock service that validates frames and emits ring 1 submissions to the audit writer; `GuestCtl` turns its ping round trips into `sync` records; `boxcar_audit::reconcile` is a subscriber thread with state, joins, rules and a paused-clock test harness. Findings reach control clients through the existing `audit.subscribe`, which gains `min_score`.

**Tech stack:** Rust 1.96.0 for everything but the eBPF crate; `nightly-2026-06-01` with `rust-src` and `bpf-linker 0.11.1` for the eBPF crate only; `aya 0.14`, `aya-ebpf 0.2.1`, `aya-build 0.2`, `aya-obj 0.3` (xtask); `bpftool` and `bindgen-cli 0.73.2` inside the kernel build container for the bindings; the M2 crates and pins.

**Spec:** `docs/specs/2026-09-29-boxcar-design.md` (sections 3 to 8 are the authority; 13 lists the open questions this plan does not close). Roadmap: `docs/plans/2026-09-30-boxcar-roadmap.md` (Sensor, Reconciler and M3 sections; the record contract under "Cross-cutting contracts"). M2 interfaces this builds on: `docs/plans/2026-10-01-m2-network-vsock-pty-control.md` and `docs/plans/2026-10-02-m2-remaining-work.md`.

## 1. Where things stand

- Repository `/home/nater/go/src/github.com/phenixrizen/boxcar`, branch `m3`, created from `m2` at `412e940`. M2 is PR #2 against `main` (https://github.com/phenixrizen/boxcar/pull/2), CI green, not merged when this was written. When PR #2 merges, rebase or merge `m3` onto `main` before opening M3's PR; do not rewrite commits that are already pushed without asking.
- What M3 can already lean on, with the file that has it:

| Exists | Where |
|---|---|
| `Source::Sensor` and `Source::Reconciler` (no payload maps to them yet); `Ring::Guest`; `Subject{pid,uid,gid}`; `Record.ts_guest_ns` | `crates/boxcar-proto/src/audit.rs` |
| `SENSOR_PORT = 1026` in `INTERNAL_PORTS`, the privileged-source and first-connection rules, `InternalServices::connect(port, ConnMeta) -> Result<UnixStream, Deny>` | `crates/boxcar-vsock/src/services.rs`, `rules.rs` |
| `ServiceRegistry::register(port, Service)`, the ctl (1024) and PTY (1025) registrations | `crates/boxcar-vmm/src/services.rs`, `vmm.rs`, `lifecycle.rs` (`test_handle`) |
| `AuditSink::{emit, try_emit, subscribe}`, `Submission{ring, ts_guest_ns, subject, payload, span, priority}`, `Priority::Critical` (fdatasync), `Subscription::next_timeout`, `Item::Lagged`, `Filter{kinds, pid, min_score}` (the score filter reads `data.score` and already exists) | `crates/boxcar-audit/src/{sink,writer,subscribe,reader}.rs` |
| Guest `hello{guest_mono_ns, guest_real_ns}`, `ping{id}`/`pong{id, guest_mono_ns}` | `crates/boxcar-proto/src/guest.rs`, `crates/boxcar-vmm/src/guest_ctl.rs`, `crates/boxcar-init/src/ctl.rs` |
| Init mounts tracefs, cgroup2 and bpffs (best effort), creates cgroups `/sys/fs/cgroup/system` and `/sys/fs/cgroup/session`, and drops privileges only in the forked session child (`session.rs`, `setup`) | `crates/boxcar-init/src/{mounts,session,main}.rs` |
| Kernel 6.18.54 with `CONFIG_DEBUG_INFO_BTF`, `BPF_SYSCALL`, `BPF_JIT_ALWAYS_ON`, `BPF_LSM`, `BPF_EVENTS`, `KPROBES`, `FTRACE`, `FUNCTION_TRACER`, `DYNAMIC_FTRACE`, `MEMFD_CREATE`, `MODULES=n`, `LSM="landlock,lockdown,yama,bpf"`; `target/guest/vmlinux` keeps its `.BTF` section (`build.sh` fails without it) | `guest/kernel/{boxcar.fragment,build.sh,VERSION}` |
| `cargo xtask {kernel,initramfs,rootfs,schema,test-kvm}`; `test-kvm` takes `m1` and `m2` and rejects `m3` by test | `xtask/src/{main,initramfs,test_kvm,schema}.rs` |
| `boxcar events --from --type --pid`; `boxcar audit verify` | `crates/boxcar/src/cmd/{events,audit}.rs` |

- What does not exist: any `proc.*`, `finding` or `sync` payload; a service on 1026; a guest-side sensor source port; a sensor flag in `SessionConfig` or on the kernel command line; the three sensor crates; `vmlinux.rs`; the reconciler; `xtask gen-vmlinux`, `check-vmlinux`, `sensor`; `test-kvm m3`.
- The development machine on 2026-10-03: toolchains `1.96.0` and `stable` only, musl target installed; `cargo-binstall`, `cargo-nextest`, Docker 29 (daemon reachable) and `readelf` present; **no** `nightly-2026-06-01`, `bpf-linker`, `bpftool`, `bindgen` or `pahole`; `target/guest/vmlinux` has `.BTF` and `.BTF_ids`. **The disk had 1.7 GB free** (the volume is 492 GB; `~/.cache` is 190 GB and Docker holds 18 GB of images plus 8.5 GB of build cache, 7.6 GB of it reclaimable). The nightly toolchain with `rust-src` is about 1.5 GB and the sensor's builds need a few GB more: free space before Task 2, and say in the report what was removed.

## 2. How to work

- Environment: `$HOME/.cargo/bin` on `PATH`; Rust 1.96.0 from `rust-toolchain.toml`; build with `CARGO_INCREMENTAL=0`. KVM is available. Never copy the tree, never build a second target directory, never run `git clean`; if space runs out remove `target/debug/incremental` and `target/doc` first and say so.
- One-time setup for Tasks 2 to 4 (record the versions it installs in the Decisions section): `rustup toolchain install nightly-2026-06-01 --component rust-src`, `cargo binstall --no-confirm bpf-linker@0.11.1`. `bpftool` and `bindgen` run inside the kernel build container, never on the host.
- Guest artifacts live in `target/guest`. Rebuild the initramfs with `cargo xtask initramfs` after any init or sensor change; it now builds `boxcar-sensor` too, which needs the nightly and `bpf-linker` unless `AYA_BUILD_SKIP=1` (then the sensor carries no programs and reports `degraded`; never use that for a gated run).
- Every task ends with all of these clean:
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets --features boxcar-vmm/kvm-tests,boxcar/kvm-tests -- -D warnings`
  - `cargo fmt --all --check`
  - `cargo deny check`
  - `cargo xtask schema` leaving no diff under `proto/`
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
  - from Task 3 on, `cargo xtask sensor` (the eBPF lane: builds the sensor for the guest with the real objects and checks them, section 6)
  - `cargo xtask test-kvm m2` for any task that touches the VMM, vsock, init, the sensor, the audit crate or the CLI; from Task 6 on, `cargo xtask test-kvm m3` too. Run it in the background with its output in a log file; it takes about 25 minutes.
- Tests first: a test fails for the right reason before the code exists and asserts something that breaks when the feature breaks. No `unwrap`, `expect` or `panic!` in non-test code. The eBPF crate defines the `panic_handler` the target requires as an infinite loop; the verifier rejects a program in which it is reachable, so its code has no reachable panic. Nothing logs on a vCPU thread or on the stop path. Audit records are emitted with the blocking `emit` except where this plan says `try_emit`. A guest can never block the VMM on a viewer, and ring 1 can never block ring 0 (section 3).
- Every new file carries `// SPDX-License-Identifier: Apache-2.0` and `// Copyright 2026 The boxcar Authors`, except the eBPF crate's sources, which carry `// SPDX-License-Identifier: MIT OR GPL-2.0` with the same copyright line (section 3), and the generated `vmlinux.rs`, whose header says what generated it from what.
- Commits: `git commit -s`, one logical change each, subjects from this plan verbatim, body ending with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, `Claude-Session: <the executing session's URL>`, then the sign-off. Never commit `target/`; the eBPF crate's own `Cargo.lock` is committed. Do not push or open a PR until section 7 says so.
- Every judgment call goes into the commit message or section 8 (Decisions), appended as work proceeds. Deferred findings are reported at the end, explicitly.

## 3. Binding technical constraints

These are exact and apply to every task.

- **Pins.** Workspace: everything M2 pinned, plus `aya = "0.14"` (`boxcar-sensor`), `aya-build = "0.2"` and `cargo_metadata` at the version `aya-build 0.2` depends on (build-dependencies of `boxcar-sensor`), `aya-obj = "0.3"` (xtask). Eighth crate, outside the workspace: `aya-ebpf = "0.2.1"` with its own `Cargo.lock`. Tools, not dependencies: `nightly-2026-06-01` + `rust-src`, `bpf-linker 0.11.1`, `bindgen-cli 0.73.2`, the container's `bpftool`. No git dependencies anywhere (so no `aya-tool`: the bindings come from `bpftool btf dump file ... format c` piped through `bindgen`, which is what `aya-tool` does), no `[patch]`, `deny.toml` satisfied; a licence added to its allowlist is a recorded decision.
- **Workspace shape.** `crates/boxcar-sensor-common` and `crates/boxcar-sensor` are members like any other; `crates/boxcar-sensor-ebpf` is listed in `[workspace] exclude` so the stable `--workspace` commands never touch it. `boxcar-sensor`'s `build.rs` reads the eBPF crate's metadata by manifest path and calls `aya_build::build_ebpf` with `Toolchain::Custom("nightly-2026-06-01")`; with `AYA_BUILD_SKIP=1` it writes an empty object instead and the sensor reports `degraded{reason:"no_programs"}` at run time. `boxcar-sensor` and `boxcar-init` build for `x86_64-unknown-linux-musl` with `--profile guest`; neither enables `boxcar-proto`'s `hash` feature.
- **eBPF licence.** The eBPF object's `license` section is `"Dual MIT/GPL"` (so GPL-only helpers such as `bpf_d_path` and the LSM hooks load). The eBPF crate is licensed `MIT OR GPL-2.0`, documented in `docs/ebpf-license.md`, and nothing in it is linked into a host binary; the rest of the tree stays Apache-2.0.
- **Hooks and programs** (names are the eBPF function names and the `name` in `proc.sensor_status.programs`):

| Program | Hook | Emits |
|---|---|---|
| `sched_process_exec` | `btf_tracepoint/sched_process_exec(task, old_pid, bprm)` | `ExecEvent`: tid, tgid, ppid, uid, gid, `start_ns` (`task->start_time`), filename from `bprm->filename` (4096 max), argv read in one bounded `bpf_probe_read_user` of `min(arg_end - arg_start, 16384)` bytes from `mm->arg_start`, `argv_truncated` |
| `sched_process_fork` | `btf_tracepoint/sched_process_fork(parent, child)`, only when `child->pid == child->tgid` | `ForkEvent`: parent tid and tgid, child pid, child `start_ns`, uid, gid |
| `sched_process_exit` | `btf_tracepoint/sched_process_exit(task, group_dead)` (the 6.18 signature) | `ExitEvent`: tid, tgid, `exit_code` (`task->exit_code`), `group_dead`, `start_ns` |
| `socket_connect` | `lsm/socket_connect(sock, address, addrlen)`, returns 0 in M3 | `ConnectAttempt`: tid, tgid, family, protocol, destination and port (AF_INET and AF_INET6 parsed, others recorded by family only) |
| `tcp_connect` | `fentry/tcp_connect(sk)` | `TcpConnect`: tid, tgid, source and destination addresses and ports after port selection |
| `file_open` | `lsm.s/file_open(file)` with `bpf_d_path`, sampled 1 in `FILE_OPEN_SAMPLE` (64) per CPU, optional: its absence makes `degraded` but not failure | `FileOpen`: tid, tgid, path (4096), `f_flags`, the sample divisor |
| `memfd_create` | `fentry/__x64_sys_memfd_create(regs)` | `MemfdEvent`: tid, tgid, name (256), flags |
| `bpf_guard` | `lsm/bpf(cmd, attr, size)`: `-EPERM` for every tgid but `SENSOR_TGID`; loaded and attached **last** | `LsmDeny{hook: "bpf", detail: cmd}` |
| `kill_guard` | `lsm/task_kill(p, info, sig, cred)`: `-EPERM` when `p->tgid == SENSOR_TGID` and the caller's tgid is neither `SENSOR_TGID` nor 1 (init) | `LsmDeny{hook: "task_kill", detail: sig}` |

  Every program except the two guards emits only for tasks whose `bpf_get_current_cgroup_id()` equals the global `SESSION_CGROUP`. `SESSION_CGROUP` and `SENSOR_TGID` are `static` globals set by the loader before load (`EbpfLoader::set_global`). Events are `#[repr(C)]` structs in `boxcar-sensor-common` with a leading `kind: u32` tag; a `RingBuf` map of 256 KiB carries them; a per-CPU `Array<u64>` counts `bpf_ringbuf_reserve` failures (the drop counter). `ts_guest_ns` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC, the clock `hello` and `pong` report).
- **Ring 1 wire.** Guest to host on vsock port 1026 (`boxcar.sensor`), from guest source port **1021** (root only), one connection per VM life as the rules already enforce. Framing `[u32 LE len][json]`, `len <= boxcar_proto::sensor::MAX_FRAME = 65536`. The JSON is `SensorFrame { ts_guest_ns: u64, subject: Option<Subject>, type, data }` (the `type`/`data` pair is the audit `Payload`'s own adjacently tagged form). The host accepts only `proc.*` kinds; any other kind, a bad length, or malformed JSON ends the connection (the vsock layer records `vsock.close`) and the ingest emits nothing further. A valid frame becomes `Submission{ring: Guest, ts_guest_ns: Some(..), subject, payload, span: None, priority: Normal}` with the blocking `emit`; `proc.lsm_deny` uses `Priority::Critical`.
- **Ring 1 never blocks ring 0.** The ingest thread, not the vsock thread, reads frames. If the writer's channel is full the ingest thread waits, the vsock stream's buffer fills, the sensor's write blocks, the kernel ring buffer fills and the kernel counts drops, which the next heartbeat reports. No ring 0 producer waits on any of this.
- **Audit record types** (exact `type` strings, additive): ring 1, `Source::Sensor`: `proc.exec{tid, tgid, ppid, uid, gid, filename, argv[], argv_truncated, start_ns, cgroup_id}`, `proc.fork{parent_tid, parent_tgid, child_pid, child_start_ns, uid, gid}`, `proc.exit{tid, tgid, exit_code, group_dead, start_ns}`, `proc.connect_attempt{tid, tgid, family, proto, dst, dst_port}`, `proc.tcp_connect{tid, tgid, src, src_port, dst, dst_port}`, `proc.memfd{tid, tgid, name, flags}`, `proc.file_open{tid, tgid, path, flags, sample}`, `proc.lsm_deny{tid, tgid, hook, detail}`, `proc.heartbeat{uptime_ns, events_emitted, ringbuf_drops, frames_sent}`, `proc.sensor_status{phase: "attached"|"degraded", programs:[{name, attached, error?}], kernel_release, btf_ok, session_cgroup_id, reason?}`. Ring 0: `sync{method: "vsock_rtt", guest_mono_ns, host_mono_ns, offset_ns (i64), rtt_ns}` with `Source::Vmm`; `finding{category, score, rule, summary, evidence:[{seq, ring}], span_id?, low_confidence}` with `Source::Reconciler`. The envelope's `subject.pid` is the thread id in both rings. `argv` holds at most 256 elements and 16 KiB; paths 4096 bytes; `summary` at most 512 bytes. Findings are never sampled; `proc.file_open` is the only sampled ring 1 type.
- **Clock pairing.** `GuestCtl` already pings the guest (`next_ping`, `ping_outstanding`); the interval becomes 10 s if it differs, a ping goes out right after `hello`, and the host notes `CLOCK_MONOTONIC` at send; on `pong` it computes `rtt_ns`, `host_mono_ns = send + rtt/2`, `offset_ns = host_mono_ns - guest_mono_ns`, and emits `sync`. `ts_host_ns` stays the only cross-ring join key; the reconciler uses `sync` only for the `low_confidence` flag (latest `rtt_ns > 2 ms`, or no `sync` for 30 s while ring 1 is alive). `ptp_kvm` is not used in M3 (spec section 13 keeps it open).
- **Init and the sensor.** `boxcar.sensor=0` on the kernel command line turns the sensor off (`boxcar run --no-sensor`; `--no-vsock` implies it). Otherwise, in `vsock` mode, init opens `/boxcar-sensor` (`O_RDONLY | O_CLOEXEC`) **before** `switch_root`, and after `create_cgroups` forks a child into `/sys/fs/cgroup/system` that `fexecve`s it with `--session-cgroup <inode of /sys/fs/cgroup/session>`. The sensor runs as root with its capabilities for the VM's life; it is never on the audited filesystem. Init adds `kernel.unprivileged_bpf_disabled = 1` (off, and not re-enableable) to its default sysctls. The session child keeps dropping every capability as today, so the agent has no CAP_BPF, CAP_PERFMON or CAP_SYS_ADMIN; `bpf()` from it is refused by `bpf_guard` and recorded.
- **Sensor userspace.** One thread, no async runtime (the tree has none and init is a poll loop too): `poll(2)` on the ring buffer's fd with a 1 s timeout; on readiness, drain, convert each event to a `SensorFrame`, write the frame; on timeout or every second, write `proc.heartbeat`. `proc.sensor_status` is written once after attaching (and again if a program detaches, which the sensor notices only by failing). Startup order: connect vsock, read `/sys/kernel/btf/vmlinux` presence (`btf_ok`), load with globals set, attach every program but the guards, attach `kill_guard`, attach `bpf_guard` last, send `sensor_status`. If the object is empty (`AYA_BUILD_SKIP`) or the load fails, the sensor still connects, sends `sensor_status{degraded, reason}` and heartbeats, so silence always means something.
- **Reconciler.** `boxcar_audit::reconcile::Reconciler::spawn(sink: AuditSink, cfg: ReconcileConfig{sensor_expected: bool, clock: Arc<dyn Clock>}) -> ReconcilerHandle` starts thread `reconcile`, which subscribes from `seq` 1 with an empty filter, processes records in order, ignores `finding` records (its own), calls `on_tick(now)` on every `Idle` (1 s) and exits when the subscription ends; `ReconcilerHandle::join(Duration)` is called by `boxcar run` after the VM exits and before the writer closes. Findings are emitted with `emit`, `Priority::Critical` when `score >= 70`. State: `procs: HashMap<(tid, start_ns), Proc>`, `tid_to_tgid: HashMap<u32, (u32, start_ns)>`, `flows` by id and by 4-tuple, `dns: DnsCache` (answers by name and by address, 60 s), `pending_effects` (unattributed ring 0 effects kept 2 s for a late `proc.exec`), `indicators: PathWatch`, `last_ring1_ts`, `last_ring0_effect_ts`, `sensor_phase`, `last_sync`. Joins: effect to process by `subject.pid` through `tid_to_tgid` to a `Proc` whose `[exec_ts - 500 ms, exit_ts + 500 ms]` contains `ts_host_ns`; flow to process by 4-tuple between `net.connect` and `proc.tcp_connect` within 500 ms, else by destination between `net.connect` and `proc.connect_attempt` within 500 ms. Rules and scores in M3:

| Finding | Condition | Score |
|---|---|---|
| `unattributed_effect` | a ring 0 fs or net effect whose tid joins no `Proc` 2 s after it arrived, while the sensor is `attached` | 60 |
| `sensor_silence` | `sensor_expected` and (no `proc.sensor_status` within 5 s of `session.start`, or no heartbeat for 3 s while a ring 0 effect arrived in the last 3 s); once per episode, re-armed by the next heartbeat | 85 |
| `indicator_removal` | `fs.unlink`, `fs.rename` (source) or `fs.setattr` whose `set` carries a size of 0, of a path matching `PathWatch` (`*/.*_history`, `/var/log/**`, `/etc/ld.so.preload`, `/root/.ssh/**`) | 90 |
| `off_book_channel` | `proc.memfd`, or `proc.file_open` under `/dev/shm/` | 75 |
| `network_anomaly` | `net.connect` to an address no `net.dns` answered in the last 60 s (gateway excluded) | 60 |
| `network_anomaly` | `net.tls{sni}` whose name's answers do not include the destination | 65 |
| `network_anomaly` | more than 50 `net.dns` queries in 10 s, or 20 or more with mean label entropy above 3.5 bits | 70 |
| `privilege_probe` | any `proc.lsm_deny` | 80 |
| `policy_denial` | any `net.connect`, `net.dns`, `net.udp` or `vsock.connect` with `verdict: "deny"`, or `fs.denied` | 40 |

  `intent_effect_mismatch` and `orphaned_work` need `tool.*` spans and come with M4; the rule table and the fixture format are built so M4 adds them without reshaping. A rule whose hook the sensor reported missing is skipped; a finding whose join relied on a flow or exec within the widened window, or made while `low_confidence` holds, carries `low_confidence: true` and a score lowered by 20. `summary` names the rule's inputs in words; `evidence` lists every record the rule read, newest last.
- **Control protocol.** `audit.subscribe` gains `min_score?: u8` (applied by the existing `Filter`); the hello's capabilities become `["pty","audit","policy.net","findings"]`. There is no separate `finding` event: a client that wants findings pushed subscribes with `types: ["finding"]`, which the spec's "receives findings as pushed events" means. `status` gains `sensor: {state: "off"|"waiting"|"attached"|"degraded"|"silent", heartbeats: u64, last_heartbeat_ns?: u64}` from the ingest.
- **CLI.** `boxcar run --no-sensor`; `boxcar events --min-score N`; nothing else changes. Exit codes are M2's.
- **Everything M2 fixed stays fixed:** the slot table, guest addresses, policy v1, the vsock admission rules, the control limits and error codes, modes, exit codes, the terminal behaviour.

## 4. Review focus

1. **The agent, as root, calls `bpf()`.** Expected: `-EPERM`, a `proc.lsm_deny{hook:"bpf"}` record with `Priority::Critical`, a `privilege_probe` finding (80), the sensor still attached. Pinned in Task 4's `bpf_from_the_session_is_denied_and_recorded` (KVM) and Task 5's `privilege_probe` fixture.
2. **The agent, as root, kills the sensor.** Expected: `kill_guard` refuses with `-EPERM` and records `proc.lsm_deny{hook:"task_kill"}`; if the sensor nevertheless dies (a kernel compromise), `sensor_silence` (85) within 3 s of the next ring 0 effect. Pinned in Task 4's `the_sensor_cannot_be_killed_by_the_session` (KVM) and Task 5's `sensor_gap` fixture under the paused clock.
3. **An exec storm in the guest.** Expected: the kernel ring buffer drops, `proc.heartbeat.ringbuf_drops` counts them, the vsock thread never waits on the ingest, no ring 0 record is delayed or lost. Pinned in Task 1's `a_flooding_sensor_never_blocks_the_vsock_thread` (a fake sensor on a `UnixStream` pair writing frames faster than a stalled writer takes them).
4. **A guest writes garbage on 1026, or a second client connects.** Expected: the connection is closed and recorded, the VMM does not panic, ring 0 is unaffected; the second connection is refused by the first-connection rule. Pinned in Task 1's `garbage_frames_end_the_connection_quietly` and the existing `internal_ports_accept_only_the_first_privileged_connection`.
5. **Pid reuse.** A tid that exits and is reused inside the join window must not attribute the new process's effects to the old one. Pinned in Task 5's `proptest` over fork/exec/exit/effect sequences (`pid_reuse_never_misattributes`).
6. **A kernel whose BTF drifted.** Expected: `cargo xtask check-vmlinux` fails the build; at run time the sensor says `degraded{btf_ok:false}` and heartbeats, and the reconciler skips the rules that need the missing hooks. Pinned in Task 2's `check_vmlinux_fails_on_a_stale_hash` and Task 4's `a_degraded_sensor_still_heartbeats`.

## 5. File structure

| Path | Responsibility |
|---|---|
| `crates/boxcar-proto/src/audit/payloads.rs`, `audit.rs`, `src/sensor.rs` | `Proc*`, `Sync`, `Finding` payloads with sources and kinds; `SensorFrame`, `MAX_FRAME` |
| `crates/boxcar-vmm/src/sensor_ingest.rs`, `guest_ctl.rs`, `vmm.rs`, `lifecycle.rs`, `control/{ops,audit}.rs` | the 1026 service and its thread, `sync` from ping/pong, registration, `status.sensor`, `min_score`, the capability |
| `crates/boxcar-sensor-common/src/lib.rs` | `no_std` `repr(C)` events, `Kind`, `user` feature with `Pod` |
| `crates/boxcar-sensor-ebpf/{Cargo.toml,Cargo.lock,src/{main,vmlinux,exec,fork,exit,connect,tcp,file_open,memfd,guards}.rs}` | the programs; excluded from the workspace |
| `crates/boxcar-sensor/{build.rs,src/{main,load,drain,frame,heartbeat,status}.rs}` | the guest userspace sensor |
| `crates/boxcar-init/src/{main,sensor,sysctl,vsock}.rs` | holding the sensor fd across `switch_root`, forking it into the `system` cgroup, `boxcar.sensor=`, the sysctl |
| `crates/boxcar-audit/src/reconcile/{mod,state,join,rules,scores,clock,dns,paths}.rs`, `tests/reconcile.rs`, `tests/fixtures/<scenario>/{input,expected}.jsonl` | the reconciler and its goldens |
| `crates/boxcar/src/{cli.rs,cmd/{run,events}.rs}`, `tests/kvm_m3.rs` | `--no-sensor`, `--min-score`, the reconciler's lifetime in `run`, the M3 gated suite |
| `xtask/src/{vmlinux,sensor,initramfs,test_kvm,main}.rs`, `guest/kernel/{Dockerfile,.btf-hash}` | `gen-vmlinux`, `check-vmlinux`, `sensor`, the two-binary initramfs, `test-kvm m3` |
| `docs/{reconciler,ebpf-license,audit-events,control-protocol}.md`, `README.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml` | documentation and the `ebpf` CI job |

---

### Task 1: ring 1 types, the 1026 ingest service, and `sync` records (roadmap M3.1)

Files: `crates/boxcar-proto/src/{audit.rs,audit/payloads.rs,sensor.rs,lib.rs}`, `crates/boxcar-vmm/src/{sensor_ingest.rs,guest_ctl.rs,services.rs,vmm.rs,lifecycle.rs}`, `crates/boxcar-vmm/src/control/ops.rs` (status only), `xtask/src/schema.rs`, `proto/schema/sensor-v1.json`, `proto/testdata/sensor-v1.jsonl`, `docs/audit-events.md`; tests in `crates/boxcar-proto/src/{audit,sensor}.rs`, `crates/boxcar-vmm/src/sensor_ingest.rs`, `crates/boxcar-vmm/tests/boot_vsock.rs` (extend).

- [ ] **Tests.** `every_payload_variant_round_trips_through_a_record` gains one case per new variant and `KINDS` grows to 47 (fix the stale "34" comment); `from_kind` maps `proc.*` to `Sensor`, `sync` to `Vmm`, `finding` to `Reconciler` (replace the tests that assert `None` for `proc.exec` and `finding`). `sensor_frames_have_their_documented_shape_and_limits`: a 65536-byte frame is accepted, 65537 refused, a `fs.open` kind refused, `argv` of 257 elements refused by `check()`. In `sensor_ingest.rs`: `a_valid_frame_becomes_a_ring_1_submission` (ring `Guest`, `ts_guest_ns` carried, subject carried, `Source::Sensor` after the writer), `lsm_denies_are_critical`, `garbage_frames_end_the_connection_quietly`, `a_flooding_sensor_never_blocks_the_vsock_thread` (the fake sensor writes 10,000 frames while the sink's channel is held full; the service's `connect` returned at once and the vsock side's `write` is what blocks). In `guest_ctl.rs`: `ping_pong_becomes_a_sync_record` with a fake guest answering `pong` after a known delay (offset and rtt within tolerance). Gated: `boot_vsock` asserts a `sync` record within 15 s of `hello`.
- [ ] **Code.** Payloads and `SensorFrame` with `check()` (sizes from section 3); `SensorIngest::new(sink) -> (Self, SensorStatus)` with `service() -> Service`, thread `sensor-rx` per connection reading `[len][json]`, `status()` for `status.sensor`; register `SENSOR_PORT` next to the PTY registration in `vmm.rs` and `lifecycle.rs::test_handle`; `GuestCtl` pings on a 10 s timer and emits `sync`; `cargo xtask schema` writes `sensor-v1.json` and the golden frame lines; `docs/audit-events.md` documents the new types and the two rings.
- [ ] **Verify.** The four stable commands, `cargo xtask schema` clean, `cargo xtask test-kvm m2`.
- [ ] **Commit** `proto, vmm: ring 1 ingest on vsock 1026 and sync records`.

### Task 2: sensor event structs, kernel bindings, and the BTF drift check (roadmap M3.2)

Files: `crates/boxcar-sensor-common/{Cargo.toml,src/lib.rs}`, `crates/boxcar-sensor-ebpf/{Cargo.toml,src/vmlinux.rs}` (the generated file only; the crate's programs are Task 3), `xtask/src/{vmlinux.rs,main.rs}`, `guest/kernel/{Dockerfile,.btf-hash}`, `Cargo.toml` (`exclude`, new members, pins), `docs/ebpf-license.md`.

- [ ] **Tests.** `boxcar-sensor-common`: `every_event_is_pod_and_has_a_stable_size` (sizes asserted as constants so a change is a conscious one), `kind_tags_are_unique`. xtask: `check_vmlinux_fails_on_a_stale_hash` (a temp vmlinux whose `.BTF` bytes differ from the recorded hash gives exit 1 naming both hashes), `btf_section_is_found_by_the_elf_reader` (a hand-built ELF64 with a `.BTF` section), `gen_vmlinux_names_the_types_the_programs_need` (the generated file is checked for `task_struct`, `linux_binprm`, `mm_struct`, `sock`, `sockaddr_in`, `sockaddr_in6`, `file`, `path`, `dentry`, `kernel_siginfo`, `cred`, `pt_regs`).
- [ ] **Code.** `boxcar-sensor-common`: `#![no_std]`, `Kind` (`u32` repr), `ExecEvent`, `ForkEvent`, `ExitEvent`, `ConnectAttempt`, `TcpConnect`, `FileOpen`, `MemfdEvent`, `LsmDeny`, each `#[repr(C)]`, the `user` feature adding `unsafe impl aya::Pod`. `cargo xtask gen-vmlinux`: runs the kernel build image (Dockerfile gains `bpftool` and `bindgen-cli 0.73.2`, image rebuilt, digest recorded in `VERSION`) to `bpftool btf dump file /out/vmlinux format c` and `bindgen` with `--use-core --ctypes-prefix core::ffi --no-layout-tests --default-enum-style moduleconsts --with-derive-default` and the allowlist of section 3's types, writes `crates/boxcar-sensor-ebpf/src/vmlinux.rs` with a header naming the kernel version and the BTF hash, and writes `guest/kernel/.btf-hash` (blake3 of the `.BTF` section bytes, read by a 60-line ELF64 section reader in xtask, no new dependency). `cargo xtask check-vmlinux` recomputes the hash of `target/guest/vmlinux` and fails on drift; `cargo xtask kernel` runs it at the end. Workspace `exclude` and the pins. `docs/ebpf-license.md` explains the dual licence and the generated bindings.
- [ ] **Verify.** The stable commands; `cargo xtask gen-vmlinux` twice gives an identical file; `cargo xtask check-vmlinux` exit 0.
- [ ] **Commit** `sensor: event structs, kernel bindings and the BTF drift check`.

### Task 3: the eBPF programs and the eBPF lane (roadmap M3.3)

Files: `crates/boxcar-sensor-ebpf/src/{main,exec,fork,exit,connect,tcp,file_open,memfd,guards}.rs`, `crates/boxcar-sensor/{Cargo.toml,build.rs,src/main.rs}` (the crate shell and the build only; the sensor's behaviour is Task 4), `xtask/src/{sensor.rs,main.rs}`, `.github/workflows/ci.yml` (`ebpf` job), `CONTRIBUTING.md`.

- [ ] **Tests.** xtask `sensor` lane: `the_object_has_every_program_and_the_dual_license` parses the built object with `aya-obj` and asserts the nine program names, their section kinds (`btf_tracepoint`, `lsm`, `lsm.s`, `fentry`), the `RingBuf` and the per-CPU counter maps, the two globals, and the licence string; `an_empty_object_is_what_aya_build_skip_produces`. A `cargo test -p boxcar-sensor` unit test checks that `build.rs`'s skip path writes an empty object and the real path refuses to run without the nightly, with a message naming the `rustup` command.
- [ ] **Code.** The programs of section 3's table, one file each, every map and global in `main.rs`, `license` section `"Dual MIT/GPL"`, no `aya-log`. argv is read into the reserved ring buffer record, never onto the stack; every loop is bounded by a constant; every pointer read uses `bpf_probe_read_kernel` or `bpf_probe_read_user`. `boxcar-sensor/build.rs` as section 3 says. `cargo xtask sensor` builds `boxcar-sensor` for `x86_64-unknown-linux-musl --profile guest` with the real objects and runs the object check. CI: an `ebpf` job on `ubuntu-latest` installing the pinned nightly with `rust-src` (dtolnay/rust-toolchain at its pinned SHA), `cargo-binstall` by its pinned release and `bpf-linker@0.11.1`, then `cargo xtask sensor`; the `check` job sets `AYA_BUILD_SKIP=1` and additionally builds `boxcar-sensor` for musl. CONTRIBUTING gets the setup lines.
- [ ] **Verify.** The stable commands, `cargo xtask sensor` exit 0 (the program count printed is 9), `cargo xtask test-kvm m2` untouched.
- [ ] **Commit** `sensor: eBPF programs and the eBPF build lane`.

### Task 4: the userspace sensor, init, the initramfs, and `--no-sensor` (roadmap M3.4)

Files: `crates/boxcar-sensor/src/{main,load,drain,frame,heartbeat,status}.rs`, `crates/boxcar-init/src/{main,sensor,sysctl,vsock}.rs`, `xtask/src/initramfs.rs`, `crates/boxcar/src/{cli.rs,cmd/run.rs}`, `crates/boxcar-vmm/src/control/ops.rs` (`status.sensor` wiring), `crates/boxcar-vmm/tests/boot_vsock.rs` or a new `boot_sensor.rs`, `crates/boxcar/tests/run_args.rs`.

- [ ] **Tests.** Sensor (host-side unit tests, no kernel): `frames_are_length_prefixed_and_capped`, `a_heartbeat_goes_out_every_second_without_events` (fake clock), `an_exec_event_becomes_proc_exec_with_split_argv_and_truncation` (NUL-separated bytes, 257 elements, 16 KiB cut), `status_lists_every_program_with_its_error`. Init: `the_sensor_fd_is_opened_before_switch_root` (the order of calls on a recording fake), `boxcar_sensor_0_skips_the_sensor`. xtask: the initramfs tests gain the second binary at `/boxcar-sensor` 0755 and nothing else with data. CLI: `no_sensor_without_vsock_is_implied_not_refused`. Gated (`kvm-tests`): `the_sensor_attaches_and_heartbeats` (`proc.sensor_status{attached}` within 5 s of `session.start`, every program `attached`, a heartbeat within 2 s, `btf_ok`), `an_exec_in_the_session_is_reported_with_argv` (`-- /bin/sh -c 'ls -l /'` yields `proc.exec` for `ls` with that argv and `ppid` of the shell), `bpf_from_the_session_is_denied_and_recorded` (a guest command that calls `bpf()`: as the session's uid it gets `EPERM` from the sysctl; in a `boxcar-vmm` gated test that sends its own `SessionConfig` with `uid: 0`, the root session gets `EPERM` from `bpf_guard` and a `proc.lsm_deny{hook:"bpf"}` is recorded; a session cannot become root by itself under `no_new_privs`), `the_sensor_cannot_be_killed_by_the_session` (`kill -9` of the sensor pid from a root session, the same way, fails with `EPERM`, `proc.lsm_deny{hook:"task_kill"}`, heartbeats continue), `a_degraded_sensor_still_heartbeats` (an initramfs built with `AYA_BUILD_SKIP=1` for the test only, kept out of `target/guest`: `sensor_status{degraded, reason:"no_programs"}` then heartbeats), `no_sensor_means_no_ring_1` (`--no-sensor`: no `proc.*` record, `status.sensor.state == "off"`).
- [ ] **Code.** The sensor as section 3 describes (one thread, `poll(2)`, `EbpfLoader::set_global`, attach order with the guards last, `sensor_status`, heartbeats, frames via `boxcar_proto::sensor`). Init: `sensor::open()` before `switch_root`, `sensor::spawn(fd, session_cgroup_inode)` after `create_cgroups` (child joins the `system` cgroup, `fexecve`), source port 1021 is the sensor's own (`vsock.rs` constant), `boxcar.sensor=` parsing, the sysctl. `xtask initramfs` builds `boxcar-sensor` (`--profile guest`, musl) and packs it. `boxcar run --no-sensor` appends `boxcar.sensor=0`; `--no-vsock` does too; `status.sensor` from the ingest. `cargo xtask initramfs` then rebuilds `target/guest/initramfs.cpio`.
- [ ] **Verify.** The stable commands, `cargo xtask sensor`, `cargo xtask initramfs`, `cargo xtask test-kvm m2` (all of M2 still passes with the sensor running).
- [ ] **Commit** `sensor, init, cli: the guest sensor, its start by init, and --no-sensor`.

### Task 5: the reconciler (roadmap M3.5)

Files: `crates/boxcar-audit/src/reconcile/{mod,state,join,rules,scores,clock,dns,paths}.rs`, `crates/boxcar-audit/src/lib.rs`, `crates/boxcar-audit/tests/reconcile.rs`, `crates/boxcar-audit/tests/fixtures/<scenario>/{input,expected}.jsonl`, `crates/boxcar-proto/src/control.rs` (`min_score`), `crates/boxcar-vmm/src/control/{ops,audit}.rs` (capability, filter), `crates/boxcar/src/{cli.rs,cmd/{run,events}.rs}`, `docs/{reconciler,control-protocol}.md`.

- [ ] **Tests.** Golden scenarios, each `input.jsonl` a hand-written or recorded sequence of records and `expected.jsonl` the findings, compared byte for byte and blessed with `BOXCAR_BLESS=1` like `tests/golden.rs` (the repository's existing pattern; no `insta`): `curl_no_dns`, `history_wipe`, `memfd_exec`, `sensor_gap` (paused clock: the finding fires at exactly 3 s after the last heartbeat with an effect inside the window, not before, and once), `sensor_never_attached`, `sni_mismatch`, `dns_entropy_spike`, `privilege_probe`, `policy_denial`, `unattributed_effect`, `late_exec_is_attributed` (the `proc.exec` arrives 300 ms after the `fs.create`; no finding), `no_sensor_expected_no_silence`, `degraded_sensor_skips_hook_rules`, `low_confidence_after_a_slow_sync`. `proptest`: `pid_reuse_never_misattributes` over random fork/exec/exit/effect interleavings with reused tids. Unit: `entropy_of_labels`, `path_watch_matches_the_indicator_set`, `evidence_is_ordered_and_complete`. Control: `audit_subscribe_filters_by_min_score`; CLI: `events_min_score_is_passed_through`; `capabilities_include_findings`.
- [ ] **Code.** `Reconciler::spawn`, `ReconcilerHandle::join`, `Clock` with `SystemClock` and a `ManualClock` for tests, the state, joins and rules of section 3, `Finding` emission with evidence and `low_confidence`, `min_score` end to end, the capability, `boxcar run` starting the reconciler beside the writer with `sensor_expected = vsock && !no_sensor` and joining it (5 s) before closing the writer. `docs/reconciler.md` explains every rule, its score, its inputs and what lowers its confidence; `docs/control-protocol.md` gains `min_score` and `findings`.
- [ ] **Verify.** The stable commands; `cargo xtask test-kvm m2`.
- [ ] **Commit** `audit: reconciler with joins, rules and findings`.

### Task 6: the M3 gated suite, `cargo xtask test-kvm m3`, and documentation

Files: `crates/boxcar/tests/kvm_m3.rs`, `xtask/src/{test_kvm,main}.rs`, `README.md`, `docs/{audit-events,reconciler,networking}.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml` (the `kvm` job runs `m3`).

- [ ] **Tests.** `kvm_m3.rs` with the M2 harness: `a_download_to_a_blocked_address_is_a_joined_finding` (`--net`, default deny, `wget` to the address the host resolves `example.com` to at test time, by address so no `net.dns` precedes it: `net.connect{verdict:"deny"}`, `proc.exec{wget}`, `proc.connect_attempt`, a `policy_denial` finding and a `network_anomaly` finding whose evidence holds a ring 0 and a ring 1 seq, `boxcar audit verify` passing), `an_allowed_download_joins_its_process` (`--allow example.com`: `net.connect{verdict:"allow"}` and `proc.tcp_connect` with the same 4-tuple, no finding), `a_history_wipe_is_a_finding` (`rm ~/.ash_history` after writing it: `indicator_removal` 90), `events_streams_findings_by_min_score` (`boxcar events --type finding --min-score 70`), `status_reports_the_sensor` (`attached`, heartbeats increasing).
- [ ] **Code.** `test-kvm m3` (same packages, `BOXCAR_TEST_NET` as `m2`); the `m3` rejection test becomes acceptance; README gains "The sensor" (what it reports, what it cannot, `--no-sensor`, the two rings in one log) and "Findings" (`boxcar events --type finding`, the categories and scores); docs updated; CI's `kvm` job runs `m3`.
- [ ] **Verify.** Everything in section 2 including `cargo xtask test-kvm m3`, with the run's counts recorded in section 8.
- [ ] **Commit** `cli, xtask, docs: M3 e2e suite and documentation`.

## 6. The eBPF lane

`cargo xtask sensor` is the KVM-free proof that the programs exist and link: it builds `boxcar-sensor` for the guest with the real objects (so it needs the nightly and `bpf-linker`), parses the embedded object with `aya-obj`, and asserts the program names and kinds, the maps, the globals and the licence of section 3. It does not load anything; loading is proved by the gated tests of Task 4. CI runs it in the `ebpf` job; the `check` job builds the sensor with `AYA_BUILD_SKIP=1` so a stable toolchain alone still builds the whole tree.

## 7. Finishing M3

1. All commands in section 2 are clean at the final commit, including `cargo xtask sensor`, `cargo xtask test-kvm m2` and `m3`.
2. A last read of the whole branch against its base for anything that contradicts section 3, with the same checks M2's section 8 made: the type list, sources and rings of every new record; the vsock admission rules untouched; modes; no `unwrap` outside tests; the eBPF crate's licence and the workspace `exclude`; nothing from the eBPF crate linked into a host binary.
3. Then, if asked: push `m3` and open a PR against `main` whose description lists every accepted limitation, including whatever the eBPF verifier forced.

## 8. Decisions (appended while executing this plan)

Made while writing the plan, 2026-10-03:

- **No async runtime in the sensor.** The roadmap says tokio; the tree has no async runtime, init is a `poll(2)` loop, and a static musl binary in the initramfs should stay small. The ring buffer's fd is pollable, so the sensor is one thread on `poll(2)`.
- **The eBPF crate is excluded from the workspace, not just from default members,** so the `--workspace` commands of section 2 keep working on the stable toolchain. `build.rs` reads its metadata by manifest path. Its `Cargo.lock` is committed.
- **No `aya-tool`.** It is not on crates.io and would be a git install; `bpftool` plus `bindgen-cli` in the kernel build container produce the same file reproducibly, and the generator's inputs (kernel version, BTF hash) are in the file's header.
- **Findings reach control clients through `audit.subscribe`,** with `min_score` and the `findings` capability, rather than a second `finding` event type: one delivery path, one outbox, one pacing rule. A finding record is a pushed event.
- **`intent_effect_mismatch` and `orphaned_work` wait for M4,** which brings `tool.*` spans; the roadmap's `phantom_write` and `orphan_after_span` fixtures come with them. `off_book_channel` covers `memfd_create` and `/dev/shm` opens in M3; opens of unlinked inodes are not detectable from ring 0 without inode tracking and are left out.
- **`kill_guard` (`lsm/task_kill`) is added** to the roadmap's program table: the spec names self-protection, and a sensor root can `kill -9` is no corroboration. Init (tgid 1) and the sensor itself may still signal it.
- **Golden fixtures use the repository's bless pattern** (`expected.jsonl`, `BOXCAR_BLESS=1`) instead of `insta`, which would add a dependency for the same check.
- **`ptp_kvm` is not used;** `sync` comes from the ctl channel's ping round trip. The spec's open question about `ptp_kvm` on nested hosts stays open.
- **The sensor binary is separate** (the spec's "two small guest binaries"), held open by init across `switch_root` and started with `fexecve`, so it is never on the audited filesystem and init keeps its three dependencies.
- **Guest source port 1021** is the sensor's; 1023 and 1022 stay init's.
- **`kernel.unprivileged_bpf_disabled = 1`** is set by init as a second layer under the LSM guard; the sensor is privileged and unaffected.

### Task 1

- The `sync` payload's Rust type is `ClockSync`: a type named `Sync` would
  shadow the marker trait wherever the crate's types are glob-imported.
  The wire name stays `sync`.
- The sync thread is started by the VMM (`GuestCtl::start_sync`), not by
  the channel itself, so the channel's unit tests and the PTY hub's keep
  their exact message sequences; it pings only once the config has been
  queued (`config_sent`), never between `hello` and `config`. The first
  ping therefore follows the config within 50 ms; the plan's "right after
  `hello`" is that.
- `status.sensor` lands with this task rather than Task 4: the ingest knows
  the sensor's state as soon as it exists, and a `Status` from an older
  server reads as `off` (`#[serde(default)]`).
- Frame limits beyond the plan's: a `proc.memfd` name 256 bytes (the
  kernel's), a `proc.sensor_status` with at most 32 programs, names 128
  bytes. The 64 KiB frame cap is checked on the declared length before any
  byte of the frame is read; no valid frame reaches it, so the cap is
  tested at the decoder, with the argv and path limits tested on frames.
- The golden `sensor-v1.jsonl` holds the frames' JSON as lines (one per
  `proc.*` type) rather than length-prefixed bytes, so it reads like the
  other golden files; the test re-frames each line.
- The gated `sync` assertion is in `boot_session`'s graceful-stop test,
  whose session lives long enough for the pong; the plan named
  `boot_vsock`, whose console init has no control channel.

### Task 2

- The bindings are generated by the Debian packages of the pinned kernel
  build image, `bpftool` 7.5.0 and `bindgen` 0.71.1, rather than
  `bindgen-cli` 0.73.2 fetched onto the host or into the image: one pinned
  image carries every tool the kernel side needs, and the generated file is
  committed and guarded by the BTF hash either way. The versions are named
  in the file's header.
- The built image's digest is not recorded in `VERSION`: a built image has
  no stable digest to pin; the base image's is pinned there already, and the
  apt versions show in the generated header.
- The image has no rustfmt; `gen-vmlinux` formats the written file with the
  host toolchain's, run from the repository root, so the committed bindings
  are formatted and `#[rustfmt::skip]` on the `mod` keeps them that way.
- `.btf-hash` is the blake3 of the `.BTF` section's bytes, read by a
  60-line ELF64 section reader in xtask (no new dependency), not of the
  whole `vmlinux`: a rebuild that leaves the types alone leaves the hash
  alone.
- `cargo xtask kernel` runs the check only once a hash is recorded; before
  the first `gen-vmlinux` it says to run it, so a fresh clone can build a
  kernel.
- The eBPF crate gets its skeleton here (manifest, its own
  `rust-toolchain.toml` for builds by hand, a `main.rs` with the panic
  handler, the `Dual MIT/GPL` licence section and the `vmlinux` module, and
  its `Cargo.lock`), so the bindings have a home and Task 3 adds programs
  to a crate that already builds for `bpfel-unknown-none`.
- The common crate's `Header` puts `kind` first (the reader looks at it
  before it knows the struct) and lays the rest out so no struct has
  implicit padding; the tests pin every size and the header's offset.
- Setup done on the development machine on 2026-10-03: `rustup toolchain
  install nightly-2026-06-01 --profile minimal --component rust-src`
  (rustc 1.98.0-nightly 2026-05-31) and `cargo binstall bpf-linker@0.11.1`.
  rustup updated itself to 1.29.1 on the way. Disk after: 18 GB free.

### Task 3

- The programs read kernel memory through `bpf_probe_read_kernel` at
  every step rather than dereferencing the BTF pointers directly: the
  verifier accepts either on these program types, and the helper form
  cannot fault on a null parent, mm or socket. The one direct address is
  `&file->f_path` handed to `bpf_d_path`, which must be derived from the
  hook's argument.
- argv is read in one `bpf_probe_read_user_buf` of up to 16 KiB straight
  into the reserved ring buffer record (NUL-separated, as the kernel holds
  it); userspace splits it. Nothing of that size touches the 512-byte
  stack.
- The globals are `static mut` with a non-zero sentinel (`u64::MAX`), so
  they sit in `.data`, where the loader writes them before load and the
  compiler cannot fold their initial value; the lane checks `.data` is two
  u64s, since aya-obj exposes no symbol table.
- The nightly's `dangerous_implicit_autorefs` lint (an error in this crate)
  rules out `(*ev).field.method()` and `(*ev).field[..n]`: fields of a
  reserved record are written through raw pointers or an explicit `&mut`.
- aya-build runs `cargo build --package` where the build script runs, so
  `boxcar-sensor`'s `build.rs` changes directory into the eBPF crate first:
  the crate stays excluded from the workspace and cargo sees it as the
  package it is; aya-build's target directory is absolute under `OUT_DIR`.
- `bpf_guard` lets only the sensor's tgid through; `kill_guard` also lets
  init (tgid 1) and the sensor itself signal the sensor. A signal number of
  0 (an existence probe) is not refused.
- The lane cannot see the hook each program attaches to (aya-obj keeps the
  section name private); it checks the program names and section kinds,
  and the hook names are checked when the gated tests load the programs
  in a guest (Task 4).
- CI's `check` job sets `AYA_BUILD_SKIP=1` for the whole job and builds the
  sensor for musl with an empty object; the new `ebpf` job installs the
  pinned nightly, cargo-binstall 1.25.1 by release and checksum, and
  bpf-linker 0.11.1, then runs `cargo xtask sensor`. The KVM suite was not
  run for this task: no code a VM runs changed.
- `deny.toml` allows `Zlib`: `foldhash`, the hasher `hashbrown` 0.17 uses,
  reached through `aya` and `object`. It is a permissive licence with no
  requirement beyond keeping the notice in the source; it is the only
  addition the sensor's dependencies needed.
