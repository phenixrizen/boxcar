# boxcar: Rust microVM runtime for audited agent isolates

## Context

bitvessel (this repo) is a 2017 fork of Google's novm, a Go/KVM type-2 hypervisor whose founding idea was serving a VM's root filesystem from the host instead of a disk image. The user wants to run AI coding agents (Claude Code, Codex, ...) inside microVMs and derive a complete, trustworthy record of what each agent did: every file operation, every network call, every process, joined to what the model said it intended. Go did not break bitvessel (it builds on Go 1.26 with a six-line kernel-header patch), but its 2017 device model (legacy virtio 0.9, 9P2000.u, no vsock, no virtio-fs, cgo-heavy) is not worth carrying forward, and the parts a port would translate are exactly what rust-vmm already provides.

Decision: rebuild as **boxcar**, a new Apache-2.0 Rust project at `github.com/phenixrizen/boxcar` (remote exists and is empty; check out to `/home/nater/go/src/github.com/phenixrizen/boxcar`). Conductor (`github.com/phenixrizen/conductor`, Go) will later drive boxcar as a child process over the control protocol; that integration is a separate plan in the conductor repo. No changes to bitvessel.

### The design in one paragraph

The isolation boundary is the audit boundary. **Ring 0 (host, tamper-proof):** the VMM serves the rootfs and workspace over virtio-fs in-process, so every file op arrives as a FUSE request carrying guest pid/uid/gid; it terminates guest TCP/UDP in a user-mode network stack, so connections, DNS and TLS SNI are events and egress policy lives in the same code; and it runs a model API gateway that holds the real API key and records every request/response, whose tool_use/tool_result blocks define spans of intent. **Ring 1 (guest, best-effort):** a small Aya eBPF sensor streams exec/fork/exit/connect over vsock. A **reconciler** joins the three streams and emits findings (unattributed effects, sensor silence, intent-vs-effect mismatch, indicator removal, off-book channels, orphaned work, network anomalies, privilege probes), which is how "the model is hiding its trail" becomes a detectable signal. The log is append-only and blake3 hash-chained from day one.

### User decisions

| Decision | Choice |
|---|---|
| License | Apache-2.0, with a CLA (DCO sign-off plus `CLA.md`) so relicensing stays possible |
| Scope | boxcar only; conductor integration is a later plan |
| Gateway providers | Anthropic Messages API **and** OpenAI-compatible (chat completions + responses) |
| Milestone 1 | Shell on the serial console with an audited virtio-fs rootfs, file ops streaming with guest pids |
| Agent placement | The agent loop runs inside the microVM |

## Verified constraints (2026-09-29)

These came out of reading the pinned crate sources and the dev box. They are load-bearing.

- **Version pin set.** fuse-backend-rs 0.14.0 pins `vm-memory = "=0.17.1"` and `virtio-queue = 0.17.0`, so the whole VMM sits on: vm-memory =0.17.1, virtio-queue =0.17.0, linux-loader =0.13.2, virtio-vsock =0.11.0, virtio-bindings =0.2.7, kvm-ioctls =0.25.0, kvm-bindings =0.14.1 (fam-wrappers), vm-superio =0.8.2, event-manager =0.4.2, vm-allocator =0.1.4, vmm-sys-util =0.15.0, smoltcp 0.14 (0BSD), blake3 1.8, nix 0.31 (guest), cpio 0.4 (xtask), aya 0.14 / aya-ebpf 0.2.1 / aya-build 0.2 / bpf-linker 0.11.1, hyper 1.11 + rustls 0.23 (ring backend), oci-client 0.18 + ocirender 0.2.2 (M5). Kata pins the same way.
- **No git dependencies.** rust-vmm's `virtio-device` crate is unpublished and its repo (vm-virtio) was archived on 2026-09-11, so we do not depend on it. `boxcar-virtio` owns the device trait and the virtio-mmio transport outright, seeded from that crate's snapshot (Apache-2.0 OR MIT, roughly a thousand lines including tests) and Firecracker's `transport/mmio.rs`, with the original copyright headers kept and a NOTICE entry. Ring handling stays on crates.io `virtio-queue 0.17.0` and `virtio-bindings 0.2.7`, which fuse-backend-rs and virtio-vsock require anyway. This is the Cloud Hypervisor model: rust-vmm queue, in-tree device layer. Firecracker owns even the queue; we cannot, because fuse-backend-rs's virtio-fs transport takes a `virtio_queue::DescriptorChain`.
- **Transport semantics to preserve.** The driver writes status 0 at probe (a reset before activation) and DRIVER_OK later. `activate` is called on the vCPU thread and must only hand queues and eventfds to a worker; `reset` must be a no-op on an inactive device. The Linux virtio-mmio driver during the M1.8 boot is the conformance oracle.
- **Credential squash.** `PassthroughFs::set_creds` calls `setresuid` for any non-zero uid, which fails in an unprivileged host process. `AuditFs` passes the inner FS `Context { uid: 0, gid: 0, pid }`; the real guest ids go into the audit record only. Consequence: the guest agent runs as the host uid/gid so it owns what it creates; chown, device mknod and `security.*` xattrs return EPERM (documented; ownership xattr in M5).
- **Every `FileSystem` trait method defaults to ENOSYS.** The decorator must forward all of them via a macro, and a differential test must compare `Server<AuditFs<P>>` with `Server<P>` per opcode.
- **`OverlayFs` implements `FileSystem` but not `BackendFileSystem`**, so it cannot mount under `Vfs`. `AuditFs<F: FileSystem>` stays generic; M1 uses `AuditFs<PassthroughFs>` directly, M5 uses `AuditFs<OverlayFs>`.
- **FUSE header pid is the guest thread id (TID),** namespaced to the guest, not the TGID. The reconciler maps TID to TGID using ring 1 fork/exec events.
- **Boot path:** Firecracker legacy (MPTable + `virtio_mmio.device=` cmdline, `pci=off`, no ACPI). Still supported by Firecracker, deprecated but fine since we build the guest kernel. Plan B is a minimal ACPI port with the pinned `acpi_tables 0.2.1`.
- **Guest kernel 6.18 LTS** from Firecracker's `microvm-kernel-ci-x86_64-6.18.config` + our fragment. `IO_URING=n` and friends need `CONFIG_EXPERT=y`. Lockdown must be **integrity**, not confidentiality (confidentiality blocks kprobes, BPF kernel reads, tracefs). `lsm=landlock,lockdown,yama,bpf`.
- **Aya:** the eBPF crate needs a pinned nightly + `rust-src` + bpf-linker (prebuilt via cargo-binstall; no system LLVM). Userspace is stable, musl. No CO-RE from Rust yet: `vmlinux.rs` is generated from **our** guest kernel's BTF with aya-tool (needs bpftool + bindgen-cli) and guarded by a committed BTF hash. eBPF license string must be "Dual MIT/GPL" (separate artifact; document).
- **Dev box (WSL2, Ubuntu 20.04, AMD, nested virt on):** `/dev/kvm` absent until `sudo modprobe kvm_amd`; gcc 9.4, no pahole/libelf-dev/bpftool/bindgen; Docker 29 with a reachable daemon, user in the docker group. So the kernel and BTF bindings build inside a digest-pinned container. `ping_group_range` is "1 0" (no unprivileged ICMP). Keep rootfs/workspace on ext4, never `/mnt/c`. 64 cores, 62 GB RAM, 47 GB free.
- Dotted kernel params (`boxcar.uid=`) do not reach init's env; init parses `/proc/cmdline`. `pivot_root` fails from initramfs; use MS_MOVE + chroot. `/dev/console` gives no job control; the M1 shell uses `/dev/ttyS0` with `TIOCSCTTY`.

## Repo layout

```
boxcar/
├── Cargo.toml                 # workspace; [workspace.dependencies] pins; no git deps, no [patch]
├── rust-toolchain.toml        # channel 1.96, targets x86_64-unknown-linux-musl
├── .cargo/config.toml         # alias xtask = "run -p xtask --"
├── deny.toml                  # license allowlist; multiple-versions=deny for rust-vmm crates; ban aws-lc-sys
├── LICENSE  LICENSE-BSD-3-Clause  NOTICE  CLA.md  CONTRIBUTING.md (DCO)
├── docs/specs/2026-09-29-boxcar-design.md   # the brainstormed design, committed first
├── docs/{architecture,boot,control-protocol,audit-events,reconciler,ebpf-license,wsl2,perf}.md
├── crates/
│   ├── boxcar/              # bin: run, attach, status, stop, events, policy, audit {verify,record}, doctor
│   ├── boxcar-proto/        # serde-only wire types: control v1, audit Record, guest<->VMM msgs (builds for musl)
│   ├── boxcar-audit/        # single-writer chained JSONL log, subscriptions, reader, verify; (M3) reconciler
│   ├── boxcar-vmm/          # KVM, memory, x86 boot, vCPU threads, buses, serial/i8042, wiring, control server, PtyHub
│   ├── boxcar-virtio/       # our own VirtioDevice trait + virtio-mmio transport, IrqTrigger, slots/GSIs, ioeventfd/irqfd, drain_queue, mocks
│   ├── boxcar-fs/           # AuditFs<F> + virtio-fs device
│   ├── boxcar-net/          # smoltcp user-mode stack (pure) + virtio-net device
│   ├── boxcar-vsock/        # Cloud Hypervisor csm/muxer port + virtio-vsock device + InternalServices
│   ├── boxcar-init/         # guest PID 1 (musl static)
│   ├── boxcar-sensor/       # M3 userspace (musl); boxcar-sensor-ebpf (bpfel, not a default member); boxcar-sensor-common (no_std)
│   ├── boxcar-gateway/      # M4 hyper/tokio model gateway
│   └── boxcar-policy/       # M5 TOML policy (M2 ships a smaller net policy inside boxcar-net)
├── xtask/                   # kernel, initramfs, rootfs, schema, test-kvm, gen-vmlinux, sensor
├── guest/kernel/            # build.sh, Dockerfile, base/microvm-kernel-ci-x86_64-6.18.config, boxcar.fragment, VERSION
├── proto/schema/*.json      # schemars output, committed; proto/testdata/*.jsonl golden vectors (Go side reuses)
└── .github/workflows/ci.yml
```

Dependency direction: `boxcar -> boxcar-vmm -> {fs, net, vsock} -> boxcar-virtio`; everything -> `boxcar-audit -> boxcar-proto`; `boxcar-init -> boxcar-proto`. `boxcar-net`'s stack modules never depend on virtio (only `device.rs` does) so the stack is testable with synthetic frames.

## Cross-cutting contracts

### Audit record (`boxcar-proto::audit::Record`, one JSON object per line)

| Field | Type | Notes |
|---|---|---|
| `v` | u8 | 1. Additive changes only; consumers ignore unknown fields and types |
| `session_id` | string | UUIDv7 |
| `seq` | u64 | gapless, assigned only by the writer thread |
| `ring` | 0 or 1 | 0 host-observed, 1 guest-reported |
| `src` | enum | `vmm fs net vsock pty guest sensor reconciler gateway control` |
| `type` | string | dotted, prefix-filterable: `fs.open`, `net.connect`, `proc.exec`, `tool.open`, `finding` |
| `ts_host_ns` | u64 | CLOCK_REALTIME at the writer. **The cross-ring join key** |
| `ts_mono_ns` | u64 | host CLOCK_MONOTONIC for durations and span windows |
| `ts_guest_ns` | u64? | ring 1 only; orders ring 1 internally |
| `subject` | `{pid, uid, gid}`? | guest identity from FUSE ctx or sensor; pid is a TID |
| `data` | object | per type |
| `span` | `{trace_id, span_id}`? | M4 |
| `prev`, `hash` | string | `b3:<hex>`; `hash = blake3(prev_bytes || canonical_json(record_without_hash))`; genesis prev = blake3(session_id) |

Types by milestone. **M1:** `vmm.start{kernel blake3, initramfs blake3, cmdline, vcpus, mem}`, `vmm.stop`, `fs.mount`, `fs.open{flags, exec}`, `fs.create`, `fs.close{path, path_at_open, bytes_read, bytes_written, size, blake3, hash_status, open_seq, attrib}`, `fs.unlink`, `fs.rmdir`, `fs.rename`, `fs.mkdir`, `fs.mknod`, `fs.symlink`, `fs.link`, `fs.setattr`, `fs.fallocate`, `fs.xattr`, plus failed `lookup`/`access` (EACCES/EPERM) and `checkpoint`. Verbose level adds `fs.read`/`fs.write`/`fs.readdir`. **M2:** `net.dhcp`, `net.dns{qname, qtype, rcode, answers, verdict}`, `net.connect{flow, proto, src(with guest port), dst, names, verdict, rule}`, `net.tls{flow, sni, alpn}`, `net.close`, `net.drop`, `vsock.connect`, `vsock.close`, `session.start`, `session.exit`, `policy.changed`, `control.*`, `sync`. **M3 (ring 1):** `proc.exec{pid, tgid, ppid, uid, filename, argv, argv_truncated, start_ns}`, `proc.fork`, `proc.exit`, `proc.connect_attempt`, `proc.tcp_connect{4-tuple}`, `proc.memfd`, `proc.file_open` (sampled), `proc.lsm_deny`, `proc.heartbeat`, `proc.sensor_status`; and `finding{category, score, span_id?, summary, evidence:[{seq, ring}]}`. **M4:** `llm.request`, `llm.response`, `llm.text` (hashed), `tool.open{span_id, tool_use_id, tool_name, args_hash, args_summary, args_full?}`, `tool.close{result_status, result_hash, result_summary}`. **M5:** `policy.loaded`, `policy.exception`.

Limits and redaction (`boxcar_proto::limits`): path 4096, argv 256 elems / 16 KiB, summaries 512 B, bodies over 8 KiB are hashed only, env values never logged. The gateway strips auth headers structurally before the recorder sees bytes; `redact::scrub` is defense in depth. Never sample writes/creates/unlinks/renames/setattr/verdicts/spans/findings; reads and `proc.file_open` may be sampled; drops are counted in `checkpoint`.

### Log writer (`boxcar-audit`)

One writer thread per session owns `<data_dir>/sessions/<session_id>/{meta.json, events.jsonl, events.<n>.jsonl, checkpoints.jsonl}`. Producers send `(Event, ring, ts_guest_ns?)` over a bounded crossbeam channel (64k); the writer stamps time, assigns seq, chains, writes through a `BufWriter`, and `fdatasync`s on every checkpoint (1024 records or 2 s) and immediately after any deny verdict, LSM deny, or finding with score >= 70. Rotation at 256 MiB keeps the chain continuous. Startup tolerates a torn last line. `boxcar audit verify [--evidence <finding_id>] [--json]` recomputes the chain. `LogReader { seek_seq, stream(from, Filter{kinds, pid, span_id, min_score}) }` backs subscriptions.

### Control protocol v1 (`boxcar-proto::control`)

Unix socket `<state>/control.sock` (0600 in a 0700 dir, default `$XDG_RUNTIME_DIR/boxcar/<session_id>/`), `SO_PEERCRED` uid must match, JSON lines, 1 MiB max, every message has a size cap and a test. Server sends `{"v":1,"event":"hello","protocol":"boxcar.control","versions":[1],"session_id":...,"capabilities":[...]}` first. Requests `{"v":1,"id":N,"op":...}`, responses `{"v":1,"id":N,"ok":true,"result":{}}` or `{"ok":false,"error":{"code","message"}}`, events `{"v":1,"event":...}`. Error codes: `bad_request unsupported_version unknown_op invalid_state not_found busy internal`.

| Op | Milestone | Notes |
|---|---|---|
| `status` | M2 | state, session_id, pid, uptime, guest init/session state, `audit.next_seq` |
| `stop {mode: graceful|force, timeout_ms}` | M2 | then `state` event |
| `pty.attach {session, mode: rw|ro, replay_bytes}` | M2 | connection goes raw after the ok line |
| `pty.resize {rows, cols}` | M2 | |
| `audit.subscribe {from_seq?, types?[prefixes], pid?, span_id?, min_score?}` | M2 | replay from file then live queue (16k); `audit.lagged{resume_seq}` on overflow, never loses records |
| `policy.get` / `policy.update {net:{default, allow[], deny[]}, vsock:{allow_ports[]}}` | M2 | M5 adds `exception {rule_id, action, ttl_s}` |
| `finding` (event) | M3 | pushed when score >= notify threshold |
| `span.list {active_only?}` | M4 | |
| `audit.verify {from_seq?}` | M5 | |

`boxcar run --ready-fd N` writes `{"ready":true,"control":"...","session_id":"..."}` once bound. This is conductor's integration point.

### Guest to VMM messages (`boxcar-proto::guest`, over vsock)

| Port (guest -> CID 2) | Name | Framing |
|---|---|---|
| 1024 | `boxcar.ctl` | JSON lines: init sends `hello`, `session.started`, `session.exited`, `pong`, `log`; VMM sends `config{argv, env, cwd, uid, gid, hostname, term, rows, cols, sysctls}`, `resize`, `signal`, `shutdown{grace_ms}`, `ping` |
| 1025 | `boxcar.pty` | first line `{"t":"pty","session":"main"}`, then raw bytes |
| 1026 | `boxcar.sensor` (M3) | `[u32 LE len][record json]` |
| other | | `<state>/vsock.sock_<port>` only if allowlisted, else RST and `vsock.connect{verdict:deny}` |

Anti-spoofing: internal ports accept only a guest source port below 1024 (root only in the guest) and only the first connection per port; init binds 1023/1022 before dropping privileges.

## Component design

### VMM core (`boxcar-vmm`)

Guest physical map (Firecracker legacy): GDT 0x500, IDT 0x520, zero page 0x7000, stack 0x8ff0, page tables 0x9000/0xa000/0xb000 (identity map 1 GiB), cmdline 0x20000 (2048 max), MPTable 0x9fc00, kernel ELF from 1 MiB, initramfs at the top of low RAM, MMIO slots 4 KiB from 0xC000_0000 (vm-allocator `AddressAllocator`), GSIs 5–23 (`IdAllocator`), IOAPIC/LAPIC in kernel, TSS 0xFFFB_D000, RAM above 4 GiB if mem > 3 GiB. E820: `[0,0x9fc00)` RAM, `[0x9fc00,0x100000)` reserved, `[1M, min(mem,3G))` RAM, `[4G, 4G+(mem-3G))` RAM.

Boot order in `Vmm::new`: `Kvm::new` (assert API 12, check extensions, raise RLIMIT_NOFILE) -> `create_vm`, `set_tss_address`, `create_irq_chip`, `create_pit2` (before any vCPU) -> `GuestMemoryMmap::from_ranges` + `set_user_memory_region` per region -> `linux_loader::loader::Elf::load` (64-bit entry from `kernel_load`) -> initramfs via `read_exact_volatile_from` -> devices (slot, GSI, EventFds, `register_ioevent` at base+0x50, `register_irqfd`) -> `Cmdline::new(2048)` + `add_virtio_mmio_device` per device + `load_cmdline` at 0x20000 -> MPTable (port Firecracker `arch/x86_64/mptable.rs` + bindgen `mpspec.rs`, keep Amazon and Chromium headers) -> `boot_params` via `LinuxBootConfigurator::write_bootparams` (type_of_loader 0xff, boot_flag 0xaa55, header 0x53726448, kernel_alignment 0x0100_0000, cmd_line_ptr, ramdisk) -> vCPUs -> threads.

Base cmdline (M1): `console=ttyS0 reboot=k panic=1 pci=off nomodule 8250.nr_uarts=1 i8042.noaux i8042.nomux i8042.dumbkbd lockdown=integrity random.trust_cpu=on quiet loglevel=4 rdinit=/init boxcar.mode=console boxcar.uid=<host uid> boxcar.gid=<host gid> [boxcar.cmd=<base64url json argv>]`. M2 adds `ip=10.0.2.15::10.0.2.2:255.255.255.0:boxcar:eth0:off:10.0.2.2 boxcar.mode=vsock`. `--debug-boot` adds `earlyprintk=serial,ttyS0,115200`.

vCPU setup per Firecracker `regs.rs`/`gdt.rs`/`msr.rs`: CPUID from `get_supported_cpuid` patched Cloud-Hypervisor style (leaf 1 apic id/ncpus/HTT/hypervisor bit, leaf 0xB/0x1F topology, AMD 0x8000_0008/0x8000_001E, keep KVM leaves); MSRs (SYSENTER/STAR/LSTAR/KERNEL_GS_BASE = 0, MISC_ENABLE fast string, MTRRdefType); FPU fcw 0x37f mxcsr 0x1f80; BSP regs rip=entry rsp=rbp=0x8ff0 rsi=0x7000 rflags 2; sregs with the 4-entry GDT, cr3=0x9000, PAE/PE/PG, EFER LME|LMA; LAPIC LVT0 ExtINT, LVT1 NMI. APs get CPUID/MSRs/FPU/LAPIC only and just call `run()`.

Run loop: `IoIn/IoOut` -> PIO bus (unmapped reads 0xff), `MmioRead/MmioWrite` -> MMIO bus -> `MmioTransport<D>`, `Shutdown` -> reset, `SystemEvent`, `FailEntry/InternalError` -> dump regs and error, `EINTR` -> check stop flag. **Kick:** capture `*mut kvm_run` per thread, write `immediate_exit = 1` then `pthread_kill(tid, SIGRTMIN)` with a no-op handler (no lost-wakeup race).

Legacy devices: COM1 0x3f8 via `vm_superio::Serial::with_events` behind `Arc<Mutex>`, irqfd GSI 4, stdout or `<state>/console.log`; i8042 0x60/0x64 via `vm_superio::I8042Device` (0xFE to port 0x64 signals reset -> shutdown); stdin raw mode with a restore guard and panic hook, FIFO backpressure via `in_buffer_empty`, Ctrl-] twice within 1 s forces stop. No RTC (kvmclock only).

Shutdown triggers: i8042 reset, `Shutdown`/`SystemEvent`, vCPU error, SIGTERM/SIGINT (signalfd), control `stop`, (M2) `session.exited`. Sequence: state Stopping -> (graceful) `shutdown{grace_ms}` to init and wait for reset -> kick and join vCPUs -> `kill_evt` and join device threads -> drain audit, append `vmm.stop`, fsync -> unlink sockets, restore terminal, exit with the session code.

Threads: main (EventManager: stdin, serial evt, reset evt, vcpu-exited evts, signalfd, stop evt), vcpu-N, fs-<tag>-qN (one per virtio-fs queue; host I/O blocks), net (EventManager: rx/tx evts, smoltcp timerfd, dynamic host sockets), vsock (queue evts + muxer epoll), audit-writer, fs-hash x2, control accept + per-client, pty-hub (M2), gateway tokio runtime (M4).

### virtio device layer (`boxcar-virtio`, owned in-tree)

`boxcar-virtio` defines `trait VirtioDevice { device_type, avail_features, ack_features, read_config, write_config, activate(ActivatedQueues) -> Result, reset, queue_notify(q) }` and `struct VirtioConfig { queues: Vec<Queue>, driver_features, device_status, queue_select, interrupt_status }`. `MmioTransport<D>` implements the virtio 1.2 section 4.2.2 register map (magic 0x74726976, version 2, device and vendor id, feature select and bits, queue select/size/ready/notify, interrupt status and ack, status, queue descriptor/driver/device addresses, config generation, config space at 0x100+), seeded from the rust-vmm virtio-device snapshot and Firecracker's mmio.rs with headers kept. The status write path calls `activate` exactly once on DRIVER_OK and `reset` on status 0 (no-op when inactive). Owning this layer means we can add what we need later without upstream: audit hooks on config writes, a virtio-pci transport, snapshot serialization. `DeviceContext { mem, vm, slot{base,size,gsi}, irq: Arc<IrqTrigger>, queue_evts, kill_evt }` with `register()` doing ioeventfd (base+0x50, datamatch q) and irqfd. `IrqTrigger { evt, status: Arc<AtomicU8> }` shares `interrupt_status`; `signal_used_queue` = fetch_or 1 + write. `MmioTransport<D>(D)` newtype implements `BusDevice`; `bus.rs` ported from Firecracker (`BTreeMap<BusRange, Arc<Mutex<dyn BusDevice>>>`). All devices offer `VERSION_1 | RING_F_EVENT_IDX`. `drain_queue(q, mem, |chain| -> Result<u32>) -> Result<bool>` does disable_notification / pop / add_used / needs_notification / enable_notification. Fixed slot order: 0 fs `root` GSI 5, 1 fs `workspace` GSI 6, 2 net GSI 7, 3 vsock GSI 8.

### Filesystem (`boxcar-fs`)

Device: type 26, config `tag[36]` + `num_request_queues` (1 in M1, `min(vcpus,4)` in M2), queue 0 hiprio, max size 1024, no DAX, no notifications. Worker per queue: `Reader::from_descriptor_chain(mem, chain)` + `VirtioFsWriter::new(mem, chain).into()` -> `server.handle_message(r, w, None, Some(&hook))`; `FsServer = Server<AuditFs<PassthroughFs<()>>>` shared as `Arc`. `hook: MetricsHook` counts every opcode with pid/uid and warns on opcodes AuditFs does not model. Shares: root = `CachePolicy::Always`, workspace = `CachePolicy::Auto`; both `writeback=false` (keeps every write synchronous with the caller's pid), `xattr=true`, `do_import=true`; call `import()` after `new`.

`AuditFs<F>` (`audit_fs.rs`): `new(inner, MountInfo{tag, guest_path, host_root_fd}, sink, AuditFsOptions{level, hash_max_bytes: 64 MiB})`. `init` masks `WRITEBACK_CACHE` and emits `fs.mount`. Squash creds to 0/0 (real ids in `subject`). Maintain `PathMap { nodes: ino -> {parent, name, nlookup, deleted}, by_name }` from `lookup`, `readdirplus` (wrap `add_entry`, each entry is an implicit lookup), `forget`, `create`/`mkdir`/`mknod`/`symlink`/`link`, `rename` (incl. RENAME_EXCHANGE), `unlink`/`rmdir` (mark deleted until forget); `path(ino)` walks parents, depth cap 4096, no syscalls. `HandleTable fh -> {ino, path_at_open, flags, opener, counters}`; reads/writes with `ctx.pid == 0` or `FUSE_WRITE_CACHE` attribute to the opener with `attrib: "handle"`. On `release` of a written/created/truncated handle, queue a hash job: worker opens via `openat2(host_root_fd, rel, RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`, fstats before and after `blake3::Hasher::update_reader`, sets `hash_status` in {ok, raced, gone, skipped_size, error}, then emits `fs.close`. `fs.open` records `exec: flags & __FMODE_EXEC(0x20)` (verify in the M1.10 test). `forward!` macro covers every 0.14.0 trait method. Documented blind spots: page-cache hits, guest tmpfs, hash-after-close races.

### Network (`boxcar-net`)

Device (type 1): rx=0/tx=1 size 256, features `VERSION_1|EVENT_IDX|NET_F_MAC`, no offloads, MAC `02:62:6f:78:00:01`, 12-byte `virtio_net_hdr_v1`. RX with no buffers: bounded pending queue (1024), `enable_notification` on the RX queue, retry on ioeventfd (lost-wakeup pitfall). One `NetSubscriber` on the net thread owns both queues and `NetStack`, a timerfd from `iface.poll_delay()`, and dynamic host fds via `EventOps`.

Stack: guest `10.0.2.15/24`; gateway, DNS and DHCP at `10.0.2.2`. A dispatcher runs **before** smoltcp: ARP to smoltcp plus proxy-ARP for the whole /24; UDP:67 -> static DHCP lease; UDP:53 -> DNS parser (bounds-checked, fuzzed), policy (denied names get NXDOMAIN), forward to the host resolver with id remap and 5 s timeout, strip AAAA, fill `DnsCache` (ip -> names with TTL), emit `net.dns`; other UDP -> NAT relay (default deny); ICMP never reaches smoltcp (echo to .2 answered locally, rest dropped); IPv6 dropped (guest `disable_ipv6=1`); TCP SYN -> policy verdict; other TCP -> `poll_ingress_single`. TCP relay: `set_any_ip(true)` + default route to 10.0.2.2; **deferred SYN**: on allow, start a non-blocking `socket2` connect (or `ServiceRegistry` for internal targets in M4), park the SYN; on connect success create `tcp::Socket` (256 KiB buffers, Nagle off, no ACK delay), `listen(dst endpoint)`, feed the parked SYN; on failure synthesize RST; on deny send RST. Backpressure both ways; FIN -> shutdown(Write), RST -> abort. SNI/Host gate for domain-rule flows: buffer up to 16 KiB / 5 s, `sni::parse_client_hello` or plain HTTP Host; mismatch resets both sides. Policy v1: `domain[:port]` (exact or `*.suffix`), `cidr[:port]`, default deny/allow, hot-swapped via `ArcSwap`; built-in deny for 127/8, 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16 unless explicitly allowed. `net.connect.src` always includes the guest source port (M3 join key).

### vsock (`boxcar-vsock`)

Port Cloud Hypervisor `virtio-devices/src/vsock/{mod, csm/*, unix/*}` (keep Intel/Amazon Apache-2.0 and Chromium BSD-3 headers, NOTICE entry); drop its `packet.rs` for `virtio_vsock::packet::VsockPacket<B>` (0.11) with a small shim for data slices (vm-memory 0.17 removed `VolatileSlice::as_ptr`; crib adaptations from `vhost-device-vsock`). New `device.rs` on boxcar-virtio: type 19, queues rx/tx/evt size 256, `guest_cid = 3`, TX via `from_tx_virtq_chain` -> `send_pkt`, RX via `from_rx_virtq_chain` -> `recv_pkt`, muxer epoll fd as an event source. Additions: `InternalServices::connect(port, meta) -> Option<UnixStream>` tried first (UnixStream pair, one end to the VMM service); otherwise `<uds>_<port>` if allowlisted, else RST; host-to-guest keeps Firecracker's `CONNECT <port>\n` / `OK <port>\n`; the privileged-source-port rule above. Port the CH unit tests over plain buffers.

### Guest (`guest/kernel`, `boxcar-init`)

Kernel fragment: `EXPERT=y ACPI=n PCI=n MODULES=n X86_MPPARSE=y KVM_GUEST=y PARAVIRT=y PTP_1588_CLOCK_KVM=y VIRTIO_MMIO=y VIRTIO_MMIO_CMDLINE_DEVICES=y FUSE_FS=y VIRTIO_FS=y FUSE_DAX=n VIRTIO_NET=y VSOCKETS=y VIRTIO_VSOCKETS=y VIRTIO_CONSOLE=n SERIAL_8250(_CONSOLE)=y BLK_DEV_INITRD=y DEVTMPFS=y TMPFS=y UNIX98_PTYS=y IP_PNP(_DHCP)=y CGROUPS=y CGROUP_BPF=y BPF_SYSCALL=y BPF_JIT(_ALWAYS_ON)=y BPF_LSM=y BPF_EVENTS=y KPROBES=y KPROBE_EVENTS=y FTRACE=y FUNCTION_TRACER=y DYNAMIC_FTRACE=y DEBUG_INFO_DWARF5=y DEBUG_INFO_BTF=y SECURITY=y SECURITY_LANDLOCK=y SECURITY_LOCKDOWN_LSM(_EARLY)=y SECURITY_YAMA=y LSM="landlock,lockdown,yama,bpf" DEVMEM=n PROC_KCORE=n IO_URING=n`. `cargo xtask kernel` (Docker default: `debian:trixie` by digest with build-essential, flex, bison, bc, libelf-dev, libssl-dev, dwarves >= 1.22; `--native` requires pahole >= 1.22) downloads and verifies the tarball pinned in `guest/kernel/VERSION`, merges base + fragment with `merge_config.sh`, `olddefconfig`, **fails if any fragment line is missing from the final .config**, builds `vmlinux`, strips debug but keeps `.BTF`, outputs `target/guest/{vmlinux, vmlinux.debug, kernel.config}`.

`cargo xtask initramfs`: builds `boxcar-init` for musl with a `guest` profile (opt-level s, lto, strip, panic=abort plus a panic hook to `/dev/kmsg`), writes a reproducible newc cpio (`/init`, dirs, `/dev/console` c 5:1 0600, `/dev/null` c 1:3, M3 `/sbin/boxcar-sensor`), prints its blake3. `cargo xtask rootfs alpine` fetches alpine-minirootfs into `target/guest/rootfs-alpine/`.

Init order: mount proc/sysfs/devtmpfs, parse `/proc/cmdline` (hello mode prints `BOXCAR_INIT_HELLO` and reboots) -> mount virtio-fs `root` at `/newroot` and `workspace` at `/newroot/workspace` -> MS_MOVE dev/proc/sys in, mount devpts (newinstance, ptmxmode 0666, gid 5), tmpfs at dev/shm and run, tracefs, cgroup2, bpffs (`/tmp` stays on virtio-fs so it is audited) -> `chdir /newroot; mount . / MS_MOVE; chroot .` -> hostname, sysctls (`kptr_restrict=2 dmesg_restrict=1 unprivileged_bpf_disabled=1 perf_event_paranoid=3 yama.ptrace_scope=1 ipv6 disabled`), `lo` up, (M2) resolv.conf bind -> cgroups `system` and `session` -> (M3) start sensor from the initramfs copy -> (M2) connect vsock 1024 from src port 1023, `hello`, receive `config`; connect 1025 from 1022 -> spawn session: M1 fork + setsid + open `/dev/ttyS0` + TIOCSCTTY; M2 openpty + setsid + TIOCSCTTY; then join `session` cgroup, `setgroups([])`, `setresgid`, `setresuid(host uid)`, `PR_SET_NO_NEW_PRIVS`, drop bounding/ambient caps, `chdir /workspace`, `execve` -> PID 1 single-threaded `poll` over signalfd(SIGCHLD reap loop), ctl stream, PTY master, PTY stream; handle resize/signal/shutdown; on session exit drain PTY to EIO and send `session.exited` -> `sync`, `reboot(RB_AUTOBOOT)` (kernel writes 0xFE to 0x64, VMM exits).

PtyHub on the host keeps a 256 KiB scrollback ring, fans output to attached clients, merges rw input, backpressures the guest when all clients stall. `boxcar run` attaches the local terminal in-process (size at start and on SIGWINCH); `boxcar attach <id>` uses `pty.attach` plus a second connection for `pty.resize`; detach keys ctrl-p,ctrl-q.

### Sensor (`boxcar-sensor*`, M3)

aya-template shape: `boxcar-sensor-common` (`#![no_std]`, `#[repr(C)]` events with a `Kind: u32` tag, `user` feature adds `Pod`), `boxcar-sensor-ebpf` (`#![no_std, no_main]`, one file per program, license section "Dual MIT/GPL", excluded from default members), `boxcar-sensor` (userspace, tokio, musl; `build.rs` calls `aya_build::build_ebpf(..., Toolchain::Custom("nightly-2026-06-01"))`, honors `AYA_BUILD_SKIP=1`; embeds with `include_bytes_aligned!`).

| Program | Hook | Emits |
|---|---|---|
| `btf_tracepoint sched_process_exec` | after successful exec; argv from `current->mm->arg_start..arg_end` (bounded loop, `argv_truncated`), filename from `bprm` | `ExecEvent` |
| `btf_tracepoint sched_process_fork` | filter `child->pid == child->tgid` | `ForkEvent` |
| `btf_tracepoint sched_process_exit` | 6.18 signature `(task_struct*, bool group_dead)` | `ExitEvent` |
| `lsm socket_connect` | pid + destination; can return -EPERM | `ConnectAttempt` |
| `fentry tcp_connect` | full 4-tuple after port selection | `TcpConnect` |
| `lsm file_open` (sleepable, optional, sampled) | `bpf_d_path` | `FileOpen` |
| `fentry __x64_sys_memfd_create` | | `Memfd` |
| `lsm bpf` | deny `bpf()` to every tgid except the sensor's (loaded last) | `LsmDeny` |

Userspace drains a `RingBuf` (256 KiB, `AsyncFd`), converts to ring 1 records, writes `[u32 len][json]` to vsock port 1026, sends `proc.heartbeat{uptime_ns, events_emitted, ringbuf_drops}` every second and `proc.sensor_status{phase: attached|degraded, programs, kernel_release, btf_ok}`. Pass the bare LSM hook name (aya prepends `bpf_lsm_`). `vmlinux.rs`: `aya-tool generate --btf target/guest/vmlinux task_struct linux_binprm sock sockaddr sockaddr_in sockaddr_in6 mm_struct file path dentry` via `cargo xtask gen-vmlinux`, committed, with `guest/kernel/.btf-hash` and `xtask check-vmlinux` failing on drift. Dev setup: `rustup toolchain install nightly-2026-06-01 --component rust-src`, `rustup target add x86_64-unknown-linux-musl`, `cargo binstall bpf-linker@0.11.1 bindgen-cli@0.73.2`, bpftool v7.7 static, or run aya-tool inside the kernel build container.

### Reconciler (`boxcar-audit::reconcile`, M3)

A subscriber task consuming the writer's broadcast in seq order; emits `finding` records back into the writer. State: `procs: HashMap<(tid, start_ns), Proc>`, `tid_to_tgid`, `flows` and `flows_by_tuple`, `DnsCache`, `spans` stack with `executor_pid`, `PathWatch` from policy indicators, `last_ring1_ts`, `ring0_active`. Joins: fs/net effect -> process by TID (mapped to TGID) whose `[exec_ts, exit_ts]` contains `ts_host_ns`; flow -> process by 4-tuple within 500 ms (`fentry/tcp_connect` vs `net.connect`); process -> span by time containment plus ancestry to the executor pid; a span inherits the worst score.

| Finding | Condition | Score |
|---|---|---|
| `unattributed_effect` | effect pid has no live Proc | 60 |
| `sensor_silence` | no heartbeat for 3 s while ring 0 is active (1 s tick) | 85 |
| `intent_effect_mismatch` (argv) | declared tool command differs from observed argv (normalized) | 70 |
| `intent_effect_mismatch` (phantom write) | tool_result claims a write ring 0 never saw | 65 |
| `intent_effect_mismatch` (hidden net) | ring 0 saw a connection the tool_result omits | 55 |
| `indicator_removal` | unlink/truncate of history, logs, sensor, init paths | 90 |
| `off_book_channel` | memfd_create, tmpfs write, open of an unlinked inode | 75 |
| `orphaned_work` | span-bound process alive after `tool.close` (1 s tick) | 50 |
| `network_anomaly` | connect with no prior DNS for the IP; DNS rate/entropy spike; SNI resolves elsewhere than dst | 60–70 |
| `privilege_probe` | any `proc.lsm_deny` for bpf/module/ptrace/mount | 80 |
| `policy_denial` | any deny verdict | 40 |

Rules that depend on a hook the sensor reports missing are down-weighted. Tests: golden fixtures `tests/fixtures/<scenario>/{input,expected}.jsonl` with `insta` snapshots (scenarios: curl_no_dns, phantom_write, history_wipe, memfd_exec, sensor_gap, orphan_after_span, sni_mismatch, pid_reuse, dns_entropy_spike) and `proptest` for pid-reuse intervals.

### Gateway (`boxcar-gateway`, M4)

tokio + hyper 1.11 (`hyper-util` auto server) + `http-body-util`, client leg `hyper-rustls` 0.27 / rustls 0.23 with the `ring` backend (keeps cargo-deny clean; ban aws-lc-sys). Justification: HTTP/2 upstream and Codex's Responses-over-WebSocket path rule out a hand-rolled server. Runs on its own runtime thread; reachable from the guest at `10.0.2.2:8080` via a `ServiceRegistry` target (DNS `gateway.boxcar.internal` -> 10.0.2.2; the TCP flow becomes an internal UnixStream pair exempt from egress policy). Routes: `/v1/messages` -> Anthropic, `/v1/chat/completions` -> OpenAI chat, `/v1/responses` (POST and WS upgrade) -> OpenAI responses. Init injects `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and placeholder keys (`sk-boxcar-proxy`) via `config.env`; the gateway strips `authorization`, `x-api-key`, `anthropic-*` auth headers on ingress, substitutes the real key, and records `client_supplied_auth: true` if the agent sent its own key. Streaming passthrough with a `Tee` that forwards bytes unmodified and unbuffered while an incremental parser emits records. Provider-neutral `ModelEvent { RequestMeta, ToolIntent, ToolResult, ResponseMeta, AssistantText }`. Anthropic: state machine on `content_block_start/delta/stop` per index for `tool_use` (`input_json_delta`), usage from `message_start`/`message_delta`, tolerate thinking/server_tool_use/unknown events; `tool_result` blocks arrive in the **next** request's messages -> `tool.close`. OpenAI chat: accumulate `delta.tool_calls[]` by index, finish on `finish_reason == tool_calls`; `role: tool` messages close. Responses: `response.output_item.added` (function_call) / `function_call_arguments.delta|done`; `function_call_output` items close; `response.completed` carries usage. Failure modes: upstream errors pass through unchanged; malformed SSE degrades to pass-through with `parse_degraded: true`; WS upgrade failure lets Codex fall back to HTTPS; bounded tee buffer. Tests: recorded SSE fixtures per provider, two-request span test, malformed-tail test, redaction test, tee byte-identity test.

### Policy (`boxcar-policy`, M5)

TOML with `deny_unknown_fields`: `[egress] default, allow_sni, allow_ip, allow_port, max_dns_qps, max_dns_entropy`; `[fs] writable, denied, indicators`; `[exec] default, deny_path`; `[spans] keep_tool_args, keep_text`. Compiled into `GlobSet`s and `IpNet` lists; pure `eval_egress`, `eval_fs`, `eval_exec`, `eval_connect` return `Verdict`. Evaluation points: net stack, AuditFs (deny returns EPERM), sensor LSM (deny lists mirrored into eBPF maps). Live exceptions via `policy.update` mutate an `ArcSwap<Policy>` with TTL timers and emit `policy.exception`. Built-in `agent-isolate` profile (gateway, package registries, git hosts, ports 80/443, DNS <= 20 qps, writable `/workspace` `/tmp` cache; indicators watch history/logs/sensor/init) and `agent-isolate-strict` (exec default deny).

## Milestones and tasks

Sizes: S <= 1 day, M 2–3 days, L 4–7 days. "KVM" steps need `/dev/kvm` and the built guest artifacts; gated tests use `--features kvm-tests` and skip when `/dev/kvm` or `BOXCAR_TEST_{KERNEL,INITRAMFS,ROOTFS}` is absent.

### M0: repo bootstrap (S)

1. `git clone https://github.com/phenixrizen/boxcar.git /home/nater/go/src/github.com/phenixrizen/boxcar` (empty repo; `git init` + remote if clone refuses). `sudo modprobe kvm_amd && setfacl -m u:$USER:rw /dev/kvm`.
2. Commit LICENSE (Apache-2.0), LICENSE-BSD-3-Clause, NOTICE (Firecracker, Cloud Hypervisor, vmm-reference, vhost-device attributions), CLA.md, CONTRIBUTING.md (DCO), README stub, and `docs/specs/2026-09-29-boxcar-design.md` written from the brainstorm (rings, reconciler, gateway, conductor seam, license reasoning).
3. Toolchain: `rustup target add x86_64-unknown-linux-musl`, `cargo install cargo-binstall`, `cargo binstall cargo-deny cargo-nextest`.

### M1: shell on console with audited rootfs (about 3–4 weeks)

| ID | Task | Key files | Verify |
|---|---|---|---|
| M1.1 (S) | Workspace, pins (no git deps), deny.toml, CI (fmt, clippy -D warnings, test, cargo-deny, musl build) | `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `.github/workflows/ci.yml` | `cargo build --workspace && cargo deny check`; no `git+` sources in `Cargo.lock` |
| M1.2 (S) | **Dependency sanity check**: a stub feeding a crates.io `virtio_queue::DescriptorChain` into `Reader::from_descriptor_chain` and `VsockPacket::from_tx_virtq_chain` | temp code in `crates/boxcar-fs` | `cargo check`; `cargo tree -d` shows no duplicate rust-vmm crates |
| M1.3 (M) | `boxcar-proto` audit types + limits + redact; `boxcar-audit` writer with seq, hash chain, checkpoints, rotation, torn-tail recovery; `boxcar audit verify` | `crates/boxcar-proto/src/{audit,limits,redact,ids}.rs`, `crates/boxcar-audit/src/{sink,writer,chain,segment,checkpoint,verify}.rs`, `crates/boxcar/src/cmd/audit.rs` | `cargo test -p boxcar-audit`: seq gapless under 8 producer threads; 10k records across a forced rotation verify; flipping one byte fails verify at the right seq; golden `proto/testdata/audit-v1.jsonl` round-trips |
| M1.4 (S) | `boxcar doctor` (KVM caps, /dev/kvm perms, docker, musl target, pahole) and a KVM smoke guest (real-mode `out 0x3f8; hlt`) | `crates/boxcar/src/doctor.rs`, `crates/boxcar-vmm/tests/smoke.rs` | `cargo run -p boxcar -- doctor` all OK; KVM: smoke test sees `'K'` then `Hlt` |
| M1.5 (M) | Kernel build via Docker with fragment verification | `guest/kernel/{build.sh,Dockerfile,VERSION,boxcar.fragment,base/*.config}`, `xtask/src/kernel.rs` | `cargo xtask kernel`; `file target/guest/vmlinux` is ELF x86-64; `readelf -S` shows `.BTF`; xtask prints `fragment: all N applied` |
| M1.6 (S) | `boxcar-init` hello mode + `xtask initramfs` | `crates/boxcar-init/src/{main,cmdline}.rs`, `xtask/src/initramfs.rs` | `cpio -itv < target/guest/initramfs.cpio` lists `init` and `crw------- dev/console`; init is statically linked; cmdline parser unit test |
| M1.7 (L) | x86 boot: layout, E820, initrd, boot_params, MPTable + mpspec bindgen, page tables, GDT, regs, MSRs, CPUID, LAPIC, cmdline | `crates/boxcar-vmm/src/arch/x86_64/{mod,layout,boot,mptable,mpspec,regs,gdt,msr,cpuid,interrupts}.rs`, `memory.rs`, `cmdline.rs` | `cargo test -p boxcar-vmm` (no KVM): E820 for 512 MiB / 3 GiB / 5 GiB; MPTable checksums (ported Firecracker tests); page table contents; cmdline contains `virtio_mmio.device=4K@0xc0000000:5` |
| M1.8 (M) | vCPU loop, kick, PIO bus, serial, i8042, stdin raw mode, main EventManager, shutdown | `vcpu.rs`, `kick.rs`, `bus.rs`, `devices/legacy.rs`, `stdin.rs`, `lifecycle.rs`, `vmm.rs` | KVM: `boxcar run --kernel target/guest/vmlinux --initramfs target/guest/initramfs.cpio --no-fs --cmdline-extra boxcar.mode=hello` prints the kernel banner and `BOXCAR_INIT_HELLO`, exits 0 in < 3 s, terminal restored |
| M1.9 (M) | `boxcar-virtio`: VirtioDevice trait, VirtioConfig, MmioTransport register map, IrqTrigger, SlotAllocator, ioeventfd/irqfd, drain_queue, mocks; port the register-map tests from virtio-device and Firecracker with attribution | `crates/boxcar-virtio/src/{device,config,mmio,irq,context,slots,queue,features,testing}.rs`, `NOTICE` | `cargo test -p boxcar-virtio`: dummy device reads magic 0x74726976 / version 2 / device id; feature select high and low round-trip; status handshake calls `activate` exactly once and `reset` on status 0; queue addresses match; interrupt ack clears bits |
| M1.10 (L) | `AuditFs`: forward macro, PathMap, HandleTable, cred squash, HashWorker (openat2), MetricsHook, differential test | `crates/boxcar-fs/src/{audit_fs,forward,path_map,handles,hasher,events,share}.rs`, `tests/{auditfs,differential}.rs` | `cargo test -p boxcar-fs` on a tempdir with `Context{pid:42,uid:1000}`: create/write/release yields `fs.close` with blake3 == `b3sum`; rename/unlink paths correct; readdirplus then forget empties the map; differential test 0 mismatches; creates succeed unprivileged |
| M1.11 (M) | virtio-fs device (config space, hiprio + 1 request queue, worker) | `crates/boxcar-fs/src/device.rs` | `cargo test -p boxcar-fs virtio_roundtrip`: FUSE_INIT then FUSE_LOOKUP through mock queues; used len > 0; `out.error == 0`; irq signalled |
| M1.12 (M) | init console mode (mounts, move, chroot, sysctls, ttyS0 shell, reaper, reboot) + `xtask rootfs alpine` | `crates/boxcar-init/src/{mounts,sysctl,session,reaper,shutdown}.rs`, `xtask/src/rootfs.rs` | KVM: `boxcar run --kernel ... --initramfs ... --rootfs target/guest/rootfs-alpine --workspace /tmp/ws --audit /tmp/a.jsonl`; `id` shows the host uid; `echo hi > /workspace/a.txt; exit`; VM exits 0; `jq 'select(.type=="fs.close" and .data.path=="/a.txt")'` shows `bytes_written:3`, blake3 == `b3sum /tmp/ws/a.txt`, `subject.pid > 1`; `boxcar audit verify /tmp/a.jsonl` passes |
| M1.13 (M) | CLI finish: `-- CMD` via `boxcar.cmd`, default paths, gated e2e tests | `crates/boxcar/src/{cli,run,term}.rs`, `crates/boxcar/tests/kvm_m1.rs`, `xtask/src/test_kvm.rs` | `cargo xtask test-kvm m1` green; `boxcar run ... -- /bin/sh -c 'ls /workspace'` prints and exits 0 |

### M2: network, vsock, PTY, control v1 (about 4–5 weeks; net and vsock tracks run in parallel after M2.2)

| ID | Task | Key files | Verify |
|---|---|---|---|
| M2.1 (M) | SMP: per-vCPU CPUID topology, MPTable CPUs, kick under load | `arch/x86_64/{cpuid,mptable}.rs`, `vcpu.rs` | KVM: `--vcpus 4`, guest `nproc` = 4; `stop` during `yes > /dev/null` on all CPUs exits < 1 s |
| M2.2 (M) | Control v1 types + server (hello, status, stop), `boxcar status/stop`, `--ready-fd`, SO_PEERCRED | `boxcar-proto/src/control.rs`, `boxcar-vmm/src/control/{mod,server,conn}.rs`, `boxcar/src/client.rs` | `socat - UNIX-CONNECT:$S` with a status request returns `ok:true`; golden `control-v1.jsonl` round-trips |
| M2.3 (M) | Net wire layer: dispatcher, ARP/proxy-ARP, DHCP, ICMP to gateway | `boxcar-net/src/{config,stack,frame,arp,dhcp,icmp}.rs` | synthetic DISCOVER -> OFFER (.15, router .2); ARP for .2 and .77 answered; ICMP to 8.8.8.8 dropped with `net.drop` |
| M2.4 (M) | DNS parser, forwarder, DnsCache, net policy v1 (ArcSwap) | `boxcar-net/src/dns/{mod,parse,forwarder,cache}.rs`, `policy.rs` | denied name -> NXDOMAIN + `net.dns{verdict:deny}`; allowed query forwarded to a fake upstream and cached; AAAA stripped; `cargo fuzz run dns_parse` 10 min clean |
| M2.5 (L) | TCP relay: deferred SYN, any_ip, socket2 connect, backpressure, FIN/RST, SNI/Host gate, private-range deny | `boxcar-net/src/tcp/{mod,flow,relay}.rs`, `sni.rs`, `http_host.rs`, `upstream.rs` | two-interface smoltcp harness with a loopback echo server: 10 MiB echoes intact; denied dst gets RST; rustls ClientHello fixtures parse; mismatched SNI resets; `cargo fuzz run sni` clean |
| M2.6 (S) | UDP NAT relay, IPv6 drop | `boxcar-net/src/udp.rs` | allowed UDP round-trips; default deny drops with an event |
| M2.7 (M) | virtio-net device + net thread | `boxcar-net/src/device.rs`, `boxcar-vmm/src/devices/mod.rs` | unit: mock TX chain reaches the stack, stack frame lands in RX with the 12-byte header. KVM: guest has 10.0.2.15; `--allow example.com` makes `wget -qO- http://example.com` work; `wget https://blocked.example` fails; audit has `net.dns`, `net.connect`, `net.tls{sni}` |
| M2.8 (L) | vsock port: csm, muxer, killq, rxq, txbuf, device, hybrid UDS, InternalServices, privileged-src-port rule | `boxcar-vsock/src/**` | ported CH tests pass. KVM: host `socat UNIX-LISTEN:$STATE/vsock.sock_5000 -` with `--vsock-allow 5000` and guest `socat - VSOCK-CONNECT:2:5000` exchange data; `CONNECT 5001` gets `OK`; unprivileged guest connect to 2:1024 refused and audited |
| M2.9 (M) | init v2: ctl client, config, PTY session, relay, resize, exit report, graceful shutdown, cgroups | `boxcar-init/src/{vsock,pty,session}.rs`, `boxcar-proto/src/guest.rs`, `boxcar-vmm/src/guest_ctl.rs` | KVM: `boxcar run ... -- /bin/sh -c 'exit 7'` exits 7 and records `session.exit{code:7}` |
| M2.10 (M) | PtyHub, `pty.attach/resize`, `boxcar attach`, interactive `run` | `boxcar-vmm/src/pty.rs`, `boxcar/src/attach.rs` | KVM: `boxcar run ... -- /bin/sh -l` is interactive; `stty size` matches the host and follows resize; `boxcar attach <id>` from a second terminal mirrors output |
| M2.11 (M) | `audit.subscribe` with replay and lag recovery, `LogReader`/`Filter`, `policy.get/update`, schemas, docs | `boxcar-audit/src/{subscribe,reader}.rs`, `xtask/src/schema.rs`, `docs/{control-protocol,audit-events}.md` | `boxcar events --from 0 | head` shows seq 1..; `boxcar policy allow api.github.com:443` flips a live verdict and records `policy.changed`; `cargo xtask schema && git diff --exit-code proto/` |
| M2.12 (S) | virtio-fs multiqueue, perf baseline | `boxcar-fs/src/device.rs`, `docs/perf.md` | KVM: 4 request queues; record `tar -xf` and `npm ci` timings |
| M2.13 (M) | M2 gated e2e tests | `crates/boxcar/tests/{kvm_net,kvm_vsock,kvm_pty,kvm_control}.rs` | `cargo xtask test-kvm m2` green |

### M3: sensor and reconciler (about 3–4 weeks)

| ID | Task | Key files | Verify |
|---|---|---|---|
| M3.1 (S) | Vsock port 1026 `SensorIngest` service, `ping/pong` clock offset, `sync` records, session cgroup id passed to the sensor | `boxcar-vmm/src/services/sensor.rs`, `boxcar-init` | KVM: a fake guest client on 1026 lands records in the log with `ring: 1` |
| M3.2 (S) | `boxcar-sensor-common` structs + Pod; nightly/bpf-linker/bindgen/bpftool setup documented; `xtask gen-vmlinux` + `check-vmlinux` | `crates/boxcar-sensor-common/src/lib.rs`, `xtask/src/sensor.rs`, `guest/kernel/.btf-hash` | `cargo build` both features; `cargo xtask gen-vmlinux` produces a committed `vmlinux.rs`; `check-vmlinux` fails on a stale hash |
| M3.3 (L) | eBPF programs (exec, fork, exit, socket_connect, tcp_connect, file_open, memfd, bpf guard) | `crates/boxcar-sensor-ebpf/src/*.rs` | KVM-free lane compiles and BTF-links all objects |
| M3.4 (M) | Sensor userspace: load/attach, ringbuf drain, vsock framing, heartbeat, sensor_status; initramfs inclusion; init starts it before privilege drop | `crates/boxcar-sensor/src/{main,load,drain,vsock,heartbeat}.rs`, `boxcar-init/src/sensor.rs`, `xtask/src/initramfs.rs` | KVM: all programs attach, heartbeat within 2 s, `sensor_status{attached}`; agent uid has no CAP_BPF; `bpf()` from the agent is denied and produces `proc.lsm_deny` |
| M3.5 (L) | Reconciler state, joins (TID->TGID), rules, timers, golden fixtures, `finding` control event | `boxcar-audit/src/reconcile/{state,join,rules,scores}.rs`, `tests/reconcile.rs`, `tests/fixtures/*` | all scenarios pass under `insta`; silence and orphan timers fire under a paused clock; KVM e2e: `curl https://blocked.example` inside yields `net.tls` + deny verdict (ring 0), `proc.exec{curl}` + `proc.connect_attempt` (ring 1), and a `finding{network_anomaly}`, all chain-verified |

### M4: gateway, spans, first real agent (about 3–4 weeks)

| ID | Task | Key files | Verify |
|---|---|---|---|
| M4.1 (M) | `ServiceRegistry` target for `10.0.2.2:8080` / `gateway.boxcar.internal`; gateway server, routing, TLS client, tee | `boxcar-net/src/services.rs`, `boxcar-gateway/src/{server,route,tls,tee}.rs` | loopback test proxies a stub upstream end-to-end with a byte-identical body |
| M4.2 (L) | Anthropic + OpenAI chat + OpenAI responses parsers -> `ModelEvent` -> `llm.*`/`tool.*` records | `boxcar-gateway/src/parse/{anthropic,openai_chat,openai_responses,model}.rs`, `tests/fixtures/*` | parser snapshots; two-request span test; malformed-tail degrade; redaction test |
| M4.3 (M) | Key injection + env injection through `config.env`; `boxcar run --provider anthropic --api-key-env` | `boxcar-gateway/src/auth.rs`, `boxcar-init` | recorded request has no auth value; placeholder key works end-to-end against a stub |
| M4.4 (M) | Reconciler span attribution (`span` field on effects), `span.list` op; defaults 2 GiB / 2 vCPUs | `boxcar-audit/src/reconcile/spans.rs` | golden fixture with spans; KVM e2e: Claude Code inside runs a Bash tool; `tool.open`/`tool.close` bracket the tool's `proc.exec` and `fs.close` in one chain-verified log |

### M5: OCI images, policy, exporters, hardening, docs (about 3–4 weeks)

| ID | Task | Key files | Verify |
|---|---|---|---|
| M5.1 (L) | OCI pull (`oci-client`) + unpack (`ocirender`) into `$XDG_CACHE_HOME/boxcar/layers/<digest>`; `AuditFs<OverlayFs>` with per-instance upper; check OverlayFs whiteout mknod needs (wrap to `.wh.` files if CAP_MKNOD is required); ownership override xattr | `boxcar/src/oci.rs`, `boxcar-fs/src/overlay.rs` | `boxcar run --image alpine:3.20 -- /bin/sh -c 'apk add curl'` works unprivileged; audit shows writes in the upper dir |
| M5.2 (M) | `boxcar-policy` TOML, eval functions, defaults, ArcSwap live exceptions with TTL, enforcement in AuditFs and sensor maps | `crates/boxcar-policy/src/{model,eval,defaults,live}.rs` | table-driven tests; a `policy.update` exception flips a live verdict and reverts on TTL |
| M5.3 (M) | Exporters: OTLP spans (tool spans, findings as span events) and OCSF JSON; `boxcar audit record --bless` | `boxcar-audit/src/export/{otel,ocsf}.rs`, `boxcar/src/cmd/audit.rs` | snapshot tests; re-recording a fixture re-blesses deterministically |
| M5.4 (M) | Hardening: seccompiler filters for VMM threads, Landlock on the VMM process; `boxcar doctor` fix-its for WSL2 | `boxcar-vmm/src/hardening.rs`, `docs/wsl2.md` | e2e suite still green under filters; doctor prints the modprobe/setfacl hints |
| M5.5 (S) | Docs (`architecture`, `boot`, `audit-events` covering every type, `reconciler`, `ebpf-license`, `perf`), README, release workflow | `docs/*.md`, `.github/workflows/release.yml` | `cargo deny check` green with the allowlist (Apache-2.0, MIT, BSD-2/3, 0BSD, ISC, Unicode-3.0, Unlicense, CC0-1.0, CDLA-Permissive-2.0) |

## Verification

- **KVM-free (default CI on ubuntu-latest):** `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo nextest run --workspace`, `cargo deny check`, musl build of init and sensor userspace, eBPF build lane (nightly + bpf-linker via binstall, no load). Covers boot layout/MPTable/page tables, virtio glue with mock queues, AuditFs on a tempdir, FUSE server round-trips, smoltcp with synthetic frames, vsock csm/muxer over buffers and UDS pairs, proto golden vectors, chain verify, reconciler goldens, gateway fixtures, policy eval.
- **KVM-gated:** `cargo xtask test-kvm {m1,m2,m3,m4}` behind `[ -e /dev/kvm ]`; locally after `sudo modprobe kvm_amd && setfacl -m u:$USER:rw /dev/kvm`; in CI as a separate job on `runs-on: [self-hosted, kvm]` or a nested-virt runner, gated by `vars.HAS_KVM`.
- **Milestone demos:** M1 = `boxcar run` to an Alpine shell, write a file, exit, `boxcar audit verify` passes and the `fs.close` record carries the right blake3 and guest pid. M2 = interactive agent PTY over vsock, allowed and denied egress visible as `net.*` events, `boxcar attach` from a second terminal. M3 = `curl` to a blocked host produces a joined finding across both rings. M4 = Claude Code inside talking through the gateway with tool spans bracketing effects. M5 = run from an OCI image with a policy file and export the session to OTLP.

## Risks and mitigations

| Risk | Mitigation | Early signal |
|---|---|---|
| vm-memory 0.17.1 pin freezes the rust-vmm stack | one pin table; cargo-deny `multiple-versions=deny`; keep the vm-memory surface narrow; ready to fork fuse-backend-rs (Apache-2.0) to bump | M1.2 |
| Owning the MMIO transport: spec-conformance bugs the Linux driver tolerates silently | register-map tests ported from virtio-device and Firecracker; `--debug-boot` review of the virtio probe lines in dmesg; the M1.8 boot as oracle | M1.9 |
| MPTable-only boot regressions on 6.18 | smoke first, SMP early, `--debug-boot`; plan B minimal ACPI with `acpi_tables 0.2.1` | M1.8, M2.1 |
| virtio-fs without DAX is slow for metadata-heavy workloads | per-share cache policy, multiqueue, perf baseline; DAX stays off because it would bypass audit | M2.12 |
| AuditFs completeness and attribution gaps | forward macro, differential test, MetricsHook counters, handle attribution, documented blind spots | M1.10 |
| Unprivileged host creds (setresuid EPERM) | squash to 0/0; agent runs as the host uid; ownership xattr in M5 | M1.10 |
| smoltcp middlebox pitfalls (any_ip ICMP, SYN/listen ordering, buffers, lost RX wakeups) | dispatcher in front of smoltcp, deferred SYN with `poll_ingress_single`, 256 KiB buffers, synthesized RST, fuzzed parsers, private-range deny | M2.3–M2.5 |
| vsock port effort (raw-pointer packets vs borrowed `VsockPacket`, vm-memory API removals) | keep CH structure 1:1, crib from vhost-device-vsock, port tests first | M2.8 |
| Guest spoofing internal vsock channels | privileged source port + first-connection rule; audit denials | M2.8 |
| No CO-RE: kernel/BTF drift breaks the sensor | generated `vmlinux.rs` committed with a BTF hash guard; sensor reports `btf_ok`/`degraded`; rules down-weighted when hooks are missing | M3.2 |
| Nightly requirement | only the eBPF crate; pinned nightly; `AYA_BUILD_SKIP` for stable lanes; prebuilt bpf-linker | M3.3 |
| Provider API drift | tolerant parsers (unknown events forwarded), `parse_degraded`, fixtures recorded from reality and re-blessable | M4.2 |
| Event volume (FUSE ops in the thousands/s) | bounded channel, per-handle aggregation, verbose-only lookups, sampling only for reads, drop counters in checkpoints | M1.3, M1.13 |
| Clock skew across rings | `ts_host_ns` sole join key; `sync` records via ptp_kvm or vsock RTT; widen join window and mark `low_confidence` on WSL2 | M3.1 |
| WSL2 nested virt quirks (`/dev/kvm` perms, slow exits, hidden CPUID bits, 9p on /mnt/c) | `boxcar doctor` fix-its, event idx + ioeventfd/irqfd everywhere, PTY over vsock, ext4 paths only, second CI environment on KVM runners | M1.4 |
| Ubuntu 20.04 toolchain too old for the kernel | Docker build by default, digest-pinned image | M1.5 |
| PID 1 panic is a kernel panic | single-threaded poll loop, no unwraps, panic hook to kmsg, `panic=1` so the VMM reports a reset | M1.12 |
