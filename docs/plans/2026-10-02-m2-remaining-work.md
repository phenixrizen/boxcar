# M2: remaining work (Tasks 13, 14, 15)

Written 2026-10-02 so that a fresh session can pick up M2 from here with no other context. It supersedes the original M2 plan (`docs/plans/2026-10-01-m2-network-vsock-pty-control.md`) for Tasks 13 to 15. The design spec (`docs/specs/2026-09-29-boxcar-design.md`) stays the authority on anything this document leaves open.

## 1. Where things stand

- Repository: `/home/nater/go/src/github.com/phenixrizen/boxcar`, branch `m2`, based on `main` at `d3be817` (M1 is merged). Head is the `docs:` commit on top of `2bb5800` (Task 13a committed, unreviewed; see below). Nothing is pushed or in a PR for M2 yet.
- Tasks 1 to 12 are done, reviewed and committed. What exists:

| Area | Commits (newest last) |
|---|---|
| Fixed virtio slot table, device enablement, exit codes | `bb93440` |
| SMP bring-up | `e0b50ce` |
| Control protocol v1 types and server (hello, status, stop), `--ready-fd` | `c609fb1`, `b6552fe`, `5f7e7bf` |
| Decoupled console writer, escape always reachable | `4c9c318`, `cf3cf84` |
| `boxcar-net`: frames, ARP, DHCP, ICMP, DNS forwarder, policy v1, TCP relay, UDP NAT, virtio-net, wiring | `949caa1` .. `c004591` |
| `boxcar-vsock` (Cloud Hypervisor port), internal services | `c386202`, `beda850`, `cee3287` |
| Guest control channel, init v2 (PTY session, exit report, graceful shutdown) | `c7d23c2`, `24f82b0`, `6e0522e`, `d0be0e2`, `7646130` |
| PtyHub, `pty.attach`/`pty.watch`/`pty.resize`, `boxcar attach`, interactive `run` over the hub, foreground-only terminal use, SIGTSTP/SIGCONT job control | `ae2b79c`, `655a064`, `98971a8`, `1766214` |

- Verified at `1766214`: `cargo test -p boxcar -p boxcar-vmm` 289 passed; `cargo xtask test-kvm m1` exit 0 with 324 passed (it also runs the M2 gated tests that exist so far); clippy, fmt and `cargo deny check` clean.
- **Task 13a is committed but unreviewed.** Commits `c5bfbdd` (`audit: live subscriptions with replay and lag recovery`) and `2bb5800` (`cli: events command`) landed after this plan was first written; the tree is clean. The workspace passed 975 tests, clippy, fmt, deny, and `cargo xtask test-kvm m1` at `2bb5800`; by hand `boxcar events --from 0` streamed 76 records byte-identical to the log. Review them against section 4 before building on them. Deviations the implementer declared: the subscribe response is `{"next_seq":N,"sub":K}` (events carry `sub`; a connection may hold four subscriptions); instead of a 16 MiB outbox cap (a 2 MiB cap already existed) the audit forwarder uses `Conn::send_paced`, which waits while 1 MiB is unread and cuts off a client that takes no byte for 30 s, so a slow client lags (`audit.lagged`) and recovers from the log; the reader reuses the verifier's strict duplicate-key parser without hashing; subscribers may see records a failed writer later rolls back (the VMM exits 3 anyway); the control path was written before its tests (mutation checks pass). The `boxcar-vmm` rustdoc `-D warnings` failure is pre-existing (Task 14).

## 2. How to work

- Environment: put `$HOME/.cargo/bin` on `PATH`; Rust is pinned to 1.96.0 by `rust-toolchain.toml`. KVM is available on this machine. The disk is tight (about 20 GB free, `target/` is about 27 GB): never copy the tree or build a second target directory, and never run `git clean`. If space runs out, remove `target/debug/incremental` and `target/doc` first.
- Guest artifacts for the gated tests are in `target/guest` (`vmlinux`, `initramfs.cpio`, `rootfs-alpine`). Rebuild init-side changes with `cargo xtask initramfs` before a gated run.
- Every task ends with all of these clean:
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets --features boxcar-vmm/kvm-tests,boxcar/kvm-tests -- -D warnings`
  - `cargo fmt --all --check`
  - `cargo deny check`
  - `cargo xtask test-kvm m1` for any task that touches the VMM, net, vsock, init or the CLI (boots real VMs, a few minutes); from Task 15 on, `cargo xtask test-kvm m2` too.
- Commits: `git commit -s`, one logical change each, with the subjects given below. Do not push, and do not open a PR, unless asked.
- Tests are written first and must fail for the right reason before the code exists. A test must assert something that would break if the feature broke.
- No `unwrap`, `expect` or `panic!` in non-test code. Every new file has the license header the neighbouring files carry (`// SPDX-License-Identifier: Apache-2.0` and `// Copyright 2026 The boxcar Authors`). Ported third-party code keeps its provenance header and gets a `NOTICE` entry.
- Probe scripts and scratch files go under `/tmp` or the gitignored workspace folders, not into tracked files. Leave no VM running and no directories behind under `$XDG_RUNTIME_DIR/boxcar` or `/tmp`.
- Never log on the VM's stop path (a log write to a stalled stderr can hang the stop); never block the audit writer on a consumer.

## 3. Binding technical constraints

These are exact and apply to Tasks 13 to 15.

- **Pins.** Rust `1.96.0`, edition 2021. The M1 pin set (vm-memory 0.17.1, virtio-queue 0.17.0, virtio-vsock 0.11.0) plus `smoltcp = "0.14"`, `socket2 = "0.5"` (feature `all`), `arc-swap = "1"`, `proptest = "1"` (dev). Task 13b adds `schemars = "0.8"`. No git dependencies, no `[patch]`; `deny.toml` stays satisfied.
- **Fixed virtio slots.** Slot 0 virtio-fs `root` at `0xC000_0000` GSI 5; slot 1 virtio-fs `workspace` at `0xC000_1000` GSI 6; slot 2 virtio-net at `0xC000_2000` GSI 7; slot 3 virtio-vsock at `0xC000_3000` GSI 8. A disabled device leaves its slot empty.
- **Guest network.** Guest `10.0.2.15/24`; gateway, DNS and DHCP server `10.0.2.2`; guest MAC `02:62:6f:78:00:01`, gateway MAC `02:62:6f:78:00:02`; lease 24 h; hostname `boxcar`; IPv6 dropped.
- **Policy v1.** Rules are `domain[:port]` (exact or `*.suffix`) and `cidr[:port]`, with `default = deny | allow`. Built-in deny for `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16` (plus `0.0.0.0/8` and the host's own interface addresses) unless a rule explicitly allows the exact CIDR. The gateway `10.0.2.2` is always reachable for DNS and DHCP. The live policy is an `Arc<ArcSwap<Policy>>` (`Vmm::policy()` returns it; the net thread reads it).
- **vsock.** Guest CID 3, host CID 2. Guest to host ports: 1024 `boxcar.ctl` (JSON lines), 1025 `boxcar.pty` (one JSON header line, then raw bytes), 1026 `boxcar.sensor` (reserved). Internal ports accept only a guest source port below 1024 and only the first connection per port; any other guest-to-host port goes to `<state>/vsock.sock_<port>` only if allowlisted, else RST and an audited denial. Host to guest uses the hybrid protocol on `<state>/vsock.sock`: `CONNECT <port>\n` then `OK <port>\n`.
- **Control protocol v1.** Unix stream socket `<state>/control.sock`, mode 0600 in a 0700 state directory (default `$XDG_RUNTIME_DIR/boxcar/<session_id>/`, fallback `/tmp/boxcar-<uid>/<session_id>/`); `SO_PEERCRED` uid must equal the VMM's; UTF-8 JSON lines, 1 MiB maximum line. Server first: `{"v":1,"event":"hello","protocol":"boxcar.control","versions":[1],"server":"boxcar/<version>","session_id":"...","capabilities":[...]}`. Request `{"v":1,"id":<u64>,"op":"<op>",...}`; response `{"v":1,"id":N,"ok":true,"result":{...}}` or `{"v":1,"id":N,"ok":false,"error":{"code":"...","message":"..."}}`; event `{"v":1,"event":"<name>",...}`. Error codes, exactly: `bad_request unsupported_version unknown_op invalid_state not_found busy rate_limited internal`. Every message type has a size cap and a test. Unknown fields are ignored and unknown events tolerated. More than 100 requests per second gets `rate_limited`. The hello advertises only what is implemented; today `["pty"]`, and Task 13a adds `audit`, Task 13b `policy.net`.
- **Control ops that exist:** `status`, `stop`, `pty.attach` (returns `{raw:true, attach_id}` and turns the connection into raw bytes), `pty.watch{attach_id}` (events about that attach, such as `pty.detached`, on a second connection), `pty.resize`. The module docs of `crates/boxcar-vmm/src/control/ops.rs` describe them and the way events from elsewhere reach a connection's outbox; `audit.subscribe` should reuse that mechanism.
- **Guest to VMM messages** (`boxcar-proto::guest`, JSON lines on vsock 1024, 64 KiB maximum): guest to host `hello`, `session.started{pid}`, `session.exited{code?, signal?}`, `pong`, `log`; host to guest `config`, `resize`, `signal`, `shutdown`, `ping`.
- **Audit record types** (exact `type` strings): the M1 `fs.*` types plus `net.dhcp`, `net.dns`, `net.connect`, `net.tls`, `net.close`, `net.drop`, `net.udp`, `vsock.connect`, `vsock.close`, `session.start`, `session.exit`, `policy.changed`, `control.connect`, `control.stop`, `sync`. `fs.close` gains `ts_release_ns` (producer time). An optional `path_b64` appears on every `fs.*` payload that has a `path`, set when the name was not valid UTF-8 (Task 14). `policy.changed` does not exist in the code yet (Task 13b).
- **Modes.** Every file or socket the VMM creates after the shares are imported gets an explicit mode (the umask is 0 after `PassthroughFs::import`): sockets 0600, directories 0700, logs 0600.
- **Exit codes of `boxcar run`:** the guest session's exit code when init reported one; 128 + signal when the session was killed by a signal; 0 on a clean reset with no session report and after `boxcar stop`; 1 on a vCPU error; 3 when the audit log could not be written; 130 after SIGINT or the console escape; 143, 129, 131 after SIGTERM, SIGHUP, SIGQUIT.
- **Terminal behaviour already implemented (do not regress).** The terminal is read and put in raw mode only from its foreground process group; a run started in the background does not take it; `kill -TSTP` (or Ctrl-Z while cooked) gives the terminal back as it was and stops the process, `fg` takes it again, `bg` leaves it to the shell. SIGTSTP and SIGCONT are blocked on every thread and read by a `job-control` thread (`crates/boxcar-vmm/src/stdin.rs`).

## 4. Task 13a: audit subscriptions, reader filters, `audit.subscribe`, `boxcar events`

Files: `crates/boxcar-audit/src/{subscribe,writer,reader,sink,lib}.rs`, `crates/boxcar-vmm/src/control/ops.rs`, `crates/boxcar-proto/src/control.rs`, `crates/boxcar/src/cmd/events.rs`, `crates/boxcar/src/client.rs`; tests `crates/boxcar-audit/tests/subscribe.rs`, reader unit tests, `crates/boxcar/tests/events_cli.rs`. Start by reviewing commits `c5bfbdd` and `2bb5800` (section 1) against these requirements; fix what the review finds, then continue.

Requirements:
- The writer publishes an `Arc<Record>` to live subscribers after chaining and writing a record, through a bounded per-subscriber queue (16384). The writer never blocks on a subscriber.
- `Subscription` replays from the log files for `seq` below the sequence the writer reported at subscribe time, then drains the live queue with no gap and no duplicate. On queue overflow it yields an `audit.lagged{resume_seq}` item and resumes from the files (and keeps doing so however often it lags). Replay spans rotated segments. A `from_seq` in the future waits for live records. The subscription ends when the writer closes.
- Reader `Filter { kinds: Vec<String> /* prefixes */, pid: Option<u32>, min_score: Option<u8> }`; `LogReader::records_from(seq)`; duplicate JSON keys rejected on the reader path as on the verify path (reuse the verifier's raw-line parsing).
- Control op `audit.subscribe{from_seq?, types?[prefixes], pid?}` returns `{next_seq}`, then `audit{sub, rec}` events on that connection until it closes, and `audit.lagged{resume_seq}` events. Add `audit` to the hello's capabilities. A slow control client must not hold up the writer or the VM: bound the connection's outbox and close it (or report lag) when it overflows.
- The control client's `Client::pending` queue has no cap today; give it one, since an event stream makes it matter.
- CLI: `boxcar events [--from SEQ] [--type PREFIX]... [SESSION_ID]` streams records as JSON lines, one per line, until the session ends or the pipe closes; the session is `--control` or `SESSION_ID`, or the only one running (same discovery as `status`).
- Tests (names are a guide): `replay_then_live_without_gaps`, `a_lagged_subscriber_gets_resume_seq_and_recovers`, `filters_by_prefix_and_pid`, `reader_rejects_duplicate_keys`, a control-level test of `audit.subscribe` through the ops, and `events_streams_from_a_fake_server`.
- Commits: `audit: live subscriptions with replay and lag recovery`, then `cli: events command` (the control op lands with the second).
- Verify: `boxcar events --from 0 <id> | head` prints seq 1 onward during a run.

## 5. Task 13b: policy ops with live revocation, `boxcar policy`, schemas, docs

Files: `crates/boxcar-vmm/src/control/ops.rs`, `crates/boxcar-proto/src/control.rs`, `crates/boxcar-net/src/{policy,tcp/*,udp}.rs`, `crates/boxcar-vsock/src/*`, `crates/boxcar/src/cmd/policy.rs`, `xtask/src/{main,schema}.rs`, `proto/schema/`, `proto/testdata/`, `docs/control-protocol.md`, `docs/audit-events.md`, `.github/workflows/ci.yml`.

Requirements:
- `policy.get` returns `{net:{default, allow[], deny[]}, vsock:{allow_ports[]}}`. `policy.update{net?, vsock?}` returns `{policy_version}`, swaps the live policy atomically, and records and emits `policy.changed{by_pid, version}`. Add `policy.net` to the hello's capabilities. Reject malformed rules with `bad_request`, naming the rule.
- **Live revocation.** After a net update, connections that are already open and that the new policy denies are closed (RST to the guest, host socket closed, UDP mappings dropped) and recorded in `net.close` with a reason that says why (suggested: `policy`; document the string). Connections the new policy still allows are untouched.
- **vsock hot swap.** The vsock allowlist (`--vsock-allow`) becomes swappable the same way (an `ArcSwap`), read when a guest connects.
- CLI: `boxcar policy allow RULE`, `boxcar policy deny RULE`, `boxcar policy show`.
- Schemas: add `schemars = "0.8"`; `cargo xtask schema` writes `proto/schema/{control-v1,audit-v1,guest-v1}.json` and refreshes `proto/testdata/control-v1.jsonl`; CI runs it and fails on `git diff --exit-code proto/`.
- Docs: `docs/control-protocol.md` (every op, event and error with fields) and `docs/audit-events.md` (every `type` string with fields).
- Tests: `policy_update_flips_a_live_verdict_and_records_policy_changed`, a live-revocation test with a real relayed flow, a vsock hot-swap test, ops-level `policy.get`/`policy.update` tests including a malformed rule, and a CLI test against a fake server.
- Commits: `vmm, net, vsock: policy ops with live revocation`, then `cli, docs: events and policy commands; schemas`.
- Verify: `boxcar policy allow api.github.com:443` changes a subsequent connect's verdict; `cargo xtask schema && git diff --exit-code proto/` is clean.

## 6. Task 14: virtio-fs multiqueue, hash-worker restart, producer timestamps, non-UTF-8 names, and the debt bundle

Files: `crates/boxcar-fs/src/{device,audit_fs,hasher,events,path_map}.rs`, `crates/boxcar-proto/src/audit/payloads.rs`, `crates/boxcar-proto/src/ids.rs`, `crates/boxcar-audit/src/segment.rs`, `crates/boxcar-vmm/src/stdin.rs`, `guest/kernel/build.sh`, `.github/workflows/ci.yml`, `crates/boxcar/src/cmd/run.rs`; tests `crates/boxcar-fs/tests/{virtio_roundtrip,auditfs}.rs`; `docs/perf.md`.

Requirements:
- `VirtioFs::new(.., num_request_queues: u16)` with `min(vcpus, 4)` from the VMM; one worker per request queue; the hiprio queue on the first.
- `AuditFs::restart_hashing()` is called on device re-activation, so a mid-session reset does not leave hashing inline.
- `FsClose` gains `ts_release_ns: u64` (CLOCK_REALTIME at release, producer side). Every `fs.*` payload with `path` gains `path_b64: Option<String>` (skipped when none), set when the raw name was not valid UTF-8, with `path` holding the lossy form.
- `SessionId` loses its `Default` impl. `boxcar_audit::SESSIONS_DIR` is the single `"sessions"` constant used by the writer and the CLI's audit-directory check.
- `guest/kernel/build.sh`: the `.BTF` check becomes `readelf -S vmlinux | grep -Eq '\] \.BTF +'`.
- CI: pin `cargo-deny` to `0.20.2` and pin action references to commit SHAs.
- Tests: `four_request_queues_serve_requests_concurrently`, `reactivation_restarts_the_hash_threads`, `fs_close_carries_the_release_time`, `a_non_utf8_name_gets_path_b64` (a file named `b"a\xff"`: `path == "/a\u{fffd}"`, `path_b64 == Some(base64("/a\xff"))`), `session_id_has_no_default`, and the existing suites plus the gated `boot_console` test.
- Measure `tar -xf` of the Alpine tarball and an `npm ci`-sized tree copy inside the guest with 1 and 4 queues, and record both in `docs/perf.md`.
- Commits: `fs: multiqueue, hash restart, release timestamps, non-UTF-8 names`, then `build, proto, audit: M1 debt (BTF grep, CI pins, SessionId default, sessions constant)`.

Debt carried into this task from earlier work (do them in the second commit or a third, `vmm: console mode foreground rule and test debt`):
1. **M1 console mode (`--no-vsock`, interactive).** `StdinSubscriber::on_stdin` (`crates/boxcar-vmm/src/stdin.rs`) reads fd 0 on the main loop with SIGTTIN unblocked, so after `kill -TSTP` and `bg`, or a start with `&`, the first line typed for the shell stops the VM again (`Stopped (tty input)`). Apply the foreground rule the `pty-stdin` thread uses (only read when `is_foreground`; otherwise leave the fd unread and look again later), without breaking the escape (Ctrl-] twice) in the foreground.
2. **Missing test.** Nothing covers the restore after the post-write foreground re-check in `Tty::take` (`stdin.rs`, the branch that restores `current` when the process moved to the background between the check and the write). Technique that worked as a probe: in an integration test of `boxcar-vmm`, define `#[no_mangle] pub extern "C" fn tcsetattr(..)` in the test binary that looks up the real one with `dlsym(RTLD_NEXT, "tcsetattr")`; on the first call it asks a forked "shell" (session leader with the PTY as controlling terminal, SIGTTOU blocked) to `tcsetpgrp` the terminal back, waits for the acknowledgement, then performs the real write. The job (forked, own process group, default signal dispositions and mask) calls `RawModeGuard::enter()`: expect `None`, the settings restored field for field, and the job not stopped. Control in the same harness: a plain `tcsetattr` from the background with SIGTTOU unblocked is stopped by the kernel.
3. **Rustdoc.** `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` fails on older warnings plus two new ones. Known: unclosed HTML tags `<uid>` and `<session-id>` in help text (`crates/boxcar/src/cli.rs` near lines 187 and 289), `crates/boxcar-vmm/src/arch/x86_64/cpuid.rs` lines 70 and 159, `stdin.rs` lines 27 and 468 (public docs linking private items), `crates/boxcar/src/cmd/attach.rs` line 14 (redundant explicit link target). Fix them all and add the command to CI.
4. **Net device.** The TX drain in the virtio-net device is a private copy of `drain_queue` with stop checks; a `drain_queue_until` predicate would remove the copy.
5. **Smaller items** (do them if they are cheap, otherwise list them in the docs as limits): a test whose split TX chain exceeds the 64 KiB bound; `// boxcar:` comments on the muxer constructor's field initializers; a hash job that panics never records its `fs.close` (record `HashStatus::Error` from the guard); up to 64 KiB pending in the VMM's vsock connection buffer is dropped at a guest reset without a report.

## 7. Task 15: M2 gated end-to-end suite, `cargo xtask test-kvm m2`, and documentation

Files: `crates/boxcar/tests/kvm_m2.rs`, `docs/networking.md`, `xtask/src/test_kvm.rs`, `README.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`.

Requirements:
- `cargo xtask test-kvm m2` runs the M1 suite plus `kvm_m2.rs` and the gated `boot_{smp,net,vsock,session,attach}.rs` with `--test-threads=1 --nocapture`, exporting `BOXCAR_TEST_NET=1` only when `example.com` resolves from the host. Add `m2` to the `Milestone` enum in `xtask/src/test_kvm.rs` (today only `m1` exists, and its help text says it also runs the M2 tests until this task lands: update that).
- `kvm_m2.rs` drives the real binary: (a) `--allow example.com -- wget -qO- http://example.com` exits 0 with the page in the console log and `net.connect{verdict:"allow"}` in the session log; (b) `-- wget -qO- http://blocked.example` fails and the log has a deny; (c) `-- /bin/sh -c 'exit 7'` exits 7; (d) `boxcar status` during a run shows `running`, and `boxcar stop` ends it with exit 0 and a `control.stop` record; (e) `boxcar events --type net. <id>` after (a) prints at least the DHCP, DNS, connect and close records; (f) `boxcar policy allow blocked.example` during a run makes a second wget succeed and records `policy.changed`. They skip with a printed reason without the artifacts or KVM.
- README: a "Networking and policy" section (`--allow`, `--policy-file`, the built-in private-range deny, the audit events); an "Attach" section (detach with Ctrl-P Ctrl-Q, `--ro`, `--replay`, several terminals, the 1 MiB per-client limit and `pty.detached`); an exit-code table; a short "Job control" note (a stop gives the terminal back, `fg` takes it again, a run started in the background leaves the terminal alone). CONTRIBUTING: `cargo xtask test-kvm m2`. CI: document the KVM job gate `vars.HAS_KVM`.
- Documentation items collected from earlier reviews, to state in `docs/networking.md` or the README as known behaviour:
  - on a terminal, Ctrl-C reaches a `-- CMD` session (raw mode); Ctrl-] twice stops the VM;
  - piped input with `--stdin` whose end-of-file reaches the guest before its shell is ready can hang that shell (`printf ... | boxcar run --stdin -- /bin/sh`);
  - in vsock mode the kernel and init messages go to `<state>/console.log` (`--console-log`, `--console-stdout`);
  - `--no-vsock` is M1's console session: stdin is not forwarded for `-- CMD`, and (until Task 14's item 1 lands) a backgrounded interactive console run stops on the first line typed for the shell;
  - policy flags are rejected with `--no-fs` and no `--net`;
  - the net thread wakes every millisecond while the guest posts no receive buffers and smoltcp has data (bounded);
  - an attach client that lets 1 MiB of output pile up, or takes nothing for 30 s, is detached by the VMM (`pty.detached`, reason `slow`); a `boxcar attach` that is stopped with Ctrl-Z or `kill -TSTP` for long enough can hit this (confirm the exact rule in `crates/boxcar-vmm/src/pty/raw.rs` and `pty.rs` before writing it down).
- Commit: `cli, xtask, docs: M2 e2e suite and documentation`.
- Verify: `cargo xtask test-kvm m2` is green on this machine, with its output kept for the hand-off; the README sections exist.

## 8. Finishing M2

1. All commands in section 2 are clean at the final commit, plus `cargo xtask test-kvm m2`.
2. A last read of the whole branch against `main` (`git diff main...m2 --stat`, then the control protocol, audit event and policy code paths) for anything that contradicts section 3.
3. Then, if asked: push `m2` and open a PR against `main`.

## 9. Decisions (appended while executing this plan)

Judgment calls made while carrying out sections 4 to 8, each also in the
commit that made it. Written 2026-10-02.

### Task 13a review (`91f26fe`)

- `Subscription::next_timeout` returns `Idle` after passing over 1024
  records of a replay without one to deliver (`REPLAY_YIELD`), so a
  forwarder on a long filtered replay sees its connection close and the
  stop sequence is not held waiting for it. `next` still reads through.
- The audit forwarder logs at debug, not warn, when a subscription fails:
  its thread is joined by the connection's, which the stop sequence joins,
  and a stalled stderr must not hold the stop.
- Accepted as declared: the `sub` field in the `audit.subscribe` response,
  four subscriptions a connection, the 16384-record (not byte) queue bound,
  and that a failed writer may have streamed records it then cut off. The
  reader needs no guard against a half-written line: `SegmentWriter` writes
  whole lines only.

### Task 13b (`4bd1861`, and the commit after it)

- `policy.get` reports a `version` beside `net` and `vsock`, so a client
  knows which policy it read; `policy.update` returns `policy_version`.
- The network policy's wire shape loses rule interleaving: the policy in
  force puts every deny before every allow, as `boxcar run` orders `--deny`
  and `--allow`. Documented in `docs/control-protocol.md`.
- `policy.update` with `net` on a VM without a network card, or `vsock`
  without a vsock device, is `invalid_state` rather than an inert success.
- A connect still under way when the policy changes is given up as a
  timed-out one is (reset, `net.close{reason:"policy"}`): it had a
  `net.connect{allow}` and so gets its `net.close`.
- Revocation decides each open flow as it was first decided: on the names
  the DNS cache gave the destination then (UDP mappings now keep them),
  not on the TLS server name the gate saw, which the flow does not keep.
- Connections already made to a vsock port taken off the allowlist stay
  open; the list is read at each request only.
- `boxcar policy allow RULE` also takes RULE out of the denies (and `deny`
  out of the allows), so the two toggle a target; a rule already in its
  list sends no update. A rule that does not parse exits 2 before any
  connection, as `boxcar run` does. The vsock allowlist is changeable over
  the protocol only; the CLI shows it.
- The schemas are generated by `cargo xtask schema` from
  `#[cfg_attr(feature = "schema", derive(JsonSchema))]` on the proto
  types (an optional feature, on for xtask only, so the musl guest init is
  unaffected); `Hash`, `SessionId` and `Ring` have hand-written schemas.
  `proto/testdata/control-v1.jsonl` holds one example of every message,
  checked by `crates/boxcar-proto/tests/control_golden.rs`.

### Task 14

- `path_b64` is set on every `fs.*` payload with a `path` and on no other
  name (`path_at_open`, `target_path`, `target`, `from`, `to` stay lossy
  text), and covers at most the first 4096 bytes of the raw path, as
  `path` is cut to 4096.
- `ts_release_ns` is taken when the handle is released, before the hash
  job is queued, so it is the producer's time whatever the hash takes.
- A hash thread that panics now records its job's close as `error`
  (plan item 5c): the `Finished` guard carries the close until the normal
  record is made. The two existing panic tests expect that record.
- `FsDevices::attach` takes `FsOptions { audit, request_queues }` so that
  it keeps seven arguments (clippy's bound); `request_queues(vcpus)` is
  `vcpus.clamp(1, 4)`.
- The perf measurements are of a debug build, the only one on the machine
  (a release target would not fit the disk), and say so.
- Plan items 5a (a split TX chain over the 64 KiB bound) and 5b (`//
  boxcar:` comments on the muxer's own fields) were already in the tree
  (`a_split_tx_chain_over_64_kib_is_read_only_to_its_bound`; every
  boxcar-added field initializer in `VsockMuxer::new` carries one); 5d is
  documented in docs/audit-events.md's `vsock.close` row.
- The stdin console subscriber reads only in the foreground (debt item 1):
  in the background it unwatches stdin and polls the foreground every
  200 ms from a timerfd; tested on a pipe with an injected foreground
  predicate, in a real event loop.
- `target/debug/incremental` was removed once to make room for the builds
  (the disk was down to nothing during the workspace test build).
