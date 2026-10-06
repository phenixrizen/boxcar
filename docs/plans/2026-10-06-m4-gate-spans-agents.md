# M4: model traffic gate, spans, Claude Code and Codex running inside

**Goal:** After M4, a session's log holds what the agent asked its model and what the model told it to do, taken on the host where the guest cannot alter it, with no credential ever held by boxcar. For a destination the policy marks `inspect`, the network stack ends the guest's TLS with a certificate from a per-session CA the guest trusts, opens its own verified TLS connection to the real host, relays the plaintext unchanged both ways, and observes it: every HTTP/1.1 and HTTP/2 exchange becomes `http.request` and `http.response`, and the model APIs it knows (Anthropic Messages; OpenAI chat and responses, the latter also over WebSocket) become `llm.*` and `tool.*` records. A `tool.open` opens a span, the `tool.close` in the agent's next request closes it, and the reconciler attributes the processes and effects in between to it, fires `intent_effect_mismatch` and `orphaned_work`, and answers `span.list`. The sensor reports the size and time of each TLS write and read of a process whose runtime exports OpenSSL's functions, so the reconciler can name the process behind a model request. `boxcar run --dump DIR` writes the guest's frames, the decrypted streams and each decoded exchange, after bitvessel's `DebugNet`. Claude Code (the native build and the npm build under Node) and Codex run inside a Debian guest on their own account logins, and a Bash tool call brackets its `proc.exec` and `fs.close` in one chain-verified log.

The design this plan argues from is `docs/specs/2026-09-29-boxcar-design.md` as amended on 2026-10-06 (its section 14), which replaced the model gateway with this gate. The roadmap's "Gateway (`boxcar-gateway`, M4)" section and its M4.1 to M4.4 rows are superseded by this plan where they differ.

## 1. Where things stand

- Repository `/home/nater/go/src/github.com/phenixrizen/boxcar`, branch `m4`, created from `m3` at `8ea1913`. M3 is PR #3 against `main` (https://github.com/phenixrizen/boxcar/pull/3), CI green, mergeable, not merged when this was written. When PR #3 merges, merge `main` into `m4` before opening M4's PR; do not rewrite commits that are already pushed without asking.
- What M4 can lean on, with the file that has it:

| Exists | Where |
|---|---|
| The TCP relay: deferred SYN, `FlowState::{Gating, Relaying, Ending}`, `GateBuf` holding a gated flow's first bytes, `gate()` reading a ClientHello (`sni::parse_client_hello` → `Hello{sni, alpn}`) or an HTTP `Host` (`http_host::parse_request`), `Policy::gate_allows(name, port)`, `net.tls` | `crates/boxcar-net/src/tcp/{relay,flow}.rs`, `sni.rs`, `http_host.rs`, `policy.rs` |
| Policy v1: `Rule{verdict, target: Domain{pattern, port} | Cidr{net, port}, text}`, `Policy::parse(lines)`, `ArcSwap<Policy>` hot-swapped by `policy.update`; wire `NetPolicy{default, allow[], deny[]}` | `crates/boxcar-net/src/policy.rs`, `crates/boxcar-proto/src/control.rs` |
| `audit::emit` (blocking) and `audit::try_emit` (droppable, `net.drop`) on the net thread; `Drops` counting by reason | `crates/boxcar-net/src/audit.rs`, `stack.rs` |
| `Source::Gateway` (unused), `Record.span: Option<SpanRef{trace_id, span_id}>`, `Payload` with 47 kinds, `Finding{span_id: Option<String>}` | `crates/boxcar-proto/src/audit.rs`, `audit/payloads.rs` |
| `SessionConfig{argv, env, cwd, uid, gid, hostname, term, rows, cols, sysctls}` sent over the guest control channel; init's `pty::session_env`, `resolver.rs` (writes a file on the `/run` tmpfs and bind-mounts it over `/etc/resolv.conf`, following links, creating what is missing) | `crates/boxcar-proto/src/guest.rs`, `crates/boxcar-init/src/{pty,resolver,mounts,session}.rs` |
| The reconciler: `State{procs, pending, flows, sensor, dns, ...}`, `rules::observe`, `rules::on_tick`, `Draft` findings with evidence, blessed fixtures (`BOXCAR_BLESS=1`), `ManualClock` | `crates/boxcar-audit/src/reconcile/{mod,state,rules,clock,dns,paths}.rs`, `tests/reconcile.rs`, `tests/fixtures/*.jsonl` |
| The sensor: `load::load(session_cgroup, sensor_tgid)`, `PROGRAMS: [Program; 9]` with `ProgramKind::{BtfTracepoint, Lsm, SleepableLsm, FEntry}`, the eBPF lane (`cargo xtask sensor`) checking names, kinds, maps, globals and licence | `crates/boxcar-sensor/src/{main,load}.rs`, `crates/boxcar-sensor-common/src/programs.rs`, `crates/boxcar-sensor-ebpf/src/*.rs`, `xtask/src/sensor.rs` |
| `boxcar run --audit-level verbose` (`fs.read`, `fs.write`, `fs.readdir`), `--allow`, `--deny`, `--policy-file`, `--dns`, `--no-sensor`; `boxcar events`, `boxcar policy`, `boxcar audit verify`; `cargo xtask rootfs alpine` (minirootfs 3.22.6, with busybox `wget` and `ssl_client` linking `libssl.so.3`, and `ca-certificates-bundle` at `/etc/ssl/certs/ca-certificates.crt`) | `crates/boxcar/src/{cli.rs,cmd/*.rs}`, `xtask/src/rootfs.rs` |
| The gated harness: `guest_or_skip`, `networked_guest_or_skip`, `boxcar_run(guest, scratch, flags, command) -> Run{records(), stdout(), ...}`, `start(...)` for a live session with `control()`, `of_kind`; `cargo xtask test-kvm {m1,m2,m3}` | `crates/boxcar/tests/kvm_harness/mod.rs`, `tests/kvm_m3.rs`, `xtask/src/test_kvm.rs` |

- What does not exist: an `inspect` rule; any CA; any TLS code (the lock file has no `rustls`, `ring` or `rcgen`); an HTTP parser beyond the request line and `Host`; any `http.*`, `llm.*`, `tool.*`, `span.*`, `net.inspect`, `proc.tls_io` or `proc.tls_attach` payload; spans in the reconciler; `span.list`; a uprobe in the sensor; a dump mode; a Debian rootfs; `test-kvm m4`.
- The agents, verified on 2026-10-06: Claude Code's documentation says it trusts `NODE_EXTRA_CA_CERTS` and the OS trust store, and that TLS-inspection proxies work with no further configuration once their root is in the OS store; its native build is a Bun executable with BoringSSL compiled in and no symbols for it; its npm build runs under Node, which exports OpenSSL's functions. Codex's workspace manifest pins `rustls 0.23` with `rustls-native-certs` (the OS store) for its Rust binary, which the npm package launches. groundcover's documentation supports TLS capture for OpenSSL, Go `crypto/tls`, Node.js and Java only, and not for stripped binaries.
- The development machine on 2026-10-06: Rust 1.96.0 and `nightly-2026-06-01` with `rust-src`, `bpf-linker 0.11.1`, Docker, KVM; `~/.local/share/claude/versions/2.1.290` (native Claude Code), `@openai/codex` under nvm's Node 25. **The disk had 8.1 GB free** (`target/` is 25 GB, of which `target/debug/deps` 16 GB and `target/kernel-cache` 5.4 GB; `target/debug/incremental`, 631 MB, was removed while this was written since `CARGO_INCREMENTAL=0` never uses it). The new dependencies and the Debian rootfs need about 3 GB; free space before Task 7 if needed and say in the report what was removed.

## 2. How to work

- Environment: `$HOME/.cargo/bin` on `PATH`; Rust 1.96.0 from `rust-toolchain.toml`; build with `CARGO_INCREMENTAL=0`. KVM is available. Never copy the tree, never build a second target directory, never run `git clean`; if space runs out remove `target/doc` and stale `target/debug/deps` artifacts first and say so.
- Guest artifacts live in `target/guest`. Rebuild the initramfs with `cargo xtask initramfs` after any init or sensor change (it needs the nightly and `bpf-linker`; never `AYA_BUILD_SKIP=1` for a gated run). `cargo xtask rootfs alpine` for the stock guest; from Task 7, `cargo xtask rootfs debian` for the agents' guest.
- Every task ends with all of these clean:
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets --features boxcar-vmm/kvm-tests,boxcar/kvm-tests -- -D warnings`
  - `cargo fmt --all --check`
  - `cargo deny check`
  - `cargo xtask schema` leaving no diff under `proto/`
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
  - `cargo xtask sensor` and `cargo xtask check-vmlinux` for any task that touches the sensor crates
  - `cargo xtask test-kvm m3` for any task that touches the VMM, the net stack, init, the sensor, the audit crate or the CLI (it runs M1 to M3's gated tests); from Task 7 on, `cargo xtask test-kvm m4` too. Run it in the background with its output in a log file; it takes about 30 minutes.
- Tests first: a test fails for the right reason before the code exists and asserts something that breaks when the feature breaks. No `unwrap`, `expect` or `panic!` in non-test code. Nothing logs on a vCPU thread or on the stop path. Audit records are emitted with the blocking `emit` except where this plan says `try_emit`. A guest can never block the VMM on a viewer, and ring 1 can never block ring 0. The gate never modifies a byte of the stream it relays. No credential value, header or body, is ever written to a record, a dump file, a log line or a test fixture.
- Every new file carries `// SPDX-License-Identifier: Apache-2.0` and `// Copyright 2026 The boxcar Authors`, except the eBPF crate's sources, which carry `// SPDX-License-Identifier: MIT OR GPL-2.0` with the same copyright line.
- Commits: `git commit -s`, one logical change each, subjects from this plan verbatim, body ending with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, `Claude-Session: <the executing session's URL>`, then the sign-off. Never commit `target/`. Do not push or open a PR until section 7 says so.
- Every judgment call goes into the commit message or section 8 (Decisions), appended as work proceeds. Deferred findings are reported at the end, explicitly.

## 3. Binding technical constraints

These are exact and apply to every task.

- **Pins.** Workspace additions, crates.io only, no git dependencies, no `[patch]`: `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }`, `rustls-pki-types = "1"`, `rustls-native-certs = "0.8"`, `rcgen = { version = "0.14", default-features = false, features = ["crypto", "ring", "pem"] }`, `flate2 = "1.1"` (its default pure-Rust `miniz_oxide` backend), `brotli-decompressor = { version = "6", default-features = false, features = ["std"] }`. `aws-lc-sys` stays banned; `ring` builds C and assembly through `cc` the way `blake3` does, on the host only (no guest crate depends on `boxcar-net`). `deny.toml` gains `ISC` (`ring` is `Apache-2.0 AND ISC`; `rustls-webpki` and `untrusted` are `ISC`), a recorded decision. No `tokio`, `hyper`, `h2` or any async runtime: the gate is sans-IO on the net thread, like smoltcp.
- **Policy.** A third line kind, `inspect TARGET`, where `TARGET` is a domain pattern or a CIDR with an optional port, exactly as `allow` and `deny` take them. It does not decide a verdict: a flow is admitted by `allow`/`deny` as today, and an admitted TLS flow whose gate name (the ClientHello's server name, or, for a CIDR rule, the destination) matches an `inspect` rule is inspected. A plain HTTP flow matching one is observed without TLS. `Policy::inspects(name: Option<&str>, dst: SocketAddrV4) -> Option<&Rule>`; `NetPolicy.inspect: Vec<String>` (`#[serde(default)]`), reported by `policy.get`, taken by `policy.update` for the flows that follow (an open flow keeps its state). `boxcar run --inspect RULE` (repeatable, refused with `--no-net`), and `inspect` lines in `--policy-file`. A session has a CA only when its policy has an `inspect` rule at start.
- **The session CA.** Made at `boxcar run` with `rcgen`: ECDSA P-256, subject `CN=boxcar session <session_id>`, `CA:true`, path length 0, valid from one hour before now for 30 days. Leaf certificates per inspected name (or IP, as a SAN), signed on first use, valid for the same period, cached (at most 1024, oldest evicted). The key material lives only in the VMM's memory (`SessionCa` behind an `Arc`); nothing writes it to disk. `vmm.start` gains `inspect_ca_sha256: Option<String>` (omitted when there is no CA): the SHA-256 of the CA certificate's DER as lowercase hex, which is how a reader knows which authority a session's guest was told to trust.
- **Guest trust.** `SessionConfig` gains `ca_pem: Option<String>` (`#[serde(default)]`; the config message's size limit grows by 8 KiB for it). When present, init, before privileges drop and after the `/run` tmpfs is mounted on the new root, writes it to `/run/boxcar/ca.pem` (0644), writes `/run/boxcar/ca-bundle.pem` as the root share's `/etc/ssl/certs/ca-certificates.crt` (when that exists, following links as `resolver.rs` does) followed by the session CA, bind-mounts the bundle over `/etc/ssl/certs/ca-certificates.crt` (creating an empty file there first when the rootfs has none, in the root share, which the host records), and adds to the session environment, unless the config's `env` already sets them: `NODE_EXTRA_CA_CERTS=/run/boxcar/ca.pem`, `SSL_CERT_FILE=/run/boxcar/ca-bundle.pem`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and `GIT_SSL_CAINFO` to the bundle. A failure costs the guest its trust in the gate (inspected connections then fail closed inside the guest), never its boot; init reports it as a warning. Without `ca_pem`, init touches none of this.
- **The gate.** For an inspected TLS flow, after `gate()` passes it: `FlowState::Inspecting`. The held ClientHello bytes are fed to a `rustls::server::Acceptor`; the upstream leg is a `rustls::ClientConnection` to the real host (server name from the ClientHello, ALPN as the guest offered, roots from `rustls-native-certs`, TLS 1.2 and 1.3) driven by the existing host socket; when its handshake completes, the guest leg is `acceptor.into_connection(config)` with a per-connection `ServerConfig` carrying the leaf for the name and exactly the ALPN protocol upstream chose (none when none). Plaintext read from one leg is written unchanged to the other, bounded by each side's buffer, with the back-pressure the relay has today; a copy of every plaintext byte, with its direction, goes to the observer (below). Failures and their records: upstream certificate not trusted → `net.inspect{result:"upstream_untrusted"}`, both sides reset, `net.close{reason:"inspect"}`; upstream handshake failed otherwise → `result:"upstream_failed"`; the guest rejected the leaf (an alert, or a close during the handshake) → `result:"guest_rejected"`; handshakes not done within the gate's timeout → `result:"timeout"`. Success: `net.inspect{result:"ok", flow, sni, alpn (the protocol chosen or null), version ("1.2"|"1.3"), rule}` once, before any plaintext moves. `net.tls` gains `inspect: bool` (`#[serde(default)]`). An inspected plain HTTP flow (no TLS) has no `net.inspect`; its bytes go to the observer directly. The gate never writes a byte it did not read from the other leg. For a flow the test harness needs, `BOXCAR_TEST_UPSTREAM_ROOTS=<pem path>` adds roots to the upstream store; only a `kvm-tests` build reads it, as `BOXCAR_TEST_FAIL_AUDIT_AFTER`.
- **The observer.** Thread `gate-observe`, one per VM with a network, fed by a bounded `crossbeam` channel (4096 messages, each at most 64 KiB of plaintext plus its flow, direction and host time). The net thread copies plaintext into it with `try_send`; when the channel is full the chunk is dropped, the flow's streams are marked `degraded{reason:"observer_lag"}` from that byte on (the observer sees a `Lost` marker), and `net.drop{reason:"observe"}` counts it. Nothing on the net thread waits for the observer. The observer owns, per flow, the HTTP state machine (below), the content decoders, the model parsers, the hashes, the records and the dump files; it emits with the blocking `emit` (a full writer stalls the observer, never the net thread). At `vmm.stop` the observer finishes what it holds (open streams end with `degraded{reason:"flow_closed"}`), then exits; `boxcar run` joins it before closing the writer, with a 5 s bound.
- **HTTP.** `boxcar_net::http`: HTTP/1.1 (request line, headers, `Content-Length`, chunked, `Connection: close`, pipelining in order, `101 Switching Protocols` handing the stream to the WebSocket reader) and HTTP/2 (the client preface, frames, `SETTINGS` including `HEADER_TABLE_SIZE`, `HEADERS` and `CONTINUATION`, `DATA` with padding, `RST_STREAM`, `GOAWAY`, `WINDOW_UPDATE` ignored, `PUSH_PROMISE` treated as degraded; HPACK decoded passively per direction with its dynamic table, static table and Huffman code from RFC 7541, size updates honoured). Limits: a header block 64 KiB, header names and values 8 KiB each, a path 4096 bytes, at most 256 concurrent streams per flow; a body is kept for parsing up to **16 MiB** and hashed whatever its size (blake3 over the decoded bytes; `body_truncated: true` past the limit, and the parsers see nothing of such a body). Content decoding: `gzip`, `deflate` (`flate2`), `br` (`brotli-decompressor`); any other `Content-Encoding` leaves the body undecoded with `degraded{reason:"content_encoding"}`. SSE (`text/event-stream`) is split into events (`data:` lines joined, `event:`, `id:`) as bytes arrive. WebSocket (after a 101 with `Upgrade: websocket`): RFC 6455 frames, client frames unmasked, fragments reassembled, text messages handed to the model parser; `permessage-deflate` inflated with context takeover as negotiated; any other negotiated extension is `degraded{reason:"ws_extension"}`. Credentials: the header names `authorization`, `proxy-authorization`, `x-api-key`, `cookie`, `set-cookie`, `x-goog-api-key`, `api-key` and any name ending in `-token` or `-secret` are removed from the header map before it leaves the parser (`Headers::redacted()` is the only accessor), and the values are never copied anywhere, not into the dump either; `redact::scrub` is applied to every summary as defence in depth.
- **Audit record types** (exact `type` strings, additive; ring 0 unless said; sources: `net.inspect` is `Source::Net`; `http.*`, `llm.*` and `tool.*` are `Source::Gate`, the renamed `Gateway` (wire `gate`); `span.*` is `Source::Reconciler`; `proc.*` is `Source::Sensor`, ring 1):
  - `net.inspect{flow, sni: Option<String>, alpn: Option<String>, version: Option<String>, result, rule: Option<String>}`.
  - `http.request{flow, stream, version ("1.1"|"2"), method, authority, path (cut at 4096), content_type, content_encoding, content_length: Option<u64>, user_agent (cut at 512), body_bytes, body_b3 ("b3:..." of the decoded body, or null when empty), body_truncated, degraded: Option<String>}` when the request's body has ended; `http.response{flow, stream, status, content_type, content_encoding, body_bytes, body_b3, body_truncated, sse_events: u64, ws_messages: u64, dur_ms (first request byte to last response byte), degraded}` when the response ends. A WebSocket stream has one `http.request` (the upgrade) and one `http.response` at its end.
  - `llm.request{flow, stream, provider ("anthropic"|"openai_chat"|"openai_responses"), model, stream: bool, messages: u32, system_b3: Option<String>, tools: Vec<String> (at most 64 names), max_tokens: Option<u64>, body_bytes, body_b3, degraded}`; `llm.response{flow, stream, provider, model: Option<String>, stop_reason: Option<String>, input_tokens, output_tokens, cache_read_tokens: Option<u64>, text_bytes, text_b3, tool_uses: u32, dur_ms, degraded}`. There is no `llm.text` record: the assistant text is hashed into `llm.response` (decision).
  - `tool.open{tool_use_id, tool_name, args_b3, args_summary (512 bytes, from the arguments' JSON), args: Option<serde_json::Value> (the arguments inline when their JSON is at most 8 KiB, else omitted)}` with the envelope's `span = {trace_id: <session_id>, span_id: <tool_use_id>}`; `tool.close{tool_use_id, status ("ok"|"error"), result_bytes, result_b3, result_summary (512)}` with the same `span`. Both carry the `flow` and `stream` they were read from.
  - `span.effects{span_id, tool_name, opened_seq, closed_seq: Option<u64>, executor_tgid: Option<u32>, procs: Vec<u32> (tgids, at most 1024), effects: Vec<u64> (seqs, at most 4096), truncated: bool}`, emitted by the reconciler when a span closes and, for spans still open, at `vmm.stop`.
  - Ring 1: `proc.tls_io{tid, tgid, dir ("write"|"read"), bytes: u32}` and `proc.tls_attach{path, ok, error: Option<String>}` (`subject` absent).
  - `KINDS` grows from 47 to 57. Summaries 512 bytes; bodies over 8 KiB are never inlined (so `tool.open.args` is the one inline body, and only to 8 KiB).
- **Model parsers** (`boxcar_net::model`), chosen by `authority` and `path`, all tolerant (unknown fields and events ignored; a parse failure degrades the stream, never the flow): Anthropic Messages (`/v1/messages`): request `model`, `messages[]` (count; the last user message's `tool_result` blocks → `tool.close`, `is_error` → `status:"error"`), `system` (hashed), `tools[].name`, `max_tokens`, `stream`; response as JSON or SSE: `message_start` (model, usage.input_tokens, cache_read_input_tokens), `content_block_start{type:"tool_use"}` + `input_json_delta` accumulation + `content_block_stop` → `tool.open`, `text_delta` → hashed text, `message_delta` (stop_reason, usage.output_tokens) → `llm.response`. OpenAI chat (`/v1/chat/completions`): `messages[]` with `role:"tool"` → `tool.close` by `tool_call_id`; response `choices[].delta.tool_calls[]` by `index` accumulated until `finish_reason` or the stream's end → `tool.open`; `usage` when present. OpenAI responses (`/v1/responses`, POST or WebSocket): request `input[]` items `function_call_output` → `tool.close` by `call_id`; events `response.output_item.added{item.type:"function_call"}`, `response.function_call_arguments.delta|done` → `tool.open`; `response.output_text.delta` → hashed text; `response.completed{response.usage}` → `llm.response`; over WebSocket, `response.create` messages are requests and the events are responses, with one `llm.request`/`llm.response` pair per `response.create`.
- **Spans in the reconciler.** `State.spans: HashMap<String, Span{tool_use_id, tool_name, args (the inline `args` when present), opened: (seq, ts), closed: Option<(seq, ts)>, procs: HashSet<ProcKey>, effects: Vec<u64>, executor: Option<ProcKey>}>` and `open_spans` in open order. The **session root** is the `Proc` of `session.start.pid`; the **executor** of a span is the tgid a `proc.tls_io{dir:"write"}` joined to the span's `llm.request` (same tgid's write within 500 ms before the request's `http.request`, bytes within 10% of `body_bytes` plus 1 KiB), else the session root. A `proc.exec` while spans are open joins one when its ancestry (through `proc.fork` and `proc.exec` records: `ppid`, `parent_tgid`) reaches the executor or the session root, by: (1) argv match: a `Bash`/`bash`/`shell`/`exec_command`/`local_shell` tool whose `command` (or `cmd[]` joined) equals, after whitespace normalization, the exec's argv after a `-c`/`-lc` or the whole argv; (2) the only open span, if one; (3) otherwise unattributed (kept 2 s for a late `tool.open`). Descendants of a joined process join its span. A ring 0 effect joins the span of its process. Rules:

| Finding | Condition | Score |
|---|---|---|
| `intent_effect_mismatch` / `argv` | a span joined by ancestry alone (case 2) whose tool is a shell tool and whose joined exec's normalized argv differs from the declared command | 70 |
| `intent_effect_mismatch` / `phantom_write` | a `Write`, `Edit`, `MultiEdit`, `NotebookEdit` or `apply_patch` span closed with `status:"ok"` with no `fs.create`, `fs.close{bytes_written > 0}` or `fs.rename` on the declared path (made relative to `/workspace`) among its effects, 1 s after it closed | 65 |
| `intent_effect_mismatch` / `hidden_net` | a span whose processes made an allowed `net.connect` to a destination no token of the declared command or arguments names (by any of the flow's `names` or its address), closed `ok` | 55 |
| `orphaned_work` | a span-bound process still alive 1 s after its span closed (checked on the tick) | 50 |

  Findings inside a span carry `span_id`; `span.effects` is emitted at close. `span.list{active_only?}` → `{spans: [{span_id, tool_name, opened_seq, closed_seq?, procs: u32, effects: u32, worst_score: u8}]}` (at most 1024 entries, newest first), served by the control socket from a `SpanIndex` (`Arc<Mutex<..>>`) the reconciler keeps and `boxcar run` hands the VMM; hello's capabilities gain `spans` and `policy.inspect`. `boxcar spans [--active]` prints it.
- **Ring 1 TLS.** eBPF programs, all filtered by `SESSION_CGROUP` like the others: `uprobe/ssl_write` (`SSL_write(ssl, buf, num)` → `TlsIoEvent{dir: write, bytes: num}`), `uprobe/ssl_write_ex` (`num`), `uprobe/ssl_read` saving `(tid → nothing)` and `uretprobe/ssl_read` (the return value when positive → `dir: read`), `uprobe/ssl_read_ex` saving the `readbytes` pointer per tid in a `HashMap<u32, u64>` (1024 entries) and `uretprobe/ssl_read_ex` reading `*readbytes` when the return is 1. The plaintext buffer is never read: bytes and time only. The sensor's userspace attaches them to a path once, the first time it sees it: the `filename` of each `proc.exec` it forwards, and, on each heartbeat, every mapped file whose name begins with `libssl.so` in `/proc/<tgid>/maps` of the session's tgids seen since the last heartbeat (at most 64 paths per session, then `proc.tls_attach{ok:false, error:"limit"}` once); aya's `UProbe::attach(Some("SSL_write"), 0, path, None)` resolves the symbol from the file, and a missing symbol is `proc.tls_attach{ok:false, error}` once per path. `PROGRAMS` grows to 15 with `ProgramKind::{UProbe, URetProbe}`, all `optional: true` (they attach to no target at load; the lane checks they exist). The eBPF licence stays `Dual MIT/GPL`.
- **Dump mode.** `boxcar run --dump DIR` (DIR made 0700 if missing, must not be a share or inside one, the audit dir's rule): `frames.pcap` (pcap 2.4, little endian, microsecond timestamps, `LINKTYPE_ETHERNET`, snaplen 65535) of every frame the guest sent and every frame the stack gave it, copied on the net thread into a bounded channel (4096 frames) to thread `dump` with `try_send`; a dropped frame is `net.drop{reason:"dump"}`. For inspected flows, the observer writes `flows/<flow>.c2s` and `flows/<flow>.s2c` (plaintext as relayed, before content decoding) and `http/<flow>-<stream>.req` and `.resp` (the start line, the redacted headers, a blank line, the decoded body), each file created 0600. The dump is a debugging aid, not part of the audit log: nothing in it is hashed or chained, and the README says so. Filesystem traffic is already dumped by `--audit-level verbose`; the dump adds nothing for it (decision).
- **The agents' guest.** `cargo xtask rootfs debian`: in Docker (`debian:trixie-slim`, pinned by digest in `xtask/src/rootfs.rs`), `apt-get install ca-certificates curl nodejs npm git procps`, `npm install -g @anthropic-ai/claude-code @openai/codex`, the native Claude Code installer for `/usr/local/bin/claude-native` (its version recorded in the Decisions), then `docker export` unpacked as the invoking user into `target/guest/rootfs-debian`, with `/tmp` and `/workspace`. The gated agent tests need `target/guest/rootfs-debian` and a credential from the host environment: `CLAUDE_CODE_OAUTH_TOKEN` for Claude Code (passed into the session environment; `boxcar run --env NAME=VALUE` is added for it, repeatable), `CODEX_HOME` pointing at a directory with an `auth.json` for Codex (copied into the session's workspace, which the test deletes after); the tests skip, saying why, when either is missing. No credential value may appear in a record, a dump, a log, a fixture or the test's output; the test asserts that the token's value is absent from the whole log and the dump.
- **Everything M3 fixed stays fixed:** the slot table, guest addresses, policy v1's `allow`/`deny` semantics, the vsock admission rules, the control limits and error codes, modes, exit codes, the terminal behaviour, the sensor's existing programs and frames, the reconciler's existing rules and scores.

## 4. Review focus

1. **The agent, as root, reads the session CA's key.** There is none in the guest: the guest has the certificate only (`/run/boxcar/ca.pem`), the key is VMM memory. Pinned by Task 1's `the_guest_gets_the_certificate_and_never_the_key` (the config carries no private key material; the gated test reads `/run/boxcar` and finds exactly the two files).
2. **The agent presents its OAuth token to the model.** Expected: the request is relayed byte for byte (the provider accepts it), `http.request` and `llm.request` exist, and the token's value appears nowhere: not in the log, not in the dump, not in a summary. Pinned by Task 3's `credential_headers_never_leave_the_parser` (unit, with `authorization`, `x-api-key` and `cookie`), Task 7's `--dump` test and the agent tests' absence assertions.
3. **The provider's certificate is wrong** (a test upstream with an untrusted chain). Expected: `net.inspect{result:"upstream_untrusted"}`, the guest's connection reset, no plaintext ever relayed, the session continues. Pinned by Task 2's `an_untrusted_upstream_is_refused_and_recorded`.
4. **The agent pins its certificate** (a guest client that rejects the leaf). Expected: `net.inspect{result:"guest_rejected"}`, `net.close{reason:"inspect"}`, nothing relayed, the gate does not retry without inspection. Pinned by Task 2's `a_guest_that_rejects_the_leaf_is_recorded_and_not_relayed`.
5. **A model stream the observer cannot keep up with.** Expected: the guest's bytes keep moving at the relay's pace, the observer marks the streams degraded, `net.drop{reason:"observe"}` counts the loss, no ring 0 record is delayed. Pinned by Task 2's `a_slow_observer_never_slows_the_relay`.
6. **Two Bash tool calls in flight at once** (Claude Code runs tools in parallel). Expected: each `proc.exec` joins the span whose declared command it matches, not the first open one. Pinned by Task 5's `parallel_tools_join_by_argv` fixture.
7. **HPACK state after a header table size change, and a CONTINUATION split at every byte.** Expected: the same headers whatever the split. Pinned by Task 3's RFC 7541 vectors and `any_split_decodes_the_same` (proptest).

## 5. File structure

| Path | Responsibility |
|---|---|
| `crates/boxcar-net/src/policy.rs`, `crates/boxcar-proto/src/control.rs` | `inspect` rules and their wire field |
| `crates/boxcar-net/src/gate/{mod,ca,tls,observe}.rs` | the session CA and leaves, the two TLS legs, the observer channel and thread |
| `crates/boxcar-net/src/tcp/{relay,flow}.rs`, `audit.rs`, `config.rs`, `stack.rs`, `device.rs` | `FlowState::Inspecting`, the inspected pump, `net.inspect`, the dump tap, the drop reasons |
| `crates/boxcar-net/src/http/{mod,h1,h2,hpack,huffman,body,sse,ws,headers}.rs` | the HTTP state machines, HPACK, content decoding, SSE, WebSocket, redaction |
| `crates/boxcar-net/src/model/{mod,anthropic,openai_chat,openai_responses,summary}.rs` | the model parsers, `llm.*` and `tool.*` |
| `crates/boxcar-net/src/dump.rs` | the pcap writer and the dump directory |
| `crates/boxcar-proto/src/audit.rs`, `audit/payloads.rs`, `guest.rs` | the new payloads, `Source::Gate`, `SessionConfig.ca_pem`, `VmmStart.inspect_ca_sha256` |
| `crates/boxcar-init/src/{trust,pty,main}.rs` | the guest's trust store and variables |
| `crates/boxcar-audit/src/reconcile/{spans,rules,state,mod}.rs`, `tests/fixtures/*.jsonl` | spans, the two rules, `span.effects`, `SpanIndex` |
| `crates/boxcar-vmm/src/{vmm,lifecycle}.rs`, `control/ops.rs` | `VmConfig{inspect_ca, dump, spans}`, `span.list`, the capabilities, the observer's lifetime |
| `crates/boxcar-sensor-common/src/{lib,programs}.rs`, `crates/boxcar-sensor-ebpf/src/tls.rs`, `crates/boxcar-sensor/src/{tls,load,main}.rs` | `TlsIoEvent`, the six programs, attaching by path |
| `crates/boxcar/src/{cli.rs,cmd/{run,spans}.rs}`, `tests/kvm_m4.rs` | `--inspect`, `--dump`, `--env`, `boxcar spans`, the M4 gated suite |
| `xtask/src/{rootfs,test_kvm}.rs`, `.github/workflows/ci.yml` | `rootfs debian`, `test-kvm m4` |
| `docs/{gate,audit-events,control-protocol,reconciler,networking}.md`, `README.md`, `docs/perf.md` | documentation |

---

### Task 1: `inspect` rules, the session CA, and the guest's trust store

Files: `crates/boxcar-net/src/policy.rs`, `crates/boxcar-net/src/gate/{mod,ca}.rs`, `crates/boxcar-net/Cargo.toml`, `Cargo.toml`, `deny.toml`, `crates/boxcar-proto/src/{control.rs,guest.rs,audit/payloads.rs}`, `crates/boxcar-init/src/{trust.rs,pty.rs,main.rs,session.rs}`, `crates/boxcar-vmm/src/vmm.rs`, `crates/boxcar/src/{cli.rs,cmd/run.rs,cmd/policy.rs}`, `xtask/src/schema.rs`, `proto/schema/*.json`, `docs/audit-events.md`; tests in the same files and `crates/boxcar-vmm/tests/boot_session.rs`.

- [ ] **Tests.** `policy.rs`: `inspect_lines_parse_like_allow_and_deny` (domain, wildcard, CIDR, ports), `inspect_does_not_decide_a_verdict` (an `inspect` with no `allow` still denies), `inspects_matches_the_gate_name_or_the_destination`; `control.rs`: `NetPolicy` round trip with and without `inspect`, the rule-count limit counts inspect lines. `gate/ca.rs`: `a_leaf_for_a_name_verifies_against_the_session_ca` (rustls `WebPkiServerVerifier` with the CA as the only root accepts the leaf for the name and rejects it for another), `a_leaf_for_an_address_carries_an_ip_san`, `leaves_are_cached_and_bounded` (1024 then eviction), `the_fingerprint_is_sha256_of_the_der`, `the_guest_gets_the_certificate_and_never_the_key` (the PEM `SessionCa::pem()` returns holds one `CERTIFICATE` block and nothing else). `trust.rs` (init, pure parts): `the_bundle_is_the_rootfs_store_followed_by_the_session_ca`, `a_rootfs_without_a_store_gets_the_ca_alone`, `variables_are_added_only_when_absent`; `pty.rs`: `session_env_names_the_bundle_when_the_config_has_a_ca`. `payloads.rs`: `vmm.start` with and without `inspect_ca_sha256`. `run.rs`: `inspect_rules_reach_the_policy_and_make_a_ca`, `no_inspect_means_no_ca`, `--inspect` refused with `--no-net`. Gated (`boot_session`): with `--inspect example.com`, the guest's `/run/boxcar/ca.pem` matches the `inspect_ca_sha256` the log carries (the test computes it from the PEM the guest prints), `/etc/ssl/certs/ca-certificates.crt` in the guest ends with that certificate, `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` are in the session's environment, and `/run/boxcar` holds exactly `ca.pem` and `ca-bundle.pem`; without `--inspect`, `/run/boxcar` does not exist.
- [ ] **Code.** `Rule.kind: RuleKind{Allow, Deny, Inspect}` (replacing `verdict` on the rule, with `verdict()` for the first two); `Policy::inspects`; `NetPolicy.inspect`; `SessionCa` (`rcgen`) with `leaf_for(&SanTarget) -> Arc<CertifiedKey>`; `SessionConfig.ca_pem`; init's `trust::install(ca_pem) -> Result<Installed, Failed>` after `mount_api` and before the session's fork, and `session_env` additions; `VmConfig.inspect_ca: Option<Arc<SessionCa>>`; `boxcar run --inspect`; `cargo xtask schema`; `docs/audit-events.md` for the new `vmm.start` field.
- [ ] **Verify.** The stable commands, `cargo deny check` with `ISC` allowed, `cargo xtask schema` clean, `cargo xtask initramfs`, `cargo xtask test-kvm m3`.
- [ ] **Commit** `net, init, cli: inspect rules, the session CA and the guest's trust store`.

### Task 2: TLS termination for inspected flows and the observer channel

Files: `crates/boxcar-net/src/gate/{tls,observe}.rs`, `crates/boxcar-net/src/tcp/{relay,flow}.rs`, `audit.rs`, `config.rs`, `stack.rs`, `device.rs`, `crates/boxcar-proto/src/audit/payloads.rs`, `audit.rs`, `crates/boxcar-vmm/src/{vmm,lifecycle}.rs`, `crates/boxcar/src/cmd/run.rs`, `docs/audit-events.md`; tests in `crates/boxcar-net/src/gate/tls.rs`, `tcp/relay.rs`, `crates/boxcar-net/tests/inspect.rs`, `crates/boxcar/tests/kvm_m4.rs` (new, first test).

- [ ] **Tests.** `gate/tls.rs`, with in-memory buffers for the guest leg and a loopback TLS server thread for the upstream leg (its root given through the test hook): `an_inspected_flow_relays_plaintext_both_ways_unchanged` (1 MiB each way, byte-identical, the observer saw the same bytes with the right directions), `the_guest_leg_offers_exactly_the_alpn_upstream_chose` (h2 and http/1.1, and none), `an_untrusted_upstream_is_refused_and_recorded`, `a_guest_that_rejects_the_leaf_is_recorded_and_not_relayed`, `a_slow_observer_never_slows_the_relay` (an observer that never reads: the relay moves at the host's pace, `net.drop{reason:"observe"}` counts, the stream is marked degraded), `handshakes_time_out_with_the_gate` ; `payloads.rs`: `net.inspect` and `net.tls.inspect` round trips, `KINDS` 48. `tests/inspect.rs`: through the net stack's existing synthetic-frame harness, a flow to an inspected CIDR whose upstream is the loopback server: `net.connect`, `net.tls{inspect:true}`, `net.inspect{result:"ok"}`, `net.close{reason:"fin"}` in order. Gated (`kvm_m4.rs`): `an_inspected_download_is_relayed_and_recorded`: Alpine, `--inspect example.com --allow example.com:443`, `wget -q -O - https://example.com/`, the page text reaches the guest, the log has `net.inspect{result:"ok", sni:"example.com"}` and `net.close{reason:"fin"}` for that flow, and the session exits 0; `an_inspected_connection_to_an_untrusted_host_fails_closed` with the test upstream and no root given.
- [ ] **Code.** `Inspect` (the two legs and their buffers) owned by `Flow` in `FlowState::Inspecting`; `relay::pump` splits into the plain pump and `pump_inspected`; `Observer` channel and the `gate-observe` thread (this task: it counts bytes and records `degraded`; Task 3 gives it the HTTP state machine); `NetConfig.inspect: Option<InspectConfig{ca, upstream_roots}>`; `DropReason::{Observe, Dump}`; `net.inspect` and `net.tls.inspect`; the observer's join in `boxcar run`.
- [ ] **Verify.** The stable commands, `cargo xtask test-kvm m3`, the new gated tests by name.
- [ ] **Commit** `net: TLS termination for inspected flows and the observer channel`.

### Task 3: the HTTP observer: HTTP/1.1, HTTP/2, HPACK, content decoding, SSE, WebSocket and `http.*` records

Files: `crates/boxcar-net/src/http/{mod,h1,h2,hpack,huffman,body,sse,ws,headers}.rs`, `crates/boxcar-net/src/gate/observe.rs`, `crates/boxcar-net/Cargo.toml`, `Cargo.toml`, `crates/boxcar-proto/src/audit/payloads.rs`, `audit.rs`, `docs/audit-events.md`; tests in the same files and `crates/boxcar-net/tests/fixtures/http/*`.

- [ ] **Tests.** `hpack.rs`: RFC 7541 C.2 (literal forms), C.3 and C.4 (request sequences without and with Huffman, checking the dynamic table after each), C.5 and C.6 (responses with evictions at a 256-byte table), `a_size_update_shrinks_the_table`, `oversized_indices_and_integers_are_errors_not_panics` (proptest over random bytes: never panics); `huffman.rs`: every symbol round trips, an EOS in the middle is an error, padding over 7 bits is an error. `h1.rs`: a request with `Content-Length`, one with chunked body and trailers, two pipelined requests, a response with no body (`204`, `304`, `HEAD`), `101` handing off. `h2.rs`: a hand-built exchange (preface, `SETTINGS`, `HEADERS` + `CONTINUATION` split, two interleaved streams with padded `DATA`, `RST_STREAM`), `any_split_decodes_the_same` (proptest: the same bytes cut at random points give the same events), limits (`header block too large`, 257th stream) degrade the stream. `body.rs`: gzip, deflate, brotli bodies decode; `zstd` degrades; `a_17_mib_body_is_hashed_and_truncated`. `sse.rs`: events across chunk boundaries, comments, multi-line `data`. `ws.rs`: masked client text frames, fragmented messages, `permessage-deflate` with context takeover (a fixture made with a known inflate), an unknown extension degrades. `headers.rs`: `credential_headers_never_leave_the_parser` (`authorization`, `proxy-authorization`, `x-api-key`, `cookie`, `set-cookie`, `x-foo-token`: absent from `redacted()`, and the raw map has no accessor). `observe.rs`: `http_records_carry_hashes_and_sizes` for an h1 and an h2 exchange, `a_lost_marker_degrades_the_open_streams`. `payloads.rs`: `http.request` and `http.response` round trips, `KINDS` 50.
- [ ] **Code.** The modules above; the observer runs the state machine per flow and emits `http.request` at the end of a request's body and `http.response` at the end of a response.
- [ ] **Verify.** The stable commands, `cargo xtask test-kvm m3` (the observer is on the ring 0 path), and the gated test of Task 2 now also yields `http.request{authority:"example.com", method:"GET"}` and `http.response{status:200}` (extend it).
- [ ] **Commit** `net: the HTTP observer with HPACK, content decoding, SSE and WebSocket`.

### Task 4: the model parsers, `llm.*` and `tool.*` records

Files: `crates/boxcar-net/src/model/{mod,anthropic,openai_chat,openai_responses,summary}.rs`, `crates/boxcar-net/src/gate/observe.rs`, `crates/boxcar-proto/src/audit/payloads.rs`, `audit.rs`, `crates/boxcar-proto/src/redact.rs` (if a scrub is missing), `docs/audit-events.md`, `crates/boxcar-net/tests/fixtures/model/*`; tests in the same files.

- [ ] **Tests.** Fixtures written from the providers' public API documentation (not recorded; synthetic prompts), one request and one streamed response per provider plus a non-streamed Anthropic response and a WebSocket responses exchange, with blessed expected records (`BOXCAR_BLESS=1`, the repository's pattern): `anthropic_tool_use_opens_and_the_next_request_closes` (two requests: the second's `tool_result` closes the span; `is_error` → `error`), `anthropic_usage_and_stop_reason_land_in_llm_response`, `openai_chat_tool_calls_by_index`, `openai_responses_function_calls_and_outputs`, `openai_responses_over_websocket`, `unknown_events_are_ignored`, `a_malformed_stream_degrades_and_keeps_what_it_had`, `arguments_over_8_kib_are_hashed_not_inlined`, `summaries_are_512_bytes_and_scrubbed` (a summary that would carry a credential-looking token is scrubbed by `redact::scrub`), `the_span_reference_is_the_session_and_the_tool_use_id`. `payloads.rs`: four round trips, `KINDS` 54, `Source::Gate` (`gate`) for `http.*`, `llm.*`, `tool.*`.
- [ ] **Code.** `model::Parser` chosen per stream from `authority` and `path`; the three providers; `summary::of(json) -> String` (512 bytes, keys and the first values, scrubbed); `Source::Gate`; the observer emits `llm.request` at the end of a request body, `tool.close` for each `tool_result` in it, `tool.open` per completed `tool_use`, `llm.response` at the end of the response.
- [ ] **Verify.** The stable commands, `cargo xtask schema` clean, `cargo xtask test-kvm m3`.
- [ ] **Commit** `net: Anthropic and OpenAI parsers, llm.* and tool.* records`.

### Task 5: spans in the reconciler, `intent_effect_mismatch`, `orphaned_work`, `span.list` (roadmap M4.4)

Files: `crates/boxcar-audit/src/reconcile/{spans,rules,state,mod}.rs`, `crates/boxcar-audit/src/lib.rs`, `crates/boxcar-audit/tests/reconcile.rs`, `tests/fixtures/{bash_span_joins_effects,parallel_tools_join_by_argv,argv_mismatch,phantom_write,hidden_net,orphan_after_span,span_effects_at_stop}.jsonl` and their expected files, `crates/boxcar-proto/src/{control.rs,audit/payloads.rs,audit.rs}`, `crates/boxcar-vmm/src/{vmm.rs,control/ops.rs}`, `crates/boxcar/src/{cli.rs,cmd/{run,spans}.rs}`, `docs/{reconciler,control-protocol,audit-events}.md`; tests in the same files.

- [ ] **Tests.** Fixtures (host-time ordered, with `session.start`, `proc.*` lineage, `tool.open`/`tool.close`, `fs.*` and `net.*`): the seven above; `bash_span_joins_effects` expects a `span.effects` with the shell's exec, its child `curl` and the `fs.close` it made, `executor_tgid` the session root; `parallel_tools_join_by_argv` opens two Bash spans and expects each exec in the right one; `argv_mismatch` fires 70 with evidence of the `tool.open` and the `proc.exec`; `phantom_write` fires 65 one tick after the close; `hidden_net` fires 55; `orphan_after_span` fires 50 on the tick; `span_effects_at_stop` emits `span.effects{closed_seq: null}` for an open span at `vmm.stop`; `a_tls_write_names_the_executor` (a `proc.tls_io{write}` sized like the `http.request` 100 ms before it makes that tgid the executor). `control.rs`: `span.list` round trips, `active_only`; `ops.rs`: `span_list_reads_the_index`. `cli`: `boxcar spans` prints one line per span.
- [ ] **Code.** `spans.rs` (the `Span` model, joins, `SpanIndex`), the four rules in `rules.rs`, `span.effects`, `ReconcileConfig.spans: Option<SpanIndex>`, `VmConfig.spans`, `span.list`, capabilities `spans` and `policy.inspect`, `boxcar spans`.
- [ ] **Verify.** The stable commands, `cargo xtask schema` clean, `cargo xtask test-kvm m3`.
- [ ] **Commit** `audit, vmm, cli: tool spans, the intent rules and span.list`.

### Task 6: ring 1 TLS writes and reads from runtimes that export OpenSSL's functions

Files: `crates/boxcar-sensor-common/src/{lib,programs}.rs`, `crates/boxcar-sensor-ebpf/src/{tls.rs,main.rs}`, `crates/boxcar-sensor/src/{tls.rs,load.rs,main.rs}`, `crates/boxcar-proto/src/{sensor.rs,audit/payloads.rs,audit.rs}`, `xtask/src/sensor.rs`, `docs/audit-events.md`, `README.md`; tests in the same files, `crates/boxcar-vmm/tests/boot_sensor.rs`, `crates/boxcar/tests/kvm_m4.rs`.

- [ ] **Tests.** `programs.rs`: 15 programs, the six new ones `optional`, kinds `UProbe`/`URetProbe`; the lane (`xtask sensor`) asserts their names, kinds and the new `TLS_READS` map. `sensor::tls` (userspace, unit): `a_path_is_tried_once`, `the_limit_is_64_paths_then_one_error`, `maps_lines_name_libssl` (parsing `/proc/<pid>/maps` text). `payloads.rs`: `proc.tls_io`, `proc.tls_attach` round trips, `KINDS` 57; `sensor.rs`: both kinds are sensor kinds. Gated (`kvm_m4.rs`): `a_tls_download_is_seen_by_both_rings`: Alpine, `wget -q -O /dev/null https://example.com/` (busybox `ssl_client` loads `libssl.so.3`): `proc.tls_attach{ok:true}` for a path ending `libssl.so.3`, `proc.tls_io{dir:"write"}` and `{dir:"read"}` from the `ssl_client` tgid, and with `--inspect example.com` the reconciler's `span`-less join is exercised by `boot_sensor`'s assertion that the `http.request` and a `tls_io` write of its size lie within 500 ms.
- [ ] **Code.** `TlsIoEvent`, the six programs, `TLS_READS` map, `sensor::tls::Attacher` (paths tried, heartbeat sweep of `/proc/<tgid>/maps`), the frames.
- [ ] **Verify.** The stable commands, `cargo xtask sensor`, `cargo xtask check-vmlinux`, `cargo xtask initramfs`, `cargo xtask test-kvm m3`, the new gated test by name.
- [ ] **Commit** `sensor: TLS write and read events from OpenSSL-exporting runtimes`.

### Task 7: the dump mode, the Debian guest, the agents inside, `cargo xtask test-kvm m4`, and documentation

Files: `crates/boxcar-net/src/dump.rs`, `crates/boxcar-net/src/gate/observe.rs`, `stack.rs`, `device.rs`, `crates/boxcar-vmm/src/vmm.rs`, `crates/boxcar/src/{cli.rs,cmd/run.rs}`, `crates/boxcar/tests/kvm_m4.rs`, `xtask/src/{rootfs,test_kvm,main}.rs`, `.github/workflows/ci.yml`, `docs/{gate,networking,audit-events,control-protocol,reconciler,perf}.md`, `README.md`, `CONTRIBUTING.md`.

- [ ] **Tests.** `dump.rs`: `the_pcap_header_and_records_are_well_formed` (magic `0xa1b2c3d4`, version 2.4, link type 1, each record's lengths), `a_full_channel_drops_and_counts`, `the_dump_dir_may_not_be_a_share` (reuses the audit dir's rule). `run.rs`: `--env` parsing (`NAME=VALUE`, refused without `=`), `--dump` makes the directory 0700. `test_kvm.rs`: `m4_runs_the_same_packages_and_names_itself`, exports `BOXCAR_TEST_ROOTFS_DEBIAN` when `target/guest/rootfs-debian` exists. Gated (`kvm_m4.rs`): `a_stub_model_speaks_anthropic_and_the_log_gets_spans` (a loopback HTTPS stub on the host replaying the Anthropic fixtures, trusted through the test hook, inspected by CIDR; the guest's `wget --post-data` sends a request, then a second with the `tool_result`; the log has `llm.request`, `tool.open`, `tool.close`, `llm.response`, `span.effects`, and `boxcar spans` lists the span closed), `the_dump_holds_the_frames_and_the_decoded_exchange` (`frames.pcap` well-formed with the flow's SYN; `http/<flow>-<stream>.req` holds the request line and no `authorization` line although the request sent one), `claude_code_native_runs_a_bash_tool_inside` and `claude_code_under_node_runs_a_bash_tool_inside` (Debian guest, `CLAUDE_CODE_OAUTH_TOKEN` from the host, `--inspect api.anthropic.com --allow api.anthropic.com:443 --allow platform.claude.com:443 --allow claude.ai:443`, `claude -p 'Run: echo boxcar-m4 > marker.txt' --allowedTools Bash`: `llm.request{provider:"anthropic"}`, a `tool.open{tool_name:"Bash"}` whose `span.effects` holds a `proc.exec` of a shell with that command and the `fs.close` of `marker.txt`, no finding above 50, the token's value absent from the log and the dump; under Node also `proc.tls_attach{ok:true}` for the `node` binary and `proc.tls_io` from its tgid), `codex_runs_a_shell_tool_inside` (`codex exec` with `CODEX_HOME`, `--inspect api.openai.com --allow api.openai.com:443 --allow chatgpt.com:443 --allow auth.openai.com:443`, the same shape with `provider:"openai_responses"`). Each agent test skips with a message when its rootfs or credential is missing.
- [ ] **Code.** `dump.rs` and the tap in the net thread; the observer's dump files; `--dump`, `--env`; `cargo xtask rootfs debian`; `test-kvm m4`; CI's kvm job runs `m4`. Documentation: `docs/gate.md` (what is inspected, the CA, what is and is not recorded, the redaction, the limits, how to inspect by hand with `--dump`), `docs/networking.md` (inspect), `docs/audit-events.md` (every new type with its source and ring), `docs/control-protocol.md` (`span.list`, `NetPolicy.inspect`, the capabilities), `docs/reconciler.md` (spans and the four rules), `README.md` ("Watching the model traffic", "Running Claude Code and Codex inside", "Dump mode"), `docs/perf.md` (the gate's cost on a 100 MB inspected download), `CONTRIBUTING.md` (the fixtures' bless pattern for model streams).
- [ ] **Verify.** Every command in section 2 including `cargo xtask test-kvm m3` and `m4`, with the agent tests run once each with real credentials from this machine and their output kept out of the report except pass or fail.
- [ ] **Commit** `net, cli, xtask, docs: dump mode, the Debian guest, the agents inside and the M4 suite`.

## 6. Fixtures and recordings

The model parsers' fixtures are written by hand from the providers' public documentation so that nothing recorded from a real session enters the repository. After Task 7, one real exchange per agent may be recorded with `--dump` to check the parsers against reality; what is kept of it is a note in the Decisions (provider, version, which events appeared, anything the parser degraded on), never the bytes.

## 7. Finishing M4

1. All commands in section 2 are clean at the final commit, including `cargo xtask sensor`, `cargo xtask test-kvm m3` and `m4`.
2. A last read of the whole branch against its base for anything that contradicts section 3, with the checks M3's section 7 made, plus: no code path writes a credential header's value anywhere; the gate never writes to a leg what it did not read from the other; nothing on the net thread waits for the observer or the dump; every new record type's source and ring.
3. Then, if asked: push `m4` and open a PR against `main` whose description lists every accepted limitation.

## 8. Decisions (appended while executing this plan)

Made while writing the plan, 2026-10-06:

- **The gate replaces the gateway**, per the spec's amendment of this date (section 14). The agent keeps its own login; boxcar holds no credential and injects none. `Source::Gateway` is renamed `Gate` (wire `gate`); nothing ever emitted the old value.
- **The gate relays plaintext byte for byte and modifies nothing**, including HTTP/2 framing and HPACK. Both legs therefore see the same bytes, the passive HPACK decoder stays in step, and the record is of what the agent sent, not of what a proxy made of it. The cost is that content encodings the observer cannot decode (zstd) are observed as hashes only.
- **No async runtime.** rustls is sans-IO and lives on the net thread beside smoltcp, as the relay does; the heavy work (decoding, parsing, hashing, dump files) is on the `gate-observe` thread behind a channel that never blocks the net thread. The roadmap's tokio and hyper are not added.
- **`ring`, not `aws-lc-rs`**, for rustls and rcgen: `aws-lc-sys` stays banned. `ring` builds C and assembly on the host like `blake3`; `ISC` joins the licence allowlist for it, `rustls-webpki` and `untrusted`.
- **Upstream roots are the host's** (`rustls-native-certs`), not a bundled set: the host is trusted and keeps its store current; a bundled set would be a second thing to update.
- **`inspect` may name a CIDR** so that a test upstream on the loopback can be inspected without DNS; the leaf then carries an IP SAN. For agents, inspect by name.
- **Credentials are removed by header name** at the one accessor the parsers have, and never copied into the dump either. The redaction scrub on summaries is defence in depth, not the mechanism.
- **The trust store is installed by init on the `/run` tmpfs**, with a bind over the rootfs's bundle, following `resolver.rs`'s pattern: the root share keeps its own file, and the host records the one case where init must create it.
- **`llm.text` is not a record**: the assistant text's size and hash are fields of `llm.response`.
- **Spans are membership records, not rewritten effects.** `span.effects` lists a span's processes and effects at close; effects are never edited after the writer chained them. Findings carry `span_id`.
- **The trace id is the session id** and the span id the provider's tool use id, which is unique within a conversation; a session with two conversations that reuse an id would collide, accepted.
- **Ring 1 TLS events carry sizes and times, never bytes**: the sensor cannot know which bytes are a credential, and the gate already has the plaintext in ring 0. Their use is to name the process behind a request.
- **Dump mode covers the network only**; `--audit-level verbose` is already the filesystem's dump. Nothing in the dump is chained; it is a debugging aid.
- **The agents' guest is Debian** because the native Claude Code build needs glibc; Alpine stays the stock guest and the one the KVM-free parts of the suite assume. The agent tests need credentials from the host environment and skip without them; CI never has them.

### Task 1

- `inspect` lines live in their own list (`Policy.inspect: Vec<Inspect>`,
  `NetPolicy.inspect`) rather than as a third `RuleKind` on `Rule`: no
  decision path can mistake one for a rule, and the verdict code is
  untouched. `Policy::inspects` is the one reader.
- rcgen is used without its `pem` feature, which would bring `base64 0.23`
  beside the workspace's `0.22`; the PEM block is written in `gate/ca.rs`.
  `time` (for the validity dates rcgen takes) and `ring` (for the SHA-256
  fingerprint) are direct dependencies at the versions rustls uses.
  `getrandom 0.2` (ring) is skipped in `deny.toml` beside uuid's `0.4`.
- rcgen's `Ia5String` takes any ASCII as a DNS SAN, so a leaf's name is
  checked as a DNS name (`rustls_pki_types::DnsName`) first; a server name
  that is not one is refused, never signed.
- `SessionConfig::validate` checks `ca_pem` on both sides of the guest
  channel: ASCII, at most 8 KiB, a `CERTIFICATE` block, nothing that says
  `PRIVATE KEY`. The field is omitted from the line when unset, so the
  guest protocol's golden lines are unchanged.
- The `policy.inspect` capability lands here, where the protocol starts
  carrying inspect lines; `spans` waits for Task 5.
- Init makes no directory in the root share: a rootfs without
  `/etc/ssl/certs` gets the CA on `/run` and the variables only, and the
  console says so. Alpine's bundle ends in a blank line; the bundle keeps
  the store's text as it is and appends the CA after it.
- The gated test is in `boot_session` (the VMM's `VmConfig`), beside the
  session tests, with the CA made by the test; `boxcar run --inspect` is
  covered by unit tests here and by the M4 gated suite from Task 2 on.

### Task 2

- **Which flows the gate reads.** A flow a network rule allowed is not
  gated today (its first bytes go straight through). When the policy has
  an `inspect` line that could name the flow (`Policy::may_inspect`: a
  network line holding the destination, or a domain line matching one of
  the DNS names the guest had for it), its first bytes are read too, and
  `Policy::inspects` decides on what they show. Such a flow needs no name
  to pass (`gated` on the flow says whether a domain rule requires one),
  and gets a `net.tls` only when it is inspected. A read-for-inspection
  flow that shows neither TLS nor HTTP is relayed untouched after the
  gate's byte or time limit, as any gated flow that shows no name would be
  denied: the delay is the gate's 5 s at worst, accepted.
- **rustls's full plaintext buffer is back-pressure, not an error.**
  `read_tls` refuses more TLS bytes with an `io::ErrorKind::Other` error
  while 16 KiB of decrypted plaintext wait unread. The gate takes it as
  "no room": the host socket is not read, and the guest's bytes stay in
  the smoltcp socket (closing its window), until the relay has moved some
  plaintext on. Each leg's writer has a 64 KiB limit for the same reason.
- **The host's TLS close ends the host side.** After the upstream's
  `close_notify` the gate reads nothing more from it, so the socket's EOF
  is never seen; the flow counts the host as done when its TLS close is in
  and every byte it sent has gone to the guest leg.
- **`net.close.tx` and `rx` count wire bytes** (TLS records) for an
  inspected flow, as for any flow; the plaintext sizes are the observer's
  (`http.*`, Task 3).
- **The observer thread belongs to the device.** `VirtioNet` starts
  `gate-observe` when the session has a gate, gives every stack it builds
  the same sender, and joins the thread (5 s at most) when the device is
  dropped, after the net thread: the thread ends when the last sender is
  gone. `boxcar run` does not join it separately, as the plan said; the
  VMM's own stop order covers it.
- **The observer is told `Open` before any plaintext**, and `Close` only
  after an `Open`: a flow that failed its handshakes was never announced.
- **The test rig moved** from `tests/tcp.rs` into `tests/common/rig.rs`,
  so `tests/inspect.rs` drives a real TLS handshake (a rustls client over
  the rig's smoltcp interface) through the stack to a TLS upstream on the
  loopback: the stack-level test checks the whole `net.connect`,
  `net.tls{inspect}`, `net.inspect{ok}`, `net.close{fin}` sequence, the
  plaintext both ways and the observer's copy, as the plan asked, with
  real TLS rather than synthetic frames.
- **`cargo xtask test-kvm m4` lands now** (the same packages as `m3`, with
  `kvm_m4`), so the gated tests of this task can run; the plan put it in
  Task 7, which adds the Debian guest to it.
- **A test upstream's root** reaches the gate through
  `BOXCAR_TEST_UPSTREAM_ROOTS` (a PEM file), read by `boxcar run` only
  under the `kvm-tests` feature; `gate::ca::pem_certificates` decodes it.
  The CLI crate takes `rustls-pki-types` as a dependency for the type.
- **Loopback upstreams in the gated tests** are reached with
  `--allow 127.0.0.0/8:PORT` (the exact private range lifts its built-in
  denial; loopback is not one of the host's own addresses) and
  `--inspect 127.0.0.1:PORT`.
- **The Alpine guest gets a TLS client.** The minirootfs has busybox's
  `wget` but not the `ssl_client` helper it hands HTTPS to, nor OpenSSL's
  libraries, so no gated test could reach an HTTPS host. `cargo xtask
  rootfs alpine` now adds `libcrypto3`, `libssl3` and `ssl_client` from
  the release branch's `main` repository (3.5.9-r0, 3.5.9-r0 and
  1.37.0-r20 on 2026-10-06), pinned by SHA-256 like the minirootfs and
  unpacked without their signatures and metadata; the rootfs's
  `etc/boxcar-rootfs.json` lists them. Another Alpine release gets the
  bare minirootfs, with a warning.
- **A test upstream on this host is reached by the host's own address**,
  not the loopback, which inside the guest is the guest's own: the test
  finds the address the host sends out through (a UDP socket connected to
  a documentation address, nothing sent) and allows it with two rules,
  the private range it is in named exactly and the address itself, which
  lift the built-in and the host-local denials. A host with no such
  address skips the test.
- **busybox's `ssl_client` names the address as its server name** when
  given one; the untrusted-upstream test accepts that or none.
- **One look at an inspected flow makes up to four rounds** of host I/O,
  TLS phases and guest output while each moves something: a
  `close_notify` or relayed data a step queues goes out in the same call,
  rather than waiting for a host event that, with nothing left to read,
  never comes. Without it a guest's FIN left the flow open until the VM
  stopped (`net.close{reason:"shutdown"}` instead of `fin`).

### Task 3

- **HPACK and the HTTP/1.1 head parser are crates, not transcriptions.**
  `fluke-hpack` (MIT, the maintained fork of `hpack`) decodes the header
  blocks: its static and dynamic tables, Huffman code and size updates
  are the RFC's, and a hand-transcribed Huffman table of 257 codes could
  be checked only against the RFC's few examples. `httparse` (MIT or
  Apache-2.0) parses request and response lines and headers. The frames,
  streams, bodies, chunked coding, event streams and WebSocket frames are
  in-tree. The RFC 7541 C.4 sequence is still a test of the whole path.
- **Credential headers lose their values at the parser.** `Headers::push`
  keeps the name of a header that carries a credential (by name, or by a
  `-token`, `-secret` or `-password` suffix) and drops the value, so no
  accessor can give it: there is no raw map to redact afterwards.
- **An upgrade request holds the guest's side** until the response says
  whether the protocol switched: bytes after a `Connection: Upgrade`
  request are the new protocol's on a `101`, and are not read as a next
  request.
- **A response that reads until the connection closes is whole at the
  close** (`degraded` stays unset); one with a length, or chunked, that
  the close cut short is `incomplete`.
- **A WebSocket reader told to drop its context cannot tell** that a
  sender kept it: the inflater copies from an empty window and yields
  bytes that are not the message, with no error. The test checks that the
  message is not the original rather than that inflation fails.
- **`Source::Gateway` became `Source::Gate` here**, where the first gate
  records land; nothing had emitted the old value.
- **The observer records with the blocking emit** on the `gate-observe`
  thread, which the net thread never waits on; a full writer stalls the
  observer and the channel fills, which the net thread counts as
  `net.drop{reason:"observe"}`.
- **Times in `http.response.dur_ms` are the observer's**: when it took the
  bytes, which is when they moved unless it fell behind.
- **The gated suite runs alone.** With a build running beside it,
  `kvm_m3`'s `a_download_to_a_blocked_address_is_a_joined_finding` saw its
  finding marked low in confidence (a sync round trip over 2 ms, or a
  lagging subscription, under load) and failed on the score; alone it
  passes. The verification runs of this plan keep the machine to the
  gated suite while it runs.

### Task 4

- **The streaming flag is `streaming`**, not `stream`: `stream` on every
  gate record is the HTTP stream id the exchange was read from.
- **The provider is chosen by the request's path alone** (`/v1/messages`,
  `/chat/completions`, `/responses`, with any prefix), not the host: the
  APIs keep their paths behind gateways and proxies, and a session's
  `inspect` lines already say which hosts are watched.
- **Tool results are the ones the agent just added**: the `tool_result`
  blocks of an Anthropic request's last message, the `role: tool`
  messages after the last assistant turn of a chat request, every
  `function_call_output` item of a responses request. Earlier turns'
  results were recorded when they were first sent.
- **The trace id is the session id**, which the CA carries
  (`SessionCa::session_id`) and the observer thread is given; the span id
  is the provider's tool use id. `tool.open` and `tool.close` carry the
  span in the envelope; `llm.*` records do not.
- **Fixtures are inline**, from the providers' public API documentation:
  the parsers' tests hold the request and reply JSON and the event
  streams as literals, and the observer-level tests frame them as
  HTTP/1.1 and WebSocket bytes; there are no recorded files. The plan's
  blessed fixture files were not needed for the records' shapes, which
  the protocol crate's round-trip cases pin.
- **A model API call through an exchange the observer could not read
  whole** (a truncated body, a lost chunk, a flow closed mid-reply) gets
  its `llm.*` record with `degraded` set rather than no record, so a
  reader can tell a call that was made from one that was not.

### Task 5

- **The agent is in no span.** The session root (`session.start.pid`),
  and a span's executor once one is named, never join a span: a `Write`
  tool's `fs.create` comes from the agent itself, so an effect by a
  process in no span joins the only open span, or the write tool span
  whose declared path it touches, while the agent's own connections (its
  model requests) join nothing. Without this the root's own exec, held
  for a late `tool.open`, joined the first `Write` span and was reported
  as orphaned work.
- **"Equals" became "carries"** for the argv join: Claude Code's Bash
  tool runs `bash -c "eval '<command>' < /dev/null && pwd -P >| ..."`, so
  the shell's `-c` command is compared after whitespace is collapsed and
  quotes and backslashes dropped, and matches when it is the declared
  command or contains it; the whole argv must still equal the declared
  one (Codex's `["bash","-lc",...]` as an array). The `argv` rule judges
  only an exec that is a shell given `-c` (the form a shell tool spawns),
  joined by ancestry alone, and fires once a span: the agent's own helper
  processes (a `git` run by the runtime while one Bash span is open) are
  attributed without a finding.
- **`span.effects.effects` holds the `proc.exec` seqs** of the span's
  processes besides their ring 0 effects: `procs` gives tgids, which pid
  reuse makes ambiguous, and a reader of the record should reach every
  record it rests on by seq.
- **The executor stays the session root in this task.** `proc.tls_io` is
  Task 6's payload, so the `tls_io`-to-`llm.request` join that names the
  executor, and the plan's `a_tls_write_names_the_executor` fixture, move
  to Task 6 with the payload; `Span.executor` and `is_agent` are in place
  for it.
- **`fs.unlink` counts as a write for `phantom_write`**, since an
  `apply_patch` that deletes a file produces only an unlink; `fs.open`
  joins no span (the close carries what the open led to), and
  `fs.setattr` and `fs.mkdir` join without counting as writes.
- **The reconciler's `observe`/`on_tick` still return findings**, and
  the span records are drained with `Reconciler::take_records` after
  each step, so M3's scenarios and fixtures are unchanged; the span
  scenarios check both streams in production order (`check_all`). The
  envelope's `span` is set on findings inside a span and on
  `span.effects`, with the session id read from the records as the
  trace id.
- **`orphaned_work` needs the exit program** (`sched_process_exit`
  attached): without exits nothing says who still runs. `span.list`
  accepts no parameters at all as the default.

### Task 6

- **The return probes are their own programs**, `ssl_read_ret` and
  `ssl_read_ex_ret`: an object lists programs by function name, so the
  entry and return probes of one symbol cannot share one. The table's
  `hook` holds the symbol for both.
- **A process's maps are looked at 50 ms after its exec, then once a
  second while it lives**, not only at the heartbeat: busybox's
  `ssl_client` runs for a fraction of a second, and a sweep only at the
  heartbeat found its `libssl.so.3` too late or not at all. A process
  whose maps cannot be read has ended and is forgotten; an exit record
  forgets it sooner.
- **The attach is ok when `SSL_write` and `SSL_read` took**; the `_ex`
  forms are newer and a runtime may lack them. A file without the symbols
  (`/bin/busybox`, every shell) gets its `proc.tls_attach{ok:false}` once,
  as the plan says, and counts against the 64 paths.
- **The executor's write may come before or after the `http.request`**,
  within 500 ms either way: ring 1 reaches the log through the vsock
  stream and the VMM, ring 0 through the observer thread, and neither
  order is guaranteed. A request's body may also go out in several
  `SSL_write` calls, so a process whose writes of the window sum to the
  body's size (within a tenth plus 1 KiB) carries it too. The fixture
  `a_tls_write_names_the_executor` pins the plan's case, and two more
  scenarios the other order and the sum.
- **A late `tool.open` adopts a waiting exec as the only open span only
  within the 500 ms join window**; by argv it adopts within the full 2 s.
  The late case covers the observer writing the record a moment after the
  agent acted, which is milliseconds; a process exec'd a second before
  the span is more likely the agent's own runtime (a `claude` started
  from the session shell), which must not be a tool's.
- **The gated test downloads twice** with 2 s between: the first run
  loads `libssl.so.3`, whose probes attach on the sweep, and the second
  run's writes and reads are the ones asserted.
- **The sensor's own reads are nobody's effect.** Attaching a probe reads
  the file for its symbol, through virtio-fs, so the session's programs
  (`/bin/busybox`, `wget`, `ls`...) show up as `fs.open` and `fs.close`
  by the sensor's pid, which no process the sensor reports owns: the
  first gated run made 18 `no_process` findings of them. The reconciler
  now knows the sensor's pid from `proc.sensor_status` and judges none of
  its effects.
- **The symbols are resolved on a thread of the sensor's own.** Reading a
  program for its symbols (aya does it at each attach) took the sensor's
  one thread off its ring buffer for a few milliseconds per program, and
  that was enough for a `proc.tcp_connect` to reach the log after its
  `net.connect` instead of before, which the M3 test
  `a_download_to_a_blocked_address_is_a_joined_finding` showed as a
  finding naming "the session" rather than `wget`. The sensor now reads
  the file and finds the four functions' offsets on a `tls-resolve`
  thread (the `object` crate, the same aya uses, added to the workspace),
  which writes a byte to a pipe the event loop polls beside the ring
  buffer; the loop then attaches by absolute offset, a syscall each. The
  event path never waits on a file, and a program is read once.
- **`proc.sensor_status` names the sensor's other threads.** The
  resolver thread's reads reach ring 0 under its own thread id, which is
  not the sensor's pid, so the fix above left three `no_process`
  findings of them. The status record gains `threads` (absent when
  empty), the sensor fills it with the resolver's id before it sends the
  status, and the reconciler leaves every effect of those threads alone
  as it does the pid's.
- **`connect_without_dns` waits for the sensor's connect.** The rule
  named the process at the `net.connect` itself, so whether it said
  `wget` or "the session" depended on which ring's record the writer
  took first, by a fraction of a millisecond; the M3 test
  `a_download_to_a_blocked_address_is_a_joined_finding` turned on that
  race and failed one run in two once the sensor had more to do at an
  exec. The reconciler now holds a nameless connect until its
  `proc.tcp_connect` has met it or the 500 ms join window has passed,
  whichever is first, and judges it then with the process named; the
  finding's content is the same, and the `policy_denial` fixture's order
  changed by one line.
