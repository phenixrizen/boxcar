# Exporting a session to OTLP and OCSF, and `audit.verify` (M5 Task 6, #28)

Branch `issue-28`, from `main` at 09cba4f. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`: section 3 (*Export*), section 4 (focus 8) and section 6, Task 6. Subject: `audit: export a session to OTLP and OCSF`.

`boxcar audit export PATH --format otlp|ocsf [--out FILE] [--otlp-endpoint URL]` reads a verified log and writes one of two forms of it:
- **OTLP:** one OpenTelemetry trace, the session with its model calls and tool spans, findings as span events.
- **OCSF:** one event per mapped record, as JSON lines.

Every span, span event and OCSF event points back to its record's `seq` and hash. Both forms are deterministic for a given log. The control op `audit.verify{from_seq?}` verifies a running session's log against the writer's chain head. Section 10 records the review of this plan.

## 1. Where it sits

What the code has, read for this plan:
- **The envelope** (`boxcar-proto audit.rs:307-347`):
  - `seq`, `ts_host_ns` (`CLOCK_REALTIME` when the writer took the record, above 2^53), `src`, `type`, `data`, `prev`, `hash` (`b3:` and 64 hex digits);
  - optionally `subject {pid, uid, gid}` and `span {trace_id, span_id}`. Only `tool.open`, `tool.close`, `span.effects` and a span's `finding` carry `span`. Its `trace_id` is the session id as text, and its `span_id` is the provider's raw `tool_use_id`.
- **What links the records:**
  - **A model call** (`llm.request`, then `llm.response`) pairs by `(flow, stream)` with no shared id. Over WebSocket one stream carries several calls, so a response pairs with the latest unanswered request on its `(flow, stream)`. A request can go unanswered, and a response can arrive with no request.
  - **A tool call:** `tool.open` lies between its call's `llm.request` and `llm.response` in the log, on the same `(flow, stream)`.
  - **Closing it:** `tool.close` and `span.effects` join the open by `tool_use_id`. The close that counts is the one `span.effects.closed_seq` names, since OpenAI Responses repeats closes and the reconciler ignores some. `span.effects` also carries the span's `procs` and `effects`.
  - **Findings:** a `finding` names its span by `span_id` (four rules do) and its `evidence` by seq.
  - **Order:** the reconciler can write records after `vmm.stop`.
- **Raw text in the log:** paths, argv, `cmdline`, DNS names, SNI, URL paths, and `tool.open.args` (scrubbed, up to 8 KiB). Prompts, replies and tool results are never inline, only sizes and BLAKE3 hashes. The summaries (`args_summary`, `result_summary`, `finding.summary`) are scrubbed and at most 512 bytes.
- **Readers:**
  - `verify_session` and `verify_jsonl` return a `VerifyReport` with `incomplete` (Task 7).
  - `LogReader` reads a session directory.
  - Nothing builds a span index offline: `boxcar spans` asks a running VMM.
- **Fixtures:** no fixture holds a model call, a tool span and a finding together. `golden.rs` builds a deterministic chained log with `Chainer`.
- **The writer's chain head** (`last_hash`) never leaves the writer's thread; sinks see only `next_seq` and `failure`. `audit.subscribe` reaches the writer in-band (`Msg::Subscribe`), and the writer flushes before it answers.
- **HTTP:** `ureq` 3.4 on rustls with the ring provider is the registry client's (`oci/client.rs:189-221`). Plain `http://` works in every build.

## 2. Reading a log for export

`boxcar_audit::export::Log::read(path)` takes a session directory, or one chained `.jsonl` file (as `boxcar audit verify` does):
- It verifies the log first:
  - **A broken chain** (`VerifyError`) stops the export.
  - **An intact log** is exported whole.
  - **An incomplete log** (Task 7) is exported up to its `last_seq`, the records that verified. The export then exits 4, as verify does, and says why on stderr.
- It reads the records up to the verified `last_seq` and no further, so a writer still appending cannot add an unverified record. A session directory is read with `LogReader`; a `.jsonl` file line by line, as `verify_jsonl` walks it.
- It parses each record's payload (`Payload::from_record`). A kind this build does not know is skipped and counted, as an unmapped one is.

The exporters read only the `Log`. Nothing else enters an export: no clock, no host name, no environment, not even the exporter's own version, so a newer boxcar exports an old log the same way.

## 3. OTLP

One `ExportTraceServiceRequest` in OTLP/JSON. The encoding rules:
- keys in lowerCamelCase;
- `traceId` and `spanId` as lowercase hex;
- enums as integers;
- 64-bit integers, `timeUnixNano` among them, as decimal strings;
- attribute values as `{"stringValue"}`, `{"intValue": "<decimal>"}`, `{"boolValue"}`, `{"arrayValue": {"values": [...]}}`.

The JSON is written pretty-printed with a trailing newline (the same bytes are POSTed), and built from `serde` structs whose field order is the struct's. There is one `resourceSpans` with one `scopeSpans`, and its `scope` is `{name: "boxcar", version: <vmm.start.version>}`.

**The resource's attributes**, each only when the log has it:
- `service.name` = `boxcar`;
- `service.version` = `vmm.start.version`;
- `boxcar.session.id`;
- `boxcar.image.reference` and `boxcar.image.manifest_digest`;
- `boxcar.policy.sha256`;
- `boxcar.hardening.seccomp` and `boxcar.hardening.landlock`.

**Ids.**
- **The trace id** is the session id's 16 bytes (the UUIDv7 without its hyphens).
- **A tool span's id** is the first 8 bytes of BLAKE3 of its `tool_use_id`, as the M5 plan has it.
- **Every other span's id** is the first 8 bytes of BLAKE3 of a label and its first record's hash: `boxcar.session ` for the session span, `boxcar.chat ` for a model call.
- **An all-zero id** (invalid in OTLP) takes the next 8 bytes instead.

### Spans

Every span carries `boxcar.record.seq` and `boxcar.record.hash`, of the record that opened it. The spans are in the order of that record's seq.

| Span | Opened by | Ended by | Parent | `name`, `kind` |
|---|---|---|---|---|
| the session | `vmm.start` | `vmm.stop`, else the last exported record | none | `boxcar.session`, 1 (internal) |
| a model call | `llm.request` | its `llm.response` (same `(flow, stream)`, the latest unanswered request), else its own time | the session | `chat <model>` (`chat` with no model), 3 (client) |
| a tool call | the first `tool.open` of its `tool_use_id` | the `tool.close` that `span.effects.closed_seq` names, else the first `tool.close`, else the session's end | the model call open on the `tool.open`'s `(flow, stream)` when it was recorded, else the session | `execute_tool <tool_name>`, 1 (internal) |

A response with no request opens no span, and is counted as unpaired.

**The session span:**
- **Attributes:** `boxcar.vmm.stop.reason`, `boxcar.vmm.exit_code`, and `boxcar.log.incomplete` (the kind) when the log was cut.
- **Status:** error when there is no `vmm.stop`, or its reason is `vcpu_error`, `audit_failed` or `vmm_error`, with the reason as the message. Otherwise unset.

**A model call's attributes** (the GenAI conventions' names):
- `gen_ai.operation.name` = `chat`;
- `gen_ai.provider.name`, and the older `gen_ai.system`, both `anthropic` or `openai` from `provider`;
- `gen_ai.request.model`, `gen_ai.request.max_tokens`;
- `gen_ai.response.model`, `gen_ai.response.finish_reasons` (`[stop_reason]`);
- `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`;
- boxcar's own: `boxcar.llm.api` (`anthropic`, `openai_chat` or `openai_responses`), `boxcar.llm.streaming`, `boxcar.llm.tool_uses`, `boxcar.llm.degraded`, `boxcar.net.flow`, `boxcar.http.stream`;
- the response's `boxcar.response.seq` and `boxcar.response.hash`;
- `boxcar.llm.unanswered` = true when there was no response.

**A tool call's attributes:**
- `gen_ai.operation.name` = `execute_tool`, `gen_ai.tool.name`, `gen_ai.tool.call.id`;
- `boxcar.tool.args_b3`;
- from its `span.effects`: `boxcar.span.procs` (an int array), `boxcar.span.effects` (the effects' seqs, an int array), `boxcar.span.executor_tgid`, `boxcar.span.truncated`;
- `boxcar.close.seq`.

**A tool call's status** comes from the close that counts: `ok` is OK (1), `error` is error (2), and no close leaves it unset.

**Events.** Each `finding` is an event named `boxcar.finding`, at its record's time, on the span its `span_id` names, or on the session span when it names none. Its attributes:
- `boxcar.finding.category`, `.score`, `.rule`, `.summary`;
- `.evidence` (the evidence's seqs, an int array), `.low_confidence`;
- `boxcar.record.seq`, `boxcar.record.hash`.

Events are in seq order.

**What an OTLP export never holds:** any raw text of the log beyond the finding summaries. No path, argv, `cmdline`, DNS name, URL, `args`, `args_summary` or `result_summary`; a test checks it (section 7).

### The endpoint

With `--otlp-endpoint URL`, the export is POSTed to `URL` with `/v1/traces` appended (unless the URL already ends with it), with `Content-Type: application/json`:
- **The client:** a `ureq` agent built like the registry client's (rustls with the ring provider, the host's roots, 30 s timeouts, no redirects). The registry client's agent setup is factored out to share it.
- **`http://`** is accepted for any host: a collector usually listens on plain HTTP on the loopback or a private network. The address is the user's to choose.
- **200:** success, unless the body's `partialSuccess.rejectedSpans` is non-zero, which is reported as a failure with its `errorMessage`.
- **Anything else** is a failure, with the status and at most 512 bytes of the body. Nothing is retried: one run, one POST.

With both `--out` and `--otlp-endpoint`, the file is written first. Without `--out`, the export goes to stdout, unless an endpoint was given.

## 4. OCSF

**Version:** OCSF 1.9.0, the schema server's current version. Each mapped record becomes one compact JSON object on its own line, in seq order. Each class's requirements were read from the 1.9.0 schema with no profile: `schema.ocsf.io/api/classes/<class>?profiles=`.

**Every event has:**
- `class_uid`, `category_uid`, `activity_id`, and `type_uid` = `class_uid * 100 + activity_id`;
- `time`: `ts_host_ns` in milliseconds;
- `severity_id`: 1 (informational), except for findings;
- `status_id`: 1 (success) or 2 (failure), from an `OpResult` or a verdict; absent when the record has neither;
- `metadata`:
  - `version` = `"1.9.0"`;
  - `product` = `{name: "boxcar", vendor_name: "boxcar", version: <vmm.start.version>}`;
  - `uid` = the record's hash;
  - `sequence` = its `seq`;
  - `correlation_uid` = the session id;
  - `log_name` = `"boxcar"`.

**When a verdict refused something:** `action_id` 2 (denied) and `disposition_id` 2 (blocked); an allowed one is 1 and 1.

**The objects that need a source:**
- **`device`** (required by 1001 and 1007): `{type_id: 6, type: "Virtual", uid: <session id>}`.
- **`actor`** (required by 1001, 1007 and 6003):
  - `{process: {pid}, user: {uid}}` from the record's `subject`;
  - else, for model and tool records, `{app_name: <provider>}`;
  - else `{app_name: "boxcar"}`.
- **A share's path** becomes a guest path through the `fs.mount` records (tag to guest path), as the reconciler joins them.

**What each kind becomes:**

| Kind | Class (category) | Activity | What it carries |
|---|---|---|---|
| `fs.create`, `fs.mkdir`, `fs.mknod`, `fs.symlink`, `fs.link` | File System Activity 1001 (1) | 1 Create | `file {name, path, type_id}`; `fs.link`'s source as `file_result` |
| `fs.open` | 1001 | 14 Open | `file`; `exec` in `unmapped` |
| `fs.read`, `fs.readdir` | 1001 | 2 Read | `file` |
| `fs.write`, `fs.fallocate` | 1001 | 3 Update | `file` |
| `fs.close` | 1001 | 99 Other (`activity_name` `Close`) | `file` with `hashes [{algorithm_id: 99, algorithm: "BLAKE3", value}]` and `size`; the byte counts in `unmapped` |
| `fs.unlink`, `fs.rmdir` | 1001 | 4 Delete | `file` |
| `fs.rename` | 1001 | 5 Rename | `file` (from), `file_result` (to) |
| `fs.setattr`, `fs.xattr` | 1001 | 6 Set Attributes | `file` |
| `fs.mount` | 1001 | 12 Mount | `file {name, path: guest path, type_id: 2}` |
| `fs.denied` | 1001 | the activity of its `op` (lookup and getattr as 8 Get Attributes), else 99 | `file`, status 2, `action_id` 2, `disposition_id` 2; `reason` and `rule` in `status_detail` |
| `proc.exec` | Process Activity 1007 (1) | 1 Launch | `process {pid: tgid, tid, file {name, path}, cmd_line, user {uid}, parent_process {pid: ppid}}` |
| `proc.exit` | 1007 | 2 Terminate | `process {pid: tgid}`; `exit_code` when it exited, a signal in `status_detail` |
| `net.connect`, `net.udp` | Network Activity 4001 (4) | 1 Open | `src_endpoint {ip, port}`, `dst_endpoint {ip, port, hostname}`, `connection_info {protocol_name, uid: flow}` |
| `net.close` | 4001 | 2 Close | the flow's endpoints (joined by `flow`), `traffic {bytes_out, bytes_in}`; `dur_ms` and `reason` in `unmapped` |
| `net.dns` | DNS Activity 4003 (4) | 6 Traffic | `query {hostname, type}`, `answers [{rdata}]`, `rcode_id`, `rcode` |
| `http.request` | HTTP Activity 4002 (4) | its method (3 Get, 6 Post, ...; else 99) | `http_request {http_method, url {hostname, path, url_string}, user_agent, version}`, the flow's endpoints |
| `http.response` | 4002 | its request's method | `http_response {code}`, `http_request {http_method}` |
| `finding` | Detection Finding 2004 (2) | 1 Create | `finding_info`, `risk_score`, `severity_id` (below); `evidence`, `span_id` and `low_confidence` in `unmapped` |
| `llm.request`, `llm.response`, `tool.open`, `tool.close` | API Activity 6003 (6) | 1 Create for a request or an open; 2 Read for a response or a close | `api {operation, service {name}}`, `src_endpoint` (the flow's), `actor`; model names and token counts in `unmapped` |

**A finding's fields:**
- `finding_info` = `{uid: <record hash>, title: <rule>, desc: <summary>, types: [<category>], analytic {name: <rule>, type_id: 1}}`;
- `risk_score` = its score;
- `severity_id` by score: under 40 low (2), under 70 medium (3), under 90 high (4), else critical (5).

**API Activity's operations:** `chat` for model calls, and `execute_tool` with the tool's name as the service for tool records.

**What every kind skips:** each kind keeps the fields it has, and none carries `tool.open.args`, `args_summary` or `result_summary`.

**Skipped and counted:**
- `vmm.*`, `checkpoint`, `control.*`, `session.*`, `policy.*`, `sync`, `span.effects`;
- `net.dhcp`, `net.tls`, `net.inspect`, `net.drop`;
- `vsock.*`;
- every `proc.*` but `exec` and `exit`;
- a kind this build does not know.

The counts go to stderr, never into the export.

## 5. `audit.verify`

The roadmap names the op `audit.verify {from_seq?}`, and the M5 plan says it "answers the writer's chain state". Here it means: **the log on disk, from `from_seq` (default 1) to the writer's head, is a valid chain that ends at the head the writer holds.**

1. **Flush.** The op sends the writer a new in-band message, `Msg::Head`, beside `Msg::Subscribe`. The writer flushes the segment and answers with its head: the last `seq` and `hash`, and the session directory. A writer that failed answers with its failure; one that is closed, with `BrokenPipe`.
2. **Verify.** On the connection's thread (ops already run there), it checks the session's log from `from_seq` to the head's `seq`, with a new `verify_range(dir, from_seq, to_seq)` in `boxcar-audit`:
   - it rehashes each record from `from_seq` on;
   - it checks each `prev` link and each checkpoint's root and count in the range, using the stored hashes of the records before `from_seq` that a checkpoint's window covers;
   - it checks the index lines of the checkpoints in the range.

   Before `from_seq` it reads only. `LogReader::seek_seq` starts the walk at the checkpoint at or before `from_seq`.
3. **Compare.** The record at the head's `seq` must have the head's hash.

The reply, `AuditVerify`:
- `{ok: true, from_seq, from_prev, last_seq, last_hash, checkpoints, failed}`;
- `from_prev` is the stored hash of the record before `from_seq` (the genesis value for 1). A client that verified up to `from_seq - 1` before compares it with the hash it holds, and so verifies a running log a stretch at a time.

The errors:
- **a break** is `internal`, with `VerifyError`'s message; the reply never says `ok: false`;
- **a closed log** is `invalid_state`, as for `audit.subscribe`;
- **`from_seq` past the head** is `bad_request`.

A failed writer's log is still verified: it was cut back to its last consistent record, and the reply says `failed: true`. The hello lists `audit.verify`. `docs/control-protocol.md` gets its section, and its size limit holds.

**CLI:** `boxcar audit verify --control PATH [--from-seq N] [--json]` asks a running session; a session directory or `.jsonl`, as now, verifies a log on disk. It prints `ok: verified seq <from>..<last> against the writer's head <hash>`. An older server that lacks the capability gets a clear error.

## 6. `boxcar audit export`

`boxcar audit export PATH --format otlp|ocsf [--out FILE] [--otlp-endpoint URL]`:
- **Output:** writes the export to `FILE`, else to stdout unless an endpoint was given. `--otlp-endpoint` needs `--format otlp`.
- **stderr:** one summary line, for example `otlp: 1 trace, 9 spans, 2 events from 31 records (4 unpaired)` or `ocsf: 21 events from 31 records, 10 skipped (checkpoint 2, vmm.start 1, ...)`.
- **Exit codes:**
  - 0: exported;
  - 1: a broken chain (`fail: <break>`, nothing written), an I/O error, or a POST that failed;
  - 2: a usage error;
  - 4: an incomplete log, whose verified prefix was exported.

## 7. Tests

**The fixture** is `crates/boxcar-audit/tests/fixtures/export/session.jsonl`, a chained log built by the test with `Chainer` from fixed timestamps and a fixed session id, as `golden.rs` builds its file, and blessed with `BOXCAR_BLESS=1`. It holds:
- **the session:** `vmm.start` (with image and hardening), `policy.loaded`, the two `fs.mount`s;
- **the network:** a `net.connect` and a `net.dns`;
- **the first model call:** `http.request`, `llm.request`, a `tool.open`, `http.response`, `llm.response`;
- **the tool's work:** `proc.exec`, `fs.create`, `fs.write`, `fs.close`, `proc.exit`;
- **the second model call:** `http.request`, `llm.request` and the `tool.close` it carries;
- **the reconciler's records:** `span.effects`, a finding on the span and one without a span;
- **the end:**
  - the second `llm.response`;
  - a duplicate `tool.close` (OpenAI Responses' repeat);
  - a response with no request;
  - a model call over WebSocket with two requests on one stream;
  - `net.close`, a `checkpoint`, `vmm.stop`;
  - a finding after `vmm.stop`.

`fixtures/export/session.otlp.json` and `session.ocsf.jsonl` are its blessed exports.

**Tests (`boxcar-audit/tests/export.rs`):**
- the fixture verifies;
- each export matches its blessed file byte for byte;
- exporting the same log twice gives identical bytes (review focus 8);
- **the OTLP export:**
  - the trace id is the session's;
  - every span's parent exists;
  - the tool span is the model call's child, and its id is BLAKE3 of its `tool_use_id`;
  - the duplicate close does not end it;
  - the span-less finding is on the session span;
  - unpaired records open no span;
- **the WebSocket pairing:** each response pairs with the latest request on its stream;
- **no raw text in OTLP:** none of the fixture's paths, argv, `cmdline`, DNS names, `args` or summaries but the findings' appears in the export;
- **the OCSF export:**
  - every event has its class's required fields (a table of the 1.9.0 base classes' required attributes);
  - `type_uid` is right;
  - the counts of skipped kinds are right;
- **a broken chain** exports nothing;
- **an incomplete fixture** (its last line cut) exports the verified prefix, and says so.

**CLI tests (`boxcar/tests/audit_cli.rs`):**
- `export` to stdout and to `--out`;
- each exit code;
- `--otlp-endpoint` against a local HTTP server in the test: the path `/v1/traces`, the content type, the bytes; a 500, and a partial success, are failures;
- `--otlp-endpoint` without `--format otlp` is a usage error.

**`audit.verify`:**
- **ops tests:**
  - the reply on a live writer;
  - `from_seq` in the middle, and its `from_prev` equals the earlier record's hash;
  - `from_seq` past the head is `bad_request`;
  - a closed log is `invalid_state`;
  - a record corrupted on disk is `internal`;
- **`verify_range`'s own tests:** a range that starts inside a checkpoint's window; a break before `from_seq` that it does not see; one after, that it does;
- **the golden control lines** and `control_golden.rs` gain the op;
- **the CLI** against a fake server;
- **a gated test in `kvm_m5`:**
  - `boxcar audit verify --control` during a run, and again with `--from-seq` past the first answer;
  - after the run, `boxcar audit export --format otlp` of the session, whose spans include the session span;
  - the same with `--format ocsf`.

**By hand, recorded as decisions:**
- **On the test box:** the fixture's OTLP export POSTed to `otelcol-contrib` (the OTLP receiver on `127.0.0.1:4318`, the `debug` exporter with detailed verbosity), which decodes every span and event.
- **OCSF:** each of the fixture's OCSF events sent to the OCSF server's validator for 1.9.0, with no error.

## 8. Out of scope

- Metrics or logs in OTLP; protobuf OTLP; gRPC.
- A collector's credentials: no header flag, a later task's if asked.
- `docs/export.md`, which is Task 8's (#30). The mapping lives in the module docs and this plan until then.
- OCSF profiles (host, cloud, OSINT).
- Exporting guest-clock times.
- Exporting a live session continuously.

## 9. Decisions (to the M5 plan's section 8 when the task ships)

- **An export holds only what the log does**, through a `Log` read once. No wall clock, host, environment or exporter version enters it. The scope's and the product's versions are `vmm.start`'s.
- **`gen_ai.provider.name` beside `gen_ai.system`.** The GenAI conventions renamed `gen_ai.system` to `gen_ai.provider.name`. Both are written, for backends on either side of the rename.
- **Model calls pair on `(flow, stream)`, with the latest unanswered request**, which WebSocket's several calls per stream need. **A tool span ends at the close `span.effects` names**, not the first one, since OpenAI Responses repeats closes.
- **Ids:** BLAKE3 of the `tool_use_id` for tool spans (the M5 plan's), and of a label and the first record's hash for the session and model-call spans.
- **OCSF 1.9.0, with `net.udp` mapped beside `net.connect`.** The M5 plan names `net.connect` and `net.close`, but `net.close` also closes UDP flows, which would otherwise close with no open.
- **An incomplete log exports its verified prefix and exits 4**, as verify does. A broken one exports nothing.
- **`audit.verify` verifies a range against the writer's flushed head**, and gives `from_prev` so a client can verify a running log a stretch at a time.
- **`--otlp-endpoint` takes `http://`**: collectors are commonly plain HTTP on a private address, and the URL is the user's.

## 10. Review

To be filled in from Codex's adversarial review of this plan, before the code.
