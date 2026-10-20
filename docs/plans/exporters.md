# Exporting a session to OTLP and OCSF, and `audit.verify` (M5 Task 6, #28)

Branch `issue-28`, from `main` at 09cba4f. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`: section 3 (*Export*), section 4 (focus 8) and section 6, Task 6. Subject: `audit: export a session to OTLP and OCSF`.

`boxcar audit export PATH --format otlp|ocsf [--out FILE] [--otlp-endpoint URL]` reads a verified log and writes one of two forms of it:
- **OTLP:** one OpenTelemetry trace, the session with its model calls and tool spans, findings as span events.
- **OCSF:** one event per mapped record, as JSON lines.

Every span, span event and OCSF event points back to its record's `seq` and hash. For a given log and a given boxcar version, both forms are byte-for-byte deterministic. The control op `audit.verify{from_seq?}` verifies a running session's log against the writer's chain head, a bounded stretch per call. Section 10 records Codex's review of the first draft and what it changed.

## 1. Where it sits

What the code has, read for this plan:
- **The envelope** (`boxcar-proto audit.rs:307-347`):
  - `seq`, `ts_host_ns` (`CLOCK_REALTIME` when the writer took the record, above 2^53), `src`, `type`, `data`, `prev`, `hash` (`b3:` and 64 hex digits);
  - optionally `subject {pid, uid, gid}` and `span {trace_id, span_id}`. Only `tool.open`, `tool.close`, `span.effects` and a span's `finding` carry `span`. Its `trace_id` is the session id as text, and its `span_id` is the provider's raw `tool_use_id`.
- **What links the records:**
  - **A model call** (`llm.request`, then `llm.response`) pairs by `(flow, stream)` with no shared id. Over WebSocket one stream carries several calls, so a response pairs with the latest unanswered request on its `(flow, stream)`. A request can go unanswered, and a response can arrive with no request.
  - **A tool call:** `tool.open` lies between its call's `llm.request` and `llm.response` in the log, on the same `(flow, stream)`. Late opens are no exception (`track.rs:291`, `:375`).
  - **Closing it:** `tool.close` and `span.effects` join the open by `tool_use_id`. The close that counts is the one `span.effects.closed_seq` names. A null there means the span is still open: the reconciler rejected the closes it saw, for example one from another executor (`spans.rs:947`). OpenAI Responses also repeats closes.
  - **A repeated id:** the reconciler can evict a finished span and later accept its `tool_use_id` again (`spans.rs:1481`). `span.effects.opened_seq` tells the occurrences apart.
  - **Findings:** a `finding` names its span by `span_id` (four rules do) and its `evidence` by seq.
  - **Order:** the reconciler can write records after `vmm.stop`.
- **Text in the log:**
  - **Raw:** paths, argv (scrubbed only with `--scrub-argv`), `cmdline`, DNS names, SNI, URL paths (their query values redacted), and `tool.open.args` (scrubbed, up to 8 KiB).
  - **Capped but not scrubbed:** model names, tool names and `tool_use_id`s (`model/mod.rs:127`, `:254`).
  - **Never inline:** prompts, replies and tool results; the log holds only their sizes and BLAKE3 hashes.
  - **Scrubbed summaries** of at most 512 bytes: `args_summary`, `result_summary`, `finding.summary`.
- **Readers:**
  - `verify_session` and `verify_jsonl` return a `VerifyReport` with `incomplete` (Task 7).
  - `LogReader` trusts the hashes it reads (`reader.rs:7`).
  - Nothing builds a span index offline: `boxcar spans` asks a running VMM.
  - `boxcar-proto`'s `redact` has `scrub_argv` and `scrub_text`.
- **Fixtures:** no fixture holds a model call, a tool span and a finding together. `golden.rs` builds a deterministic chained log with `Chainer`.
- **The writer:**
  - Its chain head (`last_hash`) never leaves its thread; sinks see only `next_seq` and `failure`.
  - A failing writer publishes its failure before it rolls back, then exits (`writer.rs:328`).
  - `audit.subscribe` reaches it in-band (`Msg::Subscribe`), and it flushes before it answers.
- **Control:**
  - Ops run on the connection's thread, and server shutdown joins it (`server.rs:218`).
  - The CLI client waits 10 s for a reply (`client.rs:36`).
- **HTTP:** `ureq` 3.4 on rustls with the ring provider is the registry client's (`oci/client.rs:189-221`). It sets DNS, connect and header timeouts, but no deadline for the whole exchange.

## 2. Reading a log for export

`boxcar_audit::export::Log::read(path)` takes a session directory, or one chained `.jsonl` file, as `boxcar audit verify` does. It reads the log **once**: the verification walk keeps every record it verified (`verify::read_verified`, a variant of the walk that returns the records with the report). So the records exported are the bytes that were hashed. A file replaced, changed or cut back after the check cannot slip in.

What the read decides:
- **A broken chain** (`VerifyError`) exports nothing.
- **An intact log** is exported whole.
- **An incomplete log** (Task 7) exports the records that verified, up to its `last_seq`. The export then exits 4, as verify does, and says why on stderr.
- **No records at all** (incomplete as `no_segment`): OTLP gives `{"resourceSpans": []}` and OCSF nothing, with the same exit code. An empty `.jsonl` is no log, as verify says.
- **A kind this build does not know** is skipped and counted.
- **A known kind whose `data` does not parse** stops the export with exit 1: the log verified, so this is a log boxcar cannot read, not a cut.

**What an export may depend on:** only the log and the boxcar version that runs the export. No wall clock, host name, environment, locale or time zone enters it. Every list and map is built in a fixed order: seq order, or a fixed attribute order per span and event, with no `HashMap` iteration. A mapping change in a later version shows in the blessed snapshots.

## 3. OTLP

One `ExportTraceServiceRequest` in OTLP/JSON. The encoding:
- keys in lowerCamelCase;
- `traceId` and `spanId` as lowercase hex;
- enums as integers;
- `timeUnixNano` as decimal strings;
- attribute values as `{"stringValue"}`, `{"intValue": "<decimal>"}`, `{"boolValue"}`, `{"arrayValue": {"values": [...]}}`.

`intValue` is a signed 64-bit number. A `u64` above `i64::MAX` is written as `stringValue` instead, and in an array every element is then written as a string. Times and token counts never get near that limit; the rule keeps the output valid if one does.

The JSON is pretty-printed with a trailing newline (the same bytes are POSTed), from `serde` structs and vectors built in a fixed order. There is one `resourceSpans` with one `scopeSpans`, and its `scope` is `{name: "boxcar", version: <vmm.start.version>}`.

**The resource's attributes**, in this order and each only when the log has it:
- `service.name` = `boxcar`;
- `service.version` = `vmm.start.version`;
- `boxcar.session.id`;
- `boxcar.image.reference` and `boxcar.image.manifest_digest`;
- `boxcar.policy.sha256`;
- `boxcar.hardening.seccomp` and `boxcar.hardening.landlock`.

**Ids.**
- **The trace id** is the session id's 16 bytes (the UUIDv7 without its hyphens).
- **A tool span's id** is the first 8 bytes of BLAKE3 of its `tool_use_id`, as the M5 plan has it, for that id's first occurrence. A later occurrence of the same id hashes `tool_use_id`, a space and its `opened_seq`.
- **Every other span's id** is the first 8 bytes of BLAKE3 of a label and its first record's hash: `boxcar.session ` for the session span, `boxcar.chat ` for a model call.
- **A clash** (an all-zero id, which OTLP refuses, or the same id twice in one trace) takes the next 8 bytes of the same hash. The trace is checked for both.

### Spans

Every span carries `boxcar.record.seq` and `boxcar.record.hash` of the record that opened it, and the spans are in the order of that seq. A span whose end comes before its start (the wall clock stepped back) ends at its start.

| Span | Opened by | Ended by | Parent | `name`, `kind` |
|---|---|---|---|---|
| the session | `vmm.start`, else the first record | `vmm.stop`, else the last exported record | none | `boxcar.session`, 1 (internal) |
| a model call | `llm.request` | its `llm.response` (same `(flow, stream)`, the latest unanswered request), else its own time | the session | `chat <model>` (`chat` with no model), 3 (client) |
| a tool call | a `tool.open` that begins an occurrence (below) | see below | the model call open on the `tool.open`'s `(flow, stream)` when it was recorded, else the session | `execute_tool <tool_name>`, 1 (internal) |

**A tool call's occurrences.** The occurrences of a `tool_use_id` are its `span.effects` records, each opened by the `tool.open` at its `opened_seq`. A `tool.open` that no `span.effects` names is an occurrence of its own: the reconciler's records can be missing from a log cut short. A repeated `tool.open` within an occurrence, the reconciler's ignored duplicate, opens nothing.

**How an occurrence ends:**
- **`span.effects` with a `closed_seq`:** at that record, with that close's status. `ok` is OK (1), `error` is error (2).
- **`span.effects` with a null `closed_seq`:** the span was still open. It ends with the session, status unset and `boxcar.span.open` = true; no `tool.close` overrides that.
- **No `span.effects`:** at the first `tool.close` of its id after the open, marked `boxcar.span.close_unconfirmed` = true, with that close's status. With no close either, it ends with the session.

A response with no request opens no span and is counted as unpaired. A request with no response opens a span that ends at its own time.

**The session span:**
- **Attributes:** `boxcar.vmm.stop.reason`, `boxcar.vmm.exit_code`, and `boxcar.log.incomplete` (the kind) when the log was cut.
- **Status:** error when there is no `vmm.stop`, or its reason is `vcpu_error`, `audit_failed` or `vmm_error`, with the reason as the message. Otherwise unset.
- Records after `vmm.stop` (the reconciler's) still belong to the session: their findings become its events.

**A model call's attributes**, from the GenAI conventions as of semantic-conventions-genai commit 547934a (2026-10-18):
- `gen_ai.operation.name` = `chat`;
- **the provider:** `gen_ai.provider.name`, and the older `gen_ai.system` the M5 plan names, both `anthropic` or `openai`;
- **the request:** `gen_ai.request.model`, `gen_ai.request.max_tokens`, `gen_ai.request.stream`;
- **the response:** `gen_ai.response.model`, `gen_ai.response.finish_reasons` (`[stop_reason]`);
- **usage:**
  - `gen_ai.usage.input_tokens`, which includes cached tokens: for Anthropic, `input_tokens + cache_read_tokens`; for OpenAI, `input_tokens` as recorded, which already includes them;
  - `gen_ai.usage.cache_read.input_tokens`, when recorded;
  - `gen_ai.usage.output_tokens`;
  - a count the log does not have is left out;
- **errors:** `error.type` = the response's `degraded`, when it has one, and the span's status is then error;
- **boxcar's own:**
  - `boxcar.llm.api` (`anthropic`, `openai_chat` or `openai_responses`), `boxcar.llm.tool_uses`;
  - `boxcar.net.flow`, `boxcar.http.stream`;
  - the response's `boxcar.response.seq` and `boxcar.response.hash`;
  - `boxcar.llm.unanswered` = true when there was no response.

**A tool call's attributes:**
- `gen_ai.operation.name` = `execute_tool`, `gen_ai.tool.name`, `gen_ai.tool.call.id`;
- `boxcar.tool.args_b3`;
- from its `span.effects`:
  - `boxcar.span.procs` (an int array);
  - `boxcar.span.effects` (the effects' seqs, an int array);
  - `boxcar.span.executor_tgid`, `boxcar.span.truncated`;
- `boxcar.close.seq`, when it closed.

**Events.** Each `finding` is an event named `boxcar.finding`, at its record's time, on the span its `span_id` names. With no span, or one the log does not hold, the event goes on the session span, and an unresolved name is kept as `boxcar.finding.span_id`. A `span_id` names the latest occurrence opened before the finding. The event's attributes:
- `boxcar.finding.category`, `.score`, `.rule`, `.summary`;
- `.evidence` (the evidence's seqs, an int array), `.low_confidence`;
- `boxcar.record.seq`, `boxcar.record.hash`.

Events are in seq order.

**What an OTLP export holds of the log's text.** Of the log's raw text, only the finding summaries, which are already scrubbed. The identifiers the M5 plan names are kept, each passed through `redact::scrub_text` so a secret-looking value cannot ride in one:
- model names;
- tool names;
- `tool_use_id`s;
- the image reference.

Nothing else from the log's text appears: no path, argv, `cmdline`, DNS name, SNI, URL, `args`, `args_summary` or `result_summary`. A test checks it (section 7).

### The endpoint

With `--otlp-endpoint URL`, the export is POSTed with `Content-Type: application/json`.

**The URL:**
- It is parsed as a URL and must be `http` or `https`, with no user or password in it (refused, so a credential never lands in an error or a shell history line) and no query or fragment.
- Its path gets `v1/traces` appended (a trailing `/` is allowed), unless it already ends with `/v1/traces`.
- `http://` is accepted for any host: a collector usually listens on plain HTTP on the loopback or a private network. The address is the user's to choose.

**The client:**
- A `ureq` agent built like the registry client's: rustls with the ring provider, the host's roots, no redirects. The registry client's agent setup is factored out to share it.
- A global deadline of 60 s for the whole exchange.
- At most 64 KiB of the response body is read.

**The response:**
- **200** with an empty body, or a JSON object without a `partialSuccess`, is success.
- **A `partialSuccess`:**
  - `rejectedSpans` (a number, or a decimal string, either accepted) above 0 is a failure, with its `errorMessage`;
  - 0 with an `errorMessage` is success, with that message as a warning.
- **A 200 body that is not JSON** is a failure: the receiver is not speaking OTLP.
- **Any other status** is a failure, with the status and at most 512 bytes of the body.
- Nothing is retried: one run, one POST.

With both `--out` and `--otlp-endpoint`, the file is written first. Without `--out`, the export goes to stdout, unless an endpoint was given.

## 4. OCSF

**Version:** OCSF 1.9.0, the schema server's current version. Each mapped record becomes one compact JSON object on its own line, in seq order. The classes' and objects' requirements were read from the 1.9.0 schema with no profile (`schema.ocsf.io/api/classes/<class>?profiles=`, `/api/objects/<object>?profiles=`). One profile is used, `security_control`, on the events that carry a verdict (below), which list it in `metadata.profiles`. Every number OCSF types as a string is written as a decimal string, `user.uid` and `connection_info.uid` among them.

**Every event has:**
- `class_uid`, `category_uid`, `activity_id`, and `type_uid` = `class_uid * 100 + activity_id`;
- `activity_name`, when `activity_id` is 99;
- `time`: `ts_host_ns` in milliseconds;
- `severity_id`: 1 (informational), except for findings;
- `metadata`:
  - `version` = `"1.9.0"`;
  - `product` = `{name: "boxcar", vendor_name: "boxcar", version: <vmm.start.version>}`;
  - `uid` = the record's hash;
  - `sequence` = its `seq`;
  - `correlation_uid` = the session id;
  - `log_name` = `"boxcar"`.

**`status_id`** is 1 (success) or 2 (failure), from the outcome: an `OpResult`, a DNS `rcode`, an HTTP status, a tool's `status`. It is left out when the record has none.

**A verdict is not an outcome.** With the `security_control` profile, an allowed verdict is `action_id` 1 and `disposition_id` 1; a refused one is 2 and 2.

**The objects that need a source:**
- **`device`** (required by 1001 and 1007): `{type_id: 6, type: "Virtual", uid: <session id>}`.
- **`actor`** (required by 1001, 1007 and 6003):
  - `{process: {pid}, user: {uid}}` from the record's `subject`;
  - else `{application: {name: "boxcar"}}` (1.9.0 deprecates `app_name` for it).
- **`src_endpoint` and `dst_endpoint`:**
  - the flow's addresses, joined by `flow` from its `net.connect` or `net.udp`;
  - where the log has none for the record (DNS, or an unjoined flow), `src_endpoint` = `{name: "guest", uid: <session id>}` and `dst_endpoint` = `{name: "boxcar"}`. Both satisfy the object's "at least one of" constraint.
- **`file`:** `name` and `type_id` (1 regular file, 2 folder, 7 symbolic link, a node's type from its mode, 0 unknown) are always there, and `path` when the record has one.
- **A share's path** becomes a guest path through the `fs.mount` records (tag to guest path), as the reconciler joins them.

**What each kind becomes:**

| Kind | Class (category) | Activity | What it carries |
|---|---|---|---|
| `fs.create`, `fs.mkdir`, `fs.mknod`, `fs.symlink` | File System Activity 1001 (1) | 1 Create | `file` |
| `fs.link` | 1001 | 1 Create | `file` = the existing file (`target_path`), `file_result` = the new name (`path`) |
| `fs.open` | 1001 | 14 Open | `file`; `exec` in `unmapped` |
| `fs.read`, `fs.readdir` | 1001 | 2 Read | `file` |
| `fs.write`, `fs.fallocate` | 1001 | 3 Update | `file` |
| `fs.close` | 1001 | 99 (`Close`) | `file` with `hashes [{algorithm_id: 99, algorithm: "BLAKE3", value}]` and `size`; the byte counts in `unmapped` |
| `fs.unlink`, `fs.rmdir` | 1001 | 4 Delete | `file` |
| `fs.rename` | 1001 | 5 Rename | `file` (from), `file_result` (to) |
| `fs.setattr`, `fs.xattr` | 1001 | 6 Set Attributes | `file` |
| `fs.mount` | 1001 | 12 Mount | `file {name, path: guest path, type_id: 2}` |
| `fs.denied` | 1001 | its `op`'s activity (lookup and getattr: 8 Get Attributes), else 99 (`Denied`) | `file`, `status_id` 2; when `reason` is `policy`, `action_id` 2 and `disposition_id` 2; `reason` and `rule` in `status_detail` |
| `proc.exec` | Process Activity 1007 (1) | 1 Launch | `process {pid: tgid, ptid: tid, file {name, path, type_id: 1}, cmd_line, user {uid}, parent_process {pid: ppid}}` (1.6 deprecated `tid` for `ptid`); `cmd_line` is the argv scrubbed as `--scrub-argv` scrubs it |
| `proc.exit` with `group_dead` | 1007 | 2 Terminate | `process {pid: tgid}`; `exit_code` when it exited, the signal in `status_detail` |
| `net.connect`, `net.udp` | Network Activity 4001 (4) | 1 Open | `src_endpoint {ip, port}`, `dst_endpoint {ip, port, hostname}`, `connection_info {protocol_name, uid: flow, direction_id: 2}` (outbound; the object requires a direction), the verdict |
| `net.close` | 4001 | 2 Close | the flow's endpoints, `traffic {bytes_out, bytes_in}`; `dur_ms` and `reason` in `unmapped` |
| `net.dns` | DNS Activity 4003 (4) | 6 Traffic | `query {hostname, type}`, `answers [{rdata}]`, `rcode_id`, `rcode`; `status_id` from the `rcode`; the verdict |
| `http.request` | HTTP Activity 4002 (4) | its method (3 Get, 6 Post, ...; else 99 with the method) | `http_request {http_method, url {hostname, path, url_string}, user_agent, version}`, the flow's endpoints |
| `http.response` | 4002 | its request's method | `http_response {code}`, `http_request {http_method}`; `status_id` from the code |
| `finding` | Detection Finding 2004 (2) | 1 Create | `finding_info`, `risk_score`, `severity_id` (below); `evidence`, `span_id` and `low_confidence` in `unmapped` |
| `llm.request`, `llm.response`, `tool.open`, `tool.close` | API Activity 6003 (6) | 99 (`Model Request`, `Model Response`, `Tool Call`, `Tool Result`) | `api {operation, service {name}}`, `src_endpoint`, `actor`; for tools `status_id` from `status`; model names and token counts in `unmapped` |

**A finding's fields:**
- `finding_info` = `{uid: <record hash>, title: <rule>, desc: <summary>, types: [<category>], analytic {name: <rule>, type_id: 1}}`;
- `risk_score` = its score;
- `severity_id` by score: under 40 low (2), under 70 medium (3), under 90 high (4), else critical (5).

**API Activity's operations:** `chat` with the provider as the service for model calls; `execute_tool` with the tool's name (scrubbed, as in OTLP) as the service for tool records.

**What OCSF keeps of the log's text:**
- what OCSF exists to carry: paths, DNS names, URL hosts and paths (their queries already redacted), and argv as `cmd_line`, scrubbed;
- never `tool.open.args`, `args_summary` or `result_summary`.

**Skipped and counted:**
- `vmm.*`, `checkpoint`, `control.*`, `session.*`, `policy.*`, `sync`, `span.effects`;
- `net.dhcp`, `net.tls`, `net.inspect`, `net.drop`;
- `vsock.*`;
- every `proc.*` but `exec` and a `proc.exit` with `group_dead`; a thread's exit is counted as `proc.exit (thread)`;
- a kind this build does not know.

The counts go to stderr, never into the export.

## 5. `audit.verify`

The roadmap names the op `audit.verify {from_seq?}`, and the M5 plan says it "answers the writer's chain state". Here it means: **the log on disk, from `from_seq` (default 1), is a valid chain up to the writer's head, checked a bounded stretch per call.**

1. **The head.** The op sends the writer a new in-band message, `Msg::Head`, beside `Msg::Subscribe`. The writer flushes the segment and answers with its head: the last `seq` and `hash`, and the session directory.
   - **A failed writer** has no head it can vouch for: it published its failure before its best-effort rollback. The op answers `invalid_state`, naming the failure, and the log is left to `boxcar audit verify PATH` once the run ends.
   - **A closed writer** (`BrokenPipe`) answers `invalid_state` too, as `audit.subscribe` does.
   - **`from_seq` past the head** is `bad_request`.
2. **The walk**, on the connection's thread (ops already run there), through a new raw-record cursor in `boxcar-audit` (`verify::Range`):
   - **Start:** the last checkpoint the index lists **before** `from_seq`, or the log's start. A checkpoint's root covers the records since the previous checkpoint, so starting there gives the window `from_seq` sits in, including when `from_seq` is itself a checkpoint. The bootstrap is explicit: `LogReader::seek_seq` would skip the window.
   - **Records before `from_seq`:** read raw, and only their stored hashes kept, for the window.
   - **From `from_seq` on:** each record is hashed again from its raw line, with its `prev` link, each checkpoint's root and count, and the index line of each checkpoint in the range.
   - **Bounds:** the walk reads no segment or index line past the head it was given, so a writer appending meanwhile changes nothing.
   - **A stretch per call:** the walk stops after 50,000 records or 64 MiB, whichever comes first, or at the head.
   - **Cancellation:** it checks the server's shutdown flag between records, so a stopping VMM never waits on it. A stopped walk is answered `invalid_state` (`the session is stopping`).
3. **The reply**, `AuditVerify`:
   - `{from_seq, from_prev, to_seq, to_hash, head_seq, head_hash, checkpoints: <count>, more: bool}`;
   - **`from_prev`** is the stored hash of the record before `from_seq` (the genesis value for 1). A client that verified up to `from_seq - 1` compares it with the hash it holds.
   - **`more`** is true until `to_seq` reaches the head. When it does, the record there must carry the head's hash.

The errors:
- **A break** is `internal`. Its message is `VerifyError`'s, cut to 512 bytes.
- **The reply** has a fixed shape, well under the 1 MiB line limit, and a size test pins it.

The hello lists `audit.verify`, and `docs/control-protocol.md` gets its section.

**CLI:** `boxcar audit verify --control PATH [--from-seq N] [--json]` asks a running session:
- It calls the op until `more` is false, each reply within the client's 10 s timeout.
- It checks each reply's `from_prev` against the previous reply's `to_hash`.
- It prints `ok: verified seq <from>..<head> against the writer's head <hash>`.
- An older server, whose hello lacks `audit.verify`, gets a clear error.

A session directory or `.jsonl`, as now, verifies a log on disk.

## 6. `boxcar audit export`

`boxcar audit export PATH --format otlp|ocsf [--out FILE] [--otlp-endpoint URL]`:
- **Output:** writes the export to `FILE`, else to stdout unless an endpoint was given. `--otlp-endpoint` needs `--format otlp`.
- **stderr:** one summary line, for example `otlp: 1 trace, 9 spans, 2 events from 31 records (1 unpaired)` or `ocsf: 21 events from 31 records, 10 skipped (checkpoint 2, vmm.start 1, ...)`.
- **Exit codes:**
  - 0: exported;
  - 1: a broken chain (`fail: <break>`, nothing written), a payload that does not parse, an I/O error, or a POST that failed, an incomplete log's included;
  - 2: a usage error;
  - 4: an incomplete log whose verified prefix was exported (and POSTed, when asked).

## 7. Tests

**The fixture** is `crates/boxcar-audit/tests/fixtures/export/session.jsonl`, a chained log built by the test with `Chainer` from fixed timestamps and a fixed session id, as `golden.rs` builds its file, and blessed with `BOXCAR_BLESS=1`. It holds:
- **the session:** `vmm.start` (with image and hardening), `policy.loaded`, the two `fs.mount`s;
- **the network:** a `net.connect`, a `net.udp`, a `net.dns` that was allowed but answered SERVFAIL, and one that was refused;
- **the first model call:** an Anthropic call with cache tokens, `http.request`, `llm.request`, a `tool.open`, `http.response`, `llm.response`;
- **the tool's work:** `proc.exec` (an argv with a token in it), `fs.create`, `fs.write`, `fs.link`, `fs.close`, a thread's `proc.exit` and the group's;
- **the second model call:** `http.request`, `llm.request` and the `tool.close` it carries;
- **the reconciler's records:** `span.effects`, a finding on the span, one without a span, and one naming a span the log does not hold;
- **after the first call:**
  - the second `llm.response`;
  - a duplicate `tool.close` (OpenAI Responses' repeat);
  - a response with no request, and a request with no response;
  - two requests over WebSocket on one stream;
- **tool calls with harder endings:**
  - a second tool call whose `span.effects` has a null `closed_seq` despite a `tool.close` from another executor;
  - a third whose `tool_use_id` repeats after eviction, with its own `span.effects`;
- **the end:** a token count above `i64::MAX`, `net.close`, a `checkpoint`, `vmm.stop`, a finding after `vmm.stop`, and a record of a kind no build knows (`x.future`).

`fixtures/export/session.otlp.json` and `session.ocsf.jsonl` are its blessed exports. The fixture's argv, a model name and a tool name carry secret-looking values, to show the scrubbing.

**Tests (`boxcar-audit/tests/export.rs`):**
- the fixture verifies;
- each export matches its blessed file byte for byte;
- **determinism:** the same log exported twice by `Log::read` twice gives identical bytes, and the CLI does too, run as two processes with different `TZ`, `LANG` and `HOME` (review focus 8);
- **the OTLP export:**
  - the trace id is the session's;
  - every span's parent exists, and every id is distinct and non-zero;
  - the tool span is its model call's child, and its id is BLAKE3 of its `tool_use_id`;
  - the repeated id's second occurrence has a span of its own;
  - the duplicate close ends nothing;
  - a null `closed_seq` stays open, whatever the other executor's close said;
  - a finding naming an absent span is on the session span, with its name kept;
  - the response with no request opens no span; the request with no response opens one;
  - each WebSocket response pairs with the latest request on its stream;
  - Anthropic's input tokens include the cached ones;
  - the token count above `i64::MAX` is a string;
- **no raw text in OTLP:** none of the fixture's paths, argv, `cmdline`, DNS names, URLs, `args` or summaries (the findings' aside) appears; the secret-looking values in the model name, the tool name and the image are scrubbed;
- **the OCSF export:**
  - every event satisfies its class's required attributes and, recursively, those of its objects, with their "at least one of" constraints: a table from the 1.9.0 schema, in the test;
  - `type_uid` is right;
  - the argv's token is scrubbed in `cmd_line`;
  - the link's direction is right;
  - only the group's `proc.exit` maps;
  - the SERVFAIL is `status_id` 2 with an allowed verdict;
  - the skipped counts, `x.future` among them, are right;
- **a broken chain** exports nothing;
- **an incomplete fixture** (its last line cut) exports the verified prefix;
- **an empty log** exports the empty forms;
- **a record of a known kind with bad data** stops the export;
- **a file changed after reading** cannot change an export: the read and the export are one pass, and a test swaps a segment's bytes between `Log::read` and the export, which then holds the old bytes.

**CLI tests (`boxcar/tests/audit_cli.rs`):**
- `export` to stdout and to `--out`;
- each exit code: 4 for an incomplete log, 1 for an incomplete log whose POST failed;
- **`--otlp-endpoint`** against a local HTTP server in the test:
  - the path for a URL with and without a trailing `/`, and one already ending in `/v1/traces`;
  - the content type and the bytes;
  - a 500 is a failure;
  - a partial success with `rejectedSpans` as a number, and as a string, is a failure;
  - a 200 that is not JSON is a failure;
  - a body over 64 KiB is cut;
  - a server that never answers fails at the deadline;
- **usage errors:** a URL with a user and password, or a query, is refused before anything is read; `--otlp-endpoint` without `--format otlp`.

**`audit.verify`:**
- **ops tests:**
  - the reply on a live writer;
  - `from_seq` in the middle, and exactly at a checkpoint, and its `from_prev` equals the earlier record's hash;
  - a log longer than one stretch answers `more`, and a second call finishes it;
  - `from_seq` past the head is `bad_request`;
  - a closed log is `invalid_state`, and so is a failed one;
  - a record corrupted on disk is `internal`;
  - the shutdown flag stops a long walk at once;
  - the reply at its largest fits its limit;
- **`verify::Range`'s own tests:**
  - a range that starts inside a checkpoint's window, and one that starts on a checkpoint;
  - a range across a segment rotation;
  - a break before `from_seq`, which it does not see, and one after, which it does;
  - an index line appended during the walk, which it does not read;
- **the golden control lines** and `control_golden.rs` gain the op;
- **the CLI** against a fake server: it loops on `more`, and a `from_prev` that does not chain is refused;
- **a gated test in `kvm_m5`:**
  - `boxcar audit verify --control` during a run, and with `--from-seq` past the first answer;
  - after the run, `boxcar audit export` of the session in both forms.

**By hand, recorded as decisions:**
- **On the test box:** the fixture's OTLP export POSTed to `otelcol-contrib` 0.163.1 (the OTLP receiver on `127.0.0.1:4318`, the `debug` exporter with detailed verbosity), which decodes every span and event.
- **OCSF:** each of the fixture's OCSF events sent to the OCSF server's validator for 1.9.0, with no error.

Both were done on 2026-10-20:
- **The collector:** `otelcol-contrib` 0.163.1 answered the fixture's export `200 {"partialSuccess":{}}`, and its debug exporter decoded all 12 spans and 4 span events, with no error or warning.
- **The validator** (`POST schema.ocsf.io/api/v2/validate`) passed all 44 of the fixture's events, with no error. Its only warnings, on a first run, named `actor.app_name` and `process.tid` as deprecated in 1.9.0; they became `actor.application.name` and `process.ptid`, and a second run had no warning either.

## 8. Out of scope

- Metrics or logs in OTLP; protobuf OTLP; gRPC.
- A collector's credentials: no header flag, a later task's if asked.
- `docs/export.md`, which is Task 8's (#30). The mapping lives in the module docs and this plan until then.
- OCSF profiles beyond `security_control`.
- Exporting guest-clock times.
- Exporting a live session continuously.

## 9. Decisions (to the M5 plan's section 8 when the task ships)

- **An export reads the log once, in the verification walk**, so what it exports is what was hashed. Only the log and the running version shape it.
- **Identifiers are the exception to "no raw text" in OTLP**: model and tool names, `tool_use_id`s and the image, which the M5 plan names as attributes. Each passes through `scrub_text`. **OCSF carries argv scrubbed** as `--scrub-argv` scrubs it, and never the tools' arguments.
- **`gen_ai.provider.name` beside `gen_ai.system`,** pinned to semantic-conventions-genai 547934a. The conventions renamed `gen_ai.system` to `gen_ai.provider.name`, and both are written, for backends on either side of the rename. Input tokens include cached ones.
- **Model calls pair on `(flow, stream)`, with the latest unanswered request.**
- **A tool span is an occurrence `span.effects` defines**, ended only by the close it names. A null close stays open. Without `span.effects`, the first close ends the span, marked unconfirmed.
- **Ids:** BLAKE3 of the `tool_use_id` for a tool span's first occurrence (the M5 plan's). A later occurrence adds its `opened_seq`. The session and model-call spans use a label and their first record's hash. Clashes take the hash's next 8 bytes.
- **OCSF 1.9.0 with the `security_control` profile for verdicts; `net.udp` mapped beside `net.connect`; API Activity as 99 with names; only a group's exit is a process's termination.**
- **Values above `i64::MAX` are strings in OTLP.**
- **An incomplete log exports its verified prefix and exits 4**, as verify does. A broken one exports nothing.
- **`audit.verify` checks a bounded stretch per call against the writer's flushed head**, cancellable. It refuses a failed writer. The CLI chains the stretches by `from_prev`.
- **`--otlp-endpoint` takes `http://`**, never a user and password, and has a 60 s deadline and a 64 KiB response cap. Nothing is retried.

## 10. Review (2026-10-20, before the code)

Codex (`codex exec`, read-only, reasoning effort xhigh) reviewed the first draft (the plan's first commit) against the code and the specifications. Its findings, and what changed:

1. **A rejected close could end a span** (HIGH): a null `closed_seq` now stays open. Without `span.effects`, the first close ends the span, marked unconfirmed (section 3).
2. **Exported bytes could differ from verified ones** (HIGH): the export reads the log once, in the verification walk (section 2).
3. **A failed writer has no reliable head** (HIGH): `audit.verify` refuses it with `invalid_state` (section 5).
4. **Privacy weaker than promised** (HIGH): labels and ids are an explicit exception, scrubbed with `scrub_text`, and OCSF's `cmd_line` is scrubbed. The tests put secret-looking values in each (sections 3, 4, 7).
5. **A long verify could time out and hold up shutdown** (HIGH): stretches of 50,000 records or 64 MiB, `more`, the shutdown flag between records, and a CLI that loops (section 5).
6. **The range's checkpoint bootstrap** (MEDIUM): an explicit cursor from the last checkpoint before `from_seq`, bounded by the head; tests at a checkpoint, across a rotation, and during an index append (sections 5, 7).
7. **OCSF required fields** (MEDIUM): `file.type_id` everywhere, fallback endpoints for DNS and unjoined flows, and a recursive check of objects and their constraints (sections 4, 7).
8. **Profile-only fields** (MEDIUM): `security_control` is declared where verdicts are; OCSF's string-typed numbers are written as strings (section 4).
9. **A repeated `tool_use_id`** (MEDIUM): occurrences by `opened_seq`, a later occurrence's id with its `opened_seq`, and a trace-wide clash check (section 3).
10. **Missing context and clock steps** (MEDIUM): rules for no `vmm.start`, an empty log, an absent span and an end before a start. `vmm.stop` is no longer the end of the records (sections 2, 3).
11. **OCSF operations** (MEDIUM): only a group's exit terminates a process, the link's direction is fixed, API Activity is 99 with names, and a DNS outcome is separate from its verdict (section 4).
12. **The POST's deadline and responses** (MEDIUM): a 60 s deadline, a 64 KiB cap, URL parsing without a user or password, and `rejectedSpans` as a number or a string (section 3).
13. **int64 overflow** (MEDIUM): above `i64::MAX`, a string (section 3).
14. **GenAI conventions** (MEDIUM): pinned at a commit; `gen_ai.request.stream`, `error.type`, and cached input tokens counted in (section 3).
15. **Tests and bounds** (MEDIUM): the unpaired-response wording fixed, failed-writer, cancellation, size, bad-payload and exit-code tests added; `checkpoints` is a count (sections 5, 7).
16. **Determinism's contract** (LOW): narrowed to a log and a version, with a fixed order everywhere, tested by two processes under different environments (sections 2, 7).
