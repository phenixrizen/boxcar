# Verifying and exporting a log

How to check a session's audit log and get it out of boxcar: `boxcar
audit verify`, on a log on disk or against a running session's audit
writer, and `boxcar audit export`, which writes a verified log as one
OpenTelemetry trace or as OCSF events and can send the trace to a
collector. The record fields are in [audit-events.md](audit-events.md);
the findings and tool spans an export carries are the reconciler's
([reconciler.md](reconciler.md)); the model calls are the gate's
([gate.md](gate.md)); the `audit.verify` op is in
[control-protocol.md](control-protocol.md).

## Verifying a log

`boxcar audit verify PATH` checks a log from its bytes on disk. PATH is a
session directory (`<data_dir>/sessions/<session_id>/`) or one `.jsonl`
file. Each line is read as plain JSON, never as a typed record, and the
first failure is reported:

- an object with the same key twice, at any depth, is not a record;
- `v` is 1, and every record names the log's session;
- `seq` is the previous one plus 1, from 1;
- `prev` is the previous record's `hash` (for the first, the session's
  genesis value);
- `hash` is computed again: blake3 of `prev`'s 32 raw bytes, then the
  line as compact JSON with its keys sorted and `hash` removed;
- each checkpoint's `root_hash` and `records_since` match the records
  since the checkpoint before it.

For a session directory it also checks `meta.json` against the segment
files, and that `checkpoints.jsonl` lists exactly the log's checkpoint
records, in order, with their segment, offset and fields. A single
`.jsonl` file is checked as a whole chain from seq 1; it has no index, so
the one cut it can tell from a break is a partial last line. A file with
no records is no log.

It prints one line on stdout:

| Exit | Line | Means |
|---|---|---|
| 0 | `ok: N records, S segments, last seq L` | The chain is intact. |
| 4 | `incomplete: N records verified, S segments, last seq L; the tail is cut (...), cause unknown` | What is there verifies; the tail was cut mid-write (below). |
| 1 | `fail: <the first break>` | A record changed, missing or out of order, a checkpoint or index line that does not match, or a file that cannot be read. |
| 2 | (the usage error, on stderr) | PATH and `--control` together, or neither. |

With `--json` the line is one object: the report `{"ok": true, "records",
"segments", "checkpoints", "last_seq", "last_hash"}`, with `ok: false` and
`incomplete {kind, segment, offset, bytes}` for an incomplete log; or the
break, `{"ok": false, "error", "message", ...}`, `error` being `io`,
`parse`, `chain`, `gap`, `checkpoint`, `checkpoint_count`, `genesis`,
`checkpoint_file` or `layout`, with that kind's fields (`seq`, `expected`
and `got` for `chain`).

Verify proves the chain is intact up to its last record. It does not
prove the session ended there: a log cut at a record boundary after the
last checkpoint the index lists verifies as intact, and only its missing
`vmm.stop` tells.

## An incomplete log

A process killed while it writes the log keeps every `write(2)` that
completed and loses the rest. The tails such a kill leaves, and only
those, make a log incomplete rather than broken:

| `kind` | The tail |
|---|---|
| `partial_line` | The newest segment ends in a partial line no longer than a record can be (64 KiB). |
| `unindexed_checkpoint` | The last record is a checkpoint that `checkpoints.jsonl` does not list yet; it lists every one before it. |
| `partial_index_line` | The same, with `checkpoints.jsonl` ending in the first bytes of that checkpoint's line, byte for byte. |
| `rotation` | The newest segment file is empty and `meta.json` does not list it yet; the one before ends in a checkpoint the index lists. |
| `no_segment` | `meta.json` lists one segment and there is none: a new session cut before its first record. |

`segment`, `offset` and `bytes` say where the tail is cut; what they name
for each kind is in [audit-events.md](audit-events.md). Exactly one of
these, at the very end; two, or one anywhere else, is a break (exit 1).

Verify cannot tell a crash from a deliberate cut. Whoever cuts the files
at the same place leaves the same bytes, and nothing in the log says why
it ended, so verify says where the log stops, not why: `cause unknown`.
An incomplete log hides no more than a cut at a record boundary can:
`checkpoints.jsonl` still proves every record up to the last checkpoint
it lists.

## Verifying a running session

`boxcar audit verify --control PATH [--from-seq N] [--json]` asks a
running session, through its control socket at PATH (`boxcar run` prints
it), to check its log as it is written. Each request is one
`audit.verify`:

1. The VMM asks the audit writer for its head, in band: the writer
   flushes the log and answers with its last record's seq and hash.
2. It walks the log on disk from `from_seq` toward that head, checking
   each record as verify checks a log on disk: its line hashed again, with
   no key twice, its seq, its `prev` link, each checkpoint's root and
   count and its line in `checkpoints.jsonl`. The record at the head must
   carry the head's hash.
3. It answers with the stretch it checked: `from_seq`, `from_prev` (the
   hash the record before `from_seq` stores), `to_seq`, `to_hash`, the
   head, how many checkpoints were among them, and `more` while `to_seq`
   is below the head.

A stretch is at most 50,000 records or 64 MiB of lines, whichever comes
first, and never past the head: records the writer appends meanwhile are
not read, and are left for the next request, which asks for a new head.
The walk starts at the last checkpoint the index lists before `from_seq`,
or at the log's start, since a checkpoint's root covers the records since
the one before it. The records between there and `from_seq` are read only
for the hashes they store, so a change to one of them that keeps its
stored hash is not seen; a run from seq 1 checks them all. The walk runs
on the control connection's thread, and stops between two records when
the session stops.

The CLI asks from `--from-seq` (1 by default) until `more` is false,
waiting up to 10 s for each reply, and chains the stretches: each must
start at the seq it asked for, from the hash the one before ended at (its
`from_prev` against the earlier `to_hash`), and end within the head, with
the head's hash when it reaches it. It prints `ok: verified seq
<from>..<head> against the writer's head <hash>; from <from_prev>, the
hash stored before seq <from>` and exits 0; with `--json`, `{"ok": true,
"from_seq", "from_prev", "to_seq", "head_seq", "head_hash",
"checkpoints", "stretches"}`. That `from_prev` is the first stretch's: a
run from the seq after an earlier run's head is chained to it when the
two hashes are one. There is no incomplete answer here: the walk reads only
lines the writer flushed whole.

It exits 1 when:

- the VMM found a break (the op's `internal` error, the verifier's message
  cut to 512 bytes), or a stretch does not chain: `fail: ...` on stdout;
- the session cannot verify its log: `error: ...` on stderr. Its writer
  has closed, or has failed (`invalid_state`, naming the failure: a failed
  writer published its failure before its rollback, so it has no head it
  can vouch for, and its log is for `boxcar audit verify PATH` once the
  run ends); the session is stopping (`invalid_state`); `--from-seq` is
  past the head (`bad_request`); or the VMM is older than `audit.verify`
  (its hello does not list it).

With `--json` each of these is `{"ok": false, "error", "message"}` on
stdout, `error` being `break`, `chain`, `unsupported`, or the op's error
code. `--from-seq` without `--control` is a usage error (exit 2).

## Exporting

`boxcar audit export PATH --format otlp|ocsf [--out FILE]
[--otlp-endpoint URL]` exports a log that verifies. PATH is what verify
takes.

- **Read once.** The log is read in the verification walk itself, which
  keeps each record as it verifies: what is exported is the bytes that
  were hashed, and a file changed after the check cannot change the
  export.
- **A broken log exports nothing**: `fail: <the break>` on stderr, exit 1.
- **An incomplete log exports what verified**, says `incomplete: the
  log's tail is cut (...); exported the N records that verified` on
  stderr, and exits 4. A log with no records (`no_segment`) exports
  `{"resourceSpans": []}` in OTLP and nothing in OCSF.
- **A record this version cannot read**, a known kind whose `data` does
  not fit it, stops the export with exit 1: the log verified, so it is
  not a cut. A kind this version does not know, a newer log's, is skipped
  and counted.
- **Deterministic.** The same log exported by the same boxcar version
  gives the same bytes. No clock, host name, environment, locale or time
  zone enters an export, and every list is built in a fixed order. The
  version an export names (`service.version`, `metadata.product.version`)
  is the one that wrote the log, from its `vmm.start`. A test exports in
  two processes with different `TZ`, `LANG` and `HOME` and compares the
  bytes.

Without `--out` the export goes to stdout, unless `--otlp-endpoint` sends
it; stdout carries the export alone. With both, the file is written
first. stderr has one summary line. The examples in this document come
from the test fixture, `crates/boxcar-audit/tests/fixtures/export/session.jsonl`,
and its blessed exports beside it; its summary lines are:

```text
otlp: 1 trace, 12 spans, 4 events from 53 records (1 unpaired)
ocsf: 44 events from 53 records, 9 skipped (checkpoint 1, policy.loaded 1, proc.exit (thread) 1, span.effects 3, vmm.start 1, vmm.stop 1, x.future 1)
```

| Exit | Means |
|---|---|
| 0 | Exported, and sent when asked. |
| 1 | A broken log, a record it cannot read, a file it cannot write, or a POST that failed, an incomplete log's included. |
| 2 | A usage error: `--otlp-endpoint` without `--format otlp`, or a URL it refuses. Checked before the log is read. |
| 4 | An incomplete log: what verified was exported, and sent when asked. |

## OTLP: the trace

`--format otlp` writes one `ExportTraceServiceRequest` in OTLP/JSON,
pretty-printed with a trailing newline: keys in lowerCamelCase, ids in
lowercase hex, enums as integers, times and integers as decimal strings.
It holds one `resourceSpans` with one `scopeSpans`, whose scope is
`boxcar` at the log's version.

The trace is the session: its trace id is the session id's 16 bytes
(`019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b` is
`019a2b3c4d5e7f608a9b0c1d2e3f4a5b`). Its spans, in the order of the
records that opened them:

| Span | Opened by | Ended by | Parent | `name`, `kind` |
|---|---|---|---|---|
| The session | `vmm.start`, else the first record | `vmm.stop`, else the last record | none | `boxcar.session`, 1 (internal) |
| A model call | `llm.request` | its `llm.response`, else where it started | the session | `chat <model>`, 3 (client) |
| A tool call | a `tool.open` that begins an occurrence | the close its `span.effects` names (below) | the model call open on the `tool.open`'s `(flow, stream)`, else the session | `execute_tool <tool>`, 1 (internal) |

- **Model calls** pair on `(flow, stream)`, the one thing a request and
  its response share: a response answers the latest request still
  unanswered there, since over WebSocket one stream carries several
  calls. A response with no request opens no span and is counted as
  unpaired; a request with no response opens a span that ends where it
  starts, with `boxcar.llm.unanswered` true.
- **Tool calls.** A span is one occurrence of a `tool_use_id` as the
  reconciler's `span.effects` defines it: opened by the `tool.open` at its
  `opened_seq`, ended only by the close at its `closed_seq`.
  - A `closed_seq`: the span ends there, OK (1) for a `tool.close` with
    status `ok`, ERROR (2) for one with `error`.
  - A null `closed_seq`, the reconciler having accepted no close (one from
    another process, say): the span ends with the session, its status
    unset and `boxcar.span.open` true, whatever `tool.close` the log holds.
  - No `span.effects` (a log cut before the reconciler wrote it): the
    first `tool.close` of the id after the open ends it, with that close's
    status and `boxcar.span.close_unconfirmed` true; with none, it ends
    with the session.

  A `tool.open` of an id whose occurrence is still open, which no
  `span.effects` names, opens nothing, and a repeated `tool.close` ends
  nothing more. An id the reconciler took again after letting its span go
  gets a span per occurrence.
- **Findings** are span events named `boxcar.finding`, at the finding's
  time, on the span its `span_id` names (the latest occurrence of that id
  opened before it), else on the session span. Records after `vmm.stop`,
  such as the reconciler's last findings, are exported like any other.
- **Time.** A span whose end comes before its start (the wall clock
  stepped back) ends at its start.

**Span ids** are the first 8 bytes of a BLAKE3 hash:

- a tool span's, of its raw `tool_use_id` (the log's `span.span_id`), for
  the id's first occurrence; a later occurrence hashes the id, a space and
  its `tool.open`'s seq;
- the session span's, of `boxcar.session ` and the 32 bytes of its first
  record's hash; a model call's, of `boxcar.chat ` and its `llm.request`'s
  hash.

An id that is zero, or already taken in the trace, takes the hash's next
8 bytes.

## OTLP: attributes

Every span and event carries `boxcar.record.seq` and `boxcar.record.hash`
of the record it comes from (the one that opened the span, the finding's
own), which find it in the log.

- **The resource**, each when the log has it: `service.name` (`boxcar`),
  `service.version` (from `vmm.start`), `boxcar.session.id`,
  `boxcar.image.reference` and `boxcar.image.manifest_digest`,
  `boxcar.hardening.seccomp` and `boxcar.hardening.landlock`, and
  `boxcar.policy.sha256` (from `policy.loaded`).
- **The session span:** `boxcar.vmm.stop.reason`, `boxcar.vmm.exit_code`,
  and `boxcar.log.incomplete` (the kind) for an incomplete log. Its status
  is ERROR when the log has no `vmm.stop`, or its reason is `vcpu_error`,
  `audit_failed` or `vmm_error`; unset otherwise.
- **A model call**, after the GenAI semantic conventions as of
  semantic-conventions-genai commit 547934a:
  - `gen_ai.operation.name` = `chat`;
  - `gen_ai.provider.name` and `gen_ai.system`, both `anthropic` or
    `openai` (for either OpenAI API): the conventions renamed the second
    to the first, and both are written for backends on either side of the
    rename;
  - `gen_ai.request.model`, `gen_ai.request.max_tokens`,
    `gen_ai.request.stream`, `gen_ai.response.model`,
    `gen_ai.response.finish_reasons` (the stop reason);
  - `gen_ai.usage.input_tokens`, which counts cached tokens in, as the
    conventions do: Anthropic's records count them apart, so it is
    `input_tokens` plus `cache_read_tokens`, while OpenAI's input count
    already holds them; `gen_ai.usage.cache_read.input_tokens` and
    `gen_ai.usage.output_tokens`. A count the log lacks is left out;
  - `error.type` = the response's `degraded`, when it has one, and the
    status is then ERROR;
  - `boxcar.llm.api` (`anthropic`, `openai_chat` or `openai_responses`),
    `boxcar.llm.tool_uses`, `boxcar.net.flow`, `boxcar.http.stream`, and
    the response's `boxcar.response.seq` and `boxcar.response.hash`; or,
    for a request no response answered, `boxcar.llm.unanswered` = true
    and none of the response's attributes.
- **A tool call:** `gen_ai.operation.name` = `execute_tool`,
  `gen_ai.tool.name`, `gen_ai.tool.call.id`, `boxcar.tool.args_b3` (the
  arguments' hash); from its `span.effects`, `boxcar.span.procs` (tgids),
  `boxcar.span.effects` (the effects' seqs), `boxcar.span.executor_tgid`,
  `boxcar.span.attribution_unverified` (its reasons, when there are any)
  and `boxcar.span.truncated`; `boxcar.close.seq` when it closed.
- **A finding event:** `boxcar.finding.category`, `.score`, `.rule`,
  `.summary`, `.evidence` (the evidence's seqs), `.low_confidence`, and
  `.span_id` when its `span_id` names no span in the log.

An `intValue` is a signed 64-bit integer. A count above `i64::MAX` is
written as a `stringValue` instead, and in an array every element then
is: the fixture's output count of 18446744073709551615 shows it.

**What an OTLP export never holds.** None of the log's raw text: no path,
argv, `cmdline`, DNS name, server name, URL, user agent, address, tool
arguments, `args_summary` or `result_summary`. Prompts and replies are not
in the log to begin with. The findings' summaries are the one text it
carries, and the log holds them scrubbed. The identifiers the attributes
need (model names, tool names, `tool_use_id`s, stop reasons, the image
reference) each go through the redaction scrub, so a secret-looking value
in one comes out as `[redacted]`; the scrub over-matches on purpose, so a
long identifier can too. The fixture's model named `sk-ant-api03-...` is
exported as `chat [redacted]`.

The fixture's first tool call, abridged:

```json
{
  "traceId": "019a2b3c4d5e7f608a9b0c1d2e3f4a5b",
  "spanId": "ae8e5d78984dadee",
  "parentSpanId": "67d56f53ce280d9f",
  "name": "execute_tool bash",
  "kind": 1,
  "startTimeUnixNano": "1792000000011000000",
  "endTimeUnixNano": "1792000000023000000",
  "attributes": [
    {"key": "boxcar.record.seq", "value": {"intValue": "11"}},
    {"key": "gen_ai.tool.call.id", "value": {"stringValue": "toolu_A"}},
    {"key": "boxcar.close.seq", "value": {"intValue": "23"}}
  ],
  "status": {"code": 1}
}
```

## Sending to a collector

`--otlp-endpoint URL` POSTs the OTLP export to a collector's OTLP/HTTP
receiver.

- **The URL** is `http` or `https`, with no user or password (a
  credential must not land in an error or a shell's history) and no query
  or fragment; anything else is refused with exit 2 before the log is
  read. `/v1/traces` is appended to its path, a trailing `/` dropped
  first, unless the path already ends with it. Plain `http://` is taken
  for any host: a collector often listens on the loopback or a private
  network.
- **The POST** is one request with the export's bytes and
  `Content-Type: application/json`, over rustls with the host's root
  certificates for `https` (plain `http` loads none, so a host without
  them still reaches a collector on its loopback), following no redirect,
  with 60 s for the whole exchange.
  Nothing is retried.
- **The answer.** 200 with an empty body, or with a JSON object that has
  no `partialSuccess`, is success. A `partialSuccess` whose
  `rejectedSpans` (a number or a decimal string) is above 0 is a failure,
  with its `errorMessage`; one that rejected nothing but has an
  `errorMessage` is success, and the message is shown. A 200 whose body
  is not a JSON object is a failure: the receiver is not speaking OTLP.
  Any other status, a redirect included, is a failure, shown with at most
  512 bytes of the body; a 202 or 204 too, by choice: OTLP/HTTP has one
  success, 200 with an `ExportTraceServiceResponse`, and a receiver that
  answers otherwise is not speaking it. At most 64 KiB of an answer is
  read.

stderr then says `sent to` and the URL posted to (with `; the collector
says: <message>` when it sent one), or `error:`, the URL and why, and the
export exits 1.

To look at a session's trace in the OpenTelemetry Collector, run it with
the OTLP receiver on HTTP and the `debug` exporter:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
```

```bash
otelcol-contrib --config otelcol.yaml
boxcar audit export ~/.local/share/boxcar/sessions/<session-id> \
  --format otlp --otlp-endpoint http://127.0.0.1:4318
```

The export goes to `http://127.0.0.1:4318/v1/traces`, and the collector
prints each span and event it decoded.

## OCSF

`--format ocsf` writes OCSF 1.9.0 events, one compact JSON object per
line with its keys sorted, one for each record it maps, in seq order.
Every event has:

- `class_uid`, `category_uid`, `activity_id`, `type_uid` (`class_uid` ×
  100 + `activity_id`), and `activity_name` where the activity is 99;
- `time`: `ts_host_ns` in milliseconds;
- `severity_id`: 1 (informational), findings aside;
- `metadata`: `version` `1.9.0`; `product` `{name: "boxcar",
  vendor_name: "boxcar", version}`; `uid`, the record's hash; `sequence`,
  its seq; `correlation_uid`, the session id; `log_name` `boxcar`.

`metadata.uid` finds the record in the log, and `correlation_uid` joins a
session's events. `status_id` is 1 (success) or 2 (failure) where the
record has an outcome: a filesystem result, a DNS `rcode`, an HTTP status
(400 and above fail), a tool's `status`, a model response's `degraded`
(failure only).

**A verdict is not an outcome.** `net.connect`, `net.udp` and `net.dns`
carry the policy's verdict, and so does `fs.denied` when its `reason` is
`policy`: allowed is `action_id` 1 and `disposition_id` 1, refused is 2
and 2. These events list the `security_control` profile in
`metadata.profiles`. A lookup the policy allowed and the server answered
SERVFAIL is `status_id` 2 with an allowed verdict.

**The objects:**

- `device`, on File System and Process Activity: `{type_id: 6, type:
  "Virtual", uid: <session id>}`.
- `actor`, on those and API Activity: the record's `subject` as
  `{process: {pid}, user: {uid}}`, else `{application: {name: "boxcar"}}`.
- `src_endpoint` and `dst_endpoint`: the flow's addresses and ports,
  joined by its number from its `net.connect` or `net.udp`, the
  destination's first name as `hostname`. A record with no addresses (a
  lookup, or a flow the log does not open) has `{name: "guest", uid:
  <session id>}` and `{name: "boxcar"}`.
- `file`: `name`, `path` and `type_id`. The path is the guest's: a share's
  path joined to where its `fs.mount` mounted it.

`user.uid` and `connection_info.uid`, which OCSF types as strings, are
decimal strings.

## OCSF: what each record becomes

| Kind | Class (category) | Activity | What it carries |
|---|---|---|---|
| `fs.create`, `fs.mkdir`, `fs.mknod`, `fs.symlink` | File System Activity 1001 (1) | 1 Create | `file` (`type_id` 1, 2, from the node's mode, 7) |
| `fs.link` | 1001 | 1 Create | `file`, the existing file; `file_result`, the new name |
| `fs.open` | 1001 | 14 Open | `file`; `exec` and `flags` in `unmapped` |
| `fs.read`, `fs.readdir` | 1001 | 2 Read | `file` |
| `fs.write`, `fs.fallocate` | 1001 | 3 Update | `file` |
| `fs.close` | 1001 | 99 `Close` | `file` with `hashes` (BLAKE3, `algorithm_id` 99) and `size`; `bytes_read` and `bytes_written` in `unmapped` |
| `fs.unlink`, `fs.rmdir` | 1001 | 4 Delete | `file` |
| `fs.rename` | 1001 | 5 Rename | `file` (from), `file_result` (to) |
| `fs.setattr`, `fs.xattr` | 1001 | 6 Set Attributes | `file` |
| `fs.mount` | 1001 | 12 Mount | `file`, the guest directory |
| `fs.denied` | 1001 | its `op`'s (`lookup`, `getattr`, `access`, `getxattr`, `listxattr`: 8 Get Attributes), else 99 `Denied` | `file`; `status_id` 2; `status_detail` (`<op> refused: errno N`, the reason, the rule); the verdict when the reason is `policy` |
| `proc.exec` | Process Activity 1007 (1) | 1 Launch | `process {pid, ptid, file, cmd_line, user {uid}, parent_process {pid}}` |
| `proc.exit` of a thread group | 1007 | 2 Terminate | `process {pid}`; `exit_code`, or `status_detail` naming the signal that ended it |
| `net.connect`, `net.udp` | Network Activity 4001 (4) | 1 Open | the endpoints; `connection_info {protocol_name, uid: <flow>, direction_id: 2}` (outbound); the verdict |
| `net.close` | 4001 | 2 Close | the endpoints; `traffic {bytes_out, bytes_in}`; `dur_ms` and `reason` in `unmapped` |
| `net.dns` | DNS Activity 4003 (4) | 6 Traffic | `query {hostname, type}`, `answers [{rdata}]`, `rcode_id` (99 for a code OCSF does not list) and `rcode` (the code's OCSF name; for 99, its number as text); the verdict |
| `http.request` | HTTP Activity 4002 (4) | its method's (3 Get, 6 Post, ...), else 99 named by the method | `http_request {http_method, url {hostname, path, url_string}, version, user_agent}`; the endpoints |
| `http.response` | 4002 | its request's method's | `http_response {code}`, `http_request {http_method}`; the endpoints |
| `finding` | Detection Finding 2004 (2) | 1 Create | `finding_info`, `risk_score`, `severity_id`; `evidence`, `span_id` and `low_confidence` in `unmapped` |
| `llm.request`, `llm.response` | API Activity 6003 (6) | 99 `Model Request`, `Model Response` | `api {operation: "chat", service {name: <the API>}}`; the endpoints; the model, `streaming`, the token counts and the stop reason in `unmapped` |
| `tool.open`, `tool.close` | 6003 | 99 `Tool Call`, `Tool Result` | `api {operation: "execute_tool", service {name: <the tool>}}`; the endpoints; `tool_use_id` in `unmapped` |

- **`proc.exec`:** `pid` is the tgid, `ptid` the thread, `file` the
  program the kernel ran, and `cmd_line` the argv scrubbed as `boxcar run
  --scrub-argv` scrubs it, joined by spaces.
- **A finding:** `finding_info {uid: <record hash>, title: <rule>, desc:
  <summary>, types: [<category>], analytic {name: <rule>, type_id: 1}}`,
  `risk_score` its score, and `severity_id` by score: below 40 is 2 (low),
  below 70 is 3 (medium), below 90 is 4 (high), else 5 (critical).
- **API Activity:** a model record's service is the API the gate
  recorded (`anthropic`, `openai_chat`, `openai_responses`); a tool
  record's is the tool's name, a `tool.close` taking the name its
  `tool.open` gave (`tool` when the log has none).
- **An HTTP response** takes the method of the latest request on its
  `(flow, stream)`; with none, its activity is 0.

**What OCSF carries of the log's text.** What OCSF exists to carry, as
the log holds it: paths, DNS names and answers, URL hosts and paths (the
log has already redacted their query values), user agents, and the
findings' summaries, which the log holds scrubbed. Scrubbed on export:
`cmd_line`, model names, stop reasons, tool names and `tool_use_id`s.
Never: a tool's arguments, `args_summary` or `result_summary`.

**Skipped**, and counted in the summary line: `vmm.*`, `checkpoint`,
`control.*`, `session.*`, `policy.*`, `sync`, `span.effects`, `net.dhcp`,
`net.tls`, `net.inspect`, `net.drop`, `vsock.*`, every `proc.*` but
`proc.exec` and a thread group's `proc.exit` (a thread's exit is counted
as `proc.exit (thread)`), and a kind this version does not know.

The fixture's `proc.exec`, an argv of `curl -H "Authorization: Bearer
..." https://example.com/`, abridged and laid out over lines here:

```json
{
  "activity_id": 1,
  "class_uid": 1007,
  "metadata": {
    "correlation_uid": "019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b",
    "sequence": 14,
    "uid": "b3:af23ccb007a01dab432c67ed42306b3c157b379eb51327749c0149395c1fedd3"
  },
  "process": {
    "cmd_line": "curl -H Authorization:[redacted] https://example.com/",
    "file": {"name": "curl", "path": "/usr/bin/curl", "type_id": 1},
    "parent_process": {"pid": 1},
    "pid": 100,
    "ptid": 100,
    "user": {"uid": "1000"}
  },
  "type_uid": 100701
}
```

## Checked by hand

The tests compare each export of the fixture with its blessed file byte
for byte, and check every OCSF event against what its 1.9.0 class and
objects require. Two checks were also made by hand, on 2026-10-20, and
recorded in `docs/plans/exporters.md`:

- **The OpenTelemetry Collector.** `otelcol-contrib` 0.163.1, with the
  OTLP receiver on `127.0.0.1:4318` and the `debug` exporter at detailed
  verbosity, answered the fixture's export `200 {"partialSuccess":{}}`
  and decoded all 12 spans and 4 span events, with no error or warning.
- **The OCSF validator.** The OCSF schema server's validator for 1.9.0
  (`POST schema.ocsf.io/api/v2/validate`) passed all 44 of the fixture's
  events with no error. A first run warned that `actor.app_name` and
  `process.tid` are deprecated in 1.9.0; they became
  `actor.application.name` and `process.ptid`, and a second run had no
  warning.
