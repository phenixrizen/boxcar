# The control protocol, version 1

How a client (`boxcar status`, `boxcar stop`, `boxcar attach`, `boxcar
events`, `boxcar policy`, or conductor) drives a running VMM. The types are
in `crates/boxcar-proto/src/control.rs`; `cargo xtask schema` writes their
JSON Schema to `proto/schema/control-v1.json` and example lines to
`proto/testdata/control-v1.jsonl`.

## Transport

- A Unix stream socket, `<state>/control.sock`, mode 0600 in a 0700 state
  directory: `$XDG_RUNTIME_DIR/boxcar/<session_id>/` by default, else
  `/tmp/boxcar-<uid>/<session_id>/`. `boxcar run --ready-fd N` writes
  `{"ready":true,"control":"<path>","session_id":"<id>"}` and a newline to
  fd `N` once the socket is bound.
- Only a peer whose uid is the VMM's is served (`SO_PEERCRED`). Any other
  connection is closed before the hello and recorded as
  `control.connect{verdict:"deny"}`; a served one is recorded as `allow`.
- Every message is one line of UTF-8 JSON of at most 1 MiB, not counting
  the newline. A longer line is answered `bad_request` and the connection
  is closed. Unknown fields are ignored everywhere; a client ignores events
  it does not know.
- A connection may make 100 requests a second, in bursts of up to 100. A
  request over the budget is answered `rate_limited` and dropped.
- A client that leaves 2 MiB unread is cut off. The one stream the server
  paces for the client is `audit.subscribe` (below).
- The server speaks first, with the hello. Then the client sends requests,
  each answered by one response with the same `id`; the server may send
  events between responses.

```text
<- {"v":1,"event":"hello","protocol":"boxcar.control","versions":[1],"server":"boxcar/0.1.0","session_id":"...","capabilities":["pty","audit","policy.net","policy.inspect","findings","spans"]}
-> {"v":1,"id":1,"op":"status"}
<- {"v":1,"id":1,"ok":true,"result":{"state":"running",...}}
-> {"v":1,"id":2,"op":"stop","mode":"graceful"}
<- {"v":1,"id":2,"ok":true,"result":{"accepted":true}}
<- {"v":1,"event":"state","state":"stopping"}
<- {"v":1,"event":"state","state":"stopped"}
```

## Messages

**Hello** (the server's first line): `v` 1, `event` `"hello"`, `protocol`
`"boxcar.control"`, `versions` `[1]`, `server` `"boxcar/<version>"`,
`session_id`, and `capabilities`: the op families served beyond `status`
and `stop`, today
`["pty","audit","policy.net","policy.inspect","findings","spans"]`
(`policy.inspect`: the network policy carries `inspect` lines; `spans`:
`span.list` is served).

**Request**: `{"v":1,"id":N,"op":"<op>", ...}`. `id` is an unsigned
64-bit integer the client chooses; every other field is a parameter of the
op.

**Response**: `{"v":1,"id":N,"ok":true,"result":{...}}` or
`{"v":1,"id":N,"ok":false,"error":{"code":"<code>","message":"..."}}`.
`id` is 0 when the request had none that could be read. `message` is for
people; clients act on `code`.

**Event**: `{"v":1,"event":"<name>", ...}`; the events are listed below.

## Error codes

Exactly these, in `snake_case`:

| Code | When |
|---|---|
| `bad_request` | The line is too long, not UTF-8, not a JSON object, lacks `v`, `id` or `op`, or the parameters do not fit the op. |
| `unsupported_version` | `v` is not 1. |
| `unknown_op` | The server has no such op. |
| `invalid_state` | The op cannot be done in the VM's current state. |
| `not_found` | What the op names does not exist. |
| `busy` | The server cannot take the op now. |
| `rate_limited` | Over the connection's request budget; the request was dropped. |
| `internal` | The server failed. |

## Ops

### `status`

No parameters. The result:

| Field | Type | Meaning |
|---|---|---|
| `state` | `booting` / `running` / `stopping` / `stopped` | Where the VM is in its life. |
| `session_id` | string | The session's id. |
| `pid` | u32 | The VMM's process id. |
| `uptime_ms` | u64 | Milliseconds since the VM was built. |
| `vcpus` | u8 | |
| `mem_mib` | u64 | |
| `guest.init_ready` | bool | Init has said hello over the guest control channel. |
| `guest.session_pid` | u32 or null | The session's process id in the guest, once started. |
| `guest.exit` | `{code, signal}` or null | How the session ended, once it did (one of `code` and `signal` set, both null only when init could not tell). |
| `audit.next_seq` | u64 | The seq the log writer gives its next record. |
| `audit.failed` | bool | The log writer has failed (which stops the VM). |
| `devices` | string[] | The virtio devices present, by slot name in slot order: `fs:root`, `fs:workspace`, `net`, `vsock`. |
| `sensor.state` | `off` / `waiting` / `attached` / `degraded` / `silent` | The guest's sensor (ring 1): `off` for a VM without one (no vsock device, or `--no-sensor`); `waiting` until it says what it attached; `attached` or `degraded` as it said (`proc.sensor_status`); `silent` once its stream ended or no heartbeat came for 3 s. A server from before the sensor sends no `sensor`; read it as `off`. |
| `sensor.heartbeats` | u64 | Heartbeats taken so far. |
| `sensor.last_heartbeat_ns` | u64, omitted until the first | Host `CLOCK_REALTIME`, in nanoseconds, when the last heartbeat arrived. |

### `stop`

Parameters: `mode` (`graceful`, the default, or `force`), `timeout_ms`
(u64; 5000 when absent). `graceful`, while a session runs, asks the guest's
init to end it (a hangup and `SIGTERM` to the session's process group,
`SIGKILL` after `timeout_ms`) and the VM stops when the guest resets, or
a little after `timeout_ms` at the latest; `force`, or no session to end,
stops the vCPUs at once. The result is `{"accepted":true}`; then the
connection, and every other, hears `state` `stopping`, and `stopped` as the
server shuts down. The stop is recorded as `control.stop{by_pid, mode}`.
`boxcar run` exits 0 after a stop.

### `pty.attach`

Parameters: `session` (`"main"`, the only one), `mode` (`rw` or `ro`),
`replay_bytes` (u64, 0 when absent, capped at the server's 256 KiB
scrollback). The result is `{"raw":true,"attach_id":"<32 hex digits>"}`;
from the next byte the connection carries the session's terminal, both
ways, and nothing else: the newest `replay_bytes` of its output first, then
its output as it comes, with nothing missed or repeated between them. With
`rw`, what the client sends is typed into the session (bytes past the
server's 64 KiB input queue are dropped); with `ro` it is discarded. A client
that leaves more than 1 MiB of output unread, or takes no byte for 30 s, is
detached as slow: its stream ends after the last byte it took and the
connection is closed; the reason goes to the connections that watch the
attach (`pty.watch`). When the session's terminal ends, the stream ends
after its last byte and the connection is closed. A client may close its
sending side and keep reading.

Errors: `bad_request` (parameters that do not parse), `not_found` (a
`session` other than `main`), `invalid_state` (init has not opened the
terminal yet, or the VM has no vsock device). Once the terminal has ended,
an attach gets its replay, then the end.

### `pty.watch`

Parameters: `attach_id` (from a `pty.attach` response, on any connection),
`session` (optional, `"main"`). The result is `{}`; from then on this
connection hears the attach's `pty.detached`. Watching twice changes
nothing. Errors: `bad_request` (no `attach_id`), `not_found` (an unknown
`attach_id`, one whose attach has ended, or another `session`),
`invalid_state` (no vsock device).

### `pty.resize`

Parameters: `session` (`"main"`), `rows` and `cols` (each 1 to 65535). The
result is `{}`; the size goes to the guest unless the terminal has it
already, and the latest size any client asks for wins. Errors:
`bad_request` (a size out of range), `not_found` (another `session`),
`invalid_state` (the terminal is not open, or has ended), `busy` (the guest
control channel has too much waiting).

### `audit.subscribe`

Parameters, each optional: `from_seq` (u64; 1 when absent, and 0 means 1),
`types` (string[]: type prefixes, at most 32, each 1 to 64 bytes; `"net."`
takes every `net.*` record, `"fs.write"` that type; absent or empty takes
every type), `pid` (u32: only records attributed to that guest process),
`min_score` (u8, 0 to 100: only records whose `data.score` is at least
this; a record without a score passes, so with `types: ["finding"]` it keeps
the findings that matter). A record must pass every filter given.

Findings (`docs/reconciler.md`) are records like any other: a client that
wants them pushed subscribes with `types: ["finding"]`; the `findings`
capability says the server has a reconciler.

The result is `{"next_seq":N,"sub":K}`: `N` is the seq the log's next record
had when the subscription began (records below it come from the log on
disk, records from it on are live; a `from_seq` of `N` or more waits for
the live records), `K` the subscription's id on this connection, counting
from 1. Then, until the connection closes, the connection hears:

- `audit` events: `{"v":1,"event":"audit","sub":K,"rec":{...}}`, one
  record each, `rec` the record as the log holds it (see
  `docs/audit-events.md`), in seq order, with none missed or repeated.
- `audit.lagged` events: `{"v":1,"event":"audit.lagged","sub":K,
  "resume_seq":R}`: the client read too slowly for the server to hold the
  live records for it (the server keeps 16384 records a subscription), and
  it was dropped from the live stream. The records from `R` on follow, read
  back from the log and then live again; those before `R` were delivered.

The server never waits for a client on the writer's side. A client with
1 MiB unread is waited for by its own subscription only, which then lags as
above; one that takes no byte for 30 s is disconnected, and reconnects with
`from_seq`. A connection holds at most 4 subscriptions, which end with it.
The events stop, with the connection open, when the log ends (the VM is
stopping). Records a failed writer later cuts off the end of the log may
have been streamed before the failure.

Errors: `bad_request` (parameters that do not parse or pass the limits),
`busy` (4 subscriptions already), `invalid_state` (the audit log is closed
or has failed), `internal` (the log cannot be read).

### `policy.get`

No parameters. The result is the policy in force:

```json
{"net":{"default":"deny","allow":["example.com:443","*.github.io"],"deny":["10.0.0.0/8"],
        "inspect":["api.anthropic.com:443"]},
 "vsock":{"allow_ports":[5000]},
 "version":1}
```

`net.default` is `allow` or `deny`; `net.allow` and `net.deny` are the
rules' targets as written, each list in order, in the form `boxcar run
--allow` takes: `name[:port]`, `*.name[:port]`, `address[:port]` or
`address/prefix[:port]`. `net.inspect` lists the `inspect` lines (`boxcar
run --inspect`) the same way: destinations whose TLS the gate ends and
whose traffic it observes once an allow rule admitted the connection; they
decide no verdict, and a server from before them leaves the list out. `vsock.allow_ports` are the host ports a guest
vsock connection may reach besides the VMM's own (1024 to 1026). `version`
is 1 for the policy the VM started with, one more for each update. A VM
without a network card or a vsock device reports that part empty.

### `policy.update`

Parameters: `net` and `vsock`, each optional and in the shape `policy.get`
reports, each replacing its whole policy. At least one must be given. The
result is `{"policy_version":V}`, the version from now on, and the update is
recorded as `policy.changed{by_pid, version}`.

The network policy in force puts every deny before every allow, each list
in the order given, as `boxcar run` orders `--deny` and `--allow`: the first
rule that matches decides, so a deny wins over an allow of the same target.
(A policy file whose allows and denies are interleaved reads back from
`policy.get` in this shape, which is the same policy only when no allow
before a deny matches what that deny does.) The built-in denials stay: the
guest's own network, `0.0.0.0/8`, multicast and reserved addresses always,
and the six private ranges unless a rule allows exactly the range.

The new policy decides every later DNS query, connection and datagram. The
VMM then ends what is open and the new policy denies: TCP connections and
connects under way are reset (the guest gets an RST, the host socket is
closed with a reset), UDP mappings are closed, and each is recorded as
`net.close` with reason `policy`. What the new policy still allows is left
as it is. The vsock allowlist is read at each guest connection request;
connections already made to a port taken off the list stay open.

Errors, with nothing changed: `bad_request` (parameters that do not parse;
neither `net` nor `vsock`; over 4096 rules; a rule empty or over 512 bytes;
over 1024 ports; a rule that does not parse, named as
`net.allow[2] "exa_mple.com": ...`; a port below 1027, named as
`vsock.allow_ports[0]`), `invalid_state` (`net` on a VM without a network
card, `vsock` on one without a vsock device).

### `span.list`

Parameters: `active_only`, optional, `false` by default. The result is the
session's tool spans (docs/reconciler.md), newest first, at most 1024:

```json
{"spans":[{"span_id":"toolu_02","tool_name":"Write","opened_seq":61,"procs":0,"effects":1,"worst_score":0},
          {"span_id":"toolu_01","tool_name":"Bash","opened_seq":40,"closed_seq":58,"procs":2,"effects":3,"worst_score":55}]}
```

`span_id` is the provider's tool use id, `opened_seq` the seq of the
`tool.open` and `closed_seq` that of the `tool.close`, absent while the span
is open; `procs` and `effects` count what the reconciler has attributed to
it so far, and `worst_score` is the highest score of a finding inside it, 0
with none. With `active_only` only the open spans are listed. The list is
empty before the first tool call, and on a VM run without the reconciler's
index. `boxcar spans [--active] [--json]` prints it.

## Events

| Event | Fields | When |
|---|---|---|
| `hello` | see Messages | The server's first line. |
| `state` | `state`: `booting` / `running` / `stopping` / `stopped` | The VM entered that state. Sent to every connection; each state at most once a connection. `stopped` is the last line before the server closes the connection. |
| `pty.detached` | `attach_id`, `reason` | The server detached that attach from the session's terminal; to the connections that watch it (`pty.watch`). `reason` is `slow`: the client left more than 1 MiB unread or took no byte for 30 s. |
| `audit` | `sub`, `rec` | One audit record for subscription `sub`. |
| `audit.lagged` | `sub`, `resume_seq` | Subscription `sub` fell behind; the records from `resume_seq` on follow. |

## Limits, in one place

| What | Limit |
|---|---|
| A line, either way | 1 MiB |
| Requests a connection | 100 a second, bursts of 100 |
| Unread bytes before a connection is cut off | 2 MiB; an `audit` stream waits for the client from 1 MiB |
| A client that takes nothing (`pty.attach`, `audit.subscribe`) | 30 s |
| `pty.attach` replay | 256 KiB scrollback; 64 KiB input queue; 1 MiB output backlog |
| `audit.subscribe` | 4 a connection; 32 type prefixes of 1 to 64 bytes; 16384 live records queued a subscription |
| `policy.update` | 4096 rules of 1 to 512 bytes; 1024 vsock ports, each 1027 or more |
| `span.list` | 1024 entries, newest first |
