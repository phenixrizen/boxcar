# The reconciler

The reconciler is a thread of `boxcar run` that reads the session's audit
log as it is written, joins what the two rings say, and writes `finding`
records back into the same log. It is rules, not models: each finding names
the rule that fired, says in a sentence what it saw, and lists the records
it read as evidence, so a reader can go back to them. `boxcar events --type
finding` streams findings from a running session; `--min-score` keeps the
ones that matter. A score of 70 or more is written through to disk at once.
With the model traffic gate (`docs/networking.md`) it also keeps the session's
tool spans, writes each one's membership as `span.effects`, and answers
`boxcar spans`.

## How it joins

- **A filesystem effect to a process.** Filesystem records name the guest
  *thread* that acted (`subject.pid`). Ring 1's `proc.fork` (processes and
  threads) and `proc.exec` say which process each thread belongs to and
  from when; `proc.exit` with `group_dead` says when a process ended. A
  process is keyed by its id *and* its start time, so a reused pid is a new
  process. An effect at host time *t* belongs to the process whose life,
  widened by 500 ms on both sides, covers *t*. An effect whose thread no
  process owns yet waits 2 s for a late `proc.exec` before it is judged.
- **A TCP flow to a process.** `net.connect` (ring 0) and `proc.tcp_connect`
  (ring 1) carry the same 4-tuple; they join when they fall within 500 ms
  of each other, in either order.
- **Time.** `ts_host_ns` is the one clock across rings. `sync` records say
  how far the guest's clock stands from it and how surely; when the last
  pairing's round trip was over 2 ms, no pairing came for 30 s while ring 1
  was alive, or the reconciler missed records (its subscription lagged),
  findings that rest on a cross-ring join are marked `low_confidence` and
  lose 20 points.
- **A degraded sensor.** `proc.sensor_status` says which programs
  attached. Rules that need a program the sensor does not have are skipped:
  the attribution rules need `sched_process_exec`, `sched_process_fork` and
  `sched_process_exit`.

## Tool spans

A span is one tool call the model asked for. The gate's `tool.open` (the
model's reply asked for a tool) opens it, and the `tool.close` in the
agent's next request (the tool's result) closes it; both carry the span in
their envelope, with the session id as the trace id and the provider's
tool use id as the span id. In between, the reconciler attributes
processes and ring 0 effects to the span:

- **The agent.** The session's root process (`session.start.pid`) is the
  agent, and so is a span's executor: the process whose `proc.tls_io`
  write, within 500 ms of the gate's `http.request` and sized like its
  body (within a tenth plus 1 KiB, as one write or as the process's
  writes of the window summed), carried the model request the span came
  from. The agent itself is in no span.
- **A process.** A `proc.exec` while spans are open joins one when its
  ancestry (through `ppid`) reaches the agent: first by argv, for a shell
  tool (`Bash`, `bash`, `shell`, `exec_command`, `local_shell`, `exec`)
  whose declared `command` (or `cmd`, a string or an array joined with
  spaces; for a free-text tool such as Codex's `exec`, the quoted string
  after `cmd:` or `command:` in the arguments' summary) the exec
  carries, which is the shell's `-c` command being the declared
  one or containing it (Claude Code wraps it in `eval '...' < /dev/null
  && pwd -P >| ...`), or the whole argv being the declared one, after
  whitespace is collapsed and quotes dropped; else as the only open span.
  An exec that joins nothing waits 2 s for a late `tool.open`. A process
  forked or exec'd by a span's process joins that span, and a process
  that exec's again stays in its span.
- **An effect.** `fs.create`, `fs.close`, `fs.rename`, `fs.unlink`,
  `fs.mkdir` and `fs.setattr` join the span of the thread's process, and
  `net.connect` the span of the process its `proc.tcp_connect` named. A
  filesystem effect by a process in no span is the agent's own work (a
  `Write` tool writes from the agent): it joins the only open write tool
  span (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `apply_patch`), or
  the write tool span whose declared path it touches; a shell tool's work
  is its process's, and what the agent itself writes meanwhile (Codex
  installs plugins in the background) is nobody's. An effect that joins
  nothing waits 2 s for its process to join a span. The agent's own
  connections join no span.
- **The record.** At the close, and at `vmm.stop` for a span still open,
  the reconciler writes `span.effects`: the span's processes by tgid (at
  most 1024) and the seqs of its records (each process's `proc.exec`
  and the effects above, at most 4096), with `truncated` set when a limit
  cut the list. The effects themselves are never edited.

Findings inside a span carry its id in `span_id` and in their envelope.
`boxcar spans` lists the spans from the control socket's `span.list`
(docs/control-protocol.md), newest first, with the worst finding's score
inside each.

## The rules

| Category | Rule | Fires when | Score |
|---|---|---|---|
| `unattributed_effect` | `no_process` | a filesystem effect's thread belongs to no process the sensor reported, 2 s after it happened, while the sensor is attached | 60 |
| `sensor_silence` | `never_attached` | the VM runs a sensor, the session started, and 5 s later the sensor has said nothing | 85 |
| `sensor_silence` | `heartbeat_lost` | no heartbeat for over 3 s while a ring 0 effect arrived in the last 3 s; once per silence, re-armed by the next heartbeat | 85 |
| `indicator_removal` | `indicator_removal` | `fs.unlink`, `fs.rename` (the source) or `fs.setattr` to size 0 of a shell history (`.*_history`), a file under `/var/log/`, `/etc/ld.so.preload`, or a file under `/root/.ssh/` | 90 |
| `off_book_channel` | `memfd_create` | `proc.memfd` | 75 |
| `off_book_channel` | `shm_open` | `proc.file_open` of a path under `/dev/shm/` (sampled: one open in 64 is seen) | 75 |
| `network_anomaly` | `connect_without_dns` | `net.connect` to an address that no `net.dns` answer named in the last 60 s and that the stack had no name for (the gateway excepted); judged once the sensor's `proc.tcp_connect` has named the process, or 500 ms after the connect, whichever comes first, since the two come in either order | 60 |
| `network_anomaly` | `sni_mismatch` | `net.tls` whose server name was answered with addresses that do not include the flow's destination | 65 |
| `network_anomaly` | `dns_rate` | more than 50 `net.dns` queries within 10 s; then quiet for 10 s | 70 |
| `network_anomaly` | `dns_entropy` | 20 or more queries within 10 s whose first labels carry over 3.5 bits of entropy on average; then quiet for 10 s | 70 |
| `privilege_probe` | `lsm_deny` | any `proc.lsm_deny`: a `bpf()` call, or a signal to the sensor, refused | 80 |
| `policy_denial` | `policy_denial` | `net.dns`, `net.connect`, `net.tls`, `net.udp` or `vsock.connect` with `verdict: "deny"`, or `fs.denied` | 40 |
| `intent_effect_mismatch` | `argv` | a shell tool's span took a shell by ancestry alone (it was the only open span) whose command does not carry the declared one, and no exec in the span carried the declared command by its close (a runtime's helper shell before the command is no mismatch); once a span | 70 |
| `intent_effect_mismatch` | `phantom_write` | a write tool's call said `ok`, and a second after its close no `fs.create`, `fs.close` with bytes written, `fs.rename` or `fs.unlink` among its effects touched a declared path (`file_path`, `notebook_path`, `path`, `filename`, or the files an `apply_patch` names) | 65 |
| `intent_effect_mismatch` | `hidden_net` | a span's process made an allowed `net.connect` whose names and address appear nowhere in the call's arguments, and the call said `ok`; judged at the close | 55 |
| `orphaned_work` | `orphaned_work` | a span's process is still running a second after the span closed, while the sensor reports exits; once a span | 50 |

The span rules rest on cross-ring joins (`tool.open` is ring 0, the exec
ring 1) and are marked `low_confidence` as the joins are, `phantom_write`
excepted.

## What a finding carries

`{"category", "score", "rule", "summary", "evidence": [{"seq", "ring"}],
"low_confidence"}`, and `span_id` inside a span. `evidence` lists the
records the rule read, oldest first and the finding's cause last: the
effect, the process's `proc.exec` when known, the flow's `net.connect` and
the sensor's connect that joined it. The summary names the process by its
program and pid when the join found one (`wget (pid 212) connected to ...`),
the thread otherwise.

## Limits

- The reconciler never blocks the log's writer: it is a subscriber like any
  other, and if it falls behind it reads the gap back from the log and marks
  the findings of the next minute `low_confidence`.
- A process's first actions before the sensor attached (the sensor needs a
  moment at boot) are attributed only if their thread was later seen; the
  gated tests give it three seconds.
- The reconciler keeps the last 65536 records' rings for the evidence and
  prunes DNS answers after 60 s; a session is not a database.
- A span lists at most 1024 processes and 4096 effect records; 4096 spans
  are kept in memory, the oldest settled one going first; `span.list`
  returns at most 1024 entries.
