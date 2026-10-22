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
  how far the guest's clock stands from it and how surely (`rtt_ns`: a
  ping's round trip, or, through `ptp_kvm` where the guest has its clock,
  the microseconds one read of the TSC took, whatever the load); when the
  last pairing's bound was over 2 ms, no pairing came for 30 s while ring
  1 was alive, or the reconciler missed records (its subscription lagged),
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
  agent, and so is a span's bound executor: the process that opened the
  flow the model request the span came from went over (its
  `proc.tcp_connect` joined the flow's `net.connect`, before or after the
  request). Until that join, the process whose `proc.tls_io` write,
  within 500 ms of the gate's `http.request` and sized like its body
  (within a tenth plus 1 KiB, as one write or as the process's writes of
  the window summed), carried the request is a provisional executor, when
  it is the only process that fits; it is reconsidered with every write of
  the window (two that fit name none) and replaced by the flow's opener
  when that comes. A provisional executor is reported in `span.effects`
  and is never the agent: ancestry is traced to the root instead, and its
  own work is judged as any process's. The agent itself is in no span.
- **The close.** A span's executor is its request's bound executor, or,
  when that entry is gone, the process the sensor says opened the
  request's flow (learned at the open or later). A span with a known
  executor closes only by a `tool.close` that came over a flow that same
  process opened. An agent whose requests come from several processes (a
  script whose every request is a `curl` of its own) cannot be told from
  its own tools, which are the script's children too, so its spans stay
  open until the session ends, recorded then as they stand. Agents that
  send every request themselves (Claude Code, Codex) close theirs: one over a flow another process opened is dropped, and
  one over a flow whose opener is not known yet waits up to 2 s to learn
  it, then is dropped if it never does; so does one for a span whose
  request flow is on record but not yet who opened it. The span stays
  open for its own close (or is recorded as it stands at the VM's stop).
  Once the state has let a flow go for room (it remembers the last 16384
  flows, and the last 4096 openers), a close for a span whose request flow
  is not on record is dropped too: that flow may have been let go with its
  opener, and nothing then shows the close is the executor's. A span
  whose request flow is not on record in a log that never let one go (a
  log without the gate's flows), or a session without the sensor's
  lineage programs, takes any close: there is nothing to hold it to.
- **Bounds.** At most 256 spans are open at once: past that the oldest
  open span gets its `span.effects` as it stands (`closed_seq` null,
  `truncated`) and takes nothing more, nor its `tool.close`.
- **What is compared.** The gate hands the reconciler each call's
  arguments as the model sent them, in memory and never recorded (the
  record's copy is scrubbed); declared commands and paths are compared
  with what ran exactly, quotes kept. A span that has only the record's
  copy (a log read later) compares that copy when nothing in it was
  redacted, and where something was the `argv` rule cannot tell and says
  nothing. Findings quote the record's scrubbed copy, never the
  arguments as sent. With `boxcar run --scrub-argv` the log records each
  `proc.exec`'s argv scrubbed, and the sensor's ingest keeps each argv
  that scrubbing changed, as run, in memory (4096 execs and 8 MiB at
  most) for the reconciler, which compares and joins by it. An argv let
  go before the reconciler took it is compared as recorded: what was
  redacted then does not carry the declared command, and the `argv` rule
  says so.
- **A process.** A `proc.exec` while spans are open joins one when its
  ancestry (through `ppid`) reaches the agent: first by argv, for a shell
  tool (`Bash`, `bash`, `shell`, `exec_command`, `local_shell`, `exec`)
  whose declared `command` (or `cmd`, a string or an array; for a free-text tool such as Codex's `exec`, the quoted string
  after `cmd:` or `command:` in the arguments' summary) the exec
  carries, compared exactly: a declared argv is the exec's argv, the file
  run being the program it names; a declared command line is the `-c`
  command of a shell the kernel ran (`proc.exec.filename`, never
  `argv[0]`, which the caller sets), its options read as the shell reads
  them (they end at the first operand or `--`, `-o` takes one, and `-n`
  or `-o noexec` runs nothing) (spaces at either end aside), or
  Claude Code's wrapper around exactly it read as a shell reads
  it (its own setup as whole `&&` parts, then `eval '<command>' <
  /dev/null && pwd -P >| <file>`, nothing after; the setup varies by
  version and shell, as sourcing its shell snapshot, `export`s, `shopt`
  or `setopt`, an `unalias` group, and is not judged beyond each part
  being there; the forms of 2.1.290, 2.1.304 and 2.1.306 are tested; the
  `>nul` rewrite of Windows and `CLAUDE_CODE_SHELL_PREFIX` are not read),
  or, run without a shell, the exec's argv is its words. The declared command appearing
  elsewhere in the shell's text (a comment, beside other commands, inside
  a longer `eval`) is not carrying it, nor is a command that reads the
  same once its quotes are dropped. Else as the only open span.
  An exec that joins nothing waits 2 s for a late `tool.open`. A process
  forked or exec'd by a span's process joins that span, and a process
  that exec's again stays in its span; when a process ran before the
  gate recorded the call (a runtime that runs its tool at once, as
  Codex), every exec of it that waited joins with it.
- **An effect.** `fs.create`, `fs.close`, `fs.rename`, `fs.unlink`,
  `fs.mkdir` and `fs.setattr` join the span of the thread's process, and
  `net.connect` the span of the process its `proc.tcp_connect` named. A
  filesystem effect by the agent itself (the root or a bound executor,
  the executor by its identity, tgid and start time, since one that has
  exited may have left its pid to another process, and so at every step
  of a process's ancestry when the reconciler asks whether it descends
  from the agent; any process in no
  span when the sensor's lineage programs are not
  attached, since then none can be told apart) is the agent's own work (a
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
  cut the list: the count, or the 64 MiB that the effects of every span
  kept may hold at once, paths included. A span's effects are let go
  once it has settled (its count stays for `span.list`). The effects
  themselves are never edited.

**Harness shapes.** What the close rule needs of an agent is that one
process send every model request, and that its tools be that process's
descendants, which is how the harnesses boxcar runs its gated agent tests
with behave: Claude Code (the native build and the npm one, one Bun or
Node process sending every request, its Bash tool a child shell) and
Codex (one process, its shell tool a child; over WebSocket, one stream
carrying several calls). A harness that sends each request from a
process of its own (a script whose every request is a `wget`) is told
apart from nothing: its tools are the script's children too, and a tool
that could send a model request could then close its own span. Boxcar
does not trust a tool, so such a harness's spans stay open and are
recorded as they stand at the stop, with a `span.effects` whose
`closed_seq` is null, and `boxcar spans` lists them open (#7, decided
2026-10-21: there is no safe way to close them without trusting the
harness's whole process tree, and no policy knob that would). An agent
written for boxcar sends its requests from one process.

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
| `unverified_intent` | `args_lost` | a tool call's `tool.open` carried neither its arguments nor their hash (the gate did not keep them whole: `args_summary` is `[arguments not kept whole]`), so what the call did could not be compared with what was declared; said at the close, nothing partial kept | 45 |

The span rules rest on cross-ring joins (`tool.open` is ring 0, the exec
ring 1) and are marked `low_confidence` as the joins are, `phantom_write`
and `args_lost` excepted (the latter reads ring 0 alone).

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
- A span lists at most 1024 processes and 4096 effect records, and the
  spans kept hold at most 64 MiB of effects between them, a settled span's
  let go; 4096 spans are kept in memory, the oldest settled one going
  first; `span.list`
  returns at most 1024 entries.
