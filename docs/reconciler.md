# The reconciler

The reconciler is a thread of `boxcar run` that reads the session's audit
log as it is written, joins what the two rings say, and writes `finding`
records back into the same log. It is rules, not models: each finding names
the rule that fired, says in a sentence what it saw, and lists the records
it read as evidence, so a reader can go back to them. `boxcar events --type
finding` streams findings from a running session; `--min-score` keeps the
ones that matter. A score of 70 or more is written through to disk at once.

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

## The rules

| Category | Rule | Fires when | Score |
|---|---|---|---|
| `unattributed_effect` | `no_process` | a filesystem effect's thread belongs to no process the sensor reported, 2 s after it happened, while the sensor is attached | 60 |
| `sensor_silence` | `never_attached` | the VM runs a sensor, the session started, and 5 s later the sensor has said nothing | 85 |
| `sensor_silence` | `heartbeat_lost` | no heartbeat for over 3 s while a ring 0 effect arrived in the last 3 s; once per silence, re-armed by the next heartbeat | 85 |
| `indicator_removal` | `indicator_removal` | `fs.unlink`, `fs.rename` (the source) or `fs.setattr` to size 0 of a shell history (`.*_history`), a file under `/var/log/`, `/etc/ld.so.preload`, or a file under `/root/.ssh/` | 90 |
| `off_book_channel` | `memfd_create` | `proc.memfd` | 75 |
| `off_book_channel` | `shm_open` | `proc.file_open` of a path under `/dev/shm/` (sampled: one open in 64 is seen) | 75 |
| `network_anomaly` | `connect_without_dns` | `net.connect` to an address that no `net.dns` answer named in the last 60 s and that the stack had no name for (the gateway excepted) | 60 |
| `network_anomaly` | `sni_mismatch` | `net.tls` whose server name was answered with addresses that do not include the flow's destination | 65 |
| `network_anomaly` | `dns_rate` | more than 50 `net.dns` queries within 10 s; then quiet for 10 s | 70 |
| `network_anomaly` | `dns_entropy` | 20 or more queries within 10 s whose first labels carry over 3.5 bits of entropy on average; then quiet for 10 s | 70 |
| `privilege_probe` | `lsm_deny` | any `proc.lsm_deny`: a `bpf()` call, or a signal to the sensor, refused | 80 |
| `policy_denial` | `policy_denial` | `net.dns`, `net.connect`, `net.tls`, `net.udp` or `vsock.connect` with `verdict: "deny"`, or `fs.denied` | 40 |

`intent_effect_mismatch` and `orphaned_work` need the tool spans of M4 and
are not fired in M3.

## What a finding carries

`{"category", "score", "rule", "summary", "evidence": [{"seq", "ring"}],
"low_confidence"}`, and `span_id` once M4 has spans. `evidence` lists the
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
