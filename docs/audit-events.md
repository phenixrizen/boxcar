# Audit records, schema version 1

Every record is one line of JSON in `<data_dir>/sessions/<session_id>/`
(`events.000001.jsonl`, rotated into further segments at 256 MiB, with
`checkpoints.jsonl` and `meta.json` beside them). The types are in
`crates/boxcar-proto/src/audit.rs` and `audit/payloads.rs`; `cargo xtask
schema` writes their JSON Schema to `proto/schema/audit-v1.json`. `boxcar
audit verify` checks a log; `boxcar events` streams a running session's
records; `proto/testdata/audit-v1.jsonl` is a golden six-record session.
Records come from two rings: ring 0 is observed on the host, ring 1 is
reported from inside the guest by its sensor (`proc.*`).

## The envelope

| Field | Type | Meaning |
|---|---|---|
| `v` | 1 | The schema version. |
| `session_id` | string | A lowercase hyphenated UUIDv7, the session's. |
| `seq` | u64 | The record's position in the session, from 1 with no gaps; the single writer assigns it. |
| `ring` | 0 or 1 | 0: observed on the host, where the guest cannot alter it. 1: reported from inside the guest. |
| `src` | string | Who made the record: `vmm`, `fs`, `net`, `vsock`, `control`, `session`, `policy`, `sensor` (ring 1), `reconciler` (and, later, `pty`, `guest`, `gateway`). |
| `type` | string | The dotted event type, below. New types are additive; a reader ignores types it does not know. |
| `ts_host_ns` | u64 | Host `CLOCK_REALTIME`, nanoseconds since the epoch, when the writer took the event. The one timestamp that joins events across rings. |
| `ts_mono_ns` | u64 | Host `CLOCK_MONOTONIC` at the same moment. |
| `ts_guest_ns` | u64, optional | The guest's `CLOCK_MONOTONIC`, for events reported from inside the guest; `sync` records pair it with the host's clocks. |
| `subject` | `{pid, uid, gid}`, optional | The guest process the event is attributed to. The pid is the guest *thread* id in both rings: from the FUSE header for `fs.*`, from the sensor for `proc.*`. |
| `data` | object | The payload, shaped by `type`. |
| `span` | `{trace_id, span_id}`, optional | Where the event sits in a trace (M4). |
| `prev` | string | The previous record's `hash`; for the first record, `b3:` + blake3 of the session id's text. |
| `hash` | string | `b3:` + 64 lowercase hex digits: blake3 of the 32 raw bytes of `prev`, then the record as compact JSON with every object key sorted and `hash` removed. |

Unset optional envelope fields are left out, never written as `null`.
Within `data`, an `Option` marked below as *omitted* is left out when
unset; every other `Option` is written as `null`.

Readers must not trust a line's syntax: a key given twice in one object, at
any depth, is an error (the reader and the verifier reject it). Numbers
must be read without loss: `ts_host_ns` does not fit a double.

Limits: paths 4096 bytes, argv 256 elements and 16 KiB, summaries 512 bytes,
a record 64 KiB. Longer strings are cut and end in `…`.

Common pieces:

- `result`: `{"ok":true}` or `{"ok":false,"errno":13,"err":"EACCES"}`
  (`errno` and `err` omitted on success; `err` omitted when Linux has no
  name for the number).
- `verdict`: `allow` or `deny`.
- `rule`: the policy rule that decided, as written (`allow example.com:443`),
  or a built-in: `builtin:guest-net` (the guest's own network),
  `builtin:this-net` (`0.0.0.0/8`), `builtin:reserved` (multicast and
  reserved), `builtin:private` (a private range no rule lifts),
  `builtin:host-local` (one of the host's own addresses),
  `builtin:udp-needs-cidr` (a domain allow passed over for UDP); `null` when
  the policy's default decided.
- `attrib`: whose identity `subject` is: `caller` (the requesting process)
  or `handle` (the process that opened the handle, when the request had no
  usable caller: pid 0, or a page-cache write-back).

## `vmm.*` and `checkpoint` (host, src `vmm`)

| Type | Fields | When |
|---|---|---|
| `vmm.start` | `version`, `kernel {path, blake3}`, `initramfs {path, blake3}` or null, `cmdline`, `vcpus`, `mem_mib`, `shares [{tag, host_root}]` (omitted when none), `inspect_ca_sha256` (omitted when the policy has no `inspect` rule) | The VM was built and is about to run. `inspect_ca_sha256` is the SHA-256, lowercase hex, of the DER certificate of the session CA the guest was told to trust for the gate's certificates (`--inspect`). |
| `vmm.stop` | `reason`, `exit_code` (or null), `console_dropped_bytes`, `stdin_dropped_bytes` | The VM stopped; the last record of a run (a closing checkpoint follows). `reason`: `guest_reset`, `guest_shutdown`, `signal`, `console_escape`, `stop_requested`, `vcpu_error`, `audit_failed`, `vmm_error`. The byte counts are console output the host never wrote out and console input it dropped (0 for a run without them). |
| `checkpoint` | `records_since`, `dropped`, `root_hash` | The writer's summary of the records since the previous checkpoint: every 1024 records or 2 s, at a segment seal, and at close. `root_hash` is blake3 over the raw hashes of those records; `dropped` counts droppable events (`fs.read`, `net.drop`) the full channel dropped. |

## `fs.*` (host, src `fs`)

Every filesystem operation the guest performs on a share (`root`, or
`workspace` at `/workspace`), seen by the virtio-fs device the VMM serves
in-process. `mount` is the share's tag and `path` is within the share.
`subject` carries the guest's pid, uid and gid from the FUSE header.
Writes, creates, unlinks, renames, setattr and denials are never dropped;
reads may be (and are counted in `checkpoint.dropped`).

Every payload with a `path` has `path_b64` beside it, present only when
the name was not valid UTF-8: `path` then holds the lossy text (`U+FFFD`
for each bad byte) and `path_b64` the raw bytes in standard base64, at most
the first 4096 of them. The other names (`path_at_open`, `target_path`,
`target`, `from`, `to`) are lossy text only.

| Type | Fields |
|---|---|
| `fs.mount` | `mount`, `guest_path`, `host_root`, `cache_policy` |
| `fs.open` | `mount`, `path`, `fh`, `flags` (raw `open(2)` flags), `flags_decoded [string]`, `exec` (the open is for `execve`), `result` |
| `fs.create` | `mount`, `path`, `fh`, `mode`, `flags`, `result` |
| `fs.close` | `mount`, `path` (at close), `path_at_open`, `fh`, `bytes_read`, `bytes_written`, `size` (or null), `blake3` (or null), `hash_status`, `open_seq` (or null), `attrib`, `ts_release_ns` (host `CLOCK_REALTIME` at the release itself: the hash that completes the record may come later, and the record's `ts_host_ns` is then later still; 0 in logs written before it existed) |
| `fs.read` | `mount`, `path`, `fh`, `offset`, `len`, `result`, `attrib` |
| `fs.write` | `mount`, `path`, `fh`, `offset`, `len`, `result`, `attrib` |
| `fs.unlink` | `mount`, `path`, `result` |
| `fs.rmdir` | `mount`, `path`, `result` |
| `fs.mkdir` | `mount`, `path`, `mode`, `result` |
| `fs.mknod` | `mount`, `path`, `mode`, `rdev`, `result` |
| `fs.symlink` | `mount`, `path` (the new link), `target`, `result` |
| `fs.link` | `mount`, `path` (the new name), `target_path`, `result` |
| `fs.rename` | `mount`, `from`, `to`, `flags` (`renameat2(2)`), `result` |
| `fs.setattr` | `mount`, `path`, `set {mode, uid, gid, size, atime, mtime}` (each omitted when not asked), `result` |
| `fs.fallocate` | `mount`, `path`, `offset`, `len`, `mode`, `result` |
| `fs.xattr` | `mount`, `path`, `name`, `op` (`set` or `remove`), `result` |
| `fs.denied` | `mount`, `path`, `op` (`lookup`, `access`, `open`, ...), `errno` |
| `fs.readdir` | `mount`, `path`, `result` |

`fs.close.hash_status`: `ok` (`blake3` is set), `raced` (the file changed
while it was hashed), `gone`, `skipped_size` (over the hashing limit),
`not_hashed` (nothing was written through the handle), `error` (the file
could not be read, its path was not fully known, or the hash thread failed
on it). The hash is computed off the FUSE reply path by two threads a
share; a guest that resets its virtio-fs driver stops them, and the next
activation starts them again.

## `net.*` (host, src `net`)

The guest's network is a user-mode stack inside the VMM: the guest is
`10.0.2.15`, the gateway `10.0.2.2` answers ARP, DHCP, DNS and ICMP echo
itself, terminates the guest's TCP and relays it to host sockets, and
relays UDP by NAT. Every decision is recorded here. `flow` numbers TCP
connections and UDP mappings from one count, so an id names one flow of
either kind within a session.

| Type | Fields | When |
|---|---|---|
| `net.dhcp` | `op` (`offer` or `ack`), `yiaddr` | The gateway answered a DHCP DISCOVER or REQUEST with the static lease. |
| `net.dns` | `txid`, `qname`, `qtype` (1 A, 28 AAAA, ...), `rcode` (0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 1 FORMERR), `answers [string]` (the addresses given), `verdict`, `rule` | A guest DNS query was answered: NXDOMAIN when the policy denies the name, else the upstream's answer (AAAA records stripped), SERVFAIL when the upstream did not answer in 5 s. |
| `net.connect` | `flow`, `proto` (`tcp`), `src` (`ip:port`), `dst`, `names [string]` (the names DNS answers gave `dst`, newest first), `verdict`, `rule` | A guest SYN was decided, before anything answered it. A denied one gets an RST. |
| `net.tls` | `flow`, `kind` (`tls` or `http`), `sni` (or null), `alpn [string]`, `verdict`, `inspect` (omitted when false) | The gate read a flow's first bytes: a flow a domain rule allowed must show that name as its TLS server name or HTTP `Host`, or both sides are reset. `inspect` is true when an `inspect` line names the flow: a TLS flow then gets a `net.inspect`, a plain HTTP flow is observed as it is. A flow a network rule allowed gets this record only when it is inspected. |
| `net.inspect` | `flow`, `sni` (or null), `alpn` (the protocol both legs agreed on, or null), `version` (`1.3`, `1.2`, or null), `result`, `rule` | The gate ended an inspected flow's TLS, or could not. `result`: `ok` (recorded before any plaintext moves), `upstream_untrusted` (the real host's certificate is not one the host's trust store vouches for), `upstream_failed` (its handshake failed otherwise), `guest_rejected` (the guest refused the session CA's leaf, or closed during the handshake), `timeout` (the handshakes outran the gate's time). On anything but `ok` nothing was relayed, and the flow's `net.close` says `inspect`. |
| `net.close` | `flow`, `tx`, `rx` (payload bytes the guest sent and received), `dur_ms`, `reason` | A TCP flow or UDP mapping ended. `reason`: `fin` (closed both ways), `reset` (the host or the guest reset it), `timeout` (a host connect took over 10 s, or the guest stayed silent 60 s), `gate` (the gate denied the name, or none was shown within 16 KiB or 5 s), `refused`, `unreachable`, `error` (the host connect failed, or the guest sent data after its FIN), `evicted` (the table was full), `idle` (a UDP mapping unused for 60 s), `policy` (a new policy denies it), `shutdown` (the VM stopped). |
| `net.udp` | `flow`, `src`, `dst`, `names`, `verdict`, `rule` | The first datagram of a UDP 5-tuple was decided. A domain allow admits no UDP (nothing in a datagram shows a name); allow UDP by address. |
| `net.drop` | `reason`, `count` | Guest frames were dropped: at most one record a second for each reason, counting every drop since the last. `reason`: `ipv6`, `icmp` (other than echo to the gateway), `dhcp`, `dns` (too short), `dns_bogus` (an upstream answer for no query), `udp_denied` (more datagrams on a tuple refused within the minute), `udp_send`, `udp_oversize`, `udp_table_full`, `queue_full`, `tcp_pending_full`, `src_spoof`, `observe` (plaintext bytes of an inspected flow the observer's channel had no room for: the flow went on, the observer's copy has a hole), `other`. Droppable: emitted without waiting, counted in `checkpoint.dropped` when the channel is full. |

Every allowed `net.connect` and `net.udp` has exactly one `net.close`. An
inspected TLS flow has exactly one `net.inspect`, after its `net.tls` and
before its `net.close`; `net.close{reason:"inspect"}` ends one the gate
could not carry.

## `vsock.*` (host, src `vsock`)

| Type | Fields | When |
|---|---|---|
| `vsock.connect` | `port`, `dir` (`guest` or `host`), `peer` (`internal`, `uds` or `guest`), `src_port`, `verdict`, `reason` (or null) | A vsock connection was decided. A guest connection to an internal port (1024 `boxcar.ctl`, 1025 `boxcar.pty`, 1026 `boxcar.sensor`) is served by the VMM only from a guest source port below 1024 and only the first per port per activation; one to any other port reaches the host socket `<state>/vsock.sock_<port>` only when the port is allowlisted (`--vsock-allow`, `policy.update`). A host connection (`CONNECT <port>` on `<state>/vsock.sock`) is recorded once the guest accepts it. `reason` on a denial: `unprivileged`, `duplicate`, `no_service`, `port`, or the service's own, such as `reactivated`. |
| `vsock.close` | `port`, `dir`, `tx`, `rx` | A connection that a `vsock.connect` let through ended. `tx` and `rx` count payload bytes that reached the other side; bytes the VMM still held for the guest (up to 64 KiB a connection) when the guest reset its vsock driver are neither counted nor reported. |

## `session.*` (guest, ring 1, src `session`)

Reported by the guest's init over the control channel; the `subject` is the
session's process (uid and gid as configured).

| Type | Fields | When |
|---|---|---|
| `session.start` | `argv [string]`, `cwd`, `uid`, `gid`, `pid` | Init started the session the VMM asked for. |
| `session.exit` | `code` (or null), `signal` (or null) | The session's process ended: its exit code, or the signal that killed it; both null only when init could not tell. `boxcar run` exits with `code`, or 128 plus `signal`. |

## `control.*` (host, src `control`)

| Type | Fields | When |
|---|---|---|
| `control.connect` | `pid`, `uid`, `verdict` | A process connected to the control socket: served (`allow`) when its uid is the VMM's, closed before the hello otherwise (`deny`). |
| `control.stop` | `by_pid`, `mode` (`graceful` or `force`) | A control client asked the VM to stop. Recorded before the stop begins. |

## `policy.*` (host, src `policy`)

| Type | Fields | When |
|---|---|---|
| `policy.changed` | `by_pid`, `version` | A control client replaced the session's policy (`policy.update`): the network rules, the vsock allowlist, or both. `version` is 1 for the policy the VM started with, one more for each update; `policy.get` reports it. The flows the new policy denies end with `net.close{reason:"policy"}`. |

## `sync` (host, src `vmm`)

| Type | Fields | When |
|---|---|---|
| `sync` | `method` (`vsock_rtt`), `guest_mono_ns`, `host_mono_ns`, `offset_ns`, `rtt_ns` | The VMM pinged init over the control channel and init answered: the guest's `CLOCK_MONOTONIC` when it answered, the host's at the round trip's midpoint, `host_mono_ns - guest_mono_ns`, and the round trip, which bounds how sure the pairing is. The first comes right after the session's config, then one every 10 s. `ts_host_ns` stays the one timestamp that joins events across rings; `sync` says how the guest's `ts_guest_ns` relates to it. |

## `proc.*` (guest, ring 1, src `sensor`)

Reported by the sensor init starts in the guest before privileges drop, over
vsock port 1026, for processes in the session's cgroup. Every record carries
`ts_guest_ns`; all but the sensor's own (`proc.heartbeat`,
`proc.sensor_status`) carry a `subject`, whose pid is the thread. Ring 1 is
corroboration, not the record: the guest can silence it, and the silence
shows (the heartbeats stop; `status` says `silent`). `tid` and `tgid` are
the thread and its process; `start_ns`, the process's start on the guest's
clock, tells a process from a later one with the same pid.

| Type | Fields | When |
|---|---|---|
| `proc.exec` | `tid`, `tgid`, `ppid`, `uid`, `gid`, `filename`, `argv [string]` (256 elements and 16 KiB at most), `argv_truncated`, `start_ns`, `cgroup_id` | A process ran a new program (`execve` succeeded). |
| `proc.fork` | `parent_tid`, `parent_tgid`, `child_pid`, `child_start_ns`, `uid`, `gid`, `thread` | A process made a new process, or (`thread`) a new thread of its own; the reconciler ties the thread to the process, since `fs.*` records name threads. |
| `proc.exit` | `tid`, `tgid`, `exit_code` (the kernel's status word), `group_dead`, `start_ns` | A thread ended; `group_dead` when it was its process's last. |
| `proc.connect_attempt` | `tid`, `tgid`, `family`, `proto`, `dst` (*omitted* unless IPv4 or IPv6), `dst_port` (*omitted* the same) | A process asked to connect a socket, with the destination as asked. |
| `proc.tcp_connect` | `tid`, `tgid`, `src`, `src_port`, `dst`, `dst_port` | The kernel sent a connection's first segment: the 4-tuple that joins the flow to `net.connect`. |
| `proc.memfd` | `tid`, `tgid`, `name` (256 bytes at most), `flags` | A process made an anonymous memory file. |
| `proc.file_open` | `tid`, `tgid`, `path`, `flags`, `sample` | One open in `sample`: the only sampled record of ring 1. |
| `proc.lsm_deny` | `tid`, `tgid`, `hook` (`bpf` or `task_kill`), `detail` (the `bpf` command, or the signal) | The sensor's self-protection refused a `bpf()` call by another process, or a signal to the sensor. Written through to disk at once. |
| `proc.heartbeat` | `uptime_ns`, `events_emitted`, `ringbuf_drops`, `frames_sent` | The sensor is alive: once a second, with its counters since it started. `ringbuf_drops` counts events the kernel could not place in the ring buffer: lost. |
| `proc.sensor_status` | `phase` (`attached` or `degraded`), `programs [{name, attached, error?}]`, `kernel_release`, `btf_ok`, `session_cgroup_id`, `pid` (the sensor's own), `reason` (*omitted* unless one reason covers it) | What the sensor could attach, once it has tried, and again if that changes. |

The sensor's stream is framed `[u32 LE len][json]`, each frame the record's
`type` and `data` with `ts_guest_ns` and `subject` beside them, at most 64
KiB; `proto/schema/sensor-v1.json` and `proto/testdata/sensor-v1.jsonl`
describe it. A frame that is not a sensor's ends the stream.

## `finding` (host, src `reconciler`)

| Type | Fields | When |
|---|---|---|
| `finding` | `category` (`unattributed_effect`, `sensor_silence`, `intent_effect_mismatch`, `indicator_removal`, `off_book_channel`, `orphaned_work`, `network_anomaly`, `privilege_probe`, `policy_denial`), `score` (0 to 100), `rule`, `summary` (512 bytes at most), `evidence [{seq, ring}]` (the records the rule read, newest last), `span_id` (*omitted* until M4), `low_confidence` | The reconciler's conclusion from records of both rings. Never sampled; a score of 70 or more is written through to disk at once. The rules are in `docs/reconciler.md`. |

## Order and durability

Records are chained in the order the single writer took them, which is the
order their producers submitted them, across all sources. A `vmm.start`
is first; `vmm.stop` and a closing `checkpoint` are last. A `net.connect`
precedes its flow's `net.tls` and `net.close`; `net.tls{allow}` is in the
log before the first held byte reaches the host; `net.udp{allow}` before
its first datagram does. Every record is on disk by the next checkpoint
(within 2 s); `vmm.stop`, `proc.lsm_deny` and a `finding` scoring 70 or
more are `fdatasync`ed at once. A writer that fails
stops the VM (`boxcar run` exits 3) and cuts the log back to its last
consistent record; `boxcar audit verify` accepts what is left.
