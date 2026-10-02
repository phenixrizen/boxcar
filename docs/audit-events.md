# Audit records, schema version 1

Every record is one line of JSON in `<data_dir>/sessions/<session_id>/`
(`events.000001.jsonl`, rotated into further segments at 256 MiB, with
`checkpoints.jsonl` and `meta.json` beside them). The types are in
`crates/boxcar-proto/src/audit.rs` and `audit/payloads.rs`; `cargo xtask
schema` writes their JSON Schema to `proto/schema/audit-v1.json`. `boxcar
audit verify` checks a log; `boxcar events` streams a running session's
records; `proto/testdata/audit-v1.jsonl` is a golden six-record session.

## The envelope

| Field | Type | Meaning |
|---|---|---|
| `v` | 1 | The schema version. |
| `session_id` | string | A lowercase hyphenated UUIDv7, the session's. |
| `seq` | u64 | The record's position in the session, from 1 with no gaps; the single writer assigns it. |
| `ring` | 0 or 1 | 0: observed on the host, where the guest cannot alter it. 1: reported from inside the guest. |
| `src` | string | Who made the record: `vmm`, `fs`, `net`, `vsock`, `control`, `session`, `policy` (and, later, `pty`, `guest`, `sensor`, `reconciler`, `gateway`). |
| `type` | string | The dotted event type, below. New types are additive; a reader ignores types it does not know. |
| `ts_host_ns` | u64 | Host `CLOCK_REALTIME`, nanoseconds since the epoch, when the writer took the event. The one timestamp that joins events across rings. |
| `ts_mono_ns` | u64 | Host `CLOCK_MONOTONIC` at the same moment. |
| `ts_guest_ns` | u64, optional | The guest's clock, for events reported from inside the guest. |
| `subject` | `{pid, uid, gid}`, optional | The guest process the event is attributed to. For `fs.*`, the pid is the guest *thread* id from the FUSE header. |
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
| `vmm.start` | `version`, `kernel {path, blake3}`, `initramfs {path, blake3}` or null, `cmdline`, `vcpus`, `mem_mib`, `shares [{tag, host_root}]` (omitted when none) | The VM was built and is about to run. |
| `vmm.stop` | `reason`, `exit_code` (or null), `console_dropped_bytes`, `stdin_dropped_bytes` | The VM stopped; the last record of a run (a closing checkpoint follows). `reason`: `guest_reset`, `guest_shutdown`, `signal`, `console_escape`, `stop_requested`, `vcpu_error`, `audit_failed`, `vmm_error`. The byte counts are console output the host never wrote out and console input it dropped (0 for a run without them). |
| `checkpoint` | `records_since`, `dropped`, `root_hash` | The writer's summary of the records since the previous checkpoint: every 1024 records or 2 s, at a segment seal, and at close. `root_hash` is blake3 over the raw hashes of those records; `dropped` counts droppable events (`fs.read`, `net.drop`) the full channel dropped. |

## `fs.*` (host, src `fs`)

Every filesystem operation the guest performs on a share (`root`, or
`workspace` at `/workspace`), seen by the virtio-fs device the VMM serves
in-process. `mount` is the share's tag and `path` is within the share.
`subject` carries the guest's pid, uid and gid from the FUSE header.
Writes, creates, unlinks, renames, setattr and denials are never dropped;
reads may be (and are counted in `checkpoint.dropped`).

| Type | Fields |
|---|---|
| `fs.mount` | `mount`, `guest_path`, `host_root`, `cache_policy` |
| `fs.open` | `mount`, `path`, `fh`, `flags` (raw `open(2)` flags), `flags_decoded [string]`, `exec` (the open is for `execve`), `result` |
| `fs.create` | `mount`, `path`, `fh`, `mode`, `flags`, `result` |
| `fs.close` | `mount`, `path` (at close), `path_at_open`, `fh`, `bytes_read`, `bytes_written`, `size` (or null), `blake3` (or null), `hash_status`, `open_seq` (or null), `attrib` |
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
`not_hashed` (nothing was written through the handle), `error`.

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
| `net.tls` | `flow`, `kind` (`tls` or `http`), `sni` (or null), `alpn [string]`, `verdict` | The gate read a flow's first bytes: a flow a domain rule allowed must show that name as its TLS server name or HTTP `Host`, or both sides are reset. |
| `net.close` | `flow`, `tx`, `rx` (payload bytes the guest sent and received), `dur_ms`, `reason` | A TCP flow or UDP mapping ended. `reason`: `fin` (closed both ways), `reset` (the host or the guest reset it), `timeout` (a host connect took over 10 s, or the guest stayed silent 60 s), `gate` (the gate denied the name, or none was shown within 16 KiB or 5 s), `refused`, `unreachable`, `error` (the host connect failed, or the guest sent data after its FIN), `evicted` (the table was full), `idle` (a UDP mapping unused for 60 s), `policy` (a new policy denies it), `shutdown` (the VM stopped). |
| `net.udp` | `flow`, `src`, `dst`, `names`, `verdict`, `rule` | The first datagram of a UDP 5-tuple was decided. A domain allow admits no UDP (nothing in a datagram shows a name); allow UDP by address. |
| `net.drop` | `reason`, `count` | Guest frames were dropped: at most one record a second for each reason, counting every drop since the last. `reason`: `ipv6`, `icmp` (other than echo to the gateway), `dhcp`, `dns` (too short), `dns_bogus` (an upstream answer for no query), `udp_denied` (more datagrams on a tuple refused within the minute), `udp_send`, `udp_oversize`, `udp_table_full`, `queue_full`, `tcp_pending_full`, `src_spoof`, `other`. Droppable: emitted without waiting, counted in `checkpoint.dropped` when the channel is full. |

Every allowed `net.connect` and `net.udp` has exactly one `net.close`.

## `vsock.*` (host, src `vsock`)

| Type | Fields | When |
|---|---|---|
| `vsock.connect` | `port`, `dir` (`guest` or `host`), `peer` (`internal`, `uds` or `guest`), `src_port`, `verdict`, `reason` (or null) | A vsock connection was decided. A guest connection to an internal port (1024 `boxcar.ctl`, 1025 `boxcar.pty`, 1026 `boxcar.sensor`) is served by the VMM only from a guest source port below 1024 and only the first per port per activation; one to any other port reaches the host socket `<state>/vsock.sock_<port>` only when the port is allowlisted (`--vsock-allow`, `policy.update`). A host connection (`CONNECT <port>` on `<state>/vsock.sock`) is recorded once the guest accepts it. `reason` on a denial: `unprivileged`, `duplicate`, `no_service`, `port`, or the service's own, such as `reactivated`. |
| `vsock.close` | `port`, `dir`, `tx`, `rx` | A connection that a `vsock.connect` let through ended. |

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

## Order and durability

Records are chained in the order the single writer took them, which is the
order their producers submitted them, across all sources. A `vmm.start`
is first; `vmm.stop` and a closing `checkpoint` are last. A `net.connect`
precedes its flow's `net.tls` and `net.close`; `net.tls{allow}` is in the
log before the first held byte reaches the host; `net.udp{allow}` before
its first datagram does. Every record is on disk by the next checkpoint
(within 2 s); `vmm.stop` is `fdatasync`ed at once. A writer that fails
stops the VM (`boxcar run` exits 3) and cuts the log back to its last
consistent record; `boxcar audit verify` accepts what is left.
