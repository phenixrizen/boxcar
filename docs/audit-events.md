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
| `src` | string | Who made the record: `vmm`, `fs`, `net`, `vsock`, `control`, `session`, `policy`, `sensor` (ring 1), `reconciler`, `gate` (the model traffic gate's observer) (and, later, `pty`, `guest`). |
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
  `builtin:udp-needs-cidr` (a domain allow passed over for UDP), or for
  `net.dns`, `dns_rate` (a query over the policy's `max_dns_qps`); `null` when
  the policy's default decided.
- `attrib`: whose identity `subject` is: `caller` (the requesting process)
  or `handle` (the process that opened the handle, when the request had no
  usable caller: pid 0, or a page-cache write-back).

## `vmm.*` and `checkpoint` (host, src `vmm`)

| Type | Fields | When |
|---|---|---|
| `vmm.start` | `version`, `kernel {path, blake3}`, `initramfs {path, blake3}` or null, `cmdline`, `vcpus`, `mem_mib`, `shares [{tag, host_root}]` (omitted when none), `inspect_ca_sha256` (omitted when the policy has no `inspect` rule), `image {reference, manifest_digest, config_digest}` (omitted unless the session boots from an image), `hardening {seccomp_threads` (present, `true`, when the worker threads each confine themselves to their role's list), `seccomp, landlock}` (omitted when the VM was built by another program than `boxcar run`, such as a test) | The VM was built and is about to run. `hardening` is how the VMM process is confined, both in force before the record is made: `seccomp` is `enforce` (a syscall off the allowlist kills the process: a crash, with no `vmm.stop`), `log` (the kernel logs such a call, which goes ahead) or `off` (`boxcar run --seccomp`); `landlock` is `full` (every right boxcar handles is enforced), `partial` (the kernel enforces some of them), `unsupported` (no usable Landlock: the process runs unconfined) or `off` (`--landlock off`). `image` names the image `--image` gave, normalized, and the manifest and config digests of the cached image whose tree the session's root share was copied from. `inspect_ca_sha256` is the SHA-256, lowercase hex, of the DER certificate of the session CA the guest was told to trust for the gate's certificates (`--inspect`). |
| `vmm.stop` | `reason`, `exit_code` (or null), `console_dropped_bytes`, `stdin_dropped_bytes` | The VM stopped. What follows it is the reconciler's last records (its findings, and the `span.effects` of tool spans still open), then a closing checkpoint. `reason`: `guest_reset`, `guest_shutdown`, `signal`, `console_escape`, `stop_requested`, `vcpu_error`, `audit_failed`, `vmm_error`. The byte counts are console output the host never wrote out and console input it dropped (0 for a run without them). |
| `checkpoint` | `records_since`, `dropped`, `root_hash` | The writer's summary of the records since the previous checkpoint: every 1024 records or 2 s, at a segment seal, and at close. `root_hash` is blake3 over the raw hashes of those records; `dropped` counts droppable events (`fs.read`, `net.drop`) the full channel dropped. |

## `fs.*` (host, src `fs`)

Every filesystem operation the guest performs on a share (`root`, or
`workspace` at `/workspace`), seen by the virtio-fs device the VMM serves
in-process. `mount` is the share's tag and `path` is within the share.
`subject` carries the guest's pid, uid and gid from the FUSE header.
Creates, unlinks, renames, setattr, closes (with the bytes read and written)
and denials are never dropped; the per-operation `fs.read`, `fs.write` and
`fs.readdir` records of `--audit-level verbose` may be (and are counted in
`checkpoint.dropped`).

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
| `fs.denied` | `mount`, `path`, `op` (`lookup`, `access`, `open`, `exec` (an open to run a program), `create`, `rename`, `write`, `setattr`, `getattr`, ...), `errno`, `reason` (`policy`, or omitted), `rule` (or omitted) |
| `fs.readdir` | `mount`, `path`, `result` |

`fs.denied` is a refusal: of the host's own (`errno` as the host gave it,
`reason` omitted), or of the session's policy (`reason` `policy`), made
before the request reached the host, which then changed nothing and got no
other record. A policy refusal is `EACCES` for a denied path (`[fs]
denied`), a refused program (`[exec] deny`: any open of it, its rename,
its link) or a node id the guest was never handed, and `EROFS` for a change
outside `[fs] writable`; `rule` is the glob that refused it, also when the
file was refused by its identity under another name (a hard link, a case
variant), and is omitted for an `EROFS`, where no glob matched, and for a
node id with no path (`path` is then `<ino:N>`). A `readdirplus` entry the
policy denies is listed without its inode and recorded nowhere.

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
| `net.dns` | `txid`, `qname`, `qtype` (1 A, 28 AAAA, ...), `rcode` (0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 1 FORMERR, 5 REFUSED), `answers [string]` (the addresses given), `verdict`, `rule` | A guest DNS query was answered: REFUSED, `verdict` `deny` and `rule` `dns_rate` when it came over the policy's `max_dns_qps` (counted before anything else, malformed queries included; nothing goes upstream), NXDOMAIN when the policy denies the name, else the upstream's answer (AAAA records stripped), SERVFAIL when the upstream did not answer in 5 s. |
| `net.connect` | `flow`, `proto` (`tcp`), `src` (`ip:port`), `dst`, `names [string]` (the names DNS answers gave `dst`, newest first), `verdict`, `rule` | A guest SYN was decided, before anything answered it. A denied one gets an RST. |
| `net.tls` | `flow`, `kind` (`tls` or `http`), `sni` (or null), `alpn [string]`, `verdict`, `inspect` (omitted when false) | The gate read a flow's first bytes: a flow a domain rule allowed must show that name as its TLS server name or HTTP `Host`, or both sides are reset. `inspect` is true when an `inspect` line names the flow: a TLS flow then gets a `net.inspect`, a plain HTTP flow is observed as it is. A flow a network rule allowed gets this record only when it is inspected. |
| `net.inspect` | `flow`, `sni` (or null), `alpn` (the protocol both legs agreed on, or null), `version` (`1.3`, `1.2`, or null), `result`, `rule` | The gate ended an inspected flow's TLS, or could not. `result`: `ok` (recorded before any plaintext moves), `upstream_untrusted` (the real host's certificate is not one the host's trust store vouches for), `upstream_failed` (its handshake failed otherwise), `guest_rejected` (the guest refused the session CA's leaf, or closed during the handshake), `timeout` (the handshakes outran the gate's time). On anything but `ok` nothing was relayed, and the flow's `net.close` says `inspect`. |
| `net.close` | `flow`, `tx`, `rx` (payload bytes the guest sent and received), `dur_ms`, `reason` | A TCP flow or UDP mapping ended. `reason`: `fin` (closed both ways), `reset` (the host or the guest reset it), `timeout` (a host connect took over 10 s, or the guest stayed silent 60 s), `gate` (the gate denied the name, or none was shown within 16 KiB or 5 s), `refused`, `unreachable`, `error` (the host connect failed, or the guest sent data after its FIN), `evicted` (the table was full), `idle` (a UDP mapping unused for 60 s), `policy` (a new policy denies it), `shutdown` (the VM stopped). |
| `net.udp` | `flow`, `src`, `dst`, `names`, `verdict`, `rule` | The first datagram of a UDP 5-tuple was decided. A domain allow admits no UDP (nothing in a datagram shows a name); allow UDP by address. |
| `net.drop` | `reason`, `count` | Guest frames were dropped: at most one record a second for each reason, counting every drop since the last. `reason`: `ipv6`, `icmp` (other than echo to the gateway), `dhcp`, `dns` (too short), `dns_bogus` (an upstream answer for no query), `udp_denied` (more datagrams on a tuple refused within the minute), `udp_send`, `udp_oversize`, `udp_table_full`, `queue_full`, `tcp_pending_full`, `src_spoof`, `observe` (plaintext bytes of an inspected flow the observer's channel had no room for: the flow went on, the observer's copy has a hole), `dump` (a frame the `--dump` queue had no room for: the dump has a hole, the traffic went on), `other`. Droppable: emitted without waiting, counted in `checkpoint.dropped` when the channel is full. |

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
| `session.start` | `argv [string]` (with `--scrub-argv`, scrubbed as `proc.exec`'s is), `cwd`, `uid`, `gid`, `pid` | Init started the session the VMM asked for. |
| `session.exit` | `code` (or null), `signal` (or null) | The session's process ended: its exit code, or the signal that killed it; both null only when init could not tell. `boxcar run` exits with `code`, or 128 plus `signal`. |

## `control.*` (host, src `control`)

| Type | Fields | When |
|---|---|---|
| `control.connect` | `pid`, `uid`, `verdict` | A process connected to the control socket: served (`allow`) when its uid is the VMM's, closed before the hello otherwise (`deny`). |
| `control.stop` | `by_pid`, `mode` (`graceful` or `force`) | A control client asked the VM to stop. Recorded before the stop begins. |

## `policy.*` (host, src `policy`)

| Type | Fields | When |
|---|---|---|
| `policy.loaded` | `source` (`profile`, `file` or `flags`), `name` (or null), `sha256` (or null), `egress_rules`, `fs_rules`, `exec_rules` | The policy the session started with: once, right after `vmm.start`, before anything else is recorded. `source` is `profile` for `boxcar run --policy NAME`, `file` for `--policy PATH` (a TOML policy file), `flags` for the line policy (`--policy-file`, `--deny`, `--allow`, `--inspect`, or none of them). `name` is the profile's name or the path as given to `--policy` or `--policy-file` (4096 bytes at most), `sha256` the SHA-256, lowercase hex, of the text the policy was read from; both null when there was none. `egress_rules` counts the allow, deny and inspect rules in force, the flags' included; `fs_rules` the policy file's `[fs]` globs (`writable`, its default `/workspace/**` and `/tmp/**` included, `denied`, `indicators`) and `exec_rules` its `[exec] deny` globs, both 0 for a line policy. |
| `policy.changed` | `by_pid`, `version` | A control client replaced the session's permanent policy (`policy.update`): the network rules, the vsock allowlist, or both; or, with `by_pid` 0, live exceptions expired. `version` is 1 for the policy the VM started with, one more for each update, grant and expiry; `policy.get` reports it. The flows the new policy denies end with `net.close{reason:"policy"}`. |
| `policy.exception` | `id`, `rule`, `kind` (`egress`, `writable` or `exec`), `ttl_s`, `expires_ns`, `by_pid`, `version` | A control client granted a live exception (`policy.update` with `exception`): an egress target allowed after the permanent rules, a path glob writes may name, or a path glob programs may be run from despite `[exec] deny`, for `ttl_s` seconds. `id` counts from 1 for the session; `expires_ns` is when it goes, by the clock of `ts_host_ns` (it is kept by `CLOCK_BOOTTIME`, so a step of the wall clock does not move it); it goes with a `policy.changed{by_pid: 0}`. |

## `sync` (host, src `vmm`)

| Type | Fields | When |
|---|---|---|
| `sync` | `method` (`ptp_kvm` or `vsock_rtt`), `guest_mono_ns`, `host_mono_ns`, `offset_ns`, `rtt_ns` | The VMM pinged init over the control channel and init answered. With `ptp_kvm` (a guest whose KVM offers the `KVM virtual PTP` clock, which bare-metal hosts do; the guest runs on `kvm-clock` for it) init read the host's `CLOCK_REALTIME` and its own clocks from one read of the TSC: `guest_mono_ns` is the guest's `CLOCK_MONOTONIC` at that read, `host_mono_ns` the host's at it, and `rtt_ns` the window on the guest's clock the read was taken in, microseconds. With `vsock_rtt` (no such clock): the guest's `CLOCK_MONOTONIC` when it answered, the host's at the round trip's midpoint, and the round trip. Either way `offset_ns` is `host_mono_ns - guest_mono_ns`, and `rtt_ns` bounds how sure the pairing is. The first comes right after the session's config, then one every 10 s. `ts_host_ns` stays the one timestamp that joins events across rings; `sync` says how the guest's `ts_guest_ns` relates to it. |

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
| `proc.exec` | `tid`, `tgid`, `ppid`, `uid`, `gid`, `filename`, `argv [string]` (256 elements and 16 KiB at most; with `boxcar run --scrub-argv`, each element scrubbed as free text is), `argv_truncated`, `start_ns`, `cgroup_id` | A process ran a new program (`execve` succeeded). |
| `proc.fork` | `parent_tid`, `parent_tgid`, `child_pid`, `child_start_ns`, `uid`, `gid`, `thread` | A process made a new process, or (`thread`) a new thread of its own; the reconciler ties the thread to the process, since `fs.*` records name threads. |
| `proc.exit` | `tid`, `tgid`, `exit_code` (the kernel's status word), `group_dead`, `start_ns` | A thread ended; `group_dead` when it was its process's last. |
| `proc.connect_attempt` | `tid`, `tgid`, `family`, `proto`, `dst` (*omitted* unless IPv4 or IPv6), `dst_port` (*omitted* the same) | A process asked to connect a socket, with the destination as asked. |
| `proc.tcp_connect` | `tid`, `tgid`, `src`, `src_port`, `dst`, `dst_port` | The kernel sent a connection's first segment: the 4-tuple that joins the flow to `net.connect`. |
| `proc.memfd` | `tid`, `tgid`, `name` (256 bytes at most), `flags` | A process made an anonymous memory file. |
| `proc.file_open` | `tid`, `tgid`, `path`, `flags`, `sample` | One open in `sample`: the only sampled record of ring 1. |
| `proc.lsm_deny` | `tid`, `tgid`, `hook` (`bpf` or `task_kill`), `detail` (the `bpf` command, or the signal) | The sensor's self-protection refused a `bpf()` call by another process, or a signal to the sensor. Written through to disk at once. |
| `proc.heartbeat` | `uptime_ns`, `events_emitted`, `ringbuf_drops`, `frames_sent` | The sensor is alive: once a second, with its counters since it started. `ringbuf_drops` counts events the kernel could not place in the ring buffer: lost. |
| `proc.sensor_status` | `phase` (`attached` or `degraded`), `programs [{name, attached, error?}]`, `kernel_release`, `btf_ok`, `session_cgroup_id`, `pid` (the sensor's own), `threads` (the sensor's other threads, the TLS resolver's; *omitted* when none: their reads of the shares are the sensor's, which the reconciler leaves alone), `reason` (*omitted* unless one reason covers it) | What the sensor could attach, once it has tried, and again if that changes. |
| `proc.tls_io` | `tid`, `tgid`, `dir` (`write` or `read`), `bytes` | A process wrote to or read from a TLS connection through a runtime that exports OpenSSL's `SSL_write` and `SSL_read` (or their `_ex` forms), which the sensor probed: the size and the time, never the bytes. What names the process behind a model request (`docs/reconciler.md`). |
| `proc.tls_attach` | `path`, `ok`, `error` (*omitted* when ok) | The sensor tried to attach its TLS probes to a file: each program the session ran and each `libssl.so*` a session process mapped, once each; `error` is `limit` once after 64 paths, or `not a regular file` for a path that names a device, a pipe or a directory (never read). The file is opened once, its symbols read from it and the probes attached to it, whatever the path names by then. No `subject`. |

The sensor's stream is framed `[u32 LE len][json]`, each frame the record's
`type` and `data` with `ts_guest_ns` and `subject` beside them, at most 64
KiB; `proto/schema/sensor-v1.json` and `proto/testdata/sensor-v1.jsonl`
describe it. A frame that is not a sensor's ends the stream.

## `http.*` (host, src `gate`)

The observer's reading of an inspected flow's plaintext (`--inspect`):
every HTTP/1.1 and HTTP/2 exchange, as the bytes moved. The observer
takes a copy of the plaintext off the net thread; bodies are
content-decoded (`gzip`, `deflate`, `br`), hashed whole, and kept for the
model parsers up to 16 MiB. A header that carries a credential
(`authorization`, `x-api-key`, `cookie`, names ending in `-token` or
`-secret`, among others) has its value dropped at the parser: nothing
downstream can see it. `stream` is HTTP/2's stream id, or 1, 2, 3... for
HTTP/1.1's requests in order on the flow.

| Type | Fields | When |
|---|---|---|
| `http.request` | `flow`, `stream`, `version` (`1.1` or `2`), `method`, `authority`, `path` (query values that are long, not plain, or under a secret-looking name replaced by `[redacted]`, the fragment dropped, then cut at 4096 bytes), `content_type`, `content_encoding`, `content_length`, `user_agent` (scrubbed as free text, cut at 512), `body_bytes` (decoded), `body_b3`, `body_truncated`, `degraded` | A request's body ended (or could not: `degraded` says why: `lost` (the observer's channel had no room), `incomplete`, `flow_closed`, `content_encoding` (a coding the observer does not decode: the raw body is hashed), `content_decode`, `decode_budget` (the body decoded past 64 MiB: the rest is hashed raw), `observe_budget` (the observer held 256 MiB across every flow: the body was hashed, not kept; or the exchange itself, with its heads, found no room: it was recorded as it stands and let go; or, with no stream, the connection's parsers would have passed it and the connection is observed no further), `too_many_exchanges` (512 exchanges were open on the flow: the oldest is recorded as it stands), `sse_line` (an event-stream line ran past 16 MiB: it was dropped), `upgrade_wait` (more than 64 KiB came while a request to switch protocols waited for its answer), `pipeline` (256 requests were waiting for their responses), `header_block_too_large` (a header block over 64 KiB, or one that decodes past 128 KiB), or a parser's reason, such as `rst_stream`: a stream that is observed no further is recorded at once). |
| `http.response` | `flow`, `stream`, `status`, `content_type`, `content_encoding`, `body_bytes`, `body_b3`, `body_truncated`, `sse_events` (events of a `text/event-stream` body), `ws_messages` (messages of a WebSocket stream, both ways), `dur_ms` (the request's first byte to the response's last, as the observer took them), `degraded` | A response ended; for a WebSocket stream, when it closed. |

## `llm.*` and `tool.*` (host, src `gate`)

The model APIs the gate knows, read from the exchanges above: the
Anthropic Messages API (`/v1/messages`), OpenAI Chat Completions
(`/chat/completions`) and OpenAI Responses (`/responses`, as JSON, as an
event stream, or over WebSocket), chosen by the request's path whatever
the host. Bodies are read tolerantly: unknown fields and events are passed
over, and a body that does not read degrades the record, never the flow.
Text is never inline: prompts, replies and tool results appear as sizes
and blake3 hashes, and in summaries of at most 512 bytes, scrubbed. A
`tool.open` and the `tool.close` that answers it carry the envelope's
`span`: `trace_id` is the session id, `span_id` the provider's tool use
id; the reconciler attributes the processes and effects between them to
that span (`span.effects`, docs/reconciler.md).

| Type | Fields | When |
|---|---|---|
| `llm.request` | `flow`, `stream`, `provider` (`anthropic`, `openai_chat`, `openai_responses`), `model`, `streaming`, `messages` (count), `system_b3`, `tools [string]` (names, at most 64), `max_tokens`, `body_bytes`, `body_b3`, `degraded` | A request's body ended; over WebSocket, a `response.create` message came. The `tool.close`s it carried follow it. |
| `tool.close` | `flow`, `stream`, `tool_use_id`, `status` (`ok` or `error`), `result_bytes`, `result_b3`, `result_summary` (scrubbed by key when it is JSON, as free text otherwise) | The request carried a tool result (`tool_result`, a `role: tool` message, a `function_call_output`): the span closes. |
| `tool.open` | `flow`, `stream`, `tool_use_id`, `tool_name`, `args_b3`, `args_summary`, `args` (the arguments as JSON when at most 8 KiB, omitted otherwise; both scrubbed by key and in their strings; with a policy file's `[spans] keep_tool_args = false`, `args` is omitted and `args_summary` is `[arguments not kept: keep_tool_args = false]`; when a piece of the arguments found no room in the observer, `args` and `args_b3` are both omitted and `args_summary` is `[arguments not kept whole]`: nothing partial is kept, and the reconciler says so at the close, `unverified_intent`) | The model's reply asked for a tool: in a stream, as soon as the call's arguments are whole; in a document, at its end. The span opens. |
| `llm.response` | `flow`, `stream`, `provider`, `model` (cut at 256 bytes, as `stop_reason` and `llm.request`'s `model` and `tools` names are), `stop_reason`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `text_bytes`, `text_b3`, `tool_uses`, `dur_ms`, `degraded` | The reply ended (the stream's end, the document's end, or over WebSocket the `response.completed`); `degraded` says what cut it short (`stream_unfinished`, `stream_error`, `block_unfinished`, `call_unfinished`, `event_json`, `response_json`, `body_truncated`, `flow_closed`, `stream_budget` (the reply's tool calls gathered more than 16 MiB, or more than 256 were under way at once: no call grew further), `observe_budget` (the observer's 256 MiB across every flow was spent), `sse_line`). A tool id over 256 bytes is kept as its first 128 bytes, `~b3:` and the hash of the whole id, an open and its close alike, and a tool name is cut at 1 KiB; a call whose arguments lost a piece for want of room carries none (`args_summary` `[arguments not kept whole]`). |

## `span.*` and `finding` (host, src `reconciler`)

| Type | Fields | When |
|---|---|---|
| `span.effects` | `span_id`, `tool_name`, `opened_seq`, `closed_seq` (or null), `executor_tgid` (the process that opened the model request's flow; before that is known, provisionally the one process whose TLS writes fit the request; else the session root; or null), `procs [u32]` (tgids, at most 1024), `effects [u64]` (seqs, ascending, at most 4096: each process's `proc.exec` and the `fs.*` and `net.connect` records of their work), `truncated` | A tool span closed (its `tool.close` came), or the VM stopped with it open (`closed_seq` null). A membership record: what the reconciler attributed to the span (`docs/reconciler.md`); the effects themselves are never edited. The envelope's `span` names the span. |
| `finding` | `category` (`unattributed_effect`, `sensor_silence`, `intent_effect_mismatch`, `indicator_removal`, `off_book_channel`, `orphaned_work`, `network_anomaly`, `privilege_probe`, `policy_denial`, `unverified_intent`), `score` (0 to 100), `rule`, `summary` (512 bytes at most), `evidence [{seq, ring}]` (the records the rule read, newest last), `span_id` (set inside a span, omitted otherwise; the envelope's `span` then names it too), `low_confidence` | The reconciler's conclusion from records of both rings. Never sampled; a score of 70 or more is written through to disk at once. The rules are in `docs/reconciler.md`. |

## Order and durability

Records are chained in the order the single writer took them, which is the
order their producers submitted them, across all sources. A `vmm.start`
is first and `policy.loaded` second. `vmm.stop` is followed only by the
reconciler's last records (the findings it makes once it reads the stop,
and the `span.effects` of tool spans still open) and a closing
`checkpoint`, which is last. A `net.connect`
precedes its flow's `net.tls` and `net.close`; `net.tls{allow}` is in the
log before the first held byte reaches the host; `net.udp{allow}` before
its first datagram does. Every record is on disk by the next checkpoint
(within 2 s); `vmm.stop`, `proc.lsm_deny` and a `finding` scoring 70 or
more are `fdatasync`ed at once. A writer that fails
stops the VM (`boxcar run` exits 3) and cuts the log back to its last
consistent record; `boxcar audit verify` accepts what is left.

A crash can end the log mid-write: a process killed while it writes keeps
every `write(2)` that completed and loses the rest. A log cut at a record
boundary verifies as intact, and only its missing `vmm.stop` and closing
`checkpoint` tell. Any other cut leaves the tail in one of these states,
and `boxcar audit verify` reports the log as *incomplete*, exit code 4,
with what verified before the cut (`--json`: `incomplete {kind, segment,
offset, bytes}`):

| `kind` | The tail | `segment`, `offset`, `bytes` |
|---|---|---|
| `partial_line` | The newest segment ends in a partial line, no longer than a record (64 KiB): a write cut short. | Where the line starts, and its length. |
| `unindexed_checkpoint` | The last record is a checkpoint, the newest segment's last line, which `checkpoints.jsonl` does not list; it lists every checkpoint before it. Cut between the checkpoint's sync and its index line. | Where the checkpoint's line starts; 0. |
| `partial_index_line` | The same, but `checkpoints.jsonl` ends in the first bytes of that checkpoint's index line, byte for byte: its append cut short. | Where the checkpoint's line starts, and how many bytes of its index line there are. |
| `rotation` | The newest segment file is empty, and `meta.json` does not list it yet; the one before ends in a checkpoint the index lists. | The empty segment; 0, 0. |
| `no_segment` | `meta.json` lists one segment, and there is none: a new session cut before its first record. | 1; 0, 0. |

Exactly one of them, at the very end. Two at once, or one anywhere else,
is a break (exit code 1): a partial line in a segment before the newest,
an index line naming a checkpoint past the end, an extra segment that is
not empty, a partial index line that does not start its checkpoint's
line. The writer's own rollback after a failure cuts `checkpoints.jsonl`
before the segment, so a crash in the middle of it leaves one of these
states too. A deliberate cut can leave the same tails, so verify cannot
tell a crash from one, and says `cause unknown`. An incomplete log hides
no more than a cut at a record boundary can: `checkpoints.jsonl` still
proves every record up to the last checkpoint it lists.
