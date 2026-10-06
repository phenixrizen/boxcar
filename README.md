# boxcar

A microVM runtime for running AI coding agents in isolation, with a complete,
tamper-evident record of everything the agent did.

boxcar boots a small Linux guest on KVM from a directory, not a disk image.
The root filesystem and the workspace are served by the runtime itself over
virtio-fs, the guest's network is terminated by a user-mode stack inside the
runtime, and the model API is reached through a gateway that holds the real
key. Every file operation, connection, DNS query, process, and model tool call
lands in one append-only, hash-chained log. A second, best-effort sensor
inside the guest reports process lineage, and a reconciler flags where the
two views, or the model's stated intent, disagree.

Status: pre-alpha. See [docs/specs](docs/specs) for
the design and [docs/plans](docs/plans) for the
roadmap.

## Quick start

On x86_64 Linux with KVM and Docker (see
[CONTRIBUTING.md](CONTRIBUTING.md#kvm-on-the-dev-machine)):

```bash
cargo xtask kernel               # target/guest/vmlinux, built in Docker
cargo xtask initramfs            # target/guest/initramfs.cpio
cargo xtask rootfs alpine        # target/guest/rootfs-alpine/
cargo run -p boxcar -- run --kernel target/guest/vmlinux \
    --initramfs target/guest/initramfs.cpio --rootfs target/guest/rootfs-alpine
```

The last command boots the guest into a login shell on a terminal of its
own, relayed to yours, as your own uid and gid, with a fresh workspace at
`/workspace` and a network card behind a policy that allows nothing yet;
`exit` ends it (Ctrl-] twice stops the VM). Add `-- CMD [ARGS...]` to run a
command instead, such as `-- /bin/sh -c 'echo hi > /workspace/a.txt'`; the
run exits with the command's exit code. `boxcar run` prints the session's
id, its audit directory and its control socket on stderr (`audit: ...`, in
`~/.local/share/boxcar/sessions/` unless `XDG_DATA_HOME` or `--audit-dir`
says otherwise). To check that its log is intact:

```bash
cargo run -p boxcar -- audit verify ~/.local/share/boxcar/sessions/<session-id>
```

### Rootfs persistence

The guest owns the `--rootfs` directory and changes it in place: what a
session writes outside `/workspace` (a package installed, a file in `/tmp`
or `/root`) is there for the next session that boots from the same
directory. Sessions must not share one rootfs directory at the same time.
Until the per-session overlay lands, give each session a fresh copy (for
example `cp -a target/guest/rootfs-alpine /tmp/rootfs-1`), or run
`cargo xtask rootfs alpine` again to start from a clean one. The session's
`vmm.start` record names the host directory behind each share.

## What you get

Every file operation the guest makes on its root filesystem and its
workspace is a record in the session's hash-chained log
(`events.000001.jsonl`, one JSON object per line), with the guest process
that made it. The write above ends in this `fs.close`: the bytes written,
and the blake3 of the file as it was when it was closed. Each record's
`hash` covers the record and the `prev` hash before it, so
`boxcar audit verify` finds a record that was changed, removed or moved.

```json
{
  "v": 1,
  "session_id": "01a0f42e-4fdf-74e9-95de-4e59c0ac45eb",
  "seq": 17,
  "ring": 0,
  "src": "fs",
  "type": "fs.close",
  "ts_host_ns": 1790803086699680800,
  "ts_mono_ns": 56639722415839,
  "subject": { "pid": 510, "uid": 1000, "gid": 1000 },
  "data": {
    "attrib": "handle",
    "blake3": "b3:0b8b60248fad7ac6dfac221b7e01a8b91c772421a15b387dd1fb2d6a94aee438",
    "bytes_read": 0,
    "bytes_written": 3,
    "fh": 1,
    "hash_status": "ok",
    "mount": "workspace",
    "open_seq": null,
    "path": "/a.txt",
    "path_at_open": "/a.txt",
    "size": 3
  },
  "prev": "b3:a4a0dd122372b11407216f4a6c847043619e16e30d902419a4f3c7f3f688b9c2",
  "hash": "b3:c383911bcb6384aa0f182498dd8d7be0cdc2ed36245fcdda8d92dd5e11f9ed04"
}
```

## What the log does and does not capture

- At the default (`--audit-level normal`) the log records opens, creates,
  closes and every change (unlink, rename, mkdir, setattr, ...), and denied
  lookups. It does not record reads, writes, lookups, `getattr` or
  directory listings one by one: what went through a handle is summed up in
  its `fs.close`. `--audit-level verbose` adds reads, writes and listings,
  which may be dropped (and counted) when the log is busy.
- The hash in `fs.close` is best effort. The file is read again by path
  after the close; if it changed in the meantime (another handle wrote to
  it, or the path now names another file) the close says `raced` instead
  of giving a hash, and a file over 64 MiB is `skipped_size`.
- `fs.denied` is mostly dormant. The guest's kernel checks permissions
  itself and refuses most accesses before they reach the host, and on the
  host every request is served with your permissions (the guest's ids are
  recorded, not enforced there), so a denial is recorded only when your
  own permissions refuse it.
- Reads the guest kernel serves from its page cache never reach the host
  and are not seen. The root filesystem is cached aggressively; the
  workspace is revalidated.
- If the log cannot be written (a full disk, an I/O error), boxcar stops
  the VM, refuses every further change to the shares with EIO in the
  meantime, and exits 3 with `audit log failed: <why>`. The records the
  guest's last operations produced before the failure may be lost; the log
  is cut back to its last complete record and still verifies.
- `boxcar audit verify` proves that the chain is intact and complete up to
  its last record: nothing was changed, removed or reordered. It does not
  prove that the session ended cleanly; look for its `vmm.stop`.

## Networking and policy

With shares the guest gets a network card. The network is played inside
the runtime, with no TAP device and no privileges: the guest is
`10.0.2.15/24`, `10.0.2.2` is its gateway, DNS server and DHCP server, and
the guest's TCP connections end in the runtime and are relayed to host
sockets; UDP is relayed by NAT. Nothing leaves without a policy rule that
allows it. `--no-net` takes the card away.

```bash
boxcar run ... --allow example.com --allow '*.github.com:443' \
    --allow 198.51.100.7:22 --policy-file team.policy -- npm ci
```

- `--allow RULE` and `--deny RULE` take `domain[:port]` (the name, or every
  name under it for `*.domain`) or `cidr[:port]` (an address, or a network
  such as `198.51.100.0/24`); `--policy-file PATH` reads `allow RULE`,
  `deny RULE` and at most one `default allow|deny` (deny when absent), one
  a line. The file's rules come first, then the denies, then the allows,
  and the first rule that matches decides.
- A domain rule admits only clients that say the name: the guest's DNS
  query for it is answered, and a connection it allowed is held until its
  first bytes show that name as a TLS server name or an HTTP `Host`, or it
  is reset. Protocols that show no name (SSH, SMTP) and UDP need a CIDR
  rule. A name no rule allows does not resolve (NXDOMAIN).
- Private and local networks (`127.0.0.0/8`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`,
  `0.0.0.0/8`, multicast, and the host's own addresses) stay denied unless
  a rule names exactly that range, so an agent cannot reach the host's
  services or a cloud metadata endpoint by accident.
- The policy can change while the VM runs: `boxcar policy show`, `boxcar
  policy allow RULE` and `boxcar policy deny RULE` (or `policy.update` on
  the control socket). Connections the new policy denies are closed at
  once and recorded as such.
- Every decision is in the log: `net.dhcp`, `net.dns` (the query, its
  verdict and the addresses answered), `net.connect` (each connection with
  its verdict and the rule that decided), `net.tls` (the name the
  connection showed), `net.close` (bytes each way, duration, why it ended),
  `net.udp`, `net.drop`, and `policy.changed`. See
  [docs/audit-events.md](docs/audit-events.md) for every field and
  [docs/networking.md](docs/networking.md) for what the network does and
  does not do.

## Watching the model traffic

`--inspect RULE` (written like `--allow`, which must still admit the
connection) watches the guest's traffic to a destination: a TLS
connection ends in boxcar, which reaches the real host with its own TLS,
checked against the host's trust store, hands the guest a certificate
from the session's own CA (init puts it in the guest's trust store and
names it in the environment Node, Python, curl and git read), and relays
the plaintext unchanged both ways with a copy to an observer. The
observer records every HTTP exchange (`http.request`, `http.response`)
and the model APIs it knows, the Anthropic Messages API and OpenAI's
chat and responses APIs, as `llm.request` and `llm.response`; each tool
use in a reply opens a span (`tool.open`) that the tool result in the
next request closes (`tool.close`), and the reconciler attributes the
processes and effects in between to it (`span.effects`, `boxcar spans`)
and judges them (`intent_effect_mismatch`, `orphaned_work`).

```bash
boxcar run --rootfs R --workspace W --allow api.anthropic.com:443 \
    --inspect api.anthropic.com:443 -- claude -p 'List the files here'
boxcar spans            # the tool calls so far, newest first
```

No text is ever recorded inline: prompts, replies and tool results appear
as sizes and hashes, and in scrubbed summaries of at most 512 bytes; tool
arguments are kept whole up to 8 KiB. Credential headers' values are
dropped at the parser and reach no record, summary or dump. The agent
keeps its own credential; boxcar never holds or injects one. The whole
of it is in [docs/gate.md](docs/gate.md).

## Running Claude Code and Codex inside

The agents need glibc, a Node, and their own account logins. `cargo xtask
rootfs debian` builds a Debian guest (`target/guest/rootfs-debian`) with
Claude Code twice (the native build as `claude-native`, the npm build as
`claude`) and Codex, at pinned versions. A credential goes into the
session's environment with `--env`, over the control channel and into no
record; the gate inspects the model's host and the policy admits the
account's other endpoints:

```bash
boxcar run --rootfs target/guest/rootfs-debian --workspace W \
    --inspect api.anthropic.com:443 --allow api.anthropic.com:443 \
    --allow platform.claude.com:443 --allow claude.ai:443 \
    --env CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
    -- claude-native -p 'Run: echo hello > hello.txt' --allowedTools Bash

boxcar run --rootfs target/guest/rootfs-debian --workspace W \
    --inspect api.openai.com:443 --inspect chatgpt.com:443 \
    --allow api.openai.com:443 --allow chatgpt.com:443 \
    --allow auth.openai.com:443 --allow '*.oaiusercontent.com:443' \
    --env CODEX_HOME=/workspace/.codex \
    -- codex exec --skip-git-repo-check 'Run: echo hello > hello.txt'
```

(`claude setup-token` makes a Claude Code token; Codex reads `auth.json`
under `CODEX_HOME`, copied into the workspace here. A Codex account login
talks to `chatgpt.com`, an API key to `api.openai.com`; both are
inspected above.) Afterwards `boxcar
spans` lists the tool calls, and the log holds, for the Bash call, the
exec of the shell with that command and the close of the file it wrote,
in one chain. The gated tests `claude_code_native_runs_a_bash_tool_inside`,
`claude_code_under_node_runs_a_bash_tool_inside` and
`codex_runs_a_shell_tool_inside` do exactly this, and skip without the
Debian guest or a credential.

## Dump mode

`boxcar run --dump DIR` writes a debugging dump of the network beside the
log: `frames.pcap` with every frame the guest sent and every frame it was
given (open it with Wireshark or `tcpdump -r`), and for inspected flows
each decoded exchange as `http/<flow>-<stream>.req` and `.resp` (the
start line, the headers the observer kept, the decoded body with
secret-looking fields scrubbed) and, for one upgraded to WebSocket, its
messages as `.ws`. DIR is made 0700, its files 0600, and it
may be neither a share nor inside one. The dump is an aid, not part of
the audit log: nothing in it is hashed or chained. Filesystem traffic has
its own dump, `--audit-level verbose`.

## The sensor

Ring 0 of the log is what the host sees: every file operation, every
connection, every vsock request, observed where the guest cannot alter it.
Ring 1 is what the guest reports about itself: a small eBPF sensor that
init starts from the initramfs before the session's privileges drop, and
that streams to the VMM over vsock port 1026. It reports, for processes in
the session's cgroup:

- `proc.exec` (the program and its arguments), `proc.fork` (processes and
  threads), `proc.exit`;
- `proc.connect_attempt` (a `connect()` as asked) and `proc.tcp_connect`
  (the 4-tuple once the port is chosen), which is what ties a connection to
  a process;
- `proc.memfd` (anonymous memory files) and a sample of `proc.file_open`;
- `proc.tls_io`: the size and time of each TLS write and read of a
  runtime that exports OpenSSL's functions (Node, or busybox's
  `ssl_client` through `libssl`), never the bytes, and `proc.tls_attach`
  for each file the sensor tried to probe; this is what names the process
  behind a model request;
- `proc.lsm_deny`: the sensor's own protection refused something, a
  `bpf()` call or a signal to the sensor;
- `proc.heartbeat` once a second, and `proc.sensor_status` with what it
  could attach.

Ring 1 is corroboration, not the record. A guest that is root inside can
still try to silence it; the silence shows (the heartbeats stop, `boxcar
status` says `silent`, and the reconciler says so). `boxcar run
--no-sensor` runs without it; `status.sensor` then says `off`. The
programs are built on a pinned nightly and embedded in the sensor
(`CONTRIBUTING.md`, "The eBPF lane"); their licence is `MIT OR GPL-2.0`
(`docs/ebpf-license.md`).

## Findings

The reconciler reads the log beside the VM, joins the rings (a file
effect to the process whose thread made it, a flow to the process that
connected), and writes `finding` records into the same log: a category, a
score from 0 to 100, the rule, a sentence, and the records it read as
evidence. The rules are in `docs/reconciler.md`; in short:

| Category | Score | Fires when |
|---|---|---|
| `indicator_removal` | 90 | a shell history, a log, `ld.so.preload` or a file under `/root/.ssh` is removed or truncated |
| `sensor_silence` | 85 | the sensor never reports, or its heartbeats stop while the session keeps acting |
| `privilege_probe` | 80 | the sensor's guards refuse a `bpf()` call or a signal to the sensor |
| `off_book_channel` | 75 | `memfd_create`, or an open under `/dev/shm` |
| `network_anomaly` | 60 to 70 | a connection to an address no DNS answer named; a TLS server name that resolves elsewhere; a DNS rate or entropy spike |
| `unattributed_effect` | 60 | a file effect by a thread no reported process owns |
| `policy_denial` | 40 | the policy denied a query, a connection or a vsock request |

```
boxcar events --type finding --min-score 70      # the ones that matter, live
boxcar events --type finding                     # all of them
```

A finding whose join rested on a weak clock pairing, or on records the
reconciler missed, is marked `low_confidence` and scores 20 lower.

## Attach

A session's terminal is the runtime's, not your terminal's: `boxcar run`
relays it, and other terminals can join.

```bash
boxcar attach                    # the only running session
boxcar attach --ro <session-id>  # watch without typing
boxcar attach --replay 0 <id>    # without the last 64 KiB of output first
```

- What the session prints shows on every attached terminal, starting with
  the newest `--replay` bytes of its output (64 KiB by default, up to the
  runtime's 256 KiB scrollback). What is typed on any `rw` attach goes to
  the session, every key included; `--ro` sends nothing.
- Press Ctrl-P then Ctrl-Q, within a second, to detach: the session goes
  on. The session's terminal takes the size of the latest terminal to
  attach or to resize.
- The runtime keeps at most 1 MiB of output for each attached terminal,
  and waits at most 30 s for one that takes nothing. A terminal that falls
  further behind than that (or sits stopped that long) is detached with
  the reason `slow`, and `boxcar attach` exits 3; attach again to catch
  up. The session itself is never held up by a viewer.
- `boxcar run`'s own terminal is the primary one: when its stdout is a
  slow pipe the session waits for it (1 MiB behind), so nothing of a
  command's output is lost. Once the VM has stopped boxcar writes out what
  is left for as long as stdout takes it, and says how much it did not.
- The same terminal is reachable for programs over the control socket
  (`pty.attach`, `pty.resize`, `pty.watch`): see
  [docs/control-protocol.md](docs/control-protocol.md).

## Exit codes of `boxcar run`

| Code | Meaning |
|---|---|
| the command's | The session's command exited with it. |
| 128 + N | The session's command was killed by signal N (137: SIGKILL). |
| 0 | The guest reset with no session to report; `boxcar stop` ended the run; the console session (`--no-vsock`) ended. |
| 1 | A vCPU error, or a usage error that is not a parse error. |
| 2 | A command-line error, a policy rule that does not parse included. |
| 3 | The audit log could not be written: the VM was stopped, and stderr says `audit log failed: <why>`. |
| 130 | SIGINT (Ctrl-C on a non-raw terminal, or `kill -INT`), or Ctrl-] twice on the terminal. |
| 143, 129, 131 | SIGTERM, SIGHUP, SIGQUIT. |

## Job control

`boxcar run` and `boxcar attach` take the terminal only while they are in
its foreground. A run started in the background (`boxcar run ... &`) does
not read the terminal and leaves its settings alone; `fg` brings it
forward and it takes the terminal, raw. `kill -TSTP` (or Ctrl-Z while the
terminal is cooked; while it is raw, Ctrl-Z goes to the guest) stops the
run and gives the terminal back to the shell as it was; `fg` takes it
again, `bg` leaves it to the shell. A session stopped with its attach for
longer than 30 s is detached as slow when it continues (see above).

Licensed under Apache-2.0. Ported code keeps its original notices; see
[NOTICE](NOTICE).
