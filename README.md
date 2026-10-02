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
