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

Status: pre-alpha. See [docs/superpowers/specs](docs/superpowers/specs) for
the design and [docs/superpowers/plans](docs/superpowers/plans) for the
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

The last command boots the guest into a login shell on its serial console,
as your own uid and gid, with a fresh workspace at `/workspace`; `exit` ends
it (Ctrl-] twice stops the VM). Add `-- CMD [ARGS...]` to run a command
instead, such as `-- /bin/sh -c 'echo hi > /workspace/a.txt'`. `boxcar run`
prints the session's audit directory on stderr (`audit: ...`, in
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

Licensed under Apache-2.0. Ported code keeps its original notices; see
[NOTICE](NOTICE).
