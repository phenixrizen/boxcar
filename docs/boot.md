# From `boxcar run` to the agent's shell

What happens between `boxcar run` and the session's first prompt, step by
step, and how a session ends: on the host, in `boxcar run` and the VMM; in
the guest, in the kernel and in `boxcar-init`, its PID 1. Each step names
the audit records it makes; their fields are in
[audit-events.md](audit-events.md). The process and its threads are in
[architecture.md](architecture.md); the image cache in
[images.md](images.md); the policy in [policy.md](policy.md); the guest's
network in [networking.md](networking.md) and [gate.md](gate.md); the
control socket in [control-protocol.md](control-protocol.md).

## Before the session exists

`boxcar run` checks everything it can refuse before it makes a session, so
a typo leaves nothing behind.

1. **The flags.** The VM gets a network card and a vsock device when it
   has shares (`--rootfs` or `--image`), unless `--no-net` or `--no-vsock`
   says otherwise. `--image` must parse as a reference; `--pull` and
   `--cache-dir` need `--image`; `--allow`, `--deny`, `--inspect`,
   `--policy-file` and `--dns` need a network; `--stdin` and
   `--vsock-allow` need the vsock device. Each refusal exits 2.
2. **The policy.** `--policy` names a built-in profile (`agent-isolate`,
   `agent-isolate-strict`) or a TOML policy file; without it the policy is
   the line policy of `--policy-file`, deny by default. `--deny`, `--allow`
   and `--inspect` are added after the policy's own rules. A rule that
   does not parse exits 2, saying where it is. A policy file's `[fs]` and
   `[exec]` become the shares' path rules, `max_dns_qps` the network's DNS
   rate, `[fs] indicators` the reconciler's, `[spans] keep_tool_args` the
   gate's, and `[record] scrub_argv` acts as `--scrub-argv`. What
   `policy.loaded` will say (the source, the name, the text's SHA-256, the
   rule counts) is settled here ([policy.md](policy.md)).
3. **The paths.** `--ready-fd` must name a descriptor open for writing,
   not 0, 1 or 2; `--rootfs` and `--workspace` must be directories with
   UTF-8 paths; the audit directory (`--audit-dir`, else
   `$XDG_DATA_HOME/boxcar` or `~/.local/share/boxcar`) may be neither a
   share nor inside one, and no share may expose its logs; `--dump` needs
   a network (exit 2) and a new or empty directory that is neither a
   share, nor inside one, nor holds one. The other refusals here exit 1.
4. **The image.** With `--image`, the cache (`--cache-dir`, else
   `$XDG_CACHE_HOME/boxcar` or `~/.cache/boxcar`) is locked shared and the
   image is found there or pulled, as `--pull` says: `missing` (the
   default), `always` or `never`. stderr says `image: <reference>
   <manifest digest>`, with `(cached)` when no layer was fetched (the registry may still have been
   asked for the manifest). An image
   the cache lacks under `--pull never` exits 1. The lock is held until the
   session's copy is made, so `boxcar image rm` and `boxcar image prune`
   wait for it ([images.md](images.md)).

## The session

1. **The session id**, a new UUIDv7. It names the log's directory, the
   state directory and the session CA.
2. **The session CA**, only when the policy has an `inspect` line: made for
   this session, its key kept in the process ([gate.md](gate.md)).
3. **What the session runs.** The command after `--`; else, with an image,
   its Entrypoint and Cmd; else a login shell, `/bin/sh -l`. The
   environment is boxcar's defaults (`PATH`, `HOME`, `TERM`, `LANG`,
   `BOXCAR_SESSION_ID`), then the image's `Env`, then `--env`, one value
   per name, the last given winning. The working directory is the image's
   `WorkingDir`, or `/workspace`. The user is the invoking user's real uid
   and gid. The terminal has stdin's size, or 24 by 80. With a session CA,
   its certificate (never the key) goes too. In vsock mode the config is
   checked as init will check it. The kernel command line is measured as
   the VMM will build it: over 2048 bytes is refused.
4. **The directories.** The session's directory,
   `<audit dir>/sessions/<id>/`, and the state directory, `<id>/` under
   `$XDG_RUNTIME_DIR/boxcar` (or `/tmp/boxcar-<uid>`), both mode 0700. The
   state directory holds the sockets and, in vsock mode, the serial
   console's `console.log` (mode 0600), unless `--console-log` or
   `--console-stdout` says otherwise.
5. **The Landlock domain** (`--landlock enforce`, the default), applied
   before the run starts a thread of its own, so that every thread
   inherits it. Beneath the session's and the state directories, the shares
   and a dump directory it allows everything but running a program. It
   allows reading the cached image's tree, the kernel and the initramfs,
   and the few host files the process reads by itself (`/etc/resolv.conf`
   with a network, its mount table with shares, three that glibc reads);
   writing a `--console-log` file; and `/dev/kvm`. No rule lets the process
   run a program or bind a TCP port. A kernel without a usable Landlock
   runs the session unconfined, with a warning; `vmm.start` records which
   ([architecture.md](architecture.md) has the confinement).
6. **Signals.** `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` are blocked on
   every thread, so that they reach the VMM only through its signalfd;
   `SIGWINCH` too, for the terminal's size. When stdin is a terminal, a
   `job-control` thread takes `SIGTSTP` and `SIGCONT` (the README's "Job
   control").
7. **The audit writer.** Its thread starts the log. stderr says
   `session: <id>` and `audit: <dir>`.
8. **The shares.** The root share is `--rootfs`, or with an image a copy
   of the cached tree at `rootfs/` in the session's directory, reflinked
   where the filesystem can, with what init would otherwise make at boot
   (mount points, the working directory, `/etc/resolv.conf`, the trust
   store) made in it first. The workspace is `--workspace`, or a new
   `workspace/` in the session's directory; stderr says
   `workspace: <dir>`. The image cache's lock goes. The guest caches the
   root share freely and revalidates the workspace, which the host may
   change too. stderr says `console: <path>` when the console goes to the
   state directory. The copy is in [images.md](images.md).
9. **The reconciler.** Its thread, `reconcile`, subscribes to the log from
   the first record, before the VM is built
   ([reconciler.md](reconciler.md)).

## Building the VM

`Vmm::new` builds the VM, in order:

1. With the vsock device, the session's config is checked again.
   `/dev/kvm` is opened, its capabilities and vCPU limit checked, and the
   open-file limit raised to the hard limit.
2. The VM, with its TSS, in-kernel irqchip and PIT.
3. Guest memory (`--mem-mib`, 512 by default), mapped into the VM and kept
   out of core dumps.
4. The kernel, an uncompressed ELF `vmlinux` loaded at its physical
   addresses, and the initramfs, copied to the top of low memory.
5. The legacy devices: COM1, the guest's `ttyS0`, whose output a `console`
   thread writes out; and an i8042 that knows only the reset command.
6. The boot scan: when the policy denies paths or refuses programs, the
   shares are walked once, to know those files by host identity before
   any device serves them. A directory it cannot read fails the run.
7. The virtio-mmio devices, each in its fixed slot: virtio-fs `root`
   (slot 0) and `workspace` (slot 1), virtio-net (slot 2), virtio-vsock
   (slot 3, guest CID 3, host socket `vsock.sock` in the state directory).
   Behind the vsock device's internal ports: the guest control channel
   (1024, `boxcar.ctl`), the PTY hub that carries the session's terminal
   (1025, `boxcar.pty`), and, unless `--no-sensor`, the sensor's stream
   (1026, `boxcar.sensor`).
8. The kernel command line: the base (`console=ttyS0 reboot=k panic=1
   pci=off nomodule ... lockdown=integrity ... quiet loglevel=4
   rdinit=/init`; `--debug-boot` swaps the quiet part for early printk);
   with a network card, `ip=10.0.2.15::10.0.2.2:255.255.255.0:boxcar:eth0:off:10.0.2.2`
   and `boxcar.net=1`; then the `boxcar.*` keys and `--cmdline-extra`;
   then one `virtio_mmio.device=` entry per device. Then the zero page and
   the MP table.
9. The vCPUs (`--vcpus`, 1 by default). vCPU 0 is set up in 64-bit mode at
   the kernel's entry point, with the zero page in `rsi`.
10. The seccomp filter (`--seccomp enforce`, the default): one allowlist,
    installed on every thread at once, after the kernel and the initramfs
    were read and hashed.
11. `vmm.start`: the version, the kernel's and the initramfs's paths and
    blake3 hashes, the command line, the vCPUs, the memory, the shares,
    `inspect_ca_sha256`, `image` and `hardening`. Then `policy.loaded`.
    They are always the log's first two records.
12. The control socket, `control.sock` in the state directory, mode 0600,
    bound after `vmm.start` so the log has no `control.connect` before it.
    A client can connect from now on; `status` says `booting`. A socket
    that cannot be bound ends the run with `vmm.stop{reason: "vmm_error"}`.

## Starting the VM

1. stderr says `control: <path>`. With `--ready-fd FD`, the line
   `{"ready":true,"control":"<path>","session_id":"<id>"}` goes to FD, and
   FD is closed.
2. In vsock mode, `boxcar run` attaches to the session's terminal before
   the VM runs, so it has the session's output from the first byte. It is
   the PTY hub's primary client: when its stdout falls behind, the hub
   stops reading the guest, and the session waits on its terminal rather
   than lose output. stdin goes to the session when it is a terminal, when
   no command was given, or with `--stdin`. A terminal is put in raw mode
   while the run is in its foreground, and its size follows `SIGWINCH`.
3. `Vmm::run` makes the main thread the main loop. It waits on the stop
   latch, the i8042's reset, the stop signals' signalfd, the audit
   writer's failure eventfd, each vCPU's exit, and the expiry of live
   policy exceptions.
4. The vCPU threads (`vcpu0`, `vcpu1`, ...) start last, so that nothing
   that can fail follows them; `status` says `running`. Each runs
   `KVM_RUN` in a loop and hands its port and MMIO exits to the devices.
   vCPU 0's first `KVM_RUN` enters the kernel. The process's other
   threads are in [architecture.md](architecture.md).

## The kernel and init

The kernel unpacks the initramfs as its root and runs `/init` (`rdinit=`),
which is `boxcar-init`. The initramfs holds init, the sensor
(`/boxcar-sensor`) and empty mount points. Init mounts `proc`, `sysfs` and
`devtmpfs`, reads the `boxcar.*` keys from `/proc/cmdline` (a repeated key
keeps its last value, so `--cmdline-extra` can override boxcar's), and
goes by `boxcar.mode`:

- `vsock`, with shares and the vsock device: the session the VMM
  configures over the control channel (below).
- `console`, with shares and `--no-vsock`: M1's session on the serial
  console ([The other modes](#the-other-modes)).
- `hello`, with `--no-fs`: `BOXCAR_INIT_HELLO` on the console, then a
  reboot; there is nothing to run.

A step that fails says `boxcar-init: <step>: <error>` on the console, and
init reboots; PID 1 never exits. In vsock mode the kernel's and init's
lines go to `console.log` by default, not to the terminal; a step that
fails once the session's config has come is also sent to the host, which
logs it on stderr (`guest: boxcar-init: <step>: <error>`).

### Vsock mode

1. **The shares.** `root` is mounted at `/newroot`, and `workspace` at
   `/newroot/workspace` (made if the root has none). Each share's first
   request is recorded as `fs.mount`.
2. **The API filesystems.** `/dev`, `/proc` and `/sys` move into the new
   root; `devpts`, and a tmpfs each on `/dev/shm` and `/run`, are mounted
   there, and `tracefs`, `cgroup2` and `bpf` where the kernel has them.
   Everything else, `/tmp` included, is the root share, which the host
   records.
3. **The root switch.** The sensor's binary is opened first, since the
   initramfs is out of reach after it; then `/newroot` becomes `/`.
4. **The network.** The kernel configured `eth0` from `ip=` as it booted,
   with no DHCP. With `boxcar.net=1`, init writes `nameserver 10.0.2.2` to
   `/run/boxcar/resolv.conf` and binds it over `/etc/resolv.conf`, through
   any link there, so the root share keeps its own file. A failure here
   is a warning, not a reboot.
5. **Kernel settings**, through `/proc/sys`: `kernel.kptr_restrict` 2,
   `kernel.dmesg_restrict` 1, `kernel.unprivileged_bpf_disabled` 1,
   `kernel.perf_event_paranoid` 3, `kernel.yama.ptrace_scope` 1, and IPv6
   off. One the kernel lacks or refuses is a warning.
6. **The cgroups**: `system` for init's helpers, `session` for the session
   and everything it starts.
7. **The sensor** (unless `--no-sensor`), before the session, so that its
   first exec is seen. It runs as root in `system`, keeping its
   capabilities. It connects to port 1026 from guest port 1021
   (`vsock.connect`), loads its eBPF programs filtered to the session's
   cgroup, says it is ready, reports `proc.sensor_status`, and sends a
   `proc.heartbeat` every second. Init waits up to 3 s for it; a sensor
   that is late or dies is a warning, and the session starts without it
   (the README's "The sensor").
8. **The control channel.** Init connects to port 1024 from guest port
   1023 (`vsock.connect`) and says `hello`. The VMM serves its internal
   ports only from a guest port below 1024, which only a process with
   `CAP_NET_BIND_SERVICE` can bind, and only the first connection to each,
   so the session cannot pose as init. The VMM answers with the session's
   config; with no config within 10 s, init says so on the console and
   reboots. From the config on, the VMM pairs the clocks: a `sync` now,
   then one every 10 s.
9. **The config.** Init checks it again and sets the hostname, `boxcar`.
   With a session CA, it writes `/run/boxcar/ca.pem`, binds a bundle of
   the root share's store and the CA over
   `/etc/ssl/certs/ca-certificates.crt`, and names them in the session's
   environment (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
   `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`) unless the config sets them
   ([gate.md](gate.md)).
10. **The terminal.** Init connects to port 1025 from guest port 1022
    (`vsock.connect`), sends the header
    `{"v":1,"session":"main","rows":R,"cols":C}`, and opens a PTY of that
    size whose slave belongs to the session's user.
11. **The session.** Init forks the session's process, which, before it
    runs anything: leads a session of its own with the PTY's slave as its
    controlling terminal, and as its stdin, stdout and stderr; joins the
    `session` cgroup; empties its capability bounding set and its ambient
    set, while still root; drops its supplementary groups; takes the
    session's gid and uid, real, effective and saved; sets `no_new_privs`;
    changes to the working directory; and puts every signal back to its
    default action, unblocked. Then it runs the command, looked for on the
    session's `PATH` unless it holds a `/`. Nothing it runs can gain a
    capability, even as uid 0. A command that cannot be run is
    `boxcar-init: exec: <command>: <error>` on the terminal, and exit
    status 127.
12. **`session.start`.** Init reports the session's pid, and the VMM
    records `session.start`: the argv (scrubbed with `--scrub-argv`), the
    working directory, the uid, the gid and the pid.

The agent's shell is up. Init relays the PTY's master to port 1025 and
back; the PTY hub relays that to `boxcar run`'s stdout and from its stdin.

## While the session runs

Init's loop relays the terminal, reaps every child (the orphans the kernel
hands it included), and serves the host over the control channel: `resize`
(the host's `SIGWINCH`, or `pty.resize`) sets the PTY's size, `ping` gets
a `pong` (the `sync` records), and `shutdown` ends the session (`boxcar
stop`, below). A control channel the host closes while the session runs
counts as a `shutdown` with 5 s of grace. What the session does on the
shares, the network and vsock is recorded on the host (ring 0); what the
sensor sees of its processes is `proc.*` (ring 1).

## How a session ends

When the session's process exits:

1. Init sends what is left on the PTY to the host, for as long as the
   host takes it (until it has taken nothing for 2 s), closes its sending
   side of the stream, and reports how the session ended. The VMM records
   `session.exit` (the exit code, or the signal that killed it), keeps it
   for the run's exit code, and closes its side of the control channel.
2. Init sweeps the processes left, the sensor among them: `SIGTERM` to
   every process but itself, `SIGKILL` 2 s later, and at most 10 s more
   for the last of them.
3. Init waits for the host to close its side of both streams, the sign
   that the report and the last output are in, until 2 s after the host
   last took a byte. It writes `boxcar: session exited <code>` (or
   `boxcar: session killed by signal <n>`) on the console, gives the
   console up to 2 s to send it, syncs, and reboots.
4. With `reboot=k` the reboot is a reset through the i8042, which the main
   loop sees: the VM's exit is a guest reset carrying the session's end.

The VMM's stop sequence then runs on the main thread:

1. The control clients hear `stopping`.
2. Every vCPU is kicked out of `KVM_RUN` and its thread joined.
3. The devices close. Each virtio-fs device is reset, which records an
   `fs.close` for every file the guest left open; the network card's
   thread records a `net.close` (`shutdown`) for every flow still open;
   the vsock thread records a `vsock.close` for every connection, and the
   host socket is removed.
4. The guest control channel's threads get 1 s, so that what init sent
   last is recorded. The PTY hub's stream closes; its clients get the end
   of the output.
5. The console writer gets 2 s to write what the guest printed last; what
   it could not is counted.
6. The control server shuts down: each client hears `stopped`, the socket
   is removed, and the state directory too if it is empty.
7. `vmm.stop`: the reason, the exit code, and the console output and input
   dropped. It is synced to disk at once.
8. The terminal is restored.

Then `boxcar run` writes the session's last output to stdout for as long
as stdout takes it (until it has taken nothing for 2 s, 30 s at most, or
another stop signal), and says on stderr how many bytes it could not
(`boxcar: N bytes of session output not delivered: ...`). The reconciler,
which ends when it reads `vmm.stop`, writes its last findings and a
`span.effects` for each span still open (`closed_seq` null); these may
follow `vmm.stop` in the log. It gets 5 s. The writer then closes the log:
it writes every record it accepted, a final `checkpoint`, and syncs.
stderr says how the VM ended (`guest reset; the session exited 0`), and
`boxcar run` exits.

## Other ways it ends

- **`boxcar stop`** asks for a graceful stop over the control socket
  (`control.stop{mode: "graceful"}`). Init sends the session's process
  group `SIGHUP` and `SIGTERM`, then `SIGKILL` after `--timeout-ms` (5000
  by default, 60 s at most), and the session ends as above, `session.exit`
  included. The guest's reset is taken as the stop that was asked for; a
  guest that has not reset 3 s after the timeout is stopped by the VMM.
  `boxcar stop --force`, or a stop with no session running, stops the
  vCPUs at once. Either way the run exits 0.
- **A stop signal** to `boxcar run` (`SIGINT`, `SIGTERM`, `SIGHUP`,
  `SIGQUIT`) stops the VM at once through the stop sequence: no
  `session.exit` unless the session had ended already. On a raw terminal
  Ctrl-C goes to the session, not to `boxcar run`.
- **Ctrl-] twice** within a second on the terminal stops the VM the same
  way; the escape does not reach the session.
- **The audit writer failing** stops the VM. The log is cut back to its
  last complete record and takes nothing more, `vmm.stop` included; stderr
  says `audit log failed: <why>`.
- **A seccomp kill** (a syscall off the allowlist under `--seccomp
  enforce`) kills `boxcar run` by `SIGSYS`: a crash. There is no stop
  sequence: no `vmm.stop`, no final checkpoint, no `fs.close` for the
  files the guest held open. The log may end mid-record, which
  `boxcar audit verify` reports as incomplete (exit 4).

| How the run ended | `vmm.stop` reason | Exit code |
|---|---|---|
| The session exited | `guest_reset` | the session's code, or 128 + N for signal N |
| `boxcar stop`, graceful or forced | `stop_requested` | 0 |
| `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT` | `signal` | 130, 143, 129, 131 |
| Ctrl-] twice | `console_escape` | 130 |
| A vCPU error | `vcpu_error` | 1 |
| The VMM failed after `vmm.start` | `vmm_error` | 1 |
| The audit log failed | none recorded | 3 |
| A seccomp kill | none | killed by `SIGSYS` |
| A guest reset with no session report (console and hello modes) | `guest_reset` | 0 |

The README's "Exit codes of `boxcar run`" lists the usage errors too.

## The other modes

- **Console mode** (`--no-vsock`, not with `--image`): the command line
  carries `boxcar.mode=console`, `boxcar.uid`, `boxcar.gid` and, after
  `--cmdline-extra`, the command as `boxcar.cmd`. Init mounts the shares,
  switches root, and sets up the network, the hostname, the kernel
  settings and the cgroups as in vsock mode, but starts no sensor and has
  no control channel. It makes
  `/dev/ttyS0` its own controlling terminal and runs the session in its
  foreground, in `/workspace`, with a fixed environment (`HOME`, `TERM`,
  `PATH`, `USER=agent`), dropping privileges the same way. When the
  session ends it sweeps the rest, writes the exit line on the console,
  and reboots. The console is on stdout unless `--console-log` says
  otherwise, and stdin goes to it, with Ctrl-] twice stopping the VM, only
  when the console is on stdout, no command was given and stdin is a
  terminal. There are no `session.*`
  or `sync` records, and the run exits 0 whatever the command did.
- **Hello mode** (`--no-fs`): no shares, and no network card or vsock
  device unless `--net` or `--vsock` asks. Init prints
  `BOXCAR_INIT_HELLO` and reboots; the log records `vmm.start`,
  `policy.loaded`, then `vmm.stop{reason: "guest_reset"}`, and the run
  exits 0.
