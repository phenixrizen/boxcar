# Architecture

What a session is made of: the crates, the one `boxcar run` process and
what each of its threads owns, the two rings and how both reach the one
audit log, how the process is confined, the control socket, and the guest's
side. How a session boots and ends, step by step, is in
[boot.md](boot.md); the records are in [audit-events.md](audit-events.md);
the network and the model traffic gate in [networking.md](networking.md)
and [gate.md](gate.md); what the reconciler makes of the log in
[reconciler.md](reconciler.md); the policy in [policy.md](policy.md); the
control protocol in [control-protocol.md](control-protocol.md).

## The crates

The host side:

- `boxcar`: the command-line interface (`run`, `attach`, `status`, `stop`,
  `events`, `spans`, `policy`, `audit verify` and `audit export`, `image
  pull`, `ls`, `rm` and `prune`, `doctor`), with the control socket's
  client, the OCI registry client and image cache, and the OTLP sender of
  `audit export`.
- `boxcar-vmm`: the virtual machine monitor: KVM, guest memory, the boot,
  the vCPU threads, the buses and the legacy devices (COM1, the guest's
  console, and an i8042 for its reset), the main loop and the stop
  sequence, the guest control channel, the PTY hub, the sensor's ingest,
  the live policy, the control socket's server, and the process's
  hardening.
- `boxcar-virtio`: the virtio device layer: the `VirtioDevice` trait every
  device implements, the virtio-mmio transport, interrupts, the fixed MMIO
  slots, and the bus the vCPUs dispatch their exits on.
- `boxcar-fs`: audited virtio-fs: `AuditFs`, a decorator over
  fuse-backend-rs's passthrough filesystem that records every operation
  and enforces the path rules, and the threads that hash closed files.
- `boxcar-net`: the user-mode network: a virtio-net card in front of a
  smoltcp stack that plays the guest's gateway, DNS server and DHCP
  server, decides every query, connection and datagram by the policy, and
  relays them over host sockets; and the model traffic gate: the session's
  CA, the two TLS legs, and the observer that reads HTTP and the model
  APIs.
- `boxcar-vsock`: virtio-vsock: a port of Cloud Hypervisor's connection
  state machine and Unix-socket muxer behind a device of boxcar's own, the
  rules for what may connect, and the VMM's internal ports.
- `boxcar-audit`: the hash-chained audit log: the sink every producer
  holds, the one writer, checkpoints, the reader, live subscriptions,
  verification, the reconciler, and the OTLP and OCSF exports.
- `boxcar-proto`: the types both sides share: the audit records and their
  chain, the control protocol, the guest control channel, the sensor
  stream, field limits, and the redaction scrub. The guest init builds it
  without its `hash` feature (blake3, which builds C code).
- `boxcar-policy`: policy files: the TOML model, its parser, what a file
  compiles to (the network policy and the path rules), and the built-in
  profiles.

The guest side, packed into the initramfs:

- `boxcar-init`: the guest's PID 1, a static musl binary.
- `boxcar-sensor`: the guest sensor, which loads the eBPF programs and
  streams ring 1 to the VMM over vsock.
- `boxcar-sensor-ebpf`: the eBPF programs, built for `bpfel-unknown-none`
  on a pinned nightly by `boxcar-sensor`'s build script. It is a crate
  apart, with its own lock file, outside the stable workspace.
- `boxcar-sensor-common`: the `no_std`, `repr(C)` events the programs hand
  the sensor through the kernel's ring buffer.

For building and testing:

- `boxcar-testreg`: an in-process OCI registry for the tests.
- `xtask`: `cargo xtask` builds the guest kernel and the initramfs (init
  and the sensor), fetches a root filesystem, builds and checks the
  sensor's eBPF lane and the kernel type bindings its programs read,
  writes the protocol schemas, and runs the KVM-gated suites
  (`test-kvm`).

## One process

A session is one `boxcar run` process. The VMM, its devices, the network
stack and the gate, the audit writer, the reconciler and the control
socket all run in it, as threads. It runs no other program. In order, it:

1. Checks every flag, loads the policy, and finds the image in the cache
   or pulls it, before the session exists: a refused flag leaves nothing
   behind.
2. Makes the session's id, its CA when the policy has an `inspect` line,
   the session directory under the audit directory (the log, the image's
   copy, the default workspace) and the state directory (the sockets).
3. Applies the Landlock domain on the main thread, before any thread of
   its own starts (see [Confinement](#confinement)).
4. Blocks the stop signals and `SIGWINCH`, so every thread started later
   inherits the mask and the signals are read from signalfds; on a
   terminal, starts `job-control`.
5. Starts the audit writer, copies the image's tree for the session (or
   takes `--rootfs`), and starts the reconciler.
6. Builds the VM (`Vmm::new`): KVM, guest memory, the kernel and the
   initramfs, the console's writer, the legacy devices, a virtio-fs device
   per share, the network card, the vsock device with the VMM's services
   on its internal ports, the kernel command line and the vCPUs. Then it
   installs the seccomp filter, records `vmm.start` and `policy.loaded`,
   and binds the control socket.
7. With the vsock device, attaches itself to the session's terminal
   (stdout, stdin, the terminal's size) before the guest runs, so it has
   the session's output from the first byte.
8. Runs the VM (`Vmm::run`): starts the vCPU threads, last, and runs the
   main loop on the main thread until something stops the VM, then the
   stop sequence.
9. Waits for the session's last output to reach stdout, gives the
   reconciler up to 5 s to finish, closes the audit log, and exits with
   the code the stop gives: the session's own when its end stopped the
   VM, and 3 whenever the audit log failed.

## Threads

Every thread is named where it is started; `ps -T` and `top -H` show the
names, cut by the kernel to their first 15 bytes (`fs-workspace-hash0`
shows as `fs-workspace-ha`).

| Thread | Started by | When | Owns, does |
|---|---|---|---|
| main (`boxcar`) | | The process | The steps above; then the main loop, one `EventManager` on the stop triggers (the stop latch, the i8042 reset, the stop signals' signalfd, each vCPU's exit eventfd, the audit writer's failure eventfd), the timer that expires live policy exceptions, and, in a `--no-vsock` session on a terminal, the console's input; then the stop sequence. Records `vmm.start`, `policy.loaded` and `vmm.stop`. |
| `job-control` | main | Before the audit log starts, when stdin is a terminal | `SIGTSTP` and `SIGCONT`, from a signalfd: gives the terminal back on a stop, takes it again on a continue in the foreground. |
| `audit-writer` | main | After the Landlock domain | The log: every record's seq, timestamps and hash, the segments and the checkpoints; subscriptions and the chain's head. |
| `reconcile` | main | After the writer, before the VM is built | Reads the log from seq 1, writes `finding` and `span.effects` back into it, keeps the span index. |
| `console` | main, in `Vmm::new` | As the VM is built | Drains the serial console's ring to stdout or the console's log. |
| `fs-<tag>-hash<N>` | main, in `Vmm::new`; a vCPU thread, when a device is activated again after a reset | Two per share | Hashes a closed file whose handle wrote, created or truncated it, opened again beneath the share's root, and records its `fs.close`. |
| `gate-observe` | main, in `Vmm::new` | When the policy has an `inspect` line | Reads the inspected flows' plaintext: `http.*`, `llm.*`, `tool.*`. |
| `dump` | main, in `Vmm::new` | With `--dump` | Writes `frames.pcap`. |
| `guest-ctl-sync` | main, in `Vmm::new` | With the vsock device | Pings init once the session's config has gone, then every 10 s. |
| `control-accept` | main, in `Vmm::new` | Once `vmm.start` is recorded | Accepts on `control.sock`, checks each peer's uid, records `control.connect`. |
| `pty-stdout` | main | With the vsock device, before the guest runs | Writes the session's output to stdout, as the PTY hub's primary client. |
| `pty-stdin` | main | With the vsock device, when stdin goes to the session (a terminal, no command, or `--stdin`) | Sends stdin to the session; on a terminal, Ctrl-] twice stops the VM. |
| `winch` | main | With the vsock device, when stdin is a terminal | Gives the session's terminal the host terminal's size on each `SIGWINCH`. |
| `vcpu<N>` | main, in `Vmm::run` | Last, one per vCPU, from `vcpu0` | `KVM_RUN` in a loop; its port and MMIO exits go to the devices on the buses. A device the guest's driver activates is activated on it. |
| `fs-<tag>-q<N>` | a vCPU thread | When the guest activates the share's virtio-fs device: one per request queue, the smaller of the vCPU count and 4 (`q1` serves the high-priority queue too) | Serves FUSE requests through `AuditFs`: the path rules, the host filesystem, `fs.*`. |
| `net` | a vCPU thread | When the guest activates the network card | The stack: frames both ways, ARP, DHCP, DNS, every policy decision, the TCP and UDP relays and their host sockets, the gate's TLS legs; `net.*`. |
| `vsock` | a vCPU thread | When the guest activates the vsock device | The muxer: guest connections, the host socket, the allowlisted ports, and the internal ports' services; `vsock.*`. |
| `guest-ctl-rx`, `guest-ctl-tx` | the `vsock` thread | When init connects to port 1024 | Reads init's lines (`session.started` and `session.exited`, recorded as `session.start` and `session.exit`; the pongs that become `sync`); writes the VMM's (the session's config, pings, resizes, signals, a shutdown). |
| `pty-hub` | the `vsock` thread | When init connects to port 1025 | Reads the session's terminal into a 256 KiB scrollback and every client's queue; writes the clients' input to it. |
| `sensor-rx` | the `vsock` thread | When the sensor connects to port 1026 | Reads the sensor's frames and records them as ring 1 (`proc.*`). |
| `control-conn` | `control-accept` | One per served connection | The connection: the hello, the framing, the rate limit, and every op, which runs on this thread. |
| `audit-forward` | `control-conn` | One per `audit.subscribe` | Forwards a subscription's records into the connection, at the client's pace. |
| `pty-attach` | `control-conn` | One per `pty.attach` | Writes the session's output to the attached client; the connection's own thread carries what the client types. |
| `graceful-stop` | `control-conn` | A graceful `stop` while a session runs | Stops the VM if the guest has not reset within the grace plus 3 s. |
| `tell` | main | Each line said once the VM has stopped, and on an early error | Writes one line to stderr and is waited for at most 250 ms, so a stalled stderr cannot keep the process from exiting. |

A `kvm-tests` build of `boxcar` has one more, `seccomp-trip`, with which
the gated tests make a call off the seccomp allowlist.

- **Devices.** A device's threads live with its activation: when the
  guest's driver resets the device, or the VM stops, they are stopped and
  joined, and the next activation starts them again. Each waits on its
  queues' eventfds and a kill eventfd with an `EventManager` of its own.
  The guest's queue notifications reach them through KVM's ioeventfds and
  their interrupts reach the guest through irqfds, with no vCPU thread in
  between.
- **The vCPUs never wait on the host's output.** The UART writes into a
  bounded ring that `console` drains; when the ring is full the oldest
  bytes are dropped and counted (`vmm.stop`'s `console_dropped_bytes`).
- **The session waits on `boxcar run`, never on a viewer.** While
  `pty-stdout` is too far behind, the PTY hub stops reading the guest, and
  the session waits on its terminal. A viewer that falls behind
  (`pty.attach`) is detached instead.
- **What passes between threads outside the log**, in memory only: each
  model call's arguments as sent (`gate-observe` to `reconcile`), each
  argv `--scrub-argv` changed, as run (`sensor-rx` to `reconcile`), and
  the span index (`reconcile` to `span.list`). None of it is recorded.

## The two rings

Every record says which ring it comes from (`ring`) and what made it
(`src`). Ring 0 is what the host observes from outside the guest; ring 1
is what the guest reports from inside.

**Ring 0.** Everything that leaves the guest goes through a device the VMM
serves, and the VMM records it there, in code the guest cannot change:

- **Files.** The root share and the workspace are virtio-fs, served
  in-process by `AuditFs` on the `fs-<tag>-q<N>` threads. There is no DAX
  window, so the guest reaches file data only through FUSE requests; the
  guest's page cache can serve a repeated read without one. Opens, closes
  (with the bytes read and written and the file's hash) and every change
  are recorded; each read and write is too only at `--audit-level
  verbose`. Each operation is recorded (`fs.*`) with the guest thread, uid
  and gid the FUSE header carries.
- **The network.** The guest's TCP ends in the stack the `net` thread
  owns, and its UDP goes through it by NAT. The stack decides each query,
  connection and datagram before it is answered, and records the decision
  (`net.*`). For a destination an `inspect` line names, the stack ends the
  guest's TLS itself and `gate-observe` reads a copy of the plaintext:
  `http.*`, and for the model APIs it knows, `llm.*` and `tool.*`, whose
  tool calls open and close spans.
- **vsock.** Every connection the `vsock` thread decides, from either
  side, is recorded (`vsock.*`).
- **The process's own records.** `vmm.start` and `vmm.stop`, `policy.*`,
  `control.*`, the clock pairings (`sync`), the writer's `checkpoint`s,
  and the reconciler's `finding` and `span.effects`.

The policy is enforced at the same places: the stack decides the network,
`AuditFs` refuses what the path rules deny before a request reaches the
host filesystem, and the vsock device lets a guest port through to the
host only when it is allowlisted. `policy.update` replaces the views those
threads read; the `net` thread is woken to end at once what the new policy
denies.

Ring 0 does not depend on the guest's cooperation. A guest that silences
its sensor still reaches no file and no host but through the VMM. The
audit directory may be neither a share nor inside one, so the guest cannot
reach the log that records it.

**Ring 1** is best effort:

- **The sensor**, over vsock port 1026 to `sensor-rx`: `proc.*`. For the
  processes in the session's cgroup, their lineage (exec with its argv,
  fork, exit), their connections with the 4-tuple, `memfd_create`, sampled
  opens, and the size and time of TLS writes and reads in runtimes that
  export OpenSSL's functions; for anyone, the sensor's refusals of `bpf()`
  and of signals to itself (`proc.lsm_deny`); a heartbeat every second;
  and what attached (`proc.sensor_status`).
- **Init's reports**, over the guest control channel to `guest-ctl-rx`:
  `session.start` and `session.exit`. They come from inside the guest, so
  they are ring 1.

Ring 1 is corroboration, not the record. The guest can silence it, and
the silence shows: the heartbeats stop, `boxcar status` says the sensor is
`silent`, and the reconciler writes a `sensor_silence` finding. With
`--no-sensor` or `--no-vsock` there is no sensor.

## Into the log

Every producer holds a clone of one `AuditSink` and hands it
`Submission`s: the ring, the subject, the payload, a span when there is
one, and a priority. They go over one bounded channel (65,536 entries) to
`audit-writer`, the only place records are made.

- The writer stamps `ts_host_ns` and `ts_mono_ns`, assigns the next `seq`,
  links the record to the one before (`prev`), hashes it with blake3, and
  appends it as one line to the current segment. It drains the channel in
  batches and flushes after each. `ts_host_ns` is the one timestamp that
  joins the rings; the sensor's records carry the guest's clock too
  (`ts_guest_ns`), and `sync` records pair the two clocks.
- A record that must not be lost waits for room: its producer is held,
  the record is never dropped. That is every record but the ones that may
  be sampled (`fs.read`, `fs.write` and `fs.readdir`, which only
  `--audit-level verbose` records, and `net.drop`), which are dropped when
  the channel is full and counted in the next checkpoint's `dropped`. The sensor's
  stream is held back the same way, down to the guest, whose kernel ring
  buffer counts what it cannot place.
- A `checkpoint` is a record in the chain: how many records came since the
  last one, the drops, and a blake3 root over their hashes. One comes
  every 1024 records or 2 s, when a 256 MiB segment is sealed, and at
  close; each is synced to disk before `checkpoints.jsonl` lists it.
  `vmm.stop`, `proc.lsm_deny` and findings scoring 70 or more are synced
  at once.
- Subscriptions (the reconciler's, `audit.subscribe`'s) and requests for
  the chain's head (`audit.verify`) travel in the same channel, between
  records. The writer never waits on a subscriber: one that falls behind
  is dropped from the live stream and catches up from the files.
- A write that fails ends the writer. From then on every sink refuses,
  and the writer's failure eventfd wakes the main loop, which stops the VM
  (`vmm.stop` reason `audit_failed`). The writer cuts the log back to its
  last consistent record, and `boxcar run` says why and exits 3.

At the end, `boxcar run` closes the writer after the VM's stop sequence
and the reconciler: it drains every accepted record, writes a last
checkpoint and syncs.

## The reconciler

`reconcile` subscribes to the log from seq 1, as any reader would, and
writes back into it, as ring 0 with `src` `reconciler`:

- It joins the rings: a filesystem effect to the process whose thread it
  names, by ring 1's fork and exec records; a TCP flow to the process
  whose `proc.tcp_connect` carries its 4-tuple; across both, by
  `ts_host_ns`.
- It writes a `finding` when a rule fires, naming the rule and listing
  the records it read as evidence, by seq and ring.
- It keeps the session's tool spans: the gate's `tool.open` opens one,
  the `tool.close` in the agent's next request closes it, and the
  processes and effects in between are attributed to it and written as
  `span.effects`. Its index is what `span.list` (`boxcar spans`) reads.

It ends at `vmm.stop`, after a last pass, or when `boxcar run` asks. The
rules and the joins are in [reconciler.md](reconciler.md).

## Stopping

The first stop trigger decides how the run ends: the guest's reset (init
reboots once the session has ended) or shutdown, a vCPU error, `SIGINT`,
`SIGTERM`, `SIGHUP` or `SIGQUIT`, Ctrl-] twice on the terminal, the
control socket's `stop`, or the audit writer's failure. A graceful `stop`
asks init to end the session first, and `graceful-stop` stops the VM if
the guest has not reset in time.

The main thread then runs the stop sequence, in an order that puts every
record in the log:

1. Tells the control clients the VM is `stopping`.
2. Kicks every vCPU out of `KVM_RUN` and joins its thread.
3. Resets the devices: each virtio-fs device joins its workers, waits for
   the hashes under way and records an `fs.close` for every file the guest
   left open; the `net` thread records the end of every flow and is
   joined, then `gate-observe` and `dump`; the `vsock` thread records the
   end of every connection and is joined.
4. Waits up to 1 s for the guest control channel's threads, so that a
   report init sent last is recorded; closes the PTY hub's stream; lets
   `console` drain for up to 2 s.
5. Marks the VM `stopped` and shuts the control server down: each client
   hears `stopped` and is disconnected, with no wait on any of them.
6. Records `vmm.stop` and gives the terminal back.

## Confinement

`boxcar run` confines its own process two ways. Both are recorded in
`vmm.start` as `hardening`.

**Landlock** (`--landlock enforce`, the default, or `off`; also
`BOXCAR_LANDLOCK`). The main thread applies the domain before it starts
any thread of its own, so every thread inherits it. A thread from before
it (a resolver the registry client left running after a pull) is confined
too: on Landlock ABI 8 and later by `LANDLOCK_RESTRICT_SELF_TSYNC`;
before that, `boxcar run` waits for it to end, and fails if it does not.
The domain allows:

- everything but running a program beneath the session directory, the
  state directory, the shares as given (`--rootfs`, `--workspace`) and a
  `--dump` directory;
- reading beneath the cached image's tree, and reading the kernel and the
  initramfs;
- writing a `--console-log` file outside the state directory;
- reading, writing and `ioctl`s on `/dev/kvm`;
- reading `/etc/resolv.conf` with a network, `/proc/self/mountinfo` with
  shares, and the few files glibc reads on its own;
- removing the session's and the state directories when they are empty.

It allows no TCP bind, and no signal or abstract Unix socket outside the
domain. A kernel without a usable Landlock (none, or only ABI 1) runs the
session without it, with a warning: `unsupported`. A kernel that enforces
every right boxcar handles is `full`, one that enforces only some of them
`partial`.

**seccomp** (`--seccomp enforce`, the default, `log` or `off`; also
`BOXCAR_SECCOMP`). One allowlist for the whole process, measured over the
gated suites and completed from the code, is installed once the VM is
built and before `vmm.start` is recorded, with `SECCOMP_FILTER_FLAG_TSYNC`, so the threads running then
and every thread started later have it. On top of it, each worker thread
started once that list is in confines itself to its role's list as its
first act (the net thread keeps
sockets and loses files; a virtio-fs queue keeps files and loses sockets;
the audit writer has the log's files; the control socket's threads have
their socket, the log's files and the threads they start), through a hook
set before `boxcar run` spawns anything; a role's list is a subset of the
process list, and the kernel takes the strictest answer. The vCPU threads,
which start the device workers at the guest's activation, and the main
thread keep the process list, since a filter is inherited by the threads a
thread starts; so do the threads started before the VM was built (the
audit writer, the control socket's acceptor, the terminal's), since
`TSYNC` installs the process list only while no thread's filters differ
from the installer's, and the device workers, the guest channels, the
connections and the subscriptions all start after it. `vmm.start`'s
`hardening.seccomp_threads` says the workers are confined so. A few calls are allowed only
with some arguments: `ioctl` by request, `socket` and `socketpair` by
family, `clone` for threads only, `prctl` for `PR_SET_NAME` and
`PR_SET_NO_NEW_PRIVS`, `seccomp` to add a filter to the calling thread
alone (which only narrows), `tgkill` to this process. A second filter answers `clone3` `ENOSYS`, since a filter
cannot read its flags, and glibc falls back to `clone`. The list is built
for x86_64 glibc. Under `enforce` a call off the list kills the process:
a crash, with no `vmm.stop` (see *Order and durability* in
[audit-events.md](audit-events.md) for what `boxcar audit verify` then
says). `log` has the kernel log such a call and lets it go ahead.

Guest memory is kept out of the process's core dumps.

## The control socket

`<state>/control.sock`, where the state directory is
`$XDG_RUNTIME_DIR/boxcar/<session_id>/`, or
`/tmp/boxcar-<uid>/<session_id>/` without a usable `XDG_RUNTIME_DIR`: mode
0600 in a 0700 directory. `Vmm::new` binds it once `vmm.start` is
recorded, so a client can connect while the guest boots;
`boxcar run --ready-fd N` says where it is once it is bound. The same
directory holds the vsock device's host socket, `vsock.sock` (a host
process reaches a guest port with `CONNECT <port>`), is where a guest
connection to an allowlisted port is sent (`vsock.sock_<port>`), and, in
vsock mode, holds the serial console's `console.log` unless
`--console-log` or `--console-stdout` says otherwise.

- `control-accept` reads each peer's credentials: only the VMM's own uid
  is served, and both outcomes are recorded (`control.connect`).
- Each served connection gets a `control-conn` thread: JSON lines of at
  most 1 MiB, a rate limit, and the ops `status`, `stop`, `pty.attach`,
  `pty.watch`, `pty.resize`, `audit.subscribe`, `audit.verify`,
  `policy.get`, `policy.update` and `span.list`. Nothing it writes blocks:
  lines go into an outbox, so the server can queue an event on any
  connection, and shut them all down, without waiting on a client.
- The clients are `boxcar status`, `stop`, `attach`, `events`, `policy`
  and `spans`, and `boxcar audit verify --control`.

## The guest

What runs in the guest, and how it reaches the VMM; the order it starts
in is [boot.md](boot.md)'s.

- **Devices.** COM1 (the console) and the i8042, and in fixed MMIO slots
  one virtio-fs device per share (`root` at `/`, `workspace` at
  `/workspace`), the network card and the vsock device (the guest is CID
  3). The kernel starts `/init` from the initramfs, which carries
  `/boxcar-sensor` beside it.
- **Init** is a single-threaded PID 1. With shares and the vsock device
  (the default), it mounts the shares and starts the sensor, which it
  waits for, for a bounded time, before the session starts, so the
  session's first exec is seen. It connects the guest control channel
  (port 1024), says `hello`, and takes the session's config: the command,
  its user, environment, working directory and terminal size, and the
  session's CA when the gate inspects. It runs the session on a PTY of its
  own, as the invoking user's uid and gid, and relays the PTY over port
  1025 to `pty-hub`. It reports the session's start and end and serves
  the host's requests (a resize, a signal, a ping, a shutdown). Once the
  session has ended and the VMM has taken the report and the last output,
  init reboots, and the guest's reset stops the VM. With `--no-vsock` the
  session runs on the serial console instead; a VM with no shares prints
  a marker and reboots.
- **The sensor** runs as root in a cgroup apart from the session's, with
  its programs filtered to the session's cgroup. It connects to port
  1026, says what it attached, and streams `proc.*` frames with a
  heartbeat every second. It is one event loop on `poll(2)`, with one
  helper thread, `tls-resolve`, that reads programs' files for the
  symbols the TLS probes attach to.
- **The internal ports** (1024 `boxcar.ctl`, 1025 `boxcar.pty`, 1026
  `boxcar.sensor`) take a connection only from a guest port below 1024,
  which only a process with `CAP_NET_BIND_SERVICE` can bind (init and the
  sensor it starts, never the session), and each takes one connection in
  the VMM's life: a later one, after the guest re-activated its vsock
  driver, is refused as `reactivated`. Any other guest port reaches the
  host only when it is allowlisted (`--vsock-allow`, `policy.update`).
