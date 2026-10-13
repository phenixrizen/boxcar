# The guest's network

What the user-mode network in the runtime does, what it records, and what
it does not do. The protocol and record fields are in
[control-protocol.md](control-protocol.md) and
[audit-events.md](audit-events.md); the policy rules are described in the
README's "Networking and policy".

## The network the guest sees

- One virtio-net card (slot 2), when the VM has shares; `--no-net` takes
  it away, and `--no-fs` has none. The guest is `10.0.2.15/24` at
  `02:62:6f:78:00:01`; `10.0.2.2` at `02:62:6f:78:00:02` is its router,
  DNS server and DHCP server (a 24 h lease, hostname `boxcar`), all played
  by the runtime. Proxy ARP answers for every other address on the /24.
  The kernel command line carries the address (`ip=`), and init points
  `/etc/resolv.conf` at the gateway.
- IPv6 is dropped and counted (`net.drop{reason:"ipv6"}`); the guest
  disables it. ICMP echo to the gateway is answered; every other ICMP is
  dropped and counted.
- DNS queries to the gateway are forwarded to the host's resolvers
  (`/etc/resolv.conf`, or `--dns`), with AAAA answers stripped, a 5 s
  timeout (SERVFAIL), a cache of 4096 answers that the policy's domain
  rules are matched against, and NXDOMAIN for a name the policy denies.
- TCP: the guest's SYN is decided before it is answered (`net.connect`); an
  allowed one starts a host connect, and only when that succeeds does the
  guest get its SYN-ACK. A connect that takes over 10 s, or fails, resets
  the guest's side (`net.close` `timeout`, `refused`, `unreachable`,
  `error`). A flow a domain rule allowed is gated: its first bytes (up to
  16 KiB, 5 s) must show the name as a TLS server name or an HTTP `Host`
  that a domain rule allows on that port, or both sides are reset
  (`net.tls{verdict:"deny"}`, `net.close{reason:"gate"}`). Bytes then move
  both ways with back-pressure: a host that stops reading closes the
  guest's window, a guest that stops reading stops the host read. A guest
  silent for 60 s while waited on ends its flow (`timeout`).
- Inspection (`--inspect RULE`, `inspect` lines in a policy file): a
  connection an allow rule admitted, whose first bytes show a name (or,
  for a network rule, whose destination) an `inspect` line names, is
  watched. A TLS connection ends in the runtime: the real host is reached
  with the runtime's own TLS and checked against the host's trust store,
  the guest gets a certificate for the name signed by the session's CA
  (init puts the CA in the guest's store and names it in the session's
  environment), and the plaintext is relayed unchanged both ways with a
  copy to the observer (`net.inspect`). A plain HTTP connection is
  observed as it is. A host the store does not vouch for, a guest that
  refuses the leaf, or handshakes slower than the gate's 5 s end the
  connection with nothing relayed (`net.inspect` says which,
  `net.close{reason:"inspect"}`). The agent keeps its own credential;
  nothing is injected. A connection read for inspection that shows
  neither TLS nor HTTP is relayed untouched after the gate's limit. What
  the gate records, and `--dump DIR` for looking at the traffic by hand,
  are in [gate.md](gate.md).
- UDP: the first datagram of a 5-tuple is decided (`net.udp`) and gets a
  connected host socket; a domain `allow` admits no UDP (nothing in a
  datagram shows a name: `builtin:udp-needs-cidr`), so UDP needs a CIDR
  rule. Mappings idle for 60 s are closed (`idle`); replies over 1472
  bytes are dropped (no fragmentation).
- Bounds: 4096 TCP flows (the idlest evicted for a new one, `evicted`),
  256 host connects under way (a SYN past that is dropped for the guest to
  retry), 1024 UDP mappings, 4096 cached DNS answers, 256 queries in
  flight. Frames the guest does not take are dropped and counted
  (`queue_full`); the net thread wakes every millisecond while the guest
  posts no receive buffers and the stack has frames for it (bounded).
- Live policy changes (`boxcar policy`, `policy.update`): the new policy
  decides the next query, connection and datagram, and the stack's next
  poll ends what is open and now denied, decided as it first was, on the
  names the guest knew the destination by then: TCP flows and connects
  under way are reset, UDP mappings closed, each `net.close{reason:
  "policy"}`. What the new policy still allows is untouched. The vsock
  allowlist is read at each guest connection request; connections already
  made to a port taken off it stay open.

## Known behaviour

- On a terminal, Ctrl-C reaches a `-- CMD` session (the terminal is raw);
  Ctrl-] twice stops the VM.
- Piped input with `--stdin` whose end-of-file reaches the guest before
  its shell is ready can hang that shell (`printf ... | boxcar run --stdin
  -- /bin/sh`): the shell starts, finds its input at end-of-file, and some
  shells wait on the terminal instead of exiting. Give the shell a command
  (`-- /bin/sh -c '...'`) or a script instead.
- In vsock mode the kernel's and init's messages go to `<state>/console.
  log` (`--console-log` to put them elsewhere, `--console-stdout` to see
  them interleaved with the session).
- `--no-vsock` is M1's console session: the session runs on the serial
  console, stdin is not forwarded for `-- CMD`, the run exits 0 whatever
  the command's exit status (the console shows it), and the network and
  the control socket work as usual.
- Policy flags (`--allow`, `--deny`, `--policy-file`, `--dns`) are refused
  with `--no-fs` and no `--net`: there is no network to apply them to.
- An attach client (`boxcar attach`, a `pty.attach` connection) that lets
  1 MiB of output pile up, or takes nothing for 30 s, is detached by the
  runtime (`pty.detached`, reason `slow`; `boxcar attach` exits 3). A
  `boxcar attach` stopped with Ctrl-Z or `kill -TSTP` for that long is
  detached when it continues; attach again.
- An `audit.subscribe` client that reads slowly lags (`audit.lagged`) and
  recovers from the log; one that takes nothing for 30 s is disconnected
  and reconnects with `from_seq`.
- `vsock.close` counts payload bytes that reached the other side; bytes
  the runtime still held for the guest (up to 64 KiB a connection) when
  the guest reset its vsock driver are neither counted nor reported.
- The guest cannot reach the host's own addresses, the private ranges, or
  `0.0.0.0/8` unless a rule names exactly that address or range; the
  gateway `10.0.2.2` serves DNS and DHCP only.
