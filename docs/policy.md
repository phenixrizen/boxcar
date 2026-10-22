# The session's policy

What a session may reach, write and run, and how boxcar holds it to that:
the two forms a policy takes, the policy file and its built-in profiles,
the network rules, the path and program rules enforced at the shares, and
the changes a control client can make while the session runs. The network
in depth is [networking.md](networking.md) and the model traffic gate
[gate.md](gate.md); the records' fields are in
[audit-events.md](audit-events.md), the control socket's `policy.get` and
`policy.update` in [control-protocol.md](control-protocol.md), and the
findings a refusal makes in [reconciler.md](reconciler.md).

## Two forms

- **A line policy.** `boxcar run --allow RULE`, `--deny RULE` and
  `--inspect RULE`, and `--policy-file PATH`: a file of one rule a line,
  `allow RULE`, `deny RULE`, `inspect RULE`, and at most one `default
  allow` or `default deny` (deny when none says). `#` starts a comment;
  blank lines are ignored. A line policy is about the network only: it
  checks no path and refuses no program. Its file has no size limit.
- **A policy file.** `boxcar run --policy FILE|NAME`: TOML, which also says
  what the session may write and run. NAME is a built-in profile
  (`agent-isolate`, `agent-isolate-strict`); anything else is a path, so
  `./agent-isolate` is a file of that name. `--deny`, `--allow` and
  `--inspect` add to it, after its own rules, as they add to a line file.

Which go together:

- `--policy` and `--policy-file` conflict.
- `--allow`, `--deny`, `--inspect`, `--policy-file` and `--dns` (where the
  guest's DNS queries are forwarded) conflict with `--no-net`, and a VM
  with no network (`--no-fs` without `--net`) refuses them with exit 2.
- `--policy` needs no network: a policy file is about more than the
  network.

A rule that does not parse refuses the run with exit 2 before the session
exists, saying where: `--policy-file PATH line N: ...`, `--allow "RULE":
...`, or `--policy PATH:LINE:COLUMN: ...`.

`boxcar policy profile NAME` prints a built-in profile byte for byte, the
text `--policy NAME` reads; it needs no session, and a name there is no
profile of exits 2. A profile is a starting point for a file of one's own:

```bash
boxcar policy profile agent-isolate-strict > team.toml
boxcar run ... --policy ./team.toml
```

## The policy file

```toml
version = 1                     # required, and 1

[egress]
default = "deny"                # or "allow"; deny when absent
allow = ["api.example.com:443", "198.51.100.0/24:22"]
deny = ["*.ads.example"]
inspect = ["api.example.com:443"]
max_dns_qps = 20                # optional, 1 to 10000

[fs]
writable = ["/workspace/**", "/tmp/**"]  # the default when absent
denied = ["/workspace/.env", "**/secrets/*"]
indicators = ["/var/log/**"]

[exec]
deny = ["**/nc", "/usr/bin/{socat,telnet}"]

[spans]
keep_tool_args = true           # the default

[record]
scrub_argv = false              # the default
```

`version` is required and must be 1. Every table, and every key in one, is
optional; a key the format does not have is refused wherever it is.

- `[egress]`
  - `default`: the verdict when no rule matches, `"allow"` or `"deny"`;
    `"deny"` when absent.
  - `allow`, `deny`: targets, written as for `--allow` (see *The network*).
    Every deny comes before every allow, whatever the order in the file, so
    a deny of a target wins over an allow of it.
  - `inspect`: targets whose connections the gate watches once an allow
    admitted them. They decide no verdict.
  - `max_dns_qps`: the guest's DNS queries a second, 1 to 10000; no rate
    when absent.
- `[fs]`
  - `writable`: what a change must name. When absent, `["/workspace/**",
    "/tmp/**"]`: the workspace, and `/tmp`, which is the root share's (init
    mounts no tmpfs there); the rest of the root share is read-only. A
    `writable` the file gives replaces the default whole, and `writable =
    []` makes nothing writable.
  - `denied`: what may not be looked up, opened, created or changed at all.
  - `indicators`: paths added to those the reconciler's `indicator_removal`
    rule watches.
- `[exec] deny`: program files that may not be run, or opened at all. On
  the shares, by path, through AuditFs; and, through the sensor, by name
  wherever the file is: each glob's last component (`**/nc` denies `nc`,
  `/usr/bin/{socat,telnet}` denies `socat` and `telnet`) is refused at
  `execve` with `EPERM` whatever directory holds the file, a copy to the
  guest's tmpfs included, and recorded as `proc.exec_denied`. A last
  component with a wildcard in it (`**/nc*`) is matched on the shares
  only; `policy.loaded` says how many names went to the sensor and how
  many globs stayed with the shares. A copy under another name is not
  stopped by name, and the write that made it is in the log.
- `[spans] keep_tool_args`: `true` keeps a tool call's arguments inline in
  `tool.open` when their JSON is at most 8 KiB. `false` drops them and the
  summary made from them (`args_summary` reads `[arguments not kept:
  keep_tool_args = false]`); `args_b3` stays, and the reconciler still
  compares what ran with the arguments it holds in memory.
- `[record] scrub_argv`: `true` is `boxcar run --scrub-argv`, each
  `proc.exec`'s argv recorded scrubbed. Either one turns it on.

The `[fs]` and `[exec]` lists are globs of guest paths:

- A guest path is the path as the guest sees it: the root share's paths as
  they are, the workspace's under `/workspace`. It is matched as raw bytes,
  and case matters.
- A glob is absolute: it starts with `/` or `**/`. A relative one is
  refused, since it could never match.
- `*` stays within one component and `**` crosses components (`globset`
  with `literal_separator`); `?`, `[...]` and `{a,b}` work as `globset` has
  them.
- For `writable` and `denied`, a glob covers what it names and everything
  beneath it: a path is writable, or denied, when it or any of its
  ancestors matches. `/workspace/secrets` covers the directory and all it
  holds; `/workspace/secrets/**` covers what it holds, not the directory.
  So the default `/workspace/**` makes the workspace's contents writable,
  not `/workspace` itself: a `chmod` of it is `EROFS`.
- `[exec] deny` and `indicators` match the path itself.

Limits: the text at most 1 MiB, UTF-8, and each list at most 1024 entries.
The first thing wrong refuses the whole file, with the line and the column
(both from 1, columns counting characters) of what is wrong: TOML syntax, a
wrong type, an unknown key, a missing or wrong `version`, a target or glob
that does not parse, a DNS rate out of range, a list too long. A
`team.toml` whose third line is `allow = ["ok.test", "exa_mple.com"]`:

```
error: --policy team.toml:3:21: [egress] allow: "exa_mple.com" is not a host name or *.name: labels of a-z, 0-9 and -, 1 to 63 long, 253 in all
```

## The built-in profiles

`agent-isolate` lets an agent reach its model provider (allowed and
inspected), the package registries and the git hosts, and nothing else; it
may write anywhere on its shares. As `boxcar policy profile agent-isolate`
prints it:

```toml
# agent-isolate: an agent, its model provider, its package managers.
#
# The model providers are allowed and inspected: the gate ends their TLS,
# relays the traffic unchanged and records the model calls and the tool
# spans. The package registries and git hosts are allowed on 443, and the
# Debian mirrors on 80 too (apt's default sources are plain HTTP, signed).
# Everything else is denied. The session may write all of its shares: with
# --image the root share is the session's own copy of the image.
version = 1

[egress]
default = "deny"
allow = [
    # Model providers.
    "api.anthropic.com:443",
    "*.anthropic.com:443",
    "api.openai.com:443",
    "chatgpt.com:443",
    "*.openai.com:443",
    # Package registries.
    "registry.npmjs.org:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "crates.io:443",
    "static.crates.io:443",
    "index.crates.io:443",
    "dl-cdn.alpinelinux.org:443",
    "deb.debian.org:443",
    "deb.debian.org:80",
    "security.debian.org:443",
    "security.debian.org:80",
    # Git hosts.
    "github.com:443",
    "*.githubusercontent.com:443",
    "codeload.github.com:443",
    "gitlab.com:443",
]
inspect = [
    "api.anthropic.com:443",
    "*.anthropic.com:443",
    "api.openai.com:443",
    "chatgpt.com:443",
    "*.openai.com:443",
]
max_dns_qps = 20

[fs]
writable = ["/**"]
indicators = ["**/.*_history", "/var/log/**", "/etc/ld.so.preload", "/root/.ssh/**"]
```

Its `indicators` are the reconciler's own paths, written as globs. Since it
inspects the model providers, a session under it makes its own CA.

`agent-isolate-strict` has the same `[egress]` and `indicators`, keeps
writes to `/workspace` and `/tmp`, so a package install fails, and refuses
the usual network tools, Debian's `nc.openbsd` and `nc.traditional` among
them. Its tables that differ:

```toml
[fs]
writable = ["/workspace/**", "/tmp/**"]
indicators = ["**/.*_history", "/var/log/**", "/etc/ld.so.preload", "/root/.ssh/**"]

[exec]
deny = ["**/nc", "**/nc.openbsd", "**/nc.traditional", "**/netcat", "**/ncat", "**/socat", "**/telnet"]
```

## The network

`[egress]`, like a line policy, decides the guest's DNS queries, TCP
connections and UDP flows. A target is one word:

- `name[:port]`: that name;
- `*.name[:port]`: every name under it, not the name itself;
- `address[:port]`: one IPv4 address;
- `address/prefix[:port]`: an IPv4 network, with no host bits set.

Without a port a rule covers every port. Names match without regard to case
or a trailing dot. A target that looks numeric must be an address:
`192.168.1.300` is refused, not taken for a name that never matches.

A connection is decided in this order:

1. Denied unless an `allow` rule names exactly that address (a `/32`, and
   this port if the rule has one): one of the host's own addresses. A
   domain rule, a wider network or an allowing default does not lift this.
2. Denied whatever the rules say: the guest's own network (`10.0.2.0/24`),
   `0.0.0.0/8`, multicast and the reserved range (`224.0.0.0/4`,
   `240.0.0.0/4`).
3. Denied unless an `allow` rule names exactly that range (and this port,
   if the rule has one): `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`.
4. The rules, the first that matches deciding: the policy's own (a policy
   file's denies, then its allows; a line file's in its order), then each
   `--deny`, then each `--allow`. So a `--deny` wins over an `--allow` and
   the default, not over an allow the policy itself has.
5. The default.

- **Domain rules.** A domain rule admits only clients that say the name: a
  connection it allowed is held until its first bytes show a TLS server
  name or an HTTP `Host` that a domain rule allows on that port, or both
  sides are reset. A protocol that shows no name (SSH, SMTP) needs a network
  rule, and so does UDP: a domain `allow` admits no datagram
  (`builtin:udp-needs-cidr`).
- **DNS.** Walking the rules in order, the first domain rule that matches a
  name decides if it allows (on any port) or denies on every port; a deny
  on one port does not stop the name resolving. With none, the default. A
  name the policy denies is answered NXDOMAIN by the gateway, recorded
  `net.dns{verdict:"deny"}`, and nothing goes upstream.
- **The DNS rate.** `max_dns_qps` gives the guest a burst of that many DNS
  messages, then one each `1 s / max_dns_qps`. Every message counts,
  malformed or not, before anything else is decided; one over the rate is
  answered REFUSED, recorded `net.dns{verdict:"deny", rule:"dns_rate"}`,
  and goes no further. Only a policy file sets a rate, and it is the
  session's: no live change lifts it.
- **Inspection.** An `inspect` target decides nothing. A connection an
  allow admitted whose name (or, for a network target, destination) an
  `inspect` target matches has its TLS ended in boxcar and its traffic
  recorded; a session with any `inspect` target makes its own CA. An
  agent that pins its provider's certificate cannot be inspected: allow
  its provider without an `inspect` target, and it runs with the flow
  recorded by ring 0 only. What the gate records, and what it never does,
  is in [gate.md](gate.md).

`net.dns`, `net.connect` and `net.udp` record each decision with its
verdict and the rule that decided, as written (a `builtin:` name for a
built-in denial, null for the default); `net.tls` records the gate's
verdict on the name a flow showed. What the network does around the policy
is in [networking.md](networking.md).

## Paths and programs

`[fs]` and `[exec]` are enforced at ring 0, by the runtime's virtio-fs
server, on every request the guest makes of a share, before the request
reaches the host. Only a policy file has them: with a line policy, or none,
nothing is checked at the shares.

- **`denied`**: a lookup, open, create or change naming a denied path is
  refused with `EACCES`. A directory listing still shows the name, but never
  the file's inode or attributes.
- **Outside `writable`**: a change is refused with `EROFS`: a create,
  `mkdir`, `mknod`, `symlink`, `link`, `rename`, `unlink` or `rmdir`; an
  open for writing or with `O_TRUNC`; a write, `setattr`, `fallocate`, or
  an xattr set or removed. Each write is checked as it is made, not only at
  the open.
- **`[exec] deny`**: any open of a matching file is refused with `EACCES`,
  to run it or to read it, so neither the loader (`ld.so /usr/bin/nc`) nor
  a copy (`cp /usr/bin/nc /tmp/x`) runs it; so are its rename and its link.

A denied path is refused with `EACCES` whatever `writable` says. A request
on a file is checked by every name the share knows for it, its hard links
included: it is refused when any name is denied or refused to run, and a
change is allowed only when every name is writable. The guest resolves
symlinks itself, so a rule applies to the file a link leads to, not to the
link's name.

**The boot scan.** Names alone do not hold a file: a hard link made before
the session, or a case variant on a case-insensitive host filesystem, names
it another way. So when `denied` or `[exec] deny` has anything in it, the
shares' host directories are walked once before the guest boots, all shares
as one set, and boxcar notes by host identity (`st_dev`, `st_ino`) every
denied entry (everything beneath a denied directory included), every
directory on the way to one, and every regular file an `[exec] deny` glob
names. With these:

- a reply that would hand the guest a denied file is refused, whatever name
  it came by;
- a create, `unlink`, `rmdir` or `rename` first reads what the name is now,
  by its identity: a denied file is not opened, removed or moved through
  another name, a directory holding one is not removed or moved, and a
  refused program is not opened or moved;
- a denied glob's literal prefix (its components before the first
  wildcard: `/workspace/secrets` for `/workspace/secrets/**`), and every
  ancestor of it, may not be renamed.

The walk follows no symlink and stops at 4,000,000 entries. A directory it
cannot read, or shares past the limit, fail the run before the guest boots,
rather than leave `denied` held by name alone.

**The node-id gate.** While a policy file is in force, a request on a node
id the share never handed the guest is refused (`EACCES`): the guest kernel
is not trusted to send only the ids it was given. A file whose path the
share does not know whole is refused too: `EROFS` for a change, `EACCES`
otherwise.

**Out of reach:**

- `[exec] deny` refuses program files, not the names they are run by. A
  BusyBox applet (`/usr/bin/nc` a symlink to `/bin/busybox`) is BusyBox:
  `**/nc` stops a real `nc` binary but not the applet.
- Only the shares are policed. A program the guest fetches or writes onto
  a tmpfs (`/run`, `/dev/shm`) runs, whatever its name; a refused program
  cannot be copied there, since reading it is refused. The sensor, when
  attached, still reports the exec (`proc.exec`).
- The scan's sets are fixed at boot. What the host makes, links or replaces
  on a share during the session is held by its names alone, the
  literal-prefix guard aside.

With `--rootfs`, init creates `/etc/resolv.conf` on the root share when the
tree has none; under a `writable` that leaves out `/etc` it cannot, and the
guest resolves no names. An `--image` session's copy has the file made
before boot.

Each refusal is one `fs.denied` with `reason: "policy"`, its `op` (`exec`
for an open to run a program), its `errno`, and `rule`: the glob that
refused it, also when the file was refused by its identity under another
name. `rule` is absent for a change outside `writable`, where no glob
matched, and for a node id never handed or a path not known whole. The
request never reaches the host and gets no other record. The reconciler
writes a `policy_denial` finding (score 40) for each, naming the rule:
`exec of /usr/bin/nc was refused by the policy ([exec] deny **/nc)`.

## Changing the policy while the session runs

The control socket replaces the permanent network rules and vsock
allowlist, and grants live exceptions; `boxcar policy` is its client, for
the session `--control` or SESSION_ID names, or the only one running.
Nothing else a policy file says changes: its DNS rate, its path rules
(exceptions aside), its indicators, `[spans]` and `[record]` stay as the
session started.

- `boxcar policy show [--json]`: the permanent policy (version, default,
  allow, deny and inspect rules, vsock ports), then each live exception
  with the seconds it has left.
- `boxcar policy allow RULE`, `boxcar policy deny RULE`: a permanent
  change. RULE goes to the end of its list and out of the other, the whole
  network policy goes back with `policy.update`, and the new version is
  printed (`policy version N`). The policy in force then puts every deny
  before every allow: a line policy whose allows and denies interleave
  reads back in that shape, the same policy only when no allow before a
  deny matches what that deny does.
- `boxcar policy allow RULE --ttl DURATION`: an `egress` exception, RULE
  allowed after the permanent rules. A permanent deny of it still wins: an
  exception opens what the default denies, never what the policy denies by
  name.
- `boxcar policy allow --writable GLOB --ttl DURATION`: a `writable`
  exception, GLOB added to `writable`.
- `boxcar policy allow --exec GLOB --ttl DURATION`: an `exec` exception,
  lifting `[exec] deny` for each name GLOB matches. A file is opened only
  when every name it has that `[exec] deny` matches is lifted; one lifted
  name also lifts the refusal by identity the boot scan recorded.
- `boxcar policy exception ls [--json]`: the live exceptions: id, kind,
  rule, seconds left.

A `writable` or `exec` exception needs shares and a `--policy` file's path
rules; `denied` takes none. A new network policy, or an egress exception's
grant or expiry, decides the next query, connection and datagram, and what
is open and now denied ends at once (`net.close{reason:"policy"}`). The
shares read the path rules at every request, so a handle opened for
writing under a `writable` exception stops writing when it expires.

Exceptions:

- DURATION is `90`, `90s`, `10m` or `1h`, from 1 s to 24 h.
- At most 64 live at once; the 65th is refused until one expires.
- Each grant is its own exception, with an id (from 1 for the session) and
  an expiry of its own: two grants of one rule expire at their own times,
  and a permanent rule the same as an exception's stays when it goes.
- They are kept apart from the permanent policy: `policy.get` reports them
  apart, and an update replaces only the permanent part, so a client that
  writes back what it read never makes an exception permanent.
- Expiry is kept by `CLOCK_BOOTTIME`: a step of the wall clock does not move
  it, and time suspended counts. A timer on the VMM's main loop removes each
  one as it expires.
- A VMM whose hello lists no `policy.exception` grants none: `--ttl` and
  `exception ls` say so and exit 1.

`boxcar policy` exits 0; 1 when the control socket cannot be reached or
refuses the change (a VM without a network card has no network policy; a
65th exception); 2 for a RULE or GLOB that does not parse, checked before
any connection is made, or a profile there is none of.

## What is recorded

- `policy.loaded`: once, right after `vmm.start`, before anything else.
  `source` is `profile`, `file`, or `flags` for a line policy (or none);
  `name` the profile or the path as given; `sha256` the text's (a profile's
  is that of what `boxcar policy profile NAME` prints); `egress_rules` the
  allow, deny and inspect rules, the flags' included; `fs_rules` the `[fs]`
  globs, the default `writable` included; `exec_rules` the `[exec] deny`
  globs.
- `policy.changed{by_pid, version}`: a client replaced the permanent
  policy, or, with `by_pid` 0, exceptions expired.
- `policy.exception{id, rule, kind, ttl_s, expires_ns, by_pid, version}`:
  a client granted an exception; `expires_ns` is by the clock of
  `ts_host_ns`.

`version` is 1 for the policy the session started with, one more for each
update, grant and expiry; the policy's records are made in version order.
The network's decisions, `fs.denied` and the findings are above; every
field is in [audit-events.md](audit-events.md), and the control messages
in [control-protocol.md](control-protocol.md).
