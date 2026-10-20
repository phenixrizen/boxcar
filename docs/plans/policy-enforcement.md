# Enforcing paths and programs, and expiring exceptions (M5 Task 5, #27)

Branch `issue-27`, from `main` at 8f29dbf. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`: section 3 (*Crate boundaries*, *Policy files*, *Live exceptions*), section 4 (focus 5 and 6) and section 6, Task 5. Task 4's plan is `docs/plans/policy-files.md`. Subject: `policy: enforce paths and programs, and expiring exceptions`.

Task 4 made the policy file and put its network half into force. This task puts the rest in force:
- `[fs] writable` and `denied` and `[exec] deny`, at ring 0, by every `AuditFs`;
- `[fs] indicators`, by the reconciler;
- `[spans] keep_tool_args`, by the gate;
- `[record] scrub_argv`, through the same switch as `--scrub-argv`.

Live exceptions sit on top of the permanent policy. Each has a time to live, is recorded when it is granted, and expires on the VMM's event loop. `PolicyFile::not_in_force` and the stderr warning go. Section 8 records the review of this plan and what it changed.

## 1. Where it sits

| File | What |
| --- | --- |
| `crates/boxcar-fs/src/rules.rs` (new) | `PathRules`: the compiled `writable`, `denied`, `exec` deny and exception globs, guest-path matching, the denied globs' literal prefixes, `LiveRules` (the `ArcSwap` every share reads) |
| `crates/boxcar-fs/src/scan.rs` (new) | the boot scan: the host identities of what `denied` and `[exec] deny` name, and the directories that hold denied entries, across every share of the session |
| `crates/boxcar-fs/src/{audit_fs,path_map,device}.rs` | the checks per operation; every name of an inode; `readdirplus` without denied inodes; the node-id gate; `opendir`'s flags |
| `crates/boxcar-policy/src/{model,parse,profiles}.rs` | globs checked by `boxcar_fs::rules`; the strict profile's program names; `not_in_force` goes |
| `crates/boxcar-proto/src/{audit.rs,audit/payloads.rs,control.rs}` | `fs.denied.reason`/`rule`, `policy.exception` (59 kinds), `PolicyUpdateParams.exception`, `PolicyView.exceptions`, the `policy.exception` capability |
| `crates/boxcar-vmm/src/{policy,vmm,lifecycle}.rs`, `control/ops.rs`, `devices/mod.rs` | the permanent policy and the exceptions held apart; compiled views; records under the lock; the expiry timer on the main loop; the session-wide scan |
| `crates/boxcar-audit/src/reconcile/{mod,paths,rules}.rs` | the policy's indicators; a policy refusal's summary |
| `crates/boxcar-net/src/{gate/*,model/*}` | `keep_tool_args = false`: `tool.open` without `args` or the summary made from them |
| `crates/boxcar/src/{cli.rs,cmd/run.rs,cmd/policy.rs}` | the file's `[fs]`, `[exec]`, `[spans]`, `[record]` into force; `policy allow --ttl`, `--writable`, `--exec`; `policy exception ls` |
| `crates/boxcar-fs/tests/policy.rs` (new), `crates/boxcar/tests/{kvm_m5,policy_cli,run_args}.rs` | the table of attempts, the CLI, the gated runs |
| `docs/audit-events.md`, `docs/control-protocol.md`, `docs/plans/2026-10-13-m5-…md` §8 | the records, the protocol, the decisions |

Dependencies: `globset` (already in the workspace) for `boxcar-fs` and `boxcar-audit`, and `arc-swap` for `boxcar-fs`. `boxcar-policy` gains `boxcar-fs`, as the M5 plan's crate boundaries have it, so that one function decides what a path glob is. Nothing else is new.

## 2. Path rules

### What a guest path is

A share serves a guest directory (`FsShareConfig::guest_path`): `/` for the root share, `/workspace` for the workspace. The guest path of a node is that directory joined with the node's share-relative path from `PathMap`:
- `/` + `/etc/x` is `/etc/x`;
- `/workspace` + `/src/a` is `/workspace/src/a`.

Paths are matched as raw bytes (an `OsStr`), never as the lossy record text, and never cut. A node whose path `PathMap` cannot give whole (an unknown ancestor, deeper than its limit) fails closed while rules are in force: `EROFS` for a change, `EACCES` otherwise.

Globs are `globset` globs with `literal_separator(true)`, absolute (starting `/` or `**/`), exactly as Task 4 checks them. That check moves into `boxcar_fs::rules::glob`, and `boxcar-policy` calls it.

### The three rules

A glob names a path and everything beneath it, for `denied` and for `writable` alike. A path is denied, or writable, when it or any of its ancestors matches. So `/workspace/secrets` covers the directory and all it holds, while `/workspace/secrets/**` covers what it holds but not the directory itself.

- **`denied`**: cannot be looked up, opened, created, listed with its inode, or changed in any way: `EACCES`.
- **`writable`**: a change must name a writable path, or `EROFS`. Because the rule takes ancestors, a directory that may be renamed may also have its contents edited in place. So moving a directory to a writable place, editing it, and moving it back changes nothing that could not have been changed where it was.
- **`[exec] deny`**: a file one of whose names (or whose identity, section 2, *The boot scan*) matches may not be opened at all, for exec or otherwise, and may not be renamed or linked, unless a live `exec` exception matches that name: `EACCES`. So the loader route (`ld-musl-x86_64.so.1 /usr/bin/nc`, which opens the program read-only and maps it), a copy (`cp /usr/bin/nc /tmp/x`), and a rename (`mv /usr/bin/nc x`) are all refused with the exec.

Denied is checked first, then exec, then writable.

A session with no policy file has `PathRules::allow_all()`, and none of these checks run. Nothing changes from today: `tests/differential.rs` holds AuditFs transparent.

### Which operations, by what

| Operation | Checked by | Refused when |
| --- | --- | --- |
| `lookup` | the named path, before the inner call; the reply's identity after it | the path or the identity is denied: `EACCES`, the reply's lookup given back |
| `create` | the named path; the identity of what the name is now (`fstatat` beneath the share's root, before the inner call); the reply's identity | denied (`EACCES`); not writable (`EROFS`) |
| `mkdir`, `mknod`, `symlink` | the named path | denied; not writable |
| `link` | the new name; every known name, and the identity, of the source | denied; an exec-denied source; not writable by every name (`EROFS`: a link changes the inode's link count) |
| `rename` | the old and the new path; the identity of what each is now | denied; a directory holding denied entries; a denied glob's literal prefix or an ancestor of one; an exec-denied file; not writable |
| `unlink`, `rmdir` | the named path; the identity of what it is now | denied; not writable |
| `open` (any) | every name `PathMap` knows for the inode (its name and its aliases), and its identity | denied; exec-denied; for writing or `O_TRUNC`, not writable by every name |
| `setattr`, `write`, `fallocate`, `setxattr`, `removexattr` | every known name | denied; not writable by every name |
| `getattr`, `readlink`, `getxattr`, `listxattr`, `opendir`, `access`, `statfs` | the node id itself (the gate, below) | the map does not hold it, or its stored identity is denied |
| `readdirplus` | each entry's path and identity | listed by name with node id 0 and zeroed attributes |

`write`, `setattr` and the rest are checked at the time of each request, not only at the open. So a handle opened under a `writable` exception stops writing when the exception expires. `O_TRUNC` arrives as a separate `setattr` of the size (the passthrough never negotiates `ATOMIC_O_TRUNC`), and that `setattr` is checked like any other.

A `lookup` of `.` or `..` is checked by the path of the inode it returns, not by the name.

### The node-id gate

A hostile guest kernel can send any node id, not only those it was handed. The passthrough numbers its inodes in sequence and keeps an inode while a lookup holds it, so the id of a denied entry can be guessed from its neighbours in a listing. While rules are in force, every request that carries a node id is refused (`EACCES`) when `PathMap` does not hold that id. `forget`, `batch_forget`, `release`, `releasedir` and `destroy` are exempt. The checks above already refuse unknown ids, and the gate covers the requests that are otherwise forwarded: `getattr`, `readlink`, `getxattr`, `listxattr`, `opendir`, `access`, `statfs`. `PathMap` holds exactly the inodes the kernel was handed, so an honest kernel never meets the gate.

`opendir` passes the inner filesystem only the flags that read a directory (`O_RDONLY`, `O_NONBLOCK`, `O_CLOEXEC`, `O_NOATIME`, `O_LARGEFILE`), never `O_TMPFILE` or a write mode. This applies with or without rules: an `opendir` with `O_TMPFILE | O_RDWR` would make an unnamed host file that no record names.

### `readdirplus`

`readdirplus` hands the kernel an inode for every entry without a `lookup`. An entry whose path or identity is denied goes into the reply with node id 0 and zeroed attributes. The kernel takes that as a name without attributes, as `readdir` gives it. The inner filesystem's count for the entry is given back after the inner call returns, whether or not the reply succeeded, and `PathMap` never learns it. A withheld entry is not recorded: a listing refuses nothing. A later `lookup` of the name is refused like any other.

### The boot scan

Names alone do not hold a denied file. A file can have another name made before the session starts: a hard link, or, on a case-insensitive host filesystem, a case variant. So when `denied` or `[exec] deny` has anything in it, the session's shares are scanned once before their devices start (`scan.rs`; `FsDevices::attach` runs it, and its result is one set for the whole session, since the root share and the workspace can be on one host filesystem and share hard links). The scan:
- walks beneath each share's host directory;
- follows no symlinks;
- crosses mount points, as the passthrough does;
- stops at 4,000,000 entries in all.

It records:
- **denied identities**: the `(st_dev, st_ino)` of every entry whose guest path is denied (so everything beneath a denied directory), each with the glob that denied it;
- **holding directories**: the identities of the directories on the way to a denied entry, each with that glob;
- **exec identities**: every regular file whose guest path an `[exec] deny` glob matches, with that glob.

With these:
- a `lookup`, `create` or `readdirplus` reply whose identity is denied is refused, or listed without its inode, whatever name it came by;
- a `create`, `unlink`, `rmdir` or `rename` naming an existing entry first reads that entry's identity (`fstatat` beneath the share's root, no symlink followed) and refuses a denied one, a holding directory (`rename`, `rmdir`), or an exec one (`rename`). So a case variant cannot remove a denied file, a create cannot truncate one through an alias, and the paths of denied entries never change;
- an `open` of an exec identity is refused unless one of the file's known names matches an `exec` exception. So a hard link made before the session does not get the program past `[exec] deny`.

A directory the scan cannot read fails the session, with its path. The passthrough's lookups need only search permission, so an entry beneath an unreadable directory could otherwise be reached without the scan seeing it. A session over the limit fails too (`error: --policy: [fs] denied needs the shares scanned, and they have more than 4000000 entries`), rather than run with `denied` held by name alone.

The sets are fixed for the session. `denied` has no exceptions and no update, nothing can be created or renamed onto a denied path, and nothing denied can be removed or renamed. A change made on the host behind the session's back is the host's (section 6), with one guard. A `rename` of a denied glob's *literal prefix* (the components before its first wildcard: `/workspace/secrets` for `/workspace/secrets/**`), or of any ancestor of one, is refused. So a denied tree the host makes after boot cannot be moved out from under an anchored glob either.

### Orderings

- A name check happens before the inner call. The names of a node change only through the guest's own `rename` and `link`, which are checked themselves. Directories holding denied entries, and literal prefixes, never move.
- A `lookup` or `create` reply checked by identity is checked after the inner call, so no rename between the name check and the reply hands the kernel a denied inode.
- A `create`'s existing-entry check and its inner call: an alias of a denied file cannot be renamed into the name between the two, because a rename of a denied identity is refused.
- A `link` that adds a name to an inode, racing a `write` checked a moment before, lets that one write through. It is linearized before the link, and the next request sees both names.
- An exception's expiry and an operation checked under it: the operation that read the rules before the swap completes, and every request after the swap reads the new rules (one `ArcSwap::load` per request).
- The kernel may forget a name under memory pressure, and `PathMap` forgets it too. A check by every known name is a check by the names held at the time. The identity sets do not depend on what the kernel holds.

### Records

`fs.denied` gains two optional fields:
- `reason`: `"policy"` for these refusals, omitted for the inner filesystem's own (an `EACCES` from the host, as today);
- `rule`: the glob that refused it, whether a `denied` glob, an `[exec] deny` glob, a holding directory's glob, or a denied literal prefix's glob, and also for a refusal by identity. It is omitted for a `writable` refusal, where no glob matched, and for a node with no whole path.

`op` is the operation (`lookup`, `create`, `rename`, `open`, `exec`, `write`, `setattr`, `getattr`, ...), where `exec` is an open for exec. A refused operation never reaches the host and gets no other record. `fs.denied` is never sampled, as the M5 plan has it. The reconciler's `policy_denial` summary names the policy:
- `exec of /usr/bin/nc was refused by the policy ([exec] deny **/nc)`;
- `create of /etc/x was refused by the policy (outside [fs] writable)`.

### `[fs] writable`'s default

A file that gives no `writable` gets `["/workspace/**", "/tmp/**"]`. Init mounts no tmpfs on `/tmp`, so `/tmp` belongs to the root share, and with the M5 plan's default of `/workspace/**` alone a policy file without `writable` would make it read-only. That breaks `mktemp`, compilers and package builds. The strict profile lists `/tmp/**` too. This changes a binding constraint of the M5 plan, so it was put to the owner on the pull request, who approved it; the M5 plan's section 3 and section 8 say so. A tmpfs on `/tmp` was the other way: it was refused because what is written there would be neither recorded nor policed. A `writable` the file names replaces the default whole, `[]` included.

## 3. Indicators, spans, argv

- **`[fs] indicators`**: `ReconcileConfig` gains the policy's indicator globs (`PolicyIndicators`, compiled in `boxcar-audit`), matched by guest path: `root` is at `/`, `workspace` at `/workspace`. `indicator_removal` fires for a path the built-in rules name (as now) or one the policy's globs match.
- **`[spans] keep_tool_args = false`**: `tool.open` keeps `args_b3` and drops `args`. `args_summary` becomes `"[arguments not kept: keep_tool_args = false]"`, because the summary is made from the arguments. The setting reaches the tracker through `InspectConfig`, as `declared` does. The reconciler still compares against the declared arguments it holds in memory, so spans and their findings do not change.
- **`[record] scrub_argv = true`**: the same `RawArgv` as `--scrub-argv`, made when either asks.

## 4. Live exceptions

### Held apart

`LivePolicy` holds:
- the permanent policy: the network rules (`policy.update`'s), the vsock ports, and the path rules from the file (or allow-all);
- up to 64 live exceptions, each `{id, rule, kind, ttl_s, expires_ns, deadline, by_pid}`.

The views (the net `ArcSwap` and the fs `LiveRules`) are compiled from both on every change, under `LivePolicy`'s lock. `policy.get` reads the permanent part, never a compiled view:
- **`egress`**: an `allow` rule after the permanent rules. A permanent `deny` of the same target still wins, because denies come first, so an exception opens what the default denies, not what the policy denies by name. The target is written as `--allow` takes it.
- **`writable`**: a glob added to `writable`.
- **`exec`**: a glob that lifts `[exec] deny` for the names it matches.

`id` counts from 1 for the session. `ttl_s` is from 1 to 86400. `deadline` is `CLOCK_BOOTTIME` at the grant plus `ttl_s`, which neither a step of the wall clock nor a suspend moves. `expires_ns` is the realtime clock's view of that deadline, for the record (the clock `ts_host_ns` is in).

### The protocol

- `policy.update` takes `exception: {rule, kind: "egress"|"writable"|"exec", ttl_s}`, and nothing else beside it. With `net` or `vsock` it is `bad_request`, so an update is either a whole permanent part or one exception.
  - The rule is checked as its kind requires (a target, or an absolute glob) and refused with `bad_request` naming it.
  - The 65th live exception is `busy`.
  - An `egress` exception on a VM without a network card, or a `writable` or `exec` one on a VM without shares, is `invalid_state`.
  - The result is the new version, and `policy.exception{id, rule, kind, ttl_s, expires_ns, by_pid, version}` is recorded.
- `policy.get` answers `net` (the permanent rules only, as now), `vsock`, `version` and `exceptions: [{id, rule, kind, ttl_s, expires_ns, by_pid}]`, the live ones by id. A client that writes back the `net` it read never makes an exception permanent: `net` never holds one.
- An update of `net` or `vsock` replaces only the permanent part. The exceptions stay, with their expiries.
- Hello's capabilities gain `policy.exception`.
- Records are made under `LivePolicy`'s lock (it holds the audit sink), so the versions in the log are in order: `policy.changed` for an update, `policy.exception` for a grant, `policy.changed{by_pid: 0}` for an expiry.

### Expiry

`ExceptionTimer` is a subscriber on the VMM's main loop, beside `ControlSubscriber`. It is a `TimerFd` armed for the earliest deadline and re-armed through an eventfd at each grant, waking at least once a minute while any exception lives, so a suspend cannot hold one past its time.

When it fires, it takes `LivePolicy`'s lock and removes every exception whose deadline has passed. It then compiles and swaps the views, wakes the net device, and moves the version on once. Finally it records `policy.changed{by_pid: 0, version}`, where 0 means the VMM, at an expiry, and re-arms.

The net stack revokes the flows the remaining policy denies, as after any update. Two grants of one rule are two exceptions, each with its own expiry. A permanent rule that is the same as an exception's stays when the exception goes. A firing that finds nothing expired re-arms and changes nothing.

The clock is a small trait (`PolicyClock`: boottime and realtime nanoseconds). Sessions use the system's clock and tests a manual one. So `an_exception_expires_on_the_loop` moves the clock past a deadline, wakes the timer, and sees the swap and the record, with no sleep.

### The CLI

- `boxcar policy allow RULE --ttl DURATION`: an `egress` exception. Without `--ttl`, it is the permanent change it is today.
- `--writable GLOB --ttl DURATION` and `--exec GLOB --ttl DURATION`: the other kinds, given in place of RULE. `--ttl` is required for both.
- `DURATION` is `90`, `90s`, `10m` or `1h`, from 1 s to 24 h.
- `boxcar policy exception ls [--json]` lists the live exceptions (id, kind, rule, seconds left), read from `policy.get`.
- `boxcar policy show` lists them after the permanent policy.
- Against a server without the capability, `--ttl` and `exception ls` say so and exit 1.

## 5. Tests

- **`boxcar-fs` rules**: matching by guest path for both shares; the ancestor rule for `denied` and `writable`; literal prefixes; raw non-UTF-8 bytes; exceptions added; allow-all checks nothing.
- **`boxcar-fs` scan**: identities beneath a denied directory; holding directories; exec identities; one set across two shares, with a hard link between them; a symlink not followed; an unreadable directory fails; the entry limit; nothing walked when nothing is denied or exec-denied.
- **The table of attempts** (`tests/policy.rs`), against `AuditFs` over a real passthrough share. Each attempt is refused with its errno and one `fs.denied{reason: "policy", rule}`, and nothing changes on the host:
  - **lookups**: a denied name; through a symlink into a denied directory (the guest resolves it, then looks up the real path); `..` and `.` by where they lead, and a share whose root is denied; a pre-existing hard link of a denied file; a "case variant" (an alias the host made by hard link, standing for a case-insensitive host);
  - **`readdirplus`**: listed, no inode, zeroed attributes, the inner count given back;
  - **making names**: `create`, `mkdir`, `mknod`, `symlink` and `link` onto a denied path; `create` through an alias of a denied file (nothing truncated);
  - **renames**: onto a denied path; out of one; of a holding directory; of a literal prefix; `RENAME_EXCHANGE` with a denied path;
  - **removals**: `unlink` and `rmdir` of denied paths, and `unlink` of an alias of a denied file;
  - **changes outside `writable`** (`EROFS`): writes, truncation, `setattr`, `fallocate` and xattrs; the same through a hard link made before the session to a read-only name; a directory moved out to a writable place and back with nothing edited that could not be edited in place;
  - **exec**: an exec-open of a program by its name, by a hard link the scan found, and by one the guest looked up; a read-only open of it (the loader route); a rename and a link of it; an `exec` exception lifting it;
  - **an exception's end**: a handle opened for writing under a `writable` exception, refused after the exception is removed;
  - **the node-id gate**: `getattr`, `opendir`, `readlink` and `getxattr` of an id the map does not hold;
  - **`opendir`'s flags**: an `opendir` with `O_TMPFILE | O_RDWR` makes no host file;
  - **allow-all**: all of the above allowed with no rules.
- **`boxcar-vmm`**:
  - grants, and the 65th refused (`busy`);
  - an exception alongside `net` refused, and a `net` update keeping the exceptions;
  - `policy.get` showing the permanent part and the exceptions apart, and the CLI's read-modify-write while an egress exception lives leaving it out of `net`;
  - two grants of one rule expiring on their own times, and a permanent rule surviving its twin's expiry;
  - `an_exception_expires_on_the_loop`: manual clock, main loop, `policy.changed{by_pid: 0}`, the views swapped and the device woken;
  - the records in version order, and the capability.
- **`boxcar-proto`**: the exact JSON of `policy.exception` and `fs.denied` (59 kinds), the control messages' shapes and limits, and the schemas regenerated.
- **`boxcar-audit`**: a policy refusal's summary; a policy indicator's `indicator_removal` by guest path, in either share.
- **`boxcar-net`**: `keep_tool_args = false` keeps `args_b3` and drops the rest; the reconciler's span findings unchanged.
- **`boxcar`**:
  - `--ttl` parsing, and `--writable` and `--exec` needing `--ttl`;
  - `exception ls` against the fake server;
  - `run` with `[record] scrub_argv` acting as the flag;
  - the warning gone.
- **Gated (`kvm_m5`)**:
  - **`agent-isolate-strict`** from an image with no `/etc/resolv.conf` and a regular-file copy of BusyBox at `/usr/bin/nc`. The session:
    - resolves and reaches `github.com:443` by name;
    - writes `/workspace` and `/tmp`;
    - is refused a write to `/etc` (`EROFS`);
    - is refused running `/usr/bin/nc` (`EACCES`): directly, through a symlink in `/workspace`, through the loader (`/lib/ld-musl-x86_64.so.1 /usr/bin/nc`), and as a copy (`cp /usr/bin/nc /tmp/x` fails reading it);
    - is refused a hard link of it (`ln /usr/bin/nc /workspace/n`).

    Each refusal is `fs.denied{reason: "policy"}` with its `policy_denial` finding.
  - **An exception during a run**: a `writable` exception for `/etc/**` with `--ttl 3s`. A write goes through, then after the expiry is refused, and the log shows `policy.exception`, then `policy.changed{by_pid: 0}`.
- **Checks**: the Rust checks with the eBPF programs built, `cargo xtask schema` with no further diff, and `cargo xtask test-kvm m5` on the test box.

## 6. Out of scope

- Refusing programs that are not on the shares: a program in the guest's `/run` or `/dev/shm`, which are tmpfs, would need the sensor, at ring 1.
- Exceptions to `denied`.
- Showing the path rules in `policy.get` (the file's sha256 is in `policy.loaded`).
- Changing the permanent path rules over the control socket.
- Changes made on the host during a session, beyond the literal-prefix guard: a file the host gives a new inode, or a tree it makes under a wildcard-anchored glob.
- A `--rootfs` session's boot paths. An image's are made before boot (Task 3). A `--rootfs` directory without `/etc/resolv.conf`, under a policy whose `writable` leaves out `/etc`, loses its name resolution, because init cannot create the file.
- `docs/policy.md` (Task 8, #30).

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **Denied is held by identity as well as by name.** A boot scan of all the session's shares, as one set, finds the denied entries and the directories that hold them. Every create, unlink, rmdir and rename reads what the name is now. So neither a hard link, nor a case-insensitive host, nor a renamed parent reaches a denied file. A directory the scan cannot read, or a session past 4,000,000 entries, fails before boot.
- **The node-id gate**: while rules are in force, an id the path map does not hold is refused for every request but the releases. The guest kernel is not trusted to send only the ids it was given.
- **A glob covers what is beneath what it names, for `denied` and `writable` alike.** For `writable`, this means a directory that may be moved may also be edited in place, so moving it out and back launders nothing.
- **`[exec] deny` refuses every open of the file, and its renames and links**, by any known name and by the identity the scan found. So the loader route, a copy, a rename and a pre-existing hard link do not run it either. A program the guest already holds a copy of, or one off the shares, is out of reach (section 6).
- **`readdirplus` lists a denied entry without its inode or its attributes**, as `readdir` would. Names stay visible, so the listing is unchanged and only the inode is withheld.
- **`opendir` takes only a directory read's flags**, with or without rules.
- **`link` needs its source writable by every name**: a link changes the inode's link count, and a read-only file stays read-only under any new name.
- **The default `writable` is `/workspace/**` and `/tmp/**`**, a change to the M5 plan's section 3 the owner approved: `/tmp` is the root share's.
- **An egress exception is an allow after the permanent rules**: it opens what the default denies, never what the policy denies by name.
- **An exception comes alone in its `policy.update`**: an update is either a whole permanent part or one exception. A whole-policy update never carries an exception, so nothing a client reads back can make one permanent.
- **The 65th exception is `busy`**: the request is sound, and it fits once one expires.
- **Expiry by `CLOCK_BOOTTIME`**, recorded as realtime `expires_ns`. A step of the wall clock does not move an expiry, and a suspend counts. `policy.changed{by_pid: 0}` marks an expiry, and every policy record is made under the policy's lock, in version order.
- **`keep_tool_args = false` drops the summary as well as the arguments**, because the summary is made from them. `args_b3` stays, so a call can still be matched to arguments someone holds.
- **The strict profile refuses `nc.openbsd`, `nc.traditional` and `netcat` as well**, which Debian's `nc` resolves to through its alternatives.

## 8. Review (2026-10-19, before the code)

An adversarial review of the first draft (9c55f4a) against the code found the following. Each is answered in the sections above.

1. **A denied file read by a guessed node id** (a hostile guest kernel; the passthrough's ids are sequential; a failed `readdirplus` leaks counts): the node-id gate, and the withheld entries' counts given back whatever the reply.
2. **`create` truncating a denied file through an alias** before its reply is checked: the existing-entry check before the inner call, and denied identities that cannot be renamed.
3. **`unlink` and `rmdir` by name only** (a case variant removes a denied file): the existing-entry check.
4. **Renames laundering `writable` and `[exec] deny`**: the ancestor rule for `writable`; exec-denied files cannot be renamed or linked.
5. **`[exec] deny` defeated by the loader and by a copy**, and Debian's `nc` resolving to `nc.openbsd`: every open refused; the strict profile's names.
6. **Departures from the M5 plan**: the draft's table had only write and exec opens (now every open and the gate); the default `writable` (kept as bound and put to the owner, who approved adding `/tmp/**` after a second opinion from Codex); the gated hard link (added).
7. **The scan**: unreadable directories (fail the session), one set across shares, host-made trees (the literal-prefix guard; the rest out of scope).
8. **The clock**: `CLOCK_BOOTTIME` deadlines, records under the lock.
9. **`policy.get` reading the compiled view**: the permanent part is held apart and read; the CLI's read-modify-write is tested.
10. **Smaller points**: zeroed attributes for withheld entries; `opendir`'s flags; `setattr` of `/workspace` and `/tmp` themselves is `EROFS` (a test pins it); a `--rootfs` session's boot paths (section 6); withheld listings not recorded.
