# Enforcing paths and programs, and expiring exceptions (M5 Task 5, #27)

Branch `issue-27`, from `main` at 8f29dbf. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`: section 3 (*Crate boundaries*, *Policy files*, *Live exceptions*), section 4 (focus 5 and 6) and section 6, Task 5. Task 4's plan is `docs/plans/policy-files.md`. Subject: `policy: enforce paths and programs, and expiring exceptions`.

Task 4 made the policy file and put its network half into force. This task puts the rest in force. `[fs] writable` and `denied` and `[exec] deny` are enforced at ring 0 by every `AuditFs`. `[fs] indicators` goes to the reconciler, `[spans] keep_tool_args` to the gate, and `[record] scrub_argv` to the same switch as `--scrub-argv`. On top of the permanent policy come live exceptions, which have a time to live, are recorded as they are granted, and expire on the VMM's event loop. `PolicyFile::not_in_force` and the stderr warning go.

## 1. Where it sits

| File | What |
| --- | --- |
| `crates/boxcar-fs/src/rules.rs` (new) | `PathRules`: the compiled `writable`, `denied`, `exec` deny and exception globs, guest-path matching, `LiveRules` (the `ArcSwap` every share reads) |
| `crates/boxcar-fs/src/scan.rs` (new) | the boot scan: the host identities of what `denied` names, and the directories that hold them |
| `crates/boxcar-fs/src/{audit_fs,path_map,share,device}.rs` | the checks per operation; every name of an inode; `readdirplus` without denied inodes |
| `crates/boxcar-policy/src/{model,parse,profiles}.rs` | globs checked by `boxcar_fs::rules`; the default `writable`; `not_in_force` goes |
| `crates/boxcar-proto/src/{audit.rs,audit/payloads.rs,control.rs}` | `fs.denied.reason`/`rule`, `policy.exception` (59 kinds), `PolicyUpdateParams.exception`, `PolicyView.exceptions`, the `policy.exception` capability |
| `crates/boxcar-vmm/src/{policy,vmm,lifecycle}.rs`, `control/ops.rs`, `devices/mod.rs` | the permanent policy and the exceptions held apart; compiled views; the expiry timer on the main loop; `policy.exception` and `policy.changed` |
| `crates/boxcar-audit/src/reconcile/{mod,paths,rules}.rs` | the policy's indicators; a policy refusal's summary |
| `crates/boxcar-net/src/{gate/*,model/*}` | `keep_tool_args = false`: `tool.open` without `args` or `args_summary` |
| `crates/boxcar/src/{cli.rs,cmd/run.rs,cmd/policy.rs}` | the file's `[fs]`, `[exec]`, `[spans]`, `[record]` into force; `policy allow --ttl`, `--writable`, `--exec`; `policy exception ls` |
| `crates/boxcar-fs/tests/auditfs.rs`, `crates/boxcar/tests/{kvm_m5,policy_cli,run_args}.rs` | the table of attempts, the CLI, the gated run |
| `docs/audit-events.md`, `docs/control-protocol.md`, `docs/plans/2026-10-13-m5-…md` §8 | the records, the protocol, the decisions |

Dependencies: `globset` (already in the workspace) for `boxcar-fs` and `boxcar-audit`. `boxcar-policy` gains `boxcar-fs`, as the M5 plan's crate boundaries have it, so that one function decides what a path glob is. Nothing else is new.

## 2. Path rules

### What a guest path is

A share serves a guest directory (`FsShareConfig::guest_path`: `/` for the root share, `/workspace` for the workspace). The guest path of a node is that directory joined with the node's share-relative path from `PathMap`: `/` + `/etc/x` is `/etc/x`, and `/workspace` + `/src/a` is `/workspace/src/a`. It is matched as raw bytes (an `OsStr`), never the lossy record text, and never cut. A node whose path `PathMap` cannot give whole (an unknown ancestor, deeper than its limit) has no guest path. Such a node fails closed: it is not writable, and when the policy denies anything it is denied.

Globs are `globset` globs with `literal_separator(true)`, absolute (starting `/` or `**/`), exactly as Task 4 checks them. That check moves into `boxcar_fs::rules::glob`, which `boxcar-policy` calls.

### The three rules

- **`denied`**: a path is denied when it, or any of its ancestors, matches a `denied` glob. So `/workspace/secrets` denies the directory and everything beneath it, while `/workspace/secrets/**` denies what it holds but not the directory itself. Denied means it cannot be looked up, opened, created, or changed in any way. The refusal is `EACCES`.
- **`writable`**: a mutating operation must name a path that matches a `writable` glob (no ancestor rule: the glob says what it means). Otherwise the refusal is `EROFS`. Denied is checked first, so a denied path is `EACCES` even where it would also be read-only.
- **`exec`**: opening a file for exec (`__FMODE_EXEC` in the open flags, which already reaches the trait: `fs.open.exec`) is refused with `EACCES` when any name of the file matches an `[exec] deny` glob and no live `exec` exception matches that name.

A session with no policy file has `PathRules::allow_all()`: no check runs, and nothing changes from today (`tests/differential.rs` holds AuditFs transparent).

### Which operations, by what

| Operation | Checked by | Denied | Not writable |
| --- | --- | --- | --- |
| `lookup` | the named path, before the inner call; then the identity of the reply (section 2, *The boot scan*) | `EACCES`, the reply's lookup given back | - |
| `create`, `mkdir`, `mknod`, `symlink` | the named path; for `create`, also the reply's identity | `EACCES` | `EROFS` |
| `link` | the new name; every known name of the source inode | `EACCES` | `EROFS` (the source's link count changes: it must be writable by all its names) |
| `rename` | the old and the new path (both are changed; with `RENAME_EXCHANGE`, each is both); the old path's identity against the holding directories | `EACCES` | `EROFS` |
| `unlink`, `rmdir` | the named path | `EACCES` | `EROFS` |
| `open` for writing, or with `O_TRUNC`; `setattr`; `write`; `fallocate`; `setxattr`; `removexattr` | every name `PathMap` knows for the inode (its primary name and its aliases) | `EACCES` when any is denied | `EROFS` unless all are writable |
| `open` with `__FMODE_EXEC` | every known name | `EACCES` when any is denied | `EACCES` when any matches `[exec] deny` with no exception |
| `readdirplus` | each entry's path, and its identity | listed without its inode | - |

`write`, `setattr` and the rest are checked at the time of the request, not only at the open. So a handle opened under a `writable` exception stops writing when that exception expires. `O_TRUNC` arrives as a separate `setattr` of the size, since the passthrough never negotiates `ATOMIC_O_TRUNC`, and that `setattr` is checked like any other. `readdir` (names only), `getattr`, `readlink`, `opendir`, `getxattr`, `listxattr`, `access` and the rest are not checked. They take an inode, and the guest never gets the inode of anything denied (below).

`lookup` of `.` or `..` is checked by the path of the inode it returns, not by the name.

### `readdirplus`

`readdirplus` hands the kernel an inode for every entry without a `lookup`. An entry whose path is denied, or whose identity is, goes into the reply with node id 0, which the kernel takes as a name without attributes, as `readdir` gives it. The inner filesystem's count for it is given back (`forget`, after the inner call returns, for the entries that made it into the reply), and `PathMap` never learns it. A later `lookup` of the name is refused as any other.

### The boot scan

Names alone do not hold a denied file. A file can have another name before the session starts: a hard link, or on a case-insensitive host filesystem a case variant. A directory above it could also be renamed to a path no glob names. So when `denied` is not empty, each share's host directory is walked once before the device starts (`scan.rs`). The walk uses `openat` beneath the share's root, follows no symlinks, crosses mount points as the passthrough does, and stops at 4,000,000 entries.

- **Denied identities**: the `(st_dev, st_ino)` of every entry whose guest path is denied (so everything beneath a denied directory), each with the glob that denied it.
- **Holding directories**: the identities of the directories on the way to a denied entry.

With these:

- a `lookup`, `create` or `readdirplus` reply whose identity is denied is refused, or listed without its inode, whatever the name it came by;
- a `rename` whose old path is a holding directory (by identity: a `fstatat` beneath the share's root of the parent's host path, made only when the scan found any) is refused with `EACCES`. So the paths of denied entries never change, and the name checks stay true.

The set is fixed for the session. `denied` has no exceptions and no update, nothing can be created or renamed onto a denied path, and nothing denied can be removed or renamed. A share larger than the limit fails the session before it boots (`error: --policy: [fs] denied needs share root scanned, and it has more than 4000000 entries`), rather than enforce `denied` by name alone. A share the scan cannot read (`EACCES` on the host) is walked as far as it can be. What it cannot read, the passthrough cannot serve either.

`writable` and `exec` are by name. A hard link made before the session, under names the guest has not looked up, is not tied to them: writing through a name in `/workspace` that also names a file in `/usr` changes that file, unless the guest has looked up the `/usr` name. That is a documented limit, as is a program copied before it is run (the M5 plan's ring-0 note): `exec` refuses program files by their names, and a copy is a new file.

### Orderings

- A name check happens before the inner call. The names of a node change only by the guest's own `rename` and `link`, which are checked themselves. A rename racing a write cannot move a file from a writable name to a read-only one without that rename passing the writable check on both names.
- A `link` that adds a name to an inode, racing a `write` checked a moment before, lets that one write through. It is linearized before the link, and the next request sees both names.
- An exception's expiry and an operation checked under it: the operation that read the rules before the swap completes, and every request after the swap reads the new rules (`ArcSwap::load` per request).
- A `lookup` reply checked by identity is checked after the inner call, so no rename between the name check and the reply hands the kernel a denied inode.

### Records

`fs.denied` gains two optional fields:
- `reason`: `"policy"` for these refusals, omitted for the inner filesystem's own (an `EACCES` from the host, as today);
- `rule`: the glob that refused it (the `denied` or `[exec] deny` glob, also for a refusal by identity), omitted for a `writable` refusal, where no glob matched.

`op` is the operation (`lookup`, `create`, `rename`, `open`, `exec`, `write`, `setattr`, ...: `exec` is an open for exec). A refused operation never reaches the host and gets no other record. `fs.denied` is never sampled, as now. The reconciler's `policy_denial` summary names the policy: `exec of /usr/bin/nc was refused by the policy ([exec] deny **/nc)`, `write of /etc/x was refused by the policy (outside [fs] writable)`.

### `[fs] writable`'s default

A file that gives no `writable` gets `["/workspace/**", "/tmp/**"]`. Init mounts no tmpfs on `/tmp`, so `/tmp` is the root share's, and a session that cannot write `/tmp` breaks most programs. This changes Task 4's default of `/workspace/**` alone, which put nothing in force, and is a decision recorded in the M5 plan's section 8.

## 3. Indicators, spans, argv

- **`[fs] indicators`**: `ReconcileConfig` gains the policy's indicator globs (compiled by `boxcar_fs::rules`) and the guest directory of each mount (`root` → `/`, `workspace` → `/workspace`). `indicator_removal` fires for a path the built-in rules name (as now) or one the policy's globs match by its guest path. The profiles list the built-in ones, which still match as they do.
- **`[spans] keep_tool_args = false`**: `tool.open` keeps `args_b3` and drops `args` and `args_summary`. `args_summary` becomes `"[arguments not kept: keep_tool_args = false]"`, a fixed text: the summary is made from the arguments. It reaches the tracker through `InspectConfig`, as `declared` does. The reconciler still compares the declared arguments it holds in memory, so spans and their findings are unchanged.
- **`[record] scrub_argv = true`**: the same `RawArgv` as `--scrub-argv`, made when either asks.

## 4. Live exceptions

### Held apart

`LivePolicy` holds the permanent policy (the network rules as today; the path rules from the file, or allow-all) and up to 64 live exceptions, each `{id, rule, kind, ttl_s, expires_ns, by_pid}`. The views are compiled from both on every change, under `LivePolicy`'s lock:

- **`egress`**: an `allow` rule after the permanent rules. A permanent `deny` of the same target still wins (denies come first), so an exception opens what the default denies, not what the policy denies by name. It is a target as `--allow` takes it.
- **`writable`**: a glob added to `writable`.
- **`exec`**: a glob that lifts `[exec] deny` for the names it matches.

`id` counts from 1 for the session. `expires_ns` is the host's realtime clock (`ts_host_ns`'s clock) at the grant plus `ttl_s`. `ttl_s` is from 1 to 86400.

### The protocol

- `policy.update` takes `exception: {rule, kind: "egress"|"writable"|"exec", ttl_s}`, alone. With `net` or `vsock` beside it, it is `bad_request`, so an update is either a whole permanent part or one exception. The rule is checked as its kind's (a target; an absolute glob) and refused with `bad_request` naming it. The 65th live exception is `busy`. A `writable` or `exec` exception on a VM with no shares is `invalid_state`. The result is the new version, and `policy.exception{id, rule, kind, ttl_s, expires_ns, by_pid, version}` is recorded.
- `policy.get` answers `net` (the permanent rules only, as now), `vsock`, `version` and `exceptions: [{id, rule, kind, ttl_s, expires_ns, by_pid}]`, the live ones by id. A client that writes back the `net` it read never makes an exception permanent, because `net` never holds one.
- An update of `net` or `vsock` replaces only the permanent part. The exceptions stay, with their expiries.
- Hello's capabilities gain `policy.exception`.

### Expiry

A `TimerFd` subscriber on the VMM's main loop (`ExceptionTimer`, beside `ControlSubscriber`) is armed for the earliest expiry. A grant re-arms it through an eventfd it watches. When it fires, it takes `LivePolicy`'s lock, removes every exception whose `expires_ns` has passed by the policy's clock, compiles and swaps the views, wakes the net device, moves the version on once, and records `policy.changed{by_pid: 0, version}` (0: the VMM, at an expiry). Then it re-arms for the next. The net stack revokes the flows the remaining policy denies, as after any update. Two grants of one rule are two exceptions with their own expiries. A permanent rule the same as an exception's stays when the exception goes. An expiry that finds nothing expired (the timer early against the clock) re-arms and changes nothing.

The clock is `boxcar_audit::Clock`: `SystemClock` in a session, `ManualClock` in the tests. So `an_exception_expires_on_the_loop` moves the clock past an expiry, wakes the timer, and sees the swap and the record with no sleep.

### The CLI

- `boxcar policy allow RULE --ttl DURATION`: an `egress` exception.
- `--writable GLOB --ttl DURATION`, `--exec GLOB --ttl DURATION`: the other kinds (in place of RULE; `--ttl` required).
- `DURATION` is `90`, `90s`, `10m` or `1h`, from 1 s to 24 h.
- `boxcar policy allow RULE` without `--ttl` is the permanent change it is today.
- `boxcar policy exception ls [--json]`: the live exceptions (id, kind, rule, seconds left), from `policy.get`.
- `boxcar policy show` lists them after the permanent policy.
- Against a server without the capability, `--ttl` and `exception ls` say so and exit 1.

## 5. Tests

- **`boxcar-fs` rules**: matching by guest path for both shares; the ancestor rule for `denied` and not for `writable`; raw non-UTF-8 bytes; a node with no whole path fails closed; exceptions added and removed; allow-all checks nothing.
- **`boxcar-fs` scan**: identities beneath a denied directory; holding directories; a symlink not followed; the entry limit; a share with no `denied` is not walked.
- **The table of attempts**, against `AuditFs` over a real passthrough share (`tests/auditfs.rs`), each refused with its errno and one `fs.denied{reason: "policy", rule}`, and nothing changed on the host:
  - a lookup of a denied name;
  - a lookup through a symlink into a denied directory (the guest resolves it: the lookup of the real path);
  - `..` back into a denied directory;
  - a pre-existing hard link of a denied file;
  - a "case variant" (an alias made on the host by hard link, standing for a case-insensitive host);
  - `readdirplus` of a directory holding denied entries (listed, no inode, the inner count given back);
  - create, mkdir, mknod, symlink and link onto a denied path;
  - a rename onto a denied path, out of one, and of a holding directory;
  - `RENAME_EXCHANGE` with a denied path;
  - unlink and rmdir of denied paths;
  - writes, truncation, setattr, fallocate and xattrs outside `writable` (`EROFS`), and the same through a hard link made in the session to a read-only name;
  - an exec-open of a program whose name, or whose hard link's known name, matches `[exec] deny`, and one an `exec` exception lifts;
  - a handle opened for writing under a `writable` exception, refused after the exception is removed;
  - and, all allowed, the same operations under allow-all.
- **`boxcar-vmm`**: grants, the 65th refused (`busy`), an exception alongside `net` refused, a `net` update keeping the exceptions, `policy.get` showing them apart, two grants of one rule expiring on their own times, a permanent rule surviving its twin's expiry, `an_exception_expires_on_the_loop` (manual clock, main loop, `policy.changed{by_pid: 0}`, the net view swapped and the device woken), the capability.
- **`boxcar-proto`**: `policy.exception`'s and `fs.denied`'s exact JSON (59 kinds), the control messages' shapes and limits, the schemas regenerated.
- **`boxcar-audit`**: a policy refusal's summary; a policy indicator's `indicator_removal` by guest path in either share.
- **`boxcar-net`**: `keep_tool_args = false` keeps `args_b3` and drops the rest; the reconciler's span findings unchanged.
- **`boxcar`**: `--ttl` parsing, `--writable`/`--exec` needing `--ttl`, `exception ls` against the fake server, `run` with `[record] scrub_argv` acting as the flag, the warning gone.
- **Gated (`kvm_m5`)**: `agent-isolate-strict` from an image with no `/etc/resolv.conf` and a regular-file copy of BusyBox at `/usr/bin/nc`. The session:
  - resolves and reaches `github.com:443` by name;
  - writes `/workspace` and `/tmp`;
  - is refused a write to `/etc` (`EROFS`);
  - is refused running `/usr/bin/nc` (`EACCES`), directly and through a symlink in `/workspace`.

  Each refusal is `fs.denied{reason: "policy"}` with its `policy_denial` finding. A second gated test grants a `writable` exception for `/etc/**` with `--ttl 3s` during a run: a write goes through, then after the expiry is refused, and the log shows `policy.exception` then `policy.changed{by_pid: 0}`.
- **Checks**: the Rust checks with the eBPF programs built, `cargo xtask schema` with no further diff, and `cargo xtask test-kvm m5` on the test box.

## 6. Out of scope

Exec refusal beyond the shares (a program on the guest's tmpfs or copied before it is run; the sensor would be ring 1). Exceptions to `denied`. Showing the path rules in `policy.get` (the file's sha256 is in `policy.loaded`). Changing the permanent path rules over the control socket. `docs/policy.md` (Task 8, #30).

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **Denied is held by identity as well as by name**: a boot scan of each share when `denied` is not empty, so a hard link, a case-insensitive host or a renamed parent never reaches a denied file. The directories that hold denied entries cannot be renamed. A share over 4,000,000 entries fails the session rather than run with `denied` by name alone.
- **`writable` and `exec` are by name**: every name the share knows, all of them writable to write and none of them denied to run. Hard links made before the session are a documented limit, as copies are for `exec`.
- **A `denied` glob covers what is beneath what it names; `writable` does not.** A denied directory's contents are unreachable in any case, and saying so makes a share root that matches deny its whole share. `writable` matches only what its glob says.
- **`readdirplus` lists a denied entry without its inode**, as `readdir` would. Names stay visible, so the listing is unchanged and only the inode is withheld.
- **`link` needs its source writable by every name**: a link changes the inode's link count, and a read-only file stays read-only under any new name.
- **The default `writable` is `/workspace/**` and `/tmp/**`**, because `/tmp` is the root share's.
- **An egress exception is an allow after the permanent rules**: it opens what the default denies, never what the policy denies by name.
- **An exception comes alone in its `policy.update`**: an update is either a whole permanent part or one exception. A whole-policy update never carries one, so nothing a client read back can make an exception permanent.
- **The 65th exception is `busy`**: the request is sound, and it fits once one expires.
- **Expiry by the realtime clock**, the clock `expires_ns` is recorded in. A clock step moves an expiry by the step. `policy.changed{by_pid: 0}` marks an expiry.
- **`keep_tool_args = false` drops `args_summary` as well as `args`**: the summary is made from the arguments. `args_b3` stays, so a call can still be matched to the arguments someone holds.
