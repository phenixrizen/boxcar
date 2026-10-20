# Confining the VMM with seccomp and Landlock (M5 Task 7, #29)

Branch `issue-29`, from `main` at f6c0dad. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`: section 3 (*Hardening*), section 4 (focus 7) and section 6, Task 7. Subject: `vmm: confine the VMM with seccomp and Landlock`.

The VMM process runs unconfined today. This task confines it two ways:
- **Landlock** limits which files the process can reach.
- **One seccomp allowlist** for the whole process limits which syscalls it can make. A syscall off the list kills the process.

Both are recorded in `vmm.start` as `hardening`. `boxcar audit verify` learns to tell a crash's torn tail from a broken chain, because a seccomp kill is a crash. `boxcar doctor` learns to check nested virtualization on WSL2, Landlock, seccomp and the image cache's free space. `docs/wsl2.md` is new.

## 1. Where it sits

What the code does today, measured and read for this plan:
- **Threads.** `boxcar run` starts its first thread at `run.rs:285` (`job-control`, on a terminal only), then `audit-writer` (`run.rs:287`) and `reconcile` (`run.rs:386`), all before `Vmm::new` (`run.rs:400`). The M5 plan named only the last two. During an image pull, before all of these, ureq starts an unnamed resolver thread for each name it looks up (`ureq resolver.rs:147`). Each ends once it has answered, or lingers after a timeout, and the pull then fails.
- **Threads started by other threads.** Many threads start after the vCPUs run, and not from the main thread:
  - a vCPU thread starts the fs, net and vsock workers when the guest activates each device;
  - the vsock thread starts `guest-ctl-*`, `pty-hub` and `sensor-rx`;
  - `control-accept` starts each `control-conn`, which can start `audit-forward`, `pty-attach` or `graceful-stop`.
  In all, 32 thread names were seen over the gated suites.
- **Where the files are.**
  - The audit session directory, `<audit>/sessions/<id>`, holds the log, the session's copy of the image (`rootfs`) and the default workspace.
  - The state directory, `<sessions root>/<id>` (`$XDG_RUNTIME_DIR/boxcar`, else `/tmp/boxcar-<uid>`), holds `control.sock`, `vsock.sock`, the vsock ports' sockets and `console.log`.
  - Both directories are made after the point where Landlock must be applied (`run.rs:276-279`).
- **No child processes.** The image copy reflinks or copies in-process, and docker credential helpers are never run.
- **The syscalls, measured.** bpftrace on the test box traced every syscall of every process whose main thread is `boxcar`, over the whole `cargo xtask test-kvm m5` run (579 tests, all passing), from each process's first `KVM_RUN` on.
  - It found 78 syscalls.
  - `ioctl`: `KVM_RUN`, `TCGETS`, `TCSETS`, `TIOCGPGRP`, `FIONREAD` and `FIONBIO`.
  - `socket`: `AF_INET` and `AF_NETLINK` (route, for `getifaddrs`); `socketpair` is `AF_UNIX`.
  - `prctl`: `PR_SET_NAME` only.
  - `tgkill`: the vCPU kick (`SIGRTMIN`) and `SIGTSTP` only, each to this process.
  - No `execve`, and no `clone`, because glibc 2.39 starts threads with `clone3`.
  - The raw counts and the bpftrace program go into the pull request, not the repository.
- **The kernel.** The test box now runs Linux 7.0 (Landlock ABI 8, which adds `LANDLOCK_RESTRICT_SELF_TSYNC`), not the 6.14 the M5 plan assumed. `landlock` 0.4.7 knows ABI 8 and 9.

## 2. Landlock

### Where

On the main thread at `run.rs:276-279`: after `ensure_sessions_root`, before `block_stop_signals` and before `job-control`. Every thread `boxcar run` starts on purpose starts after this, so every one of them inherits the domain.

On ABI 8 and later, `restrict_self` also takes `LANDLOCK_RESTRICT_SELF_TSYNC` (`all_threads(true)`), so a resolver thread still running from the pull is confined too. On an older kernel, the thread count is read from `/proc/self/task` just before. If more than one thread is running and TSYNC is not available, the status is `partial` (section 5).

### Before it

The directories the rules name must exist, so `run` makes them first:
- **The audit session directory.** `boxcar_audit` gains `prepare_session_dir(audit_dir, id)`. It makes `<audit>/sessions/<id>` (mode 0700, all the way down) and syncs its parent. `SegmentWriter::open_or_create` already takes an existing empty directory as a new session (`segment.rs:266-288`).
- **The state directory** (0700). `create_console_log`, the vsock device and the control server already accept an existing one.
- **The `--console-log PATH` file**, when it lies outside the state directory: opened with `O_CREAT`, without truncating.

### The rules

The ruleset handles every filesystem right of the newest ABI the crate knows (`AccessFs::from_all(ABI::V9)`), `CompatLevel::BestEffort`. It also handles:
- **TCP binds** (`AccessNet::BindTcp`, ABI 4), with no rule, so no TCP bind is allowed. The VMM listens on no TCP port; outbound TCP connections, UDP and netlink are not covered by this right.
- **Both scopes** (ABI 6): signals and abstract unix sockets outside the domain. The VMM signals only its own threads and uses no abstract sockets.

`EXECUTE` is granted nowhere: the VMM runs no program.

| Path | Rights | Why |
|---|---|---|
| `<audit>/sessions/<id>` | all but `EXECUTE`, beneath | the log, the image copy, the default workspace |
| each share's host directory (`--rootfs`, `--workspace`) | all but `EXECUTE`, beneath | the guest's filesystem |
| the state directory | all but `EXECUTE`, beneath | sockets made, connected to and removed (`MAKE_SOCK`, `RESOLVE_UNIX`), `console.log` |
| the sessions root | `REMOVE_DIR`, beneath | the state directory's `rmdir` at the stop |
| `--console-log PATH` outside the state directory | `WRITE_FILE`, `TRUNCATE` | the console |
| `--dump DIR` | all but `EXECUTE`, beneath | `frames.pcap` and the HTTP exchanges |
| the cached image's `rootfs` | `READ_FILE`, `READ_DIR`, beneath | the session copy, made after this point |
| the kernel, the initramfs | `READ_FILE` | `Vmm::new` reads and hashes them |
| `/dev/kvm` | `READ_FILE`, `WRITE_FILE`, `IOCTL_DEV` | the VM |
| `/etc/resolv.conf` | `READ_FILE` | `NetConfig::from_host` (`run.rs:358`) |
| `/proc/self/mountinfo` | `READ_FILE` | the passthrough's mount fd (`mount_fd.rs`), per share |

A path that does not exist gets no rule. The open it would have allowed then fails as it does today (`ENOENT`), so the early errors `run_args.rs` pins keep their messages.

Some access needs no rule:
- **Opens through `/proc/self/fd/N`** (the passthrough's reopen) are checked against the file they resolve to, which lies beneath its share.
- **`O_PATH` opens** need no right.
- **Inherited descriptors.** stdin, stdout and stderr were opened before the domain, and Landlock does not check them.

What is read before this point needs no rule either: the policy file, the trust store, the docker config, the image pull, and `BOXCAR_TEST_UPSTREAM_ROOTS` in a `kvm-tests` build.

### Status and failure

The `RestrictionStatus` becomes one of:
- `full` when every handled right is enforced on every thread;
- `partial` when the kernel enforces only some of the handled rights (on 7.0, everything but `RESOLVE_UNIX`), or when a thread was left out;
- `unsupported` when the kernel has no Landlock; the run goes on.

Any other error fails the run before the session starts, with a hint naming `--landlock off`. A rule that cannot be opened is one example.

## 3. seccomp

### Where

In `Vmm::start`, between the last fallible setup step and `VcpuSet::spawn` (`vmm.rs:843-845`): one filter, `SECCOMP_FILTER_FLAG_TSYNC`, built with `seccompiler` 0.5. Every running thread and every later one has it, including the vCPU threads, which start under it. If installing it fails, `start` fails. Its error path already records `vmm.stop{reason: "vmm_error"}` and tears down. Nothing of the guest has run.

`--seccomp enforce|log|off`, default `enforce`, also read from `BOXCAR_SECCOMP`:
- **`enforce`**: a call off the list is `SECCOMP_RET_KILL_PROCESS`.
- **`log`**: `SECCOMP_RET_LOG`, so the kernel's audit log names each call off the list while the run goes on. This is how the list is checked and extended.
- **`off`**: installs nothing.

`clone3` is answered `ENOSYS` in both `enforce` and `log`. Its flags sit in memory a filter cannot read, so glibc falls back to `clone`, and `clone` is filtered by its flags.

### The list

It lives in `crates/boxcar-vmm/src/hardening.rs`, x86_64 only, in groups, with a comment on each saying who makes the calls. It is the union of three sources:
1. **What was measured**: the 78 calls of section 1, after the first `KVM_RUN`.
2. **What the guest can reach but the suites never made.** A guest that can make the VMM issue a call off the list can kill it, so these come from reading the code, not from a trace:
   - **Every FUSE operation the passthrough serves** (`fuse-backend-rs` 0.14 `passthrough/sync_io.rs`, through `AuditFs`). The calls it can make: `openat`, `mkdirat`, `mknodat`, `symlinkat`, `linkat`, `unlinkat`, `renameat2`, `readlinkat`, `fchownat`, `fchmodat`, `fchmod`, `utimensat`, `ftruncate`, `fallocate`, `fsync`, `fdatasync`, `newfstatat`, `statx`, `fstat`, `fstatfs`, `getxattr`, `setxattr`, `listxattr`, `removexattr`, `lseek`, `preadv`, `pwritev`, `getdents64`, `umask`, and whatever credential switching it does (`setresuid`/`setresgid` or `setfsuid`/`setfsgid`, read from the source).
   - **Every socket call the net stack makes for a guest flow**, TCP, UDP or DNS, including its errors and `SO_LINGER` resets.
   - **The vsock muxer's** connect, accept, `socketpair` and resets.
   - **A device reset and reactivation from the guest**: the fs, net and vsock devices.
3. **Rare host paths no test reached**:
   - **The vCPU failure path**: `KVM_GET_REGS`, `KVM_GET_SREGS`.
   - **The terminal**: `TIOCGWINSZ` on a resize, and `TIOCOUTQ` when measuring the output queue at the stop.
   - **The audit writer's failure path**: `ftruncate`, already measured.
   - **A panic**: `tgkill`/`rt_sigprocmask` from `abort`, and the panic hook's `TCSETS`.

Each group also names the libc alternatives for its calls, so the list does not depend on one glibc:
- `poll`/`ppoll`;
- `epoll_wait`/`epoll_pwait`/`epoll_pwait2`;
- `clock_nanosleep`/`nanosleep`;
- the stat family;
- `accept`/`accept4`.

Only calls that exist on x86_64 are named, and a unit test checks that each name resolves.

**Arguments are filtered** only where the M5 plan says. Each value is from the trace or from the code:
- **`ioctl`**, by request number: `KVM_RUN`, `KVM_GET_REGS`, `KVM_GET_SREGS`, `TCGETS`, `TCSETS`, `TIOCGPGRP`, `TIOCGWINSZ`, `TIOCOUTQ`, `FIONREAD`, `FIONBIO`. They are compared as 32-bit values: the kernel reads `cmd` as an `unsigned int`.
- **`socket`**, by family: `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK` with protocol `NETLINK_ROUTE` only.
- **`clone`**: `CLONE_THREAD` must be set, so it starts threads and never processes.
- **`prctl`**: `PR_SET_NAME` only.
- **`tgkill`**: the thread group must be this process. The filter is built at run time, so it knows the pid. This item is new: the M5 plan names only the four above.

### Off the vCPU path

The VM is built before the filter, so `KVM_CREATE_*`, `KVM_SET_*`, `KVM_IRQFD` and `KVM_IOEVENTFD` stay off the list. Section 7 must show that a device reset re-registers nothing. If one does, its request joins the list with a comment.

## 4. Crashes and verify

### What a kill leaves

A seccomp kill, like any `SIGKILL`, keeps every completed `write(2)` (the page cache survives) and loses the rest. Given the writer's order (`writer.rs:399-485`, `checkpoint.rs:20-24`), the log can be left only in these states:
1. **Cut at a record boundary**: bytes still in the writer's buffer are lost. This verifies today, and nothing can tell it from a clean end except the missing `vmm.stop`.
2. **A partial last line in the newest segment**: a `write_all` cut short. The kernel stops copying once a fatal signal is pending.
3. **A checkpoint that is the last line of the newest segment, with no index line**: killed between the checkpoint's sync and its index append.
4. **A partial last line in `checkpoints.jsonl`**, which must be the index line of state 3's checkpoint.
5. **A rotation cut short**: segment `n+1` exists and is empty, while `meta.json` still lists `n`. Segment `n` ends in an indexed checkpoint, because a seal checkpoints and syncs the index first.
6. **A new session cut before its first segment**: `meta.json` lists one segment, and the directory has none.

### What verify says

`verify_session` and `verify_jsonl` check the chain as today up to the tail. A tail in exactly one of states 2 to 6 makes the result **torn**, not broken.

Each torn state is checked for what a kill can produce:
- **A partial line** must follow the last newline, be no longer than the largest record line, and be in the newest segment only.
- **A partial index line** must be a prefix of the index line computed for the last checkpoint, byte for byte.
- **An unindexed checkpoint** must be the last line of all, and the index must list every checkpoint before it.
- **The extra segment** must be empty.

Anything else is broken as today: two torn states at once, a torn line anywhere but the end, or an index that names a checkpoint past the end.

The index keeps what it guarantees. A torn tail can hide nothing an attacker could not already hide by cutting at a record boundary, which verifies today. Everything up to the last indexed checkpoint is proven either way.

**Output:**
- **CLI:** `torn: N records, S segments, last seq n; the tail was cut (<what>): a crash, not a broken chain`. It exits 0, as a cut at a record boundary does.
- **`--json`:** `{"ok": true, "torn": {"kind": ..., "segment": ..., "offset": ..., "bytes": ...}, ...}`.
- **The reader** already stops quietly at a partial last line in the newest segment (`reader.rs:14-16`), and the writer's recovery already accepts states 2, 3 and 5. This brings verify into line with both.

### Core dumps

`SECCOMP_RET_KILL_PROCESS` dumps core where the limits allow. A core holds guest RAM, which may hold an agent's secrets, and is as large as that RAM. So guest memory is marked `MADV_DONTDUMP` once it is mapped (`vmm.rs`, after the regions are made). The rest of the core stays, for debugging.

## 5. The record, the flags, doctor

- **`vmm.start`** gains `hardening{seccomp, landlock}`: `"enforce"|"log"|"off"` and `"full"|"partial"|"unsupported"|"off"`.
  - It is optional, so `VmConfig::new` (the in-process tests) leaves it out, and the golden log stays unchanged.
  - The record is made in `Vmm::new`, before the filter is installed. If the install then fails, `vmm.stop{reason: "vmm_error"}` follows, so `enforce` in `vmm.start` never stands alone in a log whose VM ran unfiltered.
  - The size test grows by the field.
- **`--landlock enforce|off`**, default `enforce`, also read from `BOXCAR_LANDLOCK`. This flag is new; the M5 plan names only `--seccomp`, but its `"off"` value needs a way to happen. It is a way out when a path this plan missed stops a session.
- **`VmConfig`** gains `seccomp: SeccompMode` (default `Off`) and `hardening: Option<Hardening>` (default `None`). `boxcar run` sets both. A test process cannot take a process-wide filter (section 7).
- **`boxcar doctor`** adds:
  - **nested virtualization on WSL2**: when `/proc/sys/kernel/osrelease` names Microsoft or WSL and `/proc/cpuinfo` has neither `vmx` nor `svm`, it fails and prints the `.wslconfig` lines and `wsl --shutdown`;
  - **Landlock**: the ABI, or `MISS` with why (the kernel's `lsm=` list);
  - **seccomp**: whether `SECCOMP_RET_KILL_PROCESS` and `SECCOMP_RET_LOG` are available (`/proc/sys/kernel/seccomp/actions_avail`); it fails with `--seccomp off` as the hint, since `enforce` is the default;
  - **the image cache's free space** (`statvfs`), `MISS` under 2 GiB.

  Each check takes its input as a parameter, as the existing checks do. The misplaced doc comment above `cache_check` (`doctor.rs:250-255`) moves to `nofile_check`.
- **`docs/wsl2.md`**: nested virtualization, `.wslconfig`, `/dev/kvm` access, and what Landlock and seccomp look like under WSL's kernel.
- **`docs/audit-events.md`**: `vmm.start`'s new field. The README's section on what the log does and does not capture covers torn tails and seccomp kills.

## 6. Out of scope

- **Per-thread filters.** The M5 plan's decision stands: one list for the process.
- **Confining `boxcar` client commands** (`policy`, `audit`, `attach`, `image`).
- **Filtering `mmap`/`mprotect` for `PROT_EXEC`.**
- **Landlock's `CONNECT_TCP`.** The guest's flows connect anywhere the policy allows, and the policy changes live.
- **aarch64.**
- **The `audit.verify` control op**, which is Task 6's.

## 7. Tests

- **Unit, `hardening.rs`**:
  - every syscall named resolves on x86_64 (to a `libc::SYS_*` number);
  - the filter compiles in each mode;
  - `clone3` is answered `ENOSYS`.
- **In a child process.** The test binary runs itself again with an argument, as `tty_restore.rs` does, because a filter or a Landlock domain cannot be taken back in the test process:
  - Landlock is applied to a rule on one temporary directory. A thread started afterwards is refused a file outside it (`EACCES`) and allowed one inside.
  - The filter is installed in `enforce`. Threads started afterwards work: `clone3` → `ENOSYS` → `clone`. A call off the list ends the child with `SIGSYS`.
  - In `log`, the same call returns.
- **Verify, crashes made by killing a real child process at each point** (`boxcar-audit/tests`):
  - **(2)** `RLIMIT_FSIZE` set to each byte offset within the last flush: the write that crosses it is cut, and `SIGXFSZ` ends the child.
  - **(3)** A `Syncer` that sends itself `SIGKILL` right after the sync before an index append.
  - **(5) and (6)** `Syncer` gains `sync_dir`, so directory syncs go through it as well. A test syncer kills itself after the directory sync that follows a new segment, or a new session's `meta.json`.
  - **(4)** A partial index line cannot be cut by `RLIMIT_FSIZE`, because the segment file is always larger. It is made by truncating the index at each byte of its last line.
  - **States 2 to 6 verify as torn.** A cut at a record boundary verifies `ok`.
  - **Tampered tails stay broken:** a partial line in a segment before the last, two torn states together, a partial index line that is no prefix of its checkpoint's, an extra segment that is not empty.
  - **The CLI and `--json` output** for each.
- **Gated.** Every test in `kvm_m1` to `kvm_m5` runs the `boxcar` binary, whose defaults are `--seccomp enforce` and `--landlock enforce`, so the suites run confined:
  - `boot_*` in `boxcar-vmm` build the VM inside the test process and run unconfined, by `VmConfig`'s defaults.
  - New in `kvm_m5`:
    - `a_session_runs_confined`: `vmm.start.hardening` is `{enforce, full}` or `{enforce, partial}` as the kernel allows. A share is written. A device is reset and reactivated by the guest (`echo 1 > /sys/bus/virtio/devices/.../reset`, or the equivalent unbind and bind). The run ends cleanly.
    - `a_seccomp_kill_is_a_crash`: a `kvm-tests` build reads `BOXCAR_TEST_SECCOMP_TRIP` and makes one call off the list once the guest has run. The run dies by `SIGSYS`, with no `vmm.stop`. `boxcar audit verify` says `ok` or `torn`, never `fail`.
- **On the test box, recorded in the pull request:**
  - `test-kvm m5` (every suite) under `BOXCAR_SECCOMP=log`, with the kernel's log showing no seccomp record (type 1326) and no Landlock denial (type 1423) from `boxcar`;
  - then under the defaults, with every test passing and the Claude Code and Codex agent tests run.

## 7a. In-process tests and `TSYNC`

The nine `boxcar-vmm` `boot_*` test files run the VM inside the test binary. A process-wide filter installed there would bind libtest and every later test in that binary, and a Landlock domain would bind the test's temporary directories. So `VmConfig` keeps both off by default. The binary is confined by `boxcar run`, and the binary's gated tests are the ones the M5 plan's "every gated suite under `enforce`" counts. The `boot_*` tests run unconfined, and say so in their module docs.

## 8. Decisions (to the M5 plan's section 8 when the task ships)

- **The list is measured, then completed by reading the code.** A trace shows what the tests reached. The guest can reach more: every FUSE operation the passthrough serves, every socket path a flow takes, and device resets. A call off the list is a guest-triggered kill, so those come from the source. bpftrace replaced `strace -f -c`: it does not slow the timing-sensitive tests, and it counts by thread and by argument.
- **Landlock on ABI 8 and later uses `LANDLOCK_RESTRICT_SELF_TSYNC`.** The ordering before the first thread stays, for older kernels.
- **A torn tail exits 0, reported as `torn`.** It is the same event as a cut at a record boundary, which exits 0 today, plus a partial write. What it can hide is bounded by the index, as before.
- **Guest memory is `MADV_DONTDUMP`.** A kill must not write the guest's memory to disk.
- **`--landlock enforce|off`.** The M5 plan's record admits `"off"`, and a missed path needs a way out without a new build.
- **TCP binds and both scopes are handled.** The VMM uses none of them.
- **The `boot_*` tests run unconfined** (section 7a).

## 9. Review

To be filled in from Codex's adversarial review of this plan, before the code.
