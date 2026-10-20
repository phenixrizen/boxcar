# Confining the VMM with seccomp and Landlock (M5 Task 7, #29)

Branch `issue-29`, from `main` at f6c0dad. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`: section 3 (*Hardening*), section 4 (focus 7) and section 6, Task 7. Subject: `vmm: confine the VMM with seccomp and Landlock`.

The VMM process runs unconfined today. This task confines it two ways:
- **Landlock** limits which files the process can reach.
- **One seccomp allowlist** for the whole process limits which syscalls it can make. A syscall off the list kills the process.

Both are recorded in `vmm.start` as `hardening`. `boxcar audit verify` learns to report a log whose tail was cut mid-write as *incomplete*, apart from a broken chain, because a seccomp kill is a crash. `boxcar doctor` learns to check nested virtualization on WSL2, Landlock, seccomp and the image cache's free space. `docs/wsl2.md` is new. Section 9 records Codex's review of this plan's first draft and what it changed.

## 1. Where it sits

What the code does today, measured and read for this plan:
- **Threads.** `boxcar run` starts its first thread at `run.rs:285` (`job-control`, on a terminal only), then `audit-writer` (`run.rs:287`) and `reconcile` (`run.rs:386`), all before `Vmm::new` (`run.rs:400`). The M5 plan named only the last two. During an image pull, before all of these, ureq starts an unnamed resolver thread for each name it looks up and drops its handle (`ureq resolver.rs:147`). Such a thread can outlive the lookup that used it.
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
- **No credential switching.** `PassthroughFs` would call `setresuid`/`setresgid` around creating operations, but `AuditFs` hands it uid 0 and gid 0, so it never does (`boxcar-fs forward.rs:23-30`).
- **The syscalls, measured.** bpftrace on the test box traced every syscall of every process whose main thread is `boxcar`, over the whole `cargo xtask test-kvm m5` run (579 tests, all passing).
  - A first run counted everything; a second counted from each process's first `KVM_RUN`, and found 78 syscalls.
  - `ioctl`: `KVM_RUN`, `TCGETS`, `TCSETS`, `TIOCGPGRP`, `FIONREAD`, `FIONBIO`.
  - `socket`: `AF_INET` stream, and `AF_NETLINK` raw (`NETLINK_ROUTE`, from glibc's `getifaddrs`); `socketpair` is `AF_UNIX`.
  - `prctl`: `PR_SET_NAME` only.
  - `tgkill`: the vCPU kick (`SIGRTMIN`) and `SIGTSTP` only, each to this process.
  - No `execve`, and no `clone`, because glibc 2.39 starts threads with `clone3`.
  - The bpftrace program and the counts go into the pull request, not the repository.
- **The host binary is glibc's.** It is built for `x86_64-unknown-linux-gnu`; only the guest uses musl.
- **The kernel.** The test box now runs Linux 7.0 (Landlock ABI 8, which adds `LANDLOCK_RESTRICT_SELF_TSYNC`), not the 6.14 the M5 plan assumed. `landlock` 0.4.7 knows ABI 8 and 9.

## 2. Landlock

### Where

On the main thread at `run.rs:276-279`: after `ensure_sessions_root`, before `block_stop_signals` and before `job-control`. Every thread `boxcar run` starts on purpose starts after this point, so each one inherits the domain.

**Earlier threads.** A ureq resolver thread from the pull may still be running at this point:
- **On ABI 8 and later**, `restrict_self` also takes `LANDLOCK_RESTRICT_SELF_TSYNC` (`all_threads(true)`), which confines every thread.
- **Without it**, `run` counts the threads in `/proc/self/task`. While more than one runs, it waits up to 30 s for the others to end, then applies the domain. If one is still running after that, the run fails before the session starts, saying why.

So no thread runs outside the domain, as the M5 plan requires (section 4, focus 7).

### Before it

The directories the rules name must exist, so `run` makes them first:
- **The audit session directory.** `boxcar_audit` gains `prepare_session_dir(audit_dir, id)`. It makes `<audit>/sessions/<id>` (mode 0700, all the way down) and syncs its parent. `SegmentWriter::open_or_create` already takes an existing empty directory as a new session (`segment.rs:266-288`).
- **The state directory** (0700). `create_console_log`, the vsock device and the control server already accept an existing one.
- **The `--console-log PATH` file**, when it lies outside the state directory: opened with `O_CREAT`, without truncating.

`run` now owns cleaning up the directories it makes here, through a guard. Until now the vsock device and the control server removed the state directory only when they had made it, and a construction failure removed it only when the console log was in it (`run.rs:433`). The guard removes both directories, if empty, on every way out:
- a failure before the session starts;
- the end of the run, after `Vmm::run` returns.

### The rules

The ruleset handles every filesystem right of the newest ABI the crate knows (`AccessFs::from_all(ABI::V9)`), `CompatLevel::BestEffort`. It also handles:
- **TCP binds** (`AccessNet::BindTcp`, ABI 4), with no rule, so no TCP bind is allowed. The VMM listens on no TCP port. Its outbound TCP connections, UDP sockets and netlink sockets are not covered by this right.
- **Both scopes** (ABI 6): signals and abstract unix sockets outside the domain. The VMM signals only its own threads and uses no abstract sockets.

`EXECUTE` is granted nowhere, because the VMM runs no program.

| Path | Rights | Why |
|---|---|---|
| `<audit>/sessions/<id>` | all but `EXECUTE`, beneath | the log, the image copy, the default workspace |
| each share's host directory (`--rootfs`, `--workspace`) | all but `EXECUTE`, beneath | the guest's filesystem |
| the state directory | all but `EXECUTE`, beneath | sockets made, connected to and removed (`MAKE_SOCK`, `RESOLVE_UNIX`), `console.log` |
| the sessions root | `REMOVE_DIR`, beneath | the state directory's `rmdir` at the end |
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

### ABI 1

ABI 1 has no `REFER`, and refuses every rename or link from one directory to another while a domain is in force. The guest's `mv a/x b/` would fail. So a kernel whose best ABI is 1 (Linux 5.13 to 5.18) is treated as having no Landlock: the run goes on unconfined, with status `unsupported`.

### Status and failure

The `RestrictionStatus` becomes one of:
- `full` when every handled right is enforced;
- `partial` when the kernel enforces only some of them: on 7.0, everything but `RESOLVE_UNIX`;
- `unsupported` when there is no Landlock, or only ABI 1; the run goes on;
- `off` with `--landlock off`.

Any other error fails the run before the session starts, with a hint naming `--landlock off`. A rule that cannot be opened is one example; a thread that outlives the 30 s wait is another.

## 3. seccomp

### Where

In `Vmm::new`, after the last KVM setup call (`create_vcpus`, `vmm.rs:590`) and before `vmm.start` is recorded (`vmm.rs:643`): one filter, `SECCOMP_FILTER_FLAG_TSYNC`, built with `seccompiler` 0.5. Every running thread and every later one has it, including the vCPU threads, which start under it.

Several steps now run under the filter that ran before it in the first draft:
- the control socket's bind;
- `run`'s ready line and terminal attach;
- `Vmm::start`'s setup.

Their calls are on the list. `vmm.start`'s `hardening.seccomp` is then a fact, not an intent. If the install fails, `Vmm::new` fails before anything of the session is recorded or the guest has run, and `run` reports the error.

### Modes

`--seccomp enforce|log|off`, default `enforce`, also read from `BOXCAR_SECCOMP`. The flag wins over the variable.
- **`enforce`**: a call off the list is `SECCOMP_RET_KILL_PROCESS`.
- **`log`**: `SECCOMP_RET_LOG`, so the kernel's audit log names each call off the list while the run goes on. This is how the list is checked and extended.
- **`off`**: installs nothing.

`clone3` is answered `ENOSYS` in both `enforce` and `log`. Its flags sit in memory a filter cannot read, so glibc falls back to `clone`, and `clone` is filtered by its flags.

The list is built for x86_64 glibc (`target_env = "gnu"`). On any other target, `enforce` and `log` fail with a message, and `off` runs. musl, for one, signals threads with `tkill`, which this list does not allow.

### The list

It lives in `crates/boxcar-vmm/src/hardening.rs`, in groups, with a comment on each saying who makes the calls. It is the union of four sources:
1. **What was measured** (section 1).
2. **What the guest can reach but the suites never made**, read from the code. A guest that can make the VMM issue a call off the list can kill it:
   - every FUSE operation `PassthroughFs` serves through `AuditFs` (`fuse-backend-rs` 0.14 `passthrough/{sync_io,mod,util,statx}.rs`), and `AuditFs`'s own `fstatat` and the hasher's `openat2`;
   - every socket call of a TCP, UDP or DNS flow, its errors and its `SO_LINGER` reset;
   - the vsock muxer's connects, accepts and resets;
   - a device reset and reactivation from the guest, which starts threads, makes eventfds, epolls and timerfds, and remakes the DNS forwarder's socket on a vCPU thread.
3. **Rare host paths no test reached**:
   - the vCPU failure path: `KVM_GET_REGS`, `KVM_GET_SREGS`;
   - a terminal resize: `TIOCGWINSZ`;
   - measuring the output queue at the stop: `TIOCOUTQ`;
   - the audit writer's rotation at 256 MiB: `rename` of `meta.json.tmp`, a directory `fsync`;
   - its failure path: `ftruncate`;
   - `abort`: `rt_sigaction`, `rt_sigprocmask`, `tgkill` to itself;
   - the main thread's heap growing: `brk`.
4. **Alternatives in glibc** for a call the code makes, so the list does not hang on one glibc version:
   - `poll`/`ppoll`;
   - `epoll_wait`/`epoll_pwait`/`epoll_pwait2`;
   - `clock_nanosleep`/`nanosleep`;
   - `accept`/`accept4`;
   - `read`/`readv`/`pread64`/`preadv` and their writes;
   - `rename`/`renameat`/`renameat2`;
   - `clock_gettime`/`gettimeofday` (the vDSO's fallbacks).

The list, by group:

| Group | Calls |
|---|---|
| memory | `brk`, `mmap`, `munmap`, `mremap`, `mprotect`, `madvise` |
| threads | `clone` (filtered), `exit`, `exit_group`, `futex`, `set_robust_list`, `rseq`, `sigaltstack`, `sched_yield`, `sched_getaffinity`, `gettid`, `getpid`, `getpgrp`, `prctl` (filtered) |
| signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `restart_syscall`, `tgkill` (filtered), `signalfd4` |
| time | `clock_gettime`, `clock_getres`, `gettimeofday`, `nanosleep`, `clock_nanosleep`, `timerfd_create`, `timerfd_settime` |
| randomness | `getrandom` |
| events | `eventfd2`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`, `poll`, `ppoll` |
| descriptors | `close`, `dup`, `fcntl`, `ioctl` (filtered) |
| reads and writes | `read`, `write`, `readv`, `writev`, `pread64`, `pwrite64`, `preadv`, `pwritev`, `lseek` |
| files (the shares, the log, the dumps) | `openat`, `openat2`, `newfstatat`, `fstat`, `statx`, `fstatfs`, `getdents64`, `mkdirat`, `mknodat`, `symlinkat`, `linkat`, `unlinkat`, `unlink`, `rmdir`, `rename`, `renameat`, `renameat2`, `readlinkat`, `chmod`, `fchmod`, `fchmodat`, `fchownat`, `utimensat`, `ftruncate`, `fallocate`, `fsync`, `fdatasync`, `umask` |
| extended attributes (paths through `/proc/self/fd`) | `getxattr`, `setxattr`, `listxattr`, `removexattr` |
| sockets | `socket` (filtered), `socketpair` (filtered), `bind`, `listen`, `accept`, `accept4`, `connect`, `getsockname`, `getpeername`, `getsockopt`, `setsockopt`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown` |
| answered `ENOSYS` | `clone3` |

**Arguments are filtered** for the calls the M5 plan names, and for two more:
- **`ioctl`**, by request number: `KVM_RUN`, `KVM_GET_REGS`, `KVM_GET_SREGS`, `TCGETS`, `TCSETS`, `TIOCGPGRP`, `TIOCGWINSZ`, `TIOCOUTQ`, `FIONREAD`, `FIONBIO`. They are compared as 32-bit values: the kernel reads `cmd` as an `unsigned int`.
- **`socket`**, by family: `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK` with protocol `NETLINK_ROUTE` only.
- **`socketpair`**: `AF_UNIX` only. New.
- **`clone`**: `CLONE_THREAD` must be set, so it starts threads and never processes.
- **`prctl`**: `PR_SET_NAME` only.
- **`tgkill`**: the thread group must be this process. The filter is built at run time, so it knows the pid. New.

A unit test checks that every name resolves to a `libc::SYS_*` number on x86_64. Section 7's run under `log` checks that nothing a test reaches is missing.

### KVM after the filter

The VM is built before the filter, so `KVM_CREATE_*`, `KVM_SET_*`, `KVM_IRQFD` and `KVM_IOEVENTFD` stay off the list. A device reset and reactivation reuses its eventfds, and registers nothing with KVM again (`boxcar-virtio mmio.rs:435`, `context.rs:66`). Section 7's reset test shows it under `enforce`.

## 4. Crashes and verify

### What a kill leaves

A seccomp kill, like any `SIGKILL`, keeps every completed `write(2)` (the page cache survives) and loses the rest. Given the writer's order (`writer.rs:399-485`, `checkpoint.rs:20-24`), and its failure path once rolling back is reordered (below), the log can be left only in these states:
1. **Cut at a record boundary**: bytes still in the writer's buffer are lost. This verifies today, and nothing can tell it from a clean end except the missing `vmm.stop`.
2. **A partial last line in the newest segment**: a `write_all` cut short. The kernel stops copying once a fatal signal is pending.
3. **A checkpoint that is the last line of the newest segment, with no index line**: killed between the checkpoint's sync and its index append. The same state arises when killed halfway through the failure path's rollback (below).
4. **A partial last line in `checkpoints.jsonl`**, which must be the index line of a state-3 checkpoint.
5. **A rotation cut short**: segment `n+1` exists and is empty, while `meta.json` still lists `n`. Segment `n` ends in an indexed checkpoint, because a seal checkpoints and syncs the index first.
6. **A new session cut before its first segment**: `meta.json` lists one segment, and the directory has none.

**The failure path, reordered.** When a write fails, the writer rolls back. Today it truncates the segment first and then the index (`writer.rs:318`). A kill between the two would leave a partial index line whose checkpoint is gone, a state no ordinary kill produces. The rollback now cuts the index first, so a kill between the two leaves state 3. Recovery is not in this list: it runs only when a writer reopens a session, and `boxcar run` never does (`run.rs:193`).

### What verify says

`verify_session` and `verify_jsonl` check the chain as today up to the tail. A tail in exactly one of states 2 to 6 makes the result **incomplete**, not broken.

Each state is checked for what a kill can produce:
- **A partial line** must follow the last newline, be no longer than the largest record line, and be in the newest segment only.
- **A partial index line** must be a prefix of the index line computed for the last checkpoint, byte for byte.
- **An unindexed checkpoint** must be the last line of all, and the index must list every checkpoint before it.
- **The extra segment** must be empty.

Anything else stays broken as today:
- two of these states at once;
- a partial line anywhere but the end;
- an index line naming a checkpoint past the end.

**Verify cannot prove the cause.** A crash and a deliberate cut can leave the same tail, so verify says only what it proved:
- **CLI:** `incomplete: N records verified, S segments, last seq n; the tail is cut (<what>), cause unknown`, exiting with a code of its own, `4`.
- **`--json`:** `{"ok": false, "incomplete": {"kind": ..., "segment": ..., "offset": ..., "bytes": ...}, "records": ..., ...}`.

An incomplete tail can hide no more than a cut at a record boundary already can, which verifies `ok`. The index still proves everything up to the last indexed checkpoint, and an index line past the end stays broken.

The reader already stops quietly at a partial last line in the newest segment (`reader.rs:14-16`).

### Core dumps

`SECCOMP_RET_KILL_PROCESS` dumps core where the limits allow. A core holds guest RAM, which may hold an agent's secrets, and is as large as that RAM. So every guest memory region, high memory included, is marked `MADV_DONTDUMP` once it is mapped (`memory.rs:35`). A failure is an error, like any other step of the build. The rest of the core stays, for debugging. A unit test reads the mapping's flags back from `/proc/self/smaps`; where a core goes (a file, systemd-coredump, apport) is the host's, so no gated test looks for one.

## 5. The record, the flags, doctor

- **`vmm.start`** gains `hardening{seccomp, landlock}`: `"enforce"|"log"|"off"` and `"full"|"partial"|"unsupported"|"off"`.
  - It is optional, so the golden log stays unchanged.
  - With the filter installed before the record (section 3), both values are facts.
  - The size test grows by the field.
- **`--landlock enforce|off`**, default `enforce`, also read from `BOXCAR_LANDLOCK`; the flag wins. This flag is new; the M5 plan names only `--seccomp`, but its `"off"` value needs a way to happen. It is a way out when a path this plan missed stops a session.
- **`VmConfig`** gains:
  - `seccomp: SeccompMode`, default `Off`;
  - `landlock: Option<LandlockStatus>`, what `run` applied, for the record;
  - `hardening` is recorded only when either is set.
- **`boxcar doctor`** adds:
  - **nested virtualization on WSL2**: when `/proc/sys/kernel/osrelease` names Microsoft or WSL and `/proc/cpuinfo` has neither `vmx` nor `svm`, it fails and prints the `.wslconfig` lines and `wsl --shutdown`;
  - **Landlock**: the ABI, or `MISS` with why (no Landlock in the kernel's `lsm=` list, or ABI 1);
  - **seccomp**: whether `SECCOMP_RET_KILL_PROCESS` and `SECCOMP_RET_LOG` are available (`/proc/sys/kernel/seccomp/actions_avail`); it fails with `--seccomp off` as the hint, since `enforce` is the default;
  - **the image cache's free space** (`statvfs`), `MISS` under 2 GiB.

  Each check takes its input as a parameter, as the existing checks do. The misplaced doc comment above `cache_check` (`doctor.rs:250-255`) moves to `nofile_check`.
- **`xtask test-kvm`** refuses to run with `BOXCAR_SECCOMP=off` or `BOXCAR_LANDLOCK=off`, and prints the modes it runs under, so an inherited setting cannot quietly weaken a run.
- **`docs/wsl2.md`**: nested virtualization, `.wslconfig`, `/dev/kvm` access, and what Landlock and seccomp look like under WSL's kernel.
- **`docs/audit-events.md`**: `vmm.start`'s new field. The README's section on what the log does and does not capture covers incomplete logs and seccomp kills, and `boxcar audit verify --help` gives its exit codes.

## 6. Out of scope

- **Per-thread filters.** The M5 plan's decision stands: one list for the process.
- **Confining `boxcar` client commands** (`policy`, `audit`, `attach`, `image`).
- **Filtering `mmap`/`mprotect` for `PROT_EXEC`.**
- **Landlock's `CONNECT_TCP`.** The guest's flows connect anywhere the policy allows, and the policy changes live.
- **aarch64, and host builds against musl.**
- **The `audit.verify` control op**, which is Task 6's.

## 7. Tests

### Unit, `hardening.rs` and the Landlock module

- Every syscall named resolves on x86_64 (to a `libc::SYS_*` number).
- The filter compiles in each mode.
- `clone3` is answered `ENOSYS`.
- The mode decisions:
  - ABI 0 and 1 give `unsupported`;
  - a partial ruleset gives `partial`;
  - the thread wait gives up after its timeout.

### In a child process

The test binary runs itself again with an argument, as `tty_restore.rs` does, because a filter or a domain cannot be taken back in the test process.

**Landlock:**
- A thread started afterwards is refused a file outside the one allowed directory (`EACCES`) and allowed one inside.
- **TSYNC**: a sibling thread started before and kept waiting is confined once released.
- **Without TSYNC**, forced through a test knob:
  - a sibling that ends within the wait lets the domain apply;
  - one that does not makes it fail.

**seccomp:**
- **TSYNC**: a sibling started before the filter and kept waiting dies with `SIGSYS` when it makes a call off the list.
- Threads started afterwards work: `clone3` → `ENOSYS` → `clone`.
- A call off the list ends the child with `SIGSYS`.
- In `log`, the same call returns.
- `abort` under the filter ends the child with `SIGABRT`, not `SIGSYS`.

### Verify, crashes made by killing a real child process at each point

These are in `boxcar-audit/tests`. Each limit is armed after the child's setup, and each test asserts the signal that ended the child.
- **(2)** `RLIMIT_FSIZE` set to each byte offset within the last flush: the write that crosses it is cut, and `SIGXFSZ` ends the child.
- **(3)** A `Syncer` that sends itself `SIGKILL` right after the sync before an index append.
- **(5) and (6)** `Syncer` gains `sync_dir`, so directory syncs go through it as well. A test syncer kills itself after the directory sync that follows a new segment, or a new session's `meta.json`.
- **(4), and the two sides of the reordered rollback**, which no signal can cut reliably: made by truncating the files at each byte. The index's last line is cut, and the state between the index's rollback and the segment's is built.

Then:
- **States 2 to 6 verify as incomplete.** A cut at a record boundary verifies `ok`.
- **Tampered tails stay broken:**
  - a partial line in a segment before the last;
  - two of the states together;
  - a partial index line that is no prefix of its checkpoint's;
  - an extra segment that is not empty;
  - an index line past the end.
- **The CLI's line, its exit code and the `--json` output** for each.

### Gated

**Every `kvm_m1` to `kvm_m5` test runs the `boxcar` binary**, confined by its defaults: `--seccomp enforce`, `--landlock enforce`.

**Every `boot_*` test in `boxcar-vmm` runs confined too:**
- **How:** each builds its VM in a child copy of the test binary, with `VmConfig.seccomp = Enforce`. A helper (`confined(test_name, body)`) runs the test again in a child with `--exact`. The child runs the body, then `_exit(0)` from the test thread, so libtest's own bookkeeping never runs under the filter. The parent asserts that the child exited 0, and names the signal when one ended it.
- **Why:** a filter installed in the test process itself would bind libtest and every later test in that binary.
- **Landlock** is `run`'s, so the `boot_*` tests cover seccomp, and `kvm_m*` covers both.

**New:**
- **`boot_reset.rs`** (in-process, confined, with the guest session as root, which `SessionConfig::for_user(argv, 0, 0)` allows): each device is unbound and bound again through the guest's sysfs, one at a time, and then used:
  - the net card, then a DNS lookup and a TCP connection through the stack;
  - the workspace's virtio-fs, unmounted first, then mounted again and written;
  - the vsock device: the session's channel goes and the session ends (`ctl.rs:17`), and the VMM must stop cleanly, recording `vmm.stop`, not die by `SIGSYS`.
- **`kvm_m5`**:
  - `a_session_runs_confined`: `vmm.start.hardening` is what the run's lane asks: `BOXCAR_SECCOMP`, else `enforce`, and `full` or `partial` as the kernel allows.
  - `a_seccomp_kill_is_a_crash`, run with `--seccomp enforce` on its command line: a `kvm-tests` build reads `BOXCAR_TEST_SECCOMP_TRIP` and makes one call off the list once the guest has run. The run dies by `SIGSYS`, with no `vmm.stop`. `boxcar audit verify` says `ok` or `incomplete`, never `fail`.

### Lanes on the test box, recorded in the pull request

1. `test-kvm m5` (every suite) with `BOXCAR_SECCOMP=log`. Afterwards the kernel's log shows no seccomp record (type 1326) from `boxcar` but the trip's own, and no Landlock denial (type 1423).
2. `test-kvm m5` with the defaults: every test passes, the Claude Code and Codex agent tests run, and the kernel's log again shows no Landlock denial.

## 8. Decisions (to the M5 plan's section 8 when the task ships)

- **The list is measured, then completed by reading the code.** A trace shows what the tests reached. The guest can reach more: every FUSE operation the passthrough serves, every socket path a flow takes, and device resets. A call off the list is a guest-triggered kill, so those calls come from the source.
- **bpftrace replaced `strace -f -c`.** It does not slow the timing-sensitive tests, and it counts by thread and by argument.
- **The filter goes in before `vmm.start` is recorded**, in `Vmm::new`, so the record states what is in force.
- **glibc only.** The list is glibc's, and the host binary is built against glibc.
- **Landlock confines every thread or the run does not start.** On ABI 8 and later, `LANDLOCK_RESTRICT_SELF_TSYNC` covers every thread. Without it, `run` waits up to 30 s for threads from before the point (ureq's resolvers) to end, then refuses. ABI 1 counts as no Landlock: without `REFER` it breaks renames across directories.
- **A cut tail is "incomplete, cause unknown", with exit code 4.** Verify cannot tell a crash from a deliberate cut. What it can hide is bounded by the index, as for a cut at a record boundary.
- **The writer's rollback cuts the index before the segment**, so a kill halfway leaves a state a crash can produce.
- **Guest memory is `MADV_DONTDUMP`.** A kill must not write the guest's memory to disk.
- **`--landlock enforce|off`, and `BOXCAR_SECCOMP`/`BOXCAR_LANDLOCK`.** The M5 plan's record admits `"off"`, and a missed path needs a way out without a new build. The variables let a whole suite run under `log`. `xtask test-kvm` refuses `off`.
- **TCP binds and both scopes are handled.** The VMM uses none of them.
- **The `boot_*` tests run confined, each in a child of the test binary**, so `test-kvm`'s every suite runs under `enforce`.

## 9. Review (2026-10-20, before the code)

Codex (`codex exec`, read-only, reasoning effort xhigh) reviewed the first draft (3b09ec7) against the code. Its findings, and what changed:

1. **`tkill` under musl** (HIGH): musl's `pthread_kill` and `raise` use `tkill`. The host binary is glibc's, so the list is declared glibc-only, and other targets refuse `enforce` and `log` (section 3).
2. **A resolver thread outside Landlock** (HIGH): ureq drops its resolver's handle, so a thread can outlive the pull. TSYNC is used where the kernel has it; otherwise `run` waits, then refuses. The first draft only recorded `partial` (section 2).
3. **Unconfined `boot_*` tests miss the issue's "Done when"** (HIGH): `test-kvm` runs them. Each now runs confined in a child copy of the test binary. Added a test of TSYNC on a sibling that already runs (section 7).
4. **ABI 1 breaks renames across directories** (MEDIUM): it counts as unsupported (section 2).
5. **The list was not in the plan** (MEDIUM): it is now, with its arguments and its four sources. Credential switching is off (section 1), so `setresuid` is not on it.
6. **The rollback's order, and recovery** (MEDIUM): the rollback cuts the index first, so a kill halfway leaves state 3. Recovery never runs for `boxcar run`. The kill tests arm their limits after setup and assert the signal (section 4).
7. **"A crash" claims too much** (MEDIUM): verify now says "incomplete … cause unknown" and exits 4 (section 4).
8. **`vmm.start` recorded an intent** (MEDIUM): the filter goes in before the record (section 3).
9. **The reset test** (MEDIUM): resetting vsock ends the session by design. The test is now in-process with a root guest session, one device at a time, each used afterwards; for vsock, a clean stop is what it proves (section 7).
10. **Who removes pre-made directories** (LOW): `run` owns them through a guard on every way out (section 2).
11. **The `log` lane contradicts tests that need `enforce`** (LOW): those tests say `--seccomp enforce` themselves, the flag wins over the variable, and `test-kvm` refuses `off` and prints its modes (sections 5 and 7).

Codex also confirmed:
- an existing empty session directory is taken as new;
- a device reset reuses its eventfds and registers nothing with KVM again;
- denying TCP binds leaves outbound connections and UDP alone;
- `MADV_DONTDUMP` fits the anonymous guest mappings.
