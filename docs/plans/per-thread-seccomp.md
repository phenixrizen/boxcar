# Per-thread seccomp filters for the VMM (#34)

Branch `issue-34`, from `main`. The M5 plan (`docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 8) and the hardening plan (`docs/plans/vmm-hardening.md`, section 6) decided on **one seccomp allowlist for the whole process**, and set per-thread filters aside: a filter per thread role, each from that role's own syscall inventory and installed by the thread itself, as Firecracker does. This plan is that work. Subject: `vmm: a seccomp filter per thread role`.

Today every thread of `boxcar run` can make every syscall any thread needs: the net thread can `openat` a file, a virtio-fs queue thread can `connect` a socket, the audit writer can `ioctl(KVM_RUN)`. The process list is the union of all roles' needs. A filter per role narrows each thread to its own, so that a flaw in one device model is held to that device's calls.

## 1. What is measured

The hardening task traced every syscall of every `boxcar` process over `cargo xtask test-kvm m5`, by thread name, from each process's first `KVM_RUN` on (`/dev/shm/syscalls-run.bt` on the test box, 2026-10-20, at f6c0dad: 579 tests). The counts by thread are in the appendix. The threads, and who starts them (read from the spawn sites, `thread::Builder::new().name(...)`, and confirmed by the trace: a thread that spawns makes `clone3` and `prctl`):

- **`boxcar`**, the main thread: starts the vCPUs, the control socket's acceptor, the PTY threads, the guest control channel's three threads, the audit writer, the sensor's reader, the console, `tell`, `winch`, `job-control`, `graceful-stop`, `events-signals`, the dump writer and the reconciler.
- **`vcpu<N>`**: on the guest's virtio-mmio status write, activates a device, which spawns its workers: **`net`**, **`vsock`**, **`fs-<tag>-q<N>`**. The trace shows `clone3`, `prctl`, `eventfd2`, `epoll_create1` and `timerfd_create` on `vcpu0`: the device's event loop is made and its thread started on the vCPU thread.
- **`control-accept`** starts a **`control-conn`** per client; a connection starts an **`audit-forward`** per subscription.
- **`fs-<tag>-hash<N>`** are started with the device, not by the queue threads (no `clone` in their trace).
- Everything else spawns nothing.

## 2. The constraint: filters are inherited

A seccomp filter installed on a thread is inherited by every thread it later creates. A thread may add filters, never remove one; the kernel runs them all and takes the strictest answer. So a role may be given a filter only if that filter also allows everything the threads it spawns need, transitively; or the spawning must move to a thread whose filter allows it.

That rules out a tight filter for the vCPU threads as the code stands: a vCPU spawns `net`, `vsock` and the virtio-fs queues, whose union is nearly the process list. The same holds for `control-accept` and `control-conn`, whose children (`control-conn`, `audit-forward`) are narrow, so their own lists simply include the children's.

## 3. Design

- **The process list stays** as the floor, installed with `TSYNC` once the VM is built, as today. A role's filter is a second (or third) filter on its own thread, installed by the thread at its start with no `TSYNC`, under the same mode (`--seccomp enforce` kills, `log` logs, `off` installs nothing). Every role's list is a subset of the process list: a thread never gains a call the process forbids (a unit test holds this).
- **Roles** (`hardening::seccomp::Role`), one per thread name prefix, each with a list measured from the trace and completed from the code's rare paths, as the process list was (a failed write, a resize, the log's rotation, `abort`):
  - `Net` (`net`): the user-mode stack, the gate's TLS legs, the DNS resolver: sockets, `epoll`, `timerfd`, `getrandom`, memory, threads; no files.
  - `Observe` (`gate-observe`) and `Dump` (`dump`): memory, `futex`, the dump files' `openat`, `write`, `fdatasync`; no sockets.
  - `Vsock` (`vsock`): unix sockets and `socketpair`, `ioctl(FIONBIO)`, `epoll`; no files, no inet sockets.
  - `FsQueue` (`fs-*-q*`): the passthrough's file calls (`openat`, `openat2`, `statx`, `getdents64`, `preadv`, `pwritev`, the renames and links, xattrs, `fallocate`, `utimensat`), `futex`; no sockets.
  - `FsHash` (`fs-*-hash*`): `openat2`, `read`, `pread64`, `fstat`, `close`, `futex`; nothing else.
  - `AuditWriter` (`audit-writer`): `write`, `fdatasync`, `ftruncate`, `openat`, `rename`, `statx`, `fsync`, `futex`.
  - `AuditForward` (`audit-forward`): `read`, `openat`, `lseek`, `sendto`, `statx`, `futex`.
  - `ControlAccept` (`control-accept`) and `ControlConn` (`control-conn`): the unix socket's `accept4`, `getsockopt` (`SO_PEERCRED`), `read`, `sendto`, `shutdown`, `fcntl`, `epoll`, `clone`/`clone3` and `prctl` for the threads they start, and the union of those threads' lists.
  - `GuestCtl` (`guest-ctl-rx`, `-tx`, `-sync`), `SensorRx` (`sensor-rx`): `read`, `recvfrom`, `sendto`, `futex`, `clock_nanosleep`.
  - `Pty` (`pty-hub`, `pty-stdin`, `pty-stdout`, `pty-attach`), `Console` (`console`): `read`, `write`, `poll`, `ioctl` on the terminal, `openat` for the console log.
  - `Reconcile` (`reconcile`), `Tell` (`tell`): memory, `futex`, `write`, `nanosleep`.
  - The vCPUs, the main thread, `winch`, `job-control`, `graceful-stop`, `events-signals` and `seccomp-trip` (a test's) keep the process list in this task. A later task moves device activation's spawn to a spawner thread, after which the vCPUs get a list of their own (`ioctl` by request, `write` to the kick eventfds, `rt_sigreturn`, `futex`, memory).
- **`confine_thread(role)`** (`crates/boxcar-vmm/src/hardening/seccomp.rs`): builds the role's filter and applies it to the calling thread with `seccompiler::apply_filter` (no `TSYNC`); a no-op under `off`, before the mode is known, and before the process list is in. The mode is set once, early, by `boxcar run` (`hardening::seccomp::set_mode`, before any thread is spawned); the process floor comes with `TSYNC` at `Vmm::new`, as today, and only the threads started after it add their role's filter: `TSYNC` fails for a thread whose filters differ from the installer's (the lane showed it: *Seccomp filter synchronization failed in thread N*), so the order is the process list first, then each later thread's own. The threads started before the VM is built (the audit writer, the control socket's acceptor, the terminal's, the hashers, `tell`) keep the process list; the device workers, the guest channels, the connections and the subscriptions start after it. Each spawn site's closure calls `confine_thread(Role::X)` as its first statement; the crates outside `boxcar-vmm` (`boxcar-net`, `boxcar-fs`, `boxcar-vsock`, `boxcar-audit`) take a `confine: fn()` (or an `Arc<dyn Fn()>`) with their spawn configuration, so they stay free of the VMM's policy, and the VMM passes the role's closure.
- **The record.** `vmm.start`'s `hardening` gains `seccomp_threads` (the roles confined, as a list), so a log says what each thread could do.

## 4. Modes and lanes

As for the process list: a `log` lane on the test box first, where a call off a role's list is logged (`audit_seccomp` with the thread's name, which `/dev/shm/lanes.bt` already keys on) and the test still passes; every logged call is read, added where it belongs or shown to be a test's deliberate trip; then the `enforce` lane. Both lanes' outputs go in the pull request.

## 5. Tests

- **Unit** (`seccomp.rs`): every role's list is a subset of the process list; every role names each call once; the filters build in both modes; `confine_thread` before `set_mode` installs nothing.
- **In a child process** (`tests/confined`, as the hardening task's): a child sets the mode, spawns a thread for a role, confines it and makes a call off that role's list but on the process list: killed under `enforce`, logged under `log`. One per role whose list is narrowest.
- **Gated**: the lanes, and `a_session_runs_confined` reading `seccomp_threads` from `vmm.start`.

## 6. Out of scope

- The vCPU threads' own list (needs the spawner, above), and the main thread's.
- Filtering by argument beyond what the process list filters today.
- aarch64, musl.

## 7. Docs

`docs/architecture.md`'s seccomp paragraph; `docs/audit-events.md`'s `vmm.start` row; `docs/plans/vmm-hardening.md` section 6 and the M5 plan's section 8 record the change.

## 8. Decisions

- **Filters stack; the process list stays the floor.** A role's filter narrows, never widens.
- **A role must cover what it spawns.** The vCPUs stay on the process list until activation's spawn moves off them.
- **Lists come from the trace, then the code**, as the process list did; the trace is re-run on the tree this task changes before the lanes.
- **The process list lets a thread add a filter of its own**: `seccomp(SECCOMP_SET_MODE_FILTER)` without flags and `prctl(PR_SET_NO_NEW_PRIVS)`, which the role's install makes under it. The log lane showed every role logging exactly those two calls, and `getpgrp` on the terminal's threads, and nothing else; a filter added so can only narrow.

## Appendix: the trace, by thread (2026-10-20, f6c0dad)

| Thread | Calls | Syscalls |
|---|---|---|
| `audit-forward` | 17 | read, close, lseek, mmap, mprotect, munmap, rt_sigprocmask, madvise, sendto, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity, openat, statx |
| `audit-writer` | 14 | write, close, mprotect, munmap, rt_sigprocmask, madvise, exit, fcntl, fdatasync, ftruncate, sigaltstack, futex, restart_syscall, statx |
| `boxcar` | 26 | read, write, close, munmap, rt_sigprocmask, ioctl, getpid, sendto, shutdown, fcntl, rmdir, unlink, getpgrp, sigaltstack, prctl, futex, clock_nanosleep, exit_group, epoll_wait, epoll_ctl, tgkill, set_robust_list, timerfd_settime, signalfd4, rseq, clone3 |
| `console` | 10 | write, close, munmap, rt_sigprocmask, madvise, exit, fcntl, sigaltstack, futex, clock_nanosleep |
| `control-accept` | 22 | read, close, poll, mmap, mprotect, munmap, rt_sigprocmask, ioctl, madvise, sendto, getsockopt, exit, fcntl, sigaltstack, prctl, futex, restart_syscall, set_robust_list, accept4, eventfd2, rseq, clone3 |
| `control-conn` | 25 | read, write, close, poll, mmap, mprotect, munmap, rt_sigprocmask, sched_yield, madvise, getpid, sendto, recvfrom, shutdown, exit, fcntl, sigaltstack, prctl, gettid, futex, sched_getaffinity, openat, set_robust_list, rseq, clone3 |
| `dump` | 10 | write, close, munmap, rt_sigprocmask, sched_yield, madvise, exit, fcntl, sigaltstack, futex |
| `fs-root-hash0` | 12 | read, close, fstat, munmap, rt_sigprocmask, sched_yield, madvise, exit, fcntl, sigaltstack, futex, 437 |
| `fs-root-hash1` | 12 | read, close, fstat, munmap, rt_sigprocmask, sched_yield, madvise, exit, fcntl, sigaltstack, futex, 437 |
| `fs-root-q1` | 36 | read, write, close, lseek, mmap, mprotect, munmap, rt_sigprocmask, madvise, dup, exit, fcntl, ftruncate, umask, sigaltstack, fstatfs, gettid, getxattr, futex, sched_getaffinity, getdents64, epoll_wait, openat, mkdirat, mknodat, newfstatat, unlinkat, symlinkat, readlinkat, fchmodat, utimensat, preadv, pwritev, renameat2, getrandom, statx |
| `fs-workspace-ha` | 12 | read, close, fstat, munmap, rt_sigprocmask, sched_yield, madvise, exit, fcntl, sigaltstack, futex, 437 |
| `fs-workspace-q1` | 36 | read, write, close, lseek, mmap, mprotect, munmap, rt_sigprocmask, madvise, dup, exit, fcntl, fsync, fdatasync, ftruncate, umask, sigaltstack, gettid, getxattr, futex, sched_getaffinity, getdents64, epoll_wait, openat, mkdirat, newfstatat, unlinkat, symlinkat, readlinkat, fchmodat, utimensat, preadv, pwritev, renameat2, getrandom, statx |
| `gate-observe` | 15 | read, write, close, mmap, mprotect, munmap, rt_sigprocmask, sched_yield, mremap, madvise, exit, fcntl, sigaltstack, futex, openat |
| `graceful-stop` | 10 | mmap, mprotect, munmap, rt_sigprocmask, madvise, exit, sigaltstack, gettid, sched_getaffinity, clock_nanosleep |
| `guest-ctl-rx` | 14 | close, mmap, mprotect, munmap, rt_sigprocmask, madvise, recvfrom, shutdown, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity |
| `guest-ctl-sync` | 8 | munmap, rt_sigprocmask, madvise, exit, sigaltstack, futex, restart_syscall, clock_nanosleep |
| `guest-ctl-tx` | 13 | close, mmap, mprotect, munmap, rt_sigprocmask, madvise, sendto, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity |
| `job-control` | 9 | read, poll, rt_sigaction, rt_sigprocmask, ioctl, getpid, getpgrp, gettid, tgkill |
| `net` | 30 | read, write, close, mmap, mprotect, munmap, rt_sigprocmask, writev, madvise, socket, connect, sendto, recvfrom, recvmsg, shutdown, bind, getsockname, getpeername, setsockopt, getsockopt, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity, epoll_wait, epoll_ctl, timerfd_settime, getrandom |
| `pty-hub` | 19 | read, close, poll, mmap, mprotect, munmap, rt_sigprocmask, ioctl, madvise, sendto, recvfrom, shutdown, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity, restart_syscall |
| `pty-stdin` | 18 | read, write, close, poll, mmap, mprotect, munmap, rt_sigprocmask, ioctl, madvise, exit, fcntl, getpgrp, sigaltstack, gettid, sched_getaffinity, restart_syscall, clock_nanosleep |
| `pty-stdout` | 17 | read, write, close, poll, mmap, mprotect, munmap, rt_sigprocmask, madvise, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity, restart_syscall, openat |
| `reconcile` | 8 | mprotect, munmap, rt_sigprocmask, madvise, exit, sigaltstack, futex, restart_syscall |
| `sensor-rx` | 13 | close, mmap, mprotect, munmap, rt_sigprocmask, madvise, recvfrom, exit, fcntl, sigaltstack, gettid, futex, sched_getaffinity |
| `tell` | 11 | write, mmap, mprotect, munmap, rt_sigprocmask, madvise, exit, sigaltstack, gettid, futex, sched_getaffinity |
| `vcpu0` | 22 | write, close, mmap, mprotect, munmap, rt_sigprocmask, rt_sigreturn, ioctl, madvise, exit, fcntl, sigaltstack, prctl, futex, epoll_ctl, set_robust_list, timerfd_create, eventfd2, epoll_create1, getrandom, rseq, clone3 |
| `vsock` | 24 | read, write, close, mmap, mprotect, munmap, rt_sigprocmask, ioctl, madvise, sendto, shutdown, socketpair, exit, fcntl, sigaltstack, prctl, gettid, futex, sched_getaffinity, epoll_wait, epoll_ctl, set_robust_list, rseq, clone3 |
| `winch` | 1 | restart_syscall |
