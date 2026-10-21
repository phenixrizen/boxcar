// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The VMM process's seccomp allowlist: one filter for every thread,
//! installed with `SECCOMP_FILTER_FLAG_TSYNC` once the VM is built and before
//! `vmm.start` is recorded, so the threads already running and every thread
//! started later have it.
//!
//! The list is the syscalls measured over the gated suites (bpftrace on the
//! test box, from each process's first `KVM_RUN` on), completed from the
//! code with what the guest can reach that the suites never did (every FUSE
//! operation the passthrough serves, every socket call of a flow, a device
//! reset), the host's rare paths (a vCPU failure, a terminal resize, the
//! audit log's rotation, `abort`), and glibc's alternatives for a call the
//! code makes. It is built for x86_64 glibc: musl, for one, signals threads
//! with `tkill`, which it does not allow.
//!
//! Seven calls are allowed only with some arguments: `ioctl` by request,
//! `socket` and `socketpair` by family, `clone` for threads only, `prctl`
//! for `PR_SET_NAME` and `PR_SET_NO_NEW_PRIVS`, `seccomp` to add a filter
//! without flags (a thread's own, which only narrows), and `tgkill` to
//! this process. `clone3` passes its flags in memory a filter cannot
//! read, so a second filter answers it `ENOSYS`, and glibc falls back to
//! `clone`.
//!
//! On top of the process list, each worker thread started once that list
//! is in confines itself to its role's list ([`Role`], [`confine_thread`])
//! as its first act, through the hook `boxcar_confine` runs at a thread's
//! start, which [`set_mode`] sets before `boxcar run` spawns anything. A
//! role's list is a subset of the process list: the net thread keeps
//! sockets and loses files, a virtio-fs queue keeps files and loses
//! sockets. Filters are inherited by the threads a thread starts, so a
//! role that starts threads lists what they need too; the vCPU threads,
//! which start the device workers, and the main thread keep the process
//! list. A thread started before the process list went in (the audit
//! writer, the control socket's acceptor, the terminal's) keeps it alone:
//! `TSYNC` can install the process list only while no thread's filters
//! differ from the installer's, so the order is the process list first,
//! by `TSYNC`, then each later thread's own.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

pub use boxcar_proto::SeccompMode;
use seccompiler::{
    BackendError, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

/// Why the filter could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    /// The list is glibc's on x86_64; this build is not.
    #[error("the seccomp allowlist is built for x86_64 with glibc only; run with --seccomp off")]
    Unsupported,
    #[error("cannot build the seccomp filter: {0}")]
    Build(#[from] BackendError),
    #[error("cannot install the seccomp filter: {0}")]
    Install(#[from] seccompiler::Error),
}

/// The allocator and thread stacks.
const MEMORY: &[i64] = &[
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
];

/// Starting, naming, parking and ending threads (`clone` and `prctl` are
/// filtered apart), and who this process is: the control socket's owner
/// check reads the uid when it binds.
const THREADS: &[i64] = &[
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_futex,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_sigaltstack,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_getpgrp,
    libc::SYS_getuid,
    libc::SYS_getgid,
];

/// `SECCOMP_SET_MODE_FILTER`.
const SECCOMP_SET_MODE_FILTER: u64 = 1;

/// The vCPU kick's handler, the stop signals' and the terminal's signalfds,
/// job control, and `abort` (`tgkill` is filtered apart).
const SIGNALS: &[i64] = &[
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_restart_syscall,
    libc::SYS_signalfd4,
];

/// Clocks (the vDSO's fallbacks), sleeps, and the timers of the main loop,
/// the net stack and the exceptions.
const TIME: &[i64] = &[
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_gettimeofday,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
];

/// Hash maps' seeds, TLS, the allocator.
const RANDOM: &[i64] = &[libc::SYS_getrandom];

/// The event loops: eventfds, epoll and poll, with glibc's alternatives.
const EVENTS: &[i64] = &[
    libc::SYS_eventfd2,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_poll,
    libc::SYS_ppoll,
];

/// Descriptors (`ioctl` is filtered apart).
const DESCRIPTORS: &[i64] = &[libc::SYS_close, libc::SYS_dup, libc::SYS_fcntl];

/// Reads and writes: the shares' data (`preadv`, `pwritev`), the log, the
/// sockets, the terminal.
const IO: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_lseek,
];

/// Files: every operation the passthrough serves for the guest (beneath a
/// share's directory, or through `/proc/self/fd`), `AuditFs`'s look at what
/// a name points to, the hasher's `openat2`, the audit log's appends,
/// syncs and rotation (`rename` of `meta.json.tmp`), the dumps, and the
/// control socket's and the state directory's making and removal.
const FILES: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_newfstatat,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_fstatfs,
    libc::SYS_getdents64,
    libc::SYS_mkdir,
    libc::SYS_mkdirat,
    libc::SYS_mknodat,
    libc::SYS_symlinkat,
    libc::SYS_linkat,
    libc::SYS_unlinkat,
    libc::SYS_unlink,
    libc::SYS_rmdir,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_readlinkat,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_fchownat,
    libc::SYS_utimensat,
    libc::SYS_ftruncate,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_umask,
    // The overlay's copy-up of an image's file into the session's layer.
    libc::SYS_copy_file_range,
];

/// Extended attributes, which the passthrough reaches by path through
/// `/proc/self/fd`.
const XATTRS: &[i64] = &[
    libc::SYS_getxattr,
    libc::SYS_setxattr,
    libc::SYS_listxattr,
    libc::SYS_removexattr,
    // The overlay's copy-up carries a file's xattrs by descriptor.
    libc::SYS_fgetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_flistxattr,
];

/// Sockets: the guest's TCP and UDP flows and its DNS, the gate, the
/// vsock muxer's unix sockets, the control socket, and glibc's
/// `getifaddrs` over netlink (`socket` and `socketpair` are filtered apart).
const SOCKETS: &[i64] = &[
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
];

/// Every call allowed whatever its arguments, by group.
const GROUPS: &[&[i64]] = &[
    MEMORY,
    THREADS,
    SIGNALS,
    TIME,
    RANDOM,
    EVENTS,
    DESCRIPTORS,
    IO,
    FILES,
    XATTRS,
    SOCKETS,
];

/// `_IOC(dir, KVMIO, nr, size)` for x86_64.
const fn kvm_ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | ((size as u64) << 16) | (0xae << 8) | nr
}

/// `_IOC_READ`.
const IOC_READ: u64 = 2;

/// `KVM_RUN`: the vCPU loop.
const KVM_RUN: u64 = kvm_ioc(0, 0x80, 0);
/// `KVM_GET_REGS`: a failed vCPU's registers, for its error.
const KVM_GET_REGS: u64 = kvm_ioc(IOC_READ, 0x81, size_of::<kvm_bindings::kvm_regs>());
/// `KVM_GET_SREGS`: likewise.
const KVM_GET_SREGS: u64 = kvm_ioc(IOC_READ, 0x83, size_of::<kvm_bindings::kvm_sregs>());

/// The `ioctl` requests allowed: the vCPU loop and its failure path, the
/// terminal (raw mode, job control, a resize, the output queue at the
/// stop), and non-blocking sockets.
const IOCTLS: &[u64] = &[
    KVM_RUN,
    KVM_GET_REGS,
    KVM_GET_SREGS,
    libc::TCGETS,
    libc::TCSETS,
    libc::TIOCGPGRP,
    libc::TIOCGWINSZ,
    libc::TIOCOUTQ,
    libc::FIONREAD,
    libc::FIONBIO,
];

/// The socket families allowed whatever the protocol: the vsock muxer's
/// and the control socket's, and the guest's flows.
const FAMILIES: &[u64] = &[
    libc::AF_UNIX as u64,
    libc::AF_INET as u64,
    libc::AF_INET6 as u64,
];

/// The mode `boxcar run` was given, set before any thread is spawned, so
/// that a worker confines itself at its start.
static MODE: OnceLock<SeccompMode> = OnceLock::new();

/// Whether the process list is in ([`install`] has run): only then does a
/// thread add its role's filter, since `TSYNC` must come first.
static PROCESS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Sets the mode for the per-thread filters, once, and the hook a worker
/// runs at its start. Nothing is installed under [`SeccompMode::Off`], or
/// where the list does not apply (not x86_64 glibc).
pub fn set_mode(mode: SeccompMode) {
    if MODE.set(mode).is_err() {
        return;
    }
    if mode != SeccompMode::Off && cfg!(all(target_arch = "x86_64", target_env = "gnu")) {
        boxcar_confine::set_hook(hook);
    }
}

/// Whether the worker threads started from now on confine themselves to
/// their roles: a mode was set, not `off`, the process list is in, on a
/// host the lists are built for.
pub fn threads_confined() -> bool {
    MODE.get().is_some_and(|mode| *mode != SeccompMode::Off)
        && PROCESS_INSTALLED.load(Ordering::Acquire)
        && cfg!(all(target_arch = "x86_64", target_env = "gnu"))
}

/// The hook: a thread whose name says its role is confined to it.
fn hook(name: &str) {
    if let Some(role) = Role::of(name) {
        if let Err(error) = confine_thread(role) {
            boxcar_virtio::limited!(warn, "seccomp: cannot confine the {name} thread: {error}");
        }
    }
}

/// A worker thread's role, by its name: what the thread does, and so what
/// it may call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// `net`: the user-mode stack, the gate's TLS legs, DNS.
    Net,
    /// `vsock`: the vsock device and its muxer, which also starts the
    /// guest control channel's, the sensor's and the PTY hub's threads
    /// when the guest connects.
    Vsock,
    /// `fs-<tag>-q<N>`: a virtio-fs queue, the passthrough's file calls.
    FsQueue,
    /// `fs-<tag>-hash<N>`: a hasher, reading files.
    FsHash,
    /// `gate-observe` and `dump`: parsing, and the dump files.
    Observe,
    /// `audit-writer`: the log's files.
    AuditWriter,
    /// `audit-forward`: a subscription, reading the log and sending it.
    AuditForward,
    /// `control-accept` and `control-conn`: the control socket, which
    /// start connections and subscriptions.
    Control,
    /// `guest-ctl-rx`, `guest-ctl-tx`, `guest-ctl-sync`, `sensor-rx`:
    /// the guest channels' readers and writers.
    GuestChannel,
    /// `pty-hub`, `pty-stdin`, `pty-stdout`, `pty-attach`, `console`: the
    /// terminal, its attachments and the console log.
    Terminal,
    /// `reconcile`, `tell`: in-process work, a line to stderr.
    Quiet,
}

impl Role {
    /// The role a thread's name says, or none for a thread that keeps the
    /// process list (the main thread, the vCPUs, the signal threads).
    pub fn of(name: &str) -> Option<Role> {
        Some(match name {
            "net" => Role::Net,
            "vsock" => Role::Vsock,
            "gate-observe" | "dump" => Role::Observe,
            "audit-writer" => Role::AuditWriter,
            "audit-forward" => Role::AuditForward,
            "control-accept" | "control-conn" => Role::Control,
            "guest-ctl-rx" | "guest-ctl-tx" | "guest-ctl-sync" | "sensor-rx" => Role::GuestChannel,
            "pty-hub" | "pty-stdin" | "pty-stdout" | "pty-attach" | "console" => Role::Terminal,
            "reconcile" | "tell" => Role::Quiet,
            _ if name.starts_with("fs-") && name.contains("-hash") => Role::FsHash,
            _ if name.starts_with("fs-") && name.contains("-q") => Role::FsQueue,
            _ => return None,
        })
    }

    /// Every role, for the tests.
    pub const ALL: [Role; 11] = [
        Role::Net,
        Role::Vsock,
        Role::FsQueue,
        Role::FsHash,
        Role::Observe,
        Role::AuditWriter,
        Role::AuditForward,
        Role::Control,
        Role::GuestChannel,
        Role::Terminal,
        Role::Quiet,
    ];

    /// The calls the role may make whatever their arguments, beyond
    /// [`RUNTIME`]; the filtered calls are added by [`role_rules`].
    fn calls(self) -> Vec<i64> {
        let mut calls: Vec<i64> = RUNTIME.to_vec();
        let groups: &[&[i64]] = match self {
            Role::Net => &[IO, EVENTS, SOCKETS, TIMERS],
            // Starts the guest channels' and the PTY hub's threads.
            Role::Vsock => &[IO, EVENTS, SOCKETS, TIMERS, SPAWN, TERMINAL_FILES],
            Role::FsQueue => &[IO, EVENTS, FILES, XATTRS],
            Role::FsHash => &[HASH_FILES],
            Role::Observe => &[IO, DUMP_FILES],
            Role::AuditWriter => &[IO, FILES],
            Role::AuditForward => &[IO, LOG_FILES, SEND],
            // Starts connections and their subscriptions.
            Role::Control => &[IO, EVENTS, SOCKETS, LOG_FILES, SPAWN],
            Role::GuestChannel => &[IO, SEND],
            Role::Terminal => &[IO, EVENTS, SEND, SPAWN, TERMINAL_FILES],
            Role::Quiet => &[],
        };
        calls.extend(groups.iter().flat_map(|group| group.iter()));
        calls.sort_unstable();
        calls.dedup();
        calls
    }
}

/// What every thread needs: memory, its own life and signals, the clocks,
/// randomness, descriptors, a line to stderr, job control's `getpgrp`,
/// and `abort`'s `tgkill` (filtered to this process, as for the process
/// list).
const RUNTIME: &[i64] = &[
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_futex,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_sigaltstack,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_getpgrp,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_restart_syscall,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_gettimeofday,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_getrandom,
    libc::SYS_close,
    libc::SYS_dup,
    libc::SYS_fcntl,
    libc::SYS_write,
    libc::SYS_poll,
    libc::SYS_ppoll,
];

/// The timers of the net stack and the vsock device's event loops.
const TIMERS: &[i64] = &[
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_eventfd2,
];

/// Sending and receiving on a connected socket.
const SEND: &[i64] = &[
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
];

/// Starting a thread (`clone` and `prctl` are filtered apart, as for the
/// process list).
const SPAWN: &[i64] = &[];

/// Reading files for their hash.
const HASH_FILES: &[i64] = &[
    libc::SYS_read,
    libc::SYS_pread64,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_newfstatat,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_lseek,
];

/// The dump files: made, written, synced.
const DUMP_FILES: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
];

/// The log's files, read by a subscription.
const LOG_FILES: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_newfstatat,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_getdents64,
];

/// The console log and the terminal's `ioctl`s (filtered apart).
const TERMINAL_FILES: &[i64] = &[libc::SYS_openat, libc::SYS_fstat, libc::SYS_statx];

/// Installs the filter for `mode` on every thread of this process: nothing
/// for [`SeccompMode::Off`]. Once it returns, no thread can take it off.
pub fn install(mode: SeccompMode) -> Result<(), SeccompError> {
    if mode == SeccompMode::Off {
        return Ok(());
    }
    if !cfg!(all(target_arch = "x86_64", target_env = "gnu")) {
        return Err(SeccompError::Unsupported);
    }
    let [clone3, allowlist] = filters(mode, std::process::id())?;
    // `clone3`'s first: once the allowlist is in, a `seccomp(2)` may only
    // add a filter to the calling thread, never with `TSYNC`.
    seccompiler::apply_filter_all_threads(&clone3)?;
    seccompiler::apply_filter_all_threads(&allowlist)?;
    // From here on a worker adds its role's filter at its start.
    PROCESS_INSTALLED.store(true, Ordering::Release);
    Ok(())
}

/// Confines the calling thread to `role`'s list, under the mode
/// [`set_mode`] set: nothing before it, under `off`, or before the
/// process list is in ([`install`]), which `TSYNC` must put in first. The
/// filter adds to the process list's: the kernel takes the stricter
/// answer.
pub fn confine_thread(role: Role) -> Result<(), SeccompError> {
    let Some(&mode) = MODE.get() else {
        return Ok(());
    };
    if mode == SeccompMode::Off || !PROCESS_INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }
    if !cfg!(all(target_arch = "x86_64", target_env = "gnu")) {
        return Err(SeccompError::Unsupported);
    }
    let program = role_filter(mode, role, std::process::id())?;
    seccompiler::apply_filter(&program)?;
    Ok(())
}

/// `role`'s filter: its calls whatever their arguments, and the filtered
/// calls with the process list's arguments, `clone3` answered by the
/// process's own filter.
fn role_filter(mode: SeccompMode, role: Role, pid: u32) -> Result<BpfProgram, BackendError> {
    let off_list = match mode {
        SeccompMode::Log => SeccompAction::Log,
        SeccompMode::Enforce | SeccompMode::Off => SeccompAction::KillProcess,
    };
    let filter = SeccompFilter::new(
        role_rules(role, pid)?,
        off_list,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )?;
    BpfProgram::try_from(filter)
}

/// `role`'s rules: its calls, and of the filtered calls those the role
/// uses, with the process list's arguments.
fn role_rules(role: Role, pid: u32) -> Result<BTreeMap<i64, Vec<SeccompRule>>, BackendError> {
    let process = rules(pid)?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = role
        .calls()
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    // The filtered calls, as the process list filters them.
    let mut keep = |nr: i64| {
        if let Some(filtered) = process.get(&nr) {
            rules.insert(nr, filtered.clone());
        }
    };
    keep(libc::SYS_tgkill);
    // The role's own install: `prctl(PR_SET_NO_NEW_PRIVS)` and `seccomp`
    // happen under the process list, before this filter is in, but a
    // thread may still add one later.
    keep(libc::SYS_prctl);
    keep(libc::SYS_seccomp);
    match role {
        Role::Net => {
            keep(libc::SYS_socket);
            keep(libc::SYS_ioctl);
        }
        Role::Vsock | Role::Control | Role::Terminal => {
            keep(libc::SYS_socket);
            keep(libc::SYS_socketpair);
            keep(libc::SYS_ioctl);
            keep(libc::SYS_clone);
            keep(libc::SYS_clone3);
        }
        Role::FsQueue
        | Role::FsHash
        | Role::Observe
        | Role::AuditWriter
        | Role::AuditForward
        | Role::GuestChannel
        | Role::Quiet => {}
    }
    Ok(rules)
}

/// The two filters, in the order they are installed: one that answers
/// `clone3` `ENOSYS` and allows everything else, and the allowlist, whose
/// calls off the list are killed (`Enforce`) or logged (`Log`). The kernel
/// takes the stricter answer of the two, so `clone3` gets `ENOSYS`.
fn filters(mode: SeccompMode, pid: u32) -> Result<[BpfProgram; 2], BackendError> {
    let off_list = match mode {
        SeccompMode::Log => SeccompAction::Log,
        SeccompMode::Enforce | SeccompMode::Off => SeccompAction::KillProcess,
    };
    let clone3 = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        TargetArch::x86_64,
    )?;
    let allowlist = SeccompFilter::new(
        rules(pid)?,
        off_list,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )?;
    Ok([
        BpfProgram::try_from(clone3)?,
        BpfProgram::try_from(allowlist)?,
    ])
}

/// The allowlist's rules: every call of [`GROUPS`] whatever its arguments,
/// the filtered calls with theirs, and `clone3`, which the other filter
/// answers.
fn rules(pid: u32) -> Result<BTreeMap<i64, Vec<SeccompRule>>, BackendError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = GROUPS
        .iter()
        .flat_map(|group| group.iter())
        .map(|&nr| (nr, Vec::new()))
        .collect();
    rules.insert(libc::SYS_clone3, Vec::new());
    rules.insert(libc::SYS_ioctl, any_of(1, IOCTLS)?);
    let mut socket = any_of(0, FAMILIES)?;
    // glibc's `getifaddrs`, for the net stack's look at the host's
    // addresses: route sockets only.
    socket.push(SeccompRule::new(vec![
        dword_eq(0, libc::AF_NETLINK as u64)?,
        dword_eq(2, libc::NETLINK_ROUTE as u64)?,
    ])?);
    rules.insert(libc::SYS_socket, socket);
    rules.insert(libc::SYS_socketpair, any_of(0, &[libc::AF_UNIX as u64])?);
    // A thread, never a process.
    let thread = libc::CLONE_THREAD as u64;
    rules.insert(
        libc::SYS_clone,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(thread),
            thread,
        )?])?],
    );
    rules.insert(
        libc::SYS_prctl,
        any_of(
            0,
            &[libc::PR_SET_NAME as u64, libc::PR_SET_NO_NEW_PRIVS as u64],
        )?,
    );
    // A thread's own filter, on top of this one (`confine_thread`): a
    // filter without flags, so never `TSYNC` onto the others.
    rules.insert(
        libc::SYS_seccomp,
        vec![SeccompRule::new(vec![
            dword_eq(0, SECCOMP_SET_MODE_FILTER)?,
            dword_eq(1, 0)?,
        ])?],
    );
    // The vCPU kick, job control's `SIGTSTP` and `abort`, all to this
    // process's own threads.
    rules.insert(libc::SYS_tgkill, any_of(0, &[u64::from(pid)])?);
    Ok(rules)
}

/// One rule per value: argument `arg`, compared as 32 bits, is `value`.
fn any_of(arg: u8, values: &[u64]) -> Result<Vec<SeccompRule>, BackendError> {
    values
        .iter()
        .map(|&value| SeccompRule::new(vec![dword_eq(arg, value)?]))
        .collect()
}

fn dword_eq(arg: u8, value: u64) -> Result<SeccompCondition, BackendError> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Every call is named once, by its x86_64 number, and none of the
    /// filtered ones is also allowed whatever its arguments.
    #[test]
    fn every_call_is_named_once() {
        let mut seen = HashSet::new();
        for &nr in GROUPS.iter().flat_map(|group| group.iter()) {
            assert!((0..512).contains(&nr), "{nr}");
            assert!(seen.insert(nr), "{nr} is named twice");
        }
        for filtered in [
            libc::SYS_ioctl,
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_prctl,
            libc::SYS_tgkill,
            libc::SYS_tkill,
            libc::SYS_kill,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_seccomp,
            libc::SYS_ptrace,
        ] {
            assert!(!seen.contains(&filtered), "{filtered}");
        }
    }

    /// The KVM requests computed from the structures' sizes are the
    /// numbers the kernel's headers give.
    #[test]
    fn the_kvm_requests_are_the_kernels() {
        assert_eq!(KVM_RUN, 0xae80);
        assert_eq!(KVM_GET_REGS, 0x8090_ae81);
        assert_eq!(KVM_GET_SREGS, 0x8138_ae83);
    }

    /// Both filters build in both modes that install one.
    #[test]
    fn the_filters_build_in_each_mode() {
        for mode in [SeccompMode::Enforce, SeccompMode::Log] {
            let [clone3, allowlist] = filters(mode, 4242).unwrap();
            assert!(!clone3.is_empty());
            assert!(allowlist.len() > clone3.len());
        }
    }

    /// Every role's list is within the process list, so a thread never
    /// gains a call the process forbids, and each role names a call once.
    #[test]
    fn every_role_is_within_the_process_list() {
        let process = rules(4242).unwrap();
        for role in Role::ALL {
            let calls = role.calls();
            let mut seen = HashSet::new();
            for nr in &calls {
                assert!(seen.insert(*nr), "{role:?} names {nr} twice");
                assert!(
                    process.contains_key(nr),
                    "{role:?} allows {nr}, which the process does not"
                );
            }
            // The filtered calls a role keeps carry the process list's
            // arguments, no wider.
            let own = role_rules(role, 4242).unwrap();
            for (nr, filtered) in &own {
                assert!(process.contains_key(nr), "{role:?}: {nr}");
                assert_eq!(filtered.len(), process[nr].len(), "{role:?}: {nr}");
            }
        }
    }

    /// Threads are told their role by name; the ones that keep the process
    /// list have none.
    #[test]
    fn roles_are_told_by_thread_name() {
        assert_eq!(Role::of("net"), Some(Role::Net));
        assert_eq!(Role::of("fs-root-q1"), Some(Role::FsQueue));
        assert_eq!(Role::of("fs-workspace-hash0"), Some(Role::FsHash));
        assert_eq!(Role::of("control-conn"), Some(Role::Control));
        assert_eq!(Role::of("guest-ctl-sync"), Some(Role::GuestChannel));
        assert_eq!(Role::of("pty-attach"), Some(Role::Terminal));
        for plain in [
            "boxcar",
            "vcpu0",
            "vcpu12",
            "winch",
            "job-control",
            "seccomp-trip",
            "",
        ] {
            assert_eq!(Role::of(plain), None, "{plain}");
        }
    }

    /// Every role's filter builds in both modes that install one.
    #[test]
    fn the_role_filters_build() {
        for mode in [SeccompMode::Enforce, SeccompMode::Log] {
            for role in Role::ALL {
                assert!(
                    !role_filter(mode, role, 4242).unwrap().is_empty(),
                    "{role:?}"
                );
            }
        }
    }

    /// Before a mode is set, or before the process list is in, a thread
    /// that confines itself is left as it is: the tests' threads, a client
    /// command's, and the threads `boxcar run` starts before the VM.
    #[test]
    fn confining_a_thread_before_the_mode_is_set_installs_nothing() {
        confine_thread(Role::Net).unwrap();
        // SAFETY: PR_GET_SECCOMP takes no further arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP) }, 0);
    }

    /// `off` installs nothing, so this process stays as it is.
    #[test]
    fn off_installs_nothing() {
        install(SeccompMode::Off).unwrap();
        // SAFETY: PR_GET_SECCOMP takes no further arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP) }, 0);
    }
}
