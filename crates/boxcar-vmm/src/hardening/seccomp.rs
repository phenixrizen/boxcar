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
//! Six calls are allowed only with some arguments: `ioctl` by request,
//! `socket` and `socketpair` by family, `clone` for threads only, `prctl`
//! for `PR_SET_NAME`, and `tgkill` to this process. `clone3` passes its
//! flags in memory a filter cannot read, so a second filter answers it
//! `ENOSYS`, and glibc falls back to `clone`.

use std::collections::BTreeMap;
use std::mem::size_of;

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
];

/// Extended attributes, which the passthrough reaches by path through
/// `/proc/self/fd`.
const XATTRS: &[i64] = &[
    libc::SYS_getxattr,
    libc::SYS_setxattr,
    libc::SYS_listxattr,
    libc::SYS_removexattr,
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
    // `clone3`'s first: once the allowlist is in, neither `seccomp(2)` nor
    // `prctl(PR_SET_NO_NEW_PRIVS)` is allowed any more.
    seccompiler::apply_filter_all_threads(&clone3)?;
    seccompiler::apply_filter_all_threads(&allowlist)?;
    Ok(())
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
    rules.insert(libc::SYS_prctl, any_of(0, &[libc::PR_SET_NAME as u64])?);
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

    /// `off` installs nothing, so this process stays as it is.
    #[test]
    fn off_installs_nothing() {
        install(SeccompMode::Off).unwrap();
        // SAFETY: PR_GET_SECCOMP takes no further arguments.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP) }, 0);
    }
}
