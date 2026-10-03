// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The events the guest sensor's eBPF programs hand to its userspace through
//! the kernel's ring buffer: `#![no_std]`, `#[repr(C)]`, every one starting
//! with a [`Header`] whose `kind` says which struct follows. The eBPF crate
//! fills them; the userspace sensor (`user` feature) reads them as
//! `aya::Pod` and turns them into `proc.*` records.
//!
//! Sizes are part of the contract between the two sides, which are built by
//! different toolchains: the tests pin them. [`programs`] lists what the
//! built object must contain.

#![no_std]

pub mod programs;

use core::mem::size_of;

/// The most bytes of `argv` an exec event carries, the arguments
/// NUL-separated as the kernel holds them.
pub const ARGV_MAX: usize = 16384;
/// The most bytes of a path or program name.
pub const PATH_MAX: usize = 4096;
/// The most bytes of a `memfd_create` name, as the kernel allows.
pub const MEMFD_NAME_MAX: usize = 256;

/// `AF_INET`, as `sockaddr.sa_family` carries it.
pub const AF_INET: u16 = 2;
/// `AF_INET6`.
pub const AF_INET6: u16 = 10;

/// `LsmDeny.hook`: the `bpf()` call was refused.
pub const HOOK_BPF: u32 = 1;
/// `LsmDeny.hook`: a signal to the sensor was refused.
pub const HOOK_TASK_KILL: u32 = 2;

/// Which event struct follows a [`Header`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Exec = 1,
    Fork = 2,
    Exit = 3,
    ConnectAttempt = 4,
    TcpConnect = 5,
    FileOpen = 6,
    Memfd = 7,
    LsmDeny = 8,
}

impl Kind {
    /// The kind a header's tag names, if any.
    pub const fn from_u32(tag: u32) -> Option<Kind> {
        match tag {
            1 => Some(Kind::Exec),
            2 => Some(Kind::Fork),
            3 => Some(Kind::Exit),
            4 => Some(Kind::ConnectAttempt),
            5 => Some(Kind::TcpConnect),
            6 => Some(Kind::FileOpen),
            7 => Some(Kind::Memfd),
            8 => Some(Kind::LsmDeny),
            _ => None,
        }
    }

    /// The size of this kind's struct: what the eBPF side reserves in the
    /// ring buffer, and what the reader expects to find.
    pub const fn size(self) -> usize {
        match self {
            Kind::Exec => size_of::<ExecEvent>(),
            Kind::Fork => size_of::<ForkEvent>(),
            Kind::Exit => size_of::<ExitEvent>(),
            Kind::ConnectAttempt => size_of::<ConnectAttempt>(),
            Kind::TcpConnect => size_of::<TcpConnect>(),
            Kind::FileOpen => size_of::<FileOpen>(),
            Kind::Memfd => size_of::<MemfdEvent>(),
            Kind::LsmDeny => size_of::<LsmDeny>(),
        }
    }
}

/// The hook an [`LsmDeny`] names.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    Bpf = HOOK_BPF,
    TaskKill = HOOK_TASK_KILL,
}

impl Hook {
    pub const fn from_u32(hook: u32) -> Option<Hook> {
        match hook {
            HOOK_BPF => Some(Hook::Bpf),
            HOOK_TASK_KILL => Some(Hook::TaskKill),
            _ => None,
        }
    }

    /// The name the `proc.lsm_deny` record carries.
    pub const fn name(self) -> &'static str {
        match self {
            Hook::Bpf => "bpf",
            Hook::TaskKill => "task_kill",
        }
    }
}

/// What every event starts with. `kind` is first so the reader can tell the
/// struct before it knows it; the clock is the guest's `CLOCK_MONOTONIC`
/// (`bpf_ktime_get_ns`), `tid` and `tgid` the calling thread and its
/// process, `cgroup_id` the cgroup it is in.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub kind: u32,
    pub tid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
}

/// `Kind::Exec`: a successful `execve`. `argv` holds `argv_len` bytes of
/// NUL-separated arguments, cut at [`ARGV_MAX`] (`argv_truncated` then 1);
/// `filename` holds `filename_len` bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    pub header: Header,
    pub ppid: u32,
    pub argv_len: u32,
    pub filename_len: u32,
    pub argv_truncated: u32,
    /// The process's start time on the guest's clock.
    pub start_ns: u64,
    pub filename: [u8; PATH_MAX],
    pub argv: [u8; ARGV_MAX],
}

/// `Kind::Fork`: a new process (not a new thread). The header is the
/// parent's.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ForkEvent {
    pub header: Header,
    pub child_pid: u32,
    pub _pad: u32,
    pub child_start_ns: u64,
}

/// `Kind::Exit`: a thread ended.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExitEvent {
    pub header: Header,
    /// The kernel's exit code word.
    pub exit_code: i32,
    /// 1 when the thread was the last of its process.
    pub group_dead: u32,
    pub start_ns: u64,
}

/// `Kind::ConnectAttempt`: a `connect()` as the LSM saw it. `dst` holds an
/// IPv4 address in its first 4 bytes or an IPv6 address in all 16, by
/// `family`; `dst_port` is in host order; `proto` is the socket's
/// `IPPROTO_*`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectAttempt {
    pub header: Header,
    pub family: u16,
    pub dst_port: u16,
    pub proto: u32,
    pub dst: [u8; 16],
}

/// `Kind::TcpConnect`: the first segment of a connection, with the 4-tuple
/// after the source port was chosen. Ports in host order; addresses as in
/// [`ConnectAttempt`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TcpConnect {
    pub header: Header,
    pub family: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad: u16,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

/// `Kind::FileOpen`: one open in `sample`, with `path_len` bytes of the
/// resolved path.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileOpen {
    pub header: Header,
    pub flags: u32,
    pub sample: u32,
    pub path_len: u32,
    pub _pad: u32,
    pub path: [u8; PATH_MAX],
}

/// `Kind::Memfd`: a `memfd_create`, with `name_len` bytes of its name.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdEvent {
    pub header: Header,
    pub flags: u32,
    pub name_len: u32,
    pub name: [u8; MEMFD_NAME_MAX],
}

/// `Kind::LsmDeny`: the self-protection refused something: `hook` is a
/// [`Hook`]'s number, `detail` the `bpf()` command or the signal.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmDeny {
    pub header: Header,
    pub hook: u32,
    pub _pad: u32,
    pub detail: i64,
}

#[cfg(feature = "user")]
mod pod {
    // SAFETY: every struct is `repr(C)`, `Copy`, and made of integers and
    // integer arrays: any bit pattern is a value.
    unsafe impl aya::Pod for super::Header {}
    unsafe impl aya::Pod for super::ExecEvent {}
    unsafe impl aya::Pod for super::ForkEvent {}
    unsafe impl aya::Pod for super::ExitEvent {}
    unsafe impl aya::Pod for super::ConnectAttempt {}
    unsafe impl aya::Pod for super::TcpConnect {}
    unsafe impl aya::Pod for super::FileOpen {}
    unsafe impl aya::Pod for super::MemfdEvent {}
    unsafe impl aya::Pod for super::LsmDeny {}
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn every_event_is_pod_and_has_a_stable_size() {
        assert_eq!(size_of::<Header>(), 40);
        assert_eq!(size_of::<ExecEvent>(), 40 + 24 + PATH_MAX + ARGV_MAX);
        assert_eq!(size_of::<ForkEvent>(), 40 + 16);
        assert_eq!(size_of::<ExitEvent>(), 40 + 16);
        assert_eq!(size_of::<ConnectAttempt>(), 40 + 24);
        assert_eq!(size_of::<TcpConnect>(), 40 + 40);
        assert_eq!(size_of::<FileOpen>(), 40 + 16 + PATH_MAX);
        assert_eq!(size_of::<MemfdEvent>(), 40 + 8 + MEMFD_NAME_MAX);
        assert_eq!(size_of::<LsmDeny>(), 40 + 16);
        // The header is the first field of every event, at offset 0, so the
        // reader can look at the kind before it knows the struct.
        assert_eq!(core::mem::offset_of!(ExecEvent, header), 0);
        assert_eq!(core::mem::offset_of!(LsmDeny, header), 0);
        assert_eq!(core::mem::offset_of!(Header, kind), 0);
        #[cfg(feature = "user")]
        {
            fn pod<T: aya::Pod>() {}
            pod::<Header>();
            pod::<ExecEvent>();
            pod::<ForkEvent>();
            pod::<ExitEvent>();
            pod::<ConnectAttempt>();
            pod::<TcpConnect>();
            pod::<FileOpen>();
            pod::<MemfdEvent>();
            pod::<LsmDeny>();
        }
    }

    #[test]
    fn kind_tags_are_unique_and_round_trip() {
        let all = [
            Kind::Exec,
            Kind::Fork,
            Kind::Exit,
            Kind::ConnectAttempt,
            Kind::TcpConnect,
            Kind::FileOpen,
            Kind::Memfd,
            Kind::LsmDeny,
        ];
        for (i, a) in all.iter().enumerate() {
            assert_eq!(Kind::from_u32(*a as u32), Some(*a));
            for b in &all[i + 1..] {
                assert_ne!(*a as u32, *b as u32);
            }
        }
        assert_eq!(Kind::from_u32(0), None);
        assert_eq!(Kind::from_u32(99), None);
        assert_eq!(Kind::Exec.size(), size_of::<ExecEvent>());
        assert_eq!(Kind::LsmDeny.size(), size_of::<LsmDeny>());
    }

    #[test]
    fn hooks_and_families_have_their_numbers() {
        assert_eq!(Hook::from_u32(HOOK_BPF), Some(Hook::Bpf));
        assert_eq!(Hook::from_u32(HOOK_TASK_KILL), Some(Hook::TaskKill));
        assert_eq!(Hook::from_u32(0), None);
        assert_eq!(Hook::Bpf.name(), "bpf");
        assert_eq!(Hook::TaskKill.name(), "task_kill");
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
    }
}
