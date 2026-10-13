// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! What every program shares: the maps, the globals the loader sets, the
//! session filter, and the header every event starts with.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{PerCpuArray, RingBuf};
use boxcar_sensor_common::programs::{RING_BUFFER_BYTES, UNSET};
use boxcar_sensor_common::{Header, Kind};

/// The events, to userspace.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_BYTES, 0);

/// Events the ring buffer had no room for, per CPU.
#[map]
pub static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// `file_open`'s sampling counter, per CPU.
#[map]
pub static SAMPLES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The session cgroup's id, set by the loader before load. Until then
/// `UNSET`, which no cgroup has: nothing is reported.
#[no_mangle]
pub static mut SESSION_CGROUP: u64 = UNSET;

/// The sensor's own process, set by the loader before load, which the
/// guards let through.
#[no_mangle]
pub static mut SENSOR_TGID: u64 = UNSET;

#[inline(always)]
pub fn session_cgroup() -> u64 {
    // SAFETY: a read of a global the loader wrote before any program ran.
    unsafe { core::ptr::read_volatile(&raw const SESSION_CGROUP) }
}

#[inline(always)]
pub fn sensor_tgid() -> u64 {
    // SAFETY: as above.
    unsafe { core::ptr::read_volatile(&raw const SENSOR_TGID) }
}

/// Whether the current task is in the session's cgroup.
#[inline(always)]
pub fn in_session() -> bool {
    // SAFETY: the helper reads the current task's cgroup; no pointer is passed.
    unsafe { bpf_get_current_cgroup_id() == session_cgroup() }
}

/// The current task's process id.
#[inline(always)]
pub fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Fills `header` for the current task.
///
/// # Safety
/// `header` points into a reserved ring buffer record.
#[inline(always)]
pub unsafe fn fill_header(header: *mut Header, kind: Kind) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    (*header).kind = kind as u32;
    (*header).tid = pid_tgid as u32;
    (*header).tgid = (pid_tgid >> 32) as u32;
    (*header).uid = uid_gid as u32;
    (*header).gid = (uid_gid >> 32) as u32;
    (*header)._pad = 0;
    (*header).ts_ns = bpf_ktime_get_ns();
    (*header).cgroup_id = bpf_get_current_cgroup_id();
}

/// Counts an event the ring buffer had no room for; the heartbeat reports
/// the count.
#[inline(always)]
pub fn count_drop() {
    if let Some(drops) = DROPS.get_ptr_mut(0) {
        // SAFETY: a per-CPU slot of the map, ours while this program runs.
        unsafe { *drops += 1 };
    }
}

/// A kernel value at `src`, or `fallback` when it cannot be read.
///
/// # Safety
/// `src` is a kernel address; the helper checks it before reading.
#[inline(always)]
pub unsafe fn read_or<T: Copy>(src: *const T, fallback: T) -> T {
    bpf_probe_read_kernel(src).unwrap_or(fallback)
}
