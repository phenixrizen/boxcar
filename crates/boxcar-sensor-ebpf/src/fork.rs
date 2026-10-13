// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `sched_process_fork`: a process in the session made a new task: a
//! process, or a thread of its own, which the reconciler needs to know too.

use aya_ebpf::macros::btf_tracepoint;
use aya_ebpf::programs::BtfTracePointContext;
use boxcar_sensor_common::{ForkEvent, Kind};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::task_struct;

#[btf_tracepoint(function = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let child: *const task_struct = ctx.arg(1);
    // SAFETY: the tracepoint's argument, read through the checked helper.
    let (pid, tgid) = unsafe {
        (
            read_or(&raw const (*child).pid, 0),
            read_or(&raw const (*child).tgid, 0),
        )
    };
    let Some(mut entry) = EVENTS.reserve::<ForkEvent>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::Fork);
        (*ev).child_pid = pid as u32;
        (*ev).thread = u32::from(pid != tgid);
        (*ev).child_start_ns = read_or(&raw const (*child).start_time, 0);
    }
    entry.submit(0);
    0
}
