// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `sched_process_exit`: a thread in the session ended.

use aya_ebpf::macros::btf_tracepoint;
use aya_ebpf::programs::BtfTracePointContext;
use boxcar_sensor_common::{ExitEvent, Kind};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::task_struct;

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let task: *const task_struct = ctx.arg(0);
    // The tracepoint's `bool group_dead`, in a register.
    let group_dead: u8 = ctx.arg(1);
    let Some(mut entry) = EVENTS.reserve::<ExitEvent>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; `task` is the tracepoint's argument.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::Exit);
        (*ev).exit_code = read_or(&raw const (*task).exit_code, 0);
        (*ev).group_dead = u32::from(group_dead != 0);
        (*ev).start_ns = read_or(&raw const (*task).start_time, 0);
    }
    entry.submit(0);
    0
}
