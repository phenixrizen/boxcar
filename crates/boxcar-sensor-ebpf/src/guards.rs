// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! The sensor's self-protection: `bpf()` is for the sensor alone, and a
//! signal to the sensor from anyone but init or itself is refused. Each
//! refusal is reported.

use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;
use boxcar_sensor_common::{Hook, Kind, LsmDeny};

use crate::common::{count_drop, current_tgid, fill_header, read_or, sensor_tgid, EVENTS};
use crate::vmlinux::task_struct;

/// `-EPERM`.
const DENIED: i32 = -1;

/// Init's process id.
const INIT_TGID: u32 = 1;

#[lsm(hook = "bpf")]
pub fn bpf_guard(ctx: LsmContext) -> i32 {
    if u64::from(current_tgid()) == sensor_tgid() {
        return 0;
    }
    let cmd: i32 = ctx.arg(0);
    deny(Hook::Bpf, i64::from(cmd))
}

#[lsm(hook = "task_kill")]
pub fn kill_guard(ctx: LsmContext) -> i32 {
    let target: *const task_struct = ctx.arg(0);
    let sig: i32 = ctx.arg(2);
    // SAFETY: the hook's argument, read through the checked helper.
    let target_tgid = unsafe { read_or(&raw const (*target).tgid, 0) } as u32;
    if u64::from(target_tgid) != sensor_tgid() {
        return 0;
    }
    let caller = current_tgid();
    if u64::from(caller) == sensor_tgid() || caller == INIT_TGID || sig == 0 {
        return 0;
    }
    deny(Hook::TaskKill, i64::from(sig))
}

/// Reports a refusal and refuses.
fn deny(hook: Hook, detail: i64) -> i32 {
    match EVENTS.reserve::<LsmDeny>(0) {
        Some(mut entry) => {
            let ev = entry.as_mut_ptr();
            // SAFETY: `ev` is a reserved record.
            unsafe {
                fill_header(&raw mut (*ev).header, Kind::LsmDeny);
                (*ev).hook = hook as u32;
                (*ev)._pad = 0;
                (*ev).detail = detail;
            }
            entry.submit(0);
        }
        None => count_drop(),
    }
    DENIED
}
