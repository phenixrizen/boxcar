// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `sched_process_exec`: a process in the session ran a new program.

use aya_ebpf::helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf};
use aya_ebpf::macros::btf_tracepoint;
use aya_ebpf::programs::BtfTracePointContext;
use boxcar_sensor_common::{ExecEvent, Kind, ARGV_MAX};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::{linux_binprm, mm_struct, task_struct};

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let task: *const task_struct = ctx.arg(0);
    let bprm: *const linux_binprm = ctx.arg(2);
    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; `task` and `bprm` are the
    // tracepoint's arguments, read through the checked helpers.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::Exec);
        let parent: *const task_struct =
            read_or(&raw const (*task).real_parent, core::ptr::null_mut()).cast_const();
        (*ev).ppid = if parent.is_null() {
            0
        } else {
            read_or(&raw const (*parent).tgid, 0) as u32
        };
        (*ev).start_ns = read_or(&raw const (*task).start_time, 0);

        let filename: *const core::ffi::c_char = read_or(&raw const (*bprm).filename, core::ptr::null());
        (*ev).filename_len = match bpf_probe_read_kernel_str_bytes(filename as *const u8, &mut (*ev).filename) {
            Ok(name) => name.len() as u32,
            Err(_) => 0,
        };

        (*ev).argv_len = 0;
        (*ev).argv_truncated = 0;
        let mm: *const mm_struct = read_or(&raw const (*task).mm, core::ptr::null_mut()).cast_const();
        if !mm.is_null() {
            let arg_start = read_or(&raw const (*mm).__bindgen_anon_1.arg_start, 0) as usize;
            let arg_end = read_or(&raw const (*mm).__bindgen_anon_1.arg_end, 0) as usize;
            let mut len = arg_end.saturating_sub(arg_start);
            if len > ARGV_MAX {
                len = ARGV_MAX;
                (*ev).argv_truncated = 1;
            }
            let argv: &mut [u8] = &mut (*ev).argv;
            if let Some(dst) = argv.get_mut(..len) {
                if bpf_probe_read_user_buf(arg_start as *const u8, dst).is_ok() {
                    (*ev).argv_len = len as u32;
                }
            }
        }
    }
    entry.submit(0);
    0
}
