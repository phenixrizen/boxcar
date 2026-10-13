// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `memfd_create`: a process in the session made an anonymous memory file.

use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;
use aya_ebpf::macros::fentry;
use aya_ebpf::programs::FEntryContext;
use boxcar_sensor_common::{Kind, MemfdEvent};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::pt_regs;

#[fentry(function = "__x64_sys_memfd_create")]
pub fn memfd_create(ctx: FEntryContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let regs: *const pt_regs = ctx.arg(0);
    let Some(mut entry) = EVENTS.reserve::<MemfdEvent>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; the registers are the syscall
    // wrapper's argument, and the name is read from user memory through
    // the checked helper.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::Memfd);
        let name = read_or(&raw const (*regs).di, 0) as *const u8;
        (*ev).flags = read_or(&raw const (*regs).si, 0) as u32;
        (*ev).name_len = match bpf_probe_read_user_str_bytes(name, &mut (*ev).name) {
            Ok(name) => name.len() as u32,
            Err(_) => 0,
        };
    }
    entry.submit(0);
    0
}
