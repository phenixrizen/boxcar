// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `file_open`, sleepable: one open in `FILE_OPEN_SAMPLE` per CPU, with the
//! path the kernel resolves (`bpf_d_path`). Observation only.

use aya_ebpf::helpers::bpf_d_path;
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;
use boxcar_sensor_common::programs::FILE_OPEN_SAMPLE;
use boxcar_sensor_common::{FileOpen, Kind, PATH_MAX};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS, SAMPLES};
use crate::vmlinux::file;

#[lsm(hook = "file_open", sleepable)]
pub fn file_open(ctx: LsmContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let Some(counter) = SAMPLES.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: a per-CPU slot of the map, ours while this program runs.
    let n = unsafe {
        *counter = (*counter).wrapping_add(1);
        *counter
    };
    if n % FILE_OPEN_SAMPLE != 0 {
        return 0;
    }
    let file: *mut file = ctx.arg(0);
    let Some(mut entry) = EVENTS.reserve::<FileOpen>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; `file` is the hook's argument, and
    // `bpf_d_path` takes the address of its `f_path`.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::FileOpen);
        (*ev).flags = read_or(&raw const (*file).f_flags, 0);
        (*ev).sample = FILE_OPEN_SAMPLE as u32;
        (*ev)._pad = 0;
        let written = bpf_d_path(
            // aya's helper names the kernel's `path` through its own bindings;
            // ours is the same struct from the same kernel.
            (&raw mut (*file).__bindgen_anon_1.f_path).cast::<aya_ebpf::bindings::path>(),
            (&raw mut (*ev).path).cast(),
            PATH_MAX as u32,
        );
        // The helper's count includes the terminating NUL.
        (*ev).path_len = if written > 0 {
            (written as u32).saturating_sub(1)
        } else {
            0
        };
    }
    entry.submit(0);
    0
}
