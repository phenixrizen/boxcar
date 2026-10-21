// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `bprm_check_security`, sleepable: a program whose name the policy
//! denies (`[exec] deny`, its globs' last components, sent by the VMM into
//! `EXEC_DENY`) is refused with `-EPERM` wherever it is, and the refusal
//! reported. Ring 0 refuses the same names by path on the shares; this
//! catches a copy elsewhere under the same name.

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::LsmContext;
use boxcar_sensor_common::programs::EXEC_DENY_ENTRIES;
use boxcar_sensor_common::{ExecDeniedEvent, ExecName, Kind, EXEC_NAME_MAX, PATH_MAX};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::linux_binprm;

/// The names the policy denies, NUL-padded; the value is unused.
#[map]
pub static EXEC_DENY: HashMap<ExecName, u8> = HashMap::with_max_entries(EXEC_DENY_ENTRIES, 0);

/// `-EPERM`.
const DENIED: i32 = -1;

#[lsm(hook = "bprm_check_security", sleepable)]
pub fn exec_deny(ctx: LsmContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let bprm: *const linux_binprm = ctx.arg(0);
    // The record first: its buffer holds the path while the name is read
    // out of it, and goes back unused when the program is allowed.
    let Some(mut entry) = EVENTS.reserve::<ExecDeniedEvent>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; `bprm` is the hook's argument,
    // read through the checked helpers.
    let denied = unsafe {
        let filename: *const core::ffi::c_char =
            read_or(&raw const (*bprm).filename, core::ptr::null());
        let len = match bpf_probe_read_kernel_str_bytes(filename as *const u8, &mut (*ev).filename)
        {
            Ok(name) => name.len(),
            Err(_) => 0,
        };
        (*ev).filename_len = len as u32;
        (*ev)._pad = 0;
        is_denied(&(*ev).filename, len)
    };
    if !denied {
        entry.discard(0);
        return 0;
    }
    // SAFETY: `ev` is the reserved record, filled above.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::ExecDenied);
    }
    entry.submit(0);
    DENIED
}

/// Whether the last component of `path[..len]` is in `EXEC_DENY`.
///
/// The name is read backwards from the end, at most `EXEC_NAME_MAX`
/// bytes: a name that long or longer is never in the map, so the scan
/// need go no further, and the verifier walks two short loops instead of
/// the whole path.
#[inline(always)]
fn is_denied(path: &[u8; PATH_MAX], len: usize) -> bool {
    let len = if len > PATH_MAX { PATH_MAX } else { len };
    // Bytes of the name found so far, counting back from the end.
    let mut name_len = 0usize;
    let mut found = false;
    let mut back = 0usize;
    while back < EXEC_NAME_MAX {
        if back >= len {
            // The path's start, with no `/`: the whole path is the name.
            name_len = back;
            found = true;
            break;
        }
        let at = len - 1 - back;
        if at >= PATH_MAX {
            break;
        }
        if path[at] == b'/' {
            name_len = back;
            found = true;
            break;
        }
        back += 1;
    }
    if !found || name_len == 0 || name_len >= EXEC_NAME_MAX {
        return false;
    }
    let start = len - name_len;
    let mut key: ExecName = [0; EXEC_NAME_MAX];
    let mut j = 0usize;
    while j < EXEC_NAME_MAX {
        if j >= name_len {
            break;
        }
        let at = start + j;
        if at >= PATH_MAX {
            break;
        }
        key[j] = path[at];
        j += 1;
    }
    // SAFETY: the map's own lookup; the value is not read.
    unsafe { EXEC_DENY.get(&key) }.is_some()
}
