// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! TLS writes and reads of a runtime that exports OpenSSL's functions:
//! probes on `SSL_write`, `SSL_write_ex`, `SSL_read` and `SSL_read_ex`,
//! which the userspace sensor attaches to each file it finds them in. Only
//! the size and the time of each call are reported; the buffer is never
//! read. A read's size is known at its return: the entry probe notes the
//! thread (and, for `SSL_read_ex`, where its `readbytes` goes), the return
//! probe reports.

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user};
use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use boxcar_sensor_common::programs::TLS_READS_ENTRIES;
use boxcar_sensor_common::{Kind, TlsIoEvent, TLS_DIR_READ, TLS_DIR_WRITE};

use crate::common::{count_drop, fill_header, in_session, EVENTS};

/// The reads under way, by thread: for `SSL_read_ex` the address of its
/// `readbytes` out-parameter, for `SSL_read` 0.
#[map]
pub static TLS_READS: HashMap<u32, u64> = HashMap::with_max_entries(TLS_READS_ENTRIES, 0);

#[inline(always)]
fn current_tid() -> u32 {
    bpf_get_current_pid_tgid() as u32
}

/// One `TlsIoEvent` into the ring buffer.
#[inline(always)]
fn report(dir: u32, bytes: u32) {
    let Some(mut entry) = EVENTS.reserve::<TlsIoEvent>(0) else {
        count_drop();
        return;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::TlsIo);
        (*ev).dir = dir;
        (*ev).bytes = bytes;
    }
    entry.submit(0);
}

/// A byte count as the event carries it.
#[inline(always)]
fn clamp(n: usize) -> u32 {
    if n > u32::MAX as usize {
        u32::MAX
    } else {
        n as u32
    }
}

/// `int SSL_write(SSL *ssl, const void *buf, int num)`.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    if !in_session() {
        return 0;
    }
    let num: i32 = ctx.arg(2).unwrap_or(0);
    if num > 0 {
        report(TLS_DIR_WRITE, num as u32);
    }
    0
}

/// `int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)`.
#[uprobe]
pub fn ssl_write_ex(ctx: ProbeContext) -> u32 {
    if !in_session() {
        return 0;
    }
    let num: usize = ctx.arg(2).unwrap_or(0);
    if num > 0 {
        report(TLS_DIR_WRITE, clamp(num));
    }
    0
}

/// `int SSL_read(SSL *ssl, void *buf, int num)`: the size comes at the
/// return.
#[uprobe]
pub fn ssl_read(_ctx: ProbeContext) -> u32 {
    if !in_session() {
        return 0;
    }
    let _ = TLS_READS.insert(&current_tid(), &0u64, 0);
    0
}

/// The return of `SSL_read`: the bytes read when positive.
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    if !in_session() {
        return 0;
    }
    let tid = current_tid();
    if TLS_READS.get_ptr(&tid).is_none() {
        return 0;
    }
    let _ = TLS_READS.remove(&tid);
    let ret: i32 = ctx.ret();
    if ret > 0 {
        report(TLS_DIR_READ, ret as u32);
    }
    0
}

/// `int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)`:
/// the size is written to `readbytes`, read at the return.
#[uprobe]
pub fn ssl_read_ex(ctx: ProbeContext) -> u32 {
    if !in_session() {
        return 0;
    }
    let readbytes: *const usize = ctx.arg(3).unwrap_or(core::ptr::null());
    let _ = TLS_READS.insert(&current_tid(), &(readbytes as u64), 0);
    0
}

/// The return of `SSL_read_ex`: `*readbytes` when the call succeeded.
#[uretprobe]
pub fn ssl_read_ex_ret(ctx: RetProbeContext) -> u32 {
    if !in_session() {
        return 0;
    }
    let tid = current_tid();
    let Some(slot) = TLS_READS.get_ptr(&tid) else {
        return 0;
    };
    // SAFETY: the pointer is into the map's value, valid while this
    // program runs.
    let readbytes = unsafe { *slot };
    let _ = TLS_READS.remove(&tid);
    let ret: i32 = ctx.ret();
    if ret != 1 || readbytes == 0 {
        return 0;
    }
    // SAFETY: the helper checks the user address before reading it.
    let n: usize = unsafe { bpf_probe_read_user(readbytes as *const usize) }.unwrap_or(0);
    if n > 0 {
        report(TLS_DIR_READ, clamp(n));
    }
    0
}
