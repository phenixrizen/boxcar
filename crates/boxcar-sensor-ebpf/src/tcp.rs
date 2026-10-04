// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `tcp_connect`: the kernel sends a connection's first segment; the
//! 4-tuple is settled.

use aya_ebpf::macros::fentry;
use aya_ebpf::programs::FEntryContext;
use boxcar_sensor_common::{Kind, TcpConnect, AF_INET6};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::sock;

#[fentry(function = "tcp_connect")]
pub fn tcp_connect(ctx: FEntryContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let sk: *const sock = ctx.arg(0);
    let Some(mut entry) = EVENTS.reserve::<TcpConnect>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; `sk` is the function's argument,
    // read through the checked helpers.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::TcpConnect);
        let common = &raw const (*sk).__sk_common;
        let family = read_or(&raw const (*common).skc_family, 0);
        (*ev).family = family;
        (*ev)._pad = 0;
        let ports = &raw const (*common).__bindgen_anon_3.__bindgen_anon_1;
        (*ev).dst_port = u16::from_be(read_or(&raw const (*ports).skc_dport, 0));
        (*ev).src_port = read_or(&raw const (*ports).skc_num, 0);
        (*ev).src = [0; 16];
        (*ev).dst = [0; 16];
        if family == AF_INET6 {
            (*ev).src = read_or(&raw const (*common).skc_v6_rcv_saddr.in6_u.u6_addr8, [0; 16]);
            (*ev).dst = read_or(&raw const (*common).skc_v6_daddr.in6_u.u6_addr8, [0; 16]);
        } else {
            let addrs = &raw const (*common).__bindgen_anon_1.__bindgen_anon_1;
            let saddr: u32 = read_or(&raw const (*addrs).skc_rcv_saddr, 0);
            let daddr: u32 = read_or(&raw const (*addrs).skc_daddr, 0);
            core::ptr::copy_nonoverlapping(
                saddr.to_ne_bytes().as_ptr(),
                (&raw mut (*ev).src).cast::<u8>(),
                4,
            );
            core::ptr::copy_nonoverlapping(
                daddr.to_ne_bytes().as_ptr(),
                (&raw mut (*ev).dst).cast::<u8>(),
                4,
            );
        }
    }
    entry.submit(0);
    0
}
