// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! `socket_connect`: a process in the session asked to connect a socket.
//! Observation only: the hook returns 0.

use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;
use boxcar_sensor_common::{ConnectAttempt, Kind, AF_INET, AF_INET6};

use crate::common::{count_drop, fill_header, in_session, read_or, EVENTS};
use crate::vmlinux::{sock, sockaddr, sockaddr_in, sockaddr_in6, socket};

/// `sizeof(struct sockaddr_in)` and `sizeof(struct sockaddr_in6)`.
const IN_LEN: i32 = 16;
const IN6_LEN: i32 = 28;

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    if !in_session() {
        return 0;
    }
    let sock: *const socket = ctx.arg(0);
    let address: *const sockaddr = ctx.arg(1);
    let addrlen: i32 = ctx.arg(2);
    let Some(mut entry) = EVENTS.reserve::<ConnectAttempt>(0) else {
        count_drop();
        return 0;
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is a reserved record; the hook's arguments are read
    // through the checked helpers.
    unsafe {
        fill_header(&raw mut (*ev).header, Kind::ConnectAttempt);
        let family = read_or(&raw const (*address).sa_family, 0);
        (*ev).family = family;
        (*ev).dst_port = 0;
        (*ev).dst = [0; 16];
        let sk: *const sock = read_or(&raw const (*sock).sk, core::ptr::null_mut()).cast_const();
        (*ev).proto = if sk.is_null() {
            0
        } else {
            u32::from(read_or(&raw const (*sk).sk_protocol, 0))
        };
        if family == AF_INET && addrlen >= IN_LEN {
            let sa = address as *const sockaddr_in;
            (*ev).dst_port = u16::from_be(read_or(&raw const (*sa).sin_port, 0));
            let addr: u32 = read_or(&raw const (*sa).sin_addr.s_addr, 0);
            core::ptr::copy_nonoverlapping(
                addr.to_ne_bytes().as_ptr(),
                (&raw mut (*ev).dst).cast::<u8>(),
                4,
            );
        } else if family == AF_INET6 && addrlen >= IN6_LEN {
            let sa6 = address as *const sockaddr_in6;
            (*ev).dst_port = u16::from_be(read_or(&raw const (*sa6).sin6_port, 0));
            (*ev).dst = read_or(&raw const (*sa6).sin6_addr.in6_u.u6_addr8, [0; 16]);
        }
    }
    entry.submit(0);
    0
}
