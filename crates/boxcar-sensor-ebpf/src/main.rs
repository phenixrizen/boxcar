// SPDX-License-Identifier: MIT OR GPL-2.0
// Copyright 2026 The boxcar Authors

//! The guest sensor's eBPF programs: process lineage (`exec`, `fork`,
//! `exit`), connections (`socket_connect`, `tcp_connect`), anonymous files
//! (`memfd_create`), sampled opens (`file_open`), and the self-protection
//! (`bpf`, `task_kill`). Every event is a struct of `boxcar-sensor-common`
//! in the `EVENTS` ring buffer; every program but the guards reports only
//! for tasks in the session's cgroup (`SESSION_CGROUP`, set by the loader).
//!
//! The object's `license` section is `Dual MIT/GPL` so the kernel lets it
//! use the GPL-only helpers and the LSM hooks (docs/ebpf-license.md). The
//! kernel types the programs read are `vmlinux`, generated from the guest
//! kernel's BTF by `cargo xtask gen-vmlinux`.

#![no_std]
#![no_main]

mod common;
mod connect;
mod exec;
mod exit;
mod file_open;
mod fork;
mod guards;
mod memfd;
mod tcp;
#[rustfmt::skip]
mod vmlinux;

/// The target has no unwinding; the verifier rejects a program in which
/// this is reachable, so no program may panic.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
