// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest sensor: ring 1 of the audit log. Started by init before the
//! session's privileges drop, it loads the eBPF programs it carries
//! ([`object`]), attaches them, and streams their events to the VMM over
//! vsock port 1026 as `proc.*` records, with a heartbeat every second.
//!
//! Task 3 of the M3 plan builds the programs in; Task 4 gives this binary
//! its behaviour. Until then it reports what it carries and exits.

mod object;

fn main() {
    println!(
        "boxcar-sensor: carrying {} bytes of eBPF programs",
        object::OBJECT.len()
    );
}
