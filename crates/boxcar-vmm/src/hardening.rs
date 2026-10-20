// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Confining the VMM process: a Landlock domain over the paths a session
//! uses ([`domain`]), applied by `boxcar run` before its first thread, and
//! one seccomp allowlist for every thread ([`seccomp`]), installed by
//! [`crate::vmm::Vmm::new`] once the VM is built. Both are recorded in
//! `vmm.start` as `hardening`.
//!
//! A call off the allowlist kills the process: a crash, with no `vmm.stop`.
//! Guest memory is kept out of the core dump
//! ([`crate::memory::exclude_from_core_dumps`]).

pub mod domain;
pub mod seccomp;

pub use boxcar_proto::{Hardening, LandlockStatus, SeccompMode};
