// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! KVM virtual machine monitor: memory, boot, vCPUs, buses, and the run loop.

pub mod arch;
pub mod cmdline;
pub mod console;
pub mod control;
pub mod devices;
pub mod guest_ctl;
pub mod kick;
pub mod kvm;
pub mod lifecycle;
pub mod memory;
pub mod pty;
pub mod services;
pub mod stdin;
pub mod vcpu;
pub mod vmm;
