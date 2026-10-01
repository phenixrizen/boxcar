// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! KVM virtual machine monitor: memory, boot, vCPUs, buses, and the run loop.

pub mod arch;
pub mod cmdline;
pub mod control;
pub mod devices;
pub mod kick;
pub mod kvm;
pub mod lifecycle;
pub mod memory;
pub mod stdin;
pub mod vcpu;
pub mod vmm;
