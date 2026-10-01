// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from Firecracker (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/arch/x86_64/mod.rs (module layout) and the guest memory helpers
// of src/vmm/src/test_utils/mod.rs at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. The boot configuration that Firecracker
// keeps in this file is in boot.rs; the memory layout functions are in
// crate::memory.

//! x86_64 boot setup: guest physical layout, the zero page and e820 map, the
//! MP table, and each vCPU's boot registers, MSRs, CPUID and LAPIC. Everything
//! here that does not take a `VcpuFd` works on a plain `GuestMemoryMmap`.

/// The zero page and the MP table.
pub mod boot;
/// Per-vCPU CPUID patching.
pub mod cpuid;
mod gdt;
/// Contains logic for setting up Advanced Programmable Interrupt Controller (local version).
pub mod interrupts;
/// Layout for the x86_64 system.
pub mod layout;
mod mpspec;
mod mptable;
/// Logic for configuring x86_64 model specific registers (MSRs).
pub mod msr;
/// Logic for configuring x86_64 registers.
pub mod regs;

#[cfg(test)]
pub(crate) mod test_utils {
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    /// Guest memory of `size` bytes at `start`.
    pub(crate) fn single_region_mem_at(start: u64, size: usize) -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(start), size)]).unwrap()
    }

    /// Guest memory of `size` bytes at address 0.
    pub(crate) fn single_region_mem(size: usize) -> GuestMemoryMmap {
        single_region_mem_at(0, size)
    }

    /// Guest memory of `size` bytes laid out as boxcar lays out a guest.
    pub(crate) fn arch_mem(size: u64) -> GuestMemoryMmap {
        crate::memory::create_guest_memory(size).unwrap()
    }

    /// A `Kvm` handle, or `None` after printing why KVM is not usable here.
    #[cfg(feature = "kvm-tests")]
    pub(crate) fn kvm_or_skip(test: &str) -> Option<kvm_ioctls::Kvm> {
        match crate::kvm::kvm_available() {
            Ok(()) => Some(kvm_ioctls::Kvm::new().unwrap()),
            Err(reason) => {
                eprintln!("skipping {test}: {reason}");
                None
            }
        }
    }

    /// A VM with one vCPU, or `None` after printing why KVM is not usable.
    #[cfg(feature = "kvm-tests")]
    pub(crate) fn vcpu_or_skip(
        test: &str,
    ) -> Option<(kvm_ioctls::Kvm, kvm_ioctls::VmFd, kvm_ioctls::VcpuFd)> {
        let kvm = kvm_or_skip(test)?;
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        Some((kvm, vm, vcpu))
    }
}
