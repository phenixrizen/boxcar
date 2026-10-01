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
// src/vmm/src/arch/x86_64/layout.rs at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: the PVH, ACPI, PCI and 64-bit
// MMIO constants are dropped; the GDT, IDT, page table, virtio-mmio slot and
// page size constants are added.

//! Magic addresses externally used to lay out x86_64 VMs.

/// GDT: four 8-byte descriptors (null, code, data, TSS).
pub const BOOT_GDT_START: u64 = 0x500;

/// IDT: a single null descriptor, right after the GDT.
pub const BOOT_IDT_START: u64 = 0x520;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// Boot page tables: PML4, then one PDPTE page, then one PDE page of 512
/// 2 MiB entries identity-mapping the first 1 GiB.
pub const PML4_START: u64 = 0x9000;
/// See [`PML4_START`].
pub const PDPTE_START: u64 = 0xa000;
/// See [`PML4_START`].
pub const PDE_START: u64 = 0xb000;

/// Kernel command line start address.
pub const CMDLINE_START: u64 = 0x20000;
/// Kernel command line maximum size, including the NUL terminator.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Start of memory region we will use for system data (the MP table). We are
/// putting its start address where EBDA normally starts, i.e. in the last
/// 1 KiB of the first 640 KiB of memory. Everything from here to
/// [`HIMEM_START`] is reported as reserved in the e820 map.
pub const SYSTEM_MEM_START: u64 = 0x9fc00;

/// The MP floating pointer and configuration table.
pub const MPTABLE_START: u64 = SYSTEM_MEM_START;

/// Start of the high memory; the kernel is loaded here.
pub const HIMEM_START: u64 = 0x0010_0000; // 1 MB.

/// APIC address
pub const APIC_ADDR: u32 = 0xfee0_0000;

/// IOAPIC address
pub const IOAPIC_ADDR: u32 = 0xfec0_0000;

// Typically, on x86 systems 24 IRQs are used for legacy devices (0-23).
// However, the first 5 are reserved.
/// First usable GSI for legacy interrupts (IRQ) on x86_64.
pub const GSI_LEGACY_START: u32 = 5;
/// Last usable GSI for legacy interrupts (IRQ) on x86_64.
pub const GSI_LEGACY_END: u32 = 23;
/// Number of legacy GSI (IRQ) available on x86_64.
pub const GSI_LEGACY_NUM: u32 = GSI_LEGACY_END - GSI_LEGACY_START + 1;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// First address that cannot be addressed using 32 bit anymore.
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

/// The size of the memory area reserved for MMIO 32-bit accesses.
pub const MMIO32_MEM_SIZE: u64 = 1 << 30;
/// The start of the memory area reserved for MMIO 32-bit accesses. Guest RAM
/// below 4 GiB ends here; RAM beyond it continues at
/// [`FIRST_ADDR_PAST_32BITS`].
pub const MMIO32_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MMIO32_MEM_SIZE;

/// The first virtio-mmio device slot.
pub const VIRTIO_MMIO_START: u64 = MMIO32_MEM_START;
/// The size of one virtio-mmio device slot.
pub const VIRTIO_MMIO_SLOT_SIZE: u64 = 0x1000;

/// The guest page size, used to align the initrd.
pub const GUEST_PAGE_SIZE: u64 = 0x1000;

// The GDT's four descriptors end where the IDT starts, and nothing low
// overlaps the zero page, the stack, the page tables or the command line.
// Checked at compile time.
const _: () = {
    assert!(BOOT_GDT_START + 4 * 8 == BOOT_IDT_START);
    assert!(BOOT_IDT_START + 8 <= ZERO_PAGE_START);
    assert!(ZERO_PAGE_START + 4096 <= BOOT_STACK_POINTER);
    assert!(BOOT_STACK_POINTER < PML4_START);
    assert!(PML4_START + 0x1000 == PDPTE_START);
    assert!(PDPTE_START + 0x1000 == PDE_START);
    assert!(PDE_START + 512 * 8 <= CMDLINE_START);
    assert!(CMDLINE_START + CMDLINE_MAX_SIZE as u64 <= MPTABLE_START);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The guest physical layout exactly as the global constraints state it.
    #[test]
    fn layout_matches_the_global_constraints() {
        assert_eq!(BOOT_GDT_START, 0x500);
        assert_eq!(BOOT_IDT_START, 0x520);
        assert_eq!(ZERO_PAGE_START, 0x7000);
        assert_eq!(BOOT_STACK_POINTER, 0x8ff0);
        assert_eq!(PML4_START, 0x9000);
        assert_eq!(PDPTE_START, 0xa000);
        assert_eq!(PDE_START, 0xb000);
        assert_eq!(CMDLINE_START, 0x20000);
        assert_eq!(CMDLINE_MAX_SIZE, 2048);
        assert_eq!(MPTABLE_START, 0x9fc00);
        assert_eq!(HIMEM_START, 0x100000);
        assert_eq!(VIRTIO_MMIO_START, 0xC000_0000);
        assert_eq!(MMIO32_MEM_START, 0xC000_0000);
        assert_eq!(VIRTIO_MMIO_SLOT_SIZE, 4096);
        assert_eq!((GSI_LEGACY_START, GSI_LEGACY_END), (5, 23));
        assert_eq!(GSI_LEGACY_NUM, 19);
        assert_eq!(KVM_TSS_ADDRESS, 0xFFFB_D000);
        assert_eq!(FIRST_ADDR_PAST_32BITS, 0x1_0000_0000);
    }
}
