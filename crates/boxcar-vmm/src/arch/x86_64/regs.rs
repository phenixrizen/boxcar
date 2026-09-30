// Copyright © 2020, Oracle and/or its affiliates.
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
// src/vmm/src/arch/x86_64/regs.rs at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: the PVH path is dropped (Linux
// 64-bit boot only); the register values are built by pure functions
// (`boot_regs`, `boot_fpu`, `boot_sregs`) that the vCPU setters wrap; errors
// are `arch::Error`; the tests that need a vCPU run behind `kvm-tests`.

//! The boot register state of the BSP: long mode with paging on, flat
//! segments from a four-entry GDT, identity-mapped page tables for the first
//! 1 GiB, and the Linux 64-bit boot protocol's `rip`, `rsp` and `rsi`.

use std::mem;

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs};
use kvm_ioctls::VcpuFd;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use super::gdt::{gdt_entry, kvm_segment_from_gdt};
use super::layout::{
    BOOT_GDT_START, BOOT_IDT_START, BOOT_STACK_POINTER, PDE_START, PDPTE_START, PML4_START,
    ZERO_PAGE_START,
};
use crate::arch::{kvm_error, write_error, Error, Result};

const BOOT_GDT_OFFSET: u64 = BOOT_GDT_START;
const BOOT_IDT_OFFSET: u64 = BOOT_IDT_START;

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

/// The FPU state of a vCPU at boot: the x87 control word and MXCSR at their
/// reset values.
pub fn boot_fpu() -> kvm_fpu {
    kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    }
}

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<()> {
    vcpu.set_fpu(&boot_fpu()).map_err(kvm_error("set_fpu"))
}

/// The general-purpose registers of the BSP at the 64-bit kernel entry.
pub fn boot_regs(entry_addr: GuestAddress) -> kvm_regs {
    kvm_regs {
        // Configure regs as required by Linux 64-bit boot protocol.
        rflags: 0x0000_0000_0000_0002u64,
        rip: entry_addr.raw_value(),
        // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments
        // are made to rsp (i.e. reserving space for local variables or pushing
        // values on to the stack), local variables and function parameters are
        // still accessible from a constant offset from rbp.
        rsp: BOOT_STACK_POINTER,
        // Starting stack pointer.
        rbp: BOOT_STACK_POINTER,
        // Must point to zero page address per Linux ABI. This is x86_64 specific.
        rsi: ZERO_PAGE_START,
        ..Default::default()
    }
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `entry_addr` - Starting instruction pointer.
pub fn setup_regs(vcpu: &VcpuFd, entry_addr: GuestAddress) -> Result<()> {
    vcpu.set_regs(&boot_regs(entry_addr))
        .map_err(kvm_error("set_regs"))
}

/// Writes the GDT, IDT and boot page tables into `mem` and puts `sregs` in
/// 64-bit mode on them: flat code, data and TSS segments, `cr3` at the PML4,
/// PAE, protected mode, paging, and `EFER.LME | EFER.LMA`.
pub fn boot_sregs(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    configure_segments_and_sregs(mem, sregs)?;
    setup_page_tables(mem, sregs)
}

/// Configures the special registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &VcpuFd) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(kvm_error("get_sregs"))?;
    boot_sregs(mem, &mut sregs)?;
    vcpu.set_sregs(&sregs).map_err(kvm_error("set_sregs"))
}

/// The four boot GDT entries, as specified by the Linux 64-bit boot protocol.
fn boot_gdt_table() -> [u64; BOOT_GDT_MAX] {
    [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt_entry(0x808b, 0, 0xfffff), // TSS
    ]
}

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::NotEnoughMemory("GDT"))?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(write_error("GDT"))?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(write_error("IDT"))
}

fn configure_segments_and_sregs(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    // Configure GDT entries as specified by Linux 64bit boot protocol
    let gdt_table = boot_gdt_table();

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = (mem::size_of::<[u64; BOOT_GDT_MAX]>() - 1) as u16;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = (mem::size_of::<u64>() - 1) as u16;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    // 64-bit protected mode
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    Ok(())
}

fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
        .map_err(write_error("PML4"))?;

    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
        .map_err(write_error("PDPTE"))?;
    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(write_error("PDE"))?;
    }

    sregs.cr3 = boot_pml4_addr.raw_value();
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]

    use super::*;
    use crate::arch::x86_64::test_utils::single_region_mem;

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0xaf_9b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf_9300_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f_8b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 24));

        assert_eq!(0xffff_ffff, sregs.tr.limit);

        assert!(sregs.cr0 & X86_CR0_PE != 0);
        assert!(sregs.efer & EFER_LME != 0 && sregs.efer & EFER_LMA != 0);

        assert_eq!(0x0, read_u64(gm, BOOT_GDT_OFFSET));
        assert_eq!(0x0, read_u64(gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xffff_ffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0, sregs.tr.avl);
    }

    fn validate_page_tables(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0xa003, read_u64(gm, PML4_START));
        assert_eq!(0xb003, read_u64(gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(gm, PDE_START + (i * 8)));
        }

        assert_eq!(PML4_START, sregs.cr3);
        assert!(sregs.cr4 & X86_CR4_PAE != 0);
        assert!(sregs.cr0 & X86_CR0_PG != 0);
    }

    #[test]
    fn test_write_gdt_table() {
        // Not enough memory for the gdt table to be written.
        let gm = single_region_mem(BOOT_GDT_OFFSET as usize);
        let gdt_table: [u64; BOOT_GDT_MAX] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];
        write_gdt_table(&gdt_table, &gm).unwrap_err();

        // We allocate exactly the amount needed to write four u64 to `BOOT_GDT_OFFSET`.
        let gm =
            single_region_mem(BOOT_GDT_OFFSET as usize + (mem::size_of::<u64>() * BOOT_GDT_MAX));

        let gdt_table: [u64; BOOT_GDT_MAX] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];
        write_gdt_table(&gdt_table, &gm).unwrap();
    }

    #[test]
    fn test_write_idt_table() {
        // Not enough memory for the a u64 value to fit.
        let gm = single_region_mem(BOOT_IDT_OFFSET as usize);
        let val = 0x100;
        write_idt_value(val, &gm).unwrap_err();

        let gm = single_region_mem(BOOT_IDT_OFFSET as usize + mem::size_of::<u64>());
        // We have allocated exactly the amount neded to write an u64 to `BOOT_IDT_OFFSET`.
        write_idt_value(val, &gm).unwrap();
    }

    #[test]
    fn test_configure_segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = single_region_mem(0x10000);
        configure_segments_and_sregs(&gm, &mut sregs).unwrap();

        validate_segments_and_sregs(&gm, &sregs);
    }

    #[test]
    fn test_setup_page_tables() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = single_region_mem(PML4_START as usize);
        setup_page_tables(&gm, &mut sregs).unwrap_err();

        let gm = single_region_mem(PDPTE_START as usize);
        setup_page_tables(&gm, &mut sregs).unwrap_err();

        let gm = single_region_mem(PDE_START as usize);
        setup_page_tables(&gm, &mut sregs).unwrap_err();

        let gm = single_region_mem(0x10000);
        setup_page_tables(&gm, &mut sregs).unwrap();

        validate_page_tables(&gm, &sregs);
    }

    /// The selectors, GDT/IDT registers and control registers the brief
    /// names, from a zeroed `kvm_sregs`.
    #[test]
    fn boot_sregs_selectors_and_control_registers() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = single_region_mem(0x10000);
        boot_sregs(&gm, &mut sregs).unwrap();

        validate_segments_and_sregs(&gm, &sregs);
        validate_page_tables(&gm, &sregs);
        assert_eq!((sregs.gdt.base, sregs.gdt.limit), (0x500, 31));
        assert_eq!((sregs.idt.base, sregs.idt.limit), (0x520, 7));
        assert_eq!(sregs.cs.selector, 0x8);
        assert_eq!(
            (sregs.cs.base, sregs.cs.limit, sregs.cs.l),
            (0, 0xffff_ffff, 1)
        );
        for seg in [sregs.ds, sregs.es, sregs.fs, sregs.gs, sregs.ss] {
            assert_eq!((seg.selector, seg.base, seg.limit), (0x10, 0, 0xffff_ffff));
        }
        assert_eq!(sregs.tr.selector, 0x18);
        assert_eq!(sregs.cr3, 0x9000);
        assert_eq!(sregs.cr0, X86_CR0_PE | X86_CR0_PG);
        assert_eq!(sregs.cr4, X86_CR4_PAE);
        assert_eq!(sregs.efer, EFER_LME | EFER_LMA);
    }

    #[test]
    fn boot_regs_follow_the_64bit_boot_protocol() {
        let regs = boot_regs(GuestAddress(0x100_0000));
        let expected = kvm_regs {
            rflags: 2,
            rip: 0x100_0000,
            rsp: 0x8ff0,
            rbp: 0x8ff0,
            rsi: 0x7000,
            ..Default::default()
        };
        assert_eq!(regs, expected);
    }

    #[test]
    fn boot_fpu_control_words() {
        let fpu = boot_fpu();
        assert_eq!((fpu.fcw, fpu.mxcsr), (0x37f, 0x1f80));
    }

    #[cfg(feature = "kvm-tests")]
    mod kvm {
        use super::*;
        use crate::arch::x86_64::test_utils::vcpu_or_skip;

        #[test]
        fn test_setup_fpu() {
            let Some((_kvm, _vm, vcpu)) = vcpu_or_skip("test_setup_fpu") else {
                return;
            };
            setup_fpu(&vcpu).unwrap();

            let expected_fpu: kvm_fpu = kvm_fpu {
                fcw: 0x37f,
                mxcsr: 0x1f80,
                ..Default::default()
            };
            let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
            assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
            // Setting the mxcsr register from kvm_fpu inside setup_fpu does not influence
            // anything. See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        }

        #[test]
        fn test_setup_regs() {
            let Some((_kvm, _vm, vcpu)) = vcpu_or_skip("test_setup_regs") else {
                return;
            };

            let expected_regs: kvm_regs = kvm_regs {
                rflags: 0x0000_0000_0000_0002u64,
                rip: 1,
                rsp: BOOT_STACK_POINTER,
                rbp: BOOT_STACK_POINTER,
                rsi: ZERO_PAGE_START,
                ..Default::default()
            };

            setup_regs(&vcpu, GuestAddress(expected_regs.rip)).unwrap();

            let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
            assert_eq!(actual_regs, expected_regs);
        }

        #[test]
        fn test_setup_sregs() {
            let Some((_kvm, _vm, vcpu)) = vcpu_or_skip("test_setup_sregs") else {
                return;
            };
            let gm = single_region_mem(0x10000);

            vcpu.set_sregs(&Default::default()).unwrap();
            setup_sregs(&gm, &vcpu).unwrap();

            let mut sregs: kvm_sregs = vcpu.get_sregs().unwrap();
            // for AMD KVM_GET_SREGS returns g = 0 for each kvm_segment.
            // We set it to 1, otherwise the test will fail.
            sregs.gs.g = 1;

            validate_segments_and_sregs(&gm, &sregs);
            validate_page_tables(&gm, &sregs);
        }
    }
}
