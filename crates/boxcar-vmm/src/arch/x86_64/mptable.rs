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
// src/vmm/src/arch/x86_64/mptable.rs at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: the table is written at the fixed
// MPTABLE_START (0x9fc00) instead of an address from Firecracker's resource
// allocator; errors are `arch::Error` and no conversion unwraps; the OEM ID is
// "BOXCAR"; the checksum test reads guest memory with `read_slice`.

//! The Intel MultiProcessor Specification 1.4 table: how the guest finds its
//! CPUs, the IOAPIC, the ISA bus and the legacy interrupt routing without
//! ACPI.

use std::mem;

use libc::c_char;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use super::layout::{APIC_ADDR, GSI_LEGACY_END, IOAPIC_ADDR, MPTABLE_START};
use super::mpspec;
use crate::arch::{write_error, Error, Result};

// These `mpspec` wrapper types are only data, reading them from data is a safe initialization.
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_bus {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_cpu {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_intsrc {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_ioapic {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_table {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_lintsrc {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpf_intel {}

// With APIC/xAPIC, there are only 255 APIC IDs available. And IOAPIC occupies
// one APIC ID, so only 254 CPUs at maximum may be supported. Actually it's
// a large number for FC usecases.
/// The most vCPUs the MP table can describe.
pub const MAX_SUPPORTED_CPUS: u8 = 254;

// Convenience macro for making arrays of diverse character types.
macro_rules! char_array {
    ($t:ty; $( $c:expr ),*) => ( [ $( $c as $t ),* ] )
}

// Most of these variables are sourced from the Intel MP Spec 1.4.
const SMP_MAGIC_IDENT: [c_char; 4] = char_array!(c_char; '_', 'M', 'P', '_');
const MPC_SIGNATURE: [c_char; 4] = char_array!(c_char; 'P', 'C', 'M', 'P');
const MPC_SPEC: i8 = 4;
const MPC_OEM: [c_char; 8] = char_array!(c_char; 'B', 'O', 'X', 'C', 'A', 'R', ' ', ' ');
const MPC_PRODUCT_ID: [c_char; 12] = ['0' as c_char; 12];
const BUS_TYPE_ISA: [u8; 6] = *b"ISA   ";
const IO_APIC_DEFAULT_PHYS_BASE: u32 = IOAPIC_ADDR; // source: linux/arch/x86/include/asm/apicdef.h
const APIC_DEFAULT_PHYS_BASE: u32 = APIC_ADDR; // source: linux/arch/x86/include/asm/apicdef.h
const APIC_VERSION: u8 = 0x14;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;

// The bindings expose the mpspec_def.h constants as u32; the table fields
// are u8 or u16 and every value is below 256.
const MP_PROCESSOR: u8 = mpspec::MP_PROCESSOR as u8;
const MP_BUS: u8 = mpspec::MP_BUS as u8;
const MP_IOAPIC: u8 = mpspec::MP_IOAPIC as u8;
const MP_INTSRC: u8 = mpspec::MP_INTSRC as u8;
const MP_LINTSRC: u8 = mpspec::MP_LINTSRC as u8;
const CPU_ENABLED: u8 = mpspec::CPU_ENABLED as u8;
const CPU_BOOTPROCESSOR: u8 = mpspec::CPU_BOOTPROCESSOR as u8;
const MPC_APIC_USABLE: u8 = mpspec::MPC_APIC_USABLE as u8;
const MP_IRQPOL_DEFAULT: u16 = mpspec::MP_IRQPOL_DEFAULT as u16;
const MP_INT: u8 = mpspec::mp_irq_source_types::mp_INT as u8;
const MP_NMI: u8 = mpspec::mp_irq_source_types::mp_NMI as u8;
const MP_EXTINT: u8 = mpspec::mp_irq_source_types::mp_ExtINT as u8;
// GSI_LEGACY_END is 23: one interrupt source entry per IOAPIC pin 0..=23.
const LAST_IRQ: u8 = GSI_LEGACY_END as u8;

fn compute_checksum<T: ByteValued>(v: &T) -> u8 {
    let mut checksum: u8 = 0;
    for i in v.as_slice() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

fn compute_mp_size(num_cpus: u8) -> usize {
    mem::size_of::<mpspec::mpf_intel>()
        + mem::size_of::<mpspec::mpc_table>()
        + mem::size_of::<mpspec::mpc_cpu>() * (num_cpus as usize)
        + mem::size_of::<mpspec::mpc_ioapic>()
        + mem::size_of::<mpspec::mpc_bus>()
        + mem::size_of::<mpspec::mpc_intsrc>() * (GSI_LEGACY_END as usize + 1)
        + mem::size_of::<mpspec::mpc_lintsrc>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`, at
/// [`MPTABLE_START`].
pub fn setup_mptable(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<()> {
    if num_cpus > MAX_SUPPORTED_CPUS {
        return Err(Error::TooManyCpus(num_cpus));
    }

    let mp_size = compute_mp_size(num_cpus);
    tracing::debug!(
        "mptable: {mp_size} bytes for {num_cpus} vCPUs at address {MPTABLE_START:#010x}"
    );

    // Used to keep track of the next base pointer into the MP table.
    let mut base_mp = GuestAddress(MPTABLE_START);
    let mut mp_num_entries: u16 = 0;

    let mut checksum: u8 = 0;
    let ioapicid: u8 = num_cpus + 1;

    // The checked_add here ensures the all of the following base_mp.unchecked_add's will be without
    // overflow.
    if let Some(end_mp) = base_mp.checked_add((mp_size - 1) as u64) {
        if !mem.address_in_range(end_mp) {
            return Err(Error::NotEnoughMemory("MP table"));
        }
    } else {
        return Err(Error::AddressOverflow("MP table"));
    }

    mem.write_slice(&vec![0; mp_size], base_mp)
        .map_err(write_error("MP table"))?;

    {
        let size = mem::size_of::<mpspec::mpf_intel>() as u64;
        let mut mpf_intel = mpspec::mpf_intel {
            signature: SMP_MAGIC_IDENT,
            physptr: u32::try_from(base_mp.raw_value() + size)
                .map_err(|_| Error::AddressOverflow("MP configuration table"))?,
            length: 1,
            specification: 4,
            ..mpspec::mpf_intel::default()
        };
        mpf_intel.checksum = mpf_intel_compute_checksum(&mpf_intel);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(write_error("MP floating pointer"))?;
        base_mp = base_mp.unchecked_add(size);
        mp_num_entries += 1;
    }

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(mem::size_of::<mpspec::mpc_table>() as u64);

    {
        let size = mem::size_of::<mpspec::mpc_cpu>() as u64;
        for cpu_id in 0..num_cpus {
            let mpc_cpu = mpspec::mpc_cpu {
                type_: MP_PROCESSOR,
                apicid: cpu_id,
                apicver: APIC_VERSION,
                cpuflag: CPU_ENABLED | if cpu_id == 0 { CPU_BOOTPROCESSOR } else { 0 },
                cpufeature: CPU_STEPPING,
                featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
                ..Default::default()
            };
            mem.write_obj(mpc_cpu, base_mp)
                .map_err(write_error("MP CPU entry"))?;
            base_mp = base_mp.unchecked_add(size);
            checksum = checksum.wrapping_add(compute_checksum(&mpc_cpu));
            mp_num_entries += 1;
        }
    }
    {
        let size = mem::size_of::<mpspec::mpc_bus>() as u64;
        let mpc_bus = mpspec::mpc_bus {
            type_: MP_BUS,
            busid: 0,
            bustype: BUS_TYPE_ISA,
        };
        mem.write_obj(mpc_bus, base_mp)
            .map_err(write_error("MP bus entry"))?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus));
        mp_num_entries += 1;
    }
    {
        let size = mem::size_of::<mpspec::mpc_ioapic>() as u64;
        let mpc_ioapic = mpspec::mpc_ioapic {
            type_: MP_IOAPIC,
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: MPC_APIC_USABLE,
            apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
        };
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(write_error("MP IOAPIC entry"))?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic));
        mp_num_entries += 1;
    }
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..=LAST_IRQ {
        let size = mem::size_of::<mpspec::mpc_intsrc>() as u64;
        let mpc_intsrc = mpspec::mpc_intsrc {
            type_: MP_INTSRC,
            irqtype: MP_INT,
            irqflag: MP_IRQPOL_DEFAULT,
            srcbus: 0,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(write_error("MP interrupt source entry"))?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc));
        mp_num_entries += 1;
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: MP_LINTSRC,
            irqtype: MP_EXTINT,
            irqflag: MP_IRQPOL_DEFAULT,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(write_error("MP local interrupt source entry"))?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
        mp_num_entries += 1;
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: MP_LINTSRC,
            irqtype: MP_NMI,
            irqflag: MP_IRQPOL_DEFAULT,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0xFF,
            destapiclint: 1,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(write_error("MP local interrupt source entry"))?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
        mp_num_entries += 1;
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = mpspec::mpc_table {
            signature: MPC_SIGNATURE,
            // it's safe to use unchecked_offset_from because
            // table_end > table_base
            length: u16::try_from(table_end.unchecked_offset_from(table_base))
                .map_err(|_| Error::AddressOverflow("MP configuration table end"))?,
            spec: MPC_SPEC,
            oem: MPC_OEM,
            oemcount: mp_num_entries,
            productid: MPC_PRODUCT_ID,
            lapic: APIC_DEFAULT_PHYS_BASE,
            ..Default::default()
        };
        debug_assert_eq!(
            mpc_table.length as usize + mem::size_of::<mpspec::mpf_intel>(),
            mp_size
        );
        checksum = checksum.wrapping_add(compute_checksum(&mpc_table));
        #[allow(clippy::cast_possible_wrap)]
        let checksum_final = (!checksum).wrapping_add(1) as i8;
        mpc_table.checksum = checksum_final;
        mem.write_obj(mpc_table, table_base)
            .map_err(write_error("MP configuration table"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::layout::SYSTEM_MEM_START;
    use crate::arch::x86_64::test_utils::single_region_mem_at;

    fn table_entry_size(type_: u8) -> usize {
        match u32::from(type_) {
            mpspec::MP_PROCESSOR => mem::size_of::<mpspec::mpc_cpu>(),
            mpspec::MP_BUS => mem::size_of::<mpspec::mpc_bus>(),
            mpspec::MP_IOAPIC => mem::size_of::<mpspec::mpc_ioapic>(),
            mpspec::MP_INTSRC => mem::size_of::<mpspec::mpc_intsrc>(),
            mpspec::MP_LINTSRC => mem::size_of::<mpspec::mpc_lintsrc>(),
            _ => panic!("unrecognized mpc table entry type: {}", type_),
        }
    }

    #[test]
    fn bounds_check() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));

        setup_mptable(&mem, num_cpus).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus) - 1);

        setup_mptable(&mem, num_cpus).unwrap_err();
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();

        assert_eq!(mpf_intel_compute_checksum(&mpf_intel), mpf_intel.checksum);
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();

        let mut buffer = vec![0u8; mpc_table.length as usize];
        mem.read_slice(&mut buffer, mpc_offset).unwrap();
        assert_eq!(
            buffer
                .iter()
                .fold(0u8, |accum, &item| accum.wrapping_add(item)),
            0
        );
    }

    #[test]
    fn mpc_entry_count() {
        let num_cpus = 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();

        let expected_entry_count =
            // Intel floating point
            1
            // CPU
            + u16::from(num_cpus)
            // IOAPIC
            + 1
            // ISA Bus
            + 1
            // IRQ
            + u16::try_from(GSI_LEGACY_END).unwrap() + 1
            // Interrupt source ExtINT
            + 1
            // Interrupt source NMI
            + 1;
        assert_eq!(mpc_table.oemcount, expected_entry_count);
    }

    #[test]
    fn cpu_entry_count() {
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(MAX_SUPPORTED_CPUS));

        for i in 0..MAX_SUPPORTED_CPUS {
            setup_mptable(&mem, i).unwrap();

            let mpf_intel: mpspec::mpf_intel =
                mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
            let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
            let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();
            let mpc_end = mpc_offset.checked_add(u64::from(mpc_table.length)).unwrap();

            let mut entry_offset = mpc_offset
                .checked_add(mem::size_of::<mpspec::mpc_table>() as u64)
                .unwrap();
            let mut cpu_count = 0;
            while entry_offset < mpc_end {
                let entry_type: u8 = mem.read_obj(entry_offset).unwrap();
                entry_offset = entry_offset
                    .checked_add(table_entry_size(entry_type) as u64)
                    .unwrap();
                assert!(entry_offset <= mpc_end);
                if u32::from(entry_type) == mpspec::MP_PROCESSOR {
                    cpu_count += 1;
                }
            }
            assert_eq!(cpu_count, i);
        }
    }

    #[test]
    fn cpu_entry_count_max() {
        let cpus = MAX_SUPPORTED_CPUS + 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(cpus));

        let result = setup_mptable(&mem, cpus).unwrap_err();
        assert!(matches!(result, Error::TooManyCpus(255)));
    }

    /// The floating pointer carries the `_MP_` signature and points at the
    /// `PCMP` configuration table right behind it; the BSP is flagged and the
    /// IOAPIC takes the APIC ID after the last CPU.
    #[test]
    fn signatures_and_boot_processor() {
        let num_cpus = 2;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));
        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
        assert_eq!(mpf_intel.signature, SMP_MAGIC_IDENT);
        assert_eq!(
            u64::from(mpf_intel.physptr),
            SYSTEM_MEM_START + mem::size_of::<mpspec::mpf_intel>() as u64
        );
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();
        assert_eq!(mpc_table.signature, MPC_SIGNATURE);
        assert_eq!(mpc_table.lapic, 0xfee0_0000);

        let cpu_base = mpc_offset.unchecked_add(mem::size_of::<mpspec::mpc_table>() as u64);
        let bsp: mpspec::mpc_cpu = mem.read_obj(cpu_base).unwrap();
        let ap: mpspec::mpc_cpu = mem
            .read_obj(cpu_base.unchecked_add(mem::size_of::<mpspec::mpc_cpu>() as u64))
            .unwrap();
        assert_eq!(
            (bsp.apicid, bsp.cpuflag),
            (0, CPU_ENABLED | CPU_BOOTPROCESSOR)
        );
        assert_eq!((ap.apicid, ap.cpuflag), (1, CPU_ENABLED));

        let ioapic: mpspec::mpc_ioapic = mem
            .read_obj(cpu_base.unchecked_add(
                (mem::size_of::<mpspec::mpc_cpu>() * 2 + mem::size_of::<mpspec::mpc_bus>()) as u64,
            ))
            .unwrap();
        assert_eq!(ioapic.type_, MP_IOAPIC);
        assert_eq!(ioapic.apicid, num_cpus + 1);
        assert_eq!(ioapic.apicaddr, 0xfec0_0000);
    }
}
