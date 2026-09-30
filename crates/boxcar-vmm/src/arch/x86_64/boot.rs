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
// src/vmm/src/arch/x86_64/mod.rs (configure_system_for_boot,
// configure_64bit_boot, add_e820_entry and their tests) at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: Linux 64-bit boot of an ELF
// vmlinux only (no PVH, no bzImage setup header, no ACPI RSDP); the e820 map
// is boxcar's (RAM below the EBDA, the EBDA to 1 MiB reserved, RAM from 1 MiB
// in each region, no PCI MMCONFIG hole); the command line is written by the
// caller; vCPU configuration lives in regs, msr, cpuid and interrupts.

//! The zero page (`boot_params` with its e820 map) and the MP table: what
//! the kernel reads about the machine before it runs its first instruction.

use std::cmp::max;

use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::bootparam::boot_params;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use super::layout::{HIMEM_START, SYSTEM_MEM_START, ZERO_PAGE_START};
use super::mptable;
use crate::arch::{Error, Result};

// Value taken from https://elixir.bootlin.com/linux/v5.10.68/source/arch/x86/include/uapi/asm/e820.h#L31
/// Usable normal RAM
pub const E820_RAM: u32 = 1;

/// Reserved area that should be avoided during memory allocations
pub const E820_RESERVED: u32 = 2;

const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
const KERNEL_LOADER_OTHER: u8 = 0xff;
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.

/// Where the initrd was loaded in guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitrdConfig {
    /// Guest physical address of the first byte.
    pub address: GuestAddress,
    /// Size in bytes.
    pub size: usize,
}

/// Configures the system for booting Linux: writes the MP table for
/// `num_cpus` at `0x9fc00`, then `boot_params` at the zero page (`0x7000`)
/// with the command line pointer and size, the initrd, and the e820 map.
///
/// `cmdline_size` is the length of the command line written at
/// `cmdline_addr` including its NUL terminator, i.e.
/// `cmdline.as_cstring()?.as_bytes_with_nul().len()`.
pub fn configure_system(
    mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: Option<InitrdConfig>,
    num_cpus: u8,
) -> Result<()> {
    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(mem, num_cpus)?;

    let himem_start = GuestAddress(HIMEM_START);

    let mut params = boot_params::default();
    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    params.hdr.cmd_line_ptr = to_u32("cmd_line_ptr", cmdline_addr.raw_value())?;
    params.hdr.cmdline_size = to_u32("cmdline_size", cmdline_size as u64)?;
    if let Some(initrd_config) = initrd {
        params.hdr.ramdisk_image = to_u32("ramdisk_image", initrd_config.address.raw_value())?;
        params.hdr.ramdisk_size = to_u32("ramdisk_size", initrd_config.size as u64)?;
    }

    // We mark first [0x0, SYSTEM_MEM_START) region as usable RAM and the subsequent
    // [SYSTEM_MEM_START, HIMEM_START) as reserved.
    add_e820_entry(&mut params, 0, SYSTEM_MEM_START, E820_RAM)?;
    add_e820_entry(
        &mut params,
        SYSTEM_MEM_START,
        HIMEM_START - SYSTEM_MEM_START,
        E820_RESERVED,
    )?;

    for region in mem.iter() {
        // the first 1MB is reserved for the kernel
        if region.last_addr() < himem_start {
            continue;
        }
        let addr = max(himem_start, region.start_addr());
        add_e820_entry(
            &mut params,
            addr.raw_value(),
            region.last_addr().unchecked_offset_from(addr) + 1,
            E820_RAM,
        )?;
    }

    LinuxBootConfigurator::write_bootparams(
        &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
        mem,
    )
    .map_err(Error::ZeroPage)
}

fn to_u32(field: &'static str, value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::BootParamOverflow { field, value })
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) -> Result<()> {
    if params.e820_entries as usize >= params.e820_table.len() {
        return Err(Error::E820TableFull);
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use linux_loader::loader::bootparam::boot_e820_entry;
    use vm_memory::Bytes;

    use super::*;
    use crate::arch::x86_64::layout::{CMDLINE_START, MPTABLE_START};
    use crate::arch::x86_64::test_utils::{arch_mem, single_region_mem};

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    fn read_boot_params(mem: &GuestMemoryMmap) -> boot_params {
        mem.read_obj(GuestAddress(ZERO_PAGE_START)).unwrap()
    }

    /// An e820 map as `(addr, size, type)` entries.
    type E820Map = Vec<(u64, u64, u32)>;

    /// The e820 map, copied out of the packed struct.
    fn e820(params: &boot_params) -> E820Map {
        let entries = params.e820_table;
        entries[..params.e820_entries as usize]
            .iter()
            .map(|e| ({ e.addr }, { e.size }, { e.type_ }))
            .collect()
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = single_region_mem(0x10000);
        let err = mptable::setup_mptable(&gm, 1);
        assert!(matches!(
            err.unwrap_err(),
            Error::NotEnoughMemory("MP table")
        ));

        // Now assigning some memory that falls before the 32bit memory hole.
        let gm = arch_mem(512 * MIB);
        configure_system(&gm, GuestAddress(0), 0, None, no_vcpus).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let gm = arch_mem(3 * GIB);
        configure_system(&gm, GuestAddress(0), 0, None, no_vcpus).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let gm = arch_mem(5 * GIB);
        configure_system(&gm, GuestAddress(0), 0, None, no_vcpus).unwrap();
    }

    /// The e820 map for 512 MiB, 3 GiB and 5 GiB guests, exactly as the
    /// global constraints state it.
    #[test]
    fn e820_layout() {
        let low = [
            (0, 0x9fc00, E820_RAM),
            (0x9fc00, 0x100000 - 0x9fc00, E820_RESERVED),
        ];
        let cases: [(u64, E820Map); 3] = [
            (
                512 * MIB,
                vec![low[0], low[1], (0x100000, 512 * MIB - 0x100000, E820_RAM)],
            ),
            (
                3 * GIB,
                vec![low[0], low[1], (0x100000, 3 * GIB - 0x100000, E820_RAM)],
            ),
            (
                5 * GIB,
                vec![
                    low[0],
                    low[1],
                    (0x100000, 3 * GIB - 0x100000, E820_RAM),
                    (4 * GIB, 2 * GIB, E820_RAM),
                ],
            ),
        ];
        for (size, expected) in cases {
            let gm = arch_mem(size);
            configure_system(&gm, GuestAddress(CMDLINE_START), 1, None, 1).unwrap();
            assert_eq!(e820(&read_boot_params(&gm)), expected, "{size:#x} bytes");
        }
    }

    /// The setup header fields the brief lists, with an initrd.
    #[test]
    fn boot_params_header() {
        let gm = arch_mem(512 * MIB);
        let initrd = InitrdConfig {
            address: GuestAddress(0x1fe0_0000),
            size: 0x20_0000,
        };
        configure_system(&gm, GuestAddress(CMDLINE_START), 57, Some(initrd), 2).unwrap();

        let params = read_boot_params(&gm);
        let hdr = params.hdr;
        assert_eq!({ hdr.type_of_loader }, 0xff);
        assert_eq!({ hdr.boot_flag }, 0xaa55);
        assert_eq!({ hdr.header }, 0x5372_6448);
        assert_eq!({ hdr.kernel_alignment }, 0x0100_0000);
        assert_eq!({ hdr.cmd_line_ptr }, 0x20000);
        assert_eq!({ hdr.cmdline_size }, 57);
        assert_eq!({ hdr.ramdisk_image }, 0x1fe0_0000);
        assert_eq!({ hdr.ramdisk_size }, 0x20_0000);
        assert_eq!({ params.acpi_rsdp_addr }, 0);

        // The MP table went to 0x9fc00.
        let signature: [u8; 4] = gm.read_obj(GuestAddress(MPTABLE_START)).unwrap();
        assert_eq!(&signature, b"_MP_");
    }

    #[test]
    fn boot_params_without_initrd() {
        let gm = arch_mem(512 * MIB);
        configure_system(&gm, GuestAddress(CMDLINE_START), 10, None, 1).unwrap();
        let hdr = read_boot_params(&gm).hdr;
        assert_eq!(({ hdr.ramdisk_image }, { hdr.ramdisk_size }), (0, 0));
    }

    #[test]
    fn boot_params_fields_must_fit_in_32_bits() {
        let gm = arch_mem(512 * MIB);
        let err = configure_system(&gm, GuestAddress(1 << 32), 10, None, 1).unwrap_err();
        assert!(matches!(
            err,
            Error::BootParamOverflow {
                field: "cmd_line_ptr",
                value: 0x1_0000_0000
            }
        ));
    }

    #[test]
    fn too_many_cpus() {
        let gm = arch_mem(512 * MIB);
        let err = configure_system(&gm, GuestAddress(CMDLINE_START), 10, None, 255).unwrap_err();
        assert!(matches!(err, Error::TooManyCpus(255)));
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(boot_e820_entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_table: e820_map,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_table[0]),
            format!("{:?}", expected_params.e820_table[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = u8::try_from(params.e820_table.len()).unwrap() + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_
        )
        .is_err());
    }
}
