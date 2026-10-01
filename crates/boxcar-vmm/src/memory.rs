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
// src/vmm/src/arch/x86_64/mod.rs (arch_memory_regions, initrd_load_addr and
// the regions tests) at commit 21f19ed8109578108568c8a8f3623ddb6f097878. The
// BSD-3-Clause text referred to above is in LICENSE-BSD-3-Clause. Adapted:
// only the 32-bit MMIO hole [3 GiB, 4 GiB) is carved out (no 64-bit MMIO
// region); the initrd address is capped at 3 GiB and checked against the end
// of the kernel; errors are `arch::Error`.

//! Guest RAM: one region below the 32-bit MMIO hole at 3 GiB, and a second
//! from 4 GiB for whatever does not fit below it.

use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::arch::x86_64::layout::{FIRST_ADDR_PAST_32BITS, GUEST_PAGE_SIZE, MMIO32_MEM_START};
use crate::arch::{Error, Result};

/// The guest RAM regions for `size` bytes: `[0, min(size, 3 GiB))`, then
/// `[4 GiB, 4 GiB + (size - 3 GiB))` when `size` exceeds 3 GiB. Empty for a
/// zero size.
pub fn arch_memory_regions(size: u64) -> Vec<(GuestAddress, usize)> {
    if size == 0 {
        return Vec::new();
    }
    let low = size.min(MMIO32_MEM_START);
    let mut regions = vec![(GuestAddress(0), low as usize)];
    if size > MMIO32_MEM_START {
        regions.push((
            GuestAddress(FIRST_ADDR_PAST_32BITS),
            (size - MMIO32_MEM_START) as usize,
        ));
    }
    regions
}

/// Anonymous guest memory of `size` bytes laid out by
/// [`arch_memory_regions`].
pub fn create_guest_memory(size: u64) -> Result<GuestMemoryMmap> {
    if size == 0 {
        return Err(Error::ZeroMemorySize);
    }
    GuestMemoryMmap::from_ranges(&arch_memory_regions(size)).map_err(Error::GuestMemory)
}

/// Returns the memory address where the initrd could be loaded: as high as
/// possible below `min(end of RAM, 3 GiB)`, page aligned. Fails when the
/// initrd does not fit, or when that address is below `kernel_end` (one past
/// the kernel's last loaded byte, `KernelLoaderResult::kernel_end`).
pub fn initrd_load_addr(
    mem: &GuestMemoryMmap,
    initrd_size: usize,
    kernel_end: GuestAddress,
) -> Result<GuestAddress> {
    let mem_end = mem.last_addr().raw_value().saturating_add(1);
    let limit = mem_end.min(MMIO32_MEM_START);
    let start = limit
        .checked_sub(initrd_size as u64)
        .ok_or(Error::InitrdTooLarge {
            size: initrd_size,
            limit,
        })?;
    let addr = start & !(GUEST_PAGE_SIZE - 1);
    if addr < kernel_end.raw_value() {
        return Err(Error::InitrdOverlapsKernel {
            addr,
            kernel_end: kernel_end.raw_value(),
        });
    }
    Ok(GuestAddress(addr))
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestMemoryRegion;

    use super::*;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    /// A kernel loaded at 1 MiB that ends at 16 MiB.
    const KERNEL_END: GuestAddress = GuestAddress(16 * MIB);

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1u64 << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        const MEMORY_SIZE: u64 = (1 << 32) + 0x8000;

        let regions = arch_memory_regions(MEMORY_SIZE);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1u64 << 32), regions[1].0);

        assert_eq!(
            regions[1],
            (
                GuestAddress(FIRST_ADDR_PAST_32BITS),
                MEMORY_SIZE as usize - regions[0].1
            )
        )
    }

    #[test]
    fn regions_at_the_hole() {
        assert_eq!(
            arch_memory_regions(3 * GIB),
            vec![(GuestAddress(0), 0xC000_0000)]
        );
        assert_eq!(
            arch_memory_regions(5 * GIB),
            vec![
                (GuestAddress(0), 0xC000_0000),
                (GuestAddress(0x1_0000_0000), 0x8000_0000),
            ]
        );
        assert!(arch_memory_regions(0).is_empty());
    }

    #[test]
    fn create_guest_memory_regions() {
        let mem = create_guest_memory(512 * MIB).unwrap();
        assert_eq!(mem.num_regions(), 1);
        assert_eq!(mem.last_addr(), GuestAddress(512 * MIB - 1));

        let mem = create_guest_memory(5 * GIB).unwrap();
        let regions: Vec<(u64, u64)> = mem
            .iter()
            .map(|r| (r.start_addr().raw_value(), r.len()))
            .collect();
        assert_eq!(regions, vec![(0, 3 * GIB), (4 * GIB, 2 * GIB)]);

        assert!(matches!(create_guest_memory(0), Err(Error::ZeroMemorySize)));
    }

    #[test]
    fn initrd_512mib_guest_2mib_initrd() {
        let mem = create_guest_memory(512 * MIB).unwrap();
        let addr = initrd_load_addr(&mem, 2 * MIB as usize, KERNEL_END).unwrap();
        assert_eq!(addr, GuestAddress(0x1fe0_0000));
    }

    #[test]
    fn initrd_is_page_aligned_and_ends_by_the_top() {
        let mem = create_guest_memory(512 * MIB).unwrap();
        let addr = initrd_load_addr(&mem, 0x1234, KERNEL_END).unwrap();
        assert_eq!(addr, GuestAddress(512 * MIB - 0x2000));
        assert_eq!(addr.raw_value() % 4096, 0);
    }

    #[test]
    fn initrd_stays_below_3gib() {
        let mem = create_guest_memory(5 * GIB).unwrap();
        let addr = initrd_load_addr(&mem, 2 * MIB as usize, KERNEL_END).unwrap();
        assert_eq!(addr, GuestAddress(3 * GIB - 2 * MIB));
    }

    #[test]
    fn initrd_too_large_or_over_the_kernel() {
        let mem = create_guest_memory(512 * MIB).unwrap();
        assert!(matches!(
            initrd_load_addr(&mem, 512 * MIB as usize + 1, KERNEL_END),
            Err(Error::InitrdTooLarge { .. })
        ));
        // 500 MiB from the top of 512 MiB starts at 12 MiB, inside the kernel.
        assert!(matches!(
            initrd_load_addr(&mem, 500 * MIB as usize, KERNEL_END),
            Err(Error::InitrdOverlapsKernel {
                addr: 0xc0_0000,
                kernel_end: 0x100_0000
            })
        ));
        // Right up to the kernel's end is fine.
        let addr = initrd_load_addr(&mem, 496 * MIB as usize, KERNEL_END).unwrap();
        assert_eq!(addr, KERNEL_END);
    }
}
