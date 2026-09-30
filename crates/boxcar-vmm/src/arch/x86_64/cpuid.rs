// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Derived from Cloud Hypervisor (https://github.com/cloud-hypervisor/cloud-hypervisor),
// arch/src/x86_64/mod.rs (configure_vcpu and update_cpuid_topology) at commit
// 853c440425ebe23bcf5fb43d9058bd1d8a0abe2a. Adapted: one flat topology (one
// thread per core, `num_cpus` cores, one die, one package) patched in place on
// `kvm_bindings::CpuId` entries KVM already reports; no entries are added.

//! Per-vCPU CPUID: KVM's supported CPUID with the APIC ID, the topology and
//! the hypervisor bit filled in for this vCPU.

use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{Kvm, VcpuFd};

use crate::arch::{kvm_error, Result};

/// Basic feature information.
const LEAF_FEATURES: u32 = 0x1;
/// Thermal and power management.
const LEAF_THERMAL_POWER: u32 = 0x6;
/// Architectural performance monitoring.
const LEAF_ARCH_PERFMON: u32 = 0xa;
/// Extended topology enumeration.
const LEAF_EXT_TOPOLOGY: u32 = 0xb;
/// V2 extended topology enumeration.
const LEAF_EXT_TOPOLOGY_V2: u32 = 0x1f;
/// AMD: address sizes and core count.
const LEAF_AMD_SIZES: u32 = 0x8000_0008;
/// AMD: extended APIC ID.
const LEAF_AMD_EXT_APIC_ID: u32 = 0x8000_001e;

/// Leaf 1 ECX bit 31: running under a hypervisor.
const LEAF1_ECX_HYPERVISOR: u32 = 1 << 31;
/// Leaf 1 EDX bit 28: HTT, EBX[23:16] is valid.
const LEAF1_EDX_HTT: u32 = 1 << 28;
/// Leaf 1 EBX[15:8]: CLFLUSH line size in 8-byte units (64 bytes).
const CLFLUSH_LINE_SIZE: u32 = 8;
/// Leaf 6 ECX bit 3: energy performance bias.
const LEAF6_ECX_EPB: u32 = 1 << 3;

/// Leaf 0xB/0x1F ECX[15:8] level types.
const LEVEL_TYPE_INVALID: u32 = 0;
const LEVEL_TYPE_THREAD: u32 = 1;
const LEVEL_TYPE_CORE: u32 = 2;

/// Patches KVM's supported CPUID for vCPU `vcpu_id` of `num_cpus`:
///
/// - leaf 0x1: EBX `[31:24]` = `vcpu_id` (initial APIC ID), `[23:16]` =
///   `num_cpus`, `[15:8]` = 8 (CLFLUSH 64 bytes); ECX bit 31 (hypervisor) set;
///   EDX bit 28 (HTT) set when `num_cpus > 1`, cleared otherwise.
/// - leaf 0x6: ECX bit 3 (EPB) cleared.
/// - leaf 0xA: all registers zeroed (no architectural PMU).
/// - leaves 0xB and 0x1F: EDX = `vcpu_id` (x2APIC ID) on every subleaf;
///   subleaf 0 is the thread level (type 1, EBX = 1, EAX shift 0), subleaf 1
///   the core level (type 2, EBX = `num_cpus`, EAX = bits needed for
///   `num_cpus` IDs); any further subleaf is marked invalid (type 0,
///   EAX = EBX = 0) so the enumeration ends at the core level. ECX[7:0] is the
///   subleaf number.
/// - AMD leaf 0x8000_0008: ECX `[7:0]` = `num_cpus - 1`.
/// - AMD leaf 0x8000_001E: EAX = `vcpu_id` (extended APIC ID).
///
/// The KVM leaves `0x4000_0000..=0x4000_00FF` and everything else are left
/// as KVM reported them.
pub fn patch_cpuid(cpuid: &mut CpuId, vcpu_id: u8, num_cpus: u8) {
    let apic_id = u32::from(vcpu_id);
    let cpus = u32::from(num_cpus);
    // Bits of the x2APIC ID that select the core within the package.
    let core_shift = u32::BITS - cpus.saturating_sub(1).leading_zeros();

    for entry in cpuid.as_mut_slice() {
        match entry.function {
            LEAF_FEATURES => {
                entry.ebx =
                    (entry.ebx & 0xff) | (apic_id << 24) | (cpus << 16) | (CLFLUSH_LINE_SIZE << 8);
                entry.ecx |= LEAF1_ECX_HYPERVISOR;
                if num_cpus > 1 {
                    entry.edx |= LEAF1_EDX_HTT;
                } else {
                    entry.edx &= !LEAF1_EDX_HTT;
                }
            }
            LEAF_THERMAL_POWER => entry.ecx &= !LEAF6_ECX_EPB,
            LEAF_ARCH_PERFMON => {
                entry.eax = 0;
                entry.ebx = 0;
                entry.ecx = 0;
                entry.edx = 0;
            }
            LEAF_EXT_TOPOLOGY | LEAF_EXT_TOPOLOGY_V2 => {
                let (shift, count, level_type) = match entry.index {
                    0 => (0, 1, LEVEL_TYPE_THREAD),
                    1 => (core_shift, cpus, LEVEL_TYPE_CORE),
                    _ => (0, 0, LEVEL_TYPE_INVALID),
                };
                entry.eax = shift;
                entry.ebx = count;
                entry.ecx = (level_type << 8) | (entry.index & 0xff);
                entry.edx = apic_id;
            }
            LEAF_AMD_SIZES => entry.ecx = (entry.ecx & !0xff) | (cpus.saturating_sub(1) & 0xff),
            LEAF_AMD_EXT_APIC_ID => entry.eax = apic_id,
            _ => {}
        }
    }
}

/// Sets the CPUID of `vcpu` to KVM's supported CPUID patched by
/// [`patch_cpuid`] for vCPU `vcpu_id` of `num_cpus`.
pub fn setup_cpuid(kvm: &Kvm, vcpu: &VcpuFd, vcpu_id: u8, num_cpus: u8) -> Result<()> {
    let mut cpuid = kvm
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .map_err(kvm_error("get_supported_cpuid"))?;
    patch_cpuid(&mut cpuid, vcpu_id, num_cpus);
    vcpu.set_cpuid2(&cpuid).map_err(kvm_error("set_cpuid2"))
}

#[cfg(test)]
mod tests {
    use kvm_bindings::{kvm_cpuid_entry2, KVM_CPUID_FLAG_SIGNIFCANT_INDEX};

    use super::*;

    const ALL: u32 = 0xffff_ffff;

    fn entry(function: u32, index: u32, regs: [u32; 4]) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 {
            function,
            index,
            flags: if matches!(function, 0xb | 0x1f) {
                KVM_CPUID_FLAG_SIGNIFCANT_INDEX
            } else {
                0
            },
            eax: regs[0],
            ebx: regs[1],
            ecx: regs[2],
            edx: regs[3],
            ..Default::default()
        }
    }

    /// A host-like CPUID: every register the patch must not touch is
    /// all-ones, so a stray write shows up.
    fn synthetic_cpuid() -> CpuId {
        CpuId::from_entries(&[
            entry(0x0, 0, [0x1f, 0x756e_6547, 0x6c65_746e, 0x4965_6e69]),
            entry(0x1, 0, [0x000a_0655, 0x5a3f_08ab, 0x7ffa_3203, 0x0f8b_fbff]),
            entry(0x6, 0, [0x4, 0, 0xf, 0]),
            entry(0xa, 0, [ALL, ALL, ALL, ALL]),
            entry(0xb, 0, [1, 2, 0x100, 0x33]),
            entry(0xb, 1, [6, 24, 0x201, 0x33]),
            entry(0xb, 2, [0, 0, 2, 0x33]),
            entry(0x1f, 0, [1, 2, 0x100, 0x33]),
            entry(0x1f, 1, [6, 24, 0x201, 0x33]),
            entry(0x1f, 2, [7, 48, 0x502, 0x33]),
            entry(
                0x4000_0000,
                0,
                [0x4000_0001, 0x4b4d_564b, 0x564b_4d56, 0x4d],
            ),
            entry(0x4000_0001, 0, [ALL, ALL, ALL, ALL]),
            entry(0x8000_0008, 0, [0x3030, ALL, 0x0000_70ff, 0]),
            entry(0x8000_001e, 0, [ALL, ALL, ALL, ALL]),
        ])
        .unwrap()
    }

    fn regs(cpuid: &CpuId, function: u32, index: u32) -> [u32; 4] {
        let e = cpuid
            .as_slice()
            .iter()
            .find(|e| e.function == function && e.index == index)
            .unwrap();
        [e.eax, e.ebx, e.ecx, e.edx]
    }

    #[test]
    fn patch_cpuid_four_vcpus() {
        let original = synthetic_cpuid();
        let mut cpuid = synthetic_cpuid();
        patch_cpuid(&mut cpuid, 3, 4);

        // Leaf 1: EBX = apic id 3, 4 logical CPUs, CLFLUSH 8, brand index kept;
        // ECX gains the hypervisor bit; EDX gains HTT.
        let [eax, ebx, ecx, edx] = regs(&cpuid, 0x1, 0);
        assert_eq!(eax, 0x000a_0655);
        assert_eq!(ebx, 0x0304_08ab);
        assert_eq!(ebx >> 24, 3);
        assert_eq!((ebx >> 16) & 0xff, 4);
        assert_eq!((ebx >> 8) & 0xff, 8);
        assert_eq!(ecx, 0x7ffa_3203 | (1 << 31));
        assert_eq!(edx, 0x0f8b_fbff | (1 << 28));

        // Leaf 6: ECX bit 3 cleared, the rest kept.
        assert_eq!(regs(&cpuid, 0x6, 0), [0x4, 0, 0x7, 0]);
        // Leaf 0xA: zeroed.
        assert_eq!(regs(&cpuid, 0xa, 0), [0, 0, 0, 0]);

        // Leaves 0xB and 0x1F: thread level, core level, then invalid; EDX is
        // the x2APIC ID everywhere.
        for leaf in [0xb, 0x1f] {
            assert_eq!(regs(&cpuid, leaf, 0), [0, 1, (1 << 8), 3], "leaf {leaf:#x}");
            assert_eq!(
                regs(&cpuid, leaf, 1),
                [2, 4, (2 << 8) | 1, 3],
                "leaf {leaf:#x}"
            );
            assert_eq!(regs(&cpuid, leaf, 2), [0, 0, 2, 3], "leaf {leaf:#x}");
        }

        // AMD: NC = 3, ApicIdSize kept; extended APIC ID = 3, rest kept.
        assert_eq!(regs(&cpuid, 0x8000_0008, 0), [0x3030, ALL, 0x0000_7003, 0]);
        assert_eq!(regs(&cpuid, 0x8000_001e, 0), [3, ALL, ALL, ALL]);

        // Untouched: leaf 0 and the KVM leaves.
        for (function, index) in [(0x0, 0), (0x4000_0000, 0), (0x4000_0001, 0)] {
            assert_eq!(
                regs(&cpuid, function, index),
                regs(&original, function, index),
                "leaf {function:#x}"
            );
        }
        assert_eq!(cpuid.as_slice().len(), original.as_slice().len());
    }

    #[test]
    fn patch_cpuid_single_vcpu_clears_htt() {
        let mut cpuid = synthetic_cpuid();
        patch_cpuid(&mut cpuid, 0, 1);

        let [_, ebx, ecx, edx] = regs(&cpuid, 0x1, 0);
        assert_eq!(ebx, 0x0001_08ab);
        assert_ne!(ecx & (1 << 31), 0);
        assert_eq!(edx & (1 << 28), 0);
        assert_eq!(edx, 0x0f8b_fbff & !(1 << 28));

        for leaf in [0xb, 0x1f] {
            assert_eq!(regs(&cpuid, leaf, 0), [0, 1, 1 << 8, 0]);
            assert_eq!(regs(&cpuid, leaf, 1), [0, 1, (2 << 8) | 1, 0]);
        }
        assert_eq!(regs(&cpuid, 0x8000_0008, 0)[2], 0x0000_7000);
        assert_eq!(regs(&cpuid, 0x8000_001e, 0)[0], 0);
    }

    /// The core-level shift is the number of bits needed for `num_cpus` IDs.
    #[test]
    fn patch_cpuid_core_shift() {
        for (num_cpus, shift) in [(1, 0), (2, 1), (3, 2), (4, 2), (5, 3), (8, 3), (9, 4)] {
            let mut cpuid = synthetic_cpuid();
            patch_cpuid(&mut cpuid, 0, num_cpus);
            assert_eq!(regs(&cpuid, 0xb, 1)[0], shift, "{num_cpus} vCPUs");
            assert_eq!(regs(&cpuid, 0xb, 1)[1], u32::from(num_cpus));
        }
    }

    #[cfg(feature = "kvm-tests")]
    mod kvm {
        use super::*;
        use crate::arch::x86_64::test_utils::vcpu_or_skip;

        #[test]
        fn setup_cpuid_sets_the_apic_id() {
            let Some((kvm, _vm, vcpu)) = vcpu_or_skip("setup_cpuid_sets_the_apic_id") else {
                return;
            };
            setup_cpuid(&kvm, &vcpu, 0, 2).unwrap();

            let cpuid = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
            let [_, ebx, ecx, edx] = regs(&cpuid, 0x1, 0);
            assert_eq!(ebx >> 24, 0);
            assert_eq!((ebx >> 16) & 0xff, 2);
            assert_ne!(ecx & (1 << 31), 0);
            assert_ne!(edx & (1 << 28), 0);
        }
    }
}
