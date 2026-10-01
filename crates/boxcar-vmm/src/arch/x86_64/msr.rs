// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from Firecracker (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/arch/x86_64/msr.rs (create_boot_msr_entries, set_msrs and their
// tests) and the MSR indexes from src/vmm/src/arch/x86_64/generated/msr_index.rs,
// at commit 21f19ed8109578108568c8a8f3623ddb6f097878. Adapted: only the boot
// MSR list is kept (no snapshot MSR ranges, CPU templates or Hyper-V MSRs);
// errors are `arch::Error`; the tests that need a vCPU run behind `kvm-tests`.

//! Model Specific Registers (MSRs) a vCPU is given before it boots Linux.

use kvm_bindings::{kvm_msr_entry, Msrs};
use kvm_ioctls::VcpuFd;

use crate::arch::{kvm_error, Error, Result};

/// `IA32_TIME_STAMP_COUNTER`.
pub const MSR_IA32_TSC: u32 = 0x10;
/// `IA32_SYSENTER_CS`.
pub const MSR_IA32_SYSENTER_CS: u32 = 0x174;
/// `IA32_SYSENTER_ESP`.
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
/// `IA32_SYSENTER_EIP`.
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
/// `IA32_MISC_ENABLE`.
pub const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;
/// `IA32_MISC_ENABLE` bit 0: fast-string operations enabled.
pub const MSR_IA32_MISC_ENABLE_FAST_STRING: u32 = 0x1;
/// `IA32_MTRR_DEF_TYPE`.
#[allow(non_upper_case_globals)]
pub const MSR_MTRRdefType: u32 = 0x2ff;
/// `IA32_STAR`: SYSCALL target segments.
pub const MSR_STAR: u32 = 0xc000_0081;
/// `IA32_LSTAR`: 64-bit SYSCALL target.
pub const MSR_LSTAR: u32 = 0xc000_0082;
/// `IA32_CSTAR`: compatibility-mode SYSCALL target.
pub const MSR_CSTAR: u32 = 0xc000_0083;
/// `IA32_FMASK`: SYSCALL flag mask.
pub const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
/// `IA32_KERNEL_GS_BASE`.
pub const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// The MSRs set on every vCPU before boot, in the order Firecracker sets them.
pub fn create_boot_msr_entries() -> Vec<kvm_msr_entry> {
    let msr_entry_default = |msr| kvm_msr_entry {
        index: msr,
        data: 0x0,
        ..Default::default()
    };

    vec![
        msr_entry_default(MSR_IA32_SYSENTER_CS),
        msr_entry_default(MSR_IA32_SYSENTER_ESP),
        msr_entry_default(MSR_IA32_SYSENTER_EIP),
        // x86_64 specific msrs, we only run on x86_64 not x86.
        msr_entry_default(MSR_STAR),
        msr_entry_default(MSR_CSTAR),
        msr_entry_default(MSR_KERNEL_GS_BASE),
        msr_entry_default(MSR_SYSCALL_MASK),
        msr_entry_default(MSR_LSTAR),
        // end of x86_64 specific code
        msr_entry_default(MSR_IA32_TSC),
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
            ..Default::default()
        },
        // set default memory type for physical memory outside configured
        // memory ranges to write-back by setting MTRR enable bit (11) and
        // setting memory type to write-back (value 6).
        // https://wiki.osdev.org/MTRR
        kvm_msr_entry {
            index: MSR_MTRRdefType,
            data: (1 << 11) | 0x6,
            ..Default::default()
        },
    ]
}

/// Sets `msr_entries` on `vcpu`, failing unless KVM accepts every one.
///
/// # Errors
///
/// When:
/// - Failed to create [`vmm_sys_util::fam::FamStructWrapper`] for MSRs.
/// - [`kvm_ioctls::VcpuFd::set_msrs`] errors.
/// - [`kvm_ioctls::VcpuFd::set_msrs`] fails to write all given MSRs entries.
pub fn set_msrs(vcpu: &VcpuFd, msr_entries: &[kvm_msr_entry]) -> Result<()> {
    let msrs = Msrs::from_entries(msr_entries).map_err(Error::Msrs)?;
    let expected = msrs.as_fam_struct_ref().nmsrs as usize;
    let written = vcpu.set_msrs(&msrs).map_err(kvm_error("set_msrs"))?;
    if written == expected {
        Ok(())
    } else {
        Err(Error::SetMsrsIncomplete { written, expected })
    }
}

/// Configure Model Specific Registers (MSRs) required to boot Linux for a
/// given x86_64 vCPU: [`create_boot_msr_entries`].
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<()> {
    set_msrs(vcpu, &create_boot_msr_entries())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boot MSR list exactly as the brief states it.
    #[test]
    fn boot_msr_entries_are_the_linux_boot_set() {
        let entries: Vec<(u32, u64)> = create_boot_msr_entries()
            .iter()
            .map(|entry| (entry.index, entry.data))
            .collect();
        assert_eq!(
            entries,
            vec![
                (0x174, 0),
                (0x175, 0),
                (0x176, 0),
                (0xc000_0081, 0),
                (0xc000_0083, 0),
                (0xc000_0102, 0),
                (0xc000_0084, 0),
                (0xc000_0082, 0),
                (0x10, 0),
                (0x1a0, 1),
                (0x2ff, (1 << 11) | 6),
            ]
        );
    }

    #[cfg(feature = "kvm-tests")]
    mod kvm {
        use super::*;
        use crate::arch::x86_64::test_utils::vcpu_or_skip;

        #[test]
        fn test_setup_msrs() {
            let Some((_kvm, _vm, vcpu)) = vcpu_or_skip("test_setup_msrs") else {
                return;
            };
            setup_msrs(&vcpu).unwrap();

            // This test will check against the last MSR entry configured (the tenth one).
            // See create_msr_entries() for details.
            let test_kvm_msrs_entry = [kvm_msr_entry {
                index: MSR_IA32_MISC_ENABLE,
                ..Default::default()
            }];
            let mut kvm_msrs_wrapper = Msrs::from_entries(&test_kvm_msrs_entry).unwrap();

            // Get_msrs() returns the number of msrs that it succeed in reading.
            // We only want to read one in this test case scenario.
            let read_nmsrs = vcpu.get_msrs(&mut kvm_msrs_wrapper).unwrap();
            // Validate it only read one.
            assert_eq!(read_nmsrs, 1);

            // Official entries that were setup when we did setup_msrs. We need to assert that the
            // tenth one (i.e the one with index MSR_IA32_MISC_ENABLE has the data we
            // expect.
            let entry_vec = create_boot_msr_entries();
            assert_eq!(entry_vec[9], kvm_msrs_wrapper.as_slice()[0]);
        }

        #[test]
        fn test_set_valid_msrs() {
            // Test `set_msrs()` with a valid MSR entry. It should succeed, as IA32_TSC MSR is
            // listed in supported MSRs as of now.
            let Some((_kvm, _vm, vcpu)) = vcpu_or_skip("test_set_valid_msrs") else {
                return;
            };
            let msr_entries = vec![kvm_msr_entry {
                index: MSR_IA32_TSC,
                data: 0,
                ..Default::default()
            }];
            set_msrs(&vcpu, &msr_entries).unwrap();
        }

        #[test]
        fn test_set_invalid_msrs() {
            // Test `set_msrs()` with an invalid MSR entry. It should fail, as MSR index 2 is not
            // listed in supported MSRs as of now. If hardware vendor adds this MSR index and KVM
            // supports this MSR, we need to change the index as needed.
            let Some((_kvm, _vm, vcpu)) = vcpu_or_skip("test_set_invalid_msrs") else {
                return;
            };
            let msr_entries = vec![kvm_msr_entry {
                index: 2,
                ..Default::default()
            }];
            assert!(matches!(
                set_msrs(&vcpu, &msr_entries).unwrap_err(),
                Error::SetMsrsIncomplete {
                    written: 0,
                    expected: 1
                }
            ));
        }
    }
}
