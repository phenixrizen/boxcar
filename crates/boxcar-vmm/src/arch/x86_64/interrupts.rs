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
// src/vmm/src/arch/x86_64/interrupts.rs at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: the register accessors return
// `arch::Error::LapicRegister` for an out-of-range offset instead of
// panicking, and convert bytes without zerocopy; the tests that need a vCPU
// run behind `kvm-tests`.

//! Local APIC setup: LINT0 delivers external interrupts (the PIC), LINT1
//! delivers NMIs.

use kvm_bindings::kvm_lapic_state;
use kvm_ioctls::VcpuFd;

use crate::arch::{kvm_error, Error, Result};

// Defines poached from apicdef.h kernel header.
const APIC_LVT0: usize = 0x350;
const APIC_LVT1: usize = 0x360;
const APIC_MODE_NMI: u32 = 0x4;
const APIC_MODE_EXTINT: u32 = 0x7;

fn klapic_range(reg_offset: usize) -> Result<std::ops::Range<usize>> {
    let end = reg_offset
        .checked_add(4)
        .ok_or(Error::LapicRegister(reg_offset))?;
    Ok(reg_offset..end)
}

fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> Result<u32> {
    let reg = klapic
        .regs
        .get(klapic_range(reg_offset)?)
        .ok_or(Error::LapicRegister(reg_offset))?;
    let mut bytes = [0u8; 4];
    for (byte, value) in bytes.iter_mut().zip(reg) {
        // c_char to u8: the same bits.
        *byte = *value as u8;
    }
    Ok(u32::from_le_bytes(bytes))
}

fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) -> Result<()> {
    let reg = klapic
        .regs
        .get_mut(klapic_range(reg_offset)?)
        .ok_or(Error::LapicRegister(reg_offset))?;
    for (slot, byte) in reg.iter_mut().zip(value.to_le_bytes()) {
        // u8 to c_char: the same bits.
        *slot = byte as std::os::raw::c_char;
    }
    Ok(())
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    ((reg) & !0x700) | ((mode) << 8)
}

/// Configures LAPICs.  LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
///
/// # Arguments
/// * `vcpu` - The VCPU object to configure.
pub fn set_lint(vcpu: &VcpuFd) -> Result<()> {
    let mut klapic = vcpu.get_lapic().map_err(kvm_error("get_lapic"))?;

    let lvt_lint0 = get_klapic_reg(&klapic, APIC_LVT0)?;
    set_klapic_reg(
        &mut klapic,
        APIC_LVT0,
        set_apic_delivery_mode(lvt_lint0, APIC_MODE_EXTINT),
    )?;
    let lvt_lint1 = get_klapic_reg(&klapic, APIC_LVT1)?;
    set_klapic_reg(
        &mut klapic,
        APIC_LVT1,
        set_apic_delivery_mode(lvt_lint1, APIC_MODE_NMI),
    )?;

    vcpu.set_lapic(&klapic).map_err(kvm_error("set_lapic"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KVM_APIC_REG_SIZE: usize = 0x400;

    #[test]
    fn test_set_and_get_klapic_reg() {
        let reg_offset = 0x340;
        let mut klapic = kvm_lapic_state::default();
        set_klapic_reg(&mut klapic, reg_offset, 3).unwrap();
        let value = get_klapic_reg(&klapic, reg_offset).unwrap();
        assert_eq!(value, 3);
    }

    #[test]
    fn test_set_and_get_klapic_reg_overflow() {
        let reg_offset = 0x340;
        let mut klapic = kvm_lapic_state::default();
        set_klapic_reg(
            &mut klapic,
            reg_offset,
            u32::try_from(i32::MAX).unwrap() + 1u32,
        )
        .unwrap();
        let value = get_klapic_reg(&klapic, reg_offset).unwrap();
        assert_eq!(value, u32::try_from(i32::MAX).unwrap() + 1u32);
    }

    /// Firecracker panics here; the port returns an error instead.
    #[test]
    fn test_set_and_get_klapic_out_of_bounds() {
        let reg_offset = KVM_APIC_REG_SIZE + 10;
        let mut klapic = kvm_lapic_state::default();
        assert!(matches!(
            set_klapic_reg(&mut klapic, reg_offset, 3),
            Err(Error::LapicRegister(offset)) if offset == reg_offset
        ));
        assert!(matches!(
            get_klapic_reg(&klapic, reg_offset),
            Err(Error::LapicRegister(offset)) if offset == reg_offset
        ));
        // The last register that still fits, and one byte past it.
        set_klapic_reg(&mut klapic, KVM_APIC_REG_SIZE - 4, 1).unwrap();
        get_klapic_reg(&klapic, KVM_APIC_REG_SIZE - 3).unwrap_err();
        get_klapic_reg(&klapic, usize::MAX).unwrap_err();
    }

    #[test]
    fn test_apic_delivery_mode() {
        let mut v: Vec<u32> = (0..20)
            .map(|_| vmm_sys_util::rand::xor_pseudo_rng_u32())
            .collect();

        v.iter_mut()
            .for_each(|x| *x = set_apic_delivery_mode(*x, 2));
        let after: Vec<u32> = v.iter().map(|x| (*x & !0x700) | ((2) << 8)).collect();
        assert_eq!(v, after);
    }

    /// LVT0 becomes ExtINT and LVT1 NMI, other bits kept, on a synthetic
    /// LAPIC page.
    #[test]
    fn lint_delivery_modes_on_a_synthetic_lapic() {
        let mut klapic = kvm_lapic_state::default();
        set_klapic_reg(&mut klapic, APIC_LVT0, 0x0001_0000).unwrap(); // masked
        set_klapic_reg(&mut klapic, APIC_LVT1, 0x0001_0400).unwrap(); // masked, NMI already
        let lint0 = set_apic_delivery_mode(get_klapic_reg(&klapic, APIC_LVT0).unwrap(), 7);
        let lint1 = set_apic_delivery_mode(get_klapic_reg(&klapic, APIC_LVT1).unwrap(), 4);
        assert_eq!(lint0, 0x0001_0700);
        assert_eq!(lint1, 0x0001_0400);
    }

    #[cfg(feature = "kvm-tests")]
    mod kvm {
        use super::*;
        use crate::arch::x86_64::test_utils::kvm_or_skip;

        #[test]
        fn test_setlint() {
            let Some(kvm) = kvm_or_skip("test_setlint") else {
                return;
            };
            assert!(kvm.check_extension(kvm_ioctls::Cap::Irqchip));
            let vm = kvm.create_vm().unwrap();
            // the get_lapic ioctl will fail if there is no irqchip created beforehand.
            vm.create_irq_chip().unwrap();
            let vcpu = vm.create_vcpu(0).unwrap();
            let klapic_before: kvm_lapic_state = vcpu.get_lapic().unwrap();

            // Compute the value that is expected to represent LVT0 and LVT1.
            let lint0 = get_klapic_reg(&klapic_before, APIC_LVT0).unwrap();
            let lint1 = get_klapic_reg(&klapic_before, APIC_LVT1).unwrap();
            let lint0_mode_expected = set_apic_delivery_mode(lint0, APIC_MODE_EXTINT);
            let lint1_mode_expected = set_apic_delivery_mode(lint1, APIC_MODE_NMI);

            set_lint(&vcpu).unwrap();

            // Compute the value that represents LVT0 and LVT1 after set_lint.
            let klapic_actual: kvm_lapic_state = vcpu.get_lapic().unwrap();
            let lint0_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT0).unwrap();
            let lint1_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT1).unwrap();
            assert_eq!(lint0_mode_expected, lint0_mode_actual);
            assert_eq!(lint1_mode_expected, lint1_mode_actual);
        }

        #[test]
        fn test_setlint_fails() {
            let Some(kvm) = kvm_or_skip("test_setlint_fails") else {
                return;
            };
            let vm = kvm.create_vm().unwrap();
            let vcpu = vm.create_vcpu(0).unwrap();
            // 'get_lapic' ioctl triggered by the 'set_lint' function will fail if there is no
            // irqchip created beforehand.
            set_lint(&vcpu).unwrap_err();
        }
    }
}
