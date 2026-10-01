// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! KVM smoke test: one vCPU runs a real-mode guest that writes `K` to COM1
//! and halts. It proves `/dev/kvm`, memory registration, register setup and
//! the run loop work on this host before anything larger is built on them.
//!
//! Skips with a printed reason when `/dev/kvm` is not accessible, or when
//! `BOXCAR_FAKE_NO_KVM=1` forces the same answer.

#![cfg(feature = "kvm-tests")]

use std::env;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use boxcar_vmm::kvm::{kvm_available, KvmContext};
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::VcpuExit;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

const FAKE_NO_KVM: &str = "BOXCAR_FAKE_NO_KVM";
const GUEST_ADDR: u64 = 0x1000;
const MEM_SIZE: usize = 0x1000;
const COM1: u16 = 0x3f8;
/// `mov dx,0x3f8; mov al,'K'; out dx,al; hlt`, real mode.
const CODE: [u8; 7] = [0xba, 0xf8, 0x03, 0xb0, 0x4b, 0xee, 0xf4];

/// The process environment is shared by every test in this binary, so a test
/// that reads or writes `BOXCAR_FAKE_NO_KVM` holds this for its whole run.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Sets `BOXCAR_FAKE_NO_KVM=1` and restores the previous value on drop, also
/// when the test panics.
struct FakeNoKvm(Option<OsString>);

impl FakeNoKvm {
    fn set() -> Self {
        let previous = env::var_os(FAKE_NO_KVM);
        env::set_var(FAKE_NO_KVM, "1");
        FakeNoKvm(previous)
    }
}

impl Drop for FakeNoKvm {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => env::set_var(FAKE_NO_KVM, value),
            None => env::remove_var(FAKE_NO_KVM),
        }
    }
}

#[test]
fn guest_writes_k_to_com1_then_halts() {
    let _env = lock_env();
    if let Err(reason) = kvm_available() {
        eprintln!("skipping guest_writes_k_to_com1_then_halts: {reason}");
        return;
    }

    let ctx = KvmContext::open().expect("open /dev/kvm");
    // Declared before the VM so the VM is dropped first.
    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(GUEST_ADDR), MEM_SIZE)])
        .expect("map guest memory");
    mem.write_slice(&CODE, GuestAddress(GUEST_ADDR))
        .expect("copy guest code into memory");
    let vm = ctx.kvm.create_vm().expect("KVM_CREATE_VM");

    let host_addr = mem
        .get_host_address(GuestAddress(GUEST_ADDR))
        .expect("host address of guest memory");
    let region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: GUEST_ADDR,
        memory_size: MEM_SIZE as u64,
        userspace_addr: host_addr as u64,
        flags: 0,
    };
    // SAFETY: `host_addr` is the start of a live MEM_SIZE-byte anonymous
    // mapping owned by `mem`, which outlives `vm` and the vCPU below.
    unsafe { vm.set_user_memory_region(region) }.expect("KVM_SET_USER_MEMORY_REGION");

    let mut vcpu = vm.create_vcpu(0).expect("KVM_CREATE_VCPU");
    let mut sregs = vcpu.get_sregs().expect("KVM_GET_SREGS");
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).expect("KVM_SET_SREGS");
    let mut regs = vcpu.get_regs().expect("KVM_GET_REGS");
    regs.rip = GUEST_ADDR;
    regs.rflags = 2;
    vcpu.set_regs(&regs).expect("KVM_SET_REGS");

    match vcpu.run().expect("first KVM_RUN") {
        VcpuExit::IoOut(port, data) => {
            assert_eq!(port, COM1);
            assert_eq!(data, [b'K']);
        }
        other => panic!("first exit: expected IoOut(0x3f8, [b'K']), got {other:?}"),
    }
    match vcpu.run().expect("second KVM_RUN") {
        VcpuExit::Hlt => {}
        other => panic!("second exit: expected Hlt, got {other:?}"),
    }
}

#[test]
fn fake_no_kvm_reports_unavailable() {
    let _env = lock_env();
    let _fake = FakeNoKvm::set();
    let reason = kvm_available().expect_err("BOXCAR_FAKE_NO_KVM=1 must report KVM unavailable");
    assert!(
        reason.contains(FAKE_NO_KVM),
        "the reason should name the variable, got: {reason}"
    );
}
