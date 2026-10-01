// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Architecture-specific boot setup. boxcar boots x86_64 guests only, through
//! the Linux 64-bit boot protocol (no PVH, no ACPI, no PCI).

pub mod x86_64;

use vm_memory::GuestMemoryError;

/// Everything that can go wrong while laying out guest memory, writing the
/// boot structures into it, or putting a vCPU in its boot state.
///
/// Messages do not repeat the wrapped error; it is reachable through
/// [`std::error::Error::source`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A guest needs at least some memory.
    #[error("guest memory size must be greater than zero")]
    ZeroMemorySize,
    /// `GuestMemoryMmap::from_ranges` failed.
    #[error("cannot create guest memory")]
    GuestMemory(#[source] vm_memory::mmap::FromRangesError),
    /// The initrd is larger than the RAM below the 32-bit MMIO hole.
    #[error("an initrd of {size} bytes does not fit below {limit:#x}")]
    InitrdTooLarge { size: usize, limit: u64 },
    /// The highest page-aligned initrd address is still inside the kernel.
    #[error("the initrd at {addr:#x} would overlap the kernel, which ends at {kernel_end:#x}")]
    InitrdOverlapsKernel { addr: u64, kernel_end: u64 },
    /// Building the kernel command line failed (too long, invalid characters).
    #[error("invalid kernel command line")]
    Cmdline(#[source] linux_loader::cmdline::Error),
    /// All 128 e820 slots of `boot_params` are used.
    #[error("the e820 table in boot_params is full")]
    E820TableFull,
    /// A `boot_params` header field is 32 bits wide and the value is not.
    #[error("boot_params field {field} cannot hold {value:#x}")]
    BootParamOverflow { field: &'static str, value: u64 },
    /// `LinuxBootConfigurator::write_bootparams` failed.
    #[error("cannot write boot_params to the zero page")]
    ZeroPage(#[source] linux_loader::configurator::Error),
    /// The MP table describes at most 254 CPUs (255 APIC IDs, one for the
    /// IOAPIC).
    #[error("{0} vCPUs exceed the MP table limit of 254")]
    TooManyCpus(u8),
    /// A boot structure does not fit in guest memory.
    #[error("guest memory is too small to hold the {0}")]
    NotEnoughMemory(&'static str),
    /// A boot structure's address arithmetic overflows.
    #[error("the address of the {0} overflows")]
    AddressOverflow(&'static str),
    /// Writing a boot structure to guest memory failed.
    #[error("cannot write the {what} to guest memory")]
    MemoryWrite {
        what: &'static str,
        #[source]
        source: GuestMemoryError,
    },
    /// A LAPIC register offset is outside `kvm_lapic_state::regs`.
    #[error("LAPIC register offset {0:#x} is out of range")]
    LapicRegister(usize),
    /// The MSR list does not fit in a `kvm_msrs` wrapper.
    #[error("cannot build the MSR list")]
    Msrs(#[source] vmm_sys_util::fam::Error),
    /// `KVM_SET_MSRS` stopped before the end of the list.
    #[error("KVM_SET_MSRS set {written} of {expected} MSRs")]
    SetMsrsIncomplete { written: usize, expected: usize },
    /// A KVM ioctl failed.
    #[error("KVM {op} failed")]
    Kvm {
        op: &'static str,
        #[source]
        source: kvm_ioctls::Error,
    },
}

/// Result of the boot setup functions.
pub type Result<T> = std::result::Result<T, Error>;

/// Maps a guest memory write error to [`Error::MemoryWrite`] for `what`.
pub(crate) fn write_error(what: &'static str) -> impl FnOnce(GuestMemoryError) -> Error {
    move |source| Error::MemoryWrite { what, source }
}

/// Maps a KVM ioctl error to [`Error::Kvm`] for `op`.
pub(crate) fn kvm_error(op: &'static str) -> impl FnOnce(kvm_ioctls::Error) -> Error {
    move |source| Error::Kvm { op, source }
}
