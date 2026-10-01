// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The KVM handle: opening `/dev/kvm`, checking the API version, and checking
//! the capabilities boxcar depends on.

use std::fs::OpenOptions;
use std::io;

use kvm_ioctls::Kvm;

/// Re-exported so callers that only inspect capabilities need not depend on
/// `kvm-ioctls`.
pub use kvm_ioctls::Cap;

/// The one KVM API version boxcar supports. It has been 12 since Linux 2.6.
pub const KVM_API_VERSION: i32 = 12;

/// The device node every KVM ioctl starts from.
pub const KVM_DEVICE: &str = "/dev/kvm";

/// What to do when `/dev/kvm` cannot be opened.
pub const KVM_OPEN_HINT: &str =
    "run: sudo modprobe kvm_amd (or kvm_intel); sudo setfacl -m u:$USER:rw /dev/kvm";

/// Setting this to `1` makes [`kvm_available`] report KVM as unavailable, so
/// the skip path of the gated tests can be exercised on a machine that has KVM.
pub const FAKE_NO_KVM_ENV: &str = "BOXCAR_FAKE_NO_KVM";

/// Capabilities the VMM cannot run without: the in-kernel interrupt
/// controller and timer, the TSS address, memory regions, eventfd-based
/// device kicks and interrupts, immediate exit for vCPU kicks, CPUID and
/// multiprocessor state.
pub const REQUIRED_CAPS: &[Cap] = &[
    Cap::Irqchip,
    Cap::UserMemory,
    Cap::SetTssAddr,
    Cap::Pit2,
    Cap::PitState2,
    Cap::Ioeventfd,
    Cap::Irqfd,
    Cap::ImmediateExit,
    Cap::ExtCpuid,
    Cap::MpState,
];

/// An open `/dev/kvm` whose API version is supported.
pub struct KvmContext {
    pub kvm: Kvm,
}

/// Why [`KvmContext::open`] failed, or what a caller found missing afterwards.
#[derive(Debug, thiserror::Error)]
pub enum KvmError {
    #[error("cannot open /dev/kvm: {0} ({hint})", hint = KVM_OPEN_HINT)]
    Open(#[source] io::Error),
    #[error("unsupported KVM API version {0} (boxcar needs {want})", want = KVM_API_VERSION)]
    ApiVersion(i32),
    /// For callers that require every [`REQUIRED_CAPS`] entry: build it from
    /// [`KvmContext::missing_caps`].
    #[error("KVM lacks required capabilities: {0:?}")]
    MissingCaps(Vec<Cap>),
}

impl KvmContext {
    /// Opens `/dev/kvm` and checks that the API version is
    /// [`KVM_API_VERSION`].
    pub fn open() -> Result<Self, KvmError> {
        let kvm = Kvm::new().map_err(|errno| KvmError::Open(errno.into()))?;
        let version = kvm.get_api_version();
        if version != KVM_API_VERSION {
            return Err(KvmError::ApiVersion(version));
        }
        Ok(KvmContext { kvm })
    }

    /// The entries of [`REQUIRED_CAPS`] this host's KVM does not report.
    pub fn missing_caps(&self) -> Vec<Cap> {
        REQUIRED_CAPS
            .iter()
            .copied()
            .filter(|&cap| !self.kvm.check_extension(cap))
            .collect()
    }

    /// The most vCPUs one VM may have.
    pub fn max_vcpus(&self) -> usize {
        self.kvm.get_max_vcpus()
    }
}

/// `Ok` when this process can open `/dev/kvm` for reading and writing;
/// otherwise the reason, for a test to print before it skips. Also reports
/// unavailable while `BOXCAR_FAKE_NO_KVM=1`.
pub fn kvm_available() -> Result<(), String> {
    if std::env::var_os(FAKE_NO_KVM_ENV).is_some_and(|value| value == "1") {
        return Err(format!("{FAKE_NO_KVM_ENV}=1 forces KVM to be unavailable"));
    }
    match OpenOptions::new().read(true).write(true).open(KVM_DEVICE) {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("{KVM_DEVICE} is not accessible: {error}")),
    }
}
