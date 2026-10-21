// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The host's clock, read through `ptp_kvm`. A KVM guest with the driver
//! has a PTP clock named `KVM virtual PTP`, whose `PTP_SYS_OFFSET_PRECISE`
//! gives the host's `CLOCK_REALTIME` and the guest's clocks from one read
//! of the TSC (the `KVM_HC_CLOCK_PAIRING` hypercall), which pairs the two
//! to within the read's own window, microseconds, whatever the load; a
//! ping's round trip pairs them to within half of itself. The kernel
//! gives the read only against the `kvm-clock` clocksource, which the
//! VMM's command line selects. A guest without the clock (a host whose
//! KVM declines the hypercall, as some nested ones do) has none, or whose
//! read is declined, and its pongs carry no pair.

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use boxcar_proto::guest::PtpPair;

use crate::ctl::clock_ns;

/// The clock `ptp_kvm` registers.
const KVM_CLOCK_NAME: &str = "KVM virtual PTP";

/// `PTP_SYS_OFFSET_PRECISE`: `_IOWR('=', 8, struct ptp_sys_offset_precise)`,
/// a 64-byte structure.
const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = 0xC040_3D08;

/// `struct ptp_clock_time`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PtpClockTime {
    sec: i64,
    nsec: u32,
    reserved: u32,
}

/// `struct ptp_sys_offset_precise`: the device's time and the system's
/// `CLOCK_REALTIME` and `CLOCK_MONOTONIC_RAW`, all from one read.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PtpSysOffsetPrecise {
    device: PtpClockTime,
    sys_realtime: PtpClockTime,
    sys_monoraw: PtpClockTime,
    rsv: [u32; 4],
}

/// `ptp_kvm`'s clock, open.
pub struct PtpKvm {
    file: File,
}

impl PtpKvm {
    /// The KVM PTP clock, when the guest has one: the `/sys/class/ptp`
    /// entry named for it, opened as its `/dev` node.
    pub fn open() -> Option<PtpKvm> {
        Self::open_in(Path::new("/sys/class/ptp"), Path::new("/dev"))
    }

    fn open_in(class: &Path, dev: &Path) -> Option<PtpKvm> {
        for entry in fs::read_dir(class).ok()?.flatten() {
            let name = fs::read_to_string(entry.path().join("clock_name")).unwrap_or_default();
            if name.trim() != KVM_CLOCK_NAME {
                continue;
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(dev.join(entry.file_name()))
                .ok()?;
            return Some(PtpKvm { file });
        }
        None
    }

    /// One pair: the host's `CLOCK_REALTIME` and the guest's
    /// `CLOCK_MONOTONIC` at one read of the TSC, and the window on the
    /// guest's clock within which the read was taken. The read gives the
    /// guest's raw monotonic clock, which is moved onto `CLOCK_MONOTONIC`
    /// by the two clocks' distance around the read. `None` when the clock
    /// declines the read.
    pub fn pair(&self) -> Option<PtpPair> {
        let before = (
            clock_ns(libc::CLOCK_MONOTONIC),
            clock_ns(libc::CLOCK_MONOTONIC_RAW),
        );
        let mut arg = PtpSysOffsetPrecise::default();
        // SAFETY: PTP_SYS_OFFSET_PRECISE fills one ptp_sys_offset_precise
        // through its argument, which points at `arg`, alive for the call.
        let rc =
            unsafe { libc::ioctl(self.file.as_raw_fd(), PTP_SYS_OFFSET_PRECISE as _, &mut arg) };
        if rc != 0 {
            return None;
        }
        let after = (
            clock_ns(libc::CLOCK_MONOTONIC),
            clock_ns(libc::CLOCK_MONOTONIC_RAW),
        );
        let skew = (i128::from(before.0) - i128::from(before.1) + i128::from(after.0)
            - i128::from(after.1))
            / 2;
        let guest_mono_ns = u64::try_from(i128::from(ns(arg.sys_monoraw)) + skew).ok()?;
        Some(PtpPair {
            host_real_ns: ns(arg.device),
            guest_mono_ns,
            window_ns: after.0.saturating_sub(before.0),
        })
    }
}

/// A `ptp_clock_time` in nanoseconds; 0 for one before the epoch.
fn ns(time: PtpClockTime) -> u64 {
    u64::try_from(time.sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(time.nsec))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request is the kernel's: direction, size, magic and number.
    #[test]
    fn the_request_is_the_kernels() {
        assert_eq!(std::mem::size_of::<PtpSysOffsetPrecise>(), 64);
        assert_eq!(std::mem::size_of::<PtpClockTime>(), 16);
        let dir: libc::c_ulong = 3 << 30;
        let size = (std::mem::size_of::<PtpSysOffsetPrecise>() as libc::c_ulong) << 16;
        let magic = libc::c_ulong::from(b'=') << 8;
        assert_eq!(PTP_SYS_OFFSET_PRECISE, dir | size | magic | 8);
    }

    /// Only the KVM clock is opened: a class with other clocks, or none,
    /// gives nothing; the KVM one is opened by its name under `/dev`.
    #[test]
    fn only_the_kvm_clock_is_opened() {
        let tmp = tempfile::tempdir().unwrap();
        let class = tmp.path().join("class");
        let dev = tmp.path().join("dev");
        fs::create_dir_all(class.join("ptp0")).unwrap();
        fs::create_dir_all(&dev).unwrap();
        fs::write(class.join("ptp0/clock_name"), "hyperv\n").unwrap();
        fs::write(dev.join("ptp0"), "").unwrap();
        assert!(PtpKvm::open_in(&class, &dev).is_none());
        assert!(PtpKvm::open_in(&tmp.path().join("none"), &dev).is_none());
        fs::create_dir_all(class.join("ptp1")).unwrap();
        fs::write(class.join("ptp1/clock_name"), "KVM virtual PTP\n").unwrap();
        assert!(
            PtpKvm::open_in(&class, &dev).is_none(),
            "no device node yet"
        );
        fs::write(dev.join("ptp1"), "").unwrap();
        let ptp = PtpKvm::open_in(&class, &dev).unwrap();
        // A plain file is no PTP clock: the read is declined, not faked.
        assert!(ptp.pair().is_none());
    }

    #[test]
    fn times_convert_to_nanoseconds_and_saturate() {
        assert_eq!(
            ns(PtpClockTime {
                sec: 1,
                nsec: 5,
                reserved: 0
            }),
            1_000_000_005
        );
        assert_eq!(
            ns(PtpClockTime {
                sec: -1,
                nsec: 5,
                reserved: 0
            }),
            5
        );
    }
}
