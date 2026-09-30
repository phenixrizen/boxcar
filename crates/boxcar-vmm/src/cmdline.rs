// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The kernel command line: a base string, extra arguments, and one
//! `virtio_mmio.device=<size>@<base>:<gsi>` per virtio-mmio device.

use linux_loader::cmdline::Cmdline;
use vm_memory::GuestAddress;

use crate::arch::x86_64::layout::CMDLINE_MAX_SIZE;
use crate::arch::{Error, Result};

/// One virtio-mmio device announced to the guest on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioDeviceEntry {
    /// Size of the device's MMIO slot in bytes.
    pub size: u32,
    /// Guest physical base address of the slot.
    pub base: u64,
    /// The GSI the device interrupts on.
    pub gsi: u32,
}

/// Builds the command line: `base`, then each of `extra`, then a
/// `virtio_mmio.device=` entry per device (e.g.
/// `virtio_mmio.device=4K@0xc0000000:5`), separated by single spaces.
///
/// Fails when the result, with its NUL terminator, would exceed
/// [`CMDLINE_MAX_SIZE`] (2048) bytes, or when a part is not printable ASCII.
/// The size to put in `boot_params` is
/// `cmdline.as_cstring()?.as_bytes_with_nul().len()`.
pub fn build_cmdline(base: &str, extra: &[&str], devices: &[MmioDeviceEntry]) -> Result<Cmdline> {
    compose(CMDLINE_MAX_SIZE, base, extra, devices)
}

/// The size, NUL terminator included, of the command line
/// [`build_cmdline`] builds from the same parts, whether or not it fits in
/// [`CMDLINE_MAX_SIZE`]: for a caller that refuses one that is too long
/// and says by how much. Fails as `build_cmdline` does on a part that is
/// not printable ASCII.
pub fn cmdline_size(base: &str, extra: &[&str], devices: &[MmioDeviceEntry]) -> Result<usize> {
    let cmdline = compose(usize::MAX, base, extra, devices)?;
    let cmdline = cmdline.as_cstring().map_err(Error::Cmdline)?;
    Ok(cmdline.as_bytes_with_nul().len())
}

/// The command line of [`build_cmdline`], in at most `capacity` bytes.
fn compose(
    capacity: usize,
    base: &str,
    extra: &[&str],
    devices: &[MmioDeviceEntry],
) -> Result<Cmdline> {
    let mut cmdline = Cmdline::new(capacity).map_err(Error::Cmdline)?;
    cmdline.insert_str(base).map_err(Error::Cmdline)?;
    for arg in extra {
        cmdline.insert_str(arg).map_err(Error::Cmdline)?;
    }
    for device in devices {
        cmdline
            .add_virtio_mmio_device(
                u64::from(device.size),
                GuestAddress(device.base),
                device.gsi,
                None,
            )
            .map_err(Error::Cmdline)?;
    }
    Ok(cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(cmdline: &Cmdline) -> String {
        cmdline.as_cstring().unwrap().into_string().unwrap()
    }

    #[test]
    fn two_virtio_mmio_devices() {
        let devices = [
            MmioDeviceEntry {
                size: 0x1000,
                base: 0xc000_0000,
                gsi: 5,
            },
            MmioDeviceEntry {
                size: 0x1000,
                base: 0xc000_1000,
                gsi: 6,
            },
        ];
        let cmdline =
            build_cmdline("console=ttyS0 reboot=k", &["boxcar.mode=hello"], &devices).unwrap();
        let text = text(&cmdline);
        assert!(
            text.contains("virtio_mmio.device=4K@0xc0000000:5"),
            "{text}"
        );
        assert!(
            text.contains("virtio_mmio.device=4K@0xc0001000:6"),
            "{text}"
        );
        assert_eq!(
            text,
            "console=ttyS0 reboot=k boxcar.mode=hello \
             virtio_mmio.device=4K@0xc0000000:5 virtio_mmio.device=4K@0xc0001000:6"
        );
        assert_eq!(
            cmdline.as_cstring().unwrap().as_bytes_with_nul().len(),
            text.len() + 1
        );
    }

    #[test]
    fn base_and_extras_in_order() {
        let cmdline = build_cmdline("a=1", &["b=2", "c"], &[]).unwrap();
        assert_eq!(text(&cmdline), "a=1 b=2 c");
    }

    #[test]
    fn rejects_a_cmdline_over_2048_bytes() {
        // 2047 bytes plus the NUL terminator fit exactly.
        let fits = "a".repeat(2047);
        let cmdline = build_cmdline(&fits, &[], &[]).unwrap();
        assert_eq!(
            cmdline.as_cstring().unwrap().as_bytes_with_nul().len(),
            2048
        );

        let base = "a".repeat(2048);
        assert!(matches!(
            build_cmdline(&base, &[], &[]),
            Err(Error::Cmdline(linux_loader::cmdline::Error::TooLarge))
        ));

        let half = "b".repeat(1024);
        assert!(matches!(
            build_cmdline(&half, &[&half], &[]),
            Err(Error::Cmdline(linux_loader::cmdline::Error::TooLarge))
        ));

        let device = MmioDeviceEntry {
            size: 0x1000,
            base: 0xc000_0000,
            gsi: 5,
        };
        assert!(matches!(
            build_cmdline(&"c".repeat(2020), &[], &[device]),
            Err(Error::Cmdline(linux_loader::cmdline::Error::TooLarge))
        ));
    }

    #[test]
    fn the_size_is_measured_past_the_limit() {
        let device = MmioDeviceEntry {
            size: 0x1000,
            base: 0xc000_0000,
            gsi: 5,
        };
        let fits = build_cmdline("a=1", &["b=2"], &[device]).unwrap();
        assert_eq!(
            cmdline_size("a=1", &["b=2"], &[device]).unwrap(),
            fits.as_cstring().unwrap().as_bytes_with_nul().len()
        );
        let long = "c".repeat(2048);
        assert!(build_cmdline("a=1", &[&long], &[device]).is_err());
        assert_eq!(
            cmdline_size("a=1", &[&long], &[device]).unwrap(),
            "a=1 ".len() + 2048 + " virtio_mmio.device=4K@0xc0000000:5".len() + 1
        );
        assert!(matches!(
            cmdline_size("a=1", &["bad\u{7}"], &[]),
            Err(Error::Cmdline(_))
        ));
    }

    #[test]
    fn rejects_invalid_parts() {
        assert!(matches!(
            build_cmdline("console=ttyS0", &["bad\u{7}"], &[]),
            Err(Error::Cmdline(_))
        ));
        let zero = MmioDeviceEntry {
            size: 0,
            base: 0xc000_0000,
            gsi: 5,
        };
        assert!(matches!(
            build_cmdline("console=ttyS0", &[], &[zero]),
            Err(Error::Cmdline(linux_loader::cmdline::Error::MmioSize))
        ));
    }
}
