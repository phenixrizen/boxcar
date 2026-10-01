// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Feature bits every boxcar device offers.
//!
//! The bit numbers come from `virtio-bindings`; the masks are what a device
//! ORs into [`VirtioDevice::avail_features`](crate::VirtioDevice::avail_features).

/// Bit number of `VIRTIO_F_VERSION_1` (32): the device follows virtio 1.x.
/// virtio-mmio version 2 devices must offer it; the Linux driver refuses a
/// device that does not.
pub use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;

/// Bit number of `VIRTIO_RING_F_EVENT_IDX` (29): the `used_event` and
/// `avail_event` notification suppression fields.
pub use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

/// `VIRTIO_F_VERSION_1` as a feature mask.
pub const VERSION_1: u64 = 1 << VIRTIO_F_VERSION_1;

/// `VIRTIO_RING_F_EVENT_IDX` as a feature mask.
pub const EVENT_IDX: u64 = 1 << VIRTIO_RING_F_EVENT_IDX;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_and_masks_match_the_spec() {
        assert_eq!(VIRTIO_F_VERSION_1, 32);
        assert_eq!(VIRTIO_RING_F_EVENT_IDX, 29);
        assert_eq!(VERSION_1, 0x1_0000_0000);
        assert_eq!(EVENT_IDX, 0x2000_0000);
    }
}
