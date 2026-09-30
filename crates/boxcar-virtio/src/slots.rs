// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Hands out virtio-mmio slots: 4 KiB of MMIO from `0xC000_0000` and a GSI
//! from `5..=23`, both in call order, so the same device list always lands
//! in the same slots (slot 0 is `0xC000_0000` with GSI 5, slot 1
//! `0xC000_1000` with GSI 6, and so on).

use tracing::warn;
use vm_allocator::{AddressAllocator, AllocPolicy, IdAllocator};

use crate::context::MmioSlot;
use crate::mmio::MMIO_SLOT_SIZE;

/// Start of the virtio-mmio window, at the bottom of the 32-bit MMIO hole.
pub const MMIO_WINDOW_BASE: u64 = 0xC000_0000;
/// Size of the virtio-mmio window.
pub const MMIO_WINDOW_SIZE: u64 = 0x1000_0000;
/// The first GSI given to a device. 0 to 4 belong to the legacy devices.
pub const FIRST_GSI: u32 = 5;
/// The last GSI given to a device: the IOAPIC has 24 pins.
pub const LAST_GSI: u32 = 23;

/// Why no slot could be handed out.
#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    /// The GSIs or the MMIO window ran out, or an allocator was misused.
    #[error("virtio-mmio slot allocation: {0}")]
    Allocator(#[from] vm_allocator::Error),
}

/// Allocates [`MmioSlot`]s deterministically.
#[derive(Debug)]
pub struct SlotAllocator {
    mmio: AddressAllocator,
    gsis: IdAllocator,
}

impl SlotAllocator {
    /// An allocator over the whole window and GSI range.
    pub fn new() -> Result<Self, SlotError> {
        Ok(Self {
            mmio: AddressAllocator::new(MMIO_WINDOW_BASE, MMIO_WINDOW_SIZE)?,
            gsis: IdAllocator::new(FIRST_GSI, LAST_GSI)?,
        })
    }

    /// The next slot: the lowest free 4 KiB of the window and the lowest free
    /// GSI. Fails once the 19 GSIs are gone.
    pub fn alloc(&mut self) -> Result<MmioSlot, SlotError> {
        let gsi = self.gsis.allocate_id()?;
        let range =
            match self
                .mmio
                .allocate(MMIO_SLOT_SIZE, MMIO_SLOT_SIZE, AllocPolicy::FirstMatch)
            {
                Ok(range) => range,
                Err(err) => {
                    if let Err(free) = self.gsis.free_id(gsi) {
                        warn!("could not return GSI {gsi} after a failed slot allocation: {free}");
                    }
                    return Err(err.into());
                }
            };
        Ok(MmioSlot {
            base: range.start(),
            size: range.len(),
            gsi,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_follow_the_fixed_device_order() {
        let mut slots = SlotAllocator::new().unwrap();
        // Slot 0: virtio-fs `root`; slot 1: virtio-fs `workspace`; slots 2
        // and 3: net and vsock in M2.
        let expected = [
            (0xC000_0000, 5),
            (0xC000_1000, 6),
            (0xC000_2000, 7),
            (0xC000_3000, 8),
        ];
        for (base, gsi) in expected {
            assert_eq!(
                slots.alloc().unwrap(),
                MmioSlot {
                    base,
                    size: 0x1000,
                    gsi
                }
            );
        }
    }

    #[test]
    fn two_allocators_hand_out_the_same_slots() {
        let mut a = SlotAllocator::new().unwrap();
        let mut b = SlotAllocator::new().unwrap();
        for _ in 0..8 {
            assert_eq!(a.alloc().unwrap(), b.alloc().unwrap());
        }
    }

    #[test]
    fn allocation_stops_when_the_gsis_run_out() {
        let mut slots = SlotAllocator::new().unwrap();
        let all: Vec<MmioSlot> = (FIRST_GSI..=LAST_GSI)
            .map(|_| slots.alloc().unwrap())
            .collect();
        assert_eq!(all.len(), 19);
        assert_eq!(all.last().unwrap().gsi, 23);
        assert_eq!(all.last().unwrap().base, 0xC000_0000 + 18 * 0x1000);
        // Slots never overlap and stay inside the window.
        for pair in all.windows(2) {
            assert_eq!(pair[1].base, pair[0].base + pair[0].size);
        }
        assert!(all
            .iter()
            .all(|s| s.base + s.size <= MMIO_WINDOW_BASE + MMIO_WINDOW_SIZE));

        assert!(matches!(
            slots.alloc(),
            Err(SlotError::Allocator(
                vm_allocator::Error::ResourceNotAvailable
            ))
        ));
    }
}
