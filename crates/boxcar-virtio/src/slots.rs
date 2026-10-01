// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Hands out virtio-mmio slots: 4 KiB of MMIO in the window that starts at
//! `0xC000_0000` and a GSI from `5..=23`, each asked for by its exact place
//! with [`SlotAllocator::reserve`], so that a device always lands in the
//! slot the VMM's fixed table gives it whichever devices are present. The
//! allocator only refuses a slot or GSI that is outside the window, or
//! already taken.

use vm_allocator::{AddressAllocator, AllocPolicy};

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

/// Why a slot could not be reserved.
#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    /// The address allocator refused the slot, or could not be set up.
    #[error("virtio-mmio slot allocation: {0}")]
    Allocator(#[from] vm_allocator::Error),
    /// The slot is not 4 KiB aligned, or does not lie inside the window.
    #[error(
        "the virtio-mmio slot at {base:#x} is not an aligned 4 KiB slot inside the window \
         {:#x}..{:#x}",
        MMIO_WINDOW_BASE,
        MMIO_WINDOW_BASE + MMIO_WINDOW_SIZE
    )]
    BadSlot { base: u64 },
    /// The slot is already reserved.
    #[error("the virtio-mmio slot at {base:#x} is already taken")]
    SlotTaken { base: u64 },
    /// The GSI is not one a device may use.
    #[error("GSI {gsi} is outside the device range {}..={}", FIRST_GSI, LAST_GSI)]
    GsiOutOfRange { gsi: u32 },
    /// The GSI is already reserved.
    #[error("GSI {gsi} is already taken")]
    GsiTaken { gsi: u32 },
}

/// Reserves [`MmioSlot`]s, each at the place the caller names.
#[derive(Debug)]
pub struct SlotAllocator {
    mmio: AddressAllocator,
    /// Bit `n` is set when GSI `n` is taken. `vm_allocator::IdAllocator`
    /// hands out the next free id only, never a given one.
    gsis: u32,
}

impl SlotAllocator {
    /// An allocator over the whole window and GSI range, with nothing taken.
    pub fn new() -> Result<Self, SlotError> {
        Ok(Self {
            mmio: AddressAllocator::new(MMIO_WINDOW_BASE, MMIO_WINDOW_SIZE)?,
            gsis: 0,
        })
    }

    /// The 4 KiB slot at `base` and the GSI `gsi`, or an error naming what
    /// is wrong or already taken: `base` must be a 4 KiB-aligned slot inside
    /// the window and `gsi` in `5..=23`. A refused reservation takes
    /// nothing, so the same slot and GSI can be asked for again, or
    /// differently.
    pub fn reserve(&mut self, base: u64, gsi: u32) -> Result<MmioSlot, SlotError> {
        if !(FIRST_GSI..=LAST_GSI).contains(&gsi) {
            return Err(SlotError::GsiOutOfRange { gsi });
        }
        let bit = 1u32 << gsi;
        if self.gsis & bit != 0 {
            return Err(SlotError::GsiTaken { gsi });
        }
        let offset = base.wrapping_sub(MMIO_WINDOW_BASE);
        if base < MMIO_WINDOW_BASE
            || offset > MMIO_WINDOW_SIZE - MMIO_SLOT_SIZE
            || !offset.is_multiple_of(MMIO_SLOT_SIZE)
        {
            return Err(SlotError::BadSlot { base });
        }
        let range = match self.mmio.allocate(
            MMIO_SLOT_SIZE,
            MMIO_SLOT_SIZE,
            AllocPolicy::ExactMatch(base),
        ) {
            Ok(range) => range,
            // Inside the window and aligned, so the slot is not free: the
            // allocator says so as `InvalidStateTransition` when the very
            // slot is allocated and `ResourceNotAvailable` for any overlap.
            Err(
                vm_allocator::Error::ResourceNotAvailable
                | vm_allocator::Error::InvalidStateTransition(..),
            ) => return Err(SlotError::SlotTaken { base }),
            Err(err) => return Err(err.into()),
        };
        self.gsis |= bit;
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
    fn reserve_hands_out_exactly_the_slot_asked_for() {
        let mut slots = SlotAllocator::new().unwrap();
        // Out of order, and skipping slots 0 and 1: a disabled device leaves
        // its slot empty.
        for (base, gsi) in [(0xC000_3000, 8), (0xC000_2000, 7), (0xC000_0000, 5)] {
            assert_eq!(
                slots.reserve(base, gsi).unwrap(),
                MmioSlot {
                    base,
                    size: 0x1000,
                    gsi
                }
            );
        }
    }

    #[test]
    fn a_slot_cannot_be_reserved_twice() {
        let mut slots = SlotAllocator::new().unwrap();
        slots.reserve(0xC000_1000, 6).unwrap();
        // Same slot, another GSI: the slot is taken.
        assert!(matches!(
            slots.reserve(0xC000_1000, 9),
            Err(SlotError::SlotTaken { base: 0xC000_1000 })
        ));
        // Another slot, the same GSI: the GSI is taken.
        assert!(matches!(
            slots.reserve(0xC000_2000, 6),
            Err(SlotError::GsiTaken { gsi: 6 })
        ));
        // Neither failure took anything: both are still free.
        slots.reserve(0xC000_2000, 9).unwrap();
        slots.reserve(0xC000_5000, 10).unwrap();
    }

    #[test]
    fn a_slot_outside_the_window_or_gsi_range_is_refused() {
        let mut slots = SlotAllocator::new().unwrap();
        for base in [
            0,
            0xBFFF_F000,
            0xC000_0800,
            0xD000_0000,
            MMIO_WINDOW_BASE + MMIO_WINDOW_SIZE,
            u64::MAX,
        ] {
            assert!(
                matches!(slots.reserve(base, 5), Err(SlotError::BadSlot { .. })),
                "{base:#x}"
            );
        }
        for gsi in [0, 4, 24, u32::MAX] {
            assert!(
                matches!(
                    slots.reserve(0xC000_0000, gsi),
                    Err(SlotError::GsiOutOfRange { .. })
                ),
                "{gsi}"
            );
        }
        // The last slot of the window and the last GSI are fine.
        let last = slots.reserve(0xCFFF_F000, 23).unwrap();
        assert_eq!(last.base + last.size, MMIO_WINDOW_BASE + MMIO_WINDOW_SIZE);
        // Nothing above was taken.
        slots.reserve(0xC000_0000, 5).unwrap();
    }

    #[test]
    fn every_gsi_of_the_range_can_be_reserved_once() {
        let mut slots = SlotAllocator::new().unwrap();
        for (i, gsi) in (FIRST_GSI..=LAST_GSI).enumerate() {
            let base = MMIO_WINDOW_BASE + i as u64 * MMIO_SLOT_SIZE;
            assert_eq!(slots.reserve(base, gsi).unwrap().gsi, gsi);
        }
        // All 19 GSIs are gone, whatever slot is asked for.
        assert!(matches!(
            slots.reserve(0xC001_0000, 5),
            Err(SlotError::GsiTaken { gsi: 5 })
        ));
    }

    #[test]
    fn two_allocators_agree_on_what_is_free() {
        let mut a = SlotAllocator::new().unwrap();
        let mut b = SlotAllocator::new().unwrap();
        for (base, gsi) in [(0xC000_1000, 6), (0xC000_0000, 5), (0xC000_1000, 6)] {
            assert_eq!(
                a.reserve(base, gsi).map_err(|e| e.to_string()),
                b.reserve(base, gsi).map_err(|e| e.to_string())
            );
        }
    }
}
