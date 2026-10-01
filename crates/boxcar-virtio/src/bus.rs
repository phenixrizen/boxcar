// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from Firecracker (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/vstate/bus.rs at commit 21f19ed8109578108568c8a8f3623ddb6f097878
// (at that commit the bus lives under vstate/, not devices/). The BSD-3-Clause
// text referred to above is in LICENSE-BSD-3-Clause. Adapted: devices sit
// directly in a `BTreeMap` keyed by range (no slab, no locks around the map,
// no `remove` or `move_range`), `insert` takes `&mut self`, `read` and `write`
// return whether a device answered instead of an error, and `BusDevice` takes
// only the offset and returns nothing from `write`. The tests are Firecracker's
// minus the removal and relocation cases, plus one for a rejected insert.

//! Routes reads and writes in an address space (PIO or MMIO) to the device
//! that owns the address.

use std::cmp::Ordering;
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A device that responds to reads and writes in some address space.
///
/// The device does not care where it sits in the address space: each method
/// is given the offset into the range the device was inserted with.
pub trait BusDevice: Send {
    /// Reads `data.len()` bytes at `offset` into `data`.
    fn read(&mut self, offset: u64, data: &mut [u8]);
    /// Writes `data` at `offset`.
    fn write(&mut self, offset: u64, data: &[u8]);
}

/// Why a [`Bus`] or [`BusRange`] operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BusError {
    /// The new device's range overlaps a device already on the bus.
    #[error("the range overlaps a device already on the bus")]
    Overlap,
    /// A range of zero bytes.
    #[error("a bus range cannot be empty")]
    ZeroSizedRange,
    /// The range runs past the end of the address space.
    #[error("the range runs past the end of the address space")]
    InvalidRange,
}

/// The addresses a device occupies on a [`Bus`]: `base` to `end` inclusive.
///
/// Ranges compare by `base` only, which is what lets the bus find the range
/// that could contain an address with a single ordered-map lookup.
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    base: u64,
    end: u64,
}

impl BusRange {
    /// The range of `len` bytes starting at `base`. Fails for an empty range
    /// or one that runs past `u64::MAX`.
    pub fn new(base: u64, len: u64) -> Result<Self, BusError> {
        if len == 0 {
            return Err(BusError::ZeroSizedRange);
        }
        let end = base.checked_add(len - 1).ok_or(BusError::InvalidRange)?;
        Ok(BusRange { base, end })
    }

    /// The first address of the range.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The last address of the range (inclusive).
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Whether the two ranges share at least one address.
    pub fn overlaps(&self, other: &BusRange) -> bool {
        self.base <= other.end && other.base <= self.end
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A shared handle to a device on a [`Bus`].
pub type SharedBusDevice = Arc<Mutex<dyn BusDevice>>;

/// Routes accesses in one address space to the devices inserted into it.
///
/// No two devices may overlap. An access is delivered only when it lies
/// entirely inside one device's range; anything else is unmapped, and what an
/// unmapped access means is the caller's decision (the VMM answers unmapped
/// PIO reads with `0xff`).
#[derive(Default)]
pub struct Bus {
    devices: BTreeMap<BusRange, SharedBusDevice>,
}

impl Bus {
    /// A bus with nothing on it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts `device` at `[base, base + len)`. Fails, leaving the bus as it
    /// was, when the range is empty, runs past `u64::MAX`, or overlaps a
    /// device already on the bus.
    pub fn insert(&mut self, device: SharedBusDevice, base: u64, len: u64) -> Result<(), BusError> {
        let range = BusRange::new(base, len)?;
        if self.devices.keys().any(|r| r.overlaps(&range)) {
            return Err(BusError::Overlap);
        }
        self.devices.insert(range, device);
        Ok(())
    }

    /// Reads `data.len()` bytes at `addr` from the device that owns them.
    /// Returns `false`, leaving `data` untouched, when no single device covers
    /// the whole access.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        match self.resolve(addr, data.len()) {
            Some((offset, device)) => {
                lock(device).read(offset, data);
                true
            }
            None => false,
        }
    }

    /// Writes `data` at `addr` to the device that owns it. Returns `false`
    /// when no single device covers the whole access.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        match self.resolve(addr, data.len()) {
            Some((offset, device)) => {
                lock(device).write(offset, data);
                true
            }
            None => false,
        }
    }

    /// The device whose range contains all of `[addr, addr + len)`, and the
    /// offset of `addr` into that range.
    fn resolve(&self, addr: u64, len: usize) -> Option<(u64, &SharedBusDevice)> {
        let access = BusRange::new(addr, u64::try_from(len).ok()?).ok()?;
        // The last range starting at or below `addr` is the only candidate.
        let (range, device) = self.devices.range(..=access).next_back()?;
        (access.end() <= range.end()).then_some((addr - range.base(), device))
    }
}

/// Locks a device. A device whose lock was poisoned (a thread panicked while
/// inside it) keeps serving: the panic already surfaced on that thread, and
/// refusing the access would only turn it into an unmapped one here.
fn lock(device: &SharedBusDevice) -> MutexGuard<'_, dyn BusDevice + 'static> {
    device.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {
        fn read(&mut self, _offset: u64, _data: &mut [u8]) {}
        fn write(&mut self, _offset: u64, _data: &[u8]) {}
    }

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        fn read(&mut self, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        fn write(&mut self, offset: u64, data: &[u8]) {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }
        }
    }

    /// A device that answers every read with its own id, so that a test can
    /// tell which device an access was routed to.
    struct IdDevice(u8);
    impl BusDevice for IdDevice {
        fn read(&mut self, _offset: u64, data: &mut [u8]) {
            data.fill(self.0);
        }
        fn write(&mut self, _offset: u64, _data: &[u8]) {}
    }

    #[test]
    fn bus_range_new() {
        // Zero length is invalid.
        assert!(matches!(BusRange::new(0, 0), Err(BusError::ZeroSizedRange)));
        assert!(matches!(
            BusRange::new(u64::MAX, 0),
            Err(BusError::ZeroSizedRange)
        ));

        // Overflow is invalid.
        assert!(matches!(
            BusRange::new(u64::MAX, 2),
            Err(BusError::InvalidRange)
        ));
        assert!(matches!(
            BusRange::new(2, u64::MAX),
            Err(BusError::InvalidRange)
        ));

        // Ranges that exactly reach u64::MAX are valid.
        let r = BusRange::new(u64::MAX, 1).unwrap();
        assert_eq!(r.base(), u64::MAX);
        assert_eq!(r.end(), u64::MAX);

        let r = BusRange::new(1, u64::MAX).unwrap();
        assert_eq!(r.base(), 1);
        assert_eq!(r.end(), u64::MAX);

        let r = BusRange::new(u64::MAX - 4095, 4096).unwrap();
        assert_eq!(r.base(), u64::MAX - 4095);
        assert_eq!(r.end(), u64::MAX);

        // One sized valid range.
        let r = BusRange::new(0, 1).unwrap();
        assert_eq!(r.base(), 0);
        assert_eq!(r.end(), 0);

        // Normal valid range.
        let r = BusRange::new(0x1000, 0x400).unwrap();
        assert_eq!(r.base(), 0x1000);
        assert_eq!(r.end(), 0x13ff);
    }

    #[test]
    fn bus_multiple_devices() {
        let mut bus = Bus::new();
        let dev_a = Arc::new(Mutex::new(IdDevice(0xa)));
        let dev_b = Arc::new(Mutex::new(IdDevice(0xb)));
        let dev_c = Arc::new(Mutex::new(IdDevice(0xc)));

        bus.insert(dev_a.clone(), 0x1000, 0x100).unwrap();
        bus.insert(dev_b.clone(), 0x2000, 0x100).unwrap();
        bus.insert(dev_c.clone(), 0x3000, 0x100).unwrap();

        let read = |bus: &Bus, addr| {
            let mut data = [0u8; 1];
            assert!(bus.read(addr, &mut data), "read at {addr:#x}");
            data[0]
        };

        // Every range decodes to the device that owns it, at both ends.
        assert_eq!(read(&bus, 0x1000), 0xa);
        assert_eq!(read(&bus, 0x10ff), 0xa);
        assert_eq!(read(&bus, 0x2000), 0xb);
        assert_eq!(read(&bus, 0x20ff), 0xb);
        assert_eq!(read(&bus, 0x3000), 0xc);
        assert_eq!(read(&bus, 0x30ff), 0xc);

        // The gaps between them are unmapped.
        assert!(!bus.read(0x1100, &mut [0; 1]));
        assert!(!bus.read(0x0fff, &mut [0; 1]));
        assert!(!bus.read(0x3100, &mut [0; 1]));

        // Accesses must be fully contained in a single device's range. Add a
        // device right after `dev_b` and one at the very top of the address
        // space to exercise the boundaries.
        bus.insert(dev_a.clone(), 0x2100, 0x100).unwrap();
        bus.insert(dev_a.clone(), u64::MAX, 1).unwrap();

        // An access ending on the last byte of a range is served, while one
        // crossing into the adjacent device is served by neither.
        let mut data = [0; 4];
        assert!(bus.read(0x20fc, &mut data));
        assert_eq!(data, [0xb; 4]);
        let mut data = [0; 4];
        assert!(!bus.read(0x20fe, &mut data));
        assert_eq!(data, [0; 4], "an unmapped read leaves the buffer alone");

        // An access wrapping around the end of the address space is rejected.
        assert!(bus.read(u64::MAX, &mut [0; 1]));
        assert!(!bus.read(u64::MAX, &mut data));

        // Zero sized accesses are rejected.
        assert!(!bus.read(0x2000, &mut []));
        assert!(!bus.write(0x2000, &[]));
    }

    #[test]
    fn bus_insert() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        bus.insert(dummy.clone(), 0x10, 0).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        assert_eq!(format!("{result:?}"), "Err(Overlap)");

        bus.insert(dummy.clone(), 0x10, 0x10).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x01).unwrap_err();
        bus.insert(dummy.clone(), 0x0, 0x20).unwrap_err();
        bus.insert(dummy.clone(), 0x20, 0x05).unwrap();
        bus.insert(dummy.clone(), 0x25, 0x05).unwrap();
        bus.insert(dummy, 0x0, 0x10).unwrap();
    }

    #[test]
    fn a_rejected_insert_leaves_the_bus_unchanged() {
        let mut bus = Bus::new();
        bus.insert(Arc::new(Mutex::new(IdDevice(0xa))), 0x10, 0x10)
            .unwrap();
        assert_eq!(
            bus.insert(Arc::new(Mutex::new(IdDevice(0xb))), 0x18, 0x10),
            Err(BusError::Overlap)
        );
        let mut data = [0u8; 1];
        assert!(bus.read(0x18, &mut data));
        assert_eq!(data[0], 0xa, "the first device still owns 0x18");
        assert!(
            !bus.read(0x20, &mut data),
            "the rejected range stays unmapped"
        );
    }

    #[test]
    fn bus_read_write() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x16, &[0, 0, 0, 0]));
        assert!(bus.read(0x1c, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x1c, &[0, 0, 0, 0]));
        assert!(!bus.read(0x1d, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x1d, &[0, 0, 0, 0]));
        assert!(!bus.read(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x20, &[0, 0, 0, 0]));
        assert!(!bus.read(0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x06, &[0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        bus.insert(dummy, 0x10, 0x10).unwrap();

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn busrange_cmp() {
        let range = BusRange::new(0x10, 2).unwrap();
        assert_eq!(range, BusRange::new(0x10, 3).unwrap());
        assert_eq!(range, BusRange::new(0x10, 2).unwrap());

        assert!(range < BusRange::new(0x12, 1).unwrap());
        assert!(range < BusRange::new(0x12, 3).unwrap());

        assert_eq!(range, range.clone());

        let mut bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        let device = Arc::new(Mutex::new(DummyDevice));
        bus.insert(device, 0x10, 0x10).unwrap();
        assert!(bus.write(0x10, &data));
        assert!(bus.read(0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange::new(0x1000, 0x400).unwrap();
        assert!(a.overlaps(&BusRange::new(0x1000, 0x400).unwrap()));
        assert!(a.overlaps(&BusRange::new(0xf00, 0x400).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x1000, 0x01).unwrap()));
        assert!(a.overlaps(&BusRange::new(0xfff, 0x02).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x1100, 0x100).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x13ff, 0x100).unwrap()));
        assert!(!a.overlaps(&BusRange::new(0x1400, 0x100).unwrap()));
        assert!(!a.overlaps(&BusRange::new(0xf00, 0x100).unwrap()));
    }
}
