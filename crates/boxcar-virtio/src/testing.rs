// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// `DummyDevice` is adapted from the test devices of rust-vmm vm-virtio
// (https://github.com/rust-vmm/vm-virtio), virtio-device/src/virtio_config.rs
// (`Dummy`) at tag virtio-queue-v0.17.0, commit
// ec17cad1c79e0525647914b33bd9238f6f509471, and of Firecracker
// (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/devices/virtio/transport/mmio.rs (`DummyDevice`) at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above (THIRD-PARTY in Firecracker's tree) is in LICENSE-BSD-3-Clause.
// Adapted to boxcar's `VirtioDevice` trait; it records every call the
// transport makes so tests can assert on them.

//! Test support: a [`DummyDevice`] and helpers that build an
//! [`MmioTransport`] over plain guest memory, with no KVM.
//!
//! Compiled for this crate's tests and, through the `testing` feature, for
//! other crates' tests (`boxcar-virtio = { ..., features = ["testing"] }` in
//! their `[dev-dependencies]`). Nothing here belongs in a shipped binary.

use std::cell::RefCell;
use std::io;
use std::sync::Arc;

use vm_memory::mmap::FromRangesError;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::bus::BusDevice;
use crate::context::{DeviceContext, MmioSlot};
use crate::device::{ActivateError, ActivatedQueue, VirtioDevice};
use crate::features::{EVENT_IDX, VERSION_1};
use crate::irq::IrqTrigger;
use crate::mmio::MmioTransport;

/// The dummy's virtio device ID; no real device uses it.
pub const DUMMY_DEVICE_TYPE: u32 = 0xffff;
/// The dummy's queue maximum sizes; it has two queues.
pub const DUMMY_QUEUE_MAX_SIZES: [u16; 2] = [256, 128];
/// The dummy's initial config space: 8 bytes, each distinct, so a read at the
/// wrong offset shows.
pub const DUMMY_CONFIG: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
/// The slot [`transport`] puts devices in: slot 0 of the fixed order.
pub const TEST_SLOT: MmioSlot = MmioSlot {
    base: 0xC000_0000,
    size: 0x1000,
    gsi: 5,
};

/// What the dummy was given at activation.
#[derive(Debug)]
pub struct Activation {
    /// Guest memory.
    pub mem: Arc<GuestMemoryMmap>,
    /// The queues and their eventfds, in index order.
    pub queues: Vec<ActivatedQueue>,
    /// The IRQ trigger.
    pub irq: Arc<IrqTrigger>,
    /// The features the driver negotiated.
    pub driver_features: u64,
}

/// A virtio device that does nothing but record what the transport asks of
/// it: device type 0xffff, two queues, an 8-byte config space, and the
/// `VERSION_1 | EVENT_IDX` feature set every boxcar device offers.
#[derive(Debug)]
pub struct DummyDevice {
    /// What `avail_features` returns.
    pub avail_features: u64,
    /// The config space.
    pub config: [u8; 8],
    /// Makes `activate` fail (after counting the call).
    pub fail_activate: bool,
    /// How many times `activate` was called.
    pub activate_calls: usize,
    /// How many times `reset` was called.
    pub reset_calls: usize,
    /// What the last successful `activate` handed over; cleared by `reset`.
    pub activation: Option<Activation>,
    /// `(offset, len)` of every `read_config`.
    pub config_reads: RefCell<Vec<(u64, usize)>>,
    /// `(offset, data)` of every `write_config`.
    pub config_writes: Vec<(u64, Vec<u8>)>,
    /// Every `queue_notify` index.
    pub notifies: Vec<u32>,
}

impl DummyDevice {
    /// A dummy in its initial state.
    pub fn new() -> Self {
        Self {
            avail_features: VERSION_1 | EVENT_IDX,
            config: DUMMY_CONFIG,
            fail_activate: false,
            activate_calls: 0,
            reset_calls: 0,
            activation: None,
            config_reads: RefCell::new(Vec::new()),
            config_writes: Vec::new(),
            notifies: Vec::new(),
        }
    }
}

impl Default for DummyDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for DummyDevice {
    fn device_type(&self) -> u32 {
        DUMMY_DEVICE_TYPE
    }

    fn num_queues(&self) -> usize {
        DUMMY_QUEUE_MAX_SIZES.len()
    }

    fn queue_max_size(&self, idx: usize) -> u16 {
        DUMMY_QUEUE_MAX_SIZES.get(idx).copied().unwrap_or(0)
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.config_reads.borrow_mut().push((offset, data.len()));
        if let Some(src) = config_window(&self.config, offset, data.len()) {
            data[..src.len()].copy_from_slice(src);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.config_writes.push((offset, data.to_vec()));
        let Ok(start) = usize::try_from(offset) else {
            return;
        };
        if let Some(dst) = self.config.get_mut(start..) {
            let n = dst.len().min(data.len());
            dst[..n].copy_from_slice(&data[..n]);
        }
    }

    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        queues: Vec<ActivatedQueue>,
        irq: Arc<IrqTrigger>,
        driver_features: u64,
    ) -> Result<(), ActivateError> {
        self.activate_calls += 1;
        if self.fail_activate {
            return Err(ActivateError::Device("the dummy was told to fail".into()));
        }
        self.activation = Some(Activation {
            mem,
            queues,
            irq,
            driver_features,
        });
        Ok(())
    }

    fn reset(&mut self) {
        self.reset_calls += 1;
        self.activation = None;
    }

    fn queue_notify(&mut self, idx: u32) {
        self.notifies.push(idx);
    }
}

/// The part of `config` a read of `len` bytes at `offset` covers.
fn config_window(config: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let rest = config.get(start..)?;
    Some(&rest[..rest.len().min(len)])
}

/// `size` bytes of anonymous guest memory at guest physical address 0.
pub fn guest_memory(size: usize) -> Result<Arc<GuestMemoryMmap>, FromRangesError> {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).map(Arc::new)
}

/// `device` behind a transport in [`TEST_SLOT`], with a fresh
/// [`DeviceContext`] and no KVM.
pub fn transport<D: VirtioDevice>(
    device: D,
    mem: Arc<GuestMemoryMmap>,
) -> io::Result<MmioTransport<D>> {
    let ctx = DeviceContext::new(TEST_SLOT, device.num_queues())?;
    Ok(MmioTransport::new(device, mem, ctx))
}

/// A 32-bit register read at `offset`, as the guest driver does it.
pub fn read_u32<B: BusDevice + ?Sized>(dev: &mut B, offset: u64) -> u32 {
    let mut data = [0u8; 4];
    dev.read(offset, &mut data);
    u32::from_le_bytes(data)
}

/// A 32-bit register write at `offset`, as the guest driver does it.
pub fn write_u32<B: BusDevice + ?Sized>(dev: &mut B, offset: u64, value: u32) {
    dev.write(offset, &value.to_le_bytes());
}
