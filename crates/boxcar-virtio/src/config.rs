// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from rust-vmm vm-virtio (https://github.com/rust-vmm/vm-virtio),
// virtio-device/src/virtio_config.rs (`VirtioConfig`, `set_driver_features`)
// and virtio-device/src/lib.rs (the `status` module) at tag
// virtio-queue-v0.17.0, commit ec17cad1c79e0525647914b33bd9238f6f509471. The
// BSD-3-Clause text referred to above is in LICENSE-BSD-3-Clause. Adapted: one
// concrete struct over `virtio_queue::Queue` instead of the generic
// `VirtioConfig<Q>` and its blanket trait impls; it also holds the queue
// eventfds and the activation flag, has no config space (devices own theirs),
// and knows how to return itself to the reset state.

//! Transport-side virtio state: negotiated features, selectors, device
//! status, interrupt status, and the queues as the driver configured them.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use virtio_queue::{Queue, QueueT};
use vmm_sys_util::eventfd::EventFd;

/// Device Status bits (virtio 1.2 section 2.1), in the order a driver
/// normally sets them. Writing 0 resets the device.
pub mod status {
    /// The guest found the device and recognised it as a virtio device.
    pub const ACKNOWLEDGE: u8 = 1;
    /// The guest knows how to drive the device.
    pub const DRIVER: u8 = 2;
    /// The driver is set up and ready to drive the device.
    pub const DRIVER_OK: u8 = 4;
    /// The driver has acknowledged the features it understands; feature
    /// negotiation is complete.
    pub const FEATURES_OK: u8 = 8;
    /// The device hit an error it cannot recover from without a reset.
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    /// The guest gave up on the device.
    pub const FAILED: u8 = 128;
}

/// Everything the transport tracks for one device. The fields are public so
/// tests and diagnostics can inspect them; only the transport changes them.
#[derive(Debug)]
pub struct VirtioConfig {
    /// Features the device offers.
    pub device_features: u64,
    /// Features the driver accepted.
    pub driver_features: u64,
    /// Which 32-bit page DeviceFeatures reads.
    pub device_features_select: u32,
    /// Which 32-bit page DriverFeatures writes.
    pub driver_features_select: u32,
    /// The queue the queue registers address.
    pub queue_select: u32,
    /// The Device Status register.
    pub device_status: u8,
    /// The InterruptStatus bits, shared with the device's `IrqTrigger`.
    pub interrupt_status: Arc<AtomicU8>,
    /// ConfigGeneration. It is never reset, so it only moves forward.
    pub config_generation: u32,
    /// The queues as the driver configured them. At activation the device
    /// gets a copy of each; these stay behind for the registers to read.
    pub queues: Vec<Queue>,
    /// One notification eventfd per queue, in queue order.
    pub queue_evts: Vec<EventFd>,
    /// Whether the device has been activated since the last reset.
    pub activated: bool,
}

impl VirtioConfig {
    /// The state after a reset, offering `device_features`.
    pub fn new(
        device_features: u64,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt_status: Arc<AtomicU8>,
    ) -> Self {
        VirtioConfig {
            device_features,
            driver_features: 0,
            device_features_select: 0,
            driver_features_select: 0,
            queue_select: 0,
            device_status: 0,
            interrupt_status,
            config_generation: 0,
            queues,
            queue_evts,
            activated: false,
        }
    }

    /// Page `page` of the device features; zero past page 1.
    pub fn device_features_page(&self, page: u32) -> u32 {
        match page {
            0 => self.device_features as u32,
            1 => (self.device_features >> 32) as u32,
            _ => 0,
        }
    }

    /// Stores `value` as page `page` of the driver features. Pages past 1
    /// are ignored.
    pub fn set_driver_features_page(&mut self, page: u32, value: u32) {
        let v = u64::from(value);
        self.driver_features = match page {
            0 => (self.driver_features & !0xffff_ffff) | v,
            1 => (self.driver_features & 0xffff_ffff) | (v << 32),
            _ => self.driver_features,
        };
    }

    /// The queue QueueSel points at, if it exists.
    pub fn selected_queue(&self) -> Option<&Queue> {
        usize::try_from(self.queue_select)
            .ok()
            .and_then(|i| self.queues.get(i))
    }

    /// The queue QueueSel points at, if it exists.
    pub fn selected_queue_mut(&mut self) -> Option<&mut Queue> {
        usize::try_from(self.queue_select)
            .ok()
            .and_then(|i| self.queues.get_mut(i))
    }

    /// Back to the state after [`VirtioConfig::new`]: features, selectors,
    /// status, interrupt status and every queue cleared, not activated. The
    /// offered features, the queue eventfds and ConfigGeneration are kept.
    pub fn reset(&mut self) {
        self.driver_features = 0;
        self.device_features_select = 0;
        self.driver_features_select = 0;
        self.queue_select = 0;
        self.device_status = 0;
        self.interrupt_status.store(0, Ordering::SeqCst);
        self.queues.iter_mut().for_each(QueueT::reset);
        self.activated = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> VirtioConfig {
        let queues = vec![Queue::new(256).unwrap(), Queue::new(16).unwrap()];
        VirtioConfig::new(
            (3 << 32) | 7,
            queues,
            Vec::new(),
            Arc::new(AtomicU8::new(0)),
        )
    }

    #[test]
    fn feature_pages() {
        let mut c = config();
        assert_eq!(c.device_features_page(0), 7);
        assert_eq!(c.device_features_page(1), 3);
        assert_eq!(c.device_features_page(2), 0);

        // From rust-vmm's `test_impls`.
        assert_eq!(c.driver_features, 0);
        c.set_driver_features_page(0, 1);
        assert_eq!(c.driver_features, 1);
        c.set_driver_features_page(1, 1);
        assert_eq!(c.driver_features, (1 << 32) + 1);
        c.set_driver_features_page(2, 1);
        assert_eq!(c.driver_features, (1 << 32) + 1);
        c.set_driver_features_page(0, 0);
        assert_eq!(c.driver_features, 1 << 32);
    }

    #[test]
    fn queue_selection() {
        let mut c = config();
        assert_eq!(c.selected_queue().map(QueueT::max_size), Some(256));
        c.queue_select = 1;
        assert_eq!(c.selected_queue_mut().map(|q| q.max_size()), Some(16));
        c.queue_select = 2;
        assert!(c.selected_queue().is_none());
        assert!(c.selected_queue_mut().is_none());
        c.queue_select = u32::MAX;
        assert!(c.selected_queue().is_none());
    }

    #[test]
    fn reset_keeps_offered_features_and_config_generation() {
        let mut c = config();
        c.driver_features = 5;
        c.device_features_select = 1;
        c.driver_features_select = 1;
        c.queue_select = 1;
        c.device_status = status::ACKNOWLEDGE | status::DRIVER;
        c.interrupt_status.store(3, Ordering::SeqCst);
        c.config_generation = 4;
        c.queues[0].set_size(32);
        c.queues[0].set_ready(true);
        c.queues[0].set_event_idx(true);
        c.activated = true;

        c.reset();
        assert_eq!(c.device_features, (3 << 32) | 7);
        assert_eq!(c.driver_features, 0);
        assert_eq!(c.device_features_select, 0);
        assert_eq!(c.driver_features_select, 0);
        assert_eq!(c.queue_select, 0);
        assert_eq!(c.device_status, 0);
        assert_eq!(c.interrupt_status.load(Ordering::SeqCst), 0);
        assert_eq!(c.config_generation, 4);
        assert_eq!(c.queues[0].size(), 256);
        assert!(!c.queues[0].ready());
        assert!(!c.queues[0].event_idx_enabled());
        assert!(!c.activated);
    }
}
