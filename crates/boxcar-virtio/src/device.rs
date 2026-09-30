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
// Derived from rust-vmm vm-virtio (https://github.com/rust-vmm/vm-virtio),
// virtio-device/src/lib.rs (the `VirtioDevice` trait) at tag
// virtio-queue-v0.17.0, commit ec17cad1c79e0525647914b33bd9238f6f509471. The
// BSD-3-Clause text referred to above is in LICENSE-BSD-3-Clause. Rewritten:
// the transport owns features, status and queue configuration (see
// `VirtioConfig`), so the device trait shrinks to identity, queue sizes,
// config space, and `activate`/`reset`, and activation hands the device its
// queues, their eventfds and the IRQ trigger.

//! The interface every boxcar virtio device implements.

use std::io;
use std::sync::Arc;

use virtio_queue::Queue;
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use crate::irq::IrqTrigger;

/// One queue as the device receives it at activation: the ring configuration
/// the driver programmed, and the eventfd the guest's QueueNotify writes for
/// this queue signal (through KVM's ioeventfd).
#[derive(Debug)]
pub struct ActivatedQueue {
    /// The queue, with `event_idx` enabled when the driver negotiated
    /// `VIRTIO_RING_F_EVENT_IDX`.
    pub queue: Queue,
    /// Becomes readable when the driver notifies this queue.
    pub evt: EventFd,
}

/// Why a device could not be activated. The transport then sets
/// DEVICE_NEEDS_RESET and the driver has to reset the device.
#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    /// Queue `index` could not be handed to the device (the transport could
    /// not rebuild it from the driver's configuration).
    #[error("queue {index}: {source}")]
    Queue {
        /// The queue.
        index: usize,
        /// What was wrong with its configuration.
        #[source]
        source: virtio_queue::Error,
    },
    /// Queue `index` has no notification eventfd.
    #[error("queue {0} has no notification eventfd")]
    MissingQueueEvent(usize),
    /// An eventfd could not be duplicated, a worker could not be spawned, or
    /// other I/O failed.
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    /// A device-specific failure.
    #[error("device: {0}")]
    Device(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A virtio device behind a transport.
///
/// The transport handles feature negotiation, the status state machine and
/// the queue registers; the device describes itself, serves its config
/// space, and runs its queues once activated.
pub trait VirtioDevice: Send {
    /// The virtio device ID (virtio 1.2 section 5), e.g. 26 for virtio-fs.
    fn device_type(&self) -> u32;

    /// How many queues the device has.
    fn num_queues(&self) -> usize;

    /// The largest size queue `idx` accepts; what QueueNumMax reads. It must
    /// be a power of two no larger than 32768; a queue with an invalid
    /// maximum reads as absent (QueueNumMax 0).
    fn queue_max_size(&self, idx: usize) -> u16;

    /// The features the device offers. Must include `VIRTIO_F_VERSION_1`
    /// (bit 32) and `VIRTIO_RING_F_EVENT_IDX` (bit 29); see
    /// [`features`](crate::features).
    fn avail_features(&self) -> u64;

    /// Reads `data.len()` bytes of the device config space at `offset`.
    /// Bytes past the end of the config space are left untouched.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes `data` into the device config space at `offset`. Bytes past
    /// the end of the config space are dropped.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Called once, on the vCPU thread, when DRIVER_OK is set. Must only hand
    /// the queues to a worker and return.
    ///
    /// `queues` holds every queue in index order, including any the driver
    /// did not mark ready. On `Err` the device must be left as if `activate`
    /// had not been called: the transport treats it as not activated and
    /// will not call [`reset`](VirtioDevice::reset) for it.
    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        queues: Vec<ActivatedQueue>,
        irq: Arc<IrqTrigger>,
        driver_features: u64,
    ) -> Result<(), ActivateError>;

    /// Called on a status-0 write. Must be a no-op when the device is not
    /// activated. After it returns the device must no longer touch guest
    /// memory or raise interrupts, and must accept a new `activate`.
    fn reset(&mut self);

    /// The driver wrote `idx` to QueueNotify. Only reached when no ioeventfd
    /// is registered for the slot (with one, KVM signals the queue's eventfd
    /// and the write never exits to the VMM).
    fn queue_notify(&mut self, _idx: u32) {}
}
