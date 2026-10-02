// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! boxcar's virtio device layer: the [`VirtioDevice`] trait every device
//! implements, the virtio-mmio transport the guest's `virtio_mmio` driver
//! talks to, the IRQ trigger, MMIO slot and GSI allocation, the queue-drain
//! helper, the PIO/MMIO [`Bus`] the VMM dispatches exits on, and
//! [`limited!`], which keeps a guest from flooding the host's log.
//!
//! Ring handling is `virtio-queue`'s ([`virtio_queue::Queue`]); constants are
//! `virtio-bindings`'.

pub mod bus;
pub mod config;
pub mod context;
pub mod device;
pub mod features;
pub mod irq;
pub mod mmio;
pub mod queue;
pub mod ratelimit;
pub mod slots;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use bus::{Bus, BusDevice, BusError, BusRange, SharedBusDevice};
pub use config::{status, VirtioConfig};
pub use context::{DeviceContext, MmioSlot};
pub use device::{ActivateError, ActivatedQueue, VirtioDevice};
pub use irq::IrqTrigger;
pub use mmio::MmioTransport;
pub use queue::{drain_queue, drain_queue_until};
pub use slots::{SlotAllocator, SlotError};
