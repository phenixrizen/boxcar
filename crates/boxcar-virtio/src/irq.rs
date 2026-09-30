// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from Firecracker (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/devices/virtio/transport/mmio.rs (`IrqTrigger` and its test) at
// commit 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text
// referred to above is in LICENSE-BSD-3-Clause. Adapted: the status is the
// `AtomicU8` the transport's InterruptStatus register reads, the two interrupt
// kinds are two methods instead of an `IrqType`, errors are `io::Error`,
// there are no metrics, and a device can flag DEVICE_NEEDS_RESET through it.

//! The interrupt a virtio-mmio device raises towards the guest.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

use virtio_bindings::virtio_mmio::{VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING};
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

/// InterruptStatus bit 0: the device used buffers in at least one queue.
pub const INT_VRING: u8 = VIRTIO_MMIO_INT_VRING as u8;
/// InterruptStatus bit 1: the device configuration changed.
pub const INT_CONFIG: u8 = VIRTIO_MMIO_INT_CONFIG as u8;

/// Raises a device's interrupt: sets the reason in the InterruptStatus bits
/// and writes the eventfd that KVM's irqfd turns into the guest interrupt.
///
/// `status` and `needs_reset` are shared with the transport: it reads
/// `status` through InterruptStatus and clears acknowledged bits through
/// InterruptACK, and shows `needs_reset` as DEVICE_NEEDS_RESET in the Status
/// register until the driver resets the device.
#[derive(Debug)]
pub struct IrqTrigger {
    /// Registered with KVM as the irqfd for the device's GSI.
    pub evt: EventFd,
    /// The InterruptStatus bits.
    pub status: Arc<AtomicU8>,
    /// Set by [`IrqTrigger::signal_needs_reset`]; cleared by a device reset.
    pub needs_reset: Arc<AtomicBool>,
}

impl IrqTrigger {
    /// A trigger with a fresh non-blocking eventfd and no pending reasons.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            evt: EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)?,
            status: Arc::new(AtomicU8::new(0)),
            needs_reset: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Tells the guest the device used buffers.
    pub fn signal_used_queue(&self) -> io::Result<()> {
        self.signal(INT_VRING)
    }

    /// Tells the guest the device configuration changed.
    pub fn signal_config_change(&self) -> io::Result<()> {
        self.signal(INT_CONFIG)
    }

    /// Tells the guest the device hit an error it cannot recover from: the
    /// Status register shows DEVICE_NEEDS_RESET until the driver resets the
    /// device, and the driver gets a configuration change interrupt (virtio
    /// 1.2 section 2.1.2). A device worker calls this after a fatal error,
    /// such as an `Err` from [`drain_queue`](crate::drain_queue)'s callback.
    /// The request is recorded even if the interrupt cannot be sent.
    pub fn signal_needs_reset(&self) -> io::Result<()> {
        self.needs_reset.store(true, Ordering::SeqCst);
        self.signal(INT_CONFIG)
    }

    fn signal(&self, reason: u8) -> io::Result<()> {
        // The reason is visible before the interrupt can be taken.
        self.status.fetch_or(reason, Ordering::SeqCst);
        self.evt.write(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irq_trigger() {
        let irq = IrqTrigger::new().unwrap();
        assert_eq!(irq.status.load(Ordering::SeqCst), 0);

        // Nothing is pending on a fresh trigger.
        assert_eq!(
            irq.evt.read().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        irq.signal_config_change().unwrap();
        assert_eq!(irq.status.load(Ordering::SeqCst), INT_CONFIG);
        assert_eq!(irq.evt.read().unwrap(), 1);

        irq.status.store(0, Ordering::SeqCst);
        irq.signal_used_queue().unwrap();
        assert_eq!(irq.status.load(Ordering::SeqCst), INT_VRING);
        assert_eq!(irq.evt.read().unwrap(), 1);

        // Reasons accumulate until the driver acknowledges them, and
        // interrupts coalesce in the eventfd counter.
        irq.signal_config_change().unwrap();
        irq.signal_used_queue().unwrap();
        assert_eq!(irq.status.load(Ordering::SeqCst), INT_VRING | INT_CONFIG);
        assert_eq!(irq.evt.read().unwrap(), 2);

        // A full eventfd fails the signal rather than blocking the caller.
        irq.evt.write(u64::MAX - 1).unwrap();
        irq.signal_config_change().unwrap_err();
        irq.signal_used_queue().unwrap_err();
    }

    #[test]
    fn signal_needs_reset_raises_a_config_change() {
        let irq = IrqTrigger::new().unwrap();
        assert!(!irq.needs_reset.load(Ordering::SeqCst));

        irq.signal_needs_reset().unwrap();
        assert!(irq.needs_reset.load(Ordering::SeqCst));
        assert_eq!(irq.status.load(Ordering::SeqCst), INT_CONFIG);
        assert_eq!(irq.evt.read().unwrap(), 1);

        // The request stays set even when the interrupt cannot be sent.
        irq.needs_reset.store(false, Ordering::SeqCst);
        irq.evt.write(u64::MAX - 1).unwrap();
        irq.signal_needs_reset().unwrap_err();
        assert!(irq.needs_reset.load(Ordering::SeqCst));
    }

    #[test]
    fn interrupt_bits_match_the_spec() {
        assert_eq!(INT_VRING, 0x1);
        assert_eq!(INT_CONFIG, 0x2);
    }
}
