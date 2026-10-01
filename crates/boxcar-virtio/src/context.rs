// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What a virtio-mmio device needs from the VM: its MMIO slot and GSI, the
//! IRQ trigger, one notification eventfd per queue, and a kill eventfd, plus
//! the KVM wiring that connects them.

use std::io;
use std::sync::Arc;

use kvm_ioctls::{IoEventAddress, VmFd};
use vmm_sys_util::eventfd::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK};

use crate::irq::IrqTrigger;
use crate::mmio::regs;

/// Where a virtio-mmio device lives: `size` bytes of MMIO at `base`, and the
/// GSI its interrupt is routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioSlot {
    /// First guest physical address of the slot.
    pub base: u64,
    /// Length of the slot in bytes.
    pub size: u64,
    /// The interrupt line.
    pub gsi: u32,
}

/// The eventfds and IRQ trigger of one device, created before the device is
/// wrapped in its transport.
///
/// [`DeviceContext::new`] needs no VM, so tests can build a whole transport
/// over plain guest memory; only [`DeviceContext::register`] talks to KVM.
#[derive(Debug)]
pub struct DeviceContext {
    /// The device's MMIO slot and GSI.
    pub slot: MmioSlot,
    /// The interrupt the device raises; registered as the GSI's irqfd.
    pub irq: Arc<IrqTrigger>,
    /// One eventfd per queue, signalled when the guest writes that queue's
    /// index to QueueNotify.
    pub queue_evts: Vec<EventFd>,
    /// Written at shutdown to stop the device's workers.
    pub kill_evt: EventFd,
}

impl DeviceContext {
    /// Fresh non-blocking eventfds for a device with `num_queues` queues in
    /// `slot`.
    pub fn new(slot: MmioSlot, num_queues: usize) -> io::Result<Self> {
        let queue_evts = (0..num_queues)
            .map(|_| new_eventfd())
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            slot,
            irq: Arc::new(IrqTrigger::new()?),
            queue_evts,
            kill_evt: new_eventfd()?,
        })
    }

    /// Wires the device into KVM: for each queue an ioeventfd on the slot's
    /// QueueNotify register that fires only for that queue's index (so the
    /// notification never exits to the VMM), and the IRQ trigger's eventfd
    /// as the irqfd of the slot's GSI.
    pub fn register(&self, vm: &VmFd) -> io::Result<()> {
        let notify = self
            .slot
            .base
            .checked_add(regs::QUEUE_NOTIFY)
            .ok_or_else(|| invalid("the slot's QueueNotify address overflows"))?;
        for (index, evt) in self.queue_evts.iter().enumerate() {
            // A 4-byte datamatch: the guest writes the queue index as a u32.
            let datamatch =
                u32::try_from(index).map_err(|_| invalid("queue index does not fit in u32"))?;
            vm.register_ioevent(evt, &IoEventAddress::Mmio(notify), datamatch)?;
        }
        vm.register_irqfd(&self.irq.evt, self.slot.gsi)?;
        Ok(())
    }
}

fn new_eventfd() -> io::Result<EventFd> {
    EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: MmioSlot = MmioSlot {
        base: 0xC000_0000,
        size: 0x1000,
        gsi: 5,
    };

    #[test]
    fn new_needs_no_vm() {
        let ctx = DeviceContext::new(SLOT, 3).unwrap();
        assert_eq!(ctx.slot, SLOT);
        assert_eq!(ctx.queue_evts.len(), 3);

        // Every eventfd is distinct and non-blocking: nothing is pending, and
        // a write to one shows up only on that one.
        for evt in ctx.queue_evts.iter().chain([&ctx.kill_evt, &ctx.irq.evt]) {
            assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        ctx.queue_evts[1].write(1).unwrap();
        assert_eq!(
            ctx.queue_evts[0].read().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(ctx.queue_evts[1].read().unwrap(), 1);
        assert_eq!(
            ctx.queue_evts[2].read().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn a_device_without_queues_still_gets_an_irq_and_kill_evt() {
        let ctx = DeviceContext::new(SLOT, 0).unwrap();
        assert!(ctx.queue_evts.is_empty());
        ctx.kill_evt.write(1).unwrap();
        assert_eq!(ctx.kill_evt.read().unwrap(), 1);
    }
}
