// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The virtio-net device in its fixed slot: slot 2 of
//! [`SLOT_TABLE`](super::slots::SLOT_TABLE), `0xC000_2000` on GSI 7. The
//! device and its net thread are `boxcar_net::device`; this builds it and
//! puts it on the bus.

use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use boxcar_audit::AuditSink;
use boxcar_net::{InspectConfig, NetConfig, Policy, VirtioNet};
use boxcar_virtio::bus::Bus;
use boxcar_virtio::{DeviceContext, MmioSlot, MmioTransport, SlotAllocator, VirtioDevice};
use kvm_ioctls::VmFd;
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use super::slots::{slot, SlotId};
use super::DeviceError;

/// The virtio-net device behind its transport.
pub type NetTransport = MmioTransport<VirtioNet>;

/// What the network card is built from: the stack's config, where it
/// records, the policy it reads, and the gate when the session inspects.
pub struct NetSetup<'a> {
    pub cfg: &'a NetConfig,
    pub audit: &'a AuditSink,
    pub policy: &'a Arc<ArcSwap<Policy>>,
    pub inspect: Option<Arc<InspectConfig>>,
    /// The dump directory, when the run has one.
    pub dump: Option<boxcar_net::DumpDir>,
}

/// The VM's network card, if it has one.
#[derive(Default)]
pub struct NetDevice {
    device: Option<Arc<Mutex<NetTransport>>>,
    /// The device's policy wake (`VirtioNet::policy_wake`).
    policy_wake: Option<EventFd>,
}

impl NetDevice {
    /// With a `setup`, creates the virtio-net device, whose stack records
    /// into its `audit` and reads its `policy` at every decision: its fixed slot
    /// reserved from `slots`, the eventfds and IRQ trigger registered with
    /// KVM (an ioeventfd for each queue on the slot's QueueNotify, the
    /// irqfd on its GSI), and the transport on `mmio` at the slot's base.
    /// Without a setup, there is no device and the slot stays empty.
    pub fn attach(
        vm: &VmFd,
        mem: &Arc<GuestMemoryMmap>,
        mmio: &mut Bus,
        slots: &mut SlotAllocator,
        setup: Option<NetSetup<'_>>,
    ) -> Result<NetDevice, DeviceError> {
        let Some(NetSetup {
            cfg,
            audit,
            policy,
            inspect,
            dump,
        }) = setup
        else {
            return Ok(NetDevice::default());
        };
        let slot = reserve(slots)?;
        let device = VirtioNet::with_dump(
            cfg.clone(),
            audit.clone(),
            Arc::clone(policy),
            inspect,
            dump,
        )
        .map_err(DeviceError::Net)?;
        let policy_wake = device
            .policy_wake()
            .try_clone()
            .map_err(DeviceError::NetWake)?;
        let ctx = DeviceContext::new(slot, device.num_queues()).map_err(DeviceError::NetWiring)?;
        // Before the transport takes the context apart.
        ctx.register(vm).map_err(DeviceError::NetWiring)?;
        let transport = Arc::new(Mutex::new(MmioTransport::new(device, Arc::clone(mem), ctx)));
        mmio.insert(transport.clone(), slot.base, slot.size)?;
        tracing::debug!("virtio-net: slot {:#x}, GSI {}", slot.base, slot.gsi);
        Ok(NetDevice {
            device: Some(transport),
            policy_wake: Some(policy_wake),
        })
    }

    /// Whether the VM has the device.
    pub fn is_attached(&self) -> bool {
        self.device.is_some()
    }

    /// The device's policy wake, to write after a new policy is stored
    /// (see `VirtioNet::policy_wake`); `None` without the device.
    pub fn policy_wake(&self) -> Option<&EventFd> {
        self.policy_wake.as_ref()
    }

    /// Ends the device for good: its net thread stops, which records the
    /// end of every flow, then the gate's observer records what it still
    /// holds and is joined, and the dump's thread too
    /// (`VirtioNet::shutdown`). Called once the vCPUs have stopped, and
    /// before `vmm.stop`, so the observer's last records come before it.
    pub fn close(&self) {
        if let Some(device) = &self.device {
            let mut transport = device.lock().unwrap_or_else(PoisonError::into_inner);
            transport.reset();
            transport.device_mut().shutdown();
        }
    }
}

/// The net device's fixed slot, reserved from `slots`.
fn reserve(slots: &mut SlotAllocator) -> Result<MmioSlot, DeviceError> {
    let fixed = slot(SlotId::Net);
    slots
        .reserve(fixed.base, fixed.gsi)
        .map_err(DeviceError::NetSlot)
}

#[cfg(test)]
mod tests {
    use boxcar_virtio::SlotError;

    use super::*;

    /// The device takes slot 2 and GSI 7 whatever else is attached, and the
    /// slot stays taken.
    #[test]
    fn the_net_device_reserves_slot_2() {
        let mut allocator = SlotAllocator::new().unwrap();
        let net = reserve(&mut allocator).unwrap();
        assert_eq!((net.base, net.size, net.gsi), (0xC000_2000, 0x1000, 7));
        assert!(matches!(
            reserve(&mut allocator),
            Err(DeviceError::NetSlot(SlotError::GsiTaken { gsi: 7 }))
        ));
    }

    #[test]
    fn without_a_config_there_is_no_device() {
        let net = NetDevice::default();
        assert!(!net.is_attached());
        // Nothing to reset.
        net.close();
    }
}
