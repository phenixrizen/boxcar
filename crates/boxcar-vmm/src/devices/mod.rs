// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The devices the VMM puts on its buses. The legacy PIO devices live in
//! [`legacy`]; the virtio-mmio devices come from `boxcar-virtio`, the
//! virtio-fs shares, [`FsDevices`], from `boxcar-fs`, and the network card,
//! [`NetDevice`], from `boxcar-net`. Where each virtio device sits is fixed
//! by the table in [`slots`].

pub mod legacy;
pub mod net;
pub mod slots;

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use boxcar_audit::AuditSink;
use boxcar_fs::{AuditFsOptions, FsError, FsShareConfig, VirtioFs};
use boxcar_virtio::bus::{Bus, BusError};
use boxcar_virtio::{
    DeviceContext, MmioSlot, MmioTransport, SlotAllocator, SlotError, VirtioDevice,
};
use kvm_ioctls::VmFd;
use vm_memory::GuestMemoryMmap;

use self::slots::{slot, SlotId};

pub use crate::console::ConsoleOut;
pub use legacy::{EventFdTrigger, LegacyDevices, SerialDevice, I8042};
pub use net::NetDevice;

/// The tags of the virtio-fs shares, in slot order: slot 0 (`0xC000_0000`,
/// GSI 5) is the root filesystem, slot 1 (`0xC000_1000`, GSI 6) the
/// workspace. Slot 2 is the network card's ([`NetDevice`]), slot 3 is kept
/// for vsock.
pub const FS_TAGS: [&str; 2] = ["root", "workspace"];

/// The slot of each of the [`FS_TAGS`], in the same order.
const FS_SLOTS: [SlotId; 2] = [SlotId::FsRoot, SlotId::FsWorkspace];

/// Why a device could not be put on the VM.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// There are shares, but not one for each of [`FS_TAGS`].
    #[error("{count} virtio-fs shares; there are none, or root and workspace together")]
    ShareCount { count: usize },
    /// The shares are not [`FS_TAGS`] in order.
    #[error("virtio-fs share {index} is tagged {tag:?}; the shares are root, then workspace")]
    ShareOrder { index: usize, tag: String },
    /// The share cannot be served.
    #[error("cannot serve the virtio-fs share {tag}")]
    Fs {
        tag: String,
        #[source]
        source: FsError,
    },
    /// The share's fixed virtio-mmio slot or GSI could not be reserved.
    #[error("cannot reserve the virtio-mmio slot of the virtio-fs share {tag}")]
    Slot {
        tag: String,
        #[source]
        source: SlotError,
    },
    /// The eventfds could not be created or registered with KVM.
    #[error("cannot wire the virtio-fs share {tag} into KVM")]
    Wiring {
        tag: String,
        #[source]
        source: io::Error,
    },
    /// The network card's stack cannot be built.
    #[error("cannot create the virtio-net device")]
    Net(#[source] boxcar_net::ConfigError),
    /// The network card's fixed slot or GSI could not be reserved.
    #[error("cannot reserve the virtio-mmio slot of the virtio-net device")]
    NetSlot(#[source] SlotError),
    /// The network card's eventfds could not be created or registered with
    /// KVM.
    #[error("cannot wire the virtio-net device into KVM")]
    NetWiring(#[source] io::Error),
    #[error("cannot place a virtio-mmio device on the bus")]
    Bus(#[from] BusError),
}

/// The fixed slot of the device `id`, reserved from `slots`, for the share
/// `tag`.
fn reserve_slot(slots: &mut SlotAllocator, id: SlotId, tag: &str) -> Result<MmioSlot, DeviceError> {
    let fixed = slot(id);
    slots
        .reserve(fixed.base, fixed.gsi)
        .map_err(|source| DeviceError::Slot {
            tag: tag.to_owned(),
            source,
        })
}

/// Checks that `shares` are none, or [`FS_TAGS`] in order: the virtio-fs
/// devices are present together or not at all (see [`slots::DeviceSet`]).
fn check_shares(shares: &[FsShareConfig]) -> Result<(), DeviceError> {
    if !shares.is_empty() && shares.len() != FS_TAGS.len() {
        return Err(DeviceError::ShareCount {
            count: shares.len(),
        });
    }
    for (index, (share, tag)) in shares.iter().zip(FS_TAGS).enumerate() {
        if share.tag != tag {
            return Err(DeviceError::ShareOrder {
                index,
                tag: share.tag.clone(),
            });
        }
    }
    Ok(())
}

/// A virtio-fs device behind its transport.
pub type FsTransport = MmioTransport<VirtioFs>;

/// The virtio-fs devices, in slot order.
#[derive(Default)]
pub struct FsDevices {
    devices: Vec<Arc<Mutex<FsTransport>>>,
}

impl FsDevices {
    /// Creates a device for each share, in order: its fixed slot reserved
    /// from `slots` (see [`slots::SLOT_TABLE`]), the eventfds and IRQ
    /// trigger registered with KVM (an ioeventfd per queue on the slot's
    /// QueueNotify, the irqfd on its GSI), and the transport on `mmio` at
    /// the slot's base. The shares must be none, or tagged as in
    /// [`FS_TAGS`] and in that order, so each lands in its fixed slot.
    pub fn attach(
        vm: &VmFd,
        mem: &Arc<GuestMemoryMmap>,
        mmio: &mut Bus,
        slots: &mut SlotAllocator,
        shares: &[FsShareConfig],
        audit: &AuditSink,
        options: AuditFsOptions,
    ) -> Result<FsDevices, DeviceError> {
        check_shares(shares)?;
        let mut devices = FsDevices::default();
        for (share, id) in shares.iter().zip(FS_SLOTS) {
            let tag = || share.tag.clone();
            let wiring = |source| DeviceError::Wiring { tag: tag(), source };
            let slot = reserve_slot(slots, id, &share.tag)?;
            let device = VirtioFs::new(share.clone(), audit.clone(), options)
                .map_err(|source| DeviceError::Fs { tag: tag(), source })?;
            let ctx = DeviceContext::new(slot, device.num_queues()).map_err(wiring)?;
            // Before the transport takes the context apart.
            ctx.register(vm).map_err(wiring)?;
            let transport = Arc::new(Mutex::new(MmioTransport::new(device, Arc::clone(mem), ctx)));
            mmio.insert(transport.clone(), slot.base, slot.size)?;
            tracing::debug!(
                "virtio-fs {}: slot {:#x}, GSI {}",
                share.tag,
                slot.base,
                slot.gsi
            );
            devices.devices.push(transport);
        }
        Ok(devices)
    }

    /// How many shares have a device.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether there are no shares.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Resets every device through its transport, as a driver's status-0
    /// write would: each activated device stops and joins its workers,
    /// waits for its content hashes, and records the close of every file
    /// the guest left open. A device the guest never activated has nothing
    /// to stop. Called once the vCPUs have stopped, and before the audit
    /// writer is closed.
    pub fn close(&self) {
        for device in &self.devices {
            device
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .reset();
        }
    }
}

#[cfg(test)]
mod tests {
    use boxcar_fs::CachePolicyKind;

    use super::*;

    fn share(tag: &str) -> FsShareConfig {
        FsShareConfig {
            tag: tag.into(),
            host_dir: "/".into(),
            guest_path: "/".into(),
            cache: CachePolicyKind::Auto,
        }
    }

    #[test]
    fn the_shares_are_none_or_root_and_workspace() {
        check_shares(&[]).unwrap();
        check_shares(&[share("root"), share("workspace")]).unwrap();
        for count in [1, 3] {
            let shares = vec![share("root"); count];
            assert!(
                matches!(check_shares(&shares), Err(DeviceError::ShareCount { count: c }) if c == count),
                "{count}"
            );
        }
        assert!(matches!(
            check_shares(&[share("workspace"), share("root")]),
            Err(DeviceError::ShareOrder { index: 0, .. })
        ));
        assert!(matches!(
            check_shares(&[share("root"), share("other")]),
            Err(DeviceError::ShareOrder { index: 1, .. })
        ));
    }

    /// Each share takes the slot and GSI the table gives its device, and the
    /// slots stay taken, so a second claim on one is an error.
    #[test]
    fn the_fs_devices_reserve_their_fixed_slots() {
        let mut allocator = SlotAllocator::new().unwrap();
        let root = reserve_slot(&mut allocator, FS_SLOTS[0], "root").unwrap();
        let workspace = reserve_slot(&mut allocator, FS_SLOTS[1], "workspace").unwrap();
        assert_eq!((root.base, root.gsi), (0xC000_0000, 5));
        assert_eq!((workspace.base, workspace.gsi), (0xC000_1000, 6));
        match reserve_slot(&mut allocator, FS_SLOTS[0], "root") {
            Err(DeviceError::Slot {
                tag,
                source: SlotError::GsiTaken { gsi: 5 },
            }) => assert_eq!(tag, "root"),
            other => panic!("{other:?}"),
        }
    }
}
