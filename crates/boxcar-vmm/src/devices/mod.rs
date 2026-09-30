// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The devices the VMM puts on its buses. The legacy PIO devices live in
//! [`legacy`]; the virtio-mmio devices come from `boxcar-virtio`, and the
//! virtio-fs shares, [`FsDevices`], from `boxcar-fs`.

pub mod legacy;

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

use crate::cmdline::MmioDeviceEntry;

pub use legacy::{ConsoleOut, EventFdTrigger, LegacyDevices, SerialDevice, I8042};

/// The tags of the virtio-fs shares, in slot order: slot 0 (`0xC000_0000`,
/// GSI 5) is the root filesystem, slot 1 (`0xC000_1000`, GSI 6) the
/// workspace. Slots 2 and 3 are kept for net and vsock.
pub const FS_TAGS: [&str; 2] = ["root", "workspace"];

/// Why a device could not be put on the VM.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// The shares are not a prefix of [`FS_TAGS`].
    #[error("virtio-fs share {index} is tagged {tag:?}; the shares are root, then workspace")]
    ShareOrder { index: usize, tag: String },
    /// The share cannot be served.
    #[error("cannot serve the virtio-fs share {tag}")]
    Fs {
        tag: String,
        #[source]
        source: FsError,
    },
    /// No virtio-mmio slot was left.
    #[error("no virtio-mmio slot for the virtio-fs share {tag}")]
    Slot {
        tag: String,
        #[source]
        source: SlotError,
    },
    /// The slot is too large for the kernel command line.
    #[error("the virtio-mmio slot of {size:#x} bytes for {tag} does not fit the command line")]
    SlotSize { tag: String, size: u64 },
    /// The eventfds could not be created or registered with KVM.
    #[error("cannot wire the virtio-fs share {tag} into KVM")]
    Wiring {
        tag: String,
        #[source]
        source: io::Error,
    },
    #[error("cannot place a virtio-mmio device on the bus")]
    Bus(#[from] BusError),
}

/// The next slot from `slots`, for the share `tag`, and its command line
/// entry.
fn next_slot(
    slots: &mut SlotAllocator,
    tag: &str,
) -> Result<(MmioSlot, MmioDeviceEntry), DeviceError> {
    let slot = slots.alloc().map_err(|source| DeviceError::Slot {
        tag: tag.to_owned(),
        source,
    })?;
    let size = u32::try_from(slot.size).map_err(|_| DeviceError::SlotSize {
        tag: tag.to_owned(),
        size: slot.size,
    })?;
    let entry = MmioDeviceEntry {
        size,
        base: slot.base,
        gsi: slot.gsi,
    };
    Ok((slot, entry))
}

/// A virtio-fs device behind its transport.
pub type FsTransport = MmioTransport<VirtioFs>;

/// The virtio-fs devices, in slot order, and their command line entries.
#[derive(Default)]
pub struct FsDevices {
    devices: Vec<Arc<Mutex<FsTransport>>>,
    entries: Vec<MmioDeviceEntry>,
}

impl FsDevices {
    /// Creates a device for each share, in order: a slot from `slots`, the
    /// eventfds and IRQ trigger registered with KVM (an ioeventfd per queue
    /// on the slot's QueueNotify, the irqfd on its GSI), and the transport
    /// on `mmio` at the slot's base. The shares must be tagged as in
    /// [`FS_TAGS`], in that order, so each always lands in its fixed slot.
    pub fn attach(
        vm: &VmFd,
        mem: &Arc<GuestMemoryMmap>,
        mmio: &mut Bus,
        slots: &mut SlotAllocator,
        shares: &[FsShareConfig],
        audit: &AuditSink,
        options: AuditFsOptions,
    ) -> Result<FsDevices, DeviceError> {
        for (index, share) in shares.iter().enumerate() {
            if FS_TAGS.get(index) != Some(&share.tag.as_str()) {
                return Err(DeviceError::ShareOrder {
                    index,
                    tag: share.tag.clone(),
                });
            }
        }
        let mut devices = FsDevices::default();
        for share in shares {
            let tag = || share.tag.clone();
            let wiring = |source| DeviceError::Wiring { tag: tag(), source };
            let (slot, entry) = next_slot(slots, &share.tag)?;
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
            devices.entries.push(entry);
            devices.devices.push(transport);
        }
        Ok(devices)
    }

    /// The command line entries [`FsDevices::attach`] announces for shares
    /// tagged `tags`, in order, from the slots it would take from `slots`,
    /// without creating a device.
    pub fn cmdline_entries_for(
        slots: &mut SlotAllocator,
        tags: &[&str],
    ) -> Result<Vec<MmioDeviceEntry>, DeviceError> {
        tags.iter()
            .map(|tag| next_slot(slots, tag).map(|(_, entry)| entry))
            .collect()
    }

    /// One `virtio_mmio.device=` entry per device, in slot order.
    pub fn cmdline_entries(&self) -> &[MmioDeviceEntry] {
        &self.entries
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
