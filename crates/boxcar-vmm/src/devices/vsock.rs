// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The virtio-vsock device in its fixed slot: slot 3 of
//! [`SLOT_TABLE`](super::slots::SLOT_TABLE), `0xC000_3000` on GSI 8. The
//! device and its vsock thread are `boxcar_vsock::device`; this builds it,
//! with the VMM's [`ServiceRegistry`] behind its internal ports, and puts it
//! on the bus.

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use boxcar_audit::AuditSink;
use boxcar_virtio::bus::Bus;
use boxcar_virtio::{DeviceContext, MmioSlot, MmioTransport, SlotAllocator, VirtioDevice};
use boxcar_vsock::{VirtioVsock, VsockConfig};
use kvm_ioctls::VmFd;
use vm_memory::GuestMemoryMmap;

use super::slots::{slot, SlotId};
use super::DeviceError;
use crate::services::ServiceRegistry;

/// The virtio-vsock device behind its transport.
pub type VsockTransport = MmioTransport<VirtioVsock>;

/// The mode of the directory the socket goes in, when it is created here:
/// the session's state directory, as the control socket's.
const DIR_MODE: u32 = 0o700;

/// The VM's vsock device, if it has one.
#[derive(Default)]
pub struct VsockDevice {
    device: Option<Arc<Mutex<VsockTransport>>>,
}

impl VsockDevice {
    /// With `cfg`, creates the virtio-vsock device, which serves the
    /// internal ports through `services` and records into `audit`: its
    /// fixed slot reserved from `slots`, its host socket bound at
    /// `cfg.uds_path` (mode 0600; the directory is created mode 0700 if it
    /// is missing), the eventfds and IRQ trigger registered with KVM (an
    /// ioeventfd for each queue on the slot's QueueNotify, the irqfd on its
    /// GSI), and the transport on `mmio` at the slot's base. Without
    /// `cfg`, there is no device and the slot stays empty.
    pub fn attach(
        vm: &VmFd,
        mem: &Arc<GuestMemoryMmap>,
        mmio: &mut Bus,
        slots: &mut SlotAllocator,
        cfg: Option<&VsockConfig>,
        audit: &AuditSink,
        services: &Arc<ServiceRegistry>,
    ) -> Result<VsockDevice, DeviceError> {
        let Some(cfg) = cfg else {
            return Ok(VsockDevice::default());
        };
        let fixed = slot(SlotId::Vsock);
        let slot = slots
            .reserve(fixed.base, fixed.gsi)
            .map_err(DeviceError::VsockSlot)?;
        socket_dir(&cfg.uds_path).map_err(|source| DeviceError::VsockDir {
            path: cfg.uds_path.clone(),
            source,
        })?;
        let device = VirtioVsock::new(cfg.clone(), services.clone(), audit.clone())
            .map_err(DeviceError::Vsock)?;
        let ctx: DeviceContext =
            DeviceContext::new(slot, device.num_queues()).map_err(DeviceError::VsockWiring)?;
        // Before the transport takes the context apart.
        ctx.register(vm).map_err(DeviceError::VsockWiring)?;
        let transport = Arc::new(Mutex::new(MmioTransport::new(device, Arc::clone(mem), ctx)));
        mmio.insert(transport.clone(), slot.base, slot.size)?;
        log_slot(&slot, &cfg.uds_path);
        Ok(VsockDevice {
            device: Some(transport),
        })
    }

    /// Whether the VM has the device.
    pub fn is_attached(&self) -> bool {
        self.device.is_some()
    }

    /// Resets the device through its transport, as a driver's status-0
    /// write would: an activated device stops its vsock thread, which
    /// records the end of every connection, and joins it. Then unlinks the
    /// host socket, so that the state directory can go. Called once the
    /// vCPUs have stopped, and before the audit writer is closed.
    pub fn close(&self) {
        if let Some(device) = &self.device {
            let mut transport = device.lock().unwrap_or_else(PoisonError::into_inner);
            transport.reset();
            transport.device_mut().close_socket();
        }
    }
}

/// Creates the directory `uds_path` goes in, mode 0700, unless it exists.
fn socket_dir(uds_path: &Path) -> io::Result<()> {
    match uds_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            DirBuilder::new().recursive(true).mode(DIR_MODE).create(dir)
        }
        _ => Ok(()),
    }
}

fn log_slot(slot: &MmioSlot, uds_path: &Path) {
    tracing::debug!(
        "virtio-vsock: slot {:#x}, GSI {}, socket {}",
        slot.base,
        slot.gsi,
        uds_path.display()
    );
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use boxcar_virtio::SlotError;

    use super::*;

    /// The device takes slot 3 and GSI 8 whatever else is attached, and the
    /// slot stays taken.
    #[test]
    fn the_vsock_slot_is_slot_3() {
        let mut allocator = SlotAllocator::new().unwrap();
        let fixed = slot(SlotId::Vsock);
        let vsock = allocator.reserve(fixed.base, fixed.gsi).unwrap();
        assert_eq!(
            (vsock.base, vsock.size, vsock.gsi),
            (0xC000_3000, 0x1000, 8)
        );
        assert!(matches!(
            allocator.reserve(fixed.base, fixed.gsi),
            Err(SlotError::GsiTaken { gsi: 8 })
        ));
    }

    #[test]
    fn without_a_config_there_is_no_device() {
        let vsock = VsockDevice::default();
        assert!(!vsock.is_attached());
        // Nothing to reset.
        vsock.close();
    }

    #[test]
    fn the_socket_directory_is_made_0700() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("boxcar").join("session");
        socket_dir(&state.join("vsock.sock")).unwrap();
        for made in [&state, &dir.path().join("boxcar")] {
            assert_eq!(
                fs::metadata(made).unwrap().permissions().mode() & 0o777,
                0o700,
                "{}",
                made.display()
            );
        }
        // One that exists is left as it is.
        socket_dir(&state.join("vsock.sock")).unwrap();
        socket_dir(Path::new("vsock.sock")).unwrap();
    }
}
