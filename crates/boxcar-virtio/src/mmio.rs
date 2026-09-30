// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
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
// Seeded from two sources:
//   - rust-vmm vm-virtio (https://github.com/rust-vmm/vm-virtio),
//     virtio-device/src/mmio.rs (register decoding) and
//     virtio-device/src/lib.rs (`ack_device_status`) at tag
//     virtio-queue-v0.17.0, commit ec17cad1c79e0525647914b33bd9238f6f509471;
//   - Firecracker (https://github.com/firecracker-microvm/firecracker),
//     src/vmm/src/devices/virtio/transport/mmio.rs (`MmioTransport`, its
//     status state machine and activation) at commit
//     21f19ed8109578108568c8a8f3623ddb6f097878.
// The BSD-3-Clause text referred to above (THIRD-PARTY in Firecracker's tree)
// is in LICENSE-BSD-3-Clause. Adapted: generic over one owned `VirtioDevice`
// (no `Arc<Mutex<dyn VirtioDevice>>`, no vhost-user), the transport owns the
// queues and features in a `VirtioConfig`, activation hands the device copies
// of the configured queues with their eventfds, FEATURES_OK is refused for
// unoffered features (rust-vmm), QueueNum is bounded by the queue maximum,
// InterruptACK is honoured in any state, and the address registers read back.

//! The virtio-mmio transport (virtio 1.2 section 4.2.2, version 2): the
//! register map the guest's `virtio_mmio` driver talks to, in front of one
//! [`VirtioDevice`].

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::{error, warn};
use virtio_queue::{Queue, QueueT};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use crate::bus::BusDevice;
use crate::config::{status, VirtioConfig};
use crate::context::{DeviceContext, MmioSlot};
use crate::device::{ActivateError, ActivatedQueue, VirtioDevice};
use crate::features::{EVENT_IDX, VERSION_1};
use crate::irq::IrqTrigger;

/// MagicValue: "virt" in little endian.
pub const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
/// Version: 2, the non-legacy virtio-mmio interface.
pub const MMIO_VERSION: u32 = 2;
/// VendorID. The spec assigns none to MMIO devices; 0 as in crosvm and
/// Firecracker.
pub const VENDOR_ID: u32 = 0;
/// The size of one virtio-mmio slot: registers and device config space.
pub const MMIO_SLOT_SIZE: u64 = 0x1000;

/// Register offsets from the start of a slot (virtio 1.2 section 4.2.2).
/// Every register below [`regs::CONFIG`] is 32 bits wide and accessed as such.
pub mod regs {
    /// R: 0x74726976.
    pub const MAGIC_VALUE: u64 = 0x000;
    /// R: 2.
    pub const VERSION: u64 = 0x004;
    /// R: the virtio device ID.
    pub const DEVICE_ID: u64 = 0x008;
    /// R: the vendor ID.
    pub const VENDOR_ID: u64 = 0x00c;
    /// R: 32 feature bits, from the page DeviceFeaturesSel picks.
    pub const DEVICE_FEATURES: u64 = 0x010;
    /// W: the page DeviceFeatures reads.
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    /// W: 32 accepted feature bits, into the page DriverFeaturesSel picks.
    pub const DRIVER_FEATURES: u64 = 0x020;
    /// W: the page DriverFeatures writes.
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    /// W: the queue the queue registers address.
    pub const QUEUE_SEL: u64 = 0x030;
    /// R: the selected queue's maximum size; 0 if it does not exist.
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    /// W: the selected queue's size.
    pub const QUEUE_NUM: u64 = 0x038;
    /// RW: the selected queue is ready.
    pub const QUEUE_READY: u64 = 0x044;
    /// W: the index of a queue with new buffers.
    pub const QUEUE_NOTIFY: u64 = 0x050;
    /// R: why the device interrupted.
    pub const INTERRUPT_STATUS: u64 = 0x060;
    /// W: the InterruptStatus bits the driver handled.
    pub const INTERRUPT_ACK: u64 = 0x064;
    /// RW: Device Status.
    pub const STATUS: u64 = 0x070;
    /// W: descriptor table address, low 32 bits.
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    /// W: descriptor table address, high 32 bits.
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    /// W: driver (available) ring address, low 32 bits.
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    /// W: driver (available) ring address, high 32 bits.
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    /// W: device (used) ring address, low 32 bits.
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    /// W: device (used) ring address, high 32 bits.
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    /// R: changes whenever the device config space changes.
    pub const CONFIG_GENERATION: u64 = 0x0fc;
    /// RW: the device config space starts here, any access width.
    pub const CONFIG: u64 = 0x100;
}

/// The last byte of the register block.
const REGS_END: u64 = regs::CONFIG - 1;
/// The last byte of the device config space.
const CONFIG_END: u64 = MMIO_SLOT_SIZE - 1;

const ACK_DRIVER: u8 = status::ACKNOWLEDGE | status::DRIVER;
const ACK_DRIVER_FEATURES: u8 = ACK_DRIVER | status::FEATURES_OK;
const ALL_OK: u8 = ACK_DRIVER_FEATURES | status::DRIVER_OK;

/// A virtio device behind the virtio-mmio register map. Inserted straight
/// into the MMIO [`Bus`](crate::Bus) at its slot.
///
/// This needs three things wired up to work in a VM (see
/// [`DeviceContext::register`]): MMIO accesses to the slot routed here,
/// each queue's eventfd registered as an ioeventfd on QueueNotify with the
/// queue index as datamatch, and the IRQ trigger's eventfd registered as the
/// irqfd of the slot's GSI.
pub struct MmioTransport<D: VirtioDevice> {
    device: D,
    mem: Arc<GuestMemoryMmap>,
    cfg: VirtioConfig,
    irq: Arc<IrqTrigger>,
    slot: MmioSlot,
    kill_evt: EventFd,
}

impl<D: VirtioDevice> MmioTransport<D> {
    /// Puts `device` behind the register map, in the state after a reset.
    ///
    /// A queue whose [`VirtioDevice::queue_max_size`] is not a valid queue
    /// size reads as absent (QueueNumMax 0), and a queue without an eventfd
    /// in `ctx` fails activation; both are logged here.
    pub fn new(device: D, mem: Arc<GuestMemoryMmap>, ctx: DeviceContext) -> Self {
        let DeviceContext {
            slot,
            irq,
            queue_evts,
            kill_evt,
        } = ctx;

        let queues: Vec<Queue> = (0..device.num_queues())
            .map(|idx| {
                let max = device.queue_max_size(idx);
                Queue::new(max).unwrap_or_else(|err| {
                    error!(
                        "virtio-mmio {:#x}: queue {idx} has invalid maximum size {max} ({err}); \
                         it will read as absent",
                        slot.base
                    );
                    Queue::default()
                })
            })
            .collect();
        if queue_evts.len() != queues.len() {
            error!(
                "virtio-mmio {:#x}: {} queues but {} queue eventfds",
                slot.base,
                queues.len(),
                queue_evts.len()
            );
        }
        let features = device.avail_features();
        if features & VERSION_1 == 0 {
            warn!(
                "virtio-mmio {:#x}: device does not offer VIRTIO_F_VERSION_1; \
                 the guest driver will refuse it",
                slot.base
            );
        }

        let cfg = VirtioConfig::new(features, queues, queue_evts, irq.status.clone());
        Self {
            device,
            mem,
            cfg,
            irq,
            slot,
            kill_evt,
        }
    }

    /// The device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// The device, mutably.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// The transport state: features, selectors, status and queues.
    pub fn config(&self) -> &VirtioConfig {
        &self.cfg
    }

    /// The kill eventfd from the device's context, for the shutdown path.
    pub fn kill_evt(&self) -> &EventFd {
        &self.kill_evt
    }

    fn check_status(&self, set: u8, clear: u8) -> bool {
        self.cfg.device_status & (set | clear) == set
    }

    fn read_register(&self, offset: u64) -> Option<u32> {
        let queue = self.cfg.selected_queue();
        let v = match offset {
            regs::MAGIC_VALUE => MMIO_MAGIC_VALUE,
            regs::VERSION => MMIO_VERSION,
            regs::DEVICE_ID => self.device.device_type(),
            regs::VENDOR_ID => VENDOR_ID,
            regs::DEVICE_FEATURES => self
                .cfg
                .device_features_page(self.cfg.device_features_select),
            // The queue was built with `device.queue_max_size(idx)`, so this
            // is that value, or 0 when the device gave an invalid maximum.
            regs::QUEUE_NUM_MAX => queue.map_or(0, |q| u32::from(q.max_size())),
            regs::QUEUE_NUM => queue.map_or(0, |q| u32::from(q.size())),
            regs::QUEUE_READY => queue.map_or(0, |q| u32::from(q.ready())),
            regs::INTERRUPT_STATUS => u32::from(self.cfg.interrupt_status.load(Ordering::SeqCst)),
            regs::STATUS => u32::from(self.cfg.device_status),
            // Write-only in the spec; the stored halves are returned.
            regs::QUEUE_DESC_LOW => queue.map_or(0, |q| low(q.desc_table())),
            regs::QUEUE_DESC_HIGH => queue.map_or(0, |q| high(q.desc_table())),
            regs::QUEUE_DRIVER_LOW => queue.map_or(0, |q| low(q.avail_ring())),
            regs::QUEUE_DRIVER_HIGH => queue.map_or(0, |q| high(q.avail_ring())),
            regs::QUEUE_DEVICE_LOW => queue.map_or(0, |q| low(q.used_ring())),
            regs::QUEUE_DEVICE_HIGH => queue.map_or(0, |q| high(q.used_ring())),
            regs::CONFIG_GENERATION => self.cfg.config_generation,
            _ => return None,
        };
        Some(v)
    }

    fn write_register(&mut self, offset: u64, v: u32) {
        match offset {
            regs::DEVICE_FEATURES_SEL => self.cfg.device_features_select = v,
            regs::DRIVER_FEATURES => {
                if self.check_status(
                    status::DRIVER,
                    status::FEATURES_OK | status::FAILED | status::DEVICE_NEEDS_RESET,
                ) {
                    self.cfg
                        .set_driver_features_page(self.cfg.driver_features_select, v);
                } else {
                    warn!(
                        "virtio-mmio {:#x}: driver features written in status {:#x}",
                        self.slot.base, self.cfg.device_status
                    );
                }
            }
            regs::DRIVER_FEATURES_SEL => self.cfg.driver_features_select = v,
            regs::QUEUE_SEL => self.cfg.queue_select = v,
            regs::QUEUE_NUM => {
                let base = self.slot.base;
                self.update_queue(|q| set_queue_size(base, q, v));
            }
            regs::QUEUE_READY => self.update_queue(|q| q.set_ready(v == 1)),
            regs::QUEUE_NOTIFY => self.device.queue_notify(v),
            regs::INTERRUPT_ACK => {
                // Only the low byte holds InterruptStatus bits.
                let ack = (v & 0xff) as u8;
                self.cfg.interrupt_status.fetch_and(!ack, Ordering::SeqCst);
            }
            regs::STATUS => self.write_status(v),
            regs::QUEUE_DESC_LOW => self.update_queue(|q| q.set_desc_table_address(Some(v), None)),
            regs::QUEUE_DESC_HIGH => self.update_queue(|q| q.set_desc_table_address(None, Some(v))),
            regs::QUEUE_DRIVER_LOW => {
                self.update_queue(|q| q.set_avail_ring_address(Some(v), None))
            }
            regs::QUEUE_DRIVER_HIGH => {
                self.update_queue(|q| q.set_avail_ring_address(None, Some(v)))
            }
            regs::QUEUE_DEVICE_LOW => self.update_queue(|q| q.set_used_ring_address(Some(v), None)),
            regs::QUEUE_DEVICE_HIGH => {
                self.update_queue(|q| q.set_used_ring_address(None, Some(v)))
            }
            _ => warn!(
                "virtio-mmio {:#x}: write to unknown or read-only register {offset:#x}",
                self.slot.base
            ),
        }
    }

    /// Applies `f` to the selected queue. Queues are configured between
    /// FEATURES_OK and DRIVER_OK; writes at any other time are ignored.
    fn update_queue<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if !self.check_status(status::FEATURES_OK, status::DRIVER_OK | status::FAILED) {
            warn!(
                "virtio-mmio {:#x}: queue register written in status {:#x}",
                self.slot.base, self.cfg.device_status
            );
            return;
        }
        let selected = self.cfg.queue_select;
        match self.cfg.selected_queue_mut() {
            Some(queue) => f(queue),
            None => warn!(
                "virtio-mmio {:#x}: queue register written for absent queue {selected}",
                self.slot.base
            ),
        }
    }

    /// The Device Status state machine (virtio 1.2 sections 2.1 and 3.1.1).
    ///
    /// The driver may only add bits, one step at a time: ACKNOWLEDGE, then
    /// DRIVER, then FEATURES_OK, then DRIVER_OK. Any other value is refused
    /// and logged, leaving the status as it was; in particular DRIVER_OK
    /// without FEATURES_OK is refused rather than marking the device FAILED.
    /// FAILED can be set at any time. Writing 0 resets.
    fn write_status(&mut self, v: u32) {
        let Ok(new) = u8::try_from(v) else {
            warn!(
                "virtio-mmio {:#x}: status {v:#x} does not fit in 8 bits",
                self.slot.base
            );
            return;
        };
        let current = self.cfg.device_status;

        if new & status::FAILED != 0 {
            self.cfg.device_status |= status::FAILED;
            return;
        }
        match (current, new) {
            (_, 0) => self.reset(),
            (0, status::ACKNOWLEDGE) | (status::ACKNOWLEDGE, ACK_DRIVER) => {
                self.cfg.device_status = new
            }
            (ACK_DRIVER, ACK_DRIVER_FEATURES) => self.features_ok(),
            (ACK_DRIVER_FEATURES, ALL_OK) => self.driver_ok(),
            _ => warn!(
                "virtio-mmio {:#x}: invalid status transition {current:#x} -> {new:#x}",
                self.slot.base
            ),
        }
    }

    /// FEATURES_OK is accepted only if the driver took no feature the device
    /// did not offer; otherwise the bit does not stick and the driver sees
    /// the negotiation failed when it reads the status back.
    fn features_ok(&mut self) {
        let unoffered = self.cfg.driver_features & !self.cfg.device_features;
        if unoffered != 0 {
            warn!(
                "virtio-mmio {:#x}: driver accepted features {unoffered:#x} the device did not \
                 offer; FEATURES_OK refused",
                self.slot.base
            );
            return;
        }
        self.cfg.device_status = ACK_DRIVER_FEATURES;
    }

    /// Sets DRIVER_OK and activates the device, once per reset cycle. On
    /// failure the device is marked DEVICE_NEEDS_RESET and the driver gets a
    /// configuration change interrupt (virtio 1.2 section 2.1.2).
    fn driver_ok(&mut self) {
        self.cfg.device_status = ALL_OK;
        if self.cfg.activated {
            return;
        }
        match self.activate() {
            Ok(()) => self.cfg.activated = true,
            Err(err) => {
                error!(
                    "virtio-mmio {:#x}: device type {} failed to activate: {err}",
                    self.slot.base,
                    self.device.device_type()
                );
                self.cfg.device_status |= status::DEVICE_NEEDS_RESET;
                if let Err(err) = self.irq.signal_config_change() {
                    error!(
                        "virtio-mmio {:#x}: could not signal DEVICE_NEEDS_RESET: {err}",
                        self.slot.base
                    );
                }
            }
        }
    }

    /// Hands the device a copy of every queue as the driver configured it,
    /// with `event_idx` set to what was negotiated, and the queue's eventfd.
    fn activate(&mut self) -> Result<(), ActivateError> {
        let event_idx = self.cfg.driver_features & EVENT_IDX != 0;
        let mut queues = Vec::with_capacity(self.cfg.queues.len());
        for (index, configured) in self.cfg.queues.iter().enumerate() {
            let mut queue = Queue::try_from(configured.state())
                .map_err(|source| ActivateError::Queue { index, source })?;
            queue.set_event_idx(event_idx);
            let evt = self
                .cfg
                .queue_evts
                .get(index)
                .ok_or(ActivateError::MissingQueueEvent(index))?
                .try_clone()?;
            queues.push(ActivatedQueue { queue, evt });
        }
        self.device.activate(
            self.mem.clone(),
            queues,
            self.irq.clone(),
            self.cfg.driver_features,
        )
    }

    /// A status-0 write: the device is reset only if it was activated, then
    /// the transport returns to its initial state.
    fn reset(&mut self) {
        if self.cfg.activated {
            self.device.reset();
        }
        self.cfg.reset();
    }
}

impl<D: VirtioDevice> BusDevice for MmioTransport<D> {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        match offset {
            0..=REGS_END if data.len() == 4 => match self.read_register(offset) {
                Some(v) => data.copy_from_slice(&v.to_le_bytes()),
                None => warn!(
                    "virtio-mmio {:#x}: read of unknown or write-only register {offset:#x}",
                    self.slot.base
                ),
            },
            regs::CONFIG..=CONFIG_END => self.device.read_config(offset - regs::CONFIG, data),
            _ => warn!(
                "virtio-mmio {:#x}: invalid read of {} bytes at {offset:#x}",
                self.slot.base,
                data.len()
            ),
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        match offset {
            0..=REGS_END => match <[u8; 4]>::try_from(data) {
                Ok(bytes) => self.write_register(offset, u32::from_le_bytes(bytes)),
                Err(_) => warn!(
                    "virtio-mmio {:#x}: invalid write of {} bytes at {offset:#x}",
                    self.slot.base,
                    data.len()
                ),
            },
            regs::CONFIG..=CONFIG_END => {
                if self.check_status(status::DRIVER, status::FAILED | status::DEVICE_NEEDS_RESET) {
                    self.device.write_config(offset - regs::CONFIG, data);
                } else {
                    warn!(
                        "virtio-mmio {:#x}: config space written in status {:#x}",
                        self.slot.base, self.cfg.device_status
                    );
                }
            }
            _ => warn!(
                "virtio-mmio {:#x}: invalid write of {} bytes at {offset:#x}",
                self.slot.base,
                data.len()
            ),
        }
    }
}

/// QueueNum: a power of two between 1 and the queue's maximum, which is
/// `device.queue_max_size(idx)`; anything else is refused.
fn set_queue_size(base: u64, queue: &mut Queue, v: u32) {
    let result = u16::try_from(v)
        .map_err(|_| virtio_queue::Error::InvalidSize)
        .and_then(|size| queue.try_set_size(size));
    if let Err(err) = result {
        warn!(
            "virtio-mmio {base:#x}: queue size {v} refused (maximum {}): {err}",
            queue.max_size()
        );
    }
}

fn low(addr: u64) -> u32 {
    addr as u32
}

fn high(addr: u64) -> u32 {
    (addr >> 32) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtio_bindings::virtio_mmio as vb;

    /// The register map, pinned against the offsets `virtio-bindings`
    /// generates from Linux's `virtio_mmio.h`.
    #[test]
    fn register_offsets_match_the_linux_header() {
        let pairs = [
            (regs::MAGIC_VALUE, vb::VIRTIO_MMIO_MAGIC_VALUE),
            (regs::VERSION, vb::VIRTIO_MMIO_VERSION),
            (regs::DEVICE_ID, vb::VIRTIO_MMIO_DEVICE_ID),
            (regs::VENDOR_ID, vb::VIRTIO_MMIO_VENDOR_ID),
            (regs::DEVICE_FEATURES, vb::VIRTIO_MMIO_DEVICE_FEATURES),
            (
                regs::DEVICE_FEATURES_SEL,
                vb::VIRTIO_MMIO_DEVICE_FEATURES_SEL,
            ),
            (regs::DRIVER_FEATURES, vb::VIRTIO_MMIO_DRIVER_FEATURES),
            (
                regs::DRIVER_FEATURES_SEL,
                vb::VIRTIO_MMIO_DRIVER_FEATURES_SEL,
            ),
            (regs::QUEUE_SEL, vb::VIRTIO_MMIO_QUEUE_SEL),
            (regs::QUEUE_NUM_MAX, vb::VIRTIO_MMIO_QUEUE_NUM_MAX),
            (regs::QUEUE_NUM, vb::VIRTIO_MMIO_QUEUE_NUM),
            (regs::QUEUE_READY, vb::VIRTIO_MMIO_QUEUE_READY),
            (regs::QUEUE_NOTIFY, vb::VIRTIO_MMIO_QUEUE_NOTIFY),
            (regs::INTERRUPT_STATUS, vb::VIRTIO_MMIO_INTERRUPT_STATUS),
            (regs::INTERRUPT_ACK, vb::VIRTIO_MMIO_INTERRUPT_ACK),
            (regs::STATUS, vb::VIRTIO_MMIO_STATUS),
            (regs::QUEUE_DESC_LOW, vb::VIRTIO_MMIO_QUEUE_DESC_LOW),
            (regs::QUEUE_DESC_HIGH, vb::VIRTIO_MMIO_QUEUE_DESC_HIGH),
            (regs::QUEUE_DRIVER_LOW, vb::VIRTIO_MMIO_QUEUE_AVAIL_LOW),
            (regs::QUEUE_DRIVER_HIGH, vb::VIRTIO_MMIO_QUEUE_AVAIL_HIGH),
            (regs::QUEUE_DEVICE_LOW, vb::VIRTIO_MMIO_QUEUE_USED_LOW),
            (regs::QUEUE_DEVICE_HIGH, vb::VIRTIO_MMIO_QUEUE_USED_HIGH),
            (regs::CONFIG_GENERATION, vb::VIRTIO_MMIO_CONFIG_GENERATION),
            (regs::CONFIG, vb::VIRTIO_MMIO_CONFIG),
        ];
        for (ours, linux) in pairs {
            assert_eq!(ours, u64::from(linux), "register {ours:#x}");
        }
    }

    /// And against the offsets in the task brief, digit for digit.
    #[test]
    fn register_offsets_match_the_spec_table() {
        let table: [(u64, u64); 24] = [
            (regs::MAGIC_VALUE, 0x000),
            (regs::VERSION, 0x004),
            (regs::DEVICE_ID, 0x008),
            (regs::VENDOR_ID, 0x00c),
            (regs::DEVICE_FEATURES, 0x010),
            (regs::DEVICE_FEATURES_SEL, 0x014),
            (regs::DRIVER_FEATURES, 0x020),
            (regs::DRIVER_FEATURES_SEL, 0x024),
            (regs::QUEUE_SEL, 0x030),
            (regs::QUEUE_NUM_MAX, 0x034),
            (regs::QUEUE_NUM, 0x038),
            (regs::QUEUE_READY, 0x044),
            (regs::QUEUE_NOTIFY, 0x050),
            (regs::INTERRUPT_STATUS, 0x060),
            (regs::INTERRUPT_ACK, 0x064),
            (regs::STATUS, 0x070),
            (regs::QUEUE_DESC_LOW, 0x080),
            (regs::QUEUE_DESC_HIGH, 0x084),
            (regs::QUEUE_DRIVER_LOW, 0x090),
            (regs::QUEUE_DRIVER_HIGH, 0x094),
            (regs::QUEUE_DEVICE_LOW, 0x0a0),
            (regs::QUEUE_DEVICE_HIGH, 0x0a4),
            (regs::CONFIG_GENERATION, 0x0fc),
            (regs::CONFIG, 0x100),
        ];
        for (ours, spec) in table {
            assert_eq!(ours, spec);
        }
        assert_eq!(MMIO_MAGIC_VALUE.to_le_bytes(), *b"virt");
    }
}
