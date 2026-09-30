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
// Register-map tests ported from two sources and adapted to boxcar's
// `VirtioDevice` trait and `MmioTransport`:
//   - rust-vmm vm-virtio (https://github.com/rust-vmm/vm-virtio),
//     virtio-device/src/mmio.rs and virtio-device/src/lib.rs at tag
//     virtio-queue-v0.17.0 (commit ec17cad1c79e0525647914b33bd9238f6f509471);
//   - Firecracker (https://github.com/firecracker-microvm/firecracker),
//     src/vmm/src/devices/virtio/transport/mmio.rs at commit
//     21f19ed8109578108568c8a8f3623ddb6f097878.
// The BSD-3-Clause text referred to above (THIRD-PARTY in Firecracker's tree)
// is in LICENSE-BSD-3-Clause. The tests marked (a) to (h) are boxcar's own.

//! The virtio-mmio transport over a `DummyDevice` and plain guest memory,
//! and `drain_queue` over a mock split queue. None of this needs KVM.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use boxcar_virtio::features::{EVENT_IDX, VERSION_1};
use boxcar_virtio::status::{
    ACKNOWLEDGE, DEVICE_NEEDS_RESET, DRIVER, DRIVER_OK, FAILED, FEATURES_OK,
};
use boxcar_virtio::testing::{
    self, DummyDevice, DUMMY_CONFIG, DUMMY_DEVICE_TYPE, DUMMY_QUEUE_MAX_SIZES, TEST_SLOT,
};
use boxcar_virtio::{drain_queue, Bus, BusDevice, DeviceContext, MmioTransport};
use virtio_queue::desc::split::{Descriptor as SplitDescriptor, VirtqUsedElem};
use virtio_queue::desc::RawDescriptor;
use virtio_queue::mock::MockSplitQueue;
use virtio_queue::{Queue, QueueT};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

type Transport = MmioTransport<DummyDevice>;

/// Guest RAM for every test: 64 KiB at guest physical address 0.
const GUEST_MEM_SIZE: usize = 0x1_0000;
/// "virt" in little endian.
const MAGIC: u32 = 0x7472_6976;
const ACK_DRIVER: u8 = ACKNOWLEDGE | DRIVER;
const ACK_DRIVER_FEATURES: u8 = ACKNOWLEDGE | DRIVER | FEATURES_OK;
const ALL_OK: u8 = ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK;
/// The queue size `setup_queues` programs.
const SETUP_QUEUE_SIZE: u32 = 16;

fn transport() -> Transport {
    transport_with(DummyDevice::new())
}

fn transport_with(device: DummyDevice) -> Transport {
    let mem = testing::guest_memory(GUEST_MEM_SIZE).expect("64 KiB of guest memory");
    testing::transport(device, mem).expect("transport over guest memory")
}

/// A transport built from a context the test keeps handles into.
fn transport_with_context(
    device: DummyDevice,
) -> (Transport, Arc<boxcar_virtio::IrqTrigger>, Vec<EventFd>) {
    let mem = testing::guest_memory(GUEST_MEM_SIZE).expect("64 KiB of guest memory");
    let ctx = DeviceContext::new(TEST_SLOT, 2).expect("device context without KVM");
    let irq = ctx.irq.clone();
    let kicks = ctx
        .queue_evts
        .iter()
        .map(|evt| evt.try_clone().expect("clone queue eventfd"))
        .collect();
    (MmioTransport::new(device, mem, ctx), irq, kicks)
}

fn read(t: &mut Transport, offset: u64) -> u32 {
    testing::read_u32(t, offset)
}

fn write(t: &mut Transport, offset: u64, value: u32) {
    testing::write_u32(t, offset, value)
}

fn status(t: &mut Transport) -> u8 {
    read(t, 0x070) as u8
}

fn set_status(t: &mut Transport, value: u8) {
    write(t, 0x070, u32::from(value))
}

/// ACKNOWLEDGE, DRIVER, both feature pages, FEATURES_OK.
fn negotiate(t: &mut Transport, features: u64) {
    set_status(t, ACKNOWLEDGE);
    set_status(t, ACK_DRIVER);
    write(t, 0x024, 0);
    write(t, 0x020, features as u32);
    write(t, 0x024, 1);
    write(t, 0x020, (features >> 32) as u32);
    set_status(t, ACK_DRIVER_FEATURES);
    assert_eq!(status(t), ACK_DRIVER_FEATURES, "FEATURES_OK accepted");
}

/// Ring addresses `setup_queues` gives queue `q`: descriptor table, driver
/// (available) ring, device (used) ring.
fn ring_addrs(q: u32) -> (u64, u64, u64) {
    let base = 0x1000 * (u64::from(q) + 1);
    (base, base + 0x400, base + 0x800)
}

/// Programs both queues the way the Linux driver does, then sets them ready.
fn setup_queues(t: &mut Transport) {
    for q in 0..2 {
        let (desc, driver, device) = ring_addrs(q);
        write(t, 0x030, q);
        write(t, 0x038, SETUP_QUEUE_SIZE);
        write(t, 0x080, desc as u32);
        write(t, 0x084, (desc >> 32) as u32);
        write(t, 0x090, driver as u32);
        write(t, 0x094, (driver >> 32) as u32);
        write(t, 0x0a0, device as u32);
        write(t, 0x0a4, (device >> 32) as u32);
        write(t, 0x044, 1);
    }
}

/// The whole handshake: negotiate, program the queues, DRIVER_OK.
fn activate(t: &mut Transport, features: u64) {
    negotiate(t, features);
    setup_queues(t);
    set_status(t, ALL_OK);
    assert_eq!(status(t), ALL_OK, "DRIVER_OK accepted");
}

// (a) Identification registers.

#[test]
fn identification_registers_read_magic_version_device_and_vendor() {
    let mut t = transport();
    assert_eq!(read(&mut t, 0x000), MAGIC);
    assert_eq!(read(&mut t, 0x004), 2);
    assert_eq!(read(&mut t, 0x008), 0xffff);
    assert_eq!(read(&mut t, 0x008), DUMMY_DEVICE_TYPE);
    assert_eq!(read(&mut t, 0x00c), 0);
}

// (b) Feature pages.

#[test]
fn device_features_are_paged_by_the_selector() {
    let mut t = transport();
    let features = t.device().avail_features;
    assert_eq!(features, VERSION_1 | EVENT_IDX);

    // DeviceFeaturesSel starts at 0: the low 32 bits, EVENT_IDX (bit 29) set.
    assert_eq!(read(&mut t, 0x010), features as u32);
    assert_ne!(read(&mut t, 0x010) & (1 << 29), 0);

    write(&mut t, 0x014, 1);
    assert_eq!(read(&mut t, 0x010), (features >> 32) as u32);
    assert_ne!(read(&mut t, 0x010) & 1, 0, "VERSION_1 is bit 0 of page 1");

    // No features are defined past page 1.
    write(&mut t, 0x014, 2);
    assert_eq!(read(&mut t, 0x010), 0);
}

#[test]
fn driver_features_round_trip_through_both_pages() {
    let mut t = transport();

    // Ignored until the driver has set DRIVER.
    write(&mut t, 0x020, 0xffff_ffff);
    assert_eq!(t.config().driver_features, 0);

    set_status(&mut t, ACKNOWLEDGE);
    set_status(&mut t, ACK_DRIVER);
    write(&mut t, 0x024, 0);
    write(&mut t, 0x020, EVENT_IDX as u32);
    write(&mut t, 0x024, 1);
    write(&mut t, 0x020, (VERSION_1 >> 32) as u32);
    assert_eq!(t.config().driver_features_select, 1);
    assert_eq!(t.config().driver_features, VERSION_1 | EVENT_IDX);

    // Rewriting page 0 leaves page 1 alone, and a page past 1 is ignored.
    write(&mut t, 0x024, 0);
    write(&mut t, 0x020, 0);
    assert_eq!(t.config().driver_features, VERSION_1);
    write(&mut t, 0x024, 2);
    write(&mut t, 0x020, 0xffff_ffff);
    assert_eq!(t.config().driver_features, VERSION_1);

    // Frozen once FEATURES_OK is set.
    write(&mut t, 0x024, 0);
    write(&mut t, 0x020, EVENT_IDX as u32);
    set_status(&mut t, ACK_DRIVER_FEATURES);
    write(&mut t, 0x020, 0);
    assert_eq!(t.config().driver_features, VERSION_1 | EVENT_IDX);
}

#[test]
fn features_ok_is_refused_when_the_driver_acks_an_unoffered_feature() {
    let mut t = transport();
    set_status(&mut t, ACKNOWLEDGE);
    set_status(&mut t, ACK_DRIVER);
    // Bit 5 is not in the dummy's feature set.
    write(&mut t, 0x020, (EVENT_IDX as u32) | (1 << 5));
    set_status(&mut t, ACK_DRIVER_FEATURES);
    assert_eq!(status(&mut t), ACK_DRIVER, "FEATURES_OK must not stick");

    // Dropping the bad bit lets FEATURES_OK through.
    write(&mut t, 0x020, EVENT_IDX as u32);
    set_status(&mut t, ACK_DRIVER_FEATURES);
    assert_eq!(status(&mut t), ACK_DRIVER_FEATURES);
}

// (c) The status handshake and activation.

#[test]
fn handshake_activates_exactly_once_with_the_negotiated_features() {
    let mut t = transport();
    negotiate(&mut t, VERSION_1 | EVENT_IDX);
    setup_queues(&mut t);
    assert_eq!(t.device().activate_calls, 0);
    assert!(!t.config().activated);

    set_status(&mut t, ALL_OK);
    assert_eq!(status(&mut t), ALL_OK);
    assert_eq!(t.device().activate_calls, 1);
    assert!(t.config().activated);

    let act = t
        .device()
        .activation
        .as_ref()
        .expect("device holds its queues");
    assert_eq!(act.queues.len(), 2);
    assert_eq!(act.driver_features, VERSION_1 | EVENT_IDX);
    assert!(
        act.queues.iter().all(|q| q.queue.event_idx_enabled()),
        "EVENT_IDX was negotiated, so every handed-over queue uses it"
    );

    // Neither a repeated DRIVER_OK write nor FAILED activates again.
    set_status(&mut t, ALL_OK);
    set_status(&mut t, ALL_OK | FAILED);
    assert_eq!(t.device().activate_calls, 1);
}

#[test]
fn event_idx_stays_off_when_the_driver_does_not_negotiate_it() {
    let mut t = transport();
    activate(&mut t, VERSION_1);
    let act = t.device().activation.as_ref().expect("activated");
    assert_eq!(act.driver_features, VERSION_1);
    assert!(act.queues.iter().all(|q| !q.queue.event_idx_enabled()));
}

#[test]
fn activated_queues_match_the_programmed_registers_and_carry_the_eventfds() {
    let (mut t, irq, kicks) = transport_with_context(DummyDevice::new());
    activate(&mut t, VERSION_1 | EVENT_IDX);
    let act = t.device().activation.as_ref().expect("activated");

    for (q, activated) in (0u32..).zip(&act.queues) {
        let (desc, driver, device) = ring_addrs(q);
        assert_eq!(activated.queue.size(), SETUP_QUEUE_SIZE as u16);
        assert_eq!(activated.queue.desc_table(), desc);
        assert_eq!(activated.queue.avail_ring(), driver);
        assert_eq!(activated.queue.used_ring(), device);
        assert!(activated.queue.ready());
    }

    // What KVM does when the guest writes 1 to QueueNotify: the device sees
    // it on queue 1's eventfd.
    kicks[1].write(1).expect("kick queue 1");
    assert_eq!(act.queues[1].evt.read().expect("queue 1 was kicked"), 1);

    // The device signals through the context's IRQ trigger.
    assert!(Arc::ptr_eq(&act.irq, &irq));
}

#[test]
fn invalid_status_transitions_are_refused() {
    let mut t = transport();

    // Skipping ACKNOWLEDGE, or an arbitrary value, from reset.
    set_status(&mut t, ACK_DRIVER);
    assert_eq!(status(&mut t), 0);
    set_status(&mut t, 0x42);
    assert_eq!(status(&mut t), 0);

    set_status(&mut t, ACKNOWLEDGE);
    set_status(&mut t, ACK_DRIVER);

    // DRIVER_OK without FEATURES_OK is refused: no activation, status kept.
    set_status(&mut t, ACK_DRIVER | DRIVER_OK);
    assert_eq!(status(&mut t), ACK_DRIVER);
    assert_eq!(t.device().activate_calls, 0);

    set_status(&mut t, ACK_DRIVER_FEATURES);
    assert_eq!(status(&mut t), ACK_DRIVER_FEATURES);

    // Clearing a bit, or DRIVER_OK without the cumulative bits.
    set_status(&mut t, ACK_DRIVER);
    assert_eq!(status(&mut t), ACK_DRIVER_FEATURES);
    set_status(&mut t, DRIVER_OK);
    assert_eq!(status(&mut t), ACK_DRIVER_FEATURES);
    assert_eq!(t.device().activate_calls, 0);
}

#[test]
fn activation_failure_sets_device_needs_reset_and_signals_a_config_change() {
    let mut device = DummyDevice::new();
    device.fail_activate = true;
    let (mut t, irq, _kicks) = transport_with_context(device);

    negotiate(&mut t, VERSION_1 | EVENT_IDX);
    setup_queues(&mut t);
    set_status(&mut t, ALL_OK);

    assert_eq!(status(&mut t), ALL_OK | DEVICE_NEEDS_RESET);
    assert_eq!(t.device().activate_calls, 1);
    assert!(!t.config().activated);
    // Virtio 1.2 section 2.1.2: DEVICE_NEEDS_RESET comes with a
    // configuration change notification.
    assert_eq!(read(&mut t, 0x060), 0x2);
    assert_eq!(irq.evt.read().expect("config change interrupt"), 1);

    // Further status writes other than reset are refused.
    set_status(&mut t, ALL_OK);
    assert_eq!(t.device().activate_calls, 1);

    // The device was never activated, so a reset does not reach it.
    set_status(&mut t, 0);
    assert_eq!(status(&mut t), 0);
    assert_eq!(t.device().reset_calls, 0);
}

// (d) Reset.

#[test]
fn reset_before_activation_does_not_reset_the_device() {
    let mut t = transport();
    negotiate(&mut t, VERSION_1 | EVENT_IDX);
    setup_queues(&mut t);

    set_status(&mut t, 0);
    assert_eq!(t.device().reset_calls, 0);
    assert_eq!(status(&mut t), 0);
    assert_eq!(t.config().driver_features, 0);
    assert!(t.config().queues.iter().all(|q| !q.ready()));
}

#[test]
fn reset_after_activation_resets_the_device_and_clears_the_transport() {
    let mut t = transport();
    activate(&mut t, VERSION_1 | EVENT_IDX);
    t.config().interrupt_status.store(0x3, Ordering::SeqCst);
    write(&mut t, 0x014, 1);
    write(&mut t, 0x030, 1);

    set_status(&mut t, 0);
    assert_eq!(t.device().reset_calls, 1);
    assert!(t.device().activation.is_none());
    assert_eq!(status(&mut t), 0);

    let cfg = t.config();
    assert!(!cfg.activated);
    assert_eq!(cfg.driver_features, 0);
    assert_eq!(cfg.device_features_select, 0);
    assert_eq!(cfg.driver_features_select, 0);
    assert_eq!(cfg.queue_select, 0);
    assert_eq!(cfg.interrupt_status.load(Ordering::SeqCst), 0);
    for (q, max) in cfg.queues.iter().zip(DUMMY_QUEUE_MAX_SIZES) {
        assert!(!q.ready());
        assert_eq!(q.size(), max);
        assert!(!q.event_idx_enabled());
    }

    // The driver can bring the device up again; that is a second activation.
    activate(&mut t, VERSION_1);
    assert_eq!(t.device().activate_calls, 2);
}

#[test]
fn failed_keeps_the_device_active_until_the_driver_resets_it() {
    let mut t = transport();
    activate(&mut t, VERSION_1 | EVENT_IDX);

    write(&mut t, 0x070, 0x8f);
    assert_eq!(status(&mut t), 0x8f);
    assert!(t.config().activated);
    assert_eq!(t.device().reset_calls, 0);

    set_status(&mut t, 0);
    assert_eq!(status(&mut t), 0);
    assert!(!t.config().activated);
    assert_eq!(t.device().reset_calls, 1);
    assert_eq!(t.config().driver_features, 0);
}

// (e) Queue registers.

#[test]
fn queue_registers_program_the_selected_queue() {
    let mut t = transport();
    negotiate(&mut t, VERSION_1 | EVENT_IDX);

    write(&mut t, 0x030, 1);
    assert_eq!(read(&mut t, 0x034), u32::from(DUMMY_QUEUE_MAX_SIZES[1]));
    assert_eq!(read(&mut t, 0x044), 0);

    write(&mut t, 0x038, 64);
    write(&mut t, 0x080, 0x1000);
    write(&mut t, 0x084, 0x1);
    write(&mut t, 0x090, 0x2000);
    write(&mut t, 0x094, 0x2);
    write(&mut t, 0x0a0, 0x3000);
    write(&mut t, 0x0a4, 0x3);
    write(&mut t, 0x044, 1);

    let q = &t.config().queues[1];
    assert_eq!(q.size(), 64);
    assert_eq!(q.desc_table(), 0x1_0000_1000);
    assert_eq!(q.avail_ring(), 0x2_0000_2000);
    assert_eq!(q.used_ring(), 0x3_0000_3000);
    assert!(q.ready());
    assert_eq!(read(&mut t, 0x044), 1);

    // The address registers read back the halves that were written.
    assert_eq!(read(&mut t, 0x080), 0x1000);
    assert_eq!(read(&mut t, 0x084), 0x1);
    assert_eq!(read(&mut t, 0x090), 0x2000);
    assert_eq!(read(&mut t, 0x094), 0x2);
    assert_eq!(read(&mut t, 0x0a0), 0x3000);
    assert_eq!(read(&mut t, 0x0a4), 0x3);

    // Queue 0 was not selected and is untouched.
    let q0 = &t.config().queues[0];
    assert_eq!(q0.size(), DUMMY_QUEUE_MAX_SIZES[0]);
    assert!(!q0.ready());
    write(&mut t, 0x030, 0);
    assert_eq!(read(&mut t, 0x034), u32::from(DUMMY_QUEUE_MAX_SIZES[0]));
}

#[test]
fn queue_num_is_bounded_by_the_device_maximum() {
    let mut t = transport();
    negotiate(&mut t, VERSION_1 | EVENT_IDX);
    write(&mut t, 0x030, 0);
    let max = DUMMY_QUEUE_MAX_SIZES[0];

    for bad in [u32::from(max) * 2, 0, 3, 0x1_0000] {
        write(&mut t, 0x038, bad);
        assert_eq!(t.config().queues[0].size(), max, "QueueNum {bad} refused");
    }
    write(&mut t, 0x038, 32);
    assert_eq!(t.config().queues[0].size(), 32);
}

#[test]
fn queue_registers_are_writable_only_between_features_ok_and_driver_ok() {
    let mut t = transport();
    set_status(&mut t, ACKNOWLEDGE);
    set_status(&mut t, ACK_DRIVER);
    write(&mut t, 0x030, 0);
    write(&mut t, 0x038, 32);
    write(&mut t, 0x044, 1);
    assert_eq!(t.config().queues[0].size(), DUMMY_QUEUE_MAX_SIZES[0]);
    assert!(!t.config().queues[0].ready());

    // After DRIVER_OK every queue register is frozen.
    let mut t = transport();
    activate(&mut t, VERSION_1 | EVENT_IDX);
    write(&mut t, 0x030, 0);
    let before = t.config().queues[0].state();
    write(&mut t, 0x038, 0);
    write(&mut t, 0x044, 0);
    for reg in [0x080, 0x084, 0x090, 0x094, 0x0a0, 0x0a4] {
        write(&mut t, reg, 0xdead_bee0);
    }
    assert_eq!(t.config().queues[0].state(), before);
}

#[test]
fn a_queue_select_past_the_last_queue_reads_as_absent() {
    let mut t = transport();
    negotiate(&mut t, VERSION_1 | EVENT_IDX);
    write(&mut t, 0x030, 2);
    assert_eq!(read(&mut t, 0x034), 0);
    assert_eq!(read(&mut t, 0x044), 0);
    write(&mut t, 0x038, 16);
    write(&mut t, 0x044, 1);
    assert!(t.config().queues.iter().all(|q| !q.ready()));
}

#[test]
fn queue_notify_without_an_ioeventfd_reaches_the_device() {
    let mut t = transport();
    activate(&mut t, VERSION_1 | EVENT_IDX);
    write(&mut t, 0x050, 1);
    write(&mut t, 0x050, 0);
    assert_eq!(t.device().notifies, [1, 0]);
}

// (f) Interrupt status and acknowledgement.

#[test]
fn interrupt_ack_clears_only_the_acked_bits() {
    let (mut t, irq, _kicks) = transport_with_context(DummyDevice::new());
    activate(&mut t, VERSION_1 | EVENT_IDX);

    irq.signal_used_queue().expect("used buffer interrupt");
    irq.signal_config_change().expect("config change interrupt");
    assert_eq!(read(&mut t, 0x060), 0x3);

    write(&mut t, 0x064, 0x1);
    assert_eq!(read(&mut t, 0x060), 0x2);
    assert_eq!(irq.status.load(Ordering::SeqCst), 0x2);
    write(&mut t, 0x064, 0x2);
    assert_eq!(read(&mut t, 0x060), 0);

    // Firecracker's pattern: only the acked bits go.
    t.config()
        .interrupt_status
        .store(0b10_1010, Ordering::SeqCst);
    write(&mut t, 0x064, 0b111);
    assert_eq!(
        t.config().interrupt_status.load(Ordering::SeqCst),
        0b10_1000
    );
}

// A device asking for a reset.

#[test]
fn a_device_worker_can_request_a_reset() {
    let mut t = transport();
    activate(&mut t, VERSION_1 | EVENT_IDX);
    let irq = t
        .device()
        .activation
        .as_ref()
        .expect("activated")
        .irq
        .clone();

    // What a worker does after a fatal drain_queue error.
    irq.signal_needs_reset().expect("signal the reset request");
    assert!(irq.needs_reset.load(Ordering::SeqCst));
    assert_eq!(status(&mut t), ALL_OK | DEVICE_NEEDS_RESET);
    assert_eq!(read(&mut t, 0x070) & 64, 64);
    assert_eq!(read(&mut t, 0x060) & 0x2, 0x2, "config change interrupt");
    assert_eq!(irq.evt.read().expect("interrupt raised"), 1);

    // While the device needs a reset the driver cannot write its config.
    t.write(0x100, &[0xaa]);
    assert!(t.device().config_writes.is_empty());

    // The driver resets: the request is cleared and Status reads 0.
    set_status(&mut t, 0);
    assert!(!irq.needs_reset.load(Ordering::SeqCst));
    assert_eq!(read(&mut t, 0x070), 0);
    assert_eq!(read(&mut t, 0x060), 0);
    assert_eq!(t.device().reset_calls, 1);

    // And the device comes back up normally.
    activate(&mut t, VERSION_1 | EVENT_IDX);
    assert_eq!(status(&mut t), ALL_OK);
}

// (g) Device configuration space.

#[test]
fn config_space_reads_hit_read_config_at_the_offset() {
    let mut t = transport();

    let mut two = [0u8; 2];
    t.read(0x103, &mut two);
    assert_eq!(two, DUMMY_CONFIG[3..5]);
    assert_eq!(t.device().config_reads.borrow().last(), Some(&(3, 2)));

    let word = read(&mut t, 0x104);
    assert_eq!(word.to_le_bytes(), DUMMY_CONFIG[4..8]);
    assert_eq!(t.device().config_reads.borrow().last(), Some(&(4, 4)));

    let mut one = [0u8; 1];
    t.read(0x100, &mut one);
    assert_eq!(one[0], DUMMY_CONFIG[0]);
    assert_eq!(t.device().config_reads.borrow().last(), Some(&(0, 1)));
}

#[test]
fn config_space_writes_need_the_driver_status() {
    let mut t = transport();
    t.write(0x102, &[0xaa]);
    assert!(t.device().config_writes.is_empty());
    assert_eq!(t.device().config, DUMMY_CONFIG);

    set_status(&mut t, ACKNOWLEDGE);
    set_status(&mut t, ACK_DRIVER);
    t.write(0x102, &[0xaa, 0xbb]);
    assert_eq!(t.device().config_writes, [(2, vec![0xaa, 0xbb])]);
    assert_eq!(t.device().config[2..4], [0xaa, 0xbb]);

    let mut back = [0u8; 2];
    t.read(0x102, &mut back);
    assert_eq!(back, [0xaa, 0xbb]);
}

#[test]
fn config_generation_starts_at_zero() {
    let mut t = transport();
    assert_eq!(read(&mut t, 0x0fc), 0);
}

// Malformed accesses (ported from Firecracker's read and write tests).

#[test]
fn register_reads_of_the_wrong_width_or_an_unknown_offset_leave_the_buffer_alone() {
    let mut t = transport();

    let orig = [0xff, 0, 0xfe, 0, 0];
    let mut five = orig;
    t.read(0x000, &mut five);
    assert_eq!(five, orig, "a 5-byte register read is ignored");

    let orig = [0xff, 0, 0xfe, 0];
    for offset in [0x0fd, 0x0fb, 0x0a8, 0x018] {
        let mut buf = orig;
        t.read(offset, &mut buf);
        assert_eq!(buf, orig, "read at {offset:#x}");
    }
    let mut three = [0xff, 0, 0xfe];
    t.read(0x0fc, &mut three);
    assert_eq!(three, [0xff, 0, 0xfe], "a 3-byte register read is ignored");
}

#[test]
fn register_writes_of_the_wrong_width_or_an_unknown_offset_are_ignored() {
    let mut t = transport();

    // A 5-byte write to DeviceFeaturesSel.
    t.write(0x014, &[1, 0, 0, 0, 0]);
    assert_eq!(t.config().device_features_select, 0);
    // A 2-byte write to Status.
    t.write(0x070, &[ACKNOWLEDGE, 0]);
    assert_eq!(status(&mut t), 0);

    // Unknown and read-only registers.
    write(&mut t, 0x0fb, 0xf);
    write(&mut t, 0x0fc, 0xf);
    write(&mut t, 0x0a8, 0xf);
    write(&mut t, 0x000, 0xf);
    assert_eq!(read(&mut t, 0x0fc), 0);
    assert_eq!(read(&mut t, 0x000), MAGIC);
    assert_eq!(status(&mut t), 0);
}

// The transport on the MMIO bus.

#[test]
fn the_transport_answers_its_slot_on_the_mmio_bus() {
    let t = Arc::new(Mutex::new(transport()));
    let mut bus = Bus::new();
    bus.insert(t.clone(), TEST_SLOT.base, TEST_SLOT.size)
        .expect("slot is free");

    let mut word = [0u8; 4];
    assert!(bus.read(TEST_SLOT.base, &mut word));
    assert_eq!(u32::from_le_bytes(word), MAGIC);

    assert!(bus.write(
        TEST_SLOT.base + 0x070,
        &u32::from(ACKNOWLEDGE).to_le_bytes()
    ));
    assert!(bus.read(TEST_SLOT.base + 0x070, &mut word));
    assert_eq!(u32::from_le_bytes(word), u32::from(ACKNOWLEDGE));

    let mut byte = [0u8; 1];
    assert!(bus.read(TEST_SLOT.base + 0x107, &mut byte));
    assert_eq!(byte[0], DUMMY_CONFIG[7]);

    // One past the slot is unmapped.
    assert!(!bus.read(TEST_SLOT.base + TEST_SLOT.size, &mut word));
    assert!(!bus.write(TEST_SLOT.base + TEST_SLOT.size, &word));
}

// (h) drain_queue over a mock split queue.

/// Size of the mock queue.
const QUEUE_LEN: u16 = 16;
/// Where the tests put the used ring. The mock sizes its available ring in
/// elements rather than bytes when it places the used ring after it, so its
/// own used ring overlaps the available ring's entries and `used_event`;
/// moving the used ring out of the way keeps the two rings independent.
const USED_RING: u64 = 0x2000;

#[derive(Debug)]
enum DrainError {
    Rejected(u16),
    Queue(String),
}

impl From<virtio_queue::Error> for DrainError {
    fn from(err: virtio_queue::Error) -> Self {
        DrainError::Queue(err.to_string())
    }
}

fn queue_memory() -> GuestMemoryMmap {
    GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)])
        .expect("64 KiB of guest memory")
}

/// Offers `count` one-descriptor chains, starting at descriptor `first`.
fn offer_chains(mock: &MockSplitQueue<'_, GuestMemoryMmap>, first: u16, count: u16) {
    let descs: Vec<RawDescriptor> = (first..first + count)
        .map(|i| {
            RawDescriptor::from(SplitDescriptor::new(
                0x4000 + 0x100 * u64::from(i),
                0x100,
                0,
                0,
            ))
        })
        .collect();
    mock.add_desc_chains(&descs, first).expect("offer chains");
}

fn device_queue(mock: &MockSplitQueue<'_, GuestMemoryMmap>, event_idx: bool) -> Queue {
    let mut queue: Queue = mock.create_queue().expect("queue over the mock rings");
    queue.set_used_ring_address(Some(USED_RING as u32), Some(0));
    queue.set_event_idx(event_idx);
    queue
}

/// The driver's `used_event`: notify me once the used index passes this.
fn set_used_event(mem: &GuestMemoryMmap, mock: &MockSplitQueue<'_, GuestMemoryMmap>, value: u16) {
    let addr = GuestAddress(mock.avail_addr().0 + 4 + 2 * u64::from(QUEUE_LEN));
    mem.write_obj(value.to_le(), addr)
        .expect("write used_event");
}

fn used_idx(mem: &GuestMemoryMmap) -> u16 {
    u16::from_le(mem.read_obj(GuestAddress(USED_RING + 2)).expect("used idx"))
}

fn used_elem(mem: &GuestMemoryMmap, index: u64) -> VirtqUsedElem {
    mem.read_obj(GuestAddress(USED_RING + 4 + 8 * index))
        .expect("used element")
}

/// The device's `avail_event`: kick me once the available index passes this.
fn avail_event(mem: &GuestMemoryMmap) -> u16 {
    let addr = GuestAddress(USED_RING + 4 + 8 * u64::from(QUEUE_LEN));
    u16::from_le(mem.read_obj(addr).expect("avail_event"))
}

#[test]
fn drain_queue_uses_every_chain_and_reports_a_wanted_notification() {
    let mem = queue_memory();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    offer_chains(&mock, 0, 3);
    let mut queue = device_queue(&mock, true);
    // The driver wants an interrupt once the third buffer is used.
    set_used_event(&mem, &mock, 2);

    let mut seen = Vec::new();
    let notify = drain_queue(&mut queue, &mem, |chain| {
        let head = chain.head_index();
        seen.push(head);
        Ok::<_, DrainError>(0x10 + u32::from(head))
    })
    .expect("drain");

    assert!(notify, "used_event 2 was crossed");
    assert_eq!(seen, [0, 1, 2]);
    assert_eq!(used_idx(&mem), 3);
    for i in 0..3 {
        let elem = used_elem(&mem, i);
        assert_eq!(u64::from(elem.id()), i);
        assert_eq!(u64::from(elem.len()), 0x10 + i);
    }
    // Notifications were re-enabled at the point the device stopped.
    assert_eq!(queue.next_avail(), 3);
    assert_eq!(avail_event(&mem), 3);
}

#[test]
fn drain_queue_reports_no_notification_when_the_driver_does_not_want_one() {
    let mem = queue_memory();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    offer_chains(&mock, 0, 1);
    let mut queue = device_queue(&mock, true);
    // The driver only wants to hear about the eleventh buffer.
    set_used_event(&mem, &mock, 10);

    let notify = drain_queue(&mut queue, &mem, |_| Ok::<_, DrainError>(0)).expect("drain");
    assert!(!notify, "needs_notification said no");
    assert_eq!(used_idx(&mem), 1);

    // The driver pulls used_event back and offers another buffer.
    set_used_event(&mem, &mock, 1);
    offer_chains(&mock, 1, 1);
    let notify = drain_queue(&mut queue, &mem, |_| Ok::<_, DrainError>(0)).expect("drain");
    assert!(notify);
    assert_eq!(used_idx(&mem), 2);
}

#[test]
fn drain_queue_on_an_empty_queue_calls_nothing() {
    let mem = queue_memory();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock, true);

    let notify = drain_queue(&mut queue, &mem, |chain| {
        Err::<u32, _>(DrainError::Rejected(chain.head_index()))
    })
    .expect("nothing to drain");
    assert!(!notify, "nothing was used");
    assert_eq!(used_idx(&mem), 0);

    // Without EVENT_IDX the device always notifies.
    let mut queue = device_queue(&mock, false);
    let notify = drain_queue(&mut queue, &mem, |_| Ok::<_, DrainError>(0)).expect("drain");
    assert!(notify);
}

#[test]
fn drain_queue_completes_the_failed_chain_and_stops() {
    let mem = queue_memory();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    offer_chains(&mock, 0, 3);
    let mut queue = device_queue(&mock, true);

    let mut seen = Vec::new();
    let err = drain_queue(&mut queue, &mem, |chain| {
        let head = chain.head_index();
        seen.push(head);
        if head == 1 {
            Err(DrainError::Rejected(head))
        } else {
            Ok(0x40)
        }
    })
    .expect_err("the callback failed");

    assert!(matches!(err, DrainError::Rejected(1)), "{err:?}");
    assert_eq!(seen, [0, 1], "the drain stops at the failure");
    // Both chains the callback saw went back to the driver, the failed one
    // with nothing written, so no guest request is left hanging.
    assert_eq!(used_idx(&mem), 2);
    let first = used_elem(&mem, 0);
    assert_eq!((first.id(), first.len()), (0, 0x40));
    let failed = used_elem(&mem, 1);
    assert_eq!((failed.id(), failed.len()), (1, 0));
    // The third chain is still available.
    assert_eq!(queue.next_avail(), 2);
}

#[test]
fn drain_queue_gives_up_on_an_available_index_it_cannot_pop() {
    let mem = queue_memory();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock, true);
    // A broken or hostile driver: the available index runs more than a
    // queue's worth ahead, so nothing can be popped, yet the ring never looks
    // empty. The drain must fail rather than spin.
    let idx = GuestAddress(mock.avail_addr().0 + 2);
    mem.write_obj((QUEUE_LEN + 1).to_le(), idx)
        .expect("write avail idx");

    let err = drain_queue(&mut queue, &mem, |chain| {
        Err::<u32, _>(DrainError::Rejected(chain.head_index()))
    })
    .expect_err("the ring cannot be drained");
    let DrainError::Queue(msg) = err else {
        panic!("expected a queue error, got {err:?}");
    };
    assert!(msg.contains("available ring index"), "{msg}");
    assert_eq!(used_idx(&mem), 0);
}

#[test]
fn drain_queue_surfaces_queue_errors() {
    let mem = queue_memory();
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock, false);
    // A used ring outside guest memory: disabling notifications writes its
    // flags and fails.
    queue.set_used_ring_address(Some(0), Some(0x10));

    let err = drain_queue(&mut queue, &mem, |_| Ok::<_, DrainError>(0))
        .expect_err("the used ring is not in guest memory");
    let DrainError::Queue(msg) = err else {
        panic!("expected a queue error, got {err:?}");
    };
    assert!(msg.contains("memory"), "{msg}");

    // A chain whose head index is outside the queue cannot go back on the
    // used ring; that error comes back too, after the callback ran.
    let mock = MockSplitQueue::new(&mem, QUEUE_LEN);
    let mut queue = device_queue(&mock, true);
    let avail = mock.avail_addr().0;
    mem.write_obj(20u16.to_le(), GuestAddress(avail + 4))
        .expect("avail ring entry 0");
    mem.write_obj(1u16.to_le(), GuestAddress(avail + 2))
        .expect("avail idx");
    let mut calls = 0;
    let err = drain_queue(&mut queue, &mem, |_| {
        calls += 1;
        Ok::<_, DrainError>(0)
    })
    .expect_err("head 20 does not fit a 16-entry used ring");
    let DrainError::Queue(msg) = err else {
        panic!("expected a queue error, got {err:?}");
    };
    assert!(msg.contains("descriptor index"), "{msg}");
    assert_eq!(calls, 1);
    assert_eq!(used_idx(&mem), 0);
}
