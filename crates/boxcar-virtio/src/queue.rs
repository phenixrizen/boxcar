// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Draining a queue without losing a wakeup.

use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_memory::GuestMemoryMmap;

/// Processes every descriptor chain the driver has made available, returning
/// each to the used ring with the length `f` reports, and returns whether the
/// driver wants an interrupt for the buffers just used.
///
/// Notifications from the driver are disabled while the ring is drained and
/// re-enabled before returning. Re-enabling re-checks the available ring, and
/// if the driver added a chain in between (and so may not have notified),
/// the drain starts over; a chain offered at any point before this returns
/// is processed by this call.
///
/// An error from `f` aborts the drain and is returned: the chain `f` failed
/// on is not added to the used ring, and notifications stay disabled, so the
/// caller should treat the queue as broken. Errors from the queue itself
/// (writing the used ring or the notification fields) are returned as well.
/// When `VIRTIO_RING_F_EVENT_IDX` is enabled on `queue`, the result honours
/// the driver's `used_event`; without it the result is always `true`.
///
/// If the available ring keeps announcing chains that cannot be popped (the
/// driver wrote an available index more than a queue's worth ahead, or the
/// ring is not readable), the drain fails with
/// [`virtio_queue::Error::InvalidAvailRingIndex`] instead of spinning. The
/// queue must be ready and inside guest memory ([`QueueT::is_valid`]); a
/// device checks that once, at activation.
pub fn drain_queue<F, E>(queue: &mut Queue, mem: &GuestMemoryMmap, mut f: F) -> Result<bool, E>
where
    F: FnMut(DescriptorChain<&GuestMemoryMmap>) -> Result<u32, E>,
    E: From<virtio_queue::Error>,
{
    // Consecutive passes that popped nothing although the ring said there
    // was more. One is a race with the driver: it published a chain after the
    // last pop and before notifications were re-enabled, and the next pass
    // pops it. Two in a row means the ring cannot be popped at all.
    let mut idle_passes = 0;
    loop {
        queue.disable_notification(mem)?;
        let mut used_any = false;
        while let Some(chain) = queue.pop_descriptor_chain(mem) {
            let head = chain.head_index();
            let len = f(chain)?;
            queue.add_used(mem, head, len)?;
            used_any = true;
        }
        if !queue.enable_notification(mem)? {
            break;
        }
        idle_passes = if used_any { 0 } else { idle_passes + 1 };
        if idle_passes == 2 {
            return Err(virtio_queue::Error::InvalidAvailRingIndex.into());
        }
    }
    Ok(queue.needs_notification(mem)?)
}
