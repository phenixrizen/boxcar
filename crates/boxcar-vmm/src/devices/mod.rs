// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The devices the VMM puts on its buses. The legacy PIO devices live in
//! [`legacy`]; the virtio-mmio devices come from `boxcar-virtio`.

pub mod legacy;

pub use legacy::{ConsoleOut, EventFdTrigger, LegacyDevices, SerialDevice, I8042};
