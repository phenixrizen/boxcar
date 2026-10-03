// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from Firecracker (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/devices/legacy/mod.rs (EventFdTrigger) and
// src/vmm/src/devices/legacy/serial.rs (SerialEventsWrapper, SerialOut and
// the BusDevice impl of SerialWrapper) at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: no metrics and no output rate
// limiter; the serial input and its event handling are in crate::stdin; the
// i8042 is vm-superio's reset-only device, not Firecracker's own; devices go
// on boxcar-virtio's Bus, whose BusDevice takes only the offset.

//! The legacy PIO devices: COM1, a 16550A UART at `0x3f8..=0x3ff` on GSI 4
//! (the guest's `ttyS0` console), and an i8042 at `0x60..=0x64` that knows
//! only the CPU reset command, which is how the guest reboots with
//! `reboot=k`. Both are vm-superio devices behind [`BusDevice`] adapters.
//!
//! The UART's output goes into a [`ConsoleSink`], which never blocks: the
//! vCPU thread that wrote the byte to the port is never held by the host's
//! stdout (see [`crate::console`]).

use std::io;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use boxcar_virtio::bus::{Bus, BusDevice, BusError};
use vm_superio::serial::{Error as SerialError, SerialEvents};
use vm_superio::{I8042Device, Serial, Trigger};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::console::ConsoleSink;

/// COM1's first port.
pub const COM1_BASE: u64 = 0x3f8;
/// COM1's eight registers.
pub const COM1_LEN: u64 = 8;
/// COM1's legacy IRQ line.
pub const COM1_GSI: u32 = 4;
/// The i8042 data port; the command and status port is `0x64`.
pub const I8042_BASE: u64 = 0x60;
/// `0x60..=0x64`: the command port is offset 4.
pub const I8042_LEN: u64 = 5;

/// A vm-superio [`Trigger`] that writes an [`EventFd`]: the serial's
/// interrupt line (registered as an irqfd) and the i8042's reset event.
#[derive(Debug)]
pub struct EventFdTrigger(pub EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.0.write(1)
    }
}

impl Deref for EventFdTrigger {
    type Target = EventFd;

    fn deref(&self) -> &EventFd {
        &self.0
    }
}

/// The UART's event callbacks. Only one matters: when the guest has read the
/// receive FIFO empty, `buffer_ready` is written so the stdin subscriber can
/// start reading host input again.
#[derive(Debug)]
pub struct ConsoleEvents {
    buffer_ready: EventFd,
}

impl SerialEvents for ConsoleEvents {
    fn buffer_read(&self) {}

    fn out_byte(&self) {}

    fn tx_lost_byte(&self) {}

    fn in_buffer_empty(&self) {
        // The counter saturates only after 2^64 - 2 unread events; a failed
        // write therefore means nobody listens, and nothing is lost.
        if let Err(error) = self.buffer_ready.write(1) {
            tracing::debug!("serial: cannot signal an empty input buffer: {error}");
        }
    }
}

type Uart = Serial<EventFdTrigger, ConsoleEvents, ConsoleSink>;

/// COM1. Shared between the PIO bus (the vCPU threads) and the stdin
/// subscriber (the main thread) behind an `Arc<Mutex>`.
pub struct SerialDevice {
    uart: Uart,
}

impl SerialDevice {
    /// A UART writing to `out`, with fresh non-blocking eventfds for its
    /// interrupt and its buffer-ready event.
    pub fn new(out: ConsoleSink) -> io::Result<Self> {
        let interrupt = EventFdTrigger(EventFd::new(EFD_NONBLOCK)?);
        let events = ConsoleEvents {
            buffer_ready: EventFd::new(EFD_NONBLOCK)?,
        };
        Ok(SerialDevice {
            uart: Serial::with_events(interrupt, events, out),
        })
    }

    /// The interrupt line: register it as an irqfd on [`COM1_GSI`].
    pub fn interrupt_evt(&self) -> &EventFd {
        self.uart.interrupt_evt()
    }

    /// Written each time the guest reads the receive FIFO empty.
    pub fn buffer_ready_evt(&self) -> &EventFd {
        &self.uart.events().buffer_ready
    }

    /// Free bytes in the receive FIFO.
    pub fn fifo_capacity(&self) -> usize {
        self.uart.fifo_capacity()
    }

    /// Queues host input for the guest, raising the received-data interrupt
    /// when the guest enabled it. Returns how many bytes fit; the rest must
    /// wait for [`buffer_ready_evt`](Self::buffer_ready_evt).
    pub fn enqueue(&mut self, bytes: &[u8]) -> usize {
        let room = self.uart.fifo_capacity();
        match self.uart.enqueue_raw_bytes(bytes) {
            Ok(count) => count,
            Err(SerialError::FullFifo) => 0,
            Err(error) => {
                tracing::warn!("serial: cannot raise the receive interrupt: {error:?}");
                // The bytes are in the FIFO; only the interrupt is missing.
                bytes.len().min(room)
            }
        }
    }
}

impl BusDevice for SerialDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if let (Ok(offset), [byte]) = (u8::try_from(offset), data) {
            *byte = self.uart.read(offset);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let (Ok(offset), [value]) = (u8::try_from(offset), data) else {
            return;
        };
        // The sink never fails; what can is the interrupt line, whose
        // trigger is an eventfd write.
        if let Err(error) = self.uart.write(offset, *value) {
            tracing::warn!("serial: {error:?}");
        }
    }
}

/// The i8042 controller, reduced to the CPU reset command (`0xFE` written to
/// port `0x64`), which writes the reset eventfd. Reads return 0.
pub struct I8042 {
    device: I8042Device<EventFdTrigger>,
}

impl I8042 {
    /// An i8042 that writes `reset_evt` when the guest resets the CPU.
    pub fn new(reset_evt: EventFd) -> Self {
        I8042 {
            device: I8042Device::new(EventFdTrigger(reset_evt)),
        }
    }
}

impl BusDevice for I8042 {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if let (Ok(offset), [byte]) = (u8::try_from(offset), data) {
            *byte = self.device.read(offset);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if let (Ok(offset), [value]) = (u8::try_from(offset), data) {
            if let Err(error) = self.device.write(offset, *value) {
                tracing::error!("i8042: cannot signal the CPU reset: {error}");
            }
        }
    }
}

/// COM1 and the i8042, built together. The VMM registers the serial's
/// interrupt as an irqfd and watches `reset_evt` on its main loop.
pub struct LegacyDevices {
    pub serial: Arc<Mutex<SerialDevice>>,
    pub i8042: Arc<Mutex<I8042>>,
    /// Written by the i8042 when the guest resets the CPU.
    pub reset_evt: EventFd,
}

impl LegacyDevices {
    /// Both devices, the serial writing to `out`.
    pub fn new(out: ConsoleSink) -> io::Result<Self> {
        let reset_evt = EventFd::new(EFD_NONBLOCK)?;
        Ok(LegacyDevices {
            serial: Arc::new(Mutex::new(SerialDevice::new(out)?)),
            i8042: Arc::new(Mutex::new(I8042::new(reset_evt.try_clone()?))),
            reset_evt,
        })
    }

    /// Puts COM1 at [`COM1_BASE`] and the i8042 at [`I8042_BASE`] on `pio`.
    pub fn attach(&self, pio: &mut Bus) -> Result<(), BusError> {
        pio.insert(self.serial.clone(), COM1_BASE, COM1_LEN)?;
        pio.insert(self.i8042.clone(), I8042_BASE, I8042_LEN)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::console::ConsoleWriter;

    /// A console target that keeps what the guest wrote, shared with the
    /// test; it stalls in `write` while the test holds `gate`.
    #[derive(Clone, Default)]
    struct Captured {
        gate: Arc<Mutex<()>>,
        got: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _gate = self.gate.lock().unwrap();
            self.got.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> Vec<u8> {
            self.got.lock().unwrap().clone()
        }
    }

    fn devices_on_a_bus() -> (LegacyDevices, Bus, Captured, ConsoleWriter) {
        let out = Captured::default();
        let (sink, writer) = ConsoleWriter::spawn_with(out.clone()).unwrap();
        let devices = LegacyDevices::new(sink).unwrap();
        let mut pio = Bus::new();
        devices.attach(&mut pio).unwrap();
        (devices, pio, out, writer)
    }

    /// Nothing is pending on a non-blocking eventfd.
    fn is_quiet(evt: &EventFd) -> bool {
        matches!(evt.read(), Err(e) if e.kind() == ErrorKind::WouldBlock)
    }

    #[test]
    fn serial_output_written_through_the_pio_bus_reaches_the_console() {
        let (_devices, pio, out, writer) = devices_on_a_bus();
        for byte in b"hi\r\n" {
            assert!(pio.write(0x3f8, &[*byte]));
        }
        // The console is drained by its own thread.
        assert_eq!(
            writer.flush_and_join(Duration::from_secs(5)).dropped_bytes,
            0
        );
        assert_eq!(out.text(), b"hi\r\n");

        // The line status register reports an empty transmitter.
        let mut lsr = [0u8];
        assert!(pio.read(0x3fd, &mut lsr));
        assert_eq!(lsr[0] & 0x60, 0x60, "LSR {:#x}", lsr[0]);
    }

    /// The vCPU thread's port write returns while the host's stdout is
    /// stalled: a paused pipe reader no longer parks a vCPU in `write_all`
    /// under the serial mutex, which the stop sequence could not free.
    #[test]
    fn a_stalled_console_does_not_hold_the_vcpu_in_the_serial_write() {
        let (devices, pio, out, writer) = devices_on_a_bus();
        let stall = out.gate.lock().unwrap();

        let pio = Arc::new(pio);
        let vcpu_pio = pio.clone();
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let start = Instant::now();
            // Well over the console ring: the guest keeps printing.
            for i in 0..400_000u32 {
                vcpu_pio.write(0x3f8, &[b'a' + (i % 26) as u8]);
            }
            let _ = done.send(start.elapsed());
        });
        let elapsed = finished
            .recv_timeout(Duration::from_secs(20))
            .expect("a serial write blocked on the stalled console");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        // The serial mutex is free too: the stdin side can still use it.
        assert!(devices.serial.try_lock().is_ok());

        drop(stall);
        let stats = writer.flush_and_join(Duration::from_secs(10));
        assert!(stats.dropped_bytes > 0);
    }

    #[test]
    fn bytes_enqueued_on_the_shared_serial_are_read_through_the_pio_bus() {
        let (devices, pio, _out, _writer) = devices_on_a_bus();
        // Enable the received-data interrupt (IER bit 0).
        assert!(pio.write(0x3f9, &[0x01]));
        assert_eq!(devices.serial.lock().unwrap().enqueue(b"ok"), 2);
        assert_eq!(
            devices
                .serial
                .lock()
                .unwrap()
                .interrupt_evt()
                .read()
                .unwrap(),
            1
        );

        let mut byte = [0u8];
        assert!(pio.read(0x3f8, &mut byte));
        assert_eq!(byte[0], b'o');
        assert!(pio.read(0x3f8, &mut byte));
        assert_eq!(byte[0], b'k');
    }

    #[test]
    fn i8042_reset_write_fires_the_reset_eventfd() {
        let (devices, pio, _out, _writer) = devices_on_a_bus();
        // 0xFE to the data port (0x60) is not a reset.
        assert!(pio.write(0x60, &[0xfe]));
        assert!(is_quiet(&devices.reset_evt));
        // Another command to 0x64 is not a reset either.
        assert!(pio.write(0x64, &[0xaa]));
        assert!(is_quiet(&devices.reset_evt));

        assert!(pio.write(0x64, &[0xfe]));
        assert_eq!(devices.reset_evt.read().unwrap(), 1);

        // The status register reads 0: never busy, so kb_wait() passes.
        let mut status = [0xffu8];
        assert!(pio.read(0x64, &mut status));
        assert_eq!(status[0], 0);
    }

    #[test]
    fn com1_and_i8042_occupy_their_ports() {
        let (_devices, pio, _out, _writer) = devices_on_a_bus();
        let mut byte = [0u8];
        for port in [0x3f8, 0x3ff, 0x60, 0x64] {
            assert!(pio.read(port, &mut byte), "{port:#x}");
        }
        for port in [0x3f7, 0x400, 0x5f, 0x65] {
            assert!(!pio.read(port, &mut byte), "{port:#x}");
        }
    }
}
