// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// The exit dispatch follows Firecracker
// (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/vstate/vcpu.rs (Vcpu::run_emulation and handle_kvm_exit) at
// commit 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text
// referred to above is in LICENSE-BSD-3-Clause. Adapted: one thread per vCPU
// with no pause or snapshot states and no event channel; the thread runs
// until a stop flag and a kick end it, or until an exit ends the VM, which
// it reports over a channel and an eventfd; `Shutdown` and every
// `SystemEvent` end the VM instead of being errors or ignored; `FailEntry`
// and `InternalError` dump the registers; unmapped PIO reads return 0xff.

//! The vCPU threads: one `std::thread` per vCPU, each running `KVM_RUN` in a
//! loop and dispatching its exits.
//!
//! | Exit | Action |
//! |---|---|
//! | `IoIn` / `IoOut` | the PIO bus; unmapped reads fill `0xff`, unmapped writes and port `0x80` are ignored |
//! | `MmioRead` / `MmioWrite` | the MMIO bus; unmapped reads fill `0` |
//! | `Hlt` | logged once, continue |
//! | `Shutdown` | ends the VM: `VmExit::GuestReset` |
//! | `SystemEvent` | ends the VM: `VmExit::GuestShutdown` |
//! | `FailEntry` / `InternalError` | registers dumped at error level, `VmExit::VcpuError` |
//! | `Err(EINTR)` / `Err(EAGAIN)` | clear `immediate_exit`, check the stop flag, continue |
//! | any other exit or error | `VmExit::VcpuError` |

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use boxcar_virtio::bus::Bus;
use kvm_ioctls::{VcpuExit, VcpuFd};
use vmm_sys_util::eventfd::EventFd;

use crate::kick::{KickableVcpu, VcpuKicker};
use crate::lifecycle::VmExit;

/// The POST diagnostic port. Linux writes it for I/O delays; it has no device.
pub const DEBUG_PORT: u16 = 0x80;

/// A guest `in`: the device's answer, or `0xff` in every byte when no device
/// covers the access (what an empty ISA bus returns).
pub(crate) fn pio_in(bus: &Bus, port: u16, data: &mut [u8]) {
    data.fill(0xff);
    bus.read(u64::from(port), data);
}

/// A guest `out`: to the device, if any. Port 0x80 is a no-op.
pub(crate) fn pio_out(bus: &Bus, port: u16, data: &[u8]) {
    if port != DEBUG_PORT {
        bus.write(u64::from(port), data);
    }
}

/// A guest MMIO read: the device's answer, or zeroes when there is none.
fn mmio_read(bus: &Bus, addr: u64, data: &mut [u8]) {
    data.fill(0);
    if !bus.read(addr, data) {
        tracing::debug!("unmapped MMIO read at {addr:#x}, {} bytes", data.len());
    }
}

/// A guest MMIO write: to the device, if any.
fn mmio_write(bus: &Bus, addr: u64, data: &[u8]) {
    if !bus.write(addr, data) {
        tracing::debug!("unmapped MMIO write at {addr:#x}, {} bytes", data.len());
    }
}

/// What one `KVM_RUN` told the loop to do.
enum Step {
    /// Handled; run again.
    Continue,
    /// `EINTR` or `EAGAIN`: a kick or a stray signal.
    Interrupted,
    /// The exit ends the VM.
    Exit(VmExit),
    /// The vCPU failed; dump its registers and end the VM with this message.
    Failed(String),
}

/// What a vCPU thread shares with the rest of the VMM.
struct VcpuContext {
    id: u8,
    pio: Arc<Bus>,
    mmio: Arc<Bus>,
    stop: Arc<AtomicBool>,
}

fn dispatch(
    ctx: &VcpuContext,
    result: Result<VcpuExit<'_>, kvm_ioctls::Error>,
    hlt_seen: &mut bool,
) -> Step {
    match result {
        Ok(VcpuExit::IoIn(port, data)) => {
            pio_in(&ctx.pio, port, data);
            Step::Continue
        }
        Ok(VcpuExit::IoOut(port, data)) => {
            pio_out(&ctx.pio, port, data);
            Step::Continue
        }
        Ok(VcpuExit::MmioRead(addr, data)) => {
            mmio_read(&ctx.mmio, addr, data);
            Step::Continue
        }
        Ok(VcpuExit::MmioWrite(addr, data)) => {
            mmio_write(&ctx.mmio, addr, data);
            Step::Continue
        }
        Ok(VcpuExit::Hlt) => {
            if !*hlt_seen {
                *hlt_seen = true;
                tracing::info!("vCPU {}: KVM_EXIT_HLT (logged once)", ctx.id);
            }
            Step::Continue
        }
        Ok(VcpuExit::Shutdown) => Step::Exit(VmExit::GuestReset),
        Ok(VcpuExit::SystemEvent(kind, data)) => {
            tracing::debug!("vCPU {}: system event {kind}, data {data:x?}", ctx.id);
            Step::Exit(VmExit::GuestShutdown)
        }
        Ok(VcpuExit::FailEntry(reason, cpu)) => Step::Failed(format!(
            "vCPU {}: KVM_EXIT_FAIL_ENTRY, hardware entry failure reason {reason:#x} on host CPU {cpu}",
            ctx.id
        )),
        Ok(VcpuExit::InternalError) => {
            Step::Failed(format!("vCPU {}: KVM_EXIT_INTERNAL_ERROR", ctx.id))
        }
        Ok(VcpuExit::Intr) => Step::Interrupted,
        Ok(other) => Step::Failed(format!("vCPU {}: unexpected exit {other:?}", ctx.id)),
        Err(error) if matches!(error.errno(), libc::EINTR | libc::EAGAIN) => Step::Interrupted,
        Err(error) => Step::Failed(format!("vCPU {}: KVM_RUN failed: {error}", ctx.id)),
    }
}

/// Logs the vCPU's registers at error level, for a failure report.
fn dump_registers(id: u8, vcpu: &VcpuFd) {
    match vcpu.get_regs() {
        Ok(regs) => tracing::error!("vCPU {id} regs: {regs:x?}"),
        Err(error) => tracing::error!("vCPU {id}: get_regs failed: {error}"),
    }
    match vcpu.get_sregs() {
        Ok(sregs) => tracing::error!("vCPU {id} sregs: {sregs:x?}"),
        Err(error) => tracing::error!("vCPU {id}: get_sregs failed: {error}"),
    }
}

/// Runs the vCPU until the stop flag is set (`None`) or an exit ends the VM.
fn run_loop(ctx: &VcpuContext, vcpu: &mut KickableVcpu) -> Option<VmExit> {
    let mut hlt_seen = false;
    loop {
        if ctx.stop.load(Ordering::SeqCst) {
            return None;
        }
        let step = dispatch(ctx, vcpu.fd().run(), &mut hlt_seen);
        match step {
            Step::Continue => {}
            Step::Interrupted => vcpu.clear_immediate_exit(),
            Step::Exit(exit) => return Some(exit),
            Step::Failed(message) => {
                // A kick can make KVM_RUN fail after the stop flag is set.
                vcpu.clear_immediate_exit();
                if ctx.stop.load(Ordering::SeqCst) {
                    return None;
                }
                tracing::error!("{message}");
                dump_registers(ctx.id, vcpu.fd());
                return Some(VmExit::VcpuError(message));
            }
        }
    }
}

/// Tells the main loop that this vCPU thread is done, from its drop so it
/// also happens when the thread panics: the exit, if any, over the channel,
/// then the eventfd.
struct ExitNotifier {
    id: u8,
    exit: Option<VmExit>,
    exits: Sender<VmExit>,
    exited: EventFd,
}

impl Drop for ExitNotifier {
    fn drop(&mut self) {
        let exit = if thread::panicking() {
            Some(VmExit::VcpuError(format!(
                "vCPU {} thread panicked",
                self.id
            )))
        } else {
            self.exit.take()
        };
        if let Some(exit) = exit {
            // The receiver outlives every vCPU thread; a send can only fail
            // once the VM is already stopping.
            let _ = self.exits.send(exit);
        }
        if let Err(error) = self.exited.write(1) {
            tracing::error!("vCPU {}: cannot signal its exit: {error}", self.id);
        }
    }
}

fn thread_main(
    ctx: VcpuContext,
    vcpu: VcpuFd,
    kicker: Arc<VcpuKicker>,
    mut notifier: ExitNotifier,
) {
    // Declared after `notifier`, so it drops (disarming the kicker and
    // unmapping kvm_run) before the notifier reports the thread done.
    let mut vcpu = KickableVcpu::new(kicker, vcpu);
    notifier.exit = run_loop(&ctx, &mut vcpu);
}

struct VcpuThread {
    id: u8,
    kicker: Arc<VcpuKicker>,
    handle: JoinHandle<()>,
}

/// The running vCPU threads and their shared stop flag.
pub(crate) struct VcpuSet {
    stop: Arc<AtomicBool>,
    threads: Vec<VcpuThread>,
}

impl VcpuSet {
    /// Starts one thread per vCPU, vCPU `i` being `vcpus[i]`. The thread
    /// sends the `VmExit` that ends its run, if any, over `exits` and then
    /// writes `exited[i]`, also when it panics. The kick handler must be
    /// installed first. On failure the threads already started are stopped.
    pub(crate) fn spawn(
        vcpus: Vec<VcpuFd>,
        pio: &Arc<Bus>,
        mmio: &Arc<Bus>,
        exits: &Sender<VmExit>,
        exited: Vec<EventFd>,
    ) -> io::Result<VcpuSet> {
        if exited.len() != vcpus.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "one exit eventfd per vCPU",
            ));
        }
        let mut set = VcpuSet {
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::with_capacity(vcpus.len()),
        };
        for (index, (vcpu, exited)) in vcpus.into_iter().zip(exited).enumerate() {
            if let Err(error) = set.spawn_one(index, vcpu, pio, mmio, exits, exited) {
                set.stop_and_join();
                return Err(error);
            }
        }
        Ok(set)
    }

    fn spawn_one(
        &mut self,
        index: usize,
        vcpu: VcpuFd,
        pio: &Arc<Bus>,
        mmio: &Arc<Bus>,
        exits: &Sender<VmExit>,
        exited: EventFd,
    ) -> io::Result<()> {
        let id = u8::try_from(index)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many vCPUs"))?;
        let notifier = ExitNotifier {
            id,
            exit: None,
            exits: exits.clone(),
            exited,
        };
        let ctx = VcpuContext {
            id,
            pio: pio.clone(),
            mmio: mmio.clone(),
            stop: self.stop.clone(),
        };
        let kicker = Arc::new(VcpuKicker::new());
        let handle = thread::Builder::new().name(format!("vcpu{id}")).spawn({
            let kicker = kicker.clone();
            move || thread_main(ctx, vcpu, kicker, notifier)
        })?;
        self.threads.push(VcpuThread { id, kicker, handle });
        Ok(())
    }

    /// Sets the stop flag, kicks every vCPU, and joins every thread.
    pub(crate) fn stop_and_join(self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in &self.threads {
            thread.kicker.kick();
        }
        for thread in self.threads {
            if thread.handle.join().is_err() {
                tracing::error!("vCPU {} thread panicked", thread.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use boxcar_virtio::bus::BusDevice;

    use super::*;

    /// Records writes; reads return the offset.
    #[derive(Default)]
    struct Probe {
        writes: Vec<(u64, Vec<u8>)>,
    }

    impl BusDevice for Probe {
        fn read(&mut self, offset: u64, data: &mut [u8]) {
            data.fill(offset as u8);
        }
        fn write(&mut self, offset: u64, data: &[u8]) {
            self.writes.push((offset, data.to_vec()));
        }
    }

    #[test]
    fn unmapped_pio_reads_fill_ff_and_writes_are_ignored() {
        let bus = Bus::new();
        let mut data = [0u8; 4];
        pio_in(&bus, 0x70, &mut data);
        assert_eq!(data, [0xff; 4]);
        pio_out(&bus, 0x70, &[1, 2]);
    }

    #[test]
    fn mapped_pio_reaches_the_device_at_its_offset() {
        let probe = Arc::new(Mutex::new(Probe::default()));
        let mut bus = Bus::new();
        bus.insert(probe.clone(), 0x3f8, 8).unwrap();

        let mut data = [0u8];
        pio_in(&bus, 0x3fd, &mut data);
        assert_eq!(data, [5]);
        pio_out(&bus, 0x3f8, b"x");
        assert_eq!(probe.lock().unwrap().writes, vec![(0, b"x".to_vec())]);
    }

    #[test]
    fn debug_port_writes_are_a_no_op() {
        let probe = Arc::new(Mutex::new(Probe::default()));
        let mut bus = Bus::new();
        bus.insert(probe.clone(), u64::from(DEBUG_PORT), 1).unwrap();
        pio_out(&bus, DEBUG_PORT, &[0x42]);
        assert!(probe.lock().unwrap().writes.is_empty());
    }
}
