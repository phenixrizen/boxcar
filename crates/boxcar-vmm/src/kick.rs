// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Ported from Firecracker (https://github.com/firecracker-microvm/firecracker),
// src/vmm/src/vstate/vcpu.rs (Vcpu::register_kick_signal_handler and the
// immediate_exit-then-signal sequence of VcpuHandle::send_event) at commit
// 21f19ed8109578108568c8a8f3623ddb6f097878. The BSD-3-Clause text referred to
// above is in LICENSE-BSD-3-Clause. Adapted: the handler is installed once per
// process instead of once per vCPU thread; the kicker writes the vCPU's own
// `kvm_run` mapping through a pointer the vCPU thread publishes (Firecracker
// maps a second view through a dup'd vCPU fd), and publishing and withdrawing
// that pointer under a mutex ties its validity to the vCPU thread's life.

//! Kicking a vCPU thread out of `KVM_RUN` from another thread.
//!
//! A kick sets `kvm_run.immediate_exit`, so a `KVM_RUN` that has not started
//! yet returns `EINTR` at once, and then sends [`kick_signal`] to the thread,
//! so one already running in the guest returns `EINTR` too. The signal's
//! handler does nothing; its only effect is the interrupted ioctl. Together
//! they leave no window in which a kick is lost, provided the vCPU loop
//! checks its stop flag after arming and after every interrupted run, and
//! the kicker sets that flag before kicking.

use std::io;
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{fence, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use kvm_bindings::kvm_run;
use kvm_ioctls::VcpuFd;
use libc::{c_int, c_void, siginfo_t};
use vmm_sys_util::signal::{register_signal_handler, SIGRTMIN};

/// The signal that interrupts a vCPU thread's `KVM_RUN`.
pub fn kick_signal() -> c_int {
    SIGRTMIN()
}

extern "C" fn handle_kick(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
    // Interrupting the ioctl is the whole job. The fence pairs with the
    // kicker's, so the KVM_RUN that follows sees immediate_exit set.
    fence(Ordering::Acquire);
}

/// Installs the no-op handler for [`kick_signal`], without `SA_RESTART`, so
/// the signal makes `KVM_RUN` return `EINTR`. Must run before any vCPU thread
/// starts. The first call installs it; later calls return that result.
pub fn register_kick_handler() -> io::Result<()> {
    static INSTALLED: OnceLock<Result<(), i32>> = OnceLock::new();
    let result = INSTALLED.get_or_init(|| {
        register_signal_handler(kick_signal(), handle_kick).map_err(|error| error.errno())
    });
    result.map_err(io::Error::from_raw_os_error)
}

/// The vCPU thread and its `kvm_run`, while the thread is running the vCPU.
struct Target {
    run: *mut kvm_run,
    thread: libc::pthread_t,
}

// SAFETY: a `Target` is only used under `VcpuKicker::target`'s lock. `run`
// points into the `kvm_run` mapping of a `VcpuFd` that the vCPU thread owns
// and keeps alive until it withdraws the target, and `thread` is that thread,
// which does not exit before withdrawing it (see `KickableVcpu`).
unsafe impl Send for Target {}

/// Kicks one vCPU. The main thread keeps one per vCPU; the vCPU thread arms
/// it through [`KickableVcpu`].
#[derive(Default)]
pub struct VcpuKicker {
    target: Mutex<Option<Target>>,
}

impl VcpuKicker {
    /// A kicker with nothing to kick yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the calling thread, running the vCPU whose `kvm_run` is `run`,
    /// the target of [`kick`](Self::kick).
    ///
    /// # Safety
    ///
    /// `run` must stay valid for writes until [`disarm`](Self::disarm), and
    /// the calling thread must call `disarm` before it exits.
    unsafe fn arm(&self, run: *mut kvm_run) {
        // SAFETY: pthread_self has no preconditions.
        let thread = unsafe { libc::pthread_self() };
        *self.lock() = Some(Target { run, thread });
    }

    /// Withdraws the target. Waits for a kick in progress to finish.
    fn disarm(&self) {
        *self.lock() = None;
    }

    /// Makes the vCPU leave `KVM_RUN` as soon as possible, or not enter it.
    /// Does nothing when no vCPU thread is armed: one that has not armed yet
    /// checks the stop flag once it has, and one that disarmed is gone.
    pub fn kick(&self) {
        let target = self.lock();
        let Some(target) = target.as_ref() else {
            return;
        };
        // SAFETY: the target is armed, so `run` is valid (see `Target`).
        unsafe { ptr::addr_of_mut!((*target.run).immediate_exit).write_volatile(1) };
        fence(Ordering::SeqCst);
        // SAFETY: the target is armed, so the thread has not exited.
        let ret = unsafe { libc::pthread_kill(target.thread, kick_signal()) };
        if ret != 0 {
            tracing::warn!(
                "cannot signal a vCPU thread: {}",
                io::Error::from_raw_os_error(ret)
            );
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Target>> {
        self.target.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A vCPU armed for kicking, owned by the thread that runs it. Creating it
/// arms the kicker with this thread and the vCPU's `kvm_run`; dropping it
/// disarms the kicker before the `VcpuFd` (and its mapping) goes away. It
/// cannot leave the thread that created it.
pub struct KickableVcpu {
    kicker: Arc<VcpuKicker>,
    vcpu: VcpuFd,
    _this_thread: PhantomData<*const ()>,
}

impl KickableVcpu {
    /// Arms `kicker` for `vcpu` on the calling thread, which must be the one
    /// that runs it.
    pub fn new(kicker: Arc<VcpuKicker>, mut vcpu: VcpuFd) -> Self {
        let run: *mut kvm_run = vcpu.get_kvm_run();
        // SAFETY: the mapping lives as long as `vcpu`, which this struct owns
        // and drops only after `Drop::drop` disarms, on this same thread
        // (the struct is neither Send nor Sync).
        unsafe { kicker.arm(run) };
        KickableVcpu {
            kicker,
            vcpu,
            _this_thread: PhantomData,
        }
    }

    /// The vCPU, to run it and handle its exits.
    pub fn fd(&mut self) -> &mut VcpuFd {
        &mut self.vcpu
    }

    /// Clears `immediate_exit` after an interrupted run. The caller checks
    /// its stop flag afterwards; the fence orders that load after the clear.
    pub fn clear_immediate_exit(&mut self) {
        let run: *mut kvm_run = self.vcpu.get_kvm_run();
        // SAFETY: `run` points into this vCPU's live mapping. The write is
        // volatile like the kicker's.
        unsafe { ptr::addr_of_mut!((*run).immediate_exit).write_volatile(0) };
        fence(Ordering::SeqCst);
    }
}

impl Drop for KickableVcpu {
    fn drop(&mut self) {
        self.kicker.disarm();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn kick_without_an_armed_vcpu_does_nothing() {
        let kicker = VcpuKicker::new();
        kicker.kick();
        let mut run = Box::new(kvm_run::default());
        // SAFETY: `run` outlives the disarm below, on this thread.
        unsafe { kicker.arm(&mut *run) };
        kicker.disarm();
        kicker.kick();
        assert_eq!(run.immediate_exit, 0);
    }

    /// Without KVM: an armed thread blocked in a syscall is interrupted with
    /// `EINTR`, and its `immediate_exit` is set.
    #[test]
    fn kick_sets_immediate_exit_and_interrupts_a_blocked_thread() {
        register_kick_handler().unwrap();
        let kicker = Arc::new(VcpuKicker::new());
        let (armed, is_armed) = mpsc::channel();
        let vcpu_thread = thread::spawn({
            let kicker = kicker.clone();
            move || {
                let mut run = Box::new(kvm_run::default());
                let mut fds = [0; 2];
                // SAFETY: `fds` has room for both ends.
                assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
                // SAFETY: `run` outlives the disarm below, on this thread.
                unsafe { kicker.arm(&mut *run) };
                armed.send(()).unwrap();
                let mut byte = 0u8;
                // Nobody writes the pipe: only a signal ends this read.
                // SAFETY: reads one byte into `byte`.
                let ret = unsafe { libc::read(fds[0], ptr::addr_of_mut!(byte).cast(), 1) };
                let errno = io::Error::last_os_error().raw_os_error();
                kicker.disarm();
                // SAFETY: both ends are open and closed once.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                (ret, errno, run.immediate_exit)
            }
        });
        is_armed.recv().unwrap();
        // The first kick can land before the thread blocks in read; kick
        // until the read returns.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !vcpu_thread.is_finished() {
            assert!(
                Instant::now() < deadline,
                "the kick never interrupted the read"
            );
            kicker.kick();
            thread::sleep(Duration::from_millis(5));
        }
        let (ret, errno, immediate_exit) = vcpu_thread.join().unwrap();
        assert_eq!(ret, -1);
        assert_eq!(errno, Some(libc::EINTR));
        assert_eq!(immediate_exit, 1);
    }
}
