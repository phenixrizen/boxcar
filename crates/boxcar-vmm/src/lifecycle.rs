// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! How a VM stops.
//!
//! Stop triggers: the i8042 reset event, a vCPU's `Shutdown` or
//! `SystemEvent` exit, a vCPU error, `SIGTERM` or `SIGINT` (read from a
//! signalfd on the main thread), Ctrl-] twice on the console, and
//! [`VmmHandle::request_stop`]. The first trigger decides the [`VmExit`]; the
//! VM is then `Stopping` and later triggers are ignored.
//!
//! The stop sequence, run on the main thread: kick and join every vCPU,
//! close the devices, emit `vmm.stop` through the audit sink, restore the
//! terminal, and return the `VmExit`. The caller (`boxcar run`) then closes
//! the audit writer, which drains, checkpoints and syncs the log.

use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use boxcar_audit::{AuditSink, Priority, Submission};
use boxcar_proto::{Payload, Ring, VmmStop};
use event_manager::{EventManager, EventOps, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
use vmm_sys_util::signal::create_sigset;

use crate::devices::LegacyDevices;
use crate::stdin::RawModeGuard;
use crate::vcpu::VcpuSet;

/// Why the VMM was asked to stop the VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// `SIGINT` or `SIGTERM` arrived; the signal number.
    Signal(i32),
    /// Ctrl-] was pressed twice within a second on the console.
    ConsoleEscape,
    /// [`VmmHandle::request_stop`] was called.
    Requested,
}

/// How the VM ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// The guest reset the machine: the i8042 reset command, or a triple
    /// fault (`KVM_EXIT_SHUTDOWN`). This is how the guest reboots.
    GuestReset,
    /// The guest reported a system event (`KVM_EXIT_SYSTEM_EVENT`).
    GuestShutdown,
    /// The host stopped the VM.
    StopRequested(StopReason),
    /// A vCPU failed; the message says which and how.
    VcpuError(String),
}

impl VmExit {
    /// The process exit code `boxcar run` uses: 0 when the guest reset or
    /// shut down, 1 after a vCPU error, 128 plus the signal number after a
    /// signal (130 for Ctrl-C), and 130 for any other requested stop.
    pub fn exit_code(&self) -> i32 {
        match self {
            VmExit::GuestReset | VmExit::GuestShutdown => 0,
            VmExit::VcpuError(_) => 1,
            VmExit::StopRequested(StopReason::Signal(signo)) => 128 + signo,
            VmExit::StopRequested(_) => 130,
        }
    }

    /// The `reason` of the `vmm.stop` record.
    pub fn audit_reason(&self) -> &'static str {
        match self {
            VmExit::GuestReset => "guest_reset",
            VmExit::GuestShutdown => "guest_shutdown",
            VmExit::StopRequested(StopReason::Signal(_)) => "signal",
            VmExit::StopRequested(StopReason::ConsoleEscape) => "console_escape",
            VmExit::StopRequested(StopReason::Requested) => "stop_requested",
            VmExit::VcpuError(_) => "vcpu_error",
        }
    }
}

impl fmt::Display for VmExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmExit::GuestReset => f.write_str("guest reset"),
            VmExit::GuestShutdown => f.write_str("guest shutdown"),
            VmExit::StopRequested(StopReason::Signal(signo)) => {
                write!(f, "stopped by signal {signo}")
            }
            VmExit::StopRequested(StopReason::ConsoleEscape) => {
                f.write_str("stopped from the console")
            }
            VmExit::StopRequested(StopReason::Requested) => f.write_str("stop requested"),
            VmExit::VcpuError(message) => write!(f, "vCPU error: {message}"),
        }
    }
}

/// Where the VM is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmState {
    Running,
    /// A stop trigger fired; the stop sequence runs or has run.
    Stopping,
}

/// Records the first stop trigger and wakes the main loop. Shared by the
/// main loop's subscribers and every [`VmmHandle`].
pub(crate) struct StopLatch {
    exit: Mutex<Option<VmExit>>,
    /// Written on every trigger so the main loop's epoll returns.
    wake: EventFd,
}

impl StopLatch {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(StopLatch {
            exit: Mutex::new(None),
            wake: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    /// Makes `exit` the VM's outcome unless a trigger came first, and wakes
    /// the main loop. Returns whether this trigger was the first.
    pub(crate) fn trigger(&self, exit: VmExit) -> bool {
        let first = {
            let mut slot = self.lock();
            if slot.is_none() {
                tracing::debug!("stopping: {exit}");
                *slot = Some(exit);
                true
            } else {
                tracing::debug!("ignoring a later stop trigger: {exit}");
                false
            }
        };
        if let Err(error) = self.wake.write(1) {
            tracing::warn!("cannot wake the main loop: {error}");
        }
        first
    }

    pub(crate) fn state(&self) -> VmState {
        match *self.lock() {
            None => VmState::Running,
            Some(_) => VmState::Stopping,
        }
    }

    /// The outcome, once a trigger fired.
    pub(crate) fn outcome(&self) -> Option<VmExit> {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, Option<VmExit>> {
        self.exit.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Stops a VM from another thread. Cheap to clone.
#[derive(Clone)]
pub struct VmmHandle {
    latch: Arc<StopLatch>,
}

impl VmmHandle {
    pub(crate) fn new(latch: Arc<StopLatch>) -> Self {
        VmmHandle { latch }
    }

    /// Asks the VM to stop with `reason`. Returns at once; `Vmm::run` then
    /// runs the stop sequence and returns `VmExit::StopRequested(reason)`,
    /// unless another trigger came first.
    pub fn request_stop(&self, reason: StopReason) {
        self.latch.trigger(VmExit::StopRequested(reason));
    }

    /// Whether the VM is still running.
    pub fn state(&self) -> VmState {
        self.latch.state()
    }
}

/// `SIGINT` and `SIGTERM`, the signals that stop the VM.
fn stop_sigset() -> io::Result<libc::sigset_t> {
    create_sigset(&[libc::SIGINT, libc::SIGTERM])
        .map_err(|e| io::Error::from_raw_os_error(e.errno()))
}

/// Blocks `SIGINT` and `SIGTERM` on the calling thread, and so on every
/// thread it starts afterwards, so that they reach the VMM only through its
/// signalfd. Call it before starting any thread: a thread that leaves them
/// unblocked would take the signal's default action and kill the process.
/// `Vmm::run` calls it too, before it starts the vCPU threads.
pub fn block_stop_signals() -> io::Result<()> {
    let set = stop_sigset()?;
    // SAFETY: `set` is a valid sigset and the old mask is not requested.
    let ret = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut()) };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }
    Ok(())
}

/// A non-blocking signalfd for `SIGINT` and `SIGTERM`.
pub(crate) struct SignalFd(OwnedFd);

impl SignalFd {
    pub(crate) fn new() -> io::Result<Self> {
        let set = stop_sigset()?;
        // SAFETY: `set` is a valid sigset; the result is checked.
        let fd = unsafe { libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new descriptor that nothing else owns.
        Ok(SignalFd(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// The number of the next pending stop signal, or `None` when there is
    /// none.
    pub(crate) fn read(&self) -> io::Result<Option<i32>> {
        // SAFETY: signalfd_siginfo is plain data; all zeroes is valid.
        let mut info: libc::signalfd_siginfo = unsafe { mem::zeroed() };
        let size = mem::size_of::<libc::signalfd_siginfo>();
        // SAFETY: reads at most `size` bytes into `info`.
        let n = unsafe { libc::read(self.0.as_raw_fd(), ptr::addr_of_mut!(info).cast(), size) };
        if n < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
                _ => Err(error),
            };
        }
        if usize::try_from(n).ok() != Some(size) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("short signalfd read of {n} bytes"),
            ));
        }
        Ok(i32::try_from(info.ssi_signo).ok())
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// The main loop's subscribers, of either kind.
pub(crate) type MainLoop = EventManager<Box<dyn MutEventSubscriber>>;

/// Turns the main loop's stop events into [`StopLatch::trigger`] calls: the
/// latch's own wake-up, the i8042 reset, the stop signals, and each vCPU's
/// "exited" eventfd (the vCPU sends its `VmExit` over `exits` before writing
/// it).
pub(crate) struct ControlSubscriber {
    latch: Arc<StopLatch>,
    reset_evt: EventFd,
    signals: SignalFd,
    vcpu_exited: Vec<EventFd>,
    exits: Receiver<VmExit>,
}

impl ControlSubscriber {
    pub(crate) fn new(
        latch: Arc<StopLatch>,
        reset_evt: EventFd,
        signals: SignalFd,
        vcpu_exited: Vec<EventFd>,
        exits: Receiver<VmExit>,
    ) -> Self {
        ControlSubscriber {
            latch,
            reset_evt,
            signals,
            vcpu_exited,
            exits,
        }
    }

    /// Every descriptor to watch for input. The caller registers them, so a
    /// failure reaches it rather than `init`, which cannot report one.
    pub(crate) fn fds(&self) -> Vec<RawFd> {
        let mut fds = vec![
            self.latch.wake.as_raw_fd(),
            self.reset_evt.as_raw_fd(),
            self.signals.as_raw_fd(),
        ];
        fds.extend(self.vcpu_exited.iter().map(AsRawFd::as_raw_fd));
        fds
    }

    fn on_signal(&self) {
        loop {
            match self.signals.read() {
                Ok(Some(signo)) => {
                    self.latch
                        .trigger(VmExit::StopRequested(StopReason::Signal(signo)));
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::error!("cannot read the signalfd: {error}");
                    break;
                }
            }
        }
    }

    fn on_vcpu_exited(&self, evt: &EventFd) {
        let _ = evt.read();
        while let Ok(exit) = self.exits.try_recv() {
            self.latch.trigger(exit);
        }
    }
}

impl MutEventSubscriber for ControlSubscriber {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        let fd = events.fd();
        if fd == self.latch.wake.as_raw_fd() {
            let _ = self.latch.wake.read();
        } else if fd == self.reset_evt.as_raw_fd() {
            if self.reset_evt.read().is_ok() {
                self.latch.trigger(VmExit::GuestReset);
            }
        } else if fd == self.signals.as_raw_fd() {
            self.on_signal();
        } else if let Some(evt) = self.vcpu_exited.iter().find(|e| e.as_raw_fd() == fd) {
            self.on_vcpu_exited(evt);
        }
    }

    /// Registration happens in the caller; see [`ControlSubscriber::fds`].
    fn init(&mut self, _ops: &mut EventOps) {}
}

/// Runs the main loop until a stop trigger fires, and returns its outcome.
pub(crate) fn wait_for_stop(
    main_loop: &mut MainLoop,
    latch: &StopLatch,
) -> Result<VmExit, event_manager::Error> {
    loop {
        if let Some(exit) = latch.outcome() {
            return Ok(exit);
        }
        main_loop.run()?;
    }
}

/// What the stop sequence takes apart.
pub(crate) struct Teardown<'a> {
    pub(crate) vcpus: VcpuSet,
    pub(crate) devices: &'a LegacyDevices,
    pub(crate) audit: &'a AuditSink,
    pub(crate) terminal: Option<RawModeGuard>,
}

/// The stop sequence. The VM is already `Stopping` (a trigger fired, or the
/// main loop failed); `reason` and `exit_code` go into `vmm.stop`.
pub(crate) fn stop(teardown: Teardown<'_>, reason: &str, exit_code: i32) {
    let Teardown {
        vcpus,
        devices,
        audit,
        terminal,
    } = teardown;
    vcpus.stop_and_join();
    devices.close();
    record_stop(audit, reason, exit_code);
    drop(terminal);
}

/// Emits `vmm.stop`, synced as soon as it is written.
pub(crate) fn record_stop(audit: &AuditSink, reason: &str, exit_code: i32) {
    let record = Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload: Payload::VmmStop(VmmStop {
            reason: reason.to_owned(),
            exit_code: Some(exit_code),
        }),
        span: None,
        priority: Priority::Critical,
    };
    if let Err(error) = audit.emit(record) {
        tracing::error!("cannot record vmm.stop: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_and_reasons() {
        let cases = [
            (VmExit::GuestReset, 0, "guest_reset", "guest reset"),
            (VmExit::GuestShutdown, 0, "guest_shutdown", "guest shutdown"),
            (
                VmExit::StopRequested(StopReason::Signal(libc::SIGINT)),
                130,
                "signal",
                "stopped by signal 2",
            ),
            (
                VmExit::StopRequested(StopReason::Signal(libc::SIGTERM)),
                143,
                "signal",
                "stopped by signal 15",
            ),
            (
                VmExit::StopRequested(StopReason::ConsoleEscape),
                130,
                "console_escape",
                "stopped from the console",
            ),
            (
                VmExit::VcpuError("vCPU 0: KVM_EXIT_FAIL_ENTRY".into()),
                1,
                "vcpu_error",
                "vCPU error: vCPU 0: KVM_EXIT_FAIL_ENTRY",
            ),
        ];
        for (exit, code, reason, text) in cases {
            assert_eq!(exit.exit_code(), code, "{exit:?}");
            assert_eq!(exit.audit_reason(), reason, "{exit:?}");
            assert_eq!(exit.to_string(), text);
        }
    }

    #[test]
    fn the_first_trigger_wins_and_wakes_the_loop() {
        let latch = Arc::new(StopLatch::new().unwrap());
        let handle = VmmHandle::new(latch.clone());
        assert_eq!(handle.state(), VmState::Running);
        assert!(latch.outcome().is_none());

        assert!(latch.trigger(VmExit::GuestReset));
        handle.request_stop(StopReason::Requested);
        assert!(!latch.trigger(VmExit::VcpuError("late".into())));

        assert_eq!(handle.state(), VmState::Stopping);
        assert_eq!(latch.outcome(), Some(VmExit::GuestReset));
        assert_eq!(latch.wake.read().unwrap(), 3);
    }

    #[test]
    fn a_blocked_signal_is_read_from_the_signalfd() {
        // Run on a thread of its own: the block must not leak into other
        // tests, and the signal goes to this thread only.
        std::thread::spawn(|| {
            block_stop_signals().unwrap();
            let signals = SignalFd::new().unwrap();
            assert_eq!(signals.read().unwrap(), None);
            // SAFETY: signals the calling thread, which blocks SIGTERM.
            let ret = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
            assert_eq!(ret, 0);
            assert_eq!(signals.read().unwrap(), Some(libc::SIGTERM));
            assert_eq!(signals.read().unwrap(), None);
        })
        .join()
        .unwrap();
    }
}
