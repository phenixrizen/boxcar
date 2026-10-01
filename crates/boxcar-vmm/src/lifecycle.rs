// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! How a VM stops.
//!
//! Stop triggers: the i8042 reset event, a vCPU's `Shutdown` or
//! `SystemEvent` exit, a vCPU error, `SIGTERM`, `SIGINT`, `SIGHUP` or
//! `SIGQUIT` (read from a signalfd on the main thread), Ctrl-] twice on the
//! console, [`VmmHandle::request_stop`], and the audit log writer failing
//! (its failure eventfd, [`AuditSink::failure_event`]): a VM whose actions
//! can no longer be recorded does not keep running. The first trigger
//! decides the [`VmExit`]; the VM is then `Stopping` and later triggers are
//! ignored.
//!
//! The stop sequence, run on the main thread: kick and join every vCPU,
//! close the devices (reset every virtio-fs device through its transport,
//! which joins its workers and records the close of every file the guest
//! left open, then flush the console), emit `vmm.stop` through the audit
//! sink, restore the terminal, and return the `VmExit`. The caller
//! (`boxcar run`) then closes the audit writer, which drains, checkpoints
//! and syncs the log, so every record the devices made is in it. After an
//! audit failure the sequence is the same; the records it makes are
//! refused, and each refusal is logged.

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

use crate::devices::{FsDevices, LegacyDevices};
use crate::stdin::RawModeGuard;
use crate::vcpu::VcpuSet;

/// The exit code of a run whose audit log failed.
pub const AUDIT_FAILED_EXIT: i32 = 3;

/// Why the VMM was asked to stop the VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// `SIGINT`, `SIGTERM`, `SIGHUP` or `SIGQUIT` arrived; the signal
    /// number.
    Signal(i32),
    /// Ctrl-] was pressed twice within a second on the console.
    ConsoleEscape,
    /// [`VmmHandle::request_stop`] was called.
    Requested,
}

/// How the guest's session ended, as its init reported it: the exit code of
/// the session's process, or the signal that killed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionOutcome {
    /// The exit code, when the process exited.
    pub code: Option<i32>,
    /// The signal number, when a signal killed the process.
    pub signal: Option<i32>,
}

/// How the VM ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// The guest reset the machine: the i8042 reset command, or a triple
    /// fault (`KVM_EXIT_SHUTDOWN`). This is how the guest reboots. `session`
    /// is how the guest's session ended when its init reported that before
    /// the reset, and `None` when it did not.
    GuestReset { session: Option<SessionOutcome> },
    /// The guest reported a system event (`KVM_EXIT_SYSTEM_EVENT`).
    GuestShutdown,
    /// The host stopped the VM.
    StopRequested(StopReason),
    /// A vCPU failed; the message says which and how.
    VcpuError(String),
    /// The audit log's writer failed; the message says where and how.
    AuditFailed(String),
}

/// The process exit code `boxcar run` uses for `exit`, and the one
/// `vmm.stop` records:
///
/// - a guest reset that carries the session's exit code: that code;
/// - one that carries the signal that killed the session: 128 plus the
///   signal number (137 for `SIGKILL`);
/// - a guest reset with no session report, and a guest shutdown: 0;
/// - a vCPU error: 1;
/// - a failed audit log: [`AUDIT_FAILED_EXIT`] (3);
/// - a stop by a host signal: 128 plus the signal number (130 for Ctrl-C,
///   129 for a hangup), and 130 for any other requested stop.
pub fn exit_code_for(exit: &VmExit) -> i32 {
    match exit {
        VmExit::GuestReset {
            session: Some(SessionOutcome {
                code: Some(code), ..
            }),
        } => *code,
        VmExit::GuestReset {
            session:
                Some(SessionOutcome {
                    signal: Some(signal),
                    ..
                }),
        } => 128 + signal,
        VmExit::GuestReset { .. } | VmExit::GuestShutdown => 0,
        VmExit::VcpuError(_) => 1,
        VmExit::AuditFailed(_) => AUDIT_FAILED_EXIT,
        VmExit::StopRequested(StopReason::Signal(signo)) => 128 + signo,
        VmExit::StopRequested(_) => 130,
    }
}

impl VmExit {
    /// The `reason` of the `vmm.stop` record.
    pub fn audit_reason(&self) -> &'static str {
        match self {
            VmExit::GuestReset { .. } => "guest_reset",
            VmExit::GuestShutdown => "guest_shutdown",
            VmExit::StopRequested(StopReason::Signal(_)) => "signal",
            VmExit::StopRequested(StopReason::ConsoleEscape) => "console_escape",
            VmExit::StopRequested(StopReason::Requested) => "stop_requested",
            VmExit::VcpuError(_) => "vcpu_error",
            VmExit::AuditFailed(_) => "audit_failed",
        }
    }
}

impl fmt::Display for VmExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmExit::GuestReset { .. } => f.write_str("guest reset"),
            VmExit::GuestShutdown => f.write_str("guest shutdown"),
            VmExit::StopRequested(StopReason::Signal(signo)) => {
                write!(f, "stopped by signal {signo}")
            }
            VmExit::StopRequested(StopReason::ConsoleEscape) => {
                f.write_str("stopped from the console")
            }
            VmExit::StopRequested(StopReason::Requested) => f.write_str("stop requested"),
            VmExit::VcpuError(message) => write!(f, "vCPU error: {message}"),
            VmExit::AuditFailed(message) => write!(f, "audit log failed: {message}"),
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

/// The signals that stop the VM: `SIGINT` (Ctrl-C), `SIGTERM`, `SIGHUP`
/// (the terminal or the ssh session went away) and `SIGQUIT` (`Ctrl-\`).
/// Each would otherwise kill the process with no stop sequence: no
/// `fs.close` for the files left open, no `vmm.stop`, no final checkpoint,
/// and a terminal left raw.
pub const STOP_SIGNALS: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn stop_sigset() -> io::Result<libc::sigset_t> {
    create_sigset(&STOP_SIGNALS).map_err(|e| io::Error::from_raw_os_error(e.errno()))
}

/// Blocks the [`STOP_SIGNALS`] on the calling thread, and so on every
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

/// A non-blocking signalfd for the [`STOP_SIGNALS`].
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
/// latch's own wake-up, the i8042 reset, the stop signals, each vCPU's
/// "exited" eventfd (the vCPU sends its `VmExit` over `exits` before writing
/// it), and the audit writer's failure eventfd.
pub(crate) struct ControlSubscriber {
    latch: Arc<StopLatch>,
    reset_evt: EventFd,
    signals: SignalFd,
    vcpu_exited: Vec<EventFd>,
    exits: Receiver<VmExit>,
    audit: AuditSink,
}

impl ControlSubscriber {
    pub(crate) fn new(
        latch: Arc<StopLatch>,
        reset_evt: EventFd,
        signals: SignalFd,
        vcpu_exited: Vec<EventFd>,
        exits: Receiver<VmExit>,
        audit: AuditSink,
    ) -> Self {
        ControlSubscriber {
            latch,
            reset_evt,
            signals,
            vcpu_exited,
            exits,
            audit,
        }
    }

    /// Every descriptor to watch for input. The caller registers them, so a
    /// failure reaches it rather than `init`, which cannot report one.
    pub(crate) fn fds(&self) -> Vec<RawFd> {
        let mut fds = vec![
            self.latch.wake.as_raw_fd(),
            self.reset_evt.as_raw_fd(),
            self.signals.as_raw_fd(),
            self.audit.failure_event().as_raw_fd(),
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

    /// The audit writer failed. Its eventfd is not read, so it stays
    /// readable for anyone else who waits on it; this subscriber stops
    /// watching it instead, and stops the VM.
    fn on_audit_failed(&self, events: Events, ops: &mut EventOps) {
        if let Err(error) = ops.remove(events) {
            tracing::warn!("cannot stop watching the audit failure eventfd: {error}");
        }
        let reason = self.audit.failure().map_or_else(
            || "the audit log writer failed".to_owned(),
            |failure| failure.to_string(),
        );
        tracing::error!("audit log failed: {reason}; stopping the VM");
        self.latch.trigger(VmExit::AuditFailed(reason));
    }

    fn on_vcpu_exited(&self, evt: &EventFd) {
        let _ = evt.read();
        while let Ok(exit) = self.exits.try_recv() {
            self.latch.trigger(exit);
        }
    }
}

impl MutEventSubscriber for ControlSubscriber {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let fd = events.fd();
        if fd == self.audit.failure_event().as_raw_fd() {
            self.on_audit_failed(events, ops);
        } else if fd == self.latch.wake.as_raw_fd() {
            let _ = self.latch.wake.read();
        } else if fd == self.reset_evt.as_raw_fd() {
            if self.reset_evt.read().is_ok() {
                self.latch.trigger(VmExit::GuestReset { session: None });
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
    pub(crate) fs: &'a FsDevices,
    pub(crate) devices: &'a LegacyDevices,
    pub(crate) audit: &'a AuditSink,
    pub(crate) terminal: Option<RawModeGuard>,
}

/// The stop sequence. The VM is already `Stopping` (a trigger fired, or the
/// main loop failed); `reason` and `exit_code` go into `vmm.stop`.
pub(crate) fn stop(teardown: Teardown<'_>, reason: &str, exit_code: i32) {
    let Teardown {
        vcpus,
        fs,
        devices,
        audit,
        terminal,
    } = teardown;
    vcpus.stop_and_join();
    fs.close();
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
    use event_manager::SubscriberOps;

    use super::*;

    #[test]
    fn exit_codes_and_reasons() {
        let cases = [
            (
                VmExit::GuestReset { session: None },
                0,
                "guest_reset",
                "guest reset",
            ),
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
                VmExit::StopRequested(StopReason::Signal(libc::SIGHUP)),
                129,
                "signal",
                "stopped by signal 1",
            ),
            (
                VmExit::StopRequested(StopReason::Signal(libc::SIGQUIT)),
                131,
                "signal",
                "stopped by signal 3",
            ),
            (
                VmExit::VcpuError("vCPU 0: KVM_EXIT_FAIL_ENTRY".into()),
                1,
                "vcpu_error",
                "vCPU error: vCPU 0: KVM_EXIT_FAIL_ENTRY",
            ),
            (
                VmExit::AuditFailed("cannot sync /a/events.000001.jsonl at seq 9: EIO".into()),
                3,
                "audit_failed",
                "audit log failed: cannot sync /a/events.000001.jsonl at seq 9: EIO",
            ),
        ];
        for (exit, code, reason, text) in cases {
            assert_eq!(exit_code_for(&exit), code, "{exit:?}");
            assert_eq!(exit.audit_reason(), reason, "{exit:?}");
            assert_eq!(exit.to_string(), text);
        }
    }

    #[test]
    fn run_exit_code_maps_session_outcome() {
        let reset = |session| VmExit::GuestReset { session };
        let outcome = |code, signal| Some(SessionOutcome { code, signal });
        let cases = [
            // The session's own exit code, when init reported one.
            (reset(outcome(Some(7), None)), 7),
            (reset(outcome(Some(0), None)), 0),
            // 128 plus the signal that killed the session.
            (reset(outcome(None, Some(9))), 137),
            // A clean reset with no session report.
            (reset(None), 0),
            (reset(outcome(None, None)), 0),
            (VmExit::GuestShutdown, 0),
            (VmExit::VcpuError("vCPU 0".into()), 1),
            (VmExit::AuditFailed("EIO".into()), 3),
            // A host stop signal.
            (
                VmExit::StopRequested(StopReason::Signal(libc::SIGTERM)),
                143,
            ),
            (VmExit::StopRequested(StopReason::Signal(libc::SIGINT)), 130),
        ];
        for (exit, code) in cases {
            assert_eq!(exit_code_for(&exit), code, "{exit:?}");
        }
    }

    #[test]
    fn the_first_trigger_wins_and_wakes_the_loop() {
        let latch = Arc::new(StopLatch::new().unwrap());
        let handle = VmmHandle::new(latch.clone());
        assert_eq!(handle.state(), VmState::Running);
        assert!(latch.outcome().is_none());

        assert!(latch.trigger(VmExit::GuestReset { session: None }));
        handle.request_stop(StopReason::Requested);
        assert!(!latch.trigger(VmExit::VcpuError("late".into())));

        assert_eq!(handle.state(), VmState::Stopping);
        assert_eq!(latch.outcome(), Some(VmExit::GuestReset { session: None }));
        assert_eq!(latch.wake.read().unwrap(), 3);
    }

    #[test]
    fn a_hangup_or_quit_stops_the_vm_like_an_interrupt() {
        let set = stop_sigset().unwrap();
        for signo in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            // SAFETY: `set` is a valid, initialized sigset.
            let member = unsafe { libc::sigismember(&set, signo) };
            assert_eq!(member, 1, "signal {signo} is a stop signal");
        }
    }

    /// Syncs nothing: every sync fails.
    struct BrokenDisk;

    impl boxcar_audit::Syncer for BrokenDisk {
        fn sync(&self, _: &std::fs::File) -> io::Result<()> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    /// The main loop, with only the control subscriber on it, turns the
    /// writer's failure into the VM's outcome: `AuditFailed`, with the
    /// writer's reason.
    #[test]
    fn an_audit_log_failure_stops_the_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = boxcar_audit::WriterConfig::new(tmp.path(), boxcar_proto::SessionId::new());
        let (sink, writer) = boxcar_audit::spawn_with_syncer(cfg, BrokenDisk).unwrap();
        let segment = writer.session_dir().join("events.000001.jsonl");

        let latch = Arc::new(StopLatch::new().unwrap());
        let (_exits_tx, exits) = std::sync::mpsc::channel();
        let control = ControlSubscriber::new(
            latch.clone(),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            SignalFd::new().unwrap(),
            Vec::new(),
            exits,
            sink.clone(),
        );
        let fds = control.fds();
        let mut main_loop: MainLoop = EventManager::new().unwrap();
        let id = main_loop.add_subscriber(Box::new(control));
        let mut ops = main_loop.event_ops(id).unwrap();
        for fd in fds {
            ops.add(Events::new_raw(fd, event_manager::EventSet::IN))
                .unwrap();
        }

        // A critical record is synced at once, and the sync fails.
        record_stop(&sink, "test", 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let exit = loop {
            if let Some(exit) = latch.outcome() {
                break exit;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the audit failure did not stop the VM"
            );
            main_loop.run_with_timeout(100).unwrap();
        };
        let failure = sink.failure().expect("the writer failed");
        assert_eq!(exit, VmExit::AuditFailed(failure.to_string()));
        assert_eq!(failure.path, segment);
        assert_eq!(exit_code_for(&exit), AUDIT_FAILED_EXIT);
        // The eventfd is left readable for anyone else who waits on it.
        assert_eq!(sink.failure_event().read().unwrap(), 1);
        assert!(writer.close().is_err());
    }

    #[test]
    fn a_blocked_signal_is_read_from_the_signalfd() {
        // Run on a thread of its own: the block must not leak into other
        // tests, and the signal goes to this thread only.
        std::thread::spawn(|| {
            block_stop_signals().unwrap();
            let signals = SignalFd::new().unwrap();
            assert_eq!(signals.read().unwrap(), None);
            for signo in STOP_SIGNALS {
                // SAFETY: signals the calling thread, which blocks every
                // stop signal.
                let ret = unsafe { libc::pthread_kill(libc::pthread_self(), signo) };
                assert_eq!(ret, 0);
                assert_eq!(signals.read().unwrap(), Some(signo));
                assert_eq!(signals.read().unwrap(), None);
            }
        })
        .join()
        .unwrap();
    }
}
