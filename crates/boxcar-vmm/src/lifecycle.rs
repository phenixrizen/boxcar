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
//! A guest reset carries how the session ended when the guest's init
//! reported it over the control channel ([`crate::guest_ctl`]), which init
//! does, and waits for the VMM to take, before it reboots. A graceful stop
//! ([`VmmHandle::request_graceful_stop`], the control socket's `stop`)
//! comes before any trigger: it asks init to end the session
//! (`shutdown{grace_ms}`), which makes the VM `Stopping`; the guest's reset
//! is then the requested stop, and when none comes within the grace and
//! [`GRACEFUL_STOP_MARGIN`], the VMM stops the VM itself.
//!
//! The stop sequence, run on the main thread: tell the control clients the
//! VM is `stopping`, kick and join every vCPU, close the devices (reset
//! every virtio-fs device through its transport, which joins its workers
//! and records the close of every file the guest left open, the network
//! card, whose net thread records the end of every flow before it is
//! joined, and the vsock device, whose vsock thread records the end of
//! every connection before it is joined, and whose host socket is then
//! unlinked), wait at most [`CLOSE_DEADLINE`] for the guest control
//! channel's threads (so a report init sent last is recorded), close the
//! PTY hub's stream (its clients get the end of the session's output), let
//! the
//! console writer drain what it can for at most [`CONSOLE_DEADLINE`]
//! (it counts what it could not deliver), mark the VM `stopped` and shut
//! the control server down (each client hears `stopped` and is
//! disconnected, with no wait on any of them), emit `vmm.stop` through the
//! audit sink with that count as `console_dropped_bytes` (and the stdin
//! subscriber's as `stdin_dropped_bytes`), restore the terminal, and return
//! the `VmExit`. Nothing the sequence does on purpose is logged before the
//! terminal is restored: stderr may be the very sink the console is stalled
//! on (`2>&1 | slow-reader`, a terminal held by XOFF), and a blocked log
//! write would hold the stop. The only log calls left on that path report
//! faults (a panicked thread, a failed syscall, a refused audit record), and
//! `vmm.stop`'s own failure is logged after the terminal is restored. The
//! caller (`boxcar run`) then closes
//! the audit writer, which drains, checkpoints and syncs the log, so every
//! record the devices made is in it. After an audit failure the sequence is
//! the same; the records it makes are refused, and each refusal is logged.

use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use boxcar_audit::{AuditSink, EmitError, Priority, Submission};
use boxcar_proto::control::{AuditStatus, Status};
use boxcar_proto::guest::HostMsg;
use boxcar_proto::{Payload, Ring, VmmStop};
use event_manager::{EventManager, EventOps, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
use vmm_sys_util::signal::create_sigset;

use crate::console::ConsoleWriter;
use crate::control::ControlServer;
use crate::devices::{FsDevices, NetDevice, VsockDevice};
use crate::guest_ctl::{GuestCtl, GuestCtlHandle, CLOSE_DEADLINE};
use crate::policy::LivePolicy;
use crate::pty::PtyHub;
use crate::sensor_ingest::SensorIngest;
use crate::services::ServiceRegistry;
use crate::stdin::RawModeGuard;
use crate::vcpu::VcpuSet;

pub use boxcar_proto::control::{SessionOutcome, VmState};

/// The exit code of a run whose audit log failed.
pub const AUDIT_FAILED_EXIT: i32 = 3;

/// How much longer than the grace a graceful stop waits for the guest to
/// reset before the VMM stops the VM itself.
pub const GRACEFUL_STOP_MARGIN: Duration = Duration::from_secs(3);

/// How long the stop sequence waits for the console writer to drain what
/// the guest printed last. A host stdout that has stalled (a paused pipe
/// reader) must not hold the stop up longer.
pub const CONSOLE_DEADLINE: Duration = Duration::from_secs(2);

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
/// - a guest reset that carries the session's exit code: that code,
///   clamped to 0..=255 (init reports it; the code wins when a report
///   somehow has a signal too);
/// - one that carries the signal that killed the session: 128 plus the
///   signal number (137 for `SIGKILL`), at most 255;
/// - a guest reset with no session report, and a guest shutdown: 0;
/// - a vCPU error: 1;
/// - a failed audit log: [`AUDIT_FAILED_EXIT`] (3);
/// - a stop by a host signal: 128 plus the signal number (130 for Ctrl-C,
///   129 for a hangup), and 130 for the console escape;
/// - a stop asked for through [`VmmHandle::request_stop`] or
///   [`VmmHandle::request_graceful_stop`] (the control socket's `stop`): 0,
///   whatever the session did.
pub fn exit_code_for(exit: &VmExit) -> i32 {
    match exit {
        VmExit::GuestReset {
            session: Some(SessionOutcome {
                code: Some(code), ..
            }),
        } => (*code).clamp(0, 255),
        VmExit::GuestReset {
            session:
                Some(SessionOutcome {
                    signal: Some(signal),
                    ..
                }),
        } => signal_exit_code(*signal),
        VmExit::GuestReset { .. } | VmExit::GuestShutdown => 0,
        VmExit::VcpuError(_) => 1,
        VmExit::AuditFailed(_) => AUDIT_FAILED_EXIT,
        VmExit::StopRequested(StopReason::Signal(signo)) => signal_exit_code(*signo),
        VmExit::StopRequested(StopReason::ConsoleEscape) => 130,
        VmExit::StopRequested(StopReason::Requested) => 0,
    }
}

/// 128 plus `signal`, as a shell reports a process the signal killed;
/// saturating at 255, and 128 for a signal number below 0.
fn signal_exit_code(signal: i32) -> i32 {
    128_i32.saturating_add(signal.max(0)).min(255)
}

/// What a guest reset means: the stop that was asked for when a graceful
/// stop is under way, else the reset with how the session ended, when init
/// reported it.
pub(crate) fn reset_exit(graceful: bool, session: Option<SessionOutcome>) -> VmExit {
    if graceful {
        VmExit::StopRequested(StopReason::Requested)
    } else {
        VmExit::GuestReset { session }
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
            VmExit::GuestReset {
                session:
                    Some(SessionOutcome {
                        code: Some(code), ..
                    }),
            } => write!(f, "guest reset; the session exited {code}"),
            VmExit::GuestReset {
                session:
                    Some(SessionOutcome {
                        signal: Some(signal),
                        ..
                    }),
            } => write!(f, "guest reset; the session was killed by signal {signal}"),
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

/// Records the first stop trigger and wakes the main loop. Shared by the
/// main loop's subscribers and every [`VmmHandle`]. Also keeps where the VM
/// is in its life, [`VmState`]: `Booting` until the vCPUs start, `Running`,
/// `Stopping` from the first trigger or a graceful stop, `Stopped` once the
/// stop sequence has stopped the vCPUs and closed the devices.
pub(crate) struct StopLatch {
    exit: Mutex<Option<VmExit>>,
    /// Written on every trigger so the main loop's epoll returns.
    wake: EventFd,
    running: AtomicBool,
    stopped: AtomicBool,
    /// A graceful stop is under way: init was asked to end the session.
    graceful: AtomicBool,
}

impl StopLatch {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(StopLatch {
            exit: Mutex::new(None),
            wake: EventFd::new(EFD_NONBLOCK)?,
            running: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
        })
    }

    /// Marks a graceful stop under way. Returns whether this call did.
    pub(crate) fn begin_graceful(&self) -> bool {
        !self.graceful.swap(true, Ordering::AcqRel)
    }

    /// Takes back a graceful stop that could not be asked for: the caller
    /// stops the VM at once instead.
    pub(crate) fn cancel_graceful(&self) {
        self.graceful.store(false, Ordering::Release);
    }

    /// Whether a graceful stop is under way.
    pub(crate) fn graceful(&self) -> bool {
        self.graceful.load(Ordering::Acquire)
    }

    /// The vCPU threads have started.
    pub(crate) fn mark_running(&self) {
        self.running.store(true, Ordering::Release);
    }

    /// The stop sequence has stopped the vCPUs and closed the devices.
    pub(crate) fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::Release);
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
        if self.stopped.load(Ordering::Acquire) {
            VmState::Stopped
        } else if self.lock().is_some() || self.graceful() {
            VmState::Stopping
        } else if self.running.load(Ordering::Acquire) {
            VmState::Running
        } else {
            VmState::Booting
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

/// What a [`VmmHandle`] reports about its VM that does not change.
pub(crate) struct VmInfo {
    /// The session's id, or empty for a VM built without a control socket.
    pub(crate) session_id: String,
    /// When the VM was built.
    pub(crate) built: Instant,
    pub(crate) vcpus: u8,
    pub(crate) mem_mib: u64,
    /// The virtio devices present, by slot name in slot order.
    pub(crate) devices: Vec<String>,
    pub(crate) audit: AuditSink,
    /// The services on the internal vsock ports.
    pub(crate) services: Arc<ServiceRegistry>,
    /// The guest control channel: what init reported, and a way to tell it.
    pub(crate) guest: Arc<GuestCtl>,
    /// The session's terminal (port 1025), when the VM has the vsock
    /// device.
    pub(crate) pty: Option<PtyHub>,
    /// The sensor stream (port 1026), when the VM has the vsock device.
    pub(crate) sensor: Option<Arc<SensorIngest>>,
    /// The policy in force: the network policy the net stack reads and
    /// the vsock allowlist, which the control socket's `policy.update`
    /// replaces.
    pub(crate) policy: Arc<LivePolicy>,
    /// The reconciler's span index, which `span.list` reads, when the run
    /// gave one.
    pub(crate) spans: Option<boxcar_audit::SpanIndex>,
}

/// Stops a VM from another thread, and reports its status. Cheap to clone.
#[derive(Clone)]
pub struct VmmHandle {
    latch: Arc<StopLatch>,
    info: Arc<VmInfo>,
}

impl VmmHandle {
    pub(crate) fn new(latch: Arc<StopLatch>, info: Arc<VmInfo>) -> Self {
        VmmHandle { latch, info }
    }

    /// Asks the VM to stop with `reason`. Returns at once; `Vmm::run` then
    /// runs the stop sequence and returns `VmExit::StopRequested(reason)`,
    /// unless another trigger came first.
    pub fn request_stop(&self, reason: StopReason) {
        self.latch.trigger(VmExit::StopRequested(reason));
    }

    /// Where the VM is in its life.
    pub fn state(&self) -> VmState {
        self.latch.state()
    }

    /// Asks the guest's init to end the session, giving it `grace_ms`
    /// between `SIGHUP` and `SIGTERM` and `SIGKILL`, when a session runs
    /// (the stop is marked before init is told): see the module
    /// docs. Returns at once, with whether it did; when it did not (no
    /// session runs, or init cannot be told), the caller stops the VM with
    /// [`VmmHandle::request_stop`]. The VM is `Stopping` from here; when it
    /// has not stopped `grace_ms` plus `margin` later, it is stopped as
    /// [`VmmHandle::request_stop`] would. Logs nothing.
    pub fn request_graceful_stop(&self, grace_ms: u64, margin: Duration) -> bool {
        if self.latch.graceful() || self.latch.outcome().is_some() {
            // Under way already.
            return true;
        }
        let guest = &self.info.guest;
        if !guest.session_running() {
            return false;
        }
        // Marked first: a reset that comes as soon as init has the message
        // is the stop that was asked for, never the session's own end.
        if !self.latch.begin_graceful() {
            return true;
        }
        if guest.handle().send(HostMsg::Shutdown { grace_ms }).is_err() {
            self.latch.cancel_graceful();
            return false;
        }
        let wait = Duration::from_millis(grace_ms).saturating_add(margin);
        let latch = Arc::clone(&self.latch);
        let spawned = std::thread::Builder::new()
            .name("graceful-stop".into())
            .spawn(move || fall_back_after(&latch, wait));
        if spawned.is_err() {
            // Nothing would stop a guest that does not reset.
            self.latch
                .trigger(VmExit::StopRequested(StopReason::Requested));
        }
        true
    }

    /// The guest control channel's sending side.
    pub fn guest_ctl(&self) -> GuestCtlHandle {
        self.info.guest.handle()
    }

    /// The PTY hub: the session's terminal, which `boxcar run` and the
    /// control socket's `pty.attach` attach to. `None` without the vsock
    /// device.
    pub fn pty(&self) -> Option<PtyHub> {
        self.info.pty.clone()
    }

    /// The VM's status, as the control socket's `status` reports it, with
    /// what the guest's init reported over the control channel.
    pub fn status(&self) -> Status {
        let info = &self.info;
        Status {
            state: self.state(),
            session_id: info.session_id.clone(),
            pid: std::process::id(),
            uptime_ms: u64::try_from(info.built.elapsed().as_millis()).unwrap_or(u64::MAX),
            vcpus: info.vcpus,
            mem_mib: info.mem_mib,
            guest: info.guest.status(),
            audit: AuditStatus {
                next_seq: info.audit.next_seq(),
                failed: info.audit.has_failed(),
            },
            devices: info.devices.clone(),
            sensor: info
                .sensor
                .as_ref()
                .map(|sensor| sensor.status())
                .unwrap_or_default(),
        }
    }

    /// The session's id; empty for a VM built without a control socket.
    pub(crate) fn session_id(&self) -> &str {
        &self.info.session_id
    }

    /// The sink of the session's audit log.
    pub(crate) fn audit(&self) -> &AuditSink {
        &self.info.audit
    }

    /// The policy in force, and the way to replace it (the control
    /// socket's `policy.get` and `policy.update`).
    pub fn policy(&self) -> &LivePolicy {
        &self.info.policy
    }

    /// The reconciler's span index (the control socket's `span.list`),
    /// when the run keeps one.
    pub fn spans(&self) -> Option<&boxcar_audit::SpanIndex> {
        self.info.spans.as_ref()
    }

    /// The services on the internal vsock ports, where the guest control
    /// channel and the PTY hub register theirs. Empty until they do; the
    /// vsock device, if the VM has one, asks it for every guest connection
    /// to an internal port that its rules let through.
    pub fn services(&self) -> Arc<ServiceRegistry> {
        Arc::clone(&self.info.services)
    }
}

/// Stops the VM as requested unless it has stopped (a trigger fired) by
/// `wait` from now: a graceful stop's fallback.
fn fall_back_after(latch: &StopLatch, wait: Duration) {
    let deadline = Instant::now() + wait;
    loop {
        if latch.outcome().is_some() {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            latch.trigger(VmExit::StopRequested(StopReason::Requested));
            return;
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

/// The signals that stop the VM: `SIGINT` (Ctrl-C), `SIGTERM`, `SIGHUP`
/// (the terminal or the ssh session went away) and `SIGQUIT` (`Ctrl-\`).
/// Each would otherwise kill the process with no stop sequence: no
/// `fs.close` for the files left open, no `vmm.stop`, no final checkpoint,
/// and a terminal left raw.
pub const STOP_SIGNALS: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn sigset(signals: &[i32]) -> io::Result<libc::sigset_t> {
    create_sigset(signals).map_err(|e| io::Error::from_raw_os_error(e.errno()))
}

/// Blocks the [`STOP_SIGNALS`] on the calling thread, and so on every
/// thread it starts afterwards, so that they reach the VMM only through its
/// signalfd. Call it before starting any thread: a thread that leaves them
/// unblocked would take the signal's default action and kill the process.
/// `Vmm::run` calls it too, before it starts the vCPU threads.
pub fn block_stop_signals() -> io::Result<()> {
    block_signals(&STOP_SIGNALS)
}

/// Blocks `signals` on the calling thread and every thread it starts
/// afterwards, so that a [`SignalFd::with`] them sees each one (a signal
/// is taken by any thread that leaves it unblocked): `SIGWINCH` for a
/// terminal's size, read by `boxcar run` and `boxcar attach`.
pub fn block_signals(signals: &[i32]) -> io::Result<()> {
    let set = sigset(signals)?;
    // SAFETY: `set` is a valid sigset and the old mask is not requested.
    let ret = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut()) };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }
    Ok(())
}

/// A non-blocking signalfd for the [`STOP_SIGNALS`] (or other signals,
/// [`SignalFd::with`]): with them blocked ([`block_stop_signals`]), how
/// they are seen.
pub struct SignalFd(OwnedFd);

impl SignalFd {
    pub fn new() -> io::Result<Self> {
        SignalFd::with(&STOP_SIGNALS)
    }

    /// A signalfd for `signals`, which the caller has blocked
    /// ([`block_signals`]).
    pub fn with(signals: &[i32]) -> io::Result<Self> {
        let set = sigset(signals)?;
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
    pub fn read(&self) -> io::Result<Option<i32>> {
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
/// it), and the audit writer's failure eventfd. A guest reset carries what
/// `guest` holds of the session's end ([`reset_exit`]).
pub(crate) struct ControlSubscriber {
    latch: Arc<StopLatch>,
    reset_evt: EventFd,
    signals: SignalFd,
    vcpu_exited: Vec<EventFd>,
    exits: Receiver<VmExit>,
    audit: AuditSink,
    guest: Arc<GuestCtl>,
}

impl ControlSubscriber {
    pub(crate) fn new(
        latch: Arc<StopLatch>,
        reset_evt: EventFd,
        signals: SignalFd,
        vcpu_exited: Vec<EventFd>,
        exits: Receiver<VmExit>,
        audit: AuditSink,
        guest: Arc<GuestCtl>,
    ) -> Self {
        ControlSubscriber {
            latch,
            reset_evt,
            signals,
            vcpu_exited,
            exits,
            audit,
            guest,
        }
    }

    /// The outcome of a guest reset, now.
    fn guest_reset(&self) -> VmExit {
        reset_exit(self.latch.graceful(), self.guest.exit())
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
            let exit = match exit {
                VmExit::GuestReset { .. } => self.guest_reset(),
                exit => exit,
            };
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
                self.latch.trigger(self.guest_reset());
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
    pub(crate) net: &'a NetDevice,
    pub(crate) vsock: &'a VsockDevice,
    /// The guest control channel, whose threads end once the vsock device
    /// is closed.
    pub(crate) guest: &'a GuestCtl,
    /// The PTY hub, whose stream is closed after the vsock device.
    pub(crate) pty: Option<&'a PtyHub>,
    pub(crate) console: ConsoleWriter,
    /// Console input bytes the stdin subscriber dropped, read once the main
    /// loop is done.
    pub(crate) stdin_dropped_bytes: u64,
    pub(crate) control: Option<ControlServer>,
    pub(crate) latch: &'a StopLatch,
    pub(crate) audit: &'a AuditSink,
    pub(crate) terminal: Option<RawModeGuard>,
}

/// The stop sequence. The VM is already `Stopping` (a trigger fired, or the
/// main loop failed); `reason` and `exit_code` go into `vmm.stop`. The
/// control clients hear `stopping` first, then `stopped` as the server
/// shuts down, which closes every connection without waiting on any client,
/// before `vmm.stop`: the log has no `control.*` record after it.
pub(crate) fn stop(teardown: Teardown<'_>, reason: &str, exit_code: i32) {
    let Teardown {
        vcpus,
        fs,
        net,
        vsock,
        guest,
        pty,
        console,
        stdin_dropped_bytes,
        control,
        latch,
        audit,
        terminal,
    } = teardown;
    if let Some(control) = &control {
        control.notify_state(VmState::Stopping);
    }
    vcpus.stop_and_join();
    fs.close();
    net.close();
    vsock.close();
    // What init sent last is recorded before `vmm.stop`.
    guest.close(CLOSE_DEADLINE);
    // The session's output has all come: its clients get their end. Logs
    // nothing and waits on nothing.
    if let Some(pty) = pty {
        pty.close();
    }
    let console = console.flush_and_join(CONSOLE_DEADLINE);
    latch.mark_stopped();
    if let Some(control) = control {
        control.shutdown();
    }
    let counts = StopCounts {
        console_dropped_bytes: console.dropped_bytes,
        stdin_dropped_bytes,
    };
    let recorded = emit_stop(audit, reason, exit_code, counts);
    drop(terminal);
    // After the terminal is back: this write may block on a stalled stderr.
    if let Err(error) = recorded {
        tracing::error!("cannot record vmm.stop: {error}");
    }
}

/// The byte counts `vmm.stop` carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StopCounts {
    /// See [`ConsoleWriter::flush_and_join`].
    pub(crate) console_dropped_bytes: u64,
    /// Console input the host dropped (see [`crate::stdin`]).
    pub(crate) stdin_dropped_bytes: u64,
}

/// Emits `vmm.stop`, synced as soon as it is written, and logs a failure to.
/// The stop sequence uses [`emit_stop`] and logs later.
pub(crate) fn record_stop(audit: &AuditSink, reason: &str, exit_code: i32, counts: StopCounts) {
    if let Err(error) = emit_stop(audit, reason, exit_code, counts) {
        tracing::error!("cannot record vmm.stop: {error}");
    }
}

/// Emits `vmm.stop`, synced as soon as it is written; logs nothing.
fn emit_stop(
    audit: &AuditSink,
    reason: &str,
    exit_code: i32,
    counts: StopCounts,
) -> Result<(), EmitError> {
    let record = Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload: Payload::VmmStop(VmmStop {
            reason: reason.to_owned(),
            exit_code: Some(exit_code),
            console_dropped_bytes: counts.console_dropped_bytes,
            stdin_dropped_bytes: counts.stdin_dropped_bytes,
        }),
        span: None,
        priority: Priority::Critical,
    };
    audit.emit(record)
}

/// A handle on a VM that was never built: a fresh latch, 2 vCPUs, 256 MiB,
/// both virtio-fs devices, an audit log under `dir`, the guest control
/// channel at port 1024 for a login shell as uid 1000, the PTY hub at
/// port 1025, and a policy that denies everything, with a net device's
/// wake nobody reads and an empty vsock allowlist standing for the
/// devices.
#[cfg(test)]
pub(crate) fn test_handle(dir: &std::path::Path) -> (VmmHandle, boxcar_audit::WriterHandle) {
    let session_id = boxcar_proto::SessionId::new();
    let (sink, writer) =
        boxcar_audit::spawn(boxcar_audit::WriterConfig::new(dir, session_id.clone()))
            .expect("audit writer");
    let session =
        crate::guest_ctl::SessionConfig::for_user(vec!["/bin/sh".into(), "-l".into()], 1000, 1000);
    let guest = GuestCtl::new(session, sink.clone());
    let services = Arc::new(ServiceRegistry::new());
    services
        .register(boxcar_vsock::services::CTL_PORT, guest.service())
        .expect("register the control channel");
    let pty = PtyHub::new(guest.handle()).expect("the PTY hub");
    services
        .register(boxcar_vsock::services::PTY_PORT, pty.service())
        .expect("register the PTY hub");
    let sensor = SensorIngest::new(sink.clone());
    services
        .register(boxcar_vsock::services::SENSOR_PORT, sensor.service())
        .expect("register the sensor stream");
    let policy = LivePolicy::new(
        Arc::new(arc_swap::ArcSwap::from_pointee(
            boxcar_net::Policy::default(),
        )),
        Some(EventFd::new(EFD_NONBLOCK).expect("the policy wake")),
        Some(Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()))),
    );
    let info = VmInfo {
        session_id: session_id.to_string(),
        built: Instant::now(),
        vcpus: 2,
        mem_mib: 256,
        devices: vec!["fs:root".into(), "fs:workspace".into()],
        audit: sink,
        services,
        guest,
        pty: Some(pty),
        sensor: Some(sensor),
        policy: Arc::new(policy),
        spans: Some(boxcar_audit::SpanIndex::new()),
    };
    let latch = Arc::new(StopLatch::new().expect("stop latch"));
    (VmmHandle::new(latch, Arc::new(info)), writer)
}

#[cfg(test)]
mod tests {
    use event_manager::SubscriberOps;

    use super::*;

    /// `status.sensor` is `waiting` until the sensor connects and says what
    /// it attached; `off` is for a VM without one, which `test_handle` is
    /// not.
    #[test]
    fn status_reports_the_sensor_once_it_speaks() {
        use std::io::Write;

        use boxcar_proto::control::SensorState;
        use boxcar_proto::sensor::{encode, SensorFrame};
        use boxcar_proto::{Payload, ProcHeartbeat, ProcSensorStatus, SensorPhase};
        use boxcar_vsock::{ConnMeta, InternalServices};

        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        assert_eq!(handle.status().sensor.state, SensorState::Waiting);
        assert_eq!(handle.services().ports(), [1024, 1025, 1026]);
        let mut sensor = handle
            .services()
            .connect(
                boxcar_vsock::services::SENSOR_PORT,
                ConnMeta { guest_port: 1021 },
            )
            .unwrap();
        let status = SensorFrame {
            ts_guest_ns: 1,
            subject: None,
            payload: Payload::ProcSensorStatus(ProcSensorStatus {
                phase: SensorPhase::Attached,
                programs: Vec::new(),
                kernel_release: "6.18.54".into(),
                btf_ok: true,
                session_cgroup_id: 1,
                pid: 77,
                reason: None,
            }),
        };
        let heartbeat = SensorFrame {
            ts_guest_ns: 2,
            subject: None,
            payload: Payload::ProcHeartbeat(ProcHeartbeat {
                uptime_ns: 2,
                events_emitted: 0,
                ringbuf_drops: 0,
                frames_sent: 1,
            }),
        };
        sensor.write_all(&encode(&status).unwrap()).unwrap();
        sensor.write_all(&encode(&heartbeat).unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.status().sensor.heartbeats < 1 {
            assert!(Instant::now() < deadline, "{:?}", handle.status().sensor);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(handle.status().sensor.state, SensorState::Attached);
        drop(sensor);
        writer.close().unwrap();
    }

    #[test]
    fn exit_codes_and_reasons() {
        let cases = [
            (
                VmExit::StopRequested(StopReason::Requested),
                0,
                "stop_requested",
                "stop requested",
            ),
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
        assert_eq!(
            reset(outcome(Some(7), None)).to_string(),
            "guest reset; the session exited 7"
        );
        assert_eq!(
            reset(outcome(None, Some(9))).to_string(),
            "guest reset; the session was killed by signal 9"
        );
        assert_eq!(reset(outcome(None, None)).to_string(), "guest reset");
    }

    /// Guest-supplied values cannot leave 0..=255: a code is clamped, and
    /// 128 plus a signal saturates; a code wins over a signal when both
    /// are somehow set.
    #[test]
    fn exit_codes_are_clamped_and_signals_saturate() {
        let reset = |code, signal| VmExit::GuestReset {
            session: Some(SessionOutcome { code, signal }),
        };
        let cases = [
            (reset(Some(255), None), 255),
            (reset(Some(256), None), 255),
            (reset(Some(300), None), 255),
            (reset(Some(i32::MAX), None), 255),
            (reset(Some(-1), None), 0),
            (reset(Some(i32::MIN), None), 0),
            (reset(None, Some(15)), 143),
            (reset(None, Some(127)), 255),
            (reset(None, Some(128)), 255),
            (reset(None, Some(200)), 255),
            (reset(None, Some(i32::MAX)), 255),
            (reset(None, Some(-5)), 128),
            (reset(Some(3), Some(9)), 3),
            (reset(Some(0), Some(9)), 0),
            (VmExit::StopRequested(StopReason::Signal(200)), 255),
            (VmExit::StopRequested(StopReason::Signal(i32::MAX)), 255),
        ];
        for (exit, code) in cases {
            assert_eq!(exit_code_for(&exit), code, "{exit:?}");
        }
    }

    /// The reset carries the session init reported; after a graceful stop
    /// it is that stop, which exits 0 whatever the session did.
    #[test]
    fn a_reset_carries_the_reported_session_unless_a_stop_was_asked_for() {
        let outcome = SessionOutcome {
            code: None,
            signal: Some(15),
        };
        assert_eq!(
            reset_exit(false, None),
            VmExit::GuestReset { session: None }
        );
        assert_eq!(
            reset_exit(false, Some(outcome)),
            VmExit::GuestReset {
                session: Some(outcome)
            }
        );
        let stopped = reset_exit(true, Some(outcome));
        assert_eq!(stopped, VmExit::StopRequested(StopReason::Requested));
        assert_eq!(exit_code_for(&stopped), 0);
        assert_eq!(
            reset_exit(true, None),
            VmExit::StopRequested(StopReason::Requested)
        );
    }

    /// A fake init on the handle's control channel, with its session
    /// started.
    fn fake_session(handle: &VmmHandle) -> std::io::BufReader<std::os::unix::net::UnixStream> {
        use boxcar_proto::guest::{decode, encode, GuestMsg, HostMsg};
        use boxcar_vsock::InternalServices;
        use std::io::{BufRead, Write};

        let mut stream = handle
            .services()
            .connect(1024, boxcar_vsock::ConnMeta { guest_port: 1023 })
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let hello = GuestMsg::Hello {
            init_version: "0".into(),
            guest_mono_ns: 0,
            guest_real_ns: 0,
        };
        stream.write_all(&encode(&hello).unwrap()).unwrap();
        let mut lines = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut line = Vec::new();
        lines.read_until(b'\n', &mut line).unwrap();
        assert!(matches!(decode(&line).unwrap(), HostMsg::Config(_)));
        stream
            .write_all(&encode(&GuestMsg::SessionStarted { pid: 9 }).unwrap())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.status().guest.session_pid.is_none() {
            assert!(Instant::now() < deadline, "no session");
            std::thread::sleep(Duration::from_millis(5));
        }
        lines
    }

    /// Without a session to end, a graceful stop is not taken: the caller
    /// stops at once.
    #[test]
    fn a_graceful_stop_needs_a_running_session() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        handle.latch.mark_running();
        assert!(!handle.request_graceful_stop(1000, Duration::from_secs(1)));
        assert_eq!(handle.state(), VmState::Running);
        writer.close().unwrap();
    }

    /// With a session, init is asked to end it; the VM is `stopping`, and
    /// stops by itself when the guest never resets.
    #[test]
    fn a_graceful_stop_asks_init_then_falls_back() {
        use boxcar_proto::guest::{decode, HostMsg};
        use std::io::BufRead;

        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        handle.latch.mark_running();
        let mut init = fake_session(&handle);
        let asked = Instant::now();
        assert!(handle.request_graceful_stop(100, Duration::from_millis(100)));
        let mut line = Vec::new();
        init.read_until(b'\n', &mut line).unwrap();
        assert_eq!(
            decode::<HostMsg>(&line).unwrap(),
            HostMsg::Shutdown { grace_ms: 100 }
        );
        assert_eq!(handle.state(), VmState::Stopping);
        // A second graceful stop changes nothing.
        assert!(handle.request_graceful_stop(100, Duration::from_millis(100)));
        let deadline = asked + Duration::from_secs(5);
        let exit = loop {
            if let Some(exit) = handle.latch.outcome() {
                break exit;
            }
            assert!(Instant::now() < deadline, "no fallback stop");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(
            asked.elapsed() >= Duration::from_millis(200),
            "{:?}",
            asked.elapsed()
        );
        assert_eq!(exit, VmExit::StopRequested(StopReason::Requested));
        writer.close().unwrap();
    }

    #[test]
    fn the_first_trigger_wins_and_wakes_the_loop() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let latch = handle.latch.clone();
        latch.mark_running();
        assert_eq!(handle.state(), VmState::Running);
        assert!(latch.outcome().is_none());

        assert!(latch.trigger(VmExit::GuestReset { session: None }));
        handle.request_stop(StopReason::Requested);
        assert!(!latch.trigger(VmExit::VcpuError("late".into())));

        assert_eq!(handle.state(), VmState::Stopping);
        assert_eq!(latch.outcome(), Some(VmExit::GuestReset { session: None }));
        assert_eq!(latch.wake.read().unwrap(), 3);
        writer.close().unwrap();
    }

    /// Booting until the vCPUs start, running, stopping from the first
    /// trigger, stopped once the stop sequence is done; and the rest of the
    /// status from the VM's config and the audit sink.
    #[test]
    fn the_status_follows_the_vm_through_its_life() {
        let tmp = tempfile::tempdir().unwrap();
        let (handle, writer) = test_handle(tmp.path());
        let status = handle.status();
        assert_eq!(status.state, VmState::Booting);
        assert_eq!(status.session_id, handle.session_id());
        assert_eq!(status.pid, std::process::id());
        assert_eq!((status.vcpus, status.mem_mib), (2, 256));
        assert_eq!(status.devices, ["fs:root", "fs:workspace"]);
        assert_eq!(status.guest, boxcar_proto::control::GuestStatus::default());
        assert_eq!(
            status.audit,
            AuditStatus {
                next_seq: 1,
                failed: false
            }
        );

        handle.latch.mark_running();
        assert_eq!(handle.status().state, VmState::Running);
        handle.request_stop(StopReason::Requested);
        assert_eq!(handle.status().state, VmState::Stopping);
        handle.latch.mark_stopped();
        assert_eq!(handle.status().state, VmState::Stopped);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(handle.status().uptime_ms >= 5);
        writer.close().unwrap();
    }

    #[test]
    fn a_hangup_or_quit_stops_the_vm_like_an_interrupt() {
        let set = sigset(&STOP_SIGNALS).unwrap();
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
            GuestCtl::new(
                crate::guest_ctl::SessionConfig::for_user(vec!["sh".into()], 1, 1),
                sink.clone(),
            ),
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
        record_stop(&sink, "test", 0, StopCounts::default());
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
