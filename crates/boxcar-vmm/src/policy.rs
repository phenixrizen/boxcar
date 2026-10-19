// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session's live policy: what the control socket's `policy.get` reads
//! and `policy.update` replaces (see [`crate::control::ops`]), and the live
//! exceptions on top of it.
//!
//! [`LivePolicy`] holds the permanent policy (the network rules, the vsock
//! allowlist, the path rules of the policy file) apart from up to
//! [`MAX_EXCEPTIONS`] live exceptions, and the handles the devices read:
//! the network policy (`Arc<ArcSwap<Policy>>`, which the net stack loads
//! at every decision) with the net device's policy wake (written after a
//! swap, so the net thread polls at once and revokes what the new policy
//! denies), the vsock allowlist ([`AllowPorts`], which the muxer reads at
//! each guest request), and the path rules every share reads
//! ([`LiveRules`]). Those views are compiled from the permanent policy and
//! the exceptions together at every change, under one lock that also
//! orders the records (`policy.changed`, `policy.exception`), so their
//! versions are in the log's order. 1 is the policy the VM started with,
//! and each update, grant and expiry is the next version.
//!
//! The network policy's wire shape ([`NetPolicy`]) is a default and two
//! lists of targets, allows and denies; the policy in force puts every deny
//! before every allow, as `boxcar run` orders `--deny` and `--allow`, so a
//! deny of a target wins over an allow of it. A rule that does not parse
//! refuses the whole update, naming the rule, and nothing changes.
//!
//! An exception is an `egress` target allowed after the permanent rules
//! (so a permanent deny of it still wins), a `writable` glob, or an `exec`
//! glob lifting `[exec] deny`. It lives `ttl_s` seconds by
//! `CLOCK_BOOTTIME`, which a step of the wall clock does not move and a
//! suspend does not stop; [`ExpiryTimer`] removes it on the main loop.
//! `policy.get` reports the permanent policy and the exceptions apart, and
//! `policy.update` replaces only the permanent part, so no exception
//! becomes permanent by a client writing back what it read.

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use boxcar_audit::{AuditSink, Priority, Submission};
use boxcar_fs::rules::{glob, LiveRules, PathRules, PathSpec};
use boxcar_net::{List, Policy, Verdict};
use boxcar_proto::control::{
    ExceptionGrant, ExceptionKind, ExceptionView, NetPolicy, PolicyUpdateParams, PolicyView,
    VsockPolicy, MAX_EXCEPTIONS,
};
use boxcar_proto::{Payload, PolicyChanged, PolicyException, Ring};
use boxcar_vsock::AllowPorts;
use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

/// The version of the policy a VM starts with.
pub const FIRST_VERSION: u64 = 1;

/// How often the expiry timer looks at the clock while any exception
/// lives, at the longest.
const EXPIRY_RECHECK: Duration = Duration::from_secs(60);

/// The clocks an exception's life is kept by.
pub trait PolicyClock: Send + Sync {
    /// `CLOCK_BOOTTIME`, in nanoseconds: what deadlines are kept in.
    fn boot_ns(&self) -> u64;
    /// `CLOCK_REALTIME`, in nanoseconds since the epoch: what records say
    /// (`expires_ns`, the clock of a record's `ts_host_ns`).
    fn real_ns(&self) -> u64;
}

/// The system's clocks.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemPolicyClock;

impl PolicyClock for SystemPolicyClock {
    fn boot_ns(&self) -> u64 {
        clock_ns(libc::CLOCK_BOOTTIME)
    }

    fn real_ns(&self) -> u64 {
        clock_ns(libc::CLOCK_REALTIME)
    }
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid place for the time; the clock ids used here
    // exist on every kernel boxcar runs on.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    u64::try_from(ts.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(ts.tv_nsec).unwrap_or(0))
}

/// Clocks a test moves by hand.
#[derive(Debug, Default)]
pub struct ManualPolicyClock {
    boot: AtomicU64,
    real: AtomicU64,
}

impl ManualPolicyClock {
    pub fn new(boot_ns: u64, real_ns: u64) -> ManualPolicyClock {
        ManualPolicyClock {
            boot: AtomicU64::new(boot_ns),
            real: AtomicU64::new(real_ns),
        }
    }

    /// Moves both clocks on by `by`.
    pub fn advance(&self, by: Duration) {
        let ns = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.boot.fetch_add(ns, Ordering::AcqRel);
        self.real.fetch_add(ns, Ordering::AcqRel);
    }
}

impl PolicyClock for ManualPolicyClock {
    fn boot_ns(&self) -> u64 {
        self.boot.load(Ordering::Acquire)
    }

    fn real_ns(&self) -> u64 {
        self.real.load(Ordering::Acquire)
    }
}

/// A live exception.
#[derive(Clone, Debug)]
struct Exception {
    id: u32,
    rule: String,
    kind: ExceptionKind,
    ttl_s: u32,
    /// When it expires, by the realtime clock: for the record.
    expires_ns: u64,
    /// When it expires, by `CLOCK_BOOTTIME`: what is enforced.
    deadline: u64,
    by_pid: u32,
}

impl Exception {
    fn view(&self) -> ExceptionView {
        ExceptionView {
            id: self.id,
            rule: self.rule.clone(),
            kind: self.kind,
            ttl_s: self.ttl_s,
            expires_ns: self.expires_ns,
            by_pid: self.by_pid,
        }
    }
}

/// What the lock guards: the permanent policy and the exceptions.
struct State {
    /// The permanent network policy: what `policy.get` reports and
    /// `policy.update` replaces.
    net: Policy,
    /// The permanent path rules; `None` when the session has none.
    paths: Option<PathSpec>,
    exceptions: Vec<Exception>,
    next_id: u32,
}

/// The policy in force, and the way to replace it.
pub struct LivePolicy {
    /// What the net stack reads: the permanent rules with the egress
    /// exceptions after them.
    net: Arc<ArcSwap<Policy>>,
    /// The net device's policy wake; `None` on a VM without the device,
    /// which takes no network update or egress exception.
    net_wake: Option<EventFd>,
    /// The vsock device's allowlist; `None` on a VM without the device,
    /// which takes no vsock update.
    vsock: Option<AllowPorts>,
    /// What every share reads; `None` on a VM without shares.
    fs: Option<LiveRules>,
    /// Where the policy's records go; `None` records nothing (tests).
    audit: Option<AuditSink>,
    clock: Arc<dyn PolicyClock>,
    /// Written at each grant, so the expiry timer re-arms.
    expiry_wake: EventFd,
    version: AtomicU64,
    state: Mutex<State>,
}

/// Why an update was refused. Nothing changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// A network rule does not parse: which list (`allow` or `deny`),
    /// where in it, the rule, and what is wrong with it.
    Rule {
        list: &'static str,
        at: usize,
        rule: String,
        problem: String,
    },
    /// An exception's rule is not one of its kind.
    Exception { rule: String, problem: String },
    /// `net`, or an egress exception, was given, and the VM has no network
    /// card.
    NoNetDevice,
    /// `vsock` was given, and the VM has no vsock device.
    NoVsockDevice,
    /// A writable or exec exception, and the VM has no shares.
    NoShares,
    /// A writable or exec exception, and the session's policy has no path
    /// rules to lift.
    NoPathRules,
    /// [`MAX_EXCEPTIONS`] are live already.
    TooManyExceptions,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Rule {
                list,
                at,
                rule,
                problem,
            } => write!(f, "net.{list}[{at}] {rule:?}: {problem}"),
            UpdateError::Exception { rule, problem } => {
                write!(f, "exception.rule {rule:?}: {problem}")
            }
            UpdateError::NoNetDevice => {
                f.write_str("the VM has no network card, so it has no network policy to update")
            }
            UpdateError::NoVsockDevice => {
                f.write_str("the VM has no vsock device, so it has no vsock allowlist to update")
            }
            UpdateError::NoShares => {
                f.write_str("the VM has no shares, so it has no path rules to lift")
            }
            UpdateError::NoPathRules => f.write_str(
                "the session's policy has no path rules (no --policy file): there is nothing to lift",
            ),
            UpdateError::TooManyExceptions => write!(
                f,
                "{MAX_EXCEPTIONS} exceptions are live already; one more fits once one expires"
            ),
        }
    }
}

impl std::error::Error for UpdateError {}

impl LivePolicy {
    /// The policy in force at the start, version [`FIRST_VERSION`]: `net`
    /// is the handle the net stack reads, `net_wake` the net device's
    /// policy wake (`None` without the device), `vsock` the vsock device's
    /// allowlist (`None` without the device). No path rules, no records,
    /// the system's clocks, until [`with_paths`](Self::with_paths),
    /// [`with_audit`](Self::with_audit) and [`with_clock`](Self::with_clock)
    /// say otherwise.
    pub fn new(
        net: Arc<ArcSwap<Policy>>,
        net_wake: Option<EventFd>,
        vsock: Option<AllowPorts>,
    ) -> io::Result<LivePolicy> {
        let permanent = net.load().as_ref().clone();
        Ok(LivePolicy {
            net,
            net_wake,
            vsock,
            fs: None,
            audit: None,
            clock: Arc::new(SystemPolicyClock),
            expiry_wake: EventFd::new(EFD_NONBLOCK)?,
            version: AtomicU64::new(FIRST_VERSION),
            state: Mutex::new(State {
                net: permanent,
                paths: None,
                exceptions: Vec::new(),
                next_id: 1,
            }),
        })
    }

    /// The shares' path rules: `fs` is what they read, `paths` the
    /// permanent rules it was compiled from (`None`: allow-all).
    pub fn with_paths(mut self, fs: LiveRules, paths: Option<PathSpec>) -> LivePolicy {
        self.fs = Some(fs);
        self.state
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .paths = paths;
        self
    }

    /// Records the policy's changes to `audit`.
    pub fn with_audit(mut self, audit: AuditSink) -> LivePolicy {
        self.audit = Some(audit);
        self
    }

    /// Keeps exceptions' lives by `clock`.
    pub fn with_clock(mut self, clock: Arc<dyn PolicyClock>) -> LivePolicy {
        self.clock = clock;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Every change leaves the state whole before it returns.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The network policy in force: the permanent rules and the egress
    /// exceptions.
    pub fn net(&self) -> Arc<Policy> {
        self.net.load_full()
    }

    /// The vsock allowlist in force; empty without the vsock device.
    pub fn vsock_allow(&self) -> Vec<u32> {
        self.vsock
            .as_ref()
            .map(|allow| allow.load().as_ref().clone())
            .unwrap_or_default()
    }

    /// The version of the policy in force.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// The policy as `policy.get` reports it: the permanent part, and the
    /// live exceptions apart, by id.
    pub fn view(&self) -> PolicyView {
        let state = self.lock();
        PolicyView {
            net: net_view(&state.net),
            vsock: VsockPolicy {
                allow_ports: self.vsock_allow(),
            },
            version: self.version(),
            exceptions: state.exceptions.iter().map(Exception::view).collect(),
        }
    }

    /// The eventfd the expiry timer watches: written at each grant.
    pub fn expiry_wake(&self) -> &EventFd {
        &self.expiry_wake
    }

    /// The clocks exceptions are kept by.
    pub fn clock(&self) -> &dyn PolicyClock {
        self.clock.as_ref()
    }

    /// The earliest deadline of a live exception, by `CLOCK_BOOTTIME`.
    pub fn next_deadline(&self) -> Option<u64> {
        self.lock().exceptions.iter().map(|e| e.deadline).min()
    }

    /// Applies `params` from the client `by_pid` ([`PolicyUpdateParams::check`]
    /// has passed): replaces what it gives of the permanent policy (the
    /// network policy, the vsock allowlist, or both), or grants its one
    /// exception, records the change, and returns the new version.
    /// Everything is checked before anything is swapped: on an error
    /// nothing changed. The net thread is woken after a network swap, to
    /// revoke what the new policy denies.
    pub fn update(&self, params: &PolicyUpdateParams, by_pid: u32) -> Result<u64, UpdateError> {
        if let Some(grant) = &params.exception {
            return self.grant(grant, by_pid);
        }
        let mut state = self.lock();
        let net = match &params.net {
            Some(view) => {
                if self.net_wake.is_none() {
                    return Err(UpdateError::NoNetDevice);
                }
                Some(net_policy(view)?)
            }
            None => None,
        };
        let vsock = match (&params.vsock, &self.vsock) {
            (Some(view), Some(allow)) => Some((view.allow_ports.clone(), allow)),
            (Some(_), None) => return Err(UpdateError::NoVsockDevice),
            (None, _) => None,
        };
        if let Some(policy) = net {
            state.net = policy;
            self.apply_net(&state);
        }
        if let Some((ports, allow)) = vsock {
            allow.store(Arc::new(ports));
        }
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        self.record(Payload::PolicyChanged(PolicyChanged { by_pid, version }));
        Ok(version)
    }

    /// Grants `grant` for the client `by_pid`, records it as
    /// `policy.exception`, wakes the expiry timer, and returns the new
    /// version.
    fn grant(&self, grant: &ExceptionGrant, by_pid: u32) -> Result<u64, UpdateError> {
        let mut state = self.lock();
        if state.exceptions.len() >= MAX_EXCEPTIONS {
            return Err(UpdateError::TooManyExceptions);
        }
        let refused = |problem: String| UpdateError::Exception {
            rule: grant.rule.clone(),
            problem,
        };
        match grant.kind {
            ExceptionKind::Egress => {
                if self.net_wake.is_none() {
                    return Err(UpdateError::NoNetDevice);
                }
                Policy::default()
                    .add(List::Allow, &grant.rule)
                    .map_err(|kind| refused(kind.to_string()))?;
            }
            ExceptionKind::Writable | ExceptionKind::Exec => {
                if self.fs.is_none() {
                    return Err(UpdateError::NoShares);
                }
                if state.paths.is_none() {
                    return Err(UpdateError::NoPathRules);
                }
                glob(&grant.rule).map_err(|error| refused(error.to_string()))?;
            }
        }
        let ttl_ns = u64::from(grant.ttl_s) * 1_000_000_000;
        let exception = Exception {
            id: state.next_id,
            rule: grant.rule.clone(),
            kind: grant.kind,
            ttl_s: grant.ttl_s,
            expires_ns: self.clock.real_ns().saturating_add(ttl_ns),
            deadline: self.clock.boot_ns().saturating_add(ttl_ns),
            by_pid,
        };
        state.next_id += 1;
        state.exceptions.push(exception.clone());
        self.apply(&state, grant.kind);
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        self.record(Payload::PolicyException(PolicyException {
            id: exception.id,
            rule: exception.rule,
            kind: grant.kind.as_str().to_owned(),
            ttl_s: exception.ttl_s,
            expires_ns: exception.expires_ns,
            by_pid,
            version,
        }));
        if let Err(error) = self.expiry_wake.write(1) {
            tracing::warn!("cannot wake the exception timer: {error}");
        }
        Ok(version)
    }

    /// Removes every exception whose deadline has passed, swaps the views,
    /// records `policy.changed{by_pid: 0}`, and returns the new version;
    /// `None`, changing nothing, when none has.
    pub fn expire(&self) -> Option<u64> {
        let mut state = self.lock();
        let now = self.clock.boot_ns();
        let (gone, kept): (Vec<Exception>, Vec<Exception>) = state
            .exceptions
            .drain(..)
            .partition(|exception| exception.deadline <= now);
        state.exceptions = kept;
        if gone.is_empty() {
            return None;
        }
        if gone.iter().any(|e| e.kind == ExceptionKind::Egress) {
            self.apply_net(&state);
        }
        if gone.iter().any(|e| e.kind != ExceptionKind::Egress) {
            self.apply_paths(&state);
        }
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        self.record(Payload::PolicyChanged(PolicyChanged { by_pid: 0, version }));
        Some(version)
    }

    /// Compiles and swaps the view an exception of `kind` changes.
    fn apply(&self, state: &State, kind: ExceptionKind) {
        match kind {
            ExceptionKind::Egress => self.apply_net(state),
            ExceptionKind::Writable | ExceptionKind::Exec => self.apply_paths(state),
        }
    }

    /// The permanent network rules with an allow for each egress exception
    /// after them, swapped in, and the net thread woken.
    fn apply_net(&self, state: &State) {
        let mut compiled = state.net.clone();
        for exception in &state.exceptions {
            if exception.kind == ExceptionKind::Egress {
                // Checked at its grant.
                if let Err(error) = compiled.add(List::Allow, &exception.rule) {
                    tracing::warn!("exception {}: {error}", exception.id);
                }
            }
        }
        self.net.store(Arc::new(compiled));
        if let Some(wake) = &self.net_wake {
            if let Err(error) = wake.write(1) {
                tracing::warn!("cannot wake the net thread for the new policy: {error}");
            }
        }
    }

    /// The permanent path rules with the writable and exec exceptions,
    /// swapped in.
    fn apply_paths(&self, state: &State) {
        let (Some(fs), Some(paths)) = (&self.fs, &state.paths) else {
            return;
        };
        let rules = |kind| {
            state
                .exceptions
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| e.rule.clone())
                .collect::<Vec<_>>()
        };
        let writable = rules(ExceptionKind::Writable);
        let exec = rules(ExceptionKind::Exec);
        match PathRules::new(paths, &writable, &exec) {
            Ok(compiled) => fs.store(Arc::new(compiled)),
            // Checked at their grants: the rules in force stay.
            Err(error) => tracing::warn!("cannot compile the path rules: {error}"),
        }
    }

    /// Records `payload`; one that cannot be recorded is logged, as the
    /// writer has failed or closed and the VM is stopping either way.
    fn record(&self, payload: Payload) {
        let Some(audit) = &self.audit else {
            return;
        };
        let kind = payload.kind();
        let submission = Submission {
            ring: Ring::Host,
            ts_guest_ns: None,
            subject: None,
            payload,
            span: None,
            priority: Priority::Normal,
        };
        if let Err(error) = audit.emit(submission) {
            tracing::warn!("cannot record {kind}: {error}");
        }
    }
}

/// A `CLOCK_BOOTTIME` timerfd, armed relative to now.
struct BootTimer(OwnedFd);

impl BootTimer {
    fn new() -> io::Result<BootTimer> {
        // SAFETY: plain syscall; the result is checked.
        let fd = unsafe {
            libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just made and nothing else owns it.
        Ok(BootTimer(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Fires once, `after` from now; never, for zero.
    fn arm(&self, after: Duration) -> io::Result<()> {
        let value = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: libc::time_t::try_from(after.as_secs()).unwrap_or(libc::time_t::MAX),
                tv_nsec: libc::c_long::from(after.subsec_nanos()),
            },
        };
        // SAFETY: `value` is a valid itimerspec; the old value is not asked.
        let done =
            unsafe { libc::timerfd_settime(self.0.as_raw_fd(), 0, &value, std::ptr::null_mut()) };
        if done < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Takes a firing, if one is there.
    fn clear(&self) {
        let mut count = [0u8; 8];
        // SAFETY: reads at most 8 bytes into `count`; a nonblocking read of
        // a timer that has not fired fails with EAGAIN, which is fine.
        unsafe { libc::read(self.0.as_raw_fd(), count.as_mut_ptr().cast(), count.len()) };
    }
}

/// Removes exceptions as they expire, on the VMM's main loop: a
/// `CLOCK_BOOTTIME` timer armed for the earliest deadline (and at least
/// every [`EXPIRY_RECHECK`] while any lives), re-armed at each grant
/// through [`LivePolicy::expiry_wake`].
pub struct ExpiryTimer {
    policy: Arc<LivePolicy>,
    timer: BootTimer,
    wake: EventFd,
}

impl ExpiryTimer {
    pub fn new(policy: Arc<LivePolicy>) -> io::Result<ExpiryTimer> {
        let wake = policy.expiry_wake().try_clone()?;
        Ok(ExpiryTimer {
            policy,
            timer: BootTimer::new()?,
            wake,
        })
    }

    /// The descriptors to watch for input.
    pub fn fds(&self) -> Vec<RawFd> {
        vec![self.wake.as_raw_fd(), self.timer.0.as_raw_fd()]
    }

    /// Expires what is due and arms the timer for what is next.
    pub fn tick(&self) {
        self.policy.expire();
        let after = match self.policy.next_deadline() {
            Some(deadline) => {
                let left = deadline.saturating_sub(self.policy.clock().boot_ns());
                Duration::from_nanos(left)
                    .min(EXPIRY_RECHECK)
                    .max(Duration::from_millis(1))
            }
            None => Duration::ZERO,
        };
        if let Err(error) = self.timer.arm(after) {
            tracing::error!("cannot arm the exception timer: {error}");
        }
    }
}

impl MutEventSubscriber for ExpiryTimer {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if events.fd() == self.wake.as_raw_fd() {
            let _ = self.wake.read();
        } else {
            self.timer.clear();
        }
        self.tick();
    }

    /// Registration happens in the caller; see [`ExpiryTimer::fds`].
    fn init(&mut self, _ops: &mut EventOps) {}
}

/// `policy` as the control protocol shows it: its default, and its rules'
/// targets as written, the allows and the denies each in order.
pub fn net_view(policy: &Policy) -> NetPolicy {
    let mut view = NetPolicy {
        default: policy.default,
        allow: Vec::new(),
        deny: Vec::new(),
        inspect: Vec::new(),
    };
    // The text is `<verb> <target>`, as the parser wrote it.
    let target = |text: &str| {
        text.split_once(' ')
            .map_or(text, |(_, target)| target)
            .to_owned()
    };
    for rule in &policy.rules {
        match rule.verdict {
            Verdict::Allow => view.allow.push(target(&rule.text)),
            Verdict::Deny => view.deny.push(target(&rule.text)),
        }
    }
    view.inspect
        .extend(policy.inspect.iter().map(|line| target(&line.text)));
    view
}

/// The policy `view` describes: the denies, then the allows, then the
/// inspect lines, each in order, and the default
/// ([`Policy::from_lists`]). A target that does not parse names itself.
pub fn net_policy(view: &NetPolicy) -> Result<Policy, UpdateError> {
    Policy::from_lists(view.default, &view.deny, &view.allow, &view.inspect).map_err(|error| {
        let rules = match error.list {
            List::Deny => &view.deny,
            List::Allow => &view.allow,
            List::Inspect => &view.inspect,
        };
        UpdateError::Rule {
            list: error.list.name(),
            at: error.index,
            rule: rules.get(error.index).cloned().unwrap_or_default(),
            problem: error.kind.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use boxcar_proto::control::NetPolicy;
    use vmm_sys_util::eventfd::EFD_NONBLOCK;

    use super::*;

    fn live(net: Policy) -> LivePolicy {
        LivePolicy::new(
            Arc::new(ArcSwap::from_pointee(net)),
            Some(EventFd::new(EFD_NONBLOCK).unwrap()),
            Some(Arc::new(ArcSwap::from_pointee(vec![5000]))),
        )
        .unwrap()
    }

    fn net(default: Verdict, allow: &[&str], deny: &[&str]) -> NetPolicy {
        NetPolicy {
            default,
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            deny: deny.iter().map(|s| (*s).to_owned()).collect(),
            inspect: Vec::new(),
        }
    }

    /// Inspect lines go to their own list and come back as inspect lines,
    /// after the rules; a bad one is named with its list.
    #[test]
    fn inspect_lines_round_trip_through_the_view() {
        let policy = Policy::parse(&[
            "inspect api.example.com:443",
            "allow api.example.com",
            "inspect 127.0.0.1:8443",
        ])
        .unwrap();
        let view = net_view(&policy);
        assert_eq!(view.allow, ["api.example.com"]);
        assert_eq!(view.inspect, ["api.example.com:443", "127.0.0.1:8443"]);
        let made = net_policy(&view).unwrap();
        assert_eq!(made.inspect, policy.inspect);
        assert_eq!(made.rules.len(), 1);
        let mut bad = view.clone();
        bad.inspect.push("exa_mple.com".into());
        let error = net_policy(&bad).unwrap_err();
        let UpdateError::Rule { list, at, rule, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!((*list, *at, rule.as_str()), ("inspect", 2, "exa_mple.com"));
    }

    fn at(ip: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), port)
    }

    /// The view is the rules' targets as written, allows and denies apart,
    /// whatever their order in the policy; the policy an update makes puts
    /// the denies first.
    #[test]
    fn the_view_splits_the_rules_and_an_update_puts_denies_first() {
        let policy = Policy::parse(&[
            "allow Example.COM.",
            "deny *.evil.example.com:8080",
            "allow 203.0.113.0/24:443",
            "default allow",
        ])
        .unwrap();
        assert_eq!(
            net_view(&policy),
            net(
                Verdict::Allow,
                &["Example.COM.", "203.0.113.0/24:443"],
                &["*.evil.example.com:8080"]
            )
        );
        // Through an update and back: the same view.
        let made = net_policy(&net_view(&policy)).unwrap();
        assert_eq!(net_view(&made), net_view(&policy));
        assert_eq!(made.default, Verdict::Allow);
        let texts: Vec<&str> = made.rules.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "deny *.evil.example.com:8080",
                "allow Example.COM.",
                "allow 203.0.113.0/24:443"
            ]
        );
        // So a deny of a target wins over an allow of it.
        let both = net_policy(&net(Verdict::Deny, &["a.test"], &["a.test"])).unwrap();
        assert_eq!(
            both.egress(at([192, 0, 2, 1], 443), &["a.test".to_owned()]),
            (Verdict::Deny, Some("deny a.test".to_owned()))
        );
        assert_eq!(net_view(&Policy::default()), net(Verdict::Deny, &[], &[]));
    }

    /// A target that does not parse is named with its list and place, and
    /// what is wrong with it.
    #[test]
    fn a_bad_rule_is_named() {
        let cases = [
            (
                net(Verdict::Deny, &["exa_mple.com"], &[]),
                ("allow", 0, "exa_mple.com"),
            ),
            (
                net(Verdict::Deny, &["a.test"], &["ok.test", "192.168.1.300"]),
                ("deny", 1, "192.168.1.300"),
            ),
            (
                net(Verdict::Deny, &["b.test", "two words"], &["c.test"]),
                ("allow", 1, "two words"),
            ),
            (net(Verdict::Deny, &[""], &[]), ("allow", 0, "")),
            (
                net(Verdict::Deny, &[], &["10.1.2.3/8"]),
                ("deny", 0, "10.1.2.3/8"),
            ),
        ];
        for (view, (list, at, rule)) in cases {
            let error = net_policy(&view).unwrap_err();
            let UpdateError::Rule {
                list: got_list,
                at: got_at,
                rule: got_rule,
                problem,
            } = &error
            else {
                panic!("{view:?}: {error}");
            };
            assert_eq!((*got_list, *got_at, got_rule.as_str()), (list, at, rule));
            assert!(!problem.is_empty());
            assert!(
                error.to_string().starts_with(&format!("net.{list}[{at}] ")),
                "{error}"
            );
        }
    }

    /// An update swaps what it names, wakes the net thread for a network
    /// swap, and moves the version on; a view reports it all. Nothing
    /// changes on a refusal.
    #[test]
    fn an_update_swaps_wakes_and_versions() {
        let live = live(Policy::default());
        let wake = live.net_wake.as_ref().unwrap().try_clone().unwrap();
        assert_eq!(live.version(), FIRST_VERSION);
        assert_eq!(live.view().version, 1);
        assert_eq!(live.vsock_allow(), [5000]);

        let net_only = PolicyUpdateParams {
            net: Some(net(Verdict::Deny, &["api.github.com:443"], &[])),
            vsock: None,
            exception: None,
        };
        assert_eq!(live.update(&net_only, 1), Ok(2));
        assert_eq!(wake.read().unwrap(), 1, "woken once");
        assert_eq!(
            live.net()
                .egress(at([140, 82, 112, 6], 443), &["api.github.com".to_owned()]),
            (Verdict::Allow, Some("allow api.github.com:443".to_owned()))
        );
        assert_eq!(live.vsock_allow(), [5000], "untouched");

        let vsock_only = PolicyUpdateParams {
            net: None,
            vsock: Some(VsockPolicy {
                allow_ports: vec![6000, 7000],
            }),
            exception: None,
        };
        assert_eq!(live.update(&vsock_only, 1), Ok(3));
        assert!(wake.read().is_err(), "not woken for a vsock swap");
        assert_eq!(live.vsock_allow(), [6000, 7000]);
        assert_eq!(
            live.view(),
            PolicyView {
                net: net(Verdict::Deny, &["api.github.com:443"], &[]),
                vsock: VsockPolicy {
                    allow_ports: vec![6000, 7000]
                },
                version: 3,
                exceptions: Vec::new(),
            }
        );

        // A bad rule in a request that also has a good vsock list: nothing
        // of it is taken.
        let refused = PolicyUpdateParams {
            net: Some(net(Verdict::Allow, &["exa_mple.com"], &[])),
            vsock: Some(VsockPolicy::default()),
            exception: None,
        };
        assert!(matches!(
            live.update(&refused, 1),
            Err(UpdateError::Rule {
                list: "allow",
                at: 0,
                ..
            })
        ));
        assert_eq!(live.version(), 3);
        assert_eq!(live.vsock_allow(), [6000, 7000]);
        assert_eq!(live.net().default, Verdict::Deny);
    }

    /// Without the device there is nothing to update: refused, and the
    /// version stays.
    #[test]
    fn an_update_without_the_device_is_refused() {
        let none = LivePolicy::new(
            Arc::new(ArcSwap::from_pointee(Policy::default())),
            None,
            None,
        )
        .unwrap();
        let net_only = PolicyUpdateParams {
            net: Some(net(Verdict::Allow, &[], &[])),
            vsock: None,
            exception: None,
        };
        assert_eq!(none.update(&net_only, 1), Err(UpdateError::NoNetDevice));
        let vsock_only = PolicyUpdateParams {
            net: None,
            vsock: Some(VsockPolicy {
                allow_ports: vec![5000],
            }),
            exception: None,
        };
        assert_eq!(none.update(&vsock_only, 1), Err(UpdateError::NoVsockDevice));
        assert_eq!(none.version(), FIRST_VERSION);
        assert_eq!(none.net().default, Verdict::Deny);
        assert!(none.vsock_allow().is_empty());
        assert_eq!(none.view().vsock, VsockPolicy::default());
    }

    /// A session with path rules, a net card, records and a manual clock.
    struct Session {
        live: Arc<LivePolicy>,
        clock: Arc<ManualPolicyClock>,
        fs: LiveRules,
        net_wake: EventFd,
        writer: boxcar_audit::WriterHandle,
        _dir: tempfile::TempDir,
    }

    impl Session {
        fn new() -> Session {
            let dir = tempfile::tempdir().unwrap();
            let (sink, writer) = boxcar_audit::spawn(boxcar_audit::WriterConfig::new(
                dir.path(),
                boxcar_proto::SessionId::new(),
            ))
            .unwrap();
            let clock = Arc::new(ManualPolicyClock::new(
                1_000_000_000_000,
                1_760_000_000_000_000_000,
            ));
            let spec = PathSpec {
                writable: vec!["/workspace/**".to_owned()],
                denied: Vec::new(),
                exec_deny: vec!["**/nc".to_owned()],
            };
            let fs: LiveRules = Arc::new(ArcSwap::from_pointee(
                PathRules::new(&spec, &[], &[]).unwrap(),
            ));
            let wake = EventFd::new(EFD_NONBLOCK).unwrap();
            let net_wake = wake.try_clone().unwrap();
            let permanent = Policy::parse(&["deny blocked.test", "allow ok.test"]).unwrap();
            let live = LivePolicy::new(
                Arc::new(ArcSwap::from_pointee(permanent)),
                Some(wake),
                Some(Arc::new(ArcSwap::from_pointee(Vec::new()))),
            )
            .unwrap()
            .with_paths(Arc::clone(&fs), Some(spec))
            .with_audit(sink)
            .with_clock(clock.clone());
            Session {
                live: Arc::new(live),
                clock,
                fs,
                net_wake,
                writer,
                _dir: dir,
            }
        }

        fn grant(&self, rule: &str, kind: ExceptionKind, ttl_s: u32) -> Result<u64, UpdateError> {
            let params = PolicyUpdateParams {
                exception: Some(ExceptionGrant {
                    rule: rule.to_owned(),
                    kind,
                    ttl_s,
                }),
                ..PolicyUpdateParams::default()
            };
            self.live.update(&params, 4242)
        }

        fn allows(&self, name: &str) -> bool {
            let (verdict, _) = self
                .live
                .net()
                .egress(at([192, 0, 2, 9], 443), &[name.to_owned()]);
            verdict == Verdict::Allow
        }

        /// The policy's records, in log order: (kind, data).
        fn records(self) -> Vec<(String, serde_json::Value)> {
            let session = self.writer.session_dir().to_owned();
            drop(self.live);
            self.writer.close().unwrap();
            boxcar_audit::LogReader::open(&session)
                .unwrap()
                .records()
                .map(Result::unwrap)
                .filter(|r| r.kind.starts_with("policy."))
                .map(|r| (r.kind, r.data))
                .collect()
        }
    }

    /// An egress exception allows its target after the permanent rules
    /// (a permanent deny still wins); writable and exec ones change what
    /// the shares read; each moves the version on, wakes what reads it,
    /// and is listed apart from the permanent policy.
    #[test]
    fn exceptions_are_granted_on_top_of_the_permanent_policy() {
        let s = Session::new();
        assert!(!s.allows("pypi.org"));
        assert_eq!(s.grant("pypi.org:443", ExceptionKind::Egress, 600), Ok(2));
        assert!(s.allows("pypi.org"));
        assert_eq!(s.net_wake.read().unwrap(), 1, "the net thread woken");
        assert_eq!(s.grant("blocked.test", ExceptionKind::Egress, 600), Ok(3));
        assert!(!s.allows("blocked.test"), "a permanent deny still wins");

        assert!(!s.fs.load().writable(b"/etc/hosts"));
        assert_eq!(s.grant("/etc/**", ExceptionKind::Writable, 60), Ok(4));
        assert!(s.fs.load().writable(b"/etc/hosts"));
        assert_eq!(s.fs.load().exec_denied(b"/workspace/nc"), Some("**/nc"));
        assert_eq!(s.grant("/workspace/*", ExceptionKind::Exec, 60), Ok(5));
        assert_eq!(s.fs.load().exec_denied(b"/workspace/nc"), None);

        let view = s.live.view();
        assert_eq!(view.version, 5);
        assert_eq!(view.net.allow, ["ok.test"], "never an exception in net");
        assert_eq!(view.net.deny, ["blocked.test"]);
        let listed: Vec<(u32, &str, ExceptionKind, u32)> = view
            .exceptions
            .iter()
            .map(|e| (e.id, e.rule.as_str(), e.kind, e.ttl_s))
            .collect();
        assert_eq!(
            listed,
            [
                (1, "pypi.org:443", ExceptionKind::Egress, 600),
                (2, "blocked.test", ExceptionKind::Egress, 600),
                (3, "/etc/**", ExceptionKind::Writable, 60),
                (4, "/workspace/*", ExceptionKind::Exec, 60),
            ]
        );
        assert!(view.exceptions.iter().all(|e| e.by_pid == 4242));
        assert_eq!(
            view.exceptions[0].expires_ns,
            1_760_000_000_000_000_000 + 600_000_000_000
        );

        // A client writing back the view it read makes nothing permanent:
        // the exception lives on beside it, and goes at its time.
        let back = PolicyUpdateParams {
            net: Some(view.net.clone()),
            ..PolicyUpdateParams::default()
        };
        assert_eq!(s.live.update(&back, 7), Ok(6));
        assert!(s.allows("pypi.org"), "the exception kept");
        assert_eq!(s.live.view().exceptions.len(), 4);
        s.clock.advance(Duration::from_secs(601));
        assert_eq!(s.live.expire(), Some(7));
        assert!(!s.allows("pypi.org"), "gone, never made permanent");
        assert!(s.live.view().exceptions.is_empty());
        assert!(!s.fs.load().writable(b"/etc/hosts"));

        let kinds: Vec<(String, u64)> = s
            .records()
            .into_iter()
            .map(|(kind, data)| (kind, data["version"].as_u64().unwrap()))
            .collect();
        let kinds: Vec<(&str, u64)> = kinds.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(
            kinds,
            [
                ("policy.exception", 2),
                ("policy.exception", 3),
                ("policy.exception", 4),
                ("policy.exception", 5),
                ("policy.changed", 6),
                ("policy.changed", 7),
            ],
            "in version order"
        );
    }

    /// What an exception may not be: a rule not of its kind, a path
    /// exception on a session without path rules or shares, an egress one
    /// without a net card, the 65th; nothing changes.
    #[test]
    fn exceptions_are_refused_when_they_cannot_be() {
        let s = Session::new();
        assert!(matches!(
            s.grant("exa_mple.com", ExceptionKind::Egress, 60),
            Err(UpdateError::Exception { .. })
        ));
        assert!(matches!(
            s.grant("etc/**", ExceptionKind::Writable, 60),
            Err(UpdateError::Exception { .. })
        ));
        for i in 0..MAX_EXCEPTIONS {
            s.grant(&format!("h{i}.test"), ExceptionKind::Egress, 60)
                .unwrap();
        }
        assert_eq!(
            s.grant("one.more.test", ExceptionKind::Egress, 60),
            Err(UpdateError::TooManyExceptions)
        );
        assert_eq!(s.live.version(), FIRST_VERSION + MAX_EXCEPTIONS as u64);

        let bare = live(Policy::default());
        let writable = PolicyUpdateParams {
            exception: Some(ExceptionGrant {
                rule: "/etc/**".to_owned(),
                kind: ExceptionKind::Writable,
                ttl_s: 60,
            }),
            ..PolicyUpdateParams::default()
        };
        assert_eq!(bare.update(&writable, 1), Err(UpdateError::NoShares));
        let no_rules = live(Policy::default()).with_paths(
            Arc::new(ArcSwap::from_pointee(PathRules::allow_all())),
            None,
        );
        assert_eq!(no_rules.update(&writable, 1), Err(UpdateError::NoPathRules));
        let no_net = LivePolicy::new(
            Arc::new(ArcSwap::from_pointee(Policy::default())),
            None,
            None,
        )
        .unwrap();
        let egress = PolicyUpdateParams {
            exception: Some(ExceptionGrant {
                rule: "a.test".to_owned(),
                kind: ExceptionKind::Egress,
                ttl_s: 60,
            }),
            ..PolicyUpdateParams::default()
        };
        assert_eq!(no_net.update(&egress, 1), Err(UpdateError::NoNetDevice));
        assert_eq!(no_net.version(), FIRST_VERSION);
    }

    /// Two grants of one rule are two exceptions, each going at its own
    /// time; a permanent rule the same as an exception's stays when the
    /// exception goes; an expiry with nothing due changes nothing.
    #[test]
    fn exceptions_expire_on_their_own_times() {
        let s = Session::new();
        s.grant("pypi.org:443", ExceptionKind::Egress, 60).unwrap();
        s.clock.advance(Duration::from_secs(30));
        s.grant("pypi.org:443", ExceptionKind::Egress, 60).unwrap();
        s.grant("ok.test", ExceptionKind::Egress, 10).unwrap();
        assert_eq!(s.live.expire(), None, "nothing due");
        s.clock.advance(Duration::from_secs(31));
        // The first pypi grant and the ok.test twin are due.
        assert_eq!(s.live.expire(), Some(5));
        assert!(s.allows("pypi.org"), "the second grant lives on");
        assert!(s.allows("ok.test"), "the permanent twin stays");
        assert_eq!(s.live.view().exceptions.len(), 1);
        s.clock.advance(Duration::from_secs(30));
        assert_eq!(s.live.expire(), Some(6));
        assert!(!s.allows("pypi.org"));
        assert_eq!(s.live.next_deadline(), None);
    }

    /// The expiry timer on a main loop: a grant wakes it; once the clock is
    /// past the deadline, a tick swaps the views back, wakes the net
    /// thread, and records `policy.changed{by_pid: 0}`.
    #[test]
    fn an_exception_expires_on_the_loop() {
        use event_manager::{EventManager, EventSet, Events, SubscriberOps};

        let s = Session::new();
        let mut main_loop: EventManager<Box<dyn MutEventSubscriber>> = EventManager::new().unwrap();
        let timer = ExpiryTimer::new(Arc::clone(&s.live)).unwrap();
        let fds = timer.fds();
        let id = main_loop.add_subscriber(Box::new(timer));
        let mut ops = main_loop.event_ops(id).unwrap();
        for fd in fds {
            ops.add(Events::new_raw(fd, EventSet::IN)).unwrap();
        }

        assert_eq!(s.grant("/etc/**", ExceptionKind::Writable, 600), Ok(2));
        assert_eq!(s.grant("pypi.org:443", ExceptionKind::Egress, 600), Ok(3));
        let _ = s.net_wake.read();
        // The grants' wake: the timer arms, and nothing is due.
        assert!(main_loop.run_with_timeout(1000).unwrap() >= 1);
        assert_eq!(s.live.version(), 3);
        assert!(s.fs.load().writable(b"/etc/hosts"));

        s.clock.advance(Duration::from_secs(600));
        s.live.expiry_wake().write(1).unwrap();
        assert!(main_loop.run_with_timeout(1000).unwrap() >= 1);
        assert_eq!(s.live.version(), 4);
        assert!(!s.fs.load().writable(b"/etc/hosts"));
        assert!(!s.allows("pypi.org"));
        assert_eq!(s.net_wake.read().unwrap(), 1, "the net thread woken");
        let last = s.records().pop().unwrap();
        assert_eq!(last.0, "policy.changed");
        assert_eq!(last.1, serde_json::json!({"by_pid": 0, "version": 4}));
    }
}
