// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the reconciler remembers: the processes ring 1 reported and the
//! threads they own, the flows ring 0 opened, the effects still waiting for
//! a process, what the sensor said about itself, the clocks' pairing, and
//! the DNS cache.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddrV4;

use boxcar_proto::Ring;

use super::dns::DnsCache;
use super::{JOIN_WINDOW_NS, PENDING_NS};

/// A process, by its id and start time: pid reuse gives a new key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcKey {
    pub tgid: u32,
    pub start_ns: u64,
}

/// A process ring 1 reported.
#[derive(Clone, Debug)]
pub struct Proc {
    pub key: ProcKey,
    pub ppid: u32,
    pub uid: u32,
    pub filename: String,
    pub argv: Vec<String>,
    /// Host time of the record that first named it (fork or exec).
    pub first_ts: u64,
    /// The seq of its `proc.exec`, when one came.
    pub exec_seq: Option<u64>,
    /// Host time of its last thread's exit, once it ended.
    pub exit_ts: Option<u64>,
}

impl Proc {
    /// A short name: the program, or the pid.
    pub fn name(&self) -> String {
        match self.argv.first() {
            Some(arg0) => arg0.rsplit('/').next().unwrap_or(arg0).to_owned(),
            None if !self.filename.is_empty() => self
                .filename
                .rsplit('/')
                .next()
                .unwrap_or(&self.filename)
                .to_owned(),
            None => format!("pid {}", self.key.tgid),
        }
    }

    /// Whether an effect at `ts` (host time) can be this process's: within
    /// its life, widened by the join window on both sides.
    pub fn covers(&self, ts: u64) -> bool {
        ts + JOIN_WINDOW_NS >= self.first_ts
            && self.exit_ts.is_none_or(|exit| ts <= exit + JOIN_WINDOW_NS)
    }
}

/// A thread's membership of a process, from when.
#[derive(Clone, Copy, Debug)]
struct Membership {
    key: ProcKey,
    since_ts: u64,
}

/// A ring 0 effect waiting for the process that made it.
#[derive(Clone, Debug)]
pub struct PendingEffect {
    pub seq: u64,
    pub ts: u64,
    pub tid: u32,
    pub kind: String,
    /// The path or destination, for the summary.
    pub what: String,
}

/// A flow ring 0 relays, from its `net.connect`.
#[derive(Clone, Debug)]
pub struct Flow {
    pub seq: u64,
    pub ts: u64,
    pub proto: String,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    /// The names the stack had for the destination.
    pub names: Vec<String>,
    /// The policy let it through.
    pub allowed: bool,
    /// The process whose `proc.tcp_connect` matched, once one did.
    pub proc_key: Option<ProcKey>,
    pub proc_seq: Option<u64>,
}

/// A `proc.tcp_connect` waiting for its `net.connect`, or found none.
#[derive(Clone, Debug)]
pub struct SensorConnect {
    pub seq: u64,
    pub ts: u64,
    pub tid: u32,
    pub src_port: u16,
    pub dst: SocketAddrV4,
}

/// What the sensor said about itself.
#[derive(Clone, Debug, Default)]
pub struct Sensor {
    /// Host time and seq of the last `proc.sensor_status`.
    pub status: Option<(u64, u64)>,
    /// The programs it reported attached.
    pub attached: HashSet<String>,
    /// Host time and seq of the last heartbeat.
    pub heartbeat: Option<(u64, u64)>,
    /// A silence finding is open: no second one until a heartbeat comes.
    pub silence_open: bool,
    /// The never-attached finding was made.
    pub never_attached_reported: bool,
}

impl Sensor {
    pub fn is_attached(&self, program: &str) -> bool {
        self.attached.contains(program)
    }

    /// Whether every program the exec/fork/exit joins need is attached.
    pub fn lineage_ok(&self) -> bool {
        [
            "sched_process_exec",
            "sched_process_fork",
            "sched_process_exit",
        ]
        .iter()
        .all(|p| self.is_attached(p))
    }
}

#[derive(Debug, Default)]
pub struct State {
    procs: HashMap<ProcKey, Proc>,
    /// Each thread's memberships, oldest first.
    threads: HashMap<u32, Vec<Membership>>,
    pub pending: VecDeque<PendingEffect>,
    pub flows: HashMap<u64, Flow>,
    pub sensor_connects: VecDeque<SensorConnect>,
    pub sensor: Sensor,
    pub dns: DnsCache,
    /// The session's id, from the first record: the trace id of every
    /// span.
    pub session_id: Option<String>,
    /// Host time and seq of `session.start`.
    pub session_start: Option<(u64, u64)>,
    /// Host time of the last ring 0 effect (fs or net).
    pub last_effect_ts: Option<u64>,
    /// Host time and round trip of the last `sync`.
    pub last_sync: Option<(u64, u64)>,
    /// Until when a subscription gap keeps findings low in confidence.
    pub lag_until: u64,
    /// Until when the DNS spike rule stays quiet after firing.
    pub dns_quiet_until: u64,
    /// `vmm.stop` was seen.
    pub stopped: bool,
    /// The ring of each recent record, for the evidence.
    rings: BTreeMap<u64, Ring>,
}

/// How many records' rings are kept for the evidence.
const RINGS_KEPT: usize = 65536;

impl State {
    /// Notes which ring `seq` came from.
    pub fn note_ring(&mut self, seq: u64, ring: Ring) {
        self.rings.insert(seq, ring);
        while self.rings.len() > RINGS_KEPT {
            if let Some(oldest) = self.rings.keys().next().copied() {
                self.rings.remove(&oldest);
            }
        }
    }

    /// The ring `seq` came from; `Host` when it is no longer kept, as every
    /// record a rule reads is recent.
    pub fn ring_of(&self, seq: u64) -> Ring {
        self.rings.get(&seq).copied().unwrap_or(Ring::Host)
    }

    /// A process ring 1 named: by fork (no argv yet) or exec.
    pub fn upsert_proc(&mut self, key: ProcKey, ts: u64, fill: impl FnOnce(&mut Proc)) {
        let proc = self.procs.entry(key).or_insert_with(|| Proc {
            key,
            ppid: 0,
            uid: 0,
            filename: String::new(),
            argv: Vec::new(),
            first_ts: ts,
            exec_seq: None,
            exit_ts: None,
        });
        if ts < proc.first_ts {
            proc.first_ts = ts;
        }
        fill(proc);
        self.join_thread(key.tgid, key, ts);
    }

    /// `tid` belongs to the process `key` from `ts` on.
    pub fn join_thread(&mut self, tid: u32, key: ProcKey, ts: u64) {
        let memberships = self.threads.entry(tid).or_default();
        if memberships.last().is_some_and(|m| m.key == key) {
            return;
        }
        memberships.push(Membership { key, since_ts: ts });
    }

    pub fn proc(&self, key: ProcKey) -> Option<&Proc> {
        self.procs.get(&key)
    }

    pub fn proc_mut(&mut self, key: ProcKey) -> Option<&mut Proc> {
        self.procs.get_mut(&key)
    }

    /// The process a thread `tid` belonged to at host time `ts`: the latest
    /// membership that had begun by then (join window allowed) and whose
    /// process had not ended more than the window before. Pid reuse makes a
    /// new membership with a later start, so an old process never takes a
    /// new one's effects.
    pub fn attribute(&self, tid: u32, ts: u64) -> Option<ProcKey> {
        let memberships = self.threads.get(&tid)?;
        memberships
            .iter()
            .rev()
            .filter(|m| m.since_ts <= ts + JOIN_WINDOW_NS)
            .find(|m| self.procs.get(&m.key).is_some_and(|p| p.covers(ts)))
            .map(|m| m.key)
    }

    /// Effects whose wait is over at `now`.
    pub fn expire_pending(&mut self, now: u64) -> Vec<PendingEffect> {
        let mut expired = Vec::new();
        while let Some(front) = self.pending.front() {
            if now.saturating_sub(front.ts) >= PENDING_NS {
                if let Some(effect) = self.pending.pop_front() {
                    expired.push(effect);
                }
            } else {
                break;
            }
        }
        expired
    }

    /// Pending effects a newly known process can take.
    pub fn resolve_pending(&mut self) -> Vec<(PendingEffect, ProcKey)> {
        let mut resolved = Vec::new();
        let mut kept = VecDeque::new();
        while let Some(effect) = self.pending.pop_front() {
            match self.attribute(effect.tid, effect.ts) {
                Some(key) => resolved.push((effect, key)),
                None => kept.push_back(effect),
            }
        }
        self.pending = kept;
        resolved
    }

    /// Whether a cross-ring join made now is low in confidence: a stale or
    /// slow clock pairing, or a gap in what the reconciler saw.
    pub fn low_confidence(&self, now: u64, ring1_alive: bool) -> bool {
        if now < self.lag_until {
            return true;
        }
        match self.last_sync {
            Some((ts, rtt_ns)) => {
                rtt_ns > super::SYNC_RTT_UNSURE_NS
                    || (ring1_alive && now.saturating_sub(ts) > super::SYNC_STALE_NS)
            }
            None => {
                ring1_alive
                    && self
                        .session_start
                        .is_some_and(|(ts, _)| now.saturating_sub(ts) > super::SYNC_STALE_NS)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const S: u64 = 1_000_000_000;

    /// A tid is reused: process A lives from 1 s to 2 s, process B, with
    /// the same pid, from 3 s on. Whatever the effects' times, none is given
    /// to the wrong process: A never takes one after its end plus the
    /// window, B never one before its start minus the window.
    #[test]
    fn pid_reuse_never_misattributes() {
        let a = ProcKey {
            tgid: 100,
            start_ns: 10,
        };
        let b = ProcKey {
            tgid: 100,
            start_ns: 20,
        };
        let mut state = State::default();
        state.upsert_proc(a, S, |p| p.argv = vec!["a".into()]);
        if let Some(proc) = state.proc_mut(a) {
            proc.exit_ts = Some(2 * S);
        }
        state.upsert_proc(b, 3 * S, |p| p.argv = vec!["b".into()]);

        proptest!(|(ts in 0u64..6 * S)| {
            let got = state.attribute(100, ts);
            if ts + JOIN_WINDOW_NS < S {
                prop_assert_eq!(got, None, "before A");
            } else if ts <= 2 * S + JOIN_WINDOW_NS && ts + JOIN_WINDOW_NS < 3 * S {
                prop_assert_eq!(got, Some(a), "A's life, widened");
            } else if ts + JOIN_WINDOW_NS >= 3 * S {
                prop_assert_eq!(got, Some(b), "B's life, widened");
            } else {
                prop_assert_eq!(got, None, "between the two");
            }
        });
    }

    #[test]
    fn a_thread_belongs_to_its_process_for_its_life() {
        let key = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let mut state = State::default();
        state.upsert_proc(key, S, |p| p.argv = vec!["node".into()]);
        state.join_thread(501, key, S + 100);
        assert_eq!(state.attribute(501, S + 200), Some(key));
        assert_eq!(state.attribute(501, 0), None, "before the thread existed");
        if let Some(proc) = state.proc_mut(key) {
            proc.exit_ts = Some(2 * S);
        }
        assert_eq!(state.attribute(501, 2 * S + JOIN_WINDOW_NS), Some(key));
        assert_eq!(state.attribute(501, 2 * S + JOIN_WINDOW_NS + 1), None);
        assert_eq!(state.attribute(502, S + 200), None, "an unknown thread");
    }
}
