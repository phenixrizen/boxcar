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
use super::{EXEC_PENDING_NS, JOIN_WINDOW_NS, PENDING_NS};

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
    /// The argv is complete enough for an exact comparison.
    pub argv_complete: bool,
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
    id: u64,
    key: ProcKey,
    since_ts: u64,
    exit_ts: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct LineageTombstone {
    key: ProcKey,
    ppid: u32,
    first_ts: u64,
    exit_ts: Option<u64>,
}

impl LineageTombstone {
    fn covers(&self, ts: u64) -> bool {
        ts + JOIN_WINDOW_NS >= self.first_ts
            && self.exit_ts.is_none_or(|exit| ts <= exit + JOIN_WINDOW_NS)
    }
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
    /// The process already established for this item, if any.
    pub proc_key: Option<ProcKey>,
    /// Establishing the process crossed released lineage.
    pub lineage_evicted: bool,
}

/// A `net.connect` to an address no DNS answer named, waiting for the
/// sensor's connect that names its process before it is judged.
#[derive(Clone, Copy, Debug)]
pub struct PendingConnect {
    pub flow: u64,
    pub seq: u64,
    pub ts: u64,
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
    pub proc_lineage_evicted: bool,
    pub proc_seq: Option<u64>,
}

/// A `proc.tcp_connect` waiting for its `net.connect`, or found none.
#[derive(Clone, Debug)]
pub struct SensorConnect {
    pub seq: u64,
    pub ts: u64,
    pub tid: u32,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    /// The process already established for this item, if any.
    pub proc_key: Option<ProcKey>,
    /// Establishing the process crossed released lineage.
    pub lineage_evicted: bool,
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
    /// The sensor's own process and its other threads, from
    /// `proc.sensor_status`: their reads of the programs the session runs
    /// (to find the TLS symbols) are the sensor's own, not the session's.
    pub pid: Option<u32>,
    pub threads: HashSet<u32>,
}

impl Sensor {
    pub fn is_attached(&self, program: &str) -> bool {
        self.attached.contains(program)
    }

    /// Whether `tid` is boxcar's own in the guest: the sensor's threads,
    /// or init (pid 1), whose reads of the shares (the trust store it
    /// binds) are nobody's work either.
    pub fn is_own(&self, tid: u32) -> bool {
        tid == 1 || self.pid == Some(tid) || self.threads.contains(&tid)
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

/// The most flows the state remembers; past it the oldest goes.
pub const MAX_FLOWS: usize = 16384;
/// The most process generations whose lineage the state remembers.
pub const MAX_PROCS: usize = 16384;
/// The most bytes of process filenames and argv strings the state remembers.
pub const MAX_PROC_TEXT_BYTES: usize = 64 * 1024 * 1024;
/// The most thread-to-process memberships retained at once.
pub const MAX_MEMBERSHIPS: usize = 65536;
/// The most released process generations whose minimal lineage is retained.
const MAX_LINEAGE_TOMBSTONES: usize = MAX_PROCS;
/// A dead thread can still name a late effect near its exit.
const THREAD_RETIRE_NS: u64 = PENDING_NS + JOIN_WINDOW_NS;

/// A process selected for release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcEviction {
    pub key: ProcKey,
    /// The process is still reachable by a join or ancestry walk.
    pub forced: bool,
}

#[derive(Debug)]
pub struct State {
    procs: HashMap<ProcKey, Proc>,
    /// Process generations in the order they were first reported.
    proc_order: BTreeMap<u64, ProcKey>,
    proc_ordinals: HashMap<ProcKey, u64>,
    next_proc_ordinal: u64,
    /// Retained child links, so an ended ancestor is held without walking
    /// every live process.
    proc_parent: HashMap<ProcKey, ProcKey>,
    proc_children: HashMap<ProcKey, HashSet<ProcKey>>,
    /// Ended process generations in exit-time order.
    exited_procs: BTreeMap<(u64, u64), ProcKey>,
    exited_proc_keys: HashMap<ProcKey, (u64, u64)>,
    next_exit_ordinal: u64,
    /// Bytes of filenames and argv strings in `procs`.
    proc_text_bytes: usize,
    proc_limit: usize,
    proc_text_limit: usize,
    /// Each thread's memberships, oldest first.
    threads: HashMap<u32, Vec<Membership>>,
    /// Threads belonging to each process, for targeted release.
    proc_threads: HashMap<ProcKey, HashSet<u32>>,
    /// All memberships in insertion order, for aggregate enforcement.
    membership_order: BTreeMap<u64, (u32, ProcKey)>,
    next_membership_id: u64,
    membership_limit: usize,
    /// Non-group thread exits, in exit-time order.
    exited_threads: BTreeMap<(u64, u64), u64>,
    membership_exit_keys: HashMap<u64, (u64, u64)>,
    /// Minimal lineage for process generations released for room.
    lineage_tombstones: HashMap<ProcKey, LineageTombstone>,
    tombstones_by_tgid: HashMap<u32, Vec<ProcKey>>,
    tombstone_order: VecDeque<ProcKey>,
    pub pending: VecDeque<PendingEffect>,
    /// Connects without a name, waiting for their process (at most the
    /// join window).
    pub pending_connects: VecDeque<PendingConnect>,
    pub flows: HashMap<u64, Flow>,
    /// The flows in the order they came, to let the oldest go past
    /// [`MAX_FLOWS`].
    pub flow_order: VecDeque<u64>,
    /// Whether a flow has been let go for room: from then on, a flow not
    /// on record may be one that was.
    pub flows_let_go: bool,
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

impl Default for State {
    fn default() -> Self {
        State {
            procs: HashMap::new(),
            proc_order: BTreeMap::new(),
            proc_ordinals: HashMap::new(),
            next_proc_ordinal: 0,
            proc_parent: HashMap::new(),
            proc_children: HashMap::new(),
            exited_procs: BTreeMap::new(),
            exited_proc_keys: HashMap::new(),
            next_exit_ordinal: 0,
            proc_text_bytes: 0,
            proc_limit: MAX_PROCS,
            proc_text_limit: MAX_PROC_TEXT_BYTES,
            threads: HashMap::new(),
            proc_threads: HashMap::new(),
            membership_order: BTreeMap::new(),
            next_membership_id: 0,
            membership_limit: MAX_MEMBERSHIPS,
            exited_threads: BTreeMap::new(),
            membership_exit_keys: HashMap::new(),
            lineage_tombstones: HashMap::new(),
            tombstones_by_tgid: HashMap::new(),
            tombstone_order: VecDeque::new(),
            pending: VecDeque::new(),
            pending_connects: VecDeque::new(),
            flows: HashMap::new(),
            flow_order: VecDeque::new(),
            flows_let_go: false,
            sensor_connects: VecDeque::new(),
            sensor: Sensor::default(),
            dns: DnsCache::default(),
            session_id: None,
            session_start: None,
            last_effect_ts: None,
            last_sync: None,
            lag_until: 0,
            dns_quiet_until: 0,
            stopped: false,
            rings: BTreeMap::new(),
        }
    }
}

impl State {
    #[cfg(test)]
    pub(super) fn with_process_limits(proc_limit: usize, proc_text_limit: usize) -> Self {
        State {
            proc_limit,
            proc_text_limit,
            ..State::default()
        }
    }

    #[cfg(test)]
    fn with_limits(proc_limit: usize, proc_text_limit: usize, membership_limit: usize) -> Self {
        State {
            proc_limit,
            proc_text_limit,
            membership_limit,
            ..State::default()
        }
    }

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
        let old_bytes = self.procs.get(&key).map_or(0, proc_text_bytes);
        let new = !self.procs.contains_key(&key);
        let proc = self.procs.entry(key).or_insert_with(|| Proc {
            key,
            ppid: 0,
            uid: 0,
            filename: String::new(),
            argv: Vec::new(),
            argv_complete: true,
            first_ts: ts,
            exec_seq: None,
            exit_ts: None,
        });
        if ts < proc.first_ts {
            proc.first_ts = ts;
        }
        fill(proc);
        let new_bytes = proc_text_bytes(proc);
        self.proc_text_bytes = self.proc_text_bytes - old_bytes + new_bytes;
        if new {
            let ordinal = self.next_proc_ordinal;
            self.next_proc_ordinal = self.next_proc_ordinal.wrapping_add(1);
            self.proc_order.insert(ordinal, key);
            self.proc_ordinals.insert(key, ordinal);
        }
        if !self.proc_parent.contains_key(&key) {
            let parent = self
                .procs
                .get(&key)
                .and_then(|proc| self.attribute(proc.ppid, proc.first_ts));
            if let Some(parent) = parent.filter(|parent| *parent != key) {
                self.proc_parent.insert(key, parent);
                self.proc_children.entry(parent).or_default().insert(key);
            }
        }
        self.join_thread(key.tgid, key, ts);
    }

    /// `tid` belongs to the process `key` from `ts` on.
    pub fn join_thread(&mut self, tid: u32, key: ProcKey, ts: u64) {
        let memberships = self.threads.entry(tid).or_default();
        if memberships.last().is_some_and(|m| m.key == key) {
            return;
        }
        let id = self.next_membership_id;
        self.next_membership_id = self.next_membership_id.wrapping_add(1);
        memberships.push(Membership {
            id,
            key,
            since_ts: ts,
            exit_ts: None,
        });
        self.proc_threads.entry(key).or_default().insert(tid);
        self.membership_order.insert(id, (tid, key));
        while self.membership_order.len() > self.membership_limit {
            let Some((&oldest, _)) = self.membership_order.first_key_value() else {
                break;
            };
            self.remove_membership(oldest);
        }
    }

    /// A thread ended. Its membership remains through every late-effect
    /// window, then can be released without waiting for the process.
    pub fn exit_thread(&mut self, tid: u32, key: ProcKey, ts: u64) {
        let Some(membership) = self
            .threads
            .get_mut(&tid)
            .and_then(|memberships| memberships.iter_mut().rev().find(|m| m.key == key))
        else {
            return;
        };
        if membership.exit_ts.is_some() {
            return;
        }
        membership.exit_ts = Some(ts);
        let order_key = (ts, membership.id);
        self.exited_threads.insert(order_key, membership.id);
        self.membership_exit_keys.insert(membership.id, order_key);
    }

    /// A process ended. Normal retirement consumes this queue from the
    /// front once every join that can still need the process has settled.
    pub fn exit_process(&mut self, key: ProcKey, ts: u64) {
        if let Some(proc) = self.procs.get_mut(&key) {
            if proc.exit_ts.is_none() {
                proc.exit_ts = Some(ts);
                let order_key = (ts, self.next_exit_ordinal);
                self.next_exit_ordinal = self.next_exit_ordinal.wrapping_add(1);
                self.exited_procs.insert(order_key, key);
                self.exited_proc_keys.insert(key, order_key);
            }
        }
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
            .filter(|m| m.exit_ts.is_none_or(|exit| ts <= exit + JOIN_WINDOW_NS))
            .find(|m| self.procs.get(&m.key).is_some_and(|p| p.covers(ts)))
            .map(|m| m.key)
    }

    /// The process a thread named, and whether only released lineage could
    /// establish it.
    pub fn attribute_lineage(&self, tid: u32, ts: u64) -> Option<(ProcKey, bool)> {
        if let Some(key) = self.attribute(tid, ts) {
            return Some((key, self.is_lineage_evicted(key)));
        }
        self.tombstones_by_tgid.get(&tid).and_then(|keys| {
            keys.iter().rev().find_map(|key| {
                self.lineage_tombstones
                    .get(key)
                    .filter(|tombstone| tombstone.covers(ts))
                    .map(|tombstone| (tombstone.key, true))
            })
        })
    }

    /// The minimal process lineage retained for an ancestry walk.
    pub fn lineage_proc(&self, key: ProcKey) -> Option<(u32, u64, bool)> {
        self.procs
            .get(&key)
            .map(|proc| (proc.ppid, proc.first_ts, self.is_lineage_evicted(proc.key)))
            .or_else(|| {
                self.lineage_tombstones
                    .get(&key)
                    .map(|proc| (proc.ppid, proc.first_ts, true))
            })
    }

    /// The parent identity retained for `key`, and whether resolving it
    /// crossed released lineage.
    pub fn lineage_parent(
        &self,
        key: ProcKey,
        ppid: u32,
        first_ts: u64,
    ) -> Option<(ProcKey, bool)> {
        if let Some(parent) = self.proc_parent.get(&key).copied() {
            return Some((
                parent,
                self.is_lineage_evicted(key) || self.is_lineage_evicted(parent),
            ));
        }
        self.attribute_lineage(ppid, first_ts)
    }

    pub fn is_lineage_evicted(&self, key: ProcKey) -> bool {
        self.lineage_tombstones.contains_key(&key)
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
        while let Some(mut effect) = self.pending.pop_front() {
            let owner = effect
                .proc_key
                .map(|key| (key, effect.lineage_evicted))
                .or_else(|| self.attribute_lineage(effect.tid, effect.ts));
            match owner {
                Some((key, evicted)) => {
                    effect.proc_key = Some(key);
                    effect.lineage_evicted |= evicted;
                    resolved.push((effect, key));
                }
                None => kept.push_back(effect),
            }
        }
        self.pending = kept;
        resolved
    }

    /// Fixes each waiting item's process identity before `evicted` is
    /// released, and keeps the resulting degradation with that item.
    pub fn note_lineage_eviction(&mut self, evicted: ProcKey) {
        let pending_updates: Vec<(Option<ProcKey>, bool)> = self
            .pending
            .iter()
            .map(|effect| {
                let owner = effect.proc_key.or_else(|| {
                    self.attribute_lineage(effect.tid, effect.ts)
                        .map(|(key, _)| key)
                });
                let affected = owner.is_some_and(|key| self.lineage_depends_on(key, evicted));
                (owner, affected)
            })
            .collect();
        for (effect, (owner, affected)) in self.pending.iter_mut().zip(pending_updates) {
            effect.proc_key = owner;
            effect.lineage_evicted |= affected;
        }

        let connect_updates: Vec<(Option<ProcKey>, bool)> = self
            .sensor_connects
            .iter()
            .map(|connect| {
                let owner = connect.proc_key.or_else(|| {
                    self.attribute_lineage(connect.tid, connect.ts)
                        .map(|(key, _)| key)
                });
                let affected = owner.is_some_and(|key| self.lineage_depends_on(key, evicted));
                (owner, affected)
            })
            .collect();
        for (connect, (owner, affected)) in self.sensor_connects.iter_mut().zip(connect_updates) {
            connect.proc_key = owner;
            connect.lineage_evicted |= affected;
        }

        let affected_flows: Vec<u64> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                flow.proc_key
                    .is_some_and(|key| self.lineage_depends_on(key, evicted))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in affected_flows {
            if let Some(flow) = self.flows.get_mut(&id) {
                flow.proc_lineage_evicted = true;
            }
        }
    }

    /// Whether process count or retained filename/argv text is over its
    /// aggregate limit.
    pub fn process_limits_exceeded(&self) -> bool {
        self.procs.len() > self.proc_limit || self.proc_text_bytes > self.proc_text_limit
    }

    /// Processes that can be released now, oldest first. An exited process
    /// is released normally after every join wait and ancestry dependency
    /// is gone. The aggregate limits may select an otherwise retained
    /// process; that selection is marked `forced` for its span.
    pub fn process_evictions(
        &mut self,
        now: u64,
        externally_referenced: &HashSet<ProcKey>,
        settlement_protected: &HashSet<ProcKey>,
    ) -> Vec<ProcEviction> {
        let mut referenced = externally_referenced.clone();
        for effect in &self.pending {
            if let Some(key) = effect
                .proc_key
                .or_else(|| self.attribute(effect.tid, effect.ts))
            {
                referenced.insert(key);
            }
        }
        for connect in &self.sensor_connects {
            if let Some(key) = connect
                .proc_key
                .or_else(|| self.attribute(connect.tid, connect.ts))
            {
                referenced.insert(key);
            }
        }
        for flow in self.flows.values() {
            if let Some(key) = flow.proc_key {
                referenced.insert(key);
            }
        }

        // Every retained descendant keeps its ancestry available. Work
        // backwards until the set closes; cycles stop at the set itself.
        let mut todo: Vec<ProcKey> = referenced.iter().copied().collect();
        while let Some(key) = todo.pop() {
            let Some((ppid, first_ts, _)) = self.lineage_proc(key) else {
                continue;
            };
            let Some((parent, _)) = self.lineage_parent(key, ppid, first_ts) else {
                continue;
            };
            if parent != key && referenced.insert(parent) {
                todo.push(parent);
            }
        }

        let mut protected = settlement_protected.clone();
        let mut todo: Vec<ProcKey> = protected.iter().copied().collect();
        while let Some(key) = todo.pop() {
            let Some((ppid, first_ts, _)) = self.lineage_proc(key) else {
                continue;
            };
            let Some((parent, _)) = self.lineage_parent(key, ppid, first_ts) else {
                continue;
            };
            if parent != key && protected.insert(parent) {
                todo.push(parent);
            }
        }

        let mut selected = HashSet::new();
        let mut evictions = Vec::new();
        let mut remaining_count = self.procs.len();
        let mut remaining_bytes = self.proc_text_bytes;

        let ended: Vec<ProcKey> = now
            .checked_sub(EXEC_PENDING_NS)
            .into_iter()
            .flat_map(|eligible_through| {
                self.exited_procs
                    .range(..=(eligible_through, u64::MAX))
                    .map(|(_, key)| *key)
            })
            .collect();
        for key in ended {
            let has_children = self.proc_children.get(&key).is_some_and(|children| {
                children.iter().any(|child| self.procs.contains_key(child))
            });
            if !referenced.contains(&key) && !has_children && self.procs.contains_key(&key) {
                selected.insert(key);
                evictions.push(ProcEviction { key, forced: false });
                remaining_count -= 1;
                remaining_bytes -= self.procs.get(&key).map_or(0, proc_text_bytes);
            }
        }
        if remaining_count > self.proc_limit || remaining_bytes > self.proc_text_limit {
            for key in self.proc_order.values() {
                if selected.contains(key)
                    || protected.contains(key)
                    || !self.procs.contains_key(key)
                {
                    continue;
                }
                selected.insert(*key);
                evictions.push(ProcEviction {
                    key: *key,
                    forced: true,
                });
                remaining_count -= 1;
                remaining_bytes -= self.procs.get(key).map_or(0, proc_text_bytes);
                if remaining_count <= self.proc_limit && remaining_bytes <= self.proc_text_limit {
                    break;
                }
            }
        }
        evictions
    }

    /// Releases process entries and every thread membership that names one.
    pub fn evict_processes(&mut self, evictions: &[ProcEviction]) {
        if evictions.is_empty() {
            return;
        }
        for eviction in evictions {
            let key = eviction.key;
            if let Some(proc) = self.procs.remove(&key) {
                self.proc_text_bytes -= proc_text_bytes(&proc);
                if eviction.forced {
                    self.insert_tombstone(&proc);
                }
            }
            if let Some(ordinal) = self.proc_ordinals.remove(&key) {
                self.proc_order.remove(&ordinal);
            }
            if let Some(order_key) = self.exited_proc_keys.remove(&key) {
                self.exited_procs.remove(&order_key);
            }
            if let Some(parent) = self.proc_parent.remove(&key) {
                if let Some(children) = self.proc_children.get_mut(&parent) {
                    children.remove(&key);
                    if children.is_empty() {
                        self.proc_children.remove(&parent);
                    }
                }
            }
            // Keep this reverse set while retained children still point
            // at `key`. Their own release removes both directions, and a
            // late update of `key` can still see that it has children.
            let membership_ids: Vec<u64> = self
                .proc_threads
                .get(&key)
                .into_iter()
                .flat_map(|tids| tids.iter())
                .flat_map(|tid| self.threads.get(tid).into_iter().flatten())
                .filter(|membership| membership.key == key)
                .map(|membership| membership.id)
                .collect();
            for id in membership_ids {
                self.remove_membership(id);
            }
            self.proc_threads.remove(&key);
        }
    }

    /// Releases dead non-group thread memberships from their exit-time
    /// queue. No unrelated thread is visited.
    pub fn retire_thread_memberships(&mut self, now: u64) {
        let Some(eligible_through) = now.checked_sub(THREAD_RETIRE_NS) else {
            return;
        };
        while self
            .exited_threads
            .first_key_value()
            .is_some_and(|((exit, _), _)| *exit <= eligible_through)
        {
            let Some((_, membership_id)) = self.exited_threads.pop_first() else {
                break;
            };
            self.membership_exit_keys.remove(&membership_id);
            self.remove_membership(membership_id);
        }
    }

    /// Whether `key` is `ancestor` or needs it in its ancestry walk.
    pub fn lineage_depends_on(&self, key: ProcKey, ancestor: ProcKey) -> bool {
        let mut current = key;
        let mut seen = HashSet::new();
        while seen.insert(current) {
            if current == ancestor {
                return true;
            }
            let Some((ppid, first_ts, _)) = self.lineage_proc(current) else {
                return false;
            };
            let Some((parent, _)) = self.lineage_parent(current, ppid, first_ts) else {
                return false;
            };
            current = parent;
        }
        false
    }

    fn remove_membership(&mut self, id: u64) {
        let Some((tid, key)) = self.membership_order.remove(&id) else {
            return;
        };
        if let Some(exit_key) = self.membership_exit_keys.remove(&id) {
            self.exited_threads.remove(&exit_key);
        }
        let mut remove_tid = false;
        if let Some(memberships) = self.threads.get_mut(&tid) {
            memberships.retain(|membership| membership.id != id);
            remove_tid = memberships.is_empty();
        }
        if remove_tid {
            self.threads.remove(&tid);
        }
        let still_names_key = self
            .threads
            .get(&tid)
            .is_some_and(|memberships| memberships.iter().any(|membership| membership.key == key));
        if !still_names_key {
            if let Some(tids) = self.proc_threads.get_mut(&key) {
                tids.remove(&tid);
                if tids.is_empty() {
                    self.proc_threads.remove(&key);
                }
            }
        }
    }

    fn insert_tombstone(&mut self, proc: &Proc) {
        if self.lineage_tombstones.contains_key(&proc.key) {
            return;
        }
        let tombstone = LineageTombstone {
            key: proc.key,
            ppid: proc.ppid,
            first_ts: proc.first_ts,
            exit_ts: proc.exit_ts,
        };
        self.lineage_tombstones.insert(proc.key, tombstone);
        self.tombstones_by_tgid
            .entry(proc.key.tgid)
            .or_default()
            .push(proc.key);
        self.tombstone_order.push_back(proc.key);
        while self.tombstone_order.len() > MAX_LINEAGE_TOMBSTONES {
            let Some(oldest) = self.tombstone_order.pop_front() else {
                break;
            };
            self.lineage_tombstones.remove(&oldest);
            if let Some(keys) = self.tombstones_by_tgid.get_mut(&oldest.tgid) {
                keys.retain(|key| *key != oldest);
                if keys.is_empty() {
                    self.tombstones_by_tgid.remove(&oldest.tgid);
                }
            }
        }
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

fn proc_text_bytes(proc: &Proc) -> usize {
    proc.filename.capacity() + proc.argv.iter().map(String::capacity).sum::<usize>()
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

    #[test]
    fn settled_processes_and_their_thread_memberships_are_released() {
        let key = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let mut state = State::default();
        state.upsert_proc(key, S, |proc| {
            proc.filename = "/bin/worker".into();
            proc.argv = vec!["worker".into(), "run".into()];
        });
        state.join_thread(501, key, S);
        state.exit_process(key, 2 * S);

        let evictions =
            state.process_evictions(2 * S + EXEC_PENDING_NS, &HashSet::new(), &HashSet::new());
        assert_eq!(evictions, [ProcEviction { key, forced: false }]);
        state.evict_processes(&evictions);
        assert!(state.proc(key).is_none());
        assert!(state.threads.is_empty());
        assert_eq!(state.proc_text_bytes, 0);
    }

    #[test]
    fn a_retained_descendant_keeps_its_ancestry() {
        let parent = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let child = ProcKey {
            tgid: 501,
            start_ns: 2,
        };
        let mut state = State::default();
        state.upsert_proc(parent, S, |proc| {
            proc.ppid = 100;
        });
        state.exit_process(parent, 2 * S);
        state.upsert_proc(child, 2 * S, |proc| proc.ppid = parent.tgid);

        let evictions = state.process_evictions(20 * S, &HashSet::new(), &HashSet::new());
        assert!(!evictions.iter().any(|eviction| eviction.key == parent));
    }

    #[test]
    fn many_short_lived_processes_stay_within_the_aggregate_limits() {
        let mut state = State::with_process_limits(32, 512);
        for i in 0..2000u32 {
            let now = u64::from(i) * S;
            let key = ProcKey {
                tgid: i + 100,
                start_ns: u64::from(i) + 1,
            };
            state.upsert_proc(key, now, |proc| {
                proc.filename = "/bin/short-lived".into();
                proc.argv = vec!["short-lived".into(), format!("{i}")];
            });
            state.exit_process(key, now);
            let evictions = state.process_evictions(now, &HashSet::new(), &HashSet::new());
            state.evict_processes(&evictions);
            assert!(state.procs.len() <= 32);
            assert!(state.proc_text_bytes <= 512);
        }
        assert!(state.procs.len() <= 32);
        assert!(state.proc_text_bytes <= 512);
        assert_eq!(
            state.threads.values().map(Vec::len).sum::<usize>(),
            state.procs.len()
        );
    }

    #[test]
    fn aggregate_limits_identify_a_retained_process_release() {
        let mut state = State::with_process_limits(1, usize::MAX);
        let first = ProcKey {
            tgid: 100,
            start_ns: 1,
        };
        let second = ProcKey {
            tgid: 101,
            start_ns: 2,
        };
        state.upsert_proc(first, S, |_| {});
        state.upsert_proc(second, 2 * S, |_| {});
        let evictions = state.process_evictions(2 * S, &HashSet::new(), &HashSet::new());
        assert_eq!(
            evictions.first(),
            Some(&ProcEviction {
                key: first,
                forced: true
            })
        );
    }

    #[test]
    fn an_ended_thread_membership_is_released_after_late_effects_settle() {
        let key = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let mut state = State::default();
        state.upsert_proc(key, S, |_| {});
        state.join_thread(501, key, S);
        state.exit_thread(501, key, 2 * S);

        state.retire_thread_memberships(2 * S + THREAD_RETIRE_NS - 1);
        assert_eq!(state.attribute(501, 2 * S), Some(key));
        state.retire_thread_memberships(2 * S + THREAD_RETIRE_NS);
        assert!(!state.threads.contains_key(&501));
        assert!(state.proc(key).is_some());
    }

    #[test]
    fn thread_memberships_stay_within_the_aggregate_limit() {
        let key = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let mut state = State::with_limits(usize::MAX, usize::MAX, 3);
        state.upsert_proc(key, S, |_| {});
        for tid in 501..506 {
            state.join_thread(tid, key, S + u64::from(tid));
        }

        assert_eq!(state.membership_order.len(), 3);
        assert_eq!(state.threads.values().map(Vec::len).sum::<usize>(), 3);
        assert!(!state.threads.contains_key(&500));
        assert!(!state.threads.contains_key(&501));
        assert!(!state.threads.contains_key(&502));
        assert!(state.threads.contains_key(&505));
    }

    #[test]
    fn process_text_accounting_uses_retained_capacity() {
        let key = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let mut filename = String::with_capacity(1024);
        filename.push('x');
        let mut argument = String::with_capacity(1024);
        argument.push('y');
        let mut state = State::with_process_limits(usize::MAX, 1024);
        state.upsert_proc(key, S, |proc| {
            proc.filename = filename;
            proc.argv = vec![argument];
        });

        assert!(state.proc_text_bytes >= 2048);
        assert!(state.process_limits_exceeded());
    }

    #[test]
    fn process_release_visits_only_its_indexed_threads() {
        let first = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let second = ProcKey {
            tgid: 600,
            start_ns: 2,
        };
        let mut state = State::default();
        state.upsert_proc(first, S, |_| {});
        state.upsert_proc(second, S, |_| {});
        for tid in 501..510 {
            state.join_thread(tid, first, S);
        }
        for tid in 601..610 {
            state.join_thread(tid, second, S);
        }

        state.evict_processes(&[ProcEviction {
            key: first,
            forced: false,
        }]);

        assert!(!state.proc_threads.contains_key(&first));
        assert_eq!(state.proc_threads.get(&second).map(HashSet::len), Some(10));
        assert_eq!(state.attribute(605, S), Some(second));
    }

    #[test]
    fn waiting_items_keep_their_resolved_process() {
        let key = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let mut state = State::default();
        state.upsert_proc(key, S, |_| {});
        state.join_thread(501, key, S);
        state.pending.push_back(PendingEffect {
            seq: 1,
            ts: S,
            tid: 501,
            kind: "fs.close".into(),
            what: "workspace/result".into(),
            proc_key: None,
            lineage_evicted: false,
        });
        state.sensor_connects.push_back(SensorConnect {
            seq: 2,
            ts: S,
            tid: 501,
            src: "10.0.0.2:4000".parse().expect("source address"),
            dst: "10.0.0.3:443".parse().expect("destination address"),
            proc_key: None,
            lineage_evicted: false,
        });

        state.note_lineage_eviction(key);
        state.evict_processes(&[ProcEviction { key, forced: true }]);

        let (effect, owner) = state.resolve_pending().pop().expect("resolved effect");
        assert_eq!(owner, key);
        assert_eq!(effect.proc_key, Some(key));
        assert!(effect.lineage_evicted);
        let connect = state.sensor_connects.front().expect("waiting connect");
        assert_eq!(connect.proc_key, Some(key));
        assert!(connect.lineage_evicted);
    }

    #[test]
    fn parent_and_child_links_change_together() {
        let parent = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let child = ProcKey {
            tgid: 501,
            start_ns: 2,
        };
        let mut state = State::default();
        state.upsert_proc(parent, S, |_| {});
        state.upsert_proc(child, 2 * S, |proc| proc.ppid = parent.tgid);

        state.evict_processes(&[ProcEviction {
            key: parent,
            forced: true,
        }]);

        assert_eq!(state.proc_parent.get(&child), Some(&parent));
        assert!(state
            .proc_children
            .get(&parent)
            .is_some_and(|children| children.contains(&child)));

        state.upsert_proc(parent, S, |_| {});
        state.exit_process(parent, 3 * S);
        let evictions =
            state.process_evictions(3 * S + EXEC_PENDING_NS, &HashSet::new(), &HashSet::new());
        assert!(!evictions.iter().any(|eviction| eviction.key == parent));
    }

    #[test]
    fn ended_processes_are_retired_in_exit_time_order() {
        let first = ProcKey {
            tgid: 500,
            start_ns: 1,
        };
        let second = ProcKey {
            tgid: 600,
            start_ns: 2,
        };
        let mut state = State::default();
        state.upsert_proc(first, S, |_| {});
        state.upsert_proc(second, S, |_| {});
        state.exit_process(first, 2 * S);
        state.exit_process(second, 4 * S);

        let evictions =
            state.process_evictions(2 * S + EXEC_PENDING_NS, &HashSet::new(), &HashSet::new());
        assert_eq!(
            evictions,
            [ProcEviction {
                key: first,
                forced: false
            }]
        );
    }

    #[test]
    fn released_lineage_stays_within_its_limit() {
        let mut state = State::default();
        for i in 0..=MAX_LINEAGE_TOMBSTONES as u32 {
            state.insert_tombstone(&Proc {
                key: ProcKey {
                    tgid: i + 100,
                    start_ns: u64::from(i),
                },
                ppid: 1,
                uid: 1000,
                filename: String::new(),
                argv: Vec::new(),
                argv_complete: true,
                first_ts: u64::from(i),
                exec_seq: None,
                exit_ts: None,
            });
        }

        assert_eq!(state.lineage_tombstones.len(), MAX_LINEAGE_TOMBSTONES);
        assert_eq!(state.tombstone_order.len(), MAX_LINEAGE_TOMBSTONES);
        assert!(!state.lineage_tombstones.contains_key(&ProcKey {
            tgid: 100,
            start_ns: 0,
        }));
    }
}
