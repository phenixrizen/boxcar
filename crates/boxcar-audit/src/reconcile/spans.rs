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
//!   (through `ppid`) reaches the agent (the session's root, or the span's
//!   bound executor): by argv first (a shell tool whose declared command
//!   the exec carries, compared exactly as the call sent it), else as the
//!   only open span. One that joins no span waits [`PENDING_NS`] for a
//!   late `tool.open`.
//! - A process forked or exec'd by a span's process joins that span.
//! - A filesystem effect joins the span of its process. One by the agent
//!   itself, in no span (as for a `Write` tool), joins the
//!   only open write tool span, or the write tool span whose declared
//!   path it touches; a shell tool's work is its process's, and the
//!   agent's own housekeeping meanwhile is nobody's. One that joins
//!   nothing waits for its process to join.
//! - A `net.connect` joins the span of the process its `proc.tcp_connect`
//!   named, once the two have met.
//! - The executor of a span is the process that opened the flow its
//!   model request came over (bound); until that is known, provisionally,
//!   the one process whose `proc.tls_io` writes, within
//!   [`EXECUTOR_WINDOW_NS`] of the gate's `http.request` and sized like its
//!   body, carried it. Only a bound executor counts as the agent, and only
//!   it may close the span ([`CLOSE_WAIT_NS`]).
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
use boxcar_proto::redact::scrub_text;
use boxcar_proto::{Finding, FindingCategory, ProcExec, Record, SpanEffects, ToolClose, ToolOpen};
use serde_json::Value;

use super::rules::Draft;
use super::state::{ProcKey, State};
use super::{JOIN_WINDOW_NS, PENDING_NS};

/// The most processes a span lists.
pub const MAX_SPAN_PROCS: usize = 1024;
/// The most effect records a span lists.
pub const MAX_SPAN_EFFECTS: usize = 4096;
/// The most bytes the effects of every span kept hold at once (the
/// entries and their paths); past it a span takes no more, `truncated`.
/// A span's are let go once it has settled and been recorded.
pub const MAX_EFFECT_BYTES: usize = 64 * 1024 * 1024;
/// How long after a span's close its effects and processes are judged.
pub const SETTLE_NS: u64 = 1_000_000_000;
/// The most spans kept in memory; beyond it the oldest settled span goes
/// (the oldest closed one, if none has settled).
const MAX_SPANS_KEPT: usize = 4096;
/// The most spans open at once; beyond it the oldest open span is set
/// aside: its `span.effects` written as it stands, `truncated`, and
/// nothing more joins it.
pub const MAX_OPEN_SPANS: usize = 256;
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
const SHELL_TOOLS: [&str; 6] = [
    "Bash",
    "bash",
    "shell",
    "exec_command",
    "local_shell",
    "exec",
];
/// The tools that declare a file they write.
const WRITE_TOOLS: [&str; 5] = ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];
/// Programs whose `-c` argument is the command they run.
const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ash", "ksh"];
/// How much of a command a summary quotes.
const QUOTE_LIMIT: usize = 120;

/// What a redacted value reads as in a record.
const REDACTED: &str = "[redacted]";
/// The most tool calls whose arguments [`DeclaredArgs`] keeps.
pub const MAX_DECLARED: usize = 1024;
/// The most bytes of arguments [`DeclaredArgs`] keeps, in all.
pub const MAX_DECLARED_BYTES: usize = 8 * 1024 * 1024;
/// The largest one call's arguments may be to be kept.
pub const DECLARED_ARGS_LIMIT: usize = 64 * 1024;
/// The most flows whose opener is remembered.
const MAX_FLOW_OWNERS: usize = 4096;
/// The most `tool.close`s waiting to learn who opened their flow.
const MAX_PENDING_CLOSES: usize = 256;
/// How long a `tool.close` waits to learn who opened its flow; one that
/// never learns is not applied, and its span stays open.
pub const CLOSE_WAIT_NS: u64 = 2_000_000_000;

/// A tool call's arguments as the model sent them, before any scrub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declared {
    Json(Value),
    /// Free text (Codex's custom tools), or JSON that did not parse.
    Text(String),
}

/// A shell tool's declared command, as the model sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    /// A command line, for a shell to run.
    Text(String),
    /// An argv, run as it is.
    Argv(Vec<String>),
}

impl Command {
    /// The command on one line, as a finding quotes it.
    fn display(&self) -> String {
        match self {
            Command::Text(text) => one_line(text),
            Command::Argv(argv) => one_line(&argv.join(" ")),
        }
    }

    fn mentions(&self, needle: &str) -> bool {
        match self {
            Command::Text(text) => text.contains(needle),
            Command::Argv(argv) => argv.iter().any(|arg| arg.contains(needle)),
        }
    }
}

/// The arguments of tool calls as the model sent them: the gate puts
/// them, the reconciler takes them when it opens the span, so a shell
/// tool's declared command and a write tool's paths are compared with
/// what ran as they were, not as the record keeps them (scrubbed, where
/// two different secrets read the same). Held in memory only, never
/// recorded, and bounded: [`MAX_DECLARED`] calls, [`MAX_DECLARED_BYTES`],
/// the oldest going first. Cheap to clone; one per session.
#[derive(Clone, Debug, Default)]
pub struct DeclaredArgs {
    inner: Arc<Mutex<DeclaredInner>>,
}

#[derive(Debug, Default)]
struct DeclaredInner {
    calls: HashMap<String, (Declared, usize)>,
    order: VecDeque<String>,
    bytes: usize,
}

impl DeclaredArgs {
    pub fn new() -> DeclaredArgs {
        DeclaredArgs::default()
    }

    /// Keeps the call `id`'s `args`, `len` bytes as sent; arguments over
    /// [`DECLARED_ARGS_LIMIT`] are not kept.
    pub fn put(&self, id: &str, args: Declared, len: usize) {
        if len > DECLARED_ARGS_LIMIT {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, old)) = inner.calls.insert(id.to_owned(), (args, len)) {
            inner.bytes -= old;
        } else {
            inner.order.push_back(id.to_owned());
        }
        inner.bytes += len;
        while inner.order.len() > MAX_DECLARED || inner.bytes > MAX_DECLARED_BYTES {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some((_, old)) = inner.calls.remove(&oldest) {
                inner.bytes -= old;
            }
        }
    }

    /// The call `id`'s arguments, which are let go.
    pub fn take(&self, id: &str) -> Option<Declared> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (args, len) = inner.calls.remove(id)?;
        inner.bytes -= len;
        inner.order.retain(|kept| kept != id);
        Some(args)
    }
}

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

impl Effect {
    /// What it holds: the entry and its strings.
    fn bytes(&self) -> usize {
        let strings = match &self.kind {
            EffectKind::Fs {
                mount, path, to, ..
            } => mount.capacity() + path.capacity() + to.as_ref().map_or(0, String::capacity),
            EffectKind::Exec | EffectKind::Net { .. } => 0,
        };
        size_of::<Effect>() + strings
    }
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
    /// The declared shell command, for a shell tool.
    declared: Option<Command>,
    /// The declared command and paths are the call's arguments as sent
    /// (from [`DeclaredArgs`]), not the record's scrubbed copy.
    declared_raw: bool,
    /// The declared command as a finding quotes it: from the record's
    /// scrubbed copy, scrubbed again as text.
    declared_display: Option<String>,
    /// The flow and stream of the model request the span came from.
    request: (u64, u32),
    /// The declared paths, as (mount, path without its leading slash),
    /// for a write tool.
    paths: Vec<(String, String)>,
    /// The declared paths as a finding quotes them, from the record's
    /// scrubbed copy.
    paths_display: Vec<String>,
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
    /// What `effects` holds of [`MAX_EFFECT_BYTES`].
    effect_bytes: usize,
    /// Effects let go once the span settled and was recorded: counted,
    /// no longer kept.
    effects_let_go: usize,
    /// The process behind the model request: the one that opened its flow
    /// (`executor_bound`), or, provisionally, the one whose `proc.tls_io`
    /// write alone fit it; the session root otherwise.
    pub executor: Option<ProcKey>,
    /// The executor opened the request's flow: it counts as the agent.
    executor_bound: bool,
    truncated: bool,
    pub worst_score: u8,
    /// The checks a second after the close ran.
    settled: bool,
    /// The `argv` rule fired: once a span.
    argv_fired: bool,
    /// A shell the span took by ancestry alone whose command does not
    /// carry the declared one: (the shell, its exec's seq, its host time,
    /// its command). Judged at the close.
    mismatch: Option<(ProcKey, u64, u64, String)>,
    /// An exec that carries the declared command joined the span.
    carried: bool,
    /// Its `span.effects` was written.
    recorded: bool,
    /// Set aside open, past [`MAX_OPEN_SPANS`].
    abandoned: bool,
}

impl Span {
    /// A span for `open`, judged by `raw` (the arguments as sent) when the
    /// gate kept them, else by the record's scrubbed copy.
    fn new(open: &ToolOpen, raw: Option<Declared>, seq: u64, ts: u64) -> Span {
        let name = open.tool_name.as_str();
        // What the record has, scrubbed: what findings quote.
        let (recorded_command, recorded_paths) = match open.args.as_ref() {
            Some(args) => (declared_command(name, args), declared_paths(name, args)),
            None => (
                declared_command_text(name, &open.args_summary),
                declared_paths_text(name, &open.args_summary),
            ),
        };
        let declared_display = recorded_command
            .as_ref()
            .map(|command| scrub_text(&command.display()));
        let paths_display = recorded_paths
            .iter()
            .map(|(mount, path)| format!("{} on {mount}", scrub_text(path)))
            .collect();
        let (declared, paths, mut args_text, declared_raw) = match &raw {
            Some(Declared::Json(args)) => (
                declared_command(name, args),
                declared_paths(name, args),
                args.to_string(),
                true,
            ),
            Some(Declared::Text(text)) => (
                declared_command_text(name, text),
                declared_paths_text(name, text),
                text.clone(),
                true,
            ),
            None => (
                recorded_command,
                recorded_paths,
                match open.args.as_ref() {
                    Some(args) => args.to_string(),
                    None => open.args_summary.clone(),
                },
                false,
            ),
        };
        args_text.make_ascii_lowercase();
        Span {
            id: open.tool_use_id.clone(),
            tool_name: open.tool_name.clone(),
            declared,
            declared_raw,
            declared_display,
            request: (open.flow, open.stream),
            paths,
            paths_display,
            args_text,
            opened: (seq, ts),
            closed: None,
            status: None,
            members: Vec::new(),
            effects: Vec::new(),
            effect_bytes: 0,
            effects_let_go: 0,
            executor: None,
            executor_bound: false,
            truncated: false,
            worst_score: 0,
            settled: false,
            argv_fired: false,
            mismatch: None,
            carried: false,
            recorded: false,
            abandoned: false,
        }
    }

    pub fn is_open(&self) -> bool {
        self.closed.is_none() && !self.abandoned
    }

    fn is_shell_tool(&self) -> bool {
        SHELL_TOOLS.contains(&self.tool_name.as_str())
    }

    fn is_write_tool(&self) -> bool {
        WRITE_TOOLS.contains(&self.tool_name.as_str())
    }

    /// An exec joined the span: notes whether it ran the declared command.
    fn note_exec(&mut self, program: &str, argv: &[String]) {
        if self.carried_by(program, argv) == Some(true) {
            self.carried = true;
        }
    }

    /// Whether an exec carries the declared command, compared exactly
    /// ([`carries`]): with the call's arguments as sent, or with the
    /// record's copy when that has nothing redacted (a scrub only ever
    /// puts in the redaction mark, so such a copy is the original). `None`
    /// when that cannot tell: no declared command, or a copy with a
    /// redacted part (two different values read the same once redacted).
    fn carried_by(&self, program: &str, argv: &[String]) -> Option<bool> {
        let declared = self.declared.as_ref()?;
        if !self.declared_raw && declared.mentions(REDACTED) {
            return None;
        }
        Some(carries(declared, program, argv))
    }

    fn has_member(&self, key: ProcKey) -> bool {
        self.members.iter().any(|m| m.key == key)
    }

    /// Adds `effect`, its bytes counted in `held` (every span's) against
    /// [`MAX_EFFECT_BYTES`].
    fn push_effect(&mut self, effect: Effect, held: &mut usize) {
        if self.effects.iter().any(|e| e.seq == effect.seq) {
            return;
        }
        let bytes = effect.bytes();
        if self.effects.len() >= MAX_SPAN_EFFECTS || *held + bytes > MAX_EFFECT_BYTES {
            self.truncated = true;
            return;
        }
        *held += bytes;
        self.effect_bytes += bytes;
        self.effects.push(effect);
    }

    /// Lets the effects go, keeping their count; gives back their bytes.
    fn let_go_effects(&mut self, held: &mut usize) {
        self.effects_let_go += self.effects.len();
        self.effects = Vec::new();
        *held -= self.effect_bytes;
        self.effect_bytes = 0;
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
            effects: u32::try_from(self.effects.len() + self.effects_let_go).unwrap_or(u32::MAX),
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
    /// The process behind each request, by the request's flow and stream
    /// (and whether it opened the flow), and the order they came in.
    executors: HashMap<(u64, u32), (ProcKey, bool)>,
    executor_order: VecDeque<(u64, u32)>,
    /// The process that opened each flow, from the sensor's connect, and
    /// the order they came in.
    flow_owners: HashMap<u64, ProcKey>,
    flow_order: VecDeque<u64>,
    /// The calls' arguments as sent, from the gate.
    declared: Option<DeclaredArgs>,
    /// `tool.close`s of bound spans whose flow's opener is not known yet.
    pending_closes: VecDeque<PendingClose>,
    /// What the kept spans' effects hold, against [`MAX_EFFECT_BYTES`].
    effect_bytes: usize,
    /// Findings a deferred close made, for the next tick to hand over.
    deferred_findings: Vec<Finding>,
}

/// What becomes of a `tool.close`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Apply,
    Drop,
    /// Who opened the span's request flow, or the close's, is not known yet.
    Wait,
}

/// A `tool.close` waiting to learn who opened the flows it rests on.
#[derive(Clone, Debug)]
struct PendingClose {
    record: Record,
    close: ToolClose,
}

impl Spans {
    pub fn new(index: Option<SpanIndex>, declared: Option<DeclaredArgs>) -> Spans {
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
            flow_owners: HashMap::new(),
            flow_order: VecDeque::new(),
            declared,
            pending_closes: VecDeque::new(),
            effect_bytes: 0,
            deferred_findings: Vec::new(),
        }
    }

    /// A `proc.tls_io` write: each request of the window whose flow's
    /// opener is not known is reconsidered: the one process whose writes
    /// fit it is its executor, provisionally; none, or two, and it has
    /// none. The write is kept for a request still to come.
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
        let open: Vec<(Request, Option<u32>)> = self
            .requests
            .iter()
            .filter(|r| {
                !self.flow_owners.contains_key(&r.flow)
                    && !self
                        .executors
                        .get(&(r.flow, r.stream))
                        .is_some_and(|(_, bound)| *bound)
            })
            .map(|r| (*r, self.carrier(r)))
            .collect();
        for (request, carrier) in open {
            match carrier {
                Some(tgid) => {
                    self.name_executor(state, request.flow, request.stream, tgid, request.ts)
                }
                None => self.unname_executor(request.flow, request.stream),
            }
        }
    }

    /// An `http.request`: the process that opened its flow is its
    /// executor. Without that, the write that carried it names one,
    /// provisionally (one write of its size or a process's writes of the
    /// window summed, from one process only); the request waits for the
    /// writes and the flow's opener to come.
    pub fn http_request(&mut self, state: &State, ts: u64, flow: u64, stream: u32, body: u64) {
        if let Some(owner) = self.flow_owners.get(&flow).copied() {
            self.bind_executor(flow, stream, owner);
            return;
        }
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

    /// The process whose writes carried `request`: the one process with
    /// a write of the window sized like the body, else the one process
    /// whose writes of the window sum to it. Two processes that fit name
    /// nobody: a size and a time are evidence, not proof.
    fn carrier(&self, request: &Request) -> Option<u32> {
        let (ts, body) = (request.ts, request.body_bytes);
        let mut one = self
            .tls_writes
            .iter()
            .filter(|w| within(w.ts, ts) && sized(w.bytes, body))
            .map(|w| w.tgid);
        if let Some(first) = one.next() {
            return one.all(|tgid| tgid == first).then_some(first);
        }
        let mut sums: Vec<(u32, u64)> = Vec::new();
        for write in self.tls_writes.iter().filter(|w| within(w.ts, ts)) {
            match sums.iter_mut().find(|(tgid, _)| *tgid == write.tgid) {
                Some((_, sum)) => *sum += write.bytes,
                None => sums.push((write.tgid, write.bytes)),
            }
        }
        let mut fits = sums.into_iter().filter(|(_, sum)| sized(*sum, body));
        match (fits.next(), fits.next()) {
            (Some((tgid, _)), None) => Some(tgid),
            _ => None,
        }
    }

    /// The process that opened `flow`, `key` as the sensor's connect named
    /// it, made the request on (`flow`, `stream`): its bound executor,
    /// whatever the pid names by now. The open spans that came from the
    /// request take it.
    fn bind_executor(&mut self, flow: u64, stream: u32, key: ProcKey) {
        self.set_executor(flow, stream, key, true);
    }

    /// A TLS write of the process `tgid` carried the request on (`flow`,
    /// `stream`): its executor, provisionally, the pid read at the
    /// request's time `ts`. A bound executor is never replaced by a
    /// provisional one.
    fn name_executor(&mut self, state: &State, flow: u64, stream: u32, tgid: u32, ts: u64) {
        if let Some(key) = state.attribute(tgid, ts) {
            self.set_executor(flow, stream, key, false);
        }
    }

    fn set_executor(&mut self, flow: u64, stream: u32, key: ProcKey, bound: bool) {
        match self.executors.get(&(flow, stream)) {
            Some((_, true)) if !bound => return,
            Some(&named) if named == (key, bound) => return,
            Some(_) => {}
            None => self.executor_order.push_back((flow, stream)),
        }
        self.executors.insert((flow, stream), (key, bound));
        while self.executor_order.len() > MAX_EXECUTORS {
            if let Some(oldest) = self.executor_order.pop_front() {
                self.executors.remove(&oldest);
            }
        }
        self.set_span_executors((flow, stream), Some((key, bound)));
    }

    /// A provisional executor no longer stands: the request has none.
    fn unname_executor(&mut self, flow: u64, stream: u32) {
        if let Some((_, false)) = self.executors.get(&(flow, stream)) {
            self.executors.remove(&(flow, stream));
            self.executor_order.retain(|named| *named != (flow, stream));
            self.set_span_executors((flow, stream), None);
        }
    }

    /// The open spans that came from `request` take `executor`; a span
    /// whose executor is bound keeps it unless `executor` is bound too.
    fn set_span_executors(&mut self, request: (u64, u32), executor: Option<(ProcKey, bool)>) {
        let bound = executor.is_some_and(|(_, bound)| bound);
        for id in &self.open {
            if let Some(span) = self
                .spans
                .get_mut(id)
                .filter(|span| span.request == request && (bound || !span.executor_bound))
            {
                span.executor = executor.map(|(key, _)| key);
                span.executor_bound = executor.is_some_and(|(_, bound)| bound);
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
        while self.open.len() >= MAX_OPEN_SPANS {
            let oldest = self.open.remove(0);
            self.abandon(&oldest);
        }
        let raw = self
            .declared
            .as_ref()
            .and_then(|declared| declared.take(&id));
        let mut span = Span::new(open, raw, record.seq, record.ts_host_ns);
        match self.executors.get(&(open.flow, open.stream)) {
            Some(&(key, bound)) if bound || !self.flow_owners.contains_key(&open.flow) => {
                span.executor = Some(key);
                span.executor_bound = bound;
            }
            // The request's entry gone (evicted) or only provisional: the
            // flow's opener, when known, is the executor.
            _ => {
                if let Some(&owner) = self.flow_owners.get(&open.flow) {
                    span.executor = Some(owner);
                    span.executor_bound = true;
                }
            }
        }
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
            let (program, argv) = (proc.filename.clone(), proc.argv.clone());
            match self.choose(state, pending.key, &program, &argv) {
                Some((_, true))
                    if record.ts_host_ns.saturating_sub(pending.ts) > JOIN_WINDOW_NS =>
                {
                    self.pending_execs.push_back(pending);
                }
                Some((span_id, judge)) => {
                    self.join(state, &span_id, pending.key, Some(pending.seq));
                    if judge {
                        findings.extend(self.judge_argv(
                            &span_id,
                            pending.key,
                            pending.seq,
                            pending.ts,
                            &program,
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
            let taken = owner.is_none()
                && self.take_agent_effect(state, effect.who, effect.ts, &effect.kind, effect.seq);
            if !taken {
                self.recent.push_back(effect);
            }
        }
        self.index_update(&id);
        findings
    }

    /// A `tool.close`: closes the span, judges its connections and writes
    /// its `span.effects`. A span closes only by its executor (the process
    /// that opened the flow of its model request): the close must come
    /// over a flow that process opened. An agent whose requests come from
    /// several processes (a script's `curl`s) cannot be told from its own
    /// tools, so its spans stay open until the session ends. A close by another process is dropped (the span
    /// stays open for its own close); one where either opener is not known
    /// yet waits [`CLOSE_WAIT_NS`] to learn them, else is dropped. So is
    /// one for a span whose request flow is not on record once flows have
    /// been let go for room (it may have been, with its opener). A span
    /// whose request flow is not on record otherwise (a log without the
    /// gate's flows), or a session without the sensor's lineage programs,
    /// has nothing to hold a close to, and takes any.
    pub fn close(&mut self, state: &State, record: &Record, close: &ToolClose) -> Vec<Finding> {
        if !state.sensor.lineage_ok() {
            return self.apply_close(state, record, close);
        }
        match self.close_verdict(state, close) {
            Verdict::Apply => self.apply_close(state, record, close),
            Verdict::Drop => Vec::new(),
            Verdict::Wait => {
                if self.pending_closes.len() >= MAX_PENDING_CLOSES {
                    self.pending_closes.pop_front();
                }
                self.pending_closes.push_back(PendingClose {
                    record: record.clone(),
                    close: close.clone(),
                });
                Vec::new()
            }
        }
    }

    /// Whether `close` may close its span now: who opened the span's
    /// request flow (its bound executor) against who opened the close's.
    fn close_verdict(&self, state: &State, close: &ToolClose) -> Verdict {
        let Some(span) = self.spans.get(&close.tool_use_id) else {
            return Verdict::Drop;
        };
        if span.closed.is_some() || span.abandoned {
            return Verdict::Drop;
        }
        let executor = match (span.executor_bound, span.executor) {
            (true, Some(executor)) => Some(executor),
            _ => self.flow_owners.get(&span.request.0).copied(),
        };
        match (executor, self.flow_owners.get(&close.flow)) {
            // The request's flow is known but not yet who opened it: wait
            // for the sensor to say.
            (None, _) if state.flows.contains_key(&span.request.0) => Verdict::Wait,
            // Not on record, and flows have been let go for room: this one
            // may have been, and who opened it with it. Nothing shows the
            // close is the executor's: the span stays open.
            (None, _) if state.flows_let_go => Verdict::Drop,
            // No such flow on record (a log without the gate's flows):
            // nothing to hold the close to.
            (None, _) => Verdict::Apply,
            (Some(executor), Some(closer)) if executor == *closer => Verdict::Apply,
            (Some(_), Some(_)) => Verdict::Drop,
            (Some(_), None) => Verdict::Wait,
        }
    }

    /// Closes the span `close` names.
    fn apply_close(&mut self, state: &State, record: &Record, close: &ToolClose) -> Vec<Finding> {
        let id = close.tool_use_id.as_str();
        let Some(span) = self.spans.get_mut(id) else {
            return Vec::new();
        };
        if span.closed.is_some() || span.abandoned {
            return Vec::new();
        }
        span.closed = Some((record.seq, record.ts_host_ns));
        span.status = Some(close.status.clone());
        self.open.retain(|open| open != id);
        let mut findings = self.argv_at_close(state, id);
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
                span.note_exec(&exec.filename, &exec.argv);
                span.push_effect(
                    Effect {
                        seq,
                        kind: EffectKind::Exec,
                    },
                    &mut self.effect_bytes,
                );
            }
            self.index_update(&id);
            return Vec::new();
        }
        if let Some(id) = self.parent_span(state, key) {
            self.join(state, &id, key, Some(seq));
            return Vec::new();
        }
        match self.choose(state, key, &exec.filename, &exec.argv) {
            Some((id, judge)) => {
                self.join(state, &id, key, Some(seq));
                if judge {
                    self.judge_argv(&id, key, seq, ts, &exec.filename, &exec.argv)
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
                if !self.take_agent_effect(state, who, ts, &kind, seq) {
                    self.remember(RecentEffect { seq, ts, who, kind });
                }
            }
        }
    }

    /// A flow's `net.connect` met the `proc.tcp_connect` of `key`: `key`
    /// opened it, and the flow is an effect of its span.
    pub fn flow(&mut self, state: &State, flow: u64, seq: u64, ts: u64, key: ProcKey) {
        if self.flow_owners.insert(flow, key).is_none() {
            self.flow_order.push_back(flow);
        }
        while self.flow_order.len() > MAX_FLOW_OWNERS {
            if let Some(oldest) = self.flow_order.pop_front() {
                self.flow_owners.remove(&oldest);
            }
        }
        // Requests on the flow already seen: their opener is their
        // executor now, whatever a TLS write said, and they wait for no
        // more writes.
        let streams: Vec<u32> = self
            .executors
            .keys()
            .filter(|(f, _)| *f == flow)
            .map(|&(_, stream)| stream)
            .chain(
                self.requests
                    .iter()
                    .filter(|r| r.flow == flow)
                    .map(|r| r.stream),
            )
            .collect();
        for stream in streams {
            self.bind_executor(flow, stream, key);
        }
        self.requests.retain(|r| r.flow != flow);
        // Open spans whose request came over this flow and have no bound
        // executor: its opener is theirs.
        for id in &self.open {
            if let Some(span) = self.spans.get_mut(id) {
                if span.request.0 == flow && !span.executor_bound {
                    span.executor = Some(key);
                    span.executor_bound = true;
                }
            }
        }
        // Closes that waited to learn who opened their flows: applied,
        // dropped, or still waiting.
        let waiting: Vec<PendingClose> = self.pending_closes.drain(..).collect();
        for pending in waiting {
            match self.close_verdict(state, &pending.close) {
                Verdict::Apply => {
                    let findings = self.apply_close(state, &pending.record, &pending.close);
                    self.deferred_findings.extend(findings);
                }
                Verdict::Drop => {}
                Verdict::Wait => self.pending_closes.push_back(pending),
            }
        }
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
        let mut findings = std::mem::take(&mut self.deferred_findings);
        while self
            .pending_closes
            .front()
            .is_some_and(|p| now.saturating_sub(p.record.ts_host_ns) >= CLOSE_WAIT_NS)
        {
            self.pending_closes.pop_front();
        }
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
            self.let_go_effects(&id);
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
    fn choose(
        &self,
        state: &State,
        key: ProcKey,
        program: &str,
        argv: &[String],
    ) -> Option<(String, bool)> {
        if self.open.is_empty() {
            return None;
        }
        let by_argv = self.open.iter().find(|id| {
            self.spans
                .get(*id)
                .is_some_and(|span| span.carried_by(program, argv) == Some(true))
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
        // An executor by its identity, not its pid: one that has exited
        // may have left its pid to another process.
        self.session_pid == Some(key.tgid)
            || self.open.iter().any(|id| {
                self.spans
                    .get(id)
                    .is_some_and(|span| span.executor_bound && span.executor == Some(key))
            })
    }

    /// Whether `key`'s ancestry reaches the span's executor or the session
    /// root (`key` itself being the agent reaches nothing: the agent is in
    /// no span). With neither known there is nothing to reach: every
    /// process is the agent's.
    fn reaches_agent(&self, state: &State, key: ProcKey, span_id: &str) -> bool {
        // A provisional executor (a TLS write's) is evidence, never the
        // agent: only one that opened the request's flow is.
        let executor = self
            .spans
            .get(span_id)
            .filter(|span| span.executor_bound)
            .and_then(|span| span.executor);
        if executor.is_none() && self.session_pid.is_none() {
            return true;
        }
        // The agent: the bound executor by its identity (one that has
        // exited may have left its pid to another process), else the
        // session root by its pid.
        let is_agent = |candidate: ProcKey| match executor {
            Some(executor) => candidate == executor,
            None => self.session_pid == Some(candidate.tgid),
        };
        let mut current = key;
        for depth in 0..MAX_ANCESTRY {
            let Some(proc) = state.proc(current) else {
                return false;
            };
            if is_agent(proc.key) {
                return depth > 0;
            }
            if proc.ppid <= 1 {
                return false;
            }
            match state.attribute(proc.ppid, proc.first_ts) {
                Some(parent) if parent == current => return false,
                Some(parent) if is_agent(parent) => return true,
                Some(parent) => current = parent,
                // A parent not on record: the session root, alone, is
                // known by its pid.
                None => return executor.is_none() && self.session_pid == Some(proc.ppid),
            }
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
        if let Some(member_of) = self.by_proc.get(&key).cloned() {
            // Already this span's: a later exec of the same process (one
            // that waited for the span's open with its first, as when the
            // runtime runs the tool before the gate records the call) is
            // the span's effect too.
            if let (true, Some(seq)) = (member_of == id, exec_seq) {
                if let Some(span) = self.spans.get_mut(id) {
                    span.push_effect(
                        Effect {
                            seq,
                            kind: EffectKind::Exec,
                        },
                        &mut self.effect_bytes,
                    );
                }
                self.index_update(id);
            }
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
            if exec_seq.is_some() {
                if let Some(proc) = state.proc(key) {
                    span.note_exec(&proc.filename, &proc.argv);
                }
            }
            if let Some(seq) = exec_seq {
                span.push_effect(
                    Effect {
                        seq,
                        kind: EffectKind::Exec,
                    },
                    &mut self.effect_bytes,
                );
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

    /// A filesystem effect by no span's process, made by the agent (the
    /// session root or a span's bound executor): it joins the only open
    /// write tool span, or the write tool span whose declared path it
    /// touches; a shell tool's work is its process's. One by any other
    /// process joins nothing here. Without the sensor's lineage programs
    /// no process can be told from another, and any such effect is taken
    /// for the agent's.
    fn take_agent_effect(
        &mut self,
        state: &State,
        who: Who,
        ts: u64,
        kind: &EffectKind,
        seq: u64,
    ) -> bool {
        if !matches!(kind, EffectKind::Fs { .. }) {
            return false;
        }
        if state.sensor.lineage_ok() {
            let key = match who {
                Who::Tid(tid) => state.attribute(tid, ts),
                Who::Proc(key) => Some(key),
            };
            if !key.is_some_and(|key| self.is_agent(key)) {
                return false;
            }
        }
        let writers: Vec<&String> = self
            .open
            .iter()
            .filter(|id| self.spans.get(*id).is_some_and(Span::is_write_tool))
            .collect();
        let id = match writers.as_slice() {
            [] => return false,
            [only] => (*only).clone(),
            many => {
                let Some(id) = many
                    .iter()
                    .find(|id| self.spans.get(**id).is_some_and(|span| span.touches(kind)))
                else {
                    return false;
                };
                (*id).clone()
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
            span.push_effect(effect, &mut self.effect_bytes);
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
        let settled = self.order.iter().position(|id| {
            self.spans
                .get(id)
                .is_some_and(|span| !span.is_open() && span.settled && span.recorded)
        });
        // None settled: the oldest that is not open goes all the same,
        // its record written first. Open spans are bounded on their own.
        let victim = settled.or_else(|| {
            self.order
                .iter()
                .position(|id| self.spans.get(id).is_some_and(|span| !span.is_open()))
        });
        let Some(index) = victim else {
            return;
        };
        let Some(id) = self.order.remove(index) else {
            return;
        };
        self.write_record(&id);
        if let Some(span) = self.spans.remove(&id) {
            self.effect_bytes -= span.effect_bytes;
            for member in &span.members {
                self.by_proc.remove(&member.key);
            }
        }
    }

    /// Sets an open span aside: its record is written as it stands,
    /// `truncated`, and it takes nothing more.
    fn abandon(&mut self, id: &str) {
        let Some(span) = self.spans.get_mut(id) else {
            return;
        };
        span.abandoned = true;
        span.settled = true;
        span.truncated = true;
        self.write_record(id);
        self.let_go_effects(id);
        self.index_update(id);
    }

    /// Lets a settled, recorded span's effects go: nothing judges them
    /// again.
    fn let_go_effects(&mut self, id: &str) {
        if let Some(span) = self.spans.get_mut(id) {
            if span.settled && span.recorded {
                span.let_go_effects(&mut self.effect_bytes);
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

    /// Notes a shell the span took by ancestry alone whose command does
    /// not carry the declared one; [`Spans::argv_at_close`] judges it.
    fn judge_argv(
        &mut self,
        id: &str,
        key: ProcKey,
        exec_seq: u64,
        ts: u64,
        program: &str,
        argv: &[String],
    ) -> Vec<Finding> {
        let Some(span) = self.spans.get_mut(id) else {
            return Vec::new();
        };
        if span.declared.is_none() || !span.is_shell_tool() || span.mismatch.is_some() {
            return Vec::new();
        }
        // The finding quotes the command scrubbed, as a record would.
        let Some(command) = shell_command(program, argv) else {
            return Vec::new();
        };
        match span.carried_by(program, argv) {
            Some(true) => span.carried = true,
            Some(false) => span.mismatch = Some((key, exec_seq, ts, command)),
            None => {}
        }
        Vec::new()
    }

    /// `intent_effect_mismatch` / `argv`, at the close: a shell tool's span
    /// took a shell by ancestry alone whose command does not carry the
    /// declared one, and no exec in the span ever carried it (a runtime's
    /// helper shell before the command, as Claude Code under Node runs
    /// `bash -c env`, is no mismatch).
    fn argv_at_close(&mut self, state: &State, id: &str) -> Vec<Finding> {
        let Some(span) = self.spans.get(id) else {
            return Vec::new();
        };
        if span.carried || span.argv_fired {
            return Vec::new();
        }
        let (Some((key, exec_seq, ts, command)), Some(declared)) =
            (span.mismatch.clone(), span.declared_display.clone())
        else {
            return Vec::new();
        };
        let opened_seq = span.opened.0;
        let tool = span.tool_name.clone();
        let summary = format!(
            "the {tool} tool call {id} declared \"{}\", but the shell it ran (pid {}) was given \
             \"{}\", and nothing in the call ran the declared command",
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
        let paths = span.paths_display.clone();
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

/// The command a shell tool declared, as sent: `command` or `cmd` (a
/// string, or an array of strings), or a `local_shell` action's `command`.
fn declared_command(tool_name: &str, args: &Value) -> Option<Command> {
    if !SHELL_TOOLS.contains(&tool_name) {
        return None;
    }
    let value = args
        .get("command")
        .or_else(|| args.get("cmd"))
        .or_else(|| args.get("action").and_then(|action| action.get("command")))?;
    match value {
        Value::String(text) => (!text.trim().is_empty()).then(|| Command::Text(text.clone())),
        Value::Array(parts) => {
            let argv = parts
                .iter()
                .map(|part| part.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?;
            (!argv.is_empty()).then_some(Command::Argv(argv))
        }
        _ => None,
    }
}

/// The command a shell tool declared when its arguments were free text
/// (Codex's `exec` tool takes `tools.exec_command({cmd:"...", ...})`),
/// read from the arguments' summary: the quoted string after `cmd:` or
/// `command:` (with or without quotes around the name), unescaped.
fn declared_command_text(tool_name: &str, text: &str) -> Option<Command> {
    if !SHELL_TOOLS.contains(&tool_name) {
        return None;
    }
    let at = ["\"cmd\":", "cmd:", "\"command\":", "command:"]
        .iter()
        .filter_map(|key| text.find(key).map(|at| at + key.len()))
        .min()?;
    let rest = text[at..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut command = String::new();
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    command.push(next);
                }
            }
            '"' => break,
            _ => command.push(ch),
        }
    }
    (!command.trim().is_empty()).then_some(Command::Text(command))
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
    paths.extend(patch_paths(patch));
    paths.sort();
    paths.dedup();
    paths
}

/// The paths a write tool declared in free text (an `apply_patch` whose
/// input is the patch itself).
fn declared_paths_text(tool_name: &str, text: &str) -> Vec<(String, String)> {
    if !WRITE_TOOLS.contains(&tool_name) {
        return Vec::new();
    }
    let mut paths = patch_paths(text);
    paths.sort();
    paths.dedup();
    paths
}

/// The files a patch adds, updates or deletes.
fn patch_paths(patch: &str) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    for line in patch.lines() {
        for prefix in ["*** Add File: ", "*** Update File: ", "*** Delete File: "] {
            if let Some(path) = line.strip_prefix(prefix) {
                paths.push(mounted(path.trim()));
            }
        }
    }
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

/// The command a shell was given with `-c` (or `-lc`, `-ec`...), as
/// given; `None` for a program that is no shell, or a shell without one.
/// The program is the file the kernel ran (`proc.exec.filename`), never
/// `argv[0]`, which the caller sets as it likes.
///
/// The options are read as a POSIX shell reads them: they end at the
/// first operand or `--`; `-o` and `-O` (and bash's `--rcfile`,
/// `--init-file`) take one; `-c` makes the first operand the command; and
/// `-n` (or `-o noexec`) reads the command without running it, so no
/// command is run at all.
fn shell_argument<'a>(program: &str, argv: &'a [String]) -> Option<&'a String> {
    if !SHELLS.contains(&base_name(program)) {
        return None;
    }
    let mut command = false;
    let mut at = 1;
    while let Some(arg) = argv.get(at) {
        if arg == "--" || arg == "-" {
            at += 1;
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            at += if matches!(long, "rcfile" | "init-file") {
                2
            } else {
                1
            };
            continue;
        }
        let (set, flags) = match (arg.strip_prefix('-'), arg.strip_prefix('+')) {
            (Some(flags), _) => (true, flags),
            (None, Some(flags)) => (false, flags),
            (None, None) => break,
        };
        if flags.is_empty() {
            break;
        }
        at += 1;
        for (n, flag) in flags.char_indices() {
            match flag {
                'c' if set => command = true,
                'n' if set => return None,
                'o' | 'O' => {
                    // The operand: the rest of the cluster, else the next
                    // argument.
                    let rest = &flags[n + 1..];
                    let operand = if rest.is_empty() {
                        at += 1;
                        argv.get(at - 1).map(String::as_str)
                    } else {
                        Some(rest)
                    };
                    if set && flag == 'o' && operand == Some("noexec") {
                        return None;
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    if !command {
        return None;
    }
    argv.get(at)
}

/// The last part of a path.
fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether the file the kernel ran is the program `arg0` names.
fn same_program(program: &str, arg0: &str) -> bool {
    !program.is_empty() && base_name(program) == base_name(arg0)
}

/// The shell's `-c` command scrubbed as a record's arguments are, on one
/// line: what a finding quotes.
fn shell_command(program: &str, argv: &[String]) -> Option<String> {
    let command = one_line(&scrub_text(shell_argument(program, argv)?));
    (!command.is_empty()).then_some(command)
}

/// Whether an exec of `program` with `argv` carries the declared command,
/// compared exactly, the shell's quoting kept: a declared argv is the
/// exec's argv, the file run being the program it names; a declared
/// command line is the `-c` command of a shell the kernel ran (spaces at
/// either end aside), or Claude Code's wrapper around exactly it
/// ([`wraps`]), or, run without a shell, the exec's argv is its words and
/// the file run their program. The declared command merely appearing in
/// the shell's text (in a comment, beside other commands, inside a longer
/// `eval`) is not carrying it, nor is a command that reads the same once
/// its quotes are dropped, nor one given to a program that only calls
/// itself a shell.
fn carries(declared: &Command, program: &str, argv: &[String]) -> bool {
    match declared {
        Command::Argv(words) => {
            argv == words.as_slice() && words.first().is_some_and(|w| same_program(program, w))
        }
        Command::Text(text) => {
            let text = text.trim();
            if let Some(given) = shell_argument(program, argv) {
                if given.trim() == text || wraps(given, text) {
                    return true;
                }
            }
            lex(text).is_some_and(|tokens| {
                tokens.len() == argv.len()
                    && argv.first().is_some_and(|arg0| same_program(program, arg0))
                    && tokens
                        .iter()
                        .zip(argv)
                        .all(|(token, arg)| matches!(token, Tok::Word(word) if word == arg))
            })
        }
    }
}

/// Whether the shell command `text` ends as Claude Code's wrapper around
/// exactly `declared`, read as a shell reads it (quotes, escapes,
/// comments): its last `&&` part `pwd -P >| <file>`, the one before it
/// `eval <one word>` (and `< /dev/null` unless the command reads its own
/// input) whose word, unquoted, is the declared command. The parts before
/// are the runtime's own setup and are not judged here, but each must be
/// there: a comment or an open quote that swallows the rest is no
/// wrapper.
///
/// The setup is what the Claude Code at hand puts there, and it changes
/// between versions; the two parts judged have not, from 2.1.290 (the
/// form taken from its binary) through 2.1.304 (the guest's) to 2.1.306:
/// `source <its shell snapshot> 2>/dev/null || true`, `export PATH=...`
/// and, since 2.1.30x, exports of its plugins' variables joined by
/// newlines and ended by `:`, `shopt -u extglob 2>/dev/null || true`
/// (bash) or `setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL 2>/dev/null ||
/// true` (zsh), and a `{ \builtin unalias -- ...; \builtin unset -f --
/// ...; } >/dev/null 2>&1 || true` group, each of them one or more
/// non-empty `&&` parts. What is not read here: the `>nul` rewrite it
/// applies on Windows, and `CLAUDE_CODE_SHELL_PREFIX`, which runs the
/// whole line through a program of the user's; neither is a form boxcar
/// runs an agent under.
fn wraps(text: &str, declared: &str) -> bool {
    let Some(tokens) = lex(text) else {
        return false;
    };
    let parts: Vec<&[Tok]> = tokens
        .split(|t| matches!(t, Tok::Op(op) if op == "&&"))
        .collect();
    let [setup @ .., eval, last] = parts.as_slice() else {
        return false;
    };
    let last_ok = matches!(
        last,
        [Tok::Word(pwd), Tok::Word(p), Tok::Op(to), Tok::Word(file)]
            if pwd == "pwd" && p == "-P" && to == ">|" && !file.is_empty()
    );
    let word = match eval {
        [Tok::Word(e), Tok::Word(word)] if e == "eval" => word,
        [Tok::Word(e), Tok::Word(word), Tok::Op(from), Tok::Word(null)]
            if e == "eval" && from == "<" && null == "/dev/null" =>
        {
            word
        }
        _ => return false,
    };
    last_ok && word.trim() == declared && setup.iter().all(|part| !part.is_empty())
}

/// A shell token at the top level of a command.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    /// A word, its quotes and escapes resolved.
    Word(String),
    /// An operator (`&&`, `|`, `;`, `>|`, `<`, a newline...).
    Op(String),
}

/// The operators of two characters the lexer knows.
const TWO_CHAR_OPS: [&str; 7] = ["&&", "||", ">|", ">>", "<<", ">&", "<&"];

/// `text` as a shell reads its top level: words (single quotes literal,
/// double quotes with `\"`, `\\`, `\$` and `` \` `` escapes, a backslash
/// outside quotes escaping the next character), operators, and comments (a
/// `#` starting a word, to the line's end) dropped. `None` when a quote is
/// left open.
fn lex(text: &str) -> Option<Vec<Tok>> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = text.chars().peekable();
    let flush = |tokens: &mut Vec<Tok>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            tokens.push(Tok::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => word.push(c),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            c @ ('"' | '\\' | '$' | '`') => word.push(c),
                            '\n' => {}
                            c => {
                                word.push('\\');
                                word.push(c);
                            }
                        },
                        c => word.push(c),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(c) => {
                    in_word = true;
                    word.push(c);
                }
                None => {
                    in_word = true;
                    word.push('\\');
                }
            },
            '#' if !in_word => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        tokens.push(Tok::Op("\n".to_owned()));
                        break;
                    }
                }
            }
            '\n' => {
                flush(&mut tokens, &mut word, &mut in_word);
                tokens.push(Tok::Op("\n".to_owned()));
            }
            c if c.is_whitespace() => flush(&mut tokens, &mut word, &mut in_word),
            '&' | '|' | ';' | '<' | '>' | '(' | ')' => {
                flush(&mut tokens, &mut word, &mut in_word);
                let mut op = c.to_string();
                if let Some(&next) = chars.peek() {
                    let pair: String = [c, next].iter().collect();
                    if TWO_CHAR_OPS.contains(&pair.as_str()) {
                        chars.next();
                        op = pair;
                    }
                }
                tokens.push(Tok::Op(op));
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    flush(&mut tokens, &mut word, &mut in_word);
    Some(tokens)
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

/// Whitespace runs as one space, trimmed: a command on one line.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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
        let text = |t: &str| Some(Command::Text(t.to_owned()));
        let argv = |a: &[&str]| Some(Command::Argv(a.iter().map(|s| (*s).to_owned()).collect()));
        assert_eq!(
            declared_command("Bash", &json!({"command": "  ls   -la\n"})),
            text("  ls   -la\n")
        );
        assert_eq!(
            declared_command("shell", &json!({"command": ["bash", "-lc", "make test"]})),
            argv(&["bash", "-lc", "make test"])
        );
        assert_eq!(
            declared_command("exec_command", &json!({"cmd": "cargo build"})),
            text("cargo build")
        );
        assert_eq!(
            declared_command(
                "local_shell",
                &json!({"action": {"type": "exec", "command": ["ls"]}})
            ),
            argv(&["ls"])
        );
        assert_eq!(declared_command("Read", &json!({"command": "ls"})), None);
        assert_eq!(declared_command("Bash", &json!({"timeout": 5})), None);
        assert_eq!(declared_command("Bash", &json!({"command": "  "})), None);
        assert_eq!(
            declared_command("shell", &json!({"command": ["ls", 5]})),
            None
        );
    }

    #[test]
    fn a_declared_command_is_read_from_free_text_arguments() {
        let text = "text(await tools.exec_command({cmd:\"echo  hi > \\\"a b\\\"\",workdir:\"/workspace\",max_output_tokens:1000}));";
        assert_eq!(
            declared_command_text("exec", text),
            Some(Command::Text("echo  hi > \"a b\"".to_owned()))
        );
        assert_eq!(
            declared_command_text("shell", "{\"command\": \"ls -la\"}"),
            Some(Command::Text("ls -la".to_owned()))
        );
        assert_eq!(declared_command_text("Read", "cmd:\"ls\""), None);
        assert_eq!(declared_command_text("exec", "no command here"), None);
        assert_eq!(
            declared_paths_text(
                "apply_patch",
                "*** Begin Patch\n*** Update File: src/main.rs\n*** End Patch"
            ),
            vec![("workspace".to_owned(), "src/main.rs".to_owned())]
        );
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
            shell_command("/bin/sh", &argv(&["/bin/sh", "-c", "echo  hi"])),
            Some("echo hi".to_owned())
        );
        assert_eq!(
            shell_command("/usr/bin/bash", &argv(&["bash", "-lc", "make"])),
            Some("make".to_owned())
        );
        assert_eq!(
            shell_command("/usr/bin/bash", &argv(&["bash", "script.sh"])),
            None
        );
        assert_eq!(
            shell_command("/usr/bin/curl", &argv(&["curl", "-c", "jar"])),
            None
        );
        assert_eq!(shell_command("", &argv(&[])), None);
    }

    fn words(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    fn text(t: &str) -> Command {
        Command::Text(t.to_owned())
    }

    #[test]
    fn a_wrapped_command_still_carries_the_declared_one() {
        let declared = text("echo boxcar-m4 > marker.txt");
        let shell = |c: &str| words(&["bash", "-c", c]);
        assert!(carries(
            &declared,
            "/bin/bash",
            &shell("eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/claude-cwd")
        ));
        assert!(carries(
            &declared,
            "/bin/bash",
            &shell("echo boxcar-m4 > marker.txt")
        ));
        assert!(carries(&text("  ls -la\n"), "/bin/bash", &shell("ls -la")));
        // Claude Code's own setup before the eval is its own.
        assert!(carries(&declared, "/bin/bash", &shell(
                "source /tmp/snapshot.sh 2>/dev/null || true && export PATH=\"${PATH:+$PATH:}\"'/x' && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/claude-1-cwd"
            )
        ));
        // Its quoting of a quote, `'"'"'`, reads back as the quote.
        assert!(carries(
            &text("echo 'it''s'"),
            "/bin/bash",
            &shell(r#"eval 'echo '"'"'it'"'"''"'"'s'"'"'' < /dev/null && pwd -P >| /tmp/c"#)
        ));
        // A command that reads its own input gets no `< /dev/null`.
        assert!(carries(
            &text("sort < in.txt"),
            "/bin/bash",
            &shell("eval 'sort < in.txt' && pwd -P >| /tmp/c")
        ));
        // Claude Code 2.1.304, the guest's, under bash: the snapshot, the
        // PATH, `shopt`, the unalias group (a `;` and a redirection inside
        // braces), then the two parts judged.
        assert!(carries(&declared, "/bin/bash", &shell(concat!(
            "source /root/.claude/shell-snapshots/snapshot-bash-1792541123845-tgt6wz.sh 2>/dev/null || true",
            " && export PATH=\"${PATH:+$PATH:}\"'/root/.local/bin'",
            " && shopt -u extglob 2>/dev/null || true",
            " && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true",
            " && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/claude-a1b2-cwd"
        ))));
        // Claude Code 2.1.306 under zsh, as this host runs it: its plugins'
        // exports in one part, joined by newlines and ended by `:`, then
        // `setopt`, the unalias group, and the two parts judged.
        assert!(carries(&declared, "/bin/zsh", &words(&["zsh", "-c", concat!(
            "source /home/u/.claude/shell-snapshots/snapshot-zsh-1792541123845-tgt6wz.sh 2>/dev/null || true",
            " && export CODEX_COMPANION_SESSION_ID='784e8f8f-ed58-4703-b074-3cd250a05963'\n",
            "export CLAUDE_PLUGIN_DATA='/home/u/.claude/plugins/data/codex-openai-codex'\n",
            ": && setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL 2>/dev/null || true",
            " && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true",
            " && eval 'echo boxcar-m4 > marker.txt' && pwd -P >| /tmp/claude-139a-cwd"
        )])));
        // With CLAUDE_CODE_SHELL_PREFIX set, the shell-option part covers
        // both shells; the line is then run through the prefix program,
        // which is not read here.
        assert!(carries(&declared, "/bin/bash", &shell(concat!(
            "source /tmp/s.sh 2>/dev/null || true",
            " && { shopt -u extglob || setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; } >/dev/null 2>&1 || true",
            " && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c"
        ))));
        // An argv, as declared; a line run without a shell, as its words.
        let make = Command::Argv(words(&["bash", "-lc", "make test"]));
        assert!(carries(
            &make,
            "/bin/bash",
            &words(&["bash", "-lc", "make test"])
        ));
        assert!(!carries(
            &make,
            "/bin/bash",
            &words(&["bash", "-lc", "make  test"])
        ));
        assert!(carries(
            &text("ls -la 'a b'"),
            "/bin/ls",
            &words(&["ls", "-la", "a b"])
        ));
        assert!(!carries(
            &text("ls -la a b"),
            "/bin/ls",
            &words(&["ls", "-la", "a b"])
        ));
        assert!(!carries(
            &text("ls -la"),
            "/usr/bin/curl",
            &words(&["curl", "http://x/"])
        ));
        // Only the wrapper around exactly the command, as the shell reads
        // it: nothing more, nothing in a comment or an open quote.
        for other in [
            "rm -rf / # echo boxcar-m4 > marker.txt",
            "echo boxcar-m4 > marker.txt; rm -rf /",
            "eval 'echo boxcar-m4 > marker.txt; rm -rf /' < /dev/null && pwd -P >| /tmp/c",
            "eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c; rm -rf /",
            "eval 'rm -rf /; echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c",
            "xeval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c",
            "eval echo boxcar-m4 > marker.txt < /dev/null && pwd -P >| /tmp/c",
            "printf other # && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c",
            "printf \"other && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c\"",
            "printf 'other && eval ' && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c'",
            " && eval 'echo boxcar-m4 > marker.txt' < /dev/null && pwd -P >| /tmp/c",
        ] {
            assert!(!carries(&declared, "/bin/bash", &shell(other)), "{other}");
        }
        // Options as a shell reads them: an operand ends them, `-n` runs
        // nothing.
        for other in [
            &words(&["bash", "/dev/null", "-c", "echo boxcar-m4 > marker.txt"]),
            &words(&["bash", "-n", "-c", "echo boxcar-m4 > marker.txt"]),
            &words(&["bash", "-nc", "echo boxcar-m4 > marker.txt"]),
            &words(&["bash", "-o", "noexec", "-c", "echo boxcar-m4 > marker.txt"]),
            &words(&["bash", "--", "-c", "echo boxcar-m4 > marker.txt"]),
        ] {
            assert!(!carries(&declared, "/bin/bash", other), "{other:?}");
        }
        for ok in [
            &words(&["bash", "-l", "-c", "echo boxcar-m4 > marker.txt"]),
            &words(&["bash", "-c", "--", "echo boxcar-m4 > marker.txt"]),
            &words(&[
                "bash",
                "-o",
                "pipefail",
                "-c",
                "echo boxcar-m4 > marker.txt",
            ]),
            &words(&["bash", "+n", "--norc", "-c", "echo boxcar-m4 > marker.txt"]),
            &words(&[
                "bash",
                "--rcfile",
                "/x",
                "-ec",
                "echo boxcar-m4 > marker.txt",
            ]),
        ] {
            assert!(carries(&declared, "/bin/bash", ok), "{ok:?}");
        }
        // A program that only calls itself a shell runs no shell command.
        assert!(!carries(
            &declared,
            "/usr/bin/python3",
            &shell("echo boxcar-m4 > marker.txt")
        ));
        assert!(!carries(
            &make,
            "/usr/bin/python3",
            &words(&["bash", "-lc", "make test"])
        ));
        assert!(!carries(
            &text("ls -la"),
            "/usr/bin/python3",
            &words(&["ls", "-la"])
        ));
        // Quotes are kept: the same text without them is another program.
        let quoted = text("printf '%s' 'ok; id'");
        assert!(carries(
            &quoted,
            "/bin/bash",
            &shell("printf '%s' 'ok; id'")
        ));
        assert!(!carries(&quoted, "/bin/bash", &shell("printf '%s' ok; id")));
        assert!(!carries(
            &quoted,
            "/bin/bash",
            &shell("eval 'printf '\"'\"'%s'\"'\"' ok; id' < /dev/null && pwd -P >| /tmp/c")
        ));
    }

    #[test]
    fn the_lexer_reads_quotes_escapes_and_comments() {
        let word = |w: &str| Tok::Word(w.to_owned());
        let op = |o: &str| Tok::Op(o.to_owned());
        assert_eq!(
            lex(r#"a 'b c' "d\"e" f\ g && h >| i # j && k"#).unwrap(),
            [
                word("a"),
                word("b c"),
                word("d\"e"),
                word("f g"),
                op("&&"),
                word("h"),
                op(">|"),
                word("i")
            ]
        );
        assert_eq!(lex("a#b c").unwrap(), [word("a#b"), word("c")]);
        assert_eq!(
            lex("2>/dev/null").unwrap(),
            [word("2"), op(">"), word("/dev/null")]
        );
        assert_eq!(lex("'open"), None);
        assert_eq!(lex("\"open"), None);
    }

    #[test]
    fn a_record_copy_with_a_redaction_cannot_tell() {
        let open = |args: Value| ToolOpen {
            flow: 1,
            stream: 1,
            tool_use_id: "toolu_1".into(),
            tool_name: "Bash".into(),
            args_b3: None,
            args_summary: args.to_string(),
            args: Some(args),
        };
        let command = "curl -H 'X-Api-Key: k1' https://example.com/";
        let mut scrubbed = json!({"command": command});
        boxcar_proto::redact::scrub_deep(&mut scrubbed);
        let ran = words(&["bash", "-c", command]);
        // The record's copy alone: redacted, so it cannot tell.
        let span = Span::new(&open(scrubbed.clone()), None, 1, 1);
        assert_eq!(span.carried_by("/bin/bash", &ran), None);
        // With the call's arguments as sent: exact.
        let raw = Some(Declared::Json(json!({"command": command})));
        let span = Span::new(&open(scrubbed), raw, 1, 1);
        assert_eq!(span.carried_by("/bin/bash", &ran), Some(true));
        assert!(!span.declared_display.unwrap().contains("k1"));
        // A copy with nothing redacted is the original.
        let span = Span::new(&open(json!({"command": "ls -la"})), None, 1, 1);
        assert_eq!(
            span.carried_by("/bin/bash", &words(&["bash", "-c", "ls -la"])),
            Some(true)
        );
    }

    #[test]
    fn a_quoted_secret_is_quoted_scrubbed_whole() {
        let open = |args: Value| ToolOpen {
            flow: 1,
            stream: 1,
            tool_use_id: "toolu_1".into(),
            tool_name: "Bash".into(),
            args_b3: None,
            args_summary: args.to_string(),
            args: Some(args),
        };
        for command in [
            json!("client --password 'alpha beta'"),
            json!("client --password alpha\\ beta"),
            json!(["client", "--password", "alpha beta"]),
        ] {
            let mut scrubbed = json!({"command": command});
            boxcar_proto::redact::scrub_deep(&mut scrubbed);
            let raw = Some(Declared::Json(json!({"command": command})));
            let span = Span::new(&open(scrubbed), raw, 1, 1);
            let display = span.declared_display.unwrap();
            assert!(
                !display.contains("alpha") && !display.contains("beta"),
                "{display}"
            );
        }
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
    fn one_line_collapses_space_and_keeps_quotes() {
        assert_eq!(one_line("  a \t b\n\"c\"  'd' \\e "), "a b \"c\" 'd' \\e");
        assert_eq!(one_line(""), "");
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
