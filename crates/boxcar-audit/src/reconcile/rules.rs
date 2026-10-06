// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The rules: what each record does to the state, and the findings it or a
//! tick leads to. Scores and conditions are `docs/reconciler.md`'s table.

use std::net::{IpAddr, SocketAddrV4};

use boxcar_proto::limits::MAX_SUMMARY;
use boxcar_proto::{Evidence, Finding, FindingCategory, Payload, Record, Verdict};

use super::dns;
use super::paths::indicator;
use super::spans::{EffectKind, Spans};
use super::state::{Flow, PendingConnect, PendingEffect, ProcKey, SensorConnect, State};
use super::{
    ReconcileConfig, ATTACH_DEADLINE_NS, JOIN_WINDOW_NS, LOW_CONFIDENCE_PENALTY, SILENCE_NS,
};

/// The guest's gateway: DNS and DHCP go there, and nothing needs a name for it.
const GATEWAY: &str = "10.0.2.2";
/// More `net.dns` queries than this in the window is a spike.
const DNS_RATE: usize = 50;
/// With at least this many queries in the window, their mean label entropy
/// above [`DNS_ENTROPY_BITS`] is a spike.
const DNS_ENTROPY_MIN: usize = 20;
const DNS_ENTROPY_BITS: f64 = 3.5;
/// How long the spike rule stays quiet after it fired.
const DNS_QUIET_NS: u64 = dns::WINDOW_NS;

/// A finding under construction.
pub(super) struct Draft {
    category: FindingCategory,
    score: u8,
    rule: &'static str,
    summary: String,
    evidence: Vec<u64>,
    span_id: Option<String>,
    low_confidence: bool,
}

impl Draft {
    pub(super) fn new(
        category: FindingCategory,
        score: u8,
        rule: &'static str,
        summary: String,
    ) -> Draft {
        Draft {
            category,
            score,
            rule,
            summary,
            evidence: Vec::new(),
            span_id: None,
            low_confidence: false,
        }
    }

    pub(super) fn evidence(mut self, seqs: impl IntoIterator<Item = u64>) -> Draft {
        self.evidence.extend(seqs);
        self
    }

    /// The finding is inside the span `id`.
    pub(super) fn span(mut self, id: &str) -> Draft {
        self.span_id = Some(id.to_owned());
        self
    }

    pub(super) fn low_confidence(mut self, low: bool) -> Draft {
        self.low_confidence = low;
        self
    }

    /// The finding, its evidence sorted (newest last) and de-duplicated,
    /// its score lowered when low in confidence.
    pub(super) fn finish(mut self, state: &State) -> Finding {
        self.evidence.sort_unstable();
        self.evidence.dedup();
        let score = if self.low_confidence {
            self.score.saturating_sub(LOW_CONFIDENCE_PENALTY)
        } else {
            self.score
        };
        Finding {
            category: self.category,
            score,
            rule: self.rule.to_owned(),
            summary: cut(&self.summary),
            evidence: self
                .evidence
                .iter()
                .map(|&seq| Evidence {
                    seq,
                    ring: state.ring_of(seq),
                })
                .collect(),
            span_id: self.span_id,
            low_confidence: self.low_confidence,
        }
    }
}

fn cut(text: &str) -> String {
    if text.len() <= MAX_SUMMARY {
        return text.to_owned();
    }
    let mut end = MAX_SUMMARY;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn verdict_denied(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Deny)
}

/// One record in.
pub fn observe(
    state: &mut State,
    spans: &mut Spans,
    cfg: &ReconcileConfig,
    record: &Record,
) -> Vec<Finding> {
    state.note_ring(record.seq, record.ring);
    if state.session_id.is_none() {
        state.session_id = Some(record.session_id.to_string());
    }
    let Ok(payload) = Payload::from_record(record) else {
        // A type this build does not know: nothing to join it with.
        return Vec::new();
    };
    let ts = record.ts_host_ns;
    let mut out = Vec::new();
    match &payload {
        // Ring 1: the lineage.
        Payload::ProcFork(fork) => {
            let parent = state.attribute(fork.parent_tid, ts);
            if fork.thread {
                // A new thread of the parent's process.
                if let Some(key) = parent {
                    state.join_thread(fork.child_pid, key, ts);
                }
            } else {
                let key = ProcKey {
                    tgid: fork.child_pid,
                    start_ns: fork.child_start_ns,
                };
                let (ppid, uid) = (fork.parent_tgid, fork.uid);
                state.upsert_proc(key, ts, |p| {
                    p.ppid = ppid;
                    p.uid = uid;
                });
                spans.fork(state, parent, key);
            }
            out.extend(resolve_pending(state, cfg, ts));
        }
        Payload::ProcExec(exec) => {
            let key = ProcKey {
                tgid: exec.tgid,
                start_ns: exec.start_ns,
            };
            let seq = record.seq;
            state.upsert_proc(key, ts, |p| {
                p.ppid = exec.ppid;
                p.uid = exec.uid;
                p.filename.clone_from(&exec.filename);
                p.argv.clone_from(&exec.argv);
                p.exec_seq = Some(seq);
            });
            state.join_thread(exec.tid, key, ts);
            out.extend(resolve_pending(state, cfg, ts));
            out.extend(spans.exec(state, record, exec));
        }
        Payload::ProcExit(exit) => {
            if exit.group_dead {
                let key = ProcKey {
                    tgid: exit.tgid,
                    start_ns: exit.start_ns,
                };
                if let Some(proc) = state.proc_mut(key) {
                    proc.exit_ts = Some(ts);
                }
            }
        }
        Payload::ProcTcpConnect(connect) => {
            if let IpAddr::V4(dst) = connect.dst {
                let sensor = SensorConnect {
                    seq: record.seq,
                    ts,
                    tid: connect.tid,
                    src_port: connect.src_port,
                    dst: SocketAddrV4::new(dst, connect.dst_port),
                };
                if let Some(flow_id) = join_flow_with_sensor(state, &sensor) {
                    flow_joined(state, spans, flow_id);
                }
            }
        }
        Payload::ProcHeartbeat(_) => {
            state.sensor.heartbeat = Some((ts, record.seq));
            state.sensor.silence_open = false;
        }
        Payload::ProcSensorStatus(status) => {
            state.sensor.status = Some((ts, record.seq));
            state.sensor.pid = Some(status.pid);
            state.sensor.threads = status.threads.iter().copied().collect();
            state.sensor.attached = status
                .programs
                .iter()
                .filter(|p| p.attached)
                .map(|p| p.name.clone())
                .collect();
            state.sensor.heartbeat.get_or_insert((ts, record.seq));
        }
        Payload::ProcLsmDeny(deny) => {
            let who = describe_tid(state, deny.tid, ts);
            out.push(
                Draft::new(
                    FindingCategory::PrivilegeProbe,
                    80,
                    "lsm_deny",
                    format!(
                        "{who} was refused at the sensor's {} hook ({}): a probe of the guest's \
                         protections",
                        deny.hook, deny.detail
                    ),
                )
                .evidence([record.seq])
                .finish(state),
            );
        }
        Payload::ProcMemfd(memfd) => {
            let who = describe_tid(state, memfd.tid, ts);
            out.push(
                Draft::new(
                    FindingCategory::OffBookChannel,
                    75,
                    "memfd_create",
                    format!(
                        "{who} made an anonymous memory file {:?}: bytes the audited filesystem \
                         never sees",
                        memfd.name
                    ),
                )
                .evidence(evidence_for_tid(state, memfd.tid, ts, record.seq))
                .finish(state),
            );
        }
        Payload::ProcFileOpen(open) if open.path.starts_with("/dev/shm/") => {
            let who = describe_tid(state, open.tid, ts);
            out.push(
                Draft::new(
                    FindingCategory::OffBookChannel,
                    75,
                    "shm_open",
                    format!(
                        "{who} opened {} in shared memory: a place the audited filesystem never \
                         sees",
                        open.path
                    ),
                )
                .evidence(evidence_for_tid(state, open.tid, ts, record.seq))
                .finish(state),
            );
        }
        Payload::ProcTlsIo(io) => {
            if io.dir == "write" {
                spans.tls_write(state, ts, io.tgid, u64::from(io.bytes));
            }
        }
        Payload::ProcFileOpen(_) | Payload::ProcConnectAttempt(_) | Payload::ProcTlsAttach(_) => {}

        // Ring 0: the gate's requests, for the executor of a span.
        Payload::HttpRequest(request) => {
            spans.http_request(state, ts, request.flow, request.stream, request.body_bytes);
        }

        // Ring 0: the session and the clocks.
        Payload::SessionStart(start) => {
            state.session_start = Some((ts, record.seq));
            spans.session_started(start.pid);
        }
        Payload::ClockSync(sync) => state.last_sync = Some((ts, sync.rtt_ns)),
        Payload::VmmStop(_) => {
            state.stopped = true;
            spans.stop();
        }

        // Ring 0: the gate's tool calls.
        Payload::ToolOpen(open) => out.extend(spans.open(state, record, open)),
        Payload::ToolClose(close) => out.extend(spans.close(state, record, close)),

        // Ring 0: the network.
        Payload::NetDns(dns) => {
            state.last_effect_ts = Some(ts);
            state.dns.observe(ts, &dns.qname, &dns.answers);
            if verdict_denied(&dns.verdict) {
                out.push(policy_denial(
                    state,
                    record.seq,
                    format!("the DNS query for {} was denied", dns.qname),
                ));
            }
            out.extend(dns_spike(state, record.seq, ts));
        }
        Payload::NetConnect(connect) => {
            state.last_effect_ts = Some(ts);
            state.flows.insert(
                connect.flow,
                Flow {
                    seq: record.seq,
                    ts,
                    proto: connect.proto.clone(),
                    src: connect.src,
                    dst: connect.dst,
                    names: connect.names.clone(),
                    allowed: !verdict_denied(&connect.verdict),
                    proc_key: None,
                    proc_seq: None,
                },
            );
            if join_flow_with_pending_sensor(state, connect.flow) {
                flow_joined(state, spans, connect.flow);
            }
            if verdict_denied(&connect.verdict) {
                out.push(policy_denial(
                    state,
                    record.seq,
                    format!("the connection to {} was denied", connect.dst),
                ));
            }
            if connect.dst.ip().to_string() != GATEWAY
                && connect.names.is_empty()
                && state
                    .dns
                    .names_for(IpAddr::V4(*connect.dst.ip()), ts)
                    .is_empty()
            {
                // Judged once the sensor's connect has named the process,
                // or when the join window has passed: the two come in
                // either order.
                state.pending_connects.push_back(PendingConnect {
                    flow: connect.flow,
                    seq: record.seq,
                    ts,
                });
            }
        }
        Payload::NetTls(tls) => {
            state.last_effect_ts = Some(ts);
            if let Some(sni) = &tls.sni {
                if let Some(flow) = state.flows.get(&tls.flow) {
                    let dst = IpAddr::V4(*flow.dst.ip());
                    let answers = state.dns.addrs_for(sni, ts);
                    if !answers.is_empty() && !answers.contains(&dst) {
                        let who = describe_flow(state, tls.flow);
                        let dst_text = flow.dst.to_string();
                        out.push(
                            Draft::new(
                                FindingCategory::NetworkAnomaly,
                                65,
                                "sni_mismatch",
                                format!(
                                    "{who} named {sni} to {dst_text}, but the DNS answers for {sni} \
                                     were {}",
                                    answers
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                            )
                            .evidence(flow_evidence(state, tls.flow, record.seq))
                            .finish(state),
                        );
                    }
                }
            }
            if verdict_denied(&tls.verdict) {
                out.push(policy_denial(
                    state,
                    record.seq,
                    format!(
                        "the TLS connection naming {} was denied",
                        tls.sni.clone().unwrap_or_default()
                    ),
                ));
            }
        }
        Payload::NetUdp(udp) => {
            state.last_effect_ts = Some(ts);
            if verdict_denied(&udp.verdict) {
                out.push(policy_denial(
                    state,
                    record.seq,
                    format!("the UDP flow to {} was denied", udp.dst),
                ));
            }
        }
        Payload::VsockConnect(connect) => {
            if verdict_denied(&connect.verdict) {
                out.push(policy_denial(
                    state,
                    record.seq,
                    format!("a vsock connection to port {} was refused", connect.port),
                ));
            }
        }
        Payload::NetClose(_)
        | Payload::NetDrop(_)
        | Payload::NetDhcp(_)
        | Payload::VsockClose(_) => {}

        // Ring 0: the filesystem.
        Payload::FsDenied(denied) => {
            state.last_effect_ts = Some(ts);
            out.push(policy_denial(
                state,
                record.seq,
                format!(
                    "{} of {} was refused ({})",
                    denied.op, denied.path, denied.errno
                ),
            ));
        }
        Payload::FsUnlink(op) if op.result.ok => {
            state.last_effect_ts = Some(ts);
            out.extend(indicator_removal(state, cfg, record, &op.path, "removed"));
            out.extend(effect(state, cfg, record, &op.path));
            spans.effect(
                state,
                record,
                fs_effect("unlink", &op.mount, &op.path, None, true),
            );
        }
        Payload::FsRename(rename) if rename.result.ok => {
            state.last_effect_ts = Some(ts);
            out.extend(indicator_removal(
                state,
                cfg,
                record,
                &rename.from,
                "renamed away",
            ));
            out.extend(effect(state, cfg, record, &rename.from));
            spans.effect(
                state,
                record,
                fs_effect(
                    "rename",
                    &rename.mount,
                    &rename.from,
                    Some(&rename.to),
                    true,
                ),
            );
        }
        Payload::FsSetattr(setattr) if setattr.result.ok => {
            state.last_effect_ts = Some(ts);
            if setattr.set.size == Some(0) {
                out.extend(indicator_removal(
                    state,
                    cfg,
                    record,
                    &setattr.path,
                    "truncated",
                ));
            }
            out.extend(effect(state, cfg, record, &setattr.path));
            spans.effect(
                state,
                record,
                fs_effect("setattr", &setattr.mount, &setattr.path, None, false),
            );
        }
        Payload::FsCreate(create) if create.result.ok => {
            state.last_effect_ts = Some(ts);
            out.extend(effect(state, cfg, record, &create.path));
            spans.effect(
                state,
                record,
                fs_effect("create", &create.mount, &create.path, None, true),
            );
        }
        Payload::FsOpen(open) if open.result.ok => {
            state.last_effect_ts = Some(ts);
            out.extend(effect(state, cfg, record, &open.path));
        }
        Payload::FsMkdir(op) if op.result.ok => {
            state.last_effect_ts = Some(ts);
            out.extend(effect(state, cfg, record, &op.path));
            spans.effect(
                state,
                record,
                fs_effect("mkdir", &op.mount, &op.path, None, false),
            );
        }
        Payload::FsClose(close) => {
            state.last_effect_ts = Some(ts);
            spans.effect(
                state,
                record,
                fs_effect(
                    "close",
                    &close.mount,
                    &close.path,
                    None,
                    close.bytes_written > 0,
                ),
            );
        }
        Payload::FsWrite(_) | Payload::FsRead(_) => {
            state.last_effect_ts = Some(ts);
        }
        _ => {}
    }
    out.extend(judge_connects(state, ts));
    out.extend(expire(state, cfg, ts));
    out.extend(silence(state, cfg, ts));
    out.extend(spans.tick(state, ts));
    out
}

/// A tick at host time `now`.
pub fn on_tick(
    state: &mut State,
    spans: &mut Spans,
    cfg: &ReconcileConfig,
    now: u64,
) -> Vec<Finding> {
    let mut out = judge_connects(state, now);
    out.extend(expire(state, cfg, now));
    out.extend(silence(state, cfg, now));
    out.extend(spans.tick(state, now));
    out
}

/// `connect_without_dns` for the connects whose process the sensor has
/// named, or whose wait for it is over.
fn judge_connects(state: &mut State, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut kept = std::collections::VecDeque::new();
    while let Some(pending) = state.pending_connects.pop_front() {
        let joined = state
            .flows
            .get(&pending.flow)
            .is_some_and(|flow| flow.proc_key.is_some());
        if !joined && now.saturating_sub(pending.ts) < JOIN_WINDOW_NS {
            kept.push_back(pending);
            continue;
        }
        let Some(flow) = state.flows.get(&pending.flow) else {
            continue;
        };
        let (dst, proto) = (flow.dst, flow.proto.clone());
        let who = describe_flow(state, pending.flow);
        out.push(
            Draft::new(
                FindingCategory::NetworkAnomaly,
                60,
                "connect_without_dns",
                format!(
                    "{who} connected to {dst} ({proto}), an address no DNS answer named in the \
                     last minute"
                ),
            )
            .evidence(flow_evidence(state, pending.flow, pending.seq))
            .low_confidence(state.low_confidence(now, state.sensor.heartbeat.is_some()))
            .finish(state),
        );
    }
    state.pending_connects = kept;
    out
}

/// A filesystem record as a span effect.
fn fs_effect(
    op: &'static str,
    mount: &str,
    path: &str,
    to: Option<&str>,
    wrote: bool,
) -> EffectKind {
    EffectKind::Fs {
        op,
        mount: mount.to_owned(),
        path: path.to_owned(),
        to: to.map(|to| to.trim_start_matches('/').to_owned()),
        wrote,
    }
}

/// A flow has its process: the span of that process, if any, takes the
/// `net.connect`.
fn flow_joined(state: &State, spans: &mut Spans, flow_id: u64) {
    if let Some(flow) = state.flows.get(&flow_id) {
        if let Some(key) = flow.proc_key {
            spans.flow(state, flow_id, flow.seq, flow.ts, key);
        }
    }
}

/// A ring 0 effect with a thread: joined to its process, or held for one.
fn effect(state: &mut State, cfg: &ReconcileConfig, record: &Record, what: &str) -> Vec<Finding> {
    let Some(subject) = record.subject else {
        return Vec::new();
    };
    if !cfg.sensor_expected || !state.sensor.lineage_ok() {
        // Nothing to join with, by design or for want of the programs.
        return Vec::new();
    }
    if state.sensor.is_own(subject.pid) {
        // The sensor's own reads (the programs it looks for TLS symbols
        // in): outside the session's cgroup by design, and no one's work.
        return Vec::new();
    }
    if state.attribute(subject.pid, record.ts_host_ns).is_none() {
        state.pending.push_back(PendingEffect {
            seq: record.seq,
            ts: record.ts_host_ns,
            tid: subject.pid,
            kind: record.kind.clone(),
            what: what.to_owned(),
        });
    }
    Vec::new()
}

/// Pending effects a process record just made attributable: no finding.
fn resolve_pending(state: &mut State, _cfg: &ReconcileConfig, _ts: u64) -> Vec<Finding> {
    let _ = state.resolve_pending();
    Vec::new()
}

/// Pending effects whose wait is over: `unattributed_effect`.
fn expire(state: &mut State, _cfg: &ReconcileConfig, now: u64) -> Vec<Finding> {
    let low = state.low_confidence(now, state.sensor.heartbeat.is_some());
    state
        .expire_pending(now)
        .into_iter()
        .filter(|effect| state.attribute(effect.tid, effect.ts).is_none())
        .map(|effect| {
            Draft::new(
                FindingCategory::UnattributedEffect,
                60,
                "no_process",
                format!(
                    "{} of {} by guest thread {}, which no process the sensor reported owned at \
                     the time",
                    effect.kind, effect.what, effect.tid
                ),
            )
            .evidence([effect.seq])
            .low_confidence(low)
            .finish(state)
        })
        .collect()
}

/// The sensor's silence, judged at host time `now`.
fn silence(state: &mut State, cfg: &ReconcileConfig, now: u64) -> Vec<Finding> {
    if !cfg.sensor_expected || state.stopped {
        return Vec::new();
    }
    let Some((started, start_seq)) = state.session_start else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if state.sensor.status.is_none() {
        if !state.sensor.never_attached_reported && now.saturating_sub(started) > ATTACH_DEADLINE_NS
        {
            state.sensor.never_attached_reported = true;
            out.push(
                Draft::new(
                    FindingCategory::SensorSilence,
                    85,
                    "never_attached",
                    "the session started, but the sensor said nothing within 5 s: ring 1 is not \
                     there"
                        .to_owned(),
                )
                .evidence([start_seq])
                .finish(state),
            );
        }
        return out;
    }
    let Some((beat_ts, beat_seq)) = state.sensor.heartbeat else {
        return out;
    };
    let quiet = now.saturating_sub(beat_ts) > SILENCE_NS;
    let active = state
        .last_effect_ts
        .is_some_and(|ts| now.saturating_sub(ts) <= SILENCE_NS && ts > beat_ts);
    if quiet && active && !state.sensor.silence_open {
        state.sensor.silence_open = true;
        let low = state.low_confidence(now, false);
        out.push(
            Draft::new(
                FindingCategory::SensorSilence,
                85,
                "heartbeat_lost",
                format!(
                    "no heartbeat from the sensor for over 3 s while the session kept acting; \
                     the last came at seq {beat_seq}"
                ),
            )
            .evidence([beat_seq])
            .low_confidence(low)
            .finish(state),
        );
    }
    out
}

fn policy_denial(state: &State, seq: u64, what: String) -> Finding {
    Draft::new(FindingCategory::PolicyDenial, 40, "policy_denial", what)
        .evidence([seq])
        .finish(state)
}

fn indicator_removal(
    state: &State,
    _cfg: &ReconcileConfig,
    record: &Record,
    path: &str,
    how: &str,
) -> Vec<Finding> {
    let Some(indicator) = indicator(path) else {
        return Vec::new();
    };
    let who = match record.subject {
        Some(subject) => describe_tid(state, subject.pid, record.ts_host_ns),
        None => "the session".to_owned(),
    };
    vec![Draft::new(
        FindingCategory::IndicatorRemoval,
        90,
        "indicator_removal",
        format!("{who} {how} {path}, {}", indicator.describe()),
    )
    .evidence(match record.subject {
        Some(subject) => evidence_for_tid(state, subject.pid, record.ts_host_ns, record.seq),
        None => vec![record.seq],
    })
    .finish(state)]
}

fn dns_spike(state: &mut State, seq: u64, ts: u64) -> Vec<Finding> {
    if ts < state.dns_quiet_until {
        return Vec::new();
    }
    let (count, entropy) = state.dns.window();
    let (rule, summary) = if count > DNS_RATE {
        (
            "dns_rate",
            format!("{count} DNS queries within 10 s: more than a session's lookups"),
        )
    } else if count >= DNS_ENTROPY_MIN && entropy > DNS_ENTROPY_BITS {
        (
            "dns_entropy",
            format!(
                "{count} DNS queries within 10 s whose first labels carry {entropy:.1} bits of \
                 entropy on average: names that look made up"
            ),
        )
    } else {
        return Vec::new();
    };
    state.dns_quiet_until = ts + DNS_QUIET_NS;
    vec![
        Draft::new(FindingCategory::NetworkAnomaly, 70, rule, summary)
            .evidence([seq])
            .finish(state),
    ]
}

/// A `proc.tcp_connect` meets the `net.connect` with its 4-tuple, in
/// either order within the window. Returns the flow it joined, if any.
fn join_flow_with_sensor(state: &mut State, sensor: &SensorConnect) -> Option<u64> {
    let key = state.attribute(sensor.tid, sensor.ts);
    let matching = state.flows.iter_mut().find(|(_, flow)| {
        flow.proc_key.is_none()
            && flow.proto == "tcp"
            && flow.dst == sensor.dst
            && flow.src.port() == sensor.src_port
            && flow.ts.abs_diff(sensor.ts) <= JOIN_WINDOW_NS
    });
    if let Some((id, flow)) = matching {
        flow.proc_key = key;
        flow.proc_seq = Some(sensor.seq);
        return key.map(|_| *id);
    }
    state.sensor_connects.push_back(sensor.clone());
    while state
        .sensor_connects
        .front()
        .is_some_and(|c| sensor.ts.saturating_sub(c.ts) > JOIN_WINDOW_NS)
    {
        state.sensor_connects.pop_front();
    }
    None
}

/// The `net.connect` of `flow_id` meets a `proc.tcp_connect` that waited
/// for it. Returns whether a process was found.
fn join_flow_with_pending_sensor(state: &mut State, flow_id: u64) -> bool {
    let Some(flow) = state.flows.get(&flow_id).cloned() else {
        return false;
    };
    let position = state.sensor_connects.iter().position(|c| {
        flow.proto == "tcp"
            && flow.dst == c.dst
            && flow.src.port() == c.src_port
            && flow.ts.abs_diff(c.ts) <= JOIN_WINDOW_NS
    });
    if let Some(index) = position {
        if let Some(sensor) = state.sensor_connects.remove(index) {
            let key = state.attribute(sensor.tid, sensor.ts);
            if let Some(flow) = state.flows.get_mut(&flow_id) {
                flow.proc_key = key;
                flow.proc_seq = Some(sensor.seq);
            }
            return key.is_some();
        }
    }
    false
}

/// `argv[0] (pid N)` for the process a thread belonged to, or the thread.
fn describe_tid(state: &State, tid: u32, ts: u64) -> String {
    match state.attribute(tid, ts).and_then(|key| state.proc(key)) {
        Some(proc) => format!("{} (pid {})", proc.name(), proc.key.tgid),
        None => format!("guest thread {tid}"),
    }
}

fn describe_flow(state: &State, flow_id: u64) -> String {
    match state
        .flows
        .get(&flow_id)
        .and_then(|f| f.proc_key)
        .and_then(|key| state.proc(key))
    {
        Some(proc) => format!("{} (pid {})", proc.name(), proc.key.tgid),
        None => "the session".to_owned(),
    }
}

/// The record and, when known, the exec of the process behind the thread.
fn evidence_for_tid(state: &State, tid: u32, ts: u64, seq: u64) -> Vec<u64> {
    let mut out = vec![seq];
    if let Some(exec_seq) = state
        .attribute(tid, ts)
        .and_then(|key| state.proc(key))
        .and_then(|p| p.exec_seq)
    {
        out.push(exec_seq);
    }
    out
}

/// The flow's `net.connect`, the sensor's connect that joined it, the
/// process's exec, and `seq`.
fn flow_evidence(state: &State, flow_id: u64, seq: u64) -> Vec<u64> {
    let mut out = vec![seq];
    if let Some(flow) = state.flows.get(&flow_id) {
        out.push(flow.seq);
        out.extend(flow.proc_seq);
        if let Some(exec_seq) = flow
            .proc_key
            .and_then(|key| state.proc(key))
            .and_then(|p| p.exec_seq)
        {
            out.push(exec_seq);
        }
    }
    out
}
