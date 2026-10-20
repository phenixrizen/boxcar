// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A log as one OpenTelemetry trace: an `ExportTraceServiceRequest` in
//! OTLP/JSON (lowerCamelCase keys, hex ids, integer enums, 64-bit integers
//! as decimal strings), pretty-printed with a trailing newline.
//!
//! The trace id is the session id. Its spans:
//! - **the session**, from `vmm.start` (else the first record) to
//!   `vmm.stop` (else the last record);
//! - **a model call** per `llm.request`, ended by its `llm.response`: the one
//!   on the same `(flow, stream)` that answers the latest unanswered
//!   request, as WebSocket carries several calls on one stream. A response
//!   with no request opens nothing and is counted as unpaired;
//! - **a tool call** per occurrence of a `tool_use_id`, as `span.effects`
//!   defines it: opened by the `tool.open` at its `opened_seq`, ended only by
//!   the close at its `closed_seq` (a null one stays open). A `tool.open`
//!   no `span.effects` names is an occurrence of its own, ended by the next
//!   close of its id and marked unconfirmed. Its parent is the model call
//!   open on its `(flow, stream)` when it was recorded.
//!
//! Each `finding` is an event on the span it names, else on the session.
//! The attributes follow the GenAI conventions (semantic-conventions-genai
//! 547934a), with `gen_ai.system` beside `gen_ai.provider.name`. Of the
//! log's text only the identifiers those name (model and tool names,
//! `tool_use_id`s, the image) appear, each through
//! [`boxcar_proto::redact::scrub_text`], and the findings' summaries, which
//! the log holds scrubbed.

use std::collections::{BTreeMap, BTreeSet};

use boxcar_proto::redact::scrub_text;
use boxcar_proto::{Finding, Payload, Record, SpanEffects, ToolClose};
use serde::Serialize;

use super::Log;

/// `SPAN_KIND_INTERNAL`.
const KIND_INTERNAL: u8 = 1;
/// `SPAN_KIND_CLIENT`.
const KIND_CLIENT: u8 = 3;
/// `STATUS_CODE_OK`.
const STATUS_OK: u8 = 1;
/// `STATUS_CODE_ERROR`.
const STATUS_ERROR: u8 = 2;

/// What an export holds, for its summary line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub spans: usize,
    pub events: usize,
    pub records: usize,
    /// Model responses with no request to pair with.
    pub unpaired: usize,
}

/// The log as an OTLP/JSON trace, and what it holds.
pub fn export(log: &Log) -> (Vec<u8>, Summary) {
    let mut summary = Summary {
        records: log.entries.len(),
        ..Summary::default()
    };
    let request = Request {
        resource_spans: match Trace::build(log, &mut summary) {
            Some(trace) => vec![trace.resource_spans(log)],
            None => Vec::new(),
        },
    };
    let mut bytes = serde_json::to_vec_pretty(&request).unwrap_or_default();
    bytes.push(b'\n');
    (bytes, summary)
}

/// A span being built.
struct SpanDraft {
    /// The seq of the record that opened it, which orders the spans.
    open_seq: u64,
    /// What its id is hashed from.
    id_from: Vec<u8>,
    /// Its parent, by index; the session's is `None`.
    parent: Option<usize>,
    name: String,
    kind: u8,
    start: u64,
    end: u64,
    attributes: Vec<KeyValue>,
    events: Vec<Event>,
    status: Option<Status>,
}

/// A tool call's occurrence.
struct Occurrence {
    tool_use_id: String,
    open_seq: u64,
    span: usize,
    /// The `span.effects` that defines it, if the log has one.
    effects: Option<(u64, SpanEffects)>,
    /// Without effects: the first close of its id after the open.
    close: Option<u64>,
}

struct Trace {
    spans: Vec<SpanDraft>,
}

impl Trace {
    /// The spans of `log`, or `None` for a log with no records.
    fn build(log: &Log, summary: &mut Summary) -> Option<Trace> {
        let first = log.entries.first()?;
        let last = log.entries.last()?;
        let at = |seq: u64| -> Option<&Record> {
            usize::try_from(seq.checked_sub(first.record.seq)?)
                .ok()
                .and_then(|i| log.entries.get(i))
                .map(|e| &e.record)
        };

        // Each occurrence `span.effects` defines, by the seq of its open.
        let mut defined: BTreeMap<(String, u64), (u64, SpanEffects)> = BTreeMap::new();
        for entry in &log.entries {
            if let Some(Payload::SpanEffects(effects)) = &entry.payload {
                defined
                    .entry((effects.span_id.clone(), effects.opened_seq))
                    .or_insert((entry.record.seq, effects.clone()));
            }
        }

        let start_record = log
            .entries
            .iter()
            .find(|e| matches!(e.payload, Some(Payload::VmmStart(_))))
            .map_or(&first.record, |e| &e.record);
        let stop = log.entries.iter().find_map(|e| match &e.payload {
            Some(Payload::VmmStop(stop)) => Some((&e.record, stop)),
            _ => None,
        });
        let session_end = stop.map_or(last.record.ts_host_ns, |(r, _)| r.ts_host_ns);

        let mut spans = vec![session_span(log, start_record, stop, session_end)];
        // The model calls still open, by `(flow, stream)`, latest last.
        let mut open_calls: BTreeMap<(u64, u32), Vec<usize>> = BTreeMap::new();
        let mut occurrences: Vec<Occurrence> = Vec::new();
        let mut seen_ids: BTreeSet<String> = BTreeSet::new();

        for entry in &log.entries {
            let record = &entry.record;
            match &entry.payload {
                Some(Payload::LlmRequest(req)) => {
                    let span = spans.len();
                    spans.push(model_call(record, req));
                    open_calls
                        .entry((req.flow, req.stream))
                        .or_default()
                        .push(span);
                }
                Some(Payload::LlmResponse(resp)) => {
                    match open_calls
                        .get_mut(&(resp.flow, resp.stream))
                        .and_then(Vec::pop)
                    {
                        Some(span) => answer(&mut spans[span], record, resp),
                        None => summary.unpaired += 1,
                    }
                }
                Some(Payload::ToolOpen(open)) => {
                    let id = &open.tool_use_id;
                    let effects = defined.get(&(id.clone(), record.seq)).cloned();
                    if effects.is_none() && open_at(&occurrences, id, record.seq) {
                        // The reconciler's ignored duplicate.
                        continue;
                    }
                    let parent = open_calls
                        .get(&(open.flow, open.stream))
                        .and_then(|calls| calls.last().copied())
                        .unwrap_or(0);
                    let id_from = if seen_ids.insert(id.clone()) {
                        id.as_bytes().to_vec()
                    } else {
                        format!("{id} {}", record.seq).into_bytes()
                    };
                    let span = spans.len();
                    spans.push(tool_call(record, open, parent, id_from));
                    occurrences.push(Occurrence {
                        tool_use_id: id.clone(),
                        open_seq: record.seq,
                        span,
                        effects,
                        close: None,
                    });
                }
                Some(Payload::ToolClose(close)) => {
                    for occurrence in occurrences.iter_mut().filter(|o| {
                        o.tool_use_id == close.tool_use_id
                            && o.effects.is_none()
                            && o.close.is_none()
                    }) {
                        occurrence.close = Some(record.seq);
                    }
                }
                Some(Payload::Finding(finding)) => {
                    let target = finding
                        .span_id
                        .as_ref()
                        .and_then(|id| {
                            occurrences
                                .iter()
                                .rev()
                                .find(|o| &o.tool_use_id == id && o.open_seq < record.seq)
                        })
                        .map_or(0, |o| o.span);
                    let unresolved = finding.span_id.as_deref().filter(|_| target == 0);
                    spans[target]
                        .events
                        .push(finding_event(record, finding, unresolved));
                }
                _ => {}
            }
        }

        for occurrence in &occurrences {
            let span = &mut spans[occurrence.span];
            match &occurrence.effects {
                Some((_, effects)) => {
                    span.attributes.extend(effects_attributes(effects));
                    match effects.closed_seq.and_then(at) {
                        Some(close) => end_tool(span, close),
                        None => {
                            span.end = session_end;
                            span.attributes
                                .push(KeyValue::bool("boxcar.span.open", true));
                        }
                    }
                }
                None => match occurrence.close.and_then(at) {
                    Some(close) => {
                        end_tool(span, close);
                        span.attributes
                            .push(KeyValue::bool("boxcar.span.close_unconfirmed", true));
                    }
                    None => span.end = session_end,
                },
            }
        }
        for span in &mut spans {
            span.end = span.end.max(span.start);
        }
        summary.spans = spans.len();
        summary.events = spans.iter().map(|s| s.events.len()).sum();
        Some(Trace { spans })
    }

    fn resource_spans(self, log: &Log) -> ResourceSpans {
        let trace_id = log
            .session_id()
            .map(|id| id.as_str().replace('-', ""))
            .unwrap_or_default();
        let mut order: Vec<usize> = (0..self.spans.len()).collect();
        order.sort_by_key(|&i| (self.spans[i].open_seq, i));
        let ids = assign_ids(&self.spans);
        let spans = order
            .into_iter()
            .map(|i| {
                let draft = &self.spans[i];
                Span {
                    trace_id: trace_id.clone(),
                    span_id: hex(&ids[i]),
                    parent_span_id: draft.parent.map(|p| hex(&ids[p])).unwrap_or_default(),
                    name: draft.name.clone(),
                    kind: draft.kind,
                    start_time_unix_nano: draft.start.to_string(),
                    end_time_unix_nano: draft.end.to_string(),
                    attributes: draft.attributes.clone(),
                    events: draft.events.clone(),
                    status: draft.status.clone(),
                }
            })
            .collect();
        ResourceSpans {
            resource: Resource {
                attributes: resource_attributes(log),
            },
            scope_spans: vec![ScopeSpans {
                scope: Scope {
                    name: "boxcar".into(),
                    version: log.version().map(str::to_owned),
                },
                spans,
            }],
        }
    }
}

/// Whether an occurrence of `id` without `span.effects`, or with ones that
/// say it was still open at `seq`, is open at `seq`: then a `tool.open` of
/// the same id there is a duplicate.
fn open_at(occurrences: &[Occurrence], id: &str, seq: u64) -> bool {
    occurrences
        .iter()
        .rev()
        .find(|o| o.tool_use_id == id)
        .is_some_and(|o| match &o.effects {
            Some((_, effects)) => effects.closed_seq.is_none_or(|closed| closed > seq),
            None => o.close.is_none(),
        })
}

/// Each span's id: 8 bytes of BLAKE3 of what it is hashed from, the first 8
/// unless they are zero or already taken in the trace, then the next.
fn assign_ids(spans: &[SpanDraft]) -> Vec<[u8; 8]> {
    let mut taken: BTreeSet<[u8; 8]> = BTreeSet::new();
    let mut order: Vec<usize> = (0..spans.len()).collect();
    order.sort_by_key(|&i| (spans[i].open_seq, i));
    let mut ids = vec![[0u8; 8]; spans.len()];
    for i in order {
        let mut xof = blake3::Hasher::new()
            .update(&spans[i].id_from)
            .finalize_xof();
        loop {
            let mut id = [0u8; 8];
            xof.fill(&mut id);
            if id != [0; 8] && taken.insert(id) {
                ids[i] = id;
                break;
            }
        }
    }
    ids
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record_attributes(record: &Record) -> [KeyValue; 2] {
    [
        KeyValue::int("boxcar.record.seq", record.seq),
        KeyValue::string("boxcar.record.hash", record.hash.to_string()),
    ]
}

fn resource_attributes(log: &Log) -> Vec<KeyValue> {
    let mut attributes = vec![KeyValue::string("service.name", "boxcar")];
    if let Some(version) = log.version() {
        attributes.push(KeyValue::string("service.version", version));
    }
    if let Some(id) = log.session_id() {
        attributes.push(KeyValue::string("boxcar.session.id", id.as_str()));
    }
    for entry in &log.entries {
        match &entry.payload {
            Some(Payload::VmmStart(start)) => {
                if let Some(image) = &start.image {
                    attributes.push(KeyValue::string(
                        "boxcar.image.reference",
                        scrub_text(&image.reference),
                    ));
                    attributes.push(KeyValue::string(
                        "boxcar.image.manifest_digest",
                        image.manifest_digest.as_str(),
                    ));
                }
                if let Some(hardening) = &start.hardening {
                    attributes.push(KeyValue::string(
                        "boxcar.hardening.seccomp",
                        word(&hardening.seccomp),
                    ));
                    attributes.push(KeyValue::string(
                        "boxcar.hardening.landlock",
                        word(&hardening.landlock),
                    ));
                }
            }
            Some(Payload::PolicyLoaded(loaded)) => {
                if let Some(sha) = &loaded.sha256 {
                    attributes.push(KeyValue::string("boxcar.policy.sha256", sha.as_str()));
                }
            }
            _ => {}
        }
    }
    attributes
}

/// A unit enum's wire name, such as `enforce`.
fn word(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn session_span(
    log: &Log,
    start: &Record,
    stop: Option<(&Record, &boxcar_proto::VmmStop)>,
    end: u64,
) -> SpanDraft {
    let mut attributes = record_attributes(start).to_vec();
    let mut status = None;
    match stop {
        Some((_, stop)) => {
            attributes.push(KeyValue::string(
                "boxcar.vmm.stop.reason",
                stop.reason.as_str(),
            ));
            if let Some(code) = stop.exit_code {
                attributes.push(KeyValue::signed("boxcar.vmm.exit_code", i64::from(code)));
            }
            if matches!(
                stop.reason.as_str(),
                "vcpu_error" | "audit_failed" | "vmm_error"
            ) {
                status = Some(Status::error(&stop.reason));
            }
        }
        None => status = Some(Status::error("no vmm.stop: the session did not stop")),
    }
    if let Some(cut) = &log.report.incomplete {
        attributes.push(KeyValue::string("boxcar.log.incomplete", cut.kind.as_str()));
    }
    let mut id_from = b"boxcar.session ".to_vec();
    id_from.extend_from_slice(&start.hash.0);
    SpanDraft {
        open_seq: start.seq,
        id_from,
        parent: None,
        name: "boxcar.session".into(),
        kind: KIND_INTERNAL,
        start: start.ts_host_ns,
        end,
        attributes,
        events: Vec::new(),
        status,
    }
}

/// `anthropic` or `openai`, the GenAI conventions' provider for a
/// recorded API.
fn provider(api: &str) -> &'static str {
    if api.starts_with("openai") {
        "openai"
    } else {
        "anthropic"
    }
}

fn model_call(record: &Record, req: &boxcar_proto::LlmRequest) -> SpanDraft {
    let model = req.model.as_deref().map(scrub_text);
    let mut attributes = record_attributes(record).to_vec();
    attributes.extend([
        KeyValue::string("gen_ai.operation.name", "chat"),
        KeyValue::string("gen_ai.provider.name", provider(&req.provider)),
        KeyValue::string("gen_ai.system", provider(&req.provider)),
    ]);
    if let Some(model) = &model {
        attributes.push(KeyValue::string("gen_ai.request.model", model.as_str()));
    }
    if let Some(max) = req.max_tokens {
        attributes.push(KeyValue::int("gen_ai.request.max_tokens", max));
    }
    attributes.extend([
        KeyValue::bool("gen_ai.request.stream", req.streaming),
        KeyValue::string("boxcar.llm.api", req.provider.as_str()),
        KeyValue::int("boxcar.net.flow", req.flow),
        KeyValue::int("boxcar.http.stream", u64::from(req.stream)),
    ]);
    let mut id_from = b"boxcar.chat ".to_vec();
    id_from.extend_from_slice(&record.hash.0);
    SpanDraft {
        open_seq: record.seq,
        id_from,
        parent: Some(0),
        name: match &model {
            Some(model) => format!("chat {model}"),
            None => "chat".into(),
        },
        kind: KIND_CLIENT,
        start: record.ts_host_ns,
        end: record.ts_host_ns,
        attributes,
        events: Vec::new(),
        status: None,
    }
}

/// A model call's span, now answered by `resp` at `record`.
fn answer(span: &mut SpanDraft, record: &Record, resp: &boxcar_proto::LlmResponse) {
    span.end = record.ts_host_ns;
    let attributes = &mut span.attributes;
    if let Some(model) = &resp.model {
        attributes.push(KeyValue::string("gen_ai.response.model", scrub_text(model)));
    }
    if let Some(reason) = &resp.stop_reason {
        attributes.push(KeyValue::strings(
            "gen_ai.response.finish_reasons",
            &[scrub_text(reason)],
        ));
    }
    // The conventions' input tokens include the cached ones: Anthropic
    // counts those apart, OpenAI within.
    let input = match (
        provider(&resp.provider),
        resp.input_tokens,
        resp.cache_read_tokens,
    ) {
        ("anthropic", Some(input), Some(cached)) => Some(input.saturating_add(cached)),
        (_, input, _) => input,
    };
    if let Some(input) = input {
        attributes.push(KeyValue::int("gen_ai.usage.input_tokens", input));
    }
    if let Some(cached) = resp.cache_read_tokens {
        attributes.push(KeyValue::int(
            "gen_ai.usage.cache_read.input_tokens",
            cached,
        ));
    }
    if let Some(output) = resp.output_tokens {
        attributes.push(KeyValue::int("gen_ai.usage.output_tokens", output));
    }
    attributes.push(KeyValue::int(
        "boxcar.llm.tool_uses",
        u64::from(resp.tool_uses),
    ));
    if let Some(degraded) = &resp.degraded {
        attributes.push(KeyValue::string("error.type", degraded.as_str()));
        span.status = Some(Status::error(degraded));
    }
    attributes.push(KeyValue::int("boxcar.response.seq", record.seq));
    attributes.push(KeyValue::string(
        "boxcar.response.hash",
        record.hash.to_string(),
    ));
}

fn tool_call(
    record: &Record,
    open: &boxcar_proto::ToolOpen,
    parent: usize,
    id_from: Vec<u8>,
) -> SpanDraft {
    let name = scrub_text(&open.tool_name);
    let mut attributes = record_attributes(record).to_vec();
    attributes.extend([
        KeyValue::string("gen_ai.operation.name", "execute_tool"),
        KeyValue::string("gen_ai.tool.name", name.as_str()),
        KeyValue::string("gen_ai.tool.call.id", scrub_text(&open.tool_use_id)),
    ]);
    if let Some(b3) = &open.args_b3 {
        attributes.push(KeyValue::string("boxcar.tool.args_b3", b3.as_str()));
    }
    SpanDraft {
        open_seq: record.seq,
        id_from,
        parent: Some(parent),
        name: format!("execute_tool {name}"),
        kind: KIND_INTERNAL,
        start: record.ts_host_ns,
        end: record.ts_host_ns,
        attributes,
        events: Vec::new(),
        status: None,
    }
}

fn effects_attributes(effects: &SpanEffects) -> Vec<KeyValue> {
    let procs: Vec<u64> = effects.procs.iter().map(|&p| u64::from(p)).collect();
    let mut attributes = vec![
        KeyValue::ints("boxcar.span.procs", &procs),
        KeyValue::ints("boxcar.span.effects", &effects.effects),
    ];
    if let Some(tgid) = effects.executor_tgid {
        attributes.push(KeyValue::int("boxcar.span.executor_tgid", u64::from(tgid)));
    }
    attributes.push(KeyValue::bool("boxcar.span.truncated", effects.truncated));
    attributes
}

/// A tool span, ended by the close at `close`, with its status.
fn end_tool(span: &mut SpanDraft, close: &Record) {
    span.end = close.ts_host_ns;
    span.attributes
        .push(KeyValue::int("boxcar.close.seq", close.seq));
    if close.kind == "tool.close" {
        if let Ok(close) = serde_json::from_value::<ToolClose>(close.data.clone()) {
            span.status = Some(if close.status == "ok" {
                Status::ok()
            } else {
                Status::error(&close.status)
            });
        }
    }
}

fn finding_event(record: &Record, finding: &Finding, unresolved: Option<&str>) -> Event {
    let evidence: Vec<u64> = finding.evidence.iter().map(|e| e.seq).collect();
    let mut attributes = vec![
        KeyValue::string("boxcar.finding.category", word(&finding.category)),
        KeyValue::int("boxcar.finding.score", u64::from(finding.score)),
        KeyValue::string("boxcar.finding.rule", finding.rule.as_str()),
        KeyValue::string("boxcar.finding.summary", finding.summary.as_str()),
        KeyValue::ints("boxcar.finding.evidence", &evidence),
        KeyValue::bool("boxcar.finding.low_confidence", finding.low_confidence),
    ];
    if let Some(id) = unresolved {
        attributes.push(KeyValue::string("boxcar.finding.span_id", scrub_text(id)));
    }
    attributes.extend(record_attributes(record));
    Event {
        time_unix_nano: record.ts_host_ns.to_string(),
        name: "boxcar.finding".into(),
        attributes,
    }
}

// The OTLP/JSON shapes, in the field order the encoding gives them.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    resource_spans: Vec<ResourceSpans>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceSpans {
    resource: Resource,
    scope_spans: Vec<ScopeSpans>,
}

#[derive(Serialize)]
struct Resource {
    attributes: Vec<KeyValue>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSpans {
    scope: Scope,
    spans: Vec<Span>,
}

#[derive(Serialize)]
struct Scope {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Span {
    trace_id: String,
    span_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    parent_span_id: String,
    name: String,
    kind: u8,
    start_time_unix_nano: String,
    end_time_unix_nano: String,
    attributes: Vec<KeyValue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    time_unix_nano: String,
    name: String,
    attributes: Vec<KeyValue>,
}

#[derive(Clone, Serialize)]
struct Status {
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
    code: u8,
}

impl Status {
    fn ok() -> Status {
        Status {
            message: String::new(),
            code: STATUS_OK,
        }
    }

    fn error(message: &str) -> Status {
        Status {
            message: message.to_owned(),
            code: STATUS_ERROR,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct KeyValue {
    key: String,
    value: AnyValue,
}

/// An attribute's value, as OTLP/JSON writes `AnyValue`.
#[derive(Clone, Debug, PartialEq, Serialize)]
enum AnyValue {
    #[serde(rename = "stringValue")]
    Str(String),
    /// A signed 64-bit integer, as a decimal string.
    #[serde(rename = "intValue")]
    Int(String),
    #[serde(rename = "boolValue")]
    Bool(bool),
    #[serde(rename = "arrayValue")]
    Array(ArrayValue),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ArrayValue {
    values: Vec<AnyValue>,
}

impl KeyValue {
    fn new(key: &str, value: AnyValue) -> KeyValue {
        KeyValue {
            key: key.to_owned(),
            value,
        }
    }

    fn string(key: &str, value: impl Into<String>) -> KeyValue {
        KeyValue::new(key, AnyValue::Str(value.into()))
    }

    fn bool(key: &str, value: bool) -> KeyValue {
        KeyValue::new(key, AnyValue::Bool(value))
    }

    /// An unsigned count: `intValue` while it fits a signed 64-bit integer,
    /// else `stringValue`.
    fn int(key: &str, value: u64) -> KeyValue {
        KeyValue::new(key, unsigned(value))
    }

    fn signed(key: &str, value: i64) -> KeyValue {
        KeyValue::new(key, AnyValue::Int(value.to_string()))
    }

    /// An array of unsigned counts: all strings if any does not fit.
    fn ints(key: &str, values: &[u64]) -> KeyValue {
        let fit = values.iter().all(|&v| i64::try_from(v).is_ok());
        let values = values
            .iter()
            .map(|v| {
                if fit {
                    AnyValue::Int(v.to_string())
                } else {
                    AnyValue::Str(v.to_string())
                }
            })
            .collect();
        KeyValue::new(key, AnyValue::Array(ArrayValue { values }))
    }

    fn strings(key: &str, values: &[String]) -> KeyValue {
        let values = values.iter().map(|v| AnyValue::Str(v.clone())).collect();
        KeyValue::new(key, AnyValue::Array(ArrayValue { values }))
    }
}

fn unsigned(value: u64) -> AnyValue {
    if i64::try_from(value).is_ok() {
        AnyValue::Int(value.to_string())
    } else {
        AnyValue::Str(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A count past `i64::MAX` is a string, alone or in an array.
    #[test]
    fn counts_past_i64_are_strings() {
        assert_eq!(unsigned(7), AnyValue::Int("7".into()));
        let big = u64::MAX;
        assert_eq!(unsigned(big), AnyValue::Str(big.to_string()));
        let array = KeyValue::ints("k", &[1, big]);
        assert_eq!(
            array.value,
            AnyValue::Array(ArrayValue {
                values: vec![AnyValue::Str("1".into()), AnyValue::Str(big.to_string())]
            })
        );
    }

    /// The encoding's value shapes.
    #[test]
    fn values_encode_as_otlp_json() {
        let json = |kv: KeyValue| serde_json::to_string(&kv).unwrap();
        assert_eq!(
            json(KeyValue::string("a", "b")),
            r#"{"key":"a","value":{"stringValue":"b"}}"#
        );
        assert_eq!(
            json(KeyValue::int("a", 3)),
            r#"{"key":"a","value":{"intValue":"3"}}"#
        );
        assert_eq!(
            json(KeyValue::bool("a", true)),
            r#"{"key":"a","value":{"boolValue":true}}"#
        );
        assert_eq!(
            json(KeyValue::ints("a", &[1, 2])),
            r#"{"key":"a","value":{"arrayValue":{"values":[{"intValue":"1"},{"intValue":"2"}]}}}"#
        );
    }

    /// An id that is zero, or taken, gives way to the hash's next 8 bytes.
    #[test]
    fn ids_are_distinct_and_never_zero() {
        let draft = |from: &[u8], seq| SpanDraft {
            open_seq: seq,
            id_from: from.to_vec(),
            parent: None,
            name: String::new(),
            kind: KIND_INTERNAL,
            start: 0,
            end: 0,
            attributes: Vec::new(),
            events: Vec::new(),
            status: None,
        };
        let ids = assign_ids(&[draft(b"x", 1), draft(b"x", 2), draft(b"y", 3)]);
        let first = blake3::hash(b"x");
        assert_eq!(ids[0], first.as_bytes()[..8]);
        assert_eq!(ids[1], first.as_bytes()[8..16]);
        assert_ne!(ids[2], ids[0]);
        assert!(ids.iter().all(|id| *id != [0; 8]));
    }
}
