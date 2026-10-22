// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Exporting a log: the fixture session `fixtures/export/session.jsonl`,
//! built here from fixed inputs with `Chainer`, and its blessed exports
//! `session.otlp.json` and `session.ocsf.jsonl`, which must match byte for
//! byte. The fixture holds the cases the span model gets wrong: a WebSocket
//! stream with two calls, a response with no request, a request with no
//! response, a repeated close, a close the reconciler rejected, a
//! `tool_use_id` used again after eviction, a finding naming a span the log
//! does not hold, records after `vmm.stop`, a count above `i64::MAX`, a
//! kind no version knows, and secret-looking values in an argv, a model
//! name and a tool name.
//!
//! `BOXCAR_BLESS=1 cargo test -p boxcar-audit --test export` rewrites the
//! three files after a deliberate change.

use std::collections::BTreeSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use boxcar_audit::export::{ocsf, otlp, Log};
use boxcar_audit::{Chainer, PartialRecord};
use boxcar_proto::{
    ArtifactRef, Attrib, Checkpoint, Evidence, Finding, FindingCategory, FsClose, FsCreate, FsIo,
    FsLink, FsMount, Hardening, Hash, HashStatus, HttpRequest, HttpResponse, ImageRef,
    LandlockStatus, LlmRequest, LlmResponse, NetClose, NetConnect, NetDns, NetUdp, OpResult,
    Payload, PolicyLoaded, ProcExec, ProcExit, Record, Ring, SeccompMode, SessionId, Source,
    SpanEffects, SpanRef, Subject, ToolClose, ToolOpen, Verdict, VmmStart, VmmStop,
};
use serde_json::{json, Value};

const SESSION: &str = "019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b";
/// The first record's time; each record is a millisecond after the last.
const T0: u64 = 1_792_000_000_000_000_000;

/// Raw text the fixture holds that an OTLP export must not.
const RAW: [&str; 7] = [
    "raw-path-marker",
    "raw-dns-marker",
    "raw-url-marker",
    "raw-args-marker",
    "raw-args-summary-marker",
    "raw-result-summary-marker",
    "raw-cmdline-marker",
];
/// Secret-looking values the exports must scrub.
const SECRETS: [&str; 3] = [
    "sk-ant-api03-leakedinmodel",
    "ghp_0123456789toolname",
    "raw-bearer-marker",
];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/export")
}

/// Writes `path` whole or not at all, so that tests blessing it at once
/// never read it half written.
fn write_atomically(path: &Path, bytes: &[u8]) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}-{n}.tmp", std::process::id()));
    fs::write(&tmp, bytes).unwrap();
    fs::rename(&tmp, path).unwrap();
}

fn b3(bytes: &[u8]) -> Hash {
    Hash::from_blake3(blake3::hash(bytes))
}

fn ok() -> OpResult {
    OpResult {
        ok: true,
        errno: None,
        err: None,
    }
}

fn addr(ip: [u8; 4], port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(ip), port)
}

/// Builds a chained log from payloads, as the writer would.
struct Builder {
    session: SessionId,
    chain: Chainer,
    records: Vec<Record>,
    /// The raw hashes since the last checkpoint.
    window: Vec<Hash>,
}

impl Builder {
    fn new() -> Builder {
        let session: SessionId = SESSION.parse().unwrap();
        Builder {
            chain: Chainer::genesis(&session),
            session,
            records: Vec::new(),
            window: Vec::new(),
        }
    }

    fn seq(&self) -> u64 {
        self.records.len() as u64 + 1
    }

    fn raw(
        &mut self,
        src: Source,
        kind: &str,
        data: Value,
        subject: Option<Subject>,
        span: Option<&str>,
    ) -> u64 {
        let seq = self.seq();
        let record = self.chain.next(PartialRecord {
            session_id: self.session.clone(),
            ring: Ring::Host,
            src,
            kind: kind.to_owned(),
            ts_host_ns: T0 + seq * 1_000_000,
            ts_mono_ns: 1_000_000_000 + seq * 1_000_000,
            ts_guest_ns: None,
            subject,
            data,
            span: span.map(|id| SpanRef {
                trace_id: SESSION.into(),
                span_id: id.into(),
            }),
        });
        if kind == "checkpoint" {
            self.window.clear();
        } else {
            self.window.push(record.hash);
        }
        self.records.push(record);
        seq
    }

    fn push(&mut self, payload: Payload) -> u64 {
        self.with(payload, None, None)
    }

    fn with(&mut self, payload: Payload, subject: Option<Subject>, span: Option<&str>) -> u64 {
        let (kind, data) = payload.into_parts();
        self.raw(payload.source(), &kind, data, subject, span)
    }

    fn checkpoint(&mut self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        for hash in &self.window {
            hasher.update(&hash.0);
        }
        let payload = Payload::Checkpoint(Checkpoint {
            records_since: self.window.len() as u64,
            dropped: 0,
            root_hash: Hash::from_blake3(hasher.finalize()),
        });
        self.push(payload)
    }

    fn text(&self) -> String {
        self.records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect()
    }
}

fn subject(pid: u32) -> Option<Subject> {
    Some(Subject {
        pid,
        uid: 1000,
        gid: 1000,
    })
}

fn request(flow: u64, stream: u32, method: &str, path: &str) -> Payload {
    Payload::HttpRequest(HttpRequest {
        flow,
        stream,
        version: "HTTP/2".into(),
        method: method.into(),
        authority: Some("api.anthropic.com".into()),
        path: Some(path.into()),
        content_type: Some("application/json".into()),
        content_encoding: None,
        content_length: Some(10),
        user_agent: Some("agent/1".into()),
        body_bytes: 10,
        body_b3: None,
        body_truncated: false,
        degraded: None,
    })
}

fn llm_request(flow: u64, stream: u32, provider: &str, model: &str) -> Payload {
    Payload::LlmRequest(LlmRequest {
        flow,
        stream,
        provider: provider.into(),
        model: Some(model.into()),
        streaming: true,
        messages: 2,
        system_b3: None,
        tools: vec!["bash".into()],
        max_tokens: Some(1024),
        body_bytes: 10,
        body_b3: None,
        degraded: None,
    })
}

fn llm_response(
    flow: u64,
    stream: u32,
    provider: &str,
    model: &str,
    tokens: (u64, u64),
) -> Payload {
    Payload::LlmResponse(LlmResponse {
        flow,
        stream,
        provider: provider.into(),
        model: Some(model.into()),
        stop_reason: Some("end_turn".into()),
        input_tokens: Some(tokens.0),
        output_tokens: Some(tokens.1),
        cache_read_tokens: None,
        text_bytes: 5,
        text_b3: None,
        tool_uses: 0,
        dur_ms: 40,
        degraded: None,
    })
}

fn tool_open(flow: u64, stream: u32, id: &str, name: &str) -> Payload {
    Payload::ToolOpen(ToolOpen {
        flow,
        stream,
        tool_use_id: id.into(),
        tool_name: name.into(),
        args_b3: Some(b3(b"args").to_string()),
        args_summary: "raw-args-summary-marker".into(),
        args: Some(json!({"command": "raw-args-marker"})),
    })
}

fn tool_close(flow: u64, stream: u32, id: &str, status: &str) -> Payload {
    Payload::ToolClose(ToolClose {
        flow,
        stream,
        tool_use_id: id.into(),
        status: status.into(),
        result_bytes: 3,
        result_b3: None,
        result_summary: "raw-result-summary-marker".into(),
    })
}

fn effects(id: &str, opened: u64, closed: Option<u64>, procs: Vec<u32>, fx: Vec<u64>) -> Payload {
    Payload::SpanEffects(SpanEffects {
        span_id: id.into(),
        tool_name: "bash".into(),
        opened_seq: opened,
        closed_seq: closed,
        executor_tgid: Some(100),
        procs,
        effects: fx,
        truncated: false,
    })
}

fn finding(
    category: FindingCategory,
    score: u8,
    rule: &str,
    summary: &str,
    evidence: u64,
    span: Option<&str>,
) -> Payload {
    Payload::Finding(Finding {
        category,
        score,
        rule: rule.into(),
        summary: summary.into(),
        evidence: vec![Evidence {
            seq: evidence,
            ring: Ring::Guest,
        }],
        span_id: span.map(str::to_owned),
        low_confidence: false,
    })
}

fn fs_io(path: &str) -> FsIo {
    FsIo {
        mount: "workspace".into(),
        path: path.into(),
        path_b64: None,
        fh: 7,
        offset: 0,
        len: 1,
        result: ok(),
        attrib: Attrib::Caller,
    }
}

/// The fixture session.
fn fixture() -> Builder {
    let mut b = Builder::new();
    let a = "toolu_A";
    b.push(Payload::VmmStart(VmmStart {
        version: "0.5.0".into(),
        kernel: ArtifactRef {
            path: "/boot/vmlinux".into(),
            blake3: b3(b"kernel"),
        },
        initramfs: None,
        cmdline: "console=ttyS0 raw-cmdline-marker".into(),
        vcpus: 2,
        mem_mib: 512,
        shares: Vec::new(),
        inspect_ca_sha256: None,
        image: Some(ImageRef {
            reference: "registry.example/agent:1".into(),
            manifest_digest: format!("sha256:{}", "cd".repeat(32)),
            config_digest: format!("sha256:{}", "ef".repeat(32)),
        }),
        hardening: Some(Hardening {
            seccomp: SeccompMode::Enforce,
            landlock: LandlockStatus::Partial,
            seccomp_threads: false,
        }),
    }));
    b.push(Payload::PolicyLoaded(PolicyLoaded {
        source: "profile".into(),
        name: Some("agent-isolate".into()),
        sha256: Some("ab".repeat(32)),
        egress_rules: 3,
        fs_rules: 2,
        exec_rules: 0,
        exec_ring1: None,
    }));
    for (tag, dir) in [("root", "/"), ("workspace", "/workspace")] {
        b.push(Payload::FsMount(FsMount {
            mount: tag.into(),
            guest_path: dir.into(),
            host_root: format!("/host/{tag}"),
            cache_policy: "auto".into(),
        }));
    }
    b.push(Payload::NetConnect(NetConnect {
        flow: 1,
        proto: "tcp".into(),
        src: addr([10, 0, 2, 15], 40000),
        dst: addr([160, 79, 104, 10], 443),
        names: vec!["api.anthropic.com".into()],
        verdict: Verdict::Allow,
        rule: None,
    }));
    // Allowed, and answered SERVFAIL; then one the policy refused.
    let dns6 = b.push(Payload::NetDns(NetDns {
        txid: 1,
        qname: "raw-dns-marker.example".into(),
        qtype: 1,
        rcode: 2,
        answers: Vec::new(),
        verdict: Verdict::Allow,
        rule: None,
    }));
    b.push(Payload::NetDns(NetDns {
        txid: 2,
        qname: "blocked.example".into(),
        qtype: 28,
        rcode: 3,
        answers: Vec::new(),
        verdict: Verdict::Deny,
        rule: Some("default deny".into()),
    }));
    b.push(Payload::NetUdp(NetUdp {
        flow: 2,
        src: addr([10, 0, 2, 15], 5353),
        dst: addr([10, 0, 2, 2], 53),
        names: Vec::new(),
        verdict: Verdict::Allow,
        rule: None,
    }));
    // The first model call, which asks for a tool.
    b.push(request(1, 1, "POST", "/raw-url-marker"));
    b.push(llm_request(1, 1, "anthropic", "claude-test"));
    let open_a = b.with(tool_open(1, 1, a, "bash"), None, Some(a));
    b.push(Payload::HttpResponse(HttpResponse {
        flow: 1,
        stream: 1,
        status: 200,
        content_type: Some("text/event-stream".into()),
        content_encoding: None,
        body_bytes: 100,
        body_b3: None,
        body_truncated: false,
        sse_events: 9,
        ws_messages: 0,
        dur_ms: 40,
        degraded: None,
    }));
    b.push(Payload::LlmResponse(LlmResponse {
        stop_reason: Some("tool_use".into()),
        cache_read_tokens: Some(25),
        tool_uses: 1,
        ..match llm_response(1, 1, "anthropic", "claude-test", (100, 50)) {
            Payload::LlmResponse(r) => r,
            _ => unreachable!(),
        }
    }));
    // The tool's work.
    let exec = b.with(
        Payload::ProcExec(ProcExec {
            tid: 100,
            tgid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            filename: "/usr/bin/curl".into(),
            argv: vec![
                "curl".into(),
                "-H".into(),
                "Authorization: Bearer raw-bearer-marker".into(),
                "https://example.com/".into(),
            ],
            argv_truncated: false,
            start_ns: 5,
            cgroup_id: 9,
        }),
        subject(100),
        None,
    );
    let create = b.with(
        Payload::FsCreate(FsCreate {
            mount: "workspace".into(),
            path: "/raw-path-marker.txt".into(),
            path_b64: None,
            fh: 7,
            mode: 0o644,
            flags: 0o101,
            result: ok(),
        }),
        subject(100),
        None,
    );
    let write = b.with(
        Payload::FsWrite(fs_io("/raw-path-marker.txt")),
        subject(100),
        None,
    );
    let link = b.with(
        Payload::FsLink(FsLink {
            mount: "workspace".into(),
            path: "/link.txt".into(),
            path_b64: None,
            target_path: "/raw-path-marker.txt".into(),
            result: ok(),
        }),
        subject(100),
        None,
    );
    let close = b.with(
        Payload::FsClose(FsClose {
            mount: "workspace".into(),
            path: "/raw-path-marker.txt".into(),
            path_b64: None,
            path_at_open: "/raw-path-marker.txt".into(),
            fh: 7,
            bytes_read: 0,
            bytes_written: 1,
            size: Some(1),
            blake3: Some(b3(b"x")),
            hash_status: HashStatus::Ok,
            open_seq: Some(create),
            attrib: Attrib::Caller,
            ts_release_ns: T0,
        }),
        subject(100),
        None,
    );
    b.with(
        Payload::ProcExit(ProcExit {
            tid: 101,
            tgid: 100,
            exit_code: 0,
            group_dead: false,
            start_ns: 6,
        }),
        subject(101),
        None,
    );
    b.with(
        Payload::ProcExit(ProcExit {
            tid: 100,
            tgid: 100,
            exit_code: 0,
            group_dead: true,
            start_ns: 5,
        }),
        subject(100),
        None,
    );
    // The second model call carries the tool's result.
    b.push(request(1, 3, "POST", "/v1/messages"));
    b.push(llm_request(1, 3, "anthropic", "claude-test"));
    let close_a = b.with(tool_close(1, 3, a, "ok"), None, Some(a));
    b.with(
        effects(
            a,
            open_a,
            Some(close_a),
            vec![100],
            vec![create, write, link, close],
        ),
        None,
        Some(a),
    );
    b.with(
        finding(
            FindingCategory::IntentEffectMismatch,
            75,
            "argv",
            "finding-summary-marker",
            exec,
            Some(a),
        ),
        None,
        Some(a),
    );
    b.push(finding(
        FindingCategory::NetworkAnomaly,
        30,
        "dns",
        "a lookup failed",
        dns6,
        None,
    ));
    b.push(finding(
        FindingCategory::OrphanedWork,
        50,
        "orphaned_work",
        "work after an absent span",
        exec,
        Some("toolu_ABSENT"),
    ));
    b.push(llm_response(1, 3, "anthropic", "claude-test", (200, 20)));
    // OpenAI Responses' repeated close: it ends nothing.
    b.with(tool_close(1, 5, a, "ok"), None, Some(a));
    // A response with no request, and a request with no response.
    b.push(llm_response(9, 1, "openai_chat", "gpt-test", (1, 1)));
    b.push(llm_request(1, 7, "anthropic", "claude-test"));
    // Two calls on one WebSocket stream: each response answers the latest.
    b.push(Payload::NetConnect(NetConnect {
        flow: 3,
        proto: "tcp".into(),
        src: addr([10, 0, 2, 15], 40001),
        dst: addr([162, 159, 140, 245], 443),
        names: vec!["chatgpt.com".into()],
        verdict: Verdict::Allow,
        rule: None,
    }));
    b.push(llm_request(
        3,
        1,
        "openai_responses",
        "sk-ant-api03-leakedinmodel",
    ));
    b.push(llm_request(3, 1, "openai_responses", "gpt-test"));
    b.push(llm_response(3, 1, "openai_responses", "gpt-test", (7, 5)));
    b.push(llm_response(
        3,
        1,
        "openai_responses",
        "sk-ant-api03-leakedinmodel",
        (9, 6),
    ));
    // A tool call the reconciler kept open: its close came from another
    // executor.
    let b_id = "toolu_B";
    b.push(llm_request(1, 9, "anthropic", "claude-test"));
    let open_b = b.with(
        tool_open(1, 9, b_id, "ghp_0123456789toolname"),
        None,
        Some(b_id),
    );
    b.push(llm_response(1, 9, "anthropic", "claude-test", (3, 3)));
    b.with(tool_close(1, 11, b_id, "error"), None, Some(b_id));
    b.with(
        effects(b_id, open_b, None, Vec::new(), Vec::new()),
        None,
        Some(b_id),
    );
    // `toolu_A` again, after the reconciler evicted it.
    b.push(llm_request(1, 13, "anthropic", "claude-test"));
    let open_a2 = b.with(tool_open(1, 13, a, "bash"), None, Some(a));
    b.push(llm_response(1, 13, "anthropic", "claude-test", (4, 4)));
    let close_a2 = b.with(tool_close(1, 15, a, "ok"), None, Some(a));
    b.with(
        effects(a, open_a2, Some(close_a2), Vec::new(), Vec::new()),
        None,
        Some(a),
    );
    // A count no signed 64-bit integer holds.
    b.push(llm_request(1, 17, "anthropic", "claude-test"));
    b.push(llm_response(
        1,
        17,
        "anthropic",
        "claude-test",
        (1, u64::MAX),
    ));
    b.push(Payload::NetClose(NetClose {
        flow: 1,
        tx: 1000,
        rx: 2000,
        dur_ms: 500,
        reason: "fin".into(),
    }));
    b.checkpoint();
    b.push(Payload::VmmStop(VmmStop {
        reason: "guest_reset".into(),
        exit_code: Some(0),
        console_dropped_bytes: 0,
        stdin_dropped_bytes: 0,
    }));
    // The reconciler's late finding, on the latest `toolu_A`.
    b.with(
        finding(
            FindingCategory::UnattributedEffect,
            90,
            "phantom_write",
            "a late write",
            close,
            Some(a),
        ),
        None,
        Some(a),
    );
    b.raw(
        Source::Vmm,
        "x.future",
        json!({"what": "a later kind"}),
        None,
        None,
    );
    b
}

/// The fixture as a file, written and checked against the committed one.
fn fixture_file() -> PathBuf {
    let path = fixtures().join("session.jsonl");
    let text = fixture().text();
    if std::env::var_os("BOXCAR_BLESS").is_some() {
        fs::create_dir_all(fixtures()).unwrap();
        write_atomically(&path, text.as_bytes());
    }
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        text,
        "fixtures/export/session.jsonl is not what fixture() builds; after a deliberate change \
         rerun with BOXCAR_BLESS=1"
    );
    path
}

/// `actual` is the blessed file `name`, or becomes it under `BOXCAR_BLESS`.
fn check_blessed(name: &str, actual: &[u8]) {
    let path = fixtures().join(name);
    if std::env::var_os("BOXCAR_BLESS").is_some() {
        write_atomically(&path, actual);
    }
    let expected = fs::read(&path).unwrap_or_default();
    assert!(
        expected == actual,
        "{name} is not what the export gives; after a deliberate change rerun with \
         BOXCAR_BLESS=1\n--- export\n{}",
        String::from_utf8_lossy(actual)
    );
}

fn otlp_of(path: &Path) -> (Value, otlp::Summary) {
    let (bytes, summary) = otlp::export(&Log::read(path).unwrap());
    (serde_json::from_slice(&bytes).unwrap(), summary)
}

fn spans(trace: &Value) -> &Vec<Value> {
    trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .unwrap()
}

fn attr<'a>(item: &'a Value, key: &str) -> Option<&'a Value> {
    item["attributes"]
        .as_array()?
        .iter()
        .find(|kv| kv["key"] == key)
        .map(|kv| &kv["value"])
}

fn span_by_seq(trace: &Value, seq: u64) -> &Value {
    spans(trace)
        .iter()
        .find(|s| attr(s, "boxcar.record.seq") == Some(&json!({"intValue": seq.to_string()})))
        .unwrap_or_else(|| panic!("no span opened at seq {seq}"))
}

#[test]
fn the_fixture_verifies() {
    let log = Log::read(&fixture_file()).unwrap();
    assert_eq!(log.report.incomplete, None);
    assert_eq!(log.entries.len(), fixture().records.len());
}

#[test]
fn the_exports_are_the_blessed_ones() {
    let log = Log::read(&fixture_file()).unwrap();
    check_blessed("session.otlp.json", &otlp::export(&log).0);
    check_blessed("session.ocsf.jsonl", &ocsf::export(&log).0);
}

/// Review focus 8: the same log, read twice, exports to the same bytes.
#[test]
fn an_export_is_deterministic() {
    let path = fixture_file();
    let (one, two) = (Log::read(&path).unwrap(), Log::read(&path).unwrap());
    assert_eq!(otlp::export(&one).0, otlp::export(&two).0);
    assert_eq!(ocsf::export(&one).0, ocsf::export(&two).0);
}

#[test]
fn the_trace_holds_the_session_its_calls_and_its_tools() {
    let (trace, summary) = otlp_of(&fixture_file());
    let all = spans(&trace);
    let trace_id = SESSION.replace('-', "");
    let ids: BTreeSet<&str> = all.iter().map(|s| s["spanId"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), all.len(), "span ids are distinct");
    for span in all {
        assert_eq!(span["traceId"], trace_id.as_str());
        assert_ne!(span["spanId"], "0000000000000000");
        if let Some(parent) = span["parentSpanId"].as_str() {
            assert!(ids.contains(parent), "{span}");
        }
    }
    assert_eq!(summary.unpaired, 1, "the response with no request");

    let session = span_by_seq(&trace, 1);
    assert_eq!(session["name"], "boxcar.session");
    assert!(session.get("parentSpanId").is_none());
    let first_call = span_by_seq(&trace, 10);
    assert_eq!(first_call["name"], "chat claude-test");
    assert_eq!(first_call["kind"], 3);
    // Anthropic's input tokens and its cached ones.
    assert_eq!(
        attr(first_call, "gen_ai.usage.input_tokens"),
        Some(&json!({"intValue": "125"}))
    );
    assert_eq!(
        attr(first_call, "gen_ai.provider.name"),
        Some(&json!({"stringValue": "anthropic"}))
    );

    // The tool span: the first call's child, its id BLAKE3 of the id, ended
    // by the close span.effects names (seq 23), not the repeat (seq 29).
    let tool = span_by_seq(&trace, 11);
    assert_eq!(tool["parentSpanId"], first_call["spanId"]);
    let id = blake3::hash(b"toolu_A");
    let hex: String = id.as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(tool["spanId"], hex.as_str());
    assert_eq!(tool["endTimeUnixNano"], (T0 + 23 * 1_000_000).to_string());
    assert_eq!(tool["status"]["code"], 1);
    assert_eq!(
        tool["events"].as_array().unwrap().len(),
        1,
        "the argv finding"
    );

    // The repeated id's second occurrence is a span of its own.
    let again = span_by_seq(&trace, 43);
    assert_ne!(again["spanId"], tool["spanId"]);
    assert_eq!(
        again["events"].as_array().map_or(0, Vec::len),
        1,
        "the late finding"
    );

    // The span the reconciler kept open stays open, whatever the other
    // executor's close said.
    let kept_open = span_by_seq(&trace, 38);
    assert_eq!(
        attr(kept_open, "boxcar.span.open"),
        Some(&json!({"boolValue": true}))
    );
    assert!(kept_open.get("status").is_none());

    // The finding naming an absent span is the session's, its name kept.
    let names: Vec<&Value> = session["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| attr(e, "boxcar.finding.span_id"))
        .collect();
    assert_eq!(names, [&json!({"stringValue": "toolu_ABSENT"})]);

    // The request with no response ends at its own time, and says so;
    // an answered one does not.
    let unanswered = span_by_seq(&trace, 31);
    assert_eq!(
        unanswered["startTimeUnixNano"],
        unanswered["endTimeUnixNano"]
    );
    assert_eq!(
        attr(unanswered, "boxcar.llm.unanswered"),
        Some(&json!({"boolValue": true}))
    );
    assert_eq!(attr(span_by_seq(&trace, 10), "boxcar.llm.unanswered"), None);

    // Each WebSocket response answers the latest request on its stream.
    let ws_first = span_by_seq(&trace, 33);
    let ws_second = span_by_seq(&trace, 34);
    assert_eq!(
        ws_second["endTimeUnixNano"],
        (T0 + 35 * 1_000_000).to_string()
    );
    assert_eq!(
        ws_first["endTimeUnixNano"],
        (T0 + 36 * 1_000_000).to_string()
    );

    // A count past i64::MAX is a string.
    let big = span_by_seq(&trace, 47);
    assert_eq!(
        attr(big, "gen_ai.usage.output_tokens"),
        Some(&json!({"stringValue": u64::MAX.to_string()}))
    );
}

#[test]
fn an_otlp_export_holds_no_raw_text_and_no_secret() {
    let text = String::from_utf8(otlp::export(&Log::read(&fixture_file()).unwrap()).0).unwrap();
    for raw in RAW.iter().chain(&SECRETS) {
        assert!(!text.contains(raw), "{raw} is in the OTLP export");
    }
    assert!(
        text.contains("finding-summary-marker"),
        "the findings' summaries stay"
    );
}

/// The attributes OCSF 1.9.0 requires of each class and object used, with
/// no profile, and their "at least one of" constraints.
fn check_ocsf(event: &Value) {
    let has = |v: &Value, k: &str| v.get(k).is_some_and(|x| !x.is_null());
    let any = |v: &Value, keys: &[&str]| keys.iter().any(|k| has(v, k));
    let class = event["class_uid"].as_u64().unwrap();
    let activity = event["activity_id"].as_u64().unwrap();
    assert_eq!(
        event["type_uid"].as_u64().unwrap(),
        class * 100 + activity,
        "{event}"
    );
    for key in [
        "activity_id",
        "category_uid",
        "class_uid",
        "metadata",
        "severity_id",
        "time",
        "type_uid",
    ] {
        assert!(has(event, key), "{key}: {event}");
    }
    let metadata = &event["metadata"];
    assert!(
        has(metadata, "version") && any(&metadata["product"], &["name", "uid"]),
        "{event}"
    );
    let endpoint = |v: &Value| any(v, &["ip", "uid", "name", "hostname", "svc_name", "domain"]);
    let actor = |v: &Value| any(v, &["process", "user", "application", "session"]);
    let file = |v: &Value| has(v, "name") && has(v, "type_id");
    match class {
        1001 => {
            assert!(actor(&event["actor"]) && file(&event["file"]), "{event}");
            assert!(has(&event["device"], "type_id") && any(&event["device"], &["uid", "name"]));
            if let Some(result) = event.get("file_result") {
                assert!(file(result), "{event}");
            }
            if let Some(hashes) = event["file"].get("hashes") {
                for h in hashes.as_array().unwrap() {
                    assert!(has(h, "value") && has(h, "algorithm_id"), "{event}");
                }
            }
        }
        1007 => {
            assert!(actor(&event["actor"]), "{event}");
            assert!(any(&event["process"], &["pid", "uid", "cpid"]), "{event}");
            assert!(has(&event["device"], "type_id"), "{event}");
            if let Some(f) = event["process"].get("file") {
                assert!(file(f), "{event}");
            }
        }
        4001 | 4003 => {
            assert!(
                endpoint(&event["src_endpoint"]) || endpoint(&event["dst_endpoint"]),
                "{event}"
            );
            if let Some(info) = event.get("connection_info") {
                assert!(has(info, "direction_id"), "{event}");
            }
            if class == 4003 {
                assert!(has(&event["query"], "hostname"), "{event}");
            }
        }
        4002 => {
            assert!(any(event, &["http_request", "http_response"]), "{event}");
            if let Some(response) = event.get("http_response") {
                assert!(has(response, "code"), "{event}");
            }
        }
        2004 => {
            assert!(has(&event["finding_info"], "uid"), "{event}");
            let analytic = &event["finding_info"]["analytic"];
            assert!(
                has(analytic, "type_id") && any(analytic, &["name", "uid"]),
                "{event}"
            );
        }
        6003 => {
            assert!(
                actor(&event["actor"]) && has(&event["api"], "operation"),
                "{event}"
            );
            assert!(endpoint(&event["src_endpoint"]), "{event}");
        }
        other => panic!("class {other} is not one the export maps"),
    }
    if activity == 99 {
        assert!(has(event, "activity_name"), "{event}");
    }
    if has(event, "action_id") {
        assert_eq!(metadata["profiles"], json!(["security_control"]), "{event}");
    }
}

#[test]
fn every_ocsf_event_has_what_its_class_requires() {
    let (bytes, summary) = ocsf::export(&Log::read(&fixture_file()).unwrap());
    let text = String::from_utf8(bytes).unwrap();
    let events: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.len(), summary.events);
    for event in &events {
        check_ocsf(event);
    }
    let by_seq = |seq: u64| {
        events
            .iter()
            .find(|e| e["metadata"]["sequence"] == seq)
            .unwrap_or_else(|| panic!("no event for seq {seq}"))
    };
    // The argv's bearer token is scrubbed; the link points the right way.
    let exec = by_seq(14);
    let cmd_line = exec["process"]["cmd_line"].as_str().unwrap();
    assert!(!cmd_line.contains("raw-bearer-marker"), "{cmd_line}");
    let link = by_seq(17);
    assert_eq!(link["file"]["path"], "/workspace/raw-path-marker.txt");
    assert_eq!(link["file_result"]["path"], "/workspace/link.txt");
    // SERVFAIL on an allowed lookup: the outcome failed, the verdict allowed.
    let servfail = by_seq(6);
    assert_eq!(
        (
            servfail["status_id"].clone(),
            servfail["disposition_id"].clone()
        ),
        (json!(2), json!(1))
    );
    // Only the thread group's exit maps.
    assert!(events.iter().all(|e| e["metadata"]["sequence"] != 19));
    assert_eq!(by_seq(20)["activity_id"], 2);
    // What was skipped, by kind.
    for (kind, count) in [
        ("vmm.start", 1),
        ("vmm.stop", 1),
        ("policy.loaded", 1),
        ("checkpoint", 1),
        ("span.effects", 3),
        ("proc.exit (thread)", 1),
        ("x.future", 1),
    ] {
        assert_eq!(
            summary.skipped.0.get(kind).copied(),
            Some(count),
            "{kind}: {}",
            summary.skipped
        );
    }
    // No tool arguments or summaries, and the secrets scrubbed.
    for raw in [
        "raw-args-marker",
        "raw-args-summary-marker",
        "raw-result-summary-marker",
    ]
    .iter()
    .chain(&SECRETS)
    {
        assert!(!text.contains(raw), "{raw} is in the OCSF export");
    }
}

#[test]
fn a_broken_chain_exports_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.jsonl");
    let text = fixture().text().replacen("claude-test", "claude-tesT", 1);
    fs::write(&path, text).unwrap();
    assert!(Log::read(&path).is_err());
}

#[test]
fn an_incomplete_log_exports_what_verified() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cut.jsonl");
    let mut text = fixture().text();
    text.truncate(text.len() - 10);
    fs::write(&path, &text).unwrap();
    let log = Log::read(&path).unwrap();
    assert!(log.report.incomplete.is_some());
    let records = fixture().records.len();
    assert_eq!(log.entries.len(), records - 1);
    let (trace, _) = otlp_of(&path);
    assert_eq!(
        attr(span_by_seq(&trace, 1), "boxcar.log.incomplete"),
        Some(&json!({"stringValue": "partial_line"}))
    );
}

#[test]
fn a_known_kind_with_bad_data_stops_the_export() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.jsonl");
    let mut b = Builder::new();
    b.raw(Source::Vmm, "vmm.stop", json!({"reason": 7}), None, None);
    fs::write(&path, b.text()).unwrap();
    match Log::read(&path) {
        Err(boxcar_audit::export::ExportError::Payload { seq: 1, kind, .. }) => {
            assert_eq!(kind, "vmm.stop")
        }
        other => panic!("not a payload error: {:?}", other.err()),
    }
}

/// The export comes from what was verified: a file changed after the read
/// cannot change it.
#[test]
fn a_file_changed_after_the_read_changes_no_export() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    fs::write(&path, fixture().text()).unwrap();
    let log = Log::read(&path).unwrap();
    fs::write(
        &path,
        fixture().text().replace("claude-test", "claude-swap"),
    )
    .unwrap();
    let blessed = fs::read(fixtures().join("session.otlp.json")).unwrap();
    assert_eq!(otlp::export(&log).0, blessed);
}
