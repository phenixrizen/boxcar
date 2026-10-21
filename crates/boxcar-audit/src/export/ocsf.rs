// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A log as OCSF 1.9.0 events, one compact JSON object per line, in seq
//! order: `fs.*` as File System Activity (1001), `proc.exec` and a thread
//! group's `proc.exit` as Process Activity (1007), `net.connect`,
//! `net.udp` and `net.close` as Network Activity (4001), `net.dns` as DNS
//! Activity (4003), `http.*` as HTTP Activity (4002), `finding` as
//! Detection Finding (2004), and `llm.*` and `tool.*` as API Activity
//! (6003). Every other kind is skipped and counted.
//!
//! Each event carries its record's hash as `metadata.uid` and its seq as
//! `metadata.sequence`, the session as `metadata.correlation_uid`. Events
//! with a policy's verdict carry it as `action_id` and `disposition_id`,
//! under the `security_control` profile they list. Objects are JSON maps
//! with sorted keys, so an event's bytes depend on its record alone.
//! `proc.exec`'s argv is scrubbed as `--scrub-argv` scrubs it; tools'
//! arguments and summaries are never carried.

use std::collections::BTreeMap;

use boxcar_proto::redact::{scrub_argv, scrub_text};
use boxcar_proto::{OpResult, Payload, Record, Verdict};
use serde_json::{json, Map, Value};

use super::{file_name, Log, Mounts, Skipped};

/// The OCSF version the events follow.
pub const VERSION: &str = "1.9.0";

const FILE_ACTIVITY: u32 = 1001;
const PROCESS_ACTIVITY: u32 = 1007;
const NETWORK_ACTIVITY: u32 = 4001;
const HTTP_ACTIVITY: u32 = 4002;
const DNS_ACTIVITY: u32 = 4003;
const DETECTION_FINDING: u32 = 2004;
const API_ACTIVITY: u32 = 6003;

/// `file.type_id`.
const REGULAR_FILE: u8 = 1;
const FOLDER: u8 = 2;
const SYMBOLIC_LINK: u8 = 7;
const UNKNOWN_TYPE: u8 = 0;

/// What an export holds, for its summary line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub events: usize,
    pub records: usize,
    pub skipped: Skipped,
}

/// The log as OCSF JSON lines, and what they hold.
pub fn export(log: &Log) -> (Vec<u8>, Summary) {
    let mut out = Vec::new();
    let mut summary = Summary {
        records: log.entries.len(),
        ..Summary::default()
    };
    let mut cx = Context {
        session: log
            .session_id()
            .map(|id| id.as_str().to_owned())
            .unwrap_or_default(),
        version: log.version().unwrap_or("").to_owned(),
        mounts: Mounts::default(),
        flows: BTreeMap::new(),
        methods: BTreeMap::new(),
        tools: BTreeMap::new(),
    };
    for entry in &log.entries {
        let event = match &entry.payload {
            Some(payload) => {
                cx.learn(payload);
                cx.event(&entry.record, payload)
            }
            None => None,
        };
        match event {
            Some(event) => {
                if let Ok(line) = serde_json::to_vec(&Value::Object(event)) {
                    out.extend_from_slice(&line);
                    out.push(b'\n');
                    summary.events += 1;
                }
            }
            None => summary.skipped.add(&skip_name(entry)),
        }
    }
    (out, summary)
}

/// The kind a skipped record is counted under: a thread's exit apart from
/// a thread group's.
fn skip_name(entry: &super::Entry) -> String {
    match &entry.payload {
        Some(Payload::ProcExit(exit)) if !exit.group_dead => "proc.exit (thread)".into(),
        _ => entry.record.kind.clone(),
    }
}

/// A flow's ends and protocol, from its `net.connect` or `net.udp`.
struct Flow {
    proto: String,
    src: Value,
    dst: Value,
}

/// What earlier records tell later ones.
struct Context {
    session: String,
    version: String,
    mounts: Mounts,
    flows: BTreeMap<u64, Flow>,
    /// The latest request's method on each `(flow, stream)`.
    methods: BTreeMap<(u64, u32), String>,
    /// Each tool call's tool, by its `tool_use_id`, scrubbed.
    tools: BTreeMap<String, String>,
}

impl Context {
    fn learn(&mut self, payload: &Payload) {
        self.mounts.learn(payload);
        match payload {
            Payload::NetConnect(c) => {
                self.flows.insert(
                    c.flow,
                    Flow {
                        proto: c.proto.clone(),
                        src: endpoint(&c.src.ip().to_string(), c.src.port(), &[]),
                        dst: endpoint(&c.dst.ip().to_string(), c.dst.port(), &c.names),
                    },
                );
            }
            Payload::NetUdp(u) => {
                self.flows.insert(
                    u.flow,
                    Flow {
                        proto: "udp".into(),
                        src: endpoint(&u.src.ip().to_string(), u.src.port(), &[]),
                        dst: endpoint(&u.dst.ip().to_string(), u.dst.port(), &u.names),
                    },
                );
            }
            Payload::HttpRequest(r) => {
                self.methods.insert((r.flow, r.stream), r.method.clone());
            }
            Payload::ToolOpen(t) => {
                self.tools
                    .insert(t.tool_use_id.clone(), scrub_text(&t.tool_name));
            }
            _ => {}
        }
    }

    /// The event for `record`, or `None` for a kind that maps to none.
    fn event(&self, record: &Record, payload: &Payload) -> Option<Map<String, Value>> {
        use Payload as P;
        let fs = |activity, name: Option<&str>, path: (&str, &str), type_id, result| {
            let mut e = self.base(record, FILE_ACTIVITY, 1, activity, name);
            self.host(record, &mut e);
            e.insert("file".into(), self.file(path.0, path.1, type_id));
            status(&mut e, result);
            e
        };
        Some(match payload {
            P::FsCreate(c) => fs(1, None, (&c.mount, &c.path), REGULAR_FILE, Some(&c.result)),
            P::FsMkdir(c) => fs(1, None, (&c.mount, &c.path), FOLDER, Some(&c.result)),
            P::FsMknod(c) => fs(
                1,
                None,
                (&c.mount, &c.path),
                node_type(c.mode),
                Some(&c.result),
            ),
            P::FsSymlink(c) => fs(1, None, (&c.mount, &c.path), SYMBOLIC_LINK, Some(&c.result)),
            P::FsLink(l) => {
                // The existing file, and the new name the link gave it.
                let mut e = fs(
                    1,
                    None,
                    (&l.mount, &l.target_path),
                    REGULAR_FILE,
                    Some(&l.result),
                );
                e.insert(
                    "file_result".into(),
                    self.file(&l.mount, &l.path, REGULAR_FILE),
                );
                e
            }
            P::FsOpen(o) => {
                let mut e = fs(14, None, (&o.mount, &o.path), REGULAR_FILE, Some(&o.result));
                unmapped(&mut e, json!({"exec": o.exec, "flags": o.flags_decoded}));
                e
            }
            P::FsRead(io) => fs(
                2,
                None,
                (&io.mount, &io.path),
                REGULAR_FILE,
                Some(&io.result),
            ),
            P::FsReaddir(op) => fs(2, None, (&op.mount, &op.path), FOLDER, Some(&op.result)),
            P::FsWrite(io) => fs(
                3,
                None,
                (&io.mount, &io.path),
                REGULAR_FILE,
                Some(&io.result),
            ),
            P::FsFallocate(f) => fs(3, None, (&f.mount, &f.path), REGULAR_FILE, Some(&f.result)),
            P::FsClose(c) => {
                let mut e = fs(99, Some("Close"), (&c.mount, &c.path), REGULAR_FILE, None);
                if let Some(Value::Object(file)) = e.get_mut("file") {
                    if let Some(hash) = &c.blake3 {
                        let value = hash.to_string();
                        let value = value.strip_prefix("b3:").unwrap_or(&value).to_owned();
                        file.insert(
                            "hashes".into(),
                            json!([{"algorithm_id": 99, "algorithm": "BLAKE3", "value": value}]),
                        );
                    }
                    if let Some(size) = c.size {
                        file.insert("size".into(), json!(size));
                    }
                }
                unmapped(
                    &mut e,
                    json!({"bytes_read": c.bytes_read, "bytes_written": c.bytes_written}),
                );
                e
            }
            P::FsUnlink(op) => fs(
                4,
                None,
                (&op.mount, &op.path),
                UNKNOWN_TYPE,
                Some(&op.result),
            ),
            P::FsRmdir(op) => fs(4, None, (&op.mount, &op.path), FOLDER, Some(&op.result)),
            P::FsRename(r) => {
                let mut e = fs(5, None, (&r.mount, &r.from), UNKNOWN_TYPE, Some(&r.result));
                e.insert(
                    "file_result".into(),
                    self.file(&r.mount, &r.to, UNKNOWN_TYPE),
                );
                e
            }
            P::FsSetattr(s) => fs(6, None, (&s.mount, &s.path), UNKNOWN_TYPE, Some(&s.result)),
            P::FsXattr(x) => fs(6, None, (&x.mount, &x.path), UNKNOWN_TYPE, Some(&x.result)),
            P::FsMount(m) => {
                let mut e = self.base(record, FILE_ACTIVITY, 1, 12, None);
                self.host(record, &mut e);
                e.insert(
                    "file".into(),
                    json!({"name": file_name(&m.guest_path), "path": m.guest_path, "type_id": FOLDER}),
                );
                e
            }
            P::FsDenied(d) => {
                let (activity, name) = match d.op.as_str() {
                    "open" | "exec" => (14, None),
                    "create" | "mkdir" | "mknod" | "symlink" | "link" => (1, None),
                    "read" | "readdir" => (2, None),
                    "write" | "fallocate" => (3, None),
                    "unlink" | "rmdir" => (4, None),
                    "rename" => (5, None),
                    "setattr" | "setxattr" | "removexattr" => (6, None),
                    "lookup" | "getattr" | "access" | "getxattr" | "listxattr" => (8, None),
                    _ => (99, Some("Denied")),
                };
                let mut e = fs(activity, name, (&d.mount, &d.path), UNKNOWN_TYPE, None);
                e.insert("status_id".into(), json!(2));
                let mut detail = format!("{} refused: errno {}", d.op, d.errno);
                if let Some(reason) = &d.reason {
                    detail.push_str(&format!(", {reason}"));
                }
                if let Some(rule) = &d.rule {
                    detail.push_str(&format!(" ({rule})"));
                }
                e.insert("status_detail".into(), json!(detail));
                if d.reason.as_deref() == Some("policy") {
                    verdict(&mut e, false);
                }
                e
            }
            P::ProcExec(x) => {
                let mut e = self.base(record, PROCESS_ACTIVITY, 1, 1, None);
                self.host(record, &mut e);
                e.insert(
                    "process".into(),
                    json!({
                        "pid": x.tgid,
                        "ptid": x.tid,
                        "file": {"name": file_name(&x.filename), "path": x.filename, "type_id": REGULAR_FILE},
                        "cmd_line": scrub_argv(&x.argv).join(" "),
                        "user": {"uid": x.uid.to_string()},
                        "parent_process": {"pid": x.ppid},
                    }),
                );
                e
            }
            P::ProcExit(x) if x.group_dead => {
                let mut e = self.base(record, PROCESS_ACTIVITY, 1, 2, None);
                self.host(record, &mut e);
                e.insert("process".into(), json!({"pid": x.tgid}));
                // The wait status: an exit code, or the signal that ended it.
                let status = x.exit_code;
                if status & 0x7f == 0 {
                    e.insert("exit_code".into(), json!((status >> 8) & 0xff));
                } else {
                    e.insert(
                        "status_detail".into(),
                        json!(format!("killed by signal {}", status & 0x7f)),
                    );
                }
                e
            }
            P::NetConnect(c) => self.flow_open(record, c.flow, c.verdict),
            P::NetUdp(u) => self.flow_open(record, u.flow, u.verdict),
            P::NetClose(c) => {
                let mut e = self.base(record, NETWORK_ACTIVITY, 4, 2, None);
                self.endpoints(c.flow, &mut e);
                e.insert(
                    "traffic".into(),
                    json!({"bytes_out": c.tx, "bytes_in": c.rx}),
                );
                unmapped(&mut e, json!({"dur_ms": c.dur_ms, "reason": c.reason}));
                e
            }
            P::NetDns(d) => {
                let mut e = self.base(record, DNS_ACTIVITY, 4, 6, None);
                self.guest_endpoints(&mut e);
                e.insert(
                    "query".into(),
                    json!({"hostname": d.qname, "type": qtype(d.qtype)}),
                );
                let answers: Vec<Value> = d.answers.iter().map(|a| json!({"rdata": a})).collect();
                if !answers.is_empty() {
                    e.insert("answers".into(), Value::Array(answers));
                }
                e.insert("rcode_id".into(), json!(rcode_id(d.rcode)));
                e.insert("rcode".into(), json!(rcode_name(d.rcode)));
                e.insert("status_id".into(), json!(if d.rcode == 0 { 1 } else { 2 }));
                verdict(&mut e, d.verdict == Verdict::Allow);
                e
            }
            P::HttpRequest(r) => {
                let (activity, name) = http_activity(&r.method);
                let mut e = self.base(record, HTTP_ACTIVITY, 4, activity, name);
                self.endpoints(r.flow, &mut e);
                let mut url = Map::new();
                if let Some(host) = &r.authority {
                    url.insert("hostname".into(), json!(host));
                }
                let path = r.path.clone().unwrap_or_else(|| "/".into());
                url.insert("path".into(), json!(path));
                url.insert(
                    "url_string".into(),
                    json!(format!("{}{}", r.authority.as_deref().unwrap_or(""), path)),
                );
                let mut request = Map::new();
                request.insert("http_method".into(), json!(r.method));
                request.insert("url".into(), Value::Object(url));
                request.insert("version".into(), json!(r.version));
                if let Some(agent) = &r.user_agent {
                    request.insert("user_agent".into(), json!(agent));
                }
                e.insert("http_request".into(), Value::Object(request));
                e
            }
            P::HttpResponse(r) => {
                let method = self
                    .methods
                    .get(&(r.flow, r.stream))
                    .cloned()
                    .unwrap_or_default();
                let (activity, name) = http_activity(&method);
                let mut e = self.base(record, HTTP_ACTIVITY, 4, activity, name);
                self.endpoints(r.flow, &mut e);
                e.insert("http_response".into(), json!({"code": r.status}));
                if !method.is_empty() {
                    e.insert("http_request".into(), json!({"http_method": method}));
                }
                e.insert(
                    "status_id".into(),
                    json!(if r.status < 400 { 1 } else { 2 }),
                );
                e
            }
            P::Finding(f) => {
                let mut e = self.base(record, DETECTION_FINDING, 2, 1, None);
                let category = serde_json::to_value(f.category).unwrap_or(Value::Null);
                e.insert(
                    "finding_info".into(),
                    json!({
                        "uid": record.hash.to_string(),
                        "title": f.rule,
                        "desc": f.summary,
                        "types": [category],
                        "analytic": {"name": f.rule, "type_id": 1},
                    }),
                );
                e.insert("risk_score".into(), json!(f.score));
                e.insert("severity_id".into(), json!(severity(f.score)));
                let evidence: Vec<Value> = f
                    .evidence
                    .iter()
                    .map(|ev| json!({"seq": ev.seq, "ring": ev.ring}))
                    .collect();
                let mut extra = Map::new();
                extra.insert("evidence".into(), Value::Array(evidence));
                if let Some(span) = &f.span_id {
                    extra.insert("span_id".into(), json!(scrub_text(span)));
                }
                extra.insert("low_confidence".into(), json!(f.low_confidence));
                unmapped(&mut e, Value::Object(extra));
                e
            }
            P::LlmRequest(r) => {
                let mut e = self.api(record, r.flow, "Model Request", "chat", &r.provider);
                let mut extra = Map::new();
                if let Some(model) = &r.model {
                    extra.insert("model".into(), json!(scrub_text(model)));
                }
                extra.insert("streaming".into(), json!(r.streaming));
                unmapped(&mut e, Value::Object(extra));
                e
            }
            P::LlmResponse(r) => {
                let mut e = self.api(record, r.flow, "Model Response", "chat", &r.provider);
                let mut extra = Map::new();
                if let Some(model) = &r.model {
                    extra.insert("model".into(), json!(scrub_text(model)));
                }
                for (key, value) in [
                    ("input_tokens", r.input_tokens),
                    ("output_tokens", r.output_tokens),
                    ("cache_read_tokens", r.cache_read_tokens),
                ] {
                    if let Some(value) = value {
                        extra.insert(key.into(), json!(value));
                    }
                }
                if let Some(reason) = &r.stop_reason {
                    extra.insert("stop_reason".into(), json!(scrub_text(reason)));
                }
                unmapped(&mut e, Value::Object(extra));
                if r.degraded.is_some() {
                    e.insert("status_id".into(), json!(2));
                }
                e
            }
            P::ToolOpen(t) => {
                let name = scrub_text(&t.tool_name);
                let mut e = self.api(record, t.flow, "Tool Call", "execute_tool", &name);
                unmapped(&mut e, json!({"tool_use_id": scrub_text(&t.tool_use_id)}));
                e
            }
            P::ToolClose(t) => {
                let tool = self
                    .tools
                    .get(&t.tool_use_id)
                    .map_or("tool", String::as_str);
                let mut e = self.api(record, t.flow, "Tool Result", "execute_tool", tool);
                e.insert(
                    "status_id".into(),
                    json!(if t.status == "ok" { 1 } else { 2 }),
                );
                unmapped(&mut e, json!({"tool_use_id": scrub_text(&t.tool_use_id)}));
                e
            }
            _ => return None,
        })
    }

    /// The fields every event has.
    fn base(
        &self,
        record: &Record,
        class: u32,
        category: u32,
        activity: u32,
        name: Option<&str>,
    ) -> Map<String, Value> {
        let mut e = Map::new();
        e.insert("class_uid".into(), json!(class));
        e.insert("category_uid".into(), json!(category));
        e.insert("activity_id".into(), json!(activity));
        if let Some(name) = name {
            e.insert("activity_name".into(), json!(name));
        }
        e.insert(
            "type_uid".into(),
            json!(u64::from(class) * 100 + u64::from(activity)),
        );
        e.insert("time".into(), json!(record.ts_host_ns / 1_000_000));
        e.insert("severity_id".into(), json!(1));
        e.insert(
            "metadata".into(),
            json!({
                "version": VERSION,
                "product": {"name": "boxcar", "vendor_name": "boxcar", "version": self.version},
                "uid": record.hash.to_string(),
                "sequence": record.seq,
                "correlation_uid": self.session,
                "log_name": "boxcar",
            }),
        );
        e
    }

    /// The `device` and `actor` of a host class (1001, 1007).
    fn host(&self, record: &Record, e: &mut Map<String, Value>) {
        e.insert(
            "device".into(),
            json!({"type_id": 6, "type": "Virtual", "uid": self.session}),
        );
        e.insert("actor".into(), actor(record));
    }

    fn file(&self, mount: &str, path: &str, type_id: u8) -> Value {
        let path = self.mounts.guest_path(mount, path);
        json!({"name": file_name(&path), "path": path, "type_id": type_id})
    }

    /// A flow's ends, joined by its number, else the guest's and boxcar's.
    fn endpoints(&self, flow: u64, e: &mut Map<String, Value>) {
        match self.flows.get(&flow) {
            Some(f) => {
                e.insert("src_endpoint".into(), f.src.clone());
                e.insert("dst_endpoint".into(), f.dst.clone());
            }
            None => self.guest_endpoints(e),
        }
    }

    /// The guest and boxcar as ends, for a record that names no addresses.
    fn guest_endpoints(&self, e: &mut Map<String, Value>) {
        e.insert(
            "src_endpoint".into(),
            json!({"name": "guest", "uid": self.session}),
        );
        e.insert("dst_endpoint".into(), json!({"name": "boxcar"}));
    }

    fn flow_open(&self, record: &Record, flow: u64, allowed: Verdict) -> Map<String, Value> {
        let mut e = self.base(record, NETWORK_ACTIVITY, 4, 1, None);
        self.endpoints(flow, &mut e);
        let proto = self.flows.get(&flow).map_or("tcp", |f| f.proto.as_str());
        e.insert(
            "connection_info".into(),
            json!({"protocol_name": proto, "uid": flow.to_string(), "direction_id": 2}),
        );
        verdict(&mut e, allowed == Verdict::Allow);
        e
    }

    /// API Activity, as `99` with `name`, for `operation` of `service`.
    fn api(
        &self,
        record: &Record,
        flow: u64,
        name: &str,
        operation: &str,
        service: &str,
    ) -> Map<String, Value> {
        let mut e = self.base(record, API_ACTIVITY, 6, 99, Some(name));
        e.insert(
            "api".into(),
            json!({"operation": operation, "service": {"name": service}}),
        );
        e.insert("actor".into(), actor(record));
        let mut ends = Map::new();
        self.endpoints(flow, &mut ends);
        if let Some(src) = ends.remove("src_endpoint") {
            e.insert("src_endpoint".into(), src);
        }
        if let Some(dst) = ends.remove("dst_endpoint") {
            e.insert("dst_endpoint".into(), dst);
        }
        e
    }
}

fn endpoint(ip: &str, port: u16, names: &[String]) -> Value {
    let mut end = Map::new();
    end.insert("ip".into(), json!(ip));
    end.insert("port".into(), json!(port));
    if let Some(name) = names.first() {
        end.insert("hostname".into(), json!(name));
    }
    Value::Object(end)
}

/// The record's subject as an actor, else boxcar itself.
fn actor(record: &Record) -> Value {
    match &record.subject {
        Some(s) => json!({"process": {"pid": s.pid}, "user": {"uid": s.uid.to_string()}}),
        None => json!({"application": {"name": "boxcar"}}),
    }
}

/// `status_id` from an operation's result.
fn status(e: &mut Map<String, Value>, result: Option<&OpResult>) {
    if let Some(result) = result {
        e.insert("status_id".into(), json!(if result.ok { 1 } else { 2 }));
    }
}

/// A policy's verdict, under the `security_control` profile.
fn verdict(e: &mut Map<String, Value>, allowed: bool) {
    let id = if allowed { 1 } else { 2 };
    e.insert("action_id".into(), json!(id));
    e.insert("disposition_id".into(), json!(id));
    if let Some(Value::Object(metadata)) = e.get_mut("metadata") {
        metadata.insert("profiles".into(), json!(["security_control"]));
    }
}

/// What the log holds that OCSF has no attribute for.
fn unmapped(e: &mut Map<String, Value>, extra: Value) {
    e.insert("unmapped".into(), extra);
}

/// `file.type_id` from a node's mode.
fn node_type(mode: u32) -> u8 {
    match mode & libc::S_IFMT {
        libc::S_IFREG => REGULAR_FILE,
        libc::S_IFDIR => FOLDER,
        libc::S_IFCHR => 3,
        libc::S_IFBLK => 4,
        libc::S_IFSOCK => 5,
        libc::S_IFIFO => 6,
        libc::S_IFLNK => SYMBOLIC_LINK,
        _ => UNKNOWN_TYPE,
    }
}

/// HTTP Activity's activity for a method, and its name when it is 99.
fn http_activity(method: &str) -> (u32, Option<&str>) {
    match method {
        "CONNECT" => (1, None),
        "DELETE" => (2, None),
        "GET" => (3, None),
        "HEAD" => (4, None),
        "OPTIONS" => (5, None),
        "POST" => (6, None),
        "PUT" => (7, None),
        "TRACE" => (8, None),
        "PATCH" => (9, None),
        "" => (0, None),
        other => (99, Some(other)),
    }
}

/// `severity_id` from a finding's score.
fn severity(score: u8) -> u8 {
    match score {
        0..=39 => 2,
        40..=69 => 3,
        70..=89 => 4,
        _ => 5,
    }
}

/// `rcode_id`: DNS's own codes where OCSF lists them, else 99.
fn rcode_id(rcode: u16) -> u16 {
    match rcode {
        0..=11 | 16..=25 => rcode,
        _ => 99,
    }
}

/// `rcode`: the code's name as OCSF 1.9.0 captions it; for one it does
/// not list (`rcode_id` 99, Other, "defined by the event source"), the
/// code's number as text.
fn rcode_name(rcode: u16) -> String {
    let name = match rcode {
        0 => "NoError",
        1 => "FormError",
        2 => "ServError",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        6 => "YXDomain",
        7 => "YXRRSet",
        8 => "NXRRSet",
        9 => "NotAuth",
        10 => "NotZone",
        11 => "DSOTYPENI",
        16 => "BADVERS",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        24 => "Unassigned",
        25 => "Reserved",
        other => return other.to_string(),
    };
    name.to_owned()
}

/// A query type's name, such as `A`, else its number.
fn qtype(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_map_to_severities() {
        assert_eq!(
            [0, 39, 40, 69, 70, 89, 90, 100].map(severity),
            [2, 2, 3, 3, 4, 4, 5, 5]
        );
    }

    #[test]
    fn methods_map_to_activities() {
        assert_eq!(http_activity("GET"), (3, None));
        assert_eq!(http_activity("POST"), (6, None));
        assert_eq!(http_activity("PROPFIND"), (99, Some("PROPFIND")));
    }

    #[test]
    fn rcodes_outside_ocsfs_list_are_other() {
        assert_eq!(rcode_id(3), 3);
        assert_eq!(rcode_id(12), 99);
        assert_eq!(rcode_id(16), 16);
        assert_eq!(rcode_name(0), "NoError");
        assert_eq!(rcode_name(3), "NXDomain");
        assert_eq!(rcode_name(16), "BADVERS");
        assert_eq!(rcode_name(25), "Reserved");
        // Other: the source's to define, so the code itself.
        assert_eq!(rcode_name(12), "12");
    }

    #[test]
    fn modes_map_to_file_types() {
        assert_eq!(node_type(libc::S_IFIFO | 0o644), 6);
        assert_eq!(node_type(libc::S_IFLNK), SYMBOLIC_LINK);
        assert_eq!(node_type(0o644), UNKNOWN_TYPE);
    }
}
