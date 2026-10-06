// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask schema`: the JSON Schemas of the control protocol, the
//! audit records, the guest control channel and the sensor stream, and the
//! golden lines of the control protocol and the sensor stream.
//!
//! Written from the types in `boxcar-proto` (built with its `schema`
//! feature) to `proto/schema/{control-v1,audit-v1,guest-v1,sensor-v1}.json`,
//! draft 7, `proto/testdata/control-v1.jsonl`, one example of each control
//! message, and `proto/testdata/sensor-v1.jsonl`, one frame of each sensor
//! record type (as JSON lines; on the wire each is length-prefixed). The
//! output is deterministic (sorted keys, fixed examples), so CI runs this
//! and fails on a difference: a change to the types must come with its
//! schemas.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use boxcar_proto::audit::{Payload, Record};
use boxcar_proto::control::{
    self, to_line, AuditEvent, AuditLagged, AuditSubscribeParams, AuditSubscribed, ErrorBody,
    ErrorCode, Hello, NetPolicy, PolicyUpdateParams, PolicyUpdated, PolicyView, PtyAttachParams,
    PtyAttached, PtyDetached, PtyMode, PtyResizeParams, PtyWatchParams, Ready, Request, Response,
    SensorState, SensorStatus, StateEvent, Status, StopMode, StopParams, VmState, VsockPolicy,
};
use boxcar_proto::guest::{GuestMsg, HostMsg, SessionConfig};
use boxcar_proto::sensor::SensorFrame;
use boxcar_proto::{
    Hash, NetConnect, ProcConnectAttempt, ProcExec, ProcExit, ProcFileOpen, ProcFork,
    ProcHeartbeat, ProcLsmDeny, ProcMemfd, ProcSensorStatus, ProcTcpConnect, ProgramStatus, Ring,
    SensorPhase, SessionId, Source, Subject, Verdict,
};
use schemars::gen::{SchemaGenerator, SchemaSettings};
use schemars::schema::{RootSchema, Schema, SchemaObject};
use serde_json::json;

/// Where the schemas go, from the repository root.
const SCHEMA_DIR: &str = "proto/schema";
/// Where the control protocol's golden lines go.
const CONTROL_LINES: &str = "proto/testdata/control-v1.jsonl";
/// Where the sensor stream's golden frames go.
const SENSOR_LINES: &str = "proto/testdata/sensor-v1.jsonl";

/// The session id every example names.
const SESSION: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

/// Writes the four schemas and the golden lines.
pub fn run() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;
    let schemas = root.join(SCHEMA_DIR);
    fs::create_dir_all(&schemas).with_context(|| format!("create {}", schemas.display()))?;
    for (name, schema) in [
        ("control-v1.json", control_schema()),
        ("audit-v1.json", audit_schema()),
        ("guest-v1.json", guest_schema()),
        ("sensor-v1.json", sensor_schema()),
    ] {
        let path = schemas.join(name);
        let mut text = serde_json::to_string_pretty(&schema)?;
        text.push('\n');
        fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    let lines = root.join(CONTROL_LINES);
    fs::write(&lines, control_lines()?).with_context(|| format!("write {}", lines.display()))?;
    println!("wrote {}", lines.display());
    let frames = root.join(SENSOR_LINES);
    fs::write(&frames, sensor_lines()?).with_context(|| format!("write {}", frames.display()))?;
    println!("wrote {}", frames.display());
    Ok(())
}

fn generator() -> SchemaGenerator {
    SchemaSettings::draft07().into_generator()
}

/// A root schema whose definitions are every type `gen` saw, with
/// `title`, `description`, and `one_of` the alternatives for the whole
/// document (or a reference when there is one).
fn root(
    mut gen: SchemaGenerator,
    title: &str,
    description: &str,
    one_of: Vec<Schema>,
) -> RootSchema {
    let meta_schema = gen.settings().meta_schema.clone();
    let mut schema = SchemaObject::default();
    schema.metadata().title = Some(title.to_owned());
    schema.metadata().description = Some(description.to_owned());
    match one_of.len() {
        1 => {
            if let Some(Schema::Object(only)) = one_of.into_iter().next() {
                schema.reference = only.reference;
            }
        }
        _ => schema.subschemas().one_of = Some(one_of),
    }
    RootSchema {
        meta_schema,
        schema,
        definitions: gen.take_definitions(),
    }
}

/// The control protocol: a line on the socket is one of the messages;
/// the ops' parameters and results are defined beside them.
pub fn control_schema() -> RootSchema {
    let mut gen = generator();
    let lines = vec![
        gen.subschema_for::<Hello>(),
        gen.subschema_for::<Request>(),
        gen.subschema_for::<Response>(),
        gen.subschema_for::<StateEvent>(),
        gen.subschema_for::<PtyDetached>(),
        gen.subschema_for::<AuditEvent>(),
        gen.subschema_for::<AuditLagged>(),
    ];
    for define in [
        SchemaGenerator::subschema_for::<Status>,
        SchemaGenerator::subschema_for::<StopParams>,
        SchemaGenerator::subschema_for::<PtyAttachParams>,
        SchemaGenerator::subschema_for::<PtyAttached>,
        SchemaGenerator::subschema_for::<PtyWatchParams>,
        SchemaGenerator::subschema_for::<PtyResizeParams>,
        SchemaGenerator::subschema_for::<AuditSubscribeParams>,
        SchemaGenerator::subschema_for::<AuditSubscribed>,
        SchemaGenerator::subschema_for::<PolicyView>,
        SchemaGenerator::subschema_for::<PolicyUpdateParams>,
        SchemaGenerator::subschema_for::<PolicyUpdated>,
        SchemaGenerator::subschema_for::<Ready>,
    ] {
        define(&mut gen);
    }
    root(
        gen,
        "boxcar control protocol v1",
        "One line of the control socket: the server's Hello, a client's Request, the \
         server's Response, or an event (StateEvent, PtyDetached, AuditEvent, AuditLagged). \
         Each op's parameters and result are defined beside them; see docs/control-protocol.md.",
        lines,
    )
}

/// The audit log: a line is a `Record`; `Payload` gives each `type` its
/// `data`.
pub fn audit_schema() -> RootSchema {
    let mut gen = generator();
    let record = gen.subschema_for::<Record>();
    gen.subschema_for::<Payload>();
    root(
        gen,
        "boxcar audit record v1",
        "One line of a session's audit log: a Record, whose `data` is shaped by its `type` as \
         Payload lists (`type` and `data` side by side). See docs/audit-events.md.",
        vec![record],
    )
}

/// The guest control channel: a line is a `GuestMsg` or a `HostMsg`.
pub fn guest_schema() -> RootSchema {
    let mut gen = generator();
    let lines = vec![
        gen.subschema_for::<GuestMsg>(),
        gen.subschema_for::<HostMsg>(),
    ];
    // `config`'s fields are inlined into its variant; the struct on its own
    // is what the VMM checks and init runs.
    gen.subschema_for::<SessionConfig>();
    root(
        gen,
        "boxcar guest control channel v1",
        "One line on vsock port 1024 between the guest's init and the VMM: a GuestMsg (init to \
         the VMM) or a HostMsg (the VMM to init), tagged by `t`.",
        lines,
    )
}

/// The sensor stream: a frame is a `SensorFrame`, whose `type` and `data`
/// are the audit `Payload`'s.
pub fn sensor_schema() -> RootSchema {
    let mut gen = generator();
    let frame = gen.subschema_for::<SensorFrame>();
    gen.subschema_for::<Payload>();
    root(
        gen,
        "boxcar sensor stream v1",
        "One frame on vsock port 1026 from the guest's sensor to the VMM, its length prefix \
         not counted: a SensorFrame, whose `type` and `data` are a `proc.*` record's as the \
         audit Payload shapes them. See docs/audit-events.md.",
        vec![frame],
    )
}

/// The golden frames: one record of each sensor type, as the sensor would
/// send them during one session, as JSON lines.
pub fn sensor_lines() -> Result<Vec<u8>> {
    let subject = Some(Subject {
        pid: 212,
        uid: 1000,
        gid: 1000,
    });
    let frame = |ts_guest_ns: u64, subject: Option<Subject>, payload: Payload| SensorFrame {
        ts_guest_ns,
        subject,
        payload,
    };
    let frames = [
        frame(
            1_000_000_000,
            None,
            Payload::ProcSensorStatus(ProcSensorStatus {
                phase: SensorPhase::Degraded,
                programs: vec![
                    ProgramStatus {
                        name: "sched_process_exec".to_owned(),
                        attached: true,
                        error: None,
                    },
                    ProgramStatus {
                        name: "file_open".to_owned(),
                        attached: false,
                        error: Some("the hook is not sleepable here".to_owned()),
                    },
                ],
                kernel_release: "6.18.54".to_owned(),
                btf_ok: true,
                session_cgroup_id: 4242,
                pid: 77,
                reason: None,
            }),
        ),
        frame(
            1_500_000_000,
            Some(Subject {
                pid: 200,
                uid: 1000,
                gid: 1000,
            }),
            Payload::ProcFork(ProcFork {
                parent_tid: 200,
                parent_tgid: 200,
                child_pid: 212,
                child_start_ns: 1_499_990_000,
                uid: 1000,
                gid: 1000,
                thread: false,
            }),
        ),
        frame(
            1_500_100_000,
            subject,
            Payload::ProcExec(ProcExec {
                tid: 212,
                tgid: 212,
                ppid: 200,
                uid: 1000,
                gid: 1000,
                filename: "/usr/bin/curl".to_owned(),
                argv: ["curl", "-sS", "https://example.com/"]
                    .map(str::to_owned)
                    .to_vec(),
                argv_truncated: false,
                start_ns: 1_499_990_000,
                cgroup_id: 4242,
            }),
        ),
        frame(
            1_500_200_000,
            subject,
            Payload::ProcConnectAttempt(ProcConnectAttempt {
                tid: 212,
                tgid: 212,
                family: 2,
                proto: "tcp".to_owned(),
                dst: "93.184.215.14".parse().ok(),
                dst_port: Some(443),
            }),
        ),
        frame(
            1_500_200_500,
            subject,
            Payload::ProcTcpConnect(ProcTcpConnect {
                tid: 212,
                tgid: 212,
                src: "10.0.2.15"
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                src_port: 40000,
                dst: "93.184.215.14"
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                dst_port: 443,
            }),
        ),
        frame(
            1_600_000_000,
            subject,
            Payload::ProcFileOpen(ProcFileOpen {
                tid: 212,
                tgid: 212,
                path: "/dev/shm/stage".to_owned(),
                flags: 0o100002,
                sample: 64,
            }),
        ),
        frame(
            1_600_100_000,
            subject,
            Payload::ProcMemfd(ProcMemfd {
                tid: 212,
                tgid: 212,
                name: "stage".to_owned(),
                flags: 1,
            }),
        ),
        frame(
            1_700_000_000,
            subject,
            Payload::ProcLsmDeny(ProcLsmDeny {
                tid: 212,
                tgid: 212,
                hook: "bpf".to_owned(),
                detail: 5,
            }),
        ),
        frame(
            1_800_000_000,
            subject,
            Payload::ProcExit(ProcExit {
                tid: 212,
                tgid: 212,
                exit_code: 256,
                group_dead: true,
                start_ns: 1_499_990_000,
            }),
        ),
        frame(
            2_000_000_000,
            None,
            Payload::ProcHeartbeat(ProcHeartbeat {
                uptime_ns: 1_000_000_000,
                events_emitted: 8,
                ringbuf_drops: 0,
                frames_sent: 10,
            }),
        ),
    ];
    let mut out = Vec::new();
    for frame in &frames {
        frame
            .check()
            .with_context(|| format!("the {} example", frame.payload.kind()))?;
        out.extend(serde_json::to_vec(frame)?);
        out.push(b'\n');
    }
    Ok(out)
}

/// A record as the log would hold it, for the `audit` event's example.
fn example_record() -> Record {
    Record {
        v: 1,
        session_id: SESSION.parse().unwrap_or_else(|_| SessionId::new()),
        seq: 7,
        ring: Ring::Host,
        src: Source::Net,
        kind: "net.connect".to_owned(),
        ts_host_ns: 1_700_000_000_000_000_000,
        ts_mono_ns: 5_001_000_000,
        ts_guest_ns: None,
        subject: Some(Subject {
            pid: 212,
            uid: 1000,
            gid: 1000,
        }),
        data: Payload::NetConnect(NetConnect {
            flow: 3,
            proto: "tcp".to_owned(),
            src: "10.0.2.15:40000"
                .parse()
                .unwrap_or_else(|_| unreachable_addr()),
            dst: "93.184.215.14:443"
                .parse()
                .unwrap_or_else(|_| unreachable_addr()),
            names: vec!["example.com".to_owned()],
            verdict: Verdict::Allow,
            rule: Some("allow example.com".to_owned()),
        })
        .into_parts()
        .1,
        span: None,
        prev: Hash([0x11; 32]),
        hash: Hash([0x22; 32]),
    }
}

/// Never reached: the literals above parse.
fn unreachable_addr() -> std::net::SocketAddrV4 {
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
}

/// The golden lines: every message type, every op with its parameters and
/// result, every event, every error code, and the ready line, in the order
/// a session might see them.
pub fn control_lines() -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut line = |message: &dyn erased::Message| -> Result<()> {
        out.extend(message.line()?);
        Ok(())
    };
    let capabilities = ["pty", "audit", "policy.net", "policy.inspect", "findings"]
        .map(str::to_owned)
        .to_vec();
    line(&Ready {
        ready: true,
        control: format!("/run/user/1000/boxcar/{SESSION}/control.sock"),
        session_id: SESSION.to_owned(),
    })?;
    line(&Hello::new("boxcar/0.1.0", SESSION, capabilities))?;

    line(&Request::new(1, "status", json!({})))?;
    let status = Status {
        state: VmState::Running,
        session_id: SESSION.to_owned(),
        pid: 4242,
        uptime_ms: 61_500,
        vcpus: 2,
        mem_mib: 512,
        guest: control::GuestStatus {
            init_ready: true,
            session_pid: Some(212),
            exit: None,
        },
        audit: control::AuditStatus {
            next_seq: 8,
            failed: false,
        },
        devices: ["fs:root", "fs:workspace", "net", "vsock"]
            .map(str::to_owned)
            .to_vec(),
        sensor: SensorStatus {
            state: SensorState::Attached,
            heartbeats: 61,
            last_heartbeat_ns: Some(1_700_000_000_000_000_000),
        },
    };
    line(&Response::success(1, serde_json::to_value(&status)?))?;

    line(&Request::new(
        2,
        "pty.attach",
        serde_json::to_value(PtyAttachParams {
            session: control::PTY_SESSION.to_owned(),
            mode: PtyMode::Rw,
            replay_bytes: 65_536,
        })?,
    ))?;
    line(&Response::success(
        2,
        serde_json::to_value(PtyAttached {
            raw: true,
            attach_id: "0123456789abcdef0123456789abcdef".to_owned(),
        })?,
    ))?;
    line(&Request::new(
        3,
        "pty.watch",
        serde_json::to_value(PtyWatchParams {
            attach_id: "0123456789abcdef0123456789abcdef".to_owned(),
            session: Some(control::PTY_SESSION.to_owned()),
        })?,
    ))?;
    line(&Response::success(3, json!({})))?;
    line(&Request::new(
        4,
        "pty.resize",
        serde_json::to_value(PtyResizeParams {
            session: control::PTY_SESSION.to_owned(),
            rows: 40,
            cols: 120,
        })?,
    ))?;
    line(&Response::success(4, json!({})))?;
    line(&PtyDetached::slow("0123456789abcdef0123456789abcdef"))?;

    line(&Request::new(
        5,
        "audit.subscribe",
        serde_json::to_value(AuditSubscribeParams {
            from_seq: Some(1),
            types: vec!["net.".to_owned()],
            pid: Some(212),
            min_score: Some(70),
        })?,
    ))?;
    line(&Response::success(
        5,
        serde_json::to_value(AuditSubscribed {
            next_seq: 8,
            sub: 1,
        })?,
    ))?;
    line(&AuditEvent::new(1, example_record()))?;
    line(&AuditLagged::new(1, 16_385))?;

    line(&Request::new(6, "policy.get", json!({})))?;
    let view = PolicyView {
        net: NetPolicy {
            default: Verdict::Deny,
            allow: ["example.com", "*.github.io:443"]
                .map(str::to_owned)
                .to_vec(),
            deny: vec!["10.0.0.0/8".to_owned()],
            inspect: vec!["api.anthropic.com:443".to_owned()],
        },
        vsock: VsockPolicy {
            allow_ports: vec![5000],
        },
        version: 1,
    };
    line(&Response::success(6, serde_json::to_value(&view)?))?;
    line(&Request::new(
        7,
        "policy.update",
        serde_json::to_value(PolicyUpdateParams {
            net: Some(NetPolicy {
                default: Verdict::Deny,
                allow: ["example.com", "*.github.io:443", "api.github.com:443"]
                    .map(str::to_owned)
                    .to_vec(),
                deny: vec!["10.0.0.0/8".to_owned()],
                inspect: vec!["api.anthropic.com:443".to_owned()],
            }),
            vsock: None,
        })?,
    ))?;
    line(&Response::success(
        7,
        serde_json::to_value(PolicyUpdated { policy_version: 2 })?,
    ))?;

    // Every error code once.
    let errors = [
        (
            ErrorCode::BadRequest,
            "stop parameters: unknown variant `now`",
        ),
        (ErrorCode::UnsupportedVersion, "v must be 1"),
        (ErrorCode::UnknownOp, "no op \"pty.detach\""),
        (
            ErrorCode::InvalidState,
            "the session's terminal is not open yet: the guest's init has not connected it",
        ),
        (
            ErrorCode::NotFound,
            "no session \"other\": the session is \"main\"",
        ),
        (
            ErrorCode::Busy,
            "a connection holds at most 4 audit subscriptions; close one (or the connection) first",
        ),
        (
            ErrorCode::RateLimited,
            "over 100 requests a second; the request was dropped",
        ),
        (
            ErrorCode::Internal,
            "the response: the line is over 1048576 bytes",
        ),
    ];
    for (n, (code, message)) in errors.into_iter().enumerate() {
        line(&Response::failure(
            8 + n as u64,
            ErrorBody::new(code, message),
        ))?;
    }

    line(&Request::new(
        16,
        "stop",
        serde_json::to_value(StopParams {
            mode: StopMode::Graceful,
            timeout_ms: Some(5000),
        })?,
    ))?;
    line(&Response::success(16, json!({"accepted": true})))?;
    line(&StateEvent::new(VmState::Stopping))?;
    line(&StateEvent::new(VmState::Stopped))?;
    Ok(out)
}

/// Any message, as its line.
mod erased {
    use anyhow::Result;
    use serde::Serialize;

    pub trait Message {
        fn line(&self) -> Result<Vec<u8>>;
    }

    impl<T: Serialize> Message for T {
        fn line(&self) -> Result<Vec<u8>> {
            Ok(super::to_line(self)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each root defines its message types, and a definition is one for
    /// each type named: the derive sees the same types the protocol does.
    #[test]
    fn the_roots_define_their_messages() {
        let mut control = control_schema();
        for name in [
            "Hello",
            "Request",
            "Response",
            "ErrorBody",
            "ErrorCode",
            "StateEvent",
            "VmState",
            "Status",
            "StopParams",
            "PtyAttachParams",
            "PtyAttached",
            "PtyWatchParams",
            "PtyResizeParams",
            "PtyDetached",
            "AuditSubscribeParams",
            "AuditSubscribed",
            "AuditLagged",
            "NetPolicy",
            "VsockPolicy",
            "PolicyView",
            "PolicyUpdateParams",
            "PolicyUpdated",
            "Ready",
            "Record",
            "SensorStatus",
            "SensorState",
        ] {
            assert!(control.definitions.contains_key(name), "control: {name}");
        }
        assert!(
            control
                .definitions
                .keys()
                .any(|k| k.starts_with("AuditEvent")),
            "{:?}",
            control.definitions.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            control.schema.subschemas().one_of.as_ref().map(Vec::len),
            Some(7)
        );
        assert_eq!(
            control.meta_schema.as_deref(),
            Some("http://json-schema.org/draft-07/schema#")
        );

        let audit = audit_schema();
        for name in [
            "Record",
            "Payload",
            "Ring",
            "Source",
            "Hash",
            "SessionId",
            "Subject",
            "SpanRef",
            "Verdict",
            "OpResult",
            "NetConnect",
            "FsClose",
            "PolicyChanged",
            "ClockSync",
            "ProcExec",
            "ProcSensorStatus",
            "Finding",
            "FindingCategory",
            "Evidence",
        ] {
            assert!(audit.definitions.contains_key(name), "audit: {name}");
        }
        assert_eq!(
            audit.schema.reference.as_deref(),
            Some("#/definitions/Record")
        );

        let guest = guest_schema();
        for name in ["GuestMsg", "HostMsg", "SessionConfig", "LogLevel"] {
            assert!(guest.definitions.contains_key(name), "guest: {name}");
        }

        let sensor = sensor_schema();
        for name in [
            "SensorFrame",
            "Payload",
            "Subject",
            "ProcExec",
            "ProcHeartbeat",
        ] {
            assert!(sensor.definitions.contains_key(name), "sensor: {name}");
        }
        assert_eq!(
            sensor.schema.reference.as_deref(),
            Some("#/definitions/SensorFrame")
        );
    }

    /// One frame of each sensor record type, every one a frame the stream
    /// accepts.
    #[test]
    fn the_sensor_lines_cover_every_proc_type() {
        let text = String::from_utf8(sensor_lines().unwrap()).unwrap();
        let mut kinds: Vec<String> = text
            .lines()
            .map(|line| {
                let frame: SensorFrame = serde_json::from_str(line).unwrap();
                frame.check().unwrap();
                frame.payload.kind().to_owned()
            })
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            [
                "proc.connect_attempt",
                "proc.exec",
                "proc.exit",
                "proc.file_open",
                "proc.fork",
                "proc.heartbeat",
                "proc.lsm_deny",
                "proc.memfd",
                "proc.sensor_status",
                "proc.tcp_connect",
            ]
        );
        assert_eq!(sensor_lines().unwrap(), sensor_lines().unwrap());
    }

    /// The output is the same every time: CI compares it with what is
    /// committed.
    #[test]
    fn the_output_is_deterministic() {
        let once = serde_json::to_string(&control_schema()).unwrap();
        assert_eq!(once, serde_json::to_string(&control_schema()).unwrap());
        assert_eq!(control_lines().unwrap(), control_lines().unwrap());
        let text = String::from_utf8(control_lines().unwrap()).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.lines().count() > 20);
        for line in text.lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(value.is_object(), "{line}");
        }
    }
}
