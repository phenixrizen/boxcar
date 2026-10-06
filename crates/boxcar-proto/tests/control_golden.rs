// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The golden control protocol lines, `proto/testdata/control-v1.jsonl`
//! (written by `cargo xtask schema`): every line parses as the message its
//! shape says it is, and every op, event and error code appears.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use boxcar_proto::control::{
    parse_request, AuditEvent, AuditLagged, AuditSubscribeParams, ErrorCode, Hello,
    PolicyUpdateParams, PolicyUpdated, PolicyView, PtyAttachParams, PtyAttached, PtyDetached,
    PtyResizeParams, PtyWatchParams, Ready, Response, SpanList, SpanListParams, StateEvent, Status,
    StopParams, MAX_LINE,
};
use serde_json::Value;

const OPS: [&str; 9] = [
    "status",
    "stop",
    "pty.attach",
    "pty.watch",
    "pty.resize",
    "audit.subscribe",
    "policy.get",
    "policy.update",
    "span.list",
];
const EVENTS: [&str; 5] = ["hello", "state", "pty.detached", "audit", "audit.lagged"];
const CODES: [ErrorCode; 8] = [
    ErrorCode::BadRequest,
    ErrorCode::UnsupportedVersion,
    ErrorCode::UnknownOp,
    ErrorCode::InvalidState,
    ErrorCode::NotFound,
    ErrorCode::Busy,
    ErrorCode::RateLimited,
    ErrorCode::Internal,
];

fn golden() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto/testdata/control-v1.jsonl");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The parameters of a request parse as the op's type, and the result of
/// the response that follows it as the op's result type.
fn check_op(op: &str, params: &Value, result: &Value) {
    fn as_<T: serde::de::DeserializeOwned>(what: &str, value: &Value) {
        serde_json::from_value::<T>(value.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
    }
    match op {
        "status" => as_::<Status>("status result", result),
        "stop" => {
            as_::<StopParams>("stop params", params);
            assert_eq!(result["accepted"], true);
        }
        "pty.attach" => {
            as_::<PtyAttachParams>("pty.attach params", params);
            as_::<PtyAttached>("pty.attach result", result);
        }
        "pty.watch" => {
            as_::<PtyWatchParams>("pty.watch params", params);
            assert!(result.as_object().is_some_and(|o| o.is_empty()));
        }
        "pty.resize" => {
            as_::<PtyResizeParams>("pty.resize params", params);
            assert!(result.as_object().is_some_and(|o| o.is_empty()));
        }
        "audit.subscribe" => {
            as_::<AuditSubscribeParams>("audit.subscribe params", params);
            assert!(result["next_seq"].is_u64() && result["sub"].is_u64());
        }
        "policy.get" => as_::<PolicyView>("policy.get result", result),
        "policy.update" => {
            as_::<PolicyUpdateParams>("policy.update params", params);
            as_::<PolicyUpdated>("policy.update result", result);
        }
        "span.list" => {
            as_::<SpanListParams>("span.list params", params);
            as_::<SpanList>("span.list result", result);
            let list: SpanList = serde_json::from_value(result.clone()).unwrap();
            assert_eq!(list.spans.len(), 2);
            assert!(list.spans[0].closed_seq.is_none() && list.spans[1].closed_seq.is_some());
        }
        other => panic!("an op the protocol does not have: {other}"),
    }
}

#[test]
fn every_golden_line_parses_as_what_it_is_and_everything_appears() {
    let text = golden();
    let mut ops = BTreeSet::new();
    let mut events = BTreeSet::new();
    let mut codes = BTreeSet::new();
    let mut pending: Option<(u64, String, Value)> = None;
    let mut ready = false;
    for (n, line) in text.lines().enumerate() {
        assert!(line.len() <= MAX_LINE);
        let value: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("line {n}: {e}"));
        if value.get("ready").is_some() {
            let ready_line: Ready = serde_json::from_str(line).unwrap();
            assert!(ready_line.ready && ready_line.control.ends_with("/control.sock"));
            ready = true;
        } else if let Some(event) = value["event"].as_str() {
            match event {
                "hello" => {
                    let hello: Hello = serde_json::from_str(line).unwrap();
                    assert_eq!(hello.protocol, "boxcar.control");
                    assert_eq!(hello.versions, [1]);
                    assert_eq!(
                        hello.capabilities,
                        [
                            "pty",
                            "audit",
                            "policy.net",
                            "policy.inspect",
                            "findings",
                            "spans"
                        ]
                    );
                }
                "state" => {
                    serde_json::from_str::<StateEvent>(line).unwrap();
                }
                "pty.detached" => {
                    let detached: PtyDetached = serde_json::from_str(line).unwrap();
                    assert_eq!(detached.reason, "slow");
                }
                "audit" => {
                    let audit: AuditEvent = serde_json::from_str(line).unwrap();
                    assert_eq!(audit.rec.seq, 7);
                }
                "audit.lagged" => {
                    serde_json::from_str::<AuditLagged>(line).unwrap();
                }
                other => panic!("line {n}: an event the protocol does not have: {other}"),
            }
            events.insert(event.to_owned());
        } else if value.get("op").is_some() {
            let request =
                parse_request(line.as_bytes()).unwrap_or_else(|e| panic!("line {n}: {e:?}"));
            assert!(
                OPS.contains(&request.op.as_str()),
                "line {n}: {}",
                request.op
            );
            assert!(pending.is_none(), "line {n}: a request before its response");
            pending = Some((request.id, request.op.clone(), request.params));
        } else if let Some(ok) = value.get("ok") {
            let response: Response = serde_json::from_str(line).unwrap();
            if ok == true {
                let (id, op, params) = pending.take().expect("a response to a request");
                assert_eq!(response.id, id, "line {n}");
                check_op(&op, &params, &response.result.unwrap());
                ops.insert(op);
            } else {
                let error = response.error.expect("an error");
                assert!(!error.message.is_empty());
                codes.insert(error.code.as_str().to_owned());
            }
        } else {
            panic!("line {n}: not a message: {line}");
        }
    }
    assert!(ready, "the ready line");
    assert!(pending.is_none(), "a request without its response");
    assert_eq!(ops, OPS.iter().map(|s| (*s).to_owned()).collect());
    assert_eq!(events, EVENTS.iter().map(|s| (*s).to_owned()).collect());
    assert_eq!(codes, CODES.iter().map(|c| c.as_str().to_owned()).collect());
}
