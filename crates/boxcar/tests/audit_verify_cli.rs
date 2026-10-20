// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit verify --control` against a fake control server in the
//! test: it asks `audit.verify` until `more` is false, chains the stretches
//! by `from_prev`, refuses a stretch that does not chain, and tells a break
//! from a session that cannot verify, an older one included. No KVM needed.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};

use boxcar_proto::control::{
    to_line, AuditVerify, AuditVerifyParams, ErrorBody, ErrorCode, Hello, Response,
};
use boxcar_proto::Hash;
use serde_json::{json, Value};

const SESSION: &str = "01999a8e-1c2d-7e3f-8a4b-5c6d7e8f9a0b";

/// What a current server's hello lists.
const CAPABILITIES: [&str; 8] = [
    "pty",
    "audit",
    "policy.net",
    "policy.inspect",
    "findings",
    "spans",
    "policy.exception",
    "audit.verify",
];

/// A hash made of one byte.
fn h(byte: u8) -> Hash {
    Hash([byte; 32])
}

/// A stretch: seq `from` to `to`, starting from `from_prev`, ending at the
/// hash `h(to)`, against a head at `head`, whose hash is `h(head)`.
fn stretch(from: u64, from_prev: Hash, to: u64, head: u64) -> AuditVerify {
    AuditVerify {
        from_seq: from,
        from_prev,
        to_seq: to,
        to_hash: h(to as u8),
        head_seq: head,
        head_hash: h(head as u8),
        checkpoints: 1,
        more: to < head,
    }
}

/// A fake control server at `path` whose hello lists `capabilities`: it
/// answers each `audit.verify` with the next of `replies`, and anything
/// else `unknown_op`. One connection, then it returns the parameters of
/// each request it got.
fn fake_server(
    path: &Path,
    capabilities: &[&str],
    replies: Vec<Result<AuditVerify, ErrorBody>>,
) -> JoinHandle<Vec<Value>> {
    let capabilities: Vec<String> = capabilities.iter().map(|c| (*c).to_owned()).collect();
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let mut requests = Vec::new();
        let mut replies = replies.into_iter();
        let (mut stream, _) = listener.accept().unwrap();
        let hello = Hello::new("boxcar/fake", SESSION, capabilities);
        stream.write_all(&to_line(&hello).unwrap()).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let request: Value = serde_json::from_str(&line).unwrap();
            let id = request["id"].as_u64().unwrap();
            let op = request["op"].as_str().unwrap().to_owned();
            requests.push(request);
            let response = match (op.as_str(), replies.next()) {
                ("audit.verify", Some(Ok(reply))) => {
                    Response::success(id, serde_json::to_value(reply).unwrap())
                }
                ("audit.verify", Some(Err(error))) => Response::failure(id, error),
                ("audit.verify", None) => panic!("asked once too often"),
                (other, _) => Response::failure(id, ErrorBody::unknown_op(other)),
            };
            let _ = stream.write_all(&to_line(&response).unwrap());
        }
        requests
    })
}

/// A socket path in a fresh directory.
fn socket() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("control.sock");
    (tmp, path)
}

fn verify(control: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["audit", "verify", "--control"])
        .arg(control)
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The `from_seq` of each request the server got.
fn asked(requests: &[Value]) -> Vec<u64> {
    requests
        .iter()
        .map(|r| {
            assert_eq!(r["op"], "audit.verify", "{r}");
            let params: AuditVerifyParams = serde_json::from_value(r.clone()).unwrap();
            params.from_seq.expect("a from_seq")
        })
        .collect()
}

/// Three stretches, the head moving on meanwhile: each asked from the seq
/// after the last, each starting from the hash the one before ended at.
fn three_stretches() -> Vec<Result<AuditVerify, ErrorBody>> {
    vec![
        Ok(stretch(1, h(0), 10, 22)),
        Ok(stretch(11, h(10), 20, 25)),
        Ok(stretch(21, h(20), 25, 25)),
    ]
}

/// It asks until `more` is false, from the seq after each stretch, and
/// says what it verified against which head.
#[test]
fn it_asks_until_the_head_chaining_the_stretches() {
    let (_tmp, path) = socket();
    let server = fake_server(&path, &CAPABILITIES, three_stretches());
    let output = verify(&path, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        text(&output.stdout),
        format!(
            "ok: verified seq 1..25 against the writer's head b3:{}\n",
            "19".repeat(32)
        )
    );
    assert_eq!(asked(&server.join().unwrap()), [1, 11, 21]);

    // As one JSON object.
    let (_tmp, path) = socket();
    let server = fake_server(&path, &CAPABILITIES, three_stretches());
    let output = verify(&path, &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary,
        json!({
            "ok": true,
            "from_seq": 1,
            "to_seq": 25,
            "head_seq": 25,
            "head_hash": h(25),
            "checkpoints": 3,
            "stretches": 3,
        })
    );
    server.join().unwrap();

    // From a seq: the first stretch's `from_prev` is the server's to say.
    let (_tmp, path) = socket();
    let replies = vec![
        Ok(stretch(11, h(77), 20, 25)),
        Ok(stretch(21, h(20), 25, 25)),
    ];
    let server = fake_server(&path, &CAPABILITIES, replies);
    let output = verify(&path, &["--from-seq", "11"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).starts_with("ok: verified seq 11..25 "),
        "{}",
        text(&output.stdout)
    );
    assert_eq!(asked(&server.join().unwrap()), [11, 21]);
}

/// A stretch that does not start from the hash the one before ended at is
/// refused, and nothing more is asked; so is one that claims the head with
/// another hash.
#[test]
fn a_stretch_that_does_not_chain_is_refused() {
    let (_tmp, path) = socket();
    let replies = vec![
        Ok(stretch(1, h(0), 10, 25)),
        Ok(stretch(11, h(99), 20, 25)),
        Ok(stretch(21, h(20), 25, 25)),
    ];
    let server = fake_server(&path, &CAPABILITIES, replies);
    let output = verify(&path, &[]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = text(&output.stdout);
    assert!(
        stdout.starts_with("fail: the stretch from seq 11 does not chain")
            && stdout.contains(&h(99).to_string())
            && stdout.contains(&h(10).to_string()),
        "{stdout}"
    );
    assert_eq!(asked(&server.join().unwrap()), [1, 11]);

    let (_tmp, path) = socket();
    let mut wrong = stretch(1, h(0), 25, 25);
    wrong.to_hash = h(3);
    let server = fake_server(&path, &CAPABILITIES, vec![Ok(wrong)]);
    let output = verify(&path, &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        (&error["ok"], &error["error"]),
        (&json!(false), &json!("chain"))
    );
    server.join().unwrap();
}

/// A break the VMM found is `fail:` with its message; a session that
/// cannot verify (its writer closed, say) is an error on stderr. Both
/// exit 1.
#[test]
fn a_break_and_a_refusal_exit_1() {
    let message = "chain broken at seq 7: expected b3:00, got b3:11";
    let (_tmp, path) = socket();
    let replies = vec![
        Ok(stretch(1, h(0), 5, 25)),
        Err(ErrorBody::new(ErrorCode::Internal, message)),
    ];
    let server = fake_server(&path, &CAPABILITIES, replies);
    let output = verify(&path, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(text(&output.stdout), format!("fail: {message}\n"));
    server.join().unwrap();

    let (_tmp, path) = socket();
    let closed = "cannot verify the audit log: the audit log writer is closed";
    let replies = vec![Err(ErrorBody::new(ErrorCode::InvalidState, closed))];
    let server = fake_server(&path, &CAPABILITIES, replies);
    let output = verify(&path, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(text(&output.stdout), "");
    assert!(
        text(&output.stderr).contains(&format!("audit.verify: invalid_state: {closed}")),
        "{}",
        text(&output.stderr)
    );
    server.join().unwrap();

    let (_tmp, path) = socket();
    let replies = vec![Err(ErrorBody::new(ErrorCode::InvalidState, closed))];
    let server = fake_server(&path, &CAPABILITIES, replies);
    let output = verify(&path, &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["error"], "invalid_state");
    server.join().unwrap();
}

/// A server whose hello lacks `audit.verify` is not asked, and the error
/// says why.
#[test]
fn a_server_without_audit_verify_is_not_asked() {
    let (_tmp, path) = socket();
    let older = &CAPABILITIES[..7];
    let server = fake_server(&path, older, Vec::new());
    let output = verify(&path, &[]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("its hello lists no audit.verify"),
        "{stderr}"
    );
    assert!(server.join().unwrap().is_empty(), "nothing was asked");
}

/// `--from-seq` without `--control`, or no log at all, is a usage error.
#[test]
fn usage_errors_exit_2() {
    for args in [
        &["audit", "verify"][..],
        &["audit", "verify", "x", "--from-seq", "2"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_boxcar"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}
