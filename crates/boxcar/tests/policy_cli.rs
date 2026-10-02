// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar policy` against a fake control server in the test: what `show`
//! prints, the `policy.get` and `policy.update` that `allow` and `deny`
//! send, and how each ends (a rule that does not parse, a refusal, no
//! server). No KVM needed.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use boxcar_proto::control::{
    to_line, ErrorBody, ErrorCode, Hello, NetPolicy, PolicyUpdateParams, PolicyUpdated, PolicyView,
    Response, VsockPolicy,
};
use boxcar_proto::Verdict;
use serde_json::Value;

const SESSION: &str = "01999a8e-1c2d-7e3f-8a4b-5c6d7e8f9a0b";

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The policy the fake server starts with: version 1.
fn starting_policy() -> PolicyView {
    PolicyView {
        net: NetPolicy {
            default: Verdict::Deny,
            allow: strings(&["a.test", "*.github.io:443"]),
            deny: strings(&["b.test", "c.test"]),
        },
        vsock: VsockPolicy {
            allow_ports: vec![5000, 6000],
        },
        version: 1,
    }
}

/// What the fake server saw and did.
#[derive(Default)]
struct Served {
    requests: Vec<Value>,
}

/// A fake control server at `path` holding `policy`: it sends the hello,
/// answers `policy.get` with the policy and `policy.update` by applying
/// `net` and `vsock` and moving the version on, unless `refuse` names the
/// error to answer an update with. One connection, then it returns what it
/// saw.
fn fake_server(
    path: &Path,
    mut policy: PolicyView,
    refuse: Option<ErrorBody>,
) -> JoinHandle<Served> {
    // A test may start a second server at the same path.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let mut served = Served::default();
        let (mut stream, _) = listener.accept().unwrap();
        let hello = Hello::new(
            "boxcar/fake",
            SESSION,
            strings(&["pty", "audit", "policy.net"]),
        );
        stream.write_all(&to_line(&hello).unwrap()).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let request: Value = serde_json::from_str(&line).unwrap();
            let id = request["id"].as_u64().unwrap();
            served.requests.push(request.clone());
            let response = match request["op"].as_str().unwrap() {
                "policy.get" => Response::success(id, serde_json::to_value(&policy).unwrap()),
                "policy.update" => match &refuse {
                    Some(error) => Response::failure(id, error.clone()),
                    None => {
                        let params: PolicyUpdateParams =
                            serde_json::from_value(request.clone()).unwrap();
                        if let Some(net) = params.net {
                            policy.net = net;
                        }
                        if let Some(vsock) = params.vsock {
                            policy.vsock = vsock;
                        }
                        policy.version += 1;
                        Response::success(
                            id,
                            serde_json::to_value(PolicyUpdated {
                                policy_version: policy.version,
                            })
                            .unwrap(),
                        )
                    }
                },
                other => Response::failure(id, ErrorBody::unknown_op(other)),
            };
            let _ = stream.write_all(&to_line(&response).unwrap());
        }
        served
    })
}

fn policy(control: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .arg("policy")
        .args(args)
        .arg("--control")
        .arg(control)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The ops of the requests the server saw, in order.
fn ops(served: &Served) -> Vec<&str> {
    served
        .requests
        .iter()
        .map(|r| r["op"].as_str().unwrap())
        .collect()
}

/// The `net` an update asked for.
fn updated_net(served: &Served) -> NetPolicy {
    let update = served
        .requests
        .iter()
        .find(|r| r["op"] == "policy.update")
        .expect("an update");
    assert!(
        update.get("vsock").is_none(),
        "only the net policy: {update}"
    );
    serde_json::from_value(update["net"].clone()).unwrap()
}

#[test]
fn policy_show_prints_the_policy_as_a_table_or_json() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let server = fake_server(&socket, starting_policy(), None);
    let output = policy(&socket, &["show"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "version  1\n\
         default  deny\n\
         allow    a.test\n\
         allow    *.github.io:443\n\
         deny     b.test\n\
         deny     c.test\n\
         vsock    5000, 6000\n"
    );
    assert_eq!(ops(&server.join().unwrap()), ["policy.get"]);

    let server = fake_server(&socket, starting_policy(), None);
    let output = policy(&socket, &["show", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        serde_json::from_str::<Value>(&stdout(&output)).unwrap(),
        serde_json::to_value(starting_policy()).unwrap()
    );
    assert!(stdout(&output).ends_with('\n'));
    server.join().unwrap();
}

/// A policy with nothing in it reads as such.
#[test]
fn policy_show_of_an_empty_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let empty = PolicyView {
        net: NetPolicy {
            default: Verdict::Allow,
            allow: Vec::new(),
            deny: Vec::new(),
        },
        vsock: VsockPolicy::default(),
        version: 7,
    };
    let server = fake_server(&socket, empty, None);
    let output = policy(&socket, &["show"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "version  7\n\
         default  allow\n\
         allow    (none)\n\
         deny     (none)\n\
         vsock    (none)\n"
    );
    server.join().unwrap();
}

/// `allow RULE` reads the policy, appends the rule to the allows, takes
/// the same rule out of the denies, and sends the whole network policy
/// back; the vsock list is not touched. It says the new version.
#[test]
fn policy_allow_appends_the_rule_and_drops_its_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let server = fake_server(&socket, starting_policy(), None);
    let output = policy(&socket, &["allow", "b.test"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "policy version 2\n");
    let served = server.join().unwrap();
    assert_eq!(ops(&served), ["policy.get", "policy.update"]);
    assert_eq!(
        updated_net(&served),
        NetPolicy {
            default: Verdict::Deny,
            allow: strings(&["a.test", "*.github.io:443", "b.test"]),
            deny: strings(&["c.test"]),
        }
    );
}

#[test]
fn policy_deny_appends_the_rule_and_drops_its_allow() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let server = fake_server(&socket, starting_policy(), None);
    let output = policy(&socket, &["deny", "*.github.io:443"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "policy version 2\n");
    let served = server.join().unwrap();
    assert_eq!(
        updated_net(&served),
        NetPolicy {
            default: Verdict::Deny,
            allow: strings(&["a.test"]),
            deny: strings(&["b.test", "c.test", "*.github.io:443"]),
        }
    );
}

/// A rule the policy already has in that list changes nothing: no update
/// is sent, and the version stays.
#[test]
fn policy_allow_of_a_rule_already_allowed_sends_no_update() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let server = fake_server(&socket, starting_policy(), None);
    let output = policy(&socket, &["allow", "a.test"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "policy version 1 (unchanged)\n");
    assert_eq!(ops(&server.join().unwrap()), ["policy.get"]);
}

/// A rule that does not parse is refused here, as `boxcar run` refuses
/// one: exit 2, with the reason, before any connection is made.
#[test]
fn a_rule_that_does_not_parse_exits_2_before_connecting() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nobody.sock");
    for (verb, rule, why) in [
        ("allow", "exa_mple.com", "not a host name"),
        ("deny", "192.168.1.300", "not an IPv4 address"),
        ("allow", "a.test:0", "not a port"),
        ("allow", "two words", "one target"),
        ("allow", "", "one target"),
    ] {
        let output = policy(&missing, &[verb, rule]);
        assert_eq!(output.status.code(), Some(2), "{verb} {rule:?}");
        assert!(
            stderr(&output).contains(why),
            "{verb} {rule:?}: {}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("cannot connect"));
    }
}

/// A server that refuses the update, or no server at all: exit 1 and the
/// reason.
#[test]
fn policy_fails_when_the_server_refuses_or_is_not_there() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let refusal = ErrorBody::new(ErrorCode::InvalidState, "the VM has no network card");
    let server = fake_server(&socket, starting_policy(), Some(refusal));
    let output = policy(&socket, &["allow", "d.test"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("policy.update: invalid_state: the VM has no network card"),
        "{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");
    server.join().unwrap();

    let missing = tmp.path().join("nobody.sock");
    for args in [&["show"][..], &["allow", "d.test"], &["deny", "d.test"]] {
        let output = policy(&missing, args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&output).contains("cannot connect"),
            "{}",
            stderr(&output)
        );
    }
}

/// `policy` wants a subcommand, and `allow` and `deny` want a rule.
#[test]
fn policy_usage_errors_exit_2() {
    let shared = Arc::new(Mutex::new(()));
    let _held = shared.lock().unwrap();
    for args in [&[][..], &["allow"], &["deny"], &["grant", "a.test"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_boxcar"))
            .arg("policy")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    drop(UnixStream::pair());
}
