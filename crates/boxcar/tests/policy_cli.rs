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
    to_line, ErrorBody, ErrorCode, ExceptionKind, ExceptionView, Hello, NetPolicy,
    PolicyUpdateParams, PolicyUpdated, PolicyView, Response, VsockPolicy,
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
            inspect: strings(&["a.test:443"]),
        },
        vsock: VsockPolicy {
            allow_ports: vec![5000, 6000],
        },
        version: 1,
        exceptions: Vec::new(),
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
fn fake_server(path: &Path, policy: PolicyView, refuse: Option<ErrorBody>) -> JoinHandle<Served> {
    fake_server_with(path, policy, refuse, &CAPABILITIES)
}

/// What a current server's hello lists.
const CAPABILITIES: [&str; 7] = [
    "pty",
    "audit",
    "policy.net",
    "policy.inspect",
    "findings",
    "spans",
    "policy.exception",
];

/// [`fake_server`] whose hello lists `capabilities`. A grant
/// (`policy.update` with `exception`) adds the exception to the policy's
/// list, with the next id.
fn fake_server_with(
    path: &Path,
    mut policy: PolicyView,
    refuse: Option<ErrorBody>,
    capabilities: &[&str],
) -> JoinHandle<Served> {
    let capabilities = strings(capabilities);
    // A test may start a second server at the same path.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let mut served = Served::default();
        let (mut stream, _) = listener.accept().unwrap();
        let hello = Hello::new("boxcar/fake", SESSION, capabilities);
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
                        if let Some(grant) = params.exception {
                            policy.exceptions.push(ExceptionView {
                                id: policy.exceptions.len() as u32 + 1,
                                rule: grant.rule,
                                kind: grant.kind,
                                ttl_s: grant.ttl_s,
                                expires_ns: u64::MAX / 2,
                                by_pid: 42,
                            });
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
         inspect  a.test:443\n\
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
            inspect: Vec::new(),
        },
        vsock: VsockPolicy::default(),
        version: 7,
        exceptions: Vec::new(),
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
         inspect  (none)\n\
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
            inspect: strings(&["a.test:443"]),
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
            inspect: strings(&["a.test:443"]),
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
        // No comment in a rule: what the VMM would refuse is refused here.
        ("allow", "a.test # x", "one target"),
        ("deny", "a.test#x", "not a host name"),
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

/// `boxcar policy profile NAME` with no session: what it printed.
fn profile(name: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["policy", "profile", name])
        .output()
        .unwrap()
}

/// Each profile prints byte for byte as `boxcar run --policy NAME` reads
/// it, so a copy of it in a file is the same policy.
#[test]
fn policy_profile_prints_each_profile_as_run_reads_it() {
    for name in boxcar_policy::profiles::NAMES {
        let output = profile(name);
        assert_eq!(output.status.code(), Some(0), "{name}: {}", stderr(&output));
        let text = boxcar_policy::profiles::text(name).unwrap();
        assert_eq!(stdout(&output), text, "{name}");
        assert_eq!(
            boxcar_policy::parse(&stdout(&output)).unwrap(),
            boxcar_policy::parse(text).unwrap()
        );
    }
}

/// A name there is no profile of is a usage error that names the ones
/// there are.
#[test]
fn policy_profile_refuses_a_name_there_is_no_profile_of() {
    for name in ["agent", "Agent-Isolate", "./agent-isolate", ""] {
        let output = profile(name);
        assert_eq!(output.status.code(), Some(2), "{name:?}");
        assert!(stdout(&output).is_empty());
        assert!(
            stderr(&output).contains(&format!(
                "error: there is no profile {name:?}; the profiles are agent-isolate, \
                 agent-isolate-strict"
            )),
            "{name:?}: {}",
            stderr(&output)
        );
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

/// `allow ... --ttl` grants an exception, alone in its update and of the
/// kind its flag says, without reading the policy first.
#[test]
fn allow_with_a_ttl_grants_an_exception() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    for (args, rule, kind, ttl_s) in [
        (
            &["allow", "pypi.org:443", "--ttl", "10m"][..],
            "pypi.org:443",
            "egress",
            600,
        ),
        (
            &["allow", "--writable", "/etc/**", "--ttl", "90"][..],
            "/etc/**",
            "writable",
            90,
        ),
        (
            &["allow", "--exec", "/workspace/*", "--ttl", "1h"][..],
            "/workspace/*",
            "exec",
            3600,
        ),
    ] {
        let server = fake_server(&socket, starting_policy(), None);
        let output = policy(&socket, args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            stderr(&output)
        );
        assert_eq!(
            stdout(&output),
            format!("policy version 2 ({kind} exception {rule} for {ttl_s} s)\n")
        );
        let served = server.join().unwrap();
        assert_eq!(ops(&served), ["policy.update"]);
        let update = &served.requests[0];
        assert_eq!(
            update["exception"],
            serde_json::json!({"rule": rule, "kind": kind, "ttl_s": ttl_s})
        );
        assert!(update.get("net").is_none() && update.get("vsock").is_none());
    }
}

/// What a grant needs: `--ttl` for a path exception, a rule that parses as
/// its kind, a duration within a day: usage errors before any connection.
#[test]
fn an_exception_that_cannot_be_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("nobody.sock");
    for args in [
        &["allow", "--writable", "/etc/**"][..],
        &["allow", "--writable", "etc/**", "--ttl", "60"][..],
        &["allow", "--exec", "/usr/bin/[z-a]", "--ttl", "60"][..],
        &["allow", "exa_mple.com", "--ttl", "60"][..],
        &["allow", "pypi.org", "--ttl", "2d"][..],
        &["allow", "pypi.org", "--ttl", "0"][..],
        &["allow", "pypi.org", "--writable", "/x", "--ttl", "60"][..],
        &["allow"][..],
    ] {
        let output = policy(&socket, args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

/// `exception ls` lists the live exceptions; with `--json`, the list as the
/// server gave it.
#[test]
fn exception_ls_lists_the_live_exceptions() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let mut live = starting_policy();
    live.exceptions = vec![ExceptionView {
        id: 3,
        rule: "pypi.org:443".into(),
        kind: ExceptionKind::Egress,
        ttl_s: 600,
        expires_ns: u64::MAX / 2,
        by_pid: 42,
    }];
    let server = fake_server(&socket, live.clone(), None);
    let output = policy(&socket, &["exception", "ls"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).starts_with("3    egress   pypi.org:443 ("),
        "{}",
        stdout(&output)
    );
    server.join().unwrap();

    let server = fake_server(&socket, live.clone(), None);
    let output = policy(&socket, &["exception", "ls", "--json"]);
    assert_eq!(
        serde_json::from_str::<Value>(&stdout(&output)).unwrap(),
        serde_json::to_value(&live.exceptions).unwrap()
    );
    server.join().unwrap();

    let server = fake_server(&socket, starting_policy(), None);
    let output = policy(&socket, &["exception", "ls"]);
    assert_eq!(stdout(&output), "(none)\n");
    server.join().unwrap();
}

/// A server whose hello lists no `policy.exception` is told so, and asked
/// nothing.
#[test]
fn a_server_without_exceptions_is_not_asked_for_one() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let older = &CAPABILITIES[..6];
    for args in [
        &["allow", "pypi.org", "--ttl", "60"][..],
        &["exception", "ls"][..],
    ] {
        let server = fake_server_with(&socket, starting_policy(), None, older);
        let output = policy(&socket, args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("policy.exception"),
            "{}",
            stderr(&output)
        );
        assert!(server.join().unwrap().requests.is_empty());
    }
}

/// A permanent `allow` while an exception lives writes back the permanent
/// rules it read, which never hold the exception.
#[test]
fn a_permanent_allow_never_writes_an_exception_back() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("control.sock");
    let mut live = starting_policy();
    live.exceptions = vec![ExceptionView {
        id: 1,
        rule: "pypi.org:443".into(),
        kind: ExceptionKind::Egress,
        ttl_s: 600,
        expires_ns: u64::MAX / 2,
        by_pid: 42,
    }];
    let server = fake_server(&socket, live, None);
    let output = policy(&socket, &["allow", "new.test"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let net = updated_net(&server.join().unwrap());
    assert_eq!(net.allow, ["a.test", "*.github.io:443", "new.test"]);
}
