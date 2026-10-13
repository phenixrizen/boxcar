// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The reconciler's rules on scenarios: each scenario is a sequence of
//! records (built here, typed) and ticks of the paused clock; the findings
//! it yields are compared, as JSON lines, with `tests/fixtures/<name>.jsonl`.
//! `BOXCAR_BLESS=1 cargo test -p boxcar-audit --test reconcile` rewrites the
//! fixtures after a deliberate change; read the diff before committing it.

use std::fs;
use std::net::{IpAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;

use boxcar_audit::{ManualClock, ReconcileConfig, Reconciler};
use boxcar_proto::{
    ClockSync, Finding, FsCreate, FsPathOp, Hash, NetConnect, NetDns, NetTls, OpResult, Payload,
    ProcExec, ProcExit, ProcFork, ProcHeartbeat, ProcLsmDeny, ProcMemfd, ProcSensorStatus,
    ProcTcpConnect, ProgramStatus, Record, Ring, SensorPhase, SessionId, SessionStart, Subject,
    Verdict, VmmStop, VsockConnect,
};

const SESSION: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;
/// The scenarios' epoch: a plausible host time.
const T0: u64 = 1_700_000_000 * S;

/// The programs, as the sensor names them.
const PROGRAMS: [&str; 9] = [
    "sched_process_exec",
    "sched_process_fork",
    "sched_process_exit",
    "socket_connect",
    "tcp_connect",
    "file_open",
    "memfd_create",
    "kill_guard",
    "bpf_guard",
];

/// What a scenario feeds the reconciler.
enum Step {
    Record(Box<Record>),
    Tick(u64),
}

/// Builds records with running seqs.
struct Log {
    seq: u64,
}

impl Log {
    fn new() -> Log {
        Log { seq: 0 }
    }

    fn rec(
        &mut self,
        at_ms: u64,
        ring: Ring,
        subject: Option<(u32, u32, u32)>,
        payload: Payload,
    ) -> Step {
        self.seq += 1;
        let src = payload.source();
        let (kind, data) = payload.into_parts();
        Step::Record(Box::new(Record {
            v: 1,
            session_id: SESSION.parse().unwrap_or_else(|_| SessionId::new()),
            seq: self.seq,
            ring,
            src,
            kind: kind.to_owned(),
            ts_host_ns: T0 + at_ms * MS,
            ts_mono_ns: at_ms * MS,
            ts_guest_ns: (ring == Ring::Guest).then_some(at_ms * MS),
            subject: subject.map(|(pid, uid, gid)| Subject { pid, uid, gid }),
            data,
            span: None,
            prev: Hash([0x11; 32]),
            hash: Hash([0x22; 32]),
        }))
    }

    fn session_start(&mut self, at_ms: u64, pid: u32) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            Some((pid, 1000, 1000)),
            Payload::SessionStart(SessionStart {
                argv: vec!["/bin/sh".into(), "-l".into()],
                cwd: "/workspace".into(),
                uid: 1000,
                gid: 1000,
                pid,
            }),
        )
    }

    fn sensor_status(&mut self, at_ms: u64, attached: &[&str]) -> Step {
        let programs = PROGRAMS
            .iter()
            .map(|name| ProgramStatus {
                name: (*name).to_owned(),
                attached: attached.contains(name),
                error: (!attached.contains(name)).then(|| "not here".to_owned()),
            })
            .collect();
        let phase = if attached.len() == PROGRAMS.len() {
            SensorPhase::Attached
        } else {
            SensorPhase::Degraded
        };
        self.rec(
            at_ms,
            Ring::Guest,
            None,
            Payload::ProcSensorStatus(ProcSensorStatus {
                phase,
                programs,
                kernel_release: "6.18.54".into(),
                btf_ok: true,
                session_cgroup_id: 4242,
                pid: 77,
                reason: None,
            }),
        )
    }

    fn heartbeat(&mut self, at_ms: u64) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            None,
            Payload::ProcHeartbeat(ProcHeartbeat {
                uptime_ns: at_ms * MS,
                events_emitted: 0,
                ringbuf_drops: 0,
                frames_sent: 0,
            }),
        )
    }

    fn exec(&mut self, at_ms: u64, pid: u32, ppid: u32, start_ns: u64, argv: &[&str]) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            Some((pid, 1000, 1000)),
            Payload::ProcExec(ProcExec {
                tid: pid,
                tgid: pid,
                ppid,
                uid: 1000,
                gid: 1000,
                filename: format!("/usr/bin/{}", argv[0]),
                argv: argv.iter().map(|a| (*a).to_owned()).collect(),
                argv_truncated: false,
                start_ns,
                cgroup_id: 4242,
            }),
        )
    }

    fn fork(&mut self, at_ms: u64, parent: u32, child: u32, start_ns: u64, thread: bool) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            Some((parent, 1000, 1000)),
            Payload::ProcFork(ProcFork {
                parent_tid: parent,
                parent_tgid: parent,
                child_pid: child,
                child_start_ns: start_ns,
                uid: 1000,
                gid: 1000,
                thread,
            }),
        )
    }

    fn exit(&mut self, at_ms: u64, pid: u32, start_ns: u64) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            Some((pid, 1000, 1000)),
            Payload::ProcExit(ProcExit {
                tid: pid,
                tgid: pid,
                exit_code: 0,
                group_dead: true,
                start_ns,
            }),
        )
    }

    fn tcp_connect(&mut self, at_ms: u64, pid: u32, src_port: u16, dst: &str) -> Step {
        let dst: SocketAddrV4 = dst.parse().unwrap();
        self.rec(
            at_ms,
            Ring::Guest,
            Some((pid, 1000, 1000)),
            Payload::ProcTcpConnect(ProcTcpConnect {
                tid: pid,
                tgid: pid,
                src: IpAddr::V4("10.0.2.15".parse().unwrap()),
                src_port,
                dst: IpAddr::V4(*dst.ip()),
                dst_port: dst.port(),
            }),
        )
    }

    fn lsm_deny(&mut self, at_ms: u64, pid: u32, hook: &str, detail: i64) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            Some((pid, 1000, 1000)),
            Payload::ProcLsmDeny(ProcLsmDeny {
                tid: pid,
                tgid: pid,
                hook: hook.into(),
                detail,
            }),
        )
    }

    fn memfd(&mut self, at_ms: u64, pid: u32, name: &str) -> Step {
        self.rec(
            at_ms,
            Ring::Guest,
            Some((pid, 1000, 1000)),
            Payload::ProcMemfd(ProcMemfd {
                tid: pid,
                tgid: pid,
                name: name.into(),
                flags: 1,
            }),
        )
    }

    fn sync(&mut self, at_ms: u64, rtt_ns: u64) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            None,
            Payload::ClockSync(ClockSync {
                method: "vsock_rtt".into(),
                guest_mono_ns: at_ms * MS,
                host_mono_ns: at_ms * MS + 1_000,
                offset_ns: 1_000,
                rtt_ns,
            }),
        )
    }

    fn vmm_stop(&mut self, at_ms: u64) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            None,
            Payload::VmmStop(VmmStop {
                reason: "guest_reset".into(),
                exit_code: Some(0),
                console_dropped_bytes: 0,
                stdin_dropped_bytes: 0,
            }),
        )
    }

    fn fs_create(&mut self, at_ms: u64, tid: u32, path: &str) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            Some((tid, 1000, 1000)),
            Payload::FsCreate(FsCreate {
                mount: "workspace".into(),
                path: path.into(),
                path_b64: None,
                fh: 1,
                mode: 0o644,
                flags: 0o101,
                result: OpResult::ok(),
            }),
        )
    }

    fn fs_unlink(&mut self, at_ms: u64, tid: u32, path: &str) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            Some((tid, 1000, 1000)),
            Payload::FsUnlink(FsPathOp {
                mount: "root".into(),
                path: path.into(),
                path_b64: None,
                result: OpResult::ok(),
            }),
        )
    }

    fn dns(&mut self, at_ms: u64, qname: &str, answers: &[&str], verdict: Verdict) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            None,
            Payload::NetDns(NetDns {
                txid: 1,
                qname: qname.into(),
                qtype: 1,
                rcode: 0,
                answers: answers.iter().map(|a| (*a).to_owned()).collect(),
                verdict,
                rule: None,
            }),
        )
    }

    fn connect(
        &mut self,
        at_ms: u64,
        flow: u64,
        src_port: u16,
        dst: &str,
        names: &[&str],
        verdict: Verdict,
    ) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            None,
            Payload::NetConnect(NetConnect {
                flow,
                proto: "tcp".into(),
                src: format!("10.0.2.15:{src_port}").parse().unwrap(),
                dst: dst.parse().unwrap(),
                names: names.iter().map(|n| (*n).to_owned()).collect(),
                verdict,
                rule: None,
            }),
        )
    }

    fn tls(&mut self, at_ms: u64, flow: u64, sni: &str) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            None,
            Payload::NetTls(NetTls {
                flow,
                kind: "client_hello".into(),
                sni: Some(sni.into()),
                alpn: vec!["h2".into()],
                verdict: Verdict::Allow,
            }),
        )
    }

    fn vsock_denied(&mut self, at_ms: u64, port: u32) -> Step {
        self.rec(
            at_ms,
            Ring::Host,
            None,
            Payload::VsockConnect(VsockConnect {
                port,
                dir: "guest".into(),
                peer: "guest:5000".into(),
                src_port: 5000,
                verdict: Verdict::Deny,
                reason: Some("not_allowed".into()),
            }),
        )
    }
}

/// Runs `steps` through a fresh reconciler and returns its findings.
fn run(sensor_expected: bool, steps: Vec<Step>) -> Vec<Finding> {
    let clock = Arc::new(ManualClock::new(T0));
    let mut reconciler = Reconciler::new(ReconcileConfig {
        sensor_expected,
        clock: clock.clone(),
    });
    let mut findings = Vec::new();
    for step in steps {
        match step {
            Step::Record(record) => {
                clock.set(record.ts_host_ns);
                findings.extend(reconciler.observe(&record));
            }
            Step::Tick(at_ms) => {
                clock.set(T0 + at_ms * MS);
                findings.extend(reconciler.on_tick(T0 + at_ms * MS));
            }
        }
    }
    findings
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{name}.jsonl"))
}

/// Compares the findings with the scenario's fixture, blessing it when asked.
fn check(name: &str, findings: &[Finding]) {
    let mut text = String::new();
    for finding in findings {
        text.push_str(&serde_json::to_string(finding).unwrap());
        text.push('\n');
    }
    let path = fixture_path(name);
    if std::env::var_os("BOXCAR_BLESS").is_some() {
        fs::write(&path, &text).unwrap();
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; bless with BOXCAR_BLESS=1", path.display()));
    assert!(
        text == expected,
        "{name}: the findings differ from {}; after a deliberate change rerun with \
         BOXCAR_BLESS=1\n--- fixture\n{expected}--- findings\n{text}",
        path.display()
    );
}

/// A session with the sensor attached and a heartbeat, from `at_ms`.
fn attached(log: &mut Log, steps: &mut Vec<Step>) {
    steps.push(log.session_start(0, 100));
    steps.push(log.sensor_status(100, &PROGRAMS));
    steps.push(log.heartbeat(1000));
}

#[test]
fn curl_no_dns() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(2000, 212, 100, 10, &["wget", "http://93.184.216.34/"]));
    steps.push(log.tcp_connect(2050, 212, 40000, "93.184.216.34:80"));
    steps.push(log.connect(2060, 1, 40000, "93.184.216.34:80", &[], Verdict::Allow));
    for at in [3000, 4000, 5000] {
        steps.push(log.heartbeat(at));
    }
    steps.push(Step::Tick(5000));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "connect_without_dns");
    assert_eq!(findings[0].score, 60);
    assert!(
        findings[0].summary.starts_with("wget (pid 212)"),
        "{}",
        findings[0].summary
    );
    // Evidence: the exec, the sensor's connect and the flow, oldest first.
    let seqs: Vec<u64> = findings[0].evidence.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, [4, 5, 6]);
    check("curl_no_dns", &findings);
}
#[test]
fn an_allowed_download_with_a_name_is_quiet() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(2000, 212, 100, 10, &["wget", "http://example.com/"]));
    steps.push(log.dns(2010, "example.com", &["93.184.216.34"], Verdict::Allow));
    steps.push(log.tcp_connect(2050, 212, 40000, "93.184.216.34:80"));
    steps.push(log.connect(
        2060,
        1,
        40000,
        "93.184.216.34:80",
        &["example.com"],
        Verdict::Allow,
    ));
    steps.push(log.exit(2500, 212, 10));
    steps.push(Step::Tick(6000));
    let findings = run(true, steps);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn history_wipe() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(1500, 300, 100, 20, &["sh", "-c", "rm ~/.ash_history"]));
    steps.push(log.fs_unlink(1600, 300, "/home/agent/.ash_history"));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "indicator_removal");
    assert_eq!(findings[0].score, 90);
    let seqs: Vec<u64> = findings[0].evidence.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, [4, 5]);
    check("history_wipe", &findings);
}

#[test]
fn memfd_exec() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(1500, 400, 100, 30, &["python3", "stage.py"]));
    steps.push(log.memfd(1600, 400, "stage"));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "memfd_create");
    assert_eq!(findings[0].score, 75);
    check("memfd_exec", &findings);
}

#[test]
fn sensor_gap() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.heartbeat(2000));
    steps.push(log.exec(2100, 500, 100, 40, &["sh"]));
    // The heartbeats stop; the session keeps acting.
    steps.push(log.fs_create(4500, 500, "notes.txt"));
    for at in [3000, 4000, 5000, 6000, 7000] {
        steps.push(Step::Tick(at));
    }
    // A heartbeat ends the silence; a second gap is a second finding.
    steps.push(log.heartbeat(8000));
    steps.push(log.fs_create(9000, 500, "more.txt"));
    for at in [10000, 11000, 12000, 13000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert_eq!(findings.len(), 2, "{findings:?}");
    for finding in &findings {
        assert_eq!(finding.rule, "heartbeat_lost");
        assert_eq!(finding.score, 85);
    }
    check("sensor_gap", &findings);
}

#[test]
fn sensor_never_attached() {
    let mut log = Log::new();
    let mut steps = vec![log.session_start(0, 100)];
    for at in [1000, 2000, 3000, 4000, 5000, 6000, 7000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "never_attached");
    check("sensor_never_attached", &findings);
}

#[test]
fn no_sensor_expected_no_silence() {
    let mut log = Log::new();
    let mut steps = vec![log.session_start(0, 100)];
    steps.push(log.fs_create(500, 100, "a.txt"));
    for at in [1000, 3000, 6000, 9000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(false, steps);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn sni_mismatch() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(1500, 600, 100, 50, &["curl", "https://example.com/"]));
    steps.push(log.dns(1600, "example.com", &["93.184.216.34"], Verdict::Allow));
    steps.push(log.dns(1650, "cdn.example", &["203.0.113.9"], Verdict::Allow));
    steps.push(log.tcp_connect(1700, 600, 40001, "203.0.113.9:443"));
    steps.push(log.connect(
        1710,
        1,
        40001,
        "203.0.113.9:443",
        &["cdn.example"],
        Verdict::Allow,
    ));
    steps.push(log.tls(1800, 1, "example.com"));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "sni_mismatch");
    assert_eq!(findings[0].score, 65);
    check("sni_mismatch", &findings);
}

#[test]
fn dns_entropy_spike() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    for i in 0..25u64 {
        let at = 2000 + i * 100;
        if at % 1000 == 0 {
            steps.push(log.heartbeat(at));
        }
        let label: String = (0..24)
            .map(|k| b"0123456789abcdef"[((i * 7 + k * 13) % 16) as usize] as char)
            .collect();
        steps.push(log.dns(at, &format!("{label}.exfil.example"), &[], Verdict::Allow));
    }
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "one finding, then quiet: {findings:?}");
    assert_eq!(findings[0].rule, "dns_entropy");
    assert_eq!(findings[0].score, 70);
    check("dns_entropy_spike", &findings);
}
#[test]
fn dns_rate_spike() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    for i in 0..60u64 {
        let at = 2000 + i * 50;
        if at % 1000 == 0 {
            steps.push(log.heartbeat(at));
        }
        steps.push(log.dns(at, &format!("host{i}.example"), &[], Verdict::Allow));
    }
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "dns_rate");
    check("dns_rate_spike", &findings);
}
#[test]
fn privilege_probe() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(1500, 700, 100, 60, &["probe"]));
    steps.push(log.lsm_deny(1600, 700, "bpf", 0));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "lsm_deny");
    assert_eq!(findings[0].score, 80);
    check("privilege_probe", &findings);
}

#[test]
fn policy_denial() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.dns(1500, "blocked.example", &[], Verdict::Deny));
    steps.push(log.connect(1600, 1, 40002, "198.51.100.7:443", &[], Verdict::Deny));
    steps.push(log.vsock_denied(1700, 5000));
    let findings = run(true, steps);
    assert_eq!(
        findings.len(),
        4,
        "the denied connect is also one no DNS named: {findings:?}"
    );
    assert_eq!(
        findings
            .iter()
            .filter(|f| f.rule == "policy_denial")
            .count(),
        3
    );
    assert!(findings
        .iter()
        .all(|f| f.rule != "policy_denial" || f.score == 40));
    check("policy_denial", &findings);
}

#[test]
fn unattributed_effect() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.fs_create(1500, 999, "mystery.txt"));
    steps.push(Step::Tick(2000));
    steps.push(Step::Tick(3000));
    steps.push(Step::Tick(4000));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, "no_process");
    assert_eq!(findings[0].score, 60);
    assert!(!findings[0].low_confidence);
    check("unattributed_effect", &findings);
}

#[test]
fn late_exec_is_attributed() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.fs_create(1500, 800, "early.txt"));
    steps.push(log.exec(1800, 800, 100, 70, &["touch", "early.txt"]));
    for at in [2000, 3000, 4000, 5000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn thread_effects_are_attributed() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(1500, 900, 100, 80, &["node", "build.js"]));
    steps.push(log.fork(1600, 900, 901, 81, true));
    steps.push(log.fs_create(1700, 901, "dist/app.js"));
    for at in [2000, 3000, 4000, 5000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn degraded_sensor_skips_hook_rules() {
    let mut log = Log::new();
    let mut steps = vec![log.session_start(0, 100)];
    let without_exec: Vec<&str> = PROGRAMS
        .iter()
        .copied()
        .filter(|p| *p != "sched_process_exec")
        .collect();
    steps.push(log.sensor_status(100, &without_exec));
    steps.push(log.heartbeat(1000));
    steps.push(log.fs_create(1500, 999, "mystery.txt"));
    steps.push(log.memfd(1600, 999, "stage"));
    for at in [2000, 3000, 4000, 5000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert_eq!(
        findings.len(),
        1,
        "no join rule without exec, but the memfd stands: {findings:?}"
    );
    assert_eq!(findings[0].rule, "memfd_create");
    check("degraded_sensor_skips_hook_rules", &findings);
}

#[test]
fn low_confidence_after_a_slow_sync() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.sync(1100, 5 * MS));
    steps.push(log.fs_create(1500, 999, "mystery.txt"));
    for at in [2000, 3000, 4000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].low_confidence);
    assert_eq!(findings[0].score, 40);
    check("low_confidence_after_a_slow_sync", &findings);
}

#[test]
fn the_stop_record_ends_the_timers() {
    let mut log = Log::new();
    let mut steps = vec![log.session_start(0, 100)];
    steps.push(log.vmm_stop(500));
    for at in [1000, 6000, 7000] {
        steps.push(Step::Tick(at));
    }
    let findings = run(true, steps);
    assert!(
        findings.is_empty(),
        "no silence finding after the stop: {findings:?}"
    );
}

#[test]
fn evidence_is_ordered_and_complete() {
    let mut log = Log::new();
    let mut steps = Vec::new();
    attached(&mut log, &mut steps);
    steps.push(log.exec(1500, 300, 100, 20, &["sh"]));
    steps.push(log.fs_unlink(1600, 300, "/var/log/messages"));
    let findings = run(true, steps);
    assert_eq!(findings.len(), 1);
    let evidence = &findings[0].evidence;
    assert_eq!(evidence.len(), 2);
    assert!(evidence.windows(2).all(|w| w[0].seq < w[1].seq));
    assert_eq!(evidence[0].ring, Ring::Guest, "the exec");
    assert_eq!(evidence[1].ring, Ring::Host, "the unlink");
}
