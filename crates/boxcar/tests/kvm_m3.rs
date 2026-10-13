// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The M3 end-to-end tests: the `boxcar` binary runs real VMs on KVM with
//! the sensor in the initramfs and the reconciler beside the log, and the
//! tests read what is left behind: ring 1 beside ring 0, and the findings
//! that join them.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible (`cargo xtask test-kvm m3` checks and sets them). The
//! tests that reach the network also skip when `BOXCAR_TEST_NET=0`, and
//! when this host cannot reach example.com.

#![cfg(feature = "kvm-tests")]

mod kvm_harness;

use std::thread;
use std::time::Duration;

use boxcar_proto::{Record, Ring};
use kvm_harness::{
    boxcar, boxcar_run, example_com_ipv4, guest_or_skip, networked_guest_or_skip, of_kind, start,
    text, Scratch,
};
use serde_json::Value;

/// The findings among `records`, with their rule names.
fn findings(records: &[Record]) -> Vec<&Record> {
    of_kind(records, "finding")
}

fn rules(records: &[Record]) -> Vec<String> {
    findings(records)
        .iter()
        .map(|r| r.data["rule"].as_str().unwrap_or("?").to_owned())
        .collect()
}

/// (a) A download to an address the policy denies, by address so no DNS
/// names it: ring 0 records the denied connection, ring 1 the `wget` and
/// its connect, and the reconciler joins them into findings whose evidence
/// spans both rings. The log verifies.
#[test]
fn a_download_to_a_blocked_address_is_a_joined_finding() {
    let Some(guest) =
        networked_guest_or_skip("a_download_to_a_blocked_address_is_a_joined_finding")
    else {
        return;
    };
    let Some(ip) = example_com_ipv4() else {
        eprintln!("skipping: example.com has no IPv4 address from this host");
        return;
    };
    let scratch = Scratch::new();
    let url = format!("http://{ip}/");
    let run = boxcar_run(
        &guest,
        &scratch,
        &[],
        &[
            "/bin/sh",
            "-c",
            &format!("wget -qO- {url}; echo DONE; sleep 1; exit 0"),
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();

    let connects = of_kind(&records, "net.connect");
    let denied = connects
        .iter()
        .find(|r| r.data["verdict"] == "deny" && r.data["dst"] == format!("{ip}:80"))
        .unwrap_or_else(|| {
            panic!(
                "no denied connection to {ip}:80 in {connects:?}\n{}",
                run.describe()
            )
        });
    let execs = of_kind(&records, "proc.exec");
    let wget = execs
        .iter()
        .find(|r| r.data["argv"][0] == "wget")
        .unwrap_or_else(|| panic!("no exec of wget in {execs:?}\n{}", run.describe()));
    assert!(
        of_kind(&records, "proc.connect_attempt")
            .iter()
            .any(|r| r.data["dst"] == ip.to_string() && r.data["dst_port"] == 80),
        "no connect attempt to {ip}\n{}",
        run.describe()
    );

    let rules = rules(&records);
    assert!(
        rules.contains(&"policy_denial".to_owned()),
        "{rules:?}\n{}",
        run.describe()
    );
    let anomaly = findings(&records)
        .into_iter()
        .find(|r| r.data["rule"] == "connect_without_dns")
        .unwrap_or_else(|| {
            panic!(
                "no connect_without_dns finding in {rules:?}\n{}",
                run.describe()
            )
        });
    assert_eq!(anomaly.data["category"], "network_anomaly");
    assert_eq!(anomaly.data["score"], 60, "{anomaly:?}");
    assert!(
        anomaly.data["summary"]
            .as_str()
            .unwrap()
            .starts_with("wget (pid "),
        "the finding names the process: {anomaly:?}"
    );
    let evidence = anomaly.data["evidence"].as_array().unwrap();
    let seqs: Vec<u64> = evidence
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert!(
        seqs.contains(&wget.seq),
        "the exec is evidence: {seqs:?} vs {}",
        wget.seq
    );
    assert!(
        seqs.contains(&denied.seq),
        "the connection is evidence: {seqs:?} vs {}",
        denied.seq
    );
    let rings: Vec<u64> = evidence
        .iter()
        .map(|e| e["ring"].as_u64().unwrap())
        .collect();
    assert!(
        rings.contains(&0) && rings.contains(&1),
        "both rings: {rings:?}"
    );
    for finding in findings(&records) {
        assert_eq!(finding.ring, Ring::Host);
        assert_eq!(finding.data["low_confidence"], false, "{finding:?}");
    }
}

/// (b) An allowed download: the flow joins the process (the sensor's
/// connect carries the same 4-tuple as the stack's), and nothing is found.
#[test]
fn an_allowed_download_joins_its_process_and_finds_nothing() {
    let Some(guest) =
        networked_guest_or_skip("an_allowed_download_joins_its_process_and_finds_nothing")
    else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &["--allow", "example.com"],
        &[
            "/bin/sh",
            "-c",
            "wget -qO- http://example.com > /dev/null; sleep 1; exit 0",
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();
    let allowed: Vec<_> = of_kind(&records, "net.connect")
        .into_iter()
        .filter(|r| r.data["verdict"] == "allow")
        .collect();
    assert!(!allowed.is_empty(), "{}", run.describe());
    let tcp = of_kind(&records, "proc.tcp_connect");
    for connect in &allowed {
        let src_port = connect.data["src"]
            .as_str()
            .and_then(|s| s.rsplit(':').next())
            .and_then(|p| p.parse::<u64>().ok())
            .unwrap();
        let dst = connect.data["dst"].as_str().unwrap();
        let (dst_ip, dst_port) = dst.rsplit_once(':').unwrap();
        assert!(
            tcp.iter().any(|r| {
                r.data["src_port"] == src_port
                    && r.data["dst"] == dst_ip
                    && r.data["dst_port"] == dst_port.parse::<u64>().unwrap()
            }),
            "no proc.tcp_connect with the 4-tuple of {connect:?} among {tcp:?}\n{}",
            run.describe()
        );
    }
    assert!(
        findings(&records).is_empty(),
        "findings: {:?}\n{}",
        rules(&records),
        run.describe()
    );
}

/// (c) Removing a shell history is an `indicator_removal` finding, with the
/// unlink and the shell's exec as evidence.
#[test]
fn a_history_wipe_is_a_finding() {
    let Some(guest) = guest_or_skip("a_history_wipe_is_a_finding") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &["--no-net"],
        &[
            "/bin/sh",
            "-c",
            "echo hi > /workspace/.ash_history; rm /workspace/.ash_history; sleep 1; exit 0",
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();
    let wipes: Vec<_> = findings(&records)
        .into_iter()
        .filter(|r| r.data["rule"] == "indicator_removal")
        .collect();
    assert_eq!(wipes.len(), 1, "{:?}\n{}", rules(&records), run.describe());
    let wipe = wipes[0];
    assert_eq!(wipe.data["category"], "indicator_removal");
    assert_eq!(wipe.data["score"], 90);
    assert!(
        wipe.data["summary"]
            .as_str()
            .unwrap()
            .contains("a shell history"),
        "{wipe:?}"
    );
    let unlink = of_kind(&records, "fs.unlink")
        .into_iter()
        .find(|r| r.data["path"].as_str().unwrap().ends_with(".ash_history"))
        .unwrap_or_else(|| panic!("no unlink in the log\n{}", run.describe()));
    let seqs: Vec<u64> = wipe.data["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert!(
        seqs.contains(&unlink.seq),
        "{seqs:?} vs unlink {}",
        unlink.seq
    );
    assert!(
        seqs.len() >= 2,
        "the shell's exec is evidence too: {seqs:?}"
    );
}

/// (d) `boxcar events --type finding --min-score 70` streams the findings
/// that score, and only those, while the session runs.
#[test]
fn events_streams_findings_by_min_score() {
    let Some(guest) = networked_guest_or_skip("events_streams_findings_by_min_score") else {
        return;
    };
    let Some(ip) = example_com_ipv4() else {
        eprintln!("skipping: example.com has no IPv4 address from this host");
        return;
    };
    let scratch = Scratch::new();
    let script = format!(
        "wget -qO- http://{ip}/ > /dev/null 2>&1; echo hi > /workspace/.ash_history; \
         rm /workspace/.ash_history; echo DONE; sleep 4"
    );
    let mut running = start(&guest, &scratch, &[], &["/bin/sh", "-c", &script]);
    let control = running.control();
    running.until("the session's work", |run| run.stdout().contains("DONE"));
    let events = boxcar(
        &["events", "--type", "finding", "--min-score", "70"],
        &control,
    );
    assert!(events.status.success(), "{}", text(&events.stderr));
    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());

    let lines: Vec<Record> = text(&events.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}")))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "one finding scores 70 or more: {lines:?}\n{}",
        run.describe()
    );
    assert_eq!(lines[0].kind, "finding");
    assert_eq!(lines[0].data["rule"], "indicator_removal");
    // The lower ones are in the log, not in the stream.
    let all = rules(&run.records());
    assert!(all.contains(&"policy_denial".to_owned()), "{all:?}");
    assert!(all.contains(&"connect_without_dns".to_owned()), "{all:?}");
}

/// (e) `boxcar status --json` reports the sensor: attached, with heartbeats
/// that keep coming.
#[test]
fn status_reports_the_sensor() {
    let Some(guest) = guest_or_skip("status_reports_the_sensor") else {
        return;
    };
    let scratch = Scratch::new();
    let mut running = start(&guest, &scratch, &["--no-net"], &["sleep", "6"]);
    let control = running.control();
    let sensor = |control: &std::path::Path| -> Value {
        let status = boxcar(&["status", "--json"], control);
        assert!(status.status.success(), "{}", text(&status.stderr));
        let json: Value = serde_json::from_slice(&status.stdout).unwrap();
        json["sensor"].clone()
    };
    let mut first = sensor(&control);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while first["state"] != "attached" && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(250));
        first = sensor(&control);
    }
    assert_eq!(first["state"], "attached", "{first}");
    thread::sleep(Duration::from_millis(2200));
    let second = sensor(&control);
    assert_eq!(second["state"], "attached", "{second}");
    assert!(
        second["heartbeats"].as_u64().unwrap() > first["heartbeats"].as_u64().unwrap(),
        "{first} then {second}"
    );
    assert!(second["last_heartbeat_ns"].as_u64().is_some(), "{second}");
    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
}
