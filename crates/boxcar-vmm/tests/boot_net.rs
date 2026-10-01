// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The first guest download: the console init with the Alpine rootfs and a
//! network card whose policy is `allow example.com` (deny by default). The
//! session shows eth0's address, fetches http://example.com with busybox
//! wget, fails to resolve blocked.example, and says `DONE`. The console must
//! show all four, and the session log must hold the DNS queries and their
//! verdicts, the allowed connect to port 80, and the gate's reading of its
//! `Host`.
//!
//! The kernel configures eth0 itself from `ip=` (`off`: no DHCP), so the
//! log has no `net.dhcp`, and none is asked for.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible; when `BOXCAR_TEST_NET=0`; and when this host cannot open
//! a TCP connection to example.com:80 within 3 s, since the guest's would
//! fail too. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use std::{env, fs};

use arc_swap::ArcSwap;
use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_net::{NetConfig, Policy};
use boxcar_proto::{guestcmd, Record, SessionId};
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::vmm::{ConsoleOut, StopReason, VmConfig, VmExit, Vmm};

const TEST: &str = "boot_net";
/// Boot, two downloads and a failed lookup.
const LIMIT: Duration = Duration::from_secs(60);
/// How long the host may take to reach example.com before the test skips.
const REACH_LIMIT: Duration = Duration::from_secs(3);

/// What the session runs.
const SESSION: [&str; 3] = [
    "/bin/sh",
    "-c",
    "ip -4 addr show eth0; wget -qO- http://example.com | head -c 100; \
     wget -qO- https://blocked.example 2>&1; echo DONE",
];

/// The artifact `var` names, or `None` when it is unset.
fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The kernel, initramfs and rootfs, or `None` after printing why the test
/// skips.
fn guest_or_skip() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let (Some(kernel), Some(initramfs), Some(rootfs)) = (
        artifact("BOXCAR_TEST_KERNEL"),
        artifact("BOXCAR_TEST_INITRAMFS"),
        artifact("BOXCAR_TEST_ROOTFS"),
    ) else {
        eprintln!(
            "skipping {TEST}: BOXCAR_TEST_KERNEL, BOXCAR_TEST_INITRAMFS and \
             BOXCAR_TEST_ROOTFS must all be set"
        );
        return None;
    };
    if let Err(reason) = kvm_available() {
        eprintln!("skipping {TEST}: {reason}");
        return None;
    }
    if env::var_os("BOXCAR_TEST_NET").is_some_and(|value| value == "0") {
        eprintln!("skipping {TEST}: BOXCAR_TEST_NET=0");
        return None;
    }
    if let Err(reason) = example_com_reachable() {
        eprintln!("skipping {TEST}: {reason}");
        return None;
    }
    Some((kernel, initramfs, rootfs))
}

/// Whether this host opens a TCP connection to example.com:80 (IPv4, as
/// the guest's network is) within [`REACH_LIMIT`].
fn example_com_reachable() -> Result<(), String> {
    let addr = ("example.com", 80)
        .to_socket_addrs()
        .map_err(|error| format!("this host cannot resolve example.com: {error}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or("example.com has no IPv4 address from this host")?;
    TcpStream::connect_timeout(&addr, REACH_LIMIT)
        .map(drop)
        .map_err(|error| format!("this host cannot reach {addr} within {REACH_LIMIT:?}: {error}"))
}

fn share(tag: &str, host_dir: PathBuf, guest_path: &str, cache: CachePolicyKind) -> FsShareConfig {
    FsShareConfig {
        tag: tag.into(),
        host_dir,
        guest_path: guest_path.into(),
        cache,
    }
}

/// The records of type `kind`.
fn of_kind<'a>(records: &'a [Record], kind: &str) -> Vec<&'a Record> {
    records.iter().filter(|r| r.kind == kind).collect()
}

#[test]
fn a_guest_downloads_what_the_policy_allows_and_resolves_nothing_else() {
    let Some((kernel, initramfs, rootfs)) = guest_or_skip() else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");

    // SAFETY: getuid and getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let argv = SESSION.map(String::from);
    let policy = Policy::parse(&["allow example.com"]).unwrap();
    let cfg = VmConfig {
        cmdline_extra: vec![
            "boxcar.mode=console".into(),
            format!("boxcar.uid={uid}"),
            format!("boxcar.gid={gid}"),
            format!("boxcar.cmd={}", guestcmd::encode(&argv)),
        ],
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        net: Some(NetConfig::from_host()),
        policy: Arc::new(ArcSwap::from_pointee(policy)),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();

    // A watchdog stops a guest that neither resets nor shuts down.
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}\n{output}");
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?}; console:\n{output}"
    );
    // The guest's tty ends lines with CRLF: match substrings.
    assert!(
        output.contains("inet 10.0.2.15/24"),
        "eth0 has no address:\n{output}"
    );
    let lower = output.to_lowercase();
    assert!(
        lower.contains("<!doctype html>") || lower.contains("example domain"),
        "nothing from example.com:\n{output}"
    );
    assert!(
        output
            .lines()
            .any(|line| line.contains("blocked.example") && line.contains("bad address")),
        "no failure for blocked.example:\n{output}"
    );
    assert!(output.contains("DONE"), "no DONE:\n{output}");
    assert!(
        output.contains("boxcar: session exited 0"),
        "no exit line:\n{output}"
    );

    let report = verify_session(&session_dir).unwrap();
    eprintln!("{TEST}: {report:?}");
    let records: Vec<Record> = LogReader::open(&session_dir)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .collect();
    for record in records.iter().filter(|r| r.kind.starts_with("net.")) {
        eprintln!("{TEST}: {} {}", record.kind, record.data);
    }

    let dns = of_kind(&records, "net.dns");
    assert!(
        dns.iter()
            .any(|r| r.data["qname"] == "example.com" && r.data["verdict"] == "allow"),
        "no allowed net.dns for example.com: {dns:?}"
    );
    assert!(
        dns.iter().any(|r| r.data["qname"] == "blocked.example"
            && r.data["verdict"] == "deny"
            && r.data["rcode"] == 3),
        "no NXDOMAIN for blocked.example: {dns:?}"
    );

    let connects = of_kind(&records, "net.connect");
    let http = connects
        .iter()
        .find(|r| {
            r.data["verdict"] == "allow"
                && r.data["dst"]
                    .as_str()
                    .is_some_and(|dst| dst.ends_with(":80"))
        })
        .unwrap_or_else(|| panic!("no allowed connect to port 80: {connects:?}"));
    assert_eq!(http.data["rule"], "allow example.com", "{http:?}");
    let names = http.data["names"].as_array().unwrap();
    assert!(names.iter().any(|n| n == "example.com"), "{http:?}");

    // The domain rule let the connect through to the gate, which read the
    // request's Host and let it on.
    let gate = of_kind(&records, "net.tls")
        .into_iter()
        .find(|r| r.data["flow"] == http.data["flow"])
        .unwrap_or_else(|| panic!("no net.tls for the connect {http:?}"));
    assert_eq!(gate.data["kind"], "http", "{gate:?}");
    assert_eq!(gate.data["sni"], "example.com", "{gate:?}");
    assert_eq!(gate.data["verdict"], "allow", "{gate:?}");
    assert!(
        !connects
            .iter()
            .any(|r| r.data["names"].to_string().contains("blocked.example")),
        "blocked.example was never resolved, so never connected to: {connects:?}"
    );
}
