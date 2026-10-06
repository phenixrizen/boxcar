// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The M4 end-to-end tests: the `boxcar` binary runs real VMs on KVM whose
//! policy inspects a destination, and the tests read what the gate left in
//! the log: the flow's TLS ended in boxcar, the real host reached with
//! boxcar's own TLS, the plaintext relayed, and what was recorded of it.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible (`cargo xtask test-kvm m4` checks and sets them). The
//! tests that reach the network also skip when `BOXCAR_TEST_NET=0`, and
//! when this host cannot reach example.com.

#![cfg(feature = "kvm-tests")]

mod kvm_harness;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boxcar_net::policy::PRIVATE_RANGES;
use boxcar_proto::Record;
use kvm_harness::{boxcar_run, guest_or_skip, networked_guest_or_skip, of_kind, Scratch};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::ServerConfig;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The one record of `kind` for `flow`.
fn for_flow<'a>(records: &'a [Record], kind: &str, flow: u64) -> Option<&'a Record> {
    of_kind(records, kind)
        .into_iter()
        .find(|r| r.data["flow"] == flow)
}

/// An address of this host the guest can reach: not the loopback, which
/// is the guest's own, but the one the host sends out through (found with
/// a UDP socket that sends nothing). `None` when the host has none.
fn host_address() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    match probe.local_addr().ok()? {
        SocketAddr::V4(addr) if !addr.ip().is_loopback() && !addr.ip().is_unspecified() => {
            Some(*addr.ip())
        }
        _ => None,
    }
}

/// The rules that let the guest reach `addr:port` on this host: the
/// private range the address is in, named exactly, which lifts its
/// built-in denial, and the address itself, which lifts the host-local
/// one.
fn host_rules(addr: Ipv4Addr, port: u16) -> Vec<String> {
    let mut rules = vec![format!("{addr}/32:{port}")];
    if let Some(range) = PRIVATE_RANGES.iter().find(|range| range.contains(addr)) {
        rules.push(format!("{range}:{port}"));
    }
    rules
}

/// A TLS server on `addr` with a self-signed certificate for it, which no
/// trust store vouches for. Its thread takes one connection and ends with
/// it.
fn untrusted_upstream(addr: Ipv4Addr) -> (SocketAddrV4, thread::JoinHandle<()>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec![addr.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind(SocketAddrV4::new(addr, 0)).unwrap();
    let SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
        panic!("not IPv4");
    };
    let thread = thread::spawn(move || {
        // The gate's upstream leg connects, then gives up on the
        // certificate; whatever it sends is read and the connection ends.
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        let mut buf = [0; 1024];
        let _ = tls.read(&mut buf);
        let _ = tls.flush();
    });
    (addr, thread)
}

/// An inspected download: the guest's TLS to example.com ends in boxcar,
/// which reaches example.com with its own TLS, relays the page, and
/// records the flow as decided (`net.tls{inspect:true}`), inspected
/// (`net.inspect{ok}`) and closed (`fin`). The guest, trusting the session
/// CA, sees the page.
#[test]
fn an_inspected_download_is_relayed_and_recorded() {
    let Some(guest) = networked_guest_or_skip("an_inspected_download_is_relayed_and_recorded")
    else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &["--allow", "example.com:443", "--inspect", "example.com:443"],
        &[
            "/bin/sh",
            "-c",
            "wget -q -O - https://example.com/ | grep -c -i '<html' ; sleep 1",
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(
        run.stdout.lines().any(|line| line.trim() == "1"),
        "the page did not reach the guest:\n{}",
        run.describe()
    );
    let records = run.records();
    let tls: Vec<_> = of_kind(&records, "net.tls")
        .into_iter()
        .filter(|r| r.data["sni"] == "example.com")
        .collect();
    assert_eq!(tls.len(), 1, "{tls:?}\n{}", run.describe());
    assert_eq!(tls[0].data["verdict"], "allow");
    assert_eq!(tls[0].data["inspect"], true, "{:?}", tls[0]);
    let flow = tls[0].data["flow"].as_u64().unwrap();
    let inspect = for_flow(&records, "net.inspect", flow)
        .unwrap_or_else(|| panic!("no net.inspect for flow {flow}\n{}", run.describe()));
    assert_eq!(inspect.data["result"], "ok", "{inspect:?}");
    assert_eq!(inspect.data["sni"], "example.com");
    assert_eq!(inspect.data["rule"], "inspect example.com:443");
    assert!(
        inspect.data["version"] == "1.3" || inspect.data["version"] == "1.2",
        "{inspect:?}"
    );
    let close = for_flow(&records, "net.close", flow)
        .unwrap_or_else(|| panic!("no net.close for flow {flow}\n{}", run.describe()));
    assert_eq!(close.data["reason"], "fin", "{close:?}");
    assert!(
        close.data["rx"].as_u64().unwrap() > 0 && close.data["tx"].as_u64().unwrap() > 0,
        "{close:?}"
    );
    // In order: decided, inspected, closed.
    assert!(tls[0].seq < inspect.seq && inspect.seq < close.seq);
    // The CA the guest was told to trust is on record.
    let start = of_kind(&records, "vmm.start");
    assert!(
        start[0].data["inspect_ca_sha256"]
            .as_str()
            .is_some_and(|h| h.len() == 64),
        "{:?}",
        start[0]
    );
}

/// An inspected connection to a host the trust store does not vouch for
/// fails closed: `net.inspect{upstream_untrusted}`, nothing relayed, the
/// guest's connection reset (`net.close{inspect}`), and the session goes
/// on.
#[test]
fn an_inspected_connection_to_an_untrusted_host_fails_closed() {
    let Some(guest) = guest_or_skip("an_inspected_connection_to_an_untrusted_host_fails_closed")
    else {
        return;
    };
    let Some(host) = host_address() else {
        eprintln!("skipping: this host has no address a guest could reach");
        return;
    };
    let (addr, upstream) = untrusted_upstream(host);
    let port = addr.port();
    let scratch = Scratch::new();
    let mut flags: Vec<String> = Vec::new();
    for rule in host_rules(host, port) {
        flags.push("--allow".to_owned());
        flags.push(rule);
    }
    flags.push("--inspect".to_owned());
    flags.push(format!("{host}:{port}"));
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let run = boxcar_run(
        &guest,
        &scratch,
        &flags,
        &[
            "/bin/sh",
            "-c",
            &format!(
                "if wget -q -O - https://{host}:{port}/ ; then echo FETCHED; else echo REFUSED; \
                 fi; sleep 1; exit 0"
            ),
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(
        run.stdout.contains("REFUSED"),
        "the guest fetched from an untrusted host:\n{}",
        run.describe()
    );
    let records = run.records();
    let inspects = of_kind(&records, "net.inspect");
    assert!(!inspects.is_empty(), "no net.inspect\n{}", run.describe());
    for inspect in &inspects {
        assert_eq!(
            inspect.data["result"],
            "upstream_untrusted",
            "{inspect:?}\n{}",
            run.describe()
        );
        // busybox's ssl_client names the address it was given as the
        // server name; a client may name nothing.
        assert!(
            inspect.data["sni"].is_null() || inspect.data["sni"] == host.to_string(),
            "{inspect:?}"
        );
        let flow = inspect.data["flow"].as_u64().unwrap();
        let close = for_flow(&records, "net.close", flow).unwrap();
        assert_eq!(close.data["reason"], "inspect", "{close:?}");
        assert_eq!(
            close.data["rx"], 0,
            "nothing came back to the guest: {close:?}"
        );
        let tls = for_flow(&records, "net.tls", flow).unwrap();
        assert_eq!(tls.data["inspect"], true, "{tls:?}");
        assert_eq!(tls.data["kind"], "tls");
    }
    drop(upstream);
}

/// Ring 1 sees the TLS of a runtime that exports OpenSSL's functions:
/// busybox's `ssl_client` loads `libssl.so.3`, which the sensor finds in
/// its maps and attaches its probes to, so the next download's writes and
/// reads are reported with their sizes. With the destination inspected,
/// the gate's `http.request` and a write of its size lie within 500 ms:
/// what names the process behind a request.
#[test]
fn a_tls_download_is_seen_by_both_rings() {
    let Some(guest) = networked_guest_or_skip("a_tls_download_is_seen_by_both_rings") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &["--allow", "example.com:443", "--inspect", "example.com:443"],
        &[
            "/bin/sh",
            "-c",
            "wget -q -O /dev/null https://example.com/; sleep 2; \
             wget -q -O /dev/null https://example.com/; sleep 1",
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();
    let attached = of_kind(&records, "proc.tls_attach");
    let libssl = attached
        .iter()
        .find(|r| {
            r.data["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("libssl.so.3"))
        })
        .unwrap_or_else(|| {
            panic!(
                "no proc.tls_attach for libssl.so.3 among {attached:?}\n{}",
                run.describe()
            )
        });
    assert_eq!(libssl.data["ok"], true, "{libssl:?}");
    assert!(libssl.subject.is_none(), "{libssl:?}");
    // The shell itself was tried (its exec's filename, as exec'd) and has
    // no such symbol.
    assert!(
        attached
            .iter()
            .any(|r| r.data["path"] == "/bin/sh" && r.data["ok"] == false),
        "{attached:?}"
    );
    let clients: Vec<_> = of_kind(&records, "proc.exec")
        .into_iter()
        .filter(|r| r.data["argv"][0] == "ssl_client")
        .collect();
    assert!(clients.len() >= 2, "{clients:?}\n{}", run.describe());
    let second = clients[clients.len() - 1];
    let tgid = second.data["tgid"].as_u64().unwrap();
    let io: Vec<_> = of_kind(&records, "proc.tls_io")
        .into_iter()
        .filter(|r| r.data["tgid"] == tgid)
        .collect();
    let writes: Vec<_> = io.iter().filter(|r| r.data["dir"] == "write").collect();
    let reads: Vec<_> = io.iter().filter(|r| r.data["dir"] == "read").collect();
    assert!(
        !writes.is_empty() && !reads.is_empty(),
        "writes {writes:?}, reads {reads:?}\n{}",
        run.describe()
    );
    for record in &io {
        assert!(record.data["bytes"].as_u64().unwrap() > 0, "{record:?}");
        assert_eq!(record.ring, boxcar_proto::Ring::Guest, "{record:?}");
        assert_eq!(
            record.subject.map(|s| s.pid as u64),
            Some(tgid),
            "{record:?}"
        );
    }
    // The second download's request, and the write that carried it.
    let requests = of_kind(&records, "http.request");
    let request = requests
        .last()
        .unwrap_or_else(|| panic!("no http.request\n{}", run.describe()));
    assert_eq!(request.data["method"], "GET", "{request:?}");
    let body = request.data["body_bytes"].as_u64().unwrap();
    let carried = writes.iter().any(|w| {
        w.ts_host_ns.abs_diff(request.ts_host_ns) <= 500 * 1_000_000
            && w.data["bytes"].as_u64().unwrap().abs_diff(body) <= body / 10 + 1024
    });
    assert!(
        carried,
        "no tls_io write within 500 ms and 1 KiB of {request:?}: {writes:?}\n{}",
        run.describe()
    );
}
