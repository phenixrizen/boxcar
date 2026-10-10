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

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boxcar_net::policy::PRIVATE_RANGES;
use boxcar_proto::Record;
use kvm_harness::{
    boxcar, boxcar_run, guest_or_skip, networked_guest_or_skip, of_kind, start_env, Scratch,
};
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

// --- a model on the host

/// The token the stub tests send: it must appear nowhere afterwards.
const TEST_TOKEN: &str = "boxcar-test-token-0123456789abcdef";

/// An Anthropic reply that asks for a Bash tool, as an event stream.
const STREAMED_TOOL_USE: &str = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-fable-5-1\",\"usage\":{\"input_tokens\":120,\"output_tokens\":1,\"cache_read_input_tokens\":100}}}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Running\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" it.\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_9\",\"name\":\"Bash\",\"input\":{}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \\\"ec\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"ho hi\\\"}\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":1}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":30}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

/// The reply once the tool result came back.
const FINAL_REPLY: &str = "{\"type\":\"message\",\"model\":\"claude-fable-5-1\",\"content\":[{\"type\":\"text\",\"text\":\"Done.\"}],\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":150,\"output_tokens\":5}}";

/// The first request: a prompt, streamed.
const FIRST_REQUEST: &str = "{\"model\":\"claude-fable-5-1\",\"max_tokens\":64,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Run echo hi\"}]}";
/// The second request: the tool's result.
const SECOND_REQUEST: &str = "{\"model\":\"claude-fable-5-1\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Run echo hi\"},{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"toolu_9\",\"name\":\"Bash\",\"input\":{\"command\":\"echo hi\"}}]},{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"toolu_9\",\"content\":\"hi\"}]}]}";

/// A model on the host's loopback: a TLS server with a certificate for
/// its address, whose PEM the test hands `boxcar run` through
/// `BOXCAR_TEST_UPSTREAM_ROOTS`. It speaks enough HTTP/1.1 for the
/// Anthropic Messages API: a prompt gets [`STREAMED_TOOL_USE`], a tool
/// result [`FINAL_REPLY`], anything else a small JSON body. It takes
/// `connections` connections, one request each, then ends.
struct Stub {
    addr: SocketAddrV4,
    roots: PathBuf,
    thread: thread::JoinHandle<()>,
}

fn stub_model(addr: Ipv4Addr, scratch: &Scratch, connections: usize) -> Stub {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec![addr.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let roots = scratch.path("stub-roots.pem");
    fs::write(
        &roots,
        boxcar_net::gate::ca::pem_certificate(cert.der().as_ref()),
    )
    .unwrap();
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
        for _ in 0..connections {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let Some((head, body)) = read_request(&mut tls) else {
                continue;
            };
            let request_line = head.lines().next().unwrap_or_default().to_owned();
            let (content_type, reply) = if request_line.contains("/v1/messages") {
                if body.contains("tool_result") {
                    ("application/json", FINAL_REPLY.to_owned())
                } else {
                    ("text/event-stream", STREAMED_TOOL_USE.to_owned())
                }
            } else {
                ("application/json", "{\"ok\":true}".to_owned())
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = tls.write_all(response.as_bytes());
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    Stub {
        addr,
        roots,
        thread,
    }
}

/// One HTTP/1.1 request: its head (up to the blank line) and its body (by
/// `Content-Length`), or `None` when the connection ended first.
fn read_request(
    tls: &mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
) -> Option<(String, String)> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = tls.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    while bytes.len() < head_end + length {
        let n = tls.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&bytes[head_end..]).into_owned();
    Some((head, body))
}

/// The flags that let the guest reach the stub, inspected, with the dump
/// in `scratch`.
fn stub_flags(stub: &Stub, scratch: &Scratch) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    for rule in host_rules(*stub.addr.ip(), stub.addr.port()) {
        flags.push("--allow".to_owned());
        flags.push(rule);
    }
    flags.push("--inspect".to_owned());
    flags.push(stub.addr.to_string());
    flags.push("--dump".to_owned());
    flags.push(scratch.path("dump").to_string_lossy().into_owned());
    flags
}

/// A `wget` of `body` to the stub's Messages endpoint, with the test
/// token as the agent's credential.
fn post(stub: &Stub, body: &str) -> String {
    format!(
        "wget -q -O /dev/null --header 'Content-Type: application/json' \
         --header 'Authorization: Bearer {TEST_TOKEN}' --post-data '{body}' \
         https://{}/v1/messages",
        stub.addr
    )
}

/// Every byte under `dir`, as text, for the absence assertions.
fn text_under(dir: &Path) -> String {
    let mut text = String::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                text.push_str(&text_under(&path));
            } else if let Ok(bytes) = fs::read(&path) {
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    text
}

/// A session talks to a model on the host, in the Anthropic Messages
/// API, through the gate: the prompt and its streamed reply become
/// `llm.request` and `llm.response`, the reply's tool use opens a span
/// (`tool.open`), the tool result the next request carries closes it
/// (`tool.close`), the reconciler writes `span.effects`, and `boxcar
/// spans` lists the span closed. The credential the agent sent appears
/// nowhere: not in the log, not in the dump.
#[test]
fn a_stub_model_speaks_anthropic_and_the_log_gets_spans() {
    let Some(guest) = guest_or_skip("a_stub_model_speaks_anthropic_and_the_log_gets_spans") else {
        return;
    };
    let Some(host) = host_address() else {
        eprintln!("skipping: this host has no address a guest could reach");
        return;
    };
    let scratch = Scratch::new();
    let stub = stub_model(host, &scratch, 2);
    let flags = stub_flags(&stub, &scratch);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let script = format!(
        "{}; sleep 1; {}; touch /workspace/done; sleep 4; exit 0",
        post(&stub, FIRST_REQUEST),
        post(&stub, SECOND_REQUEST)
    );
    let mut running = start_env(
        &guest,
        &scratch,
        &flags,
        &["/bin/sh", "-c", &script],
        &[("BOXCAR_TEST_UPSTREAM_ROOTS", stub.roots.as_path())],
    );
    running.until("the second request", |_| {
        scratch.path("workspace/done").exists()
    });
    let control = running.control();
    // The span, closed, as the control socket lists it.
    thread::sleep(Duration::from_millis(500));
    let listed = boxcar(&["spans"], &control);
    let spans_out = kvm_harness::text(&listed.stdout);
    assert!(
        spans_out
            .lines()
            .any(|l| l.starts_with("toolu_9  Bash  closed")),
        "boxcar spans said:\n{spans_out}\nstderr:\n{}",
        kvm_harness::text(&listed.stderr)
    );
    let active = boxcar(&["spans", "--active"], &control);
    assert_eq!(kvm_harness::text(&active.stdout), "", "nothing still open");
    let run = running.finish();
    stub.thread.join().unwrap();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();
    let requests = of_kind(&records, "llm.request");
    assert_eq!(requests.len(), 2, "{}", run.describe());
    for request in &requests {
        assert_eq!(request.data["provider"], "anthropic", "{request:?}");
        assert_eq!(request.data["model"], "claude-fable-5-1", "{request:?}");
    }
    assert_eq!(requests[0].data["streaming"], true);
    assert_eq!(requests[1].data["streaming"], false);
    let opens = of_kind(&records, "tool.open");
    assert_eq!(opens.len(), 1, "{}", run.describe());
    assert_eq!(opens[0].data["tool_use_id"], "toolu_9");
    assert_eq!(opens[0].data["tool_name"], "Bash");
    assert_eq!(opens[0].data["args"]["command"], "echo hi");
    let span = opens[0]
        .span
        .as_ref()
        .expect("the tool.open carries its span");
    assert_eq!(span.span_id, "toolu_9");
    assert_eq!(span.trace_id, records[0].session_id.to_string());
    let closes = of_kind(&records, "tool.close");
    assert_eq!(closes.len(), 1, "{}", run.describe());
    assert_eq!(closes[0].data["status"], "ok");
    let responses = of_kind(&records, "llm.response");
    assert_eq!(responses.len(), 2, "{}", run.describe());
    assert_eq!(responses[0].data["stop_reason"], "tool_use");
    assert_eq!(responses[0].data["tool_uses"], 1);
    assert_eq!(responses[1].data["stop_reason"], "end_turn");
    let effects = of_kind(&records, "span.effects");
    assert_eq!(effects.len(), 1, "{}", run.describe());
    assert_eq!(effects[0].data["span_id"], "toolu_9");
    assert_eq!(effects[0].data["closed_seq"], closes[0].seq);
    assert_eq!(effects[0].data["opened_seq"], opens[0].seq);
    // The credential went to the model and nowhere else. This test puts
    // it on wget's command line, which the session's own records
    // (`session.start`, the shell's and wget's `proc.exec`) carry as the
    // command they are; every other record, and the dump, must be free
    // of it. An agent reads its token from the environment, which no
    // record carries (the agent tests check the whole log).
    let own_command = ["session.start", "proc.exec"];
    let leaked: Vec<&boxcar_proto::Record> = records
        .iter()
        .filter(|r| !own_command.contains(&r.kind.as_str()))
        .filter(|r| serde_json::to_string(r).unwrap().contains(TEST_TOKEN))
        .collect();
    assert!(leaked.is_empty(), "the token is in the log: {leaked:?}");
    let log_text = text_under(&run.session_dir());
    assert!(
        !log_text.to_ascii_lowercase().contains("\"authorization\""),
        "an authorization header is in the log"
    );
    assert!(
        !text_under(&scratch.path("dump")).contains(TEST_TOKEN),
        "the token is in the dump"
    );
}

/// The dump of an inspected session: `frames.pcap` is a pcap file and
/// holds the flow's SYN, and the decoded request file holds the request
/// line and the headers the observer kept, which do not include the
/// `Authorization` the request carried.
#[test]
fn the_dump_holds_the_frames_and_the_decoded_exchange() {
    let Some(guest) = guest_or_skip("the_dump_holds_the_frames_and_the_decoded_exchange") else {
        return;
    };
    let Some(host) = host_address() else {
        eprintln!("skipping: this host has no address a guest could reach");
        return;
    };
    let scratch = Scratch::new();
    let stub = stub_model(host, &scratch, 1);
    let flags = stub_flags(&stub, &scratch);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let script = format!("{}; sleep 2; exit 0", post(&stub, FIRST_REQUEST));
    let running = start_env(
        &guest,
        &scratch,
        &flags,
        &["/bin/sh", "-c", &script],
        &[("BOXCAR_TEST_UPSTREAM_ROOTS", stub.roots.as_path())],
    );
    let run = running.finish();
    stub.thread.join().unwrap();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let records = run.records();
    let request = of_kind(&records, "http.request")
        .into_iter()
        .find(|r| r.data["path"] == "/v1/messages")
        .unwrap_or_else(|| {
            let net: Vec<_> = records
                .iter()
                .filter(|r| r.kind.starts_with("net.") || r.kind.starts_with("http."))
                .map(|r| format!("{} {}", r.kind, r.data))
                .collect();
            panic!(
                "no http.request; the network records:\n{}\n{}",
                net.join("\n"),
                run.describe()
            )
        });
    let flow = request.data["flow"].as_u64().unwrap();
    let stream = request.data["stream"].as_u64().unwrap();

    let dump = scratch.path("dump");
    let pcap = fs::read(dump.join("frames.pcap")).unwrap();
    assert!(pcap.len() >= 24, "{}", pcap.len());
    let u32_at = |bytes: &[u8], at: usize| {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    };
    assert_eq!(u32_at(&pcap, 0), 0xa1b2_c3d4);
    assert_eq!(u16::from_le_bytes([pcap[4], pcap[5]]), 2);
    assert_eq!(u16::from_le_bytes([pcap[6], pcap[7]]), 4);
    assert_eq!(u32_at(&pcap, 20), 1, "Ethernet");
    // Every record's lengths add up, no TCP record holds payload, and one
    // is the flow's SYN to the stub.
    let mut at = 24;
    let mut frames = 0;
    let mut syn = false;
    while at + 16 <= pcap.len() {
        let included = u32_at(&pcap, at + 8) as usize;
        let original = u32_at(&pcap, at + 12) as usize;
        assert!(included <= original && at + 16 + included <= pcap.len());
        let frame = &pcap[at + 16..at + 16 + included];
        if frame.len() >= 14 + 20 + 20 && frame[12..14] == [0x08, 0x00] && frame[23] == 6 {
            let ihl = usize::from(frame[14] & 0x0f) * 4;
            let tcp = &frame[14 + ihl..];
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let flags = tcp[13];
            if dst_port == stub.addr.port() && flags & 0x12 == 0x02 {
                syn = true;
            }
            // A TCP segment is kept to its headers, without its payload.
            assert_eq!(included, 14 + ihl + usize::from(tcp[12] >> 4) * 4);
        }
        frames += 1;
        at += 16 + included;
    }
    assert_eq!(at, pcap.len(), "a record ran past the file's end");
    assert!(frames > 2 && syn, "{frames} frames, syn {syn}");

    let req = fs::read_to_string(dump.join(format!("http/{flow}-{stream}.req")))
        .unwrap_or_else(|e| panic!("no request file: {e}"));
    assert!(req.starts_with("POST /v1/messages HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("content-type: application/json\r\n"), "{req}");
    // The body, decoded and scrubbed (its keys in the scrub's order).
    let body = req.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert!(
        body.starts_with('{') && body.contains("\"model\":\"claude-fable-5-1\""),
        "{req}"
    );
    assert!(!req.to_ascii_lowercase().contains("authorization"), "{req}");
    assert!(!req.contains(TEST_TOKEN), "{req}");
    let resp = fs::read_to_string(dump.join(format!("http/{flow}-{stream}.resp"))).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200\r\n"), "{resp}");
    assert!(
        resp.contains("content-type: text/event-stream\r\n"),
        "{resp}"
    );
    assert!(resp.contains("event: message_stop"), "{resp}");
    assert!(
        !text_under(&dump).contains(TEST_TOKEN),
        "the token is in the dump"
    );
    // The dump's files are the run's alone.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&dump).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(dump.join("frames.pcap"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

// --- the agents inside

/// The Debian guest, or `None` after saying why the agent tests skip.
fn debian_guest_or_skip(test: &str) -> Option<kvm_harness::Guest> {
    let guest = guest_or_skip(test)?;
    let Some(debian) = std::env::var_os("BOXCAR_TEST_ROOTFS_DEBIAN") else {
        eprintln!(
            "skipping {test}: BOXCAR_TEST_ROOTFS_DEBIAN is not set (cargo xtask rootfs debian)"
        );
        return None;
    };
    if std::env::var_os("BOXCAR_TEST_NET").is_some_and(|value| value == "0") {
        eprintln!("skipping {test}: BOXCAR_TEST_NET=0");
        return None;
    }
    Some(kvm_harness::Guest {
        kernel: guest.kernel,
        initramfs: guest.initramfs,
        rootfs: PathBuf::from(debian),
    })
}

/// The Claude Code token, or `None` after saying why the test skips: the
/// host's `CLAUDE_CODE_OAUTH_TOKEN`, else the access token of the host's
/// own Claude Code login (`~/.claude/.credentials.json`) while it has at
/// least ten minutes left. Only the access token goes to the guest, never
/// the refresh token, so nothing in the guest can rotate the host's login.
/// Its value is passed on and never printed.
fn claude_token_or_skip(test: &str) -> Option<String> {
    if let Ok(token) = std::env::var("CLAUDE_CODE_OAUTH_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }
    let login = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".claude/.credentials.json"))
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
    let oauth = login.as_ref().map(|login| &login["claudeAiOauth"]);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    match oauth.and_then(|o| Some((o["accessToken"].as_str()?, o["expiresAt"].as_u64()?))) {
        Some((token, expires)) if expires > now_ms + 10 * 60 * 1000 && !token.is_empty() => {
            Some(token.to_owned())
        }
        Some(_) => {
            eprintln!(
                "skipping {test}: the local Claude Code login expires within 10 minutes; run \
                 claude once to refresh it, or set CLAUDE_CODE_OAUTH_TOKEN"
            );
            None
        }
        None => {
            eprintln!(
                "skipping {test}: neither CLAUDE_CODE_OAUTH_TOKEN nor a local Claude Code login \
                 (claude setup-token)"
            );
            None
        }
    }
}

/// The policy a Claude Code session needs: the model inspected, the
/// account's endpoints allowed.
const CLAUDE_FLAGS: [&str; 8] = [
    "--inspect",
    "api.anthropic.com:443",
    "--allow",
    "api.anthropic.com:443",
    "--allow",
    "platform.claude.com:443",
    "--allow",
    "claude.ai:443",
];

/// How long an agent's run may take: a start, a model round trip or two,
/// a tool call.
const AGENT_LIMIT: Duration = Duration::from_secs(300);

/// What an agent session is asked to do, and what the log must show of
/// it: a Bash (or shell) tool call whose span holds the exec of a shell
/// with that command and the close of the file it wrote.
const AGENT_PROMPT: &str =
    "Run this exact shell command and then stop: echo boxcar-m4 > marker.txt";

/// Checks an agent run's log: the model request through the gate, the
/// tool span with the shell's exec and the marker's write, no finding
/// above 50, and the credential nowhere.
fn check_agent_run(run: &kvm_harness::Run, provider: &str, scratch: &Scratch, secret: &str) {
    let records = run.records();
    let requests = of_kind(&records, "llm.request");
    assert!(
        requests.iter().any(|r| r.data["provider"] == provider),
        "no llm.request from {provider}: {requests:?}\n{}",
        run.describe()
    );
    let opens = of_kind(&records, "tool.open");
    let shell_tools = [
        "Bash",
        "bash",
        "shell",
        "exec_command",
        "local_shell",
        "exec",
    ];
    let open = opens
        .iter()
        .find(|r| {
            shell_tools.contains(&r.data["tool_name"].as_str().unwrap_or_default())
                && r.data.to_string().contains("boxcar-m4")
        })
        .unwrap_or_else(|| {
            panic!(
                "no shell tool.open with the command among {opens:?}\n{}",
                run.describe()
            )
        });
    let span_id = open.data["tool_use_id"].as_str().unwrap().to_owned();
    let effects = of_kind(&records, "span.effects")
        .into_iter()
        .find(|r| r.data["span_id"] == span_id)
        .unwrap_or_else(|| panic!("no span.effects for {span_id}\n{}", run.describe()));
    let seqs: Vec<u64> = effects.data["effects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    let in_span: Vec<&boxcar_proto::Record> =
        records.iter().filter(|r| seqs.contains(&r.seq)).collect();
    assert!(
        in_span
            .iter()
            .any(|r| r.kind == "proc.exec" && r.data["argv"].to_string().contains("boxcar-m4")),
        "no shell exec with the command in the span: {in_span:?}\n{}",
        run.describe()
    );
    assert!(
        in_span.iter().any(|r| r.kind == "fs.close"
            && r.data["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("marker.txt"))),
        "no fs.close of marker.txt in the span: {in_span:?}\n{}",
        run.describe()
    );
    assert_eq!(
        fs::read_to_string(scratch.path("workspace/marker.txt"))
            .unwrap()
            .trim(),
        "boxcar-m4"
    );
    let loud: Vec<_> = of_kind(&records, "finding")
        .into_iter()
        .filter(|r| r.data["score"].as_u64().unwrap_or(0) > 50)
        .collect();
    assert!(
        loud.is_empty(),
        "findings above 50: {loud:?}\n{}",
        run.describe()
    );
    let log_text = text_under(&run.session_dir());
    assert!(!log_text.contains(secret), "the credential is in the log");
    assert!(
        !text_under(&scratch.path("dump")).contains(secret),
        "the credential is in the dump"
    );
    assert!(
        !run.stderr.contains(secret)
            && !run.stdout.contains(secret)
            && !run.console.contains(secret)
    );
}

/// Claude Code's native build runs a Bash tool inside, on the account's
/// own login.
#[test]
fn claude_code_native_runs_a_bash_tool_inside() {
    let Some(guest) = debian_guest_or_skip("claude_code_native_runs_a_bash_tool_inside") else {
        return;
    };
    let Some(token) = claude_token_or_skip("claude_code_native_runs_a_bash_tool_inside") else {
        return;
    };
    let scratch = Scratch::new();
    let env_flag = format!("CLAUDE_CODE_OAUTH_TOKEN={token}");
    let dump = scratch.path("dump").to_string_lossy().into_owned();
    let mut flags: Vec<&str> = CLAUDE_FLAGS.to_vec();
    flags.extend([
        "--env",
        &env_flag,
        "--env",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
        "--dump",
        &dump,
    ]);
    let run = start_env(
        &guest,
        &scratch,
        &flags,
        &[
            "/usr/local/bin/claude-native",
            "-p",
            AGENT_PROMPT,
            "--allowedTools",
            "Bash",
        ],
        &[],
    )
    .with_limit(AGENT_LIMIT)
    .finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    check_agent_run(&run, "anthropic", &scratch, &token);
}

/// Claude Code from npm runs a Bash tool inside. Since 2.1 the npm package
/// installs the same native build (`bin/claude.exe`), not a Node script,
/// so this is the npm installation path rather than a second runtime;
/// Node's own TLS is `node_tls_is_seen_by_both_rings`.
#[test]
fn claude_code_from_npm_runs_a_bash_tool_inside() {
    let Some(guest) = debian_guest_or_skip("claude_code_from_npm_runs_a_bash_tool_inside") else {
        return;
    };
    let Some(token) = claude_token_or_skip("claude_code_from_npm_runs_a_bash_tool_inside") else {
        return;
    };
    let scratch = Scratch::new();
    let env_flag = format!("CLAUDE_CODE_OAUTH_TOKEN={token}");
    let dump = scratch.path("dump").to_string_lossy().into_owned();
    let mut flags: Vec<&str> = CLAUDE_FLAGS.to_vec();
    flags.extend([
        "--env",
        &env_flag,
        "--env",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
        "--dump",
        &dump,
    ]);
    let run = start_env(
        &guest,
        &scratch,
        &flags,
        &[
            "/usr/local/bin/claude",
            "-p",
            AGENT_PROMPT,
            "--allowedTools",
            "Bash",
        ],
        &[],
    )
    .with_limit(AGENT_LIMIT)
    .finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    check_agent_run(&run, "anthropic", &scratch, &token);
}

/// Node exports OpenSSL's functions, so ring 1 sees a Node program's TLS:
/// in the Debian guest, `node` fetches an inspected page twice; the
/// sensor attaches to the `node` binary, reports its writes and reads, and
/// the gate's `http.request` of the second fetch has a write of its size
/// within 500 ms.
#[test]
fn node_tls_is_seen_by_both_rings() {
    let Some(guest) = debian_guest_or_skip("node_tls_is_seen_by_both_rings") else {
        return;
    };
    if let Err(reason) = kvm_harness::example_com_reachable() {
        eprintln!("skipping node_tls_is_seen_by_both_rings: {reason}");
        return;
    }
    let scratch = Scratch::new();
    let script = "const https = require('https'); \
        const get = () => new Promise((ok, fail) => https.get('https://example.com/', \
          (res) => { res.resume(); res.on('end', ok); }).on('error', fail)); \
        get().then(() => new Promise((ok) => setTimeout(ok, 2000))).then(get) \
          .then(() => console.log('FETCHED'), (e) => { console.log('FAILED', e.message); process.exit(1); });";
    let run = boxcar_run(
        &guest,
        &scratch,
        &["--allow", "example.com:443", "--inspect", "example.com:443"],
        &["/usr/local/bin/node", "-e", script],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("FETCHED"), "{}", run.describe());
    let records = run.records();
    let attach = of_kind(&records, "proc.tls_attach")
        .into_iter()
        .find(|r| r.data["path"] == "/usr/local/bin/node")
        .unwrap_or_else(|| panic!("no proc.tls_attach for node\n{}", run.describe()));
    assert_eq!(attach.data["ok"], true, "{attach:?}");
    let node: Vec<u64> = of_kind(&records, "proc.exec")
        .into_iter()
        .filter(|r| r.data["filename"] == "/usr/local/bin/node")
        .map(|r| r.data["tgid"].as_u64().unwrap())
        .collect();
    let io: Vec<_> = of_kind(&records, "proc.tls_io")
        .into_iter()
        .filter(|r| node.contains(&r.data["tgid"].as_u64().unwrap()))
        .collect();
    let writes: Vec<_> = io.iter().filter(|r| r.data["dir"] == "write").collect();
    assert!(
        !writes.is_empty() && io.iter().any(|r| r.data["dir"] == "read"),
        "no TLS writes and reads from node {node:?}: {io:?}\n{}",
        run.describe()
    );
    let request = of_kind(&records, "http.request")
        .into_iter()
        .last()
        .unwrap_or_else(|| panic!("no http.request\n{}", run.describe()));
    let body = request.data["body_bytes"].as_u64().unwrap();
    assert!(
        writes.iter().any(
            |w| w.ts_host_ns.abs_diff(request.ts_host_ns) <= 500 * 1_000_000
                && w.data["bytes"].as_u64().unwrap().abs_diff(body) <= body / 10 + 1024
        ),
        "no node write within 500 ms and 1 KiB of {request:?}: {writes:?}"
    );
}

/// Codex runs a shell tool inside, on the account's own login
/// (`CODEX_HOME`, or `~/.codex`, holding `auth.json`).
#[test]
fn codex_runs_a_shell_tool_inside() {
    let Some(guest) = debian_guest_or_skip("codex_runs_a_shell_tool_inside") else {
        return;
    };
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".codex")));
    let auth = codex_home.as_ref().map(|dir| dir.join("auth.json"));
    let Some(auth) = auth.filter(|path| path.is_file()) else {
        eprintln!(
            "skipping codex_runs_a_shell_tool_inside: no auth.json under CODEX_HOME or ~/.codex"
        );
        return;
    };
    let auth_json = fs::read_to_string(&auth).unwrap();
    // Whatever the file holds is the secret: none of its long values may
    // show up anywhere.
    let secret = auth_json
        .split('"')
        .filter(|part| part.len() >= 32)
        .max_by_key(|part| part.len())
        .unwrap_or("")
        .to_owned();
    let scratch = Scratch::new();
    let home = scratch.path("workspace/.codex");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("auth.json"), &auth_json).unwrap();
    let dump = scratch.path("dump").to_string_lossy().into_owned();
    // An account login talks to chatgpt.com (the Responses API over
    // WebSocket), an API key to api.openai.com: both are inspected. The
    // content host serves what Codex's plugin listing points at; denied,
    // Codex asks for it again and again.
    let flags = [
        "--inspect",
        "api.openai.com:443",
        "--inspect",
        "chatgpt.com:443",
        "--allow",
        "api.openai.com:443",
        "--allow",
        "chatgpt.com:443",
        "--allow",
        "auth.openai.com:443",
        "--allow",
        "*.oaiusercontent.com:443",
        "--env",
        "CODEX_HOME=/workspace/.codex",
        "--dump",
        &dump,
    ];
    let run = start_env(
        &guest,
        &scratch,
        &flags,
        &[
            "/usr/local/bin/codex",
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            AGENT_PROMPT,
        ],
        &[],
    )
    .with_limit(AGENT_LIMIT)
    .finish();
    let _ = fs::remove_dir_all(&home);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    check_agent_run(&run, "openai_responses", &scratch, &secret);
}
