// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The model traffic gate end to end through the stack: a guest (the test
//! rig's smoltcp interface carrying a rustls client) connects to a TLS
//! upstream on 127.0.0.1 that an `inspect` line names; the stack ends the
//! guest's TLS with the session CA's leaf, reaches the upstream with its
//! own TLS, relays the plaintext unchanged, hands the observer a copy, and
//! records `net.tls{inspect}`, `net.inspect` and `net.close`. Plain HTTP
//! an `inspect` line names is observed as it is relayed; an upstream the
//! trust store does not vouch for fails closed; and an observer that
//! never reads slows nothing.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boxcar_net::gate::{Direction, Message, Observer};
use boxcar_net::{InspectConfig, Policy, SessionCa, Verdict};
use boxcar_proto::{NetClose, NetDrop, NetInspect, NetTls, Payload};
use common::rig::{host_peer, Rig};
use common::{harness_gate, resolve};
use crossbeam_channel::Receiver;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use smoltcp::iface::SocketHandle;

/// The name the guest asks for and the test upstream answers to.
const NAME: &str = "api.example";
const LIMIT: Duration = Duration::from_secs(30);

/// A TLS upstream on the loopback for [`NAME`], offering `alpn`, that
/// reads `expect` bytes of plaintext, writes `reply`, and closes. Its
/// certificate, which the gate must be told to trust, and what it read.
fn upstream(
    alpn: &[&str],
    expect: usize,
    reply: Vec<u8>,
) -> (
    SocketAddrV4,
    CertificateDer<'static>,
    thread::JoinHandle<Vec<u8>>,
) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec![NAME.to_owned(), "127.0.0.1".to_owned()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
        panic!("not IPv4");
    };
    let thread = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        let mut got = Vec::new();
        let mut buf = vec![0; 16384];
        while got.len() < expect {
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
                Err(error) => panic!("upstream read: {error}"),
            }
        }
        if !reply.is_empty() {
            tls.write_all(&reply).unwrap();
        }
        tls.conn.send_close_notify();
        let _ = tls.flush();
        let _ = tls.sock.shutdown(std::net::Shutdown::Write);
        while let Ok(n) = tls.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
        got
    });
    (addr, cert_der, thread)
}

/// A session CA and the gate's config, trusting `extra` upstream beside
/// the host's store, with an observer channel of `cap` messages.
fn gate(
    extra: &[CertificateDer<'static>],
    cap: usize,
) -> (Arc<InspectConfig>, Observer, Receiver<Message>) {
    let ca = Arc::new(SessionCa::generate("inspect-test").unwrap());
    let cfg = Arc::new(InspectConfig::new(ca, InspectConfig::host_roots(extra)).unwrap());
    let (observer, rx) = Observer::with_capacity(cap);
    (cfg, observer, rx)
}

/// The guest's TLS client: trusts the session CA, asks for [`NAME`].
fn guest_client(ca: &SessionCa, alpn: &[&str]) -> ClientConnection {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    ClientConnection::new(Arc::new(config), ServerName::try_from(NAME).unwrap()).unwrap()
}

/// Carries `client`'s TLS bytes over the guest socket `handle`, both
/// ways, stepping the rig until `done`.
fn drive(
    rig: &mut Rig,
    handle: SocketHandle,
    client: &mut ClientConnection,
    what: &str,
    mut done: impl FnMut(&mut ClientConnection) -> bool,
) {
    let mut pending: Vec<u8> = Vec::new();
    rig.until(LIMIT, what, |rig| {
        while client.wants_write() {
            client.write_tls(&mut pending).unwrap();
        }
        let socket = rig.socket(handle);
        if !pending.is_empty() && socket.can_send() {
            let n = socket.send_slice(&pending).unwrap();
            pending.drain(..n);
        }
        if socket.can_recv() {
            let mut buf = vec![0; 65536];
            let n = socket.recv_slice(&mut buf).unwrap();
            let mut rd = &buf[..n];
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
            }
            // A refused certificate shows here; the tests that expect one
            // look at the flow's records.
            let _ = client.process_new_packets();
        }
        done(client) && pending.is_empty()
    });
}

fn tls_records(events: &[Payload]) -> Vec<&NetTls> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetTls(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn inspect_records(events: &[Payload]) -> Vec<&NetInspect> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetInspect(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn close_records(events: &[Payload]) -> Vec<&NetClose> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetClose(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn position(events: &[Payload], pick: impl Fn(&Payload) -> bool) -> usize {
    events.iter().position(pick).expect("the record")
}

/// Everything the observer was told, once the channel's senders are gone.
fn observed(rx: Receiver<Message>) -> Vec<Message> {
    let mut all = Vec::new();
    while let Ok(msg) = rx.recv_timeout(Duration::from_secs(5)) {
        all.push(msg);
    }
    all
}

fn data(messages: &[Message], dir: Direction) -> Vec<u8> {
    messages
        .iter()
        .filter_map(|m| match m {
            Message::Data { dir: d, bytes, .. } if *d == dir => Some(bytes.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// The whole path: the guest's TLS ends in the stack, the upstream is
/// reached with the stack's own TLS, the request and the reply pass
/// unchanged, the observer gets both, and the log has the three records
/// in order.
#[test]
fn an_inspected_tls_flow_is_ended_relayed_and_recorded() {
    let request = b"GET / HTTP/1.1\r\nHost: api.example\r\n\r\n".to_vec();
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let (addr, cert, up) = upstream(&["http/1.1"], request.len(), reply.clone());
    let (cfg, observer, rx) = gate(&[cert], 4096);
    let policy = Policy::parse(&[
        "allow 127.0.0.0/8".to_owned(),
        format!("inspect 127.0.0.1:{}", addr.port()),
    ])
    .unwrap();
    let mut rig = Rig::new(harness_gate(policy, Some((Arc::clone(&cfg), observer))));
    let (handle, _guest) = rig.connect(addr);
    let mut client = guest_client(cfg.ca(), &["http/1.1"]);
    drive(&mut rig, handle, &mut client, "the guest handshake", |c| {
        !c.is_handshaking()
    });
    assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
    client.writer().write_all(&request).unwrap();
    let mut got = Vec::new();
    drive(&mut rig, handle, &mut client, "the reply", |c| {
        let mut buf = [0; 4096];
        if let Ok(n) = c.reader().read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        got.len() >= reply.len()
    });
    assert_eq!(got, reply);
    client.send_close_notify();
    drive(&mut rig, handle, &mut client, "the close_notify", |c| {
        !c.wants_write()
    });
    rig.socket(handle).close();
    rig.settle();
    assert_eq!(up.join().unwrap(), request);

    let events = rig.events();
    let tls = tls_records(&events);
    assert_eq!(tls.len(), 1, "{tls:?}");
    assert_eq!(tls[0].kind, "tls");
    assert_eq!(tls[0].sni.as_deref(), Some(NAME));
    assert_eq!(tls[0].alpn, ["http/1.1"]);
    assert_eq!(tls[0].verdict, Verdict::Allow);
    assert!(tls[0].inspect);
    let inspects = inspect_records(&events);
    assert_eq!(inspects.len(), 1, "{inspects:?}");
    let inspect = inspects[0];
    assert_eq!(inspect.flow, tls[0].flow);
    assert_eq!(inspect.result, "ok");
    assert_eq!(inspect.sni.as_deref(), Some(NAME));
    assert_eq!(inspect.alpn.as_deref(), Some("http/1.1"));
    assert_eq!(inspect.version.as_deref(), Some("1.3"));
    assert_eq!(
        inspect.rule.as_deref(),
        Some(format!("inspect 127.0.0.1:{}", addr.port()).as_str())
    );
    let closes = close_records(&events);
    assert_eq!(closes.len(), 1, "{closes:?}");
    assert_eq!(closes[0].reason, "fin");
    let at_tls = position(&events, |e| matches!(e, Payload::NetTls(_)));
    let at_inspect = position(&events, |e| matches!(e, Payload::NetInspect(_)));
    let at_close = position(&events, |e| matches!(e, Payload::NetClose(_)));
    assert!(at_tls < at_inspect && at_inspect < at_close);

    // `events` took the stack with it: the observer's senders are gone.
    let messages = observed(rx);
    assert!(
        matches!(
            &messages[0],
            Message::Open { name: Some(name), alpn: Some(alpn), tls: true, .. }
                if name == NAME && alpn == "http/1.1"
        ),
        "{:?}",
        messages[0]
    );
    assert_eq!(data(&messages, Direction::ToHost), request);
    assert_eq!(data(&messages, Direction::ToGuest), reply);
    assert!(
        matches!(messages.last(), Some(Message::Close { .. })),
        "{messages:?}"
    );
}

/// Plain HTTP an `inspect` line names is relayed as it is, and the
/// observer gets the request and the reply; there is no `net.inspect`.
#[test]
fn a_plain_http_flow_an_inspect_line_names_is_observed_as_it_is() {
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let reply: &'static [u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    let (addr, peer) = host_peer(request.len(), reply);
    let (cfg, observer, rx) = gate(&[], 4096);
    let policy = Policy::parse(&[
        // The name resolves (the default), the flow is allowed by address
        // (not gated), and the line names it.
        "default allow".to_owned(),
        "allow 127.0.0.0/8".to_owned(),
        "inspect example.com".to_owned(),
    ])
    .unwrap();
    let mut rig = Rig::new(harness_gate(policy, Some((cfg, observer))));
    // The guest resolved the name to the loopback: the line may name it.
    resolve(&mut rig.h, "example.com", std::net::Ipv4Addr::LOCALHOST);
    let (handle, _guest) = rig.connect(addr);
    rig.send(handle, request);
    assert_eq!(rig.recv(handle, reply.len()), reply);
    rig.socket(handle).close();
    let seen = rig.seen(&peer);
    assert_eq!(seen.bytes, request);
    rig.settle();

    let events = rig.events();
    let tls = tls_records(&events);
    assert_eq!(tls.len(), 1, "{tls:?}");
    assert_eq!(tls[0].kind, "http");
    assert_eq!(tls[0].sni.as_deref(), Some("example.com"));
    assert!(tls[0].inspect);
    assert!(inspect_records(&events).is_empty());
    assert_eq!(close_records(&events)[0].reason, "fin");

    // `events` took the stack with it: the observer's senders are gone.
    let messages = observed(rx);
    assert!(
        matches!(&messages[0], Message::Open { name: Some(name), alpn: None, tls: false, .. } if name == "example.com"),
        "{:?}",
        messages[0]
    );
    assert_eq!(data(&messages, Direction::ToHost), request);
    assert_eq!(data(&messages, Direction::ToGuest), reply);
    assert!(matches!(messages.last(), Some(Message::Close { .. })));
}

/// An observer that never reads: the relay moves at the host's pace, the
/// bytes all reach the host, and the loss is counted as `observe`.
#[test]
fn a_slow_observer_never_slows_the_relay() {
    let mut request =
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1048576\r\n\r\n".to_vec();
    request.extend((0..1024 * 1024).map(|i| (i % 251) as u8));
    let reply: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (addr, peer) = host_peer(request.len(), reply);
    // Room for one message, and nobody reading.
    let (cfg, observer, rx) = gate(&[], 1);
    let policy = Policy::parse(&[
        // The name resolves (the default), the flow is allowed by address
        // (not gated), and the line names it.
        "default allow".to_owned(),
        "allow 127.0.0.0/8".to_owned(),
        "inspect example.com".to_owned(),
    ])
    .unwrap();
    let mut rig = Rig::new(harness_gate(policy, Some((cfg, observer))));
    resolve(&mut rig.h, "example.com", std::net::Ipv4Addr::LOCALHOST);
    let (handle, _guest) = rig.connect(addr);
    rig.send(handle, &request);
    assert_eq!(rig.recv(handle, reply.len()), reply);
    rig.socket(handle).close();
    let seen = rig.seen(&peer);
    assert_eq!(seen.bytes, request, "every byte reached the host");
    rig.settle();
    let events = rig.events();
    let observe_drops: Vec<&NetDrop> = events
        .iter()
        .filter_map(|e| match e {
            Payload::NetDrop(d) if d.reason == "observe" => Some(d),
            _ => None,
        })
        .collect();
    let dropped: u64 = observe_drops.iter().map(|d| d.count).sum();
    assert!(dropped > 0, "no observe drops in {events:?}");
    assert_eq!(close_records(&events)[0].reason, "fin");
    assert_eq!(rx.len(), 1, "the one message the channel had room for");
}

/// An upstream the trust store does not vouch for: the guest handshake
/// never completes, the flow is reset, `net.inspect` says why, and the
/// observer is told nothing.
#[test]
fn an_untrusted_upstream_is_refused_at_the_stack() {
    let (addr, _cert, up) = upstream(&["http/1.1"], 0, Vec::new());
    // The host's store alone: the upstream's certificate is not in it.
    let (cfg, observer, rx) = gate(&[], 4096);
    let policy = Policy::parse(&[
        "allow 127.0.0.0/8".to_owned(),
        format!("inspect 127.0.0.1:{}", addr.port()),
    ])
    .unwrap();
    let mut rig = Rig::new(harness_gate(policy, Some((Arc::clone(&cfg), observer))));
    let (handle, _guest) = rig.connect(addr);
    let mut client = guest_client(cfg.ca(), &["http/1.1"]);
    // The guest's socket is reset before its handshake completes.
    let mut pending: Vec<u8> = Vec::new();
    rig.until(LIMIT, "the reset", |rig| {
        while client.wants_write() {
            client.write_tls(&mut pending).unwrap();
        }
        let socket = rig.socket(handle);
        if !pending.is_empty() && socket.can_send() {
            let n = socket.send_slice(&pending).unwrap();
            pending.drain(..n);
        }
        socket.state() == smoltcp::socket::tcp::State::Closed
    });
    assert!(client.is_handshaking(), "the guest was never answered");
    rig.settle();
    drop(up);

    let events = rig.events();
    let inspects = inspect_records(&events);
    assert_eq!(inspects.len(), 1, "{inspects:?}");
    assert_eq!(inspects[0].result, "upstream_untrusted");
    assert_eq!(inspects[0].sni.as_deref(), Some(NAME));
    assert_eq!(inspects[0].alpn, None);
    let closes = close_records(&events);
    assert_eq!(closes.len(), 1, "{closes:?}");
    assert_eq!(closes[0].reason, "inspect");
    assert_eq!(
        (closes[0].tx, closes[0].rx),
        (closes[0].tx, 0),
        "nothing came back"
    );
    assert!(tls_records(&events)[0].inspect);

    // `events` took the stack with it: the observer's senders are gone.
    let messages = observed(rx);
    assert!(messages.is_empty(), "{messages:?}");
}
