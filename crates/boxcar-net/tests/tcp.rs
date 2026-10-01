// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The TCP relay end to end. A second smoltcp interface plays the guest:
//! its frames go to the stack's `push_guest_frame`, and what
//! `pop_host_frame` gives back goes into its device. Behind the stack, real
//! sockets on 127.0.0.1 play the far end, which the test policies allow
//! with `allow 127.0.0.0/8` (the exact range lifts the built-in denial),
//! and a [`FakeEventLoop`] over poll(2) plays the net thread, watching the
//! fds the stack asks for. The audit log says what was decided and how
//! each flow ended.

mod common;

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use boxcar_net::sni::{parse_client_hello, Hello};
use boxcar_net::upstream::{HostAddrs, BUILTIN_HOST_LOCAL};
use boxcar_net::{Interest, Policy, Verdict, FLOW_TOKEN_BASE};
use boxcar_proto::{NetClose, NetConnect, NetTls, Payload};
use common::{
    drops, guest_arp, harness_config, harness_with, resolve, segment, syn, FakeEventLoop, Harness,
    Segment, GATEWAY, GUEST, GUEST_MAC,
};
use proptest::collection::vec;
use proptest::prelude::*;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use socket2::{Domain, Socket, Type};

/// A ClientHello `openssl s_client -connect 127.0.0.1:<port> -servername
/// example.com -alpn h2,http/1.1` (OpenSSL 1.1.1q) sent a throwaway
/// listener: one TLS record, as captured.
const OPENSSL_CLIENT_HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x01, 0x46, 0x01, 0x00, 0x01, 0x42, 0x03, 0x03, 0xa8, 0xaa, 0x02, 0x62, 0x1f,
    0x02, 0x34, 0xe0, 0x78, 0xb8, 0x8a, 0x3f, 0x8c, 0xf7, 0x07, 0x48, 0xa7, 0x38, 0x12, 0x15, 0x87,
    0x16, 0xcf, 0x1f, 0xed, 0x33, 0xc9, 0x16, 0xb3, 0x2c, 0xa9, 0x3e, 0x20, 0xe8, 0xfa, 0xe4, 0xf0,
    0x8d, 0xeb, 0xf3, 0xee, 0x82, 0x09, 0xf0, 0x0e, 0x4f, 0x5c, 0xd6, 0x53, 0x43, 0xcf, 0xd0, 0x6e,
    0x6b, 0x5f, 0x3c, 0x60, 0x39, 0xa5, 0x58, 0x4d, 0x3c, 0x9a, 0xaa, 0xcf, 0x00, 0x3e, 0x13, 0x02,
    0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
    0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
    0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d,
    0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0xbb,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c,
    0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
    0x2e, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e,
    0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b,
    0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03,
    0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b,
    0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x01,
    0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xd3, 0xf4, 0x44, 0xab, 0xa0,
    0x18, 0x8a, 0x47, 0x8d, 0xf7, 0xe4, 0xd1, 0x8e, 0xf5, 0x1e, 0x3e, 0xcb, 0x03, 0x7f, 0xd5, 0x22,
    0xa5, 0xde, 0xb0, 0x8f, 0x12, 0x01, 0xfb, 0x60, 0x6f, 0xff, 0x32,
];

/// The guest's frame MTU: 1500 bytes of IP and the Ethernet header.
const FRAME_MTU: usize = 1514;

fn policy(lines: &[&str]) -> Policy {
    Policy::parse(lines).unwrap()
}

fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => panic!("{addr} is not IPv4"),
    }
}

/// The byte at offset `i` of every stream the tests send: a period of 251,
/// so a lost, repeated or reordered chunk shows.
fn pattern(i: u64) -> u8 {
    (i % 251) as u8
}

/// The guest's NIC: what the guest sent and the stack has not taken, and
/// what the stack sent and the guest has not read.
#[derive(Default)]
struct Wire {
    to_stack: VecDeque<Vec<u8>>,
    to_guest: VecDeque<Vec<u8>>,
}

impl phy::Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.to_guest.pop_front()?;
        Some((Rx(frame), Tx(&mut self.to_stack)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.to_stack))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = FRAME_MTU;
        caps
    }
}

struct Rx(Vec<u8>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.push_back(frame);
        result
    }
}

/// The stack, a guest in front of it, and the net thread behind it.
struct Rig {
    h: Harness,
    events: FakeEventLoop,
    iface: Interface,
    wire: Wire,
    sockets: SocketSet<'static>,
    epoch: Instant,
    next_port: u16,
}

impl Rig {
    fn new(h: Harness) -> Rig {
        let mut wire = Wire::default();
        let mut config = Config::new(HardwareAddress::Ethernet(GUEST_MAC));
        config.random_seed = 0x5eed;
        let mut iface = Interface::new(config, &mut wire, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(GUEST.into(), 24)).unwrap());
        iface.routes_mut().add_default_ipv4_route(GATEWAY).unwrap();
        Rig {
            h,
            events: FakeEventLoop::new(),
            iface,
            wire,
            sockets: SocketSet::new(Vec::new()),
            epoch: Instant::now(),
            next_port: 40_000,
        }
    }

    fn clock(&self) -> SmolInstant {
        SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    /// A guest socket connecting to `dst`, and the guest's end of it.
    fn connect(&mut self, dst: SocketAddrV4) -> (SocketHandle, SocketAddrV4) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1 << 20]),
            tcp::SocketBuffer::new(vec![0; 1 << 20]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        self.next_port += 1;
        socket
            .connect(self.iface.context(), dst, self.next_port)
            .unwrap();
        (
            self.sockets.add(socket),
            SocketAddrV4::new(GUEST, self.next_port),
        )
    }

    fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(handle)
    }

    /// One round: the guest sends, the stack takes it and answers, the
    /// guest reads, and the host fds that are ready are handed over
    /// (waiting a little for one when nothing else moved).
    fn step(&mut self) {
        self.iface
            .poll(self.clock(), &mut self.wire, &mut self.sockets);
        let mut moved = false;
        while let Some(frame) = self.wire.to_stack.pop_front() {
            self.h.stack.push_guest_frame(&frame);
            moved = true;
        }
        let outcome = self.h.stack.poll(Instant::now());
        self.events.apply(&outcome.fd_changes);
        while let Some(frame) = self.h.stack.pop_host_frame() {
            self.wire.to_guest.push_back(frame);
            moved = true;
        }
        self.iface
            .poll(self.clock(), &mut self.wire, &mut self.sockets);
        let wait = if moved || !self.wire.to_stack.is_empty() {
            Duration::ZERO
        } else {
            Duration::from_millis(2)
        };
        self.events.dispatch(&mut self.h.stack, wait);
    }

    /// Steps until `done`, failing after `limit`.
    fn until(&mut self, limit: Duration, what: &str, mut done: impl FnMut(&mut Rig) -> bool) {
        let start = Instant::now();
        while !done(self) {
            assert!(start.elapsed() < limit, "timed out waiting for {what}");
            self.step();
        }
    }

    /// Steps until the stack holds no flow.
    fn settle(&mut self) {
        self.until(Duration::from_secs(10), "every flow to end", |rig| {
            rig.h.stack.open_flows() == 0
        });
    }

    /// Sends `bytes` on `handle` and steps until they have all gone.
    fn send(&mut self, handle: SocketHandle, bytes: &[u8]) {
        let mut at = 0;
        self.until(Duration::from_secs(10), "the guest's send", |rig| {
            let socket = rig.socket(handle);
            assert!(socket.is_open(), "the connection ended: {}", socket.state());
            if socket.can_send() {
                at += socket.send_slice(&bytes[at..]).unwrap();
            }
            at == bytes.len()
        });
    }

    /// Steps until `handle` has received `n` bytes, and returns them.
    fn recv(&mut self, handle: SocketHandle, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        self.until(Duration::from_secs(10), "the guest's receive", |rig| {
            let socket = rig.socket(handle);
            let mut buf = vec![0; n - got.len()];
            if socket.can_recv() {
                let k = socket.recv_slice(&mut buf).unwrap();
                got.extend_from_slice(&buf[..k]);
            }
            assert!(
                got.len() == n || socket.may_recv(),
                "the connection ended after {} bytes: {}",
                got.len(),
                socket.state()
            );
            got.len() == n
        });
        got
    }

    /// Steps until the host peer reports what it saw: the stack closes a
    /// host socket at the poll after the one that unwatched it.
    fn seen(&mut self, peer: &mpsc::Receiver<Seen>) -> Seen {
        let mut seen = None;
        self.until(Duration::from_secs(10), "the host peer", |_| {
            seen = peer.try_recv().ok();
            seen.is_some()
        });
        seen.unwrap()
    }

    /// Sends `bytes` and waits for them to come back.
    fn ping(&mut self, handle: SocketHandle, bytes: &[u8]) {
        self.send(handle, bytes);
        assert_eq!(self.recv(handle, bytes.len()), bytes);
    }

    /// Steps until the guest's socket is closed, and says whether a reset
    /// closed it: the guest's own side never closed, so only a reset gets
    /// it to Closed from Established.
    fn wait_reset(&mut self, handle: SocketHandle) {
        self.until(Duration::from_secs(10), "the guest's reset", |rig| {
            rig.socket(handle).state() == tcp::State::Closed
        });
    }

    fn events(self) -> Vec<Payload> {
        self.h.events()
    }
}

/// A listener that echoes every connection until EOF, then shuts down its
/// write side.
fn echo_server() -> SocketAddrV4 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = v4(listener.local_addr().unwrap());
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            thread::spawn(move || {
                let mut buf = vec![0; 64 * 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = conn.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// What a host peer saw of its one connection.
#[derive(Debug)]
struct Seen {
    bytes: Vec<u8>,
    /// How it ended: EOF, or a read error.
    end: Result<(), ErrorKind>,
}

/// A listener that takes one connection, answers `reply` once it has read
/// `reply_after` bytes, reads until the connection ends, and says what it
/// saw.
fn host_peer(reply_after: usize, reply: &'static [u8]) -> (SocketAddrV4, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = v4(listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        let mut replied = false;
        let end = loop {
            match conn.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    bytes.extend_from_slice(&buf[..n]);
                    if !replied && bytes.len() >= reply_after {
                        conn.write_all(reply).unwrap();
                        replied = true;
                    }
                }
                Err(e) => break Err(e.kind()),
            }
        };
        let _ = tx.send(Seen { bytes, end });
    });
    (addr, rx)
}

/// A listener on 127.0.0.1 whose accept queue is full, so a connect to it
/// gets no answer, and the sockets that keep it that way.
fn black_hole() -> (SocketAddrV4, Vec<Socket>) {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    listener
        .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    listener.listen(0).unwrap();
    let addr = listener.local_addr().unwrap().as_socket_ipv4().unwrap();
    let mut held = vec![listener];
    for _ in 0..16 {
        let client = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        match client.connect_timeout(&addr.into(), Duration::from_millis(250)) {
            Ok(()) => held.push(client),
            Err(_) => return (addr, held),
        }
    }
    panic!("the accept queue never filled");
}

/// A TLS 1.3-shaped ClientHello in one record, naming `sni` (if any) and
/// offering `alpn`.
fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    fn with_len16(body: Vec<u8>) -> Vec<u8> {
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend(body);
        out
    }
    let mut extensions = Vec::new();
    if let Some(name) = sni {
        let mut entry = vec![0];
        entry.extend(with_len16(name.as_bytes().to_vec()));
        extensions.extend(0_u16.to_be_bytes());
        extensions.extend(with_len16(with_len16(entry)));
    }
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for proto in alpn {
            list.push(proto.len() as u8);
            list.extend(proto.as_bytes());
        }
        extensions.extend(16_u16.to_be_bytes());
        extensions.extend(with_len16(with_len16(list)));
    }
    let mut body = vec![3, 3];
    body.extend([7; 32]);
    body.push(0);
    body.extend(with_len16(vec![0x13, 0x01]));
    body.extend([1, 0]);
    body.extend(with_len16(extensions));
    let mut handshake = vec![1];
    handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);
    let mut record = vec![22, 3, 1];
    record.extend(with_len16(handshake));
    record
}

fn connects(events: &[Payload]) -> Vec<NetConnect> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetConnect(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn tls(events: &[Payload]) -> Vec<NetTls> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetTls(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

fn closes(events: &[Payload]) -> Vec<NetClose> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetClose(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn connect_record(
    flow: u64,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    names: &[&str],
    verdict: Verdict,
    rule: Option<&str>,
) -> NetConnect {
    NetConnect {
        flow,
        proto: "tcp".into(),
        src,
        dst,
        names: names.iter().map(|n| n.to_string()).collect(),
        verdict,
        rule: rule.map(str::to_owned),
    }
}

fn tls_record(flow: u64, kind: &str, sni: Option<&str>, alpn: &[&str], verdict: Verdict) -> NetTls {
    NetTls {
        flow,
        kind: kind.into(),
        sni: sni.map(str::to_owned),
        alpn: alpn.iter().map(|a| a.to_string()).collect(),
        verdict,
    }
}

/// The close records' flows, byte counts and reasons (not their
/// durations).
fn close_summary(events: &[Payload]) -> Vec<(u64, u64, u64, String)> {
    closes(events)
        .into_iter()
        .map(|c| (c.flow, c.tx, c.rx, c.reason))
        .collect()
}

#[test]
fn an_allowed_connection_echoes_10_mib_intact() {
    const TOTAL: u64 = 10 << 20;
    let server = echo_server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    let (s, guest) = rig.connect(server);
    let (mut sent, mut got, mut closed) = (0_u64, 0_u64, false);
    let mut buf = vec![0; 64 * 1024];
    rig.until(Duration::from_secs(120), "the echo", |rig| {
        let socket = rig.socket(s);
        assert!(
            socket.state() != tcp::State::Closed,
            "the connection was reset after {sent} bytes out and {got} back"
        );
        while sent < TOTAL && socket.can_send() {
            let n = (TOTAL - sent).min(buf.len() as u64) as usize;
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = pattern(sent + i as u64);
            }
            let k = socket.send_slice(&buf[..n]).unwrap();
            sent += k as u64;
            if k < n {
                break;
            }
        }
        if sent == TOTAL && !closed {
            socket.close();
            closed = true;
        }
        while socket.can_recv() {
            let k = socket.recv_slice(&mut buf).unwrap();
            for (i, b) in buf[..k].iter().enumerate() {
                assert_eq!(*b, pattern(got + i as u64), "byte {}", got + i as u64);
            }
            got += k as u64;
        }
        got == TOTAL && !socket.may_recv()
    });
    rig.settle();
    assert_eq!(rig.events.flows_watched(), 0, "every host fd unwatched");

    let events = rig.events();
    assert_eq!(
        connects(&events),
        [connect_record(
            1,
            guest,
            server,
            &[],
            Verdict::Allow,
            Some("allow 127.0.0.0/8")
        )]
    );
    assert!(tls(&events).is_empty(), "a network rule is not gated");
    assert_eq!(close_summary(&events), [(1, TOTAL, TOTAL, "fin".into())]);
    assert!(drops(&events).is_empty(), "{:?}", drops(&events));
}

#[test]
fn a_denied_destination_gets_rst_and_an_event() {
    let mut h = harness_with(policy(&["allow example.com", "default deny"]));
    h.stack.poll(Instant::now());
    let guest = SocketAddrV4::new(GUEST, 40_000);
    let far = SocketAddrV4::new(Ipv4Addr::new(93, 184, 215, 14), 443);
    h.stack.push_guest_frame(&syn(guest, far, 1000));
    let frames = h.drain();
    assert_eq!(frames.len(), 1, "one reset, at once");
    assert_eq!(
        segment(&frames[0]).unwrap(),
        Segment {
            src: far,
            dst: guest,
            syn: false,
            ack: true,
            rst: true,
            fin: false,
            seq: 0,
            ack_number: 1001,
            window: 0,
            payload: Vec::new(),
        }
    );

    // The gateway is never a destination, and the sequence number wraps.
    let guest_b = SocketAddrV4::new(GUEST, 40_001);
    let gateway = SocketAddrV4::new(GATEWAY, 80);
    h.stack.push_guest_frame(&syn(guest_b, gateway, -1));
    let frames = h.drain();
    assert_eq!(frames.len(), 1);
    let reset = segment(&frames[0]).unwrap();
    assert!(reset.rst && reset.ack && !reset.syn);
    assert_eq!((reset.src, reset.dst), (gateway, guest_b));
    assert_eq!(reset.ack_number, 0, "u32::MAX + 1 wraps");

    // Nothing was handed to smoltcp, so nothing more comes.
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());
    assert_eq!(h.stack.open_flows(), 0);
    let events = h.events();
    assert_eq!(
        connects(&events),
        [
            connect_record(1, guest, far, &[], Verdict::Deny, None),
            connect_record(
                2,
                guest_b,
                gateway,
                &[],
                Verdict::Deny,
                Some("builtin:guest-net")
            ),
        ]
    );
    assert!(closes(&events).is_empty(), "no flow was opened");
    assert!(drops(&events).is_empty());

    // A guest's TCP takes the reset: its connect fails at once.
    let mut rig = Rig::new(harness_with(policy(&["default deny"])));
    let (s, _) = rig.connect(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443));
    rig.until(Duration::from_secs(2), "the guest's reset", |rig| {
        rig.socket(s).state() == tcp::State::Closed
    });
}

/// A stack whose DNS cache knows example.com as 127.0.0.1, under a policy
/// that allows example.com by name (so its flows are gated) and lifts the
/// loopback denial.
fn gated_rig() -> Rig {
    let mut h = harness_with(policy(&[
        "allow example.com",
        "allow 127.0.0.0/8",
        "default deny",
    ]));
    resolve(&mut h, "example.com", Ipv4Addr::LOCALHOST);
    Rig::new(h)
}

#[test]
fn sni_mismatch_resets_both_sides() {
    let (server, seen) = host_peer(1, b"never");
    let mut rig = gated_rig();
    let (s, guest) = rig.connect(server);
    let hello = client_hello(Some("evil.example"), &["h2"]);
    rig.send(s, &hello);
    rig.wait_reset(s);
    rig.settle();
    let seen = rig.seen(&seen);
    assert!(seen.bytes.is_empty(), "nothing reached the host: {seen:?}");
    assert_eq!(
        seen.end,
        Err(ErrorKind::ConnectionReset),
        "the host is reset"
    );

    let events = rig.events();
    assert_eq!(
        connects(&events),
        [connect_record(
            1,
            guest,
            server,
            &["example.com"],
            Verdict::Allow,
            Some("allow example.com")
        )]
    );
    assert_eq!(
        tls(&events),
        [tls_record(
            1,
            "tls",
            Some("evil.example"),
            &["h2"],
            Verdict::Deny
        )]
    );
    assert_eq!(close_summary(&events), [(1, 0, 0, "gate".into())]);
}

#[test]
fn sni_match_is_logged_and_forwarded() {
    let (server, seen) = host_peer(OPENSSL_CLIENT_HELLO.len(), b"pong");
    let mut rig = gated_rig();
    let (s, _) = rig.connect(server);
    rig.send(s, OPENSSL_CLIENT_HELLO);
    assert_eq!(rig.recv(s, 4), b"pong");
    rig.socket(s).close();
    rig.settle();
    let seen = rig.seen(&seen);
    assert_eq!(seen.bytes, OPENSSL_CLIENT_HELLO, "the hello, byte for byte");
    assert_eq!(seen.end, Ok(()));

    let events = rig.events();
    assert_eq!(
        tls(&events),
        [tls_record(
            1,
            "tls",
            Some("example.com"),
            &["h2", "http/1.1"],
            Verdict::Allow
        )]
    );
    assert_eq!(
        close_summary(&events),
        [(1, OPENSSL_CLIENT_HELLO.len() as u64, 4, "fin".into())]
    );
}

#[test]
fn plain_http_host_is_gated() {
    let mut rig = gated_rig();

    // A Host with a port, in any case, on any port.
    let reply = b"HTTP/1.1 204 No Content\r\n\r\n";
    let (server, seen) = host_peer(1, reply);
    let request = format!(
        "GET / HTTP/1.1\r\nHost: Example.COM:{}\r\nAccept: */*\r\n\r\n",
        server.port()
    );
    let (s, _) = rig.connect(server);
    rig.send(s, request.as_bytes());
    assert_eq!(rig.recv(s, reply.len()), reply);
    rig.socket(s).close();
    rig.settle();
    let seen = rig.seen(&seen);
    assert_eq!(seen.bytes, request.as_bytes());

    // Another name.
    let (server, seen) = host_peer(1, b"never");
    let (s, _) = rig.connect(server);
    rig.send(s, b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n");
    rig.wait_reset(s);
    rig.settle();
    let seen = rig.seen(&seen);
    assert!(seen.bytes.is_empty());
    assert_eq!(seen.end, Err(ErrorKind::ConnectionReset));

    // No name at all.
    let (server, seen) = host_peer(1, b"never");
    let (s, _) = rig.connect(server);
    rig.send(s, b"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n");
    rig.wait_reset(s);
    rig.settle();
    assert!(rig.seen(&seen).bytes.is_empty());

    let events = rig.events();
    assert_eq!(
        tls(&events),
        [
            tls_record(1, "http", Some("example.com"), &[], Verdict::Allow),
            tls_record(2, "http", Some("evil.example"), &[], Verdict::Deny),
            tls_record(3, "http", None, &[], Verdict::Deny),
        ]
    );
    assert_eq!(
        close_summary(&events),
        [
            (1, request.len() as u64, reply.len() as u64, "fin".into()),
            (2, 0, 0, "gate".into()),
            (3, 0, 0, "gate".into()),
        ]
    );
}

#[test]
fn connect_timeout_resets_the_guest_side() {
    let (server, _held) = black_hole();
    let mut rig = Rig::new(harness_config(policy(&["allow 127.0.0.0/8"]), |cfg| {
        cfg.tcp.connect_timeout = Duration::from_secs(2)
    }));
    let start = Instant::now();
    let (s, guest) = rig.connect(server);
    rig.until(Duration::from_secs(11), "the guest's reset", |rig| {
        rig.socket(s).state() == tcp::State::Closed
    });
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(1900), "{waited:?}");
    rig.settle();
    assert_eq!(
        rig.events.flows_watched(),
        0,
        "the connecting fd is unwatched"
    );

    let events = rig.events();
    assert_eq!(
        connects(&events),
        [connect_record(
            1,
            guest,
            server,
            &[],
            Verdict::Allow,
            Some("allow 127.0.0.0/8")
        )]
    );
    let closes = closes(&events);
    assert_eq!(close_summary(&events), [(1, 0, 0, "timeout".into())]);
    assert!(closes[0].dur_ms >= 1900, "{}", closes[0].dur_ms);
}

#[test]
fn flow_table_evicts_oldest_at_cap() {
    let server = echo_server();
    let mut rig = Rig::new(harness_config(policy(&["allow 127.0.0.0/8"]), |cfg| {
        cfg.tcp.flow_cap = 8
    }));
    let mut sockets = Vec::new();
    for i in 0..8 {
        let (s, _) = rig.connect(server);
        rig.ping(s, &[i]);
        sockets.push(s);
    }
    // The first flow is busy again, so the second is the idlest.
    rig.ping(sockets[0], b"again");
    assert_eq!(rig.h.stack.open_flows(), 8);

    let (ninth, _) = rig.connect(server);
    rig.ping(ninth, b"ninth");
    rig.wait_reset(sockets[1]);
    for (i, s) in sockets.iter().enumerate().filter(|(i, _)| *i != 1) {
        assert_eq!(rig.socket(*s).state(), tcp::State::Established, "flow {i}");
    }
    rig.ping(sockets[0], b"still here");
    assert_eq!(rig.h.stack.open_flows(), 8);

    let events = rig.events();
    assert_eq!(connects(&events).len(), 9);
    assert_eq!(close_summary(&events), [(2, 1, 1, "evicted".into())]);
}

#[test]
fn backpressure_when_the_host_stops_reading() {
    // A host peer that takes the connection and reads nothing until told,
    // with a small receive buffer.
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    listener.set_recv_buffer_size(4096).unwrap();
    listener
        .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    listener.listen(1).unwrap();
    let server = listener.local_addr().unwrap().as_socket_ipv4().unwrap();
    let (go, start_reading) = mpsc::channel::<()>();
    let (report, received) = mpsc::channel();
    thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        let mut conn = std::net::TcpStream::from(conn);
        start_reading.recv().unwrap();
        let mut buf = vec![0; 64 * 1024];
        let mut n = 0_u64;
        loop {
            match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    for (i, b) in buf[..k].iter().enumerate() {
                        assert_eq!(*b, pattern(n + i as u64), "byte {}", n + i as u64);
                    }
                    n += k as u64;
                }
                Err(e) => panic!("{e}"),
            }
        }
        report.send(n).unwrap();
    });

    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    let (s, _) = rig.connect(server);
    let mut sent = 0_u64;
    let mut buf = vec![0; 64 * 1024];
    let mut fill = |socket: &mut tcp::Socket, sent: &mut u64, limit: u64| {
        while *sent < limit && socket.can_send() {
            let n = (limit - *sent).min(buf.len() as u64) as usize;
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = pattern(*sent + i as u64);
            }
            let k = socket.send_slice(&buf[..n]).unwrap();
            *sent += k as u64;
            if k < n {
                break;
            }
        }
    };

    // The guest writes until it can write no more: the stack's window has
    // closed and stays closed.
    let mut still = 0;
    rig.until(
        Duration::from_secs(60),
        "the guest's window to close",
        |rig| {
            let socket = rig.socket(s);
            assert!(socket.is_open(), "{}", socket.state());
            let before = sent;
            fill(socket, &mut sent, u64::MAX);
            still = if sent == before { still + 1 } else { 0 };
            still >= 250
        },
    );
    let stalled = sent;
    let socket = rig.socket(s);
    assert_eq!(
        socket.send_queue(),
        socket.send_capacity(),
        "the guest's own buffer is full: the window is shut"
    );
    assert!(stalled < 64 << 20, "the stack buffers without bound");

    // The host reads again; nothing is lost.
    go.send(()).unwrap();
    let total = stalled + (1 << 20);
    let mut closed = false;
    rig.until(Duration::from_secs(60), "the rest", |rig| {
        let socket = rig.socket(s);
        fill(socket, &mut sent, total);
        if sent == total && !closed {
            socket.close();
            closed = true;
        }
        closed && socket.send_queue() == 0
    });
    let mut got = None;
    rig.until(Duration::from_secs(30), "the host to read it all", |_| {
        got = received.try_recv().ok();
        got.is_some()
    });
    assert_eq!(got, Some(total));
}

#[test]
fn backpressure_when_the_guest_stops_reading() {
    // A host peer that writes as fast as it may, counting what it got out.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = v4(listener.local_addr().unwrap());
    const TOTAL: u64 = 24 << 20;
    let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&written);
    thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = vec![0; 64 * 1024];
        let mut n = 0_u64;
        while n < TOTAL {
            let k = (TOTAL - n).min(buf.len() as u64) as usize;
            for (i, b) in buf[..k].iter_mut().enumerate() {
                *b = pattern(n + i as u64);
            }
            conn.write_all(&buf[..k]).unwrap();
            n += k as u64;
            counter.store(n, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    let (s, _) = rig.connect(server);
    rig.until(Duration::from_secs(10), "the connection", |rig| {
        rig.socket(s).state() == tcp::State::Established
    });
    // The guest reads nothing: the host's writes stop, and the stack does
    // not watch a socket it cannot read for (a level-triggered poller
    // would spin).
    let token = FLOW_TOKEN_BASE + 1;
    let mut last = 0;
    let mut still = 0;
    rig.until(
        Duration::from_secs(60),
        "the host's writes to stall",
        |rig| {
            // The guest's window is shut: its buffer is full.
            let socket = rig.socket(s);
            let shut = socket.recv_queue() == socket.recv_capacity();
            let now = written.load(std::sync::atomic::Ordering::SeqCst);
            still = if now == last && shut { still + 1 } else { 0 };
            last = now;
            still >= 250
        },
    );
    assert!(
        last < TOTAL,
        "the host wrote everything into a guest that reads nothing"
    );
    assert_eq!(
        rig.events.watching(token).map(|i| i.readable),
        None,
        "not watched while the guest's socket has no room"
    );
    // The guest reads it all, intact.
    let mut got = 0_u64;
    let mut buf = vec![0; 64 * 1024];
    rig.until(Duration::from_secs(60), "the rest", |rig| {
        let socket = rig.socket(s);
        while socket.can_recv() {
            let k = socket.recv_slice(&mut buf).unwrap();
            for (i, b) in buf[..k].iter().enumerate() {
                assert_eq!(*b, pattern(got + i as u64), "byte {}", got + i as u64);
            }
            got += k as u64;
        }
        got == TOTAL && !socket.may_recv()
    });
}

#[test]
fn pending_connects_are_bounded() {
    let (server, _held) = black_hole();
    let mut h = harness_config(policy(&["allow 127.0.0.0/8"]), |cfg| {
        cfg.tcp.pending_cap = 2
    });
    h.stack.poll(Instant::now());
    let guest = |port| SocketAddrV4::new(GUEST, port);
    for port in [40_000, 40_001, 40_002, 40_002] {
        h.stack.push_guest_frame(&syn(guest(port), server, 1));
    }
    assert!(h.drain().is_empty(), "nothing is answered: the third waits");
    assert_eq!(h.stack.open_flows(), 2);
    h.stack.shutdown();
    let events = h.events();
    let decided: Vec<u64> = connects(&events).iter().map(|c| c.flow).collect();
    assert_eq!(decided, [1, 2], "the dropped SYN is not decided");
    let dropped: Vec<(String, u64)> = drops(&events)
        .into_iter()
        .map(|d| (d.reason, d.count))
        .collect();
    assert_eq!(
        dropped,
        [
            ("tcp_pending_full".into(), 1),
            ("tcp_pending_full".into(), 1)
        ]
    );
    assert_eq!(
        close_summary(&events),
        [(1, 0, 0, "shutdown".into()), (2, 0, 0, "shutdown".into())]
    );
}

/// A gated rig whose gate is bounded by `change`.
fn gated_rig_with(change: impl FnOnce(&mut boxcar_net::TcpLimits)) -> Rig {
    let mut h = harness_config(policy(&["allow example.com", "allow 127.0.0.0/8"]), |cfg| {
        change(&mut cfg.tcp)
    });
    resolve(&mut h, "example.com", Ipv4Addr::LOCALHOST);
    Rig::new(h)
}

#[test]
fn the_gate_denies_at_its_byte_and_time_limits() {
    // Nothing in time.
    let mut rig = gated_rig_with(|tcp| tcp.gate_timeout = Duration::from_millis(300));
    let (server, seen) = host_peer(1, b"never");
    let start = Instant::now();
    let (s, _) = rig.connect(server);
    rig.wait_reset(s);
    assert!(start.elapsed() >= Duration::from_millis(300));
    assert!(rig.seen(&seen).bytes.is_empty());
    rig.settle();
    let events = rig.events();
    assert_eq!(
        tls(&events),
        [tls_record(1, "tls", None, &[], Verdict::Deny)]
    );
    assert_eq!(close_summary(&events), [(1, 0, 0, "gate".into())]);

    // Bytes past the limit, or a FIN, long before the time is up.
    let mut rig = gated_rig_with(|tcp| {
        tcp.gate_limit = 64;
        tcp.gate_timeout = Duration::from_secs(60);
    });
    let (server, seen) = host_peer(1, b"never");
    let (s, _) = rig.connect(server);
    rig.send(s, &b"GET /".repeat(13));
    rig.wait_reset(s);
    assert!(rig.seen(&seen).bytes.is_empty());

    let (server, seen) = host_peer(1, b"never");
    let (s, _) = rig.connect(server);
    let hello = client_hello(Some("example.com"), &[]);
    rig.send(s, &hello[..20]);
    rig.socket(s).close();
    rig.until(Duration::from_secs(10), "the guest's reset", |rig| {
        rig.socket(s).state() == tcp::State::Closed
    });
    assert!(rig.seen(&seen).bytes.is_empty());
    rig.settle();

    let events = rig.events();
    assert_eq!(
        tls(&events),
        [
            tls_record(1, "http", None, &[], Verdict::Deny),
            tls_record(2, "tls", None, &[], Verdict::Deny),
        ]
    );
    assert_eq!(
        close_summary(&events),
        [(1, 0, 0, "gate".into()), (2, 0, 0, "gate".into())]
    );
}

#[test]
fn resets_cross_both_ways() {
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));

    // The guest resets: the host is reset.
    let (server, seen) = host_peer(5, b"");
    let (s, _) = rig.connect(server);
    rig.send(s, b"hello");
    rig.until(Duration::from_secs(10), "the bytes to arrive", |rig| {
        rig.h.stack.open_flows() == 1 && rig.socket(s).send_queue() == 0
    });
    rig.socket(s).abort();
    let seen = rig.seen(&seen);
    assert_eq!(seen.bytes, b"hello");
    assert_eq!(seen.end, Err(ErrorKind::ConnectionReset));
    rig.settle();

    // The host resets: the guest is reset.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = v4(listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let (s, _) = rig.connect(server);
    let mut conn = None;
    rig.until(Duration::from_secs(10), "the connection", |rig| {
        conn = conn
            .take()
            .or_else(|| listener.accept().ok().map(|(c, _)| c));
        conn.is_some() && rig.socket(s).state() == tcp::State::Established
    });
    let conn = conn.unwrap();
    socket2::SockRef::from(&conn)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(conn);
    rig.wait_reset(s);
    rig.settle();
    assert_eq!(rig.events.flows_watched(), 0);

    let events = rig.events();
    assert_eq!(
        close_summary(&events),
        [(1, 5, 0, "reset".into()), (2, 0, 0, "reset".into())]
    );
}

#[test]
fn a_refused_connect_resets_the_guest() {
    // A port nothing listens on: bind one and let it go.
    let server = v4(TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap());
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    let (s, _) = rig.connect(server);
    rig.wait_reset(s);
    rig.settle();
    let events = rig.events();
    assert_eq!(connects(&events).len(), 1);
    assert_eq!(close_summary(&events), [(1, 0, 0, "refused".into())]);
}

#[test]
fn host_local_addresses_are_denied() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = v4(listener.local_addr().unwrap());
    let other_port = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local.port().wrapping_add(1));
    let public = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443);
    let mut h = harness_with(policy(&["allow 127.0.0.0/8"]));
    h.stack
        .set_host_addrs(HostAddrs::fixed(vec![Ipv4Addr::LOCALHOST, *public.ip()]));
    h.stack.poll(Instant::now());
    let guest = |port| SocketAddrV4::new(GUEST, port);
    let resets = |h: &mut Harness| {
        h.drain()
            .iter()
            .filter_map(|f| segment(f))
            .filter(|s| s.rst)
            .count()
    };

    // The range is lifted, but the host's own address is not.
    h.stack.push_guest_frame(&syn(guest(40_000), local, 1));
    assert_eq!(resets(&mut h), 1);
    // An exact /32 on that port lifts it, for that port only.
    h.policy.store(Arc::new(policy(&[
        "allow 127.0.0.0/8",
        &format!("allow 127.0.0.1:{}", local.port()),
    ])));
    h.stack.push_guest_frame(&syn(guest(40_001), local, 1));
    assert_eq!(resets(&mut h), 0, "allowed: the connect is under way");
    h.stack.push_guest_frame(&syn(guest(40_002), other_port, 1));
    assert_eq!(resets(&mut h), 1);
    // Default allow does not reach it either.
    h.policy.store(Arc::new(Policy::allow_all()));
    h.stack.push_guest_frame(&syn(guest(40_003), public, 1));
    assert_eq!(resets(&mut h), 1);

    let events = h.events();
    let host_local = Some(BUILTIN_HOST_LOCAL);
    assert_eq!(
        connects(&events),
        [
            connect_record(1, guest(40_000), local, &[], Verdict::Deny, host_local),
            connect_record(
                2,
                guest(40_001),
                local,
                &[],
                Verdict::Allow,
                Some("allow 127.0.0.0/8")
            ),
            connect_record(3, guest(40_002), other_port, &[], Verdict::Deny, host_local),
            connect_record(4, guest(40_003), public, &[], Verdict::Deny, host_local),
        ]
    );
    drop(listener);
}

#[test]
fn syn_retransmits_while_pending_are_dropped_silently() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = v4(listener.local_addr().unwrap());
    let mut h = harness_with(policy(&["allow 127.0.0.0/8"]));
    let mut events = FakeEventLoop::new();
    events.apply(&h.stack.poll(Instant::now()).fd_changes);
    h.stack.push_guest_frame(&guest_arp());
    assert_eq!(h.drain().len(), 1, "the ARP reply");

    let guest = SocketAddrV4::new(GUEST, 40_000);
    for _ in 0..3 {
        h.stack.push_guest_frame(&syn(guest, server, 7000));
        events.apply(&h.stack.poll(Instant::now()).fd_changes);
    }
    assert!(
        h.drain().is_empty(),
        "nothing for the guest while the host connect is under way"
    );
    let token = FLOW_TOKEN_BASE + 1;
    assert_eq!(
        events.watching(token),
        Some(Interest {
            readable: false,
            writable: true
        }),
        "the connecting socket is watched for writability"
    );

    // The host connect completes: the parked SYN is answered.
    let mut frames = Vec::new();
    let start = Instant::now();
    while frames.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no SYN-ACK");
        events.dispatch(&mut h.stack, Duration::from_millis(50));
        events.apply(&h.stack.poll(Instant::now()).fd_changes);
        frames = h.drain();
    }
    assert_eq!(frames.len(), 1);
    let syn_ack = segment(&frames[0]).unwrap();
    assert!(syn_ack.syn && syn_ack.ack && !syn_ack.rst);
    assert_eq!((syn_ack.src, syn_ack.dst), (server, guest));
    assert_eq!(syn_ack.ack_number, 7001);

    // A late retransmit is dropped too.
    h.stack.push_guest_frame(&syn(guest, server, 7000));
    events.apply(&h.stack.poll(Instant::now()).fd_changes);
    assert!(h.drain().is_empty());

    h.stack.shutdown();
    let events = h.events();
    assert_eq!(
        connects(&events),
        [connect_record(
            1,
            guest,
            server,
            &[],
            Verdict::Allow,
            Some("allow 127.0.0.0/8")
        )]
    );
    assert!(drops(&events).is_empty(), "{:?}", drops(&events));
    assert_eq!(close_summary(&events), [(1, 0, 0, "shutdown".into())]);
    drop(listener);
}

#[test]
fn a_real_client_hello_reads() {
    assert_eq!(
        parse_client_hello(OPENSSL_CLIENT_HELLO),
        Hello::Tls {
            sni: Some("example.com".into()),
            alpn: vec!["h2".into(), "http/1.1".into()],
        }
    );
    for cut in 0..OPENSSL_CLIENT_HELLO.len() {
        assert_eq!(
            parse_client_hello(&OPENSSL_CLIENT_HELLO[..cut]),
            Hello::NeedMore,
            "cut at {cut}"
        );
    }
    // What follows the record does not matter.
    let mut more = OPENSSL_CLIENT_HELLO.to_vec();
    more.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xff]);
    assert!(matches!(parse_client_hello(&more), Hello::Tls { .. }));
    // Not a handshake record.
    let mut other = OPENSSL_CLIENT_HELLO.to_vec();
    other[0] = 0x17;
    assert_eq!(parse_client_hello(&other), Hello::NotTls);
    assert_eq!(
        parse_client_hello(&client_hello(None, &[])),
        Hello::Tls {
            sni: None,
            alpn: Vec::new()
        }
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn parse_client_hello_never_panics(
        noise in vec(any::<u8>(), 0..2048),
        flips in vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
        cut in any::<prop::sample::Index>(),
    ) {
        parse_client_hello(&noise);
        // The real hello, with some bytes changed and cut short.
        let mut hello = OPENSSL_CLIENT_HELLO.to_vec();
        for (at, byte) in &flips {
            let i = at.index(hello.len());
            hello[i] = *byte;
        }
        parse_client_hello(&hello);
        parse_client_hello(&hello[..cut.index(hello.len() + 1)]);
        // A record header that admits the noise.
        let mut framed = vec![22, 3, 1];
        framed.extend((noise.len() as u16).to_be_bytes());
        framed.extend(&noise);
        parse_client_hello(&framed);
    }
}
