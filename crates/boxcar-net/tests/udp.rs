// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The UDP relay end to end, on raw guest frames. Behind the stack, a
//! `UdpSocket` on 127.0.0.1 plays the far end, which the test policies
//! allow with `allow 127.0.0.0/8` (the exact range lifts the built-in
//! denial), and a [`FakeEventLoop`] over poll(2) plays the net thread,
//! watching the fds the stack asks for. The audit log says what was
//! decided and how each mapping ended. Time passing for the stack is an
//! injected `now`.

mod common;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use boxcar_net::policy::{BUILTIN_GUEST_NET, BUILTIN_PRIVATE, BUILTIN_UDP_NEEDS_CIDR};
use boxcar_net::upstream::{HostAddrs, BUILTIN_HOST_LOCAL};
use boxcar_net::{Interest, Policy, PollOutcome, Verdict, UDP_TOKEN_BASE};
use boxcar_proto::{NetConnect, NetUdp, Payload};
use common::{
    drops, harness_config, harness_with, resolve, syn, udp, FakeEventLoop, Harness, GATEWAY,
    GATEWAY_MAC, GUEST, GUEST_MAC,
};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};

/// How long a mapping may go unused (the default).
const IDLE: Duration = Duration::from_secs(60);

/// The largest reply that fits the link: 1500 bytes of IP, less the IPv4
/// and UDP headers.
const MAX_REPLY: usize = 1472;

fn policy(lines: &[&str]) -> Policy {
    Policy::parse(lines).unwrap()
}

fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => panic!("{addr} is not IPv4"),
    }
}

fn guest(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(GUEST, port)
}

/// A UDP datagram the stack sent the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Datagram {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: Vec<u8>,
}

/// `frame` as a UDP datagram the stack sent the guest, after checking the
/// Ethernet addresses, both checksums (the UDP one present), and that the
/// frame fits the link; `None` if it is not UDP.
fn datagram(frame: &[u8]) -> Option<Datagram> {
    assert!(
        frame.len() <= 1514,
        "{} bytes do not fit the link",
        frame.len()
    );
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!((eth.src_addr(), eth.dst_addr()), (GATEWAY_MAC, GUEST_MAC));
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let checks = ChecksumCapabilities::default();
    let packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let ip = Ipv4Repr::parse(&packet, &checks).unwrap();
    if ip.next_header != IpProtocol::Udp {
        return None;
    }
    let packet = UdpPacket::new_checked(packet.payload()).unwrap();
    assert_ne!(packet.checksum(), 0, "the UDP checksum is given");
    let ports = UdpRepr::parse(&packet, &ip.src_addr.into(), &ip.dst_addr.into(), &checks)
        .expect("a correct UDP checksum");
    Some(Datagram {
        src: SocketAddrV4::new(ip.src_addr, ports.src_port),
        dst: SocketAddrV4::new(ip.dst_addr, ports.dst_port),
        payload: packet.payload().to_vec(),
    })
}

/// A server on 127.0.0.1: the far end of the guest's datagrams.
fn server() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let at = v4(socket.local_addr().unwrap());
    (socket, at)
}

/// The next datagram `server` got, and where from.
fn recv(server: &UdpSocket) -> (Vec<u8>, SocketAddrV4) {
    let mut buf = [0; 2048];
    let (n, from) = server.recv_from(&mut buf).expect("a datagram");
    (buf[..n].to_vec(), v4(from))
}

/// Whether `server` has nothing waiting (it has had a few ms for anything
/// on its way: loopback delivers within the sender's call).
fn nothing_at(server: &UdpSocket) -> bool {
    thread::sleep(Duration::from_millis(3));
    server.set_nonblocking(true).unwrap();
    let mut buf = [0; 2048];
    let got = server.recv_from(&mut buf);
    server.set_nonblocking(false).unwrap();
    matches!(got, Err(e) if e.kind() == ErrorKind::WouldBlock)
}

fn udps(events: &[Payload]) -> Vec<NetUdp> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetUdp(u) => Some(u.clone()),
            _ => None,
        })
        .collect()
}

/// Each `net.close`'s flow, bytes each way and reason (its duration
/// aside).
fn closes(events: &[Payload]) -> Vec<(u64, u64, u64, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetClose(c) => Some((c.flow, c.tx, c.rx, c.reason.clone())),
            _ => None,
        })
        .collect()
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

/// The `net.drop` counts for `reason`, summed.
fn dropped(events: &[Payload], reason: &str) -> u64 {
    drops(events)
        .iter()
        .filter(|d| d.reason == reason)
        .map(|d| d.count)
        .sum()
}

fn net_udp(
    flow: u64,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    names: &[&str],
    verdict: Verdict,
    rule: Option<&str>,
) -> NetUdp {
    NetUdp {
        flow,
        src,
        dst,
        names: names.iter().map(|n| (*n).to_owned()).collect(),
        verdict,
        rule: rule.map(str::to_owned),
    }
}

/// The stack, and the net thread behind it.
struct Rig {
    h: Harness,
    events: FakeEventLoop,
}

impl Rig {
    fn new(h: Harness) -> Rig {
        let mut rig = Rig {
            h,
            events: FakeEventLoop::new(),
        };
        rig.poll(Instant::now());
        rig
    }

    /// The guest sends `payload` from its port `port` to `dst`.
    fn send(&mut self, port: u16, dst: SocketAddrV4, payload: &[u8]) {
        self.h
            .stack
            .push_guest_frame(&udp(GATEWAY_MAC, guest(port), dst, payload));
    }

    /// Polls the stack at `now`, and starts and stops watching fds as it
    /// asks.
    fn poll(&mut self, now: Instant) -> PollOutcome {
        let outcome = self.h.stack.poll(now);
        self.events.apply(&outcome.fd_changes);
        outcome
    }

    /// The UDP datagrams the stack has sent the guest.
    fn received(&mut self) -> Vec<Datagram> {
        self.h.drain().iter().filter_map(|f| datagram(f)).collect()
    }

    /// Polls and hands over ready host fds until the guest has received
    /// `n` datagrams, and returns them.
    fn receive(&mut self, n: usize) -> Vec<Datagram> {
        let start = Instant::now();
        let mut got = Vec::new();
        loop {
            self.poll(Instant::now());
            got.extend(self.received());
            if got.len() >= n {
                return got;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the guest got {} of {n} datagrams",
                got.len()
            );
            self.events
                .dispatch(&mut self.h.stack, Duration::from_millis(2));
        }
    }

    /// Hands over what host fds are ready within a few ms, and polls.
    fn settle(&mut self) {
        for _ in 0..3 {
            self.events
                .dispatch(&mut self.h.stack, Duration::from_millis(2));
            self.poll(Instant::now());
        }
    }

    fn events(self) -> Vec<Payload> {
        self.h.events()
    }
}

/// The guest's datagrams reach the server from one host port for each
/// 5-tuple, and the server's replies come back to the guest from the
/// server's address with both checksums right. Each mapping is recorded
/// once, closed once, and takes its flow id from the count TCP's flows use.
#[test]
fn an_allowed_udp_flow_round_trips_to_a_local_echo() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8", "default deny"])));
    // A denied SYN is flow 1.
    let blocked = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);
    rig.h
        .stack
        .push_guest_frame(&syn(guest(39_999), blocked, 1));
    rig.h.drain();

    rig.send(40_001, at, b"ping one");
    let (got, from) = recv(&server);
    assert_eq!(got, b"ping one");
    assert_eq!(*from.ip(), Ipv4Addr::LOCALHOST);
    rig.poll(Instant::now());
    assert_eq!(
        rig.events.watching(UDP_TOKEN_BASE + 2),
        Some(Interest {
            readable: true,
            writable: false,
        }),
        "flow 2's host socket is watched for replies"
    );
    server.send_to(b"pong one", from).unwrap();
    assert_eq!(
        rig.receive(1),
        [Datagram {
            src: at,
            dst: guest(40_001),
            payload: b"pong one".to_vec(),
        }]
    );

    // The same tuple again: the same mapping, from the same host port.
    rig.send(40_001, at, b"ping two");
    assert_eq!(recv(&server), (b"ping two".to_vec(), from));
    // Another guest port: a mapping of its own.
    rig.send(40_002, at, b"ping three");
    let (got, other) = recv(&server);
    assert_eq!(got, b"ping three");
    assert_ne!(other, from);
    server.send_to(b"pong three!", other).unwrap();
    server.send_to(b"pong one again", from).unwrap();
    let mut back = rig.receive(2);
    back.sort_by_key(|d| d.dst.port());
    assert_eq!(
        back,
        [
            Datagram {
                src: at,
                dst: guest(40_001),
                payload: b"pong one again".to_vec(),
            },
            Datagram {
                src: at,
                dst: guest(40_002),
                payload: b"pong three!".to_vec(),
            },
        ]
    );
    assert_eq!(rig.h.stack.udp_mappings(), 2);
    assert_eq!(rig.events.udp_watched(), 2);

    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(connects(&events).len(), 1);
    assert_eq!(connects(&events)[0].flow, 1);
    let rule = Some("allow 127.0.0.0/8");
    assert_eq!(
        udps(&events),
        [
            net_udp(2, guest(40_001), at, &[], Verdict::Allow, rule),
            net_udp(3, guest(40_002), at, &[], Verdict::Allow, rule),
        ]
    );
    assert_eq!(
        closes(&events),
        [
            (2, 16, 22, "shutdown".to_owned()),
            (3, 10, 11, "shutdown".to_owned()),
        ]
    );
    assert!(drops(&events).is_empty(), "{:?}", drops(&events));
}

/// Under `default deny`, UDP that no rule allows is dropped: to an address
/// only the default decides, to the gateway on a port other than DNS
/// (`builtin:guest-net`), and to a private address no rule lifts
/// (`builtin:private`). Each gets one `net.udp{deny}`, and no host socket,
/// datagram or reply.
#[test]
fn default_deny_drops_udp_with_an_event() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(Policy::default()));
    let public = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 123);
    let gateway = SocketAddrV4::new(GATEWAY, 123);
    rig.send(40_001, public, b"ntp");
    rig.send(40_002, gateway, b"ntp");
    rig.send(40_003, at, b"hello");
    rig.settle();
    assert!(rig.received().is_empty(), "no reply");
    assert_eq!(rig.h.stack.udp_mappings(), 0);
    assert_eq!(rig.events.udp_watched(), 0);
    assert!(nothing_at(&server), "nothing reached the server");

    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(
        udps(&events),
        [
            net_udp(1, guest(40_001), public, &[], Verdict::Deny, None),
            net_udp(
                2,
                guest(40_002),
                gateway,
                &[],
                Verdict::Deny,
                Some(BUILTIN_GUEST_NET)
            ),
            net_udp(
                3,
                guest(40_003),
                at,
                &[],
                Verdict::Deny,
                Some(BUILTIN_PRIVATE)
            ),
        ]
    );
    assert!(closes(&events).is_empty(), "no mapping was made");
    assert!(drops(&events).is_empty(), "{:?}", drops(&events));
}

/// A mapping no datagram has used for a minute is closed by the poll that
/// finds it so (`net.close{idle}`), its host socket unwatched in that
/// poll's outcome and closed at the next. The next datagram on its tuple
/// is a new mapping, decided and recorded again.
#[test]
fn idle_mappings_expire() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, at, b"one");
    let start = Instant::now();
    assert_eq!(recv(&server).0, b"one");
    let token = UDP_TOKEN_BASE + 1;

    let outcome = rig.poll(start);
    let due = outcome.next_deadline.expect("the mapping's expiry");
    assert!(
        due <= start + IDLE && due + Duration::from_secs(5) > start + IDLE,
        "due {:?} after the datagram, not a minute",
        due.saturating_duration_since(start)
    );
    assert!(rig.events.watching(token).is_some());

    // A second short of the minute: still there.
    rig.poll(start + IDLE - Duration::from_secs(1));
    assert_eq!(rig.h.stack.udp_mappings(), 1);
    assert!(rig.events.watching(token).is_some());

    // A minute on: closed, and unwatched by the same outcome.
    let outcome = rig.poll(start + IDLE);
    assert_eq!(rig.h.stack.udp_mappings(), 0);
    assert_eq!(rig.events.watching(token), None);
    assert_eq!(
        outcome.next_deadline,
        Some(start + IDLE),
        "at once: the socket closes at the next poll"
    );
    let outcome = rig.poll(start + IDLE);
    assert_eq!(outcome.next_deadline, None, "nothing left to wait for");

    // The tuple again: a new mapping.
    rig.send(40_001, at, b"two");
    assert_eq!(recv(&server).0, b"two");
    rig.poll(Instant::now());
    assert!(rig.events.watching(UDP_TOKEN_BASE + 2).is_some());

    rig.h.stack.shutdown();
    let events = rig.events();
    let rule = Some("allow 127.0.0.0/8");
    assert_eq!(
        udps(&events),
        [
            net_udp(1, guest(40_001), at, &[], Verdict::Allow, rule),
            net_udp(2, guest(40_001), at, &[], Verdict::Allow, rule),
        ]
    );
    assert_eq!(
        closes(&events),
        [
            (1, 3, 0, "idle".to_owned()),
            (2, 3, 0, "shutdown".to_owned()),
        ]
    );
    let idle = events
        .iter()
        .find_map(|e| match e {
            Payload::NetClose(c) if c.reason == "idle" => Some(c.dur_ms),
            _ => None,
        })
        .unwrap();
    assert!(
        (60_000..65_000).contains(&idle),
        "lasted a minute: {idle} ms"
    );
}

/// At the cap, a new mapping evicts the one idle longest (by its last
/// datagram either way), which is closed `evicted` and unwatched; the
/// others carry on.
#[test]
fn mapping_table_evicts_idle_longest_at_cap() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_config(policy(&["allow 127.0.0.0/8"]), |c| {
        c.udp.mapping_cap = 4;
    }));
    let mut from = Vec::new();
    for n in 1..=4_u8 {
        rig.send(40_000 + u16::from(n), at, &[n]);
        from.push(recv(&server).1);
        thread::sleep(Duration::from_millis(2));
    }
    // Flow 1 hears back, so flow 2 is the one idle longest.
    rig.poll(Instant::now());
    server.send_to(b"back", from[0]).unwrap();
    assert_eq!(rig.receive(1)[0].dst, guest(40_001));
    thread::sleep(Duration::from_millis(2));

    rig.send(40_005, at, b"five");
    assert_eq!(recv(&server).0, b"five");
    rig.poll(Instant::now());
    assert_eq!(rig.h.stack.udp_mappings(), 4);
    assert_eq!(
        rig.events.watching(UDP_TOKEN_BASE + 2),
        None,
        "flow 2 evicted"
    );
    for flow in [1, 3, 4, 5] {
        assert!(
            rig.events.watching(UDP_TOKEN_BASE + flow).is_some(),
            "flow {flow}"
        );
    }
    // Flow 1 still carries both ways, from its own host port.
    rig.send(40_001, at, b"still");
    assert_eq!(recv(&server), (b"still".to_vec(), from[0]));
    server.send_to(b"here", from[0]).unwrap();
    assert_eq!(
        rig.receive(1),
        [Datagram {
            src: at,
            dst: guest(40_001),
            payload: b"here".to_vec(),
        }]
    );
    // Flow 2's tuple again: a new mapping, which evicts flow 3.
    thread::sleep(Duration::from_millis(2));
    rig.send(40_002, at, b"two again");
    assert_eq!(recv(&server).0, b"two again");
    rig.poll(Instant::now());
    assert_eq!(rig.h.stack.udp_mappings(), 4);
    assert_eq!(rig.events.watching(UDP_TOKEN_BASE + 3), None);
    assert_eq!(rig.events.udp_watched(), 4);

    rig.h.stack.shutdown();
    let events = rig.events();
    let flows: Vec<(u64, u16)> = udps(&events)
        .iter()
        .map(|u| (u.flow, u.src.port()))
        .collect();
    assert_eq!(
        flows,
        [
            (1, 40_001),
            (2, 40_002),
            (3, 40_003),
            (4, 40_004),
            (5, 40_005),
            (6, 40_002)
        ]
    );
    let mut ended: Vec<(u64, String)> = closes(&events)
        .into_iter()
        .map(|(flow, _, _, reason)| (flow, reason))
        .collect();
    ended.sort();
    let want: Vec<(u64, String)> = [
        (1, "shutdown"),
        (2, "evicted"),
        (3, "evicted"),
        (4, "shutdown"),
        (5, "shutdown"),
        (6, "shutdown"),
    ]
    .into_iter()
    .map(|(flow, reason)| (flow, reason.to_owned()))
    .collect();
    assert_eq!(ended, want);
}

/// An address a domain rule allows is not reachable over UDP: no name can
/// be checked on a datagram, so the domain rule's allow is a deny
/// (`builtin:udp-needs-cidr`). A network rule that decides first admits
/// it.
#[test]
fn domain_rules_do_not_admit_udp() {
    let (server, at) = server();
    let mut h = harness_with(policy(&["allow echo.test", "allow 127.0.0.0/8"]));
    resolve(&mut h, "echo.test", *at.ip());
    let mut rig = Rig::new(h);
    rig.send(40_001, at, b"by name");
    rig.settle();
    assert_eq!(rig.h.stack.udp_mappings(), 0);
    assert!(nothing_at(&server), "nothing reached the server");

    // With the network rule first, it decides.
    rig.h
        .policy
        .store(Arc::new(policy(&["allow 127.0.0.0/8", "allow echo.test"])));
    rig.send(40_002, at, b"by address");
    assert_eq!(recv(&server).0, b"by address");

    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(
        udps(&events),
        [
            net_udp(
                1,
                guest(40_001),
                at,
                &["echo.test"],
                Verdict::Deny,
                Some(BUILTIN_UDP_NEEDS_CIDR)
            ),
            net_udp(
                2,
                guest(40_002),
                at,
                &["echo.test"],
                Verdict::Allow,
                Some("allow 127.0.0.0/8")
            ),
        ]
    );
}

/// A reply larger than one datagram on the link (1472 bytes of payload)
/// is dropped (`udp_oversize`), not fragmented; the largest that fits goes
/// through, and the mapping stays.
#[test]
fn oversize_replies_are_dropped() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, at, b"big?");
    let (_, from) = recv(&server);
    rig.poll(Instant::now());
    server.send_to(&[0xaa; 1600], from).unwrap();
    server.send_to(&[0xbb; MAX_REPLY + 1], from).unwrap();
    server.send_to(&[0xcc; MAX_REPLY], from).unwrap();
    let got = rig.receive(1);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].payload, vec![0xcc; MAX_REPLY]);
    rig.settle();
    assert!(rig.received().is_empty());

    rig.send(40_001, at, b"still there");
    assert_eq!(recv(&server), (b"still there".to_vec(), from));
    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(dropped(&events, "udp_oversize"), 2);
    assert_eq!(
        closes(&events),
        [(1, 15, MAX_REPLY as u64, "shutdown".to_owned())]
    );
}

/// A denied 5-tuple is recorded once; its later datagrams are counted as
/// `udp_denied` and not recorded. Another tuple is decided on its own.
#[test]
fn denied_tuples_are_recorded_once_then_counted() {
    let mut rig = Rig::new(harness_with(Policy::default()));
    let dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9);
    for _ in 0..5 {
        rig.send(40_001, dst, b"x");
    }
    rig.send(40_002, dst, b"y");
    rig.send(40_002, dst, b"y");
    rig.poll(Instant::now());
    assert!(rig.received().is_empty());
    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(
        udps(&events),
        [
            net_udp(1, guest(40_001), dst, &[], Verdict::Deny, None),
            net_udp(2, guest(40_002), dst, &[], Verdict::Deny, None),
        ]
    );
    let reasons: Vec<String> = drops(&events).into_iter().map(|d| d.reason).collect();
    assert!(reasons.iter().all(|r| r == "udp_denied"), "{reasons:?}");
    assert_eq!(dropped(&events, "udp_denied"), 5);
}

/// A tuple denied under one policy is decided again under the next: a
/// swapped policy that allows it opens a mapping at its next datagram.
#[test]
fn a_swapped_policy_decides_a_denied_tuple_again() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(Policy::default()));
    rig.send(40_001, at, b"no");
    rig.send(40_001, at, b"no");
    assert!(nothing_at(&server));
    rig.h.policy.store(Arc::new(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, at, b"yes");
    assert_eq!(recv(&server).0, b"yes");
    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(
        udps(&events),
        [
            net_udp(
                1,
                guest(40_001),
                at,
                &[],
                Verdict::Deny,
                Some(BUILTIN_PRIVATE)
            ),
            net_udp(
                2,
                guest(40_001),
                at,
                &[],
                Verdict::Allow,
                Some("allow 127.0.0.0/8")
            ),
        ]
    );
    assert_eq!(dropped(&events, "udp_denied"), 1);
}

/// One of the host's own addresses is denied (`builtin:host-local`) as for
/// TCP, unless a rule names exactly that address.
#[test]
fn host_local_addresses_are_denied() {
    let (server, at) = server();
    let mut h = harness_with(policy(&["allow 127.0.0.0/8"]));
    h.stack.set_host_addrs(HostAddrs::fixed(vec![*at.ip()]));
    let mut rig = Rig::new(h);
    rig.send(40_001, at, b"host");
    assert!(nothing_at(&server));
    rig.h.policy.store(Arc::new(policy(&[
        &format!("allow {}", at.ip()),
        "allow 127.0.0.0/8",
    ])));
    rig.send(40_002, at, b"named");
    assert_eq!(recv(&server).0, b"named");
    rig.h.stack.shutdown();
    let events = rig.events();
    let verdicts: Vec<(Verdict, Option<String>)> = udps(&events)
        .into_iter()
        .map(|u| (u.verdict, u.rule))
        .collect();
    assert_eq!(
        verdicts,
        [
            (Verdict::Deny, Some(BUILTIN_HOST_LOCAL.to_owned())),
            (Verdict::Allow, Some(format!("allow {}", at.ip()))),
        ]
    );
}

/// The host's kernel answering a datagram with port unreachable
/// (`ECONNREFUSED` on the mapping's socket) ends nothing: the error is
/// read and dropped, and when the port opens the mapping carries on, from
/// the same host port.
#[test]
fn a_refused_port_keeps_its_mapping() {
    // A port nothing listens on: bind one and let it go.
    let closed = {
        let (socket, at) = server();
        drop(socket);
        at
    };
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, closed, b"anyone?");
    rig.poll(Instant::now());
    let token = UDP_TOKEN_BASE + 1;
    // The refusal is waiting on the socket.
    let start = Instant::now();
    while !rig
        .events
        .wait(Duration::from_millis(2))
        .iter()
        .any(|(t, ..)| *t == token)
    {
        assert!(start.elapsed() < Duration::from_secs(5), "no refusal");
    }
    // A datagram sent with the refusal pending still goes.
    rig.send(40_001, closed, b"again?");
    rig.settle();
    assert_eq!(rig.h.stack.udp_mappings(), 1);
    assert!(rig.events.watching(token).is_some());

    let server = UdpSocket::bind(SocketAddr::V4(closed)).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    rig.send(40_001, closed, b"now?");
    let (got, from) = recv(&server);
    assert_eq!(got, b"now?");
    server.send_to(b"yes", from).unwrap();
    assert_eq!(rig.receive(1)[0].payload, b"yes");

    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(udps(&events).len(), 1, "one mapping throughout");
    assert_eq!(closes(&events), [(1, 7 + 6 + 4, 3, "shutdown".to_owned())]);
    assert!(drops(&events).is_empty(), "{:?}", drops(&events));
}

/// Stopping the stack closes every mapping (`net.close{shutdown}`); a
/// denied tuple, which never had one, gets none.
#[test]
fn shutdown_closes_mappings() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8", "default deny"])));
    rig.send(40_001, at, b"a");
    rig.send(40_002, at, b"bb");
    recv(&server);
    recv(&server);
    rig.send(
        40_003,
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9),
        b"no",
    );
    rig.poll(Instant::now());
    assert_eq!(rig.events.udp_watched(), 2);
    assert_eq!(rig.h.stack.udp_mappings(), 2);
    rig.h.stack.shutdown();
    assert_eq!(rig.h.stack.udp_mappings(), 0);
    let events = rig.events();
    assert_eq!(udps(&events).len(), 3);
    assert_eq!(
        closes(&events),
        [
            (1, 1, 0, "shutdown".to_owned()),
            (2, 2, 0, "shutdown".to_owned()),
        ]
    );
}
