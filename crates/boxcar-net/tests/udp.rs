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
use boxcar_net::stack::QUEUE_CAP;
use boxcar_net::upstream::{decide, decide_udp, HostAddrs, BUILTIN_HOST_LOCAL};
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

/// The RFC 1071 sum of `bytes`, added to `acc`, unfolded: written apart
/// from smoltcp, which writes the stack's checksums.
fn sum16(mut acc: u32, bytes: &[u8]) -> u32 {
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        acc += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = pairs.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// The UDP pseudo-header of a datagram from `src` to `dst` of `len` bytes
/// (header included).
fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> Vec<u8> {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo
}

/// The UDP checksum field of an IPv4 UDP `frame`, after checking both the
/// IPv4 header checksum and the UDP checksum with [`sum16`].
fn checked_udp_checksum(frame: &[u8]) -> u16 {
    let ip = frame.get(14..).expect("an IPv4 packet");
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    assert_eq!(fold(sum16(0, &ip[..header])), 0xffff, "the IPv4 checksum");
    let segment = &ip[header..total];
    let len = u16::from_be_bytes([segment[4], segment[5]]);
    assert_eq!(usize::from(len), segment.len());
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let sum = sum16(sum16(0, &pseudo_header(src, dst, len)), segment);
    assert_eq!(fold(sum), 0xffff, "the UDP checksum");
    u16::from_be_bytes([segment[6], segment[7]])
}

/// `frame` as a UDP datagram the stack sent the guest, after checking the
/// Ethernet addresses, both checksums (the UDP one present; by smoltcp and
/// by [`checked_udp_checksum`]), and that the frame fits the link; `None`
/// if it is not UDP.
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
    assert_eq!(checked_udp_checksum(frame), packet.checksum());
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
        self.receive_frames(n)
            .iter()
            .filter_map(|f| datagram(f))
            .collect()
    }

    /// [`receive`](Self::receive), as the frames that carried them.
    fn receive_frames(&mut self, n: usize) -> Vec<Vec<u8>> {
        let start = Instant::now();
        let mut got = Vec::new();
        loop {
            self.poll(Instant::now());
            got.extend(self.h.drain().into_iter().filter(|f| datagram(f).is_some()));
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

/// UDP passes over a domain `allow`, as no name can be checked on a
/// datagram; domain denials, network rules and the default still decide.
/// Passing the domain allow over is named (`builtin:udp-needs-cidr`) when
/// it leaves the flow denied.
#[test]
fn domain_allows_are_passed_over_for_udp() {
    let (server, at) = server();
    let mut h = harness_with(policy(&[
        "allow echo.test",
        "allow bad.test",
        "allow 127.0.0.0/8",
    ]));
    resolve(&mut h, "echo.test", *at.ip());
    resolve(&mut h, "bad.test", *at.ip());
    let mut rig = Rig::new(h);
    // A network rule after the domain allows admits the named address.
    rig.send(40_001, at, b"by address");
    assert_eq!(recv(&server).0, b"by address");

    // A network deny after the domain allow: denied, for want of a
    // network rule that allows it.
    rig.h.policy.store(Arc::new(policy(&[
        "allow echo.test",
        &format!("deny {}", at.ip()),
        "allow 127.0.0.0/8",
    ])));
    rig.send(40_002, at, b"passed over");
    // A domain deny still denies an address whose names match it.
    rig.h
        .policy
        .store(Arc::new(policy(&["deny bad.test", "allow 127.0.0.0/8"])));
    rig.send(40_003, at, b"named and denied");
    rig.settle();
    assert!(nothing_at(&server), "nothing more reached the server");
    // The first mapping went with the second policy, which denies it too.
    assert_eq!(rig.h.stack.udp_mappings(), 0);

    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(closes(&events), [(1, 10, 0, "policy".into())]);
    let names = ["bad.test", "echo.test"];
    assert_eq!(
        udps(&events),
        [
            net_udp(
                1,
                guest(40_001),
                at,
                &names,
                Verdict::Allow,
                Some("allow 127.0.0.0/8")
            ),
            net_udp(
                2,
                guest(40_002),
                at,
                &names,
                Verdict::Deny,
                Some(BUILTIN_UDP_NEEDS_CIDR)
            ),
            net_udp(
                3,
                guest(40_003),
                at,
                &names,
                Verdict::Deny,
                Some("deny bad.test")
            ),
        ]
    );
}

/// Under `default allow`, an address whose cached names match a domain
/// allow is admitted by the default, the domain rule passed over (TCP
/// would gate it on the name). Decided here rather than sent: an address
/// the default decides is not private, and a datagram to it would leave
/// the host.
#[test]
fn default_allow_admits_udp_to_a_named_address() {
    let named = Ipv4Addr::new(192, 0, 2, 7);
    let mut h = harness_with(policy(&["allow echo.test", "default allow"]));
    resolve(&mut h, "echo.test", named);
    let names = h.stack.dns_names(named);
    assert_eq!(names, ["echo.test"]);
    let current = h.policy.load_full();
    let dst = SocketAddrV4::new(named, 9);
    let mut addrs = HostAddrs::fixed(Vec::new());
    assert_eq!(
        decide_udp(&mut addrs, &current, dst, &names, Instant::now()),
        (Verdict::Allow, None)
    );
    let tcp = decide(&mut addrs, &current, dst, &names, Instant::now());
    assert!(tcp.by_domain, "TCP is gated: {tcp:?}");
    h.events();
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
    // A port that refuses the mapping: its socket is connected elsewhere,
    // so the kernel finds no socket for the mapping's datagrams and
    // answers port unreachable. It stays bound throughout.
    let (server, closed) = server();
    let elsewhere = UdpSocket::bind("127.0.0.1:0").unwrap();
    server.connect(elsewhere.local_addr().unwrap()).unwrap();
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

    // The port opens to the mapping: the server's socket is connected to
    // the mapping's host port instead.
    let ports = ports_connected_to(closed);
    assert_eq!(ports.len(), 1, "{ports:?}");
    server
        .connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, ports[0]))
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

/// An IPv4 socket address a `getsockname`/`getpeername`-style call
/// writes for `fd`, if it writes one.
fn socket_addr(
    fd: libc::c_int,
    call: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
    ) -> libc::c_int,
) -> Option<SocketAddrV4> {
    // SAFETY: an all-zero sockaddr_in is a valid value.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `addr` is a live sockaddr_in of `len` bytes, which the call
    // writes at most; any fd number may be asked about.
    let done = unsafe { call(fd, (&mut addr as *mut libc::sockaddr_in).cast(), &mut len) };
    (done == 0 && addr.sin_family == libc::AF_INET as libc::sa_family_t).then(|| {
        SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
            u16::from_be(addr.sin_port),
        )
    })
}

/// The local ports of this process's sockets connected to `peer`: for a
/// test server's address, the stack's mappings to it, open or waiting to
/// close. The fd table is walked by number, so other tests' fds coming and
/// going do not disturb the count (none of them is connected to `peer`).
fn ports_connected_to(peer: SocketAddrV4) -> Vec<u16> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| socket_addr(*fd, libc::getpeername) == Some(peer))
        .filter_map(|fd| Some(socket_addr(fd, libc::getsockname)?.port()))
        .collect()
}

fn connected_to(peer: SocketAddrV4) -> usize {
    ports_connected_to(peer).len()
}

/// Evicted sockets wait for the next poll to close; while `parked_cap` of
/// them wait, a new tuple that would evict another is dropped
/// (`udp_table_full`, not recorded), so the host's sockets stay below
/// the cap plus twice the parked bound however many tuples come between
/// polls.
#[test]
fn parked_sockets_are_bounded() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_config(policy(&["allow 127.0.0.0/8"]), |c| {
        c.udp.mapping_cap = 4;
        c.udp.parked_cap = 2;
    }));
    for port in 1..=4 {
        rig.send(41_000 + port, at, b"x");
        recv(&server);
    }
    rig.poll(Instant::now());
    assert_eq!(connected_to(at), 4);

    // One batch, no poll: two new tuples evict two mappings, whose
    // sockets wait; the rest find the table full.
    for port in 5..=10 {
        rig.send(41_000 + port, at, b"x");
    }
    assert_eq!(connected_to(at), 4 + 2, "the cap and two parked");
    assert_eq!(rig.h.stack.udp_mappings(), 4);
    // The poll hands their unwatching over; they close at the next.
    rig.poll(Instant::now());
    for port in 11..=20 {
        rig.send(41_000 + port, at, b"x");
    }
    assert_eq!(
        connected_to(at),
        4 + 2 + 2,
        "the cap, two parked, two closing"
    );
    rig.poll(Instant::now());
    rig.poll(Instant::now());
    assert_eq!(connected_to(at), 4);
    // Room again: a new tuple is decided and gets a mapping.
    rig.send(41_100, at, b"x");
    assert_eq!(recv(&server).0, b"x");

    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(dropped(&events, "udp_table_full"), 4 + 8);
    let allowed = udps(&events)
        .iter()
        .filter(|u| u.verdict == Verdict::Allow)
        .count();
    assert_eq!(allowed, 4 + 2 + 2 + 1, "only the tuples that got a mapping");
    let evicted = closes(&events).iter().filter(|c| c.3 == "evicted").count();
    assert_eq!(evicted, 2 + 2 + 1);
}

/// At the parked bound only new tuples are dropped (`udp_table_full`): a
/// datagram on a mapping the table still holds is carried, not dropped.
/// (Task 8's re-review probe.)
#[test]
fn existing_mappings_carry_at_the_parked_bound() {
    let (server, at) = server();
    let mut h = harness_config(policy(&["allow 127.0.0.0/8"]), |c| {
        c.udp.mapping_cap = 2;
        c.udp.parked_cap = 1;
    });
    h.stack.poll(Instant::now());
    for port in [1, 2] {
        h.stack
            .push_guest_frame(&udp(GATEWAY_MAC, guest(port), at, b"a"));
        assert_eq!(recv(&server).0, b"a");
    }
    h.stack.poll(Instant::now());
    // A new tuple evicts tuple 1, whose socket is parked: the bound.
    h.stack
        .push_guest_frame(&udp(GATEWAY_MAC, guest(3), at, b"b"));
    assert_eq!(recv(&server).0, b"b");
    // Another new tuple finds the table full.
    h.stack
        .push_guest_frame(&udp(GATEWAY_MAC, guest(4), at, b"c"));
    // The mappings still in the table carry on, with nothing between.
    for port in [2, 3] {
        h.stack
            .push_guest_frame(&udp(GATEWAY_MAC, guest(port), at, b"still"));
        assert_eq!(recv(&server).0, b"still", "tuple {port}");
    }
    assert!(nothing_at(&server));

    h.stack.shutdown();
    let events = h.events();
    assert_eq!(dropped(&events, "udp_table_full"), 1);
    let closes = closes(&events);
    assert!(
        closes.iter().any(|c| c.0 == 1 && c.3 == "evicted"),
        "{closes:?}"
    );
}

/// Waits until the net thread sees `token` ready.
fn wait_ready(rig: &Rig, token: u64) {
    let start = Instant::now();
    while !rig
        .events
        .wait(Duration::from_millis(2))
        .iter()
        .any(|(t, ..)| *t == token)
    {
        assert!(start.elapsed() < Duration::from_secs(5), "never ready");
    }
}

/// One readiness event reads at most 64 datagrams; the socket stays ready,
/// and the rest come at the next event, in order.
#[test]
fn an_event_reads_at_most_64_datagrams() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, at, b"go");
    let (_, from) = recv(&server);
    rig.poll(Instant::now());
    let token = UDP_TOKEN_BASE + 1;
    for i in 0..100_u8 {
        server.send_to(&[i], from).unwrap();
    }
    wait_ready(&rig, token);
    thread::sleep(Duration::from_millis(3));
    rig.h.stack.on_host_fd_event(token, true, false);
    let mut got: Vec<u8> = rig.received().iter().map(|d| d.payload[0]).collect();
    assert_eq!(got.len(), 64, "one event's worth");
    wait_ready(&rig, token);
    while got.len() < 100 {
        wait_ready(&rig, token);
        rig.h.stack.on_host_fd_event(token, true, false);
        got.extend(rig.received().iter().map(|d| d.payload[0]));
    }
    assert_eq!(got, (0..100).collect::<Vec<u8>>());
    rig.h.stack.shutdown();
    assert_eq!(closes(&rig.events()), [(1, 2, 100, "shutdown".to_owned())]);
}

/// With the guest's queue full, replies are dropped (`queue_full`) and not
/// counted as received; the queue holds what it took.
#[test]
fn replies_to_a_full_guest_queue_are_dropped() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, at, b"go");
    let (_, from) = recv(&server);
    rig.poll(Instant::now());
    let token = UDP_TOKEN_BASE + 1;
    // The guest takes nothing, so its queue fills.
    let mut sent = 0;
    while sent < QUEUE_CAP + 100 {
        for _ in 0..64 {
            server.send_to(b"r", from).unwrap();
            sent += 1;
        }
        wait_ready(&rig, token);
        rig.h.stack.on_host_fd_event(token, true, false);
    }
    // Whatever is still on the socket.
    while rig
        .events
        .wait(Duration::from_millis(5))
        .iter()
        .any(|(t, ..)| *t == token)
    {
        rig.h.stack.on_host_fd_event(token, true, false);
    }
    assert_eq!(rig.received().len(), QUEUE_CAP);
    rig.h.stack.shutdown();
    let events = rig.events();
    assert_eq!(dropped(&events, "queue_full"), (sent - QUEUE_CAP) as u64);
    assert_eq!(
        closes(&events),
        [(1, 2, QUEUE_CAP as u64, "shutdown".to_owned())]
    );
}

/// Replies carry checksums an independent RFC 1071 sum accepts, and one
/// whose UDP checksum sums to zero carries 0xFFFF on the wire (zero means
/// none). Empty datagrams go both ways, and a stranger's datagram to the
/// mapping's host port is not delivered.
#[test]
fn a_zero_checksum_is_sent_as_all_ones() {
    let (server, at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, at, b"");
    let (got, from) = recv(&server);
    assert!(got.is_empty(), "an empty datagram goes on");
    rig.poll(Instant::now());

    let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
    stranger.send_to(b"forged", from).unwrap();
    server.send_to(b"", from).unwrap();
    // A payload that makes the whole sum 0xFFFF, so the checksum
    // computes to zero.
    let len: u16 = 8 + 4;
    let mut header = Vec::new();
    header.extend_from_slice(&at.port().to_be_bytes());
    header.extend_from_slice(&40_001_u16.to_be_bytes());
    header.extend_from_slice(&len.to_be_bytes());
    header.extend_from_slice(&[0, 0]);
    let rest = fold(sum16(
        sum16(0, &pseudo_header(*at.ip(), GUEST, len)),
        &header,
    ));
    let fill = 0xffff - rest;
    let zero_sum = [(fill >> 8) as u8, fill as u8, 0, 0];
    assert_eq!(
        fold(sum16(
            sum16(sum16(0, &pseudo_header(*at.ip(), GUEST, len)), &header),
            &zero_sum
        )),
        0xffff
    );
    server.send_to(&zero_sum, from).unwrap();

    let frames = rig.receive_frames(2);
    rig.settle();
    assert!(rig.received().is_empty(), "nothing from the stranger");
    let got: Vec<Datagram> = frames.iter().filter_map(|f| datagram(f)).collect();
    assert_eq!(
        got,
        [
            Datagram {
                src: at,
                dst: guest(40_001),
                payload: Vec::new(),
            },
            Datagram {
                src: at,
                dst: guest(40_001),
                payload: zero_sum.to_vec(),
            },
        ]
    );
    assert_eq!(checked_udp_checksum(&frames[1]), 0xffff);
    rig.h.stack.shutdown();
    assert_eq!(closes(&rig.events()), [(1, 0, 4, "shutdown".to_owned())]);
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

/// A policy swapped in while mappings are open closes, at the stack's next
/// poll, every mapping the new policy denies, recorded as
/// `net.close{reason:"policy"}`; its tuple is decided again, and refused,
/// at its next datagram. A mapping the new policy still allows goes on.
#[test]
fn a_policy_update_drops_the_mappings_it_denies_and_keeps_the_rest() {
    let (kept_server, kept_at) = server();
    let (dropped_server, dropped_at) = server();
    let mut rig = Rig::new(harness_with(policy(&["allow 127.0.0.0/8"])));
    rig.send(40_001, kept_at, b"kept");
    rig.send(40_002, dropped_at, b"dropped");
    assert_eq!(recv(&kept_server).0, b"kept");
    assert_eq!(recv(&dropped_server).0, b"dropped");
    rig.poll(Instant::now());
    assert_eq!(rig.h.stack.udp_mappings(), 2);

    // The exact range with the kept server's port lifts the loopback
    // denial there, nowhere else.
    let keep = format!("allow 127.0.0.0/8:{}", kept_at.port());
    rig.h.policy.store(Arc::new(policy(&[&keep])));
    rig.poll(Instant::now());
    assert_eq!(rig.h.stack.udp_mappings(), 1, "the denied mapping is gone");
    assert_eq!(rig.events.udp_watched(), 1, "and its host fd unwatched");

    rig.send(40_001, kept_at, b"kept again");
    assert_eq!(recv(&kept_server).0, b"kept again");
    rig.send(40_002, dropped_at, b"again");
    assert!(nothing_at(&dropped_server));
    rig.h.stack.shutdown();

    let events = rig.events();
    assert_eq!(
        udps(&events),
        [
            net_udp(
                1,
                guest(40_001),
                kept_at,
                &[],
                Verdict::Allow,
                Some("allow 127.0.0.0/8")
            ),
            net_udp(
                2,
                guest(40_002),
                dropped_at,
                &[],
                Verdict::Allow,
                Some("allow 127.0.0.0/8")
            ),
            net_udp(
                3,
                guest(40_002),
                dropped_at,
                &[],
                Verdict::Deny,
                Some(BUILTIN_PRIVATE)
            ),
        ]
    );
    assert_eq!(
        closes(&events),
        [(2, 7, 0, "policy".into()), (1, 14, 0, "shutdown".into())]
    );
}
