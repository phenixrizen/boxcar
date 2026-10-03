// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The DNS forwarder from both of its sides: the guest's queries go in as
//! frames, a socket on 127.0.0.1 plays the upstream resolver (answering,
//! staying silent, or answering wrong as each test needs), and the guest's
//! answers come out as frames. The audit log says what was asked, decided
//! and answered.

mod common;

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boxcar_net::dns::cache::{DnsCache, CACHE_CAP};
use boxcar_net::dns::forwarder::DNS_TIMEOUT;
use boxcar_net::stack::{DNS_TOKEN, QUEUE_CAP};
use boxcar_net::{Interest, Policy, Verdict};
use boxcar_proto::{NetDns, NetDrop, Payload};
use common::{harness, harness_with, udp, Harness, GATEWAY, GATEWAY_MAC, GUEST, GUEST_MAC};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket};

const A: u16 = 1;
const CNAME: u16 = 5;
const SOA: u16 = 6;
const AAAA: u16 = 28;
const ANY: u16 = 255;
const IN: u16 = 1;
/// The port the guest's resolver asks from.
const GUEST_PORT: u16 = 41_000;
/// Where a query's name starts: right after the header.
const QNAME_AT: u16 = 12;

fn policy(lines: &[&str]) -> Policy {
    Policy::parse(lines).unwrap()
}

/// `name` in wire form, uncompressed.
fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A compression pointer to offset `at`.
fn pointer(at: u16) -> Vec<u8> {
    (0xc000 | at).to_be_bytes().to_vec()
}

fn header(id: u16, flags: u16, [qd, an, ns, ar]: [u16; 4]) -> Vec<u8> {
    [id, flags, qd, an, ns, ar]
        .iter()
        .flat_map(|n| n.to_be_bytes())
        .collect()
}

/// A standard query for one name, recursion desired, as a stub resolver
/// sends it.
fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = header(id, 0x0100, [1, 0, 0, 0]);
    m.extend(wire_name(name));
    m.extend(qtype.to_be_bytes());
    m.extend(IN.to_be_bytes());
    m
}

/// A resource record, its owner name already in wire form (perhaps a
/// pointer).
#[derive(Clone, Debug)]
struct Rr {
    owner: Vec<u8>,
    rtype: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn a(owner: Vec<u8>, ip: [u8; 4], ttl: u32) -> Rr {
    Rr {
        owner,
        rtype: A,
        ttl,
        rdata: ip.to_vec(),
    }
}

fn aaaa(owner: Vec<u8>, ip: &str) -> Rr {
    Rr {
        owner,
        rtype: AAAA,
        ttl: 60,
        rdata: ip.parse::<Ipv6Addr>().unwrap().octets().to_vec(),
    }
}

fn cname(owner: Vec<u8>, target: &str, ttl: u32) -> Rr {
    Rr {
        owner,
        rtype: CNAME,
        ttl,
        rdata: wire_name(target),
    }
}

/// An SOA for `zone` naming `ns.<zone>` and `hostmaster.<zone>`.
fn soa(zone: &str) -> Rr {
    let mut rdata = wire_name(&format!("ns.{zone}"));
    rdata.extend(wire_name(&format!("hostmaster.{zone}")));
    for n in [2_026_100_101_u32, 3600, 600, 86_400, 60] {
        rdata.extend(n.to_be_bytes());
    }
    Rr {
        owner: wire_name(zone),
        rtype: SOA,
        ttl: 60,
        rdata,
    }
}

/// The upstream's answer to `query` (a header and one question): its id
/// and question, recursion available, `rcode`, and these records.
fn reply(query: &[u8], rcode: u16, answers: &[Rr], authority: &[Rr]) -> Vec<u8> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    let counts = [1, answers.len() as u16, authority.len() as u16, 0];
    let mut m = header(id, 0x8180 | rcode, counts);
    m.extend_from_slice(&query[12..]);
    for rr in answers.iter().chain(authority) {
        m.extend(&rr.owner);
        m.extend(rr.rtype.to_be_bytes());
        m.extend(IN.to_be_bytes());
        m.extend(rr.ttl.to_be_bytes());
        m.extend((rr.rdata.len() as u16).to_be_bytes());
        m.extend(&rr.rdata);
    }
    m
}

/// A guest frame carrying `payload` from the guest's resolver to the
/// gateway's port 53.
fn dns_frame(payload: &[u8]) -> Vec<u8> {
    udp(
        GATEWAY_MAC,
        SocketAddrV4::new(GUEST, GUEST_PORT),
        SocketAddrV4::new(GATEWAY, 53),
        payload,
    )
}

/// The DNS message in a frame the stack sent the guest, after checking it
/// comes from the gateway's port 53 to the guest's resolver with both
/// checksums right and fits the link.
fn dns_payload(frame: &[u8]) -> Vec<u8> {
    assert!(frame.len() <= 14 + 1500, "within the link's MTU");
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!((eth.src_addr(), eth.dst_addr()), (GATEWAY_MAC, GUEST_MAC));
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
    let packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    // Parsing checks the header checksum.
    let ip = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
    assert_eq!((ip.src_addr, ip.dst_addr), (GATEWAY, GUEST));
    assert_eq!(ip.next_header, IpProtocol::Udp);
    let datagram = UdpPacket::new_checked(packet.payload()).unwrap();
    assert_ne!(datagram.checksum(), 0, "the UDP checksum is computed");
    assert!(datagram.verify_checksum(&ip.src_addr.into(), &ip.dst_addr.into()));
    assert_eq!((datagram.src_port(), datagram.dst_port()), (53, GUEST_PORT));
    datagram.payload().to_vec()
}

/// A DNS message as the test reads it, with its own small decoder (not the
/// stack's).
#[derive(Debug)]
struct Message {
    id: u16,
    flags: u16,
    counts: [u16; 4],
    question: Option<(String, u16)>,
    /// Every record in every section: owner, type, and its data as text.
    records: Vec<(String, u16, String)>,
}

fn u16_at(m: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([m[at], m[at + 1]])
}

/// The name at `at`, and where the bytes after it start.
fn read_name(m: &[u8], mut at: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = usize::from(m[at]);
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(at + 2);
            at = (len & 0x3f) << 8 | usize::from(m[at + 1]);
        } else if len == 0 {
            return (labels.join("."), end.unwrap_or(at + 1));
        } else {
            labels.push(String::from_utf8(m[at + 1..at + 1 + len].to_vec()).unwrap());
            at += 1 + len;
        }
    }
    panic!("a name that does not end");
}

fn read_message(m: &[u8]) -> Message {
    let counts = [u16_at(m, 4), u16_at(m, 6), u16_at(m, 8), u16_at(m, 10)];
    let mut at = 12;
    let mut question = None;
    for _ in 0..counts[0] {
        let (name, next) = read_name(m, at);
        question = Some((name, u16_at(m, next)));
        at = next + 4;
    }
    let mut records = Vec::new();
    for _ in 0..counts[1] + counts[2] + counts[3] {
        let (owner, next) = read_name(m, at);
        let rtype = u16_at(m, next);
        let len = usize::from(u16_at(m, next + 8));
        let start = next + 10;
        let rdata = &m[start..start + len];
        let text = match rtype {
            A => Ipv4Addr::from(<[u8; 4]>::try_from(rdata).unwrap()).to_string(),
            AAAA => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()).to_string(),
            CNAME | SOA => read_name(m, start).0,
            _ => format!("{rdata:?}"),
        };
        records.push((owner, rtype, text));
        at = start + len;
    }
    assert_eq!(at, m.len(), "nothing after the records");
    Message {
        id: u16_at(m, 0),
        flags: u16_at(m, 2),
        counts,
        question,
        records,
    }
}

/// The next query the stack forwarded, and where from.
fn forwarded(h: &Harness) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0; 4096];
    let (n, from) = h.upstream.recv_from(&mut buf).unwrap();
    (buf[..n].to_vec(), from)
}

/// Every query the stack has forwarded and the upstream has not read yet.
fn all_forwarded(h: &Harness) -> Vec<Vec<u8>> {
    h.upstream.set_nonblocking(true).unwrap();
    let mut buf = [0; 4096];
    let mut got = Vec::new();
    loop {
        match h.upstream.recv(&mut buf) {
            Ok(n) => got.push(buf[..n].to_vec()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }
    h.upstream.set_nonblocking(false).unwrap();
    got
}

/// Lets the stack read its upstream socket until it has answered the guest.
/// On loopback the datagram is there by the time `send_to` returns, so the
/// first round nearly always does.
fn answered(h: &mut Harness) -> Vec<Vec<u8>> {
    for _ in 0..2000 {
        h.stack.on_host_fd_event(DNS_TOKEN, true, false);
        let frames = h.drain();
        if !frames.is_empty() {
            return frames;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("the stack never answered the guest");
}

fn record(
    txid: u16,
    qname: &str,
    qtype: u16,
    rcode: u16,
    answers: &[&str],
    verdict: Verdict,
    rule: Option<&str>,
) -> Payload {
    Payload::NetDns(NetDns {
        txid,
        qname: qname.to_owned(),
        qtype,
        rcode,
        answers: answers.iter().map(|a| a.to_string()).collect(),
        verdict,
        rule: rule.map(str::to_owned),
    })
}

fn dns_records(events: &[Payload]) -> Vec<Payload> {
    events
        .iter()
        .filter(|e| matches!(e, Payload::NetDns(_)))
        .cloned()
        .collect()
}

#[test]
fn a_denied_name_gets_nxdomain_and_an_event() {
    let mut h = harness_with(policy(&[
        "default deny",
        "allow example.com",
        "deny *.ads.example.net",
        "allow *.example.net",
    ]));
    for (id, name, qtype) in [
        (0x1111, "blocked.example", A),
        // Denied by a rule, not the default; the guest's spelling of the
        // name comes back as it asked.
        (0x2222, "Tracker.Ads.Example.NET", AAAA),
    ] {
        let q = query(id, name, qtype);
        h.stack.push_guest_frame(&dns_frame(&q));
        let frames = h.drain();
        assert_eq!(frames.len(), 1, "{name}");
        let got = dns_payload(&frames[0]);
        let m = read_message(&got);
        assert_eq!(m.id, id);
        assert_eq!(m.flags, 0x8183, "QR, RD, RA and NXDOMAIN");
        assert_eq!(m.counts, [1, 0, 0, 0]);
        assert_eq!(got[12..], q[12..], "the question, as asked");
    }
    assert!(all_forwarded(&h).is_empty(), "nothing went upstream");
    assert_eq!(
        h.events(),
        [
            record(0x1111, "blocked.example", A, 3, &[], Verdict::Deny, None),
            record(
                0x2222,
                "tracker.ads.example.net",
                AAAA,
                3,
                &[],
                Verdict::Deny,
                Some("deny *.ads.example.net"),
            ),
        ]
    );
}

#[test]
fn an_allowed_query_is_forwarded_and_the_answer_cached() {
    let mut h = harness_with(policy(&["allow example.com"]));
    let first = h.stack.poll(Instant::now());
    assert_eq!(first.fd_changes.len(), 1, "the upstream socket is watched");
    let watch = first.fd_changes[0];
    assert_eq!(watch.token, DNS_TOKEN);
    assert!(watch.fd > 2);
    assert_eq!(
        watch.interest,
        Interest {
            readable: true,
            writable: false
        }
    );
    assert!(h.stack.poll(Instant::now()).fd_changes.is_empty(), "once");

    let q = query(0xbeef, "Example.COM", A);
    h.stack.push_guest_frame(&dns_frame(&q));
    assert!(h.drain().is_empty(), "the answer is the upstream's to give");
    let (sent, from) = forwarded(&h);
    assert_eq!(sent[2..], q[2..], "forwarded as asked, under its own id");

    let edge = wire_name("edge.cdn.test");
    let upstream_reply = reply(
        &sent,
        0,
        &[
            cname(pointer(QNAME_AT), "edge.cdn.test", 300),
            a(edge.clone(), [93, 184, 215, 14], 120),
            a(edge, [93, 184, 215, 15], 120),
            // Not on the chain from the question: passed on, never believed.
            a(wire_name("unrelated.test"), [203, 0, 113, 66], 120),
        ],
        &[],
    );
    h.upstream.send_to(&upstream_reply, from).unwrap();
    let frames = answered(&mut h);
    assert_eq!(frames.len(), 1);
    let got = dns_payload(&frames[0]);
    assert_eq!(
        got[..2],
        0xbeef_u16.to_be_bytes(),
        "the guest's id, restored"
    );
    assert_eq!(
        got[2..],
        upstream_reply[2..],
        "the rest as the upstream sent it"
    );

    // The queried name comes first, then the chain to the address.
    for ip in [[93, 184, 215, 14], [93, 184, 215, 15]] {
        assert_eq!(
            h.stack.dns_names(Ipv4Addr::from(ip)),
            ["example.com", "edge.cdn.test"]
        );
    }
    assert!(h.stack.dns_names(Ipv4Addr::new(203, 0, 113, 66)).is_empty());
    assert_eq!(
        h.events(),
        [record(
            0xbeef,
            "example.com",
            A,
            0,
            &["93.184.215.14", "93.184.215.15"],
            Verdict::Allow,
            Some("allow example.com"),
        )]
    );
}

#[test]
fn aaaa_answers_are_stripped() {
    let mut h = harness_with(policy(&["allow *.example.com"]));

    // The CNAME and the authority stay; the target's AAAA records go.
    h.stack
        .push_guest_frame(&dns_frame(&query(0x0a0a, "www.example.com", AAAA)));
    let (sent, from) = forwarded(&h);
    let edge = wire_name("edge.cdn.test");
    let upstream_reply = reply(
        &sent,
        0,
        &[
            cname(pointer(QNAME_AT), "edge.cdn.test", 300),
            aaaa(edge.clone(), "2001:db8::1"),
            aaaa(edge, "2001:db8::2"),
        ],
        &[soa("cdn.test")],
    );
    h.upstream.send_to(&upstream_reply, from).unwrap();
    let m = read_message(&dns_payload(&answered(&mut h)[0]));
    assert_eq!(m.id, 0x0a0a);
    assert_eq!(m.flags, 0x8180);
    assert_eq!(m.counts, [1, 1, 1, 0]);
    assert_eq!(m.question, Some(("www.example.com".to_owned(), AAAA)));
    assert_eq!(
        m.records,
        [
            (
                "www.example.com".to_owned(),
                CNAME,
                "edge.cdn.test".to_owned()
            ),
            ("cdn.test".to_owned(), SOA, "ns.cdn.test".to_owned()),
        ]
    );

    // Of A and AAAA together, the A records stay, in their order.
    h.stack
        .push_guest_frame(&dns_frame(&query(0x0b0b, "api.example.com", ANY)));
    let (sent, from) = forwarded(&h);
    let upstream_reply = reply(
        &sent,
        0,
        &[
            a(pointer(QNAME_AT), [192, 0, 2, 1], 60),
            aaaa(pointer(QNAME_AT), "2001:db8::3"),
            a(pointer(QNAME_AT), [192, 0, 2, 2], 60),
        ],
        &[],
    );
    h.upstream.send_to(&upstream_reply, from).unwrap();
    let m = read_message(&dns_payload(&answered(&mut h)[0]));
    assert_eq!(m.counts, [1, 2, 0, 0]);
    assert_eq!(
        m.records,
        [
            ("api.example.com".to_owned(), A, "192.0.2.1".to_owned()),
            ("api.example.com".to_owned(), A, "192.0.2.2".to_owned()),
        ]
    );

    let rule = Some("allow *.example.com");
    assert_eq!(
        h.events(),
        [
            record(
                0x0a0a,
                "www.example.com",
                AAAA,
                0,
                &[],
                Verdict::Allow,
                rule
            ),
            record(
                0x0b0b,
                "api.example.com",
                ANY,
                0,
                &["192.0.2.1", "192.0.2.2"],
                Verdict::Allow,
                rule,
            ),
        ]
    );
}

#[test]
fn dns_cache_is_bounded() {
    let mut cache = DnsCache::new();
    let t0 = Instant::now();
    let ip = |i: u32| Ipv4Addr::from(0xc633_0000 + i);
    for i in 0..5000 {
        cache.insert_at(ip(i), &format!("host{i}.example"), 300, t0);
    }
    assert!(cache.len() <= 4096);
    assert_eq!(cache.len(), CACHE_CAP);
    let evicted = 5000 - CACHE_CAP as u32;
    assert!(
        cache.names_for_at(ip(0), t0).is_empty(),
        "the oldest is gone"
    );
    assert!(cache.names_for_at(ip(evicted - 1), t0).is_empty());
    assert_eq!(
        cache.names_for_at(ip(evicted), t0),
        [format!("host{evicted}.example")]
    );
    assert_eq!(cache.names_for_at(ip(4999), t0), ["host4999.example"]);
}

#[test]
fn forwarder_times_out_with_servfail() {
    let mut h = harness();
    let asked = Instant::now();
    let q = query(0x5151, "slow.example", A);
    h.stack.push_guest_frame(&dns_frame(&q));
    let (late, from) = forwarded(&h);
    let deadline = h
        .stack
        .poll(Instant::now())
        .next_deadline
        .expect("the query's deadline");
    assert!(deadline >= asked + DNS_TIMEOUT);
    assert!(deadline <= Instant::now() + DNS_TIMEOUT);

    // The upstream stays silent. Just before the deadline the guest is still
    // waiting; at it, it gets SERVFAIL.
    h.stack.poll(deadline - Duration::from_millis(1));
    assert!(h.drain().is_empty());
    h.stack.poll(deadline);
    let frames = h.drain();
    assert_eq!(frames.len(), 1);
    let got = dns_payload(&frames[0]);
    let m = read_message(&got);
    assert_eq!(m.id, 0x5151);
    assert_eq!(m.flags, 0x8182, "QR, RD, RA and SERVFAIL");
    assert_eq!(m.counts, [1, 0, 0, 0]);
    assert_eq!(got[12..], q[12..]);

    // An answer after that is ignored and counted. A second query's answer
    // comes in behind it, so once that reaches the guest the stack has read
    // both.
    let too_late = reply(&late, 0, &[a(pointer(QNAME_AT), [192, 0, 2, 9], 60)], &[]);
    h.upstream.send_to(&too_late, from).unwrap();
    h.stack
        .push_guest_frame(&dns_frame(&query(0x5252, "fast.example", A)));
    let (sent, from) = forwarded(&h);
    let answer = reply(&sent, 0, &[a(pointer(QNAME_AT), [192, 0, 2, 10], 60)], &[]);
    h.upstream.send_to(&answer, from).unwrap();
    let frames = answered(&mut h);
    assert_eq!(frames.len(), 1);
    assert_eq!(read_message(&dns_payload(&frames[0])).id, 0x5252);
    assert!(h.stack.dns_names(Ipv4Addr::new(192, 0, 2, 9)).is_empty());

    assert_eq!(
        h.events(),
        [
            record(0x5151, "slow.example", A, 2, &[], Verdict::Allow, None),
            Payload::NetDrop(NetDrop {
                reason: "dns_bogus".into(),
                count: 1,
            }),
            record(
                0x5252,
                "fast.example",
                A,
                0,
                &["192.0.2.10"],
                Verdict::Allow,
                None
            ),
        ]
    );
}

/// An answer is taken only for a query in flight, by its id and its
/// question (in any case); a malformed one, or one that is not a response,
/// is ignored like a stranger's.
#[test]
fn a_reply_must_match_a_query_in_flight_by_id_and_question() {
    let mut h = harness();
    h.stack
        .push_guest_frame(&dns_frame(&query(0x7777, "example.com", A)));
    let (sent, from) = forwarded(&h);
    let id = u16::from_be_bytes([sent[0], sent[1]]);
    let to = |name, qtype| query(id, name, qtype);
    let answer = |ip| [a(pointer(QNAME_AT), ip, 60)];

    let mut wrong_id = reply(&sent, 0, &answer([203, 0, 113, 6]), &[]);
    wrong_id[..2].copy_from_slice(&(id ^ 0x8000).to_be_bytes());
    let wrong_name = reply(&to("evil.example", A), 0, &answer([203, 0, 113, 7]), &[]);
    let wrong_type = reply(&to("example.com", AAAA), 0, &[], &[]);
    let mut malformed = reply(&sent, 0, &answer([203, 0, 113, 8]), &[]);
    malformed.truncate(malformed.len() - 2);
    let not_a_response = sent.clone();
    let right = reply(&to("EXAMPLE.com", A), 0, &answer([192, 0, 2, 1]), &[]);
    let ignored = [wrong_id, wrong_name, wrong_type, malformed, not_a_response];
    for m in ignored.iter().chain([&right]) {
        h.upstream.send_to(m, from).unwrap();
    }

    let frames = answered(&mut h);
    assert_eq!(frames.len(), 1);
    let m = read_message(&dns_payload(&frames[0]));
    assert_eq!(m.id, 0x7777);
    assert_eq!(
        m.records,
        [("EXAMPLE.com".to_owned(), A, "192.0.2.1".to_owned())]
    );
    for last in 6..=8 {
        assert!(h
            .stack
            .dns_names(Ipv4Addr::new(203, 0, 113, last))
            .is_empty());
    }
    assert_eq!(
        h.stack.dns_names(Ipv4Addr::new(192, 0, 2, 1)),
        ["example.com"]
    );

    h.stack.shutdown();
    let events = h.events();
    assert_eq!(
        dns_records(&events),
        [record(
            0x7777,
            "example.com",
            A,
            0,
            &["192.0.2.1"],
            Verdict::Allow,
            None
        )]
    );
    let bogus = common::drops(&events);
    assert!(bogus.iter().all(|d| d.reason == "dns_bogus"), "{bogus:?}");
    assert_eq!(
        bogus.iter().map(|d| d.count).sum::<u64>(),
        ignored.len() as u64
    );
}

/// 256 queries wait for the upstream at most; the next is refused with
/// SERVFAIL at once. Each forwarded query has an id of its own. The queries
/// still waiting when the stack stops are recorded as unanswered.
#[test]
fn at_most_256_queries_wait_for_the_upstream() {
    let mut h = harness();
    for id in 0..=256u16 {
        let name = format!("q{id}.example");
        h.stack.push_guest_frame(&dns_frame(&query(id, &name, A)));
    }
    let frames = h.drain();
    assert_eq!(frames.len(), 1, "the 257th is answered at once");
    let m = read_message(&dns_payload(&frames[0]));
    assert_eq!((m.id, m.flags), (256, 0x8182));

    // The loopback socket may not have kept them all; those it did carry
    // distinct ids.
    let sent = all_forwarded(&h);
    assert!(!sent.is_empty());
    let ids: HashSet<u16> = sent.iter().map(|q| u16_at(q, 0)).collect();
    assert_eq!(ids.len(), sent.len(), "every id in flight is distinct");

    h.stack.shutdown();
    let records = dns_records(&h.events());
    let txids: Vec<u16> = records
        .iter()
        .map(|r| match r {
            Payload::NetDns(dns) => {
                assert_eq!(dns.rcode, 2, "{dns:?}");
                assert!(dns.answers.is_empty());
                dns.txid
            }
            _ => unreachable!(),
        })
        .collect();
    let mut want = vec![256];
    want.extend(0..256);
    assert_eq!(txids, want, "the refused one, then the rest in order");
}

/// A message that is not one plain query gets FORMERR and goes nowhere:
/// a response, another opcode, two questions, none, and a name that points
/// at itself. The question comes back when there is one to read.
#[test]
fn queries_that_are_not_plain_get_formerr() {
    let mut h = harness();
    let mut response = query(0x0102, "example.com", A);
    response[2] |= 0x80;
    let mut status = query(0x0103, "example.com", A);
    status[2] = 2 << 3 | 0x01; // opcode 2, RD
    let mut two = query(0x0104, "example.com", A);
    two[5] = 2;
    two.extend(wire_name("example.net"));
    two.extend(A.to_be_bytes());
    two.extend(IN.to_be_bytes());
    let none = header(0x0105, 0x0100, [0; 4]);
    let mut looped = header(0x0106, 0x0100, [1, 0, 0, 0]);
    looped.extend(pointer(QNAME_AT));
    looped.extend(A.to_be_bytes());
    looped.extend(IN.to_be_bytes());

    for (m, flags, echoed) in [
        (&response, 0x8181, true),
        (&status, 0x9181, true),
        (&two, 0x8181, false),
        (&none, 0x8181, false),
        (&looped, 0x8181, false),
    ] {
        h.stack.push_guest_frame(&dns_frame(m));
        let frames = h.drain();
        assert_eq!(frames.len(), 1);
        let got = dns_payload(&frames[0]);
        assert_eq!(got[..2], m[..2], "the id");
        assert_eq!(u16_at(&got, 2), flags, "FORMERR");
        if echoed {
            assert_eq!(read_message(&got).counts, [1, 0, 0, 0]);
            assert_eq!(got[12..], m[12..]);
        } else {
            assert_eq!(got.len(), 12, "the header alone");
            assert_eq!(got[4..], [0; 8]);
        }
    }
    assert!(all_forwarded(&h).is_empty(), "nothing went upstream");
    let allow = Verdict::Allow;
    assert_eq!(
        h.events(),
        [
            record(0x0102, "example.com", A, 1, &[], allow, None),
            record(0x0103, "example.com", A, 1, &[], allow, None),
            record(0x0104, "", 0, 1, &[], allow, None),
            record(0x0105, "", 0, 1, &[], allow, None),
            record(0x0106, "", 0, 1, &[], allow, None),
        ]
    );
}

/// An answer the link cannot carry in one frame is cut to its header and
/// question with TC set, as a DNS server does, and the guest asks again
/// over TCP; it is neither cached nor recorded as answered. One that just
/// fits goes as it is.
#[test]
fn a_reply_too_big_for_the_link_is_truncated() {
    let mut h = harness();
    // 12 bytes of header, 17 of question and 16 for each A record: 90 make
    // 1469 bytes, within 1500 - 20 - 8; 100 do not.
    for (id, count, fits) in [(0x4141, 90u8, true), (0x4242, 100, false)] {
        let q = query(id, "big.example", A);
        h.stack.push_guest_frame(&dns_frame(&q));
        let (sent, from) = forwarded(&h);
        let records: Vec<Rr> = (0..count)
            .map(|i| a(pointer(QNAME_AT), [198, 51, 100, i], 60))
            .collect();
        let upstream_reply = reply(&sent, 0, &records, &[]);
        h.upstream.send_to(&upstream_reply, from).unwrap();
        let frames = answered(&mut h);
        assert_eq!(frames.len(), 1);
        let got = dns_payload(&frames[0]);
        if fits {
            assert_eq!(got.len(), 1469);
            assert_eq!(got[2..], upstream_reply[2..]);
        } else {
            let m = read_message(&got);
            assert_eq!(m.id, id);
            assert_eq!(m.flags, 0x8380, "QR, TC, RD and RA");
            assert_eq!(m.counts, [1, 0, 0, 0]);
            assert_eq!(got[12..], q[12..]);
        }
    }
    assert_eq!(
        h.stack.dns_names(Ipv4Addr::new(198, 51, 100, 89)),
        ["big.example"]
    );
    assert!(h
        .stack
        .dns_names(Ipv4Addr::new(198, 51, 100, 99))
        .is_empty());

    let events = h.events();
    let fitted: Vec<String> = (0..90).map(|i| format!("198.51.100.{i}")).collect();
    let fitted: Vec<&str> = fitted.iter().map(String::as_str).collect();
    assert_eq!(
        events,
        [
            record(0x4141, "big.example", A, 0, &fitted, Verdict::Allow, None),
            record(0x4242, "big.example", A, 0, &[], Verdict::Allow, None),
        ]
    );
}

/// The stack reads the policy at every query, so a swapped policy decides
/// the next one; `policy()` is the handle it reads.
#[test]
fn the_policy_is_read_for_every_query() {
    let mut h = harness_with(policy(&["default deny"]));
    assert!(Arc::ptr_eq(&h.stack.policy(), &h.policy));
    h.stack
        .push_guest_frame(&dns_frame(&query(0x0201, "example.com", A)));
    assert_eq!(u16_at(&dns_payload(&h.drain()[0]), 2), 0x8183, "NXDOMAIN");

    h.policy.store(Arc::new(policy(&["allow example.com"])));
    h.stack
        .push_guest_frame(&dns_frame(&query(0x0202, "example.com", A)));
    assert!(h.drain().is_empty());
    let (sent, _) = forwarded(&h);
    assert_eq!(sent[2..], query(0, "example.com", A)[2..]);

    // The stack stops before the upstream answers.
    h.stack.shutdown();
    assert_eq!(
        h.events(),
        [
            record(0x0201, "example.com", A, 3, &[], Verdict::Deny, None),
            record(
                0x0202,
                "example.com",
                A,
                2,
                &[],
                Verdict::Allow,
                Some("allow example.com"),
            ),
        ]
    );
}

/// A query is recorded even when the guest's full queue refuses its
/// answer, unlike a lease: it was asked and decided, and an allowed one has
/// gone upstream, which the log must show whether or not the guest takes
/// the answer. The refused answer is counted as `queue_full`.
#[test]
fn a_query_is_recorded_even_when_the_guest_queue_refuses_its_answer() {
    let mut h = harness_with(policy(&["default deny"]));
    for id in 0..=QUEUE_CAP as u16 {
        h.stack
            .push_guest_frame(&dns_frame(&query(id, "blocked.example", A)));
    }
    assert_eq!(h.drain().len(), QUEUE_CAP, "the last answer was refused");
    h.stack.shutdown();
    let events = h.events();
    let records = dns_records(&events);
    assert_eq!(records.len(), QUEUE_CAP + 1);
    assert_eq!(
        records.last(),
        Some(&record(
            QUEUE_CAP as u16,
            "blocked.example",
            A,
            3,
            &[],
            Verdict::Deny,
            None
        ))
    );
    assert_eq!(
        common::drops(&events),
        [NetDrop {
            reason: "queue_full".into(),
            count: 1,
        }]
    );
}

/// An answer must repeat the query's class as well as its name and type:
/// a CH query is not answered by an IN reply, which is counted as bogus.
#[test]
fn a_reply_must_repeat_the_question_class() {
    const TXT: u16 = 16;
    const CH: u16 = 3;
    let mut h = harness();
    let mut q = query(0x5555, "version.bind", TXT);
    let class_at = q.len() - 2;
    q[class_at..].copy_from_slice(&CH.to_be_bytes());
    h.stack.push_guest_frame(&dns_frame(&q));
    let (sent, from) = forwarded(&h);
    assert_eq!(sent[2..], q[2..]);

    let mut txt = vec![9];
    txt.extend(b"boxcar 1");
    let answer = |class: u16| {
        let mut m = reply(&sent, 0, &[], &[]);
        m[7] = 1; // one answer
        m[class_at..class_at + 2].copy_from_slice(&class.to_be_bytes());
        m.extend(pointer(QNAME_AT));
        m.extend(TXT.to_be_bytes());
        m.extend(class.to_be_bytes());
        m.extend(60u32.to_be_bytes());
        m.extend((txt.len() as u16).to_be_bytes());
        m.extend(&txt);
        m
    };
    let wrong_class = answer(IN);
    let right = answer(CH);
    h.upstream.send_to(&wrong_class, from).unwrap();
    h.upstream.send_to(&right, from).unwrap();
    let frames = answered(&mut h);
    assert_eq!(frames.len(), 1);
    let got = dns_payload(&frames[0]);
    assert_eq!(got[..2], 0x5555_u16.to_be_bytes());
    assert_eq!(got[2..], right[2..], "the CH answer");

    assert_eq!(
        h.events(),
        [
            Payload::NetDrop(NetDrop {
                reason: "dns_bogus".into(),
                count: 1,
            }),
            record(0x5555, "version.bind", TXT, 0, &[], Verdict::Allow, None),
        ]
    );
}

/// A rule's port does not stop a name resolving if the rule allows: a
/// port-qualified allow under default deny gets the name forwarded, and so
/// does a name whose only deny is on another port.
#[test]
fn a_port_qualified_allow_lets_the_name_resolve() {
    let mut h = harness_with(policy(&[
        "default deny",
        "allow api.example.com:443",
        "deny example.com:80",
        "allow example.com",
    ]));
    for (id, name, rule, ip) in [
        (
            0x0301,
            "api.example.com",
            "allow api.example.com:443",
            [192, 0, 2, 31],
        ),
        (0x0302, "example.com", "allow example.com", [192, 0, 2, 32]),
    ] {
        h.stack.push_guest_frame(&dns_frame(&query(id, name, A)));
        assert!(h.drain().is_empty(), "{name}: forwarded, not refused");
        let (sent, from) = forwarded(&h);
        let answer = reply(&sent, 0, &[a(pointer(QNAME_AT), ip, 60)], &[]);
        h.upstream.send_to(&answer, from).unwrap();
        let m = read_message(&dns_payload(&answered(&mut h)[0]));
        assert_eq!((m.id, m.flags), (id, 0x8180), "{name}: {rule}");
        assert_eq!(h.stack.dns_names(Ipv4Addr::from(ip)), [name]);
    }
    assert_eq!(
        h.events(),
        [
            record(
                0x0301,
                "api.example.com",
                A,
                0,
                &["192.0.2.31"],
                Verdict::Allow,
                Some("allow api.example.com:443"),
            ),
            record(
                0x0302,
                "example.com",
                A,
                0,
                &["192.0.2.32"],
                Verdict::Allow,
                Some("allow example.com"),
            ),
        ]
    );
}

/// A record an upstream might send: owned by the question's name or some
/// other, of a common type with data of its shape or of any type with any
/// data.
fn any_record() -> impl Strategy<Value = Rr> {
    let owner = prop_oneof![
        Just(pointer(QNAME_AT)),
        vec(b'a'..=b'z', 1..12).prop_map(|l| wire_name(&String::from_utf8(l).unwrap())),
    ];
    let data = prop_oneof![
        vec(any::<u8>(), 4..=4).prop_map(|d| (A, d)),
        vec(any::<u8>(), 16..=16).prop_map(|d| (AAAA, d)),
        vec(b'a'..=b'z', 1..30).prop_map(|l| (CNAME, wire_name(&String::from_utf8(l).unwrap()))),
        (any::<u16>(), vec(any::<u8>(), 0..64)),
    ];
    (owner, data, any::<u32>()).prop_map(|(owner, (rtype, rdata), ttl)| Rr {
        owner,
        rtype,
        ttl,
        rdata,
    })
}

/// Whatever the upstream answers, large or small, the guest gets exactly
/// one well-formed frame that fits the link: that answer, stripped or cut,
/// or (when it does not read) the plain one sent after it.
#[test]
fn whatever_the_upstream_answers_the_guest_gets_one_frame_that_fits() {
    let h = RefCell::new(harness());
    let id = std::cell::Cell::new(0u16);
    let strategy = (vec(any_record(), 0..120), 0u16..16, vec(any::<u8>(), 0..4));
    TestRunner::default()
        .run(&strategy, |(records, rcode, tail)| {
            let mut h = h.borrow_mut();
            id.set(id.get().wrapping_add(1));
            let q = query(id.get(), "fuzz.example", A);
            h.stack.push_guest_frame(&dns_frame(&q));
            let (sent, from) = forwarded(&h);
            let mut wild = reply(&sent, rcode, &records, &[]);
            wild.extend(tail);
            h.upstream.send_to(&wild, from).unwrap();
            h.upstream
                .send_to(&reply(&sent, 0, &[], &[]), from)
                .unwrap();
            let frames = answered(&mut h);
            prop_assert_eq!(frames.len(), 1);
            let got = dns_payload(&frames[0]);
            prop_assert_eq!(u16_at(&got, 0), id.get());
            prop_assert_eq!(&got[12..12 + q.len() - 12], &q[12..]);
            h.stack.on_host_fd_event(DNS_TOKEN, true, false);
            prop_assert!(h.drain().is_empty(), "one answer only");
            Ok(())
        })
        .unwrap();
}
