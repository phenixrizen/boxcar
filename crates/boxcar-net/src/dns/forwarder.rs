// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! [`Forwarder`]: one non-blocking UDP socket connected to the upstream
//! resolver, and the guest queries waiting on it.
//!
//! Each query goes upstream under an id the forwarder picks, unique among
//! those in flight and not predictable from the ones before it (SipHash,
//! keyed at random for the process, over a counter), and an answer is
//! taken only when it
//! carries an id in flight *and* repeats that query's question (the name in
//! any case, the type and the class) *and* reads as a whole. Anything else that
//! arrives is bogus and ignored, and the query it might have been for
//! waits on. At most [`MAX_IN_FLIGHT`] queries wait at once, and a query
//! unanswered after [`DNS_TIMEOUT`] is given up.
//!
//! The forwarder knows nothing of frames or of the guest's link: it takes
//! and gives back DNS messages, and the stack answers the guest.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::dns::parse::{self, Question};
use crate::policy::Verdict;

/// How long a query waits for the upstream before the guest gets SERVFAIL.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// The most queries waiting for the upstream at once; the guest gets
/// SERVFAIL for one more at once.
pub const MAX_IN_FLIGHT: usize = 256;
/// The largest UDP datagram.
const MAX_DATAGRAM: usize = 65_535;
/// How many ids [`Forwarder::forward`] draws before it gives up on finding
/// one not in flight. With at most 256 of 65536 taken, each draw collides
/// with odds of 1 in 256 at worst, so this is never reached in practice.
const ID_DRAWS: usize = 64;
/// How many socket errors one [`Forwarder::receive`] takes before it stops
/// reading. Each ICMP error for an earlier datagram is reported once, so a
/// few are normal; more mean something else is wrong.
const MAX_ERRORS: usize = 16;

/// A guest query and what the stack needs to answer and record it.
#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    /// The guest's id for the query.
    pub txid: u16,
    /// Where the guest asked from.
    pub guest: SocketAddrV4,
    pub question: Question,
    /// The guest's message, as it sent it.
    pub query: Vec<u8>,
    /// The policy's verdict on the name, and the rule that gave it.
    pub verdict: Verdict,
    pub rule: Option<String>,
}

/// An answer for a query in flight.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub pending: Pending,
    /// The upstream's message with the guest's id put back.
    pub reply: Vec<u8>,
    /// What [`parse::parse_answers`] read from it.
    pub answers: Vec<(String, Ipv4Addr, u32)>,
}

/// One datagram from the upstream.
#[derive(Clone, Debug, PartialEq)]
pub enum Received {
    Answer(Answer),
    /// A datagram that answers no query in flight, or does not read.
    Bogus,
}

/// Why a query was not sent upstream; the guest gets SERVFAIL.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("{MAX_IN_FLIGHT} queries are already waiting for the upstream")]
    Full,
    #[error("the query could not be sent upstream: {0}")]
    Send(io::Error),
}

#[derive(Debug)]
struct InFlight {
    pending: Pending,
    deadline: Instant,
    /// The order queries were sent in.
    seq: u64,
}

/// The upstream socket and the queries waiting on it.
#[derive(Debug)]
pub struct Forwarder {
    socket: UdpSocket,
    upstream: SocketAddr,
    in_flight: HashMap<u16, InFlight>,
    /// How long a query waits; [`DNS_TIMEOUT`] unless a test shortens it.
    timeout: Duration,
    cap: usize,
    /// The id generator's key: std's SipHash with a key drawn at random
    /// for the process.
    id_key: RandomState,
    /// How many ids have been drawn: what the key hashes into the next.
    id_counter: u64,
    seq: u64,
    buf: Vec<u8>,
}

impl Forwarder {
    /// A forwarder to the first of `upstreams` a UDP socket can be
    /// connected to (bound to the unspecified address of its family, on a
    /// port the kernel picks).
    pub fn connect(upstreams: &[SocketAddr]) -> io::Result<Forwarder> {
        let mut last = io::Error::new(ErrorKind::InvalidInput, "no DNS upstream");
        for &upstream in upstreams {
            match socket_to(upstream) {
                Ok(socket) => {
                    return Ok(Forwarder {
                        socket,
                        upstream,
                        in_flight: HashMap::new(),
                        timeout: DNS_TIMEOUT,
                        cap: MAX_IN_FLIGHT,
                        id_key: RandomState::new(),
                        id_counter: 0,
                        seq: 0,
                        buf: vec![0; MAX_DATAGRAM],
                    });
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// The upstream queries go to.
    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// The socket's fd, for the net thread to watch for reading.
    pub fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// How many queries wait for the upstream.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// How long queries sent from now on wait.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Sends the guest's query upstream under a fresh id, to wait for its
    /// answer until `now` and the timeout. A query that cannot wait, or
    /// cannot be sent, comes back with the reason.
    pub fn forward(
        &mut self,
        pending: Pending,
        now: Instant,
    ) -> Result<(), (Pending, ForwardError)> {
        if self.in_flight.len() >= self.cap {
            return Err((pending, ForwardError::Full));
        }
        let Some(id) = self.fresh_id() else {
            return Err((pending, ForwardError::Full));
        };
        let mut message = pending.query.clone();
        match message.get_mut(..2) {
            Some(head) => head.copy_from_slice(&id.to_be_bytes()),
            None => {
                let error = io::Error::new(ErrorKind::InvalidInput, "shorter than a DNS header");
                return Err((pending, ForwardError::Send(error)));
            }
        }
        if let Err(error) = self.send(&message) {
            return Err((pending, ForwardError::Send(error)));
        }
        self.seq += 1;
        let deadline = now.checked_add(self.timeout).unwrap_or(now);
        self.in_flight.insert(
            id,
            InFlight {
                pending,
                deadline,
                seq: self.seq,
            },
        );
        Ok(())
    }

    /// Reads every datagram waiting on the socket, in the order they came:
    /// answers to queries in flight, which leave the table, and the bogus
    /// rest.
    pub fn receive(&mut self) -> Vec<Received> {
        let mut buf = std::mem::take(&mut self.buf);
        let mut received = Vec::new();
        let mut errors = 0;
        loop {
            match self.socket.recv(&mut buf) {
                Ok(len) => {
                    let answer = buf.get(..len).and_then(|datagram| self.accept(datagram));
                    received.push(answer.map_or(Received::Bogus, Received::Answer));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => {
                    // An ICMP error for an earlier query, most likely: the
                    // upstream's port is closed or it is unreachable. The
                    // queries it was for time out.
                    boxcar_virtio::limited!(warn, "net: dns upstream {}: {error}", self.upstream);
                    errors += 1;
                    if errors >= MAX_ERRORS {
                        break;
                    }
                }
            }
        }
        self.buf = buf;
        received
    }

    /// The queries whose time is up at `now`, taken from the table, in the
    /// order they were sent.
    pub fn expire(&mut self, now: Instant) -> Vec<Pending> {
        self.take(|waiting| waiting.deadline <= now)
    }

    /// When the next query's time is up, if any waits.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.in_flight
            .values()
            .map(|waiting| waiting.deadline)
            .min()
    }

    /// Every query still waiting, taken from the table, in the order they
    /// were sent: for when the stack stops.
    pub fn abandon(&mut self) -> Vec<Pending> {
        self.take(|_| true)
    }

    fn take(&mut self, due: impl Fn(&InFlight) -> bool) -> Vec<Pending> {
        let mut ids: Vec<(u64, u16)> = self
            .in_flight
            .iter()
            .filter(|(_, waiting)| due(waiting))
            .map(|(id, waiting)| (waiting.seq, *id))
            .collect();
        ids.sort_unstable();
        ids.into_iter()
            .filter_map(|(_, id)| self.in_flight.remove(&id))
            .map(|waiting| waiting.pending)
            .collect()
    }

    /// The answer `datagram` gives, if it is one: a response with an id in
    /// flight, that query's question (name in any case, type and class),
    /// and records that read.
    fn accept(&mut self, datagram: &[u8]) -> Option<Answer> {
        let (id, question) = parse::parse_reply(datagram).ok()?;
        if self.in_flight.get(&id)?.pending.question != question {
            return None;
        }
        let answers = parse::parse_answers(datagram).ok()?;
        let pending = self.in_flight.remove(&id)?.pending;
        let mut reply = datagram.to_vec();
        reply
            .get_mut(..2)?
            .copy_from_slice(&pending.txid.to_be_bytes());
        Some(Answer {
            pending,
            reply,
            answers,
        })
    }

    /// An id no query in flight has, drawn again while it collides.
    fn fresh_id(&mut self) -> Option<u16> {
        for _ in 0..ID_DRAWS {
            let id = self.next_id();
            if !self.in_flight.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    /// The next id: the keyed hash of the next counter value. Without the
    /// key, the ids already seen say nothing about the next one.
    fn next_id(&mut self) -> u16 {
        self.id_counter = self.id_counter.wrapping_add(1);
        // 16 of SipHash's 64 output bits.
        (self.id_key.hash_one(self.id_counter) >> 48) as u16
    }

    /// Sends one datagram. A connected UDP socket reports the ICMP error
    /// of an earlier datagram at its next call, a send included, which then
    /// sends nothing; so a refusal is tried once more.
    fn send(&self, message: &[u8]) -> io::Result<()> {
        match self.socket.send(message) {
            Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                self.socket.send(message).map(drop)
            }
            sent => sent.map(drop),
        }
    }
}

/// A non-blocking UDP socket connected to `upstream`.
fn socket_to(upstream: SocketAddr) -> io::Result<UdpSocket> {
    let any: SocketAddr = match upstream {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any)?;
    socket.set_nonblocking(true)?;
    socket.connect(upstream)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        let mut m = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend([0, 0, 1, 0, 1]);
        m
    }

    fn pending(txid: u16, name: &str) -> Pending {
        Pending {
            txid,
            guest: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 41_000),
            question: Question {
                name: name.to_owned(),
                qtype: 1,
                qclass: 1,
            },
            query: query(name),
            verdict: Verdict::Allow,
            rule: None,
        }
    }

    /// A forwarder to a socket on 127.0.0.1 that the test holds.
    fn local() -> (Forwarder, UdpSocket) {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let forwarder = Forwarder::connect(&[upstream.local_addr().unwrap()]).unwrap();
        (forwarder, upstream)
    }

    /// The upstream's empty answer to `query`.
    fn empty_answer(query: &[u8]) -> Vec<u8> {
        let mut m = query.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m
    }

    #[test]
    fn answers_are_matched_by_id_and_given_back_the_guests_id() {
        let (mut forwarder, upstream) = local();
        let now = Instant::now();
        for (txid, name) in [(1, "a.test"), (2, "b.test"), (3, "c.test")] {
            forwarder.forward(pending(txid, name), now).unwrap();
        }
        assert_eq!(forwarder.in_flight(), 3);
        let mut sent = Vec::new();
        for _ in 0..3 {
            let mut buf = [0; 512];
            let (n, from) = upstream.recv_from(&mut buf).unwrap();
            sent.push((buf[..n].to_vec(), from));
        }
        let ids: std::collections::HashSet<_> = sent.iter().map(|(m, _)| [m[0], m[1]]).collect();
        assert_eq!(ids.len(), 3, "distinct ids");

        let (b_query, from) = &sent[1];
        upstream.send_to(&empty_answer(b_query), from).unwrap();
        let received = forwarder.receive();
        let [Received::Answer(answer)] = received.as_slice() else {
            panic!("{received:?}");
        };
        assert_eq!(answer.pending, pending(2, "b.test"));
        assert_eq!(answer.reply[..2], [0, 2]);
        assert_eq!(answer.reply[2..], empty_answer(b_query)[2..]);
        assert!(answer.answers.is_empty());
        assert_eq!(forwarder.in_flight(), 2);

        // The same answer again matches nothing in flight.
        upstream.send_to(&empty_answer(b_query), from).unwrap();
        assert_eq!(forwarder.receive(), [Received::Bogus]);
        assert!(forwarder.receive().is_empty(), "nothing left to read");
    }

    /// Ids are spread over the whole space and are not a simple step from
    /// one to the next; two forwarders draw different ids.
    #[test]
    fn ids_are_keyed_hashes_of_a_counter() {
        let (mut a, _ua) = local();
        let (mut b, _ub) = local();
        let ids: Vec<u16> = (0..4096).map(|_| a.next_id()).collect();
        let distinct: std::collections::HashSet<u16> = ids.iter().copied().collect();
        // 4096 draws from 65536 values: about 3970 distinct expected.
        assert!(distinct.len() > 3800, "{}", distinct.len());
        let steps: std::collections::HashSet<u16> =
            ids.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
        assert!(steps.len() > 3800, "no fixed stride: {}", steps.len());
        let high = ids.iter().filter(|id| **id >= 0x8000).count();
        assert!((1700..2400).contains(&high), "top bit balanced: {high}");
        let other: Vec<u16> = (0..64).map(|_| b.next_id()).collect();
        assert_ne!(ids[..64], other[..], "a key of its own");
    }

    #[test]
    fn queries_expire_in_the_order_they_were_sent() {
        let (mut forwarder, _upstream) = local();
        let t0 = Instant::now();
        forwarder.forward(pending(1, "a.test"), t0).unwrap();
        forwarder.set_timeout(Duration::from_secs(1));
        forwarder
            .forward(pending(2, "b.test"), t0 + Duration::from_millis(10))
            .unwrap();
        forwarder
            .forward(pending(3, "c.test"), t0 + Duration::from_millis(20))
            .unwrap();
        assert_eq!(
            forwarder.next_deadline(),
            Some(t0 + Duration::from_millis(1010))
        );
        assert!(forwarder
            .expire(t0 + Duration::from_millis(1009))
            .is_empty());
        let due: Vec<u16> = forwarder
            .expire(t0 + Duration::from_secs(2))
            .iter()
            .map(|p| p.txid)
            .collect();
        assert_eq!(due, [2, 3]);
        assert_eq!(forwarder.next_deadline(), Some(t0 + DNS_TIMEOUT));
        assert_eq!(forwarder.abandon(), [pending(1, "a.test")]);
        assert_eq!(forwarder.next_deadline(), None);
    }

    #[test]
    fn at_most_the_cap_wait() {
        let (mut forwarder, _upstream) = local();
        let now = Instant::now();
        for txid in 0..MAX_IN_FLIGHT as u16 {
            forwarder.forward(pending(txid, "a.test"), now).unwrap();
        }
        let (refused, why) = forwarder.forward(pending(999, "a.test"), now).unwrap_err();
        assert_eq!(refused.txid, 999);
        assert!(matches!(why, ForwardError::Full));
        assert_eq!(forwarder.in_flight(), MAX_IN_FLIGHT);
    }

    /// An upstream whose port is closed answers with ICMP errors, which
    /// the socket reports at its next call: they neither stop the reading
    /// nor the sending.
    #[test]
    fn a_closed_upstream_port_is_not_fatal() {
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let mut forwarder = Forwarder::connect(&[addr]).unwrap();
        let now = Instant::now();
        forwarder.forward(pending(1, "a.test"), now).unwrap();
        forwarder.forward(pending(2, "b.test"), now).unwrap();
        assert!(forwarder.receive().is_empty());
        forwarder.forward(pending(3, "c.test"), now).unwrap();
        assert!(forwarder.receive().is_empty());
        assert_eq!(forwarder.expire(now + DNS_TIMEOUT).len(), 3);
    }

    #[test]
    fn an_upstream_list_is_tried_in_order() {
        assert!(Forwarder::connect(&[]).is_err());
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = upstream.local_addr().unwrap();
        // A UDP socket without SO_BROADCAST cannot be connected to the
        // broadcast address; the next one is used.
        let unusable: SocketAddr = "255.255.255.255:53".parse().unwrap();
        let forwarder = Forwarder::connect(&[unusable, addr]).unwrap();
        assert_eq!(forwarder.upstream(), addr);
    }
}
