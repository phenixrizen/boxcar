// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! DNS for the guest: the gateway (`10.0.2.2:53`) answers its queries by
//! forwarding them to the host's resolver, under the egress policy.
//!
//! A guest message that is not one plain query (a response, another
//! opcode, other than one question, or one that does not read) gets
//! FORMERR. A name the policy denies gets NXDOMAIN, made here. Any other
//! query goes upstream ([`forwarder`]); its answer comes back to the guest
//! with the guest's id, without AAAA answers (the guest network carries no
//! IPv6), and cut to its header and question with TC set if it would not
//! fit the link in one frame. A query the upstream does not answer in time,
//! or that cannot be sent, gets SERVFAIL. The addresses each answer gives
//! go into the [`cache`], under every name that led to them.
//!
//! - [`parse`]: reading, and rewriting, DNS messages.
//! - [`forwarder`]: the upstream socket and the queries waiting on it.
//! - [`cache`]: which names each address was given for.

pub mod cache;
pub mod forwarder;
pub mod parse;

use parse::{Header, FLAG_OPCODE, FLAG_QR, FLAG_RA, FLAG_RCODE, FLAG_RD, FLAG_TC};

use crate::stack::IP_MTU;

/// The response codes the stack gives or reads.
pub const NOERROR: u16 = 0;
pub const FORMERR: u16 = 1;
pub const SERVFAIL: u16 = 2;
pub const NXDOMAIN: u16 = 3;

/// The largest DNS message the guest's link carries in one frame: the IP
/// MTU less the IPv4 and UDP headers.
pub const MAX_MESSAGE: usize = IP_MTU - 20 - 8;

/// The answer with no records the gateway itself gives `query` (a guest
/// message at least a header long): its id, its opcode and RD bit, QR and
/// RA set, `rcode`, and its question if it has exactly one that reads.
/// `None` for a message shorter than a header.
pub fn error_reply(query: &[u8], rcode: u16) -> Option<Vec<u8>> {
    let header = Header::parse(query).ok()?;
    let flags = FLAG_QR | (header.flags & (FLAG_OPCODE | FLAG_RD)) | FLAG_RA | (rcode & FLAG_RCODE);
    Some(header_and_question(query, header.id, flags))
}

/// `reply` cut to its header and question, with TC set and no records:
/// what a server sends when the answer does not fit, so the guest asks
/// again over TCP. `None` for a message shorter than a header.
pub fn truncated(reply: &[u8]) -> Option<Vec<u8>> {
    let header = Header::parse(reply).ok()?;
    Some(header_and_question(
        reply,
        header.id,
        header.flags | FLAG_TC,
    ))
}

/// A message's response code: the low four bits of its flags (the EDNS
/// extension of it is not read). `None` for one shorter than a header.
pub fn rcode(message: &[u8]) -> Option<u16> {
    Header::parse(message)
        .ok()
        .map(|header| header.flags & FLAG_RCODE)
}

/// A header with `id` and `flags` and no records, then the question of
/// `message` written out again, if it has exactly one that reads.
fn header_and_question(message: &[u8], id: u16, flags: u16) -> Vec<u8> {
    let question = Header::parse(message)
        .ok()
        .filter(|header| header.counts[0] == 1)
        .and_then(|_| parse::read_question(message).ok());
    let mut out = Vec::with_capacity(parse::HEADER_LEN + parse::MAX_NAME_LEN + 4);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    let questions = u16::from(question.is_some());
    for count in [questions, 0, 0, 0] {
        out.extend_from_slice(&count.to_be_bytes());
    }
    if let Some(question) = question {
        out.extend_from_slice(&question.name);
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&question.qclass.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(flags: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34];
        m.extend(flags.to_be_bytes());
        m.extend([0, 1, 0, 0, 0, 0, 0, 1]);
        m.extend([
            7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        m.extend([0, 1, 0, 1]);
        // An EDNS OPT record, which no error reply carries.
        m.extend([0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        m
    }

    #[test]
    fn error_replies_echo_the_id_opcode_rd_and_question() {
        let q = query(0x0100);
        let question_end = 12 + 13 + 4;
        let nx = error_reply(&q, NXDOMAIN).unwrap();
        assert_eq!(nx[..4], [0x12, 0x34, 0x81, 0x83]);
        assert_eq!(nx[4..12], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(nx[12..], q[12..question_end], "the question as asked");
        assert_eq!(rcode(&nx), Some(NXDOMAIN));

        // No RD asked, none given; another opcode is repeated.
        let status = error_reply(&query(0x1000), FORMERR).unwrap();
        assert_eq!(status[2..4], [0x90, 0x81]);
        // Two questions, or one that does not read: the header alone.
        let mut two = query(0x0100);
        two[5] = 2;
        assert_eq!(error_reply(&two, FORMERR).unwrap()[4..], [0; 8]);
        let mut cut = query(0x0100);
        cut.truncate(20);
        assert_eq!(error_reply(&cut, SERVFAIL).unwrap().len(), 12);
        assert_eq!(error_reply(&q[..11], FORMERR), None);
    }

    #[test]
    fn a_truncated_reply_keeps_its_flags_and_question_and_sets_tc() {
        let mut reply = query(0x8180);
        reply[7] = 1; // an answer count, though no answer follows
        let cut = truncated(&reply).unwrap();
        assert_eq!(cut[2..4], [0x83, 0x80]);
        assert_eq!(cut[4..12], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(cut.len(), 12 + 13 + 4);
        assert_eq!(truncated(&[0; 5]), None);
        assert_eq!(rcode(&[0; 5]), None);
    }
}
