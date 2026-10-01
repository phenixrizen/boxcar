// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! DNS messages, read and rewritten without trusting a byte of them.
//!
//! Every read is bounds-checked, and a malformed message is a [`DnsError`],
//! never a panic. Names are read under these limits:
//!
//! - a label is at most 63 bytes, and the two other label types (`0x40`
//!   and `0x80`) are refused;
//! - a whole name is at most 255 bytes in wire form;
//! - a compression pointer must point before its name's start and before
//!   every earlier pointer of the same name, at most 64 of them, so every
//!   name ends and a pointer loop is an error.
//!
//! A name is given as lowercase text, its labels joined with dots. A name
//! with a byte in a label that is not printable ASCII, or a dot or a
//! backslash inside a label, has no such text and is refused where text is
//! needed ([`DnsError::Name`]), so that two different names never read the
//! same; the queries a stub resolver sends never have one.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// The fixed header every DNS message starts with.
pub const HEADER_LEN: usize = 12;
/// The longest name in wire form, length bytes and the root included.
pub const MAX_NAME_LEN: usize = 255;
/// The most compression pointers one name may follow.
pub const MAX_HOPS: usize = 64;
/// The most CNAMEs followed from a question to its address.
pub const MAX_CHAIN: usize = 16;

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// The header flag bits this module reads or sets.
pub(crate) const FLAG_QR: u16 = 0x8000;
pub(crate) const FLAG_OPCODE: u16 = 0x7800;
pub(crate) const FLAG_TC: u16 = 0x0200;
pub(crate) const FLAG_RD: u16 = 0x0100;
pub(crate) const FLAG_RA: u16 = 0x0080;
pub(crate) const FLAG_RCODE: u16 = 0x000f;

/// A query's question, as the policy and the audit log see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Lowercase, labels joined with dots, no trailing dot; `.` for the
    /// root.
    pub name: String,
    pub qtype: u16,
}

/// Why a message was not read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("the message ends early")]
    Truncated,
    #[error("the message is a response, not a query")]
    NotQuery,
    #[error("the message is a query, not a response")]
    NotResponse,
    #[error("opcode {0} is not a standard query")]
    Opcode(u8),
    #[error("{0} questions; only messages with one are answered")]
    Questions(u16),
    #[error("a compression pointer does not point back")]
    Pointer,
    #[error("a name follows more than {MAX_HOPS} compression pointers")]
    Hops,
    #[error("a name is longer than {MAX_NAME_LEN} bytes")]
    NameTooLong,
    #[error("a label of an unknown type")]
    LabelType,
    #[error("a name has a byte that is not printable ASCII, or a dot or backslash in a label")]
    Name,
    #[error("a record's data does not fit its type")]
    Rdata,
}

/// The guest's id and question of a standard query (QR clear, opcode 0)
/// with exactly one question. The whole message must read, every record
/// included, and the name must have text.
pub fn parse_query(payload: &[u8]) -> Result<(u16, Question), DnsError> {
    let header = Header::parse(payload)?;
    if header.is_response() {
        return Err(DnsError::NotQuery);
    }
    if header.opcode() != 0 {
        return Err(DnsError::Opcode(header.opcode()));
    }
    if header.counts[0] != 1 {
        return Err(DnsError::Questions(header.counts[0]));
    }
    let message = walk(payload)?;
    let question = message.questions.first().ok_or(DnsError::Truncated)?;
    Ok((header.id, question.text()?))
}

/// The id and question of a response to a standard query with exactly one
/// question. Only the header and the question are read.
pub fn parse_reply(payload: &[u8]) -> Result<(u16, Question), DnsError> {
    let header = Header::parse(payload)?;
    if !header.is_response() {
        return Err(DnsError::NotResponse);
    }
    if header.opcode() != 0 {
        return Err(DnsError::Opcode(header.opcode()));
    }
    if header.counts[0] != 1 {
        return Err(DnsError::Questions(header.counts[0]));
    }
    Ok((header.id, read_question(payload)?.text()?))
}

/// The addresses a response gives for its question, with every name that
/// leads to each: for each A record of class IN in the answer section whose
/// owner is on the CNAME chain from the question, the owner, then each name
/// back along the chain to the question's, all with the least TTL along
/// the way. A records off the chain are not believed. The whole message
/// must read; a response with no answer gives an empty list.
pub fn parse_answers(payload: &[u8]) -> Result<Vec<(String, Ipv4Addr, u32)>, DnsError> {
    let message = walk(payload)?;
    let [question] = message.questions.as_slice() else {
        return Err(DnsError::Questions(message.header.counts[0]));
    };
    let qname = name_text(&question.name).ok_or(DnsError::Name)?;
    let mut cnames = Vec::new();
    let mut addresses = Vec::new();
    let answers = message
        .records
        .iter()
        .filter(|r| r.section == Section::Answer && r.class == CLASS_IN);
    for record in answers {
        match record.rtype {
            TYPE_A => {
                let octets = <[u8; 4]>::try_from(record.rdata).map_err(|_| DnsError::Rdata)?;
                if let Some(owner) = name_text(&record.name) {
                    addresses.push((owner, Ipv4Addr::from(octets), record.ttl()));
                }
            }
            TYPE_CNAME => {
                let target = match record.parts.as_deref() {
                    Some([Part::Name(target)]) => name_text(target),
                    _ => None,
                };
                if let (Some(owner), Some(target)) = (name_text(&record.name), target) {
                    cnames.push((owner, target, record.ttl()));
                }
            }
            _ => {}
        }
    }
    // Each name on the chain, with the least TTL of the CNAMEs leading to
    // it.
    let mut chain = vec![(qname, u32::MAX)];
    while chain.len() <= MAX_CHAIN {
        let Some((last, ttl)) = chain.last() else {
            break;
        };
        let Some((_, target, cname_ttl)) = cnames.iter().find(|(owner, ..)| owner == last) else {
            break;
        };
        if chain.iter().any(|(name, _)| name == target) {
            break;
        }
        let ttl = (*ttl).min(*cname_ttl);
        chain.push((target.clone(), ttl));
    }
    let mut found = Vec::new();
    for (owner, ip, ttl) in addresses {
        let Some(at) = chain.iter().position(|(name, _)| *name == owner) else {
            continue;
        };
        let Some(path) = chain.get(..=at) else {
            continue;
        };
        let ttl = path.iter().map(|(_, t)| *t).fold(ttl, u32::min);
        found.extend(path.iter().rev().map(|(name, _)| (name.clone(), ip, ttl)));
    }
    Ok(found)
}

/// The message without the AAAA records of its answer section, its answer
/// count lowered to match; everything else (the header, the question,
/// CNAMEs, the other sections) is kept. A message with no AAAA answer comes
/// back byte for byte; one that does not read comes back as it is.
///
/// Records after a removed one move, so their names are written again with
/// compression pointers of their own, and so are the names in the data of
/// the types that have them.
pub fn strip_aaaa(payload: &[u8]) -> Vec<u8> {
    try_strip_aaaa(payload).unwrap_or_else(|_| payload.to_vec())
}

fn try_strip_aaaa(payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    let message = walk(payload)?;
    let stripped = |r: &Record| r.section == Section::Answer && r.rtype == TYPE_AAAA;
    let removed = message.records.iter().filter(|r| stripped(r)).count();
    if removed == 0 {
        return Ok(payload.to_vec());
    }
    let header = message.header;
    let mut counts = header.counts;
    counts[1] = counts[1].saturating_sub(u16::try_from(removed).map_err(|_| DnsError::Rdata)?);
    let mut out = Writer::default();
    out.u16(header.id);
    out.u16(header.flags);
    for count in counts {
        out.u16(count);
    }
    for question in &message.questions {
        out.name(&question.name, true);
        out.u16(question.qtype);
        out.u16(question.qclass);
    }
    for record in message.records.iter().filter(|r| !stripped(r)) {
        out.name(&record.name, true);
        out.u16(record.rtype);
        out.u16(record.class);
        out.u32(record.raw_ttl);
        let length_at = out.bytes.len();
        out.u16(0);
        match &record.parts {
            None => out.bytes.extend_from_slice(record.rdata),
            Some(parts) => {
                let compress = compressible(record.rtype);
                for part in parts {
                    match part {
                        Part::Name(name) => out.name(name, compress),
                        Part::Bytes(bytes) => out.bytes.extend_from_slice(bytes),
                    }
                }
            }
        }
        let length = out.bytes.len() - length_at - 2;
        let length = u16::try_from(length).map_err(|_| DnsError::Rdata)?;
        if let Some(field) = out.bytes.get_mut(length_at..length_at + 2) {
            field.copy_from_slice(&length.to_be_bytes());
        }
    }
    Ok(out.bytes)
}

/// The header's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub id: u16,
    pub flags: u16,
    /// Questions, answers, authority records, additional records.
    pub counts: [u16; 4],
}

impl Header {
    pub(crate) fn parse(message: &[u8]) -> Result<Header, DnsError> {
        let field = |i: usize| u16_at(message, 2 * i);
        Ok(Header {
            id: field(0)?,
            flags: field(1)?,
            counts: [field(2)?, field(3)?, field(4)?, field(5)?],
        })
    }

    pub(crate) fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub(crate) fn opcode(&self) -> u8 {
        // Four bits.
        ((self.flags & FLAG_OPCODE) >> 11) as u8
    }
}

/// A question as it is in the message, its name in wire form with every
/// pointer followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawQuestion {
    pub name: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

impl RawQuestion {
    fn text(&self) -> Result<Question, DnsError> {
        Ok(Question {
            name: name_text(&self.name).ok_or(DnsError::Name)?,
            qtype: self.qtype,
        })
    }
}

/// The question right after the header, read alone.
pub(crate) fn read_question(message: &[u8]) -> Result<RawQuestion, DnsError> {
    let (name, next) = read_name(message, HEADER_LEN)?;
    Ok(RawQuestion {
        name,
        qtype: u16_at(message, next)?,
        qclass: u16_at(message, next + 2)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Section {
    Answer,
    Authority,
    Additional,
}

/// A resource record.
#[derive(Clone, Debug)]
pub(crate) struct Record<'a> {
    pub section: Section,
    /// The owner, in wire form with every pointer followed.
    pub name: Vec<u8>,
    pub rtype: u16,
    pub class: u16,
    /// The TTL as sent.
    pub raw_ttl: u32,
    /// The data as it is in the message.
    pub rdata: &'a [u8],
    /// The data read field by field, for the types whose data holds names;
    /// `None` for the rest, whose data is opaque.
    pub parts: Option<Vec<Part<'a>>>,
}

impl Record<'_> {
    /// The TTL, a value with its top bit set counting as zero (RFC 2181
    /// §8).
    pub(crate) fn ttl(&self) -> u32 {
        if self.raw_ttl > i32::MAX as u32 {
            0
        } else {
            self.raw_ttl
        }
    }
}

/// A field of a record's data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Part<'a> {
    /// A name, in wire form with every pointer followed.
    Name(Vec<u8>),
    Bytes(&'a [u8]),
}

/// A whole message, read.
#[derive(Clone, Debug)]
pub(crate) struct Message<'a> {
    pub header: Header,
    pub questions: Vec<RawQuestion>,
    pub records: Vec<Record<'a>>,
}

/// Reads the header, every question and every record the counts promise.
/// Bytes after the last record are ignored.
pub(crate) fn walk(message: &[u8]) -> Result<Message<'_>, DnsError> {
    let header = Header::parse(message)?;
    let [questions, answers, authority, additional] = header.counts;
    let mut at = HEADER_LEN;
    let mut read = Message {
        header,
        questions: Vec::new(),
        records: Vec::new(),
    };
    for _ in 0..questions {
        let (name, next) = read_name(message, at)?;
        read.questions.push(RawQuestion {
            name,
            qtype: u16_at(message, next)?,
            qclass: u16_at(message, next + 2)?,
        });
        at = next + 4;
    }
    for (section, count) in [
        (Section::Answer, answers),
        (Section::Authority, authority),
        (Section::Additional, additional),
    ] {
        for _ in 0..count {
            let (name, next) = read_name(message, at)?;
            let rtype = u16_at(message, next)?;
            let class = u16_at(message, next + 2)?;
            let raw_ttl = u32_at(message, next + 4)?;
            let length = usize::from(u16_at(message, next + 8)?);
            let start = next + 10;
            let rdata = message
                .get(start..start + length)
                .ok_or(DnsError::Truncated)?;
            let parts = read_rdata(message, start, start + length, rtype)?;
            read.records.push(Record {
                section,
                name,
                rtype,
                class,
                raw_ttl,
                rdata,
                parts,
            });
            at = start + length;
        }
    }
    Ok(read)
}

/// A field in the data of a type that holds names.
#[derive(Clone, Copy)]
enum Field {
    Name,
    Fixed(usize),
}

/// The fields of the data of the types that hold names: those RFC 1035
/// defines, which may be compressed, and RP, AFSDB, RT, PX and SRV, whose
/// names a receiver should decompress (RFC 3597 §4). Every other type's
/// data is opaque, and may hold no pointer.
fn layout(rtype: u16) -> Option<&'static [Field]> {
    use Field::{Fixed, Name};
    Some(match rtype {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR.
        2..=5 | 7..=9 | 12 => &[Name],
        // SOA: the primary server and the mailbox, then five numbers.
        6 => &[Name, Name, Fixed(20)],
        // MINFO, RP.
        14 | 17 => &[Name, Name],
        // MX, AFSDB, RT: a preference, then a name.
        15 | 18 | 21 => &[Fixed(2), Name],
        // PX.
        26 => &[Fixed(2), Name, Name],
        // SRV: priority, weight and port, then the target.
        33 => &[Fixed(6), Name],
        _ => return None,
    })
}

/// Whether names in a type's data may be written compressed: only in the
/// types RFC 1035 defines.
fn compressible(rtype: u16) -> bool {
    (2..=15).contains(&rtype)
}

/// The data from `start` to `end` read field by field, if its type holds
/// names; the fields must fill it exactly.
fn read_rdata(
    message: &[u8],
    start: usize,
    end: usize,
    rtype: u16,
) -> Result<Option<Vec<Part<'_>>>, DnsError> {
    let Some(fields) = layout(rtype) else {
        return Ok(None);
    };
    let mut parts = Vec::with_capacity(fields.len());
    let mut at = start;
    for field in fields {
        match *field {
            Field::Name => {
                let (name, next) = read_name(message, at)?;
                if next > end {
                    return Err(DnsError::Rdata);
                }
                parts.push(Part::Name(name));
                at = next;
            }
            Field::Fixed(len) => {
                if at + len > end {
                    return Err(DnsError::Rdata);
                }
                let bytes = message.get(at..at + len).ok_or(DnsError::Truncated)?;
                parts.push(Part::Bytes(bytes));
                at += len;
            }
        }
    }
    if at != end {
        return Err(DnsError::Rdata);
    }
    Ok(Some(parts))
}

/// The name at `at`, in wire form with every pointer followed (labels, then
/// the root's zero byte), and where the bytes after it in the message
/// start.
pub(crate) fn read_name(message: &[u8], at: usize) -> Result<(Vec<u8>, usize), DnsError> {
    let mut wire = Vec::new();
    let mut pos = at;
    // Every pointer must point below this: the name's start, then each
    // pointer's target. Positions only fall from pointer to pointer, so
    // the name ends.
    let mut below = at;
    let mut after = None;
    let mut hops = 0;
    loop {
        let len = *message.get(pos).ok_or(DnsError::Truncated)?;
        match len & 0xc0 {
            0x00 if len == 0 => {
                wire.push(0);
                return Ok((wire, after.unwrap_or(pos + 1)));
            }
            0x00 => {
                let len = usize::from(len);
                let label = message
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(DnsError::Truncated)?;
                // The label, its length byte, and the root's byte to come.
                if wire.len() + 1 + len + 1 > MAX_NAME_LEN {
                    return Err(DnsError::NameTooLong);
                }
                wire.push(len as u8);
                wire.extend_from_slice(label);
                pos += 1 + len;
            }
            0xc0 => {
                let low = *message.get(pos + 1).ok_or(DnsError::Truncated)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if target >= below {
                    return Err(DnsError::Pointer);
                }
                hops += 1;
                if hops > MAX_HOPS {
                    return Err(DnsError::Hops);
                }
                after.get_or_insert(pos + 2);
                below = target;
                pos = target;
            }
            _ => return Err(DnsError::LabelType),
        }
    }
}

/// A wire-form name as text: lowercase labels joined with dots, `.` for
/// the root. `None` if a label holds a byte that is not printable ASCII, a
/// dot or a backslash, or the name is not well formed.
pub(crate) fn name_text(wire: &[u8]) -> Option<String> {
    let mut text = String::new();
    let mut rest = wire;
    loop {
        let (&len, tail) = rest.split_first()?;
        if len == 0 {
            break;
        }
        let (label, tail) = tail.split_at_checked(usize::from(len))?;
        if !text.is_empty() {
            text.push('.');
        }
        for &b in label {
            if !b.is_ascii_graphic() || b == b'.' || b == b'\\' {
                return None;
            }
            text.push(char::from(b.to_ascii_lowercase()));
        }
        rest = tail;
    }
    if text.is_empty() {
        text.push('.');
    }
    Some(text)
}

/// A wire-form name as text for a record, whatever its bytes: as
/// [`name_text`] where it has text, else with each byte that is not
/// printable ASCII written `\DDD`, and a dot or backslash in a label
/// escaped with a backslash (as in a zone file).
pub(crate) fn name_display(wire: &[u8]) -> String {
    if let Some(text) = name_text(wire) {
        return text;
    }
    let mut text = String::new();
    let mut rest = wire;
    while let Some((&len, tail)) = rest.split_first() {
        if len == 0 {
            break;
        }
        let Some((label, tail)) = tail.split_at_checked(usize::from(len)) else {
            break;
        };
        if !text.is_empty() {
            text.push('.');
        }
        for &b in label {
            match b {
                b'.' | b'\\' => {
                    text.push('\\');
                    text.push(char::from(b));
                }
                _ if b.is_ascii_graphic() => text.push(char::from(b.to_ascii_lowercase())),
                _ => text.push_str(&format!("\\{b:03}")),
            }
        }
        rest = tail;
    }
    if text.is_empty() {
        text.push('.');
    }
    text
}

fn u16_at(message: &[u8], at: usize) -> Result<u16, DnsError> {
    match message.get(at..at + 2) {
        Some(&[a, b]) => Ok(u16::from_be_bytes([a, b])),
        _ => Err(DnsError::Truncated),
    }
}

fn u32_at(message: &[u8], at: usize) -> Result<u32, DnsError> {
    match message.get(at..at + 4) {
        Some(&[a, b, c, d]) => Ok(u32::from_be_bytes([a, b, c, d])),
        _ => Err(DnsError::Truncated),
    }
}

/// A message being written, with what it needs to compress names: where
/// each name suffix already written starts.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    suffixes: HashMap<Vec<u8>, u16>,
}

impl Writer {
    fn u16(&mut self, n: u16) {
        self.bytes.extend_from_slice(&n.to_be_bytes());
    }

    fn u32(&mut self, n: u32) {
        self.bytes.extend_from_slice(&n.to_be_bytes());
    }

    /// Writes a wire-form name. Compressed, it ends with a pointer to the
    /// longest suffix already written (byte for byte, so case is kept),
    /// and its own suffixes may be pointed to later.
    fn name(&mut self, wire: &[u8], compress: bool) {
        let mut rest = wire;
        while let Some((&len, tail)) = rest.split_first() {
            if len == 0 {
                break;
            }
            if compress {
                if let Some(&at) = self.suffixes.get(rest) {
                    self.u16(0xc000 | at);
                    return;
                }
                // A pointer has 14 bits.
                if let Ok(at @ 0..0x4000) = u16::try_from(self.bytes.len()) {
                    self.suffixes.insert(rest.to_vec(), at);
                }
            }
            let Some((label, after)) = tail.split_at_checked(usize::from(len)) else {
                break;
            };
            self.bytes.push(len);
            self.bytes.extend_from_slice(label);
            rest = after;
        }
        self.bytes.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    const SOA: u16 = 6;
    const MX: u16 = 15;
    const OPT: u16 = 41;

    fn wire(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn pointer(at: usize) -> Vec<u8> {
        (0xc000 | at as u16).to_be_bytes().to_vec()
    }

    fn header(id: u16, flags: u16, counts: [u16; 4]) -> Vec<u8> {
        let mut m = Vec::new();
        for n in [id, flags, counts[0], counts[1], counts[2], counts[3]] {
            m.extend(n.to_be_bytes());
        }
        m
    }

    /// Appends a record: `owner` already in wire form.
    fn push_rr(m: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
        m.extend(owner);
        m.extend(rtype.to_be_bytes());
        m.extend(CLASS_IN.to_be_bytes());
        m.extend(ttl.to_be_bytes());
        m.extend((rdata.len() as u16).to_be_bytes());
        m.extend(rdata);
    }

    fn question(m: &mut Vec<u8>, name: &str, qtype: u16) {
        m.extend(wire(name));
        m.extend(qtype.to_be_bytes());
        m.extend(CLASS_IN.to_be_bytes());
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = header(0x1234, FLAG_RD, [1, 0, 0, 0]);
        question(&mut m, name, qtype);
        m
    }

    /// Every record's owner, type and data with names as text, from a
    /// message that must read.
    fn records(m: &[u8]) -> Vec<(Section, String, u16, Vec<String>)> {
        walk(m)
            .unwrap()
            .records
            .iter()
            .map(|r| {
                let data = match &r.parts {
                    None => vec![format!("{:?}", r.rdata)],
                    Some(parts) => parts
                        .iter()
                        .map(|p| match p {
                            Part::Name(n) => name_display(n),
                            Part::Bytes(b) => format!("{b:?}"),
                        })
                        .collect(),
                };
                (r.section, name_display(&r.name), r.rtype, data)
            })
            .collect()
    }

    #[test]
    fn a_plain_query_reads_with_its_name_in_lowercase() {
        let mut m = header(0xbeef, FLAG_RD, [1, 0, 0, 1]);
        question(&mut m, "WWW.Example.com", TYPE_A);
        // An EDNS OPT record: the root, type 41, a 1232-byte payload size.
        m.extend([0]);
        m.extend(OPT.to_be_bytes());
        m.extend(1232u16.to_be_bytes());
        m.extend([0, 0, 0, 0, 0, 0]);
        assert_eq!(
            parse_query(&m),
            Ok((
                0xbeef,
                Question {
                    name: "www.example.com".into(),
                    qtype: TYPE_A
                }
            ))
        );
        assert_eq!(
            parse_query(&query("", TYPE_A)).map(|(_, q)| q.name),
            Ok(".".into()),
            "the root"
        );
    }

    #[test]
    fn a_query_that_is_not_plain_or_does_not_read_is_refused() {
        let plain = query("example.com", TYPE_A);
        let with = |change: fn(&mut Vec<u8>)| {
            let mut m = plain.clone();
            change(&mut m);
            parse_query(&m)
        };
        assert!(parse_query(&plain).is_ok());
        assert_eq!(with(|m| m[2] |= 0x80), Err(DnsError::NotQuery));
        assert_eq!(with(|m| m[2] |= 5 << 3), Err(DnsError::Opcode(5)));
        assert_eq!(with(|m| m[5] = 0), Err(DnsError::Questions(0)));
        assert_eq!(with(|m| m[5] = 2), Err(DnsError::Questions(2)));
        assert_eq!(with(|m| m.truncate(11)), Err(DnsError::Truncated));
        assert_eq!(with(|m| m.truncate(m.len() - 1)), Err(DnsError::Truncated));
        // A record promised and not there.
        assert_eq!(with(|m| m[7] = 1), Err(DnsError::Truncated));
        // The two reserved label types.
        assert_eq!(with(|m| m[12] = 0x47), Err(DnsError::LabelType));
        assert_eq!(with(|m| m[12] = 0x87), Err(DnsError::LabelType));
        // Bytes that have no text: a space, a control byte, a dot in a
        // label, a byte above ASCII.
        for bad in [b' ', 0x07, b'.', 0xc3] {
            let mut m = plain.clone();
            m[14] = bad;
            assert_eq!(parse_query(&m), Err(DnsError::Name), "{bad:#x}");
        }
        assert_eq!(parse_reply(&plain), Err(DnsError::NotResponse));
    }

    #[test]
    fn compression_pointers_must_point_back_and_end() {
        // A name made of a pointer to itself, to after itself, and two
        // names pointing at each other.
        let mut own = header(1, 0, [1, 0, 0, 0]);
        own.extend(pointer(12));
        own.extend([0, 1, 0, 1]);
        assert_eq!(parse_query(&own), Err(DnsError::Pointer));
        let mut ahead = header(1, 0, [1, 0, 0, 0]);
        ahead.extend(pointer(14));
        ahead.extend(wire("example.com"));
        assert_eq!(read_name(&ahead, 12), Err(DnsError::Pointer));
        // "a" + pointer to 16, and at 16 "b" + pointer back to 12.
        let mut pair = header(1, 0, [0; 4]);
        pair.extend([1, b'a']);
        pair.extend(pointer(16));
        pair.extend([1, b'b']);
        pair.extend(pointer(12));
        assert_eq!(read_name(&pair, 12), Err(DnsError::Pointer));
        assert_eq!(read_name(&pair, 16), Err(DnsError::Pointer));

        // A pointer back into the message is followed, and the name ends
        // where the pointer does.
        let mut chained = wire("example.com");
        let at = chained.len();
        chained.extend([3, b'w', b'w', b'w']);
        chained.extend(pointer(0));
        assert_eq!(
            read_name(&chained, at),
            Ok((wire("www.example.com"), chained.len()))
        );

        // 64 pointers in a row are followed; 65 are not.
        let mut hops = wire("x");
        for i in 0..MAX_HOPS + 1 {
            let target = if i == 0 { 0 } else { 3 + 2 * (i - 1) };
            hops.extend(pointer(target));
        }
        let at_hop = |n: usize| 3 + 2 * (n - 1);
        assert_eq!(read_name(&hops, at_hop(MAX_HOPS)).unwrap().0, wire("x"));
        assert_eq!(read_name(&hops, at_hop(MAX_HOPS + 1)), Err(DnsError::Hops));
    }

    #[test]
    fn names_and_labels_have_their_limits() {
        let label = |len| {
            let mut l = vec![len as u8];
            l.extend(std::iter::repeat_n(b'a', len));
            l
        };
        // Four 63-byte labels are 256 bytes with the root; three and one of
        // 61 are 255.
        let mut fits = [label(63), label(63), label(63), label(61)].concat();
        fits.push(0);
        assert_eq!(read_name(&fits, 0).map(|(n, _)| n.len()), Ok(255));
        let mut long = [label(63), label(63), label(63), label(62)].concat();
        long.push(0);
        assert_eq!(read_name(&long, 0), Err(DnsError::NameTooLong));
        // Too long by pointers too: a name pointing at a long one.
        let mut via = fits.clone();
        via.extend(label(1));
        via.extend(pointer(0));
        assert_eq!(read_name(&via, fits.len()), Err(DnsError::NameTooLong));
        // A label of 64 is the reserved 0x40 type.
        assert_eq!(read_name(&label(64), 0), Err(DnsError::LabelType));
    }

    #[test]
    fn names_as_text() {
        assert_eq!(
            name_text(&wire("Foo.Example.COM")).as_deref(),
            Some("foo.example.com")
        );
        assert_eq!(
            name_text(&wire("_dmarc.example.com")).as_deref(),
            Some("_dmarc.example.com")
        );
        assert_eq!(name_text(&[0]).as_deref(), Some("."));
        assert_eq!(name_text(&[3, b'a', b'.', b'b', 0]), None);
        assert_eq!(name_text(&[2, b'a', 0]), None, "not well formed");
        assert_eq!(name_display(&[3, b'a', b'.', b'B', 0]), "a\\.b");
        assert_eq!(name_display(&[2, b' ', 0xff, 1, b'x', 0]), "\\032\\255.x");
        assert_eq!(name_display(&[2, b'\\', b'z', 0]), "\\\\z");
    }

    /// `www.example.com` → CNAME `a.cdn.test` → CNAME `b.cdn.test` → A, as
    /// an upstream sends it, with compression.
    fn chain_reply() -> Vec<u8> {
        let mut m = header(0x4321, 0x8180, [1, 6, 0, 0]);
        question(&mut m, "www.example.com", TYPE_A);
        let a_target = m.len() + 12;
        push_rr(&mut m, &pointer(12), TYPE_CNAME, 300, &wire("a.cdn.test"));
        let mut b = vec![1, b'b'];
        b.extend(pointer(a_target + 2));
        let b_target = m.len() + 12;
        push_rr(&mut m, &pointer(a_target), TYPE_CNAME, 100, &b);
        push_rr(&mut m, &pointer(b_target), TYPE_A, 200, &[192, 0, 2, 1]);
        // Off the chain: not believed.
        push_rr(
            &mut m,
            &wire("elsewhere.test"),
            TYPE_A,
            200,
            &[203, 0, 113, 1],
        );
        // Another class: not believed.
        let mut chaos = Vec::new();
        push_rr(
            &mut chaos,
            &pointer(b_target),
            TYPE_A,
            200,
            &[203, 0, 113, 2],
        );
        chaos[pointer(0).len() + 3] = 3; // class CH
        m.extend(chaos);
        // A TTL with its top bit set counts as zero.
        push_rr(&mut m, &pointer(12), TYPE_A, 0x8000_0000, &[192, 0, 2, 2]);
        m
    }

    #[test]
    fn answers_follow_the_cname_chain_from_the_question() {
        let m = chain_reply();
        assert_eq!(
            parse_reply(&m),
            Ok((
                0x4321,
                Question {
                    name: "www.example.com".into(),
                    qtype: TYPE_A
                }
            ))
        );
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(
            parse_answers(&m),
            Ok(vec![
                ("b.cdn.test".into(), ip, 100),
                ("a.cdn.test".into(), ip, 100),
                ("www.example.com".into(), ip, 100),
                ("www.example.com".into(), Ipv4Addr::new(192, 0, 2, 2), 0),
            ])
        );

        // A CNAME loop ends the chain.
        let mut looped = header(1, 0x8180, [1, 2, 0, 0]);
        question(&mut looped, "a.test", TYPE_A);
        push_rr(
            &mut looped,
            &wire("a.test"),
            TYPE_CNAME,
            60,
            &wire("b.test"),
        );
        push_rr(
            &mut looped,
            &wire("b.test"),
            TYPE_CNAME,
            60,
            &wire("a.test"),
        );
        assert_eq!(parse_answers(&looped), Ok(vec![]));

        // An A record whose data is not four bytes does not read.
        let mut short = header(1, 0x8180, [1, 1, 0, 0]);
        question(&mut short, "a.test", TYPE_A);
        push_rr(&mut short, &pointer(12), TYPE_A, 60, &[192, 0, 2]);
        assert_eq!(parse_answers(&short), Err(DnsError::Rdata));
        // Nor does a CNAME whose name runs past its data.
        let mut overrun = header(1, 0x8180, [1, 1, 0, 0]);
        question(&mut overrun, "a.test", TYPE_A);
        push_rr(&mut overrun, &pointer(12), TYPE_CNAME, 60, &[1, b'x']);
        overrun.extend([0, 0, 0, 0]);
        assert_eq!(parse_answers(&overrun), Err(DnsError::Rdata));
    }

    #[test]
    fn strip_aaaa_keeps_everything_but_aaaa_answers() {
        // www.example.com AAAA: a CNAME to edge.cdn.test, two AAAA records
        // (one owned by a name that starts inside the record before it),
        // and an authority SOA and MX whose names point into what is
        // removed.
        let mut m = header(0x0a0a, 0x8180, [1, 3, 2, 1]);
        question(&mut m, "www.example.com", TYPE_AAAA);
        let edge = m.len() + 12;
        push_rr(
            &mut m,
            &pointer(12),
            TYPE_CNAME,
            300,
            &wire("edge.cdn.test"),
        );
        let v6 = m.len();
        push_rr(&mut m, &pointer(edge), TYPE_AAAA, 60, &[0x20; 16]);
        let mut v6_owner = vec![2, b'v', b'6'];
        v6_owner.extend(pointer(edge));
        let v6_at = m.len();
        push_rr(&mut m, &v6_owner, TYPE_AAAA, 60, &[0x21; 16]);
        let mut soa = pointer(v6_at);
        soa.extend(pointer(edge + 5)); // cdn.test
        soa.extend([0; 20]);
        push_rr(&mut m, &pointer(edge + 5), SOA, 60, &soa);
        let mut mx = vec![0, 10];
        mx.extend(pointer(v6_at));
        push_rr(&mut m, &pointer(v6), MX, 60, &mx);
        push_rr(&mut m, &[0], OPT, 0, &[]);

        let stripped = strip_aaaa(&m);
        let out = walk(&stripped).unwrap();
        assert_eq!(out.header.id, 0x0a0a);
        assert_eq!(out.header.flags, 0x8180);
        assert_eq!(out.header.counts, [1, 1, 2, 1]);
        assert_eq!(out.questions[0].name, wire("www.example.com"));
        let zero = format!("{:?}", [0u8; 20]);
        assert_eq!(
            records(&stripped),
            [
                (
                    Section::Answer,
                    "www.example.com".into(),
                    TYPE_CNAME,
                    vec!["edge.cdn.test".into()]
                ),
                (
                    Section::Authority,
                    "cdn.test".into(),
                    SOA,
                    vec!["v6.edge.cdn.test".into(), "cdn.test".into(), zero]
                ),
                (
                    Section::Authority,
                    "edge.cdn.test".into(),
                    MX,
                    vec![format!("{:?}", [0u8, 10]), "v6.edge.cdn.test".into()]
                ),
                (Section::Additional, ".".into(), OPT, vec!["[]".into()]),
            ]
        );
        assert!(stripped.len() < m.len());
        assert_eq!(strip_aaaa(&stripped), stripped, "nothing more to strip");

        // Without AAAA answers, or unreadable, the message is untouched.
        let a_only = chain_reply();
        assert_eq!(strip_aaaa(&a_only), a_only);
        let mut broken = m.clone();
        broken.truncate(broken.len() - 3);
        assert_eq!(strip_aaaa(&broken), broken);
        // AAAA outside the answer section stays.
        let mut glue = header(1, 0x8180, [1, 0, 0, 1]);
        question(&mut glue, "ns.test", TYPE_A);
        push_rr(&mut glue, &pointer(12), TYPE_AAAA, 60, &[0x22; 16]);
        assert_eq!(strip_aaaa(&glue), glue);
    }

    /// A label: mostly an ordinary one, sometimes any bytes at all (64 to
    /// 70 of them make one of the reserved label types).
    fn label() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![4 => vec(b'a'..=b'z', 1..8), 1 => vec(any::<u8>(), 0..70)]
    }

    /// A name: labels, then the root, a pointer to the question's name
    /// (which is how a server compresses), or a pointer anywhere near:
    /// ahead, behind, or at itself.
    fn name() -> impl Strategy<Value = Vec<u8>> {
        let end = prop_oneof![
            3 => Just(None),
            2 => Just(Some(12u16)),
            1 => (0u16..0x200).prop_map(Some),
        ];
        (vec(label(), 0..4), end).prop_map(|(labels, pointer)| {
            let mut out = Vec::new();
            for label in labels {
                out.push(label.len() as u8);
                out.extend(label);
            }
            match pointer {
                Some(at) => out.extend((0xc000 | at).to_be_bytes()),
                None => out.push(0),
            }
            out
        })
    }

    /// A record's type and data: mostly data shaped for its type, names
    /// included, and sometimes any type with any bytes.
    fn typed_rdata() -> impl Strategy<Value = (u16, Vec<u8>)> {
        let fixed = |n| vec(any::<u8>(), n..=n);
        prop_oneof![
            3 => fixed(4).prop_map(|d| (TYPE_A, d)),
            2 => fixed(16).prop_map(|d| (TYPE_AAAA, d)),
            2 => name().prop_map(|n| (TYPE_CNAME, n)),
            1 => (name(), name(), fixed(20)).prop_map(|(a, b, c)| (SOA, [a, b, c].concat())),
            1 => (fixed(2), name()).prop_map(|(p, n)| (MX, [p, n].concat())),
            1 => (fixed(6), name()).prop_map(|(p, n)| (33, [p, n].concat())),
            1 => vec(any::<u8>(), 0..16).prop_map(|d| (OPT, d)),
            1 => (any::<u16>(), vec(any::<u8>(), 0..40)),
        ]
    }

    /// A record, its length field usually right.
    fn record() -> impl Strategy<Value = Vec<u8>> {
        (
            name(),
            typed_rdata(),
            any::<u32>(),
            prop::option::weighted(0.05, any::<u16>()),
        )
            .prop_map(|(owner, (rtype, rdata), ttl, length)| {
                let mut out = owner;
                out.extend(rtype.to_be_bytes());
                out.extend(CLASS_IN.to_be_bytes());
                out.extend(ttl.to_be_bytes());
                let length = length.unwrap_or(rdata.len() as u16);
                out.extend(length.to_be_bytes());
                out.extend(rdata);
                out
            })
    }

    /// A message shaped like a query or a reply: a header whose counts
    /// usually match, one question, records, and now and then a few bytes
    /// changed.
    fn message() -> impl Strategy<Value = Vec<u8>> {
        let flags = prop_oneof![Just(FLAG_RD), Just(0x8180), any::<u16>()];
        let qtype = prop_oneof![Just(TYPE_A), Just(TYPE_AAAA), any::<u16>()];
        let qname = (vec(label(), 0..4)).prop_map(|labels| {
            let mut out = Vec::new();
            for label in labels {
                out.push(label.len() as u8);
                out.extend(label);
            }
            out.push(0);
            out
        });
        (
            any::<u16>(),
            flags,
            prop_oneof![4 => qname, 1 => name()],
            qtype,
            vec(record(), 0..6),
            vec(record(), 0..3),
            prop::option::weighted(0.05, any::<[u16; 4]>()),
            prop_oneof![4 => Just(vec![]), 1 => vec((any::<usize>(), any::<u8>()), 1..3)],
        )
            .prop_map(
                |(id, flags, qname, qtype, answers, more, counts, changes)| {
                    let counts = counts.unwrap_or([1, answers.len() as u16, more.len() as u16, 0]);
                    let mut m = header(id, flags, counts);
                    m.extend(qname);
                    m.extend(qtype.to_be_bytes());
                    m.extend(CLASS_IN.to_be_bytes());
                    for record in answers.into_iter().chain(more) {
                        m.extend(record);
                    }
                    let len = m.len();
                    for (at, byte) in changes {
                        m[at % len] = byte;
                    }
                    m
                },
            )
    }

    fn bytes_or_messages() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![vec(any::<u8>(), 0..600), message()]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn parse_query_never_panics(m in bytes_or_messages()) {
            let _ = parse_query(&m);
            let _ = parse_reply(&m);
            let _ = read_question(&m);
        }

        #[test]
        fn parse_answers_never_panics(m in bytes_or_messages()) {
            let _ = parse_answers(&m);
        }

        #[test]
        fn strip_aaaa_never_panics(m in bytes_or_messages()) {
            let _ = strip_aaaa(&m);
        }

        /// What reads strips to what reads, with the same header but the
        /// answer count, the same questions, and the same records, names
        /// and data, less the AAAA answers.
        #[test]
        fn strip_aaaa_keeps_what_it_does_not_strip(m in message()) {
            let Ok(before) = walk(&m) else { return Ok(()) };
            let stripped = strip_aaaa(&m);
            let after = walk(&stripped).expect("the stripped message reads");
            prop_assert_eq!(after.header.id, before.header.id);
            prop_assert_eq!(after.header.flags, before.header.flags);
            prop_assert_eq!(&after.questions, &before.questions);
            let kept: Vec<_> = records(&m)
                .into_iter()
                .filter(|(section, _, rtype, _)| !(*section == Section::Answer && *rtype == TYPE_AAAA))
                .collect();
            prop_assert_eq!(records(&stripped), kept);
            prop_assert_eq!(parse_answers(&stripped), parse_answers(&m));
        }
    }
}
