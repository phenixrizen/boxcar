// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The gate's TLS reader: the server name and the ALPN protocols a flow's
//! first bytes ask for, when they are a TLS ClientHello.
//!
//! [`parse_client_hello`] reads only the first TLS record: its header (a
//! handshake record, version 3.x, at most 16 KiB), the handshake header
//! (a ClientHello), and the hello's fields in order (legacy version,
//! random, session id, cipher suites, compression methods, extensions). Of
//! the extensions it reads `server_name` (type 0, its `host_name` entry)
//! and ALPN (type 16). A hello longer than its first record reads as
//! [`Hello::NeedMore`], as an incomplete record does: the gate's byte and
//! time limits turn that into a denial.
//!
//! It is hand-rolled: every length is checked against what is there
//! before it is used, and bytes that do not make a well-formed hello read
//! as [`Hello::NotTls`], never a panic. A hello that names its server
//! ambiguously (two `server_name` or ALPN extensions, two host names) or
//! with bytes no host name has is not well formed.

/// What a flow's first bytes say about a TLS ClientHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hello {
    /// They begin like a ClientHello, but its first record is not all
    /// there yet, or the hello goes on past it.
    NeedMore,
    /// A ClientHello: the host name it names, lowercase and without a
    /// trailing dot (`None` when it names none), and the ALPN protocols it
    /// offers, in its order.
    Tls {
        sni: Option<String>,
        alpn: Vec<String>,
    },
    /// Not a TLS handshake record, or not a well-formed ClientHello.
    NotTls,
}

/// The content type of a handshake record.
pub const CONTENT_HANDSHAKE: u8 = 22;
/// The longest TLS plaintext record (RFC 8446 §5.1).
pub const MAX_RECORD: usize = 1 << 14;

const RECORD_HEADER: usize = 5;
const HANDSHAKE_HEADER: usize = 4;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_ALPN: u16 = 16;
const NAME_TYPE_HOST_NAME: u8 = 0;
/// The longest host name, without its trailing dot.
const MAX_HOST_NAME: usize = 253;
/// The longest legacy session id.
const MAX_SESSION_ID: usize = 32;
/// The size of the hello's random.
const RANDOM: usize = 32;

/// Reads a ClientHello from the start of `buf`, the bytes a flow's client
/// has sent so far. Bytes after the first record do not matter.
pub fn parse_client_hello(buf: &[u8]) -> Hello {
    let Some(&content) = buf.first() else {
        return Hello::NeedMore;
    };
    if content != CONTENT_HANDSHAKE {
        return Hello::NotTls;
    }
    // The legacy record version: SSL 3.0 to TLS 1.3 all write 3.x.
    match buf.get(1) {
        None => return Hello::NeedMore,
        Some(3) => {}
        Some(_) => return Hello::NotTls,
    }
    match buf.get(2) {
        None => return Hello::NeedMore,
        Some(minor) if *minor <= 4 => {}
        Some(_) => return Hello::NotTls,
    }
    let Some(length) = Reader::at(buf, 3).u16() else {
        return Hello::NeedMore;
    };
    let length = usize::from(length);
    if length == 0 || length > MAX_RECORD {
        return Hello::NotTls;
    }
    let Some(record) = buf.get(RECORD_HEADER..RECORD_HEADER + length) else {
        return Hello::NeedMore;
    };
    let mut handshake = Reader(record);
    if handshake.u8() != Some(HANDSHAKE_CLIENT_HELLO) {
        return Hello::NotTls;
    }
    // A handshake header or a hello cut by the record's end goes on in the
    // next record, which is not read.
    let Some(body_length) = handshake.u24() else {
        return Hello::NeedMore;
    };
    let Some(body) = record.get(HANDSHAKE_HEADER..HANDSHAKE_HEADER.saturating_add(body_length))
    else {
        return Hello::NeedMore;
    };
    match client_hello(body) {
        Some((sni, alpn)) => Hello::Tls { sni, alpn },
        None => Hello::NotTls,
    }
}

/// The host name and ALPN protocols of a ClientHello's body, or `None` if
/// it is not well formed.
fn client_hello(body: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let mut hello = Reader(body);
    hello.skip(2)?; // legacy_version
    hello.skip(RANDOM)?;
    let session_id = usize::from(hello.u8()?);
    if session_id > MAX_SESSION_ID {
        return None;
    }
    hello.skip(session_id)?;
    let suites = usize::from(hello.u16()?);
    if suites < 2 || suites % 2 != 0 {
        return None;
    }
    hello.skip(suites)?;
    let compression = usize::from(hello.u8()?);
    if compression < 1 {
        return None;
    }
    hello.skip(compression)?;
    // Before TLS 1.2 the extensions may be absent altogether.
    if hello.is_empty() {
        return Some((None, Vec::new()));
    }
    let length = usize::from(hello.u16()?);
    let mut extensions = Reader(hello.take(length)?);
    if !hello.is_empty() {
        return None;
    }
    let mut sni: Option<Option<String>> = None;
    let mut alpn: Option<Vec<String>> = None;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let length = usize::from(extensions.u16()?);
        let data = extensions.take(length)?;
        let repeated = match kind {
            EXTENSION_SERVER_NAME => sni.replace(server_name(data)?).is_some(),
            EXTENSION_ALPN => alpn.replace(protocols(data)?).is_some(),
            _ => false,
        };
        if repeated {
            return None;
        }
    }
    Some((sni.flatten(), alpn.unwrap_or_default()))
}

/// The host name a `server_name` extension names (`None` when it names
/// only other kinds of name), or `None` outside if it is not well formed.
fn server_name(data: &[u8]) -> Option<Option<String>> {
    let mut extension = Reader(data);
    let length = usize::from(extension.u16()?);
    let list = extension.take(length)?;
    if !extension.is_empty() || list.is_empty() {
        return None;
    }
    let mut list = Reader(list);
    let mut host = None;
    while !list.is_empty() {
        let kind = list.u8()?;
        let length = usize::from(list.u16()?);
        let name = list.take(length)?;
        if kind == NAME_TYPE_HOST_NAME && host.replace(host_name(name)?).is_some() {
            return None;
        }
    }
    Some(host)
}

/// A host name as the gate matches it: printable ASCII without spaces,
/// lowercase, without one trailing dot, 1 to 253 bytes.
fn host_name(name: &[u8]) -> Option<String> {
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty() || name.len() > MAX_HOST_NAME || !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    std::str::from_utf8(name).ok().map(str::to_ascii_lowercase)
}

/// The protocols an ALPN extension offers, as text: printable ASCII as it
/// is, other bytes (and `\`) escaped as `\xNN`. `None` if the extension is
/// not well formed.
fn protocols(data: &[u8]) -> Option<Vec<String>> {
    let mut extension = Reader(data);
    let length = usize::from(extension.u16()?);
    let list = extension.take(length)?;
    if !extension.is_empty() || list.is_empty() {
        return None;
    }
    let mut list = Reader(list);
    let mut out = Vec::new();
    while !list.is_empty() {
        let length = usize::from(list.u8()?);
        if length == 0 {
            return None;
        }
        out.push(protocol_text(list.take(length)?));
    }
    Some(out)
}

fn protocol_text(id: &[u8]) -> String {
    let mut text = String::with_capacity(id.len());
    for &b in id {
        if b.is_ascii_graphic() && b != b'\\' {
            text.push(char::from(b));
        } else {
            text.push_str(&format!("\\x{b:02x}"));
        }
    }
    text
}

/// The unread rest of a byte string, read from the front. Every read
/// checks that the bytes are there and takes nothing when they are not.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The bytes of `buf` from `at` on (none if `at` is past its end).
    fn at(buf: &'a [u8], at: usize) -> Self {
        Reader(buf.get(at..).unwrap_or_default())
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        match *self.take(2)? {
            [high, low] => Some(u16::from_be_bytes([high, low])),
            _ => None,
        }
    }

    fn u24(&mut self) -> Option<usize> {
        match *self.take(3)? {
            [high, mid, low] => {
                Some(usize::from(high) << 16 | usize::from(mid) << 8 | usize::from(low))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn with_len16(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend(with_len16(data));
        out
    }

    fn sni_ext(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, name) in entries {
            list.push(*kind);
            list.extend(with_len16(name));
        }
        extension(0, &with_len16(&list))
    }

    fn alpn_ext(protocols: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for p in protocols {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        extension(16, &with_len16(&list))
    }

    /// A ClientHello body with these extensions (`None`: no extensions
    /// block at all).
    fn body(extensions: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend([0x42; RANDOM]);
        b.push(32);
        b.extend([0x5e; 32]);
        b.extend(with_len16(&[0x13, 0x01, 0x13, 0x02]));
        b.extend([1, 0]);
        if let Some(extensions) = extensions {
            b.extend(with_len16(extensions));
        }
        b
    }

    fn record(body: &[u8]) -> Vec<u8> {
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(body);
        let mut r = vec![CONTENT_HANDSHAKE, 3, 1];
        r.extend(with_len16(&handshake));
        r
    }

    fn hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        record(&body(Some(&extensions.concat())))
    }

    fn tls(sni: Option<&str>, alpn: &[&str]) -> Hello {
        Hello::Tls {
            sni: sni.map(str::to_owned),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn the_name_and_protocols_are_read() {
        let h = hello(&[
            extension(10, &[0, 2, 0, 29]),
            sni_ext(&[(0, b"Example.COM.")]),
            alpn_ext(&[b"h2", b"http/1.1"]),
            extension(43, &[2, 3, 4]),
        ]);
        assert_eq!(
            parse_client_hello(&h),
            tls(Some("example.com"), &["h2", "http/1.1"])
        );
        // Names of other kinds are passed over.
        let h = hello(&[sni_ext(&[(7, b"\x00\x01"), (0, b"a.example")])]);
        assert_eq!(parse_client_hello(&h), tls(Some("a.example"), &[]));
        assert_eq!(
            parse_client_hello(&hello(&[sni_ext(&[(7, b"other")])])),
            tls(None, &[])
        );
        // No extensions, or none of these.
        assert_eq!(parse_client_hello(&record(&body(None))), tls(None, &[]));
        assert_eq!(parse_client_hello(&hello(&[])), tls(None, &[]));
        // An ALPN id that is not text is escaped.
        let h = hello(&[alpn_ext(&[b"\x00\\x"])]);
        assert_eq!(parse_client_hello(&h), tls(None, &["\\x00\\x5cx"]));
    }

    #[test]
    fn short_input_needs_more_and_other_input_is_not_tls() {
        let h = hello(&[sni_ext(&[(0, b"example.com")])]);
        for cut in 0..h.len() {
            assert_eq!(parse_client_hello(&h[..cut]), Hello::NeedMore, "{cut}");
        }
        for not in [
            &b"GET / HTTP/1.1\r\n"[..],
            &[0x17, 3, 3, 0, 5][..],
            &[22, 2, 0][..],
            &[22, 3, 5][..],
            &[22, 3, 1, 0, 0][..],
            &[22, 3, 1, 0x40, 0x01][..],
            // A handshake that is not a ClientHello.
            &[22, 3, 3, 0, 4, 2, 0, 0, 0][..],
        ] {
            assert_eq!(parse_client_hello(not), Hello::NotTls, "{not:?}");
        }
    }

    #[test]
    fn a_hello_past_its_first_record_needs_more() {
        let full = hello(&[sni_ext(&[(0, b"example.com")])]);
        // Split the handshake message over two records.
        let handshake = &full[RECORD_HEADER..];
        let (a, b) = handshake.split_at(20);
        let mut split = vec![CONTENT_HANDSHAKE, 3, 1];
        split.extend(with_len16(a));
        split.extend([CONTENT_HANDSHAKE, 3, 1]);
        split.extend(with_len16(b));
        assert_eq!(parse_client_hello(&split), Hello::NeedMore);
        // Even the handshake header.
        let (a, b) = handshake.split_at(2);
        let mut split = vec![CONTENT_HANDSHAKE, 3, 1];
        split.extend(with_len16(a));
        split.extend([CONTENT_HANDSHAKE, 3, 1]);
        split.extend(with_len16(b));
        assert_eq!(parse_client_hello(&split), Hello::NeedMore);
    }

    #[test]
    fn ambiguous_or_malformed_hellos_are_not_tls() {
        for (why, h) in [
            (
                "two server_name extensions",
                hello(&[sni_ext(&[(0, b"a.example")]), sni_ext(&[(0, b"b.example")])]),
            ),
            (
                "two host names",
                hello(&[sni_ext(&[(0, b"a.example"), (0, b"b.example")])]),
            ),
            (
                "two ALPN extensions",
                hello(&[alpn_ext(&[b"h2"]), alpn_ext(&[b"h2"])]),
            ),
            ("an empty name list", hello(&[extension(0, &[0, 0])])),
            ("an empty name", hello(&[sni_ext(&[(0, b"")])])),
            ("just a dot", hello(&[sni_ext(&[(0, b".")])])),
            ("a space", hello(&[sni_ext(&[(0, b"a b.example")])])),
            ("a NUL", hello(&[sni_ext(&[(0, b"a.example\x00b")])])),
            (
                "not ASCII",
                hello(&[sni_ext(&[(0, "é.example".as_bytes())])]),
            ),
            ("too long", hello(&[sni_ext(&[(0, &[b'a'; 254])])])),
            ("an empty protocol", hello(&[alpn_ext(&[b""])])),
            ("an empty protocol list", hello(&[extension(16, &[0, 0])])),
            (
                "a list longer than its extension",
                hello(&[extension(0, &[0, 9, 0, 0, 1, b'a'])]),
            ),
            (
                "bytes after the list",
                hello(&[extension(16, &[0, 3, 2, b'h', b'2', 0xff])]),
            ),
            (
                "an extension past the block",
                record(&body(Some(&[0, 0, 0, 9, 1]))),
            ),
        ] {
            assert_eq!(parse_client_hello(&h), Hello::NotTls, "{why}");
        }
        // Fields before the extensions.
        let mut b = body(Some(&[]));
        b[2 + RANDOM] = 33;
        assert_eq!(parse_client_hello(&record(&b)), Hello::NotTls, "session id");
        let mut b = body(None);
        let suites = 2 + RANDOM + 1 + 32;
        b[suites + 1] = 3;
        assert_eq!(parse_client_hello(&record(&b)), Hello::NotTls, "odd suites");
        let mut b = body(None);
        b.extend([0xaa]);
        assert_eq!(
            parse_client_hello(&record(&b)),
            Hello::NotTls,
            "a stray byte"
        );
        let mut b = body(None);
        let compression = suites + 2 + 4;
        b[compression] = 0;
        b.truncate(compression + 1);
        assert_eq!(
            parse_client_hello(&record(&b)),
            Hello::NotTls,
            "compression"
        );
    }

    #[test]
    fn a_full_size_record_reads() {
        let padding = extension(21, &vec![0; MAX_RECORD - 200]);
        let h = hello(&[padding, sni_ext(&[(0, b"example.com")])]);
        assert!(h.len() - RECORD_HEADER <= MAX_RECORD);
        assert!(h.len() - RECORD_HEADER > MAX_RECORD - 200);
        assert_eq!(parse_client_hello(&h), tls(Some("example.com"), &[]));
        let over = hello(&[extension(21, &vec![0; MAX_RECORD])]);
        assert_eq!(
            parse_client_hello(&over),
            Hello::NotTls,
            "a record over 16 KiB"
        );
    }

    /// A hello built from parts the fuzzer picks: well-formed lengths most
    /// of the time, so the extension walk is reached.
    fn any_hello() -> impl Strategy<Value = Vec<u8>> {
        let ext = prop_oneof![
            vec(any::<u8>(), 0..40).prop_map(|name| sni_ext(&[(0, &name)])),
            vec(vec(any::<u8>(), 0..12), 0..4).prop_map(|ps| {
                let ps: Vec<&[u8]> = ps.iter().map(Vec::as_slice).collect();
                alpn_ext(&ps)
            }),
            (any::<u16>(), vec(any::<u8>(), 0..24)).prop_map(|(k, d)| extension(k, &d)),
            vec(any::<u8>(), 0..24),
        ];
        (
            vec(ext, 0..6),
            vec((any::<prop::sample::Index>(), any::<u8>()), 0..3),
        )
            .prop_map(|(exts, flips)| {
                let mut h = hello(&exts);
                for (at, byte) in flips {
                    let i = at.index(h.len());
                    h[i] = byte;
                }
                h
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn parse_client_hello_never_panics_on_built_hellos(
            h in any_hello(),
            cut in any::<prop::sample::Index>(),
        ) {
            let whole = parse_client_hello(&h);
            if let Hello::Tls { sni: Some(name), .. } = &whole {
                prop_assert!(name.bytes().all(|b| b.is_ascii_graphic()));
                prop_assert_eq!(name.to_ascii_lowercase(), name.clone());
            }
            parse_client_hello(&h[..cut.index(h.len() + 1)]);
        }
    }
}
