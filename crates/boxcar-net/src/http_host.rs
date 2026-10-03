// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The gate's HTTP reader: the host a plain HTTP/1.x request is for.
//!
//! [`parse_request`] reads the request line and the headers up to the
//! blank line that ends them, and gives the host the request names: the
//! `Host` header (its name in any case), or the authority of an
//! absolute-form (`GET http://host/ HTTP/1.1`) or authority-form
//! (`CONNECT host:port HTTP/1.1`) target, which a server prefers over the
//! header. Where both are present they must name the same host. The host
//! comes back lowercase, without its port or a trailing dot.
//!
//! It reads strictly, so that what it reads is what a server reads: lines
//! end in CRLF (a bare CR or LF anywhere is refused), the request line is
//! `method SP target SP HTTP/1.0|HTTP/1.1` and at most
//! [`MAX_REQUEST_LINE`] bytes, header names are tokens with no space
//! before the colon (so a folded line is refused), and a request with two
//! `Host` headers, or a host with anything but letters, digits, `-`, `_`
//! and `.` (or a bracketed IPv6 literal), is refused. Every index is
//! checked; nothing here panics.

/// The longest request line read: a longer one is refused.
pub const MAX_REQUEST_LINE: usize = 8 * 1024;

/// The longest host name, without its trailing dot.
const MAX_HOST: usize = 253;

/// What a flow's first bytes say about a plain HTTP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The request line or the headers are not all there yet.
    NeedMore,
    /// A request for this host.
    Host(String),
    /// Not an HTTP/1.x request, or one that names no host or names it
    /// ambiguously.
    Invalid,
}

/// The host a plain HTTP request asks for, when `buf` holds one whole
/// (request line and headers); `None` otherwise, including when more
/// bytes are needed. The gate uses [`parse_request`], which says which.
pub fn parse_host(buf: &[u8]) -> Option<String> {
    match parse_request(buf) {
        Request::Host(host) => Some(host),
        Request::NeedMore | Request::Invalid => None,
    }
}

/// Reads the request at the start of `buf`; bytes after its headers do
/// not matter.
pub fn parse_request(buf: &[u8]) -> Request {
    let request_end = match line_end(buf, 0) {
        Err(()) => return Request::Invalid,
        Ok(None) => {
            // Refuse early what can never become a request line.
            let printable = buf
                .iter()
                .enumerate()
                .all(|(i, b)| (0x20..=0x7e).contains(b) || (*b == b'\r' && i + 1 == buf.len()));
            let start_ok = buf.first().is_none_or(|b| is_tchar(*b));
            return if printable && start_ok && buf.len() <= MAX_REQUEST_LINE + 1 {
                Request::NeedMore
            } else {
                Request::Invalid
            };
        }
        Ok(Some(end)) => end,
    };
    if request_end > MAX_REQUEST_LINE {
        return Request::Invalid;
    }
    let Some(line) = buf.get(..request_end) else {
        return Request::Invalid;
    };
    let Some(target_host) = request_line(line) else {
        return Request::Invalid;
    };
    let mut header_host: Option<String> = None;
    let mut at = request_end + 2;
    loop {
        let end = match line_end(buf, at) {
            Err(()) => return Request::Invalid,
            Ok(None) => {
                // Refuse early a header that can never be one.
                let partial = buf.get(at..).unwrap_or_default();
                let fits = partial.iter().enumerate().all(|(i, b)| {
                    *b == b'\t'
                        || (*b >= 0x20 && *b != 0x7f)
                        || (*b == b'\r' && i + 1 == partial.len())
                });
                let folded = matches!(partial.first(), Some(b' ' | b'\t'));
                return if fits && !folded {
                    Request::NeedMore
                } else {
                    Request::Invalid
                };
            }
            Ok(Some(end)) => end,
        };
        let Some(header) = buf.get(at..end) else {
            return Request::Invalid;
        };
        at = end + 2;
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header_field(header) else {
            return Request::Invalid;
        };
        if name.eq_ignore_ascii_case(b"host") {
            let Some(host) = authority_host(value) else {
                return Request::Invalid;
            };
            if header_host.replace(host).is_some() {
                return Request::Invalid;
            }
        }
    }
    match (target_host, header_host) {
        (Some(target), Some(header)) if target != header => Request::Invalid,
        (Some(host), _) | (None, Some(host)) => Request::Host(host),
        (None, None) => Request::Invalid,
    }
}

/// Where the line starting at `from` ends (the index of its CR), `None`
/// if its end is not there yet, or an error for a bare CR or LF.
fn line_end(buf: &[u8], from: usize) -> Result<Option<usize>, ()> {
    let rest = buf.get(from..).unwrap_or_default();
    for (i, b) in rest.iter().enumerate() {
        match b {
            b'\n' => return Err(()),
            b'\r' => {
                return match rest.get(i + 1) {
                    Some(b'\n') => Ok(Some(from + i)),
                    Some(_) => Err(()),
                    None => Ok(None),
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// The host a request line's target names, if it names one (`Some(None)`
/// for an origin-form or `*` target, which leave it to `Host`), or `None`
/// if the line is not an HTTP/1.x request line.
fn request_line(line: &[u8]) -> Option<Option<String>> {
    let mut parts = line.split(|b| *b == b' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || method.is_empty() || target.is_empty() {
        return None;
    }
    if !method.iter().all(|b| is_tchar(*b)) || !target.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return None;
    }
    if target.first() == Some(&b'/') || target == b"*" {
        return Some(None);
    }
    if let Some(at) = target.windows(3).position(|w| w == b"://") {
        // Absolute form: a scheme, then the authority up to the path,
        // query or fragment.
        let (scheme, rest) = (target.get(..at)?, target.get(at + 3..)?);
        if scheme.is_empty() || !scheme.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        let end = rest
            .iter()
            .position(|b| matches!(b, b'/' | b'?' | b'#'))
            .unwrap_or(rest.len());
        return authority_host(rest.get(..end)?).map(Some);
    }
    // Authority form, for CONNECT only.
    if method != b"CONNECT" {
        return None;
    }
    authority_host(target).map(Some)
}

/// A header line's name and value (without the whitespace around it), or
/// `None` if the name is not a token directly before the colon.
fn header_field(header: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = header.iter().position(|b| *b == b':')?;
    let (name, value) = (header.get(..colon)?, header.get(colon + 1..)?);
    if name.is_empty() || !name.iter().all(|b| is_tchar(*b)) {
        return None;
    }
    if !value
        .iter()
        .all(|b| *b == b'\t' || (*b >= 0x20 && *b != 0x7f))
    {
        return None;
    }
    let value = value.trim_ascii();
    Some((name, value))
}

/// The host of an authority, `host[:port]`: lowercase, without its port
/// or one trailing dot. `None` for user information, a bad port, or a host
/// with anything but letters, digits, `-`, `_` and `.` (or a bracketed IPv6
/// literal).
fn authority_host(authority: &[u8]) -> Option<String> {
    let (host, port) = if authority.first() == Some(&b'[') {
        let close = authority.iter().position(|b| *b == b']')?;
        let literal = authority.get(1..close)?;
        if literal.is_empty()
            || !literal
                .iter()
                .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        {
            return None;
        }
        (authority.get(..=close)?, authority.get(close + 1..)?)
    } else {
        match authority.iter().rposition(|b| *b == b':') {
            Some(colon) => (authority.get(..colon)?, authority.get(colon..)?),
            None => (authority, &b""[..]),
        }
    };
    // What follows the host: nothing, or a port.
    if let Some(digits) = port.strip_prefix(b":") {
        if digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
    } else if !port.is_empty() {
        return None;
    }
    let host = host.strip_suffix(b".").unwrap_or(host);
    let bracketed = host.first() == Some(&b'[');
    if host.is_empty()
        || host.len() > MAX_HOST
        || (!bracketed
            && !host
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    {
        return None;
    }
    std::str::from_utf8(host).ok().map(str::to_ascii_lowercase)
}

/// A byte of an HTTP token (RFC 9110 §5.6.2).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn host(name: &str) -> Request {
        Request::Host(name.to_owned())
    }

    #[test]
    fn the_host_header_names_the_host() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            host("example.com")
        );
        assert_eq!(
            parse_request(b"GET /a?b HTTP/1.0\r\nUser-Agent: x\r\nhOsT:\t Example.COM.:8080 \r\nAccept: */*\r\n\r\nbody"),
            host("example.com")
        );
        assert_eq!(
            parse_host(b"OPTIONS * HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(
            parse_host(b"POST /x HTTP/1.1\r\nHost: a_b-c.example:\r\n\r\n").as_deref(),
            Some("a_b-c.example"),
            "an empty port"
        );
    }

    #[test]
    fn a_target_with_an_authority_names_the_host() {
        assert_eq!(
            parse_request(b"GET http://Example.com:80/x HTTP/1.1\r\n\r\n"),
            host("example.com")
        );
        assert_eq!(
            parse_request(b"GET http://example.com?q HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            host("example.com")
        );
        assert_eq!(
            parse_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
            host("example.com")
        );
        // The target wins at the server, so the two must agree.
        assert_eq!(
            parse_request(b"GET http://evil.example/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Request::Invalid
        );
        assert_eq!(
            parse_request(b"GET http://user@example.com/ HTTP/1.1\r\n\r\n"),
            Request::Invalid
        );
        assert_eq!(
            parse_request(b"GET example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Request::Invalid,
            "authority form is for CONNECT"
        );
    }

    #[test]
    fn partial_requests_need_more() {
        let whole = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        for cut in 0..whole.len() {
            assert_eq!(parse_request(&whole[..cut]), Request::NeedMore, "{cut}");
        }
        assert_eq!(parse_request(whole), host("example.com"));
        // A request line up to the limit may still be coming.
        let mut long = b"GET /".to_vec();
        long.resize(MAX_REQUEST_LINE, b'a');
        assert_eq!(parse_request(&long), Request::NeedMore);
    }

    #[test]
    fn what_a_server_might_read_differently_is_invalid() {
        for bad in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
            b"GET / HTTP/1.1\nHost: example.com\n\n",
            b"GET / HTTP/1.1\r\nHost: example.com\nHost: evil.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\revil\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nX: y\r\n Host: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: exa mple.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com:80:80\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com:http\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com/x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: \r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: [zz]\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n",
            b"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET / HTTP/2.0\r\nHost: example.com\r\n\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET /\r\n\r\n",
            b"G(T / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"\x16\x03\x01\x00\x10",
            b"GET / HTTP/1.1\r\n\x00",
        ] {
            assert_eq!(
                parse_request(bad),
                Request::Invalid,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let mut long = b"GET /".to_vec();
        long.resize(MAX_REQUEST_LINE + 2, b'a');
        assert_eq!(
            parse_request(&long),
            Request::Invalid,
            "a request line past the limit"
        );
        long.truncate(MAX_REQUEST_LINE + 1);
        long.extend(b" HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(parse_request(&long), Request::Invalid);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn parse_request_never_panics(
            noise in vec(any::<u8>(), 0..512),
            header in "[ -~]{0,64}",
            cut in any::<prop::sample::Index>(),
        ) {
            parse_request(&noise);
            let request = format!("GET / HTTP/1.1\r\n{header}\r\nHost: example.com\r\n\r\n");
            let request = request.as_bytes();
            parse_request(&request[..cut.index(request.len() + 1)]);
            if let Request::Host(host) = parse_request(request) {
                prop_assert_eq!(host, "example.com");
            }
        }
    }
}
