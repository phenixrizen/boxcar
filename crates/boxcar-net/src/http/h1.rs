// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! HTTP/1.1, read passively in both directions.
//!
//! Requests come in order on the guest's side and responses in the same
//! order on the host's (pipelining keeps the order), so a queue of the
//! requests seen pairs each response with its request: what a response's
//! body framing depends on (a `HEAD` has none), and which exchange it
//! belongs to. Heads are parsed by `httparse`; a body is as long as
//! `Content-Length` says, chunked, absent (requests without either,
//! `1xx`, `204`, `304`, answers to `HEAD`), or, for a response, until the
//! connection closes. A `101` that answers a WebSocket upgrade hands the
//! rest of both directions over ([`H1::take_upgrade`]).
//!
//! A head over [`MAX_HEADERS_BYTES`], one `httparse` refuses, or a chunk
//! size that does not read degrades that direction: nothing more is read
//! from it.

use std::collections::VecDeque;

use super::headers::{HeaderError, Headers, MAX_HEADERS_BYTES};
use super::{Event, Version};
use crate::gate::Direction;

/// The most headers one head may carry.
const MAX_HEADER_COUNT: usize = 128;

/// How a message's body is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    /// No body.
    None,
    /// This many bytes to come.
    Length(u64),
    /// Chunked: reading a size line.
    ChunkSize,
    /// Chunked: this many bytes of the chunk to come, then its CRLF.
    ChunkData(u64),
    /// Chunked: the CRLF after a chunk's data.
    ChunkEnd,
    /// Chunked: the trailer lines, up to a blank one.
    Trailers,
    /// A response that ends with the connection.
    UntilClose,
}

/// One direction's state.
#[derive(Debug)]
struct Side {
    buf: Vec<u8>,
    /// The body under way, for `stream`.
    body: Option<(u32, Framing)>,
    broken: bool,
}

impl Side {
    fn new() -> Side {
        Side {
            buf: Vec::new(),
            body: None,
            broken: false,
        }
    }
}

/// A request seen, waiting for its response.
#[derive(Clone, Debug)]
struct Seen {
    stream: u32,
    head: bool,
    upgrade: bool,
}

/// A `101` was answered: the connection is WebSocket from here, with the
/// bytes each direction had beyond the heads.
#[derive(Debug)]
pub struct Upgrade {
    pub stream: u32,
    pub extensions: Vec<String>,
    pub c2s: Vec<u8>,
    pub s2c: Vec<u8>,
}

/// An HTTP/1.1 connection's two directions.
#[derive(Debug)]
pub struct H1 {
    c2s: Side,
    s2c: Side,
    /// Requests whose response has not ended, oldest first.
    seen: VecDeque<Seen>,
    next_stream: u32,
    upgrade: Option<Upgrade>,
}

impl Default for H1 {
    fn default() -> Self {
        H1::new()
    }
}

impl H1 {
    pub fn new() -> H1 {
        H1 {
            c2s: Side::new(),
            s2c: Side::new(),
            seen: VecDeque::new(),
            next_stream: 1,
            upgrade: None,
        }
    }

    /// Takes bytes that moved in `dir`.
    pub fn feed(&mut self, dir: Direction, bytes: &[u8], out: &mut Vec<Event>) {
        if self.upgrade.is_some() {
            // Handed over: the caller takes the upgrade and the rest.
            if let Some(upgrade) = &mut self.upgrade {
                match dir {
                    Direction::ToHost => upgrade.c2s.extend_from_slice(bytes),
                    Direction::ToGuest => upgrade.s2c.extend_from_slice(bytes),
                }
            }
            return;
        }
        let side = match dir {
            Direction::ToHost => &mut self.c2s,
            Direction::ToGuest => &mut self.s2c,
        };
        if side.broken {
            return;
        }
        side.buf.extend_from_slice(bytes);
        loop {
            let before = (self.side(dir).buf.len(), self.side(dir).body);
            match dir {
                Direction::ToHost => self.read_request(out),
                Direction::ToGuest => self.read_response(out),
            }
            if self.upgrade.is_some() || self.side(dir).broken {
                break;
            }
            let after = (self.side(dir).buf.len(), self.side(dir).body);
            if after == before {
                break;
            }
        }
    }

    /// The upgrade a `101` made, once, with the bytes beyond it.
    pub fn take_upgrade(&mut self) -> Option<Upgrade> {
        self.upgrade.take()
    }

    /// Bytes were lost in `dir`: nothing more reads there, and what was
    /// open there is degraded.
    pub fn lost(&mut self, dir: Direction, out: &mut Vec<Event>) {
        let stream = self.side(dir).body.map(|(stream, _)| stream);
        self.degrade(dir, stream, "lost", out);
    }

    /// The connection ended: a response read until close ends now.
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        if let Some((stream, Framing::UntilClose)) = self.s2c.body {
            self.s2c.body = None;
            out.push(Event::ResponseEnd { stream });
            self.seen.retain(|s| s.stream != stream);
        }
        for side in [&mut self.c2s, &mut self.s2c] {
            if let Some((stream, _)) = side.body.take() {
                out.push(Event::Degraded {
                    stream: Some(stream),
                    reason: "incomplete",
                });
            }
        }
    }

    fn side(&mut self, dir: Direction) -> &mut Side {
        match dir {
            Direction::ToHost => &mut self.c2s,
            Direction::ToGuest => &mut self.s2c,
        }
    }

    fn degrade(
        &mut self,
        dir: Direction,
        stream: Option<u32>,
        reason: &'static str,
        out: &mut Vec<Event>,
    ) {
        let side = self.side(dir);
        side.broken = true;
        side.body = None;
        side.buf.clear();
        out.push(Event::Degraded { stream, reason });
    }

    /// One step on the guest's side: a body's bytes, or a request head.
    fn read_request(&mut self, out: &mut Vec<Event>) {
        // After a request that asks to switch protocols, what the guest
        // sends is the new protocol's if the host agrees: it waits for the
        // response.
        if self.c2s.body.is_none() && self.seen.back().is_some_and(|s| s.upgrade) {
            return;
        }
        if let Some((stream, framing)) = self.c2s.body {
            let done = body_step(&mut self.c2s, stream, framing, Direction::ToHost, out);
            match done {
                Ok(true) => {
                    self.c2s.body = None;
                    out.push(Event::RequestEnd { stream });
                }
                Ok(false) => {}
                Err(reason) => self.degrade(Direction::ToHost, Some(stream), reason, out),
            }
            return;
        }
        let mut storage = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
        let mut request = httparse::Request::new(&mut storage);
        let parsed = match request.parse(&self.c2s.buf) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) => {
                if self.c2s.buf.len() > MAX_HEADERS_BYTES {
                    self.degrade(Direction::ToHost, None, "head_too_large", out);
                }
                return;
            }
            Err(_) => return self.degrade(Direction::ToHost, None, "bad_request_head", out),
        };
        let method = request.method.unwrap_or("").to_owned();
        let path = request.path.map(str::to_owned);
        let headers = match collect(request.headers) {
            Ok(headers) => headers,
            Err(_) => return self.degrade(Direction::ToHost, None, "head_too_large", out),
        };
        self.c2s.buf.drain(..parsed);
        let stream = self.next_stream;
        self.next_stream = self.next_stream.wrapping_add(1).max(1);
        let framing = if headers.chunked() {
            Framing::ChunkSize
        } else {
            match headers.content_length() {
                Some(0) | None => Framing::None,
                Some(n) => Framing::Length(n),
            }
        };
        self.seen.push_back(Seen {
            stream,
            head: method.eq_ignore_ascii_case("HEAD"),
            upgrade: headers.upgrades_to_websocket(),
        });
        let authority = headers
            .get_str("host")
            .map(|h| h.trim().to_ascii_lowercase());
        out.push(Event::RequestHead {
            stream,
            method,
            authority,
            path,
            version: Version::Http1,
            headers,
        });
        if framing == Framing::None {
            out.push(Event::RequestEnd { stream });
        } else {
            self.c2s.body = Some((stream, framing));
        }
    }

    /// One step on the host's side: a body's bytes, or a response head.
    fn read_response(&mut self, out: &mut Vec<Event>) {
        if let Some((stream, framing)) = self.s2c.body {
            let done = body_step(&mut self.s2c, stream, framing, Direction::ToGuest, out);
            match done {
                Ok(true) => {
                    self.s2c.body = None;
                    out.push(Event::ResponseEnd { stream });
                    self.seen.retain(|s| s.stream != stream);
                }
                Ok(false) => {}
                Err(reason) => self.degrade(Direction::ToGuest, Some(stream), reason, out),
            }
            return;
        }
        if self.s2c.buf.is_empty() {
            return;
        }
        let Some(request) = self.seen.front().cloned() else {
            // A response to nothing the guest asked: unreadable from here.
            return self.degrade(Direction::ToGuest, None, "unrequested_response", out);
        };
        let mut storage = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
        let mut response = httparse::Response::new(&mut storage);
        let parsed = match response.parse(&self.s2c.buf) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) => {
                if self.s2c.buf.len() > MAX_HEADERS_BYTES {
                    self.degrade(
                        Direction::ToGuest,
                        Some(request.stream),
                        "head_too_large",
                        out,
                    );
                }
                return;
            }
            Err(_) => {
                return self.degrade(
                    Direction::ToGuest,
                    Some(request.stream),
                    "bad_response_head",
                    out,
                )
            }
        };
        let status = response.code.unwrap_or(0);
        let headers = match collect(response.headers) {
            Ok(headers) => headers,
            Err(_) => {
                return self.degrade(
                    Direction::ToGuest,
                    Some(request.stream),
                    "head_too_large",
                    out,
                )
            }
        };
        self.s2c.buf.drain(..parsed);
        let stream = request.stream;
        if status == 101 {
            let extensions = headers.websocket_extensions();
            out.push(Event::ResponseHead {
                stream,
                status,
                headers,
            });
            if request.upgrade {
                out.push(Event::Upgraded {
                    stream,
                    extensions: extensions.clone(),
                });
                self.seen.pop_front();
                self.upgrade = Some(Upgrade {
                    stream,
                    extensions,
                    c2s: std::mem::take(&mut self.c2s.buf),
                    s2c: std::mem::take(&mut self.s2c.buf),
                });
            } else {
                self.degrade(Direction::ToGuest, Some(stream), "unknown_upgrade", out);
            }
            return;
        }
        if (100..200).contains(&status) {
            // Interim: the final response follows for the same request.
            out.push(Event::ResponseHead {
                stream,
                status,
                headers,
            });
            return;
        }
        let framing = if request.head || status == 204 || status == 304 {
            Framing::None
        } else if headers.chunked() {
            Framing::ChunkSize
        } else {
            match headers.content_length() {
                Some(0) => Framing::None,
                Some(n) => Framing::Length(n),
                None => Framing::UntilClose,
            }
        };
        out.push(Event::ResponseHead {
            stream,
            status,
            headers,
        });
        if framing == Framing::None {
            out.push(Event::ResponseEnd { stream });
            self.seen.pop_front();
        } else {
            self.s2c.body = Some((stream, framing));
        }
    }
}

/// `httparse`'s headers as [`Headers`].
fn collect(parsed: &[httparse::Header<'_>]) -> Result<Headers, HeaderError> {
    let mut headers = Headers::new();
    for header in parsed {
        headers.push(header.name, header.value)?;
    }
    Ok(headers)
}

/// One step of a body: moves what the buffer holds of it. `Ok(true)` when
/// the body ended.
fn body_step(
    side: &mut Side,
    stream: u32,
    framing: Framing,
    dir: Direction,
    out: &mut Vec<Event>,
) -> Result<bool, &'static str> {
    let body = |bytes: Vec<u8>| match dir {
        Direction::ToHost => Event::RequestBody { stream, bytes },
        Direction::ToGuest => Event::ResponseBody { stream, bytes },
    };
    match framing {
        Framing::None => Ok(true),
        Framing::Length(left) => {
            if side.buf.is_empty() {
                return Ok(false);
            }
            let take = usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(side.buf.len());
            let bytes: Vec<u8> = side.buf.drain(..take).collect();
            out.push(body(bytes));
            let left = left - take as u64;
            side.body = Some((stream, Framing::Length(left)));
            Ok(left == 0)
        }
        Framing::UntilClose => {
            if !side.buf.is_empty() {
                out.push(body(std::mem::take(&mut side.buf)));
            }
            Ok(false)
        }
        Framing::ChunkSize => {
            let Some(end) = side.buf.windows(2).position(|w| w == b"\r\n") else {
                if side.buf.len() > 1024 {
                    return Err("bad_chunk");
                }
                return Ok(false);
            };
            let line = std::str::from_utf8(&side.buf[..end]).map_err(|_| "bad_chunk")?;
            let size = line.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size, 16).map_err(|_| "bad_chunk")?;
            side.buf.drain(..end + 2);
            side.body = Some((
                stream,
                if size == 0 {
                    Framing::Trailers
                } else {
                    Framing::ChunkData(size)
                },
            ));
            Ok(false)
        }
        Framing::ChunkData(left) => {
            if side.buf.is_empty() {
                return Ok(false);
            }
            let take = usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(side.buf.len());
            let bytes: Vec<u8> = side.buf.drain(..take).collect();
            out.push(body(bytes));
            let left = left - take as u64;
            side.body = Some((
                stream,
                if left == 0 {
                    Framing::ChunkEnd
                } else {
                    Framing::ChunkData(left)
                },
            ));
            Ok(false)
        }
        Framing::ChunkEnd => {
            if side.buf.len() < 2 {
                return Ok(false);
            }
            if &side.buf[..2] != b"\r\n" {
                return Err("bad_chunk");
            }
            side.buf.drain(..2);
            side.body = Some((stream, Framing::ChunkSize));
            Ok(false)
        }
        Framing::Trailers => {
            // Lines up to a blank one; the trailers themselves are not
            // kept.
            loop {
                let Some(end) = side.buf.windows(2).position(|w| w == b"\r\n") else {
                    if side.buf.len() > MAX_HEADERS_BYTES {
                        return Err("bad_chunk");
                    }
                    return Ok(false);
                };
                let blank = end == 0;
                side.buf.drain(..end + 2);
                if blank {
                    return Ok(true);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(c2s: &[u8], s2c: &[u8], split: usize) -> Vec<Event> {
        let mut h1 = H1::new();
        let mut out = Vec::new();
        for chunk in c2s.chunks(split.max(1)) {
            h1.feed(Direction::ToHost, chunk, &mut out);
        }
        for chunk in s2c.chunks(split.max(1)) {
            h1.feed(Direction::ToGuest, chunk, &mut out);
        }
        h1.finish(&mut out);
        out
    }

    fn bodies(events: &[Event], response: bool) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::RequestBody { bytes, .. } if !response => Some(bytes.clone()),
                Event::ResponseBody { bytes, .. } if response => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[test]
    fn a_request_with_a_length_and_a_response_with_one() {
        let c2s = b"POST /v1/messages HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer x\r\nContent-Length: 5\r\n\r\nhello";
        let s2c =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nok";
        for split in [1, 7, 4096] {
            let events = run(c2s, s2c, split);
            match &events[0] {
                Event::RequestHead {
                    stream: 1,
                    method,
                    authority,
                    path,
                    version: Version::Http1,
                    headers,
                } => {
                    assert_eq!(method, "POST");
                    assert_eq!(authority.as_deref(), Some("api.example"));
                    assert_eq!(path.as_deref(), Some("/v1/messages"));
                    assert_eq!(headers.len(), 3);
                    assert_eq!(headers.get("authorization"), None);
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(bodies(&events, false), b"hello");
            assert!(events.contains(&Event::RequestEnd { stream: 1 }));
            assert!(matches!(
                events
                    .iter()
                    .find(|e| matches!(e, Event::ResponseHead { .. })),
                Some(Event::ResponseHead {
                    stream: 1,
                    status: 200,
                    ..
                })
            ));
            assert_eq!(bodies(&events, true), b"ok");
            assert_eq!(
                events.last(),
                Some(&Event::ResponseEnd { stream: 1 }),
                "{split}: {events:?}"
            );
            assert!(
                !events.iter().any(|e| matches!(e, Event::Degraded { .. })),
                "{events:?}"
            );
        }
    }

    #[test]
    fn chunked_bodies_with_extensions_and_trailers() {
        let c2s = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n";
        let s2c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        for split in [1, 3, 4096] {
            let events = run(c2s, s2c, split);
            assert_eq!(bodies(&events, false), b"Wikipedia", "{split}");
            assert_eq!(bodies(&events, true), b"abc", "{split}");
            assert!(events.contains(&Event::RequestEnd { stream: 1 }));
            assert_eq!(events.last(), Some(&Event::ResponseEnd { stream: 1 }));
        }
    }

    #[test]
    fn pipelined_requests_pair_with_their_responses_in_order() {
        let c2s = b"HEAD /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\nGET /c HTTP/1.1\r\nHost: a\r\n\r\n";
        let s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\n\r\nuntil close";
        let events = run(c2s, s2c, 4096);
        let heads: Vec<(u32, u16)> = events
            .iter()
            .filter_map(|e| match e {
                Event::ResponseHead { stream, status, .. } => Some((*stream, *status)),
                _ => None,
            })
            .collect();
        assert_eq!(heads, [(1, 200), (2, 204), (3, 200)]);
        // HEAD's 200 with a length has no body; the 204 none; the last
        // reads until close.
        assert_eq!(bodies(&events, true), b"until close");
        let ends: Vec<u32> = events
            .iter()
            .filter_map(|e| match e {
                Event::ResponseEnd { stream } => Some(*stream),
                _ => None,
            })
            .collect();
        assert_eq!(ends, [1, 2, 3]);
    }

    #[test]
    fn a_101_hands_the_connection_over_with_the_bytes_beyond() {
        let mut h1 = H1::new();
        let mut out = Vec::new();
        h1.feed(Direction::ToHost, b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\n\r\n\x81\x01A", &mut out);
        h1.feed(Direction::ToGuest, b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n\x81\x01B", &mut out);
        let upgrade = h1.take_upgrade().expect("an upgrade");
        assert_eq!(upgrade.stream, 1);
        assert_eq!(upgrade.extensions, ["permessage-deflate"]);
        assert_eq!(upgrade.c2s, b"\x81\x01A");
        assert_eq!(upgrade.s2c, b"\x81\x01B");
        assert!(out
            .iter()
            .any(|e| matches!(e, Event::Upgraded { stream: 1, .. })));
        assert!(h1.take_upgrade().is_none());
    }

    #[test]
    fn bad_heads_and_oversized_ones_degrade_the_direction_only() {
        let events = run(
            b"NOT HTTP\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            4096,
        );
        assert!(
            matches!(
                events[0],
                Event::Degraded {
                    stream: None,
                    reason: "bad_request_head"
                }
            ),
            "{events:?}"
        );
        // The response side, with no request to pair, degrades on its own.
        assert!(
            matches!(
                events[1],
                Event::Degraded {
                    stream: None,
                    reason: "unrequested_response"
                }
            ),
            "{events:?}"
        );
        // A head that never ends and passes the limit (a value that goes
        // on and on; many headers would hit httparse's count first).
        let mut big = b"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEADERS_BYTES + 1024));
        let events = run(&big, b"", 1024);
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::Degraded {
                    reason: "head_too_large",
                    ..
                }
            )),
            "{events:?}"
        );
        let events = run(
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"",
            4096,
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::Degraded {
                    stream: Some(1),
                    reason: "bad_chunk"
                }
            )),
            "{events:?}"
        );
    }

    #[test]
    fn a_body_cut_short_is_incomplete_at_the_end() {
        let events = run(
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc",
            b"",
            4096,
        );
        assert_eq!(bodies(&events, false), b"abc");
        assert!(events.contains(&Event::Degraded {
            stream: Some(1),
            reason: "incomplete"
        }));
        assert!(!events.contains(&Event::RequestEnd { stream: 1 }));
    }
}
