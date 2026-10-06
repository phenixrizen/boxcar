// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! HTTP/2, read passively in both directions.
//!
//! Frames are read as they come (the client's preface first); `HEADERS`
//! and `CONTINUATION` fragments make a header block, decoded with an HPACK
//! decoder per direction (`fluke-hpack`: the static and dynamic tables,
//! Huffman, size updates), whose dynamic table the peer's
//! `SETTINGS_HEADER_TABLE_SIZE` bounds; `DATA` is a stream's body;
//! `END_STREAM` ends a side of it; `RST_STREAM` degrades it. `PUSH_PROMISE`
//! blocks are decoded, so the table stays in step, and the promised
//! stream is not followed. Everything else (`SETTINGS` acks, `PING`,
//! `PRIORITY`, `WINDOW_UPDATE`, `GOAWAY`, unknown types) is passed over.
//!
//! Bounds: a header block [`MAX_HEADER_BLOCK`], [`MAX_STREAMS`] streams
//! open at once (the rest are degraded as they open), a frame's length
//! what the 24-bit field can say. A decoder error, a preface that is not
//! one, or a fragment out of order degrades the direction: nothing more is
//! read from it (its HPACK table cannot be trusted).

use std::collections::HashMap;

use fluke_hpack::Decoder;

use super::headers::Headers;
use super::{Event, Version};
use crate::gate::Direction;

/// What a client sends first.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The most bytes a header block (its fragments together) may hold.
pub const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// The most streams open at once.
pub const MAX_STREAMS: usize = 256;

const FRAME_HEADER: usize = 9;
const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const CONTINUATION: u8 = 9;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;
const ACK: u8 = 0x1;
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;

/// A header block under way.
struct Pending {
    stream: u32,
    block: Vec<u8>,
    end_stream: bool,
    /// A `PUSH_PROMISE`'s block: decoded for the table, not reported.
    promise: bool,
}

/// One direction's state.
struct Dir {
    buf: Vec<u8>,
    decoder: Decoder<'static>,
    pending: Option<Pending>,
    /// The client's preface has been read (the guest's side only).
    preface: bool,
    broken: bool,
}

impl Dir {
    fn new(preface_needed: bool) -> Dir {
        Dir {
            buf: Vec::new(),
            decoder: Decoder::new(),
            pending: None,
            preface: !preface_needed,
            broken: false,
        }
    }
}

/// What has been seen of a stream.
#[derive(Clone, Copy, Debug, Default)]
struct Stream {
    request_head: bool,
    request_end: bool,
    response_head: bool,
    response_end: bool,
}

impl Stream {
    fn done(&self) -> bool {
        self.request_end && self.response_end
    }
}

/// An HTTP/2 connection's two directions.
pub struct H2 {
    c2s: Dir,
    s2c: Dir,
    streams: HashMap<u32, Stream>,
    refused: usize,
}

impl Default for H2 {
    fn default() -> Self {
        H2::new()
    }
}

impl H2 {
    pub fn new() -> H2 {
        H2 {
            c2s: Dir::new(true),
            s2c: Dir::new(false),
            streams: HashMap::new(),
            refused: 0,
        }
    }

    /// Takes bytes that moved in `dir`.
    pub fn feed(&mut self, dir: Direction, bytes: &[u8], out: &mut Vec<Event>) {
        if self.side(dir).broken {
            return;
        }
        self.side(dir).buf.extend_from_slice(bytes);
        if !self.side(dir).preface {
            let side = self.side(dir);
            let have = side.buf.len().min(PREFACE.len());
            if side.buf[..have] != PREFACE[..have] {
                return self.degrade(dir, None, "no_preface", out);
            }
            if side.buf.len() < PREFACE.len() {
                return;
            }
            side.buf.drain(..PREFACE.len());
            side.preface = true;
        }
        loop {
            let side = self.side(dir);
            if side.broken || side.buf.len() < FRAME_HEADER {
                return;
            }
            let len = usize::from(side.buf[0]) << 16
                | usize::from(side.buf[1]) << 8
                | usize::from(side.buf[2]);
            let kind = side.buf[3];
            let flags = side.buf[4];
            let stream =
                u32::from_be_bytes([side.buf[5] & 0x7f, side.buf[6], side.buf[7], side.buf[8]]);
            if side.buf.len() < FRAME_HEADER + len {
                return;
            }
            let payload: Vec<u8> = side.buf[FRAME_HEADER..FRAME_HEADER + len].to_vec();
            side.buf.drain(..FRAME_HEADER + len);
            self.frame(dir, kind, flags, stream, &payload, out);
        }
    }

    /// Bytes were lost: the HPACK tables are out of step with the peer's,
    /// so nothing more can be read either way.
    pub fn lost(&mut self, out: &mut Vec<Event>) {
        for (stream, state) in &self.streams {
            if !state.done() {
                out.push(Event::Degraded {
                    stream: Some(*stream),
                    reason: "lost",
                });
            }
        }
        self.streams.clear();
        self.c2s.broken = true;
        self.s2c.broken = true;
    }

    /// The connection ended: what is open is incomplete.
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        let mut open: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.done())
            .map(|(id, _)| *id)
            .collect();
        open.sort_unstable();
        for stream in open {
            out.push(Event::Degraded {
                stream: Some(stream),
                reason: "incomplete",
            });
        }
        self.streams.clear();
    }

    fn side(&mut self, dir: Direction) -> &mut Dir {
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
        side.buf.clear();
        side.pending = None;
        out.push(Event::Degraded { stream, reason });
    }

    fn frame(
        &mut self,
        dir: Direction,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
        out: &mut Vec<Event>,
    ) {
        // A header block under way admits only its continuation.
        if let Some(pending) = &self.side(dir).pending {
            if kind != CONTINUATION || pending.stream != stream {
                return self.degrade(dir, Some(stream), "continuation", out);
            }
        }
        match kind {
            DATA => {
                let Some(body) = unpad(payload, flags & PADDED != 0) else {
                    return self.degrade(dir, Some(stream), "bad_padding", out);
                };
                if !self.streams.contains_key(&stream) {
                    return;
                }
                if !body.is_empty() {
                    out.push(match dir {
                        Direction::ToHost => Event::RequestBody {
                            stream,
                            bytes: body.to_vec(),
                        },
                        Direction::ToGuest => Event::ResponseBody {
                            stream,
                            bytes: body.to_vec(),
                        },
                    });
                }
                if flags & END_STREAM != 0 {
                    self.end(dir, stream, out);
                }
            }
            HEADERS => {
                let Some(mut fragment) = unpad(payload, flags & PADDED != 0) else {
                    return self.degrade(dir, Some(stream), "bad_padding", out);
                };
                if flags & PRIORITY_FLAG != 0 {
                    if fragment.len() < 5 {
                        return self.degrade(dir, Some(stream), "bad_headers", out);
                    }
                    fragment = &fragment[5..];
                }
                self.side(dir).pending = Some(Pending {
                    stream,
                    block: fragment.to_vec(),
                    end_stream: flags & END_STREAM != 0,
                    promise: false,
                });
                if flags & END_HEADERS != 0 {
                    self.complete(dir, out);
                } else if fragment.len() > MAX_HEADER_BLOCK {
                    self.degrade(dir, Some(stream), "header_block_too_large", out);
                }
            }
            PUSH_PROMISE => {
                let Some(rest) = unpad(payload, flags & PADDED != 0) else {
                    return self.degrade(dir, Some(stream), "bad_padding", out);
                };
                if rest.len() < 4 {
                    return self.degrade(dir, Some(stream), "bad_push_promise", out);
                }
                let promised = u32::from_be_bytes([rest[0] & 0x7f, rest[1], rest[2], rest[3]]);
                out.push(Event::Degraded {
                    stream: Some(promised),
                    reason: "push_promise",
                });
                self.side(dir).pending = Some(Pending {
                    stream,
                    block: rest[4..].to_vec(),
                    end_stream: false,
                    promise: true,
                });
                if flags & END_HEADERS != 0 {
                    self.complete(dir, out);
                }
            }
            CONTINUATION => {
                let Some(pending) = self.side(dir).pending.as_mut() else {
                    return self.degrade(dir, Some(stream), "continuation", out);
                };
                pending.block.extend_from_slice(payload);
                if pending.block.len() > MAX_HEADER_BLOCK {
                    return self.degrade(dir, Some(stream), "header_block_too_large", out);
                }
                if flags & END_HEADERS != 0 {
                    self.complete(dir, out);
                }
            }
            RST_STREAM => {
                if let Some(state) = self.streams.remove(&stream) {
                    if !state.done() {
                        out.push(Event::Degraded {
                            stream: Some(stream),
                            reason: "rst_stream",
                        });
                    }
                }
            }
            SETTINGS => {
                if flags & ACK != 0 || stream != 0 {
                    return;
                }
                for pair in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([pair[0], pair[1]]);
                    let value = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
                    if id == SETTINGS_HEADER_TABLE_SIZE {
                        // What this side's decoder allows bounds the other
                        // side's encoder, which is what the other side's
                        // decoder follows.
                        let other = match dir {
                            Direction::ToHost => &mut self.s2c,
                            Direction::ToGuest => &mut self.c2s,
                        };
                        other
                            .decoder
                            .set_max_table_size(usize::try_from(value).unwrap_or(usize::MAX));
                    }
                }
            }
            PRIORITY => {}
            _ => {}
        }
    }

    /// A header block is whole: decode it and report the head or the
    /// trailers it is.
    fn complete(&mut self, dir: Direction, out: &mut Vec<Event>) {
        let side = self.side(dir);
        let Some(pending) = side.pending.take() else {
            return;
        };
        let decoded = match side.decoder.decode(&pending.block) {
            Ok(fields) => fields,
            Err(_) => return self.degrade(dir, Some(pending.stream), "hpack", out),
        };
        if pending.promise {
            return;
        }
        let mut headers = Headers::new();
        let mut method = None;
        let mut path = None;
        let mut authority = None;
        let mut status = None;
        for (name, value) in &decoded {
            let name = String::from_utf8_lossy(name);
            let text = || String::from_utf8_lossy(value).into_owned();
            match name.as_ref() {
                ":method" => method = Some(text()),
                ":path" => path = Some(text()),
                ":authority" => authority = Some(text().to_ascii_lowercase()),
                ":status" => status = text().parse::<u16>().ok(),
                ":scheme" | ":protocol" => {}
                _ => {
                    if headers.push(&name, value).is_err() {
                        return self.degrade(
                            dir,
                            Some(pending.stream),
                            "header_block_too_large",
                            out,
                        );
                    }
                }
            }
        }
        let stream = pending.stream;
        let known = self.streams.contains_key(&stream);
        match dir {
            Direction::ToHost => {
                if !known {
                    if self.open_streams() >= MAX_STREAMS {
                        self.refused += 1;
                        return out.push(Event::Degraded {
                            stream: Some(stream),
                            reason: "streams",
                        });
                    }
                    self.streams.insert(stream, Stream::default());
                }
                let state = self.streams.entry(stream).or_default();
                if !state.request_head {
                    state.request_head = true;
                    let authority = authority.or_else(|| {
                        headers
                            .get_str("host")
                            .map(|h| h.trim().to_ascii_lowercase())
                    });
                    out.push(Event::RequestHead {
                        stream,
                        method: method.unwrap_or_default(),
                        authority,
                        path,
                        version: Version::Http2,
                        headers,
                    });
                }
                // Else trailers: nothing kept of them.
            }
            Direction::ToGuest => {
                if !known {
                    // A response to a request this side never saw.
                    return out.push(Event::Degraded {
                        stream: Some(stream),
                        reason: "unrequested_response",
                    });
                }
                let state = self.streams.entry(stream).or_default();
                if let Some(status) = status.filter(|_| !state.response_head) {
                    out.push(Event::ResponseHead {
                        stream,
                        status,
                        headers,
                    });
                    // An interim response is followed by the final one.
                    if !(100..200).contains(&status) {
                        state.response_head = true;
                    }
                }
            }
        }
        if pending.end_stream {
            self.end(dir, stream, out);
        }
    }

    fn end(&mut self, dir: Direction, stream: u32, out: &mut Vec<Event>) {
        let Some(state) = self.streams.get_mut(&stream) else {
            return;
        };
        match dir {
            Direction::ToHost => {
                if !state.request_end {
                    state.request_end = true;
                    out.push(Event::RequestEnd { stream });
                }
            }
            Direction::ToGuest => {
                if !state.response_end {
                    state.response_end = true;
                    out.push(Event::ResponseEnd { stream });
                }
            }
        }
        if state.done() {
            self.streams.remove(&stream);
        }
    }

    fn open_streams(&self) -> usize {
        self.streams.values().filter(|s| !s.done()).count()
    }
}

/// `payload` without its padding, when `padded`.
fn unpad(payload: &[u8], padded: bool) -> Option<&[u8]> {
    if !padded {
        return Some(payload);
    }
    let pad = usize::from(*payload.first()?);
    let body = &payload[1..];
    body.get(..body.len().checked_sub(pad)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame of `kind` with `flags` on `stream` carrying `payload`.
    pub(crate) fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(FRAME_HEADER + payload.len());
        let len = payload.len() as u32;
        f.extend_from_slice(&len.to_be_bytes()[1..]);
        f.push(kind);
        f.push(flags);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn encode(encoder: &mut fluke_hpack::Encoder<'_>, fields: &[(&str, &str)]) -> Vec<u8> {
        let fields: Vec<(&[u8], &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        encoder.encode(fields)
    }

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .flat_map(|w| {
                (0..w.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&w[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn run(c2s: &[u8], s2c: &[u8], split: usize) -> Vec<Event> {
        let mut h2 = H2::new();
        let mut out = Vec::new();
        for chunk in c2s.chunks(split.max(1)) {
            h2.feed(Direction::ToHost, chunk, &mut out);
        }
        for chunk in s2c.chunks(split.max(1)) {
            h2.feed(Direction::ToGuest, chunk, &mut out);
        }
        h2.finish(&mut out);
        out
    }

    /// RFC 7541 C.4: three requests with Huffman-coded strings on one
    /// connection, the dynamic table carrying across them.
    #[test]
    fn rfc_7541_c4_requests_decode_in_sequence() {
        let blocks = [
            hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"),
            hex("8286 84be 5886 a8eb 1064 9cbf"),
            hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
        ];
        let mut c2s = PREFACE.to_vec();
        for (i, block) in blocks.iter().enumerate() {
            c2s.extend(frame(
                HEADERS,
                END_HEADERS | END_STREAM,
                (2 * i + 1) as u32,
                block,
            ));
        }
        let events = run(&c2s, &[], 4096);
        type Head = (u32, String, Option<String>, Option<String>, usize);
        let heads: Vec<Head> = events
            .iter()
            .filter_map(|e| match e {
                Event::RequestHead {
                    stream,
                    method,
                    authority,
                    path,
                    headers,
                    ..
                } => Some((
                    *stream,
                    method.clone(),
                    authority.clone(),
                    path.clone(),
                    headers.len(),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            heads,
            [
                (
                    1,
                    "GET".into(),
                    Some("www.example.com".into()),
                    Some("/".into()),
                    0
                ),
                (
                    3,
                    "GET".into(),
                    Some("www.example.com".into()),
                    Some("/".into()),
                    1
                ),
                (
                    5,
                    "GET".into(),
                    Some("www.example.com".into()),
                    Some("/index.html".into()),
                    1
                ),
            ]
        );
        match &events[1] {
            Event::RequestEnd { stream: 1 } => {}
            other => panic!("{other:?}"),
        }
        let third = events
            .iter()
            .find(|e| matches!(e, Event::RequestHead { stream: 5, .. }))
            .unwrap();
        if let Event::RequestHead { headers, .. } = third {
            assert_eq!(headers.get_str("custom-key"), Some("custom-value"));
        }
        // No responses came: the streams are incomplete at the end, and
        // nothing else was wrong.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::Degraded { reason, .. } if *reason != "incomplete")),
            "{events:?}"
        );
    }

    /// A request and its streamed response, the request's block split over
    /// a CONTINUATION, padded DATA, two streams interleaved, at every
    /// split of the bytes.
    #[test]
    fn interleaved_streams_decode_the_same_at_any_split() {
        let mut enc_c = fluke_hpack::Encoder::new();
        let mut enc_s = fluke_hpack::Encoder::new();
        let head1 = encode(
            &mut enc_c,
            &[
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "api.example"),
                (":path", "/v1/messages"),
                ("content-type", "application/json"),
                ("authorization", "Bearer secret"),
            ],
        );
        let head3 = encode(
            &mut enc_c,
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "api.example"),
                (":path", "/health"),
                ("content-type", "text/plain"),
            ],
        );
        let (first, second) = head1.split_at(head1.len() / 2);
        let mut c2s = PREFACE.to_vec();
        c2s.extend(frame(SETTINGS, 0, 0, &[0, 1, 0, 0, 0x10, 0]));
        c2s.extend(frame(HEADERS, 0, 1, first));
        c2s.extend(frame(CONTINUATION, END_HEADERS, 1, second));
        c2s.extend(frame(HEADERS, END_HEADERS | END_STREAM, 3, &head3));
        // Padded DATA: pad length 3, then the body, then padding.
        let mut padded = vec![3];
        padded.extend_from_slice(b"{\"model\":\"m\"}");
        padded.extend_from_slice(&[0, 0, 0]);
        c2s.extend(frame(DATA, PADDED | END_STREAM, 1, &padded));
        let resp1 = encode(
            &mut enc_s,
            &[(":status", "200"), ("content-type", "text/event-stream")],
        );
        let resp3 = encode(&mut enc_s, &[(":status", "204")]);
        let mut s2c = Vec::new();
        s2c.extend(frame(HEADERS, END_HEADERS, 1, &resp1));
        s2c.extend(frame(DATA, 0, 1, b"event: a\n\n"));
        s2c.extend(frame(HEADERS, END_HEADERS | END_STREAM, 3, &resp3));
        s2c.extend(frame(DATA, END_STREAM, 1, b"event: b\n\n"));
        let whole = run(&c2s, &s2c, 4096);
        for split in [1, 2, 5, 13] {
            assert_eq!(run(&c2s, &s2c, split), whole, "split {split}");
        }
        let kinds: Vec<String> = whole
            .iter()
            .map(|e| match e {
                Event::RequestHead { stream, .. } => format!("req-head {stream}"),
                Event::RequestBody { stream, bytes } => {
                    format!("req-body {stream} {}", bytes.len())
                }
                Event::RequestEnd { stream } => format!("req-end {stream}"),
                Event::ResponseHead { stream, status, .. } => {
                    format!("resp-head {stream} {status}")
                }
                Event::ResponseBody { stream, bytes } => {
                    format!("resp-body {stream} {}", bytes.len())
                }
                Event::ResponseEnd { stream } => format!("resp-end {stream}"),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "req-head 1",
                "req-head 3",
                "req-end 3",
                "req-body 1 13",
                "req-end 1",
                "resp-head 1 200",
                "resp-body 1 10",
                "resp-head 3 204",
                "resp-end 3",
                "resp-body 1 10",
                "resp-end 1",
            ]
        );
        if let Event::RequestHead {
            headers, authority, ..
        } = &whole[0]
        {
            assert_eq!(authority.as_deref(), Some("api.example"));
            assert!(headers.has("authorization"));
            assert_eq!(headers.get("authorization"), None);
            assert_eq!(headers.content_type().as_deref(), Some("application/json"));
        }
    }

    /// A header table size the client allows applies to the server's
    /// blocks: an encoder using a 1024-byte table after SETTINGS said so.
    #[test]
    fn a_settings_table_size_bounds_the_other_directions_decoder() {
        let mut enc_s = fluke_hpack::Encoder::new();
        enc_s.set_max_table_size(1024);
        let mut c2s = PREFACE.to_vec();
        c2s.extend(frame(SETTINGS, 0, 0, &[0, 1, 0, 0, 4, 0]));
        let mut enc_c = fluke_hpack::Encoder::new();
        let head = encode(
            &mut enc_c,
            &[(":method", "GET"), (":path", "/"), (":authority", "a")],
        );
        c2s.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &head));
        let mut s2c = Vec::new();
        let resp = encode(
            &mut enc_s,
            &[(":status", "200"), ("x-long", &"v".repeat(600))],
        );
        s2c.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &resp));
        let events = run(&c2s, &s2c, 4096);
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::ResponseHead {
                    stream: 1,
                    status: 200,
                    ..
                }
            )),
            "{events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e, Event::Degraded { .. })),
            "{events:?}"
        );
    }

    /// Resets, pushes, bad prefaces and a block out of order degrade what
    /// they must and nothing more.
    #[test]
    fn resets_pushes_and_errors_degrade_the_right_scope() {
        let mut enc_c = fluke_hpack::Encoder::new();
        let head = encode(
            &mut enc_c,
            &[(":method", "GET"), (":path", "/"), (":authority", "a")],
        );
        let mut c2s = PREFACE.to_vec();
        c2s.extend(frame(HEADERS, END_HEADERS, 1, &head));
        c2s.extend(frame(RST_STREAM, 0, 1, &[0, 0, 0, 8]));
        let events = run(&c2s, &[], 4096);
        assert!(
            events.contains(&Event::Degraded {
                stream: Some(1),
                reason: "rst_stream"
            }),
            "{events:?}"
        );

        let mut enc_s = fluke_hpack::Encoder::new();
        let mut c2s = PREFACE.to_vec();
        c2s.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &head));
        let mut s2c = Vec::new();
        let mut promise = 2u32.to_be_bytes().to_vec();
        promise.extend(encode(
            &mut enc_s,
            &[(":method", "GET"), (":path", "/push")],
        ));
        s2c.extend(frame(PUSH_PROMISE, END_HEADERS, 1, &promise));
        let resp = encode(&mut enc_s, &[(":status", "200")]);
        s2c.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &resp));
        let events = run(&c2s, &s2c, 4096);
        assert!(
            events.contains(&Event::Degraded {
                stream: Some(2),
                reason: "push_promise"
            }),
            "{events:?}"
        );
        // The promise's block kept the table in step: the response reads.
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::ResponseHead {
                    stream: 1,
                    status: 200,
                    ..
                }
            )),
            "{events:?}"
        );

        let events = run(b"GET / HTTP/1.1\r\n", &[], 4096);
        assert_eq!(
            events,
            [Event::Degraded {
                stream: None,
                reason: "no_preface"
            }]
        );

        let mut c2s = PREFACE.to_vec();
        c2s.extend(frame(HEADERS, 0, 1, &head[..2]));
        c2s.extend(frame(DATA, 0, 1, b"x"));
        let events = run(&c2s, &[], 4096);
        assert!(
            events.contains(&Event::Degraded {
                stream: Some(1),
                reason: "continuation"
            }),
            "{events:?}"
        );
    }

    #[test]
    fn random_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(|(c2s in proptest::collection::vec(any::<u8>(), 0..512), s2c in proptest::collection::vec(any::<u8>(), 0..512))| {
            let mut with_preface = PREFACE.to_vec();
            with_preface.extend(&c2s);
            let _ = run(&with_preface, &s2c, 7);
            let _ = run(&c2s, &s2c, 4096);
        });
    }
}
