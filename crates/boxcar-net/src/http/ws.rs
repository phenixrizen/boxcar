// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! WebSocket (RFC 6455) after a `101`, read passively in both directions:
//! frames unmasked (the guest's are masked), fragments joined into
//! messages, `permessage-deflate` (RFC 7692) inflated with the context
//! each side agreed to keep or not, control frames passed over, a close
//! frame reported. Any other extension the handshake agreed to makes the
//! messages unreadable, which [`Ws::new`] says.
//!
//! Bounds: a message [`MAX_MESSAGE`] bytes, inflated or not; past it, or
//! on a frame that does not read, the direction is degraded.

use flate2::{Decompress, FlushDecompress, Status};

use super::Event;
use crate::gate::Direction;

/// The most bytes a message may hold, before or after inflation.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

const OP_CONTINUATION: u8 = 0;
const OP_TEXT: u8 = 1;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;
/// What RFC 7692 has the sender drop from every compressed message.
const DEFLATE_TAIL: [u8; 4] = [0, 0, 0xff, 0xff];

/// A message under way.
struct Partial {
    text: bool,
    compressed: bool,
    payload: Vec<u8>,
}

/// One direction's state.
struct WsDir {
    buf: Vec<u8>,
    partial: Option<Partial>,
    /// The inflater, when `permessage-deflate` was agreed.
    inflater: Option<Decompress>,
    /// This side gave up its context between messages.
    no_context_takeover: bool,
    broken: bool,
    closed: bool,
}

impl WsDir {
    fn new(deflate: bool, no_context_takeover: bool) -> WsDir {
        WsDir {
            buf: Vec::new(),
            partial: None,
            inflater: deflate.then(|| Decompress::new(false)),
            no_context_takeover,
            broken: false,
            closed: false,
        }
    }
}

/// A WebSocket connection's two directions, on `stream`.
pub struct Ws {
    stream: u32,
    c2s: WsDir,
    s2c: WsDir,
}

impl Ws {
    /// A connection whose handshake agreed `extensions` (each as the
    /// `Sec-WebSocket-Extensions` entry, lowercase): none, or
    /// `permessage-deflate` with its parameters. Anything else cannot be
    /// read: `Err("ws_extension")`.
    pub fn new(stream: u32, extensions: &[String]) -> Result<Ws, &'static str> {
        let mut deflate = false;
        let (mut client_reset, mut server_reset) = (false, false);
        for extension in extensions {
            let mut parts = extension.split(';').map(str::trim);
            match parts.next() {
                Some("permessage-deflate") => {
                    deflate = true;
                    for param in parts {
                        let name = param.split('=').next().unwrap_or("").trim();
                        match name {
                            "client_no_context_takeover" => client_reset = true,
                            "server_no_context_takeover" => server_reset = true,
                            "client_max_window_bits" | "server_max_window_bits" | "" => {}
                            _ => return Err("ws_extension"),
                        }
                    }
                }
                Some("") | None => {}
                Some(_) => return Err("ws_extension"),
            }
        }
        Ok(Ws {
            stream,
            c2s: WsDir::new(deflate, client_reset),
            s2c: WsDir::new(deflate, server_reset),
        })
    }

    /// Takes bytes that moved in `dir`.
    pub fn feed(&mut self, dir: Direction, bytes: &[u8], out: &mut Vec<Event>) {
        let stream = self.stream;
        let side = self.side(dir);
        if side.broken || side.closed {
            return;
        }
        side.buf.extend_from_slice(bytes);
        loop {
            match frame(&side.buf) {
                Ok(None) => return,
                Ok(Some(parsed)) => {
                    let Frame {
                        fin,
                        rsv1,
                        opcode,
                        mut payload,
                        consumed,
                    } = parsed;
                    side.buf.drain(..consumed);
                    match opcode {
                        OP_CLOSE => {
                            side.closed = true;
                            side.buf.clear();
                            return out.push(Event::WsClosed { stream });
                        }
                        OP_PING | OP_PONG => continue,
                        OP_TEXT | OP_BINARY => {
                            if side.partial.is_some() {
                                return degrade(side, stream, "ws_fragment", out);
                            }
                            side.partial = Some(Partial {
                                text: opcode == OP_TEXT,
                                compressed: rsv1,
                                payload: std::mem::take(&mut payload),
                            });
                        }
                        OP_CONTINUATION => {
                            let Some(partial) = side.partial.as_mut() else {
                                return degrade(side, stream, "ws_fragment", out);
                            };
                            if partial.payload.len() + payload.len() > MAX_MESSAGE {
                                return degrade(side, stream, "ws_message_too_large", out);
                            }
                            partial.payload.append(&mut payload);
                        }
                        _ => return degrade(side, stream, "ws_opcode", out),
                    }
                    if fin {
                        let Some(partial) = side.partial.take() else {
                            continue;
                        };
                        let payload = if partial.compressed {
                            match inflate(side, &partial.payload) {
                                Ok(payload) => payload,
                                Err(reason) => return degrade(side, stream, reason, out),
                            }
                        } else {
                            partial.payload
                        };
                        out.push(Event::WsMessage {
                            stream,
                            dir,
                            text: partial.text,
                            payload,
                        });
                    }
                }
                Err(reason) => return degrade(side, stream, reason, out),
            }
        }
    }

    /// Bytes were lost in `dir`: its frames cannot be found again.
    pub fn lost(&mut self, dir: Direction, out: &mut Vec<Event>) {
        let stream = self.stream;
        degrade(self.side(dir), stream, "lost", out);
    }

    /// The connection ended.
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        let stream = self.stream;
        for side in [&mut self.c2s, &mut self.s2c] {
            if side.partial.take().is_some() {
                out.push(Event::Degraded {
                    stream: Some(stream),
                    reason: "incomplete",
                });
            }
        }
    }

    fn side(&mut self, dir: Direction) -> &mut WsDir {
        match dir {
            Direction::ToHost => &mut self.c2s,
            Direction::ToGuest => &mut self.s2c,
        }
    }
}

fn degrade(side: &mut WsDir, stream: u32, reason: &'static str, out: &mut Vec<Event>) {
    side.broken = true;
    side.buf.clear();
    side.partial = None;
    out.push(Event::Degraded {
        stream: Some(stream),
        reason,
    });
}

/// A compressed message's bytes, inflated with the side's context.
fn inflate(side: &mut WsDir, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let Some(inflater) = side.inflater.as_mut() else {
        return Err("ws_compressed_without_deflate");
    };
    let mut input = payload.to_vec();
    input.extend_from_slice(&DEFLATE_TAIL);
    let mut out = Vec::with_capacity(input.len() * 4 + 1024);
    let mut consumed = 0;
    loop {
        if out.len() == out.capacity() {
            out.reserve(32 * 1024);
        }
        let before = inflater.total_in();
        let status = inflater
            .decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
            .map_err(|_| "ws_inflate")?;
        consumed += usize::try_from(inflater.total_in() - before).unwrap_or(usize::MAX);
        if out.len() > MAX_MESSAGE {
            return Err("ws_message_too_large");
        }
        if status == Status::StreamEnd {
            break;
        }
        // The inflater may hold output it had no room to write: it is
        // done only once every input byte is in and it left room to spare.
        if consumed >= input.len() && out.len() < out.capacity() {
            break;
        }
    }
    if side.no_context_takeover {
        inflater.reset(false);
    }
    Ok(out)
}

/// One frame, parsed.
struct Frame {
    fin: bool,
    rsv1: bool,
    opcode: u8,
    payload: Vec<u8>,
    consumed: usize,
}

/// The frame at the start of `buf`, if whole: `None` while more is needed.
fn frame(buf: &[u8]) -> Result<Option<Frame>, &'static str> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x30 != 0 {
        return Err("ws_frame");
    }
    let masked = b1 & 0x80 != 0;
    let mut at = 2;
    let len = match b1 & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            at = 4;
            usize::from(u16::from_be_bytes([buf[2], buf[3]]))
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            at = 10;
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&buf[2..10]);
            usize::try_from(u64::from_be_bytes(bytes)).map_err(|_| "ws_frame")?
        }
        n => usize::from(n),
    };
    if len > MAX_MESSAGE {
        return Err("ws_message_too_large");
    }
    let key = if masked {
        if buf.len() < at + 4 {
            return Ok(None);
        }
        let key = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
        at += 4;
        Some(key)
    } else {
        None
    };
    if buf.len() < at + len {
        return Ok(None);
    }
    let mut payload = buf[at..at + len].to_vec();
    if let Some(key) = key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    Ok(Some(Frame {
        fin: b0 & 0x80 != 0,
        rsv1: b0 & 0x40 != 0,
        opcode: b0 & 0x0f,
        payload,
        consumed: at + len,
    }))
}

#[cfg(test)]
mod tests {
    use flate2::{Compress, Compression, FlushCompress};

    use super::*;

    fn build(fin: bool, rsv1: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![(u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(mask_bit | n as u8),
            n if n < 65536 => {
                f.push(mask_bit | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(mask_bit | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                f.extend_from_slice(&key);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => f.extend_from_slice(payload),
        }
        f
    }

    /// `payload` deflated as RFC 7692 sends it: raw deflate, synced, the
    /// trailing empty block dropped.
    fn deflate(compressor: &mut Compress, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 64);
        let mut consumed = 0;
        loop {
            if out.len() == out.capacity() {
                out.reserve(1024);
            }
            let before = compressor.total_in();
            compressor
                .compress_vec(&payload[consumed..], &mut out, FlushCompress::Sync)
                .unwrap();
            consumed += (compressor.total_in() - before) as usize;
            if consumed == payload.len() && out.len() < out.capacity() {
                break;
            }
        }
        assert!(out.ends_with(&DEFLATE_TAIL));
        out.truncate(out.len() - 4);
        out
    }

    fn messages(events: &[Event]) -> Vec<(Direction, bool, Vec<u8>)> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::WsMessage {
                    dir, text, payload, ..
                } => Some((*dir, *text, payload.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn masked_text_fragments_and_control_frames() {
        let mut ws = Ws::new(7, &[]).unwrap();
        let mut bytes = Vec::new();
        bytes.extend(build(false, false, OP_TEXT, Some([1, 2, 3, 4]), b"hel"));
        bytes.extend(build(true, false, OP_PING, Some([9, 9, 9, 9]), b"p"));
        bytes.extend(build(
            false,
            false,
            OP_CONTINUATION,
            Some([5, 6, 7, 8]),
            b"lo ",
        ));
        bytes.extend(build(
            true,
            false,
            OP_CONTINUATION,
            Some([0, 0, 0, 0]),
            b"world",
        ));
        bytes.extend(build(true, false, OP_BINARY, None, &[0, 255, 7]));
        bytes.extend(build(true, false, OP_CLOSE, Some([1, 1, 1, 1]), &[3, 232]));
        let whole = {
            let mut out = Vec::new();
            ws.feed(Direction::ToHost, &bytes, &mut out);
            out
        };
        for split in [1, 3, 10] {
            let mut ws = Ws::new(7, &[]).unwrap();
            let mut out = Vec::new();
            for chunk in bytes.chunks(split) {
                ws.feed(Direction::ToHost, chunk, &mut out);
            }
            assert_eq!(out, whole, "split {split}");
        }
        assert_eq!(
            messages(&whole),
            [
                (Direction::ToHost, true, b"hello world".to_vec()),
                (Direction::ToHost, false, vec![0, 255, 7]),
            ]
        );
        assert_eq!(whole.last(), Some(&Event::WsClosed { stream: 7 }));
    }

    #[test]
    fn long_frames_carry_their_length_in_two_or_eight_bytes() {
        let medium = vec![b'm'; 1000];
        let large = vec![b'l'; 70_000];
        let mut ws = Ws::new(1, &[]).unwrap();
        let mut out = Vec::new();
        ws.feed(
            Direction::ToGuest,
            &build(true, false, OP_BINARY, None, &medium),
            &mut out,
        );
        ws.feed(
            Direction::ToGuest,
            &build(true, false, OP_BINARY, None, &large),
            &mut out,
        );
        let got = messages(&out);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].2, medium);
        assert_eq!(got[1].2, large);
    }

    /// permessage-deflate: messages inflate, with the context kept across
    /// them unless the side gave it up.
    /// Messages far larger than one TLS record, compressed with the
    /// context kept, fed in the chunks the relay would hand over: each
    /// comes out whole and exact, and so does the next one, which the
    /// compressor wrote against the first's window.
    #[test]
    fn large_compressed_messages_survive_chunked_feeding() {
        let mut text = String::from("{\"type\":\"response.create\",\"instructions\":\"");
        for i in 0..6000u32 {
            text.push_str(&format!(
                "line {i} of the instructions, with words that repeat and words that do not {}; ",
                i * 7919 % 1013
            ));
        }
        text.push_str("\",\"input\":[]}");
        let first = text.as_bytes();
        let second = text.replace("response.create", "response.completed");
        let second = second.as_bytes();
        let mut compressor = Compress::new(Compression::default(), false);
        let a = deflate(&mut compressor, first);
        let b = deflate(&mut compressor, second);
        assert!(
            a.len() > 16 * 1024 || first.len() > 100 * 1024,
            "{} {}",
            a.len(),
            first.len()
        );
        let mut ws = Ws::new(
            3,
            &["permessage-deflate; client_max_window_bits".to_owned()],
        )
        .unwrap();
        let mut out = Vec::new();
        let wire = [
            build(true, true, OP_TEXT, Some([9, 8, 7, 6]), &a),
            build(true, true, OP_TEXT, Some([1, 1, 2, 3]), &b),
        ]
        .concat();
        for chunk in wire.chunks(16 * 1024 - 37) {
            ws.feed(Direction::ToHost, chunk, &mut out);
        }
        let got = messages(&out);
        assert_eq!(got.len(), 2, "{out:?}");
        assert_eq!(got[0].2.len(), first.len());
        assert!(got[0].2 == first, "the first message differs");
        assert_eq!(got[1].2.len(), second.len());
        assert!(got[1].2 == second, "the second message differs");
    }

    #[test]
    fn permessage_deflate_with_and_without_context_takeover() {
        let first = b"{\"type\":\"response.create\",\"input\":\"hello hello hello\"}";
        let second = b"{\"type\":\"response.create\",\"input\":\"hello hello again\"}";
        let mut compressor = Compress::new(Compression::default(), false);
        let a = deflate(&mut compressor, first);
        let b = deflate(&mut compressor, second);
        // With the context kept, both read.
        let mut ws = Ws::new(
            3,
            &["permessage-deflate; client_max_window_bits".to_owned()],
        )
        .unwrap();
        let mut out = Vec::new();
        ws.feed(
            Direction::ToHost,
            &build(true, true, OP_TEXT, Some([1, 2, 3, 4]), &a),
            &mut out,
        );
        ws.feed(
            Direction::ToHost,
            &build(true, true, OP_TEXT, Some([4, 3, 2, 1]), &b),
            &mut out,
        );
        assert_eq!(
            messages(&out),
            [
                (Direction::ToHost, true, first.to_vec()),
                (Direction::ToHost, true, second.to_vec()),
            ]
        );
        // Without it on the client side, the second depends on a context
        // the reader was told to drop: what comes out is not the message
        // (the inflater copies from an empty window rather than failing).
        let mut ws = Ws::new(
            3,
            &["permessage-deflate; client_no_context_takeover".to_owned()],
        )
        .unwrap();
        let mut out = Vec::new();
        ws.feed(
            Direction::ToHost,
            &build(true, true, OP_TEXT, Some([1, 2, 3, 4]), &a),
            &mut out,
        );
        ws.feed(
            Direction::ToHost,
            &build(true, true, OP_TEXT, Some([4, 3, 2, 1]), &b),
            &mut out,
        );
        let got = messages(&out);
        assert_eq!(got.len(), 2, "{out:?}");
        assert_eq!(got[0].2, first);
        assert_ne!(got[1].2, second, "the context was dropped");
        // A sender that resets its own context each message reads fine
        // with the context dropped.
        let mut fresh = Compress::new(Compression::default(), false);
        let a = deflate(&mut fresh, first);
        fresh.reset();
        let b = deflate(&mut fresh, second);
        let mut ws = Ws::new(
            3,
            &["permessage-deflate; server_no_context_takeover".to_owned()],
        )
        .unwrap();
        let mut out = Vec::new();
        ws.feed(
            Direction::ToGuest,
            &build(true, true, OP_TEXT, None, &a),
            &mut out,
        );
        ws.feed(
            Direction::ToGuest,
            &build(true, true, OP_TEXT, None, &b),
            &mut out,
        );
        assert_eq!(messages(&out).len(), 2, "{out:?}");
    }

    #[test]
    fn unknown_extensions_opcodes_and_rsv_bits_are_refused() {
        assert_eq!(
            Ws::new(1, &["x-webkit-deflate-frame".to_owned()]).err(),
            Some("ws_extension")
        );
        assert_eq!(
            Ws::new(1, &["permessage-deflate; magic=1".to_owned()]).err(),
            Some("ws_extension")
        );
        let mut ws = Ws::new(1, &[]).unwrap();
        let mut out = Vec::new();
        ws.feed(
            Direction::ToGuest,
            &build(true, false, 3, None, b"x"),
            &mut out,
        );
        assert_eq!(
            out,
            [Event::Degraded {
                stream: Some(1),
                reason: "ws_opcode"
            }]
        );
        let mut ws = Ws::new(1, &[]).unwrap();
        let mut out = Vec::new();
        ws.feed(Direction::ToGuest, &[0x80 | 0x20 | OP_TEXT, 0], &mut out);
        assert_eq!(
            out,
            [Event::Degraded {
                stream: Some(1),
                reason: "ws_frame"
            }]
        );
        // A compressed frame without the extension.
        let mut ws = Ws::new(1, &[]).unwrap();
        let mut out = Vec::new();
        ws.feed(
            Direction::ToGuest,
            &build(true, true, OP_TEXT, None, b"x"),
            &mut out,
        );
        assert_eq!(
            out,
            [Event::Degraded {
                stream: Some(1),
                reason: "ws_compressed_without_deflate"
            }]
        );
    }
}
