// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Server-sent events (`text/event-stream`), split as the bytes come.
//!
//! An event is lines up to a blank one: `data:` lines joined with
//! newlines, an `event:` name, an `id:`; comments (`:`) and unknown fields
//! are ignored, a leading space after the colon is dropped, and a line
//! ending may be `\n`, `\r\n` or `\r`. A stream's last event without a
//! blank line after it is given at [`SseParser::finish`].

use super::retain::{Retained, Share};

/// One event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

/// The splitter's state across chunks.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
    current: SseEvent,
    has_data: bool,
    /// A line ran past [`MAX_EVENT_BYTES`] without ending: its bytes are
    /// dropped until it ends.
    skipping: bool,
    /// Some line was dropped so, or for want of room in the observer's
    /// budget.
    overflowed: bool,
    /// What the buffered line and the event under way take of the
    /// observer's budget.
    share: Share,
}

/// The most bytes an event may hold before the rest of it is dropped.
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

impl SseParser {
    pub fn new() -> SseParser {
        SseParser::default()
    }

    /// A parser whose buffered bytes come out of the observer's
    /// `retained` budget.
    pub fn with_retained(retained: Retained) -> SseParser {
        SseParser {
            share: Share::new(retained),
            ..SseParser::default()
        }
    }

    /// Takes `bytes`, appending the events they complete to `out`.
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<SseEvent>) {
        let mut bytes = bytes;
        if self.skipping {
            // The rest of the over-long line goes, up to its end.
            match bytes.iter().position(|&b| b == b'\n' || b == b'\r') {
                Some(at) => {
                    self.skipping = false;
                    // Past the line's end, CRLF as one.
                    let crlf = bytes[at] == b'\r' && bytes.get(at + 1) == Some(&b'\n');
                    bytes = &bytes[at + if crlf { 2 } else { 1 }..];
                }
                None => return,
            }
        }
        self.buf.extend_from_slice(bytes);
        while let Some((line, rest)) = split_line(&self.buf).map(|(l, r)| (l.to_vec(), r.len())) {
            let at = self.buf.len() - rest;
            self.buf.drain(..at);
            self.line(&line, out);
        }
        super::trim(&mut self.buf);
        if self.buf.len() > MAX_EVENT_BYTES || !self.share.set(self.held()) {
            // Too long, or no room left: the line goes, to its end, and
            // with no room the event under way goes too.
            if self.buf.len() <= MAX_EVENT_BYTES {
                self.current = SseEvent::default();
                self.has_data = false;
            }
            self.buf = Vec::new();
            self.skipping = true;
            self.overflowed = true;
            self.share.set(self.held());
        }
    }

    /// The bytes held: the line buffer's allocation and the event under
    /// way's.
    fn held(&self) -> usize {
        self.buf.capacity()
            + self.current.data.capacity()
            + self.current.event.as_ref().map_or(0, String::capacity)
            + self.current.id.as_ref().map_or(0, String::capacity)
    }

    /// Whether a line was dropped for running past [`MAX_EVENT_BYTES`].
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// The event under way, if any: a stream that ended without a blank
    /// line.
    pub fn finish(&mut self, out: &mut Vec<SseEvent>) {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.line(&line, out);
        }
        self.dispatch(out);
        self.share.clear();
    }

    fn line(&mut self, line: &[u8], out: &mut Vec<SseEvent>) {
        if line.is_empty() {
            return self.dispatch(out);
        }
        if line[0] == b':' {
            return;
        }
        let (field, value) = match line.iter().position(|&b| b == b':') {
            Some(at) => {
                let value = &line[at + 1..];
                let value = value.strip_prefix(b" ").unwrap_or(value);
                (&line[..at], value)
            }
            None => (line, &b""[..]),
        };
        let value = String::from_utf8_lossy(value);
        match field {
            b"data" => {
                if self.current.data.len() + value.len() < MAX_EVENT_BYTES {
                    if self.has_data {
                        self.current.data.push('\n');
                    }
                    self.current.data.push_str(&value);
                }
                self.has_data = true;
            }
            b"event" => self.current.event = Some(value.into_owned()),
            b"id" => self.current.id = Some(value.into_owned()),
            _ => {}
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        if self.has_data || self.current.event.is_some() || self.current.id.is_some() {
            out.push(std::mem::take(&mut self.current));
        }
        self.has_data = false;
    }
}

/// The first line of `buf` and what follows it, if a line ending is there.
fn split_line(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = buf.iter().position(|&b| b == b'\n' || b == b'\r')?;
    let line = &buf[..at];
    let rest = if buf[at] == b'\r' {
        match buf.get(at + 1) {
            Some(b'\n') => &buf[at + 2..],
            // A bare CR at the very end may be half of a CRLF: wait.
            None => return None,
            Some(_) => &buf[at + 1..],
        }
    } else {
        &buf[at + 1..]
    };
    Some((line, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut parser = SseParser::new();
        let mut out = Vec::new();
        for chunk in chunks {
            parser.feed(chunk, &mut out);
        }
        parser.finish(&mut out);
        out
    }

    #[test]
    fn events_split_across_chunks_and_line_endings() {
        let stream = b"event: message_start\ndata: {\"a\":1}\n\n: keep-alive\n\ndata: first\r\ndata: second\r\n\r\nid: 7\r\ndata: last";
        let whole = all(&[stream]);
        let mut pieces = Vec::new();
        for i in 0..stream.len() {
            pieces.push(&stream[i..i + 1]);
        }
        let by_byte = all(&pieces);
        assert_eq!(whole, by_byte);
        assert_eq!(
            whole,
            [
                SseEvent {
                    event: Some("message_start".into()),
                    data: "{\"a\":1}".into(),
                    id: None,
                },
                SseEvent {
                    event: None,
                    data: "first\nsecond".into(),
                    id: None,
                },
                SseEvent {
                    event: None,
                    data: "last".into(),
                    id: Some("7".into()),
                },
            ]
        );
    }

    #[test]
    fn comments_blank_lines_and_unknown_fields_are_nothing() {
        assert!(all(&[b": hi\n\n\n\nretry: 3000\n\n"]).is_empty());
        assert_eq!(
            all(&[b"data:no-space\ndata\n\n"]),
            [SseEvent {
                event: None,
                data: "no-space\n".into(),
                id: None,
            }]
        );
    }

    /// A line that never ends is held only up to the limit; the parser
    /// reads on after it ends.
    #[test]
    fn a_line_past_the_limit_is_dropped_to_its_end() {
        let mut parser = SseParser::new();
        let mut out = Vec::new();
        let chunk = vec![b'x'; 1024 * 1024];
        parser.feed(b"data: ", &mut out);
        for _ in 0..(MAX_EVENT_BYTES / chunk.len() + 2) {
            parser.feed(&chunk, &mut out);
            assert!(parser.buf.len() <= MAX_EVENT_BYTES + chunk.len());
        }
        assert!(parser.overflowed());
        parser.feed(b"tail\n\ndata: ok\n\n", &mut out);
        assert_eq!(out.last().map(|e| e.data.as_str()), Some("ok"));
    }

    /// A long line, once read, leaves neither its allocation nor its
    /// charge behind.
    #[test]
    fn a_drained_line_gives_back_its_room() {
        let retained = crate::http::Retained::default();
        let mut parser = SseParser::with_retained(retained.clone());
        let mut out = Vec::new();
        let mut line = b":".to_vec();
        line.extend(std::iter::repeat_n(b'x', 8 * 1024 * 1024));
        parser.feed(&line, &mut out);
        assert!(retained.held() >= 8 * 1024 * 1024);
        parser.feed(b"\n", &mut out);
        assert!(
            parser.buf.capacity() <= 64 * 1024,
            "{}",
            parser.buf.capacity()
        );
        assert!(retained.held() <= 64 * 1024, "{}", retained.held());
    }
}
