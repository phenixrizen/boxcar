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

/// One ordered result from splitting an event stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SseItem {
    Event(SseEvent),
    /// A line was not retained, so the event under way was discarded.
    DroppedLine,
}

/// The splitter's state across chunks.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
    current: SseEvent,
    has_data: bool,
    /// A line ran past [`MAX_EVENT_BYTES`] without ending: its bytes are
    /// dropped until it ends.
    skipping_line: bool,
    /// The skipped line ended in a CR at the end of the previous chunk;
    /// a leading LF still belongs to that line ending.
    skipping_line_cr: bool,
    /// The event containing a dropped line is ignored through its blank
    /// terminator.
    discarding_event: bool,
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
        let mut ordered = Vec::new();
        self.feed_ordered(bytes, &mut ordered);
        out.extend(ordered.into_iter().filter_map(|item| match item {
            SseItem::Event(event) => Some(event),
            SseItem::DroppedLine => None,
        }));
    }

    /// Takes `bytes`, preserving dropped lines among the completed events.
    pub fn feed_ordered(&mut self, bytes: &[u8], out: &mut Vec<SseItem>) {
        let mut bytes = bytes;
        if self.skipping_line && self.skipping_line_cr {
            if bytes.is_empty() {
                return;
            }
            self.skipping_line = false;
            self.skipping_line_cr = false;
            bytes = bytes.strip_prefix(b"\n").unwrap_or(bytes);
        }
        if self.skipping_line {
            // The rest of the over-long line goes, up to its end.
            match bytes.iter().position(|&b| b == b'\n' || b == b'\r') {
                Some(at) => {
                    if bytes[at] == b'\r' && bytes.get(at + 1).is_none() {
                        self.skipping_line_cr = true;
                        return;
                    }
                    self.skipping_line = false;
                    // Past the line's end, CRLF as one.
                    let crlf = bytes[at] == b'\r' && bytes.get(at + 1) == Some(&b'\n');
                    bytes = &bytes[at + if crlf { 2 } else { 1 }..];
                }
                None => return,
            }
        }
        self.buf.extend_from_slice(bytes);
        while let Some((line_len, rest)) = split_line(&self.buf).map(|(l, r)| (l.len(), r.len())) {
            let at = self.buf.len() - rest;
            if line_len > MAX_EVENT_BYTES {
                self.buf.drain(..at);
                self.discard_event(out);
                continue;
            }
            let line = self.buf[..line_len].to_vec();
            self.buf.drain(..at);
            self.line(&line, out);
        }
        super::trim(&mut self.buf);
        if self.buf.len() > MAX_EVENT_BYTES || !self.share.set(self.held()) {
            // Too long, or no room left: the line goes, to its end, and
            // with no room the event under way goes too.
            self.discard_event(out);
            self.skipping_line = !self.buf.is_empty();
            // A CR that ends the buffer ended the line; an LF after it
            // belongs to it.
            self.skipping_line_cr = self.buf.last() == Some(&b'\r');
            self.buf = Vec::new();
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

    /// Whether a line was dropped for its size or for want of observer room.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// The event under way, if any: a stream that ended without a blank
    /// line.
    pub fn finish(&mut self, out: &mut Vec<SseEvent>) {
        let mut ordered = Vec::new();
        self.finish_ordered(&mut ordered);
        out.extend(ordered.into_iter().filter_map(|item| match item {
            SseItem::Event(event) => Some(event),
            SseItem::DroppedLine => None,
        }));
    }

    /// Finishes the stream, preserving a final dropped line in order.
    pub fn finish_ordered(&mut self, out: &mut Vec<SseItem>) {
        if !self.skipping_line && !self.discarding_event && !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.line(&line, out);
        }
        if !self.discarding_event {
            self.dispatch(out);
        }
        self.buf.clear();
        self.share.clear();
    }

    fn line(&mut self, line: &[u8], out: &mut Vec<SseItem>) {
        if line.is_empty() {
            if self.discarding_event {
                self.discarding_event = false;
                self.current = SseEvent::default();
                self.has_data = false;
                return;
            }
            return self.dispatch(out);
        }
        if self.discarding_event {
            return;
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
                let separator = usize::from(self.has_data);
                let fits = self
                    .current
                    .data
                    .len()
                    .checked_add(separator)
                    .and_then(|len| len.checked_add(value.len()))
                    .is_some_and(|len| len <= MAX_EVENT_BYTES);
                if !fits {
                    self.discard_event(out);
                    return;
                }
                if self.has_data {
                    self.current.data.push('\n');
                }
                self.current.data.push_str(&value);
                self.has_data = true;
            }
            b"event" => self.current.event = Some(value.into_owned()),
            b"id" => self.current.id = Some(value.into_owned()),
            _ => {}
        }
    }

    fn discard_event(&mut self, out: &mut Vec<SseItem>) {
        self.overflowed = true;
        if !self.discarding_event {
            out.push(SseItem::DroppedLine);
        }
        self.current = SseEvent::default();
        self.has_data = false;
        self.discarding_event = true;
    }

    fn dispatch(&mut self, out: &mut Vec<SseItem>) {
        if self.has_data || self.current.event.is_some() || self.current.id.is_some() {
            out.push(SseItem::Event(std::mem::take(&mut self.current)));
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
        let mut events = Vec::new();
        let mut ordered = Vec::new();
        let chunk = vec![b'x'; 1024 * 1024];
        parser.feed_ordered(b"data: ", &mut ordered);
        for _ in 0..(MAX_EVENT_BYTES / chunk.len() + 2) {
            parser.feed_ordered(&chunk, &mut ordered);
            assert!(parser.buf.len() <= MAX_EVENT_BYTES + chunk.len());
        }
        assert!(parser.overflowed());
        parser.feed_ordered(b"tail\n\ndata: ok\n\n", &mut ordered);
        assert_eq!(
            ordered
                .iter()
                .filter(|item| matches!(item, SseItem::DroppedLine))
                .count(),
            1
        );
        for item in ordered {
            if let SseItem::Event(event) = item {
                events.push(event);
            }
        }
        assert_eq!(events.last().map(|e| e.data.as_str()), Some("ok"));
    }

    #[test]
    fn a_budget_drop_follows_events_completed_in_the_same_feed() {
        let retained = Retained::with_limit(512);
        let mut parser = SseParser::with_retained(retained);
        let mut out = Vec::new();
        let mut bytes = b"data: first\n\n".to_vec();
        bytes.extend_from_slice(b"data: ");
        bytes.extend(std::iter::repeat_n(b'x', 1024));
        parser.feed_ordered(&bytes, &mut out);
        assert!(matches!(
            out.as_slice(),
            [SseItem::Event(_), SseItem::DroppedLine]
        ));
    }

    #[test]
    fn a_split_crlf_ends_a_skipped_line_once() {
        let retained = Retained::with_limit(512);
        let mut parser = SseParser::with_retained(retained);
        let mut out = Vec::new();
        let mut line = b"data: ".to_vec();
        line.extend(std::iter::repeat_n(b'x', 1024));
        parser.feed_ordered(&line, &mut out);
        parser.feed_ordered(b"tail\r", &mut out);
        parser.feed_ordered(b"\ndata: same event\n\ndata: next\n\n", &mut out);
        assert_eq!(
            out,
            [
                SseItem::DroppedLine,
                SseItem::Event(SseEvent {
                    event: None,
                    data: "next".to_owned(),
                    id: None,
                }),
            ]
        );
    }

    #[test]
    fn a_line_cut_at_its_cr_ends_there() {
        let retained = Retained::with_limit(512);
        let mut parser = SseParser::with_retained(retained);
        let mut out = Vec::new();
        let mut line = b"data: ".to_vec();
        line.extend(std::iter::repeat_n(b'x', 1024));
        line.push(b'\r');
        parser.feed_ordered(&line, &mut out);
        parser.feed_ordered(b"\rdata: next\n\n", &mut out);
        assert_eq!(
            out,
            [
                SseItem::DroppedLine,
                SseItem::Event(SseEvent {
                    event: None,
                    data: "next".to_owned(),
                    id: None,
                }),
            ]
        );
    }

    #[test]
    fn an_event_past_the_aggregate_limit_is_discarded() {
        let mut parser = SseParser::new();
        let mut out = Vec::new();
        let value = vec![b'x'; MAX_EVENT_BYTES / 2];
        let mut line = b"data: ".to_vec();
        line.extend_from_slice(&value);
        line.push(b'\n');
        parser.feed_ordered(&line, &mut out);
        parser.feed_ordered(&line, &mut out);
        parser.feed_ordered(b"\ndata: ok\n\n", &mut out);
        assert_eq!(
            out,
            [
                SseItem::DroppedLine,
                SseItem::Event(SseEvent {
                    event: None,
                    data: "ok".to_owned(),
                    id: None,
                }),
            ]
        );
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
