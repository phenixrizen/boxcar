// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Server-sent events (`text/event-stream`), split as the bytes come.
//!
//! An event is lines up to a blank one: `data:` lines joined with
//! newlines, an `event:` name, an `id:`; comments (`:`) and unknown fields
//! are ignored, a leading space after the colon is dropped, and a line
//! ending may be `\n`, `\r\n` or `\r`. A stream's last event without a
//! blank line after it is given at [`SseParser::finish`].

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
}

/// The most bytes an event may hold before the rest of it is dropped.
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

impl SseParser {
    pub fn new() -> SseParser {
        SseParser::default()
    }

    /// Takes `bytes`, appending the events they complete to `out`.
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<SseEvent>) {
        self.buf.extend_from_slice(bytes);
        while let Some((line, rest)) = split_line(&self.buf).map(|(l, r)| (l.to_vec(), r.len())) {
            let at = self.buf.len() - rest;
            self.buf.drain(..at);
            self.line(&line, out);
        }
    }

    /// The event under way, if any: a stream that ended without a blank
    /// line.
    pub fn finish(&mut self, out: &mut Vec<SseEvent>) {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.line(&line, out);
        }
        self.dispatch(out);
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
}
