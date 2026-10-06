// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the observer keeps of one inspected flow: its HTTP connection
//! ([`crate::http::Connection`]) and, per stream, the exchange under way,
//! whose request and response become `http.request` and `http.response`
//! records when they end. Bodies are decoded, hashed and kept by
//! [`BodySink`]; event streams are split and counted; WebSocket messages
//! are counted. The model parsers (`crate::model`) read the same
//! exchanges, through [`Observation::exchanges`]; the model tracker
//! ([`crate::model::Tracker`]) reads them as they end, for `llm.*` and
//! `tool.*`.
//!
//! Times are the observer's: when it took the bytes, which is when they
//! moved unless it fell behind.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::Instant;

use boxcar_proto::{HttpRequest, HttpResponse, Payload, SpanRef};

use super::Direction;
use crate::dump::{self, DumpDir};
use crate::http::{BodySink, Connection, Event, Headers, SseEvent, SseParser, Version};
use crate::model::Tracker;

/// A record the observer made, with the span it belongs to, if any.
#[derive(Clone, Debug, PartialEq)]
pub struct Emit {
    pub payload: Payload,
    pub span: Option<SpanRef>,
}

impl Emit {
    pub fn plain(payload: Payload) -> Emit {
        Emit {
            payload,
            span: None,
        }
    }

    pub fn in_span(payload: Payload, span: SpanRef) -> Emit {
        Emit {
            payload,
            span: Some(span),
        }
    }
}

/// The most bytes of a path kept in a record.
pub const PATH_CUT: usize = 4096;
/// The most bytes of a user agent kept in a record.
pub const USER_AGENT_CUT: usize = 512;

/// A request's head, as the record will say it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub authority: Option<String>,
    pub path: Option<String>,
    pub version: Version,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub content_length: Option<u64>,
    pub user_agent: Option<String>,
}

/// A response's head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
}

/// One request and its response on a stream.
pub struct Exchange {
    pub stream: u32,
    pub request: Option<RequestHead>,
    pub request_body: Option<BodySink>,
    request_started: Instant,
    request_recorded: bool,
    request_degraded: Option<&'static str>,
    pub response: Option<ResponseHead>,
    pub response_body: Option<BodySink>,
    /// The heads as the dump writes them, when there is a dump.
    request_head_text: Option<String>,
    response_head_text: Option<String>,
    sse: Option<SseParser>,
    /// The event stream's events, as they complete: the model parsers
    /// take them.
    pub sse_events: Vec<SseEvent>,
    sse_count: u64,
    /// The WebSocket messages of an upgraded stream, as they complete.
    pub ws_messages: Vec<(Direction, bool, Vec<u8>)>,
    ws_count: u64,
    upgraded: bool,
    response_recorded: bool,
    response_degraded: Option<&'static str>,
    last_response_at: Instant,
}

impl Exchange {
    fn new(stream: u32, now: Instant) -> Exchange {
        Exchange {
            stream,
            request: None,
            request_body: None,
            request_started: now,
            request_recorded: false,
            request_degraded: None,
            response: None,
            response_body: None,
            request_head_text: None,
            response_head_text: None,
            sse: None,
            sse_events: Vec::new(),
            sse_count: 0,
            ws_messages: Vec::new(),
            ws_count: 0,
            upgraded: false,
            response_recorded: false,
            response_degraded: None,
            last_response_at: now,
        }
    }

    /// Whether both sides have been recorded (or will never be).
    fn done(&self) -> bool {
        self.request_recorded && self.response_recorded
    }
}

/// One inspected flow under observation.
pub struct Observation {
    pub flow: u64,
    pub dst: SocketAddrV4,
    pub name: Option<String>,
    pub tls: bool,
    conn: Connection,
    exchanges: HashMap<u32, Exchange>,
    model: Tracker,
    /// Where each decoded exchange is written, when the session dumps.
    dump: Option<DumpDir>,
}

impl Observation {
    /// A flow whose plaintext begins: HTTP/2 when `alpn` says `h2`, else
    /// HTTP/1.1.
    pub fn new(
        flow: u64,
        dst: SocketAddrV4,
        name: Option<String>,
        alpn: Option<&str>,
        tls: bool,
        trace_id: &str,
    ) -> Observation {
        Observation {
            flow,
            dst,
            name,
            tls,
            conn: Connection::new(alpn),
            exchanges: HashMap::new(),
            model: Tracker::new(flow, trace_id.to_owned()),
            dump: None,
        }
    }

    /// The observation with the dump: each exchange's decoded request and
    /// response are written to `http/<flow>-<stream>.req` and `.resp`.
    pub fn with_dump(mut self, dump: Option<DumpDir>) -> Observation {
        self.dump = dump;
        self
    }

    /// Writes one side of an exchange to the dump, if there is one. A
    /// failure is the dump's alone.
    fn dump_side(&self, exchange: &Exchange, request: bool) {
        let Some(dir) = &self.dump else {
            return;
        };
        let (head, body, content_type) = if request {
            (
                &exchange.request_head_text,
                &exchange.request_body,
                exchange
                    .request
                    .as_ref()
                    .and_then(|r| r.content_type.clone()),
            )
        } else {
            (
                &exchange.response_head_text,
                &exchange.response_body,
                exchange
                    .response
                    .as_ref()
                    .and_then(|r| r.content_type.clone()),
            )
        };
        let Some(head) = head else {
            return;
        };
        let body = body.as_ref().map(BodySink::kept).unwrap_or_default();
        let _ = dump::write_exchange(
            dir,
            self.flow,
            exchange.stream,
            request,
            head,
            content_type.as_deref(),
            body,
        );
    }

    /// The exchanges under way, by stream.
    pub fn exchanges(&mut self) -> &mut HashMap<u32, Exchange> {
        &mut self.exchanges
    }

    /// Plaintext that moved in `dir`, taken at `now`: the records it
    /// completes go to `out`.
    pub fn data(&mut self, dir: Direction, bytes: &[u8], now: Instant, out: &mut Vec<Emit>) {
        let mut events = Vec::new();
        self.conn.feed(dir, bytes, &mut events);
        self.handle(events, now, out);
    }

    /// A hole in `dir`'s plaintext.
    pub fn lost(&mut self, dir: Direction, now: Instant, out: &mut Vec<Emit>) {
        let mut events = Vec::new();
        self.conn.lost(dir, &mut events);
        self.handle(events, now, out);
    }

    /// The flow ended: what is open is recorded as it stands.
    pub fn close(&mut self, now: Instant, out: &mut Vec<Emit>) {
        let mut events = Vec::new();
        self.conn.finish(&mut events);
        self.handle(events, now, out);
        self.model.close(now, out);
        let mut open: Vec<u32> = self.exchanges.keys().copied().collect();
        open.sort_unstable();
        for stream in open {
            let Some(mut exchange) = self.exchanges.remove(&stream) else {
                continue;
            };
            if exchange.request.is_some() && !exchange.request_recorded {
                exchange.request_degraded.get_or_insert("flow_closed");
                out.push(Emit::plain(self.request_record(&mut exchange)));
            }
            if exchange.response.is_some() && !exchange.response_recorded {
                exchange.response_degraded.get_or_insert("flow_closed");
                out.push(Emit::plain(self.response_record(&mut exchange, now)));
            }
        }
    }

    fn handle(&mut self, events: Vec<Event>, now: Instant, out: &mut Vec<Emit>) {
        for event in events {
            match event {
                Event::RequestHead {
                    stream,
                    method,
                    authority,
                    path,
                    version,
                    headers,
                } => {
                    let exchange = self
                        .exchanges
                        .entry(stream)
                        .or_insert_with(|| Exchange::new(stream, now));
                    exchange.request_started = now;
                    exchange.request_body =
                        Some(BodySink::new(headers.content_encoding().as_deref()));
                    if self.dump.is_some() {
                        let start = format!(
                            "{method} {} HTTP/{}",
                            path.as_deref().unwrap_or("*"),
                            version.as_str()
                        );
                        exchange.request_head_text =
                            Some(dump::head_text(&start, headers.visible()));
                    }
                    exchange.request =
                        Some(request_head(method, authority, path, version, &headers));
                    let path = exchange.request.as_ref().and_then(|r| r.path.clone());
                    self.model.request_head(stream, path.as_deref(), now);
                }
                Event::RequestBody { stream, bytes } => {
                    if let Some(sink) = self
                        .exchanges
                        .get_mut(&stream)
                        .and_then(|e| e.request_body.as_mut())
                    {
                        sink.push(&bytes);
                    }
                }
                Event::RequestEnd { stream } => {
                    if let Some(mut exchange) = self.exchanges.remove(&stream) {
                        if let Some(sink) = exchange.request_body.as_mut() {
                            sink.finish();
                        }
                        self.dump_side(&exchange, true);
                        if !exchange.request_recorded && exchange.request.is_some() {
                            out.push(Emit::plain(self.request_record(&mut exchange)));
                        }
                        self.model.request_end(stream, &exchange, out);
                        self.exchanges.insert(stream, exchange);
                    }
                }
                Event::ResponseHead {
                    stream,
                    status,
                    headers,
                } => {
                    let exchange = self
                        .exchanges
                        .entry(stream)
                        .or_insert_with(|| Exchange::new(stream, now));
                    exchange.last_response_at = now;
                    // An interim response is followed by the final one.
                    if (100..200).contains(&status) && status != 101 {
                        continue;
                    }
                    let content_type = headers.content_type();
                    exchange.sse =
                        (content_type.as_deref() == Some("text/event-stream")).then(SseParser::new);
                    exchange.response_body =
                        Some(BodySink::new(headers.content_encoding().as_deref()));
                    exchange.response = Some(ResponseHead {
                        status,
                        content_type,
                        content_encoding: headers.content_encoding(),
                    });
                    if self.dump.is_some() {
                        let start = format!("HTTP/{} {status}", self.conn.version().as_str());
                        exchange.response_head_text =
                            Some(dump::head_text(&start, headers.visible()));
                    }
                    self.model.response_head(stream, status, &headers);
                }
                Event::ResponseBody { stream, bytes } => {
                    if let Some(exchange) = self.exchanges.get_mut(&stream) {
                        exchange.last_response_at = now;
                        let decoded = match exchange.response_body.as_mut() {
                            Some(sink) => sink.push(&bytes),
                            None => Vec::new(),
                        };
                        if let Some(sse) = exchange.sse.as_mut() {
                            let before = exchange.sse_events.len();
                            sse.feed(&decoded, &mut exchange.sse_events);
                            exchange.sse_count += (exchange.sse_events.len() - before) as u64;
                        }
                        self.model.response_body(stream, exchange, out);
                    }
                }
                Event::ResponseEnd { stream } => {
                    if let Some(mut exchange) = self.exchanges.remove(&stream) {
                        exchange.last_response_at = now;
                        if let Some(sink) = exchange.response_body.as_mut() {
                            let rest = sink.finish();
                            if let Some(sse) = exchange.sse.as_mut() {
                                let before = exchange.sse_events.len();
                                sse.feed(&rest, &mut exchange.sse_events);
                                sse.finish(&mut exchange.sse_events);
                                exchange.sse_count += (exchange.sse_events.len() - before) as u64;
                            }
                        }
                        self.dump_side(&exchange, false);
                        if !exchange.response_recorded && exchange.response.is_some() {
                            out.push(Emit::plain(self.response_record(&mut exchange, now)));
                        }
                        self.model.response_end(stream, &exchange, now, out);
                        if !exchange.done() {
                            self.exchanges.insert(stream, exchange);
                        }
                    }
                }
                Event::Upgraded { stream, .. } => {
                    if let Some(exchange) = self.exchanges.get_mut(&stream) {
                        exchange.upgraded = true;
                    }
                    self.model.upgraded(stream);
                }
                Event::WsMessage {
                    stream,
                    dir,
                    text,
                    payload,
                } => {
                    if let Some(dump_dir) = &self.dump {
                        let _ = dump::append_ws(
                            dump_dir,
                            self.flow,
                            stream,
                            dir.as_str(),
                            text,
                            &payload,
                        );
                    }
                    if let Some(exchange) = self.exchanges.get_mut(&stream) {
                        exchange.last_response_at = now;
                        exchange.ws_count += 1;
                        self.model.ws_message(stream, dir, text, &payload, now, out);
                        exchange.ws_messages.push((dir, text, payload));
                    }
                }
                Event::WsClosed { stream } => {
                    if let Some(mut exchange) = self.exchanges.remove(&stream) {
                        exchange.last_response_at = now;
                        self.dump_side(&exchange, false);
                        if !exchange.response_recorded && exchange.response.is_some() {
                            out.push(Emit::plain(self.response_record(&mut exchange, now)));
                        }
                    }
                }
                Event::Degraded { stream, reason } => {
                    let streams: Vec<u32> = match stream {
                        Some(stream) => vec![stream],
                        None => self.exchanges.keys().copied().collect(),
                    };
                    for stream in streams {
                        if let Some(exchange) = self.exchanges.get_mut(&stream) {
                            if !exchange.request_recorded {
                                exchange.request_degraded.get_or_insert(reason);
                            }
                            if !exchange.response_recorded {
                                exchange.response_degraded.get_or_insert(reason);
                            }
                        }
                        self.model.degraded(stream, reason);
                    }
                }
            }
        }
    }

    fn request_record(&self, exchange: &mut Exchange) -> Payload {
        exchange.request_recorded = true;
        let head = exchange.request.clone().unwrap_or_else(|| RequestHead {
            method: String::new(),
            authority: None,
            path: None,
            version: self.conn.version(),
            content_type: None,
            content_encoding: None,
            content_length: None,
            user_agent: None,
        });
        let body = exchange
            .request_body
            .as_ref()
            .map(BodySink::summary)
            .unwrap_or_default();
        Payload::HttpRequest(HttpRequest {
            flow: self.flow,
            stream: exchange.stream,
            version: head.version.as_str().to_owned(),
            method: head.method,
            authority: head.authority,
            path: head.path,
            content_type: head.content_type,
            content_encoding: head.content_encoding,
            content_length: head.content_length,
            user_agent: head.user_agent,
            body_bytes: body.bytes,
            body_b3: body.b3,
            body_truncated: body.truncated,
            degraded: exchange
                .request_degraded
                .or(body.degraded)
                .map(str::to_owned),
        })
    }

    fn response_record(&self, exchange: &mut Exchange, now: Instant) -> Payload {
        exchange.response_recorded = true;
        let head = exchange.response.clone().unwrap_or(ResponseHead {
            status: 0,
            content_type: None,
            content_encoding: None,
        });
        let body = exchange
            .response_body
            .as_ref()
            .map(BodySink::summary)
            .unwrap_or_default();
        let end = exchange.last_response_at.max(exchange.request_started);
        let _ = now;
        Payload::HttpResponse(HttpResponse {
            flow: self.flow,
            stream: exchange.stream,
            status: head.status,
            content_type: head.content_type,
            content_encoding: head.content_encoding,
            body_bytes: body.bytes,
            body_b3: body.b3,
            body_truncated: body.truncated,
            sse_events: exchange.sse_count,
            ws_messages: exchange.ws_count,
            dur_ms: u64::try_from(
                end.saturating_duration_since(exchange.request_started)
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
            degraded: exchange
                .response_degraded
                .or(body.degraded)
                .map(str::to_owned),
        })
    }
}

/// The head of a request, cut to what a record keeps.
fn request_head(
    method: String,
    authority: Option<String>,
    path: Option<String>,
    version: Version,
    headers: &Headers,
) -> RequestHead {
    RequestHead {
        method,
        authority,
        path: path.map(|p| cut(&p, PATH_CUT)),
        version,
        content_type: headers.content_type(),
        content_encoding: headers.content_encoding(),
        content_length: headers.content_length(),
        user_agent: headers
            .get_str("user-agent")
            .map(|ua| cut(ua, USER_AGENT_CUT)),
    }
}

/// `text` cut to at most `max` bytes at a character boundary, ending in
/// `…` when cut.
pub fn cut(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max.saturating_sub(3);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn observation(alpn: Option<&str>) -> Observation {
        Observation::new(
            5,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 443),
            Some("api.example".into()),
            alpn,
            true,
            "trace-test",
        )
    }

    #[test]
    fn an_h1_exchange_becomes_a_request_and_a_response_record() {
        let mut obs = observation(Some("http/1.1"));
        let mut out = Vec::new();
        let t0 = Instant::now();
        obs.data(
            Direction::ToHost,
            b"POST /v1/complete HTTP/1.1\r\nHost: api.example\r\nUser-Agent: claude-cli/2.1\r\nAuthorization: Bearer x\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"model\":\"m\"}",
            t0,
            &mut out,
        );
        assert_eq!(out.len(), 1, "{out:?}");
        match &out[0].payload {
            Payload::HttpRequest(r) => {
                assert_eq!((r.flow, r.stream), (5, 1));
                assert_eq!(r.version, "1.1");
                assert_eq!(r.method, "POST");
                assert_eq!(r.authority.as_deref(), Some("api.example"));
                assert_eq!(r.path.as_deref(), Some("/v1/complete"));
                assert_eq!(r.content_type.as_deref(), Some("application/json"));
                assert_eq!(r.content_length, Some(13));
                assert_eq!(r.user_agent.as_deref(), Some("claude-cli/2.1"));
                assert_eq!(r.body_bytes, 13);
                assert_eq!(
                    r.body_b3.as_deref(),
                    Some(format!("b3:{}", blake3::hash(b"{\"model\":\"m\"}").to_hex()).as_str())
                );
                assert!(!r.body_truncated && r.degraded.is_none());
            }
            other => panic!("{other:?}"),
        }
        let kept = obs
            .exchanges()
            .get(&1)
            .unwrap()
            .request_body
            .as_ref()
            .unwrap()
            .kept()
            .to_vec();
        assert_eq!(kept, b"{\"model\":\"m\"}");
        obs.data(
            Direction::ToGuest,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 44\r\n\r\nevent: message_start\ndata: {}\n\nevent: ping\n\n",
            t0 + std::time::Duration::from_millis(250),
            &mut out,
        );
        assert_eq!(out.len(), 2, "{out:?}");
        match &out[1].payload {
            Payload::HttpResponse(r) => {
                assert_eq!((r.flow, r.stream, r.status), (5, 1, 200));
                assert_eq!(r.content_type.as_deref(), Some("text/event-stream"));
                assert_eq!(r.sse_events, 2);
                assert_eq!(r.ws_messages, 0);
                assert_eq!(r.body_bytes, 44);
                assert!(r.dur_ms >= 250, "{}", r.dur_ms);
                assert!(r.degraded.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert!(obs.exchanges().is_empty());
    }

    #[test]
    fn a_flow_that_closes_mid_exchange_records_what_it_has_as_degraded() {
        let mut obs = observation(None);
        let mut out = Vec::new();
        let now = Instant::now();
        obs.data(
            Direction::ToHost,
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            now,
            &mut out,
        );
        obs.data(
            Direction::ToGuest,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial",
            now,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        obs.close(now, &mut out);
        assert_eq!(out.len(), 2, "{out:?}");
        match &out[1].payload {
            Payload::HttpResponse(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.body_bytes, 7);
                assert_eq!(r.degraded.as_deref(), Some("incomplete"));
            }
            other => panic!("{other:?}"),
        }
        // A response that reads until the close is whole at the close.
        let mut obs = observation(None);
        let mut out = Vec::new();
        obs.data(
            Direction::ToHost,
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            now,
            &mut out,
        );
        obs.data(
            Direction::ToGuest,
            b"HTTP/1.1 200 OK\r\n\r\nwhole",
            now,
            &mut out,
        );
        obs.close(now, &mut out);
        match &out[1].payload {
            Payload::HttpResponse(r) => {
                assert_eq!(r.body_bytes, 5);
                assert_eq!(r.degraded, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn lost_bytes_degrade_the_open_exchanges() {
        let mut obs = observation(None);
        let mut out = Vec::new();
        let now = Instant::now();
        obs.data(
            Direction::ToHost,
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nstart",
            now,
            &mut out,
        );
        obs.lost(Direction::ToHost, now, &mut out);
        obs.close(now, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        match &out[0].payload {
            Payload::HttpRequest(r) => {
                assert_eq!(r.degraded.as_deref(), Some("lost"));
                assert_eq!(r.body_bytes, 5);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cut_keeps_character_boundaries() {
        assert_eq!(cut("abc", 10), "abc");
        assert_eq!(cut("abcdefghij", 6), "abc…");
        assert_eq!(cut("ééééé", 5), "é…");
    }
}
