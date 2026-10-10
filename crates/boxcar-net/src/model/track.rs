// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The model records of one inspected flow, read from its exchanges as
//! the observer keeps them: `llm.request` and the `tool.close`s it carries
//! when a request's body ends, `tool.open`s as a response's tool calls
//! become whole (in a stream, as they come), `llm.response` when the
//! response ends. Over WebSocket, each `response.create` message is a
//! request and the events until `response.completed` its response.
//!
//! Spans: a `tool.open` and the `tool.close` that answers it share
//! `{trace_id: <the session>, span_id: <the provider's tool use id>}`.

use std::collections::HashMap;
use std::time::Instant;

use boxcar_proto::{
    LlmRequest, LlmResponse, Payload, SpanRef, ToolClose as ToolClosePayload,
    ToolOpen as ToolOpenPayload,
};
use serde_json::Value;

use super::{
    anthropic, openai_chat, openai_responses, Provider, RequestInfo, ResponseInfo, ToolClose,
    ToolOpen,
};
use crate::gate::exchange::{Emit, Exchange};
use crate::gate::Direction;
use crate::http::{Headers, SseEvent};

/// A response under way, by its provider.
enum Stream {
    Anthropic(anthropic::Stream),
    Chat(openai_chat::Stream),
    Responses(openai_responses::Stream),
}

impl Stream {
    fn new(provider: Provider) -> Stream {
        match provider {
            Provider::Anthropic => Stream::Anthropic(anthropic::Stream::new()),
            Provider::OpenAiChat => Stream::Chat(openai_chat::Stream::new()),
            Provider::OpenAiResponses => Stream::Responses(openai_responses::Stream::new()),
        }
    }

    fn event(&mut self, event: &SseEvent) -> Vec<ToolOpen> {
        match self {
            Stream::Anthropic(s) => s.event(event),
            Stream::Chat(s) => s.event(event),
            Stream::Responses(s) => s.event(event),
        }
    }

    fn finish(self) -> (ResponseInfo, Vec<ToolOpen>) {
        match self {
            Stream::Anthropic(s) => s.finish(),
            Stream::Chat(s) => s.finish(),
            Stream::Responses(s) => s.finish(),
        }
    }
}

/// One exchange's model state.
struct Tracked {
    provider: Provider,
    started: Instant,
    /// The request was recorded (its body ended).
    requested: bool,
    /// A streamed response under way.
    stream: Option<Stream>,
    /// The response is a stream (events), not one document.
    sse: bool,
    /// Over WebSocket: the responses are the events until completion.
    ws: bool,
    degraded: Option<&'static str>,
}

/// The model records of one flow.
pub struct Tracker {
    flow: u64,
    trace_id: String,
    streams: HashMap<u32, Tracked>,
}

impl Tracker {
    /// A tracker for `flow`, whose spans belong to `trace_id` (the
    /// session).
    pub fn new(flow: u64, trace_id: String) -> Tracker {
        Tracker {
            flow,
            trace_id,
            streams: HashMap::new(),
        }
    }

    /// Whether `stream` speaks a model API.
    pub fn tracks(&self, stream: u32) -> bool {
        self.streams.contains_key(&stream)
    }

    /// A request's head: tracked when its path names a provider.
    pub fn request_head(&mut self, stream: u32, path: Option<&str>, now: Instant) {
        if let Some(provider) = Provider::for_request(path) {
            self.streams.insert(
                stream,
                Tracked {
                    provider,
                    started: now,
                    requested: false,
                    stream: None,
                    sse: false,
                    ws: false,
                    degraded: None,
                },
            );
        }
    }

    /// A request's body ended: `llm.request`, and the `tool.close`s it
    /// carried.
    pub fn request_end(&mut self, stream: u32, exchange: &Exchange, out: &mut Vec<Emit>) {
        let Some(tracked) = self.streams.get_mut(&stream) else {
            return;
        };
        if tracked.requested {
            return;
        }
        tracked.requested = true;
        let summary = exchange
            .request_body
            .as_ref()
            .map(crate::http::BodySink::summary)
            .unwrap_or_default();
        let body = exchange
            .request_body
            .as_ref()
            .map(|b| b.kept())
            .unwrap_or(&[]);
        if summary.bytes == 0 && !summary.truncated {
            // No body: an upgrade, or nothing a model API takes.
            return;
        }
        let parsed = if summary.truncated {
            Err("body_truncated")
        } else if let Some(reason) = summary.degraded {
            Err(reason)
        } else {
            match tracked.provider {
                Provider::Anthropic => anthropic::request(body),
                Provider::OpenAiChat => openai_chat::request(body),
                Provider::OpenAiResponses => openai_responses::request(body),
            }
        };
        let (info, closes, degraded) = match parsed {
            Ok((info, closes)) => (info, closes, None),
            Err(reason) => (RequestInfo::default(), Vec::new(), Some(reason)),
        };
        let provider = tracked.provider;
        out.push(Emit::plain(Payload::LlmRequest(LlmRequest {
            flow: self.flow,
            stream,
            provider: provider.as_str().to_owned(),
            model: info.model,
            streaming: info.stream,
            messages: info.messages,
            system_b3: info.system_b3,
            tools: info.tools,
            max_tokens: info.max_tokens,
            body_bytes: summary.bytes,
            body_b3: summary.b3,
            degraded: degraded.map(str::to_owned),
        })));
        for close in closes {
            out.push(self.close_record(stream, close));
        }
    }

    /// A response's head: a stream of events, or one document at the end.
    pub fn response_head(&mut self, stream: u32, status: u16, headers: &Headers) {
        let Some(tracked) = self.streams.get_mut(&stream) else {
            return;
        };
        if (100..200).contains(&status) {
            return;
        }
        tracked.sse = headers.content_type().as_deref() == Some("text/event-stream");
        if tracked.sse {
            tracked.stream = Some(Stream::new(tracked.provider));
        }
    }

    /// More of a response came: the events it completed (the exchange's
    /// events, which it drops after this), each tool call that is whole a
    /// `tool.open`.
    pub fn response_body(&mut self, stream: u32, exchange: &Exchange, out: &mut Vec<Emit>) {
        let Some(tracked) = self.streams.get_mut(&stream) else {
            return;
        };
        let Some(parser) = tracked.stream.as_mut() else {
            return;
        };
        let mut opens = Vec::new();
        for event in &exchange.sse_events {
            opens.extend(parser.event(event));
        }
        for open in opens {
            out.push(self.open_record(stream, open));
        }
    }

    /// The response ended: `llm.response`, after any tool call still
    /// whole only now.
    pub fn response_end(
        &mut self,
        stream: u32,
        exchange: &Exchange,
        now: Instant,
        out: &mut Vec<Emit>,
    ) {
        self.response_body(stream, exchange, out);
        let Some(mut tracked) = self.streams.remove(&stream) else {
            return;
        };
        let summary = exchange
            .response_body
            .as_ref()
            .map(crate::http::BodySink::summary)
            .unwrap_or_default();
        let (mut info, opens) = match tracked.stream.take() {
            Some(parser) => parser.finish(),
            None => {
                let body = exchange
                    .response_body
                    .as_ref()
                    .map(|b| b.kept())
                    .unwrap_or(&[]);
                let parsed = if summary.truncated {
                    Err("body_truncated")
                } else if let Some(reason) = summary.degraded {
                    Err(reason)
                } else {
                    match tracked.provider {
                        Provider::Anthropic => anthropic::response(body),
                        Provider::OpenAiChat => openai_chat::response(body),
                        Provider::OpenAiResponses => openai_responses::response(body),
                    }
                };
                match parsed {
                    Ok(parsed) => parsed,
                    Err(reason) => (
                        ResponseInfo {
                            degraded: Some(reason),
                            ..ResponseInfo::default()
                        },
                        Vec::new(),
                    ),
                }
            }
        };
        if let Some(reason) = tracked.degraded {
            info.degraded.get_or_insert(reason);
        }
        for open in opens {
            out.push(self.open_record(stream, open));
        }
        out.push(self.response_record(stream, tracked.provider, info, tracked.started, now));
    }

    /// The stream switched to WebSocket: requests and responses are
    /// messages from here.
    pub fn upgraded(&mut self, stream: u32) {
        if let Some(tracked) = self.streams.get_mut(&stream) {
            tracked.ws = true;
            tracked.requested = true;
        }
    }

    /// A WebSocket message: a `response.create` is a request; the events
    /// are the response, until it completes.
    pub fn ws_message(
        &mut self,
        stream: u32,
        dir: Direction,
        text: bool,
        payload: &[u8],
        now: Instant,
        out: &mut Vec<Emit>,
    ) {
        let Some(tracked) = self.streams.get_mut(&stream) else {
            return;
        };
        if !text {
            return;
        }
        let Ok(value) = serde_json::from_slice::<Value>(payload) else {
            tracked.degraded.get_or_insert("message_json");
            return;
        };
        let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
        let provider = tracked.provider;
        match dir {
            Direction::ToHost => {
                if kind != "response.create" {
                    return;
                }
                let (info, closes) = openai_responses::request_value(&value);
                tracked.started = now;
                tracked.stream = Some(Stream::new(provider));
                let flow = self.flow;
                out.push(Emit::plain(Payload::LlmRequest(LlmRequest {
                    flow,
                    stream,
                    provider: provider.as_str().to_owned(),
                    model: info.model,
                    streaming: true,
                    messages: info.messages,
                    system_b3: info.system_b3,
                    tools: info.tools,
                    max_tokens: info.max_tokens,
                    body_bytes: payload.len() as u64,
                    body_b3: super::b3(payload),
                    degraded: None,
                })));
                for close in closes {
                    out.push(self.close_record(stream, close));
                }
            }
            Direction::ToGuest => {
                let Some(Stream::Responses(parser)) = tracked.stream.as_mut() else {
                    return;
                };
                let opens = parser.value(&value);
                let completed = matches!(
                    kind,
                    "response.completed" | "response.incomplete" | "response.failed"
                );
                let started = tracked.started;
                let finished = if completed {
                    tracked.stream.take().map(Stream::finish)
                } else {
                    None
                };
                for open in opens {
                    out.push(self.open_record(stream, open));
                }
                if let Some((info, late)) = finished {
                    for open in late {
                        out.push(self.open_record(stream, open));
                    }
                    out.push(self.response_record(stream, provider, info, started, now));
                }
            }
        }
    }

    /// Something about `stream` could not be read.
    pub fn degraded(&mut self, stream: u32, reason: &'static str) {
        if let Some(tracked) = self.streams.get_mut(&stream) {
            tracked.degraded.get_or_insert(reason);
        }
    }

    /// The flow ended: responses under way are recorded as they stand.
    pub fn close(&mut self, now: Instant, out: &mut Vec<Emit>) {
        let mut open: Vec<u32> = self.streams.keys().copied().collect();
        open.sort_unstable();
        for stream in open {
            self.end(stream, now, out);
        }
    }

    /// `stream` is observed no further (the flow ended, or the stream was
    /// reset or could not be read): a response under way is recorded as it
    /// stands, and the stream is forgotten.
    pub fn end(&mut self, stream: u32, now: Instant, out: &mut Vec<Emit>) {
        let Some(tracked) = self.streams.remove(&stream) else {
            return;
        };
        let Some(parser) = tracked.stream else {
            return;
        };
        let (mut info, opens) = parser.finish();
        info.degraded
            .get_or_insert(tracked.degraded.unwrap_or("flow_closed"));
        for open in opens {
            out.push(self.open_record(stream, open));
        }
        out.push(self.response_record(stream, tracked.provider, info, tracked.started, now));
    }

    fn span(&self, tool_use_id: &str) -> SpanRef {
        SpanRef {
            trace_id: self.trace_id.clone(),
            span_id: tool_use_id.to_owned(),
        }
    }

    fn open_record(&self, stream: u32, open: ToolOpen) -> Emit {
        let span = self.span(&open.tool_use_id);
        Emit::in_span(
            Payload::ToolOpen(ToolOpenPayload {
                flow: self.flow,
                stream,
                tool_use_id: open.tool_use_id,
                tool_name: open.tool_name,
                args_b3: open.args_b3,
                args_summary: open.args_summary,
                args: open.args,
            }),
            span,
        )
    }

    fn close_record(&self, stream: u32, close: ToolClose) -> Emit {
        let span = self.span(&close.tool_use_id);
        Emit::in_span(
            Payload::ToolClose(ToolClosePayload {
                flow: self.flow,
                stream,
                tool_use_id: close.tool_use_id,
                status: close.status,
                result_bytes: close.result_bytes,
                result_b3: close.result_b3,
                result_summary: close.result_summary,
            }),
            span,
        )
    }

    fn response_record(
        &self,
        stream: u32,
        provider: Provider,
        info: ResponseInfo,
        started: Instant,
        now: Instant,
    ) -> Emit {
        Emit::plain(Payload::LlmResponse(LlmResponse {
            flow: self.flow,
            stream,
            provider: provider.as_str().to_owned(),
            model: info.model,
            stop_reason: info.stop_reason,
            input_tokens: info.input_tokens,
            output_tokens: info.output_tokens,
            cache_read_tokens: info.cache_read_tokens,
            text_bytes: info.text_bytes,
            text_b3: info.text_b3,
            tool_uses: info.tool_uses,
            dur_ms: u64::try_from(now.saturating_duration_since(started).as_millis())
                .unwrap_or(u64::MAX),
            degraded: info.degraded.map(str::to_owned),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, Instant};

    use boxcar_proto::Payload;

    use crate::gate::exchange::{Emit, Observation};
    use crate::gate::Direction;

    fn observation() -> Observation {
        Observation::new(
            9,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 443),
            Some("api.anthropic.com".into()),
            Some("http/1.1"),
            true,
            "session-trace",
        )
    }

    fn kinds(out: &[Emit]) -> Vec<&'static str> {
        out.iter().map(|e| e.payload.kind()).collect()
    }

    fn h1_request(path: &str, body: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn h1_sse(events: &[(&str, &str)]) -> Vec<u8> {
        let mut body = String::new();
        for (event, data) in events {
            body.push_str(&format!("event: {event}\ndata: {data}\n\n"));
        }
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// An Anthropic turn: the request, its streamed reply with a tool
    /// use (opened at its block's stop, before the reply ends), then the
    /// next request carrying the result (the close). The span reference
    /// ties the open and the close.
    #[test]
    fn an_anthropic_turn_opens_and_the_next_request_closes() {
        let mut obs = observation();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let request = serde_json::json!({
            "model": "claude-fable-5-1", "max_tokens": 1024, "stream": true,
            "system": "be brief", "tools": [{"name": "Bash"}],
            "messages": [{"role": "user", "content": "list the files"}]
        });
        obs.data(
            Direction::ToHost,
            &h1_request("/v1/messages", &request.to_string()),
            t0,
            &mut out,
        );
        assert_eq!(kinds(&out), ["http.request", "llm.request"], "{out:?}");
        let Payload::LlmRequest(req) = &out[1].payload else {
            panic!()
        };
        assert_eq!(req.provider, "anthropic");
        assert_eq!(req.model.as_deref(), Some("claude-fable-5-1"));
        assert!(req.streaming);
        assert_eq!(req.tools, ["Bash"]);
        assert_eq!(req.messages, 1);
        assert!(req.body_b3.is_some());
        out.clear();

        let reply = h1_sse(&[
            (
                "message_start",
                r#"{"type":"message_start","message":{"model":"claude-fable-5-1","usage":{"input_tokens":30,"output_tokens":1}}}"#,
            ),
            (
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            (
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Listing."}}"#,
            ),
            (
                "content_block_stop",
                r#"{"type":"content_block_stop","index":0}"#,
            ),
            (
                "content_block_start",
                r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_7","name":"Bash","input":{}}}"#,
            ),
            (
                "content_block_delta",
                r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls -la\"}"}}"#,
            ),
            (
                "content_block_stop",
                r#"{"type":"content_block_stop","index":1}"#,
            ),
            (
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":12}}"#,
            ),
            ("message_stop", r#"{"type":"message_stop"}"#),
        ]);
        // In pieces: the tool.open comes as soon as its block stops.
        let cut = reply.len() * 2 / 3;
        obs.data(
            Direction::ToGuest,
            &reply[..cut],
            t0 + Duration::from_millis(100),
            &mut out,
        );
        obs.data(
            Direction::ToGuest,
            &reply[cut..],
            t0 + Duration::from_millis(300),
            &mut out,
        );
        assert_eq!(
            kinds(&out),
            ["tool.open", "http.response", "llm.response"],
            "{out:?}"
        );
        let Payload::ToolOpen(open) = &out[0].payload else {
            panic!()
        };
        assert_eq!(
            (open.tool_use_id.as_str(), open.tool_name.as_str()),
            ("toolu_7", "Bash")
        );
        assert_eq!(open.args, Some(serde_json::json!({"command": "ls -la"})));
        assert_eq!(
            out[0]
                .span
                .as_ref()
                .map(|s| (s.trace_id.as_str(), s.span_id.as_str())),
            Some(("session-trace", "toolu_7"))
        );
        let Payload::LlmResponse(resp) = &out[2].payload else {
            panic!()
        };
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(
            (resp.input_tokens, resp.output_tokens),
            (Some(30), Some(12))
        );
        assert_eq!(resp.tool_uses, 1);
        assert!(resp.text_b3.is_some() && resp.text_bytes == 8);
        assert!(resp.dur_ms >= 300, "{}", resp.dur_ms);
        assert_eq!(resp.degraded, None);
        assert!(out[2].span.is_none());
        out.clear();

        let next = serde_json::json!({
            "model": "claude-fable-5-1", "max_tokens": 1024, "stream": true,
            "messages": [
                {"role": "user", "content": "list the files"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_7", "name": "Bash", "input": {"command": "ls -la"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_7", "content": "total 0"}]}
            ]
        });
        obs.data(
            Direction::ToHost,
            &h1_request("/v1/messages", &next.to_string()),
            t0 + Duration::from_secs(1),
            &mut out,
        );
        assert_eq!(
            kinds(&out),
            ["http.request", "llm.request", "tool.close"],
            "{out:?}"
        );
        let Payload::ToolClose(close) = &out[2].payload else {
            panic!()
        };
        assert_eq!(
            (
                close.tool_use_id.as_str(),
                close.status.as_str(),
                close.result_summary.as_str()
            ),
            ("toolu_7", "ok", "total 0")
        );
        assert_eq!(
            out[2].span.as_ref().map(|s| s.span_id.as_str()),
            Some("toolu_7")
        );
        // Nothing of the credential, the prompt or the result text is inline.
        for emit in &out {
            let text = serde_json::to_string(&emit.payload).unwrap();
            assert!(
                !text.contains("secret") && !text.contains("list the files"),
                "{text}"
            );
        }
    }

    /// A path that names no provider is an HTTP exchange only; a body the
    /// parser cannot read degrades the model record, not the flow.
    #[test]
    fn unknown_paths_and_unreadable_bodies_degrade_only_what_they_touch() {
        let mut obs = observation();
        let mut out = Vec::new();
        let now = Instant::now();
        obs.data(
            Direction::ToHost,
            &h1_request("/v1/models", "{}"),
            now,
            &mut out,
        );
        assert_eq!(kinds(&out), ["http.request"]);
        out.clear();
        obs.data(
            Direction::ToHost,
            &h1_request("/v1/chat/completions", "not json at all"),
            now,
            &mut out,
        );
        assert_eq!(kinds(&out), ["http.request", "llm.request"], "{out:?}");
        let Payload::LlmRequest(req) = &out[1].payload else {
            panic!()
        };
        assert_eq!(req.provider, "openai_chat");
        assert_eq!(req.degraded.as_deref(), Some("request_json"));
        out.clear();
        // The flow closes with the reply under way: llm.response says so.
        obs.data(
            Direction::ToGuest,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            now,
            &mut out,
        );
        obs.data(Direction::ToGuest, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 500\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n", now, &mut out);
        obs.close(now, &mut out);
        // The first reply answers the untracked request: HTTP only. The
        // second, cut short, is the chat request's.
        let llm: Vec<&Emit> = out
            .iter()
            .filter(|e| e.payload.kind() == "llm.response")
            .collect();
        assert_eq!(llm.len(), 1, "{out:?}");
        let Payload::LlmResponse(last) = &llm[0].payload else {
            panic!()
        };
        assert_eq!(last.stream, 2);
        assert!(
            matches!(
                last.degraded.as_deref(),
                Some("incomplete") | Some("stream_unfinished") | Some("flow_closed")
            ),
            "{last:?}"
        );
    }

    /// Responses over WebSocket: a `response.create` message is a request,
    /// the events until `response.completed` its reply.
    #[test]
    fn responses_over_websocket_pair_messages_into_requests_and_replies() {
        let mut obs = Observation::new(
            3,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443),
            Some("api.openai.com".into()),
            Some("http/1.1"),
            true,
            "session-trace",
        );
        let mut out = Vec::new();
        let now = Instant::now();
        obs.data(Direction::ToHost, b"GET /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n", now, &mut out);
        obs.data(Direction::ToGuest, b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", now, &mut out);
        assert_eq!(kinds(&out), ["http.request"], "{out:?}");
        out.clear();
        let text = |payload: &str, mask: Option<[u8; 4]>| -> Vec<u8> {
            let mut f = vec![0x81];
            let mask_bit = if mask.is_some() { 0x80 } else { 0 };
            if payload.len() < 126 {
                f.push(mask_bit | payload.len() as u8);
            } else {
                f.push(mask_bit | 126);
                f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            match mask {
                Some(key) => {
                    f.extend_from_slice(&key);
                    f.extend(payload.bytes().enumerate().map(|(i, b)| b ^ key[i % 4]));
                }
                None => f.extend_from_slice(payload.as_bytes()),
            }
            f
        };
        obs.data(
            Direction::ToHost,
            &text(
                r#"{"type":"response.create","model":"gpt-5-codex","input":"ls"}"#,
                Some([1, 2, 3, 4]),
            ),
            now,
            &mut out,
        );
        assert_eq!(kinds(&out), ["llm.request"], "{out:?}");
        out.clear();
        obs.data(Direction::ToGuest, &text(r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_9","name":"shell"}}"#, None), now, &mut out);
        obs.data(Direction::ToGuest, &text(r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_9","name":"shell","arguments":"{\"command\":[\"ls\"]}"}}"#, None), now, &mut out);
        obs.data(Direction::ToGuest, &text(r#"{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":5,"output_tokens":3}}}"#, None), now, &mut out);
        assert_eq!(kinds(&out), ["tool.open", "llm.response"], "{out:?}");
        assert_eq!(
            out[0].span.as_ref().map(|s| s.span_id.as_str()),
            Some("call_9")
        );
        let Payload::LlmResponse(resp) = &out[1].payload else {
            panic!()
        };
        assert_eq!(resp.provider, "openai_responses");
        assert_eq!(resp.stop_reason.as_deref(), Some("completed"));
        assert_eq!(resp.tool_uses, 1);
    }
}
