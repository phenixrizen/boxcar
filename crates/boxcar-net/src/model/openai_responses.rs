// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! OpenAI Responses: `POST /v1/responses`, as JSON, as an event stream,
//! or over WebSocket (`response.create` messages in, the same events
//! out).
//!
//! A request's `input` items are counted, its `instructions` hashed, its
//! `tools` named; `function_call_output` items close the spans their
//! `call_id`s opened. A response gives the model, the status, the usage,
//! the output text and the `function_call` items, each a span's open once
//! its arguments are whole (`response.output_item.done`, or the
//! `function_call_arguments.done` for it).

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    b3, content_text, tool_close, tool_open_text, u64_of, RequestInfo, ResponseInfo, Text,
    ToolClose, ToolOpen,
};
use crate::http::SseEvent;

/// What a request (a `POST` body, or a `response.create` message) said,
/// and the tool results it carried.
pub fn request(body: &[u8]) -> Result<(RequestInfo, Vec<ToolClose>), &'static str> {
    let json: Value = serde_json::from_slice(body).map_err(|_| "request_json")?;
    Ok(request_value(&json))
}

/// [`request`] for a parsed value.
pub fn request_value(json: &Value) -> (RequestInfo, Vec<ToolClose>) {
    let input = json.get("input");
    let items = input.and_then(Value::as_array);
    let mut info = RequestInfo {
        model: json.get("model").and_then(Value::as_str).map(str::to_owned),
        stream: json.get("stream").and_then(Value::as_bool).unwrap_or(false),
        messages: match input {
            Some(Value::Array(items)) => items.len() as u32,
            Some(Value::String(_)) => 1,
            _ => 0,
        },
        system_b3: json
            .get("instructions")
            .and_then(|i| b3(content_text(i).as_bytes())),
        tools: Vec::new(),
        max_tokens: u64_of(json.get("max_output_tokens")),
    };
    if let Some(tools) = json.get("tools").and_then(Value::as_array) {
        info.tools = tools
            .iter()
            .filter_map(|t| {
                t.get("name")
                    .or_else(|| t.get("type"))
                    .and_then(Value::as_str)
            })
            .take(64)
            .map(str::to_owned)
            .collect();
    }
    let mut closes = Vec::new();
    if let Some(items) = items {
        for item in items {
            if item.get("type").and_then(Value::as_str) != Some("function_call_output") {
                continue;
            }
            let Some(id) = item.get("call_id").and_then(Value::as_str) else {
                continue;
            };
            let output = item.get("output").cloned().unwrap_or(Value::Null);
            closes.push(tool_close(id, &output, false));
        }
    }
    (info, closes)
}

/// A response as one JSON document (a `response` object).
pub fn response(body: &[u8]) -> Result<(ResponseInfo, Vec<ToolOpen>), &'static str> {
    let json: Value = serde_json::from_slice(body).map_err(|_| "response_json")?;
    Ok(response_value(&json))
}

/// [`response`] for a parsed `response` object.
pub fn response_value(json: &Value) -> (ResponseInfo, Vec<ToolOpen>) {
    let mut text = Text::default();
    let mut opens = Vec::new();
    if let Some(output) = json.get("output").and_then(Value::as_array) {
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("message") => {
                    if let Some(parts) = item.get("content").and_then(Value::as_array) {
                        for part in parts {
                            if let Some(t) = part.get("text").and_then(Value::as_str) {
                                text.push(t);
                            }
                        }
                    }
                }
                Some("function_call") => opens.push(item_open(item)),
                _ => {}
            }
        }
    }
    let info = ResponseInfo {
        model: json.get("model").and_then(Value::as_str).map(str::to_owned),
        stop_reason: json
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned),
        text_bytes: text.bytes(),
        text_b3: text.b3(),
        tool_uses: opens.len() as u32,
        degraded: None,
        ..usage_of(json.get("usage"))
    };
    (info, opens)
}

fn usage_of(usage: Option<&Value>) -> ResponseInfo {
    ResponseInfo {
        input_tokens: u64_of(usage.and_then(|u| u.get("input_tokens"))),
        output_tokens: u64_of(usage.and_then(|u| u.get("output_tokens"))),
        cache_read_tokens: u64_of(
            usage
                .and_then(|u| u.get("input_tokens_details"))
                .and_then(|d| d.get("cached_tokens")),
        ),
        ..ResponseInfo::default()
    }
}

/// A whole `function_call` item as a span's open.
fn item_open(item: &Value) -> ToolOpen {
    let id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let name = item.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = item
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    tool_open_text(id, name, arguments)
}

/// A function call under way in a stream, by its output index.
#[derive(Default)]
struct Call {
    item_id: String,
    call_id: String,
    name: String,
    arguments: String,
    done: bool,
}

/// A streamed response, event by event; the same for the events of a
/// WebSocket session.
#[derive(Default)]
pub struct Stream {
    info: ResponseInfo,
    text: Text,
    calls: BTreeMap<u64, Call>,
    degraded: Option<&'static str>,
    completed: bool,
}

impl Stream {
    pub fn new() -> Stream {
        Stream::default()
    }

    /// One event from the stream: the calls it completes.
    pub fn event(&mut self, event: &SseEvent) -> Vec<ToolOpen> {
        let Ok(data) = serde_json::from_str::<Value>(&event.data) else {
            if !event.data.is_empty() {
                self.degraded.get_or_insert("event_json");
            }
            return Vec::new();
        };
        self.value(&data)
    }

    /// One event as a parsed value (a WebSocket message carries one).
    pub fn value(&mut self, data: &Value) -> Vec<ToolOpen> {
        let kind = data.get("type").and_then(Value::as_str).unwrap_or("");
        let mut opens = Vec::new();
        match kind {
            "response.created" | "response.in_progress" => {
                if let Some(model) = data
                    .get("response")
                    .and_then(|r| r.get("model"))
                    .and_then(Value::as_str)
                {
                    self.info.model = Some(model.to_owned());
                }
            }
            "response.output_item.added" => {
                let item = data.get("item");
                if item.and_then(|i| i.get("type")).and_then(Value::as_str) == Some("function_call")
                {
                    let index = u64_of(data.get("output_index")).unwrap_or(0);
                    let call = self.calls.entry(index).or_default();
                    call.item_id = item
                        .and_then(|i| i.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    call.call_id = item
                        .and_then(|i| i.get("call_id"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    call.name = item
                        .and_then(|i| i.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    if let Some(args) = item
                        .and_then(|i| i.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        call.arguments = args.to_owned();
                    }
                }
            }
            "response.function_call_arguments.delta" => {
                let index = u64_of(data.get("output_index")).unwrap_or(0);
                if let Some(delta) = data.get("delta").and_then(Value::as_str) {
                    self.calls
                        .entry(index)
                        .or_default()
                        .arguments
                        .push_str(delta);
                }
            }
            "response.function_call_arguments.done" => {
                let index = u64_of(data.get("output_index")).unwrap_or(0);
                let call = self.calls.entry(index).or_default();
                if let Some(args) = data.get("arguments").and_then(Value::as_str) {
                    call.arguments = args.to_owned();
                }
            }
            "response.output_item.done" => {
                let index = u64_of(data.get("output_index")).unwrap_or(0);
                let item = data.get("item");
                if item.and_then(|i| i.get("type")).and_then(Value::as_str) == Some("function_call")
                {
                    let mut call = self.calls.remove(&index).unwrap_or_default();
                    if let Some(id) = item.and_then(|i| i.get("call_id")).and_then(Value::as_str) {
                        call.call_id = id.to_owned();
                    }
                    if let Some(name) = item.and_then(|i| i.get("name")).and_then(Value::as_str) {
                        call.name = name.to_owned();
                    }
                    if let Some(args) = item
                        .and_then(|i| i.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        call.arguments = args.to_owned();
                    }
                    call.done = true;
                    self.info.tool_uses += 1;
                    let id = if call.call_id.is_empty() {
                        &call.item_id
                    } else {
                        &call.call_id
                    };
                    opens.push(tool_open_text(id, &call.name, &call.arguments));
                }
            }
            "response.output_text.delta" => {
                if let Some(delta) = data.get("delta").and_then(Value::as_str) {
                    self.text.push(delta);
                }
            }
            "response.completed" | "response.incomplete" | "response.failed" => {
                self.completed = true;
                let response = data.get("response");
                if let Some(model) = response
                    .and_then(|r| r.get("model"))
                    .and_then(Value::as_str)
                {
                    self.info.model = Some(model.to_owned());
                }
                self.info.stop_reason = response
                    .and_then(|r| r.get("status"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| Some(kind.trim_start_matches("response.").to_owned()));
                let usage = usage_of(response.and_then(|r| r.get("usage")));
                if usage.input_tokens.is_some() || usage.output_tokens.is_some() {
                    self.info.input_tokens = usage.input_tokens;
                    self.info.output_tokens = usage.output_tokens;
                    self.info.cache_read_tokens = usage.cache_read_tokens;
                }
            }
            "error" => {
                self.degraded.get_or_insert("stream_error");
            }
            _ => {}
        }
        opens
    }

    /// The stream ended: what it said, and the calls never marked done.
    pub fn finish(mut self) -> (ResponseInfo, Vec<ToolOpen>) {
        let mut opens = Vec::new();
        for (_, call) in std::mem::take(&mut self.calls) {
            if call.done {
                continue;
            }
            self.degraded.get_or_insert("call_unfinished");
            self.info.tool_uses += 1;
            let id = if call.call_id.is_empty() {
                &call.item_id
            } else {
                &call.call_id
            };
            opens.push(tool_open_text(id, &call.name, &call.arguments));
        }
        if !self.completed {
            self.degraded.get_or_insert("stream_unfinished");
        }
        self.info.text_bytes = self.text.bytes();
        self.info.text_b3 = self.text.b3();
        self.info.degraded = self.degraded;
        (self.info, opens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(data: &str) -> SseEvent {
        SseEvent {
            event: None,
            data: data.to_owned(),
            id: None,
        }
    }

    #[test]
    fn a_request_counts_items_names_tools_and_closes_outputs() {
        let body = serde_json::json!({
            "model": "gpt-5-codex",
            "stream": true,
            "instructions": "You are Codex.",
            "max_output_tokens": 8192,
            "tools": [{"type": "function", "name": "shell"}, {"type": "web_search"}],
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "ls"}]},
                {"type": "function_call", "call_id": "call_a", "name": "shell", "arguments": "{\"command\":[\"ls\"]}"},
                {"type": "function_call_output", "call_id": "call_a", "output": "a\nb\n"}
            ]
        });
        let (info, closes) = request(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.model.as_deref(), Some("gpt-5-codex"));
        assert_eq!(info.messages, 3);
        assert_eq!(info.system_b3, b3(b"You are Codex."));
        assert_eq!(info.tools, ["shell", "web_search"]);
        assert_eq!(info.max_tokens, Some(8192));
        assert_eq!(closes.len(), 1);
        assert_eq!(
            (closes[0].tool_use_id.as_str(), closes[0].result_bytes),
            ("call_a", 4)
        );
        let (info, _) = request(br#"{"model":"m","input":"hi"}"#).unwrap();
        assert_eq!(info.messages, 1);
    }

    #[test]
    fn a_json_response_opens_its_function_calls() {
        let body = serde_json::json!({
            "model": "gpt-5-codex",
            "status": "completed",
            "usage": {"input_tokens": 70, "output_tokens": 12, "input_tokens_details": {"cached_tokens": 64}},
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": "Listing."}]},
                {"type": "function_call", "id": "fc_1", "call_id": "call_b", "name": "shell", "arguments": "{\"command\":[\"ls\",\"-la\"]}"}
            ]
        });
        let (info, opens) = response(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.stop_reason.as_deref(), Some("completed"));
        assert_eq!(
            (
                info.input_tokens,
                info.output_tokens,
                info.cache_read_tokens
            ),
            (Some(70), Some(12), Some(64))
        );
        assert_eq!(info.text_b3, b3(b"Listing."));
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].tool_use_id, "call_b");
        assert_eq!(
            opens[0].args,
            Some(serde_json::json!({"command": ["ls", "-la"]}))
        );
    }

    #[test]
    fn streamed_function_calls_open_when_their_item_is_done() {
        let mut stream = Stream::new();
        let mut opens = Vec::new();
        opens.extend(stream.event(&sse(
            r#"{"type":"response.created","response":{"id":"resp_1","model":"gpt-5-codex"}}"#,
        )));
        opens.extend(stream.event(&sse(r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1"}}"#)));
        opens.extend(stream.event(&sse(
            r#"{"type":"response.output_text.delta","output_index":0,"delta":"List"}"#,
        )));
        opens.extend(stream.event(&sse(
            r#"{"type":"response.output_text.delta","output_index":0,"delta":"ing."}"#,
        )));
        opens.extend(stream.event(&sse(r#"{"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_b","name":"shell","arguments":""}}"#)));
        opens.extend(stream.event(&sse(r#"{"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"command\":"}"#)));
        opens.extend(stream.event(&sse(r#"{"type":"response.function_call_arguments.delta","output_index":1,"delta":"[\"ls\"]}"}"#)));
        opens.extend(stream.event(&sse(r#"{"type":"response.function_call_arguments.done","output_index":1,"arguments":"{\"command\":[\"ls\"]}"}"#)));
        assert!(opens.is_empty());
        opens.extend(stream.event(&sse(r#"{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_b","name":"shell","arguments":"{\"command\":[\"ls\"]}"}}"#)));
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].args, Some(serde_json::json!({"command": ["ls"]})));
        opens.extend(stream.event(&sse(r#"{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":70,"output_tokens":12}}}"#)));
        let (info, late) = stream.finish();
        assert!(late.is_empty());
        assert_eq!(info.model.as_deref(), Some("gpt-5-codex"));
        assert_eq!(info.stop_reason.as_deref(), Some("completed"));
        assert_eq!(
            (info.input_tokens, info.output_tokens),
            (Some(70), Some(12))
        );
        assert_eq!(info.text_b3, b3(b"Listing."));
        assert_eq!(info.tool_uses, 1);
        assert_eq!(info.degraded, None);
    }

    /// Over WebSocket the same events arrive as messages, with the
    /// request as a `response.create` message.
    #[test]
    fn websocket_messages_are_the_same_values() {
        let create = serde_json::json!({"type": "response.create", "model": "gpt-5-codex", "input": "hi", "stream": true});
        let (info, _) = request_value(&create);
        assert_eq!(info.model.as_deref(), Some("gpt-5-codex"));
        let mut stream = Stream::new();
        stream.value(&serde_json::json!({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "call_id": "call_z", "name": "shell"}}));
        let opens = stream.value(&serde_json::json!({"type": "response.output_item.done", "output_index": 0, "item": {"type": "function_call", "call_id": "call_z", "name": "shell", "arguments": "{}"}}));
        assert_eq!(opens.len(), 1);
        let (info, _) = stream.finish();
        assert_eq!(info.degraded, Some("stream_unfinished"));
    }
}
