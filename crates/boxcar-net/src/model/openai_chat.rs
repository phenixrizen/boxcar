// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! OpenAI Chat Completions: `POST /v1/chat/completions`.
//!
//! A request's `messages` are counted, a leading `system` (or
//! `developer`) message hashed, its `tools` named; `role: tool` messages
//! close the spans their `tool_call_id`s opened. A response, as JSON or
//! as an event stream of chunks (`data: {...}` up to `data: [DONE]`),
//! gives the model, the finish reason, the usage, the text and the
//! `tool_calls`, each a span's open once its arguments are whole
//! (streamed by `index`).

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    b3, content_text, tool_close, tool_open_text, u64_of, RequestInfo, ResponseInfo, Text,
    ToolClose, ToolOpen,
};
use crate::http::SseEvent;

/// What a request said, and the tool results it carried.
pub fn request(body: &[u8]) -> Result<(RequestInfo, Vec<ToolClose>), &'static str> {
    let json: Value = serde_json::from_slice(body).map_err(|_| "request_json")?;
    let messages = json.get("messages").and_then(Value::as_array);
    let system = messages.and_then(|m| {
        m.iter().find(|msg| {
            matches!(
                msg.get("role").and_then(Value::as_str),
                Some("system") | Some("developer")
            )
        })
    });
    let mut info = RequestInfo {
        model: json.get("model").and_then(Value::as_str).map(str::to_owned),
        stream: json.get("stream").and_then(Value::as_bool).unwrap_or(false),
        messages: messages.map_or(0, |m| m.len() as u32),
        system_b3: system
            .and_then(|s| s.get("content"))
            .and_then(|c| b3(content_text(c).as_bytes())),
        tools: Vec::new(),
        max_tokens: u64_of(json.get("max_completion_tokens"))
            .or_else(|| u64_of(json.get("max_tokens"))),
    };
    if let Some(tools) = json.get("tools").and_then(Value::as_array) {
        info.tools = tools
            .iter()
            .filter_map(|t| {
                t.get("function")
                    .and_then(|f| f.get("name"))
                    .or_else(|| t.get("name"))
                    .and_then(Value::as_str)
            })
            .take(64)
            .map(str::to_owned)
            .collect();
    }
    // The tool results are the `tool` messages after the last assistant
    // turn: what the agent just sent back.
    let mut closes = Vec::new();
    if let Some(messages) = messages {
        let last_assistant = messages
            .iter()
            .rposition(|m| m.get("role").and_then(Value::as_str) == Some("assistant"));
        let from = last_assistant.map_or(0, |i| i + 1);
        for message in &messages[from..] {
            if message.get("role").and_then(Value::as_str) != Some("tool") {
                continue;
            }
            let Some(id) = message.get("tool_call_id").and_then(Value::as_str) else {
                continue;
            };
            let content = message.get("content").cloned().unwrap_or(Value::Null);
            closes.push(tool_close(id, &content, false));
        }
    }
    Ok((info, closes))
}

/// A response as one JSON document.
pub fn response(body: &[u8]) -> Result<(ResponseInfo, Vec<ToolOpen>), &'static str> {
    let json: Value = serde_json::from_slice(body).map_err(|_| "response_json")?;
    let mut text = Text::default();
    let mut opens = Vec::new();
    let mut finish = None;
    if let Some(choice) = json
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
    {
        finish = choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let message = choice.get("message");
        if let Some(content) = message.and_then(|m| m.get("content")) {
            text.push(&content_text(content));
        }
        if let Some(calls) = message
            .and_then(|m| m.get("tool_calls"))
            .and_then(Value::as_array)
        {
            for call in calls {
                opens.push(call_open(call));
            }
        }
    }
    let usage = json.get("usage");
    let info = ResponseInfo {
        model: json.get("model").and_then(Value::as_str).map(str::to_owned),
        stop_reason: finish,
        input_tokens: u64_of(usage.and_then(|u| u.get("prompt_tokens"))),
        output_tokens: u64_of(usage.and_then(|u| u.get("completion_tokens"))),
        cache_read_tokens: u64_of(
            usage
                .and_then(|u| u.get("prompt_tokens_details"))
                .and_then(|d| d.get("cached_tokens")),
        ),
        text_bytes: text.bytes(),
        text_b3: text.b3(),
        tool_uses: opens.len() as u32,
        degraded: None,
    };
    Ok((info, opens))
}

/// A whole `tool_calls[]` entry as a span's open.
fn call_open(call: &Value) -> ToolOpen {
    let id = call.get("id").and_then(Value::as_str).unwrap_or("");
    let function = call.get("function");
    let name = function
        .and_then(|f| f.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let arguments = function
        .and_then(|f| f.get("arguments"))
        .and_then(Value::as_str)
        .unwrap_or("{}");
    tool_open_text(id, name, arguments)
}

/// A tool call under way in a stream, by its `index`.
#[derive(Default)]
struct Call {
    id: String,
    name: String,
    arguments: String,
}

/// A streamed response, chunk by chunk.
#[derive(Default)]
pub struct Stream {
    info: ResponseInfo,
    text: Text,
    calls: BTreeMap<u64, Call>,
    degraded: Option<&'static str>,
    done: bool,
}

impl Stream {
    pub fn new() -> Stream {
        Stream::default()
    }

    /// One chunk: the tool calls it completes (at a finish reason, or at
    /// `[DONE]`).
    pub fn event(&mut self, event: &SseEvent) -> Vec<ToolOpen> {
        if event.data.trim() == "[DONE]" {
            self.done = true;
            return self.take_calls();
        }
        let Ok(data) = serde_json::from_str::<Value>(&event.data) else {
            if !event.data.is_empty() {
                self.degraded.get_or_insert("event_json");
            }
            return Vec::new();
        };
        if let Some(model) = data.get("model").and_then(Value::as_str) {
            self.info.model = Some(model.to_owned());
        }
        if let Some(usage) = data.get("usage").filter(|u| !u.is_null()) {
            self.info.input_tokens = u64_of(usage.get("prompt_tokens"));
            self.info.output_tokens = u64_of(usage.get("completion_tokens"));
            self.info.cache_read_tokens = u64_of(
                usage
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens")),
            );
        }
        let mut finished = false;
        if let Some(choice) = data
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        {
            let delta = choice.get("delta");
            if let Some(content) = delta.and_then(|d| d.get("content")).and_then(Value::as_str) {
                self.text.push(content);
            }
            if let Some(calls) = delta
                .and_then(|d| d.get("tool_calls"))
                .and_then(Value::as_array)
            {
                for call in calls {
                    let index = u64_of(call.get("index")).unwrap_or(0);
                    let entry = self.calls.entry(index).or_default();
                    if let Some(id) = call.get("id").and_then(Value::as_str) {
                        entry.id = id.to_owned();
                    }
                    let function = call.get("function");
                    if let Some(name) = function.and_then(|f| f.get("name")).and_then(Value::as_str)
                    {
                        entry.name.push_str(name);
                    }
                    if let Some(part) = function
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        entry.arguments.push_str(part);
                    }
                }
            }
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.info.stop_reason = Some(reason.to_owned());
                finished = true;
            }
        }
        if finished {
            self.take_calls()
        } else {
            Vec::new()
        }
    }

    fn take_calls(&mut self) -> Vec<ToolOpen> {
        let calls = std::mem::take(&mut self.calls);
        let mut opens = Vec::new();
        for (_, call) in calls {
            self.info.tool_uses += 1;
            opens.push(tool_open_text(&call.id, &call.name, &call.arguments));
        }
        opens
    }

    /// The stream ended: what it said, and the calls not yet reported.
    pub fn finish(mut self) -> (ResponseInfo, Vec<ToolOpen>) {
        let opens = self.take_calls();
        if !self.done && self.info.stop_reason.is_none() {
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

    fn chunk(data: &str) -> SseEvent {
        SseEvent {
            event: None,
            data: data.to_owned(),
            id: None,
        }
    }

    #[test]
    fn a_request_names_its_tools_and_closes_with_tool_messages() {
        let body = serde_json::json!({
            "model": "gpt-5",
            "stream": true,
            "max_completion_tokens": 2048,
            "tools": [{"type": "function", "function": {"name": "shell"}}],
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "ls"},
                {"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "shell", "arguments": "{\"cmd\":[\"ls\"]}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "a b"}
            ]
        });
        let (info, closes) = request(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.model.as_deref(), Some("gpt-5"));
        assert_eq!(info.messages, 4);
        assert_eq!(info.system_b3, b3(b"be terse"));
        assert_eq!(info.tools, ["shell"]);
        assert_eq!(info.max_tokens, Some(2048));
        assert_eq!(closes.len(), 1);
        assert_eq!(
            (
                closes[0].tool_use_id.as_str(),
                closes[0].result_summary.as_str()
            ),
            ("call_1", "a b")
        );
    }

    #[test]
    fn a_json_response_opens_its_tool_calls() {
        let body = serde_json::json!({
            "model": "gpt-5",
            "choices": [{"message": {"content": "On it.", "tool_calls": [
                {"id": "call_2", "type": "function", "function": {"name": "shell", "arguments": "{\"cmd\":[\"echo\",\"hi\"]}"}}
            ]}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 9, "prompt_tokens_details": {"cached_tokens": 40}}
        });
        let (info, opens) = response(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.stop_reason.as_deref(), Some("tool_calls"));
        assert_eq!(
            (
                info.input_tokens,
                info.output_tokens,
                info.cache_read_tokens
            ),
            (Some(50), Some(9), Some(40))
        );
        assert_eq!(info.text_b3, b3(b"On it."));
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].tool_name, "shell");
        assert_eq!(
            opens[0].args,
            Some(serde_json::json!({"cmd": ["echo", "hi"]}))
        );
    }

    #[test]
    fn streamed_tool_calls_accumulate_by_index_until_the_finish() {
        let mut stream = Stream::new();
        let mut opens = Vec::new();
        opens.extend(stream.event(&chunk(r#"{"model":"gpt-5","choices":[{"delta":{"role":"assistant","content":"On"},"finish_reason":null}]}"#)));
        opens.extend(stream.event(&chunk(
            r#"{"choices":[{"delta":{"content":" it."},"finish_reason":null}]}"#,
        )));
        opens.extend(stream.event(&chunk(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_2","type":"function","function":{"name":"shell","arguments":""}}]},"finish_reason":null}]}"#)));
        opens.extend(stream.event(&chunk(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\":[\"ec"}}]},"finish_reason":null}]}"#)));
        opens.extend(stream.event(&chunk(r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_3","type":"function","function":{"name":"shell","arguments":"{\"cmd\":[\"pwd\"]}"}}]},"finish_reason":null}]}"#)));
        opens.extend(stream.event(&chunk(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ho\",\"hi\"]}"}}]},"finish_reason":null}]}"#)));
        assert!(opens.is_empty());
        opens.extend(stream.event(&chunk(
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
        )));
        assert_eq!(opens.len(), 2);
        assert_eq!(opens[0].tool_use_id, "call_2");
        assert_eq!(
            opens[0].args,
            Some(serde_json::json!({"cmd": ["echo", "hi"]}))
        );
        assert_eq!(opens[1].tool_use_id, "call_3");
        opens.extend(stream.event(&chunk(
            r#"{"choices":[],"usage":{"prompt_tokens":50,"completion_tokens":9}}"#,
        )));
        opens.extend(stream.event(&chunk("[DONE]")));
        let (info, late) = stream.finish();
        assert!(late.is_empty());
        assert_eq!(info.stop_reason.as_deref(), Some("tool_calls"));
        assert_eq!(info.text_b3, b3(b"On it."));
        assert_eq!((info.input_tokens, info.output_tokens), (Some(50), Some(9)));
        assert_eq!(info.tool_uses, 2);
        assert_eq!(info.degraded, None);
    }

    #[test]
    fn a_stream_without_its_end_is_unfinished() {
        let mut stream = Stream::new();
        stream.event(&chunk(
            r#"{"choices":[{"delta":{"content":"half"},"finish_reason":null}]}"#,
        ));
        let (info, _) = stream.finish();
        assert_eq!(info.degraded, Some("stream_unfinished"));
        assert_eq!(info.text_bytes, 4);
    }
}
