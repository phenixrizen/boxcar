// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The Anthropic Messages API: `POST /v1/messages`.
//!
//! A request's `messages` are counted, its `system` hashed, its `tools`
//! named; the `tool_result` blocks in its last user message close the
//! spans their `tool_use_id`s opened. A response, as one JSON document or
//! as an event stream (`message_start`, `content_block_start`,
//! `content_block_delta`, `content_block_stop`, `message_delta`,
//! `message_stop`), gives the model, the stop reason, the token counts,
//! the text (hashed) and the `tool_use` blocks, each a span's open once
//! its input is whole.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::http::Retained;

use super::{
    b3, content_text, tool_close, tool_open, tool_open_lost, tool_open_text, u64_of, CallBudget,
    RequestInfo, ResponseInfo, Text, ToolClose, ToolOpen,
};
use crate::http::SseEvent;

/// What a request said, and the tool results it carried.
pub fn request(body: &[u8]) -> Result<(RequestInfo, Vec<ToolClose>), &'static str> {
    let json: Value = serde_json::from_slice(body).map_err(|_| "request_json")?;
    let messages = json.get("messages").and_then(Value::as_array);
    let mut info = RequestInfo {
        model: json.get("model").and_then(Value::as_str).map(str::to_owned),
        stream: json.get("stream").and_then(Value::as_bool).unwrap_or(false),
        messages: messages.map_or(0, |m| m.len() as u32),
        system_b3: json
            .get("system")
            .and_then(|s| b3(content_text(s).as_bytes())),
        tools: Vec::new(),
        max_tokens: u64_of(json.get("max_tokens")),
    };
    if let Some(tools) = json.get("tools").and_then(Value::as_array) {
        info.tools = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .take(64)
            .map(str::to_owned)
            .collect();
    }
    // The tool results are in the last message, which the agent just
    // added: a result for a call the model made in its last reply.
    let mut closes = Vec::new();
    if let Some(last) = messages.and_then(|m| m.last()) {
        if let Some(blocks) = last.get("content").and_then(Value::as_array) {
            for block in blocks {
                if block.get("type").and_then(Value::as_str) != Some("tool_result") {
                    continue;
                }
                let Some(id) = block.get("tool_use_id").and_then(Value::as_str) else {
                    continue;
                };
                let content = block.get("content").cloned().unwrap_or(Value::Null);
                let is_error = block
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                closes.push(tool_close(id, &content, is_error));
            }
        }
    }
    Ok((info, closes))
}

/// A response as one JSON document.
pub fn response(body: &[u8]) -> Result<(ResponseInfo, Vec<ToolOpen>), &'static str> {
    let json: Value = serde_json::from_slice(body).map_err(|_| "response_json")?;
    let mut text = Text::default();
    let mut opens = Vec::new();
    if let Some(blocks) = json.get("content").and_then(Value::as_array) {
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        text.push(t);
                    }
                }
                Some("tool_use") => {
                    let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    let input = block.get("input").cloned().unwrap_or(Value::Null);
                    opens.push(tool_open(id, name, &input));
                }
                _ => {}
            }
        }
    }
    let usage = json.get("usage");
    let info = ResponseInfo {
        model: json.get("model").and_then(Value::as_str).map(str::to_owned),
        stop_reason: json
            .get("stop_reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        input_tokens: u64_of(usage.and_then(|u| u.get("input_tokens"))),
        output_tokens: u64_of(usage.and_then(|u| u.get("output_tokens"))),
        cache_read_tokens: u64_of(usage.and_then(|u| u.get("cache_read_input_tokens"))),
        text_bytes: text.bytes(),
        text_b3: text.b3(),
        tool_uses: opens.len() as u32,
        degraded: None,
    };
    Ok((info, opens))
}

/// A `tool_use` block under way in a stream.
#[derive(Default)]
struct Block {
    id: String,
    name: String,
    json: String,
    /// A piece of the arguments found no room: they are lost for good.
    lost: bool,
}

/// A streamed response, event by event.
#[derive(Default)]
pub struct Stream {
    info: ResponseInfo,
    text: Text,
    blocks: BTreeMap<u64, Block>,
    budget: CallBudget,
    degraded: Option<&'static str>,
}

impl Stream {
    pub fn new() -> Stream {
        Stream::default()
    }

    /// The stream's tool calls take their bytes from the observer's
    /// `retained` budget too.
    pub fn with_retained(mut self, retained: Retained) -> Stream {
        self.budget = CallBudget::with_retained(retained);
        self
    }

    /// One event: the `tool_use` blocks it completes.
    pub fn event(&mut self, event: &SseEvent) -> Vec<ToolOpen> {
        let mut opens = Vec::new();
        let Ok(data) = serde_json::from_str::<Value>(&event.data) else {
            // A ping or a comment carries no JSON; anything else that does
            // not read is noted.
            if !event.data.is_empty() {
                self.degraded.get_or_insert("event_json");
            }
            return opens;
        };
        let kind = event
            .event
            .as_deref()
            .or_else(|| data.get("type").and_then(Value::as_str))
            .unwrap_or("");
        match kind {
            "message_start" => {
                let message = data.get("message");
                self.info.model = message
                    .and_then(|m| m.get("model"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let usage = message.and_then(|m| m.get("usage"));
                self.info.input_tokens = u64_of(usage.and_then(|u| u.get("input_tokens")));
                self.info.cache_read_tokens =
                    u64_of(usage.and_then(|u| u.get("cache_read_input_tokens")));
                if let Some(output) = u64_of(usage.and_then(|u| u.get("output_tokens"))) {
                    self.info.output_tokens = Some(output);
                }
            }
            "content_block_start" => {
                let index = u64_of(data.get("index")).unwrap_or(0);
                let block = data.get("content_block");
                let text = |key: &str| {
                    block
                        .and_then(|b| b.get(key))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                };
                let (id, name) = (text("id"), text("name"));
                if text("type") == "tool_use"
                    && (self.blocks.contains_key(&index)
                        || CallBudget::admit_call(self.blocks.len(), &mut self.degraded))
                    && self.budget.admit(id.len() + name.len(), &mut self.degraded)
                {
                    self.blocks.insert(
                        index,
                        Block {
                            id: id.to_owned(),
                            name: name.to_owned(),
                            json: String::new(),
                            lost: false,
                        },
                    );
                }
            }
            "content_block_delta" => {
                let index = u64_of(data.get("index")).unwrap_or(0);
                let delta = data.get("delta");
                match delta.and_then(|d| d.get("type")).and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(t) = delta.and_then(|d| d.get("text")).and_then(Value::as_str) {
                            self.text.push(t);
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(block) = self.blocks.get_mut(&index) {
                            if let Some(part) = delta
                                .and_then(|d| d.get("partial_json"))
                                .and_then(Value::as_str)
                            {
                                if block.lost {
                                    // Nothing more: the arguments are gone.
                                } else if self.budget.admit(part.len(), &mut self.degraded) {
                                    block.json.push_str(part);
                                } else {
                                    block.lost = true;
                                    block.json = String::new();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let index = u64_of(data.get("index")).unwrap_or(0);
                if let Some(block) = self.blocks.remove(&index) {
                    self.info.tool_uses += 1;
                    opens.push(block_open(&block));
                }
            }
            "message_delta" => {
                if let Some(reason) = data
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.info.stop_reason = Some(reason.to_owned());
                }
                if let Some(output) = u64_of(data.get("usage").and_then(|u| u.get("output_tokens")))
                {
                    self.info.output_tokens = Some(output);
                }
            }
            "error" => {
                self.degraded.get_or_insert("stream_error");
            }
            _ => {}
        }
        opens
    }

    /// The stream ended: what it said, and the tool uses it never closed.
    pub fn finish(mut self) -> (ResponseInfo, Vec<ToolOpen>) {
        let mut opens = Vec::new();
        for (_, block) in std::mem::take(&mut self.blocks) {
            self.degraded.get_or_insert("block_unfinished");
            self.info.tool_uses += 1;
            opens.push(block_open(&block));
        }
        self.info.text_bytes = self.text.bytes();
        self.info.text_b3 = self.text.b3();
        self.info.degraded = self.degraded;
        (self.info, opens)
    }
}

/// A `tool_use` block as a span's open: its input as JSON when it is
/// JSON (an empty input is `{}`), else as text, not inlined.
fn block_open(block: &Block) -> ToolOpen {
    if block.lost {
        return tool_open_lost(&block.id, &block.name);
    }
    if block.json.trim().is_empty() {
        return tool_open(&block.id, &block.name, &Value::Object(Default::default()));
    }
    tool_open_text(&block.id, &block.name, &block.json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(event: &str, data: &str) -> SseEvent {
        SseEvent {
            event: Some(event.to_owned()),
            data: data.to_owned(),
            id: None,
        }
    }

    #[test]
    fn a_request_is_counted_hashed_and_its_tool_results_close_spans() {
        let body = serde_json::json!({
            "model": "claude-fable-5-1",
            "max_tokens": 4096,
            "stream": true,
            "system": [{"type": "text", "text": "You are boxcar's agent."}],
            "tools": [{"name": "Bash"}, {"name": "Write"}],
            "messages": [
                {"role": "user", "content": "run ls"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls"}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "a\nb"}]},
                    {"type": "tool_result", "tool_use_id": "toolu_2", "content": "no such file", "is_error": true}
                ]}
            ]
        });
        let (info, closes) = request(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.model.as_deref(), Some("claude-fable-5-1"));
        assert!(info.stream);
        assert_eq!(info.messages, 3);
        assert_eq!(info.system_b3, b3(b"You are boxcar's agent."));
        assert_eq!(info.tools, ["Bash", "Write"]);
        assert_eq!(info.max_tokens, Some(4096));
        assert_eq!(closes.len(), 2);
        assert_eq!(
            (
                closes[0].tool_use_id.as_str(),
                closes[0].status.as_str(),
                closes[0].result_summary.as_str()
            ),
            ("toolu_1", "ok", "a\nb")
        );
        assert_eq!(
            (closes[1].tool_use_id.as_str(), closes[1].status.as_str()),
            ("toolu_2", "error")
        );
        assert!(request(b"not json").is_err());
    }

    #[test]
    fn a_json_response_gives_usage_text_and_tool_uses() {
        let body = serde_json::json!({
            "model": "claude-fable-5-1",
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 120, "output_tokens": 30, "cache_read_input_tokens": 100},
            "content": [
                {"type": "text", "text": "Running it."},
                {"type": "tool_use", "id": "toolu_9", "name": "Bash", "input": {"command": "echo hi"}}
            ]
        });
        let (info, opens) = response(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(
            (
                info.input_tokens,
                info.output_tokens,
                info.cache_read_tokens
            ),
            (Some(120), Some(30), Some(100))
        );
        assert_eq!(info.text_bytes, 11);
        assert_eq!(info.text_b3, b3(b"Running it."));
        assert_eq!(info.tool_uses, 1);
        assert_eq!(opens[0].tool_use_id, "toolu_9");
        assert_eq!(
            opens[0].args,
            Some(serde_json::json!({"command": "echo hi"}))
        );
    }

    /// The streamed form: text deltas hash to the same text, the tool
    /// use's input is whole at its block's stop, usage and stop reason
    /// come from the deltas.
    #[test]
    fn a_streamed_response_opens_tool_uses_at_their_block_stop() {
        let mut stream = Stream::new();
        let mut opens = Vec::new();
        opens.extend(stream.event(&sse("message_start", r#"{"type":"message_start","message":{"model":"claude-fable-5-1","usage":{"input_tokens":120,"output_tokens":1,"cache_read_input_tokens":100}}}"#)));
        opens.extend(stream.event(&sse(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        )));
        opens.extend(stream.event(&sse("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Running"}}"#)));
        opens.extend(stream.event(&sse("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" it."}}"#)));
        opens.extend(stream.event(&sse(
            "content_block_stop",
            r#"{"type":"content_block_stop","index":0}"#,
        )));
        opens.extend(stream.event(&sse("content_block_start", r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_9","name":"Bash","input":{}}}"#)));
        assert!(opens.is_empty());
        opens.extend(stream.event(&sse("content_block_delta", r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"ec"}}"#)));
        opens.extend(stream.event(&sse("content_block_delta", r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ho hi\"}"}}"#)));
        assert!(opens.is_empty());
        opens.extend(stream.event(&sse(
            "content_block_stop",
            r#"{"type":"content_block_stop","index":1}"#,
        )));
        assert_eq!(opens.len(), 1);
        assert_eq!(
            opens[0].args,
            Some(serde_json::json!({"command": "echo hi"}))
        );
        opens.extend(stream.event(&sse("ping", r#"{"type":"ping"}"#)));
        opens.extend(stream.event(&sse("message_delta", r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":30}}"#)));
        opens.extend(stream.event(&sse("message_stop", r#"{"type":"message_stop"}"#)));
        // Something new the parser does not know is passed over.
        opens.extend(stream.event(&sse(
            "thinking_summary",
            r#"{"type":"thinking_summary","text":"..."}"#,
        )));
        let (info, late) = stream.finish();
        assert!(late.is_empty());
        assert_eq!(info.model.as_deref(), Some("claude-fable-5-1"));
        assert_eq!(info.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(
            (
                info.input_tokens,
                info.output_tokens,
                info.cache_read_tokens
            ),
            (Some(120), Some(30), Some(100))
        );
        assert_eq!(info.text_b3, b3(b"Running it."));
        assert_eq!(info.tool_uses, 1);
        assert_eq!(info.degraded, None);
    }

    #[test]
    fn a_stream_cut_short_still_opens_what_it_had_and_says_so() {
        let mut stream = Stream::new();
        stream.event(&sse("content_block_start", r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Write","input":{}}}"#));
        stream.event(&sse("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"/tmp/x\""}}"#));
        stream.event(&sse(
            "error",
            r#"{"type":"error","error":{"type":"overloaded_error"}}"#,
        ));
        let (info, opens) = stream.finish();
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].args, None, "the input never became JSON");
        assert_eq!(info.degraded, Some("stream_error"));
    }

    /// Calls that never finish, and arguments that never stop, are held
    /// only up to the stream's budget.
    #[test]
    fn a_streams_calls_are_bounded() {
        use crate::model::{STREAM_CALLS, STREAM_CALL_BYTES};
        let mut stream = Stream::new();
        for index in 0..STREAM_CALLS + 10 {
            stream.event(&sse(
                "content_block_start",
                &format!(r#"{{"type":"content_block_start","index":{index},"content_block":{{"type":"tool_use","id":"t{index}","name":"Bash","input":{{}}}}}}"#),
            ));
        }
        assert_eq!(stream.blocks.len(), STREAM_CALLS);
        let part = "x".repeat(1024 * 1024);
        let delta = format!(
            r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"input_json_delta","partial_json":"{part}"}}}}"#
        );
        for _ in 0..(STREAM_CALL_BYTES / part.len() + 4) {
            stream.event(&sse("content_block_delta", &delta));
        }
        assert!(stream.blocks[&0].json.len() <= STREAM_CALL_BYTES);
        let (info, _) = stream.finish();
        assert_eq!(info.degraded, Some("stream_budget"));
    }

    /// A call's id and name count against the stream's budget too.
    #[test]
    fn call_names_count_against_the_budget() {
        use crate::model::STREAM_CALL_BYTES;
        let mut stream = Stream::new();
        let name = "n".repeat(4 * 1024 * 1024);
        for index in 0..8 {
            stream.event(&sse(
                "content_block_start",
                &format!(r#"{{"type":"content_block_start","index":{index},"content_block":{{"type":"tool_use","id":"t{index}","name":"{name}","input":{{}}}}}}"#),
            ));
        }
        let held: usize = stream
            .blocks
            .values()
            .map(|b| b.name.len() + b.id.len())
            .sum();
        assert!(held <= STREAM_CALL_BYTES, "{held}");
        let (info, _) = stream.finish();
        assert_eq!(info.degraded, Some("stream_budget"));
    }

    /// Arguments that lost a piece for want of room are lost whole: later
    /// pieces are not kept, and the call carries no arguments.
    #[test]
    fn a_call_that_lost_a_piece_keeps_no_arguments() {
        use crate::http::{Retained, Share};
        // Its id and name take 6 bytes; another holder takes 25, leaving 9.
        let retained = Retained::with_limit(40);
        let mut other = Share::new(retained.clone());
        let mut stream = Stream::new().with_retained(retained);
        stream.event(&sse(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}"#,
        ));
        let delta = |part: &str| {
            serde_json::json!({
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": part}
            })
            .to_string()
        };
        assert!(other.grow(25));
        stream.event(&sse("content_block_delta", &delta("{\"password\":\"")));
        other.clear();
        stream.event(&sse("content_block_delta", &delta("demo-pass\"}")));
        let opens = stream.event(&sse(
            "content_block_stop",
            r#"{"type":"content_block_stop","index":0}"#,
        ));
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].args, None);
        assert!(
            !opens[0].args_summary.contains("demo-pass"),
            "{}",
            opens[0].args_summary
        );
        assert_eq!(opens[0].raw, None);
    }
}
