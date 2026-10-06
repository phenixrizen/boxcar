// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The model APIs the gate knows, read from the exchanges the observer
//! keeps: what the agent asked (`llm.request`), what it was told
//! (`llm.response`), the tool calls the model made (`tool.open`) and the
//! results the agent sent back (`tool.close`).
//!
//! A parser is chosen by the request's path ([`Provider::for_request`]).
//! Each reads its provider's JSON tolerantly, as `serde_json::Value`:
//! unknown fields and events are passed over, and a body that does not
//! read degrades the exchange, never the flow. Bodies larger than the
//! observer keeps are not read at all (`body_truncated`).
//!
//! - [`anthropic`]: the Messages API, as JSON or as an event stream.
//! - [`openai_chat`]: Chat Completions, as JSON or as an event stream.
//! - [`openai_responses`]: Responses, as JSON, as an event stream, or over
//!   WebSocket.
//! - [`summary`]: the 512-byte summaries and the hashes records carry.

pub mod anthropic;
pub mod openai_chat;
pub mod openai_responses;
pub mod summary;
pub mod track;

use serde_json::Value;

pub use summary::{b3, summarize, SUMMARY_LIMIT};
pub use track::Tracker;

/// Which API an exchange speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
    OpenAiChat,
    OpenAiResponses,
}

impl Provider {
    /// As `llm.*` records name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAiChat => "openai_chat",
            Provider::OpenAiResponses => "openai_responses",
        }
    }

    /// The provider a request's `path` names, whatever the host: the APIs
    /// keep their paths behind gateways and proxies.
    pub fn for_request(path: Option<&str>) -> Option<Provider> {
        let path = path?.split('?').next()?.trim_end_matches('/');
        if path.ends_with("/v1/messages") || path.ends_with("/messages") && path.contains("/v1") {
            Some(Provider::Anthropic)
        } else if path.ends_with("/chat/completions") {
            Some(Provider::OpenAiChat)
        } else if path.ends_with("/responses") {
            Some(Provider::OpenAiResponses)
        } else {
            None
        }
    }
}

/// What a request said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestInfo {
    pub model: Option<String>,
    pub stream: bool,
    pub messages: u32,
    pub system_b3: Option<String>,
    pub tools: Vec<String>,
    pub max_tokens: Option<u64>,
}

/// A tool result the agent sent back: the span's close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolClose {
    pub tool_use_id: String,
    /// `ok`, or `error` when the agent said so.
    pub status: String,
    pub result_bytes: u64,
    pub result_b3: Option<String>,
    pub result_summary: String,
}

/// A tool call the model made: the span's open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOpen {
    pub tool_use_id: String,
    pub tool_name: String,
    pub args_b3: Option<String>,
    pub args_summary: String,
    /// The arguments as JSON, when at most [`ARGS_INLINE`] bytes.
    pub args: Option<Value>,
}

/// The most bytes of arguments a `tool.open` carries inline.
pub const ARGS_INLINE: usize = 8 * 1024;

/// What a response said, once it ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseInfo {
    pub model: Option<String>,
    pub stop_reason: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub text_bytes: u64,
    pub text_b3: Option<String>,
    pub tool_uses: u32,
    pub degraded: Option<&'static str>,
}

/// The text a response carried, hashed whole as it came.
#[derive(Default)]
pub struct Text {
    hasher: blake3::Hasher,
    bytes: u64,
}

impl Text {
    pub fn push(&mut self, text: &str) {
        if !text.is_empty() {
            self.hasher.update(text.as_bytes());
            self.bytes = self.bytes.saturating_add(text.len() as u64);
        }
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn b3(&self) -> Option<String> {
        (self.bytes > 0).then(|| format!("b3:{}", self.hasher.finalize().to_hex()))
    }
}

/// A tool call's arguments, as a `tool.open` carries them.
pub fn tool_open(id: &str, name: &str, args: &Value) -> ToolOpen {
    let json = serde_json::to_string(args).unwrap_or_default();
    ToolOpen {
        tool_use_id: id.to_owned(),
        tool_name: name.to_owned(),
        args_b3: b3(json.as_bytes()),
        args_summary: summarize(args),
        args: (json.len() <= ARGS_INLINE).then(|| args.clone()),
    }
}

/// A tool call whose arguments came as JSON text (OpenAI's).
pub fn tool_open_text(id: &str, name: &str, arguments: &str) -> ToolOpen {
    match serde_json::from_str::<Value>(arguments) {
        Ok(value) => tool_open(id, name, &value),
        Err(_) => ToolOpen {
            tool_use_id: id.to_owned(),
            tool_name: name.to_owned(),
            args_b3: b3(arguments.as_bytes()),
            args_summary: summary::cut(arguments, SUMMARY_LIMIT),
            args: None,
        },
    }
}

/// A tool result, from its content (text, or blocks) and whether the
/// agent called it an error.
pub fn tool_close(id: &str, content: &Value, is_error: bool) -> ToolClose {
    let text = content_text(content);
    ToolClose {
        tool_use_id: id.to_owned(),
        status: if is_error { "error" } else { "ok" }.to_owned(),
        result_bytes: text.len() as u64,
        result_b3: b3(text.as_bytes()),
        result_summary: summary::cut(&summary::scrubbed(&text), SUMMARY_LIMIT),
    }
}

/// The text of a content value: a string as it is, blocks' `text` joined
/// with newlines, anything else as JSON.
pub fn content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => {
            let mut text = String::new();
            for block in blocks {
                let piece = match block.get("text").and_then(Value::as_str) {
                    Some(t) => t.to_owned(),
                    None => match block.get("type").and_then(Value::as_str) {
                        Some(kind) => format!("[{kind}]"),
                        None => block.to_string(),
                    },
                };
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&piece);
            }
            text
        }
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `value` as a u64, from a number or a numeric string.
pub fn u64_of(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_are_chosen_by_path() {
        assert_eq!(
            Provider::for_request(Some("/v1/messages")),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            Provider::for_request(Some("/v1/messages?beta=true")),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            Provider::for_request(Some("/gateway/v1/messages/")),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            Provider::for_request(Some("/v1/chat/completions")),
            Some(Provider::OpenAiChat)
        );
        assert_eq!(
            Provider::for_request(Some("/v1/responses")),
            Some(Provider::OpenAiResponses)
        );
        assert_eq!(
            Provider::for_request(Some("/backend-api/codex/responses")),
            Some(Provider::OpenAiResponses)
        );
        assert_eq!(Provider::for_request(Some("/v1/models")), None);
        assert_eq!(Provider::for_request(None), None);
    }

    #[test]
    fn tool_opens_and_closes_hash_summarize_and_inline_within_the_limit() {
        let args = serde_json::json!({"command": "ls -la", "timeout": 1000});
        let open = tool_open("toolu_1", "Bash", &args);
        assert_eq!(open.tool_name, "Bash");
        assert!(open.args_b3.as_deref().unwrap().starts_with("b3:"));
        assert_eq!(open.args, Some(args));
        assert!(open.args_summary.contains("ls -la"));
        let big = serde_json::json!({"content": "x".repeat(ARGS_INLINE)});
        let open = tool_open("toolu_2", "Write", &big);
        assert_eq!(open.args, None);
        assert!(open.args_summary.len() <= SUMMARY_LIMIT + 3);
        let open = tool_open_text("call_1", "shell", "{\"cmd\":[\"ls\"]}");
        assert_eq!(open.args, Some(serde_json::json!({"cmd": ["ls"]})));
        let open = tool_open_text("call_2", "shell", "not json");
        assert_eq!(open.args, None);
        assert_eq!(open.args_summary, "not json");
        let close = tool_close(
            "toolu_1",
            &serde_json::json!([{"type": "text", "text": "total 0"}]),
            false,
        );
        assert_eq!((close.status.as_str(), close.result_bytes), ("ok", 7));
        assert_eq!(close.result_summary, "total 0");
        let close = tool_close("toolu_1", &serde_json::json!("boom"), true);
        assert_eq!(close.status, "error");
    }
}
