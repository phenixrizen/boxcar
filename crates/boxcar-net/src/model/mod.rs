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

use boxcar_audit::Declared;

use crate::http::{Retained, Share};
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
    /// The arguments as the model sent them, and their size: for the
    /// reconciler's comparisons only, never recorded.
    pub raw: Option<(Declared, usize)>,
}

/// The most bytes of arguments a `tool.open` carries inline.
pub const ARGS_INLINE: usize = 8 * 1024;

/// `tool.open.args_summary` when the arguments are not kept (a policy
/// file's `[spans] keep_tool_args = false`): the summary is made from them.
pub const ARGS_NOT_KEPT: &str = "[arguments not kept: keep_tool_args = false]";
/// The most bytes of a tool call's id kept anywhere (records, spans):
/// past it the id becomes its first [`ID_PREFIX`] bytes and a hash of all
/// of it, the same for its open and its close, two ids never one.
pub const MAX_TOOL_ID: usize = 256;
/// What a too-long id keeps of itself before its hash.
pub const ID_PREFIX: usize = 128;
/// The most bytes of a tool's name kept anywhere.
pub const MAX_TOOL_NAME: usize = 1024;

/// `text` cut to at most `max` bytes at a character boundary, nothing
/// added: the same text always cuts the same way.
/// The most bytes of a model's name or a stop reason kept.
pub const MAX_LABEL: usize = 256;

/// A short label from a reply or request (a model's name, a stop reason),
/// cut at [`MAX_LABEL`].
pub fn label(text: &str) -> String {
    capped(text, MAX_LABEL)
}

/// A tool call's id as it is kept: itself, or past [`MAX_TOOL_ID`] its
/// first [`ID_PREFIX`] bytes, `~`, and blake3 of the whole id.
pub fn tool_id(id: &str) -> String {
    if id.len() <= MAX_TOOL_ID {
        return id.to_owned();
    }
    format!(
        "{}~b3:{}",
        capped(id, ID_PREFIX),
        blake3::hash(id.as_bytes()).to_hex()
    )
}

fn capped(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

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

/// The most bytes a streamed response's tool calls may gather (names and
/// arguments, as they come, whether or not the calls finished): past it
/// the response is `degraded: "stream_budget"` and no call grows further.
pub const STREAM_CALL_BYTES: usize = 16 * 1024 * 1024;
/// The most tool calls a streamed response may have under way at once.
pub const STREAM_CALLS: usize = 256;

/// What a streamed response's tool calls have gathered so far, and their
/// part of the observer's retained bytes.
#[derive(Default)]
pub struct CallBudget {
    bytes: usize,
    share: Share,
}

impl CallBudget {
    /// A budget whose bytes come out of the observer's `retained` too.
    pub fn with_retained(retained: Retained) -> CallBudget {
        CallBudget {
            bytes: 0,
            share: Share::new(retained),
        }
    }

    /// Whether `n` more bytes fit, in the response's budget and the
    /// observer's; when not, `degraded` says so.
    pub fn admit(&mut self, n: usize, degraded: &mut Option<&'static str>) -> bool {
        match self.bytes.checked_add(n) {
            Some(total) if total <= STREAM_CALL_BYTES => {
                if !self.share.grow(n) {
                    degraded.get_or_insert("observe_budget");
                    return false;
                }
                self.bytes = total;
                true
            }
            _ => {
                degraded.get_or_insert("stream_budget");
                false
            }
        }
    }

    /// Whether one more call fits beside the `open` ones; when not,
    /// `degraded` says so.
    pub fn admit_call(open: usize, degraded: &mut Option<&'static str>) -> bool {
        if open < STREAM_CALLS {
            return true;
        }
        degraded.get_or_insert("stream_budget");
        false
    }
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
    let mut inline = args.clone();
    boxcar_proto::redact::scrub_deep(&mut inline);
    ToolOpen {
        tool_use_id: tool_id(id),
        tool_name: capped(name, MAX_TOOL_NAME),
        args_b3: b3(json.as_bytes()),
        args_summary: summarize(args),
        args: (json.len() <= ARGS_INLINE).then_some(inline),
        raw: Some((Declared::Json(args.clone()), json.len())),
    }
}

/// A tool call whose arguments were not kept whole (a piece of them found
/// no room): its id and name only. Arguments with a piece missing are not
/// the arguments, and what is left of them is not scrubbed reliably.
pub fn tool_open_lost(id: &str, name: &str) -> ToolOpen {
    ToolOpen {
        tool_use_id: tool_id(id),
        tool_name: capped(name, MAX_TOOL_NAME),
        args_b3: None,
        args_summary: "[arguments not kept whole]".to_owned(),
        args: None,
        raw: None,
    }
}

/// A tool call whose arguments came as JSON text (OpenAI's).
pub fn tool_open_text(id: &str, name: &str, arguments: &str) -> ToolOpen {
    match serde_json::from_str::<Value>(arguments) {
        Ok(value) => tool_open(id, name, &value),
        Err(_) => ToolOpen {
            tool_use_id: tool_id(id),
            tool_name: capped(name, MAX_TOOL_NAME),
            args_b3: b3(arguments.as_bytes()),
            args_summary: summary::cut(&summary::scrubbed(arguments), SUMMARY_LIMIT),
            args: None,
            raw: Some((Declared::Text(arguments.to_owned()), arguments.len())),
        },
    }
}

/// A tool result, from its content (text, or blocks) and whether the
/// agent called it an error.
pub fn tool_close(id: &str, content: &Value, is_error: bool) -> ToolClose {
    let text = content_text(content);
    ToolClose {
        tool_use_id: tool_id(id),
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
    #[test]
    fn ids_and_names_are_capped_alike_for_open_and_close() {
        let id = "i".repeat(MAX_TOOL_ID * 4);
        let name = "n".repeat(MAX_TOOL_NAME * 4);
        let open = tool_open(&id, &name, &serde_json::json!({}));
        let close = tool_close(&id, &serde_json::json!("done"), false);
        assert!(open.tool_use_id.len() <= MAX_TOOL_ID);
        assert_eq!(open.tool_name.len(), MAX_TOOL_NAME);
        assert_eq!(open.tool_use_id, close.tool_use_id);
        // Two long ids that share their start stay two.
        let other = format!("{}j", "i".repeat(MAX_TOOL_ID * 4 - 1));
        assert_ne!(tool_id(&id), tool_id(&other));
        assert_eq!(tool_id("short"), "short");
        assert_eq!(capped("ééé", 3), "é");
    }

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
