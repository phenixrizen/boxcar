// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The summaries and hashes `llm.*` and `tool.*` records carry.

use serde_json::Value;

/// The most bytes a summary holds.
pub const SUMMARY_LIMIT: usize = 512;

/// `b3:` and blake3 of `bytes`; `None` for none.
pub fn b3(bytes: &[u8]) -> Option<String> {
    (!bytes.is_empty()).then(|| format!("b3:{}", blake3::hash(bytes).to_hex()))
}

/// `value` as compact JSON, scrubbed of what looks like a credential and
/// cut to [`SUMMARY_LIMIT`].
pub fn summarize(value: &Value) -> String {
    let mut value = value.clone();
    boxcar_proto::redact::scrub(&mut value);
    let json = match value {
        Value::String(text) => text,
        other => other.to_string(),
    };
    cut(&json, SUMMARY_LIMIT)
}

/// `text` with credential-looking tokens replaced, through the protocol
/// crate's scrub.
pub fn scrubbed(text: &str) -> String {
    let mut value = Value::String(text.to_owned());
    boxcar_proto::redact::scrub(&mut value);
    match value {
        Value::String(text) => text,
        other => other.to_string(),
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
    use super::*;

    #[test]
    fn summaries_are_bounded_and_hashes_are_blake3() {
        let value = serde_json::json!({"k": "v".repeat(1000)});
        let summary = summarize(&value);
        assert!(summary.len() <= SUMMARY_LIMIT);
        assert!(summary.ends_with('…'));
        assert_eq!(summarize(&serde_json::json!("plain")), "plain");
        assert_eq!(b3(b""), None);
        assert_eq!(
            b3(b"x").unwrap(),
            format!("b3:{}", blake3::hash(b"x").to_hex())
        );
    }
}
