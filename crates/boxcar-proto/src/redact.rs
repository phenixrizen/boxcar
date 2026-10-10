// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Redaction of secrets before a value reaches the audit log.

use serde_json::Value;

/// What a redacted value is replaced with.
const REDACTED: &str = "[redacted]";

/// [`REDACTED`] as characters, to tell a value already redacted.
const REDACTED_CHARS: [char; 10] = ['[', 'r', 'e', 'd', 'a', 'c', 't', 'e', 'd', ']'];

/// Stems that mark an object key as holding a secret. A key matches when its
/// lowercase form contains one of these anywhere, so `access_token`,
/// `client_secret`, `X-Api-Key`, `Authorization`, `Proxy-Authorization` and
/// `Set-Cookie` all match.
const SECRET_STEMS: [&str; 9] = [
    "api_key",
    "api-key",
    "apikey",
    "authorization",
    "secret",
    "token",
    "bearer",
    "password",
    "cookie",
];

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SECRET_STEMS.iter().any(|stem| lower.contains(stem))
}

/// Replaces the value of every secret-looking key in `v` with `"[redacted]"`,
/// however deeply the key is nested in objects and arrays.
///
/// A key looks like a secret when its lowercase form contains `api_key`,
/// `api-key`, `apikey`, `authorization`, `secret`, `token`, `bearer`,
/// `password` or `cookie`. This is substring matching on purpose, so it
/// over-matches: `tokenizer`, `max_tokens` and `secrets_count` are redacted
/// along with `access_token`. For an audit log that is the right trade-off.
/// The log is append-only and hash-chained, so a secret that slips through can
/// never be taken back out, while a harmless value that gets redacted only
/// costs some detail.
///
/// The whole value under a matching key is replaced, whatever its shape.
/// Keys are the only thing inspected: a secret inside a string value is not
/// found here. [`scrub_deep`] adds [`scrub_text`] on every string, for
/// values whose strings are free text (tool arguments, say).
pub fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_secret_key(key) {
                    *child = Value::String(REDACTED.to_owned());
                } else {
                    scrub(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// [`scrub`], then [`scrub_text`] on every string left, however deeply it
/// is nested.
pub fn scrub_deep(v: &mut Value) {
    scrub(v);
    texts(v);
}

fn texts(v: &mut Value) {
    match v {
        Value::String(text) => {
            let clean = scrub_text(text);
            if clean != *text {
                *text = clean;
            }
        }
        Value::Object(map) => map.values_mut().for_each(texts),
        Value::Array(items) => items.iter_mut().for_each(texts),
        _ => {}
    }
}

/// Query parameter names that carry a credential without a secret stem in
/// them (OAuth's `code`, signed URLs' `sig`, …), lowercase.
const SECRET_PARAMS: [&str; 10] = [
    "code",
    "state",
    "sig",
    "signature",
    "key",
    "auth",
    "session",
    "sid",
    "pass",
    "pwd",
];

/// The longest query value kept as it is.
const QUERY_VALUE_KEPT: usize = 16;

/// A request target (`/path?query`, or an absolute URL) as a record may
/// keep it: the path through [`scrub_text`], every query parameter's name,
/// and only the values that are short, plain and not under a secret-looking
/// name. The fragment is dropped.
pub fn scrub_target(target: &str) -> String {
    let target = target.split('#').next().unwrap_or("");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let mut out = scrub_text(path);
    let Some(query) = query else {
        return out;
    };
    out.push('?');
    for (n, pair) in query.split('&').enumerate() {
        if n > 0 {
            out.push('&');
        }
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (pair, None),
        };
        let lower = name.to_ascii_lowercase();
        let secret_name =
            is_secret_key(&lower) || SECRET_PARAMS.contains(&lower.as_str()) || name.contains('%');
        out.push_str(&scrub_text(name));
        let Some(value) = value else {
            continue;
        };
        out.push('=');
        let plain = value.len() <= QUERY_VALUE_KEPT
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ','));
        if value.is_empty() || (plain && !secret_name) {
            out.push_str(value);
        } else {
            out.push_str(REDACTED);
        }
    }
    out
}

/// Prefixes that mark a word as a credential whatever surrounds it.
const TOKEN_PREFIXES: [&str; 20] = [
    "sk-",
    "sk_",
    "pk_",
    "rk_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "AIza",
    "eyJ",
    "npm_",
];

/// The fewest characters a word must have past a known prefix to be taken
/// for a credential.
const PREFIX_TAIL: usize = 8;

/// The length from which an unbroken run of letters and digits (with `-`,
/// `_`, `+` and `=`) holding both is taken for a credential.
const OPAQUE_RUN: usize = 32;

/// `text` with what looks like a credential replaced by `"[redacted]"`:
///
/// - the value after a secret-looking key and `=` or `:` (`token=…`,
///   `"api_key": "…"`, `Authorization: …` to the end of the line or quote),
///   and the word after a secret-looking `--flag`;
/// - the word after `Bearer` or `Basic`;
/// - the password in a URL's `user:password@`;
/// - a word starting with a known token prefix (`sk-`, `ghp_`, `AKIA`,
///   `eyJ`, …);
/// - a run of 32 or more letters and digits holding both.
///
/// Like [`scrub`] it over-matches on purpose: long hashes and identifiers
/// are redacted along with keys. The same text always scrubs the same way,
/// so two scrubbed texts still compare.
pub fn scrub_text(text: &str) -> String {
    let text = key_values(text);
    let text = userinfo(&text);
    words(&text)
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | '.' | '~' | '%')
}

/// The first pass: values after secret-looking keys, words after a
/// secret-looking flag or an auth scheme.
fn key_values(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if !is_key_char(chars[i]) || (i > 0 && is_key_char(chars[i - 1])) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_key_char(chars[i]) {
            i += 1;
        }
        let key: String = chars[start..i].iter().collect();
        out.push_str(&key);
        let lower = key.to_ascii_lowercase();
        let scheme = lower == "bearer" || lower == "basic";
        if !scheme && !is_secret_key(&key) {
            continue;
        }
        // `"key": …` is JSON-like, `key: …` a header running to the end of
        // its line.
        let quoted_key = matches!(chars.get(i), Some('"' | '\''));
        let mut j = i;
        if quoted_key {
            j += 1;
        }
        while j < chars.len() && chars[j] == ' ' {
            j += 1;
        }
        let sep = chars.get(j).copied();
        let (value_start, ends): (usize, fn(char) -> bool) = match sep {
            Some('=') | Some(':') => {
                let mut k = j + 1;
                while k < chars.len() && chars[k] == ' ' {
                    k += 1;
                }
                if let Some(&q) = chars.get(k).filter(|c| matches!(c, '"' | '\'')) {
                    let end = chars[k + 1..]
                        .iter()
                        .position(|&c| c == q)
                        .map_or(chars.len(), |p| k + 1 + p);
                    replace(&mut out, &chars, i, k + 1, end);
                    i = end;
                    continue;
                }
                let header = sep == Some(':') && !quoted_key;
                (
                    k,
                    if header {
                        |c: char| matches!(c, '\n' | '\r' | '"' | '\'')
                    } else {
                        |c: char| {
                            c.is_whitespace()
                                || matches!(c, '"' | '\'' | '&' | ';' | ',' | '}' | ']')
                        }
                    },
                )
            }
            Some(_) if j > i && (scheme || key.starts_with("--")) => {
                (j, |c: char| c.is_whitespace() || matches!(c, '"' | '\''))
            }
            _ => continue,
        };
        let end = if chars[value_start..].starts_with(&REDACTED_CHARS) {
            value_start
        } else {
            chars[value_start..]
                .iter()
                .position(|&c| ends(c))
                .map_or(chars.len(), |p| value_start + p)
        };
        if end > value_start {
            replace(&mut out, &chars, i, value_start, end);
            i = end;
        }
    }
    out
}

/// Pushes `chars[from..value]` and then the redaction mark in place of
/// `chars[value..end]`, if that is not empty.
fn replace(out: &mut String, chars: &[char], from: usize, value: usize, end: usize) {
    out.extend(&chars[from..value]);
    if end > value {
        out.push_str(REDACTED);
    }
}

/// The second pass: `scheme://user:password@` loses the password.
fn userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| {
                c == '/' || c == '?' || c == '#' || c.is_whitespace() || c == '"' || c == '\''
            })
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match (authority.rfind('@'), authority.find(':')) {
            (Some(at_sign), Some(colon)) if colon < at_sign => {
                out.push_str(&authority[..=colon]);
                out.push_str(REDACTED);
                out.push_str(&authority[at_sign..]);
            }
            _ => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// The third pass: words with a known token prefix, and long opaque runs.
fn words(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    for c in text.chars() {
        if is_word_char(c) {
            word.push(c);
        } else {
            push_word(&mut out, &word);
            word.clear();
            out.push(c);
        }
    }
    push_word(&mut out, &word);
    out
}

fn push_word(out: &mut String, word: &str) {
    let prefixed = TOKEN_PREFIXES
        .iter()
        .any(|prefix| word.starts_with(prefix) && word.len() >= prefix.len() + PREFIX_TAIL);
    if prefixed {
        out.push_str(REDACTED);
        return;
    }
    // Paths and dotted names are split into their parts first, so a long
    // path is not taken for one opaque run.
    let mut start = 0;
    for (at, c) in word
        .char_indices()
        .chain(std::iter::once((word.len(), '/')))
    {
        if matches!(c, '/' | '.' | '~' | '%') {
            let part = &word[start..at];
            let opaque = part.len() >= OPAQUE_RUN
                && part.chars().any(|c| c.is_ascii_digit())
                && part.chars().any(|c| c.is_ascii_alphabetic());
            out.push_str(if opaque { REDACTED } else { part });
            if at < word.len() {
                out.push(c);
            }
            start = at + c.len_utf8();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An object that has every key in `keys`, each set to `value`.
    fn object(keys: &[&str], value: &str) -> Value {
        Value::Object(
            keys.iter()
                .map(|key| ((*key).to_owned(), json!(value)))
                .collect(),
        )
    }

    /// Scrubs an object that has every key in `keys` and checks that every
    /// value was replaced.
    fn assert_all_redacted(keys: &[&str]) {
        let mut v = object(keys, "hunter2");
        scrub(&mut v);
        assert_eq!(v, object(keys, "[redacted]"));
    }

    #[test]
    fn text_loses_what_looks_like_a_credential() {
        let cases = [
            (
                "curl -H 'Authorization: Bearer abc.def' https://x",
                "curl -H 'Authorization: [redacted]' https://x",
            ),
            (
                "curl -H \"X-Api-Key: k1\" -d a=1",
                "curl -H \"X-Api-Key: [redacted]\" -d a=1",
            ),
            (
                "export OPENAI_API_KEY=abc123 && run",
                "export OPENAI_API_KEY=[redacted] && run",
            ),
            (
                "{\"access_token\": \"t0k\", \"n\": 1}",
                "{\"access_token\": \"[redacted]\", \"n\": 1}",
            ),
            ("{\"max_tokens\": 100}", "{\"max_tokens\": [redacted]}"),
            (
                "gh auth --token abc123 login",
                "gh auth --token [redacted] login",
            ),
            ("sent Bearer abcdef to it", "sent Bearer [redacted] to it"),
            ("bearer=abcdef", "bearer=[redacted]"),
            (
                "git clone https://me:pw@example.com/r.git",
                "git clone https://me:[redacted]@example.com/r.git",
            ),
            ("key sk-ant-api03-abcdefgh end", "key [redacted] end"),
            ("ghp_0123456789abcdef", "[redacted]"),
            ("jwt eyJhbGciOi.eyJzdWIi.c2ln ok", "jwt [redacted] ok"),
            (
                "blob Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg== x",
                "blob [redacted] x",
            ),
            (
                "/home/user/src/project/crates/boxcar/src/main.rs",
                "/home/user/src/project/crates/boxcar/src/main.rs",
            ),
            (
                "ls -la /workspace && echo done",
                "ls -la /workspace && echo done",
            ),
            ("café token", "café token"),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text}");
        }
    }

    #[test]
    fn targets_keep_names_and_plain_values() {
        let cases = [
            ("/v1/messages?beta=true", "/v1/messages?beta=true"),
            ("/v1/messages", "/v1/messages"),
            ("/r?api_key=abc&n=1", "/r?api_key=[redacted]&n=1"),
            (
                "/cb?code=4%2F0AX&state=xyz",
                "/cb?code=[redacted]&state=[redacted]",
            ),
            ("/p?q=a-long-value-over-the-limit", "/p?q=[redacted]"),
            ("/p?x%74oken=a", "/p?x%74oken=[redacted]"),
            ("/p?flag&n=", "/p?flag&n="),
            ("/p#access_token=t", "/p"),
            (
                "http://u:pw@h/p?k=v&key=v",
                "http://u:[redacted]@h/p?k=v&key=[redacted]",
            ),
        ];
        for (target, want) in cases {
            assert_eq!(scrub_target(target), want, "{target}");
        }
    }

    #[test]
    fn text_scrubbing_is_stable() {
        let text = "a token=x b";
        assert_eq!(scrub_text(&scrub_text(text)), scrub_text(text));
    }

    #[test]
    fn deep_scrubbing_reaches_strings() {
        let mut v = json!({"command": ["sh", "-c", "curl -H 'Authorization: Bearer q' u"], "password": "p"});
        scrub_deep(&mut v);
        assert_eq!(
            v,
            json!({"command": ["sh", "-c", "curl -H 'Authorization: [redacted]' u"], "password": "[redacted]"})
        );
    }

    #[test]
    fn random_text_never_panics() {
        use proptest::prelude::*;
        proptest!(|(text in ".{0,200}")| {
            let _ = scrub_text(&text);
        });
    }

    #[test]
    fn a_key_that_is_just_a_stem_is_redacted() {
        let mut v = json!({
            "api_key": "k1",
            "api-key": "k2",
            "apikey": "k3",
            "authorization": "Bearer abc",
            "secret": "s",
            "token": "t",
            "bearer": "b",
            "password": "p",
            "cookie": "session=abc",
            "keep": "visible",
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "api_key": "[redacted]",
                "api-key": "[redacted]",
                "apikey": "[redacted]",
                "authorization": "[redacted]",
                "secret": "[redacted]",
                "token": "[redacted]",
                "bearer": "[redacted]",
                "password": "[redacted]",
                "cookie": "[redacted]",
                "keep": "visible",
            })
        );
    }

    #[test]
    fn matching_ignores_case() {
        assert_all_redacted(&[
            "Authorization",
            "X-API-KEY",
            "X-Api-Key",
            "ApiKey",
            "apiKey",
            "Api_Key",
            "PASSWORD",
            "Token",
            "SeCrEt",
            "BEARER",
            "Cookie",
        ]);
        let mut v = json!({"Content-Type": "application/json"});
        scrub(&mut v);
        assert_eq!(v, json!({"Content-Type": "application/json"}));
    }

    #[test]
    fn a_stem_anywhere_in_the_key_matches() {
        assert_all_redacted(&[
            "access_token",
            "refresh_token",
            "bearer_token",
            "X-Amz-Security-Token",
            "client_secret",
            "secret_access_key",
            "db_password",
            "OPENAI_API_KEY",
            "x-goog-api-key",
            "Proxy-Authorization",
            "Set-Cookie",
        ]);
    }

    #[test]
    fn over_matching_is_the_intended_trade_off() {
        // A stem inside a longer, harmless word still matches: the log is
        // append-only and hash-chained, so a secret that slips through can
        // never be taken back out, while a redacted harmless value only costs
        // some detail. `tokens_used_hint` contains `token`, so it is redacted
        // like `tokenizer` and `max_tokens`.
        assert_all_redacted(&[
            "tokenizer",
            "max_tokens",
            "tokens_used_hint",
            "input_tokens",
            "secrets_count",
            "authorization_url",
            "api_key_id",
            "x-api-keys",
            "passwords",
            "cookies_enabled",
        ]);
    }

    #[test]
    fn keys_without_any_stem_are_untouched() {
        let original = json!({
            "keep": "visible",
            "content-type": "application/json",
            "accept": "*/*",
            "user-agent": "curl/8",
            "model": "m",
            "stop_reason": "end_turn",
            "n": 1,
            // A prefix of a stem is not the stem.
            "author": "me",
            "pass": "x",
            "cook": "y",
            "tok": 1,
            "bear": "z",
            "secre": "w",
            "api": "v",
            "key": "u",
            "": "empty key",
        });
        let mut v = original.clone();
        scrub(&mut v);
        assert_eq!(v, original);
    }

    #[test]
    fn nested_objects_and_arrays_are_walked() {
        let mut v = json!({
            "request": {
                "headers": {
                    "Authorization": "Bearer sk-1",
                    "Set-Cookie": "id=1; HttpOnly",
                    "accept": "*/*",
                },
                "body": [
                    {"access_token": "t", "n": 1},
                    [{"client_secret": "p", "user": "u"}],
                ],
            },
            "n": 3,
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "request": {
                    "headers": {
                        "Authorization": "[redacted]",
                        "Set-Cookie": "[redacted]",
                        "accept": "*/*",
                    },
                    "body": [
                        {"access_token": "[redacted]", "n": 1},
                        [{"client_secret": "[redacted]", "user": "u"}],
                    ],
                },
                "n": 3,
            })
        );
    }

    #[test]
    fn a_matching_key_replaces_the_whole_value_whatever_its_shape() {
        let mut v = json!({
            "authorization": {"scheme": "Bearer", "token": "abc"},
            "secret": [1, 2, 3],
            "token": null,
            "password": 12345,
            "cookie": {"id": "1"},
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "authorization": "[redacted]",
                "secret": "[redacted]",
                "token": "[redacted]",
                "password": "[redacted]",
                "cookie": "[redacted]",
            })
        );
    }

    #[test]
    fn values_are_never_inspected_and_non_objects_are_left_alone() {
        for original in [
            json!(null),
            json!(1),
            json!("token"),
            json!(["secret", "password"]),
            json!({"note": "Bearer abc", "list": ["token"]}),
        ] {
            let mut v = original.clone();
            scrub(&mut v);
            assert_eq!(v, original);
        }
    }
}
