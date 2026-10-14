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
        Value::Array(items) => {
            // An array of strings may be an argv: a secret flag's value is
            // the next string.
            let mut flag = false;
            let mut user = false;
            for item in items.iter_mut() {
                let next_flag = item.as_str().is_some_and(is_secret_flag);
                let next_user = item.as_str().is_some_and(is_user_flag);
                match item {
                    Value::String(_) if flag => *item = Value::String(REDACTED.to_owned()),
                    Value::String(text) if user => *text = scrub_text(&user_value(text)),
                    Value::String(text) => *text = scrub_arg(text),
                    _ => texts(item),
                }
                flag = next_flag;
                user = next_user;
            }
        }
        _ => {}
    }
}

/// An argv as a record may keep it: each argument through [`scrub_text`],
/// and the argument after a secret-looking flag (`--token`, `--password`)
/// redacted whole. The same argv always scrubs the same way, and a JSON
/// array of the same strings scrubs as [`scrub_deep`] does it.
pub fn scrub_argv(argv: &[String]) -> Vec<String> {
    let mut flag = false;
    let mut user = false;
    argv.iter()
        .map(|arg| {
            let out = if flag {
                REDACTED.to_owned()
            } else if user {
                scrub_text(&user_value(arg))
            } else {
                scrub_arg(arg)
            };
            flag = is_secret_flag(arg);
            user = is_user_flag(arg);
            out
        })
        .collect()
}

/// One whole argument through [`scrub_text`], a value attached to a
/// secret-looking name (`--cookie=a; b=c`, `API_TOKEN=a b`,
/// `Authorization: Basic a b`) or to a user flag (`--user=alice:pw`)
/// taken whole first: in an argv neither a space nor a `;` ends the
/// value. A secret name's value goes first, and what is left goes on
/// through the user-flag and text rules, so a name that is itself a
/// credential (`-u<key>:pw`) is not kept, nor a single-dash option that
/// starts like `-u` (`-user-password=a b:c`) read as a user flag.
fn scrub_arg(arg: &str) -> String {
    let whole;
    let arg = match attached_secret(arg) {
        Some(name) => {
            whole = format!("{name}{REDACTED}");
            whole.as_str()
        }
        None => arg,
    };
    match attached_user(arg) {
        Some((flag, value)) => format!("{flag}{}", scrub_text(&user_value(value))),
        None => scrub_text(arg),
    }
}

/// The name of a word that gives a secret-looking name a value after a
/// `=` or `:`, the separator included; none when the value is empty. The
/// separators are tried from the first, so the most is taken:
/// `--password:a=b` loses `a=b`, and `--Db:Password=a b` (a namespaced
/// key) loses `a b`. The name may start with `-`, `+` or `/` (`--cookie`,
/// `+token`, `/password`), be quoted (`'password'`), and hold dots and
/// colons (`-Ddb.password`, `Db:Password`); `Basic`, an auth scheme,
/// counts as secret.
fn attached_secret(word: &str) -> Option<&str> {
    let mut seps = [word.find('='), word.find(':')];
    seps.sort();
    seps.into_iter()
        .flatten()
        .find(|&at| {
            let (name, value) = (&word[..at], &word[at + 1..]);
            let bare = unquoted(name.trim_start_matches(['-', '+', '/']));
            !value.is_empty()
                && !bare.is_empty()
                && bare
                    .chars()
                    .all(|c| is_key_char(c) || matches!(c, '.' | ':'))
                && (is_secret_key(bare) || bare.eq_ignore_ascii_case("basic"))
        })
        .map(|at| &word[..=at])
}

/// `name` without the matching quotes around it, if it has them.
fn unquoted(name: &str) -> &str {
    for q in ['\'', '"'] {
        if let Some(inner) = name.strip_prefix(q).and_then(|n| n.strip_suffix(q)) {
            return inner;
        }
    }
    name
}

/// Flags whose value is `user:password` (curl's, wget's): `-u`,
/// `--user`, `-U`, `--proxy-user`.
const USER_FLAGS: [&str; 4] = ["-u", "--user", "-U", "--proxy-user"];

fn is_user_flag(arg: &str) -> bool {
    USER_FLAGS.contains(&arg)
}

/// A user flag's `value` (`user:password`, quoted or not) with its
/// password redacted, a closing quote kept; a user alone, or an empty
/// password, as it is.
fn user_value(value: &str) -> String {
    let Some(colon) = value.find(':') else {
        return value.to_owned();
    };
    let (head, tail) = value.split_at(colon + 1);
    let close = match value.chars().next() {
        Some(q @ ('\'' | '"')) if tail.ends_with(q) => 1,
        _ => 0,
    };
    if tail.len() == close {
        return value.to_owned();
    }
    format!("{head}{REDACTED}{}", &tail[tail.len() - close..])
}

/// A word that is a user flag with its value attached (`-ualice:pw`,
/// `--user=alice:pw`): the flag, then the value.
fn attached_user(word: &str) -> Option<(&str, &str)> {
    for flag in ["--user=", "--proxy-user="] {
        if let Some(value) = word.strip_prefix(flag) {
            return Some((flag, value));
        }
    }
    let flag = word.get(..2).filter(|f| matches!(*f, "-u" | "-U"))?;
    let value = &word[2..];
    (value.contains(':') && !value.starts_with('-')).then_some((flag, value))
}

/// The passwords of `user:password` values after the user flags
/// ([`USER_FLAGS`]) in `text`: the value the next word, attached, or after
/// `=`. Words are read as a shell reads them: a quoted part, spaces and
/// all, belongs to its word.
fn user_flags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut after_flag = false;
    let mut i = 0;
    while let Some(c) = text[i..].chars().next() {
        if c.is_whitespace() {
            out.push(c);
            i += c.len_utf8();
            continue;
        }
        let end = word_end(text, i);
        let word = &text[i..end];
        if after_flag {
            out.push_str(&user_value(word));
            after_flag = false;
        } else if is_user_flag(word) {
            out.push_str(word);
            after_flag = true;
        } else if let Some((flag, value)) = attached_user(word) {
            out.push_str(flag);
            out.push_str(&user_value(value));
        } else {
            out.push_str(word);
        }
        i = end;
    }
    out
}

/// Where the shell word starting at byte `start` of `text` ends: at the
/// first whitespace outside quotes, a backslash escaping what follows.
fn word_end(text: &str, start: usize) -> usize {
    let mut quote = None;
    let mut chars = text[start..].char_indices();
    while let Some((at, c)) = chars.next() {
        match (quote, c) {
            (_, '\\') => {
                chars.next();
            }
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, c) if c.is_whitespace() => return start + at,
            _ => {}
        }
    }
    text.len()
}

/// `--token`, `-password`: a flag, without a value of its own, whose name
/// looks like a secret's. A `:` does not make a value its own: in
/// `--Secrets:ApiKey VALUE` (.NET's configuration keys) it is part of the
/// name, so the next argument is taken as the value all the same.
fn is_secret_flag(arg: &str) -> bool {
    arg.starts_with('-')
        && !arg.contains('=')
        && arg.len() > 1
        && is_secret_key(arg.trim_start_matches('-'))
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
    self::target(target)
}

/// [`scrub_target`]'s work, the path through [`plain`].
fn target(target: &str) -> String {
    let target = target.split('#').next().unwrap_or("");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let mut out = plain(path);
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
        out.push_str(&plain(name));
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
/// - the password in a URL's `user:password@`, and in the
///   `user:password` after curl's and wget's user flags (`-u`, `--user`,
///   `-U`, `--proxy-user`), separate, attached or after `=`;
/// - a word starting with a known token prefix (`sk-`, `ghp_`, `AKIA`,
///   `eyJ`, …);
/// - a run of 32 or more letters and digits holding both.
///
/// Like [`scrub`] it over-matches on purpose: long hashes and identifiers
/// are redacted along with keys. The same text always scrubs the same way,
/// so two scrubbed texts still compare.
pub fn scrub_text(text: &str) -> String {
    plain(&urls(text))
}

/// [`scrub_text`] without the URL pass: keys, userinfo, tokens.
fn plain(text: &str) -> String {
    let text = user_flags(text);
    let text = key_values(&text);
    let text = userinfo(&text);
    words(&text)
}

/// Each URL in `text` (`scheme://...`, to the next space, quote, `<` or
/// `>`) scrubbed as a request target ([`scrub_target`]): its query values
/// kept only when short, plain and under an ordinary name. A `,` or `;`
/// does not end a URL (a path may hold either); one the text put after it
/// is taken in, over-matching at worst.
/// A redirect's `code`, a signed URL's `sig`, are found wherever the URL
/// sits (a `Refresh` header, a `Link`, a command's argument).
fn urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let scheme_start = rest[..at]
            .char_indices()
            .rev()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(p, c)| p + c.len_utf8());
        let end = rest[at + 3..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
            .map_or(rest.len(), |p| at + 3 + p);
        out.push_str(&rest[..scheme_start]);
        if scheme_start == at {
            // No scheme before `://`: not a URL.
            out.push_str(&rest[at..at + 3]);
            rest = &rest[at + 3..];
            continue;
        }
        out.push_str(&target(&rest[scheme_start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
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
                    let end = quoted_end(&chars, k + 1, q);
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
            Some(q @ ('"' | '\'')) if j > i && (scheme || key.starts_with('-')) => {
                let end = quoted_end(&chars, j + 1, q);
                replace(&mut out, &chars, i, j + 1, end);
                i = end;
                continue;
            }
            Some(_) if j > i && (scheme || key.starts_with('-')) => {
                (j, |c: char| c.is_whitespace() || matches!(c, '"' | '\''))
            }
            _ => continue,
        };
        let end = if chars[value_start..].starts_with(&REDACTED_CHARS) {
            value_start
        } else {
            unquoted_end(&chars, value_start, ends)
        };
        if end > value_start {
            replace(&mut out, &chars, i, value_start, end);
            i = end;
        }
    }
    out
}

/// Where a value quoted with `q` from `start` ends: at the first `q` not
/// escaped by a backslash, or at the end.
fn quoted_end(chars: &[char], start: usize, q: char) -> usize {
    let mut k = start;
    while k < chars.len() {
        match chars[k] {
            '\\' => k += 2,
            c if c == q => return k,
            _ => k += 1,
        }
    }
    chars.len()
}

/// Where an unquoted value from `start` ends: at the first character
/// `ends` takes that a backslash does not escape, or at the end.
fn unquoted_end(chars: &[char], start: usize, ends: fn(char) -> bool) -> usize {
    let mut k = start;
    while k < chars.len() {
        match chars[k] {
            '\\' if k + 1 < chars.len() => k += 2,
            c if ends(c) => return k,
            _ => k += 1,
        }
    }
    chars.len()
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
    if prefixed(word) {
        out.push_str(REDACTED);
        return;
    }
    // A token after `name=` is still a token.
    for (n, piece) in word.split('=').enumerate() {
        if n > 0 {
            out.push('=');
        }
        if prefixed(piece) {
            out.push_str(REDACTED);
        } else {
            push_parts(out, piece);
        }
    }
}

/// Whether `word` starts with a known token prefix and has enough after it.
fn prefixed(word: &str) -> bool {
    TOKEN_PREFIXES
        .iter()
        .any(|prefix| word.starts_with(prefix) && word.len() >= prefix.len() + PREFIX_TAIL)
}

/// `piece` with each long opaque part redacted. Paths and dotted names are
/// split into their parts first, so a long path is not taken for one
/// opaque run.
fn push_parts(out: &mut String, piece: &str) {
    let mut start = 0;
    for (at, c) in piece
        .char_indices()
        .chain(std::iter::once((piece.len(), '/')))
    {
        if matches!(c, '/' | '.' | '~' | '%') {
            let part = &piece[start..at];
            let opaque = part.len() >= OPAQUE_RUN
                && part.chars().any(|c| c.is_ascii_digit())
                && part.chars().any(|c| c.is_ascii_alphabetic());
            out.push_str(if opaque { REDACTED } else { part });
            if at < piece.len() {
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
            (
                "client --password 'demo pass' -v",
                "client --password '[redacted]' -v",
            ),
            (
                "client --password \"de\\\"mo\" -v",
                "client --password \"[redacted]\" -v",
            ),
            (
                "client -password demo\\ pass -v",
                "client -password [redacted] -v",
            ),
            (
                "{\"token\": \"a\\\"b\", \"n\": 1}",
                "{\"token\": \"[redacted]\", \"n\": 1}",
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
                "blob [redacted]== x",
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
    fn an_argv_loses_the_value_after_a_secret_flag() {
        let argv: Vec<String> = ["client", "--password", "demo-pass", "--user", "me"]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
        let want = ["client", "--password", "[redacted]", "--user", "me"];
        assert_eq!(scrub_argv(&argv), want);
        let mut v = json!({"command": argv});
        scrub_deep(&mut v);
        assert_eq!(v, json!({"command": want}));
        // The flag with its value in one argument loses the value too.
        assert_eq!(
            scrub_argv(&["--token=abc".to_owned(), "x".to_owned()]),
            ["--token=[redacted]", "x"]
        );
    }

    #[test]
    fn user_flag_passwords_are_redacted() {
        let cases = [
            (
                "curl -u alice:short-pass https://example.test",
                "curl -u alice:[redacted] https://example.test",
            ),
            ("curl --user alice:pw x", "curl --user alice:[redacted] x"),
            ("curl -ualice:pw x", "curl -ualice:[redacted] x"),
            ("curl --user=alice:pw x", "curl --user=alice:[redacted] x"),
            (
                "curl -U proxy:pw -x p:3128 x",
                "curl -U proxy:[redacted] -x p:3128 x",
            ),
            (
                "curl --proxy-user=p:pw x",
                "curl --proxy-user=p:[redacted] x",
            ),
            (
                "curl -u 'alice:pw with space' x",
                "curl -u 'alice:[redacted]' x",
            ),
            ("curl -u \"alice:pw\" x", "curl -u \"alice:[redacted]\" x"),
            ("curl -u alice x", "curl -u alice x"),
            ("curl -u alice: x", "curl -u alice: x"),
            ("sort -u notes.txt", "sort -u notes.txt"),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text}");
        }
        // A key as the user, an empty password: the key is a token.
        let key = ["sk", "test", "a1B2c3D4e5F6g7H8i9J0k1L2"].join("_");
        let stripe = scrub_text(&format!("curl -u {key}: x"));
        assert!(!stripe.contains("a1B2c3D4e5F6g7H8i9J0k1L2"), "{stripe}");

        let argv: Vec<String> = [
            "curl",
            "-u",
            "alice:short-pass",
            "-U",
            "p:pw",
            "--user=a:b",
            "x",
        ]
        .map(str::to_owned)
        .to_vec();
        let want = [
            "curl",
            "-u",
            "alice:[redacted]",
            "-U",
            "p:[redacted]",
            "--user=a:[redacted]",
            "x",
        ];
        assert_eq!(scrub_argv(&argv), want);
        let mut v = json!({"argv": argv});
        scrub_deep(&mut v);
        assert_eq!(v, json!({"argv": want}));
        // In an argv a value is the whole argument, spaces and quotes in
        // it included.
        let argv: Vec<String> = [
            "curl",
            "--user=alice:short pass",
            "-ualice: leading",
            "-u",
            "bob:has space",
            "--proxy-user=p:\"quoted\" pw",
        ]
        .map(str::to_owned)
        .to_vec();
        let want = [
            "curl",
            "--user=alice:[redacted]",
            "-ualice:[redacted]",
            "-u",
            "bob:[redacted]",
            "--proxy-user=p:[redacted]",
        ];
        assert_eq!(scrub_argv(&argv), want);
        let mut v = json!({"argv": argv});
        scrub_deep(&mut v);
        assert_eq!(v, json!({"argv": want}));
        assert_eq!(
            scrub_text("curl --user='alice:short pass' x"),
            "curl --user='alice:[redacted]' x"
        );
    }

    #[test]
    fn a_value_attached_to_a_secret_name_is_taken_whole_in_an_argv() {
        let argv: Vec<String> = [
            "curl",
            "--cookie=theme=light; session=demo",
            "--password=two words",
            "-token='quoted' and, punctuated; too",
            "--api-key=",
            "API_TOKEN=a b",
            "-Ddb.password=first second",
            "-Dapp.cookie=a; b=c",
            "/password=alpha beta",
            "+password=alpha beta",
            "'password'=alpha beta",
            "Basic=alpha beta",
            "Authorization: Bearer alpha beta",
            "-user-password=alpha beta:gamma",
            "--Db:Password=alpha beta",
            "--Service:ApiKey=alpha;beta",
            "--output=two words",
            "LANG=C.UTF-8",
            "https://x.test/?a=b c",
        ]
        .map(str::to_owned)
        .to_vec();
        let want = [
            "curl",
            "--cookie=[redacted]",
            "--password=[redacted]",
            "-token=[redacted]",
            "--api-key=",
            "API_TOKEN=[redacted]",
            "-Ddb.password=[redacted]",
            "-Dapp.cookie=[redacted]",
            "/password=[redacted]",
            "+password=[redacted]",
            "'password'=[redacted]",
            "Basic=[redacted]",
            "Authorization:[redacted]",
            "-user-password=[redacted]",
            "--Db:Password=[redacted]",
            "--Service:ApiKey=[redacted]",
            "--output=two words",
            "LANG=C.UTF-8",
            "https://x.test/?a=b c",
        ];
        assert_eq!(scrub_argv(&argv), want);
        let mut v = json!({"argv": argv});
        scrub_deep(&mut v);
        assert_eq!(v, json!({"argv": want}));
        let again: Vec<String> = want.map(str::to_owned).to_vec();
        assert_eq!(scrub_argv(&again), want, "scrubbing is stable");
        // A user that is itself a credential goes with the password.
        let key = ["sk", "test", "a1B2c3D4e5F6g7H8i9J0k1L2"].join("_");
        for scrubbed in [
            scrub_argv(&[format!("-u{key}:x")]),
            scrub_argv(&[format!("-u{key}x:x")]),
        ] {
            assert!(
                !scrubbed[0].contains("a1B2c3D4e5F6g7H8i9J0k1L2"),
                "{scrubbed:?}"
            );
            assert!(scrubbed[0].ends_with(":[redacted]"), "{scrubbed:?}");
        }
        // A flag with a `:` in it may still take the next argument as its
        // value: both go.
        for (argv, want) in [
            (
                ["--Secrets:ApiKey", "alpha beta"],
                ["--Secrets:[redacted]", "[redacted]"],
            ),
            (
                ["--password:alpha'beta", "next"],
                ["--password:[redacted]", "[redacted]"],
            ),
        ] {
            let argv: Vec<String> = argv.map(str::to_owned).to_vec();
            assert_eq!(scrub_argv(&argv), want);
            let mut v = json!({"argv": argv});
            scrub_deep(&mut v);
            assert_eq!(v, json!({"argv": want}));
        }
    }

    #[test]
    fn urls_in_text_lose_their_credential_query_values() {
        let cases = [
            (
                "0;url=https://client.example/cb?code=a1b2c3d4e5f6a7b8c9d0&state=s",
                "0;url=https://client.example/cb?code=[redacted]&state=[redacted]",
            ),
            (
                "<https://api.example/items?page=2&sig=abc>; rel=next",
                "<https://api.example/items?page=2&sig=[redacted]>; rel=next",
            ),
            (
                "curl 'https://x.example/a?key=k1&n=1' -o out",
                "curl 'https://x.example/a?key=[redacted]&n=1' -o out",
            ),
            (
                "see https://example.com/docs#frag now",
                "see https://example.com/docs now",
            ),
            ("not a url: ://nothing", "not a url: ://nothing"),
            // A `;` or `,` in a path or a query does not end the URL.
            (
                "https://client.example/cb;v=1?code=example-code",
                "https://client.example/cb;v=1?code=[redacted]",
            ),
            (
                "go to https://x.example/p,q?n=1,2&sig=s, then",
                "go to https://x.example/p,q?n=1,2&sig=[redacted] then",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text}");
        }
        // Nested schemes end, however many.
        let nested = "a://".repeat(10_000);
        let _ = scrub_text(&nested);
    }

    #[test]
    fn urls_next_to_wide_characters_are_scrubbed() {
        let cases = [
            (
                "éhttps://x.test/?code=abc",
                "éhttps://x.test/?code=[redacted]",
            ),
            ("日本://x.test/?code=abc", "日本://x.test/?code=abc"),
            (
                "→https://例え.jp/a?sig=z ok",
                "→https://例え.jp/a?sig=[redacted] ok",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text}");
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
