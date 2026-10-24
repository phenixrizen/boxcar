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

/// Whole field names that hold secrets, lowercase. Unlike
/// [`SECRET_STEMS`], these do not match inside a longer name.
const SECRET_NAMES: [&str; 5] = ["key", "auth", "pass", "pwd", "passwd"];

/// Whether `key` is an exact secret name or contains one of the stems used to
/// identify values that should be redacted. Matching is case-insensitive;
/// stem matching is deliberately broad.
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SECRET_STEMS.iter().any(|stem| lower.contains(stem)) || SECRET_NAMES.contains(&lower.as_str())
}

/// Replaces the value of every secret-looking key in `v` with `"[redacted]"`,
/// however deeply the key is nested in objects and arrays.
///
/// A key looks like a secret when its lowercase form is exactly `key`,
/// `auth`, `pass`, `pwd` or `passwd`, or contains `api_key`, `api-key`,
/// `apikey`, `authorization`, `secret`, `token`, `bearer`, `password` or
/// `cookie`. Stem matching is broad on purpose, so it over-matches:
/// `tokenizer`, `max_tokens` and `secrets_count` are redacted along with
/// `access_token`. For an audit log that is the right trade-off.
/// The log is append-only and hash-chained, so a secret that slips through can
/// never be taken back out, while a harmless value that gets redacted only
/// costs some detail.
///
/// The whole value under a matching key is replaced, whatever its shape.
/// Every member name also goes through [`scrub_text`]; a changed name becomes
/// `[redacted]`, with a numeric suffix when that name is already present.
/// String values are not inspected here. [`scrub_deep`] adds [`scrub_text`]
/// on every string, for values whose strings are free text (tool arguments,
/// say).
pub fn scrub(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in &keys {
                let Some(child) = map.get_mut(key) else {
                    continue;
                };
                if is_secret_key(key) {
                    *child = Value::String(REDACTED.to_owned());
                } else {
                    scrub(child);
                }
            }
            let mut next_redacted_index = 1usize;
            for key in keys {
                if scrub_text(&key) == key {
                    continue;
                }
                let Some(child) = map.remove(&key) else {
                    continue;
                };
                let mut name = REDACTED.to_owned();
                while map.contains_key(&name) {
                    name = format!("{REDACTED}{next_redacted_index}");
                    next_redacted_index += 1;
                }
                map.insert(name, child);
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
            let mut argv = Argv::default();
            for item in items.iter_mut() {
                match item {
                    Value::String(text) => *text = argv.next(text),
                    _ => {
                        texts(item);
                        argv = Argv::default();
                    }
                }
            }
        }
        _ => {}
    }
}

/// An argv as a record may keep it: each argument as main records it,
/// the value after a secret word cut to the argument's end,
/// and the argument after a secret-looking flag (`--token`, `--password`)
/// redacted whole. The same argv always scrubs the same way, and a JSON
/// array of the same strings scrubs as [`scrub_deep`] does it.
pub fn scrub_argv(argv: &[String]) -> Vec<String> {
    let mut state = Argv::default();
    argv.iter().map(|arg| state.next(arg)).collect()
}

/// What scrubbing an argv carries from one argument to the next.
#[derive(Default)]
struct Argv {
    /// The last argument was a secret flag: this one is its value.
    flag: bool,
    /// The last argument was a user flag: this one is `user:password`.
    user: bool,
    /// The last argument was a code flag: this one may be code.
    code: bool,
}

impl Argv {
    /// `arg` as a record may keep it, after the arguments before it. A
    /// result a second scrub would still change goes whole, so an argv
    /// scrubs the same way twice (`docs/plans/argv-attached-values.md`,
    /// I5); code keeps [`Argv::one`]'s result as it is, so a script keeps its
    /// later commands unless its leading secret assignment was cut.
    fn next(&mut self, arg: &str) -> String {
        let mut out = self.one(arg);
        if self.code {
            // Code keeps this pass's result and main's reading of it for the
            // next argument, from the argument as given: main's text rules
            // need not be a fixed point on a script, so reading its result
            // would let that reach the next argument on a second scrub.
            self.flag = is_secret_flag(arg);
            self.user = is_user_flag(arg);
            self.code = is_code_flag(arg);
            return out;
        }
        if self.one(&out) != out {
            out = REDACTED.to_owned();
        }
        // The flags are read from the result, as a second scrub reads
        // them, never giving less than main: a secret flag counts as given
        // too (a cut can make one, `--toKen:x=y` becomes
        // `--toKen:[redacted]`, and the next argument then goes whole); a
        // user flag that was itself redacted makes the next argument go
        // whole, since main would still read it as `user:password`; a
        // code flag redacted as a secret flag's value is no code flag.
        let user_lost = is_user_flag(arg) && !is_user_flag(&out);
        self.flag = is_secret_flag(arg) || is_secret_flag(&out) || user_lost;
        self.user = is_user_flag(&out);
        self.code = is_code_flag(&out);
        out
    }

    /// `arg` in this place: whole after a secret flag; else what main
    /// makes of it here, then the cut. Code keeps main's result unless it
    /// starts with a secret environment assignment, whose value goes to the
    /// argument's end.
    fn one(&self, arg: &str) -> String {
        if self.flag {
            return REDACTED.to_owned();
        }
        let main = if self.user {
            scrub_text(&user_value(arg))
        } else {
            main_arg(arg)
        };
        if self.code && !leading_secret_assignment(arg) {
            main
        } else {
            cut(arg, main)
        }
    }
}

/// Whether `arg` begins with a shell environment assignment whose name is
/// secret-looking. The name follows the portable shell spelling: a letter or
/// underscore, then letters, digits or underscores.
fn leading_secret_assignment(arg: &str) -> bool {
    let Some((name, _)) = arg.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && is_secret_key(name)
}

/// One argument as main records it: a user flag's attached value
/// (`--user=alice:pw`, `-ualice:pw`) through [`user_value`], the rest
/// through [`scrub_text`].
fn main_arg(arg: &str) -> String {
    match attached_user(arg) {
        Some((flag, value)) => format!("{flag}{}", scrub_text(&user_value(value))),
        None => scrub_text(arg),
    }
}

/// `main`, what main made of `arg`, with everything after `arg`'s
/// [`secret_cut`] redacted too (`docs/plans/argv-attached-values.md`):
/// in an argv a value runs to the argument's end. Never less than main:
/// when main left everything up to the cut as it was, that prefix and
/// `[redacted]`; when it redacted something inside it, all of it.
fn cut(arg: &str, main: String) -> String {
    match secret_cut(arg) {
        None => main,
        Some(cut) if main.starts_with(&arg[..=cut]) => format!("{}{REDACTED}", &arg[..=cut]),
        Some(_) => REDACTED.to_owned(),
    }
}

/// Where a value attached to a secret word starts in `arg`: the first `=`
/// or `:` of `arg`'s first word that comes after a secret's stem (or
/// `basic`, an auth scheme) in that word lowercased as [`is_secret_key`]
/// reads it, or follows an exact secret name. Stem-bearing words are not
/// parsed as names, so any spelling holds: `--cookie=`, `+password=`,
/// `'password'=`, `-Ddb[0].password=`, `--Db:Password=`,
/// `Authorization: Basic …`. Exact names may have leading dashes. One pass,
/// so a long argument costs a long argument's time.
fn secret_cut(arg: &str) -> Option<usize> {
    let word = &arg[..arg.find(char::is_whitespace).unwrap_or(arg.len())];
    let lower: String = word.chars().flat_map(char::to_lowercase).collect();
    let found = SECRET_STEMS
        .iter()
        .chain(&["basic"])
        .filter_map(|stem| lower.find(stem).map(|at| at + stem.len()))
        .min();
    // Back from the lowercased word to the word: the end of the char whose
    // lowercase ends the stem.
    let mut lowered = 0;
    let mut stem_end = word.len();
    if let Some(found) = found {
        for (at, c) in word.char_indices() {
            lowered += c.to_lowercase().map(char::len_utf8).sum::<usize>();
            if lowered >= found {
                stem_end = at + c.len_utf8();
                break;
            }
        }
    }
    let stem_cut = found.and_then(|_| word[stem_end..].find(['=', ':']).map(|at| stem_end + at));
    let exact_cut = word.find(['=', ':']).filter(|&cut| {
        let name = word[..cut].trim_start_matches('-').to_ascii_lowercase();
        SECRET_NAMES.contains(&name.as_str())
    });
    let cut = match (stem_cut, exact_cut) {
        (Some(a), Some(b)) => a.min(b),
        (Some(cut), None) | (None, Some(cut)) => cut,
        (None, None) => return None,
    };
    (cut + 1 < arg.len()).then_some(cut)
}

/// A flag whose next argument is code: `-c` (`sh`, `python3`), `-e`
/// (`node`, `perl`), `--command`, `--eval`, or short flags run together
/// ending in one (`-lc`, `-ec`).
fn is_code_flag(arg: &str) -> bool {
    matches!(arg, "--command" | "--eval")
        || arg.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty()
                && flags.bytes().all(|b| b.is_ascii_alphabetic())
                && (flags.ends_with('c') || flags.ends_with('e'))
        })
}

/// Flags whose value is `user:password` (curl's, wget's): `-u`,
/// `--user`, `-U`, `--proxy-user`, or a short-option cluster ending in
/// `u` or `U`.
const USER_FLAGS: [&str; 4] = ["-u", "--user", "-U", "--proxy-user"];

fn is_user_flag(arg: &str) -> bool {
    USER_FLAGS.contains(&arg)
        || arg
            .strip_prefix('-')
            .filter(|flags| !arg.starts_with("--") && !flags.is_empty())
            .is_some_and(|flags| {
                flags.bytes().all(|b| b.is_ascii_alphabetic())
                    && (flags.ends_with('u') || flags.ends_with('U'))
            })
}

/// A user flag's `value` (`user:password`, quoted or not) with its
/// password redacted; a user alone, or an empty password, as it is. A
/// quoted value's password runs to its closing quote, and the result is
/// closed again there, whatever the word went on with (`'alice:pw'x` is one
/// value to the shell, so `x` is the password's; `'alice:[redacted]'`
/// holds no open quote for a second scrub to read past). One with no
/// closing quote is redacted to its end.
fn user_value(value: &str) -> String {
    let Some(colon) = value.find(':') else {
        return value.to_owned();
    };
    let (head, tail) = value.split_at(colon + 1);
    let quote = value.chars().next().filter(|c| matches!(c, '\'' | '"'));
    let close = quote.and_then(|q| closing_quote(tail, q));
    if close.unwrap_or(tail.len()) == 0 {
        return value.to_owned();
    }
    match (quote, close) {
        (Some(q), Some(_)) => format!("{head}{REDACTED}{q}"),
        _ => format!("{head}{REDACTED}"),
    }
}

/// Where the first `q` outside a backslash escape is in `text`.
fn closing_quote(text: &str, q: char) -> Option<usize> {
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if c == q {
            return Some(at);
        }
    }
    None
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
/// all, belongs to its word, and the value ends where the shell would end
/// the word, at an operator outside quotes ([`value_end`]), so `'alice:pw';`
/// keeps its closing quote and the `;` after it. A separate value may follow
/// horizontal space and backslash-newline continuations.
fn user_flags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut after_flag = false;
    let mut separated = false;
    let mut i = 0;
    while let Some(c) = text[i..].chars().next() {
        if c.is_whitespace() {
            if after_flag {
                if is_horizontal_space(c) {
                    separated = true;
                } else {
                    after_flag = false;
                    separated = false;
                }
            }
            out.push(c);
            i += c.len_utf8();
            continue;
        }
        let continuation = if after_flag && separated && text[i..].starts_with("\\\r\n") {
            Some(3)
        } else if after_flag && separated && text[i..].starts_with("\\\n") {
            Some(2)
        } else {
            None
        };
        if let Some(len) = continuation {
            out.push_str(&text[i..i + len]);
            i += len;
            continue;
        }
        let end = word_end(text, i);
        let word = &text[i..end];
        if after_flag {
            let (value, rest) = word.split_at(value_end(word));
            out.push_str(&user_value(value));
            out.push_str(rest);
            after_flag = false;
            separated = false;
        } else if is_user_flag(word) {
            out.push_str(word);
            after_flag = true;
            separated = false;
        } else if let Some((flag, value)) = attached_user(word) {
            let (value, rest) = value.split_at(value_end(value));
            out.push_str(flag);
            out.push_str(&user_value(value));
            out.push_str(rest);
        } else {
            out.push_str(word);
        }
        i = end;
    }
    out
}

/// Where a user flag's value ends within its word in text: at the first
/// shell operator character (`;`, `&`, `|`, `(`, `)`, `<`, `>`) outside
/// quotes, which ends the word as the shell reads it, or the word's end.
/// What follows is kept as it is: `'alice:pw';` is the value `'alice:pw'`
/// then `;`. An operator inside quotes is the value's own. A quoted value
/// the word goes on with (`'alice:pw'x`) runs to the word's end, since
/// the shell joins the two into one value ([`user_value`] closes it).
fn value_end(word: &str) -> usize {
    let mut quote = None;
    let mut chars = word.char_indices();
    while let Some((at, c)) = chars.next() {
        match (quote, c) {
            (_, '\\') => {
                chars.next();
            }
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, ';' | '&' | '|' | '(' | ')' | '<' | '>') => return at,
            _ => {}
        }
    }
    word.len()
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

/// Query parameter names that carry a credential without a secret stem or
/// exact secret name in them (OAuth's `code`, signed URLs' `sig`, …),
/// lowercase.
const SECRET_PARAMS: [&str; 6] = ["code", "state", "sig", "signature", "session", "sid"];

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

fn is_horizontal_space(c: char) -> bool {
    c.is_whitespace() && !matches!(c, '\n' | '\r')
}

/// The start of a shell word after a separate flag, including horizontal
/// whitespace and backslash-newline continuations between them.
fn shell_value_start(chars: &[char], start: usize) -> Option<usize> {
    let mut at = start;
    let mut separated = false;
    loop {
        while chars.get(at).is_some_and(|c| is_horizontal_space(*c)) {
            separated = true;
            at += 1;
        }
        if separated && chars.get(at..at + 2) == Some(&['\\', '\n']) {
            at += 2;
        } else if separated && chars.get(at..at + 3) == Some(&['\\', '\r', '\n']) {
            at += 3;
        } else {
            break;
        }
    }
    (separated && at < chars.len()).then_some(at)
}

/// Whitespace and continuations between `=` or `:` and its value.
fn attached_value_start(chars: &[char], start: usize) -> usize {
    let mut at = start;
    loop {
        while chars.get(at).is_some_and(|c| is_horizontal_space(*c)) {
            at += 1;
        }
        if chars.get(at..at + 2) == Some(&['\\', '\n']) {
            at += 2;
        } else if chars.get(at..at + 3) == Some(&['\\', '\r', '\n']) {
            at += 3;
        } else {
            return at;
        }
    }
}

/// The end of one shell word: quotes and backslash escapes join its parts;
/// whitespace and shell operators outside quotes end it.
fn shell_word_end_chars(chars: &[char], start: usize) -> usize {
    let mut quote = None;
    let mut at = start;
    while at < chars.len() {
        match (quote, chars[at]) {
            (_, '\\') if at + 1 < chars.len() => at += 2,
            (None, q @ ('\'' | '"')) => {
                quote = Some(q);
                at += 1;
            }
            (Some(q), c) if c == q => {
                quote = None;
                at += 1;
            }
            (None, c)
                if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>') =>
            {
                break;
            }
            _ => at += 1,
        }
    }
    at
}

/// Writes one shell word with its value replaced. Quotes stay only when one
/// pair surrounds the whole word; mixed quoted and unquoted parts go whole.
fn replace_shell_word(out: &mut String, chars: &[char], from: usize, value: usize, end: usize) {
    if value == end {
        out.extend(&chars[from..end]);
        return;
    }
    let quote = chars
        .get(value)
        .copied()
        .filter(|c| matches!(c, '\'' | '"'));
    let whole_quote = quote.filter(|&q| quoted_end(chars, value + 1, q) + 1 == end);
    let (secret_start, secret_end) = if whole_quote.is_some() {
        (value + 1, end - 1)
    } else {
        (value, end)
    };
    out.extend(&chars[from..secret_start]);
    if chars[secret_start..secret_end] == REDACTED_CHARS {
        out.extend(&chars[secret_start..secret_end]);
    } else if secret_start < secret_end {
        out.push_str(REDACTED);
    }
    if let Some(q) = whole_quote {
        out.push(q);
    }
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
        // `"key": …` is JSON-like; an unquoted, non-flag `key: …` is a
        // header running to the end of its line.
        let quoted_key = matches!(chars.get(i), Some('"' | '\''));
        let mut j = i;
        if quoted_key {
            j += 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
        } else {
            while j < chars.len() && is_horizontal_space(chars[j]) {
                j += 1;
            }
        }
        let sep = chars.get(j).copied();
        let (value_start, ends): (usize, fn(char) -> bool) = match sep {
            Some('=') | Some(':') => {
                let mut k = if quoted_key {
                    j + 1
                } else {
                    attached_value_start(&chars, j + 1)
                };
                if quoted_key {
                    while k < chars.len() && chars[k].is_whitespace() {
                        k += 1;
                    }
                }
                let header = sep == Some(':') && !quoted_key && !key.starts_with('-');
                if let Some(&q) = chars.get(k).filter(|c| matches!(c, '"' | '\'')) {
                    let quote_end = quoted_end(&chars, k + 1, q);
                    if quoted_key || header || quote_end + 1 == shell_word_end_chars(&chars, k) {
                        replace(&mut out, &chars, i, k + 1, quote_end);
                        i = quote_end;
                        continue;
                    }
                }
                if !header {
                    let end = if quoted_key {
                        unquoted_end(&chars, k, |c: char| {
                            c.is_whitespace()
                                || matches!(c, '"' | '\'' | '&' | ';' | ',' | '}' | ']')
                        })
                    } else {
                        shell_word_end_chars(&chars, k)
                    };
                    replace_shell_word(&mut out, &chars, i, k, end);
                    i = end;
                    continue;
                }
                (k, |c: char| matches!(c, '\n' | '\r' | '"' | '\''))
            }
            _ if scheme || key.starts_with('-') => {
                let Some(k) = shell_value_start(&chars, i) else {
                    continue;
                };
                let end = shell_word_end_chars(&chars, k);
                replace_shell_word(&mut out, &chars, i, k, end);
                i = end;
                continue;
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
    fn a_secret_flags_text_value_is_one_shell_word() {
        let cases = [
            ("client --password\talpha", "client --password\t[redacted]"),
            (
                "client --password \\\n  alpha next",
                "client --password \\\n  [redacted] next",
            ),
            (
                "client --password alpha'beta' next",
                "client --password [redacted] next",
            ),
            (
                "client --password 'alpha'beta next",
                "client --password [redacted] next",
            ),
            (
                "client --password alpha\"beta gamma\"delta next",
                "client --password [redacted] next",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text:?}");
            assert_eq!(scrub_text(want), want, "{text:?}: stable");
        }
    }

    #[test]
    fn colon_attached_flags_use_shell_word_boundaries() {
        let cases = [
            (
                "client --password:alpha'beta gamma'delta next",
                "client --password:[redacted] next",
            ),
            (
                "Authorization: Bearer alpha beta\nnext",
                "Authorization: [redacted]\nnext",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text:?}");
            assert_eq!(scrub_text(want), want, "{text:?}: stable");
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
            (
                "/p?passwd=short&mode=plain",
                "/p?passwd=[redacted]&mode=plain",
            ),
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
            // The value ends where the shell ends the word: at an operator
            // outside quotes. The quote and the operator stay (#40).
            (
                "curl https://example.test -u 'alice:pw'; echo retained",
                "curl https://example.test -u 'alice:[redacted]'; echo retained",
            ),
            (
                "curl -u \"alice:pw\"; echo x",
                "curl -u \"alice:[redacted]\"; echo x",
            ),
            (
                "curl -u alice:pw; echo x",
                "curl -u alice:[redacted]; echo x",
            ),
            ("curl -u alice:pw|cat", "curl -u alice:[redacted]|cat"),
            (
                "curl -u alice:pw&&echo x",
                "curl -u alice:[redacted]&&echo x",
            ),
            ("(curl -u alice:pw)", "(curl -u alice:[redacted])"),
            ("curl -u alice:pw>out", "curl -u alice:[redacted]>out"),
            (
                "curl --user='alice:pw'&&echo x",
                "curl --user='alice:[redacted]'&&echo x",
            ),
            ("curl -ualice:pw;id", "curl -ualice:[redacted];id"),
            // An operator inside the quotes is the password's own.
            ("curl -u 'alice:p;w' x", "curl -u 'alice:[redacted]' x"),
            (
                "curl -u \"alice:a|b\"; x",
                "curl -u \"alice:[redacted]\"; x",
            ),
            // A quoted value the word goes on with is one value to the
            // shell: redacted to the word's end, and closed again, so the
            // result scrubs the same a second time.
            ("curl -u 'alice:pw'x y", "curl -u 'alice:[redacted]' y"),
            (
                "curl -u \"alice:p\\\"w\" x",
                "curl -u \"alice:[redacted]\" x",
            ),
            ("curl -u 'alice:pw", "curl -u 'alice:[redacted]"),
            ("curl -u 'alice:' x", "curl -u 'alice:' x"),
            ("curl -u alice x", "curl -u alice x"),
            ("curl -u alice: x", "curl -u alice: x"),
            ("sort -u notes.txt", "sort -u notes.txt"),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text}");
            // A fixed point: a second scrub changes nothing (#40).
            assert_eq!(scrub_text(want), want, "{text}");
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
    fn bundled_user_flags_redact_passwords() {
        for flag in ["-su", "-sSu", "-fsSLu", "-sU"] {
            let text = format!("curl {flag} alice:short-pass https://example.test");
            let want = format!("curl {flag} alice:[redacted] https://example.test");
            assert_eq!(scrub_text(&text), want, "{flag}");

            let argv =
                ["curl", flag, "alice:short-pass", "https://example.test"].map(str::to_owned);
            let expected = ["curl", flag, "alice:[redacted]", "https://example.test"];
            assert_eq!(scrub_argv(&argv), expected, "{flag}");
            let mut value = json!({"argv": argv});
            scrub_deep(&mut value);
            assert_eq!(value, json!({"argv": expected}), "{flag}");
        }
    }

    #[test]
    fn user_flags_keep_values_after_shell_separators() {
        let cases = [
            (
                "curl -u \\\n  alice:short-pass next",
                "curl -u \\\n  alice:[redacted] next",
            ),
            (
                "curl -fsSLU\t\\\r\n  proxy:short-pass next",
                "curl -fsSLU\t\\\r\n  proxy:[redacted] next",
            ),
            ("curl -u\nalice:short-pass", "curl -u\nalice:short-pass"),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text:?}");
            assert_eq!(scrub_text(want), want, "{text:?}: stable");
        }
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
            "-Ddb[0].password=alpha beta",
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
            "-Ddb[0].password=[redacted]",
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
            scrub_argv(&[format!("-u{key}=x:x")]),
            scrub_argv(&[format!("-U{key}=x:x")]),
        ] {
            assert!(
                !scrubbed[0].contains("a1B2c3D4e5F6g7H8i9J0k1L2"),
                "{scrubbed:?}"
            );
            assert!(scrubbed[0].ends_with(":[redacted]"), "{scrubbed:?}");
        }
        // Main's own rules can redact the name the cut needs (a long run of
        // letters and digits), or a `-u` user that is a credential: all of
        // the argument goes.
        for arg in [
            format!("--password{}=alpha beta", "0123456789".repeat(4)),
            format!("-u{key}=x:pw"),
        ] {
            let scrubbed = scrub_argv(std::slice::from_ref(&arg));
            assert!(
                !scrubbed[0].contains("beta") && !scrubbed[0].contains("a1B2c3"),
                "{arg}: {scrubbed:?}"
            );
            assert_eq!(scrub_argv(&scrubbed), scrubbed, "{arg}: stable");
        }
        // A stem's letters are matched as `is_secret_key` matches them:
        // the Kelvin sign is a `k`.
        let kelvin = "--to\u{212a}en=alpha beta".to_owned();
        assert_eq!(scrub_argv(&[kelvin]), ["--to\u{212a}en=[redacted]"]);
        // A cut that leaves a bare secret flag takes the next argument in
        // the first pass, so a second pass changes nothing.
        let argv = ["--to\u{212a}en:x=y", "keep"].map(str::to_owned).to_vec();
        let want = ["--to\u{212a}en:[redacted]", "[redacted]"];
        assert_eq!(scrub_argv(&argv), want);
        assert_eq!(scrub_argv(&want.map(str::to_owned)), want, "stable");
        let mut v = json!({"argv": argv});
        scrub_deep(&mut v);
        assert_eq!(v, json!({"argv": want}));
        scrub_deep(&mut v);
        assert_eq!(v, json!({"argv": want}), "stable");
        // An attached user flag whose colon the cut removes would read
        // differently a second time: it goes whole the first time.
        for arg in ["-usecret'x=alice:pw", "-Usecret'x=alice:pw"] {
            let argv = vec!["curl".to_owned(), arg.to_owned()];
            let once = scrub_argv(&argv);
            assert_eq!(scrub_argv(&once), once, "{arg}: stable");
            assert!(
                !once[1].contains("pw") && !once[1].contains("alice"),
                "{once:?}"
            );
            let mut v = json!(argv);
            scrub_deep(&mut v);
            assert_eq!(v, json!(once), "{arg}");
        }
        // Flags redacted as a secret flag's value shape the next argument
        // the same way on every pass.
        for (argv, want) in [
            (
                ["--token", "-c", "TOKEN=x; echo retained"],
                ["--token", "[redacted]", "TOKEN=[redacted]"],
            ),
            (
                ["--token", "-u", "alice:pw"],
                ["--token", "[redacted]", "[redacted]"],
            ),
        ] {
            let argv: Vec<String> = argv.map(str::to_owned).to_vec();
            assert_eq!(scrub_argv(&argv), want, "{argv:?}");
            assert_eq!(
                scrub_argv(&want.map(str::to_owned)),
                want,
                "{argv:?}: stable"
            );
            let mut v = json!(argv);
            scrub_deep(&mut v);
            assert_eq!(v, json!(want), "{argv:?}");
            scrub_deep(&mut v);
            assert_eq!(v, json!(want), "{argv:?}: stable");
        }
        // A script given to a shell is text: only its values go, and the
        // commands after them stay.
        let script = scrub_argv(&["sh", "-c", "export TOKEN=x; rm -rf /tmp/y"].map(str::to_owned));
        assert_eq!(script[2], "export TOKEN=[redacted]; rm -rf /tmp/y");
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

    /// Code after a code flag keeps its later commands when it does not start
    /// with a secret assignment: the text rules redact its values and leave
    /// the rest. An assignment that follows no code flag loses its whole
    /// value too.
    #[test]
    fn code_after_a_code_flag_stays_text() {
        for (argv, code) in [
            (
                ["sh", "-c", "echo retained; TOKEN=x"],
                "echo retained; TOKEN=[redacted]",
            ),
            (
                ["bash", "-lc", "echo retained && TOKEN=x"],
                "echo retained && TOKEN=[redacted]",
            ),
            (
                ["python3", "-c", "run(); token='a'"],
                "run(); token='[redacted]'",
            ),
            (["node", "-e", "run(); token=1"], "run(); token=[redacted]"),
            (["sh", "-c", "env TOKEN='a;b'"], "env TOKEN='[redacted]'"),
        ] {
            let argv: Vec<String> = argv.map(str::to_owned).to_vec();
            let scrubbed = scrub_argv(&argv);
            assert_eq!(scrubbed[2], code, "{argv:?}");
            assert_eq!(scrub_argv(&scrubbed), scrubbed, "{argv:?}: stable");
            let mut v = json!(argv);
            scrub_deep(&mut v);
            assert_eq!(v[2], code, "{argv:?}");
            scrub_deep(&mut v);
            assert_eq!(v[2], code, "{argv:?}: stable");
        }
        for (argv, cut) in [
            (["env", "TOKEN=a b", "cmd"], "TOKEN=[redacted]"),
            (["curl", "--cookie=a; b=c", "x"], "--cookie=[redacted]"),
            (["curl", "-u", "token=alpha beta:pw"], "token=[redacted]"),
            (["curl", "--user", "password=a b:c"], "password=[redacted]"),
        ] {
            let argv: Vec<String> = argv.map(str::to_owned).to_vec();
            let scrubbed = scrub_argv(&argv);
            assert!(scrubbed.iter().any(|a| a == cut), "{argv:?}: {scrubbed:?}");
            let mut v = json!(argv);
            scrub_deep(&mut v);
            assert_eq!(v, json!(scrubbed), "{argv:?}");
        }
    }

    #[test]
    fn a_leading_secret_assignment_after_a_code_flag_is_cut() {
        for flag in ["-c", "-e", "--command", "--eval", "-lc", "-ec"] {
            let argv = ["runner", flag, "TOKEN=alpha beta; echo retained"].map(str::to_owned);
            let want = ["runner", flag, "TOKEN=[redacted]"];
            assert_eq!(scrub_argv(&argv), want, "{flag}");
            let mut value = json!(argv);
            scrub_deep(&mut value);
            assert_eq!(value, json!(want), "{flag}");
        }

        let argv = ["runner", "--eval", "key=alpha beta"].map(str::to_owned);
        assert_eq!(scrub_argv(&argv), ["runner", "--eval", "key=[redacted]"]);
        let ordinary = ["runner", "--eval", "mode=alpha beta; run()"].map(str::to_owned);
        assert_eq!(scrub_argv(&ordinary), ordinary);
    }

    /// A script whose credential main's text rules redact (a quoted
    /// `-u` value ending in `;`) keeps what main keeps, its later command
    /// included: code gets main's result as it is.
    #[test]
    fn a_script_keeps_what_main_keeps() {
        let script = "curl https://example.test -u 'alice:pw'; echo retained";
        let argv: Vec<String> = ["sh", "-c", script].map(str::to_owned).to_vec();
        let scrubbed = scrub_argv(&argv);
        assert_eq!(scrubbed[2], scrub_text(script));
        assert!(scrubbed[2].contains("echo retained"), "{scrubbed:?}");
        assert!(!scrubbed[2].contains("pw"), "{scrubbed:?}");
        let mut v = json!(argv);
        scrub_deep(&mut v);
        assert_eq!(v, json!(scrubbed));
        // Main's text rules are not a fixed point on this script, and a
        // second scrub drops its `=`; the argument after it is read from
        // the script as given, as main reads it, and stays.
        let argv: Vec<String> = ["python3", "-c", "-1 # token -u 'alice:pw'; x=y", "keep"]
            .map(str::to_owned)
            .to_vec();
        let once = scrub_argv(&argv);
        let twice = scrub_argv(&once);
        assert_eq!(
            (once[3].as_str(), twice[3].as_str()),
            ("keep", "keep"),
            "{once:?} {twice:?}"
        );
        let mut v = json!(argv);
        scrub_deep(&mut v);
        assert_eq!(v[3], "keep");
        scrub_deep(&mut v);
        assert_eq!(v[3], "keep");
    }

    /// The calling thread's CPU time: what its work costs, not how long a
    /// loaded machine took to let it run.
    fn thread_cpu_time() -> std::time::Duration {
        // SAFETY: timespec is plain data; all zeroes is valid.
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: clock_gettime writes one timespec through the pointer,
        // which points at `ts`, alive for the call.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        assert_eq!(rc, 0, "clock_gettime: {}", std::io::Error::last_os_error());
        std::time::Duration::new(
            u64::try_from(ts.tv_sec).unwrap(),
            u32::try_from(ts.tv_nsec).unwrap(),
        )
    }

    /// A long argument costs a long argument's time: one with no
    /// whitespace and a separator every other byte, one with a stem only
    /// near its end, and one of Kelvin signs (which lowercase to `k`).
    #[test]
    fn a_long_argument_scrubs_in_linear_time() {
        let pairs = "a:".repeat(128 * 1024);
        for arg in [
            pairs.clone(),
            format!("{pairs}token=x"),
            "\u{212a}".repeat(96 * 1024),
        ] {
            let started = thread_cpu_time();
            let _ = scrub_argv(std::slice::from_ref(&arg));
            let mut v = json!([arg]);
            scrub_deep(&mut v);
            let took = thread_cpu_time().saturating_sub(started);
            // Linear work takes the debug build about a second of the
            // thread's time; quadratic work on 256 KiB would take minutes
            // of it. The thread's own time is measured: a loaded machine,
            // which only keeps the thread off the CPU, adds nothing to it.
            assert!(took < std::time::Duration::from_secs(30), "{took:?}");
        }
    }

    /// `twice` is `once` scrubbed again: equal outside code, which keeps
    /// main's result and is only as stable as main's text rules (as is
    /// the argument after it, read from the code as main reads it).
    fn stable_outside_code(once: &[String], twice: &[String]) -> bool {
        let after_code = |i: usize, back: usize| i >= back && is_code_flag(&once[i - back]);
        once.len() == twice.len()
            && (0..once.len()).all(|i| after_code(i, 1) || after_code(i, 2) || once[i] == twice[i])
    }

    /// Argvs built from the pieces flags and values are made of (user,
    /// secret and code flags, stems, separators, quotes, the redaction
    /// mark) scrub the same way twice and alike through either entry point.
    #[test]
    fn argvs_of_flag_pieces_scrub_stably() {
        use proptest::prelude::*;
        let pieces = prop::sample::select(vec![
            "-u",
            "-U",
            "--user",
            "--proxy-user",
            "-c",
            "-e",
            "-lc",
            "--token",
            "--Secrets",
            "secret",
            "token",
            "Basic",
            "password",
            "=",
            ":",
            "'",
            "\"",
            " ",
            ";",
            "&&",
            "a",
            "x",
            "alice",
            "pw",
            "\u{212a}",
            "[redacted]",
            "-",
        ]);
        let arg = prop::collection::vec(pieces, 1..10).prop_map(|p| p.concat());
        proptest!(ProptestConfig::with_cases(2000), |(argv in prop::collection::vec(arg, 0..6))| {
            let once = scrub_argv(&argv);
            prop_assert!(stable_outside_code(&once, &scrub_argv(&once)), "{:?}", once);
            let mut v = json!(argv);
            scrub_deep(&mut v);
            prop_assert_eq!(v, json!(once));
        });
    }

    /// Random argvs (separators, quotes, whitespace, multi-byte and
    /// case-folding characters) never panic, through either entry point,
    /// and scrub the same way twice.
    #[test]
    fn random_argvs_never_panic_and_scrub_stably() {
        use proptest::prelude::*;
        let arg = "[-a-zA-Z0-9=:;'\" _.\\[\\]\u{212a}\u{e9}\u{1f600}|&]{0,24}";
        proptest!(|(argv in prop::collection::vec(arg, 0..6))| {
            let once = scrub_argv(&argv);
            prop_assert!(stable_outside_code(&once, &scrub_argv(&once)), "{:?}", once);
            let mut v = json!(argv);
            scrub_deep(&mut v);
            prop_assert_eq!(v.clone(), json!(once));
        });
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
    fn exact_secret_names_are_redacted_without_matching_substrings() {
        assert_all_redacted(&[
            "key", "KEY", "auth", "AUTH", "pass", "PASS", "pwd", "PWD", "passwd", "PASSWD",
        ]);
        let cases = [
            ("key=short", "key=[redacted]"),
            ("auth=short", "auth=[redacted]"),
            ("pass=short", "pass=[redacted]"),
            ("pwd=short", "pwd=[redacted]"),
            ("passwd=short", "passwd=[redacted]"),
            ("keyboard=short", "keyboard=short"),
            ("author=short", "author=short"),
            ("passage=short", "passage=short"),
            ("pwd_hint=short", "pwd_hint=short"),
            ("passwd_file=short", "passwd_file=short"),
            ("password_hint=short", "password_hint=[redacted]"),
        ];
        for (text, want) in cases {
            assert_eq!(scrub_text(text), want, "{text}");
        }
        assert_eq!(
            scrub_argv(&["key=short value".to_owned(), "--auth=one two".to_owned()]),
            ["key=[redacted]", "--auth=[redacted]"]
        );
    }

    #[test]
    fn json_member_names_are_scrubbed_without_colliding() {
        let mut value = json!({
            "[redacted]": "existing",
            "password=first": "one",
            "token=second": "two",
            "nested": {"auth=third": "visible"},
        });
        scrub_deep(&mut value);
        assert_eq!(
            value,
            json!({
                "[redacted]": "existing",
                "[redacted]1": "[redacted]",
                "[redacted]2": "[redacted]",
                "nested": {"[redacted]": "visible"},
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
            "passage": "x",
            "cook": "y",
            "tok": 1,
            "bear": "z",
            "secre": "w",
            "api": "v",
            "keyboard": "u",
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
