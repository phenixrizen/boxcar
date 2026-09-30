// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Redaction of secrets before a value reaches the audit log.

use serde_json::Value;

/// What a redacted value is replaced with.
const REDACTED: &str = "[redacted]";

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
/// found here, which is why the gateway strips authentication headers
/// structurally before it records anything.
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
