// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Redaction of secrets before a value reaches the audit log.

use serde_json::Value;

/// What a redacted value is replaced with.
const REDACTED: &str = "[redacted]";

/// Object keys whose values are secrets. A key matches when it equals one of
/// these ignoring ASCII case; a key that merely contains one (`max_tokens`,
/// `authorization_url`) does not.
const SECRET_KEYS: [&str; 8] = [
    "api_key",
    "api-key",
    "x-api-key",
    "authorization",
    "secret",
    "token",
    "bearer",
    "password",
];

fn is_secret_key(key: &str) -> bool {
    SECRET_KEYS
        .iter()
        .any(|secret| key.eq_ignore_ascii_case(secret))
}

/// Replaces the value of every secret-named key in `v` with `"[redacted]"`,
/// however deeply the key is nested in objects and arrays.
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

    #[test]
    fn every_listed_key_is_redacted() {
        let mut v = json!({
            "api_key": "k1",
            "api-key": "k2",
            "x-api-key": "k3",
            "authorization": "Bearer abc",
            "secret": "s",
            "token": "t",
            "bearer": "b",
            "password": "p",
            "keep": "visible",
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "api_key": "[redacted]",
                "api-key": "[redacted]",
                "x-api-key": "[redacted]",
                "authorization": "[redacted]",
                "secret": "[redacted]",
                "token": "[redacted]",
                "bearer": "[redacted]",
                "password": "[redacted]",
                "keep": "visible",
            })
        );
    }

    #[test]
    fn matching_ignores_ascii_case() {
        let mut v = json!({
            "Authorization": "Bearer abc",
            "X-API-KEY": "k",
            "Api_Key": "k",
            "PASSWORD": "p",
            "Token": "t",
            "SeCrEt": "s",
            "BEARER": "b",
            "Content-Type": "application/json",
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "Authorization": "[redacted]",
                "X-API-KEY": "[redacted]",
                "Api_Key": "[redacted]",
                "PASSWORD": "[redacted]",
                "Token": "[redacted]",
                "SeCrEt": "[redacted]",
                "BEARER": "[redacted]",
                "Content-Type": "application/json",
            })
        );
    }

    #[test]
    fn nested_objects_and_arrays_are_walked() {
        let mut v = json!({
            "request": {
                "headers": {"Authorization": "Bearer sk-1", "accept": "*/*"},
                "body": [
                    {"token": "t", "n": 1},
                    [{"password": "p", "user": "u"}],
                ],
            },
            "n": 3,
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "request": {
                    "headers": {"Authorization": "[redacted]", "accept": "*/*"},
                    "body": [
                        {"token": "[redacted]", "n": 1},
                        [{"password": "[redacted]", "user": "u"}],
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
        });
        scrub(&mut v);
        assert_eq!(
            v,
            json!({
                "authorization": "[redacted]",
                "secret": "[redacted]",
                "token": "[redacted]",
                "password": "[redacted]",
            })
        );
    }

    #[test]
    fn keys_that_only_contain_a_listed_word_are_untouched() {
        let original = json!({
            "max_tokens": 256,
            "tokens": 10,
            "secrets_count": 2,
            "author": "me",
            "authorization_url": "https://example.test/auth",
            "bearer_of": "y",
            "passwords": 3,
            "api_key_id": "k1",
            "x-api-keys": 1,
            "": "empty key",
        });
        let mut v = original.clone();
        scrub(&mut v);
        assert_eq!(v, original);
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
