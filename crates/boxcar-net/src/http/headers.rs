// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A message's headers, with no credential in them.
//!
//! Names are lowercased as they come in (HTTP/2 sends them so; HTTP/1.1
//! does not care). The value of a header that carries a credential
//! ([`is_credential`]) is dropped the moment it is pushed: the name is
//! kept, so the header counts, and nothing that reads a [`Headers`] can
//! see the value, because it was never stored. That is the gate's one
//! structural guarantee about credentials, before any redaction of text.

/// The header names whose values never enter a [`Headers`]: what carries a
/// credential, by name or by suffix.
pub const CREDENTIAL_NAMES: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
    "x-goog-api-key",
    "api-key",
    "x-auth-token",
];

/// Whether `name` (lowercase) carries a credential: one of
/// [`CREDENTIAL_NAMES`], or a name ending in `-token`, `-secret` or
/// `-password`.
pub fn is_credential(name: &str) -> bool {
    CREDENTIAL_NAMES.contains(&name)
        || name.ends_with("-token")
        || name.ends_with("-secret")
        || name.ends_with("-password")
}

/// The most header bytes a message may carry before it is degraded.
pub const MAX_HEADERS_BYTES: usize = 64 * 1024;
/// The most bytes of one name or value.
pub const MAX_FIELD_BYTES: usize = 8 * 1024;

/// A message's headers in order, credential values left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, Option<Vec<u8>>)>,
    bytes: usize,
}

/// Why a header could not be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The headers would pass [`MAX_HEADERS_BYTES`], or a field
    /// [`MAX_FIELD_BYTES`].
    TooLarge,
}

impl Headers {
    pub fn new() -> Headers {
        Headers::default()
    }

    /// Adds `name: value`, the name lowercased, the value left out when the
    /// name carries a credential.
    pub fn push(&mut self, name: &str, value: &[u8]) -> Result<(), HeaderError> {
        if name.len() > MAX_FIELD_BYTES || value.len() > MAX_FIELD_BYTES {
            return Err(HeaderError::TooLarge);
        }
        let added = name.len() + value.len() + 4;
        if self.bytes + added > MAX_HEADERS_BYTES {
            return Err(HeaderError::TooLarge);
        }
        self.bytes += added;
        let name = name.to_ascii_lowercase();
        let kept = (!is_credential(&name)).then(|| value.to_vec());
        self.entries.push((name, kept));
        Ok(())
    }

    /// How many headers there are, credentials counted.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first value of `name` (lowercase), if it has one that may be
    /// seen.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    /// `get`, as text when it is UTF-8.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Every value of `name` that may be seen.
    pub fn get_all(&self, name: &str) -> Vec<&[u8]> {
        self.entries
            .iter()
            .filter(|(n, _)| n == name)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }

    /// Whether a header named `name` is there, credential or not.
    pub fn has(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n == name)
    }

    /// The names, in order, credentials included.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(n, _)| n.as_str())
    }

    /// The headers whose values may be seen, in order.
    pub fn visible(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .filter_map(|(n, v)| v.as_deref().map(|v| (n.as_str(), v)))
    }

    /// `Content-Length`, when it is one number.
    pub fn content_length(&self) -> Option<u64> {
        self.get_str("content-length")?.trim().parse().ok()
    }

    /// `Content-Type` as text, without its parameters, lowercase.
    pub fn content_type(&self) -> Option<String> {
        let value = self.get_str("content-type")?;
        Some(
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
        )
    }

    /// `Content-Encoding`, lowercase, trimmed.
    pub fn content_encoding(&self) -> Option<String> {
        self.get_str("content-encoding")
            .map(|v| v.trim().to_ascii_lowercase())
    }

    /// Whether `Transfer-Encoding` ends in `chunked`.
    pub fn chunked(&self) -> bool {
        self.get_str("transfer-encoding").is_some_and(|v| {
            v.split(',')
                .next_back()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
        })
    }

    /// Whether `Connection` lists `token` (case-insensitively).
    pub fn connection_has(&self, token: &str) -> bool {
        self.get_all("connection").iter().any(|value| {
            std::str::from_utf8(value).is_ok_and(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
        })
    }

    /// Whether the message asks to upgrade to WebSocket.
    pub fn upgrades_to_websocket(&self) -> bool {
        self.connection_has("upgrade")
            && self
                .get_str("upgrade")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"))
    }

    /// The `Sec-WebSocket-Extensions` offered or agreed, one per entry,
    /// lowercase, parameters kept.
    pub fn websocket_extensions(&self) -> Vec<String> {
        self.get_all("sec-websocket-extensions")
            .iter()
            .filter_map(|v| std::str::from_utf8(v).ok())
            .flat_map(|v| v.split(','))
            .map(|e| e.trim().to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_headers_never_leave_the_parser() {
        let mut h = Headers::new();
        h.push("Authorization", b"Bearer sk-ant-secret").unwrap();
        h.push("X-Api-Key", b"key-value").unwrap();
        h.push("Cookie", b"session=abc").unwrap();
        h.push("Proxy-Authorization", b"Basic xyz").unwrap();
        h.push("X-Foo-Token", b"tokval").unwrap();
        h.push("My-Secret", b"s").unwrap();
        h.push("Content-Type", b"application/json").unwrap();
        assert_eq!(h.len(), 7);
        assert!(h.has("authorization") && h.has("x-api-key") && h.has("cookie"));
        for name in [
            "authorization",
            "x-api-key",
            "cookie",
            "proxy-authorization",
            "x-foo-token",
            "my-secret",
        ] {
            assert_eq!(h.get(name), None, "{name}");
            assert!(h.get_all(name).is_empty(), "{name}");
        }
        let visible: Vec<(&str, &[u8])> = h.visible().collect();
        assert_eq!(visible, [("content-type", b"application/json".as_slice())]);
        // The values are not in the struct at all.
        let debug = format!("{h:?}");
        for secret in [
            "sk-ant-secret",
            "key-value",
            "session=abc",
            "Basic xyz",
            "tokval",
        ] {
            assert!(!debug.contains(secret), "{debug}");
        }
    }

    #[test]
    fn names_are_lowercased_and_read_as_http_does() {
        let mut h = Headers::new();
        h.push("Content-Length", b" 42 ").unwrap();
        h.push("Content-Type", b"Text/Event-Stream; charset=utf-8")
            .unwrap();
        h.push("Content-Encoding", b"GZIP").unwrap();
        h.push("Transfer-Encoding", b"gzip, Chunked").unwrap();
        h.push("Connection", b"keep-alive, Upgrade").unwrap();
        h.push("Upgrade", b"WebSocket").unwrap();
        h.push(
            "Sec-WebSocket-Extensions",
            b"permessage-deflate; client_max_window_bits, x-foo",
        )
        .unwrap();
        assert_eq!(h.content_length(), Some(42));
        assert_eq!(h.content_type().as_deref(), Some("text/event-stream"));
        assert_eq!(h.content_encoding().as_deref(), Some("gzip"));
        assert!(h.chunked());
        assert!(h.connection_has("upgrade") && h.connection_has("KEEP-ALIVE"));
        assert!(h.upgrades_to_websocket());
        assert_eq!(
            h.websocket_extensions(),
            ["permessage-deflate; client_max_window_bits", "x-foo"]
        );
        assert_eq!(h.names().collect::<Vec<_>>()[0], "content-length");
    }

    #[test]
    fn the_limits_hold() {
        let mut h = Headers::new();
        assert_eq!(
            h.push("x", &vec![b'a'; MAX_FIELD_BYTES + 1]),
            Err(HeaderError::TooLarge)
        );
        let value = vec![b'a'; MAX_FIELD_BYTES];
        for _ in 0..7 {
            h.push("x", &value).unwrap();
        }
        assert_eq!(h.push("x", &value), Err(HeaderError::TooLarge));
        assert_eq!(h.len(), 7);
    }
}
