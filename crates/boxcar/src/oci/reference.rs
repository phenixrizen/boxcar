// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Image references, parsed as Docker parses them:
//! `[host[:port]/]path[:tag][@sha256:hex]`.

use std::fmt;

/// The most bytes a reference may have.
pub const MAX_LEN: usize = 255;

/// The registry a reference without one names.
pub const DEFAULT_REGISTRY: &str = "docker.io";

/// The host that serves `docker.io`'s distribution API.
pub const DOCKER_API_HOST: &str = "registry-1.docker.io";

/// A `sha256` digest: its 64 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    /// Parses `sha256:<64 hex>`.
    pub fn parse(text: &str) -> Result<Digest, ReferenceError> {
        let bad = || ReferenceError::Digest(text.to_owned());
        let hex = text.strip_prefix("sha256:").ok_or_else(bad)?;
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad());
        }
        Ok(Digest(hex.to_owned()))
    }

    /// The digest of a SHA-256 hash.
    pub fn of_hash(hash: &[u8]) -> Digest {
        let mut hex = String::with_capacity(hash.len() * 2);
        for byte in hash {
            hex.push_str(&format!("{byte:02x}"));
        }
        Digest(hex)
    }

    /// The hex digits.
    pub fn hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Digest, D::Error> {
        let text = String::deserialize(deserializer)?;
        Digest::parse(&text)
            .map_err(|_| serde::de::Error::custom("a digest is not `sha256:` and 64 hex digits"))
    }
}

/// A parsed reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    registry: String,
    repository: String,
    tag: Option<String>,
    digest: Option<Digest>,
}

/// Why a reference does not parse.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceError {
    #[error("the reference is longer than {MAX_LEN} bytes")]
    TooLong,
    #[error("the registry `{0}` is not a host name, with an optional port")]
    Registry(String),
    #[error("the repository `{0}` is not lowercase components separated by `/`")]
    Repository(String),
    #[error("the tag `{0}` is not up to 128 letters, digits, `_`, `.` or `-`")]
    Tag(String),
    #[error("the digest `{0}` is not `sha256:` and 64 hex digits")]
    Digest(String),
    #[error("the reference is empty")]
    Empty,
}

impl Reference {
    /// Parses `text`.
    pub fn parse(text: &str) -> Result<Reference, ReferenceError> {
        if text.is_empty() {
            return Err(ReferenceError::Empty);
        }
        if text.len() > MAX_LEN {
            return Err(ReferenceError::TooLong);
        }
        let (rest, digest) = match text.rsplit_once('@') {
            Some((rest, digest)) => (rest, Some(Digest::parse(digest)?)),
            None => (text, None),
        };
        // The first component is a registry when it looks like a host:
        // a dot, a port, or `localhost`.
        let (registry, path) = match rest.split_once('/') {
            Some((first, remainder))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (canonical_registry(first)?, remainder)
            }
            _ => (DEFAULT_REGISTRY.to_owned(), rest),
        };
        // A tag is what follows the last `:` of the last component.
        let (repository, tag) = match path.rfind(':') {
            Some(at) if !path[at + 1..].contains('/') => (&path[..at], Some(&path[at + 1..])),
            _ => (path, None),
        };
        let mut repository = valid_repository(repository)?;
        if registry == DEFAULT_REGISTRY && !repository.contains('/') {
            repository = format!("library/{repository}");
        }
        let tag = match (tag, &digest) {
            (Some(tag), _) => Some(valid_tag(tag)?),
            (None, None) => Some("latest".to_owned()),
            (None, Some(_)) => None,
        };
        Ok(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The registry, canonical (`docker.io` for the default and for
    /// `index.docker.io`).
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// The repository path, `library/` added on `docker.io` for a
    /// one-component path.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The tag: the one given, `latest` when neither a tag nor a digest
    /// was, none when only a digest was.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    // `vmm.start.image` (Task 3) records the digest a reference asked for.
    #[allow(dead_code)]
    pub fn digest(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }

    /// The host the registry's API is at.
    pub fn api_host(&self) -> &str {
        if self.registry == DEFAULT_REGISTRY {
            DOCKER_API_HOST
        } else {
            &self.registry
        }
    }

    /// What `/v2/<repository>/manifests/<this>` fetches: the digest when
    /// there is one, else the tag.
    pub fn manifest_reference(&self) -> String {
        match (&self.digest, &self.tag) {
            (Some(digest), _) => digest.to_string(),
            (None, Some(tag)) => tag.clone(),
            (None, None) => "latest".to_owned(),
        }
    }
}

/// `host[:port]`, lowercased, `index.docker.io` made `docker.io`.
fn canonical_registry(text: &str) -> Result<String, ReferenceError> {
    let bad = || ReferenceError::Registry(text.to_owned());
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || host.starts_with('.')
        || host.ends_with('.')
    {
        return Err(bad());
    }
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
    }
    let lower = text.to_ascii_lowercase();
    Ok(if lower == "index.docker.io" {
        DEFAULT_REGISTRY.to_owned()
    } else {
        lower
    })
}

/// A repository path: components of lowercase letters and digits joined by
/// `.`, `_`, `__` or one or more `-`, separated by `/`.
fn valid_repository(text: &str) -> Result<String, ReferenceError> {
    let bad = || ReferenceError::Repository(text.to_owned());
    if text.is_empty() {
        return Err(bad());
    }
    for component in text.split('/') {
        let bytes = component.as_bytes();
        if bytes.is_empty() || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return Err(bad());
        }
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_lowercase() || b.is_ascii_digit() {
                i += 1;
                continue;
            }
            // A separator: `.`, `_`, `__` or `-`+, followed by a word.
            let run = match b {
                b'.' => 1,
                b'_' => bytes[i..].iter().take_while(|c| **c == b'_').count(),
                b'-' => bytes[i..].iter().take_while(|c| **c == b'-').count(),
                _ => return Err(bad()),
            };
            if b == b'_' && run > 2 {
                return Err(bad());
            }
            i += run;
            match bytes.get(i) {
                Some(next) if next.is_ascii_lowercase() || next.is_ascii_digit() => {}
                _ => return Err(bad()),
            }
        }
    }
    Ok(text.to_owned())
}

/// A tag: a letter, digit or `_`, then up to 127 of those, `.` or `-`.
fn valid_tag(text: &str) -> Result<String, ReferenceError> {
    let bad = || ReferenceError::Tag(text.to_owned());
    let bytes = text.as_bytes();
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    match bytes.first() {
        Some(first) if word(*first) => {}
        _ => return Err(bad()),
    }
    if bytes.len() > 128
        || !bytes[1..]
            .iter()
            .all(|b| word(*b) || *b == b'.' || *b == b'-')
    {
        return Err(bad());
    }
    Ok(text.to_owned())
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parts(text: &str) -> (String, String, Option<String>, Option<String>) {
        let r = Reference::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        (
            r.registry().to_owned(),
            r.repository().to_owned(),
            r.tag().map(str::to_owned),
            r.digest().map(|d| d.hex().to_owned()),
        )
    }

    #[test]
    fn dockers_defaults_apply() {
        let latest = Some("latest".to_owned());
        assert_eq!(
            parts("alpine"),
            (
                "docker.io".into(),
                "library/alpine".into(),
                latest.clone(),
                None
            )
        );
        assert_eq!(
            parts("library/alpine"),
            (
                "docker.io".into(),
                "library/alpine".into(),
                latest.clone(),
                None
            )
        );
        assert_eq!(
            parts("docker.io/alpine:3.22"),
            (
                "docker.io".into(),
                "library/alpine".into(),
                Some("3.22".into()),
                None
            )
        );
        assert_eq!(
            parts("index.docker.io/library/alpine"),
            (
                "docker.io".into(),
                "library/alpine".into(),
                latest.clone(),
                None
            )
        );
        assert_eq!(
            parts("someuser/app"),
            ("docker.io".into(), "someuser/app".into(), latest, None)
        );
    }

    #[test]
    fn a_registry_is_a_first_component_with_a_dot_a_port_or_localhost() {
        assert_eq!(
            parts("localhost:5000/x"),
            (
                "localhost:5000".into(),
                "x".into(),
                Some("latest".into()),
                None
            )
        );
        assert_eq!(
            parts("localhost/x"),
            ("localhost".into(), "x".into(), Some("latest".into()), None)
        );
        assert_eq!(
            parts("host.example/a/b"),
            (
                "host.example".into(),
                "a/b".into(),
                Some("latest".into()),
                None
            )
        );
        assert_eq!(
            parts("host.example:8443/a/b:v1"),
            (
                "host.example:8443".into(),
                "a/b".into(),
                Some("v1".into()),
                None
            )
        );
        // No dot, no port, not localhost: a repository on docker.io.
        assert_eq!(
            parts("team/app"),
            (
                "docker.io".into(),
                "team/app".into(),
                Some("latest".into()),
                None
            )
        );
    }

    #[test]
    fn a_digest_names_what_is_fetched_and_a_tag_may_come_with_it() {
        let r = Reference::parse(&format!("host.example/a/b@sha256:{HEX}")).unwrap();
        assert_eq!(r.tag(), None);
        assert_eq!(r.digest().unwrap().hex(), HEX);
        assert_eq!(r.manifest_reference(), format!("sha256:{HEX}"));
        let r = Reference::parse(&format!("host.example/a/b:v1@sha256:{HEX}")).unwrap();
        assert_eq!(r.tag(), Some("v1"));
        assert_eq!(r.manifest_reference(), format!("sha256:{HEX}"));
        let r = Reference::parse("host.example/a/b:v1").unwrap();
        assert_eq!(r.manifest_reference(), "v1");
    }

    #[test]
    fn the_api_host_differs_only_for_docker_io() {
        assert_eq!(
            Reference::parse("alpine").unwrap().api_host(),
            DOCKER_API_HOST
        );
        assert_eq!(
            Reference::parse("index.docker.io/alpine")
                .unwrap()
                .api_host(),
            DOCKER_API_HOST
        );
        assert_eq!(
            Reference::parse("ghcr.io/a/b").unwrap().api_host(),
            "ghcr.io"
        );
        assert_eq!(
            Reference::parse("localhost:5000/x").unwrap().api_host(),
            "localhost:5000"
        );
    }

    #[test]
    fn what_docker_refuses_is_refused() {
        assert_eq!(Reference::parse(""), Err(ReferenceError::Empty));
        assert!(matches!(
            Reference::parse("Alpine"),
            Err(ReferenceError::Repository(_))
        ));
        assert!(matches!(
            Reference::parse("host.example/a//b"),
            Err(ReferenceError::Repository(_))
        ));
        assert!(matches!(
            Reference::parse("host.example/a/b:"),
            Err(ReferenceError::Tag(_))
        ));
        assert!(matches!(
            Reference::parse("host.example/a/b:.v1"),
            Err(ReferenceError::Tag(_))
        ));
        assert!(matches!(
            Reference::parse(&format!("host.example/a/b:{}", "t".repeat(129))),
            Err(ReferenceError::Tag(_))
        ));
        assert!(matches!(
            Reference::parse("host.example/a/b@sha256:abc"),
            Err(ReferenceError::Digest(_))
        ));
        assert!(matches!(
            Reference::parse("host.example/a/b@md5:abc"),
            Err(ReferenceError::Digest(_))
        ));
        assert!(matches!(
            Reference::parse("host_example.com/a"),
            Err(ReferenceError::Registry(_))
        ));
        let long = format!("host.example/{}", "a/".repeat(130));
        assert_eq!(
            Reference::parse(&long[..long.len() - 1]),
            Err(ReferenceError::TooLong)
        );
    }

    #[test]
    fn components_take_dockers_separators() {
        for ok in ["a.b/c_d/e__f/g-h/i--j", "a1/2b", "a_b"] {
            assert!(
                Reference::parse(&format!("host.example/{ok}")).is_ok(),
                "{ok}"
            );
        }
        for bad in ["a..b", "a___b", "_a", "a_", "a-", "-a", ".a", "a/", "/a"] {
            assert!(
                matches!(
                    Reference::parse(&format!("host.example/{bad}")),
                    Err(ReferenceError::Repository(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn display_is_the_canonical_form() {
        assert_eq!(
            Reference::parse("alpine").unwrap().to_string(),
            "docker.io/library/alpine:latest"
        );
        assert_eq!(
            Reference::parse(&format!("ghcr.io/a/b@sha256:{HEX}"))
                .unwrap()
                .to_string(),
            format!("ghcr.io/a/b@sha256:{HEX}")
        );
    }
}
