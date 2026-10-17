// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Registry credentials and challenges: `~/.docker/config.json`'s `auths`,
//! `WWW-Authenticate` parsing, token responses, and the registry error
//! codes boxcar puts into words of its own. A credential is used to build
//! one header value and never appears in a message.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use base64::Engine as _;

/// A user and password for a registry.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    user: String,
    password: String,
}

impl Credentials {
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Credentials {
        Credentials {
            user: user.into(),
            password: password.into(),
        }
    }

    /// The one place a credential is spelled out: an `Authorization`
    /// header's value.
    pub fn basic_header(&self) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.user, self.password))
        )
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[credentials]")
    }
}

/// What `~/.docker/config.json` says about registries.
#[derive(Debug, Default)]
pub struct DockerConfig {
    auths: HashMap<String, Credentials>,
    creds_store: Option<String>,
    cred_helpers: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("the Docker config does not parse: {0}")]
    Json(String),
    #[error("the `auth` of `{0}` is not base64 `user:password`")]
    Auth(String),
}

impl DockerConfig {
    /// The config file: `$DOCKER_CONFIG/config.json`, else
    /// `~/.docker/config.json`.
    pub fn path() -> Option<PathBuf> {
        let absolute = |var: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        absolute("DOCKER_CONFIG")
            .map(|dir| dir.join("config.json"))
            .or_else(|| absolute("HOME").map(|home| home.join(".docker/config.json")))
    }

    /// Parses the file's text.
    pub fn parse(text: &str) -> Result<DockerConfig, AuthError> {
        #[derive(serde::Deserialize, Default)]
        struct RawAuth {
            #[serde(default)]
            auth: Option<String>,
            #[serde(default)]
            username: Option<String>,
            #[serde(default)]
            password: Option<String>,
        }
        #[derive(serde::Deserialize, Default)]
        struct Raw {
            #[serde(default)]
            auths: HashMap<String, RawAuth>,
            #[serde(rename = "credsStore", default)]
            creds_store: Option<String>,
            #[serde(rename = "credHelpers", default)]
            cred_helpers: HashMap<String, String>,
        }
        let raw: Raw =
            serde_json::from_str(text).map_err(|error| AuthError::Json(error.to_string()))?;
        let mut auths = HashMap::new();
        for (key, entry) in raw.auths {
            let credentials = match (entry.auth, entry.username, entry.password) {
                (Some(auth), _, _) => {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(auth.trim())
                        .map_err(|_| AuthError::Auth(key.clone()))?;
                    let text =
                        String::from_utf8(decoded).map_err(|_| AuthError::Auth(key.clone()))?;
                    let (user, password) = text
                        .split_once(':')
                        .ok_or_else(|| AuthError::Auth(key.clone()))?;
                    Credentials::new(user, password)
                }
                (None, Some(user), Some(password)) => Credentials::new(user, password),
                _ => continue,
            };
            auths.insert(key, credentials);
        }
        Ok(DockerConfig {
            auths,
            creds_store: raw.creds_store.filter(|s| !s.is_empty()),
            cred_helpers: raw.cred_helpers,
        })
    }

    /// The credentials for `registry`, from `auths`. `docker.io` is also
    /// looked up under the keys Docker writes for it.
    pub fn credentials_for(&self, registry: &str) -> Option<&Credentials> {
        keys_for(registry)
            .into_iter()
            .find_map(|key| self.auths.get(key))
    }

    /// The credential helper configured for `registry`, if any:
    /// `credHelpers[registry]`, else `credsStore`.
    pub fn helper_for(&self, registry: &str) -> Option<&str> {
        keys_for(registry)
            .into_iter()
            .find_map(|key| self.cred_helpers.get(key))
            .or(self.creds_store.as_ref())
            .map(String::as_str)
    }
}

/// The keys `registry` may be filed under: itself, and for Docker Hub
/// the names Docker writes for it.
fn keys_for(registry: &str) -> Vec<&str> {
    const HUB: [&str; 4] = [
        "https://index.docker.io/v1/",
        "index.docker.io",
        "docker.io",
        "registry-1.docker.io",
    ];
    if HUB.contains(&registry) {
        HUB.to_vec()
    } else {
        vec![registry]
    }
}

/// A `WWW-Authenticate` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
    Basic,
}

/// Parses a `WWW-Authenticate` header value; none for a scheme boxcar
/// does not speak.
pub fn parse_challenge(header: &str) -> Option<Challenge> {
    let header = header.trim();
    let (scheme, params) = match header.split_once(char::is_whitespace) {
        Some((scheme, params)) => (scheme, params.trim()),
        None => (header, ""),
    };
    if scheme.eq_ignore_ascii_case("basic") {
        return Some(Challenge::Basic);
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (key, value) in auth_params(params) {
        match key.to_ascii_lowercase().as_str() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }
    Some(Challenge::Bearer {
        realm: realm?,
        service,
        scope,
    })
}

/// `key=value` pairs separated by commas, values quoted or not, a quoted
/// value keeping its commas and spaces.
fn auth_params(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let rest_trim = rest.trim_start_matches([' ', ',']);
        let Some(eq) = rest_trim.find('=') else {
            break;
        };
        let key = rest_trim[..eq].trim().to_owned();
        let after = &rest_trim[eq + 1..];
        let (value, remainder) = if let Some(quoted) = after.strip_prefix('"') {
            match quoted.find('"') {
                Some(end) => (quoted[..end].to_owned(), &quoted[end + 1..]),
                None => (quoted.to_owned(), ""),
            }
        } else {
            match after.find(',') {
                Some(end) => (after[..end].trim().to_owned(), &after[end..]),
                None => (after.trim().to_owned(), ""),
            }
        };
        out.push((key, value));
        rest = remainder;
    }
    out
}

/// The token in a token endpoint's JSON body: `token`, else
/// `access_token`.
pub fn token_in(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    ["token", "access_token"]
        .into_iter()
        .find_map(|key| {
            value
                .get(key)
                .and_then(|t| t.as_str())
                .filter(|t| !t.is_empty())
        })
        .map(str::to_owned)
}

/// What a distribution error code means, in boxcar's words; a code
/// boxcar does not know is said to be one, never repeated.
pub fn describe_code(code: &str) -> &'static str {
    match code {
        "BLOB_UNKNOWN" => "the registry has no such blob",
        "BLOB_UPLOAD_UNKNOWN" => "the registry knows no such upload",
        "DENIED" => "the registry refused access",
        "DIGEST_INVALID" => "the registry says a digest is invalid",
        "MANIFEST_BLOB_UNKNOWN" => "the registry lacks a blob the manifest names",
        "MANIFEST_INVALID" => "the registry says the manifest is invalid",
        "MANIFEST_UNKNOWN" => "the registry has no such manifest",
        "NAME_INVALID" => "the registry says the repository name is invalid",
        "NAME_UNKNOWN" => "the registry has no such repository",
        "SIZE_INVALID" => "the registry says a size is invalid",
        "TAG_INVALID" => "the registry says the tag is invalid",
        "TOOMANYREQUESTS" => "the registry is rate limiting requests",
        "UNAUTHORIZED" => "the registry wants authentication",
        "UNSUPPORTED" => "the registry does not support the operation",
        _ => "an error the registry did not name",
    }
}

/// The `errors[].code` values of a registry error body, described.
pub fn describe_errors(body: &[u8]) -> Vec<&'static str> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    value
        .get("errors")
        .and_then(|e| e.as_array())
        .map(|errors| {
            errors
                .iter()
                .map(|e| describe_code(e.get("code").and_then(|c| c.as_str()).unwrap_or("")))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    #[test]
    fn credentials_print_nothing_and_make_one_header() {
        let c = Credentials::new("alice", "s3cret");
        assert_eq!(format!("{c:?}"), "[credentials]");
        assert_eq!(c.basic_header(), format!("Basic {}", b64("alice:s3cret")));
    }

    #[test]
    fn auths_come_as_auth_or_as_username_and_password() {
        let text = format!(
            r#"{{"auths": {{
                "ghcr.io": {{"auth": "{}"}},
                "registry.example:5000": {{"username": "bob", "password": "pw:with:colons"}},
                "https://index.docker.io/v1/": {{"auth": "{}"}}
            }}}}"#,
            b64("alice:s3cret"),
            b64("hub:token")
        );
        let config = DockerConfig::parse(&text).unwrap();
        assert_eq!(
            config.credentials_for("ghcr.io"),
            Some(&Credentials::new("alice", "s3cret"))
        );
        assert_eq!(
            config.credentials_for("registry.example:5000"),
            Some(&Credentials::new("bob", "pw:with:colons"))
        );
        for key in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
            assert_eq!(
                config.credentials_for(key),
                Some(&Credentials::new("hub", "token")),
                "{key}"
            );
        }
        assert_eq!(config.credentials_for("quay.io"), None);
        assert_eq!(config.helper_for("ghcr.io"), None);
        // A password with a colon in it is kept whole: the split is at the first colon.
        let text = format!(
            r#"{{"auths": {{"r.example": {{"auth": "{}"}}}}}}"#,
            b64("u:p:q")
        );
        assert_eq!(
            DockerConfig::parse(&text)
                .unwrap()
                .credentials_for("r.example"),
            Some(&Credentials::new("u", "p:q"))
        );
    }

    #[test]
    fn helpers_are_named_but_never_run() {
        let text = r#"{"auths": {"ghcr.io": {}}, "credsStore": "desktop", "credHelpers": {"gcr.io": "gcloud"}}"#;
        let config = DockerConfig::parse(text).unwrap();
        assert_eq!(
            config.credentials_for("ghcr.io"),
            None,
            "an empty auths entry is none"
        );
        assert_eq!(config.helper_for("gcr.io"), Some("gcloud"));
        assert_eq!(config.helper_for("ghcr.io"), Some("desktop"));
        let config = DockerConfig::parse("{}").unwrap();
        assert_eq!(config.helper_for("ghcr.io"), None);
    }

    #[test]
    fn a_bad_config_is_an_error_that_names_no_secret() {
        assert!(matches!(DockerConfig::parse("{"), Err(AuthError::Json(_))));
        let text = r#"{"auths": {"ghcr.io": {"auth": "not base64!"}}}"#;
        let err = DockerConfig::parse(text).unwrap_err();
        assert_eq!(err, AuthError::Auth("ghcr.io".into()));
        assert!(!err.to_string().contains("not base64!"));
        let text = format!(
            r#"{{"auths": {{"ghcr.io": {{"auth": "{}"}}}}}}"#,
            b64("nocolon")
        );
        assert_eq!(
            DockerConfig::parse(&text).unwrap_err(),
            AuthError::Auth("ghcr.io".into())
        );
    }

    #[test]
    fn challenges_parse_with_and_without_quotes() {
        assert_eq!(
            parse_challenge(
                r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#
            ),
            Some(Challenge::Bearer {
                realm: "https://auth.docker.io/token".into(),
                service: Some("registry.docker.io".into()),
                scope: Some("repository:library/alpine:pull".into()),
            })
        );
        assert_eq!(
            parse_challenge("bearer realm=https://t.example/token, scope=\"a b\""),
            Some(Challenge::Bearer {
                realm: "https://t.example/token".into(),
                service: None,
                scope: Some("a b".into()),
            })
        );
        assert_eq!(
            parse_challenge(r#"Basic realm="Registry""#),
            Some(Challenge::Basic)
        );
        assert_eq!(parse_challenge("Basic"), Some(Challenge::Basic));
        assert_eq!(
            parse_challenge("Bearer service=x"),
            None,
            "a bearer needs a realm"
        );
        assert_eq!(parse_challenge("Digest realm=x"), None);
        assert_eq!(parse_challenge(""), None);
    }

    #[test]
    fn a_token_is_token_or_access_token() {
        assert_eq!(
            token_in(br#"{"token": "abc", "expires_in": 300}"#),
            Some("abc".into())
        );
        assert_eq!(token_in(br#"{"access_token": "def"}"#), Some("def".into()));
        assert_eq!(
            token_in(br#"{"token": "abc", "access_token": "def"}"#),
            Some("abc".into())
        );
        assert_eq!(token_in(br#"{"token": ""}"#), None);
        assert_eq!(token_in(b"nope"), None);
    }

    #[test]
    fn error_codes_become_fixed_words_and_unknown_ones_are_not_repeated() {
        assert_eq!(
            describe_code("MANIFEST_UNKNOWN"),
            "the registry has no such manifest"
        );
        assert_eq!(
            describe_code("UNAUTHORIZED"),
            "the registry wants authentication"
        );
        assert_eq!(describe_code("DENIED"), "the registry refused access");
        assert_eq!(
            describe_code("TOOMANYREQUESTS"),
            "the registry is rate limiting requests"
        );
        let secret = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
        let unknown = describe_code(secret);
        assert_eq!(unknown, "an error the registry did not name");
        let body = format!(
            r#"{{"errors": [{{"code": "{secret}", "message": "{secret}"}}, {{"code": "NAME_UNKNOWN"}}]}}"#
        );
        let described = describe_errors(body.as_bytes());
        assert_eq!(
            described,
            [
                "an error the registry did not name",
                "the registry has no such repository"
            ]
        );
        assert!(!described.join(" ").contains("QWxhZGRpbj"));
        assert_eq!(describe_errors(b"<html>"), Vec::<&str>::new());
    }
}
