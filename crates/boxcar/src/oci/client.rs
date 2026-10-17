// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! HTTP to one registry: manifests and blobs by the distribution API,
//! bounded bodies, a deadline per transfer, and the token flow. A
//! challenge is honoured only from the registry's own origin, and
//! credentials go to two places only: the realm the registry's own
//! challenge named, and the registry's origin for Basic. Nothing a
//! registry sends is repeated in an error.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

use super::auth::{self, Challenge, Credentials, DockerConfig};
use super::manifest::{self, MAX_CONFIG, MAX_MANIFEST};
use super::reference::{Digest, Reference};

/// How long a connection, the resolution of a name, or a response's
/// headers may take, and the floor of a body's deadline.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// The least a body must flow for its deadline: 64 KiB/s.
pub const MIN_RATE: u64 = 64 * 1024;
/// The most bytes a token response may have.
pub const MAX_TOKEN: u64 = 64 * 1024;
/// The most redirects a request follows.
pub const MAX_REDIRECTS: u32 = 5;

/// A manifest as the registry answered it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestResponse {
    pub content_type: String,
    pub body: Vec<u8>,
    /// SHA-256 of `body`.
    pub digest: Digest,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{0}")]
    Transport(Transport),
    #[error("{registry}/{repository}: the {what} request answered {status}{}", describe(.codes))]
    Status {
        registry: String,
        repository: String,
        what: &'static str,
        status: u16,
        codes: Vec<&'static str>,
    },
    #[error("authentication failed for {registry}/{repository}{}", helper_hint(.helper))]
    Auth {
        registry: String,
        repository: String,
        helper: Option<String>,
    },
    #[error("a challenge came from somewhere other than {registry}; no credential was sent")]
    ChallengeFromElsewhere { registry: String },
    #[error("the registry's token realm is not https")]
    InsecureRealm,
    #[error("the token endpoint redirected")]
    TokenRedirect,
    #[error("the token response holds no token")]
    NoToken,
    #[error("the {what} is larger than {max} bytes")]
    TooLarge { what: &'static str, max: u64 },
    #[error("the {what}'s Content-Length ({length}) is not its size ({size})")]
    Length {
        what: &'static str,
        length: u64,
        size: u64,
    },
    #[error("the manifest's digest is {got}, not the {expected} asked for")]
    Digest { expected: Digest, got: Digest },
    #[error("the registry's Docker-Content-Digest does not match the manifest")]
    ContentDigest,
    #[error(transparent)]
    Manifest(#[from] manifest::ManifestError),
    #[error("writing the blob: {0}")]
    Write(#[source] io::Error),
}

/// What went wrong on the wire, in boxcar's words: a registry chooses
/// URLs and messages, and none of them is repeated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Transport {
    #[error("the host was not found")]
    HostNotFound,
    #[error("the connection failed")]
    ConnectionFailed,
    #[error("the TLS handshake failed")]
    Tls,
    #[error("the transfer timed out")]
    Timeout,
    #[error("the registry closed the connection")]
    Closed,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("the registry redirected to plain http")]
    PlainHttpRedirect,
    #[error("the body is larger than allowed")]
    BodyTooLarge,
    #[error("an HTTP protocol error")]
    Protocol,
    #[error("an I/O error")]
    Io,
}

impl Transport {
    fn io(error: &io::Error) -> Transport {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Transport::Timeout,
            io::ErrorKind::ConnectionRefused => Transport::ConnectionFailed,
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof => Transport::Closed,
            _ => Transport::Io,
        }
    }
}

fn describe(codes: &[&'static str]) -> String {
    if codes.is_empty() {
        String::new()
    } else {
        format!(": {}", codes.join("; "))
    }
}

fn helper_hint(helper: &Option<String>) -> String {
    match helper {
        Some(name) => format!(
            "; its credentials are in the helper `{name}`, which boxcar does not run: `docker login` \
             without a credential helper, or an `auths` entry in ~/.docker/config.json"
        ),
        None => String::new(),
    }
}

/// How the client authenticates, once the registry has said how.
#[derive(Debug, Default)]
enum Scheme {
    #[default]
    None,
    Bearer(String),
    Basic,
}

/// A client for one repository of one registry.
pub struct Client {
    agent: ureq::Agent,
    /// `https://host[:port]`: the registry's origin. A loopback registry
    /// starts as `http://`, and becomes `https://` when it declines plain
    /// HTTP, since a plain-HTTP server reading a TLS handshake may hold the
    /// connection until a timeout, while a TLS server reading plain HTTP
    /// closes it at once.
    base: String,
    registry: String,
    repository: String,
    credentials: Option<Credentials>,
    helper: Option<String>,
    scheme: Scheme,
    /// Whether the registry is on the loopback, where plain HTTP is
    /// allowed when TLS is declined, as Docker allows its insecure local
    /// registries.
    loopback: bool,
    timeout: Duration,
}

impl Client {
    /// A client for `reference`'s repository, over HTTPS with `roots`;
    /// a registry on `localhost` or `127.0.0.0/8` is spoken to over plain
    /// HTTP, as Docker's insecure-by-default rule for local registries,
    /// and over HTTPS when it declines that; nothing else is.
    /// with the credentials `config` has for its registry.
    pub fn new(
        reference: &Reference,
        roots: Vec<CertificateDer<'static>>,
        config: Option<&DockerConfig>,
    ) -> Result<Client, ClientError> {
        let roots: Vec<ureq::tls::Certificate<'static>> = roots
            .iter()
            .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
            .collect();
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .root_certs(RootCerts::new_with_certs(&roots))
            .build();
        Client::build(reference, config, tls, is_loopback(reference.api_host()))
    }

    fn build(
        reference: &Reference,
        config: Option<&DockerConfig>,
        tls: TlsConfig,
        loopback: bool,
    ) -> Result<Client, ClientError> {
        // Redirects are followed by hand (`get`), so that a loopback
        // client, which may speak plain HTTP to its registry, is still
        // refused a plain-HTTP redirect anywhere else.
        let agent = ureq::config::Config::builder()
            .https_only(!loopback)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .user_agent(format!("boxcar/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(tls)
            .timeout_resolve(Some(TIMEOUT))
            .timeout_connect(Some(TIMEOUT))
            .timeout_recv_response(Some(TIMEOUT))
            .build()
            .new_agent();
        let (credentials, helper) = match config {
            Some(config) => (
                config.credentials_for(reference.registry()).cloned(),
                config.helper_for(reference.registry()).map(str::to_owned),
            ),
            None => (None, None),
        };
        Ok(Client {
            agent,
            base: format!(
                "{}://{}",
                if loopback { "http" } else { "https" },
                reference.api_host()
            ),
            registry: reference.registry().to_owned(),
            repository: reference.repository().to_owned(),
            credentials,
            helper,
            scheme: Scheme::None,
            loopback,
            timeout: TIMEOUT,
        })
    }

    /// Shortens the body deadline's floor, so a test of a stall ends soon.
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Client {
        self.timeout = timeout;
        self
    }

    /// `GET /v2/<repository>/manifests/<reference>`: the body (at most 4
    /// MiB), its type and its digest, checked against `Docker-Content-
    /// Digest` and, when `reference` is a digest, against that.
    pub fn manifest(&mut self, reference: &str) -> Result<ManifestResponse, ClientError> {
        let path = format!("/v2/{}/manifests/{reference}", self.repository);
        let mut response = self.get(&path, Some(manifest::ACCEPT), "manifest", self.timeout)?;
        if let Some(length) = content_length(&response) {
            if length > MAX_MANIFEST {
                return Err(ClientError::TooLarge {
                    what: "manifest",
                    max: MAX_MANIFEST,
                });
            }
        }
        let content_type = header(&response, "content-type").unwrap_or_default();
        let said = header(&response, "docker-content-digest");
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_MANIFEST)
            .read_to_vec()
            .map_err(|error| body_error(error, "manifest", MAX_MANIFEST))?;
        let digest = sha256(&body);
        if let Ok(expected) = Digest::parse(reference) {
            if expected != digest {
                return Err(ClientError::Digest {
                    expected,
                    got: digest,
                });
            }
        }
        if let Some(said) = said {
            if Digest::parse(said.trim()).ok() != Some(digest.clone()) {
                return Err(ClientError::ContentDigest);
            }
        }
        Ok(ManifestResponse {
            content_type,
            body,
            digest,
        })
    }

    /// `GET /v2/<repository>/blobs/<digest>`, streamed to `out`: exactly
    /// `size` bytes, no more read. What arrives is the caller's to verify.
    pub fn blob_to(
        &mut self,
        digest: &Digest,
        size: u64,
        out: &mut dyn Write,
    ) -> Result<(), ClientError> {
        let path = format!("/v2/{}/blobs/{digest}", self.repository);
        let deadline = self.timeout + Duration::from_secs(size / MIN_RATE);
        let mut response = self.get(&path, None, "blob", deadline)?;
        if let Some(length) = content_length(&response) {
            if length != size {
                return Err(ClientError::Length {
                    what: "blob",
                    length,
                    size,
                });
            }
        }
        let mut reader = response.body_mut().as_reader().take(size);
        let mut buf = vec![0u8; 64 * 1024];
        let mut copied = 0u64;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|error| ClientError::Transport(Transport::io(&error)))?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(ClientError::Write)?;
            copied += n as u64;
        }
        if copied != size {
            return Err(ClientError::Length {
                what: "blob",
                length: copied,
                size,
            });
        }
        Ok(())
    }

    /// The config blob, at most 1 MiB, verified against `digest`.
    pub fn config(&mut self, digest: &Digest, size: u64) -> Result<Vec<u8>, ClientError> {
        if size > MAX_CONFIG {
            return Err(ClientError::TooLarge {
                what: "config",
                max: MAX_CONFIG,
            });
        }
        let mut body = Vec::with_capacity(size as usize);
        self.blob_to(digest, size, &mut body)?;
        let got = sha256(&body);
        if got != *digest {
            return Err(ClientError::Digest {
                expected: digest.clone(),
                got,
            });
        }
        Ok(body)
    }

    /// `GET <base><path>`, the token flow included; the response when it
    /// is a 200.
    fn get(
        &mut self,
        path: &str,
        accept: Option<&str>,
        what: &'static str,
        body_timeout: Duration,
    ) -> Result<ureq::http::Response<ureq::Body>, ClientError> {
        let mut url = format!("{}{path}", self.base);
        let mut authenticated = false;
        let mut hops = 0;
        loop {
            // Credentials go to the registry's own origin, never to where
            // a redirect sent the request.
            let at_registry = self.at_registry(&url);
            let mut request = self
                .agent
                .get(&url)
                .config()
                .timeout_recv_body(Some(body_timeout))
                .build();
            if let Some(accept) = accept {
                request = request.header("Accept", accept);
            }
            if at_registry {
                match &self.scheme {
                    Scheme::Bearer(token) => {
                        request = request.header("Authorization", format!("Bearer {token}"));
                    }
                    Scheme::Basic => {
                        if let Some(credentials) = &self.credentials {
                            request = request.header("Authorization", credentials.basic_header());
                        }
                    }
                    Scheme::None => {}
                }
            }
            let mut response = match request.call() {
                Ok(response) => response,
                // A loopback registry that declines plain HTTP (a TLS server
                // closes the connection on it, or answers no HTTP): HTTPS
                // from here on.
                Err(error)
                    if self.loopback
                        && hops == 0
                        && !authenticated
                        && self.base.starts_with("http://")
                        && matches!(
                            classify(&error),
                            Transport::Tls | Transport::Closed | Transport::Protocol
                        ) =>
                {
                    self.base = format!("https://{}", &self.base["http://".len()..]);
                    url = format!("{}{path}", self.base);
                    continue;
                }
                Err(error) => return Err(transport(error)),
            };
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return Err(ClientError::Transport(Transport::TooManyRedirects));
                }
                let location = header(&response, "location")
                    .ok_or(ClientError::Transport(Transport::Protocol))?;
                url = redirect_target(&url, &location)?;
                continue;
            }
            if status == 401 {
                if authenticated {
                    return Err(self.auth_failed());
                }
                if !at_registry {
                    return Err(ClientError::ChallengeFromElsewhere {
                        registry: self.registry.clone(),
                    });
                }
                let challenge = header(&response, "www-authenticate")
                    .and_then(|h| auth::parse_challenge(&h))
                    .ok_or_else(|| self.auth_failed())?;
                match challenge {
                    Challenge::Bearer {
                        realm,
                        service,
                        scope,
                    } => {
                        let token = self.token(&realm, service.as_deref(), scope.as_deref())?;
                        self.scheme = Scheme::Bearer(token);
                    }
                    Challenge::Basic => {
                        if self.credentials.is_none() {
                            return Err(self.auth_failed());
                        }
                        self.scheme = Scheme::Basic;
                    }
                }
                authenticated = true;
                continue;
            }
            if status != 200 {
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(MAX_TOKEN)
                    .read_to_vec()
                    .unwrap_or_default();
                return Err(ClientError::Status {
                    registry: self.registry.clone(),
                    repository: self.repository.clone(),
                    what,
                    status,
                    codes: auth::describe_errors(&body),
                });
            }
            return Ok(response);
        }
    }

    /// The token the realm gives, with the credentials when there are any.
    fn token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: Option<&str>,
    ) -> Result<String, ClientError> {
        let uri: ureq::http::Uri = realm.parse().map_err(|_| ClientError::InsecureRealm)?;
        let secure = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => self.loopback && uri.host().is_some_and(is_loopback),
            _ => false,
        };
        if !secure {
            return Err(ClientError::InsecureRealm);
        }
        let mut url = realm.to_owned();
        let mut sep = if realm.contains('?') { '&' } else { '?' };
        for (key, value) in [("service", service), ("scope", scope)] {
            if let Some(value) = value {
                url.push(sep);
                url.push_str(key);
                url.push('=');
                url.push_str(value);
                sep = '&';
            }
        }
        let mut request = self
            .agent
            .get(&url)
            .config()
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_recv_body(Some(TIMEOUT))
            .build();
        if let Some(credentials) = &self.credentials {
            request = request.header("Authorization", credentials.basic_header());
        }
        let mut response = request.call().map_err(transport)?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(ClientError::TokenRedirect);
        }
        if status != 200 {
            return Err(self.auth_failed());
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_TOKEN)
            .read_to_vec()
            .map_err(|error| body_error(error, "token", MAX_TOKEN))?;
        auth::token_in(&body).ok_or(ClientError::NoToken)
    }

    fn auth_failed(&self) -> ClientError {
        ClientError::Auth {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            helper: self.helper.clone(),
        }
    }

    /// Whether the URL `url` is at the registry's own origin.
    fn at_registry(&self, url: &str) -> bool {
        url.parse::<ureq::http::Uri>()
            .map(|uri| self.same_origin(&uri))
            .unwrap_or(false)
    }

    /// Whether `uri` is at the registry's own origin.
    fn same_origin(&self, uri: &ureq::http::Uri) -> bool {
        let Ok(base) = self.base.parse::<ureq::http::Uri>() else {
            return false;
        };
        let port = |u: &ureq::http::Uri| {
            u.port_u16().or_else(|| match u.scheme_str() {
                Some("https") => Some(443),
                Some("http") => Some(80),
                _ => None,
            })
        };
        uri.scheme_str() == base.scheme_str()
            && uri.host().map(str::to_ascii_lowercase) == base.host().map(str::to_ascii_lowercase)
            && port(uri) == port(&base)
    }
}

/// Whether `host` (with or without a port) is the loopback: `localhost`
/// or an address in `127.0.0.0/8`.
fn is_loopback(host: &str) -> bool {
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
    host == "localhost"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|addr| addr.is_loopback())
}

/// Where a redirect from `from` with `location` goes: an absolute `https`
/// URL, or a plain-HTTP one on the loopback; anything else is refused in
/// boxcar's words, the location itself never repeated.
fn redirect_target(from: &str, location: &str) -> Result<String, ClientError> {
    let refused = || ClientError::Transport(Transport::Protocol);
    let from_uri: ureq::http::Uri = from.parse().map_err(|_| refused())?;
    let target = if location.starts_with('/') {
        let authority = from_uri.authority().ok_or_else(refused)?;
        let scheme = from_uri.scheme_str().ok_or_else(refused)?;
        format!("{scheme}://{authority}{location}")
    } else {
        location.to_owned()
    };
    let uri: ureq::http::Uri = target.parse().map_err(|_| refused())?;
    let host = uri.host().ok_or_else(refused)?;
    match uri.scheme_str() {
        Some("https") => Ok(target),
        Some("http") if is_loopback(host) => Ok(target),
        Some("http") => Err(ClientError::Transport(Transport::PlainHttpRedirect)),
        _ => Err(refused()),
    }
}

fn header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn content_length(response: &ureq::http::Response<ureq::Body>) -> Option<u64> {
    header(response, "content-length").and_then(|v| v.trim().parse().ok())
}

fn sha256(data: &[u8]) -> Digest {
    Digest::of_hash(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

fn transport(error: ureq::Error) -> ClientError {
    ClientError::Transport(classify(&error))
}

/// What went wrong on the wire, in boxcar's words.
fn classify(error: &ureq::Error) -> Transport {
    match error {
        ureq::Error::HostNotFound => Transport::HostNotFound,
        ureq::Error::ConnectionFailed => Transport::ConnectionFailed,
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::Pem(_) => Transport::Tls,
        ureq::Error::Timeout(_) => Transport::Timeout,
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => Transport::TooManyRedirects,
        ureq::Error::RequireHttpsOnly(_) => Transport::PlainHttpRedirect,
        ureq::Error::BodyExceedsLimit(_) => Transport::BodyTooLarge,
        ureq::Error::Io(error) => Transport::io(error),
        _ => Transport::Protocol,
    }
}

fn body_error(error: ureq::Error, what: &'static str, max: u64) -> ClientError {
    match error {
        ureq::Error::BodyExceedsLimit(_) => ClientError::TooLarge { what, max },
        other => transport(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxcar_testreg::{config, layer_tar, tar_of, Auth, Faults, Registry, Tls};

    fn reference(registry: &Registry) -> Reference {
        Reference::parse(&format!("{}/library/app:latest", registry.host())).unwrap()
    }

    fn anon(registry: &Registry) -> Client {
        Client::new(&reference(registry), vec![], None).unwrap()
    }

    fn docker_config(registry: &Registry, user: &str, password: &str) -> DockerConfig {
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{user}:{password}"),
        );
        DockerConfig::parse(&format!(
            r#"{{"auths": {{"{}": {{"auth": "{auth}"}}}}}}"#,
            registry.host()
        ))
        .unwrap()
    }

    /// An image of one layer in `registry`; the manifest digest and the layer.
    fn image(registry: &Registry) -> (String, boxcar_testreg::Blob) {
        let layer = layer_tar(&tar_of(&[("hello", b"hi")]));
        let config = config(&[], &["/bin/sh"], &[], "/");
        let digest = registry.put_image(
            "library/app",
            "latest",
            &config,
            std::slice::from_ref(&layer),
        );
        (digest, layer)
    }

    #[test]
    fn a_manifest_comes_with_its_type_and_digest_and_is_asked_for_properly() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (digest, _) = image(&registry);
        let mut client = anon(&registry);
        let m = client.manifest("latest").unwrap();
        assert_eq!(m.content_type, boxcar_testreg::OCI_MANIFEST);
        assert_eq!(m.digest.to_string(), digest);
        assert!(matches!(
            manifest::parse_document(&m.content_type, &m.body).unwrap(),
            manifest::Document::Manifest(_)
        ));
        let request = &registry.requests()[0];
        assert_eq!(request.path, "/v2/library/app/manifests/latest");
        assert_eq!(request.header("accept"), Some(manifest::ACCEPT));
        assert!(request
            .header("user-agent")
            .is_some_and(|ua| ua.starts_with("boxcar/")));
        // By digest: the same bytes; the digest asked for must be what comes.
        let by_digest = client.manifest(&digest).unwrap();
        assert_eq!(by_digest.body, m.body);
        let other = boxcar_testreg::sha256(b"other");
        let registry2 = Registry::start(Auth::None, Faults::default());
        let (real, _) = image(&registry2);
        // Name the real manifest under a digest it is not.
        registry2.put_manifest(
            "library/app",
            &other,
            &boxcar_testreg::manifest(&config(&[], &[], &[], "/"), &[]),
        );
        let mut client2 = anon(&registry2);
        let err = client2.manifest(&other).unwrap_err();
        assert!(matches!(err, ClientError::Digest { .. }), "{err}");
        let _ = real;
    }

    #[test]
    fn docker_content_digest_must_agree() {
        let registry = Registry::start(
            Auth::None,
            Faults {
                lie_content_digest: true,
                ..Faults::default()
            },
        );
        image(&registry);
        let err = anon(&registry).manifest("latest").unwrap_err();
        assert!(matches!(err, ClientError::ContentDigest), "{err}");
    }

    #[test]
    fn a_blob_streams_to_the_writer_with_its_length_checked() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (_, layer) = image(&registry);
        let digest = Digest::parse(&layer.digest()).unwrap();
        let mut client = anon(&registry);
        let mut out = Vec::new();
        client
            .blob_to(&digest, layer.data.len() as u64, &mut out)
            .unwrap();
        assert_eq!(out, layer.data);
        // A size the manifest got wrong: the Content-Length disagrees.
        let err = client
            .blob_to(&digest, layer.data.len() as u64 + 1, &mut Vec::new())
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Length { what: "blob", .. }),
            "{err}"
        );
        // A server whose Content-Length lies.
        registry.set_faults(Faults {
            short_length: vec![layer.digest()],
            ..Faults::default()
        });
        let err = client
            .blob_to(&digest, layer.data.len() as u64, &mut Vec::new())
            .unwrap_err();
        assert!(matches!(err, ClientError::Length { .. }), "{err}");
    }

    #[test]
    fn the_config_is_fetched_and_verified() {
        let registry = Registry::start(Auth::None, Faults::default());
        let cfg = config(&["A=1"], &[], &[], "/");
        let digest = Digest::parse(&registry.put_blob(&cfg)).unwrap();
        let mut client = anon(&registry);
        assert_eq!(
            client.config(&digest, cfg.data.len() as u64).unwrap(),
            cfg.data
        );
        registry.set_faults(Faults {
            corrupt: vec![cfg.digest()],
            ..Faults::default()
        });
        let err = client.config(&digest, cfg.data.len() as u64).unwrap_err();
        assert!(matches!(err, ClientError::Digest { .. }), "{err}");
    }

    #[test]
    fn an_anonymous_token_is_fetched_once_and_used() {
        let registry = Registry::start(
            Auth::Bearer {
                token: "t0k3n".into(),
                credentials: None,
            },
            Faults::default(),
        );
        let (_, layer) = image(&registry);
        let mut client = anon(&registry);
        client.manifest("latest").unwrap();
        client
            .blob_to(
                &Digest::parse(&layer.digest()).unwrap(),
                layer.data.len() as u64,
                &mut Vec::new(),
            )
            .unwrap();
        let paths: Vec<String> = registry.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(
            paths,
            [
                "/v2/library/app/manifests/latest".to_owned(),
                "/token?service=testreg&scope=repository:x:pull".to_owned(),
                "/v2/library/app/manifests/latest".to_owned(),
                format!("/v2/library/app/blobs/{}", layer.digest()),
            ]
        );
        let requests = registry.requests();
        assert_eq!(
            requests[1].header("authorization"),
            None,
            "anonymous: no Basic to the realm"
        );
        assert_eq!(requests[2].header("authorization"), Some("Bearer t0k3n"));
        assert_eq!(
            requests[3].header("authorization"),
            Some("Bearer t0k3n"),
            "the token is kept"
        );
    }

    #[test]
    fn credentials_go_to_the_realm_as_basic_and_nowhere_else() {
        let registry = Registry::start(
            Auth::Bearer {
                token: "t0k3n".into(),
                credentials: Some(("alice".into(), "pw".into())),
            },
            Faults::default(),
        );
        image(&registry);
        let config = docker_config(&registry, "alice", "pw");
        let mut client = Client::new(&reference(&registry), vec![], Some(&config)).unwrap();
        client.manifest("latest").unwrap();
        let requests = registry.requests();
        let basic = format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:pw")
        );
        assert_eq!(requests[1].path.split('?').next(), Some("/token"));
        assert_eq!(requests[1].header("authorization"), Some(basic.as_str()));
        for request in [&requests[0], &requests[2]] {
            assert_ne!(
                request.header("authorization"),
                Some(basic.as_str()),
                "{request:?}"
            );
        }
        // Wrong credentials: the failure names the registry, never them.
        let wrong = docker_config(&registry, "alice", "nope");
        let mut client = Client::new(&reference(&registry), vec![], Some(&wrong)).unwrap();
        let err = client.manifest("latest").unwrap_err();
        assert!(matches!(err, ClientError::Auth { .. }), "{err}");
        let text = err.to_string();
        assert!(text.contains("authentication failed"), "{text}");
        assert!(!text.contains("nope") && !text.contains("alice"), "{text}");
    }

    #[test]
    fn a_basic_challenge_is_answered_with_basic_once() {
        let registry = Registry::start(Auth::Basic("bob".into(), "pw".into()), Faults::default());
        image(&registry);
        let config = docker_config(&registry, "bob", "pw");
        let mut client = Client::new(&reference(&registry), vec![], Some(&config)).unwrap();
        client.manifest("latest").unwrap();
        let requests = registry.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1]
            .header("authorization")
            .is_some_and(|a| a.starts_with("Basic ")));
        // Without credentials there is nothing to answer with.
        let err = anon(&registry).manifest("latest").unwrap_err();
        assert!(
            matches!(err, ClientError::Auth { helper: None, .. }),
            "{err}"
        );
    }

    #[test]
    fn a_helper_is_named_when_it_holds_the_credentials() {
        let registry = Registry::start(
            Auth::Bearer {
                token: "t".into(),
                credentials: Some(("alice".into(), "pw".into())),
            },
            Faults::default(),
        );
        image(&registry);
        let config = DockerConfig::parse(&format!(
            r#"{{"credHelpers": {{"{}": "gcloud"}}}}"#,
            registry.host()
        ))
        .unwrap();
        let mut client = Client::new(&reference(&registry), vec![], Some(&config)).unwrap();
        let err = client.manifest("latest").unwrap_err();
        assert!(
            matches!(err, ClientError::Auth { helper: Some(ref h), .. } if h == "gcloud"),
            "{err}"
        );
        assert!(err.to_string().contains("gcloud"), "{err}");
    }

    #[test]
    fn a_challenge_from_a_redirect_target_gets_nothing() {
        // The CDN challenges every request; the registry redirects blobs to it.
        let cdn = Registry::start(
            Auth::None,
            Faults {
                always_challenge: true,
                ..Faults::default()
            },
        );
        let registry = Registry::start(
            Auth::None,
            Faults {
                redirect_blobs_to: Some(cdn.url()),
                ..Faults::default()
            },
        );
        let (_, layer) = image(&registry);
        let config = docker_config(&registry, "alice", "pw");
        let mut client = Client::new(&reference(&registry), vec![], Some(&config)).unwrap();
        let err = client
            .blob_to(
                &Digest::parse(&layer.digest()).unwrap(),
                layer.data.len() as u64,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(
            matches!(err, ClientError::ChallengeFromElsewhere { .. }),
            "{err}"
        );
        for request in cdn.requests() {
            assert_eq!(request.header("authorization"), None, "{request:?}");
            assert!(!request.path.starts_with("/token"), "{request:?}");
        }
    }

    #[test]
    fn the_token_endpoint_may_not_redirect_nor_be_plain_http_off_the_loopback() {
        let registry = Registry::start(
            Auth::Bearer {
                token: "t".into(),
                credentials: None,
            },
            Faults {
                token_redirect: Some("http://elsewhere.example/token".into()),
                ..Faults::default()
            },
        );
        image(&registry);
        let err = anon(&registry).manifest("latest").unwrap_err();
        assert!(matches!(err, ClientError::TokenRedirect), "{err}");
        registry.set_faults(Faults {
            realm: Some("http://registry.example/token".into()),
            ..Faults::default()
        });
        let before = registry.requests().len();
        let err = anon(&registry).manifest("latest").unwrap_err();
        assert!(matches!(err, ClientError::InsecureRealm), "{err}");
        assert!(registry.requests()[before..]
            .iter()
            .all(|r| !r.path.starts_with("/token")));
    }

    #[test]
    fn errors_say_the_status_in_boxcars_words_and_repeat_nothing() {
        let registry = Registry::start(
            Auth::None,
            Faults {
                echo_authorization: true,
                ..Faults::default()
            },
        );
        let mut client = anon(&registry);
        let err = client.manifest("missing").unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, ClientError::Status { status: 404, .. }),
            "{err}"
        );
        assert!(
            text.contains("an error the registry did not name"),
            "{text}"
        );
        // With a known code the words are boxcar's.
        registry.set_faults(Faults::default());
        let err = client.manifest("missing").unwrap_err();
        assert!(err.to_string().contains("no such manifest"), "{err}");
    }

    #[test]
    fn a_stalled_body_ends_at_its_deadline() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (_, layer) = image(&registry);
        registry.set_faults(Faults {
            stall: vec![layer.digest()],
            ..Faults::default()
        });
        let mut client = anon(&registry).with_timeout(Duration::from_millis(300));
        let started = std::time::Instant::now();
        let err = client
            .blob_to(
                &Digest::parse(&layer.digest()).unwrap(),
                layer.data.len() as u64,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(matches!(err, ClientError::Transport(_)), "{err}");
    }

    #[test]
    fn a_transport_error_repeats_no_url_the_registry_chose() {
        let tls = Tls::new();
        let ca = CertificateDer::from(tls.ca_der.clone());
        let registry = Registry::start_tls(
            Auth::None,
            Faults {
                redirect_blobs_to: Some("http://registry.example/cdn".into()),
                ..Faults::default()
            },
            tls,
        );
        let (_, layer) = image(&registry);
        let mut client = Client::new(&reference(&registry), vec![ca], None).unwrap();
        let err = client
            .blob_to(
                &Digest::parse(&layer.digest()).unwrap(),
                layer.data.len() as u64,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Transport(Transport::PlainHttpRedirect)),
            "{err}"
        );
        let text = format!("{err} {err:?}");
        assert!(!text.contains("registry.example"), "{text}");
    }

    #[test]
    fn tls_needs_the_registrys_ca_among_the_roots() {
        let tls = Tls::new();
        let ca = CertificateDer::from(tls.ca_der.clone());
        let registry = Registry::start_tls(Auth::None, Faults::default(), tls);
        let (digest, _) = image(&registry);
        let reference = reference(&registry);
        let mut client = Client::new(&reference, vec![ca], None).unwrap();
        assert_eq!(
            client.manifest("latest").unwrap().digest.to_string(),
            digest
        );
        let other = CertificateDer::from(Tls::new().ca_der);
        let mut client = Client::new(&reference, vec![other], None).unwrap();
        let err = client.manifest("latest").unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err}");
    }
}
