// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Sending an OTLP/JSON export to a collector (`boxcar audit export
//! --otlp-endpoint URL`): one POST of the export's bytes to `URL/v1/traces`,
//! with `Content-Type: application/json`, over the registry client's TLS
//! for `https` (rustls, the host's roots; plain `http` loads none), no
//! redirects, and one deadline for the whole exchange. Nothing is retried.
//!
//! The URL is `http` or `https`, with no user or password (a credential
//! must not land in an error or a shell's history) and no query or
//! fragment. A collector answers 200 with an `ExportTraceServiceResponse`;
//! a `partialSuccess` that rejected spans is a failure, and so is any other
//! status: OTLP/HTTP has that one success, and a 202 or 204 is not taken
//! for it.

use std::io::Read;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use serde_json::Value;
use ureq::http::Uri;

use crate::oci::client::tls_config;

/// The path a collector takes traces at.
const TRACES: &str = "/v1/traces";
/// How long the whole exchange may take.
pub const DEADLINE: Duration = Duration::from_secs(60);
/// The most of a response's body read.
const MAX_BODY: u64 = 64 * 1024;
/// The most of a failed response's body shown.
const SHOWN: usize = 512;

/// Why an endpoint was refused, before anything was read or sent.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UrlError {
    #[error("--otlp-endpoint {0}: not a URL")]
    NotAUrl(String),
    #[error("--otlp-endpoint: only http and https URLs are taken")]
    Scheme,
    #[error("--otlp-endpoint: a URL with a user or password is refused")]
    Userinfo,
    #[error("--otlp-endpoint: a URL with a query or a fragment is refused")]
    Query,
}

/// Where traces are POSTed: the endpoint with `/v1/traces` on its path.
#[derive(Debug, PartialEq, Eq)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn parse(text: &str) -> Result<Endpoint, UrlError> {
        if text.contains('#') {
            return Err(UrlError::Query);
        }
        let uri: Uri = text
            .parse()
            .map_err(|_| UrlError::NotAUrl(text.to_owned()))?;
        let scheme = uri.scheme_str().ok_or(UrlError::Scheme)?;
        if scheme != "http" && scheme != "https" {
            return Err(UrlError::Scheme);
        }
        let authority = uri
            .authority()
            .ok_or_else(|| UrlError::NotAUrl(text.to_owned()))?;
        if authority.as_str().contains('@') {
            return Err(UrlError::Userinfo);
        }
        if uri.query().is_some() {
            return Err(UrlError::Query);
        }
        let path = uri.path();
        let path = if path.ends_with(TRACES) {
            path.to_owned()
        } else {
            format!("{}{TRACES}", path.trim_end_matches('/'))
        };
        Ok(Endpoint(format!("{scheme}://{authority}{path}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the POST is over TLS, and so needs a trust store.
    pub fn is_https(&self) -> bool {
        self.0.starts_with("https://")
    }
}

/// How a POST went that the collector answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every span taken; a message the collector sent along, if any.
    Accepted(Option<String>),
    /// Refused, with why.
    Refused(String),
}

/// POSTs `body` to `endpoint`, trusting `roots` (for `https`; plain `http`
/// needs none), within `deadline` (the CLI's is [`DEADLINE`]). An error is
/// one the exchange itself met (no
/// answer in time, say); a refusal is in the [`Outcome`].
pub fn post(
    endpoint: &Endpoint,
    body: &[u8],
    roots: &[CertificateDer<'static>],
    deadline: Duration,
) -> Result<Outcome, ureq::Error> {
    let agent = ureq::config::Config::builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .user_agent(format!("boxcar/{}", env!("CARGO_PKG_VERSION")))
        .tls_config(tls_config(roots))
        .timeout_global(Some(deadline))
        .build()
        .new_agent();
    let mut response = agent
        .post(endpoint.as_str())
        .header("Content-Type", "application/json")
        .send(body)?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BODY)
        .read_to_end(&mut bytes)
        .map_err(ureq::Error::Io)?;
    Ok(outcome(status, &bytes))
}

/// What a collector's answer means.
pub fn outcome(status: u16, body: &[u8]) -> Outcome {
    if status != 200 {
        let shown = String::from_utf8_lossy(&body[..body.len().min(SHOWN)]).into_owned();
        return Outcome::Refused(format!("HTTP {status}: {}", shown.trim()));
    }
    if body.iter().all(u8::is_ascii_whitespace) {
        return Outcome::Accepted(None);
    }
    let Ok(Value::Object(answer)) = serde_json::from_slice::<Value>(body) else {
        return Outcome::Refused(
            "HTTP 200 with a body that is not a JSON object: not an OTLP receiver".into(),
        );
    };
    let Some(partial) = answer.get("partialSuccess") else {
        return Outcome::Accepted(None);
    };
    let rejected = match partial.get("rejectedSpans") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    let message = partial
        .get("errorMessage")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .map(str::to_owned);
    if rejected > 0 {
        Outcome::Refused(format!(
            "the collector rejected {rejected} spans{}",
            message.map(|m| format!(": {m}")).unwrap_or_default()
        ))
    } else {
        Outcome::Accepted(message)
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Instant;

    use super::*;

    /// A collector that takes the connection and never answers fails the
    /// POST at the deadline.
    #[test]
    fn a_silent_collector_fails_at_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let held = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
        let endpoint = Endpoint::parse(&format!("http://{addr}")).unwrap();
        let started = Instant::now();
        let result = post(&endpoint, b"{}", &[], Duration::from_millis(300));
        assert!(result.is_err(), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held.join());
    }

    #[test]
    fn the_traces_path_is_added_once() {
        let url = |t: &str| Endpoint::parse(t).map(|e| e.0);
        assert_eq!(
            url("http://127.0.0.1:4318").unwrap(),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(url("http://c:4318/").unwrap(), "http://c:4318/v1/traces");
        assert_eq!(url("https://c/otlp/").unwrap(), "https://c/otlp/v1/traces");
        assert_eq!(url("https://c/v1/traces").unwrap(), "https://c/v1/traces");
    }

    #[test]
    fn https_is_told_from_http() {
        assert!(Endpoint::parse("https://c/").unwrap().is_https());
        assert!(!Endpoint::parse("http://c:4318").unwrap().is_https());
    }

    /// OTLP/HTTP has one success, 200 with an `ExportTraceServiceResponse`.
    /// A 202 or 204 is a receiver speaking something else, and is refused
    /// like any other status, not taken for success.
    #[test]
    fn only_200_is_success() {
        for status in [202u16, 204, 301, 400, 503] {
            let why = match outcome(status, b"") {
                Outcome::Refused(why) => why,
                Outcome::Accepted(_) => panic!("{status} accepted"),
            };
            assert!(why.starts_with(&format!("HTTP {status}")), "{why}");
        }
    }

    #[test]
    fn credentials_queries_and_other_schemes_are_refused() {
        assert_eq!(
            Endpoint::parse("http://u:p@c:4318"),
            Err(UrlError::Userinfo)
        );
        assert_eq!(Endpoint::parse("http://c:4318/?k=v"), Err(UrlError::Query));
        assert_eq!(Endpoint::parse("http://c:4318/#f"), Err(UrlError::Query));
        assert_eq!(Endpoint::parse("ftp://c"), Err(UrlError::Scheme));
        assert!(Endpoint::parse("c:4318").is_err());
    }

    #[test]
    fn answers_mean_what_otlp_says() {
        assert_eq!(outcome(200, b""), Outcome::Accepted(None));
        assert_eq!(outcome(200, b"{}"), Outcome::Accepted(None));
        assert_eq!(
            outcome(200, br#"{"partialSuccess":{}}"#),
            Outcome::Accepted(None)
        );
        assert_eq!(
            outcome(
                200,
                br#"{"partialSuccess":{"rejectedSpans":"2","errorMessage":"bad"}}"#
            ),
            Outcome::Refused("the collector rejected 2 spans: bad".into())
        );
        assert_eq!(
            outcome(200, br#"{"partialSuccess":{"rejectedSpans":3}}"#),
            Outcome::Refused("the collector rejected 3 spans".into())
        );
        assert_eq!(
            outcome(
                200,
                br#"{"partialSuccess":{"rejectedSpans":0,"errorMessage":"slow"}}"#
            ),
            Outcome::Accepted(Some("slow".into()))
        );
        assert!(matches!(outcome(200, b"<html>"), Outcome::Refused(_)));
        assert_eq!(
            outcome(500, b"boom"),
            Outcome::Refused("HTTP 500: boom".into())
        );
    }
}
