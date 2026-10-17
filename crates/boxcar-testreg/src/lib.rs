// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! An in-process OCI registry for tests: a `/v2/` server on the loopback
//! over an in-memory store of blobs and manifests, builders for layers,
//! configs, manifests and indexes, and the ways a registry can misbehave
//! (challenges from the wrong place, lying digests, stalled bodies,
//! echoed credentials), each switched on by a test. Every request it
//! serves is kept for the test to look at.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine as _;

/// `sha256:<hex>` of `data`.
pub fn sha256(data: &[u8]) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, data);
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in hash.as_ref() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
pub const LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

/// A blob with its media type.
#[derive(Clone, Debug)]
pub struct Blob {
    pub media_type: String,
    pub data: Vec<u8>,
}

impl Blob {
    pub fn digest(&self) -> String {
        sha256(&self.data)
    }

    pub fn descriptor(&self) -> serde_json::Value {
        serde_json::json!({"mediaType": self.media_type, "digest": self.digest(), "size": self.data.len()})
    }
}

/// A plain tar layer.
pub fn layer_tar(tar: &[u8]) -> Blob {
    Blob {
        media_type: LAYER_TAR.into(),
        data: tar.to_vec(),
    }
}

/// A gzip layer.
pub fn layer_gzip(tar: &[u8]) -> Blob {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(tar).unwrap();
    Blob {
        media_type: LAYER_GZIP.into(),
        data: encoder.finish().unwrap(),
    }
}

/// A zstd layer.
pub fn layer_zstd(tar: &[u8]) -> Blob {
    Blob {
        media_type: LAYER_ZSTD.into(),
        data: ruzstd::encoding::compress_to_vec(tar, ruzstd::encoding::CompressionLevel::Fastest),
    }
}

/// A tar of regular files, `(path, data)` each, for layers whose content
/// does not matter much.
pub fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, path, *data).unwrap();
    }
    builder.into_inner().unwrap()
}

/// A `linux/amd64` config with `defaults`.
pub fn config(env: &[&str], entrypoint: &[&str], cmd: &[&str], working_dir: &str) -> Blob {
    let value = serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": env, "Entrypoint": entrypoint, "Cmd": cmd, "WorkingDir": working_dir},
        "rootfs": {"type": "layers", "diff_ids": []},
    });
    Blob {
        media_type: OCI_CONFIG.into(),
        data: serde_json::to_vec(&value).unwrap(),
    }
}

/// A manifest of `config` and `layers`.
pub fn manifest(config: &Blob, layers: &[Blob]) -> Blob {
    let value = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": config.descriptor(),
        "layers": layers.iter().map(Blob::descriptor).collect::<Vec<_>>(),
    });
    Blob {
        media_type: OCI_MANIFEST.into(),
        data: serde_json::to_vec(&value).unwrap(),
    }
}

/// An index of `(manifest, os, architecture)`.
pub fn index(entries: &[(&Blob, &str, &str)]) -> Blob {
    let manifests: Vec<_> = entries
        .iter()
        .map(|(m, os, arch)| {
            let mut d = m.descriptor();
            d["platform"] = serde_json::json!({"os": os, "architecture": arch});
            d
        })
        .collect();
    let value =
        serde_json::json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests});
    Blob {
        media_type: OCI_INDEX.into(),
        data: serde_json::to_vec(&value).unwrap(),
    }
}

/// One request the registry served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Lowercased names.
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// How the registry misbehaves, for the tests that need it.
#[derive(Clone, Debug, Default)]
pub struct Faults {
    /// `Docker-Content-Digest` on manifests says this instead of the truth.
    pub lie_content_digest: bool,
    /// Blobs whose bytes are served altered (their digest then lies).
    pub corrupt: Vec<String>,
    /// Blobs served with a `Content-Length` one less than the truth.
    pub short_length: Vec<String>,
    /// Blobs whose body is never sent: the connection stays open, silent.
    pub stall: Vec<String>,
    /// Error bodies echo the request's `Authorization` header as the code
    /// and the message.
    pub echo_authorization: bool,
    /// The token endpoint answers with a redirect to this URL.
    pub token_redirect: Option<String>,
    /// Blob requests are redirected (307) to this base URL.
    pub redirect_blobs_to: Option<String>,
    /// The Bearer challenge names this realm instead of the registry's own.
    pub realm: Option<String>,
    /// Every request is a 401 with a Bearer challenge, even with a token:
    /// a registry (or a CDN) that keeps challenging.
    pub always_challenge: bool,
}

/// How clients must authenticate.
#[derive(Clone, Debug)]
pub enum Auth {
    None,
    /// A Bearer challenge; the token endpoint takes anyone, or only these
    /// Basic credentials.
    Bearer {
        token: String,
        credentials: Option<(String, String)>,
    },
    /// A Basic challenge for these credentials.
    Basic(String, String),
}

struct State {
    blobs: HashMap<String, Blob>,
    /// `(repository, tag or digest)` → manifest digest.
    manifests: HashMap<(String, String), String>,
    auth: Auth,
    faults: Faults,
    requests: Vec<Request>,
}

/// The registry, serving until dropped.
pub struct Registry {
    addr: SocketAddr,
    tls: Option<Tls>,
    state: Arc<Mutex<State>>,
    stop: Arc<Mutex<bool>>,
    thread: Option<JoinHandle<()>>,
}

/// A TLS identity for the loopback: a CA and a leaf for 127.0.0.1.
pub struct Tls {
    pub ca_der: Vec<u8>,
    config: Arc<rustls::ServerConfig>,
}

impl Tls {
    /// A fresh CA and a leaf for 127.0.0.1 signed by it.
    pub fn new() -> Tls {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
            PKCS_ECDSA_P256_SHA256,
        };
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "boxcar test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_der = ca.der().to_vec();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        leaf_params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(
                Ipv4Addr::LOCALHOST,
            )));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
        Tls {
            ca_der,
            config: Arc::new(config),
        }
    }
}

impl Default for Tls {
    fn default() -> Tls {
        Tls::new()
    }
}

impl Registry {
    /// A registry on the loopback, plain HTTP.
    pub fn start(auth: Auth, faults: Faults) -> Registry {
        Registry::start_with(auth, faults, None)
    }

    /// A registry over TLS with `tls`'s leaf.
    pub fn start_tls(auth: Auth, faults: Faults, tls: Tls) -> Registry {
        Registry::start_with(auth, faults, Some(tls))
    }

    fn start_with(auth: Auth, faults: Faults, tls: Option<Tls>) -> Registry {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            blobs: HashMap::new(),
            manifests: HashMap::new(),
            auth,
            faults,
            requests: Vec::new(),
        }));
        let stop = Arc::new(Mutex::new(false));
        let tls_config = tls.as_ref().map(|t| t.config.clone());
        let thread = {
            let state = state.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if *stop.lock().unwrap() {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let state = state.clone();
                    let tls_config = tls_config.clone();
                    let base = match &tls_config {
                        Some(_) => format!("https://{addr}"),
                        None => format!("http://{addr}"),
                    };
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                        let result = match tls_config {
                            Some(config) => {
                                let conn = rustls::ServerConnection::new(config).unwrap();
                                let mut tls = rustls::StreamOwned::new(conn, stream);
                                serve(&mut tls, &state, &base)
                            }
                            None => {
                                let mut stream = stream;
                                serve(&mut stream, &state, &base)
                            }
                        };
                        let _ = result;
                    });
                }
            })
        };
        Registry {
            addr,
            tls,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>` or `https://…`.
    pub fn url(&self) -> String {
        match self.tls {
            Some(_) => format!("https://{}", self.addr),
            None => format!("http://{}", self.addr),
        }
    }

    /// `127.0.0.1:<port>`, as a reference names it.
    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// The CA to trust, when serving TLS.
    pub fn ca_der(&self) -> Option<&[u8]> {
        self.tls.as_ref().map(|t| t.ca_der.as_slice())
    }

    /// Stores `blob`; its digest.
    pub fn put_blob(&self, blob: &Blob) -> String {
        let digest = blob.digest();
        self.state
            .lock()
            .unwrap()
            .blobs
            .insert(digest.clone(), blob.clone());
        digest
    }

    /// Stores `manifest` as a blob and names it `repository:tag` and by
    /// its digest; the digest.
    pub fn put_manifest(&self, repository: &str, tag: &str, manifest: &Blob) -> String {
        let digest = self.put_blob(manifest);
        let mut state = self.state.lock().unwrap();
        state
            .manifests
            .insert((repository.to_owned(), tag.to_owned()), digest.clone());
        state
            .manifests
            .insert((repository.to_owned(), digest.clone()), digest.clone());
        digest
    }

    /// Stores a whole image: config, layers, manifest, tagged; the
    /// manifest's digest.
    pub fn put_image(&self, repository: &str, tag: &str, config: &Blob, layers: &[Blob]) -> String {
        self.put_blob(config);
        for layer in layers {
            self.put_blob(layer);
        }
        self.put_manifest(repository, tag, &manifest(config, layers))
    }

    pub fn set_faults(&self, faults: Faults) {
        self.state.lock().unwrap().faults = faults;
    }

    /// Every request served so far.
    pub fn requests(&self) -> Vec<Request> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
        // Wake the accept loop.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One connection: one request, one response.
fn serve(
    stream: &mut (impl Read + Write),
    state: &Arc<Mutex<State>>,
    base: &str,
) -> io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 64 * 1024 {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if !matches!(request.parse(&head), Ok(httparse::Status::Complete(_))) {
        return respond(stream, 400, &[], b"");
    }
    let method = request.method.unwrap_or("").to_owned();
    let path = request.path.unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let recorded = Request {
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
    };
    let response = {
        let mut state = state.lock().unwrap();
        state.requests.push(recorded.clone());
        route(&state, &recorded, base)
    };
    match response {
        Response::Full {
            status,
            headers,
            body,
        } => respond(stream, status, &headers, &body),
        Response::Stall {
            status,
            headers,
            length,
        } => {
            // Headers, then silence until the client gives up.
            let head = head_bytes(status, &headers, Some(length));
            stream.write_all(&head)?;
            stream.flush()?;
            thread::sleep(Duration::from_secs(600));
            Ok(())
        }
    }
}

enum Response {
    Full {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Stall {
        status: u16,
        headers: Vec<(String, String)>,
        /// The length announced: the blob's own, so the client waits for a
        /// body that never comes.
        length: usize,
    },
}

fn full(status: u16, headers: Vec<(&str, String)>, body: Vec<u8>) -> Response {
    Response::Full {
        status,
        headers: headers
            .into_iter()
            .map(|(n, v)| (n.to_owned(), v))
            .collect(),
        body,
    }
}

fn error_body(state: &State, request: &Request, code: &str, message: &str) -> Vec<u8> {
    let (code, message) = if state.faults.echo_authorization {
        let auth = request.header("authorization").unwrap_or("").to_owned();
        (auth.clone(), auth)
    } else {
        (code.to_owned(), message.to_owned())
    };
    serde_json::to_vec(&serde_json::json!({"errors": [{"code": code, "message": message}]}))
        .unwrap()
}

fn route(state: &State, request: &Request, base: &str) -> Response {
    let path = request.path.split('?').next().unwrap_or("");
    // The token endpoint.
    if path == "/token" {
        if let Some(to) = &state.faults.token_redirect {
            return full(302, vec![("Location", to.clone())], Vec::new());
        }
        if let Auth::Bearer { token, credentials } = &state.auth {
            if let Some((user, password)) = credentials {
                let want = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
                );
                if request.header("authorization") != Some(want.as_str()) {
                    return full(
                        401,
                        json_headers(vec![]),
                        error_body(state, request, "UNAUTHORIZED", "bad credentials"),
                    );
                }
            }
            let body = serde_json::to_vec(&serde_json::json!({"token": token})).unwrap();
            return full(200, json_headers(vec![]), body);
        }
        return full(404, vec![], Vec::new());
    }
    // Everything under /v2/ may need authentication.
    let challenge = |state: &State| -> Response {
        let realm = state
            .faults
            .realm
            .clone()
            .unwrap_or_else(|| format!("{base}/token"));
        let header = match &state.auth {
            Auth::Basic(..) => "Basic realm=\"registry\"".to_owned(),
            _ => {
                format!("Bearer realm=\"{realm}\",service=\"testreg\",scope=\"repository:x:pull\"")
            }
        };
        full(
            401,
            json_headers(vec![("WWW-Authenticate", header)]),
            error_body(state, request, "UNAUTHORIZED", "authentication required"),
        )
    };
    let authorized = match &state.auth {
        Auth::None => true,
        Auth::Bearer { token, .. } => {
            request.header("authorization") == Some(format!("Bearer {token}").as_str())
        }
        Auth::Basic(user, password) => {
            let want = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
            );
            request.header("authorization") == Some(want.as_str())
        }
    };
    if state.faults.always_challenge || !authorized {
        return challenge(state);
    }
    if path == "/v2/" {
        return full(200, json_headers(vec![]), b"{}".to_vec());
    }
    let Some(rest) = path.strip_prefix("/v2/") else {
        return full(404, vec![], Vec::new());
    };
    if let Some((repository, reference)) = rest.rsplit_once("/manifests/") {
        let Some(digest) = state
            .manifests
            .get(&(repository.to_owned(), reference.to_owned()))
        else {
            return full(
                404,
                json_headers(vec![]),
                error_body(state, request, "MANIFEST_UNKNOWN", "no such manifest"),
            );
        };
        let blob = &state.blobs[digest];
        let said = if state.faults.lie_content_digest {
            sha256(b"a lie")
        } else {
            digest.clone()
        };
        return full(
            200,
            vec![
                ("Content-Type", blob.media_type.clone()),
                ("Docker-Content-Digest", said),
            ],
            blob.data.clone(),
        );
    }
    if let Some((_repository, digest)) = rest.rsplit_once("/blobs/") {
        if let Some(to) = &state.faults.redirect_blobs_to {
            return full(307, vec![("Location", format!("{to}{path}"))], Vec::new());
        }
        let Some(blob) = state.blobs.get(digest) else {
            return full(
                404,
                json_headers(vec![]),
                error_body(state, request, "BLOB_UNKNOWN", "no such blob"),
            );
        };
        let digest = digest.to_owned();
        let headers = vec![("Content-Type", "application/octet-stream".to_owned())];
        if state.faults.stall.contains(&digest) {
            return Response::Stall {
                status: 200,
                headers: headers
                    .into_iter()
                    .map(|(n, v)| (n.to_owned(), v))
                    .collect(),
                length: blob.data.len(),
            };
        }
        let mut data = blob.data.clone();
        if state.faults.corrupt.contains(&digest) {
            if let Some(last) = data.last_mut() {
                *last ^= 0xff;
            }
        }
        if state.faults.short_length.contains(&digest) {
            let mut headers: Vec<(String, String)> = headers
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v))
                .collect();
            headers.push(("Content-Length".to_owned(), (data.len() - 1).to_string()));
            return Response::Full {
                status: 200,
                headers,
                body: data,
            };
        }
        return full(200, headers, data);
    }
    full(404, vec![], Vec::new())
}

/// `Content-Type: application/json` and `extra`.
fn json_headers(extra: Vec<(&'static str, String)>) -> Vec<(&'static str, String)> {
    let mut headers = vec![("Content-Type", "application/json".to_owned())];
    headers.extend(extra);
    headers
}

fn head_bytes(status: u16, headers: &[(String, String)], length: Option<usize>) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Other",
    };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    let mut has_length = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_length = true;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if let (false, Some(length)) = (has_length, length) {
        out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

fn respond(
    stream: &mut impl Write,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> io::Result<()> {
    stream.write_all(&head_bytes(status, headers, Some(body.len())))?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(url: &str, path: &str, auth: Option<&str>) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let addr = url.strip_prefix("http://").unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n");
        if let Some(auth) = auth {
            request.push_str(&format!("Authorization: {auth}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&response[..split]).into_owned();
        let body = response[split + 4..].to_vec();
        let mut lines = head.lines();
        let status: u16 = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .map(|l| {
                let (n, v) = l.split_once(": ").unwrap();
                (n.to_ascii_lowercase(), v.to_owned())
            })
            .collect();
        (status, headers, body)
    }

    #[test]
    fn it_serves_an_image_by_tag_and_digest() {
        let registry = Registry::start(Auth::None, Faults::default());
        let layer = layer_gzip(&tar_of(&[("hello", b"hi")]));
        let config = config(&["A=1"], &["/bin/sh"], &[], "/");
        let digest = registry.put_image("library/app", "latest", &config, &[layer.clone()]);
        let (status, headers, body) =
            get(&registry.url(), "/v2/library/app/manifests/latest", None);
        assert_eq!(status, 200);
        assert_eq!(sha256(&body), digest);
        assert!(headers.contains(&("docker-content-digest".into(), digest.clone())));
        assert!(headers.contains(&("content-type".into(), OCI_MANIFEST.into())));
        let (status, _, body) = get(
            &registry.url(),
            &format!("/v2/library/app/manifests/{digest}"),
            None,
        );
        assert_eq!((status, sha256(&body)), (200, digest));
        let (status, _, body) = get(
            &registry.url(),
            &format!("/v2/library/app/blobs/{}", layer.digest()),
            None,
        );
        assert_eq!((status, body), (200, layer.data));
        let (status, _, _) = get(&registry.url(), "/v2/library/app/manifests/nope", None);
        assert_eq!(status, 404);
        assert_eq!(registry.requests().len(), 4);
        assert_eq!(
            registry.requests()[0].path,
            "/v2/library/app/manifests/latest"
        );
    }

    #[test]
    fn it_challenges_and_takes_a_token() {
        let registry = Registry::start(
            Auth::Bearer {
                token: "t0k3n".into(),
                credentials: Some(("alice".into(), "pw".into())),
            },
            Faults::default(),
        );
        let (status, headers, _) = get(&registry.url(), "/v2/", None);
        assert_eq!(status, 401);
        let challenge = headers
            .iter()
            .find(|(n, _)| n == "www-authenticate")
            .unwrap();
        assert!(
            challenge
                .1
                .starts_with(&format!("Bearer realm=\"{}/token\"", registry.url())),
            "{}",
            challenge.1
        );
        let (status, _, _) = get(&registry.url(), "/token?service=testreg", None);
        assert_eq!(status, 401, "the token endpoint wants the credentials");
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:pw")
        );
        let (status, _, body) = get(&registry.url(), "/token?service=testreg", Some(&basic));
        assert_eq!(status, 200);
        assert_eq!(body, br#"{"token":"t0k3n"}"#);
        let (status, _, _) = get(&registry.url(), "/v2/", Some("Bearer t0k3n"));
        assert_eq!(status, 200);
    }

    #[test]
    fn faults_do_what_they_say() {
        let registry = Registry::start(Auth::None, Faults::default());
        let layer = layer_tar(&tar_of(&[("a", b"a")]));
        let digest = registry.put_blob(&layer);
        registry.set_faults(Faults {
            corrupt: vec![digest.clone()],
            echo_authorization: true,
            ..Faults::default()
        });
        let (_, _, body) = get(&registry.url(), &format!("/v2/x/blobs/{digest}"), None);
        assert_ne!(sha256(&body), digest);
        let (status, _, body) = get(
            &registry.url(),
            "/v2/x/manifests/none",
            Some("Bearer leaked"),
        );
        assert_eq!(status, 404);
        assert!(String::from_utf8_lossy(&body).contains("Bearer leaked"));
    }
}
