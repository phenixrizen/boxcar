// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Registry credentials and challenges: `~/.docker/config.json`'s `auths`
//! and its credential helpers (`docker-credential-<name> get`, run as
//! Docker runs them), `WWW-Authenticate` parsing, token responses, and the
//! registry error codes boxcar puts into words of its own. A credential is
//! used to build one header value and never appears in a message; nothing
//! a helper writes is repeated either.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;

/// The longest a credential helper may take to answer: one may ask the
/// desktop's keychain, which may ask the user.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(60);

/// The most of a helper's output that is read; the rest is drained and
/// dropped, so the helper never blocks on a full pipe.
const HELPER_OUTPUT: usize = 64 * 1024;

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

/// The names Docker writes Docker Hub under; the first is what a helper
/// is asked for.
const HUB: [&str; 4] = [
    "https://index.docker.io/v1/",
    "index.docker.io",
    "docker.io",
    "registry-1.docker.io",
];

/// The keys `registry` may be filed under: itself, and for Docker Hub
/// the names Docker writes for it.
fn keys_for(registry: &str) -> Vec<&str> {
    if HUB.contains(&registry) {
        HUB.to_vec()
    } else {
        vec![registry]
    }
}

/// The server a helper is asked for `registry`'s credentials under, as
/// Docker asks: Docker Hub by its legacy URL, any other by its name.
pub fn helper_server(registry: &str) -> &str {
    if HUB.contains(&registry) {
        HUB[0]
    } else {
        registry
    }
}

/// Why a credential helper gave no credentials: boxcar's words, naming
/// the helper, never its output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HelperError {
    #[error("the credential helper's name `{0}` is not a plain name")]
    Name(String),
    #[error("the credential helper `docker-credential-{0}` is not on the PATH")]
    Missing(String),
    #[error("the credential helper `docker-credential-{0}` could not be run")]
    Run(String),
    #[error("the credential helper `docker-credential-{0}` failed ({1})")]
    Failed(String, String),
    #[error("the credential helper `docker-credential-{0}` did not answer within {1} s")]
    Timeout(String, u64),
    #[error("the credential helper `docker-credential-{0}` gave an answer boxcar cannot read")]
    Output(String),
    #[error(
        "the credential helper `docker-credential-{0}` gave an identity token, which boxcar does not use"
    )]
    IdentityToken(String),
}

/// A Docker credential helper: the program `docker-credential-<name>`.
#[derive(Clone, Debug)]
pub struct Helper {
    name: String,
    program: PathBuf,
}

impl Helper {
    /// The helper `name` names, found in `dirs` (the PATH's directories,
    /// [`Helper::path_dirs`]). A name is plain: letters, digits, `-`,
    /// `_` and `.`, as Docker's helpers are named.
    pub fn find(name: &str, dirs: &[PathBuf]) -> Result<Helper, HelperError> {
        let plain = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !plain {
            return Err(HelperError::Name(name.to_owned()));
        }
        let file = format!("docker-credential-{name}");
        dirs.iter()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(|dir| dir.join(&file))
            .find(|program| is_executable(program))
            .map(|program| Helper {
                name: name.to_owned(),
                program,
            })
            .ok_or_else(|| HelperError::Missing(name.to_owned()))
    }

    /// The directories of this process's PATH.
    pub fn path_dirs() -> Vec<PathBuf> {
        std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default()
    }

    /// `docker-credential-<name> get`, the server on its stdin, as Docker
    /// runs it: its credentials, or none when it says it has none for the
    /// server. It gets this process's environment, at most `timeout`, and
    /// is killed after that.
    pub fn get(&self, server: &str, timeout: Duration) -> Result<Option<Credentials>, HelperError> {
        let run = || HelperError::Run(self.name.clone());
        let mut child = Command::new(&self.program)
            .arg("get")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| run())?;
        // The server, then the end of stdin: a helper reads to the end. One
        // that exits first makes the write fail, and its exit status says.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(server.as_bytes());
        }
        let stdout = child.stdout.take().ok_or_else(run)?;
        let stderr = child.stderr.take().ok_or_else(run)?;
        let out = std::thread::spawn(move || read_capped(stdout, HELPER_OUTPUT));
        let err = std::thread::spawn(move || read_capped(stderr, 4096));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(run());
                }
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(HelperError::Timeout(self.name.clone(), timeout.as_secs()));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        if !status.success() {
            // The helpers' library ends with "credentials not found in
            // native keychain" when there are none; so do the others.
            if String::from_utf8_lossy(&stderr)
                .to_ascii_lowercase()
                .contains("credentials not found")
            {
                return Ok(None);
            }
            return Err(HelperError::Failed(self.name.clone(), exit_text(status)));
        }
        #[derive(serde::Deserialize, Default)]
        struct Answer {
            #[serde(rename = "Username", default)]
            username: String,
            #[serde(rename = "Secret", default)]
            secret: String,
        }
        let answer: Answer =
            serde_json::from_slice(&stdout).map_err(|_| HelperError::Output(self.name.clone()))?;
        if answer.username == "<token>" {
            return Err(HelperError::IdentityToken(self.name.clone()));
        }
        if answer.username.is_empty() || answer.secret.is_empty() {
            return Err(HelperError::Output(self.name.clone()));
        }
        Ok(Some(Credentials::new(answer.username, answer.secret)))
    }
}

/// A regular file this process may execute.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// An exit status in words: the code, or the signal.
fn exit_text(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit status {code}"),
        (None, Some(signal)) => format!("killed by signal {signal}"),
        (None, None) => "ended".to_owned(),
    }
}

/// The first `cap` bytes of `reader`, the rest read and dropped.
fn read_capped(mut reader: impl Read, cap: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => return kept,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
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
pub(crate) mod tests {
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
    fn helpers_are_named_per_registry_then_by_the_store() {
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
        assert_eq!(helper_server("docker.io"), "https://index.docker.io/v1/");
        assert_eq!(
            helper_server("registry-1.docker.io"),
            "https://index.docker.io/v1/"
        );
        assert_eq!(helper_server("ghcr.io"), "ghcr.io");
        assert_eq!(helper_server("r.example:5000"), "r.example:5000");
    }

    /// A helper script `docker-credential-<name>` in `dir`, written and
    /// made executable by a child process: a descriptor this process held
    /// open for writing would be inherited by whatever another test's
    /// thread forked meanwhile, until that child's exec, and running the
    /// script then fails with `ETXTBSY`.
    pub(crate) fn fake_helper(dir: &Path, name: &str, script: &str) {
        let path = dir.join(format!("docker-credential-{name}"));
        let mut child = std::process::Command::new("sh")
            .args(["-c", r#"cat > "$0" && chmod 755 "$0""#])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        std::io::Write::write_all(&mut stdin, format!("#!/bin/sh\n{script}\n").as_bytes()).unwrap();
        drop(stdin);
        assert!(child.wait().unwrap().success(), "{}", path.display());
    }

    #[test]
    fn a_helper_is_found_by_a_plain_name_in_the_given_directories() {
        let tmp = tempfile::tempdir().unwrap();
        fake_helper(tmp.path(), "fake", "exit 0");
        std::fs::write(tmp.path().join("docker-credential-plain"), "").unwrap();
        let dirs = vec![PathBuf::from("/nonexistent"), tmp.path().to_owned()];
        assert_eq!(
            Helper::find("fake", &dirs).unwrap().program,
            tmp.path().join("docker-credential-fake")
        );
        assert_eq!(
            Helper::find("plain", &dirs).unwrap_err(),
            HelperError::Missing("plain".into()),
            "not executable"
        );
        assert_eq!(
            Helper::find("other", &dirs).unwrap_err(),
            HelperError::Missing("other".into())
        );
        for bad in ["", "../fake", "a b", "x/y", "fake\n"] {
            assert_eq!(
                Helper::find(bad, &dirs).unwrap_err(),
                HelperError::Name(bad.into()),
                "{bad:?}"
            );
        }
        assert!(Helper::find("fake", &[]).is_err());
    }

    #[test]
    fn a_helper_gets_the_server_and_answers_with_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let seen = tmp.path().join("server");
        fake_helper(
            tmp.path(),
            "fake",
            &format!(
                "[ \"$1\" = get ] || exit 3\nserver=$(cat)\nprintf '%s' \"$server\" > {}\nprintf '{{\"ServerURL\":\"%s\",\"Username\":\"alice\",\"Secret\":\"s3cret\"}}' \"$server\"",
                seen.display()
            ),
        );
        let helper = Helper::find("fake", &[tmp.path().to_owned()]).unwrap();
        let got = helper.get("ghcr.io", HELPER_TIMEOUT).unwrap();
        assert_eq!(got, Some(Credentials::new("alice", "s3cret")));
        assert_eq!(std::fs::read_to_string(seen).unwrap(), "ghcr.io");
    }

    #[test]
    fn a_helper_with_none_says_so_and_a_failing_one_is_an_error_that_repeats_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = [tmp.path().to_owned()];
        fake_helper(
            tmp.path(),
            "none",
            "echo 'credentials not found in native keychain' >&2; exit 1",
        );
        assert_eq!(
            Helper::find("none", &dirs)
                .unwrap()
                .get("ghcr.io", HELPER_TIMEOUT)
                .unwrap(),
            None
        );
        fake_helper(
            tmp.path(),
            "fails",
            "echo 'leaked-secret' >&2; echo leaked-too; exit 2",
        );
        let err = Helper::find("fails", &dirs)
            .unwrap()
            .get("ghcr.io", HELPER_TIMEOUT)
            .unwrap_err();
        assert_eq!(
            err,
            HelperError::Failed("fails".into(), "exit status 2".into())
        );
        assert!(!format!("{err} {err:?}").contains("leaked"));
        fake_helper(tmp.path(), "killed", "kill -9 $$");
        assert_eq!(
            Helper::find("killed", &dirs)
                .unwrap()
                .get("ghcr.io", HELPER_TIMEOUT)
                .unwrap_err(),
            HelperError::Failed("killed".into(), "killed by signal 9".into())
        );
    }

    #[test]
    fn a_helpers_answer_must_be_credentials_boxcar_can_use() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = [tmp.path().to_owned()];
        for (name, script, want) in [
            (
                "garbage",
                "echo not json",
                HelperError::Output("garbage".into()),
            ),
            (
                "empty",
                r#"printf '{"Username":"","Secret":"x"}'"#,
                HelperError::Output("empty".into()),
            ),
            (
                "nosecret",
                r#"printf '{"Username":"u"}'"#,
                HelperError::Output("nosecret".into()),
            ),
            (
                "token",
                r#"printf '{"Username":"<token>","Secret":"idt0ken-secret"}'"#,
                HelperError::IdentityToken("token".into()),
            ),
        ] {
            fake_helper(tmp.path(), name, script);
            let err = Helper::find(name, &dirs)
                .unwrap()
                .get("ghcr.io", HELPER_TIMEOUT)
                .unwrap_err();
            assert_eq!(err, want, "{name}");
            assert!(!format!("{err} {err:?}").contains("idt0ken"), "{err}");
        }
        // Output past the cap is drained, not kept, and does not hang.
        fake_helper(
            tmp.path(),
            "chatty",
            r#"head -c 300000 /dev/zero | tr '\0' 'x'; printf '{"Username":"u","Secret":"s"}'"#,
        );
        assert_eq!(
            Helper::find("chatty", &dirs)
                .unwrap()
                .get("ghcr.io", HELPER_TIMEOUT)
                .unwrap_err(),
            HelperError::Output("chatty".into())
        );
    }

    #[test]
    fn a_helper_that_does_not_answer_in_time_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        fake_helper(tmp.path(), "slow", "sleep 20");
        let helper = Helper::find("slow", &[tmp.path().to_owned()]).unwrap();
        let started = Instant::now();
        assert_eq!(
            helper
                .get("ghcr.io", Duration::from_millis(300))
                .unwrap_err(),
            HelperError::Timeout("slow".into(), 0)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
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
