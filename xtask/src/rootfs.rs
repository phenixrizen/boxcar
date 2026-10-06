// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask rootfs alpine`: the root filesystem the guest boots from.
//!
//! Downloads `alpine-minirootfs-<version>-x86_64.tar.gz` and its `.sha256`
//! from dl-cdn.alpinelinux.org into `target/rootfs-cache`, checks the
//! tarball's SHA-256 against the hash pinned here (for the default version)
//! and against the published `.sha256`, and unpacks it with `tar` into
//! `target/guest/rootfs-alpine` as the invoking user, with `/tmp` and
//! `/var/tmp` at mode 1777 and `etc/boxcar-rootfs.json` saying what it is.
//! `curl`, `sha256sum` and `tar` run as argv arrays; nothing goes through a
//! shell.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Subcommand};

/// The Alpine release unpacked by default: the latest 3.22.
pub const DEFAULT_VERSION: &str = "3.22.6";

/// The SHA-256 of [`DEFAULT_VERSION`]'s x86_64 minirootfs tarball, from the
/// release's `latest-releases.yaml` and `.sha256`.
pub const DEFAULT_SHA256: &str = "27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2";

/// Where Alpine releases are published.
const MIRROR: &str = "https://dl-cdn.alpinelinux.org/alpine";

/// A package from the release's `main` repository, pinned by its SHA-256.
pub struct Package {
    pub name: &'static str,
    pub version: &'static str,
    pub sha256: &'static str,
}

/// What the minirootfs lacks for TLS: busybox's `wget` hands HTTPS to
/// `ssl_client`, which needs OpenSSL's libraries. The gated tests reach
/// HTTPS hosts through the gate with them. Pinned for [`DEFAULT_VERSION`]'s
/// branch; another release gets the bare minirootfs.
pub const TLS_PACKAGES: [Package; 3] = [
    Package {
        name: "libcrypto3",
        version: "3.5.9-r0",
        sha256: "3f5825ced5fde1c66a5376a3f6076b3c08538ad52d9ef23f069857e212d9175a",
    },
    Package {
        name: "libssl3",
        version: "3.5.9-r0",
        sha256: "6801c740b9760b5b08da8db6367ebc18b2cc4dbaf371f7148429538b8bb04e23",
    },
    Package {
        name: "ssl_client",
        version: "1.37.0-r20",
        sha256: "11b2a5f91caf8eb5daa9a0bc2586f93545de62897f3a704fd49533e1654b7a68",
    },
];

/// The only architecture the guest has.
const ARCH: &str = "x86_64";

/// The agents' guest: Debian trixie, by digest.
pub const DEBIAN_IMAGE: &str =
    "debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f";
/// The Claude Code version the guest gets, native (`claude-native`) and
/// under Node (`claude`).
pub const CLAUDE_CODE_VERSION: &str = "2.1.290";
/// The Codex version the guest gets (`codex`).
pub const CODEX_VERSION: &str = "0.159.0";
/// The Node the npm builds run on: Claude Code 2.1 wants 22 or later, and
/// Debian trixie ships 20, so the official build goes in by tarball,
/// checked against its published SHA-256.
pub const NODE_VERSION: &str = "22.23.3";
pub const NODE_SHA256: &str = "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de";
/// The image the Debian build makes.
const DEBIAN_TAG: &str = "boxcar-guest-debian";

/// The Dockerfile of the agents' guest: the base by digest, the tools the
/// agents need, Node by tarball at a pinned version (checked against its
/// SHA-256), the native Claude Code build first (its installer removes an
/// npm `claude` it finds, so the npm builds come after), its installer
/// state removed so that a session starts clean, then Claude Code and
/// Codex from npm at pinned versions, and a check that all three commands
/// are there.
pub fn debian_dockerfile() -> String {
    format!(
        "FROM {DEBIAN_IMAGE}\n\
         ENV DEBIAN_FRONTEND=noninteractive\n\
         RUN apt-get update \\\n \
          && apt-get install -y --no-install-recommends ca-certificates curl git procps xz-utils \\\n \
          && rm -rf /var/lib/apt/lists/*\n\
         RUN curl -fsSL https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-linux-x64.tar.xz -o /tmp/node.tar.xz \\\n \
          && echo \"{NODE_SHA256}  /tmp/node.tar.xz\" | sha256sum -c - \\\n \
          && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \\\n \
          && rm /tmp/node.tar.xz\n\
         RUN curl -fsSL https://claude.ai/install.sh | bash -s -- {CLAUDE_CODE_VERSION} \\\n \
          && cp /root/.local/share/claude/versions/{CLAUDE_CODE_VERSION} /usr/local/bin/claude-native \\\n \
          && chmod 0755 /usr/local/bin/claude-native \\\n \
          && rm -rf /root/.local/share/claude /root/.local/state/claude /root/.cache/claude \\\n \
                    /root/.local/bin/claude /root/.claude /root/.claude.json\n\
         RUN npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE_VERSION} @openai/codex@{CODEX_VERSION} \\\n \
          && npm cache clean --force\n\
         RUN test -x /usr/local/bin/claude-native && test -x /usr/local/bin/claude && test -x /usr/local/bin/codex\n\
         RUN mkdir -p /workspace && chmod 1777 /tmp\n"
    )
}

/// Arguments of `cargo xtask rootfs`.
#[derive(Args)]
pub struct RootfsArgs {
    #[command(subcommand)]
    distro: Distro,
}

#[derive(Subcommand)]
enum Distro {
    /// Download, verify and unpack an Alpine minirootfs into
    /// target/guest/rootfs-alpine.
    Alpine(AlpineArgs),
    /// Build the agents' guest with Docker into target/guest/rootfs-debian:
    /// Debian trixie with Claude Code (the native build as `claude-native`,
    /// the npm build as `claude`) and Codex, at pinned versions.
    Debian,
}

#[derive(Args)]
struct AlpineArgs {
    /// The Alpine release, as MAJOR.MINOR.PATCH. Only the default is pinned;
    /// any other is checked against its published .sha256 alone.
    #[arg(long, value_name = "VERSION", default_value = DEFAULT_VERSION, value_parser = parse_version)]
    version: String,
}

/// Runs `cargo xtask rootfs`.
pub fn run(args: &RootfsArgs) -> Result<()> {
    match &args.distro {
        Distro::Alpine(alpine) => run_alpine(&alpine.version),
        Distro::Debian => run_debian(),
    }
}

/// Builds the Debian image and unpacks its filesystem, as the invoking
/// user, into `target/guest/rootfs-debian`.
fn run_debian() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;
    let guest_dir = root.join("target/guest");
    let context = root.join("target/rootfs-cache/debian-context");
    for dir in [&guest_dir, &context] {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    // The Dockerfile goes in on stdin; the context is an empty directory,
    // so nothing of the tree is sent to the daemon.
    let mut build = Command::new("docker")
        .args(["build", "-t", DEBIAN_TAG, "-f", "-"])
        .arg(&context)
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to start docker build")?;
    if let Some(mut stdin) = build.stdin.take() {
        stdin
            .write_all(debian_dockerfile().as_bytes())
            .context("write the Dockerfile to docker build")?;
    }
    let status = build.wait().context("docker build")?;
    ensure!(status.success(), "docker build failed: {status}");

    let created = Command::new("docker")
        .args(["create", DEBIAN_TAG])
        .output()
        .context("failed to start docker create")?;
    ensure!(
        created.status.success(),
        "docker create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let container = String::from_utf8_lossy(&created.stdout).trim().to_owned();
    ensure!(!container.is_empty(), "docker create named no container");

    let out = guest_dir.join("rootfs-debian");
    let partial = with_suffix(&out, ".partial");
    if partial.exists() {
        fs::remove_dir_all(&partial).with_context(|| format!("remove {}", partial.display()))?;
    }
    fs::create_dir(&partial).with_context(|| format!("create {}", partial.display()))?;
    let unpacked = export_into(&container, &partial);
    let _ = Command::new("docker").args(["rm", &container]).output();
    unpacked?;
    open_tmp_dirs(&partial)?;
    let json = partial.join("etc/boxcar-rootfs.json");
    let mut text = serde_json::to_string_pretty(&serde_json::json!({
        "distro": "debian",
        "image": DEBIAN_IMAGE,
        "arch": ARCH,
        "claude_code": CLAUDE_CODE_VERSION,
        "codex": CODEX_VERSION,
        "node": NODE_VERSION,
    }))?;
    text.push('\n');
    fs::write(&json, text).with_context(|| format!("write {}", json.display()))?;
    if out.exists() {
        fs::remove_dir_all(&out).with_context(|| format!("remove {}", out.display()))?;
    }
    fs::rename(&partial, &out).with_context(|| format!("rename to {}", out.display()))?;
    println!(
        "rootfs: {} (Debian trixie {ARCH}, Claude Code {CLAUDE_CODE_VERSION} native and npm, \
         Codex {CODEX_VERSION})",
        out.display()
    );
    Ok(())
}

/// `docker export` of `container` unpacked into `dir` as this user: the
/// device nodes (which a user cannot make) left out, ownership and modes
/// as tar sets them for a user.
fn export_into(container: &str, dir: &Path) -> Result<()> {
    let mut export = Command::new("docker")
        .args(["export", container])
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to start docker export")?;
    let stdout = export
        .stdout
        .take()
        .context("docker export has no stdout")?;
    let status = Command::new("tar")
        .args(export_tar_args(dir))
        .stdin(stdout)
        .status()
        .context("failed to start tar")?;
    let exported = export.wait().context("docker export")?;
    ensure!(exported.success(), "docker export failed: {exported}");
    ensure!(status.success(), "tar failed: {status}");
    Ok(())
}

/// The arguments after `tar` that unpack a `docker export` stream from
/// stdin into `dir`.
fn export_tar_args(dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["--extract".into(), "--file".into(), "-".into()];
    args.push("--directory".into());
    args.push(dir.into());
    args.extend(
        [
            "--no-same-owner",
            "--no-same-permissions",
            "--exclude=dev/*",
            "--exclude=.dockerenv",
        ]
        .map(OsString::from),
    );
    args
}

/// Downloads, verifies and unpacks Alpine `version`.
fn run_alpine(version: &str) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;
    let cache_dir = root.join("target/rootfs-cache");
    let guest_dir = root.join("target/guest");
    for dir in [&cache_dir, &guest_dir] {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }

    let url = tarball_url(version)?;
    let published = fetch_text(&format!("{url}.sha256"))?;
    let published = parse_sha256_file(&published, &tarball_name(version))?;
    let expected = match pinned_sha256(version) {
        Some(pinned) => {
            ensure!(
                published == pinned,
                "the published SHA-256 of {} is {published}, not the pinned {pinned}",
                tarball_name(version)
            );
            pinned.to_owned()
        }
        None => {
            eprintln!(
                "warning: Alpine {version} is not pinned in xtask/src/rootfs.rs; \
                 trusting its published .sha256"
            );
            published
        }
    };

    let tarball = cache_dir.join(tarball_name(version));
    if !tarball.exists() || sha256_of_file(&tarball)? != expected {
        download(&url, &tarball)?;
    }
    let actual = sha256_of_file(&tarball)?;
    ensure!(
        actual == expected,
        "{} has SHA-256 {actual}, expected {expected}",
        tarball.display()
    );
    let packages: &[Package] = if version == DEFAULT_VERSION {
        &TLS_PACKAGES
    } else {
        eprintln!("warning: Alpine {version} gets no TLS client: the packages are pinned for {DEFAULT_VERSION}");
        &[]
    };
    let mut apks = Vec::new();
    for package in packages {
        let apk = cache_dir.join(apk_name(package));
        let url = apk_url(version, package)?;
        if !apk.exists() || sha256_of_file(&apk)? != package.sha256 {
            download(&url, &apk)?;
        }
        let actual = sha256_of_file(&apk)?;
        ensure!(
            actual == package.sha256,
            "{} has SHA-256 {actual}, expected {}",
            apk.display(),
            package.sha256
        );
        apks.push(apk);
    }

    let out = guest_dir.join("rootfs-alpine");
    unpack(
        &tarball,
        &apks,
        &out,
        &metadata(version, &url, &expected, packages),
    )?;
    println!(
        "rootfs: {} (Alpine {version} {ARCH}, sha256 {expected})",
        out.display()
    );
    Ok(())
}

/// `version` if it is MAJOR.MINOR.PATCH in decimal.
fn parse_version(version: &str) -> Result<String, String> {
    let parts: Vec<&str> = version.split('.').collect();
    let decimal = |part: &&str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if parts.len() == 3 && parts.iter().all(decimal) {
        Ok(version.to_owned())
    } else {
        Err(format!("{version:?} is not MAJOR.MINOR.PATCH"))
    }
}

/// The release branch directory of `version`: `v3.22` for `3.22.6`.
fn branch(version: &str) -> Result<String> {
    let mut parts = version.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => Ok(format!("v{major}.{minor}")),
        _ => bail!("{version:?} is not MAJOR.MINOR.PATCH"),
    }
}

/// `alpine-minirootfs-<version>-x86_64.tar.gz`.
fn tarball_name(version: &str) -> String {
    format!("alpine-minirootfs-{version}-{ARCH}.tar.gz")
}

/// `<name>-<version>.apk`.
fn apk_name(package: &Package) -> String {
    format!("{}-{}.apk", package.name, package.version)
}

/// Where `package` is on `version`'s branch of the `main` repository.
fn apk_url(version: &str, package: &Package) -> Result<String> {
    Ok(format!(
        "{MIRROR}/{}/main/{ARCH}/{}",
        branch(version)?,
        apk_name(package)
    ))
}

/// Where the tarball of `version` is published.
fn tarball_url(version: &str) -> Result<String> {
    Ok(format!(
        "{MIRROR}/{}/releases/{ARCH}/{}",
        branch(version)?,
        tarball_name(version)
    ))
}

/// The pinned SHA-256 of `version`, if it is pinned.
fn pinned_sha256(version: &str) -> Option<&'static str> {
    (version == DEFAULT_VERSION).then_some(DEFAULT_SHA256)
}

/// The hash in a `sha256sum`-style file (`<hash>  <name>`), which must
/// name `name` and hold 64 hex digits; lowercased.
fn parse_sha256_file(text: &str, name: &str) -> Result<String> {
    let mut fields = text.split_whitespace();
    let (Some(hash), Some(file), None) = (fields.next(), fields.next(), fields.next()) else {
        bail!("the .sha256 of {name} is not `<hash>  <name>`: {text:?}");
    };
    ensure!(
        file.trim_start_matches('*') == name,
        "the .sha256 of {name} names {file:?}"
    );
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "the .sha256 of {name} holds {hash:?}, not a SHA-256"
    );
    Ok(hash.to_ascii_lowercase())
}

/// The arguments after `curl` that fetch `url` over HTTPS only, redirects
/// included, failing on an HTTP error, into `out` (or to stdout without
/// one).
fn curl_args(url: &str, out: Option<&Path>) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
    ]
    .map(OsString::from)
    .to_vec();
    if let Some(out) = out {
        args.push("--output".into());
        args.push(out.into());
    }
    args.push(url.into());
    args
}

/// The body of `url`, which must be text.
fn fetch_text(url: &str) -> Result<String> {
    let output = Command::new("curl")
        .args(curl_args(url, None))
        .output()
        .context("failed to start curl")?;
    ensure!(
        output.status.success(),
        "curl {url} failed: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).with_context(|| format!("{url} is not UTF-8 text"))
}

/// Downloads `url` to `out`, through a temporary file beside it.
fn download(url: &str, out: &Path) -> Result<()> {
    let partial = with_suffix(out, ".partial");
    println!("downloading {url}");
    let status = Command::new("curl")
        .args(curl_args(url, Some(&partial)))
        .status()
        .context("failed to start curl")?;
    ensure!(status.success(), "curl {url} failed: {status}");
    fs::rename(&partial, out).with_context(|| format!("rename to {}", out.display()))
}

/// The hex SHA-256 of the file at `path`, from `sha256sum`.
fn sha256_of_file(path: &Path) -> Result<String> {
    let output = Command::new("sha256sum")
        .arg("--")
        .arg(path)
        .output()
        .context("failed to start sha256sum")?;
    ensure!(
        output.status.success(),
        "sha256sum {} failed: {}",
        path.display(),
        output.status
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let hash = text.split_whitespace().next().unwrap_or_default();
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "sha256sum printed {text:?}"
    );
    Ok(hash.to_ascii_lowercase())
}

/// The arguments after `tar` that unpack `tarball` into `dir` as the
/// invoking user, with its umask applied to the modes.
fn tar_args(tarball: &Path, dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["--extract".into(), "--gzip".into(), "--file".into()];
    args.push(tarball.into());
    args.push("--directory".into());
    args.push(dir.into());
    args.extend(["--no-same-owner", "--no-same-permissions"].map(OsString::from));
    args
}

/// The arguments after `tar` that unpack the files of the package `apk`
/// (an apk is concatenated gzip tar streams: the signature, the package
/// info, the files) into `dir`, leaving the signature, `.PKGINFO` and
/// any install scripts out.
fn apk_tar_args(apk: &Path, dir: &Path) -> Vec<OsString> {
    let mut args = tar_args(apk, dir);
    args.extend(
        [
            "--exclude=.SIGN.*",
            "--exclude=.PKGINFO",
            "--exclude=.pre-*",
            "--exclude=.post-*",
            "--exclude=.trigger",
            // apk's per-file checksums ride in pax headers tar does not know.
            "--warning=no-unknown-keyword",
        ]
        .map(OsString::from),
    );
    args
}

/// What `etc/boxcar-rootfs.json` says about the rootfs.
fn metadata(version: &str, url: &str, sha256: &str, packages: &[Package]) -> serde_json::Value {
    let packages: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| serde_json::json!({"name": p.name, "version": p.version, "sha256": p.sha256}))
        .collect();
    serde_json::json!({
        "packages": packages,
        "distro": "alpine",
        "version": version,
        "arch": ARCH,
        "url": url,
        "sha256": sha256,
    })
}

/// Unpacks `tarball` into `out`, replacing what is there, with `metadata` in
/// `etc/boxcar-rootfs.json`. The tree is built beside `out` and moved into
/// place once complete, so a failure leaves any previous rootfs as it was.
fn unpack(
    tarball: &Path,
    apks: &[PathBuf],
    out: &Path,
    metadata: &serde_json::Value,
) -> Result<()> {
    let partial = with_suffix(out, ".partial");
    if partial.exists() {
        fs::remove_dir_all(&partial).with_context(|| format!("remove {}", partial.display()))?;
    }
    fs::create_dir(&partial).with_context(|| format!("create {}", partial.display()))?;
    let status = Command::new("tar")
        .args(tar_args(tarball, &partial))
        .status()
        .context("failed to start tar")?;
    ensure!(status.success(), "tar failed: {status}");
    // The packages' files over the base; their metadata stays out.
    for apk in apks {
        let status = Command::new("tar")
            .args(apk_tar_args(apk, &partial))
            .status()
            .context("failed to start tar")?;
        ensure!(status.success(), "tar {} failed: {status}", apk.display());
    }
    open_tmp_dirs(&partial)?;

    let json = partial.join("etc/boxcar-rootfs.json");
    let mut text = serde_json::to_string_pretty(metadata)?;
    text.push('\n');
    fs::write(&json, text).with_context(|| format!("write {}", json.display()))?;

    if out.exists() {
        fs::remove_dir_all(out).with_context(|| format!("remove {}", out.display()))?;
    }
    fs::rename(&partial, out).with_context(|| format!("rename to {}", out.display()))
}

/// The directories of a root filesystem everyone may create files in,
/// relative to its root.
const TMP_DIRS: [&str; 2] = ["tmp", "var/tmp"];

/// Gives each of [`TMP_DIRS`] in the tree at `root` mode 1777: tar, run as
/// the invoking user, applies the umask and drops the sticky bit. One that
/// is not there is fine, and one that is not a directory all the way down
/// (a symbolic link at any step would take chmod out of the tree) is left
/// alone.
fn open_tmp_dirs(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    'dirs: for rel in TMP_DIRS {
        let mut dir = root.to_path_buf();
        for part in Path::new(rel).components() {
            dir.push(part);
            match fs::symlink_metadata(&dir) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => continue 'dirs,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue 'dirs,
                Err(e) => return Err(e).with_context(|| format!("stat {}", dir.display())),
            }
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1777))
            .with_context(|| format!("chmod 1777 {}", dir.display()))?;
    }
    Ok(())
}

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_debian_guest_is_pinned_and_holds_both_agents() {
        let dockerfile = debian_dockerfile();
        assert!(dockerfile.starts_with(&format!("FROM {DEBIAN_IMAGE}\n")));
        assert!(DEBIAN_IMAGE.contains("@sha256:"), "pinned by digest");
        for needle in [
            &format!("@anthropic-ai/claude-code@{CLAUDE_CODE_VERSION}"),
            &format!("@openai/codex@{CODEX_VERSION}"),
            &format!("install.sh | bash -s -- {CLAUDE_CODE_VERSION}"),
            "/usr/local/bin/claude-native",
            "ca-certificates curl git procps xz-utils",
            &format!("node-v{NODE_VERSION}-linux-x64.tar.xz"),
            &format!("{NODE_SHA256}  /tmp/node.tar.xz"),
            "test -x /usr/local/bin/claude-native && test -x /usr/local/bin/claude",
            "mkdir -p /workspace",
        ] {
            assert!(dockerfile.contains(needle), "{needle}\n{dockerfile}");
        }
        // The native installer runs before npm's install, which it would
        // otherwise undo.
        assert!(
            dockerfile.find("install.sh").unwrap() < dockerfile.find("npm install -g").unwrap()
        );
        let args: Vec<String> = export_tar_args(Path::new("/r/partial"))
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "--extract",
                "--file",
                "-",
                "--directory",
                "/r/partial",
                "--no-same-owner",
                "--no-same-permissions",
                "--exclude=dev/*",
                "--exclude=.dockerenv",
            ]
        );
    }

    use super::*;

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect()
    }

    #[test]
    fn the_default_is_pinned() {
        assert_eq!(parse_version(DEFAULT_VERSION).unwrap(), DEFAULT_VERSION);
        assert_eq!(pinned_sha256(DEFAULT_VERSION), Some(DEFAULT_SHA256));
        assert_eq!(DEFAULT_SHA256.len(), 64);
        assert!(DEFAULT_SHA256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(pinned_sha256("3.22.1"), None);
    }

    #[test]
    fn versions_are_major_minor_patch() {
        for good in ["3.22.1", "3.22.6", "10.0.12"] {
            assert_eq!(parse_version(good).unwrap(), good);
        }
        for bad in [
            "", "3.22", "3.22.6.1", "v3.22.6", "3.22.x", "3..6", "3.22.6 ", "../x",
        ] {
            assert!(parse_version(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_url_is_under_the_release_branch() {
        assert_eq!(
            tarball_url("3.22.6").unwrap(),
            "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/\
             alpine-minirootfs-3.22.6-x86_64.tar.gz"
        );
        assert_eq!(branch("3.21.10").unwrap(), "v3.21");
    }

    #[test]
    fn the_sha256_file_must_name_the_tarball() {
        let name = tarball_name("3.22.6");
        let line = format!("{DEFAULT_SHA256}  {name}\n");
        assert_eq!(parse_sha256_file(&line, &name).unwrap(), DEFAULT_SHA256);
        let binary = format!("{}  *{name}", DEFAULT_SHA256.to_uppercase());
        assert_eq!(parse_sha256_file(&binary, &name).unwrap(), DEFAULT_SHA256);

        for bad in [
            String::new(),
            DEFAULT_SHA256.to_owned(),
            format!("{DEFAULT_SHA256}  other.tar.gz"),
            format!("{DEFAULT_SHA256}  {name} extra"),
            format!("{}  {name}", &DEFAULT_SHA256[1..]),
            format!("{}g  {name}", &DEFAULT_SHA256[1..]),
            "<html>not found</html>".to_owned(),
        ] {
            assert!(parse_sha256_file(&bad, &name).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn curl_is_https_only_redirects_included_and_fails_on_http_errors() {
        assert_eq!(
            strings(curl_args("https://x/y", Some(Path::new("/c/y.partial")))),
            [
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--output",
                "/c/y.partial",
                "https://x/y"
            ]
        );
        assert_eq!(
            strings(curl_args("https://x/y.sha256", None))
                .last()
                .unwrap(),
            "https://x/y.sha256"
        );
    }

    #[test]
    fn tar_unpacks_as_the_invoking_user() {
        assert_eq!(
            strings(tar_args(Path::new("/c/a.tar.gz"), Path::new("/g/rootfs"))),
            [
                "--extract",
                "--gzip",
                "--file",
                "/c/a.tar.gz",
                "--directory",
                "/g/rootfs",
                "--no-same-owner",
                "--no-same-permissions"
            ]
        );
    }

    #[test]
    fn the_metadata_names_the_release_its_hash_and_its_packages() {
        let url = tarball_url(DEFAULT_VERSION).unwrap();
        assert_eq!(
            metadata(DEFAULT_VERSION, &url, DEFAULT_SHA256, &[]),
            serde_json::json!({
                "distro": "alpine",
                "version": "3.22.6",
                "arch": "x86_64",
                "url": url,
                "sha256": DEFAULT_SHA256,
                "packages": [],
            })
        );
        let with = metadata(DEFAULT_VERSION, &url, DEFAULT_SHA256, &TLS_PACKAGES);
        let packages = with["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[2]["name"], "ssl_client");
        assert_eq!(packages[2]["version"], TLS_PACKAGES[2].version);
    }

    /// The TLS packages come from the release branch's main repository,
    /// pinned, and unpack without their signatures and metadata.
    #[test]
    fn the_tls_packages_are_pinned_and_unpack_without_their_metadata() {
        assert_eq!(
            apk_url("3.22.6", &TLS_PACKAGES[0]).unwrap(),
            format!(
                "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/libcrypto3-{}.apk",
                TLS_PACKAGES[0].version
            )
        );
        for package in &TLS_PACKAGES {
            assert_eq!(package.sha256.len(), 64, "{}", package.name);
            assert!(package.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        let args = strings(apk_tar_args(
            Path::new("/c/ssl_client-1.apk"),
            Path::new("/r"),
        ));
        assert!(args.contains(&"--exclude=.PKGINFO".to_owned()));
        assert!(args.contains(&"--exclude=.SIGN.*".to_owned()));
        assert!(args.contains(&"--no-same-owner".to_owned()));
        assert_eq!(args[..3], ["--extract", "--gzip", "--file"]);
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// tar, as the invoking user, applies the umask and drops the sticky
    /// bit: /tmp and /var/tmp come out 0755.
    #[test]
    fn tmp_and_var_tmp_become_world_writable_and_sticky() {
        let root = tempfile::tempdir().unwrap();
        for dir in ["tmp", "var/tmp", "etc"] {
            fs::create_dir_all(root.path().join(dir)).unwrap();
            set_mode(&root.path().join(dir), 0o755);
        }
        open_tmp_dirs(root.path()).unwrap();
        assert_eq!(mode(&root.path().join("tmp")), 0o1777);
        assert_eq!(mode(&root.path().join("var/tmp")), 0o1777);
        assert_eq!(mode(&root.path().join("etc")), 0o755);
        // Again, on a tree that already has them.
        open_tmp_dirs(root.path()).unwrap();
        assert_eq!(mode(&root.path().join("tmp")), 0o1777);
    }

    /// A rootfs without /var/tmp is fine; one whose /var/tmp is a symbolic
    /// link is left alone, since chmod would follow it out of the tree.
    #[test]
    fn a_missing_or_linked_var_tmp_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        set_mode(outside.path(), 0o700);
        fs::create_dir(root.path().join("tmp")).unwrap();
        open_tmp_dirs(root.path()).unwrap();
        assert_eq!(mode(&root.path().join("tmp")), 0o1777);

        fs::create_dir(root.path().join("var")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("var/tmp")).unwrap();
        open_tmp_dirs(root.path()).unwrap();
        assert_eq!(mode(outside.path()), 0o700);
    }

    /// Nor does a link higher up take the chmod out of the tree.
    #[test]
    fn a_linked_var_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("tmp")).unwrap();
        set_mode(&outside.path().join("tmp"), 0o700);
        std::os::unix::fs::symlink(outside.path(), root.path().join("var")).unwrap();
        open_tmp_dirs(root.path()).unwrap();
        assert_eq!(mode(&outside.path().join("tmp")), 0o700);
    }

    #[test]
    fn suffixes_go_on_the_last_component() {
        assert_eq!(
            with_suffix(Path::new("/t/guest/rootfs-alpine"), ".partial"),
            Path::new("/t/guest/rootfs-alpine.partial")
        );
    }
}
