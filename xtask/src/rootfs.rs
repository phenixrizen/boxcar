// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask rootfs alpine`: the root filesystem the guest boots from.
//!
//! Downloads `alpine-minirootfs-<version>-x86_64.tar.gz` and its `.sha256`
//! from dl-cdn.alpinelinux.org into `target/rootfs-cache`, checks the
//! tarball's SHA-256 against the hash pinned here (for the default version)
//! and against the published `.sha256`, and unpacks it with `tar` into
//! `target/guest/rootfs-alpine` as the invoking user, with
//! `etc/boxcar-rootfs.json` saying what it is. `curl`, `sha256sum` and `tar`
//! run as argv arrays; nothing goes through a shell.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Subcommand};

/// The Alpine release unpacked by default: the latest 3.22.
pub const DEFAULT_VERSION: &str = "3.22.6";

/// The SHA-256 of [`DEFAULT_VERSION`]'s x86_64 minirootfs tarball, from the
/// release's `latest-releases.yaml` and `.sha256`.
pub const DEFAULT_SHA256: &str = "27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2";

/// Where Alpine releases are published.
const MIRROR: &str = "https://dl-cdn.alpinelinux.org/alpine";

/// The only architecture the guest has.
const ARCH: &str = "x86_64";

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
    }
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

    let out = guest_dir.join("rootfs-alpine");
    unpack(&tarball, &out, &metadata(version, &url, &expected))?;
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

/// The arguments after `curl` that fetch `url` over HTTPS only, failing on
/// an HTTP error, into `out` (or to stdout without one).
fn curl_args(url: &str, out: Option<&Path>) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
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

/// What `etc/boxcar-rootfs.json` says about the rootfs.
fn metadata(version: &str, url: &str, sha256: &str) -> serde_json::Value {
    serde_json::json!({
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
fn unpack(tarball: &Path, out: &Path, metadata: &serde_json::Value) -> Result<()> {
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

    let json = partial.join("etc/boxcar-rootfs.json");
    let mut text = serde_json::to_string_pretty(metadata)?;
    text.push('\n');
    fs::write(&json, text).with_context(|| format!("write {}", json.display()))?;

    if out.exists() {
        fs::remove_dir_all(out).with_context(|| format!("remove {}", out.display()))?;
    }
    fs::rename(&partial, out).with_context(|| format!("rename to {}", out.display()))
}

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
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
    fn curl_is_https_only_and_fails_on_http_errors() {
        assert_eq!(
            strings(curl_args("https://x/y", Some(Path::new("/c/y.partial")))),
            [
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
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
    fn the_metadata_names_the_release_and_its_hash() {
        let url = tarball_url(DEFAULT_VERSION).unwrap();
        assert_eq!(
            metadata(DEFAULT_VERSION, &url, DEFAULT_SHA256),
            serde_json::json!({
                "distro": "alpine",
                "version": "3.22.6",
                "arch": "x86_64",
                "url": url,
                "sha256": DEFAULT_SHA256,
            })
        );
    }

    #[test]
    fn suffixes_go_on_the_last_component() {
        assert_eq!(
            with_suffix(Path::new("/t/guest/rootfs-alpine"), ".partial"),
            Path::new("/t/guest/rootfs-alpine.partial")
        );
    }
}
