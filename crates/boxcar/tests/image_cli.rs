// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar image` from the command line, on a cache of its own: no
//! network, nothing beyond the loopback.

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn boxcar(cache: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .arg("image")
        .args(args)
        .arg("--cache-dir")
        .arg(cache)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn an_empty_cache_lists_nothing_and_is_made_private() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let out = boxcar(&cache, &["ls"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    assert_eq!(
        std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let out = boxcar(&cache, &["prune"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "removed 0 images and 0 blobs\n");
}

#[test]
fn rm_of_what_is_not_there_says_so_and_a_bad_target_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let out = boxcar(&cache, &["rm", "ghcr.io/a/b:v1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("no such image or ref"),
        "{}",
        text(&out.stderr)
    );
    let digest = format!("sha256:{}", "0".repeat(64));
    let out = boxcar(&cache, &["rm", &digest]);
    assert_eq!(out.status.code(), Some(1));
    let out = boxcar(&cache, &["rm", "Not A Ref"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("neither a digest nor a reference"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn pull_refuses_a_bad_reference_and_reports_an_unreachable_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let out = boxcar(&cache, &["pull", "Not A Ref"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("error:"),
        "{}",
        text(&out.stderr)
    );
    // A loopback port nobody listens on: refused at once, exit 1, and the
    // cache holds nothing half-done.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = boxcar(
        &cache,
        &["pull", &format!("127.0.0.1:{port}/library/app:latest")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("pulling"),
        "{}",
        text(&out.stderr)
    );
    let images: Vec<_> = std::fs::read_dir(cache.join("images")).unwrap().collect();
    assert!(images.is_empty());
}

#[test]
fn help_names_the_image_commands() {
    let out = Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["image", "--help"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let help = text(&out.stdout);
    for word in ["pull", "ls", "rm", "prune"] {
        assert!(help.contains(word), "{help}");
    }
}
