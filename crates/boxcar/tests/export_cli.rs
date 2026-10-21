// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar audit export`, run as a subprocess: the fixture session's
//! exports match the library's blessed files whatever the environment, the
//! exit codes, and the POST to a collector, served here by a minimal
//! HTTP/1.1 listener on the loopback.

use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};

/// The library's fixture session and its blessed exports.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../boxcar-audit/tests/fixtures/export")
        .join(name)
}

/// A scratch directory under Cargo's per-target test tmpdir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("export-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn boxcar<I: AsRef<OsStr>>(args: impl IntoIterator<Item = I>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// What a collector was sent.
struct Received {
    path: String,
    content_type: String,
    body: Vec<u8>,
}

/// A collector that takes one POST and answers `status` with `body`.
fn collector(status: u16, body: Vec<u8>) -> (String, JoinHandle<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let served = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
        let (mut length, mut content_type) = (0usize, String::new());
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            let header = line.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').unwrap();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap(),
                "content-type" => content_type = value.trim().to_owned(),
                _ => {}
            }
        }
        let mut sent = vec![0; length];
        reader.read_exact(&mut sent).unwrap();
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        // A client that stops reading (past its cap) may close first.
        let _ = stream.write_all(&body);
        Received {
            path,
            content_type,
            body: sent,
        }
    });
    (url, served)
}

#[test]
fn an_export_to_stdout_or_a_file_is_the_blessed_one() {
    let session = fixture("session.jsonl");
    for (format, blessed) in [
        ("otlp", "session.otlp.json"),
        ("ocsf", "session.ocsf.jsonl"),
    ] {
        let out = boxcar([
            "audit".as_ref(),
            "export".as_ref(),
            session.as_os_str(),
            "--format".as_ref(),
            format.as_ref(),
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(out.stdout, fs::read(fixture(blessed)).unwrap(), "{format}");
        assert!(
            stderr(&out).starts_with(&format!("{format}: ")),
            "{}",
            stderr(&out)
        );
    }
    let scratch = Scratch::new("out");
    let file = scratch.path("trace.json");
    let out = boxcar([
        "audit".as_ref(),
        "export".as_ref(),
        session.as_os_str(),
        "--format".as_ref(),
        "otlp".as_ref(),
        "--out".as_ref(),
        file.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert_eq!(
        fs::read(&file).unwrap(),
        fs::read(fixture("session.otlp.json")).unwrap()
    );
}

/// Review focus 8: two processes in different environments export the
/// same bytes.
#[test]
fn the_environment_changes_no_export() {
    let session = fixture("session.jsonl");
    let run = |tz: &str, lang: &str, home: &str| {
        Command::new(env!("CARGO_BIN_EXE_boxcar"))
            .args(["audit", "export", "--format", "otlp"])
            .arg(&session)
            .env("TZ", tz)
            .env("LANG", lang)
            .env("HOME", home)
            .output()
            .unwrap()
            .stdout
    };
    assert_eq!(
        run("UTC", "C", "/nonexistent"),
        run("Asia/Tokyo", "de_DE.UTF-8", "/tmp")
    );
}

#[test]
fn a_broken_log_exports_nothing_and_exits_1() {
    let scratch = Scratch::new("broken");
    let path = scratch.path("broken.jsonl");
    let text = fs::read_to_string(fixture("session.jsonl")).unwrap();
    fs::write(&path, text.replacen("claude-test", "claude-tesT", 1)).unwrap();
    let out = boxcar([
        "audit".as_ref(),
        "export".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "ocsf".as_ref(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("fail: "), "{}", stderr(&out));
}

/// The verified prefix of an incomplete log is exported, and the export
/// exits 4, unless its POST failed.
#[test]
fn an_incomplete_log_exports_what_verified_and_exits_4() {
    let scratch = Scratch::new("cut");
    let path = scratch.path("cut.jsonl");
    let mut text = fs::read_to_string(fixture("session.jsonl")).unwrap();
    text.truncate(text.len() - 10);
    fs::write(&path, &text).unwrap();
    let out = boxcar([
        "audit".as_ref(),
        "export".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "ocsf".as_ref(),
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(!out.stdout.is_empty());
    assert!(stderr(&out).contains("incomplete: "), "{}", stderr(&out));

    let (url, served) = collector(500, b"down".to_vec());
    let out = boxcar([
        "audit".as_ref(),
        "export".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "otlp".as_ref(),
        "--otlp-endpoint".as_ref(),
        url.as_ref(),
    ]);
    served.join().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn usage_errors_exit_2_before_anything_is_read() {
    for (format, url) in [
        ("ocsf", "http://127.0.0.1:4318"),
        ("otlp", "http://user:secret@127.0.0.1:4318"),
        ("otlp", "http://127.0.0.1:4318/?k=v"),
        ("otlp", "ftp://127.0.0.1"),
    ] {
        let out = boxcar([
            "audit",
            "export",
            "/nonexistent",
            "--format",
            format,
            "--otlp-endpoint",
            url,
        ]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{format} {url}: {}",
            stderr(&out)
        );
        assert!(!stderr(&out).contains("secret"), "{}", stderr(&out));
    }
}

#[test]
fn an_export_is_posted_to_the_collector() {
    let session = fixture("session.jsonl");
    let (url, served) = collector(200, br#"{"partialSuccess":{}}"#.to_vec());
    let out = boxcar([
        "audit".as_ref(),
        "export".as_ref(),
        session.as_os_str(),
        "--format".as_ref(),
        "otlp".as_ref(),
        "--otlp-endpoint".as_ref(),
        format!("{url}/").as_ref(),
    ]);
    let received = served.join().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "sent, not printed");
    assert_eq!(received.path, "/v1/traces");
    assert_eq!(received.content_type, "application/json");
    assert_eq!(
        received.body,
        fs::read(fixture("session.otlp.json")).unwrap()
    );
}

/// A plain `http` endpoint needs no trust store: the export is posted
/// from a host with none. An `https` one still needs it, and says so.
#[test]
fn a_plain_http_endpoint_needs_no_trust_store() {
    let session = fixture("session.jsonl");
    let (url, served) = collector(200, b"{}".to_vec());
    let without_roots = |endpoint: &str| {
        Command::new(env!("CARGO_BIN_EXE_boxcar"))
            .args(["audit", "export", "--format", "otlp", "--otlp-endpoint"])
            .arg(endpoint)
            .arg(&session)
            // Set, these alone are read for roots: a store with none.
            .env("SSL_CERT_FILE", "/nonexistent/roots.pem")
            .env("SSL_CERT_DIR", "/nonexistent/roots")
            .output()
            .unwrap()
    };
    let out = without_roots(&url);
    // The status first: a binary that bailed never connected, and the
    // collector would wait for it.
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(served.join().unwrap().path, "/v1/traces");

    let out = without_roots("https://127.0.0.1:9/");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        stderr(&out).contains("no root certificates found on this host"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_collector_that_refuses_fails_the_export() {
    let session = fixture("session.jsonl");
    let big = format!("{{\"pad\":\"{}\"}}", " ".repeat(100 * 1024)).into_bytes();
    for (status, body) in [
        (500, b"down".to_vec()),
        (
            200,
            br#"{"partialSuccess":{"rejectedSpans":2,"errorMessage":"bad"}}"#.to_vec(),
        ),
        (200, br#"{"partialSuccess":{"rejectedSpans":"2"}}"#.to_vec()),
        (200, b"<html>not otlp</html>".to_vec()),
        // Cut at 64 KiB, it is no JSON object.
        (200, big),
    ] {
        let (url, served) = collector(status, body);
        let out = boxcar([
            "audit".as_ref(),
            "export".as_ref(),
            session.as_os_str(),
            "--format".as_ref(),
            "otlp".as_ref(),
            "--otlp-endpoint".as_ref(),
            url.as_ref(),
        ]);
        served.join().unwrap();
        assert_eq!(out.status.code(), Some(1), "{status}: {}", stderr(&out));
    }
}
