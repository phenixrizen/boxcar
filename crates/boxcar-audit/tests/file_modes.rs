// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session's directories and files get fixed modes whatever the process
//! umask is. `PassthroughFs::import` sets the umask to 0 for the whole
//! process, so a mode that came from the umask would leave the log world
//! writable once a share is imported.
//!
//! This test changes the process umask, so it lives in a test binary of its
//! own: no other test runs in its process while the umask is 0.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use boxcar_audit::{spawn, verify_session, Priority, Submission, WriterConfig};
use boxcar_proto::{Attrib, FsIo, OpResult, Payload, Ring, SessionId};

/// Sets the process umask for as long as it lives.
struct Umask(libc::mode_t);

impl Umask {
    fn set(mask: libc::mode_t) -> Self {
        // SAFETY: umask only swaps the process file mode creation mask.
        Umask(unsafe { libc::umask(mask) })
    }
}

impl Drop for Umask {
    fn drop(&mut self) {
        // SAFETY: as above, putting the old mask back.
        unsafe { libc::umask(self.0) };
    }
}

/// The permission bits of `path`, in octal, as `ls -l` would show them.
fn mode(path: &Path) -> String {
    let mode = fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode();
    format!("{:o}", mode & 0o7777)
}

fn event(n: u64) -> Submission {
    Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload: Payload::FsWrite(FsIo {
            mount: "workspace".into(),
            path: format!("/file-{n:06}.txt"),
            fh: n,
            offset: 0,
            len: 1,
            result: OpResult::ok(),
            attrib: Attrib::Caller,
        }),
        span: None,
        priority: Priority::Normal,
    }
}

#[test]
fn session_files_are_private_under_umask_zero() {
    let scratch = tempfile::tempdir().unwrap();
    let data_dir = scratch.path().join("data");
    let _umask = Umask::set(0);

    // Small segments, so the writer also creates a segment by rotating.
    let cfg = WriterConfig {
        segment_max_bytes: 512,
        ..WriterConfig::new(&data_dir, SessionId::new())
    };
    let (sink, writer) = spawn(cfg).unwrap();
    let session = writer.session_dir().to_path_buf();
    for n in 0..8 {
        sink.emit(event(n)).unwrap();
    }
    writer.close().unwrap();
    verify_session(&session).unwrap();

    // Every directory the writer created, down to the session.
    for dir in [&data_dir, &data_dir.join("sessions"), &session] {
        assert_eq!(mode(dir), "700", "{}", dir.display());
    }
    let mut files: Vec<String> = fs::read_dir(&session)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert!(
        files.len() >= 4 && files.contains(&"events.000002.jsonl".to_owned()),
        "a rotated session: {files:?}"
    );
    for name in &files {
        assert_eq!(mode(&session.join(name)), "600", "{name}");
    }
    assert!(files.contains(&"meta.json".to_owned()), "{files:?}");
    assert!(files.contains(&"checkpoints.jsonl".to_owned()), "{files:?}");
}
