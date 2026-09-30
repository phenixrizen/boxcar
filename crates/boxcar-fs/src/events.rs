// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! From filesystem operations to audit submissions: who did it, how it
//! ended, and the two ways into the log.
//!
//! # Who: the subject
//!
//! Every FUSE request carries the guest's `uid`, `gid` and `pid`, and the
//! record's [`Subject`] is exactly those. The `pid` is a thread id: the guest
//! kernel fills it with `pid_nr_ns(task_pid(current), fc->pid_ns)`, the TID
//! of the calling thread in the mount's pid namespace, not its thread group
//! id. It is recorded as given; mapping it to a process belongs to whoever
//! joins these records with the guest's own.
//!
//! # Into the log
//!
//! [`Events::record`] is for the events that are never dropped: open,
//! create, close, unlink, rmdir, rename, mkdir, mknod, symlink, link,
//! setattr, fallocate, xattr, denied and mount. It waits while the audit
//! channel is full. [`Events::sample`] is for `fs.read`, `fs.write` and
//! `fs.readdir`, and never waits: on a full channel the event is dropped
//! and counted by the sink.
//!
//! A closed log does not fail the guest's filesystem: the operation has
//! already happened, and refusing its reply would only break the guest
//! during shutdown. The first refusal is logged at error level.

use std::ffi::CStr;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use boxcar_audit::{AuditSink, EmitError, Priority, Submission};
use boxcar_proto::limits::{truncate_utf8, MAX_PATH};
use boxcar_proto::{OpResult, Payload, Ring, Subject};
use fuse_backend_rs::api::filesystem::Context;

/// `__FMODE_EXEC`: set in the open flags of an `execve`.
const FMODE_EXEC: u32 = 0x20;

/// The open flags `flags_decoded` names, besides the access mode, in order.
const FLAG_NAMES: [(libc::c_int, &str); 8] = [
    (libc::O_CREAT, "O_CREAT"),
    (libc::O_TRUNC, "O_TRUNC"),
    (libc::O_APPEND, "O_APPEND"),
    (libc::O_EXCL, "O_EXCL"),
    (libc::O_DIRECTORY, "O_DIRECTORY"),
    (libc::O_NOFOLLOW, "O_NOFOLLOW"),
    (libc::O_CLOEXEC, "O_CLOEXEC"),
    (libc::O_PATH, "O_PATH"),
];

/// Sends one share's events to the audit log.
pub(crate) struct Events {
    sink: AuditSink,
    mount: String,
    /// Whether a refusal from a closed log has been logged yet.
    closed_reported: AtomicBool,
}

impl Events {
    pub(crate) fn new(sink: AuditSink, mount: String) -> Self {
        Events {
            sink,
            mount,
            closed_reported: AtomicBool::new(false),
        }
    }

    /// The share's tag, for the `mount` field of every event.
    pub(crate) fn mount(&self) -> String {
        self.mount.clone()
    }

    /// Records an event that must not be dropped, waiting for room.
    pub(crate) fn record(&self, subject: Option<Subject>, payload: Payload) {
        match self.sink.emit(submission(subject, payload)) {
            Ok(()) => {}
            Err(EmitError::Closed) => {
                if !self.closed_reported.swap(true, Ordering::Relaxed) {
                    tracing::error!(
                        mount = %self.mount,
                        "the audit log is closed; filesystem events are no longer recorded"
                    );
                }
            }
            Err(error @ EmitError::Checkpoint) => {
                tracing::error!(mount = %self.mount, "audit event refused: {error}");
            }
        }
    }

    /// Records an event that may be dropped when the log is busy.
    pub(crate) fn sample(&self, subject: Option<Subject>, payload: Payload) {
        // A refusal is counted by the sink and reported at the next
        // checkpoint; there is nothing to do here.
        let _ = self.sink.try_emit(submission(subject, payload));
    }
}

fn submission(subject: Option<Subject>, payload: Payload) -> Submission {
    Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject,
        payload,
        span: None,
        priority: Priority::Normal,
    }
}

/// The guest identity of a request. See the module docs for what `pid` is.
pub(crate) fn subject(ctx: &Context) -> Subject {
    Subject {
        // The FUSE header carries the pid as a u32 and fuse-backend-rs casts
        // it to i32; this undoes that cast bit for bit.
        pid: ctx.pid as u32,
        uid: ctx.uid,
        gid: ctx.gid,
    }
}

/// The Linux errno of a failed operation; EIO when the error has none.
pub(crate) fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

/// How an operation ended.
pub(crate) fn op_result<T>(result: &io::Result<T>) -> OpResult {
    match result {
        Ok(_) => OpResult::ok(),
        Err(e) => OpResult::errno(errno(e)),
    }
}

/// Whether an open is for `execve`.
pub(crate) fn is_exec(flags: u32) -> bool {
    flags & FMODE_EXEC != 0
}

/// The names of the flags set in `flags`: the access mode, then each of
/// `O_CREAT`, `O_TRUNC`, `O_APPEND`, `O_EXCL`, `O_DIRECTORY`, `O_NOFOLLOW`,
/// `O_CLOEXEC` and `O_PATH` that is set.
pub(crate) fn decode_open_flags(flags: u32) -> Vec<String> {
    // The flags are an int in open(2); FUSE carries them as a u32.
    let flags = flags as libc::c_int;
    let mut names = Vec::new();
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => names.push("O_RDONLY".to_owned()),
        libc::O_WRONLY => names.push("O_WRONLY".to_owned()),
        libc::O_RDWR => names.push("O_RDWR".to_owned()),
        // 3 is Linux's "no access, ioctl only" mode, which has no name.
        _ => {}
    }
    for (bit, name) in FLAG_NAMES {
        if flags & bit == bit {
            names.push(name.to_owned());
        }
    }
    names
}

/// Text for a record, cut to the path limit.
pub(crate) fn clip(text: String) -> String {
    if text.len() <= MAX_PATH {
        text
    } else {
        truncate_utf8(&text, MAX_PATH).0
    }
}

/// The path of `name` in the directory at `parent`, for a record.
pub(crate) fn child_path(parent: &str, name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    let path = if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    };
    clip(path)
}

/// A C string from the guest (a symlink target, an xattr name), for a
/// record.
pub(crate) fn c_text(text: &CStr) -> String {
    clip(text.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subject_is_the_request_identity() {
        let ctx = Context {
            uid: 1000,
            gid: 100,
            pid: 4321,
        };
        assert_eq!(
            subject(&ctx),
            Subject {
                pid: 4321,
                uid: 1000,
                gid: 100
            }
        );
        let high = Context {
            pid: u32::MAX as i32,
            ..ctx
        };
        assert_eq!(subject(&high).pid, u32::MAX);
    }

    #[test]
    fn flags_are_named_access_mode_first() {
        let o = |f: libc::c_int| f as u32;
        assert_eq!(decode_open_flags(o(libc::O_RDONLY)), ["O_RDONLY"]);
        assert_eq!(
            decode_open_flags(o(libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)),
            ["O_RDWR", "O_CREAT", "O_EXCL"]
        );
        assert_eq!(
            decode_open_flags(o(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)),
            ["O_RDONLY", "O_DIRECTORY", "O_CLOEXEC", "O_PATH"]
        );
        assert_eq!(decode_open_flags(3), Vec::<String>::new());
        // O_SYNC contains the O_DSYNC bit; neither is named, and neither is
        // mistaken for a named flag.
        assert_eq!(
            decode_open_flags(o(libc::O_WRONLY | libc::O_SYNC)),
            ["O_WRONLY"]
        );
    }

    #[test]
    fn exec_is_the_fmode_exec_bit() {
        assert!(is_exec(libc::O_RDONLY as u32 | 0x20));
        assert!(!is_exec(libc::O_RDWR as u32 | libc::O_CLOEXEC as u32));
    }

    #[test]
    fn results_carry_the_errno() {
        assert_eq!(op_result(&Ok::<(), io::Error>(())), OpResult::ok());
        let denied: io::Result<()> = Err(io::Error::from_raw_os_error(libc::EACCES));
        assert_eq!(op_result(&denied), OpResult::errno(libc::EACCES));
        let odd: io::Result<()> = Err(io::Error::other("no errno"));
        assert_eq!(op_result(&odd), OpResult::errno(libc::EIO));
    }

    #[test]
    fn child_paths_join_under_the_parent() {
        assert_eq!(child_path("/", b"a"), "/a");
        assert_eq!(child_path("/d", b"a"), "/d/a");
        assert_eq!(child_path("<ino:9>", b"a"), "<ino:9>/a");
        let long = child_path("/", "x".repeat(2 * MAX_PATH).as_bytes());
        assert!(long.len() <= MAX_PATH);
        assert!(long.ends_with('…'));
    }
}
