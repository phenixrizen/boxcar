// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The arguments a process ran with, kept in memory when the log records
//! them scrubbed (`boxcar run --scrub-argv`).
//!
//! The sensor's ingest scrubs each `proc.exec`'s `argv` before the record
//! is made ([`RawArgv::scrub`]); where that changed something, the argv as
//! run waits here, never recorded, for the reconciler, which compares
//! commands with what really ran ([`RawArgv::take`]). Every reader of the
//! log, the reconciler's replay after a lag included, sees the scrubbed
//! copy.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use boxcar_proto::redact::scrub_argv;
use boxcar_proto::ProcExec;

/// What a redacted value reads as in an argv record.
const REDACTED: &str = "[redacted]";

/// The most execs whose argv as run waits for the reconciler; past it the
/// oldest goes.
pub const MAX_RAW_ARGV: usize = 4096;
/// The most bytes those argvs hold.
pub const MAX_RAW_ARGV_BYTES: usize = 8 * 1024 * 1024;

/// One exec: its process (`tgid`, `start_ns`) and the guest time of its
/// record, which tells a process's execs apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExecKey {
    pub tgid: u32,
    pub start_ns: u64,
    pub ts_guest_ns: u64,
}

impl ExecKey {
    /// The key of `exec`, recorded at `ts_guest_ns`.
    pub fn of(exec: &ProcExec, ts_guest_ns: u64) -> ExecKey {
        ExecKey {
            tgid: exec.tgid,
            start_ns: exec.start_ns,
            ts_guest_ns,
        }
    }
}

/// The argvs as run of the execs recorded scrubbed. Cheap to clone; one
/// per session.
#[derive(Clone, Debug, Default)]
pub struct RawArgv {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    argv: HashMap<ExecKey, (Vec<String>, usize)>,
    order: VecDeque<ExecKey>,
    bytes: usize,
}

impl RawArgv {
    pub fn new() -> RawArgv {
        RawArgv::default()
    }

    /// Scrubs `exec`'s argv for its record, recorded at `ts_guest_ns`;
    /// where that changed something, keeps the argv as run.
    pub fn scrub(&self, ts_guest_ns: u64, exec: &mut ProcExec) {
        let scrubbed = scrub_argv(&exec.argv);
        if scrubbed == exec.argv {
            return;
        }
        let raw = std::mem::replace(&mut exec.argv, scrubbed);
        self.put(ExecKey::of(exec, ts_guest_ns), raw);
    }

    fn put(&self, key: ExecKey, argv: Vec<String>) {
        let len = argv.iter().map(String::len).sum::<usize>();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, old)) = inner.argv.insert(key, (argv, len)) {
            inner.bytes -= old;
        } else {
            inner.order.push_back(key);
        }
        inner.bytes += len;
        while inner.order.len() > MAX_RAW_ARGV || inner.bytes > MAX_RAW_ARGV_BYTES {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some((_, old)) = inner.argv.remove(&oldest) {
                inner.bytes -= old;
            }
        }
    }

    /// The argv as run of the exec `key`, if it was recorded scrubbed and
    /// is still kept; it is let go.
    pub fn take(&self, key: ExecKey) -> Option<Vec<String>> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (argv, len) = inner.argv.remove(&key)?;
        inner.bytes -= len;
        if let Some(at) = inner.order.iter().position(|k| *k == key) {
            inner.order.remove(at);
        }
        Some(argv)
    }

    /// How many argvs wait.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .argv
            .len()
    }

    /// Whether none waits.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Whether an argv taken only from its record is complete enough to
/// compare. A redaction mark may stand for any value; the as-run copy is
/// needed to distinguish it from a literal mark.
pub fn recorded_argv_is_complete(argv: &[String]) -> bool {
    !argv.iter().any(|arg| arg.contains(REDACTED))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(argv: &[&str]) -> ProcExec {
        ProcExec {
            tid: 7,
            tgid: 7,
            ppid: 1,
            uid: 0,
            gid: 0,
            filename: "/usr/bin/curl".into(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            argv_truncated: false,
            start_ns: 100,
            cgroup_id: 0,
        }
    }

    #[test]
    fn a_scrubbed_argv_is_kept_as_run_until_taken() {
        let raw = RawArgv::new();
        let mut plain = exec(&["ls", "-l"]);
        raw.scrub(10, &mut plain);
        assert_eq!(plain.argv, ["ls", "-l"]);
        assert!(raw.is_empty(), "nothing scrubbed, nothing kept");

        let mut secret = exec(&["curl", "--token=abc", "https://x.test/"]);
        raw.scrub(20, &mut secret);
        assert_eq!(secret.argv[1], "--token=[redacted]");
        let key = ExecKey::of(&secret, 20);
        assert_eq!(
            raw.take(key).unwrap(),
            ["curl", "--token=abc", "https://x.test/"]
        );
        assert!(raw.take(key).is_none(), "taken once");
        assert!(raw.is_empty());
    }

    #[test]
    fn kept_argvs_are_bounded() {
        let raw = RawArgv::new();
        for n in 0..(MAX_RAW_ARGV as u64 + 10) {
            let mut e = exec(&["curl", "--token=abc"]);
            raw.scrub(n, &mut e);
        }
        assert_eq!(raw.len(), MAX_RAW_ARGV);
        let first = ExecKey::of(&exec(&[]), 0);
        assert!(raw.take(first).is_none(), "the oldest went");

        let raw = RawArgv::new();
        let long = format!("--token={}", "a".repeat(1024 * 1024));
        for n in 0..20u64 {
            let mut e = exec(&["curl", &long]);
            raw.scrub(n, &mut e);
        }
        let held = raw.inner.lock().unwrap().bytes;
        assert!(held <= MAX_RAW_ARGV_BYTES, "{held}");
    }

    #[test]
    fn a_recorded_redaction_needs_the_as_run_copy() {
        assert!(recorded_argv_is_complete(&[
            "curl".into(),
            "https://example.test/".into()
        ]));
        assert!(!recorded_argv_is_complete(&[
            "curl".into(),
            "--token=[redacted]".into()
        ]));
    }
}
