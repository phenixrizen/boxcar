// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Running a gated test's VM under the seccomp filter, as `boxcar run`
//! runs it: in a child copy of the test binary, because the filter binds
//! the whole process it is installed in, and would bind libtest and every
//! later test in the binary.
//!
//! A test starts with `confine!();`. In the test binary as run, that
//! starts the binary again for this one test, with [`CHILD`] set, waits for
//! it, says how it ended when it did not pass, and returns. In the child
//! the test goes on, its VM installs [`SeccompMode::Enforce`] ([`seccomp`]),
//! and when it returns the child exits at once, before libtest's own
//! bookkeeping runs under the filter; a panic is left to libtest to report.

#![allow(dead_code)]

use std::io::Write;
use std::process::Command;

use boxcar_vmm::hardening::SeccompMode;

/// Set in the child that runs a test confined.
pub const CHILD: &str = "BOXCAR_TEST_CONFINED_CHILD";

/// Starts `test` confined. In the child it returns a guard that ends the
/// child when the test returns; in the parent it runs the child, asserts it
/// passed, and returns `None`.
pub fn start(test: &str) -> Option<ExitWhenDone> {
    if std::env::var_os(CHILD).is_some() {
        return Some(ExitWhenDone);
    }
    let exe = std::env::current_exe().expect("the test binary");
    let status = Command::new(exe)
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .status()
        .expect("the confined child");
    if !status.success() {
        use std::os::unix::process::ExitStatusExt;
        match status.signal() {
            Some(libc::SIGSYS) => {
                panic!("{test}: the confined child made a call off the allowlist (SIGSYS)")
            }
            Some(signal) => panic!("{test}: the confined child ended by signal {signal}"),
            None => panic!("{test}: the confined child failed: {status}"),
        }
    }
    None
}

/// The filter a test's VM installs: [`SeccompMode::Enforce`] in the
/// confined child, or [`SeccompMode::Log`] when the whole run asks for it
/// (`BOXCAR_SECCOMP=log`, as `boxcar run` reads it); none in the test
/// binary as run.
pub fn seccomp() -> SeccompMode {
    if std::env::var_os(CHILD).is_none() {
        return SeccompMode::Off;
    }
    match std::env::var("BOXCAR_SECCOMP").as_deref() {
        Ok("log") => SeccompMode::Log,
        _ => SeccompMode::Enforce,
    }
}

/// Ends the confined child when the test returns, unless it panics.
pub struct ExitWhenDone;

impl Drop for ExitWhenDone {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        // SAFETY: ends the child, whose test has passed, without libtest's
        // bookkeeping.
        unsafe { libc::_exit(0) };
    }
}

/// At the top of a `#[test]` function: runs the rest of it in a confined
/// child (see the module's docs).
macro_rules! confine {
    () => {
        fn here() {}
        let test = std::any::type_name_of_val(&here)
            .trim_end_matches("::here")
            .rsplit("::")
            .next()
            .expect("the test's name");
        let Some(_confined) = $crate::confined::start(test) else {
            return;
        };
    };
}
