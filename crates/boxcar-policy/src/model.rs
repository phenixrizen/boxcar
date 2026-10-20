// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A policy file as read and checked: the compiled egress, the path and
//! program globs as written, and the two settings.

/// A policy file, read and checked (see [`crate::parse`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyFile {
    pub egress: Egress,
    pub fs: FsRules,
    pub exec: ExecRules,
    pub spans: SpanSettings,
    pub record: RecordSettings,
}

/// `[egress]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Egress {
    /// The rules and inspect lines, compiled through the line policy: the
    /// default, then the denies, the allows and the inspect lines, each in
    /// the file's order.
    pub policy: boxcar_net::Policy,
    /// The DNS queries a second the guest may make, in a burst of as many;
    /// `None` when the file gives no rate.
    pub max_dns_qps: Option<u32>,
}

/// `[fs]`: globs of guest paths, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsRules {
    /// What a mutating operation must match: `/workspace/**` and `/tmp/**`
    /// when the file gives no `writable`.
    pub writable: Vec<String>,
    /// What may not be looked up, opened or changed.
    pub denied: Vec<String>,
    /// Added to the reconciler's `indicator_removal` paths.
    pub indicators: Vec<String>,
}

/// `[exec]`: globs of guest paths, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRules {
    /// The program files that may not be run.
    pub deny: Vec<String>,
}

/// `[spans]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpanSettings {
    /// Whether `tool.open` keeps a call's arguments inline (to 8 KiB), as
    /// it does by default.
    pub keep_tool_args: bool,
}

/// `[record]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordSettings {
    /// The same as `boxcar run --scrub-argv`; off by default.
    pub scrub_argv: bool,
}

impl PolicyFile {
    /// The `writable`, `denied` and `indicators` globs, the default
    /// `writable` included: `policy.loaded`'s `fs_rules`.
    pub fn fs_rules(&self) -> usize {
        self.fs.writable.len() + self.fs.denied.len() + self.fs.indicators.len()
    }

    /// The `[exec] deny` globs: `policy.loaded`'s `exec_rules`.
    pub fn exec_rules(&self) -> usize {
        self.exec.deny.len()
    }

    /// The path rules the shares put in force: `[fs] writable` and
    /// `denied`, and `[exec] deny`.
    pub fn path_spec(&self) -> boxcar_fs::PathSpec {
        boxcar_fs::PathSpec {
            writable: self.fs.writable.clone(),
            denied: self.fs.denied.clone(),
            exec_deny: self.exec.deny.clone(),
        }
    }
}
