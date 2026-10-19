// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A policy file as read and checked: the compiled egress, the path and
//! program globs as written, and the two settings.

use crate::profiles::RECONCILER_INDICATORS;

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
    /// What a mutating operation must match: `/workspace/**` when the file
    /// gives no `writable`.
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

    /// What the file sets that this build does not put into force yet, by
    /// its section and key: writes kept from anything but the whole tree,
    /// denied paths, indicators beyond the reconciler's own, denied
    /// programs, `keep_tool_args = false`, `scrub_argv = true`. Empty for a
    /// file whose only effect is its egress, such as `agent-isolate`. M5's
    /// Task 5 enforces them, and this goes.
    pub fn not_in_force(&self) -> Vec<&'static str> {
        let mut pending = Vec::new();
        if !self.fs.writable.iter().any(|glob| glob == "/**") {
            pending.push("[fs] writable");
        }
        if !self.fs.denied.is_empty() {
            pending.push("[fs] denied");
        }
        if self
            .fs
            .indicators
            .iter()
            .any(|glob| !RECONCILER_INDICATORS.contains(&glob.as_str()))
        {
            pending.push("[fs] indicators");
        }
        if !self.exec.deny.is_empty() {
            pending.push("[exec] deny");
        }
        if !self.spans.keep_tool_args {
            pending.push("[spans] keep_tool_args");
        }
        if self.record.scrub_argv {
            pending.push("[record] scrub_argv");
        }
        pending
    }
}
