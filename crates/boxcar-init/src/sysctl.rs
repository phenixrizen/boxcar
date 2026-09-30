// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The kernel settings init makes before the session starts, written through
//! `/proc/sys`: kernel pointers and the kernel log hidden, unprivileged BPF
//! and perf off, ptrace only of descendants, no IPv6.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use crate::console::warn;

/// Each setting: its path under `/proc/sys`, and the value written.
pub const SYSCTLS: [(&str, &str); 6] = [
    ("kernel/kptr_restrict", "2"),
    ("kernel/dmesg_restrict", "1"),
    ("kernel/unprivileged_bpf_disabled", "1"),
    ("kernel/perf_event_paranoid", "3"),
    ("kernel/yama/ptrace_scope", "1"),
    ("net/ipv6/conf/all/disable_ipv6", "1"),
];

/// Where the settings live.
const PROC_SYS: &str = "/proc/sys";

/// Writes every setting of [`SYSCTLS`]. Best effort: a setting whose file is
/// missing (the kernel lacks the feature) or refuses the value gets a
/// warning on the console, and the boot goes on.
pub fn apply() {
    apply_under(Path::new(PROC_SYS), warn);
}

/// Writes every setting of [`SYSCTLS`] under `base`, and passes what failed
/// to `report`, one message per setting.
fn apply_under(base: &Path, mut report: impl FnMut(&str)) {
    for (name, value) in SYSCTLS {
        if let Err(e) = write(&base.join(name), value) {
            report(&format!("sysctl {name}={value}: {e}"));
        }
    }
}

/// Writes `value` to the existing file `path`.
fn write(path: &Path, value: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .open(path)?
        .write_all(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn the_settings() {
        assert_eq!(
            SYSCTLS,
            [
                ("kernel/kptr_restrict", "2"),
                ("kernel/dmesg_restrict", "1"),
                ("kernel/unprivileged_bpf_disabled", "1"),
                ("kernel/perf_event_paranoid", "3"),
                ("kernel/yama/ptrace_scope", "1"),
                ("net/ipv6/conf/all/disable_ipv6", "1"),
            ]
        );
    }

    /// Present files get their value; each missing one is reported, and the
    /// rest are still written.
    #[test]
    fn each_setting_is_written_or_reported() {
        let base = std::env::temp_dir().join(format!("boxcar-init-sysctl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("kernel")).unwrap();
        fs::create_dir_all(base.join("net/ipv6/conf/all")).unwrap();
        for name in ["kernel/kptr_restrict", "net/ipv6/conf/all/disable_ipv6"] {
            fs::write(base.join(name), "0").unwrap();
        }

        let mut reports = Vec::new();
        apply_under(&base, |msg| reports.push(msg.to_owned()));

        assert_eq!(
            fs::read_to_string(base.join("kernel/kptr_restrict")).unwrap(),
            "2"
        );
        assert_eq!(
            fs::read_to_string(base.join("net/ipv6/conf/all/disable_ipv6")).unwrap(),
            "1"
        );
        assert_eq!(reports.len(), 4, "{reports:?}");
        for (report, name) in reports.iter().zip([
            "kernel/dmesg_restrict=1",
            "kernel/unprivileged_bpf_disabled=1",
            "kernel/perf_event_paranoid=3",
            "kernel/yama/ptrace_scope=1",
        ]) {
            assert!(report.starts_with(&format!("sysctl {name}: ")), "{report}");
        }
        // Missing files are not created.
        assert!(!base.join("kernel/dmesg_restrict").exists());
        fs::remove_dir_all(&base).unwrap();
    }
}
