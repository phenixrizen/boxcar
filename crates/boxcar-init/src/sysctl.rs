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

/// Writes the settings a session's config asks for, `[name, value]` with
/// dotted names, after [`SYSCTLS`]. Best effort, as [`apply`]: a name that
/// is not one ([`config_path`]), a missing file or a refused value gets a
/// warning.
pub fn apply_config(settings: &[(String, String)]) {
    for (name, value) in settings {
        let Some(path) = config_path(name) else {
            warn(&format!("sysctl {name:?}: not a setting's name"));
            continue;
        };
        if let Err(e) = write(&Path::new(PROC_SYS).join(&path), value) {
            warn(&format!("sysctl {name}={value}: {e}"));
        }
    }
}

/// The path under `/proc/sys` of the dotted setting `name`: its parts,
/// each letters, digits, `_` or `-`, joined by `/`. `None` for anything
/// else, which could name a file outside `/proc/sys` or none.
pub fn config_path(name: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in name.split('.') {
        let ok = !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !ok {
            return None;
        }
        parts.push(part);
    }
    Some(parts.join("/"))
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

    /// A dotted name from the config is a path under `/proc/sys`; one
    /// that could leave it, or names nothing, is refused.
    #[test]
    fn a_config_sysctl_names_a_file_under_proc_sys() {
        assert_eq!(
            config_path("vm.overcommit_memory").as_deref(),
            Some("vm/overcommit_memory")
        );
        assert_eq!(
            config_path("net.ipv4.ip_forward").as_deref(),
            Some("net/ipv4/ip_forward")
        );
        for bad in [
            "", ".", "vm.", ".vm", "vm..x", "../etc", "vm/x", "a b", "vm.\0",
        ] {
            assert_eq!(config_path(bad), None, "{bad:?}");
        }
    }
}
