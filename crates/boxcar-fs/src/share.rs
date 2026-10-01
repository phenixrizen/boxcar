// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! One virtio-fs share: which host directory is served, under which tag, and
//! how the guest may cache it.

use std::path::PathBuf;
use std::time::Duration;

use fuse_backend_rs::passthrough::{CachePolicy, Config};

/// How long the guest may cache entries and attributes of a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePolicyKind {
    /// Cache freely: the host does not change the directory behind the
    /// guest's back. For the root filesystem.
    Always,
    /// Revalidate on open and after a short timeout: the host may edit files
    /// while the guest runs. For the workspace.
    Auto,
}

impl CachePolicyKind {
    /// The name recorded in `fs.mount`.
    pub fn as_str(self) -> &'static str {
        match self {
            CachePolicyKind::Always => "always",
            CachePolicyKind::Auto => "auto",
        }
    }

    /// Entry and attribute timeout the guest is told to use.
    fn timeout(self) -> Duration {
        match self {
            CachePolicyKind::Always => Duration::from_secs(5),
            CachePolicyKind::Auto => Duration::from_secs(1),
        }
    }
}

/// A host directory served to the guest over virtio-fs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsShareConfig {
    /// The virtio-fs tag the guest mounts: `root` or `workspace`.
    pub tag: String,
    /// The directory served. It must be valid UTF-8, since the passthrough
    /// takes its root as a `String`; the device rejects any other.
    pub host_dir: PathBuf,
    /// Where the guest mounts the share, for the record.
    pub guest_path: String,
    /// `Always` for the root filesystem, `Auto` for the workspace.
    pub cache: CachePolicyKind,
}

/// The passthrough configuration for `share`: rooted at `host_dir`, with the
/// share's cache policy and timeouts, extended attributes on, and the
/// write-back cache off, so every write reaches the host (and the audit)
/// when the guest makes it.
pub fn passthrough_config(share: &FsShareConfig) -> Config {
    let timeout = share.cache.timeout();
    Config {
        root_dir: share.host_dir.to_string_lossy().into_owned(),
        cache_policy: match share.cache {
            CachePolicyKind::Always => CachePolicy::Always,
            CachePolicyKind::Auto => CachePolicy::Auto,
        },
        writeback: false,
        xattr: true,
        do_import: true,
        entry_timeout: timeout,
        attr_timeout: timeout,
        ..Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(cache: CachePolicyKind) -> FsShareConfig {
        FsShareConfig {
            tag: "root".into(),
            host_dir: PathBuf::from("/srv/rootfs"),
            guest_path: "/".into(),
            cache,
        }
    }

    #[test]
    fn always_caches_for_five_seconds() {
        let cfg = passthrough_config(&share(CachePolicyKind::Always));
        assert_eq!(cfg.root_dir, "/srv/rootfs");
        assert_eq!(cfg.cache_policy, CachePolicy::Always);
        assert_eq!(cfg.entry_timeout, Duration::from_secs(5));
        assert_eq!(cfg.attr_timeout, Duration::from_secs(5));
        assert!(!cfg.writeback);
        assert!(cfg.xattr);
        assert!(cfg.do_import);
    }

    #[test]
    fn auto_caches_for_one_second() {
        let cfg = passthrough_config(&share(CachePolicyKind::Auto));
        assert_eq!(cfg.cache_policy, CachePolicy::Auto);
        assert_eq!(cfg.entry_timeout, Duration::from_secs(1));
        assert_eq!(cfg.attr_timeout, Duration::from_secs(1));
        assert!(!cfg.writeback);
    }

    #[test]
    fn policy_names() {
        assert_eq!(CachePolicyKind::Always.as_str(), "always");
        assert_eq!(CachePolicyKind::Auto.as_str(), "auto");
    }
}
