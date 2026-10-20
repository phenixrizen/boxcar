// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The paths whose removal or truncation is an `indicator_removal` finding:
//! shell histories, logs, the loader's preload file, root's ssh directory,
//! and whatever a policy file's `[fs] indicators` adds ([`PolicyIndicators`]).
//! Paths are as the filesystem records carry them: absolute in the `root`
//! share, relative to the share in `workspace`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// The guest directory each share is mounted at, by its record `mount`.
pub const MOUNTS: [(&str, &str); 2] = [("root", "/"), ("workspace", "/workspace")];

/// A policy file's `[fs] indicators`: globs of guest paths (`globset`, with
/// `literal_separator`, absolute, as the policy file checks them), matched
/// against a record's path joined to its share's guest directory.
#[derive(Clone, Debug)]
pub struct PolicyIndicators {
    texts: Vec<String>,
    set: GlobSet,
}

impl PolicyIndicators {
    /// The indicators `globs`; an error names the glob that does not
    /// compile.
    pub fn new(globs: &[String]) -> Result<PolicyIndicators, String> {
        let mut builder = GlobSetBuilder::new();
        for text in globs {
            let glob = GlobBuilder::new(text)
                .literal_separator(true)
                .build()
                .map_err(|error| format!("{text:?}: {error}"))?;
            builder.add(glob);
        }
        let set = builder.build().map_err(|error| error.to_string())?;
        Ok(PolicyIndicators {
            texts: globs.to_vec(),
            set,
        })
    }

    /// The first glob, in the order given, that `path` in the share
    /// recorded as `mount` matches by its guest path. A mount boxcar does
    /// not serve matches nothing.
    pub fn matching(&self, mount: &str, path: &str) -> Option<&str> {
        let (_, dir) = MOUNTS.iter().find(|(name, _)| *name == mount)?;
        let dir = dir.trim_end_matches('/');
        let mut guest = String::with_capacity(dir.len() + path.len() + 1);
        guest.push_str(dir);
        if !path.starts_with('/') {
            guest.push('/');
        }
        guest.push_str(path);
        if guest.is_empty() {
            guest.push('/');
        }
        self.set
            .matches(OsStr::from_bytes(guest.as_bytes()))
            .into_iter()
            .min()
            .map(|index| self.texts[index].as_str())
    }
}

/// What a watched path is, for the finding's summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indicator {
    ShellHistory,
    Log,
    LoaderPreload,
    RootSsh,
}

impl Indicator {
    pub fn describe(self) -> &'static str {
        match self {
            Indicator::ShellHistory => "a shell history",
            Indicator::Log => "a log under /var/log",
            Indicator::LoaderPreload => "/etc/ld.so.preload",
            Indicator::RootSsh => "a file under /root/.ssh",
        }
    }
}

/// The indicator `path` is, if it is one.
pub fn indicator(path: &str) -> Option<Indicator> {
    let base = path.rsplit('/').next().unwrap_or(path);
    if base.starts_with('.') && base.ends_with("_history") {
        return Some(Indicator::ShellHistory);
    }
    if path.starts_with("/var/log/") {
        return Some(Indicator::Log);
    }
    if path == "/etc/ld.so.preload" {
        return Some(Indicator::LoaderPreload);
    }
    if path.starts_with("/root/.ssh/") {
        return Some(Indicator::RootSsh);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy's indicators match by guest path, in either share.
    #[test]
    fn policy_indicators_match_by_guest_path() {
        let globs = vec![
            "/workspace/notes/**".to_owned(),
            "/opt/audit/*.log".to_owned(),
        ];
        let watched = PolicyIndicators::new(&globs).unwrap();
        assert_eq!(
            watched.matching("workspace", "/notes/a.md"),
            Some("/workspace/notes/**")
        );
        assert_eq!(
            watched.matching("workspace", "notes/a.md"),
            Some("/workspace/notes/**")
        );
        assert_eq!(
            watched.matching("root", "/workspace/notes/a.md"),
            Some("/workspace/notes/**")
        );
        assert_eq!(
            watched.matching("root", "/opt/audit/x.log"),
            Some("/opt/audit/*.log")
        );
        assert_eq!(watched.matching("root", "/opt/audit/d/x.log"), None);
        assert_eq!(watched.matching("root", "/notes/a.md"), None);
        assert_eq!(watched.matching("scratch", "/notes/a.md"), None);
        assert!(PolicyIndicators::new(&["/a/[b".to_owned()]).is_err());
    }

    #[test]
    fn path_watch_matches_the_indicator_set() {
        assert_eq!(
            indicator("/home/agent/.ash_history"),
            Some(Indicator::ShellHistory)
        );
        assert_eq!(indicator(".bash_history"), Some(Indicator::ShellHistory));
        assert_eq!(
            indicator("project/.zsh_history"),
            Some(Indicator::ShellHistory)
        );
        assert_eq!(indicator("/var/log/messages"), Some(Indicator::Log));
        assert_eq!(indicator("/var/log/nginx/access.log"), Some(Indicator::Log));
        assert_eq!(
            indicator("/etc/ld.so.preload"),
            Some(Indicator::LoaderPreload)
        );
        assert_eq!(
            indicator("/root/.ssh/authorized_keys"),
            Some(Indicator::RootSsh)
        );
        for other in [
            "/var/logs/x",
            "/home/agent/history",
            "/etc/ld.so.cache",
            "/root/.sshd",
            "notes_history.txt",
            "",
        ] {
            assert_eq!(indicator(other), None, "{other}");
        }
    }
}
