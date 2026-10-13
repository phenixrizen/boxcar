// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The paths whose removal or truncation is an `indicator_removal` finding:
//! shell histories, logs, the loader's preload file, root's ssh directory.
//! Paths are as the filesystem records carry them: absolute in the `root`
//! share, relative to the share in `workspace`.

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
