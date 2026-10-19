// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The built-in profiles: policy files in the binary, chosen by name
//! (`boxcar run --policy NAME`) and printed by `boxcar policy profile
//! NAME`.
//!
//! `agent-isolate` lets an agent reach its model provider (allowed and
//! inspected), the package registries and the git hosts, and nothing else;
//! it may write anywhere on its shares. `agent-isolate-strict` has the same
//! network, keeps writes to `/workspace` and `/tmp`, and refuses to run the
//! usual network tools.

/// The profiles, by name.
pub const NAMES: [&str; 2] = ["agent-isolate", "agent-isolate-strict"];

/// The reconciler's own `indicator_removal` paths as globs (shell
/// histories, logs, the loader's preload file, root's ssh directory;
/// `boxcar-audit`'s `reconcile/paths.rs`), which the profiles list.
pub const RECONCILER_INDICATORS: [&str; 4] = [
    "**/.*_history",
    "/var/log/**",
    "/etc/ld.so.preload",
    "/root/.ssh/**",
];

/// The text of the profile `name`, if there is one by that name.
pub fn text(name: &str) -> Option<&'static str> {
    match name {
        "agent-isolate" => Some(AGENT_ISOLATE),
        "agent-isolate-strict" => Some(AGENT_ISOLATE_STRICT),
        _ => None,
    }
}

const AGENT_ISOLATE: &str = r#"# agent-isolate: an agent, its model provider, its package managers.
#
# The model providers are allowed and inspected: the gate ends their TLS,
# relays the traffic unchanged and records the model calls and the tool
# spans. The package registries and git hosts are allowed on 443, and the
# Debian mirrors on 80 too (apt's default sources are plain HTTP, signed).
# Everything else is denied. The session may write all of its shares: with
# --image the root share is the session's own copy of the image.
version = 1

[egress]
default = "deny"
allow = [
    # Model providers.
    "api.anthropic.com:443",
    "*.anthropic.com:443",
    "api.openai.com:443",
    "chatgpt.com:443",
    "*.openai.com:443",
    # Package registries.
    "registry.npmjs.org:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "crates.io:443",
    "static.crates.io:443",
    "index.crates.io:443",
    "dl-cdn.alpinelinux.org:443",
    "deb.debian.org:443",
    "deb.debian.org:80",
    "security.debian.org:443",
    "security.debian.org:80",
    # Git hosts.
    "github.com:443",
    "*.githubusercontent.com:443",
    "codeload.github.com:443",
    "gitlab.com:443",
]
inspect = [
    "api.anthropic.com:443",
    "*.anthropic.com:443",
    "api.openai.com:443",
    "chatgpt.com:443",
    "*.openai.com:443",
]
max_dns_qps = 20

[fs]
writable = ["/**"]
indicators = ["**/.*_history", "/var/log/**", "/etc/ld.so.preload", "/root/.ssh/**"]
"#;

const AGENT_ISOLATE_STRICT: &str = r#"# agent-isolate-strict: agent-isolate's network; writes kept to /workspace
# and /tmp, so a package install fails; the usual network tools refused.
#
# [exec] deny refuses program files, not the names they are run by: a
# BusyBox applet (/usr/bin/nc linking to /bin/busybox) is BusyBox, so these
# stop a real nc binary but not the applet. A refused program cannot be
# opened at all, so a loader or a copy does not run it either; Debian's nc
# leads to nc.openbsd or nc.traditional, named too.
version = 1

[egress]
default = "deny"
allow = [
    # Model providers.
    "api.anthropic.com:443",
    "*.anthropic.com:443",
    "api.openai.com:443",
    "chatgpt.com:443",
    "*.openai.com:443",
    # Package registries.
    "registry.npmjs.org:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "crates.io:443",
    "static.crates.io:443",
    "index.crates.io:443",
    "dl-cdn.alpinelinux.org:443",
    "deb.debian.org:443",
    "deb.debian.org:80",
    "security.debian.org:443",
    "security.debian.org:80",
    # Git hosts.
    "github.com:443",
    "*.githubusercontent.com:443",
    "codeload.github.com:443",
    "gitlab.com:443",
]
inspect = [
    "api.anthropic.com:443",
    "*.anthropic.com:443",
    "api.openai.com:443",
    "chatgpt.com:443",
    "*.openai.com:443",
]
max_dns_qps = 20

[fs]
writable = ["/workspace/**", "/tmp/**"]
indicators = ["**/.*_history", "/var/log/**", "/etc/ld.so.preload", "/root/.ssh/**"]

[exec]
deny = ["**/nc", "**/nc.openbsd", "**/nc.traditional", "**/netcat", "**/ncat", "**/socat", "**/telnet"]
"#;

#[cfg(test)]
mod tests {
    use boxcar_net::Policy;

    use super::*;
    use crate::parse;

    /// The line policy `agent-isolate`'s egress was written from.
    const AGENT_ISOLATE_LINES: &str = "
default deny
allow api.anthropic.com:443
allow *.anthropic.com:443
allow api.openai.com:443
allow chatgpt.com:443
allow *.openai.com:443
allow registry.npmjs.org:443
allow pypi.org:443
allow files.pythonhosted.org:443
allow crates.io:443
allow static.crates.io:443
allow index.crates.io:443
allow dl-cdn.alpinelinux.org:443
allow deb.debian.org:443
allow deb.debian.org:80
allow security.debian.org:443
allow security.debian.org:80
allow github.com:443
allow *.githubusercontent.com:443
allow codeload.github.com:443
allow gitlab.com:443
inspect api.anthropic.com:443
inspect *.anthropic.com:443
inspect api.openai.com:443
inspect chatgpt.com:443
inspect *.openai.com:443
";

    fn profile(name: &str) -> crate::PolicyFile {
        let text = text(name).unwrap_or_else(|| panic!("no profile {name}"));
        parse(text).unwrap_or_else(|error| panic!("{name}: {error}"))
    }

    /// `agent-isolate`'s egress is the line policy it was written from,
    /// rule for rule and text for text.
    #[test]
    fn agent_isolate_egress_is_the_line_policy_it_was_written_from() {
        let lines: Vec<&str> = AGENT_ISOLATE_LINES.lines().collect();
        let want = Policy::parse(&lines).unwrap();
        let isolate = profile("agent-isolate");
        assert_eq!(isolate.egress.policy, want);
        assert_eq!(isolate.egress.max_dns_qps, Some(20));
        assert_eq!(isolate.fs.writable, ["/**"]);
        assert!(isolate.fs.denied.is_empty());
        assert_eq!(isolate.fs.indicators, RECONCILER_INDICATORS);
        assert!(isolate.exec.deny.is_empty());
        assert!(isolate.spans.keep_tool_args);
        assert!(!isolate.record.scrub_argv);
    }

    /// The strict profile has the same network and indicators, and keeps
    /// writes and programs in.
    #[test]
    fn the_strict_profile_keeps_writes_and_programs_in() {
        let isolate = profile("agent-isolate");
        let strict = profile("agent-isolate-strict");
        assert_eq!(strict.egress, isolate.egress);
        assert_eq!(strict.fs.writable, ["/workspace/**", "/tmp/**"]);
        assert!(strict.fs.denied.is_empty());
        assert_eq!(strict.fs.indicators, isolate.fs.indicators);
        assert_eq!(
            strict.exec.deny,
            [
                "**/nc",
                "**/nc.openbsd",
                "**/nc.traditional",
                "**/netcat",
                "**/ncat",
                "**/socat",
                "**/telnet"
            ]
        );
    }

    /// Every name has a text, and no other name does.
    #[test]
    fn every_profile_is_named() {
        for name in NAMES {
            assert!(text(name).is_some(), "{name}");
            profile(name);
        }
        for other in [
            "",
            "agent",
            "Agent-Isolate",
            "agent-isolate.toml",
            "default",
        ] {
            assert_eq!(text(other), None, "{other:?}");
        }
    }

    /// The profiles' globs match what they say, as `globset` reads them
    /// with `literal_separator`: the histories anywhere, the logs and root's
    /// ssh files beneath their directories, the network tools wherever
    /// their program files are; and nothing else.
    #[test]
    fn the_profiles_globs_match_what_they_name() {
        let set = |globs: &[String]| {
            let mut builder = globset::GlobSetBuilder::new();
            for glob in globs {
                builder.add(
                    globset::GlobBuilder::new(glob)
                        .literal_separator(true)
                        .build()
                        .unwrap(),
                );
            }
            builder.build().unwrap()
        };
        let strict = profile("agent-isolate-strict");
        let indicators = set(&strict.fs.indicators);
        for path in [
            "/root/.bash_history",
            "/home/agent/.ash_history",
            "/workspace/project/.zsh_history",
            "/var/log/messages",
            "/var/log/apk/apk.log",
            "/etc/ld.so.preload",
            "/root/.ssh/authorized_keys",
        ] {
            assert!(indicators.is_match(path), "{path}");
        }
        for path in [
            "/var/logs/x",
            "/etc/ld.so.preload.d/x",
            "/root/.sshx/a",
            "/workspace/history",
        ] {
            assert!(!indicators.is_match(path), "{path}");
        }
        let programs = set(&strict.exec.deny);
        for path in [
            "/usr/bin/nc",
            "/bin/nc",
            "/usr/local/bin/ncat",
            "/usr/bin/socat",
            "/workspace/tools/telnet",
            "/bin/nc.openbsd",
            "/bin/nc.traditional",
            "/usr/bin/netcat",
        ] {
            assert!(programs.is_match(path), "{path}");
        }
        for path in [
            "/usr/bin/ncdu",
            "/usr/bin/nc.other",
            "/bin/busybox",
            "/usr/bin/telnetd",
        ] {
            assert!(!programs.is_match(path), "{path}");
        }
        let writable = set(&strict.fs.writable);
        for path in ["/workspace/a", "/workspace/a/b/c", "/tmp/x"] {
            assert!(writable.is_match(path), "{path}");
        }
        for path in ["/usr/bin/x", "/etc/passwd", "/workspacex/a", "/tmpx"] {
            assert!(!writable.is_match(path), "{path}");
        }
        let everything = set(&profile("agent-isolate").fs.writable);
        assert!(everything.is_match("/usr/lib/x"));
        assert!(everything.is_match("/workspace/a"));
    }

    /// The model providers are inspected, so the session makes its CA.
    #[test]
    fn the_providers_are_inspected() {
        let isolate = profile("agent-isolate");
        let inspected: Vec<&str> = isolate
            .egress
            .policy
            .inspect
            .iter()
            .map(|line| line.text.as_str())
            .collect();
        assert_eq!(
            inspected,
            [
                "inspect api.anthropic.com:443",
                "inspect *.anthropic.com:443",
                "inspect api.openai.com:443",
                "inspect chatgpt.com:443",
                "inspect *.openai.com:443",
            ]
        );
    }
}
