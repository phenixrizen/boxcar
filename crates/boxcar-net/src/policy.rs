// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Policy v1: what the guest may reach and which names it may resolve.
//!
//! A policy is lines of text, one rule a line. `#` starts a comment, and
//! blank lines are ignored:
//!
//! ```text
//! default deny              # or allow; deny when no line says
//! allow example.com         # that name, any port
//! allow *.github.io:443     # every name under github.io, port 443 only
//! deny 203.0.113.0/24       # a network
//! allow 192.168.0.0/16      # lifts the built-in denial of exactly this range
//! allow 198.51.100.7:22     # a bare address is a /32
//! ```
//!
//! [`Policy::egress`] decides a connection: the guest's own network is
//! always denied; then the six [built-in private ranges](PRIVATE_RANGES)
//! are denied unless an `allow` rule names that exact range; then the rules
//! in file order, the first that matches deciding; then the default.
//! [`Policy::dns`] decides a name: the first domain rule that matches it,
//! whatever its port, else the default.
//!
//! The stack shares one policy through an `Arc<arc_swap::ArcSwap<Policy>>`
//! and loads it for every decision, so a swapped policy decides the next
//! query or connection.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

pub use boxcar_proto::audit::Verdict;

/// The rule text records give for a destination on the guest's own network.
pub const BUILTIN_GUEST_NET: &str = "builtin:guest-net";
/// The rule text records give for a destination in a built-in private range.
pub const BUILTIN_PRIVATE: &str = "builtin:private";

/// The ranges denied unless a rule allows exactly one of them: loopback,
/// the three RFC 1918 networks, shared address space (RFC 6598), and link
/// local, where cloud metadata services live.
pub const PRIVATE_RANGES: [Ipv4Net; 6] = [
    Ipv4Net::masked(Ipv4Addr::new(127, 0, 0, 0), 8),
    Ipv4Net::masked(Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::masked(Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::masked(Ipv4Addr::new(192, 168, 0, 0), 16),
    Ipv4Net::masked(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::masked(Ipv4Addr::new(169, 254, 0, 0), 16),
];

/// The guest's own network, `10.0.2.0/24`. Its gateway's DNS and DHCP are
/// answered by the stack and never reach [`Policy::egress`].
pub const GUEST_NET: Ipv4Net =
    Ipv4Net::masked(crate::config::GATEWAY_IP, crate::config::NETMASK_BITS);

/// An IPv4 network: an address and a prefix length, with no host bits set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    /// The network of `prefix` bits (at most 32) that holds `addr`.
    pub const fn masked(addr: Ipv4Addr, prefix: u8) -> Ipv4Net {
        let prefix = if prefix > 32 { 32 } else { prefix };
        Ipv4Net {
            addr: Ipv4Addr::from_bits(addr.to_bits() & mask(prefix)),
            prefix,
        }
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is on this network.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        ip.to_bits() & mask(self.prefix) == self.addr.to_bits()
    }
}

/// The netmask of a prefix length, as bits.
const fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Why text is not an [`Ipv4Net`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("{0:?} is not an address/prefix")]
    Syntax(String),
    #[error("prefix /{0} is longer than 32")]
    Prefix(String),
    #[error("{0} has host bits set; the network is {1}")]
    HostBits(String, Ipv4Net),
}

/// `a.b.c.d/n`, `n` from 0 to 32, with the host bits zero: `10.0.0.0/8`
/// parses, `10.1.2.3/8` does not.
impl FromStr for Ipv4Net {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, NetError> {
        let syntax = || NetError::Syntax(s.to_owned());
        let (addr, prefix) = s.split_once('/').ok_or_else(syntax)?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| syntax())?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return Err(syntax());
        }
        let prefix = match prefix.parse::<u8>() {
            Ok(bits) if bits <= 32 => bits,
            _ => return Err(NetError::Prefix(prefix.to_owned())),
        };
        let net = Ipv4Net::masked(addr, prefix);
        if net.addr != addr {
            return Err(NetError::HostBits(s.to_owned(), net));
        }
        Ok(net)
    }
}

/// One `allow` or `deny` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub verdict: Verdict,
    pub target: Target,
    /// The rule as written, without its comment: what records name it by.
    pub text: String,
}

/// What a rule names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// One name, `example.com`, or every name under one, `*.example.com`
    /// (not `example.com` itself); lowercase, with no trailing dot.
    Domain { pattern: String, port: Option<u16> },
    /// A network; a bare address is a /32.
    Cidr { net: Ipv4Net, port: Option<u16> },
}

/// A policy file's rules and default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The verdict when no rule matches.
    pub default: Verdict,
    /// In file order: the first that matches decides.
    pub rules: Vec<Rule>,
}

/// No rules, and deny: a policy file with nothing in it.
impl Default for Policy {
    fn default() -> Self {
        Policy {
            default: Verdict::Deny,
            rules: Vec::new(),
        }
    }
}

/// A policy line that does not parse, and why.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("policy line {line}: {kind}")]
pub struct PolicyError {
    /// From 1, counting comments and blank lines.
    pub line: usize,
    pub kind: PolicyErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyErrorKind {
    #[error("{0:?} is not a rule; a rule starts with allow, deny or default")]
    UnknownWord(String),
    #[error("default is given twice")]
    DuplicateDefault,
    #[error("default takes allow or deny")]
    Default,
    #[error("{0} takes one target: a name, *.name, address or network, and an optional :port")]
    Target(&'static str),
    #[error("{0:?} is not a port from 1 to 65535")]
    Port(String),
    #[error(
        "{0:?} is not a host name or *.name: labels of a-z, 0-9 and -, 1 to 63 long, 253 in all"
    )]
    Pattern(String),
    #[error(transparent)]
    Net(#[from] NetError),
}

impl Policy {
    /// No rules, and allow: everything but the built-in denials.
    pub fn allow_all() -> Self {
        Policy {
            default: Verdict::Allow,
            rules: Vec::new(),
        }
    }

    /// Parses a policy file's lines: `default allow|deny` at most once
    /// (deny when absent), and `allow|deny <target>`, where the target is
    /// `name[:port]`, `*.name[:port]`, `address[:port]` or
    /// `address/prefix[:port]`. Names are lowercased and lose a trailing
    /// dot. `#` starts a comment.
    pub fn parse<S: AsRef<str>>(lines: &[S]) -> Result<Policy, PolicyError> {
        let mut default = None;
        let mut rules = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let at = |kind| PolicyError {
                line: index + 1,
                kind,
            };
            let line = line.as_ref();
            let line = line.split_once('#').map_or(line, |(rule, _)| rule);
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                [] => {}
                ["default", rest @ ..] => {
                    let verdict = match rest {
                        ["allow"] => Verdict::Allow,
                        ["deny"] => Verdict::Deny,
                        _ => return Err(at(PolicyErrorKind::Default)),
                    };
                    if default.replace(verdict).is_some() {
                        return Err(at(PolicyErrorKind::DuplicateDefault));
                    }
                }
                [verb @ ("allow" | "deny"), rest @ ..] => {
                    let (verdict, verb) = if *verb == "allow" {
                        (Verdict::Allow, "allow")
                    } else {
                        (Verdict::Deny, "deny")
                    };
                    let [target] = rest else {
                        return Err(at(PolicyErrorKind::Target(verb)));
                    };
                    rules.push(Rule {
                        verdict,
                        target: parse_target(target).map_err(at)?,
                        text: format!("{verb} {target}"),
                    });
                }
                [word, ..] => return Err(at(PolicyErrorKind::UnknownWord((*word).to_owned()))),
            }
        }
        Ok(Policy {
            default: default.unwrap_or(Verdict::Deny),
            rules,
        })
    }

    /// The verdict on a connection to `dst`, which the guest knows by
    /// `names` (those the DNS cache holds for its address), and the text of
    /// the rule that decided, or `None` for the default.
    ///
    /// In order: the guest's own network ([`GUEST_NET`]) is denied as
    /// `builtin:guest-net`; an address in a [built-in private
    /// range](PRIVATE_RANGES) is denied as `builtin:private` unless an
    /// `allow` rule names exactly that range (the same address and prefix,
    /// and, if the rule has a port, this port); then the first rule that
    /// matches decides, a domain rule matching when any of `names` matches
    /// it, a network rule when it holds the address, either only on its
    /// port if it has one; then the default.
    pub fn egress(&self, dst: SocketAddrV4, names: &[String]) -> (Verdict, Option<String>) {
        let (ip, port) = (*dst.ip(), dst.port());
        if GUEST_NET.contains(ip) {
            return (Verdict::Deny, Some(BUILTIN_GUEST_NET.to_owned()));
        }
        if let Some(range) = PRIVATE_RANGES.iter().find(|range| range.contains(ip)) {
            let lifted = self.rules.iter().any(|rule| {
                rule.verdict == Verdict::Allow
                    && matches!(rule.target, Target::Cidr { net, port: on }
                        if net == *range && on_port(on, port))
            });
            if !lifted {
                return (Verdict::Deny, Some(BUILTIN_PRIVATE.to_owned()));
            }
        }
        let decided = self.rules.iter().find(|rule| match &rule.target {
            Target::Domain { pattern, port: on } => {
                on_port(*on, port) && names.iter().any(|name| name_matches(pattern, name))
            }
            Target::Cidr { net, port: on } => on_port(*on, port) && net.contains(ip),
        });
        match decided {
            Some(rule) => (rule.verdict, Some(rule.text.clone())),
            None => (self.default, None),
        }
    }

    /// The verdict on resolving `qname`: a denied name gets NXDOMAIN.
    pub fn dns(&self, qname: &str) -> Verdict {
        self.dns_rule(qname).0
    }

    /// [`dns`](Self::dns), with the text of the rule that decided, or
    /// `None` for the default.
    pub fn dns_rule(&self, qname: &str) -> (Verdict, Option<String>) {
        let decided = self.rules.iter().find(|rule| match &rule.target {
            Target::Domain { pattern, .. } => name_matches(pattern, qname),
            Target::Cidr { .. } => false,
        });
        match decided {
            Some(rule) => (rule.verdict, Some(rule.text.clone())),
            None => (self.default, None),
        }
    }
}

/// Whether a rule on port `on` (any port when `None`) covers `port`.
fn on_port(on: Option<u16>, port: u16) -> bool {
    on.is_none_or(|on| on == port)
}

/// Whether `name` matches a domain pattern: the name itself, or for
/// `*.suffix` any name under the suffix but not the suffix itself. Case
/// and one trailing dot on `name` do not matter.
fn name_matches(pattern: &str, name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return name.eq_ignore_ascii_case(pattern);
    };
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    // Where the dot before the suffix would be; there must be a label
    // before it.
    let Some(dot) = name.len().checked_sub(suffix.len() + 1) else {
        return false;
    };
    dot > 0
        && name.get(dot) == Some(&b'.')
        && name
            .get(dot + 1..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

/// A rule's target: a name or `*.name`, an address, or a network, each
/// with an optional `:port`.
fn parse_target(target: &str) -> Result<Target, PolicyErrorKind> {
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (target, None),
    };
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return Ok(Target::Cidr {
            net: Ipv4Net::masked(addr, 32),
            port,
        });
    }
    if host.contains('/') {
        return Ok(Target::Cidr {
            net: host.parse()?,
            port,
        });
    }
    Ok(Target::Domain {
        pattern: domain_pattern(host)?,
        port,
    })
}

/// A port from 1 to 65535, in decimal digits only.
fn parse_port(port: &str) -> Result<u16, PolicyErrorKind> {
    let refused = || PolicyErrorKind::Port(port.to_owned());
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(refused()),
        Ok(port) => Ok(port),
    }
}

/// `name` or `*.name` as a pattern: lowercase, without a trailing dot, and
/// a valid host name after the `*.`.
fn domain_pattern(host: &str) -> Result<String, PolicyErrorKind> {
    let lower = host.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    let suffix = name.strip_prefix("*.").unwrap_or(name);
    if !is_hostname(suffix) {
        return Err(PolicyErrorKind::Pattern(host.to_owned()));
    }
    Ok(name.to_owned())
}

/// Labels of 1 to 63 lowercase letters, digits and hyphens, 253 bytes in
/// all.
fn is_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(lines: &[&str]) -> Policy {
        Policy::parse(lines).unwrap()
    }

    fn at(ip: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), port)
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    fn allow(rule: &str) -> (Verdict, Option<String>) {
        (Verdict::Allow, Some(rule.to_owned()))
    }

    fn deny(rule: &str) -> (Verdict, Option<String>) {
        (Verdict::Deny, Some(rule.to_owned()))
    }

    /// A verdict and the rule that gave it.
    type Ruling = (Verdict, Option<String>);

    const DEFAULT_ALLOW: (Verdict, Option<String>) = (Verdict::Allow, None);
    const DEFAULT_DENY: (Verdict, Option<String>) = (Verdict::Deny, None);

    #[test]
    fn private_ranges_are_denied_unless_exactly_allowed() {
        let open = parse(&["default allow"]);
        for ip in [
            [127, 0, 0, 1],
            [127, 255, 255, 254],
            [10, 0, 0, 1],
            [10, 255, 1, 2],
            [172, 16, 0, 1],
            [172, 31, 255, 255],
            [192, 168, 1, 1],
            [100, 64, 0, 1],
            [100, 127, 255, 255],
            [169, 254, 169, 254],
        ] {
            assert_eq!(
                open.egress(at(ip, 443), &[]),
                deny(BUILTIN_PRIVATE),
                "{ip:?}"
            );
        }
        // Just outside each range.
        for ip in [
            [126, 255, 255, 255],
            [128, 0, 0, 1],
            [11, 0, 0, 1],
            [172, 15, 255, 255],
            [172, 32, 0, 0],
            [192, 169, 0, 1],
            [100, 63, 255, 255],
            [100, 128, 0, 0],
            [169, 253, 255, 255],
            [8, 8, 8, 8],
        ] {
            assert_eq!(open.egress(at(ip, 443), &[]), DEFAULT_ALLOW, "{ip:?}");
        }

        // An allow of exactly the range lifts it, and then the rules decide
        // in order as for any address.
        let lifted = parse(&[
            "default deny",
            "deny 10.1.0.0/16",
            "allow 10.0.0.0/8",
            "allow 192.168.0.0/16",
        ]);
        assert_eq!(
            lifted.egress(at([10, 2, 0, 1], 22), &[]),
            allow("allow 10.0.0.0/8")
        );
        assert_eq!(
            lifted.egress(at([10, 1, 0, 1], 22), &[]),
            deny("deny 10.1.0.0/16")
        );
        assert_eq!(
            lifted.egress(at([192, 168, 7, 7], 80), &[]),
            allow("allow 192.168.0.0/16")
        );
        assert_eq!(
            lifted.egress(at([172, 16, 0, 1], 80), &[]),
            deny(BUILTIN_PRIVATE)
        );

        // A narrower, a wider, or a differently masked allow does not lift
        // it, and nor does a name.
        let near = parse(&[
            "default allow",
            "allow 192.168.1.0/24",
            "allow 0.0.0.0/0",
            "allow 172.16.0.0/16",
            "allow 127.0.0.1",
            "allow intranet.corp",
        ]);
        for ip in [
            [192, 168, 1, 5],
            [172, 16, 0, 1],
            [127, 0, 0, 1],
            [10, 1, 1, 1],
        ] {
            assert_eq!(
                near.egress(at(ip, 443), &names(&["intranet.corp"])),
                deny(BUILTIN_PRIVATE),
                "{ip:?}"
            );
        }

        // An allow with a port lifts the range for that port only.
        let port = parse(&["allow 10.0.0.0/8:5432"]);
        assert_eq!(
            port.egress(at([10, 9, 9, 9], 5432), &[]),
            allow("allow 10.0.0.0/8:5432")
        );
        assert_eq!(
            port.egress(at([10, 9, 9, 9], 22), &[]),
            deny(BUILTIN_PRIVATE)
        );

        // The guest's own network is never reachable, the gateway included,
        // whatever the rules say.
        let everything = parse(&[
            "default allow",
            "allow 10.0.0.0/8",
            "allow 10.0.2.0/24",
            "allow 10.0.2.2",
        ]);
        for ip in [
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            [10, 0, 2, 77],
            [10, 0, 2, 255],
        ] {
            assert_eq!(
                everything.egress(at(ip, 53), &[]),
                deny(BUILTIN_GUEST_NET),
                "{ip:?}"
            );
        }
        assert_eq!(
            everything.egress(at([10, 0, 3, 1], 53), &[]),
            allow("allow 10.0.0.0/8")
        );
    }

    #[test]
    fn domain_rules_match_exact_and_suffix() {
        let p = parse(&[
            "default deny",
            "allow example.com",
            "deny *.evil.example.com",
            "allow *.example.com",
            "allow *.github.io",
        ]);
        let web = at([93, 184, 215, 14], 443);
        let cases: &[(&[&str], Ruling)] = &[
            (&["example.com"], allow("allow example.com")),
            (&["Example.COM"], allow("allow example.com")),
            (&["example.com."], allow("allow example.com")),
            (&["www.example.com"], allow("allow *.example.com")),
            (&["a.b.example.com"], allow("allow *.example.com")),
            (&["x.evil.example.com"], deny("deny *.evil.example.com")),
            // `*.evil.example.com` is not `evil.example.com` itself.
            (&["evil.example.com"], allow("allow *.example.com")),
            (&["user.github.io"], allow("allow *.github.io")),
            (&["github.io"], DEFAULT_DENY),
            (&["notexample.com"], DEFAULT_DENY),
            (&["example.com.evil.net"], DEFAULT_DENY),
            (&["xexample.com"], DEFAULT_DENY),
            (&[], DEFAULT_DENY),
            // Any of the address's names may match.
            (
                &["cdn.test", "www.example.com"],
                allow("allow *.example.com"),
            ),
        ];
        for (known, want) in cases {
            assert_eq!(&p.egress(web, &names(known)), want, "{known:?}");
        }

        for (name, want) in [
            ("example.com", allow("allow example.com")),
            ("WWW.Example.Com", allow("allow *.example.com")),
            ("www.example.com.", allow("allow *.example.com")),
            ("a.evil.example.com", deny("deny *.evil.example.com")),
            ("github.io", DEFAULT_DENY),
            ("blocked.example", DEFAULT_DENY),
            (".", DEFAULT_DENY),
            ("", DEFAULT_DENY),
        ] {
            assert_eq!(p.dns_rule(name), want, "{name:?}");
            assert_eq!(p.dns(name), want.0, "{name:?}");
        }
        assert_eq!(
            parse(&["default allow"]).dns("anything.test"),
            Verdict::Allow
        );
    }

    #[test]
    fn port_qualified_rules() {
        let p = parse(&[
            "default deny",
            "allow api.example.com:443",
            "deny example.com:80",
            "allow example.com",
            "allow 203.0.113.0/24:8443",
            "allow 198.51.100.7",
        ]);
        let host = |port| at([93, 184, 215, 14], port);
        assert_eq!(
            p.egress(host(443), &names(&["api.example.com"])),
            allow("allow api.example.com:443")
        );
        assert_eq!(
            p.egress(host(80), &names(&["api.example.com"])),
            DEFAULT_DENY
        );
        assert_eq!(
            p.egress(host(80), &names(&["example.com"])),
            deny("deny example.com:80")
        );
        assert_eq!(
            p.egress(host(443), &names(&["example.com"])),
            allow("allow example.com")
        );
        assert_eq!(
            p.egress(at([203, 0, 113, 9], 8443), &[]),
            allow("allow 203.0.113.0/24:8443")
        );
        assert_eq!(p.egress(at([203, 0, 113, 9], 443), &[]), DEFAULT_DENY);
        assert_eq!(
            p.egress(at([198, 51, 100, 7], 1234), &[]),
            allow("allow 198.51.100.7")
        );
        assert_eq!(p.egress(at([198, 51, 100, 8], 1234), &[]), DEFAULT_DENY);

        // A name's port does not matter to DNS: the first domain rule that
        // matches the name decides, here a port-qualified deny.
        assert_eq!(
            p.dns_rule("api.example.com"),
            allow("allow api.example.com:443")
        );
        assert_eq!(p.dns_rule("example.com"), deny("deny example.com:80"));
    }

    #[test]
    fn rules_parse_into_targets_keeping_their_text() {
        let p = parse(&[
            "# a comment, then a blank line",
            "",
            "  allow   Example.COM.  # trailing comment",
            "deny *.Ads.example.net:8080",
            "allow 203.0.113.0/24:443",
            "allow 198.51.100.7",
            "default allow",
        ]);
        assert_eq!(p.default, Verdict::Allow);
        assert_eq!(
            p.rules,
            [
                Rule {
                    verdict: Verdict::Allow,
                    target: Target::Domain {
                        pattern: "example.com".into(),
                        port: None,
                    },
                    text: "allow Example.COM.".into(),
                },
                Rule {
                    verdict: Verdict::Deny,
                    target: Target::Domain {
                        pattern: "*.ads.example.net".into(),
                        port: Some(8080),
                    },
                    text: "deny *.Ads.example.net:8080".into(),
                },
                Rule {
                    verdict: Verdict::Allow,
                    target: Target::Cidr {
                        net: "203.0.113.0/24".parse().unwrap(),
                        port: Some(443),
                    },
                    text: "allow 203.0.113.0/24:443".into(),
                },
                Rule {
                    verdict: Verdict::Allow,
                    target: Target::Cidr {
                        net: "198.51.100.7/32".parse().unwrap(),
                        port: None,
                    },
                    text: "allow 198.51.100.7".into(),
                },
            ]
        );
        assert_eq!(Policy::parse::<&str>(&[]), Ok(Policy::default()));
        assert_eq!(Policy::default().default, Verdict::Deny);
        assert_eq!(parse(&["# nothing"]).default, Verdict::Deny);
        assert_eq!(parse(&["default deny"]).default, Verdict::Deny);
    }

    #[test]
    fn a_bad_line_is_refused_with_its_number() {
        use PolicyErrorKind as K;
        let refused = |lines: &[&str]| Policy::parse(lines).unwrap_err();
        let long_label = format!("allow {}.com", "a".repeat(64));
        let long_name = format!("allow {}.com", vec!["a".repeat(60); 5].join("."));
        let cases: Vec<(Vec<&str>, usize, K)> = vec![
            (
                vec!["permit example.com"],
                1,
                K::UnknownWord("permit".into()),
            ),
            (vec!["Allow example.com"], 1, K::UnknownWord("Allow".into())),
            (
                vec!["# c", "", "default deny", "default allow"],
                4,
                K::DuplicateDefault,
            ),
            (vec!["default"], 1, K::Default),
            (vec!["default maybe"], 1, K::Default),
            (vec!["default deny now"], 1, K::Default),
            (vec!["allow"], 1, K::Target("allow")),
            (vec!["deny a.com b.com"], 1, K::Target("deny")),
            (vec!["allow example.com:0"], 1, K::Port("0".into())),
            (vec!["allow example.com:65536"], 1, K::Port("65536".into())),
            (vec!["allow example.com:http"], 1, K::Port("http".into())),
            (vec!["allow example.com:"], 1, K::Port("".into())),
            (vec!["allow example.com:+443"], 1, K::Port("+443".into())),
            (vec!["allow *"], 1, K::Pattern("*".into())),
            (vec!["allow *."], 1, K::Pattern("*.".into())),
            (vec!["allow a.*.com"], 1, K::Pattern("a.*.com".into())),
            (vec!["allow **.com"], 1, K::Pattern("**.com".into())),
            (
                vec!["allow exa_mple.com"],
                1,
                K::Pattern("exa_mple.com".into()),
            ),
            (
                vec!["allow example..com"],
                1,
                K::Pattern("example..com".into()),
            ),
            (
                vec!["allow .example.com"],
                1,
                K::Pattern(".example.com".into()),
            ),
            (
                vec!["allow exämple.com"],
                1,
                K::Pattern("exämple.com".into()),
            ),
            (vec![&long_label], 1, K::Pattern(long_label[6..].into())),
            (vec![&long_name], 1, K::Pattern(long_name[6..].into())),
            (vec!["allow [::1]:443"], 1, K::Pattern("[::1]".into())),
        ];
        for (lines, line, kind) in cases {
            let error = refused(&lines);
            assert_eq!(error, PolicyError { line, kind }, "{lines:?}");
            assert!(error
                .to_string()
                .starts_with(&format!("policy line {line}: ")));
        }
        for (text, why) in [
            ("allow 10.1.2.3/8", "host bits"),
            ("allow 10.0.0.0/33", "prefix"),
            ("allow 10.0.0/8", "address"),
            ("allow 10.0.0.0/", "prefix"),
        ] {
            let error = refused(&[text]);
            assert!(matches!(error.kind, K::Net(_)), "{text}: {why}: {error:?}");
        }
    }

    #[test]
    fn networks_parse_print_and_contain() {
        let net: Ipv4Net = "172.16.0.0/12".parse().unwrap();
        assert_eq!(
            (net.addr(), net.prefix()),
            (Ipv4Addr::new(172, 16, 0, 0), 12)
        );
        assert_eq!(net.to_string(), "172.16.0.0/12");
        assert!(net.contains(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!net.contains(Ipv4Addr::new(172, 32, 0, 0)));

        let all: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(Ipv4Addr::BROADCAST) && all.contains(Ipv4Addr::UNSPECIFIED));
        let one: Ipv4Net = "198.51.100.7/32".parse().unwrap();
        assert!(one.contains(Ipv4Addr::new(198, 51, 100, 7)));
        assert!(!one.contains(Ipv4Addr::new(198, 51, 100, 6)));

        assert_eq!(
            "10.1.2.3/8".parse::<Ipv4Net>(),
            Err(NetError::HostBits(
                "10.1.2.3/8".into(),
                Ipv4Net::masked(Ipv4Addr::new(10, 0, 0, 0), 8)
            ))
        );
        assert_eq!(
            "10.0.0.0/33".parse::<Ipv4Net>(),
            Err(NetError::Prefix("33".into()))
        );
        for bad in [
            "10.0.0.0",
            "10.0.0/8",
            "10.0.0.0/x",
            "/8",
            "10.0.0.0/-1",
            "",
        ] {
            assert!(bad.parse::<Ipv4Net>().is_err(), "{bad}");
        }

        assert_eq!(GUEST_NET.to_string(), "10.0.2.0/24");
        let ranges: Vec<String> = PRIVATE_RANGES.iter().map(|n| n.to_string()).collect();
        assert_eq!(
            ranges,
            [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "169.254.0.0/16"
            ]
        );
    }
}
