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
//! [`Policy::egress`] decides a connection:
//!
//! 1. Denied whatever the rules say: the guest's own network
//!    ([`GUEST_NET`], `builtin:guest-net`), "this network" `0.0.0.0/8`
//!    ([`THIS_NET`], `builtin:this-net`: a host connect to `0.0.0.0` reaches
//!    the host's own loopback), and multicast and the reserved range,
//!    broadcast included ([`RESERVED_RANGES`], `builtin:reserved`).
//! 2. The six [built-in private ranges](PRIVATE_RANGES) are denied
//!    (`builtin:private`) unless an `allow` rule names that exact range.
//! 3. The rules in file order, the first that matches deciding.
//! 4. The default.
//!
//! [`Policy::dns`] decides a name: walking the rules in order, the first
//! domain rule that matches the name and either allows (on any port) or
//! denies on every port decides; a deny on one port is
//! [`egress`](Policy::egress)'s business and does not stop the name
//! resolving. Else the default.
//!
//! A domain rule admits only clients that say the name. A connection a
//! domain rule allowed is held at the TCP relay's gate until its first
//! bytes show the name it is for: the server name of a TLS ClientHello, or
//! the `Host` of a plain HTTP request. [`Policy::gate_allows`] then decides
//! on that name and the port: the first domain rule that matches both
//! decides, and a name no domain rule matches is denied (never the
//! default). A connection that shows no name (a protocol where the server
//! speaks first, such as SMTP, or one that is neither TLS nor HTTP, such
//! as SSH) is reset. Allow those by address with a network rule
//! (`allow 192.0.2.10:22`), which is not gated.
//!
//! UDP shows no name at all, so a domain rule admits none: when an
//! allowing domain rule decides a UDP flow's first datagram, the
//! [UDP relay](crate::udp) denies it as `builtin:udp-needs-cidr`
//! ([`BUILTIN_UDP_NEEDS_CIDR`]). Allow UDP by address with a network rule
//! (`allow 192.0.2.53:53`, `allow 198.51.100.0/24:123`).
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
/// The rule text records give for a destination in "this network",
/// `0.0.0.0/8`.
pub const BUILTIN_THIS_NET: &str = "builtin:this-net";
/// The rule text records give for a multicast or reserved destination.
pub const BUILTIN_RESERVED: &str = "builtin:reserved";
/// The rule text records give for a UDP flow an allowing domain rule
/// decided: no name can be checked on a datagram, so only a network rule
/// admits UDP.
pub const BUILTIN_UDP_NEEDS_CIDR: &str = "builtin:udp-needs-cidr";

/// "This network" (RFC 1122 §3.2.1.3), never a destination: a host
/// connect to `0.0.0.0` reaches the host's own loopback, past the
/// `127.0.0.0/8` denial. Denied whatever the rules say.
pub const THIS_NET: Ipv4Net = Ipv4Net::masked(Ipv4Addr::new(0, 0, 0, 0), 8);

/// Multicast, and the reserved range with the limited broadcast address
/// in it: no relay connects there. Denied whatever the rules say.
pub const RESERVED_RANGES: [Ipv4Net; 2] = [
    Ipv4Net::masked(Ipv4Addr::new(224, 0, 0, 0), 4),
    Ipv4Net::masked(Ipv4Addr::new(240, 0, 0, 0), 4),
];

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
    #[error("{0:?} looks like an address but is not an IPv4 address")]
    Address(String),
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
    /// In order: the guest's own network ([`GUEST_NET`]), "this network"
    /// ([`THIS_NET`]) and multicast and reserved addresses
    /// ([`RESERVED_RANGES`]) are denied as `builtin:guest-net`,
    /// `builtin:this-net` and `builtin:reserved`, and no rule lifts that;
    /// an address in a [built-in private range](PRIVATE_RANGES) is denied
    /// as `builtin:private` unless an `allow` rule names exactly that range
    /// (the same address and prefix, and, if the rule has a port, this
    /// port); then the first rule that matches decides, a domain rule
    /// matching when any of `names` matches it, a network rule when it
    /// holds the address, either only on its port if it has one; then the
    /// default.
    pub fn egress(&self, dst: SocketAddrV4, names: &[String]) -> (Verdict, Option<String>) {
        match self.decide(dst, names) {
            Decided::Builtin(builtin) => (Verdict::Deny, Some(builtin.to_owned())),
            Decided::Rule(rule) => (rule.verdict, Some(rule.text.clone())),
            Decided::Default => (self.default, None),
        }
    }

    /// The rule that decides [`egress`](Self::egress) for `dst` and
    /// `names`, or `None` when a built-in denial or the default does. The
    /// TCP relay gates a flow a domain rule allowed on the name its first
    /// bytes ask for, which must match that rule.
    pub fn egress_rule(&self, dst: SocketAddrV4, names: &[String]) -> Option<&Rule> {
        match self.decide(dst, names) {
            Decided::Rule(rule) => Some(rule),
            Decided::Builtin(_) | Decided::Default => None,
        }
    }

    /// Whether an `allow` rule names exactly `net` (the same address and
    /// prefix) on `port`: on that port, or on every port. This is what
    /// lifts a built-in denial that rules may lift.
    pub fn allows_exactly(&self, net: Ipv4Net, port: u16) -> bool {
        self.rules.iter().any(|rule| {
            rule.verdict == Verdict::Allow
                && matches!(rule.target, Target::Cidr { net: named, port: on }
                    if named == net && on_port(on, port))
        })
    }

    /// What decides [`egress`](Self::egress), in its order.
    fn decide(&self, dst: SocketAddrV4, names: &[String]) -> Decided<'_> {
        let (ip, port) = (*dst.ip(), dst.port());
        if let Some(builtin) = never_reachable(ip) {
            return Decided::Builtin(builtin);
        }
        if let Some(range) = PRIVATE_RANGES.iter().find(|range| range.contains(ip)) {
            if !self.allows_exactly(*range, port) {
                return Decided::Builtin(BUILTIN_PRIVATE);
            }
        }
        let decided = self.rules.iter().find(|rule| match &rule.target {
            Target::Domain { pattern, port: on } => {
                on_port(*on, port) && names.iter().any(|name| name_matches(pattern, name))
            }
            Target::Cidr { net, port: on } => on_port(*on, port) && net.contains(ip),
        });
        decided.map_or(Decided::Default, Decided::Rule)
    }

    /// The gate's verdict on a connection to `port` that showed `name`
    /// (its TLS server name or HTTP `Host`), and the text of the rule that
    /// decided: walking the rules in order, the first domain rule whose
    /// pattern matches the name and whose port, if it has one, is `port`.
    /// No such rule denies, with no rule text: the gate never falls back
    /// to the default, so `default allow` admits no name by itself.
    pub fn gate_allows(&self, name: &str, port: u16) -> (Verdict, Option<String>) {
        let decided = self.rules.iter().find(|rule| match &rule.target {
            Target::Domain { pattern, port: on } => {
                on_port(*on, port) && name_matches(pattern, name)
            }
            Target::Cidr { .. } => false,
        });
        match decided {
            Some(rule) => (rule.verdict, Some(rule.text.clone())),
            None => (Verdict::Deny, None),
        }
    }

    /// The verdict on resolving `qname`: a denied name gets NXDOMAIN.
    ///
    /// Walking the rules in order, the first domain rule that matches the
    /// name decides if it allows, with a port or without, or if it denies
    /// without a port. A matching deny with a port is passed over: it
    /// denies connections on that port, which [`egress`](Self::egress)
    /// judges, not the name. With no deciding rule, the default.
    pub fn dns(&self, qname: &str) -> Verdict {
        self.dns_rule(qname).0
    }

    /// [`dns`](Self::dns), with the text of the rule that decided, or
    /// `None` for the default.
    pub fn dns_rule(&self, qname: &str) -> (Verdict, Option<String>) {
        let decided = self.rules.iter().find(|rule| match &rule.target {
            // An allow on any port lets the name resolve; only a deny on
            // every port refuses it.
            Target::Domain { pattern, port } => {
                name_matches(pattern, qname) && (rule.verdict == Verdict::Allow || port.is_none())
            }
            Target::Cidr { .. } => false,
        });
        match decided {
            Some(rule) => (rule.verdict, Some(rule.text.clone())),
            None => (self.default, None),
        }
    }
}

/// What decided a connection's verdict.
enum Decided<'a> {
    /// A built-in denial, by its rule text.
    Builtin(&'static str),
    Rule(&'a Rule),
    Default,
}

/// The built-in rule text for an address no rule may open: on the guest's
/// own network, in "this network", or multicast or reserved.
fn never_reachable(ip: Ipv4Addr) -> Option<&'static str> {
    if GUEST_NET.contains(ip) {
        Some(BUILTIN_GUEST_NET)
    } else if THIS_NET.contains(ip) {
        Some(BUILTIN_THIS_NET)
    } else if RESERVED_RANGES.iter().any(|range| range.contains(ip)) {
        Some(BUILTIN_RESERVED)
    } else {
        None
    }
}

/// Whether a rule on port `on` (any port when `None`) covers `port`.
fn on_port(on: Option<u16>, port: u16) -> bool {
    on.is_none_or(|on| on == port)
}

/// Whether `name` matches a domain pattern: the name itself, or for
/// `*.suffix` any name under the suffix but not the suffix itself. Case
/// and one trailing dot on `name` do not matter. Domain rules match names
/// this way for [`Policy::egress`] and [`Policy::dns`], and the TCP
/// relay's gate matches a flow's server name or `Host` with it.
pub fn name_matches(pattern: &str, name: &str) -> bool {
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
/// with an optional `:port`. A target that looks numeric (one with a `/`,
/// or of digits and dots only) must be an address or a network: a typo
/// such as `192.168.1.300` or `10.0.0.1.` is refused rather than taken for
/// a name that never matches.
fn parse_target(target: &str) -> Result<Target, PolicyErrorKind> {
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (target, None),
    };
    if host.contains('/') {
        return Ok(Target::Cidr {
            net: host.parse()?,
            port,
        });
    }
    if !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let addr = host
            .parse::<Ipv4Addr>()
            .map_err(|_| PolicyErrorKind::Address(host.to_owned()))?;
        return Ok(Target::Cidr {
            net: Ipv4Net::masked(addr, 32),
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

        // For DNS, an allow on any port lets the name resolve, and a deny
        // on one port is passed over: it is egress's to judge.
        assert_eq!(
            p.dns_rule("api.example.com"),
            allow("allow api.example.com:443")
        );
        assert_eq!(p.dns_rule("example.com"), allow("allow example.com"));
    }

    #[test]
    fn a_deny_on_one_port_does_not_stop_a_name_resolving() {
        let ruling = |lines: &[&str], name| parse(lines).dns_rule(name);
        // Port-qualified denies are passed over, whatever the default.
        assert_eq!(
            ruling(&["deny example.com:80", "allow example.com"], "example.com"),
            allow("allow example.com")
        );
        assert_eq!(
            ruling(&["deny example.com:80"], "example.com"),
            DEFAULT_DENY
        );
        assert_eq!(
            ruling(&["default allow", "deny example.com:80"], "example.com"),
            DEFAULT_ALLOW
        );
        assert_eq!(
            ruling(
                &["deny *.example.com:443", "allow *.example.com"],
                "www.example.com"
            ),
            allow("allow *.example.com")
        );
        // A port-qualified allow lets the name resolve under default deny.
        assert_eq!(
            ruling(
                &["default deny", "allow api.example.com:443"],
                "api.example.com"
            ),
            allow("allow api.example.com:443")
        );
        // A deny on every port decides, whatever allows come after.
        assert_eq!(
            ruling(
                &[
                    "deny example.com",
                    "allow example.com:443",
                    "allow example.com"
                ],
                "example.com"
            ),
            deny("deny example.com")
        );
        assert_eq!(
            ruling(&["default allow", "deny *.example.com"], "a.example.com"),
            deny("deny *.example.com")
        );
        // Egress still applies the port-qualified deny.
        let p = parse(&["deny example.com:80", "allow example.com"]);
        let known = names(&["example.com"]);
        assert_eq!(
            p.egress(at([93, 184, 215, 14], 80), &known),
            deny("deny example.com:80")
        );
        assert_eq!(
            p.egress(at([93, 184, 215, 14], 443), &known),
            allow("allow example.com")
        );
    }

    /// "This network", multicast and the reserved range are denied before
    /// any rule is read: neither the default, an exact allow, an allow of
    /// everything, nor a name lifts them.
    #[test]
    fn unspecified_multicast_and_reserved_destinations_are_never_reachable() {
        let cases = [
            ([0, 0, 0, 0], BUILTIN_THIS_NET),
            ([0, 1, 2, 3], BUILTIN_THIS_NET),
            ([0, 255, 255, 255], BUILTIN_THIS_NET),
            ([224, 0, 0, 1], BUILTIN_RESERVED),
            ([239, 255, 255, 250], BUILTIN_RESERVED),
            ([240, 0, 0, 1], BUILTIN_RESERVED),
            ([255, 255, 255, 255], BUILTIN_RESERVED),
        ];
        let everything = parse(&[
            "default allow",
            "allow 0.0.0.0/8",
            "allow 0.0.0.0",
            "allow 0.1.2.3",
            "allow 224.0.0.0/4",
            "allow 224.0.0.1:443",
            "allow 240.0.0.0/4",
            "allow 255.255.255.255",
            "allow 0.0.0.0/0",
            "allow example.com",
        ]);
        let known = names(&["example.com"]);
        for (ip, builtin) in cases {
            for (policy, which) in [(&Policy::allow_all(), "allow_all"), (&everything, "allows")] {
                assert_eq!(
                    policy.egress(at(ip, 443), &known),
                    deny(builtin),
                    "{ip:?} under {which}"
                );
            }
        }
        // Their neighbors are ordinary addresses.
        for ip in [[1, 0, 0, 0], [223, 255, 255, 255]] {
            assert_eq!(Policy::allow_all().egress(at(ip, 443), &[]), DEFAULT_ALLOW);
        }
        assert_eq!(THIS_NET.to_string(), "0.0.0.0/8");
        let reserved: Vec<String> = RESERVED_RANGES.iter().map(|n| n.to_string()).collect();
        assert_eq!(reserved, ["224.0.0.0/4", "240.0.0.0/4"]);
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
            // What looks numeric must be an address.
            (
                vec!["allow 192.168.1.300"],
                1,
                K::Address("192.168.1.300".into()),
            ),
            (
                vec!["# c", "allow 10.0.0.1."],
                2,
                K::Address("10.0.0.1.".into()),
            ),
            (vec!["allow 10.0.0"], 1, K::Address("10.0.0".into())),
            (
                vec!["deny 10.0.0.1.:443"],
                1,
                K::Address("10.0.0.1.".into()),
            ),
            (vec!["allow 1.2.3.4.5"], 1, K::Address("1.2.3.4.5".into())),
        ];
        for (lines, line, kind) in cases {
            let error = refused(&lines);
            assert_eq!(error, PolicyError { line, kind }, "{lines:?}");
            assert!(error
                .to_string()
                .starts_with(&format!("policy line {line}: ")));
        }
        // A name with a letter is a name.
        assert_eq!(
            parse(&["allow 1e100.net"]).rules[0].target,
            Target::Domain {
                pattern: "1e100.net".into(),
                port: None
            }
        );
        for (text, why) in [
            ("allow 10.0.0.0/33", "prefix"),
            ("allow 10.0.0.1./8", "address"),
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

    #[test]
    fn egress_rule_is_the_rule_that_decided() {
        let p = parse(&[
            "deny evil.example",
            "allow example.com:443",
            "allow 127.0.0.0/8",
            "allow 203.0.113.0/24",
            "default allow",
        ]);
        let named = names(&["example.com"]);
        let rule = p.egress_rule(at([93, 184, 215, 14], 443), &named).unwrap();
        assert_eq!(rule.text, "allow example.com:443");
        assert!(matches!(rule.target, Target::Domain { .. }));
        // The same address on another port: the default decides.
        assert!(p.egress_rule(at([93, 184, 215, 14], 80), &named).is_none());
        // A deny decides too.
        let rule = p
            .egress_rule(at([1, 2, 3, 4], 80), &names(&["evil.example"]))
            .unwrap();
        assert_eq!(rule.verdict, Verdict::Deny);
        // A network rule.
        let rule = p.egress_rule(at([203, 0, 113, 9], 22), &[]).unwrap();
        assert_eq!(rule.text, "allow 203.0.113.0/24");
        // Built-in denials are no rule's.
        assert!(p.egress_rule(at([10, 0, 2, 2], 53), &named).is_none());
        assert!(p.egress_rule(at([192, 168, 1, 1], 80), &named).is_none());
        // The lift is not the decision: the first matching rule is.
        let rule = p.egress_rule(at([127, 0, 0, 1], 80), &named).unwrap();
        assert_eq!(rule.text, "allow 127.0.0.0/8");
    }

    #[test]
    fn allows_exactly_needs_the_same_network_and_port() {
        let p = parse(&[
            "allow 192.0.2.7:443",
            "allow 198.51.100.7",
            "allow 10.0.0.0/8",
            "deny 203.0.113.7",
        ]);
        let host = |ip: [u8; 4]| Ipv4Net::masked(Ipv4Addr::from(ip), 32);
        assert!(p.allows_exactly(host([192, 0, 2, 7]), 443));
        assert!(!p.allows_exactly(host([192, 0, 2, 7]), 80), "another port");
        assert!(p.allows_exactly(host([198, 51, 100, 7]), 1));
        assert!(p.allows_exactly(host([198, 51, 100, 7]), 65_535));
        assert!(
            !p.allows_exactly(host([10, 1, 2, 3]), 80),
            "inside, not exact"
        );
        assert!(p.allows_exactly(Ipv4Net::masked(Ipv4Addr::new(10, 0, 0, 0), 8), 80));
        assert!(!p.allows_exactly(host([203, 0, 113, 7]), 80), "a deny");
    }

    #[test]
    fn the_gate_passes_a_name_any_domain_rule_allows() {
        let p = parse(&["allow a.example", "allow b.example"]);
        assert_eq!(p.gate_allows("b.example", 443), allow("allow b.example"));
        assert_eq!(p.gate_allows("A.Example.", 80), allow("allow a.example"));
        assert_eq!(p.gate_allows("c.example", 443), (Verdict::Deny, None));
    }

    #[test]
    fn the_gate_honors_an_earlier_deny() {
        let p = parse(&["deny evil.example", "allow *.example"]);
        assert_eq!(
            p.gate_allows("evil.example", 443),
            deny("deny evil.example")
        );
        assert_eq!(p.gate_allows("good.example", 443), allow("allow *.example"));
        // A deny on one port denies only there.
        let p = parse(&["deny evil.example:443", "allow *.example"]);
        assert_eq!(
            p.gate_allows("evil.example", 443),
            deny("deny evil.example:443")
        );
        assert_eq!(p.gate_allows("evil.example", 80), allow("allow *.example"));
    }

    #[test]
    fn the_gate_needs_a_rule_on_the_port() {
        let p = parse(&["allow b.example:80"]);
        assert_eq!(p.gate_allows("b.example", 80), allow("allow b.example:80"));
        assert_eq!(p.gate_allows("b.example", 443), (Verdict::Deny, None));
    }

    #[test]
    fn a_network_rule_or_the_default_never_passes_a_name() {
        let p = parse(&["allow 0.0.0.0/0", "allow 127.0.0.1", "default allow"]);
        for name in ["example.com", "127.0.0.1", "0.0.0.0"] {
            assert_eq!(p.gate_allows(name, 443), (Verdict::Deny, None), "{name}");
        }
    }
}
