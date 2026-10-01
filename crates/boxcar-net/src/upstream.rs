// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The relays' host side: how a guest flow is decided ([`decide`] for a
//! TCP SYN, [`decide_udp`] for the first datagram of a UDP 5-tuple, both
//! denying the host's own addresses first), the non-blocking connect a
//! guest's SYN waits on, and the host's own addresses, which the guest may
//! not reach unless a rule names one exactly.
//!
//! A guest connection to one of the host's own interface addresses reaches
//! whatever the host serves on `0.0.0.0`, and no static range covers those
//! addresses (they are often public). So before the policy judges a SYN,
//! the stack denies such a destination as `builtin:host-local` unless an
//! `allow` rule names exactly that address as a `/32` (on that port, if
//! the rule has one), as an exact range lifts a built-in private denial.
//! Loopback is left to the policy's liftable `127.0.0.0/8` denial.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, Type};

use crate::policy::{Ipv4Net, Policy, Rule, Target, Verdict};

/// The rule text records give for a destination that is one of the host's
/// own addresses.
pub const BUILTIN_HOST_LOCAL: &str = "builtin:host-local";

/// How long the host's addresses are trusted before they are read again.
pub const HOST_ADDRS_REFRESH: Duration = Duration::from_secs(5);

/// Where a guest connection goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectTarget {
    /// A host socket connected to the guest's destination. (M2 Task 10
    /// adds a variant for the internal services the gateway offers.)
    Host(SocketAddrV4),
}

/// Starts a non-blocking connect to `target`, with Nagle's algorithm off
/// (the guest's own TCP decides when to send). The stream is returned
/// while the connect is under way; [`progress`] says when it is done.
pub fn connect(target: ConnectTarget) -> io::Result<TcpStream> {
    let ConnectTarget::Host(dst) = target;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_nodelay(true)?;
    match socket.connect(&SocketAddr::V4(dst).into()) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(error) => return Err(error),
    }
    Ok(socket.into())
}

/// How a connect [`connect`] started stands.
#[derive(Debug)]
pub enum Progress {
    /// Connected.
    Done,
    /// Still under way: the event was not for its completion.
    Waiting,
    /// It failed.
    Failed(io::Error),
}

/// How `stream`'s connect stands, once its fd has been reported ready.
pub fn progress(stream: &TcpStream) -> Progress {
    match stream.take_error() {
        Ok(Some(error)) | Err(error) => return Progress::Failed(error),
        Ok(None) => {}
    }
    match stream.peer_addr() {
        Ok(_) => Progress::Done,
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Progress::Waiting,
        Err(error) => Progress::Failed(error),
    }
}

/// The `net.close` reason for a connect that failed with `error`.
pub fn close_reason(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "refused",
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => "unreachable",
        io::ErrorKind::TimedOut => "timeout",
        _ => "error",
    }
}

/// Makes closing `stream` reset the connection rather than end it with a
/// FIN: for a flow the relay aborts.
pub fn reset_on_close(stream: &TcpStream) {
    // Nothing to do if the socket refuses: it closes with a FIN instead.
    let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

/// The verdict on a guest flow, and what decided it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// The text of the rule that decided, or `None` for the default.
    pub rule: Option<String>,
    /// An allowing domain rule decided: the TCP relay gates the flow on
    /// the name it shows.
    pub by_domain: bool,
}

/// Decides a guest flow to `dst`, which the guest knows by `names` (those
/// the DNS cache holds for its address): one of the host's own addresses
/// that no rule lifts is denied as [`BUILTIN_HOST_LOCAL`] ([`host_local`]),
/// and anything else is the policy's [`egress`](Policy::egress) verdict.
pub fn decide(
    addrs: &mut HostAddrs,
    policy: &Policy,
    dst: SocketAddrV4,
    names: &[String],
    now: Instant,
) -> Decision {
    if host_local(addrs, policy, dst, now) {
        return Decision {
            verdict: Verdict::Deny,
            rule: Some(BUILTIN_HOST_LOCAL.to_owned()),
            by_domain: false,
        };
    }
    let (verdict, rule) = policy.egress(dst, names);
    Decision {
        verdict,
        rule,
        by_domain: allowed_by_domain(policy.egress_rule(dst, names)),
    }
}

/// Decides a guest UDP flow to `dst`, which the guest knows by `names`:
/// one of the host's own addresses that no rule lifts is denied as
/// [`BUILTIN_HOST_LOCAL`], as for TCP, and anything else is the policy's
/// [`egress_udp`](Policy::egress_udp) verdict, which passes over domain
/// allows.
pub fn decide_udp(
    addrs: &mut HostAddrs,
    policy: &Policy,
    dst: SocketAddrV4,
    names: &[String],
    now: Instant,
) -> (Verdict, Option<String>) {
    if host_local(addrs, policy, dst, now) {
        return (Verdict::Deny, Some(BUILTIN_HOST_LOCAL.to_owned()));
    }
    policy.egress_udp(dst, names)
}

/// Whether `rule`, the rule that decided a flow, is an allowing domain
/// rule.
fn allowed_by_domain(rule: Option<&Rule>) -> bool {
    matches!(
        rule,
        Some(Rule {
            verdict: Verdict::Allow,
            target: Target::Domain { .. },
            ..
        })
    )
}

/// Whether a connection to `dst` is to one of the host's own addresses
/// that no rule lifts: denied as [`BUILTIN_HOST_LOCAL`].
pub fn host_local(addrs: &mut HostAddrs, policy: &Policy, dst: SocketAddrV4, now: Instant) -> bool {
    addrs.contains(*dst.ip(), now)
        && !policy.allows_exactly(Ipv4Net::masked(*dst.ip(), 32), dst.port())
}

/// Reads the host's addresses.
type Reader = Box<dyn FnMut() -> io::Result<Vec<Ipv4Addr>> + Send>;

/// The host's own IPv4 addresses, read again at most every
/// [`HOST_ADDRS_REFRESH`].
pub struct HostAddrs {
    read: Reader,
    addrs: Vec<Ipv4Addr>,
    read_at: Option<Instant>,
}

impl HostAddrs {
    /// The host's non-loopback IPv4 interface addresses, from
    /// `getifaddrs(3)`.
    pub fn system() -> Self {
        HostAddrs::with_reader(interface_addrs)
    }

    /// Always `addrs`: for tests.
    pub fn fixed(addrs: Vec<Ipv4Addr>) -> Self {
        HostAddrs::with_reader(move || Ok(addrs.clone()))
    }

    /// Addresses `read` gives. When it fails, the addresses it gave last
    /// stand until the next read.
    pub fn with_reader(read: impl FnMut() -> io::Result<Vec<Ipv4Addr>> + Send + 'static) -> Self {
        HostAddrs {
            read: Box::new(read),
            addrs: Vec::new(),
            read_at: None,
        }
    }

    /// Whether `ip` is one of the host's addresses, reading them again
    /// first if the last read is [`HOST_ADDRS_REFRESH`] old at `now`.
    pub fn contains(&mut self, ip: Ipv4Addr, now: Instant) -> bool {
        let stale = self
            .read_at
            .is_none_or(|at| now.saturating_duration_since(at) >= HOST_ADDRS_REFRESH);
        if stale {
            match (self.read)() {
                Ok(addrs) => self.addrs = addrs,
                Err(error) => {
                    boxcar_virtio::limited!(warn, "net: reading the host's addresses: {error}");
                }
            }
            self.read_at = Some(now);
        }
        self.addrs.contains(&ip)
    }
}

impl fmt::Debug for HostAddrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostAddrs")
            .field("addrs", &self.addrs)
            .field("read_at", &self.read_at)
            .finish_non_exhaustive()
    }
}

/// The host's IPv4 interface addresses, loopback left out, each once.
fn interface_addrs() -> io::Result<Vec<Ipv4Addr>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs stores a pointer to a list it allocates in `list`,
    // or fails and stores nothing.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addrs = Vec::new();
    let mut node = list;
    while !node.is_null() {
        // SAFETY: `node` is a node of the list getifaddrs gave, which is
        // freed only below, after the walk.
        let entry = unsafe { &*node };
        let sockaddr = entry.ifa_addr;
        // SAFETY: a non-null `ifa_addr` points to a socket address whose
        // family field is valid to read; an AF_INET one is a sockaddr_in,
        // read unaligned so its alignment does not matter.
        if !sockaddr.is_null() && i32::from(unsafe { (*sockaddr).sa_family }) == libc::AF_INET {
            let sin = unsafe { std::ptr::read_unaligned(sockaddr.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            if !ip.is_loopback() && !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
        node = entry.ifa_next;
    }
    // SAFETY: `list` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn the_host_addresses_are_read_again_every_five_seconds() {
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        let mut addrs = HostAddrs::with_reader(move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            // The first read gives one address, later ones another.
            Ok(vec![Ipv4Addr::new(192, 0, 2, if n == 0 { 1 } else { 2 })])
        });
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert!(addrs.contains(Ipv4Addr::new(192, 0, 2, 1), at(0)));
        assert!(addrs.contains(Ipv4Addr::new(192, 0, 2, 1), at(4)));
        assert!(!addrs.contains(Ipv4Addr::new(192, 0, 2, 2), at(4)));
        assert_eq!(reads.load(Ordering::SeqCst), 1, "cached");
        assert!(addrs.contains(Ipv4Addr::new(192, 0, 2, 2), at(5)));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        // A clock reading older than the last read does not read again.
        assert!(addrs.contains(Ipv4Addr::new(192, 0, 2, 2), at(1)));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_failed_read_keeps_the_last_addresses() {
        let mut first = true;
        let mut addrs = HostAddrs::with_reader(move || {
            if std::mem::take(&mut first) {
                Ok(vec![Ipv4Addr::new(198, 51, 100, 1)])
            } else {
                Err(io::Error::from_raw_os_error(libc::ENOMEM))
            }
        });
        let t0 = Instant::now();
        assert!(addrs.contains(Ipv4Addr::new(198, 51, 100, 1), t0));
        let later = t0 + HOST_ADDRS_REFRESH;
        assert!(addrs.contains(Ipv4Addr::new(198, 51, 100, 1), later));
    }

    #[test]
    fn the_system_addresses_leave_loopback_out() {
        let addrs = interface_addrs().unwrap();
        assert!(addrs.iter().all(|ip| !ip.is_loopback()), "{addrs:?}");
        let mut unique = addrs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), addrs.len());
    }

    #[test]
    fn only_an_exact_address_rule_lifts_the_host_local_denial() {
        let host = Ipv4Addr::new(203, 0, 113, 7);
        let mut addrs = HostAddrs::fixed(vec![host]);
        let now = Instant::now();
        let to = |port| SocketAddrV4::new(host, port);
        let policy = |lines: &[&str]| Policy::parse(lines).unwrap();
        for denying in [
            policy(&["default allow"]),
            policy(&["allow 203.0.113.0/24"]),
            policy(&["allow 0.0.0.0/0"]),
            policy(&["allow 203.0.113.7:80"]),
            policy(&["deny 203.0.113.7"]),
        ] {
            assert!(
                host_local(&mut addrs, &denying, to(443), now),
                "{denying:?}"
            );
        }
        assert!(!host_local(
            &mut addrs,
            &policy(&["allow 203.0.113.7"]),
            to(443),
            now
        ));
        assert!(!host_local(
            &mut addrs,
            &policy(&["allow 203.0.113.7:443"]),
            to(443),
            now
        ));
        // Not a host address.
        let other = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 443);
        assert!(!host_local(
            &mut addrs,
            &policy(&["default deny"]),
            other,
            now
        ));
    }

    #[test]
    fn only_an_allowing_domain_rule_decides_by_domain() {
        let policy = Policy::parse(&[
            "allow example.com",
            "deny evil.example",
            "allow 192.0.2.0/24",
        ])
        .unwrap();
        let by_domain = |i: usize| allowed_by_domain(policy.rules.get(i));
        assert!(by_domain(0));
        assert!(!by_domain(1));
        assert!(!by_domain(2));
        assert!(!allowed_by_domain(None));
    }

    #[test]
    fn decide_is_host_local_then_egress() {
        let host = Ipv4Addr::new(203, 0, 113, 7);
        let mut addrs = HostAddrs::fixed(vec![host]);
        let now = Instant::now();
        let policy = Policy::parse(&["allow example.com", "allow 203.0.113.0/24"]).unwrap();
        let names = vec!["example.com".to_owned()];
        let decided = |addrs: &mut HostAddrs, ip: Ipv4Addr, names: &[String]| {
            decide(addrs, &policy, SocketAddrV4::new(ip, 443), names, now)
        };
        assert_eq!(
            decided(&mut addrs, host, &names),
            Decision {
                verdict: Verdict::Deny,
                rule: Some(BUILTIN_HOST_LOCAL.to_owned()),
                by_domain: false,
            },
            "the host's own address, whatever the names"
        );
        let other = Ipv4Addr::new(203, 0, 113, 8);
        assert_eq!(
            decided(&mut addrs, other, &names),
            Decision {
                verdict: Verdict::Allow,
                rule: Some("allow example.com".to_owned()),
                by_domain: true,
            }
        );
        assert_eq!(
            decided(&mut addrs, other, &[]),
            Decision {
                verdict: Verdict::Allow,
                rule: Some("allow 203.0.113.0/24".to_owned()),
                by_domain: false,
            }
        );
        assert_eq!(
            decided(&mut addrs, Ipv4Addr::new(198, 51, 100, 1), &[]),
            Decision {
                verdict: Verdict::Deny,
                rule: None,
                by_domain: false,
            },
            "the default"
        );
    }

    #[test]
    fn decide_udp_is_host_local_then_egress_udp() {
        let host = Ipv4Addr::new(203, 0, 113, 7);
        let mut addrs = HostAddrs::fixed(vec![host]);
        let now = Instant::now();
        let policy = Policy::parse(&["allow example.com", "default allow"]).unwrap();
        let names = vec!["example.com".to_owned()];
        assert_eq!(
            decide_udp(
                &mut addrs,
                &policy,
                SocketAddrV4::new(host, 53),
                &names,
                now
            ),
            (Verdict::Deny, Some(BUILTIN_HOST_LOCAL.to_owned()))
        );
        // The domain allow is passed over, and the default decides.
        let other = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 53);
        assert_eq!(
            decide_udp(&mut addrs, &policy, other, &names, now),
            (Verdict::Allow, None)
        );
        let lifted = Policy::parse(&["allow 203.0.113.7:53"]).unwrap();
        assert_eq!(
            decide_udp(&mut addrs, &lifted, SocketAddrV4::new(host, 53), &[], now),
            (Verdict::Allow, Some("allow 203.0.113.7:53".to_owned()))
        );
    }

    #[test]
    fn connect_failures_name_their_reason() {
        let reason = |errno| close_reason(&io::Error::from_raw_os_error(errno));
        assert_eq!(reason(libc::ECONNREFUSED), "refused");
        assert_eq!(reason(libc::ENETUNREACH), "unreachable");
        assert_eq!(reason(libc::EHOSTUNREACH), "unreachable");
        assert_eq!(reason(libc::ETIMEDOUT), "timeout");
        assert_eq!(reason(libc::EACCES), "error");
    }

    #[test]
    fn a_refused_connect_is_reported() {
        // A port nothing listens on: bind one and let it go.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let stream = connect(ConnectTarget::Host(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        )))
        .unwrap();
        let start = Instant::now();
        loop {
            match progress(&stream) {
                Progress::Failed(error) => {
                    assert_eq!(close_reason(&error), "refused", "{error}");
                    break;
                }
                Progress::Waiting => {
                    assert!(start.elapsed() < Duration::from_secs(5));
                    std::thread::sleep(Duration::from_millis(1));
                }
                Progress::Done => panic!("connected to nothing"),
            }
        }
    }
}
