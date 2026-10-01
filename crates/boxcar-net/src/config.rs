// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest network's addressing and the DNS upstreams the stack is built
//! with. The egress policy is in [`policy`](crate::policy).
//!
//! The addressing is fixed: the guest is `10.0.2.15/24` at
//! `02:62:6f:78:00:01`, and `10.0.2.2` at `02:62:6f:78:00:02` is its
//! gateway, DNS server, and DHCP server, all played by the stack. The guest
//! is called `boxcar` and leases its address for 24 hours.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The guest's address.
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
/// The gateway's address: the guest's router, DNS server and DHCP server.
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
/// The prefix length of the guest's network.
pub const NETMASK_BITS: u8 = 24;
/// The guest's MAC address: locally administered, unicast, `bo` `x`.
pub const GUEST_MAC: [u8; 6] = [0x02, 0x62, 0x6f, 0x78, 0x00, 0x01];
/// The gateway's MAC address, which answers for every other host on the
/// guest's network.
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x62, 0x6f, 0x78, 0x00, 0x02];
/// The guest's host name, given in every DHCP lease.
pub const HOSTNAME: &str = "boxcar";
/// How long a DHCP lease lasts, in seconds: 24 hours.
pub const LEASE_SECS: u32 = 24 * 60 * 60;
/// The DNS upstream used when the host's resolver configuration names none.
pub const FALLBACK_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
/// Where the host's DNS servers are read from.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// How the guest's network is laid out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetConfig {
    pub guest_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    /// The network's prefix length.
    pub netmask: u8,
    pub guest_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub hostname: String,
    /// Where guest DNS queries are forwarded, in order of preference.
    pub dns_upstreams: Vec<SocketAddr>,
}

/// The fixed addressing, with [`FALLBACK_DNS`] as the only upstream.
/// [`NetConfig::from_host`] takes the host's DNS servers instead.
impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            guest_ip: GUEST_IP,
            gateway: GATEWAY_IP,
            netmask: NETMASK_BITS,
            guest_mac: GUEST_MAC,
            gateway_mac: GATEWAY_MAC,
            hostname: HOSTNAME.to_owned(),
            dns_upstreams: vec![FALLBACK_DNS],
        }
    }
}

impl NetConfig {
    /// The fixed addressing, forwarding DNS to the servers the host's
    /// [`RESOLV_CONF`] names, or to [`FALLBACK_DNS`] when it names none or
    /// cannot be read.
    pub fn from_host() -> Self {
        let named = fs::read_to_string(RESOLV_CONF)
            .map(|text| nameservers(&text))
            .unwrap_or_default();
        NetConfig {
            dns_upstreams: if named.is_empty() {
                vec![FALLBACK_DNS]
            } else {
                named
            },
            ..NetConfig::default()
        }
    }

    /// The network mask as an address, such as `255.255.255.0` for /24.
    /// A prefix length over 32 counts as 32.
    pub fn netmask_addr(&self) -> Ipv4Addr {
        let bits = u32::from(self.netmask.min(32));
        Ipv4Addr::from(u32::MAX.checked_shl(32 - bits).unwrap_or(0))
    }

    /// Whether `addr` is on the guest's network.
    pub fn on_network(&self, addr: Ipv4Addr) -> bool {
        let mask = u32::from(self.netmask_addr());
        u32::from(addr) & mask == u32::from(self.gateway) & mask
    }

    /// Checks what the stack depends on: a network with room for a guest
    /// and a gateway, both on it, distinct, and unicast at both layers, a
    /// host name a DHCP lease can carry, and a DNS upstream.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=30).contains(&self.netmask) {
            return Err(ConfigError::Netmask(self.netmask));
        }
        for (role, addr) in [("gateway", self.gateway), ("guest", self.guest_ip)] {
            if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() {
                return Err(ConfigError::NotUnicast { role, addr });
            }
        }
        if self.guest_ip == self.gateway {
            return Err(ConfigError::SameAddress(self.guest_ip));
        }
        if !self.on_network(self.guest_ip) {
            return Err(ConfigError::GuestOffNetwork {
                guest: self.guest_ip,
                gateway: self.gateway,
                netmask: self.netmask,
            });
        }
        for (role, mac) in [("gateway", self.gateway_mac), ("guest", self.guest_mac)] {
            // The group bit is the low bit of the first octet.
            if mac[0] & 1 != 0 || mac == [0; 6] {
                return Err(ConfigError::MacNotUnicast {
                    role,
                    mac: mac_text(mac),
                });
            }
        }
        if self.guest_mac == self.gateway_mac {
            return Err(ConfigError::SameMac(mac_text(self.guest_mac)));
        }
        let label = self.hostname.as_bytes();
        if label.is_empty()
            || label.len() > 63
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(ConfigError::Hostname(self.hostname.clone()));
        }
        if self.dns_upstreams.is_empty() {
            return Err(ConfigError::NoDnsUpstream);
        }
        Ok(())
    }
}

/// A [`NetConfig`] the stack cannot be built with.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("netmask /{0} leaves no room for a guest and a gateway; use /1 to /30")]
    Netmask(u8),
    #[error("the {role} address {addr} is not a unicast address")]
    NotUnicast { role: &'static str, addr: Ipv4Addr },
    #[error("the guest and the gateway are both {0}")]
    SameAddress(Ipv4Addr),
    #[error("the guest address {guest} is not on the gateway's network {gateway}/{netmask}")]
    GuestOffNetwork {
        guest: Ipv4Addr,
        gateway: Ipv4Addr,
        netmask: u8,
    },
    #[error("the {role} MAC address {mac} is not a unicast address")]
    MacNotUnicast { role: &'static str, mac: String },
    #[error("the guest and the gateway both have the MAC address {0}")]
    SameMac(String),
    #[error("host name {0:?} is not 1 to 63 ASCII letters, digits and hyphens")]
    Hostname(String),
    #[error("the network interface has no room for {0}")]
    Interface(&'static str),
    #[error("no DNS upstream to forward the guest's queries to")]
    NoDnsUpstream,
    #[error("no DNS upstream could be given a socket: {0}")]
    DnsUpstream(String),
}

fn mac_text(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// The DNS servers a resolv.conf names, in its order, on port 53. Lines
/// other than `nameserver <address>`, and addresses that do not parse (such
/// as a link-local address with a zone), are skipped.
pub fn nameservers(resolv_conf: &str) -> Vec<SocketAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("nameserver"), Some(addr)) => addr.parse::<IpAddr>().ok(),
                _ => None,
            }
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_fixed_addressing_and_validates() {
        let cfg = NetConfig::default();
        assert_eq!(cfg.guest_ip, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(cfg.gateway, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(cfg.netmask, 24);
        assert_eq!(cfg.guest_mac, [0x02, 0x62, 0x6f, 0x78, 0x00, 0x01]);
        assert_eq!(cfg.gateway_mac, [0x02, 0x62, 0x6f, 0x78, 0x00, 0x02]);
        assert_eq!(cfg.hostname, "boxcar");
        assert_eq!(cfg.dns_upstreams, ["1.1.1.1:53".parse().unwrap()]);
        assert_eq!(LEASE_SECS, 86_400);
        assert_eq!(cfg.netmask_addr(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn on_network_is_the_gateways_prefix() {
        let cfg = NetConfig::default();
        for inside in [[10, 0, 2, 0], [10, 0, 2, 77], [10, 0, 2, 255]] {
            assert!(cfg.on_network(inside.into()), "{inside:?}");
        }
        for outside in [[10, 0, 3, 1], [10, 1, 2, 2], [8, 8, 8, 8]] {
            assert!(!cfg.on_network(outside.into()), "{outside:?}");
        }
        let wide = NetConfig {
            netmask: 32,
            ..NetConfig::default()
        };
        assert_eq!(wide.netmask_addr(), Ipv4Addr::BROADCAST);
        let none = NetConfig {
            netmask: 0,
            ..NetConfig::default()
        };
        assert_eq!(none.netmask_addr(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn validate_refuses_what_the_stack_cannot_be_built_with() {
        let with = |change: fn(&mut NetConfig)| {
            let mut cfg = NetConfig::default();
            change(&mut cfg);
            cfg.validate()
        };
        assert_eq!(with(|c| c.netmask = 0), Err(ConfigError::Netmask(0)));
        assert_eq!(with(|c| c.netmask = 31), Err(ConfigError::Netmask(31)));
        assert_eq!(with(|c| c.netmask = 99), Err(ConfigError::Netmask(99)));
        assert!(matches!(
            with(|c| c.gateway = Ipv4Addr::new(224, 0, 0, 1)),
            Err(ConfigError::NotUnicast {
                role: "gateway",
                ..
            })
        ));
        assert!(matches!(
            with(|c| c.guest_ip = Ipv4Addr::UNSPECIFIED),
            Err(ConfigError::NotUnicast { role: "guest", .. })
        ));
        assert_eq!(
            with(|c| c.guest_ip = c.gateway),
            Err(ConfigError::SameAddress(GATEWAY_IP))
        );
        assert!(matches!(
            with(|c| c.guest_ip = Ipv4Addr::new(10, 0, 3, 15)),
            Err(ConfigError::GuestOffNetwork { .. })
        ));
        assert!(matches!(
            with(|c| c.gateway_mac = [0x03, 0, 0, 0, 0, 2]),
            Err(ConfigError::MacNotUnicast {
                role: "gateway",
                ..
            })
        ));
        assert!(matches!(
            with(|c| c.guest_mac = [0; 6]),
            Err(ConfigError::MacNotUnicast { role: "guest", .. })
        ));
        assert!(matches!(
            with(|c| c.guest_mac = c.gateway_mac),
            Err(ConfigError::SameMac(_))
        ));
        assert_eq!(
            with(|c| c.dns_upstreams.clear()),
            Err(ConfigError::NoDnsUpstream)
        );
        for bad in ["", "box car", "boxcar.local", &"x".repeat(64)] {
            let cfg = NetConfig {
                hostname: bad.to_owned(),
                ..NetConfig::default()
            };
            assert!(
                matches!(cfg.validate(), Err(ConfigError::Hostname(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn nameservers_are_read_in_order_and_junk_is_skipped() {
        let text = "\
# Generated by NetworkManager
search example.internal
nameserver 127.0.0.53
nameserver   9.9.9.9   # trailing words are ignored
;nameserver 8.8.8.8
nameserver fe80::1%eth0
nameserver 2606:4700:4700::1111
nameserver
options edns0 trust-ad
";
        assert_eq!(
            nameservers(text),
            [
                "127.0.0.53:53".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:53".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
            ]
        );
        assert!(nameservers("").is_empty());
    }
}
