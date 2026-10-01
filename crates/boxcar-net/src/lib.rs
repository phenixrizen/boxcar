// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! boxcar's user-mode network: the guest's gateway, played inside the VMM
//! with no TAP device and no privileges.
//!
//! The guest is `10.0.2.15/24`; `10.0.2.2` is its router, DNS server and
//! DHCP server. [`NetStack`] takes the guest's Ethernet frames and gives
//! back the frames it sends in reply. A dispatcher sorts every frame before
//! smoltcp sees it, so the link-level basics are answered the same way
//! every time:
//!
//! - [`frame`]: the sort, [`classify`](frame::classify).
//! - [`arp`]: proxy ARP for the whole network but the guest's own address.
//! - [`dhcp`]: a static lease.
//! - [`icmp`]: echo replies from the gateway; all other ICMP is dropped.
//! - [`dns`]: the gateway's DNS, forwarded to the host's resolver, and the
//!   names each answer gave its addresses.
//! - [`policy`]: what the guest may reach and resolve.
//! - [`tcp`]: the TCP relay, which decides each connection before
//!   answering it, carries it over a host socket, and gates the ones a
//!   domain rule allowed on the name they ask for ([`sni`],
//!   [`http_host`]); [`upstream`]: how a flow is decided, its host
//!   connects, and the host's own addresses, which the guest may not
//!   reach.
//! - [`udp`]: the UDP relay, NAT with one connected host socket for each
//!   5-tuple the policy allows by address.
//! - [`stack`]: the queues, smoltcp's interface (the far end of the
//!   relayed connections), and the counted drops.
//! - [`audit`]: the `net.*` records.
//! - [`config`]: the addressing, the DNS upstreams, and the relays' bounds.
//!
//! IPv6 is dropped and counted.

pub mod arp;
pub mod audit;
pub mod config;
pub mod dhcp;
pub mod dns;
pub mod frame;
pub mod http_host;
pub mod icmp;
pub mod policy;
pub mod sni;
pub mod stack;
pub mod tcp;
pub mod udp;
pub mod upstream;

pub use audit::DropReason;
pub use config::{ConfigError, NetConfig};
pub use frame::Dispatch;
pub use policy::{Ipv4Net, Policy, PolicyError, Rule, Target, Verdict};
pub use stack::{FdChange, Interest, NetStack, PollOutcome, DNS_TOKEN};
pub use tcp::{TcpLimits, FLOW_TOKEN_BASE};
pub use udp::{UdpLimits, UDP_TOKEN_BASE};
