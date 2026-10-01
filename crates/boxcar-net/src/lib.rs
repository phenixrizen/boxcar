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
//! - [`stack`]: the queues, smoltcp's interface (which takes TCP), and the
//!   counted drops.
//! - [`audit`]: the `net.*` records.
//! - [`config`]: the addressing and the DNS upstreams.
//!
//! IPv6 is dropped. UDP other than DHCP and DNS is dropped and counted
//! until its relay lands; TCP reaches smoltcp, which has no sockets yet and
//! resets every connection.

pub mod arp;
pub mod audit;
pub mod config;
pub mod dhcp;
pub mod dns;
pub mod frame;
pub mod icmp;
pub mod policy;
pub mod stack;

pub use audit::DropReason;
pub use config::{ConfigError, NetConfig};
pub use frame::Dispatch;
pub use policy::{Ipv4Net, Policy, PolicyError, Rule, Target, Verdict};
pub use stack::{FdChange, Interest, NetStack, PollOutcome, DNS_TOKEN};
