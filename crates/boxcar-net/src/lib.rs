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
//! - [`stack`]: the queues, smoltcp's interface (which takes TCP), and the
//!   counted drops.
//! - [`audit`]: the `net.*` records.
//! - [`config`]: the addressing and the egress policy.
//!
//! IPv6 is dropped. DNS and other UDP are dropped and counted until their
//! handlers land; TCP reaches smoltcp, which has no sockets yet and resets
//! every connection.

pub mod arp;
pub mod audit;
pub mod config;
pub mod dhcp;
pub mod frame;
pub mod icmp;
pub mod stack;

pub use audit::DropReason;
pub use config::{ConfigError, NetConfig, Policy};
pub use frame::Dispatch;
pub use stack::{FdChange, Interest, NetStack, PollOutcome};
