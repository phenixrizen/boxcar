// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The TCP relay: the guest's connections, carried by host sockets.
//!
//! A guest SYN is decided before anything answers it (the deferred SYN).
//! The destination must not be one of the host's own addresses
//! ([`upstream::host_local`](crate::upstream::host_local)), and then the
//! policy's [`egress`](crate::Policy::egress) decides. A denied SYN gets an
//! RST+ACK from the destination's address at once. An allowed one starts a
//! non-blocking host connect and is parked; its retransmits are dropped
//! while it waits. Only when the host connect succeeds does the guest get
//! a SYN-ACK: a smoltcp socket is made to listen on the destination's
//! address and port, and the parked SYN is fed to it. A connect that fails
//! or takes longer than [`TcpLimits::connect_timeout`] gets the guest an
//! RST+ACK instead.
//!
//! Then bytes move both ways ([`relay`]). Each direction stops when the
//! next hop has no room: guest bytes stay in the smoltcp socket's receive
//! buffer while the host socket refuses them, which closes the guest's
//! window, and the host socket is not read while the smoltcp send buffer
//! is full. A FIN from either side is passed on as a FIN, after every byte
//! before it, a reset as a reset. A guest that stays silent for
//! [`GUEST_TIMEOUT`] while it is waited on ends its flow (`timeout`).
//!
//! A flow a domain rule allowed is gated first ([`relay`]): its first
//! bytes are held, unforwarded, until they show a TLS ClientHello server
//! name ([`sni`](crate::sni)) or a plain HTTP `Host`
//! ([`http_host`](crate::http_host)) that the policy's domain rules allow
//! on this port ([`Policy::gate_allows`](crate::Policy::gate_allows)),
//! within [`TcpLimits::gate_limit`] bytes and [`TcpLimits::gate_timeout`];
//! else both sides are reset.
//!
//! Every table is bounded: [`TcpLimits::flow_cap`] flows, the idlest
//! evicted to make room, and [`TcpLimits::pending_cap`] connects under way,
//! a SYN past that being dropped (`tcp_pending_full`) for the guest to
//! send again.
//!
//! Records: `net.connect` for every SYN decided, `net.tls` for every gate
//! decision, and one `net.close` for every flow that was allowed.

pub mod flow;
pub mod relay;

use std::time::Duration;

pub use flow::{Flow, FlowId, FlowState, FlowTable, GateBuf, Pending, FLOW_ID_LIMIT};

/// The [`FdChange`](crate::FdChange) token of flow 0's host socket; flow
/// `n`'s is this plus `n`. Below it are the stack's own tokens, such as
/// [`DNS_TOKEN`](crate::DNS_TOKEN); from it, [`FLOW_ID_LIMIT`] (2^62)
/// tokens on, the UDP mappings' ([`UDP_TOKEN_BASE`](crate::UDP_TOKEN_BASE)).
/// Flow ids stay below 2^62, so the spaces never meet.
pub const TCP_TOKEN_BASE: u64 = 1 << 62;

/// The size of each smoltcp socket buffer, receive and send.
///
/// What a flow can hold, at worst: both buffers (128 KiB, allocated with
/// the flow), plus its tail of guest bytes taken out for the host: up to a
/// gate prefix ([`GATE_LIMIT`], about 16 KiB) after a gate pass, and the
/// receive buffer's worth (64 KiB) taken once at the guest's FIN. That is
/// about 208 KiB a flow, and 4096 × 208 KiB ≈ 832 MiB at the flow cap,
/// beside the host sockets' kernel buffers.
pub const SOCKET_BUFFER: usize = 64 * 1024;

/// The gate's default byte limit: one TLS record of the largest size, with
/// its header, so a ClientHello that fills its record still passes.
pub const GATE_LIMIT: usize = crate::sni::MAX_RECORD + crate::sni::RECORD_HEADER;

/// How long a relayed connection's guest may stay silent while the relay
/// waits on it (to answer a SYN-ACK, acknowledge data or a FIN, or answer
/// a keep-alive) before smoltcp gives up on it: the flow ends `timeout`
/// and the host side is reset.
pub const GUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How often an idle relayed connection probes the guest, so a guest that
/// is there answers well within [`GUEST_TIMEOUT`] and an idle connection
/// is not taken for a vanished one.
pub const KEEP_ALIVE: Duration = Duration::from_secs(20);

/// The longest connect or gate timeout a config may ask for.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// The relay's bounds. The defaults are production's; tests lower them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpLimits {
    /// Flows held at once; at the cap, the flow idle longest (by the last
    /// byte it moved either way) is evicted for a new one.
    pub flow_cap: usize,
    /// Host connects under way at once; a SYN past it is dropped.
    pub pending_cap: usize,
    /// How long a host connect may take before the guest is reset.
    pub connect_timeout: Duration,
    /// How long, from its connect, a gated flow may take to show its name.
    pub gate_timeout: Duration,
    /// How many bytes a gated flow may send before it shows its name; at
    /// most [`SOCKET_BUFFER`].
    pub gate_limit: usize,
}

impl Default for TcpLimits {
    fn default() -> Self {
        TcpLimits {
            flow_cap: 4096,
            pending_cap: 256,
            connect_timeout: Duration::from_secs(10),
            gate_timeout: Duration::from_secs(5),
            gate_limit: GATE_LIMIT,
        }
    }
}

impl TcpLimits {
    /// What is wrong with these bounds, if anything: every cap must be at
    /// least one, the gate's byte limit must fit a socket buffer, and no
    /// timeout may pass [`MAX_TIMEOUT`].
    pub fn check(&self) -> Result<(), &'static str> {
        if self.connect_timeout > MAX_TIMEOUT || self.gate_timeout > MAX_TIMEOUT {
            return Err("tcp timeouts must be at most a day");
        }
        if self.flow_cap == 0 {
            return Err("tcp.flow_cap must be at least 1");
        }
        if self.pending_cap == 0 {
            return Err("tcp.pending_cap must be at least 1");
        }
        if self.gate_limit == 0 || self.gate_limit > SOCKET_BUFFER {
            return Err("tcp.gate_limit must be 1 byte to the socket buffer's size");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_production_bounds() {
        let limits = TcpLimits::default();
        assert_eq!(limits.flow_cap, 4096);
        assert_eq!(limits.pending_cap, 256);
        assert_eq!(limits.connect_timeout, Duration::from_secs(10));
        assert_eq!(limits.gate_timeout, Duration::from_secs(5));
        assert_eq!(limits.gate_limit, 16384 + 5);
        assert_eq!(SOCKET_BUFFER, 64 * 1024);
        assert_eq!(GUEST_TIMEOUT, Duration::from_secs(60));
        assert!(KEEP_ALIVE * 2 < GUEST_TIMEOUT, "two probes before it");
        assert_eq!(limits.check(), Ok(()));
        for broken in [
            TcpLimits {
                flow_cap: 0,
                ..TcpLimits::default()
            },
            TcpLimits {
                pending_cap: 0,
                ..TcpLimits::default()
            },
            TcpLimits {
                gate_limit: 0,
                ..TcpLimits::default()
            },
            TcpLimits {
                gate_limit: SOCKET_BUFFER + 1,
                ..TcpLimits::default()
            },
            TcpLimits {
                gate_timeout: Duration::MAX,
                ..TcpLimits::default()
            },
            TcpLimits {
                connect_timeout: MAX_TIMEOUT + Duration::from_secs(1),
                ..TcpLimits::default()
            },
        ] {
            assert!(broken.check().is_err(), "{broken:?}");
        }
    }
}
