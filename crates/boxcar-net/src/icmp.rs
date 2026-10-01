// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! ICMP: the gateway answers an echo request sent to it, so `ping 10.0.2.2`
//! works. Nothing else is answered and no ICMP goes to the host, which has
//! no unprivileged way to send it; the stack drops the rest.

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv4Packet, Icmpv4Repr, IpProtocol,
    Ipv4Packet, Ipv4Repr,
};

use crate::config::NetConfig;
use crate::frame::ipv4_frame;

/// The hop limit of the replies.
const TTL: u8 = 64;

/// The echo reply to a guest echo request for the gateway, with the
/// request's identifier, sequence number and data. Anything else (another
/// destination, another ICMP message, a malformed packet) gets nothing.
pub fn reply(cfg: &NetConfig, frame: &[u8]) -> Option<Vec<u8>> {
    let checks = ChecksumCapabilities::default();
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let packet = Ipv4Packet::new_checked(eth.payload()).ok()?;
    let ip = Ipv4Repr::parse(&packet, &checks).ok()?;
    if ip.next_header != IpProtocol::Icmp || ip.dst_addr != cfg.gateway {
        return None;
    }
    let icmp = Icmpv4Packet::new_checked(packet.payload()).ok()?;
    let Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data,
    } = Icmpv4Repr::parse(&icmp, &checks).ok()?
    else {
        return None;
    };
    let echo = Icmpv4Repr::EchoReply {
        ident,
        seq_no,
        data,
    };
    let reply = Ipv4Repr {
        src_addr: cfg.gateway,
        dst_addr: ip.src_addr,
        next_header: IpProtocol::Icmp,
        payload_len: echo.buffer_len(),
        hop_limit: TTL,
    };
    Some(ipv4_frame(
        EthernetAddress(cfg.gateway_mac),
        eth.src_addr(),
        &reply,
        |buf| echo.emit(&mut Icmpv4Packet::new_unchecked(buf), &checks),
    ))
}
