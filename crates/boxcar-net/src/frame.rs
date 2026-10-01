// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The dispatcher's sort: what one guest Ethernet frame is, and so where it
//! goes. [`classify`] reads only; every length is checked before it is used,
//! and a frame it cannot make sense of is [`Dispatch::Other`], never a
//! panic.
//!
//! Classification trusts nothing it has not checked: an IPv4 packet must
//! have a correct header checksum and must not be a fragment (the guest's
//! TCP never fragments, and nothing here reassembles), and a UDP, ICMP or
//! TCP header must fit and carry a correct checksum (UDP's may be absent).
//! The handlers behind it can rely on that.

use std::net::{Ipv4Addr, SocketAddrV4};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr,
    Icmpv4Packet, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    UdpPacket, UdpRepr, DHCP_SERVER_PORT,
};

/// The DNS port.
pub const DNS_PORT: u16 = 53;

/// Where a guest frame goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// An Ethernet/IPv4 ARP packet: proxy ARP, and smoltcp's neighbor cache.
    Arp,
    /// UDP to port 67, any address: the static DHCP lease.
    Dhcp,
    /// UDP to port 53 at the gateway: the DNS forwarder.
    Dns {
        src: SocketAddrV4,
        dst: SocketAddrV4,
    },
    /// Any other UDP: the UDP relay.
    Udp {
        src: SocketAddrV4,
        dst: SocketAddrV4,
    },
    /// ICMP: echo to the gateway is answered, the rest dropped.
    Icmp { src: Ipv4Addr, dst: Ipv4Addr },
    /// A TCP segment with SYN and with none of ACK, FIN and RST: a new
    /// connection.
    TcpSyn {
        src: SocketAddrV4,
        dst: SocketAddrV4,
    },
    /// Any other TCP segment, a SYN with FIN or RST among them.
    Tcp {
        src: SocketAddrV4,
        dst: SocketAddrV4,
    },
    /// IPv6, which the guest network does not carry.
    Ipv6,
    /// Anything else, including every frame that is malformed, truncated,
    /// fragmented, or fails a checksum.
    Other,
}

/// Sorts one guest frame. `gateway` is the gateway's address, which
/// decides whether UDP to port 53 is DNS for the forwarder or ordinary UDP.
pub fn classify(frame: &[u8], gateway: Ipv4Addr) -> Dispatch {
    let Ok(eth) = EthernetFrame::new_checked(frame) else {
        return Dispatch::Other;
    };
    match eth.ethertype() {
        EthernetProtocol::Arp => {
            let parsed = ArpPacket::new_checked(eth.payload()).and_then(|p| ArpRepr::parse(&p));
            match parsed {
                Ok(ArpRepr::EthernetIpv4 { .. }) => Dispatch::Arp,
                _ => Dispatch::Other,
            }
        }
        EthernetProtocol::Ipv4 => classify_ipv4(eth.payload(), gateway),
        EthernetProtocol::Ipv6 => Dispatch::Ipv6,
        EthernetProtocol::Unknown(_) => Dispatch::Other,
    }
}

fn classify_ipv4(payload: &[u8], gateway: Ipv4Addr) -> Dispatch {
    let checks = ChecksumCapabilities::default();
    let Ok(packet) = Ipv4Packet::new_checked(payload) else {
        return Dispatch::Other;
    };
    // Version 4, the header checksum, and no fragment.
    let Ok(ip) = Ipv4Repr::parse(&packet, &checks) else {
        return Dispatch::Other;
    };
    let (src, dst) = (ip.src_addr, ip.dst_addr);
    let body = packet.payload();
    match ip.next_header {
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(body) else {
                return Dispatch::Other;
            };
            // The checksum (or its absence), and a nonzero destination port.
            let Ok(ports) = UdpRepr::parse(&udp, &src.into(), &dst.into(), &checks) else {
                return Dispatch::Other;
            };
            let src = SocketAddrV4::new(src, ports.src_port);
            let dst = SocketAddrV4::new(dst, ports.dst_port);
            if ports.dst_port == DHCP_SERVER_PORT {
                Dispatch::Dhcp
            } else if ports.dst_port == DNS_PORT && *dst.ip() == gateway {
                Dispatch::Dns { src, dst }
            } else {
                Dispatch::Udp { src, dst }
            }
        }
        IpProtocol::Icmp => match Icmpv4Packet::new_checked(body) {
            Ok(icmp) if icmp.verify_checksum() => Dispatch::Icmp { src, dst },
            _ => Dispatch::Other,
        },
        IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(body) else {
                return Dispatch::Other;
            };
            if !tcp.verify_checksum(&src.into(), &dst.into()) {
                return Dispatch::Other;
            }
            let src = SocketAddrV4::new(src, tcp.src_port());
            let dst = SocketAddrV4::new(dst, tcp.dst_port());
            // SYN with FIN or RST is no connection: smoltcp drops it.
            if tcp.syn() && !tcp.ack() && !tcp.fin() && !tcp.rst() {
                Dispatch::TcpSyn { src, dst }
            } else {
                Dispatch::Tcp { src, dst }
            }
        }
        _ => Dispatch::Other,
    }
}

/// The UDP payload of a guest frame [`classify`] sorted as UDP (DHCP, DNS,
/// or other); `None` for any other frame.
pub(crate) fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    Some(udp.payload())
}

/// An Ethernet frame carrying `payload` in a UDP datagram from `src` to
/// `dst`, with both checksums filled in; `None` for a payload too long for
/// one datagram.
pub(crate) fn udp_frame(
    eth_src: EthernetAddress,
    eth_dst: EthernetAddress,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let ports = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let ip = Ipv4Repr {
        src_addr: *src.ip(),
        dst_addr: *dst.ip(),
        next_header: IpProtocol::Udp,
        payload_len: ports.header_len() + payload.len(),
        hop_limit: TTL,
    };
    // The IPv4 total length is 16 bits.
    if ip.buffer_len() + ip.payload_len > usize::from(u16::MAX) {
        return None;
    }
    Some(ipv4_frame(eth_src, eth_dst, &ip, |datagram| {
        ports.emit(
            &mut UdpPacket::new_unchecked(datagram),
            &(*src.ip()).into(),
            &(*dst.ip()).into(),
            payload.len(),
            |body| body.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        )
    }))
}

/// Whether a guest frame [`classify`] sorted as TCP is a reset (RST
/// without SYN).
pub(crate) fn tcp_reset_flag(frame: &[u8]) -> bool {
    tcp_header(frame).is_some_and(|tcp| tcp.rst() && !tcp.syn())
}

/// The TCP header of a guest frame, if it is IPv4 TCP.
fn tcp_header(frame: &[u8]) -> Option<TcpPacket<&[u8]>> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let packet = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if packet.next_header() != IpProtocol::Tcp {
        return None;
    }
    TcpPacket::new_checked(packet.payload()).ok()
}

/// The sequence number of a guest TCP segment (a SYN's is the guest's
/// initial sequence number).
pub(crate) fn tcp_seq(frame: &[u8]) -> Option<u32> {
    tcp_header(frame).map(|tcp| tcp.seq_number().0 as u32)
}

/// Where a guest TCP segment's FIN sits in the sequence space (after its
/// data), if it carries one (without SYN or RST).
pub(crate) fn tcp_fin_position(frame: &[u8]) -> Option<u32> {
    let tcp = tcp_header(frame)?;
    if !tcp.fin() || tcp.syn() || tcp.rst() {
        return None;
    }
    let data = u32::try_from(tcp.payload().len()).ok()?;
    Some((tcp.seq_number().0 as u32).wrapping_add(data))
}

/// The RST+ACK that refuses a guest's TCP segment `segment` (a SYN, for
/// the relay): from the address and port it was sent to, with the
/// sequence number of its acknowledgement (zero, for a SYN, which has
/// none) and acknowledging all it occupied, and a zero window (RFC 9293
/// §3.10.7.1). `None` for a frame that is not an IPv4 TCP segment.
pub(crate) fn tcp_reset(
    segment: &[u8],
    eth_src: EthernetAddress,
    eth_dst: EthernetAddress,
) -> Option<Vec<u8>> {
    let eth = EthernetFrame::new_checked(segment).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let packet = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if packet.next_header() != IpProtocol::Tcp {
        return None;
    }
    let (src, dst) = (packet.src_addr(), packet.dst_addr());
    let tcp = TcpPacket::new_checked(packet.payload()).ok()?;
    let seq_number = if tcp.ack() {
        tcp.ack_number()
    } else {
        TcpSeqNumber(0)
    };
    // A segment fits a 16-bit IPv4 length, so this always converts.
    let occupied = i32::try_from(tcp.segment_len()).ok()?;
    let reply = TcpRepr {
        src_port: tcp.dst_port(),
        dst_port: tcp.src_port(),
        control: TcpControl::Rst,
        seq_number,
        ack_number: Some(TcpSeqNumber(tcp.seq_number().0.wrapping_add(occupied))),
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: dst,
        dst_addr: src,
        next_header: IpProtocol::Tcp,
        payload_len: reply.buffer_len(),
        hop_limit: TTL,
    };
    Some(ipv4_frame(eth_src, eth_dst, &ip, |datagram| {
        reply.emit(
            &mut TcpPacket::new_unchecked(datagram),
            &dst.into(),
            &src.into(),
            &ChecksumCapabilities::default(),
        )
    }))
}

/// The hop limit of the replies the stack makes.
const TTL: u8 = 64;

/// An Ethernet frame carrying the IPv4 packet `ip` describes, with its
/// header checksum filled in; `fill` writes the `ip.payload_len` bytes of
/// payload. For the replies the dispatcher makes itself.
pub(crate) fn ipv4_frame(
    eth_src: EthernetAddress,
    eth_dst: EthernetAddress,
    ip: &Ipv4Repr,
    fill: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let eth = EthernetRepr {
        src_addr: eth_src,
        dst_addr: eth_dst,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut buf = vec![0; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &ChecksumCapabilities::default());
    fill(packet.payload_mut());
    buf
}
