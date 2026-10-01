// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! DHCP: one static lease. A DISCOVER gets an OFFER and a REQUEST an ACK,
//! both for the guest's address, with the gateway as router, DNS server and
//! server identifier, the network's mask, the guest's host name, and a
//! 24-hour lease. Nothing is remembered between messages: the lease is the
//! same whoever asks.

use std::net::Ipv4Addr;

use boxcar_proto::NetDhcp;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    DhcpMessageType, DhcpOption, DhcpPacket, DhcpRepr, EthernetAddress, EthernetFrame,
    EthernetProtocol, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr, DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT,
};

use crate::config::{NetConfig, LEASE_SECS};
use crate::frame::ipv4_frame;

/// The DHCP option that carries the host name.
const OPT_HOST_NAME: u8 = 12;
/// The smallest BOOTP message (RFC 1542); some clients refuse shorter.
const MIN_MESSAGE_LEN: usize = 300;
/// The hop limit of the replies.
const TTL: u8 = 64;

/// The lease answering a guest DHCP message, and its `net.dhcp` record:
/// an OFFER for a DISCOVER, an ACK for a REQUEST. Any other message, or a
/// malformed one, gets nothing.
///
/// The reply is broadcast when the request's broadcast flag asks for it,
/// and sent to the client's MAC and the leased address otherwise.
pub fn reply(cfg: &NetConfig, frame: &[u8]) -> Option<(Vec<u8>, NetDhcp)> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    let ip = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 || ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    if udp.dst_port() != DHCP_SERVER_PORT {
        return None;
    }
    let packet = DhcpPacket::new_checked(udp.payload()).ok()?;
    let request = DhcpRepr::parse(&packet).ok()?;
    let (message_type, op) = match request.message_type {
        DhcpMessageType::Discover => (DhcpMessageType::Offer, "offer"),
        DhcpMessageType::Request => (DhcpMessageType::Ack, "ack"),
        _ => return None,
    };

    let hostname = [DhcpOption {
        kind: OPT_HOST_NAME,
        data: cfg.hostname.as_bytes(),
    }];
    let mut lease = DhcpRepr {
        message_type,
        transaction_id: request.transaction_id,
        secs: 0,
        client_hardware_address: request.client_hardware_address,
        // An ACK repeats the address a renewing client gave; an OFFER has
        // none to repeat.
        client_ip: match message_type {
            DhcpMessageType::Ack => request.client_ip,
            _ => Ipv4Addr::UNSPECIFIED,
        },
        your_ip: cfg.guest_ip,
        server_ip: cfg.gateway,
        router: Some(cfg.gateway),
        subnet_mask: Some(cfg.netmask_addr()),
        relay_agent_ip: request.relay_agent_ip,
        broadcast: request.broadcast,
        requested_ip: None,
        client_identifier: request.client_identifier,
        server_identifier: Some(cfg.gateway),
        parameter_request_list: None,
        dns_servers: Some(Default::default()),
        max_size: None,
        lease_duration: Some(LEASE_SECS),
        // smoltcp does not write these; the client takes the RFC 2131
        // defaults, half and seven eighths of the lease.
        renew_duration: None,
        rebind_duration: None,
        additional_options: &hostname,
    };
    lease.dns_servers.as_mut()?.push(cfg.gateway).ok()?;

    let (eth_dst, ip_dst) = if request.broadcast {
        (EthernetAddress::BROADCAST, Ipv4Addr::BROADCAST)
    } else {
        (request.client_hardware_address, cfg.guest_ip)
    };
    let ports = UdpRepr {
        src_port: DHCP_SERVER_PORT,
        dst_port: DHCP_CLIENT_PORT,
    };
    let message_len = lease.buffer_len().max(MIN_MESSAGE_LEN);
    let ip = Ipv4Repr {
        src_addr: cfg.gateway,
        dst_addr: ip_dst,
        next_header: IpProtocol::Udp,
        payload_len: ports.header_len() + message_len,
        hop_limit: TTL,
    };
    let mut emitted = Ok(());
    let reply = ipv4_frame(EthernetAddress(cfg.gateway_mac), eth_dst, &ip, |datagram| {
        ports.emit(
            &mut UdpPacket::new_unchecked(datagram),
            &cfg.gateway.into(),
            &ip_dst.into(),
            message_len,
            // Bytes after the end option stay zero: padding.
            |message| emitted = lease.emit(&mut DhcpPacket::new_unchecked(message)),
            &ChecksumCapabilities::default(),
        )
    });
    emitted.ok()?;
    Some((
        reply,
        NetDhcp {
            op: op.to_owned(),
            yiaddr: cfg.guest_ip,
        },
    ))
}
