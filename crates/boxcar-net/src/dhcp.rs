// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! DHCP: one static lease, for the guest's address, with the gateway as
//! router, DNS server and server identifier, the network's mask, the
//! guest's host name, and a 24-hour lease. Nothing is remembered between
//! messages. Following RFC 2131:
//!
//! - a DISCOVER gets an OFFER;
//! - a REQUEST naming another server (option 54) gets nothing: its client
//!   took that server's offer (§4.3.2);
//! - a REQUEST for another address, in option 50 or in `ciaddr`, gets a
//!   NAK, broadcast (§4.3.2, §4.1);
//! - any other REQUEST gets an ACK.
//!
//! An OFFER or ACK goes to `ciaddr` when the client has one (a renewal),
//! else by broadcast when the client's broadcast flag asks for it, else to
//! the client's MAC and the leased address (§4.1). Every reply carries the
//! request's client identifier (option 61) back unaltered, whatever its form
//! (RFC 6842).
//!
//! Requests are read field by field from the message, with every option
//! length checked, rather than with `DhcpRepr::parse`, which refuses a
//! 7-byte client identifier that is not an Ethernet address and keeps no
//! other form. Replies are built with `DhcpRepr`.

use std::net::Ipv4Addr;

use boxcar_proto::NetDhcp;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpHardware, DhcpFlags, DhcpMessageType, DhcpOpCode, DhcpOption, DhcpPacket, DhcpRepr,
    EthernetAddress, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket,
    UdpRepr, DHCP_CLIENT_PORT, DHCP_SERVER_PORT,
};

use crate::config::{NetConfig, LEASE_SECS};
use crate::frame::ipv4_frame;

const OPT_PAD: u8 = 0;
const OPT_HOST_NAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;
/// Where the options start: after the fixed fields and the magic cookie.
const OPTIONS_START: usize = 240;
const MAGIC_COOKIE: u32 = 0x6382_5363;
/// The smallest BOOTP message (RFC 1542); some clients refuse shorter.
const MIN_MESSAGE_LEN: usize = 300;
/// The hop limit of the replies.
const TTL: u8 = 64;

/// What the server does with one guest DHCP message.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    /// Send `frame` to the guest and record `record`.
    Reply { frame: Vec<u8>, record: NetDhcp },
    /// Nothing, and nothing to count: a REQUEST that took another server's
    /// offer.
    NotForUs,
    /// Nothing: a message the server does not answer (RELEASE, DECLINE,
    /// INFORM, a BOOTREPLY), or a malformed one. The stack counts it as a
    /// `dhcp` drop.
    Unanswered,
}

/// The server's answer to a guest frame carrying a DHCP message.
pub fn answer(cfg: &NetConfig, frame: &[u8]) -> Answer {
    let Some(request) = dhcp_message(frame).and_then(Request::parse) else {
        return Answer::Unanswered;
    };
    let built = match request.message_type {
        DhcpMessageType::Discover => lease(cfg, &request, DhcpMessageType::Offer),
        DhcpMessageType::Request => {
            if request.server_id.is_some_and(|id| id != cfg.gateway) {
                return Answer::NotForUs;
            }
            let other_address = request.requested_ip.is_some_and(|ip| ip != cfg.guest_ip)
                || !(request.ciaddr.is_unspecified() || request.ciaddr == cfg.guest_ip);
            if other_address {
                nak(cfg, &request)
            } else {
                lease(cfg, &request, DhcpMessageType::Ack)
            }
        }
        _ => None,
    };
    match built {
        Some((frame, record)) => Answer::Reply { frame, record },
        None => Answer::Unanswered,
    }
}

/// The UDP payload of an IPv4 datagram to the DHCP server port.
fn dhcp_message(frame: &[u8]) -> Option<&[u8]> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    (udp.dst_port() == DHCP_SERVER_PORT).then(|| udp.payload())
}

/// The parts of a client's message the server reads.
struct Request<'a> {
    message_type: DhcpMessageType,
    xid: u32,
    broadcast: bool,
    ciaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: EthernetAddress,
    /// Option 50.
    requested_ip: Option<Ipv4Addr>,
    /// Option 54.
    server_id: Option<Ipv4Addr>,
    /// Option 61, as sent.
    client_id: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// A BOOTREQUEST over Ethernet with the DHCP cookie and a message type.
    /// An option that runs past the end of the message makes it malformed;
    /// of an option given twice, the first counts.
    fn parse(message: &'a [u8]) -> Option<Request<'a>> {
        let packet = DhcpPacket::new_checked(message).ok()?;
        let wellformed = packet.opcode() == DhcpOpCode::Request
            && packet.hardware_type() == ArpHardware::Ethernet
            && packet.hardware_len() == 6
            && packet.magic_number() == MAGIC_COOKIE;
        if !wellformed {
            return None;
        }
        let mut message_type = None;
        let mut requested_ip = None;
        let mut server_id = None;
        let mut client_id = None;
        let mut rest = message.get(OPTIONS_START..)?;
        loop {
            match rest {
                [] | [OPT_END, ..] => break,
                [OPT_PAD, tail @ ..] => rest = tail,
                [kind, len, tail @ ..] => {
                    let (data, tail) = tail.split_at_checked(usize::from(*len))?;
                    match (*kind, data) {
                        (OPT_MESSAGE_TYPE, &[t]) => {
                            message_type = message_type.or(Some(DhcpMessageType::from(t)))
                        }
                        (OPT_REQUESTED_IP, &[a, b, c, d]) => {
                            requested_ip = requested_ip.or(Some(Ipv4Addr::new(a, b, c, d)))
                        }
                        (OPT_SERVER_ID, &[a, b, c, d]) => {
                            server_id = server_id.or(Some(Ipv4Addr::new(a, b, c, d)))
                        }
                        (OPT_CLIENT_ID, id) if !id.is_empty() => client_id = client_id.or(Some(id)),
                        _ => {}
                    }
                    rest = tail;
                }
                // A kind with no length.
                [_] => return None,
            }
        }
        Some(Request {
            message_type: message_type?,
            xid: packet.transaction_id(),
            broadcast: packet.flags().contains(DhcpFlags::BROADCAST),
            ciaddr: packet.client_ip(),
            giaddr: packet.relay_agent_ip(),
            chaddr: packet.client_hardware_address(),
            requested_ip,
            server_id,
            client_id,
        })
    }

    /// The client's identifier, to send back.
    fn client_id_option(&self) -> Option<DhcpOption<'a>> {
        self.client_id.map(|data| DhcpOption {
            kind: OPT_CLIENT_ID,
            data,
        })
    }
}

/// An OFFER or an ACK of the static lease.
fn lease(
    cfg: &NetConfig,
    request: &Request,
    message_type: DhcpMessageType,
) -> Option<(Vec<u8>, NetDhcp)> {
    let ack = message_type == DhcpMessageType::Ack;
    let mut options = vec![DhcpOption {
        kind: OPT_HOST_NAME,
        data: cfg.hostname.as_bytes(),
    }];
    options.extend(request.client_id_option());
    let mut repr = DhcpRepr {
        message_type,
        transaction_id: request.xid,
        secs: 0,
        client_hardware_address: request.chaddr,
        // An ACK repeats the address a renewing client gave; an OFFER has
        // none to repeat.
        client_ip: if ack {
            request.ciaddr
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        your_ip: cfg.guest_ip,
        server_ip: cfg.gateway,
        router: Some(cfg.gateway),
        subnet_mask: Some(cfg.netmask_addr()),
        relay_agent_ip: request.giaddr,
        broadcast: request.broadcast,
        requested_ip: None,
        // Sent back raw, in `options`.
        client_identifier: None,
        server_identifier: Some(cfg.gateway),
        parameter_request_list: None,
        dns_servers: Some(Default::default()),
        max_size: None,
        lease_duration: Some(LEASE_SECS),
        // smoltcp does not write these; the client takes the RFC 2131
        // defaults, half and seven eighths of the lease.
        renew_duration: None,
        rebind_duration: None,
        additional_options: &options,
    };
    repr.dns_servers.as_mut()?.push(cfg.gateway).ok()?;
    // A client with an address (necessarily the guest's, or it would have
    // been refused) is unicast there, whatever its broadcast flag says.
    let unicast = !request.broadcast || request.ciaddr == cfg.guest_ip;
    let (eth_dst, ip_dst) = if unicast {
        (request.chaddr, cfg.guest_ip)
    } else {
        (EthernetAddress::BROADCAST, Ipv4Addr::BROADCAST)
    };
    let frame = build(cfg, &repr, eth_dst, ip_dst)?;
    let op = if ack { "ack" } else { "offer" };
    Some((
        frame,
        NetDhcp {
            op: op.to_owned(),
            yiaddr: cfg.guest_ip,
        },
    ))
}

/// A NAK: the address asked for is not the client's. It carries only the
/// message type, the server identifier, and the client's identifier, and
/// is broadcast, as RFC 2131 has it for a client with no relay agent.
fn nak(cfg: &NetConfig, request: &Request) -> Option<(Vec<u8>, NetDhcp)> {
    let options: Vec<DhcpOption> = request.client_id_option().into_iter().collect();
    let repr = DhcpRepr {
        message_type: DhcpMessageType::Nak,
        transaction_id: request.xid,
        secs: 0,
        client_hardware_address: request.chaddr,
        client_ip: Ipv4Addr::UNSPECIFIED,
        your_ip: Ipv4Addr::UNSPECIFIED,
        server_ip: Ipv4Addr::UNSPECIFIED,
        router: None,
        subnet_mask: None,
        relay_agent_ip: request.giaddr,
        broadcast: request.broadcast,
        requested_ip: None,
        client_identifier: None,
        server_identifier: Some(cfg.gateway),
        parameter_request_list: None,
        dns_servers: None,
        max_size: None,
        lease_duration: None,
        renew_duration: None,
        rebind_duration: None,
        additional_options: &options,
    };
    let frame = build(cfg, &repr, EthernetAddress::BROADCAST, Ipv4Addr::BROADCAST)?;
    Some((
        frame,
        NetDhcp {
            op: "nak".to_owned(),
            yiaddr: Ipv4Addr::UNSPECIFIED,
        },
    ))
}

/// `repr` from the gateway's port 67 to `ip_dst` port 68, padded to the
/// BOOTP minimum, with both checksums filled in.
fn build(
    cfg: &NetConfig,
    repr: &DhcpRepr,
    eth_dst: EthernetAddress,
    ip_dst: Ipv4Addr,
) -> Option<Vec<u8>> {
    let ports = UdpRepr {
        src_port: DHCP_SERVER_PORT,
        dst_port: DHCP_CLIENT_PORT,
    };
    let message_len = repr.buffer_len().max(MIN_MESSAGE_LEN);
    let ip = Ipv4Repr {
        src_addr: cfg.gateway,
        dst_addr: ip_dst,
        next_header: IpProtocol::Udp,
        payload_len: ports.header_len() + message_len,
        hop_limit: TTL,
    };
    let mut emitted = Ok(());
    let frame = ipv4_frame(EthernetAddress(cfg.gateway_mac), eth_dst, &ip, |datagram| {
        ports.emit(
            &mut UdpPacket::new_unchecked(datagram),
            &cfg.gateway.into(),
            &ip_dst.into(),
            message_len,
            // Bytes after the end option stay zero: padding.
            |message| emitted = repr.emit(&mut DhcpPacket::new_unchecked(message)),
            &ChecksumCapabilities::default(),
        )
    });
    emitted.ok()?;
    Some(frame)
}
