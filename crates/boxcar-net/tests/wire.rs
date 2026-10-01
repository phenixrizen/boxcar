// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The wire layer from the guest's side of the link: frames built with
//! `smoltcp::wire` go in through `push_guest_frame`, the answers come out of
//! `pop_host_frame`, and the audit log says what was dropped and leased.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use boxcar_audit::{LogReader, WriterConfig, WriterHandle};
use boxcar_net::frame::{classify, Dispatch};
use boxcar_net::stack::QUEUE_CAP;
use boxcar_net::{NetConfig, NetStack, Policy};
use boxcar_proto::{NetDhcp, NetDrop, Payload, SessionId, Source};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, DhcpFlags, DhcpMessageType, DhcpOpCode, DhcpOption,
    DhcpPacket, DhcpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr,
    Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber, UdpPacket, UdpRepr, DHCP_CLIENT_PORT, DHCP_SERVER_PORT,
};
use tempfile::TempDir;

const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const GUEST_MAC: EthernetAddress = EthernetAddress([0x02, 0x62, 0x6f, 0x78, 0x00, 0x01]);
const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x02, 0x62, 0x6f, 0x78, 0x00, 0x02]);
const XID: u32 = 0x3903_f326;

/// A stack with the default addressing, logging into a fresh session.
struct Harness {
    stack: NetStack,
    writer: WriterHandle,
    _dir: TempDir,
}

fn harness() -> Harness {
    let dir = TempDir::new().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let policy = Arc::new(ArcSwap::from_pointee(Policy::allow_all()));
    let stack = NetStack::new(NetConfig::default(), sink, policy).unwrap();
    Harness {
        stack,
        writer,
        _dir: dir,
    }
}

impl Harness {
    /// Everything the stack sent the guest so far.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| self.stack.pop_host_frame()).collect()
    }

    /// Closes the log and returns the payloads the stack recorded, after
    /// checking that each came from the network stack.
    fn events(self) -> Vec<Payload> {
        let session = self.writer.session_dir().to_owned();
        drop(self.stack);
        self.writer.close().unwrap();
        LogReader::open(&session)
            .unwrap()
            .records()
            .map(|r| r.unwrap())
            .filter(|r| r.kind != "checkpoint")
            .map(|r| {
                assert_eq!(r.src, Source::Net, "{}", r.kind);
                Payload::from_record(&r).unwrap()
            })
            .collect()
    }
}

fn drops(events: &[Payload]) -> Vec<NetDrop> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetDrop(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

fn ethernet(
    src: EthernetAddress,
    dst: EthernetAddress,
    ethertype: EthernetProtocol,
    payload: &[u8],
) -> Vec<u8> {
    let repr = EthernetRepr {
        src_addr: src,
        dst_addr: dst,
        ethertype,
    };
    let mut buf = vec![0; repr.buffer_len() + payload.len()];
    let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
    repr.emit(&mut frame);
    frame.payload_mut().copy_from_slice(payload);
    buf
}

/// An IPv4 packet from the guest's MAC to `eth_dst`, its transport filled
/// in by `fill` (which gets the IP addresses for checksums).
fn ipv4(
    eth_dst: EthernetAddress,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpProtocol,
    payload_len: usize,
    fill: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: protocol,
        payload_len,
        hop_limit: 64,
    };
    let mut packet = vec![0; ip.buffer_len() + payload_len];
    let mut view = Ipv4Packet::new_unchecked(&mut packet[..]);
    ip.emit(&mut view, &ChecksumCapabilities::default());
    fill(view.payload_mut());
    ethernet(GUEST_MAC, eth_dst, EthernetProtocol::Ipv4, &packet)
}

fn udp(eth_dst: EthernetAddress, src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let repr = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    ipv4(
        eth_dst,
        *src.ip(),
        *dst.ip(),
        IpProtocol::Udp,
        repr.header_len() + payload.len(),
        |buf| {
            repr.emit(
                &mut UdpPacket::new_unchecked(buf),
                &(*src.ip()).into(),
                &(*dst.ip()).into(),
                payload.len(),
                |p| p.copy_from_slice(payload),
                &ChecksumCapabilities::default(),
            )
        },
    )
}

/// The guest's DHCP client identifier in its Ethernet form: hardware type
/// 1, then the MAC.
const CLIENT_ID: [u8; 7] = [1, 0x02, 0x62, 0x6f, 0x78, 0x00, 0x01];

/// A DHCP client message, by the fields the server reads.
struct Client<'a> {
    message_type: DhcpMessageType,
    broadcast: bool,
    ciaddr: Ipv4Addr,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    client_id: &'a [u8],
}

impl Client<'static> {
    /// A DISCOVER from a client with no address.
    fn discover() -> Self {
        Client {
            message_type: DhcpMessageType::Discover,
            broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested_ip: None,
            server_id: None,
            client_id: &CLIENT_ID,
        }
    }

    /// A REQUEST taking the gateway's offer of the guest's address.
    fn request() -> Self {
        Client {
            message_type: DhcpMessageType::Request,
            requested_ip: Some(GUEST),
            server_id: Some(GATEWAY),
            ..Client::discover()
        }
    }
}

/// The DHCP message `client` describes. The client identifier goes in raw,
/// whatever its form.
fn dhcp_payload(client: &Client) -> Vec<u8> {
    let client_id = [DhcpOption {
        kind: 61,
        data: client.client_id,
    }];
    let repr = DhcpRepr {
        message_type: client.message_type,
        transaction_id: XID,
        secs: 0,
        client_hardware_address: GUEST_MAC,
        client_ip: client.ciaddr,
        your_ip: Ipv4Addr::UNSPECIFIED,
        server_ip: Ipv4Addr::UNSPECIFIED,
        router: None,
        subnet_mask: None,
        relay_agent_ip: Ipv4Addr::UNSPECIFIED,
        broadcast: client.broadcast,
        requested_ip: client.requested_ip,
        client_identifier: None,
        server_identifier: client.server_id,
        parameter_request_list: Some(&[1, 3, 6, 12, 15, 28, 51][..]),
        dns_servers: None,
        max_size: Some(1500),
        lease_duration: None,
        renew_duration: None,
        rebind_duration: None,
        additional_options: if client.client_id.is_empty() {
            &[]
        } else {
            &client_id
        },
    };
    let mut payload = vec![0; repr.buffer_len()];
    repr.emit(&mut DhcpPacket::new_unchecked(&mut payload[..]))
        .unwrap();
    payload
}

/// A DHCP message sent as a client sends it: from 0.0.0.0 by broadcast,
/// or from `ciaddr` to the gateway once it has an address.
fn dhcp_frame(ciaddr: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let (eth_dst, dst) = if ciaddr.is_unspecified() {
        (EthernetAddress::BROADCAST, Ipv4Addr::BROADCAST)
    } else {
        (GATEWAY_MAC, GATEWAY)
    };
    udp(
        eth_dst,
        SocketAddrV4::new(ciaddr, DHCP_CLIENT_PORT),
        SocketAddrV4::new(dst, DHCP_SERVER_PORT),
        payload,
    )
}

fn dhcp_from(client: &Client) -> Vec<u8> {
    dhcp_frame(client.ciaddr, &dhcp_payload(client))
}

/// A DISCOVER, or a REQUEST taking the gateway's offer.
fn dhcp(message_type: DhcpMessageType, broadcast: bool) -> Vec<u8> {
    let client = match message_type {
        DhcpMessageType::Request => Client::request(),
        _ => Client::discover(),
    };
    dhcp_from(&Client {
        message_type,
        broadcast,
        ..client
    })
}

/// What a DHCP reply said, read from the frame with smoltcp's option
/// iterator (not the server's parser), after checking both checksums.
#[derive(Debug)]
struct Lease {
    eth_src: EthernetAddress,
    eth_dst: EthernetAddress,
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    ip_total_len: u16,
    ports: (u16, u16),
    udp_len: u16,
    op: DhcpOpCode,
    transaction_id: u32,
    client_hardware_address: EthernetAddress,
    client_ip: Ipv4Addr,
    your_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    relay_agent_ip: Ipv4Addr,
    broadcast: bool,
    options: Vec<(u8, Vec<u8>)>,
}

impl Lease {
    fn option(&self, kind: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, data)| &data[..])
    }

    fn message_type(&self) -> DhcpMessageType {
        match self.option(53) {
            Some(&[t]) => DhcpMessageType::from(t),
            other => panic!("message type option: {other:?}"),
        }
    }

    fn kinds(&self) -> Vec<u8> {
        let mut kinds: Vec<u8> = self.options.iter().map(|(k, _)| *k).collect();
        kinds.sort();
        kinds
    }
}

fn lease(frame: &[u8]) -> Lease {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
    let ip_packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    // Parsing checks the header checksum.
    let ip = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::default()).unwrap();
    assert_eq!(ip.next_header, IpProtocol::Udp);
    let udp = UdpPacket::new_checked(ip_packet.payload()).unwrap();
    // A UDP checksum of zero would mean none was computed: ours always is.
    assert_ne!(udp.checksum(), 0, "the UDP checksum is computed");
    assert!(udp.verify_checksum(&ip.src_addr.into(), &ip.dst_addr.into()));
    let packet = DhcpPacket::new_checked(udp.payload()).unwrap();
    assert_eq!(packet.magic_number(), 0x6382_5363);
    Lease {
        eth_src: eth.src_addr(),
        eth_dst: eth.dst_addr(),
        ip_src: ip.src_addr,
        ip_dst: ip.dst_addr,
        ip_total_len: ip_packet.total_len(),
        ports: (udp.src_port(), udp.dst_port()),
        udp_len: udp.len(),
        op: packet.opcode(),
        transaction_id: packet.transaction_id(),
        client_hardware_address: packet.client_hardware_address(),
        client_ip: packet.client_ip(),
        your_ip: packet.your_ip(),
        server_ip: packet.server_ip(),
        relay_agent_ip: packet.relay_agent_ip(),
        broadcast: packet.flags().contains(DhcpFlags::BROADCAST),
        options: packet
            .options()
            .map(|o| (o.kind, o.data.to_vec()))
            .collect(),
    }
}

/// What every reply carries: from the gateway's port 67 to port 68, a
/// BOOTREPLY for the client's transaction and MAC, no relay agent, the
/// server identifier, and the client identifier back unaltered.
fn assert_reply_header(lease: &Lease) {
    assert_eq!(lease.eth_src, GATEWAY_MAC);
    assert_eq!(lease.ip_src, GATEWAY);
    assert_eq!(lease.ports, (DHCP_SERVER_PORT, DHCP_CLIENT_PORT));
    assert_eq!(lease.op, DhcpOpCode::Reply);
    assert_eq!(lease.transaction_id, XID);
    assert_eq!(lease.client_hardware_address, GUEST_MAC);
    assert_eq!(lease.relay_agent_ip, Ipv4Addr::UNSPECIFIED);
    assert_eq!(lease.option(54), Some(&GATEWAY.octets()[..]));
    assert_eq!(lease.option(61), Some(&CLIENT_ID[..]));
    // Padded to the 300-byte BOOTP minimum.
    assert_eq!(lease.udp_len, 8 + 300);
    assert_eq!(lease.ip_total_len, 20 + 8 + 300);
}

/// The parts of the static lease that every OFFER and ACK carries.
fn assert_static_lease(lease: &Lease) {
    assert_reply_header(lease);
    assert_eq!(lease.your_ip, GUEST);
    assert_eq!(lease.server_ip, GATEWAY);
    assert_eq!(lease.option(3), Some(&GATEWAY.octets()[..]), "router");
    assert_eq!(lease.option(1), Some(&[255, 255, 255, 0][..]), "mask");
    assert_eq!(lease.option(6), Some(&GATEWAY.octets()[..]), "DNS");
    assert_eq!(
        lease.option(51),
        Some(&86_400u32.to_be_bytes()[..]),
        "lease"
    );
    assert_eq!(lease.option(12), Some(&b"boxcar"[..]), "host name");
}

fn dhcp_records(events: &[Payload]) -> Vec<NetDhcp> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetDhcp(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

fn arp_request(sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    arp_request_from(GUEST_MAC, sender, target)
}

/// An ARP request with `mac` as both the Ethernet source and the sender's
/// hardware address.
fn arp_request_from(mac: EthernetAddress, sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: mac,
        source_protocol_addr: sender,
        target_hardware_addr: EthernetAddress([0; 6]),
        target_protocol_addr: target,
    };
    let mut payload = vec![0; repr.buffer_len()];
    repr.emit(&mut ArpPacket::new_unchecked(&mut payload[..]));
    ethernet(
        mac,
        EthernetAddress::BROADCAST,
        EthernetProtocol::Arp,
        &payload,
    )
}

fn icmp_echo(dst: Ipv4Addr, ident: u16, seq_no: u16, data: &[u8]) -> Vec<u8> {
    let repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data,
    };
    ipv4(
        GATEWAY_MAC,
        GUEST,
        dst,
        IpProtocol::Icmp,
        repr.buffer_len(),
        |buf| {
            repr.emit(
                &mut Icmpv4Packet::new_unchecked(buf),
                &ChecksumCapabilities::default(),
            )
        },
    )
}

fn tcp_syn(src: SocketAddrV4, dst: SocketAddrV4, seq: i32) -> Vec<u8> {
    let repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(seq),
        ack_number: None,
        window_len: 64240,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    ipv4(
        GATEWAY_MAC,
        *src.ip(),
        *dst.ip(),
        IpProtocol::Tcp,
        repr.buffer_len(),
        |buf| {
            repr.emit(
                &mut TcpPacket::new_unchecked(buf),
                &(*src.ip()).into(),
                &(*dst.ip()).into(),
                &ChecksumCapabilities::default(),
            )
        },
    )
}

/// An Ethernet frame carrying an IPv6 header (a neighbor solicitation's
/// worth of bytes; nothing past the ethertype is looked at).
fn ipv6_frame() -> Vec<u8> {
    let mut packet = vec![0u8; 64];
    packet[0] = 0x60;
    packet[6] = 58; // next header: ICMPv6
    packet[7] = 255;
    ethernet(
        GUEST_MAC,
        EthernetAddress([0x33, 0x33, 0xff, 0x00, 0x00, 0x01]),
        EthernetProtocol::Ipv6,
        &packet,
    )
}

#[test]
fn dhcp_discover_gets_an_offer_for_the_guest_ip() {
    let mut h = harness();
    h.stack
        .push_guest_frame(&dhcp(DhcpMessageType::Discover, false));
    let replies = h.drain();
    assert_eq!(replies.len(), 1, "one OFFER");
    let offer = lease(&replies[0]);
    assert_eq!(offer.message_type(), DhcpMessageType::Offer);
    assert_static_lease(&offer);
    assert_eq!(offer.client_ip, Ipv4Addr::UNSPECIFIED);
    // No broadcast flag: the reply goes straight to the client.
    assert!(!offer.broadcast);
    assert_eq!(offer.eth_dst, GUEST_MAC);
    assert_eq!(offer.ip_dst, GUEST);

    assert_eq!(
        h.events(),
        [Payload::NetDhcp(NetDhcp {
            op: "offer".into(),
            yiaddr: GUEST,
        })]
    );
}

#[test]
fn dhcp_request_gets_an_ack() {
    let mut h = harness();
    h.stack
        .push_guest_frame(&dhcp(DhcpMessageType::Request, true));
    let replies = h.drain();
    assert_eq!(replies.len(), 1, "one ACK");
    let ack = lease(&replies[0]);
    assert_eq!(ack.message_type(), DhcpMessageType::Ack);
    assert_static_lease(&ack);
    // The client asked for a broadcast reply and gets one.
    assert!(ack.broadcast);
    assert_eq!(ack.eth_dst, EthernetAddress::BROADCAST);
    assert_eq!(ack.ip_dst, Ipv4Addr::BROADCAST);

    assert_eq!(
        h.events(),
        [Payload::NetDhcp(NetDhcp {
            op: "ack".into(),
            yiaddr: GUEST,
        })]
    );
}

/// A renewing client has an address (`ciaddr`), and its ACK goes there by
/// unicast even when its broadcast flag is set (RFC 2131 §4.1).
#[test]
fn a_renewing_client_gets_its_ack_unicast_to_its_address() {
    let mut h = harness();
    h.stack.push_guest_frame(&dhcp_from(&Client {
        message_type: DhcpMessageType::Request,
        broadcast: true,
        ciaddr: GUEST,
        ..Client::discover()
    }));
    let replies = h.drain();
    assert_eq!(replies.len(), 1, "one ACK");
    let ack = lease(&replies[0]);
    assert_eq!(ack.message_type(), DhcpMessageType::Ack);
    assert_static_lease(&ack);
    assert_eq!(ack.client_ip, GUEST, "ciaddr repeated");
    assert_eq!((ack.eth_dst, ack.ip_dst), (GUEST_MAC, GUEST));
    assert_eq!(
        dhcp_records(&h.events()),
        [NetDhcp {
            op: "ack".into(),
            yiaddr: GUEST,
        }]
    );
}

/// A client asking for an address that is not the guest's, rebooting with
/// an old lease (option 50) or renewing one (`ciaddr`), is refused with a
/// NAK, broadcast, carrying nothing but the message type, the server
/// identifier and the client identifier (RFC 2131 §4.3.2).
#[test]
fn a_request_for_another_address_gets_a_broadcast_nak() {
    let mut h = harness();
    let elsewhere = Ipv4Addr::new(10, 0, 2, 99);
    let rebooting = Client {
        message_type: DhcpMessageType::Request,
        requested_ip: Some(elsewhere),
        ..Client::discover()
    };
    let renewing = Client {
        message_type: DhcpMessageType::Request,
        ciaddr: elsewhere,
        ..Client::discover()
    };
    for client in [rebooting, renewing] {
        h.stack.push_guest_frame(&dhcp_from(&client));
        let replies = h.drain();
        assert_eq!(replies.len(), 1, "one NAK");
        let nak = lease(&replies[0]);
        assert_eq!(nak.message_type(), DhcpMessageType::Nak);
        assert_reply_header(&nak);
        assert_eq!(nak.kinds(), [53, 54, 61], "no lease options");
        assert_eq!(
            (nak.client_ip, nak.your_ip, nak.server_ip),
            (
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED
            )
        );
        assert!(!nak.broadcast, "the client's flags, echoed");
        assert_eq!(
            (nak.eth_dst, nak.ip_dst),
            (EthernetAddress::BROADCAST, Ipv4Addr::BROADCAST)
        );
    }
    let nak = NetDhcp {
        op: "nak".into(),
        yiaddr: Ipv4Addr::UNSPECIFIED,
    };
    assert_eq!(
        h.events(),
        [Payload::NetDhcp(nak.clone()), Payload::NetDhcp(nak)]
    );
}

/// A REQUEST naming another server took that server's offer: the gateway
/// says nothing, records nothing, and counts nothing.
#[test]
fn a_request_choosing_another_server_is_not_answered() {
    let mut h = harness();
    h.stack.push_guest_frame(&dhcp_from(&Client {
        server_id: Some(Ipv4Addr::new(192, 168, 1, 1)),
        ..Client::request()
    }));
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());
    h.stack.shutdown();
    assert!(h.events().is_empty());
}

/// The client identifier comes back unaltered whatever its form (RFC
/// 6842): an RFC 4361 IAID and DUID as systemd-networkd sends it, a short
/// one, and a 7-byte one that is not an Ethernet address.
#[test]
fn every_client_identifier_is_echoed_unaltered() {
    let duid: &[u8] = &[
        255, // RFC 4361: IAID and DUID follow
        0x8c, 0x2d, 0x5e, 0x11, // IAID
        0x00, 0x02, 0x00, 0x00, 0xab, 0x11, // DUID-EN, enterprise 43793
        0x5c, 0x6a, 0x2b, 0x31, 0x9e, 0x0e, 0x3c, 0x77,
    ];
    let mut h = harness();
    for id in [duid, &[0, 0xbe, 0xef], &[0, 1, 2, 3, 4, 5, 6]] {
        for (client, want) in [
            (Client::discover(), DhcpMessageType::Offer),
            (Client::request(), DhcpMessageType::Ack),
        ] {
            h.stack.push_guest_frame(&dhcp_from(&Client {
                client_id: id,
                ..client
            }));
            let replies = h.drain();
            assert_eq!(replies.len(), 1, "{want:?} for {id:?}");
            let reply = lease(&replies[0]);
            assert_eq!(reply.message_type(), want);
            assert_eq!(reply.option(61), Some(id), "{want:?}");
            assert!(reply.udp_len >= 8 + 300);
        }
    }
    let records = dhcp_records(&h.events());
    assert_eq!(records.len(), 6, "{records:?}");
}

/// What the server does not answer, malformed or not, is a `dhcp` drop:
/// no message type, options that run past the end, a BOOTREPLY, and the
/// messages a server answers nothing to.
#[test]
fn unanswerable_dhcp_is_a_dhcp_drop() {
    let mut h = harness();
    let discover = dhcp_payload(&Client::discover());
    assert_eq!(discover[240..243], [53, 1, 1], "option 53 comes first");

    let mut untyped = discover.clone();
    untyped[240..243].fill(0); // three pads
    let mut truncated = discover[..243].to_vec();
    truncated.extend_from_slice(&[61, 7, 1, 2]);
    let mut reply = discover.clone();
    reply[0] = 2; // BOOTREPLY
    let mut payloads = vec![untyped, truncated, reply];
    for message_type in [
        DhcpMessageType::Release,
        DhcpMessageType::Decline,
        DhcpMessageType::Inform,
    ] {
        payloads.push(dhcp_payload(&Client {
            message_type,
            ..Client::discover()
        }));
    }
    let sent = payloads.len() as u64;
    for payload in payloads {
        h.stack
            .push_guest_frame(&dhcp_frame(Ipv4Addr::UNSPECIFIED, &payload));
        assert!(h.drain().is_empty());
    }
    h.stack.shutdown();
    let events = h.events();
    assert!(dhcp_records(&events).is_empty());
    let drops = drops(&events);
    assert!(drops.iter().all(|d| d.reason == "dhcp"), "{drops:?}");
    assert_eq!(drops.iter().map(|d| d.count).sum::<u64>(), sent);
}

#[test]
fn arp_for_the_gateway_and_for_any_other_host_is_answered_with_the_gateway_mac() {
    let mut h = harness();
    for target in [
        GATEWAY,
        Ipv4Addr::new(10, 0, 2, 77),
        Ipv4Addr::new(10, 0, 2, 1),
        Ipv4Addr::new(10, 0, 2, 254),
    ] {
        h.stack.push_guest_frame(&arp_request(GUEST, target));
        let replies = h.drain();
        assert_eq!(replies.len(), 1, "who-has {target}");
        let eth = EthernetFrame::new_checked(&replies[0][..]).unwrap();
        assert_eq!(eth.src_addr(), GATEWAY_MAC);
        assert_eq!(eth.dst_addr(), GUEST_MAC);
        assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
        let arp = ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).unwrap()).unwrap();
        assert_eq!(
            arp,
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: GATEWAY_MAC,
                source_protocol_addr: target,
                target_hardware_addr: GUEST_MAC,
                target_protocol_addr: GUEST,
            },
            "who-has {target}"
        );
    }

    // The guest's own address (a duplicate-address probe from 0.0.0.0, or a
    // gratuitous announcement) is never claimed, nor is anything off the /24.
    for (sender, target) in [
        (Ipv4Addr::UNSPECIFIED, GUEST),
        (GUEST, GUEST),
        (GUEST, Ipv4Addr::new(10, 0, 3, 1)),
        (GUEST, Ipv4Addr::new(8, 8, 8, 8)),
    ] {
        h.stack.push_guest_frame(&arp_request(sender, target));
        assert!(h.drain().is_empty(), "{sender} asking who-has {target}");
    }

    // smoltcp saw the guest's ARP too, to learn its MAC, but answers none of
    // it a second time.
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());
    assert!(h.events().is_empty());
}

#[test]
fn icmp_echo_to_the_gateway_is_answered_and_to_others_is_dropped_with_an_event() {
    let mut h = harness();
    let data = b"boxcar ping payload 0123456789";
    h.stack
        .push_guest_frame(&icmp_echo(GATEWAY, 0x1234, 7, data));
    let replies = h.drain();
    assert_eq!(replies.len(), 1, "one echo reply");
    let eth = EthernetFrame::new_checked(&replies[0][..]).unwrap();
    assert_eq!(eth.src_addr(), GATEWAY_MAC);
    assert_eq!(eth.dst_addr(), GUEST_MAC);
    let ip_packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let ip = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::default()).unwrap();
    assert_eq!((ip.src_addr, ip.dst_addr), (GATEWAY, GUEST));
    assert_eq!(ip.next_header, IpProtocol::Icmp);
    let icmp_packet = Icmpv4Packet::new_checked(ip_packet.payload()).unwrap();
    assert_eq!(
        Icmpv4Repr::parse(&icmp_packet, &ChecksumCapabilities::default()).unwrap(),
        Icmpv4Repr::EchoReply {
            ident: 0x1234,
            seq_no: 7,
            data,
        }
    );

    // Anywhere else: no reply from the gateway, and none from smoltcp,
    // which never sees ICMP.
    h.stack
        .push_guest_frame(&icmp_echo(Ipv4Addr::new(8, 8, 8, 8), 0x1234, 8, data));
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());

    assert_eq!(
        h.events(),
        [Payload::NetDrop(NetDrop {
            reason: "icmp".into(),
            count: 1,
        })]
    );
}

#[test]
fn ipv6_frames_are_dropped_with_an_event() {
    let mut h = harness();
    h.stack.push_guest_frame(&ipv6_frame());
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());
    assert_eq!(
        h.events(),
        [Payload::NetDrop(NetDrop {
            reason: "ipv6".into(),
            count: 1,
        })]
    );
}

/// DNS and the rest of UDP have no handler yet; what nothing understands is
/// `other`. Each is dropped under its own reason.
#[test]
fn dns_other_udp_and_unknown_frames_are_dropped_under_their_own_reasons() {
    let mut h = harness();
    let guest = SocketAddrV4::new(GUEST, 40000);
    h.stack.push_guest_frame(&udp(
        GATEWAY_MAC,
        guest,
        SocketAddrV4::new(GATEWAY, 53),
        b"\x12\x34query",
    ));
    // DNS to anyone but the gateway is ordinary UDP.
    h.stack.push_guest_frame(&udp(
        GATEWAY_MAC,
        guest,
        SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
        b"\x12\x34query",
    ));
    // An LLDP frame.
    h.stack.push_guest_frame(&ethernet(
        GUEST_MAC,
        EthernetAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]),
        EthernetProtocol::Unknown(0x88cc),
        &[0; 46],
    ));
    // Too short to be Ethernet.
    h.stack.push_guest_frame(&[0x02, 0x62]);
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());

    let mut got: Vec<(String, u64)> = drops(&h.events())
        .into_iter()
        .map(|d| (d.reason, d.count))
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("dns_unimplemented".to_owned(), 1),
            ("other".to_owned(), 1),
            ("udp_unimplemented".to_owned(), 1),
        ]
    );
}

/// The first drop of a reason is recorded at once; the rest within its
/// second are counted and recorded together when the second is up, apart
/// from other reasons'.
#[test]
fn drops_are_coalesced_per_reason() {
    let mut h = harness();
    for _ in 0..5 {
        h.stack.push_guest_frame(&ipv6_frame());
    }
    for _ in 0..3 {
        h.stack
            .push_guest_frame(&icmp_echo(Ipv4Addr::new(8, 8, 8, 8), 1, 1, b""));
    }
    let held = h.stack.poll(Instant::now());
    assert!(
        held.next_deadline.is_some(),
        "held counts ask for a poll when they fall due"
    );
    let flushed = h.stack.poll(Instant::now() + Duration::from_secs(2));
    assert_eq!(flushed.next_deadline, None, "nothing is held any more");

    let events = drops(&h.events());
    for (reason, total) in [("ipv6", 5), ("icmp", 3)] {
        let counts: Vec<u64> = events
            .iter()
            .filter(|d| d.reason == reason)
            .map(|d| d.count)
            .collect();
        assert_eq!(
            counts.first(),
            Some(&1),
            "{reason}: the first is recorded at once"
        );
        assert_eq!(counts.iter().sum::<u64>(), total, "{reason}: {counts:?}");
        assert!(
            counts.len() < total as usize,
            "{reason}: coalesced, {counts:?}"
        );
    }
}

/// TCP goes to smoltcp, which takes any destination (any-IP with a default
/// route through itself). It has no sockets yet, so it resets the SYN. That
/// it answers at once, rather than asking who has the guest's address,
/// shows it learned the guest's MAC from an ARP the guest sent for some
/// other address.
#[test]
fn a_tcp_syn_reaches_smoltcp_which_knows_the_guest_mac_from_its_arp() {
    let mut h = harness();
    h.stack
        .push_guest_frame(&arp_request(GUEST, Ipv4Addr::new(10, 0, 2, 77)));
    assert_eq!(h.drain().len(), 1, "the proxy-ARP reply");

    let guest = SocketAddrV4::new(GUEST, 40000);
    let remote = SocketAddrV4::new(Ipv4Addr::new(93, 184, 215, 14), 80);
    h.stack.push_guest_frame(&tcp_syn(guest, remote, 1000));
    h.stack.poll(Instant::now());
    let replies = h.drain();
    assert_eq!(replies.len(), 1, "one RST");

    let eth = EthernetFrame::new_checked(&replies[0][..]).unwrap();
    assert_eq!(
        eth.ethertype(),
        EthernetProtocol::Ipv4,
        "not an ARP request"
    );
    assert_eq!((eth.src_addr(), eth.dst_addr()), (GATEWAY_MAC, GUEST_MAC));
    let ip_packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let ip = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::default()).unwrap();
    assert_eq!((ip.src_addr, ip.dst_addr), (*remote.ip(), GUEST));
    let tcp_packet = TcpPacket::new_checked(ip_packet.payload()).unwrap();
    let tcp = TcpRepr::parse(
        &tcp_packet,
        &ip.src_addr.into(),
        &ip.dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!((tcp.src_port, tcp.dst_port), (80, 40000));
    assert_eq!(tcp.control, TcpControl::Rst);
    assert_eq!(tcp.ack_number, Some(TcpSeqNumber(1001)));
    assert!(h.events().is_empty());
}

/// smoltcp learns only the guest's own binding. ARP from more made-up
/// senders than its neighbor cache holds does not evict the guest, and a
/// made-up MAC for the guest's address does not redirect its replies: a SYN
/// afterwards is reset at once, to the guest's MAC.
#[test]
fn spoofed_arp_neither_evicts_nor_poisons_the_guest_in_smoltcp() {
    let mut h = harness();
    h.stack.push_guest_frame(&arp_request(GUEST, GATEWAY));
    for i in 100..110u8 {
        h.stack.push_guest_frame(&arp_request_from(
            EthernetAddress([0x02, 0, 0, 0, 0, i]),
            Ipv4Addr::new(10, 0, 2, i),
            GATEWAY,
        ));
    }
    h.stack.push_guest_frame(&arp_request_from(
        EthernetAddress([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        GUEST,
        GATEWAY,
    ));
    assert_eq!(h.drain().len(), 12, "each gets its proxy-ARP reply");
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());

    let guest = SocketAddrV4::new(GUEST, 40000);
    let remote = SocketAddrV4::new(Ipv4Addr::new(93, 184, 215, 14), 80);
    h.stack.push_guest_frame(&tcp_syn(guest, remote, 1000));
    h.stack.poll(Instant::now());
    let replies = h.drain();
    assert_eq!(replies.len(), 1, "one RST");
    let eth = EthernetFrame::new_checked(&replies[0][..]).unwrap();
    assert_eq!(
        eth.ethertype(),
        EthernetProtocol::Ipv4,
        "not an ARP request"
    );
    assert_eq!(eth.dst_addr(), GUEST_MAC);
}

/// The TCP destination port of a reset smoltcp sent the guest.
fn reset_port(frame: &[u8]) -> u16 {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.rst());
    tcp.dst_port()
}

/// A guest that sends and never takes frames cannot grow either queue past
/// its cap. smoltcp answers each SYN with a reset until the guest's queue
/// is full, then takes no more; SYNs wait for it until theirs is full too,
/// and after that are dropped as `queue_full`. Nothing that waited is lost:
/// smoltcp takes it once the guest drains its queue.
#[test]
fn queues_are_capped_and_smoltcp_waits_for_the_guest() {
    let mut h = harness();
    h.stack.push_guest_frame(&arp_request(GUEST, GATEWAY));
    assert_eq!(h.drain().len(), 1, "the proxy-ARP reply");
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty());

    let remote = SocketAddrV4::new(Ipv4Addr::new(93, 184, 215, 14), 80);
    let first_port = 1024u16;
    let mut port = first_port;
    // Answered; then waiting for smoltcp; then no room anywhere.
    for _ in 0..3 {
        for _ in 0..QUEUE_CAP {
            h.stack
                .push_guest_frame(&tcp_syn(SocketAddrV4::new(GUEST, port), remote, 1));
            port += 1;
        }
        h.stack.poll(Instant::now());
    }
    let answered = h.drain();
    assert_eq!(answered.len(), QUEUE_CAP, "the guest's queue is capped");
    let cap = QUEUE_CAP as u16;
    assert_eq!(reset_port(&answered[0]), first_port);
    assert_eq!(reset_port(&answered[QUEUE_CAP - 1]), first_port + cap - 1);

    h.stack.poll(Instant::now());
    let waited = h.drain();
    assert_eq!(waited.len(), QUEUE_CAP, "what waited is answered now");
    assert_eq!(reset_port(&waited[0]), first_port + cap);
    assert_eq!(reset_port(&waited[QUEUE_CAP - 1]), first_port + 2 * cap - 1);
    h.stack.poll(Instant::now());
    assert!(h.drain().is_empty(), "the third round was dropped");

    h.stack.shutdown();
    let drops = drops(&h.events());
    assert!(drops.iter().all(|d| d.reason == "queue_full"), "{drops:?}");
    assert_eq!(drops.iter().map(|d| d.count).sum::<u64>(), QUEUE_CAP as u64);
}

/// Counts still held when the stack stops are recorded by `shutdown`.
#[test]
fn shutdown_records_the_drops_still_held() {
    let mut h = harness();
    for _ in 0..5 {
        h.stack.push_guest_frame(&ipv6_frame());
    }
    h.stack.shutdown();
    let counts: Vec<u64> = drops(&h.events())
        .into_iter()
        .map(|d| {
            assert_eq!(d.reason, "ipv6");
            d.count
        })
        .collect();
    assert_eq!(counts, [1, 4], "the first at once, the rest at shutdown");
}

#[test]
fn the_stack_is_send() {
    fn send<T: Send>() {}
    send::<NetStack>();
}

#[test]
fn classify_sorts_each_kind_of_frame() {
    let guest = SocketAddrV4::new(GUEST, 40000);
    let gateway_dns = SocketAddrV4::new(GATEWAY, 53);
    let other_dns = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);
    let web = SocketAddrV4::new(Ipv4Addr::new(93, 184, 215, 14), 443);
    let cases: Vec<(Vec<u8>, Dispatch)> = vec![
        (arp_request(GUEST, GATEWAY), Dispatch::Arp),
        (dhcp(DhcpMessageType::Discover, false), Dispatch::Dhcp),
        (
            udp(GATEWAY_MAC, guest, gateway_dns, b"q"),
            Dispatch::Dns {
                src: guest,
                dst: gateway_dns,
            },
        ),
        (
            udp(GATEWAY_MAC, guest, other_dns, b"q"),
            Dispatch::Udp {
                src: guest,
                dst: other_dns,
            },
        ),
        (
            icmp_echo(GATEWAY, 1, 1, b""),
            Dispatch::Icmp {
                src: GUEST,
                dst: GATEWAY,
            },
        ),
        (
            tcp_syn(guest, web, 1),
            Dispatch::TcpSyn {
                src: guest,
                dst: web,
            },
        ),
        (ipv6_frame(), Dispatch::Ipv6),
        (vec![0; 13], Dispatch::Other),
    ];
    for (frame, want) in cases {
        assert_eq!(classify(&frame, GATEWAY), want);
    }

    // A segment that is not a bare SYN is plain TCP.
    let mut ack = tcp_syn(guest, web, 1);
    let tcp_at = 14 + 20;
    ack[tcp_at + 13] = 0x10; // flags: ACK only
    fix_tcp_checksum(&mut ack);
    assert_eq!(
        classify(&ack, GATEWAY),
        Dispatch::Tcp {
            src: guest,
            dst: web,
        }
    );

    // A bad checksum, a fragment, and a truncated packet are not trusted.
    let mut corrupt = udp(GATEWAY_MAC, guest, gateway_dns, b"q");
    *corrupt.last_mut().unwrap() ^= 0xff;
    assert_eq!(classify(&corrupt, GATEWAY), Dispatch::Other);
    let mut fragment = udp(GATEWAY_MAC, guest, other_dns, b"q");
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut fragment[14..]);
        ip.set_more_frags(true);
        ip.fill_checksum();
    }
    assert_eq!(classify(&fragment, GATEWAY), Dispatch::Other);
    let whole = tcp_syn(guest, web, 1);
    assert_eq!(
        classify(&whole[..whole.len() - 1], GATEWAY),
        Dispatch::Other
    );
}

fn fix_tcp_checksum(frame: &mut [u8]) {
    let mut ip = Ipv4Packet::new_unchecked(&mut frame[14..]);
    let (src, dst) = (ip.src_addr(), ip.dst_addr());
    TcpPacket::new_unchecked(ip.payload_mut()).fill_checksum(&src.into(), &dst.into());
}

/// Random bytes shaped into an Ethernet frame carrying a well-formed IPv4
/// header (and, for UDP, ICMP and TCP, a well-formed transport header with
/// a correct checksum), so the fuzzing reaches the parsers behind the
/// dispatcher instead of stopping at the IPv4 checksum.
fn shaped_ipv4(protocol: u8, dst_port: u16, to_gateway: bool, mut body: Vec<u8>) -> Vec<u8> {
    let src = GUEST;
    let dst = if to_gateway {
        GATEWAY
    } else {
        Ipv4Addr::new(192, 0, 2, 1)
    };
    let protocol = IpProtocol::from(protocol);
    match protocol {
        IpProtocol::Udp if body.len() >= 8 => {
            // A BOOTREQUEST over Ethernet with the DHCP magic cookie, so
            // random options reach the DHCP parser.
            // A DISCOVER or a REQUEST, half the time with no other option,
            // so random headers and options also reach the reply builder.
            if dst_port == DHCP_SERVER_PORT && body.len() >= 8 + 244 {
                body[8..11].copy_from_slice(&[1, 1, 6]);
                body[8 + 236..8 + 240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
                let message_type = if body[12] & 1 == 0 { 1 } else { 3 };
                body[8 + 240..8 + 243].copy_from_slice(&[53, 1, message_type]);
                if body[13] & 1 == 0 {
                    body[8 + 243] = 255;
                }
            }
            let len = body.len() as u16;
            let mut packet = UdpPacket::new_unchecked(&mut body[..]);
            packet.set_dst_port(dst_port);
            packet.set_len(len);
            packet.set_checksum(0);
        }
        IpProtocol::Icmp if body.len() >= 8 => {
            Icmpv4Packet::new_unchecked(&mut body[..]).fill_checksum();
        }
        IpProtocol::Tcp if body.len() >= 20 => {
            body[12] = (body[12] & 0x0f) | 0x50; // data offset 5
            let mut packet = TcpPacket::new_unchecked(&mut body[..]);
            packet.set_dst_port(dst_port);
            packet.fill_checksum(&src.into(), &dst.into());
        }
        _ => {}
    }
    ipv4(GATEWAY_MAC, src, dst, protocol, body.len(), |buf| {
        buf.copy_from_slice(&body)
    })
}

/// Random bytes after an ARP header that claims Ethernet and IPv4.
fn shaped_arp(mut body: Vec<u8>) -> Vec<u8> {
    let header = [0, 1, 8, 0, 6, 4];
    for (b, h) in body.iter_mut().zip(header) {
        *b = h;
    }
    ethernet(
        GUEST_MAC,
        EthernetAddress::BROADCAST,
        EthernetProtocol::Arp,
        &body,
    )
}

fn frames() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..1600),
        (
            prop_oneof![Just(1u8), Just(6u8), Just(17u8), any::<u8>()],
            prop_oneof![Just(53u16), Just(67u16), Just(80u16), any::<u16>()],
            any::<bool>(),
            vec(any::<u8>(), 0..1480),
        )
            .prop_map(|(protocol, port, to_gateway, body)| shaped_ipv4(
                protocol, port, to_gateway, body
            )),
        vec(any::<u8>(), 0..64).prop_map(shaped_arp),
    ]
}

proptest! {
    #[test]
    fn classify_never_panics_on_arbitrary_bytes(frame in frames()) {
        let _ = classify(&frame, GATEWAY);
    }
}

/// The whole stack, not just the dispatcher, takes anything the guest
/// sends without panicking.
#[test]
fn the_stack_never_panics_on_arbitrary_frames() {
    let h = RefCell::new(harness());
    TestRunner::default()
        .run(&frames(), |frame| {
            let mut h = h.borrow_mut();
            h.stack.push_guest_frame(&frame);
            h.stack.poll(Instant::now());
            h.drain();
            Ok(())
        })
        .unwrap();
}
