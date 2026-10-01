// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! ARP: the gateway answers for every address on the guest's network but
//! the guest's own (proxy ARP), so every frame the guest sends on the link
//! comes to the stack, whatever address it is for.
//!
//! smoltcp must also learn the guest's MAC, to send it TCP segments without
//! first asking for it. It is not handed the guest's ARP as sent: with
//! any-IP on, smoltcp answers a request for any address at all, the guest's
//! own included, and would claim it. It is handed instead an ARP *reply*
//! from the guest to the gateway carrying the same sender, which fills its
//! neighbor cache and draws no answer.

use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr,
};

use crate::config::NetConfig;

/// The gateway's answer to a guest ARP request, if it gets one: a reply
/// giving the gateway's MAC for any address on the guest's network except
/// the guest's own, and except the address the sender claims for itself (a
/// gratuitous announcement, or a conflict check). Requests for addresses off
/// the network, replies, and malformed packets get nothing.
pub fn reply(cfg: &NetConfig, frame: &[u8]) -> Option<Vec<u8>> {
    let Some(ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr,
        source_protocol_addr,
        target_protocol_addr,
        ..
    }) = parse(frame)
    else {
        return None;
    };
    let answer = operation == ArpOperation::Request
        && source_hardware_addr.is_unicast()
        && cfg.on_network(target_protocol_addr)
        && target_protocol_addr != cfg.guest_ip
        && target_protocol_addr != source_protocol_addr;
    if !answer {
        return None;
    }
    let gateway_mac = EthernetAddress(cfg.gateway_mac);
    Some(arp_frame(
        gateway_mac,
        source_hardware_addr,
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: gateway_mac,
            source_protocol_addr: target_protocol_addr,
            target_hardware_addr: source_hardware_addr,
            target_protocol_addr: source_protocol_addr,
        },
    ))
}

/// The frame that teaches smoltcp the sender of a guest ARP packet: an ARP
/// reply from that sender to the gateway. Only a unicast sender with an
/// address on the guest's network other than the gateway's is taught; an
/// address probe (sender `0.0.0.0`) teaches nothing.
pub fn learning_frame(cfg: &NetConfig, frame: &[u8]) -> Option<Vec<u8>> {
    let Some(ArpRepr::EthernetIpv4 {
        source_hardware_addr,
        source_protocol_addr,
        ..
    }) = parse(frame)
    else {
        return None;
    };
    let teach = source_hardware_addr.is_unicast()
        && cfg.on_network(source_protocol_addr)
        && source_protocol_addr != cfg.gateway;
    if !teach {
        return None;
    }
    let gateway_mac = EthernetAddress(cfg.gateway_mac);
    Some(arp_frame(
        source_hardware_addr,
        gateway_mac,
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr,
            source_protocol_addr,
            target_hardware_addr: gateway_mac,
            target_protocol_addr: cfg.gateway,
        },
    ))
}

fn parse(frame: &[u8]) -> Option<ArpRepr> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Arp {
        return None;
    }
    let packet = ArpPacket::new_checked(eth.payload()).ok()?;
    ArpRepr::parse(&packet).ok()
}

fn arp_frame(eth_src: EthernetAddress, eth_dst: EthernetAddress, arp: ArpRepr) -> Vec<u8> {
    let eth = EthernetRepr {
        src_addr: eth_src,
        dst_addr: eth_dst,
        ethertype: EthernetProtocol::Arp,
    };
    let mut buf = vec![0; eth.buffer_len() + arp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
    eth.emit(&mut frame);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    buf
}
