// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the integration tests share: a stack with the default addressing,
//! logging into a fresh session, whose DNS upstream is a local socket the
//! test holds; and builders for the frames the guest sends.

// Each test file uses its own part of this.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use boxcar_audit::{LogReader, WriterConfig, WriterHandle};
use boxcar_net::{NetConfig, NetStack, Policy};
use boxcar_proto::{NetDrop, Payload, SessionId, Source};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet,
    Ipv4Repr, UdpPacket, UdpRepr,
};
use tempfile::TempDir;

pub const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
pub const GUEST_MAC: EthernetAddress = EthernetAddress([0x02, 0x62, 0x6f, 0x78, 0x00, 0x01]);
pub const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x02, 0x62, 0x6f, 0x78, 0x00, 0x02]);

/// A stack, the policy it reads, and the socket it forwards DNS to.
pub struct Harness {
    pub stack: NetStack,
    /// The stack's policy, which a test may swap.
    pub policy: Arc<ArcSwap<Policy>>,
    /// The stack's DNS upstream, on 127.0.0.1: nothing answers the stack
    /// unless the test does, and no query leaves the host.
    pub upstream: UdpSocket,
    writer: WriterHandle,
    _dir: TempDir,
}

/// A stack that lets everything through but the built-in denials.
pub fn harness() -> Harness {
    harness_with(Policy::allow_all())
}

pub fn harness_with(policy: Policy) -> Harness {
    let dir = TempDir::new().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let cfg = NetConfig {
        dns_upstreams: vec![upstream.local_addr().unwrap()],
        ..NetConfig::default()
    };
    let policy = Arc::new(ArcSwap::from_pointee(policy));
    let stack = NetStack::new(cfg, sink, Arc::clone(&policy)).unwrap();
    Harness {
        stack,
        policy,
        upstream,
        writer,
        _dir: dir,
    }
}

impl Harness {
    /// Everything the stack sent the guest so far.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| self.stack.pop_host_frame()).collect()
    }

    /// Closes the log and returns the payloads the stack recorded, after
    /// checking that each came from the network stack.
    pub fn events(self) -> Vec<Payload> {
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

pub fn drops(events: &[Payload]) -> Vec<NetDrop> {
    events
        .iter()
        .filter_map(|e| match e {
            Payload::NetDrop(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

pub fn ethernet(
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
pub fn ipv4(
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

pub fn udp(
    eth_dst: EthernetAddress,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
) -> Vec<u8> {
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
