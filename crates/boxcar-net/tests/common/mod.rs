// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the integration tests share: a stack with the default addressing,
//! logging into a fresh session, whose DNS upstream is a local socket the
//! test holds; and builders for the frames the guest sends.

// Each test file uses its own part of this.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use boxcar_audit::{LogReader, WriterConfig, WriterHandle};
use boxcar_net::{FdChange, Interest, NetConfig, NetStack, Policy, DNS_TOKEN};
use boxcar_proto::{NetDrop, Payload, SessionId, Source};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet,
    Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
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
    harness_config(policy, |_| {})
}

/// A stack whose config `change` adjusts from the default (the DNS
/// upstream is set after it).
pub fn harness_config(policy: Policy, change: impl FnOnce(&mut NetConfig)) -> Harness {
    let dir = TempDir::new().unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut cfg = NetConfig::default();
    change(&mut cfg);
    cfg.dns_upstreams = vec![upstream.local_addr().unwrap()];
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

/// A guest TCP segment from `src` to `dst` (through the gateway's MAC):
/// `control` with sequence number `seq`, no ACK, a 64 KiB window and an
/// MSS of 1460.
pub fn tcp(src: SocketAddrV4, dst: SocketAddrV4, control: TcpControl, seq: i32) -> Vec<u8> {
    let repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control,
        seq_number: TcpSeqNumber(seq),
        ack_number: None,
        window_len: 65_535,
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

/// The guest's SYN from `src` to `dst` with sequence number `seq`.
pub fn syn(src: SocketAddrV4, dst: SocketAddrV4, seq: i32) -> Vec<u8> {
    tcp(src, dst, TcpControl::Syn, seq)
}

/// A TCP segment the stack sent the guest, as read back: its addresses,
/// flags, numbers and window, after checking the Ethernet addresses and
/// both checksums.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
    pub seq: u32,
    pub ack_number: u32,
    pub window: u16,
    pub payload: Vec<u8>,
}

/// `frame` as a TCP segment the stack sent the guest, or `None` if it is
/// not TCP.
pub fn segment(frame: &[u8]) -> Option<Segment> {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    assert_eq!((eth.src_addr(), eth.dst_addr()), (GATEWAY_MAC, GUEST_MAC));
    let packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let ip = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
    if ip.next_header != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(packet.payload()).unwrap();
    assert!(tcp.verify_checksum(&ip.src_addr.into(), &ip.dst_addr.into()));
    Some(Segment {
        src: SocketAddrV4::new(ip.src_addr, tcp.src_port()),
        dst: SocketAddrV4::new(ip.dst_addr, tcp.dst_port()),
        syn: tcp.syn(),
        ack: tcp.ack(),
        rst: tcp.rst(),
        fin: tcp.fin(),
        seq: tcp.seq_number().0 as u32,
        ack_number: tcp.ack_number().0 as u32,
        window: tcp.window_len(),
        payload: tcp.payload().to_vec(),
    })
}

/// An ARP request from the guest for the gateway, which teaches the stack
/// (and its smoltcp) the guest's MAC.
pub fn guest_arp() -> Vec<u8> {
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr};
    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: GUEST_MAC,
        source_protocol_addr: GUEST,
        target_hardware_addr: EthernetAddress([0; 6]),
        target_protocol_addr: GATEWAY,
    };
    let mut payload = vec![0; repr.buffer_len()];
    repr.emit(&mut ArpPacket::new_unchecked(&mut payload[..]));
    ethernet(
        GUEST_MAC,
        EthernetAddress::BROADCAST,
        EthernetProtocol::Arp,
        &payload,
    )
}

/// Teaches the stack's DNS cache that `name` is `ip`: the guest asks the
/// gateway for it, the test's upstream answers with one A record, and the
/// stack's answer to the guest is thrown away.
pub fn resolve(h: &mut Harness, name: &str, ip: Ipv4Addr) {
    let mut query = vec![0x51, 0x7e, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let guest = SocketAddrV4::new(GUEST, 41_000);
    let gateway = SocketAddrV4::new(GATEWAY, 53);
    h.stack.poll(std::time::Instant::now());
    h.stack
        .push_guest_frame(&udp(GATEWAY_MAC, guest, gateway, &query));
    let mut buf = [0; 1500];
    let (n, from) = h.upstream.recv_from(&mut buf).unwrap();
    let mut reply = buf[..n].to_vec();
    // QR, RD, RA; one answer: a pointer to the question's name, A, IN, a
    // minute, 4 bytes.
    reply[2..4].copy_from_slice(&[0x81, 0x80]);
    reply[6..8].copy_from_slice(&[0, 1]);
    reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    reply.extend_from_slice(&ip.octets());
    h.upstream.send_to(&reply, from).unwrap();
    for _ in 0..2000 {
        h.stack.on_host_fd_event(DNS_TOKEN, true, false);
        if !h.drain().is_empty() {
            assert!(h.stack.dns_names(ip).iter().any(|n| n == name));
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("the stack never answered the guest's query for {name}");
}

/// The net thread's part, played with poll(2): the fds the stack asked to
/// watch through [`FdChange`], and their readiness handed back through
/// `on_host_fd_event`.
#[derive(Debug, Default)]
pub struct FakeEventLoop {
    watched: BTreeMap<u64, (RawFd, Interest)>,
}

impl FakeEventLoop {
    pub fn new() -> Self {
        FakeEventLoop::default()
    }

    /// Starts, changes or stops watching fds as the stack asks. Every fd
    /// named must still be open: the stack closes an fd only after the
    /// outcome that unwatches it.
    pub fn apply(&mut self, changes: &[FdChange]) {
        for change in changes {
            // SAFETY: F_GETFD only reads the descriptor's flags.
            let open = unsafe { libc::fcntl(change.fd, libc::F_GETFD) } != -1;
            assert!(open, "{change:?}: the fd is already closed");
            if change.interest.readable || change.interest.writable {
                self.watched
                    .insert(change.token, (change.fd, change.interest));
            } else {
                self.watched.remove(&change.token);
            }
        }
    }

    /// What `token` is watched for, if it is.
    pub fn watching(&self, token: u64) -> Option<Interest> {
        self.watched.get(&token).map(|(_, interest)| *interest)
    }

    /// How many fds are watched.
    pub fn len(&self) -> usize {
        self.watched.len()
    }

    /// How many relayed connections' fds are watched.
    pub fn flows_watched(&self) -> usize {
        self.watched.range(boxcar_net::FLOW_TOKEN_BASE..).count()
    }

    /// Waits up to `timeout` for a watched fd to be ready, and returns each
    /// ready one's token and whether it is readable and writable (an error
    /// or hang-up is both). A watched fd must be open: the stack closes an
    /// fd only after asking for it to be unwatched.
    pub fn wait(&self, timeout: Duration) -> Vec<(u64, bool, bool)> {
        let tokens: Vec<u64> = self.watched.keys().copied().collect();
        let mut fds: Vec<libc::pollfd> = self
            .watched
            .values()
            .map(|(fd, interest)| libc::pollfd {
                fd: *fd,
                events: if interest.readable { libc::POLLIN } else { 0 }
                    | if interest.writable { libc::POLLOUT } else { 0 },
                revents: 0,
            })
            .collect();
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: `fds` is a live array of `fds.len()` pollfd structs.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if n <= 0 {
            return Vec::new();
        }
        tokens
            .into_iter()
            .zip(fds)
            .filter(|(_, fd)| fd.revents != 0)
            .map(|(token, fd)| {
                assert_eq!(
                    fd.revents & libc::POLLNVAL,
                    0,
                    "token {token}: fd {} was closed while watched",
                    fd.fd
                );
                let broken = fd.revents & (libc::POLLERR | libc::POLLHUP) != 0;
                (
                    token,
                    broken || fd.revents & libc::POLLIN != 0,
                    broken || fd.revents & libc::POLLOUT != 0,
                )
            })
            .collect()
    }

    /// Waits up to `timeout` and hands what is ready to the stack; says
    /// how many fds were.
    pub fn dispatch(&self, stack: &mut NetStack, timeout: Duration) -> usize {
        let ready = self.wait(timeout);
        for (token, readable, writable) in &ready {
            stack.on_host_fd_event(*token, *readable, *writable);
        }
        ready.len()
    }
}
