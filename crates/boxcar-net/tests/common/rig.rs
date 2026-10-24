// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A guest in front of the stack and a net thread behind it, for the TCP
//! and gate tests: a second smoltcp interface plays the guest (its frames
//! go to `push_guest_frame`, what `pop_host_frame` gives back goes into its
//! device), real sockets on 127.0.0.1 play the far end, and a
//! [`FakeEventLoop`] over poll(2) plays the net thread.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use boxcar_proto::Payload;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, TcpControl, TcpPacket};

use super::{ipv4, segment, FakeEventLoop, Harness, GATEWAY, GATEWAY_MAC, GUEST, GUEST_MAC};

pub const FRAME_MTU: usize = 1514;

pub fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => panic!("{addr} is not IPv4"),
    }
}

/// The guest's NIC: what the guest sent and the stack has not taken, and
/// what the stack sent and the guest has not read.
#[derive(Default)]
pub struct Wire {
    to_stack: VecDeque<Vec<u8>>,
    to_guest: VecDeque<Vec<u8>>,
}

impl phy::Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.to_guest.pop_front()?;
        Some((Rx(frame), Tx(&mut self.to_stack)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.to_stack))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = FRAME_MTU;
        caps
    }
}

pub struct Rx(Vec<u8>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.push_back(frame);
        result
    }
}

/// The stack, a guest in front of it, and the net thread behind it.
pub struct Rig {
    pub h: Harness,
    pub events: FakeEventLoop,
    pub iface: Interface,
    pub wire: Wire,
    pub sockets: SocketSet<'static>,
    pub epoch: Instant,
    pub next_port: u16,
    /// Added to the stack's clock (not the guest's): time passing for the
    /// stack alone.
    pub skew: Duration,
    /// The guest has vanished: it sends nothing, and what the stack sends
    /// it is lost.
    pub gone: bool,
    /// The window field of the last segment (not a SYN) the stack sent the
    /// guest, and the largest.
    pub last_window: Option<u16>,
    pub max_window: u16,
}

impl Rig {
    pub fn new(h: Harness) -> Rig {
        let mut wire = Wire::default();
        let mut config = Config::new(HardwareAddress::Ethernet(GUEST_MAC));
        config.random_seed = 0x5eed;
        let mut iface = Interface::new(config, &mut wire, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(GUEST.into(), 24)).unwrap());
        iface.routes_mut().add_default_ipv4_route(GATEWAY).unwrap();
        Rig {
            h,
            events: FakeEventLoop::new(),
            iface,
            wire,
            sockets: SocketSet::new(Vec::new()),
            epoch: Instant::now(),
            next_port: 40_000,
            skew: Duration::ZERO,
            gone: false,
            last_window: None,
            max_window: 0,
        }
    }

    /// The guest's clock, skewed as the stack's is.
    pub fn clock(&self) -> SmolInstant {
        SmolInstant::from_micros((self.epoch.elapsed() + self.skew).as_micros() as i64)
    }

    /// A guest socket connecting to `dst`, and the guest's end of it.
    pub fn connect(&mut self, dst: SocketAddrV4) -> (SocketHandle, SocketAddrV4) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1 << 20]),
            tcp::SocketBuffer::new(vec![0; 1 << 20]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        self.next_port += 1;
        socket
            .connect(self.iface.context(), dst, self.next_port)
            .unwrap();
        (
            self.sockets.add(socket),
            SocketAddrV4::new(GUEST, self.next_port),
        )
    }

    pub fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(handle)
    }

    /// One round: the guest sends, the stack takes it and answers, the
    /// guest reads, and the host fds that are ready are handed over
    /// (waiting a little for one when nothing else moved).
    pub fn step(&mut self) {
        if !self.gone {
            self.iface
                .poll(self.clock(), &mut self.wire, &mut self.sockets);
        }
        let mut moved = false;
        while let Some(frame) = self.wire.to_stack.pop_front() {
            self.h.stack.push_guest_frame(&frame);
            moved = true;
        }
        let outcome = self.h.stack.poll(Instant::now() + self.skew);
        self.events.apply(&outcome.fd_changes);
        while let Some(frame) = self.h.stack.pop_host_frame() {
            if let Some(seg) = segment(&frame) {
                // A SYN-ACK's window is never scaled: it is left out.
                if seg.ack && !seg.rst && !seg.syn {
                    self.last_window = Some(seg.window);
                    self.max_window = self.max_window.max(seg.window);
                }
            }
            if !self.gone {
                self.wire.to_guest.push_back(frame);
            }
            moved = true;
        }
        if !self.gone {
            self.iface
                .poll(self.clock(), &mut self.wire, &mut self.sockets);
        }
        let wait = if moved || !self.wire.to_stack.is_empty() {
            Duration::ZERO
        } else {
            Duration::from_millis(2)
        };
        self.events.dispatch(&mut self.h.stack, wait);
    }

    /// Steps until `done`, failing after `limit`.
    pub fn until(&mut self, limit: Duration, what: &str, mut done: impl FnMut(&mut Rig) -> bool) {
        let start = Instant::now();
        while !done(self) {
            assert!(start.elapsed() < limit, "timed out waiting for {what}");
            self.step();
        }
    }

    /// Steps until the stack holds no flow.
    pub fn settle(&mut self) {
        self.until(Duration::from_secs(10), "every flow to end", |rig| {
            rig.h.stack.open_flows() == 0
        });
    }

    /// Sends `bytes` on `handle` and steps until they have all gone.
    pub fn send(&mut self, handle: SocketHandle, bytes: &[u8]) {
        let mut at = 0;
        self.until(Duration::from_secs(10), "the guest's send", |rig| {
            let socket = rig.socket(handle);
            assert!(socket.is_open(), "the connection ended: {}", socket.state());
            if socket.can_send() {
                at += socket.send_slice(&bytes[at..]).unwrap();
            }
            at == bytes.len()
        });
    }

    /// Steps until `handle` has received `n` bytes, and returns them.
    pub fn recv(&mut self, handle: SocketHandle, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        self.until(Duration::from_secs(10), "the guest's receive", |rig| {
            let socket = rig.socket(handle);
            let mut buf = vec![0; n - got.len()];
            if socket.can_recv() {
                let k = socket.recv_slice(&mut buf).unwrap();
                got.extend_from_slice(&buf[..k]);
            }
            assert!(
                got.len() == n || socket.may_recv(),
                "the connection ended after {} bytes: {}",
                got.len(),
                socket.state()
            );
            got.len() == n
        });
        got
    }

    /// Steps until the host peer reports what it saw: the stack closes a
    /// host socket at the poll after the one that unwatched it.
    pub fn seen(&mut self, peer: &mpsc::Receiver<Seen>) -> Seen {
        let mut seen = None;
        self.until(Duration::from_secs(10), "the host peer", |_| {
            seen = peer.try_recv().ok();
            seen.is_some()
        });
        seen.unwrap()
    }

    /// Sends `bytes` and waits for them to come back.
    pub fn ping(&mut self, handle: SocketHandle, bytes: &[u8]) {
        self.send(handle, bytes);
        assert_eq!(self.recv(handle, bytes.len()), bytes);
    }

    /// Steps until the guest's socket is closed, and says whether a reset
    /// closed it: the guest's own side never closed, so only a reset gets
    /// it to Closed from Established.
    pub fn wait_reset(&mut self, handle: SocketHandle) {
        self.until(Duration::from_secs(10), "the guest's reset", |rig| {
            rig.socket(handle).state() == tcp::State::Closed
        });
    }

    pub fn events(self) -> Vec<Payload> {
        self.h.events()
    }
}

/// A guest that plays TCP by hand, one segment at a time: what the stack
/// last acknowledged and offered, the payload it sent, and its resets.
pub struct RawGuest {
    pub h: Harness,
    pub events: FakeEventLoop,
    pub guest: SocketAddrV4,
    pub server: SocketAddrV4,
    /// The next sequence number the guest sends, and what it acknowledges.
    pub seq: u32,
    pub ack: u32,
    pub acked: u32,
    pub window: u32,
    pub resets: usize,
    pub received: Vec<u8>,
}

impl RawGuest {
    /// A guest connected through `h` to `server`.
    pub fn connect(h: Harness, server: SocketAddrV4) -> RawGuest {
        let mut raw = RawGuest {
            h,
            events: FakeEventLoop::new(),
            guest: SocketAddrV4::new(GUEST, 40_000),
            server,
            seq: 1000,
            ack: 0,
            acked: 0,
            window: 0,
            resets: 0,
            received: Vec::new(),
        };
        raw.turn();
        raw.h.stack.push_guest_frame(&super::guest_arp());
        raw.h.drain();
        raw.h
            .stack
            .push_guest_frame(&super::syn(raw.guest, server, 1000));
        let start = Instant::now();
        while raw.ack == 0 {
            assert!(start.elapsed() < Duration::from_secs(5), "no SYN-ACK");
            raw.events
                .dispatch(&mut raw.h.stack, Duration::from_millis(10));
            raw.turn();
        }
        raw.seq = 1001;
        raw.send(TcpControl::None, &[]);
        raw
    }

    /// The stack's turn: its poll, the host fds, its poll again; what it
    /// sent the guest is read.
    pub fn turn(&mut self) {
        let outcome = self.h.stack.poll(Instant::now());
        self.events.apply(&outcome.fd_changes);
        self.events.dispatch(&mut self.h.stack, Duration::ZERO);
        let outcome = self.h.stack.poll(Instant::now());
        self.events.apply(&outcome.fd_changes);
        for frame in self.h.drain() {
            let Some(s) = segment(&frame) else { continue };
            if s.rst {
                self.resets += 1;
            } else {
                let end = s
                    .seq
                    .wrapping_add(s.payload.len() as u32)
                    .wrapping_add(u32::from(s.syn))
                    .wrapping_add(u32::from(s.fin));
                if s.syn && s.ack {
                    self.ack = end;
                    self.acked = s.ack_number;
                    self.window = u32::from(s.window);
                } else if s.ack {
                    self.ack = self.ack.max(end);
                    self.acked = s.ack_number;
                    self.window = u32::from(s.window);
                    self.received.extend_from_slice(&s.payload);
                }
            }
        }
    }

    /// The guest sends `payload` (and `control`) at its next sequence
    /// number, and the stack takes its turn.
    pub fn send(&mut self, control: TcpControl, payload: &[u8]) {
        let frame = self.segment(control, payload);
        self.h.stack.push_guest_frame(&frame);
        self.seq = self
            .seq
            .wrapping_add(payload.len() as u32 + u32::from(control == TcpControl::Fin));
        self.turn();
    }

    /// A segment at the guest's next sequence number, acknowledging
    /// everything (no window scaling).
    pub fn segment(&self, control: TcpControl, payload: &[u8]) -> Vec<u8> {
        let repr = smoltcp::wire::TcpRepr {
            src_port: self.guest.port(),
            dst_port: self.server.port(),
            control,
            seq_number: smoltcp::wire::TcpSeqNumber(self.seq as i32),
            ack_number: Some(smoltcp::wire::TcpSeqNumber(self.ack as i32)),
            window_len: 65_535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        ipv4(
            GATEWAY_MAC,
            *self.guest.ip(),
            *self.server.ip(),
            smoltcp::wire::IpProtocol::Tcp,
            repr.buffer_len(),
            |buf| {
                repr.emit(
                    &mut TcpPacket::new_unchecked(buf),
                    &(*self.guest.ip()).into(),
                    &(*self.server.ip()).into(),
                    &smoltcp::phy::ChecksumCapabilities::default(),
                )
            },
        )
    }

    /// Room in the stack's window at the guest's next sequence number.
    pub fn room(&self) -> u32 {
        let room = self.acked.wrapping_add(self.window).wrapping_sub(self.seq);
        if room < 1 << 30 {
            room
        } else {
            0
        }
    }
}

/// A listener that echoes every connection until EOF, then shuts down its
/// write side.
pub fn echo_server() -> SocketAddrV4 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = v4(listener.local_addr().unwrap());
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            thread::spawn(move || {
                let mut buf = vec![0; 64 * 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = conn.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// What a host peer saw of its one connection.
#[derive(Debug)]
pub struct Seen {
    pub bytes: Vec<u8>,
    /// How it ended: EOF, or a read error.
    pub end: Result<(), ErrorKind>,
}

/// A listener that takes one connection, answers `reply` once it has read
/// `reply_after` bytes, reads until the connection ends, and says what it
/// saw.
pub fn host_peer(reply_after: usize, reply: &'static [u8]) -> (SocketAddrV4, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = v4(listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        let mut replied = false;
        let end = loop {
            match conn.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    bytes.extend_from_slice(&buf[..n]);
                    if !replied && bytes.len() >= reply_after {
                        conn.write_all(reply).unwrap();
                        replied = true;
                    }
                }
                Err(e) => break Err(e.kind()),
            }
        };
        let _ = tx.send(Seen { bytes, end });
    });
    (addr, rx)
}
