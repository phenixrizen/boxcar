// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from cloud-hypervisor virtio-devices/src/vsock/unix/muxer.rs at commit 853c440425ebe23bcf5fb43d9058bd1d8a0abe2a.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Cloud Hypervisor is https://github.com/cloud-hypervisor/cloud-hypervisor.
// Adapted: a guest connection request goes through boxcar's rules
// (`crate::rules`) instead of straight to `<uds>_<port>`, and the
// connections the rules let through, and the host connections the guest
// accepts, are recorded as `vsock.connect` and `vsock.close` (every
// `// boxcar:` block). The host socket is bound by the device and handed
// in, so that it outlives an activation. The nested epoll is
// vmm-sys-util's; packets are virtio-vsock 0.11's (`crate::packet_ext`);
// log lines go through `boxcar_virtio::limited!` and the per-packet and
// per-event debug lines are gone; `unwrap`s, `unreachable!` and let-chains (edition 2024)
// are rewritten; the snapshot hooks (`VsockBackend`) are dropped. An
// allowlisted port's host socket is connected without waiting, a host client
// of the vsock socket has 5 s to send its `CONNECT` line and counts toward
// the connection limit meanwhile, and an internal port is taken only once its
// connection is added (all `// boxcar:`). The tests
// build their packets over plain buffers, use ports outside the internal
// ones (which the rules keep for the VMM) and allowlist them, and keep
// their sockets in a temporary directory.

//! `VsockMuxer` is the device-facing component of the Unix domain sockets vsock backend. I.e.
//! by implementing the `VsockBackend` trait, it abstracts away the gory details of translating
//! between AF_VSOCK and AF_UNIX, and presents a clean interface to the rest of the vsock
//! device model.
//!
//! The vsock muxer has two main roles:
//!
//! ## Vsock connection multiplexer
//!
//! It's the muxer's job to create, manage, and terminate `VsockConnection` objects. The
//! muxer also routes packets to their owning connections. It does so via a connection
//! `HashMap`, keyed by what is basically a (host_port, guest_port) tuple.
//!
//! Vsock packet traffic needs to be inspected, in order to detect connection request
//! packets (leading to the creation of a new connection), and connection reset packets
//! (leading to the termination of an existing connection). All other packets, though, must
//! belong to an existing connection and, as such, the muxer simply forwards them.
//!
//! ## Event dispatcher
//!
//! There are three event categories that the vsock backend is interested it:
//! 1. A new host-initiated connection is ready to be accepted from the listening host Unix
//!    socket;
//! 2. Data is available for reading from a newly-accepted host-initiated connection (i.e.
//!    the host is ready to issue a vsock connection request, informing us of the
//!    destination port to which it wants to connect);
//! 3. Some event was triggered for a connected Unix socket, that belongs to a
//!    `VsockConnection`.
//!
//! The muxer gets notified about all of these events, because, as a `VsockEpollListener`
//! implementor, it gets to register a nested epoll FD into the main VMM epoll()ing loop. All
//! other pollable FDs are then registered under this nested epoll FD.
//!
//! To route all these events to their handlers, the muxer uses another `HashMap` object,
//! mapping `RawFd`s to `EpollListener`s.
//!
//! ## boxcar's rules
//!
//! A guest connection request is decided by `crate::rules`: an internal port is served by a
//! VMM service (privileged source port, first connection only), an allowlisted port reaches
//! `<uds>_<port>`, and anything else is reset. Every decision, and the end of every connection
//! let through, is recorded (`vsock.connect`, `vsock.close`); see `crate::rules`.
//!
//! A host client of the vsock socket has [`CONNECT_TIMEOUT`] to send its whole
//! `CONNECT <port>\n` line, at most 32 bytes, or it is closed; until it has, it counts toward
//! the connection limit, with the connections.

use std::cmp::max;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::str;
use std::sync::Arc;
// boxcar: for the `CONNECT` deadlines.
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use boxcar_audit::AuditSink;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
// boxcar: the `CONNECT` deadlines' timer.
use vmm_sys_util::timerfd::TimerFd;

use super::super::csm::ConnState;
use super::super::defs::uapi;
use super::super::device::VsockConfig;
use super::super::packet_ext::VsockPacket;
use super::super::rules::{self, AllowPorts, Decision, Dir, Peer, Rules};
use super::super::services::InternalServices;
use super::super::{Result as VsockResult, VsockChannel, VsockEpollListener, VsockError};
use super::muxer_killq::MuxerKillQ;
use super::muxer_rxq::MuxerRxQ;
use super::{defs, Error, MuxerConnection, Result};

/// A unique identifier of a `MuxerConnection` object. Connections are stored in a hash map,
/// keyed by a `ConnMapKey` object.
///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ConnMapKey {
    local_port: u32,
    peer_port: u32,
}

/// A muxer RX queue item.
///
#[derive(Clone, Copy, Debug)]
pub(super) enum MuxerRx {
    /// The packet must be fetched from the connection identified by `ConnMapKey`.
    ConnRx(ConnMapKey),
    /// The muxer must produce an RST packet.
    RstPkt { local_port: u32, peer_port: u32 },
}

/// An epoll listener, registered under the muxer's nested epoll FD.
///
enum EpollListener {
    /// The listener is a `MuxerConnection`, identified by `key`, and interested in the events
    /// in `evset`. Since `MuxerConnection` implements `VsockEpollListener`, notifications will
    /// be forwarded to the listener via `VsockEpollListener::notify()`.
    Connection { key: ConnMapKey, evset: EventSet },
    /// A listener interested in new host-initiated connections.
    HostSock,
    /// A listener interested in reading host "connect \<port>" commands from a freshly
    /// connected host socket.
    LocalStream(UnixStream),
    // boxcar: fires at the earliest `CONNECT` deadline of the `LocalStream`s.
    /// The timer of the host clients' `CONNECT` deadlines.
    CommandTimer,
}

// boxcar: the bound on a host client's `CONNECT` line, documented: the line, newline included,
// is at most this many bytes (Cloud Hypervisor's buffer), or the client is dropped.
const PARTIALLY_READ_COMMAND_BUF_SIZE: usize = 32;

// boxcar: how long a host client has, from its accept, to send its whole `CONNECT <port>\n`
// line before it is dropped.
/// How long a host client of the vsock socket has to send its whole `CONNECT <port>\n` line
/// (at most 32 bytes, newline included) before the muxer closes it.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A partially read "CONNECT" command.
#[derive(Default)]
struct PartiallyReadCommand {
    /// The bytes of the command that have been read so far.
    buf: [u8; PARTIALLY_READ_COMMAND_BUF_SIZE],
    /// How much of `buf` has been used.
    len: usize,
}

/// The vsock connection multiplexer.
///
pub struct VsockMuxer {
    /// Guest CID.
    cid: u64,
    /// A hash map used to store the active connections.
    conn_map: HashMap<ConnMapKey, MuxerConnection>,
    /// A hash map used to store epoll event listeners / handlers.
    listener_map: HashMap<RawFd, EpollListener>,
    /// A hash map used to store partially read "connect" commands.
    partial_command_map: HashMap<RawFd, PartiallyReadCommand>,
    /// The RX queue. Items in this queue are consumed by `VsockMuxer::recv_pkt()`, and
    /// produced
    /// - by `VsockMuxer::send_pkt()` (e.g. RST in response to a connection request packet);
    ///   and
    /// - in response to EPOLLIN events (e.g. data available to be read from an AF_UNIX
    ///   socket).
    rxq: MuxerRxQ,
    /// A queue used for terminating connections that are taking too long to shut down.
    killq: MuxerKillQ,
    /// The Unix socket, through which host-initiated connections are accepted.
    host_sock: UnixListener,
    /// The nested epoll, used to register epoll listeners.
    epoll: Epoll,
    /// A hash map used to keep track of used host-side ports, in order to assign local
    /// ports to host-initiated connections. Each allocated port is mapped to the peer
    /// port of the connection owning it, so that a port can only be released by its owner.
    local_port_map: HashMap<u32, u32>,
    /// The last used host-side port.
    local_port_last: u32,
    // boxcar: the rules, and the records.
    /// What becomes of a guest connection request. They also know the path of the host-side
    /// Unix socket, from which the path of a Unix socket listening on an allowlisted port
    /// follows: "\<that path>_\<port number>".
    rules: Rules,
    /// Where `vsock.connect` and `vsock.close` go.
    audit: AuditSink,
    /// The connections a `vsock.connect` let through, and who opened them: each gets its
    /// `vsock.close` when it is removed.
    audited: HashMap<ConnMapKey, Dir>,
    // boxcar: host clients still sending their `CONNECT` line, and the bounds on them.
    /// When each host client still sending its `CONNECT` line (a `LocalStream`, by fd) must
    /// have sent it.
    command_deadlines: HashMap<RawFd, Instant>,
    /// Armed for the earliest of `command_deadlines`; never read, only re-armed or cleared,
    /// which resets it.
    command_timer: TimerFd,
    /// How long a host client has to send its `CONNECT` line: [`CONNECT_TIMEOUT`].
    command_timeout: Duration,
    /// The most connections and host clients still sending their `CONNECT` line there may be,
    /// together: `defs::MAX_CONNECTIONS`.
    max_connections: usize,
}

impl VsockChannel for VsockMuxer {
    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())`: `pkt` has been successfully filled in; or
    /// - `Err(VsockError::NoData)`: there was no available data with which to fill in the
    ///   packet.
    ///
    fn recv_pkt(&mut self, pkt: &mut VsockPacket<'_>) -> VsockResult<()> {
        // We'll look for instructions on how to build the RX packet in the RX queue. If the
        // queue is empty, that doesn't necessarily mean we don't have any pending RX, since
        // the queue might be out-of-sync. If that's the case, we'll attempt to sync it first,
        // and then try to pop something out again.
        if self.rxq.is_empty() && !self.rxq.is_synced() {
            self.rxq = MuxerRxQ::from_conn_map(&self.conn_map);
        }

        while let Some(rx) = self.rxq.peek() {
            let res = match rx {
                // We need to build an RST packet, going from `local_port` to `peer_port`.
                MuxerRx::RstPkt {
                    local_port,
                    peer_port,
                } => {
                    pkt.set_op(uapi::VSOCK_OP_RST)
                        .set_src_cid(uapi::VSOCK_HOST_CID)
                        .set_dst_cid(self.cid)
                        .set_src_port(local_port)
                        .set_dst_port(peer_port)
                        .set_len(0)
                        .set_type(uapi::VSOCK_TYPE_STREAM)
                        .set_flags(0)
                        .set_buf_alloc(0)
                        .set_fwd_cnt(0);
                    // boxcar: peeked, so there: no `unwrap`.
                    self.rxq.pop();
                    return Ok(());
                }

                // We'll defer building the packet to this connection, since it has something
                // to say.
                MuxerRx::ConnRx(key) => {
                    let mut conn_res = Err(VsockError::NoData);
                    let mut do_pop = true;
                    self.apply_conn_mutation(key, |conn| {
                        conn_res = conn.recv_pkt(pkt);
                        do_pop = !conn.has_pending_rx();
                    });
                    if do_pop {
                        self.rxq.pop();
                    }
                    conn_res
                }
            };

            if res.is_ok() {
                // Inspect traffic, looking for RST packets, since that means we have to
                // terminate and remove this connection from the active connection pool.
                //
                if pkt.op() == uapi::VSOCK_OP_RST {
                    self.remove_connection(ConnMapKey {
                        local_port: pkt.src_port(),
                        peer_port: pkt.dst_port(),
                    });
                }

                return Ok(());
            }
        }

        Err(VsockError::NoData)
    }

    /// Deliver a guest-generated packet to its destination in the vsock backend.
    ///
    /// This absorbs unexpected packets, handles RSTs (by dropping connections), and forwards
    /// all the rest to their owning `MuxerConnection`.
    ///
    /// Returns:
    /// always `Ok(())` - the packet has been consumed, and its virtio TX buffers can be
    /// returned to the guest vsock driver.
    ///
    fn send_pkt(&mut self, pkt: &VsockPacket<'_>) -> VsockResult<()> {
        let conn_key = ConnMapKey {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
        };

        // If this packet has an unsupported type (!=stream), we must send back an RST.
        //
        if pkt.type_() != uapi::VSOCK_TYPE_STREAM {
            self.enq_rst(pkt.dst_port(), pkt.src_port());
            return Ok(());
        }

        // We don't know how to handle packets addressed to other CIDs. We only handle the host
        // part of the guest - host communication here.
        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            boxcar_virtio::limited!(
                debug,
                "vsock: dropping guest packet for unknown CID {}",
                pkt.dst_cid()
            );
            return Ok(());
        }

        // An RST forcefully terminates the connection it names and no reply should be made.
        if pkt.op() == uapi::VSOCK_OP_RST {
            self.remove_connection(conn_key);
            return Ok(());
        }

        if !self.conn_map.contains_key(&conn_key) {
            // This packet can't be routed to any active connection (based on its src and dst
            // ports).  The only orphan / unroutable packets we know how to handle are
            // connection requests.
            if pkt.op() == uapi::VSOCK_OP_REQUEST {
                // Oh, this is a connection request!
                self.handle_peer_request_pkt(pkt);
            } else {
                // Send back an RST, to let the drive know we weren't expecting this packet.
                self.enq_rst(pkt.dst_port(), pkt.src_port());
            }
            return Ok(());
        }

        // Alright, everything looks in order - forward this packet to its owning connection.
        let mut res: VsockResult<()> = Ok(());
        self.apply_conn_mutation(conn_key, |conn| {
            res = conn.send_pkt(pkt);
        });

        res
    }

    /// Check if the muxer has any pending RX data, with which to fill a guest-provided RX
    /// buffer.
    ///
    fn has_pending_rx(&self) -> bool {
        !self.rxq.is_empty() || !self.rxq.is_synced()
    }
}

impl VsockEpollListener for VsockMuxer {
    /// Get the FD to be registered for polling upstream (in the main VMM epoll loop, in this
    /// case).
    ///
    /// This will be the muxer's nested epoll FD.
    ///
    fn get_polled_fd(&self) -> RawFd {
        self.epoll.as_raw_fd()
    }

    /// Get the epoll events to be polled upstream.
    ///
    /// Since the polled FD is a nested epoll FD, we're only interested in EPOLLIN events (i.e.
    /// some event occurred on one of the FDs registered under our epoll FD).
    ///
    fn get_polled_evset(&self) -> EventSet {
        EventSet::IN
    }

    /// Notify the muxer about a pending event having occurred under its nested epoll FD.
    ///
    fn notify(&mut self, _: EventSet) {
        let mut epoll_events = vec![EpollEvent::default(); 32];
        'epoll: loop {
            match self.epoll.wait(0, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for evt in epoll_events.iter().take(ev_cnt) {
                        self.handle_event(
                            evt.fd(),
                            // boxcar: truncated rather than unwrapped; the kernel reports only
                            // the flags it knows.
                            EventSet::from_bits_truncate(evt.events()),
                        );
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    boxcar_virtio::limited!(
                        warn,
                        "vsock: failed to consume muxer epoll event: {e}"
                    );
                }
            }
            break 'epoll;
        }
    }
}

impl VsockMuxer {
    /// Muxer constructor.
    ///
    /// boxcar: the muxer of one activation, for the guest `cfg.guest_cid`. It accepts host
    /// connections on `host_sock`, which the device bound at `cfg.uds_path` (see
    /// `super::bind_listener`), serves the internal ports through `services`, reaches
    /// `<cfg.uds_path>_<port>` for the ports in `cfg.allow_ports`, and records into `audit`.
    /// The allowlist is this muxer's own; [`VsockMuxer::with_allow_ports`] takes one that
    /// is shared and swapped.
    pub fn new(
        cfg: &VsockConfig,
        host_sock: UnixListener,
        services: Arc<dyn InternalServices>,
        audit: AuditSink,
    ) -> Result<Self> {
        let allow_ports: AllowPorts = Arc::new(ArcSwap::from_pointee(cfg.allow_ports.clone()));
        VsockMuxer::with_allow_ports(cfg, allow_ports, host_sock, services, audit)
    }

    /// boxcar: [`VsockMuxer::new`], reaching `<cfg.uds_path>_<port>` for the ports in
    /// `allow_ports` as it stands at each guest request (`cfg.allow_ports` is not read): the
    /// device hands every activation's muxer the one list the VMM swaps.
    pub fn with_allow_ports(
        cfg: &VsockConfig,
        allow_ports: AllowPorts,
        host_sock: UnixListener,
        services: Arc<dyn InternalServices>,
        audit: AuditSink,
    ) -> Result<Self> {
        // Create the nested epoll FD. This FD will be added to the device thread's event loop,
        // at device activation time.
        let epoll = Epoll::new().map_err(Error::EpollFdCreate)?;

        // The host Unix socket, through which host-initiated connections are accepted.
        host_sock.set_nonblocking(true).map_err(Error::UnixBind)?;

        let mut muxer = Self {
            cid: cfg.guest_cid,
            host_sock,
            epoll,
            rxq: MuxerRxQ::new(),
            conn_map: HashMap::with_capacity(defs::MAX_CONNECTIONS),
            listener_map: HashMap::with_capacity(defs::MAX_CONNECTIONS + 1),
            partial_command_map: Default::default(),
            killq: MuxerKillQ::new(),
            local_port_last: (1u32 << 30) - 1,
            local_port_map: HashMap::with_capacity(defs::MAX_CONNECTIONS),
            // boxcar: the rules that decide a guest's connection requests.
            rules: Rules::new(&cfg.uds_path, allow_ports, services),
            // boxcar: where `vsock.connect` and `vsock.close` go.
            audit,
            // boxcar: the connections a `vsock.connect` let through, whose end is recorded.
            audited: HashMap::new(),
            // boxcar: when each host client must have sent its whole `CONNECT` line.
            command_deadlines: HashMap::new(),
            // boxcar: armed for the earliest of those deadlines.
            command_timer: TimerFd::new().map_err(|e| Error::CommandTimer(e.into()))?,
            // boxcar: `CONNECT_TIMEOUT`, shorter in tests.
            command_timeout: CONNECT_TIMEOUT,
            // boxcar: connections and host clients still sending their line, together.
            max_connections: defs::MAX_CONNECTIONS,
        };

        muxer.add_listener(muxer.host_sock.as_raw_fd(), EpollListener::HostSock)?;
        // boxcar: the `CONNECT` deadlines' timer is watched with the rest.
        muxer.add_listener(muxer.command_timer.as_raw_fd(), EpollListener::CommandTimer)?;
        Ok(muxer)
    }

    // boxcar: the end of an activation.
    /// Removes every connection, which closes its host end, recording `vsock.close` for each
    /// one a `vsock.connect` let through. The device thread calls it when the device is reset.
    pub fn close_all(&mut self) {
        let keys: Vec<ConnMapKey> = self.conn_map.keys().copied().collect();
        for key in keys {
            self.remove_connection(key);
        }
    }

    /// Handle/dispatch an epoll event to its listener.
    ///
    fn handle_event(&mut self, fd: RawFd, event_set: EventSet) {
        match self.listener_map.get_mut(&fd) {
            // This event needs to be forwarded to a `MuxerConnection` that is listening for
            // it.
            //
            Some(EpollListener::Connection { key, evset: _ }) => {
                let key_copy = *key;
                // The handling of this event will most probably mutate the state of the
                // receiving connection. We'll need to check for new pending RX, event set
                // mutation, and all that, so we're wrapping the event delivery inside those
                // checks.
                self.apply_conn_mutation(key_copy, |conn| {
                    conn.notify(event_set);
                });
            }

            // A new host-initiated connection is ready to be accepted.
            //
            Some(EpollListener::HostSock) => {
                // boxcar: host clients still sending their `CONNECT` line count too.
                if self.conn_map.len() + self.command_deadlines.len() >= self.max_connections {
                    // If we're already maxed-out on connections, we'll just accept and
                    // immediately discard this potentially new one.
                    boxcar_virtio::limited!(
                        warn,
                        "vsock: connection limit reached; refusing new host connection"
                    );
                    let _ = self.host_sock.accept();
                    return;
                }
                self.host_sock
                    .accept()
                    .map_err(Error::UnixAccept)
                    .and_then(|(stream, _)| {
                        stream
                            .set_nonblocking(true)
                            .map(|_| stream)
                            .map_err(Error::UnixAccept)
                    })
                    .and_then(|stream| {
                        // Before forwarding this connection to a listening AF_VSOCK socket on
                        // the guest side, we need to know the destination port. We'll read
                        // that port from a "connect" command received on this socket, so the
                        // next step is to ask to be notified the moment we can read from it.
                        // boxcar: the fd, for its `CONNECT` deadline.
                        let fd = stream.as_raw_fd();
                        self.add_listener(fd, EpollListener::LocalStream(stream))
                            .map(|()| fd)
                    })
                    .map(|fd| {
                        // boxcar: and to have it within `CONNECT_TIMEOUT`.
                        self.command_deadlines
                            .insert(fd, Instant::now() + self.command_timeout);
                        self.arm_command_timer();
                    })
                    .unwrap_or_else(|err| {
                        boxcar_virtio::limited!(
                            warn,
                            "vsock: unable to accept local connection: {err:?}"
                        );
                    });
            }

            // Data is ready to be read from a host-initiated connection. That would be the
            // "connect" command that we're expecting.
            Some(EpollListener::LocalStream(_)) => {
                if let Some(EpollListener::LocalStream(stream)) = self.listener_map.get_mut(&fd) {
                    let command = self
                        .partial_command_map
                        .entry(stream.as_raw_fd())
                        .or_default();
                    let port = Self::read_local_stream_port(command, stream);

                    if matches!(&port, Err(Error::UnixRead(e)) if e.kind() == ErrorKind::WouldBlock)
                    {
                        return;
                    }

                    // either we have `Ok(port)` or a fatal Error such as
                    // Error::InvalidPortRequest, either way we must remove
                    // the command from the map
                    self.partial_command_map.remove(&stream.as_raw_fd());
                    // boxcar: no deadline any more; the timer goes on to the next one, or finds
                    // none when it fires.
                    self.command_deadlines.remove(&stream.as_raw_fd());

                    // boxcar: just found as a `LocalStream`; a `let`-`else` for `unreachable!`.
                    let Some(EpollListener::LocalStream(stream)) = self.remove_listener(fd) else {
                        return;
                    };

                    port.and_then(|peer_port| {
                        let local_port = self.allocate_local_port(peer_port);

                        self.add_connection(
                            ConnMapKey {
                                local_port,
                                peer_port,
                            },
                            MuxerConnection::new_local_init(
                                stream,
                                uapi::VSOCK_HOST_CID,
                                self.cid,
                                local_port,
                                peer_port,
                            ),
                        )
                    })
                    .unwrap_or_else(|err| {
                        boxcar_virtio::limited!(
                            debug,
                            "vsock: error adding local-init connection: {err:?}"
                        );
                    });
                }
            }

            // boxcar: a `CONNECT` deadline passed.
            Some(EpollListener::CommandTimer) => self.expire_commands(),

            _ => {
                boxcar_virtio::limited!(
                    debug,
                    "vsock: unexpected event: fd={fd:?}, event_set={event_set:?}"
                );
            }
        }
    }

    // boxcar: the `CONNECT` deadlines.
    /// Closes every host client whose `CONNECT` deadline has passed, and arms the timer for
    /// the next deadline.
    fn expire_commands(&mut self) {
        let now = Instant::now();
        let expired: Vec<RawFd> = self
            .command_deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(fd, _)| *fd)
            .collect();
        for fd in expired {
            self.command_deadlines.remove(&fd);
            self.partial_command_map.remove(&fd);
            // Dropping the stream closes it: the client reads EOF, with no `OK`.
            self.remove_listener(fd);
            boxcar_virtio::limited!(
                debug,
                "vsock: a host client sent no CONNECT line within {:?}; closed",
                self.command_timeout
            );
        }
        self.arm_command_timer();
    }

    /// Arms the timer for the earliest `CONNECT` deadline, or disarms it when there is none.
    /// Either resets its expiration count, so the timer is never read.
    fn arm_command_timer(&mut self) {
        let next = self.command_deadlines.values().min().copied();
        let armed = match next {
            None => self.command_timer.clear(),
            // At least 1 ms: a zero duration would disarm it.
            Some(at) => self.command_timer.reset(
                at.saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1)),
                None,
            ),
        };
        if let Err(err) = armed {
            boxcar_virtio::limited!(warn, "vsock: cannot arm the CONNECT deadline timer: {err}");
        }
    }

    fn parse_port_from_read_command(command: &PartiallyReadCommand) -> Result<u32> {
        // normally followed by the port and a `\n`
        let connect_prefix: &str = "connect ";

        let opt_new_line_position = command.buf[..command.len].iter().position(|x| *x == b'\n');

        // we need to read more to get a `connect ` statement
        if command.len < connect_prefix.len() {
            return match opt_new_line_position {
                Some(_) => Err(Error::InvalidPortRequest),
                None => Err(Error::UnixRead(io::ErrorKind::WouldBlock.into())),
            };
        }

        // check for both upper and lower case connect statements
        if !command.buf[..connect_prefix.len()].eq_ignore_ascii_case(connect_prefix.as_bytes()) {
            return Err(Error::InvalidPortRequest);
        }

        // we filled our buffer
        if command.buf.len() == command.len && opt_new_line_position.is_none() {
            return Err(Error::InvalidPortRequest);
        }

        // we parsed correctly `connect ` but need to wait for `\n`
        let new_line_position =
            opt_new_line_position.ok_or(Error::UnixRead(io::ErrorKind::WouldBlock.into()))?;

        // we now have the newline, we will treat everything in between as the port
        let port_string_as_bytes = &command.buf[connect_prefix.len()..new_line_position];

        str::from_utf8(port_string_as_bytes)
            .map_err(|_| Error::InvalidPortRequest)?
            .trim()
            .parse::<u32>()
            .map_err(|_| Error::InvalidPortRequest)
    }

    /// Parse a host "connect" command, and extract the destination vsock port.
    ///
    fn read_local_stream_port(
        command: &mut PartiallyReadCommand,
        stream: &mut UnixStream,
    ) -> Result<u32> {
        // the minimum connect statement that is still valid
        let connect_min_statement: &str = "connect 0\n";

        // read the amount of bytes that are required for a valid connect
        // with the minimum length (`connect_min_statement`).
        // Then, continue with reading a single byte at a time, this is
        // really inefficient but prevents us to read past the `\n` character
        // which might swallow actual application data
        // alternative: the bytes that might have been read beyond `\n` would need
        // to be sent somehow via `MuxerConnection` prior to reading from `stream` again
        // Another, currently unstable alternative: use UnixStream::peak to read the
        // data without removing it from the queue.
        // Issue: https://github.com/rust-lang/rust/issues/76923
        let read_bytes = stream
            .read(&mut command.buf[command.len..max(connect_min_statement.len(), command.len + 1)])
            .map_err(Error::UnixRead)?;

        if read_bytes == 0 {
            return Err(Error::InvalidPortRequest);
        }

        command.len += read_bytes;
        Self::parse_port_from_read_command(command)
    }

    /// Add a new connection to the active connection pool.
    ///
    fn add_connection(&mut self, key: ConnMapKey, conn: MuxerConnection) -> Result<()> {
        // We might need to make room for this new connection, so let's sweep the kill queue
        // first.  It's fine to do this here because:
        // - unless the kill queue is out of sync, this is a pretty inexpensive operation; and
        // - we are under no pressure to respect any accurate timing for connection
        //   termination.
        self.sweep_killq();

        // boxcar: host clients still sending their `CONNECT` line count too.
        if self.conn_map.len() + self.command_deadlines.len() >= self.max_connections {
            boxcar_virtio::limited!(
                warn,
                "vsock: muxer connection limit reached ({})",
                defs::MAX_CONNECTIONS
            );
            return Err(Error::TooManyConnections);
        }

        self.add_listener(
            conn.get_polled_fd(),
            EpollListener::Connection {
                key,
                evset: conn.get_polled_evset(),
            },
        )
        .map(|_| {
            if conn.has_pending_rx() {
                // We can safely ignore any error in adding a connection RX indication. Worst
                // case scenario, the RX queue will get desynchronized, but we'll handle that
                // the next time we need to yield an RX packet.
                self.rxq.push(MuxerRx::ConnRx(key));
            }
            self.conn_map.insert(key, conn);
        })
    }

    /// Remove a connection from the active connection poll.
    ///
    fn remove_connection(&mut self, key: ConnMapKey) {
        if let Some(conn) = self.conn_map.remove(&key) {
            self.remove_listener(conn.get_polled_fd());
            // boxcar: the end of a connection a `vsock.connect` let through.
            if let Some(dir) = self.audited.remove(&key) {
                let port = match dir {
                    Dir::Guest => key.local_port,
                    Dir::Host => key.peer_port,
                };
                rules::record_close(&self.audit, port, dir, conn.tx_bytes(), conn.rx_bytes());
            }
        }
        self.free_local_port(key);
    }

    /// Schedule a connection for immediate termination.
    /// I.e. as soon as we can also let our peer know we're dropping the connection, by sending
    /// it an RST packet.
    ///
    fn kill_connection(&mut self, key: ConnMapKey) {
        let mut had_rx = false;
        self.conn_map.entry(key).and_modify(|conn| {
            had_rx = conn.has_pending_rx();
            conn.kill();
        });
        // This connection will now have an RST packet to yield, so we need to add it to the RX
        // queue.  However, there's no point in doing that if it was already in the queue.
        if !had_rx {
            // We can safely ignore any error in adding a connection RX indication. Worst case
            // scenario, the RX queue will get desynchronized, but we'll handle that the next
            // time we need to yield an RX packet.
            self.rxq.push(MuxerRx::ConnRx(key));
        }
    }

    /// Register a new epoll listener under the muxer's nested epoll FD.
    ///
    fn add_listener(&mut self, fd: RawFd, listener: EpollListener) -> Result<()> {
        let evset = match listener {
            EpollListener::Connection { evset, .. } => evset,
            EpollListener::LocalStream(_) => EventSet::IN,
            EpollListener::HostSock => EventSet::IN,
            // boxcar: the `CONNECT` deadlines' timer.
            EpollListener::CommandTimer => EventSet::IN,
        };

        self.epoll
            .ctl(ControlOperation::Add, fd, EpollEvent::new(evset, fd as u64))
            .map(|_| {
                self.listener_map.insert(fd, listener);
            })
            .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove (and return) a previously registered epoll listener.
    ///
    fn remove_listener(&mut self, fd: RawFd) -> Option<EpollListener> {
        let maybe_listener = self.listener_map.remove(&fd);

        if maybe_listener.is_some() {
            self.epoll
                .ctl(ControlOperation::Delete, fd, EpollEvent::default())
                .unwrap_or_else(|err| {
                    boxcar_virtio::limited!(
                        warn,
                        "vsock muxer: error removing epoll listener for fd {fd:?}: {err:?}"
                    );
                });
        }

        maybe_listener
    }

    /// Allocate a host-side port to be assigned to a new host-initiated connection.
    ///
    fn allocate_local_port(&mut self, peer_port: u32) -> u32 {
        // TODO: this doesn't seem very space-efficient.
        // Maybe rewrite this to limit port range and use a bitmap?
        //

        loop {
            self.local_port_last = (self.local_port_last + 1) & !(1 << 31) | (1 << 30);
            if let Entry::Vacant(entry) = self.local_port_map.entry(self.local_port_last) {
                entry.insert(peer_port);
                break;
            }
        }
        self.local_port_last
    }

    /// Mark the host-side port allocated to `key`, if any, as free.
    ///
    fn free_local_port(&mut self, key: ConnMapKey) {
        if self.local_port_map.get(&key.local_port) == Some(&key.peer_port) {
            self.local_port_map.remove(&key.local_port);
        }
    }

    /// Handle a new connection request coming from our peer (the guest vsock driver).
    ///
    /// boxcar: the rules decide (`crate::rules`). A request they refuse is recorded and gets an
    /// RST. One they let through is recorded, and served by a VMM service through the stream it
    /// handed over, or connected to the host-side Unix socket expected to be listening at the
    /// file system path corresponding to the destination port. If that succeeds, a new
    /// connection object will be created and added to the connection pool. On failure, a new
    /// RST packet will be scheduled for delivery to the guest, and the connection's end is
    /// recorded at once.
    ///
    fn handle_peer_request_pkt(&mut self, pkt: &VsockPacket<'_>) {
        let (port, src_port) = (pkt.dst_port(), pkt.src_port());
        let (stream, peer) = match self.rules.decide(port, src_port) {
            Decision::Deny(peer, refusal) => {
                rules::record_connect(&self.audit, port, Dir::Guest, peer, src_port, Some(refusal));
                self.enq_rst(port, src_port);
                return;
            }
            Decision::Internal(stream) => (Ok(stream), Peer::Internal),
            // boxcar: without waiting, so a host service that does not accept cannot hold up
            // the vsock thread: a full accept queue refuses as a missing listener does.
            Decision::Uds(port_path) => (rules::connect_port_socket(&port_path), Peer::Uds),
        };
        rules::record_connect(&self.audit, port, Dir::Guest, peer, src_port, None);

        let key = ConnMapKey {
            local_port: port,
            peer_port: src_port,
        };
        let added = stream
            .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
            .map_err(Error::UnixConnect)
            .and_then(|stream| {
                self.add_connection(
                    key,
                    MuxerConnection::new_peer_init(
                        stream,
                        uapi::VSOCK_HOST_CID,
                        self.cid,
                        port,
                        src_port,
                        pkt.buf_alloc(),
                    ),
                )
            });
        match added {
            Ok(()) => {
                self.audited.insert(key, Dir::Guest);
                // boxcar: an internal port is taken only once its connection is added.
                if peer == Peer::Internal {
                    self.rules.served(port);
                }
            }
            Err(_) => {
                rules::record_close(&self.audit, port, Dir::Guest, 0, 0);
                self.enq_rst(port, src_port);
            }
        }
    }

    /// Perform an action that might mutate a connection's state.
    ///
    /// This is used as shorthand for repetitive tasks that need to be performed after a
    /// connection object mutates. E.g.
    /// - update the connection's epoll listener;
    /// - schedule the connection to be queried for RX data;
    /// - kill the connection if an unrecoverable error occurs.
    ///
    fn apply_conn_mutation<F>(&mut self, key: ConnMapKey, mut_fn: F)
    where
        F: FnOnce(&mut MuxerConnection),
    {
        if let Some(conn) = self.conn_map.get_mut(&key) {
            let had_rx = conn.has_pending_rx();
            let was_expiring = conn.will_expire();
            let prev_state = conn.state();

            mut_fn(conn);

            // If this is a host-initiated connection that has just become established, we'll have
            // to send an ack message to the host end.
            if prev_state == ConnState::LocalInit && conn.state() == ConnState::Established {
                // boxcar: the guest accepted a host connection: it is recorded, and its end
                // will be.
                rules::record_connect(
                    &self.audit,
                    key.peer_port,
                    Dir::Host,
                    Peer::Guest,
                    key.local_port,
                    None,
                );
                self.audited.insert(key, Dir::Host);
                let msg = format!("OK {}\n", key.local_port);
                match conn.send_bytes_raw(msg.as_bytes()) {
                    Ok(written) if written == msg.len() => (),
                    Ok(_) => {
                        // If we can't write a dozen bytes to a pristine connection something
                        // must be really wrong. Killing it.
                        conn.kill();
                        boxcar_virtio::limited!(
                            warn,
                            "vsock: unable to fully write connection ack msg."
                        );
                    }
                    Err(err) => {
                        conn.kill();
                        boxcar_virtio::limited!(
                            warn,
                            "vsock: unable to ack host connection: {err:?}"
                        );
                    }
                }
            }

            // If the connection wasn't previously scheduled for RX, add it to our RX queue.
            if !had_rx && conn.has_pending_rx() {
                self.rxq.push(MuxerRx::ConnRx(key));
            }

            // If the connection wasn't previously scheduled for termination, add it to the
            // kill queue.
            if !was_expiring && conn.will_expire() {
                // boxcar: `conn.will_expire()` guarantees an expiry; matched, not unwrapped.
                if let Some(expiry) = conn.expiry() {
                    self.killq.push(key, expiry);
                }
            }

            let fd = conn.get_polled_fd();
            let new_evset = conn.get_polled_evset();
            if new_evset.is_empty() {
                // If the connection no longer needs epoll notifications, remove its listener
                // from our list.
                self.remove_listener(fd);
                return;
            }
            if let Some(EpollListener::Connection { evset, .. }) = self.listener_map.get_mut(&fd) {
                if *evset != new_evset {
                    // If the set of events that the connection is interested in has changed,
                    // we need to update its epoll listener.
                    *evset = new_evset;
                    self.epoll
                        .ctl(
                            ControlOperation::Modify,
                            fd,
                            EpollEvent::new(new_evset, fd as u64),
                        )
                        .unwrap_or_else(|err| {
                            // This really shouldn't happen, like, ever. However, "famous last
                            // words" and all that, so let's just kill it with fire, and walk
                            // away.
                            self.kill_connection(key);
                            boxcar_virtio::limited!(
                                error,
                                "vsock: error updating epoll listener for (lp={}, pp={}): {:?}",
                                key.local_port,
                                key.peer_port,
                                err
                            );
                        });
                }
            } else {
                // The connection had previously asked to be removed from the listener map (by
                // returning an empty event set via `get_polled_fd()`), but now wants back in.
                self.add_listener(
                    fd,
                    EpollListener::Connection {
                        key,
                        evset: new_evset,
                    },
                )
                .unwrap_or_else(|err| {
                    self.kill_connection(key);
                    boxcar_virtio::limited!(
                        error,
                        "vsock: error updating epoll listener for (lp={}, pp={}): {:?}",
                        key.local_port,
                        key.peer_port,
                        err
                    );
                });
            }
        }
    }

    /// Check if any connections have timed out, and if so, schedule them for immediate
    /// termination.
    ///
    fn sweep_killq(&mut self) {
        while let Some(key) = self.killq.pop() {
            // Connections don't get removed from the kill queue when their kill timer is
            // disarmed, since that would be a costly operation. This means we must check if
            // the connection has indeed expired, prior to killing it.
            let mut kill = false;
            self.conn_map
                .entry(key)
                .and_modify(|conn| kill = conn.has_expired());
            if kill {
                self.kill_connection(key);
            }
        }

        if self.killq.is_empty() && !self.killq.is_synced() {
            self.killq = MuxerKillQ::from_conn_map(&self.conn_map);
            // If we've just re-created the kill queue, we can sweep it again; maybe there's
            // more to kill.
            self.sweep_killq();
        }
    }

    /// Enqueue an RST packet into `self.rxq`.
    ///
    /// Enqueue errors aren't propagated up the call chain, since there is nothing we can do to
    /// handle them. We do, however, log a warning, since not being able to enqueue an RST
    /// packet means we have to drop it, which is not normal operation.
    ///
    fn enq_rst(&mut self, local_port: u32, peer_port: u32) {
        let pushed = self.rxq.push(MuxerRx::RstPkt {
            local_port,
            peer_port,
        });
        if !pushed {
            boxcar_virtio::limited!(
                warn,
                "vsock: muxer.rxq full; dropping RST packet for lp={local_port}, pp={peer_port}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::min;
    use std::io::Write;
    use std::net::Shutdown;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use std::{fs, thread};

    use boxcar_audit::{WriterConfig, WriterHandle};
    use boxcar_proto::SessionId;
    use tempfile::TempDir;

    use super::super::super::csm::defs as csm_defs;
    use super::super::super::packet_ext::testing::PacketBuf;
    use super::super::super::packet_ext::PacketExt;
    use super::super::super::services::{ConnMeta, Deny};
    use super::*;

    impl PartiallyReadCommand {
        /// used to construct `PartiallyReadCommand` for tests
        fn from_str(s: &str) -> Self {
            let input_bytes = s.as_bytes();
            let mut command = PartiallyReadCommand::default();
            let len_to_copy = min(input_bytes.len(), PARTIALLY_READ_COMMAND_BUF_SIZE);
            command.buf[..len_to_copy].copy_from_slice(&input_bytes[..len_to_copy]);
            command.len = len_to_copy;
            command
        }
    }

    const PEER_CID: u64 = 3;
    const PEER_BUF_ALLOC: u32 = 64 * 1024;
    // boxcar: the host ports the guest connects to in these tests: outside the internal ports,
    // which the rules keep for the VMM, and allowlisted, so that they reach `<uds>_<port>` as in
    // Cloud Hypervisor. 2026 stands in for Cloud Hypervisor's 1026, and 1 << 30 is the first
    // port the muxer gives a host connection.
    const LOCAL_PORT_A: u32 = 2026;
    const ALLOWED: [u32; 2] = [LOCAL_PORT_A, 1 << 30];

    /// boxcar: serves no internal port.
    struct NoServices;

    impl InternalServices for NoServices {
        fn connect(&self, _port: u32, _meta: ConnMeta) -> std::result::Result<UnixStream, Deny> {
            Err(Deny::NoService)
        }
    }

    // boxcar: the packet is over plain buffers (`PacketBuf`) and the sockets are in a temporary
    // directory, with the session's audit log beside them. Field order is drop order: the
    // muxer, and its audit sink, before the log's writer.
    struct MuxerTestContext {
        pkt: PacketBuf,
        muxer: VsockMuxer,
        uds_path: PathBuf,
        _writer: WriterHandle,
        _dir: TempDir,
    }

    impl MuxerTestContext {
        fn new(name: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let (sink, writer) =
                boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new()))
                    .unwrap();
            let pkt = PacketBuf::new();
            let uds_path = dir.path().join(format!("test_vsock_{name}.sock"));
            let cfg = VsockConfig {
                guest_cid: PEER_CID,
                uds_path: uds_path.clone(),
                allow_ports: ALLOWED.to_vec(),
            };
            let listener = super::super::bind_listener(&uds_path).unwrap();
            let muxer = VsockMuxer::new(&cfg, listener, Arc::new(NoServices), sink).unwrap();

            Self {
                pkt,
                muxer,
                uds_path,
                _writer: writer,
                _dir: dir,
            }
        }

        fn init_pkt(
            &mut self,
            local_port: u32,
            peer_port: u32,
            op: u16,
        ) -> &mut VsockPacket<'static> {
            self.pkt
                .clear_hdr()
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_src_cid(PEER_CID)
                .set_dst_cid(uapi::VSOCK_HOST_CID)
                .set_src_port(peer_port)
                .set_dst_port(local_port)
                .set_op(op)
                .set_buf_alloc(PEER_BUF_ALLOC)
        }

        fn init_data_pkt(
            &mut self,
            local_port: u32,
            peer_port: u32,
            data: &[u8],
        ) -> &mut VsockPacket<'static> {
            assert!(data.len() <= self.pkt.buf_capacity().unwrap());
            self.init_pkt(local_port, peer_port, uapi::VSOCK_OP_RW)
                .set_len(data.len() as u32);
            self.pkt.copy_buf_from_slice(0, data).unwrap();
            &mut self.pkt
        }

        fn pkt_data(&self) -> Vec<u8> {
            let mut data = vec![0u8; self.pkt.len() as usize];
            self.pkt.copy_buf_to_slice(0, &mut data).unwrap();
            data
        }

        fn send(&mut self) {
            self.muxer.send_pkt(&self.pkt).unwrap();
        }

        fn recv(&mut self) {
            self.muxer.recv_pkt(&mut self.pkt).unwrap();
        }

        fn notify_muxer(&mut self) {
            self.muxer.notify(EventSet::IN);
        }

        fn count_epoll_listeners(&self) -> (usize, usize) {
            let mut local_lsn_count = 0usize;
            let mut conn_lsn_count = 0usize;
            for key in self.muxer.listener_map.values() {
                match key {
                    EpollListener::LocalStream(_) => local_lsn_count += 1,
                    EpollListener::Connection { .. } => conn_lsn_count += 1,
                    _ => (),
                }
            }
            (local_lsn_count, conn_lsn_count)
        }

        fn create_local_listener(&self, port: u32) -> LocalListener {
            LocalListener::new(rules::port_socket_path(&self.uds_path, port))
        }

        fn local_connect(&mut self, peer_port: u32) -> (UnixStream, u32) {
            let (init_local_lsn_count, init_conn_lsn_count) = self.count_epoll_listeners();

            let mut stream = UnixStream::connect(&self.uds_path).unwrap();
            stream.set_nonblocking(true).unwrap();
            // The muxer would now get notified of a new connection having arrived at its Unix
            // socket, so it can accept it.
            self.notify_muxer();

            // Just after having accepted a new local connection, the muxer should've added a new
            // `LocalStream` listener to its `listener_map`.
            let (local_lsn_count, _) = self.count_epoll_listeners();
            assert_eq!(local_lsn_count, init_local_lsn_count + 1);

            let buf = format!("CONNECT {peer_port}\n");
            stream.write_all(buf.as_bytes()).unwrap();
            // The muxer would now get notified that data is available for reading from the locally
            // initiated connection.
            // this needs to happen multiple times because the command may not be read at once
            for _ in 0..buf.len() {
                self.notify_muxer();
            }

            // Successfully reading and parsing the connection request should have removed the
            // LocalStream epoll listener and added a Connection epoll listener.
            let (local_lsn_count, conn_lsn_count) = self.count_epoll_listeners();
            assert_eq!(local_lsn_count, init_local_lsn_count);
            assert_eq!(conn_lsn_count, init_conn_lsn_count + 1);

            // A LocalInit connection should've been added to the muxer connection map.  A new
            // local port should also have been allocated for the new LocalInit connection.
            let local_port = self.muxer.local_port_last;
            let key = ConnMapKey {
                local_port,
                peer_port,
            };
            assert!(self.muxer.conn_map.contains_key(&key));
            assert_eq!(self.muxer.local_port_map.get(&local_port), Some(&peer_port));

            // A connection request for the peer should now be available from the muxer.
            assert!(self.muxer.has_pending_rx());
            self.recv();
            assert_eq!(self.pkt.op(), uapi::VSOCK_OP_REQUEST);
            assert_eq!(self.pkt.dst_port(), peer_port);
            assert_eq!(self.pkt.src_port(), local_port);

            self.init_pkt(local_port, peer_port, uapi::VSOCK_OP_RESPONSE);
            self.send();

            let mut buf = [0u8; 32];
            let len = stream.read(&mut buf[..]).unwrap();
            assert_eq!(&buf[..len], format!("OK {local_port}\n").as_bytes());

            (stream, local_port)
        }
    }

    struct LocalListener {
        path: PathBuf,
        sock: UnixListener,
    }
    impl LocalListener {
        fn new<P: AsRef<Path> + Clone>(path: P) -> Self {
            // Clear in case it is still there from a previous run
            let _ = fs::remove_file(path.as_ref());

            let path_buf = path.as_ref().to_path_buf();
            let sock = UnixListener::bind(path).unwrap();
            sock.set_nonblocking(true).unwrap();
            Self {
                path: path_buf,
                sock,
            }
        }
        fn accept(&mut self) -> UnixStream {
            let (stream, _) = self.sock.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            stream
        }
    }
    impl Drop for LocalListener {
        fn drop(&mut self) {
            fs::remove_file(&self.path).unwrap();
        }
    }

    #[test]
    fn test_muxer_epoll_listener() {
        let ctx = MuxerTestContext::new("muxer_epoll_listener");
        assert_eq!(ctx.muxer.get_polled_fd(), ctx.muxer.epoll.as_raw_fd());
        assert_eq!(ctx.muxer.get_polled_evset(), EventSet::IN);
    }

    #[test]
    fn test_bad_peer_pkt() {
        const LOCAL_PORT: u32 = LOCAL_PORT_A;
        const PEER_PORT: u32 = 1025;
        const SOCK_DGRAM: u16 = 2;

        let mut ctx = MuxerTestContext::new("bad_peer_pkt");
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST)
            .set_type(SOCK_DGRAM);
        ctx.send();

        // The guest sent a SOCK_DGRAM packet. Per the vsock spec, we need to reply with an RST
        // packet, since vsock only supports stream sockets.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        // Any orphan (i.e. without a connection), non-RST packet, should be replied to with an
        // RST.
        let bad_ops = [
            uapi::VSOCK_OP_RESPONSE,
            uapi::VSOCK_OP_CREDIT_REQUEST,
            uapi::VSOCK_OP_CREDIT_UPDATE,
            uapi::VSOCK_OP_SHUTDOWN,
            uapi::VSOCK_OP_RW,
        ];
        for op in bad_ops.iter() {
            ctx.init_pkt(LOCAL_PORT, PEER_PORT, *op);
            ctx.send();
            assert!(ctx.muxer.has_pending_rx());
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
            assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
            assert_eq!(ctx.pkt.dst_port(), PEER_PORT);
        }

        // Any packet addressed to anything other than VSOCK_VHOST_CID should get dropped.
        assert!(!ctx.muxer.has_pending_rx());
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST)
            .set_dst_cid(uapi::VSOCK_HOST_CID + 1);
        ctx.send();
        assert!(!ctx.muxer.has_pending_rx());

        // An orphan RST, however, must be absorbed silently.
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_RST);
        ctx.send();
        assert!(!ctx.muxer.has_pending_rx());
    }

    // Both ends of a vsock connection can close it at the same instant, in which case their
    // teardown packets cross in flight and the peer's RST arrives after we've already dropped
    // the connection. Answering that orphan RST is not just pointless but dangerous: by the
    // time the reply is delivered, the peer may have reused the port pair, and the reply will
    // kill that innocent connection instead.
    #[test]
    fn test_orphan_rst_does_not_kill_reused_port_pair() {
        const LOCAL_PORT: u32 = LOCAL_PORT_A;
        const PEER_PORT: u32 = 1025;

        let mut ctx = MuxerTestContext::new("orphan_rst_reused_port_pair");
        let mut listener = ctx.create_local_listener(LOCAL_PORT);
        let key = ConnMapKey {
            local_port: LOCAL_PORT,
            peer_port: PEER_PORT,
        };

        // Establish a peer-initiated connection, then tear it down from our end.
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        let _stream = listener.accept();
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        ctx.muxer.kill_connection(key);
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert!(!ctx.muxer.conn_map.contains_key(&key));

        // The peer's own RST, sent before it could have seen ours, now arrives for a connection
        // we no longer have.
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_RST);
        ctx.send();
        assert!(!ctx.muxer.has_pending_rx());

        // The peer's ephemeral port allocator hands out the same port again.
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        let _stream = listener.accept();
        assert!(ctx.muxer.conn_map.contains_key(&key));

        // The new connection must come up cleanly. A reply to the orphan RST would still be
        // queued ahead of this response, and delivering it would drop the new connection.
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert!(!ctx.muxer.has_pending_rx());
        assert!(ctx.muxer.conn_map.contains_key(&key));
    }

    #[test]
    fn test_peer_connection() {
        const LOCAL_PORT: u32 = LOCAL_PORT_A;
        const PEER_PORT: u32 = 1025;

        let mut ctx = MuxerTestContext::new("peer_connection");

        // Test peer connection refused.
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.len(), 0);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        // Test peer connection accepted.
        let mut listener = ctx.create_local_listener(LOCAL_PORT);
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        assert_eq!(ctx.muxer.conn_map.len(), 1);
        let mut stream = listener.accept();
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.pkt.len(), 0);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);
        let key = ConnMapKey {
            local_port: LOCAL_PORT,
            peer_port: PEER_PORT,
        };
        assert!(ctx.muxer.conn_map.contains_key(&key));

        // Test guest -> host data flow.
        let data = [1, 2, 3, 4];
        ctx.init_data_pkt(LOCAL_PORT, PEER_PORT, &data);
        ctx.send();
        let mut buf = vec![0; data.len()];
        stream.read_exact(buf.as_mut_slice()).unwrap();
        assert_eq!(buf.as_slice(), data);

        // Test host -> guest data flow.
        let data = [5u8, 6, 7, 8];
        stream.write_all(&data).unwrap();

        // When data is available on the local stream, an EPOLLIN event would normally be delivered
        // to the muxer's nested epoll FD. For testing only, we can fake that event notification
        // here.
        ctx.notify_muxer();
        // After being notified, the muxer should've figured out that RX data was available for one
        // of its connections, so it should now be reporting that it can fill in an RX packet.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RW);
        assert_eq!(ctx.pkt_data().as_slice(), data);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        assert!(!ctx.muxer.has_pending_rx());
    }

    #[test]
    fn test_local_connection() {
        let mut ctx = MuxerTestContext::new("local_connection");
        let peer_port = 1025;
        let (mut stream, local_port) = ctx.local_connect(peer_port);

        // Test guest -> host data flow.
        let data = [1, 2, 3, 4];
        ctx.init_data_pkt(local_port, peer_port, &data);
        ctx.send();

        let mut buf = vec![0u8; data.len()];
        stream.read_exact(buf.as_mut_slice()).unwrap();
        assert_eq!(buf.as_slice(), &data);

        // Test host -> guest data flow.
        let data = [5, 6, 7, 8];
        stream.write_all(&data).unwrap();
        ctx.notify_muxer();

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RW);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);
        assert_eq!(ctx.pkt_data().as_slice(), data);
    }

    #[test]
    fn test_local_close() {
        let peer_port = 1025;
        let mut ctx = MuxerTestContext::new("local_close");
        let local_port;
        {
            let (_stream, local_port_) = ctx.local_connect(peer_port);
            local_port = local_port_;
        }
        // Local var `_stream` was now dropped, thus closing the local stream. After the muxer gets
        // notified via EPOLLIN, it should attempt to gracefully shutdown the connection, issuing a
        // VSOCK_OP_SHUTDOWN with both no-more-send and no-more-recv indications set.
        ctx.notify_muxer();
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_SHUTDOWN);
        assert_ne!(ctx.pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND, 0);
        assert_ne!(ctx.pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV, 0);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);

        // The connection should get removed (and its local port freed), after the peer replies
        // with an RST.
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_RST);
        ctx.send();
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(!ctx.muxer.conn_map.contains_key(&key));
        assert!(!ctx.muxer.local_port_map.contains_key(&local_port));
    }

    // A guest-initiated connection whose guest-chosen destination port happens to collide
    // with a host-allocated local port must not release that port when it is torn down: the
    // host-initiated connection that actually owns the allocation is still using it
    #[test]
    fn test_peer_init_conn_does_not_free_host_local_port() {
        let host_peer_port = 1111;
        let guest_src_port = 2222;
        let mut ctx = MuxerTestContext::new("peer_init_conn_does_not_free_host_local_port");

        // Establish and take note of the local port allocated to it
        let (_host_stream, local_port) = ctx.local_connect(host_peer_port);
        let host_key = ConnMapKey {
            local_port,
            peer_port: host_peer_port,
        };
        assert!(ctx.muxer.conn_map.contains_key(&host_key));
        assert_eq!(
            ctx.muxer.local_port_map.get(&local_port),
            Some(&host_peer_port)
        );

        // open a second connection to that same local port, from a different
        // guest-side port. This needs a host listener at "<uds_path>_<local_port>", for
        // the muxer to connect to
        let _listener = ctx.create_local_listener(local_port);
        ctx.init_pkt(local_port, guest_src_port, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        let guest_key = ConnMapKey {
            local_port,
            peer_port: guest_src_port,
        };
        assert!(ctx.muxer.conn_map.contains_key(&guest_key));

        // breaking down the guest-initiated connection must leave the host-initiated one, and
        // its port allocation alone
        ctx.init_pkt(local_port, guest_src_port, uapi::VSOCK_OP_RST);
        ctx.send();
        assert!(!ctx.muxer.conn_map.contains_key(&guest_key));
        assert!(ctx.muxer.conn_map.contains_key(&host_key));
        assert_eq!(
            ctx.muxer.local_port_map.get(&local_port),
            Some(&host_peer_port)
        );
    }

    #[test]
    fn test_local_send_half_close() {
        let peer_port = 1025;
        let mut ctx = MuxerTestContext::new("local_send_half_close");
        let (mut stream, local_port) = ctx.local_connect(peer_port);

        stream.shutdown(Shutdown::Write).unwrap();
        ctx.notify_muxer();
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_SHUTDOWN);
        assert_ne!(ctx.pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND, 0);
        assert_eq!(ctx.pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV, 0);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);

        let data = [1, 2, 3, 4];
        ctx.init_data_pkt(local_port, peer_port, &data);
        ctx.send();

        let mut buf = vec![0u8; data.len()];
        stream.read_exact(buf.as_mut_slice()).unwrap();
        assert_eq!(buf.as_slice(), &data);

        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(ctx.muxer.conn_map.contains_key(&key));
    }

    #[test]
    fn test_peer_close() {
        let peer_port = 1025;
        let local_port = LOCAL_PORT_A;
        let mut ctx = MuxerTestContext::new("peer_close");

        let mut sock = ctx.create_local_listener(local_port);
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        let mut stream = sock.accept();

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(ctx.muxer.conn_map.contains_key(&key));

        // Emulate a full shutdown from the peer (no-more-send + no-more-recv).
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_SHUTDOWN)
            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_SEND)
            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_RCV);
        ctx.send();

        // Now, the muxer should remove the connection from its map, and reply with an RST.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.src_port(), local_port);
        assert_eq!(ctx.pkt.dst_port(), peer_port);
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(!ctx.muxer.conn_map.contains_key(&key));

        // The muxer should also drop / close the local Unix socket for this connection.
        let mut buf = vec![0u8; 16];
        assert_eq!(stream.read(buf.as_mut_slice()).unwrap(), 0);
    }

    #[test]
    fn test_peer_send_half_close() {
        // Regression test for the systemd sd_notify (vsock-stream) deadlock: the guest writes its
        // message, half-closes its send side, then waits for the host to close. The muxer must
        // surface the guest's half-close as an EOF on the host stream (while keeping the connection
        // alive), otherwise both ends block forever.
        let peer_port = 1025;
        let local_port = LOCAL_PORT_A;
        let mut ctx = MuxerTestContext::new("peer_send_half_close");

        let mut sock = ctx.create_local_listener(local_port);
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        let mut stream = sock.accept();

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);

        // The guest sends its message, then half-closes its send side.
        let data = &[1, 2, 3, 4];
        ctx.init_data_pkt(local_port, peer_port, data);
        ctx.send();
        ctx.init_pkt(local_port, peer_port, uapi::VSOCK_OP_SHUTDOWN)
            .set_flag(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
        ctx.send();

        // The host should read the message followed by an EOF, and the connection should still be
        // alive (the muxer did not tear it down).
        let mut buf = vec![0u8; 16];
        assert_eq!(stream.read(buf.as_mut_slice()).unwrap(), data.len());
        assert_eq!(&buf[..data.len()], data);
        assert_eq!(stream.read(buf.as_mut_slice()).unwrap(), 0);
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        assert!(ctx.muxer.conn_map.contains_key(&key));
    }

    #[test]
    fn test_muxer_rxq() {
        let mut ctx = MuxerTestContext::new("muxer_rxq");
        let local_port = LOCAL_PORT_A;
        let peer_port_first = 1025;
        let mut listener = ctx.create_local_listener(local_port);
        let mut streams: Vec<UnixStream> = Vec::new();

        for peer_port in peer_port_first..peer_port_first + defs::MUXER_RXQ_SIZE {
            ctx.init_pkt(local_port, peer_port as u32, uapi::VSOCK_OP_REQUEST);
            ctx.send();
            streams.push(listener.accept());
        }

        // The muxer RX queue should now be full (with connection responses), but still
        // synchronized.
        assert!(ctx.muxer.rxq.is_synced());

        // One more queued reply should desync the RX queue.
        ctx.init_pkt(
            local_port,
            (peer_port_first + defs::MUXER_RXQ_SIZE) as u32,
            uapi::VSOCK_OP_REQUEST,
        );
        ctx.send();
        assert!(!ctx.muxer.rxq.is_synced());

        // With an out-of-sync queue, an RST should evict any non-RST packet from the queue, and
        // take its place. We'll check that by making sure that the last packet popped from the
        // queue is an RST.
        ctx.init_pkt(
            local_port + 1,
            peer_port_first as u32,
            uapi::VSOCK_OP_REQUEST,
        );
        ctx.send();

        for peer_port in peer_port_first..peer_port_first + defs::MUXER_RXQ_SIZE - 1 {
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
            // The response order should hold. The evicted response should have been the last
            // enqueued.
            assert_eq!(ctx.pkt.dst_port(), peer_port as u32);
        }
        // There should be one more packet in the queue: the RST.
        assert_eq!(ctx.muxer.rxq.len(), 1);
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);

        // The queue should now be empty, but out-of-sync, so the muxer should report it has some
        // pending RX.
        assert!(ctx.muxer.rxq.is_empty());
        assert!(!ctx.muxer.rxq.is_synced());
        assert!(ctx.muxer.has_pending_rx());

        // The next recv should sync the queue back up. It should also yield one of the two
        // responses that are still left:
        // - the one that desynchronized the queue; and
        // - the one that got evicted by the RST.
        ctx.recv();
        assert!(ctx.muxer.rxq.is_synced());
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);

        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
    }

    #[test]
    fn test_muxer_killq() {
        let mut ctx = MuxerTestContext::new("muxer_killq");
        let local_port = LOCAL_PORT_A;
        let peer_port_first = 1025;
        let peer_port_last = peer_port_first + defs::MUXER_KILLQ_SIZE;
        let mut listener = ctx.create_local_listener(local_port);

        for peer_port in peer_port_first..=peer_port_last {
            ctx.init_pkt(local_port, peer_port as u32, uapi::VSOCK_OP_REQUEST);
            ctx.send();
            ctx.notify_muxer();
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
            assert_eq!(ctx.pkt.src_port(), local_port);
            assert_eq!(ctx.pkt.dst_port(), peer_port as u32);
            {
                let _stream = listener.accept();
            }
            ctx.notify_muxer();
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_SHUTDOWN);
            assert_eq!(ctx.pkt.src_port(), local_port);
            assert_eq!(ctx.pkt.dst_port(), peer_port as u32);
            // The kill queue should be synchronized, up until the `defs::MUXER_KILLQ_SIZE`th
            // connection we schedule for termination.
            assert_eq!(
                ctx.muxer.killq.is_synced(),
                peer_port < peer_port_first + defs::MUXER_KILLQ_SIZE
            );
        }

        assert!(!ctx.muxer.killq.is_synced());
        assert!(!ctx.muxer.has_pending_rx());

        // Wait for the kill timers to expire.
        thread::sleep(Duration::from_millis(csm_defs::CONN_SHUTDOWN_TIMEOUT_MS));

        // Trigger a kill queue sweep, by requesting a new connection.
        ctx.init_pkt(
            local_port,
            peer_port_last as u32 + 1,
            uapi::VSOCK_OP_REQUEST,
        );
        ctx.send();

        // After sweeping the kill queue, it should now be synced (assuming the RX queue is larger
        // than the kill queue, since an RST packet will be queued for each killed connection).
        assert!(ctx.muxer.killq.is_synced());
        assert!(ctx.muxer.has_pending_rx());
        // There should be `defs::MUXER_KILLQ_SIZE` RSTs in the RX queue, from terminating the
        // dying connections in the recent killq sweep.
        for _p in peer_port_first..peer_port_last {
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
            assert_eq!(ctx.pkt.src_port(), local_port);
        }

        // There should be one more packet in the RX queue: the connection response our request
        // that triggered the kill queue sweep.
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
        assert_eq!(ctx.pkt.dst_port(), peer_port_last as u32 + 1);

        assert!(!ctx.muxer.has_pending_rx());
    }

    #[test]
    fn test_regression_handshake() {
        // Address one of the issues found while fixing the following issue:
        // https://github.com/firecracker-microvm/firecracker/issues/1751
        // This test checks that the handshake message is not accounted for
        let mut ctx = MuxerTestContext::new("regression_handshake");
        let peer_port = 1025;

        // Create a local connection.
        let (_, local_port) = ctx.local_connect(peer_port);

        // Get the connection from the connection map.
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        let conn = ctx.muxer.conn_map.get_mut(&key).unwrap();

        // Check that fwd_cnt is 0 - "OK ..." was not accounted for.
        assert_eq!(conn.fwd_cnt().0, 0);
    }

    #[test]
    fn test_regression_rxq_pop() {
        // Address one of the issues found while fixing the following issue:
        // https://github.com/firecracker-microvm/firecracker/issues/1751
        // This test checks that a connection is not popped out of the muxer
        // rxq when multiple flags are set
        let mut ctx = MuxerTestContext::new("regression_rxq_pop");
        let peer_port = 1025;
        let (mut stream, local_port) = ctx.local_connect(peer_port);

        // Send some data.
        let data = [5u8, 6, 7, 8];
        stream.write_all(&data).unwrap();
        ctx.notify_muxer();

        // Get the connection from the connection map.
        let key = ConnMapKey {
            local_port,
            peer_port,
        };
        let conn = ctx.muxer.conn_map.get_mut(&key).unwrap();

        // Forcefully insert another flag.
        conn.insert_credit_update();

        // Call recv twice in order to check that the connection is still
        // in the rxq.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();

        // Since initially the connection had two flags set, now there should
        // not be any pending RX in the muxer.
        assert!(!ctx.muxer.has_pending_rx());
    }

    // boxcar: a host client has `CONNECT_TIMEOUT` to send its whole `CONNECT` line, and counts
    // toward the connection limit while it does.
    #[test]
    fn a_host_client_slow_to_send_its_connect_line_is_dropped() {
        let mut ctx = MuxerTestContext::new("slow_connect");
        ctx.muxer.command_timeout = Duration::from_millis(100);

        // One client sends half a line, then nothing.
        let mut slow = UnixStream::connect(&ctx.uds_path).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        ctx.notify_muxer();
        slow.write_all(b"CONN").unwrap();
        ctx.notify_muxer();
        assert_eq!(ctx.count_epoll_listeners(), (1, 0));
        assert_eq!(ctx.muxer.command_deadlines.len(), 1);
        // Another one finishes in time, and is not dropped later.
        let (_fast, local_port) = ctx.local_connect(1025);
        let key = ConnMapKey {
            local_port,
            peer_port: 1025,
        };

        thread::sleep(Duration::from_millis(150));
        // The deadline timer fires: the muxer's epoll is readable.
        ctx.notify_muxer();
        assert_eq!(ctx.count_epoll_listeners(), (0, 1));
        assert!(ctx.muxer.command_deadlines.is_empty());
        let mut rest = Vec::new();
        slow.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        assert!(ctx.muxer.conn_map.contains_key(&key));
        assert!(!ctx.muxer.has_pending_rx());
        // With no deadline left, the timer is disarmed: nothing wakes the muxer.
        assert!(!ctx.muxer.command_timer.is_armed().unwrap());
    }

    #[test]
    fn host_clients_still_sending_their_connect_line_count_toward_the_limit() {
        let mut ctx = MuxerTestContext::new("connect_limit");
        ctx.muxer.max_connections = 2;
        let mut waiting = Vec::new();
        for _ in 0..2 {
            waiting.push(UnixStream::connect(&ctx.uds_path).unwrap());
            ctx.notify_muxer();
        }
        assert_eq!(ctx.count_epoll_listeners(), (2, 0));

        // A third is accepted and closed at once.
        let mut third = UnixStream::connect(&ctx.uds_path).unwrap();
        third
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        ctx.notify_muxer();
        let mut rest = Vec::new();
        third.read_to_end(&mut rest).unwrap();
        assert_eq!(ctx.count_epoll_listeners(), (2, 0));

        // And the guest cannot connect while they wait.
        let _listener = ctx.create_local_listener(LOCAL_PORT_A);
        ctx.init_pkt(LOCAL_PORT_A, 1025, uapi::VSOCK_OP_REQUEST);
        ctx.send();
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert!(ctx.muxer.conn_map.is_empty());
    }

    #[test]
    fn test_parse_command() {
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("")),
            Err(Error::UnixRead(_))
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("\n")),
            Err(Error::InvalidPortRequest)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("CONN\n")),
            Err(Error::InvalidPortRequest)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("FOO ")),
            Err(Error::UnixRead(_))
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("FOOFOOX ")),
            Err(Error::InvalidPortRequest)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("CONNECT ")),
            Err(Error::UnixRead(_))
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("connect ")),
            Err(Error::UnixRead(_))
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str("connect \n")),
            Err(Error::InvalidPortRequest)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "connect 1337"
            )),
            Err(Error::UnixRead(_))
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "connect -1337\n"
            )),
            Err(Error::InvalidPortRequest)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "connect 8589934592\n"
            )),
            Err(Error::InvalidPortRequest)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "CONNECT 👾\n"
            )),
            Err(Error::InvalidPortRequest)
        ));
        let max_buf_length_no_newline = "CONNECT                        1";
        assert_eq!(
            max_buf_length_no_newline.len(),
            PARTIALLY_READ_COMMAND_BUF_SIZE
        );
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                max_buf_length_no_newline
            )),
            Err(Error::InvalidPortRequest)
        ));
        let max_buf_length_correct = "CONNECT                       1\n";
        assert_eq!(
            max_buf_length_correct.len(),
            PARTIALLY_READ_COMMAND_BUF_SIZE
        );
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                max_buf_length_correct
            )),
            Ok(1)
        ));

        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "connect 0\n"
            )),
            Ok(0)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "connect 1337\n"
            )),
            Ok(1337)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "CONNECT 1337\n"
            )),
            Ok(1337)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "CONNECT  1337\n"
            )),
            Ok(1337)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "CONNECT 1337 \n"
            )),
            Ok(1337)
        ));
        assert!(matches!(
            VsockMuxer::parse_port_from_read_command(&PartiallyReadCommand::from_str(
                "CONNECT  1337 \n"
            )),
            Ok(1337)
        ));
    }
}
