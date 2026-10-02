// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
//
// Ported from cloud-hypervisor virtio-devices/src/vsock/mod.rs at commit 853c440425ebe23bcf5fb43d9058bd1d8a0abe2a.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Cloud Hypervisor is https://github.com/cloud-hypervisor/cloud-hypervisor.
// The BSD-3-Clause text referred to above (THIRD-PARTY) is in
// LICENSE-BSD-3-Clause. Adapted: the module list is boxcar's (no
// `packet.rs`, a device of its own, the rules and the services); the
// packet errors are virtio-vsock 0.11's, so only the channel's own two
// remain; event sets are vmm-sys-util's; the snapshot hooks
// (`VsockBackend`) and the device test harness are dropped; and the
// constants and traits are public, for the muxer's tests and the VMM.

//! boxcar's virtio-vsock device: a port of Cloud Hypervisor's vsock
//! connection state machine and Unix-socket muxer, behind a device of
//! boxcar's own.
//!
//! - [`device`]: [`VirtioVsock`], the device (type 19, CID 3 by default),
//!   and the `vsock` thread that serves its queues.
//! - [`unix`]: [`VsockMuxer`], which turns guest vsock connections into
//!   host Unix-socket connections and back, and the host socket where host
//!   processes reach guest ports with `CONNECT <port>\n` (the hybrid
//!   protocol: the answer is `OK <port>\n`).
//! - `csm`: the state machine of one connection, with flow control.
//! - [`rules`]: which guest connections the muxer lets through, and the
//!   `vsock.connect` and `vsock.close` records.
//! - [`services`]: the VMM's own services on the internal ports.
//!
//! The packets are rust-vmm's `virtio_vsock::packet::VsockPacket` (0.11),
//! not Cloud Hypervisor's; see `packet_ext`.

mod csm;
pub mod device;
mod packet_ext;
pub mod rules;
pub mod services;
pub mod unix;

use std::os::unix::io::RawFd;
use std::result;

use thiserror::Error;
use vmm_sys_util::epoll::EventSet;

pub use device::{VirtioVsock, VsockConfig};
pub use packet_ext::VsockPacket;
pub use rules::{port_socket_path, AllowPorts};
pub use services::{ConnMeta, Deny, InternalServices};
pub use unix::{bind_listener, VsockMuxer, VsockUnixError};

/// The vsock protocol's numbers.
pub mod defs {

    /// Max vsock packet data/buffer size.
    pub const MAX_PKT_BUF_SIZE: usize = 64 * 1024;

    /// The protocol's numbers, as Linux defines them.
    pub mod uapi {

        /// Vsock packet operation IDs.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Connection request.
        pub const VSOCK_OP_REQUEST: u16 = 1;
        /// Connection response.
        pub const VSOCK_OP_RESPONSE: u16 = 2;
        /// Connection reset.
        pub const VSOCK_OP_RST: u16 = 3;
        /// Connection clean shutdown.
        pub const VSOCK_OP_SHUTDOWN: u16 = 4;
        /// Connection data (read/write).
        pub const VSOCK_OP_RW: u16 = 5;
        /// Flow control credit update.
        pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
        /// Flow control credit update request.
        pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

        /// Vsock packet flags.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will receive no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will send no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

        /// Vsock packet type.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Stream / connection-oriented packet (the only currently valid type).
        pub const VSOCK_TYPE_STREAM: u16 = 1;

        /// The host's CID.
        pub const VSOCK_HOST_CID: u64 = 2;
    }
}

/// Why a channel could not fill in a packet.
#[derive(Debug, Error)]
pub enum VsockError {
    /// A data fetch was attempted when no data was available.
    #[error("A data fetch was attempted when no data was available")]
    NoData,
    /// A data buffer was expected for the provided packet, but it is missing.
    #[error("A data buffer was expected for the provided packet, but it is missing")]
    PktBufMissing,
}
type Result<T> = result::Result<T, VsockError>;

/// A passive, event-driven object, that needs to be notified whenever an epoll-able event occurs.
///
/// An event-polling control loop will use `get_polled_fd()` and `get_polled_evset()` to query
/// the listener for the file descriptor and the set of events it's interested in. When such an
/// event occurs, the control loop will route the event to the listener via `notify()`.
///
pub trait VsockEpollListener {
    /// Get the file descriptor the listener needs polled.
    fn get_polled_fd(&self) -> RawFd;

    /// Get the set of events for which the listener wants to be notified.
    fn get_polled_evset(&self) -> EventSet;

    /// Notify the listener that one or more events have occurred.
    fn notify(&mut self, evset: EventSet);
}

/// Trait to describe any channel that handles vsock packet traffic (sending and receiving packets)
///
/// Since we're implementing the device model here, our responsibility is to always process the sending of
/// packets (i.e. the TX queue). So, any locally generated data, addressed to the driver (e.g.
/// a connection response or RST), will have to be queued, until we get to processing the RX queue.
///
/// Note: `recv_pkt()` and `send_pkt()` are named analogous to `Read::read()` and `Write::write()`,
///       respectively. I.e.
///       - `recv_pkt(&mut pkt)` will read data from the channel, and place it into `pkt`; and
///       - `send_pkt(&pkt)` will fetch data from `pkt`, and place it into the channel.
pub trait VsockChannel {
    /// Read/receive an incoming packet from the channel.
    fn recv_pkt(&mut self, pkt: &mut VsockPacket<'_>) -> Result<()>;

    /// Write/send a packet through the channel.
    fn send_pkt(&mut self, pkt: &VsockPacket<'_>) -> Result<()>;

    /// Checks whether there is pending incoming data inside the channel, meaning that a subsequent
    /// call to `recv_pkt()` won't fail.
    fn has_pending_rx(&self) -> bool;
}
