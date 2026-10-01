// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from cloud-hypervisor virtio-devices/src/vsock/unix/mod.rs at commit 853c440425ebe23bcf5fb43d9058bd1d8a0abe2a.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors
//
// Cloud Hypervisor is https://github.com/cloud-hypervisor/cloud-hypervisor.
// Adapted: the muxer is exported under its own name, `bind_listener`
// (`// boxcar:`) binds the host socket, mode 0600, which the device keeps
// for every activation's muxer, and the error gains the `CONNECT` deadline
// timer's (`// boxcar:`).

//! This module implements the Unix Domain Sockets backend for vsock - a mediator between
//! guest-side AF_VSOCK sockets and host-side AF_UNIX sockets. The heavy lifting is performed by
//! `muxer::VsockMuxer`, a connection multiplexer that uses `super::csm::VsockConnection` for
//! handling vsock connection states.
//!
//! Check out `muxer.rs` for a more detailed explanation of the inner workings of this backend.

mod muxer;
mod muxer_killq;
mod muxer_rxq;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::{io, result};

pub use muxer::VsockMuxer;
use thiserror::Error;
pub use Error as VsockUnixError;

mod defs {
    /// Maximum number of established connections that we can handle.
    pub(super) const MAX_CONNECTIONS: usize = 1023;

    /// Size of the muxer RX packet queue.
    pub(super) const MUXER_RXQ_SIZE: usize = 256;

    /// Size of the muxer connection kill queue.
    pub(super) const MUXER_KILLQ_SIZE: usize = 128;
}

#[derive(Error, Debug)]
pub enum Error {
    /// Error registering a new epoll-listening FD.
    #[error("Error registering a new epoll-listening FD")]
    EpollAdd(#[source] io::Error),
    /// Error creating an epoll FD.
    #[error("Error creating an epoll FD")]
    EpollFdCreate(#[source] io::Error),
    /// The host made an invalid vsock port connection request.
    #[error("The host made an invalid vsock port connection request")]
    InvalidPortRequest,
    /// Error accepting a new connection from the host-side Unix socket.
    #[error("Error accepting a new connection from the host-side Unix socket")]
    UnixAccept(#[source] io::Error),
    /// Error binding to the host-side Unix socket.
    #[error("Error binding to the host-side Unix socket")]
    UnixBind(#[source] io::Error),
    /// Error connecting to a host-side Unix socket.
    #[error("Error connecting to a host-side Unix socket")]
    UnixConnect(#[source] io::Error),
    /// Error reading from host-side Unix socket.
    #[error("Error reading from host-side Unix socket")]
    UnixRead(#[source] io::Error),
    /// Muxer connection limit reached.
    #[error("Muxer connection limit reached")]
    TooManyConnections,
    // boxcar: the timer that drops host clients slow to send their `CONNECT` line.
    /// The `CONNECT` deadline timer could not be created.
    #[error("Error creating the CONNECT deadline timer")]
    CommandTimer(#[source] io::Error),
}

type Result<T> = result::Result<T, Error>;
type MuxerConnection = super::csm::VsockConnection<UnixStream>;

// boxcar: the host socket of the hybrid protocol, bound once for the
// device's life.

/// The mode of the host socket: the VMM's user only.
pub const LISTENER_MODE: u32 = 0o600;

/// Binds the host socket at `path`, where host processes connect to guest
/// ports with `CONNECT <port>\n`, makes it mode [`LISTENER_MODE`] (set, not
/// left to the umask, which is 0 once the VMM has imported its shares), and
/// makes it non-blocking. On failure nothing is left at `path` by this call.
pub fn bind_listener(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path).map_err(Error::UnixBind)?;
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(LISTENER_MODE))
        .and_then(|()| listener.set_nonblocking(true))
    {
        let _ = fs::remove_file(path);
        return Err(Error::UnixBind(error));
    }
    Ok(listener)
}
