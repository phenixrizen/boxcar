// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The VMM's own services on vsock: the internal ports.
//!
//! Three host ports belong to the VMM rather than to a host socket: 1024
//! `boxcar.ctl` (the guest control channel), 1025 `boxcar.pty` (the agent's
//! terminal) and 1026 `boxcar.sensor` (reserved). A guest connection to one
//! of them is served by [`InternalServices::connect`], and only when it
//! comes from a guest source port below [`PRIVILEGED_PORT_LIMIT`] (which
//! only root can bind, so an unprivileged process in the guest cannot pose
//! as init) and is the first to that port since the device was activated
//! (so a process that got root later cannot take over a channel init
//! already holds). Any other guest connection to them is reset and
//! recorded as refused (see the muxer).

use std::os::unix::net::UnixStream;

/// `boxcar.ctl`: JSON lines between init and the VMM.
pub const CTL_PORT: u32 = 1024;
/// `boxcar.pty`: one JSON header line, then the agent's terminal bytes.
pub const PTY_PORT: u32 = 1025;
/// `boxcar.sensor`: reserved for M3.
pub const SENSOR_PORT: u32 = 1026;
/// The internal ports, which never reach a host socket.
pub const INTERNAL_PORTS: [u32; 3] = [CTL_PORT, PTY_PORT, SENSOR_PORT];
/// Guest source ports below this are privileged: only root binds them.
pub const PRIVILEGED_PORT_LIMIT: u32 = 1024;

/// Whether `port` is one of the [`INTERNAL_PORTS`].
pub fn is_internal(port: u32) -> bool {
    INTERNAL_PORTS.contains(&port)
}

/// What a service learns of a guest connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnMeta {
    /// The guest's source port: below [`PRIVILEGED_PORT_LIMIT`].
    pub guest_port: u32,
}

/// The VMM's services on the [`INTERNAL_PORTS`].
pub trait InternalServices: Send + Sync {
    /// A guest connection to the internal `port`, already found privileged
    /// and first, from the vsock thread. A service takes it by returning
    /// its end of a stream (one end of a `UnixStream::pair`, typically,
    /// whose other end it keeps): the guest's bytes are written to it and
    /// what the service writes to its own end reaches the guest. `None`
    /// when nothing serves `port` or the service will not take the
    /// connection: the guest's request is reset. It must not block.
    fn connect(&self, port: u32, meta: ConnMeta) -> Option<UnixStream>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_internal_ports_are_1024_to_1026() {
        assert_eq!(INTERNAL_PORTS, [1024, 1025, 1026]);
        for port in [1023, 1027, 0, 5000, u32::MAX] {
            assert!(!is_internal(port), "{port}");
        }
        assert!(INTERNAL_PORTS.iter().all(|&port| is_internal(port)));
        assert_eq!(PRIVILEGED_PORT_LIMIT, 1024);
    }
}
