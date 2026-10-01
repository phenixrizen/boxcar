// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! AF_VSOCK, init's side: the two connections to the VMM, from privileged
//! guest ports.
//!
//! The VMM serves its internal ports (1024 the control channel, 1025 the
//! session's terminal) only from a guest source port below 1024, which only
//! root may bind (`CAP_NET_BIND_SERVICE`, which init holds: the session's
//! drop happens in its own child), so no other process in the guest can
//! pose as init. Init binds 1023 for the control channel and 1022 for the
//! terminal before it connects.
//!
//! Through libc: nix's `socket` feature would bring a second `memoffset`
//! into the build.

use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::errno::Errno;

use crate::console::Failed;

/// The host's context id.
pub const HOST_CID: u32 = libc::VMADDR_CID_HOST;
/// `boxcar.ctl`, the control channel.
pub const CTL_PORT: u32 = 1024;
/// The guest port the control channel comes from.
pub const CTL_SOURCE_PORT: u32 = 1023;
/// `boxcar.pty`, the session's terminal.
pub const PTY_PORT: u32 = 1025;
/// The guest port the terminal comes from.
pub const PTY_SOURCE_PORT: u32 = 1022;

/// The vsock address of `port` at context `cid`.
pub fn address(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: sockaddr_vm is plain data; all zeroes is valid.
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;
    addr
}

/// A stream to the host's `port`, from the guest's `source_port`: bound,
/// then connected, close-on-exec, blocking. The kernel bounds the connect
/// (2 s by default) and the VMM answers at once, with the connection or a
/// reset.
pub fn connect(source_port: u32, port: u32) -> Result<OwnedFd, Failed> {
    // SAFETY: socket takes integer arguments only.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Failed::new("socket AF_VSOCK", Errno::last()));
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let local = address(libc::VMADDR_CID_ANY, source_port);
    // SAFETY: bind reads one sockaddr_vm of the size given.
    let rc = unsafe { libc::bind(fd.as_raw_fd(), addr_ptr(&local), ADDR_LEN) };
    if rc != 0 {
        return Err(Failed::new(
            &format!("bind vsock port {source_port}"),
            Errno::last(),
        ));
    }
    let remote = address(HOST_CID, port);
    // SAFETY: connect reads one sockaddr_vm of the size given.
    let rc = unsafe { libc::connect(fd.as_raw_fd(), addr_ptr(&remote), ADDR_LEN) };
    if rc != 0 {
        return Err(Failed::new(
            &format!("connect vsock {HOST_CID}:{port}"),
            Errno::last(),
        ));
    }
    Ok(fd)
}

/// The size of a vsock address, as the socket calls take it.
const ADDR_LEN: libc::socklen_t = mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;

fn addr_ptr(addr: &libc::sockaddr_vm) -> *const libc::sockaddr {
    (addr as *const libc::sockaddr_vm).cast()
}

/// Makes `fd` non-blocking, for the poll loop.
pub fn set_nonblocking(fd: RawFd) -> Result<(), Errno> {
    // SAFETY: fcntl with integer arguments only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(Errno::last());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// Closes the sending side of the stream `fd` (`shutdown(SHUT_WR)`): the
/// host reads its end. Best effort.
pub fn close_output(fd: RawFd) {
    // SAFETY: shutdown takes integer arguments only.
    unsafe { libc::shutdown(fd, libc::SHUT_WR) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ports_are_the_constraints() {
        assert_eq!(HOST_CID, 2);
        assert_eq!((CTL_PORT, CTL_SOURCE_PORT), (1024, 1023));
        assert_eq!((PTY_PORT, PTY_SOURCE_PORT), (1025, 1022));
    }

    #[test]
    fn an_address_is_a_cid_and_a_port() {
        let addr = address(HOST_CID, CTL_PORT);
        assert_eq!(i32::from(addr.svm_family), libc::AF_VSOCK);
        assert_eq!((addr.svm_cid, addr.svm_port), (2, 1024));
        let any = address(libc::VMADDR_CID_ANY, CTL_SOURCE_PORT);
        assert_eq!((any.svm_cid, any.svm_port), (u32::MAX, 1023));
    }
}
