// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The stream to the VMM: vsock port 1026 (`boxcar.sensor`), from the
//! guest's port 1021, which only root can bind; the VMM takes the first such
//! connection and refuses later ones.

use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The VMM's context id.
pub const HOST_CID: u32 = libc::VMADDR_CID_HOST;
/// The sensor stream's port on the host.
pub const SENSOR_PORT: u32 = 1026;
/// The guest port the sensor connects from: below 1024, as the host demands.
pub const SOURCE_PORT: u32 = 1021;

fn address(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: sockaddr_vm is plain data; all zeroes is valid.
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;
    addr
}

const ADDR_LEN: libc::socklen_t = mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;

/// A blocking, close-on-exec stream to the host's sensor port.
pub fn connect() -> io::Result<File> {
    // SAFETY: socket takes integer arguments only.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let local = address(libc::VMADDR_CID_ANY, SOURCE_PORT);
    // SAFETY: bind reads one sockaddr_vm of the size given.
    if unsafe { libc::bind(fd.as_raw_fd(), (&raw const local).cast(), ADDR_LEN) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let remote = address(HOST_CID, SENSOR_PORT);
    // SAFETY: connect reads one sockaddr_vm of the size given.
    if unsafe { libc::connect(fd.as_raw_fd(), (&raw const remote).cast(), ADDR_LEN) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(File::from(fd))
}
