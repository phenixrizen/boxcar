// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Who is on the other end of a Unix socket.

use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr;

/// The process id, user id and group id of `stream`'s peer, from
/// `SO_PEERCRED`: the credentials it had when it connected.
pub fn peer_cred(stream: &UnixStream) -> io::Result<(u32, u32, u32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let size = mem::size_of::<libc::ucred>();
    let mut len = libc::socklen_t::try_from(size).map_err(io::Error::other)?;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`, a ucred,
    // and stores how many it wrote in `len`.
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(size) {
        return Err(io::Error::other(format!(
            "SO_PEERCRED returned {len} bytes, not {size}"
        )));
    }
    let pid = u32::try_from(cred.pid)
        .map_err(|_| io::Error::other(format!("SO_PEERCRED returned pid {}", cred.pid)))?;
    Ok((pid, cred.uid, cred.gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_of_a_socket_pair_is_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getuid and getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!(peer_cred(&a).unwrap(), (std::process::id(), uid, gid));
    }
}
