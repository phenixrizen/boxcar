// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The packet the ported connection state machine and muxer work on.
//!
//! Cloud Hypervisor's vsock code has a `VsockPacket` of its own (its
//! `packet.rs`). boxcar drops it for rust-vmm's
//! [`virtio_vsock::packet::VsockPacket`] at the pinned 0.11, which parses
//! a chain the same way (a header descriptor, then an optional data
//! descriptor, or both in one) and keeps a private copy of the header it
//! read, so the guest cannot change a field after it was checked. The
//! header setters write through to guest memory at once, where Cloud
//! Hypervisor's copied the header back at the end (`commit_hdr`).
//!
//! What the ported code asks of a packet beyond 0.11's header accessors is
//! [`PacketExt`]: whether it has a data buffer and how big, the header
//! cleared, and the data moved between the packet and a host stream through
//! vm-memory 0.17's [`ReadVolatile`] and [`WriteVolatile`], straight between
//! guest memory and the socket.

use std::io;

use vm_memory::{Bytes, ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

/// virtio-vsock 0.11's packet over guest memory without dirty-page
/// tracking, as `vm_memory::GuestMemoryMmap` hands it out, or over plain
/// buffers ([`virtio_vsock::packet::VsockPacket::new`]).
pub type VsockPacket<'a> = virtio_vsock::packet::VsockPacket<'a, ()>;

/// What the ported connection state machine needs of a packet's data
/// buffer and header, on top of [`VsockPacket`]'s own accessors.
pub(crate) trait PacketExt {
    /// Zeroes every header field, in the packet and in guest memory.
    fn clear_hdr(&mut self) -> &mut Self;

    /// Whether the packet has a data buffer: an RX packet always does, a TX
    /// packet when its `len` is not 0.
    fn has_buf(&self) -> bool;

    /// The length of the data buffer, if there is one: for a TX packet its
    /// `len`, for an RX packet the room the driver gave.
    fn buf_capacity(&self) -> Option<usize>;

    /// Copies `dst.len()` bytes of the data buffer from `offset` into `dst`.
    fn copy_buf_to_slice(&self, offset: usize, dst: &mut [u8]) -> io::Result<()>;

    /// Reads at most `len` bytes from `reader` into the start of the data
    /// buffer, and returns how many it read.
    fn read_volatile_from<R: ReadVolatile>(
        &mut self,
        reader: &mut R,
        len: usize,
    ) -> io::Result<usize>;

    /// Writes the `len` bytes of the data buffer from `offset` to `writer`,
    /// as far as it takes them, and returns how many it took.
    fn write_volatile_to<W: WriteVolatile>(
        &self,
        writer: &mut W,
        offset: usize,
        len: usize,
    ) -> io::Result<usize>;

    /// Copies `src` into the data buffer at `offset`.
    #[cfg(test)]
    fn copy_buf_from_slice(&mut self, offset: usize, src: &[u8]) -> io::Result<()>;
}

impl PacketExt for VsockPacket<'_> {
    fn clear_hdr(&mut self) -> &mut Self {
        // Every field, 44 bytes in all: the setters cannot fail.
        self.set_src_cid(0)
            .set_dst_cid(0)
            .set_src_port(0)
            .set_dst_port(0)
            .set_len(0)
            .set_type(0)
            .set_op(0)
            .set_flags(0)
            .set_buf_alloc(0)
            .set_fwd_cnt(0)
    }

    fn has_buf(&self) -> bool {
        self.data_slice().is_some()
    }

    fn buf_capacity(&self) -> Option<usize> {
        self.data_slice().map(VolatileSlice::len)
    }

    fn copy_buf_to_slice(&self, offset: usize, dst: &mut [u8]) -> io::Result<()> {
        data(self)?
            .read_slice(dst, offset)
            .map_err(volatile_error_to_io)
    }

    fn read_volatile_from<R: ReadVolatile>(
        &mut self,
        reader: &mut R,
        len: usize,
    ) -> io::Result<usize> {
        let mut slice = data(self)?.subslice(0, len).map_err(volatile_error_to_io)?;
        reader
            .read_volatile(&mut slice)
            .map_err(volatile_error_to_io)
    }

    fn write_volatile_to<W: WriteVolatile>(
        &self,
        writer: &mut W,
        offset: usize,
        len: usize,
    ) -> io::Result<usize> {
        let slice = data(self)?
            .subslice(offset, len)
            .map_err(volatile_error_to_io)?;
        writer.write_volatile(&slice).map_err(volatile_error_to_io)
    }

    #[cfg(test)]
    fn copy_buf_from_slice(&mut self, offset: usize, src: &[u8]) -> io::Result<()> {
        data(self)?
            .write_slice(src, offset)
            .map_err(volatile_error_to_io)
    }
}

/// The packet's data buffer, or an error saying it has none.
fn data<'a, 'p>(pkt: &'p VsockPacket<'a>) -> io::Result<&'p VolatileSlice<'a, ()>> {
    pkt.data_slice()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing packet buffer"))
}

/// The I/O error inside a volatile memory error, or the error as I/O.
fn volatile_error_to_io(error: VolatileMemoryError) -> io::Error {
    match error {
        VolatileMemoryError::IOError(error) => error,
        other => io::Error::other(other),
    }
}

/// Test support: packets over plain buffers.
#[cfg(test)]
pub(crate) mod testing {
    use std::ops::{Deref, DerefMut};

    use virtio_vsock::packet::PKT_HEADER_SIZE;

    use super::VsockPacket;

    /// The data buffer of a [`PacketBuf`]: the size of the RX buffers Linux
    /// posts.
    pub(crate) const DATA_LEN: usize = 4096;

    /// A packet and the plain buffers it points into, which it owns, so the
    /// tests need no guest memory.
    pub(crate) struct PacketBuf {
        pkt: VsockPacket<'static>,
        _hdr: Box<[u8]>,
        _data: Box<[u8]>,
    }

    impl PacketBuf {
        /// A zeroed header and a [`DATA_LEN`]-byte data buffer.
        pub(crate) fn new() -> PacketBuf {
            let mut hdr = vec![0u8; PKT_HEADER_SIZE].into_boxed_slice();
            let mut data = vec![0u8; DATA_LEN].into_boxed_slice();
            // SAFETY: the two buffers are on the heap and live in the same
            // `PacketBuf` as the packet, so they outlive every use of it
            // (moving a `Box` does not move what it points to), and nothing
            // else touches them.
            let pkt = unsafe { VsockPacket::new(&mut hdr, Some(&mut data)) }
                .expect("a header of PKT_HEADER_SIZE bytes");
            PacketBuf {
                pkt,
                _hdr: hdr,
                _data: data,
            }
        }
    }

    impl Deref for PacketBuf {
        type Target = VsockPacket<'static>;

        fn deref(&self) -> &Self::Target {
            &self.pkt
        }
    }

    impl DerefMut for PacketBuf {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.pkt
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{PacketBuf, DATA_LEN};
    use super::*;

    #[test]
    fn the_buffer_moves_through_volatile_io() {
        let mut pkt = PacketBuf::new();
        assert!(pkt.has_buf());
        assert_eq!(pkt.buf_capacity(), Some(DATA_LEN));

        // In from a reader, at most `len` of what it has.
        let mut source: &[u8] = b"hello, vsock";
        assert_eq!(pkt.read_volatile_from(&mut source, 5).unwrap(), 5);
        let mut out = [0u8; 5];
        pkt.copy_buf_to_slice(0, &mut out).unwrap();
        assert_eq!(&out, b"hello");

        // Out to a writer, from an offset.
        pkt.copy_buf_from_slice(5, b", world").unwrap();
        let mut sink = Vec::new();
        assert_eq!(pkt.write_volatile_to(&mut sink, 2, 10).unwrap(), 10);
        assert_eq!(sink, b"llo, world");

        // Past the end of the buffer is an error, not a short copy.
        assert!(pkt.copy_buf_to_slice(DATA_LEN - 1, &mut [0u8; 2]).is_err());
        assert!(pkt.write_volatile_to(&mut Vec::new(), DATA_LEN, 1).is_err());
        assert!(pkt.read_volatile_from(&mut source, DATA_LEN + 1).is_err());
    }

    #[test]
    fn clearing_the_header_zeroes_every_field() {
        let mut pkt = PacketBuf::new();
        pkt.set_src_cid(3)
            .set_dst_cid(2)
            .set_src_port(1023)
            .set_dst_port(1024)
            .set_len(7)
            .set_type(1)
            .set_op(5)
            .set_flags(3)
            .set_buf_alloc(4096)
            .set_fwd_cnt(9);
        pkt.clear_hdr();
        let mut raw = [0xffu8; virtio_vsock::packet::PKT_HEADER_SIZE];
        pkt.header_slice().read_slice(&mut raw, 0).unwrap();
        assert_eq!(raw, [0u8; virtio_vsock::packet::PKT_HEADER_SIZE]);
        assert_eq!(
            (pkt.src_cid(), pkt.op(), pkt.len(), pkt.fwd_cnt()),
            (0, 0, 0, 0)
        );
    }
}
