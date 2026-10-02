// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Audited virtio-fs: `AuditFs` over the fuse-backend-rs passthrough filesystem.
//!
//! - [`share`]: a share's configuration and its passthrough `Config`.
//! - [`device`]: [`VirtioFs`], the virtio-fs device serving a share.
//! - [`audit_fs`]: [`AuditFs`], the `FileSystem` decorator that records.
//! - [`path_map`]: inode to path, without syscalls.
//! - [`handles`]: open handles and what went through them.
//! - [`hasher`]: content hashes for `fs.close`, off the reply path.
//! - `events` and `forward`: building submissions, and the `forward!` macro
//!   that delegates every trait method.

#[macro_use]
mod forward;

pub mod audit_fs;
pub mod device;
mod events;
pub mod handles;
pub mod hasher;
pub mod path_map;
pub mod share;

pub use audit_fs::{AuditFs, AuditFsOptions, AuditLevel};
pub use device::{FsError, FsServer, OpcodeCounts, VirtioFs, MAX_REQUEST_QUEUES};
pub use handles::{HandleEntry, HandleTable};
pub use hasher::{HashJob, HashWorker};
pub use path_map::{FileId, PathMap, PathText, ROOT_INO};
pub use share::{passthrough_config, CachePolicyKind, FsShareConfig};

#[cfg(test)]
mod dep_check {
    //! Pin-set canary for the rust-vmm and fuse-backend-rs dependency set.
    //!
    //! `fuse-backend-rs` (virtio-fs request parsing) and `virtio-vsock` (vsock
    //! packet parsing) both take a `virtio_queue::DescriptorChain` in their
    //! public API, and boxcar builds and drains chains with `virtio-queue`
    //! itself. Cargo will happily resolve two semver-incompatible `virtio-queue`
    //! releases side by side; the `DescriptorChain` types are then unrelated and
    //! a chain from one crate cannot be handed to the other. Nothing would
    //! notice until the first line of device code that mixes them.
    //!
    //! This test exists to catch a future pin change that splits the queue types
    //! (or the `vm-memory` types they are generic over). It builds one
    //! descriptor chain with `virtio-queue`'s mock split queue, hands it to
    //! `fuse_backend_rs::transport::Reader::from_descriptor_chain` and to
    //! `virtio_vsock::packet::VsockPacket::from_tx_virtq_chain`, and stops
    //! compiling if either crate expects a different `DescriptorChain`. What
    //! the two calls return is beside the point: that they type-check and
    //! return without panicking is the test.
    //!
    //! `virtio-vsock` is a dev-dependency of this crate only for this test, and
    //! `virtio-queue`'s `test-utils` feature (which exposes the mock) is enabled
    //! on the dev-dependency entry only, so neither reaches a shipped binary.

    use fuse_backend_rs::transport::Reader;
    use virtio_bindings::bindings::virtio_ring::VRING_DESC_F_WRITE;
    use virtio_queue::desc::{split::Descriptor as SplitDescriptor, RawDescriptor};
    use virtio_queue::mock::MockSplitQueue;
    use virtio_vsock::packet::VsockPacket;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    /// Guest RAM the canary allocates: 64 KiB at guest physical address 0.
    const GUEST_MEM_SIZE: usize = 64 * 1024;
    /// Split-queue size handed to the mock; its tables sit below 0x1000.
    const QUEUE_SIZE: u16 = 16;
    /// Payload limit passed to the vsock packet parser.
    const MAX_VSOCK_DATA: u32 = 4096;

    #[test]
    fn one_descriptor_chain_feeds_fuse_and_vsock() {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)])
            .expect("64 KiB of anonymous guest memory");

        // The mock lays the descriptor table and rings out from address 0 of
        // `mem`; the buffers the chain points at live above them.
        let queue = MockSplitQueue::new(&mem, QUEUE_SIZE);
        let mut chain = queue
            .build_desc_chain(&[
                // Device-readable request header.
                RawDescriptor::from(SplitDescriptor::new(0x1000, 0x100, 0, 0)),
                // Device-writable reply buffer.
                RawDescriptor::from(SplitDescriptor::new(
                    0x2000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
            ])
            .expect("mock chain of two descriptors");

        // Guard the harness: both consumers below must be fed a real chain,
        // not an empty one that would make them bail out before touching it.
        assert_eq!(chain.clone().count(), 2, "mock chain has two descriptors");

        // fuse-backend-rs takes the chain by value...
        let _ = Reader::from_descriptor_chain(&mem, chain.clone());
        // ...and virtio-vsock by mutable reference. Same chain type in both.
        let _ = VsockPacket::from_tx_virtq_chain(&mem, &mut chain, MAX_VSOCK_DATA);
    }
}
