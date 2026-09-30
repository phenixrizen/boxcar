// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Audit record schema and wire types shared by the host and the guest.
//!
//! - [`audit`]: the record envelope, its hash chain, and the typed payloads.
//! - [`guestcmd`]: the session command on the kernel command line.
//! - [`ids`]: session identifiers.
//! - [`limits`]: size limits for record fields, and the cut that enforces them.
//! - [`redact`]: scrubbing secrets out of a value before it is recorded.
//!
//! # Features
//!
//! `hash` (on by default) provides everything that needs blake3, which builds
//! C code: `Hash::from_blake3`, `Record::compute_hash`, and `genesis_prev`.
//! The static musl guest init depends on this crate without it. Every type
//! and its serialization, including the `b3:` text of `Hash`, works either
//! way.

pub mod audit;
pub mod guestcmd;
pub mod ids;
pub mod limits;
pub mod redact;

#[cfg(feature = "hash")]
pub use audit::genesis_prev;
pub use audit::{
    ArtifactRef, Attrib, Checkpoint, FsClose, FsCreate, FsDenied, FsFallocate, FsIo, FsLink,
    FsMkdir, FsMknod, FsMount, FsOpen, FsPathOp, FsRename, FsSetattr, FsSymlink, FsXattr, Hash,
    HashStatus, OpResult, ParseHashError, Payload, Record, Ring, SetAttr, ShareRef, Source,
    SpanRef, Subject, VmmStart, VmmStop, SCHEMA_VERSION,
};
pub use guestcmd::GuestCmdError;
pub use ids::{ParseSessionIdError, SessionId};
