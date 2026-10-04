// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Audit record schema and wire types shared by the host and the guest.
//!
//! - [`audit`]: the record envelope, its hash chain, and the typed payloads.
//! - [`control`]: the control protocol, v1: requests, responses, events.
//! - [`guest`]: the guest control channel between init and the VMM.
//! - [`guestcmd`]: the session command on the kernel command line.
//! - [`ids`]: session identifiers.
//! - [`limits`]: size limits for record fields, and the cut that enforces them.
//! - [`redact`]: scrubbing secrets out of a value before it is recorded.
//! - [`sensor`]: the sensor stream from the guest's sensor to the VMM.
//!
//! # Features
//!
//! `hash` (on by default) provides everything that needs blake3, which builds
//! C code: `Hash::from_blake3`, `Record::compute_hash`, and `genesis_prev`.
//! The static musl guest init depends on this crate without it. Every type
//! and its serialization, including the `b3:` text of `Hash`, works either
//! way.

pub mod audit;
pub mod control;
pub mod guest;
pub mod guestcmd;
pub mod ids;
pub mod limits;
pub mod redact;
pub mod sensor;

#[cfg(feature = "hash")]
pub use audit::genesis_prev;
pub use audit::{
    ArtifactRef, Attrib, Checkpoint, ClockSync, ControlConnect, ControlStop, Evidence, Finding,
    FindingCategory, FsClose, FsCreate, FsDenied, FsFallocate, FsIo, FsLink, FsMkdir, FsMknod,
    FsMount, FsOpen, FsPathOp, FsRename, FsSetattr, FsSymlink, FsXattr, Hash, HashStatus, NetClose,
    NetConnect, NetDhcp, NetDns, NetDrop, NetTls, NetUdp, OpResult, ParseHashError, Payload,
    PolicyChanged, ProcConnectAttempt, ProcExec, ProcExit, ProcFileOpen, ProcFork, ProcHeartbeat,
    ProcLsmDeny, ProcMemfd, ProcSensorStatus, ProcTcpConnect, ProgramStatus, Record, Ring,
    SensorPhase, SessionExit, SessionStart, SetAttr, ShareRef, Source, SpanRef, Subject, Verdict,
    VmmStart, VmmStop, VsockClose, VsockConnect, SCHEMA_VERSION,
};
pub use guestcmd::GuestCmdError;
pub use ids::{ParseSessionIdError, SessionId};
