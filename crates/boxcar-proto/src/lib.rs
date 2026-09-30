// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Audit record schema and wire types shared by the host and the guest.

/// Placeholder that proves the optional hashing dependencies resolve when the
/// `hash` feature is on. The audit record schema replaces it.
#[cfg(feature = "hash")]
pub use blake3::Hash as Blake3Hash;
