// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! OCI images: references, a registry client, a cache of verified blobs
//! and unpacked trees, and the unpacking itself. The plan is
//! `docs/plans/oci-image-cache.md`.

pub mod auth;
pub mod client;
pub mod decode;
pub mod defaults;
pub mod framer;
pub mod manifest;
pub mod pull;
pub mod reference;
pub mod store;
pub mod unpack;

#[cfg(test)]
pub(crate) mod testutil;
