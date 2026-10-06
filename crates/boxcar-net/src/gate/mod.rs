// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The model traffic gate: for a connection the policy marks `inspect`
//! ([`crate::policy::Policy::inspects`]), the relay ends the guest's TLS
//! itself, connects to the real host with its own TLS, relays the
//! plaintext unchanged both ways and observes it.
//!
//! - [`ca`]: the session's certificate authority, whose key never leaves
//!   the VMM, and the leaf certificates it signs for the names the guest
//!   connects to. The guest is told to trust the CA's certificate (init
//!   puts it in the trust store); that is the whole of what the guest
//!   gets.

pub mod ca;

pub use ca::{CaError, LeafTarget, SessionCa};
