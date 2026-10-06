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
//! - [`tls`]: the two legs of an inspected flow, sans I/O: the upstream
//!   handshake first, then the guest's with the leaf and the protocol
//!   upstream chose, then plaintext moved unchanged.
//! - [`observe`]: the channel to the `gate-observe` thread, which takes a
//!   copy of every plaintext byte and never holds the net thread.

pub mod ca;
pub mod observe;
pub mod tls;

pub use ca::{CaError, LeafTarget, SessionCa};
pub use observe::{Direction, Message, Observed, Observer};
pub use tls::{Inspect, InspectConfig, Phase};
