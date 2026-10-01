// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The control socket: how a client drives a running VM, over the control
//! protocol of `boxcar_proto::control`.
//!
//! - [`server`]: [`ControlServer`] binds `<state>/control.sock` (mode 0600
//!   in a 0700 state directory, whatever the umask), accepts connections on
//!   a thread of its own, and closes every one when the VM stops.
//! - `conn`: one thread per connection: the hello, line framing with the
//!   1 MiB cap, the rate limit, and dispatch to [`Ops`].
//! - [`ops`]: [`Ops`], what the ops do, and [`VmmOps`], the VMM's.
//! - [`peercred`]: the peer's credentials, so that only the VMM's own user
//!   is served.

mod conn;
pub mod ops;
pub mod peercred;
pub mod server;

pub use ops::{ConnCtx, Ops, RawUpgrade, VmmOps};
pub use server::ControlServer;
