// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! boxcar's rules for guest connections, and the `vsock.*` records: what
//! the ported muxer calls where Cloud Hypervisor's connects every guest
//! request to `<uds>_<port>`.
//!
//! A guest connection request (`VSOCK_OP_REQUEST` to the host CID) is
//! decided by `Rules::decide`:
//!
//! - to an internal port ([`INTERNAL_PORTS`](crate::services::INTERNAL_PORTS)):
//!   refused as `unprivileged` from a guest source port of 1024 or more, as
//!   `duplicate` once a connection to that port was served in this
//!   activation, as `no_service` when [`InternalServices::connect`] does
//!   not take it; otherwise served by the service, and the port is taken;
//! - to an allowlisted port: connected to the host socket `<uds>_<port>`;
//! - to any other port: refused as `port`.
//!
//! A refused request is reset and recorded as `vsock.connect` with verdict
//! `deny`. One that is let through is recorded as `vsock.connect` with
//! verdict `allow`, and its end as `vsock.close` with the payload bytes
//! each way; a host socket that does not answer is such an end, with no
//! bytes. A host connection (`CONNECT <port>` on the vsock socket) is
//! recorded once the guest accepts it, and its end too; one the guest
//! resets is not recorded. Records wait for room in the log: none is
//! dropped.

use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use boxcar_audit::{AuditSink, EmitError, Priority, Submission};
use boxcar_proto::{Payload, Ring, Verdict, VsockClose, VsockConnect};

use crate::services::{ConnMeta, InternalServices, PRIVILEGED_PORT_LIMIT};

/// Who opened a connection: the `dir` of its records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dir {
    /// The guest, to a host port.
    Guest,
    /// A host process, through the vsock socket, to a guest port.
    Host,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::Guest => "guest",
            Dir::Host => "host",
        }
    }
}

/// The other end of a connection: the `peer` of `vsock.connect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Peer {
    /// A VMM service on an internal port.
    Internal,
    /// The host socket `<uds>_<port>`.
    Uds,
    /// The guest, for a host connection.
    Guest,
}

impl Peer {
    fn as_str(self) -> &'static str {
        match self {
            Peer::Internal => "internal",
            Peer::Uds => "uds",
            Peer::Guest => "guest",
        }
    }
}

/// Why a guest connection was refused: the `reason` of `vsock.connect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// An internal port, from a guest source port of 1024 or more.
    Unprivileged,
    /// An internal port already served in this activation.
    Duplicate,
    /// An internal port no service took.
    NoService,
    /// A port that is not allowlisted.
    Port,
}

impl Refusal {
    fn as_str(self) -> &'static str {
        match self {
            Refusal::Unprivileged => "unprivileged",
            Refusal::Duplicate => "duplicate",
            Refusal::NoService => "no_service",
            Refusal::Port => "port",
        }
    }
}

/// What becomes of a guest connection request.
pub(crate) enum Decision {
    /// Served by a VMM service, through its end of a stream.
    Internal(UnixStream),
    /// To be connected to the host socket at this path.
    Uds(PathBuf),
    /// Reset.
    Deny(Peer, Refusal),
}

/// The rules of one activation: the allowlist, the services, and the
/// internal ports already served.
pub(crate) struct Rules {
    uds_path: PathBuf,
    allow_ports: HashSet<u32>,
    services: Arc<dyn InternalServices>,
    /// The internal ports a service took a connection on: each is served
    /// once an activation.
    served: HashSet<u32>,
}

impl Rules {
    pub(crate) fn new(
        uds_path: &Path,
        allow_ports: &[u32],
        services: Arc<dyn InternalServices>,
    ) -> Rules {
        Rules {
            uds_path: uds_path.to_owned(),
            allow_ports: allow_ports.iter().copied().collect(),
            services,
            served: HashSet::new(),
        }
    }

    /// Decides a guest request for host `port` from guest `src_port`: see
    /// the module docs.
    pub(crate) fn decide(&mut self, port: u32, src_port: u32) -> Decision {
        if crate::services::is_internal(port) {
            if src_port >= PRIVILEGED_PORT_LIMIT {
                return Decision::Deny(Peer::Internal, Refusal::Unprivileged);
            }
            if self.served.contains(&port) {
                return Decision::Deny(Peer::Internal, Refusal::Duplicate);
            }
            let meta = ConnMeta {
                guest_port: src_port,
            };
            return match self.services.connect(port, meta) {
                Some(stream) => {
                    self.served.insert(port);
                    Decision::Internal(stream)
                }
                None => Decision::Deny(Peer::Internal, Refusal::NoService),
            };
        }
        if self.allow_ports.contains(&port) {
            Decision::Uds(port_socket_path(&self.uds_path, port))
        } else {
            Decision::Deny(Peer::Uds, Refusal::Port)
        }
    }
}

/// The host socket a guest connection to an allowlisted `port` reaches:
/// `<uds_path>_<port>`.
pub fn port_socket_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut path = OsString::from(uds_path.as_os_str());
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

/// Records `vsock.connect` for a connection to `port` from `src_port`, let
/// through, or refused for `refusal`.
pub(crate) fn record_connect(
    audit: &AuditSink,
    port: u32,
    dir: Dir,
    peer: Peer,
    src_port: u32,
    refusal: Option<Refusal>,
) {
    record(
        audit,
        Payload::VsockConnect(VsockConnect {
            port,
            dir: dir.as_str().to_owned(),
            peer: peer.as_str().to_owned(),
            src_port,
            verdict: if refusal.is_some() {
                Verdict::Deny
            } else {
                Verdict::Allow
            },
            reason: refusal.map(|refusal| refusal.as_str().to_owned()),
        }),
    );
}

/// Records `vsock.close` for a connection to `port`, which carried `tx`
/// payload bytes from the guest and `rx` to it.
pub(crate) fn record_close(audit: &AuditSink, port: u32, dir: Dir, tx: u64, rx: u64) {
    record(
        audit,
        Payload::VsockClose(VsockClose {
            port,
            dir: dir.as_str().to_owned(),
            tx,
            rx,
        }),
    );
}

/// Records `payload`, waiting for room in the log. A log that is closed
/// (the session is ending) or has failed (the VMM stops on that) records
/// nothing more.
fn record(audit: &AuditSink, payload: Payload) {
    let submission = Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload,
        span: None,
        priority: Priority::Normal,
    };
    match audit.emit(submission) {
        Ok(()) | Err(EmitError::Closed | EmitError::Failed) => {}
        Err(error @ EmitError::Checkpoint) => {
            boxcar_virtio::limited!(error, "vsock: audit record refused: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Serves every internal port, and counts the connections it took.
    #[derive(Default)]
    struct Everything {
        taken: Mutex<Vec<(u32, ConnMeta)>>,
    }

    impl InternalServices for Everything {
        fn connect(&self, port: u32, meta: ConnMeta) -> Option<UnixStream> {
            self.taken.lock().unwrap().push((port, meta));
            UnixStream::pair().ok().map(|(ours, _theirs)| ours)
        }
    }

    /// Serves nothing.
    struct Nothing;

    impl InternalServices for Nothing {
        fn connect(&self, _port: u32, _meta: ConnMeta) -> Option<UnixStream> {
            None
        }
    }

    fn refusal(decision: Decision) -> Option<(Peer, Refusal)> {
        match decision {
            Decision::Deny(peer, refusal) => Some((peer, refusal)),
            Decision::Internal(_) | Decision::Uds(_) => None,
        }
    }

    #[test]
    fn an_internal_port_is_served_once_and_only_from_a_privileged_port() {
        let services = Arc::new(Everything::default());
        let mut rules = Rules::new(Path::new("/s/vsock.sock"), &[], services.clone());
        assert_eq!(
            refusal(rules.decide(1024, 1024)),
            Some((Peer::Internal, Refusal::Unprivileged))
        );
        assert!(matches!(rules.decide(1024, 1023), Decision::Internal(_)));
        assert_eq!(
            refusal(rules.decide(1024, 1022)),
            Some((Peer::Internal, Refusal::Duplicate))
        );
        // Each port is its own.
        assert!(matches!(rules.decide(1025, 1022), Decision::Internal(_)));
        assert_eq!(
            *services.taken.lock().unwrap(),
            [
                (1024, ConnMeta { guest_port: 1023 }),
                (1025, ConnMeta { guest_port: 1022 })
            ]
        );
    }

    /// A port nothing serves stays free: a service registered later takes
    /// the next privileged connection.
    #[test]
    fn an_internal_port_nothing_serves_is_refused_and_stays_free() {
        let mut rules = Rules::new(Path::new("/s/vsock.sock"), &[1026], Arc::new(Nothing));
        for _ in 0..2 {
            assert_eq!(
                refusal(rules.decide(1026, 1000)),
                Some((Peer::Internal, Refusal::NoService))
            );
        }
        assert!(rules.served.is_empty());
    }

    #[test]
    fn other_ports_reach_the_suffixed_socket_only_when_allowlisted() {
        let mut rules = Rules::new(Path::new("/s/vsock.sock"), &[5000], Arc::new(Nothing));
        match rules.decide(5000, 40_000) {
            Decision::Uds(path) => assert_eq!(path, Path::new("/s/vsock.sock_5000")),
            _ => panic!("5000 is allowlisted"),
        }
        assert_eq!(
            refusal(rules.decide(5001, 40_000)),
            Some((Peer::Uds, Refusal::Port))
        );
        // A privileged source port changes nothing outside the internal
        // ports.
        assert_eq!(
            refusal(rules.decide(22, 1000)),
            Some((Peer::Uds, Refusal::Port))
        );
    }

    #[test]
    fn the_words_are_the_schemas() {
        assert_eq!([Dir::Guest.as_str(), Dir::Host.as_str()], ["guest", "host"]);
        assert_eq!(
            [Peer::Internal, Peer::Uds, Peer::Guest].map(Peer::as_str),
            ["internal", "uds", "guest"]
        );
        assert_eq!(
            [
                Refusal::Unprivileged,
                Refusal::Duplicate,
                Refusal::NoService,
                Refusal::Port
            ]
            .map(Refusal::as_str),
            ["unprivileged", "duplicate", "no_service", "port"]
        );
    }
}
