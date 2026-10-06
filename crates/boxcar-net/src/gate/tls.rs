// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The two TLS legs of an inspected flow, sans I/O.
//!
//! The guest's ClientHello, which the gate held, goes to a rustls
//! [`Acceptor`]. Before the guest is answered, the upstream leg (a rustls
//! client to the real host, with the host's trust store and the ALPN
//! protocols the guest offered) completes its handshake: only then does
//! the guest leg get its config, with the leaf for the name and exactly
//! the protocol upstream chose, so the guest can never negotiate what the
//! host did not. Then plaintext moves: what one leg's reader gives goes
//! to the other leg's writer unchanged, a copy going to the observer, each
//! direction held back by the far leg's room, and a close on one side
//! (a `close_notify`, or the guest's FIN) becomes a `close_notify` on the
//! other.
//!
//! The relay drives it: guest TLS bytes in through [`Inspect::guest_in`]
//! (as many as rustls takes; the rest stay in the smoltcp socket), guest
//! TLS bytes out through [`Inspect::guest_out`] (as far as the socket has
//! room), the host socket through [`Inspect::host_io`] (non-blocking),
//! and [`Inspect::step`] for the phases and the plaintext. Nothing here
//! blocks or logs.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::Arc;

use rustls::client::ClientConnection;
use rustls::crypto::CryptoProvider;
use rustls::server::{Accepted, Acceptor, ClientHello, ResolvesServerCert, ServerConnection};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, ServerName};

use super::ca::{LeafTarget, SessionCa};
use super::observe::Direction;

/// How much plaintext each leg buffers for the other before its reader
/// is left alone: the far leg's room.
pub const PLAINTEXT_BUFFER: usize = 64 * 1024;
/// How much plaintext one read takes.
const READ_CHUNK: usize = 16 * 1024;
/// How many host reads one `host_io` makes at most, so one busy flow
/// does not hold the net thread.
const HOST_READS: usize = 8;

/// Why the gate cannot be set up.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("no trusted root certificates: the host's store gave none")]
    NoRoots,
    #[error("rustls refuses the configuration: {0}")]
    Tls(#[from] rustls::Error),
}

/// What every inspected flow shares: the session CA, the upstream
/// client's template (the trust store), and the crypto provider.
pub struct InspectConfig {
    ca: Arc<SessionCa>,
    client: ClientConfig,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for InspectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectConfig")
            .field("ca", &self.ca)
            .finish_non_exhaustive()
    }
}

impl InspectConfig {
    /// A config trusting `roots` upstream (the host's store, plus any the
    /// test harness adds), signing leaves with `ca`.
    pub fn new(ca: Arc<SessionCa>, roots: RootCertStore) -> Result<InspectConfig, SetupError> {
        if roots.is_empty() {
            return Err(SetupError::NoRoots);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(InspectConfig {
            ca,
            client,
            provider,
        })
    }

    /// The host's own trust store, with `extra` added: what the upstream
    /// leg verifies the real host against.
    pub fn host_roots(extra: &[CertificateDer<'static>]) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        roots.add_parsable_certificates(extra.iter().cloned());
        roots
    }

    pub fn ca(&self) -> &Arc<SessionCa> {
        &self.ca
    }
}

/// Where an inspected flow stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The upstream handshake is under way; the guest waits.
    Upstream,
    /// The guest handshake is under way.
    Guest,
    /// Both handshakes done: plaintext moves.
    Relaying,
    /// Over, with the `net.inspect` result that says why.
    Failed(&'static str),
}

/// Serves one leaf, whatever the hello.
#[derive(Debug)]
struct OneLeaf(Arc<CertifiedKey>);

impl ResolvesServerCert for OneLeaf {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// The guest leg: taking the hello, then a connection.
enum Guest {
    Accepting {
        acceptor: Box<Acceptor>,
        accepted: Option<Box<Accepted>>,
    },
    Open(Box<ServerConnection>),
    /// Given up (a failure): no more bytes either way.
    Gone,
}

/// Plaintext read from one leg and not yet taken by the other.
#[derive(Default)]
struct Pending {
    bytes: Vec<u8>,
    at: usize,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn rest(&self) -> &[u8] {
        self.bytes.get(self.at..).unwrap_or(&[])
    }
}

/// What a round of host I/O came to.
#[derive(Debug, Default)]
pub struct HostIo {
    /// The host closed its side (EOF on the socket).
    pub eof: bool,
    /// The socket failed.
    pub error: Option<io::Error>,
}

/// What the flow negotiated, for `net.inspect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    pub alpn: Option<String>,
    pub version: Option<String>,
}

/// An inspected flow's two legs.
pub struct Inspect {
    cfg: Arc<InspectConfig>,
    name: Option<String>,
    target: LeafTarget,
    host: ClientConnection,
    guest: Guest,
    phase: Phase,
    /// Plaintext from the guest waiting for room on the host leg, and the
    /// other way.
    to_host: Pending,
    to_guest: Pending,
    /// The host socket gave EOF.
    host_eof: bool,
    /// A `close_notify` has been sent each way.
    host_notified: bool,
    guest_notified: bool,
    /// The guest's stream ended: its `close_notify`, or its FIN.
    guest_done: bool,
    /// rustls holds as much decrypted plaintext from that leg as it will
    /// (it refuses more TLS bytes with an `Other` error): no more is taken
    /// from that side until the relay has read some.
    host_plain_full: bool,
    guest_plain_full: bool,
    /// Plaintext bytes moved each way.
    pub to_host_bytes: u64,
    pub to_guest_bytes: u64,
}

impl std::fmt::Debug for Inspect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inspect")
            .field("name", &self.name)
            .field("phase", &self.phase)
            .field("to_host_bytes", &self.to_host_bytes)
            .field("to_guest_bytes", &self.to_guest_bytes)
            .finish_non_exhaustive()
    }
}

impl Inspect {
    /// Starts inspecting a flow to `dst` whose ClientHello `hello` named
    /// `name` (or nothing) and offered `alpn`: the upstream connection is
    /// made for that name (or the address), with those protocols, and the
    /// hello goes to the acceptor. The `net.inspect` result on failure.
    pub fn new(
        cfg: &Arc<InspectConfig>,
        name: Option<String>,
        dst: Ipv4Addr,
        alpn: &[String],
        hello: &[u8],
    ) -> Result<Inspect, &'static str> {
        let (server_name, target) = match &name {
            Some(name) => (
                ServerName::try_from(name.clone()).map_err(|_| "guest_rejected")?,
                LeafTarget::Name(name.clone()),
            ),
            None => (
                ServerName::IpAddress(IpAddr::V4(dst).into()),
                LeafTarget::Ip(dst),
            ),
        };
        let mut client = cfg.client.clone();
        client.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        let mut host =
            ClientConnection::new(Arc::new(client), server_name).map_err(|_| "upstream_failed")?;
        host.set_buffer_limit(Some(PLAINTEXT_BUFFER));
        let mut inspect = Inspect {
            cfg: Arc::clone(cfg),
            name,
            target,
            host,
            guest: Guest::Accepting {
                acceptor: Box::default(),
                accepted: None,
            },
            phase: Phase::Upstream,
            to_host: Pending::default(),
            to_guest: Pending::default(),
            host_eof: false,
            host_notified: false,
            guest_notified: false,
            guest_done: false,
            host_plain_full: false,
            guest_plain_full: false,
            to_host_bytes: 0,
            to_guest_bytes: 0,
        };
        let mut fed = 0;
        while fed < hello.len() {
            match inspect.guest_in(&hello[fed..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => fed += n,
            }
        }
        match inspect.phase {
            Phase::Failed(reason) => Err(reason),
            _ => Ok(inspect),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The flow's name, as the hello gave it.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// What the guest leg negotiated, once it has.
    pub fn negotiated(&self) -> Negotiated {
        let (alpn, version) = match &self.guest {
            Guest::Open(conn) => (
                conn.alpn_protocol()
                    .map(|p| String::from_utf8_lossy(p).into_owned()),
                conn.protocol_version().map(|v| match v {
                    ProtocolVersion::TLSv1_3 => "1.3".to_owned(),
                    ProtocolVersion::TLSv1_2 => "1.2".to_owned(),
                    other => format!("{other:?}"),
                }),
            ),
            _ => (None, None),
        };
        Negotiated { alpn, version }
    }

    /// Takes TLS bytes from the guest: how many rustls took (the rest
    /// wait in the socket). An error ends the flow (`phase`).
    pub fn guest_in(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        match &mut self.guest {
            Guest::Accepting { acceptor, accepted } => {
                if accepted.is_some() {
                    // The hello is in; what follows waits for the
                    // connection (the guest sends nothing more before the
                    // ServerHello anyway).
                    return Ok(0);
                }
                let mut rd = bytes;
                let n = acceptor.read_tls(&mut rd)?;
                match acceptor.accept() {
                    Ok(Some(done)) => *accepted = Some(Box::new(done)),
                    Ok(None) => {}
                    Err((_, _alert)) => {
                        self.fail("guest_rejected");
                    }
                }
                Ok(n)
            }
            Guest::Open(conn) => {
                if self.guest_plain_full {
                    return Ok(0);
                }
                let mut rd = bytes;
                let n = match conn.read_tls(&mut rd) {
                    Ok(n) => n,
                    // No room for more plaintext: the bytes wait in the socket.
                    Err(error) if error.kind() == ErrorKind::Other => {
                        self.guest_plain_full = true;
                        return Ok(0);
                    }
                    Err(error) => return Err(error),
                };
                if let Err(_error) = conn.process_new_packets() {
                    let reason = if self.phase == Phase::Guest {
                        "guest_rejected"
                    } else {
                        "guest_failed"
                    };
                    self.fail(reason);
                }
                Ok(n)
            }
            Guest::Gone => Ok(0),
        }
    }

    /// Writes TLS bytes for the guest into `room`, as far as it goes: how
    /// many.
    pub fn guest_out(&mut self, room: &mut [u8]) -> usize {
        let Guest::Open(conn) = &mut self.guest else {
            return 0;
        };
        let mut written = 0;
        while conn.wants_write() && written < room.len() {
            let mut slice = &mut room[written..];
            match conn.write_tls(&mut slice) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(_) => break,
            }
        }
        written
    }

    /// Whether TLS bytes wait for the guest.
    pub fn wants_guest_write(&self) -> bool {
        matches!(&self.guest, Guest::Open(conn) if conn.wants_write())
    }

    /// Whether the upstream leg has TLS bytes for the host socket.
    pub fn wants_host_write(&self) -> bool {
        self.host.wants_write()
    }

    /// Whether the upstream leg would take more from the host socket.
    pub fn wants_host_read(&self) -> bool {
        !self.host_eof
            && !self.host_plain_full
            && self.host.wants_read()
            && !matches!(self.phase, Phase::Failed(_))
    }

    /// Whether the guest leg would take more TLS bytes from the guest.
    pub fn wants_guest_read(&self) -> bool {
        !self.guest_plain_full && !matches!(self.guest, Guest::Gone)
    }

    /// Moves TLS bytes between the upstream leg and the host socket (which
    /// is non-blocking): writes while the socket takes them, reads while
    /// it has them, `readable` and `writable` cleared when it refuses.
    pub fn host_io(
        &mut self,
        host: &mut TcpStream,
        readable: &mut bool,
        writable: &mut bool,
    ) -> HostIo {
        let mut io = HostIo::default();
        if matches!(self.phase, Phase::Failed(_)) {
            return io;
        }
        while *writable && self.host.wants_write() {
            match self.host.write_tls(host) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => *writable = false,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => {
                    io.error = Some(error);
                    return io;
                }
            }
        }
        let mut reads = 0;
        while *readable && self.wants_host_read() && reads < HOST_READS {
            reads += 1;
            match self.host.read_tls(host) {
                Ok(0) => {
                    self.host_eof = true;
                    io.eof = true;
                }
                Ok(_) => {
                    if let Err(error) = self.host.process_new_packets() {
                        let reason = match self.phase {
                            Phase::Upstream => classify_upstream(&error),
                            _ => "upstream_failed",
                        };
                        self.fail(reason);
                        return io;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => *readable = false,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                // rustls: no room for more plaintext until the relay reads.
                Err(error) if error.kind() == ErrorKind::Other => self.host_plain_full = true,
                Err(error) => {
                    io.error = Some(error);
                    return io;
                }
            }
        }
        io
    }

    /// The guest's TCP stream ended (its FIN): during the handshakes that
    /// is a rejection; while relaying, the host is told with a
    /// `close_notify` once the guest's plaintext has gone.
    pub fn guest_eof(&mut self) {
        match self.phase {
            Phase::Upstream | Phase::Guest => self.fail("guest_rejected"),
            Phase::Relaying => self.guest_done = true,
            Phase::Failed(_) => {}
        }
    }

    /// Whether the host leg is done with: the host closed and every byte
    /// it sent has gone to the guest leg, or the flow failed.
    pub fn host_finished(&self) -> bool {
        matches!(self.phase, Phase::Failed(_)) || (self.host_eof && self.to_guest.is_empty())
    }

    /// Whether the guest has been told of the host's close (its
    /// `close_notify` is queued or sent).
    pub fn guest_notified(&self) -> bool {
        self.guest_notified
    }

    /// Whether the host has been told of the guest's close.
    pub fn host_notified(&self) -> bool {
        self.host_notified
    }

    /// Advances the phases and moves plaintext, appending a copy of every
    /// byte moved to `out` with its direction. The phase afterwards.
    pub fn step(&mut self, out: &mut Vec<(Direction, Vec<u8>)>) -> Phase {
        match self.phase {
            Phase::Upstream => {
                if !self.host.is_handshaking() {
                    self.open_guest_leg();
                }
            }
            Phase::Guest => {
                if matches!(&self.guest, Guest::Open(conn) if !conn.is_handshaking()) {
                    self.phase = Phase::Relaying;
                }
            }
            Phase::Relaying => {}
            Phase::Failed(_) => return self.phase,
        }
        if self.phase == Phase::Relaying {
            self.relay(out);
        }
        self.phase
    }

    /// The upstream handshake is done: the guest leg gets the leaf for the
    /// name and the protocol upstream chose.
    fn open_guest_leg(&mut self) {
        let Guest::Accepting { accepted, .. } = &mut self.guest else {
            return;
        };
        let Some(accepted) = accepted.take() else {
            // The hello was not whole: more guest bytes complete it.
            return;
        };
        let leaf = match self.cfg.ca.leaf_for(&self.target) {
            Ok(leaf) => leaf,
            Err(_) => return self.fail("guest_rejected"),
        };
        let built = ServerConfig::builder_with_provider(Arc::clone(&self.cfg.provider))
            .with_safe_default_protocol_versions()
            .map(|b| {
                b.with_no_client_auth()
                    .with_cert_resolver(Arc::new(OneLeaf(leaf)))
            });
        let mut config = match built {
            Ok(config) => config,
            Err(_) => return self.fail("guest_rejected"),
        };
        config.alpn_protocols = self
            .host
            .alpn_protocol()
            .map(<[u8]>::to_vec)
            .into_iter()
            .collect();
        match accepted.into_connection(Arc::new(config)) {
            Ok(mut conn) => {
                conn.set_buffer_limit(Some(PLAINTEXT_BUFFER));
                self.guest = Guest::Open(Box::new(conn));
                self.phase = Phase::Guest;
            }
            Err((_, _alert)) => self.fail("guest_rejected"),
        }
    }

    /// Plaintext both ways, each held back by the far leg's room.
    fn relay(&mut self, out: &mut Vec<(Direction, Vec<u8>)>) {
        let Guest::Open(guest) = &mut self.guest else {
            return;
        };
        // Guest to host.
        loop {
            if self.to_host.is_empty() {
                if self.guest_done {
                    break;
                }
                let mut buf = vec![0; READ_CHUNK];
                match guest.reader().read(&mut buf) {
                    Ok(0) => {
                        self.guest_done = true;
                        break;
                    }
                    Ok(n) => {
                        self.guest_plain_full = false;
                        buf.truncate(n);
                        out.push((Direction::ToHost, buf.clone()));
                        self.to_host_bytes = self.to_host_bytes.saturating_add(n as u64);
                        self.to_host = Pending { bytes: buf, at: 0 };
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                        self.guest_done = true;
                        break;
                    }
                    Err(_) => return self.fail("guest_failed"),
                }
            }
            match self.host.writer().write(self.to_host.rest()) {
                Ok(0) => break,
                Ok(n) => self.to_host.at += n,
                Err(_) => return self.fail("upstream_failed"),
            }
        }
        if self.guest_done && self.to_host.is_empty() && !self.host_notified {
            self.host.send_close_notify();
            self.host_notified = true;
        }
        // Host to guest.
        loop {
            if self.to_guest.is_empty() {
                let mut buf = vec![0; READ_CHUNK];
                match self.host.reader().read(&mut buf) {
                    Ok(0) => {
                        self.host_eof = true;
                        break;
                    }
                    Ok(n) => {
                        self.host_plain_full = false;
                        buf.truncate(n);
                        out.push((Direction::ToGuest, buf.clone()));
                        self.to_guest_bytes = self.to_guest_bytes.saturating_add(n as u64);
                        self.to_guest = Pending { bytes: buf, at: 0 };
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                        self.host_eof = true;
                        break;
                    }
                    Err(_) => return self.fail("upstream_failed"),
                }
            }
            match guest.writer().write(self.to_guest.rest()) {
                Ok(0) => break,
                Ok(n) => self.to_guest.at += n,
                Err(_) => return self.fail("guest_failed"),
            }
        }
        if self.host_eof && self.to_guest.is_empty() && !self.guest_notified {
            guest.send_close_notify();
            self.guest_notified = true;
        }
    }

    fn fail(&mut self, reason: &'static str) {
        if !matches!(self.phase, Phase::Failed(_)) {
            self.phase = Phase::Failed(reason);
        }
        self.guest = Guest::Gone;
    }
}

/// The `net.inspect` result for an upstream handshake that failed with
/// `error`: a certificate the trust store refuses, or anything else.
fn classify_upstream(error: &rustls::Error) -> &'static str {
    match error {
        rustls::Error::InvalidCertificate(_) => "upstream_untrusted",
        _ => "upstream_failed",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, SocketAddrV4, TcpListener};
    use std::thread;
    use std::time::{Duration, Instant};

    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::StreamOwned;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    /// The name the guest asks for and the test upstream answers to.
    pub(crate) const NAME: &str = "api.example";
    const DEADLINE: Duration = Duration::from_secs(30);

    /// A test upstream: a TLS server on the loopback for [`NAME`] with a
    /// self-signed certificate, offering `alpn`. Its thread reads `expect`
    /// bytes of plaintext, then writes `reply` and closes.
    pub(crate) struct Upstream {
        pub addr: SocketAddrV4,
        pub cert: CertificateDer<'static>,
        pub thread: thread::JoinHandle<Vec<u8>>,
    }

    pub(crate) fn upstream(alpn: &[&str], expect: usize, reply: Vec<u8>) -> Upstream {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec![NAME.to_owned(), "127.0.0.1".to_owned()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
            panic!("not IPv4");
        };
        let thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(DEADLINE)).unwrap();
            let conn = ServerConnection::new(config).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            let mut got = Vec::new();
            let mut buf = vec![0; 16384];
            while got.len() < expect {
                match tls.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
                    Err(error) => panic!("upstream read: {error}"),
                }
            }
            if !reply.is_empty() {
                tls.write_all(&reply).unwrap();
            }
            tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tls.sock.shutdown(std::net::Shutdown::Write);
            // Take the guest's close, so the socket closes cleanly.
            while let Ok(n) = tls.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
            got
        });
        Upstream {
            addr,
            cert: cert_der,
            thread,
        }
    }

    /// A session CA and the config an inspected flow uses, trusting
    /// `extra` upstream (and the host's store).
    pub(crate) fn config(extra: &[CertificateDer<'static>]) -> Arc<InspectConfig> {
        let ca = Arc::new(SessionCa::generate("tls-test").unwrap());
        Arc::new(InspectConfig::new(ca, InspectConfig::host_roots(extra)).unwrap())
    }

    /// The guest: a rustls client for [`NAME`] offering `alpn`, trusting
    /// `roots`.
    pub(crate) fn make_guest(roots: RootCertStore, alpn: &[&str]) -> ClientConnection {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        ClientConnection::new(Arc::new(config), ServerName::try_from(NAME).unwrap()).unwrap()
    }

    fn trust(ca: &SessionCa) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        roots
    }

    /// The guest's ClientHello, as the gate would hold it.
    fn hello_of(guest: &mut ClientConnection) -> Vec<u8> {
        let mut hello = Vec::new();
        while guest.wants_write() {
            guest.write_tls(&mut hello).unwrap();
        }
        hello
    }

    thread_local! {
        /// Guest TLS bytes the gate did not take yet: what the smoltcp
        /// socket would hold.
        static GUEST_QUEUE: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// One round of everything the relay would do, with copies of the
    /// plaintext moved appended to `plain`.
    fn drive(
        inspect: &mut Inspect,
        guest: &mut ClientConnection,
        host: &mut TcpStream,
        plain: &mut Vec<(Direction, Vec<u8>)>,
    ) -> Phase {
        GUEST_QUEUE.with(|queue| {
            let mut queue = queue.borrow_mut();
            while guest.wants_write() {
                guest.write_tls(&mut *queue).unwrap();
            }
            let mut at = 0;
            while at < queue.len() {
                match inspect.guest_in(&queue[at..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => at += n,
                }
            }
            queue.drain(..at);
        });
        loop {
            let mut room = vec![0; 16384];
            let n = inspect.guest_out(&mut room);
            if n == 0 {
                break;
            }
            let mut rd = &room[..n];
            while !rd.is_empty() {
                guest.read_tls(&mut rd).unwrap();
            }
            // A guest that refuses the certificate says so with an alert.
            let _ = guest.process_new_packets();
        }
        let (mut readable, mut writable) = (true, true);
        let io = inspect.host_io(host, &mut readable, &mut writable);
        if let Some(error) = io.error {
            panic!("host socket: {error}");
        }
        inspect.step(plain)
    }

    fn connect(addr: SocketAddrV4) -> TcpStream {
        GUEST_QUEUE.with(|queue| queue.borrow_mut().clear());
        let host = TcpStream::connect(addr).unwrap();
        host.set_nonblocking(true).unwrap();
        host
    }

    /// Runs the flow: the guest sends `send`, then reads until the host
    /// closes. What the guest received, and the copies the observer got.
    fn run_flow(
        inspect: &mut Inspect,
        guest: &mut ClientConnection,
        host: &mut TcpStream,
        send: &[u8],
    ) -> (Vec<u8>, Vec<(Direction, Vec<u8>)>) {
        let mut plain = Vec::new();
        let mut received = Vec::new();
        let mut sent = 0;
        let mut closed = false;
        let started = Instant::now();
        loop {
            let phase = drive(inspect, guest, host, &mut plain);
            if let Phase::Failed(reason) = phase {
                panic!("the flow failed: {reason}");
            }
            if !guest.is_handshaking() {
                if sent < send.len() {
                    let n = guest.writer().write(&send[sent..]).unwrap();
                    sent += n;
                } else if !closed {
                    guest.send_close_notify();
                    closed = true;
                }
                let mut buf = vec![0; 16384];
                match guest.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
                    Err(error) => panic!("guest read: {error}"),
                }
            }
            assert!(started.elapsed() < DEADLINE, "the flow did not finish");
            thread::sleep(Duration::from_millis(1));
        }
        // The close goes through.
        for _ in 0..100 {
            drive(inspect, guest, host, &mut plain);
            if inspect.host_notified() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        (received, plain)
    }

    /// Bytes each way come through unchanged, and the observer's copies
    /// are the same bytes in the same order.
    #[test]
    fn an_inspected_flow_relays_plaintext_both_ways_unchanged() {
        let request: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let reply: Vec<u8> = (0..1024 * 1024).map(|i| (i % 241) as u8).collect();
        let up = upstream(&["h2", "http/1.1"], request.len(), reply.clone());
        let cfg = config(std::slice::from_ref(&up.cert));
        let mut guest = make_guest(trust(cfg.ca()), &["h2", "http/1.1"]);
        let hello = hello_of(&mut guest);
        let mut inspect = Inspect::new(
            &cfg,
            Some(NAME.into()),
            Ipv4Addr::LOCALHOST,
            &["h2".into(), "http/1.1".into()],
            &hello,
        )
        .unwrap();
        let mut host = connect(up.addr);
        let (received, plain) = run_flow(&mut inspect, &mut guest, &mut host, &request);
        assert_eq!(received, reply);
        assert_eq!(up.thread.join().unwrap(), request);
        let to_host: Vec<u8> = plain
            .iter()
            .filter(|(d, _)| *d == Direction::ToHost)
            .flat_map(|(_, b)| b.clone())
            .collect();
        let to_guest: Vec<u8> = plain
            .iter()
            .filter(|(d, _)| *d == Direction::ToGuest)
            .flat_map(|(_, b)| b.clone())
            .collect();
        assert_eq!(to_host, request);
        assert_eq!(to_guest, reply);
        assert_eq!(inspect.to_host_bytes, request.len() as u64);
        assert_eq!(inspect.to_guest_bytes, reply.len() as u64);
        assert_eq!(inspect.phase(), Phase::Relaying);
        assert_eq!(inspect.negotiated().alpn.as_deref(), Some("h2"));
        assert_eq!(inspect.negotiated().version.as_deref(), Some("1.3"));
    }

    /// The guest gets the protocol upstream chose: h2 when upstream
    /// speaks it, http/1.1 when that is all it takes, none when it
    /// chooses none.
    #[test]
    fn the_guest_leg_offers_exactly_the_alpn_upstream_chose() {
        for (server, expect) in [
            (&["h2", "http/1.1"][..], Some("h2")),
            (&["http/1.1"][..], Some("http/1.1")),
            (&[][..], None),
        ] {
            let up = upstream(server, 2, b"ok".to_vec());
            let cfg = config(std::slice::from_ref(&up.cert));
            let mut guest = make_guest(trust(cfg.ca()), &["h2", "http/1.1"]);
            let hello = hello_of(&mut guest);
            let mut inspect = Inspect::new(
                &cfg,
                Some(NAME.into()),
                Ipv4Addr::LOCALHOST,
                &["h2".into(), "http/1.1".into()],
                &hello,
            )
            .unwrap();
            let mut host = connect(up.addr);
            let (received, _) = run_flow(&mut inspect, &mut guest, &mut host, b"hi");
            assert_eq!(received, b"ok");
            assert_eq!(
                guest.alpn_protocol(),
                expect.map(str::as_bytes),
                "{server:?}"
            );
            assert_eq!(inspect.negotiated().alpn.as_deref(), expect);
            up.thread.join().unwrap();
        }
    }

    /// An upstream the trust store does not vouch for ends the flow before
    /// the guest is answered: nothing is relayed.
    #[test]
    fn an_untrusted_upstream_is_refused_and_recorded() {
        let up = upstream(&["http/1.1"], 0, Vec::new());
        // The host's store, without the test upstream's certificate.
        let cfg = config(&[]);
        let mut guest = make_guest(trust(cfg.ca()), &["http/1.1"]);
        let hello = hello_of(&mut guest);
        let mut inspect = Inspect::new(
            &cfg,
            Some(NAME.into()),
            Ipv4Addr::LOCALHOST,
            &["http/1.1".into()],
            &hello,
        )
        .unwrap();
        let mut host = connect(up.addr);
        let mut plain = Vec::new();
        let started = Instant::now();
        let phase = loop {
            let phase = drive(&mut inspect, &mut guest, &mut host, &mut plain);
            if matches!(phase, Phase::Failed(_)) {
                break phase;
            }
            assert!(started.elapsed() < DEADLINE);
            thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(phase, Phase::Failed("upstream_untrusted"));
        assert!(guest.is_handshaking(), "the guest was never answered");
        assert!(plain.is_empty());
        assert_eq!((inspect.to_host_bytes, inspect.to_guest_bytes), (0, 0));
        drop(host);
        let _ = up.thread.join();
    }

    /// A guest that does not trust the session CA (one that pins, or was
    /// not given the certificate) refuses the leaf: the flow fails
    /// `guest_rejected`, and nothing is relayed.
    #[test]
    fn a_guest_that_rejects_the_leaf_is_recorded_and_not_relayed() {
        let up = upstream(&["http/1.1"], 0, Vec::new());
        let cfg = config(std::slice::from_ref(&up.cert));
        let mut guest = make_guest(RootCertStore::empty(), &["http/1.1"]);
        let hello = hello_of(&mut guest);
        let mut inspect = Inspect::new(
            &cfg,
            Some(NAME.into()),
            Ipv4Addr::LOCALHOST,
            &["http/1.1".into()],
            &hello,
        )
        .unwrap();
        let mut host = connect(up.addr);
        let mut plain = Vec::new();
        let started = Instant::now();
        let phase = loop {
            let phase = drive(&mut inspect, &mut guest, &mut host, &mut plain);
            if matches!(phase, Phase::Failed(_)) {
                break phase;
            }
            assert!(started.elapsed() < DEADLINE);
            thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(phase, Phase::Failed("guest_rejected"));
        assert!(plain.is_empty());
        drop(host);
        let _ = up.thread.join();
    }

    /// A guest FIN during the handshake is a rejection; one while relaying
    /// becomes a `close_notify` to the host once its bytes have gone.
    #[test]
    fn a_guest_fin_is_a_rejection_before_the_handshake_and_a_close_after() {
        let up = upstream(&[], 0, Vec::new());
        let cfg = config(std::slice::from_ref(&up.cert));
        let mut guest = make_guest(trust(cfg.ca()), &[]);
        let hello = hello_of(&mut guest);
        let mut inspect =
            Inspect::new(&cfg, Some(NAME.into()), Ipv4Addr::LOCALHOST, &[], &hello).unwrap();
        inspect.guest_eof();
        assert_eq!(inspect.phase(), Phase::Failed("guest_rejected"));
        drop(up);

        let up = upstream(&[], 3, Vec::new());
        let cfg = config(std::slice::from_ref(&up.cert));
        let mut guest = make_guest(trust(cfg.ca()), &[]);
        let hello = hello_of(&mut guest);
        let mut inspect =
            Inspect::new(&cfg, Some(NAME.into()), Ipv4Addr::LOCALHOST, &[], &hello).unwrap();
        let mut host = connect(up.addr);
        let mut plain = Vec::new();
        let started = Instant::now();
        while drive(&mut inspect, &mut guest, &mut host, &mut plain) != Phase::Relaying {
            assert!(started.elapsed() < DEADLINE);
            thread::sleep(Duration::from_millis(1));
        }
        guest.writer().write_all(b"bye").unwrap();
        drive(&mut inspect, &mut guest, &mut host, &mut plain);
        inspect.guest_eof();
        while !inspect.host_notified() {
            drive(&mut inspect, &mut guest, &mut host, &mut plain);
            assert!(started.elapsed() < DEADLINE);
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(up.thread.join().unwrap(), b"bye");
        assert_eq!(inspect.to_host_bytes, 3);
    }
}
