// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! boxcar's rules in the vsock muxer, driven with hand-built packets over
//! plain buffers and Unix sockets in a temporary directory: no guest
//! memory, no device, no KVM. The muxer is told about host socket events
//! by calling `notify` where the vsock thread would on an epoll wakeup.
//!
//! Each test reads back the session's audit log: every decision on a guest
//! connection is a `vsock.connect`, and the end of every connection one let
//! through a `vsock.close`.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boxcar_audit::{LogReader, WriterConfig, WriterHandle};
use boxcar_proto::{Record, SessionId};
use boxcar_vsock::defs::uapi;
use boxcar_vsock::{
    bind_listener, port_socket_path, ConnMeta, InternalServices, VsockChannel, VsockConfig,
    VsockEpollListener, VsockMuxer, VsockPacket,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use vm_memory::{Bytes, VolatileSlice};
use vmm_sys_util::epoll::EventSet;

const GUEST_CID: u64 = 3;
/// What the guest says it can buffer, as Linux does.
const GUEST_BUF_ALLOC: u32 = 256 * 1024;
const HEADER_LEN: usize = 44;
const DATA_LEN: usize = 4096;

/// A packet over plain buffers, which it owns.
struct Pkt {
    pkt: VsockPacket<'static>,
    _hdr: Box<[u8]>,
    _data: Box<[u8]>,
}

impl Pkt {
    fn new() -> Pkt {
        let mut hdr = vec![0u8; HEADER_LEN].into_boxed_slice();
        let mut data = vec![0u8; DATA_LEN].into_boxed_slice();
        // SAFETY: both buffers are on the heap and live in the same `Pkt`
        // as the packet (moving a `Box` does not move what it points to),
        // and nothing else touches them.
        let pkt = unsafe { VsockPacket::new(&mut hdr, Some(&mut data)) }.unwrap();
        Pkt {
            pkt,
            _hdr: hdr,
            _data: data,
        }
    }

    fn data(&self) -> &VolatileSlice<'static, ()> {
        self.pkt.data_slice().unwrap()
    }

    /// The guest's packet `op` from its `port` to host `host_port`.
    fn guest(&mut self, host_port: u32, port: u32, op: u16) -> &mut Self {
        self.pkt.set_header_from_raw(&[0; HEADER_LEN]).unwrap();
        self.pkt
            .set_src_cid(GUEST_CID)
            .set_dst_cid(uapi::VSOCK_HOST_CID)
            .set_src_port(port)
            .set_dst_port(host_port)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_op(op)
            .set_buf_alloc(GUEST_BUF_ALLOC);
        self
    }

    /// The guest's data packet carrying `bytes`.
    fn guest_data(&mut self, host_port: u32, port: u32, bytes: &[u8]) -> &mut Self {
        self.guest(host_port, port, uapi::VSOCK_OP_RW);
        self.pkt.set_len(bytes.len() as u32);
        self.data().write_slice(bytes, 0).unwrap();
        self
    }

    /// The payload of a packet for the guest.
    fn payload(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.pkt.len() as usize];
        self.data().read_slice(&mut bytes, 0).unwrap();
        bytes
    }

    /// (op, src_port, dst_port) of a packet for the guest, which comes from
    /// the host to the guest.
    fn route(&self) -> (u16, u32, u32) {
        assert_eq!(self.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(self.pkt.dst_cid(), GUEST_CID);
        (self.pkt.op(), self.pkt.src_port(), self.pkt.dst_port())
    }
}

/// The VMM's services, faked: those on `ports` take every connection and
/// keep their end of it.
struct FakeServices {
    ports: Vec<u32>,
    taken: Mutex<Vec<(u32, ConnMeta, UnixStream)>>,
}

impl FakeServices {
    fn on(ports: &[u32]) -> Arc<FakeServices> {
        Arc::new(FakeServices {
            ports: ports.to_vec(),
            taken: Mutex::new(Vec::new()),
        })
    }

    /// The service ends of the connections taken, with their port and
    /// guest port.
    fn taken(&self) -> Vec<(u32, ConnMeta)> {
        self.taken
            .lock()
            .unwrap()
            .iter()
            .map(|(port, meta, _)| (*port, *meta))
            .collect()
    }
}

impl InternalServices for FakeServices {
    fn connect(&self, port: u32, meta: ConnMeta) -> Option<UnixStream> {
        if !self.ports.contains(&port) {
            return None;
        }
        let (ours, theirs) = UnixStream::pair().ok()?;
        self.taken.lock().unwrap().push((port, meta, theirs));
        Some(ours)
    }
}

/// A muxer with its host socket and audit log in a temporary directory.
/// Field order is drop order: the muxer, and its audit sink, before the
/// log's writer.
struct Fixture {
    muxer: VsockMuxer,
    pkt: Pkt,
    uds_path: PathBuf,
    writer: WriterHandle,
    _dir: TempDir,
}

impl Fixture {
    fn new(allow_ports: &[u32], services: Arc<dyn InternalServices>) -> Fixture {
        let dir = TempDir::new().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new()))
                .unwrap();
        let uds_path = dir.path().join("vsock.sock");
        let cfg = VsockConfig {
            allow_ports: allow_ports.to_vec(),
            ..VsockConfig::new(&uds_path)
        };
        let listener = bind_listener(&uds_path).unwrap();
        let muxer = VsockMuxer::new(&cfg, listener, services, sink).unwrap();
        Fixture {
            muxer,
            pkt: Pkt::new(),
            uds_path,
            writer,
            _dir: dir,
        }
    }

    /// The guest sends the packet built in `self.pkt`.
    fn send(&mut self) {
        self.muxer.send_pkt(&self.pkt.pkt).unwrap();
    }

    /// The guest asks to connect from `port` to host `host_port`, and gets
    /// the muxer's answer: (op, src_port, dst_port).
    fn request(&mut self, host_port: u32, port: u32) -> (u16, u32, u32) {
        self.pkt.guest(host_port, port, uapi::VSOCK_OP_REQUEST);
        self.send();
        self.recv()
    }

    /// The next packet for the guest: (op, src_port, dst_port).
    fn recv(&mut self) -> (u16, u32, u32) {
        assert!(self.muxer.has_pending_rx(), "nothing for the guest");
        self.muxer.recv_pkt(&mut self.pkt.pkt).unwrap();
        self.pkt.route()
    }

    /// Lets the muxer handle its host socket events, as the vsock thread
    /// does when the muxer's epoll is ready; a few times, for commands it
    /// reads a byte at a time.
    fn notify(&mut self) {
        for _ in 0..16 {
            self.muxer.notify(EventSet::IN);
        }
    }

    /// Closes the log and returns the `vsock.*` records' (type, data).
    fn vsock_records(self) -> Vec<(String, Value)> {
        let Fixture {
            muxer,
            writer,
            _dir,
            ..
        } = self;
        drop(muxer);
        let session = writer.session_dir().to_owned();
        writer.close().unwrap();
        let records: Vec<Record> = LogReader::open(&session)
            .unwrap()
            .records()
            .map(Result::unwrap)
            .collect();
        records
            .into_iter()
            .filter(|r| r.kind.starts_with("vsock."))
            .map(|r| (r.kind, r.data))
            .collect()
    }
}

fn connect_record(
    port: u32,
    dir: &str,
    peer: &str,
    src_port: u32,
    reason: Option<&str>,
) -> (String, Value) {
    (
        "vsock.connect".to_owned(),
        json!({
            "port": port,
            "dir": dir,
            "peer": peer,
            "src_port": src_port,
            "verdict": if reason.is_some() { "deny" } else { "allow" },
            "reason": reason,
        }),
    )
}

fn close_record(port: u32, dir: &str, tx: u64, rx: u64) -> (String, Value) {
    (
        "vsock.close".to_owned(),
        json!({"port": port, "dir": dir, "tx": tx, "rx": rx}),
    )
}

/// A host listener at `path`, non-blocking.
fn listen(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

#[test]
fn internal_ports_accept_only_the_first_privileged_connection() {
    let services = FakeServices::on(&[1024]);
    let mut fx = Fixture::new(&[], services.clone());

    // Init, from a privileged port: served.
    let reply = fx.request(1024, 1023);
    assert_eq!(reply, (uapi::VSOCK_OP_RESPONSE, 1024, 1023));
    assert_eq!(services.taken(), [(1024, ConnMeta { guest_port: 1023 })]);
    // Its bytes reach the service, and the service's the guest.
    fx.pkt.guest_data(1024, 1023, b"{\"hello\":1}\n");
    fx.send();
    let mut theirs = services.taken.lock().unwrap()[0].2.try_clone().unwrap();
    theirs
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut got = [0u8; 12];
    theirs.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"{\"hello\":1}\n");
    theirs.write_all(b"{\"config\":{}}\n").unwrap();
    fx.notify();
    assert_eq!(fx.recv(), (uapi::VSOCK_OP_RW, 1024, 1023));
    assert_eq!(fx.pkt.payload(), b"{\"config\":{}}\n");

    // An unprivileged process: reset, the service never asked.
    assert_eq!(fx.request(1024, 5000), (uapi::VSOCK_OP_RST, 1024, 5000));
    // Root again, but the port is taken: reset.
    assert_eq!(fx.request(1024, 1022), (uapi::VSOCK_OP_RST, 1024, 1022));
    assert_eq!(services.taken().len(), 1);
    assert!(!fx.muxer.has_pending_rx());

    let records = fx.vsock_records();
    assert_eq!(
        records,
        [
            connect_record(1024, "guest", "internal", 1023, None),
            connect_record(1024, "guest", "internal", 5000, Some("unprivileged")),
            connect_record(1024, "guest", "internal", 1022, Some("duplicate")),
            // Dropping the muxer is not closing its connections: only
            // `close_all` (a device reset) and a guest or host close record
            // the end. See `close_all_records_the_end_of_every_connection`.
        ]
    );
}

#[test]
fn an_allowlisted_port_lands_on_the_suffixed_socket() {
    let mut fx = Fixture::new(&[5000], FakeServices::on(&[]));
    let host = listen(&port_socket_path(&fx.uds_path, 5000));
    assert_eq!(
        port_socket_path(&fx.uds_path, 5000),
        fx.uds_path.with_file_name("vsock.sock_5000")
    );

    assert_eq!(
        fx.request(5000, 40_000),
        (uapi::VSOCK_OP_RESPONSE, 5000, 40_000)
    );
    let (mut stream, _) = host.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    fx.pkt.guest_data(5000, 40_000, b"ping");
    fx.send();
    let mut got = [0u8; 4];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    stream.write_all(b"pong!").unwrap();
    fx.notify();
    assert_eq!(fx.recv(), (uapi::VSOCK_OP_RW, 5000, 40_000));
    assert_eq!(fx.pkt.payload(), b"pong!");

    // The guest resets it: the host end is closed, and the end recorded.
    fx.pkt.guest(5000, 40_000, uapi::VSOCK_OP_RST);
    fx.send();
    assert_eq!(stream.read(&mut got).unwrap(), 0);

    assert_eq!(
        fx.vsock_records(),
        [
            connect_record(5000, "guest", "uds", 40_000, None),
            close_record(5000, "guest", 4, 5),
        ]
    );
}

/// An allowlisted port with nothing listening: let through, and over at
/// once.
#[test]
fn an_allowlisted_port_nobody_listens_on_is_reset_after_its_records() {
    let mut fx = Fixture::new(&[5000], FakeServices::on(&[]));
    assert_eq!(fx.request(5000, 40_000), (uapi::VSOCK_OP_RST, 5000, 40_000));
    assert_eq!(
        fx.vsock_records(),
        [
            connect_record(5000, "guest", "uds", 40_000, None),
            close_record(5000, "guest", 0, 0),
        ]
    );
}

#[test]
fn an_unlisted_port_is_reset_and_audited() {
    let mut fx = Fixture::new(&[5000], FakeServices::on(&[]));
    // Something listens there, and is never reached.
    let host = listen(&port_socket_path(&fx.uds_path, 5001));
    assert_eq!(fx.request(5001, 40_000), (uapi::VSOCK_OP_RST, 5001, 40_000));
    assert_eq!(
        host.accept().map(drop).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    // A privileged source port opens nothing outside the internal ports.
    assert_eq!(fx.request(22, 1000), (uapi::VSOCK_OP_RST, 22, 1000));
    assert!(!fx.muxer.has_pending_rx());
    assert_eq!(
        fx.vsock_records(),
        [
            connect_record(5001, "guest", "uds", 40_000, Some("port")),
            connect_record(22, "guest", "uds", 1000, Some("port")),
        ]
    );
}

#[test]
fn an_unregistered_internal_port_is_reset_with_no_service() {
    let services = FakeServices::on(&[1024]);
    let mut fx = Fixture::new(&[1025, 1026], services.clone());
    // Allowlisting an internal port changes nothing: it is the VMM's.
    let host = listen(&port_socket_path(&fx.uds_path, 1025));
    assert_eq!(fx.request(1025, 1022), (uapi::VSOCK_OP_RST, 1025, 1022));
    assert_eq!(fx.request(1026, 1021), (uapi::VSOCK_OP_RST, 1026, 1021));
    assert_eq!(
        host.accept().map(drop).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert!(services.taken().is_empty());
    assert_eq!(
        fx.vsock_records(),
        [
            connect_record(1025, "guest", "internal", 1022, Some("no_service")),
            connect_record(1026, "guest", "internal", 1021, Some("no_service")),
        ]
    );
}

#[test]
fn host_to_guest_connect_protocol_round_trips() {
    let mut fx = Fixture::new(&[], FakeServices::on(&[]));

    // A host process asks for guest port 5000.
    let mut host = UnixStream::connect(&fx.uds_path).unwrap();
    host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    host.write_all(b"CONNECT 5000\n").unwrap();
    fx.notify();
    let (op, local_port, guest_port) = fx.recv();
    assert_eq!((op, guest_port), (uapi::VSOCK_OP_REQUEST, 5000));
    // The muxer's own ports for host connections, far above the rest.
    assert!(local_port >= 1 << 30, "{local_port}");

    // The guest accepts: the host process hears `OK <port>`, the port the
    // guest sees the connection come from.
    fx.pkt.guest(local_port, 5000, uapi::VSOCK_OP_RESPONSE);
    fx.send();
    let ok = format!("OK {local_port}\n");
    let mut got = vec![0u8; ok.len()];
    host.read_exact(&mut got).unwrap();
    assert_eq!(got, ok.as_bytes());

    // Bytes both ways.
    host.write_all(b"hello guest").unwrap();
    fx.notify();
    assert_eq!(fx.recv(), (uapi::VSOCK_OP_RW, local_port, 5000));
    assert_eq!(fx.pkt.payload(), b"hello guest");
    fx.pkt.guest_data(local_port, 5000, b"hi");
    fx.send();
    let mut hi = [0u8; 2];
    host.read_exact(&mut hi).unwrap();
    assert_eq!(&hi, b"hi");

    // The guest resets it.
    fx.pkt.guest(local_port, 5000, uapi::VSOCK_OP_RST);
    fx.send();
    assert_eq!(host.read(&mut hi).unwrap(), 0);

    // A second host process asks for a guest port nothing listens on: the
    // guest resets the request, and the host process is closed on, with no
    // `OK`. Never accepted, it is not recorded.
    let mut refused = UnixStream::connect(&fx.uds_path).unwrap();
    refused
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    refused.write_all(b"CONNECT 1024\n").unwrap();
    fx.notify();
    let (op, refused_port, guest_port) = fx.recv();
    assert_eq!((op, guest_port), (uapi::VSOCK_OP_REQUEST, 1024));
    fx.pkt.guest(refused_port, 1024, uapi::VSOCK_OP_RST);
    fx.send();
    let mut rest = Vec::new();
    refused.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "{rest:?}");

    assert_eq!(
        fx.vsock_records(),
        [
            connect_record(5000, "host", "guest", local_port, None),
            close_record(5000, "host", 2, 11),
        ]
    );
}

#[test]
fn close_all_records_the_end_of_every_connection() {
    let services = FakeServices::on(&[1024]);
    let mut fx = Fixture::new(&[5000], services.clone());
    let host = listen(&port_socket_path(&fx.uds_path, 5000));
    assert_eq!(fx.request(1024, 1023).0, uapi::VSOCK_OP_RESPONSE);
    assert_eq!(fx.request(5000, 40_000).0, uapi::VSOCK_OP_RESPONSE);
    let (mut stream, _) = host.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    fx.pkt.guest_data(5000, 40_000, b"abc");
    fx.send();

    fx.muxer.close_all();
    // The host ends are closed.
    let mut got = Vec::new();
    stream.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"abc");
    let mut theirs = services.taken.lock().unwrap().remove(0).2;
    theirs
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(theirs.read(&mut [0u8; 1]).unwrap(), 0);

    let mut records = fx.vsock_records();
    // The closes come in the connection map's order.
    records[2..].sort_by_key(|(_, data)| data["port"].as_u64());
    assert_eq!(
        records,
        [
            connect_record(1024, "guest", "internal", 1023, None),
            connect_record(5000, "guest", "uds", 40_000, None),
            close_record(1024, "guest", 0, 0),
            close_record(5000, "guest", 3, 0),
        ]
    );
}

/// Sets the process umask for as long as it lives.
struct Umask(libc::mode_t);

impl Umask {
    fn set(mask: libc::mode_t) -> Umask {
        // SAFETY: umask only swaps the process file mode creation mask.
        Umask(unsafe { libc::umask(mask) })
    }
}

impl Drop for Umask {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe { libc::umask(self.0) };
    }
}

#[test]
fn the_listener_socket_is_0600() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vsock.sock");
    // The VMM runs with umask 0 once the shares are imported: the mode is
    // set, not left to the umask.
    let listener = {
        let _umask = Umask::set(0);
        bind_listener(&path).unwrap()
    };
    let meta = fs::symlink_metadata(&path).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    // It accepts without blocking.
    assert_eq!(
        listener.accept().map(drop).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    // A second bind at the same path fails, and leaves the first alone.
    assert!(bind_listener(&path).is_err());
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
}
