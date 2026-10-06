// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The sensor stream: the VMM's service on vsock port 1026
//! (`boxcar.sensor`), where the guest's sensor sends ring 1 records.
//!
//! The sensor connects once init has started it, from a privileged guest
//! port, and writes frames ([`boxcar_proto::sensor`]: a length, then the
//! record as `type` and `data` with the guest's clock and the process
//! beside them). A thread of the VMM's reads them and hands each to the
//! audit writer as a ring 1 submission with `src` `sensor`; the writer
//! stamps the host clocks and the sequence number. `proc.lsm_deny` is
//! written through to disk at once (`Priority::Critical`); the rest waits
//! for room like any record. The sensor is never dropped on the floor: when
//! the writer's channel is full the reading thread waits, the stream's
//! buffer fills, the sensor's write blocks, and the kernel's ring buffer
//! counts what it then cannot place, which the next heartbeat reports. No
//! ring 0 producer waits on any of it, and the vsock thread never does:
//! [`SensorIngest::service`] only makes a stream pair.
//!
//! A frame that is not a sensor record (a bad length, not JSON, a kind that
//! is not `proc.*`, a string over its limit) ends the stream: the reading
//! thread drops its end, the vsock device records the close, and the log
//! then shows a sensor that fell silent. The VMM takes one connection in
//! its life, like the control channel: a later one is refused as
//! `reactivated`.
//!
//! [`SensorIngest::status`] is what the control socket's `status` reports
//! under `sensor`: `waiting` until the sensor says what it attached,
//! `attached` or `degraded` as it said, `silent` once its stream ended or
//! no heartbeat came for [`SILENCE`].

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use boxcar_audit::{AuditSink, Priority, Submission};
use boxcar_proto::control::{SensorState, SensorStatus};
use boxcar_proto::sensor::{Decoder, SensorFrame};
use boxcar_proto::{Payload, Ring, SensorPhase};
use boxcar_vsock::{ConnMeta, Deny};

pub use crate::guest_ctl::REACTIVATED;
use crate::services::Service;

/// A sensor whose last heartbeat is older than this is `silent`.
pub const SILENCE: Duration = Duration::from_secs(3);

/// Bytes read from the stream at a time.
const READ_CHUNK: usize = 16384;

/// The sensor stream's service: see the module docs.
pub struct SensorIngest {
    audit: AuditSink,
    silence: Duration,
    /// Set once the one connection of the VMM's life is taken.
    taken: AtomicBool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The stream was taken and has not ended.
    connected: bool,
    /// The stream ended, however it did.
    ended: bool,
    heartbeats: u64,
    /// When the last heartbeat arrived, and the host's `CLOCK_REALTIME` then.
    last_heartbeat: Option<(Instant, u64)>,
    /// What the sensor last said it had attached.
    phase: Option<SensorPhase>,
}

impl SensorIngest {
    /// A service that records into `audit`, idle until its
    /// [`service`](SensorIngest::service) takes the sensor's connection.
    pub fn new(audit: AuditSink) -> Arc<SensorIngest> {
        SensorIngest::with_silence(audit, SILENCE)
    }

    /// The same, with its own idea of how long a quiet sensor is `silent`.
    pub fn with_silence(audit: AuditSink, silence: Duration) -> Arc<SensorIngest> {
        Arc::new(SensorIngest {
            audit,
            silence,
            taken: AtomicBool::new(false),
            state: Mutex::new(State::default()),
        })
    }

    /// The service for port 1026: takes the first connection, and refuses
    /// every later one as [`REACTIVATED`].
    pub fn service(self: &Arc<Self>) -> Service {
        let ingest = Arc::clone(self);
        Arc::new(move |meta| ingest.accept(meta))
    }

    /// What the control socket's `status` reports under `sensor`.
    pub fn status(&self) -> SensorStatus {
        let state = self.lock();
        let quiet = state
            .last_heartbeat
            .map(|(at, _)| at.elapsed() > self.silence)
            .unwrap_or(false);
        let phase = match state.phase {
            None => SensorState::Waiting,
            Some(SensorPhase::Attached) => SensorState::Attached,
            Some(SensorPhase::Degraded) => SensorState::Degraded,
        };
        SensorStatus {
            state: if state.ended || (state.connected && quiet) {
                SensorState::Silent
            } else {
                phase
            },
            heartbeats: state.heartbeats,
            last_heartbeat_ns: state.last_heartbeat.map(|(_, ns)| ns),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The sensor's connection, on the vsock thread: one in the VMM's life.
    fn accept(self: &Arc<Self>, meta: ConnMeta) -> Result<UnixStream, Deny> {
        if self.taken.swap(true, Ordering::SeqCst) {
            boxcar_virtio::limited!(
                warn,
                "sensor stream: refused a connection from guest port {}: the sensor's was \
                 taken already",
                meta.guest_port
            );
            return Err(Deny::Refused(REACTIVATED));
        }
        match self.open() {
            Ok(ours) => Ok(ours),
            Err(error) => {
                // Not taken after all: the sensor may try again.
                self.taken.store(false, Ordering::SeqCst);
                boxcar_virtio::limited!(warn, "sensor stream: cannot take the connection: {error}");
                Err(Deny::NoService)
            }
        }
    }

    /// Makes the stream pair and starts the reading thread on the VMM's
    /// end; returns the end the vsock device gets.
    fn open(self: &Arc<Self>) -> io::Result<UnixStream> {
        let (ours, theirs) = UnixStream::pair()?;
        let ingest = Arc::clone(self);
        thread::Builder::new()
            .name("sensor-rx".into())
            .spawn(move || ingest.read_frames(theirs))?;
        self.lock().connected = true;
        Ok(ours)
    }

    /// The reader: the sensor's frames until the stream ends or a frame is
    /// not a sensor's.
    fn read_frames(&self, mut stream: UnixStream) {
        let mut decoder = Decoder::new();
        let mut buf = vec![0u8; READ_CHUNK];
        'read: loop {
            let n = match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            decoder.feed(&buf[..n]);
            loop {
                match decoder.next_frame() {
                    Ok(Some(frame)) => self.record(frame),
                    Ok(None) => break,
                    Err(error) => {
                        boxcar_virtio::limited!(
                            warn,
                            "sensor stream: closed on a frame that is not a sensor's: {error}"
                        );
                        break 'read;
                    }
                }
            }
        }
        // Dropping the stream is what tells the vsock device.
        let mut state = self.lock();
        state.connected = false;
        state.ended = true;
    }

    /// Notes what the frame says about the sensor, then records it; waits
    /// for room in the log.
    fn record(&self, frame: SensorFrame) {
        {
            let mut state = self.lock();
            match &frame.payload {
                Payload::ProcHeartbeat(_) => {
                    state.heartbeats += 1;
                    state.last_heartbeat = Some((Instant::now(), realtime_ns()));
                }
                Payload::ProcSensorStatus(status) => state.phase = Some(status.phase),
                _ => {}
            }
        }
        // A closed or failed log stops the VM by itself.
        let _ = self.audit.emit(submission(frame));
    }
}

/// The ring 1 submission a frame becomes: the guest's clock and subject as
/// sent, written through at once when it is a `proc.lsm_deny`.
pub fn submission(frame: SensorFrame) -> Submission {
    let priority = match frame.payload {
        Payload::ProcLsmDeny(_) => Priority::Critical,
        _ => Priority::Normal,
    };
    Submission {
        ring: Ring::Guest,
        ts_guest_ns: Some(frame.ts_guest_ns),
        subject: frame.subject,
        payload: frame.payload,
        span: None,
        priority,
    }
}

/// Host `CLOCK_REALTIME` in nanoseconds since the Unix epoch.
fn realtime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid pointer to a timespec, which the call fills.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return 0;
    }
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    use boxcar_audit::{LogReader, Priority, WriterConfig};
    use boxcar_proto::control::SensorState;
    use boxcar_proto::sensor::{encode, SensorFrame};
    use boxcar_proto::{
        Payload, ProcExec, ProcHeartbeat, ProcLsmDeny, ProcSensorStatus, Record, Ring, SensorPhase,
        SessionId, Source, Subject,
    };
    use boxcar_vsock::{ConnMeta, Deny};
    use serde_json::json;

    use super::*;

    const LIMIT: Duration = Duration::from_secs(5);

    fn subject() -> Subject {
        Subject {
            pid: 212,
            uid: 1000,
            gid: 1000,
        }
    }

    fn exec_frame(ts_guest_ns: u64, argv: &[&str]) -> SensorFrame {
        SensorFrame {
            ts_guest_ns,
            subject: Some(subject()),
            payload: Payload::ProcExec(ProcExec {
                tid: 212,
                tgid: 212,
                ppid: 200,
                uid: 1000,
                gid: 1000,
                filename: "/bin/ls".into(),
                argv: argv.iter().map(|a| a.to_string()).collect(),
                argv_truncated: false,
                start_ns: 99,
                cgroup_id: 4242,
            }),
        }
    }

    fn heartbeat_frame(ts_guest_ns: u64, frames_sent: u64) -> SensorFrame {
        SensorFrame {
            ts_guest_ns,
            subject: None,
            payload: Payload::ProcHeartbeat(ProcHeartbeat {
                uptime_ns: ts_guest_ns,
                events_emitted: frames_sent,
                ringbuf_drops: 0,
                frames_sent,
            }),
        }
    }

    fn deny_frame() -> SensorFrame {
        SensorFrame {
            ts_guest_ns: 5,
            subject: Some(subject()),
            payload: Payload::ProcLsmDeny(ProcLsmDeny {
                tid: 212,
                tgid: 212,
                hook: "bpf".into(),
                detail: 5,
            }),
        }
    }

    fn status_frame(phase: SensorPhase) -> SensorFrame {
        SensorFrame {
            ts_guest_ns: 1,
            subject: None,
            payload: Payload::ProcSensorStatus(ProcSensorStatus {
                phase,
                programs: Vec::new(),
                kernel_release: "6.18.54".into(),
                btf_ok: true,
                session_cgroup_id: 4242,
                pid: 77,
                threads: Vec::new(),
                reason: None,
            }),
        }
    }

    fn log(dir: &std::path::Path) -> Vec<Record> {
        LogReader::open(dir)
            .unwrap()
            .records()
            .map(Result::unwrap)
            .filter(|r| r.kind.starts_with("proc."))
            .collect()
    }

    fn wait_for(ingest: &SensorIngest, what: &str, cond: impl Fn(&SensorStatus) -> bool) {
        let deadline = Instant::now() + LIMIT;
        while !cond(&ingest.status()) {
            assert!(Instant::now() < deadline, "{what}: {:?}", ingest.status());
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    struct Harness {
        ingest: Arc<SensorIngest>,
        writer: boxcar_audit::WriterHandle,
        session_dir: std::path::PathBuf,
        _tmp: tempfile::TempDir,
    }

    fn harness(silence: Duration) -> Harness {
        let tmp = tempfile::tempdir().unwrap();
        let (sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(tmp.path(), SessionId::new())).unwrap();
        let session_dir = writer.session_dir().to_path_buf();
        Harness {
            ingest: SensorIngest::with_silence(sink, silence),
            writer,
            session_dir,
            _tmp: tmp,
        }
    }

    fn connect(ingest: &Arc<SensorIngest>) -> UnixStream {
        let stream = (ingest.service())(ConnMeta { guest_port: 1021 }).unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        stream
    }

    #[test]
    fn a_valid_frame_becomes_a_ring_1_submission() {
        let h = harness(SILENCE);
        assert_eq!(h.ingest.status().state, SensorState::Waiting);
        let mut guest = connect(&h.ingest);
        // Connected, but nothing said yet.
        assert_eq!(h.ingest.status().state, SensorState::Waiting);
        guest
            .write_all(&encode(&status_frame(SensorPhase::Attached)).unwrap())
            .unwrap();
        guest
            .write_all(&encode(&exec_frame(777, &["ls", "-l"])).unwrap())
            .unwrap();
        guest
            .write_all(&encode(&heartbeat_frame(800, 1)).unwrap())
            .unwrap();
        wait_for(&h.ingest, "the heartbeat", |s| s.heartbeats == 1);
        let status = h.ingest.status();
        assert_eq!(status.state, SensorState::Attached);
        assert!(status.last_heartbeat_ns.is_some(), "{status:?}");

        // The sensor connects once in the VM's life.
        assert_eq!(
            (h.ingest.service())(ConnMeta { guest_port: 1021 }).err(),
            Some(Deny::Refused(REACTIVATED))
        );

        // Its stream's end is the sensor falling silent.
        drop(guest);
        wait_for(&h.ingest, "the stream's end", |s| {
            s.state == SensorState::Silent
        });
        h.writer.close().unwrap();
        let records = log(&h.session_dir);
        let kinds: Vec<&str> = records.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["proc.sensor_status", "proc.exec", "proc.heartbeat"]);
        for record in &records {
            assert_eq!(record.ring, Ring::Guest, "{record:?}");
            assert_eq!(record.src, Source::Sensor, "{record:?}");
        }
        let exec = &records[1];
        assert_eq!(exec.ts_guest_ns, Some(777));
        assert_eq!(exec.subject, Some(subject()));
        assert_eq!(exec.data["argv"], json!(["ls", "-l"]));
        assert_eq!(records[2].subject, None);
        assert_eq!(records[2].ts_guest_ns, Some(800));
    }

    #[test]
    fn lsm_denies_are_critical_and_the_rest_normal() {
        let critical = submission(deny_frame());
        assert_eq!(critical.priority, Priority::Critical);
        assert_eq!(critical.ring, Ring::Guest);
        assert_eq!(critical.ts_guest_ns, Some(5));
        assert_eq!(critical.subject, Some(subject()));
        let normal = submission(exec_frame(1, &["ls"]));
        assert_eq!(normal.priority, Priority::Normal);
        assert_eq!(normal.ring, Ring::Guest);
        assert_eq!(normal.ts_guest_ns, Some(1));
        assert!(normal.span.is_none());
    }

    #[test]
    fn garbage_frames_end_the_connection_quietly() {
        // A length no frame has.
        let h = harness(SILENCE);
        let mut guest = connect(&h.ingest);
        guest.write_all(b"\xff\xff\xff\x7fnot a frame").unwrap();
        let mut rest = Vec::new();
        guest.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "the VMM wrote nothing back: {rest:?}");
        wait_for(&h.ingest, "the stream's end", |s| {
            s.state == SensorState::Silent
        });

        // A frame of a kind that does not travel here, well formed.
        let h2 = harness(SILENCE);
        let mut guest = connect(&h2.ingest);
        let json = serde_json::to_vec(&json!({
            "ts_guest_ns": 1,
            "type": "session.exit",
            "data": {"code": 0, "signal": null},
        }))
        .unwrap();
        let mut raw = (json.len() as u32).to_le_bytes().to_vec();
        raw.extend(json);
        guest.write_all(&raw).unwrap();
        let mut rest = Vec::new();
        guest.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        wait_for(&h2.ingest, "the stream's end", |s| {
            s.state == SensorState::Silent
        });

        for h in [h, h2] {
            h.writer.close().unwrap();
            assert!(log(&h.session_dir).is_empty(), "nothing was recorded");
        }
    }

    #[test]
    fn a_flooding_sensor_is_taken_without_loss_and_connect_never_waits() {
        let h = harness(SILENCE);
        let frames: Vec<u8> = (1..=10_000u64)
            .flat_map(|n| encode(&heartbeat_frame(n, n)).unwrap())
            .collect();
        let started = Instant::now();
        let mut guest = connect(&h.ingest);
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "connect took {:?}",
            started.elapsed()
        );
        guest.write_all(&frames).unwrap();
        drop(guest);
        wait_for(&h.ingest, "every frame", |s| s.heartbeats == 10_000);
        h.writer.close().unwrap();
        let records = log(&h.session_dir);
        assert_eq!(records.len(), 10_000);
        assert_eq!(records[9_999].ts_guest_ns, Some(10_000));
    }

    #[test]
    fn the_status_follows_what_the_sensor_says_and_when() {
        let h = harness(Duration::from_millis(60));
        let mut guest = connect(&h.ingest);
        guest
            .write_all(&encode(&status_frame(SensorPhase::Degraded)).unwrap())
            .unwrap();
        wait_for(&h.ingest, "degraded", |s| s.state == SensorState::Degraded);
        guest
            .write_all(&encode(&status_frame(SensorPhase::Attached)).unwrap())
            .unwrap();
        guest
            .write_all(&encode(&heartbeat_frame(1, 1)).unwrap())
            .unwrap();
        wait_for(&h.ingest, "attached", |s| s.state == SensorState::Attached);
        // Quiet past the silence: silent, until the next heartbeat.
        wait_for(&h.ingest, "silent", |s| s.state == SensorState::Silent);
        guest
            .write_all(&encode(&heartbeat_frame(2, 2)).unwrap())
            .unwrap();
        wait_for(&h.ingest, "attached again", |s| {
            s.state == SensorState::Attached && s.heartbeats == 2
        });
        drop(guest);
        h.writer.close().unwrap();
    }
}
