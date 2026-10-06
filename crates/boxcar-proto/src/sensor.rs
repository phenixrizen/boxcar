// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The sensor stream: ring 1 records from the guest's sensor to the VMM on
//! vsock port 1026 (`boxcar.sensor`).
//!
//! A frame is a 4-byte little-endian length, then that many bytes of JSON:
//! a [`SensorFrame`], which is the record's `type` and `data` as the audit
//! [`Payload`] writes them, with the guest's clock (`ts_guest_ns`) and the
//! process the record is about (`subject`) beside them. The VMM's writer
//! supplies everything else in the envelope: `seq`, the host clocks, `src`
//! `sensor`, `ring` 1.
//!
//! ```text
//! [len u32 LE][{"ts_guest_ns":..,"subject":{..},"type":"proc.exec","data":{..}}]
//! ```
//!
//! The JSON is at most [`MAX_FRAME`] bytes. Only `proc.*` records travel
//! here ([`is_sensor_kind`]); the limits of [`crate::limits`] apply to the
//! strings inside ([`SensorFrame::check`]). A frame that breaks any of this
//! ends the stream: the host closes the connection and the sensor's silence
//! is what the log then shows.

use serde::{Deserialize, Serialize};

use crate::limits::{MAX_ARGV_BYTES, MAX_ARGV_ELEMS, MAX_PATH, MAX_SUMMARY};
use crate::{Payload, Subject};

/// The most JSON a frame carries, in bytes, its length prefix not counted.
pub const MAX_FRAME: usize = 65536;

/// The longest `proc.memfd` name, as the kernel allows.
pub const MAX_MEMFD_NAME: usize = 256;

/// The most programs a `proc.sensor_status` lists.
pub const MAX_PROGRAMS: usize = 32;

/// The longest hook, program, transport or kernel release name.
const MAX_NAME: usize = 128;

/// Whether records of `kind` travel on the sensor stream: the `proc.*`
/// family, and nothing else.
pub fn is_sensor_kind(kind: &str) -> bool {
    kind.starts_with("proc.")
}

/// One record from the sensor: the guest's clock when it happened, the
/// process it is about, and the record's `type` and `data`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SensorFrame {
    /// The guest's `CLOCK_MONOTONIC`, in nanoseconds.
    pub ts_guest_ns: u64,
    /// The thread the record is about, with its user; none for the
    /// sensor's own records (heartbeat, status).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    /// The record, as `type` and `data`.
    #[serde(flatten)]
    pub payload: Payload,
}

/// Why bytes are not a frame, or a frame is not accepted.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The length prefix says this many bytes: over [`MAX_FRAME`].
    #[error("a frame of {0} bytes, over the sensor stream's limit of {MAX_FRAME}")]
    TooLong(usize),
    /// Not JSON, or not a record.
    #[error("not a sensor frame: {0}")]
    Json(String),
    /// A record of a kind that does not travel on the stream.
    #[error("{0:?} records do not travel on the sensor stream")]
    Kind(String),
    /// A string or list over its limit.
    #[error("{0}")]
    Limit(String),
}

fn within(what: &str, len: usize, max: usize) -> Result<(), FrameError> {
    if len > max {
        return Err(FrameError::Limit(format!(
            "{what} is {len} bytes, over {max}"
        )));
    }
    Ok(())
}

impl SensorFrame {
    /// Whether the frame may travel: a `proc.*` record whose strings and
    /// lists are within their limits.
    pub fn check(&self) -> Result<(), FrameError> {
        let kind = self.payload.kind();
        if !is_sensor_kind(kind) {
            return Err(FrameError::Kind(kind.to_owned()));
        }
        match &self.payload {
            Payload::ProcExec(exec) => {
                within("filename", exec.filename.len(), MAX_PATH)?;
                if exec.argv.len() > MAX_ARGV_ELEMS {
                    return Err(FrameError::Limit(format!(
                        "argv has {} elements, over {MAX_ARGV_ELEMS}",
                        exec.argv.len()
                    )));
                }
                let bytes: usize = exec.argv.iter().map(String::len).sum();
                within("argv", bytes, MAX_ARGV_BYTES)?;
            }
            Payload::ProcFileOpen(open) => within("path", open.path.len(), MAX_PATH)?,
            Payload::ProcMemfd(memfd) => within("name", memfd.name.len(), MAX_MEMFD_NAME)?,
            Payload::ProcLsmDeny(deny) => within("hook", deny.hook.len(), MAX_NAME)?,
            Payload::ProcConnectAttempt(attempt) => {
                within("proto", attempt.proto.len(), MAX_NAME)?;
            }
            Payload::ProcTlsIo(io) => within("dir", io.dir.len(), MAX_NAME)?,
            Payload::ProcTlsAttach(attach) => {
                within("path", attach.path.len(), MAX_PATH)?;
                if let Some(error) = &attach.error {
                    within("error", error.len(), MAX_SUMMARY)?;
                }
            }
            Payload::ProcSensorStatus(status) => {
                within("kernel_release", status.kernel_release.len(), MAX_NAME)?;
                if status.programs.len() > MAX_PROGRAMS {
                    return Err(FrameError::Limit(format!(
                        "{} programs, over {MAX_PROGRAMS}",
                        status.programs.len()
                    )));
                }
                for program in &status.programs {
                    within("a program's name", program.name.len(), MAX_NAME)?;
                    if let Some(error) = &program.error {
                        within("a program's error", error.len(), MAX_SUMMARY)?;
                    }
                }
                if let Some(reason) = &status.reason {
                    within("reason", reason.len(), MAX_SUMMARY)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// `frame` as its bytes on the stream: the length, then the JSON. Refused
/// when the frame may not travel ([`SensorFrame::check`]) or its JSON is
/// over [`MAX_FRAME`].
pub fn encode(frame: &SensorFrame) -> Result<Vec<u8>, FrameError> {
    frame.check()?;
    let json = serde_json::to_vec(frame).map_err(|e| FrameError::Json(e.to_string()))?;
    if json.len() > MAX_FRAME {
        return Err(FrameError::TooLong(json.len()));
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Frames out of a byte stream, however the bytes arrive. Feed what was
/// read, then take frames until there is none complete. An error means the
/// stream is not a sensor's: stop reading it.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Whether nothing is waiting: no partial frame.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next complete frame, or `None` until more bytes arrive.
    pub fn next_frame(&mut self) -> Result<Option<SensorFrame>, FrameError> {
        let Some(prefix) = self.buf.get(..4) else {
            return Ok(None);
        };
        let len = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
        if len > MAX_FRAME {
            return Err(FrameError::TooLong(len));
        }
        let Some(json) = self.buf.get(4..4 + len) else {
            return Ok(None);
        };
        let frame: SensorFrame =
            serde_json::from_slice(json).map_err(|e| FrameError::Json(e.to_string()))?;
        self.buf.drain(..4 + len);
        frame.check()?;
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::control::StopMode;
    use crate::{ControlStop, Payload, ProcExec, ProcHeartbeat, Subject};

    fn exec(argv: Vec<String>) -> SensorFrame {
        SensorFrame {
            ts_guest_ns: 123,
            subject: Some(Subject {
                pid: 212,
                uid: 1000,
                gid: 1000,
            }),
            payload: Payload::ProcExec(ProcExec {
                tid: 212,
                tgid: 212,
                ppid: 200,
                uid: 1000,
                gid: 1000,
                filename: "/bin/ls".into(),
                argv,
                argv_truncated: false,
                start_ns: 99,
                cgroup_id: 4242,
            }),
        }
    }

    fn heartbeat() -> SensorFrame {
        SensorFrame {
            ts_guest_ns: 456,
            subject: None,
            payload: Payload::ProcHeartbeat(ProcHeartbeat {
                uptime_ns: 1_000_000_000,
                events_emitted: 1,
                ringbuf_drops: 0,
                frames_sent: 1,
            }),
        }
    }

    #[test]
    fn frames_have_their_documented_shape_and_limits() {
        let frame = exec(vec!["ls".into(), "-l".into()]);
        let bytes = encode(&frame).unwrap();
        let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(len, bytes.len() - 4);
        let json: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
        assert_eq!(json["type"], "proc.exec");
        assert_eq!(json["ts_guest_ns"], 123);
        assert_eq!(
            json["subject"],
            json!({"pid": 212, "uid": 1000, "gid": 1000})
        );
        assert_eq!(json["data"]["argv"], json!(["ls", "-l"]));
        assert_eq!(json["data"]["filename"], "/bin/ls");
        let mut decoder = Decoder::new();
        decoder.feed(&bytes);
        assert_eq!(decoder.next_frame().unwrap(), Some(frame));
        assert_eq!(decoder.next_frame().unwrap(), None);

        // No subject: the key is left out, and reads back as none.
        let bytes = encode(&heartbeat()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
        assert!(json.get("subject").is_none(), "{json}");
        let mut decoder = Decoder::new();
        decoder.feed(&bytes);
        assert_eq!(decoder.next_frame().unwrap(), Some(heartbeat()));

        // Only sensor records travel here.
        let not_proc = SensorFrame {
            ts_guest_ns: 1,
            subject: None,
            payload: Payload::ControlStop(ControlStop {
                by_pid: 1,
                mode: StopMode::Graceful,
            }),
        };
        assert_eq!(
            encode(&not_proc).unwrap_err(),
            FrameError::Kind("control.stop".into())
        );
        // Received, such a frame is refused the same way.
        let json = serde_json::to_vec(&not_proc).unwrap();
        let mut raw = (json.len() as u32).to_le_bytes().to_vec();
        raw.extend(json);
        let mut decoder = Decoder::new();
        decoder.feed(&raw);
        assert_eq!(
            decoder.next_frame().unwrap_err(),
            FrameError::Kind("control.stop".into())
        );

        // argv: 256 elements and 16 KiB at most.
        let many = exec((0..257).map(|i| i.to_string()).collect());
        assert!(
            matches!(encode(&many), Err(FrameError::Limit(_))),
            "257 elements"
        );
        let most = exec((0..256).map(|i| i.to_string()).collect());
        encode(&most).unwrap();
        let big = exec(vec!["x".repeat(16384), "y".into()]);
        assert!(
            matches!(encode(&big), Err(FrameError::Limit(_))),
            "16385 bytes"
        );
        let full = exec(vec!["x".repeat(16383), "y".into()]);
        encode(&full).unwrap();
        // A path over its limit.
        let mut long_name = exec(vec!["ls".into()]);
        if let Payload::ProcExec(ref mut e) = long_name.payload {
            e.filename = "/".repeat(4097);
        }
        assert!(matches!(encode(&long_name), Err(FrameError::Limit(_))));
    }

    #[test]
    fn the_decoder_reassembles_split_frames_and_refuses_bad_lengths() {
        let first = encode(&exec(vec!["a".into()])).unwrap();
        let second = encode(&heartbeat()).unwrap();
        let mut all = first.clone();
        all.extend(&second);
        let mut decoder = Decoder::new();
        let mut got = Vec::new();
        for chunk in all.chunks(7) {
            decoder.feed(chunk);
            while let Some(frame) = decoder.next_frame().unwrap() {
                got.push(frame);
            }
        }
        assert_eq!(got, [exec(vec!["a".into()]), heartbeat()]);
        assert!(decoder.is_empty());

        // A length over the limit is refused before any of the frame is
        // read: the sender is not a sensor.
        let mut decoder = Decoder::new();
        decoder.feed(&((MAX_FRAME as u32) + 1).to_le_bytes());
        assert_eq!(
            decoder.next_frame().unwrap_err(),
            FrameError::TooLong(MAX_FRAME + 1)
        );
        // The largest length, with bytes that are not a frame.
        let mut decoder = Decoder::new();
        decoder.feed(&(MAX_FRAME as u32).to_le_bytes());
        decoder.feed(&vec![b'x'; MAX_FRAME]);
        assert!(matches!(decoder.next_frame(), Err(FrameError::Json(_))));
        // A length of zero is not a frame either.
        let mut decoder = Decoder::new();
        decoder.feed(&0u32.to_le_bytes());
        assert!(matches!(decoder.next_frame(), Err(FrameError::Json(_))));
        // Three bytes are not a length yet.
        let mut decoder = Decoder::new();
        decoder.feed(&[1, 0, 0]);
        assert_eq!(decoder.next_frame().unwrap(), None);
    }

    #[test]
    fn every_proc_kind_is_a_sensor_record_and_nothing_else_is() {
        for kind in [
            "proc.exec",
            "proc.fork",
            "proc.exit",
            "proc.connect_attempt",
            "proc.tcp_connect",
            "proc.memfd",
            "proc.file_open",
            "proc.lsm_deny",
            "proc.heartbeat",
            "proc.sensor_status",
            "proc.tls_io",
            "proc.tls_attach",
        ] {
            assert!(is_sensor_kind(kind), "{kind}");
        }
        for kind in [
            "sync",
            "finding",
            "fs.open",
            "session.start",
            "proc",
            "procx.exec",
            "",
        ] {
            assert!(!is_sensor_kind(kind), "{kind}");
        }
    }
}
