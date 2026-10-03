// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Once a second, whatever else happens: `proc.heartbeat`, with the
//! counters since the sensor started.

use std::time::{Duration, Instant};

use boxcar_proto::sensor::SensorFrame;
use boxcar_proto::{Payload, ProcHeartbeat};

/// How often a heartbeat goes out.
pub const INTERVAL: Duration = Duration::from_secs(1);

/// The heartbeat's schedule and counters.
pub struct Heartbeat {
    started: Instant,
    next_due: Instant,
    /// Events taken from the ring buffer so far.
    pub events_emitted: u64,
    /// Frames written to the stream so far, heartbeats included.
    pub frames_sent: u64,
}

impl Heartbeat {
    pub fn new(now: Instant) -> Heartbeat {
        Heartbeat {
            started: now,
            next_due: now + INTERVAL,
            events_emitted: 0,
            frames_sent: 0,
        }
    }

    /// Whether a heartbeat is due.
    pub fn due(&self, now: Instant) -> bool {
        now >= self.next_due
    }

    /// How long until the next one is due.
    pub fn wait(&self, now: Instant) -> Duration {
        self.next_due.saturating_duration_since(now)
    }

    /// A frame was written.
    pub fn sent(&mut self) {
        self.frames_sent += 1;
    }

    /// The heartbeat frame for now, and the next one scheduled: an interval
    /// after this one was due, or after now when the sensor stalled for
    /// longer than an interval, so a stall never makes a burst.
    pub fn frame(&mut self, now: Instant, ringbuf_drops: u64, ts_guest_ns: u64) -> SensorFrame {
        self.next_due = if now > self.next_due + INTERVAL {
            now + INTERVAL
        } else {
            self.next_due + INTERVAL
        };
        SensorFrame {
            ts_guest_ns,
            subject: None,
            payload: Payload::ProcHeartbeat(ProcHeartbeat {
                uptime_ns: u64::try_from(now.duration_since(self.started).as_nanos())
                    .unwrap_or(u64::MAX),
                events_emitted: self.events_emitted,
                ringbuf_drops,
                frames_sent: self.frames_sent,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use boxcar_proto::Payload;

    use super::*;

    #[test]
    fn a_heartbeat_goes_out_every_second_without_events() {
        let start = Instant::now();
        let mut hb = Heartbeat::new(start);
        assert!(!hb.due(start));
        assert_eq!(hb.wait(start), INTERVAL);
        let later = start + Duration::from_millis(400);
        assert_eq!(hb.wait(later), Duration::from_millis(600));
        let due = start + INTERVAL;
        assert!(hb.due(due));
        assert_eq!(hb.wait(due), Duration::ZERO);
        hb.events_emitted += 3;
        let frame = hb.frame(due, 5, 2_000_000_000);
        assert_eq!(frame.ts_guest_ns, 2_000_000_000);
        assert!(frame.subject.is_none());
        let Payload::ProcHeartbeat(beat) = frame.payload else {
            unreachable!()
        };
        assert_eq!(beat.uptime_ns, INTERVAL.as_nanos() as u64);
        assert_eq!((beat.events_emitted, beat.ringbuf_drops), (3, 5));
        // The heartbeat itself counts as a frame sent, once it is written.
        assert_eq!(beat.frames_sent, 0);
        hb.sent();
        assert_eq!(hb.frames_sent, 1);
        // The next one is due a second after this one, not after `now`.
        assert!(!hb.due(due + Duration::from_millis(999)));
        assert!(hb.due(due + INTERVAL));
        // A late tick does not pile up: the next is scheduled from the
        // last due time, at most one interval ahead of now.
        let late = due + Duration::from_secs(5);
        hb.frame(late, 0, 0);
        assert!(hb.wait(late) <= INTERVAL);
    }
}
