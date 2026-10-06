// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The network stack's way into the audit log, and the coalescing that
//! keeps a guest that floods it with junk from flooding the log.
//!
//! [`emit`] is for records that must not be lost (leases, DNS queries,
//! verdicts); [`try_emit`] for records the log may drop when it is busy,
//! which it counts (`net.drop`). Dropped frames are recorded through
//! [`Drops`]: at most one `net.drop` a second for each [`DropReason`],
//! counting every frame since the last.

use std::time::{Duration, Instant};

use boxcar_audit::{AuditSink, EmitError, Priority, Submission};
use boxcar_proto::{NetClose, NetDrop, Payload, Ring};

use crate::tcp::FlowId;

/// The shortest time between two `net.drop` records for one reason.
pub const DROP_INTERVAL: Duration = Duration::from_secs(1);

/// Records `payload`, waiting while the log's channel is full.
pub fn emit(sink: &AuditSink, payload: Payload) -> Result<(), EmitError> {
    sink.emit(submission(payload))
}

/// Records an event that must not be dropped, waiting for room in the
/// log. A log that is closed (the session is ending) or has failed (the
/// VMM stops on that) records nothing more.
pub(crate) fn record(sink: &AuditSink, payload: Payload) {
    #[cfg(test)]
    tests::RECORDED.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(&payload);
        }
    });
    match emit(sink, payload) {
        Ok(()) | Err(EmitError::Closed | EmitError::Failed) => {}
        Err(error @ EmitError::Checkpoint) => {
            boxcar_virtio::limited!(error, "net: audit record refused: {error}");
        }
    }
}

/// The `net.close` of flow `id`, opened at `opened` and ending at `now`
/// for `reason`, having moved `tx` bytes from the guest and `rx` to it.
pub(crate) fn close_record(
    id: FlowId,
    tx: u64,
    rx: u64,
    opened: Instant,
    now: Instant,
    reason: &str,
) -> Payload {
    let dur_ms = now.saturating_duration_since(opened).as_millis();
    Payload::NetClose(NetClose {
        flow: id.0,
        tx,
        rx,
        dur_ms: u64::try_from(dur_ms).unwrap_or(u64::MAX),
        reason: reason.to_owned(),
    })
}

/// Records `payload` if the log's channel has room, and says whether it
/// did. The log counts what it drops and reports the count at its next
/// checkpoint.
pub fn try_emit(sink: &AuditSink, payload: Payload) -> bool {
    sink.try_emit(submission(payload))
}

fn submission(payload: Payload) -> Submission {
    Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: None,
        payload,
        span: None,
        priority: Priority::Normal,
    }
}

/// Why the stack dropped a guest frame: the `reason` of `net.drop`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// IPv6, which the guest network does not carry.
    Ipv6,
    /// ICMP other than an echo request to the gateway.
    Icmp,
    /// UDP to the DHCP port that gets no lease: a message other than a
    /// DISCOVER or a REQUEST, or a malformed one.
    Dhcp,
    /// UDP to the gateway's DNS port too short to hold a DNS header, which
    /// gets no answer. (Longer messages that are not plain queries get
    /// FORMERR, and a `net.dns`.)
    Dns,
    /// A datagram from the DNS upstream that answers no query in flight:
    /// its id is not in flight, its question is not that query's, or it
    /// does not read.
    DnsBogus,
    /// A datagram for a 5-tuple the UDP relay refused within the last
    /// minute: its first datagram was recorded (`net.udp` with the
    /// policy's denial), and the rest are counted here.
    UdpDenied,
    /// A guest datagram the host socket of its UDP mapping did not take
    /// (it had no room, or failed); datagrams are not queued.
    UdpSend,
    /// A reply too long for one datagram on the link (over 1472 bytes of
    /// payload): the relay does not fragment.
    UdpOversize,
    /// A datagram for a new 5-tuple the UDP relay allowed while its table
    /// was full and the most evicted sockets already waited to close: it
    /// opens no socket and is not recorded, and the next one is decided
    /// again.
    UdpTableFull,
    /// A queue between the guest and the stack was full.
    QueueFull,
    /// A guest SYN the policy allowed while the most host connects were
    /// under way: the guest sends it again, and it is decided then.
    TcpPendingFull,
    /// TCP, UDP or ICMP (DNS included) from an IPv4 source that is not the
    /// guest's address. (DHCP, answered by the gateway itself, may come
    /// from any address.)
    SrcSpoof,
    /// Plaintext of an inspected flow the observer's channel had no room
    /// for: the flow went on at the relay's pace, the observer's copy has
    /// a hole (counted in bytes, not frames).
    Observe,
    /// Anything else: an unknown protocol, or a malformed frame.
    Other,
}

impl DropReason {
    /// Every reason, in the order [`Drops`] keeps them.
    pub const ALL: [DropReason; 14] = [
        DropReason::Ipv6,
        DropReason::Icmp,
        DropReason::Dhcp,
        DropReason::Dns,
        DropReason::DnsBogus,
        DropReason::UdpDenied,
        DropReason::UdpSend,
        DropReason::UdpOversize,
        DropReason::UdpTableFull,
        DropReason::QueueFull,
        DropReason::TcpPendingFull,
        DropReason::SrcSpoof,
        DropReason::Observe,
        DropReason::Other,
    ];

    /// The reason as `net.drop` spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::Ipv6 => "ipv6",
            DropReason::Icmp => "icmp",
            DropReason::Dhcp => "dhcp",
            DropReason::Dns => "dns",
            DropReason::DnsBogus => "dns_bogus",
            DropReason::UdpDenied => "udp_denied",
            DropReason::UdpSend => "udp_send",
            DropReason::UdpOversize => "udp_oversize",
            DropReason::UdpTableFull => "udp_table_full",
            DropReason::QueueFull => "queue_full",
            DropReason::TcpPendingFull => "tcp_pending_full",
            DropReason::SrcSpoof => "src_spoof",
            DropReason::Observe => "observe",
            DropReason::Other => "other",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// One reason's count.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    /// When its last `net.drop` was made.
    last: Option<Instant>,
    /// Drops since then.
    held: u64,
}

impl Tally {
    /// Whether a record may be made at `now`: none has been, or the last
    /// was at least [`DROP_INTERVAL`] before. A clock reading older than
    /// the last record waits.
    fn due(&self, now: Instant) -> bool {
        self.last
            .is_none_or(|last| now.checked_duration_since(last) >= Some(DROP_INTERVAL))
    }

    fn take(&mut self, reason: DropReason, now: Instant) -> NetDrop {
        self.last = Some(now);
        NetDrop {
            reason: reason.as_str().to_owned(),
            count: std::mem::take(&mut self.held),
        }
    }
}

/// The dropped-frame counts, by reason, and when each may next be
/// recorded.
#[derive(Clone, Debug, Default)]
pub struct Drops {
    tallies: [Tally; DropReason::ALL.len()],
}

impl Drops {
    pub fn new() -> Self {
        Drops::default()
    }

    /// Counts one frame dropped for `reason` at `now`, and returns the
    /// `net.drop` to record now, if one is due: the first drop for a reason
    /// is recorded at once, and later ones once [`DROP_INTERVAL`] has passed
    /// since the last record. Until then they are held, and
    /// [`flush`](Self::flush) records them.
    pub fn count(&mut self, reason: DropReason, now: Instant) -> Option<NetDrop> {
        self.count_many(reason, 1, now)
    }

    /// [`count`](Self::count) for `n` frames at once; nothing for none.
    pub fn count_many(&mut self, reason: DropReason, n: u64, now: Instant) -> Option<NetDrop> {
        if n == 0 {
            return None;
        }
        let tally = &mut self.tallies[reason.index()];
        tally.held = tally.held.saturating_add(n);
        tally.due(now).then(|| tally.take(reason, now))
    }

    /// The `net.drop` records of every held count that is due at `now`.
    pub fn flush(&mut self, now: Instant) -> Vec<NetDrop> {
        DropReason::ALL
            .into_iter()
            .zip(&mut self.tallies)
            .filter(|(_, tally)| tally.held > 0 && tally.due(now))
            .map(|(reason, tally)| tally.take(reason, now))
            .collect()
    }

    /// The `net.drop` records of every held count, due or not: for when
    /// the stack stops.
    pub fn flush_all(&mut self, now: Instant) -> Vec<NetDrop> {
        DropReason::ALL
            .into_iter()
            .zip(&mut self.tallies)
            .filter(|(_, tally)| tally.held > 0)
            .map(|(reason, tally)| tally.take(reason, now))
            .collect()
    }

    /// When the earliest held count falls due, if any is held. (A count is
    /// held only behind a record already made, so each has a `last`.)
    pub fn next_due(&self) -> Option<Instant> {
        self.tallies
            .iter()
            .filter(|tally| tally.held > 0)
            .filter_map(|tally| tally.last?.checked_add(DROP_INTERVAL))
            .min()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    /// What a test runs on every record [`record`] makes on its thread, at
    /// the moment it makes it (before it reaches the log).
    pub(crate) type Hook = Box<dyn FnMut(&Payload)>;

    thread_local! {
        pub(crate) static RECORDED: RefCell<Option<Hook>> = RefCell::new(None);
    }

    fn drop_of(reason: &str, count: u64) -> NetDrop {
        NetDrop {
            reason: reason.to_owned(),
            count,
        }
    }

    #[test]
    fn the_first_drop_is_recorded_at_once_and_the_rest_once_a_second() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut drops = Drops::new();

        assert_eq!(
            drops.count(DropReason::Icmp, at(0)),
            Some(drop_of("icmp", 1))
        );
        assert_eq!(drops.next_due(), None, "nothing held");
        assert_eq!(drops.count(DropReason::Icmp, at(100)), None);
        assert_eq!(drops.count(DropReason::Icmp, at(999)), None);
        assert_eq!(drops.next_due(), Some(at(1000)));
        assert!(drops.flush(at(999)).is_empty(), "not due yet");

        assert_eq!(drops.flush(at(1000)), [drop_of("icmp", 2)]);
        assert_eq!(drops.next_due(), None);
        assert!(drops.flush(at(5000)).is_empty(), "nothing held");

        // A second after the last record, a drop goes out at once again.
        assert_eq!(
            drops.count(DropReason::Icmp, at(2000)),
            Some(drop_of("icmp", 1))
        );
        // A clock reading older than the last record waits.
        assert_eq!(drops.count(DropReason::Icmp, at(1500)), None);
        assert_eq!(drops.flush(at(3000)), [drop_of("icmp", 1)]);
    }

    #[test]
    fn counts_of_many_and_of_none() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut drops = Drops::new();
        assert_eq!(drops.count_many(DropReason::QueueFull, 0, at(0)), None);
        assert_eq!(drops.next_due(), None, "nothing counted");
        assert_eq!(
            drops.count_many(DropReason::QueueFull, 3, at(0)),
            Some(drop_of("queue_full", 3))
        );
        assert_eq!(drops.count_many(DropReason::QueueFull, 4, at(10)), None);
        assert_eq!(drops.flush(at(1000)), [drop_of("queue_full", 4)]);
    }

    #[test]
    fn flush_all_takes_what_is_held_due_or_not() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut drops = Drops::new();
        assert!(drops.count(DropReason::Ipv6, at(0)).is_some());
        assert!(drops.count(DropReason::Other, at(0)).is_some());
        for _ in 0..4 {
            assert_eq!(drops.count(DropReason::Ipv6, at(1)), None);
        }
        assert!(drops.flush(at(2)).is_empty(), "not due");
        assert_eq!(drops.flush_all(at(2)), [drop_of("ipv6", 4)]);
        assert!(drops.flush_all(at(3)).is_empty(), "nothing held");
        assert_eq!(drops.next_due(), None);
    }

    #[test]
    fn reasons_are_counted_apart() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut drops = Drops::new();

        assert_eq!(
            drops.count(DropReason::Ipv6, at(0)),
            Some(drop_of("ipv6", 1))
        );
        assert_eq!(
            drops.count(DropReason::Other, at(10)),
            Some(drop_of("other", 1))
        );
        for _ in 0..3 {
            assert_eq!(drops.count(DropReason::Ipv6, at(20)), None);
        }
        assert_eq!(drops.count(DropReason::Other, at(500)), None);
        assert_eq!(drops.next_due(), Some(at(1000)));

        assert_eq!(drops.flush(at(1000)), [drop_of("ipv6", 3)]);
        assert_eq!(drops.next_due(), Some(at(1010)));
        assert_eq!(drops.flush(at(1010)), [drop_of("other", 1)]);
    }

    #[test]
    fn durations_are_whole_milliseconds() {
        let t0 = Instant::now();
        let Payload::NetClose(close) = close_record(
            FlowId(3),
            1,
            2,
            t0,
            t0 + std::time::Duration::from_micros(2_500),
            "fin",
        ) else {
            panic!("not a close");
        };
        assert_eq!((close.flow, close.tx, close.rx, close.dur_ms), (3, 1, 2, 2));
        let Payload::NetClose(close) = close_record(FlowId(3), 0, 0, t0, t0, "fin") else {
            panic!("not a close");
        };
        assert_eq!(close.dur_ms, 0);
    }

    #[test]
    fn every_reason_has_its_own_slot_and_name() {
        for (i, reason) in DropReason::ALL.into_iter().enumerate() {
            assert_eq!(reason.index(), i, "{reason:?}");
        }
        let names: Vec<&str> = DropReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            names,
            [
                "ipv6",
                "icmp",
                "dhcp",
                "dns",
                "dns_bogus",
                "udp_denied",
                "udp_send",
                "udp_oversize",
                "udp_table_full",
                "queue_full",
                "tcp_pending_full",
                "src_spoof",
                "observe",
                "other"
            ]
        );
    }
}
