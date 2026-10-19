// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest's DNS query rate (a policy file's `max_dns_qps`): a burst of
//! `qps` messages, then one each `1 s / qps`, kept as a generic cell rate
//! (the theoretical time the next message is due).

use std::time::{Duration, Instant};

/// The rule text a `net.dns` gives for a message refused for the rate.
pub const RULE: &str = "dns_rate";

/// How many DNS messages the guest may send, and when.
#[derive(Clone, Debug)]
pub struct QueryRate {
    /// The time between messages once a burst is spent: `1 s / qps`.
    interval: Duration,
    /// How far ahead of now the next due time may be and still admit a
    /// message: `qps - 1` intervals, so a burst holds `qps`.
    tolerance: Duration,
    /// When the next message is due, if any came.
    due: Option<Instant>,
}

impl QueryRate {
    /// A rate of `qps` messages a second (at least 1).
    pub fn new(qps: u32) -> QueryRate {
        let qps = qps.max(1);
        let interval = Duration::from_secs(1) / qps;
        QueryRate {
            interval,
            tolerance: interval * (qps - 1),
            due: None,
        }
    }

    /// Whether a message at `now` is within the rate. One that is, is
    /// counted; one that is not, is not, so a guest that keeps asking over
    /// the rate gets through again as soon as the rate allows.
    pub fn admit(&mut self, now: Instant) -> bool {
        let due = self.due.map_or(now, |due| due.max(now));
        if due.saturating_duration_since(now) > self.tolerance {
            return false;
        }
        self.due = Some(due + self.interval);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many of `count` messages at `now` the rate admits.
    fn admitted(rate: &mut QueryRate, now: Instant, count: usize) -> usize {
        (0..count).filter(|_| rate.admit(now)).count()
    }

    /// A burst of `qps`, then nothing until an interval has passed, then
    /// one each interval; a whole second refills the burst.
    #[test]
    fn a_burst_then_one_each_interval() {
        let start = Instant::now();
        let mut rate = QueryRate::new(4);
        assert_eq!(admitted(&mut rate, start, 10), 4);
        let quarter = Duration::from_millis(250);
        assert!(!rate.admit(start + quarter / 2), "half an interval");
        assert!(rate.admit(start + quarter));
        assert!(!rate.admit(start + quarter));
        assert!(rate.admit(start + quarter * 2));
        // Idle for a second and more: a whole burst again, and no more.
        let later = start + Duration::from_secs(5);
        assert_eq!(admitted(&mut rate, later, 10), 4);
    }

    /// One a second admits one, then the next a second later.
    #[test]
    fn one_a_second() {
        let start = Instant::now();
        let mut rate = QueryRate::new(1);
        assert!(rate.admit(start));
        assert!(!rate.admit(start));
        assert!(!rate.admit(start + Duration::from_millis(999)));
        assert!(rate.admit(start + Duration::from_secs(1)));
        assert!(!rate.admit(start + Duration::from_secs(1)));
    }

    /// Refusals do not count: a guest asking over the rate all the time
    /// still gets one through each interval.
    #[test]
    fn refusals_are_not_counted() {
        let start = Instant::now();
        let mut rate = QueryRate::new(2);
        let half = Duration::from_millis(500);
        assert_eq!(admitted(&mut rate, start, 2), 2);
        for step in 1..=10u32 {
            let now = start + half * step;
            assert_eq!(admitted(&mut rate, now, 100), 1, "step {step}");
        }
    }

    /// The largest rate a policy may give still bounds a burst, and zero
    /// is taken as one.
    #[test]
    fn the_largest_and_the_smallest() {
        let start = Instant::now();
        let mut rate = QueryRate::new(10_000);
        assert_eq!(admitted(&mut rate, start, 20_000), 10_000);
        assert!(rate.admit(start + Duration::from_micros(100)));
        let mut zero = QueryRate::new(0);
        assert_eq!(admitted(&mut zero, start, 3), 1);
    }
}
