// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! At most one log line per second from each call site the guest can
//! trigger at will: a malformed virtio request, an invalid register write.
//! A guest that repeats one in a loop would otherwise fill the host's log
//! and disk. The line that does get out says how many were held back
//! before it (`suppressed`).
//!
//! [`limited!`](crate::limited) is the way in: it gives its call site a
//! `static` [`RateLimit`] of its own and logs through `tracing` at the
//! level named.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[doc(hidden)]
pub use tracing;

/// The shortest time between two lines from one site.
pub const INTERVAL: Duration = Duration::from_secs(1);
const INTERVAL_NS: u64 = INTERVAL.as_nanos() as u64;

/// One call site's limit: a line at most every [`INTERVAL`].
#[derive(Debug)]
pub struct RateLimit {
    /// When the last line went out, in nanoseconds since [`epoch`] plus
    /// one; 0 before the first.
    last: AtomicU64,
    /// Lines held back since the last one that went out.
    suppressed: AtomicU64,
}

impl RateLimit {
    pub const fn new() -> Self {
        RateLimit {
            last: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Whether a line may go out now. `Some(n)` when it may, with the
    /// number of lines held back since the last one; `None` when it is
    /// held back (and counted).
    pub fn check(&self) -> Option<u64> {
        let now = u64::try_from(epoch().elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.check_at(now)
    }

    /// [`check`](Self::check) at `now`, in nanoseconds on a monotonic
    /// clock.
    pub fn check_at(&self, now: u64) -> Option<u64> {
        let stamp = now.saturating_add(1);
        let last = self.last.load(Ordering::Relaxed);
        let due = last == 0 || stamp.saturating_sub(last) >= INTERVAL_NS;
        // Of callers racing for one slot, one wins; the rest are held back.
        let won = due
            && self
                .last
                .compare_exchange(last, stamp, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok();
        if !won {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self::new()
    }
}

/// The instant the limits' clock counts from: the first use.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// `tracing::$level!(...)`, at most once per second from this call site,
/// with a `suppressed` field counting the lines held back before it.
///
/// ```
/// # let base = 0xc000_0000u64;
/// boxcar_virtio::limited!(warn, "virtio-mmio {base:#x}: bad write");
/// ```
#[macro_export]
macro_rules! limited {
    ($level:ident, $($arg:tt)+) => {{
        static LIMIT: $crate::ratelimit::RateLimit = $crate::ratelimit::RateLimit::new();
        if let Some(suppressed) = LIMIT.check() {
            $crate::ratelimit::tracing::$level!(suppressed, $($arg)+);
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn one_line_per_second_and_a_count_of_the_rest() {
        let limit = RateLimit::new();
        // The first line goes out at once, even at time 0.
        assert_eq!(limit.check_at(0), Some(0));
        // Everything within the next second is held back and counted.
        assert_eq!(limit.check_at(1), None);
        assert_eq!(limit.check_at(SECOND / 2), None);
        assert_eq!(limit.check_at(SECOND - 1), None);
        // A second after the last line, the next goes out with the count.
        assert_eq!(limit.check_at(SECOND), Some(3));
        assert_eq!(limit.check_at(SECOND + 1), None);
        // After a quiet spell the count starts over.
        assert_eq!(limit.check_at(10 * SECOND), Some(1));
        assert_eq!(limit.check_at(11 * SECOND), Some(0));
        // A clock reading older than the last line is held back too.
        assert_eq!(limit.check_at(5 * SECOND), None);
    }

    #[test]
    fn sites_are_limited_apart() {
        let (a, b) = (RateLimit::new(), RateLimit::new());
        assert_eq!(a.check_at(7), Some(0));
        assert_eq!(b.check_at(7), Some(0));
        assert_eq!(a.check_at(8), None);
        assert_eq!(b.check_at(8), None);
    }

    #[test]
    fn a_flood_from_many_threads_lets_one_line_out() {
        let limit = RateLimit::new();
        let out: u64 = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| (0..1000).filter(|_| limit.check_at(42).is_some()).count()))
                .collect();
            workers.into_iter().map(|w| w.join().unwrap() as u64).sum()
        });
        assert_eq!(out, 1);
        assert_eq!(limit.check_at(42 + SECOND), Some(7999));
    }

    #[test]
    fn the_macro_expands_at_any_level() {
        let base = 0xc000_0000u64;
        for _ in 0..3 {
            crate::limited!(warn, "virtio-mmio {base:#x}: a test line");
            crate::limited!(error, tag = "t", "virtio-fs: a test line");
        }
    }
}
