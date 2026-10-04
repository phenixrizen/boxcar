// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The reconciler's idea of now: host `CLOCK_REALTIME` in nanoseconds, the
//! same clock as every record's `ts_host_ns`, so timers and records compare.
//! Tests pause it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A source of the current time, comparable with `ts_host_ns`.
pub trait Clock: Send + Sync {
    /// Host `CLOCK_REALTIME`, in nanoseconds since the epoch.
    fn now_ns(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid pointer to a timespec, which the call fills.
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
            return 0;
        }
        u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000
            + u64::try_from(ts.tv_nsec).unwrap_or(0)
    }
}

/// A clock that moves only when told: the tests' timers.
#[derive(Debug, Default)]
pub struct ManualClock {
    ns: AtomicU64,
}

impl ManualClock {
    pub fn new(ns: u64) -> ManualClock {
        ManualClock {
            ns: AtomicU64::new(ns),
        }
    }

    pub fn set(&self, ns: u64) {
        self.ns.store(ns, Ordering::SeqCst);
    }

    pub fn advance(&self, by: Duration) {
        self.ns.fetch_add(
            u64::try_from(by.as_nanos()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }
}

impl Clock for ManualClock {
    fn now_ns(&self) -> u64 {
        self.ns.load(Ordering::SeqCst)
    }
}
