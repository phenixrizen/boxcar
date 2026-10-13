// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The observer's retained bytes, counted across every flow it holds.
//!
//! Each exchange and stream is bounded on its own (a kept body, an
//! event-stream line, a reply's tool calls), but the bounds multiply with
//! the streams and flows a guest opens. [`Retained`] is one budget the
//! observer thread shares out: a kept body, an event-stream parser's
//! buffer and a reply's tool calls each take their bytes from it through a
//! [`Share`], and give them back when they let go or are dropped. A holder
//! that finds no room degrades (the body is hashed but not kept, the line
//! dropped, the call not grown) rather than waiting or growing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The most bytes the observer retains at once, across every flow.
pub const RETAINED_LIMIT: usize = 256 * 1024 * 1024;

/// A budget of retained bytes, shared by its clones.
#[derive(Clone, Debug)]
pub struct Retained {
    held: Arc<AtomicUsize>,
    limit: usize,
}

impl Default for Retained {
    fn default() -> Retained {
        Retained::with_limit(RETAINED_LIMIT)
    }
}

impl Retained {
    /// A budget of `limit` bytes.
    pub fn with_limit(limit: usize) -> Retained {
        Retained {
            held: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    /// Takes `n` bytes if they are there: whether it did.
    fn take(&self, n: usize) -> bool {
        let mut held = self.held.load(Ordering::Relaxed);
        loop {
            let Some(next) = held.checked_add(n).filter(|next| *next <= self.limit) else {
                return false;
            };
            match self
                .held
                .compare_exchange_weak(held, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(now) => held = now,
            }
        }
    }

    fn give(&self, n: usize) {
        let _ = self
            .held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(n))
            });
    }

    /// How many bytes are held now.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }
}

/// One holder's part of a [`Retained`] budget, given back when dropped.
#[derive(Debug, Default)]
pub struct Share {
    retained: Retained,
    held: usize,
}

impl Share {
    pub fn new(retained: Retained) -> Share {
        Share { retained, held: 0 }
    }

    /// Takes `n` more bytes: whether there was room.
    pub fn grow(&mut self, n: usize) -> bool {
        if !self.retained.take(n) {
            return false;
        }
        self.held += n;
        true
    }

    /// Gives back `n` bytes (at most what is held).
    pub fn shrink(&mut self, n: usize) {
        let n = n.min(self.held);
        self.retained.give(n);
        self.held -= n;
    }

    /// Sets what is held to `want`: whether there was room to grow to it
    /// (if not, nothing changed).
    pub fn set(&mut self, want: usize) -> bool {
        if want > self.held {
            self.grow(want - self.held)
        } else {
            self.shrink(self.held - want);
            true
        }
    }

    /// Gives back everything held.
    pub fn clear(&mut self) {
        self.shrink(self.held);
    }

    /// How many bytes this holder has.
    pub fn held(&self) -> usize {
        self.held
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_draw_on_one_budget_and_give_back_when_dropped() {
        let retained = Retained::with_limit(100);
        let mut a = Share::new(retained.clone());
        let mut b = Share::new(retained.clone());
        assert!(a.grow(60));
        assert!(!b.grow(50), "only 40 left");
        assert!(b.grow(40));
        assert_eq!(retained.held(), 100);
        a.shrink(10);
        assert!(b.set(50));
        assert_eq!(retained.held(), 100);
        drop(a);
        assert_eq!(retained.held(), 50);
        b.clear();
        assert_eq!(retained.held(), 0);
    }
}
