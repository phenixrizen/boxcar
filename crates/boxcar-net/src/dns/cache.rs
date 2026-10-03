// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! [`DnsCache`]: which names the guest was told each address has, so a
//! connection to an address can be judged by its names (`net.connect`'s
//! `names`).
//!
//! It is fed from every answer the forwarder passes to the guest: for each
//! address, the name it was the answer for and every name on the CNAME
//! chain to it, so a connection to a CDN's address carries the name the
//! guest asked for. An entry lives for its TTL, held to between a minute
//! and a day. An address keeps at most [`NAMES_PER_IP`] names, and the
//! cache at most [`CACHE_CAP`] entries in all; past either, the one least
//! recently answered goes first. The per-address bound keeps the names a
//! record lists for one connection short, even when many names share an
//! address (wildcard DNS, a CDN).

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// The most (address, name) entries the cache holds.
pub const CACHE_CAP: usize = 4096;
/// The most names one address keeps.
pub const NAMES_PER_IP: usize = 16;
/// The shortest an entry lives, in seconds, whatever its TTL: answers with
/// a TTL of seconds are common, and a connection may start a little after.
pub const TTL_FLOOR: u32 = 60;
/// The longest an entry lives, in seconds.
pub const TTL_CAP: u32 = 86_400;

/// One name of an address.
#[derive(Clone, Debug)]
struct Entry {
    expires: Instant,
    /// When it was last answered, as a count of insertions: the larger, the
    /// more recent.
    stamp: u64,
}

/// A bounded reverse map from addresses to the names they were given for.
#[derive(Clone, Debug)]
pub struct DnsCache {
    cap: usize,
    by_ip: HashMap<Ipv4Addr, HashMap<String, Entry>>,
    /// Every entry by its stamp, oldest first: the eviction order.
    order: BTreeMap<u64, (Ipv4Addr, String)>,
    next_stamp: u64,
}

impl Default for DnsCache {
    fn default() -> Self {
        DnsCache::new()
    }
}

impl DnsCache {
    /// An empty cache of [`CACHE_CAP`] entries.
    pub fn new() -> Self {
        DnsCache::with_cap(CACHE_CAP)
    }

    /// An empty cache of `cap` entries.
    pub fn with_cap(cap: usize) -> Self {
        DnsCache {
            cap,
            by_ip: HashMap::new(),
            order: BTreeMap::new(),
            next_stamp: 0,
        }
    }

    /// How many (address, name) entries it holds, expired ones included
    /// until they are evicted.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Records that `name` resolved to `ip` for `ttl` seconds, now.
    pub fn insert(&mut self, ip: Ipv4Addr, name: &str, ttl: u32) {
        self.insert_at(ip, name, ttl, Instant::now());
    }

    /// Records that `name` resolved to `ip` for `ttl` seconds (held to
    /// [`TTL_FLOOR`]..=[`TTL_CAP`]) at `now`. An entry already there is
    /// renewed, its expiry the new one, and becomes the most recent. Past
    /// [`NAMES_PER_IP`] for the address, its least recently answered name
    /// is evicted; past the cache's cap, the least recently answered entry
    /// of any address.
    pub fn insert_at(&mut self, ip: Ipv4Addr, name: &str, ttl: u32, now: Instant) {
        if self.cap == 0 {
            return;
        }
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        let ttl = Duration::from_secs(ttl.clamp(TTL_FLOOR, TTL_CAP).into());
        let expires = now.checked_add(ttl).unwrap_or(now);
        let stamp = self.next_stamp;
        self.next_stamp += 1;
        let names = self.by_ip.entry(ip).or_default();
        if let Some(old) = names.insert(name.clone(), Entry { expires, stamp }) {
            self.order.remove(&old.stamp);
        }
        if names.len() > NAMES_PER_IP {
            let oldest = names
                .iter()
                .min_by_key(|(_, entry)| entry.stamp)
                .map(|(name, entry)| (name.clone(), entry.stamp));
            if let Some((oldest, oldest_stamp)) = oldest {
                names.remove(&oldest);
                self.order.remove(&oldest_stamp);
            }
        }
        self.order.insert(stamp, (ip, name));
        while self.order.len() > self.cap {
            let Some((_, (ip, name))) = self.order.pop_first() else {
                break;
            };
            if let Some(names) = self.by_ip.get_mut(&ip) {
                names.remove(&name);
                if names.is_empty() {
                    self.by_ip.remove(&ip);
                }
            }
        }
    }

    /// The names `ip` was given for that have not expired, now.
    pub fn names_for(&self, ip: Ipv4Addr) -> Vec<String> {
        self.names_for_at(ip, Instant::now())
    }

    /// The names `ip` was given for that have not expired at `now`, the
    /// most recently answered first.
    pub fn names_for_at(&self, ip: Ipv4Addr, now: Instant) -> Vec<String> {
        let Some(names) = self.by_ip.get(&ip) else {
            return Vec::new();
        };
        let mut live: Vec<(&String, u64)> = names
            .iter()
            .filter(|(_, entry)| entry.expires > now)
            .map(|(name, entry)| (name, entry.stamp))
            .collect();
        live.sort_unstable_by_key(|(_, stamp)| Reverse(*stamp));
        live.into_iter().map(|(name, _)| name.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    #[test]
    fn names_come_back_most_recent_first_lowercase_and_once() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        cache.insert_at(IP, "edge.cdn.test", 300, t0);
        cache.insert_at(IP, "Example.COM.", 300, t0);
        cache.insert_at(Ipv4Addr::new(192, 0, 2, 2), "other.test", 300, t0);
        assert_eq!(cache.names_for_at(IP, t0), ["example.com", "edge.cdn.test"]);
        // Answered again, a name is renewed and becomes the most recent.
        cache.insert_at(IP, "edge.cdn.test", 300, t0);
        assert_eq!(cache.names_for_at(IP, t0), ["edge.cdn.test", "example.com"]);
        assert_eq!(cache.len(), 3);
        assert!(cache
            .names_for_at(Ipv4Addr::new(192, 0, 2, 3), t0)
            .is_empty());
    }

    #[test]
    fn ttls_are_held_between_a_minute_and_a_day() {
        let t0 = Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut cache = DnsCache::new();
        cache.insert_at(IP, "zero.test", 0, t0);
        cache.insert_at(IP, "five-minutes.test", 300, t0);
        cache.insert_at(IP, "a-week.test", 7 * 86_400, t0);
        assert_eq!(cache.names_for_at(IP, at(59)).len(), 3, "a floor of 60 s");
        assert_eq!(
            cache.names_for_at(IP, at(60)),
            ["a-week.test", "five-minutes.test"]
        );
        assert_eq!(cache.names_for_at(IP, at(299)).len(), 2);
        assert_eq!(cache.names_for_at(IP, at(300)), ["a-week.test"]);
        assert_eq!(cache.names_for_at(IP, at(86_399)), ["a-week.test"]);
        assert!(
            cache.names_for_at(IP, at(86_400)).is_empty(),
            "a cap of a day"
        );

        // Renewed with a shorter TTL, an entry takes the new expiry.
        cache.insert_at(IP, "a-week.test", 60, at(100));
        assert_eq!(
            cache.names_for_at(IP, at(159)),
            ["a-week.test", "five-minutes.test"]
        );
        assert_eq!(cache.names_for_at(IP, at(160)), ["five-minutes.test"]);
    }

    #[test]
    fn an_address_keeps_its_16_most_recent_names() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        for i in 0..100 {
            cache.insert_at(IP, &format!("n{i}.example"), 300, t0);
        }
        let newest: Vec<String> = (84..100).rev().map(|i| format!("n{i}.example")).collect();
        assert_eq!(cache.names_for_at(IP, t0), newest);
        assert_eq!(cache.len(), NAMES_PER_IP, "evicted names leave the cache");

        // A name already there is renewed, not added twice, and evicts
        // nothing.
        cache.insert_at(IP, "n84.example", 300, t0);
        let names = cache.names_for_at(IP, t0);
        assert_eq!(names.len(), NAMES_PER_IP);
        assert_eq!(names[0], "n84.example");
        assert_eq!(names[NAMES_PER_IP - 1], "n85.example");
        // Other addresses are not touched.
        cache.insert_at(Ipv4Addr::new(192, 0, 2, 2), "other.example", 300, t0);
        assert_eq!(cache.names_for_at(IP, t0).len(), NAMES_PER_IP);
        assert_eq!(cache.len(), NAMES_PER_IP + 1);
    }

    #[test]
    fn the_least_recently_answered_entry_is_evicted() {
        let t0 = Instant::now();
        let mut cache = DnsCache::with_cap(3);
        for name in ["a.test", "b.test", "c.test"] {
            cache.insert_at(IP, name, 300, t0);
        }
        // Renewing a makes b the oldest.
        cache.insert_at(IP, "a.test", 300, t0);
        cache.insert_at(Ipv4Addr::new(192, 0, 2, 9), "d.test", 300, t0);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.names_for_at(IP, t0), ["a.test", "c.test"]);
        cache.insert_at(Ipv4Addr::new(192, 0, 2, 9), "e.test", 300, t0);
        cache.insert_at(Ipv4Addr::new(192, 0, 2, 9), "f.test", 300, t0);
        assert!(cache.names_for_at(IP, t0).is_empty());
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.by_ip.len(), 1, "an address with no names is dropped");

        let mut none = DnsCache::with_cap(0);
        none.insert_at(IP, "a.test", 300, t0);
        assert!(none.is_empty());
    }
}
