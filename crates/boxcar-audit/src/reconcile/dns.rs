// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the guest's DNS said lately: which names an address was given for,
//! which addresses a name was given, and the rate and shape of the queries.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// How long an answer stays known.
pub const TTL_NS: u64 = 60 * 1_000_000_000;
/// The window the query rate and entropy are judged over.
pub const WINDOW_NS: u64 = 10 * 1_000_000_000;
/// The most (address, name) associations kept.
pub const CACHE_CAP: usize = 4096;
/// The most names kept for one address.
pub const NAMES_PER_ADDR: usize = 16;

#[derive(Clone, Debug)]
struct Association<T> {
    value: T,
    when: u64,
    stamp: u64,
}

#[derive(Debug)]
pub struct DnsCache {
    /// The names each address was an answer for, newest first.
    by_addr: HashMap<IpAddr, Vec<Association<String>>>,
    /// The addresses each name was answered with, newest first.
    by_name: HashMap<String, Vec<Association<IpAddr>>>,
    /// Every association, oldest first, for the aggregate bound.
    order: VecDeque<(u64, IpAddr, String)>,
    next_stamp: u64,
    cap: usize,
    /// The queries in the window: when, and the name asked.
    queries: VecDeque<(u64, String)>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::with_cap(CACHE_CAP)
    }
}

impl DnsCache {
    fn with_cap(cap: usize) -> Self {
        DnsCache {
            by_addr: HashMap::new(),
            by_name: HashMap::new(),
            order: VecDeque::new(),
            next_stamp: 0,
            cap,
            queries: VecDeque::new(),
        }
    }

    /// A `net.dns` record: the name asked, and the addresses answered.
    pub fn observe(&mut self, ts: u64, qname: &str, answers: &[String]) {
        self.prune(ts);
        let name = qname.trim_end_matches('.').to_ascii_lowercase();
        self.queries.push_back((ts, name.clone()));
        while let Some((when, _)) = self.queries.front() {
            if ts.saturating_sub(*when) > WINDOW_NS {
                self.queries.pop_front();
            } else {
                break;
            }
        }
        for answer in answers {
            let Ok(addr) = answer.parse::<IpAddr>() else {
                continue;
            };
            self.remove(addr, &name);
            if self.cap == 0 {
                continue;
            }
            let stamp = self.next_stamp;
            self.next_stamp = self.next_stamp.wrapping_add(1);
            self.by_addr.entry(addr).or_default().insert(
                0,
                Association {
                    value: name.clone(),
                    when: ts,
                    stamp,
                },
            );
            self.by_name.entry(name.clone()).or_default().insert(
                0,
                Association {
                    value: addr,
                    when: ts,
                    stamp,
                },
            );
            self.order.push_back((stamp, addr, name.clone()));

            while self.by_addr.get(&addr).map_or(0, Vec::len) > NAMES_PER_ADDR {
                let oldest = self
                    .by_addr
                    .get(&addr)
                    .and_then(|names| names.last())
                    .map(|entry| entry.value.clone());
                if let Some(oldest) = oldest {
                    self.remove(addr, &oldest);
                }
            }
            while self.order.len() > self.cap {
                let Some((stamp, oldest_addr, oldest_name)) = self.order.pop_front() else {
                    break;
                };
                self.remove_maps(oldest_addr, &oldest_name, stamp);
            }
        }
    }

    /// Drops associations older than the TTL, including their empty keys.
    pub fn prune(&mut self, now: u64) {
        while let Some((_, addr, name)) = self.order.front().cloned() {
            let expired = self
                .by_addr
                .get(&addr)
                .and_then(|names| names.iter().find(|entry| entry.value == name))
                .is_none_or(|entry| now.saturating_sub(entry.when) > TTL_NS);
            if !expired {
                break;
            }
            if let Some((stamp, _, _)) = self.order.pop_front() {
                self.remove_maps(addr, &name, stamp);
            }
        }
    }

    fn remove(&mut self, addr: IpAddr, name: &str) {
        let stamp = self.by_addr.get(&addr).and_then(|names| {
            names
                .iter()
                .find(|entry| entry.value == name)
                .map(|entry| entry.stamp)
        });
        let Some(stamp) = stamp else {
            return;
        };
        self.remove_maps(addr, name, stamp);
        self.order.retain(|(kept, _, _)| *kept != stamp);
    }

    fn remove_maps(&mut self, addr: IpAddr, name: &str, stamp: u64) {
        if let Some(names) = self.by_addr.get_mut(&addr) {
            names.retain(|entry| entry.stamp != stamp);
            if names.is_empty() {
                self.by_addr.remove(&addr);
            }
        }
        if let Some(addrs) = self.by_name.get_mut(name) {
            addrs.retain(|entry| entry.stamp != stamp);
            if addrs.is_empty() {
                self.by_name.remove(name);
            }
        }
    }

    /// The names `addr` was an answer for within the TTL before `now`.
    pub fn names_for(&self, addr: IpAddr, now: u64) -> Vec<String> {
        self.by_addr
            .get(&addr)
            .map(|names| {
                names
                    .iter()
                    .filter(|entry| now.saturating_sub(entry.when) <= TTL_NS)
                    .map(|entry| entry.value.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The addresses `name` was answered with within the TTL before `now`.
    pub fn addrs_for(&self, name: &str, now: u64) -> Vec<IpAddr> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.by_name
            .get(&name)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter(|entry| now.saturating_sub(entry.when) <= TTL_NS)
                    .map(|entry| entry.value)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The queries in the window ending at the last one, and the mean
    /// Shannon entropy, in bits, of their first labels.
    pub fn window(&self) -> (usize, f64) {
        let count = self.queries.len();
        if count == 0 {
            return (0, 0.0);
        }
        let total: f64 = self
            .queries
            .iter()
            .map(|(_, name)| label_entropy(name.split('.').next().unwrap_or("")))
            .sum();
        (count, total / count as f64)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

/// The Shannon entropy of `label`'s bytes, in bits.
pub fn label_entropy(label: &str) -> f64 {
    if label.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in label.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let len = label.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_labels() {
        assert_eq!(label_entropy(""), 0.0);
        assert_eq!(label_entropy("aaaa"), 0.0);
        assert!((label_entropy("ab") - 1.0).abs() < 1e-9);
        assert!((label_entropy("abcd") - 2.0).abs() < 1e-9);
        assert!(label_entropy("3f9a0c7e1b2d4e8f6a5b9c0d") > 3.4);
        assert!(label_entropy("example") < 3.0);
    }

    #[test]
    fn answers_are_remembered_both_ways_within_the_ttl() {
        let mut cache = DnsCache::default();
        let t0 = 1_000 * 1_000_000_000;
        cache.observe(
            t0,
            "example.com.",
            &["93.184.216.34".into(), "not an address".into()],
        );
        let addr: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(cache.names_for(addr, t0 + 1), ["example.com"]);
        assert_eq!(cache.addrs_for("EXAMPLE.com", t0 + 1), [addr]);
        assert!(cache.names_for(addr, t0 + TTL_NS + 1).is_empty());
        assert!(cache.addrs_for("other.example", t0).is_empty());
        cache.observe(t0 + 5, "www.example.com", &["93.184.216.34".into()]);
        assert_eq!(
            cache.names_for(addr, t0 + 6),
            ["www.example.com", "example.com"]
        );
    }

    #[test]
    fn expired_answers_and_empty_keys_are_removed() {
        let mut cache = DnsCache::default();
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        cache.observe(1, "old.example", &[addr.to_string()]);
        cache.prune(1 + TTL_NS + 1);
        assert_eq!(cache.len(), 0);
        assert!(cache.by_addr.is_empty());
        assert!(cache.by_name.is_empty());
    }

    #[test]
    fn an_address_keeps_its_sixteen_most_recent_names() {
        let mut cache = DnsCache::default();
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..100 {
            cache.observe(i, &format!("n{i}.example"), &[addr.to_string()]);
        }
        let expected: Vec<String> = (84..100).rev().map(|i| format!("n{i}.example")).collect();
        assert_eq!(cache.names_for(addr, 100), expected);
        assert_eq!(cache.len(), NAMES_PER_ADDR);
        assert!(cache.addrs_for("n83.example", 100).is_empty());
    }

    #[test]
    fn many_distinct_answers_stay_within_the_association_limit() {
        let mut cache = DnsCache::default();
        for i in 0..(CACHE_CAP + 1000) {
            let addr: IpAddr = format!("2001:db8::{i:x}").parse().unwrap();
            cache.observe(i as u64, &format!("n{i}.example"), &[addr.to_string()]);
        }
        assert_eq!(cache.len(), CACHE_CAP);
        assert_eq!(cache.by_addr.len(), CACHE_CAP);
        assert_eq!(cache.by_name.len(), CACHE_CAP);
        assert!(cache
            .addrs_for("n0.example", (CACHE_CAP + 1000) as u64)
            .is_empty());
    }

    #[test]
    fn the_window_counts_the_last_ten_seconds() {
        let mut cache = DnsCache::default();
        let s = 1_000_000_000;
        for i in 0..30u64 {
            cache.observe(i * s, &format!("host{i}.example"), &[]);
        }
        let (count, entropy) = cache.window();
        assert_eq!(count, 11, "the last ten seconds, bounds included");
        assert!(entropy > 0.0);
    }
}
