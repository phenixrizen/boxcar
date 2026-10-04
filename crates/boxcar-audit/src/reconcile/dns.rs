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

#[derive(Debug, Default)]
pub struct DnsCache {
    /// The names each address was an answer for, newest first, with when.
    by_addr: HashMap<IpAddr, Vec<(String, u64)>>,
    /// The addresses each name was answered with, with when.
    by_name: HashMap<String, Vec<(IpAddr, u64)>>,
    /// The queries in the window: when, and the name asked.
    queries: VecDeque<(u64, String)>,
}

impl DnsCache {
    /// A `net.dns` record: the name asked, and the addresses answered.
    pub fn observe(&mut self, ts: u64, qname: &str, answers: &[String]) {
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
            let names = self.by_addr.entry(addr).or_default();
            names.retain(|(n, _)| n != &name);
            names.insert(0, (name.clone(), ts));
            let addrs = self.by_name.entry(name.clone()).or_default();
            addrs.retain(|(a, _)| a != &addr);
            addrs.insert(0, (addr, ts));
        }
    }

    /// The names `addr` was an answer for within the TTL before `now`.
    pub fn names_for(&self, addr: IpAddr, now: u64) -> Vec<String> {
        self.by_addr
            .get(&addr)
            .map(|names| {
                names
                    .iter()
                    .filter(|(_, when)| now.saturating_sub(*when) <= TTL_NS)
                    .map(|(n, _)| n.clone())
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
                    .filter(|(_, when)| now.saturating_sub(*when) <= TTL_NS)
                    .map(|(a, _)| *a)
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
        // A hex blob, as an exfiltrating resolver might send.
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
