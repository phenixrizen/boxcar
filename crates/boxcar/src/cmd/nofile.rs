// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The open file limit the network needs.
//!
//! At its caps the network stack holds a host socket for each of 4096 relayed
//! TCP connections and 1024 UDP mappings, and up to 256 more of each waiting
//! for a connect or to close, besides its DNS socket, the devices' eventfds
//! and what the shares keep open: [`NET_NEEDS`] descriptors, with some slack.
//! `boxcar run` raises the soft `RLIMIT_NOFILE` to the hard limit, at most
//! [`CAP`], when the guest has a network card, and says so when that is not
//! enough; `boxcar doctor` reports the same.

use std::io;

/// The descriptors the network needs at its caps.
pub(crate) const NET_NEEDS: u64 = 6144;
/// The highest soft limit `boxcar run` raises the limit to by itself.
pub(crate) const CAP: u64 = 65536;

/// `RLIMIT_NOFILE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limit {
    pub(crate) soft: u64,
    pub(crate) hard: u64,
}

/// The process's limit now.
pub(crate) fn current() -> io::Result<Limit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit into `limit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Limit {
        soft: limit.rlim_cur,
        hard: limit.rlim_max,
    })
}

/// The soft limit `boxcar run` sets for a VM with a network card: the hard
/// limit, but at most [`CAP`], and never less than the soft limit already
/// set.
pub(crate) fn target(limit: Limit) -> u64 {
    limit.soft.max(limit.hard.min(CAP))
}

/// Raises the soft limit to [`target`], and returns the soft limit now.
pub(crate) fn raise() -> io::Result<u64> {
    let limit = current()?;
    let soft = target(limit);
    if soft > limit.soft {
        let raised = libc::rlimit {
            rlim_cur: soft,
            rlim_max: limit.hard,
        };
        // SAFETY: setrlimit reads one rlimit from `raised`.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(soft)
}

/// What to say when a soft limit of `soft` is less than the network needs.
pub(crate) fn warning(soft: u64) -> Option<String> {
    (soft < NET_NEEDS).then(|| {
        format!(
            "the open file limit is {soft}, and the network needs up to {NET_NEEDS} at its \
             connection caps: connections past the limit fail; raise the hard limit \
             (ulimit -Hn, or LimitNOFILE= for a service)"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_is_the_hard_limit_capped_never_lower_than_now() {
        let target = |soft, hard| target(Limit { soft, hard });
        assert_eq!(target(1024, 4096), 4096);
        assert_eq!(target(1024, 1 << 20), CAP);
        assert_eq!(target(1024, libc::RLIM_INFINITY), CAP);
        assert_eq!(target(100_000, 1 << 20), 100_000, "never lowered");
        assert_eq!(target(1024, 1024), 1024);
    }

    #[test]
    fn a_limit_below_the_networks_need_is_warned_about() {
        let warned = warning(4096).unwrap();
        assert!(
            warned.starts_with("the open file limit is 4096,"),
            "{warned}"
        );
        assert!(warned.contains("6144"), "{warned}");
        assert_eq!(warning(NET_NEEDS), None);
        assert_eq!(warning(CAP), None);
    }

    /// Raising never fails for the process's own limit, and leaves it at
    /// least where it was.
    #[test]
    fn raise_reaches_the_target() {
        let before = current().unwrap();
        let soft = raise().unwrap();
        assert_eq!(soft, target(before));
        assert_eq!(current().unwrap().soft, soft);
    }
}
