// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session's live policy: what the control socket's `policy.get` reads
//! and `policy.update` replaces (see [`crate::control::ops`]).
//!
//! [`LivePolicy`] holds the handles the devices read: the network policy
//! (`Arc<ArcSwap<Policy>>`, which the net stack loads at every decision),
//! the net device's policy wake (written after a swap, so the net thread
//! polls at once and revokes what the new policy denies), and the vsock
//! allowlist ([`AllowPorts`], which the muxer reads at each guest
//! request). Each update replaces the whole network policy or the whole
//! allowlist, or both, under one lock, and gives the policy its next
//! version: 1 is the policy the VM started with.
//!
//! The network policy's wire shape ([`NetPolicy`]) is a default and two
//! lists of targets, allows and denies; the policy in force puts every deny
//! before every allow, as `boxcar run` orders `--deny` and `--allow`, so a
//! deny of a target wins over an allow of it. A rule that does not parse
//! refuses the whole update, naming the rule, and nothing changes.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use boxcar_net::{Policy, Verdict};
use boxcar_proto::control::{NetPolicy, PolicyUpdateParams, PolicyView, VsockPolicy};
use boxcar_vsock::AllowPorts;
use vmm_sys_util::eventfd::EventFd;

/// The version of the policy a VM starts with.
pub const FIRST_VERSION: u64 = 1;

/// The policy in force, and the way to replace it.
pub struct LivePolicy {
    net: Arc<ArcSwap<Policy>>,
    /// The net device's policy wake; `None` on a VM without the device,
    /// which takes no network update.
    net_wake: Option<EventFd>,
    /// The vsock device's allowlist; `None` on a VM without the device,
    /// which takes no vsock update.
    vsock: Option<AllowPorts>,
    version: AtomicU64,
    /// Held across an update, and a view: the swaps and the version move
    /// together.
    lock: Mutex<()>,
}

/// Why an update was refused. Nothing changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// A network rule does not parse: which list (`allow` or `deny`),
    /// where in it, the rule, and what is wrong with it.
    Rule {
        list: &'static str,
        at: usize,
        rule: String,
        problem: String,
    },
    /// `net` was given, and the VM has no network card.
    NoNetDevice,
    /// `vsock` was given, and the VM has no vsock device.
    NoVsockDevice,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Rule {
                list,
                at,
                rule,
                problem,
            } => write!(f, "net.{list}[{at}] {rule:?}: {problem}"),
            UpdateError::NoNetDevice => {
                f.write_str("the VM has no network card, so it has no network policy to update")
            }
            UpdateError::NoVsockDevice => {
                f.write_str("the VM has no vsock device, so it has no vsock allowlist to update")
            }
        }
    }
}

impl std::error::Error for UpdateError {}

impl LivePolicy {
    /// The policy in force at the start, version [`FIRST_VERSION`]: `net`
    /// is the handle the net stack reads, `net_wake` the net device's
    /// policy wake (`None` without the device), `vsock` the vsock device's
    /// allowlist (`None` without the device).
    pub fn new(
        net: Arc<ArcSwap<Policy>>,
        net_wake: Option<EventFd>,
        vsock: Option<AllowPorts>,
    ) -> LivePolicy {
        LivePolicy {
            net,
            net_wake,
            vsock,
            version: AtomicU64::new(FIRST_VERSION),
            lock: Mutex::new(()),
        }
    }

    /// The network policy in force.
    pub fn net(&self) -> Arc<Policy> {
        self.net.load_full()
    }

    /// The vsock allowlist in force; empty without the vsock device.
    pub fn vsock_allow(&self) -> Vec<u32> {
        self.vsock
            .as_ref()
            .map(|allow| allow.load().as_ref().clone())
            .unwrap_or_default()
    }

    /// The version of the policy in force.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// The policy in force, as `policy.get` reports it.
    pub fn view(&self) -> PolicyView {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        PolicyView {
            net: net_view(&self.net.load()),
            vsock: VsockPolicy {
                allow_ports: self.vsock_allow(),
            },
            version: self.version(),
        }
    }

    /// Replaces what `params` give (the network policy, the vsock
    /// allowlist, or both; [`PolicyUpdateParams::check`] has passed) and
    /// returns the new version. Everything is checked before anything is
    /// swapped: on an error nothing changed. The net thread is woken after
    /// a network swap, to revoke what the new policy denies.
    pub fn update(&self, params: &PolicyUpdateParams) -> Result<u64, UpdateError> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let net = match &params.net {
            Some(view) => {
                if self.net_wake.is_none() {
                    return Err(UpdateError::NoNetDevice);
                }
                Some(net_policy(view)?)
            }
            None => None,
        };
        let vsock = match (&params.vsock, &self.vsock) {
            (Some(view), Some(allow)) => Some((view.allow_ports.clone(), allow)),
            (Some(_), None) => return Err(UpdateError::NoVsockDevice),
            (None, _) => None,
        };
        if let Some(policy) = net {
            self.net.store(Arc::new(policy));
            if let Some(wake) = &self.net_wake {
                if let Err(error) = wake.write(1) {
                    tracing::warn!("cannot wake the net thread for the new policy: {error}");
                }
            }
        }
        if let Some((ports, allow)) = vsock {
            allow.store(Arc::new(ports));
        }
        Ok(self.version.fetch_add(1, Ordering::AcqRel) + 1)
    }
}

/// The verdict's wire word.
fn verb(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    }
}

/// `policy` as the control protocol shows it: its default, and its rules'
/// targets as written, the allows and the denies each in order.
pub fn net_view(policy: &Policy) -> NetPolicy {
    let mut view = NetPolicy {
        default: policy.default,
        allow: Vec::new(),
        deny: Vec::new(),
    };
    for rule in &policy.rules {
        // The text is `<verb> <target>`, as the parser wrote it.
        let target = rule
            .text
            .split_once(' ')
            .map_or(rule.text.as_str(), |(_, target)| target);
        match rule.verdict {
            Verdict::Allow => view.allow.push(target.to_owned()),
            Verdict::Deny => view.deny.push(target.to_owned()),
        }
    }
    view
}

/// The policy `view` describes: the denies, then the allows, each in
/// order, and the default. A target that does not parse names itself.
pub fn net_policy(view: &NetPolicy) -> Result<Policy, UpdateError> {
    let mut lines = vec![format!("default {}", verb(view.default))];
    lines.extend(view.deny.iter().map(|rule| format!("deny {rule}")));
    lines.extend(view.allow.iter().map(|rule| format!("allow {rule}")));
    Policy::parse(&lines).map_err(|error| {
        // Line 1 is the default, which cannot fail; the denies follow it,
        // then the allows.
        let index = error.line.saturating_sub(2);
        let (list, at, rule) = if index < view.deny.len() {
            ("deny", index, view.deny[index].as_str())
        } else {
            let at = index - view.deny.len();
            let rule = view.allow.get(at).map_or("", String::as_str);
            ("allow", at, rule)
        };
        UpdateError::Rule {
            list,
            at,
            rule: rule.to_owned(),
            problem: error.kind.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use boxcar_proto::control::NetPolicy;
    use vmm_sys_util::eventfd::EFD_NONBLOCK;

    use super::*;

    fn live(net: Policy) -> LivePolicy {
        LivePolicy::new(
            Arc::new(ArcSwap::from_pointee(net)),
            Some(EventFd::new(EFD_NONBLOCK).unwrap()),
            Some(Arc::new(ArcSwap::from_pointee(vec![5000]))),
        )
    }

    fn net(default: Verdict, allow: &[&str], deny: &[&str]) -> NetPolicy {
        NetPolicy {
            default,
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            deny: deny.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn at(ip: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), port)
    }

    /// The view is the rules' targets as written, allows and denies apart,
    /// whatever their order in the policy; the policy an update makes puts
    /// the denies first.
    #[test]
    fn the_view_splits_the_rules_and_an_update_puts_denies_first() {
        let policy = Policy::parse(&[
            "allow Example.COM.",
            "deny *.evil.example.com:8080",
            "allow 203.0.113.0/24:443",
            "default allow",
        ])
        .unwrap();
        assert_eq!(
            net_view(&policy),
            net(
                Verdict::Allow,
                &["Example.COM.", "203.0.113.0/24:443"],
                &["*.evil.example.com:8080"]
            )
        );
        // Through an update and back: the same view.
        let made = net_policy(&net_view(&policy)).unwrap();
        assert_eq!(net_view(&made), net_view(&policy));
        assert_eq!(made.default, Verdict::Allow);
        let texts: Vec<&str> = made.rules.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "deny *.evil.example.com:8080",
                "allow Example.COM.",
                "allow 203.0.113.0/24:443"
            ]
        );
        // So a deny of a target wins over an allow of it.
        let both = net_policy(&net(Verdict::Deny, &["a.test"], &["a.test"])).unwrap();
        assert_eq!(
            both.egress(at([192, 0, 2, 1], 443), &["a.test".to_owned()]),
            (Verdict::Deny, Some("deny a.test".to_owned()))
        );
        assert_eq!(net_view(&Policy::default()), net(Verdict::Deny, &[], &[]));
    }

    /// A target that does not parse is named with its list and place, and
    /// what is wrong with it.
    #[test]
    fn a_bad_rule_is_named() {
        let cases = [
            (
                net(Verdict::Deny, &["exa_mple.com"], &[]),
                ("allow", 0, "exa_mple.com"),
            ),
            (
                net(Verdict::Deny, &["a.test"], &["ok.test", "192.168.1.300"]),
                ("deny", 1, "192.168.1.300"),
            ),
            (
                net(Verdict::Deny, &["b.test", "two words"], &["c.test"]),
                ("allow", 1, "two words"),
            ),
            (net(Verdict::Deny, &[""], &[]), ("allow", 0, "")),
            (
                net(Verdict::Deny, &[], &["10.1.2.3/8"]),
                ("deny", 0, "10.1.2.3/8"),
            ),
        ];
        for (view, (list, at, rule)) in cases {
            let error = net_policy(&view).unwrap_err();
            let UpdateError::Rule {
                list: got_list,
                at: got_at,
                rule: got_rule,
                problem,
            } = &error
            else {
                panic!("{view:?}: {error}");
            };
            assert_eq!((*got_list, *got_at, got_rule.as_str()), (list, at, rule));
            assert!(!problem.is_empty());
            assert!(
                error.to_string().starts_with(&format!("net.{list}[{at}] ")),
                "{error}"
            );
        }
    }

    /// An update swaps what it names, wakes the net thread for a network
    /// swap, and moves the version on; a view reports it all. Nothing
    /// changes on a refusal.
    #[test]
    fn an_update_swaps_wakes_and_versions() {
        let live = live(Policy::default());
        let wake = live.net_wake.as_ref().unwrap().try_clone().unwrap();
        assert_eq!(live.version(), FIRST_VERSION);
        assert_eq!(live.view().version, 1);
        assert_eq!(live.vsock_allow(), [5000]);

        let net_only = PolicyUpdateParams {
            net: Some(net(Verdict::Deny, &["api.github.com:443"], &[])),
            vsock: None,
        };
        assert_eq!(live.update(&net_only), Ok(2));
        assert_eq!(wake.read().unwrap(), 1, "woken once");
        assert_eq!(
            live.net()
                .egress(at([140, 82, 112, 6], 443), &["api.github.com".to_owned()]),
            (Verdict::Allow, Some("allow api.github.com:443".to_owned()))
        );
        assert_eq!(live.vsock_allow(), [5000], "untouched");

        let vsock_only = PolicyUpdateParams {
            net: None,
            vsock: Some(VsockPolicy {
                allow_ports: vec![6000, 7000],
            }),
        };
        assert_eq!(live.update(&vsock_only), Ok(3));
        assert!(wake.read().is_err(), "not woken for a vsock swap");
        assert_eq!(live.vsock_allow(), [6000, 7000]);
        assert_eq!(
            live.view(),
            PolicyView {
                net: net(Verdict::Deny, &["api.github.com:443"], &[]),
                vsock: VsockPolicy {
                    allow_ports: vec![6000, 7000]
                },
                version: 3,
            }
        );

        // A bad rule in a request that also has a good vsock list: nothing
        // of it is taken.
        let refused = PolicyUpdateParams {
            net: Some(net(Verdict::Allow, &["exa_mple.com"], &[])),
            vsock: Some(VsockPolicy::default()),
        };
        assert!(matches!(
            live.update(&refused),
            Err(UpdateError::Rule {
                list: "allow",
                at: 0,
                ..
            })
        ));
        assert_eq!(live.version(), 3);
        assert_eq!(live.vsock_allow(), [6000, 7000]);
        assert_eq!(live.net().default, Verdict::Deny);
    }

    /// Without the device there is nothing to update: refused, and the
    /// version stays.
    #[test]
    fn an_update_without_the_device_is_refused() {
        let none = LivePolicy::new(
            Arc::new(ArcSwap::from_pointee(Policy::default())),
            None,
            None,
        );
        let net_only = PolicyUpdateParams {
            net: Some(net(Verdict::Allow, &[], &[])),
            vsock: None,
        };
        assert_eq!(none.update(&net_only), Err(UpdateError::NoNetDevice));
        let vsock_only = PolicyUpdateParams {
            net: None,
            vsock: Some(VsockPolicy {
                allow_ports: vec![5000],
            }),
        };
        assert_eq!(none.update(&vsock_only), Err(UpdateError::NoVsockDevice));
        assert_eq!(none.version(), FIRST_VERSION);
        assert_eq!(none.net().default, Verdict::Deny);
        assert!(none.vsock_allow().is_empty());
        assert_eq!(none.view().vsock, VsockPolicy::default());
    }
}
