// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar policy`: a running session's network policy, read and changed
//! through its control socket (`policy.get` and `policy.update`), and the
//! built-in profiles, printed (`profile NAME`, no session needed).
//!
//! `allow RULE` and `deny RULE` work on the policy as `policy.get`
//! reports it: the rule goes to the end of its list and out of the other,
//! and the whole network policy goes back with `policy.update`. The rule is
//! parsed here first, as `boxcar run --allow` parses it, so a rule that
//! does not parse is a usage error (exit 2) before any connection is made.
//! The vsock allowlist is read by `show` and left as it is by the others.
//!
//! `allow ... --ttl DURATION` grants a live exception (`policy.update` with
//! `exception`, alone) instead of changing the permanent policy, and
//! `exception ls` lists the live ones; both need a server whose hello lists
//! `policy.exception`. `show` lists the exceptions after the permanent
//! policy.

use std::io::{self, Write};
use std::process::ExitCode;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use boxcar_net::{List, Policy, Verdict};
use boxcar_proto::control::{
    ExceptionGrant, ExceptionKind, PolicyUpdateParams, PolicyUpdated, PolicyView,
};
use serde_json::Value;

use crate::cli::{
    ExceptionCommand, PolicyAllowArgs, PolicyCommand, PolicyProfileArgs, PolicyShowArgs,
    SessionArgs,
};
use crate::client::{self, Client};

/// The capability a server's hello lists when it takes exceptions.
const EXCEPTIONS: &str = "policy.exception";

/// The exit code of a rule that does not parse, as clap's usage errors and
/// `boxcar run`'s.
const USAGE_EXIT: u8 = 2;

pub fn run(command: PolicyCommand) -> anyhow::Result<ExitCode> {
    match command {
        PolicyCommand::Show(args) => show(&args),
        PolicyCommand::Allow(args) => allow(&args),
        PolicyCommand::Deny(args) => change(&args.rule, &args.session, Verdict::Deny),
        PolicyCommand::Profile(args) => profile(&args),
        PolicyCommand::Exception(ExceptionCommand::Ls(args)) => exceptions(&args),
    }
}

/// Prints the built-in profile `args.name`, byte for byte as `boxcar run
/// --policy NAME` reads it; a name there is no profile of is a usage
/// error, naming the profiles there are.
fn profile(args: &PolicyProfileArgs) -> anyhow::Result<ExitCode> {
    let Some(text) = boxcar_policy::profiles::text(&args.name) else {
        crate::cmd::tell(&format!(
            "error: there is no profile {:?}; the profiles are {}",
            args.name,
            boxcar_policy::profiles::NAMES.join(", ")
        ));
        return Ok(ExitCode::from(USAGE_EXIT));
    };
    let mut out = io::stdout().lock();
    out.write_all(text.as_bytes())?;
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

fn connect(session: &SessionArgs) -> anyhow::Result<Client> {
    client::connect(session.control.as_deref(), session.session_id.as_deref())
}

/// `policy.get`, as the policy it reports.
fn get(client: &mut Client) -> anyhow::Result<(PolicyView, Value)> {
    let result = client
        .request("policy.get", Value::Null)?
        .map_err(|error| anyhow!("policy.get: {error}"))?;
    let view: PolicyView =
        serde_json::from_value(result.clone()).context("the server sent a malformed policy")?;
    Ok((view, result))
}

fn show(args: &PolicyShowArgs) -> anyhow::Result<ExitCode> {
    let mut client = connect(&args.session)?;
    let (view, result) = get(&mut client)?;
    let mut out = io::stdout().lock();
    if args.json {
        writeln!(out, "{result}")?;
    } else {
        out.write_all(table(&view, now_ns()).as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// `allow`: a permanent allow rule, or with `--ttl` a live exception.
fn allow(args: &PolicyAllowArgs) -> anyhow::Result<ExitCode> {
    let Some(ttl_s) = args.ttl else {
        // clap requires RULE without --writable and --exec, which need --ttl.
        let rule = args.rule.as_deref().unwrap_or_default();
        return change(rule, &args.session, Verdict::Allow);
    };
    let (kind, rule) = match (&args.writable, &args.exec, &args.rule) {
        (Some(glob), _, _) => (ExceptionKind::Writable, glob),
        (_, Some(glob), _) => (ExceptionKind::Exec, glob),
        (_, _, Some(rule)) => (ExceptionKind::Egress, rule),
        (None, None, None) => unreachable!("clap requires one"),
    };
    // Checked as the VMM will check it, before any connection is made.
    let checked = match kind {
        ExceptionKind::Egress => Policy::default()
            .add(List::Allow, rule)
            .map_err(|kind| kind.to_string()),
        ExceptionKind::Writable | ExceptionKind::Exec => boxcar_fs::rules::glob(rule)
            .map(drop)
            .map_err(|error| error.to_string()),
    };
    if let Err(problem) = checked {
        crate::cmd::tell(&format!(
            "error: policy allow --{} {rule:?}: {problem}",
            match kind {
                ExceptionKind::Egress => "ttl",
                ExceptionKind::Writable => "writable",
                ExceptionKind::Exec => "exec",
            }
        ));
        return Ok(ExitCode::from(USAGE_EXIT));
    }
    let mut client = connect(&args.session)?;
    if !client.can(EXCEPTIONS) {
        crate::cmd::tell(&format!(
            "error: this session's VMM grants no exceptions (its hello lists no {EXCEPTIONS})"
        ));
        return Ok(ExitCode::FAILURE);
    }
    let params = PolicyUpdateParams {
        exception: Some(ExceptionGrant {
            rule: rule.clone(),
            kind,
            ttl_s,
        }),
        ..PolicyUpdateParams::default()
    };
    let result = client
        .request("policy.update", serde_json::to_value(&params)?)?
        .map_err(|error| anyhow!("policy.update: {error}"))?;
    let updated: PolicyUpdated =
        serde_json::from_value(result).context("the server sent a malformed result")?;
    println!(
        "policy version {} ({} exception {rule} for {ttl_s} s)",
        updated.policy_version,
        kind.as_str()
    );
    Ok(ExitCode::SUCCESS)
}

/// `exception ls`: the live exceptions, as a table or as the JSON list.
fn exceptions(args: &PolicyShowArgs) -> anyhow::Result<ExitCode> {
    let mut client = connect(&args.session)?;
    if !client.can(EXCEPTIONS) {
        crate::cmd::tell(&format!(
            "error: this session's VMM has no exceptions (its hello lists no {EXCEPTIONS})"
        ));
        return Ok(ExitCode::FAILURE);
    }
    let (view, _) = get(&mut client)?;
    let mut out = io::stdout().lock();
    if args.json {
        writeln!(out, "{}", serde_json::to_string(&view.exceptions)?)?;
    } else {
        out.write_all(exception_table(&view, now_ns()).as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// The realtime clock, as `expires_ns` is.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// The live exceptions, one a line: id, kind, rule, seconds left at
/// `now_ns`; `(none)` without any.
fn exception_table(view: &PolicyView, now_ns: u64) -> String {
    if view.exceptions.is_empty() {
        return "(none)\n".to_owned();
    }
    view.exceptions
        .iter()
        .map(|e| {
            let left = e.expires_ns.saturating_sub(now_ns).div_ceil(1_000_000_000);
            format!(
                "{:<4} {:<8} {} ({left} s left)\n",
                e.id,
                e.kind.as_str(),
                e.rule
            )
        })
        .collect()
}

/// Adds `rule` to the `verdict` list of the session's network policy and
/// sends the policy back, unless it is there already.
fn change(rule: &str, session: &SessionArgs, verdict: Verdict) -> anyhow::Result<ExitCode> {
    let (list, verb) = match verdict {
        Verdict::Allow => (List::Allow, "allow"),
        Verdict::Deny => (List::Deny, "deny"),
    };
    // Checked as the VMM will check it, before any connection is made.
    if let Err(kind) = Policy::default().add(list, rule) {
        crate::cmd::tell(&format!("error: policy {verb} {rule:?}: {kind}"));
        return Ok(ExitCode::from(USAGE_EXIT));
    }
    let mut client = connect(session)?;
    let (view, _) = get(&mut client)?;
    let Some(net) = with_rule(view.net, verdict, rule) else {
        println!("policy version {} (unchanged)", view.version);
        return Ok(ExitCode::SUCCESS);
    };
    let params = PolicyUpdateParams {
        net: Some(net),
        ..PolicyUpdateParams::default()
    };
    let result = client
        .request("policy.update", serde_json::to_value(&params)?)?
        .map_err(|error| anyhow!("policy.update: {error}"))?;
    let updated: PolicyUpdated =
        serde_json::from_value(result).context("the server sent a malformed result")?;
    println!("policy version {}", updated.policy_version);
    Ok(ExitCode::SUCCESS)
}

/// `net` with `rule` at the end of its `verdict` list and out of the other,
/// or `None` when it is already so.
fn with_rule(
    mut net: boxcar_proto::control::NetPolicy,
    verdict: Verdict,
    rule: &str,
) -> Option<boxcar_proto::control::NetPolicy> {
    let (into, out_of) = match verdict {
        Verdict::Allow => (&mut net.allow, &mut net.deny),
        Verdict::Deny => (&mut net.deny, &mut net.allow),
    };
    let had = out_of.len();
    out_of.retain(|r| r != rule);
    if into.iter().any(|r| r == rule) && out_of.len() == had {
        return None;
    }
    if !into.iter().any(|r| r == rule) {
        into.push(rule.to_owned());
    }
    Some(net)
}

/// The policy as a two-column table: one row a rule, `(none)` for an empty
/// list, then a row for each live exception, its seconds left at `now_ns`.
fn table(view: &PolicyView, now_ns: u64) -> String {
    let default = match view.net.default {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    };
    let mut rows: Vec<(&str, String)> = vec![
        ("version", view.version.to_string()),
        ("default", default.to_owned()),
    ];
    for (name, rules) in [
        ("allow", &view.net.allow),
        ("deny", &view.net.deny),
        ("inspect", &view.net.inspect),
    ] {
        if rules.is_empty() {
            rows.push((name, "(none)".to_owned()));
        }
        rows.extend(rules.iter().map(|rule| (name, rule.clone())));
    }
    let ports: Vec<String> = view.vsock.allow_ports.iter().map(u32::to_string).collect();
    rows.push((
        "vsock",
        if ports.is_empty() {
            "(none)".to_owned()
        } else {
            ports.join(", ")
        },
    ));
    for e in &view.exceptions {
        let left = e.expires_ns.saturating_sub(now_ns).div_ceil(1_000_000_000);
        rows.push((
            "except",
            format!("{} {} {} ({left} s left)", e.id, e.kind.as_str(), e.rule),
        ));
    }
    rows.iter()
        .map(|(name, value)| format!("{name:<8} {value}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use boxcar_proto::control::{NetPolicy, VsockPolicy};

    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn net(allow: &[&str], deny: &[&str]) -> NetPolicy {
        NetPolicy {
            default: Verdict::Deny,
            allow: strings(allow),
            deny: strings(deny),
            inspect: Vec::new(),
        }
    }

    #[test]
    fn a_rule_moves_to_the_end_of_its_list_and_out_of_the_other() {
        assert_eq!(
            with_rule(net(&["a"], &["b", "c"]), Verdict::Allow, "b"),
            Some(net(&["a", "b"], &["c"]))
        );
        assert_eq!(
            with_rule(net(&["a"], &["b"]), Verdict::Deny, "a"),
            Some(net(&[], &["b", "a"]))
        );
        assert_eq!(
            with_rule(net(&["a"], &["b"]), Verdict::Allow, "d"),
            Some(net(&["a", "d"], &["b"]))
        );
        // Already there, and nowhere else: nothing to do.
        assert_eq!(with_rule(net(&["a"], &["b"]), Verdict::Allow, "a"), None);
        // There, but also in the other list: taken out of that one.
        assert_eq!(
            with_rule(net(&["a"], &["a"]), Verdict::Allow, "a"),
            Some(net(&["a"], &[]))
        );
    }

    #[test]
    fn the_table_has_a_row_per_rule() {
        let view = PolicyView {
            net: net(&["a.test"], &[]),
            vsock: VsockPolicy {
                allow_ports: vec![5000],
            },
            version: 2,
            exceptions: Vec::new(),
        };
        assert_eq!(
            table(&view, 0),
            "version  2\ndefault  deny\nallow    a.test\ndeny     (none)\ninspect  (none)\nvsock    5000\n"
        );
        assert_eq!(exception_table(&view, 0), "(none)\n");
    }

    /// The live exceptions come after the permanent policy, each with the
    /// seconds it has left, rounded up.
    #[test]
    fn exceptions_are_listed_with_their_time_left() {
        let at = 1_760_000_000_000_000_000;
        let view = PolicyView {
            net: net(&[], &[]),
            vsock: VsockPolicy::default(),
            version: 4,
            exceptions: vec![
                boxcar_proto::control::ExceptionView {
                    id: 1,
                    rule: "pypi.org:443".into(),
                    kind: ExceptionKind::Egress,
                    ttl_s: 600,
                    expires_ns: at + 599_500_000_000,
                    by_pid: 42,
                },
                boxcar_proto::control::ExceptionView {
                    id: 2,
                    rule: "/etc/**".into(),
                    kind: ExceptionKind::Writable,
                    ttl_s: 60,
                    expires_ns: at - 1,
                    by_pid: 42,
                },
            ],
        };
        assert!(table(&view, at).ends_with(
            "vsock    (none)\nexcept   1 egress pypi.org:443 (600 s left)\nexcept   2 writable /etc/** (0 s left)\n"
        ));
        assert_eq!(
            exception_table(&view, at),
            "1    egress   pypi.org:443 (600 s left)\n2    writable /etc/** (0 s left)\n"
        );
    }

    /// A duration: seconds bare or with `s`, minutes, hours; 1 s to 24 h.
    #[test]
    fn durations_parse_within_a_day() {
        use crate::cli::parse_ttl;
        assert_eq!(parse_ttl("90"), Ok(90));
        assert_eq!(parse_ttl("90s"), Ok(90));
        assert_eq!(parse_ttl("10m"), Ok(600));
        assert_eq!(parse_ttl("1h"), Ok(3600));
        assert_eq!(parse_ttl("24h"), Ok(86_400));
        for bad in [
            "0",
            "0s",
            "25h",
            "1d",
            "",
            "m",
            "-5",
            "1.5h",
            "10 m",
            "99999999999",
        ] {
            assert!(parse_ttl(bad).is_err(), "{bad:?}");
        }
    }
}
