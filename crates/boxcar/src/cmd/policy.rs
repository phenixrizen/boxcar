// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar policy`: a running session's network policy, read and changed
//! through its control socket (`policy.get` and `policy.update`).
//!
//! `allow RULE` and `deny RULE` work on the policy as `policy.get`
//! reports it: the rule goes to the end of its list and out of the other,
//! and the whole network policy goes back with `policy.update`. The rule is
//! parsed here first, as `boxcar run --allow` parses it, so a rule that
//! does not parse is a usage error (exit 2) before any connection is made.
//! The vsock allowlist is read by `show` and left as it is by the others.

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::{anyhow, Context};
use boxcar_net::{Policy, Verdict};
use boxcar_proto::control::{PolicyUpdateParams, PolicyUpdated, PolicyView};
use serde_json::Value;

use crate::cli::{PolicyCommand, PolicyRuleArgs, PolicyShowArgs, SessionArgs};
use crate::client::{self, Client};

/// The exit code of a rule that does not parse, as clap's usage errors and
/// `boxcar run`'s.
const USAGE_EXIT: u8 = 2;

pub fn run(command: PolicyCommand) -> anyhow::Result<ExitCode> {
    match command {
        PolicyCommand::Show(args) => show(&args),
        PolicyCommand::Allow(args) => change(&args, Verdict::Allow),
        PolicyCommand::Deny(args) => change(&args, Verdict::Deny),
    }
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
        out.write_all(table(&view).as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// Adds `args.rule` to the `verdict` list of the session's network policy
/// and sends the policy back, unless it is there already.
fn change(args: &PolicyRuleArgs, verdict: Verdict) -> anyhow::Result<ExitCode> {
    let verb = match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    };
    if let Err(error) = Policy::parse(&[format!("{verb} {}", args.rule)]) {
        crate::cmd::tell(&format!(
            "error: policy {verb} {:?}: {}",
            args.rule, error.kind
        ));
        return Ok(ExitCode::from(USAGE_EXIT));
    }
    let mut client = connect(&args.session)?;
    let (view, _) = get(&mut client)?;
    let Some(net) = with_rule(view.net, verdict, &args.rule) else {
        println!("policy version {} (unchanged)", view.version);
        return Ok(ExitCode::SUCCESS);
    };
    let params = PolicyUpdateParams {
        net: Some(net),
        vsock: None,
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
/// list.
fn table(view: &PolicyView) -> String {
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
        };
        assert_eq!(
            table(&view),
            "version  2\ndefault  deny\nallow    a.test\ndeny     (none)\ninspect  (none)\nvsock    5000\n"
        );
    }
}
