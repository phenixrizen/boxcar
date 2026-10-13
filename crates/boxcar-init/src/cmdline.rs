// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The `boxcar.*` keys of the kernel command line.
//!
//! The VMM passes per-session settings to init as `boxcar.<key>[=<value>]`
//! tokens on the kernel command line, which init reads from `/proc/cmdline`.

use std::collections::BTreeMap;
use std::fs;
use std::io;

/// Prefix that marks a command line token as ours.
const PREFIX: &str = "boxcar.";

/// Where the kernel exposes its command line.
const PROC_CMDLINE: &str = "/proc/cmdline";

/// The `boxcar.*` keys of a kernel command line, with the prefix stripped.
///
/// Tokens are separated by whitespace outside double quotes. The quote
/// characters themselves are dropped, so `boxcar.cmd="a b"` gives `cmd` the
/// value `a b`; an unterminated quote runs to the end of the input. A token
/// splits at its first `=`; without one the value is the empty string. Tokens
/// without the `boxcar.` prefix are ignored, and a repeated key keeps the last
/// value. This is pure: it does no I/O.
pub fn parse(s: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut token = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => insert(&mut map, &mut token),
            c => token.push(c),
        }
    }
    insert(&mut map, &mut token);
    map
}

/// Records `token` in `map` if it is one of ours, and empties it.
fn insert(map: &mut BTreeMap<String, String>, token: &mut String) {
    if let Some(rest) = token.strip_prefix(PREFIX) {
        let (key, value) = rest.split_once('=').unwrap_or((rest, ""));
        map.insert(key.to_owned(), value.to_owned());
    }
    token.clear();
}

/// Whether the VM has a network card: the VMM says so with `boxcar.net=1`.
pub fn net_enabled(args: &BTreeMap<String, String>) -> bool {
    args.get("net").is_some_and(|value| value == "1")
}

/// Whether init starts the sensor (ring 1): it does unless `boxcar.sensor=0`
/// (`boxcar run --no-sensor`).
pub fn sensor_enabled(args: &BTreeMap<String, String>) -> bool {
    args.get("sensor").is_none_or(|value| value != "0")
}

/// [`parse`] of `/proc/cmdline`. `/proc` must already be mounted.
pub fn read() -> io::Result<BTreeMap<String, String>> {
    Ok(parse(&fs::read_to_string(PROC_CMDLINE)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn keeps_only_boxcar_tokens_and_strips_the_prefix() {
        let cmdline = "console=ttyS0 boxcar.mode=hello root=/dev/vda quiet boxcar.tag=x\n";
        assert_eq!(parse(cmdline), map(&[("mode", "hello"), ("tag", "x")]));
    }

    #[test]
    fn prefix_must_be_exact_and_at_the_start_of_the_token() {
        let cmdline = "xboxcar.a=1 boxcarx.b=2 boxcar=3 Boxcar.c=4 foo.boxcar.d=5 boxcar.e=6";
        assert_eq!(parse(cmdline), map(&[("e", "6")]));
    }

    #[test]
    fn quoted_value_keeps_its_spaces_and_loses_its_quotes() {
        let cmdline = r#"boxcar.mode=console boxcar.cmd="a b  c" quiet"#;
        assert_eq!(
            parse(cmdline),
            map(&[("mode", "console"), ("cmd", "a b  c")])
        );
    }

    #[test]
    fn a_whole_token_in_quotes_is_one_token() {
        assert_eq!(parse(r#""boxcar.cmd=a b""#), map(&[("cmd", "a b")]));
    }

    #[test]
    fn an_unterminated_quote_runs_to_the_end() {
        assert_eq!(parse(r#"boxcar.cmd="a b c"#), map(&[("cmd", "a b c")]));
    }

    #[test]
    fn empty_quotes_give_an_empty_value() {
        assert_eq!(
            parse(r#"boxcar.cmd="" boxcar.x=1"#),
            map(&[("cmd", ""), ("x", "1")])
        );
    }

    #[test]
    fn token_without_equals_maps_to_an_empty_string() {
        assert_eq!(
            parse("boxcar.debug boxcar.mode=hello"),
            map(&[("debug", ""), ("mode", "hello")])
        );
    }

    #[test]
    fn empty_value_is_an_empty_string() {
        assert_eq!(parse("boxcar.x="), map(&[("x", "")]));
    }

    #[test]
    fn only_the_first_equals_splits() {
        assert_eq!(parse("boxcar.cmd=a=b=c"), map(&[("cmd", "a=b=c")]));
    }

    #[test]
    fn duplicate_key_keeps_the_last() {
        assert_eq!(
            parse("boxcar.mode=console boxcar.mode=hello"),
            map(&[("mode", "hello")])
        );
    }

    #[test]
    fn any_whitespace_separates_tokens() {
        assert_eq!(
            parse("boxcar.a=1\t boxcar.b=2\n\nboxcar.c=3\n"),
            map(&[("a", "1"), ("b", "2"), ("c", "3")])
        );
    }

    /// The network's setup runs only when the VMM says the VM has a
    /// network card, with exactly `boxcar.net=1`.
    #[test]
    fn the_network_is_on_only_with_boxcar_net_1() {
        assert!(net_enabled(&parse("boxcar.mode=console boxcar.net=1")));
        // The sensor runs unless told not to.
        assert!(sensor_enabled(&parse("boxcar.mode=vsock")));
        assert!(sensor_enabled(&parse("boxcar.mode=vsock boxcar.sensor=1")));
        assert!(!sensor_enabled(&parse("boxcar.mode=vsock boxcar.sensor=0")));
        for cmdline in [
            "boxcar.mode=console",
            "boxcar.net=0",
            "boxcar.net",
            "boxcar.net=yes",
            "boxcar.net=1 boxcar.net=0",
            "net=1",
        ] {
            assert!(!net_enabled(&parse(cmdline)), "{cmdline}");
        }
    }

    #[test]
    fn empty_and_blank_input_give_an_empty_map() {
        assert!(parse("").is_empty());
        assert!(parse(" \t\n").is_empty());
    }
}
