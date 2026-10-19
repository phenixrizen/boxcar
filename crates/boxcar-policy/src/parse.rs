// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Reading a policy file: TOML through serde into the raw shapes below,
//! then every value checked where it stands, so that each refusal names
//! the line and the column of what it refuses.

use std::ops::Range;

use boxcar_net::{List, Policy, Verdict};
use globset::GlobBuilder;
use serde::Deserialize;
use toml::Spanned;

use crate::model::{Egress, ExecRules, FsRules, PolicyFile, RecordSettings, SpanSettings};

/// The format's version, the one `version` must give.
pub const VERSION: i64 = 1;
/// The longest policy text read, in bytes.
pub const MAX_TEXT: usize = 1024 * 1024;
/// The most entries in any one list.
pub const MAX_ENTRIES: usize = 1024;
/// The highest `max_dns_qps`.
pub const MAX_DNS_QPS: u32 = 10_000;

/// The `writable` of a file that gives none.
const DEFAULT_WRITABLE: &str = "/workspace/**";

/// Why a policy file was refused, and where: the line and the column, both
/// from 1, of what is wrong.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{line}:{column}: {message}")]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

/// A list as the file has it: its place, and each entry with its own.
type SpannedList = Spanned<Vec<Spanned<String>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    version: Spanned<i64>,
    #[serde(default)]
    egress: RawEgress,
    #[serde(default)]
    fs: RawFs,
    #[serde(default)]
    exec: RawExec,
    #[serde(default)]
    spans: RawSpans,
    #[serde(default)]
    record: RawRecord,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgress {
    default: Option<RawDefault>,
    allow: Option<SpannedList>,
    deny: Option<SpannedList>,
    inspect: Option<SpannedList>,
    max_dns_qps: Option<Spanned<i64>>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawDefault {
    Allow,
    Deny,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFs {
    writable: Option<SpannedList>,
    denied: Option<SpannedList>,
    indicators: Option<SpannedList>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExec {
    deny: Option<SpannedList>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpans {
    keep_tool_args: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    scrub_argv: Option<bool>,
}

/// Reads a policy file: its TOML, then its version, its lists' lengths,
/// its targets (through the line policy's parser), its globs and its DNS
/// rate. The first thing wrong refuses the whole file, with where it is.
pub fn parse(text: &str) -> Result<PolicyFile, ParseError> {
    if text.len() > MAX_TEXT {
        return Err(at(
            text,
            0..0,
            format!(
                "the policy is {} bytes, more than {MAX_TEXT} (1 MiB)",
                text.len()
            ),
        ));
    }
    let raw: Raw = toml::from_str(text).map_err(|error| {
        at(
            text,
            error.span().unwrap_or(0..0),
            error.message().to_owned(),
        )
    })?;
    let fail = |span: Range<usize>, message: String| at(text, span, message);

    if *raw.version.get_ref() != VERSION {
        return Err(fail(
            raw.version.span(),
            format!(
                "version {} is not one this boxcar reads: it reads version {VERSION}",
                raw.version.get_ref()
            ),
        ));
    }

    let deny = list(&raw.egress.deny, "[egress] deny", &fail)?;
    let allow = list(&raw.egress.allow, "[egress] allow", &fail)?;
    let inspect = list(&raw.egress.inspect, "[egress] inspect", &fail)?;
    let default = match raw.egress.default {
        Some(RawDefault::Allow) => Verdict::Allow,
        Some(RawDefault::Deny) | None => Verdict::Deny,
    };
    let texts = |entries: &[&Spanned<String>]| -> Vec<String> {
        entries
            .iter()
            .map(|entry| entry.get_ref().clone())
            .collect()
    };
    let policy = Policy::from_lists(default, &texts(&deny), &texts(&allow), &texts(&inspect))
        .map_err(|error| {
            let (name, entries) = match error.list {
                List::Deny => ("[egress] deny", &deny),
                List::Allow => ("[egress] allow", &allow),
                List::Inspect => ("[egress] inspect", &inspect),
            };
            let span = entries.get(error.index).map_or(0..0, |entry| entry.span());
            fail(span, format!("{name}: {}", error.kind))
        })?;
    let max_dns_qps = match &raw.egress.max_dns_qps {
        Some(rate) => match u32::try_from(*rate.get_ref()) {
            Ok(qps @ 1..=MAX_DNS_QPS) => Some(qps),
            _ => {
                return Err(fail(
                    rate.span(),
                    format!(
                        "[egress] max_dns_qps {} is not from 1 to {MAX_DNS_QPS}",
                        rate.get_ref()
                    ),
                ))
            }
        },
        None => None,
    };

    let writable = match &raw.fs.writable {
        Some(_) => globs(&raw.fs.writable, "[fs] writable", &fail)?,
        None => vec![DEFAULT_WRITABLE.to_owned()],
    };
    let fs = FsRules {
        writable,
        denied: globs(&raw.fs.denied, "[fs] denied", &fail)?,
        indicators: globs(&raw.fs.indicators, "[fs] indicators", &fail)?,
    };
    let exec = ExecRules {
        deny: globs(&raw.exec.deny, "[exec] deny", &fail)?,
    };

    Ok(PolicyFile {
        egress: Egress {
            policy,
            max_dns_qps,
        },
        fs,
        exec,
        spans: SpanSettings {
            keep_tool_args: raw.spans.keep_tool_args.unwrap_or(true),
        },
        record: RecordSettings {
            scrub_argv: raw.record.scrub_argv.unwrap_or(false),
        },
    })
}

/// A list's entries, refused when there are more than [`MAX_ENTRIES`];
/// none when the file does not give it.
fn list<'a>(
    raw: &'a Option<SpannedList>,
    name: &str,
    fail: &impl Fn(Range<usize>, String) -> ParseError,
) -> Result<Vec<&'a Spanned<String>>, ParseError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let entries = raw.get_ref();
    if entries.len() > MAX_ENTRIES {
        return Err(fail(
            raw.span(),
            format!(
                "{name} has {} entries, more than {MAX_ENTRIES}",
                entries.len()
            ),
        ));
    }
    Ok(entries.iter().collect())
}

/// A list of path globs, each absolute (starting `/` or `**/`) and one
/// `globset` compiles with `literal_separator`.
fn globs(
    raw: &Option<SpannedList>,
    name: &str,
    fail: &impl Fn(Range<usize>, String) -> ParseError,
) -> Result<Vec<String>, ParseError> {
    let mut out = Vec::new();
    for entry in list(raw, name, fail)? {
        let glob = entry.get_ref();
        if !(glob.starts_with('/') || glob.starts_with("**/")) {
            return Err(fail(
                entry.span(),
                format!("{name}: {glob:?} is relative; a path glob starts with / or **/"),
            ));
        }
        if let Err(error) = GlobBuilder::new(glob).literal_separator(true).build() {
            return Err(fail(
                entry.span(),
                format!("{name}: {glob:?} is not a glob: {}", error.kind()),
            ));
        }
        out.push(glob.clone());
    }
    Ok(out)
}

/// A refusal at the start of `span` in `text`.
fn at(text: &str, span: Range<usize>, message: String) -> ParseError {
    let (line, column) = position(text, span.start);
    ParseError {
        line,
        column,
        message,
    }
}

/// The line and column, from 1, of byte `offset` in `text`: columns count
/// characters, not bytes.
fn position(text: &str, offset: usize) -> (usize, usize) {
    let offset = text.floor_char_boundary(offset.min(text.len()));
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
    let column = text[line_start..offset].chars().count() + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> PolicyFile {
        match parse(text) {
            Ok(file) => file,
            Err(error) => panic!("{text:?}: {error}"),
        }
    }

    /// The smallest file: a version and nothing else, every default.
    #[test]
    fn a_version_alone_takes_every_default() {
        let file = ok("version = 1\n");
        assert_eq!(file.egress.policy, Policy::default());
        assert_eq!(file.egress.max_dns_qps, None);
        assert_eq!(file.fs.writable, ["/workspace/**"]);
        assert!(file.fs.denied.is_empty());
        assert!(file.fs.indicators.is_empty());
        assert!(file.exec.deny.is_empty());
        assert!(file.spans.keep_tool_args);
        assert!(!file.record.scrub_argv);
        assert_eq!(file.fs_rules(), 1);
        assert_eq!(file.exec_rules(), 0);
        assert_eq!(file.not_in_force(), ["[fs] writable"]);
    }

    /// Every field, read as written.
    #[test]
    fn every_field_is_read() {
        let file = ok(r#"
version = 1

[egress]
default = "allow"
allow = ["api.example.com:443", "198.51.100.0/24:22"]
deny = ["*.ads.example"]
inspect = ["api.example.com:443"]
max_dns_qps = 20

[fs]
writable = ["/workspace/**", "/tmp/**"]
denied = ["/workspace/.env", "**/secrets/*"]
indicators = ["/var/log/**", "/workspace/notes/**"]

[exec]
deny = ["**/nc", "/usr/bin/{socat,telnet}"]

[spans]
keep_tool_args = false

[record]
scrub_argv = true
"#);
        let want = Policy::parse(&[
            "default allow",
            "deny *.ads.example",
            "allow api.example.com:443",
            "allow 198.51.100.0/24:22",
            "inspect api.example.com:443",
        ])
        .unwrap();
        assert_eq!(file.egress.policy, want);
        assert_eq!(file.egress.max_dns_qps, Some(20));
        assert_eq!(file.fs.writable, ["/workspace/**", "/tmp/**"]);
        assert_eq!(file.fs.denied, ["/workspace/.env", "**/secrets/*"]);
        assert_eq!(file.fs.indicators, ["/var/log/**", "/workspace/notes/**"]);
        assert_eq!(file.exec.deny, ["**/nc", "/usr/bin/{socat,telnet}"]);
        assert!(!file.spans.keep_tool_args);
        assert!(file.record.scrub_argv);
        assert_eq!(file.fs_rules(), 6);
        assert_eq!(file.exec_rules(), 2);
        assert_eq!(
            file.not_in_force(),
            [
                "[fs] writable",
                "[fs] denied",
                "[fs] indicators",
                "[exec] deny",
                "[spans] keep_tool_args",
                "[record] scrub_argv",
            ]
        );
    }

    /// Each table may be empty, each list too; `writable = []` is nothing
    /// writable, not the default.
    #[test]
    fn empty_tables_and_lists_are_allowed() {
        let file = ok(
            "version = 1\n[egress]\nallow = []\n[fs]\nwritable = []\n[exec]\n[spans]\n[record]\n",
        );
        assert_eq!(file.egress.policy, Policy::default());
        assert!(file.fs.writable.is_empty());
        assert_eq!(file.fs_rules(), 0);
        // Writing everywhere, with only the reconciler's own indicators, is
        // all in force already.
        let open = ok(
            "version = 1\n[fs]\nwritable = [\"/**\"]\nindicators = [\"/var/log/**\", \"**/.*_history\"]\n",
        );
        assert!(open.not_in_force().is_empty());
        // The same as inline tables.
        let inline = ok("version = 1\negress = { default = \"deny\", allow = [\"a.test\"] }\n");
        assert_eq!(
            inline.egress.policy,
            Policy::parse(&["allow a.test"]).unwrap()
        );
    }

    /// A deny of a target wins over an allow of it, whatever the order of
    /// the keys in the file.
    #[test]
    fn denies_come_before_allows() {
        let file = ok("version = 1\n[egress]\nallow = [\"a.test\"]\ndeny = [\"a.test\"]\n");
        let texts: Vec<&str> = file
            .egress
            .policy
            .rules
            .iter()
            .map(|rule| rule.text.as_str())
            .collect();
        assert_eq!(texts, ["deny a.test", "allow a.test"]);
    }

    /// Each refusal, with the line and column of what it refuses.
    #[test]
    fn every_refusal_names_its_line_and_column() {
        let big_list = format!(
            "version = 1\n[egress]\nallow = [{}]\n",
            vec!["\"a.test\""; MAX_ENTRIES + 1].join(", ")
        );
        let cases: Vec<(String, usize, usize, &str)> = vec![
            // TOML itself.
            ("version = 1\nallow = [\n".into(), 2, 10, "unclosed array"),
            ("version = 1\n[egress\n".into(), 2, 8, "unclosed table"),
            (
                "version = 1\n[egress]\n[egress]\n".into(),
                3,
                2,
                "duplicate key",
            ),
            // The version.
            ("[egress]\n".into(), 1, 1, "missing field `version`"),
            (
                "version = 2\n".into(),
                1,
                11,
                "version 2 is not one this boxcar reads",
            ),
            ("version = \"1\"\n".into(), 1, 11, "invalid type: string"),
            // Unknown keys, at every level.
            (
                "version = 1\npolicy = 3\n".into(),
                2,
                1,
                "unknown field `policy`",
            ),
            (
                "version = 1\n[egress]\nallows = []\n".into(),
                3,
                1,
                "unknown field `allows`",
            ),
            (
                "version = 1\n[fs]\nwriteable = []\n".into(),
                3,
                1,
                "unknown field `writeable`",
            ),
            (
                "version = 1\n[exec]\nallow = []\n".into(),
                3,
                1,
                "unknown field `allow`",
            ),
            (
                "version = 1\n[spans]\nkeep = true\n".into(),
                3,
                1,
                "unknown field `keep`",
            ),
            (
                "version = 1\n[record]\nscrub = true\n".into(),
                3,
                1,
                "unknown field `scrub`",
            ),
            // Wrong types.
            (
                "version = 1\negress = 5\n".into(),
                2,
                10,
                "invalid type: integer",
            ),
            (
                "version = 1\n[egress]\nallow = \"a.test\"\n".into(),
                3,
                9,
                "invalid type: string",
            ),
            (
                "version = 1\n[egress]\nallow = [1]\n".into(),
                3,
                10,
                "invalid type: integer",
            ),
            (
                "version = 1\n[spans]\nkeep_tool_args = \"no\"\n".into(),
                3,
                18,
                "invalid type: string",
            ),
            (
                "version = 1\n[record]\nscrub_argv = 1\n".into(),
                3,
                14,
                "invalid type: integer",
            ),
            // The default.
            (
                "version = 1\n[egress]\ndefault = \"maybe\"\n".into(),
                3,
                11,
                "unknown variant `maybe`",
            ),
            // A target that does not parse, in each egress list.
            (
                "version = 1\n[egress]\nallow = [\"ok.test\", \"exa_mple.com\"]\n".into(),
                3,
                21,
                "[egress] allow: \"exa_mple.com\" is not a host name",
            ),
            (
                "version = 1\n[egress]\ndeny = [\"192.168.1.300\"]\n".into(),
                3,
                9,
                "[egress] deny: \"192.168.1.300\" looks like an address",
            ),
            (
                "version = 1\n[egress]\ninspect = [\"a.test:0\"]\n".into(),
                3,
                12,
                "[egress] inspect: \"0\" is not a port",
            ),
            (
                "version = 1\n[egress]\nallow = [\"two words\"]\n".into(),
                3,
                10,
                "[egress] allow: allow takes one target",
            ),
            (
                "version = 1\n[egress]\nallow = [\"a.test # a comment\"]\n".into(),
                3,
                10,
                "[egress] allow: allow takes one target",
            ),
            (
                "version = 1\n[egress]\nallow = [\"\"]\n".into(),
                3,
                10,
                "[egress] allow: allow takes one target",
            ),
            (
                "version = 1\n[egress]\ndeny = [\"10.1.2.3/8\"]\n".into(),
                3,
                9,
                "[egress] deny: 10.1.2.3/8 has host bits set",
            ),
            // A glob that is relative or does not compile, in each path list.
            (
                "version = 1\n[fs]\nwritable = [\"workspace/**\"]\n".into(),
                3,
                13,
                "[fs] writable: \"workspace/**\" is relative",
            ),
            (
                "version = 1\n[fs]\ndenied = [\"**\"]\n".into(),
                3,
                11,
                "[fs] denied: \"**\" is relative",
            ),
            (
                "version = 1\n[fs]\nindicators = [\"/var/log/[\"]\n".into(),
                3,
                15,
                "[fs] indicators: \"/var/log/[\" is not a glob",
            ),
            (
                "version = 1\n[exec]\ndeny = [\"/usr/bin/{nc\"]\n".into(),
                3,
                9,
                "[exec] deny: \"/usr/bin/{nc\" is not a glob",
            ),
            (
                "version = 1\n[exec]\ndeny = [\"/usr/bin/[z-a]\"]\n".into(),
                3,
                9,
                "[exec] deny: \"/usr/bin/[z-a]\" is not a glob",
            ),
            // The DNS rate.
            (
                "version = 1\n[egress]\nmax_dns_qps = 0\n".into(),
                3,
                15,
                "[egress] max_dns_qps 0 is not from 1 to 10000",
            ),
            (
                "version = 1\n[egress]\nmax_dns_qps = 10001\n".into(),
                3,
                15,
                "is not from 1 to 10000",
            ),
            (
                "version = 1\n[egress]\nmax_dns_qps = -5\n".into(),
                3,
                15,
                "[egress] max_dns_qps -5 is not",
            ),
            (
                "version = 1\n[egress]\nmax_dns_qps = 2.5\n".into(),
                3,
                15,
                "invalid type: floating point",
            ),
            // Too much.
            (
                big_list,
                3,
                9,
                "[egress] allow has 1025 entries, more than 1024",
            ),
            (
                format!("version = 1\n#{}\n", "x".repeat(MAX_TEXT)),
                1,
                1,
                "more than 1048576 (1 MiB)",
            ),
        ];
        let mut wrong = Vec::new();
        for (text, line, column, message) in cases {
            let shown = &text[..text.len().min(80)];
            match parse(&text) {
                Ok(_) => wrong.push(format!("{shown:?}: accepted")),
                Err(error) => {
                    if !error.message.contains(message)
                        || (error.line, error.column) != (line, column)
                    {
                        wrong.push(format!(
                            "{shown:?}: {error}, wanted {line}:{column}: {message}"
                        ));
                    }
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Columns count characters, so a refusal after a multi-byte character
    /// on its line points where an editor would.
    #[test]
    fn columns_count_characters() {
        let error = parse("version = 1\n[egress] # é\nallow = [\"é.test\"]\n").unwrap_err();
        assert_eq!((error.line, error.column), (3, 10), "{error}");
        assert_eq!(position("aé\nb", 3), (1, 3));
        assert_eq!(position("aé\nb", 4), (2, 1));
        assert_eq!(position("", 10), (1, 1));
        assert_eq!(error.to_string(), format!("3:10: {}", error.message));
    }
}
