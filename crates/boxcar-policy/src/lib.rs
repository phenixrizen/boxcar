// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Policy files: what a session may reach, write and run, as TOML.
//!
//! ```toml
//! version = 1                     # required, and 1
//!
//! [egress]
//! default = "deny"                # or "allow"; deny when absent
//! allow = ["api.example.com:443", "198.51.100.0/24:22"]
//! deny = ["*.ads.example"]
//! inspect = ["api.example.com:443"]
//! max_dns_qps = 20                # optional, 1 to 10000
//!
//! [fs]
//! writable = ["/workspace/**", "/tmp/**"]  # the default when absent
//! denied = ["/workspace/.env"]
//! indicators = ["/var/log/**"]
//!
//! [exec]
//! deny = ["**/nc"]
//!
//! [spans]
//! keep_tool_args = true           # the default
//!
//! [record]
//! scrub_argv = false              # the default
//! ```
//!
//! Every table, and every key in one, is optional but `version`; a key the
//! format does not have is refused wherever it is. [`parse`] reads a file
//! into a [`PolicyFile`], or says where it is wrong: a [`ParseError`] has
//! the line and the column.
//!
//! `[egress]` compiles through the line policy
//! ([`boxcar_net::Policy::from_lists`]): its targets are the line policy's
//! (`name[:port]`, `*.name[:port]`, `ip[:port]`, `ip/prefix[:port]`), and
//! its rules are the denies, then the allows, then the inspect lines, so a
//! deny of a target wins over an allow of it. `max_dns_qps` bounds the
//! guest's DNS queries a second (`boxcar_net::NetConfig::max_dns_qps`).
//!
//! The path lists are globs of guest paths (`globset`, with
//! `literal_separator`: `*` stays within a component, `**` crosses them),
//! absolute: each starts with `/` or `**/` ([`boxcar_fs::rules::glob`]),
//! and each covers what it names and all beneath it. `[fs] writable` is
//! what a change must name: `/workspace/**` and `/tmp/**` unless the file
//! says, so a file without it leaves the rest of the root share read-only;
//! `denied` is what may not be looked up, opened or changed at all;
//! `indicators` adds to the reconciler's `indicator_removal` paths;
//! `[exec] deny` is the program files that may not be run, or opened at
//! all.
//! [`PolicyFile::path_spec`] is what the shares put in force
//! ([`boxcar_fs::rules`]); `[spans] keep_tool_args` goes to the gate, and
//! `[record] scrub_argv` is `boxcar run --scrub-argv`.
//!
//! [`profiles`] holds the built-in policies, by name.

mod model;
mod parse;
pub mod profiles;

pub use model::{Egress, ExecRules, FsRules, PolicyFile, RecordSettings, SpanSettings};
pub use parse::{parse, ParseError, MAX_DNS_QPS, MAX_ENTRIES, MAX_TEXT, VERSION};
