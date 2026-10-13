// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar spans`: a running session's tool spans, from its control
//! socket's `span.list`.

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::{anyhow, Context};
use boxcar_proto::control::{SpanEntry, SpanList, SpanListParams};

use crate::cli::SpansArgs;
use crate::client;

/// Prints the spans of the session `args` names: the object the socket
/// returned with `--json`, one line per span otherwise.
pub fn run(args: &SpansArgs) -> anyhow::Result<ExitCode> {
    let session = &args.session;
    let mut client = client::connect(session.control.as_deref(), session.session_id.as_deref())?;
    let params = serde_json::to_value(SpanListParams {
        active_only: args.active,
    })
    .context("the parameters")?;
    let result = client
        .request("span.list", params)?
        .map_err(|error| anyhow!("span.list: {error}"))?;
    let mut out = io::stdout().lock();
    if args.json {
        writeln!(out, "{result}")?;
    } else {
        let list: SpanList =
            serde_json::from_value(result).context("the server sent a malformed span list")?;
        out.write_all(lines(&list.spans).as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// One line per span: the id, the tool, its state with the seqs, the
/// counts and the worst score.
fn lines(spans: &[SpanEntry]) -> String {
    let mut text = String::new();
    for span in spans {
        let state = match span.closed_seq {
            Some(closed) => format!("closed seq {}..{closed}", span.opened_seq),
            None => format!("open   seq {}..", span.opened_seq),
        };
        text.push_str(&format!(
            "{}  {}  {state}  procs {}  effects {}  worst {}\n",
            span.span_id, span.tool_name, span.procs, span.effects, span.worst_score
        ));
    }
    text
}

/// The `span.list` parameters as `boxcar spans` sends them; for the tests.
#[cfg(test)]
fn params_for(active: bool) -> serde_json::Value {
    serde_json::to_value(SpanListParams {
        active_only: active,
    })
    .unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn one_line_per_span_open_or_closed() {
        let spans = vec![
            SpanEntry {
                span_id: "toolu_02".into(),
                tool_name: "Write".into(),
                opened_seq: 61,
                closed_seq: None,
                procs: 0,
                effects: 1,
                worst_score: 0,
            },
            SpanEntry {
                span_id: "toolu_01".into(),
                tool_name: "Bash".into(),
                opened_seq: 40,
                closed_seq: Some(58),
                procs: 2,
                effects: 3,
                worst_score: 55,
            },
        ];
        assert_eq!(
            lines(&spans),
            "toolu_02  Write  open   seq 61..  procs 0  effects 1  worst 0\n\
             toolu_01  Bash  closed seq 40..58  procs 2  effects 3  worst 55\n"
        );
        assert_eq!(lines(&[]), "");
    }

    #[test]
    fn the_active_flag_is_the_active_only_parameter() {
        assert_eq!(params_for(true), json!({"active_only": true}));
        assert_eq!(params_for(false), json!({"active_only": false}));
    }
}
