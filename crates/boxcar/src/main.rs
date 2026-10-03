// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The `boxcar` command-line interface.

mod cli;
mod client;
mod cmd;

use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::Cli::try_parse_args(std::env::args_os()).unwrap_or_else(|error| error.exit());
    match cmd::run(cli) {
        Ok(code) => code,
        Err(err) => {
            cmd::tell(&format!("error: {err:#}"));
            ExitCode::from(1)
        }
    }
}
