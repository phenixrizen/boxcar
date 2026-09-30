// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The `boxcar` command-line interface.

mod cli;
mod cmd;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match cmd::run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}
