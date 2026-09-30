// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The subcommands, one module each.

mod audit;
mod doctor;
mod run;

use std::process::ExitCode;

use crate::cli::{Cli, Command};

/// Runs the command `cli` names and returns the process exit code.
pub fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Audit(command) => audit::run(command),
        Command::Doctor => doctor::run(),
        Command::Run(args) => run::run(args),
    }
}
