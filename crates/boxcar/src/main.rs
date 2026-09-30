// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The `boxcar` command-line interface.

use clap::Parser;

/// Run AI coding agents in a microVM with a tamper-evident audit log.
#[derive(Parser)]
#[command(version)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
