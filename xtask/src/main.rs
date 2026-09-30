// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Build tasks for boxcar: guest kernel, initramfs, rootfs, and gated tests.

use clap::{Parser, Subcommand};

mod kernel;

/// Build tasks for boxcar.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the guest kernel into target/guest (in Docker unless --native).
    Kernel(kernel::KernelArgs),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Kernel(args) => kernel::run(&args),
    }
}
