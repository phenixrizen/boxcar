// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Build tasks for boxcar: guest kernel, initramfs, rootfs, and gated tests.

use clap::Parser;

/// Build tasks for boxcar.
#[derive(Parser)]
#[command(version)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
