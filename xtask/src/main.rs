// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Build tasks for boxcar: guest kernel, initramfs, rootfs, gated tests,
//! and the protocol schemas.

use clap::{Parser, Subcommand};

mod initramfs;
mod kernel;
mod rootfs;
mod schema;
mod test_kvm;

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
    /// Build the guest init and pack target/guest/initramfs.cpio.
    Initramfs,
    /// Download, verify and unpack a guest root filesystem into target/guest.
    Rootfs(rootfs::RootfsArgs),
    /// Run a milestone's KVM-gated tests; skips (exit 0) without /dev/kvm or
    /// the guest artifacts.
    TestKvm(test_kvm::TestKvmArgs),
    /// Write the JSON Schemas of the control protocol, the audit records and
    /// the guest channel to proto/schema, and the control protocol's golden
    /// lines to proto/testdata/control-v1.jsonl.
    Schema,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Kernel(args) => kernel::run(&args),
        Command::Initramfs => initramfs::run(),
        Command::Rootfs(args) => rootfs::run(&args),
        Command::TestKvm(args) => test_kvm::run(&args),
        Command::Schema => schema::run(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `m1` and `m2` are the milestones with gated tests.
    #[test]
    fn test_kvm_takes_m1_and_m2() {
        assert!(Cli::try_parse_from(["xtask", "test-kvm", "m1"]).is_ok());
        assert!(Cli::try_parse_from(["xtask", "test-kvm", "m2"]).is_ok());
        for bad in [&["xtask", "test-kvm", "m3"][..], &["xtask", "test-kvm"]] {
            let error = Cli::try_parse_from(bad).err().unwrap();
            assert_eq!(error.exit_code(), 2, "{bad:?}: {error}");
        }
    }
}
