// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What `boxcar` accepts on its command line.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Run AI coding agents in a microVM with a tamper-evident audit log.
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Work with audit logs.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Check that this machine can build and run boxcar.
    ///
    /// Prints one line per check: KVM access and capabilities, Docker, the
    /// musl target, and the guest kernel and initramfs. Exits 1 when a
    /// required check fails; a guest artifact that is not built yet is not a
    /// failure.
    Doctor,
    /// Boot a microVM.
    ///
    /// Prints the session id and its audit log directory on stderr, runs the
    /// guest with its serial console on stdout (or in `--console-log`), and
    /// exits when it stops: 0 when the guest reset or shut down, 1 after a
    /// vCPU error, 130 after SIGINT (Ctrl-C) or the console escape, 143
    /// after SIGTERM. When stdin is a terminal and the console is on stdout,
    /// every key goes to the guest, Ctrl-C included; press Ctrl-] twice
    /// within a second to stop the VM.
    Run(RunArgs),
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Check that a log is intact: every hash, link, sequence number and
    /// checkpoint. Exits 0 when it is, 1 at the first break.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// A session directory, or a single `.jsonl` log file.
    pub path: PathBuf,
    /// Print the report, or the first break, as one JSON object.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// The guest kernel: an uncompressed ELF vmlinux.
    #[arg(long, value_name = "PATH")]
    pub kernel: PathBuf,
    /// A cpio archive the kernel unpacks as its initial root filesystem.
    #[arg(long, value_name = "PATH")]
    pub initramfs: Option<PathBuf>,
    /// Guest memory in MiB.
    #[arg(
        long,
        value_name = "N",
        default_value_t = boxcar_vmm::vmm::DEFAULT_MEM_MIB,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub mem_mib: u64,
    /// Number of vCPUs.
    #[arg(
        long,
        value_name = "N",
        default_value_t = boxcar_vmm::vmm::DEFAULT_VCPUS,
        value_parser = clap::value_parser!(u8).range(1..)
    )]
    pub vcpus: u8,
    /// Boot without filesystem shares. Required: this build has none yet.
    #[arg(long)]
    pub no_fs: bool,
    /// An extra kernel command line argument. Repeatable.
    #[arg(long, value_name = "STR")]
    pub cmdline_extra: Vec<String>,
    /// Early printk on the serial console and every kernel message.
    #[arg(long)]
    pub debug_boot: bool,
    /// Where audit logs go: DIR/sessions/<session-id>/.
    #[arg(long, value_name = "DIR", default_value = "./boxcar-data")]
    pub audit_dir: PathBuf,
    /// Write the serial console to PATH instead of stdout. Stdin is then not
    /// forwarded to the guest.
    #[arg(long, value_name = "PATH")]
    pub console_log: Option<PathBuf>,
}
