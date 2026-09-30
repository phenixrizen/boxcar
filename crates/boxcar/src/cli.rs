// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What `boxcar` accepts on its command line.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Shares `--rootfs` with the guest as its root filesystem and
    /// `--workspace` at /workspace, both over virtio-fs, and records what
    /// the guest does to them. The guest runs a login shell on its serial
    /// console as the invoking user's uid and gid, or, after `--`, the
    /// command given. Prints the session id, its audit log directory and
    /// the workspace on stderr, runs the guest with its serial console on
    /// stdout (or in `--console-log`), and exits when it stops: 0 when the
    /// guest reset or shut down (whatever the session's own exit status,
    /// which the console shows as `boxcar: session exited <code>`), 1 after
    /// a vCPU error, 130 after SIGINT (Ctrl-C) or the console escape, 143
    /// after SIGTERM. When stdin is a terminal, the console is on stdout and
    /// no command is given, every key goes to the guest, Ctrl-C included;
    /// press Ctrl-] twice within a second to stop the VM.
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
    /// The guest's root filesystem: a host directory shared over virtio-fs
    /// as tag `root`. Required unless `--no-fs`.
    #[arg(
        long,
        value_name = "DIR",
        required_unless_present = "no_fs",
        conflicts_with = "no_fs"
    )]
    pub rootfs: Option<PathBuf>,
    /// A host directory shared over virtio-fs as tag `workspace`, which the
    /// guest mounts at /workspace. Default: a new `workspace/` directory in
    /// the session's audit directory.
    #[arg(long, value_name = "DIR", conflicts_with = "no_fs")]
    pub workspace: Option<PathBuf>,
    /// Boot without filesystem shares: the guest init prints a marker and
    /// reboots.
    #[arg(long)]
    pub no_fs: bool,
    /// What the shares record: `normal` (opens, closes with content hashes,
    /// changes and denials) or `verbose` (also every read, write and
    /// directory listing).
    #[arg(long, value_enum, value_name = "LEVEL", default_value_t = AuditLevelArg::Normal)]
    pub audit_level: AuditLevelArg,
    /// An extra kernel command line argument. Repeatable. These follow the
    /// `boxcar.mode`, `boxcar.uid` and `boxcar.gid` keys boxcar sets, so
    /// they can override them; `boxcar.cmd` from `-- CMD` comes after them.
    /// The whole command line may not exceed 2048 bytes.
    #[arg(long, value_name = "STR")]
    pub cmdline_extra: Vec<String>,
    /// Early printk on the serial console and every kernel message.
    #[arg(long)]
    pub debug_boot: bool,
    /// Where audit logs go: DIR/sessions/<session-id>/. Default:
    /// $XDG_DATA_HOME/boxcar, or ~/.local/share/boxcar. It may not be
    /// inside `--rootfs` or `--workspace`, nor either of them inside it.
    #[arg(long, value_name = "DIR")]
    pub audit_dir: Option<PathBuf>,
    /// Write the serial console to PATH instead of stdout. Stdin is then not
    /// forwarded to the guest.
    #[arg(long, value_name = "PATH")]
    pub console_log: Option<PathBuf>,
    /// The command the guest runs instead of a login shell, and its
    /// arguments, after `--`: an argv, run without a shell, with CMD looked
    /// up in the guest's PATH unless it holds a `/`. The run is not
    /// interactive: stdin is not forwarded and the terminal is left as it
    /// is.
    #[arg(last = true, value_name = "CMD", conflicts_with = "no_fs")]
    pub command: Vec<String>,
}

/// `--audit-level`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuditLevelArg {
    Normal,
    Verbose,
}
