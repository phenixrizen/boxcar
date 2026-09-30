// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`: boots a microVM and records its session.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context};
use boxcar_audit::WriterConfig;
use boxcar_fs::{AuditFsOptions, AuditLevel, CachePolicyKind, FsShareConfig};
use boxcar_proto::SessionId;
use boxcar_vmm::lifecycle::block_stop_signals;
use boxcar_vmm::vmm::{ConsoleOut, VmConfig, Vmm};
use tracing_subscriber::EnvFilter;

use crate::cli::{AuditLevelArg, RunArgs};

/// Starts the session's audit writer, boots the VM, and waits for it to
/// stop. The exit code is the VM's (see `VmExit::exit_code`).
pub fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    init_tracing();
    // The shares are checked before the session exists, so that a typo
    // does not leave an empty session behind.
    let rootfs = args
        .rootfs
        .as_deref()
        .map(|dir| share_dir("rootfs", dir))
        .transpose()?;
    let workspace = args
        .workspace
        .as_deref()
        .map(|dir| share_dir("workspace", dir))
        .transpose()?;
    // Before any thread starts, so that every thread inherits the mask and
    // the signals reach only the VMM's signalfd.
    block_stop_signals().context("cannot block SIGINT and SIGTERM")?;

    let session_id = SessionId::new();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(&args.audit_dir, session_id.clone())).with_context(
            || {
                format!(
                    "cannot start the audit log under {}",
                    args.audit_dir.display()
                )
            },
        )?;
    eprintln!("session: {session_id}");
    eprintln!("audit: {}", writer.session_dir().display());

    let fs_shares = match rootfs {
        Some(rootfs) => {
            let workspace = match workspace {
                Some(dir) => dir,
                None => new_workspace(writer.session_dir())?,
            };
            eprintln!("workspace: {}", workspace.display());
            shares(rootfs, workspace)
        }
        // clap requires --rootfs unless --no-fs.
        None => Vec::new(),
    };

    let cfg = VmConfig {
        kernel: args.kernel,
        initramfs: args.initramfs,
        mem_mib: args.mem_mib,
        vcpus: args.vcpus,
        cmdline_extra: args.cmdline_extra,
        debug_boot: args.debug_boot,
        console: match args.console_log {
            Some(path) => ConsoleOut::File(path),
            None => ConsoleOut::Stdio,
        },
        audit: sink,
        fs_shares,
        fs_audit: AuditFsOptions {
            level: match args.audit_level {
                AuditLevelArg::Normal => AuditLevel::Normal,
                AuditLevelArg::Verbose => AuditLevel::Verbose,
            },
            ..AuditFsOptions::default()
        },
    };
    // The VM's stop sequence resets the virtio-fs devices, which records
    // the closes of files the guest left open, before `run` returns.
    let outcome = Vmm::new(cfg).and_then(Vmm::run);
    // Drains every accepted record (vmm.stop included), checkpoints, syncs.
    let closed = writer.close();

    let exit = match outcome {
        Ok(exit) => exit,
        Err(error) => {
            if let Err(close_error) = closed {
                eprintln!("error: cannot close the audit log: {close_error}");
            }
            return Err(error.into());
        }
    };
    eprintln!("{exit}");
    closed.context("cannot close the audit log")?;
    Ok(ExitCode::from(u8::try_from(exit.exit_code()).unwrap_or(1)))
}

/// The two shares, in slot order: the root filesystem, which only the guest
/// changes, cached freely; the workspace, which the host may edit too,
/// revalidated.
fn shares(rootfs: PathBuf, workspace: PathBuf) -> Vec<FsShareConfig> {
    vec![
        FsShareConfig {
            tag: "root".into(),
            host_dir: rootfs,
            guest_path: "/".into(),
            cache: CachePolicyKind::Always,
        },
        FsShareConfig {
            tag: "workspace".into(),
            host_dir: workspace,
            guest_path: "/workspace".into(),
            cache: CachePolicyKind::Auto,
        },
    ]
}

/// `dir`, made absolute, which must be an existing directory with a UTF-8
/// path (the passthrough takes its root as a string). The audit log
/// records the share's host path as given here.
fn share_dir(flag: &str, dir: &Path) -> anyhow::Result<PathBuf> {
    let absolute = dir
        .canonicalize()
        .with_context(|| format!("--{flag} {}", dir.display()))?;
    if !absolute.is_dir() {
        bail!("--{flag} {}: not a directory", dir.display());
    }
    if absolute.to_str().is_none() {
        bail!("--{flag} {}: the path is not valid UTF-8", dir.display());
    }
    Ok(absolute)
}

/// A fresh, empty `workspace/` in the session directory.
fn new_workspace(session_dir: &Path) -> anyhow::Result<PathBuf> {
    let dir = session_dir.join("workspace");
    fs::create_dir(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    Ok(dir)
}

/// Logs to stderr, at `warn` unless `RUST_LOG` says otherwise.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    // Fails only when a subscriber is already set, which is fine.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
