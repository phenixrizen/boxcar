// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`: boots a microVM and records its session.

use std::process::ExitCode;

use anyhow::{bail, Context};
use boxcar_audit::WriterConfig;
use boxcar_proto::SessionId;
use boxcar_vmm::lifecycle::block_stop_signals;
use boxcar_vmm::vmm::{ConsoleOut, VmConfig, Vmm};
use tracing_subscriber::EnvFilter;

use crate::cli::RunArgs;

/// Starts the session's audit writer, boots the VM, and waits for it to
/// stop. The exit code is the VM's (see `VmExit::exit_code`).
pub fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    init_tracing();
    if !args.no_fs {
        bail!("--no-fs is required: this build cannot share filesystems with the guest yet");
    }
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
    };
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

/// Logs to stderr, at `warn` unless `RUST_LOG` says otherwise.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    // Fails only when a subscriber is already set, which is fine.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
