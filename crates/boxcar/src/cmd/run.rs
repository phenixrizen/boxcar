// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`: boots a microVM and records its session.

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs, io};

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use boxcar_audit::{
    AuditSink, ReconcileConfig, Reconciler, SystemClock, WriterConfig, WriterHandle,
};
use boxcar_fs::{AuditFsOptions, AuditLevel, CachePolicyKind, FsShareConfig};
use boxcar_net::{NetConfig, Policy, SessionCa};
use boxcar_proto::control::{to_line, Ready};
use boxcar_proto::guest::{SessionConfig, DEFAULT_ARGV};
use boxcar_proto::{guestcmd, SessionId};
use boxcar_vmm::devices::slots::DeviceSet;
use boxcar_vmm::devices::FS_TAGS;
use boxcar_vmm::lifecycle::SignalFd;
use boxcar_vmm::lifecycle::{block_signals, block_stop_signals, exit_code_for, AUDIT_FAILED_EXIT};
use boxcar_vmm::pty::input::{self, LocalInput};
use boxcar_vmm::pty::out::{self, OutHandle, OutWait, Target};
use boxcar_vmm::pty::{Mode, PtyHub};
use boxcar_vmm::stdin::{start_job_control, stdin_is_tty, RawModeGuard};
use boxcar_vmm::vmm::{
    cmdline_size, ConsoleOut, ControlConfig, VmConfig, VmExit, Vmm, CMDLINE_MAX_SIZE,
};
use boxcar_vsock::VsockConfig;
use tracing_subscriber::EnvFilter;

use crate::cli::{AuditLevelArg, RunArgs};
use crate::client;
use crate::cmd::{nofile, tell};

/// The exit code of a usage error, as clap's: a policy rule that does not
/// parse.
const USAGE_EXIT: u8 = 2;

/// Starts the session's audit writer, boots the VM, and waits for it to
/// stop. The exit code is the VM's (see `exit_code_for`), except that
/// a run whose audit log failed at any point, while the VM ran or while
/// the log was closed, exits [`AUDIT_FAILED_EXIT`] (3) after saying
/// `audit log failed: <why>` on stderr: the log is incomplete, whatever the
/// guest did.
pub fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    init_tracing();
    // Everything that can be refused is checked before the session exists,
    // so that a typo does not leave an empty session behind: the network
    // flags, the policy, the vsock flags, the ready descriptor, the shares,
    // where the audit log and the control socket go, and the kernel command
    // line. clap requires --rootfs unless --no-fs, so the shares are known
    // here.
    let net = net_enabled(args.rootfs.is_some(), args.net, args.no_net);
    if !net && policy_flags_given(&args) {
        tell(
            "error: network policy flags need --net: without shares (--no-fs) the VM has no \
             network, and --allow, --deny, --policy-file and --dns would go unused",
        );
        return Ok(ExitCode::from(USAGE_EXIT));
    }
    let vsock = vsock_enabled(args.rootfs.is_some(), args.vsock, args.no_vsock);
    if args.stdin && !(vsock && args.rootfs.is_some()) {
        tell(
            "error: --stdin needs the vsock device: without it (--no-vsock, or no shares) the \
             session runs on the serial console, which takes no piped input",
        );
        return Ok(ExitCode::from(USAGE_EXIT));
    }
    if !vsock && !args.vsock_allow.is_empty() {
        tell(
            "error: --vsock-allow needs --vsock: without shares (--no-fs) the VM has no vsock \
             device, and the ports would go unused",
        );
        return Ok(ExitCode::from(USAGE_EXIT));
    }
    let policy = match load_policy(&args)? {
        Ok(policy) => policy,
        Err(message) => {
            tell(&format!("error: {message}"));
            return Ok(ExitCode::from(USAGE_EXIT));
        }
    };
    let ready = args.ready_fd.map(ReadyFd::take).transpose()?;
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
    let audit_dir = match &args.audit_dir {
        Some(dir) => dir.clone(),
        None => default_audit_dir(env::var_os("XDG_DATA_HOME"), env::var_os("HOME"))
            .context("no --audit-dir, and neither XDG_DATA_HOME nor HOME is an absolute path")?,
    };
    // The default workspace, made later in the session directory, cannot
    // hold the audit directory: only the directories the user names are
    // checked.
    let named: Vec<&Path> = [rootfs.as_deref(), workspace.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let audit_dir = check_audit_dir(&audit_dir, &named)?;

    let session_id = SessionId::new();
    // A session that inspects has a CA, whose key stays in this process.
    let inspect_ca = session_ca(&policy, &session_id)?;
    let user = invoking_user();
    // clap requires --rootfs unless --no-fs.
    let has_shares = rootfs.is_some();
    let share_count = if has_shares { SHARE_COUNT } else { 0 };
    let mode = guest_mode(has_shares, vsock, user.0, user.1);
    let sensor = vsock && !args.no_sensor;
    let cmdline_extra = guest_cmdline(mode, &args.cmdline_extra, &args.command, sensor);
    // The devices the VM will have, derived as `Vmm::new` derives them.
    let devices = DeviceSet::new(share_count, net, vsock);
    check_cmdline_size(args.debug_boot, &cmdline_extra, &devices)?;
    // In vsock mode the command travels in the control channel's config.
    let mut session = session_config(
        &args.command,
        user,
        &session_id,
        has_shares,
        terminal_size(stdin_terminal_size()),
    );
    // The guest is told to trust the CA: the certificate, never the key.
    session.ca_pem = inspect_ca.as_ref().map(|ca| ca.pem().to_owned());
    if mode == GuestMode::Vsock {
        session.validate()?;
    }
    if net {
        // Every relayed connection is a host socket.
        match nofile::raise() {
            Ok(soft) => {
                if let Some(warning) = nofile::warning(soft) {
                    eprintln!("warning: {warning}");
                }
            }
            Err(error) => eprintln!("warning: cannot raise the open file limit: {error}"),
        }
    }
    let sessions_root =
        client::ensure_sessions_root().context("cannot set up the control socket's directory")?;

    // Before any thread starts, so that every thread inherits the mask and
    // the signals reach only the VMM's signalfd (and SIGWINCH only the
    // session terminal's).
    block_stop_signals().context("cannot block the stop signals")?;
    block_signals(&[libc::SIGWINCH]).context("cannot block SIGWINCH")?;
    // On a terminal: SIGTSTP and SIGCONT too, read by a thread that gives
    // the terminal back when the run is stopped (Ctrl-Z, `kill -TSTP`) and
    // takes it again when it is continued in the foreground.
    start_job_control().context("cannot start the terminal's job control")?;

    let (sink, writer) = start_audit_log(WriterConfig::new(&audit_dir, session_id.clone()))
        .with_context(|| format!("cannot start the audit log under {}", audit_dir.display()))?;
    // Outlives the writer, to ask it afterwards whether it failed.
    let audit = sink.clone();
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
        None => Vec::new(),
    };

    let state_dir = sessions_root.join(session_id.as_str());
    let relayed = mode == GuestMode::Vsock;
    let console = console_out(args.console_log, args.console_stdout, relayed, &state_dir);
    // The console's file in the state directory, which this run made.
    let mut console_log = None;
    if relayed {
        if let ConsoleOut::File(path) = &console {
            if path.starts_with(&state_dir) {
                create_console_log(&state_dir, path)?;
                eprintln!("console: {}", path.display());
                console_log = Some(path.clone());
            }
        }
    }
    // A command needs no input: the terminal stays as it is.
    let interactive = args.command.is_empty();
    // In vsock mode stdin goes to the session's terminal. A terminal is
    // read, and put in raw mode, only while this process is in its
    // foreground (a run started in the background leaves it to the shell:
    // reading it would stop the run with SIGTTIN): `attach_session` sets
    // that up, and the terminal's own job control (`start_job_control`)
    // carries it through stops and continues. A pipe or a file is
    // forwarded when there is no command, or with --stdin.
    let forward_stdin = stdin_is_tty() || interactive || args.stdin;
    let cfg = VmConfig {
        kernel: args.kernel,
        initramfs: args.initramfs,
        mem_mib: args.mem_mib,
        vcpus: args.vcpus,
        cmdline_extra,
        debug_boot: args.debug_boot,
        console,
        // In vsock mode the session's terminal takes the input, not the
        // serial console.
        stdin: interactive && !relayed,
        audit: sink,
        fs_shares,
        net: net.then(|| net_config(&args.dns)),
        policy: Arc::new(ArcSwap::from_pointee(policy)),
        vsock: vsock.then(|| vsock_config(&state_dir, &args.vsock_allow)),
        sensor,
        session,
        control: Some(ControlConfig {
            state_dir: state_dir.clone(),
            session_id: session_id.clone(),
        }),
        inspect_ca,
        fs_audit: AuditFsOptions {
            level: match args.audit_level {
                AuditLevelArg::Normal => AuditLevel::Normal,
                AuditLevelArg::Verbose => AuditLevel::Verbose,
            },
            ..AuditFsOptions::default()
        },
    };
    // The reconciler reads the log beside the VM and writes its findings
    // into it; it ends at `vmm.stop`, or when asked below.
    let reconciler = Reconciler::spawn(
        audit.clone(),
        ReconcileConfig {
            sensor_expected: sensor,
            clock: Arc::new(SystemClock),
        },
    )
    .context("cannot start the reconciler")?;
    // The VM's stop sequence resets the virtio-fs devices, which records
    // the closes of files the guest left open, before `run` returns.
    let outcome = match Vmm::new(cfg) {
        Ok(mut vmm) => {
            if let Some(path) = vmm.control_path() {
                eprintln!("control: {}", path.display());
                if let Some(ready) = ready {
                    ready.announce(path, &session_id);
                }
            }
            let mut attached = None;
            if relayed {
                match attach_session(&mut vmm, forward_stdin) {
                    Ok(local) => attached = Some(local),
                    Err(error) => {
                        // The VM was built, and its stop records vmm.stop:
                        // run it to a stop at once rather than leave the
                        // log without one.
                        tell(&format!("error: {error:#}"));
                        vmm.handle()
                            .request_stop(boxcar_vmm::vmm::StopReason::Requested);
                    }
                }
            }
            let outcome = vmm.run();
            // What the session printed last may still be on its way to a
            // slow stdout: it is written before boxcar exits, for as long as
            // stdout keeps taking it (see `finish_output`).
            if let Some(local) = attached {
                if let Some(line) = finish_output(&local) {
                    tell(&line);
                }
            }
            outcome
        }
        Err(error) => {
            // No guest ran: the empty console file and the state directory
            // made for it go, as the VMM's own files there did.
            if let Some(path) = console_log {
                let _ = fs::remove_file(path);
                let _ = fs::remove_dir(&state_dir);
            }
            Err(error)
        }
    };
    // The reconciler's last findings, then the log: drains every accepted
    // record (vmm.stop included), checkpoints, syncs.
    if !reconciler.finish(Duration::from_secs(5)) {
        tell("the reconciler did not finish in time; its last findings may be missing");
    }
    let closed = writer.close();
    // What follows is said with `tell`: the VM is stopped, and a stderr that
    // is stalled (shared with a console whose reader stopped) must not keep
    // the process from exiting.

    if let Some(failure) = audit.failure() {
        match outcome {
            // It says the same as the line below.
            Ok(VmExit::AuditFailed(_)) => {}
            Ok(exit) => tell(&exit.to_string()),
            Err(error) => tell(&format!("error: {:#}", anyhow::Error::from(error))),
        }
        tell(&format!("audit log failed: {failure}"));
        return Ok(ExitCode::from(u8::try_from(AUDIT_FAILED_EXIT).unwrap_or(1)));
    }
    let exit = match outcome {
        Ok(exit) => exit,
        Err(error) => {
            if let Err(close_error) = closed {
                tell(&format!("error: cannot close the audit log: {close_error}"));
            }
            return Err(error.into());
        }
    };
    tell(&exit.to_string());
    closed.context("cannot close the audit log")?;
    Ok(ExitCode::from(
        u8::try_from(exit_code_for(&exit)).unwrap_or(1),
    ))
}

/// The descriptor `--ready-fd` names, owned from the start.
struct ReadyFd {
    fd: i32,
    file: File,
}

impl ReadyFd {
    /// Takes `fd` over, once it is known to be open for writing and not
    /// one of boxcar's own stdin, stdout and stderr.
    fn take(fd: i32) -> anyhow::Result<ReadyFd> {
        let own = match fd {
            0 => Some("stdin"),
            1 => Some("stdout"),
            2 => Some("stderr"),
            _ => None,
        };
        if let Some(own) = own {
            bail!("--ready-fd {fd}: boxcar's own {own}");
        }
        // SAFETY: F_GETFL only reads the descriptor's status flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            bail!("--ready-fd {fd}: not open");
        }
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            bail!("--ready-fd {fd}: not open for writing");
        }
        // SAFETY: `fd` is open, and boxcar was handed it to write one line
        // to and close: this File is the only thing in the process that
        // uses it from here on.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(ReadyFd { fd, file })
    }

    /// Writes the ready line for the socket at `path` and closes the
    /// descriptor. A reader that is gone does not stop the VM.
    fn announce(mut self, path: &Path, session_id: &SessionId) {
        let ready = Ready {
            ready: true,
            control: path.display().to_string(),
            session_id: session_id.to_string(),
        };
        let written = to_line(&ready)
            .map_err(io::Error::other)
            .and_then(|line| self.file.write_all(&line));
        if let Err(error) = written {
            eprintln!("warning: cannot write to --ready-fd {}: {error}", self.fd);
        }
    }
}

/// Starts the session's audit writer.
#[cfg(not(feature = "kvm-tests"))]
fn start_audit_log(cfg: WriterConfig) -> io::Result<(AuditSink, WriterHandle)> {
    boxcar_audit::spawn(cfg)
}

/// Starts the session's audit writer, which fails on purpose when the
/// gated tests ask for it with `BOXCAR_TEST_FAIL_AUDIT_AFTER=<n>`: every
/// record is checkpointed, so every record is synced, and after `n` syncs
/// every sync fails with ENOSPC, as on a full disk. The first `n` do not
/// reach the disk: the test needs the log to fail at a known record, not
/// to be durable, and an `fdatasync` per record would leave the writer far
/// behind the guest. Only a `kvm-tests` build looks at the variable.
#[cfg(feature = "kvm-tests")]
fn start_audit_log(mut cfg: WriterConfig) -> io::Result<(AuditSink, WriterHandle)> {
    let Some(value) = env::var_os("BOXCAR_TEST_FAIL_AUDIT_AFTER") else {
        return boxcar_audit::spawn(cfg);
    };
    let ok = value.to_str().and_then(|v| v.parse().ok()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("BOXCAR_TEST_FAIL_AUDIT_AFTER={value:?} is not a number"),
        )
    })?;
    cfg.checkpoint_every = 1;
    boxcar_audit::spawn_with_syncer(cfg, fault::FailAfter::new(ok))
}

#[cfg(feature = "kvm-tests")]
mod fault {
    use std::fs::File;
    use std::io;
    use std::sync::atomic::{AtomicU64, Ordering};

    use boxcar_audit::Syncer;

    /// Succeeds, without syncing, `ok` times; then fails with ENOSPC.
    pub(super) struct FailAfter {
        ok: u64,
        calls: AtomicU64,
    }

    impl FailAfter {
        pub(super) fn new(ok: u64) -> Self {
            FailAfter {
                ok,
                calls: AtomicU64::new(0),
            }
        }
    }

    impl Syncer for FailAfter {
        fn sync(&self, _: &File) -> io::Result<()> {
            if self.calls.fetch_add(1, Ordering::Relaxed) < self.ok {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            }
        }
    }
}

/// The policy of `--policy-file`, `--deny` and `--allow` (see
/// [`build_policy`]). The outer error is a policy file that cannot be read;
/// the inner one a rule that does not parse, said as the user should see
/// it.
fn load_policy(args: &RunArgs) -> anyhow::Result<Result<Policy, String>> {
    let file = match &args.policy_file {
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("--policy-file {}", path.display()))?;
            Some((path.as_path(), text))
        }
        None => None,
    };
    let file = file.as_ref().map(|(path, text)| (*path, text.as_str()));
    Ok(build_policy(file, &args.deny, &args.allow, &args.inspect))
}

/// The session's CA when `policy` has an `inspect` line: made now, for
/// `session_id`. None when nothing is inspected: no CA, nothing for the
/// guest to trust.
fn session_ca(policy: &Policy, session_id: &SessionId) -> anyhow::Result<Option<Arc<SessionCa>>> {
    if policy.inspect.is_empty() {
        return Ok(None);
    }
    let ca = SessionCa::generate(session_id.as_str()).context("cannot make the session's CA")?;
    Ok(Some(Arc::new(ca)))
}

/// Where a line of the policy came from.
enum Source<'a> {
    File { path: &'a Path, line: usize },
    Flag { flag: &'static str, rule: &'a str },
}

/// The policy the guest's network gets: the lines of the policy file
/// (`file`, its path and its text) first, then a `deny` line for each of
/// `deny`, then an `allow` line for each of `allow`, in order; the first
/// rule that matches decides; then an `inspect` line for each of
/// `inspect`, which decide no verdict. Deny by default, unless the file
/// gives a `default`. A rule that does not parse is refused with where it
/// came from: `--policy-file PATH line N: ...` or `--allow "RULE": ...`.
fn build_policy(
    file: Option<(&Path, &str)>,
    deny: &[String],
    allow: &[String],
    inspect: &[String],
) -> Result<Policy, String> {
    let mut lines: Vec<(String, Source<'_>)> = Vec::new();
    if let Some((path, text)) = file {
        for (index, line) in text.lines().enumerate() {
            let source = Source::File {
                path,
                line: index + 1,
            };
            lines.push((line.to_owned(), source));
        }
    }
    for (verb, flag, rules) in [
        ("deny", "--deny", deny),
        ("allow", "--allow", allow),
        ("inspect", "--inspect", inspect),
    ] {
        for rule in rules {
            lines.push((format!("{verb} {rule}"), Source::Flag { flag, rule }));
        }
    }
    let texts: Vec<&str> = lines.iter().map(|(text, _)| text.as_str()).collect();
    Policy::parse(&texts).map_err(|error| {
        let source = match lines.get(error.line.wrapping_sub(1)) {
            Some((_, Source::File { path, line })) => {
                format!("--policy-file {} line {line}", path.display())
            }
            Some((_, Source::Flag { flag, rule })) => format!("{flag} {rule:?}"),
            None => "the policy".to_owned(),
        };
        format!("{source}: {}", error.kind)
    })
}

/// Whether any of the flags that set the network's policy or its DNS was
/// given: `--allow`, `--deny`, `--inspect`, `--policy-file`, `--dns`.
fn policy_flags_given(args: &RunArgs) -> bool {
    !args.allow.is_empty()
        || !args.deny.is_empty()
        || !args.inspect.is_empty()
        || args.policy_file.is_some()
        || !args.dns.is_empty()
}

/// Whether the VM gets a network card: with shares unless `--no-net`, and
/// without them only with `--net` (clap leaves at most one of the two set,
/// the last given).
fn net_enabled(shares: bool, net: bool, no_net: bool) -> bool {
    !no_net && (net || shares)
}

/// Whether the VM gets a vsock device: as the network card, with shares
/// unless `--no-vsock`, and without them only with `--vsock` (clap leaves at
/// most one of the two set, the last given).
fn vsock_enabled(shares: bool, vsock: bool, no_vsock: bool) -> bool {
    !no_vsock && (vsock || shares)
}

/// The vsock device's config: the guest at CID 3, the host socket
/// `vsock.sock` in the session's `state_dir` (which the VMM makes, mode
/// 0700, beside the control socket), and the host ports `allow` lists.
fn vsock_config(state_dir: &Path, allow: &[u32]) -> VsockConfig {
    VsockConfig {
        allow_ports: allow.to_vec(),
        ..VsockConfig::new(state_dir.join(VSOCK_SOCKET))
    }
}

/// The name of the vsock device's host socket in the state directory.
const VSOCK_SOCKET: &str = "vsock.sock";

/// The guest network's config: the fixed addressing, and DNS forwarded to
/// `dns`, or to the host's resolvers when it is empty.
fn net_config(dns: &[SocketAddr]) -> NetConfig {
    let mut cfg = NetConfig::from_host();
    if !dns.is_empty() {
        cfg.dns_upstreams = dns.to_vec();
    }
    cfg
}

/// How many shares a run with `--rootfs` gives the VM ([`shares`]), for
/// the size of its command line.
const SHARE_COUNT: usize = FS_TAGS.len();

/// The shares, one per tag of the VMM's [`FS_TAGS`], in its slot order:
/// the root filesystem, which only the guest changes, cached freely; the
/// workspace, which the host may edit too, revalidated.
fn shares(rootfs: PathBuf, workspace: PathBuf) -> Vec<FsShareConfig> {
    // Fails to compile when the VMM's shares change, so the two cannot
    // drift apart.
    let [root_tag, workspace_tag] = FS_TAGS;
    vec![
        FsShareConfig {
            tag: root_tag.into(),
            host_dir: rootfs,
            guest_path: "/".into(),
            cache: CachePolicyKind::Always,
        },
        FsShareConfig {
            tag: workspace_tag.into(),
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

/// A fresh, empty `workspace/` in the session directory, as an absolute
/// path with a UTF-8 name, like a share given by flag.
fn new_workspace(session_dir: &Path) -> anyhow::Result<PathBuf> {
    let dir = session_dir.join("workspace");
    fs::create_dir(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let dir = dir
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", dir.display()))?;
    if dir.to_str().is_none() {
        bail!("{}: the path is not valid UTF-8", dir.display());
    }
    Ok(dir)
}

/// Where audit logs go without `--audit-dir`: `$XDG_DATA_HOME/boxcar`, or
/// `$HOME/.local/share/boxcar` when `XDG_DATA_HOME` is unset, empty or
/// relative (the XDG base directory spec says to ignore a relative one).
/// `None` when `HOME` is not an absolute path either.
fn default_audit_dir(xdg_data_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |var: Option<OsString>| var.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(xdg_data_home)
        .map(|data| data.join("boxcar"))
        .or_else(|| absolute(home).map(|home| home.join(".local/share/boxcar")))
}

/// The audit directory `audit_dir` as an absolute path with every symbolic
/// link resolved, once it is known that no share of `shares` (real paths
/// already) reaches its logs: the guest writes to its shares, and must not
/// reach the log that records what it does. So the audit dir may not be
/// a share or inside one, nor may a share below it hold logs
/// ([`exposes_logs`]); one deeper in a session, such as an old session's
/// workspace, holds none and may be shared again.
fn check_audit_dir(audit_dir: &Path, shares: &[&Path]) -> anyhow::Result<PathBuf> {
    let audit =
        resolve_path(audit_dir).with_context(|| format!("--audit-dir {}", audit_dir.display()))?;
    for share in shares {
        if audit.starts_with(share) {
            bail!(
                "audit dir {} is inside share {}",
                audit.display(),
                share.display()
            );
        }
        if share.strip_prefix(&audit).is_ok_and(exposes_logs) {
            bail!(
                "share {} would expose audit logs under {}",
                share.display(),
                audit.display()
            );
        }
    }
    Ok(audit)
}

/// Whether a share at `below`, a path relative to the audit dir, holds
/// session logs: the audit dir itself, `sessions`, and each session's
/// directory hold them directly. Anything deeper in a session, or beside
/// `sessions`, holds none.
fn exposes_logs(below: &Path) -> bool {
    let parts: Vec<_> = below.components().collect();
    match parts.as_slice() {
        [] => true,
        [first, rest @ ..] => first.as_os_str() == boxcar_audit::SESSIONS_DIR && rest.len() <= 1,
    }
}

/// `path` made absolute with every symbolic link resolved, whether or not
/// it exists yet: the longest part of it that exists, canonicalized, then
/// the rest. Nothing is created. The part that does not exist may not
/// hold `..`, which cannot be resolved there.
fn resolve_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut existing = absolute.as_path();
    let mut rest = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(real) => return Ok(rest.iter().rev().fold(real, |path, name| path.join(name))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{}: .. in a directory that does not exist", path.display()),
                    ));
                };
                rest.push(name);
                existing = parent;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Refuses a kernel command line the kernel cannot take: `extra` after the
/// base, and a device entry for each slot of `devices`, measured as the VMM
/// composes it.
fn check_cmdline_size(
    debug_boot: bool,
    extra: &[String],
    devices: &DeviceSet,
) -> anyhow::Result<()> {
    let size = cmdline_size(debug_boot, extra, devices)?;
    if size > CMDLINE_MAX_SIZE {
        bail!("command line too long ({size} bytes > {CMDLINE_MAX_SIZE})");
    }
    Ok(())
}

/// How long, once the VM has stopped, boxcar waits for a stdout that takes
/// nothing more before it exits without the rest of the session's output.
const OUTPUT_IDLE: Duration = Duration::from_secs(2);

/// How long, once the VM has stopped, boxcar waits for the session's output
/// at most, however steadily stdout takes it.
const OUTPUT_CAP: Duration = Duration::from_secs(30);

/// How long the stdout writer, once the wait is over, gets to stop; and the
/// PTY hub to have read the guest's last bytes. Either takes milliseconds.
const STOP_GRACE: Duration = Duration::from_millis(500);

/// `boxcar run`'s own client of the session's terminal.
struct LocalAttach {
    hub: PtyHub,
    /// Writes the session's output to stdout.
    writer: OutHandle,
}

/// Attaches `boxcar run` to the session's terminal, in the same process,
/// before the VM runs (so it gets the session's output from the first
/// byte), as the hub's primary client, which the session waits for: the
/// output to stdout ([`out`]); with `forward_stdin`, stdin to the session
/// ([`input`]), with the terminal in raw mode when stdin is one, restored
/// by the VM's stop sequence; and when stdin is a terminal, its size to the
/// session's, now and on every `SIGWINCH`.
fn attach_session(vmm: &mut Vmm, forward_stdin: bool) -> anyhow::Result<LocalAttach> {
    let handle = vmm.handle();
    let hub = handle
        .pty()
        .context("the VM has no terminal for its session")?;
    let mode = if forward_stdin { Mode::Rw } else { Mode::Ro };
    let (_, output, typed) = hub
        .attach_primary(mode)
        .context("the session's terminal has its primary client already")?;
    let stdout = Target::stdout().context("cannot write to stdout")?;
    let writer = out::spawn(output, stdout).context("cannot write the session's output")?;
    if stdin_is_tty() {
        follow_terminal_size(&hub).context("cannot follow the terminal's size")?;
        if forward_stdin {
            // Raw now when this process is in the terminal's foreground
            // (`enter`'s own look, not an earlier one); otherwise the
            // terminal stays the shell's until `fg` brings the run there.
            if let Some(guard) = RawModeGuard::enter_when_foreground()
                .context("cannot put the terminal in raw mode")?
            {
                vmm.restore_terminal_on_stop(guard);
            }
        }
    }
    if let Some(typed) = typed {
        // Reads the terminal only from the foreground, and waits in the
        // background (see `input`).
        let stdin = LocalInput::stdin().context("cannot read stdin")?;
        input::forward(stdin, typed, handle).context("cannot send stdin to the session")?;
    }
    Ok(LocalAttach { hub, writer })
}

/// Gives the session's terminal stdin's size now (the hub sends it once the
/// session's terminal opens, unless that is its size already) and on every
/// `SIGWINCH` (blocked since the start of the run, and read from a
/// signalfd of its own on a thread of its own).
fn follow_terminal_size(hub: &PtyHub) -> io::Result<()> {
    let resize = |hub: &PtyHub| {
        if let Some((rows, cols)) = stdin_terminal_size() {
            // A size init cannot be told now is sent with the next change.
            let _ = hub.resize(rows, cols);
        }
    };
    resize(hub);
    let winch = SignalFd::with(&[libc::SIGWINCH])?;
    let hub = hub.clone();
    std::thread::Builder::new()
        .name("winch".into())
        .spawn(move || loop {
            let mut pollfd = libc::pollfd {
                fd: std::os::fd::AsRawFd::as_raw_fd(&winch),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll reads and writes the one pollfd it is given.
            if unsafe { libc::poll(&mut pollfd, 1, -1) } < 0
                && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                return;
            }
            let mut changed = false;
            loop {
                match winch.read() {
                    Ok(Some(_)) => changed = true,
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            if changed {
                resize(&hub);
            }
        })?;
    Ok(())
}

/// Waits, once the VM has stopped, for the session's output to be written
/// to stdout: while stdout keeps taking bytes ([`OUTPUT_IDLE`]), for at
/// most [`OUTPUT_CAP`], and not past another stop signal (`SIGINT`,
/// `SIGTERM`, `SIGHUP`, `SIGQUIT`, still blocked and now read from a
/// signalfd of its own). Then stops the writer and counts what stdout did
/// not get, exactly: the writer has stopped, and the hub read the guest's
/// last bytes. Returns the line to say when output was left behind.
fn finish_output(local: &LocalAttach) -> Option<String> {
    let signals = SignalFd::new().ok();
    let ended = local.writer.wait_with(OUTPUT_IDLE, OUTPUT_CAP, || {
        signals
            .as_ref()
            .is_some_and(|signals| matches!(signals.read(), Ok(Some(_))))
    });
    local.writer.stop(STOP_GRACE);
    local.hub.wait_ended(STOP_GRACE);
    undelivered_line(ended, local.writer.undelivered())
}

/// The line `boxcar run` says when the wait for stdout ended (`ended`) with
/// `bytes` of the session's output not written: none when it is all out,
/// or when stdout's reader is gone.
fn undelivered_line(ended: OutWait, bytes: u64) -> Option<String> {
    let why = match ended {
        OutWait::Done | OutWait::Failed => return None,
        OutWait::Stalled => "stdout stalled",
        OutWait::Capped => "stdout still not done after 30 s",
        OutWait::Stopped => "stopped by a signal",
    };
    if bytes == 0 {
        return None;
    }
    Some(format!(
        "boxcar: {bytes} bytes of session output not delivered: {why}"
    ))
}

/// The name of the serial console's file in the state directory, in vsock
/// mode.
const CONSOLE_LOG: &str = "console.log";

/// Where the serial console goes: `--console-log` when given; else, in
/// vsock mode (`relayed`), where stdout carries the session's terminal,
/// `console.log` in the state directory, unless `--console-stdout`; else
/// (M1's console session) stdout.
fn console_out(
    console_log: Option<PathBuf>,
    console_stdout: bool,
    relayed: bool,
    state_dir: &Path,
) -> ConsoleOut {
    match console_log {
        Some(path) => ConsoleOut::File(path),
        None if relayed && !console_stdout => ConsoleOut::File(state_dir.join(CONSOLE_LOG)),
        None => ConsoleOut::Stdio,
    }
}

/// Creates the state directory (mode 0700, if it is not there yet) and the
/// console's file `path` in it, mode 0600, before the VMM opens it: the
/// VMM would create it with the process's umask.
fn create_console_log(state_dir: &Path, path: &Path) -> anyhow::Result<()> {
    match DirBuilder::new().mode(0o700).create(state_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("cannot create {}", state_dir.display())),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    Ok(())
}

/// The size of the terminal on stdin (`TIOCGWINSZ`), rows then columns,
/// when stdin is a terminal that has one (neither side 0).
pub(crate) fn stdin_terminal_size() -> Option<(u16, u16)> {
    if !boxcar_vmm::stdin::stdin_is_tty() {
        return None;
    }
    // SAFETY: winsize is plain data; all zeroes is valid.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ stores one winsize through its argument, which
    // points at `size`, alive for the call.
    let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) };
    (rc == 0 && size.ws_row > 0 && size.ws_col > 0).then_some((size.ws_row, size.ws_col))
}

/// The session's terminal size: the host's, when it has one with neither
/// side 0, else 24 by 80.
fn terminal_size(host: Option<(u16, u16)>) -> (u16, u16) {
    match host {
        Some((rows, cols)) if rows > 0 && cols > 0 => (rows, cols),
        _ => (24, 80),
    }
}

/// The session the guest control channel sends init in vsock mode: the
/// command (`-- CMD`, or a login shell) as the invoking `user`, with the
/// default environment ([`SessionConfig::for_user`]) and
/// `BOXCAR_SESSION_ID`; in `/workspace` when the workspace share is there
/// (`shares`), else `/`; on a terminal of `size`.
fn session_config(
    command: &[String],
    user: (u32, u32),
    session_id: &SessionId,
    shares: bool,
    size: (u16, u16),
) -> SessionConfig {
    let argv = if command.is_empty() {
        DEFAULT_ARGV.map(str::to_owned).to_vec()
    } else {
        command.to_vec()
    };
    let mut cfg = SessionConfig::for_user(argv, user.0, user.1);
    cfg.env
        .push(("BOXCAR_SESSION_ID".to_owned(), session_id.to_string()));
    if !shares {
        "/".clone_into(&mut cfg.cwd);
    }
    (cfg.rows, cfg.cols) = size;
    cfg
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

/// What the guest init is told to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestMode {
    /// Mount the shares, get the session from the guest control channel,
    /// and run it on a terminal of its own relayed over vsock.
    Vsock,
    /// Mount the shares and run the session on the serial console as this
    /// user and group (M1's, with `--no-vsock`).
    Console { uid: u32, gid: u32 },
    /// Print a marker and reboot: a boot without shares has nothing to run.
    Hello,
}

/// The mode of a VM with `shares` and the `vsock` device, whose session
/// runs as `uid` and `gid`.
fn guest_mode(shares: bool, vsock: bool, uid: u32, gid: u32) -> GuestMode {
    match (shares, vsock) {
        (true, true) => GuestMode::Vsock,
        (true, false) => GuestMode::Console { uid, gid },
        (false, _) => GuestMode::Hello,
    }
}

/// The `boxcar.*` keys for `mode` (in vsock mode, `boxcar.sensor=0` when the
/// sensor is off), then `extra` (`--cmdline-extra`), in order, then, in
/// console mode, `command` (`-- CMD`), if any, as `boxcar.cmd`. The user's
/// values come after boxcar's so they win: init keeps the last of a repeated
/// key. In vsock mode the command, the user and the rest travel in the
/// control channel's config instead.
fn guest_cmdline(
    mode: GuestMode,
    extra: &[String],
    command: &[String],
    sensor: bool,
) -> Vec<String> {
    let mut cmdline = match mode {
        GuestMode::Vsock if !sensor => {
            vec!["boxcar.mode=vsock".to_owned(), "boxcar.sensor=0".to_owned()]
        }
        GuestMode::Vsock => vec!["boxcar.mode=vsock".to_owned()],
        GuestMode::Console { uid, gid } => vec![
            "boxcar.mode=console".to_owned(),
            format!("boxcar.uid={uid}"),
            format!("boxcar.gid={gid}"),
        ],
        GuestMode::Hello => vec!["boxcar.mode=hello".to_owned()],
    };
    cmdline.extend_from_slice(extra);
    if !command.is_empty() && matches!(mode, GuestMode::Console { .. }) {
        cmdline.push(format!("boxcar.cmd={}", guestcmd::encode(command)));
    }
    cmdline
}

/// The invoking user's real uid and gid, which the guest session runs as:
/// the host-side filesystem acts as this user, so files the session creates
/// belong to it on both sides.
fn invoking_user() -> (u32, u32) {
    // SAFETY: getuid and getgid take no arguments, touch no memory and
    // cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&a| a.to_owned()).collect()
    }

    #[test]
    fn no_sensor_puts_the_key_on_the_command_line_in_vsock_mode_only() {
        assert_eq!(
            guest_cmdline(GuestMode::Vsock, &[], &[], false),
            ["boxcar.mode=vsock", "boxcar.sensor=0"]
        );
        assert_eq!(
            guest_cmdline(GuestMode::Vsock, &[], &[], true),
            ["boxcar.mode=vsock"]
        );
        // Without the vsock device there is no sensor to turn off.
        let console = GuestMode::Console { uid: 1, gid: 2 };
        assert_eq!(
            guest_cmdline(console, &[], &[], false),
            ["boxcar.mode=console", "boxcar.uid=1", "boxcar.gid=2"]
        );
    }

    #[test]
    fn shares_run_the_console_init_as_the_invoking_user() {
        let mode = GuestMode::Console {
            uid: 1000,
            gid: 1001,
        };
        assert_eq!(
            guest_cmdline(mode, &[], &[], true),
            ["boxcar.mode=console", "boxcar.uid=1000", "boxcar.gid=1001"]
        );
    }

    #[test]
    fn the_extras_follow_so_they_can_override() {
        let mode = GuestMode::Console { uid: 0, gid: 0 };
        let extra = strings(&["boxcar.mode=hello", "loglevel=7"]);
        assert_eq!(
            guest_cmdline(mode, &extra, &[], true),
            [
                "boxcar.mode=console",
                "boxcar.uid=0",
                "boxcar.gid=0",
                "boxcar.mode=hello",
                "loglevel=7"
            ]
        );
    }

    #[test]
    fn no_shares_boot_the_hello_init() {
        let extra = strings(&["panic=0"]);
        assert_eq!(
            guest_cmdline(GuestMode::Hello, &extra, &[], true),
            ["boxcar.mode=hello", "panic=0"]
        );
    }

    const CONSOLE: GuestMode = GuestMode::Console {
        uid: 1000,
        gid: 1000,
    };

    /// `boxcar run -- CMD ARGS`: the argv travels last, after the extras,
    /// as a `boxcar.cmd` value the guest init decodes back.
    #[test]
    fn the_command_goes_last_as_boxcar_cmd() {
        let command = strings(&["/bin/sh", "-c", "echo \"a b\" > /workspace/out.txt"]);
        let extra = strings(&["loglevel=7"]);
        let cmdline = guest_cmdline(CONSOLE, &extra, &command, true);
        assert_eq!(
            cmdline[..4],
            [
                "boxcar.mode=console",
                "boxcar.uid=1000",
                "boxcar.gid=1000",
                "loglevel=7"
            ]
        );
        assert_eq!(cmdline.len(), 5);
        let value = cmdline[4].strip_prefix("boxcar.cmd=").unwrap();
        assert_eq!(guestcmd::decode(value).unwrap(), command);
    }

    /// With a vsock device the guest runs the vsock init: the command, the
    /// user and the rest travel in the control channel's config, so the
    /// command line says only the mode; the extras still follow it.
    #[test]
    fn with_vsock_the_command_line_says_only_the_mode() {
        let command = strings(&["/bin/sh", "-c", "exit 7"]);
        assert_eq!(
            guest_cmdline(GuestMode::Vsock, &[], &command, true),
            ["boxcar.mode=vsock"]
        );
        assert_eq!(
            guest_cmdline(GuestMode::Vsock, &strings(&["loglevel=7"]), &[], true),
            ["boxcar.mode=vsock", "loglevel=7"]
        );
    }

    /// The mode follows the devices: vsock with shares and the vsock
    /// device, M1's console with shares alone (`--no-vsock`), hello
    /// without shares.
    #[test]
    fn the_guest_mode_follows_the_devices() {
        assert_eq!(guest_mode(true, true, 1000, 1001), GuestMode::Vsock);
        assert_eq!(
            guest_mode(true, false, 1000, 1001),
            GuestMode::Console {
                uid: 1000,
                gid: 1001
            }
        );
        assert_eq!(guest_mode(false, true, 1000, 1001), GuestMode::Hello);
        assert_eq!(guest_mode(false, false, 1000, 1001), GuestMode::Hello);
    }

    #[test]
    fn the_session_config_of_a_run() {
        let id: SessionId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse().unwrap();
        let command = strings(&["/bin/sh", "-c", "exit 7"]);
        let cfg = session_config(&command, (1000, 1001), &id, true, (30, 100));
        assert_eq!(cfg.argv, command);
        assert_eq!((cfg.uid, cfg.gid), (1000, 1001));
        assert_eq!(cfg.cwd, "/workspace");
        assert_eq!(cfg.hostname, "boxcar");
        assert_eq!(cfg.term, "xterm-256color");
        assert_eq!((cfg.rows, cfg.cols), (30, 100));
        assert!(cfg.sysctls.is_empty());
        let env: Vec<String> = cfg.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        assert_eq!(
            env,
            [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/workspace",
                "TERM=xterm-256color",
                "LANG=C.UTF-8",
                "BOXCAR_SESSION_ID=017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            ]
        );

        // No command: a login shell. Root's home is /root; without the
        // workspace share the session starts in /.
        let cfg = session_config(&[], (0, 0), &id, false, (24, 80));
        assert_eq!(cfg.argv, ["/bin/sh", "-l"]);
        assert!(cfg.env.contains(&("HOME".to_owned(), "/root".to_owned())));
        assert_eq!(cfg.cwd, "/");
    }

    /// What is said when the wait for stdout leaves output behind: one line
    /// with the count and why; nothing when it is all out.
    #[test]
    fn output_left_behind_is_said_with_its_count() {
        assert_eq!(undelivered_line(OutWait::Done, 0), None);
        assert_eq!(
            undelivered_line(OutWait::Stalled, 113_000).as_deref(),
            Some("boxcar: 113000 bytes of session output not delivered: stdout stalled")
        );
        assert_eq!(
            undelivered_line(OutWait::Capped, 5).as_deref(),
            Some(
                "boxcar: 5 bytes of session output not delivered: stdout still not done after 30 s"
            )
        );
        assert_eq!(
            undelivered_line(OutWait::Stopped, 7).as_deref(),
            Some("boxcar: 7 bytes of session output not delivered: stopped by a signal")
        );
        // Stdout's reader is gone: nothing to say, as before.
        assert_eq!(undelivered_line(OutWait::Failed, 9), None);
        // Given up with nothing left (it finished meanwhile): nothing to say.
        assert_eq!(undelivered_line(OutWait::Stalled, 0), None);
        assert_eq!(OUTPUT_CAP, Duration::from_secs(30));
        assert_eq!(OUTPUT_IDLE, Duration::from_secs(2));
    }

    #[test]
    fn the_terminal_size_is_the_hosts_or_24_by_80() {
        assert_eq!(terminal_size(None), (24, 80));
        assert_eq!(terminal_size(Some((0, 0))), (24, 80));
        assert_eq!(terminal_size(Some((50, 0))), (24, 80));
        assert_eq!(terminal_size(Some((50, 132))), (50, 132));
    }

    /// With a vsock device, stdout carries the session and the serial
    /// console goes to the state directory, unless asked otherwise; without
    /// one, M1's console on stdout.
    #[test]
    fn the_console_goes_to_the_state_directory_with_vsock() {
        let state = Path::new("/run/user/1000/boxcar/s1");
        assert_eq!(
            console_out(None, false, true, state),
            ConsoleOut::File(state.join("console.log"))
        );
        assert_eq!(console_out(None, true, true, state), ConsoleOut::Stdio);
        let log = PathBuf::from("/tmp/c.log");
        assert_eq!(
            console_out(Some(log.clone()), false, true, state),
            ConsoleOut::File(log.clone())
        );
        assert_eq!(console_out(None, false, false, state), ConsoleOut::Stdio);
        assert_eq!(
            console_out(Some(log.clone()), false, false, state),
            ConsoleOut::File(log)
        );
    }

    /// The devices of a run with `--rootfs`: the shares and the network.
    fn devices() -> DeviceSet {
        DeviceSet::new(SHARE_COUNT, true, false)
    }

    /// Size of the command line the VM would get, from the VMM itself.
    fn size(extra: &[String]) -> usize {
        boxcar_vmm::vmm::cmdline_size(false, extra, &devices()).unwrap()
    }

    #[test]
    fn a_command_line_up_to_the_limit_is_accepted_and_one_byte_more_is_not() {
        let command = strings(&["/bin/sh", "-c", "exit 7"]);
        let with_filler = |len: usize| {
            let extra = vec!["f".repeat(len)];
            guest_cmdline(CONSOLE, &extra, &command, true)
        };
        // The filler that makes the command line exactly 2048 bytes, NUL
        // terminator included.
        let fits = 2048 - (size(&with_filler(1)) - 1);
        assert_eq!(size(&with_filler(fits)), 2048);
        check_cmdline_size(false, &with_filler(fits), &devices()).unwrap();

        let error = check_cmdline_size(false, &with_filler(fits + 1), &devices()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "command line too long (2049 bytes > 2048)"
        );
    }

    #[test]
    fn a_long_command_is_refused_with_the_size_it_would_have() {
        let command = strings(&["/bin/sh", "-c", &"echo x; ".repeat(300)]);
        let cmdline = guest_cmdline(CONSOLE, &[], &command, true);
        let error = check_cmdline_size(false, &cmdline, &devices()).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("command line too long ({} bytes > 2048)", size(&cmdline))
        );
        // The shares' virtio_mmio.device= entries count: without them the
        // same command may fit.
        assert!(size(&cmdline) > 2048);
    }

    use boxcar_net::Verdict;

    /// The flags' policy with no `--inspect`: what the tests below built
    /// before inspect lines existed.
    fn build_policy(
        file: Option<(&Path, &str)>,
        deny: &[String],
        allow: &[String],
    ) -> Result<Policy, String> {
        super::build_policy(file, deny, allow, &[])
    }

    /// `--inspect` lines come last, in order, in their own list, and a
    /// session with one gets a CA whose certificate the guest is told to
    /// trust.
    #[test]
    fn inspect_rules_reach_the_policy_and_make_a_ca() {
        let file = "allow api.example.com:443\ninspect api.example.com:443\n";
        let policy = super::build_policy(
            Some((Path::new("p"), file)),
            &[],
            &strings(&["example.com"]),
            &strings(&["127.0.0.1:8443", "*.model.example"]),
        )
        .unwrap();
        let texts: Vec<&str> = policy.inspect.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "inspect api.example.com:443",
                "inspect 127.0.0.1:8443",
                "inspect *.model.example",
            ]
        );
        assert_eq!(policy.rules.len(), 2);
        let error = super::build_policy(None, &[], &[], &strings(&["exa_mple.com"])).unwrap_err();
        assert!(error.starts_with("--inspect \"exa_mple.com\": "), "{error}");

        let id: SessionId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse().unwrap();
        let ca = session_ca(&policy, &id).unwrap().expect("a CA");
        assert!(ca.pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!ca.pem().contains("PRIVATE KEY"));
        assert_eq!(ca.fingerprint_sha256().len(), 64);
    }

    #[test]
    fn no_inspect_means_no_ca() {
        let id: SessionId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse().unwrap();
        let policy = build_policy(None, &[], &strings(&["example.com"])).unwrap();
        assert!(policy.inspect.is_empty());
        assert!(session_ca(&policy, &id).unwrap().is_none());
    }

    /// The policy is the file's lines, then each `--deny`, then each
    /// `--allow`, in the order given; deny by default unless the file says
    /// otherwise.
    #[test]
    fn the_policy_is_the_file_then_the_denies_then_the_allows() {
        let file = "# the team's rules\nallow api.example.com:443\n\ndeny *.ads.example\n";
        let policy = build_policy(
            Some((Path::new("team.policy"), file)),
            &strings(&["203.0.113.0/24", "tracker.example"]),
            &strings(&["example.com", "192.0.2.10:22"]),
        )
        .unwrap();
        let texts: Vec<&str> = policy.rules.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "allow api.example.com:443",
                "deny *.ads.example",
                "deny 203.0.113.0/24",
                "deny tracker.example",
                "allow example.com",
                "allow 192.0.2.10:22",
            ]
        );
        assert_eq!(policy.default, Verdict::Deny);

        // A deny flag comes before an allow flag for the same name.
        let both =
            build_policy(None, &strings(&["example.com"]), &strings(&["example.com"])).unwrap();
        assert_eq!(both.dns("example.com"), Verdict::Deny);

        // The file may set the default; the flags cannot.
        let open = build_policy(Some((Path::new("p"), "default allow\n")), &[], &[]).unwrap();
        assert_eq!(open.default, Verdict::Allow);
        assert_eq!(build_policy(None, &[], &[]).unwrap(), Policy::default());
    }

    /// A rule that does not parse is named by where it came from: the
    /// file and its line, or the flag and its value.
    #[test]
    fn a_bad_rule_is_named_by_its_source() {
        let file = "allow a.example\n\nfrobnicate x\n";
        let error =
            build_policy(Some((Path::new("/etc/team.policy"), file)), &[], &[]).unwrap_err();
        assert_eq!(
            error,
            "--policy-file /etc/team.policy line 3: \"frobnicate\" is not a rule; a rule \
             starts with allow, deny, inspect or default"
        );
        let error = build_policy(
            Some((Path::new("p"), "allow a.example\n")),
            &strings(&["b.example"]),
            &strings(&["c.example", "d.example:99999"]),
        )
        .unwrap_err();
        assert_eq!(
            error,
            "--allow \"d.example:99999\": \"99999\" is not a port from 1 to 65535"
        );
        let error = build_policy(None, &strings(&["two words"]), &[]).unwrap_err();
        assert!(
            error.starts_with("--deny \"two words\": deny takes one target"),
            "{error}"
        );
        // A default only the file may give, and only once.
        let error = build_policy(
            Some((Path::new("p"), "default deny\ndefault allow\n")),
            &[],
            &[],
        )
        .unwrap_err();
        assert_eq!(error, "--policy-file p line 2: default is given twice");
    }

    #[test]
    fn vsock_is_on_with_the_shares_unless_asked_otherwise() {
        assert!(vsock_enabled(true, false, false));
        assert!(!vsock_enabled(false, false, false), "--no-fs");
        assert!(vsock_enabled(false, true, false), "--no-fs --vsock");
        assert!(!vsock_enabled(true, false, true), "--no-vsock");
    }

    /// The vsock socket is in the session's state directory, beside the
    /// control socket, and the allowlist is the flags'.
    #[test]
    fn the_vsock_config_is_in_the_state_directory() {
        let cfg = vsock_config(Path::new("/run/user/1000/boxcar/s1"), &[5000, 6000]);
        assert_eq!(cfg.guest_cid, 3);
        assert_eq!(
            cfg.uds_path,
            Path::new("/run/user/1000/boxcar/s1/vsock.sock")
        );
        assert_eq!(cfg.allow_ports, [5000, 6000]);
    }

    #[test]
    fn the_network_is_on_with_the_shares_unless_asked_otherwise() {
        // (shares, --net, --no-net)
        assert!(net_enabled(true, false, false));
        assert!(!net_enabled(false, false, false), "--no-fs");
        assert!(net_enabled(false, true, false), "--no-fs --net");
        assert!(!net_enabled(true, false, true), "--no-net");
    }

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn the_audit_dir_defaults_to_the_xdg_data_home() {
        assert_eq!(
            default_audit_dir(os("/data"), os("/home/u")),
            Some(PathBuf::from("/data/boxcar"))
        );
        // Unset, empty or relative (which the XDG spec says to ignore):
        // under the home directory.
        for xdg in [None, os(""), os("relative/data")] {
            assert_eq!(
                default_audit_dir(xdg.clone(), os("/home/u")),
                Some(PathBuf::from("/home/u/.local/share/boxcar")),
                "{xdg:?}"
            );
        }
        for home in [None, os(""), os("home")] {
            assert_eq!(default_audit_dir(None, home.clone()), None, "{home:?}");
        }
    }

    /// A scratch tree: `root/` and `workspace/` shares side by side.
    struct Tree {
        dir: tempfile::TempDir,
    }

    impl Tree {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for share in ["root", "workspace"] {
                fs::create_dir(dir.path().join(share)).unwrap();
            }
            Tree { dir }
        }

        /// The canonical path of `rel` under the tree.
        fn at(&self, rel: &str) -> PathBuf {
            self.dir.path().canonicalize().unwrap().join(rel)
        }

        /// `check_audit_dir` for the audit dir `audit` and both shares.
        fn check(&self, audit: &Path) -> anyhow::Result<PathBuf> {
            check_audit_dir(audit, &[&self.at("root"), &self.at("workspace")])
        }
    }

    #[test]
    fn an_audit_dir_beside_the_shares_is_fine() {
        let tree = Tree::new();
        // `root-audit` starts like `root` without being inside it.
        for audit in ["audit", "root-audit", "a/b/c"] {
            assert_eq!(
                tree.check(&tree.at(audit)).unwrap(),
                tree.at(audit),
                "{audit}"
            );
        }
    }

    #[test]
    fn an_audit_dir_inside_a_share_is_refused_even_before_it_exists() {
        let tree = Tree::new();
        fs::create_dir(tree.at("root/logs")).unwrap();
        for audit in ["root", "root/logs", "root/new/deeper", "workspace/audit"] {
            let error = tree.check(&tree.at(audit)).unwrap_err();
            let share = if audit.starts_with("root") {
                "root"
            } else {
                "workspace"
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "audit dir {} is inside share {}",
                    tree.at(audit).display(),
                    tree.at(share).display()
                )
            );
        }
        assert!(!tree.at("root/new").exists(), "nothing was created");
    }

    /// A share below the audit dir holds no log, and an old session's
    /// workspace is one: it may be shared again.
    #[test]
    fn a_workspace_under_an_old_session_is_accepted() {
        let tree = Tree::new();
        let old = tree.at("audit/sessions/01a0f42e-4fdf-74e9-95de-4e59c0ac45eb/workspace");
        fs::create_dir_all(&old).unwrap();
        assert_eq!(
            check_audit_dir(&tree.at("audit"), &[&tree.at("root"), &old]).unwrap(),
            tree.at("audit")
        );
    }

    /// `check_audit_dir` of `<tree>/audit` with the one share `rel` under
    /// it.
    fn check_under_audit(tree: &Tree, rel: &str) -> anyhow::Result<PathBuf> {
        let share = tree.at("audit").join(rel);
        check_audit_dir(&tree.at("audit"), &[&share])
    }

    fn exposes(tree: &Tree, rel: &str) -> String {
        format!(
            "share {} would expose audit logs under {}",
            tree.at("audit").join(rel).display(),
            tree.at("audit").display()
        )
    }

    /// The audit dir itself, `sessions` and a session's directory hold the
    /// logs directly: none of them may be a share, whether the session is
    /// there yet or not.
    #[test]
    fn a_share_holding_audit_logs_is_refused() {
        let tree = Tree::new();
        let id = "01a0f42e-4fdf-74e9-95de-4e59c0ac45eb";
        fs::create_dir_all(tree.at("audit/sessions").join(id)).unwrap();
        let error = check_under_audit(&tree, "").unwrap_err();
        assert!(
            error.to_string().starts_with("audit dir "),
            "the audit dir as a share is inside it: {error}"
        );
        for rel in [
            "sessions".to_owned(),
            format!("sessions/{id}"),
            "sessions/01a0f42e-0000-7000-8000-000000000000".to_owned(),
        ] {
            let error = check_under_audit(&tree, &rel).unwrap_err();
            assert_eq!(error.to_string(), exposes(&tree, &rel), "{rel}");
        }
    }

    /// Below a session's directory, or beside `sessions`, there are no logs.
    #[test]
    fn a_share_deeper_in_a_session_or_beside_sessions_is_accepted() {
        let tree = Tree::new();
        for rel in [
            "sessions/01a0f42e-4fdf-74e9-95de-4e59c0ac45eb/workspace",
            "sessions/01a0f42e-4fdf-74e9-95de-4e59c0ac45eb/workspace/src/deep",
            "other",
            "sessions-old",
            "other/sessions/x",
        ] {
            assert_eq!(
                check_under_audit(&tree, rel).unwrap(),
                tree.at("audit"),
                "{rel}"
            );
        }
    }

    /// The audit dir is resolved before the comparison in this direction
    /// too: named through a link or with `..`, it still may not be shared.
    #[test]
    fn a_share_exposing_logs_is_found_through_links_and_dot_dots() {
        let tree = Tree::new();
        fs::create_dir_all(tree.at("audit/sessions")).unwrap();
        std::os::unix::fs::symlink(tree.at("audit"), tree.at("audit-link")).unwrap();
        let sessions = tree.at("audit/sessions");
        for audit in [tree.at("audit-link"), tree.at("root/../audit")] {
            let error = check_audit_dir(&audit, &[&sessions]).unwrap_err();
            assert_eq!(
                error.to_string(),
                exposes(&tree, "sessions"),
                "{}",
                audit.display()
            );
        }
    }

    /// The layout the rule protects is the writer's own: a session's logs go
    /// in `<audit>/sessions/<id>/`.
    #[test]
    fn the_writer_keeps_each_session_where_no_share_may_be() {
        let tree = Tree::new();
        let audit = tree.at("audit");
        let (_sink, writer) =
            boxcar_audit::spawn(WriterConfig::new(&audit, SessionId::new())).unwrap();
        let session_dir = writer.session_dir().to_path_buf();
        writer.close().unwrap();
        let rel = session_dir.strip_prefix(&audit).unwrap();
        assert!(exposes_logs(rel), "{}", rel.display());
        assert!(exposes_logs(rel.parent().unwrap()), "{}", rel.display());
        assert!(!exposes_logs(&rel.join("workspace")));
    }

    /// The shares `boxcar run` counts for the command line are the shares it
    /// gives the VM: the VMM's tags, in its slot order.
    #[test]
    fn the_shares_are_the_vmm_s_tags_in_slot_order() {
        let shares = shares(PathBuf::from("/r"), PathBuf::from("/w"));
        let tags: Vec<&str> = shares.iter().map(|share| share.tag.as_str()).collect();
        assert_eq!(tags, FS_TAGS);
        assert_eq!(shares.len(), SHARE_COUNT);
    }

    /// The comparison is between real paths: a symbolic link into a share,
    /// or `..` out of one, does not hide the audit dir's place.
    #[test]
    fn links_and_dot_dots_are_resolved_before_the_comparison() {
        let tree = Tree::new();
        std::os::unix::fs::symlink(tree.at("root"), tree.at("link")).unwrap();
        let error = tree.check(&tree.at("link/audit")).unwrap_err();
        assert!(
            error.to_string().starts_with(&format!(
                "audit dir {} is inside share",
                tree.at("root/audit").display()
            )),
            "{error}"
        );
        let out = tree.at("root/../audit");
        assert_eq!(tree.check(&out).unwrap(), tree.at("audit"));
    }

    #[test]
    fn a_relative_audit_dir_is_made_absolute() {
        let resolved = resolve_path(Path::new("no-such-dir/sub")).unwrap();
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert!(
            resolved.ends_with("no-such-dir/sub"),
            "{}",
            resolved.display()
        );
    }

    #[test]
    fn a_dot_dot_in_a_directory_that_does_not_exist_is_refused() {
        let tree = Tree::new();
        assert!(resolve_path(&tree.at("missing/../audit")).is_err());
    }

    #[test]
    fn the_default_workspace_is_created_absolute_in_the_session_dir() {
        let tree = Tree::new();
        let workspace = new_workspace(&tree.at("workspace/../root")).unwrap();
        assert_eq!(workspace, tree.at("root/workspace"));
        assert!(workspace.is_dir());
    }
}
