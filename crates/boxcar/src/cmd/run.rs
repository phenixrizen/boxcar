// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`: boots a microVM and records its session.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs, io};

use anyhow::{bail, Context};
use boxcar_audit::{AuditSink, WriterConfig, WriterHandle};
use boxcar_fs::{AuditFsOptions, AuditLevel, CachePolicyKind, FsShareConfig};
use boxcar_proto::{guestcmd, SessionId};
use boxcar_vmm::devices::slots::DeviceSet;
use boxcar_vmm::devices::FS_TAGS;
use boxcar_vmm::lifecycle::{block_stop_signals, exit_code_for, AUDIT_FAILED_EXIT};
use boxcar_vmm::vmm::{cmdline_size, ConsoleOut, VmConfig, VmExit, Vmm, CMDLINE_MAX_SIZE};
use tracing_subscriber::EnvFilter;

use crate::cli::{AuditLevelArg, RunArgs};

/// Starts the session's audit writer, boots the VM, and waits for it to
/// stop. The exit code is the VM's (see `exit_code_for`), except that
/// a run whose audit log failed at any point, while the VM ran or while
/// the log was closed, exits [`AUDIT_FAILED_EXIT`] (3) after saying
/// `audit log failed: <why>` on stderr: the log is incomplete, whatever the
/// guest did.
pub fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    init_tracing();
    // Everything that can be refused is checked before the session exists,
    // so that a typo does not leave an empty session behind: the shares,
    // where the audit log goes, and the kernel command line.
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

    let (mode, share_count) = match &rootfs {
        Some(_) => {
            let (uid, gid) = invoking_user();
            (GuestMode::Console { uid, gid }, SHARE_COUNT)
        }
        // clap requires --rootfs unless --no-fs.
        None => (GuestMode::Hello, 0),
    };
    let cmdline_extra = guest_cmdline(mode, &args.cmdline_extra, &args.command);
    // The devices the VM will have, derived as `Vmm::new` derives them.
    let devices = DeviceSet::from_shares(share_count);
    check_cmdline_size(args.debug_boot, &cmdline_extra, &devices)?;

    // Before any thread starts, so that every thread inherits the mask and
    // the signals reach only the VMM's signalfd.
    block_stop_signals().context("cannot block the stop signals")?;

    let session_id = SessionId::new();
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

    let cfg = VmConfig {
        kernel: args.kernel,
        initramfs: args.initramfs,
        mem_mib: args.mem_mib,
        vcpus: args.vcpus,
        cmdline_extra,
        debug_boot: args.debug_boot,
        console: match args.console_log {
            Some(path) => ConsoleOut::File(path),
            None => ConsoleOut::Stdio,
        },
        // A command needs no input: the terminal stays as it is.
        stdin: args.command.is_empty(),
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

    if let Some(failure) = audit.failure() {
        match outcome {
            // It says the same as the line below.
            Ok(VmExit::AuditFailed(_)) => {}
            Ok(exit) => eprintln!("{exit}"),
            Err(error) => eprintln!("error: {:#}", anyhow::Error::from(error)),
        }
        eprintln!("audit log failed: {failure}");
        return Ok(ExitCode::from(u8::try_from(AUDIT_FAILED_EXIT).unwrap_or(1)));
    }
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
    Ok(ExitCode::from(
        u8::try_from(exit_code_for(&exit)).unwrap_or(1),
    ))
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

/// The directory of the audit dir that holds one directory per session,
/// `<audit>/sessions/<id>/`, as boxcar-audit's writer lays it out.
const SESSIONS: &str = "sessions";

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
        [first, rest @ ..] => first.as_os_str() == SESSIONS && rest.len() <= 1,
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
    /// Mount the shares and run the session on the serial console as this
    /// user and group.
    Console { uid: u32, gid: u32 },
    /// Print a marker and reboot: a boot without shares has nothing to run.
    Hello,
}

/// The `boxcar.*` keys for `mode`, then `extra` (`--cmdline-extra`), in
/// order, then `command` (`-- CMD`), if any, as `boxcar.cmd`. The user's
/// values come after boxcar's so they win: init keeps the last of a
/// repeated key.
fn guest_cmdline(mode: GuestMode, extra: &[String], command: &[String]) -> Vec<String> {
    let mut cmdline = match mode {
        GuestMode::Console { uid, gid } => vec![
            "boxcar.mode=console".to_owned(),
            format!("boxcar.uid={uid}"),
            format!("boxcar.gid={gid}"),
        ],
        GuestMode::Hello => vec!["boxcar.mode=hello".to_owned()],
    };
    cmdline.extend_from_slice(extra);
    if !command.is_empty() {
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
    fn shares_run_the_console_init_as_the_invoking_user() {
        let mode = GuestMode::Console {
            uid: 1000,
            gid: 1001,
        };
        assert_eq!(
            guest_cmdline(mode, &[], &[]),
            ["boxcar.mode=console", "boxcar.uid=1000", "boxcar.gid=1001"]
        );
    }

    #[test]
    fn the_extras_follow_so_they_can_override() {
        let mode = GuestMode::Console { uid: 0, gid: 0 };
        let extra = strings(&["boxcar.mode=hello", "loglevel=7"]);
        assert_eq!(
            guest_cmdline(mode, &extra, &[]),
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
            guest_cmdline(GuestMode::Hello, &extra, &[]),
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
        let cmdline = guest_cmdline(CONSOLE, &extra, &command);
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

    /// Size of the command line the VM would get, from the VMM itself.
    fn size(extra: &[String]) -> usize {
        boxcar_vmm::vmm::cmdline_size(false, extra, &DeviceSet::from_shares(SHARE_COUNT)).unwrap()
    }

    #[test]
    fn a_command_line_up_to_the_limit_is_accepted_and_one_byte_more_is_not() {
        let command = strings(&["/bin/sh", "-c", "exit 7"]);
        let with_filler = |len: usize| {
            let extra = vec!["f".repeat(len)];
            guest_cmdline(CONSOLE, &extra, &command)
        };
        // The filler that makes the command line exactly 2048 bytes, NUL
        // terminator included.
        let fits = 2048 - (size(&with_filler(1)) - 1);
        assert_eq!(size(&with_filler(fits)), 2048);
        check_cmdline_size(
            false,
            &with_filler(fits),
            &DeviceSet::from_shares(SHARE_COUNT),
        )
        .unwrap();

        let error = check_cmdline_size(
            false,
            &with_filler(fits + 1),
            &DeviceSet::from_shares(SHARE_COUNT),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "command line too long (2049 bytes > 2048)"
        );
    }

    #[test]
    fn a_long_command_is_refused_with_the_size_it_would_have() {
        let command = strings(&["/bin/sh", "-c", &"echo x; ".repeat(300)]);
        let cmdline = guest_cmdline(CONSOLE, &[], &command);
        let error =
            check_cmdline_size(false, &cmdline, &DeviceSet::from_shares(SHARE_COUNT)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("command line too long ({} bytes > 2048)", size(&cmdline))
        );
        // The shares' virtio_mmio.device= entries count: without them the
        // same command may fit.
        assert!(size(&cmdline) > 2048);
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
