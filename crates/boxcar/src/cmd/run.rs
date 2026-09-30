// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar run`: boots a microVM and records its session.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs, io};

use anyhow::{bail, Context};
use boxcar_audit::WriterConfig;
use boxcar_fs::{AuditFsOptions, AuditLevel, CachePolicyKind, FsShareConfig};
use boxcar_proto::{guestcmd, SessionId};
use boxcar_vmm::lifecycle::block_stop_signals;
use boxcar_vmm::vmm::{cmdline_size, ConsoleOut, VmConfig, Vmm, CMDLINE_MAX_SIZE};
use tracing_subscriber::EnvFilter;

use crate::cli::{AuditLevelArg, RunArgs};

/// Starts the session's audit writer, boots the VM, and waits for it to
/// stop. The exit code is the VM's (see `VmExit::exit_code`).
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
    // The default workspace is boxcar's own, fresh in the session
    // directory: only the directories the user names are checked.
    let named: Vec<&Path> = [rootfs.as_deref(), workspace.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let audit_dir = check_audit_dir(&audit_dir, &named)?;

    let (mode, share_count) = match &rootfs {
        Some(_) => {
            let (uid, gid) = invoking_user();
            (GuestMode::Console { uid, gid }, 2)
        }
        // clap requires --rootfs unless --no-fs.
        None => (GuestMode::Hello, 0),
    };
    let cmdline_extra = guest_cmdline(mode, &args.cmdline_extra, &args.command);
    check_cmdline_size(args.debug_boot, &cmdline_extra, share_count)?;

    // Before any thread starts, so that every thread inherits the mask and
    // the signals reach only the VMM's signalfd.
    block_stop_signals().context("cannot block SIGINT and SIGTERM")?;

    let session_id = SessionId::new();
    let (sink, writer) = boxcar_audit::spawn(WriterConfig::new(&audit_dir, session_id.clone()))
        .with_context(|| format!("cannot start the audit log under {}", audit_dir.display()))?;
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
/// link resolved, once it is known to lie outside each of `shares` (real
/// paths already) and none of them lies inside it: the guest writes to its
/// shares, and must not reach the log that records what it does.
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
        if share.starts_with(&audit) {
            bail!(
                "share {} is inside audit dir {}",
                share.display(),
                audit.display()
            );
        }
    }
    Ok(audit)
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
/// base, and a device entry for each of `fs_shares` shares, measured as
/// the VMM composes it.
fn check_cmdline_size(debug_boot: bool, extra: &[String], fs_shares: usize) -> anyhow::Result<()> {
    let size = cmdline_size(debug_boot, extra, fs_shares)?;
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
        boxcar_vmm::vmm::cmdline_size(false, extra, 2).unwrap()
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
        check_cmdline_size(false, &with_filler(fits), 2).unwrap();

        let error = check_cmdline_size(false, &with_filler(fits + 1), 2).unwrap_err();
        assert_eq!(
            error.to_string(),
            "command line too long (2049 bytes > 2048)"
        );
    }

    #[test]
    fn a_long_command_is_refused_with_the_size_it_would_have() {
        let command = strings(&["/bin/sh", "-c", &"echo x; ".repeat(300)]);
        let cmdline = guest_cmdline(CONSOLE, &[], &command);
        let error = check_cmdline_size(false, &cmdline, 2).unwrap_err();
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

    #[test]
    fn a_share_inside_the_audit_dir_is_refused() {
        let tree = Tree::new();
        let error = check_audit_dir(tree.dir.path(), &[&tree.at("root")]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "share {} is inside audit dir {}",
                tree.at("root").display(),
                tree.dir.path().canonicalize().unwrap().display()
            )
        );
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
