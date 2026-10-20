// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The VMM process's Landlock domain: the paths a session uses, and nothing
//! else by path.
//!
//! `boxcar run` applies it on its main thread before it starts any thread
//! of its own, so every thread it starts later inherits it. A thread from
//! before (a resolver ureq left running after an image pull) is confined
//! too: on Landlock ABI 8 and later by `LANDLOCK_RESTRICT_SELF_TSYNC`, and
//! otherwise by waiting for it to end before applying, failing if it does
//! not.
//!
//! The ruleset handles every filesystem right of the newest ABI the crate
//! knows, best effort, so an older kernel enforces what it can; TCP binds,
//! with no rule, so none is allowed; and both scopes, so the process can
//! neither signal nor reach an abstract unix socket outside its domain. No
//! rule grants `EXECUTE`: the VMM runs no program. ABI 1 counts as no
//! Landlock: without `REFER` it refuses every rename and link between
//! directories, which would break the guest's `mv`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

pub use boxcar_proto::LandlockStatus;
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, RestrictSelfAttr, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope, ABI,
};

/// The ABI whose rights the ruleset asks for: the newest the crate knows.
/// A kernel without some of them enforces the rest, and the status says
/// `partial`.
const TARGET: ABI = ABI::V9;

/// The first ABI with `LANDLOCK_RESTRICT_SELF_TSYNC`.
const TSYNC_ABI: i32 = 8;

/// How long [`apply`] waits for threads from before it to end, when the
/// kernel cannot confine them itself.
pub const THREAD_WAIT: Duration = Duration::from_secs(30);

/// What a rule allows beneath its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Everything but running a program: a share, the session's and the
    /// state directories, the dump directory.
    Tree,
    /// Reading files and listing directories: the cached image's tree.
    ReadTree,
    /// Writing and truncating one file: the console's log.
    WriteFile,
    /// Reading one file: the kernel, the initramfs, `/etc/resolv.conf`.
    ReadFile,
    /// Reading, writing and `ioctl`s on a device: `/dev/kvm`.
    Device,
    /// Removing an empty directory directly beneath: the sessions root, for
    /// the state directory at the end.
    RemoveDir,
}

impl Reach {
    fn access(self) -> BitFlags<AccessFs> {
        match self {
            Reach::Tree => AccessFs::from_all(TARGET) & !AccessFs::Execute,
            Reach::ReadTree => AccessFs::ReadFile | AccessFs::ReadDir,
            Reach::WriteFile => AccessFs::WriteFile | AccessFs::Truncate,
            Reach::ReadFile => AccessFs::ReadFile.into(),
            Reach::Device => AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::IoctlDev,
            Reach::RemoveDir => AccessFs::RemoveDir.into(),
        }
    }
}

/// One rule: `reach` beneath `path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub path: PathBuf,
    pub reach: Reach,
}

impl Rule {
    pub fn new(path: impl Into<PathBuf>, reach: Reach) -> Self {
        Rule {
            path: path.into(),
            reach,
        }
    }
}

/// How [`apply`] confines threads that run already.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Use `LANDLOCK_RESTRICT_SELF_TSYNC` where the kernel has it. Off only
    /// in tests, to take the other way.
    pub tsync: bool,
    /// How long to wait for other threads to end without it.
    pub thread_wait: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            tsync: true,
            thread_wait: THREAD_WAIT,
        }
    }
}

/// Why the domain could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("cannot confine the process with Landlock: {0}")]
    Ruleset(#[from] RulesetError),
    #[error("cannot confine the process with Landlock: {path}: {source}", path = .path.display())]
    Path { path: PathBuf, source: io::Error },
    #[error(
        "cannot confine the process with Landlock: {threads} threads still run after {secs} s, \
         and this kernel cannot confine threads that run already",
        secs = .waited.as_secs()
    )]
    Threads { threads: usize, waited: Duration },
    #[error("cannot count this process's threads: {0}")]
    Count(io::Error),
}

/// The best Landlock ABI the kernel offers, or 0 when it has none (not
/// built, or not in its `lsm=` list).
pub fn kernel_abi() -> i32 {
    // SAFETY: LANDLOCK_CREATE_RULESET_VERSION with a null attribute and a
    // zero size only asks for the version; nothing is read or written.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    i32::try_from(abi).unwrap_or(0).max(0)
}

/// Confines this process to `rules` and says how far. A rule whose path
/// does not exist is left out: what it would have allowed then fails as it
/// would have anyway. A kernel without Landlock, or with only ABI 1, leaves
/// the process as it is: [`LandlockStatus::Unsupported`].
pub fn apply(rules: &[Rule], options: Options) -> Result<LandlockStatus, DomainError> {
    let abi = kernel_abi();
    if abi < 2 {
        return Ok(LandlockStatus::Unsupported);
    }
    let tsync = options.tsync && abi >= TSYNC_ABI;
    if !tsync {
        wait_for_other_threads(options.thread_wait)?;
    }
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET))?
        .handle_access(AccessNet::BindTcp)?
        .scope(Scope::from_all(TARGET))?
        .create()?;
    for rule in rules {
        let Some(access) = access_for(&rule.path, rule.reach)? else {
            continue;
        };
        let fd = PathFd::new(&rule.path).map_err(|error| DomainError::Path {
            path: rule.path.clone(),
            source: io::Error::other(error),
        })?;
        ruleset = ruleset.add_rule(PathBeneath::new(fd, access))?;
    }
    if tsync {
        ruleset = ruleset.all_threads(true)?;
    }
    let status = ruleset.restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => LandlockStatus::Full,
        RulesetStatus::PartiallyEnforced => LandlockStatus::Partial,
        RulesetStatus::NotEnforced => LandlockStatus::Unsupported,
    })
}

/// What a rule for `reach` may grant on `path`: `None` when the path does
/// not exist, and only a file's rights when it is not a directory (a
/// directory's rights on a file are refused).
fn access_for(path: &Path, reach: Reach) -> Result<Option<BitFlags<AccessFs>>, DomainError> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(Some(reach.access())),
        Ok(_) => Ok(Some(reach.access() & AccessFs::from_file(TARGET))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DomainError::Path {
            path: path.to_owned(),
            source,
        }),
    }
}

/// Waits until this thread is the process's only one, up to `limit`.
fn wait_for_other_threads(limit: Duration) -> Result<(), DomainError> {
    let deadline = Instant::now() + limit;
    loop {
        let threads = thread_count().map_err(DomainError::Count)?;
        if threads <= 1 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DomainError::Threads {
                threads,
                waited: limit,
            });
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// How many threads this process has.
pub fn thread_count() -> io::Result<usize> {
    Ok(fs::read_dir("/proc/self/task")?.count())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No rule reaches `EXECUTE`, and only `Tree` makes or removes
    /// anything but the one directory `RemoveDir` names.
    #[test]
    fn no_rule_runs_a_program() {
        for reach in [
            Reach::Tree,
            Reach::ReadTree,
            Reach::WriteFile,
            Reach::ReadFile,
            Reach::Device,
            Reach::RemoveDir,
        ] {
            assert!(!reach.access().contains(AccessFs::Execute), "{reach:?}");
        }
        assert!(Reach::Tree.access().contains(AccessFs::Refer));
        assert!(Reach::Tree.access().contains(AccessFs::MakeSock));
        assert!(!Reach::ReadTree.access().contains(AccessFs::WriteFile));
    }

    /// A rule on a file grants only a file's rights, and one on a path
    /// that does not exist is left out.
    #[test]
    fn a_rule_fits_what_its_path_is() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "").unwrap();
        let on_file = access_for(&file, Reach::Tree).unwrap().unwrap();
        assert_eq!(on_file & !AccessFs::from_file(TARGET), BitFlags::empty());
        assert_eq!(
            access_for(&dir.path().join("gone"), Reach::Tree).unwrap(),
            None
        );
        assert_eq!(
            access_for(dir.path(), Reach::Tree).unwrap(),
            Some(Reach::Tree.access())
        );
    }

    /// The wait gives up after its limit while another thread runs, and
    /// says how many there were.
    #[test]
    fn the_wait_for_other_threads_gives_up() {
        let (stop, wait) = std::sync::mpsc::channel::<()>();
        let other = thread::spawn(move || {
            let _ = wait.recv();
        });
        match wait_for_other_threads(Duration::from_millis(50)) {
            Err(DomainError::Threads { threads, .. }) => assert!(threads >= 2),
            other => panic!("not a thread error: {other:?}"),
        }
        drop(stop);
        other.join().unwrap();
    }
}
