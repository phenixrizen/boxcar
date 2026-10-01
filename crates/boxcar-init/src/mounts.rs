// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The filesystems init mounts, and the switch from the initramfs to the
//! root share.
//!
//! In order: the kernel's API filesystems in the initramfs ([`early`]); the
//! `root` virtio-fs share at `/newroot` and the `workspace` share inside it
//! ([`shares`]); `/dev`, `/proc` and `/sys` moved into the new root and the
//! rest of the API filesystems mounted there ([`api`], [`optional`]); then
//! the new root made `/`. Everything else, `/tmp` included, is the root
//! share, which the host audits.

use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use nix::sys::stat::Mode;
use nix::unistd::{chdir, chroot, mkdir};

use crate::console::{warn, Failed, Step};

/// Where the root share is mounted before it becomes `/`. The initramfs
/// carries the empty directory.
pub const NEWROOT: &str = "/newroot";

/// The mounts that move from the initramfs into the new root, as they are
/// named in both.
pub const MOVED: [&str; 3] = ["/dev", "/proc", "/sys"];

/// One `mount(2)`: `source` of type `fstype` on `target`, with `flags` and
/// the filesystem's own options in `data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mount {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    pub flags: MsFlags,
    pub data: Option<&'static str>,
}

/// Neither set-user-ID programs, device nodes nor programs at all: the
/// flags of a kernel API filesystem.
const API_FLAGS: MsFlags = MsFlags::MS_NOSUID
    .union(MsFlags::MS_NODEV)
    .union(MsFlags::MS_NOEXEC);

/// Step 1, in the initramfs: `proc`, `sysfs` and `devtmpfs`.
pub fn early() -> [Mount; 3] {
    [
        Mount {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            flags: API_FLAGS,
            data: None,
        },
        Mount {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            flags: API_FLAGS,
            data: None,
        },
        Mount {
            source: "devtmpfs",
            target: "/dev",
            fstype: "devtmpfs",
            flags: MsFlags::MS_NOSUID,
            data: Some("mode=0755"),
        },
    ]
}

/// Step 2: the virtio-fs shares, by tag. `workspace` is mounted inside the
/// root share, so it must exist there; [`mount_shares`] creates it.
pub fn shares() -> [Mount; 2] {
    [
        Mount {
            source: "root",
            target: NEWROOT,
            fstype: "virtiofs",
            flags: MsFlags::MS_NOATIME,
            data: None,
        },
        Mount {
            source: "workspace",
            target: "/newroot/workspace",
            fstype: "virtiofs",
            flags: MsFlags::MS_NOATIME,
            data: None,
        },
    ]
}

/// Step 3, in the new root after [`MOVED`]: `devpts` with its own instance
/// of ptys, and `tmpfs` for POSIX shared memory and for `/run`.
pub fn api() -> [Mount; 3] {
    let tmpfs = MsFlags::MS_NOSUID.union(MsFlags::MS_NODEV);
    [
        Mount {
            source: "devpts",
            target: "/newroot/dev/pts",
            fstype: "devpts",
            flags: MsFlags::MS_NOSUID.union(MsFlags::MS_NOEXEC),
            data: Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        },
        Mount {
            source: "shm",
            target: "/newroot/dev/shm",
            fstype: "tmpfs",
            flags: tmpfs,
            data: Some("mode=1777"),
        },
        Mount {
            source: "run",
            target: "/newroot/run",
            fstype: "tmpfs",
            flags: tmpfs,
            data: Some("mode=0755"),
        },
    ]
}

/// Step 3, best effort: `tracefs`, `cgroup2` and `bpf`, which a kernel built
/// without them lacks. Their mount points are directories sysfs creates.
pub fn optional() -> [Mount; 3] {
    [
        Mount {
            source: "tracefs",
            target: "/newroot/sys/kernel/tracing",
            fstype: "tracefs",
            flags: API_FLAGS,
            data: None,
        },
        Mount {
            source: "cgroup2",
            target: "/newroot/sys/fs/cgroup",
            fstype: "cgroup2",
            flags: API_FLAGS,
            data: None,
        },
        Mount {
            source: "bpf",
            target: "/newroot/sys/fs/bpf",
            fstype: "bpf",
            flags: API_FLAGS,
            data: Some("mode=0700"),
        },
    ]
}

/// What of the best-effort mounts is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mounted {
    /// `cgroup2` at `/sys/fs/cgroup` (in the new root).
    pub cgroup2: bool,
}

/// Mounts `m`.
fn mount_one(m: &Mount) -> Result<(), Failed> {
    mount(Some(m.source), m.target, Some(m.fstype), m.flags, m.data)
        .step(&format!("mount {} on {}", m.fstype, m.target))
}

/// Creates the directory `path` unless something is there already.
pub fn ensure_dir(path: &str, mode: u32) -> Result<(), Failed> {
    match mkdir(path, Mode::from_bits_truncate(mode)) {
        Ok(()) | Err(Errno::EEXIST) => Ok(()),
        Err(errno) => Err(Failed::new(&format!("mkdir {path}"), errno)),
    }
}

/// Step 1: mounts [`early`].
pub fn mount_early() -> Result<(), Failed> {
    early().iter().try_for_each(mount_one)
}

/// Step 2: mounts [`shares`], creating `/workspace` in the root share first
/// if the root filesystem has none.
pub fn mount_shares() -> Result<(), Failed> {
    let [root, workspace] = shares();
    mount_one(&root)?;
    ensure_dir(workspace.target, 0o755)?;
    mount_one(&workspace)
}

/// Step 3: moves [`MOVED`] into the new root and mounts [`api`] there, then
/// what it can of [`optional`], with a warning for each it cannot.
pub fn mount_api() -> Result<Mounted, Failed> {
    for dir in MOVED {
        let target = format!("{NEWROOT}{dir}");
        mount(
            Some(dir),
            target.as_str(),
            None::<&str>,
            MsFlags::MS_MOVE,
            None::<&str>,
        )
        .step(&format!("move {dir} to {target}"))?;
    }
    // devtmpfs has neither.
    ensure_dir(&format!("{NEWROOT}/dev/pts"), 0o755)?;
    ensure_dir(&format!("{NEWROOT}/dev/shm"), 0o755)?;
    api().iter().try_for_each(mount_one)?;

    let mut mounted = Mounted { cgroup2: false };
    for m in optional() {
        match mount_one(&m) {
            Ok(()) => mounted.cgroup2 |= m.fstype == "cgroup2",
            Err(failed) => warn(&failed.to_string()),
        }
    }
    Ok(mounted)
}

/// Step 4: makes the new root `/`, the way `switch_root` does: the mount
/// moves over the initramfs, and init's root and working directory follow.
pub fn switch_root() -> Result<(), Failed> {
    chdir(NEWROOT).step(&format!("chdir {NEWROOT}"))?;
    mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
        .step(&format!("move {NEWROOT} to /"))?;
    chroot(".").step("chroot .")?;
    chdir("/").step("chdir /")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Mount> {
        [&early()[..], &shares()[..], &api()[..], &optional()[..]].concat()
    }

    #[test]
    fn the_initramfs_gets_proc_sys_and_dev() {
        let got: Vec<_> = early()
            .iter()
            .map(|m| (m.fstype, m.target, m.data))
            .collect();
        assert_eq!(
            got,
            [
                ("proc", "/proc", None),
                ("sysfs", "/sys", None),
                ("devtmpfs", "/dev", Some("mode=0755")),
            ]
        );
        for m in early() {
            assert!(m.flags.contains(MsFlags::MS_NOSUID), "{m:?}");
        }
    }

    #[test]
    fn the_shares_are_virtiofs_by_tag_with_noatime_only() {
        assert_eq!(
            shares(),
            [
                Mount {
                    source: "root",
                    target: "/newroot",
                    fstype: "virtiofs",
                    flags: MsFlags::MS_NOATIME,
                    data: None,
                },
                Mount {
                    source: "workspace",
                    target: "/newroot/workspace",
                    fstype: "virtiofs",
                    flags: MsFlags::MS_NOATIME,
                    data: None,
                },
            ]
        );
    }

    #[test]
    fn devpts_is_a_new_instance_with_tty_group_modes() {
        let devpts = api()[0];
        assert_eq!(devpts.fstype, "devpts");
        assert_eq!(devpts.target, "/newroot/dev/pts");
        assert_eq!(
            devpts.data,
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5")
        );
    }

    #[test]
    fn the_new_root_gets_tmpfs_at_dev_shm_and_run_and_the_kernel_filesystems() {
        let got: Vec<_> = api()
            .iter()
            .chain(optional().iter())
            .map(|m| (m.fstype, m.target))
            .collect();
        assert_eq!(
            got,
            [
                ("devpts", "/newroot/dev/pts"),
                ("tmpfs", "/newroot/dev/shm"),
                ("tmpfs", "/newroot/run"),
                ("tracefs", "/newroot/sys/kernel/tracing"),
                ("cgroup2", "/newroot/sys/fs/cgroup"),
                ("bpf", "/newroot/sys/fs/bpf"),
            ]
        );
    }

    /// `/tmp` stays on the root share, where the host audits it.
    #[test]
    fn nothing_is_mounted_on_tmp() {
        for m in all() {
            assert!(!m.target.ends_with("/tmp"), "{m:?}");
            assert!(!m.target.contains("/tmp/"), "{m:?}");
        }
    }

    #[test]
    fn the_moved_mounts_are_the_early_ones() {
        let mut early: Vec<_> = early().iter().map(|m| m.target).collect();
        let mut moved = MOVED.to_vec();
        early.sort_unstable();
        moved.sort_unstable();
        assert_eq!(early, moved);
    }
}
