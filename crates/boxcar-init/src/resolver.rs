// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest's resolver configuration, with the network (`boxcar.net=1`):
//! the gateway is its DNS server.
//!
//! Init writes `nameserver 10.0.2.2` to [`FILE`] on the `/run` tmpfs and
//! bind-mounts it over `/etc/resolv.conf`, so the root share keeps its own
//! file. `/etc/resolv.conf` may be a link, such as systemd-resolved's to
//! `../run/systemd/resolve/stub-resolv.conf` or resolvconf's to
//! `/run/resolvconf/resolv.conf`, and `mount(2)` follows a link for its
//! target. So init follows it first ([`follow`]), one component at a time,
//! at most [`MAX_LINKS`] links, and never above `/`:
//!
//! - where it leads to a file, the bind goes over that file;
//! - where it leads to nothing under `/run`, which is empty at boot, the
//!   directories (0755) and an empty file (0644) are made on the tmpfs
//!   first, out of the root share's sight;
//! - where it leads to nothing elsewhere (`/etc/resolv.conf` itself, when
//!   the rootfs has none), an empty file (0644) is created there first, in
//!   the root share, which the host records like any other change;
//! - a link that cannot be followed (a loop, too many links, `..` above
//!   `/`) is reported, and nothing is bound.
//!
//! A failure costs the guest its name resolution, not its boot: the caller
//! reports it as a warning.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use nix::sys::stat::Mode;
use nix::unistd::mkdir;

use crate::console::{Failed, Step as _};

/// Where programs read the resolver configuration.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The directory init keeps the guest's resolver configuration in.
pub const DIR: &str = "/run/boxcar";
/// The guest's resolver configuration, as init writes it.
pub const FILE: &str = "/run/boxcar/resolv.conf";
/// What it says.
pub const TEXT: &str = "nameserver 10.0.2.2\n";
/// The tmpfs init mounts at `/run`, empty at boot.
const RUN: &str = "/run";
/// The most links [`follow`] follows, as many as `realpath(3)` might before
/// it gives up on a loop, well past what a real rootfs uses.
pub const MAX_LINKS: usize = 8;

/// What is at a path, without following a link there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Link,
    /// A file, a directory, or anything else that is not a link.
    Other,
    /// Nothing (or a path through something that is not a directory).
    Missing,
}

/// The two lookups [`follow`] makes, of absolute guest paths.
pub trait Lookup {
    /// What is at `path`, as `lstat(2)` sees it.
    fn kind(&self, path: &Path) -> io::Result<Kind>;
    /// The target of the link at `path`, as written.
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
}

/// The guest's filesystem, as the directory `root` holds it: `/` for init;
/// a scratch directory in the tests.
pub struct Rooted<'a> {
    root: &'a Path,
}

impl<'a> Rooted<'a> {
    pub fn new(root: &'a Path) -> Self {
        Rooted { root }
    }

    fn host(&self, path: &Path) -> PathBuf {
        self.root.join(path.strip_prefix("/").unwrap_or(path))
    }
}

impl Lookup for Rooted<'_> {
    fn kind(&self, path: &Path) -> io::Result<Kind> {
        match fs::symlink_metadata(self.host(path)) {
            Ok(meta) if meta.file_type().is_symlink() => Ok(Kind::Link),
            Ok(_) => Ok(Kind::Other),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                Ok(Kind::Missing)
            }
            Err(error) => Err(error),
        }
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(self.host(path))
    }
}

/// Where a path leads once its links are followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Followed {
    /// Absolute, with no `.`, `..` or link in it.
    pub path: PathBuf,
    /// Whether something is there.
    pub exists: bool,
}

/// A part of a path still to be followed.
enum Part {
    Root,
    Parent,
    Name(OsString),
}

/// The parts of `path`, `.` left out.
fn parts(path: &Path) -> impl DoubleEndedIterator<Item = Part> + '_ {
    path.components().filter_map(|component| match component {
        Component::RootDir | Component::Prefix(_) => Some(Part::Root),
        Component::ParentDir => Some(Part::Parent),
        Component::Normal(name) => Some(Part::Name(name.to_owned())),
        Component::CurDir => None,
    })
}

/// Where the absolute `path` leads in `lookup`'s filesystem: each component
/// in turn, a link's target (against the link's directory, or `/`) put in
/// its place. Refused with a reason when it takes more than [`MAX_LINKS`]
/// links (a loop, or too deep), when a `..` would go above `/`, or when a
/// lookup fails other than for want of a file.
pub fn follow(lookup: &impl Lookup, path: &Path) -> Result<Followed, String> {
    let mut pending: VecDeque<Part> = parts(path).collect();
    let mut resolved = PathBuf::from("/");
    let mut links = 0;
    let mut exists = true;
    while let Some(part) = pending.pop_front() {
        match part {
            Part::Root => resolved = PathBuf::from("/"),
            Part::Parent => {
                if !resolved.pop() {
                    return Err(format!("{} leads above /", path.display()));
                }
            }
            Part::Name(name) => {
                let next = resolved.join(&name);
                // Below a missing component there is nothing to look up.
                let kind = if exists {
                    lookup
                        .kind(&next)
                        .map_err(|error| format!("lstat {}: {error}", next.display()))?
                } else {
                    Kind::Missing
                };
                match kind {
                    Kind::Link => {
                        links += 1;
                        if links > MAX_LINKS {
                            return Err(format!(
                                "{} takes more than {MAX_LINKS} links",
                                path.display()
                            ));
                        }
                        let target = lookup
                            .read_link(&next)
                            .map_err(|error| format!("readlink {}: {error}", next.display()))?;
                        for part in parts(&target).rev() {
                            pending.push_front(part);
                        }
                    }
                    Kind::Other => resolved = next,
                    Kind::Missing => {
                        resolved = next;
                        exists = false;
                    }
                }
            }
        }
    }
    Ok(Followed {
        path: resolved,
        exists,
    })
}

/// One step of giving the guest its resolver configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Create the directory `path` with `mode` unless something is there.
    Mkdir { path: PathBuf, mode: u32 },
    /// Write `text` as the whole of the file `path`, with `mode`.
    Write {
        path: PathBuf,
        text: &'static str,
        mode: u32,
    },
    /// Create `path` empty, with `mode`, unless something is there.
    Touch { path: PathBuf, mode: u32 },
    /// Bind-mount `source` over `target`.
    Bind { source: PathBuf, target: PathBuf },
}

/// The steps for `/etc/resolv.conf` as `lookup` finds it (see the module
/// docs), or why its link cannot be followed.
pub fn plan(lookup: &impl Lookup) -> Result<Vec<Step>, String> {
    let target = follow(lookup, Path::new(RESOLV_CONF))?;
    let mut steps = vec![
        Step::Mkdir {
            path: DIR.into(),
            mode: 0o755,
        },
        Step::Write {
            path: FILE.into(),
            text: TEXT,
            mode: 0o644,
        },
    ];
    if !target.exists {
        if target.path.starts_with(RUN) {
            // Every directory between /run and the file, outermost first.
            let mut dirs: Vec<PathBuf> = target
                .path
                .ancestors()
                .skip(1)
                .take_while(|dir| *dir != Path::new(RUN))
                .map(Path::to_path_buf)
                .collect();
            dirs.reverse();
            steps.extend(
                dirs.into_iter()
                    .map(|path| Step::Mkdir { path, mode: 0o755 }),
            );
        }
        steps.push(Step::Touch {
            path: target.path.clone(),
            mode: 0o644,
        });
    }
    steps.push(Step::Bind {
        source: FILE.into(),
        target: target.path,
    });
    Ok(steps)
}

/// The steps of [`plan`] for the guest's own `/`, in order, up to the first
/// that fails. Run after the switch to the root share.
pub fn set_up() -> Result<(), Failed> {
    let steps = plan(&Rooted::new(Path::new("/")))
        .map_err(|reason| Failed::new(&format!("follow {RESOLV_CONF}"), reason))?;
    steps.iter().try_for_each(run)
}

fn run(step: &Step) -> Result<(), Failed> {
    match step {
        Step::Mkdir { path, mode } => make_dir(path, *mode),
        Step::Write { path, text, mode } => {
            write_file(path, text, *mode).step(&format!("write {}", path.display()))
        }
        Step::Touch { path, mode } => touch(path, *mode),
        Step::Bind { source, target } => mount(
            Some(source.as_path()),
            target.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .step(&format!(
            "bind {} over {}",
            source.display(),
            target.display()
        )),
    }
}

/// Creates the directory `path` with `mode` unless something is there.
fn make_dir(path: &Path, mode: u32) -> Result<(), Failed> {
    match mkdir(path, Mode::from_bits_truncate(mode)) {
        Ok(()) | Err(Errno::EEXIST) => Ok(()),
        Err(errno) => Err(Failed::new(&format!("mkdir {}", path.display()), errno)),
    }
}

/// Writes `text` as the whole of the file at `path`, created if missing,
/// with `mode` whatever the umask. A link at `path` is not followed.
fn write_file(path: &Path, text: &str, mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.write_all(text.as_bytes())
}

/// Creates an empty file at `path` with `mode`, unless something (a link
/// included, which is not followed) is there already.
fn touch(path: &Path, mode: u32) -> Result<(), Failed> {
    let created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .and_then(|file| file.set_permissions(Permissions::from_mode(mode)));
    match created {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(Failed::new(&format!("create {}", path.display()), error)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::*;

    /// A scratch root holding `etc/`, `run/` and `var/`, as a rootfs
    /// after the switch has them.
    struct Root {
        dir: tempfile::TempDir,
    }

    impl Root {
        fn new() -> Root {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["etc", "run", "var"] {
                fs::create_dir(dir.path().join(sub)).unwrap();
            }
            Root { dir }
        }

        /// The host path of the guest path `path`.
        fn at(&self, path: &str) -> PathBuf {
            self.dir.path().join(path.trim_start_matches('/'))
        }

        /// Makes the guest path `link` a link to `target`, as written.
        fn link(&self, link: &str, target: &str) {
            symlink(target, self.at(link)).unwrap();
        }

        fn plan(&self) -> Result<Vec<Step>, String> {
            plan(&Rooted::new(self.dir.path()))
        }
    }

    fn mkdir(path: &str) -> Step {
        Step::Mkdir {
            path: path.into(),
            mode: 0o755,
        }
    }

    fn touched(path: &str) -> Step {
        Step::Touch {
            path: path.into(),
            mode: 0o644,
        }
    }

    fn bind(target: &str) -> Step {
        Step::Bind {
            source: FILE.into(),
            target: target.into(),
        }
    }

    /// The two steps every plan starts with: the gateway as the
    /// nameserver, in a file on the `/run` tmpfs.
    fn written() -> Vec<Step> {
        vec![
            mkdir("/run/boxcar"),
            Step::Write {
                path: FILE.into(),
                text: "nameserver 10.0.2.2\n",
                mode: 0o644,
            },
        ]
    }

    fn then(steps: &[Step]) -> Vec<Step> {
        let mut all = written();
        all.extend_from_slice(steps);
        all
    }

    #[test]
    fn a_regular_file_is_bound_over() {
        let root = Root::new();
        fs::write(root.at("/etc/resolv.conf"), "nameserver 192.0.2.53\n").unwrap();
        assert_eq!(root.plan(), Ok(then(&[bind("/etc/resolv.conf")])));
    }

    /// No file: an empty one is made in the root share, which the host
    /// records, then bound over.
    #[test]
    fn a_missing_file_is_created_in_the_share_first() {
        let root = Root::new();
        assert_eq!(
            root.plan(),
            Ok(then(&[
                touched("/etc/resolv.conf"),
                bind("/etc/resolv.conf")
            ]))
        );
    }

    /// systemd-resolved's link, relative, into a `/run` that is empty at
    /// boot: the directories and the file are made on the tmpfs.
    #[test]
    fn a_relative_link_into_run_is_made_on_the_tmpfs() {
        let root = Root::new();
        root.link(
            "/etc/resolv.conf",
            "../run/systemd/resolve/stub-resolv.conf",
        );
        assert_eq!(
            root.plan(),
            Ok(then(&[
                mkdir("/run/systemd"),
                mkdir("/run/systemd/resolve"),
                touched("/run/systemd/resolve/stub-resolv.conf"),
                bind("/run/systemd/resolve/stub-resolv.conf"),
            ]))
        );
    }

    #[test]
    fn an_absolute_link_into_run_is_made_on_the_tmpfs() {
        let root = Root::new();
        root.link("/etc/resolv.conf", "/run/resolvconf/resolv.conf");
        assert_eq!(
            root.plan(),
            Ok(then(&[
                mkdir("/run/resolvconf"),
                touched("/run/resolvconf/resolv.conf"),
                bind("/run/resolvconf/resolv.conf"),
            ]))
        );
    }

    /// A link through a linked directory (`/var/run` to `/run`) is
    /// followed component by component.
    #[test]
    fn a_link_through_a_linked_directory_is_followed() {
        let root = Root::new();
        root.link("/var/run", "../run");
        root.link("/etc/resolv.conf", "/var/run/resolvconf/resolv.conf");
        assert_eq!(
            root.plan(),
            Ok(then(&[
                mkdir("/run/resolvconf"),
                touched("/run/resolvconf/resolv.conf"),
                bind("/run/resolvconf/resolv.conf"),
            ]))
        );
    }

    /// A link to a missing file outside `/run`: the file is created there,
    /// in the root share, as a missing `/etc/resolv.conf` is.
    #[test]
    fn a_link_elsewhere_to_nothing_creates_the_file_there() {
        let root = Root::new();
        root.link("/etc/resolv.conf", "/var/resolv.conf");
        assert_eq!(
            root.plan(),
            Ok(then(&[
                touched("/var/resolv.conf"),
                bind("/var/resolv.conf")
            ]))
        );
    }

    #[test]
    fn a_link_to_a_file_is_bound_over_the_file() {
        let root = Root::new();
        fs::write(root.at("/etc/resolv.conf.real"), "").unwrap();
        root.link("/etc/resolv.conf", "resolv.conf.real");
        assert_eq!(root.plan(), Ok(then(&[bind("/etc/resolv.conf.real")])));
    }

    /// Eight links are followed; a ninth, or a loop, is too many.
    #[test]
    fn at_most_eight_links_are_followed() {
        let root = Root::new();
        root.link("/etc/resolv.conf", "/etc/l1");
        for n in 1..8 {
            root.link(&format!("/etc/l{n}"), &format!("l{}", n + 1));
        }
        fs::write(root.at("/etc/l8"), "").unwrap();
        assert_eq!(root.plan(), Ok(then(&[bind("/etc/l8")])));

        fs::remove_file(root.at("/etc/l8")).unwrap();
        root.link("/etc/l8", "l9");
        let error = root.plan().unwrap_err();
        assert!(error.contains("more than 8 links"), "{error}");

        let looped = Root::new();
        looped.link("/etc/resolv.conf", "a");
        looped.link("/etc/a", "resolv.conf");
        let error = looped.plan().unwrap_err();
        assert!(error.contains("more than 8 links"), "{error}");
    }

    /// `..` above `/` is refused, not taken as `/` the way the kernel does:
    /// such a link was made for some other root.
    #[test]
    fn a_link_above_the_root_is_refused() {
        let root = Root::new();
        root.link("/etc/resolv.conf", "../../outside/resolv.conf");
        let error = root.plan().unwrap_err();
        assert!(error.contains("above /"), "{error}");
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn write_replaces_the_file_with_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.1\nsearch old.example\n").unwrap();
        write_file(&path, "nameserver 10.0.2.2\n", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 10.0.2.2\n");
        assert_eq!(mode(&path), 0o644);
    }

    #[test]
    fn touch_creates_an_empty_file_and_leaves_one_that_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        touch(&path, 0o644).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"");
        assert_eq!(mode(&path), 0o644);
        fs::write(&path, "kept\n").unwrap();
        touch(&path, 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"kept\n");
        assert_eq!(mode(&path), 0o644);
        // A link is not followed: there is something there.
        let link = dir.path().join("link");
        symlink(dir.path().join("nowhere"), &link).unwrap();
        touch(&link, 0o644).unwrap();
        assert!(!dir.path().join("nowhere").exists());
        // A directory that is not there is an error, named.
        let error = touch(&dir.path().join("no/such"), 0o644).unwrap_err();
        assert!(error.to_string().starts_with("create "), "{error}");
    }
}
