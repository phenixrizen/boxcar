// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Finding the session's program the way `execvp` does, through the `PATH`
//! init gives the session, but before the fork: the search allocates, and
//! the child may not.

use nix::errno::Errno;
use nix::sys::stat::{stat, SFlag};

/// What is at a path the search tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Nothing, or nothing reachable.
    Missing,
    /// Something `execve` refuses with `EACCES`: a directory, a file with no
    /// execute bit, or one behind a directory init may not search.
    NotExecutable,
    /// A regular file with an execute bit.
    Executable,
}

/// The file `execve` runs for the command `name`: `name` itself when it
/// holds a `/`; else `<entry>/<name>` for the first entry of `path`, a
/// colon-separated list, where `probe` finds an executable file. As with
/// `execvp`, the search fails with `ENOENT` when nothing is found, and with
/// `EACCES` when all it found cannot be run. An empty entry, which to
/// `execvp` means the working directory, is skipped: init's is not the
/// session's.
pub fn resolve(name: &str, path: &str, probe: impl Fn(&str) -> Probe) -> Result<String, Errno> {
    if name.contains('/') {
        return Ok(name.to_owned());
    }
    if name.is_empty() {
        return Err(Errno::ENOENT);
    }
    let mut refused = false;
    for entry in path.split(':').filter(|entry| !entry.is_empty()) {
        let candidate = format!("{entry}/{name}");
        match probe(&candidate) {
            Probe::Executable => return Ok(candidate),
            Probe::NotExecutable => refused = true,
            Probe::Missing => {}
        }
    }
    Err(if refused {
        Errno::EACCES
    } else {
        Errno::ENOENT
    })
}

/// What `stat` says is at `path`, symbolic links followed as `execve`
/// follows them. The execute bits are read as they are, whoever the
/// session runs as: init is root here, for which `access` says yes to any
/// of them.
pub fn probe(path: &str) -> Probe {
    match stat(path) {
        Ok(st) => {
            let regular = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
            if regular && st.st_mode & 0o111 != 0 {
                Probe::Executable
            } else {
                Probe::NotExecutable
            }
        }
        Err(Errno::EACCES) => Probe::NotExecutable,
        Err(_) => Probe::Missing,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    const PATH: &str = "/usr/local/bin:/usr/bin:/bin";

    /// A probe over a fake tree: what is at each path, `Missing` elsewhere.
    /// It records every path it is asked about.
    struct Tree {
        entries: BTreeMap<&'static str, Probe>,
        asked: RefCell<Vec<String>>,
    }

    impl Tree {
        fn new(entries: &[(&'static str, Probe)]) -> Self {
            Tree {
                entries: entries.iter().copied().collect(),
                asked: RefCell::new(Vec::new()),
            }
        }

        fn resolve(&self, name: &str, path: &str) -> Result<String, Errno> {
            resolve(name, path, |candidate| {
                self.asked.borrow_mut().push(candidate.to_owned());
                self.entries
                    .get(candidate)
                    .copied()
                    .unwrap_or(Probe::Missing)
            })
        }
    }

    #[test]
    fn a_name_with_a_slash_is_run_as_given() {
        let tree = Tree::new(&[]);
        for name in ["/bin/sh", "./run.sh", "bin/tool", "/no/such/file"] {
            assert_eq!(tree.resolve(name, PATH).as_deref(), Ok(name));
        }
        assert!(tree.asked.borrow().is_empty(), "{:?}", tree.asked);
    }

    #[test]
    fn the_first_entry_with_an_executable_file_wins() {
        let tree = Tree::new(&[
            ("/usr/bin/ls", Probe::Executable),
            ("/bin/ls", Probe::Executable),
        ]);
        assert_eq!(tree.resolve("ls", PATH).as_deref(), Ok("/usr/bin/ls"));
        assert_eq!(*tree.asked.borrow(), ["/usr/local/bin/ls", "/usr/bin/ls"]);
    }

    #[test]
    fn what_cannot_be_run_is_passed_over() {
        let tree = Tree::new(&[
            ("/usr/local/bin/tool", Probe::NotExecutable),
            ("/usr/bin/tool", Probe::NotExecutable),
            ("/bin/tool", Probe::Executable),
        ]);
        assert_eq!(tree.resolve("tool", PATH).as_deref(), Ok("/bin/tool"));
    }

    #[test]
    fn nothing_found_is_enoent_and_nothing_runnable_is_eacces() {
        let tree = Tree::new(&[("/usr/bin/data", Probe::NotExecutable)]);
        assert_eq!(tree.resolve("nosuchcmd", PATH), Err(Errno::ENOENT));
        assert_eq!(tree.resolve("data", PATH), Err(Errno::EACCES));
        assert_eq!(tree.resolve("nosuchcmd", ""), Err(Errno::ENOENT));
    }

    #[test]
    fn the_empty_name_is_not_found() {
        let tree = Tree::new(&[("/bin/", Probe::NotExecutable)]);
        assert_eq!(tree.resolve("", PATH), Err(Errno::ENOENT));
        assert!(tree.asked.borrow().is_empty(), "{:?}", tree.asked);
    }

    /// An empty entry would mean the working directory, which is init's
    /// here and not the session's.
    #[test]
    fn empty_path_entries_are_skipped() {
        let tree = Tree::new(&[("/bin/ls", Probe::Executable)]);
        assert_eq!(tree.resolve("ls", "::/bin:").as_deref(), Ok("/bin/ls"));
        assert_eq!(*tree.asked.borrow(), ["/bin/ls"]);
    }

    #[test]
    fn the_probe_reads_the_file_type_and_the_execute_bits() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
        let file = |name: &str, mode: u32| {
            fs::write(dir.path().join(name), b"#!/bin/sh\n").unwrap();
            fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(mode)).unwrap();
        };
        file("tool", 0o755);
        file("group-only", 0o610);
        file("data", 0o644);
        fs::create_dir(dir.path().join("subdir")).unwrap();
        symlink(dir.path().join("tool"), dir.path().join("link")).unwrap();
        symlink(dir.path().join("gone"), dir.path().join("dangling")).unwrap();

        assert_eq!(probe(&at("tool")), Probe::Executable);
        assert_eq!(probe(&at("group-only")), Probe::Executable);
        assert_eq!(probe(&at("link")), Probe::Executable);
        assert_eq!(probe(&at("data")), Probe::NotExecutable);
        assert_eq!(probe(&at("subdir")), Probe::NotExecutable);
        assert_eq!(probe(&at("missing")), Probe::Missing);
        assert_eq!(probe(&at("dangling")), Probe::Missing);
        assert_eq!(probe(&at("data/under-a-file")), Probe::Missing);
    }
}
