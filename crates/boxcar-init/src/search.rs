// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The files the session's command may be, in the order `execvp` tries
//! them, through the `PATH` init gives the session.
//!
//! Only the list is made here, before the fork, since making it allocates.
//! Which of them can be run is for the session child to find out, after it
//! has become the session's user ([`crate::session::Exec`]), reading each
//! miss with [`miss`] as `execvp` does.

use nix::errno::Errno;

/// The paths `execvp` tries for the command `name` on `path`, a
/// colon-separated list: `name` alone when it holds a `/`; else
/// `<entry>/<name>` for each entry, in order. An empty entry, which to
/// `execvp` means the working directory, is skipped. The empty name has
/// none.
pub fn candidates(name: &str, path: &str) -> Vec<String> {
    if name.contains('/') {
        return vec![name.to_owned()];
    }
    if name.is_empty() {
        return Vec::new();
    }
    path.split(':')
        .filter(|entry| !entry.is_empty())
        .map(|entry| format!("{entry}/{name}"))
        .collect()
}

/// What the error from a candidate that did not run means for the search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    /// Nothing is there (`ENOENT`, `ENOTDIR`): try the next.
    Absent,
    /// Something is there that may not be run (`EACCES`): try the next,
    /// and remember it.
    Refused,
    /// Any other error, which ends the search with that error.
    Fatal,
}

/// How `execvp` reads `errno` from a candidate it could not run.
pub fn miss(errno: Errno) -> Miss {
    match errno {
        Errno::ENOENT | Errno::ENOTDIR => Miss::Absent,
        Errno::EACCES => Miss::Refused,
        _ => Miss::Fatal,
    }
}

/// The error of a search that ran out of candidates: `EACCES` when one
/// was `refused`, `ENOENT` when none was there.
pub fn not_run(refused: bool) -> Errno {
    if refused {
        Errno::EACCES
    } else {
        Errno::ENOENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/usr/local/bin:/usr/bin:/bin";

    #[test]
    fn a_name_with_a_slash_is_its_only_candidate() {
        for name in ["/bin/sh", "./run.sh", "bin/tool", "/no/such/file"] {
            assert_eq!(candidates(name, PATH), [name]);
        }
    }

    #[test]
    fn a_bare_name_is_tried_in_each_entry_in_order() {
        assert_eq!(
            candidates("ls", PATH),
            ["/usr/local/bin/ls", "/usr/bin/ls", "/bin/ls"]
        );
    }

    /// An empty entry would mean the working directory, which is not where
    /// a command given by name should come from.
    #[test]
    fn empty_entries_are_skipped() {
        assert_eq!(candidates("ls", "::/bin:"), ["/bin/ls"]);
        assert!(candidates("ls", "").is_empty());
    }

    #[test]
    fn the_empty_name_has_no_candidate() {
        assert!(candidates("", PATH).is_empty());
    }

    /// execvp goes on past a file that is not there and past one it may not
    /// run, and stops at any other error.
    #[test]
    fn a_miss_is_read_as_execvp_reads_it() {
        for errno in [Errno::ENOENT, Errno::ENOTDIR] {
            assert_eq!(miss(errno), Miss::Absent, "{errno}");
        }
        assert_eq!(miss(Errno::EACCES), Miss::Refused);
        for errno in [Errno::ENOEXEC, Errno::ELOOP, Errno::E2BIG, Errno::ETXTBSY] {
            assert_eq!(miss(errno), Miss::Fatal, "{errno}");
        }
    }

    #[test]
    fn nothing_found_is_enoent_and_nothing_runnable_is_eacces() {
        assert_eq!(not_run(false), Errno::ENOENT);
        assert_eq!(not_run(true), Errno::EACCES);
    }
}
