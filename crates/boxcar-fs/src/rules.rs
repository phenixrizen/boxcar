// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Path rules: what a session may change, may not touch at all, and may
//! not run, by guest path (a policy file's `[fs] writable`, `[fs] denied`
//! and `[exec] deny`, with the live exceptions on top).
//!
//! A rule is a glob of guest paths: `globset`, with `literal_separator`
//! (`*` stays within a component, `**` crosses them), absolute (starting
//! `/` or `**/`), checked by [`glob`]. A guest path is a share's guest
//! directory joined with a node's share-relative path ([`guest_path`]),
//! matched as raw bytes.
//!
//! A glob names a path and all beneath it: a path is denied, or
//! writable, when it or any of its ancestors matches.
//!
//! - **denied**: nothing denied may be looked up, opened, created or
//!   changed.
//! - **writable**: a change must name a writable path. A directory that
//!   may be moved may so be edited in place, and moving it out and back
//!   launders nothing.
//! - **exec**: a file one of whose names matches an `[exec] deny` glob may
//!   not be opened at all (to run it, or to read it for a loader or a
//!   copy), renamed or linked, unless an exec exception matches that name.
//!
//! A denied glob's literal prefix (its components before the first
//! wildcard) may not be renamed, nor any ancestor of it, so a tree made
//! beneath it later cannot be moved out from under the glob.
//!
//! [`PathRules::allow_all`] checks nothing: a session without a policy
//! file. [`LiveRules`] is how every share of a session reads the rules in
//! force, swapped whole when an exception comes or goes.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use globset::{Candidate, GlobBuilder, GlobSet, GlobSetBuilder};

/// The rules every share of a session reads, swapped whole.
pub type LiveRules = Arc<ArcSwap<PathRules>>;

/// Why a glob was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GlobError {
    #[error("{0:?} is relative; a path glob starts with / or **/")]
    Relative(String),
    #[error("{0:?} is not a glob: {1}")]
    Invalid(String, String),
}

/// `text` as a path glob: absolute, and one `globset` compiles with
/// `literal_separator`. A relative glob could never match a guest path,
/// so it is refused rather than left to match nothing.
pub fn glob(text: &str) -> Result<globset::Glob, GlobError> {
    if !(text.starts_with('/') || text.starts_with("**/")) {
        return Err(GlobError::Relative(text.to_owned()));
    }
    GlobBuilder::new(text)
        .literal_separator(true)
        .build()
        .map_err(|error| GlobError::Invalid(text.to_owned(), error.kind().to_string()))
}

/// The guest path of `relative` (a share-relative path, `/` for the
/// share's root) in the share served at `guest_dir` (`/`, `/workspace`).
pub fn guest_path(guest_dir: &str, relative: &[u8]) -> Vec<u8> {
    let dir = guest_dir.trim_end_matches('/').as_bytes();
    if relative == b"/" || relative.is_empty() {
        return if dir.is_empty() {
            b"/".to_vec()
        } else {
            dir.to_vec()
        };
    }
    let mut path = Vec::with_capacity(dir.len() + relative.len());
    path.extend_from_slice(dir);
    if !relative.starts_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(relative);
    path
}

/// A list of globs, compiled, with their texts so a match can name its
/// glob.
#[derive(Clone, Debug)]
struct Globs {
    texts: Vec<String>,
    set: GlobSet,
}

impl Globs {
    fn new(texts: &[String]) -> Result<Globs, GlobError> {
        let mut builder = GlobSetBuilder::new();
        for text in texts {
            builder.add(glob(text)?);
        }
        let set = builder
            .build()
            .map_err(|error| GlobError::Invalid(texts.join(", "), error.to_string()))?;
        Ok(Globs {
            texts: texts.to_vec(),
            set,
        })
    }

    fn empty() -> Globs {
        Globs {
            texts: Vec::new(),
            set: GlobSet::empty(),
        }
    }

    /// The first glob, in the order given, that matches `path`.
    fn first_match(&self, path: &Candidate<'_>) -> Option<&str> {
        if self.texts.is_empty() {
            return None;
        }
        self.set
            .matches_candidate(path)
            .into_iter()
            .min()
            .map(|index| self.texts[index].as_str())
    }

    fn is_match(&self, path: &Candidate<'_>) -> bool {
        !self.texts.is_empty() && self.set.is_match_candidate(path)
    }
}

/// A policy's path rules as written: its `writable`, `denied` and
/// `[exec] deny` globs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathSpec {
    pub writable: Vec<String>,
    pub denied: Vec<String>,
    pub exec_deny: Vec<String>,
}

/// The rules in force: a policy's path rules with the live exceptions on
/// top, or none at all.
#[derive(Clone, Debug)]
pub struct PathRules {
    /// `None`: allow-all, nothing checked.
    rules: Option<Compiled>,
}

#[derive(Clone, Debug)]
struct Compiled {
    writable: Globs,
    denied: Globs,
    /// Each denied glob's literal prefix, with the glob: none for a glob
    /// that starts with a wildcard.
    prefixes: Vec<(Vec<u8>, String)>,
    exec_deny: Globs,
    /// Live `exec` exceptions: names they match may be run.
    exec_allow: Globs,
}

/// `glob`'s literal prefix: its components before the first one with a
/// wildcard (`*`, `?`, `[`, `{`, or an escape), without a trailing `/`;
/// `None` when the first component has one.
fn literal_prefix(glob: &str) -> Option<Vec<u8>> {
    let mut prefix = Vec::new();
    // An absolute glob's first component is the empty one before its `/`.
    for component in glob.split('/').skip(usize::from(glob.starts_with('/'))) {
        if component.contains(['*', '?', '[', '{', '\\']) {
            break;
        }
        prefix.push(b'/');
        prefix.extend_from_slice(component.as_bytes());
    }
    (!prefix.is_empty()).then_some(prefix)
}

/// The first glob that matches `path` or one of its ancestors.
fn first_match_up<'a>(globs: &'a Globs, path: &[u8]) -> Option<&'a str> {
    if globs.texts.is_empty() {
        return None;
    }
    let mut end = path.len();
    loop {
        let prefix = if end == 0 { &b"/"[..] } else { &path[..end] };
        if let Some(glob) = globs.first_match(&candidate(prefix)) {
            return Some(glob);
        }
        if end == 0 {
            return None;
        }
        // The parent: up to the last `/`, the root at the top.
        end = path[..end]
            .iter()
            .rposition(|&byte| byte == b'/')
            .unwrap_or(0);
    }
}

impl Default for PathRules {
    fn default() -> Self {
        PathRules::allow_all()
    }
}

impl PathRules {
    /// No rules: every path writable, nothing denied, every program run.
    pub fn allow_all() -> PathRules {
        PathRules { rules: None }
    }

    /// `spec`, with `writable` exceptions adding to its `writable` and
    /// `exec` exceptions lifting `[exec] deny` for what they match.
    pub fn new(
        spec: &PathSpec,
        writable_exceptions: &[String],
        exec_exceptions: &[String],
    ) -> Result<PathRules, GlobError> {
        let mut writable = spec.writable.clone();
        writable.extend_from_slice(writable_exceptions);
        let prefixes = spec
            .denied
            .iter()
            .filter_map(|glob| Some((literal_prefix(glob)?, glob.clone())))
            .collect();
        Ok(PathRules {
            rules: Some(Compiled {
                writable: Globs::new(&writable)?,
                denied: Globs::new(&spec.denied)?,
                prefixes,
                exec_deny: Globs::new(&spec.exec_deny)?,
                exec_allow: if exec_exceptions.is_empty() {
                    Globs::empty()
                } else {
                    Globs::new(exec_exceptions)?
                },
            }),
        })
    }

    /// Whether any rule is checked at all.
    pub fn enforcing(&self) -> bool {
        self.rules.is_some()
    }

    /// Whether anything is denied.
    pub fn denies_anything(&self) -> bool {
        self.rules
            .as_ref()
            .is_some_and(|rules| !rules.denied.texts.is_empty())
    }

    /// Whether the shares are scanned at boot ([`crate::scan`]): anything
    /// denied, or any program refused.
    pub fn scans(&self) -> bool {
        self.rules.as_ref().is_some_and(|rules| {
            !rules.denied.texts.is_empty() || !rules.exec_deny.texts.is_empty()
        })
    }

    /// The `denied` glob that denies `path`, it or one of its ancestors;
    /// `None` when nothing does. `path` is a guest path.
    pub fn denied(&self, path: &[u8]) -> Option<&str> {
        first_match_up(&self.rules.as_ref()?.denied, path)
    }

    /// The denied glob whose literal prefix `path` is, or is an ancestor
    /// of: a path that may not be renamed.
    pub fn holds_prefix(&self, path: &[u8]) -> Option<&str> {
        let rules = self.rules.as_ref()?;
        rules.prefixes.iter().find_map(|(prefix, glob)| {
            let holds = path == b"/"
                || prefix.as_slice() == path
                || (prefix.starts_with(path) && prefix.get(path.len()) == Some(&b'/'));
            holds.then_some(glob.as_str())
        })
    }

    /// Whether a change may name `path`, a guest path: it or one of its
    /// ancestors is writable.
    pub fn writable(&self, path: &[u8]) -> bool {
        match &self.rules {
            None => true,
            Some(rules) => first_match_up(&rules.writable, path).is_some(),
        }
    }

    /// The `[exec] deny` glob that refuses `path`, unless an exec exception
    /// matches it.
    pub fn exec_denied(&self, path: &[u8]) -> Option<&str> {
        let rules = self.rules.as_ref()?;
        let path = candidate(path);
        let glob = rules.exec_deny.first_match(&path)?;
        if rules.exec_allow.is_match(&path) {
            return None;
        }
        Some(glob)
    }

    /// Whether an exec exception matches `path`: a program the scan found
    /// refused may be opened by such a name.
    pub fn exec_lifted(&self, path: &[u8]) -> bool {
        self.rules
            .as_ref()
            .is_some_and(|rules| rules.exec_allow.is_match(&candidate(path)))
    }

    /// The `[exec] deny` glob that matches `path`, exceptions aside: what
    /// the boot scan records.
    pub fn exec_named(&self, path: &[u8]) -> Option<&str> {
        self.rules.as_ref()?.exec_deny.first_match(&candidate(path))
    }
}

fn candidate(path: &[u8]) -> Candidate<'_> {
    Candidate::new(OsStr::from_bytes(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn rules(writable: &[&str], denied: &[&str], exec: &[&str]) -> PathRules {
        let spec = PathSpec {
            writable: strings(writable),
            denied: strings(denied),
            exec_deny: strings(exec),
        };
        PathRules::new(&spec, &[], &[]).unwrap()
    }

    /// A share's guest directory joined with a share-relative path: the
    /// root share's paths as they are, the workspace's under it, and each
    /// share's root as its directory.
    #[test]
    fn guest_paths_join_without_doubling_slashes() {
        assert_eq!(guest_path("/", b"/etc/x"), b"/etc/x");
        assert_eq!(guest_path("/", b"/"), b"/");
        assert_eq!(guest_path("/workspace", b"/src/a"), b"/workspace/src/a");
        assert_eq!(guest_path("/workspace", b"/"), b"/workspace");
        assert_eq!(guest_path("/workspace/", b"/a"), b"/workspace/a");
        assert_eq!(guest_path("/workspace", b"a"), b"/workspace/a");
    }

    /// Absolute globs only, and only ones globset compiles.
    #[test]
    fn globs_are_absolute_and_compile() {
        assert!(glob("/workspace/**").is_ok());
        assert!(glob("**/nc").is_ok());
        assert_eq!(
            glob("nc").unwrap_err(),
            GlobError::Relative("nc".to_owned())
        );
        assert!(matches!(glob("/a/[b"), Err(GlobError::Invalid(..))));
    }

    /// `denied` covers what its glob names and all beneath it; `a/**`
    /// covers what `a` holds, not `a` itself; the first glob in the
    /// order given is the one named.
    #[test]
    fn denied_covers_what_lies_beneath() {
        let r = rules(
            &["/**"],
            &["/workspace/secrets", "/workspace/keys/**", "**/.env"],
            &[],
        );
        assert_eq!(r.denied(b"/workspace/secrets"), Some("/workspace/secrets"));
        assert_eq!(
            r.denied(b"/workspace/secrets/a/b"),
            Some("/workspace/secrets")
        );
        assert_eq!(r.denied(b"/workspace/keys"), None);
        assert_eq!(r.denied(b"/workspace/keys/k"), Some("/workspace/keys/**"));
        assert_eq!(r.denied(b"/workspace/app/.env"), Some("**/.env"));
        assert_eq!(r.denied(b"/workspace/app/.env/x"), Some("**/.env"));
        assert_eq!(r.denied(b"/workspace/app/.ENV"), None);
        assert_eq!(r.denied(b"/workspace"), None);
        assert_eq!(r.denied(b"/"), None);
        let all = rules(&[], &["/"], &[]);
        assert_eq!(all.denied(b"/etc/passwd"), Some("/"));
    }

    /// `writable` is the glob's own: no ancestor rule.
    #[test]
    fn writable_covers_what_lies_beneath() {
        let r = rules(&["/workspace/**", "/tmp/**", "/etc/*"], &[], &[]);
        assert!(r.writable(b"/workspace/a"));
        assert!(r.writable(b"/workspace/a/b/c"));
        assert!(!r.writable(b"/workspace"));
        assert!(r.writable(b"/tmp/x"));
        assert!(!r.writable(b"/tmp"));
        assert!(!r.writable(b"/tmpx"));
        // `/etc/*` names each entry of /etc, so all beneath each.
        assert!(r.writable(b"/etc/ssl"));
        assert!(r.writable(b"/etc/ssl/certs/ca.pem"));
        assert!(!r.writable(b"/etc"));
        assert!(!r.writable(b"/usr/x"));
        let none = rules(&[], &[], &[]);
        assert!(!none.writable(b"/workspace/a"));
    }

    /// A denied glob's literal prefix and its ancestors may not be
    /// renamed; a glob that starts with a wildcard has none.
    #[test]
    fn literal_prefixes_and_their_ancestors() {
        assert_eq!(
            literal_prefix("/workspace/secrets/**"),
            Some(b"/workspace/secrets".to_vec())
        );
        assert_eq!(
            literal_prefix("/workspace/a*/x"),
            Some(b"/workspace".to_vec())
        );
        assert_eq!(literal_prefix("/etc/shadow"), Some(b"/etc/shadow".to_vec()));
        assert_eq!(literal_prefix("**/.env"), None);
        assert_eq!(literal_prefix("/*/x"), None);
        let r = rules(&["/**"], &["/workspace/secrets/**", "**/.env"], &[]);
        assert_eq!(
            r.holds_prefix(b"/workspace/secrets"),
            Some("/workspace/secrets/**")
        );
        assert_eq!(r.holds_prefix(b"/workspace"), Some("/workspace/secrets/**"));
        assert_eq!(r.holds_prefix(b"/"), Some("/workspace/secrets/**"));
        assert_eq!(r.holds_prefix(b"/workspace/secrets/a"), None);
        assert_eq!(r.holds_prefix(b"/workspace/sec"), None);
        assert_eq!(r.holds_prefix(b"/workspace/app"), None);
        assert_eq!(
            rules(&["/**"], &["**/.env"], &[]).holds_prefix(b"/workspace"),
            None
        );
    }

    /// Paths are bytes: a name that is not UTF-8 matches as any other.
    #[test]
    fn paths_that_are_not_utf8_match() {
        let r = rules(&["/workspace/**"], &["/workspace/s*"], &[]);
        assert!(r.writable(b"/workspace/\xff\xfe"));
        assert_eq!(r.denied(b"/workspace/s\xff"), Some("/workspace/s*"));
    }

    /// An exec deny holds unless an exec exception matches the same name.
    #[test]
    fn exec_deny_and_its_exceptions() {
        let spec = PathSpec {
            writable: strings(&["/**"]),
            denied: Vec::new(),
            exec_deny: strings(&["**/nc", "/usr/bin/{socat,telnet}"]),
        };
        let r = PathRules::new(&spec, &[], &[]).unwrap();
        assert_eq!(r.exec_denied(b"/usr/bin/nc"), Some("**/nc"));
        assert_eq!(r.exec_denied(b"/workspace/nc"), Some("**/nc"));
        assert_eq!(
            r.exec_denied(b"/usr/bin/telnet"),
            Some("/usr/bin/{socat,telnet}")
        );
        assert_eq!(r.exec_denied(b"/usr/bin/ncat"), None);
        let lifted = PathRules::new(&spec, &[], &strings(&["/workspace/**"])).unwrap();
        assert_eq!(lifted.exec_denied(b"/workspace/nc"), None);
        assert_eq!(lifted.exec_denied(b"/usr/bin/nc"), Some("**/nc"));
    }

    /// A writable exception adds to `writable`.
    #[test]
    fn writable_exceptions_add() {
        let spec = PathSpec {
            writable: strings(&["/workspace/**"]),
            ..PathSpec::default()
        };
        let r = PathRules::new(&spec, &strings(&["/etc/**"]), &[]).unwrap();
        assert!(r.writable(b"/etc/hosts"));
        assert!(r.writable(b"/workspace/a"));
        assert!(!r.writable(b"/usr/a"));
        assert!(matches!(
            PathRules::new(&spec, &strings(&["etc"]), &[]),
            Err(GlobError::Relative(_))
        ));
    }

    /// Allow-all checks nothing.
    #[test]
    fn allow_all_checks_nothing() {
        let r = PathRules::allow_all();
        assert!(!r.enforcing());
        assert!(!r.denies_anything());
        assert!(r.writable(b"/etc/x"));
        assert_eq!(r.denied(b"/etc/x"), None);
        assert_eq!(r.exec_denied(b"/usr/bin/nc"), None);
        assert!(rules(&[], &["/x"], &[]).denies_anything());
        assert!(!rules(&["/**"], &[], &["**/nc"]).denies_anything());
    }
}
