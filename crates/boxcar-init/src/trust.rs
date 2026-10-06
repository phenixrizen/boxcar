// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest's trust in the session CA, when the config carries one
//! (`SessionConfig::ca_pem`: the session's policy has an `inspect` rule,
//! and the gate will hand the guest certificates signed by that CA).
//!
//! Init, as root and before the session starts, writes the certificate to
//! [`CA_FILE`] on the `/run` tmpfs, builds [`BUNDLE_FILE`] from the root
//! share's own store ([`STORE`], followed through links as
//! [`crate::resolver`] follows `/etc/resolv.conf`) with the session CA
//! appended, and bind-mounts the bundle over the store, so every runtime
//! that reads the system store trusts the gate without being told. When
//! the root share has no store, the bundle is the CA alone, the store's
//! file is created in the share first if its directory is there (the host
//! records that), and if even the directory is missing nothing is bound
//! and the caller is told. [`ENV`] names the files for the runtimes that
//! read a variable rather than the store; `crate::pty::session_env` adds
//! them unless the config set them.
//!
//! The guest gets the certificate and nothing else: the key stays in the
//! VMM. A failure here costs the guest its trust in the gate (its inspected
//! connections then fail inside the guest), never its boot.

use std::path::Path;

use crate::console::Failed;
use crate::resolver::{follow, Kind, Lookup, Rooted, Step};

/// The directory on the `/run` tmpfs, shared with the resolver's file.
pub const DIR: &str = "/run/boxcar";
/// The session CA's certificate alone.
pub const CA_FILE: &str = "/run/boxcar/ca.pem";
/// The root share's store followed by the session CA.
pub const BUNDLE_FILE: &str = "/run/boxcar/ca-bundle.pem";
/// The system store the bundle is bound over, as Alpine and Debian keep it.
pub const STORE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// The variables the session gets, unless its config sets them.
pub const ENV: [(&str, &str); 5] = [
    ("NODE_EXTRA_CA_CERTS", CA_FILE),
    ("SSL_CERT_FILE", BUNDLE_FILE),
    ("CURL_CA_BUNDLE", BUNDLE_FILE),
    ("REQUESTS_CA_BUNDLE", BUNDLE_FILE),
    ("GIT_SSL_CAINFO", BUNDLE_FILE),
];

/// What installing the CA did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Installed {
    /// Whether the bundle was bound over the store (false when the root
    /// share has no `/etc/ssl/certs` to bind in).
    pub bound: bool,
}

/// The steps, and whether they bind the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub bound: bool,
}

/// The store's text, if any, followed by the session CA, each ending in a
/// newline.
pub fn bundle(store: Option<&str>, ca_pem: &str) -> String {
    let mut text = String::new();
    if let Some(store) = store {
        text.push_str(store);
        if !store.is_empty() && !store.ends_with('\n') {
            text.push('\n');
        }
    }
    text.push_str(ca_pem);
    if !ca_pem.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// The steps for `ca_pem` as `lookup` finds the guest's store (see the
/// module docs), or why the store's link cannot be followed or read.
pub fn plan(lookup: &impl Lookup, ca_pem: &str) -> Result<Plan, String> {
    let store = follow(lookup, Path::new(STORE))?;
    let mut steps = vec![
        Step::Mkdir {
            path: DIR.into(),
            mode: 0o755,
        },
        Step::Write {
            path: CA_FILE.into(),
            text: ca_pem.to_owned(),
            mode: 0o644,
        },
    ];
    let (existing, bound) = if store.exists {
        let text = lookup
            .read_to_string(&store.path)
            .map_err(|error| format!("read {}: {error}", store.path.display()))?;
        (Some(text), true)
    } else {
        // A store to create needs its directory; init makes no directories
        // in the root share.
        let dir_there = store
            .path
            .parent()
            .map(|dir| matches!(lookup.kind(dir), Ok(Kind::Other)))
            .unwrap_or(false);
        if dir_there {
            steps.push(Step::Touch {
                path: store.path.clone(),
                mode: 0o644,
            });
        }
        (None, dir_there)
    };
    steps.push(Step::Write {
        path: BUNDLE_FILE.into(),
        text: bundle(existing.as_deref(), ca_pem),
        mode: 0o644,
    });
    if bound {
        steps.push(Step::Bind {
            source: BUNDLE_FILE.into(),
            target: store.path,
        });
    }
    Ok(Plan { steps, bound })
}

/// Installs `ca_pem` in the guest's own `/`: the steps of [`plan`], in
/// order, up to the first that fails. Run after the switch to the root
/// share, before the session starts.
pub fn install(ca_pem: &str) -> Result<Installed, Failed> {
    let plan = plan(&Rooted::new(Path::new("/")), ca_pem)
        .map_err(|reason| Failed::new(&format!("follow {STORE}"), reason))?;
    plan.steps.iter().try_for_each(crate::resolver::run)?;
    Ok(Installed { bound: plan.bound })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    #[test]
    fn the_bundle_is_the_rootfs_store_followed_by_the_session_ca() {
        assert_eq!(
            bundle(
                Some("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"),
                CA
            ),
            format!("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n{CA}")
        );
        assert_eq!(bundle(Some("store\n"), CA), format!("store\n{CA}"));
        // A CA without its final newline gets one.
        assert_eq!(bundle(None, CA.trim_end()), CA);
    }

    #[test]
    fn a_rootfs_without_a_store_gets_the_ca_alone() {
        assert_eq!(bundle(None, CA), CA);
        assert_eq!(bundle(Some(""), CA), CA);
    }

    fn mkdir(path: &str) -> Step {
        Step::Mkdir {
            path: path.into(),
            mode: 0o755,
        }
    }

    fn write(path: &str, text: String) -> Step {
        Step::Write {
            path: path.into(),
            text,
            mode: 0o644,
        }
    }

    /// With a store, the bundle is the store plus the CA, bound over the
    /// store's real file (here through Alpine's `cert.pem` link too).
    #[test]
    fn a_store_is_read_appended_to_and_bound_over() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("etc/ssl/certs");
        fs::create_dir_all(&certs).unwrap();
        fs::write(certs.join("ca-certificates.crt"), "STORE\n").unwrap();
        symlink(
            "certs/ca-certificates.crt",
            dir.path().join("etc/ssl/cert.pem"),
        )
        .unwrap();
        let made = plan(&Rooted::new(dir.path()), CA).unwrap();
        assert!(made.bound);
        assert_eq!(
            made.steps,
            [
                mkdir(DIR),
                write(CA_FILE, CA.to_owned()),
                write(BUNDLE_FILE, format!("STORE\n{CA}")),
                Step::Bind {
                    source: BUNDLE_FILE.into(),
                    target: STORE.into(),
                },
            ]
        );
    }

    /// A store that is a link elsewhere is followed; the bind goes over
    /// where it leads.
    #[test]
    fn a_linked_store_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc/ssl/certs")).unwrap();
        fs::create_dir_all(dir.path().join("usr/share/ca")).unwrap();
        fs::write(dir.path().join("usr/share/ca/bundle.crt"), "S").unwrap();
        symlink(
            "/usr/share/ca/bundle.crt",
            dir.path().join("etc/ssl/certs/ca-certificates.crt"),
        )
        .unwrap();
        let made = plan(&Rooted::new(dir.path()), CA).unwrap();
        assert_eq!(
            made.steps[2..],
            [
                write(BUNDLE_FILE, format!("S\n{CA}")),
                Step::Bind {
                    source: BUNDLE_FILE.into(),
                    target: "/usr/share/ca/bundle.crt".into(),
                },
            ]
        );
    }

    /// No store but its directory: the file is created in the share and
    /// bound over. No directory either: nothing is bound, and the caller
    /// is told.
    #[test]
    fn a_missing_store_is_created_when_its_directory_is_there() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc/ssl/certs")).unwrap();
        let made = plan(&Rooted::new(dir.path()), CA).unwrap();
        assert!(made.bound);
        assert_eq!(
            made.steps,
            [
                mkdir(DIR),
                write(CA_FILE, CA.to_owned()),
                Step::Touch {
                    path: STORE.into(),
                    mode: 0o644,
                },
                write(BUNDLE_FILE, CA.to_owned()),
                Step::Bind {
                    source: BUNDLE_FILE.into(),
                    target: STORE.into(),
                },
            ]
        );
        let bare = tempfile::tempdir().unwrap();
        let made = plan(&Rooted::new(bare.path()), CA).unwrap();
        assert!(!made.bound);
        assert_eq!(
            made.steps,
            [
                mkdir(DIR),
                write(CA_FILE, CA.to_owned()),
                write(BUNDLE_FILE, CA.to_owned()),
            ]
        );
    }

    #[test]
    fn the_variables_name_the_certificate_and_the_bundle() {
        assert_eq!(ENV[0], ("NODE_EXTRA_CA_CERTS", CA_FILE));
        assert!(ENV[1..].iter().all(|(_, value)| *value == BUNDLE_FILE));
        assert!(CA_FILE.starts_with(DIR) && BUNDLE_FILE.starts_with(DIR));
    }
}
