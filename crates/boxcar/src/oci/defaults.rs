// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What a session runs: the command line first, the image second,
//! boxcar's defaults last, in `argv`, `env` and `cwd` alike.
//!
//! An image's defaults are untrusted input: bounded in size, each `Env`
//! entry a `NAME=VALUE`, the working directory absolute, and none of their
//! text repeated in an error. The environment is merged to one value per
//! name, the last given winning: init keeps the environment as given and
//! takes the first `PATH` it finds, so appending could not give the image
//! its `PATH` over the default, nor `--env` its over the image's.

use std::collections::HashMap;

use boxcar_proto::guest::DEFAULT_ARGV;

use super::store::Defaults;

/// The most text an image's defaults may hold together: `env`,
/// `entrypoint`, `cmd` and `working_dir`. The session's config travels as
/// one line of the guest channel (64 KiB).
pub const MAX_DEFAULTS: usize = 32 * 1024;

/// Why an image's defaults are refused. Fixed sentences: nothing of the
/// image's text is repeated.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DefaultsError {
    #[error("the image's defaults are larger than 32 KiB")]
    TooLarge,
    #[error("an entry of the image's environment is not NAME=VALUE")]
    EnvEntry,
    #[error("the image's working directory is not an absolute path")]
    WorkingDir,
    #[error("the image's defaults hold a NUL byte")]
    Nul,
}

/// What the session runs, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub argv: Vec<String>,
    /// One value per name, in first-seen order.
    pub env: Vec<(String, String)>,
    /// Absolute.
    pub cwd: String,
}

/// Checks an image's defaults against the bounds.
pub fn check(image: &Defaults) -> Result<(), DefaultsError> {
    let text: usize = image.env.iter().map(String::len).sum::<usize>()
        + image.entrypoint.iter().map(String::len).sum::<usize>()
        + image.cmd.iter().map(String::len).sum::<usize>()
        + image.working_dir.len();
    if text > MAX_DEFAULTS {
        return Err(DefaultsError::TooLarge);
    }
    let all = image
        .env
        .iter()
        .chain(&image.entrypoint)
        .chain(&image.cmd)
        .chain(std::iter::once(&image.working_dir));
    for text in all {
        if text.contains('\0') {
            return Err(DefaultsError::Nul);
        }
    }
    for entry in &image.env {
        match entry.split_once('=') {
            Some((name, _)) if !name.is_empty() => {}
            _ => return Err(DefaultsError::EnvEntry),
        }
    }
    if !image.working_dir.is_empty() && !image.working_dir.starts_with('/') {
        return Err(DefaultsError::WorkingDir);
    }
    Ok(())
}

/// Resolves what the session runs: `command` from the command line (empty
/// for none), `image`'s defaults when there is an image, `base` boxcar's
/// own environment, `flags` the `--env` pairs, in that order of precedence
/// from last to first.
pub fn resolve(
    command: &[String],
    image: Option<&Defaults>,
    base: Vec<(String, String)>,
    flags: &[(String, String)],
) -> Result<Resolved, DefaultsError> {
    if let Some(image) = image {
        check(image)?;
    }
    let argv = if !command.is_empty() {
        command.to_vec()
    } else {
        let from_image: Vec<String> = image
            .map(|i| i.entrypoint.iter().chain(&i.cmd).cloned().collect())
            .unwrap_or_default();
        if from_image.is_empty() {
            DEFAULT_ARGV.map(str::to_owned).to_vec()
        } else {
            from_image
        }
    };
    let mut env = base;
    if let Some(image) = image {
        env.extend(image.env.iter().map(|entry| {
            let (name, value) = entry.split_once('=').expect("checked");
            (name.to_owned(), value.to_owned())
        }));
    }
    env.extend(flags.iter().cloned());
    let cwd = match image {
        Some(image) if !image.working_dir.is_empty() => image.working_dir.clone(),
        _ => "/workspace".to_owned(),
    };
    Ok(Resolved {
        argv,
        env: merge(env),
        cwd,
    })
}

/// One value per name, the last given winning, in the order the names were
/// first seen.
pub fn merge(env: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in env {
        match at.get(&name) {
            Some(&i) => out[i].1 = value,
            None => {
                at.insert(name.clone(), out.len());
                out.push((name, value));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Vec<(String, String)> {
        [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/workspace"),
            ("TERM", "xterm"),
        ]
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
    }

    fn pairs(env: &[(String, String)]) -> Vec<String> {
        env.iter().map(|(n, v)| format!("{n}={v}")).collect()
    }

    fn image(env: &[&str], entrypoint: &[&str], cmd: &[&str], working_dir: &str) -> Defaults {
        Defaults {
            env: env.iter().map(|s| (*s).to_owned()).collect(),
            entrypoint: entrypoint.iter().map(|s| (*s).to_owned()).collect(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            working_dir: working_dir.to_owned(),
            user: "nobody".to_owned(),
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_command_line_wins_then_the_image_then_the_defaults() {
        let img = image(
            &["PATH=/opt/bin:/usr/bin", "FOO=from-image", "HOME=/srv"],
            &["/bin/sh", "-c"],
            &["echo from-image"],
            "/srv/app",
        );
        // No command, no flags: the image's entrypoint and cmd, its env over
        // the defaults, its working directory.
        let r = resolve(&[], Some(&img), base(), &[]).unwrap();
        assert_eq!(r.argv, strings(&["/bin/sh", "-c", "echo from-image"]));
        assert_eq!(
            pairs(&r.env),
            [
                "PATH=/opt/bin:/usr/bin",
                "HOME=/srv",
                "TERM=xterm",
                "FOO=from-image"
            ]
        );
        assert_eq!(r.cwd, "/srv/app");
        // A command replaces entrypoint and cmd both; --env wins over the image.
        let flags = [
            ("PATH".to_owned(), "/bin".to_owned()),
            ("NEW".to_owned(), "1".to_owned()),
        ];
        let r = resolve(&strings(&["ls", "-l"]), Some(&img), base(), &flags).unwrap();
        assert_eq!(r.argv, strings(&["ls", "-l"]));
        assert_eq!(
            pairs(&r.env),
            [
                "PATH=/bin",
                "HOME=/srv",
                "TERM=xterm",
                "FOO=from-image",
                "NEW=1"
            ]
        );
        assert_eq!(r.env.iter().filter(|(n, _)| n == "PATH").count(), 1);
    }

    #[test]
    fn without_an_image_the_defaults_and_flags_apply_and_are_merged() {
        let flags = [
            ("TERM".to_owned(), "vt100".to_owned()),
            ("TERM".to_owned(), "vt220".to_owned()),
        ];
        let r = resolve(&[], None, base(), &flags).unwrap();
        assert_eq!(r.argv, strings(&["/bin/sh", "-l"]));
        assert_eq!(
            pairs(&r.env),
            ["PATH=/usr/bin:/bin", "HOME=/workspace", "TERM=vt220"]
        );
        assert_eq!(r.cwd, "/workspace");
    }

    #[test]
    fn an_image_may_give_only_an_entrypoint_or_only_a_command_or_neither() {
        let only_entry = image(&[], &["/app"], &[], "");
        assert_eq!(
            resolve(&[], Some(&only_entry), base(), &[]).unwrap().argv,
            strings(&["/app"])
        );
        let only_cmd = image(&[], &[], &["run", "--fast"], "");
        assert_eq!(
            resolve(&[], Some(&only_cmd), base(), &[]).unwrap().argv,
            strings(&["run", "--fast"])
        );
        let neither = image(&[], &[], &[], "");
        let r = resolve(&[], Some(&neither), base(), &[]).unwrap();
        assert_eq!(r.argv, strings(&["/bin/sh", "-l"]));
        assert_eq!(r.cwd, "/workspace");
        // A value may hold `=`; an empty value is a value.
        let eq = image(&["A=b=c", "EMPTY="], &[], &[], "");
        let r = resolve(&[], Some(&eq), base(), &[]).unwrap();
        assert!(pairs(&r.env).contains(&"A=b=c".to_owned()));
        assert!(pairs(&r.env).contains(&"EMPTY=".to_owned()));
    }

    #[test]
    fn malformed_and_oversized_defaults_are_refused_in_fixed_words() {
        let secret = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ";
        let no_eq = image(&[secret], &[], &[], "");
        let err = resolve(&[], Some(&no_eq), base(), &[]).unwrap_err();
        assert_eq!(err, DefaultsError::EnvEntry);
        assert!(!err.to_string().contains("Basic"));
        let empty_name = image(&["=x"], &[], &[], "");
        assert_eq!(check(&empty_name), Err(DefaultsError::EnvEntry));
        let relative = image(&[], &[], &[], &format!("app/{secret}"));
        let err = check(&relative).unwrap_err();
        assert_eq!(err, DefaultsError::WorkingDir);
        assert!(!err.to_string().contains("Basic"));
        let nul = image(&["A=b\0c"], &[], &[], "");
        assert_eq!(check(&nul), Err(DefaultsError::Nul));
        // 32 KiB exactly is accepted; one byte more is not.
        let fill = |n: usize| "x".repeat(n);
        let at_limit = image(&[&format!("A={}", fill(MAX_DEFAULTS - 2))], &[], &[], "");
        assert_eq!(check(&at_limit), Ok(()));
        let over = image(&[&format!("A={}", fill(MAX_DEFAULTS - 1))], &[], &[], "");
        assert_eq!(check(&over), Err(DefaultsError::TooLarge));
        let spread = image(
            &[&format!("A={}", fill(MAX_DEFAULTS / 2))],
            &[&fill(MAX_DEFAULTS / 2)],
            &["x"],
            "",
        );
        assert_eq!(check(&spread), Err(DefaultsError::TooLarge));
    }

    #[test]
    fn merging_keeps_first_seen_order_and_last_value() {
        let env: Vec<(String, String)> =
            [("A", "1"), ("B", "2"), ("A", "3"), ("C", "4"), ("B", "5")]
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect();
        assert_eq!(pairs(&merge(env)), ["A=3", "B=5", "C=4"]);
    }
}
