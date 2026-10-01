// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar doctor`: checks that this machine can build and run boxcar.
//!
//! One line per check: `OK   <check>`, `FAIL <check>: <hint>` for a required
//! check that failed, or `MISS <check>: <hint>` for something that is not
//! there yet or is optional. A final `doctor: <n> failed` line counts the
//! FAIL lines, and the exit code is 1 when there are any.

use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, ExitCode};

use boxcar_vmm::kvm::{
    Cap, KvmContext, KvmError, KVM_API_VERSION, KVM_DEVICE, KVM_OPEN_HINT, REQUIRED_CAPS,
};

const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";

/// Build outputs the run command needs, with how to make each. Relative to the
/// directory `boxcar doctor` runs in, like the build tasks that write them.
const GUEST_ARTIFACTS: &[(&str, &str)] = &[
    ("target/guest/vmlinux", "run: cargo xtask kernel"),
    ("target/guest/initramfs.cpio", "run: cargo xtask initramfs"),
];

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Ok,
    /// A required check failed; the hint says how to fix it.
    Fail(String),
    /// Absent, but not a failure.
    Missing(String),
}

#[derive(Debug, PartialEq, Eq)]
struct Check {
    name: String,
    status: Status,
}

impl Check {
    fn ok(name: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: Status::Ok,
        }
    }

    fn fail(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: Status::Fail(hint.into()),
        }
    }

    fn missing(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: Status::Missing(hint.into()),
        }
    }

    fn failed(&self) -> bool {
        matches!(self.status, Status::Fail(_))
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.status {
            Status::Ok => write!(f, "OK   {}", self.name),
            Status::Fail(hint) => write!(f, "FAIL {}: {hint}", self.name),
            Status::Missing(hint) => write!(f, "MISS {}: {hint}", self.name),
        }
    }
}

/// `boxcar doctor`. Prints every check, then the failure count; exits 1 when
/// any required check failed.
pub fn run() -> anyhow::Result<ExitCode> {
    let mut checks = kvm_checks(KvmContext::open());
    checks.push(docker_check());
    checks.push(musl_check(run_argv(
        "rustup",
        &["target", "list", "--installed"],
    )));
    for (path, hint) in GUEST_ARTIFACTS {
        checks.push(artifact_check(Path::new(path), hint));
    }
    checks.push(pahole_check());

    let mut out = io::stdout().lock();
    let failed = write_report(&mut out, &checks)?;
    out.flush()?;
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Writes one line per check and the summary; returns the number of FAILs.
fn write_report(out: &mut impl Write, checks: &[Check]) -> io::Result<usize> {
    for check in checks {
        writeln!(out, "{check}")?;
    }
    let failed = checks.iter().filter(|check| check.failed()).count();
    writeln!(out, "doctor: {failed} failed")?;
    Ok(failed)
}

/// The device, API version and capability checks, from what opening KVM
/// produced. The checks that cannot run without a usable KVM fail with a
/// pointer to the one that broke.
fn kvm_checks(opened: Result<KvmContext, KvmError>) -> Vec<Check> {
    let device = "/dev/kvm readable and writable";
    let api = format!("KVM API version {KVM_API_VERSION}");
    match opened {
        Ok(ctx) => {
            let mut checks = vec![Check::ok(device), Check::ok(api)];
            checks.extend(cap_checks(&ctx.missing_caps()));
            checks
        }
        Err(KvmError::Open(error)) => {
            let mut checks = vec![Check::fail(device, format!("{error}; {KVM_OPEN_HINT}"))];
            let reason = format!("not checked: {KVM_DEVICE} cannot be opened");
            checks.push(Check::fail(api, reason.clone()));
            checks.extend(cap_checks_unchecked(&reason));
            checks
        }
        Err(KvmError::ApiVersion(found)) => {
            let mut checks = vec![
                Check::ok(device),
                Check::fail(
                    api,
                    format!(
                        "this host reports version {found}; boxcar needs {KVM_API_VERSION}, \
                         update the host kernel (WSL2: wsl --update)"
                    ),
                ),
            ];
            checks.extend(cap_checks_unchecked(
                "not checked: unsupported KVM API version",
            ));
            checks
        }
        Err(KvmError::MissingCaps(missing)) => {
            let mut checks = vec![Check::ok(device), Check::ok(api)];
            checks.extend(cap_checks(&missing));
            checks
        }
    }
}

/// One check per required capability: FAIL for each one in `missing`.
fn cap_checks(missing: &[Cap]) -> Vec<Check> {
    REQUIRED_CAPS
        .iter()
        .map(|cap| {
            let name = cap_name(cap);
            if missing.contains(cap) {
                Check::fail(
                    name,
                    "this host's KVM lacks it; update the host kernel (WSL2: wsl --update)",
                )
            } else {
                Check::ok(name)
            }
        })
        .collect()
}

/// One FAIL per required capability, for when KVM could not be queried.
fn cap_checks_unchecked(reason: &str) -> Vec<Check> {
    REQUIRED_CAPS
        .iter()
        .map(|cap| Check::fail(cap_name(cap), reason))
        .collect()
}

fn cap_name(cap: &Cap) -> String {
    format!("KVM capability {cap:?}")
}

/// `docker info` reaches a running daemon.
fn docker_check() -> Check {
    let name = "docker info";
    match run_argv("docker", &["info", "--format", "{{.ServerVersion}}"]) {
        Ok(_) => Check::ok(name),
        Err(reason) => Check::fail(
            name,
            format!(
                "{reason}; install Docker and start the daemon, or add your user to the \
                 docker group (the guest kernel and initramfs are built in a container)"
            ),
        ),
    }
}

/// `listing` is the output of `rustup target list --installed`.
fn musl_check(listing: Result<String, String>) -> Check {
    let name = format!("rust target {MUSL_TARGET} installed");
    match listing {
        Ok(listing) if listing.lines().any(|line| line.trim() == MUSL_TARGET) => Check::ok(name),
        Ok(_) => Check::fail(name, format!("run: rustup target add {MUSL_TARGET}")),
        Err(reason) => Check::fail(
            name,
            format!(
                "{reason}; install rustup (https://rustup.rs), \
                 then run: rustup target add {MUSL_TARGET}"
            ),
        ),
    }
}

/// A build output that is present or not yet built. Never a failure.
fn artifact_check(path: &Path, hint: &str) -> Check {
    let name = path.display().to_string();
    if path.is_file() {
        Check::ok(name)
    } else {
        Check::missing(name, hint)
    }
}

/// `pahole` is informational: found or not, nothing fails.
fn pahole_check() -> Check {
    let name = "pahole (informational)";
    // Any spawn that succeeds proves it is on PATH, whatever its exit status.
    match Command::new("pahole").arg("--version").output() {
        Ok(_) => Check::ok(name),
        Err(_) => Check::missing(name, "not in PATH"),
    }
}

/// Runs `program args...` (an argv array, never a shell string) and returns
/// its stdout, or a one-line reason it did not succeed.
fn run_argv(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => format!("`{program}` not found in PATH"),
            _ => format!("cannot run `{program}`: {error}"),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr
            .lines()
            .next()
            .map_or_else(|| output.status.to_string(), |line| line.trim().to_string());
        return Err(format!("`{program} {}` failed: {detail}", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(checks: &[Check]) -> (Vec<String>, usize) {
        let mut out = Vec::new();
        let failed = write_report(&mut out, checks).unwrap();
        let text = String::from_utf8(out).unwrap();
        (text.lines().map(str::to_owned).collect(), failed)
    }

    #[test]
    fn report_has_one_line_per_check_and_counts_only_fails() {
        let (lines, failed) = lines(&[
            Check::ok("a"),
            Check::fail("b", "fix b"),
            Check::missing("c", "build c"),
            Check::fail("d", "fix d"),
        ]);
        assert_eq!(
            lines,
            [
                "OK   a",
                "FAIL b: fix b",
                "MISS c: build c",
                "FAIL d: fix d",
                "doctor: 2 failed",
            ]
        );
        assert_eq!(failed, 2);
    }

    #[test]
    fn report_with_no_fails_counts_zero() {
        let (lines, failed) = lines(&[Check::ok("a"), Check::missing("b", "build b")]);
        assert_eq!(lines.last().unwrap(), "doctor: 0 failed");
        assert_eq!(failed, 0);
    }

    #[test]
    fn unopenable_kvm_fails_every_kvm_check_and_carries_the_hint() {
        let error = io::Error::from(io::ErrorKind::PermissionDenied);
        let checks = kvm_checks(Err(KvmError::Open(error)));
        assert_eq!(checks.len(), 2 + REQUIRED_CAPS.len());
        assert!(checks.iter().all(Check::failed));
        let first = checks[0].to_string();
        assert!(
            first.starts_with("FAIL /dev/kvm readable and writable: "),
            "{first}"
        );
        assert!(
            first.contains("sudo setfacl -m u:$USER:rw /dev/kvm"),
            "{first}"
        );
    }

    #[test]
    fn wrong_api_version_fails_it_and_what_depends_on_it() {
        let checks = kvm_checks(Err(KvmError::ApiVersion(11)));
        assert_eq!(checks[0], Check::ok("/dev/kvm readable and writable"));
        assert!(checks[1].failed(), "{}", checks[1]);
        assert!(
            checks[1].to_string().contains("version 11"),
            "{}",
            checks[1]
        );
        assert!(checks[2..].iter().all(Check::failed));
    }

    #[test]
    fn missing_caps_fail_only_the_missing_ones() {
        let checks = cap_checks(&[Cap::Irqfd]);
        let failed: Vec<_> = checks.iter().filter(|c| c.failed()).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].name, "KVM capability Irqfd");
        assert_eq!(checks.len(), REQUIRED_CAPS.len());
    }

    #[test]
    fn musl_target_is_matched_as_a_whole_line() {
        let listing = "x86_64-unknown-linux-gnu\nx86_64-unknown-linux-musl\n";
        assert!(!musl_check(Ok(listing.to_owned())).failed());
        // A longer target name that merely contains ours does not count.
        let lookalike = "x86_64-unknown-linux-musl-fake\n";
        assert!(musl_check(Ok(lookalike.to_owned())).failed());
        assert!(musl_check(Err("`rustup` not found in PATH".to_owned())).failed());
    }

    #[test]
    fn missing_artifacts_are_missing_not_failed() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert_eq!(artifact_check(&here, "unused").status, Status::Ok);
        let absent = Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-artifact");
        let check = artifact_check(&absent, "run: cargo xtask kernel");
        assert!(!check.failed());
        assert!(check.to_string().starts_with("MISS "), "{check}");
        assert!(
            check.to_string().ends_with(": run: cargo xtask kernel"),
            "{check}"
        );
    }

    #[test]
    fn a_program_that_is_not_installed_is_reported_by_name() {
        let error = run_argv("boxcar-no-such-program", &[]).unwrap_err();
        assert_eq!(error, "`boxcar-no-such-program` not found in PATH");
    }
}
