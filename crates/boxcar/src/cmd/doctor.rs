// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar doctor`: checks that this machine can build and run boxcar.
//!
//! One line per check: `OK   <check>`, `FAIL <check>: <hint>` for a required
//! check that failed, or `MISS <check>: <hint>` for something that is not
//! there yet or is optional, such as an open file limit too low for the
//! network at its caps. A final `doctor: <n> failed` line counts the
//! FAIL lines, and the exit code is 1 when there are any.

use std::env;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use boxcar_vmm::kvm::{
    Cap, KvmContext, KvmError, KVM_API_VERSION, KVM_DEVICE, KVM_OPEN_HINT, REQUIRED_CAPS,
};

use super::nofile::{self, Limit};
use crate::oci::store::Store;

const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";

/// Build outputs the run command needs, with how to make each. Relative to the
/// directory `boxcar doctor` runs in, like the build tasks that write them.
const GUEST_ARTIFACTS: &[(&str, &str)] = &[
    ("target/guest/vmlinux", "run: cargo xtask kernel"),
    ("target/guest/initramfs.cpio", "run: cargo xtask initramfs"),
];

/// The kernel's release; under WSL it names Microsoft, as in
/// `6.18.54.1-microsoft-standard-WSL2`.
const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const CPUINFO: &str = "/proc/cpuinfo";
/// The seccomp filter return actions the kernel offers, by name.
const SECCOMP_ACTIONS: &str = "/proc/sys/kernel/seccomp/actions_avail";
/// `landlock_create_ruleset`'s flag that asks for the ABI version instead of
/// a ruleset.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
/// Free space for the image cache below this is reported missing: a pull of
/// a large image may not fit.
const CACHE_SPACE_LOW: u64 = 2 << 30;

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
    // Under WSL a missing `/dev/kvm` usually comes from this, so it goes first.
    let mut checks: Vec<Check> = wsl_check(
        &fs::read_to_string(OSRELEASE).unwrap_or_default(),
        fs::read_to_string(CPUINFO),
    )
    .into_iter()
    .collect();
    checks.extend(kvm_checks(KvmContext::open()));
    checks.push(docker_check());
    checks.push(musl_check(run_argv(
        "rustup",
        &["target", "list", "--installed"],
    )));
    for (path, hint) in GUEST_ARTIFACTS {
        checks.push(artifact_check(Path::new(path), hint));
    }
    checks.push(pahole_check());
    checks.push(nofile_check(nofile::current()));
    checks.push(landlock_check(landlock_abi()));
    checks.push(seccomp_check(fs::read_to_string(SECCOMP_ACTIONS)));
    let cache = super::image::default_cache_dir(env::var_os("XDG_CACHE_HOME"), env::var_os("HOME"));
    let space = cache.as_deref().map(|cache| {
        let dir = nearest_existing(cache);
        cache_space_check(dir, free_space(dir))
    });
    checks.push(cache_check(cache));
    checks.extend(space);

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

/// Nested virtualization under WSL2, from the kernel's release (`osrelease`,
/// empty when it cannot be read) and `/proc/cpuinfo`. KVM in a WSL2 VM needs
/// the CPU's virtualization extensions passed through from Windows, which
/// show as the `vmx` (Intel) or `svm` (AMD) flag. `None` off WSL, where the
/// `/dev/kvm` checks say all there is to say.
fn wsl_check(osrelease: &str, cpuinfo: io::Result<String>) -> Option<Check> {
    let release = osrelease.to_ascii_lowercase();
    if !release.contains("microsoft") && !release.contains("wsl") {
        return None;
    }
    let name = "WSL2 nested virtualization";
    let cpuinfo = match cpuinfo {
        Ok(cpuinfo) => cpuinfo,
        Err(error) => return Some(Check::fail(name, format!("cannot read {CPUINFO}: {error}"))),
    };
    Some(match virt_flag(&cpuinfo) {
        Some(flag) => Check::ok(format!("{name} ({flag} in {CPUINFO})")),
        None => Check::fail(
            name,
            format!(
                "neither vmx nor svm in {CPUINFO}, so there is no KVM; in Windows, put the \
                 lines [wsl2] and nestedVirtualization=true in %UserProfile%\\.wslconfig, \
                 run wsl --shutdown, then start WSL again (see docs/wsl2.md)"
            ),
        ),
    })
}

/// `vmx` or `svm`, whichever a `flags` line of `/proc/cpuinfo` lists.
fn virt_flag(cpuinfo: &str) -> Option<&'static str> {
    cpuinfo
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim() == "flags")
        .flat_map(|(_, flags)| flags.split_whitespace())
        .find_map(|flag| ["vmx", "svm"].into_iter().find(|&want| want == flag))
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

/// The image cache: missing until a pull makes it; otherwise how much it
/// holds.
fn cache_check(cache: Option<PathBuf>) -> Check {
    let Some(cache) = cache else {
        return Check::missing(
            "image cache",
            "neither XDG_CACHE_HOME nor HOME is an absolute path",
        );
    };
    let name = format!("image cache: {}", cache.display());
    if !cache.is_dir() {
        return Check::missing(name, "boxcar image pull REF makes it");
    }
    let listing = match Store::open(&cache).and_then(|store| store.list()) {
        Ok(listing) => listing,
        Err(error) => return Check::fail(name, error.to_string()),
    };
    Check::ok(format!(
        "{name} ({} images, {} tags)",
        listing.images.len(),
        listing.refs.len()
    ))
}

/// The free space where the image cache is, or will be made: `dir` is the
/// directory measured (the cache, or its nearest ancestor that exists) and
/// `free` the bytes `statvfs` says an unprivileged user may still write
/// there. Missing, not failed, below [`CACHE_SPACE_LOW`].
fn cache_space_check(dir: &Path, free: io::Result<u64>) -> Check {
    let place = format!("for the image cache, in {}", dir.display());
    match free {
        Ok(free) => {
            let name = format!("{:.1} GiB free {place}", free as f64 / (1u64 << 30) as f64);
            if free < CACHE_SPACE_LOW {
                Check::missing(
                    name,
                    "under 2 GiB, a pull of a large image may run out of space; free some, \
                     or point --cache-dir or XDG_CACHE_HOME at a larger filesystem",
                )
            } else {
                Check::ok(name)
            }
        }
        Err(error) => Check::missing(
            format!("free space {place}"),
            format!("cannot measure it: {error}"),
        ),
    }
}

/// `path`, or its nearest ancestor that exists: where a directory not made
/// yet would be made.
fn nearest_existing(path: &Path) -> &Path {
    path.ancestors().find(|dir| dir.exists()).unwrap_or(path)
}

/// The bytes an unprivileged user may still write on the filesystem that
/// holds `path`.
fn free_space(path: &Path) -> io::Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: statvfs is plain data, for which all zeroes is a value.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a statvfs buffer.
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// The open file limit `boxcar run` gives a VM with a network card (see
/// [`nofile`]), from the process's limit now: missing, not failed, when it
/// is below what the network needs at its caps.
fn nofile_check(limit: io::Result<Limit>) -> Check {
    match limit {
        Ok(limit) => {
            let run = nofile::target(limit);
            let name = format!(
                "open file limit {run} for boxcar run (soft {}, hard {})",
                limit.soft, limit.hard
            );
            match nofile::warning(run) {
                None => Check::ok(name),
                Some(warning) => Check::missing(name, warning),
            }
        }
        Err(error) => Check::missing("open file limit", format!("cannot read it: {error}")),
    }
}

/// The kernel's Landlock ABI version, as `landlock_create_ruleset` reports
/// it.
fn landlock_abi() -> io::Result<i64> {
    let size: libc::size_t = 0;
    // SAFETY: with no attributes (a null pointer, size 0) and the version
    // flag, the call reads no memory and makes no ruleset; it returns the
    // ABI version, or -1 and errno.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            size,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(abi)
}

/// Landlock, from the ABI version the kernel reports. Missing, never failed:
/// without a Landlock boxcar can use, `boxcar run` goes on without it and
/// records that it was unsupported.
fn landlock_check(abi: io::Result<i64>) -> Check {
    let without = "sessions run without Landlock";
    match abi {
        Ok(abi) if abi >= 2 => Check::ok(format!("Landlock ABI {abi}")),
        // ABI 1 has no REFER right: under a domain the kernel refuses every
        // rename or link from one directory to another.
        Ok(abi) => Check::missing(
            format!("Landlock ABI {abi}"),
            format!(
                "boxcar needs ABI 2 (Linux 5.19) or later: without its REFER right a rename \
                 or link across directories fails, so {without}"
            ),
        ),
        Err(error) => {
            let why = match error.raw_os_error() {
                Some(libc::ENOSYS) => "this kernel has none (older than Linux 5.13, or \
                                       built without CONFIG_SECURITY_LANDLOCK)"
                    .to_owned(),
                Some(libc::EOPNOTSUPP) => "this kernel has it but did not enable it at \
                                           boot: landlock is not in its lsm= list"
                    .to_owned(),
                _ => format!("cannot ask the kernel for its ABI: {error}"),
            };
            Check::missing("Landlock", format!("{why}; {without}"))
        }
    }
}

/// The seccomp actions `--seccomp` needs, from `actions` (the text of
/// `/proc/sys/kernel/seccomp/actions_avail`). Without
/// `SECCOMP_RET_KILL_PROCESS` it fails: `boxcar run`'s default is
/// `--seccomp enforce`, which kills the process on a call off the list, so a
/// default run cannot start. Without `SECCOMP_RET_LOG` only `--seccomp log`,
/// a mode asked for by name to build or check the list, cannot work, so that
/// is missing, not failed. A file that cannot be read fails too: whether the
/// default can work is then unknown.
fn seccomp_check(actions: io::Result<String>) -> Check {
    let name = "seccomp actions kill_process and log";
    let way_out = "update the kernel, or run with --seccomp off";
    let actions = match actions {
        Ok(actions) => actions,
        Err(error) => {
            return Check::fail(
                name,
                format!(
                    "cannot read {SECCOMP_ACTIONS}: {error}; a kernel with seccomp filters \
                     lists its actions there from Linux 4.14, and boxcar run's default, \
                     --seccomp enforce, needs SECCOMP_RET_KILL_PROCESS: {way_out}"
                ),
            )
        }
    };
    let has = |action: &str| actions.split_whitespace().any(|word| word == action);
    match (has("kill_process"), has("log")) {
        (true, true) => Check::ok(name),
        (false, log) => Check::fail(
            name,
            format!(
                "this kernel has no SECCOMP_RET_KILL_PROCESS{}, which boxcar run's default, \
                 --seccomp enforce, needs: {way_out}",
                if log { "" } else { " (nor SECCOMP_RET_LOG)" }
            ),
        ),
        (true, false) => Check::missing(
            name,
            "this kernel has no SECCOMP_RET_LOG, so --seccomp log cannot work; \
             --seccomp enforce, the default, can",
        ),
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
    fn the_open_file_limit_is_what_boxcar_run_would_set() {
        let check = nofile_check(Ok(Limit {
            soft: 1024,
            hard: 1 << 20,
        }));
        assert_eq!(
            check.to_string(),
            "OK   open file limit 65536 for boxcar run (soft 1024, hard 1048576)"
        );
        let low = nofile_check(Ok(Limit {
            soft: 1024,
            hard: 4096,
        }));
        assert!(!low.failed(), "a warning, not a failure");
        let text = low.to_string();
        assert!(
            text.starts_with("MISS open file limit 4096 for boxcar run (soft 1024, hard 4096): "),
            "{text}"
        );
        assert!(text.contains("6144"), "{text}");
        let unread = nofile_check(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(!unread.failed());
    }

    const WSL2: &str = "6.18.54.1-microsoft-standard-WSL2\n";
    const INTEL: &str = "processor\t: 0\nflags\t\t: fpu vme de pse vmx ssse3\nvmx flags\t: vnmi\n";
    const AMD: &str = "processor\t: 0\nflags\t\t: fpu vme svm sse4a\n";
    /// Neither flag on a `flags` line; lookalikes elsewhere.
    const NO_VIRT: &str =
        "processor\t: 0\nmodel name\t: vmx svm\nflags\t\t: fpu vmmcall svm_lock\n";

    #[test]
    fn wsl_with_vmx_or_svm_is_ok() {
        assert_eq!(
            wsl_check(WSL2, Ok(INTEL.to_owned())),
            Some(Check::ok(
                "WSL2 nested virtualization (vmx in /proc/cpuinfo)"
            ))
        );
        assert_eq!(
            wsl_check(WSL2, Ok(AMD.to_owned())),
            Some(Check::ok(
                "WSL2 nested virtualization (svm in /proc/cpuinfo)"
            ))
        );
        // The release is matched without regard to case.
        let check = wsl_check("4.4.0-19041-Microsoft\n", Ok(AMD.to_owned()));
        assert!(check.is_some_and(|check| !check.failed()));
    }

    #[test]
    fn wsl_without_vmx_or_svm_fails_with_the_wslconfig_lines() {
        let check = wsl_check(WSL2, Ok(NO_VIRT.to_owned())).unwrap();
        assert!(check.failed(), "{check}");
        let text = check.to_string();
        for want in [
            ".wslconfig",
            "[wsl2]",
            "nestedVirtualization=true",
            "wsl --shutdown",
            "docs/wsl2.md",
        ] {
            assert!(text.contains(want), "{want} not in {text}");
        }
        let unread = wsl_check(WSL2, Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(unread.is_some_and(|check| check.failed()));
    }

    #[test]
    fn off_wsl_there_is_no_nested_virtualization_line() {
        assert_eq!(
            wsl_check("6.14.0-33-generic\n", Ok(NO_VIRT.to_owned())),
            None
        );
        // An unreadable release is read as empty: not WSL, as far as is known.
        assert_eq!(wsl_check("", Ok(NO_VIRT.to_owned())), None);
    }

    #[test]
    fn landlock_abi_2_or_later_is_ok() {
        assert_eq!(landlock_check(Ok(2)).to_string(), "OK   Landlock ABI 2");
        assert_eq!(landlock_check(Ok(8)).to_string(), "OK   Landlock ABI 8");
    }

    #[test]
    fn landlock_abi_1_is_missing_for_want_of_refer() {
        let check = landlock_check(Ok(1));
        assert!(!check.failed(), "a session runs on without Landlock");
        let text = check.to_string();
        assert!(text.starts_with("MISS Landlock ABI 1: "), "{text}");
        assert!(text.contains("REFER"), "{text}");
    }

    #[test]
    fn no_landlock_is_missing_and_says_why() {
        let built_without = landlock_check(Err(io::Error::from_raw_os_error(libc::ENOSYS)));
        assert!(!built_without.failed());
        let text = built_without.to_string();
        assert!(text.starts_with("MISS Landlock: "), "{text}");
        assert!(text.contains("CONFIG_SECURITY_LANDLOCK"), "{text}");

        let not_enabled = landlock_check(Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        assert!(!not_enabled.failed());
        let text = not_enabled.to_string();
        assert!(text.contains("lsm="), "{text}");

        let other = landlock_check(Err(io::Error::from_raw_os_error(libc::EPERM)));
        assert!(!other.failed());
        assert!(other.to_string().contains("cannot ask"), "{other}");
    }

    #[test]
    fn seccomp_with_kill_process_and_log_is_ok() {
        // As Linux 6.18 lists them.
        let all = "kill_process kill_thread trap errno user_notif trace log allow\n";
        assert_eq!(
            seccomp_check(Ok(all.to_owned())).to_string(),
            "OK   seccomp actions kill_process and log"
        );
    }

    #[test]
    fn seccomp_without_kill_process_fails_and_points_at_seccomp_off() {
        // `kill_thread` is not `kill_process`.
        let check = seccomp_check(Ok("kill_thread trap errno trace log allow\n".to_owned()));
        assert!(check.failed(), "{check}");
        let text = check.to_string();
        assert!(text.contains("SECCOMP_RET_KILL_PROCESS"), "{text}");
        assert!(text.contains("--seccomp off"), "{text}");
        assert!(!text.contains("SECCOMP_RET_LOG"), "{text}");

        let neither = seccomp_check(Ok("kill_thread trap errno allow\n".to_owned()));
        assert!(neither.failed());
        assert!(neither.to_string().contains("SECCOMP_RET_LOG"), "{neither}");

        let unread = seccomp_check(Err(io::Error::from(io::ErrorKind::NotFound)));
        assert!(unread.failed());
        assert!(unread.to_string().contains("--seccomp off"), "{unread}");
    }

    #[test]
    fn seccomp_without_log_is_missing_not_failed() {
        let check = seccomp_check(Ok("kill_process kill_thread trap errno allow\n".to_owned()));
        assert!(!check.failed(), "enforce, the default, still works");
        let text = check.to_string();
        assert!(text.starts_with("MISS "), "{text}");
        assert!(text.contains("--seccomp log"), "{text}");
    }

    #[test]
    fn the_cache_has_room_from_2_gib_free() {
        let dir = Path::new("/home/u/.cache/boxcar");
        assert_eq!(
            cache_space_check(dir, Ok(10 << 30)).to_string(),
            "OK   10.0 GiB free for the image cache, in /home/u/.cache/boxcar"
        );
        assert!(!cache_space_check(dir, Ok(2 << 30))
            .to_string()
            .starts_with("MISS"));
        let low = cache_space_check(dir, Ok(3 << 29));
        assert!(!low.failed(), "a warning, not a failure");
        let text = low.to_string();
        assert!(
            text.starts_with("MISS 1.5 GiB free for the image cache, in /home/u/.cache/boxcar: "),
            "{text}"
        );
        assert!(text.contains("2 GiB"), "{text}");
        let unmeasured = cache_space_check(dir, Err(io::Error::from(io::ErrorKind::NotFound)));
        assert!(!unmeasured.failed());
        assert!(unmeasured.to_string().starts_with("MISS "), "{unmeasured}");
    }

    #[test]
    fn a_cache_not_made_yet_is_measured_at_its_nearest_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache/boxcar");
        assert_eq!(nearest_existing(&cache), tmp.path());
        std::fs::create_dir_all(&cache).unwrap();
        assert_eq!(nearest_existing(&cache), cache);
        // statvfs answers for the directory that exists.
        let free = free_space(nearest_existing(&tmp.path().join("not-made")));
        let check = cache_space_check(tmp.path(), free);
        assert!(
            check.name.ends_with(&format!(
                " for the image cache, in {}",
                tmp.path().display()
            )),
            "{check}"
        );
        assert!(!check.to_string().contains("cannot measure"), "{check}");
    }

    #[test]
    fn a_program_that_is_not_installed_is_reported_by_name() {
        let error = run_argv("boxcar-no-such-program", &[]).unwrap_err();
        assert_eq!(error, "`boxcar-no-such-program` not found in PATH");
    }
}
