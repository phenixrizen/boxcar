// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask kernel`: build the guest kernel.
//!
//! The build is `guest/kernel/build.sh`. By default it runs inside the
//! `boxcar-kernel-builder` Docker image (Debian trixie with pahole), as the
//! invoking user, with `guest/kernel` mounted read-only at `/src`,
//! `target/guest` at `/out` and `target/kernel-cache` at `/cache`. `--native`
//! runs the script on this host once `pahole` and the libelf headers are found.
//! Every command is an argv array; nothing goes through a shell.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use clap::Args;

/// Name of the Docker image `guest/kernel/Dockerfile` builds.
const IMAGE: &str = "boxcar-kernel-builder";

/// `CONFIG_DEBUG_INFO_BTF` needs this pahole (major, minor) or newer.
const MIN_PAHOLE: (u32, u32) = (1, 22);

/// Arguments of `cargo xtask kernel`.
#[derive(Args)]
pub struct KernelArgs {
    /// Build on this host instead of in the Docker builder image. Needs
    /// pahole 1.22 or newer and the libelf headers.
    #[arg(long)]
    native: bool,

    /// Number of parallel make jobs (default: the number of CPUs).
    #[arg(long, value_name = "N")]
    jobs: Option<NonZeroUsize>,
}

/// Builds the guest kernel and prints the blake3 of `target/guest/vmlinux`.
pub fn run(args: &KernelArgs) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;
    let kernel_dir = root.join("guest/kernel");
    let out_dir = root.join("target/guest");
    let cache_dir = root.join("target/kernel-cache");
    // Created here, as the invoking user: docker would create a missing bind
    // mount source as root.
    for dir in [&out_dir, &cache_dir] {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }

    if args.native {
        build_native(&kernel_dir, &out_dir, &cache_dir, args.jobs)?;
    } else {
        build_in_docker(&kernel_dir, &out_dir, &cache_dir, args.jobs)?;
    }

    // build.sh has already checked this; checking the artifact that was
    // actually written is what makes the result trustworthy.
    let fragment_path = kernel_dir.join("boxcar.fragment");
    let config_path = out_dir.join("kernel.config");
    let fragment = fs::read_to_string(&fragment_path)
        .with_context(|| format!("read {}", fragment_path.display()))?;
    let config = fs::read_to_string(&config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let misses = verify_fragment(&fragment, &config);
    ensure!(
        misses.is_empty(),
        "{} is missing fragment lines:\n  {}",
        config_path.display(),
        misses.join("\n  ")
    );

    let vmlinux = out_dir.join("vmlinux");
    println!("target/guest/vmlinux blake3: {}", blake3_of_file(&vmlinux)?);
    Ok(())
}

/// Builds the builder image and runs `build.sh` in it as the invoking user.
fn build_in_docker(
    kernel_dir: &Path,
    out_dir: &Path,
    cache_dir: &Path,
    jobs: Option<NonZeroUsize>,
) -> Result<()> {
    let mut build = Command::new("docker");
    build.args(["build", "-t", IMAGE]).arg(kernel_dir);
    run_checked(&mut build, "docker build")?;

    let uid = id_of("-u")?;
    let gid = id_of("-g")?;
    let mut run = Command::new("docker");
    run.args(docker_run_args(
        &uid, &gid, jobs, kernel_dir, out_dir, cache_dir,
    ));
    run_checked(&mut run, "docker run")
}

/// The arguments after `docker` that run the build: user-owned output, a
/// writable `HOME` (the kernel build writes `.cache` files) and the three
/// mounts. `--rm` leaves no container behind.
fn docker_run_args(
    uid: &str,
    gid: &str,
    jobs: Option<NonZeroUsize>,
    kernel_dir: &Path,
    out_dir: &Path,
    cache_dir: &Path,
) -> Vec<OsString> {
    let mount = |host: &Path, guest: &str| {
        let mut spec = host.as_os_str().to_owned();
        spec.push(":");
        spec.push(guest);
        spec
    };
    let mut args: Vec<OsString> = ["run", "--rm", "--user"]
        .into_iter()
        .map(OsString::from)
        .collect();
    args.push(format!("{uid}:{gid}").into());
    args.extend(["-e", "HOME=/cache"].map(OsString::from));
    if let Some(jobs) = jobs {
        args.extend(["-e".into(), format!("BOXCAR_KERNEL_JOBS={jobs}").into()]);
    }
    for (host, guest) in [
        (cache_dir, "/cache"),
        (kernel_dir, "/src:ro"),
        (out_dir, "/out"),
    ] {
        args.extend(["-v".into(), mount(host, guest)]);
    }
    args.extend([IMAGE, "bash", "/src/build.sh"].map(OsString::from));
    args
}

/// Runs `build.sh` on this host, after checking its tools are there.
fn build_native(
    kernel_dir: &Path,
    out_dir: &Path,
    cache_dir: &Path,
    jobs: Option<NonZeroUsize>,
) -> Result<()> {
    let mut missing = Vec::new();
    match pahole_version() {
        None => missing.push("pahole (package dwarves) is not installed".to_owned()),
        Some(version) if !pahole_is_new_enough(&version) => missing.push(format!(
            "pahole {version} is older than {}.{}",
            MIN_PAHOLE.0, MIN_PAHOLE.1
        )),
        Some(_) => {}
    }
    if !libelf_headers_present() {
        missing.push(
            "the libelf headers (libelf-dev, or elfutils-libelf-devel) are not installed"
                .to_owned(),
        );
    }
    if !missing.is_empty() {
        bail!(
            "cannot build the kernel natively:\n  {}\n\n\
             Build inside the Docker image instead, which needs only Docker:\n  \
             cargo xtask kernel",
            missing.join("\n  ")
        );
    }

    let mut build = Command::new("bash");
    build
        .arg(kernel_dir.join("build.sh"))
        .env("BOXCAR_KERNEL_SRC", kernel_dir)
        .env("BOXCAR_KERNEL_OUT", out_dir)
        .env("BOXCAR_KERNEL_CACHE", cache_dir);
    if let Some(jobs) = jobs {
        build.env("BOXCAR_KERNEL_JOBS", jobs.to_string());
    }
    run_checked(&mut build, "build.sh")
}

/// The version `pahole --version` prints (like `v1.30`), or `None` when pahole
/// cannot be run.
fn pahole_version() -> Option<String> {
    let output = Command::new("pahole").arg("--version").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Whether a `pahole --version` output (`v1.30`) is at least [`MIN_PAHOLE`].
fn pahole_is_new_enough(version: &str) -> bool {
    let mut parts = version.trim().trim_start_matches('v').split('.');
    let mut next = || parts.next()?.parse::<u32>().ok();
    match (next(), next()) {
        (Some(major), Some(minor)) => (major, minor) >= MIN_PAHOLE,
        _ => false,
    }
}

/// Whether libelf's development headers are installed: the header itself in a
/// standard prefix, or pkg-config knowing `libelf`.
fn libelf_headers_present() -> bool {
    ["/usr/include/libelf.h", "/usr/local/include/libelf.h"]
        .iter()
        .any(|header| Path::new(header).exists())
        || Command::new("pkg-config")
            .args(["--exists", "libelf"])
            .status()
            .is_ok_and(|status| status.success())
}

/// `id -u` or `id -g`: the numeric id to run the container as.
fn id_of(flag: &str) -> Result<String> {
    let output = Command::new("id")
        .arg(flag)
        .output()
        .with_context(|| format!("run `id {flag}`"))?;
    ensure!(output.status.success(), "`id {flag}` failed");
    let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    ensure!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "`id {flag}` printed {id:?}, expected a number"
    );
    Ok(id)
}

/// Runs `command` with inherited stdio and fails unless it exits 0.
fn run_checked(command: &mut Command, what: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed to start {what}"))?;
    ensure!(status.success(), "{what} failed: {status}");
    Ok(())
}

/// The hex blake3 of the file at `path`.
fn blake3_of_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(file)
        .with_context(|| format!("read {}", path.display()))?;
    Ok(hasher.finalize().to_hex().to_string())
}

/// The fragment lines that do not hold in `config`, in fragment order.
///
/// `CONFIG_X=y` and `CONFIG_X="..."` need that exact line in the config.
/// `CONFIG_X=n` needs `# CONFIG_X is not set`, or no `CONFIG_X=` line at all.
/// Blank lines and lines starting with `#` are comments. Any other line can
/// never be applied and is reported too. `guest/kernel/build.sh` runs the same
/// check in shell so the container build fails on its own.
pub fn verify_fragment(fragment: &str, config: &str) -> Vec<String> {
    let config_lines: HashSet<&str> = config.lines().collect();
    let assigned: HashSet<&str> = config
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    fragment
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| !is_applied(line, &config_lines, &assigned))
        .map(str::to_owned)
        .collect()
}

/// Whether one fragment line holds. `config_lines` is every line of the
/// config; `assigned` is the name left of `=` on each line that has one.
fn is_applied(line: &str, config_lines: &HashSet<&str>, assigned: &HashSet<&str>) -> bool {
    let Some((name, value)) = line.split_once('=') else {
        return false;
    };
    if !is_config_name(name) || value.is_empty() {
        return false;
    }
    if value == "n" {
        config_lines.contains(format!("# {name} is not set").as_str()) || !assigned.contains(name)
    } else {
        config_lines.contains(line)
    }
}

/// `CONFIG_` followed by at least one letter, digit or underscore.
fn is_config_name(name: &str) -> bool {
    name.strip_prefix("CONFIG_").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: &str = "\
# a comment, then a blank line

CONFIG_EXPERT=y
CONFIG_LSM=\"landlock,lockdown,yama,bpf\"
CONFIG_ACPI=n
CONFIG_IO_URING=n
";

    fn config(lines: &[&str]) -> String {
        lines.join("\n") + "\n"
    }

    #[test]
    fn applied_fragment_reports_no_misses() {
        let cfg = config(&[
            "CONFIG_EXPERT=y",
            "CONFIG_LSM=\"landlock,lockdown,yama,bpf\"",
            "# CONFIG_ACPI is not set",
            "# CONFIG_IO_URING is not set",
        ]);
        assert_eq!(verify_fragment(FRAGMENT, &cfg), Vec::<String>::new());
    }

    #[test]
    fn n_line_is_satisfied_by_an_absent_symbol() {
        let cfg = config(&[
            "CONFIG_EXPERT=y",
            "CONFIG_LSM=\"landlock,lockdown,yama,bpf\"",
        ]);
        assert_eq!(verify_fragment(FRAGMENT, &cfg), Vec::<String>::new());
    }

    #[test]
    fn y_line_misses_when_off_module_or_absent() {
        for cfg in [
            config(&["# CONFIG_EXPERT is not set"]),
            config(&["CONFIG_EXPERT=m"]),
            config(&["CONFIG_EXPERT_MORE=y"]),
            config(&[]),
        ] {
            let misses = verify_fragment("CONFIG_EXPERT=y\n", &cfg);
            assert_eq!(misses, ["CONFIG_EXPERT=y"], "config: {cfg:?}");
        }
    }

    #[test]
    fn string_line_needs_the_exact_value() {
        let fragment = "CONFIG_LSM=\"landlock,lockdown,yama,bpf\"\n";
        for cfg in [
            config(&["CONFIG_LSM=\"landlock,lockdown,yama,loadpin,bpf\""]),
            config(&["CONFIG_LSM=\"landlock,lockdown,yama,bpf\" "]),
            config(&["CONFIG_LSM=\"\""]),
            config(&[]),
        ] {
            assert_eq!(
                verify_fragment(fragment, &cfg),
                ["CONFIG_LSM=\"landlock,lockdown,yama,bpf\""],
                "config: {cfg:?}"
            );
        }
    }

    #[test]
    fn n_line_misses_when_the_symbol_is_set() {
        for cfg in [
            config(&["CONFIG_ACPI=y"]),
            config(&["CONFIG_ACPI=m"]),
            config(&["CONFIG_ACPI=\"x\""]),
        ] {
            assert_eq!(
                verify_fragment("CONFIG_ACPI=n\n", &cfg),
                ["CONFIG_ACPI=n"],
                "config: {cfg:?}"
            );
        }
    }

    #[test]
    fn n_line_ignores_symbols_that_share_a_prefix() {
        let cfg = config(&[
            "CONFIG_ACPI_APEI=y",
            "CONFIG_ACPIX=y",
            "# CONFIG_ACPI_X is not set",
        ]);
        assert_eq!(
            verify_fragment("CONFIG_ACPI=n\n", &cfg),
            Vec::<String>::new()
        );
    }

    #[test]
    fn misses_come_back_in_fragment_order_and_skip_comments() {
        let cfg = config(&[
            "CONFIG_EXPERT=y",
            "CONFIG_ACPI=y",
            "CONFIG_LSM=\"other\"",
            "# CONFIG_IO_URING is not set",
        ]);
        assert_eq!(
            verify_fragment(FRAGMENT, &cfg),
            ["CONFIG_LSM=\"landlock,lockdown,yama,bpf\"", "CONFIG_ACPI=n"]
        );
    }

    #[test]
    fn a_line_that_is_not_an_assignment_is_a_miss() {
        assert_eq!(
            verify_fragment("EXPERT=y\nCONFIG_EXPERT\n", "CONFIG_EXPERT=y\n"),
            ["EXPERT=y", "CONFIG_EXPERT"]
        );
    }

    #[test]
    fn pahole_version_gate() {
        for (version, ok) in [
            ("v1.30", true),
            ("v1.22", true),
            ("v1.22\n", true),
            ("v2.0", true),
            ("v1.21", false),
            ("v0.99", false),
            ("", false),
            ("pahole", false),
            ("v1", false),
        ] {
            assert_eq!(pahole_is_new_enough(version), ok, "version {version:?}");
        }
    }

    #[test]
    fn docker_run_mounts_and_user() {
        let args: Vec<String> = docker_run_args(
            "1000",
            "1001",
            NonZeroUsize::new(8),
            Path::new("/r/guest/kernel"),
            Path::new("/r/target/guest"),
            Path::new("/r/target/kernel-cache"),
        )
        .into_iter()
        .map(|arg| arg.into_string().unwrap())
        .collect();
        assert_eq!(
            args,
            [
                "run",
                "--rm",
                "--user",
                "1000:1001",
                "-e",
                "HOME=/cache",
                "-e",
                "BOXCAR_KERNEL_JOBS=8",
                "-v",
                "/r/target/kernel-cache:/cache",
                "-v",
                "/r/guest/kernel:/src:ro",
                "-v",
                "/r/target/guest:/out",
                "boxcar-kernel-builder",
                "bash",
                "/src/build.sh",
            ]
        );
    }

    #[test]
    fn docker_run_without_jobs_leaves_the_default_to_build_sh() {
        let args = docker_run_args(
            "1",
            "2",
            None,
            Path::new("/k"),
            Path::new("/o"),
            Path::new("/c"),
        );
        assert!(!args
            .iter()
            .any(|arg| arg.to_string_lossy().contains("BOXCAR_KERNEL_JOBS")));
    }
}
