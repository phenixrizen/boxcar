// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask test-kvm m1` and `m2`: a milestone's KVM-gated tests, on
//! this machine.
//!
//! First it checks what the tests need: `/dev/kvm`, open for reading and
//! writing, and the guest artifacts in `target/guest` (the kernel, the
//! initramfs and the Alpine rootfs). When something is missing it says
//! what, and which task builds it, and exits 0, as the tests would skip.
//! Otherwise it runs `cargo test` on the gated tests with
//! `BOXCAR_TEST_KERNEL`, `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS`
//! set to the artifacts, one test at a time (each boots a VM) and with
//! their output shown, so that a skip would be seen, and fails when they
//! fail. `cargo` runs as an argv array.
//!
//! Both milestones run the gated tests of `boxcar-vmm` and `boxcar` (the
//! packages are not separable by milestone); they differ in the network:
//! `m1` exports `BOXCAR_TEST_NET=0`, so the tests that reach example.com
//! skip, and `m2` exports `BOXCAR_TEST_NET=1` when this host resolves
//! example.com, `0` otherwise.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{ensure, Context, Result};
use clap::{Args, ValueEnum};

/// The device the gated tests boot their VMs with.
const KVM: &str = "/dev/kvm";

/// Arguments of `cargo xtask test-kvm`.
#[derive(Args)]
pub struct TestKvmArgs {
    /// The milestone whose gated tests to run.
    #[arg(value_enum)]
    milestone: Milestone,
}

/// A milestone with KVM-gated tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Milestone {
    /// M1: boot, the console session, the shares and their audit log, and
    /// the gated tests of the same packages that need no network (`boot_smp`,
    /// `boot_vsock`, `boot_session`, `boot_attach`, and the M2 end-to-end
    /// tests that stay on the host); the tests that reach example.com
    /// (`boot_net`, the networked `kvm_m2` tests) skip, with
    /// `BOXCAR_TEST_NET=0`.
    M1,
    /// M2: everything M1 runs, plus the tests that reach the network
    /// (`boot_net`: the guest's network under a policy; `kvm_m2`: the
    /// binary driving a VM with `--allow`, `status`, `stop`, `events` and
    /// `policy`), with `BOXCAR_TEST_NET=1` when this host resolves
    /// example.com (else `0`, and they skip saying why).
    M2,
    /// M3: everything M2 runs, with the sensor in the initramfs and the
    /// reconciler beside the log, plus the M3 end-to-end tests (`kvm_m3`).
    M3,
}

impl Milestone {
    fn name(self) -> &'static str {
        match self {
            Milestone::M1 => "m1",
            Milestone::M2 => "m2",
            Milestone::M3 => "m3",
        }
    }

    /// The `BOXCAR_TEST_NET` the milestone exports: `0` for M1, and for M2
    /// `1` when example.com resolves from this host.
    fn net_env(self) -> &'static str {
        match self {
            Milestone::M1 => "0",
            Milestone::M2 | Milestone::M3 => {
                if example_com_resolves() {
                    "1"
                } else {
                    "0"
                }
            }
        }
    }
}

/// Whether this host resolves example.com to an IPv4 address.
fn example_com_resolves() -> bool {
    use std::net::ToSocketAddrs;
    ("example.com", 80)
        .to_socket_addrs()
        .is_ok_and(|mut addrs| addrs.any(|a| a.is_ipv4()))
}

/// Runs `cargo xtask test-kvm`.
pub fn run(args: &TestKvmArgs) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;
    let guest = Artifacts::under(&root.join("target/guest"));
    if let Some(reason) = missing(&guest, kvm_access()) {
        println!("skipping test-kvm {}: {reason}", args.milestone.name());
        return Ok(());
    }
    let net = args.milestone.net_env();
    if args.milestone != Milestone::M1 && net == "0" {
        println!("test-kvm m2: this host does not resolve example.com; the network tests skip");
    }
    let status = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args(cargo_test_args(args.milestone))
        .envs(guest.env())
        .env("BOXCAR_TEST_NET", net)
        .current_dir(root)
        .status()
        .context("failed to start cargo test")?;
    ensure!(
        status.success(),
        "the {} gated tests failed: {status}",
        args.milestone.name()
    );
    Ok(())
}

/// The arguments after `cargo` that run `milestone`'s gated tests.
fn cargo_test_args(milestone: Milestone) -> Vec<OsString> {
    let args: &[&str] = match milestone {
        Milestone::M1 | Milestone::M2 | Milestone::M3 => &[
            "test",
            "-p",
            "boxcar-vmm",
            "-p",
            "boxcar",
            "--features",
            "boxcar-vmm/kvm-tests,boxcar/kvm-tests",
            "--",
            "--test-threads=1",
            "--nocapture",
        ],
    };
    args.iter().map(OsString::from).collect()
}

/// The guest artifacts the gated tests boot.
struct Artifacts {
    kernel: PathBuf,
    initramfs: PathBuf,
    rootfs: PathBuf,
}

impl Artifacts {
    /// Where the xtask builds put them in `guest_dir` (`target/guest`).
    fn under(guest_dir: &Path) -> Self {
        Artifacts {
            kernel: guest_dir.join("vmlinux"),
            initramfs: guest_dir.join("initramfs.cpio"),
            rootfs: guest_dir.join("rootfs-alpine"),
        }
    }

    /// The variables that tell the tests where they are.
    fn env(&self) -> [(&'static str, PathBuf); 3] {
        [
            ("BOXCAR_TEST_KERNEL", self.kernel.clone()),
            ("BOXCAR_TEST_INITRAMFS", self.initramfs.clone()),
            ("BOXCAR_TEST_ROOTFS", self.rootfs.clone()),
        ]
    }
}

/// Whether KVM can be used: `/dev/kvm` opens for reading and writing.
fn kvm_access() -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(KVM)
        .map(drop)
        .map_err(|e| format!("{KVM}: {e}"))
}

/// Why the gated tests cannot run, when they cannot: `kvm`'s failure, then
/// each artifact that is not there, with the task that builds it.
fn missing(guest: &Artifacts, kvm: Result<(), String>) -> Option<String> {
    let mut reasons: Vec<String> = kvm.err().into_iter().collect();
    for (path, is_there, task) in [
        (&guest.kernel, guest.kernel.is_file(), "cargo xtask kernel"),
        (
            &guest.initramfs,
            guest.initramfs.is_file(),
            "cargo xtask initramfs",
        ),
        (
            &guest.rootfs,
            guest.rootfs.is_dir(),
            "cargo xtask rootfs alpine",
        ),
    ] {
        if !is_there {
            reasons.push(format!("{} is missing ({task})", path.display()));
        }
    }
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect()
    }

    #[test]
    fn m1_runs_the_gated_tests_of_the_vmm_and_the_cli_one_at_a_time_with_output() {
        assert_eq!(
            strings(cargo_test_args(Milestone::M1)),
            [
                "test",
                "-p",
                "boxcar-vmm",
                "-p",
                "boxcar",
                "--features",
                "boxcar-vmm/kvm-tests,boxcar/kvm-tests",
                "--",
                "--test-threads=1",
                "--nocapture",
            ]
        );
    }

    #[test]
    fn m2_runs_the_same_packages_and_names_itself() {
        assert_eq!(
            strings(cargo_test_args(Milestone::M2)),
            strings(cargo_test_args(Milestone::M1))
        );
        assert_eq!(
            (
                Milestone::M1.name(),
                Milestone::M2.name(),
                Milestone::M3.name()
            ),
            ("m1", "m2", "m3")
        );
        assert_eq!(
            strings(cargo_test_args(Milestone::M3)),
            strings(cargo_test_args(Milestone::M2))
        );
        assert_eq!(Milestone::M3.net_env(), Milestone::M2.net_env());
        // M1 never reaches the network.
        assert_eq!(Milestone::M1.net_env(), "0");
        assert!(["0", "1"].contains(&Milestone::M2.net_env()));
    }

    #[test]
    fn the_tests_are_told_where_the_artifacts_are() {
        let guest = Artifacts::under(Path::new("/r/target/guest"));
        let vars = guest.env();
        let env: Vec<(&str, &Path)> = vars
            .iter()
            .map(|(var, path)| (*var, path.as_path()))
            .collect();
        assert_eq!(
            env,
            [
                ("BOXCAR_TEST_KERNEL", Path::new("/r/target/guest/vmlinux")),
                (
                    "BOXCAR_TEST_INITRAMFS",
                    Path::new("/r/target/guest/initramfs.cpio")
                ),
                (
                    "BOXCAR_TEST_ROOTFS",
                    Path::new("/r/target/guest/rootfs-alpine")
                ),
            ]
        );
    }

    #[test]
    fn with_kvm_and_the_artifacts_nothing_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("vmlinux"), b"").unwrap();
        fs::write(dir.path().join("initramfs.cpio"), b"").unwrap();
        fs::create_dir(dir.path().join("rootfs-alpine")).unwrap();
        assert_eq!(missing(&Artifacts::under(dir.path()), Ok(())), None);
    }

    #[test]
    fn what_is_missing_is_named_with_the_task_that_builds_it() {
        let dir = tempfile::tempdir().unwrap();
        // A rootfs that is a file is no rootfs.
        fs::write(dir.path().join("rootfs-alpine"), b"").unwrap();
        let guest = Artifacts::under(dir.path());
        let reason = missing(&guest, Err("/dev/kvm: Permission denied".into())).unwrap();
        let d = dir.path().display();
        assert_eq!(
            reason,
            format!(
                "/dev/kvm: Permission denied; \
                 {d}/vmlinux is missing (cargo xtask kernel); \
                 {d}/initramfs.cpio is missing (cargo xtask initramfs); \
                 {d}/rootfs-alpine is missing (cargo xtask rootfs alpine)"
            )
        );
        let reason = missing(&guest, Ok(())).unwrap();
        assert!(
            reason.starts_with(&format!("{d}/vmlinux is missing")),
            "{reason}"
        );
    }
}
