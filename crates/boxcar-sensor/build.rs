// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Builds the eBPF programs (`crates/boxcar-sensor-ebpf`) for
//! `bpfel-unknown-none` on the pinned nightly and leaves the object at
//! `OUT_DIR/boxcar-sensor`, where `src/object.rs` embeds it. With
//! `AYA_BUILD_SKIP=1` (CI's stable lane) the object is empty and the sensor
//! runs degraded.

use std::path::Path;
use std::process::Command;
use std::{env, fs};

use anyhow::{bail, ensure, Context, Result};
use aya_build::{build_ebpf, Package, Toolchain};

/// The toolchain the eBPF crate needs; `crates/boxcar-sensor-ebpf/rust-toolchain.toml`
/// names the same one.
const TOOLCHAIN: &str = "nightly-2026-06-01";
/// The eBPF package, and the name of the binary it builds.
const EBPF_PACKAGE: &str = "boxcar-sensor-ebpf";
const EBPF_BIN: &str = "boxcar-sensor";

fn main() -> Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR")?;
    let out_dir = env::var("OUT_DIR").context("OUT_DIR")?;
    let object = Path::new(&out_dir).join(EBPF_BIN);
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    if skip_requested() {
        fs::write(&object, []).with_context(|| format!("write {}", object.display()))?;
        println!("cargo:warning=AYA_BUILD_SKIP is set: boxcar-sensor carries no eBPF programs");
        return Ok(());
    }
    toolchain_present()?;
    let ebpf_dir = Path::new(&manifest_dir)
        .parent()
        .context("the crate directory has no parent")?
        .join(EBPF_PACKAGE);
    let root_dir = ebpf_dir
        .to_str()
        .context("the eBPF crate's path is not UTF-8")?;
    // aya-build runs `cargo build --package boxcar-sensor-ebpf` where this
    // script runs, which is inside the workspace, and the eBPF crate is
    // excluded from it on purpose (it builds for another target on another
    // toolchain). Run from the crate's own directory, where cargo sees it
    // as the package it is; the target directory aya-build passes is
    // absolute, under OUT_DIR, so nothing else moves.
    env::set_current_dir(&ebpf_dir).with_context(|| format!("enter {}", ebpf_dir.display()))?;
    build_ebpf(
        [Package {
            name: EBPF_PACKAGE,
            root_dir,
            ..Default::default()
        }],
        Toolchain::Custom(TOOLCHAIN),
    )?;
    ensure!(
        object.is_file(),
        "aya-build left no {} behind",
        object.display()
    );
    Ok(())
}

/// `AYA_BUILD_SKIP` is `1` or `true`, as aya-build itself reads it.
fn skip_requested() -> bool {
    env::var("AYA_BUILD_SKIP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Fails with the install line when the pinned nightly is not there, which
/// beats aya-build's own error about `rustup run`.
fn toolchain_present() -> Result<()> {
    let status = Command::new("rustup")
        .args(["run", TOOLCHAIN, "rustc", "--version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => bail!(
            "the eBPF programs need the {TOOLCHAIN} toolchain with rust-src and bpf-linker: \
             run `rustup toolchain install {TOOLCHAIN} --profile minimal --component rust-src` \
             and `cargo binstall --no-confirm bpf-linker@0.11.1`, or set AYA_BUILD_SKIP=1 to \
             build a sensor with no programs"
        ),
    }
}
