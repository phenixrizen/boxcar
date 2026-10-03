// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask sensor`: the eBPF lane. Builds `boxcar-sensor` for the
//! guest (musl, the `guest` profile) with its real eBPF programs, which
//! needs the pinned nightly and `bpf-linker`, then parses the object the
//! build embedded and checks it against the table in
//! `boxcar_sensor_common::programs`: every program with its kind, every
//! map with its type, the globals' data section, and the `Dual MIT/GPL`
//! licence. It loads nothing; the gated tests of the sensor do that in a
//! guest. CI runs it in the `ebpf` job, while the `check` job builds the
//! sensor with `AYA_BUILD_SKIP=1` and a stable toolchain alone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{ensure, Context, Result};
use aya_obj::{Object, ProgramSection};
use boxcar_sensor_common::programs::{ProgramKind, GLOBALS, LICENSE, MAPS, PROGRAMS};

/// Where cargo puts the guest build of the sensor, under the repository.
const GUEST_BUILD_DIR: &str = "target/x86_64-unknown-linux-musl/guest/build";

/// What a check of the object found, for the report.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// Each program and the section kind it was built into.
    pub programs: Vec<(String, String)>,
    /// Each map and its type number.
    pub maps: Vec<(String, u32)>,
    pub license: String,
    /// The bytes of the globals' data section.
    pub globals_bytes: usize,
}

/// `cargo xtask sensor`: see the module docs.
pub fn run() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")?;
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "boxcar-sensor",
            "--target",
            "x86_64-unknown-linux-musl",
            "--profile",
            "guest",
        ])
        .env_remove("AYA_BUILD_SKIP")
        .current_dir(root)
        .status()
        .context("run cargo build for boxcar-sensor")?;
    ensure!(
        status.success(),
        "building boxcar-sensor for the guest failed: {status}"
    );
    let object = find_object(&root.join(GUEST_BUILD_DIR))?;
    let bytes = fs::read(&object).with_context(|| format!("read {}", object.display()))?;
    let report = check_object(&bytes)?;
    println!(
        "sensor: {} ({} bytes) has {} programs, {} maps, {} bytes of globals, licence {:?}",
        object.display(),
        bytes.len(),
        report.programs.len(),
        report.maps.len(),
        report.globals_bytes,
        report.license
    );
    for (name, kind) in &report.programs {
        println!("  {kind:<16} {name}");
    }
    Ok(())
}

/// The newest `boxcar-sensor-*/out/boxcar-sensor` under cargo's build
/// directory for the guest target: the object the last build embedded.
pub fn find_object(build_dir: &Path) -> Result<PathBuf> {
    let entries =
        fs::read_dir(build_dir).with_context(|| format!("read {}", build_dir.display()))?;
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("boxcar-sensor-") {
            continue;
        }
        let candidate = entry.path().join("out").join("boxcar-sensor");
        let Ok(meta) = fs::metadata(&candidate) else {
            continue;
        };
        let modified = meta.modified()?;
        if newest.as_ref().is_none_or(|(when, _)| modified > *when) {
            newest = Some((modified, candidate));
        }
    }
    newest
        .map(|(_, path)| path)
        .with_context(|| format!("no built eBPF object under {}", build_dir.display()))
}

/// Checks `bytes` against the table: every program with its kind, every
/// map with its type, a data section for the globals, the licence.
pub fn check_object(bytes: &[u8]) -> Result<Report> {
    ensure!(
        !bytes.is_empty(),
        "the object is empty: built with AYA_BUILD_SKIP?"
    );
    let object = Object::parse(bytes).map_err(|e| anyhow::anyhow!("not an eBPF object: {e}"))?;
    let license = object
        .license
        .to_str()
        .context("the licence is not UTF-8")?
        .to_owned();
    ensure!(
        license == LICENSE,
        "the object's licence is {license:?}, not {LICENSE:?}"
    );
    let mut programs = Vec::new();
    for program in PROGRAMS {
        let found = object.programs.get(program.name).with_context(|| {
            format!(
                "program {} is missing; the object has {:?}",
                program.name,
                object.programs.keys().collect::<Vec<_>>()
            )
        })?;
        let kind = section_kind(&found.section);
        let want = kind_name(program.kind);
        ensure!(
            kind == want,
            "program {} is a {kind} program, not {want}",
            program.name
        );
        programs.push((program.name.to_owned(), kind.to_owned()));
    }
    ensure!(
        object.programs.len() == PROGRAMS.len(),
        "the object has {} programs, the table {}: {:?}",
        object.programs.len(),
        PROGRAMS.len(),
        object.programs.keys().collect::<Vec<_>>()
    );
    let mut maps = Vec::new();
    for (name, map_type) in MAPS {
        let map = object.maps.get(name).with_context(|| {
            format!(
                "map {name} is missing; the object has {:?}",
                object.maps.keys().collect::<Vec<_>>()
            )
        })?;
        ensure!(
            map.map_type() == map_type,
            "map {name} has type {}, not {map_type}",
            map.map_type()
        );
        maps.push((name.to_owned(), map_type));
    }
    // The globals are initialized to a non-zero sentinel, so they live in
    // `.data`: one u64 each.
    let data = object
        .maps
        .get(".data")
        .context("the object has no .data section: are the globals initialized?")?;
    let globals_bytes = data.data().len();
    ensure!(
        globals_bytes == GLOBALS.len() * 8,
        ".data holds {globals_bytes} bytes, not the {} of {} u64 globals",
        GLOBALS.len() * 8,
        GLOBALS.len()
    );
    Ok(Report {
        programs,
        maps,
        license,
        globals_bytes,
    })
}

fn section_kind(section: &ProgramSection) -> &'static str {
    match section {
        ProgramSection::BtfTracePoint => "btf_tracepoint",
        ProgramSection::Lsm { sleepable: false } => "lsm",
        ProgramSection::Lsm { sleepable: true } => "lsm.s",
        ProgramSection::FEntry { sleepable: false } => "fentry",
        ProgramSection::FEntry { sleepable: true } => "fentry.s",
        _ => "other",
    }
}

fn kind_name(kind: ProgramKind) -> &'static str {
    match kind {
        ProgramKind::BtfTracepoint => "btf_tracepoint",
        ProgramKind::Lsm => "lsm",
        ProgramKind::SleepableLsm => "lsm.s",
        ProgramKind::FEntry => "fentry",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_or_foreign_object_is_refused() {
        let error = check_object(&[]).unwrap_err().to_string();
        assert!(error.contains("AYA_BUILD_SKIP"), "{error}");
        assert!(check_object(b"\x7fELF but not really").is_err());
    }

    #[test]
    fn kinds_have_their_section_names() {
        assert_eq!(kind_name(ProgramKind::BtfTracepoint), "btf_tracepoint");
        assert_eq!(kind_name(ProgramKind::SleepableLsm), "lsm.s");
        assert_eq!(
            section_kind(&ProgramSection::Lsm { sleepable: true }),
            "lsm.s"
        );
        assert_eq!(
            section_kind(&ProgramSection::FEntry { sleepable: false }),
            "fentry"
        );
        assert_eq!(section_kind(&ProgramSection::TracePoint), "other");
    }

    /// The object the last guest build embedded passes the check. Skips
    /// with a message when no guest build has been made.
    #[test]
    fn the_built_object_has_every_program_and_the_dual_license() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let object = match find_object(&root.join(GUEST_BUILD_DIR)) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("skipped: {e} (run `cargo xtask sensor`)");
                return;
            }
        };
        let bytes = fs::read(&object).unwrap();
        if bytes.is_empty() {
            eprintln!("skipped: the last build set AYA_BUILD_SKIP");
            return;
        }
        let report = check_object(&bytes).unwrap();
        assert_eq!(report.programs.len(), PROGRAMS.len());
        assert_eq!(report.license, LICENSE);
        let names: Vec<&str> = report.programs.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"bpf_guard") && names.contains(&"sched_process_exec"));
    }
}
