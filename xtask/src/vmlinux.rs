// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `cargo xtask gen-vmlinux` and `cargo xtask check-vmlinux`: the kernel
//! type bindings the sensor's eBPF programs are built against, and the
//! guard against their drifting from the kernel.
//!
//! The programs read kernel structures (`task_struct`, `linux_binprm`,
//! `sock`, ...) through Rust bindings generated from **our** guest kernel's
//! BTF, not from the running host's: there is no CO-RE from Rust yet, and we
//! build the kernel, so drift is a build check. `gen-vmlinux` runs
//! `bpftool btf dump file target/guest/vmlinux format c` and `bindgen` over
//! it inside the kernel build image (`guest/kernel/gen-vmlinux.sh`), writes
//! `crates/boxcar-sensor-ebpf/src/vmlinux.rs` with a header naming the
//! kernel and the BTF it came from, and records the blake3 of the `.BTF`
//! section in `guest/kernel/.btf-hash`. `check-vmlinux` recomputes that hash
//! from `target/guest/vmlinux` and fails on a difference, naming both; the
//! bindings' header must name the same hash. `cargo xtask kernel` runs the
//! check once a kernel is built, so a kernel whose BTF changed cannot be
//! used with stale bindings by mistake.

use std::fs;
use std::path::Path;

use std::process::Command;

use anyhow::{bail, ensure, Context, Result};

use crate::kernel::run_in_docker;

/// Where the bindings go, from the repository root.
const BINDINGS: &str = "crates/boxcar-sensor-ebpf/src/vmlinux.rs";
/// Where the BTF hash goes.
const HASH_FILE: &str = "guest/kernel/.btf-hash";
/// The script the image runs.
const SCRIPT: &str = "/src/gen-vmlinux.sh";

/// The kernel types the programs read; `guest/kernel/gen-vmlinux.sh` names
/// the same list, and bindgen brings in what they refer to.
pub const ALLOWLIST: [&str; 16] = [
    "task_struct",
    "linux_binprm",
    "mm_struct",
    "sock",
    "sock_common",
    "socket",
    "sockaddr",
    "sockaddr_in",
    "sockaddr_in6",
    "file",
    "path",
    "dentry",
    "qstr",
    "kernel_siginfo",
    "cred",
    "pt_regs",
];

fn root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask manifest directory has no parent")
}

/// `cargo xtask gen-vmlinux`: see the module docs.
pub fn gen() -> Result<()> {
    let root = root()?;
    let kernel_dir = root.join("guest/kernel");
    let out_dir = root.join("target/guest");
    let cache_dir = root.join("target/kernel-cache");
    let vmlinux = out_dir.join("vmlinux");
    ensure!(
        vmlinux.is_file(),
        "{} is missing: run `cargo xtask kernel` first",
        vmlinux.display()
    );
    fs::create_dir_all(&cache_dir).with_context(|| format!("create {}", cache_dir.display()))?;
    let hash =
        btf_hash(&fs::read(&vmlinux).with_context(|| format!("read {}", vmlinux.display()))?)?;
    let kernel = kernel_version(&kernel_dir.join("VERSION"))?;

    run_in_docker(&kernel_dir, &out_dir, &cache_dir, None, SCRIPT)?;
    let body = out_dir.join("vmlinux.rs.body");
    let tools = out_dir.join("vmlinux.tools");
    let bindings = fs::read_to_string(&body).with_context(|| format!("read {}", body.display()))?;
    let tools_text =
        fs::read_to_string(&tools).with_context(|| format!("read {}", tools.display()))?;
    let mut versions = tools_text.lines().map(str::trim).filter(|l| !l.is_empty());
    let bpftool = versions
        .next()
        .unwrap_or("bpftool (version unknown)")
        .to_owned();
    let bindgen = versions
        .next()
        .unwrap_or("bindgen (version unknown)")
        .to_owned();
    for name in ALLOWLIST {
        ensure!(
            bindings.contains(&format!("pub struct {name} "))
                || bindings.contains(&format!("pub union {name} ")),
            "the generated bindings have no {name}: is it in gen-vmlinux.sh's allowlist?"
        );
    }

    let target = root.join(BINDINGS);
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let mut text = header(&kernel, &hash, &bpftool, &bindgen);
    text.push_str(&bindings);
    fs::write(&target, text).with_context(|| format!("write {}", target.display()))?;
    // The image has no rustfmt; the host's toolchain does. Run it from the
    // repository root so the workspace's toolchain, not the eBPF crate's,
    // is the one used.
    let status = Command::new("rustfmt")
        .args(["--edition", "2021"])
        .arg(&target)
        .current_dir(root)
        .status()
        .context("run rustfmt on the generated bindings")?;
    ensure!(
        status.success(),
        "rustfmt failed on {}: {status}",
        target.display()
    );
    let hash_file = root.join(HASH_FILE);
    fs::write(&hash_file, format!("{hash}\n"))
        .with_context(|| format!("write {}", hash_file.display()))?;
    let _ = fs::remove_file(&body);
    let _ = fs::remove_file(&tools);
    let lines = fs::read_to_string(&target)
        .map(|t| t.lines().count())
        .unwrap_or(0);
    println!(
        "wrote {} ({lines} lines) and {} (BTF blake3 {hash}) from Linux {kernel} with {bpftool} \
         and {bindgen}",
        target.display(),
        hash_file.display()
    );
    Ok(())
}

/// `cargo xtask check-vmlinux`: see the module docs.
pub fn check() -> Result<()> {
    let root = root()?;
    let vmlinux = root.join("target/guest/vmlinux");
    ensure!(
        vmlinux.is_file(),
        "{} is missing: run `cargo xtask kernel` first",
        vmlinux.display()
    );
    let built =
        btf_hash(&fs::read(&vmlinux).with_context(|| format!("read {}", vmlinux.display()))?)?;
    let recorded = fs::read_to_string(root.join(HASH_FILE))
        .with_context(|| format!("read {HASH_FILE}: run `cargo xtask gen-vmlinux` once"))?;
    let bindings = fs::read_to_string(root.join(BINDINGS))
        .with_context(|| format!("read {BINDINGS}: run `cargo xtask gen-vmlinux` once"))?;
    check_hashes(&built, &recorded, &bindings)?;
    println!(
        "check-vmlinux: the kernel's BTF ({built}) is the one the bindings were generated from"
    );
    Ok(())
}

/// What `cargo xtask kernel` runs once a kernel is built: the check, when a
/// hash has been recorded; before the first `gen-vmlinux`, a reminder.
pub fn check_after_kernel_build() -> Result<()> {
    if root()?.join(HASH_FILE).is_file() {
        check()
    } else {
        println!("kernel: no {HASH_FILE} yet; run `cargo xtask gen-vmlinux` to generate the sensor's bindings");
        Ok(())
    }
}

/// The hashes agree: the built kernel's BTF, the recorded one, and the one
/// the bindings' header names.
fn check_hashes(built: &str, recorded_file: &str, bindings: &str) -> Result<()> {
    let recorded = recorded_file.trim();
    ensure!(
        !recorded.is_empty(),
        "{HASH_FILE} records no hash: run `cargo xtask gen-vmlinux`"
    );
    ensure!(
        recorded == built,
        "target/guest/vmlinux's BTF hashes to {built}, but {HASH_FILE} records {recorded}: the \
         kernel changed under the sensor's bindings; run `cargo xtask gen-vmlinux` and rebuild \
         the sensor"
    );
    match hash_in_header(bindings) {
        Some(in_header) if in_header == built => Ok(()),
        Some(in_header) => bail!(
            "{BINDINGS} was generated from BTF {in_header}, not {built}: run `cargo xtask \
             gen-vmlinux`"
        ),
        None => {
            bail!("{BINDINGS} has no `// BTF blake3:` header line: run `cargo xtask gen-vmlinux`")
        }
    }
}

/// The header the generated file starts with.
fn header(kernel: &str, hash: &str, bpftool: &str, bindgen: &str) -> String {
    format!(
        "// SPDX-License-Identifier: GPL-2.0\n\
         // Generated by `cargo xtask gen-vmlinux` from the BTF of Linux {kernel}; do not edit.\n\
         {}\
         // Tools: {bpftool}; {bindgen}\n\
         //\n\
         // These are the guest kernel's own types as its BTF describes them: the Linux\n\
         // kernel's, under its licence. Only the eBPF programs read them; nothing here is\n\
         // linked into a host binary (see docs/ebpf-license.md).\n\
         #![allow(clippy::all)]\n\
         #![allow(\n\
         \x20   non_camel_case_types,\n\
         \x20   non_snake_case,\n\
         \x20   non_upper_case_globals,\n\
         \x20   dead_code,\n\
         \x20   improper_ctypes,\n\
         \x20   unsafe_op_in_unsafe_fn,\n\
         \x20   unnecessary_transmutes\n\
         )]\n\n",
        header_line(hash)
    )
}

/// The header line that names the BTF the bindings came from.
fn header_line(hash: &str) -> String {
    format!("// BTF blake3: {hash}\n")
}

/// The hash the header of a generated file names.
fn hash_in_header(text: &str) -> Option<String> {
    text.lines()
        .take(16)
        .find_map(|line| line.strip_prefix("// BTF blake3: "))
        .map(|hash| hash.trim().to_owned())
}

/// `KERNEL_VERSION` from `guest/kernel/VERSION`.
fn kernel_version(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    text.lines()
        .find_map(|line| line.strip_prefix("KERNEL_VERSION="))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .with_context(|| format!("{} has no KERNEL_VERSION", path.display()))
}

/// The blake3 of the `.BTF` section of an ELF image, as hex.
fn btf_hash(elf: &[u8]) -> Result<String> {
    Ok(blake3::hash(&btf_section(elf)?).to_hex().to_string())
}

/// The bytes of the `.BTF` section of a little-endian ELF64 image.
fn btf_section(elf: &[u8]) -> Result<Vec<u8>> {
    let u16_at = |at: usize| -> Result<usize> {
        let b = elf.get(at..at + 2).context("ELF header truncated")?;
        Ok(u16::from_le_bytes([b[0], b[1]]) as usize)
    };
    let u32_at = |at: usize| -> Result<usize> {
        let b = elf
            .get(at..at + 4)
            .context("ELF section header truncated")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let u64_at = |at: usize| -> Result<usize> {
        let b = elf.get(at..at + 8).context("ELF header truncated")?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        usize::try_from(u64::from_le_bytes(a)).context("ELF offset does not fit")
    };
    ensure!(elf.get(..4) == Some(b"\x7fELF"), "not an ELF file");
    ensure!(elf.get(4) == Some(&2), "not a 64-bit ELF file");
    ensure!(elf.get(5) == Some(&1), "not a little-endian ELF file");
    let shoff = u64_at(40)?;
    let shentsize = u16_at(58)?;
    let shnum = u16_at(60)?;
    let shstrndx = u16_at(62)?;
    ensure!(
        shentsize >= 64 && shnum > 0,
        "the ELF file has no section headers"
    );
    ensure!(shstrndx < shnum, "the ELF file has no section name table");
    let section = |index: usize| -> Result<(usize, usize, usize)> {
        let base = shoff + index * shentsize;
        Ok((u32_at(base)?, u64_at(base + 24)?, u64_at(base + 32)?))
    };
    let (_, names_off, names_size) = section(shstrndx)?;
    let names = elf
        .get(names_off..names_off + names_size)
        .context("the section name table is out of the file")?;
    for index in 0..shnum {
        let (name_off, off, size) = section(index)?;
        let name = names
            .get(name_off..)
            .and_then(|rest| rest.split(|&b| b == 0).next())
            .unwrap_or(b"");
        if name == b".BTF" {
            return elf
                .get(off..off + size)
                .map(<[u8]>::to_vec)
                .context("the .BTF section is out of the file");
        }
    }
    bail!("the ELF file has no .BTF section")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian ELF64 with a `.shstrtab` and the sections given, in
    /// that order after the null section.
    fn elf64(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut shstrtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for (name, _) in sections {
            name_offsets.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // little endian
        out[6] = 1;
        out[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize

        let mut offsets = Vec::new();
        for (_, data) in sections {
            offsets.push(out.len() as u64);
            out.extend_from_slice(data);
        }
        let shstrtab_offset = out.len() as u64;
        out.extend_from_slice(&shstrtab);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let shoff = out.len() as u64;
        let count = sections.len() as u16 + 2;
        out[40..48].copy_from_slice(&shoff.to_le_bytes());
        out[60..62].copy_from_slice(&count.to_le_bytes());
        out[62..64].copy_from_slice(&(count - 1).to_le_bytes()); // e_shstrndx

        let mut shdr = |name: u32, offset: u64, size: u64| {
            let mut h = [0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
            h[24..32].copy_from_slice(&offset.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&h);
        };
        shdr(0, 0, 0);
        for (i, (_, data)) in sections.iter().enumerate() {
            shdr(name_offsets[i], offsets[i], data.len() as u64);
        }
        shdr(shstrtab_name, shstrtab_offset, shstrtab.len() as u64);
        out
    }

    #[test]
    fn btf_section_is_found_by_the_elf_reader() {
        let elf = elf64(&[
            (".text", b"code"),
            (".BTF", b"the btf bytes"),
            (".BTF_ids", b"ids"),
        ]);
        assert_eq!(btf_section(&elf).unwrap(), b"the btf bytes");
        let without = elf64(&[(".text", b"code"), (".BTF_ids", b"ids")]);
        let error = btf_section(&without).unwrap_err().to_string();
        assert!(error.contains(".BTF"), "{error}");
        assert!(btf_section(b"not an elf at all").is_err());
        assert!(btf_section(&[]).is_err());
    }

    #[test]
    fn check_vmlinux_fails_on_a_stale_hash() {
        let elf = elf64(&[(".BTF", b"the btf bytes")]);
        let hash = btf_hash(&elf).unwrap();
        assert_eq!(hash, blake3::hash(b"the btf bytes").to_hex().to_string());
        check_hashes(&hash, &format!("{hash}\n"), &header_line(&hash)).unwrap();
        let stale = blake3::hash(b"other").to_hex().to_string();
        let error = check_hashes(&hash, &format!("{stale}\n"), &header_line(&hash))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&hash) && error.contains(&stale), "{error}");
        let error = check_hashes(&hash, &format!("{hash}\n"), &header_line(&stale))
            .unwrap_err()
            .to_string();
        assert!(error.contains("vmlinux.rs"), "{error}");
        assert!(check_hashes(&hash, "", &header_line(&hash)).is_err());
    }

    #[test]
    fn the_header_names_the_kernel_and_the_hash_and_reads_back() {
        let header = header("6.18.54", "0123abcd", "bpftool v7.5.0", "bindgen 0.71.1");
        assert!(header.starts_with("// SPDX-License-Identifier: GPL-2.0"));
        assert!(header.contains("6.18.54") && header.contains("0123abcd"));
        assert!(header.contains("bpftool v7.5.0") && header.contains("bindgen 0.71.1"));
        assert_eq!(hash_in_header(&header), Some("0123abcd".to_owned()));
        assert_eq!(hash_in_header("pub struct task_struct {}"), None);
    }

    /// The committed bindings name the types the programs read: a
    /// regeneration with a narrower allowlist fails here.
    #[test]
    fn gen_vmlinux_names_the_types_the_programs_need() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/boxcar-sensor-ebpf/src/vmlinux.rs");
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for name in ALLOWLIST {
            assert!(
                text.contains(&format!("pub struct {name} "))
                    || text.contains(&format!("pub union {name} ")),
                "{name} is not in {}",
                path.display()
            );
        }
        assert!(
            hash_in_header(&text).is_some(),
            "the header names the BTF hash"
        );
        let recorded = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/kernel/.btf-hash"),
        )
        .unwrap();
        assert_eq!(hash_in_header(&text).unwrap(), recorded.trim());
    }
}
