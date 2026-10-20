// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! M5 end-to-end tests: sessions booted from an image. A test registry on
//! the loopback serves an image built here from the Alpine tree
//! `BOXCAR_TEST_ROOTFS` names, with a second layer carrying a package built
//! here too; `boxcar run --image` pulls it into a cache of its own and
//! boots from a per-session copy. Skips without `/dev/kvm` and the guest
//! artifacts, like the other gated suites.

#![cfg(feature = "kvm-tests")]

mod kvm_harness;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use boxcar_testreg::{config, index, layer_tar, manifest, Auth, Faults, Registry};
use kvm_harness::{
    boxcar, guest_or_skip, networked_guest_or_skip, of_kind, start_with_root, text, Guest, Run,
    Scratch,
};

/// The marker the package's program prints.
const MARKER: &str = "boxcar-test-marker";

/// The image: layer 1 the Alpine tree, layer 2 the test's additions.
struct Image {
    registry: Registry,
    /// `127.0.0.1:PORT/library/alpine:3.22`.
    by_tag: String,
    /// The same image through its index, by the index's digest.
    by_index: String,
    manifest_digest: String,
    config_digest: String,
}

fn publish(rootfs: &Path) -> Image {
    let registry = Registry::start(Auth::None, Faults::default());
    let base = layer_tar(&tar_of_dir(rootfs));
    let additions = layer_tar(&additions_layer());
    let cfg = config(
        &[
            "BOXCAR_IMAGE_TEST=1",
            "PATH=/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ],
        &["/bin/sh", "-c"],
        &["echo from-image"],
        "/app/project",
    );
    let m = manifest(&cfg, &[base.clone(), additions.clone()]);
    for blob in [&base, &additions, &cfg, &m] {
        registry.put_blob(blob);
    }
    registry.put_manifest("library/alpine", "3.22", &m);
    registry.put_manifest("library/alpine", &m.digest(), &m);
    let idx = index(&[(&m, "linux", "amd64")]);
    registry.put_manifest("library/alpine", &idx.digest(), &idx);
    let host = registry.host();
    Image {
        by_tag: format!("{host}/library/alpine:3.22"),
        by_index: format!("{host}/library/alpine@{}", idx.digest()),
        manifest_digest: m.digest(),
        config_digest: cfg.digest(),
        registry,
    }
}

/// A tar of the directory `root`: directories, regular files and symlinks
/// with their modes; anything else left out.
fn tar_of_dir(root: &Path) -> Vec<u8> {
    fn walk(builder: &mut tar::Builder<Vec<u8>>, root: &Path, dir: &Path) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            let meta = fs::symlink_metadata(&path).unwrap();
            let rel = path.strip_prefix(root).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_mode(meta.permissions().mode() & 0o7777);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            if meta.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                builder
                    .append_data(&mut header, format!("{}/", rel.display()), &[][..])
                    .unwrap();
                walk(builder, root, &path);
            } else if meta.file_type().is_symlink() {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                let target = fs::read_link(&path).unwrap();
                header.set_link_name(&target).unwrap();
                builder.append_data(&mut header, rel, &[][..]).unwrap();
            } else if meta.is_file() {
                let data = fs::read(&path).unwrap();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(data.len() as u64);
                builder.append_data(&mut header, rel, &data[..]).unwrap();
            }
        }
    }
    let mut builder = tar::Builder::new(Vec::new());
    walk(&mut builder, root, root);
    builder.into_inner().unwrap()
}

fn entry(
    builder: &mut tar::Builder<Vec<u8>>,
    kind: tar::EntryType,
    path: &str,
    mode: u32,
    data: &[u8],
    link: Option<&str>,
) {
    // ustar, as abuild writes a package's archives and apk reads them.
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_size(data.len() as u64);
    if let Some(link) = link {
        header.set_link_name(link).unwrap();
    }
    builder.append_data(&mut header, path, data).unwrap();
}

/// Layer 2: the package to install, a file no one may read, a directory no
/// one may enter, a locked directory the resolver's file must land in
/// (`/etc/resolv.conf` is a link into it), a link into the workspace, and
/// a motd.
fn additions_layer() -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let d = tar::EntryType::Directory;
    let f = tar::EntryType::Regular;
    entry(&mut b, d, "tmp/", 0o1777, &[], None);
    entry(&mut b, f, "tmp/boxcar-test-1.0-r0.apk", 0o644, &apk(), None);
    entry(&mut b, d, "conf/", 0o555, &[], None);
    entry(
        &mut b,
        tar::EntryType::Symlink,
        "etc/resolv.conf",
        0o777,
        &[],
        Some("/conf/resolv.conf"),
    );
    entry(&mut b, f, "etc/motd", 0o644, b"from the test image\n", None);
    entry(&mut b, f, "etc/secret", 0o000, b"no one reads this\n", None);
    entry(&mut b, d, "locked/", 0o000, &[], None);
    entry(&mut b, f, "locked/inside", 0o644, b"inside\n", None);
    entry(
        &mut b,
        tar::EntryType::Symlink,
        "app",
        0o777,
        &[],
        Some("/workspace"),
    );
    b.into_inner().unwrap()
}

/// An APKv2 package, `boxcar-test-1.0-r0`, whose one file `/opt/bin/
/// boxcar-test` prints [`MARKER`]: the control stream (a tar of `.PKGINFO`
/// with its end blocks cut) and the data stream (a tar whose files carry
/// their SHA-1 in a PAX header), both gzip'd and concatenated.
fn apk() -> Vec<u8> {
    let script = format!("#!/bin/sh\necho {MARKER}\n");
    let mut data = tar::Builder::new(Vec::new());
    entry(
        &mut data,
        tar::EntryType::Directory,
        "opt/",
        0o755,
        &[],
        None,
    );
    entry(
        &mut data,
        tar::EntryType::Directory,
        "opt/bin/",
        0o755,
        &[],
        None,
    );
    checksum_header(&mut data, script.as_bytes());
    entry(
        &mut data,
        tar::EntryType::Regular,
        "opt/bin/boxcar-test",
        0o755,
        script.as_bytes(),
        None,
    );
    let data_gz = gzip(&data.into_inner().unwrap());
    let sha256 = ring::digest::digest(&ring::digest::SHA256, &data_gz);
    let datahash: String = sha256.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let pkginfo = format!(
        "# Generated by boxcar's test\npkgname = boxcar-test\npkgver = 1.0-r0\n\
         pkgdesc = a marker program\nurl = https://example.invalid/\nbuilddate = 0\n\
         packager = boxcar\nsize = {}\narch = x86_64\norigin = boxcar-test\n\
         license = Apache-2.0\ndatahash = {datahash}\n",
        script.len()
    );
    let mut control = tar::Builder::new(Vec::new());
    checksum_header(&mut control, pkginfo.as_bytes());
    entry(
        &mut control,
        tar::EntryType::Regular,
        ".PKGINFO",
        0o644,
        pkginfo.as_bytes(),
        None,
    );
    let mut control_raw = control.into_inner().unwrap();
    while control_raw.ends_with(&[0u8; 512]) {
        control_raw.truncate(control_raw.len() - 512);
    }
    let mut out = gzip(&control_raw);
    out.extend_from_slice(&data_gz);
    out
}

/// The PAX header apk wants before a file: its SHA-1, as abuild-tar
/// writes it, with a complete ustar header of its own (the tar crate's
/// PAX writer leaves the name and the mode empty, which apk refuses).
fn checksum_header(builder: &mut tar::Builder<Vec<u8>>, file: &[u8]) {
    let sha1 = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, file);
    let hex: String = sha1.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let record = format!("APK-TOOLS.checksum.SHA1={hex}\n");
    // "<len> <record>", the length counting itself.
    let mut len = record.len() + 2;
    while len != format!("{len} ").len() + record.len() {
        len = format!("{len} ").len() + record.len();
    }
    let data = format!("{len} {record}");
    entry(
        builder,
        tar::EntryType::XHeader,
        "././@PaxHeader",
        0o644,
        data.as_bytes(),
        None,
    );
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// A digest of everything about a tree: every path's kind, mode, size,
/// link target and content, with hardlinks grouped. The cached tree's
/// must not change under a session.
fn tree_digest(root: &Path) -> String {
    fn walk(
        root: &Path,
        dir: &Path,
        out: &mut BTreeMap<String, String>,
        inos: &mut BTreeMap<u64, String>,
    ) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            let meta = fs::symlink_metadata(&path).unwrap();
            let rel = path.strip_prefix(root).unwrap().display().to_string();
            let mode = meta.permissions().mode() & 0o7777;
            let what = if meta.is_dir() {
                if fs::read_dir(&path).is_ok() {
                    walk(root, &path, out, inos);
                    format!("dir {mode:o}")
                } else {
                    format!("dir {mode:o} unreadable")
                }
            } else if meta.file_type().is_symlink() {
                format!("symlink {}", fs::read_link(&path).unwrap().display())
            } else if meta.is_file() {
                let mut hasher = blake3::Hasher::new();
                let Ok(mut file) = fs::File::open(&path) else {
                    out.insert(rel, format!("file {mode:o} unreadable"));
                    continue;
                };
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = file.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                let group = if meta.nlink() > 1 {
                    let first = inos.entry(meta.ino()).or_insert_with(|| rel.clone());
                    format!(" linked-with {first}")
                } else {
                    String::new()
                };
                format!(
                    "file {mode:o} {} {}{group}",
                    meta.len(),
                    hasher.finalize().to_hex()
                )
            } else {
                "other".to_owned()
            };
            out.insert(rel, what);
        }
    }
    let mut out = BTreeMap::new();
    let mut inos = BTreeMap::new();
    walk(root, root, &mut out, &mut inos);
    let mut hasher = blake3::Hasher::new();
    for (path, what) in &out {
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(what.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

/// Runs `boxcar run --image REF` with `flags`, the cache in the scratch.
fn run_image(
    guest: &Guest,
    scratch: &Scratch,
    reference: &str,
    flags: &[&str],
    command: &[&str],
) -> Run {
    let cache = scratch.path("cache");
    let root = ["--image", reference, "--cache-dir", cache.to_str().unwrap()];
    start_with_root(guest, scratch, &root, flags, command, &[]).finish()
}

fn cached_tree(scratch: &Scratch, manifest_digest: &str) -> PathBuf {
    let hex = manifest_digest.strip_prefix("sha256:").unwrap();
    scratch
        .path("cache")
        .join("images")
        .join(hex)
        .join("rootfs")
}

/// With no command, the image's Entrypoint and Cmd run, in its WorkingDir,
/// with its Env; `vmm.start` records the image and a root share in the
/// session directory.
#[test]
fn a_session_boots_from_an_image_with_its_defaults() {
    let Some(guest) = guest_or_skip("a_session_boots_from_an_image_with_its_defaults") else {
        return;
    };
    let image = publish(&guest.rootfs);
    let scratch = Scratch::new();
    let run = run_image(&guest, &scratch, &image.by_tag, &[], &[]);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("from-image"), "{}", run.describe());
    assert!(run.stderr.contains("layer 1/2"), "pulled: {}", run.stderr);
    let records = run.records();
    let start = of_kind(&records, "vmm.start");
    let image_ref = &start[0].data["image"];
    assert_eq!(image_ref["reference"], image.by_tag, "{:?}", start[0]);
    assert_eq!(image_ref["manifest_digest"], image.manifest_digest);
    assert_eq!(image_ref["config_digest"], image.config_digest);
    let host_root = start[0].data["shares"][0]["host_root"].as_str().unwrap();
    assert!(
        Path::new(host_root).starts_with(run.session_dir()),
        "{host_root} is not in {}",
        run.session_dir().display()
    );
    assert_eq!(Path::new(host_root).file_name().unwrap(), "rootfs");
    // The copy has the image's modes, and the boot paths were made in it:
    // resolv.conf in the locked /etc, the working directory in the workspace.
    let copy = Path::new(host_root);
    assert_eq!(
        fs::symlink_metadata(copy.join("conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o555
    );
    assert_eq!(
        fs::symlink_metadata(copy.join("etc/secret"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o000
    );
    assert_eq!(
        fs::symlink_metadata(copy.join("locked"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o000
    );
    assert!(
        copy.join("conf/resolv.conf").is_file(),
        "made where the link leads, before the mode"
    );
    assert_eq!(
        fs::read_link(copy.join("etc/resolv.conf")).unwrap(),
        Path::new("/conf/resolv.conf")
    );
    assert!(
        scratch.path("workspace").join("project").is_dir(),
        "WorkingDir through /app -> /workspace"
    );
    // The cached tree stores readable modes, listed in image.json.
    let cached = cached_tree(&scratch, &image.manifest_digest);
    assert_eq!(
        fs::symlink_metadata(cached.join("etc/secret"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(cached.parent().unwrap().join("image.json")).unwrap())
            .unwrap();
    assert!(json["modes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m[0] == "etc/secret" && m[1] == 0));
}

/// A command installs the package from the layer with apk, offline, and
/// runs it through the image's PATH; `pwd` is the image's WorkingDir
/// through the link; the image's Env is there, once; `--env PATH=…` then
/// hides the program.
#[test]
fn a_session_installs_a_package_from_a_local_layer_through_the_images_path() {
    let Some(guest) =
        guest_or_skip("a_session_installs_a_package_from_a_local_layer_through_the_images_path")
    else {
        return;
    };
    let image = publish(&guest.rootfs);
    let scratch = Scratch::new();
    let script = "apk add --allow-untrusted --no-network /tmp/boxcar-test-1.0-r0.apk 2>&1; \
                  echo apk=$?; boxcar-test; echo pwd=$(pwd); echo test=$BOXCAR_IMAGE_TEST; \
                  echo paths=$(env | grep -c '^PATH='); echo secret=$(stat -c %a /etc/secret); \
                  cat /etc/motd";
    let run = run_image(
        &guest,
        &scratch,
        &image.by_tag,
        &[],
        &["/bin/sh", "-c", script],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    for want in [
        "apk=0",
        MARKER,
        // The shell prints where the link led.
        "pwd=/workspace/project",
        "test=1",
        "paths=1",
        "secret=0",
        "from the test image",
    ] {
        assert!(
            run.stdout.contains(want),
            "{want} missing:\n{}",
            run.describe()
        );
    }
    // With the user's PATH over the image's, the program is not found.
    let scratch2 = Scratch::new();
    let run = run_image(
        &guest,
        &scratch2,
        &image.by_tag,
        &["--env", "PATH=/usr/bin:/bin"],
        &[
            "/bin/sh",
            "-c",
            "apk add --allow-untrusted --no-network /tmp/boxcar-test-1.0-r0.apk >/dev/null 2>&1; \
             if boxcar-test 2>/dev/null; then echo found; else echo not-found; fi; echo $PATH",
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("not-found"), "{}", run.describe());
    assert!(run.stdout.contains("/usr/bin:/bin"), "{}", run.describe());
}

/// A session that writes, removes and chmods everywhere it can leaves the
/// cached tree exactly as it was; the copy differs; a second run fetches
/// nothing.
#[test]
fn a_session_that_writes_everywhere_leaves_the_cache_unchanged() {
    let Some(guest) = guest_or_skip("a_session_that_writes_everywhere_leaves_the_cache_unchanged")
    else {
        return;
    };
    let image = publish(&guest.rootfs);
    let scratch = Scratch::new();
    // First: the pull.
    let run = run_image(&guest, &scratch, &image.by_tag, &[], &["/bin/true"]);
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let cached = cached_tree(&scratch, &image.manifest_digest);
    let before = tree_digest(&cached);
    let copy_before = tree_digest(Path::new(
        of_kind(&run.records(), "vmm.start")[0].data["shares"][0]["host_root"]
            .as_str()
            .unwrap(),
    ));
    // Second: a session that leaves nothing alone.
    let script = "echo x > /etc/x; rm -rf /usr/share /etc/motd; chmod 777 /bin /etc; \
                  echo y > /tmp/y; touch /workspace/z; mv /etc/passwd /etc/passwd.old; \
                  mkdir -p /new/dir; ln -s /etc /new/link; echo done";
    let run2 = run_image(
        &guest,
        &scratch,
        &image.by_tag,
        &[],
        &["/bin/sh", "-c", script],
    );
    assert_eq!(run2.status.code(), Some(0), "{}", run2.describe());
    assert!(run2.stdout.contains("done"), "{}", run2.describe());
    assert!(
        !run2.stderr.contains("layer 1/2"),
        "nothing fetched:\n{}",
        run2.stderr
    );
    assert!(run2.stderr.contains("(cached)"), "{}", run2.stderr);
    assert_eq!(tree_digest(&cached), before, "the cache is as it was");
    let copy2 = of_kind(&run2.records(), "vmm.start")[0].data["shares"][0]["host_root"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(
        tree_digest(Path::new(&copy2)),
        copy_before,
        "the session changed its copy"
    );
    assert!(Path::new(&copy2).join("etc/x").is_file());
    assert!(!Path::new(&copy2).join("etc/motd").exists());
}

/// A reference by the index's digest: pulled once, then found offline,
/// with the registry gone, by `--pull missing`; `--pull never` too.
#[test]
fn an_image_by_its_index_digest_boots_offline() {
    let Some(guest) = guest_or_skip("an_image_by_its_index_digest_boots_offline") else {
        return;
    };
    let image = publish(&guest.rootfs);
    let scratch = Scratch::new();
    let run = run_image(
        &guest,
        &scratch,
        &image.by_index,
        &[],
        &["/bin/echo", "first"],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("first"), "{}", run.describe());
    let records = run.records();
    assert_eq!(
        of_kind(&records, "vmm.start")[0].data["image"]["reference"],
        image.by_index
    );
    drop(image.registry);
    for pull in ["missing", "never"] {
        let run = run_image(
            &guest,
            &scratch,
            &image.by_index,
            &["--pull", pull],
            &["/bin/echo", "again"],
        );
        assert_eq!(
            run.status.code(),
            Some(0),
            "--pull {pull}: {}",
            run.describe()
        );
        assert!(run.stdout.contains("again"), "{}", run.describe());
        assert!(run.stderr.contains("(cached)"), "{}", run.stderr);
    }
    // `always` cannot reach the registry: no session.
    let run = run_image(
        &guest,
        &scratch,
        &image.by_index,
        &["--pull", "always"],
        &["/bin/true"],
    );
    assert_eq!(run.status.code(), Some(1), "{}", run.describe());
    assert!(!run.stderr.contains("session:"), "{}", run.stderr);
}

/// Writes the test's package to `BOXCAR_DUMP_APK`, for a look at it with
/// apk's own tools; nothing without the variable.
#[test]
fn the_package_can_be_dumped_for_inspection() {
    if let Ok(path) = std::env::var("BOXCAR_DUMP_APK") {
        fs::write(path, apk()).unwrap();
    }
}

/// A policy file is recorded as `policy.loaded` right after `vmm.start`,
/// with its path and the SHA-256 of its text, and its DNS rate holds in
/// the guest: lookups past a burst of two are answered REFUSED, each
/// recorded as the rate's, and nothing else of the session changes.
#[test]
fn a_policy_file_is_recorded_and_its_dns_rate_holds() {
    let Some(guest) = guest_or_skip("a_policy_file_is_recorded_and_its_dns_rate_holds") else {
        return;
    };
    let image = publish(&guest.rootfs);
    let scratch = Scratch::new();
    let policy = scratch.path("policy.toml");
    let text = "version = 1\n\n[egress]\nmax_dns_qps = 2\n\n[fs]\nwritable = [\"/**\"]\n";
    fs::write(&policy, text).unwrap();
    // Each lookup is of a name of its own, which the policy's default
    // denies: within the rate NXDOMAIN, past it REFUSED.
    let script = "for i in 1 2 3 4 5 6 7 8; do nslookup n$i.boxcar.test 10.0.2.2 >/dev/null 2>&1; \
                  done; echo looked";
    let run = run_image(
        &guest,
        &scratch,
        &image.by_tag,
        &["--policy", policy.to_str().unwrap()],
        &["sh", "-c", script],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("looked"), "{}", run.describe());
    assert!(!run.stderr.contains("warning: --policy"), "{}", run.stderr);
    let records = run.records();
    assert_eq!(records[0].kind, "vmm.start");
    assert_eq!(records[1].kind, "policy.loaded", "{:?}", records[1]);
    let sha256: String = ring::digest::digest(&ring::digest::SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        records[1].data,
        serde_json::json!({
            "source": "file",
            "name": policy.to_str().unwrap(),
            "sha256": sha256,
            "egress_rules": 0,
            "fs_rules": 1,
            "exec_rules": 0,
        })
    );
    assert_eq!(of_kind(&records, "policy.loaded").len(), 1, "once");
    let dns = of_kind(&records, "net.dns");
    let refused: Vec<_> = dns
        .iter()
        .filter(|r| r.data["rule"] == "dns_rate")
        .collect();
    assert!(
        !refused.is_empty(),
        "no lookup was refused for the rate: {dns:?}"
    );
    for record in &refused {
        assert_eq!(record.data["rcode"], 5, "{record:?}");
        assert_eq!(record.data["verdict"], "deny", "{record:?}");
    }
    assert!(
        dns.iter().any(|r| r.data["rcode"] == 3),
        "the burst got its NXDOMAIN: {dns:?}"
    );
}

/// An image for the policy tests: the Alpine tree with no
/// `/etc/resolv.conf` (whited out), and a regular-file copy of BusyBox at
/// `/usr/bin/nc` in place of the applet's link, a real program file of that
/// name.
fn publish_strict(rootfs: &Path) -> (Registry, String) {
    let registry = Registry::start(Auth::None, Faults::default());
    let base = layer_tar(&tar_of_dir(rootfs));
    let mut b = tar::Builder::new(Vec::new());
    let busybox = fs::read(rootfs.join("bin/busybox")).unwrap();
    entry(
        &mut b,
        tar::EntryType::Regular,
        "etc/.wh.resolv.conf",
        0o644,
        &[],
        None,
    );
    entry(
        &mut b,
        tar::EntryType::Regular,
        "usr/bin/nc",
        0o755,
        &busybox,
        None,
    );
    let additions = layer_tar(&b.into_inner().unwrap());
    let cfg = config(
        &["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        &["/bin/sh", "-c"],
        &["true"],
        "/workspace",
    );
    let m = manifest(&cfg, &[base.clone(), additions.clone()]);
    for blob in [&base, &additions, &cfg, &m] {
        registry.put_blob(blob);
    }
    registry.put_manifest("library/strict", "1", &m);
    let reference = format!("{}/library/strict:1", registry.host());
    (registry, reference)
}

/// The policy refusals in `records`, as (op, path, errno, rule).
fn refusals(records: &[boxcar_proto::Record]) -> Vec<(String, String, i64, Option<String>)> {
    of_kind(records, "fs.denied")
        .into_iter()
        .filter(|r| r.data["reason"] == "policy")
        .map(|r| {
            (
                r.data["op"].as_str().unwrap().to_owned(),
                r.data["path"].as_str().unwrap().to_owned(),
                r.data["errno"].as_i64().unwrap(),
                r.data["rule"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

/// `agent-isolate-strict`, from an image with no `/etc/resolv.conf` and a
/// real `nc` program file: the session boots, resolves and reaches an
/// allowed host by name, writes `/workspace` and `/tmp`, and is refused a
/// write to `/etc` (EROFS) and `nc` however it is tried: run, through a
/// symlink, through the loader, copied, hard-linked (EACCES). Each refusal
/// is a `fs.denied{reason: "policy"}` with its `policy_denial` finding.
#[test]
fn agent_isolate_strict_holds_in_a_session() {
    let Some(guest) = networked_guest_or_skip("agent_isolate_strict_holds_in_a_session") else {
        return;
    };
    let (_registry, reference) = publish_strict(&guest.rootfs);
    let scratch = Scratch::new();
    let script = "\
        wget -q -O /dev/null https://github.com/ && echo reached || echo unreached; \
        echo ok > /workspace/w && echo wrote-workspace; \
        echo ok > /tmp/t && echo wrote-tmp; \
        (echo no > /etc/boxcar-test) 2>/dev/null && echo wrote-etc || echo refused-etc; \
        /usr/bin/nc -h >/dev/null 2>&1; echo nc=$?; \
        ln -s /usr/bin/nc /workspace/n && /workspace/n -h >/dev/null 2>&1; echo link=$?; \
        /lib/ld-musl-x86_64.so.1 /usr/bin/nc -h >/dev/null 2>&1 && echo loaded || echo refused-loader; \
        cp /usr/bin/nc /tmp/x 2>/dev/null && echo copied || echo refused-copy; \
        ln /usr/bin/nc /tmp/hard 2>/dev/null && echo linked || echo refused-link; \
        echo done";
    let run = run_image(
        &guest,
        &scratch,
        &reference,
        &["--policy", "agent-isolate-strict"],
        &["sh", "-c", script],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(!run.stderr.contains("warning: --policy"), "{}", run.stderr);
    for line in [
        "reached",
        "wrote-workspace",
        "wrote-tmp",
        "refused-etc",
        "nc=126",
        "link=126",
        "refused-loader",
        "refused-copy",
        "refused-link",
        "done",
    ] {
        assert!(
            run.stdout.lines().any(|l| l == line),
            "{line}: {}",
            run.describe()
        );
    }
    let records = run.records();
    let loaded = of_kind(&records, "policy.loaded");
    assert_eq!(loaded[0].data["name"], "agent-isolate-strict");
    // Reached by name: the lookup and the connection allowed.
    assert!(
        of_kind(&records, "net.connect")
            .iter()
            .any(|r| r.data["verdict"] == "allow"
                && r.data["names"]
                    .as_array()
                    .is_some_and(|names| names.iter().any(|n| n == "github.com"))),
        "no allowed connection to github.com"
    );
    let refused = refusals(&records);
    let has = |op: &str, path: &str, errno: i64, rule: Option<&str>| {
        refused
            .iter()
            .any(|(o, p, e, r)| o == op && p == path && *e == errno && r.as_deref() == rule)
    };
    assert!(has("create", "/etc/boxcar-test", 30, None), "{refused:?}");
    assert!(has("exec", "/usr/bin/nc", 13, Some("**/nc")), "{refused:?}");
    assert!(
        has("open", "/usr/bin/nc", 13, Some("**/nc")),
        "the loader, the copy: {refused:?}"
    );
    assert!(has("link", "/tmp/hard", 13, Some("**/nc")), "{refused:?}");
    // Every refusal is a finding.
    let denials: Vec<&boxcar_proto::Record> = of_kind(&records, "finding")
        .into_iter()
        .filter(|f| f.data["rule"] == "policy_denial")
        .filter(|f| {
            f.data["summary"]
                .as_str()
                .is_some_and(|s| s.contains("refused by the policy"))
        })
        .collect();
    assert!(
        denials.len() >= refused.len(),
        "{} findings for {refused:?}",
        denials.len()
    );
    assert!(denials.iter().any(|f| f.data["summary"]
        == "exec of /usr/bin/nc was refused by the policy ([exec] deny **/nc)"));
    assert!(denials.iter().any(|f| f.data["summary"]
        == "create of /etc/boxcar-test was refused by the policy (outside [fs] writable)"));
}

/// A writable exception granted during a run lets the guest write what it
/// names, and once it expires the same write is refused; the log has the
/// grant (`policy.exception`) and the expiry (`policy.changed{by_pid: 0}`).
/// The policy file names no `writable`, so the default's `/tmp` is
/// writable, and what is written there is recorded.
#[test]
fn a_writable_exception_expires_during_a_run() {
    let Some(guest) = guest_or_skip("a_writable_exception_expires_during_a_run") else {
        return;
    };
    let (_registry, reference) = publish_strict(&guest.rootfs);
    let scratch = Scratch::new();
    let policy = scratch.path("policy.toml");
    fs::write(&policy, "version = 1\n").unwrap();
    let script = "\
        t=$(mktemp) && echo t > \"$t\" && echo TMP_WROTE; \
        (echo a > /etc/x) 2>/dev/null && echo FIRST_WROTE || echo FIRST_REFUSED; \
        while [ ! -e /workspace/go ]; do sleep 1; done; \
        (echo b > /etc/x) 2>/dev/null && echo SECOND_WROTE || echo SECOND_REFUSED; \
        while [ ! -e /workspace/go2 ]; do sleep 1; done; \
        (echo c > /etc/x) 2>/dev/null && echo THIRD_WROTE || echo THIRD_REFUSED";
    let cache = scratch.path("cache");
    let root = [
        "--image",
        reference.as_str(),
        "--cache-dir",
        cache.to_str().unwrap(),
    ];
    let mut running = start_with_root(
        &guest,
        &scratch,
        &root,
        &["--policy", policy.to_str().unwrap()],
        &["sh", "-c", script],
        &[],
    );
    let control = running.control();
    running.until("the first write to be refused", |run| {
        run.stdout().contains("FIRST_REFUSED")
    });
    let granted = boxcar(
        &["policy", "allow", "--writable", "/etc/**", "--ttl", "3s"],
        &control,
    );
    assert!(granted.status.success(), "{}", text(&granted.stderr));
    assert_eq!(
        text(&granted.stdout),
        "policy version 2 (writable exception /etc/** for 3 s)\n"
    );
    fs::write(scratch.path("workspace").join("go"), "").unwrap();
    running.until("the second write", |run| run.stdout().contains("SECOND_"));
    // The exception's three seconds, and the expiry on the VMM's loop.
    running.until("the exception to expire", |_| {
        let listed = boxcar(&["policy", "exception", "ls", "--json"], &control);
        text(&listed.stdout).trim() == "[]"
    });
    fs::write(scratch.path("workspace").join("go2"), "").unwrap();
    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    for line in [
        "TMP_WROTE",
        "FIRST_REFUSED",
        "SECOND_WROTE",
        "THIRD_REFUSED",
    ] {
        assert!(run.stdout.contains(line), "{line}: {}", run.describe());
    }
    let records = run.records();
    let granted = of_kind(&records, "policy.exception");
    assert_eq!(granted.len(), 1, "{granted:?}");
    assert_eq!(granted[0].data["kind"], "writable");
    assert_eq!(granted[0].data["rule"], "/etc/**");
    assert_eq!(granted[0].data["ttl_s"], 3);
    assert_eq!(granted[0].data["version"], 2);
    let changed = of_kind(&records, "policy.changed");
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert_eq!(
        changed[0].data,
        serde_json::json!({"by_pid": 0, "version": 3})
    );
    assert!(changed[0].seq > granted[0].seq);
    let refused: Vec<u64> = of_kind(&records, "fs.denied")
        .into_iter()
        .filter(|r| r.data["reason"] == "policy" && r.data["path"] == "/etc/x")
        .map(|r| r.seq)
        .collect();
    assert!(
        refused.iter().any(|seq| *seq < granted[0].seq),
        "{refused:?}"
    );
    assert!(
        refused.iter().any(|seq| *seq > changed[0].seq),
        "{refused:?}"
    );
    // The default's `/tmp`, written and recorded as any other share path.
    let creates = of_kind(&records, "fs.create");
    assert!(
        creates.iter().any(|r| r.data["mount"] == "root"
            && r.data["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("/tmp/"))
            && r.data["result"]["ok"] == true),
        "{creates:?}"
    );
}
