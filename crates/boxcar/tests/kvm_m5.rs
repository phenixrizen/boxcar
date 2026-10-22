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
    boxcar, boxcar_run, guest_or_skip, networked_guest_or_skip, of_kind, start, start_env,
    start_with_root, text, Guest, Run, Scratch,
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

/// With `--ownership override` the share shows what the override says: a
/// host file given one shows its owner and stands for the device node it
/// names, which the guest reads; what carries none is the session's own,
/// so a root session writes the share. The session has no capability
/// whatever its uid, so `chown` and `mknod` are refused by the guest
/// kernel in either mode, and the host file stays the host user's (#5).
#[test]
fn the_ownership_override_is_what_the_guest_sees_on_a_share() {
    let Some(guest) = guest_or_skip("the_ownership_override_is_what_the_guest_sees_on_a_share")
    else {
        return;
    };
    let script = "echo x > /workspace/f && stat -c 'f %u:%g' /workspace/f; \
                  stat -c 'null %u:%g %F' /workspace/null; \
                  cat /workspace/null && echo read-null; \
                  chown 0:7 /workspace/f 2>/dev/null && echo chowned || echo refused-chown; \
                  mknod /workspace/n c 1 3 2>/dev/null && echo made || echo refused-mknod; \
                  echo done";
    // SAFETY: getuid and getgid take no arguments.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let host_f = format!("f {uid}:{gid}");
    let host_null = format!("null {uid}:{gid} regular empty file");
    let refused = ["read-null", "refused-chown", "refused-mknod", "done"];
    for (flags, want) in [
        (
            &["--user", "0", "--ownership", "override"][..],
            vec!["f 0:0", "null 7:7 character special file"],
        ),
        (&[][..], vec![host_f.as_str(), host_null.as_str()]),
    ] {
        let scratch = Scratch::new();
        let workspace = scratch.path("workspace");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("null"), b"").unwrap();
        set_override(&workspace.join("null"), "uid=7 gid=7 dev=c:1:3");
        let run = boxcar_run(&guest, &scratch, flags, &["sh", "-c", script]);
        assert_eq!(run.status.code(), Some(0), "{}", run.describe());
        for line in want.iter().chain(refused.iter()) {
            assert!(
                run.stdout.lines().any(|l| l.trim() == *line),
                "{flags:?}: {line}: {}",
                run.describe()
            );
        }
        let meta = fs::metadata(workspace.join("f")).unwrap();
        assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), uid);
    }
}

/// Writes the ownership override `text` on the host file at `path`.
fn set_override(path: &Path, text: &str) {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = c"user.boxcar.stat";
    // SAFETY: setxattr reads the two C strings and `text.len()` bytes.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            text.as_ptr().cast(),
            text.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr: {}", std::io::Error::last_os_error());
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
        cp /bin/busybox /dev/shm/nc && /dev/shm/nc -h >/dev/null 2>&1; echo named=$?; \
        cp /bin/busybox /dev/shm/true && /dev/shm/true; echo other=$?; \
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
        // Off the shares, under a denied name: refused by the sensor; under
        // another name: not, which is the bound (#33).
        "named=126",
        "other=0",
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
    assert_eq!(
        loaded[0].data["exec_ring1"],
        serde_json::json!({"names": 7, "left_to_ring0": 0}),
        "{:?}",
        loaded[0]
    );
    // The sensor's refusal of the copy under the denied name, and its
    // finding, beside the shares' refusals below.
    let denied = of_kind(&records, "proc.exec_denied");
    assert!(
        denied.iter().any(|r| r.data["filename"] == "/dev/shm/nc"),
        "no proc.exec_denied for /dev/shm/nc: {denied:?}\n{}",
        run.describe()
    );
    assert!(
        !denied.iter().any(|r| r.data["filename"] == "/dev/shm/true"),
        "{denied:?}"
    );
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
        == "exec of /dev/shm/nc was refused by the policy ([exec] deny, by its name, through the sensor)"));
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

/// `boxcar run` confines the VMM by default: `vmm.start` records the
/// seccomp filter (`enforce`, or what `BOXCAR_SECCOMP` asks for a whole
/// run of the suites) and the Landlock domain (`full` or `partial`, as the
/// kernel allows), and a session that writes its workspace ends as usual.
#[test]
fn a_session_runs_confined() {
    let Some(guest) = guest_or_skip("a_session_runs_confined") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &[],
        &["sh", "-c", "echo confined > /workspace/c && echo WROTE"],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("WROTE"), "{}", run.describe());
    let records = run.records();
    let start = of_kind(&records, "vmm.start");
    let hardening = &start[0].data["hardening"];
    let seccomp = std::env::var("BOXCAR_SECCOMP").unwrap_or_else(|_| "enforce".into());
    assert_eq!(hardening["seccomp"], seccomp.as_str(), "{hardening}");
    assert!(
        matches!(hardening["landlock"].as_str(), Some("full" | "partial")),
        "{hardening}"
    );
    assert_eq!(
        fs::read_to_string(scratch.path("workspace").join("c")).unwrap(),
        "confined\n"
    );
    assert_eq!(of_kind(&records, "vmm.stop").len(), 1);
}

/// A call off the allowlist kills the VMM: the run dies by `SIGSYS`, its
/// log has no `vmm.stop`, and `boxcar audit verify` says the log is intact
/// or that its tail is cut, never that it is broken. The run asks for
/// `--seccomp enforce` itself, whatever its lane's `BOXCAR_SECCOMP`.
#[test]
fn a_seccomp_kill_is_a_crash() {
    use std::os::unix::process::ExitStatusExt;

    let Some(guest) = guest_or_skip("a_seccomp_kill_is_a_crash") else {
        return;
    };
    let scratch = Scratch::new();
    let mut running = start_env(
        &guest,
        &scratch,
        &["--seccomp", "enforce"],
        &["sh", "-c", "echo UP; sleep 60"],
        &[("BOXCAR_TEST_SECCOMP_TRIP", Path::new("5000"))],
    );
    running.until("the session to start", |run| run.stdout().contains("UP"));
    let run = running.finish();
    assert_eq!(
        run.status.signal(),
        Some(libc::SIGSYS),
        "{}",
        run.describe()
    );
    let dir = run.session_dir();
    let verify = std::process::Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["audit", "verify"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        matches!(verify.status.code(), Some(0 | 4)),
        "{}\n{}",
        verify.status,
        text(&verify.stdout)
    );
    let records: Vec<_> = boxcar_audit::LogReader::open(&dir)
        .unwrap()
        .records()
        .map_while(Result::ok)
        .collect();
    assert_eq!(of_kind(&records, "vmm.start").len(), 1, "{records:?}");
    assert!(of_kind(&records, "vmm.stop").is_empty(), "{records:?}");
}

/// A session's log, after the run, exports in both forms: a trace whose
/// session span names the session, and OCSF events that each point back to
/// it, the workspace's new file among them.
#[test]
fn a_session_exports_to_otlp_and_ocsf() {
    let Some(guest) = guest_or_skip("a_session_exports_to_otlp_and_ocsf") else {
        return;
    };
    let scratch = Scratch::new();
    let run = boxcar_run(
        &guest,
        &scratch,
        &[],
        &["sh", "-c", "echo exported > /workspace/e"],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    let dir = run.session_dir();
    let session = dir.file_name().unwrap().to_str().unwrap().to_owned();
    let export = |format: &str| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_boxcar"))
            .args(["audit", "export"])
            .arg(&dir)
            .args(["--format", format])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        text(&out.stdout)
    };

    let trace: serde_json::Value = serde_json::from_str(&export("otlp")).unwrap();
    let spans = trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .unwrap();
    let root = &spans[0];
    assert_eq!(root["name"], "boxcar.session", "{root}");
    assert_eq!(root["traceId"], session.replace('-', ""));

    let events: Vec<serde_json::Value> = export("ocsf")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|e| e["metadata"]["correlation_uid"] == session.as_str()),
        "every event names the session"
    );
    assert!(
        events
            .iter()
            .any(|e| e["class_uid"] == 1001 && e["file"]["path"] == "/workspace/e"),
        "the workspace's new file"
    );
}

/// `boxcar audit verify --control` checks a running session's log against
/// its audit writer's head, then again from past that head: the log has
/// grown meanwhile, since the second connection is recorded
/// (`control.connect`) before it asks. Once the run has ended, the whole
/// log verifies on disk.
#[test]
fn a_running_sessions_log_verifies_against_its_writers_head() {
    let Some(guest) = guest_or_skip("a_running_sessions_log_verifies_against_its_writers_head")
    else {
        return;
    };
    let scratch = Scratch::new();
    let mut running = start(
        &guest,
        &scratch,
        &[],
        &[
            "sh",
            "-c",
            "echo UP; while [ ! -e /workspace/go ]; do sleep 1; done; echo DONE",
        ],
    );
    let control = running.control();
    running.until("the session to start", |run| run.stdout().contains("UP"));

    let first = boxcar(&["audit", "verify", "--json"], &control);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}\n{}",
        text(&first.stdout),
        text(&first.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(summary["ok"], true, "{summary}");
    assert_eq!(summary["from_seq"], 1, "{summary}");
    let head = summary["head_seq"].as_u64().unwrap();
    assert_eq!(summary["to_seq"], head, "{summary}");
    assert!(head > 1, "{summary}");

    let from = (head + 1).to_string();
    let second = boxcar(&["audit", "verify", "--from-seq", &from], &control);
    let said = text(&second.stdout);
    assert_eq!(
        second.status.code(),
        Some(0),
        "{said}\n{}",
        text(&second.stderr)
    );
    assert!(
        said.starts_with(&format!("ok: verified seq {from}..")) && said.contains("b3:"),
        "{said}"
    );

    fs::write(scratch.path("workspace").join("go"), "").unwrap();
    let run = running.finish();
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains("DONE"), "{}", run.describe());
    let verify = std::process::Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["audit", "verify"])
        .arg(run.session_dir())
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(0), "{}", text(&verify.stdout));
    let records = run.records();
    assert!(of_kind(&records, "control.connect").len() >= 2);
}

/// What a collector was sent: the request's path and body.
fn collect_one_post(listener: std::net::TcpListener) -> (String, Vec<u8>) {
    use std::io::{BufRead, BufReader};
    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
    let mut length = 0usize;
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let mut stream = stream;
    let answer = br#"{"partialSuccess":{}}"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        answer.len()
    )
    .unwrap();
    stream.write_all(answer).unwrap();
    (path, body)
}

/// The M5 demo, against the test registry: a session from an image under
/// `agent-isolate` installs a package with apk and runs it, its log
/// verifies, and its OTLP export, sent to a collector (a minimal OTLP/HTTP
/// receiver on the loopback), is one trace whose session span and resource
/// name the session and the image. The demo against Docker Hub and the
/// OpenTelemetry Collector is recorded in the pull request that finished
/// M5.
#[test]
fn the_m5_demo_runs_against_the_test_registry() {
    let Some(guest) = guest_or_skip("the_m5_demo_runs_against_the_test_registry") else {
        return;
    };
    let image = publish(&guest.rootfs);
    let scratch = Scratch::new();
    let run = run_image(
        &guest,
        &scratch,
        &image.by_tag,
        &["--policy", "agent-isolate"],
        &[
            "/bin/sh",
            "-c",
            "apk add --allow-untrusted --no-network /tmp/boxcar-test-1.0-r0.apk && boxcar-test",
        ],
    );
    assert_eq!(run.status.code(), Some(0), "{}", run.describe());
    assert!(run.stdout.contains(MARKER), "{}", run.describe());
    let dir = run.session_dir();
    let session = dir.file_name().unwrap().to_str().unwrap().to_owned();

    let verify = std::process::Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["audit", "verify"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(0), "{}", text(&verify.stdout));
    assert!(text(&verify.stdout).starts_with("ok: "));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let collector = std::thread::spawn(move || collect_one_post(listener));
    let export = std::process::Command::new(env!("CARGO_BIN_EXE_boxcar"))
        .args(["audit", "export"])
        .arg(&dir)
        .args(["--format", "otlp", "--otlp-endpoint", &url])
        .output()
        .unwrap();
    let (path, body) = collector.join().unwrap();
    assert_eq!(export.status.code(), Some(0), "{}", text(&export.stderr));
    assert_eq!(path, "/v1/traces");
    let trace: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let resource = &trace["resourceSpans"][0]["resource"]["attributes"];
    let attribute = |key: &str| {
        resource
            .as_array()
            .unwrap()
            .iter()
            .find(|kv| kv["key"] == key)
            .map(|kv| kv["value"]["stringValue"].clone())
    };
    assert_eq!(attribute("boxcar.session.id"), Some(session.clone().into()));
    assert!(
        attribute("boxcar.image.reference")
            .and_then(|v| v.as_str().map(str::to_owned))
            .is_some_and(|r| r.ends_with("/library/alpine:3.22")),
        "{resource}"
    );
    assert!(attribute("boxcar.policy.sha256").is_some(), "{resource}");
    let spans = trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .unwrap();
    assert_eq!(spans[0]["name"], "boxcar.session");
    assert_eq!(spans[0]["traceId"], session.replace('-', ""));
}
