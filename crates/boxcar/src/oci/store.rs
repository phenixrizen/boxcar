// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The image cache: verified blobs, unpacked images and tag refs, each at
//! its final name only once complete and durable. Everything being built
//! or removed has a `.`-name no final name can have, carrying the pid and
//! a counter, and only final names are ever read.
//!
//! ```text
//! blobs/sha256/<hex>                        a verified blob
//! images/<manifest-hex>/rootfs/             the unpacked tree
//! images/<manifest-hex>/image.json          what the image is made of
//! refs/<registry>/<repository>/_tags/<tag>  a file holding a manifest digest
//! .lock                                     shared by a pull, exclusive by rm and prune
//! ```

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::reference::{Digest, Reference};
use super::unpack::delete_tree;

/// Tells two staging names apart within one process.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// `.<name>.<kind>.<pid>-<n>`: a name no final name can have.
fn staging_name(name: &str, kind: &str) -> String {
    format!(
        ".{name}.{kind}.{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The pid in a staging or deleting name, if it is one.
fn staging_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix('.')?;
    let at = rest.find(".partial.").or_else(|| rest.find(".deleting."))?;
    let tail = &rest[at..];
    let tail = tail
        .strip_prefix(".partial.")
        .or_else(|| tail.strip_prefix(".deleting."))?;
    let (pid, counter) = tail.split_once('-')?;
    if counter.is_empty() || !counter.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

/// Whether the process `pid` is still running.
fn alive(pid: u32) -> bool {
    pid == std::process::id() || Path::new(&format!("/proc/{pid}")).exists()
}

/// A name that is not staging, deleting or the lock: a final one.
fn is_final(name: &str) -> bool {
    !name.starts_with('.')
}

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// The component under which a repository's tags live: no repository
/// component can start with `_`, so a repository and a deeper
/// repository's tag never claim one path.
pub const TAGS: &str = "_tags";
/// The directory, beside `_tags`, of a repository's index entries: files
/// named by an index's digest holding the `linux/amd64` manifest's, so a
/// reference by an index's digest is found offline. Lookups, not refs:
/// only tags keep an image from `prune`; an entry goes with its image.
pub const INDEXES: &str = "_indexes";
/// Shared by pulls, exclusive for rm and prune.
const LOCK: &str = ".lock";
/// Exclusive for the sweep, which runs under the shared lock.
const SWEEP_LOCK: &str = ".sweep.lock";

/// What an image is made of, kept beside its tree as `image.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageJson {
    pub manifest: Digest,
    pub config: Digest,
    pub layers: Vec<LayerRef>,
    pub defaults: Defaults,
    /// Paths of the device nodes and FIFOs not made.
    pub skipped: Vec<String>,
    /// Paths whose mode in the tree is not the image's, with the image's
    /// mode: the tree stores every entry readable by its owner. Absent in
    /// trees cached before this field, which may hold unreadable entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modes: Vec<(String, u32)>,
    /// How the tree carries the image's ownership: [`OWNERSHIP_OVERRIDE`]
    /// (each entry's owner, special bits and device nodes in
    /// `user.boxcar.stat`, shown in the guest). Absent in trees cached
    /// before: those show the host user as every owner and have no device
    /// nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<String>,
}

/// The `ownership` of a tree unpacked with the override.
pub const OWNERSHIP_OVERRIDE: &str = "override";

/// One layer of an image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRef {
    pub digest: Digest,
    pub media_type: String,
    pub size: u64,
}

/// What the image's config says a container of it runs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub user: String,
}

/// The durability and renaming calls the store makes, so a test can see
/// their order.
pub trait Fs: Send + Sync {
    fn fsync_file(&self, file: &File) -> io::Result<()>;
    fn fsync_dir(&self, dir: &Path) -> io::Result<()>;
    /// Makes every write on `dir`'s filesystem durable.
    fn syncfs(&self, dir: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn unlink(&self, path: &Path) -> io::Result<()>;
}

/// The real calls.
pub struct RealFs;

impl Fs for RealFs {
    fn fsync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn fsync_dir(&self, dir: &Path) -> io::Result<()> {
        File::open(dir)?.sync_all()
    }

    fn syncfs(&self, dir: &Path) -> io::Result<()> {
        let dir = File::open(dir)?;
        // SAFETY: a plain syscall on a descriptor we hold.
        if unsafe { libc::syncfs(dir.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn unlink(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

/// The cache.
pub struct Store {
    dir: PathBuf,
    fs: Box<dyn Fs>,
}

/// A held lock file.
pub struct Lock {
    file: File,
}

/// A blob being written: hashed as it goes, named only when it checks out.
pub struct BlobWriter<'s> {
    store: &'s Store,
    expected: Digest,
    size: u64,
    partial: PathBuf,
    file: Option<File>,
    written: u64,
    hasher: ring::digest::Context,
    done: bool,
}

/// An image being built in a staging directory.
pub struct ImageStaging<'s> {
    store: &'s Store,
    digest: Digest,
    partial: PathBuf,
    done: bool,
}

/// What `ls` shows.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub refs: Vec<RefEntry>,
    /// The index entries: an index's digest and the manifest it led to.
    pub indexes: Vec<IndexEntry>,
    /// Every image at a final name.
    pub images: Vec<Digest>,
}

/// One index entry under a repository's `_indexes`.
#[derive(Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub registry: String,
    pub repository: String,
    pub index: Digest,
    pub manifest: Digest,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RefEntry {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: Digest,
}

/// What prune removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub images: usize,
    pub blobs: usize,
}

impl Store {
    /// The cache at `dir`, made (mode 0700, with its subdirectories) when
    /// missing.
    pub fn open(dir: &Path) -> io::Result<Store> {
        Store::open_with(dir, Box::new(RealFs))
    }

    pub fn open_with(dir: &Path, fs: Box<dyn Fs>) -> io::Result<Store> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        for sub in ["", "blobs/sha256", "images", "refs"] {
            builder.create(dir.join(sub))?;
        }
        for name in [LOCK, SWEEP_LOCK] {
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(dir.join(name))?;
        }
        Ok(Store {
            dir: dir.to_path_buf(),
            fs,
        })
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Held by a pull, so a prune waits for it.
    pub fn lock_shared(&self) -> io::Result<Lock> {
        self.lock(LOCK, libc::LOCK_SH)
    }

    /// Held by rm and prune: no pull runs meanwhile.
    pub fn lock_exclusive(&self) -> io::Result<Lock> {
        self.lock(LOCK, libc::LOCK_EX)
    }

    fn lock(&self, name: &str, how: libc::c_int) -> io::Result<Lock> {
        let file = File::open(self.dir.join(name))?;
        // SAFETY: flock on a descriptor we hold; it blocks until taken.
        if unsafe { libc::flock(file.as_raw_fd(), how) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock { file })
    }

    /// Removes the staging and deleting entries of pids that are gone.
    /// Answers how many. One sweep at a time: two pulls starting together
    /// both hold the shared lock, and must not delete the same tree.
    pub fn sweep(&self) -> io::Result<usize> {
        let _sweeping = self.lock(SWEEP_LOCK, libc::LOCK_EX)?;
        let mut removed = 0;
        let mut dirs = vec![self.dir.join("blobs/sha256"), self.dir.join("images")];
        collect_dirs(&self.dir.join("refs"), &mut dirs)?;
        for dir in dirs {
            // The directory first: an interrupted rm may have renamed an
            // image to its deleting name without syncing the rename, and
            // the tree must not be half deleted under its final name.
            let mut synced = false;
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let Some(pid) = staging_pid(name) else {
                    continue;
                };
                if alive(pid) {
                    continue;
                }
                if !synced {
                    self.fs.fsync_dir(&dir)?;
                    synced = true;
                }
                if entry.file_type()?.is_dir() {
                    delete_tree(&dir, name)?;
                } else {
                    fs::remove_file(entry.path())?;
                }
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.dir.join("blobs/sha256").join(digest.hex())
    }

    pub fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).is_file()
    }

    /// A writer for the blob `digest` of `size` bytes.
    pub fn blob_writer(&self, digest: &Digest, size: u64) -> io::Result<BlobWriter<'_>> {
        let partial = self
            .dir
            .join("blobs/sha256")
            .join(staging_name(digest.hex(), "partial"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial)?;
        Ok(BlobWriter {
            store: self,
            expected: digest.clone(),
            size,
            partial,
            file: Some(file),
            written: 0,
            hasher: ring::digest::Context::new(&ring::digest::SHA256),
            done: false,
        })
    }

    /// A staging directory for the image `digest`, with an empty `rootfs`.
    pub fn stage_image(&self, digest: &Digest) -> io::Result<ImageStaging<'_>> {
        let partial = self
            .dir
            .join("images")
            .join(staging_name(digest.hex(), "partial"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&partial)?;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o755);
        builder.create(partial.join("rootfs"))?;
        Ok(ImageStaging {
            store: self,
            digest: digest.clone(),
            partial,
            done: false,
        })
    }

    /// The image's directory, when it is at its final name.
    pub fn image_dir(&self, digest: &Digest) -> Option<PathBuf> {
        let dir = self.dir.join("images").join(digest.hex());
        dir.is_dir().then_some(dir)
    }

    /// The image's directory, when it is at its final name, made durable
    /// first: the pull that put it there may not have synced the rename
    /// yet, and a ref written to it must not outlive it.
    pub fn existing_image(&self, digest: &Digest) -> io::Result<Option<PathBuf>> {
        let Some(dir) = self.image_dir(digest) else {
            return Ok(None);
        };
        self.fs.fsync_dir(&self.dir.join("images"))?;
        Ok(Some(dir))
    }

    pub fn image_json(&self, digest: &Digest) -> io::Result<ImageJson> {
        let dir = self
            .image_dir(digest)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no image {digest}")))?;
        let text = fs::read(dir.join("image.json"))?;
        serde_json::from_slice(&text)
            .map_err(|error| invalid(format!("image.json of {digest} does not parse: {error}")))
    }

    /// The directory a reference's tags live in.
    fn tags_dir(&self, reference: &Reference) -> PathBuf {
        self.dir
            .join("refs")
            .join(reference.registry())
            .join(reference.repository())
            .join(TAGS)
    }

    fn indexes_dir(&self, reference: &Reference) -> PathBuf {
        self.dir
            .join("refs")
            .join(reference.registry())
            .join(reference.repository())
            .join(INDEXES)
    }

    fn ref_path(&self, reference: &Reference) -> io::Result<PathBuf> {
        let tag = reference.tag().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a reference without a tag has no ref",
            )
        })?;
        Ok(self.tags_dir(reference).join(tag))
    }

    /// Points `reference`'s tag at `digest`.
    pub fn write_ref(&self, reference: &Reference, digest: &Digest) -> io::Result<()> {
        let path = self.ref_path(reference)?;
        let tag = reference.tag().expect("checked by ref_path");
        self.write_entry(&self.tags_dir(reference), tag, &path, digest)
    }

    /// Records that the index `index` of `reference`'s repository led to
    /// the manifest `manifest`, replacing what the entry said before.
    pub fn write_index(
        &self,
        reference: &Reference,
        index: &Digest,
        manifest: &Digest,
    ) -> io::Result<()> {
        let dir = self.indexes_dir(reference);
        let path = dir.join(index.hex());
        self.write_entry(&dir, index.hex(), &path, manifest)
    }

    /// Writes `digest` as the entry `name` in `dir` (a tags or indexes
    /// directory), at its final name `path` only once whole and durable.
    fn write_entry(&self, dir: &Path, name: &str, path: &Path, digest: &Digest) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir)?;
        let staging = dir.join(staging_name(name, "partial"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?;
        let written = (|| {
            file.write_all(digest.to_string().as_bytes())?;
            file.write_all(b"\n")?;
            self.fs.fsync_file(&file)
        })();
        if let Err(error) = written {
            let _ = fs::remove_file(&staging);
            return Err(error);
        }
        drop(file);
        self.fs.rename(&staging, path)?;
        // The tags directory, then every directory above it up to `refs`:
        // the first ref of a repository made them, and a crash must not
        // take the chain, and the tag with it, from under a published
        // image.
        let refs = self.dir.join("refs");
        for ancestor in dir.ancestors() {
            self.fs.fsync_dir(ancestor)?;
            if ancestor == refs {
                break;
            }
        }
        Ok(())
    }

    // `boxcar run --image --pull missing` (Task 3) reads the ref without asking
    // the registry; until then only the tests read one.
    #[allow(dead_code)]
    pub fn read_ref(&self, reference: &Reference) -> io::Result<Option<Digest>> {
        read_entry(&self.ref_path(reference)?)
    }

    /// The manifest the index entry `index` of `reference`'s repository
    /// led to, if there is one.
    pub fn read_index(&self, reference: &Reference, index: &Digest) -> io::Result<Option<Digest>> {
        read_entry(&self.indexes_dir(reference).join(index.hex()))
    }

    /// The manifest digest of the cached image `reference` names, when it
    /// is whole in the cache: a tag through its ref, a digest as the image
    /// itself or through its index entry. An entry whose image is gone
    /// counts for nothing.
    pub fn find(&self, reference: &Reference) -> io::Result<Option<Digest>> {
        let manifest = match reference.digest() {
            Some(digest) if self.image_dir(digest).is_some() => digest.clone(),
            Some(digest) => match self.read_index(reference, digest)? {
                Some(manifest) => manifest,
                None => return Ok(None),
            },
            None => match self.read_ref(reference)? {
                Some(manifest) => manifest,
                None => return Ok(None),
            },
        };
        Ok(self.image_dir(&manifest).map(|_| manifest))
    }

    pub fn list(&self) -> io::Result<Listing> {
        let mut listing = Listing::default();
        for entry in fs::read_dir(self.dir.join("images"))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if is_final(name) && entry.file_type()?.is_dir() {
                if let Ok(digest) = Digest::parse(&format!("sha256:{name}")) {
                    listing.images.push(digest);
                }
            }
        }
        listing.images.sort_by(|a, b| a.hex().cmp(b.hex()));
        let mut tags_dirs = Vec::new();
        collect_dirs(&self.dir.join("refs"), &mut tags_dirs)?;
        for dir in tags_dirs {
            let kind = dir.file_name().and_then(|n| n.to_str());
            if kind != Some(TAGS) && kind != Some(INDEXES) {
                continue;
            }
            let indexes = kind == Some(INDEXES);
            let rel = dir
                .strip_prefix(self.dir.join("refs"))
                .map_err(|_| invalid("a tags directory outside refs"))?;
            let comps: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            // registry, repository components, `_tags`.
            if comps.len() < 3 {
                continue;
            }
            let registry = comps[0].clone();
            let repository = comps[1..comps.len() - 1].join("/");
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(tag) = name.to_str() else {
                    continue;
                };
                if !is_final(tag) || !entry.file_type()?.is_file() {
                    continue;
                }
                let text = fs::read_to_string(entry.path())?;
                let digest = Digest::parse(text.trim()).map_err(|error| {
                    invalid(format!(
                        "the ref {} does not parse: {error}",
                        entry.path().display()
                    ))
                })?;
                if indexes {
                    let Ok(index) = Digest::parse(&format!("sha256:{tag}")) else {
                        continue;
                    };
                    listing.indexes.push(IndexEntry {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        index,
                        manifest: digest,
                    });
                } else {
                    listing.refs.push(RefEntry {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        tag: tag.to_owned(),
                        digest,
                    });
                }
            }
        }
        listing.refs.sort_by(|a, b| {
            (&a.registry, &a.repository, &a.tag).cmp(&(&b.registry, &b.repository, &b.tag))
        });
        listing.indexes.sort_by(|a, b| {
            (&a.registry, &a.repository, a.index.hex()).cmp(&(
                &b.registry,
                &b.repository,
                b.index.hex(),
            ))
        });
        Ok(listing)
    }

    /// Removes `reference`'s tag; whether there was one.
    pub fn remove_ref(&self, reference: &Reference) -> io::Result<bool> {
        let path = self.ref_path(reference)?;
        if !path.is_file() {
            return Ok(false);
        }
        self.fs.unlink(&path)?;
        self.fs.fsync_dir(&self.tags_dir(reference))?;
        Ok(true)
    }

    /// Removes the image and every ref naming it; whether there was one.
    pub fn remove_image(&self, digest: &Digest) -> io::Result<bool> {
        let Some(final_dir) = self.image_dir(digest) else {
            return Ok(false);
        };
        // The refs first: every one unlinked, then every tags directory
        // synced, before the image goes. Every one, not only those changed
        // now: an rm interrupted after an unlink and before the sync left
        // one with an unsynced unlink and nothing to show for it.
        let refs = self.dir.join("refs");
        let listing = self.list()?;
        for entry in &listing.refs {
            if entry.digest != *digest {
                continue;
            }
            let dir = refs
                .join(&entry.registry)
                .join(&entry.repository)
                .join(TAGS);
            self.fs.unlink(&dir.join(&entry.tag))?;
        }
        for entry in &listing.indexes {
            if entry.manifest != *digest {
                continue;
            }
            let dir = refs
                .join(&entry.registry)
                .join(&entry.repository)
                .join(INDEXES);
            self.fs.unlink(&dir.join(entry.index.hex()))?;
        }
        let mut dirs = Vec::new();
        collect_dirs(&refs, &mut dirs)?;
        dirs.sort();
        for dir in dirs.iter().filter(|dir| {
            dir.file_name() == Some(OsStr::new(TAGS))
                || dir.file_name() == Some(OsStr::new(INDEXES))
        }) {
            self.fs.fsync_dir(dir)?;
        }
        let deleting = staging_name(digest.hex(), "deleting");
        let images = self.dir.join("images");
        self.fs.rename(&final_dir, &images.join(&deleting))?;
        self.fs.fsync_dir(&images)?;
        delete_tree(&images, &deleting)?;
        Ok(true)
    }

    /// Removes the images no ref names and the blobs no remaining image
    /// names.
    pub fn prune(&self) -> io::Result<Pruned> {
        self.sweep()?;
        let mut pruned = Pruned::default();
        let listing = self.list()?;
        let referenced: BTreeSet<&Digest> = listing.refs.iter().map(|r| &r.digest).collect();
        let mut kept = Vec::new();
        for image in &listing.images {
            if referenced.contains(image) {
                kept.push(image.clone());
            } else if self.remove_image(image)? {
                pruned.images += 1;
            }
        }
        let mut named: BTreeSet<String> = BTreeSet::new();
        for image in &kept {
            let json = self.image_json(image)?;
            named.insert(json.manifest.hex().to_owned());
            named.insert(json.config.hex().to_owned());
            named.extend(json.layers.iter().map(|l| l.digest.hex().to_owned()));
        }
        let blobs = self.dir.join("blobs/sha256");
        for entry in fs::read_dir(&blobs)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !is_final(name) || named.contains(name) || !entry.file_type()?.is_file() {
                continue;
            }
            let deleting = blobs.join(staging_name(name, "deleting"));
            self.fs.rename(&entry.path(), &deleting)?;
            self.fs.fsync_dir(&blobs)?;
            self.fs.unlink(&deleting)?;
            pruned.blobs += 1;
        }
        Ok(pruned)
    }
}

/// The digest an entry file holds, or none when there is no file.
fn read_entry(path: &Path) -> io::Result<Option<Digest>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Digest::parse(text.trim()).map(Some).map_err(|error| {
        invalid(format!(
            "the ref {} does not parse: {error}",
            path.display()
        ))
    })
}

/// Every directory under `dir`, itself included, deepest last.
fn collect_dirs(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    out.push(dir.to_path_buf());
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_dirs(&entry.path(), out)?;
        }
    }
    Ok(())
}

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: releasing a lock we took; closing would release it too.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl Write for BlobWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("the blob is finished"))?;
        let n = file.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl BlobWriter<'_> {
    /// Checks the digest and the size, then gives the blob its name.
    pub fn finish(mut self) -> io::Result<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| io::Error::other("the blob is finished"))?;
        if self.written != self.size {
            return Err(invalid(format!(
                "the blob's size is {} bytes, not the {} the manifest says",
                self.written, self.size
            )));
        }
        let hasher = std::mem::replace(
            &mut self.hasher,
            ring::digest::Context::new(&ring::digest::SHA256),
        );
        let got = Digest::of_hash(hasher.finish().as_ref());
        if got != self.expected {
            return Err(invalid(format!(
                "the blob does not match its digest: {got}, not {}",
                self.expected
            )));
        }
        self.store.fs.fsync_file(&file)?;
        drop(file);
        self.store
            .fs
            .rename(&self.partial, &self.store.blob_path(&self.expected))?;
        self.store
            .fs
            .fsync_dir(&self.store.dir.join("blobs/sha256"))?;
        self.done = true;
        Ok(())
    }
}

impl Drop for BlobWriter<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.partial);
        }
    }
}

impl ImageStaging<'_> {
    /// The tree to unpack into.
    pub fn rootfs(&self) -> PathBuf {
        self.partial.join("rootfs")
    }

    /// Makes the image durable and gives it its final name; answers the
    /// final directory, which may be another pull's.
    pub fn publish(mut self, json: &ImageJson) -> io::Result<PathBuf> {
        let store = self.store;
        let fs_ = &store.fs;
        fs_.syncfs(&self.partial)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(self.partial.join("image.json"))?;
        serde_json::to_writer_pretty(&mut file, json).map_err(io::Error::other)?;
        fs_.fsync_file(&file)?;
        drop(file);
        fs_.fsync_dir(&self.partial)?;
        let images = store.dir.join("images");
        let final_dir = images.join(self.digest.hex());
        if !final_dir.exists() {
            match fs_.rename(&self.partial, &final_dir) {
                Ok(()) => {
                    fs_.fsync_dir(&images)?;
                    self.done = true;
                    return Ok(final_dir);
                }
                // Another pull got there first.
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EEXIST) | Some(libc::ENOTEMPTY)
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        self.discard()?;
        fs_.fsync_dir(&images)?;
        Ok(final_dir)
    }

    /// Removes the staging directory.
    fn discard(&mut self) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        let images = self.store.dir.join("images");
        let name = self
            .partial
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("a staging name that is not UTF-8"))?
            .to_owned();
        delete_tree(&images, &name)
    }
}

impl Drop for ImageStaging<'_> {
    fn drop(&mut self) {
        let _ = self.discard();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    fn digest(n: u8) -> Digest {
        Digest::of_hash(&[n; 32])
    }

    fn json(manifest: &Digest, config: &Digest, layers: &[&Digest]) -> ImageJson {
        ImageJson {
            manifest: manifest.clone(),
            config: config.clone(),
            layers: layers
                .iter()
                .map(|d| LayerRef {
                    digest: (*d).clone(),
                    media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                    size: 1,
                })
                .collect(),
            defaults: Defaults::default(),
            skipped: Vec::new(),
            modes: Vec::new(),
            ownership: Some(OWNERSHIP_OVERRIDE.to_owned()),
        }
    }

    fn sha256(data: &[u8]) -> Digest {
        Digest::of_hash(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
    }

    fn store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("cache")).unwrap();
        (tmp, store)
    }

    /// Writes a blob of `data`.
    fn put_blob(store: &Store, data: &[u8]) -> Digest {
        let d = sha256(data);
        let mut w = store.blob_writer(&d, data.len() as u64).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap();
        d
    }

    /// Publishes an image of `manifest` with one file in its tree.
    fn put_image(store: &Store, json: &ImageJson) -> PathBuf {
        let staging = store.stage_image(&json.manifest).unwrap();
        fs::write(staging.rootfs().join("hello"), b"hi").unwrap();
        staging.publish(json).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn the_cache_is_made_private_with_its_parts() {
        let (tmp, store) = store();
        let dir = tmp.path().join("cache");
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            names(&dir),
            [".lock", ".sweep.lock", "blobs", "images", "refs"]
        );
        assert!(dir.join("blobs/sha256").is_dir());
        assert_eq!(store.dir(), dir);
        // Opening again keeps what is there.
        put_blob(&store, b"keep");
        let again = Store::open(&dir).unwrap();
        assert!(again.has_blob(&sha256(b"keep")));
    }

    #[test]
    fn a_blob_gets_its_name_only_when_digest_and_size_match() {
        let (_tmp, store) = store();
        let d = sha256(b"right");
        let mut w = store.blob_writer(&d, 5).unwrap();
        w.write_all(b"wrong").unwrap();
        let err = w.finish().unwrap_err();
        assert!(err.to_string().contains("digest"), "{err}");
        assert!(!store.has_blob(&d));
        let mut w = store.blob_writer(&d, 4).unwrap();
        w.write_all(b"right").unwrap();
        let err = w.finish().unwrap_err();
        assert!(err.to_string().contains("size"), "{err}");
        assert!(!store.has_blob(&d));
        let blobs = store.dir().join("blobs/sha256");
        assert_eq!(names(&blobs), Vec::<String>::new(), "no partial is left");
        let mut w = store.blob_writer(&d, 5).unwrap();
        w.write_all(b"right").unwrap();
        w.finish().unwrap();
        assert!(store.has_blob(&d));
        assert_eq!(fs::read(store.blob_path(&d)).unwrap(), b"right");
        // A writer dropped without finishing leaves nothing.
        let w = store.blob_writer(&sha256(b"x"), 1).unwrap();
        drop(w);
        assert_eq!(names(&blobs), [d.hex().to_owned()]);
    }

    #[test]
    fn staging_names_differ_within_one_process_and_both_may_finish() {
        let (_tmp, store) = store();
        let d = sha256(b"shared");
        let mut a = store.blob_writer(&d, 6).unwrap();
        let mut b = store.blob_writer(&d, 6).unwrap();
        let blobs = store.dir().join("blobs/sha256");
        let partials = names(&blobs);
        assert_eq!(partials.len(), 2);
        assert!(
            partials
                .iter()
                .all(|n| n.starts_with('.') && n.contains(".partial.")),
            "{partials:?}"
        );
        a.write_all(b"shared").unwrap();
        b.write_all(b"shared").unwrap();
        a.finish().unwrap();
        b.finish().unwrap();
        assert_eq!(names(&blobs), [d.hex().to_owned()]);
    }

    #[test]
    fn an_image_is_published_whole_or_not_at_all() {
        let (_tmp, store) = store();
        let (m, c, l) = (digest(1), digest(2), digest(3));
        let images = store.dir().join("images");
        let staging = store.stage_image(&m).unwrap();
        assert!(names(&images)[0].starts_with(&format!(".{}.partial.", m.hex())));
        assert!(staging.rootfs().is_dir());
        assert_eq!(store.image_dir(&m), None);
        drop(staging);
        assert_eq!(
            names(&images),
            Vec::<String>::new(),
            "dropped: nothing left"
        );
        let json = json(&m, &c, &[&l]);
        let dir = put_image(&store, &json);
        assert_eq!(dir, images.join(m.hex()));
        assert_eq!(store.image_dir(&m), Some(dir.clone()));
        assert_eq!(store.image_json(&m).unwrap(), json);
        assert_eq!(fs::read(dir.join("rootfs/hello")).unwrap(), b"hi");
        assert_eq!(names(&images), [m.hex().to_owned()]);
    }

    #[test]
    fn the_second_publisher_uses_the_first_image() {
        let (_tmp, store) = store();
        let (m, c) = (digest(1), digest(2));
        let json = json(&m, &c, &[]);
        let first = store.stage_image(&m).unwrap();
        let second = store.stage_image(&m).unwrap();
        fs::write(first.rootfs().join("from"), b"first").unwrap();
        fs::write(second.rootfs().join("from"), b"second").unwrap();
        let a = first.publish(&json).unwrap();
        let b = second.publish(&json).unwrap();
        assert_eq!(a, b);
        assert_eq!(fs::read(a.join("rootfs/from")).unwrap(), b"first");
        assert_eq!(names(&store.dir().join("images")), [m.hex().to_owned()]);
    }

    #[test]
    fn refs_live_under_tags_and_repositories_never_collide_with_them() {
        let (_tmp, store) = store();
        let (m1, m2) = (digest(1), digest(2));
        let alpine = Reference::parse("alpine:3.22").unwrap();
        assert_eq!(store.read_ref(&alpine).unwrap(), None);
        store.write_ref(&alpine, &m1).unwrap();
        assert_eq!(store.read_ref(&alpine).unwrap(), Some(m1.clone()));
        assert!(store
            .dir()
            .join("refs/docker.io/library/alpine")
            .join(TAGS)
            .join("3.22")
            .is_file());
        store.write_ref(&alpine, &m2).unwrap();
        assert_eq!(store.read_ref(&alpine).unwrap(), Some(m2.clone()));
        // `team:app` and `team/app:latest` both exist.
        let short = Reference::parse("host.example/team:app").unwrap();
        let deep = Reference::parse("host.example/team/app:latest").unwrap();
        store.write_ref(&short, &m1).unwrap();
        store.write_ref(&deep, &m2).unwrap();
        assert_eq!(store.read_ref(&short).unwrap(), Some(m1.clone()));
        assert_eq!(store.read_ref(&deep).unwrap(), Some(m2.clone()));
        let listing = store.list().unwrap();
        let mut refs: Vec<String> = listing
            .refs
            .iter()
            .map(|r| {
                format!(
                    "{}/{}:{} {}",
                    r.registry,
                    r.repository,
                    r.tag,
                    r.digest.hex()
                )
            })
            .collect();
        refs.sort();
        assert_eq!(
            refs,
            [
                format!("docker.io/library/alpine:3.22 {}", m2.hex()),
                format!("host.example/team/app:latest {}", m2.hex()),
                format!("host.example/team:app {}", m1.hex()),
            ]
        );
        assert!(store.remove_ref(&short).unwrap());
        assert!(!store.remove_ref(&short).unwrap());
        assert_eq!(store.read_ref(&short).unwrap(), None);
        assert_eq!(store.read_ref(&deep).unwrap(), Some(m2));
    }

    #[test]
    fn a_tag_shaped_like_a_staging_name_is_a_tag() {
        let (_tmp, store) = store();
        let m = digest(1);
        put_image(&store, &json(&m, &digest(2), &[]));
        let odd = Reference::parse("host.example/x:release.partial.1-1").unwrap();
        store.write_ref(&odd, &m).unwrap();
        assert_eq!(store.sweep().unwrap(), 0);
        assert_eq!(store.prune().unwrap(), Pruned::default());
        assert_eq!(store.read_ref(&odd).unwrap(), Some(m.clone()));
        assert_eq!(store.list().unwrap().refs.len(), 1);
        assert!(store.remove_ref(&odd).unwrap());
        assert_eq!(store.read_ref(&odd).unwrap(), None);
    }

    #[test]
    fn the_sweep_removes_what_dead_pids_left_and_nothing_else() {
        let (_tmp, store) = store();
        let m = digest(1);
        put_image(&store, &json(&m, &digest(2), &[]));
        let blobs = store.dir().join("blobs/sha256");
        let images = store.dir().join("images");
        fs::write(blobs.join(".aaaa.partial.999999-1"), b"half").unwrap();
        fs::create_dir_all(images.join(".bbbb.deleting.999999-2/rootfs/locked")).unwrap();
        fs::set_permissions(
            images.join(".bbbb.deleting.999999-2/rootfs/locked"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        fs::create_dir_all(images.join(".cccc.partial.999999-3/rootfs")).unwrap();
        let tags = store.dir().join("refs/host.example/x").join(TAGS);
        fs::create_dir_all(&tags).unwrap();
        fs::write(tags.join(".v1.partial.999999-4"), m.to_string()).unwrap();
        let own = std::process::id();
        fs::write(blobs.join(format!(".dddd.partial.{own}-1")), b"mine").unwrap();
        // Before the sweep, none of it is trusted.
        assert_eq!(store.image_dir(&Digest::of_hash(&[0xbb; 32])), None);
        assert_eq!(store.list().unwrap().images, std::slice::from_ref(&m));
        assert_eq!(store.list().unwrap().refs, []);
        assert_eq!(store.sweep().unwrap(), 4);
        assert_eq!(names(&blobs), [format!(".dddd.partial.{own}-1")]);
        assert_eq!(names(&images), [m.hex().to_owned()]);
        assert_eq!(names(&tags), Vec::<String>::new());
    }

    #[test]
    fn removing_an_image_removes_its_refs_first_and_prune_the_unreferenced() {
        let (_tmp, store) = store();
        let shared = put_blob(&store, b"shared layer");
        let only_a = put_blob(&store, b"a's layer");
        let only_b = put_blob(&store, b"b's layer");
        let (ma, ca) = (
            put_blob(&store, b"manifest a"),
            put_blob(&store, b"config a"),
        );
        let (mb, cb) = (
            put_blob(&store, b"manifest b"),
            put_blob(&store, b"config b"),
        );
        put_image(&store, &json(&ma, &ca, &[&shared, &only_a]));
        put_image(&store, &json(&mb, &cb, &[&shared, &only_b]));
        let a = Reference::parse("host.example/a:1").unwrap();
        let a2 = Reference::parse("host.example/a:also").unwrap();
        let b = Reference::parse("host.example/b:1").unwrap();
        store.write_ref(&a, &ma).unwrap();
        store.write_ref(&a2, &ma).unwrap();
        store.write_ref(&b, &mb).unwrap();
        // Nothing to prune while everything is referenced.
        assert_eq!(store.prune().unwrap(), Pruned::default());
        // Removing b's ref leaves b unreferenced: prune takes it and the
        // blobs only it named.
        assert!(store.remove_ref(&b).unwrap());
        assert_eq!(
            store.prune().unwrap(),
            Pruned {
                images: 1,
                blobs: 3
            }
        );
        assert_eq!(store.image_dir(&mb), None);
        assert!(store.has_blob(&shared) && store.has_blob(&only_a));
        assert!(!store.has_blob(&only_b) && !store.has_blob(&mb) && !store.has_blob(&cb));
        // Removing a by digest removes both its refs and the directory.
        assert!(store.remove_image(&ma).unwrap());
        assert!(!store.remove_image(&ma).unwrap());
        assert_eq!(store.read_ref(&a).unwrap(), None);
        assert_eq!(store.read_ref(&a2).unwrap(), None);
        assert_eq!(store.image_dir(&ma), None);
        assert_eq!(
            store.prune().unwrap(),
            Pruned {
                images: 0,
                blobs: 4
            }
        );
        assert_eq!(names(&store.dir().join("images")), Vec::<String>::new());
    }

    #[test]
    fn an_image_with_locked_directories_is_removed_whole() {
        let (_tmp, store) = store();
        let m = digest(1);
        let staging = store.stage_image(&m).unwrap();
        let locked = staging.rootfs().join("locked");
        fs::create_dir_all(locked.join("deeper")).unwrap();
        fs::write(locked.join("deeper/x"), b"x").unwrap();
        fs::set_permissions(locked.join("deeper"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        staging.publish(&json(&m, &digest(2), &[])).unwrap();
        assert!(store.remove_image(&m).unwrap());
        assert_eq!(names(&store.dir().join("images")), Vec::<String>::new());
    }

    #[test]
    fn a_prune_waits_for_a_pull_and_pulls_share() {
        let (_tmp, store) = store();
        let store = Arc::new(store);
        let shared = store.lock_shared().unwrap();
        let other_shared = store.lock_shared().unwrap();
        let (started, started_rx) = mpsc::channel();
        let (locked, locked_rx) = mpsc::channel();
        let s = store.clone();
        thread::spawn(move || {
            started.send(()).unwrap();
            let _exclusive = s.lock_exclusive().unwrap();
            locked.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            locked_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "the prune waited"
        );
        drop(shared);
        assert!(
            locked_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "still one pull"
        );
        drop(other_shared);
        locked_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the prune got its lock");
    }

    /// Records every durability call, in order.
    struct Recording {
        calls: Arc<Mutex<Vec<String>>>,
        real: RealFs,
    }

    impl Recording {
        fn new() -> (Recording, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Recording {
                    calls: calls.clone(),
                    real: RealFs,
                },
                calls,
            )
        }

        fn note(&self, what: String) {
            self.calls.lock().unwrap().push(what);
        }
    }

    fn short(path: &Path) -> String {
        let s = path.to_string_lossy();
        let s = s.rsplit("/cache/").next().unwrap().to_owned();
        // Staging names carry a pid and counter: shown as `.partial`.
        let mut out = String::new();
        for part in s.split('/') {
            if !out.is_empty() {
                out.push('/');
            }
            if let Some(at) = part.find(".partial.").or_else(|| part.find(".deleting.")) {
                let kind = if part[at..].starts_with(".partial.") {
                    ".partial"
                } else {
                    ".deleting"
                };
                out.push_str(&format!("{}{kind}", &part[..at]));
            } else {
                out.push_str(part);
            }
        }
        out
    }

    impl Fs for Recording {
        fn fsync_file(&self, file: &File) -> io::Result<()> {
            let path = fs::read_link(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(file)
            ))
            .unwrap();
            self.note(format!("fsync {}", short(&path)));
            self.real.fsync_file(file)
        }
        fn fsync_dir(&self, dir: &Path) -> io::Result<()> {
            self.note(format!("fsync-dir {}", short(dir)));
            self.real.fsync_dir(dir)
        }
        fn syncfs(&self, dir: &Path) -> io::Result<()> {
            self.note(format!("syncfs {}", short(dir)));
            self.real.syncfs(dir)
        }
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.note(format!("rename {} -> {}", short(from), short(to)));
            self.real.rename(from, to)
        }
        fn unlink(&self, path: &Path) -> io::Result<()> {
            self.note(format!("unlink {}", short(path)));
            self.real.unlink(path)
        }
    }

    #[test]
    fn durability_calls_come_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let (recording, calls) = Recording::new();
        let store = Store::open_with(&tmp.path().join("cache"), Box::new(recording)).unwrap();
        let m = put_blob(&store, b"manifest");
        let hex = m.hex().to_owned();
        assert_eq!(
            *calls.lock().unwrap(),
            [
                format!("fsync blobs/sha256/.{hex}.partial"),
                format!("rename blobs/sha256/.{hex}.partial -> blobs/sha256/{hex}"),
                "fsync-dir blobs/sha256".to_owned(),
            ]
        );
        calls.lock().unwrap().clear();
        put_image(&store, &json(&m, &digest(2), &[]));
        assert_eq!(
            *calls.lock().unwrap(),
            [
                format!("syncfs images/.{hex}.partial"),
                format!("fsync images/.{hex}.partial/image.json"),
                format!("fsync-dir images/.{hex}.partial"),
                format!("rename images/.{hex}.partial -> images/{hex}"),
                "fsync-dir images".to_owned(),
            ]
        );
        calls.lock().unwrap().clear();
        let r = Reference::parse("host.example/x:v1").unwrap();
        store.write_ref(&r, &m).unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            [
                format!("fsync refs/host.example/x/{TAGS}/.v1.partial"),
                format!("rename refs/host.example/x/{TAGS}/.v1.partial -> refs/host.example/x/{TAGS}/v1"),
                format!("fsync-dir refs/host.example/x/{TAGS}"),
                "fsync-dir refs/host.example/x".to_owned(),
                "fsync-dir refs/host.example".to_owned(),
                "fsync-dir refs".to_owned(),
            ]
        );
        // A second tag in the same directory and another repository's tag
        // for another image: both unlinks come first, then every tags
        // directory is synced, changed or not, and then the image goes.
        let r2 = Reference::parse("host.example/x:v2").unwrap();
        store.write_ref(&r2, &m).unwrap();
        let other = put_blob(&store, b"other manifest");
        put_image(&store, &json(&other, &digest(3), &[]));
        store
            .write_ref(&Reference::parse("host.example/y:v1").unwrap(), &other)
            .unwrap();
        calls.lock().unwrap().clear();
        assert!(store.remove_image(&m).unwrap());
        let got = calls.lock().unwrap().clone();
        assert_eq!(
            got[..6],
            [
                format!("unlink refs/host.example/x/{TAGS}/v1"),
                format!("unlink refs/host.example/x/{TAGS}/v2"),
                format!("fsync-dir refs/host.example/x/{TAGS}"),
                format!("fsync-dir refs/host.example/y/{TAGS}"),
                format!("rename images/{hex} -> images/.{hex}.deleting"),
                "fsync-dir images".to_owned(),
            ]
        );
        // The sweep syncs a directory before deleting what a dead process
        // left in it.
        fs::create_dir_all(store.dir().join("images/.zzzz.deleting.999999-9/rootfs")).unwrap();
        fs::write(
            store.dir().join("blobs/sha256/.qqqq.partial.999999-9"),
            b"q",
        )
        .unwrap();
        calls.lock().unwrap().clear();
        assert_eq!(store.sweep().unwrap(), 2);
        let got = calls.lock().unwrap().clone();
        assert!(got.contains(&"fsync-dir images".to_owned()), "{got:?}");
        assert!(
            got.contains(&"fsync-dir blobs/sha256".to_owned()),
            "{got:?}"
        );
        // An existing image is made durable before anyone builds on it,
        // and a losing publisher syncs the directory it found it in.
        put_image(&store, &json(&m, &digest(2), &[]));
        calls.lock().unwrap().clear();
        assert!(store.existing_image(&m).unwrap().is_some());
        assert_eq!(*calls.lock().unwrap(), ["fsync-dir images".to_owned()]);
        calls.lock().unwrap().clear();
        let loser = store.stage_image(&m).unwrap();
        loser.publish(&json(&m, &digest(2), &[])).unwrap();
        assert_eq!(
            calls.lock().unwrap().last().map(String::as_str),
            Some("fsync-dir images")
        );
        assert!(
            !calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("rename")),
            "{:?}",
            calls.lock().unwrap()
        );
    }

    #[test]
    fn index_entries_are_lookups_that_go_with_their_image() {
        let (_tmp, store) = store();
        let m1 = put_blob(&store, b"manifest one");
        let m2 = put_blob(&store, b"manifest two");
        put_image(&store, &json(&m1, &digest(2), &[]));
        put_image(&store, &json(&m2, &digest(3), &[]));
        let index_a = digest(0xa);
        let index_b = digest(0xb);
        let by_a = Reference::parse(&format!("host.example/x@{index_a}")).unwrap();
        let by_b = Reference::parse(&format!("host.example/x@{index_b}")).unwrap();
        let by_m1 = Reference::parse(&format!("host.example/x@{m1}")).unwrap();
        let tag = Reference::parse("host.example/x:v1").unwrap();
        // Nothing yet: not by index, not by manifest, not by tag.
        assert_eq!(store.find(&by_a).unwrap(), None);
        assert_eq!(
            store.find(&by_m1).unwrap(),
            Some(m1.clone()),
            "by its own digest"
        );
        assert_eq!(store.find(&tag).unwrap(), None);
        store.write_index(&by_a, &index_a, &m1).unwrap();
        store.write_ref(&tag, &m1).unwrap();
        assert_eq!(store.find(&by_a).unwrap(), Some(m1.clone()));
        assert_eq!(store.find(&tag).unwrap(), Some(m1.clone()));
        let listing = store.list().unwrap();
        assert_eq!(
            listing.indexes,
            [IndexEntry {
                registry: "host.example".into(),
                repository: "x".into(),
                index: index_a.clone(),
                manifest: m1.clone(),
            }]
        );
        assert_eq!(listing.refs.len(), 1, "an index entry is not a ref");
        // The tag moves to index B: two images, two entries; prune keeps
        // only what a tag names, and A's entry goes with A's image.
        store.write_index(&by_b, &index_b, &m2).unwrap();
        store.write_ref(&tag, &m2).unwrap();
        let pruned = store.prune().unwrap();
        assert_eq!(pruned.images, 1);
        assert_eq!(store.image_dir(&m1), None);
        assert!(store.image_dir(&m2).is_some());
        let listing = store.list().unwrap();
        assert_eq!(listing.indexes.len(), 1);
        assert_eq!(listing.indexes[0].index, index_b);
        assert_eq!(store.find(&by_a).unwrap(), None, "gone with its image");
        assert_eq!(store.find(&by_b).unwrap(), Some(m2.clone()));
        // A stale entry (its image removed by hand) counts for nothing and
        // is overwritten by the next write.
        store.write_index(&by_a, &index_a, &m1).unwrap();
        assert_eq!(store.find(&by_a).unwrap(), None);
        store.write_index(&by_a, &index_a, &m2).unwrap();
        assert_eq!(store.find(&by_a).unwrap(), Some(m2.clone()));
        // Removing the image removes its tag and both entries.
        assert!(store.remove_image(&m2).unwrap());
        let listing = store.list().unwrap();
        assert_eq!(listing.refs, []);
        assert_eq!(listing.indexes, []);
        assert_eq!(listing.images, []);
        // The tag removed, then prune: everything goes.
        put_image(&store, &json(&m1, &digest(2), &[]));
        store.write_ref(&tag, &m1).unwrap();
        store.write_index(&by_a, &index_a, &m1).unwrap();
        assert!(store.remove_ref(&tag).unwrap());
        assert_eq!(store.prune().unwrap().images, 1);
        assert_eq!(store.list().unwrap().indexes, []);
    }

    #[test]
    fn two_sweeps_at_once_remove_everything_and_fail_nothing() {
        let (_tmp, store) = store();
        let store = Arc::new(store);
        for round in 0..10 {
            let blobs = store.dir().join("blobs/sha256");
            let images = store.dir().join("images");
            for i in 0..40 {
                fs::write(blobs.join(format!(".b{round}{i}.partial.999999-{i}")), b"x").unwrap();
                let dir = images.join(format!(".i{round}{i}.partial.999999-{i}"));
                fs::create_dir_all(dir.join("rootfs/a/b")).unwrap();
                fs::write(dir.join("rootfs/a/b/f"), b"x").unwrap();
            }
            let threads: Vec<_> = (0..2)
                .map(|_| {
                    let store = store.clone();
                    thread::spawn(move || store.sweep())
                })
                .collect();
            let removed: usize = threads
                .into_iter()
                .map(|t| t.join().unwrap().unwrap())
                .sum();
            assert_eq!(removed, 80, "round {round}");
            assert_eq!(names(&blobs), Vec::<String>::new());
            assert_eq!(names(&images), Vec::<String>::new());
        }
    }

    #[test]
    fn image_json_round_trips_through_serde() {
        let j = ImageJson {
            manifest: digest(1),
            config: digest(2),
            layers: vec![LayerRef {
                digest: digest(3),
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
                size: 42,
            }],
            defaults: Defaults {
                env: vec!["PATH=/bin".into()],
                entrypoint: vec!["/bin/sh".into()],
                cmd: vec!["-c".into(), "true".into()],
                working_dir: "/workspace".into(),
                user: String::new(),
            },
            skipped: vec!["dev/null".into()],
            modes: vec![("etc/shadow".into(), 0o000)],
            ownership: Some("override".into()),
        };
        let text = serde_json::to_string(&j).unwrap();
        assert!(
            text.contains(&format!("\"sha256:{}\"", digest(1).hex())),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<ImageJson>(&text).unwrap(), j);
        assert!(serde_json::from_str::<ImageJson>(&text.replace("sha256:", "md5:")).is_err());
    }
}
