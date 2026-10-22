// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The pull, in order: the manifest (an index resolved to `linux/amd64`),
//! the config, each layer fetched or taken from the cache and applied in
//! two passes into a staging tree, `image.json`, the rename, the ref.
//! Under the store's shared lock, so a prune waits for it.

use std::cell::Cell;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use super::client::{Client, ClientError};
use super::decode::{self, Compression};
use super::framer::Framer;
use super::manifest::{self, Document, ManifestError};
use super::reference::{Digest, Reference};
use super::store::{ImageJson, LayerRef, Store, OWNERSHIP_OVERRIDE};
use super::unpack::Unpacker;

/// The most decompressed bytes an image's layers may hold together.
pub const MAX_DECOMPRESSED: u64 = 16 * 1024 * 1024 * 1024;
/// The most tar headers an image's layers may hold together.
pub const MAX_ENTRIES: u64 = 1_000_000;

/// The budgets a pull unpacks within.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub decompressed: u64,
    pub entries: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            decompressed: MAX_DECOMPRESSED,
            entries: MAX_ENTRIES,
        }
    }
}

/// One layer about to be handled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Progress {
    /// 1-based.
    pub layer: usize,
    pub layers: usize,
    pub digest: Digest,
    pub size: u64,
    /// Already in the cache: nothing to fetch.
    pub cached: bool,
}

/// What a pull produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pulled {
    pub manifest: Digest,
    pub config: Digest,
    pub dir: PathBuf,
    /// Layers fetched from the registry (the rest came from the cache).
    pub fetched: usize,
    /// Whether the image was already in the cache, whole.
    pub existed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("the index names another index")]
    IndexOfIndex,
    #[error("the cache: {0}")]
    Store(#[source] io::Error),
    #[error("layer {digest}: {source}")]
    Layer {
        digest: Digest,
        #[source]
        source: io::Error,
    },
    #[error("the cached blob {digest} is not the size this manifest gives it")]
    CachedSize { digest: Digest },
    #[error("the image is not in the cache; `boxcar image pull` it first")]
    NotCached,
}

/// When `boxcar run --image` pulls: `--pull missing|always|never`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullMode {
    /// Pull only an image the cache does not have.
    Missing,
    /// Pull: an unchanged tag fetches its manifest and nothing else.
    Always,
    /// Never: an image the cache does not have is an error.
    Never,
}

/// A cached image `ensure` found or pulled.
#[derive(Debug)]
pub struct Found {
    pub manifest: Digest,
    /// The image's directory, `rootfs` and `image.json` in it.
    pub dir: PathBuf,
    pub json: ImageJson,
    /// Whether anything was fetched.
    pub pulled: bool,
}

/// The image `reference` names, in the cache, as `mode` says: found there,
/// or pulled with a client from `client`, which is asked for only when a
/// pull happens. The caller holds the store's shared lock across this and
/// whatever it does with the image, so `rm` and `prune` wait.
pub fn ensure(
    store: &Store,
    reference: &Reference,
    mode: PullMode,
    client: impl FnOnce() -> Result<Client, ClientError>,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Found, PullError> {
    if mode != PullMode::Always {
        if let Some(manifest) = store.find(reference).map_err(PullError::Store)? {
            let dir = store.image_dir(&manifest).ok_or(PullError::NotCached)?;
            let json = store.image_json(&manifest).map_err(PullError::Store)?;
            return Ok(Found {
                manifest,
                dir,
                json,
                pulled: false,
            });
        }
        if mode == PullMode::Never {
            return Err(PullError::NotCached);
        }
    }
    let mut client = client()?;
    let pulled = pull(store, &mut client, reference, progress)?;
    let json = store
        .image_json(&pulled.manifest)
        .map_err(PullError::Store)?;
    Ok(Found {
        manifest: pulled.manifest,
        dir: pulled.dir,
        json,
        pulled: pulled.fetched > 0,
    })
}

/// Pulls `reference` into `store` with `client`, telling `progress` about
/// each layer first.
pub fn pull(
    store: &Store,
    client: &mut Client,
    reference: &Reference,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Pulled, PullError> {
    pull_within(store, client, reference, Limits::default(), progress)
}

/// [`pull`] within `limits`.
pub fn pull_within(
    store: &Store,
    client: &mut Client,
    reference: &Reference,
    limits: Limits,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Pulled, PullError> {
    let _lock = store.lock_shared().map_err(PullError::Store)?;
    store.sweep().map_err(PullError::Store)?;

    // The manifest, through an index when the reference names one; the
    // index's digest is kept for its entry.
    let response = client.manifest(&reference.manifest_reference())?;
    let mut index_digest = None;
    let (manifest, response) =
        match manifest::parse_document(&response.content_type, &response.body)? {
            Document::Manifest(manifest) => (manifest, response),
            Document::Index(index) => {
                index_digest = Some(response.digest.clone());
                let descriptor = index.linux_amd64()?.clone();
                let response = client.manifest(&descriptor.digest.to_string())?;
                match manifest::parse_document(&response.content_type, &response.body)? {
                    Document::Manifest(manifest) => (manifest, response),
                    Document::Index(_) => return Err(PullError::IndexOfIndex),
                }
            }
        };
    let manifest_digest = response.digest.clone();
    let config_digest = manifest.config.digest.clone();

    // Already whole in the cache, made durable first: only the ref moves.
    if let Some(dir) = store
        .existing_image(&manifest_digest)
        .map_err(PullError::Store)?
    {
        write_ref(store, reference, &manifest_digest)?;
        write_index(store, reference, index_digest.as_ref(), &manifest_digest)?;
        return Ok(Pulled {
            manifest: manifest_digest,
            config: config_digest,
            dir,
            fetched: 0,
            existed: true,
        });
    }
    keep_blob(store, &manifest_digest, &response.body)?;

    // The config.
    let config_bytes = if let Some(file) = cached_blob(store, &manifest.config)? {
        let mut bytes = Vec::with_capacity(manifest.config.size as usize);
        file.take(manifest.config.size)
            .read_to_end(&mut bytes)
            .map_err(PullError::Store)?;
        bytes
    } else {
        let bytes = client.config(&config_digest, manifest.config.size)?;
        keep_blob(store, &config_digest, &bytes)?;
        bytes
    };
    let image_config = manifest::parse_config(&config_bytes)?;

    // The tree, layer by layer, each in two passes.
    let staging = store
        .stage_image(&manifest_digest)
        .map_err(PullError::Store)?;
    let mut unpacker = Unpacker::new(&staging.rootfs()).map_err(PullError::Store)?;
    let bytes_left = Cell::new(limits.decompressed);
    let entries_left = Cell::new(limits.entries);
    let mut fetched = 0;
    let layers = manifest.layers.len();
    for (at, layer) in manifest.layers.iter().enumerate() {
        let cached = cached_blob(store, layer)?.is_some();
        progress(&Progress {
            layer: at + 1,
            layers,
            digest: layer.digest.clone(),
            size: layer.size,
            cached,
        });
        let layer_error = |source: io::Error| PullError::Layer {
            digest: layer.digest.clone(),
            source,
        };
        if !cached {
            let mut writer = store
                .blob_writer(&layer.digest, layer.size)
                .map_err(PullError::Store)?;
            client.blob_to(&layer.digest, layer.size, &mut writer)?;
            writer.finish().map_err(layer_error)?;
            fetched += 1;
        }
        let compression =
            Compression::for_media_type(&layer.media_type).ok_or(ManifestError::LayerType)?;
        for whiteouts in [true, false] {
            let file = File::open(store.blob_path(&layer.digest)).map_err(layer_error)?;
            let stream = decode::stream(file, compression, &bytes_left);
            let mut framer = Framer::new(stream, &entries_left);
            if whiteouts {
                unpacker.whiteouts(&mut framer).map_err(layer_error)?;
            } else {
                unpacker.entries(&mut framer).map_err(layer_error)?;
            }
            framer.finish().map_err(layer_error)?;
        }
    }
    let finished = unpacker.finish().map_err(PullError::Store)?;
    let json = ImageJson {
        manifest: manifest_digest.clone(),
        config: config_digest.clone(),
        layers: manifest
            .layers
            .iter()
            .map(|layer| LayerRef {
                digest: layer.digest.clone(),
                media_type: layer.media_type.clone(),
                size: layer.size,
            })
            .collect(),
        defaults: image_config.defaults,
        skipped: finished.skipped,
        modes: finished.modes,
        ownership: Some(OWNERSHIP_OVERRIDE.to_owned()),
    };
    let dir = staging.publish(&json).map_err(PullError::Store)?;
    write_ref(store, reference, &manifest_digest)?;
    write_index(store, reference, index_digest.as_ref(), &manifest_digest)?;
    Ok(Pulled {
        manifest: manifest_digest,
        config: config_digest,
        dir,
        fetched,
        existed: false,
    })
}

/// The cached blob `descriptor` names, when there is one: its size must
/// be what the manifest says, since the manifest's sizes bound what is
/// read.
fn cached_blob(
    store: &Store,
    descriptor: &manifest::Descriptor,
) -> Result<Option<File>, PullError> {
    let path = store.blob_path(&descriptor.digest);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PullError::Store(error)),
    };
    let size = file.metadata().map_err(PullError::Store)?.len();
    if size != descriptor.size {
        return Err(PullError::CachedSize {
            digest: descriptor.digest.clone(),
        });
    }
    Ok(Some(file))
}

/// Records the index entry when the pull went through an index.
fn write_index(
    store: &Store,
    reference: &Reference,
    index: Option<&Digest>,
    manifest: &Digest,
) -> Result<(), PullError> {
    if let Some(index) = index {
        store
            .write_index(reference, index, manifest)
            .map_err(PullError::Store)?;
    }
    Ok(())
}

/// Points the reference's tag, when it has one, at `digest`.
fn write_ref(store: &Store, reference: &Reference, digest: &Digest) -> Result<(), PullError> {
    if reference.tag().is_some() {
        store
            .write_ref(reference, digest)
            .map_err(PullError::Store)?;
    }
    Ok(())
}

/// Keeps `bytes`, already verified to be `digest`, as a blob.
fn keep_blob(store: &Store, digest: &Digest, bytes: &[u8]) -> Result<(), PullError> {
    if store.has_blob(digest) {
        return Ok(());
    }
    let mut writer = store
        .blob_writer(digest, bytes.len() as u64)
        .map_err(PullError::Store)?;
    writer.write_all(bytes).map_err(PullError::Store)?;
    writer.finish().map_err(PullError::Store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::testutil;
    use boxcar_testreg::{
        config, layer_gzip, layer_tar, layer_zstd, Auth, Blob, Faults, Registry, Tls,
    };
    use std::fs;
    use std::sync::Arc;

    fn store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("cache")).unwrap();
        (tmp, store)
    }

    fn reference(registry: &Registry, repository: &str, tag: &str) -> Reference {
        Reference::parse(&format!("{}/{repository}:{tag}", registry.host())).unwrap()
    }

    fn client(_registry: &Registry, reference: &Reference) -> Client {
        Client::new(reference, vec![], None).unwrap()
    }

    /// Pulls, collecting progress.
    fn do_pull(
        store: &Store,
        registry: &Registry,
        reference: &Reference,
    ) -> Result<(Pulled, Vec<Progress>), PullError> {
        let mut seen = Vec::new();
        let mut client = client(registry, reference);
        let pulled = pull(store, &mut client, reference, &mut |p| seen.push(p.clone()))?;
        Ok((pulled, seen))
    }

    /// A two-layer image: the second layer whites out a file of the first
    /// and adds its own.
    fn two_layers() -> (Blob, Vec<Blob>) {
        let lower = testutil::layer(&[
            testutil::dir("etc/", 0o755),
            testutil::file("etc/motd", 0o644, b"hello"),
            testutil::file("etc/gone", 0o644, b"bye"),
            testutil::file("bin/sh", 0o755, b"#!"),
        ]);
        let upper = testutil::layer(&[
            testutil::pax_file(b"etc/.wh.gone", b""),
            testutil::file("etc/added", 0o600, b"new"),
            testutil::symlink("etc/link", "/etc/motd"),
        ]);
        let config = config(&["PATH=/bin"], &["/bin/sh"], &["-c", "true"], "/workspace");
        (config, vec![layer_tar(&lower), layer_gzip(&upper)])
    }

    fn names(dir: &std::path::Path) -> Vec<String> {
        let mut out: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        out.sort();
        out
    }

    fn digest(s: &str) -> Digest {
        Digest::parse(s).unwrap()
    }

    #[test]
    fn a_pull_unpacks_the_layers_keeps_the_blobs_and_writes_the_ref() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (cfg, layers) = two_layers();
        let manifest_digest = registry.put_image("library/app", "latest", &cfg, &layers);
        let (_tmp, store) = store();
        let reference = reference(&registry, "library/app", "latest");
        let (pulled, progress) = do_pull(&store, &registry, &reference).unwrap();
        assert_eq!(pulled.manifest, digest(&manifest_digest));
        assert_eq!(pulled.config, digest(&cfg.digest()));
        assert_eq!((pulled.fetched, pulled.existed), (2, false));
        assert_eq!(pulled.dir, store.image_dir(&pulled.manifest).unwrap());
        assert_eq!(
            progress
                .iter()
                .map(|p| (p.layer, p.layers, p.cached))
                .collect::<Vec<_>>(),
            [(1, 2, false), (2, 2, false)]
        );
        // The tree.
        let listing = testutil::listing(&pulled.dir.join("rootfs"));
        assert_eq!(listing["etc/motd"], "file 644 \"hello\"");
        assert_eq!(listing["etc/added"], "file 600 \"new\"");
        assert_eq!(listing["etc/link"], "symlink -> /etc/motd");
        assert!(!listing.contains_key("etc/gone"));
        assert_eq!(listing["tmp"], "dir 1777");
        assert!(listing.contains_key("workspace"));
        // image.json.
        let json = store.image_json(&pulled.manifest).unwrap();
        assert_eq!(json.manifest, pulled.manifest);
        assert_eq!(json.config, pulled.config);
        assert_eq!(
            json.layers,
            layers
                .iter()
                .map(|l| LayerRef {
                    digest: digest(&l.digest()),
                    media_type: l.media_type.clone(),
                    size: l.data.len() as u64,
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(json.defaults.env, ["PATH=/bin"]);
        assert_eq!(json.defaults.entrypoint, ["/bin/sh"]);
        assert_eq!(json.defaults.cmd, ["-c", "true"]);
        assert_eq!(json.defaults.working_dir, "/workspace");
        assert_eq!(json.skipped, Vec::<String>::new());
        // The blobs: manifest, config, both layers; nothing half-done.
        let mut want = vec![manifest_digest.clone(), cfg.digest()];
        want.extend(layers.iter().map(Blob::digest));
        let mut want: Vec<String> = want
            .iter()
            .map(|d| d.trim_start_matches("sha256:").to_owned())
            .collect();
        want.sort();
        assert_eq!(names(&store.dir().join("blobs/sha256")), want);
        assert_eq!(
            names(&store.dir().join("images")),
            [pulled.manifest.hex().to_owned()]
        );
        // The ref.
        assert_eq!(
            store.read_ref(&reference).unwrap(),
            Some(pulled.manifest.clone())
        );
        // By digest: the same image, no ref written for it.
        let by_digest = Reference::parse(&format!(
            "{}/library/app@{manifest_digest}",
            registry.host()
        ))
        .unwrap();
        let mut client = client(&registry, &by_digest);
        let again = pull(&store, &mut client, &by_digest, &mut |_| {}).unwrap();
        assert!(again.existed);
        assert_eq!(again.fetched, 0);
    }

    #[test]
    fn an_index_resolves_to_the_linux_amd64_manifest() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (cfg, layers) = two_layers();
        let amd64 = boxcar_testreg::manifest(&cfg, &layers);
        let arm_cfg = config(&[], &[], &[], "/");
        let arm64 = boxcar_testreg::manifest(&arm_cfg, &layers[..1]);
        for blob in [&cfg, &arm_cfg, &amd64, &arm64] {
            registry.put_blob(blob);
        }
        for layer in &layers {
            registry.put_blob(layer);
        }
        registry.put_manifest("library/app", &amd64.digest(), &amd64);
        registry.put_manifest("library/app", &arm64.digest(), &arm64);
        let index =
            boxcar_testreg::index(&[(&arm64, "linux", "arm64"), (&amd64, "linux", "amd64")]);
        registry.put_manifest("library/app", "latest", &index);
        let (_tmp, store) = store();
        let reference = reference(&registry, "library/app", "latest");
        let (pulled, _) = do_pull(&store, &registry, &reference).unwrap();
        assert_eq!(pulled.manifest.to_string(), amd64.digest());
        assert_eq!(
            store.read_ref(&reference).unwrap(),
            Some(pulled.manifest.clone())
        );
        assert!(
            !store.has_blob(&digest(&index.digest())),
            "the index itself is not kept"
        );
        // Its entry is: the reference by the index's digest is found.
        let by_index = Reference::parse(&format!(
            "{}/library/app@{}",
            registry.host(),
            index.digest()
        ))
        .unwrap();
        assert_eq!(
            store.find(&by_index).unwrap(),
            Some(pulled.manifest.clone())
        );
        assert_eq!(store.list().unwrap().indexes.len(), 1);
        // An index with no linux/amd64 fails before any blob.
        let arm_only = boxcar_testreg::index(&[(&arm64, "linux", "arm64")]);
        registry.put_manifest("library/app", "arm", &arm_only);
        let arm_ref = self::reference(&registry, "library/app", "arm");
        let err = do_pull(&store, &registry, &arm_ref).unwrap_err();
        assert!(
            matches!(err, PullError::Manifest(ManifestError::NoLinuxAmd64)),
            "{err}"
        );
    }

    #[test]
    fn ensure_finds_or_pulls_as_the_mode_says() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (cfg, layers) = two_layers();
        let amd64 = boxcar_testreg::manifest(&cfg, &layers);
        registry.put_blob(&cfg);
        for layer in &layers {
            registry.put_blob(layer);
        }
        registry.put_manifest("library/app", &amd64.digest(), &amd64);
        let index = boxcar_testreg::index(&[(&amd64, "linux", "amd64")]);
        registry.put_manifest("library/app", "latest", &index);
        let (_tmp, store) = store();
        let tag = reference(&registry, "library/app", "latest");
        let by_index = Reference::parse(&format!(
            "{}/library/app@{}",
            registry.host(),
            index.digest()
        ))
        .unwrap();
        let by_manifest = Reference::parse(&format!(
            "{}/library/app@{}",
            registry.host(),
            amd64.digest()
        ))
        .unwrap();
        let client_for = |r: &Reference| {
            let r = r.clone();
            move || Client::new(&r, vec![], None)
        };
        let requests = || registry.requests().len();
        // never, empty cache: nothing asked, nothing made.
        let err = ensure(&store, &tag, PullMode::Never, client_for(&tag), &mut |_| {}).unwrap_err();
        assert!(matches!(err, PullError::NotCached), "{err}");
        assert_eq!(requests(), 0);
        // missing, empty cache: the pull.
        let found = ensure(
            &store,
            &tag,
            PullMode::Missing,
            client_for(&tag),
            &mut |_| {},
        )
        .unwrap();
        assert!(found.pulled);
        assert_eq!(found.manifest.to_string(), amd64.digest());
        assert_eq!(found.json.layers.len(), 2);
        let after_pull = requests();
        assert!(after_pull > 0);
        // missing again, by tag, by index digest and by manifest digest:
        // found, no request.
        for r in [&tag, &by_index, &by_manifest] {
            let found = ensure(&store, r, PullMode::Missing, client_for(r), &mut |_| {}).unwrap();
            assert!(!found.pulled, "{r}");
            assert_eq!(found.manifest.to_string(), amd64.digest());
        }
        assert_eq!(requests(), after_pull);
        // never: the same.
        let found = ensure(
            &store,
            &by_index,
            PullMode::Never,
            client_for(&by_index),
            &mut |_| {},
        )
        .unwrap();
        assert!(!found.pulled);
        // always: the manifest (through the index) asked for, nothing fetched.
        let found = ensure(
            &store,
            &tag,
            PullMode::Always,
            client_for(&tag),
            &mut |_| {},
        )
        .unwrap();
        assert!(!found.pulled);
        assert_eq!(requests(), after_pull + 2, "the index and the manifest");
        // The registry gone: missing and never still find the image; always
        // cannot reach it.
        drop(registry);
        for r in [&tag, &by_index] {
            assert!(
                !ensure(&store, r, PullMode::Missing, client_for(r), &mut |_| {})
                    .unwrap()
                    .pulled
            );
            assert!(
                !ensure(&store, r, PullMode::Never, client_for(r), &mut |_| {})
                    .unwrap()
                    .pulled
            );
        }
        let err = ensure(
            &store,
            &tag,
            PullMode::Always,
            client_for(&tag),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(matches!(err, PullError::Client(_)), "{err}");
    }

    #[test]
    fn zstd_layers_unpack_too() {
        let registry = Registry::start(Auth::None, Faults::default());
        let tar = testutil::layer(&[testutil::file("z", 0o644, b"zstd")]);
        let cfg = config(&[], &[], &[], "/");
        registry.put_image("library/z", "1", &cfg, &[layer_zstd(&tar)]);
        let (_tmp, store) = store();
        let reference = reference(&registry, "library/z", "1");
        let (pulled, _) = do_pull(&store, &registry, &reference).unwrap();
        assert_eq!(
            testutil::listing(&pulled.dir.join("rootfs"))["z"],
            "file 644 \"zstd\""
        );
    }

    #[test]
    fn an_unchanged_tag_fetches_nothing_and_a_moved_one_a_new_image() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (cfg, layers) = two_layers();
        let first = registry.put_image("library/app", "latest", &cfg, &layers);
        let (_tmp, store) = store();
        let reference = reference(&registry, "library/app", "latest");
        do_pull(&store, &registry, &reference).unwrap();
        let before = registry.requests().len();
        let (again, progress) = do_pull(&store, &registry, &reference).unwrap();
        assert!(again.existed);
        assert_eq!(again.fetched, 0);
        assert!(progress.is_empty());
        let paths: Vec<String> = registry.requests()[before..]
            .iter()
            .map(|r| r.path.clone())
            .collect();
        assert_eq!(paths, ["/v2/library/app/manifests/latest"]);
        // The tag moves: a new image beside the old, the ref follows, and
        // only the new layer is fetched.
        let extra = layer_tar(&testutil::layer(&[testutil::file("v2", 0o644, b"2")]));
        let mut moved_layers = layers.clone();
        moved_layers.push(extra.clone());
        let second = registry.put_image("library/app", "latest", &cfg, &moved_layers);
        assert_ne!(first, second);
        let before = registry.requests().len();
        let (moved, progress) = do_pull(&store, &registry, &reference).unwrap();
        assert_eq!(moved.manifest.to_string(), second);
        assert_eq!(moved.fetched, 1);
        assert_eq!(
            progress.iter().map(|p| p.cached).collect::<Vec<_>>(),
            [true, true, false]
        );
        let requests = registry.requests();
        let blob_requests: Vec<&String> = requests[before..]
            .iter()
            .map(|r| &r.path)
            .filter(|p| p.contains("/blobs/"))
            .collect();
        assert_eq!(
            blob_requests,
            [&format!("/v2/library/app/blobs/{}", extra.digest())]
        );
        assert_eq!(
            store.read_ref(&reference).unwrap(),
            Some(moved.manifest.clone())
        );
        assert_eq!(store.list().unwrap().images.len(), 2);
        assert_eq!(store.prune().unwrap().images, 1);
        assert_eq!(store.image_dir(&digest(&first)), None);
    }

    #[test]
    fn a_layer_shared_by_two_images_is_fetched_once() {
        let registry = Registry::start(Auth::None, Faults::default());
        let shared = layer_tar(&testutil::layer(&[testutil::file("shared", 0o644, b"s")]));
        let only_b = layer_tar(&testutil::layer(&[testutil::file("b", 0o644, b"b")]));
        let cfg = config(&[], &[], &[], "/");
        registry.put_image("team/a", "1", &cfg, std::slice::from_ref(&shared));
        registry.put_image("team/b", "1", &cfg, &[shared.clone(), only_b.clone()]);
        let (_tmp, store) = store();
        do_pull(&store, &registry, &reference(&registry, "team/a", "1")).unwrap();
        let before = registry.requests().len();
        let (pulled, progress) =
            do_pull(&store, &registry, &reference(&registry, "team/b", "1")).unwrap();
        assert_eq!(pulled.fetched, 1);
        assert_eq!(
            progress.iter().map(|p| p.cached).collect::<Vec<_>>(),
            [true, false]
        );
        let requests = registry.requests();
        let fetched: Vec<&String> = requests[before..]
            .iter()
            .map(|r| &r.path)
            .filter(|p| p.contains("/blobs/"))
            .collect();
        assert_eq!(
            fetched,
            [&format!("/v2/team/b/blobs/{}", only_b.digest())],
            "the config is cached too"
        );
        let listing = testutil::listing(&pulled.dir.join("rootfs"));
        assert!(listing.contains_key("shared") && listing.contains_key("b"));
    }

    #[test]
    fn two_pulls_of_one_image_at_once_leave_one_image() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (cfg, layers) = two_layers();
        let manifest_digest = registry.put_image("library/app", "latest", &cfg, &layers);
        let (_tmp, store) = store();
        let store = Arc::new(store);
        let registry = Arc::new(registry);
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let registry = registry.clone();
                std::thread::spawn(move || {
                    let reference = reference(&registry, "library/app", "latest");
                    do_pull(&store, &registry, &reference).unwrap().0
                })
            })
            .collect();
        let results: Vec<Pulled> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(results
            .iter()
            .all(|p| p.manifest.to_string() == manifest_digest));
        assert_eq!(
            names(&store.dir().join("images")),
            [results[0].manifest.hex().to_owned()]
        );
        let reference = reference(&registry, "library/app", "latest");
        assert_eq!(
            store.read_ref(&reference).unwrap(),
            Some(results[0].manifest.clone())
        );
        assert!(names(&store.dir().join("blobs/sha256"))
            .iter()
            .all(|n| !n.starts_with('.')));
    }

    #[test]
    fn registry_misbehaviour_fails_the_pull_and_leaves_nothing_half_done() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (cfg, layers) = two_layers();
        let manifest_digest = registry.put_image("library/app", "latest", &cfg, &layers);
        let reference = reference(&registry, "library/app", "latest");
        // Each fault against a fresh cache, so nothing is cached before it.
        for faults in [
            Faults {
                corrupt: vec![layers[1].digest()],
                ..Faults::default()
            },
            Faults {
                short_length: vec![layers[0].digest()],
                ..Faults::default()
            },
            Faults {
                lie_content_digest: true,
                ..Faults::default()
            },
            Faults {
                corrupt: vec![cfg.digest()],
                ..Faults::default()
            },
        ] {
            let (_tmp, store) = store();
            registry.set_faults(faults.clone());
            let err = do_pull(&store, &registry, &reference).unwrap_err();
            assert!(!err.to_string().is_empty());
            let images = store.dir().join("images");
            let blobs = store.dir().join("blobs/sha256");
            assert_eq!(
                names(&images),
                Vec::<String>::new(),
                "{faults:?}: no image, no staging"
            );
            assert!(
                names(&blobs).iter().all(|n| !n.starts_with('.')),
                "{faults:?}: no partial blob"
            );
            assert_eq!(store.read_ref(&reference).unwrap(), None, "{faults:?}");
        }
        // Verified blobs stay: after a corrupt second layer the manifest,
        // the config and the first layer are cached, and a clean pull
        // fetches only the rest.
        let (_tmp, store) = store();
        registry.set_faults(Faults {
            corrupt: vec![layers[1].digest()],
            ..Faults::default()
        });
        do_pull(&store, &registry, &reference).unwrap_err();
        registry.set_faults(Faults::default());
        let (pulled, progress) = do_pull(&store, &registry, &reference).unwrap();
        assert_eq!(pulled.manifest.to_string(), manifest_digest);
        assert_eq!(pulled.fetched, 1);
        assert_eq!(
            progress.iter().map(|p| p.cached).collect::<Vec<_>>(),
            [true, false]
        );
    }

    #[test]
    fn a_hostile_layer_is_refused_and_touches_nothing_outside() {
        let registry = Registry::start(Auth::None, Faults::default());
        let escape = layer_tar(&testutil::layer(&[testutil::file(
            "../escape",
            0o644,
            b"x",
        )]));
        let cfg = config(&[], &[], &[], "/");
        registry.put_image("library/evil", "1", &cfg, &[escape]);
        let (tmp, store) = store();
        fs::write(tmp.path().join("sentinel"), b"keep").unwrap();
        let reference = reference(&registry, "library/evil", "1");
        let err = do_pull(&store, &registry, &reference).unwrap_err();
        assert!(matches!(err, PullError::Layer { .. }), "{err}");
        assert!(err.to_string().contains(".."), "{err}");
        assert_eq!(names(&store.dir().join("images")), Vec::<String>::new());
        assert_eq!(names(tmp.path()), ["cache", "sentinel"]);
        assert_eq!(fs::read(tmp.path().join("sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn the_budgets_bound_what_a_layer_may_expand_to() {
        let registry = Registry::start(Auth::None, Faults::default());
        let five = testutil::layer(
            &(0..5)
                .map(|i| testutil::file(&format!("f{i}"), 0o644, b"x"))
                .collect::<Vec<_>>(),
        );
        let cfg = config(&[], &[], &[], "/");
        registry.put_image("library/many", "1", &cfg, &[layer_gzip(&five)]);
        let (_tmp, store) = store();
        let reference = reference(&registry, "library/many", "1");
        let mut client = client(&registry, &reference);
        let limits = Limits {
            decompressed: MAX_DECOMPRESSED,
            entries: 3,
        };
        let err = pull_within(&store, &mut client, &reference, limits, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("entries"), "{err}");
        let limits = Limits {
            decompressed: 1024,
            entries: MAX_ENTRIES,
        };
        let err = pull_within(&store, &mut client, &reference, limits, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
        assert_eq!(names(&store.dir().join("images")), Vec::<String>::new());
        // Within the budgets it pulls.
        pull(&store, &mut client, &reference, &mut |_| {}).unwrap();
    }

    #[test]
    fn credentials_reach_no_error_and_no_progress() {
        let registry = Registry::start(
            Auth::Bearer {
                token: "t0k3n".into(),
                credentials: Some(("alice".into(), "s3cret-pw".into())),
            },
            Faults {
                echo_authorization: true,
                ..Faults::default()
            },
        );
        let (cfg, layers) = two_layers();
        registry.put_image("library/app", "latest", &cfg, &layers);
        let (_tmp, store) = store();
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "alice:s3cret-pw",
        );
        let config = crate::oci::auth::DockerConfig::parse(&format!(
            r#"{{"auths": {{"{}": {{"auth": "{auth}"}}}}}}"#,
            registry.host()
        ))
        .unwrap();
        let reference = reference(&registry, "library/app", "latest");
        let mut client = Client::new(&reference, vec![], Some(&config)).unwrap();
        let mut progress = Vec::new();
        pull(&store, &mut client, &reference, &mut |p| {
            progress.push(format!("{p:?}"))
        })
        .unwrap();
        // A missing tag: the registry echoes the Authorization it got.
        let missing = self::reference(&registry, "library/app", "missing");
        let mut client = Client::new(&missing, vec![], Some(&config)).unwrap();
        let err = pull(&store, &mut client, &missing, &mut |p| {
            progress.push(format!("{p:?}"))
        })
        .unwrap_err();
        let everything = format!("{err} {err:?} {}", progress.join(" "));
        for secret in ["s3cret-pw", &auth, "t0k3n"] {
            assert!(!everything.contains(secret), "{secret} in: {everything}");
        }
    }

    #[test]
    fn a_cached_blob_must_be_the_size_the_manifest_says() {
        let registry = Registry::start(Auth::None, Faults::default());
        let (_tmp, store) = store();
        // A big verified blob in the cache (a layer of an earlier image).
        let big = vec![7u8; 2 * 1024 * 1024];
        let big_digest = boxcar_testreg::sha256(&big);
        {
            let mut w = store
                .blob_writer(&digest(&big_digest), big.len() as u64)
                .unwrap();
            w.write_all(&big).unwrap();
            w.finish().unwrap();
        }
        // A manifest naming it as a 1-byte config, and another as a layer
        // of the wrong size.
        let layer = layer_tar(&testutil::layer(&[testutil::file("a", 0o644, b"a")]));
        registry.put_blob(&layer);
        let lying_config = serde_json::json!({
            "schemaVersion": 2, "mediaType": boxcar_testreg::OCI_MANIFEST,
            "config": {"mediaType": boxcar_testreg::OCI_CONFIG, "digest": big_digest, "size": 1},
            "layers": [layer.descriptor()],
        });
        let m = Blob {
            media_type: boxcar_testreg::OCI_MANIFEST.into(),
            data: serde_json::to_vec(&lying_config).unwrap(),
        };
        registry.put_manifest("library/app", "config", &m);
        let err = do_pull(
            &store,
            &registry,
            &reference(&registry, "library/app", "config"),
        )
        .unwrap_err();
        assert!(matches!(err, PullError::CachedSize { .. }), "{err}");
        let cfg = config(&[], &[], &[], "/");
        registry.put_blob(&cfg);
        let lying_layer = serde_json::json!({
            "schemaVersion": 2, "mediaType": boxcar_testreg::OCI_MANIFEST,
            "config": cfg.descriptor(),
            "layers": [{"mediaType": boxcar_testreg::LAYER_TAR, "digest": big_digest, "size": 5}],
        });
        let m = Blob {
            media_type: boxcar_testreg::OCI_MANIFEST.into(),
            data: serde_json::to_vec(&lying_layer).unwrap(),
        };
        registry.put_manifest("library/app", "layer", &m);
        let err = do_pull(
            &store,
            &registry,
            &reference(&registry, "library/app", "layer"),
        )
        .unwrap_err();
        assert!(matches!(err, PullError::CachedSize { .. }), "{err}");
        assert_eq!(names(&store.dir().join("images")), Vec::<String>::new());
    }

    #[test]
    fn what_a_registry_puts_in_a_manifest_reaches_no_error() {
        let registry = Registry::start(
            Auth::Basic("alice".into(), "s3cret-pw".into()),
            Faults::default(),
        );
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "alice:s3cret-pw",
        );
        let config = crate::oci::auth::DockerConfig::parse(&format!(
            r#"{{"auths": {{"{}": {{"auth": "{auth}"}}}}}}"#,
            registry.host()
        ))
        .unwrap();
        let (_tmp, store) = store();
        let cfg = boxcar_testreg::config(&[], &[], &[], "/");
        registry.put_blob(&cfg);
        // A layer whose media type is the Authorization header the
        // registry received, and a manifest with a digest that is not one.
        let echo = serde_json::json!({
            "schemaVersion": 2, "mediaType": boxcar_testreg::OCI_MANIFEST,
            "config": cfg.descriptor(),
            "layers": [{"mediaType": format!("Basic {auth}"), "digest": boxcar_testreg::sha256(b"x"), "size": 1}],
        });
        let m = Blob {
            media_type: boxcar_testreg::OCI_MANIFEST.into(),
            data: serde_json::to_vec(&echo).unwrap(),
        };
        registry.put_manifest("library/app", "echo", &m);
        let bad_digest = serde_json::json!({
            "schemaVersion": 2, "mediaType": boxcar_testreg::OCI_MANIFEST,
            "config": cfg.descriptor(),
            "layers": [{"mediaType": boxcar_testreg::LAYER_TAR, "digest": format!("Basic {auth}"), "size": 1}],
        });
        let m = Blob {
            media_type: boxcar_testreg::OCI_MANIFEST.into(),
            data: serde_json::to_vec(&bad_digest).unwrap(),
        };
        registry.put_manifest("library/app", "digest", &m);
        // Layers that fail to unpack with the header in a PAX record, in a
        // hardlink's target, and in a path whose parent is a file.
        let pax = layer_tar(&testutil::layer(&[
            testutil::extension(
                tar::EntryType::XHeader,
                &testutil::pax_record("size", format!("Basic {auth}").as_bytes()),
            ),
            testutil::file("a", 0o644, b"a"),
        ]));
        let link = layer_tar(&testutil::layer(&[testutil::hardlink(
            "x",
            &format!("Basic {auth}"),
        )]));
        let parent = layer_tar(&testutil::layer(&[
            testutil::file("f", 0o644, b"f"),
            testutil::file(&format!("f/Basic {auth}"), 0o644, b"g"),
        ]));
        for (tag, layer) in [("pax", &pax), ("link", &link), ("parent", &parent)] {
            registry.put_blob(layer);
            let m = serde_json::json!({
                "schemaVersion": 2, "mediaType": boxcar_testreg::OCI_MANIFEST,
                "config": cfg.descriptor(),
                "layers": [layer.descriptor()],
            });
            let m = Blob {
                media_type: boxcar_testreg::OCI_MANIFEST.into(),
                data: serde_json::to_vec(&m).unwrap(),
            };
            registry.put_manifest("library/app", tag, &m);
        }
        for tag in ["echo", "digest", "pax", "link", "parent"] {
            let reference = reference(&registry, "library/app", tag);
            let mut client = Client::new(&reference, vec![], Some(&config)).unwrap();
            let err = pull(&store, &mut client, &reference, &mut |_| {}).unwrap_err();
            let text = format!("{err} {err:?}");
            assert!(
                !text.contains(&auth) && !text.contains("s3cret"),
                "{tag}: {text}"
            );
        }
    }

    #[test]
    fn tls_pulls_with_the_registrys_ca() {
        let tls = Tls::new();
        let ca = rustls_pki_types::CertificateDer::from(tls.ca_der.clone());
        let registry = Registry::start_tls(Auth::None, Faults::default(), tls);
        let (cfg, layers) = two_layers();
        registry.put_image("library/app", "latest", &cfg, &layers);
        let (_tmp, store) = store();
        let reference = reference(&registry, "library/app", "latest");
        let mut client = Client::new(&reference, vec![ca], None).unwrap();
        let pulled = pull(&store, &mut client, &reference, &mut |_| {}).unwrap();
        assert_eq!(pulled.fetched, 2);
    }
}
