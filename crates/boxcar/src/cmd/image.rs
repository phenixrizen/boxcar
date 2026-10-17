// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar image pull|ls|rm|prune`: the image cache from the command line.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use crate::cli::{CacheArgs, ImageCommand, ImagePullArgs, ImageRmArgs};
use crate::oci::auth::DockerConfig;
use crate::oci::client::Client;
use crate::oci::pull::{self, Progress};
use crate::oci::reference::{Digest, Reference};
use crate::oci::store::Store;

pub fn run(command: ImageCommand) -> Result<ExitCode> {
    match command {
        ImageCommand::Pull(args) => pull(&args),
        ImageCommand::Ls(args) => ls(&args),
        ImageCommand::Rm(args) => rm(&args),
        ImageCommand::Prune(args) => prune(&args),
    }
}

/// `$XDG_CACHE_HOME/boxcar`, else `$HOME/.cache/boxcar`.
pub(crate) fn default_cache_dir(
    xdg_cache_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    let absolute = |var: Option<OsString>| var.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(xdg_cache_home)
        .map(|cache| cache.join("boxcar"))
        .or_else(|| absolute(home).map(|home| home.join(".cache/boxcar")))
}

fn open_store(args: &CacheArgs) -> Result<Store> {
    let dir = match &args.cache_dir {
        Some(dir) => dir.clone(),
        None => default_cache_dir(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))
            .context("no --cache-dir, and neither XDG_CACHE_HOME nor HOME is an absolute path")?,
    };
    Store::open(&dir).with_context(|| format!("opening the image cache {}", dir.display()))
}

/// The host's trust store, for the registry's TLS.
fn native_roots() -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        let why: Vec<String> = result.errors.iter().map(|e| e.to_string()).collect();
        bail!(
            "no root certificates found on this host: {}",
            why.join("; ")
        );
    }
    Ok(result.certs)
}

/// `~/.docker/config.json`, when there is one.
fn docker_config() -> Result<Option<DockerConfig>> {
    let Some(path) = DockerConfig::path() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    DockerConfig::parse(&text)
        .map(Some)
        .with_context(|| format!("{}", path.display()))
}

fn pull(args: &ImagePullArgs) -> Result<ExitCode> {
    let reference = match Reference::parse(&args.reference) {
        Ok(reference) => reference,
        Err(error) => {
            super::tell(&format!("error: {}: {error}", args.reference));
            return Ok(ExitCode::from(2));
        }
    };
    let store = open_store(&args.cache)?;
    let roots = native_roots()?;
    let config = docker_config()?;
    let mut client = Client::new(&reference, roots, config.as_ref())?;
    let pulled = pull::pull(
        &store,
        &mut client,
        &reference,
        &mut |progress: &Progress| {
            super::tell(&format!(
                "layer {}/{} {} {}{}",
                progress.layer,
                progress.layers,
                progress.digest,
                human(progress.size),
                if progress.cached { " (cached)" } else { "" }
            ));
        },
    )
    .with_context(|| format!("pulling {reference}"))?;
    println!("{}", pulled.manifest);
    Ok(ExitCode::SUCCESS)
}

fn ls(args: &CacheArgs) -> Result<ExitCode> {
    let store = open_store(args)?;
    let listing = store.list()?;
    for entry in &listing.refs {
        println!(
            "{}/{}:{}\t{}",
            entry.registry, entry.repository, entry.tag, entry.digest
        );
    }
    for entry in &listing.indexes {
        println!(
            "{}/{}@{}\t{}",
            entry.registry, entry.repository, entry.index, entry.manifest
        );
    }
    for image in &listing.images {
        if !listing.refs.iter().any(|r| r.digest == *image) {
            println!("(no ref)\t{image}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn rm(args: &ImageRmArgs) -> Result<ExitCode> {
    let store = open_store(&args.cache)?;
    let _lock = store.lock_exclusive()?;
    let removed = match Digest::parse(&args.target) {
        Ok(digest) => store.remove_image(&digest)?,
        Err(_) => match Reference::parse(&args.target) {
            // A reference with a digest names an image (through its index
            // entry when the digest is an index's); one with a tag, a tag.
            Ok(reference) if reference.digest().is_some() => match store.find(&reference)? {
                Some(manifest) => store.remove_image(&manifest)?,
                None => false,
            },
            Ok(reference) => store.remove_ref(&reference)?,
            Err(error) => {
                super::tell(&format!(
                    "error: {}: neither a digest nor a reference: {error}",
                    args.target
                ));
                return Ok(ExitCode::from(2));
            }
        },
    };
    if !removed {
        super::tell(&format!("error: {}: no such image or ref", args.target));
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn prune(args: &CacheArgs) -> Result<ExitCode> {
    let store = open_store(args)?;
    let _lock = store.lock_exclusive()?;
    let pruned = store.prune()?;
    println!(
        "removed {} images and {} blobs",
        pruned.images, pruned.blobs
    );
    Ok(ExitCode::SUCCESS)
}

/// `size` in bytes, KiB, MiB or GiB.
fn human(size: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_cache_dir_follows_xdg_then_home() {
        assert_eq!(
            default_cache_dir(Some("/c".into()), Some("/h".into())),
            Some(PathBuf::from("/c/boxcar"))
        );
        assert_eq!(
            default_cache_dir(Some("relative".into()), Some("/h".into())),
            Some(PathBuf::from("/h/.cache/boxcar"))
        );
        assert_eq!(default_cache_dir(None, None), None);
    }

    #[test]
    fn sizes_read_well() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(12 * 1024 * 1024 + 300 * 1024), "12.3 MiB");
        assert_eq!(human(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
