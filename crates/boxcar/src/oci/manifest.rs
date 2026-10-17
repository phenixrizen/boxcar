// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Manifests, indexes and image configs: parsed, bounded, and resolved to
//! the one `linux/amd64` manifest an image has.

use serde::Deserialize;

use super::decode::Compression;
use super::reference::Digest;
use super::store::Defaults;

/// The most bytes a manifest or index may have.
pub const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
/// The most bytes a config may have.
pub const MAX_CONFIG: u64 = 1024 * 1024;
/// The most layers a manifest may name.
pub const MAX_LAYERS: usize = 128;
/// The most bytes a blob may have.
pub const MAX_BLOB: u64 = 8 * 1024 * 1024 * 1024;

pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

/// What `Accept` names when a manifest is asked for.
pub const ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json";

/// A blob a manifest names.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
}

/// A manifest: one config and its layers, checked against the limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// An index (a Docker manifest list): manifests by platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    pub manifests: Vec<IndexEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub descriptor: Descriptor,
    pub os: Option<String>,
    pub architecture: Option<String>,
    /// `vnd.docker.reference.type`, when the entry is an attestation.
    pub reference_type: Option<String>,
}

/// What a manifest request answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Document {
    Manifest(Manifest),
    Index(Index),
}

/// An image config: its platform and what it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageConfig {
    pub defaults: Defaults,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("schema 1 manifests are not supported")]
    Schema1,
    #[error("`{0}` is not a manifest media type")]
    UnknownType(String),
    #[error("the {what} does not parse: {why}")]
    Json { what: &'static str, why: String },
    #[error("{0} layers: more than {MAX_LAYERS}")]
    TooManyLayers(usize),
    #[error("a layer of type `{0}` is not one boxcar unpacks")]
    LayerType(String),
    #[error("the {what} is {size} bytes: more than {max}")]
    TooLarge {
        what: &'static str,
        size: u64,
        max: u64,
    },
    #[error("the config is for {os}/{architecture}, not linux/amd64")]
    Platform { os: String, architecture: String },
    #[error("the index has no linux/amd64 manifest")]
    NoLinuxAmd64,
}

/// Parses what a manifest request answered: the body's own `mediaType`
/// decides when it is there, else `content_type` (its parameters
/// ignored).
pub fn parse_document(content_type: &str, body: &[u8]) -> Result<Document, ManifestError> {
    let json = |why: serde_json::Error| ManifestError::Json {
        what: "manifest",
        why: why.to_string(),
    };
    let header_type = content_type.split(';').next().unwrap_or("").trim();
    #[derive(Deserialize)]
    struct Peek {
        #[serde(rename = "mediaType", default)]
        media_type: Option<String>,
    }
    let peek: Peek = serde_json::from_slice(body).map_err(json)?;
    let media_type = match peek.media_type {
        Some(mt) if is_manifest_type(&mt) => mt,
        _ => header_type.to_owned(),
    };
    if is_schema1(&media_type) {
        return Err(ManifestError::Schema1);
    }
    match media_type.as_str() {
        OCI_MANIFEST | DOCKER_MANIFEST => {
            #[derive(Deserialize)]
            struct Raw {
                config: Descriptor,
                #[serde(default)]
                layers: Vec<Descriptor>,
            }
            let raw: Raw = serde_json::from_slice(body).map_err(json)?;
            if raw.layers.len() > MAX_LAYERS {
                return Err(ManifestError::TooManyLayers(raw.layers.len()));
            }
            if raw.config.size > MAX_CONFIG {
                return Err(ManifestError::TooLarge {
                    what: "config",
                    size: raw.config.size,
                    max: MAX_CONFIG,
                });
            }
            for layer in &raw.layers {
                if Compression::for_media_type(&layer.media_type).is_none() {
                    return Err(ManifestError::LayerType(layer.media_type.clone()));
                }
                if layer.size > MAX_BLOB {
                    return Err(ManifestError::TooLarge {
                        what: "layer",
                        size: layer.size,
                        max: MAX_BLOB,
                    });
                }
            }
            Ok(Document::Manifest(Manifest {
                config: raw.config,
                layers: raw.layers,
            }))
        }
        OCI_INDEX | DOCKER_LIST => {
            #[derive(Deserialize)]
            struct Platform {
                os: Option<String>,
                architecture: Option<String>,
            }
            #[derive(Deserialize)]
            struct RawEntry {
                #[serde(flatten)]
                descriptor: Descriptor,
                #[serde(default)]
                platform: Option<Platform>,
                #[serde(default)]
                annotations: Option<std::collections::HashMap<String, String>>,
            }
            #[derive(Deserialize)]
            struct Raw {
                #[serde(default)]
                manifests: Vec<RawEntry>,
            }
            let raw: Raw = serde_json::from_slice(body).map_err(json)?;
            let manifests = raw
                .manifests
                .into_iter()
                .map(|entry| IndexEntry {
                    descriptor: entry.descriptor,
                    os: entry.platform.as_ref().and_then(|p| p.os.clone()),
                    architecture: entry.platform.as_ref().and_then(|p| p.architecture.clone()),
                    reference_type: entry
                        .annotations
                        .as_ref()
                        .and_then(|a| a.get("vnd.docker.reference.type").cloned()),
                })
                .collect();
            Ok(Document::Index(Index { manifests }))
        }
        other => Err(ManifestError::UnknownType(other.to_owned())),
    }
}

fn is_manifest_type(media_type: &str) -> bool {
    matches!(
        media_type,
        OCI_MANIFEST | OCI_INDEX | DOCKER_MANIFEST | DOCKER_LIST
    ) || is_schema1(media_type)
}

fn is_schema1(media_type: &str) -> bool {
    media_type.starts_with("application/vnd.docker.distribution.manifest.v1+")
}

impl Index {
    /// The `linux/amd64` manifest, attestations left out.
    pub fn linux_amd64(&self) -> Result<&Descriptor, ManifestError> {
        self.manifests
            .iter()
            .find(|entry| {
                entry.reference_type.is_none()
                    && entry.os.as_deref() == Some("linux")
                    && entry.architecture.as_deref() == Some("amd64")
            })
            .map(|entry| &entry.descriptor)
            .ok_or(ManifestError::NoLinuxAmd64)
    }
}

/// Parses an image config; it must be for `linux/amd64`.
pub fn parse_config(body: &[u8]) -> Result<ImageConfig, ManifestError> {
    #[derive(Deserialize, Default)]
    struct Inner {
        #[serde(rename = "Env", default)]
        env: Option<Vec<String>>,
        #[serde(rename = "Entrypoint", default)]
        entrypoint: Option<Vec<String>>,
        #[serde(rename = "Cmd", default)]
        cmd: Option<Vec<String>>,
        #[serde(rename = "WorkingDir", default)]
        working_dir: Option<String>,
        #[serde(rename = "User", default)]
        user: Option<String>,
    }
    #[derive(Deserialize)]
    struct Raw {
        os: String,
        architecture: String,
        #[serde(default)]
        config: Option<Inner>,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|why| ManifestError::Json {
        what: "config",
        why: why.to_string(),
    })?;
    if raw.os != "linux" || raw.architecture != "amd64" {
        return Err(ManifestError::Platform {
            os: raw.os,
            architecture: raw.architecture,
        });
    }
    let inner = raw.config.unwrap_or_default();
    Ok(ImageConfig {
        defaults: Defaults {
            env: inner.env.unwrap_or_default(),
            entrypoint: inner.entrypoint.unwrap_or_default(),
            cmd: inner.cmd.unwrap_or_default(),
            working_dir: inner.working_dir.unwrap_or_default(),
            user: inner.user.unwrap_or_default(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn digest(n: u8) -> String {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
    }

    fn manifest_json(media_type: Option<&str>, layer_type: &str, layers: usize) -> Vec<u8> {
        let mut m = json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(1), "size": 100},
            "layers": (0..layers).map(|i| json!({"mediaType": layer_type, "digest": digest(10 + i as u8), "size": 1000})).collect::<Vec<_>>(),
        });
        if let Some(mt) = media_type {
            m["mediaType"] = json!(mt);
        }
        serde_json::to_vec(&m).unwrap()
    }

    #[test]
    fn oci_and_docker_manifests_parse_to_config_and_layers() {
        for (ct, body_type) in [
            (OCI_MANIFEST, Some(OCI_MANIFEST)),
            (DOCKER_MANIFEST, Some(DOCKER_MANIFEST)),
            (OCI_MANIFEST, None),
            (
                "application/vnd.oci.image.manifest.v1+json; charset=utf-8",
                None,
            ),
        ] {
            let body = manifest_json(body_type, "application/vnd.oci.image.layer.v1.tar+gzip", 2);
            let Document::Manifest(m) = parse_document(ct, &body).unwrap() else {
                panic!("{ct}: not a manifest");
            };
            assert_eq!(m.config.digest.to_string(), digest(1));
            assert_eq!(m.config.size, 100);
            assert_eq!(m.layers.len(), 2);
            assert_eq!(m.layers[1].digest.to_string(), digest(11));
            assert_eq!(
                m.layers[0].media_type,
                "application/vnd.oci.image.layer.v1.tar+gzip"
            );
        }
    }

    #[test]
    fn the_bodys_media_type_decides_over_the_header() {
        let body = manifest_json(
            Some(OCI_MANIFEST),
            "application/vnd.oci.image.layer.v1.tar",
            1,
        );
        assert!(matches!(
            parse_document(OCI_INDEX, &body).unwrap(),
            Document::Manifest(_)
        ));
        assert!(matches!(
            parse_document("text/plain", &body).unwrap(),
            Document::Manifest(_)
        ));
    }

    #[test]
    fn what_is_not_a_manifest_is_refused() {
        let body = manifest_json(None, "application/vnd.oci.image.layer.v1.tar", 1);
        assert_eq!(
            parse_document(
                "application/vnd.docker.distribution.manifest.v1+prettyjws",
                &body
            ),
            Err(ManifestError::Schema1)
        );
        assert_eq!(
            parse_document(
                "application/vnd.docker.distribution.manifest.v1+json",
                &body
            ),
            Err(ManifestError::Schema1)
        );
        assert_eq!(
            parse_document("text/html", &body),
            Err(ManifestError::UnknownType("text/html".into()))
        );
        assert!(matches!(
            parse_document(OCI_MANIFEST, b"not json"),
            Err(ManifestError::Json {
                what: "manifest",
                ..
            })
        ));
        assert!(matches!(
            parse_document(OCI_MANIFEST, br#"{"schemaVersion": 2, "config": {"mediaType": "x", "digest": "md5:abc", "size": 1}, "layers": []}"#),
            Err(ManifestError::Json { what: "manifest", .. })
        ));
    }

    #[test]
    fn layers_are_bounded_in_number_type_and_size() {
        let body = manifest_json(None, "application/vnd.oci.image.layer.v1.tar", 129);
        assert_eq!(
            parse_document(OCI_MANIFEST, &body),
            Err(ManifestError::TooManyLayers(129))
        );
        let body = manifest_json(None, "application/vnd.oci.image.layer.v1.tar", 128);
        assert!(parse_document(OCI_MANIFEST, &body).is_ok());
        let body = manifest_json(
            None,
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            1,
        );
        assert_eq!(
            parse_document(OCI_MANIFEST, &body),
            Err(ManifestError::LayerType(
                "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip".into()
            ))
        );
        let big = json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(1), "size": 100},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest(2), "size": MAX_BLOB + 1}],
        });
        assert_eq!(
            parse_document(OCI_MANIFEST, &serde_json::to_vec(&big).unwrap()),
            Err(ManifestError::TooLarge {
                what: "layer",
                size: MAX_BLOB + 1,
                max: MAX_BLOB
            })
        );
        let big_config = json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(1), "size": MAX_CONFIG + 1},
            "layers": [],
        });
        assert_eq!(
            parse_document(OCI_MANIFEST, &serde_json::to_vec(&big_config).unwrap()),
            Err(ManifestError::TooLarge {
                what: "config",
                size: MAX_CONFIG + 1,
                max: MAX_CONFIG
            })
        );
    }

    #[test]
    fn an_index_resolves_to_linux_amd64_and_skips_attestations() {
        let index = json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [
                {"mediaType": OCI_MANIFEST, "digest": digest(1), "size": 10, "platform": {"os": "linux", "architecture": "arm64"}},
                {"mediaType": OCI_MANIFEST, "digest": digest(2), "size": 10, "platform": {"os": "unknown", "architecture": "unknown"},
                 "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": digest(3)}},
                {"mediaType": OCI_MANIFEST, "digest": digest(3), "size": 10, "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": OCI_MANIFEST, "digest": digest(4), "size": 10, "platform": {"os": "linux", "architecture": "amd64", "variant": "v2"}},
            ],
        });
        let Document::Index(i) =
            parse_document(OCI_INDEX, &serde_json::to_vec(&index).unwrap()).unwrap()
        else {
            panic!("not an index");
        };
        assert_eq!(i.manifests.len(), 4);
        assert_eq!(i.linux_amd64().unwrap().digest.to_string(), digest(3));
        // A Docker manifest list the same way; none for amd64 is an error.
        let list = json!({
            "schemaVersion": 2,
            "mediaType": DOCKER_LIST,
            "manifests": [
                {"mediaType": DOCKER_MANIFEST, "digest": digest(1), "size": 10, "platform": {"os": "linux", "architecture": "arm64"}},
                {"mediaType": OCI_MANIFEST, "digest": digest(2), "size": 10, "platform": {"os": "unknown", "architecture": "unknown"},
                 "annotations": {"vnd.docker.reference.type": "attestation-manifest"}},
            ],
        });
        let Document::Index(i) =
            parse_document(DOCKER_LIST, &serde_json::to_vec(&list).unwrap()).unwrap()
        else {
            panic!("not an index");
        };
        assert_eq!(i.linux_amd64(), Err(ManifestError::NoLinuxAmd64));
        // Content-Type says index, the body says so too through its field.
        assert!(matches!(
            parse_document(
                "application/vnd.oci.image.index.v1+json; charset=utf-8",
                &serde_json::to_vec(&index).unwrap()
            ),
            Ok(Document::Index(_))
        ));
    }

    #[test]
    fn a_config_gives_the_defaults_and_must_be_linux_amd64() {
        let config = json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin:/bin", "LANG=C.UTF-8"],
                "Entrypoint": ["/bin/sh", "-c"],
                "Cmd": ["echo hi"],
                "WorkingDir": "/workspace",
                "User": "1000:1000"
            },
            "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{HEX}")]},
        });
        let c = parse_config(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(c.defaults.env, ["PATH=/usr/bin:/bin", "LANG=C.UTF-8"]);
        assert_eq!(c.defaults.entrypoint, ["/bin/sh", "-c"]);
        assert_eq!(c.defaults.cmd, ["echo hi"]);
        assert_eq!(c.defaults.working_dir, "/workspace");
        assert_eq!(c.defaults.user, "1000:1000");
        // Missing fields are empty; `config` may be absent or null.
        let bare = json!({"architecture": "amd64", "os": "linux"});
        assert_eq!(
            parse_config(&serde_json::to_vec(&bare).unwrap())
                .unwrap()
                .defaults,
            Defaults::default()
        );
        let nulls =
            json!({"architecture": "amd64", "os": "linux", "config": {"Env": null, "Cmd": null}});
        assert_eq!(
            parse_config(&serde_json::to_vec(&nulls).unwrap())
                .unwrap()
                .defaults,
            Defaults::default()
        );
        let other = json!({"architecture": "arm64", "os": "linux"});
        assert_eq!(
            parse_config(&serde_json::to_vec(&other).unwrap()),
            Err(ManifestError::Platform {
                os: "linux".into(),
                architecture: "arm64".into()
            })
        );
        assert!(matches!(
            parse_config(b"{"),
            Err(ManifestError::Json { what: "config", .. })
        ));
    }
}
