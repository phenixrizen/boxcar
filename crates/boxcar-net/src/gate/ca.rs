// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The session's certificate authority.
//!
//! `boxcar run` makes one CA for a session that has an `inspect` rule: an
//! ECDSA P-256 key and a self-signed certificate (`CN=boxcar session
//! <id>`, `CA:true`, path length 0), valid from an hour before it was made
//! for [`VALIDITY_DAYS`] days. The key lives in this struct and nowhere
//! else: [`SessionCa::pem`] is the certificate alone, which is what init
//! writes into the guest's trust store, and [`SessionCa::fingerprint_sha256`]
//! is what `vmm.start` records so a reader knows which authority the guest
//! was told to trust.
//!
//! For each inspected name (or address: a network `inspect` rule has no
//! name) the gate asks for a leaf ([`SessionCa::leaf_for`]): a certificate
//! for that name alone, signed by the CA, with its own key, as rustls
//! serves it. Leaves are made on first use and kept, at most
//! [`MAX_LEAVES`], the oldest let go.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

/// How long the CA and its leaves are valid, from an hour before they were
/// made ([`BACKDATE`]).
pub const VALIDITY_DAYS: u64 = 30;
/// How far before its making a certificate's validity starts, for a guest
/// whose clock is behind the host's.
pub const BACKDATE: Duration = Duration::from_secs(60 * 60);
/// How many leaves the CA keeps; past it the oldest goes.
pub const MAX_LEAVES: usize = 1024;

/// What a leaf is for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LeafTarget {
    /// A DNS name, lowercase, as the ClientHello's server name gave it.
    Name(String),
    /// An address, for a connection that showed no name to a network
    /// `inspect` rule.
    Ip(Ipv4Addr),
}

impl fmt::Display for LeafTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeafTarget::Name(name) => f.write_str(name),
            LeafTarget::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Why a certificate could not be made.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("cannot generate a key: {0}")]
    Key(rcgen::Error),
    #[error("cannot make the certificate for {what}: {source}")]
    Certificate {
        what: String,
        #[source]
        source: rcgen::Error,
    },
    #[error("{0:?} is not a name a certificate can carry")]
    Name(String),
    #[error("rustls does not take the leaf's key: {0}")]
    Sign(rustls::Error),
}

/// The leaves made so far, oldest first.
struct Leaves {
    by_target: HashMap<LeafTarget, Arc<CertifiedKey>>,
    order: VecDeque<LeafTarget>,
}

/// The session's CA: its key (never exported), its certificate, and the
/// leaves it signed.
pub struct SessionCa {
    issuer: Issuer<'static, KeyPair>,
    cert: CertificateDer<'static>,
    pem: String,
    fingerprint: String,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    leaves: Mutex<Leaves>,
}

impl fmt::Debug for SessionCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCa")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl SessionCa {
    /// A new CA for the session `session_id`, made now.
    pub fn generate(session_id: &str) -> Result<SessionCa, CaError> {
        let now = OffsetDateTime::from(SystemTime::now());
        let not_before = now - BACKDATE;
        let not_after = now + Duration::from_secs(VALIDITY_DAYS * 24 * 60 * 60);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(CaError::Key)?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, format!("boxcar session {session_id}"));
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params
            .self_signed(&key)
            .map_err(|source| CaError::Certificate {
                what: "the session CA".to_owned(),
                source,
            })?;
        let der = cert.der().clone();
        let pem = pem_certificate(&der);
        let fingerprint = hex::encode(ring::digest::digest(&ring::digest::SHA256, &der));
        Ok(SessionCa {
            issuer: Issuer::new(params, key),
            cert: der,
            pem,
            fingerprint,
            not_before,
            not_after,
            leaves: Mutex::new(Leaves {
                by_target: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// The CA's certificate as PEM: one `CERTIFICATE` block, and no key.
    /// What the guest is given to trust.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The CA's certificate, DER.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    /// SHA-256 of the CA certificate's DER, lowercase hex: what `vmm.start`
    /// records.
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint
    }

    /// The leaf for `target`, made and signed on first use: its chain
    /// (the leaf, then the CA) and its key, as rustls serves them.
    pub fn leaf_for(&self, target: &LeafTarget) -> Result<Arc<CertifiedKey>, CaError> {
        if let Some(leaf) = self.lock().by_target.get(target) {
            return Ok(leaf.clone());
        }
        let leaf = Arc::new(self.sign_leaf(target)?);
        let mut leaves = self.lock();
        // Made twice under a race: the first in wins, both verify.
        let leaf = match leaves.by_target.get(target) {
            Some(first) => first.clone(),
            None => {
                leaves.by_target.insert(target.clone(), leaf.clone());
                leaves.order.push_back(target.clone());
                leaf
            }
        };
        while leaves.order.len() > MAX_LEAVES {
            if let Some(oldest) = leaves.order.pop_front() {
                leaves.by_target.remove(&oldest);
            }
        }
        Ok(leaf)
    }

    /// How many leaves are kept.
    pub fn leaves(&self) -> usize {
        self.lock().order.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Leaves> {
        // A panic while holding the lock leaves a cache that is still a
        // map; the next user carries on with it.
        self.leaves
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sign_leaf(&self, target: &LeafTarget) -> Result<CertifiedKey, CaError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(CaError::Key)?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, target.to_string());
        params.distinguished_name = name;
        params.subject_alt_names = vec![match target {
            LeafTarget::Name(name) => {
                // A DNS name as a certificate may carry it, which is what a
                // client checks against; IA5 alone would take anything ASCII.
                let checked =
                    DnsName::try_from(name.as_str()).map_err(|_| CaError::Name(name.clone()))?;
                SanType::DnsName(
                    checked
                        .as_ref()
                        .try_into()
                        .map_err(|_| CaError::Name(name.clone()))?,
                )
            }
            LeafTarget::Ip(ip) => SanType::IpAddress(IpAddr::V4(*ip)),
        }];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = self.not_before;
        params.not_after = self.not_after;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|source| CaError::Certificate {
                what: target.to_string(),
                source,
            })?;
        let chain = vec![cert.der().clone(), self.cert.clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing =
            rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(CaError::Sign)?;
        Ok(CertifiedKey::new(chain, signing))
    }
}

/// `der` as a PEM `CERTIFICATE` block: base64 in lines of 64.
pub fn pem_certificate(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        // base64 output is ASCII.
        pem.push_str(std::str::from_utf8(line).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::RootCertStore;
    use rustls_pki_types::{ServerName, UnixTime};

    use super::*;

    fn make_ca() -> SessionCa {
        SessionCa::generate("017f22e2-79b0-7cc3-98c4-dc0c0c07398f").unwrap()
    }

    /// A verifier that trusts the CA and nothing else.
    fn verifier(ca: &SessionCa) -> Arc<WebPkiServerVerifier> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap()
    }

    fn verify(ca: &SessionCa, leaf: &CertifiedKey, name: &str) -> Result<(), rustls::Error> {
        let server = ServerName::try_from(name.to_owned()).unwrap();
        verifier(ca)
            .verify_server_cert(
                &leaf.cert[0],
                &leaf.cert[1..],
                &server,
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
    }

    /// A leaf for a name is accepted for that name, under this CA only,
    /// and refused for another name.
    #[test]
    fn a_leaf_for_a_name_verifies_against_the_session_ca() {
        let ca = make_ca();
        let leaf = ca
            .leaf_for(&LeafTarget::Name("api.example.com".into()))
            .unwrap();
        assert_eq!(leaf.cert.len(), 2, "the leaf, then the CA");
        verify(&ca, &leaf, "api.example.com").unwrap();
        assert!(verify(&ca, &leaf, "other.example.com").is_err());
        // Another session's CA does not vouch for it.
        let other = make_ca();
        assert!(verify(&other, &leaf, "api.example.com").is_err());
        assert_ne!(ca.fingerprint_sha256(), other.fingerprint_sha256());
    }

    #[test]
    fn a_leaf_for_an_address_carries_an_ip_san() {
        let ca = make_ca();
        let leaf = ca
            .leaf_for(&LeafTarget::Ip(Ipv4Addr::new(127, 0, 0, 1)))
            .unwrap();
        verify(&ca, &leaf, "127.0.0.1").unwrap();
        assert!(verify(&ca, &leaf, "127.0.0.2").is_err());
    }

    /// The same target gets the same leaf; past the limit the oldest goes.
    #[test]
    fn leaves_are_cached_and_bounded() {
        let ca = make_ca();
        let first = ca.leaf_for(&LeafTarget::Name("a.example".into())).unwrap();
        let again = ca.leaf_for(&LeafTarget::Name("a.example".into())).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(ca.leaves(), 1);
        for i in 0..MAX_LEAVES {
            ca.leaf_for(&LeafTarget::Ip(Ipv4Addr::from(0x0a00_0000 + i as u32)))
                .unwrap();
        }
        assert_eq!(ca.leaves(), MAX_LEAVES);
        let remade = ca.leaf_for(&LeafTarget::Name("a.example".into())).unwrap();
        assert!(!Arc::ptr_eq(&first, &remade), "the oldest was let go");
    }

    #[test]
    fn the_fingerprint_is_sha256_of_the_der() {
        let ca = make_ca();
        let digest = ring::digest::digest(&ring::digest::SHA256, ca.cert_der());
        assert_eq!(ca.fingerprint_sha256(), hex::encode(digest));
        assert_eq!(ca.fingerprint_sha256().len(), 64);
    }

    /// The PEM the guest gets is the certificate: one block, no key.
    #[test]
    fn the_guest_gets_the_certificate_and_never_the_key() {
        let ca = make_ca();
        let pem = ca.pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(pem.matches("-----BEGIN").count(), 1);
        assert!(!pem.contains("PRIVATE KEY"));
        assert!(pem.lines().all(|line| line.len() <= 64));
        assert!(pem.len() < 2048, "{}", pem.len());
        // It is the DER, re-encoded.
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        assert_eq!(der, ca.cert_der().as_ref());
    }

    #[test]
    fn a_bad_name_is_refused_not_signed() {
        let ca = make_ca();
        let error = ca
            .leaf_for(&LeafTarget::Name("not a name".into()))
            .unwrap_err();
        assert!(matches!(error, CaError::Name(_)), "{error}");
        assert_eq!(ca.leaves(), 0);
    }
}
