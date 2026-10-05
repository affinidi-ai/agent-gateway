//! mTLS verification helpers.
//!
//! Pure-logic module: takes a captured [`PeerCertInfo`] and a configured
//! [`MtlsAuthConfig`] plus a resolved set of pinned-cert and CA-cert PEMs
//! from the certificate store, and returns either an
//! [`AuthenticatedIdentity::Mtls`] on success or a
//! [`SourceAuthError`] on failure.
//!
//! No I/O is performed here — the caller is responsible for resolving
//! certificate IDs through the store. This keeps the verification logic
//! trivial to unit-test and easy to reason about.

use std::sync::Arc;
use std::time::SystemTime;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use webpki::anchor_from_trusted_cert;
use x509_parser::prelude::*;

use crate::source_auth::errors::{SourceAuthError, SourceAuthResult};
use crate::source_auth::models::{
    AuthenticatedIdentity, MtlsAuthConfig, MtlsIdentityBinding, MtlsSans, MtlsTrust, PeerCertInfo,
};

/// OID for the TLS Client Authentication Extended Key Usage.
const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// A single resolved certificate from the store, pre-decoded into DER
/// and pre-hashed (SHA-256) so the hot verification path does no PEM
/// parsing or hashing of trust material per request.
#[derive(Clone)]
pub struct TrustEntry {
    /// Stable certificate-store ID; carried so future diagnostic logs can
    /// surface *which* configured trust entry was loaded into the cache.
    #[allow(dead_code)]
    pub id: String,
    /// PEM-decoded DER bytes of the certificate.
    pub der: Arc<Vec<u8>>,
    /// SHA-256 of `der`.
    pub fingerprint: [u8; 32],
}

/// Resolved trust material passed in by the caller. The middleware looks
/// these up from the certificate store (with a cache) before calling
/// [`verify_peer_cert`].
pub struct ResolvedTrustMaterial<'a> {
    /// Pinned client certificates referenced by
    /// [`MtlsTrust::Pinned::certificate_ids`], in the same order.
    pub pinned: &'a [TrustEntry],
    /// CA certificates referenced by
    /// [`MtlsTrust::Ca::ca_certificate_ids`], in the same order.
    pub ca: &'a [TrustEntry],
}

/// Verify a captured client certificate against an mTLS auth config.
///
/// Returns [`AuthenticatedIdentity::Mtls`] on success or a structured
/// [`SourceAuthError`] on any failure. Errors deliberately do not leak
/// fingerprint / subject information for failed attempts — only the
/// reason string is exposed to the caller.
pub fn verify_peer_cert(
    peer: &PeerCertInfo,
    config: &MtlsAuthConfig,
    trust: ResolvedTrustMaterial<'_>,
    now: SystemTime,
) -> SourceAuthResult<AuthenticatedIdentity> {
    // Reject forwarded certs if the channel forbids them.
    if matches!(peer.source, crate::source_auth::models::PeerCertSource::Forwarded) && !config.allow_forwarded {
        return Err(SourceAuthError::InvalidCredential {
            reason: "Forwarded client certificate not allowed on this channel".to_string(),
        });
    }

    // Parse leaf DER into an x509-parser certificate.
    let (_, leaf) = X509Certificate::from_der(&peer.leaf_der).map_err(|e| SourceAuthError::InvalidCredential {
        reason: format!("Failed to parse client certificate: {e}"),
    })?;

    // Compute fingerprint up front — used for binding and audit.
    let leaf_fp_raw: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(&peer.leaf_der);
        hasher.finalize().into()
    };
    let fingerprint = hex::encode(leaf_fp_raw);

    // Trust check ----------------------------------------------------------
    let issuer_dn = match &config.trust {
        MtlsTrust::Pinned { certificate_ids } => {
            verify_pinned(&leaf_fp_raw, certificate_ids, trust.pinned)?;
            String::new()
        }
        MtlsTrust::Ca {
            ca_certificate_ids,
            require_client_auth_eku,
            check_crl,
            require_ocsp,
        } => {
            if *check_crl || *require_ocsp {
                // Defense-in-depth: config validation (src/config/proxy.rs
                // ::validate_source_auth) rejects these flags at load and
                // reload time, so we should never reach this branch in
                // practice. Keep the runtime check so a hand-edited
                // _storage/ file cannot silently weaken authentication.
                return Err(SourceAuthError::Internal {
                    reason: "OCSP/CRL revocation checks are not yet implemented; \
                             set `check_crl=false` and `require_ocsp=false`"
                        .to_string(),
                });
            }
            verify_ca_chain(peer, &leaf, ca_certificate_ids, trust.ca, now)?;
            if *require_client_auth_eku {
                require_eku(&leaf, OID_EKU_CLIENT_AUTH)?;
            }
            leaf.tbs_certificate
                .issuer
                .to_string()
        }
    };

    // Identity binding ----------------------------------------------------
    let principal = derive_principal(&config.identity_binding, &leaf, &fingerprint)?;

    // Allow-list filter ---------------------------------------------------
    if !config
        .allowed_subjects
        .is_empty()
        && !config
            .allowed_subjects
            .iter()
            .any(|pat| glob_match(pat, &principal))
    {
        return Err(SourceAuthError::InvalidCredential {
            reason: "Principal not in allowed_subjects".to_string(),
        });
    }

    let sans = extract_sans(&leaf);
    let subject_dn = leaf
        .tbs_certificate
        .subject
        .to_string();

    Ok(AuthenticatedIdentity::Mtls {
        principal,
        fingerprint,
        subject_dn,
        issuer_dn,
        sans,
        source: peer.source,
    })
}

// ── Trust: pinned ──────────────────────────────────────────────────────────

fn verify_pinned(
    presented_fingerprint: &[u8; 32],
    certificate_ids: &[String],
    pinned: &[TrustEntry],
) -> SourceAuthResult<()> {
    if certificate_ids.is_empty() {
        return Err(SourceAuthError::Internal {
            reason: "Pinned trust configured with empty certificate_ids".to_string(),
        });
    }
    if certificate_ids.len() != pinned.len() {
        return Err(SourceAuthError::Internal {
            reason: format!(
                "Pinned trust resolution mismatch: {} configured, {} resolved",
                certificate_ids.len(),
                pinned.len()
            ),
        });
    }

    // Constant-time comparison per pinned entry; bool OR keeps the
    // total work independent of which entry matches.
    let mut matched = subtle::Choice::from(0u8);
    for entry in pinned {
        matched |= entry
            .fingerprint
            .ct_eq(presented_fingerprint);
    }
    if bool::from(matched) {
        for (entry, cert_id) in pinned
            .iter()
            .zip(certificate_ids.iter())
        {
            if !bool::from(
                entry
                    .fingerprint
                    .ct_eq(presented_fingerprint),
            ) {
                continue;
            }
            if let Ok((_, cert)) = x509_parser::parse_x509_certificate(&entry.der)
                && !cert.validity().is_valid()
            {
                tracing::warn!(
                    "Pinned certificate '{}' matched but is expired (not_after={})",
                    cert_id,
                    cert.validity().not_after,
                );
            }
            break;
        }
        return Ok(());
    }

    Err(SourceAuthError::InvalidCredential {
        reason: "Presented certificate does not match any pinned certificate".to_string(),
    })
}

// ── Trust: CA chain ────────────────────────────────────────────────────────

fn verify_ca_chain(
    peer: &PeerCertInfo,
    leaf: &X509Certificate<'_>,
    ca_certificate_ids: &[String],
    ca: &[TrustEntry],
    now: SystemTime,
) -> SourceAuthResult<()> {
    let _ = leaf; // x509-parser leaf retained for symmetry; webpki re-parses internally.
    if ca_certificate_ids.is_empty() {
        return Err(SourceAuthError::Internal {
            reason: "CA trust configured with empty ca_certificate_ids".to_string(),
        });
    }
    if ca_certificate_ids.len() != ca.len() {
        return Err(SourceAuthError::Internal {
            reason: format!(
                "CA trust resolution mismatch: {} configured, {} resolved",
                ca_certificate_ids.len(),
                ca.len()
            ),
        });
    }

    // Note: validity-window enforcement is delegated to webpki below via
    // `webpki_now`. We deliberately do not re-check `not_before` /
    // `not_after` here to avoid divergent behaviour on clock skew.

    // Build webpki trust anchors from pre-decoded CA DER bytes.
    let ca_certs_der: Vec<CertificateDer<'_>> = ca
        .iter()
        .map(|e| CertificateDer::from_slice(e.der.as_slice()))
        .collect();
    let anchors: Vec<TrustAnchor<'_>> = ca_certs_der
        .iter()
        .map(|c| {
            anchor_from_trusted_cert(c).map_err(|e| SourceAuthError::Internal {
                reason: format!("Failed to build CA trust anchor: {e}"),
            })
        })
        .collect::<Result<_, _>>()?;

    let leaf_der = CertificateDer::from_slice(peer.leaf_der.as_slice());
    let leaf_cert = webpki::EndEntityCert::try_from(&leaf_der).map_err(|e| SourceAuthError::InvalidCredential {
        reason: format!("Invalid client certificate DER: {e}"),
    })?;

    // `chain_der` is documented as intermediates only — see PeerCertInfo.
    let intermediates: Vec<CertificateDer<'_>> = peer
        .chain_der
        .iter()
        .map(|d| CertificateDer::from_slice(d.as_slice()))
        .collect();

    let webpki_now = UnixTime::since_unix_epoch(
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| SourceAuthError::Internal {
                reason: "System clock is set before the UNIX epoch".to_string(),
            })?,
    );

    // Verify with the client-auth EKU when present in supported algorithms.
    leaf_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            webpki_now,
            webpki::KeyUsage::client_auth(),
            None, // no CRLs
            None, // no extra cert checker
        )
        .map_err(|e| SourceAuthError::InvalidCredential {
            reason: format!("Client certificate chain verification failed: {e}"),
        })?;

    Ok(())
}

fn require_eku(
    leaf: &X509Certificate<'_>,
    oid_str: &str,
) -> SourceAuthResult<()> {
    let Ok(ext) = leaf.extended_key_usage() else {
        return Err(SourceAuthError::InvalidCredential {
            reason: "Failed to parse Extended Key Usage extension".to_string(),
        });
    };
    let Some(eku) = ext else {
        return Err(SourceAuthError::InvalidCredential {
            reason: "Certificate is missing the required Extended Key Usage extension".to_string(),
        });
    };

    // For client-auth, demand the explicit OID. We intentionally do NOT
    // accept anyExtendedKeyUsage — a server-leaf with `anyEKU` would
    // otherwise pass this check.
    if oid_str == OID_EKU_CLIENT_AUTH {
        if eku.value.client_auth {
            return Ok(());
        }
    } else if eku
        .value
        .other
        .iter()
        .any(|o| o.to_id_string() == oid_str)
    {
        return Ok(());
    }
    Err(SourceAuthError::InvalidCredential {
        reason: format!("Certificate lacks required EKU {oid_str}"),
    })
}

// ── Identity binding ───────────────────────────────────────────────────────

fn derive_principal(
    binding: &MtlsIdentityBinding,
    leaf: &X509Certificate<'_>,
    fingerprint: &str,
) -> SourceAuthResult<String> {
    match binding {
        MtlsIdentityBinding::Fingerprint => Ok(fingerprint.to_string()),
        MtlsIdentityBinding::SubjectCn => leaf
            .tbs_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| SourceAuthError::InvalidCredential {
                reason: "Certificate Subject has no Common Name (CN) for identity binding".to_string(),
            }),
        MtlsIdentityBinding::DnsSan => first_san(leaf, SanKind::Dns)
            // RFC 1035 DNS names are case-insensitive; normalize to
            // lowercase so glob patterns behave deterministically.
            .map(|s| s.to_ascii_lowercase())
            .ok_or_else(|| SourceAuthError::InvalidCredential {
                reason: "Certificate has no DNS SubjectAltName for identity binding".to_string(),
            }),
        MtlsIdentityBinding::UriSan => {
            first_san(leaf, SanKind::Uri).ok_or_else(|| SourceAuthError::InvalidCredential {
                reason: "Certificate has no URI SubjectAltName for identity binding".to_string(),
            })
        }
        MtlsIdentityBinding::IpSan => first_san(leaf, SanKind::Ip).ok_or_else(|| SourceAuthError::InvalidCredential {
            reason: "Certificate has no IP SubjectAltName for identity binding".to_string(),
        }),
        MtlsIdentityBinding::SubjectRdn { oid } => leaf
            .tbs_certificate
            .subject
            .iter_attributes()
            .find(|attr| {
                attr.attr_type()
                    .to_id_string()
                    == *oid
            })
            .and_then(|attr| {
                attr.as_str()
                    .ok()
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| SourceAuthError::InvalidCredential {
                reason: format!("Certificate Subject has no RDN with OID {oid} for identity binding"),
            }),
    }
}

// ── SAN extraction ─────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
enum SanKind {
    Dns,
    Uri,
    #[allow(dead_code)] // exposed via extract_sans for OPA/audit; not yet a binding mode.
    Email,
    Ip,
}

fn first_san(
    leaf: &X509Certificate<'_>,
    kind: SanKind,
) -> Option<String> {
    let ext = leaf
        .subject_alternative_name()
        .ok()
        .flatten()?;
    for name in &ext.value.general_names {
        match (kind, name) {
            (SanKind::Dns, GeneralName::DNSName(s)) => return Some((*s).to_string()),
            (SanKind::Uri, GeneralName::URI(s)) => return Some((*s).to_string()),
            (SanKind::Email, GeneralName::RFC822Name(s)) => return Some((*s).to_string()),
            (SanKind::Ip, GeneralName::IPAddress(bytes)) => {
                return format_ip_san(bytes);
            }
            _ => {}
        }
    }
    None
}

fn extract_sans(leaf: &X509Certificate<'_>) -> MtlsSans {
    let mut out = MtlsSans::default();
    if let Ok(Some(ext)) = leaf.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(s) => out.dns.push((*s).to_string()),
                GeneralName::URI(s) => out.uri.push((*s).to_string()),
                GeneralName::RFC822Name(s) => out
                    .email
                    .push((*s).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(s) = format_ip_san(bytes) {
                        out.ip.push(s);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Render an X.509 IP-address SAN (raw 4 or 16 bytes) as a canonical
/// string. Returns `None` for malformed lengths.
fn format_ip_san(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(arr).to_string())
        }
        16 => {
            let arr: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(arr).to_string())
        }
        _ => None,
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

#[cfg(test)]
fn decode_pem_certificate(pem_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem_bytes).map_err(|e| format!("PEM parse error: {e}"))?;
    if parsed.label != "CERTIFICATE" {
        return Err(format!("Expected PEM tag 'CERTIFICATE', got '{}'", parsed.label));
    }
    Ok(parsed.contents)
}

/// Simple glob matcher: only `*` is meaningful (zero-or-more chars).
/// Used for `allowed_subjects`. Case-sensitive — callers that want
/// case-insensitive matching (e.g. DNS-bound principals) must
/// pre-normalize both sides to lowercase.
fn glob_match(
    pattern: &str,
    candidate: &str,
) -> bool {
    if !pattern.contains('*') {
        return pattern == candidate;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 {
            if !candidate.starts_with(part) {
                return false;
            }
            cursor = part.len();
        } else if idx == parts.len() - 1 {
            // Final non-empty segment must match the tail and also lie
            // at or past the cursor (no overlap with what we've already
            // consumed).
            if !candidate[cursor..].ends_with(part) {
                return false;
            }
            // (Cursor advancement unnecessary — last segment.)
        } else {
            let Some(found) = candidate[cursor..].find(part) else {
                return false;
            };
            cursor += found + part.len();
        }
    }
    true
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_auth::models::PeerCertSource;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use std::time::Duration;

    struct TestPki {
        ca_pem: Vec<u8>,
        client_pem: Vec<u8>,
        client_der: Vec<u8>,
    }

    fn build_pki(
        client_cn: &str,
        sans: Vec<SanType>,
        with_client_eku: bool,
        validity_secs: i64,
    ) -> TestPki {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_kp = KeyPair::generate().expect("ca keypair");
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_kp)
            .expect("self-signed ca");
        let ca_pem = ca_cert.pem().into_bytes();
        let issuer = rcgen::Issuer::new(ca_params, ca_kp);

        let mut client_params = CertificateParams::default();
        client_params.distinguished_name = DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, client_cn);
        client_params.subject_alt_names = sans;
        if with_client_eku {
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        let now = ::time::OffsetDateTime::now_utc();
        client_params.not_before = now - ::time::Duration::seconds(60);
        client_params.not_after = now + ::time::Duration::seconds(validity_secs);

        let client_kp = KeyPair::generate().expect("client keypair");
        let client_cert = client_params
            .signed_by(&client_kp, &issuer)
            .expect("signed client");
        let client_pem = client_cert.pem().into_bytes();
        let client_der = client_cert.der().to_vec();

        TestPki { ca_pem, client_pem, client_der }
    }

    fn peer_from_der(der: Vec<u8>) -> PeerCertInfo {
        PeerCertInfo {
            leaf_der: der,
            // chain_der is intermediates only; rcgen test certs are
            // root-signed leaves with no intermediate.
            chain_der: Vec::new(),
            source: PeerCertSource::DirectTls,
        }
    }

    fn peer_with_intermediates(
        leaf_der: Vec<u8>,
        intermediates: Vec<Vec<u8>>,
    ) -> PeerCertInfo {
        PeerCertInfo {
            leaf_der,
            chain_der: intermediates,
            source: PeerCertSource::DirectTls,
        }
    }

    fn to_entries(pems: &[&[u8]]) -> Vec<TrustEntry> {
        pems.iter()
            .enumerate()
            .map(|(i, pem)| {
                let der = decode_pem_certificate(pem).expect("decode test pem");
                let fp: [u8; 32] = Sha256::digest(&der).into();
                TrustEntry {
                    id: format!("test-{i}"),
                    der: Arc::new(der),
                    fingerprint: fp,
                }
            })
            .collect()
    }

    #[test]
    fn pinned_accept_match() {
        let pki = build_pki("alice", vec![], false, 3600);
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Pinned {
                certificate_ids: vec!["c1".into()],
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let pinned = to_entries(&[&pki.client_pem]);
        let trust = ResolvedTrustMaterial { pinned: &pinned, ca: &[] };
        let id = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect("pinned accept");
        match id {
            AuthenticatedIdentity::Mtls { principal, fingerprint, .. } => {
                assert_eq!(principal, fingerprint);
                assert_eq!(fingerprint.len(), 64);
            }
            _ => panic!("expected Mtls identity"),
        }
    }

    #[test]
    fn pinned_reject_mismatch() {
        let pki = build_pki("alice", vec![], false, 3600);
        let other = build_pki("eve", vec![], false, 3600);
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Pinned {
                certificate_ids: vec!["c1".into()],
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let pinned = to_entries(&[&other.client_pem]);
        let trust = ResolvedTrustMaterial { pinned: &pinned, ca: &[] };
        let err = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    #[test]
    fn ca_accept_with_client_eku() {
        let pki = build_pki(
            "alice",
            vec![SanType::URI(
                "spiffe://example.org/alice"
                    .try_into()
                    .unwrap(),
            )],
            true,
            3600,
        );
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::UriSan,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let id = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect("ca accept");
        match id {
            AuthenticatedIdentity::Mtls { principal, sans, .. } => {
                assert_eq!(principal, "spiffe://example.org/alice");
                assert_eq!(sans.uri, vec!["spiffe://example.org/alice"]);
            }
            _ => panic!("expected Mtls identity"),
        }
    }

    #[test]
    fn ca_reject_unknown_issuer() {
        let pki = build_pki("alice", vec![], true, 3600);
        let other_ca = build_pki("eve", vec![], true, 3600);
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&other_ca.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let err = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    #[test]
    fn ca_reject_missing_client_auth_eku() {
        let pki = build_pki("alice", vec![], false, 3600);
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let err = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    #[test]
    fn crl_or_ocsp_set_rejected() {
        let pki = build_pki("alice", vec![], true, 3600);
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: true,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let err = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::Internal { .. }));
    }

    #[test]
    fn forwarded_rejected_when_disallowed() {
        let pki = build_pki("alice", vec![], true, 3600);
        let mut peer = peer_from_der(pki.client_der.clone());
        peer.source = PeerCertSource::Forwarded;
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: false,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let err = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    #[test]
    fn dns_san_binding() {
        let pki = build_pki(
            "alice",
            vec![SanType::DnsName(
                "agent.example.com"
                    .try_into()
                    .unwrap(),
            )],
            true,
            3600,
        );
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::DnsSan,
            allowed_subjects: vec!["agent.*".into()],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let id = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect("dns san accept");
        match id {
            AuthenticatedIdentity::Mtls { principal, .. } => assert_eq!(principal, "agent.example.com"),
            _ => panic!("expected Mtls identity"),
        }
    }

    #[test]
    fn allowed_subjects_reject_no_match() {
        let pki = build_pki(
            "alice",
            vec![SanType::DnsName(
                "intruder.example.com"
                    .try_into()
                    .unwrap(),
            )],
            true,
            3600,
        );
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::DnsSan,
            allowed_subjects: vec!["agent.*".into()],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let err = verify_peer_cert(&peer, &cfg, trust, SystemTime::now()).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    #[test]
    fn glob_matches() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("agent.*", "agent.foo"));
        assert!(glob_match("spiffe://*/alice", "spiffe://example.org/alice"));
        assert!(!glob_match("agent.*", "other.foo"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn expired_certificate_rejected() {
        let pki = build_pki("alice", vec![], true, 1);
        let peer = peer_from_der(pki.client_der.clone());
        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["ca1".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::Fingerprint,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&pki.ca_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        // Move "now" past validity window.
        let now = SystemTime::now() + Duration::from_secs(7200);
        let err = verify_peer_cert(&peer, &cfg, trust, now).expect_err("should reject");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    /// Regression: a leaf signed by an intermediate signed by the root must
    /// verify when the intermediate is provided in `chain_der` and only the
    /// root is configured in the trust store. This guards against the
    /// earlier bug where `chain_der` was being skipped, which made any
    /// non-root-signed leaf appear unverifiable.
    #[test]
    fn ca_accept_multi_level_chain_via_intermediate() {
        // Root CA (self-signed).
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.distinguished_name = DistinguishedName::new();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_kp = KeyPair::generate().expect("root keypair");
        let root_cert = root_params
            .clone()
            .self_signed(&root_kp)
            .expect("self-signed root");
        let root_pem = root_cert.pem().into_bytes();
        let root_issuer = rcgen::Issuer::new(root_params, root_kp);

        // Intermediate CA (constrained to 0 path length so it can sign
        // leaves but not further CAs).
        let mut int_params = CertificateParams::default();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        int_params.distinguished_name = DistinguishedName::new();
        int_params
            .distinguished_name
            .push(DnType::CommonName, "Test Intermediate CA");
        int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let int_kp = KeyPair::generate().expect("intermediate keypair");
        let int_cert = int_params
            .clone()
            .signed_by(&int_kp, &root_issuer)
            .expect("intermediate signed by root");
        let int_der = int_cert.der().to_vec();
        let int_issuer = rcgen::Issuer::new(int_params, int_kp);

        // Leaf signed by the intermediate.
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "alice");
        leaf_params.subject_alt_names = vec![SanType::DnsName(
            "alice.example.com"
                .try_into()
                .unwrap(),
        )];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now_t = ::time::OffsetDateTime::now_utc();
        leaf_params.not_before = now_t - ::time::Duration::seconds(60);
        leaf_params.not_after = now_t + ::time::Duration::seconds(3600);
        let leaf_kp = KeyPair::generate().expect("leaf keypair");
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &int_issuer)
            .expect("leaf signed by intermediate");
        let leaf_der = leaf_cert.der().to_vec();

        // Pipeline contract: leaf in `leaf_der`, intermediates in
        // `chain_der` (closest-to-leaf first, root excluded).
        let peer = peer_with_intermediates(leaf_der, vec![int_der]);

        let cfg = MtlsAuthConfig {
            trust: MtlsTrust::Ca {
                ca_certificate_ids: vec!["root".into()],
                require_client_auth_eku: true,
                check_crl: false,
                require_ocsp: false,
            },
            identity_binding: MtlsIdentityBinding::DnsSan,
            allowed_subjects: vec![],
            allow_forwarded: true,
        };
        let ca = to_entries(&[&root_pem]);
        let trust = ResolvedTrustMaterial { pinned: &[], ca: &ca };
        let id = verify_peer_cert(&peer, &cfg, trust, SystemTime::now())
            .expect("multi-level chain should verify against root via intermediate");
        match id {
            AuthenticatedIdentity::Mtls { principal, .. } => {
                assert_eq!(principal, "alice.example.com");
            }
            _ => panic!("expected Mtls identity"),
        }
    }
}
