//! Credential-derived managed agent identity.
//!
//! Translates `ManagedIdentityConfig::FromMtls { certificate_id }` /
//! `ManagedIdentityConfig::FromApiKey { api_key_id }` /
//! `ManagedIdentityConfig::Static { did }` into the inputs the existing DID
//! issuance pipeline expects (`identity_fields: HashMap<String, JsonValue>` +
//! canonical `identity_hash`), so the same `VCIssuer::issue_or_get_credential`
//! path that backs `PayloadExtraction` produces a stable `did:webvh` per
//! stored credential.
//!
//! ## Semantics (locked in by the user 2026-05-26)
//!
//! - **One DID per `certificate_id` / `api_key_id`.** The identity hash is
//!   keyed off the stable identifier only, *not* the underlying secret /
//!   PEM bytes. Rotating the cert or the secret value keeps the DID stable.
//!   Re-pointing the channel at a different stored credential produces a
//!   different DID.
//! - **Independent of source auth.** The DID is derived from the *stored*
//!   credential material, not from what the caller presents.
//! - **`Static { did }`** bypasses issuance: the configured DID is used
//!   verbatim. No identity record is persisted.
//! - **`Certificate.identity_did = Some(_)`** is honoured as a pre-bound
//!   override — same behaviour as `Static`, scoped per cert.
//!
//! ## Performance
//!
//! Cert / secret store lookups are unavoidable per request (the store is
//! the source of truth for `updated_at` invalidation). PEM parsing,
//! SHA-256 of the leaf DER, and HMAC over the stable identifier are
//! cached in a [`CredentialIdentityResolver`] keyed on
//! `(credential_id, updated_at)`. A cache hit is a single DashMap read.
//!
//! ## Security
//!
//! - The identity hash is computed as `HMAC-SHA256(pepper, canonical(fields))`
//!   where `pepper` is process-wide and seeded from `AG_IDENTITY_HASH_PEPPER`
//!   (≥32 hex bytes) when present, or a random 32-byte secret generated at
//!   first use. The pepper makes the hash non-invertible without the
//!   pepper, so emitting the hash via OPA input / audit does not expose
//!   the underlying secret to offline brute-force.
//! - The raw API-key SHA / value is **never** included in the emitted
//!   `identity_fields`. Only the stable identifier (`api_key_id`,
//!   `secret_id`) is surfaced to downstream consumers.
//! - mTLS `certificate_id`, `fingerprint_sha256`, `subject_dn`, `issuer_dn`
//!   are emitted (they are not secret) but the hash is not keyed off the
//!   fingerprint — see the "one DID per stored credential" rule above.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde_json::{Value as JsonValue, json};

use crate::certificates::{Certificate, CertificateKind, CertificateStore};
use crate::config::PepperCacheConfig;
use crate::secrets::{Secret, SecretsStore};
use crate::source_auth::ManagedIdentityConfig;

// ── Pepper ────────────────────────────────────────────────────────────────

static IDENTITY_HASH_PEPPER: OnceLock<Vec<u8>> = OnceLock::new();

pub async fn initialize_pepper() {
    if IDENTITY_HASH_PEPPER
        .get()
        .is_some()
    {
        return;
    }

    let resolved = PepperCacheConfig::load().await;
    let _ = IDENTITY_HASH_PEPPER.set(resolved.pepper_hash);
}

fn new_ephemeral_pepper() -> Vec<u8> {
    let mut out = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut out);
    tracing::warn!(
        target: "credential_identity",
        "Credential identity pepper was not initialized at startup; using an ephemeral pepper for this process."
    );
    out
}

/// Process-wide HMAC pepper for credential identity hashes.
///
/// Read once from `AG_IDENTITY_HASH_PEPPER` (hex, ≥32 bytes after decoding).
/// If missing or invalid, a random 32-byte pepper is generated and
/// used for the lifetime of the process — DIDs derived in that case do **not**
/// persist across restarts; operators are warned via log on initialisation.
fn pepper() -> &'static [u8] {
    IDENTITY_HASH_PEPPER
        .get_or_init(new_ephemeral_pepper)
        .as_slice()
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CredentialIdentityError {
    #[error("certificate store is not configured")]
    CertificateStoreUnavailable,

    #[error("secrets store is not configured")]
    SecretsStoreUnavailable,

    #[error("certificate '{0}' not found in cert store")]
    CertificateNotFound(String),

    #[error("certificate '{0}' is disabled")]
    CertificateDisabled(String),

    #[error("certificate '{certificate_id}' has expired (expires_at={expires_at})")]
    CertificateExpired { certificate_id: String, expires_at: DateTime<Utc> },

    #[error("certificate '{certificate_id}' has wrong kind: expected ClientLeaf, got {kind:?}")]
    CertificateWrongKind { certificate_id: String, kind: CertificateKind },

    #[error("secret '{0}' not found in secrets store")]
    SecretNotFound(String),

    #[error("invalid static DID: {0}")]
    InvalidStaticDid(String),

    #[error("failed to parse certificate PEM for '{certificate_id}': {source}")]
    CertificateParse {
        certificate_id: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("store lookup failed: {0}")]
    StoreLookup(String),

    #[error(
        "validated JWT claims are unavailable for FromJwtClaim resolution; this mode requires jwt_bearer source auth on the same surface"
    )]
    JwtClaimsUnavailable,

    #[error("required JWT claim '{0}' is missing or not a string in the validated token")]
    JwtClaimMissing(String),
}

/// Classification used by callers to map errors to HTTP status + metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialIdentityErrorClass {
    /// Operator misconfiguration (missing/disabled/expired cert, bad DID, …) → 500.
    Misconfigured,
    /// Backing store unavailable / lookup failure → 503.
    BackendUnavailable,
}

impl CredentialIdentityError {
    pub fn classify(&self) -> CredentialIdentityErrorClass {
        match self {
            Self::CertificateStoreUnavailable | Self::SecretsStoreUnavailable | Self::StoreLookup(_) => {
                CredentialIdentityErrorClass::BackendUnavailable
            }
            Self::CertificateNotFound(_)
            | Self::SecretNotFound(_)
            | Self::CertificateDisabled(_)
            | Self::CertificateExpired { .. }
            | Self::CertificateWrongKind { .. }
            | Self::CertificateParse { .. }
            | Self::InvalidStaticDid(_)
            | Self::JwtClaimsUnavailable
            | Self::JwtClaimMissing(_) => CredentialIdentityErrorClass::Misconfigured,
        }
    }

    /// Low-cardinality reason label for metrics.
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::CertificateStoreUnavailable => "cert_store_unavailable",
            Self::SecretsStoreUnavailable => "secrets_store_unavailable",
            Self::CertificateNotFound(_) => "cert_not_found",
            Self::CertificateDisabled(_) => "cert_disabled",
            Self::CertificateExpired { .. } => "cert_expired",
            Self::CertificateWrongKind { .. } => "cert_wrong_kind",
            Self::CertificateParse { .. } => "cert_parse_failed",
            Self::SecretNotFound(_) => "secret_not_found",
            Self::InvalidStaticDid(_) => "invalid_static_did",
            Self::StoreLookup(_) => "store_lookup_failed",
            Self::JwtClaimsUnavailable => "jwt_claims_unavailable",
            Self::JwtClaimMissing(_) => "jwt_claim_missing",
        }
    }
}

// ── Outcome ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CredentialIdentity {
    /// Hash + fields suitable for `VCIssuer::issue_or_get_credential`.
    Derived { identity_fields: HashMap<String, JsonValue>, identity_hash: String },
    /// Bound DID — skip issuance entirely. Returned for `Static { did }`
    /// and for certificates with `Certificate.identity_did = Some(_)`.
    Bound { did: String, identity_fields: HashMap<String, JsonValue> },
}

impl CredentialIdentity {
    /// Low-cardinality `mode` label for metrics.
    #[allow(dead_code)]
    pub fn mode_label(&self) -> &'static str {
        match self {
            Self::Derived { .. } => "derived",
            Self::Bound { .. } => "bound",
        }
    }
}

// ── Cache ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct CachedDerivation {
    updated_at: DateTime<Utc>,
    fields: HashMap<String, JsonValue>,
    hash: String,
}

/// Per-process resolver holding the parse/HMAC caches.
///
/// Construct once at startup via [`global_resolver`]; the same instance is
/// shared by inbound + outbound pipelines. Cache entries are invalidated
/// implicitly on credential rotation by comparing the stored
/// `updated_at` against the live store value.
pub struct CredentialIdentityResolver {
    mtls_cache: DashMap<String, CachedDerivation>,
    api_key_cache: DashMap<String, CachedDerivation>,
}

impl Default for CredentialIdentityResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialIdentityResolver {
    pub fn new() -> Self {
        Self {
            mtls_cache: DashMap::new(),
            api_key_cache: DashMap::new(),
        }
    }

    pub async fn resolve(
        &self,
        managed_identity: &ManagedIdentityConfig,
        certificates_store: Option<&Arc<dyn CertificateStore>>,
        secrets_store: Option<&Arc<dyn SecretsStore>>,
    ) -> Result<Option<CredentialIdentity>, CredentialIdentityError> {
        match managed_identity {
            ManagedIdentityConfig::PayloadExtraction(_) => Ok(None),

            ManagedIdentityConfig::FromMtls { certificate_id } => self
                .resolve_mtls(certificate_id, certificates_store)
                .await
                .map(Some),

            ManagedIdentityConfig::FromApiKey { api_key_id } => self
                .resolve_api_key(api_key_id, secrets_store)
                .await
                .map(Some),

            ManagedIdentityConfig::Static { did } => {
                validate_did(did).map_err(CredentialIdentityError::InvalidStaticDid)?;
                Ok(Some(CredentialIdentity::Bound {
                    did: did.clone(),
                    identity_fields: build_static_identity_fields(did),
                }))
            }

            // Request-bound: the store-based resolver has no token in scope.
            // Callers must special-case `FromJwtClaim` and route through
            // [`resolve_jwt_claim_identity`] with the validated claim set.
            ManagedIdentityConfig::FromJwtClaim { .. } => Err(CredentialIdentityError::JwtClaimsUnavailable),
        }
    }

    async fn resolve_mtls(
        &self,
        certificate_id: &str,
        store: Option<&Arc<dyn CertificateStore>>,
    ) -> Result<CredentialIdentity, CredentialIdentityError> {
        let store = store.ok_or(CredentialIdentityError::CertificateStoreUnavailable)?;
        let cert = store
            .get(certificate_id)
            .await
            .map_err(CredentialIdentityError::StoreLookup)?
            .ok_or_else(|| CredentialIdentityError::CertificateNotFound(certificate_id.to_string()))?;

        if !cert.active {
            return Err(CredentialIdentityError::CertificateDisabled(certificate_id.to_string()));
        }
        if !matches!(cert.kind, CertificateKind::ClientLeaf) {
            return Err(CredentialIdentityError::CertificateWrongKind {
                certificate_id: certificate_id.to_string(),
                kind: cert.kind,
            });
        }
        if let Some(exp) = cert.expires_at
            && exp <= Utc::now()
        {
            return Err(CredentialIdentityError::CertificateExpired {
                certificate_id: certificate_id.to_string(),
                expires_at: exp,
            });
        }

        // Pre-bound DID (operator pinned the agent identity on the cert).
        if let Some(ref did) = cert.identity_did {
            validate_did(did).map_err(CredentialIdentityError::InvalidStaticDid)?;
            return Ok(CredentialIdentity::Bound {
                did: did.clone(),
                identity_fields: build_mtls_bound_fields(certificate_id, &cert),
            });
        }

        // Cache hit?
        if let Some(entry) = self
            .mtls_cache
            .get(certificate_id)
            && entry.updated_at == cert.updated_at
        {
            return Ok(CredentialIdentity::Derived {
                identity_fields: entry.fields.clone(),
                identity_hash: entry.hash.clone(),
            });
        }

        // Miss / stale — parse the leaf for emitted fields.
        let parsed = parse_leaf(&cert.certificate_pem).map_err(|e| CredentialIdentityError::CertificateParse {
            certificate_id: certificate_id.to_string(),
            source: e,
        })?;
        let fields = build_mtls_identity_fields(certificate_id, &parsed);
        // Hash keyed on the stable identifier only — rotation of the PEM
        // under the same certificate_id keeps the DID stable.
        let hash = hash_credential(&[("credential_type", "mtls"), ("certificate_id", certificate_id)]);

        self.mtls_cache.insert(
            certificate_id.to_string(),
            CachedDerivation {
                updated_at: cert.updated_at,
                fields: fields.clone(),
                hash: hash.clone(),
            },
        );

        Ok(CredentialIdentity::Derived {
            identity_fields: fields,
            identity_hash: hash,
        })
    }

    async fn resolve_api_key(
        &self,
        api_key_id: &str,
        store: Option<&Arc<dyn SecretsStore>>,
    ) -> Result<CredentialIdentity, CredentialIdentityError> {
        // API keys managed by the API key store carry an `atgk_`-prefixed key_id.
        // Those IDs live in a separate subsystem (ApiKeyStore), not in SecretsStore,
        // so a secrets-store lookup would always fail. The hash is keyed on
        // `api_key_id` alone, so we derive identity directly — no store lookup needed.
        if api_key_id.starts_with(crate::api_keys::KEY_ID_PREFIX) {
            return Ok(self.derive_api_key_id_direct(api_key_id));
        }

        let store = store.ok_or(CredentialIdentityError::SecretsStoreUnavailable)?;
        let secret = store
            .get_by_secret_id(api_key_id)
            .await
            .map_err(|e| CredentialIdentityError::StoreLookup(e.to_string()))?
            .ok_or_else(|| CredentialIdentityError::SecretNotFound(api_key_id.to_string()))?;

        if let Some(entry) = self
            .api_key_cache
            .get(api_key_id)
            && entry.updated_at == secret.updated_at
        {
            return Ok(CredentialIdentity::Derived {
                identity_fields: entry.fields.clone(),
                identity_hash: entry.hash.clone(),
            });
        }

        let fields = build_api_key_identity_fields(api_key_id, &secret);
        let hash = hash_credential(&[("credential_type", "api_key"), ("api_key_id", api_key_id)]);

        self.api_key_cache.insert(
            api_key_id.to_string(),
            CachedDerivation {
                updated_at: secret.updated_at,
                fields: fields.clone(),
                hash: hash.clone(),
            },
        );

        Ok(CredentialIdentity::Derived {
            identity_fields: fields,
            identity_hash: hash,
        })
    }

    /// Derive `CredentialIdentity` from an `atgk_`-prefixed API key ID without
    /// a secrets-store lookup. Used when the key lives in the API key store
    /// (a separate subsystem). The hash is identical to the secrets-store path
    /// because it is keyed on `api_key_id` only.
    fn derive_api_key_id_direct(
        &self,
        api_key_id: &str,
    ) -> CredentialIdentity {
        // Sentinel updated_at that never expires — entries are valid for the
        // lifetime of the process. The key_id is immutable so no invalidation
        // is needed beyond process restart.
        let sentinel = DateTime::<Utc>::MIN_UTC;
        if let Some(entry) = self
            .api_key_cache
            .get(api_key_id)
            && entry.updated_at == sentinel
        {
            return CredentialIdentity::Derived {
                identity_fields: entry.fields.clone(),
                identity_hash: entry.hash.clone(),
            };
        }
        let mut fields = HashMap::new();
        fields.insert("credential_type".to_string(), json!("api_key"));
        fields.insert("api_key_id".to_string(), json!(api_key_id));
        let hash = hash_credential(&[("credential_type", "api_key"), ("api_key_id", api_key_id)]);
        self.api_key_cache.insert(
            api_key_id.to_string(),
            CachedDerivation {
                updated_at: sentinel,
                fields: fields.clone(),
                hash: hash.clone(),
            },
        );
        CredentialIdentity::Derived {
            identity_fields: fields,
            identity_hash: hash,
        }
    }

    /// Forget any cached entry for `certificate_id`. Call after store mutations.
    #[allow(dead_code)]
    pub fn invalidate_certificate(
        &self,
        certificate_id: &str,
    ) {
        self.mtls_cache
            .remove(certificate_id);
    }

    /// Forget any cached entry for `api_key_id`. Call after store mutations.
    #[allow(dead_code)]
    pub fn invalidate_api_key(
        &self,
        api_key_id: &str,
    ) {
        self.api_key_cache
            .remove(api_key_id);
    }

    #[cfg(test)]
    pub fn mtls_cache_len(&self) -> usize {
        self.mtls_cache.len()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn api_key_cache_len(&self) -> usize {
        self.api_key_cache.len()
    }
}

// ── Global resolver ───────────────────────────────────────────────────────

static GLOBAL_RESOLVER: OnceLock<Arc<CredentialIdentityResolver>> = OnceLock::new();

/// Shared resolver used by inbound + outbound proxy paths.
pub fn global_resolver() -> Arc<CredentialIdentityResolver> {
    GLOBAL_RESOLVER
        .get_or_init(|| Arc::new(CredentialIdentityResolver::new()))
        .clone()
}

/// Thin wrapper around the global resolver — keeps the existing call sites
/// terse. Equivalent to `global_resolver().resolve(...)`.
pub async fn derive_credential_identity(
    managed_identity: &ManagedIdentityConfig,
    certificates_store: Option<&Arc<dyn CertificateStore>>,
    secrets_store: Option<&Arc<dyn SecretsStore>>,
) -> Result<Option<CredentialIdentity>, CredentialIdentityError> {
    global_resolver()
        .resolve(managed_identity, certificates_store, secrets_store)
        .await
}

/// Resolve a [`CredentialIdentity`] from validated inbound JWT claims.
///
/// Request-bound counterpart to [`CredentialIdentityResolver::resolve`]: the
/// agent DID is derived from the value of `claim` in the caller's verified
/// token (the Entra Agent ID `oid` by default), namespaced by
/// `namespace_claims` so the same object id under different tenants / issuers
/// yields distinct DIDs. The peppered HMAC keeps the derivation stable across
/// gateways that share `AG_IDENTITY_HASH_PEPPER`.
pub fn resolve_jwt_claim_identity(
    claim: &str,
    namespace_claims: &[String],
    claims: &JsonValue,
) -> Result<CredentialIdentity, CredentialIdentityError> {
    let value = claims
        .get(claim)
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CredentialIdentityError::JwtClaimMissing(claim.to_string()))?;

    let mut owned: Vec<(String, String)> = Vec::with_capacity(3 + namespace_claims.len());
    owned.push(("credential_type".to_string(), "jwt_claim".to_string()));
    owned.push(("claim".to_string(), claim.to_string()));
    owned.push(("value".to_string(), value.to_string()));

    for ns in namespace_claims {
        let ns_value = claims
            .get(ns)
            .and_then(JsonValue::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CredentialIdentityError::JwtClaimMissing(ns.clone()))?;
        owned.push((format!("ns.{ns}"), ns_value.to_string()));
    }

    let pairs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let identity_hash = hash_credential(&pairs);

    let identity_fields = owned
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect::<HashMap<String, JsonValue>>();

    Ok(CredentialIdentity::Derived { identity_fields, identity_hash })
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Validate a DID string. Accepts `did:METHOD:method-specific-id` where
/// METHOD is non-empty lowercase alphanumeric.
fn validate_did(did: &str) -> Result<(), String> {
    if did != did.trim() {
        return Err(format!("DID has leading/trailing whitespace: '{did}'"));
    }
    if did.is_empty() {
        return Err("DID is empty".to_string());
    }
    let parts: Vec<&str> = did.splitn(3, ':').collect();
    if parts.len() < 3 || parts[0] != "did" || parts[1].is_empty() || parts[2].is_empty() {
        return Err(format!("'{did}' is not in 'did:METHOD:ID' form"));
    }
    if !parts[1]
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(format!("DID method '{}' must be lowercase alphanumeric", parts[1]));
    }
    Ok(())
}

/// A 32-byte key for `label`, derived from the process-wide pepper.
///
/// `HMAC-SHA256(pepper, label)`: gateways sharing `AG_IDENTITY_HASH_PEPPER`
/// derive the same key, and each label gives an unrelated one.
pub(crate) fn derived_key(label: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper()).expect("HMAC key");
    mac.update(label);
    mac.finalize()
        .into_bytes()
        .into()
}

/// Compute the canonical identity hash for credential-derived identity.
///
/// Output: lowercase hex of `HMAC-SHA256(pepper, canonical(pairs))` where
/// canonical encoding is `sort(pairs).flat_map(|(k,v)| [k, 0x00, v, 0x00])`.
pub(crate) fn hash_credential(pairs: &[(&str, &str)]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(pepper()).expect("HMAC key");
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in sorted {
        mac.update(k.as_bytes());
        mac.update(&[0u8]);
        mac.update(v.as_bytes());
        mac.update(&[0u8]);
    }
    hex::encode(mac.finalize().into_bytes())
}

struct ParsedLeaf {
    fingerprint_sha256_hex: String,
    subject_dn: String,
    issuer_dn: String,
}

fn parse_leaf(pem: &str) -> anyhow::Result<ParsedLeaf> {
    use sha2::{Digest, Sha256};

    let (_, parsed_pem) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow::anyhow!("PEM parse failed: {e}"))?;
    let leaf_der: &[u8] = &parsed_pem.contents;
    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf_der).map_err(|e| anyhow::anyhow!("X.509 parse failed: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(leaf_der);

    Ok(ParsedLeaf {
        fingerprint_sha256_hex: hex::encode(hasher.finalize()),
        subject_dn: cert.subject().to_string(),
        issuer_dn: cert.issuer().to_string(),
    })
}

fn build_mtls_identity_fields(
    certificate_id: &str,
    parsed: &ParsedLeaf,
) -> HashMap<String, JsonValue> {
    let mut fields = HashMap::new();
    fields.insert("credential_type".to_string(), json!("mtls"));
    fields.insert("certificate_id".to_string(), json!(certificate_id));
    fields.insert("fingerprint_sha256".to_string(), json!(parsed.fingerprint_sha256_hex));
    fields.insert("subject_dn".to_string(), json!(parsed.subject_dn));
    fields.insert("issuer_dn".to_string(), json!(parsed.issuer_dn));
    fields
}

fn build_mtls_bound_fields(
    certificate_id: &str,
    cert: &Certificate,
) -> HashMap<String, JsonValue> {
    let mut fields = HashMap::new();
    fields.insert("credential_type".to_string(), json!("mtls_bound"));
    fields.insert("certificate_id".to_string(), json!(certificate_id));
    if let Some(ref did) = cert.identity_did {
        fields.insert("did".to_string(), json!(did));
    }
    fields
}

fn build_api_key_identity_fields(
    api_key_id: &str,
    secret: &Secret,
) -> HashMap<String, JsonValue> {
    let mut fields = HashMap::new();
    fields.insert("credential_type".to_string(), json!("api_key"));
    fields.insert("api_key_id".to_string(), json!(api_key_id));
    fields.insert("secret_id".to_string(), json!(secret.secret_id.clone()));
    // NOTE: the secret's SHA / value is deliberately NOT emitted. The
    // peppered HMAC computed in `hash_credential` is the only secret-keyed
    // material, and it never escapes the identity-hash channel.
    fields
}

fn build_static_identity_fields(did: &str) -> HashMap<String, JsonValue> {
    let mut fields = HashMap::new();
    fields.insert("credential_type".to_string(), json!("static"));
    fields.insert("did".to_string(), json!(did));
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{Certificate, CertificateKind};
    use crate::secrets::Secret;
    use chrono::Duration;

    /// Destructure a `Derived` outcome into `(hash, fields)`; panics otherwise.
    fn derived_parts(r: &CredentialIdentity) -> (String, HashMap<String, JsonValue>) {
        match r {
            CredentialIdentity::Derived { identity_hash, identity_fields } => {
                (identity_hash.clone(), identity_fields.clone())
            }
            _ => panic!("expected Derived, got {r:?}"),
        }
    }

    #[test]
    fn resolve_jwt_claim_identity_derives_from_oid() {
        let claims = json!({ "oid": "11111111-2222-3333-4444-555555555555", "sub": "app-123" });
        let resolved = resolve_jwt_claim_identity("oid", &[], &claims).unwrap();
        let (hash, fields) = derived_parts(&resolved);
        assert_eq!(hash.len(), 64, "identity hash is hex SHA-256");
        assert_eq!(
            fields
                .get("credential_type")
                .unwrap(),
            &json!("jwt_claim")
        );
        assert_eq!(fields.get("claim").unwrap(), &json!("oid"));
        assert_eq!(fields.get("value").unwrap(), &json!("11111111-2222-3333-4444-555555555555"));
    }

    #[test]
    fn resolve_jwt_claim_identity_is_deterministic() {
        let claims = json!({ "oid": "agent-1" });
        let a = resolve_jwt_claim_identity("oid", &[], &claims).unwrap();
        let b = resolve_jwt_claim_identity("oid", &[], &claims).unwrap();
        assert_eq!(derived_parts(&a).0, derived_parts(&b).0, "same claim → same DID hash");
    }

    #[test]
    fn resolve_jwt_claim_identity_namespaces_by_issuer() {
        let tenant_a = json!({ "oid": "shared-oid", "iss": "https://login.microsoftonline.com/aaaa/v2.0" });
        let tenant_b = json!({ "oid": "shared-oid", "iss": "https://login.microsoftonline.com/bbbb/v2.0" });
        let ns = vec!["iss".to_string()];
        let a = resolve_jwt_claim_identity("oid", &ns, &tenant_a).unwrap();
        let b = resolve_jwt_claim_identity("oid", &ns, &tenant_b).unwrap();
        assert_ne!(derived_parts(&a).0, derived_parts(&b).0, "same oid under different issuers must not collide");
        let (_, fields) = derived_parts(&a);
        assert_eq!(fields.get("ns.iss").unwrap(), &json!("https://login.microsoftonline.com/aaaa/v2.0"));
    }

    #[test]
    fn resolve_jwt_claim_identity_missing_claim_errors() {
        let claims = json!({ "sub": "app-123" });
        let err = resolve_jwt_claim_identity("oid", &[], &claims).unwrap_err();
        assert_eq!(err.classify(), CredentialIdentityErrorClass::Misconfigured);
        match err {
            CredentialIdentityError::JwtClaimMissing(c) => assert_eq!(c, "oid"),
            other => panic!("expected JwtClaimMissing, got {other:?}"),
        }
    }

    #[test]
    fn resolve_jwt_claim_identity_missing_namespace_claim_errors() {
        let claims = json!({ "oid": "agent-1" });
        let ns = vec!["tid".to_string()];
        let err = resolve_jwt_claim_identity("oid", &ns, &claims).unwrap_err();
        match err {
            CredentialIdentityError::JwtClaimMissing(c) => assert_eq!(c, "tid"),
            other => panic!("expected JwtClaimMissing(tid), got {other:?}"),
        }
    }

    #[test]
    fn resolve_jwt_claim_identity_non_string_claim_errors() {
        let claims = json!({ "oid": 12345 });
        let err = resolve_jwt_claim_identity("oid", &[], &claims).unwrap_err();
        match err {
            CredentialIdentityError::JwtClaimMissing(c) => assert_eq!(c, "oid"),
            other => panic!("expected JwtClaimMissing, got {other:?}"),
        }
    }

    fn make_secret(value: &str) -> Secret {
        Secret {
            id: "id-1".to_string(),
            tenant_id: None,
            name: "demo key".to_string(),
            secret_id: "demo-key".to_string(),
            description: None,
            value: value.to_string(),
            secret_type: "ApiKey".to_string(),
            tags: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn self_signed_pem() -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-leaf");
        let kp = KeyPair::generate().expect("keypair");
        let cert = params
            .self_signed(&kp)
            .expect("self signed");
        cert.pem()
    }

    fn make_cert(
        pem: &str,
        active: bool,
    ) -> Certificate {
        Certificate {
            id: "cert-uuid".to_string(),
            tenant_id: None,
            certificate_id: "cert-1".to_string(),
            name: "demo cert".to_string(),
            description: None,
            certificate_pem: pem.to_string(),
            private_key_pem: None,
            expires_at: None,
            identity_did: None,
            kind: CertificateKind::ClientLeaf,
            active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec![],
        }
    }

    #[tokio::test]
    async fn payload_extraction_returns_none() {
        let mi = ManagedIdentityConfig::PayloadExtraction(crate::source_auth::models::PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".into(),
            fields: vec![],
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: false,
        });
        let res = derive_credential_identity(&mi, None, None)
            .await
            .expect("ok");
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn static_did_short_circuits() {
        let mi = ManagedIdentityConfig::Static { did: "did:example:42".into() };
        let r = derive_credential_identity(&mi, None, None)
            .await
            .expect("ok")
            .expect("some");
        match r {
            CredentialIdentity::Bound { did, identity_fields } => {
                assert_eq!(did, "did:example:42");
                assert_eq!(
                    identity_fields
                        .get("credential_type")
                        .and_then(|v| v.as_str()),
                    Some("static")
                );
                assert_eq!(
                    identity_fields
                        .get("did")
                        .and_then(|v| v.as_str()),
                    Some("did:example:42")
                );
            }
            _ => panic!("expected Bound"),
        }
    }

    #[tokio::test]
    async fn static_did_rejects_invalid() {
        for bad in &["", "not-a-did", "did::id", "did:foo", "did:FOO:bar", "http://example.com"] {
            let mi = ManagedIdentityConfig::Static { did: (*bad).into() };
            let err = derive_credential_identity(&mi, None, None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, CredentialIdentityError::InvalidStaticDid(_)),
                "expected InvalidStaticDid for '{bad}', got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn from_mtls_requires_store() {
        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };
        let err = derive_credential_identity(&mi, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialIdentityError::CertificateStoreUnavailable));
        assert_eq!(err.classify(), CredentialIdentityErrorClass::BackendUnavailable);
    }

    #[tokio::test]
    async fn from_api_key_requires_store() {
        let mi = ManagedIdentityConfig::FromApiKey { api_key_id: "k-1".into() };
        let err = derive_credential_identity(&mi, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialIdentityError::SecretsStoreUnavailable));
        assert_eq!(err.classify(), CredentialIdentityErrorClass::BackendUnavailable);
    }

    #[tokio::test]
    async fn from_mtls_derives_stable_hash_across_rotation() {
        let pem1 = self_signed_pem();
        let pem2 = self_signed_pem();
        assert_ne!(pem1, pem2, "fresh self-signed certs differ");

        let resolver = CredentialIdentityResolver::new();
        let store_a: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(make_cert(&pem1, true)));
        let store_b: Arc<dyn CertificateStore> = {
            // Same certificate_id, new PEM, bumped updated_at.
            let mut c = make_cert(&pem2, true);
            c.updated_at += Duration::seconds(1);
            Arc::new(InMemoryCertStore::new(c))
        };

        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };
        let r1 = resolver
            .resolve(&mi, Some(&store_a), None)
            .await
            .unwrap()
            .unwrap();
        let r2 = resolver
            .resolve(&mi, Some(&store_b), None)
            .await
            .unwrap()
            .unwrap();

        let (h1, fp1) = unwrap_derived(&r1);
        let (h2, fp2) = unwrap_derived(&r2);
        assert_eq!(h1, h2, "rotation under same certificate_id MUST keep hash stable");
        assert_ne!(fp1, fp2, "fingerprint MUST change with PEM rotation");
    }

    #[tokio::test]
    async fn from_mtls_disabled_cert_errors() {
        let pem = self_signed_pem();
        let store: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(make_cert(&pem, false)));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };
        let err = resolver
            .resolve(&mi, Some(&store), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialIdentityError::CertificateDisabled(ref id) if id == "cert-1"));
        assert_eq!(err.classify(), CredentialIdentityErrorClass::Misconfigured);
        assert_eq!(err.reason_label(), "cert_disabled");
    }

    #[tokio::test]
    async fn from_mtls_expired_cert_errors() {
        let pem = self_signed_pem();
        let mut cert = make_cert(&pem, true);
        cert.expires_at = Some(Utc::now() - Duration::minutes(1));
        let store: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(cert));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };
        let err = resolver
            .resolve(&mi, Some(&store), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialIdentityError::CertificateExpired { .. }));
    }

    #[tokio::test]
    async fn from_mtls_wrong_kind_errors() {
        let pem = self_signed_pem();
        let mut cert = make_cert(&pem, true);
        cert.kind = CertificateKind::ServerLeaf;
        let store: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(cert));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };
        let err = resolver
            .resolve(&mi, Some(&store), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialIdentityError::CertificateWrongKind { .. }));
    }

    #[tokio::test]
    async fn from_mtls_identity_did_pinned_returns_bound() {
        let pem = self_signed_pem();
        let mut cert = make_cert(&pem, true);
        cert.identity_did = Some("did:web:pinned.example".to_string());
        let store: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(cert));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };
        let r = resolver
            .resolve(&mi, Some(&store), None)
            .await
            .unwrap()
            .unwrap();
        match r {
            CredentialIdentity::Bound { did, .. } => assert_eq!(did, "did:web:pinned.example"),
            _ => panic!("expected Bound"),
        }
    }

    #[tokio::test]
    async fn from_api_key_does_not_emit_secret_hash() {
        let secret = make_secret("super-secret-value");
        let store: Arc<dyn SecretsStore> = Arc::new(InMemorySecretsStore::new(secret));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromApiKey { api_key_id: "demo-key".into() };
        let r = resolver
            .resolve(&mi, None, Some(&store))
            .await
            .unwrap()
            .unwrap();
        match r {
            CredentialIdentity::Derived { identity_fields, .. } => {
                assert!(
                    !identity_fields.contains_key("secret_sha256"),
                    "secret_sha256 must NOT be emitted in identity_fields; was: {identity_fields:?}"
                );
                assert!(
                    identity_fields
                        .values()
                        .all(|v| v.as_str() != Some("super-secret-value")),
                    "raw secret value must never appear in fields"
                );
            }
            _ => panic!("expected Derived"),
        }
    }

    #[tokio::test]
    async fn from_api_key_hash_stable_across_secret_value_rotation() {
        // Same api_key_id, different secret value, bumped updated_at → same hash.
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromApiKey { api_key_id: "demo-key".into() };

        let s1 = make_secret("v1");
        let store_a: Arc<dyn SecretsStore> = Arc::new(InMemorySecretsStore::new(s1));
        let h1 = unwrap_derived(
            &resolver
                .resolve(&mi, None, Some(&store_a))
                .await
                .unwrap()
                .unwrap(),
        )
        .0;

        let mut s2 = make_secret("v2-rotated");
        s2.updated_at += Duration::seconds(1);
        let store_b: Arc<dyn SecretsStore> = Arc::new(InMemorySecretsStore::new(s2));
        let h2 = unwrap_derived(
            &resolver
                .resolve(&mi, None, Some(&store_b))
                .await
                .unwrap()
                .unwrap(),
        )
        .0;

        assert_eq!(h1, h2, "API key value rotation MUST NOT change the DID");
    }

    #[tokio::test]
    async fn from_api_key_resolves_by_secret_id_not_internal_id() {
        // resolve_api_key must look up by `secret_id` (user-facing),
        // NOT by `id` (internal UUID). This test would fail with `.get(api_key_id)`
        // because the ManagedIdentityConfig holds the secret_id, not the UUID.
        let secret = Secret {
            id: "internal-uuid-111".to_string(),
            tenant_id: None,
            name: "regression key".to_string(),
            secret_id: "user-facing-key".to_string(),
            description: None,
            value: "some-value".to_string(),
            secret_type: "ApiKey".to_string(),
            tags: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let store: Arc<dyn SecretsStore> = Arc::new(InMemorySecretsStore::new(secret));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromApiKey {
            api_key_id: "user-facing-key".into(),
        };

        let result = resolver
            .resolve(&mi, None, Some(&store))
            .await
            .expect("resolution must succeed when looked up by secret_id");
        let identity = result.expect("should return Some");

        match identity {
            CredentialIdentity::Derived { identity_fields, .. } => {
                assert_eq!(
                    identity_fields
                        .get("api_key_id")
                        .and_then(|v| v.as_str()),
                    Some("user-facing-key"),
                );
                assert_eq!(
                    identity_fields
                        .get("secret_id")
                        .and_then(|v| v.as_str()),
                    Some("user-facing-key"),
                );
            }
            _ => panic!("expected Derived"),
        }

        // Confirm that looking up by the internal UUID would NOT resolve:
        let mi_wrong = ManagedIdentityConfig::FromApiKey {
            api_key_id: "internal-uuid-111".into(),
        };
        let err = resolver
            .resolve(&mi_wrong, None, Some(&store))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CredentialIdentityError::SecretNotFound(ref id) if id == "internal-uuid-111"),
            "lookup by internal id must fail; got {err:?}"
        );
    }

    #[tokio::test]
    async fn cache_hit_avoids_reparse_until_updated_at_changes() {
        let pem = self_signed_pem();
        let cert = make_cert(&pem, true);
        let store: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(cert.clone()));
        let resolver = CredentialIdentityResolver::new();
        let mi = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".into(),
        };

        // First call — miss.
        let _ = resolver
            .resolve(&mi, Some(&store), None)
            .await
            .unwrap();
        assert_eq!(resolver.mtls_cache_len(), 1);
        // Second call — hit (same updated_at).
        let _ = resolver
            .resolve(&mi, Some(&store), None)
            .await
            .unwrap();
        assert_eq!(resolver.mtls_cache_len(), 1);

        // Rotate cert: same id, new PEM, bumped updated_at. Cache entry replaced.
        let pem2 = self_signed_pem();
        let mut cert2 = cert.clone();
        cert2.certificate_pem = pem2;
        cert2.updated_at = cert.updated_at + Duration::seconds(1);
        let store2: Arc<dyn CertificateStore> = Arc::new(InMemoryCertStore::new(cert2));
        let _ = resolver
            .resolve(&mi, Some(&store2), None)
            .await
            .unwrap();
        assert_eq!(resolver.mtls_cache_len(), 1, "cache replaced rather than grown");
    }

    #[test]
    fn hash_credential_is_deterministic_within_process() {
        let h1 = hash_credential(&[("credential_type", "mtls"), ("certificate_id", "abc")]);
        let h2 = hash_credential(&[("certificate_id", "abc"), ("credential_type", "mtls")]);
        assert_eq!(h1, h2, "ordering of input pairs must not affect hash");
        assert_eq!(h1.len(), 64);
        let h3 = hash_credential(&[("credential_type", "mtls"), ("certificate_id", "different")]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn validate_did_accepts_typical_methods() {
        for ok in &["did:web:example.com", "did:webvh:gateway.acme:abc", "did:key:z6Mk..."] {
            assert!(validate_did(ok).is_ok(), "should accept {ok}");
        }
    }

    fn unwrap_derived(r: &CredentialIdentity) -> (String, String) {
        match r {
            CredentialIdentity::Derived { identity_fields, identity_hash } => (
                identity_hash.clone(),
                identity_fields
                    .get("fingerprint_sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            ),
            _ => panic!("expected Derived, got {r:?}"),
        }
    }

    // ── In-memory stores ──────────────────────────────────────────────

    struct InMemoryCertStore {
        cert: Certificate,
    }
    impl InMemoryCertStore {
        fn new(cert: Certificate) -> Self {
            Self { cert }
        }
    }

    #[async_trait::async_trait]
    impl CertificateStore for InMemoryCertStore {
        async fn list_all(&self) -> Result<Vec<crate::certificates::CertificateListItem>, String> {
            Ok(vec![])
        }
        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<Certificate>, String> {
            Ok((id == self.cert.certificate_id).then(|| self.cert.clone()))
        }
        async fn create_with_ids(
            &self,
            _r: crate::certificates::CreateCertificateRequest,
            _id: String,
            _certificate_id: String,
        ) -> Result<Certificate, String> {
            unimplemented!()
        }
        async fn update(
            &self,
            _id: &str,
            _r: crate::certificates::UpdateCertificateRequest,
        ) -> Result<Certificate, String> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<(), String> {
            unimplemented!()
        }
    }

    struct InMemorySecretsStore {
        secret: Secret,
    }
    impl InMemorySecretsStore {
        fn new(secret: Secret) -> Self {
            Self { secret }
        }
    }

    #[async_trait::async_trait]
    impl SecretsStore for InMemorySecretsStore {
        async fn create(
            &self,
            _r: crate::secrets::CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok((id == self.secret.id).then(|| self.secret.clone()))
        }
        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok((secret_id == self.secret.secret_id).then(|| self.secret.clone()))
        }
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            Ok(vec![])
        }
        async fn update(
            &self,
            _id: &str,
            _r: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            Ok(vec![])
        }
    }

    // ── atgk_ fast-path tests ─────────────────────────────────────────

    #[tokio::test]
    async fn atgk_prefix_bypasses_secrets_store() {
        // atgk_-prefixed IDs must succeed even with no secrets store supplied.
        let mi = ManagedIdentityConfig::FromApiKey {
            api_key_id: "atgk_abc123def456".into(),
        };
        let r = derive_credential_identity(&mi, None, None)
            .await
            .expect("should succeed without a secrets store")
            .expect("should return Some");
        match r {
            CredentialIdentity::Derived { identity_fields, identity_hash } => {
                assert_eq!(
                    identity_fields
                        .get("api_key_id")
                        .and_then(|v| v.as_str()),
                    Some("atgk_abc123def456"),
                );
                assert_eq!(
                    identity_fields
                        .get("credential_type")
                        .and_then(|v| v.as_str()),
                    Some("api_key"),
                );
                assert_eq!(identity_hash.len(), 64, "hash must be a 64-char hex string");
            }
            _ => panic!("expected Derived"),
        }
    }

    #[tokio::test]
    async fn atgk_hash_stable_across_calls() {
        // Same api_key_id must always produce the same hash within a process.
        let mi = ManagedIdentityConfig::FromApiKey {
            api_key_id: "atgk_stable_key".into(),
        };
        let resolver = CredentialIdentityResolver::new();
        let h1 = unwrap_derived(
            &resolver
                .resolve(&mi, None, None)
                .await
                .unwrap()
                .unwrap(),
        )
        .0;
        let h2 = unwrap_derived(
            &resolver
                .resolve(&mi, None, None)
                .await
                .unwrap()
                .unwrap(),
        )
        .0;
        assert_eq!(h1, h2, "atgk_ hash must be stable across repeated calls");
    }

    #[tokio::test]
    async fn atgk_different_ids_produce_different_hashes() {
        let resolver = CredentialIdentityResolver::new();
        let h1 = unwrap_derived(
            &resolver
                .resolve(
                    &ManagedIdentityConfig::FromApiKey {
                        api_key_id: "atgk_key_a".into(),
                    },
                    None,
                    None,
                )
                .await
                .unwrap()
                .unwrap(),
        )
        .0;
        let h2 = unwrap_derived(
            &resolver
                .resolve(
                    &ManagedIdentityConfig::FromApiKey {
                        api_key_id: "atgk_key_b".into(),
                    },
                    None,
                    None,
                )
                .await
                .unwrap()
                .unwrap(),
        )
        .0;
        assert_ne!(h1, h2, "distinct atgk_ IDs must produce distinct hashes");
    }

    #[tokio::test]
    async fn non_atgk_prefix_still_requires_secrets_store() {
        // Non-atgk_ api_key_ids must still go through the secrets store path.
        let mi = ManagedIdentityConfig::FromApiKey {
            api_key_id: "sk_some-secret-ref".into(),
        };
        let err = derive_credential_identity(&mi, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CredentialIdentityError::SecretsStoreUnavailable),
            "non-atgk_ IDs must require a secrets store; got {err:?}"
        );
    }
}
