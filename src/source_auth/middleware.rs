//! Unified source authentication middleware
//!
//! [`SourceAuthMiddleware`] is the single integration point called by every request
//! handler that needs source authentication. It dispatches to the appropriate
//! authentication backend based on the channel's `SourceAuthConfig`.

use std::sync::Arc;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, error, info, warn};

use crate::a2a::auth::{SecretsCache, get_cached_secret};
use crate::api_keys::ApiKeyValidator;
use crate::certificates::CertificateStore;
use crate::didauth::sessions::{DidAuthSessionStore, SessionView};
use crate::jwt_bearer::{
    JwksClient, JwtBearerVerifier, JwtVerificationStrategyStorage, errors::JwtBearerError, models::JwtBearerAuthConfig,
};
use crate::secrets::SecretsStore;
use crate::source_auth::errors::{SourceAuthError, SourceAuthResult};
use crate::source_auth::models::{AuthenticatedIdentity, CredentialExtraction, PeerCertInfo, SourceAuthConfig};
use crate::source_auth::mtls::{ResolvedTrustMaterial, TrustEntry, verify_peer_cert};

pub const SURFACE_AGENT_DID_AUDIENCE: &str = "{{ surface.agent_did }}";

/// The audiences a surface's caller authentication accepts on the route
/// called. The direct path and Fabric receive both resolve them here, so the
/// protected resource the route publishes, if any, is the only audience either
/// path accepts.
pub async fn resolve_surface_audience(
    config: &SourceAuthConfig,
    protected_resource: Option<&crate::protocols::protected_resource::ProtectedResourceConfig>,
    vc_issuer: Option<&crate::identity::VCIssuer>,
    surface_id: &str,
) -> SourceAuthResult<SourceAuthConfig> {
    if let Some(protected_resource) = protected_resource {
        return Ok(protected_resource.bind_audience(config.clone()));
    }
    let SourceAuthConfig::JwtBearer(jwt_config) = config else {
        return Ok(config.clone());
    };
    if !jwt_config
        .audiences
        .iter()
        .any(|audience| audience == SURFACE_AGENT_DID_AUDIENCE)
    {
        return Ok(config.clone());
    }

    let vc_issuer = vc_issuer.ok_or_else(|| SourceAuthError::Internal {
        reason: "VC issuer is unavailable for surface audience resolution".to_string(),
    })?;
    let records = vc_issuer
        .get_identity_store()
        .list_all()
        .await
        .map_err(|error| SourceAuthError::Internal {
            reason: format!("Failed to resolve surface agent DID: {error}"),
        })?;
    let agent_did =
        select_surface_agent_did(records, surface_id).ok_or_else(|| SourceAuthError::InvalidCredential {
            reason: "Surface agent DID is not initialized".to_string(),
        })?;

    let mut resolved = jwt_config.clone();
    for audience in &mut resolved.audiences {
        if audience == SURFACE_AGENT_DID_AUDIENCE {
            *audience = agent_did.clone();
        }
    }
    Ok(SourceAuthConfig::JwtBearer(resolved))
}

fn select_surface_agent_did(
    records: Vec<crate::identity::filesystem::AgentIdentityRecord>,
    surface_id: &str,
) -> Option<String> {
    records
        .into_iter()
        .filter(|record| {
            record.is_local
                && (record
                    .channel_config_id
                    .as_deref()
                    == Some(surface_id)
                    || record
                        .channel_usage
                        .iter()
                        .any(|usage| usage.channel_config_id == surface_id))
        })
        .max_by_key(|record| record.last_used_at)
        .map(|record| record.did)
}

/// Per-cert cache entry: PEM-decoded DER bytes + SHA-256 fingerprint,
/// keyed by the certificate's `updated_at` timestamp so that out-of-band
/// edits self-invalidate without an explicit cache flush.
#[derive(Clone)]
struct CachedTrustEntry {
    updated_at: DateTime<Utc>,
    der: Arc<Vec<u8>>,
    fingerprint: [u8; 32],
}

/// Unified source authentication gate.
///
/// Holds references to all authentication backends and dispatches based on
/// the channel's `SourceAuthConfig`.
#[derive(Clone)]
pub struct SourceAuthMiddleware {
    jwt_strategy_store: Arc<dyn JwtVerificationStrategyStorage>,
    jwt_verifier: Arc<JwtBearerVerifier>,
    secrets_store: Option<Arc<dyn SecretsStore>>,
    secrets_cache: SecretsCache,
    api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
    didauth_store: Arc<DidAuthSessionStore>,
    cert_store: Option<Arc<dyn CertificateStore>>,
    /// Per-cert cache for mTLS trust material; see [`CachedTrustEntry`].
    trust_cache: Arc<DashMap<String, CachedTrustEntry>>,
}

/// Return the installed middleware, or an internal (non-caller) error when a
/// surface requires source authentication but none is installed.
pub fn require_installed(middleware: Option<Arc<SourceAuthMiddleware>>) -> SourceAuthResult<Arc<SourceAuthMiddleware>> {
    middleware.ok_or_else(|| SourceAuthError::Internal {
        reason: "source authentication is not initialised".to_string(),
    })
}

impl SourceAuthMiddleware {
    /// Create a new middleware instance.
    pub fn new(
        didauth_store: Arc<DidAuthSessionStore>,
        jwt_strategy_store: Arc<dyn JwtVerificationStrategyStorage>,
        jwks_client: Arc<JwksClient>,
        secrets_store: Option<Arc<dyn SecretsStore>>,
        secrets_cache: SecretsCache,
        api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
        cert_store: Option<Arc<dyn CertificateStore>>,
    ) -> Self {
        let jwt_verifier = Arc::new(JwtBearerVerifier::new(jwks_client));
        Self {
            jwt_strategy_store,
            jwt_verifier,
            secrets_store,
            secrets_cache,
            api_key_validator,
            didauth_store,
            cert_store,
            trust_cache: Arc::new(DashMap::new()),
        }
    }

    /// Return the underlying JWT strategy store (used by the CRUD router).
    pub fn provider_store(&self) -> Arc<dyn JwtVerificationStrategyStorage> {
        Arc::clone(&self.jwt_strategy_store)
    }

    /// Return the underlying JWKS client (used by the validate-jwks-uri endpoint).
    pub fn jwks_client(&self) -> Arc<JwksClient> {
        Arc::clone(
            &self
                .jwt_verifier
                .jwks_client(),
        )
    }

    /// Authenticate an inbound request against the given source auth configuration.
    ///
    /// Dispatches to the appropriate backend and returns the authenticated identity.
    ///
    /// `peer_cert` is the (optional) client certificate captured by the
    /// listener layer. Required for mTLS auth; ignored otherwise.
    ///
    /// `view` is the authoritative surface and variant currently being
    /// authenticated against. It is only consulted by DID Auth (to reject
    /// session tokens minted for a different surface or another view of this
    /// one) - other auth methods ignore it. Callers should always pass
    /// `state.surface.surface_id` and the variant serving the request.
    pub async fn authenticate(
        &self,
        config: &SourceAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
        view: SessionView<'_>,
        peer_cert: Option<&PeerCertInfo>,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        match config {
            SourceAuthConfig::JwtBearer(jwt_config) => {
                self.authenticate_jwt_bearer(jwt_config, headers, channel_name)
                    .await
            }
            SourceAuthConfig::ApiKey(apikey_config) => {
                self.authenticate_apikey(apikey_config, headers, channel_name)
                    .await
            }
            SourceAuthConfig::ApiKeyProvider(provider_config) => {
                self.authenticate_apikey_provider(provider_config, headers, channel_name)
                    .await
            }
            SourceAuthConfig::DidAuth(didauth_config) => {
                self.authenticate_didauth(didauth_config, headers, channel_name, view)
                    .await
            }
            SourceAuthConfig::Mtls(mtls_config) => {
                self.authenticate_mtls(mtls_config, peer_cert, channel_name)
                    .await
            }
        }
    }

    // ── JWT Bearer ──────────────────────────────────────────────────────────

    async fn authenticate_jwt_bearer(
        &self,
        config: &JwtBearerAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        // 1. Extract bearer token from the configured header / scheme. A value in
        // another scheme, such as an MPP `Payment` credential, is not a token. A
        // value under another spelling of the header, `_` for `-`, counts as a
        // second token, since some servers read both spellings as one.
        if headers
            .iter()
            .filter(|(name, value)| {
                crate::config::target_auth_rules::same_header_name(name.as_str(), &config.token_header)
                    && in_token_scheme(value.as_bytes(), &config.token_scheme)
            })
            .count()
            > 1
        {
            return Err(SourceAuthError::InvalidCredential {
                reason: "More than one bearer token".to_string(),
            });
        }
        let header_value = headers
            .get(config.token_header.as_str())
            .and_then(|v| v.to_str().ok());
        let token = crate::jwt_bearer::validator::extract_bearer_with_scheme(header_value, &config.token_scheme)
            .map_err(SourceAuthError::from)?;

        // 2. Resolve strategy
        let jwt_strategy = self
            .jwt_strategy_store
            .get(&config.jwt_verification_strategy_id)
            .await
            .map_err(|e| JwtBearerError::Storage(e.to_string()))
            .map_err(SourceAuthError::from)?
            .ok_or_else(|| {
                SourceAuthError::from(JwtBearerError::StrategyNotFound(
                    config
                        .jwt_verification_strategy_id
                        .clone(),
                ))
            })?;

        let principal_claim = jwt_strategy
            .principal_claim_name()
            .map_err(SourceAuthError::from)?
            .to_string();

        // 3. Verify
        let claims = self
            .jwt_verifier
            .validate(token, &jwt_strategy, &config.audiences, config.audience_claim)
            .await
            .map_err(SourceAuthError::from)?;
        let subject = claims
            .get(principal_claim.as_str())
            .and_then(|v| v.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("<none>")
            .to_string();

        info!(
            surface = %channel_name,
            strategy_id = %config.jwt_verification_strategy_id,
            "JWT Bearer source authentication succeeded"
        );

        Ok(AuthenticatedIdentity::JwtBearer {
            subject,
            principal_claim,
            claims,
        })
    }

    // ── API Key (SecretsStore) ─────────────────────────────────────────────

    async fn authenticate_apikey(
        &self,
        config: &crate::source_auth::models::ApiKeyAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        let key_value =
            extract_credential(&config.extraction, headers).ok_or_else(|| SourceAuthError::MissingCredential {
                reason: "API key not found in request".to_string(),
            })?;

        let valid_keys = get_cached_secret(&config.secret_id, &self.secrets_store, &self.secrets_cache)
            .await
            .map_err(|e| {
                // Log the detail internally (secret_id, underlying cause) but never
                // surface it to the caller — doing so leaks internal secret identifiers.
                tracing::warn!(
                    surface = %channel_name,
                    error = %e,
                    "Failed to load API key secret for source auth"
                );
                SourceAuthError::Internal {
                    reason: "Authentication configuration error".to_string(),
                }
            })?;

        for valid in &valid_keys {
            if constant_time_compare(&key_value, valid) {
                info!(
                    surface = %channel_name,
                    secret_id = %config.secret_id,
                    "API Key source authentication succeeded"
                );
                return Ok(AuthenticatedIdentity::ApiKey {
                    key_name: config.secret_id.clone(),
                    provider_agent_id: None,
                });
            }
        }

        Err(SourceAuthError::InvalidCredential {
            reason: "API key not found or inactive".to_string(),
        })
    }

    // ── API Key Provider ────────────────────────────────────────────────────

    async fn authenticate_apikey_provider(
        &self,
        config: &crate::source_auth::models::ApiKeyProviderAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        let key_value =
            extract_credential(&config.extraction, headers).ok_or_else(|| SourceAuthError::MissingCredential {
                reason: "API key not found in request".to_string(),
            })?;

        let store = self
            .api_key_validator
            .as_ref()
            .ok_or_else(|| SourceAuthError::Internal {
                reason: "API Key Provider not configured".to_string(),
            })?;

        match store
            .validate(&config.agent_id, &key_value)
            .await
        {
            Ok(Some(meta)) => {
                info!(
                    surface = %channel_name,
                    agent_id = %config.agent_id,
                    key_id = %meta.key_id,
                    "API Key Provider source authentication succeeded"
                );
                Ok(AuthenticatedIdentity::ApiKey {
                    key_name: meta.key_id,
                    provider_agent_id: Some(config.agent_id.clone()),
                })
            }
            Ok(None) => {
                debug!(channel = %channel_name, agent_id = %config.agent_id, "API key not found or revoked");
                Err(SourceAuthError::InvalidCredential {
                    reason: "API key not found or revoked".to_string(),
                })
            }
            Err(e) => {
                error!(channel = %channel_name, agent_id = %config.agent_id, error = %e, "API key validation failed");
                Err(SourceAuthError::Internal {
                    reason: format!("API key validation failed: {e}"),
                })
            }
        }
    }

    // ── DID Auth ────────────────────────────────────────────────────────────

    async fn authenticate_didauth(
        &self,
        config: &crate::source_auth::models::DidAuthAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
        view: SessionView<'_>,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        let session_token =
            extract_credential(&config.extraction, headers).ok_or_else(|| SourceAuthError::MissingCredential {
                reason: "DID Auth session token not found in request".to_string(),
            })?;

        let session = self
            .didauth_store
            .get_session(&session_token)
            .await
            .ok_or_else(|| SourceAuthError::InvalidCredential {
                reason: "DID Auth session not found or expired".to_string(),
            })?;

        // Reject cross-surface and cross-view session replay: a token minted
        // for surface A must not authenticate against surface B, nor one
        // minted on a variant at the base surface or another variant, whose
        // `allowed_dids` may differ, even if the client presents it. Empty
        // `session.surface_id` catches legacy on-disk records predating the
        // binding and forces callers to re-mint.
        if !view.minted(&session) {
            warn!(
                surface = %channel_name,
                current_surface_id = %view.surface_id,
                current_variant_id = view.variant_id,
                bound_surface_id = %session.surface_id,
                bound_variant_id = session.variant_id.as_deref(),
                did = %session.did,
                "DID Auth session bound to a different surface or variant - rejecting"
            );
            return Err(SourceAuthError::InvalidCredential {
                reason: "DID Auth session not bound to this surface".to_string(),
            });
        }

        // The allow-list is the view's as it is now, not as it was when the
        // session was minted: a DID added to no list, or removed from one,
        // since then is refused on every use, as it would be at the challenge.
        if !config.allowed_dids.is_empty()
            && !config
                .allowed_dids
                .iter()
                .any(|allowed| allowed.trim() == session.did)
        {
            warn!(
                surface = %channel_name,
                did = %session.did,
                "DID Auth session's DID is not in the surface's allowed_dids - rejecting"
            );
            return Err(SourceAuthError::InvalidCredential {
                reason: "DID Auth session not bound to this surface".to_string(),
            });
        }

        // However long the session was stored for, it authenticates no longer
        // than the longest lifetime after it was minted.
        if chrono::Utc::now()
            > session.created_at
                + chrono::Duration::seconds(
                    crate::source_auth::models::DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS as i64,
                )
        {
            return Err(SourceAuthError::InvalidCredential {
                reason: "DID Auth session not found or expired".to_string(),
            });
        }

        info!(
            surface = %channel_name,
            did = %session.did,
            "DID Auth source authentication succeeded"
        );

        Ok(AuthenticatedIdentity::DidAuth { did: session.did })
    }

    // ── mTLS ────────────────────────────────────────────────────────────────

    async fn authenticate_mtls(
        &self,
        config: &crate::source_auth::models::MtlsAuthConfig,
        peer_cert: Option<&PeerCertInfo>,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        // The listener layer must have captured a peer certificate (direct
        // TLS handshake or trusted forwarded-cert header). If none is
        // present, surface a credential-missing error rather than an
        // internal error so the caller returns 401.
        let Some(peer) = peer_cert else {
            debug!(channel = %channel_name, "mTLS auth required but no client certificate was presented");
            track_mtls_failure(channel_name, "missing_cert");
            return Err(SourceAuthError::MissingCredential {
                reason: "Client certificate not presented".to_string(),
            });
        };

        let cert_store = self
            .cert_store
            .as_ref()
            .ok_or_else(|| SourceAuthError::Internal {
                reason: "mTLS auth configured but certificate store is unavailable".to_string(),
            })?;

        // Resolve the certificate IDs referenced by the trust config into
        // pre-hashed [`TrustEntry`] values. Hot path is a DashMap lookup;
        // PEM decode + SHA-256 happen at most once per (cert_id, updated_at).
        let (pinned, ca) = match &config.trust {
            crate::source_auth::models::MtlsTrust::Pinned { certificate_ids } => {
                let entries = self
                    .resolve_trust_entries(cert_store.as_ref(), certificate_ids)
                    .await?;
                (entries, Vec::new())
            }
            crate::source_auth::models::MtlsTrust::Ca { ca_certificate_ids, .. } => {
                let entries = self
                    .resolve_trust_entries(cert_store.as_ref(), ca_certificate_ids)
                    .await?;
                (Vec::new(), entries)
            }
        };

        let trust = ResolvedTrustMaterial { pinned: &pinned, ca: &ca };

        match verify_peer_cert(peer, config, trust, std::time::SystemTime::now()) {
            Ok(identity) => {
                if let AuthenticatedIdentity::Mtls {
                    principal, fingerprint, source, ..
                } = &identity
                {
                    info!(
                        surface = %channel_name,
                        principal = %principal,
                        fingerprint = %fingerprint,
                        source = %source,
                        "mTLS source authentication succeeded"
                    );
                    track_mtls_success(channel_name, *source);
                }
                Ok(identity)
            }
            Err(e) => {
                debug!(
                    surface = %channel_name,
                    error = %e,
                    "mTLS source authentication failed"
                );
                track_mtls_failure(channel_name, mtls_failure_reason(&e));
                Err(e)
            }
        }
    }

    /// Resolve a list of certificate IDs against the store, returning
    /// pre-decoded DER + pre-computed SHA-256 fingerprint per cert.
    /// Inactive certs are treated as missing. Uses the internal
    /// [`Self::trust_cache`] keyed by `cert.updated_at` to avoid
    /// re-parsing PEM on every request.
    async fn resolve_trust_entries(
        &self,
        store: &dyn CertificateStore,
        ids: &[String],
    ) -> SourceAuthResult<Vec<TrustEntry>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let cert = store
                .get(id)
                .await
                .map_err(|e| SourceAuthError::Internal {
                    reason: format!("Failed to load certificate '{id}': {e}"),
                })?
                .ok_or_else(|| SourceAuthError::ConfigNotFound { id: id.clone() })?;
            if !cert.active {
                return Err(SourceAuthError::ConfigNotFound { id: id.clone() });
            }

            // Cache hit: same updated_at as what we have.
            if let Some(existing) = self.trust_cache.get(id)
                && existing.updated_at == cert.updated_at
            {
                out.push(TrustEntry {
                    id: id.clone(),
                    der: Arc::clone(&existing.der),
                    fingerprint: existing.fingerprint,
                });
                continue;
            }

            // Miss or stale: decode + hash, populate cache.
            let der = decode_pem_certificate(
                cert.certificate_pem
                    .as_bytes(),
            )
            .map_err(|e| SourceAuthError::Internal {
                reason: format!("Failed to decode certificate '{id}': {e}"),
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&der);
            let fingerprint: [u8; 32] = hasher.finalize().into();
            let der_arc = Arc::new(der);
            self.trust_cache.insert(
                id.clone(),
                CachedTrustEntry {
                    updated_at: cert.updated_at,
                    der: Arc::clone(&der_arc),
                    fingerprint,
                },
            );
            out.push(TrustEntry {
                id: id.clone(),
                der: der_arc,
                fingerprint,
            });
        }
        Ok(out)
    }
}

/// Decode the first CERTIFICATE block from PEM bytes into DER.
fn decode_pem_certificate(pem_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem_bytes).map_err(|e| format!("PEM parse error: {e}"))?;
    if parsed.label != "CERTIFICATE" {
        return Err(format!("Expected PEM tag 'CERTIFICATE', got '{}'", parsed.label));
    }
    Ok(parsed.contents)
}

/// Map a [`SourceAuthError`] returned by mTLS verification to a low-
/// cardinality label suitable for the `reason` metric label.
fn mtls_failure_reason(err: &SourceAuthError) -> &'static str {
    match err {
        SourceAuthError::MissingCredential { .. } => "missing_cert",
        SourceAuthError::InvalidCredential { reason } => {
            if reason.contains("chain verification") {
                "chain_invalid"
            } else if reason.contains("pinned") {
                "pinned_mismatch"
            } else if reason.contains("allowed_subjects") {
                "not_allowed"
            } else if reason.contains("Forwarded") {
                "forwarded_disallowed"
            } else if reason.contains("EKU") {
                "missing_eku"
            } else if reason.contains("identity binding") {
                "binding_failed"
            } else {
                "invalid_cert"
            }
        }
        SourceAuthError::AmbiguousCredentials => "ambiguous_credentials",
        SourceAuthError::ConfigNotFound { .. } => "trust_misconfigured",
        SourceAuthError::Internal { .. } => "internal_error",
    }
}

fn track_mtls_success(
    channel_name: &str,
    source: crate::source_auth::models::PeerCertSource,
) {
    crate::metrics::backends::prometheus::_track_auth_attempt(channel_name, "mtls", source.as_str());
}

fn track_mtls_failure(
    channel_name: &str,
    reason: &str,
) {
    crate::metrics::backends::prometheus::_track_auth_attempt(channel_name, "mtls", "failure");
    crate::metrics::backends::prometheus::_track_auth_failure(channel_name, "mtls", reason);
}

// ── Credential extraction helper ────────────────────────────────────────────

/// Extract a credential string from the request based on the extraction configuration.
fn extract_credential(
    extraction: &CredentialExtraction,
    headers: &HeaderMap,
) -> Option<String> {
    match extraction {
        CredentialExtraction::HttpHeader { field } => headers
            .get(field.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        // `McpMeta` and `A2aExtension` require body parsing, which this
        // helper does not perform.
        CredentialExtraction::McpMeta | CredentialExtraction::A2aExtension => None,
    }
}

/// Whether a token header value is in `scheme`, compared ignoring case as HTTP
/// authentication schemes are. With no scheme, every value is a token.
fn in_token_scheme(
    value: &[u8],
    scheme: &str,
) -> bool {
    scheme.is_empty()
        || value
            .split(u8::is_ascii_whitespace)
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case(scheme.as_bytes()))
}

fn constant_time_compare(
    left: &str,
    right: &str,
) -> bool {
    left.as_bytes()
        .ct_eq(right.as_bytes())
        .into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_keys::{ApiKeyIssuer, ApiKeyMeta, ApiKeyResult, ApiKeyStatus};
    use crate::didauth::sessions::DidAuthSessionStore;
    use crate::jwt_bearer::{
        JwksClient,
        models::{JwksSource, JwtBearerAuthConfig, JwtVerificationStrategy},
        storage::JwtVerificationStrategyStorage,
        test_utils::start_jwks_server,
    };
    use crate::secrets::Secret;
    use crate::source_auth::errors::SourceAuthError;
    use crate::source_auth::models::*;
    use async_trait::async_trait;
    use axum::http::{HeaderMap, HeaderValue};
    use chrono::Utc;
    use dashmap::DashMap;
    use jsonwebtoken::{Algorithm, EncodingKey, Header as JwtHeader, encode};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;

    fn identity_record(
        did: &str,
        surface_id: &str,
        last_used_at: chrono::DateTime<Utc>,
        is_local: bool,
    ) -> crate::identity::filesystem::AgentIdentityRecord {
        crate::identity::filesystem::AgentIdentityRecord {
            identity_hash: did.to_string(),
            did: did.to_string(),
            created_at: last_used_at,
            identity_fields: HashMap::new(),
            usage_count: 1,
            last_used_at: Some(last_used_at),
            channel_usage: vec![crate::identity::filesystem::ChannelUsage {
                channel_config_id: surface_id.to_string(),
                usage_count: 1,
                last_used_at,
                role: None,
            }],
            private_key: None,
            channel_config_id: Some(surface_id.to_string()),
            is_local,
            verified: true,
            origin: None,
        }
    }

    #[test]
    fn surface_agent_did_selects_latest_local_identity_for_surface() {
        let earlier = Utc::now() - chrono::Duration::minutes(1);
        let later = Utc::now();
        let records = vec![
            identity_record("did:webvh:old", "shop-agent", earlier, true),
            identity_record("did:webvh:other", "other-surface", later, true),
            identity_record("did:webvh:external", "shop-agent", later, false),
            identity_record("did:webvh:current", "shop-agent", later, true),
        ];

        assert_eq!(select_surface_agent_did(records, "shop-agent").as_deref(), Some("did:webvh:current"));
    }

    #[test]
    fn surface_agent_did_requires_matching_surface() {
        let records = vec![identity_record("did:webvh:other", "other-surface", Utc::now(), true)];

        assert_eq!(select_surface_agent_did(records, "shop-agent"), None);
    }

    #[tokio::test]
    async fn a_published_protected_resource_is_the_only_audience_accepted() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            audiences: vec![SURFACE_AGENT_DID_AUDIENCE.to_string(), "https://other.example/mcp".to_string()],
            audience_claim: crate::jwt_bearer::models::AudienceClaim::ClientId,
            ..Default::default()
        });
        let protected =
            crate::protocols::protected_resource::fixtures::protected_resource("https://gateway.example/mcp/alpha");

        let resolved = resolve_surface_audience(&config, Some(&protected), None, "alpha")
            .await
            .expect("bind the protected resource");

        let SourceAuthConfig::JwtBearer(resolved) = resolved else {
            panic!("expected JWT bearer config");
        };
        assert_eq!(resolved.audiences, vec!["https://gateway.example/mcp/alpha"]);
        assert_eq!(resolved.audience_claim, crate::jwt_bearer::models::AudienceClaim::Aud);
    }

    // ── In-memory Secrets Store ─────────────────────────────────────────────

    struct InMemorySecretsStore {
        secrets: RwLock<HashMap<String, Secret>>,
    }

    impl InMemorySecretsStore {
        fn new() -> Self {
            Self {
                secrets: RwLock::new(HashMap::new()),
            }
        }

        async fn add_secret(
            &self,
            secret_id: &str,
            value: &str,
        ) {
            let secret = Secret {
                id: uuid::Uuid::new_v4().to_string(),
                tenant_id: None,
                name: secret_id.to_string(),
                secret_id: secret_id.to_string(),
                description: None,
                value: value.to_string(),
                secret_type: "ApiKey".to_string(),
                tags: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.secrets
                .write()
                .await
                .insert(secret_id.to_string(), secret);
        }
    }

    #[async_trait]
    impl SecretsStore for InMemorySecretsStore {
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            Ok(self
                .secrets
                .read()
                .await
                .values()
                .cloned()
                .map(Into::into)
                .collect())
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok(self
                .secrets
                .read()
                .await
                .values()
                .find(|s| s.id == id || s.secret_id == id)
                .cloned())
        }
        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok(self
                .secrets
                .read()
                .await
                .get(secret_id)
                .cloned())
        }
        async fn create(
            &self,
            _request: crate::secrets::CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }
        async fn update(
            &self,
            _id: &str,
            _request: crate::secrets::UpdateSecretRequest,
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
            unimplemented!()
        }
    }

    // ── In-memory API Key Validator ─────────────────────────────────────────

    struct InMemoryApiKeyValidator {
        keys: RwLock<HashMap<(String, String), ApiKeyMeta>>,
    }

    impl InMemoryApiKeyValidator {
        fn new() -> Self {
            Self {
                keys: RwLock::new(HashMap::new()),
            }
        }

        async fn add_key(
            &self,
            agent_id: &str,
            key_value: &str,
            key_id: &str,
        ) {
            let meta = ApiKeyMeta {
                key_id: key_id.to_string(),
                agent_id: agent_id.to_string(),
                client_id: "test-client".to_string(),
                status: ApiKeyStatus::Active,
                created_at: Utc::now(),
                revoked_at: None,
                last_used_at: None,
                labels: HashMap::new(),
                issuer: ApiKeyIssuer {
                    actor: "test".to_string(),
                    method: "api".to_string(),
                },
                rotated_from: None,
                needs_rotation: false,
            };
            self.keys
                .write()
                .await
                .insert((agent_id.to_string(), key_value.to_string()), meta);
        }
    }

    #[async_trait]
    impl ApiKeyValidator for InMemoryApiKeyValidator {
        async fn validate(
            &self,
            agent_id: &str,
            presented_key: &str,
        ) -> ApiKeyResult<Option<ApiKeyMeta>> {
            Ok(self
                .keys
                .read()
                .await
                .get(&(agent_id.to_string(), presented_key.to_string()))
                .cloned())
        }
    }

    // ── In-memory JWT Strategy Store ────────────────────────────────────────

    struct InMemoryStrategyStore {
        strategies: RwLock<HashMap<String, JwtVerificationStrategy>>,
    }

    impl InMemoryStrategyStore {
        fn new() -> Self {
            Self {
                strategies: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl JwtVerificationStrategyStorage for InMemoryStrategyStore {
        async fn create(
            &self,
            mut strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            strategy.id = uuid::Uuid::new_v4().to_string();
            self.strategies
                .write()
                .await
                .insert(strategy.id.clone(), strategy.clone());
            Ok(strategy)
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            Ok(self
                .strategies
                .read()
                .await
                .get(id)
                .cloned())
        }
        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            Ok(self
                .strategies
                .read()
                .await
                .values()
                .cloned()
                .collect())
        }
        async fn update(
            &self,
            strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            self.strategies
                .write()
                .await
                .insert(strategy.id.clone(), strategy.clone());
            Ok(strategy)
        }
        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.strategies
                .write()
                .await
                .remove(id);
            Ok(())
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn build_middleware(
        secrets_store: Option<Arc<dyn SecretsStore>>,
        api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
        didauth_store: Arc<DidAuthSessionStore>,
        strategy_store: Arc<dyn JwtVerificationStrategyStorage>,
        jwks_client: Arc<JwksClient>,
    ) -> SourceAuthMiddleware {
        let secrets_cache: SecretsCache = Arc::new(DashMap::new());
        SourceAuthMiddleware::new(
            didauth_store,
            strategy_store,
            jwks_client,
            secrets_store,
            secrets_cache,
            api_key_validator,
            None,
        )
    }

    #[test]
    fn require_installed_without_middleware_is_a_server_error() {
        let error = match require_installed(None) {
            Err(error) => error,
            Ok(_) => panic!("a missing middleware must not authenticate"),
        };

        assert!(matches!(error, SourceAuthError::Internal { .. }));
        assert!(!error.is_caller_attributable());
    }

    #[test]
    fn require_installed_returns_the_installed_middleware() {
        let (_, didauth, strategies) = default_stores();
        let middleware = Arc::new(build_middleware(None, None, didauth, strategies, default_jwks_client()));

        let resolved = require_installed(Some(middleware.clone())).expect("installed middleware");

        assert!(Arc::ptr_eq(&resolved, &middleware));
    }

    fn default_jwks_client() -> Arc<JwksClient> {
        Arc::new(JwksClient::new())
    }

    fn default_stores() -> (Arc<InMemorySecretsStore>, Arc<DidAuthSessionStore>, Arc<InMemoryStrategyStore>) {
        (
            Arc::new(InMemorySecretsStore::new()),
            Arc::new(DidAuthSessionStore::new()),
            Arc::new(InMemoryStrategyStore::new()),
        )
    }

    fn test_didauth_config(header_field: &str) -> DidAuthAuthConfig {
        DidAuthAuthConfig {
            extraction: CredentialExtraction::HttpHeader {
                field: header_field.to_string(),
            },
            allowed_dids: vec![],
            challenge_ttl_seconds: None,
            session_ttl_seconds: None,
            audience: None,
            allowed_algorithms: vec![],
        }
    }

    // ── API Key (SecretsStore) tests ────────────────────────────────────────

    #[tokio::test]
    async fn valid_apikey_returns_apikey_identity() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("my-secret", "secret-123")
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("secret-123"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "my-secret".to_string(),
                provider_agent_id: None,
            }
        );
    }

    #[tokio::test]
    async fn valid_apikey_comma_separated_returns_apikey_identity() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("my-secret", "key-a,key-b,key-c")
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("key-b"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "my-secret".to_string(),
                provider_agent_id: None,
            }
        );
    }

    #[tokio::test]
    async fn missing_apikey_header_returns_missing_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let headers = HeaderMap::new();
        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn invalid_apikey_returns_invalid_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("my-secret", "secret-123")
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("wrong-key"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    // ── API Key Provider tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn valid_apikey_provider_returns_apikey_identity() {
        let (_, didauth_store, strategy_store) = default_stores();
        let validator = Arc::new(InMemoryApiKeyValidator::new());
        validator
            .add_key("agent-1", "provider-key-123", "key-id-1")
            .await;

        let mw = build_middleware(None, Some(validator), didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKeyProvider(ApiKeyProviderAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            agent_id: "agent-1".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("provider-key-123"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "key-id-1".to_string(),
                provider_agent_id: Some("agent-1".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn invalid_apikey_provider_returns_invalid_credential() {
        let (_, didauth_store, strategy_store) = default_stores();
        let validator = Arc::new(InMemoryApiKeyValidator::new());

        let mw = build_middleware(None, Some(validator), didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKeyProvider(ApiKeyProviderAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            agent_id: "agent-1".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("bad-key"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    // ── DID Auth tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_session_returns_didauth_identity() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let (session_id, _) = didauth_store
            .create_session(
                "did:example:123".to_string(),
                "test-channel".to_string(),
                SessionView::base("test-surface-id"),
                3600,
            )
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&session_id).unwrap());

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::DidAuth {
                did: "did:example:123".to_string()
            }
        );
    }

    #[tokio::test]
    async fn missing_session_header_returns_missing_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let headers = HeaderMap::new();
        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn unknown_session_returns_invalid_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_static("nonexistent-token"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn expired_session_returns_invalid_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        // Create a session with 0 second TTL — it expires immediately
        let (session_id, _) = didauth_store
            .create_session(
                "did:example:expired".to_string(),
                "test-channel".to_string(),
                SessionView::base("test-surface-id"),
                0,
            )
            .await;

        // Small delay to ensure expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&session_id).unwrap());

        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    /// A session minted for surface A must not authenticate against surface
    /// B. Cross-surface replay would otherwise bypass B's per-surface
    /// `allowed_dids` / `audience` constraints.
    #[tokio::test]
    async fn session_bound_to_other_surface_is_rejected() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let (session_on_a, _) = didauth_store
            .create_session(
                "did:example:alice".to_string(),
                "surface-a".to_string(),
                SessionView::base("surface-a-id"),
                3600,
            )
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&session_on_a).unwrap());

        // Presenting A's session token against surface B must fail closed.
        let result = mw
            .authenticate(&config, &headers, "surface-b", SessionView::base("surface-b-id"), None)
            .await;
        let err = result.expect_err("cross-surface session must be rejected");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");

        // Sanity check: the same token is still valid against surface A.
        let ok = mw
            .authenticate(&config, &headers, "surface-a", SessionView::base("surface-a-id"), None)
            .await;
        assert!(ok.is_ok(), "same-surface reuse must still work");
    }

    /// The DID Auth settings of a view whose callers may list `allowed`.
    fn listing(allowed: &[&str]) -> SourceAuthConfig {
        let mut config = test_didauth_config("X-Session-Token");
        config.allowed_dids = allowed
            .iter()
            .map(|did| did.to_string())
            .collect();
        SourceAuthConfig::DidAuth(config)
    }

    /// A session goes on authenticating only while `allowed_dids`, as the view
    /// serving the request has it now, names its DID: one minted while the
    /// list was empty, which admits any DID, is refused once a list that does
    /// not name it is added, and one whose DID is removed from the list is
    /// refused from then on.
    #[tokio::test]
    async fn a_session_authenticates_only_while_the_allow_list_names_its_did() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();
        let view = SessionView::base("surface-a-id");
        let (mallory, _) = didauth_store
            .create_session("did:example:mallory".into(), "surface-a".into(), view, 3600)
            .await;
        let (bob, _) = didauth_store
            .create_session("did:example:bob".into(), "surface-a".into(), view, 3600)
            .await;
        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let presenting = |session_id: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("X-Session-Token", HeaderValue::from_str(session_id).unwrap());
            headers
        };

        let open = listing(&[]);
        assert!(
            mw.authenticate(&open, &presenting(&mallory), "surface-a", view, None)
                .await
                .is_ok(),
            "an empty allow-list admits any DID"
        );
        let alice_only = listing(&["did:example:alice"]);
        let err = mw
            .authenticate(&alice_only, &presenting(&mallory), "surface-a", view, None)
            .await
            .expect_err("a session minted while the list was empty is refused once a list leaves its DID out");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "{err:?}");

        let alice_and_bob = listing(&["did:example:alice", " did:example:bob "]);
        assert!(
            mw.authenticate(&alice_and_bob, &presenting(&bob), "surface-a", view, None)
                .await
                .is_ok(),
            "a listed DID's session authenticates"
        );
        let err = mw
            .authenticate(&alice_only, &presenting(&bob), "surface-a", view, None)
            .await
            .expect_err("a session whose DID was removed from the list is refused");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "{err:?}");
    }

    /// A session authenticates only at the view it was minted on: one minted
    /// on a variant is refused at the base surface and at another variant,
    /// and one minted on the base at a variant, even where that view's
    /// `allowed_dids` name its DID.
    #[tokio::test]
    async fn a_session_minted_on_one_view_is_refused_at_another() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();
        let base = SessionView::base("surface-a-id");
        let variant = SessionView {
            surface_id: "surface-a-id",
            variant_id: Some("variant-1"),
        };
        let other_variant = SessionView {
            surface_id: "surface-a-id",
            variant_id: Some("variant-2"),
        };
        let (on_the_variant, _) = didauth_store
            .create_session("did:example:mallory".into(), "surface-a".into(), variant, 3600)
            .await;
        let (on_the_base, _) = didauth_store
            .create_session("did:example:mallory".into(), "surface-a".into(), base, 3600)
            .await;
        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let config = listing(&["did:example:mallory"]);
        let presenting = |session_id: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("X-Session-Token", HeaderValue::from_str(session_id).unwrap());
            headers
        };

        for (case, session, view) in [
            ("minted on a variant, replayed on the base", &on_the_variant, base),
            ("minted on a variant, replayed on another variant", &on_the_variant, other_variant),
            ("minted on the base, replayed on a variant", &on_the_base, variant),
        ] {
            let err = mw
                .authenticate(&config, &presenting(session), "surface-a", view, None)
                .await
                .expect_err(case);
            assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "{case}: {err:?}");
        }
        for (session, view) in [(&on_the_variant, variant), (&on_the_base, base)] {
            assert!(
                mw.authenticate(&config, &presenting(session), "surface-a", view, None)
                    .await
                    .is_ok(),
                "a session authenticates at the view it was minted on"
            );
        }
    }

    /// No session authenticates longer than
    /// [`DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS`] after it was minted,
    /// whatever expiry it was stored with.
    #[tokio::test]
    async fn a_session_never_authenticates_past_the_longest_lifetime() {
        use crate::didauth::sessions::DidAuthSession;

        let (secrets_store, didauth_store, strategy_store) = default_stores();
        let minted =
            chrono::Utc::now() - chrono::Duration::seconds(DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS as i64 + 60);
        let session_id = "long-lived-token";
        let session = DidAuthSession {
            session_id_hash: crate::storage::filesystem::token_storage_id(session_id),
            did: "did:example:alice".to_string(),
            channel_name: "surface-a".to_string(),
            surface_id: "surface-a-id".to_string(),
            variant_id: None,
            created_at: minted,
            expires_at: chrono::Utc::now() + chrono::Duration::days(30),
            challenge: None,
        };
        didauth_store
            .insert_for_test(session)
            .await;
        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(session_id).unwrap());

        let err = mw
            .authenticate(&listing(&[]), &headers, "surface-a", SessionView::base("surface-a-id"), None)
            .await
            .expect_err("a session past the longest lifetime is refused");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "{err:?}");
    }

    /// Legacy on-disk sessions written before the surface_id binding was
    /// added deserialise with an empty `surface_id` — reject them so a
    /// resurrected old session cannot bypass the new invariant.
    #[tokio::test]
    async fn legacy_session_without_surface_binding_is_rejected() {
        use crate::didauth::sessions::DidAuthSession;

        let (secrets_store, didauth_store, strategy_store) = default_stores();

        // Fabricate a legacy session record (surface_id empty).
        let session_id = "legacy-token-xyz";
        let legacy = DidAuthSession {
            session_id_hash: crate::storage::filesystem::token_storage_id(session_id),
            did: "did:example:legacy".to_string(),
            channel_name: "some-old-channel".to_string(),
            surface_id: String::new(),
            variant_id: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            challenge: None,
        };
        didauth_store
            .insert_for_test(legacy)
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(session_id).unwrap());

        let result = mw
            .authenticate(&config, &headers, "any-surface", SessionView::base("any-surface-id"), None)
            .await;
        let err = result.expect_err("legacy unbound session must be rejected");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }));
    }

    // ── mTLS test ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mtls_missing_peer_cert_returns_missing_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::Mtls(crate::source_auth::models::MtlsAuthConfig {
            trust: crate::source_auth::models::MtlsTrust::Pinned {
                certificate_ids: vec!["cert-1".to_string()],
            },
            identity_binding: crate::source_auth::models::MtlsIdentityBinding::Fingerprint,
            allowed_subjects: Vec::new(),
            allow_forwarded: true,
        });

        let headers = HeaderMap::new();
        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    // ── JWT Bearer tests ────────────────────────────────────────────────────

    // Ed25519 test key pair — PKCS#8 format
    // Generated with: openssl genpkey -algorithm ED25519
    const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPiOVQaSEcxl/NogGyUAX88ouBy1bWJFMp4gi0pcCgcY
-----END PRIVATE KEY-----";

    // Base64url-encoded 32-byte Ed25519 public key (the `x` component for JWK)
    const ED25519_JWK_X: &str = "xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU";

    fn ed25519_jwks_body(
        kid: &str,
        x: &str,
    ) -> String {
        format!(
            r#"{{"keys":[{{"kty":"OKP","kid":"{kid}","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"{x}"}}]}}"#,
            kid = kid,
            x = x,
        )
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_token(
        claims: serde_json::Value,
        kid: &str,
    ) -> String {
        let mut header = JwtHeader::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token)).unwrap());
        map
    }

    async fn jwt_test_setup() -> (
        SourceAuthMiddleware,
        String, // strategy_id
        crate::jwt_bearer::test_utils::TestServer,
    ) {
        jwt_test_setup_naming(None).await
    }

    async fn jwt_test_setup_naming(
        principal_claim: Option<&str>
    ) -> (
        SourceAuthMiddleware,
        String, // strategy_id
        crate::jwt_bearer::test_utils::TestServer,
    ) {
        let kid = "source-auth-test-key";
        let (base, server) = start_jwks_server(ed25519_jwks_body(kid, ED25519_JWK_X), Some(3600)).await;

        let strategy_store = Arc::new(InMemoryStrategyStore::new());
        let strategy = strategy_store
            .create(JwtVerificationStrategy {
                principal_claim: principal_claim.map(str::to_string),
                id: String::new(),
                tenant_id: None,
                name: "Test EdDSA IdP".to_string(),
                expected_issuer: "https://issuer.example.com".to_string(),
                jwks_source: JwksSource::Remote {
                    jwks_uri: format!("{}/.well-known/jwks.json", base),
                },
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();

        let jwks_client = Arc::new(JwksClient::new());
        let (secrets_store, didauth_store, _) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, jwks_client);

        (mw, strategy.id, server)
    }

    #[tokio::test]
    async fn valid_jwt_returns_jwt_bearer_identity() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;

        let exp = now_secs() + 3600;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": exp,
                "iat": now_secs(),
            }),
            kid,
        );

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let identity = result.expect("should succeed");
        match identity {
            AuthenticatedIdentity::JwtBearer { subject, claims, .. } => {
                assert_eq!(subject, "user-1");
                assert_eq!(
                    claims
                        .get("iss")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "https://issuer.example.com"
                );
                assert_eq!(
                    claims
                        .get("aud")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "my-audience"
                );
            }
            other => panic!("expected JwtBearer identity, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_strategy_that_names_a_principal_claim_identifies_the_caller_by_it() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup_naming(Some("oid")).await;
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });
        let token_with = |claims: serde_json::Value| {
            let mut base = json!({
                "iss": "https://issuer.example.com",
                "sub": "pairwise-sub",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            });
            base.as_object_mut()
                .unwrap()
                .extend(
                    claims
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            make_token(base, kid)
        };

        let with_oid = token_with(json!({ "oid": "00000000-0000-0000-0000-0000000000aa" }));
        let identity = mw
            .authenticate(&config, &bearer(&with_oid), "test-channel", SessionView::base("surface"), None)
            .await
            .expect("a token with the claim authenticates");
        match &identity {
            AuthenticatedIdentity::JwtBearer { subject, principal_claim, .. } => {
                assert_eq!(subject, "00000000-0000-0000-0000-0000000000aa");
                assert_eq!(principal_claim, "oid");
            }
            _ => panic!("expected a JwtBearer identity"),
        }
        assert_eq!(
            identity
                .principal_hash(Some("tenant-1"))
                .as_deref(),
            crate::source_auth::models::jwt_caller_identity_hash(
                "https://issuer.example.com",
                Some("tenant-1"),
                "00000000-0000-0000-0000-0000000000aa",
                "oid"
            )
            .as_deref()
        );

        let without_oid = token_with(json!({}));
        let identity = mw
            .authenticate(&config, &bearer(&without_oid), "test-channel", SessionView::base("surface"), None)
            .await
            .expect("the token is valid; it just names no caller");
        assert_eq!(identity.principal_hash(None), None, "a token without the claim names no caller");

        let empty = token_with(json!({ "oid": "" }));
        let identity = mw
            .authenticate(&config, &bearer(&empty), "test-channel", SessionView::base("surface"), None)
            .await
            .unwrap();
        assert_eq!(identity.principal(), "<none>", "an empty claim reaches policy as the placeholder");
        assert_eq!(identity.principal_key(), "jwt:<none>");

        let numeric = token_with(json!({ "oid": 7 }));
        let identity = mw
            .authenticate(&config, &bearer(&numeric), "test-channel", SessionView::base("surface"), None)
            .await
            .unwrap();
        assert_eq!(identity.principal_hash(None), None, "a claim that is not a string names no caller");
    }

    #[tokio::test]
    async fn a_strategy_stored_with_a_claim_the_api_refuses_authenticates_nobody() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup_naming(Some("iss")).await;
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
        );
        let error = mw
            .authenticate(&config, &bearer(&token), "test-channel", SessionView::base("surface"), None)
            .await
            .expect_err("a strategy naming iss identifies nobody");
        assert!(matches!(error, SourceAuthError::Internal { .. }), "{error}");
        assert!(!error.is_caller_attributable(), "the strategy, not the caller, is at fault");
    }

    #[tokio::test]
    async fn missing_bearer_header_returns_missing_credential() {
        let (_mw, strategy_id, _server) = jwt_test_setup().await;

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = HeaderMap::new();
        let result = _mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn expired_jwt_returns_invalid_credential() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;

        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() - 3600, // expired 1 hour ago
                "iat": now_secs() - 7200,
            }),
            kid,
        );

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn unknown_strategy_returns_config_not_found() {
        let kid = "source-auth-test-key";
        let (mw, _strategy_id, _server) = jwt_test_setup().await;

        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
        );

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "nonexistent-strategy".to_string(),
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::ConfigNotFound { .. }), "expected ConfigNotFound, got: {err:?}");
    }

    #[tokio::test]
    async fn invalid_jwt_returns_invalid_credential() {
        let (_mw, strategy_id, _server) = jwt_test_setup().await;

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_static("Bearer not.a.valid.jwt"));

        let result = _mw
            .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn a_second_value_in_the_token_scheme_fails_and_one_in_another_scheme_does_not() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
        );
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        for (case, second, verifies) in [
            ("a second Bearer value", format!("Bearer {token}"), false),
            ("a lower-case bearer value", "bearer other".to_string(), false),
            ("a Payment value", "Payment credential".to_string(), true),
        ] {
            let mut headers = bearer(&token);
            headers.append(axum::http::header::AUTHORIZATION, HeaderValue::from_str(&second).unwrap());
            let result = mw
                .authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
                .await;
            if verifies {
                assert!(
                    matches!(&result, Ok(AuthenticatedIdentity::JwtBearer { subject, .. }) if subject == "user-1"),
                    "{case}"
                );
            } else {
                assert!(matches!(result, Err(SourceAuthError::InvalidCredential { .. })), "{case}");
            }
        }
    }

    #[tokio::test]
    async fn a_second_token_under_another_spelling_of_the_token_header_fails() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
        );
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            token_header: "X-User-Token".to_string(),
            forward_header: true,
            ..Default::default()
        });
        let authenticate = |headers: HeaderMap| {
            let mw = &mw;
            let config = &config;
            async move {
                mw.authenticate(config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
                    .await
            }
        };
        let valid = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-user-token", valid.clone());
        headers.insert("x_user_token", HeaderValue::from_static("Bearer other"));
        let result = authenticate(headers).await;
        assert!(matches!(result, Err(SourceAuthError::InvalidCredential { .. })), "{result:?}");

        let mut headers = HeaderMap::new();
        headers.insert("x_user_token", valid.clone());
        let result = authenticate(headers).await;
        assert!(matches!(result, Err(SourceAuthError::MissingCredential { .. })), "{result:?}");

        let mut headers = HeaderMap::new();
        headers.insert("x-user-token", valid);
        let result = authenticate(headers).await;
        assert!(
            matches!(&result, Ok(AuthenticatedIdentity::JwtBearer { subject, .. }) if subject == "user-1"),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn authorization_header_value_preserved() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;

        let exp = now_secs() + 3600;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-2",
                "aud": "my-audience",
                "exp": exp,
                "iat": now_secs(),
            }),
            kid,
        );
        let raw_header = format!("Bearer {}", token);
        let headers = bearer(&token);

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        mw.authenticate(&config, &headers, "test-channel", SessionView::base("test-surface-id"), None)
            .await
            .expect("should succeed");

        let forwarded = headers
            .get(axum::http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(forwarded, raw_header);
    }

    // ── Credential extraction unit tests ────────────────────────────────────

    #[test]
    fn extract_http_header_finds_value() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Custom", HeaderValue::from_static("my-value"));

        let extraction = CredentialExtraction::HttpHeader { field: "X-Custom".to_string() };
        let result = extract_credential(&extraction, &headers);
        assert_eq!(result, Some("my-value".to_string()));
    }

    #[test]
    fn extract_http_header_returns_none_when_missing() {
        let headers = HeaderMap::new();

        let extraction = CredentialExtraction::HttpHeader { field: "X-Custom".to_string() };
        let result = extract_credential(&extraction, &headers);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_mcp_meta_returns_none() {
        let headers = HeaderMap::new();
        let result = extract_credential(&CredentialExtraction::McpMeta, &headers);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_a2a_extension_returns_none() {
        let headers = HeaderMap::new();
        let result = extract_credential(&CredentialExtraction::A2aExtension, &headers);
        assert_eq!(result, None);
    }
}
