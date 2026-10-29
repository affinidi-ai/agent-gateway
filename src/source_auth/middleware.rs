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
use crate::didauth::sessions::DidAuthSessionStore;
use crate::jwt_bearer::{
    JwksClient, JwtBearerVerifier, JwtVerificationStrategyStorage, access_token, errors::JwtBearerError,
    models::JwtBearerAuthConfig,
};
use crate::secrets::SecretsStore;
use crate::source_auth::errors::{SourceAuthError, SourceAuthResult};
use crate::source_auth::models::{AuthenticatedIdentity, CredentialExtraction, PeerCertInfo, SourceAuthConfig};
use crate::source_auth::mtls::{ResolvedTrustMaterial, TrustEntry, verify_peer_cert};

pub const SURFACE_AGENT_DID_AUDIENCE: &str = "{{ surface.agent_did }}";

/// The audiences a surface's caller authentication accepts on the route
/// called. The direct path and Fabric receive both resolve them here, so the
/// resource a declaring route publishes, if any, is the only audience either
/// path accepts.
pub async fn resolve_surface_audience(
    config: &SourceAuthConfig,
    declaration: Option<&crate::source_auth::declaration::Declaration>,
    vc_issuer: Option<&crate::identity::VCIssuer>,
    surface_id: &str,
) -> SourceAuthResult<SourceAuthConfig> {
    if let Some(declaration) = declaration {
        return Ok(match config {
            SourceAuthConfig::JwtBearer(jwt_config) => {
                SourceAuthConfig::JwtBearer(declaration.bind_audience(jwt_config))
            }
            other => other.clone(),
        });
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

/// Refuse a verified token that does not grant every `required_scopes` entry.
///
/// An Access Point that requires scopes expects access tokens, so a token shaped as
/// an ID token fails as invalid before its scopes are read.
fn check_required_scopes(
    config: &JwtBearerAuthConfig,
    token: &str,
    claims: &serde_json::Value,
    scope_claims: &[String],
) -> SourceAuthResult<()> {
    if config
        .required_scopes
        .is_empty()
    {
        return Ok(());
    }
    access_token::check_access_token_shape(token, claims)?;
    let granted = access_token::granted_scopes(claims, scope_claims);
    let missing: Vec<String> = access_token::missing_scopes(&granted, &config.required_scopes)
        .into_iter()
        .map(str::to_string)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(SourceAuthError::InsufficientScope { missing })
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
    /// `surface_id` is the authoritative identifier of the surface currently
    /// being authenticated against. It is only consulted by DID Auth (to
    /// reject session tokens minted for a different surface) — other auth
    /// methods ignore it. Callers should always pass `state.surface.surface_id`.
    pub async fn authenticate(
        &self,
        config: &SourceAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
        surface_id: &str,
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
                self.authenticate_didauth(didauth_config, headers, channel_name, surface_id)
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
        // 1. Extract bearer token from the configured header / scheme
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

        // 3. Verify
        let claims = self
            .jwt_verifier
            .validate(token, &jwt_strategy, &config.audiences)
            .await
            .map_err(SourceAuthError::from)?;

        // 4. Access Point rules, kept out of `validate`, which other flows share
        let scope_claims = jwt_strategy.effective_scope_claims();
        check_required_scopes(config, token, &claims, &scope_claims)?;

        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string();

        info!(
            surface = %channel_name,
            subject = %subject,
            "JWT Bearer source authentication succeeded"
        );

        Ok(AuthenticatedIdentity::JwtBearer {
            subject,
            claims,
            strategy: Some(crate::source_auth::models::VerifyingStrategy {
                id: jwt_strategy.id,
                tenant_id: jwt_strategy.tenant_id,
                scope_claims,
            }),
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
                Ok(AuthenticatedIdentity::ApiKey { key_name: meta.key_id })
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
        surface_id: &str,
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

        // Reject cross-surface session replay: a token minted for surface A
        // must not authenticate against surface B, even if the client
        // presents it. Empty `session.surface_id` catches legacy on-disk
        // records predating the binding and forces callers to re-mint.
        if session.surface_id.is_empty() || session.surface_id != surface_id {
            warn!(
                surface = %channel_name,
                current_surface_id = %surface_id,
                bound_surface_id = %session.surface_id,
                did = %session.did,
                "DID Auth session bound to a different surface — rejecting"
            );
            return Err(SourceAuthError::InvalidCredential {
                reason: "DID Auth session not bound to this surface".to_string(),
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
        SourceAuthError::ConfigNotFound { .. } => "trust_misconfigured",
        SourceAuthError::Internal { .. } | SourceAuthError::InsufficientScope { .. } => "internal_error",
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

    fn declaration(resource: &str) -> crate::source_auth::declaration::Declaration {
        crate::source_auth::declaration::Declaration {
            resource: resource.to_string(),
            authorization_servers: vec!["https://as.example".to_string()],
            required_scopes: vec![],
            advertised_scopes: vec![],
            pin: None,
        }
    }

    #[tokio::test]
    async fn binding_the_declared_resource_keeps_the_required_scopes() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strategy-1".to_string(),
            audiences: vec!["https://other.example/mcp".to_string()],
            required_scopes: vec!["tools:call".to_string(), "read".to_string()],
            ..Default::default()
        });

        let resolved =
            resolve_surface_audience(&config, Some(&declaration("https://gateway.example/mcp/alpha")), None, "alpha")
                .await
                .expect("bind the declared resource");

        let SourceAuthConfig::JwtBearer(resolved) = resolved else {
            panic!("expected JWT bearer config");
        };
        assert_eq!(resolved.audiences, vec!["https://gateway.example/mcp/alpha"]);
        assert_eq!(resolved.required_scopes, vec!["tools:call", "read"]);
        assert_eq!(resolved.jwt_verification_strategy_id, "strategy-1");
    }

    #[tokio::test]
    async fn a_declared_resource_is_the_only_audience_accepted() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            audiences: vec![SURFACE_AGENT_DID_AUDIENCE.to_string(), "https://other.example/mcp".to_string()],
            ..Default::default()
        });

        let resolved =
            resolve_surface_audience(&config, Some(&declaration("https://gateway.example/mcp/alpha")), None, "alpha")
                .await
                .expect("bind the declared resource");

        let SourceAuthConfig::JwtBearer(resolved) = resolved else {
            panic!("expected JWT bearer config");
        };
        assert_eq!(resolved.audiences, vec!["https://gateway.example/mcp/alpha"]);
    }

    #[tokio::test]
    async fn without_a_declaration_the_configured_audiences_are_kept() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            audiences: vec!["https://other.example/mcp".to_string(), "my-audience".to_string()],
            ..Default::default()
        });

        let resolved = resolve_surface_audience(&config, None, None, "alpha")
            .await
            .expect("keep the configured audiences");

        let SourceAuthConfig::JwtBearer(resolved) = resolved else {
            panic!("expected JWT bearer config");
        };
        assert_eq!(resolved.audiences, vec!["https://other.example/mcp", "my-audience"]);
    }

    #[tokio::test]
    async fn a_declaration_leaves_a_method_without_audiences_unchanged() {
        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let resolved =
            resolve_surface_audience(&config, Some(&declaration("https://gateway.example/mcp/alpha")), None, "alpha")
                .await
                .expect("keep the api key method");

        assert_eq!(resolved, config);
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "my-secret".to_string()
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "my-secret".to_string()
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "key-id-1".to_string()
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    // ── DID Auth tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_session_returns_didauth_identity() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        let session = didauth_store
            .create_session(
                "did:example:123".to_string(),
                "test-channel".to_string(),
                "test-surface-id".to_string(),
                3600,
            )
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&session.session_id).unwrap());

        let result = mw
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn expired_session_returns_invalid_credential() {
        let (secrets_store, didauth_store, strategy_store) = default_stores();

        // Create a session with 0 second TTL — it expires immediately
        let session = didauth_store
            .create_session(
                "did:example:expired".to_string(),
                "test-channel".to_string(),
                "test-surface-id".to_string(),
                0,
            )
            .await;

        // Small delay to ensure expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&session.session_id).unwrap());

        let result = mw
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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

        let session_on_a = didauth_store
            .create_session("did:example:alice".to_string(), "surface-a".to_string(), "surface-a-id".to_string(), 3600)
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&session_on_a.session_id).unwrap());

        // Presenting A's session token against surface B must fail closed.
        let result = mw
            .authenticate(&config, &headers, "surface-b", "surface-b-id", None)
            .await;
        let err = result.expect_err("cross-surface session must be rejected");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");

        // Sanity check: the same token is still valid against surface A.
        let ok = mw
            .authenticate(&config, &headers, "surface-a", "surface-a-id", None)
            .await;
        assert!(ok.is_ok(), "same-surface reuse must still work");
    }

    /// Legacy on-disk sessions written before the surface_id binding was
    /// added deserialise with an empty `surface_id` — reject them so a
    /// resurrected old session cannot bypass the new invariant.
    #[tokio::test]
    async fn legacy_session_without_surface_binding_is_rejected() {
        use crate::didauth::sessions::DidAuthSession;

        let (secrets_store, didauth_store, strategy_store) = default_stores();

        // Fabricate a legacy session record (surface_id empty).
        let legacy = DidAuthSession {
            session_id: "legacy-token-xyz".to_string(),
            did: "did:example:legacy".to_string(),
            channel_name: "some-old-channel".to_string(),
            surface_id: String::new(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            challenge: None,
        };
        didauth_store
            .insert_for_test(legacy.clone())
            .await;

        let mw = build_middleware(Some(secrets_store), None, didauth_store, strategy_store, default_jwks_client());
        let config = SourceAuthConfig::DidAuth(test_didauth_config("X-Session-Token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-Session-Token", HeaderValue::from_str(&legacy.session_id).unwrap());

        let result = mw
            .authenticate(&config, &headers, "any-surface", "any-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
        make_typed_token(claims, kid, None)
    }

    fn make_typed_token(
        claims: serde_json::Value,
        kid: &str,
        typ: Option<&str>,
    ) -> String {
        let mut header = JwtHeader::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        header.typ = typ.map(str::to_string);
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
        jwt_test_setup_with(|_| {}).await
    }

    async fn jwt_test_setup_with(
        customise: impl FnOnce(&mut JwtVerificationStrategy)
    ) -> (SourceAuthMiddleware, String, crate::jwt_bearer::test_utils::TestServer) {
        let kid = "source-auth-test-key";
        let (base, server) = start_jwks_server(ed25519_jwks_body(kid, ED25519_JWK_X), Some(3600)).await;

        let strategy_store = Arc::new(InMemoryStrategyStore::new());
        let mut strategy = JwtVerificationStrategy {
            name: "Test EdDSA IdP".to_string(),
            expected_issuer: "https://issuer.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: format!("{}/.well-known/jwks.json", base),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ..Default::default()
        };
        customise(&mut strategy);
        let strategy = strategy_store
            .create(strategy)
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
            jwt_verification_strategy_id: strategy_id.clone(),
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let identity = result.expect("should succeed");
        match identity {
            AuthenticatedIdentity::JwtBearer { subject, claims, strategy } => {
                assert_eq!(
                    strategy,
                    Some(crate::source_auth::models::VerifyingStrategy {
                        id: strategy_id.clone(),
                        tenant_id: None,
                        scope_claims: vec!["scope".to_string(), "scp".to_string()],
                    })
                );
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
    async fn jwt_identity_names_the_verifying_strategy_its_tenant_and_scope_claims() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup_with(|strategy| {
            strategy.tenant_id = Some("tenant-a".to_string());
            strategy.scope_claims = Some(vec!["roles".to_string()]);
        })
        .await;
        let token = make_typed_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "client-1",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
            Some("at+jwt"),
        );
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id.clone(),
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let identity = mw
            .authenticate(&config, &bearer(&token), "test-channel", "test-surface-id", None)
            .await
            .expect("should succeed");
        let AuthenticatedIdentity::JwtBearer { subject, strategy, .. } = identity else {
            panic!("expected JwtBearer identity, got: {identity:?}");
        };
        assert_eq!(subject, "client-1");
        assert_eq!(
            strategy,
            Some(crate::source_auth::models::VerifyingStrategy {
                id: strategy_id.clone(),
                tenant_id: Some("tenant-a".to_string()),
                scope_claims: vec!["roles".to_string()],
            })
        );

        let wrong_audience = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["other-audience".to_string()],
            ..Default::default()
        });
        assert!(matches!(
            mw.authenticate(&wrong_audience, &bearer(&token), "test-channel", "test-surface-id", None)
                .await,
            Err(SourceAuthError::InvalidCredential { .. })
        ));
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let err = result.expect_err("should fail");
        assert!(
            matches!(&err, SourceAuthError::ConfigNotFound { id } if id == "nonexistent-strategy"),
            "expected ConfigNotFound, got: {err:?}"
        );
        assert!(!err.is_caller_attributable());
        assert_eq!(err.to_string(), "Auth config not found: nonexistent-strategy");
        assert_eq!(err.public_detail(), crate::source_auth::errors::CONFIG_NOT_FOUND_DETAIL);
        assert!(
            !err.public_detail()
                .contains("nonexistent-strategy")
        );
    }

    #[tokio::test]
    async fn a_request_without_a_token_is_a_missing_credential_even_when_the_strategy_is_gone() {
        let (mw, _strategy_id, _server) = jwt_test_setup().await;
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "nonexistent-strategy".to_string(),
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let err = mw
            .authenticate(&config, &HeaderMap::new(), "test-channel", "test-surface-id", None)
            .await
            .expect_err("no token");

        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
        assert!(
            !err.public_detail()
                .contains("nonexistent-strategy")
        );
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
            .authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
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

        mw.authenticate(&config, &headers, "test-channel", "test-surface-id", None)
            .await
            .expect("should succeed");

        let forwarded = headers
            .get(axum::http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(forwarded, raw_header);
    }

    // ── Required scopes ─────────────────────────────────────────────────────

    const ACCESS_POINT_URL: &str = "https://gw.example/agents/billing";

    fn scoped_config(
        strategy_id: String,
        required: &[&str],
    ) -> SourceAuthConfig {
        SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec![ACCESS_POINT_URL.to_string()],
            required_scopes: required
                .iter()
                .map(|scope| scope.to_string())
                .collect(),
            ..Default::default()
        })
    }

    fn access_token(extra: serde_json::Value) -> serde_json::Value {
        let mut claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "client-1",
            "aud": ACCESS_POINT_URL,
            "exp": now_secs() + 3600,
            "iat": now_secs(),
        });
        for (name, value) in extra
            .as_object()
            .expect("object")
        {
            claims[name] = value.clone();
        }
        claims
    }

    async fn authenticate_token(
        mw: &SourceAuthMiddleware,
        config: &SourceAuthConfig,
        token: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        mw.authenticate(config, &bearer(token), "test-channel", "test-surface-id", None)
            .await
    }

    #[tokio::test]
    async fn required_scopes_granted_as_scope_or_scp_string_or_array_authenticate() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup_with(|strategy| {
            strategy.tenant_id = Some("tenant-a".to_string());
        })
        .await;
        let config = scoped_config(strategy_id.clone(), &["a2a:invoke", "read"]);

        for grant in [
            json!({"scope": "read a2a:invoke extra"}),
            json!({"scope": ["a2a:invoke", "read"]}),
            json!({"scp": "a2a:invoke read"}),
            json!({"scp": ["read", "a2a:invoke"]}),
        ] {
            let token = make_typed_token(access_token(grant.clone()), kid, Some("at+jwt"));
            match authenticate_token(&mw, &config, &token).await {
                Ok(AuthenticatedIdentity::JwtBearer { subject, strategy, .. }) => {
                    assert_eq!(subject, "client-1");
                    assert_eq!(
                        strategy,
                        Some(crate::source_auth::models::VerifyingStrategy {
                            id: strategy_id.clone(),
                            tenant_id: Some("tenant-a".to_string()),
                            scope_claims: vec!["scope".to_string(), "scp".to_string()],
                        })
                    );
                }
                other => panic!("{grant}: expected JwtBearer identity, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn required_scopes_shortfall_is_insufficient_scope() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;
        let config = scoped_config(strategy_id, &["a2a:invoke", "read"]);

        for (grant, missing) in [
            (json!({"scope": "read"}), vec!["a2a:invoke"]),
            (json!({"scp": ["other"]}), vec!["a2a:invoke", "read"]),
            (json!({}), vec!["a2a:invoke", "read"]),
            (json!({"scope": 42, "scp": "a2a:invoke read"}), vec!["a2a:invoke", "read"]),
        ] {
            let token = make_token(access_token(grant.clone()), kid);
            match authenticate_token(&mw, &config, &token).await {
                Err(SourceAuthError::InsufficientScope { missing: reported }) => {
                    assert_eq!(reported, missing, "{grant}")
                }
                other => panic!("{grant}: expected InsufficientScope, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn required_scopes_read_the_strategy_scope_claims() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup_with(|strategy| {
            strategy.scope_claims = Some(vec!["roles".to_string()]);
        })
        .await;
        let config = scoped_config(strategy_id, &["Task.Run"]);

        let app_only = make_token(access_token(json!({"roles": ["Task.Run"]})), kid);
        let AuthenticatedIdentity::JwtBearer { subject, .. } = authenticate_token(&mw, &config, &app_only)
            .await
            .expect("the roles claim grants the scope")
        else {
            panic!("expected JwtBearer identity");
        };
        assert_eq!(subject, "client-1");

        let scp_only = make_token(access_token(json!({"scp": "Task.Run"})), kid);
        match authenticate_token(&mw, &config, &scp_only).await {
            Err(SourceAuthError::InsufficientScope { missing }) => assert_eq!(missing, vec!["Task.Run"]),
            other => panic!("expected InsufficientScope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn google_id_token_for_the_access_point_audience_is_refused_when_scopes_are_required() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup_with(|strategy| {
            strategy.expected_issuer = "https://accounts.google.com".to_string();
        })
        .await;
        let id_token = make_typed_token(
            json!({
                "iss": "https://accounts.google.com",
                "aud": ACCESS_POINT_URL,
                "azp": "attacker@other-project.iam.gserviceaccount.com",
                "email": "attacker@other-project.iam.gserviceaccount.com",
                "email_verified": true,
                "sub": "112233445566778899000",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
            Some("JWT"),
        );

        let scoped = scoped_config(strategy_id.clone(), &["a2a:invoke"]);
        match authenticate_token(&mw, &scoped, &id_token).await {
            Err(error) => assert_eq!(
                error.failure_kind(),
                Some(crate::source_auth::errors::SourceAuthFailureKind::InsufficientScope)
            ),
            Ok(identity) => panic!("a Google ID token must not authenticate, got {identity:?}"),
        }

        let unscoped = scoped_config(strategy_id, &[]);
        assert!(
            authenticate_token(&mw, &unscoped, &id_token)
                .await
                .is_ok(),
            "an Access Point without required scopes keeps today's acceptance"
        );
    }

    #[tokio::test]
    async fn id_token_shapes_are_invalid_when_scopes_are_required() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;
        let scoped = scoped_config(strategy_id.clone(), &["read"]);
        let unscoped = scoped_config(strategy_id, &[]);

        for (claims, typ) in [
            (access_token(json!({"scope": "read", "nonce": "n-1"})), Some("JWT")),
            (access_token(json!({"scope": "read", "at_hash": "h"})), None),
            (access_token(json!({"scope": "read"})), Some("id+jwt")),
        ] {
            let token = make_typed_token(claims.clone(), kid, typ);
            assert!(
                matches!(
                    authenticate_token(&mw, &scoped, &token).await,
                    Err(SourceAuthError::InvalidCredential { .. })
                ),
                "{claims} {typ:?}"
            );
            assert!(
                authenticate_token(&mw, &unscoped, &token)
                    .await
                    .is_ok(),
                "{claims} {typ:?}"
            );
        }

        let rfc9068 = make_typed_token(access_token(json!({"scope": "read"})), kid, Some("application/at+jwt"));
        assert!(
            authenticate_token(&mw, &scoped, &rfc9068)
                .await
                .is_ok()
        );
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
