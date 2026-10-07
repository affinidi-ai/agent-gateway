//! STS HTTP surface: the RFC 8693 / RFC 7523 token endpoint, RFC 8414 discovery,
//! and the JWKS endpoint — plus the ports the endpoint depends on.
//!
//! The endpoint depends on three ports so the whole flow is unit-testable with
//! mocks (no live crypto or key material):
//! - [`StsSigner`] — issue (`iss`) and sign JWTs; production impl [`VcIssuerSigner`].
//! - [`StsSubjectVerifier`] — verify a JWT-shaped assertion; production impl
//!   [`JwtBearerSubjectVerifier`] (reuses `src/jwt_bearer`).
//! - [`StsClientRegistry`] — authenticate a client and load its managed
//!   connection; [`InMemoryStsClientRegistry`] for now (a persistent store lands
//!   with the dashboard in a later phase).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Form;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};

use crate::identity::VCIssuer;
use crate::sts::errors::StsError;
use crate::sts::id_jag::{IdJagParams, build_id_jag_claims, validate_id_jag};
use crate::sts::policy::{AllowAllPolicyEvaluator, GatewayPolicyEvaluator, StsPolicyEvaluator, build_policy_input};
use crate::sts::token_exchange::{
    AccessTokenParams, build_access_token_claims, ceiling_scopes, compose_delegation_chain, effective_ttl,
    extract_subject_and_act, parse_scope, resolve_scopes, validate_token_exchange,
};
use crate::sts::trust_check::{DisabledTrustChecker, ListenerTrustChecker, StsTrustChecker};
use crate::sts::types::{
    BEARER, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_TOKEN_EXCHANGE, ID_JAG_JWT_TYP, TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_ID_JAG, TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT, TOKEN_TYPE_N_A, TOKEN_TYPE_VP, TokenEndpointForm,
    TokenExchangeResponse, TokenType,
};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Runtime tuning for the STS.
#[derive(Debug, Clone)]
pub struct StsConfig {
    /// Default access-token TTL when the request does not constrain it.
    pub default_ttl_secs: u64,
    /// Hard cap on any issued access-token TTL.
    pub max_ttl_secs: u64,
    /// TTL for an issued ID-JAG (kept short — it is a single-use grant).
    pub id_jag_ttl_secs: u64,
    /// The gateway's configured public base URL (from the inbound listener
    /// `external_urls`). When set, RFC 8414 discovery advertises absolute
    /// endpoints under this origin — the only reliable source behind a
    /// terminating HTTP proxy/tunnel that rewrites `Host` to `127.0.0.1` and
    /// drops forwarding headers. `None` ⇒ derive from the request.
    pub public_base_url: Option<String>,
    /// Replay-protection backend name (see `crate::sts::replay`). Defaults to the
    /// built-in in-process backend.
    pub replay_backend: String,
    /// Token-endpoint throttle configuration.
    pub throttle: crate::config::types::TokenEndpointThrottleConfig,
    pub mcp_issuer: Option<crate::sts::mcp_profile::McpIssuerProfile>,
    pub mcp_replay: Option<Arc<crate::sts::replay::McpReplay>>,
}

impl Default for StsConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 300,
            max_ttl_secs: 900,
            id_jag_ttl_secs: 120,
            public_base_url: None,
            replay_backend: crate::sts::replay::IN_PROCESS_BACKEND.to_string(),
            throttle: crate::config::types::TokenEndpointThrottleConfig::default(),
            mcp_issuer: None,
            mcp_replay: None,
        }
    }
}

/// A managed connection: what an authenticated client is permitted to request.
#[derive(Debug, Clone, Default)]
pub struct StsClientRecord {
    #[allow(dead_code)]
    pub client_id: String,
    /// The owning tenant; `None` for an appliance-global client.
    pub tenant_id: Option<String>,
    /// Allowed `audience`/`resource` targets. Empty ⇒ unrestricted.
    pub allowed_audiences: Vec<String>,
    /// Allowed scopes. Empty ⇒ unrestricted.
    pub allowed_scopes: Vec<String>,
    /// When true, an exchange without an `actor_token` mints an impersonation
    /// token (no `act`). When false (default), the authenticated client becomes
    /// the implicit actor — delegation by default.
    pub allow_impersonation: bool,
    /// Per-connection TTL cap (further capped by [`StsConfig::max_ttl_secs`]).
    pub max_ttl_secs: Option<u64>,
    /// Whether this client may obtain an ID-JAG (`requested_token_type=id-jag`).
    pub issue_id_jag: bool,
    /// Allowed subject-token type URNs. Empty ⇒ any supported subject type.
    pub allowed_subject_token_types: Vec<String>,
    /// Optional allowlist of accepted subject-token audiences (opt-in). Empty ⇒
    /// no `aud` check; when set, a JWT-shaped subject token's `aud` must match.
    pub allowed_subject_audiences: Vec<String>,
    /// Caller-leg Trust Check list evaluated on issuance (results surface to the
    /// gateway policy at `input.trust_check_results.caller[]`).
    pub trust_check_list: Vec<crate::trust_registry_verification::TrustCheckElement>,
}

// ── Ports ─────────────────────────────────────────────────────────────────────

/// Signs issued tokens and reports the issuer identifier.
#[async_trait::async_trait]
pub trait StsSigner: Send + Sync {
    /// The issuer (`iss`) identifier for minted tokens (the gateway DID).
    async fn issuer(&self) -> Result<String, StsError>;
    /// Sign a claim set into a compact JWS.
    async fn sign(
        &self,
        claims: &Value,
    ) -> Result<String, StsError>;

    async fn sign_mcp_access_token(
        &self,
        claims: &Value,
    ) -> Result<String, StsError> {
        self.sign(claims).await
    }
    /// Sign an ID-JAG claim set under the explicit `oauth-id-jag+jwt` JOSE `typ`
    /// header so a redeemer can reject a non-ID-JAG token (token confusion).
    async fn sign_id_jag(
        &self,
        claims: &Value,
    ) -> Result<String, StsError>;
    /// Public JWKS for external verification.
    async fn public_jwks(&self) -> Result<Value, StsError>;
}

/// Verifies a JWT-shaped assertion and returns its verified claims.
#[async_trait::async_trait]
pub trait StsSubjectVerifier: Send + Sync {
    async fn verify_jwt(
        &self,
        token: &str,
    ) -> Result<Value, StsError>;

    async fn verify_mcp_jwt(
        &self,
        token: &str,
        _profile: &crate::sts::mcp_profile::McpIssuerProfile,
    ) -> Result<Value, StsError> {
        self.verify_jwt(token).await
    }
}

/// Verifies a Verifiable Presentation subject token and returns a claims object
/// whose `sub` is the cryptographically-proven subject DID.
#[async_trait::async_trait]
pub trait StsVpVerifier: Send + Sync {
    async fn verify_vp(
        &self,
        vp: &str,
    ) -> Result<Value, StsError>;
}

/// Authenticates a client and loads its managed connection.
#[async_trait::async_trait]
pub trait StsClientRegistry: Send + Sync {
    async fn authenticate(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<StsClientRecord, StsError>;
}

// ── Production adapters ───────────────────────────────────────────────────────

/// [`StsSigner`] backed by the gateway [`VCIssuer`] (EdDSA / gateway key).
pub struct VcIssuerSigner {
    pub vc_issuer: Arc<VCIssuer>,
}

#[async_trait::async_trait]
impl StsSigner for VcIssuerSigner {
    async fn issuer(&self) -> Result<String, StsError> {
        self.vc_issuer
            .get_issuer_did()
            .await
            .map_err(|e| StsError::ServerError(format!("issuer lookup failed: {e}")))
    }

    async fn sign(
        &self,
        claims: &Value,
    ) -> Result<String, StsError> {
        self.vc_issuer
            .sign_jwt_with_gateway_key(claims)
            .await
            .map_err(|e| StsError::ServerError(format!("token signing failed: {e}")))
    }

    async fn sign_id_jag(
        &self,
        claims: &Value,
    ) -> Result<String, StsError> {
        self.vc_issuer
            .sign_jwt_with_gateway_key_typ(claims, ID_JAG_JWT_TYP)
            .await
            .map_err(|e| StsError::ServerError(format!("token signing failed: {e}")))
    }

    async fn sign_mcp_access_token(
        &self,
        claims: &Value,
    ) -> Result<String, StsError> {
        self.vc_issuer
            .sign_jwt_with_gateway_key_typ(claims, "at+jwt")
            .await
            .map_err(|error| StsError::ServerError(format!("token signing failed: {error}")))
    }

    async fn public_jwks(&self) -> Result<Value, StsError> {
        self.vc_issuer
            .signing_public_jwks()
            .await
            .map_err(|e| StsError::ServerError(format!("jwks projection failed: {e}")))
    }
}

/// [`StsSubjectVerifier`] backed by `src/jwt_bearer`. Resolves the verification
/// strategy by matching the token's (unverified) `iss` against a registered
/// strategy's `expected_issuer`, then verifies the signature and standard claims.
pub struct JwtBearerSubjectVerifier {
    verifier: Arc<crate::jwt_bearer::JwtBearerVerifier>,
    strategies: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
    /// Source of this gateway's own issuer DID + JWKS. A JWT whose `iss` is this
    /// gateway was signed with the gateway key, so it is verified against our own
    /// published JWKS — a gateway-issued ID-JAG can be redeemed on the loopback
    /// (issuer == resource AS) without an operator-configured self-trust strategy.
    self_issuer: Arc<VCIssuer>,
}

impl JwtBearerSubjectVerifier {
    pub fn new(
        verifier: Arc<crate::jwt_bearer::JwtBearerVerifier>,
        strategies: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
        self_issuer: Arc<VCIssuer>,
    ) -> Self {
        Self {
            verifier,
            strategies,
            self_issuer,
        }
    }

    async fn verify_local_jwt(
        &self,
        token: &str,
        issuer: &str,
    ) -> Result<Value, StsError> {
        let jwks = self
            .self_issuer
            .signing_public_jwks()
            .await
            .map_err(|error| StsError::ServerError(format!("gateway jwks projection failed: {error}")))?;
        let strategy = gateway_self_trust_strategy(issuer, &jwks)?;
        self.verifier
            .validate(token, &strategy, &[])
            .await
            .map_err(|error| StsError::InvalidGrant(format!("assertion verification failed: {error}")))
    }
}

#[async_trait::async_trait]
impl StsSubjectVerifier for JwtBearerSubjectVerifier {
    async fn verify_jwt(
        &self,
        token: &str,
    ) -> Result<Value, StsError> {
        let iss = decode_unverified_issuer(token)
            .ok_or_else(|| StsError::InvalidGrant("assertion missing a readable iss claim".to_string()))?;

        // A JWT whose issuer is this gateway was signed with the gateway's own
        // key. Verify it against our own published JWKS so a gateway-issued
        // ID-JAG can be redeemed on the loopback (issuer == resource AS) without
        // an operator-configured verification strategy for our own DID. Genuinely
        // external issuers continue through the strategy store below.
        if let Ok(self_did) = self
            .self_issuer
            .get_issuer_did()
            .await
            && iss == self_did
        {
            return self
                .verify_local_jwt(token, &self_did)
                .await;
        }

        let strategies = self
            .strategies
            .list()
            .await
            .map_err(|e| StsError::ServerError(format!("strategy store error: {e}")))?;
        let strategy = strategies
            .into_iter()
            .find(|s| s.expected_issuer == iss)
            .ok_or_else(|| StsError::InvalidGrant(format!("no verification strategy for issuer {iss}")))?;
        self.verifier
            .validate(token, &strategy, &[])
            .await
            .map_err(|e| StsError::InvalidGrant(format!("assertion verification failed: {e}")))
    }

    async fn verify_mcp_jwt(
        &self,
        token: &str,
        profile: &crate::sts::mcp_profile::McpIssuerProfile,
    ) -> Result<Value, StsError> {
        profile.validate()?;
        if decode_unverified_issuer(token).as_deref() == Some(profile.issuer.as_str()) {
            return self
                .verify_local_jwt(token, &profile.issuer)
                .await;
        }
        self.verify_jwt(token).await
    }
}

/// A [`StsSubjectVerifier`] that always fails closed. Used when no JWT
/// verification strategy backend is available so the endpoints still mount and
/// respond safely (subject verification returns `invalid_grant`).
pub struct DisabledSubjectVerifier;
#[async_trait::async_trait]
impl StsSubjectVerifier for DisabledSubjectVerifier {
    async fn verify_jwt(
        &self,
        _token: &str,
    ) -> Result<Value, StsError> {
        Err(StsError::InvalidGrant("subject token verification is not configured on this gateway".to_string()))
    }
}

/// [`StsVpVerifier`] backed by the gateway [`VCIssuer`]. Cryptographically
/// verifies the presentation and returns a claims object whose `sub` is the
/// proven `credentialSubject.id` (falling back to the holder DID), plus the
/// verified issuer DID as `identity_issuer_did`.
pub struct VcIssuerVpVerifier {
    pub vc_issuer: Arc<VCIssuer>,
}

#[async_trait::async_trait]
impl StsVpVerifier for VcIssuerVpVerifier {
    async fn verify_vp(
        &self,
        vp: &str,
    ) -> Result<Value, StsError> {
        let verified = self
            .vc_issuer
            .verify_agent_presentation_full(vp)
            .await
            .map_err(|e| StsError::InvalidGrant(format!("VP verification failed: {e}")))?;
        let sub = verified
            .subject_id
            .clone()
            .unwrap_or_else(|| verified.holder_did.clone());
        let mut claims = serde_json::Map::new();
        claims.insert("sub".to_string(), Value::String(sub));
        if let Some(issuer) = verified.issuer_did {
            claims.insert("identity_issuer_did".to_string(), Value::String(issuer));
        }
        Ok(Value::Object(claims))
    }
}

/// A [`StsVpVerifier`] that fails closed when VP verification is unavailable.
#[allow(dead_code)]
pub struct DisabledVpVerifier;

#[async_trait::async_trait]
impl StsVpVerifier for DisabledVpVerifier {
    async fn verify_vp(
        &self,
        _vp: &str,
    ) -> Result<Value, StsError> {
        Err(StsError::UnsupportedTokenType(
            "Verifiable Presentation subject tokens are not configured on this gateway".to_string(),
        ))
    }
}

/// A simple in-memory client registry. Managed connections are supplied at
/// construction; a persistent, dashboard-managed store lands in a later phase.
#[derive(Default)]
pub struct InMemoryStsClientRegistry {
    clients: HashMap<String, (Option<String>, StsClientRecord)>,
}

impl InMemoryStsClientRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a client. `secret = None` marks a public client (no secret check).
    #[allow(dead_code)]
    pub fn with_client(
        mut self,
        secret: Option<String>,
        record: StsClientRecord,
    ) -> Self {
        self.clients
            .insert(record.client_id.clone(), (secret, record));
        self
    }
}

#[async_trait::async_trait]
impl StsClientRegistry for InMemoryStsClientRegistry {
    async fn authenticate(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<StsClientRecord, StsError> {
        let (expected_secret, record) = self
            .clients
            .get(client_id)
            .ok_or_else(|| StsError::InvalidClient("unknown client".to_string()))?;
        match expected_secret {
            Some(expected) => {
                let ok = client_secret
                    .map(|s| constant_time_eq(s, expected))
                    .unwrap_or(false);
                if ok {
                    Ok(record.clone())
                } else {
                    Err(StsError::InvalidClient("invalid client credentials".to_string()))
                }
            }
            None => Ok(record.clone()),
        }
    }
}

// ── State ─────────────────────────────────────────────────────────────────────

/// Axum state for the STS routes.
#[derive(Clone)]
pub struct StsState {
    pub signer: Arc<dyn StsSigner>,
    pub verifier: Arc<dyn StsSubjectVerifier>,
    pub vp_verifier: Arc<dyn StsVpVerifier>,
    pub clients: Arc<dyn StsClientRegistry>,
    /// Policy gate: authorizes each issuance against gateway OPA before minting.
    pub policy: Arc<dyn StsPolicyEvaluator>,
    /// Trust Check: runs a client's `trust_check_list` and merges the verdict
    /// into the OPA input at `input.trust_check_results.caller[]` before the gate.
    pub trust_checker: Arc<dyn StsTrustChecker>,
    /// Single-use guard: rejects a replayed ID-JAG within its validity window.
    pub replay: Arc<dyn crate::sts::replay::ReplayProtection>,
    /// Throttle: bounds repeated attempts per client id and source address.
    pub throttle: Arc<crate::sts::throttle::TokenEndpointThrottle>,
    /// Which tenants declare an MCP resource, checked before minting for it.
    pub resource_owners: Arc<dyn crate::sts::resource_owners::StsResourceOwners>,
    pub config: StsConfig,
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// `POST /oauth2/token` — RFC 8693 token exchange and RFC 7523 ID-JAG redemption.
pub async fn token_endpoint(
    State(state): State<StsState>,
    headers: HeaderMap,
    Form(form): Form<TokenEndpointForm>,
) -> Response {
    serve_token_endpoint(&state, &headers, form, None).await
}

pub async fn mcp_token_endpoint(
    State(state): State<StsState>,
    headers: HeaderMap,
    crate::sts::mcp_profile::McpTokenForm(form): crate::sts::mcp_profile::McpTokenForm,
) -> Response {
    let Some(profile) = state
        .config
        .mcp_issuer
        .as_ref()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    serve_token_endpoint(&state, &headers, form, Some(profile)).await
}

async fn serve_token_endpoint(
    state: &StsState,
    headers: &HeaderMap,
    form: TokenEndpointForm,
    profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>,
) -> Response {
    let grant = grant_label(form.grant_type.as_deref());
    let started = std::time::Instant::now();

    // Throttle: reject a client / source that is over its configured limit.
    let throttle_client = resolve_client_credentials(headers, &form).0;
    let throttle_ip = client_source_ip(headers);
    let throttle_now = now_secs();
    if let Some(retry_after) =
        state
            .throttle
            .retry_after(throttle_client.as_deref(), throttle_ip.as_deref(), throttle_now)
    {
        crate::metrics::backends::prometheus::track_sts_token_exchange(
            grant,
            "denied",
            started
                .elapsed()
                .as_secs_f64(),
        );
        return throttled_response(retry_after);
    }

    match dispatch_with_profile(state, headers, form, profile).await {
        Ok(resp) => {
            if !state
                .throttle
                .failed_attempts_only()
            {
                state
                    .throttle
                    .record(throttle_client.as_deref(), throttle_ip.as_deref(), throttle_now);
            }
            crate::metrics::backends::prometheus::track_sts_token_exchange(
                grant,
                "ok",
                started
                    .elapsed()
                    .as_secs_f64(),
            );
            let mut response = (StatusCode::OK, axum::Json(resp)).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
            response
        }
        Err(e) => {
            if !state
                .throttle
                .failed_attempts_only()
                || matches!(e, StsError::InvalidClient(_))
            {
                state
                    .throttle
                    .record(throttle_client.as_deref(), throttle_ip.as_deref(), throttle_now);
            }
            // A server fault is `error`; every client-side rejection (bad client,
            // policy/target/scope/grant denial, malformed request) is `denied`.
            let result = if matches!(e, StsError::ServerError(_)) {
                "error"
            } else {
                "denied"
            };
            crate::metrics::backends::prometheus::track_sts_token_exchange(
                grant,
                result,
                started
                    .elapsed()
                    .as_secs_f64(),
            );
            e.into_response()
        }
    }
}

/// `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.
pub async fn authorization_server_metadata(
    State(state): State<StsState>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: HeaderMap,
) -> Response {
    let issuer = state
        .signer
        .issuer()
        .await
        .unwrap_or_default();
    // RFC 8414 requires absolute URLs. Prefer the operator-configured public
    // base (scheme + authority from the inbound `external_urls`): behind a
    // terminating HTTP proxy/tunnel the request carries neither the public host
    // (`Host` is the internal `127.0.0.1`) nor the public scheme, and forwarding
    // headers may be absent. Fall back to request-derived host/scheme, then to
    // relative paths.
    let base = compose_configured_base(
        state
            .config
            .public_base_url
            .as_deref(),
        uri.path(),
    )
    .or_else(|| metadata_base_url(&headers, uri.path()));
    let token_endpoint = match &base {
        Some(base) => format!("{base}/oauth2/token"),
        None => "/oauth2/token".to_string(),
    };
    let jwks_uri = match &base {
        Some(base) => format!("{base}/oauth2/jwks.json"),
        None => "/oauth2/jwks.json".to_string(),
    };
    axum::Json(json!({
        "issuer": issuer,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "grant_types_supported": [GRANT_TYPE_TOKEN_EXCHANGE, GRANT_TYPE_JWT_BEARER],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "subject_token_types_supported": [TOKEN_TYPE_JWT, TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_ID_JAG, TOKEN_TYPE_VP],
        "requested_token_types_supported": [TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT, TOKEN_TYPE_ID_JAG],
    }))
    .into_response()
}

/// Derive the absolute base URL for the RFC 8414 metadata endpoints from the
/// request, so `token_endpoint` / `jwks_uri` are absolute and reflect the actual
/// mount prefix (e.g. `/api`).
///
/// The public host is resolved from the proxy-forwarded value first —
/// `X-Forwarded-Host`, then the RFC 7239 `Forwarded host=` directive — and only
/// falls back to the request `Host` when neither is present. Behind a
/// terminating proxy or tunnel the direct `Host` is the gateway's *internal*
/// address (e.g. `127.0.0.1:8080`), so the forwarded value is authoritative. The
/// scheme comes from `X-Forwarded-Proto`, then `Forwarded proto=`, else defaults
/// to `https`. Returns `None` when no host can be resolved, in which case the
/// caller falls back to relative paths.
fn metadata_base_url(
    headers: &HeaderMap,
    request_path: &str,
) -> Option<String> {
    let prefix = metadata_mount_prefix(request_path)?;
    let host = first_forwarded_token(headers, "x-forwarded-host")
        .or_else(|| forwarded_directive(headers, "host"))
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())?;
    let scheme = first_forwarded_token(headers, "x-forwarded-proto")
        .or_else(|| forwarded_directive(headers, "proto"))
        .unwrap_or_else(|| "https".to_string());
    Some(format!("{scheme}://{host}{prefix}"))
}

/// The first comma-separated, trimmed token of a header (e.g. the client-most
/// entry of `X-Forwarded-Host: public.example, inner.internal`). `None` when the
/// header is absent, non-ASCII, or empty.
fn first_forwarded_token(
    headers: &HeaderMap,
    name: &str,
) -> Option<String> {
    let raw = headers
        .get(name)?
        .to_str()
        .ok()?;
    let token = raw.split(',').next()?.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Extract a directive (`host` / `proto`) from the first element of an RFC 7239
/// `Forwarded` header, stripping optional quoting. `None` when absent or empty.
fn forwarded_directive(
    headers: &HeaderMap,
    directive: &str,
) -> Option<String> {
    let raw = headers
        .get("forwarded")?
        .to_str()
        .ok()?;
    for pair in raw
        .split(',')
        .next()?
        .split(';')
    {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next()?.trim();
        if key.eq_ignore_ascii_case(directive) {
            let val = kv
                .next()?
                .trim()
                .trim_matches('"')
                .trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// The mount prefix of a discovery request — the path with the well-known suffix
/// stripped (e.g. `/api` for `/api/.well-known/oauth-authorization-server`, or
/// `""` for a root mount). `None` when the path is not the discovery route.
fn metadata_mount_prefix(request_path: &str) -> Option<&str> {
    request_path.strip_suffix("/.well-known/oauth-authorization-server")
}

/// Compose the absolute metadata base from the operator-configured public base
/// URL and the request mount prefix, e.g. `https://gw.example` + `/api` ⇒
/// `https://gw.example/api`. Only the base's origin (scheme + authority) is
/// used, so a stray path in `external_urls` never leaks into the endpoints.
/// `None` when no base is configured or it cannot be parsed.
fn compose_configured_base(
    public_base: Option<&str>,
    request_path: &str,
) -> Option<String> {
    let prefix = metadata_mount_prefix(request_path)?;
    let origin = configured_origin(public_base?)?;
    Some(format!("{origin}{prefix}"))
}

/// Extract the origin (`scheme://authority`) from a configured public base URL,
/// discarding any path/query so it composes cleanly with the mount prefix.
fn configured_origin(base: &str) -> Option<String> {
    let url = url::Url::parse(base.trim()).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

/// `GET /oauth2/jwks.json` — public keys for verifying issued tokens.
pub async fn jwks_endpoint(State(state): State<StsState>) -> Response {
    match state
        .signer
        .public_jwks()
        .await
    {
        Ok(jwks) => axum::Json(jwks).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Build the STS sub-router with its own state: `POST /oauth2/token`,
/// `GET /oauth2/jwks.json`, and `GET /.well-known/oauth-authorization-server`.
///
/// When a JWKS client and strategy store are both available the subject-token
/// verifier is wired to `src/jwt_bearer`; otherwise a fail-closed verifier is
/// used so the endpoints still mount and respond safely. The client registry is
/// injected so a persistent, dashboard-managed store can replace the in-memory
/// one without touching this wiring. When a gateway policy manager is provided,
/// every issuance is authorized against the gateway OPA policy before minting;
/// otherwise issuance proceeds under the static managed-connection allowlists.
pub fn build_sts_router(
    vc_issuer: Arc<VCIssuer>,
    jwks_client: Option<Arc<crate::jwt_bearer::JwksClient>>,
    strategy_store: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    client_store: Option<Arc<dyn crate::sts::store::StsClientStorage>>,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>,
    resource_owners: Arc<dyn crate::sts::resource_owners::StsResourceOwners>,
    config: StsConfig,
) -> axum::Router {
    let verifier: Arc<dyn StsSubjectVerifier> = match (jwks_client, strategy_store) {
        (Some(jwks), Some(store)) => {
            let jwt_verifier = Arc::new(crate::jwt_bearer::JwtBearerVerifier::new(jwks));
            Arc::new(JwtBearerSubjectVerifier::new(jwt_verifier, store, vc_issuer.clone()))
        }
        _ => Arc::new(DisabledSubjectVerifier),
    };
    let vp_verifier: Arc<dyn StsVpVerifier> = Arc::new(VcIssuerVpVerifier { vc_issuer: vc_issuer.clone() });
    let clients: Arc<dyn StsClientRegistry> = match (client_store, secrets_store) {
        (Some(store), Some(secrets)) => Arc::new(crate::sts::store::StoreBackedClientRegistry::new(store, secrets)),
        _ => Arc::new(InMemoryStsClientRegistry::new()),
    };
    let policy: Arc<dyn StsPolicyEvaluator> = match gateway_policy_manager {
        Some(manager) => Arc::new(GatewayPolicyEvaluator::new(manager)),
        None => Arc::new(AllowAllPolicyEvaluator),
    };
    let trust_checker: Arc<dyn StsTrustChecker> = match trust_registry_listener_manager {
        Some(manager) => Arc::new(ListenerTrustChecker::new(manager)),
        None => Arc::new(DisabledTrustChecker),
    };
    let replay = crate::sts::replay::build_replay_backend(&config.replay_backend);
    let throttle = Arc::new(crate::sts::throttle::TokenEndpointThrottle::from_config(&config.throttle));
    let state = StsState {
        signer: Arc::new(VcIssuerSigner { vc_issuer }),
        verifier,
        vp_verifier,
        clients,
        policy,
        trust_checker,
        replay,
        throttle,
        resource_owners,
        config,
    };
    let mut router = axum::Router::new()
        .route("/oauth2/token", axum::routing::post(token_endpoint))
        .route("/oauth2/jwks.json", axum::routing::get(jwks_endpoint))
        .route("/.well-known/oauth-authorization-server", axum::routing::get(authorization_server_metadata));
    if state
        .config
        .mcp_issuer
        .is_some()
    {
        router = router
            .route("/oauth2/mcp/token", axum::routing::post(mcp_token_endpoint))
            .route("/oauth2/mcp/jwks.json", axum::routing::get(jwks_endpoint));
    }
    router.with_state(state)
}

// ── Core flow (testable, returns a typed result) ──────────────────────────────

#[cfg(test)]
async fn dispatch(
    state: &StsState,
    headers: &HeaderMap,
    form: TokenEndpointForm,
) -> Result<TokenExchangeResponse, StsError> {
    dispatch_with_profile(state, headers, form, None).await
}

async fn dispatch_with_profile(
    state: &StsState,
    headers: &HeaderMap,
    form: TokenEndpointForm,
    profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>,
) -> Result<TokenExchangeResponse, StsError> {
    match form.grant_type.as_deref() {
        Some(GRANT_TYPE_TOKEN_EXCHANGE) => handle_token_exchange(state, headers, form, profile).await,
        Some(GRANT_TYPE_JWT_BEARER) => handle_jwt_bearer(state, headers, form, profile).await,
        Some(other) => Err(StsError::UnsupportedGrantType(other.to_string())),
        None => Err(StsError::InvalidRequest("grant_type is required".to_string())),
    }
}

async fn handle_token_exchange(
    state: &StsState,
    headers: &HeaderMap,
    form: TokenEndpointForm,
    profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>,
) -> Result<TokenExchangeResponse, StsError> {
    let req = validate_token_exchange(&form)?;

    let (client_id, client_secret) = resolve_client_credentials(headers, &form);
    let client_id = client_id.ok_or_else(|| StsError::InvalidClient("client authentication required".to_string()))?;
    let record = state
        .clients
        .authenticate(&client_id, client_secret.as_deref())
        .await?;

    let presented_type = if declares_id_jag_typ(&req.subject_token) {
        TokenType::IdJag
    } else {
        req.subject_token_type
    };
    if !record
        .allowed_subject_token_types
        .is_empty()
        && !record
            .allowed_subject_token_types
            .iter()
            .any(|t| t == presented_type.as_urn())
    {
        return Err(StsError::UnauthorizedClient(format!(
            "client may not present subject_token_type {}",
            presented_type.as_urn()
        )));
    }

    // The client declares `subject_token_type`, so an ID-JAG sent as `jwt` or
    // `id_token` is recognised by its JOSE `typ`: exchanging it here would mint
    // tokens without consuming the single-use grant on the jwt-bearer path.
    if profile.is_some()
        && (!matches!(req.subject_token_type, TokenType::Jwt | TokenType::IdToken)
            || declares_id_jag_typ(&req.subject_token))
    {
        return Err(StsError::UnsupportedTokenType(
            "MCP exchange accepts JWT or ID-token subjects; redeem ID-JAG through jwt-bearer".into(),
        ));
    }
    let gateway_did = state.signer.issuer().await?;
    let subject_claims = verify_assertion(state, req.subject_token_type, &req.subject_token, profile).await?;
    let mut assertion_expiry = None;
    if req
        .subject_token_type
        .is_jwt_shaped()
    {
        reject_self_issued(state, &gateway_did, profile, "subject", &req.subject_token, &subject_claims)?;
        if let Some(profile) = profile {
            if record
                .allowed_subject_audiences
                .is_empty()
            {
                return Err(StsError::UnauthorizedClient(
                    "MCP exchange requires explicit subject-token audiences".into(),
                ));
            }
            assertion_expiry = Some(profile.validate_subject(&subject_claims, now_secs())?);
        } else {
            assertion_expiry = claimed_expiry(&subject_claims);
        }
        enforce_subject_audience(&record, &subject_claims)?;
    }
    let (subject_sub, subject_act) = extract_subject_and_act(&subject_claims);
    let subject_sub = subject_sub.ok_or_else(|| StsError::InvalidGrant("subject_token has no sub".to_string()))?;
    let subject_sub = match profile {
        Some(profile) => profile.bound_subject(&subject_claims)?,
        None => subject_sub,
    };

    let actor_sub: Option<String> = match (&req.actor_token, req.actor_token_type) {
        (Some(actor_token), Some(actor_type)) => {
            if profile.is_some()
                && (!matches!(actor_type, TokenType::Jwt | TokenType::IdToken) || declares_id_jag_typ(actor_token))
            {
                return Err(StsError::UnsupportedTokenType(
                    "MCP exchange accepts JWT or ID-token actors; redeem ID-JAG through jwt-bearer".into(),
                ));
            }
            let actor_claims = verify_assertion(state, actor_type, actor_token, profile).await?;
            if actor_type.is_jwt_shaped() {
                reject_self_issued(state, &gateway_did, profile, "actor", actor_token, &actor_claims)?;
                let actor_expiry = match profile {
                    Some(profile) => {
                        let expiry = profile.validate_subject(&actor_claims, now_secs())?;
                        enforce_subject_audience(&record, &actor_claims)?;
                        Some(expiry)
                    }
                    None => claimed_expiry(&actor_claims),
                };
                if let Some(actor_expiry) = actor_expiry {
                    assertion_expiry = Some(assertion_expiry.map_or(actor_expiry, |expiry| expiry.min(actor_expiry)));
                }
            }
            let (asub, _) = extract_subject_and_act(&actor_claims);
            Some(asub.ok_or_else(|| StsError::InvalidGrant("actor_token has no sub".to_string()))?)
        }
        _ if !record.allow_impersonation => Some(client_id.clone()),
        _ => None,
    };

    let issuer = match profile {
        Some(profile) => profile.issuer.clone(),
        None => gateway_did,
    };
    let mcp_resource = profile
        .map(|profile| {
            profile.requested_resource(
                req.resource.as_deref(),
                req.audience.as_deref(),
                req.requested_token_type == TokenType::IdJag,
            )
        })
        .transpose()?;
    let audience = if let (Some(profile), Some(resource)) = (profile, &mcp_resource) {
        profile.authorize_resource(&record, resource, &req.scopes)?;
        crate::sts::resource_owners::ensure_client_may_target(
            state.resource_owners.as_ref(),
            record.tenant_id.as_deref(),
            resource,
        )
        .await?;
        Some(if req.requested_token_type == TokenType::IdJag {
            issuer.clone()
        } else {
            resource.clone()
        })
    } else {
        let audience = req
            .audience
            .clone()
            .or_else(|| req.resource.clone());
        enforce_audience(&record, audience.as_deref(), Some(issuer.as_str()))?;
        audience
    };

    let scopes = resolve_scopes(&req.scopes, &record.allowed_scopes)?;

    // Gate issuance on gateway OPA policy — the same engine that gates proxy
    // traffic — before any token is minted. A configured Trust Check list is
    // evaluated first and its verdict merged into `input.trust_check_results`
    // so the policy can allow/deny on a recognition/authorization result.
    let mut policy_input = build_policy_input(
        "token_exchange",
        &client_id,
        &subject_sub,
        actor_sub.as_deref(),
        audience.as_deref(),
        &scopes,
        req.requested_token_type
            .as_urn(),
    );
    if let Some(resource) = &mcp_resource {
        policy_input["sts"]["resource"] = json!(resource);
        policy_input["sts"]["issuer"] = json!(issuer);
    }
    if let Some(results) = state
        .trust_checker
        .evaluate(&client_id, &policy_input, &record.trust_check_list)
        .await
    {
        policy_input["trust_check_results"] = results;
    }
    state
        .policy
        .authorize(&policy_input)?;

    let max_ttl = record
        .max_ttl_secs
        .map(|m| m.min(state.config.max_ttl_secs))
        .unwrap_or(state.config.max_ttl_secs);
    let now = now_secs();
    let max_ttl = match assertion_expiry {
        Some(expiry) => max_ttl.min(
            expiry
                .checked_sub(now)
                .filter(|ttl| *ttl > 0)
                .ok_or_else(|| StsError::InvalidGrant("assertion expired before issuance".into()))?,
        ),
        None => max_ttl,
    };
    let ttl = effective_ttl(None, state.config.default_ttl_secs, max_ttl);
    let jti = uuid::Uuid::new_v4().to_string();

    if req.requested_token_type == TokenType::IdJag {
        if !record.issue_id_jag {
            return Err(StsError::UnauthorizedClient("client is not permitted to obtain an ID-JAG".to_string()));
        }
        let aud = audience
            .ok_or_else(|| StsError::InvalidTarget("audience or resource is required for an ID-JAG".to_string()))?;
        let id_jag_ttl = state
            .config
            .id_jag_ttl_secs
            .min(max_ttl);
        // Embed the RFC 8693 delegation actor so the agent DID (or the implicit
        // client actor) survives into the ID-JAG and, on redemption, into the
        // issued resource token.
        let grant_act = compose_delegation_chain(subject_act.clone(), actor_sub.as_deref());
        let mut claims = build_id_jag_claims(IdJagParams {
            issuer: &issuer,
            subject: &subject_sub,
            audience: &aud,
            client_id: &client_id,
            scopes: &scopes,
            issued_at: now,
            ttl_secs: id_jag_ttl,
            jti: &jti,
            act: grant_act,
        });
        if let Some(resource) = &mcp_resource {
            claims["resource"] = json!(resource);
        }
        let token = state
            .signer
            .sign_id_jag(&claims)
            .await?;
        emit_issuance_audit(
            "token_exchange",
            &client_id,
            &subject_sub,
            Some(&aud),
            TOKEN_TYPE_ID_JAG,
            &scopes,
            None,
            &jti,
        );
        return Ok(TokenExchangeResponse {
            access_token: token,
            issued_token_type: TOKEN_TYPE_ID_JAG.to_string(),
            token_type: TOKEN_TYPE_N_A.to_string(),
            expires_in: Some(id_jag_ttl),
            scope: scope_string(&scopes),
        });
    }

    let claims = build_access_token_claims(AccessTokenParams {
        issuer: &issuer,
        subject: &subject_sub,
        subject_act,
        actor_sub: actor_sub.as_deref(),
        client_id: Some(&client_id),
        audience: audience.as_deref(),
        scopes: &scopes,
        issued_at: now,
        ttl_secs: ttl,
        jti: &jti,
    });
    let token = if profile.is_some() {
        state
            .signer
            .sign_mcp_access_token(&claims)
            .await?
    } else {
        state
            .signer
            .sign(&claims)
            .await?
    };
    emit_issuance_audit(
        "token_exchange",
        &client_id,
        &subject_sub,
        audience.as_deref(),
        req.requested_token_type
            .as_urn(),
        &scopes,
        actor_sub.as_deref(),
        &jti,
    );
    Ok(TokenExchangeResponse {
        access_token: token,
        issued_token_type: req
            .requested_token_type
            .as_urn()
            .to_string(),
        token_type: BEARER.to_string(),
        expires_in: Some(ttl),
        scope: scope_string(&scopes),
    })
}

async fn handle_jwt_bearer(
    state: &StsState,
    headers: &HeaderMap,
    form: TokenEndpointForm,
    profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>,
) -> Result<TokenExchangeResponse, StsError> {
    let assertion = form
        .assertion
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidRequest("assertion is required".to_string()))?;

    let claims = match profile {
        Some(profile) => {
            state
                .verifier
                .verify_mcp_jwt(assertion, profile)
                .await?
        }
        None => {
            state
                .verifier
                .verify_jwt(assertion)
                .await?
        }
    };
    // Explicit typing (RFC 8725): the verified assertion must be an ID-JAG, so a
    // plain access/ID token from the same issuer cannot be substituted for one.
    if parse_jose_typ(assertion).as_deref() != Some(ID_JAG_JWT_TYP) {
        return Err(StsError::InvalidGrant("presented assertion is not an ID-JAG".to_string()));
    }
    let issuer = match profile {
        Some(profile) => profile.issuer.clone(),
        None => state.signer.issuer().await?,
    };
    let now = now_secs();
    // The presented assertion must be an ID-JAG addressed to this gateway.
    let id_jag = validate_id_jag(&claims, &issuer, now)?;
    let subject = match profile {
        Some(profile) => profile.bound_subject(&claims)?,
        None => id_jag.subject.clone(),
    };

    let (client_id, client_secret) = resolve_client_credentials(headers, &form);
    let client_id = client_id.ok_or_else(|| StsError::InvalidClient("client authentication required".to_string()))?;
    let record = state
        .clients
        .authenticate(&client_id, client_secret.as_deref())
        .await?;

    if id_jag.client_id != client_id {
        return Err(StsError::InvalidGrant("ID-JAG was not issued to this client".to_string()));
    }

    let legacy_audience = form
        .audience
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            form.resource
                .clone()
                .filter(|s| !s.is_empty())
        });
    let audience = if let Some(profile) = profile {
        profile.validate_subject(&claims, now)?;
        let resource = profile.requested_resource(form.resource.as_deref(), form.audience.as_deref(), false)?;
        if claims
            .get("resource")
            .and_then(Value::as_str)
            != Some(resource.as_str())
        {
            return Err(StsError::InvalidTarget("MCP resource does not match the ID-JAG grant".into()));
        }
        Some(resource)
    } else {
        enforce_audience(&record, legacy_audience.as_deref(), Some(issuer.as_str()))?;
        legacy_audience
    };

    // Requested scope defaults to the grant's scope and can never exceed it; the
    // client allowlist narrows further.
    let requested = form
        .scope
        .as_deref()
        .map(parse_scope)
        .unwrap_or_else(|| id_jag.scopes.clone());
    if let Some(profile) = profile {
        if requested
            .iter()
            .any(|scope| !id_jag.scopes.contains(scope))
        {
            return Err(StsError::InvalidScope("MCP scopes cannot exceed the ID-JAG grant".into()));
        }
        profile.authorize_resource(
            &record,
            audience
                .as_deref()
                .unwrap_or_default(),
            &requested,
        )?;
        crate::sts::resource_owners::ensure_client_may_target(
            state.resource_owners.as_ref(),
            record.tenant_id.as_deref(),
            audience
                .as_deref()
                .unwrap_or_default(),
        )
        .await?;
    }
    let ceilinged = ceiling_scopes(&requested, &id_jag.scopes);
    let scopes = resolve_scopes(&ceilinged, &record.allowed_scopes)?;

    // Gate redemption on gateway OPA policy — the same engine that gates proxy
    // traffic — before any token is minted. A configured Trust Check list is
    // evaluated first and its verdict merged into `input.trust_check_results`.
    let mut policy_input = build_policy_input(
        "jwt_bearer",
        &client_id,
        &subject,
        Some(&client_id),
        audience.as_deref(),
        &scopes,
        TOKEN_TYPE_ACCESS_TOKEN,
    );
    if profile.is_some() {
        policy_input["sts"]["resource"] = json!(audience);
        policy_input["sts"]["issuer"] = json!(issuer);
    }
    if let Some(results) = state
        .trust_checker
        .evaluate(&client_id, &policy_input, &record.trust_check_list)
        .await
    {
        policy_input["trust_check_results"] = results;
    }
    state
        .policy
        .authorize(&policy_input)?;

    let max_ttl = record
        .max_ttl_secs
        .map(|m| m.min(state.config.max_ttl_secs))
        .unwrap_or(state.config.max_ttl_secs);
    let now = now_secs();
    let ttl = effective_ttl(None, state.config.default_ttl_secs, max_ttl).min(
        id_jag
            .expires_at
            .checked_sub(now)
            .filter(|ttl| *ttl > 0)
            .ok_or_else(|| StsError::InvalidGrant("ID-JAG expired before issuance".into()))?,
    );
    let jti = uuid::Uuid::new_v4().to_string();

    // Consume the single-use grant now that every check has passed, so a benign
    // failure above never burns a valid ID-JAG. Atomic per-jti: concurrent
    // redemptions of the same grant cannot both succeed.
    let unique = if let Some(profile) = profile {
        state
            .config
            .mcp_replay
            .as_ref()
            .ok_or_else(|| StsError::ServerError("MCP replay storage is not configured".into()))?
            .record_unique(&profile.issuer, &id_jag.issuer, &id_jag.jti, id_jag.expires_at, now)
            .await?
    } else {
        state
            .replay
            .record_unique(&id_jag.jti, id_jag.expires_at, now)
    };
    if !unique {
        return Err(StsError::InvalidGrant("ID-JAG has already been redeemed".to_string()));
    }

    // Preserve the grant's delegation actor (RFC 8693 §4.1): a modern ID-JAG
    // carries `act` (the agent DID bound at issuance), which passes through
    // unchanged; a legacy ID-JAG without `act` falls back to the redeeming
    // client as the implicit actor.
    let (grant_act, redeem_actor): (Option<Value>, Option<&str>) = match &id_jag.act {
        Some(act) => (Some(act.clone()), None),
        None => (None, Some(client_id.as_str())),
    };
    let token_claims = build_access_token_claims(AccessTokenParams {
        issuer: &issuer,
        subject: &subject,
        subject_act: grant_act,
        actor_sub: redeem_actor,
        client_id: Some(&client_id),
        audience: audience.as_deref(),
        scopes: &scopes,
        issued_at: now,
        ttl_secs: ttl,
        jti: &jti,
    });
    let token = if profile.is_some() {
        state
            .signer
            .sign_mcp_access_token(&token_claims)
            .await?
    } else {
        state
            .signer
            .sign(&token_claims)
            .await?
    };
    emit_issuance_audit(
        "jwt_bearer",
        &client_id,
        &subject,
        audience.as_deref(),
        TOKEN_TYPE_ACCESS_TOKEN,
        &scopes,
        Some(&client_id),
        &jti,
    );
    Ok(TokenExchangeResponse {
        access_token: token,
        issued_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
        token_type: BEARER.to_string(),
        expires_in: Some(ttl),
        scope: scope_string(&scopes),
    })
}

async fn verify_assertion(
    state: &StsState,
    token_type: TokenType,
    token: &str,
    profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>,
) -> Result<Value, StsError> {
    if token_type.is_jwt_shaped() {
        match profile {
            Some(profile) => {
                state
                    .verifier
                    .verify_mcp_jwt(token, profile)
                    .await
            }
            None => {
                state
                    .verifier
                    .verify_jwt(token)
                    .await
            }
        }
    } else if token_type == TokenType::Vp {
        state
            .vp_verifier
            .verify_vp(token)
            .await
    } else {
        Err(StsError::UnsupportedTokenType(format!("cannot verify token of type {}", token_type.as_urn())))
    }
}

/// Enforce the managed connection's audience allowlist. An empty allowlist is
/// unrestricted; a non-empty allowlist requires a matching `audience`/`resource`.
///
/// The gateway's own issuer identifier (`self_issuer`) is **always** accepted: a
/// loopback ID-JAG is by definition audienced to this gateway as the resource
/// authorization server, so requiring an operator to allow-list the gateway's own
/// identity would be redundant ceremony. Audiences for any *other* authorization
/// server still require an explicit allowlist entry.
fn enforce_audience(
    record: &StsClientRecord,
    audience: Option<&str>,
    self_issuer: Option<&str>,
) -> Result<(), StsError> {
    if let (Some(a), Some(iss)) = (audience, self_issuer)
        && a == iss
    {
        return Ok(());
    }
    if record
        .allowed_audiences
        .is_empty()
    {
        return Ok(());
    }
    match audience {
        Some(a)
            if record
                .allowed_audiences
                .iter()
                .any(|x| x == a) =>
        {
            Ok(())
        }
        Some(a) => Err(StsError::InvalidTarget(format!("audience not allowed: {a}"))),
        None => Err(StsError::InvalidTarget("audience or resource is required".to_string())),
    }
}

/// Enforce a managed connection's optional subject-audience allowlist against a
/// verified JWT subject token. An empty allowlist is unrestricted; otherwise the
/// token's `aud` (string or array) must include one of the allowed values. This
/// is opt-in — RFC 8693 subject tokens are often minted for a different audience.
fn enforce_subject_audience(
    record: &StsClientRecord,
    subject_claims: &Value,
) -> Result<(), StsError> {
    if record
        .allowed_subject_audiences
        .is_empty()
    {
        return Ok(());
    }
    let allowed = |aud: &str| {
        record
            .allowed_subject_audiences
            .iter()
            .any(|a| a == aud)
    };
    let matches = match subject_claims.get("aud") {
        Some(Value::String(aud)) => allowed(aud),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .any(allowed),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StsError::InvalidGrant("subject_token audience is not accepted by this connection".to_string()))
    }
}

fn resolve_client_credentials(
    headers: &HeaderMap,
    form: &TokenEndpointForm,
) -> (Option<String>, Option<String>) {
    if let Some((id, secret)) = parse_basic_auth(headers) {
        return (Some(id), Some(secret));
    }
    (form.client_id.clone(), form.client_secret.clone())
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// Build an in-memory `Static` verification strategy from the gateway's own
/// published JWKS, so a JWT this gateway issued (matched by `iss`) is verified
/// against our own key without needing a persisted verification-strategy record.
pub(crate) fn gateway_self_trust_strategy(
    issuer: &str,
    jwks: &Value,
) -> Result<crate::jwt_bearer::models::JwtVerificationStrategy, StsError> {
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| StsError::ServerError("gateway jwks has no keys array".to_string()))?;
    let parsed = keys
        .iter()
        .map(|k| serde_json::from_value(k.clone()))
        .collect::<Result<Vec<crate::jwt_bearer::jwks::Jwk>, _>>()
        .map_err(|e| StsError::ServerError(format!("gateway jwk parse failed: {e}")))?;
    let now = chrono::Utc::now();
    Ok(crate::jwt_bearer::models::JwtVerificationStrategy {
        id: "sts-gateway-self-trust".to_string(),
        tenant_id: None,
        name: "gateway self-trust (auto)".to_string(),
        expected_issuer: issuer.to_string(),
        jwks_source: crate::jwt_bearer::models::JwksSource::Static { jwks: parsed },
        created_at: now,
        updated_at: now,
    })
}

/// Read the (unverified) `iss` from a JWT for strategy selection. The signature
/// is verified afterwards against the resolved strategy — this only routes.
fn decode_unverified_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    value
        .get("iss")?
        .as_str()
        .map(|s| s.to_string())
}

/// Read the JOSE `typ` header from a compact JWS. Only meaningful after the
/// signature has verified — the header is part of the signed input, so a
/// verified token's `typ` is authentic and cannot be forged in transit.
fn parse_jose_typ(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let _payload = parts.next()?;
    let _signature = parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    value
        .get("typ")?
        .as_str()
        .map(|s| s.to_string())
}

/// Whether a compact JWS declares the ID-JAG JOSE `typ`, compared as an RFC 7515
/// §4.1.9 media type: case-insensitive, with an optional `application/` prefix
/// and ignoring parameters, so it is deliberately broader than the exact `typ`
/// jwt-bearer redemption accepts. It may read the header before verification:
/// signature verification follows, so a re-spelled header can neither avoid a
/// rejection nor gain admission.
fn declares_id_jag_typ(token: &str) -> bool {
    parse_jose_typ(token).is_some_and(|typ| {
        let typ = typ.to_ascii_lowercase();
        let media_type = typ
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        media_type
            .strip_prefix("application/")
            .unwrap_or(media_type)
            == ID_JAG_JWT_TYP
    })
}

/// A verified token's `exp` in whole seconds. The JWT verifier also accepts a
/// fractional NumericDate, so one is rounded down rather than ignored.
fn claimed_expiry(claims: &Value) -> Option<u64> {
    let exp = claims.get("exp")?;
    exp.as_u64().or_else(|| {
        exp.as_f64()
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
            .map(|seconds| seconds as u64)
    })
}

/// Refuse a verified exchange subject or actor that this gateway signed, under
/// its DID or its MCP issuer, unless the legacy endpoint receives one of its own
/// access tokens (`typ: JWT`). Its ID-JAGs are consumed only through single-use
/// jwt-bearer redemption, its peer issuer attestations never become subjects,
/// and the MCP profile exchanges only external assertions.
fn reject_self_issued(
    state: &StsState,
    gateway_did: &str,
    profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>,
    role: &str,
    token: &str,
    claims: &Value,
) -> Result<(), StsError> {
    let Some(issuer) = claims
        .get("iss")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let is_mcp_issuer = |profile: Option<&crate::sts::mcp_profile::McpIssuerProfile>| {
        profile.is_some_and(|profile| profile.issuer == issuer)
    };
    let self_issued = issuer == gateway_did
        || is_mcp_issuer(profile)
        || is_mcp_issuer(
            state
                .config
                .mcp_issuer
                .as_ref(),
        );
    let legacy_access_token = profile.is_none()
        && issuer == gateway_did
        && parse_jose_typ(token).is_some_and(|typ| typ.eq_ignore_ascii_case("JWT"));
    if !self_issued || legacy_access_token {
        return Ok(());
    }
    Err(StsError::UnsupportedTokenType(match profile {
        Some(_) => format!("MCP exchange does not accept a {role} token issued by this gateway"),
        None => format!(
            "a {role} token issued by this gateway must be one of its access tokens; redeem an ID-JAG through jwt-bearer"
        ),
    }))
}

fn scope_string(scopes: &[String]) -> Option<String> {
    if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    }
}

fn grant_label(grant_type: Option<&str>) -> &'static str {
    match grant_type {
        Some(GRANT_TYPE_TOKEN_EXCHANGE) => "token_exchange",
        Some(GRANT_TYPE_JWT_BEARER) => "jwt_bearer",
        _ => "other",
    }
}

/// The client source address for throttling, resolved from proxy-forwarded
/// headers (`X-Forwarded-For` first entry, then RFC 7239 `Forwarded for=`).
pub(super) fn client_source_ip(headers: &HeaderMap) -> Option<String> {
    first_forwarded_token(headers, "x-forwarded-for").or_else(|| forwarded_directive(headers, "for"))
}

/// A `429 Too Many Requests` response carrying `Retry-After` for a throttled caller.
fn throttled_response(retry_after: u64) -> Response {
    let body = json!({
        "error": "temporarily_unavailable",
        "error_description": "too many token requests; retry later",
    });
    let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    let out = response.headers_mut();
    if let Ok(v) = header::HeaderValue::from_str(&retry_after.to_string()) {
        out.insert(header::RETRY_AFTER, v);
    }
    out.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response
}

/// Emit one structured audit event per successful issuance under the
/// `sts_audit` target: the agent (client), the subject on whose behalf, the
/// audience, the issued token type, granted scope, the acting party, and `jti`.
#[allow(clippy::too_many_arguments)]
fn emit_issuance_audit(
    grant: &str,
    client_id: &str,
    subject: &str,
    audience: Option<&str>,
    issued_token_type: &str,
    scopes: &[String],
    actor: Option<&str>,
    jti: &str,
) {
    tracing::info!(
        target: "sts_audit",
        grant = grant,
        client_id = client_id,
        subject = subject,
        audience = audience.unwrap_or_default(),
        issued_token_type = issued_token_type,
        scope = scopes.join(" "),
        actor = actor.unwrap_or_default(),
        jti = jti,
        "sts issuance"
    );
}

pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Length-checked, byte-wise constant-time string comparison for secrets.
pub(crate) fn constant_time_eq(
    a: &str,
    b: &str,
) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sts::types::{TOKEN_TYPE_ID_JAG, TOKEN_TYPE_JWT};

    /// Signer mock: `sign` returns the claim set serialized as JSON so a test can
    /// inspect exactly what would have been signed.
    struct MockSigner {
        issuer: String,
    }

    #[async_trait::async_trait]
    impl StsSigner for MockSigner {
        async fn issuer(&self) -> Result<String, StsError> {
            Ok(self.issuer.clone())
        }
        async fn sign(
            &self,
            claims: &Value,
        ) -> Result<String, StsError> {
            Ok(serde_json::to_string(claims).unwrap())
        }
        async fn sign_id_jag(
            &self,
            claims: &Value,
        ) -> Result<String, StsError> {
            Ok(serde_json::to_string(claims).unwrap())
        }
        async fn public_jwks(&self) -> Result<Value, StsError> {
            Ok(json!({ "keys": [] }))
        }
    }

    /// Verifier mock: maps a raw token string to a preset claim set.
    struct MockVerifier {
        claims: HashMap<String, Value>,
    }

    #[async_trait::async_trait]
    impl StsSubjectVerifier for MockVerifier {
        async fn verify_jwt(
            &self,
            token: &str,
        ) -> Result<Value, StsError> {
            self.claims
                .get(token)
                .cloned()
                .ok_or_else(|| StsError::InvalidGrant("unknown test token".to_string()))
        }
    }

    /// VP verifier mock: maps a raw VP string to a preset claim set.
    struct MockVpVerifier {
        vps: HashMap<String, Value>,
    }

    #[async_trait::async_trait]
    impl StsVpVerifier for MockVpVerifier {
        async fn verify_vp(
            &self,
            vp: &str,
        ) -> Result<Value, StsError> {
            self.vps
                .get(vp)
                .cloned()
                .ok_or_else(|| StsError::InvalidGrant("unknown test vp".to_string()))
        }
    }

    fn state_with(
        claims: HashMap<String, Value>,
        registry: InMemoryStsClientRegistry,
    ) -> StsState {
        StsState {
            signer: Arc::new(MockSigner {
                issuer: "did:webvh:example:gw".to_string(),
            }),
            verifier: Arc::new(MockVerifier { claims }),
            vp_verifier: Arc::new(DisabledVpVerifier),
            clients: Arc::new(registry),
            policy: Arc::new(AllowAllPolicyEvaluator),
            trust_checker: Arc::new(DisabledTrustChecker),
            replay: Arc::new(crate::sts::replay::ReplayGuard::new()),
            throttle: Arc::new(crate::sts::throttle::TokenEndpointThrottle::from_config(
                &crate::config::types::TokenEndpointThrottleConfig::default(),
            )),
            resource_owners: Arc::new(crate::sts::resource_owners::NoResourceOwners),
            config: StsConfig {
                mcp_replay: Some(Arc::new(
                    crate::sts::replay::McpReplay::new(&crate::sts::replay::McpReplayConfig::default(), None).unwrap(),
                )),
                ..StsConfig::default()
            },
        }
    }

    /// Build a compact JWS-shaped ID-JAG assertion carrying the explicit
    /// `oauth-id-jag+jwt` `typ` header and `claims` as the payload. The mock
    /// verifier maps this exact string back to `claims`; the handler reads the
    /// authentic `typ` from the header segment.
    fn id_jag_assertion(claims: &Value) -> String {
        typed_assertion(ID_JAG_JWT_TYP, claims)
    }

    /// Like [`id_jag_assertion`] but with a plain `typ: JWT` header, for an
    /// assertion that is not an ID-JAG.
    fn plain_jwt_assertion(claims: &Value) -> String {
        typed_assertion("JWT", claims)
    }

    /// A compact JWS-shaped assertion with the given JOSE `typ` header.
    fn typed_assertion(
        typ: &str,
        claims: &Value,
    ) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({ "alg": "EdDSA", "typ": typ, "kid": "key-1" }).to_string());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        format!("{header}.{payload}.sig")
    }

    fn client(
        record: StsClientRecord,
        secret: Option<&str>,
    ) -> InMemoryStsClientRegistry {
        InMemoryStsClientRegistry::new().with_client(secret.map(|s| s.to_string()), record)
    }

    fn base_record() -> StsClientRecord {
        StsClientRecord {
            client_id: "agent-client".to_string(),
            ..Default::default()
        }
    }

    fn exchange_form() -> TokenEndpointForm {
        TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_TOKEN_EXCHANGE.to_string()),
            subject_token: Some("subject-tok".to_string()),
            subject_token_type: Some(TOKEN_TYPE_JWT.to_string()),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn mcp_profile_issuance_preserves_legacy_tokens_and_binds_the_resource() {
        let profile = crate::sts::mcp_profile::McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let resource = "https://gateway.example/surfaces/alpha";
        let mut record = base_record();
        record.issue_id_jag = true;
        record.allowed_audiences = vec![resource.into()];
        record.allowed_scopes = vec!["read".into()];
        record.allowed_subject_audiences = vec!["identity-client".into()];
        let expiry = now_secs() + 90;
        let claims = HashMap::from([(
            "subject-tok".into(),
            json!({
                "iss": "https://idp.example/", "sub": "user-123", "aud": "identity-client", "exp": expiry
            }),
        )]);
        let state = state_with(claims, client(record, Some("s3cret")));
        let mut form = exchange_form();
        form.resource = Some(resource.into());
        form.scope = Some("read".into());
        let response = dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile))
            .await
            .unwrap();
        let token: Value = serde_json::from_str(&response.access_token).unwrap();
        assert_eq!(token["iss"], profile.issuer);
        assert_eq!(token["aud"], resource);
        assert_eq!(token["act"]["sub"], "agent-client");
        assert_eq!(token["scope"], "read");
        assert!(token["exp"].as_u64().unwrap() <= expiry);

        let legacy = dispatch(&state, &HeaderMap::new(), form.clone())
            .await
            .unwrap();
        let token: Value = serde_json::from_str(&legacy.access_token).unwrap();
        assert_eq!(token["iss"], "did:webvh:example:gw");
        assert_eq!(token["aud"], resource);

        form.requested_token_type = Some(TOKEN_TYPE_ID_JAG.into());
        form.audience = Some(profile.issuer.clone());
        let response = dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile))
            .await
            .unwrap();
        let grant: Value = serde_json::from_str(&response.access_token).unwrap();
        assert_eq!(grant["iss"], profile.issuer);
        assert_eq!(grant["aud"], profile.issuer);
        assert_eq!(grant["resource"], resource);
        assert_eq!(response.issued_token_type, TOKEN_TYPE_ID_JAG);
        for (resource_value, scope, audience) in [
            (None, "read", Some(profile.issuer.clone())),
            (Some("https://gateway.example/surfaces/other".into()), "read", Some(profile.issuer.clone())),
            (Some(resource.into()), "admin", Some(profile.issuer.clone())),
            (Some(resource.into()), "read", Some(resource.into())),
        ] {
            form.resource = resource_value;
            form.scope = Some(scope.into());
            form.audience = audience;
            assert!(
                dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn mcp_profile_http_endpoint_is_opt_in_and_uses_shared_issuance() {
        let profile = crate::sts::mcp_profile::McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let resource = "https://gateway.example/surfaces/alpha";
        let mut record = base_record();
        record.allowed_audiences = vec![resource.into()];
        record.allowed_subject_audiences = vec!["identity-client".into()];
        let claims = HashMap::from([(
            "subject-tok".into(),
            json!({
                "iss": "https://idp.example/", "sub": "user-123", "aud": "identity-client", "exp": now_secs() + 90
            }),
        )]);
        let mut state = state_with(claims, client(record, Some("s3cret")));
        let mut form = exchange_form();
        form.resource = Some(resource.into());
        let response = mcp_token_endpoint(
            State(state.clone()),
            HeaderMap::new(),
            crate::sts::mcp_profile::McpTokenForm(form.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        state.config.mcp_issuer = Some(profile.clone());
        let response = mcp_token_endpoint(
            State(state.clone()),
            HeaderMap::new(),
            crate::sts::mcp_profile::McpTokenForm(form.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let response: TokenExchangeResponse = serde_json::from_slice(&body).unwrap();
        let claims: Value = serde_json::from_str(&response.access_token).unwrap();
        assert_eq!(claims["iss"], profile.issuer);
        assert_eq!(claims["aud"], resource);
        let response = token_endpoint(State(state.clone()), HeaderMap::new(), Form(form.clone())).await;
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let response: TokenExchangeResponse = serde_json::from_slice(&body).unwrap();
        let claims: Value = serde_json::from_str(&response.access_token).unwrap();
        assert_eq!(claims["iss"], "did:webvh:example:gw");
        form.grant_type = Some("authorization_code".into());
        let response =
            mcp_token_endpoint(State(state), HeaderMap::new(), crate::sts::mcp_profile::McpTokenForm(form)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn mcp_profile_redemption_rejects_resource_scope_changes_and_replay() {
        let profile = crate::sts::mcp_profile::McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let resource = "https://gateway.example/surfaces/alpha";
        let expiry = now_secs() + 90;
        let grant = json!({
            "iss": "https://idp.example/", "sub": "user-123", "aud": profile.issuer,
            "resource": resource, "exp": expiry, "jti": "profile-grant", "scope": "read",
            "client_id": "agent-client", "act": {"sub": "verified-agent"}
        });
        let assertion = id_jag_assertion(&grant);
        let mut record = base_record();
        record.allowed_audiences = vec![resource.into(), "https://gateway.example/surfaces/other".into()];
        record.allowed_scopes = vec!["read".into(), "write".into()];
        let state = state_with(HashMap::from([(assertion.clone(), grant)]), client(record, Some("s3cret")));
        let mut form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.into()),
            assertion: Some(assertion),
            client_id: Some("agent-client".into()),
            client_secret: Some("s3cret".into()),
            resource: Some("https://gateway.example/surfaces/other".into()),
            scope: Some("read".into()),
            ..Default::default()
        };
        assert!(matches!(
            dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile)).await,
            Err(StsError::InvalidTarget(_))
        ));
        form.resource = Some(resource.into());
        form.scope = Some("write".into());
        assert!(matches!(
            dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile)).await,
            Err(StsError::InvalidScope(_))
        ));
        form.scope = Some("read".into());
        let response = dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile))
            .await
            .unwrap();
        let token: Value = serde_json::from_str(&response.access_token).unwrap();
        assert_eq!(token["iss"], profile.issuer);
        assert_eq!(token["aud"], resource);
        assert_eq!(token["act"]["sub"], "verified-agent");
        assert!(token["exp"].as_u64().unwrap() <= expiry);
        assert!(matches!(
            dispatch_with_profile(&state, &HeaderMap::new(), form, Some(&profile)).await,
            Err(StsError::InvalidGrant(_))
        ));
    }

    /// Minting checks resource ownership again, so a tenant client created
    /// before another tenant's surface declared its audience cannot mint for it.
    #[tokio::test]
    async fn mcp_profile_refuses_a_resource_another_tenant_serves_at_mint_time() {
        struct Declared(Vec<Option<String>>);

        #[async_trait::async_trait]
        impl crate::sts::resource_owners::StsResourceOwners for Declared {
            async fn declaring_tenants(
                &self,
                _resource: &str,
            ) -> anyhow::Result<Vec<Option<String>>> {
                Ok(self.0.clone())
            }
        }

        let profile = crate::sts::mcp_profile::McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let resource = "https://gateway.example/surfaces/b";
        let mut record = base_record();
        record.tenant_id = Some("tenant-a".into());
        record.allowed_audiences = vec![resource.into()];
        record.allowed_scopes = vec!["read".into()];
        record.allowed_subject_audiences = vec!["identity-client".into()];
        let grant = json!({
            "iss": "https://idp.example/", "sub": "user-123", "aud": profile.issuer,
            "resource": resource, "exp": now_secs() + 90, "jti": "tenant-grant", "scope": "read",
            "client_id": "agent-client", "act": {"sub": "verified-agent"}
        });
        let assertion = id_jag_assertion(&grant);
        let claims = HashMap::from([
            (
                "subject-tok".to_string(),
                json!({"iss": "https://idp.example/", "sub": "user-123", "aud": "identity-client", "exp": now_secs() + 90}),
            ),
            (assertion.clone(), grant),
        ]);
        let mut exchange = exchange_form();
        exchange.resource = Some(resource.into());
        exchange.scope = Some("read".into());
        let redemption = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.into()),
            assertion: Some(assertion),
            client_id: Some("agent-client".into()),
            client_secret: Some("s3cret".into()),
            resource: Some(resource.into()),
            scope: Some("read".into()),
            ..Default::default()
        };

        let mut state = state_with(claims, client(record, Some("s3cret")));
        state.resource_owners = Arc::new(Declared(vec![Some("tenant-b".into())]));
        for form in [exchange.clone(), redemption] {
            assert!(matches!(
                dispatch_with_profile(&state, &HeaderMap::new(), form, Some(&profile)).await,
                Err(StsError::InvalidTarget(_))
            ));
        }
        state.resource_owners = Arc::new(Declared(vec![Some("tenant-a".into())]));
        assert!(
            dispatch_with_profile(&state, &HeaderMap::new(), exchange, Some(&profile))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn mcp_profile_exchange_rejects_id_jag_subject_and_actor_tokens() {
        let profile = crate::sts::mcp_profile::McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let resource = "https://gateway.example/surfaces/alpha";
        let expiry = now_secs() + 90;
        // The client allows the grant's audience as a subject audience, so only
        // the JOSE `typ` distinguishes the grant from an identity assertion.
        let grant = json!({
            "iss": "https://idp.example/", "sub": "user-123", "aud": profile.issuer, "resource": resource,
            "exp": expiry, "jti": "exchanged-grant", "scope": "read", "client_id": "agent-client"
        });
        let identity =
            json!({ "iss": "https://idp.example/", "sub": "user-123", "aud": profile.issuer, "exp": expiry });
        let assertion = plain_jwt_assertion(&identity);
        let grants =
            [ID_JAG_JWT_TYP, "application/oauth-id-jag+jwt", "OAuth-ID-JAG+JWT", "oauth-id-jag+jwt; charset=utf-8"]
                .map(|typ| typed_assertion(typ, &grant));
        let mut claims = HashMap::from([(assertion.clone(), identity)]);
        claims.extend(
            grants
                .iter()
                .map(|token| (token.clone(), grant.clone())),
        );
        let mut record = base_record();
        record.allowed_audiences = vec![resource.into()];
        record.allowed_scopes = vec!["read".into()];
        record.allowed_subject_audiences = vec![profile.issuer.clone()];
        let state = state_with(claims, client(record, Some("s3cret")));
        let mut form = exchange_form();
        form.subject_token = Some(assertion.clone());
        form.resource = Some(resource.into());
        form.scope = Some("read".into());
        dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile))
            .await
            .expect("a plain JWT subject is exchanged");
        let mut with_actor = form.clone();
        with_actor.actor_token = Some(assertion.clone());
        with_actor.actor_token_type = Some(TOKEN_TYPE_JWT.into());
        dispatch_with_profile(&state, &HeaderMap::new(), with_actor.clone(), Some(&profile))
            .await
            .expect("a plain JWT actor is exchanged");

        // An ID-JAG is refused whatever type the client declares, and a declared
        // id-jag is refused even when the token is a plain JWT.
        let refused = grants
            .iter()
            .flat_map(|token| [(token, TOKEN_TYPE_JWT), (token, TOKEN_TYPE_ID_TOKEN)])
            .chain([(&assertion, TOKEN_TYPE_ID_JAG)]);
        for (token, declared) in refused {
            let mut as_subject = form.clone();
            as_subject.subject_token = Some(token.clone());
            as_subject.subject_token_type = Some(declared.into());
            let mut as_actor = with_actor.clone();
            as_actor.actor_token = Some(token.clone());
            as_actor.actor_token_type = Some(declared.into());
            for (role, request) in [("subject", as_subject), ("actor", as_actor)] {
                let error = dispatch_with_profile(&state, &HeaderMap::new(), request, Some(&profile))
                    .await
                    .expect_err("an ID-JAG must be redeemed through jwt-bearer");
                assert!(matches!(error, StsError::UnsupportedTokenType(_)), "{role} declared as {declared}: {error:?}");
            }
        }
    }

    #[test]
    fn id_jag_typ_is_matched_as_a_media_type() {
        let claims = json!({ "sub": "user-123" });
        for typ in [
            ID_JAG_JWT_TYP,
            "application/oauth-id-jag+jwt",
            "Application/OAUTH-ID-JAG+JWT",
            " oauth-id-jag+jwt ; charset=utf-8",
        ] {
            assert!(declares_id_jag_typ(&typed_assertion(typ, &claims)), "{typ}");
        }
        for typ in ["JWT", "at+jwt", "oauth-id-jag+jwt-extra", "x-oauth-id-jag+jwt", "text/oauth-id-jag+jwt", ""] {
            assert!(!declares_id_jag_typ(&typed_assertion(typ, &claims)), "{typ}");
        }
        assert!(!declares_id_jag_typ("subject-tok"));
        assert!(!declares_id_jag_typ(&format!(
            "{}.e30.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA"}"#)
        )));
    }

    #[tokio::test]
    async fn mcp_profile_exchange_rejects_gateway_issued_subjects_and_actors() {
        let profile = crate::sts::mcp_profile::McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        let resource = "https://gateway.example/surfaces/alpha";
        let exp = now_secs() + 90;
        let identity_claims = json!({ "iss": "https://idp.example/", "sub": "user-123", "aud": resource, "exp": exp });
        let identity = plain_jwt_assertion(&identity_claims);
        let gateway_tokens = [
            ("JWT", json!({ "iss": "did:webvh:example:gw", "sub": "user-123", "aud": resource, "exp": exp })),
            ("at+jwt", json!({ "iss": profile.issuer, "sub": "user-123", "aud": resource, "exp": exp })),
        ]
        .map(|(typ, claims)| (typed_assertion(typ, &claims), claims));
        let mut claims = HashMap::from([(identity.clone(), identity_claims)]);
        claims.extend(gateway_tokens.iter().cloned());
        let mut record = base_record();
        record.allowed_audiences = vec![resource.into()];
        record.allowed_subject_audiences = vec![resource.into()];
        let state = state_with(claims, client(record, Some("s3cret")));
        let mut form = exchange_form();
        form.subject_token = Some(identity.clone());
        form.resource = Some(resource.into());
        dispatch_with_profile(&state, &HeaderMap::new(), form.clone(), Some(&profile))
            .await
            .expect("an external identity assertion is exchanged");

        for (token, _) in &gateway_tokens {
            let mut as_subject = form.clone();
            as_subject.subject_token = Some(token.clone());
            let mut as_actor = form.clone();
            as_actor.actor_token = Some(token.clone());
            as_actor.actor_token_type = Some(TOKEN_TYPE_JWT.into());
            for (role, request) in [("subject", as_subject), ("actor", as_actor)] {
                let error = dispatch_with_profile(&state, &HeaderMap::new(), request, Some(&profile))
                    .await
                    .expect_err("a gateway-issued token is not an identity assertion");
                assert!(matches!(error, StsError::UnsupportedTokenType(_)), "{role}: {error:?}");
            }
        }
    }

    #[tokio::test]
    async fn token_exchange_accepts_only_access_tokens_among_gateway_issued_tokens() {
        let gateway = "did:webvh:example:gw";
        let profile_issuer = "https://gateway.example/api/oauth2/mcp";
        let exp = now_secs() + 300;
        let issued_by = |iss: &str| json!({ "iss": iss, "sub": "did:example:user", "exp": exp });
        let access_token = typed_assertion("JWT", &issued_by(gateway));
        let external_grant = typed_assertion(ID_JAG_JWT_TYP, &issued_by("https://idp.example/"));
        let refused = [
            (ID_JAG_JWT_TYP, gateway),
            (crate::gateways::issuer_attestation::ISSUER_ATTESTATION_TYP, gateway),
            ("at+jwt", profile_issuer),
            ("JWT", profile_issuer),
        ]
        .map(|(typ, iss)| (typed_assertion(typ, &issued_by(iss)), issued_by(iss)));
        let mut claims = HashMap::from([
            ("subject-tok".to_string(), json!({ "sub": "did:example:user" })),
            (access_token.clone(), issued_by(gateway)),
            (external_grant.clone(), issued_by("https://idp.example/")),
        ]);
        claims.extend(refused.iter().cloned());
        let mut state = state_with(claims, client(base_record(), Some("s3cret")));
        state.config.mcp_issuer = Some(crate::sts::mcp_profile::McpIssuerProfile { issuer: profile_issuer.into() });

        for accepted in [&access_token, &external_grant] {
            let mut as_subject = exchange_form();
            as_subject.subject_token = Some(accepted.clone());
            let mut as_actor = exchange_form();
            as_actor.actor_token = Some(accepted.clone());
            as_actor.actor_token_type = Some(TOKEN_TYPE_JWT.into());
            for (role, request) in [("subject", as_subject), ("actor", as_actor)] {
                dispatch(&state, &HeaderMap::new(), request)
                    .await
                    .unwrap_or_else(|error| panic!("{role} must be accepted: {error:?}"));
            }
        }
        for (token, _) in &refused {
            for declared in [TOKEN_TYPE_JWT, TOKEN_TYPE_ID_JAG] {
                let mut as_subject = exchange_form();
                as_subject.subject_token = Some(token.clone());
                as_subject.subject_token_type = Some(declared.into());
                let mut as_actor = exchange_form();
                as_actor.actor_token = Some(token.clone());
                as_actor.actor_token_type = Some(declared.into());
                for (role, request) in [("subject", as_subject), ("actor", as_actor)] {
                    let error = dispatch(&state, &HeaderMap::new(), request)
                        .await
                        .expect_err("only the gateway's own access tokens are exchanged");
                    assert!(
                        matches!(error, StsError::UnsupportedTokenType(_)),
                        "{role} declared as {declared}: {error:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn token_exchange_never_outlives_its_subject_or_actor() {
        let now = now_secs();
        let claims = HashMap::from([
            ("subject-tok".to_string(), json!({ "sub": "did:example:user", "exp": now + 30 })),
            ("long-subject".to_string(), json!({ "sub": "did:example:user", "exp": now + 3600 })),
            ("actor-tok".to_string(), json!({ "sub": "did:example:agent", "exp": now + 20 })),
            ("expired".to_string(), json!({ "sub": "did:example:user", "exp": now - 1 })),
            ("no-exp".to_string(), json!({ "sub": "did:example:user" })),
            ("fractional".to_string(), json!({ "sub": "did:example:user", "exp": now as f64 + 30.5 })),
        ]);
        let mut record = base_record();
        record.issue_id_jag = true;
        let state = state_with(claims, client(record, Some("s3cret")));
        let headers = HeaderMap::new();
        let issue = |subject: &str, actor: Option<&str>, requested: Option<&str>| {
            let mut form = exchange_form();
            form.subject_token = Some(subject.into());
            form.actor_token = actor.map(Into::into);
            form.actor_token_type = actor.map(|_| TOKEN_TYPE_JWT.into());
            form.requested_token_type = requested.map(Into::into);
            form.audience = requested.map(|_| "did:webvh:example:gw".into());
            dispatch(&state, &headers, form)
        };

        let response = issue("subject-tok", None, None)
            .await
            .unwrap();
        let token: Value = serde_json::from_str(&response.access_token).unwrap();
        assert!(response.expires_in.unwrap() <= 30);
        assert!(token["exp"].as_u64().unwrap() <= now + 30);
        let grant = issue("subject-tok", None, Some(TOKEN_TYPE_ID_JAG))
            .await
            .unwrap();
        assert!(grant.expires_in.unwrap() <= 30, "an ID-JAG is capped as well");
        let response = issue("long-subject", Some("actor-tok"), None)
            .await
            .unwrap();
        assert!(response.expires_in.unwrap() <= 20, "the actor's expiry caps the token");
        assert!(matches!(issue("expired", None, None).await, Err(StsError::InvalidGrant(_))));
        let response = issue("fractional", None, None)
            .await
            .unwrap();
        assert!(response.expires_in.unwrap() <= 30, "a fractional exp caps the token as well");
        let response = issue("no-exp", Some("actor-tok"), None)
            .await
            .unwrap();
        assert!(response.expires_in.unwrap() <= 20, "the actor's expiry caps a subject without exp");
        let response = issue("no-exp", None, None)
            .await
            .unwrap();
        assert_eq!(response.expires_in, Some(300), "a subject without exp keeps the default lifetime");
    }

    #[tokio::test]
    async fn subject_token_type_allowlist_counts_id_jag_typed_tokens_as_id_jag() {
        let grant_claims = json!({ "iss": "https://idp.example/", "sub": "did:example:user", "exp": now_secs() + 300 });
        let grant = id_jag_assertion(&grant_claims);
        let identity = plain_jwt_assertion(&grant_claims);
        let claims = HashMap::from([(grant.clone(), grant_claims.clone()), (identity.clone(), grant_claims)]);
        for (allowed, token, accepted) in
            [(TOKEN_TYPE_JWT, &identity, true), (TOKEN_TYPE_JWT, &grant, false), (TOKEN_TYPE_ID_JAG, &grant, true)]
        {
            let mut record = base_record();
            record.allowed_subject_token_types = vec![allowed.into()];
            let state = state_with(claims.clone(), client(record, Some("s3cret")));
            let mut form = exchange_form();
            form.subject_token = Some(token.clone());
            let result = dispatch(&state, &HeaderMap::new(), form).await;
            if accepted {
                assert!(result.is_ok(), "allowlist [{allowed}]: {result:?}");
            } else {
                assert!(matches!(result, Err(StsError::UnauthorizedClient(_))), "allowlist [{allowed}]: {result:?}");
            }
        }
    }

    #[tokio::test]
    async fn token_exchange_mints_access_token_with_implicit_actor() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let resp = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .expect("exchange succeeds");

        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
        assert_eq!(resp.token_type, "Bearer");
        // MockSigner echoes the claim set as JSON.
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["iss"], "did:webvh:example:gw");
        assert_eq!(minted["sub"], "did:example:user");
        // Delegation by default: the calling client is the implicit actor.
        assert_eq!(minted["act"], json!({ "sub": "agent-client" }));
        assert_eq!(minted["client_id"], "agent-client");
    }

    #[tokio::test]
    async fn token_exchange_impersonation_omits_act() {
        let mut record = base_record();
        record.allow_impersonation = true;
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let state = state_with(claims, client(record, Some("s3cret")));

        let resp = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .expect("exchange succeeds");
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert!(minted.get("act").is_none(), "impersonation mode omits act");
    }

    #[tokio::test]
    async fn token_exchange_nests_actor_over_subject_chain() {
        let mut record = base_record();
        record.allow_impersonation = true; // isolate explicit-actor behaviour
        let mut claims = HashMap::new();
        claims.insert(
            "subject-tok".to_string(),
            json!({ "sub": "did:example:user", "act": { "sub": "did:example:assistant" } }),
        );
        claims.insert("actor-tok".to_string(), json!({ "sub": "did:example:analyst" }));
        let state = state_with(claims, client(record, Some("s3cret")));

        let mut form = exchange_form();
        form.actor_token = Some("actor-tok".to_string());
        form.actor_token_type = Some(TOKEN_TYPE_JWT.to_string());

        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("exchange succeeds");
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["act"], json!({ "sub": "did:example:analyst", "act": { "sub": "did:example:assistant" } }));
    }

    #[tokio::test]
    async fn token_exchange_rejects_bad_client_secret() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "u" }));
        let state = state_with(claims, client(base_record(), Some("right")));

        let mut form = exchange_form();
        form.client_secret = Some("wrong".to_string());
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_client");
    }

    #[tokio::test]
    async fn token_exchange_rejects_disallowed_audience() {
        let mut record = base_record();
        record.allowed_audiences = vec!["https://allowed.example".to_string()];
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "u" }));
        let state = state_with(claims, client(record, Some("s3cret")));

        let mut form = exchange_form();
        form.audience = Some("https://evil.example".to_string());
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_target");
    }

    #[test]
    fn enforce_audience_always_accepts_gateway_self_issuer() {
        let mut record = base_record();
        record.allowed_audiences = vec!["https://api.example.com".to_string()];
        let gw = "did:webvh:example:gw";

        // The gateway's own issuer is accepted even though it is absent from the
        // (non-empty) allowlist — a loopback ID-JAG is always audienced here.
        enforce_audience(&record, Some(gw), Some(gw)).expect("self issuer is always an allowed audience");
        // An allow-listed resource audience is still accepted.
        enforce_audience(&record, Some("https://api.example.com"), Some(gw)).expect("listed audience allowed");
        // Any other audience still requires an explicit allowlist entry.
        assert_eq!(
            enforce_audience(&record, Some("https://evil.example"), Some(gw))
                .unwrap_err()
                .error_code(),
            "invalid_target"
        );
    }

    #[tokio::test]
    async fn id_jag_issuance_accepts_gateway_self_audience_without_listing_it() {
        let mut record = base_record();
        record.issue_id_jag = true;
        // The client restricts audiences to a downstream API and does NOT list
        // the gateway's own DID; an ID-JAG audienced to the gateway (the resource
        // AS) must still issue.
        record.allowed_audiences = vec!["https://api.example.com".to_string()];
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let state = state_with(claims, client(record, Some("s3cret")));

        let mut form = exchange_form();
        form.requested_token_type = Some(TOKEN_TYPE_ID_JAG.to_string());
        form.audience = Some("did:webvh:example:gw".to_string()); // == the MockSigner issuer

        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("ID-JAG issuance with the gateway's own audience succeeds");
        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ID_JAG);
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["aud"], "did:webvh:example:gw");
    }

    #[tokio::test]
    async fn id_jag_issuance_requires_permission_and_audience() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));

        // Not permitted → unauthorized_client.
        let state = state_with(claims.clone(), client(base_record(), Some("s3cret")));
        let mut form = exchange_form();
        form.requested_token_type = Some(TOKEN_TYPE_ID_JAG.to_string());
        form.audience = Some("https://resource.example".to_string());
        let err = dispatch(&state, &HeaderMap::new(), form.clone())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "unauthorized_client");

        // Permitted → issues an ID-JAG.
        let mut record = base_record();
        record.issue_id_jag = true;
        let state = state_with(claims, client(record, Some("s3cret")));
        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("id-jag issued");
        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ID_JAG);
        assert_eq!(resp.token_type, "N_A");
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["aud"], "https://resource.example");
        assert_eq!(minted["client_id"], "agent-client");
    }

    #[tokio::test]
    async fn id_jag_issuance_embeds_delegation_actor() {
        // Binding an actor_token (the agent) embeds it as the ID-JAG's `act` so
        // the delegation survives into the grant and, later, the redeemed token.
        let mut record = base_record();
        record.issue_id_jag = true;
        record.allow_impersonation = true; // isolate the explicit actor_token
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        claims.insert("actor-tok".to_string(), json!({ "sub": "did:example:agent" }));
        let state = state_with(claims, client(record, Some("s3cret")));

        let mut form = exchange_form();
        form.requested_token_type = Some(TOKEN_TYPE_ID_JAG.to_string());
        form.audience = Some("did:webvh:example:gw".to_string());
        form.actor_token = Some("actor-tok".to_string());
        form.actor_token_type = Some(TOKEN_TYPE_JWT.to_string());

        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("id-jag issued");
        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ID_JAG);
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["act"], json!({ "sub": "did:example:agent" }));
    }

    #[tokio::test]
    async fn jwt_bearer_redeems_id_jag_for_access_token() {
        // A prior-issued ID-JAG addressed to this gateway.
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "agent-client",
            "scope": "reports.read",
            "jti": "grant-redeem",
            "exp": now_secs() + 120
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            ..Default::default()
        };
        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("redeem succeeds");
        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["sub"], "did:example:user");
        assert_eq!(minted["aud"], "https://target.example");
        assert_eq!(minted["act"], json!({ "sub": "agent-client" }));
        assert_eq!(minted["scope"], "reports.read");
    }

    #[tokio::test]
    async fn jwt_bearer_never_outlives_the_id_jag() {
        let expiry = now_secs() + 45;
        let id_jag = json!({
            "iss": "did:webvh:example:gw", "sub": "did:example:user", "aud": "did:webvh:example:gw",
            "client_id": "agent-client", "jti": "grant-short", "exp": expiry
        });
        let assertion = id_jag_assertion(&id_jag);
        let state = state_with(HashMap::from([(assertion.clone(), id_jag)]), client(base_record(), Some("s3cret")));
        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            ..Default::default()
        };
        let response = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("redeem succeeds");
        let minted: Value = serde_json::from_str(&response.access_token).unwrap();
        assert!(response.expires_in.unwrap() <= 45);
        assert!(
            minted["exp"]
                .as_u64()
                .unwrap()
                <= expiry
        );
    }

    #[tokio::test]
    async fn jwt_bearer_preserves_id_jag_delegation_actor() {
        // An ID-JAG that carries a delegation actor (the agent DID) must be
        // redeemed into a token that preserves it as `act` — not overwrite it
        // with the redeeming client id. The client id stays in `client_id`.
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "agent-client",
            "scope": "reports.read",
            "jti": "grant-redeem-act",
            "exp": now_secs() + 120,
            "act": { "sub": "did:example:agent" }
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            ..Default::default()
        };
        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("redeem succeeds");
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["sub"], "did:example:user");
        assert_eq!(minted["act"], json!({ "sub": "did:example:agent" }));
        assert_eq!(minted["client_id"], "agent-client");
    }

    #[tokio::test]
    async fn jwt_bearer_rejects_id_jag_for_wrong_audience() {
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "u",
            "aud": "did:webvh:someone-else",
            "jti": "grant-wrong-aud",
            "exp": now_secs() + 120
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            ..Default::default()
        };
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant");
    }

    #[tokio::test]
    async fn jwt_bearer_rejects_replayed_id_jag() {
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "agent-client",
            "jti": "grant-once",
            "exp": now_secs() + 120
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let make_form = || TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion.clone()),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            ..Default::default()
        };
        // First redemption succeeds; the single-use grant is now consumed.
        dispatch(&state, &HeaderMap::new(), make_form())
            .await
            .expect("first redeem succeeds");
        let err = dispatch(&state, &HeaderMap::new(), make_form())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant", "a replayed ID-JAG must be rejected");
    }

    #[tokio::test]
    async fn jwt_bearer_rejects_id_jag_issued_to_another_client() {
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "different-agent",
            "jti": "grant-other",
            "exp": now_secs() + 120
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            ..Default::default()
        };
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant", "a client may not redeem another client's ID-JAG");
    }

    #[tokio::test]
    async fn jwt_bearer_rejects_non_id_jag_assertion() {
        // A plain-typed JWT with otherwise-valid ID-JAG claims must not redeem.
        let claims_json = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "agent-client",
            "jti": "grant-plain",
            "exp": now_secs() + 120
        });
        let assertion = plain_jwt_assertion(&claims_json);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), claims_json);
        let state = state_with(claims, client(base_record(), Some("s3cret")));

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            ..Default::default()
        };
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant", "a non-ID-JAG typ must be rejected");
    }

    #[tokio::test]
    async fn jwt_bearer_ceilings_scope_to_the_grant() {
        // The ID-JAG grants only reports.read; the client requests read + write.
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "agent-client",
            "scope": "reports.read",
            "jti": "grant-scope",
            "exp": now_secs() + 120
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let mut record = base_record();
        record.allowed_scopes = vec!["reports.read".to_string(), "reports.write".to_string()];
        let state = state_with(claims, client(record, Some("s3cret")));

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            scope: Some("reports.read reports.write".to_string()),
            ..Default::default()
        };
        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("redeem succeeds");
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        // Even though the client is allowed reports.write, the grant ceilings it out.
        assert_eq!(minted["scope"], "reports.read");
    }

    /// Policy mock that denies every issuance.
    struct DenyPolicy;

    impl crate::sts::policy::StsPolicyEvaluator for DenyPolicy {
        fn authorize(
            &self,
            _input: &Value,
        ) -> Result<(), StsError> {
            Err(StsError::UnauthorizedClient("denied by policy in test".to_string()))
        }
    }

    /// Policy mock that captures the input it was asked to authorize.
    #[derive(Default)]
    struct CapturePolicy {
        seen: std::sync::Mutex<Option<Value>>,
    }

    impl crate::sts::policy::StsPolicyEvaluator for CapturePolicy {
        fn authorize(
            &self,
            input: &Value,
        ) -> Result<(), StsError> {
            *self.seen.lock().unwrap() = Some(input.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn token_exchange_denied_by_policy() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let mut state = state_with(claims, client(base_record(), Some("s3cret")));
        state.policy = Arc::new(DenyPolicy);

        let err = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "unauthorized_client", "a policy deny must block issuance");
    }

    #[tokio::test]
    async fn policy_input_carries_issuance_context() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let mut state = state_with(claims, client(base_record(), Some("s3cret")));
        let capture = Arc::new(CapturePolicy::default());
        state.policy = capture.clone();

        dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .expect("exchange succeeds");
        let seen = capture
            .seen
            .lock()
            .unwrap()
            .clone()
            .expect("policy saw an input");
        assert_eq!(seen["sts"]["grant"], "token_exchange");
        assert_eq!(seen["sts"]["client_id"], "agent-client");
        assert_eq!(seen["sts"]["subject"], "did:example:user");
    }

    #[tokio::test]
    async fn jwt_bearer_denied_by_policy() {
        let id_jag = json!({
            "iss": "did:webvh:example:gw",
            "sub": "did:example:user",
            "aud": "did:webvh:example:gw",
            "client_id": "agent-client",
            "jti": "grant-policy",
            "exp": now_secs() + 120
        });
        let assertion = id_jag_assertion(&id_jag);
        let mut claims = HashMap::new();
        claims.insert(assertion.clone(), id_jag);
        let mut state = state_with(claims, client(base_record(), Some("s3cret")));
        state.policy = Arc::new(DenyPolicy);

        let form = TokenEndpointForm {
            grant_type: Some(GRANT_TYPE_JWT_BEARER.to_string()),
            assertion: Some(assertion),
            client_id: Some("agent-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            audience: Some("https://target.example".to_string()),
            ..Default::default()
        };
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "unauthorized_client", "a policy deny must block redemption");
    }

    /// Trust-check mock that injects a fixed results block when the list is set.
    struct MockTrustChecker {
        results: Value,
    }

    #[async_trait::async_trait]
    impl crate::sts::trust_check::StsTrustChecker for MockTrustChecker {
        async fn evaluate(
            &self,
            _subject_id: &str,
            _input: &Value,
            list: &[crate::trust_registry_verification::TrustCheckElement],
        ) -> Option<Value> {
            if list.is_empty() {
                None
            } else {
                Some(self.results.clone())
            }
        }
    }

    /// Policy mock that denies unless every caller-leg trust check result is `ok`.
    struct TrustAwarePolicy;

    impl crate::sts::policy::StsPolicyEvaluator for TrustAwarePolicy {
        fn authorize(
            &self,
            input: &Value,
        ) -> Result<(), StsError> {
            let all_ok = input
                .get("trust_check_results")
                .and_then(|r| r.get("caller"))
                .and_then(|c| c.as_array())
                .map(|arr| {
                    arr.iter().all(|r| {
                        r.get("ok")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(true);
            if all_ok {
                Ok(())
            } else {
                Err(StsError::UnauthorizedClient("trust check failed".to_string()))
            }
        }
    }

    fn trust_check_element() -> crate::trust_registry_verification::TrustCheckElement {
        crate::trust_registry_verification::TrustCheckElement {
            id: "e1".to_string(),
            trust_registry_id: "reg".to_string(),
            query_type: crate::trust_registry_verification::trust_check_element::TrqpQueryType::Recognition,
            query: crate::trust_registry_verification::trust_check_element::TrqpQueryParams::default(),
            timeout_secs: None,
            name: None,
        }
    }

    #[tokio::test]
    async fn trust_check_failure_denies_when_policy_checks_it() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let mut record = base_record();
        record.trust_check_list = vec![trust_check_element()];
        let mut state = state_with(claims, client(record, Some("s3cret")));
        state.trust_checker = Arc::new(MockTrustChecker {
            results: json!({ "caller": [{ "id": "e1", "ok": false, "error": { "code": "NOT_RECOGNIZED" } }], "target": [] }),
        });
        state.policy = Arc::new(TrustAwarePolicy);

        let err = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "unauthorized_client", "a failed trust check must block issuance");
    }

    #[tokio::test]
    async fn trust_check_pass_allows_issuance() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user" }));
        let mut record = base_record();
        record.trust_check_list = vec![trust_check_element()];
        let mut state = state_with(claims, client(record, Some("s3cret")));
        state.trust_checker = Arc::new(MockTrustChecker {
            results: json!({ "caller": [{ "id": "e1", "ok": true }], "target": [] }),
        });
        state.policy = Arc::new(TrustAwarePolicy);

        let resp = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .expect("a passing trust check allows issuance");
        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
    }

    #[test]
    fn metadata_base_url_builds_absolute_from_request() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            "gw.example:8443"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            metadata_base_url(&headers, "/api/.well-known/oauth-authorization-server").as_deref(),
            Some("https://gw.example:8443/api")
        );
    }

    #[test]
    fn metadata_base_url_honors_forwarded_proto_and_root_mount() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "gw.example".parse().unwrap());
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(
            metadata_base_url(&headers, "/.well-known/oauth-authorization-server").as_deref(),
            Some("http://gw.example")
        );
    }

    #[test]
    fn metadata_base_url_none_without_host() {
        assert!(
            metadata_base_url(&HeaderMap::new(), "/.well-known/oauth-authorization-server").is_none(),
            "no Host ⇒ fall back to relative paths"
        );
    }

    #[test]
    fn metadata_base_url_prefers_forwarded_host_over_internal_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            "127.0.0.1:8080"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "x-forwarded-host",
            "gw.public.example"
                .parse()
                .unwrap(),
        );
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            metadata_base_url(&headers, "/api/.well-known/oauth-authorization-server").as_deref(),
            Some("https://gw.public.example/api"),
            "X-Forwarded-Host must win over the tunnel's internal Host",
        );
    }

    #[test]
    fn metadata_base_url_takes_first_forwarded_host_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            "127.0.0.1:8080"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "x-forwarded-host",
            "gw.public.example, inner.internal"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            metadata_base_url(&headers, "/.well-known/oauth-authorization-server").as_deref(),
            Some("https://gw.public.example"),
        );
    }

    #[test]
    fn metadata_base_url_parses_rfc7239_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            "127.0.0.1:8080"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "forwarded",
            "for=192.0.2.60;proto=https;host=gw.public.example"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            metadata_base_url(&headers, "/api/.well-known/oauth-authorization-server").as_deref(),
            Some("https://gw.public.example/api"),
        );
    }

    #[test]
    fn configured_base_composes_origin_with_mount_prefix() {
        assert_eq!(
            compose_configured_base(
                Some("https://agent-gateway-1.example.com"),
                "/api/.well-known/oauth-authorization-server",
            )
            .as_deref(),
            Some("https://agent-gateway-1.example.com/api"),
        );
    }

    #[test]
    fn configured_base_uses_origin_only_and_supports_root_mount() {
        // A stray path in external_urls contributes only its origin, and a root
        // mount yields the bare origin.
        assert_eq!(
            compose_configured_base(
                Some("https://gw.public.example/ignored/path"),
                "/.well-known/oauth-authorization-server",
            )
            .as_deref(),
            Some("https://gw.public.example"),
        );
    }

    #[test]
    fn configured_base_none_when_unset_or_unparseable() {
        assert!(
            compose_configured_base(None, "/api/.well-known/oauth-authorization-server").is_none(),
            "unset ⇒ fall back to request-derived",
        );
        assert!(
            compose_configured_base(Some("not a url"), "/api/.well-known/oauth-authorization-server").is_none(),
            "unparseable base ⇒ fall back to request-derived",
        );
    }

    #[test]
    fn configured_origin_preserves_non_default_port() {
        assert_eq!(
            configured_origin("https://gw.public.example:8443/whatever").as_deref(),
            Some("https://gw.public.example:8443"),
        );
    }

    #[tokio::test]
    async fn subject_audience_allowlist_rejects_mismatch() {
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "did:example:user", "aud": "https://other.example" }));
        let mut record = base_record();
        record.allowed_subject_audiences = vec!["https://sts.example".to_string()];
        let state = state_with(claims, client(record, Some("s3cret")));

        let err = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant", "a subject token for a disallowed audience must be rejected");
    }

    #[tokio::test]
    async fn subject_audience_allowlist_accepts_match() {
        let mut claims = HashMap::new();
        claims.insert(
            "subject-tok".to_string(),
            json!({ "sub": "did:example:user", "aud": ["https://sts.example", "https://other.example"] }),
        );
        let mut record = base_record();
        record.allowed_subject_audiences = vec!["https://sts.example".to_string()];
        let state = state_with(claims, client(record, Some("s3cret")));

        let resp = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .expect("a subject token whose aud is allowed is accepted");
        assert_eq!(resp.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
    }

    #[tokio::test]
    async fn unsupported_grant_type_is_rejected() {
        let state = state_with(HashMap::new(), client(base_record(), Some("s3cret")));
        let form = TokenEndpointForm {
            grant_type: Some("authorization_code".to_string()),
            ..Default::default()
        };
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "unsupported_grant_type");
    }

    #[tokio::test]
    async fn missing_grant_type_is_invalid_request() {
        let state = state_with(HashMap::new(), client(base_record(), Some("s3cret")));
        let err = dispatch(&state, &HeaderMap::new(), TokenEndpointForm::default())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "invalid_request");
    }

    #[tokio::test]
    async fn vp_subject_token_unsupported_when_verifier_disabled() {
        let state = state_with(HashMap::new(), client(base_record(), Some("s3cret")));
        let mut form = exchange_form();
        form.subject_token_type = Some(TOKEN_TYPE_VP.to_string());
        let err = dispatch(&state, &HeaderMap::new(), form)
            .await
            .unwrap_err();
        // Disabled VP verifier → unsupported token type (invalid_request family).
        assert_eq!(err.error_code(), "invalid_request");
    }

    #[tokio::test]
    async fn vp_subject_token_mints_access_token_with_proven_did() {
        let mut vps = HashMap::new();
        vps.insert("vp-token".to_string(), json!({ "sub": "did:webvh:proven-agent" }));
        let state = StsState {
            signer: Arc::new(MockSigner {
                issuer: "did:webvh:example:gw".to_string(),
            }),
            verifier: Arc::new(MockVerifier { claims: HashMap::new() }),
            vp_verifier: Arc::new(MockVpVerifier { vps }),
            clients: Arc::new(client(base_record(), Some("s3cret"))),
            policy: Arc::new(AllowAllPolicyEvaluator),
            trust_checker: Arc::new(DisabledTrustChecker),
            replay: Arc::new(crate::sts::replay::ReplayGuard::new()),
            throttle: Arc::new(crate::sts::throttle::TokenEndpointThrottle::from_config(
                &crate::config::types::TokenEndpointThrottleConfig::default(),
            )),
            resource_owners: Arc::new(crate::sts::resource_owners::NoResourceOwners),
            config: StsConfig::default(),
        };
        let mut form = exchange_form();
        form.subject_token = Some("vp-token".to_string());
        form.subject_token_type = Some(TOKEN_TYPE_VP.to_string());
        let resp = dispatch(&state, &HeaderMap::new(), form)
            .await
            .expect("vp exchange succeeds");
        let minted: Value = serde_json::from_str(&resp.access_token).unwrap();
        assert_eq!(minted["sub"], "did:webvh:proven-agent");
        // Delegation-by-default still applies: the client is the actor.
        assert_eq!(minted["act"], json!({ "sub": "agent-client" }));
    }

    #[tokio::test]
    async fn subject_token_type_restriction_is_enforced() {
        let mut record = base_record();
        record.allowed_subject_token_types = vec![TOKEN_TYPE_ID_TOKEN.to_string()];
        let mut claims = HashMap::new();
        claims.insert("subject-tok".to_string(), json!({ "sub": "u" }));
        let state = state_with(claims, client(record, Some("s3cret")));
        // exchange_form presents a `jwt` subject, which is not in the allowlist.
        let err = dispatch(&state, &HeaderMap::new(), exchange_form())
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "unauthorized_client");
    }

    #[test]
    fn gateway_self_trust_strategy_projects_okp_jwks() {
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "key-1"
            }]
        });
        let strategy = gateway_self_trust_strategy("did:webvh:example:gw", &jwks)
            .expect("valid gateway jwks must project to a strategy");
        assert_eq!(strategy.expected_issuer, "did:webvh:example:gw");
        match strategy.jwks_source {
            crate::jwt_bearer::models::JwksSource::Static { jwks } => {
                assert_eq!(jwks.len(), 1);
                assert_eq!(jwks[0].kty, "OKP");
                assert_eq!(jwks[0].kid.as_deref(), Some("key-1"));
            }
            other => panic!("expected a Static jwks source, got {other:?}"),
        }
    }

    #[test]
    fn gateway_self_trust_strategy_rejects_jwks_without_keys() {
        let err = gateway_self_trust_strategy("did:webvh:example:gw", &json!({}))
            .expect_err("jwks without a keys array must error");
        assert!(matches!(err, StsError::ServerError(_)));
    }

    #[test]
    fn basic_auth_parsing() {
        let mut headers = HeaderMap::new();
        let creds = base64::engine::general_purpose::STANDARD.encode("agent:secret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {creds}")
                .parse()
                .unwrap(),
        );
        assert_eq!(parse_basic_auth(&headers), Some(("agent".to_string(), "secret".to_string())));
    }

    #[test]
    fn basic_auth_absent_is_none() {
        assert_eq!(parse_basic_auth(&HeaderMap::new()), None);
    }

    #[test]
    fn header_basic_auth_takes_precedence_over_form() {
        let mut headers = HeaderMap::new();
        let creds = base64::engine::general_purpose::STANDARD.encode("hdr:hsec");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {creds}")
                .parse()
                .unwrap(),
        );
        let form = TokenEndpointForm {
            client_id: Some("formid".to_string()),
            client_secret: Some("formsec".to_string()),
            ..Default::default()
        };
        assert_eq!(resolve_client_credentials(&headers, &form), (Some("hdr".to_string()), Some("hsec".to_string())));
    }

    #[test]
    fn constant_time_eq_behaviour() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn decode_unverified_issuer_reads_iss() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"iss":"did:example:x","sub":"u"}"#);
        let token = format!("h.{payload}.sig");
        assert_eq!(decode_unverified_issuer(&token), Some("did:example:x".to_string()));
    }

    #[test]
    fn decode_unverified_issuer_rejects_non_jwt() {
        assert_eq!(decode_unverified_issuer("not-a-jwt"), None);
    }
}
