//! Gateway grants: tokens the gateway obtains for its own identity from a credential
//! provider (Client Credentials or RFC 7523 JWT bearer), with no user.
//!
//! Every grant is sent on a client pinned to the token endpoint's vetted addresses
//! with redirects off, its response is read to at most 64 KiB, and failures are
//! reported as fixed categories so token endpoint text never reaches a caller or a log.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use super::OAuthTokenResponse;
use crate::audit::events::DelegationFailureReason;
use crate::credential_providers::jwt_assertion::{AssertionClaims, SigningKey, sign_assertion};
use crate::credential_providers::{CredentialProvider, CredentialProviderType};
use crate::secrets::SecretsStore;

/// Longest access token accepted from a gateway grant.
pub const MAX_GATEWAY_TOKEN_BYTES: usize = 8 * 1024;

/// Lifetime assumed when a token response carries no `expires_in`.
pub const DEFAULT_GATEWAY_TOKEN_LIFETIME_SECS: i64 = 300;

/// Longest lifetime trusted from a token response.
pub const MAX_GATEWAY_TOKEN_LIFETIME_SECS: i64 = 86_400;

/// Refresh starts this long before expiry, or halfway through a shorter life.
pub const MAX_REFRESH_MARGIN_SECS: i64 = 300;

const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

const OAUTH_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_target",
    "access_denied",
    "server_error",
    "temporarily_unavailable",
];

/// Why a gateway grant failed. Each variant is a fixed category with no detail.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTokenError {
    #[error("unsupported")]
    Unsupported,
    #[error("secret_unavailable")]
    SecretUnavailable,
    #[error("forbidden")]
    Forbidden,
    #[error("unavailable")]
    Unavailable,
    #[error("invalid_response")]
    InvalidResponse,
    #[error("assertion_failed")]
    AssertionFailed,
    #[error("scope_mismatch")]
    ScopeMismatch,
}

impl GatewayTokenError {
    pub fn category(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::SecretUnavailable => "secret_unavailable",
            Self::Forbidden => "forbidden",
            Self::Unavailable => "unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::AssertionFailed => "assertion_failed",
            Self::ScopeMismatch => "scope_mismatch",
        }
    }

    /// The audit reason for a grant that failed with this category.
    pub fn delegation_failure_reason(self) -> DelegationFailureReason {
        match self {
            Self::AssertionFailed => DelegationFailureReason::AssertionFailed,
            Self::Unavailable | Self::InvalidResponse | Self::ScopeMismatch => {
                DelegationFailureReason::TokenEndpointFailed
            }
            Self::Unsupported | Self::SecretUnavailable | Self::Forbidden => {
                DelegationFailureReason::CredentialsUnavailable
            }
        }
    }

    /// Whether this failure starts the retry backoff. Only a token endpoint failure does;
    /// a local failure is reported as itself on every request.
    pub fn backs_off(self) -> bool {
        matches!(self, Self::Unavailable | Self::InvalidResponse | Self::ScopeMismatch)
    }
}

/// The `grant` label a provider's gateway grants carry in metrics and audit detail.
pub fn grant_label(provider_type: &CredentialProviderType) -> &'static str {
    match provider_type {
        CredentialProviderType::OAuth2JwtBearer => "jwt_bearer",
        CredentialProviderType::OAuth2ClientCredentials
        | CredentialProviderType::OAuth2AuthorizationCode
        | CredentialProviderType::ApiKey => "client_credentials",
    }
}

/// The `grant` label of the token fetch counter. A provider type the gateway never grants for is
/// counted as `unsupported` instead of under a grant it did not attempt.
fn token_fetch_grant(provider_type: &CredentialProviderType) -> &'static str {
    match provider_type {
        CredentialProviderType::OAuth2JwtBearer | CredentialProviderType::OAuth2ClientCredentials => {
            grant_label(provider_type)
        }
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::ApiKey => "unsupported",
    }
}

/// How gateway grants reach a token endpoint.
#[derive(Debug, Clone)]
pub struct GrantEgress {
    pub timeout: Duration,
    /// Exact test endpoints admitted under `AG_TEST_MODE=true`; `None` in production.
    pub exact_allowlist: Option<String>,
}

impl GrantEgress {
    pub fn from_environment() -> Self {
        Self {
            timeout: Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS),
            exact_allowlist: crate::url_validation::bdd_oauth_endpoint_allowlist(),
        }
    }

    /// Whether a provider may send its client secret or assertion to `endpoint`: an
    /// https URL, or a URL the test allowlist names exactly.
    pub fn permits_token_endpoint(
        &self,
        endpoint: &str,
    ) -> bool {
        let Ok(endpoint) = url::Url::parse(endpoint.trim()) else {
            return false;
        };
        endpoint.scheme() == "https"
            || self
                .exact_allowlist
                .as_deref()
                .is_some_and(|allowlist| {
                    allowlist
                        .split(',')
                        .filter_map(|entry| url::Url::parse(entry.trim()).ok())
                        .any(|entry| entry == endpoint)
                })
    }
}

/// A secret a gateway grant read, identified by the last change of the copy it read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, Deserialize)]
pub struct SecretVersion {
    pub secret_id: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Resolves a provider's secret references, only when the secret belongs to the
/// provider's own tenant (appliance-wide providers use appliance-wide secrets), and
/// records the version of each secret it resolves.
pub struct ProviderSecrets<'a> {
    store: &'a Arc<dyn SecretsStore>,
    provider_tenant_id: Option<&'a str>,
    read: std::sync::Mutex<Vec<SecretVersion>>,
}

impl<'a> ProviderSecrets<'a> {
    pub fn new(
        store: &'a Arc<dyn SecretsStore>,
        provider: &'a CredentialProvider,
    ) -> Self {
        Self {
            store,
            provider_tenant_id: provider.tenant_id.as_deref(),
            read: std::sync::Mutex::default(),
        }
    }

    pub async fn resolve(
        &self,
        secret_ref: &str,
    ) -> Result<Zeroizing<String>, GatewayTokenError> {
        let secret = self
            .store
            .get_by_secret_id(secret_ref)
            .await
            .map_err(|_| GatewayTokenError::SecretUnavailable)?
            .ok_or(GatewayTokenError::SecretUnavailable)?;
        if secret.tenant_id.as_deref() != self.provider_tenant_id {
            return Err(GatewayTokenError::Forbidden);
        }
        self.read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(SecretVersion {
                secret_id: secret_ref.to_string(),
                updated_at: secret.updated_at,
            });
        Ok(Zeroizing::new(secret.value))
    }

    /// The versions of the secrets resolved so far, sorted and without repeats.
    pub fn versions_read(&self) -> Vec<SecretVersion> {
        let mut versions = self
            .read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        versions.sort_unstable();
        versions.dedup();
        versions
    }

    /// Whether each recorded secret still belongs to the provider's tenant at exactly the
    /// recorded version. No record, or an empty one, is never current.
    pub async fn still_current(
        &self,
        versions: Option<&[SecretVersion]>,
    ) -> bool {
        let Some(versions) = versions.filter(|versions| !versions.is_empty()) else {
            return false;
        };
        for version in versions {
            match self
                .store
                .get_by_secret_id(&version.secret_id)
                .await
            {
                Ok(Some(secret)) => {
                    let _value = Zeroizing::new(secret.value);
                    if secret.tenant_id.as_deref() != self.provider_tenant_id || secret.updated_at != version.updated_at
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

/// The lifetime to trust for a token: `expires_in` capped at
/// [`MAX_GATEWAY_TOKEN_LIFETIME_SECS`], or [`DEFAULT_GATEWAY_TOKEN_LIFETIME_SECS`]
/// when absent. A zero or negative value is refused.
pub fn bounded_lifetime_secs(expires_in: Option<i64>) -> Result<i64, GatewayTokenError> {
    match expires_in {
        None => Ok(DEFAULT_GATEWAY_TOKEN_LIFETIME_SECS),
        Some(seconds) if seconds > 0 => Ok(seconds.min(MAX_GATEWAY_TOKEN_LIFETIME_SECS)),
        Some(_) => Err(GatewayTokenError::InvalidResponse),
    }
}

/// How long before expiry a token of this lifetime is refreshed.
pub fn refresh_margin_secs(lifetime_secs: i64) -> i64 {
    MAX_REFRESH_MARGIN_SECS.min(lifetime_secs.max(0) / 2)
}

/// Requests a gateway token from the provider's token endpoint.
///
/// Client Credentials posts the client id and secret in the form. JWT bearer signs an
/// assertion whose `aud` is its audience or else the token endpoint, sends the scopes both in the assertion
/// and as the `scope` form parameter, and authenticates the client with HTTP Basic
/// when both client references are set. The token endpoint must be https unless the
/// test allowlist names it exactly; it is checked before any secret is read. The
/// timeout covers secret reads and signing as well as the request. The response must
/// be a Bearer token; any refresh token is dropped and the lifetime is bounded. A
/// response whose `scope` lacks a requested scope is refused; one without `scope` is
/// taken to grant the requested scopes (RFC 6749 section 5.1).
pub async fn request_gateway_grant(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &ProviderSecrets<'_>,
    egress: &GrantEgress,
) -> Result<OAuthTokenResponse, GatewayTokenError> {
    let result = tokio::time::timeout(egress.timeout, send_gateway_grant(provider, scopes, secrets, egress))
        .await
        .unwrap_or(Err(GatewayTokenError::Unavailable));
    crate::metrics::backends::prometheus::track_token_fetch(
        token_fetch_grant(&provider.provider_type),
        match &result {
            Ok(_) => "ok",
            Err(error) => error.category(),
        },
    );
    result
}

async fn send_gateway_grant(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &ProviderSecrets<'_>,
    egress: &GrantEgress,
) -> Result<OAuthTokenResponse, GatewayTokenError> {
    let endpoint = provider
        .token_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .ok_or(GatewayTokenError::Unsupported)?;
    if !egress.permits_token_endpoint(endpoint) {
        return Err(GatewayTokenError::Forbidden);
    }
    let mut form: Vec<(&'static str, Zeroizing<String>)> = Vec::new();
    let mut basic_credentials = None;
    match provider.provider_type {
        CredentialProviderType::OAuth2ClientCredentials => {
            let client_id = secrets
                .resolve(required_ref(
                    provider
                        .client_id_secret_ref
                        .as_deref(),
                )?)
                .await?;
            let client_secret = secrets
                .resolve(required_ref(
                    provider
                        .client_secret_secret_ref
                        .as_deref(),
                )?)
                .await?;
            form.push(("grant_type", Zeroizing::new("client_credentials".into())));
            form.push(("client_id", client_id));
            form.push(("client_secret", client_secret));
        }
        CredentialProviderType::OAuth2JwtBearer => {
            let settings = provider
                .jwt_bearer
                .as_ref()
                .ok_or(GatewayTokenError::Unsupported)?;
            let key_text = secrets
                .resolve(&settings.signing_key_secret_ref)
                .await?;
            let key = SigningKey::parse(&key_text, settings.signing_algorithm)
                .map_err(|_| GatewayTokenError::AssertionFailed)?;
            let assertion = sign_assertion(
                &key,
                &AssertionClaims {
                    issuer: &settings.assertion_issuer,
                    subject: settings.subject(),
                    audience: settings.audience(endpoint),
                    scopes,
                    key_id: settings
                        .key_id
                        .as_deref()
                        .or(key.embedded_key_id()),
                },
                chrono::Utc::now().timestamp(),
            )
            .map_err(|_| GatewayTokenError::AssertionFailed)?;
            form.push(("grant_type", Zeroizing::new(JWT_BEARER_GRANT_TYPE.into())));
            form.push(("assertion", assertion));
            match (
                provider
                    .client_id_secret_ref
                    .as_deref(),
                provider
                    .client_secret_secret_ref
                    .as_deref(),
            ) {
                (Some(id_ref), Some(secret_ref)) => {
                    let client_id = secrets
                        .resolve(id_ref)
                        .await?;
                    let client_secret = secrets
                        .resolve(secret_ref)
                        .await?;
                    basic_credentials = Some(basic_authorization(&client_id, &client_secret)?);
                }
                (Some(id_ref), None) => form.push((
                    "client_id",
                    secrets
                        .resolve(id_ref)
                        .await?,
                )),
                (None, _) => {}
            }
        }
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::ApiKey => {
            return Err(GatewayTokenError::Unsupported);
        }
    }
    if !scopes.is_empty() {
        form.push(("scope", Zeroizing::new(scopes.join(" "))));
    }
    if let Some(resource) = provider.resource.as_deref() {
        form.push(("resource", Zeroizing::new(resource.to_string())));
    }
    let raw = endpoint.to_string();
    let timeout = egress.timeout;
    let allowlist = egress.exact_allowlist.clone();
    let (client, target) = tokio::task::spawn_blocking(move || {
        crate::egress::pinned_configured_client(&raw, timeout, allowlist.as_deref())
    })
    .await
    .map_err(|_| GatewayTokenError::Unavailable)?
    .map_err(|error| match error {
        crate::egress::EgressError::Blocked(_) => GatewayTokenError::Forbidden,
        _ => GatewayTokenError::Unavailable,
    })?;
    let pairs: Vec<(&str, &str)> = form
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let mut request = client
        .post(target.url)
        .header(ACCEPT, "application/json")
        .form(&pairs);
    if let Some(credentials) = basic_credentials {
        request = request.header(AUTHORIZATION, credentials);
    }
    let response = request
        .send()
        .await
        .map_err(|_| GatewayTokenError::Unavailable)?;
    let status = response.status();
    let body = super::oauth::read_token_response(response).await?;
    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = status.as_u16(),
            error_code = oauth_error_code(&body).unwrap_or("none"),
            "Gateway grant rejected by the token endpoint"
        );
        return Err(GatewayTokenError::Unavailable);
    }
    let response = parse_grant_response(&body)?;
    if !issued_scopes_cover(response.scope.as_deref(), scopes) {
        return Err(GatewayTokenError::ScopeMismatch);
    }
    Ok(response)
}

fn issued_scopes_cover(
    issued: Option<&str>,
    requested: &[String],
) -> bool {
    let Some(issued) = issued else {
        return true;
    };
    let issued: std::collections::HashSet<&str> = issued
        .split_whitespace()
        .collect();
    requested
        .iter()
        .flat_map(|scope| scope.split_whitespace())
        .all(|scope| issued.contains(scope))
}

fn required_ref(secret_ref: Option<&str>) -> Result<&str, GatewayTokenError> {
    secret_ref
        .filter(|secret_ref| !secret_ref.trim().is_empty())
        .ok_or(GatewayTokenError::Unsupported)
}

/// RFC 6749 section 2.3.1: the client id and secret are form-urlencoded before they
/// are joined and base64-encoded.
fn basic_authorization(
    client_id: &str,
    client_secret: &str,
) -> Result<HeaderValue, GatewayTokenError> {
    use base64::Engine;
    let joined = Zeroizing::new(format!("{}:{}", urlencoding::encode(client_id), urlencoding::encode(client_secret)));
    let header =
        Zeroizing::new(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(joined.as_bytes())));
    let mut value = HeaderValue::from_str(&header).map_err(|_| GatewayTokenError::SecretUnavailable)?;
    value.set_sensitive(true);
    Ok(value)
}

pub(crate) fn oauth_error_code(body: &[u8]) -> Option<&'static str> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let error = serde_json::from_slice::<ErrorBody>(body)
        .ok()?
        .error;
    OAUTH_ERROR_CODES
        .iter()
        .copied()
        .find(|code| *code == error)
}

#[derive(Deserialize)]
struct GrantResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<serde_json::Value>,
    scope: Option<String>,
}

fn parse_grant_response(body: &[u8]) -> Result<OAuthTokenResponse, GatewayTokenError> {
    let response: GrantResponse = serde_json::from_slice(body).map_err(|_| GatewayTokenError::InvalidResponse)?;
    let mut access_token = Zeroizing::new(
        response
            .access_token
            .unwrap_or_default(),
    );
    if access_token.is_empty()
        || access_token.len() > MAX_GATEWAY_TOKEN_BYTES
        || !access_token
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(GatewayTokenError::InvalidResponse);
    }
    if !response
        .token_type
        .as_deref()
        .is_some_and(|token_type| token_type.eq_ignore_ascii_case("bearer"))
    {
        return Err(GatewayTokenError::InvalidResponse);
    }
    let expires_in = match response.expires_in {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(number)) => Some(
            number
                .as_i64()
                .ok_or(GatewayTokenError::InvalidResponse)?,
        ),
        Some(serde_json::Value::String(text)) => Some(
            text.trim()
                .parse()
                .map_err(|_| GatewayTokenError::InvalidResponse)?,
        ),
        Some(_) => return Err(GatewayTokenError::InvalidResponse),
    };
    Ok(OAuthTokenResponse {
        access_token: std::mem::take(&mut *access_token),
        refresh_token: None,
        token_type: "Bearer".into(),
        expires_in: Some(bounded_lifetime_secs(expires_in)?),
        scope: response.scope,
    })
}

/// The backoff shared by every gateway grant the gateway sends, for legacy and modern
/// delegation alike.
pub static GATEWAY_GRANT_BACKOFF: std::sync::LazyLock<GrantBackoff> =
    std::sync::LazyLock::new(|| GrantBackoff::new(4_096));

/// Per-key retry backoff after token endpoint failures: 1 s after the first failure,
/// doubling to at most 60 s, cleared by a success. Grants sent in the same window that
/// fail together count as one failure.
pub struct GrantBackoff {
    entries: moka::future::Cache<String, BackoffEntry>,
}

/// A failed grant sent before `retry_at` is not counted. A success records no failures,
/// which never holds a grant back, and sets `retry_at` to its own completion, so a slower
/// failure sent before it is ignored.
#[derive(Debug, Clone, Copy)]
struct BackoffEntry {
    failures: u32,
    retry_at: Instant,
}

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

fn backoff_delay(failures: u32) -> Duration {
    BACKOFF_INITIAL
        .saturating_mul(
            1u32 << failures
                .saturating_sub(1)
                .min(6),
        )
        .min(BACKOFF_MAX)
}

impl GrantBackoff {
    pub fn new(capacity: u64) -> Self {
        Self {
            entries: moka::future::Cache::builder()
                .max_capacity(capacity)
                .time_to_idle(BACKOFF_MAX * 2)
                .build(),
        }
    }

    pub async fn retry_allowed(
        &self,
        key: &str,
        now: Instant,
    ) -> bool {
        self.entries
            .get(key)
            .await
            .is_none_or(|entry| entry.failures == 0 || now >= entry.retry_at)
    }

    /// Records a grant sent at `sent` that failed at `failed`. It counts only when it was
    /// sent at or after the current `retry_at`.
    pub async fn record_failure(
        &self,
        key: &str,
        sent: Instant,
        failed: Instant,
    ) {
        self.entries
            .entry_by_ref(key)
            .and_upsert_with(|existing| {
                let existing = existing.map(|entry| entry.into_value());
                std::future::ready(match existing {
                    Some(entry) if sent < entry.retry_at => entry,
                    _ => {
                        let failures = existing
                            .map_or(0, |entry| entry.failures)
                            .saturating_add(1);
                        BackoffEntry {
                            failures,
                            retry_at: failed + backoff_delay(failures),
                        }
                    }
                })
            })
            .await;
    }

    pub async fn record_success(
        &self,
        key: &str,
        succeeded: Instant,
    ) {
        self.entries
            .insert(
                key.to_string(),
                BackoffEntry {
                    failures: 0,
                    retry_at: succeeded,
                },
            )
            .await;
    }

    /// Sends [`request_gateway_grant`] unless the provider and scope set are inside a
    /// failure backoff window, in which case the grant is `Unavailable` without a request.
    pub async fn request(
        &self,
        provider: &CredentialProvider,
        scopes: &[String],
        secrets: &ProviderSecrets<'_>,
        egress: &GrantEgress,
    ) -> Result<OAuthTokenResponse, GatewayTokenError> {
        self.request_at(provider, scopes, secrets, egress, Instant::now())
            .await
    }

    async fn request_at(
        &self,
        provider: &CredentialProvider,
        scopes: &[String],
        secrets: &ProviderSecrets<'_>,
        egress: &GrantEgress,
        now: Instant,
    ) -> Result<OAuthTokenResponse, GatewayTokenError> {
        let entered = Instant::now();
        let key = backoff_key(provider, scopes);
        if !self
            .retry_allowed(&key, now)
            .await
        {
            held_back_by_backoff(provider);
            return Err(GatewayTokenError::Unavailable);
        }
        let result = request_gateway_grant(provider, scopes, secrets, egress).await;
        let completed = now + entered.elapsed();
        match &result {
            Ok(_) => {
                self.record_success(&key, completed)
                    .await
            }
            Err(error) if error.backs_off() => {
                self.record_failure(&key, now, completed)
                    .await
            }
            Err(_) => {}
        }
        result
    }
}

fn held_back_by_backoff(provider: &CredentialProvider) {
    debug!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        grant = grant_label(&provider.provider_type),
        "Gateway grant held back by the retry backoff"
    );
}

/// The backoff key of a provider and scope set; a provider edit starts a new key.
fn backoff_key(
    provider: &CredentialProvider,
    scopes: &[String],
) -> String {
    let mut scopes = scopes.to_vec();
    scopes.sort_unstable();
    scopes.dedup();
    format!(
        "{}|{}|{}",
        provider.id,
        provider
            .updated_at
            .timestamp_micros(),
        scopes.join(" ")
    )
}

/// What a gateway token is for. Part of the cache key, so tokens for different
/// purposes are never shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatewayTokenPurpose {
    TargetAuthentication,
}

/// The cache key of a gateway token: independent of the caller, and new whenever
/// the provider record, the scope set or the audience changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GatewayTokenKey {
    pub purpose: GatewayTokenPurpose,
    pub credential_provider_id: String,
    pub provider_digest: [u8; 32],
    pub scopes: Vec<String>,
    pub audience: Option<String>,
}

impl GatewayTokenKey {
    /// The Target Authentication key for `provider` and its effective `scopes`.
    pub fn for_target_auth(
        provider: &CredentialProvider,
        scopes: &[String],
    ) -> Result<Self, GatewayTokenError> {
        let provider_digest = crate::mcp::continuations::delegation::provider_digest(provider)
            .map_err(|_| GatewayTokenError::Unavailable)?;
        let mut scopes = scopes.to_vec();
        scopes.sort_unstable();
        scopes.dedup();
        Ok(Self {
            purpose: GatewayTokenPurpose::TargetAuthentication,
            credential_provider_id: provider.id.clone(),
            provider_digest,
            scopes,
            audience: provider.resource.clone(),
        })
    }
}

/// How a returned gateway token was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Cached,
    Fresh,
    StaleAfterRefreshFailure,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Fresh => "fresh",
            Self::StaleAfterRefreshFailure => "stale",
        }
    }
}

pub struct GatewayTokenGrant {
    pub access_token: Zeroizing<String>,
    pub freshness: Freshness,
    /// When the token expires, by the wall clock of this replica.
    pub expires_at: SystemTime,
}

impl std::fmt::Debug for GatewayTokenGrant {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("GatewayTokenGrant")
            .field("access_token", &"[redacted]")
            .field("freshness", &self.freshness)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

const GATEWAY_TOKEN_CACHE_ENTRIES: u64 = 4_096;
const GATEWAY_TOKEN_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

/// Per-replica, in-memory cache of gateway tokens. Nothing is persisted, listed in
/// the delegation vault, or counted towards the `credentials` licence umbrella.
pub struct GatewayTokenCache {
    entries: moka::future::Cache<GatewayTokenKey, Arc<TokenSlot>>,
    /// Fixed egress for tests; `None` reads [`GrantEgress::from_environment`] per grant.
    egress: Option<GrantEgress>,
}

/// One key's state. `secret_refs` is copied from the provider when the slot is
/// created; the provider digest in the key covers it.
pub struct TokenSlot {
    secret_refs: Vec<String>,
    grant: tokio::sync::Mutex<()>,
    state: std::sync::Mutex<SlotState>,
}

#[derive(Default)]
struct SlotState {
    token: Option<CachedToken>,
    failures: u32,
    retry_at: Option<Instant>,
}

struct CachedToken {
    held: HeldToken,
    refresh_at: Instant,
    expires_at: Instant,
}

#[derive(Clone)]
struct HeldToken {
    access_token: Zeroizing<String>,
    expires_at: SystemTime,
}

impl HeldToken {
    fn grant(
        self,
        freshness: Freshness,
    ) -> GatewayTokenGrant {
        GatewayTokenGrant {
            access_token: self.access_token,
            freshness,
            expires_at: self.expires_at,
        }
    }
}

enum SlotView {
    Fresh(HeldToken),
    RefreshDue(HeldToken),
    Empty,
}

impl TokenSlot {
    fn new(secret_refs: Vec<String>) -> Self {
        Self {
            secret_refs,
            grant: tokio::sync::Mutex::new(()),
            state: std::sync::Mutex::new(SlotState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn view(
        &self,
        now: Instant,
    ) -> SlotView {
        match self.lock().token.as_ref() {
            Some(token) if now < token.refresh_at => SlotView::Fresh(token.held.clone()),
            Some(token) if now < token.expires_at => SlotView::RefreshDue(token.held.clone()),
            _ => SlotView::Empty,
        }
    }

    fn backed_off(
        &self,
        now: Instant,
    ) -> bool {
        self.lock()
            .retry_at
            .is_some_and(|retry_at| now < retry_at)
    }

    fn store(
        &self,
        response: OAuthTokenResponse,
        now: Instant,
    ) -> HeldToken {
        let lifetime = response
            .expires_in
            .unwrap_or(DEFAULT_GATEWAY_TOKEN_LIFETIME_SECS)
            .clamp(1, MAX_GATEWAY_TOKEN_LIFETIME_SECS);
        let margin = refresh_margin_secs(lifetime);
        let lifetime = Duration::from_secs(lifetime.unsigned_abs());
        let held = HeldToken {
            access_token: Zeroizing::new(response.access_token),
            expires_at: SystemTime::now() + lifetime,
        };
        let expires_at = now + lifetime;
        let mut state = self.lock();
        state.token = Some(CachedToken {
            held: held.clone(),
            refresh_at: expires_at - Duration::from_secs(margin.unsigned_abs()),
            expires_at,
        });
        state.failures = 0;
        state.retry_at = None;
        held
    }

    fn record_failure(
        &self,
        now: Instant,
    ) {
        let mut state = self.lock();
        state.failures = state
            .failures
            .saturating_add(1);
        state.retry_at = Some(now + backoff_delay(state.failures));
    }
}

impl GatewayTokenCache {
    #[cfg(test)]
    pub(crate) fn new(egress: GrantEgress) -> Self {
        Self::with_egress(Some(egress))
    }

    fn with_egress(egress: Option<GrantEgress>) -> Self {
        Self {
            entries: moka::future::Cache::builder()
                .max_capacity(GATEWAY_TOKEN_CACHE_ENTRIES)
                .time_to_idle(GATEWAY_TOKEN_IDLE)
                .support_invalidation_closures()
                .build(),
            egress,
        }
    }

    fn egress(&self) -> GrantEgress {
        self.egress
            .clone()
            .unwrap_or_else(GrantEgress::from_environment)
    }

    async fn slot(
        &self,
        key: &GatewayTokenKey,
        provider: &CredentialProvider,
    ) -> Arc<TokenSlot> {
        let secret_refs = provider
            .secret_refs()
            .map(str::to_string)
            .collect();
        self.entries
            .get_with(key.clone(), async move { Arc::new(TokenSlot::new(secret_refs)) })
            .await
    }

    /// Drops the entries whose slot was minted from this secret.
    pub fn invalidate_secret(
        &self,
        secret_id: &str,
    ) {
        let secret_id = secret_id.to_string();
        if let Err(error) = self
            .entries
            .invalidate_entries_if(move |_, slot| {
                slot.secret_refs
                    .contains(&secret_id)
            })
        {
            warn!(target: "credential_delegation", %error, "Gateway token cache invalidation failed; dropping every entry");
            self.entries.invalidate_all();
        }
    }

    /// Drops this provider's entries.
    pub fn invalidate_provider(
        &self,
        credential_provider_id: &str,
    ) {
        let credential_provider_id = credential_provider_id.to_string();
        if let Err(error) = self
            .entries
            .invalidate_entries_if(move |key, _| key.credential_provider_id == credential_provider_id)
        {
            warn!(target: "credential_delegation", %error, "Gateway token cache invalidation failed; dropping every entry");
            self.entries.invalidate_all();
        }
    }

    /// Drops every entry on this replica.
    pub fn invalidate_all(&self) {
        self.entries.invalidate_all();
    }
}

#[cfg(test)]
tokio::task_local! {
    static TASK_TOKEN_CACHE: Arc<GatewayTokenCache>;
}

/// The gateway token cache every surface on this replica shares.
pub fn target_token_cache() -> Arc<GatewayTokenCache> {
    static CACHE: std::sync::LazyLock<Arc<GatewayTokenCache>> =
        std::sync::LazyLock::new(|| Arc::new(GatewayTokenCache::with_egress(None)));
    #[cfg(test)]
    {
        if let Ok(cache) = TASK_TOKEN_CACHE.try_with(Arc::clone) {
            return cache;
        }
    }
    CACHE.clone()
}

/// Runs `future` with its own gateway token cache in place of the replica's, so a test
/// that counts grants is not affected by other tests invalidating the shared cache.
#[cfg(test)]
pub(crate) async fn with_own_target_token_cache<F: std::future::Future>(future: F) -> F::Output {
    TASK_TOKEN_CACHE
        .scope(Arc::new(GatewayTokenCache::with_egress(None)), future)
        .await
}

/// Single-flight cached acquisition: at most one grant per key is in flight on this
/// replica. A request that finds no valid token waits for it; while a still-valid
/// token is being refreshed, other requests keep using it. A failed refresh keeps
/// the token while it is still valid when the grant fails, and retries after a token endpoint failure back off from 1 s to
/// 60 s, counted from when the failed grant completed.
pub async fn acquire_gateway_token(
    cache: &GatewayTokenCache,
    key: &GatewayTokenKey,
    provider: &CredentialProvider,
    secrets: &ProviderSecrets<'_>,
) -> Result<GatewayTokenGrant, GatewayTokenError> {
    acquire_gateway_token_at(cache, key, provider, secrets, Instant::now()).await
}

pub(crate) async fn acquire_gateway_token_at(
    cache: &GatewayTokenCache,
    key: &GatewayTokenKey,
    provider: &CredentialProvider,
    secrets: &ProviderSecrets<'_>,
    now: Instant,
) -> Result<GatewayTokenGrant, GatewayTokenError> {
    let entered = Instant::now();
    let cached = |held: HeldToken| Ok(held.grant(Freshness::Cached));
    let slot = cache
        .slot(key, provider)
        .await;
    let _guard = match slot.view(now) {
        SlotView::Fresh(token) => return cached(token),
        SlotView::RefreshDue(token) => match slot.grant.try_lock() {
            Ok(guard) => guard,
            Err(_) => return cached(token),
        },
        SlotView::Empty => slot.grant.lock().await,
    };
    let refreshing = match slot.view(now) {
        SlotView::Fresh(token) => return cached(token),
        SlotView::RefreshDue(token) if slot.backed_off(now) => return cached(token),
        SlotView::RefreshDue(_) => true,
        SlotView::Empty if slot.backed_off(now) => {
            held_back_by_backoff(provider);
            return Err(GatewayTokenError::Unavailable);
        }
        SlotView::Empty => false,
    };
    match request_gateway_grant(provider, &key.scopes, secrets, &cache.egress()).await {
        Ok(response) => Ok(slot
            .store(response, now)
            .grant(Freshness::Fresh)),
        Err(error) => {
            let failed_at = now + entered.elapsed();
            let kept = match slot.view(failed_at) {
                SlotView::Fresh(held) | SlotView::RefreshDue(held) if refreshing => Some(held),
                _ => None,
            };
            warn!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                grant = grant_label(&provider.provider_type),
                category = error.category(),
                stale_token_kept = kept.is_some(),
                "Gateway grant failed"
            );
            if error.backs_off() {
                slot.record_failure(failed_at);
            }
            match kept {
                Some(held) => Ok(held.grant(Freshness::StaleAfterRefreshFailure)),
                None => Err(error),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_endpoint {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Recorded {
        forms: Vec<HashMap<String, String>>,
        authorizations: Vec<Option<String>>,
    }

    type EndpointState = (Arc<Mutex<Recorded>>, Arc<AtomicUsize>, StatusCode, String);

    pub(crate) struct TokenEndpoint {
        pub(crate) url: String,
        recorded: Arc<Mutex<Recorded>>,
        pub(crate) calls: Arc<AtomicUsize>,
    }

    impl TokenEndpoint {
        pub(crate) async fn start(
            status: StatusCode,
            body: String,
        ) -> Self {
            let recorded = Arc::new(Mutex::new(Recorded::default()));
            let calls = Arc::new(AtomicUsize::new(0));
            let state = (recorded.clone(), calls.clone(), status, body);
            let app = axum::Router::new()
                .route(
                    "/token",
                    axum::routing::post(
                        |axum::extract::State((recorded, calls, status, body)): axum::extract::State<EndpointState>,
                         headers: HeaderMap,
                         axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            let mut recorded = recorded
                                .lock()
                                .expect("recorder lock");
                            recorded
                                .forms
                                .push(form);
                            recorded
                                .authorizations
                                .push(
                                    headers
                                        .get(AUTHORIZATION)
                                        .and_then(|value| value.to_str().ok())
                                        .map(str::to_string),
                                );
                            (status, [("content-type", "application/json")], body)
                        },
                    ),
                )
                .with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener binds");
            let address = listener
                .local_addr()
                .expect("listener has an address");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Self {
                url: format!("http://{address}/token"),
                recorded,
                calls,
            }
        }

        pub(crate) fn grants(&self) -> usize {
            self.calls
                .load(Ordering::SeqCst)
        }

        pub(crate) fn egress(&self) -> GrantEgress {
            GrantEgress {
                timeout: Duration::from_secs(5),
                exact_allowlist: Some(self.url.clone()),
            }
        }

        pub(crate) fn last_form(&self) -> HashMap<String, String> {
            self.recorded
                .lock()
                .expect("recorder lock")
                .forms
                .last()
                .cloned()
                .expect("a request was recorded")
        }

        pub(crate) fn last_authorization(&self) -> Option<String> {
            self.recorded
                .lock()
                .expect("recorder lock")
                .authorizations
                .last()
                .cloned()
                .expect("a request was recorded")
        }
    }

    /// Gives the secret a new value, which moves its `updated_at` on.
    pub(crate) async fn replace_secret(
        store: &Arc<dyn SecretsStore>,
        secret_id: &str,
        value: &str,
    ) {
        let secret = store
            .get_by_secret_id(secret_id)
            .await
            .expect("secret reads")
            .expect("secret exists");
        store
            .update(
                &secret.id,
                crate::secrets::UpdateSecretRequest {
                    name: None,
                    description: secret.description,
                    value: Some(value.to_string()),
                    update_value: Some(true),
                    secret_type: None,
                    tags: None,
                },
            )
            .await
            .expect("secret updates");
    }
}

#[cfg(test)]
mod tests {
    use super::test_endpoint::TokenEndpoint;
    use super::*;
    use crate::component_tests::helpers::mock_auth_server::{Endpoint, Fault, JwtBearerClient, MockAuthServer};
    use crate::component_tests::helpers::oidc_keys::{KeyKind, SigningFixture};
    use crate::credential_providers::JwtBearerSettings;
    use crate::credential_providers::jwt_assertion::test_keys::{ec_pkcs8_pem, rsa_pkcs8_pem, service_account_json};
    use crate::credential_providers::jwt_assertion::{
        ASSERTION_IAT_BACKDATE_SECS, ASSERTION_LIFETIME_SECS, JwtBearerAlgorithm,
    };
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore};
    use axum::http::StatusCode;
    use std::sync::atomic::Ordering;

    #[test]
    fn provider_types_the_gateway_never_grants_for_are_counted_as_unsupported() {
        assert_eq!(token_fetch_grant(&CredentialProviderType::OAuth2JwtBearer), "jwt_bearer");
        assert_eq!(token_fetch_grant(&CredentialProviderType::OAuth2ClientCredentials), "client_credentials");
        assert_eq!(token_fetch_grant(&CredentialProviderType::OAuth2AuthorizationCode), "unsupported");
        assert_eq!(token_fetch_grant(&CredentialProviderType::ApiKey), "unsupported");
    }

    fn token_body(extra: serde_json::Value) -> String {
        let mut body = serde_json::json!({"access_token": "gateway-token", "token_type": "bearer", "expires_in": 3600});
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (name, value) in extra {
                body.insert(name.clone(), value.clone());
            }
        }
        body.to_string()
    }

    async fn secrets_with(
        directory: &tempfile::TempDir,
        entries: &[(&str, &str, Option<&str>)],
    ) -> Arc<dyn SecretsStore> {
        let store = FilesystemSecretsStore::new_async(
            directory
                .path()
                .join("secrets")
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store opens");
        for (secret_id, value, tenant) in entries {
            store
                .create(CreateSecretRequest {
                    tenant_id: tenant.map(str::to_string),
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .expect("secret is created");
        }
        Arc::new(store)
    }

    fn provider(
        provider_type: CredentialProviderType,
        token_endpoint: &str,
    ) -> CredentialProvider {
        let mut provider: CredentialProvider = serde_json::from_value(serde_json::json!({
            "id": "provider-1", "name": "Provider", "provider_id": "provider",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .expect("provider deserializes");
        provider.provider_type = provider_type;
        provider.token_endpoint = Some(token_endpoint.into());
        provider
    }

    fn jwt_provider(
        token_endpoint: &str,
        algorithm: JwtBearerAlgorithm,
    ) -> CredentialProvider {
        let mut provider = provider(CredentialProviderType::OAuth2JwtBearer, token_endpoint);
        provider.jwt_bearer = Some(JwtBearerSettings {
            assertion_issuer: "https://issuer.demo.example".into(),
            assertion_subject: Some("agent-1".into()),
            signing_key_secret_ref: "SIGNING_KEY".into(),
            signing_algorithm: algorithm,
            key_id: Some("rs-key-1".into()),
            audience: None,
        });
        provider
    }

    fn decode_segment(segment: &str) -> serde_json::Value {
        use base64::Engine;
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segment)
                .expect("segment is base64url"),
        )
        .expect("segment is JSON")
    }

    #[test]
    fn grant_failures_map_to_typed_delegation_reasons() {
        use DelegationFailureReason::{AssertionFailed, CredentialsUnavailable, TokenEndpointFailed};
        for (error, reason) in [
            (GatewayTokenError::AssertionFailed, AssertionFailed),
            (GatewayTokenError::Unavailable, TokenEndpointFailed),
            (GatewayTokenError::InvalidResponse, TokenEndpointFailed),
            (GatewayTokenError::ScopeMismatch, TokenEndpointFailed),
            (GatewayTokenError::SecretUnavailable, CredentialsUnavailable),
            (GatewayTokenError::Forbidden, CredentialsUnavailable),
            (GatewayTokenError::Unsupported, CredentialsUnavailable),
        ] {
            assert_eq!(error.delegation_failure_reason(), reason, "{error}");
        }
    }

    #[tokio::test]
    async fn an_unusable_signing_key_fails_as_an_assertion_and_is_counted() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", "not a key", None)]).await;
        let provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Rs256);
        let counter = || {
            crate::metrics::backends::prometheus::TOKEN_FETCH
                .with_label_values(&["jwt_bearer", "assertion_failed"])
                .get()
        };
        let before = counter();

        let error =
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &endpoint.egress())
                .await
                .expect_err("a malformed key cannot sign an assertion");

        assert_eq!(error, GatewayTokenError::AssertionFailed);
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            0,
            "no request reaches the token endpoint"
        );
        assert!(counter() > before);
    }

    #[tokio::test]
    async fn a_token_endpoint_failure_and_a_success_are_counted_by_grant() {
        let counter = |grant: &str, result: &str| {
            crate::metrics::backends::prometheus::TOKEN_FETCH
                .with_label_values(&[grant, result])
                .get()
        };
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CLIENT_ID", "id", None), ("CLIENT_SECRET", "secret", None)]).await;

        let failing = TokenEndpoint::start(StatusCode::BAD_REQUEST, "{\"error\":\"invalid_client\"}".into()).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &failing.url);
        provider.client_id_secret_ref = Some("CLIENT_ID".into());
        provider.client_secret_secret_ref = Some("CLIENT_SECRET".into());
        let failed_before = counter("client_credentials", "unavailable");
        let error =
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &failing.egress())
                .await
                .expect_err("the endpoint refuses the grant");
        assert_eq!(error, GatewayTokenError::Unavailable);
        assert!(counter("client_credentials", "unavailable") > failed_before);

        let working = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        provider.token_endpoint = Some(working.url.clone());
        let ok_before = counter("client_credentials", "ok");
        request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &working.egress())
            .await
            .expect("the grant succeeds");
        assert!(counter("client_credentials", "ok") > ok_before);
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_sends_a_signed_assertion_and_basic_client_auth() {
        let endpoint =
            TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({"refresh_token": "r"}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(
            &directory,
            &[("SIGNING_KEY", rsa_pkcs8_pem(), None), ("JB_ID", "jb-client", None), ("JB_SECRET", "s3cret:+/", None)],
        )
        .await;
        let mut provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Rs256);
        provider.client_id_secret_ref = Some("JB_ID".into());
        provider.client_secret_secret_ref = Some("JB_SECRET".into());

        let response = request_gateway_grant(
            &provider,
            &["agent.read".to_string()],
            &ProviderSecrets::new(&secrets, &provider),
            &endpoint.egress(),
        )
        .await
        .expect("grant succeeds");
        assert_eq!(response.access_token, "gateway-token");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.refresh_token, None, "a refresh token from a gateway grant is dropped");

        let form = endpoint.last_form();
        assert_eq!(form["grant_type"], JWT_BEARER_GRANT_TYPE);
        assert_eq!(form["scope"], "agent.read");
        assert!(!form.contains_key("client_secret"));
        let segments: Vec<&str> = form["assertion"]
            .split('.')
            .collect();
        assert_eq!(segments.len(), 3);
        let header = decode_segment(segments[0]);
        let claims = decode_segment(segments[1]);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "rs-key-1");
        assert_eq!(claims["iss"], "https://issuer.demo.example");
        assert_eq!(claims["sub"], "agent-1");
        assert_eq!(claims["aud"], endpoint.url.as_str());
        assert_eq!(claims["scope"], "agent.read");

        use base64::Engine;
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("jb-client:{}", urlencoding::encode("s3cret:+/")))
        );
        assert_eq!(endpoint.last_authorization(), Some(expected));
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_with_a_service_account_key_uses_its_key_id_and_no_client_auth() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", &service_account_json("sa-kid"), None)]).await;
        let mut provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Rs256);
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.key_id = None;
            settings.assertion_subject = None;
        }

        request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &endpoint.egress())
            .await
            .expect("grant succeeds");
        let form = endpoint.last_form();
        let segments: Vec<&str> = form["assertion"]
            .split('.')
            .collect();
        assert_eq!(decode_segment(segments[0])["kid"], "sa-kid");
        assert!(
            decode_segment(segments[1])
                .get("sub")
                .is_none(),
            "no sub claim without a subject"
        );
        assert_eq!(decode_segment(segments[1])["aud"], endpoint.url.as_str());
        assert!(!form.contains_key("scope"));
        assert!(!form.contains_key("client_id"));
        assert_eq!(endpoint.last_authorization(), None);
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_uses_the_provider_audience_as_aud() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", ec_pkcs8_pem(), None)]).await;
        let mut provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Es256);
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.audience = Some("https://issuer.demo.example".into());
        }

        request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &endpoint.egress())
            .await
            .expect("grant succeeds");
        let form = endpoint.last_form();
        let segments: Vec<&str> = form["assertion"]
            .split('.')
            .collect();
        let claims = decode_segment(segments[1]);
        assert_eq!(claims["aud"], "https://issuer.demo.example");
        assert_eq!(claims["sub"], "agent-1");
    }

    #[test]
    fn test_gateway_token_key_changes_with_the_jwt_bearer_audience() {
        let mut provider = jwt_provider("https://auth.example/token", JwtBearerAlgorithm::Es256);
        let without = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.audience = Some("urn:example:a".into());
        }
        let first = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.audience = Some("urn:example:b".into());
        }
        let second = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        assert_ne!(without, first);
        assert_ne!(first, second);
        assert_ne!(first.provider_digest, second.provider_digest);
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.audience = Some("urn:example:a".into());
        }
        assert_eq!(GatewayTokenKey::for_target_auth(&provider, &[]).expect("key"), first);
    }

    fn mock_egress(server: &MockAuthServer) -> GrantEgress {
        GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(server.token_endpoint()),
        }
    }

    fn mock_jwt_provider(
        server: &MockAuthServer,
        fixture: &SigningFixture,
    ) -> CredentialProvider {
        let algorithm = match fixture.kind() {
            KeyKind::Rsa => JwtBearerAlgorithm::Rs256,
            KeyKind::Ec => JwtBearerAlgorithm::Es256,
        };
        let mut provider = jwt_provider(&server.token_endpoint(), algorithm);
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.key_id = Some(fixture.kid.clone());
        }
        server.register_jwt_client(JwtBearerClient {
            iss: "https://issuer.demo.example".into(),
            sub: "agent-1".into(),
            keys: vec![fixture.clone()],
        });
        provider
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_is_accepted_by_the_authorization_server_for_rs256_and_es256() {
        for fixture in [SigningFixture::rs256(0), SigningFixture::es256(0)] {
            let server = MockAuthServer::start().await;
            let directory = tempfile::tempdir().expect("tempdir");
            let secrets = secrets_with(&directory, &[("SIGNING_KEY", fixture.private_pkcs8_pem(), None)]).await;
            let provider = mock_jwt_provider(&server, &fixture);

            let response = request_gateway_grant(
                &provider,
                &["read".to_string()],
                &ProviderSecrets::new(&secrets, &provider),
                &mock_egress(&server),
            )
            .await
            .expect("the authorization server accepts the assertion");

            assert!(
                !response
                    .access_token
                    .is_empty()
            );
            assert_eq!(response.expires_in, Some(3600));
            assert_eq!(server.token_request_count(), 1);
            let logged = server.requests();
            assert_eq!(logged.len(), 1);
            assert_eq!(logged[0].status, 200, "{:?}", fixture.kind());
            assert_eq!(
                logged[0]
                    .grant_type
                    .as_deref(),
                Some(JWT_BEARER_GRANT_TYPE)
            );
            assert_eq!(logged[0].scope.as_deref(), Some("read"));
        }
    }

    #[tokio::test]
    async fn test_client_credentials_grant_posts_the_client_secret() {
        let server = MockAuthServer::start().await;
        server.register_client("cc-client", "cc-secret");
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "cc-client", None), ("CC_SECRET", "cc-secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &server.token_endpoint());
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        provider.resource = Some("https://agent.example/api".into());

        let response = request_gateway_grant(
            &provider,
            &["read".to_string(), "write".to_string()],
            &ProviderSecrets::new(&secrets, &provider),
            &mock_egress(&server),
        )
        .await
        .expect("grant succeeds");
        assert!(
            !response
                .access_token
                .is_empty()
        );
        assert_eq!(response.token_type, "Bearer");
        let logged = server.requests();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].status, 200);
        assert_eq!(
            logged[0]
                .grant_type
                .as_deref(),
            Some("client_credentials")
        );
        assert_eq!(logged[0].client_id.as_deref(), Some("cc-client"));
        assert_eq!(logged[0].scope.as_deref(), Some("read write"));
        assert_eq!(logged[0].audience.as_deref(), Some("https://agent.example/api"));
    }

    #[tokio::test]
    async fn test_grant_response_over_the_size_cap_is_invalid() {
        let server = MockAuthServer::start().await;
        server.set_fault(Endpoint::Token, Fault::Oversized);
        let fixture = SigningFixture::es256(0);
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", fixture.private_pkcs8_pem(), None)]).await;
        let provider = mock_jwt_provider(&server, &fixture);
        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &mock_egress(&server))
                .await
                .map(|_| ()),
            Err(GatewayTokenError::InvalidResponse)
        );
        assert_eq!(server.request_count(Endpoint::Token), 1);
    }

    #[tokio::test]
    async fn test_grant_to_an_unlisted_loopback_endpoint_is_never_sent() {
        let server = MockAuthServer::start().await;
        server.register_client("id", "secret");
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &server.token_endpoint());
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let egress = GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: None,
        };
        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &egress)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Forbidden)
        );
        assert_eq!(server.token_request_count(), 0);
    }

    #[tokio::test]
    async fn test_grant_secret_of_another_tenant_is_forbidden_and_missing_is_unavailable() {
        let server = MockAuthServer::start().await;
        let fixture = SigningFixture::es256(0);
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", fixture.private_pkcs8_pem(), None)]).await;
        let mut provider = mock_jwt_provider(&server, &fixture);
        provider.tenant_id = Some("tenant-a".into());
        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &mock_egress(&server))
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Forbidden)
        );
        provider.tenant_id = None;
        if let Some(settings) = provider.jwt_bearer.as_mut() {
            settings.signing_key_secret_ref = "MISSING".into();
        }
        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &mock_egress(&server))
                .await
                .map(|_| ()),
            Err(GatewayTokenError::SecretUnavailable)
        );
        assert_eq!(server.token_request_count(), 0);
    }

    #[tokio::test]
    async fn test_rejected_grant_never_leaks_the_error_body() {
        let leak = "tenant-controlled-detail-7f3a";
        let endpoint = TokenEndpoint::start(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_grant", "error_description": leak}).to_string(),
        )
        .await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", ec_pkcs8_pem(), None)]).await;
        let provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Es256);

        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let error =
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &endpoint.egress())
                .await
                .expect_err("a 400 is a failure");

        assert_eq!(error, GatewayTokenError::Unavailable);
        assert!(
            !error
                .to_string()
                .contains(leak)
        );
        let logged = logs.text();
        assert!(logged.contains("Gateway grant rejected by the token endpoint"), "{logged}");
        assert!(logged.contains("invalid_grant"), "{logged}");
        assert!(!logged.contains(leak), "{logged}");
    }

    #[tokio::test]
    async fn test_grant_logs_never_carry_the_key_assertion_token_or_client_secret() {
        let access_token = "gateway-access-token-5d1c9e";
        let client_secret = "gateway-client-secret-8b27f4";
        let refusal = "refusal-detail-2e6a1b";
        let granted = serde_json::json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600});
        let jwt_endpoint = TokenEndpoint::start(StatusCode::OK, granted.to_string()).await;
        let cc_endpoint = TokenEndpoint::start(StatusCode::OK, granted.to_string()).await;
        let refusing_endpoint = TokenEndpoint::start(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_grant", "error_description": refusal}).to_string(),
        )
        .await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(
            &directory,
            &[("SIGNING_KEY", ec_pkcs8_pem(), None), ("CC_ID", "cc-client", None), ("CC_SECRET", client_secret, None)],
        )
        .await;
        let jwt = jwt_provider(&jwt_endpoint.url, JwtBearerAlgorithm::Es256);
        let mut cc = provider(CredentialProviderType::OAuth2ClientCredentials, &cc_endpoint.url);
        cc.client_id_secret_ref = Some("CC_ID".into());
        cc.client_secret_secret_ref = Some("CC_SECRET".into());
        let refused = jwt_provider(&refusing_endpoint.url, JwtBearerAlgorithm::Es256);

        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let jwt_grant = request_gateway_grant(&jwt, &[], &ProviderSecrets::new(&secrets, &jwt), &jwt_endpoint.egress())
            .await
            .expect("the JWT bearer grant succeeds");
        let cc_grant = request_gateway_grant(&cc, &[], &ProviderSecrets::new(&secrets, &cc), &cc_endpoint.egress())
            .await
            .expect("the client credentials grant succeeds");
        let refusal_error = request_gateway_grant(
            &refused,
            &[],
            &ProviderSecrets::new(&secrets, &refused),
            &refusing_endpoint.egress(),
        )
        .await
        .expect_err("a 400 is a failure");
        let logged = logs.text();

        assert_eq!(jwt_grant.access_token, access_token);
        assert_eq!(cc_grant.access_token, access_token);
        assert_eq!(refusal_error, GatewayTokenError::Unavailable);
        assert!(logged.contains("Gateway grant rejected by the token endpoint"), "{logged}");
        assert!(logged.contains("provider_id=provider"), "{logged}");
        assert!(logged.contains("status=400"), "{logged}");
        assert!(logged.contains("error_code=\"invalid_grant\""), "{logged}");
        let assertion = jwt_endpoint
            .last_form()
            .remove("assertion")
            .expect("the JWT bearer grant posts an assertion");
        let refused_assertion = refusing_endpoint
            .last_form()
            .remove("assertion")
            .expect("the refused grant posts an assertion");
        let key_lines = ec_pkcs8_pem()
            .lines()
            .filter(|line| !line.starts_with("-----") && !line.is_empty());
        for forbidden in
            [access_token, client_secret, refusal, assertion.as_str(), refused_assertion.as_str(), "PRIVATE KEY"]
                .into_iter()
                .chain(key_lines)
        {
            assert!(!logged.contains(forbidden), "the log carries {forbidden:?}: {logged}");
        }
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_requires_https() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", ec_pkcs8_pem(), None)]).await;
        let provider = jwt_provider("http://192.0.2.10/token", JwtBearerAlgorithm::Es256);
        let egress = GrantEgress {
            timeout: Duration::from_secs(1),
            exact_allowlist: Some("http://192.0.2.10/other".into()),
        };
        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &egress)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Forbidden)
        );
    }

    #[tokio::test]
    async fn test_grant_for_consent_and_api_key_providers_is_unsupported() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[]).await;
        for provider_type in [CredentialProviderType::OAuth2AuthorizationCode, CredentialProviderType::ApiKey] {
            let provider = provider(provider_type, "https://auth.example/token");
            assert_eq!(
                request_gateway_grant(
                    &provider,
                    &[],
                    &ProviderSecrets::new(&secrets, &provider),
                    &GrantEgress::from_environment()
                )
                .await
                .map(|_| ()),
                Err(GatewayTokenError::Unsupported)
            );
        }
    }

    #[test]
    fn test_parse_grant_response_bounds_and_rejects() {
        let parsed = |body: serde_json::Value| parse_grant_response(body.to_string().as_bytes());
        assert_eq!(
            parsed(serde_json::json!({"access_token": "t", "token_type": "Bearer"}))
                .expect("valid")
                .expires_in,
            Some(DEFAULT_GATEWAY_TOKEN_LIFETIME_SECS)
        );
        assert_eq!(
            parsed(serde_json::json!({"access_token": "t", "token_type": "bearer", "expires_in": 999_999_999}))
                .expect("valid")
                .expires_in,
            Some(MAX_GATEWAY_TOKEN_LIFETIME_SECS)
        );
        assert_eq!(
            parsed(serde_json::json!({"access_token": "t", "token_type": "bearer", "expires_in": "120"}))
                .expect("valid")
                .expires_in,
            Some(120)
        );
        for body in [
            serde_json::json!({"access_token": "t"}),
            serde_json::json!({"access_token": "t", "token_type": "mac"}),
            serde_json::json!({"access_token": "", "token_type": "bearer"}),
            serde_json::json!({"access_token": "a b", "token_type": "bearer"}),
            serde_json::json!({"access_token": "x".repeat(MAX_GATEWAY_TOKEN_BYTES + 1), "token_type": "bearer"}),
            serde_json::json!({"access_token": "t", "token_type": "bearer", "expires_in": 0}),
            serde_json::json!({"access_token": "t", "token_type": "bearer", "expires_in": "soon"}),
            serde_json::json!({"access_token": "t", "token_type": "bearer", "expires_in": true}),
            serde_json::json!({"access_token": "t", "token_type": "bearer", "expires_in": 1.5}),
            serde_json::json!({"token_type": "bearer"}),
        ] {
            assert_eq!(parsed(body.clone()).map(|_| ()), Err(GatewayTokenError::InvalidResponse), "{body}");
        }
        assert_eq!(parse_grant_response(b"not json").map(|_| ()), Err(GatewayTokenError::InvalidResponse));
        assert!(
            parsed(serde_json::json!({"access_token": "x".repeat(MAX_GATEWAY_TOKEN_BYTES), "token_type": "bearer"}))
                .is_ok()
        );
    }

    #[test]
    fn test_token_endpoint_is_https_or_exactly_allowlisted() {
        let egress = GrantEgress {
            timeout: Duration::from_secs(1),
            exact_allowlist: Some("not a url, http://127.0.0.1:4000/token".into()),
        };
        assert!(egress.permits_token_endpoint(" https://auth.example/token "));
        assert!(egress.permits_token_endpoint("http://127.0.0.1:4000/token"));
        assert!(!egress.permits_token_endpoint("http://127.0.0.1:4000/other"));
        assert!(!egress.permits_token_endpoint("http://auth.example/token"));
        assert!(!egress.permits_token_endpoint("not a url"));
        assert!(!egress.permits_token_endpoint(""));
        let production = GrantEgress {
            timeout: Duration::from_secs(1),
            exact_allowlist: None,
        };
        assert!(!production.permits_token_endpoint("http://127.0.0.1:4000/token"));
    }

    struct SlowSecrets {
        inner: Arc<dyn SecretsStore>,
        delay: Duration,
        reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SecretsStore for SlowSecrets {
        async fn create(
            &self,
            request: CreateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .create(request)
                .await
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            self.inner.get(id).await
        }
        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            self.reads
                .fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.inner
                .get_by_secret_id(secret_id)
                .await
        }
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.inner.list_all().await
        }
        async fn update(
            &self,
            id: &str,
            request: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .update(id, request)
                .await
        }
        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.inner.delete(id).await
        }
        async fn find_by_tag(
            &self,
            tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.inner
                .find_by_tag(tag)
                .await
        }
    }

    async fn slow_client_credentials(
        directory: &tempfile::TempDir,
        delay: Duration,
    ) -> Arc<SlowSecrets> {
        Arc::new(SlowSecrets {
            inner: secrets_with(directory, &[("CC_ID", "cc-client", None), ("CC_SECRET", "cc-secret", None)]).await,
            delay,
            reads: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    #[tokio::test]
    async fn test_client_credentials_grant_to_an_http_endpoint_sends_nothing() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let counting = slow_client_credentials(&directory, Duration::ZERO).await;
        let secrets: Arc<dyn SecretsStore> = counting.clone();
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &endpoint.url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let unlisted = GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some("http://192.0.2.10/token".into()),
        };

        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &unlisted)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Forbidden)
        );
        assert_eq!(
            counting
                .reads
                .load(Ordering::SeqCst),
            0,
            "no secret is read for an http endpoint"
        );
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            0
        );

        let granted =
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &endpoint.egress())
                .await
                .expect("an exactly allowlisted endpoint is granted");
        assert_eq!(granted.access_token, "gateway-token");
        assert_eq!(
            counting
                .reads
                .load(Ordering::SeqCst),
            2
        );
        assert_eq!(endpoint.last_form()["client_secret"], "cc-secret");
    }

    #[tokio::test]
    async fn test_a_grant_whose_secret_read_outlasts_the_timeout_is_unavailable() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets: Arc<dyn SecretsStore> = slow_client_credentials(&directory, Duration::from_secs(2)).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &endpoint.url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let egress = GrantEgress {
            timeout: Duration::from_millis(200),
            exact_allowlist: Some(endpoint.url.clone()),
        };

        let started = Instant::now();
        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &egress)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn test_client_credentials_grant_without_both_client_references_is_unsupported() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "cc-client", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &endpoint.url);
        let request = |provider: CredentialProvider| {
            let secrets = secrets.clone();
            let egress = endpoint.egress();
            async move {
                request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &egress)
                    .await
                    .map(|_| ())
            }
        };

        assert_eq!(request(provider.clone()).await, Err(GatewayTokenError::Unsupported));
        provider.client_id_secret_ref = Some("  ".into());
        assert_eq!(request(provider.clone()).await, Err(GatewayTokenError::Unsupported));
        provider.client_id_secret_ref = Some("CC_ID".into());
        assert_eq!(request(provider.clone()).await, Err(GatewayTokenError::Unsupported));
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn test_jwt_bearer_grant_with_only_a_client_id_sends_it_in_the_form_without_basic_auth() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets =
            secrets_with(&directory, &[("SIGNING_KEY", ec_pkcs8_pem(), None), ("JB_ID", "public-client", None)]).await;
        let mut provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Es256);
        provider.client_id_secret_ref = Some("JB_ID".into());

        request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &endpoint.egress())
            .await
            .expect("grant succeeds");

        let form = endpoint.last_form();
        assert_eq!(form["client_id"], "public-client");
        assert!(!form.contains_key("client_secret"));
        assert_eq!(form["grant_type"], JWT_BEARER_GRANT_TYPE);
        assert_eq!(endpoint.last_authorization(), None);

        let mut missing = provider.clone();
        missing.client_id_secret_ref = Some("MISSING".into());
        assert_eq!(
            request_gateway_grant(&missing, &[], &ProviderSecrets::new(&secrets, &missing), &endpoint.egress())
                .await
                .map(|_| ()),
            Err(GatewayTokenError::SecretUnavailable)
        );
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_a_token_endpoint_whose_host_does_not_resolve_is_unavailable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "cc-client", None), ("CC_SECRET", "cc-secret", None)]).await;
        let egress = GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: None,
        };
        let mut provider =
            provider(CredentialProviderType::OAuth2ClientCredentials, "https://token-endpoint.invalid/token");
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());

        assert_eq!(
            request_gateway_grant(&provider, &[], &ProviderSecrets::new(&secrets, &provider), &egress)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Unavailable)
        );
    }

    #[test]
    fn test_freshness_has_a_stable_label_for_each_outcome() {
        assert_eq!(Freshness::Cached.as_str(), "cached");
        assert_eq!(Freshness::Fresh.as_str(), "fresh");
        assert_eq!(Freshness::StaleAfterRefreshFailure.as_str(), "stale");
    }

    #[test]
    fn test_refresh_margin_is_at_most_five_minutes_or_half_the_lifetime() {
        assert_eq!(refresh_margin_secs(3600), 300);
        assert_eq!(refresh_margin_secs(600), 300);
        assert_eq!(refresh_margin_secs(120), 60);
        assert_eq!(refresh_margin_secs(1), 0);
        assert_eq!(refresh_margin_secs(-5), 0);
    }

    #[test]
    fn test_bounded_lifetime_defaults_caps_and_refuses() {
        assert_eq!(bounded_lifetime_secs(None), Ok(DEFAULT_GATEWAY_TOKEN_LIFETIME_SECS));
        assert_eq!(bounded_lifetime_secs(Some(60)), Ok(60));
        assert_eq!(bounded_lifetime_secs(Some(i64::MAX)), Ok(MAX_GATEWAY_TOKEN_LIFETIME_SECS));
        assert_eq!(bounded_lifetime_secs(Some(0)), Err(GatewayTokenError::InvalidResponse));
        assert_eq!(bounded_lifetime_secs(Some(-1)), Err(GatewayTokenError::InvalidResponse));
    }

    #[tokio::test]
    async fn test_grant_backoff_doubles_to_a_minute_and_clears_on_success() {
        let backoff = GrantBackoff::new(16);
        let just_before = |instant: Instant| instant - Duration::from_millis(1);
        let mut sent = Instant::now();
        for delay in [1, 2, 4, 8, 16, 32, 60, 60] {
            assert!(
                backoff
                    .retry_allowed("key", sent)
                    .await
            );
            backoff
                .record_failure("key", sent, sent)
                .await;
            let retry_at = sent + Duration::from_secs(delay);
            assert!(
                !backoff
                    .retry_allowed("key", just_before(retry_at))
                    .await,
                "{delay} s"
            );
            sent = retry_at;
        }
        assert!(
            backoff
                .retry_allowed("other", just_before(sent))
                .await
        );

        backoff
            .record_failure("key", just_before(sent), sent)
            .await;
        assert!(
            backoff
                .retry_allowed("key", sent)
                .await,
            "a failure sent before the window opened is not counted"
        );

        backoff
            .record_success("key", sent)
            .await;
        assert!(
            backoff
                .retry_allowed("key", just_before(sent))
                .await,
            "a success never holds a grant back"
        );
        let late = sent + Duration::from_secs(1);
        backoff
            .record_failure("key", just_before(sent), late)
            .await;
        assert!(
            backoff
                .retry_allowed("key", late)
                .await,
            "a slow failure sent before the success never backs off"
        );

        backoff
            .record_failure("key", late, late)
            .await;
        assert!(
            !backoff
                .retry_allowed("key", just_before(late + BACKOFF_INITIAL))
                .await
        );
        assert!(
            backoff
                .retry_allowed("key", late + BACKOFF_INITIAL)
                .await,
            "the next failure after a success starts again at 1 s"
        );
    }

    #[tokio::test]
    async fn test_concurrent_failed_grants_in_one_window_count_as_one_failure() {
        let endpoint = TokenEndpoint::start(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#.into()).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", ec_pkcs8_pem(), None)]).await;
        let provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Es256);
        let provider_secrets = ProviderSecrets::new(&secrets, &provider);
        let egress = endpoint.egress();
        let backoff = GrantBackoff::new(16);
        let scopes = vec!["read".to_string()];
        let start = Instant::now();

        let results = futures::future::join_all(
            (0..8).map(|_| backoff.request_at(&provider, &scopes, &provider_secrets, &egress, start)),
        )
        .await;

        assert!(
            results
                .iter()
                .all(|result| matches!(result, Err(GatewayTokenError::Unavailable)))
        );
        let entry = backoff
            .entries
            .get(&backoff_key(&provider, &scopes))
            .await
            .expect("the failure is recorded");
        assert_eq!(entry.failures, 1, "failures from one window count once");
        assert!(entry.retry_at >= start + BACKOFF_INITIAL);
        assert!(entry.retry_at < start + BACKOFF_INITIAL * 2 + egress.timeout);
    }

    #[tokio::test]
    async fn test_a_local_grant_failure_is_reported_as_itself_and_never_backs_off() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", "not a key", None)]).await;
        let provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Rs256);
        let provider_secrets = ProviderSecrets::new(&secrets, &provider);
        let backoff = GrantBackoff::new(16);
        let cache = GatewayTokenCache::new(endpoint.egress());
        let key = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        let start = Instant::now();

        for _ in 0..2 {
            assert_eq!(
                backoff
                    .request_at(&provider, &[], &provider_secrets, &endpoint.egress(), start)
                    .await
                    .map(|_| ()),
                Err(GatewayTokenError::AssertionFailed)
            );
            assert_eq!(
                acquire_gateway_token_at(&cache, &key, &provider, &provider_secrets, start)
                    .await
                    .map(|_| ()),
                Err(GatewayTokenError::AssertionFailed)
            );
        }
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            0
        );
        assert!(!GatewayTokenError::AssertionFailed.backs_off());
        assert!(!GatewayTokenError::Forbidden.backs_off());
        assert!(GatewayTokenError::Unavailable.backs_off());
        assert!(GatewayTokenError::InvalidResponse.backs_off());
        assert!(GatewayTokenError::ScopeMismatch.backs_off());
    }

    #[tokio::test]
    async fn test_backed_off_grant_is_unavailable_without_a_request() {
        let endpoint = TokenEndpoint::start(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#.into()).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", ec_pkcs8_pem(), None)]).await;
        let provider = jwt_provider(&endpoint.url, JwtBearerAlgorithm::Es256);
        let provider_secrets = ProviderSecrets::new(&secrets, &provider);
        let backoff = GrantBackoff::new(16);
        let scopes = vec!["read".to_string()];

        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        for _ in 0..2 {
            let error = backoff
                .request(&provider, &scopes, &provider_secrets, &endpoint.egress())
                .await
                .expect_err("a rejected grant fails");
            assert_eq!(error, GatewayTokenError::Unavailable);
        }
        let logged = logs.text();

        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            logged
                .matches("Gateway grant held back by the retry backoff")
                .count(),
            1,
            "{logged}"
        );
        assert!(logged.contains("grant=\"jwt_bearer\""), "{logged}");
        assert!(!logged.contains("Gateway grant failed"), "{logged}");
    }

    #[tokio::test]
    async fn test_a_target_auth_grant_that_cannot_reach_its_endpoint_logs_the_provider_and_category() {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let url = format!(
            "http://{}/token",
            closed
                .local_addr()
                .expect("address")
        );
        drop(closed);
        let client_secret = "cc-secret-71d3a0";
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets =
            secrets_with(&directory, &[("CC_ID", "cc-client", None), ("CC_SECRET", client_secret, None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let cache = GatewayTokenCache::new(GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(url.clone()),
        });
        let key = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        let provider_secrets = ProviderSecrets::new(&secrets, &provider);
        let start = Instant::now();

        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let failed = acquire_gateway_token_at(&cache, &key, &provider, &provider_secrets, start)
            .await
            .map(|_| ());
        let held_back = acquire_gateway_token_at(&cache, &key, &provider, &provider_secrets, start)
            .await
            .map(|_| ());
        let logged = logs.text();

        assert_eq!(failed, Err(GatewayTokenError::Unavailable));
        assert_eq!(held_back, Err(GatewayTokenError::Unavailable));
        assert_eq!(
            logged
                .matches("Gateway grant failed")
                .count(),
            1,
            "{logged}"
        );
        assert_eq!(
            logged
                .matches("Gateway grant held back by the retry backoff")
                .count(),
            1,
            "{logged}"
        );
        assert!(logged.contains("provider_id=provider"), "{logged}");
        assert!(logged.contains("grant=\"client_credentials\""), "{logged}");
        assert!(logged.contains("category=\"unavailable\""), "{logged}");
        assert!(logged.contains("stale_token_kept=false"), "{logged}");
        assert!(!logged.contains(client_secret), "{logged}");
        assert!(!logged.contains(&url), "{logged}");
    }

    #[test]
    fn test_backoff_key_changes_with_the_provider_record_and_ignores_scope_order() {
        let mut provider = provider(CredentialProviderType::OAuth2JwtBearer, "https://auth.example/token");
        let first = backoff_key(&provider, &["b".to_string(), "a".to_string()]);
        assert_eq!(first, backoff_key(&provider, &["a".to_string(), "b".to_string(), "a".to_string()]));
        provider.updated_at += chrono::Duration::seconds(1);
        assert_ne!(first, backoff_key(&provider, &["a".to_string(), "b".to_string()]));
    }

    struct CacheFixture {
        server: MockAuthServer,
        _directory: tempfile::TempDir,
        secrets: Arc<dyn SecretsStore>,
        provider: CredentialProvider,
        cache: GatewayTokenCache,
    }

    impl CacheFixture {
        async fn start(tenant: Option<&str>) -> Self {
            let server = MockAuthServer::start().await;
            let suffix = tenant.unwrap_or("appliance");
            let (id_ref, secret_ref) = (format!("CC_ID_{suffix}"), format!("CC_SECRET_{suffix}"));
            server.register_client(&format!("client-{suffix}"), "client-secret");
            let directory = tempfile::tempdir().expect("tempdir");
            let secrets = secrets_with(
                &directory,
                &[
                    (id_ref.as_str(), &format!("client-{suffix}"), tenant),
                    (secret_ref.as_str(), "client-secret", tenant),
                ],
            )
            .await;
            let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &server.token_endpoint());
            provider.id = format!("provider-{suffix}");
            provider.tenant_id = tenant.map(str::to_string);
            provider.client_id_secret_ref = Some(id_ref);
            provider.client_secret_secret_ref = Some(secret_ref);
            let cache = GatewayTokenCache::new(mock_egress(&server));
            Self {
                server,
                _directory: directory,
                secrets,
                provider,
                cache,
            }
        }

        fn key(&self) -> GatewayTokenKey {
            GatewayTokenKey::for_target_auth(&self.provider, &["read".to_string()]).expect("key builds")
        }

        async fn acquire_at(
            &self,
            now: Instant,
        ) -> Result<GatewayTokenGrant, GatewayTokenError> {
            acquire_gateway_token_at(
                &self.cache,
                &self.key(),
                &self.provider,
                &ProviderSecrets::new(&self.secrets, &self.provider),
                now,
            )
            .await
        }

        async fn acquire(&self) -> Result<GatewayTokenGrant, GatewayTokenError> {
            self.acquire_at(Instant::now())
                .await
        }
    }

    #[tokio::test]
    async fn test_a_grant_carries_its_wall_clock_expiry_and_a_cached_grant_keeps_it() {
        let fixture = CacheFixture::start(None).await;
        let before = SystemTime::now();
        let fresh = fixture
            .acquire()
            .await
            .expect("fresh token");
        let cached = fixture
            .acquire()
            .await
            .expect("cached token");

        assert_eq!(fresh.freshness, Freshness::Fresh);
        assert_eq!(cached.freshness, Freshness::Cached);
        assert_eq!(cached.expires_at, fresh.expires_at, "the cached grant reports the stored expiry");
        assert!(fresh.expires_at > before);
        assert!(
            fresh.expires_at <= SystemTime::now() + Duration::from_secs(MAX_GATEWAY_TOKEN_LIFETIME_SECS.unsigned_abs()),
            "the expiry is bounded by the trusted lifetime"
        );
        assert!(!format!("{fresh:?}").contains(fresh.access_token.as_str()), "Debug never shows the token");
    }

    #[tokio::test]
    async fn test_concurrent_requests_share_one_gateway_grant() {
        let fixture = CacheFixture::start(None).await;
        let grants = futures::future::join_all((0..16).map(|_| fixture.acquire())).await;

        let tokens: Vec<String> = grants
            .iter()
            .map(|grant| {
                grant
                    .as_ref()
                    .expect("every request gets the token")
                    .access_token
                    .to_string()
            })
            .collect();
        assert!(
            tokens
                .iter()
                .all(|token| *token == tokens[0])
        );
        assert_eq!(
            grants
                .iter()
                .filter(|grant| matches!(
                    grant,
                    Ok(GatewayTokenGrant {
                        freshness: Freshness::Fresh,
                        ..
                    })
                ))
                .count(),
            1
        );
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            1
        );

        let reused = fixture
            .acquire()
            .await
            .expect("cached token");
        assert_eq!(reused.freshness, Freshness::Cached);
        assert_eq!(*reused.access_token, tokens[0]);
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            1
        );
    }

    #[tokio::test]
    async fn test_repeated_cache_hits_never_request_another_token() {
        let fixture = CacheFixture::start(None).await;
        fixture
            .acquire()
            .await
            .expect("first grant");
        for _ in 0..500 {
            let grant = fixture
                .acquire()
                .await
                .expect("cached");
            assert_eq!(grant.freshness, Freshness::Cached);
        }
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            1
        );
    }

    #[tokio::test]
    #[ignore = "wall-clock benchmark; run with --ignored on an idle machine"]
    async fn bench_cache_hit_adds_under_a_millisecond_at_p95() {
        let fixture = CacheFixture::start(None).await;
        fixture
            .acquire()
            .await
            .expect("first grant");
        let mut samples = Vec::with_capacity(500);
        for _ in 0..500 {
            let started = Instant::now();
            fixture
                .acquire()
                .await
                .expect("cached");
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let p95 = samples[samples.len() * 95 / 100];
        assert!(p95 < Duration::from_millis(1), "cache hit p95 {p95:?}");
    }

    #[tokio::test]
    async fn test_failed_refresh_keeps_the_valid_token_and_backs_off() {
        let fixture = CacheFixture::start(None).await;
        let start = Instant::now();
        let first = fixture
            .acquire_at(start)
            .await
            .expect("first grant");
        assert_eq!(first.freshness, Freshness::Fresh);

        fixture
            .server
            .set_fault(Endpoint::Token, Fault::NotFound);
        let refresh_due = start + Duration::from_secs(3_400);
        let stale = fixture
            .acquire_at(refresh_due)
            .await
            .expect("the valid token is kept");
        assert_eq!(stale.freshness, Freshness::StaleAfterRefreshFailure);
        assert_eq!(*stale.access_token, *first.access_token);
        assert_eq!(
            fixture
                .server
                .request_count(Endpoint::Token),
            2
        );

        let backed_off = fixture
            .acquire_at(refresh_due)
            .await
            .expect("still valid");
        assert_eq!(backed_off.freshness, Freshness::Cached);
        assert_eq!(
            fixture
                .server
                .request_count(Endpoint::Token),
            2,
            "no grant inside the backoff window"
        );

        let expired = start + Duration::from_secs(3_700);
        assert_eq!(
            fixture
                .acquire_at(expired)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Unavailable)
        );
        assert_eq!(
            fixture
                .server
                .request_count(Endpoint::Token),
            3
        );
        assert_eq!(
            fixture
                .acquire_at(expired)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Unavailable)
        );
        assert_eq!(
            fixture
                .server
                .request_count(Endpoint::Token),
            3,
            "backoff without a valid token sends nothing"
        );

        fixture.server.clear_faults();
        let renewed = fixture
            .acquire_at(expired + Duration::from_secs(60))
            .await
            .expect("renewed after the backoff");
        assert_eq!(renewed.freshness, Freshness::Fresh);
        assert_eq!(
            fixture
                .server
                .request_count(Endpoint::Token),
            4
        );
    }

    #[tokio::test]
    async fn test_refresh_runs_once_while_other_requests_keep_the_valid_token() {
        let fixture = CacheFixture::start(None).await;
        let start = Instant::now();
        let first = fixture
            .acquire_at(start)
            .await
            .expect("first grant");
        let refresh_due = start + Duration::from_secs(3_400);
        let grants = futures::future::join_all((0..8).map(|_| fixture.acquire_at(refresh_due))).await;
        assert!(
            grants
                .iter()
                .all(Result::is_ok)
        );
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            2
        );
        assert!(
            grants
                .iter()
                .flatten()
                .filter(|grant| grant.freshness == Freshness::Cached)
                .all(|grant| *grant.access_token == *first.access_token)
        );
    }

    #[tokio::test]
    async fn test_updating_one_tenants_secret_leaves_another_tenants_tokens() {
        let tenant_a = CacheFixture::start(Some("tenant-a")).await;
        let tenant_b = CacheFixture::start(Some("tenant-b")).await;
        let shared = GatewayTokenCache::new(GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(format!(
                "{},{}",
                tenant_a
                    .server
                    .token_endpoint(),
                tenant_b
                    .server
                    .token_endpoint()
            )),
        });
        async fn acquire(
            shared: &GatewayTokenCache,
            fixture: &CacheFixture,
        ) -> Freshness {
            acquire_gateway_token(
                shared,
                &fixture.key(),
                &fixture.provider,
                &ProviderSecrets::new(&fixture.secrets, &fixture.provider),
            )
            .await
            .expect("grant")
            .freshness
        }
        assert_eq!(acquire(&shared, &tenant_a).await, Freshness::Fresh);
        assert_eq!(acquire(&shared, &tenant_b).await, Freshness::Fresh);

        shared.invalidate_secret("CC_SECRET_tenant-a");
        assert_eq!(acquire(&shared, &tenant_a).await, Freshness::Fresh);
        assert_eq!(acquire(&shared, &tenant_b).await, Freshness::Cached);
        assert_eq!(
            tenant_a
                .server
                .token_request_count(),
            2
        );
        assert_eq!(
            tenant_b
                .server
                .token_request_count(),
            1
        );

        shared.invalidate_provider("provider-tenant-b");
        assert_eq!(acquire(&shared, &tenant_a).await, Freshness::Cached);
        assert_eq!(acquire(&shared, &tenant_b).await, Freshness::Fresh);
        assert_eq!(
            tenant_b
                .server
                .token_request_count(),
            2
        );

        shared.invalidate_secret("UNRELATED");
        shared.invalidate_provider("unrelated");
        assert_eq!(acquire(&shared, &tenant_a).await, Freshness::Cached);
        assert_eq!(acquire(&shared, &tenant_b).await, Freshness::Cached);

        shared.invalidate_all();
        assert_eq!(acquire(&shared, &tenant_a).await, Freshness::Fresh);
        assert_eq!(acquire(&shared, &tenant_b).await, Freshness::Fresh);
        assert_eq!(
            tenant_a
                .server
                .token_request_count(),
            3
        );
        assert_eq!(
            tenant_b
                .server
                .token_request_count(),
            3
        );
    }

    #[tokio::test]
    async fn test_invalid_token_response_is_never_cached() {
        let endpoint = TokenEndpoint::start(
            StatusCode::OK,
            serde_json::json!({"access_token": "x".repeat(MAX_GATEWAY_TOKEN_BYTES + 1), "token_type": "Bearer"})
                .to_string(),
        )
        .await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &endpoint.url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let cache = GatewayTokenCache::new(endpoint.egress());
        let key = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        let secrets = ProviderSecrets::new(&secrets, &provider);
        let start = Instant::now();

        assert_eq!(
            acquire_gateway_token_at(&cache, &key, &provider, &secrets, start)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::InvalidResponse)
        );
        assert_eq!(
            acquire_gateway_token_at(&cache, &key, &provider, &secrets, start)
                .await
                .map(|_| ()),
            Err(GatewayTokenError::Unavailable)
        );
        assert_eq!(
            endpoint
                .calls
                .load(Ordering::SeqCst),
            1
        );
    }

    async fn serve_token_route(route: axum::routing::MethodRouter) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let url = format!(
            "http://{}/token",
            listener
                .local_addr()
                .expect("address")
        );
        let app = axum::Router::new().route("/token", route);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        url
    }

    #[tokio::test]
    async fn test_backoff_after_a_slow_failed_grant_runs_from_when_the_grant_failed() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = serve_token_route(axum::routing::post({
            let calls = calls.clone();
            move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1_500)).await;
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("content-type", "application/json")],
                    r#"{"error":"temporarily_unavailable"}"#,
                )
            }
        }))
        .await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let cache = GatewayTokenCache::new(GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(url),
        });
        let key = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        let secrets = ProviderSecrets::new(&secrets, &provider);
        let start = Instant::now();
        let queued_arrival = start + Duration::from_millis(1_200);

        let (first, queued) = tokio::join!(acquire_gateway_token_at(&cache, &key, &provider, &secrets, start), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            acquire_gateway_token_at(&cache, &key, &provider, &secrets, queued_arrival).await
        });

        assert_eq!(first.map(|_| ()), Err(GatewayTokenError::Unavailable));
        assert_eq!(queued.map(|_| ()), Err(GatewayTokenError::Unavailable));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a request queued behind the slow failure sends no grant");
    }

    #[tokio::test]
    async fn test_a_refresh_that_fails_after_the_token_expired_never_returns_it() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = serve_token_route(axum::routing::post({
            let calls = calls.clone();
            move || async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return (
                        StatusCode::OK,
                        [("content-type", "application/json")],
                        token_body(serde_json::json!({"expires_in": 2})),
                    );
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("content-type", "application/json")],
                    r#"{"error":"temporarily_unavailable"}"#.to_string(),
                )
            }
        }))
        .await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let cache = GatewayTokenCache::new(GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(url),
        });
        let key = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");
        let secrets = ProviderSecrets::new(&secrets, &provider);
        let start = Instant::now();

        let first = acquire_gateway_token_at(&cache, &key, &provider, &secrets, start)
            .await
            .expect("first grant");
        assert_eq!(first.freshness, Freshness::Fresh);

        let refresh_due = start + Duration::from_millis(1_900);
        assert_eq!(
            acquire_gateway_token_at(&cache, &key, &provider, &secrets, refresh_due)
                .await
                .map(|grant| grant.freshness),
            Err(GatewayTokenError::Unavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_jwt_bearer_renewal_signs_a_fresh_assertion_and_returns_a_new_token() {
        let server = MockAuthServer::start().await;
        let fixture = SigningFixture::es256(0);
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("SIGNING_KEY", fixture.private_pkcs8_pem(), None)]).await;
        let provider = mock_jwt_provider(&server, &fixture);
        let cache = GatewayTokenCache::new(mock_egress(&server));
        let key = GatewayTokenKey::for_target_auth(&provider, &["read".to_string()]).expect("key builds");
        let secrets = ProviderSecrets::new(&secrets, &provider);
        let start = Instant::now();

        let first = acquire_gateway_token_at(&cache, &key, &provider, &secrets, start)
            .await
            .expect("first grant");
        let kept = acquire_gateway_token_at(&cache, &key, &provider, &secrets, start + Duration::from_secs(3_299))
            .await
            .expect("token kept before the refresh margin");
        let renewed = acquire_gateway_token_at(&cache, &key, &provider, &secrets, start + Duration::from_secs(3_300))
            .await
            .expect("token renewed inside the refresh margin");

        assert_eq!(first.freshness, Freshness::Fresh);
        assert_eq!(kept.freshness, Freshness::Cached);
        assert_eq!(*kept.access_token, *first.access_token);
        assert_eq!(renewed.freshness, Freshness::Fresh);
        assert_ne!(*renewed.access_token, *first.access_token);
        assert_eq!(server.token_request_count(), 2);
        assert!(
            server
                .requests()
                .iter()
                .all(|logged| logged.status == 200 && logged.grant_type.as_deref() == Some(JWT_BEARER_GRANT_TYPE))
        );

        let assertions = server.accepted_assertions();
        assert_eq!(assertions.len(), 2);
        let token_endpoint = server.token_endpoint();
        for claims in &assertions {
            assert_eq!(claims["iss"], "https://issuer.demo.example");
            assert_eq!(claims["sub"], "agent-1");
            assert_eq!(claims["aud"], token_endpoint.as_str());
            assert_eq!(claims["scope"], "read");
            assert_eq!(
                claims["exp"]
                    .as_i64()
                    .expect("exp")
                    - claims["iat"]
                        .as_i64()
                        .expect("iat"),
                ASSERTION_LIFETIME_SECS + ASSERTION_IAT_BACKDATE_SECS
            );
        }
        assert_ne!(assertions[0]["jti"], assertions[1]["jti"]);
        assert!(assertions[1]["iat"].as_i64() >= assertions[0]["iat"].as_i64());
        assert!(assertions[1]["exp"].as_i64() >= assertions[0]["exp"].as_i64());
    }

    #[tokio::test]
    async fn test_grant_in_flight_during_invalidation_never_repopulates_the_cache() {
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = serve_token_route(axum::routing::post({
            let release = release.clone();
            let calls = calls.clone();
            move || async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    release.notified().await;
                }
                (
                    [("content-type", "application/json")],
                    r#"{"access_token":"slow-token","token_type":"Bearer","expires_in":3600}"#,
                )
            }
        }))
        .await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let cache = Arc::new(GatewayTokenCache::new(GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(url),
        }));
        let key = GatewayTokenKey::for_target_auth(&provider, &[]).expect("key");

        let in_flight = tokio::spawn({
            let (cache, key, provider, secrets) = (cache.clone(), key.clone(), provider.clone(), secrets.clone());
            async move {
                acquire_gateway_token(&cache, &key, &provider, &ProviderSecrets::new(&secrets, &provider))
                    .await
                    .map(|grant| grant.freshness)
            }
        });
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        cache.invalidate_secret("CC_SECRET");
        release.notify_one();
        assert_eq!(
            in_flight
                .await
                .expect("task joins"),
            Ok(Freshness::Fresh)
        );

        let after = acquire_gateway_token(&cache, &key, &provider, &ProviderSecrets::new(&secrets, &provider))
            .await
            .expect("new grant");
        assert_eq!(after.freshness, Freshness::Fresh, "the detached result is not reused");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_target_auth_key_ignores_scope_order_and_changes_with_the_provider() {
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, "https://auth.example/token");
        let key = GatewayTokenKey::for_target_auth(&provider, &["b".into(), "a".into(), "b".into()]).expect("key");
        assert_eq!(key.scopes, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(key, GatewayTokenKey::for_target_auth(&provider, &["a".into(), "b".into()]).expect("key"));
        assert_ne!(key, GatewayTokenKey::for_target_auth(&provider, &["a".into()]).expect("key"));
        provider.resource = Some("https://agent.example/api".into());
        let with_audience = GatewayTokenKey::for_target_auth(&provider, &["a".into(), "b".into()]).expect("key");
        assert_ne!(key, with_audience);
        assert_eq!(
            with_audience
                .audience
                .as_deref(),
            Some("https://agent.example/api")
        );
        provider.token_endpoint = Some("https://other.example/token".into());
        assert_ne!(
            with_audience.provider_digest,
            GatewayTokenKey::for_target_auth(&provider, &["a".into(), "b".into()])
                .expect("key")
                .provider_digest
        );
    }

    #[test]
    fn test_issued_scopes_must_cover_every_requested_scope() {
        let requested = vec!["read".to_string(), " write ".to_string(), "read".to_string()];
        assert!(issued_scopes_cover(None, &requested));
        assert!(issued_scopes_cover(Some("write read"), &requested));
        assert!(issued_scopes_cover(Some("  read   write extra "), &requested));
        assert!(!issued_scopes_cover(Some("read"), &requested));
        assert!(!issued_scopes_cover(Some(""), &requested));
        assert!(!issued_scopes_cover(Some("Read write"), &requested));
        assert!(issued_scopes_cover(Some(""), &[]));
        assert!(issued_scopes_cover(Some("read"), &[]));
        let one_entry = vec!["openid profile".to_string()];
        assert!(issued_scopes_cover(Some("profile openid"), &one_entry));
        assert!(!issued_scopes_cover(Some("openid"), &one_entry));
    }

    #[tokio::test]
    async fn test_a_grant_missing_a_requested_scope_is_refused_and_never_cached() {
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({"scope": "read"}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &endpoint.url);
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        let provider_secrets = ProviderSecrets::new(&secrets, &provider);
        let wider = vec!["read".to_string(), "write".to_string()];

        assert_eq!(
            request_gateway_grant(&provider, &["read".to_string()], &provider_secrets, &endpoint.egress())
                .await
                .map(|response| response.access_token),
            Ok("gateway-token".to_string())
        );
        assert_eq!(
            request_gateway_grant(&provider, &wider, &provider_secrets, &endpoint.egress())
                .await
                .map(|_| ()),
            Err(GatewayTokenError::ScopeMismatch)
        );

        let cache = GatewayTokenCache::new(endpoint.egress());
        let key = GatewayTokenKey::for_target_auth(&provider, &wider).expect("key");
        let start = Instant::now();
        for at in [start, start + BACKOFF_MAX] {
            assert_eq!(
                acquire_gateway_token_at(&cache, &key, &provider, &provider_secrets, at)
                    .await
                    .map(|_| ()),
                Err(GatewayTokenError::ScopeMismatch)
            );
        }
        assert_eq!(endpoint.grants(), 4, "each refused grant left nothing to serve from the cache");
    }

    #[tokio::test]
    async fn test_a_grant_stays_current_only_while_each_secret_it_read_keeps_its_version() {
        use super::test_endpoint::replace_secret;
        let endpoint = TokenEndpoint::start(StatusCode::OK, token_body(serde_json::json!({}))).await;
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(
            &directory,
            &[
                ("CC_ID", "id", Some("tenant-a")),
                ("CC_SECRET", "secret", Some("tenant-a")),
                ("UNUSED_KEY", "kept from an earlier type", Some("tenant-a")),
                ("UNRELATED", "other", Some("tenant-a")),
                ("TENANT_B", "other", Some("tenant-b")),
            ],
        )
        .await;
        let mut provider = provider(CredentialProviderType::OAuth2ClientCredentials, &endpoint.url);
        provider.tenant_id = Some("tenant-a".into());
        provider.client_id_secret_ref = Some("CC_ID".into());
        provider.client_secret_secret_ref = Some("CC_SECRET".into());
        provider.api_key_secret_ref = Some("UNUSED_KEY".into());
        let granting = ProviderSecrets::new(&secrets, &provider);
        assert_eq!(
            request_gateway_grant(&provider, &[], &granting, &endpoint.egress())
                .await
                .map(|response| response.access_token),
            Ok("gateway-token".to_string())
        );
        let versions = granting.versions_read();
        assert_eq!(
            versions
                .iter()
                .map(|version| version.secret_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CC_ID", "CC_SECRET"]
        );
        let check = ProviderSecrets::new(&secrets, &provider);
        assert!(
            check
                .still_current(Some(&versions))
                .await
        );
        assert!(
            !check
                .still_current(None)
                .await
        );
        assert!(
            !check
                .still_current(Some(&[]))
                .await
        );

        for unrelated in ["UNRELATED", "TENANT_B", "UNUSED_KEY"] {
            replace_secret(&secrets, unrelated, "changed").await;
        }
        let unused = secrets
            .get_by_secret_id("UNUSED_KEY")
            .await
            .expect("read")
            .expect("exists");
        secrets
            .delete(&unused.id)
            .await
            .expect("deletes");
        assert!(
            check
                .still_current(Some(&versions))
                .await,
            "secrets the grant did not read never matter"
        );

        replace_secret(&secrets, "CC_SECRET", "rotated").await;
        assert!(
            !check
                .still_current(Some(&versions))
                .await
        );
        let rereading = ProviderSecrets::new(&secrets, &provider);
        for secret_ref in ["CC_ID", "CC_SECRET"] {
            rereading
                .resolve(secret_ref)
                .await
                .expect("resolves");
        }
        let current = rereading.versions_read();
        assert!(
            check
                .still_current(Some(&current))
                .await
        );
        let mut newer_than_stored = current.clone();
        newer_than_stored[1].updated_at += chrono::Duration::seconds(1);
        assert!(
            !check
                .still_current(Some(&newer_than_stored))
                .await,
            "a stored copy older than the recorded version, as after a restore, is not current"
        );

        let client_id = secrets
            .get_by_secret_id("CC_ID")
            .await
            .expect("read")
            .expect("exists");
        secrets
            .set_tenant_id(&client_id.id, Some("tenant-b".into()))
            .await
            .expect("moves");
        assert!(
            !check
                .still_current(Some(&current))
                .await
        );
        secrets
            .set_tenant_id(&client_id.id, Some("tenant-a".into()))
            .await
            .expect("moves back");
        assert!(
            !check
                .still_current(Some(&current))
                .await,
            "moving the secret back is a further change"
        );

        secrets
            .delete(&client_id.id)
            .await
            .expect("deletes");
        assert!(
            !check
                .still_current(Some(&current))
                .await
        );
    }

    struct UnreadableSecrets {
        inner: Arc<dyn SecretsStore>,
    }

    #[async_trait::async_trait]
    impl SecretsStore for UnreadableSecrets {
        async fn create(
            &self,
            request: CreateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .create(request)
                .await
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            self.inner.get(id).await
        }
        async fn get_by_secret_id(
            &self,
            _secret_id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            Err(anyhow::anyhow!("secret store unavailable"))
        }
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.inner.list_all().await
        }
        async fn update(
            &self,
            id: &str,
            request: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .update(id, request)
                .await
        }
        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.inner.delete(id).await
        }
        async fn find_by_tag(
            &self,
            tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.inner
                .find_by_tag(tag)
                .await
        }
    }

    #[tokio::test]
    async fn test_a_grant_is_not_current_while_the_secrets_it_read_cannot_be_read() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = secrets_with(&directory, &[("CC_ID", "id", None), ("CC_SECRET", "secret", None)]).await;
        let provider = provider(CredentialProviderType::OAuth2ClientCredentials, "https://auth.example/token");
        let granting = ProviderSecrets::new(&secrets, &provider);
        for secret_ref in ["CC_ID", "CC_SECRET"] {
            granting
                .resolve(secret_ref)
                .await
                .expect("resolves");
        }
        let versions = granting.versions_read();
        assert_eq!(versions.len(), 2);
        assert!(
            ProviderSecrets::new(&secrets, &provider)
                .still_current(Some(&versions))
                .await
        );

        let unreadable: Arc<dyn SecretsStore> = Arc::new(UnreadableSecrets { inner: secrets });
        assert!(
            !ProviderSecrets::new(&unreadable, &provider)
                .still_current(Some(&versions))
                .await
        );
    }
}
