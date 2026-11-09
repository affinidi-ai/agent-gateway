//! Service tokens: credentials the gateway obtains from a credential provider for itself,
//! not on a user's behalf. Delegation bindings and target authentication share this one
//! path. Static credentials are read from the secrets store on every use; tokens an
//! issuer returns are cached in the delegation vault until they expire.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use super::storage::{DelegationVaultStorage, access_token_fingerprint};
use super::{DelegationToken, OAuthTokenResponse, VaultLookupResult, oauth};
use crate::config::credential_policy::RuleMode;
use crate::credential_providers::{CredentialProvider, CredentialProviderType, storage::CredentialProviderStorage};
use crate::mcp::continuations::delegation::provider_digest;
use crate::secrets::SecretsStore;

pub struct ServiceTokenContext<'a> {
    pub secrets: &'a Arc<dyn SecretsStore>,
    pub providers: &'a dyn CredentialProviderStorage,
    pub vault: &'a dyn DelegationVaultStorage,
    /// How token requests reach the provider; [`oauth::TokenEgress::from_environment`] when `None`.
    pub egress: Option<&'a oauth::TokenEgress>,
}

/// Where an issued token is cached: the vault row of `agent_did` and a user identity
/// `<purpose>:<hash>`, where the hash covers the provider's settings, the sorted scopes
/// and the version of every secret the provider references, so a change to any of them
/// never reuses a token issued before it.
#[derive(Debug, Clone, Copy)]
pub struct ServiceTokenKey<'a> {
    pub agent_did: &'a str,
    pub purpose: &'a str,
}

pub struct ServiceToken {
    value: zeroize::Zeroizing<String>,
    /// The vault row of a token an issuer returned; `None` for a static credential read
    /// from the secrets store, which is never cached.
    pub issued: Option<IssuedToken>,
}

pub struct IssuedToken {
    pub id: String,
    pub freshness: Freshness,
    /// Whether the provider's token endpoint breaks the https rule and is let through only
    /// because the rule is in warn mode.
    pub insecure_endpoint: bool,
    /// The key whose lock guards this token's renewal.
    slot: GrantSlotKey,
    /// When the provider issued this token value. A renewal keeps the vault row and its id, so
    /// this, not the row's `created_at`, dates the value.
    issued_at: DateTime<Utc>,
    /// SHA-256 of the token value, so [`invalidate`] drops the row only while it still holds
    /// the token that was sent.
    fingerprint: [u8; 32],
}

/// How an issued token was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// From the vault cache.
    Cached,
    /// From a token request just now.
    Fresh,
    /// From the vault cache, due for renewal, after its renewal failed at the token endpoint
    /// or was held back by the retry backoff.
    Stale,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

impl ServiceToken {
    pub fn value(&self) -> &str {
        &self.value
    }

    fn issued(
        token: DelegationToken,
        freshness: Freshness,
        insecure_endpoint: bool,
    ) -> Self {
        Self {
            issued: Some(IssuedToken {
                fingerprint: access_token_fingerprint(&token.access_token),
                issued_at: token.consent_granted_at,
                slot: (token.agent_did, token.user_identity_hash, token.credential_provider_id),
                id: token.id,
                freshness,
                insecure_endpoint,
            }),
            value: zeroize::Zeroizing::new(token.access_token),
        }
    }
}

/// A token younger than this many seconds is never dropped after a Target refuses it. A
/// Target that refuses a token just issued refuses every token, and dropping each one would
/// send the provider a token request per call.
pub const MIN_INVALIDATION_AGE_SECS: i64 = 30;

/// What [`invalidate`] did with a refused token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalidation {
    /// The vault row held the refused token and was deleted.
    Dropped,
    /// The token is younger than [`MIN_INVALIDATION_AGE_SECS`] and was kept.
    TooRecent,
    /// The row is gone, holds another token, or is being renewed right now: nothing to drop.
    Replaced,
}

/// Forgets an issued token its Target refused, so the next request for its key asks the
/// provider for a new token. The vault row is deleted only while it still holds the token that
/// was sent, no renewal of it is running, and the token is at least
/// [`MIN_INVALIDATION_AGE_SECS`] old at `now`. The deletion is no revocation: pending consents
/// and open subscriptions are kept. The key's retry backoff is kept, so a failing token
/// endpoint is still held back. Nothing is retried here.
pub async fn invalidate(
    vault: &dyn DelegationVaultStorage,
    issued: &IssuedToken,
    now: DateTime<Utc>,
) -> Result<Invalidation, ServiceTokenError> {
    if now - issued.issued_at < chrono::Duration::seconds(MIN_INVALIDATION_AGE_SECS) {
        return Ok(Invalidation::TooRecent);
    }
    let Ok(_renewal) = grant_slot(&issued.slot.0, &issued.slot.1, &issued.slot.2).try_lock_owned() else {
        return Ok(Invalidation::Replaced);
    };
    let dropped = vault
        .delete_token_holding(&issued.id, &issued.fingerprint)
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?;
    Ok(if dropped {
        Invalidation::Dropped
    } else {
        Invalidation::Replaced
    })
}

/// Whether a Target's answer refuses the token it was sent as invalid: a 401 with a Bearer
/// challenge in a `WWW-Authenticate` header whose `error` is `invalid_token` (RFC 6750
/// section 3.1), quoted or not. A 401 without it, or a 403, says nothing about the token.
pub fn refuses_token_as_invalid<'a>(
    status: u16,
    challenges: impl IntoIterator<Item = &'a str>,
) -> bool {
    status == 401
        && challenges
            .into_iter()
            .any(|header| bearer_error(header).as_deref() == Some("invalid_token"))
}

/// The `error` auth-param of the Bearer challenge in one `WWW-Authenticate` value, which may
/// hold several challenges (RFC 9110 section 11.6.1).
fn bearer_error(header: &str) -> Option<String> {
    let mut in_bearer = false;
    for element in split_outside_quotes(header) {
        let element = element.trim();
        let (first, rest) = element
            .split_once(|c: char| c.is_ascii_whitespace())
            .map_or((element, ""), |(first, rest)| (first, rest.trim_start()));
        let param = if first.contains('=') || rest.starts_with('=') {
            Some(element)
        } else if first.is_empty() {
            None
        } else {
            in_bearer = first.eq_ignore_ascii_case("bearer");
            (!rest.is_empty()).then_some(rest)
        };
        let Some((name, value)) = param.and_then(|param| param.split_once('=')) else {
            continue;
        };
        if in_bearer
            && name
                .trim()
                .eq_ignore_ascii_case("error")
        {
            return Some(unquote(value.trim()));
        }
    }
    None
}

/// `value` split at each comma outside a quoted string.
fn split_outside_quotes(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// A token, or a quoted string with its quotes and backslash escapes removed.
fn unquote(value: &str) -> String {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return value.to_string();
    };
    let mut unquoted = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if escaped || c != '\\' {
            unquoted.push(c);
            escaped = false;
        } else {
            escaped = true;
        }
    }
    unquoted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServiceTokenError {
    #[error("credential provider type issues no service token")]
    Unsupported,
    #[error("credential provider secret unavailable")]
    SecretUnavailable,
    #[error("credential provider token request failed")]
    TokenRequestFailed,
    /// The token endpoint answered with an OAuth error, whose `error` code this keeps.
    #[error("credential provider token request rejected: {0}")]
    TokenRequestRejected(oauth::OAuthErrorCode),
    #[error("credential provider token endpoint refused by egress policy")]
    TokenEndpointRefused,
    #[error("credential provider token endpoint is not https")]
    TokenEndpointNotHttps,
    #[error("credential provider issued other scopes than requested")]
    ScopeMismatch,
    #[error("credential provider changed during the token request")]
    ProviderChanged,
    #[error("credential store unavailable")]
    StoreUnavailable,
    #[error("credential provider token request failed")]
    ProviderMisconfigured,
}

impl ServiceTokenError {
    /// Whether the token endpoint's answer caused it, so the next request for the same key
    /// waits for the retry backoff and a cached token due for renewal is served stale. Local
    /// failures (a missing secret, an unusable signing key or provider setting, a refused
    /// endpoint, a store error) never do either.
    fn backs_off(self) -> bool {
        matches!(self, Self::TokenRequestFailed | Self::TokenRequestRejected(_) | Self::ScopeMismatch)
    }

    /// The token endpoint's OAuth `error` code, when it answered with one.
    pub fn oauth_error(&self) -> Option<oauth::OAuthErrorCode> {
        match self {
            Self::TokenRequestRejected(code) => Some(*code),
            _ => None,
        }
    }
}

/// A cached token is not injected within this many seconds of its expiry, so it does not
/// reach the target just as the issuer stops accepting it.
pub const EXPIRY_MARGIN_SECS: i64 = 60;

/// A cached token is renewed half its lifetime before it expires, but at most this many
/// seconds and at least [`EXPIRY_MARGIN_SECS`] before.
const RENEWAL_MARGIN_MAX_SECS: i64 = 300;

/// The provider's service token for `scopes`: its API key, or a cached token that grants
/// them, or a new token from the provider's grant, stored under `key`. On this replica one
/// token request per key is in flight at a time; a caller that missed the cache waits for it
/// and reads the vault again before requesting. After a failed request the next one for the
/// key waits for the retry backoff, and a caller arriving before then fails without a request.
/// A cached token due for renewal is renewed by one caller while the others keep using it;
/// when the renewal fails at the token endpoint or is held back by the backoff, the cached
/// token is served as stale until [`EXPIRY_MARGIN_SECS`] before it expires. Issued scopes must
/// equal requested ones; when none were requested the issuer's scopes are kept.
pub async fn acquire(
    provider: &CredentialProvider,
    scopes: &[String],
    context: &ServiceTokenContext<'_>,
    key: ServiceTokenKey<'_>,
    now: DateTime<Utc>,
) -> Result<ServiceToken, ServiceTokenError> {
    let arrived = Utc::now();
    let elapsed = || now + (Utc::now() - arrived);
    let egress = context
        .egress
        .cloned()
        .unwrap_or_else(oauth::TokenEgress::from_environment);
    if provider.provider_type == CredentialProviderType::OAuth2AuthorizationCode {
        return Err(ServiceTokenError::Unsupported);
    }
    if provider.provider_type == CredentialProviderType::ApiKey {
        let value = oauth::resolve_api_key(provider, context.secrets, egress.policy.tenant_credential_isolation)
            .await
            .map_err(|error| {
                warn!(target: "credential_delegation", provider_id = %provider.provider_id, %error, "API key resolution failed");
                ServiceTokenError::SecretUnavailable
            })?;
        if value.is_empty() {
            return Err(ServiceTokenError::SecretUnavailable);
        }
        return Ok(ServiceToken {
            value: zeroize::Zeroizing::new(value),
            issued: None,
        });
    }
    let endpoint = provider
        .token_endpoint
        .as_deref();
    if endpoint.is_some_and(|endpoint| !egress.admits_token_endpoint(endpoint)) {
        warn!(target: "credential_delegation", provider_id = %provider.provider_id, "Refusing a credential provider token endpoint that is not https");
        return Err(ServiceTokenError::TokenEndpointNotHttps);
    }
    let insecure_endpoint = egress.insecure_endpoint(endpoint);
    let identity = cache_identity(
        provider,
        scopes,
        context.secrets,
        key.purpose,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await?;
    let served = |token, freshness| {
        if insecure_endpoint {
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, "Using a service token from a credential provider token endpoint that is not https");
        }
        ServiceToken::issued(token, freshness, insecure_endpoint)
    };
    let mut backoff = match cached_token(provider, scopes, context, key.agent_did, &identity, now).await? {
        CachedToken::Fresh(token) => return Ok(served(token, Freshness::Cached)),
        CachedToken::RenewalDue(token) => match grant_slot(key.agent_did, &identity, &provider.id).try_lock_owned() {
            Ok(backoff) => backoff,
            Err(_) => return Ok(served(token, Freshness::Cached)),
        },
        CachedToken::None => {
            grant_slot(key.agent_did, &identity, &provider.id)
                .lock_owned()
                .await
        }
    };
    let locked_at = elapsed();
    let renewing = match cached_token(provider, scopes, context, key.agent_did, &identity, locked_at).await? {
        CachedToken::Fresh(token) => return Ok(served(token, Freshness::Cached)),
        CachedToken::RenewalDue(token) if backoff.holds_back(locked_at) => {
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, token_id = %token.id, "Service token renewal held back by the retry backoff, serving the cached token as stale");
            return Ok(served(token, Freshness::Stale));
        }
        CachedToken::RenewalDue(token) => Some(token),
        CachedToken::None if backoff.holds_back(locked_at) => {
            debug!(target: "credential_delegation", provider_id = %provider.provider_id, "Service token request held back by the retry backoff");
            return Err(ServiceTokenError::TokenRequestFailed);
        }
        CachedToken::None => None,
    };
    let outcome = token_grant(provider, scopes, context.secrets, &egress).await;
    let finished_at = elapsed();
    let (response, granted) = match backoff.record(outcome, finished_at) {
        Ok(granted) => granted,
        Err(error) => {
            return match renewing {
                Some(token) if error.backs_off() && usable_at(&token, finished_at) => {
                    warn!(target: "credential_delegation", provider_id = %provider.provider_id, token_id = %token.id, %error, "Service token renewal failed, serving the cached token as stale");
                    Ok(served(token, Freshness::Stale))
                }
                _ => Err(error),
            };
        }
    };
    let current = context
        .providers
        .get(&provider.id)
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?
        .ok_or(ServiceTokenError::ProviderChanged)?;
    if provider_digest(&current).map_err(|_| ServiceTokenError::ProviderChanged)?
        != provider_digest(provider).map_err(|_| ServiceTokenError::ProviderChanged)?
    {
        return Err(ServiceTokenError::ProviderChanged);
    }
    let created = Utc::now();
    let expires_at = response
        .expires_in
        .and_then(|seconds| created.checked_add_signed(chrono::Duration::seconds(seconds)))
        .ok_or_else(|| {
            // The token request already refuses a response without a bounded expires_in.
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, "Service token expiry out of range");
            ServiceTokenError::TokenRequestFailed
        })?;
    let token = context
        .vault
        .store_replacing_expired(
            DelegationToken {
                id: uuid::Uuid::new_v4().to_string(),
                agent_did: key.agent_did.into(),
                user_identity_hash: identity,
                credential_provider_id: provider.id.clone(),
                provider_id: provider.provider_id.clone(),
                access_token: response.access_token,
                refresh_token: None,
                token_type: response.token_type,
                scopes: granted,
                expires_at: Some(expires_at),
                delegation_vc: None,
                consent_identity: None,
                consent_granted_at: created,
                last_used_at: Some(created),
                created_at: created,
                updated_at: created,
            },
            key.purpose,
        )
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?;
    Ok(ServiceToken::issued(token, Freshness::Fresh, insecure_endpoint))
}

/// Requests a token with the provider's grant, checking the issued scopes against `scopes`.
async fn token_grant(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    egress: &oauth::TokenEgress,
) -> Result<(OAuthTokenResponse, Vec<String>), ServiceTokenError> {
    let response = match provider.provider_type {
        CredentialProviderType::OAuth2ClientCredentials => {
            oauth::fetch_scoped_client_credentials_token(provider, scopes, secrets, egress).await
        }
        CredentialProviderType::OAuth2JwtBearer => {
            oauth::fetch_jwt_bearer_token(provider, scopes, secrets, egress).await
        }
        CredentialProviderType::OAuth2ClientCredentialsJwtAuth => {
            oauth::fetch_client_credentials_jwt_auth_token(provider, scopes, secrets, egress).await
        }
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::ApiKey => {
            return Err(ServiceTokenError::Unsupported);
        }
    }
    .map_err(|error| {
        warn!(target: "credential_delegation", provider_id = %provider.provider_id, error = %format!("{error:#}"), "Service token request failed");
        if error
            .downcast_ref::<oauth::TokenEndpointRefused>()
            .is_some()
        {
            ServiceTokenError::TokenEndpointRefused
        } else if error
            .downcast_ref::<oauth::ProviderMisconfigured>()
            .is_some()
        {
            ServiceTokenError::ProviderMisconfigured
        } else if let Some(rejected) = error.downcast_ref::<oauth::TokenRequestRejected>() {
            ServiceTokenError::TokenRequestRejected(rejected.code)
        } else if let Some(error) = error.downcast_ref::<oauth::ProviderSecretError>() {
            match error {
                oauth::ProviderSecretError::NotFound | oauth::ProviderSecretError::OutsideTenant => {
                    ServiceTokenError::SecretUnavailable
                }
                oauth::ProviderSecretError::Store => ServiceTokenError::StoreUnavailable,
            }
        } else {
            ServiceTokenError::TokenRequestFailed
        }
    })?;
    let granted = response
        .scope
        .as_deref()
        .map(|scope| {
            scope
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| scopes.to_vec());
    if (!scopes.is_empty()
        && granted
            .iter()
            .any(|scope| !scopes.contains(scope)))
        || scopes
            .iter()
            .any(|scope| !granted.contains(scope))
    {
        oauth::record_token_request(provider, oauth::TokenRequestOutcome::InvalidResponse);
        return Err(ServiceTokenError::ScopeMismatch);
    }
    oauth::record_token_request(provider, oauth::TokenRequestOutcome::Success);
    Ok((response, granted))
}

const GRANT_SLOT_ENTRIES: usize = 16_384;
const BACKOFF_MEMORY_SECS: i64 = 10 * 60;

const BACKOFF_INITIAL_SECS: i64 = 1;
const BACKOFF_MAX_SECS: i64 = 60;

type GrantSlotKey = (String, String, String);
type GrantSlot = Arc<tokio::sync::Mutex<Backoff>>;
type GrantSlots = dashmap::DashMap<GrantSlotKey, GrantSlot>;

/// One lock per vault row key on this replica, held while its token is requested and
/// stored, so concurrent misses send one token request and the others then read its token
/// from the vault. It guards the key's retry backoff and holds no token values. A slot is
/// kept while any caller holds it or its backoff remembers a failure; once
/// [`GRANT_SLOT_ENTRIES`] slots exist, a new key first releases the others.
static GRANT_SLOTS: std::sync::LazyLock<GrantSlots> = std::sync::LazyLock::new(GrantSlots::new);

fn grant_slot(
    agent_did: &str,
    identity: &str,
    credential_provider_id: &str,
) -> GrantSlot {
    slot_for(&GRANT_SLOTS, GRANT_SLOT_ENTRIES, (agent_did.into(), identity.into(), credential_provider_id.into()))
}

/// The slot of `key` in `slots`, added when missing; once `capacity` slots exist, adding one
/// first releases the idle ones.
fn slot_for(
    slots: &GrantSlots,
    capacity: usize,
    key: GrantSlotKey,
) -> GrantSlot {
    if let Some(slot) = slots.get(&key) {
        return slot.clone();
    }
    if slots.len() >= capacity {
        release_idle_slots(slots, Utc::now());
    }
    slots
        .entry(key)
        .or_default()
        .clone()
}

/// Removes the slots no caller holds whose backoff remembers no failure at `now`. A slot is
/// copied only under its map shard's lock, which `retain` holds, so a slot with no other
/// copy cannot gain one meanwhile.
fn release_idle_slots(
    slots: &GrantSlots,
    now: DateTime<Utc>,
) {
    slots.retain(|_, slot| {
        Arc::strong_count(slot) > 1
            || slot
                .try_lock()
                .map_or(true, |backoff| backoff.remembers(now))
    });
}

/// The token requests to one key that failed in a row, and the time before which the next
/// one is not sent: 1 s after the first failed request ends, doubling up to 60 s. A success
/// clears it, and the failures are forgotten [`BACKOFF_MEMORY_SECS`] after the retry time.
#[derive(Debug, Default)]
struct Backoff {
    failures: u32,
    retry_at: Option<DateTime<Utc>>,
}

impl Backoff {
    fn holds_back(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.retry_at
            .is_some_and(|retry_at| now < retry_at)
    }

    fn remembers(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.retry_at
            .is_some_and(|retry_at| now < retry_at + chrono::Duration::seconds(BACKOFF_MEMORY_SECS))
    }

    fn record<T>(
        &mut self,
        outcome: Result<T, ServiceTokenError>,
        now: DateTime<Utc>,
    ) -> Result<T, ServiceTokenError> {
        match &outcome {
            Ok(_) => *self = Self::default(),
            Err(error) if error.backs_off() => {
                if !self.remembers(now) {
                    self.failures = 0;
                }
                self.failures = self
                    .failures
                    .saturating_add(1);
                self.retry_at = Some(now + backoff_delay(self.failures));
            }
            Err(_) => {}
        }
        outcome
    }
}

fn backoff_delay(failures: u32) -> chrono::Duration {
    let factor = 2_i64
        .checked_pow(failures.saturating_sub(1))
        .unwrap_or(i64::MAX);
    chrono::Duration::seconds(
        BACKOFF_INITIAL_SECS
            .saturating_mul(factor)
            .min(BACKOFF_MAX_SECS),
    )
}

/// The vault user identity of the provider's token for `scopes`: `<purpose>:` and the hex
/// SHA-256 of the provider digest, the sorted scopes and the id, tenant and `updated_at` of
/// each secret its type uses ([`CredentialProvider::service_token_secret_refs`]). Only those
/// secrets are read, one lookup each per request (and decrypted when encryption at rest is
/// on); the store is never listed.
/// A missing secret, or one outside the provider's tenant while `isolation` is enforced, is
/// refused here, so a cached token stops being served at once. Under `warn` the grant itself
/// logs the out-of-tenant secret, once per token request.
async fn cache_identity(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    purpose: &str,
    isolation: RuleMode,
) -> Result<String, ServiceTokenError> {
    let mut versions = Vec::new();
    for secret_ref in provider.service_token_secret_refs() {
        let secret = secrets
            .get_by_secret_id(secret_ref)
            .await
            .map_err(|_| ServiceTokenError::StoreUnavailable)?
            .ok_or_else(|| {
                warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Credential provider secret not found");
                ServiceTokenError::SecretUnavailable
            })?;
        if isolation.is_enforced() && provider.secret_is_outside_tenant(secret.tenant_id.as_deref()) {
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Refusing a credential provider secret outside the provider's tenant");
            return Err(ServiceTokenError::SecretUnavailable);
        }
        versions.push(serde_json::json!([secret_ref, secret.id, secret.tenant_id, secret.updated_at]));
    }
    let mut scopes = scopes.to_vec();
    scopes.sort_unstable();
    scopes.dedup();
    let digest = provider_digest(provider).map_err(|_| ServiceTokenError::ProviderChanged)?;
    let material = serde_json::json!({"provider": hex::encode(digest), "scopes": scopes, "secrets": versions});
    let hash = <sha2::Sha256 as sha2::Digest>::digest(
        material
            .to_string()
            .as_bytes(),
    );
    Ok(format!("{purpose}:{}", hex::encode(hash)))
}

/// The cached token for a key, by where `now` falls in its lifetime.
enum CachedToken {
    Fresh(DelegationToken),
    /// Past its renewal time and more than [`EXPIRY_MARGIN_SECS`] before it expires.
    RenewalDue(DelegationToken),
    None,
}

async fn cached_token(
    provider: &CredentialProvider,
    scopes: &[String],
    context: &ServiceTokenContext<'_>,
    agent_did: &str,
    identity: &str,
    now: DateTime<Utc>,
) -> Result<CachedToken, ServiceTokenError> {
    let token = match context
        .vault
        .lookup(agent_did, identity, &provider.id)
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?
    {
        VaultLookupResult::Found(token) => token,
        VaultLookupResult::ExpiredRefreshable(token) | VaultLookupResult::ExpiredNoRefresh(token) => {
            debug!(target: "credential_delegation", token_id = %token.id, "Cached service token expired, requesting a new one");
            return Ok(CachedToken::None);
        }
        VaultLookupResult::NotFound => return Ok(CachedToken::None),
    };
    let matches = token.agent_did == agent_did
        && token.user_identity_hash == identity
        && token.credential_provider_id == provider.id
        && !token.access_token.is_empty()
        && token
            .token_type
            .eq_ignore_ascii_case("Bearer")
        && scopes
            .iter()
            .all(|scope| token.scopes.contains(scope));
    Ok(match token.expires_at {
        Some(expires) if matches && usable_at(&token, now) => {
            if now < expires - renewal_margin(expires - token.created_at) {
                CachedToken::Fresh(token)
            } else {
                CachedToken::RenewalDue(token)
            }
        }
        _ => CachedToken::None,
    })
}

/// Whether `token` may still be injected at `now`: more than [`EXPIRY_MARGIN_SECS`] before
/// it expires.
fn usable_at(
    token: &DelegationToken,
    now: DateTime<Utc>,
) -> bool {
    token
        .expires_at
        .is_some_and(|expires| expires - chrono::Duration::seconds(EXPIRY_MARGIN_SECS) > now)
}

/// How long before expiry a token of `lifetime` is renewed: half its lifetime, from
/// [`EXPIRY_MARGIN_SECS`] up to [`RENEWAL_MARGIN_MAX_SECS`].
fn renewal_margin(lifetime: chrono::Duration) -> chrono::Duration {
    chrono::Duration::seconds((lifetime.num_seconds() / 2).clamp(EXPIRY_MARGIN_SECS, RENEWAL_MARGIN_MAX_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_providers::storage::FileSystemCredentialProviderStore;
    use crate::delegation_vault::jwt_assertion::test_keys;
    use crate::delegation_vault::storage::FileSystemDelegationVaultStore;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    /// The fixture's secrets store, recording its lookups by secret id and counting its
    /// listings, able to fail either or to answer a lookup with no secret after
    /// `lookups_before_missing` more lookups.
    struct ObservedSecrets {
        inner: crate::secrets::FilesystemSecretsStore,
        lookups: Mutex<Vec<String>>,
        listing_calls: AtomicUsize,
        listing_fails: AtomicBool,
        lookup_fails: AtomicBool,
        lookups_before_missing: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SecretsStore for ObservedSecrets {
        async fn create(
            &self,
            request: crate::secrets::CreateSecretRequest,
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
            anyhow::ensure!(
                !self
                    .lookup_fails
                    .load(Ordering::SeqCst),
                "secrets store unavailable"
            );
            self.lookups
                .lock()
                .unwrap()
                .push(secret_id.to_string());
            if self
                .lookups_before_missing
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                .is_err()
            {
                return Ok(None);
            }
            self.inner
                .get_by_secret_id(secret_id)
                .await
        }
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.listing_calls
                .fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(
                !self
                    .listing_fails
                    .load(Ordering::SeqCst),
                "secrets store unavailable"
            );
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
        async fn set_tenant_id(
            &self,
            id: &str,
            tenant_id: Option<String>,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .set_tenant_id(id, tenant_id)
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

    #[derive(Default)]
    struct Endpoint {
        response: Mutex<Value>,
        failing: AtomicBool,
        delay_millis: AtomicU64,
        forms: Mutex<Vec<HashMap<String, String>>>,
    }

    struct Fixture {
        secrets: Arc<dyn SecretsStore>,
        observed: Arc<ObservedSecrets>,
        providers: FileSystemCredentialProviderStore,
        vault: FileSystemDelegationVaultStore,
        token_endpoint: String,
        egress: oauth::TokenEgress,
        endpoint: Arc<Endpoint>,
        _server: tokio::task::JoinSet<()>,
        _directory: tempfile::TempDir,
    }

    const KEY: ServiceTokenKey<'static> = ServiceTokenKey {
        agent_did: "surface:surface-1",
        purpose: "__target_auth__",
    };

    impl Fixture {
        async fn new() -> Self {
            let endpoint = Arc::new(Endpoint {
                response: Mutex::new(json!({"access_token": "issued", "token_type": "Bearer", "expires_in": 3600})),
                ..Default::default()
            });
            let app = axum::Router::new()
                .fallback(axum::routing::post(
                    |axum::extract::State(endpoint): axum::extract::State<Arc<Endpoint>>,
                     axum::Form(form): axum::Form<HashMap<String, String>>| async move {
                        endpoint
                            .forms
                            .lock()
                            .unwrap()
                            .push(form);
                        tokio::time::sleep(std::time::Duration::from_millis(
                            endpoint
                                .delay_millis
                                .load(Ordering::SeqCst),
                        ))
                        .await;
                        let status = if endpoint
                            .failing
                            .load(Ordering::SeqCst)
                        {
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR
                        } else {
                            axum::http::StatusCode::OK
                        };
                        (
                            status,
                            axum::Json(
                                endpoint
                                    .response
                                    .lock()
                                    .unwrap()
                                    .clone(),
                            ),
                        )
                    },
                ))
                .with_state(endpoint.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
            let mut server = tokio::task::JoinSet::new();
            server.spawn(async move {
                axum::serve(listener, app)
                    .await
                    .unwrap();
            });
            let directory = tempfile::tempdir().unwrap();
            let observed = Arc::new(ObservedSecrets {
                inner: crate::secrets::FilesystemSecretsStore::new(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
                lookups: Mutex::new(Vec::new()),
                listing_calls: AtomicUsize::new(0),
                listing_fails: AtomicBool::new(false),
                lookup_fails: AtomicBool::new(false),
                lookups_before_missing: AtomicUsize::new(usize::MAX),
            });
            let secrets: Arc<dyn SecretsStore> = observed.clone();
            for (secret_id, value) in [
                ("CLIENT_ID", "client-123".to_string()),
                ("CLIENT_SECRET", "client-secret".to_string()),
                ("API_KEY", "static-key".to_string()),
                ("SIGNING_KEY", test_keys::rsa_pkcs8().private_pem),
                ("CERTIFICATE", test_keys::certificate_pem()),
            ] {
                secrets
                    .create(crate::secrets::CreateSecretRequest {
                        tenant_id: None,
                        name: secret_id.into(),
                        secret_id: secret_id.into(),
                        description: None,
                        value,
                        secret_type: "General".into(),
                        tags: vec![],
                    })
                    .await
                    .unwrap();
            }
            Self {
                secrets,
                observed,
                providers: FileSystemCredentialProviderStore::new(
                    directory
                        .path()
                        .join("providers"),
                )
                .await
                .unwrap(),
                vault: FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                    .await
                    .unwrap(),
                egress: oauth::TokenEgress {
                    timeout: std::time::Duration::from_secs(5),
                    exact_allowlist: Some(token_endpoint.clone()),
                    policy: Default::default(),
                },
                token_endpoint,
                endpoint,
                _server: server,
                _directory: directory,
            }
        }

        async fn provider(
            &self,
            settings: Value,
        ) -> CredentialProvider {
            let mut value = json!({
                "id": "provider", "name": "Provider", "provider_id": "provider",
                "token_endpoint": self.token_endpoint,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            });
            value
                .as_object_mut()
                .unwrap()
                .extend(
                    settings
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            self.providers
                .create(serde_json::from_value(value).unwrap())
                .await
                .unwrap()
        }

        async fn acquire(
            &self,
            provider: &CredentialProvider,
            scopes: &[&str],
            now: DateTime<Utc>,
        ) -> Result<ServiceToken, ServiceTokenError> {
            let scopes: Vec<String> = scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect();
            let context = ServiceTokenContext {
                secrets: &self.secrets,
                providers: &self.providers,
                vault: &self.vault,
                egress: Some(&self.egress),
            };
            acquire(provider, &scopes, &context, KEY, now).await
        }

        async fn stored(&self) -> Vec<DelegationToken> {
            self.vault
                .list_all()
                .await
                .unwrap()
        }

        async fn only_stored(&self) -> DelegationToken {
            let mut stored = self.stored().await;
            assert_eq!(stored.len(), 1, "expected one stored token");
            stored.remove(0)
        }

        async fn secret_id(
            &self,
            secret_ref: &str,
        ) -> String {
            self.secrets
                .list_all()
                .await
                .unwrap()
                .into_iter()
                .find(|secret| secret.secret_id == secret_ref)
                .unwrap()
                .id
        }

        async fn rotate(
            &self,
            secret_ref: &str,
            value: &str,
        ) {
            let id = self
                .secret_id(secret_ref)
                .await;
            self.secrets
                .update(
                    &id,
                    crate::secrets::UpdateSecretRequest {
                        name: None,
                        description: None,
                        value: Some(value.into()),
                        update_value: Some(true),
                        secret_type: None,
                        tags: None,
                    },
                )
                .await
                .unwrap();
        }

        async fn grant_slot(
            &self,
            provider: &CredentialProvider,
            scopes: &[&str],
        ) -> (String, GrantSlot) {
            let scopes: Vec<String> = scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect();
            let identity = cache_identity(
                provider,
                &scopes,
                &self.secrets,
                KEY.purpose,
                self.egress
                    .policy
                    .tenant_credential_isolation,
            )
            .await
            .unwrap();
            let slot = grant_slot(KEY.agent_did, &identity, &provider.id);
            (identity, slot)
        }

        /// The time before which the key's next token request is held back; the backoff
        /// starts when the failed request ends, so it includes the request's own duration.
        async fn retry_at(
            &self,
            provider: &CredentialProvider,
            scopes: &[&str],
        ) -> DateTime<Utc> {
            let (_, slot) = self
                .grant_slot(provider, scopes)
                .await;
            slot.lock()
                .await
                .retry_at
                .expect("a failed token request starts the backoff")
        }

        /// Sends a token request at `at` that fails, checks the backoff it starts lasts
        /// `delay_secs` from the end of that request, that a request just before the retry time
        /// is held back without reaching the endpoint, and returns just after the retry time.
        async fn failed_request_then_backoff(
            &self,
            provider: &CredentialProvider,
            at: DateTime<Utc>,
            delay_secs: i64,
            requests: usize,
        ) -> DateTime<Utc> {
            assert_eq!(
                self.acquire(provider, &["read"], at)
                    .await
                    .err(),
                Some(ServiceTokenError::TokenRequestFailed),
                "{delay_secs} s"
            );
            assert_eq!(self.requests().len(), requests, "{delay_secs} s");
            let retry_at = self
                .retry_at(provider, &["read"])
                .await;
            assert!(
                retry_at >= seconds(at, delay_secs) && retry_at < seconds(at, delay_secs + 3),
                "{delay_secs} s: {retry_at}"
            );
            assert_eq!(
                self.acquire(provider, &["read"], after(retry_at, -100))
                    .await
                    .err(),
                Some(ServiceTokenError::TokenRequestFailed),
                "{delay_secs} s"
            );
            assert_eq!(self.requests().len(), requests, "{delay_secs} s: held back before the retry time");
            after(retry_at, 100)
        }

        fn lookups(&self) -> Vec<String> {
            self.observed
                .lookups
                .lock()
                .unwrap()
                .clone()
        }

        fn listings(&self) -> usize {
            self.observed
                .listing_calls
                .load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<HashMap<String, String>> {
            self.endpoint
                .forms
                .lock()
                .unwrap()
                .clone()
        }

        fn fail(
            &self,
            failing: bool,
        ) {
            self.endpoint
                .failing
                .store(failing, Ordering::SeqCst);
        }

        fn respond(
            &self,
            response: Value,
        ) {
            *self
                .endpoint
                .response
                .lock()
                .unwrap() = response;
        }
    }

    fn issued(token: Result<ServiceToken, ServiceTokenError>) -> (String, Freshness) {
        let token = token.unwrap_or_else(|error| panic!("expected an issued token, got {error}"));
        let freshness = token
            .issued
            .as_ref()
            .expect("expected an issued token")
            .freshness;
        (token.value().to_string(), freshness)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_grant_fetches_once_and_then_reuses_the_cached_token() {
        for (settings, grant_type) in [
            (
                json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                       "client_secret_secret_ref": "CLIENT_SECRET"}),
                "client_credentials",
            ),
            (
                json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY"}),
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ),
            (
                json!({"provider_type": "oauth2_client_credentials_jwt_auth", "client_id_secret_ref": "CLIENT_ID",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY", "jwt_certificate_secret_ref": "CERTIFICATE"}),
                "client_credentials",
            ),
        ] {
            let fixture = Fixture::new().await;
            let provider = fixture
                .provider(settings)
                .await;
            let now = Utc::now();
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &["read"], now)
                        .await
                ),
                ("issued".into(), Freshness::Fresh)
            );
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &["read"], now)
                        .await
                ),
                ("issued".into(), Freshness::Cached)
            );
            let requests = fixture.requests();
            assert_eq!(requests.len(), 1, "{grant_type}");
            assert_eq!(requests[0]["grant_type"], grant_type);
            assert!(!requests[0].contains_key("resource"), "{grant_type}");
            let stored = fixture.only_stored().await;
            assert_eq!(stored.agent_did, KEY.agent_did);
            assert!(
                stored
                    .user_identity_hash
                    .strip_prefix("__target_auth__:")
                    .is_some_and(|hash| hash.len() == 64),
                "{}",
                stored.user_identity_hash
            );
            assert_eq!(stored.scopes, vec!["read"]);
            assert!(stored.expires_at.is_some());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_api_key_is_read_on_every_use_and_never_cached() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "api_key", "api_key_secret_ref": "API_KEY"}))
            .await;
        for _ in 0..2 {
            let token = fixture
                .acquire(&provider, &[], Utc::now())
                .await
                .unwrap();
            assert!(token.issued.is_none());
            assert_eq!(token.value(), "static-key");
        }
        assert_eq!(fixture.lookups(), ["API_KEY", "API_KEY"]);
        assert_eq!(fixture.listings(), 0);
        assert!(fixture.requests().is_empty());
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Acquires a token for `client_credentials()` with no scopes and returns the time the
    /// token's lifetime is counted from.
    async fn cache_a_token(
        fixture: &Fixture,
        provider: &CredentialProvider,
    ) -> DateTime<Utc> {
        issued(
            fixture
                .acquire(provider, &[], Utc::now())
                .await,
        );
        fixture
            .only_stored()
            .await
            .created_at
    }

    fn seconds(
        from: DateTime<Utc>,
        seconds: i64,
    ) -> DateTime<Utc> {
        from + chrono::Duration::seconds(seconds)
    }

    #[test]
    fn a_token_is_renewed_half_its_lifetime_early_between_one_and_five_minutes() {
        for (lifetime, margin) in [(3600, 300), (600, 300), (400, 200), (120, 60), (100, 60), (10, 60)] {
            assert_eq!(
                renewal_margin(chrono::Duration::seconds(lifetime)),
                chrono::Duration::seconds(margin),
                "{lifetime}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cached_token_is_renewed_five_minutes_before_it_expires() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], seconds(created, 3299))
                    .await
            ),
            ("issued".into(), Freshness::Cached)
        );
        fixture.respond(json!({"access_token": "renewed", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], seconds(created, 3300))
                    .await
            ),
            ("renewed".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    #[test]
    fn a_401_bearer_challenge_with_invalid_token_refuses_the_token() {
        for challenge in [
            r#"Bearer error="invalid_token""#,
            "Bearer error=invalid_token",
            r#"Bearer realm="api", error="invalid_token", error_description="The token expired""#,
            r#"bearer ERROR = "invalid_token""#,
            r#"Basic realm="a, b", Bearer error="invalid_token""#,
            r#"Bearer realm="api, error=\"x\"", error="invalid_token""#,
            r#"Bearer error="invalid_\token""#,
        ] {
            assert!(refuses_token_as_invalid(401, [challenge]), "{challenge}");
        }
        assert!(refuses_token_as_invalid(401, ["Basic realm=\"a\"", "Bearer error=\"invalid_token\""]));
    }

    #[test]
    fn any_other_answer_says_nothing_about_the_token() {
        for challenge in [
            r#"Bearer error="insufficient_scope""#,
            r#"Bearer realm="api""#,
            "Bearer",
            r#"Basic error="invalid_token""#,
            r#"Bearer error_description="error=\"invalid_token\"""#,
            r#"Bearer realm="error=invalid_token""#,
            r#"Bearer error="invalid_token_extra""#,
            r#"DPoP error="invalid_token", Bearer realm="api""#,
            "",
        ] {
            assert!(!refuses_token_as_invalid(401, [challenge]), "{challenge}");
        }
        assert!(!refuses_token_as_invalid(401, std::iter::empty::<&str>()));
        for status in [200, 400, 403, 407, 500] {
            assert!(!refuses_token_as_invalid(status, [r#"Bearer error="invalid_token""#]), "{status}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_token_is_dropped_only_once_it_is_old_enough() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let mut token = fixture
            .acquire(&provider, &[], Utc::now())
            .await
            .unwrap();
        let refused = token.issued.take().unwrap();
        let issued_at = fixture
            .only_stored()
            .await
            .consent_granted_at;
        let staged = stage_a_consent(&fixture.vault).await;
        let epoch = fixture
            .vault
            .access_revision()
            .await
            .unwrap();

        assert_eq!(
            invalidate(&fixture.vault, &refused, seconds(issued_at, MIN_INVALIDATION_AGE_SECS - 1))
                .await
                .unwrap(),
            Invalidation::TooRecent
        );
        assert_eq!(fixture.stored().await.len(), 1, "a token issued less than 30 seconds ago is kept");

        assert_eq!(
            invalidate(&fixture.vault, &refused, seconds(issued_at, MIN_INVALIDATION_AGE_SECS))
                .await
                .unwrap(),
            Invalidation::Dropped
        );
        assert!(
            fixture
                .stored()
                .await
                .is_empty(),
            "the refused token's vault row is deleted"
        );
        assert_eq!(
            fixture
                .vault
                .access_revision()
                .await
                .unwrap(),
            epoch,
            "the revocation epoch, which open subscriptions watch, is unchanged"
        );
        assert!(
            fixture
                .vault
                .staged_consent(staged, [7; 32], Utc::now().timestamp() as u64)
                .await
                .unwrap()
                .is_some(),
            "a staged consent survives the drop"
        );
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], Utc::now())
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    /// Stages a consent for another identity, returning its id; it is read back with the
    /// binding digest `[7; 32]`.
    async fn stage_a_consent(vault: &FileSystemDelegationVaultStore) -> uuid::Uuid {
        let now = Utc::now().timestamp() as u64;
        let mut credential = crate::delegation_vault::tests::make_token(Some(3600), false);
        credential.agent_did = "did:example:user-agent".into();
        let id = uuid::Uuid::new_v4();
        vault
            .stage_consent(
                crate::delegation_vault::storage::StagedConsent {
                    id: id.to_string(),
                    binding_digest: [7; 32],
                    issued_at: now,
                    expires_at: now + 300,
                    snapshot: vault
                        .consent_snapshot(
                            &credential.agent_did,
                            &credential.user_identity_hash,
                            &credential.credential_provider_id,
                        )
                        .await
                        .unwrap(),
                    credential,
                },
                now,
            )
            .await
            .unwrap();
        id
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_token_is_kept_while_its_renewal_holds_the_key() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        let mut sent = fixture
            .acquire(&provider, &[], seconds(created, 60))
            .await
            .unwrap();
        let sent = sent.issued.take().unwrap();
        let (_, slot) = fixture
            .grant_slot(&provider, &[])
            .await;

        let renewing = slot.lock().await;
        assert_eq!(
            invalidate(&fixture.vault, &sent, seconds(created, 120))
                .await
                .unwrap(),
            Invalidation::Replaced
        );
        assert_eq!(fixture.only_stored().await.id, sent.id, "the row under renewal is kept");

        drop(renewing);
        assert_eq!(
            invalidate(&fixture.vault, &sent, seconds(created, 120))
                .await
                .unwrap(),
            Invalidation::Dropped
        );
        assert!(
            fixture
                .stored()
                .await
                .is_empty()
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_of_a_token_already_replaced_does_nothing() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        let mut sent = fixture
            .acquire(&provider, &[], seconds(created, 60))
            .await
            .unwrap();
        let sent = sent.issued.take().unwrap();

        fixture.respond(json!({"access_token": "renewed", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], seconds(created, 3300))
                    .await
            ),
            ("renewed".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.only_stored().await.id, sent.id, "a renewal keeps the vault row");
        assert_eq!(
            invalidate(&fixture.vault, &sent, seconds(created, 3400))
                .await
                .unwrap(),
            Invalidation::Replaced
        );
        assert_eq!(
            fixture
                .only_stored()
                .await
                .access_token,
            "renewed",
            "a late refusal of the old token leaves the renewed one"
        );

        fixture
            .vault
            .delete(&sent.id)
            .await
            .unwrap();
        assert_eq!(
            invalidate(&fixture.vault, &sent, seconds(created, 3400))
                .await
                .unwrap(),
            Invalidation::Replaced,
            "a row that is gone is not dropped again"
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_refused_token_keeps_the_retry_backoff_of_its_key() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        fixture.fail(true);
        let renew_at = seconds(created, 3300);
        let mut stale = fixture
            .acquire(&provider, &[], renew_at)
            .await
            .unwrap();
        let stale = stale.issued.take().unwrap();
        assert_eq!(stale.freshness, Freshness::Stale);
        assert_eq!(fixture.requests().len(), 2);

        assert_eq!(
            invalidate(&fixture.vault, &stale, after(renew_at, 100))
                .await
                .unwrap(),
            Invalidation::Dropped
        );
        fixture.fail(false);
        assert_eq!(
            fixture
                .acquire(&provider, &[], after(renew_at, 500))
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed),
            "the failed renewal's backoff still holds the next request back"
        );
        assert_eq!(fixture.requests().len(), 2);
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], after(renew_at, 5_000))
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_renewal_serves_the_cached_token_as_stale() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        let cached = fixture.only_stored().await;
        fixture.fail(true);
        let renew_at = seconds(created, 3300);
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], renew_at)
                    .await
            ),
            ("issued".into(), Freshness::Stale)
        );
        assert_eq!(fixture.requests().len(), 2);
        let stored = fixture.only_stored().await;
        assert_eq!(
            (stored.id, stored.expires_at, stored.updated_at),
            (cached.id.clone(), cached.expires_at, cached.updated_at)
        );
        let retry_at = fixture
            .retry_at(&provider, &[])
            .await;
        assert!(retry_at >= after(renew_at, 1_000) && retry_at < after(renew_at, 4_000), "{retry_at}");

        for held_back in [after(renew_at, 500), after(retry_at, -100)] {
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &[], held_back)
                        .await
                ),
                ("issued".into(), Freshness::Stale),
                "a renewal held back by the backoff serves the token as stale"
            );
        }
        assert_eq!(fixture.requests().len(), 2);

        fixture.fail(false);
        fixture.respond(json!({"access_token": "renewed", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], after(retry_at, 100))
                    .await
            ),
            ("renewed".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_renewal_in_flight_serves_the_cached_token_to_other_callers() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        let (_, slot) = fixture
            .grant_slot(&provider, &[])
            .await;
        let renewing = slot.lock().await;
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], seconds(created, 3300))
                    .await
            ),
            ("issued".into(), Freshness::Cached)
        );
        drop(renewing);
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn never_stale_within_sixty_seconds_of_expiry() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let created = cache_a_token(&fixture, &provider).await;
        fixture.fail(true);
        assert_eq!(
            fixture
                .acquire(&provider, &[], seconds(created, 3540))
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert_eq!(
            fixture
                .acquire(&provider, &[], seconds(created, 3545))
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert_eq!(fixture.requests().len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_living_two_minutes_or_less_is_never_stale() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture.respond(json!({"access_token": "short", "token_type": "Bearer", "expires_in": 100}));
        let created = cache_a_token(&fixture, &provider).await;
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], seconds(created, 39))
                    .await
            ),
            ("short".into(), Freshness::Cached)
        );
        fixture.fail(true);
        assert_eq!(
            fixture
                .acquire(&provider, &[], seconds(created, 40))
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_change_secret_or_policy_error_never_serves_a_stale_token() {
        for expected in [
            ServiceTokenError::ProviderChanged,
            ServiceTokenError::SecretUnavailable,
            ServiceTokenError::TokenEndpointRefused,
        ] {
            let mut fixture = Fixture::new().await;
            let provider = fixture
                .provider(client_credentials())
                .await;
            let created = cache_a_token(&fixture, &provider).await;
            let mut requests = 1;
            match expected {
                ServiceTokenError::ProviderChanged => {
                    let mut edited = provider.clone();
                    edited.default_scopes = vec!["other".into()];
                    fixture
                        .providers
                        .update(edited)
                        .await
                        .unwrap();
                    requests = 2;
                }
                ServiceTokenError::SecretUnavailable => fixture
                    .observed
                    .lookups_before_missing
                    .store(2, Ordering::SeqCst),
                _ => fixture.egress.exact_allowlist = None,
            }
            assert_eq!(
                fixture
                    .acquire(&provider, &[], seconds(created, 3300))
                    .await
                    .err(),
                Some(expected)
            );
            assert_eq!(fixture.requests().len(), requests, "{expected}");
            assert_eq!(
                fixture
                    .only_stored()
                    .await
                    .access_token,
                "issued"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_response_without_expires_in_is_refused_and_not_cached() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                             "jwt_signing_key_secret_ref": "SIGNING_KEY"}))
            .await;
        fixture.respond(json!({"access_token": "forever", "token_type": "Bearer"}));
        assert_eq!(
            fixture
                .acquire(&provider, &[], Utc::now())
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn issued_scopes_must_match_a_request_and_are_kept_when_none_were_requested() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                             "client_secret_secret_ref": "CLIENT_SECRET"}))
            .await;
        fixture.respond(
            json!({"access_token": "wide", "token_type": "Bearer", "expires_in": 3600, "scope": "read write"}),
        );
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], Utc::now())
                .await
                .err(),
            Some(ServiceTokenError::ScopeMismatch)
        );
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], Utc::now())
                    .await
            ),
            ("wide".into(), Freshness::Fresh)
        );
        let stored = fixture.only_stored().await;
        assert_eq!(stored.scopes, vec!["read", "write"]);
        assert!(!requests_have_scope(&fixture.requests()[1]));
    }

    fn requests_have_scope(form: &HashMap<String, String>) -> bool {
        form.contains_key("scope")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_endpoint_on_an_unlisted_loopback_address_is_refused_without_a_request() {
        let mut fixture = Fixture::new().await;
        fixture.egress.exact_allowlist = None;
        let loopback = fixture.token_endpoint.clone();
        for (settings, endpoint) in [
            (
                json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                       "client_secret_secret_ref": "CLIENT_SECRET"}),
                loopback.clone(),
            ),
            (
                json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY"}),
                loopback.replace("127.0.0.1", "localhost"),
            ),
            (
                json!({"provider_type": "oauth2_client_credentials_jwt_auth", "client_id_secret_ref": "CLIENT_ID",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY"}),
                loopback.clone(),
            ),
        ] {
            let mut provider = fixture
                .provider(settings)
                .await;
            provider.token_endpoint = Some(endpoint.clone());
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], Utc::now())
                    .await
                    .err(),
                Some(ServiceTokenError::TokenEndpointRefused),
                "{endpoint}"
            );
            fixture
                .providers
                .delete(&provider.id)
                .await
                .unwrap();
        }
        assert!(fixture.requests().is_empty());
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            ServiceTokenError::TokenEndpointRefused.to_string(),
            "credential provider token endpoint refused by egress policy"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_http_token_endpoint_is_refused_before_any_secret_is_read_when_enforced() {
        let mut fixture = Fixture::new().await;
        fixture.egress.exact_allowlist = None;
        for settings in [
            json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "UNSTORED_ID",
                   "client_secret_secret_ref": "UNSTORED_SECRET"}),
            json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                   "jwt_signing_key_secret_ref": "UNSTORED_KEY"}),
            json!({"provider_type": "oauth2_client_credentials_jwt_auth", "client_id_secret_ref": "UNSTORED_ID",
                   "jwt_signing_key_secret_ref": "UNSTORED_KEY"}),
        ] {
            let mut provider = fixture
                .provider(settings)
                .await;
            provider.token_endpoint = Some("http://idp.example/token".into());
            fixture
                .egress
                .policy
                .to_mut()
                .token_endpoint_https = RuleMode::Enforce;
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], Utc::now())
                    .await
                    .err(),
                Some(ServiceTokenError::TokenEndpointNotHttps),
                "{:?}",
                provider.provider_type
            );
            // Warn mode lets it through to the secret lookup, which fails on the unstored reference.
            fixture
                .egress
                .policy
                .to_mut()
                .token_endpoint_https = RuleMode::Warn;
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], Utc::now())
                    .await
                    .err(),
                Some(ServiceTokenError::SecretUnavailable),
                "{:?}",
                provider.provider_type
            );
            fixture
                .providers
                .delete(&provider.id)
                .await
                .unwrap();
        }
        assert!(fixture.requests().is_empty());
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stored_http_token_endpoint_keeps_its_token_in_warn_mode_and_loses_it_when_enforced() {
        let mut fixture = Fixture::new().await;
        fixture
            .egress
            .policy
            .to_mut()
            .token_endpoint_https = RuleMode::Enforce;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                             "client_secret_secret_ref": "CLIENT_SECRET"}))
            .await;
        let flags = |token: ServiceToken| {
            let issued = token
                .issued
                .expect("expected an issued token");
            (issued.freshness, issued.insecure_endpoint)
        };
        let now = Utc::now();
        let listed = fixture
            .acquire(&provider, &[], now)
            .await
            .unwrap();
        assert_eq!(flags(listed), (Freshness::Fresh, false), "an exactly listed http endpoint meets the rule");

        fixture.egress.exact_allowlist = None;
        fixture
            .egress
            .policy
            .to_mut()
            .token_endpoint_https = RuleMode::Warn;
        let grandfathered = fixture
            .acquire(&provider, &[], now)
            .await
            .unwrap();
        assert_eq!(grandfathered.value(), "issued");
        assert_eq!(flags(grandfathered), (Freshness::Cached, true));

        fixture
            .egress
            .policy
            .to_mut()
            .token_endpoint_https = RuleMode::Enforce;
        assert_eq!(
            fixture
                .acquire(&provider, &[], now)
                .await
                .err(),
            Some(ServiceTokenError::TokenEndpointNotHttps)
        );
        assert_eq!(fixture.requests().len(), 1);
        assert_eq!(
            ServiceTokenError::TokenEndpointNotHttps.to_string(),
            "credential provider token endpoint is not https"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tenant_providers_appliance_wide_secrets_are_refused_when_enforced_and_used_in_warn_mode() {
        let mut fixture = Fixture::new().await;
        let tenant = json!({"tenant_id": "tenant-a"});
        let mut settings = vec![
            json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                   "client_secret_secret_ref": "CLIENT_SECRET"}),
            json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                   "jwt_signing_key_secret_ref": "SIGNING_KEY"}),
            json!({"provider_type": "oauth2_client_credentials_jwt_auth", "client_id_secret_ref": "CLIENT_ID",
                   "jwt_signing_key_secret_ref": "SIGNING_KEY"}),
            json!({"provider_type": "api_key", "api_key_secret_ref": "API_KEY"}),
        ];
        for setting in &mut settings {
            setting
                .as_object_mut()
                .unwrap()
                .extend(
                    tenant
                        .as_object()
                        .unwrap()
                        .clone(),
                );
        }
        fixture
            .egress
            .policy
            .to_mut()
            .tenant_credential_isolation = RuleMode::Enforce;
        for setting in &settings {
            let provider = fixture
                .provider(setting.clone())
                .await;
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], Utc::now())
                    .await
                    .err(),
                Some(ServiceTokenError::SecretUnavailable),
                "{:?}",
                provider.provider_type
            );
            fixture
                .providers
                .delete(&provider.id)
                .await
                .unwrap();
        }
        assert!(fixture.requests().is_empty());
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        fixture
            .egress
            .policy
            .to_mut()
            .tenant_credential_isolation = RuleMode::Warn;
        let provider = fixture
            .provider(settings[0].clone())
            .await;
        let token = fixture
            .acquire(&provider, &["read"], Utc::now())
            .await
            .unwrap();
        assert_eq!(token.value(), "issued");
        assert_eq!(fixture.requests().len(), 1);
        fixture
            .providers
            .delete(&provider.id)
            .await
            .unwrap();
        let api_key = fixture
            .provider(settings[3].clone())
            .await;
        assert_eq!(
            fixture
                .acquire(&api_key, &[], Utc::now())
                .await
                .unwrap()
                .value(),
            "static-key"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_authorization_code_provider_has_no_service_token() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_authorization_code", "client_id_secret_ref": "CLIENT_ID",
                             "client_secret_secret_ref": "CLIENT_SECRET"}))
            .await;
        assert_eq!(
            fixture
                .acquire(&provider, &[], Utc::now())
                .await
                .err(),
            Some(ServiceTokenError::Unsupported)
        );
        assert!(fixture.requests().is_empty());
    }

    fn client_credentials() -> Value {
        json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
               "client_secret_secret_ref": "CLIENT_SECRET"})
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_grant_looks_up_each_secret_by_id_and_never_lists_the_store() {
        for (settings, secret_refs) in [
            (client_credentials(), vec!["CLIENT_ID", "CLIENT_SECRET"]),
            (
                json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY", "jwt_certificate_secret_ref": "CERTIFICATE"}),
                vec!["SIGNING_KEY", "CERTIFICATE"],
            ),
            (
                json!({"provider_type": "oauth2_client_credentials_jwt_auth", "client_id_secret_ref": "CLIENT_ID",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY", "jwt_certificate_secret_ref": "CERTIFICATE"}),
                vec!["CLIENT_ID", "SIGNING_KEY", "CERTIFICATE"],
            ),
            (
                json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY", "jwt_certificate_secret_ref": "CERTIFICATE",
                       "client_authentication": "client_secret_basic", "client_id_secret_ref": "CLIENT_ID",
                       "client_secret_secret_ref": "CLIENT_SECRET"}),
                vec!["CLIENT_ID", "CLIENT_SECRET", "SIGNING_KEY", "CERTIFICATE"],
            ),
            (
                json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                       "jwt_signing_key_secret_ref": "SIGNING_KEY", "jwt_certificate_secret_ref": "CERTIFICATE",
                       "client_authentication": "none", "client_id_secret_ref": "CLIENT_ID",
                       "client_secret_secret_ref": "CLIENT_SECRET"}),
                vec!["CLIENT_ID", "SIGNING_KEY", "CERTIFICATE"],
            ),
        ] {
            let fixture = Fixture::new().await;
            let provider = fixture
                .provider(settings)
                .await;
            let now = Utc::now();
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &["read"], now)
                        .await
                ),
                ("issued".into(), Freshness::Fresh)
            );
            assert_eq!(fixture.listings(), 0, "the secrets store is never listed");
            assert_eq!(fixture.lookups(), [secret_refs.clone(), secret_refs.clone()].concat());
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &["read"], now)
                        .await
                ),
                ("issued".into(), Freshness::Cached)
            );
            assert_eq!(fixture.listings(), 0, "the secrets store is never listed");
            assert_eq!(fixture.lookups(), [secret_refs.clone(), secret_refs.clone(), secret_refs].concat());
            assert_eq!(fixture.requests().len(), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reference_the_provider_type_does_not_use_is_neither_read_nor_part_of_the_key() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                             "client_secret_secret_ref": "CLIENT_SECRET", "api_key_secret_ref": "API_KEY",
                             "jwt_signing_key_secret_ref": "SIGNING_KEY"}))
            .await;
        let now = Utc::now();
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        let key = fixture
            .only_stored()
            .await
            .user_identity_hash;
        fixture
            .rotate("API_KEY", "rotated-key")
            .await;
        let api_key = fixture
            .secret_id("API_KEY")
            .await;
        fixture
            .secrets
            .delete(&api_key)
            .await
            .unwrap();
        fixture
            .rotate("SIGNING_KEY", "rotated-signing-key")
            .await;
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Cached)
        );
        assert_eq!(fixture.requests().len(), 1);
        assert!(
            fixture
                .lookups()
                .iter()
                .all(|secret_ref| secret_ref == "CLIENT_ID" || secret_ref == "CLIENT_SECRET"),
            "{:?}",
            fixture.lookups()
        );
        fixture
            .rotate("CLIENT_ID", "rotated-client")
            .await;
        fixture.respond(json!({"access_token": "after-rotation", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-rotation".into(), Freshness::Fresh)
        );
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["client_id"], "rotated-client");
        let mut keys: Vec<String> = fixture
            .stored()
            .await
            .into_iter()
            .map(|token| token.user_identity_hash)
            .collect();
        keys.retain(|stored| *stored != key);
        assert_eq!(keys.len(), 1, "the used secret's rotation keys a new token");
    }

    fn jwt_bearer_with_client(client_authentication: Option<&str>) -> Value {
        json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example", "jwt_subject": "svc@example",
               "jwt_signing_key_secret_ref": "SIGNING_KEY", "client_authentication": client_authentication,
               "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"})
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotating_the_client_secret_of_a_jwt_bearer_provider_requests_a_new_token() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(jwt_bearer_with_client(Some("client_secret_post")))
            .await;
        let now = Utc::now();
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Cached)
        );
        fixture
            .rotate("CLIENT_SECRET", "rotated-secret")
            .await;
        fixture.respond(json!({"access_token": "after-rotation", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-rotation".into(), Freshness::Fresh)
        );
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["client_secret"], "rotated-secret");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_references_of_a_jwt_bearer_provider_without_a_client_authentication_are_not_read_or_keyed() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(jwt_bearer_with_client(None))
            .await;
        let now = Utc::now();
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        fixture
            .rotate("CLIENT_ID", "rotated-client")
            .await;
        fixture
            .rotate("CLIENT_SECRET", "rotated-secret")
            .await;
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Cached)
        );
        assert_eq!(fixture.requests().len(), 1);
        assert!(
            fixture
                .lookups()
                .iter()
                .all(|secret_ref| secret_ref == "SIGNING_KEY"),
            "{:?}",
            fixture.lookups()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_client_authentication_of_a_jwt_bearer_provider_is_part_of_its_token_key() {
        let fixture = Fixture::new().await;
        let mut keys = Vec::new();
        for method in [None, Some("none"), Some("client_secret_basic"), Some("client_secret_post")] {
            let mut value = json!({
                "id": "provider", "name": "Provider", "provider_id": "provider",
                "token_endpoint": fixture.token_endpoint,
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            });
            value
                .as_object_mut()
                .unwrap()
                .extend(
                    jwt_bearer_with_client(method)
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            let provider: CredentialProvider = serde_json::from_value(value).unwrap();
            keys.push(
                cache_identity(&provider, &["read".to_string()], &fixture.secrets, "__target_auth__", RuleMode::Warn)
                    .await
                    .unwrap(),
            );
        }
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 4, "each client authentication keys its own token");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotating_a_referenced_secret_requests_a_new_token() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &["read"], now)
                .await,
        );
        fixture
            .rotate("CLIENT_SECRET", "rotated-secret")
            .await;
        fixture.respond(json!({"access_token": "after-rotation", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-rotation".into(), Freshness::Fresh)
        );
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["client_secret"], "rotated-secret");
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-rotation".into(), Freshness::Cached)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn moving_a_secret_to_another_tenant_or_editing_the_provider_requests_a_new_token() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &["read"], now)
                .await,
        );
        let client_id = fixture
            .secret_id("CLIENT_ID")
            .await;
        fixture
            .secrets
            .set_tenant_id(&client_id, Some("tenant-a".into()))
            .await
            .unwrap();
        fixture.respond(json!({"access_token": "after-move", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-move".into(), Freshness::Fresh),
            "a moved secret is used in warn mode, under a new key"
        );
        fixture
            .secrets
            .set_tenant_id(&client_id, None)
            .await
            .unwrap();
        fixture.respond(json!({"access_token": "after-move-back", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-move-back".into(), Freshness::Fresh)
        );

        let mut edited = provider.clone();
        edited.default_scopes = vec!["other".into()];
        let edited = fixture
            .providers
            .update(edited)
            .await
            .unwrap();
        fixture.respond(json!({"access_token": "after-edit", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&edited, &["read"], now)
                    .await
            ),
            ("after-edit".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 4);
        let mut identities: Vec<String> = fixture
            .stored()
            .await
            .into_iter()
            .map(|token| token.user_identity_hash)
            .collect();
        identities.sort();
        identities.dedup();
        assert_eq!(identities.len(), 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_scope_order_does_not_change_the_key_but_other_scopes_do() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        fixture.respond(json!({"access_token": "both", "token_type": "Bearer", "expires_in": 3600}));
        issued(
            fixture
                .acquire(&provider, &["read", "write"], now)
                .await,
        );
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["write", "read", "write"], now)
                    .await
            ),
            ("both".into(), Freshness::Cached)
        );
        fixture.respond(json!({"access_token": "admin", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["admin"], now)
                    .await
            ),
            ("admin".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_secret_stops_a_cached_token_without_a_request() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &["read"], now)
                .await,
        );
        let client_secret = fixture
            .secret_id("CLIENT_SECRET")
            .await;
        fixture
            .secrets
            .delete(&client_secret)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], now)
                .await
                .err(),
            Some(ServiceTokenError::SecretUnavailable)
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_secrets_store_error_never_serves_the_cached_token() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &["read"], now)
                .await,
        );
        fixture
            .observed
            .lookup_fails
            .store(true, Ordering::SeqCst);
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], now)
                .await
                .err(),
            Some(ServiceTokenError::StoreUnavailable)
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cache_hit_reads_only_the_referenced_secrets_and_never_lists_the_store() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &["read"], now)
                .await,
        );
        fixture
            .observed
            .lookups
            .lock()
            .unwrap()
            .clear();
        fixture
            .observed
            .listing_calls
            .store(0, Ordering::SeqCst);
        fixture
            .observed
            .listing_fails
            .store(true, Ordering::SeqCst);
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Cached)
        );
        assert_eq!(
            fixture
                .observed
                .listing_calls
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            *fixture
                .observed
                .lookups
                .lock()
                .unwrap(),
            vec!["CLIENT_ID".to_string(), "CLIENT_SECRET".to_string()]
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_enforced_tenant_rule_stops_a_cached_token_at_once() {
        let mut fixture = Fixture::new().await;
        let mut settings = client_credentials();
        settings["tenant_id"] = json!("tenant-a");
        let provider = fixture
            .provider(settings)
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &["read"], now)
                .await,
        );
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Cached),
            "warn mode keeps serving the cached token"
        );
        fixture
            .egress
            .policy
            .to_mut()
            .tenant_credential_isolation = RuleMode::Enforce;
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], now)
                .await
                .err(),
            Some(ServiceTokenError::SecretUnavailable)
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_new_token_removes_expired_tokens_of_the_same_purpose_only() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let expired_at = Utc::now() - chrono::Duration::seconds(10);
        let row = |id: &str, agent_did: &str, user_identity_hash: &str, expires_at: DateTime<Utc>| DelegationToken {
            id: id.into(),
            agent_did: agent_did.into(),
            user_identity_hash: user_identity_hash.into(),
            credential_provider_id: provider.id.clone(),
            provider_id: provider.provider_id.clone(),
            access_token: "old".into(),
            refresh_token: None,
            token_type: "Bearer".into(),
            scopes: vec![],
            expires_at: Some(expires_at),
            delegation_vc: None,
            consent_identity: None,
            consent_granted_at: expires_at,
            last_used_at: None,
            created_at: expires_at,
            updated_at: expires_at,
        };
        for token in [
            row("expired-earlier-settings", KEY.agent_did, "__target_auth__:earlier", expired_at),
            row("expired-earlier-release", KEY.agent_did, "__target_auth__", expired_at),
            row("live-other-scopes", KEY.agent_did, "__target_auth__:other", Utc::now() + chrono::Duration::hours(1)),
            row("expired-other-purpose", KEY.agent_did, "__mcp_client_credentials__:earlier", expired_at),
            row("expired-other-surface", "surface:surface-2", "__target_auth__:earlier", expired_at),
        ] {
            fixture
                .vault
                .store(token)
                .await
                .unwrap();
        }
        let issued_token = fixture
            .acquire(&provider, &["read"], Utc::now())
            .await
            .unwrap();
        let issued_id = issued_token
            .issued
            .expect("expected an issued token")
            .id;
        let mut left: Vec<String> = fixture
            .stored()
            .await
            .into_iter()
            .map(|token| token.id)
            .filter(|id| *id != issued_id)
            .collect();
        left.sort();
        assert_eq!(left, ["expired-other-purpose", "expired-other-surface", "live-other-scopes"]);
    }

    /// Waits until `waiters` callers besides the `holders` counted before they started hold
    /// `slot`, that is, have missed the cache and are queued for its lock. The slot map holds
    /// one copy, counted in `holders`.
    async fn until_waiting(
        slot: &GrantSlot,
        holders: usize,
        waiters: usize,
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while Arc::strong_count(slot) < holders + waiters {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("callers did not queue for the grant slot");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sixteen_concurrent_misses_send_one_token_request() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        let (_, slot) = fixture
            .grant_slot(&provider, &["read"])
            .await;
        let held = slot.lock().await;
        let holders = Arc::strong_count(&slot);
        let (results, ()) = tokio::join!(
            futures::future::join_all((0..16).map(|_| fixture.acquire(&provider, &["read"], now))),
            async {
                until_waiting(&slot, holders, 16).await;
                drop(held);
            }
        );
        let results: Vec<(String, Freshness)> = results
            .into_iter()
            .map(issued)
            .collect();
        assert!(
            results
                .iter()
                .all(|(value, _)| value == "issued")
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, freshness)| *freshness == Freshness::Cached)
                .count(),
            15
        );
        assert_eq!(fixture.requests().len(), 1);
        fixture.only_stored().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_slot_held_by_a_token_request_is_not_reclaimed_so_a_later_miss_waits_for_it() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        fixture
            .endpoint
            .delay_millis
            .store(300, Ordering::SeqCst);
        let (first, second) = tokio::join!(fixture.acquire(&provider, &["read"], now), async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while fixture.requests().is_empty() {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the first token request was not sent");
            release_idle_slots(&GRANT_SLOTS, Utc::now());
            fixture
                .acquire(&provider, &["read"], now)
                .await
        });
        assert_eq!(issued(first), ("issued".into(), Freshness::Fresh));
        assert_eq!(issued(second), ("issued".into(), Freshness::Cached));
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_stored_elsewhere_while_waiting_is_reused_without_a_request() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        let (identity, slot) = fixture
            .grant_slot(&provider, &["read"])
            .await;
        let held = slot.lock().await;
        let holders = Arc::strong_count(&slot);
        let (token, ()) = tokio::join!(fixture.acquire(&provider, &["read"], now), async {
            until_waiting(&slot, holders, 1).await;
            fixture
                .vault
                .store(DelegationToken {
                    id: "other-replica".into(),
                    agent_did: KEY.agent_did.into(),
                    user_identity_hash: identity.clone(),
                    credential_provider_id: provider.id.clone(),
                    provider_id: provider.provider_id.clone(),
                    access_token: "from-other-replica".into(),
                    refresh_token: None,
                    token_type: "Bearer".into(),
                    scopes: vec!["read".into()],
                    expires_at: Some(now + chrono::Duration::hours(1)),
                    delegation_vc: None,
                    consent_identity: None,
                    consent_granted_at: now,
                    last_used_at: None,
                    created_at: now,
                    updated_at: now,
                })
                .await
                .unwrap();
            drop(held);
        });
        assert_eq!(issued(token), ("from-other-replica".into(), Freshness::Cached));
        assert!(fixture.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_for_other_scopes_does_not_wait_for_another_key() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        let (_, slot) = fixture
            .grant_slot(&provider, &["read"])
            .await;
        let held = slot.lock().await;
        fixture.respond(json!({"access_token": "write", "token_type": "Bearer", "expires_in": 3600}));
        let other =
            tokio::time::timeout(std::time::Duration::from_secs(5), fixture.acquire(&provider, &["write"], now))
                .await
                .expect("a request for other scopes waited for another key's request");
        assert_eq!(issued(other), ("write".into(), Freshness::Fresh));
        drop(held);
        fixture.respond(json!({"access_token": "read", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("read".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    fn after(
        now: DateTime<Utc>,
        millis: i64,
    ) -> DateTime<Utc> {
        now + chrono::Duration::milliseconds(millis)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_grant_holds_back_the_next_request_until_the_backoff_passes() {
        for (failure, error) in [
            (None, ServiceTokenError::TokenRequestFailed),
            (
                Some(
                    json!({"access_token": "wide", "token_type": "Bearer", "expires_in": 3600, "scope": "read write"}),
                ),
                ServiceTokenError::ScopeMismatch,
            ),
        ] {
            let fixture = Fixture::new().await;
            let provider = fixture
                .provider(client_credentials())
                .await;
            match failure {
                Some(response) => fixture.respond(response),
                None => fixture.fail(true),
            }
            let now = Utc::now();
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
                    .err(),
                Some(error)
            );
            let retry_at = fixture
                .retry_at(&provider, &["read"])
                .await;
            assert!(retry_at >= after(now, 1_000) && retry_at < after(now, 4_000), "{error}: {retry_at}");
            for held_back in [after(now, 500), after(retry_at, -100)] {
                assert_eq!(
                    fixture
                        .acquire(&provider, &["read"], held_back)
                        .await
                        .err(),
                    Some(ServiceTokenError::TokenRequestFailed),
                    "{error}"
                );
            }
            assert_eq!(fixture.requests().len(), 1, "{error}");
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], after(retry_at, 100))
                    .await
                    .err(),
                Some(error)
            );
            assert_eq!(fixture.requests().len(), 2, "{error}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_request_slower_than_the_configured_timeout_fails_and_starts_the_backoff() {
        let mut fixture = Fixture::new().await;
        fixture.egress.timeout = std::time::Duration::from_secs(1);
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture
            .endpoint
            .delay_millis
            .store(2_500, Ordering::SeqCst);
        let now = Utc::now();
        let started = std::time::Instant::now();
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], now)
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(2_400));
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], after(now, 500))
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_backoff_doubles_after_each_failure_and_a_success_clears_it() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture.fail(true);
        let mut at = Utc::now();
        let mut requests = 0;
        for delay_secs in [1, 2, 4, 8] {
            requests += 1;
            at = fixture
                .failed_request_then_backoff(&provider, at, delay_secs, requests)
                .await;
        }
        fixture.fail(false);
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], at)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        requests += 1;
        assert_eq!(fixture.requests().len(), requests);

        fixture.fail(true);
        requests += 1;
        let released = fixture
            .failed_request_then_backoff(&provider, seconds(at, 3_600), 1, requests)
            .await;
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], released)
                .await
                .err(),
            Some(ServiceTokenError::TokenRequestFailed)
        );
        assert_eq!(fixture.requests().len(), requests + 1, "a success clears the backoff, so the first delay applies");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_backoff_starts_when_a_slow_failed_request_ends() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture.fail(true);
        fixture
            .endpoint
            .delay_millis
            .store(2_000, Ordering::SeqCst);
        let (first, queued) = tokio::join!(fixture.acquire(&provider, &["read"], Utc::now()), async {
            tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
            fixture
                .acquire(&provider, &["read"], Utc::now())
                .await
        });
        assert_eq!(first.err(), Some(ServiceTokenError::TokenRequestFailed));
        assert_eq!(queued.err(), Some(ServiceTokenError::TokenRequestFailed));
        assert_eq!(fixture.requests().len(), 1);
    }

    #[test]
    fn the_backoff_delay_doubles_from_one_second_and_stops_at_sixty() {
        let delays: Vec<i64> = [1, 2, 3, 4, 5, 6, 7, 8, 64, u32::MAX]
            .into_iter()
            .map(|failures| backoff_delay(failures).num_seconds())
            .collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]);

        let now = Utc::now();
        let mut backoff = Backoff::default();
        for _ in 0..10 {
            assert!(
                backoff
                    .record::<()>(Err(ServiceTokenError::TokenRequestFailed), now)
                    .is_err()
            );
        }
        assert!(backoff.holds_back(after(now, 59_900)));
        assert!(!backoff.holds_back(after(now, 60_000)));
        assert_eq!(backoff.record(Ok(()), now), Ok(()));
        assert!(!backoff.holds_back(now));
        assert_eq!(backoff.failures, 0);
    }

    #[test]
    fn local_errors_never_start_a_backoff() {
        let now = Utc::now();
        for error in [
            ServiceTokenError::Unsupported,
            ServiceTokenError::SecretUnavailable,
            ServiceTokenError::TokenEndpointRefused,
            ServiceTokenError::TokenEndpointNotHttps,
            ServiceTokenError::ProviderChanged,
            ServiceTokenError::StoreUnavailable,
            ServiceTokenError::ProviderMisconfigured,
        ] {
            let mut backoff = Backoff::default();
            assert_eq!(backoff.record::<()>(Err(error), now), Err(error));
            assert!(!backoff.holds_back(now), "{error}");
            assert_eq!(backoff.failures, 0, "{error}");
        }
    }

    #[test]
    fn a_failure_run_is_forgotten_ten_minutes_after_its_retry_time() {
        let failed = Err::<(), _>(ServiceTokenError::TokenRequestFailed);
        let start = Utc::now();
        let mut backoff = Backoff::default();
        assert!(!backoff.remembers(start));
        let _ = backoff.record(failed, start);
        let _ = backoff.record(failed, seconds(start, 2));
        assert_eq!((backoff.failures, backoff.retry_at), (2, Some(seconds(start, 4))));
        assert!(backoff.remembers(seconds(start, 4 + 599)));
        assert!(!backoff.remembers(seconds(start, 4 + 600)));

        let mut remembered = Backoff {
            failures: 2,
            retry_at: Some(seconds(start, 4)),
        };
        let _ = remembered.record(failed, seconds(start, 4 + 599));
        assert_eq!((remembered.failures, remembered.retry_at), (3, Some(seconds(start, 4 + 599 + 4))));

        let _ = backoff.record(failed, seconds(start, 4 + 600));
        assert_eq!((backoff.failures, backoff.retry_at), (1, Some(seconds(start, 4 + 600 + 1))));
    }

    fn slot_key(name: &str) -> GrantSlotKey {
        (format!("surface:{name}"), "identity".into(), "provider".into())
    }

    fn insert_slot(
        slots: &GrantSlots,
        name: &str,
        backoff: Backoff,
    ) -> GrantSlot {
        let slot = Arc::new(tokio::sync::Mutex::new(backoff));
        slots.insert(slot_key(name), slot.clone());
        slot
    }

    fn slot_names(slots: &GrantSlots) -> Vec<String> {
        let mut names: Vec<String> = slots
            .iter()
            .map(|entry| {
                entry
                    .key()
                    .0
                    .trim_start_matches("surface:")
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn releasing_idle_slots_keeps_held_slots_and_remembered_failures() {
        let now = Utc::now();
        let slots = GrantSlots::new();
        let held = insert_slot(&slots, "held", Backoff::default());
        let locked = insert_slot(&slots, "locked", Backoff::default())
            .try_lock_owned()
            .unwrap();
        let remembered = Backoff {
            failures: 1,
            retry_at: Some(seconds(now, -599)),
        };
        drop(insert_slot(&slots, "remembered", remembered));
        drop(insert_slot(&slots, "idle", Backoff::default()));
        let forgotten = Backoff {
            failures: 3,
            retry_at: Some(seconds(now, -600)),
        };
        drop(insert_slot(&slots, "forgotten", forgotten));
        release_idle_slots(&slots, now);
        assert_eq!(slot_names(&slots), ["held", "locked", "remembered"]);
        assert!(Arc::ptr_eq(&slot_for(&slots, 16, slot_key("held")), &held));
        drop((held, locked));
        release_idle_slots(&slots, now);
        assert_eq!(slot_names(&slots), ["remembered"]);
    }

    #[test]
    fn a_new_key_releases_idle_slots_once_the_map_is_full() {
        let slots = GrantSlots::new();
        let held = insert_slot(&slots, "held", Backoff::default());
        drop(insert_slot(&slots, "idle", Backoff::default()));
        let second = slot_for(&slots, 3, slot_key("second"));
        assert_eq!(slot_names(&slots), ["held", "idle", "second"]);
        let third = slot_for(&slots, 3, slot_key("third"));
        assert_eq!(slot_names(&slots), ["held", "second", "third"]);
        assert!(Arc::ptr_eq(&slot_for(&slots, 3, slot_key("held")), &held));
        assert!(Arc::ptr_eq(&slot_for(&slots, 3, slot_key("second")), &second));
        assert!(Arc::ptr_eq(&slot_for(&slots, 3, slot_key("third")), &third));
        assert_eq!(slot_names(&slots), ["held", "second", "third"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_appliance_wide_secret_warns_once_per_token_grant_and_not_on_a_cache_hit() {
        const WARNING: &str = "Using a credential provider secret outside the provider's tenant";
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let mut fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                             "jwt_signing_key_secret_ref": "SIGNING_KEY", "tenant_id": "tenant-a"}))
            .await;
        let now = Utc::now();
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        assert_eq!(
            logs.text()
                .matches(WARNING)
                .count(),
            1,
            "{}",
            logs.text()
        );
        for _ in 0..2 {
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &["read"], now)
                        .await
                ),
                ("issued".into(), Freshness::Cached)
            );
        }
        assert_eq!(
            logs.text()
                .matches(WARNING)
                .count(),
            1,
            "{}",
            logs.text()
        );
        fixture
            .egress
            .policy
            .to_mut()
            .tenant_credential_isolation = RuleMode::Enforce;
        assert_eq!(
            fixture
                .acquire(&provider, &["read"], now)
                .await
                .err(),
            Some(ServiceTokenError::SecretUnavailable)
        );
        assert_eq!(
            logs.text()
                .matches(WARNING)
                .count(),
            1
        );
        assert_eq!(
            logs.text()
                .matches("Refusing a credential provider secret outside the provider's tenant")
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_that_cannot_sign_never_holds_back_the_next_request() {
        let fixture = Fixture::new().await;
        fixture
            .secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "MALFORMED_KEY".into(),
                secret_id: "MALFORMED_KEY".into(),
                description: None,
                value: "not a pem key".into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                             "jwt_signing_key_secret_ref": "MALFORMED_KEY"}))
            .await;
        let now = Utc::now();
        for attempt in 1..=3 {
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
                    .err(),
                Some(ServiceTokenError::ProviderMisconfigured)
            );
            assert_eq!(fixture.lookups(), vec!["MALFORMED_KEY"; 2 * attempt], "attempt {attempt} reached the grant");
        }
        assert!(fixture.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_endpoint_answer_still_holds_back_the_next_request() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                             "jwt_signing_key_secret_ref": "SIGNING_KEY"}))
            .await;
        fixture.fail(true);
        let now = Utc::now();
        for _ in 0..3 {
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
                    .err(),
                Some(ServiceTokenError::TokenRequestFailed)
            );
        }
        assert_eq!(fixture.requests().len(), 1);
        assert_eq!(fixture.lookups(), vec!["SIGNING_KEY"; 4], "only the first attempt reached the grant");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_missing_secret_or_refused_endpoint_never_holds_back_the_next_request() {
        let mut fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        for _ in 0..2 {
            fixture
                .observed
                .lookups_before_missing
                .store(2, Ordering::SeqCst);
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
                    .err(),
                Some(ServiceTokenError::SecretUnavailable)
            );
        }
        assert_eq!(fixture.lookups(), ["CLIENT_ID", "CLIENT_SECRET", "CLIENT_ID"].repeat(2));
        fixture
            .observed
            .lookups_before_missing
            .store(usize::MAX, Ordering::SeqCst);
        let allowlist = fixture
            .egress
            .exact_allowlist
            .take();
        for _ in 0..2 {
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
                    .err(),
                Some(ServiceTokenError::TokenEndpointRefused)
            );
        }
        assert!(fixture.requests().is_empty());
        fixture.egress.exact_allowlist = allowlist;
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn editing_the_provider_during_a_backoff_requests_a_token_at_once() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture.fail(true);
        let now = Utc::now();
        for _ in 0..2 {
            assert_eq!(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
                    .err(),
                Some(ServiceTokenError::TokenRequestFailed)
            );
        }
        assert_eq!(fixture.requests().len(), 1);
        fixture.fail(false);
        let mut edited = provider.clone();
        edited.default_scopes = vec!["other".into()];
        let edited = fixture
            .providers
            .update(edited)
            .await
            .unwrap();
        assert_eq!(
            issued(
                fixture
                    .acquire(&edited, &["read"], now)
                    .await
            ),
            ("issued".into(), Freshness::Fresh)
        );
        assert_eq!(fixture.requests().len(), 2);
    }

    type Recorded = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

    async fn recording<F: std::future::Future>(body: F) -> (F::Output, Vec<(&'static str, &'static str)>) {
        let recorded: Recorded = Arc::default();
        let output = oauth::TEST_TOKEN_REQUESTS
            .scope(recorded.clone(), body)
            .await;
        let recorded = recorded
            .lock()
            .unwrap()
            .clone();
        (output, recorded)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sent_token_request_is_counted_once_and_a_cache_hit_is_not() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        let now = Utc::now();
        let (freshness, recorded) = recording(async {
            let first = issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await,
            );
            let second = issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await,
            );
            (first.1, second.1)
        })
        .await;
        assert_eq!(freshness, (Freshness::Fresh, Freshness::Cached));
        assert_eq!(recorded, vec![("oauth2_client_credentials", "success")]);
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_error_status_is_counted_as_refused_and_a_backoff_skip_is_not_counted() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture.fail(true);
        let now = Utc::now();
        let (errors, recorded) = recording(async {
            let first = fixture
                .acquire(&provider, &["read"], now)
                .await
                .err();
            let held_back = fixture
                .acquire(&provider, &["read"], after(now, 100))
                .await
                .err();
            (first, held_back)
        })
        .await;
        assert_eq!(errors, (Some(ServiceTokenError::TokenRequestFailed), Some(ServiceTokenError::TokenRequestFailed)));
        assert_eq!(recorded, vec![("oauth2_client_credentials", "refused")]);
        assert_eq!(fixture.requests().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_slower_than_the_timeout_is_counted_as_timeout() {
        let mut fixture = Fixture::new().await;
        fixture.egress.timeout = std::time::Duration::from_secs(1);
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture
            .endpoint
            .delay_millis
            .store(2_500, Ordering::SeqCst);
        let (error, recorded) = recording(fixture.acquire(&provider, &["read"], Utc::now())).await;
        assert_eq!(error.err(), Some(ServiceTokenError::TokenRequestFailed));
        assert_eq!(recorded, vec![("oauth2_client_credentials", "timeout")]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_response_without_expires_in_or_with_wider_scopes_is_counted_as_invalid_response() {
        let fixture = Fixture::new().await;
        let jwt = fixture
            .provider(json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                             "jwt_signing_key_secret_ref": "SIGNING_KEY"}))
            .await;
        fixture.respond(json!({"access_token": "forever", "token_type": "Bearer"}));
        let (error, recorded) = recording(fixture.acquire(&jwt, &[], Utc::now())).await;
        assert_eq!(error.err(), Some(ServiceTokenError::TokenRequestFailed));
        assert_eq!(recorded, vec![("oauth2_jwt_bearer", "invalid_response")]);

        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture.respond(
            json!({"access_token": "wide", "token_type": "Bearer", "expires_in": 3600, "scope": "read write"}),
        );
        let (error, recorded) = recording(fixture.acquire(&provider, &["read"], Utc::now())).await;
        assert_eq!(error.err(), Some(ServiceTokenError::ScopeMismatch));
        assert_eq!(recorded, vec![("oauth2_client_credentials", "invalid_response")]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_that_never_reaches_the_endpoint_is_not_counted() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(client_credentials())
            .await;
        fixture
            .observed
            .lookups_before_missing
            .store(0, Ordering::SeqCst);
        let (error, recorded) = recording(fixture.acquire(&provider, &["read"], Utc::now())).await;
        assert_eq!(error.err(), Some(ServiceTokenError::SecretUnavailable));
        assert!(recorded.is_empty());
        assert!(fixture.requests().is_empty());
    }
}
