//! OAuth 2.0 flow handling — authorization URL generation, callback processing, token exchange
//!
//! This module implements the full 3-legged OAuth flow:
//! 1. Generate authorization URL (with encrypted state parameter)
//! 2. Handle callback (exchange code for tokens)
//! 3. Token refresh
//! 4. DelegationCredential VC issuance

use anyhow::{Context, Result, anyhow};
use chrono::{Duration, Utc};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use super::{ConsentRequired, OAuthState, OAuthTokenResponse};
use crate::config::credential_policy::{RuleMode, credential_policy};
use crate::credential_providers::{CredentialProvider, GrantClientAuthentication};
use crate::identity::ssi::vc_issuer::VcSigner;
use crate::secrets::SecretsStore;
use std::sync::Arc;

/// How long a consent start link, and the callback state it leads to, stay usable.
const CONSENT_STATE_LIFETIME_MINUTES: i64 = 10;

/// The prefix of the cookie that binds a consent callback to the browser that
/// confirmed the consent start page. `__Host-` keeps it on the gateway's own
/// host, on `Path=/`, so a sibling subdomain cannot set it.
pub const CONSENT_COOKIE_PREFIX: &str = "__Host-ag_consent_";

/// The binding cookie of `state`: [`CONSENT_COOKIE_PREFIX`] followed by the
/// first 16 characters of its sealed browser binding, so each consent has a
/// cookie of its own and the callback reads only that one.
pub fn binding_cookie_name(state: &OAuthState) -> Option<String> {
    state
        .browser_binding
        .as_deref()
        .and_then(|binding| binding.get(..16))
        .map(|id| format!("{CONSENT_COOKIE_PREFIX}{id}"))
}

/// The gateway's consent start page for `provider`: `{redirect URI}/start`
/// with a sealed start state. The person opens it and confirms; only then does
/// the gateway build the vendor's authorization URL. `max_consent_age_secs` is
/// how long the consent may be used once given, which the page says and the
/// callback stores as the consent's end.
pub fn build_authorization_url(
    provider: &CredentialProvider,
    agent_did: &str,
    user_identity_hash: &str,
    surface_id: &str,
    scopes: &[String],
    gateway_base_url: &str,
    max_consent_age_secs: Option<u64>,
) -> Result<String> {
    let mut url = provider
        .consent_redirect_uri(gateway_base_url)
        .map_err(|reason| anyhow!("Provider '{}': {reason}", provider.provider_id))?;
    let effective_scopes = if scopes.is_empty() {
        &provider.default_scopes
    } else {
        scopes
    };
    let state = OAuthState {
        agent_did: agent_did.to_string(),
        user_identity_hash: user_identity_hash.to_string(),
        surface_id: surface_id.to_string(),
        credential_provider_id: provider.id.clone(),
        provider_id: provider.provider_id.clone(),
        max_consent_age_secs,
        nonce: Uuid::new_v4().to_string(),
        expires_at: Utc::now() + Duration::minutes(CONSENT_STATE_LIFETIME_MINUTES),
        code_verifier: None,
        scopes: effective_scopes.to_vec(),
        browser_binding: None,
    };
    let start_path = format!("{}/start", url.path());
    url.set_path(&start_path);
    url.query_pairs_mut()
        .append_pair("state", &encode_oauth_state(&state)?);

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        agent_did = %agent_did,
        user_hash = %user_identity_hash,
        scopes = ?effective_scopes,
        "Built OAuth consent start URL"
    );

    Ok(url.into())
}

/// The consent start page for `provider` ([`build_authorization_url`]), minted
/// only when the start POST could complete: the redirect URI follows the
/// consent rules and no other provider has it, the client ID resolves, and the
/// vendor's authorization URL can be built.
#[allow(clippy::too_many_arguments)]
pub async fn mint_consent_link(
    provider: &CredentialProvider,
    agent_did: &str,
    user_identity_hash: &str,
    surface_id: &str,
    scopes: &[String],
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
    provider_store: &dyn crate::credential_providers::storage::CredentialProviderStorage,
    max_consent_age_secs: Option<u64>,
) -> Result<String> {
    provider
        .consent_redirect_uri(gateway_base_url)
        .map_err(|reason| anyhow!("Provider '{}': {reason}", provider.provider_id))?;
    if crate::credential_providers::redirect_uri_taken_by(provider_store, provider, gateway_base_url)
        .await?
        .is_some()
    {
        return Err(anyhow!("Provider '{}' shares its redirect URI with another provider", provider.provider_id));
    }
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    resolve_secret(provider, secrets_store, client_id_ref, isolation_mode())
        .await
        .context("Failed to resolve client_id secret")?;
    provider
        .consent_authorization_endpoint()
        .map_err(|rule| anyhow!("Provider '{}': {rule}", provider.provider_id))?;
    build_authorization_url(
        provider,
        agent_did,
        user_identity_hash,
        surface_id,
        scopes,
        gateway_base_url,
        max_consent_age_secs,
    )
}

/// What the consent start POST answers with: the vendor's authorization URL,
/// the binding cookie's value and when the callback state expires.
pub struct ConsentStart {
    pub vendor_url: url::Url,
    pub cookie_name: String,
    pub cookie_value: zeroize::Zeroizing<String>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Begin consent from a decoded start state: resolve the client id, make a
/// PKCE verifier and 32 random binding bytes, seal a callback state that holds
/// the verifier and the bytes' SHA-256 under a fresh nonce, and build the
/// vendor's authorization URL. Nothing is claimed: the caller claims the start
/// nonce once this succeeds.
pub async fn begin_consent(
    provider: &CredentialProvider,
    start: &OAuthState,
    redirect_uri: &url::Url,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<ConsentStart> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(provider, secrets_store, client_id_ref, isolation_mode())
        .await
        .context("Failed to resolve client_id secret")?;
    let code_verifier = generate_pkce_verifier();
    let code_challenge = generate_pkce_challenge(&code_verifier);
    let mut binding = zeroize::Zeroizing::new([0u8; 32]);
    rand::rng().fill(&mut binding[..]);
    let expires_at = start
        .expires_at
        .min(Utc::now() + Duration::minutes(CONSENT_STATE_LIFETIME_MINUTES));
    let callback = OAuthState {
        nonce: Uuid::new_v4().to_string(),
        expires_at,
        code_verifier: Some(code_verifier),
        browser_binding: Some(base64_url_encode_bytes(&Sha256::digest(binding.as_slice()))),
        ..start.clone()
    };
    let vendor_url = vendor_authorization_url(
        provider,
        &client_id,
        redirect_uri.as_str(),
        &start.scopes,
        &encode_oauth_state(&callback)?,
        &code_challenge,
    )?;
    Ok(ConsentStart {
        vendor_url,
        cookie_name: binding_cookie_name(&callback).ok_or_else(|| anyhow!("OAuth state has no browser binding"))?,
        cookie_value: zeroize::Zeroizing::new(base64_url_encode_bytes(binding.as_slice())),
        expires_at,
    })
}

/// The vendor's authorization URL: the provider's
/// [`consent_authorization_endpoint`](CredentialProvider::consent_authorization_endpoint)
/// with the gateway's parameters and `additional_params` added.
fn vendor_authorization_url(
    provider: &CredentialProvider,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    code_challenge: &str,
) -> Result<url::Url> {
    let mut url = provider
        .consent_authorization_endpoint()
        .map_err(|rule| anyhow!("Provider '{}': {rule}", provider.provider_id))?;
    url.query_pairs_mut()
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", scopes.join(" ").as_str()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .extend_pairs(&provider.additional_params);
    Ok(url)
}

/// Decode a consent start state: one with neither a browser binding nor a PKCE
/// verifier, which only [`build_authorization_url`] seals.
pub fn decode_start_state(encoded: &str) -> Result<OAuthState> {
    let state = decode_oauth_state(encoded)?;
    if state
        .browser_binding
        .is_some()
        || state.code_verifier.is_some()
    {
        return Err(anyhow!("OAuth state is not a consent start state"));
    }
    Ok(state)
}

/// Decode a consent callback state: one with a browser binding and a PKCE
/// verifier, which only [`begin_consent`] seals.
pub fn decode_callback_state(encoded: &str) -> Result<OAuthState> {
    let state = decode_oauth_state(encoded)?;
    if state
        .browser_binding
        .is_none()
        || state.code_verifier.is_none()
    {
        return Err(anyhow!("OAuth state is not a consent callback state"));
    }
    Ok(state)
}

/// Whether `cookie_value`, the value of `state`'s own binding cookie, is the
/// browser binding `state` was sealed with: 32 base64url bytes whose SHA-256 is
/// the state's, compared in constant time.
pub fn browser_binding_matches(
    state: &OAuthState,
    cookie_value: Option<&str>,
) -> bool {
    use subtle::ConstantTimeEq;
    let Some(expected) = state
        .browser_binding
        .as_deref()
        .and_then(|binding| base64_url_decode(binding).ok())
        .filter(|binding| binding.len() == 32)
    else {
        return false;
    };
    cookie_value
        .and_then(|value| base64_url_decode(value).ok())
        .filter(|bytes| bytes.len() == 32)
        .is_some_and(|bytes| {
            bool::from(
                Sha256::digest(&bytes)
                    .as_slice()
                    .ct_eq(&expected),
            )
        })
}

/// Exchange an OAuth authorization code for tokens
pub async fn exchange_code_for_tokens(
    provider: &CredentialProvider,
    code: &str,
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
    code_verifier: Option<&str>,
) -> Result<OAuthTokenResponse> {
    exchange_code_for_tokens_with(
        provider,
        code,
        gateway_base_url,
        secrets_store,
        code_verifier,
        &TokenEgress::from_environment(),
    )
    .await
}

async fn exchange_code_for_tokens_with(
    provider: &CredentialProvider,
    code: &str,
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
    code_verifier: Option<&str>,
    egress: &TokenEgress,
) -> Result<OAuthTokenResponse> {
    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    egress.check_token_endpoint(&provider.provider_id, token_endpoint)?;
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(
        provider,
        secrets_store,
        client_id_ref,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await
    .context("Failed to resolve client_id")?;
    let client_secret = resolve_secret(
        provider,
        secrets_store,
        client_secret_ref,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await
    .context("Failed to resolve client_secret")?;

    let callback_url = provider
        .consent_redirect_uri(gateway_base_url)
        .map_err(|reason| anyhow!("Provider '{}': {reason}", provider.provider_id))?
        .to_string();
    crate::url_validation::validate_oauth_endpoint_url(&callback_url)
        .map_err(|e| anyhow!("Blocked callback_url for provider '{}': {}", provider.provider_id, e))?;
    let (http_client, token_url) = egress
        .pinned_client(token_endpoint)
        .await?;

    let mut params = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", callback_url.clone()),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier.to_string()));
    }

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_endpoint = %token_endpoint,
        has_pkce = %code_verifier.is_some(),
        "Exchanging authorization code for tokens"
    );

    let response = http_client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .context("Failed to send token exchange request")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read token response body")?;

    if !status.is_success() {
        let reason = token_error_code(&body);
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            reason = %reason,
            "Token exchange failed"
        );
        return Err(anyhow!("Token exchange failed (HTTP {}): {}", status, reason));
    }

    // Try JSON first; fall back to application/x-www-form-urlencoded (e.g. GitHub without Accept header)
    let token_response: OAuthTokenResponse = serde_json::from_str(&body)
        .or_else(|_| {
            let pairs: std::collections::HashMap<String, String> = serde_urlencoded::from_str(&body)?;
            Ok::<OAuthTokenResponse, serde_urlencoded::de::Error>(OAuthTokenResponse {
                access_token: pairs
                    .get("access_token")
                    .cloned()
                    .unwrap_or_default(),
                refresh_token: pairs
                    .get("refresh_token")
                    .cloned(),
                token_type: pairs
                    .get("token_type")
                    .cloned()
                    .unwrap_or_else(|| "bearer".to_string()),
                expires_in: pairs
                    .get("expires_in")
                    .and_then(|v| v.parse().ok()),
                scope: pairs.get("scope").cloned(),
            })
        })
        .map_err(|e| anyhow!("Failed to parse token response as JSON or form-urlencoded: {e}"))?;

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_type = %token_response.token_type,
        has_refresh_token = %token_response.refresh_token.is_some(),
        expires_in = ?token_response.expires_in,
        scope = ?token_response.scope,
        "Token exchange successful"
    );

    Ok(token_response)
}

/// The code answered for an OAuth error that is missing or not a valid RFC 6749 code.
pub(crate) const UNRECOGNIZED_ERROR: &str = "unrecognized_error";

/// The `error` code of a token-endpoint error response (RFC 6749 section 5.2), JSON or
/// form-encoded, checked by [`oauth_error_code`]. Nothing else in the body is logged or
/// returned: `error_description`, `error_uri` and echoed request parameters can carry
/// secrets.
pub(crate) fn token_error_code(body: &str) -> String {
    #[derive(serde::Deserialize)]
    struct TokenErrorBody {
        error: Option<String>,
    }

    serde_json::from_str::<TokenErrorBody>(body)
        .ok()
        .or_else(|| serde_urlencoded::from_str::<TokenErrorBody>(body).ok())
        .and_then(|parsed| parsed.error)
        .map_or_else(|| UNRECOGNIZED_ERROR.to_string(), |error| oauth_error_code(&error).to_string())
}

/// `error` when it is 1 to 64 bytes of the RFC 6749 section 5.2 error character set
/// (`%x20-21 / %x23-5B / %x5D-7E`), otherwise [`UNRECOGNIZED_ERROR`].
pub(crate) fn oauth_error_code(error: &str) -> &str {
    let valid = !error.is_empty()
        && error.len() <= 64
        && error
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E));
    if valid {
        error
    } else {
        UNRECOGNIZED_ERROR
    }
}

/// A refreshed token and whether its provider's token endpoint breaks the https rule and was
/// let through only because the rule is in warn mode.
pub struct RefreshedToken {
    pub response: OAuthTokenResponse,
    pub insecure_endpoint: bool,
}

/// Refresh an expired access token using a refresh token
pub async fn refresh_access_token(
    provider: &CredentialProvider,
    refresh_token: &str,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<RefreshedToken> {
    let egress = TokenEgress::from_environment();
    let response = refresh_access_token_with(provider, refresh_token, secrets_store, &egress).await?;
    Ok(RefreshedToken {
        response,
        insecure_endpoint: egress.insecure_endpoint(
            provider
                .token_endpoint
                .as_deref(),
        ),
    })
}

async fn refresh_access_token_with(
    provider: &CredentialProvider,
    refresh_token: &str,
    secrets_store: &Arc<dyn SecretsStore>,
    egress: &TokenEgress,
) -> Result<OAuthTokenResponse> {
    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    egress.check_token_endpoint(&provider.provider_id, token_endpoint)?;
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(
        provider,
        secrets_store,
        client_id_ref,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await
    .context("Failed to resolve client_id for refresh")?;
    let client_secret = resolve_secret(
        provider,
        secrets_store,
        client_secret_ref,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await
    .context("Failed to resolve client_secret for refresh")?;

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
    ];

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_endpoint = %token_endpoint,
        "Refreshing access token"
    );

    let (http_client, token_url) = egress
        .pinned_client(token_endpoint)
        .await?;

    let response = http_client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .context("Failed to send token refresh request")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read refresh response body")?;

    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            "Token refresh failed — user may need to re-consent"
        );
        return Err(anyhow!("Token refresh failed (HTTP {}): {}", status, token_error_code(&body)));
    }

    let token_response: OAuthTokenResponse = serde_json::from_str(&body)
        .or_else(|_| {
            let pairs: std::collections::HashMap<String, String> = serde_urlencoded::from_str(&body)?;
            Ok::<OAuthTokenResponse, serde_urlencoded::de::Error>(OAuthTokenResponse {
                access_token: pairs
                    .get("access_token")
                    .cloned()
                    .unwrap_or_default(),
                refresh_token: pairs
                    .get("refresh_token")
                    .cloned(),
                token_type: pairs
                    .get("token_type")
                    .cloned()
                    .unwrap_or_else(|| "bearer".to_string()),
                expires_in: pairs
                    .get("expires_in")
                    .and_then(|v| v.parse().ok()),
                scope: pairs.get("scope").cloned(),
            })
        })
        .map_err(|e| anyhow!("Failed to parse refresh response as JSON or form-urlencoded: {e}"))?;

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        has_new_refresh_token = %token_response.refresh_token.is_some(),
        expires_in = ?token_response.expires_in,
        "Token refresh successful"
    );

    Ok(token_response)
}

pub async fn refresh_scoped_access_token(
    provider: &CredentialProvider,
    refresh_token: &str,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    egress: &TokenEgress,
) -> Result<Option<OAuthTokenResponse>> {
    anyhow::ensure!(!refresh_token.is_empty() && refresh_token.len() <= 32 * 1024, "Invalid refresh credential");
    scoped_token_grant(provider, Some(refresh_token), scopes, secrets, egress).await
}

pub async fn fetch_scoped_client_credentials_token(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    egress: &TokenEgress,
) -> Result<OAuthTokenResponse> {
    scoped_token_grant(provider, None, scopes, secrets, egress)
        .await?
        .ok_or_else(|| anyhow!("Provider credential grant rejected"))
}

async fn scoped_token_grant(
    provider: &CredentialProvider,
    refresh_token: Option<&str>,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    egress: &TokenEgress,
) -> Result<Option<OAuthTokenResponse>> {
    let endpoint = validated_token_endpoint(provider, egress)?;
    let resource = match provider.resource.as_deref() {
        Some(resource) => {
            crate::sts::mcp_profile::canonical_https_url(resource)
                .map_err(|_| misconfigured("Invalid provider resource"))?;
            Some(resource)
        }
        None if refresh_token.is_some() => return Err(misconfigured("Missing refresh resource")),
        None => None,
    };
    let mode = egress
        .policy
        .tenant_credential_isolation;
    let client_id = provider_client_id(provider, secrets, mode).await?;
    let client_secret = provider_client_secret(provider, secrets, mode).await?;
    let scope = scopes.join(" ");
    let mut params = vec![
        (
            "grant_type",
            if refresh_token.is_some() {
                "refresh_token"
            } else {
                "client_credentials"
            },
        ),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
    ];
    if let Some(resource) = resource {
        params.push(("resource", resource));
    }
    if !scope.is_empty() {
        params.push(("scope", scope.as_str()));
    }
    if let Some(refresh_token) = refresh_token {
        params.push(("refresh_token", refresh_token));
    }
    request_token(provider, endpoint, &params, None, refresh_token.is_some(), egress).await
}

const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const JWT_CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The client identity a JWT Bearer grant carries, resolved from the provider's secret
/// references and held in zeroizing buffers until the request is sent.
enum GrantClient {
    /// A public client: `client_id` in the form body.
    Public { id: String },
    /// `client_id` and `client_secret` in the form body.
    Post { id: String, secret: zeroize::Zeroizing<String> },
    /// The `Authorization` header value of HTTP Basic client authentication.
    Basic { authorization: zeroize::Zeroizing<String> },
}

/// The client ID the provider's `client_id_secret_ref` names.
async fn provider_client_id(
    provider: &CredentialProvider,
    secrets: &Arc<dyn SecretsStore>,
    mode: RuleMode,
) -> Result<String> {
    let reference = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| misconfigured("Missing provider client"))?;
    Ok(resolve_secret(provider, secrets, reference, mode).await?)
}

/// The client secret the provider's `client_secret_secret_ref` names.
async fn provider_client_secret(
    provider: &CredentialProvider,
    secrets: &Arc<dyn SecretsStore>,
    mode: RuleMode,
) -> Result<zeroize::Zeroizing<String>> {
    let reference = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| misconfigured("Missing provider client secret"))?;
    Ok(zeroize::Zeroizing::new(resolve_secret(provider, secrets, reference, mode).await?))
}

/// The client identity the provider's client authentication sends with its grant, or `None`
/// when it sets no client authentication, in which case its client references are not read.
async fn grant_client(
    provider: &CredentialProvider,
    secrets: &Arc<dyn SecretsStore>,
    mode: RuleMode,
) -> Result<Option<GrantClient>> {
    let Some(method) = provider
        .jwt
        .client_authentication_method()
    else {
        return Ok(None);
    };
    let id = provider_client_id(provider, secrets, mode).await?;
    if !method.uses_secret() {
        return Ok(Some(GrantClient::Public { id }));
    }
    let secret = provider_client_secret(provider, secrets, mode).await?;
    Ok(Some(if method == GrantClientAuthentication::ClientSecretBasic {
        GrantClient::Basic {
            authorization: super::revocation::basic_authorization(&id, &secret),
        }
    } else {
        GrantClient::Post { id, secret }
    }))
}

/// Fetch a token with a JWT Bearer grant (RFC 7523 section 2.1): the signed JWT is the
/// grant, and the client identifies itself only as the provider's client authentication
/// says, not at all when it sets no client authentication. A provider that sets one also
/// asks for its scopes in the `scope` form field, which servers such as Ory Hydra grant
/// scopes from; one that sets none of them names its scopes only in the assertion's `scope` claim.
pub async fn fetch_jwt_bearer_token(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    egress: &TokenEgress,
) -> Result<OAuthTokenResponse> {
    let endpoint = validated_token_endpoint(provider, egress)?;
    let client = grant_client(
        provider,
        secrets,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await?;
    let claims = super::jwt_assertion::grant_assertion_claims(provider, scopes, Utc::now().timestamp())
        .map_err(|e| misconfigured(e.to_string()))?;
    let assertion = signed_assertion(
        provider,
        &claims,
        secrets,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await?;
    let scope = scopes.join(" ");
    let mut params = vec![("grant_type", JWT_BEARER_GRANT_TYPE), ("assertion", assertion.as_str())];
    if let Some(resource) = provider.resource.as_deref() {
        params.push(("resource", resource));
    }
    let authorization = match &client {
        None => None,
        Some(GrantClient::Public { id }) => {
            params.push(("client_id", id.as_str()));
            None
        }
        Some(GrantClient::Post { id, secret }) => {
            params.push(("client_id", id.as_str()));
            params.push(("client_secret", secret.as_str()));
            None
        }
        Some(GrantClient::Basic { authorization }) => Some(authorization.as_str()),
    };
    if client.is_some() && !scope.is_empty() {
        params.push(("scope", scope.as_str()));
    }
    request_token(provider, endpoint, &params, authorization, false, egress)
        .await?
        .ok_or_else(|| anyhow!("Provider credential grant rejected"))
}

/// Fetch a token with a Client Credentials grant whose client authenticates with a
/// signed JWT (`private_key_jwt`, RFC 7523 section 2.2) instead of a client secret.
pub async fn fetch_client_credentials_jwt_auth_token(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    egress: &TokenEgress,
) -> Result<OAuthTokenResponse> {
    let endpoint = validated_token_endpoint(provider, egress)?;
    let client_id = provider_client_id(
        provider,
        secrets,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await?;
    let claims = super::jwt_assertion::client_auth_assertion_claims(provider, &client_id, Utc::now().timestamp())
        .map_err(|e| misconfigured(e.to_string()))?;
    let assertion = signed_assertion(
        provider,
        &claims,
        secrets,
        egress
            .policy
            .tenant_credential_isolation,
    )
    .await?;
    let scope = scopes.join(" ");
    let mut params = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id.as_str()),
        ("client_assertion_type", JWT_CLIENT_ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
    ];
    if !scope.is_empty() {
        params.push(("scope", scope.as_str()));
    }
    if let Some(resource) = provider.resource.as_deref() {
        params.push(("resource", resource));
    }
    request_token(provider, endpoint, &params, None, false, egress)
        .await?
        .ok_or_else(|| anyhow!("Provider credential grant rejected"))
}

/// Sign `claims` with the provider's key, holding the PEM key and certificate in
/// zeroizing buffers for the duration.
async fn signed_assertion(
    provider: &CredentialProvider,
    claims: &super::jwt_assertion::AssertionClaims,
    secrets: &Arc<dyn SecretsStore>,
    mode: RuleMode,
) -> Result<zeroize::Zeroizing<String>> {
    let algorithm = provider
        .jwt_signing_algorithm()
        .ok_or_else(|| misconfigured("Provider does not sign assertions"))?;
    let key = zeroize::Zeroizing::new(
        resolve_secret(
            provider,
            secrets,
            provider
                .jwt
                .jwt_signing_key_secret_ref
                .as_deref()
                .ok_or_else(|| misconfigured("Missing provider signing key"))?,
            mode,
        )
        .await?,
    );
    let certificate = match provider
        .jwt
        .jwt_certificate_secret_ref
        .as_deref()
    {
        Some(secret_ref) => Some(zeroize::Zeroizing::new(resolve_secret(provider, secrets, secret_ref, mode).await?)),
        None => None,
    };
    super::jwt_assertion::sign_assertion(
        &key,
        algorithm,
        super::jwt_assertion::AssertionHeader {
            key_id: provider
                .jwt
                .jwt_key_id
                .as_deref(),
            certificate_pem: certificate
                .as_ref()
                .map(|certificate| certificate.as_str()),
        },
        claims,
    )
    .map(zeroize::Zeroizing::new)
    .map_err(|e| misconfigured(e.to_string()))
}

fn validated_token_endpoint<'provider>(
    provider: &'provider CredentialProvider,
    egress: &TokenEgress,
) -> Result<&'provider str> {
    let endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| misconfigured("Missing provider token endpoint"))?;
    egress.check_token_endpoint(&provider.provider_id, endpoint)?;
    Ok(endpoint)
}

/// How a token request reaches a credential provider's token endpoint.
#[derive(Debug, Clone)]
pub struct TokenEgress {
    pub timeout: std::time::Duration,
    /// Exact test endpoints admitted under `AG_TEST_MODE=true`; `None` in production.
    pub exact_allowlist: Option<String>,
    /// The bootstrap `[credential_policy]` the token endpoint is held to: the process-wide
    /// policy borrowed, or one a test owns.
    pub policy: std::borrow::Cow<'static, crate::config::credential_policy::CredentialPolicyConfig>,
}

/// A local provider setting or key that the token request cannot use, so the request never
/// reached the token endpoint.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProviderMisconfigured(String);

fn misconfigured(reason: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ProviderMisconfigured(reason.into()))
}

/// The token endpoint resolved to an address the egress policy blocks.
#[derive(Debug, thiserror::Error)]
#[error("token endpoint refused by egress policy")]
pub struct TokenEndpointRefused;

/// The OAuth error codes RFC 6749 section 5.2 and RFC 6750 section 3.1 register for a token
/// endpoint or a protected resource.
const REGISTERED_OAUTH_ERRORS: [&str; 8] = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_token",
    "insufficient_scope",
];

/// A token endpoint's OAuth `error` code when it is a registered one, otherwise `other`. A token
/// endpoint can put any short text in its `error`, so nothing else is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthErrorCode(&'static str);

impl OAuthErrorCode {
    pub(crate) fn new(error: &str) -> Self {
        Self(
            REGISTERED_OAUTH_ERRORS
                .into_iter()
                .find(|registered| *registered == error)
                .unwrap_or("other"),
        )
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for OAuthErrorCode {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A service token request the token endpoint answered with an OAuth error. Only its `error`
/// code is kept.
#[derive(Debug, thiserror::Error)]
#[error("Provider token request rejected")]
pub struct TokenRequestRejected {
    pub code: OAuthErrorCode,
}

/// The token endpoint is not https, and the credential policy refuses it.
#[derive(Debug, thiserror::Error)]
#[error("token_endpoint must be an https URL")]
pub struct TokenEndpointNotHttps;

#[cfg(test)]
tokio::task_local! {
    static EGRESS_OVERRIDE: TokenEgress;
}

impl TokenEgress {
    /// Runs `future` with [`Self::from_environment`] answering `self`, so a test can
    /// reach a loopback token endpoint through a caller that builds its own egress.
    #[cfg(test)]
    pub(crate) async fn scope<F: std::future::Future>(
        self,
        future: F,
    ) -> F::Output {
        EGRESS_OVERRIDE
            .scope(self, future)
            .await
    }

    pub fn from_environment() -> Self {
        #[cfg(test)]
        if let Ok(egress) = EGRESS_OVERRIDE.try_with(Clone::clone) {
            return egress;
        }
        let policy = crate::config::credential_policy::credential_policy();
        Self {
            timeout: std::time::Duration::from_secs(policy.token_request_timeout_secs),
            exact_allowlist: crate::url_validation::bdd_oauth_endpoint_allowlist(),
            policy: std::borrow::Cow::Borrowed(policy),
        }
    }

    /// Whether a provider's `endpoint` breaks the https rule and is let through only because
    /// the rule is in warn mode.
    pub fn insecure_endpoint(
        &self,
        endpoint: Option<&str>,
    ) -> bool {
        endpoint.is_some_and(|endpoint| !self.permits_token_endpoint(endpoint))
    }

    /// Whether `endpoint` meets the https rule: an https URL, or one that
    /// `insecure_token_endpoints` or the test allowlist names exactly.
    pub fn permits_token_endpoint(
        &self,
        endpoint: &str,
    ) -> bool {
        let Ok(url) = url::Url::parse(endpoint.trim()) else {
            return false;
        };
        url.scheme() == "https"
            || self
                .policy
                .allows_insecure_token_endpoint(endpoint)
            || self
                .exact_allowlist
                .as_deref()
                .is_some_and(|allowlist| {
                    allowlist
                        .split(',')
                        .filter_map(|entry| url::Url::parse(entry.trim()).ok())
                        .any(|entry| entry == url)
                })
    }

    /// Whether a stored provider may still send its credentials to `endpoint`: one that
    /// meets the https rule, or an http one while the rule is only warned about.
    pub fn admits_token_endpoint(
        &self,
        endpoint: &str,
    ) -> bool {
        self.permits_token_endpoint(endpoint)
            || (!self
                .policy
                .token_endpoint_https
                .is_enforced()
                && url::Url::parse(endpoint.trim()).is_ok_and(|url| url.scheme() == "http"))
    }

    /// Checks a stored provider's `endpoint` before any of its secrets are read, logging a
    /// warning for an http endpoint the warn mode still lets through.
    pub(crate) fn check_token_endpoint(
        &self,
        provider_id: &str,
        endpoint: &str,
    ) -> Result<(), TokenEndpointNotHttps> {
        if self.permits_token_endpoint(endpoint) {
            return Ok(());
        }
        if !self.admits_token_endpoint(endpoint) {
            warn!(target: "credential_delegation", provider_id, "Refusing a credential provider token endpoint that is not https");
            return Err(TokenEndpointNotHttps);
        }
        warn!(
            target: "credential_delegation",
            provider_id,
            "Credential provider token endpoint is not https; it will be refused once credential_policy.token_endpoint_https is enforce"
        );
        Ok(())
    }

    /// A redirect-off client that ignores proxies, pinned to the addresses `endpoint`
    /// resolved to when the Configured policy vetted it (cloud metadata, loopback and
    /// unspecified addresses refused, private networks allowed), and the URL to post to.
    /// A refused address is [`TokenEndpointRefused`].
    pub(crate) async fn pinned_client(
        &self,
        endpoint: &str,
    ) -> Result<(reqwest::Client, url::Url)> {
        let raw = endpoint.to_string();
        let timeout = self.timeout;
        let allowlist = self.exact_allowlist.clone();
        let (client, target) = tokio::task::spawn_blocking(move || {
            crate::egress::pinned_configured_direct_client(&raw, timeout, allowlist.as_deref())
        })
        .await
        .context("Provider token request failed")?
        .map_err(|error| match error {
            crate::egress::EgressError::Blocked(_) | crate::egress::EgressError::Parse(_) => {
                anyhow::Error::new(TokenEndpointRefused)
            }
            _ => anyhow!("Provider token request failed"),
        })?;
        Ok((client, target.url))
    }
}

/// The largest answer a token endpoint may give.
pub(crate) const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

/// How long a token request may take, from sending it to reading the last byte.
pub(crate) const TOKEN_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a token endpoint answered: its status and its body.
pub(crate) struct TokenEndpointAnswer {
    pub status: reqwest::StatusCode,
    pub body: zeroize::Zeroizing<Vec<u8>>,
}

/// Why a token request has no answer to read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TokenPostFailure {
    #[error("Provider token request failed")]
    Unreachable(#[source] reqwest::Error),
    #[error("Provider token response failed")]
    ResponseFailed(#[source] reqwest::Error),
    #[error("Provider token response too large")]
    TooLarge,
    #[error("Provider token request timed out")]
    TimedOut,
}

/// `request` with `authorization` as its `Authorization` header, marked sensitive so that no
/// debug output of the request shows it. `authorization` is a `Basic` credential from
/// `revocation::basic_authorization`, always printable ASCII, so a value that is not a header
/// value is a bug and stops here rather than going out unmarked. Token requests and revocation
/// requests both set the header through this function.
pub(super) fn with_sensitive_authorization(
    request: reqwest::RequestBuilder,
    authorization: &str,
) -> reqwest::RequestBuilder {
    let mut value =
        reqwest::header::HeaderValue::from_str(authorization).expect("an Authorization value is printable ASCII");
    value.set_sensitive(true);
    request.header(reqwest::header::AUTHORIZATION, value)
}

/// POST `params` to the token endpoint `endpoint` through `client`, asking for
/// JSON, with `authorization` as the `Authorization` header when one is given,
/// and read the answer: at most [`MAX_TOKEN_RESPONSE_BYTES`] within
/// [`TOKEN_REQUEST_TIMEOUT`]. The service token requests go through
/// [`post_token_request_within`] and the code exchange and refresh of external
/// consent through this function; the legacy delegated refresh and code
/// exchange read their answers themselves. Each caller judges the answer.
pub(crate) async fn post_token_request(
    client: &reqwest::Client,
    endpoint: &str,
    params: &[(&str, &str)],
    authorization: Option<&str>,
) -> std::result::Result<TokenEndpointAnswer, TokenPostFailure> {
    post_token_request_within(client, endpoint, params, authorization, TOKEN_REQUEST_TIMEOUT).await
}

/// [`post_token_request`] within `timeout` instead of [`TOKEN_REQUEST_TIMEOUT`].
pub(crate) async fn post_token_request_within(
    client: &reqwest::Client,
    endpoint: &str,
    params: &[(&str, &str)],
    authorization: Option<&str>,
    timeout: std::time::Duration,
) -> std::result::Result<TokenEndpointAnswer, TokenPostFailure> {
    let operation = async {
        let mut request = client
            .post(endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(params);
        if let Some(authorization) = authorization {
            request = with_sensitive_authorization(request, authorization);
        }
        let mut response = request
            .send()
            .await
            .map_err(TokenPostFailure::Unreachable)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_TOKEN_RESPONSE_BYTES as u64)
        {
            return Err(TokenPostFailure::TooLarge);
        }
        let status = response.status();
        let mut body = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(TokenPostFailure::ResponseFailed)?
        {
            if body
                .len()
                .saturating_add(chunk.len())
                > MAX_TOKEN_RESPONSE_BYTES
            {
                return Err(TokenPostFailure::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(TokenEndpointAnswer { status, body })
    };
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| TokenPostFailure::TimedOut)?
}

/// How a token request that was sent to a token endpoint ended: the `outcome` label of the
/// credential provider token request counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenRequestOutcome {
    Success,
    /// The endpoint answered with a non-2xx status, or the connection failed before any answer.
    Refused,
    Timeout,
    /// The answer could not be parsed, was over the size limit, lacked a usable `expires_in`
    /// or token, or granted scopes other than requested.
    InvalidResponse,
}

impl TokenRequestOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    /// The `(provider_type, outcome)` pairs recorded inside a test's scope.
    pub(crate) static TEST_TOKEN_REQUESTS: Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>;
}

/// Counts one service token request that was sent to `provider`'s token endpoint. No URL,
/// provider id, secret or tenant is a label.
pub(crate) fn record_token_request(
    provider: &CredentialProvider,
    outcome: TokenRequestOutcome,
) {
    use crate::credential_providers::CredentialProviderType as Type;
    let provider_type = match provider.provider_type {
        Type::OAuth2ClientCredentials => "oauth2_client_credentials",
        Type::OAuth2JwtBearer => "oauth2_jwt_bearer",
        Type::OAuth2ClientCredentialsJwtAuth => "oauth2_client_credentials_jwt_auth",
        Type::OAuth2AuthorizationCode => "oauth2_authorization_code",
        Type::ApiKey => "api_key",
    };
    crate::metrics::backends::prometheus::track_credential_provider_token_request(provider_type, outcome.label());
    #[cfg(test)]
    let _ = TEST_TOKEN_REQUESTS.try_with(|recorded| {
        if let Ok(mut recorded) = recorded.lock() {
            recorded.push((provider_type, outcome.label()));
        }
    });
}

impl TokenPostFailure {
    /// The token request counter's outcome for a request that was sent and failed.
    fn outcome(&self) -> TokenRequestOutcome {
        match self {
            Self::Unreachable(error) if !error.is_timeout() => TokenRequestOutcome::Refused,
            Self::ResponseFailed(error) if !error.is_timeout() => TokenRequestOutcome::InvalidResponse,
            Self::TooLarge => TokenRequestOutcome::InvalidResponse,
            Self::Unreachable(_) | Self::ResponseFailed(_) | Self::TimedOut => TokenRequestOutcome::Timeout,
        }
    }
}

/// POST a token request through the egress's pinned client ([`post_token_request_within`]),
/// with `authorization` as its `Authorization` header when one is given, and read its JSON
/// response, the whole request within the egress timeout. The access token must be a
/// non-empty Bearer with an `expires_in` of up to 366 days.
/// When `refresh` is set an `invalid_grant` answer is `Ok(None)`; any other refusal is
/// an error, and only its OAuth `error` code is logged. A failed service token request that
/// reached the endpoint is counted here; [`TokenRequestOutcome::Success`] is counted by the
/// caller that also checks the granted scopes.
async fn request_token(
    provider: &CredentialProvider,
    endpoint: &str,
    params: &[(&str, &str)],
    authorization: Option<&str>,
    refresh: bool,
    egress: &TokenEgress,
) -> Result<Option<OAuthTokenResponse>> {
    let started = tokio::time::Instant::now();
    let (client, url) = tokio::time::timeout(egress.timeout, egress.pinned_client(endpoint))
        .await
        .map_err(|_| TokenPostFailure::TimedOut)??;
    let remaining = egress
        .timeout
        .saturating_sub(started.elapsed());
    let answer = match post_token_request_within(&client, url.as_str(), params, authorization, remaining).await {
        Ok(answer) => answer,
        Err(failure) => {
            if !refresh {
                record_token_request(provider, failure.outcome());
            }
            return Err(failure.into());
        }
    };
    let refused = !answer.status.is_success();
    let result = read_token_answer(provider, answer, refresh);
    if !refresh && result.is_err() {
        record_token_request(
            provider,
            if refused {
                TokenRequestOutcome::Refused
            } else {
                TokenRequestOutcome::InvalidResponse
            },
        );
    }
    result
}

fn read_token_answer(
    provider: &CredentialProvider,
    TokenEndpointAnswer { status, body: bytes }: TokenEndpointAnswer,
    refresh: bool,
) -> Result<Option<OAuthTokenResponse>> {
    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            reason = %token_error_code(&String::from_utf8_lossy(&bytes)),
            client_authentication = provider
                .jwt
                .client_authentication_method()
                .map_or("unset", GrantClientAuthentication::as_str),
            "Provider token request rejected"
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).context("Invalid provider token response")?;
    if refresh
        && status == reqwest::StatusCode::BAD_REQUEST
        && value
            .get("error")
            .and_then(serde_json::Value::as_str)
            == Some("invalid_grant")
    {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(
            match value
                .get("error")
                .and_then(serde_json::Value::as_str)
            {
                Some(error) => anyhow::Error::new(TokenRequestRejected {
                    code: OAuthErrorCode::new(error),
                }),
                None => anyhow!("Provider token request rejected"),
            },
        );
    }
    let response: OAuthTokenResponse = serde_json::from_value(value).context("Invalid provider token response")?;
    anyhow::ensure!(
        !response
            .access_token
            .is_empty()
            && response
                .token_type
                .eq_ignore_ascii_case("Bearer")
            && response
                .expires_in
                .is_some_and(|seconds| seconds > 0 && seconds <= 366 * 86400)
            && response
                .refresh_token
                .as_deref()
                .is_none_or(|token| !token.is_empty()),
        "Invalid provider token credential"
    );
    Ok(Some(response))
}

/// Build a consent-required payload for protocol-aware signaling
#[allow(dead_code)]
pub fn build_consent_required(
    provider: &CredentialProvider,
    authorization_url: &str,
    scopes: &[String],
) -> ConsentRequired {
    ConsentRequired {
        provider_id: provider.provider_id.clone(),
        provider_name: provider.name.clone(),
        authorization_url: authorization_url.to_string(),
        scopes: scopes.to_vec(),
        message: format!("{} authorization is required to access resources on your behalf.", provider.name),
    }
}

/// Build and sign a DelegationCredential VC using the gateway's Ed25519 key.
///
/// Produces a W3C VC v2 credential with an EdDsaRdfc2022 Data Integrity Proof
/// when a `vc_signer` is provided. Falls back to an unsigned VC if no signer
/// is available (e.g. during tests or degraded mode).
pub async fn build_delegation_vc(
    gateway_did: &str,
    agent_did: &str,
    user_identity_hash: &str,
    provider: &CredentialProvider,
    scopes: &[String],
    vc_signer: Option<&Arc<dyn VcSigner>>,
) -> Result<serde_json::Value> {
    let now = Utc::now();
    let vc_id = format!("urn:uuid:{}", Uuid::new_v4());

    let credential = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://fabric.affinidi.io/credentials/delegation/v1"
        ],
        "type": ["VerifiableCredential", "DelegationCredential"],
        "id": vc_id,
        "issuer": gateway_did,
        "validFrom": now.to_rfc3339(),
        "credentialSubject": {
            "id": agent_did,
            "delegationType": "oauth2_on_behalf_of",
            "delegatedBy": {
                "identityHash": user_identity_hash,
                "claimSource": "jwt_bearer"
            },
            "resource": {
                "providerId": provider.provider_id,
                "providerName": provider.name,
                "scopes": scopes
            },
            "consentedAt": now.to_rfc3339()
        }
    });

    match vc_signer {
        Some(signer) => signer
            .sign(credential)
            .await
            .context("Failed to sign DelegationCredential VC"),
        None => {
            warn!(
                target: "credential_delegation",
                "No VC signer available — DelegationCredential will be unsigned"
            );
            Ok(credential)
        }
    }
}

/// Resolve an API key directly from the secrets store (no OAuth flow)
pub async fn resolve_api_key(
    provider: &CredentialProvider,
    secrets_store: &Arc<dyn SecretsStore>,
    mode: RuleMode,
) -> Result<String> {
    let secret_ref = provider
        .api_key_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("API key provider '{}' has no api_key_secret_ref", provider.provider_id))?;
    resolve_secret(provider, secrets_store, secret_ref, mode)
        .await
        .context("Failed to resolve API key secret")
}

/// Generate a PKCE code_verifier (RFC 7636 §4.1)
/// 128 bytes of random data, base64url-encoded (no padding), resulting in a 43-128 char string
pub(super) fn generate_pkce_verifier() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32)
        .map(|_| rng.random::<u8>())
        .collect();
    base64_url_encode_bytes(&bytes)
}

/// Generate a PKCE code_challenge from a code_verifier (RFC 7636 §4.2)
/// code_challenge = BASE64URL(SHA256(code_verifier))
pub(super) fn generate_pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64_url_encode_bytes(&digest)
}

/// Marks a state sealed with the OAuth state key rather than the at-rest key.
const SEALED_STATE_PREFIX: &str = "SEALED.";

/// Derivation label, and AES-GCM associated data, for the OAuth state key.
const OAUTH_STATE_KEY_LABEL: &[u8] = b"agent-gateway/oauth-state/v1";

/// How long a used state nonce is remembered: longer than a state lives.
const USED_STATE_NONCE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

static USED_STATE_NONCES: std::sync::LazyLock<moka::future::Cache<String, ()>> = std::sync::LazyLock::new(|| {
    moka::future::Cache::builder()
        .max_capacity(100_000)
        .time_to_live(USED_STATE_NONCE_TTL)
        .build()
});

/// Encode the OAuth state parameter, always sealed so the callback can trust it.
///
/// The state is serialized to JSON, sealed with AES-256-GCM and base64url-encoded
/// for embedding in the authorization URL, so neither the OAuth provider nor any
/// intermediary can read it (agent_did, user_identity_hash, surface_id, the PKCE
/// code_verifier, etc.) or forge one. The at-rest encryption service seals it when
/// enabled; otherwise a key derived from the identity hash pepper does, which
/// gateways sharing `AG_IDENTITY_HASH_PEPPER` share.
pub(super) fn encode_oauth_state(state: &OAuthState) -> Result<String> {
    encode_oauth_state_with(state, crate::encryption::global::get_encryption_service())
}

fn encode_oauth_state_with(
    state: &OAuthState,
    encryption: Option<crate::encryption::EncryptionService>,
) -> Result<String> {
    let state_json = serde_json::to_string(state).context("Failed to serialize OAuth state")?;

    let payload = match encryption {
        Some(enc) if enc.is_enabled() => enc
            .encrypt_string(state_json)
            .context("Failed to encrypt OAuth state")?,
        _ => {
            let sealed = crate::encryption::aes_gcm::AesGcmEncryptor::new()
                .encrypt_with_aad(&oauth_state_key(), state_json.as_bytes(), OAUTH_STATE_KEY_LABEL)
                .map_err(|e| anyhow!("Failed to seal OAuth state: {e}"))?;
            format!("{SEALED_STATE_PREFIX}{}", base64_url_encode_bytes(&sealed))
        }
    };

    Ok(base64_url_encode(&payload))
}

fn oauth_state_key() -> [u8; 32] {
    crate::identity::credential_identity::derived_key(OAUTH_STATE_KEY_LABEL)
}

/// Decode and validate the OAuth state parameter.
///
/// Reverses `encode_oauth_state`: base64url-decode, open the seal, then parse JSON and
/// check expiry. A state this gateway did not seal is rejected, so it cannot be forged.
pub fn decode_oauth_state(encoded: &str) -> Result<OAuthState> {
    decode_oauth_state_with(encoded, crate::encryption::global::get_encryption_service())
}

fn decode_oauth_state_with(
    encoded: &str,
    encryption: Option<crate::encryption::EncryptionService>,
) -> Result<OAuthState> {
    let decoded_bytes = base64_url_decode(encoded).context("Failed to base64url decode state")?;
    let decoded_str = String::from_utf8(decoded_bytes).context("OAuth state is not valid UTF-8")?;

    let state_json = if decoded_str.starts_with("ENC[") {
        match encryption {
            Some(enc) => enc
                .decrypt_string(decoded_str)
                .context("Failed to decrypt OAuth state — key may have rotated")?,
            None => return Err(anyhow!("OAuth state is encrypted but encryption service is not available")),
        }
    } else if let Some(sealed) = decoded_str.strip_prefix(SEALED_STATE_PREFIX) {
        let sealed = base64_url_decode(sealed).context("Failed to base64url decode sealed OAuth state")?;
        let opened = crate::encryption::aes_gcm::AesGcmEncryptor::new()
            .decrypt_with_aad(&oauth_state_key(), &sealed, OAUTH_STATE_KEY_LABEL)
            .map_err(|_| anyhow!("OAuth state was not issued by this gateway"))?;
        String::from_utf8(opened).context("OAuth state is not valid UTF-8")?
    } else {
        return Err(anyhow!("OAuth state is not sealed — unsealed state is not accepted"));
    };

    let state: OAuthState = serde_json::from_str(&state_json).context("Failed to parse OAuth state JSON")?;

    // Check expiry
    if Utc::now() > state.expires_at {
        return Err(anyhow!("OAuth state has expired"));
    }

    Ok(state)
}

/// Mark a decoded state's nonce as used, so each state completes one callback.
///
/// Returns `false` when the nonce was already used. Remembered per process.
pub async fn claim_oauth_state(state: &OAuthState) -> bool {
    USED_STATE_NONCES
        .entry(state.nonce.clone())
        .or_insert(())
        .await
        .is_fresh()
}

/// Whether `state`'s nonce was already claimed on this process.
#[cfg(test)]
pub(crate) async fn is_claimed(state: &OAuthState) -> bool {
    USED_STATE_NONCES.contains_key(&state.nonce)
}

/// Why a provider's secret could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderSecretError {
    #[error("provider secret not found")]
    NotFound,
    #[error("provider secret belongs to another tenant")]
    OutsideTenant,
    #[error("provider secret store unavailable")]
    Store,
}

/// Resolve a provider's secret value by secret_id, with one lookup by that id. The secret must
/// belong to the provider's own tenant; under `mode` `warn` a secret outside it is still read,
/// with a warning.
pub(super) async fn resolve_secret(
    provider: &CredentialProvider,
    secrets_store: &Arc<dyn SecretsStore>,
    secret_ref: &str,
    mode: RuleMode,
) -> Result<String, ProviderSecretError> {
    let secret = secrets_store
        .get_by_secret_id(secret_ref)
        .await
        .map_err(|_| ProviderSecretError::Store)?
        .ok_or(ProviderSecretError::NotFound)?;
    if provider.secret_is_outside_tenant(secret.tenant_id.as_deref()) {
        if mode.is_enforced() {
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Refusing a credential provider secret outside the provider's tenant");
            return Err(ProviderSecretError::OutsideTenant);
        }
        warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Using a credential provider secret outside the provider's tenant");
    }
    Ok(secret.value)
}

/// The tenant isolation mode of the running process.
pub fn isolation_mode() -> RuleMode {
    credential_policy().tenant_credential_isolation
}

fn base64_url_encode(data: &str) -> String {
    base64_url_encode_bytes(data.as_bytes())
}

fn base64_url_encode_bytes(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(encoded: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("base64url decode failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn init_test_encryption() {
        // The test encryption service lives in a thread-local (test builds), so it must be
        // initialized on every test's own thread — a `std::sync::Once` would only set it on the
        // single winning thread and leave sibling tests without a service.
        let config = crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        };
        crate::encryption::global::init_global_encryption(config).expect("failed to init test encryption");
    }

    #[test]
    fn test_encode_decode_oauth_state_roundtrip_encrypted() {
        init_test_encryption();
        let state = OAuthState {
            max_consent_age_secs: None,
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: "sha256:abc123".to_string(),
            surface_id: "ch-test-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-42".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: None,
            scopes: Vec::new(),
            browser_binding: None,
        };

        let encoded = encode_oauth_state(&state).expect("encode should succeed");
        assert!(!encoded.is_empty(), "Encoded state should not be empty");

        let decoded = decode_oauth_state(&encoded).expect("decode should succeed");
        assert_eq!(decoded.agent_did, "did:web:agent.example.com");
        assert_eq!(decoded.user_identity_hash, "sha256:abc123");
        assert_eq!(decoded.surface_id, "ch-test-1");
        assert_eq!(decoded.credential_provider_id, "cp-1");
        assert_eq!(decoded.provider_id, "github");
        assert_eq!(decoded.nonce, "nonce-42");
    }

    #[test]
    fn test_decode_oauth_state_rejects_expired() {
        init_test_encryption();
        let state = OAuthState {
            max_consent_age_secs: None,
            agent_did: "did:web:agent".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce".to_string(),
            expires_at: Utc::now() - Duration::minutes(1), // already expired
            code_verifier: None,
            scopes: Vec::new(),
            browser_binding: None,
        };

        let encoded = encode_oauth_state(&state).expect("encode should succeed");
        let result = decode_oauth_state(&encoded);
        assert!(result.is_err(), "Expired state should be rejected");
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(err_msg.contains("expired"), "Error should mention expiry, got: {}", err_msg);
    }

    fn consent_provider() -> CredentialProvider {
        serde_json::from_value(json!({
            "id": "cp-1", "name": "GitHub", "provider_id": "github",
            "authorization_endpoint": "https://github.com/login/oauth/authorize?allow_signup=false",
            "default_scopes": ["repo"], "callback_path": "/v1/identity/oauth/callback/github",
            "additional_params": {"prompt": "consent"},
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    #[test]
    fn the_vendor_url_carries_the_gateways_parameters_once_after_the_endpoints_own() {
        let url = vendor_authorization_url(
            &consent_provider(),
            "client",
            "https://gw.example/v1/identity/oauth/callback/github",
            &["repo".to_string(), "read:user".to_string()],
            "sealed",
            "challenge",
        )
        .unwrap();
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .into_owned()
            .collect();
        let expected: Vec<(String, String)> = [
            ("allow_signup", "false"),
            ("response_type", "code"),
            ("client_id", "client"),
            ("redirect_uri", "https://gw.example/v1/identity/oauth/callback/github"),
            ("scope", "repo read:user"),
            ("state", "sealed"),
            ("code_challenge", "challenge"),
            ("code_challenge_method", "S256"),
            ("prompt", "consent"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
        assert_eq!(pairs, expected);
        assert_eq!(
            url.origin()
                .ascii_serialization(),
            "https://github.com"
        );
    }

    #[test]
    fn the_vendor_url_refuses_an_unsafe_endpoint_and_reserved_or_oversized_parameters() {
        let build = |provider: &CredentialProvider| {
            vendor_authorization_url(provider, "client", "https://gw.example/cb", &[], "sealed", "challenge")
        };
        for endpoint in [
            "http://github.com/login/oauth/authorize",
            "https://user:pass@github.com/authorize",
            "https://github.com/authorize#fragment",
            "https://github.com/authorize?state=forged",
            "https://github.com/authorize?a=1&a=2",
            "not a url",
        ] {
            let mut provider = consent_provider();
            provider.authorization_endpoint = Some(endpoint.to_string());
            assert!(build(&provider).is_err(), "{endpoint}");
        }
        for (name, value) in [
            ("redirect_uri", "https://attacker.example".to_string()),
            ("code_challenge", "x".to_string()),
            ("allow_signup", "true".to_string()),
            ("long", "v".repeat(2049)),
            (&"n".repeat(129), "v".to_string()),
        ] {
            let mut provider = consent_provider();
            provider
                .additional_params
                .insert(name.to_string(), value);
            assert!(build(&provider).is_err(), "{name}");
        }
        let mut provider = consent_provider();
        provider.additional_params = (0..32)
            .map(|index| (format!("p{index}"), "v".to_string()))
            .collect();
        assert!(build(&provider).is_err(), "33 parameters with the endpoint's own");
        provider
            .additional_params
            .remove("p0");
        assert!(build(&provider).is_ok(), "32 parameters");
        let mut provider = consent_provider();
        provider.authorization_endpoint = None;
        assert!(build(&provider).is_err());
    }

    #[test]
    fn the_consent_url_is_the_gateways_start_page_with_a_start_state() {
        let mut provider = consent_provider();
        provider.callback_url = Some("https://gw.example/prefix/v1/identity/oauth/callback/github".to_string());
        let url = url::Url::parse(
            &build_authorization_url(
                &provider,
                "did:web:agent",
                "sha256:user",
                "surface",
                &[],
                "https://ignored.example",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            url.origin()
                .ascii_serialization(),
            "https://gw.example"
        );
        assert_eq!(url.path(), "/prefix/v1/identity/oauth/callback/github/start");
        let state = url
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let start = decode_start_state(&state).unwrap();
        assert_eq!(start.scopes, ["repo"]);
        assert_eq!((start.code_verifier, start.browser_binding), (None, None));
        assert!(decode_callback_state(&state).is_err(), "a start state is not a callback state");

        provider.callback_url = Some("http://gw.example/prefix/v1/identity/oauth/callback/github".to_string());
        assert!(
            build_authorization_url(
                &provider,
                "did:web:agent",
                "sha256:user",
                "surface",
                &[],
                "https://gw.example",
                None
            )
            .is_err()
        );
    }

    #[test]
    fn each_consent_stage_decodes_only_its_own_state() {
        let start = OAuthState {
            nonce: uuid::Uuid::new_v4().to_string(),
            code_verifier: None,
            ..sample_state()
        };
        let older = sample_state();
        let callback = OAuthState {
            browser_binding: Some(base64_url_encode_bytes(&Sha256::digest([1u8; 32]))),
            ..sample_state()
        };
        let binding_only = OAuthState {
            code_verifier: None,
            ..callback.clone()
        };
        let [start, older, callback, binding_only] =
            [start, older, callback, binding_only].map(|state| encode_oauth_state(&state).unwrap());
        assert!(decode_start_state(&start).is_ok());
        assert!(decode_callback_state(&callback).is_ok());
        for refused in [&older, &callback, &binding_only] {
            assert!(decode_start_state(refused).is_err());
        }
        for refused in [&start, &older, &binding_only] {
            assert!(decode_callback_state(refused).is_err());
        }
    }

    #[test]
    fn only_the_browsers_own_binding_bytes_match_their_state() {
        let bytes = [7u8; 32];
        let state = OAuthState {
            browser_binding: Some(base64_url_encode_bytes(&Sha256::digest(bytes))),
            ..sample_state()
        };
        let cookie = base64_url_encode_bytes(&bytes);
        assert!(browser_binding_matches(&state, Some(cookie.as_str())));
        let other = base64_url_encode_bytes(&[8u8; 32]);
        let hash_itself = state
            .browser_binding
            .clone()
            .unwrap();
        let short = base64_url_encode_bytes(&bytes[..16]);
        for refused in [other.as_str(), hash_itself.as_str(), short.as_str(), "", "!!"] {
            assert!(!browser_binding_matches(&state, Some(refused)), "{refused}");
        }
        assert!(!browser_binding_matches(&state, None));
        assert!(!browser_binding_matches(&sample_state(), Some(cookie.as_str())), "a state without a binding");
        assert_eq!(binding_cookie_name(&state).unwrap(), format!("__Host-ag_consent_{}", &hash_itself[..16]));
        assert_eq!(binding_cookie_name(&sample_state()), None);
    }

    #[test]
    fn test_decode_oauth_state_rejects_garbage() {
        let result = decode_oauth_state("not-valid-base64-!!!!");
        assert!(result.is_err(), "Garbage input should fail");
    }

    fn sample_state() -> OAuthState {
        OAuthState {
            max_consent_age_secs: None,
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: "sha256:abc123".to_string(),
            surface_id: "ch-test-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-42".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: Some("pkce-verifier".to_string()),
            scopes: Vec::new(),
            browser_binding: None,
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_when_encryption_disabled() {
        let disabled = crate::encryption::EncryptionService::disabled();
        let state = sample_state();

        let encoded = encode_oauth_state_with(&state, Some(disabled.clone())).expect("encode should succeed");
        // Disabled encryption still seals the state, so it neither reveals nor
        // accepts its contents in the clear.
        let decoded_str = String::from_utf8(base64_url_decode(&encoded).expect("base64url decode")).expect("utf8");
        assert!(decoded_str.starts_with(SEALED_STATE_PREFIX), "Disabled encryption must emit sealed state");
        assert!(!decoded_str.contains("pkce-verifier"), "The sealed state reveals the PKCE verifier");

        let decoded = decode_oauth_state_with(&encoded, Some(disabled)).expect("decode should succeed");
        assert_eq!(decoded.agent_did, state.agent_did);
        assert_eq!(decoded.surface_id, state.surface_id);
        assert_eq!(
            decoded
                .code_verifier
                .as_deref(),
            Some("pkce-verifier")
        );
    }

    /// A state written by anyone but this gateway is refused, whatever the
    /// at-rest encryption setting: plaintext JSON, or a seal under another key.
    #[test]
    fn a_state_the_gateway_never_issued_is_refused() {
        let state = sample_state();
        let plaintext = base64_url_encode(&serde_json::to_string(&state).unwrap());
        let foreign_seal = crate::encryption::aes_gcm::AesGcmEncryptor::new()
            .encrypt_with_aad(
                &[7u8; 32],
                serde_json::to_string(&state)
                    .unwrap()
                    .as_bytes(),
                OAUTH_STATE_KEY_LABEL,
            )
            .unwrap();
        let foreign = base64_url_encode(&format!("{SEALED_STATE_PREFIX}{}", base64_url_encode_bytes(&foreign_seal)));
        for forged in [plaintext, foreign] {
            for encryption in [None, Some(crate::encryption::EncryptionService::disabled())] {
                assert!(decode_oauth_state_with(&forged, encryption).is_err(), "a forged state was accepted");
            }
        }
    }

    #[tokio::test]
    async fn a_state_completes_only_one_callback() {
        let mut state = sample_state();
        state.nonce = uuid::Uuid::new_v4().to_string();
        assert!(claim_oauth_state(&state).await, "a fresh state was refused");
        assert!(!claim_oauth_state(&state).await, "a used state was accepted again");
    }

    #[test]
    fn test_decode_rejects_plaintext_when_encryption_enabled() {
        init_test_encryption();
        let enabled = crate::encryption::global::get_encryption_service()
            .expect("global encryption service should be initialized");
        assert!(enabled.is_enabled(), "test encryption service must be enabled");

        // Encode as plaintext (as a forged state would be)...
        let state = sample_state();
        let plaintext_encoded = base64_url_encode(&serde_json::to_string(&state).unwrap());

        // ...then attempt to decode it against an enabled encryption service.
        let result = decode_oauth_state_with(&plaintext_encoded, Some(enabled));
        assert!(result.is_err(), "Plaintext state must be rejected when encryption is enabled");
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(err_msg.contains("not sealed"), "Error should explain plaintext rejection, got: {}", err_msg);
    }

    #[test]
    fn token_error_code_keeps_only_the_oauth_error_code() {
        let json_body = r#"{"error":"invalid_grant","error_description":"Code expired description-marker","error_uri":"https://idp.example/uri-marker","refresh_token":"rt-secret-marker"}"#;
        let form_body = "error=invalid_client&error_description=description-marker&client_secret=cs-secret-marker";

        assert_eq!(token_error_code(json_body), "invalid_grant");
        assert_eq!(token_error_code(form_body), "invalid_client");
        assert_eq!(token_error_code(r#"{"error":"vendor code 7!"}"#), "vendor code 7!");
    }

    #[test]
    fn an_oauth_error_code_keeps_only_a_registered_code() {
        for code in REGISTERED_OAUTH_ERRORS {
            assert_eq!(OAuthErrorCode::new(code).as_str(), code);
            assert_eq!(OAuthErrorCode::new(code).to_string(), code);
        }
        for code in [
            "",
            "INVALID_CLIENT",
            "invalid_client ",
            "client-id-12345",
            "vendor code 7!",
            UNRECOGNIZED_ERROR,
            "line\nbreak",
            &"e".repeat(65),
        ] {
            assert_eq!(OAuthErrorCode::new(code).as_str(), "other", "{code:?}");
        }
        assert_eq!(OAuthErrorCode::new("invalid_grant"), OAuthErrorCode::new("invalid_grant"));
        assert_ne!(OAuthErrorCode::new("invalid_grant"), OAuthErrorCode::new("invalid_client"));
    }

    #[test]
    fn token_error_code_refuses_a_missing_or_invalid_code() {
        let longest = "e".repeat(64);
        assert_eq!(token_error_code(&format!(r#"{{"error":"{longest}"}}"#)), longest);
        for body in [
            "<html>upstream echoed token-secret-marker</html>".to_string(),
            r#"{"error":{"code":"nested-secret-marker"}}"#.to_string(),
            r#"{"error_description":"description-marker"}"#.to_string(),
            r#"{"error":""}"#.to_string(),
            r#"{"error":"bad\"quote"}"#.to_string(),
            r#"{"error":"back\\slash"}"#.to_string(),
            r#"{"error":"line\nbreak"}"#.to_string(),
            r#"{"error":"non_ascii_\u00e9"}"#.to_string(),
            format!(r#"{{"error":"{}"}}"#, "e".repeat(65)),
        ] {
            assert_eq!(token_error_code(&body), UNRECOGNIZED_ERROR, "{body}");
        }
    }

    async fn secrets_with_tenants() -> (tempfile::TempDir, Arc<dyn SecretsStore>) {
        init_test_encryption();
        let directory = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new(
                directory
                    .path()
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        for (secret_id, tenant_id) in [("WIDE", None), ("OWN", Some("tenant-a")), ("OTHER", Some("tenant-b"))] {
            secrets
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: tenant_id.map(String::from),
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: format!("value-{secret_id}"),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        (directory, secrets)
    }

    fn tenant_provider(tenant_id: Option<&str>) -> CredentialProvider {
        serde_json::from_value(json!({
            "id": "cp", "name": "Provider", "provider_id": "provider", "tenant_id": tenant_id,
            "provider_type": "api_key", "api_key_secret_ref": "OWN",
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }))
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_secret_must_belong_to_the_provider_tenant_when_enforced() {
        let (_directory, secrets) = secrets_with_tenants().await;
        let tenant = tenant_provider(Some("tenant-a"));
        let wide = tenant_provider(None);
        let read = |provider: &CredentialProvider, secret_ref: &'static str| {
            let secrets = secrets.clone();
            let provider = provider.clone();
            async move { resolve_secret(&provider, &secrets, secret_ref, RuleMode::Enforce).await }
        };
        assert_eq!(
            read(&tenant, "OWN")
                .await
                .as_deref(),
            Ok("value-OWN")
        );
        assert_eq!(
            read(&wide, "WIDE")
                .await
                .as_deref(),
            Ok("value-WIDE")
        );
        assert_eq!(read(&tenant, "WIDE").await, Err(ProviderSecretError::OutsideTenant));
        assert_eq!(read(&tenant, "OTHER").await, Err(ProviderSecretError::OutsideTenant));
        assert_eq!(read(&wide, "OWN").await, Err(ProviderSecretError::OutsideTenant));
        assert_eq!(read(&tenant, "MISSING").await, Err(ProviderSecretError::NotFound));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_secret_outside_the_tenant_is_still_read_in_warn_mode() {
        let (_directory, secrets) = secrets_with_tenants().await;
        let tenant = tenant_provider(Some("tenant-a"));
        for secret_ref in ["WIDE", "OTHER", "OWN"] {
            assert_eq!(
                resolve_secret(&tenant, &secrets, secret_ref, RuleMode::Warn)
                    .await
                    .unwrap(),
                format!("value-{secret_ref}")
            );
        }
        assert_eq!(
            resolve_secret(&tenant, &secrets, "MISSING", RuleMode::Warn).await,
            Err(ProviderSecretError::NotFound)
        );
        assert_eq!(
            resolve_api_key(&tenant, &secrets, RuleMode::Enforce)
                .await
                .unwrap(),
            "value-OWN"
        );
        let mut crossing = tenant.clone();
        crossing.api_key_secret_ref = Some("WIDE".into());
        assert!(
            resolve_api_key(&crossing, &secrets, RuleMode::Enforce)
                .await
                .is_err()
        );
        assert_eq!(
            resolve_api_key(&crossing, &secrets, RuleMode::Warn)
                .await
                .unwrap(),
            "value-WIDE"
        );
    }

    mod jwt_grants {
        use super::super::*;
        use crate::delegation_vault::jwt_assertion::test_keys;
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
        use serde_json::{Value, json};
        use std::collections::HashMap;

        struct TokenEndpoint {
            url: String,
            egress: TokenEgress,
            requests: tokio::sync::mpsc::Receiver<HashMap<String, String>>,
            authorizations: tokio::sync::mpsc::UnboundedReceiver<Option<String>>,
            _server: tokio::task::JoinSet<()>,
        }

        async fn token_endpoint(
            status: u16,
            body: Value,
        ) -> TokenEndpoint {
            let (sender, requests) = tokio::sync::mpsc::channel(4);
            let (authorization_sender, authorizations) = tokio::sync::mpsc::unbounded_channel();
            let app = axum::Router::new().fallback(axum::routing::post(
                move |headers: axum::http::HeaderMap, axum::Form(form): axum::Form<HashMap<String, String>>| {
                    let sender = sender.clone();
                    let authorization_sender = authorization_sender.clone();
                    let body = body.clone();
                    async move {
                        authorization_sender
                            .send(
                                headers
                                    .get(axum::http::header::AUTHORIZATION)
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_string),
                            )
                            .ok();
                        sender
                            .send(form)
                            .await
                            .unwrap();
                        (axum::http::StatusCode::from_u16(status).unwrap(), axum::Json(body))
                    }
                },
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let url = format!("http://{}/token", listener.local_addr().unwrap());
            let mut server = tokio::task::JoinSet::new();
            server.spawn(async move {
                axum::serve(listener, app)
                    .await
                    .unwrap();
            });
            TokenEndpoint {
                egress: TokenEgress {
                    timeout: std::time::Duration::from_secs(5),
                    exact_allowlist: Some(url.clone()),
                    policy: Default::default(),
                },
                url,
                requests,
                authorizations,
                _server: server,
            }
        }

        struct Fixture {
            secrets: Arc<dyn SecretsStore>,
            key: test_keys::TestKey,
            certificate: String,
            _directory: tempfile::TempDir,
        }

        async fn fixture() -> Fixture {
            let directory = tempfile::tempdir().unwrap();
            let secrets: Arc<dyn SecretsStore> = Arc::new(
                crate::secrets::FilesystemSecretsStore::new_async(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .await
                .unwrap(),
            );
            let key = test_keys::rsa_pkcs8();
            let certificate = test_keys::certificate_pem();
            let key_file =
                json!({"type": "service_account", "private_key_id": "file-key-id", "private_key": key.private_pem})
                    .to_string();
            for (secret_id, value) in [
                ("SIGNING_KEY", key.private_pem.as_str()),
                ("SIGNING_JSON", key_file.as_str()),
                ("CERTIFICATE", certificate.as_str()),
                ("CLIENT_ID", "client-123"),
                ("CLIENT_SECRET", "client-secret"),
            ] {
                secrets
                    .create(crate::secrets::CreateSecretRequest {
                        tenant_id: None,
                        name: secret_id.into(),
                        secret_id: secret_id.into(),
                        description: None,
                        value: value.into(),
                        secret_type: "General".into(),
                        tags: vec![],
                    })
                    .await
                    .unwrap();
            }
            Fixture {
                secrets,
                key,
                certificate,
                _directory: directory,
            }
        }

        fn provider(
            token_endpoint: &str,
            body: Value,
        ) -> CredentialProvider {
            let mut value = json!({
                "id": "cp", "name": "Provider", "provider_id": "provider",
                "token_endpoint": token_endpoint, "callback_path": "/v1/identity/oauth/callback/provider",
                "jwt_signing_key_secret_ref": "SIGNING_KEY",
                "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
            });
            value
                .as_object_mut()
                .unwrap()
                .extend(
                    body.as_object()
                        .unwrap()
                        .clone(),
                );
            serde_json::from_value(value).unwrap()
        }

        fn claims(
            assertion: &str,
            public_pem: &str,
            algorithm: Algorithm,
            audience: &str,
        ) -> Value {
            let mut validation = Validation::new(algorithm);
            validation.set_audience(&[audience]);
            decode::<Value>(assertion, &DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap(), &validation)
                .unwrap()
                .claims
        }

        fn issued() -> Value {
            json!({"access_token": "issued-access", "token_type": "bearer", "expires_in": 3599})
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_jwt_bearer_grant_posts_only_the_signed_assertion() {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(
                &endpoint.url,
                json!({
                "provider_type": "oauth2_jwt_bearer",
                "jwt_issuer": "agent@project.iam.gserviceaccount.com",
                "jwt_subject": "admin@example.com",
                "jwt_key_id": "google-key-id"
                }),
            );
            let scopes = vec!["https://www.googleapis.com/auth/cloud-platform".to_string()];
            let response = fetch_jwt_bearer_token(&provider, &scopes, &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            assert_eq!(response.access_token, "issued-access");
            assert_eq!(response.expires_in, Some(3599));
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            let mut keys: Vec<_> = form
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["assertion", "grant_type"]);
            assert_eq!(form["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
            assert_eq!(
                decode_header(&form["assertion"])
                    .unwrap()
                    .kid
                    .as_deref(),
                Some("google-key-id")
            );
            let claims = claims(&form["assertion"], &fixture.key.public_pem, Algorithm::RS256, &endpoint.url);
            assert_eq!(claims["iss"], "agent@project.iam.gserviceaccount.com");
            assert_eq!(claims["sub"], "admin@example.com");
            assert!(
                claims["jti"]
                    .as_str()
                    .is_some_and(|jti| uuid::Uuid::parse_str(jti).is_ok()),
                "{claims}"
            );
            assert_eq!(claims["scope"], "https://www.googleapis.com/auth/cloud-platform");
            assert_eq!(
                claims["exp"]
                    .as_i64()
                    .unwrap()
                    - claims["iat"]
                        .as_i64()
                        .unwrap(),
                300
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_service_account_json_key_signs_with_its_private_key_id_as_kid() {
            let fixture = fixture().await;
            for (key_id, expected) in [(None, "file-key-id"), (Some("configured-id"), "configured-id")] {
                let mut endpoint = token_endpoint(200, issued()).await;
                let mut body = json!({
                    "provider_type": "oauth2_jwt_bearer",
                    "jwt_issuer": "agent@project.iam.gserviceaccount.com",
                    "jwt_signing_key_secret_ref": "SIGNING_JSON"
                });
                if let Some(key_id) = key_id {
                    body["jwt_key_id"] = key_id.into();
                }
                let provider = provider(&endpoint.url, body);
                fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                    .await
                    .unwrap();
                let form = endpoint
                    .requests
                    .recv()
                    .await
                    .unwrap();
                assert_eq!(
                    decode_header(&form["assertion"])
                        .unwrap()
                        .kid
                        .as_deref(),
                    Some(expected)
                );
                claims(&form["assertion"], &fixture.key.public_pem, Algorithm::RS256, &endpoint.url);
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_jwt_bearer_grant_sends_the_resource_only_when_configured() {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(
                &endpoint.url,
                json!({
                    "provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example",
                    "resource": "https://api.example/"
                }),
            );
            fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            assert_eq!(form["resource"], "https://api.example/");
        }

        #[test]
        fn an_authorization_header_is_marked_sensitive() {
            let request =
                with_sensitive_authorization(reqwest::Client::new().post("http://127.0.0.1/token"), "Basic abc")
                    .build()
                    .unwrap();
            let value = &request.headers()[reqwest::header::AUTHORIZATION];
            assert_eq!(value, "Basic abc");
            assert!(value.is_sensitive(), "the Authorization header is not marked sensitive");
        }

        #[test]
        #[should_panic(expected = "printable ASCII")]
        fn an_authorization_value_that_is_not_a_header_value_fails_instead_of_going_unmarked() {
            let _ = with_sensitive_authorization(reqwest::Client::new().post("http://127.0.0.1/token"), "Basic a\nb");
        }

        #[test]
        fn a_basic_credential_is_a_header_value_whatever_the_client_id_and_secret_hold() {
            let long_id = "x".repeat(4096);
            let long_secret = "é".repeat(4096);
            let cases = [
                ("", ""),
                ("client id", "p@ss:w+rd/%"),
                ("line\nbreak", "tab\tand\r\nreturn"),
                ("nul\0byte", "\u{7f}del"),
                ("ünïcödé", "日本語🔑"),
                (long_id.as_str(), long_secret.as_str()),
            ];
            for (index, (client_id, secret)) in cases.into_iter().enumerate() {
                let authorization = crate::delegation_vault::revocation::basic_authorization(client_id, secret);
                assert!(
                    reqwest::header::HeaderValue::from_str(&authorization).is_ok(),
                    "the Basic credential of case {index} is not a header value"
                );
            }
        }

        fn bearer_with_client_references(client_authentication: Option<&str>) -> Value {
            json!({
                "provider_type": "oauth2_jwt_bearer",
                "jwt_issuer": "agent@project.iam.gserviceaccount.com",
                "jwt_subject": "admin@example.com",
                "client_id_secret_ref": "CLIENT_ID",
                "client_secret_secret_ref": "CLIENT_SECRET",
                "client_authentication": client_authentication,
            })
        }

        async fn grant_sent(client_authentication: Option<&str>) -> (HashMap<String, String>, Option<String>) {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(&endpoint.url, bearer_with_client_references(client_authentication));
            fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            let authorization = endpoint
                .authorizations
                .recv()
                .await
                .unwrap();
            (form, authorization)
        }

        fn form_keys(form: &HashMap<String, String>) -> Vec<&str> {
            let mut keys: Vec<_> = form
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            keys
        }

        fn basic(
            client_id: &str,
            secret: &str,
        ) -> String {
            use base64::Engine;
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}")))
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_jwt_bearer_grant_without_a_client_authentication_sends_no_client_identity() {
            let (form, authorization) = grant_sent(None).await;
            assert_eq!(form_keys(&form), ["assertion", "grant_type"]);
            assert_eq!(authorization, None);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_grant_with_a_client_authentication_also_asks_for_its_scopes_in_the_form_body() {
            let fixture = fixture().await;
            let scopes = vec!["read".to_string(), "write".to_string()];
            for method in ["none", "client_secret_basic", "client_secret_post"] {
                let mut endpoint = token_endpoint(200, issued()).await;
                let provider = provider(&endpoint.url, bearer_with_client_references(Some(method)));
                fetch_jwt_bearer_token(&provider, &scopes, &fixture.secrets, &endpoint.egress)
                    .await
                    .unwrap();
                let form = endpoint
                    .requests
                    .recv()
                    .await
                    .unwrap();
                assert_eq!(
                    form.get("scope")
                        .map(String::as_str),
                    Some("read write"),
                    "{method}"
                );
                assert_eq!(
                    claims(&form["assertion"], &fixture.key.public_pem, Algorithm::RS256, &endpoint.url)["scope"],
                    "read write"
                );
            }
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(&endpoint.url, bearer_with_client_references(Some("none")));
            fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            assert!(
                !endpoint
                    .requests
                    .recv()
                    .await
                    .unwrap()
                    .contains_key("scope"),
                "a grant with no scopes asks for none in the form body"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_public_client_sends_its_client_id_and_no_secret() {
            let (form, authorization) = grant_sent(Some("none")).await;
            assert_eq!(form_keys(&form), ["assertion", "client_id", "grant_type"]);
            assert_eq!(form["client_id"], "client-123");
            assert_eq!(authorization, None);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn client_secret_basic_sends_http_basic_and_no_client_field_in_the_form() {
            let (form, authorization) = grant_sent(Some("client_secret_basic")).await;
            assert_eq!(form_keys(&form), ["assertion", "grant_type"]);
            assert_eq!(authorization, Some(basic("client-123", "client-secret")));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn client_secret_post_sends_the_client_id_and_secret_in_the_form() {
            let (form, authorization) = grant_sent(Some("client_secret_post")).await;
            assert_eq!(form_keys(&form), ["assertion", "client_id", "client_secret", "grant_type"]);
            assert_eq!(form["client_id"], "client-123");
            assert_eq!(form["client_secret"], "client-secret");
            assert_eq!(authorization, None);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn the_basic_credential_form_urlencodes_the_client_id_and_secret_before_joining_them() {
            let fixture = fixture().await;
            for (secret_id, value) in [("ODD_ID", "client id"), ("ODD_SECRET", "p@ss:w+rd/%")] {
                fixture
                    .secrets
                    .create(crate::secrets::CreateSecretRequest {
                        tenant_id: None,
                        name: secret_id.into(),
                        secret_id: secret_id.into(),
                        description: None,
                        value: value.into(),
                        secret_type: "General".into(),
                        tags: vec![],
                    })
                    .await
                    .unwrap();
            }
            let mut endpoint = token_endpoint(200, issued()).await;
            let mut body = bearer_with_client_references(Some("client_secret_basic"));
            body["client_id_secret_ref"] = json!("ODD_ID");
            body["client_secret_secret_ref"] = json!("ODD_SECRET");
            let provider = provider(&endpoint.url, body);
            fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            assert_eq!(
                endpoint
                    .authorizations
                    .recv()
                    .await
                    .unwrap(),
                Some(basic("client+id", "p%40ss%3Aw%2Brd%2F%25"))
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_client_authentication_without_the_references_it_needs_fails_before_any_request() {
            let fixture = fixture().await;
            for (method, reference, replacement) in [
                ("none", "client_id_secret_ref", None),
                ("client_secret_basic", "client_id_secret_ref", None),
                ("client_secret_basic", "client_secret_secret_ref", None),
                ("client_secret_post", "client_secret_secret_ref", None),
                ("none", "client_id_secret_ref", Some("NO_SUCH_SECRET")),
                ("client_secret_post", "client_secret_secret_ref", Some("NO_SUCH_SECRET")),
            ] {
                let mut endpoint = token_endpoint(200, issued()).await;
                let mut body = bearer_with_client_references(Some(method));
                match replacement {
                    Some(secret_id) => body[reference] = json!(secret_id),
                    None => {
                        body.as_object_mut()
                            .unwrap()
                            .remove(reference);
                    }
                }
                let provider = provider(&endpoint.url, body);
                let error = fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                    .await
                    .expect_err(&format!("{method} with {reference} {replacement:?} was sent"));
                let text = format!("{error:#}");
                assert!(!text.contains("client-secret"), "{text}");
                assert!(
                    endpoint
                        .requests
                        .try_recv()
                        .is_err(),
                    "{method} with {reference} {replacement:?} reached the token endpoint"
                );
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_refused_grant_never_shows_the_client_secret_or_the_basic_credential() {
            let fixture = fixture().await;
            for method in ["client_secret_basic", "client_secret_post"] {
                let endpoint = token_endpoint(
                    401,
                    json!({"error": "invalid_client", "error_description": "client-secret was not accepted"}),
                )
                .await;
                let provider = provider(&endpoint.url, bearer_with_client_references(Some(method)));
                let error = fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                    .await
                    .unwrap_err();
                let text = format!("{error:#}");
                assert!(!text.contains("client-secret"), "{method}: {text}");
                assert!(!text.contains(&basic("client-123", "client-secret")), "{method}: {text}");
                assert!(!text.contains("was not accepted"), "{method}: {text}");
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_client_credentials_grant_posts_the_resource_only_when_the_provider_sets_one() {
            let fixture = fixture().await;
            let scopes = vec!["read".to_string()];
            for (resource, expected_keys) in [
                (Some("https://api.example/"), vec!["client_id", "client_secret", "grant_type", "resource", "scope"]),
                (None, vec!["client_id", "client_secret", "grant_type", "scope"]),
            ] {
                let mut endpoint = token_endpoint(200, issued()).await;
                let mut settings = json!({
                    "provider_type": "oauth2_client_credentials",
                    "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"
                });
                if let Some(resource) = resource {
                    settings["resource"] = json!(resource);
                }
                fetch_scoped_client_credentials_token(
                    &provider(&endpoint.url, settings),
                    &scopes,
                    &fixture.secrets,
                    &endpoint.egress,
                )
                .await
                .unwrap();
                let form = endpoint
                    .requests
                    .recv()
                    .await
                    .unwrap();
                let mut keys: Vec<_> = form
                    .keys()
                    .map(String::as_str)
                    .collect();
                keys.sort_unstable();
                assert_eq!(keys, expected_keys, "resource {resource:?}");
                assert_eq!(form["grant_type"], "client_credentials");
                assert_eq!(form["client_id"], "client-123");
                assert_eq!(form["client_secret"], "client-secret");
                assert_eq!(form["scope"], "read");
                assert_eq!(
                    form.get("resource")
                        .map(String::as_str),
                    resource
                );
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_client_credentials_jwt_grant_authenticates_with_a_client_assertion() {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(
                &endpoint.url,
                json!({
                    "provider_type": "oauth2_client_credentials_jwt_auth",
                    "client_id_secret_ref": "CLIENT_ID",
                    "jwt_certificate_secret_ref": "CERTIFICATE"
                }),
            );
            let scopes = vec!["api://foundry/.default".to_string()];
            let response =
                fetch_client_credentials_jwt_auth_token(&provider, &scopes, &fixture.secrets, &endpoint.egress)
                    .await
                    .unwrap();
            assert_eq!(response.access_token, "issued-access");
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            let mut keys: Vec<_> = form
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["client_assertion", "client_assertion_type", "client_id", "grant_type", "scope"]);
            assert_eq!(form["grant_type"], "client_credentials");
            assert_eq!(form["client_id"], "client-123");
            assert_eq!(form["scope"], "api://foundry/.default");
            assert_eq!(form["client_assertion_type"], "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            let header = decode_header(&form["client_assertion"]).unwrap();
            assert_eq!(header.alg, Algorithm::PS256);
            assert_eq!(
                header.x5t_s256,
                Some(crate::delegation_vault::jwt_assertion::certificate_thumbprint(&fixture.certificate).unwrap())
            );
            let claims = claims(&form["client_assertion"], &fixture.key.public_pem, Algorithm::PS256, &endpoint.url);
            assert_eq!(claims["iss"], "client-123");
            assert_eq!(claims["sub"], "client-123");
            assert!(
                claims["jti"]
                    .as_str()
                    .is_some_and(|jti| !jti.is_empty())
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_client_assertion_without_a_certificate_names_its_key_by_kid_only() {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(
                &endpoint.url,
                json!({
                    "provider_type": "oauth2_client_credentials_jwt_auth",
                    "client_id_secret_ref": "CLIENT_ID",
                    "jwt_signing_algorithm": "RS256",
                    "jwt_key_id": "key1"
                }),
            );
            fetch_client_credentials_jwt_auth_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            let header = decode_header(&form["client_assertion"]).unwrap();
            assert_eq!(header.alg, Algorithm::RS256);
            assert_eq!(header.kid.as_deref(), Some("key1"));
            assert_eq!(header.x5t_s256, None);
            assert_eq!(
                claims(&form["client_assertion"], &fixture.key.public_pem, Algorithm::RS256, &endpoint.url)["iss"],
                "client-123"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_refused_or_incomplete_token_response_is_an_error_without_key_material() {
            let fixture = fixture().await;
            let settings = json!({"provider_type": "oauth2_jwt_bearer", "jwt_issuer": "sa@example"});
            for (status, body) in [
                (400, json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."})),
                (200, json!({"access_token": "issued-access", "token_type": "Bearer"})),
                (200, json!({"access_token": "issued-access", "token_type": "mac", "expires_in": 60})),
                (200, json!({"access_token": "", "token_type": "Bearer", "expires_in": 60})),
            ] {
                let endpoint = token_endpoint(status, body).await;
                let provider = provider(&endpoint.url, settings.clone());
                let error = fetch_jwt_bearer_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                    .await
                    .unwrap_err();
                let text = format!("{error:#}");
                assert!(!text.contains("PRIVATE KEY"), "{text}");
                assert!(!text.contains("issued-access"), "{text}");
                assert!(!text.contains("Invalid JWT Signature"), "{text}");
            }
            let endpoint = token_endpoint(200, issued()).await;
            let mut unknown_key = provider(&endpoint.url, settings);
            unknown_key
                .jwt
                .jwt_signing_key_secret_ref = Some("CERTIFICATE".into());
            let error = fetch_jwt_bearer_token(&unknown_key, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "signing key must be a PEM private key or a service account JSON key matching the signing algorithm"
            );
        }

        fn unlisted(endpoint: &TokenEndpoint) -> TokenEgress {
            TokenEgress {
                exact_allowlist: None,
                ..endpoint.egress.clone()
            }
        }

        fn refused(error: &anyhow::Error) -> bool {
            error
                .downcast_ref::<TokenEndpointRefused>()
                .is_some()
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_token_request_does_not_follow_a_redirect() {
            let fixture = fixture().await;
            let mut target = token_endpoint(200, issued()).await;
            let location = target.url.clone();
            let app = axum::Router::new().fallback(axum::routing::post(move || {
                let location = location.clone();
                async move { (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, location)]) }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let redirecting = format!("http://{}/token", listener.local_addr().unwrap());
            let mut server = tokio::task::JoinSet::new();
            server.spawn(async move {
                axum::serve(listener, app)
                    .await
                    .unwrap();
            });
            let egress = TokenEgress {
                exact_allowlist: Some(format!("{redirecting},{}", target.url)),
                ..target.egress.clone()
            };
            let provider = provider(
                &redirecting,
                json!({"provider_type": "oauth2_client_credentials",
                       "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"}),
            );
            assert!(
                fetch_scoped_client_credentials_token(&provider, &[], &fixture.secrets, &egress)
                    .await
                    .is_err()
            );
            assert!(
                target
                    .requests
                    .try_recv()
                    .is_err()
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn every_token_request_refuses_an_unlisted_loopback_endpoint_before_sending() {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let egress = unlisted(&endpoint);
            let provider = provider(
                &endpoint.url,
                json!({"provider_type": "oauth2_client_credentials", "resource": "https://api.example/",
                       "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"}),
            );
            let error = refresh_scoped_access_token(&provider, "refresh", &[], &fixture.secrets, &egress)
                .await
                .unwrap_err();
            assert!(refused(&error), "{error:#}");
            let error = refresh_access_token_with(&provider, "refresh", &fixture.secrets, &egress)
                .await
                .unwrap_err();
            assert!(refused(&error), "{error:#}");
            let error = exchange_code_for_tokens_with(
                &provider,
                "code",
                "https://203.0.113.10",
                &fixture.secrets,
                None,
                &egress,
            )
            .await
            .unwrap_err();
            assert!(refused(&error), "{error:#}");
            assert_eq!(error.to_string(), "token endpoint refused by egress policy");
            assert!(
                endpoint
                    .requests
                    .try_recv()
                    .is_err()
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn the_legacy_exchange_and_refresh_reach_an_exactly_listed_endpoint() {
            let fixture = fixture().await;
            let mut endpoint = token_endpoint(200, issued()).await;
            let provider = provider(
                &endpoint.url,
                json!({"provider_type": "oauth2_authorization_code",
                       "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"}),
            );
            let exchanged = exchange_code_for_tokens_with(
                &provider,
                "code",
                "https://203.0.113.10",
                &fixture.secrets,
                Some("verifier"),
                &endpoint.egress,
            )
            .await
            .unwrap();
            assert_eq!(exchanged.access_token, "issued-access");
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["code_verifier"], "verifier");
            let refreshed = refresh_access_token_with(&provider, "refresh", &fixture.secrets, &endpoint.egress)
                .await
                .unwrap();
            assert_eq!(refreshed.access_token, "issued-access");
            let form = endpoint
                .requests
                .recv()
                .await
                .unwrap();
            assert_eq!(form["grant_type"], "refresh_token");
            assert_eq!(form["refresh_token"], "refresh");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_refresh_reports_whether_its_endpoint_breaks_the_https_rule() {
            let fixture = fixture().await;
            let endpoint = token_endpoint(200, issued()).await;
            let provider = provider(
                &endpoint.url,
                json!({"provider_type": "oauth2_authorization_code",
                       "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"}),
            );

            let refreshed = endpoint
                .egress
                .clone()
                .scope(refresh_access_token(&provider, "refresh", &fixture.secrets))
                .await
                .unwrap();

            assert_eq!(
                refreshed
                    .response
                    .access_token,
                "issued-access"
            );
            assert!(!refreshed.insecure_endpoint, "an exactly listed endpoint meets the https rule");
        }

        #[test]
        fn an_endpoint_breaks_the_https_rule_only_when_it_is_http_and_not_listed() {
            let egress = TokenEgress {
                timeout: std::time::Duration::from_secs(5),
                exact_allowlist: Some("http://idp.test/token".into()),
                policy: std::borrow::Cow::Owned(crate::config::credential_policy::CredentialPolicyConfig {
                    insecure_token_endpoints: vec!["http://idp.internal/token".into()],
                    ..Default::default()
                }),
            };

            assert!(!egress.insecure_endpoint(None));
            assert!(!egress.insecure_endpoint(Some("https://idp.example/token")));
            assert!(!egress.insecure_endpoint(Some("http://idp.internal/token")));
            assert!(!egress.insecure_endpoint(Some("http://idp.test/token")));
            assert!(egress.insecure_endpoint(Some("http://idp.example/token")));
        }

        #[tokio::test]
        async fn a_refused_token_request_logs_and_returns_only_the_oauth_error_code() {
            let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
            let fixture = fixture().await;
            let endpoint = token_endpoint(
                400,
                json!({"error": "invalid_grant", "error_description": "description-marker",
                       "error_uri": "https://idp.example/uri-marker"}),
            )
            .await;
            let provider = provider(
                &endpoint.url,
                json!({"provider_type": "oauth2_client_credentials",
                       "client_id_secret_ref": "CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET"}),
            );
            let exchange = exchange_code_for_tokens_with(
                &provider,
                "code",
                "https://203.0.113.10",
                &fixture.secrets,
                None,
                &endpoint.egress,
            )
            .await
            .unwrap_err();
            let refresh = refresh_access_token_with(&provider, "refresh", &fixture.secrets, &endpoint.egress)
                .await
                .unwrap_err();
            let service = fetch_scoped_client_credentials_token(&provider, &[], &fixture.secrets, &endpoint.egress)
                .await
                .unwrap_err();

            assert_eq!(format!("{exchange:#}"), "Token exchange failed (HTTP 400 Bad Request): invalid_grant");
            assert_eq!(format!("{refresh:#}"), "Token refresh failed (HTTP 400 Bad Request): invalid_grant");
            assert_eq!(format!("{service:#}"), "Provider token request rejected");
            assert_eq!(
                service
                    .downcast_ref::<TokenRequestRejected>()
                    .map(|rejected| rejected.code.as_str()),
                Some("invalid_grant")
            );
            let text = logs.text();
            for message in ["Token exchange failed", "Provider token request rejected"] {
                let line = text
                    .lines()
                    .find(|line| line.contains(message))
                    .unwrap_or_else(|| panic!("{message} is logged: {text}"));
                assert!(line.contains("reason=invalid_grant"), "{line}");
            }
            for marker in ["description-marker", "uri-marker", "client-secret"] {
                assert!(!text.contains(marker), "{marker} reached the log: {text}");
            }
        }

        fn https_rule(
            token_endpoint_https: crate::config::credential_policy::RuleMode,
            exact_allowlist: Option<&str>,
            insecure_token_endpoints: &[&str],
        ) -> TokenEgress {
            TokenEgress {
                timeout: std::time::Duration::from_secs(5),
                exact_allowlist: exact_allowlist.map(str::to_string),
                policy: std::borrow::Cow::Owned(crate::config::credential_policy::CredentialPolicyConfig {
                    token_endpoint_https,
                    insecure_token_endpoints: insecure_token_endpoints
                        .iter()
                        .map(|url| url.to_string())
                        .collect(),
                    ..Default::default()
                }),
            }
        }

        #[test]
        fn only_https_or_an_exactly_listed_http_endpoint_meets_the_https_rule() {
            use crate::config::credential_policy::RuleMode;

            let egress = https_rule(
                RuleMode::Warn,
                Some("http://127.0.0.1:4000/token, http://127.0.0.1:5000"),
                &["http://idp.internal/token"],
            );
            for (endpoint, permitted) in [
                ("https://auth.example/token", true),
                (" https://auth.example/token ", true),
                ("http://127.0.0.1:4000/token", true),
                ("http://idp.internal/token", true),
                ("http://idp.internal/other", false),
                ("http://127.0.0.1:4001/token", false),
                ("http://127.0.0.1:4000/other", false),
                ("http://127.0.0.1:5000/token", false),
                ("http://auth.example/token", false),
                ("ftp://auth.example/token", false),
                ("not a url", false),
                ("", false),
            ] {
                assert_eq!(egress.permits_token_endpoint(endpoint), permitted, "{endpoint}");
            }
            assert!(
                !https_rule(RuleMode::Warn, None, &[]).permits_token_endpoint("http://127.0.0.1:4000/token"),
                "outside test mode only https meets the rule"
            );

            let warn = https_rule(RuleMode::Warn, None, &[]);
            let enforce = https_rule(RuleMode::Enforce, None, &["http://idp.internal/token"]);
            for (endpoint, warned, enforced) in [
                ("https://auth.example/token", true, true),
                ("http://idp.internal/token", true, true),
                ("http://auth.example/token", true, false),
                ("ftp://auth.example/token", false, false),
                ("not a url", false, false),
            ] {
                assert_eq!(warn.admits_token_endpoint(endpoint), warned, "warn {endpoint}");
                assert_eq!(enforce.admits_token_endpoint(endpoint), enforced, "enforce {endpoint}");
            }
            assert!(
                enforce
                    .check_token_endpoint("provider", "http://auth.example/token")
                    .is_err()
            );
            assert!(
                warn.check_token_endpoint("provider", "http://auth.example/token")
                    .is_ok()
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_http_token_endpoint_is_refused_before_any_secret_is_read_when_enforced() {
            use crate::config::credential_policy::RuleMode;

            let fixture = fixture().await;
            let provider = provider(
                "http://idp.example/token",
                json!({"provider_type": "oauth2_client_credentials", "resource": "https://api.example/",
                       "client_id_secret_ref": "UNSTORED_ID", "client_secret_secret_ref": "UNSTORED_SECRET"}),
            );
            let not_https = |error: anyhow::Error| {
                error
                    .downcast_ref::<TokenEndpointNotHttps>()
                    .is_some()
            };
            for (mode, refused) in [(RuleMode::Enforce, true), (RuleMode::Warn, false)] {
                let egress = https_rule(mode, None, &[]);
                let error = refresh_scoped_access_token(&provider, "refresh", &[], &fixture.secrets, &egress)
                    .await
                    .unwrap_err();
                assert_eq!(not_https(error), refused, "{mode:?} scoped refresh");
                let error = refresh_access_token_with(&provider, "refresh", &fixture.secrets, &egress)
                    .await
                    .unwrap_err();
                if refused {
                    assert_eq!(error.to_string(), "token_endpoint must be an https URL");
                } else {
                    assert_eq!(error.to_string(), "Failed to resolve client_id for refresh");
                }
                let error = exchange_code_for_tokens_with(
                    &provider,
                    "code",
                    "https://203.0.113.10",
                    &fixture.secrets,
                    None,
                    &egress,
                )
                .await
                .unwrap_err();
                if refused {
                    assert_eq!(error.to_string(), "token_endpoint must be an https URL");
                } else {
                    assert_eq!(error.to_string(), "Failed to resolve client_id");
                }
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_metadata_endpoint_is_refused_even_when_listed() {
            let metadata = "http://169.254.169.254/token";
            let egress = TokenEgress {
                timeout: std::time::Duration::from_secs(5),
                exact_allowlist: Some(metadata.into()),
                policy: Default::default(),
            };
            let error = egress
                .pinned_client(metadata)
                .await
                .unwrap_err();
            assert!(refused(&error), "{error:#}");
        }
    }

    #[test]
    fn test_base64_url_roundtrip() {
        let original = r#"{"agent_did":"did:web:test","nonce":"abc"}"#;
        let encoded = base64_url_encode(original);
        let decoded_bytes = base64_url_decode(&encoded).expect("decode should succeed");
        let decoded = String::from_utf8(decoded_bytes).expect("should be valid UTF-8");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_build_consent_required_format() {
        let provider = CredentialProvider {
            max_consent_age_secs: None,
            id: "cp-1".to_string(),
            tenant_id: None,
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: Some("https://github.com/login/oauth/authorize".to_string()),
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GITHUB_CLIENT_ID".to_string()),
            client_secret_secret_ref: Some("GITHUB_CLIENT_SECRET".to_string()),
            default_scopes: vec!["repo".to_string()],
            callback_path: "/oauth/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            jwt: Default::default(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
            issuer: None,
            revocation_endpoint: None,
            token_endpoint_auth_method: None,
            client_id: None,
            allow_unadvertised_pkce: false,
            authorization_response_iss_parameter_supported: None,
            authorization_response_issuer: None,
            scope_comparison: Default::default(),
            revocation_ends_authorization: false,
            send_resource: true,
        };

        let consent =
            build_consent_required(&provider, "https://github.com/authorize?state=xyz", &["repo".to_string()]);
        assert_eq!(consent.provider_id, "github");
        assert_eq!(consent.provider_name, "GitHub");
        assert!(
            consent
                .authorization_url
                .contains("github.com")
        );
        assert_eq!(consent.scopes, vec!["repo"]);
        assert!(
            consent
                .message
                .contains("GitHub")
        );
    }

    #[tokio::test]
    async fn test_build_delegation_vc_structure() {
        let provider = CredentialProvider {
            max_consent_age_secs: None,
            id: "cp-1".to_string(),
            tenant_id: None,
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: None,
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GH_ID".to_string()),
            client_secret_secret_ref: Some("GH_SECRET".to_string()),
            default_scopes: vec![],
            callback_path: "/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            jwt: Default::default(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
            issuer: None,
            revocation_endpoint: None,
            token_endpoint_auth_method: None,
            client_id: None,
            allow_unadvertised_pkce: false,
            authorization_response_iss_parameter_supported: None,
            authorization_response_issuer: None,
            scope_comparison: Default::default(),
            revocation_ends_authorization: false,
            send_resource: true,
        };

        // Test without signer (unsigned fallback)
        let vc = build_delegation_vc(
            "did:web:gateway.example.com",
            "did:web:agent.example.com",
            "sha256:user123",
            &provider,
            &["repo".to_string(), "read:user".to_string()],
            None,
        )
        .await
        .expect("build_delegation_vc should succeed without signer");

        assert_eq!(vc["issuer"], "did:web:gateway.example.com");
        assert_eq!(vc["credentialSubject"]["id"], "did:web:agent.example.com");
        assert_eq!(vc["credentialSubject"]["delegatedBy"]["identityHash"], "sha256:user123");
        assert_eq!(vc["credentialSubject"]["resource"]["providerId"], "github");

        let types = vc["type"]
            .as_array()
            .expect("type should be array");
        assert!(
            types
                .iter()
                .any(|t| t == "DelegationCredential")
        );

        // VC ID should be a UUID URN
        let id = vc["id"]
            .as_str()
            .expect("id should be string");
        assert!(id.starts_with("urn:uuid:"), "VC id should be URN UUID, got: {}", id);

        // Should use v2 context
        let contexts = vc["@context"]
            .as_array()
            .expect("@context should be array");
        assert!(
            contexts
                .iter()
                .any(|c| c == "https://www.w3.org/ns/credentials/v2"),
            "Should use W3C VC v2 context"
        );

        // Should use validFrom instead of issuanceDate
        assert!(vc.get("validFrom").is_some(), "Should have validFrom field");
        assert!(
            vc.get("issuanceDate")
                .is_none(),
            "Should not have issuanceDate field"
        );
    }

    #[test]
    fn test_pkce_verifier_length_and_charset() {
        let verifier = generate_pkce_verifier();
        // Base64url of 32 bytes = 43 chars (no padding)
        assert_eq!(verifier.len(), 43, "PKCE verifier should be 43 base64url chars");
        // Must only contain base64url chars
        assert!(
            verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "PKCE verifier must be base64url: {}",
            verifier
        );
    }

    #[test]
    fn test_pkce_challenge_is_s256_of_verifier() {
        let verifier = generate_pkce_verifier();
        let challenge = generate_pkce_challenge(&verifier);

        // Manually compute expected: SHA256(verifier) → base64url
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let expected = base64_url_encode_bytes(&hash);

        assert_eq!(challenge, expected, "Challenge should be base64url(SHA256(verifier))");
    }

    #[test]
    fn test_pkce_verifier_uniqueness() {
        let v1 = generate_pkce_verifier();
        let v2 = generate_pkce_verifier();
        assert_ne!(v1, v2, "Two verifiers should be different");
    }

    #[test]
    fn test_oauth_state_with_code_verifier_roundtrip() {
        init_test_encryption();
        let state = OAuthState {
            max_consent_age_secs: None,
            agent_did: "did:web:agent".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-pkce".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: Some("test_verifier_value_12345678901234567890".to_string()),
            scopes: Vec::new(),
            browser_binding: None,
        };
        let encoded = encode_oauth_state(&state).expect("encode should succeed");
        let decoded = decode_oauth_state(&encoded).expect("decode should succeed");
        assert_eq!(decoded.code_verifier, Some("test_verifier_value_12345678901234567890".to_string()));
    }

    #[test]
    fn test_oauth_state_without_code_verifier_roundtrip() {
        init_test_encryption();
        let state = OAuthState {
            max_consent_age_secs: None,
            agent_did: "did:web:agent".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-no-pkce".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: None,
            scopes: Vec::new(),
            browser_binding: None,
        };
        let encoded = encode_oauth_state(&state).expect("encode should succeed");
        let decoded = decode_oauth_state(&encoded).expect("decode should succeed");
        assert_eq!(decoded.code_verifier, None);
    }

    #[tokio::test]
    async fn test_build_delegation_vc_signed() {
        use crate::identity::VCIssuerConfig;
        use crate::identity::ssi::vc_issuer::LocalVcSigner;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let signing_key = crate::identity::test_helpers::test_signing_key();

        let config = Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: "did:web:gateway.example.com".to_string(),
            signing_key,
            is_vp_challenge_required: false,
        }));

        let signer: Arc<dyn VcSigner> = Arc::new(LocalVcSigner::new(config));

        let provider = CredentialProvider {
            max_consent_age_secs: None,
            id: "cp-1".to_string(),
            tenant_id: None,
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: None,
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GH_ID".to_string()),
            client_secret_secret_ref: Some("GH_SECRET".to_string()),
            default_scopes: vec![],
            callback_path: "/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            jwt: Default::default(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
            issuer: None,
            revocation_endpoint: None,
            token_endpoint_auth_method: None,
            client_id: None,
            allow_unadvertised_pkce: false,
            authorization_response_iss_parameter_supported: None,
            authorization_response_issuer: None,
            scope_comparison: Default::default(),
            revocation_ends_authorization: false,
            send_resource: true,
        };

        let vc = build_delegation_vc(
            "did:web:gateway.example.com",
            "did:web:agent.example.com",
            "sha256:user123",
            &provider,
            &["repo".to_string()],
            Some(&signer),
        )
        .await
        .expect("Signed DelegationCredential should succeed");

        // Should have a Data Integrity proof
        let proof = vc
            .get("proof")
            .expect("Signed VC should contain a proof");
        assert_eq!(proof["type"], "DataIntegrityProof", "Proof type should be DataIntegrityProof");
        assert!(
            proof
                .get("proofValue")
                .is_some(),
            "Proof should contain proofValue"
        );

        // Core VC fields should still be present
        assert_eq!(vc["issuer"], "did:web:gateway.example.com");
        assert_eq!(vc["credentialSubject"]["id"], "did:web:agent.example.com");
        assert_eq!(vc["credentialSubject"]["delegationType"], "oauth2_on_behalf_of");
    }
}
