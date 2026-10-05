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
use crate::credential_providers::CredentialProvider;
use crate::identity::ssi::vc_issuer::VcSigner;
use crate::secrets::SecretsStore;
use std::sync::Arc;

/// Build the authorization URL with resolved client_id from secrets store
pub async fn build_authorization_url(
    provider: &CredentialProvider,
    agent_did: &str,
    user_identity_hash: &str,
    channel_id: &str,
    scopes: &[String],
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<String> {
    let auth_endpoint = provider
        .authorization_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no authorization_endpoint", provider.provider_id))?;

    // Resolve client_id from secrets store
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id secret")?;

    let nonce = Uuid::new_v4().to_string();

    // Generate PKCE code_verifier (RFC 7636 §4.1: 43-128 chars, unreserved charset)
    let code_verifier = generate_pkce_verifier();
    let code_challenge = generate_pkce_challenge(&code_verifier);

    let state = OAuthState {
        agent_did: agent_did.to_string(),
        user_identity_hash: user_identity_hash.to_string(),
        surface_id: channel_id.to_string(),
        credential_provider_id: provider.id.clone(),
        provider_id: provider.provider_id.clone(),
        nonce,
        expires_at: Utc::now() + Duration::minutes(10),
        code_verifier: Some(code_verifier),
    };

    let state_encoded = encode_oauth_state(&state)?;

    let callback_url = provider
        .callback_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}{}", gateway_base_url, provider.callback_path));

    let effective_scopes = if scopes.is_empty() {
        &provider.default_scopes
    } else {
        scopes
    };
    let scope_string = effective_scopes.join(" ");

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        auth_endpoint,
        urlencoding::encode(&client_id),
        urlencoding::encode(&callback_url),
        urlencoding::encode(&scope_string),
        urlencoding::encode(&state_encoded),
        urlencoding::encode(&code_challenge),
    );

    for (key, value) in &provider.additional_params {
        url.push_str(&format!("&{}={}", urlencoding::encode(key), urlencoding::encode(value)));
    }

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        agent_did = %agent_did,
        user_hash = %user_identity_hash,
        scopes = ?effective_scopes,
        "Built OAuth authorization URL with resolved client_id"
    );

    Ok(url)
}

/// Exchange an OAuth authorization code for tokens
pub async fn exchange_code_for_tokens(
    provider: &CredentialProvider,
    code: &str,
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
    code_verifier: Option<&str>,
) -> Result<OAuthTokenResponse> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id")?;
    let client_secret = resolve_secret(secrets_store, client_secret_ref)
        .await
        .context("Failed to resolve client_secret")?;

    let callback_url = provider
        .callback_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}{}", gateway_base_url, provider.callback_path));
    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    crate::url_validation::validate_oauth_endpoint_url(token_endpoint)
        .map_err(|e| anyhow!("Blocked token_endpoint for provider '{}': {}", provider.provider_id, e))?;
    crate::url_validation::validate_oauth_endpoint_url(&callback_url)
        .map_err(|e| anyhow!("Blocked callback_url for provider '{}': {}", provider.provider_id, e))?;

    let http_client = crate::http_client::external()?;

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
        .post(token_endpoint)
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
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            body = %body,
            "Token exchange failed"
        );
        return Err(anyhow!("Token exchange failed (HTTP {}): {}", status, body));
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

/// Refresh an expired access token using a refresh token
pub async fn refresh_access_token(
    provider: &CredentialProvider,
    refresh_token: &str,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<OAuthTokenResponse> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id for refresh")?;
    let client_secret = resolve_secret(secrets_store, client_secret_ref)
        .await
        .context("Failed to resolve client_secret for refresh")?;

    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    crate::url_validation::validate_oauth_endpoint_url(token_endpoint)
        .map_err(|e| anyhow!("Blocked token_endpoint for provider '{}': {}", provider.provider_id, e))?;

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

    let http_client = crate::http_client::external()?;

    let response = http_client
        .post(token_endpoint)
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
        return Err(anyhow!("Token refresh failed (HTTP {}): {}", status, body));
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
    client: &reqwest::Client,
) -> Result<Option<OAuthTokenResponse>> {
    anyhow::ensure!(!refresh_token.is_empty() && refresh_token.len() <= 32 * 1024, "Invalid refresh credential");
    scoped_token_grant(provider, Some(refresh_token), scopes, secrets, client).await
}

pub async fn fetch_scoped_client_credentials_token(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    client: &reqwest::Client,
) -> Result<OAuthTokenResponse> {
    scoped_token_grant(provider, None, scopes, secrets, client)
        .await?
        .ok_or_else(|| anyhow!("Provider credential grant rejected"))
}

async fn scoped_token_grant(
    provider: &CredentialProvider,
    refresh_token: Option<&str>,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    client: &reqwest::Client,
) -> Result<Option<OAuthTokenResponse>> {
    let endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Missing refresh endpoint"))?;
    crate::url_validation::validate_oauth_endpoint_url(endpoint).map_err(|_| anyhow!("Invalid refresh endpoint"))?;
    let resource = provider
        .resource
        .as_deref()
        .ok_or_else(|| anyhow!("Missing refresh resource"))?;
    crate::sts::mcp_profile::canonical_https_url(resource).map_err(|_| anyhow!("Invalid refresh resource"))?;
    let client_id = resolve_secret(
        secrets,
        provider
            .client_id_secret_ref
            .as_deref()
            .ok_or_else(|| anyhow!("Missing provider client"))?,
    )
    .await?;
    let client_secret = zeroize::Zeroizing::new(
        resolve_secret(
            secrets,
            provider
                .client_secret_secret_ref
                .as_deref()
                .ok_or_else(|| anyhow!("Missing provider client secret"))?,
        )
        .await?,
    );
    let operation = async {
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
            ("resource", resource),
            ("scope", scope.as_str()),
        ];
        if let Some(refresh_token) = refresh_token {
            params.push(("refresh_token", refresh_token));
        }
        let mut response = client
            .post(endpoint)
            .header("accept", "application/json")
            .form(&params)
            .send()
            .await
            .context("Provider refresh request failed")?;
        let status = response.status();
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .context("Provider refresh response failed")?
        {
            anyhow::ensure!(
                bytes
                    .len()
                    .saturating_add(chunk.len())
                    <= 64 * 1024,
                "Provider refresh response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).context("Invalid provider refresh response")?;
        if refresh_token.is_some()
            && status == reqwest::StatusCode::BAD_REQUEST
            && value
                .get("error")
                .and_then(serde_json::Value::as_str)
                == Some("invalid_grant")
        {
            return Ok(None);
        }
        anyhow::ensure!(status.is_success(), "Provider refresh rejected");
        let response: OAuthTokenResponse =
            serde_json::from_value(value).context("Invalid provider refresh response")?;
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
            "Invalid provider refresh credential"
        );
        Ok(Some(response))
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), operation)
        .await
        .context("Provider refresh timed out")?
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

/// Fetch a token using the OAuth 2.0 Client Credentials flow (M2M, no user consent)
pub async fn fetch_client_credentials_token(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<OAuthTokenResponse> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id for client_credentials")?;
    let client_secret = resolve_secret(secrets_store, client_secret_ref)
        .await
        .context("Failed to resolve client_secret for client_credentials")?;

    crate::url_validation::validate_oauth_endpoint_url(token_endpoint)
        .map_err(|e| anyhow!("Blocked token_endpoint for provider '{}': {}", provider.provider_id, e))?;

    let scope_string = scopes.join(" ");

    let http_client = crate::http_client::external()?;

    let mut params = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    if !scope_string.is_empty() {
        params.push(("scope", scope_string));
    }

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_endpoint = %token_endpoint,
        scopes = ?scopes,
        "Fetching client_credentials token (M2M)"
    );

    let response = http_client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .context("Failed to send client_credentials token request")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read client_credentials response body")?;

    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            body = %body,
            "Client credentials token fetch failed"
        );
        return Err(anyhow!("Client credentials token fetch failed (HTTP {}): {}", status, body));
    }

    let token_response: OAuthTokenResponse =
        serde_json::from_str(&body).context("Failed to parse client_credentials token response")?;

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_type = %token_response.token_type,
        expires_in = ?token_response.expires_in,
        "Client credentials token fetch successful"
    );

    Ok(token_response)
}

/// Resolve an API key directly from the secrets store (no OAuth flow)
pub async fn resolve_api_key(
    provider: &CredentialProvider,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<String> {
    let secret_ref = provider
        .api_key_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("API key provider '{}' has no api_key_secret_ref", provider.provider_id))?;
    resolve_secret(secrets_store, secret_ref)
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

/// Resolve a secret value from the secrets store by secret_id
pub(super) async fn resolve_secret(
    secrets_store: &Arc<dyn SecretsStore>,
    secret_ref: &str,
) -> Result<String> {
    let secrets = secrets_store
        .list_all()
        .await
        .context("Failed to list secrets")?;
    let secret = secrets
        .iter()
        .find(|s| s.secret_id == secret_ref)
        .ok_or_else(|| anyhow!("Secret with secret_id '{}' not found", secret_ref))?;
    let full_secret = secrets_store
        .get(&secret.id)
        .await
        .context("Failed to get secret by id")?
        .ok_or_else(|| anyhow!("Secret '{}' disappeared during resolution", secret_ref))?;
    Ok(full_secret.value)
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
        unsafe {
            std::env::set_var("OAUTH_TEST_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        }
        let config = crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "OAUTH_TEST_ENCRYPTION_KEY".to_string(),
            ..Default::default()
        };
        crate::encryption::global::init_global_encryption(config).expect("failed to init test encryption");
    }

    #[test]
    fn test_encode_decode_oauth_state_roundtrip_encrypted() {
        init_test_encryption();
        let state = OAuthState {
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: "sha256:abc123".to_string(),
            surface_id: "ch-test-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-42".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: None,
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
            agent_did: "did:web:agent".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce".to_string(),
            expires_at: Utc::now() - Duration::minutes(1), // already expired
            code_verifier: None,
        };

        let encoded = encode_oauth_state(&state).expect("encode should succeed");
        let result = decode_oauth_state(&encoded);
        assert!(result.is_err(), "Expired state should be rejected");
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(err_msg.contains("expired"), "Error should mention expiry, got: {}", err_msg);
    }

    #[test]
    fn test_decode_oauth_state_rejects_garbage() {
        let result = decode_oauth_state("not-valid-base64-!!!!");
        assert!(result.is_err(), "Garbage input should fail");
    }

    fn sample_state() -> OAuthState {
        OAuthState {
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: "sha256:abc123".to_string(),
            surface_id: "ch-test-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-42".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: Some("pkce-verifier".to_string()),
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
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
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
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
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
            agent_did: "did:web:agent".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-pkce".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: Some("test_verifier_value_12345678901234567890".to_string()),
        };
        let encoded = encode_oauth_state(&state).expect("encode should succeed");
        let decoded = decode_oauth_state(&encoded).expect("decode should succeed");
        assert_eq!(decoded.code_verifier, Some("test_verifier_value_12345678901234567890".to_string()));
    }

    #[test]
    fn test_oauth_state_without_code_verifier_roundtrip() {
        init_test_encryption();
        let state = OAuthState {
            agent_did: "did:web:agent".to_string(),
            user_identity_hash: "sha256:user".to_string(),
            surface_id: "ch-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce-no-pkce".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            code_verifier: None,
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
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
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
