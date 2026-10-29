//! Service tokens: credentials the gateway obtains from a credential provider for itself,
//! not on a user's behalf. Delegation bindings and target authentication share this one
//! path. Static credentials are read from the secrets store on every use; tokens an
//! issuer returns are cached in the delegation vault until they expire.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::warn;

use super::{DelegationToken, VaultLookupResult, oauth, storage::DelegationVaultStorage};
use crate::credential_providers::{CredentialProvider, CredentialProviderType, storage::CredentialProviderStorage};
use crate::mcp::continuations::delegation::provider_digest;
use crate::secrets::SecretsStore;

pub struct ServiceTokenContext<'a> {
    pub secrets: &'a Arc<dyn SecretsStore>,
    pub providers: &'a dyn CredentialProviderStorage,
    pub vault: &'a dyn DelegationVaultStorage,
    /// The client for token requests; the external client when `None`.
    pub http: Option<&'a reqwest::Client>,
}

/// Where an issued token is cached: the vault row of `agent_did` and the synthetic
/// user identity `identity` for the provider.
#[derive(Debug, Clone, Copy)]
pub struct ServiceTokenKey<'a> {
    pub agent_did: &'a str,
    pub identity: &'a str,
}

pub enum ServiceToken {
    /// A static credential read from the secrets store, never cached.
    Static(zeroize::Zeroizing<String>),
    /// A token an issuer returned, from the vault cache or just fetched and stored.
    Issued { token: DelegationToken, cached: bool },
}

impl ServiceToken {
    pub fn value(&self) -> &str {
        match self {
            Self::Static(value) => value,
            Self::Issued { token, .. } => &token.access_token,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServiceTokenError {
    #[error("credential provider type issues no service token")]
    Unsupported,
    #[error("credential provider secret unavailable")]
    SecretUnavailable,
    #[error("credential provider token request failed")]
    TokenRequestFailed,
    #[error("credential provider token response has no expiry")]
    MissingExpiry,
    #[error("credential provider issued other scopes than requested")]
    ScopeMismatch,
    #[error("credential provider changed during the token request")]
    ProviderChanged,
    #[error("credential store unavailable")]
    StoreUnavailable,
}

/// The provider's service token for `scopes`: its API key, or a cached token that grants
/// them, or a new token from the provider's grant, stored under `key`.
pub async fn acquire(
    provider: &CredentialProvider,
    scopes: &[String],
    context: &ServiceTokenContext<'_>,
    key: ServiceTokenKey<'_>,
    now: DateTime<Utc>,
) -> Result<ServiceToken, ServiceTokenError> {
    if provider.provider_type == CredentialProviderType::ApiKey {
        let value = oauth::resolve_api_key(provider, context.secrets)
            .await
            .map_err(|error| {
                warn!(target: "credential_delegation", provider_id = %provider.provider_id, %error, "API key resolution failed");
                ServiceTokenError::SecretUnavailable
            })?;
        if value.is_empty() {
            return Err(ServiceTokenError::SecretUnavailable);
        }
        return Ok(ServiceToken::Static(zeroize::Zeroizing::new(value)));
    }
    if let Some(token) = cached_token(provider, scopes, context, key, now).await? {
        return Ok(ServiceToken::Issued { token, cached: true });
    }
    let client = match context.http {
        Some(client) => client.clone(),
        None => crate::http_client::external().map_err(|_| ServiceTokenError::TokenRequestFailed)?,
    };
    let response = match provider.provider_type {
        CredentialProviderType::OAuth2ClientCredentials => {
            oauth::fetch_scoped_client_credentials_token(provider, scopes, context.secrets, &client).await
        }
        CredentialProviderType::OAuth2JwtBearer => {
            oauth::fetch_jwt_bearer_token(provider, scopes, context.secrets, &client).await
        }
        CredentialProviderType::OAuth2ClientCredentialsJwtAuth => {
            oauth::fetch_client_credentials_jwt_auth_token(provider, scopes, context.secrets, &client).await
        }
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::ApiKey => {
            return Err(ServiceTokenError::Unsupported);
        }
    }
    .map_err(|error| {
        warn!(target: "credential_delegation", provider_id = %provider.provider_id, error = %format!("{error:#}"), "Service token request failed");
        ServiceTokenError::TokenRequestFailed
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
    if granted
        .iter()
        .any(|scope| !scopes.contains(scope))
        || scopes
            .iter()
            .any(|scope| !granted.contains(scope))
    {
        return Err(ServiceTokenError::ScopeMismatch);
    }
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
        .ok_or(ServiceTokenError::MissingExpiry)?;
    let token = context
        .vault
        .store(DelegationToken {
            id: uuid::Uuid::new_v4().to_string(),
            agent_did: key.agent_did.into(),
            user_identity_hash: key.identity.into(),
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
        })
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?;
    Ok(ServiceToken::Issued { token, cached: false })
}

async fn cached_token(
    provider: &CredentialProvider,
    scopes: &[String],
    context: &ServiceTokenContext<'_>,
    key: ServiceTokenKey<'_>,
    now: DateTime<Utc>,
) -> Result<Option<DelegationToken>, ServiceTokenError> {
    let VaultLookupResult::Found(token) = context
        .vault
        .lookup(key.agent_did, key.identity, &provider.id)
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?
    else {
        return Ok(None);
    };
    let usable = token.agent_did == key.agent_did
        && token.user_identity_hash == key.identity
        && token.credential_provider_id == provider.id
        && !token
            .access_token
            .is_empty()
        && token
            .token_type
            .eq_ignore_ascii_case("Bearer")
        && token
            .expires_at
            .is_some_and(|expires| expires > now)
        && scopes
            .iter()
            .all(|scope| token.scopes.contains(scope));
    Ok(usable.then_some(token))
}
