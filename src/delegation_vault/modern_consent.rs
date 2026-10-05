use std::collections::HashSet;

use axum::{
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use url::Url;

use crate::credential_providers::{CredentialProvider, CredentialProviderType};
use crate::mcp::continuations::ContinuationError;
use crate::mcp::continuations::protected::ConsentTicket;

pub mod identity;

pub const CONNECT_PATH: &str = "/mcp-consent/connect";
pub const CALLBACK_PATH: &str = "/mcp-consent/callback";

#[derive(Clone)]
pub struct ModernConsentState {
    pub vault: super::handlers::DelegationVaultState,
    pub network: std::sync::Arc<crate::config::NetworkConfig>,
    pub identity_strategies: std::sync::Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
    pub verifier: std::sync::Arc<crate::jwt_bearer::JwtBearerVerifier>,
    pub continuations: std::sync::Arc<crate::mcp::continuations::service::ContinuationService>,
    pub provider_http: reqwest::Client,
}

/// The OAuth authorization response. Providers add their own parameters
/// (`session_state`, `scope`, `authuser`, `error_uri`), which RFC 6749 §4.1.2
/// requires a client to ignore, so unknown parameters are not rejected.
#[derive(Deserialize)]
pub struct ConsentQuery {
    pub state: String,
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub iss: Option<String>,
}

pub fn router(state: ModernConsentState) -> axum::Router {
    axum::Router::new()
        .route(&format!("{CONNECT_PATH}/{{provider_id}}"), axum::routing::get(connect))
        .route(&format!("{CALLBACK_PATH}/{{provider_id}}"), axum::routing::get(callback))
        .with_state(state)
}

fn failure(error: ContinuationError) -> Response {
    let status = match error {
        ContinuationError::Unavailable | ContinuationError::KeyUnavailable | ContinuationError::Capacity => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ContinuationError::BindingMismatch | ContinuationError::Denied => StatusCode::FORBIDDEN,
        ContinuationError::Conflict => StatusCode::CONFLICT,
        ContinuationError::PrincipalLimit => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        [(header::CACHE_CONTROL, "no-store"), (header::REFERRER_POLICY, "no-referrer")],
        "Consent could not be completed",
    )
        .into_response()
}

fn now_secs() -> Result<u64, ContinuationError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| ContinuationError::Unavailable)
}

async fn authorize_ticket(
    state: &ModernConsentState,
    ticket: &ConsentTicket,
    provider_id: &str,
) -> Result<(CredentialProvider, crate::jwt_bearer::models::JwtVerificationStrategy), Response> {
    use crate::mcp::continuations::delegation::{identity_strategy_digest, provider_digest, surface_digest};
    use crate::mcp::continuations::protected::ContinuationRoute;

    if ticket.binding.provider_id != provider_id || ticket.binding.route == ContinuationRoute::StandaloneProxy {
        return Err(failure(ContinuationError::BindingMismatch));
    }
    let store = state
        .vault
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| failure(ContinuationError::Unavailable))?;
    let surface = store
        .get(&ticket.binding.surface_id)
        .await
        .map_err(|_| failure(ContinuationError::Unavailable))?
        .ok_or_else(|| failure(ContinuationError::NotFound))?;
    let alias = match ticket
        .binding
        .variant_id
        .as_ref()
    {
        Some(id) => Some(
            surface
                .variants
                .iter()
                .find(|variant| &variant.id == id && variant.enabled)
                .ok_or_else(|| failure(ContinuationError::BindingMismatch))?
                .alias
                .as_str(),
        ),
        None => None,
    };
    let surface = surface
        .resolve_variant(alias)
        .map_err(|_| failure(ContinuationError::BindingMismatch))?;
    if surface.status != crate::config::agent_surface::SurfaceStatus::Active
        || surface.tenant_id != ticket.binding.tenant_id
        || surface_digest(&surface).map_err(failure)? != ticket.surface_digest
    {
        return Err(failure(ContinuationError::BindingMismatch));
    }
    let authorization = match &ticket.binding.route {
        ContinuationRoute::AccessPoint | ContinuationRoute::Fabric { .. } | ContinuationRoute::FabricSend { .. } => {
            surface.mcp_http.as_ref()
        }
        ContinuationRoute::TransitPoint { alias } => surface
            .transit
            .as_ref()
            .and_then(|transit| {
                transit
                    .points
                    .iter()
                    .find(|point| &point.alias == alias)
            })
            .and_then(|point| point.mcp_http.as_ref()),
        ContinuationRoute::StandaloneProxy => None,
    }
    .and_then(|http| http.authorization.as_ref())
    .ok_or_else(|| failure(ContinuationError::BindingMismatch))?;
    authorization
        .validate()
        .map_err(|_| failure(ContinuationError::BindingMismatch))?;
    let profile = state
        .network
        .sts
        .mcp_issuer
        .as_ref()
        .ok_or_else(|| failure(ContinuationError::Unavailable))?;
    let expected_callback = format!(
        "{}{CALLBACK_PATH}/{provider_id}",
        Url::parse(&profile.issuer)
            .map_err(|_| failure(ContinuationError::Unavailable))?
            .origin()
            .ascii_serialization()
    );
    if expected_callback != ticket.callback_url
        || profile
            .validate_network(&state.network)
            .is_err()
    {
        return Err(failure(ContinuationError::BindingMismatch));
    }
    let provider = state
        .vault
        .provider_store
        .get(provider_id)
        .await
        .map_err(|_| failure(ContinuationError::Unavailable))?
        .ok_or_else(|| failure(ContinuationError::NotFound))?;
    if provider_digest(&provider).map_err(failure)? != ticket.provider_digest
        || !crate::tenancy::can_reference(surface.tenant_id.as_deref(), provider.tenant_id.as_deref())
    {
        return Err(failure(ContinuationError::BindingMismatch));
    }
    let strategy_id = provider
        .consent_identity_strategy_id
        .as_deref()
        .ok_or_else(|| failure(ContinuationError::InvalidRecord))?;
    let strategy = state
        .identity_strategies
        .get(strategy_id)
        .await
        .map_err(|_| failure(ContinuationError::Unavailable))?
        .ok_or_else(|| failure(ContinuationError::NotFound))?;
    if identity_strategy_digest(&strategy).map_err(failure)? != ticket.identity_strategy_digest
        || !crate::tenancy::can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref())
    {
        return Err(failure(ContinuationError::BindingMismatch));
    }
    if !surface
        .outbound_credentials
        .iter()
        .any(|binding| binding.credential_provider_id == provider_id)
    {
        return Err(failure(ContinuationError::BindingMismatch));
    }
    Ok((provider, strategy))
}

async fn connect(
    State(state): State<ModernConsentState>,
    Path(provider_id): Path<String>,
    Query(query): Query<ConsentQuery>,
) -> Response {
    let result = async {
        if query.code.is_some()
            || query.error.is_some()
            || query
                .error_description
                .is_some()
            || query.iss.is_some()
        {
            return Err(failure(ContinuationError::InvalidInputResponse));
        }
        let now = now_secs().map_err(failure)?;
        let ticket = state
            .continuations
            .read_consent_ticket(&query.state, false, now)
            .await
            .map_err(failure)?;
        let (provider, _) = authorize_ticket(&state, &ticket, &provider_id).await?;
        let client_id = super::oauth::resolve_secret(
            &state.vault.secrets_store,
            provider
                .client_id_secret_ref
                .as_deref()
                .ok_or_else(|| failure(ContinuationError::InvalidRecord))?,
        )
        .await
        .map_err(|_| failure(ContinuationError::Unavailable))?;
        let verifier = super::oauth::generate_pkce_verifier();
        let mut prepared = ticket.clone();
        prepared.code_verifier = Some(verifier.clone());
        authorization_url(&provider, &prepared, &client_id, "preflight").map_err(failure)?;
        let callback_state = state
            .continuations
            .begin_consent_callback(
                ticket,
                verifier,
                state
                    .vault
                    .vault_store
                    .as_ref(),
                now_secs().map_err(failure)?,
            )
            .await
            .map_err(failure)?;
        let redirect = authorization_url(&provider, &prepared, &client_id, &callback_state).map_err(failure)?;
        let mut response = axum::response::Redirect::to(redirect.as_str()).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::REFERRER_POLICY, axum::http::HeaderValue::from_static("no-referrer"));
        Ok(response)
    }
    .await;
    result.unwrap_or_else(|response| response)
}

async fn callback(
    State(state): State<ModernConsentState>,
    Path(provider_id): Path<String>,
    Query(query): Query<ConsentQuery>,
) -> Response {
    let result = async {
        let ticket = state
            .continuations
            .read_consent_ticket(&query.state, true, now_secs().map_err(failure)?)
            .await
            .map_err(failure)?;
        let (provider, strategy) = authorize_ticket(&state, &ticket, &provider_id).await?;
        if query
            .iss
            .as_deref()
            .is_some_and(|issuer| issuer != strategy.expected_issuer)
            || query.code.is_some() == query.error.is_some()
            || (query
                .error_description
                .is_some()
                && query.error.is_none())
        {
            return Err(failure(ContinuationError::InvalidInputResponse));
        }
        if let Some(error) = query.error.as_deref() {
            if error.is_empty()
                || error.len() > 128
                || !error
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(failure(ContinuationError::InvalidInputResponse));
            }
            state
                .continuations
                .deny_consent_callback(&ticket, now_secs().map_err(failure)?)
                .await
                .map_err(failure)?;
            return Err(failure(ContinuationError::Denied));
        }
        let claimed = state
            .continuations
            .claim_consent_callback(ticket, now_secs().map_err(failure)?)
            .await
            .map_err(failure)?;
        let response = exchange_code(
            &provider,
            &claimed.ticket,
            query
                .code
                .as_deref()
                .unwrap_or_default(),
            &state.vault.secrets_store,
            &state.provider_http,
        )
        .await
        .map_err(failure)?;
        authorize_ticket(&state, &claimed.ticket, &provider_id).await?;
        let profile = state
            .network
            .sts
            .mcp_issuer
            .as_ref()
            .ok_or_else(|| failure(ContinuationError::Unavailable))?;
        let consent_identity = identity::verify_id_token(
            &state.verifier,
            &strategy,
            profile,
            &claimed.ticket,
            &response.client_id,
            &response.id_token,
            now_secs().map_err(failure)?,
        )
        .await
        .map_err(failure)?;
        let token = response.token;
        let scopes = token
            .scope
            .as_deref()
            .map(|scope| {
                scope
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                claimed
                    .ticket
                    .binding
                    .scopes
                    .clone()
            });
        if claimed
            .ticket
            .binding
            .scopes
            .iter()
            .any(|required| !scopes.contains(required))
        {
            return Err(failure(ContinuationError::Denied));
        }
        let now = chrono::Utc::now();
        let credential = super::DelegationToken {
            id: uuid::Uuid::new_v4().to_string(),
            agent_did: claimed
                .ticket
                .binding
                .agent_did
                .clone(),
            user_identity_hash: claimed
                .ticket
                .binding
                .user_identity_hash
                .clone(),
            credential_provider_id: provider.id.clone(),
            provider_id: provider.provider_id.clone(),
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            token_type: token.token_type,
            scopes,
            expires_at: token
                .expires_in
                .and_then(|seconds| now.checked_add_signed(chrono::Duration::seconds(seconds))),
            delegation_vc: None,
            consent_identity: Some(consent_identity),
            consent_granted_at: now,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        };
        state
            .continuations
            .complete_consent_callback(
                claimed,
                state
                    .vault
                    .vault_store
                    .as_ref(),
                credential,
                now_secs().map_err(failure)?,
            )
            .await
            .map_err(failure)?;
        Ok((
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store"), (header::REFERRER_POLICY, "no-referrer")],
            "Authorization completed",
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(|response| response)
}

pub fn authorization_url(
    provider: &CredentialProvider,
    ticket: &ConsentTicket,
    client_id: &str,
    callback_state: &str,
) -> Result<Url, ContinuationError> {
    if provider.provider_type != CredentialProviderType::OAuth2AuthorizationCode
        || provider.id != ticket.binding.provider_id
        || client_id.is_empty()
        || client_id.len() > 4096
        || callback_state.len() > 64 * 1024
        || provider
            .consent_identity_strategy_id
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(ContinuationError::InvalidRecord);
    }
    let resource = provider
        .resource
        .as_deref()
        .ok_or(ContinuationError::InvalidRecord)?;
    crate::sts::mcp_profile::canonical_https_url(resource).map_err(|_| ContinuationError::InvalidRecord)?;
    let endpoint = provider
        .authorization_endpoint
        .as_deref()
        .ok_or(ContinuationError::InvalidRecord)?;
    let mut url = Url::parse(endpoint).map_err(|_| ContinuationError::InvalidRecord)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ContinuationError::InvalidRecord);
    }
    let reserved = [
        "response_type",
        "client_id",
        "redirect_uri",
        "resource",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ];
    let mut names = HashSet::new();
    if provider
        .additional_params
        .len()
        > 32
        || url
            .query_pairs()
            .any(|(name, value)| {
                reserved.contains(&name.as_ref())
                    || name.len() > 128
                    || value.len() > 2048
                    || !names.insert(name.into_owned())
            })
        || provider
            .additional_params
            .iter()
            .any(|(name, value)| {
                reserved.contains(&name.as_str())
                    || name.len() > 128
                    || value.len() > 2048
                    || !names.insert(name.clone())
            })
    {
        return Err(ContinuationError::InvalidRecord);
    }
    let verifier = ticket
        .code_verifier
        .as_deref()
        .ok_or(ContinuationError::InvalidRecord)?;
    let challenge = super::oauth::generate_pkce_challenge(verifier);
    let mut scopes = ticket.binding.scopes.clone();
    if !scopes
        .iter()
        .any(|scope| scope == "openid")
    {
        scopes.push("openid".into());
    }
    let scopes = scopes.join(" ");
    let nonce = identity::nonce(ticket);
    url.query_pairs_mut()
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", ticket.callback_url.as_str()),
            ("resource", resource),
            ("scope", scopes.as_str()),
            ("state", callback_state),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .extend_pairs(
            provider
                .additional_params
                .iter(),
        );
    Ok(url)
}

pub struct ExchangedProviderResponse {
    pub token: super::OAuthTokenResponse,
    pub id_token: zeroize::Zeroizing<String>,
    pub client_id: String,
}

#[derive(Deserialize)]
struct ProviderTokenResponse {
    #[serde(flatten)]
    token: super::OAuthTokenResponse,
    id_token: String,
}

pub async fn exchange_code(
    provider: &CredentialProvider,
    ticket: &ConsentTicket,
    code: &str,
    secrets: &std::sync::Arc<dyn crate::secrets::SecretsStore>,
    client: &reqwest::Client,
) -> Result<ExchangedProviderResponse, ContinuationError> {
    if code.is_empty()
        || code.len() > 4096
        || code
            .chars()
            .any(char::is_control)
    {
        return Err(ContinuationError::InvalidInputResponse);
    }
    let endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or(ContinuationError::InvalidRecord)?;
    let resource = provider
        .resource
        .as_deref()
        .ok_or(ContinuationError::InvalidRecord)?;
    crate::url_validation::validate_oauth_endpoint_url(endpoint).map_err(|_| ContinuationError::InvalidRecord)?;
    crate::sts::mcp_profile::canonical_https_url(resource).map_err(|_| ContinuationError::InvalidRecord)?;
    let client_id = super::oauth::resolve_secret(
        secrets,
        provider
            .client_id_secret_ref
            .as_deref()
            .ok_or(ContinuationError::InvalidRecord)?,
    )
    .await
    .map_err(|_| ContinuationError::Unavailable)?;
    let client_secret = zeroize::Zeroizing::new(
        super::oauth::resolve_secret(
            secrets,
            provider
                .client_secret_secret_ref
                .as_deref()
                .ok_or(ContinuationError::InvalidRecord)?,
        )
        .await
        .map_err(|_| ContinuationError::Unavailable)?,
    );
    let verifier = ticket
        .code_verifier
        .as_deref()
        .ok_or(ContinuationError::InvalidRecord)?;
    let operation = async {
        let mut response = client
            .post(endpoint)
            .header("accept", "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", ticket.callback_url.as_str()),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("code_verifier", verifier),
                ("resource", resource),
            ])
            .send()
            .await
            .map_err(|_| ContinuationError::Unavailable)?;
        if !response.status().is_success() {
            return Err(ContinuationError::Unavailable);
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ContinuationError::Unavailable)?
        {
            if bytes
                .len()
                .saturating_add(chunk.len())
                > 64 * 1024
            {
                return Err(ContinuationError::InvalidInputResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        let response: ProviderTokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| ContinuationError::InvalidInputResponse)?;
        let token = response.token;
        if token.access_token.is_empty()
            || !token
                .token_type
                .eq_ignore_ascii_case("Bearer")
            || token
                .expires_in
                .is_some_and(|expiry| expiry <= 0 || expiry > 366 * 86400)
        {
            return Err(ContinuationError::InvalidInputResponse);
        }
        if response.id_token.is_empty() || response.id_token.len() > 32 * 1024 {
            return Err(ContinuationError::InvalidInputResponse);
        }
        Ok(ExchangedProviderResponse {
            token,
            id_token: zeroize::Zeroizing::new(response.id_token),
            client_id,
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), operation)
        .await
        .map_err(|_| ContinuationError::Unavailable)?
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn callback_routes_verify_the_consent_user_before_staging_credentials() {
        use std::sync::Arc;

        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        use tower::ServiceExt;

        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::delegation_vault::storage::{DelegationVaultStorage, FileSystemDelegationVaultStore};
        use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
        use crate::mcp::continuations::{
            delegation::{identity_strategy_digest, make_binding, provider_digest, surface_digest},
            embedded::EmbeddedContinuations,
            protected::{ContinuationCipher, ContinuationKey, ContinuationRoute},
            service::{ContinuationService, DelegationClaim},
        };
        use crate::mcp::request_validation::{McpMessageKind, ValidatedModernMessage};
        use crate::secrets::SecretsStore;
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

        #[derive(Default)]
        struct ProviderReply {
            body: tokio::sync::Mutex<serde_json::Value>,
            exchanges: tokio::sync::Mutex<Vec<std::collections::HashMap<String, String>>>,
        }

        let provider_reply = Arc::new(ProviderReply::default());
        let provider_app = axum::Router::new()
            .route(
                "/token",
                axum::routing::post(
                    |State(reply): State<Arc<ProviderReply>>,
                     axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| async move {
                        reply
                            .exchanges
                            .lock()
                            .await
                            .push(form);
                        axum::Json(
                            reply
                                .body
                                .lock()
                                .await
                                .clone(),
                        )
                    },
                ),
            )
            .with_state(provider_reply.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let provider_http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .proxy(reqwest::Proxy::http(format!("http://{}", listener.local_addr().unwrap())).unwrap())
            .build()
            .unwrap();
        let token_endpoint = "http://192.0.2.1/token";
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, provider_app)
                .await
                .unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let secrets = Arc::new(
            crate::secrets::FilesystemSecretsStore::new(
                directory
                    .path()
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        for (secret_id, value) in
            [("provider-client-id", "provider-client"), ("provider-client-secret", "fixture-secret")]
        {
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
        let providers = Arc::new(
            FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap(),
        );
        let strategies = Arc::new(
            FileSystemJwtVerificationStrategyStore::new(
                directory
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        );
        let surfaces = Arc::new(
            FileSystemAgentSurfaceStore::new(
                directory
                    .path()
                    .join("surfaces"),
            )
            .await
            .unwrap(),
        );
        let vault = Arc::new(
            FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "key-1", "x": encoding.encode(signing.verifying_key().as_bytes())}]});
        let strategy = strategies
            .create(crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &jwks).unwrap())
            .await
            .unwrap();
        let provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Provider", "provider_id": "provider",
            "authorization_endpoint": "https://identity.example/authorize", "token_endpoint": token_endpoint,
            "client_id_secret_ref": "provider-client-id", "client_secret_secret_ref": "provider-client-secret",
            "resource": "https://provider.example/api", "consent_identity_strategy_id": strategy.id,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        providers
            .create(provider.clone())
            .await
            .unwrap();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "Surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://provider.example/api"},
            "mcp_http": {"authorization": {"resource": "https://gateway.example/mcp", "scopes": ["read"]}},
            "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"]}]
        }))
        .unwrap();
        surfaces
            .save(&surface)
            .await
            .unwrap();
        let surface = surface
            .resolve_variant(None)
            .unwrap();
        let network: crate::config::NetworkConfig = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080, "protocol": "http", "external_urls": ["https://gateway.example"]}],
            "routes": {"identity": {"type": "identity_api", "prefix": "/api"}},
            "sts": {"mcp_issuer": {"issuer": "https://gateway.example/api/oauth2/mcp"}}
        })).unwrap();
        let profile = network
            .sts
            .mcp_issuer
            .as_ref()
            .unwrap();
        let now = now_secs().unwrap();
        let subject = profile
            .bound_subject(&json!({"iss": strategy.expected_issuer, "sub": "alice"}))
            .unwrap();
        let caller = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: subject.clone(),
            claims: json!({"iss": profile.issuer, "sub": subject, "scope": "read", "exp": now + 300}),
        };
        let request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: Some(json!({"elicitation": {"url": {}}})),
            client_info: None,
            method: "tools/call".into(),
            id: Some(json!(1)),
            kind: McpMessageKind::Request,
            params: Some(json!({"name": "read", "arguments": {"value": 1}})),
        };
        let binding = make_binding(
            "deployment",
            &surface,
            None,
            ContinuationRoute::AccessPoint,
            surface
                .mcp_http
                .as_ref()
                .unwrap()
                .authorization
                .as_ref()
                .unwrap(),
            &provider,
            vec!["read".into()],
            "did:web:agent.example",
            &caller,
            &request,
        )
        .unwrap();
        let service = Arc::new(ContinuationService::new(
            ContinuationCipher::new(
                "deployment".into(),
                "key".into(),
                vec![ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap()],
            )
            .unwrap(),
            Arc::new(EmbeddedContinuations::new(32).unwrap()),
        ));
        let app = router(ModernConsentState {
            vault: super::super::handlers::DelegationVaultState {
                vault_store: vault.clone(),
                provider_store: providers.clone(),
                secrets_store: secrets,
                gateway_base_url: "https://gateway.example".into(),
                agent_surface_store: Some(surfaces),
                oauth_callback_route: "/oauth/callback".into(),
                vc_signer: None,
                vc_issuer: None,
                vault_population_notifier: None,
            },
            network: Arc::new(network),
            identity_strategies: strategies,
            verifier: Arc::new(crate::jwt_bearer::JwtBearerVerifier::new(Arc::new(
                crate::jwt_bearer::JwksClient::new(),
            ))),
            continuations: service.clone(),
            provider_http,
        });

        for (provider_subject, expected_status) in [
            ("provider_changed", StatusCode::FORBIDDEN),
            ("denied", StatusCode::FORBIDDEN),
            ("bob", StatusCode::FORBIDDEN),
            ("alice", StatusCode::OK),
        ] {
            let callback_url = "https://gateway.example/mcp-consent/callback/provider";
            let (issued, connect_state) = service
                .issue_consent(
                    &request,
                    binding.clone(),
                    provider_digest(&provider).unwrap(),
                    surface_digest(&surface).unwrap(),
                    identity_strategy_digest(&strategy).unwrap(),
                    callback_url.into(),
                    300,
                    now,
                )
                .await
                .unwrap();
            let mut connect_url = Url::parse("https://gateway.example/mcp-consent/connect/provider").unwrap();
            connect_url
                .query_pairs_mut()
                .append_pair("state", &connect_state);
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(connect_url.as_str())
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                response
                    .status()
                    .is_redirection()
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let authorization = Url::parse(
                response.headers()[header::LOCATION]
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            let fields = authorization
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(fields["scope"], "read openid");
            if matches!(provider_subject, "provider_changed" | "denied") {
                let mut callback = Url::parse(callback_url).unwrap();
                callback
                    .query_pairs_mut()
                    .append_pair("state", &fields["state"])
                    .append_pair("iss", &strategy.expected_issuer);
                if provider_subject == "provider_changed" {
                    let mut changed = provider.clone();
                    changed.resource = Some("https://other-resource.example/api".into());
                    providers
                        .update(changed)
                        .await
                        .unwrap();
                    callback
                        .query_pairs_mut()
                        .append_pair("code", "must-not-exchange");
                } else {
                    callback
                        .query_pairs_mut()
                        .append_pair("error", "access_denied")
                        .append_pair("error_uri", "https://provider.example/errors/access_denied");
                }
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(callback.as_str())
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected_status, "{provider_subject}");
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert!(
                    provider_reply
                        .exchanges
                        .lock()
                        .await
                        .is_empty()
                );
                assert!(
                    vault
                        .staged_consent(issued.id, binding.digest().unwrap(), now)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    vault
                        .list_all()
                        .await
                        .unwrap()
                        .is_empty()
                );
                if provider_subject == "provider_changed" {
                    providers
                        .update(provider.clone())
                        .await
                        .unwrap();
                } else {
                    let mut retry = request.clone();
                    retry.id = Some(json!(2));
                    assert!(matches!(
                        service
                            .resume(&issued.state, &binding, &retry, now)
                            .await,
                        Err(ContinuationError::Denied)
                    ));
                    let replay = app
                        .clone()
                        .oneshot(
                            axum::http::Request::builder()
                                .uri(callback.as_str())
                                .body(axum::body::Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
                }
                continue;
            }
            let claims = json!({"iss": strategy.expected_issuer, "sub": provider_subject, "aud": "provider-client", "exp": now + 300, "iat": now, "nonce": fields["nonce"]});
            let signing_input = format!(
                "{}.{}",
                encoding.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"key-1"}"#),
                encoding.encode(serde_json::to_vec(&claims).unwrap())
            );
            let id_token = format!(
                "{signing_input}.{}",
                encoding.encode(
                    signing
                        .sign(signing_input.as_bytes())
                        .to_bytes()
                )
            );
            *provider_reply
                .body
                .lock()
                .await = json!({"access_token": "fixture-access", "token_type": "Bearer", "scope": "read openid", "expires_in": 3600, "id_token": id_token});
            let mut callback_url = Url::parse(callback_url).unwrap();
            callback_url
                .query_pairs_mut()
                .append_pair("state", &fields["state"])
                .append_pair("code", "fixture-code")
                .append_pair("iss", &strategy.expected_issuer)
                // Provider-specific response parameters (Keycloak, Entra, Google)
                // that a client must ignore.
                .append_pair("session_state", "provider-session")
                .append_pair("scope", "read openid")
                .append_pair("authuser", "0")
                .append_pair("prompt", "consent");
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(callback_url.as_str())
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status, "{provider_subject}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap();
            assert!(
                !String::from_utf8(body.to_vec())
                    .unwrap()
                    .contains("fixture-access")
            );
            assert!(
                vault
                    .list_all()
                    .await
                    .unwrap()
                    .is_empty()
            );
            let exchanges = provider_reply
                .exchanges
                .lock()
                .await;
            let exchange = exchanges.last().unwrap();
            assert_eq!(exchange["client_id"], "provider-client");
            assert_eq!(exchange["resource"], "https://provider.example/api");
            assert_eq!(exchange["redirect_uri"], "https://gateway.example/mcp-consent/callback/provider");
            assert_eq!(
                super::super::oauth::generate_pkce_challenge(&exchange["code_verifier"]),
                fields["code_challenge"]
            );
            let exchange_count = exchanges.len();
            drop(exchanges);
            let replay = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(callback_url.as_str())
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(replay.status(), StatusCode::CONFLICT);
            assert_eq!(
                provider_reply
                    .exchanges
                    .lock()
                    .await
                    .len(),
                exchange_count
            );
            let staged = vault
                .staged_consent(issued.id, binding.digest().unwrap(), now)
                .await
                .unwrap();
            if provider_subject == "bob" {
                assert!(staged.is_none());
            } else {
                assert!(staged.is_some());
                let mut retry = request.clone();
                retry.id = Some(json!(2));
                let resumed = service
                    .resume(&issued.state, &binding, &retry, now)
                    .await
                    .unwrap();
                let DelegationClaim::Claimed { continuation, credential } = service
                    .claim_delegation(resumed, vault.as_ref(), now)
                    .await
                    .unwrap()
                else {
                    panic!("verified consent must permit a single retry");
                };
                assert_eq!(credential.access_token, "fixture-access");
                assert!(
                    credential
                        .consent_identity
                        .as_ref()
                        .unwrap()
                        .matches(
                            &binding.principal,
                            provider_digest(&provider).unwrap(),
                            identity_strategy_digest(&strategy).unwrap(),
                        )
                );
                assert_eq!(
                    vault
                        .list_all()
                        .await
                        .unwrap()
                        .len(),
                    1
                );
                service
                    .complete(*continuation, now)
                    .await
                    .unwrap();
            }
        }
        tasks.shutdown().await;
    }

    #[test]
    fn modern_consent_binds_pkce_callback_and_resource_without_parameter_override() {
        let mut provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Provider", "provider_id": "provider", "authorization_endpoint": "https://idp.example/authorize?prompt=consent",
            "resource": "https://provider.example/api", "consent_identity_strategy_id": "strategy",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        })).unwrap();
        let ticket: ConsentTicket = serde_json::from_value(json!({
            "id": uuid::Uuid::new_v4(), "continuation_id": uuid::Uuid::new_v4(), "issued_at": 10, "expires_at": 100,
            "provider_digest": ([3; 32]), "surface_digest": ([4; 32]), "identity_strategy_digest": ([5; 32]),
            "callback_url": "https://gateway.example/mcp-consent/callback/provider", "code_verifier": "v".repeat(43),
            "binding": {"deployment": "deployment", "principal": "principal", "agent_did": "did:web:agent", "user_identity_hash": "user",
                "authorization_digest": ([1; 32]), "tenant_id": null, "surface_id": "surface", "variant_id": null, "route": {"kind": "access_point"},
                "resource": "https://gateway.example/mcp", "provider_id": "provider", "scopes": ["read"], "method": "tools/call", "arguments_digest": ([2; 32])}
        })).unwrap();
        let url = authorization_url(&provider, &ticket, "client", "opaque-callback-state").unwrap();
        let fields = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(fields["resource"], "https://provider.example/api");
        assert_eq!(fields["redirect_uri"], ticket.callback_url);
        assert_eq!(fields["code_challenge_method"], "S256");
        assert_eq!(fields["code_challenge"], super::super::oauth::generate_pkce_challenge(&"v".repeat(43)));
        assert_eq!(fields["state"], "opaque-callback-state");
        assert_eq!(fields["nonce"], identity::nonce(&ticket));
        assert_eq!(fields["scope"], "read openid");
        assert!(
            !url.as_str()
                .contains("code_verifier")
        );
        provider
            .additional_params
            .insert("state".into(), "forged".into());
        assert!(authorization_url(&provider, &ticket, "client", "opaque").is_err());
        provider
            .additional_params
            .clear();
        provider.resource = None;
        assert!(authorization_url(&provider, &ticket, "client", "opaque").is_err());
    }
}
