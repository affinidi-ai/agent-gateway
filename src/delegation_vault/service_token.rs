//! Service tokens: credentials the gateway obtains from a credential provider for itself,
//! not on a user's behalf. Delegation bindings and target authentication share this one
//! path. Static credentials are read from the secrets store on every use; tokens an
//! issuer returns are cached in the delegation vault until they expire.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

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

pub struct ServiceToken {
    value: zeroize::Zeroizing<String>,
    /// The vault row of a token an issuer returned; `None` for a static credential read
    /// from the secrets store, which is never cached.
    pub issued: Option<IssuedToken>,
}

pub struct IssuedToken {
    pub id: String,
    /// Whether it came from the vault cache rather than a token request just now.
    pub cached: bool,
}

impl ServiceToken {
    pub fn value(&self) -> &str {
        &self.value
    }

    fn issued(
        token: DelegationToken,
        cached: bool,
    ) -> Self {
        Self {
            value: zeroize::Zeroizing::new(token.access_token),
            issued: Some(IssuedToken { id: token.id, cached }),
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
    #[error("credential provider issued other scopes than requested")]
    ScopeMismatch,
    #[error("credential provider changed during the token request")]
    ProviderChanged,
    #[error("credential store unavailable")]
    StoreUnavailable,
}

/// A cached token is not injected within this many seconds of its expiry, so it does not
/// reach the target just as the issuer stops accepting it.
pub const EXPIRY_MARGIN_SECS: i64 = 60;

/// The provider's service token for `scopes`: its API key, or a cached token that grants
/// them, or a new token from the provider's grant, stored under `key`. Issued scopes must
/// equal requested ones; when none were requested the issuer's scopes are kept.
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
        return Ok(ServiceToken {
            value: zeroize::Zeroizing::new(value),
            issued: None,
        });
    }
    if let Some(token) = cached_token(provider, scopes, context, key, now).await? {
        return Ok(ServiceToken::issued(token, true));
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
    if (!scopes.is_empty()
        && granted
            .iter()
            .any(|scope| !scopes.contains(scope)))
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
        .ok_or_else(|| {
            // The token request already refuses a response without a bounded expires_in.
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, "Service token expiry out of range");
            ServiceTokenError::TokenRequestFailed
        })?;
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
    Ok(ServiceToken::issued(token, false))
}

async fn cached_token(
    provider: &CredentialProvider,
    scopes: &[String],
    context: &ServiceTokenContext<'_>,
    key: ServiceTokenKey<'_>,
    now: DateTime<Utc>,
) -> Result<Option<DelegationToken>, ServiceTokenError> {
    let token = match context
        .vault
        .lookup(key.agent_did, key.identity, &provider.id)
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?
    {
        VaultLookupResult::Found(token) => token,
        VaultLookupResult::ExpiredRefreshable(token) | VaultLookupResult::ExpiredNoRefresh(token) => {
            debug!(target: "credential_delegation", token_id = %token.id, "Cached service token expired, requesting a new one");
            return Ok(None);
        }
        VaultLookupResult::NotFound => return Ok(None),
    };
    let usable = token.agent_did == key.agent_did
        && token.user_identity_hash == key.identity
        && token.credential_provider_id == provider.id
        && !token.access_token.is_empty()
        && token
            .token_type
            .eq_ignore_ascii_case("Bearer")
        && token
            .expires_at
            .is_some_and(|expires| expires - chrono::Duration::seconds(EXPIRY_MARGIN_SECS) > now)
        && scopes
            .iter()
            .all(|scope| token.scopes.contains(scope));
    Ok(usable.then_some(token))
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

    #[derive(Default)]
    struct Endpoint {
        response: Mutex<Value>,
        forms: Mutex<Vec<HashMap<String, String>>>,
    }

    struct Fixture {
        secrets: Arc<dyn SecretsStore>,
        providers: FileSystemCredentialProviderStore,
        vault: FileSystemDelegationVaultStore,
        client: reqwest::Client,
        endpoint: Arc<Endpoint>,
        _server: tokio::task::JoinSet<()>,
        _directory: tempfile::TempDir,
    }

    const KEY: ServiceTokenKey<'static> = ServiceTokenKey {
        agent_did: "surface:surface-1",
        identity: "__target_auth__:digest",
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
                        axum::Json(
                            endpoint
                                .response
                                .lock()
                                .unwrap()
                                .clone(),
                        )
                    },
                ))
                .with_state(endpoint.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let client = reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::http(format!("http://{}", listener.local_addr().unwrap())).unwrap())
                .build()
                .unwrap();
            let mut server = tokio::task::JoinSet::new();
            server.spawn(async move {
                axum::serve(listener, app)
                    .await
                    .unwrap();
            });
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
                client,
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
                "token_endpoint": "http://192.0.2.1/token",
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
                http: Some(&self.client),
            };
            acquire(provider, &scopes, &context, KEY, now).await
        }

        fn requests(&self) -> Vec<HashMap<String, String>> {
            self.endpoint
                .forms
                .lock()
                .unwrap()
                .clone()
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

    fn issued(token: Result<ServiceToken, ServiceTokenError>) -> (String, bool) {
        let token = token.unwrap_or_else(|error| panic!("expected an issued token, got {error}"));
        let cached = token
            .issued
            .as_ref()
            .expect("expected an issued token")
            .cached;
        (token.value().to_string(), cached)
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
                ("issued".into(), false)
            );
            assert_eq!(
                issued(
                    fixture
                        .acquire(&provider, &["read"], now)
                        .await
                ),
                ("issued".into(), true)
            );
            let requests = fixture.requests();
            assert_eq!(requests.len(), 1, "{grant_type}");
            assert_eq!(requests[0]["grant_type"], grant_type);
            assert!(!requests[0].contains_key("resource"), "{grant_type}");
            let VaultLookupResult::Found(stored) = fixture
                .vault
                .lookup(KEY.agent_did, KEY.identity, "provider")
                .await
                .unwrap()
            else {
                panic!("the issued token must be stored under its key");
            };
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
    async fn a_cached_token_counts_as_expired_sixty_seconds_before_it_expires() {
        let fixture = Fixture::new().await;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                             "client_secret_secret_ref": "CLIENT_SECRET"}))
            .await;
        let now = Utc::now();
        issued(
            fixture
                .acquire(&provider, &[], now)
                .await,
        );
        let later = now + chrono::Duration::seconds(3600 - 90);
        assert!(
            issued(
                fixture
                    .acquire(&provider, &[], later)
                    .await
            )
            .1
        );
        fixture.respond(json!({"access_token": "renewed", "token_type": "Bearer", "expires_in": 3600}));
        let almost = now + chrono::Duration::seconds(3600 - 30);
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &[], almost)
                    .await
            ),
            ("renewed".into(), false)
        );
        assert_eq!(fixture.requests().len(), 2);
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
            ("wide".into(), false)
        );
        let VaultLookupResult::Found(stored) = fixture
            .vault
            .lookup(KEY.agent_did, KEY.identity, "provider")
            .await
            .unwrap()
        else {
            panic!("the issued token must be stored");
        };
        assert_eq!(stored.scopes, vec!["read", "write"]);
        assert!(!requests_have_scope(&fixture.requests()[1]));
    }

    fn requests_have_scope(form: &HashMap<String, String>) -> bool {
        form.contains_key("scope")
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
}
