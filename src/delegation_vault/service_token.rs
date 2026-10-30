//! Service tokens: credentials the gateway obtains from a credential provider for itself,
//! not on a user's behalf. Delegation bindings and target authentication share this one
//! path. Static credentials are read from the secrets store on every use; tokens an
//! issuer returns are cached in the delegation vault until they expire.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use super::{DelegationToken, VaultLookupResult, oauth, storage::DelegationVaultStorage};
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
    /// Whether it came from the vault cache rather than a token request just now.
    pub cached: bool,
    /// Whether the provider's token endpoint breaks the https rule and is let through only
    /// because the rule is in warn mode.
    pub insecure_endpoint: bool,
}

impl ServiceToken {
    pub fn value(&self) -> &str {
        &self.value
    }

    fn issued(
        token: DelegationToken,
        cached: bool,
        insecure_endpoint: bool,
    ) -> Self {
        Self {
            value: zeroize::Zeroizing::new(token.access_token),
            issued: Some(IssuedToken {
                id: token.id,
                cached,
                insecure_endpoint,
            }),
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
    let insecure_endpoint = endpoint.is_some_and(|endpoint| !egress.permits_token_endpoint(endpoint));
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
    if let Some(token) = cached_token(provider, scopes, context, key.agent_did, &identity, now).await? {
        if insecure_endpoint {
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, "Using a service token from a credential provider token endpoint that is not https");
        }
        return Ok(ServiceToken::issued(token, true, insecure_endpoint));
    }
    let response = match provider.provider_type {
        CredentialProviderType::OAuth2ClientCredentials => {
            oauth::fetch_scoped_client_credentials_token(provider, scopes, context.secrets, &egress).await
        }
        CredentialProviderType::OAuth2JwtBearer => {
            oauth::fetch_jwt_bearer_token(provider, scopes, context.secrets, &egress).await
        }
        CredentialProviderType::OAuth2ClientCredentialsJwtAuth => {
            oauth::fetch_client_credentials_jwt_auth_token(provider, scopes, context.secrets, &egress).await
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
        } else if error.downcast_ref::<oauth::ProviderSecretError>() == Some(&oauth::ProviderSecretError::OutsideTenant) {
            ServiceTokenError::SecretUnavailable
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
        })
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?;
    if let Err(error) = context
        .vault
        .prune_expired(key.agent_did, &provider.id, key.purpose, &token.id)
        .await
    {
        warn!(target: "credential_delegation", provider_id = %provider.provider_id, %error, "Could not remove expired service tokens");
    }
    Ok(ServiceToken::issued(token, false, insecure_endpoint))
}

/// The vault user identity of the provider's token for `scopes`: `<purpose>:` and the hex
/// SHA-256 of the provider digest, the sorted scopes and each referenced secret's id, tenant
/// and `updated_at`. Secrets are read from the store's metadata listing, never decrypted.
/// A missing secret, or one outside the provider's tenant while `isolation` is enforced, is
/// refused here, so a cached token stops being served at once.
async fn cache_identity(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets: &Arc<dyn SecretsStore>,
    purpose: &str,
    isolation: RuleMode,
) -> Result<String, ServiceTokenError> {
    let listed = secrets
        .list_all()
        .await
        .map_err(|_| ServiceTokenError::StoreUnavailable)?;
    let mut versions = Vec::new();
    for secret_ref in provider.secret_refs() {
        let secret = listed
            .iter()
            .find(|secret| secret.secret_id == secret_ref)
            .ok_or_else(|| {
                warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Credential provider secret not found");
                ServiceTokenError::SecretUnavailable
            })?;
        if secret.tenant_id != provider.tenant_id {
            if isolation.is_enforced() {
                warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Refusing a credential provider secret outside the provider's tenant");
                return Err(ServiceTokenError::SecretUnavailable);
            }
            warn!(target: "credential_delegation", provider_id = %provider.provider_id, secret_ref, "Using a credential provider secret outside the provider's tenant");
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

async fn cached_token(
    provider: &CredentialProvider,
    scopes: &[String],
    context: &ServiceTokenContext<'_>,
    agent_did: &str,
    identity: &str,
    now: DateTime<Utc>,
) -> Result<Option<DelegationToken>, ServiceTokenError> {
    let token = match context
        .vault
        .lookup(agent_did, identity, &provider.id)
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
    let usable = token.agent_did == agent_did
        && token.user_identity_hash == identity
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The fixture's secrets store, counting value reads and able to fail its listing.
    struct ObservedSecrets {
        inner: crate::secrets::FilesystemSecretsStore,
        value_reads: AtomicUsize,
        listing_fails: AtomicBool,
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
            self.value_reads
                .fetch_add(1, Ordering::SeqCst);
            self.inner.get(id).await
        }
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
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
                value_reads: AtomicUsize::new(0),
                listing_fails: AtomicBool::new(false),
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
            .token_endpoint_https = RuleMode::Enforce;
        let provider = fixture
            .provider(json!({"provider_type": "oauth2_client_credentials", "client_id_secret_ref": "CLIENT_ID",
                             "client_secret_secret_ref": "CLIENT_SECRET"}))
            .await;
        let flags = |token: ServiceToken| {
            let issued = token
                .issued
                .expect("expected an issued token");
            (issued.cached, issued.insecure_endpoint)
        };
        let now = Utc::now();
        let listed = fixture
            .acquire(&provider, &[], now)
            .await
            .unwrap();
        assert_eq!(flags(listed), (false, false), "an exactly listed http endpoint meets the rule");

        fixture.egress.exact_allowlist = None;
        fixture
            .egress
            .policy
            .token_endpoint_https = RuleMode::Warn;
        let grandfathered = fixture
            .acquire(&provider, &[], now)
            .await
            .unwrap();
        assert_eq!(grandfathered.value(), "issued");
        assert_eq!(flags(grandfathered), (true, true));

        fixture
            .egress
            .policy
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
    async fn a_cached_token_is_served_without_reading_a_secret_value() {
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
        let reads = fixture
            .observed
            .value_reads
            .load(Ordering::SeqCst);
        assert!(reads > 0, "a token request reads the client credentials");
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("issued".into(), true)
        );
        assert_eq!(
            fixture
                .observed
                .value_reads
                .load(Ordering::SeqCst),
            reads
        );
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
        let client_secret = fixture
            .secret_id("CLIENT_SECRET")
            .await;
        fixture
            .secrets
            .update(
                &client_secret,
                crate::secrets::UpdateSecretRequest {
                    name: None,
                    description: None,
                    value: Some("rotated-secret".into()),
                    update_value: Some(true),
                    secret_type: None,
                    tags: None,
                },
            )
            .await
            .unwrap();
        fixture.respond(json!({"access_token": "after-rotation", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["read"], now)
                    .await
            ),
            ("after-rotation".into(), false)
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
            ("after-rotation".into(), true)
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
            ("after-move".into(), false),
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
            ("after-move-back".into(), false)
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
            ("after-edit".into(), false)
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
            ("both".into(), true)
        );
        fixture.respond(json!({"access_token": "admin", "token_type": "Bearer", "expires_in": 3600}));
        assert_eq!(
            issued(
                fixture
                    .acquire(&provider, &["admin"], now)
                    .await
            ),
            ("admin".into(), false)
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
            .listing_fails
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
            ("issued".into(), true),
            "warn mode keeps serving the cached token"
        );
        fixture
            .egress
            .policy
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
}
