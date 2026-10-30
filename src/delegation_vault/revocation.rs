//! RFC 7009 revocation of a grant by binding at its authorization server.
//!
//! The grant's refresh token is revoked, with `token_type_hint=refresh_token`,
//! then its access token, with `token_type_hint=access_token`, so a server that
//! does not cascade the first revocation still ends the second; a grant with no
//! refresh token has only its access token revoked. A server that does not
//! revoke access tokens answers that request with an error, which changes
//! nothing else. The client authenticates as its provider's
//! `token_endpoint_auth_method` says. The calls go through the pinned, Strict,
//! `https`-only egress client, with a short timeout, and no response body is
//! ever read, echoed or logged. Revocation is best effort: its outcome is
//! returned, logged and audited with the actor that caused it, and a failed
//! revocation never keeps a grant that is being removed. [`remove_grants`]
//! revokes and deletes many grants at most [`REVOCATION_CONCURRENCY`] at a time;
//! [`delete_then_revoke`] deletes them first and revokes them on a task of its
//! own, so the change that removed them never waits on a vendor.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt as _;

use super::audit::AuditCallerContext;
use super::grants::DelegatedGrant;
use super::storage::DelegationVaultStorage;
use crate::credential_providers::{CredentialProvider, TokenEndpointAuthMethod};
use crate::secrets::SecretsStore;

const REVOCATION_TIMEOUT: Duration = Duration::from_secs(10);

/// The most grants [`remove_grants`] revokes at once.
pub const REVOCATION_CONCURRENCY: usize = 8;

/// What became of one revocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The authorization server answered 2xx.
    Revoked,
    /// The authorization server answered another status.
    Refused,
    /// The endpoint could not be reached, or the egress policy refused it.
    Unreachable,
    /// The provider names no revocation endpoint.
    NotSupported,
    /// The client's secret could not be resolved in the provider's tenant.
    ClientUnavailable,
    /// Revocation was not tried: the grant was removed without it, for the
    /// [`GrantRevocation::reason`] given.
    Skipped,
}

impl RevocationOutcome {
    /// The outcome's name in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
            Self::NotSupported => "not_supported",
            Self::ClientUnavailable => "client_unavailable",
            Self::Skipped => "skipped",
        }
    }
}

/// Why a removed grant was not revoked: no secrets store is configured, so a
/// confidential client cannot authenticate.
pub const SKIPPED_NO_SECRETS_STORE: &str = "no_secrets_store";
/// Why a removed grant was not revoked: its provider no longer exists.
pub const SKIPPED_PROVIDER_MISSING: &str = "provider_missing";
/// Why a removed grant was not revoked: an operator purged it without reading it.
pub const SKIPPED_PURGED: &str = "purged";

/// What revoking one grant came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantRevocation {
    /// The refresh token's outcome, or the access token's for a grant with no
    /// refresh token.
    pub outcome: RevocationOutcome,
    /// The access token's outcome, for a grant whose refresh token was revoked
    /// first.
    pub access_token: Option<RevocationOutcome>,
    /// Why revocation was skipped, for [`RevocationOutcome::Skipped`].
    pub reason: Option<&'static str>,
}

impl GrantRevocation {
    fn failed(outcome: RevocationOutcome) -> Self {
        Self {
            outcome,
            access_token: None,
            reason: None,
        }
    }

    fn skipped(reason: &'static str) -> Self {
        Self {
            outcome: RevocationOutcome::Skipped,
            access_token: None,
            reason: Some(reason),
        }
    }

    /// The audit record's `detail`: `vendor_revocation:<outcome>`, then
    /// `,access_token:<outcome>` when the access token was revoked as well, or
    /// `,reason:<reason>` when revocation was skipped.
    pub fn detail(self) -> String {
        let mut detail = format!("vendor_revocation:{}", self.outcome.as_str());
        if let Some(access_token) = self.access_token {
            detail.push_str(&format!(",access_token:{}", access_token.as_str()));
        }
        if let Some(reason) = self.reason {
            detail.push_str(&format!(",reason:{reason}"));
        }
        detail
    }
}

/// Revoke `grant` at `provider`'s revocation endpoint, then log and audit the
/// outcome, naming `actor`, the management caller whose change removed it.
/// Without a secrets store, a client that authenticates with a secret is not
/// revoked: the outcome is `skipped`, with the reason `no_secrets_store`.
pub async fn revoke_grant(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: Option<&Arc<dyn SecretsStore>>,
    exact_allowlist: Option<&str>,
    actor: Option<&AuditCallerContext>,
) -> GrantRevocation {
    let revocation = revoke(provider, grant, secrets, exact_allowlist).await;
    record_revocation(&provider.id, Some(&provider.name), grant, revocation, actor);
    revocation
}

/// Log and audit what became of `grant`'s revocation.
fn record_revocation(
    credential_provider_id: &str,
    provider_name: Option<&str>,
    grant: &DelegatedGrant,
    revocation: GrantRevocation,
    actor: Option<&AuditCallerContext>,
) {
    let outcome = revocation.outcome.as_str();
    let access_token = revocation
        .access_token
        .map(RevocationOutcome::as_str);
    match revocation.outcome {
        RevocationOutcome::Revoked => tracing::info!(
            target: "credential_delegation",
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            access_token,
            "Revoked a delegated grant at its authorization server"
        ),
        RevocationOutcome::NotSupported => tracing::info!(
            target: "credential_delegation",
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            "A delegated grant's provider names no revocation endpoint, so the grant is removed without revoking it"
        ),
        RevocationOutcome::Skipped => tracing::warn!(
            target: "credential_delegation",
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            reason = revocation.reason,
            "A delegated grant is removed without revoking it at its authorization server"
        ),
        RevocationOutcome::Refused | RevocationOutcome::Unreachable | RevocationOutcome::ClientUnavailable => {
            tracing::warn!(
                target: "credential_delegation",
                grant_id = %grant.id,
                credential_provider_id = %credential_provider_id,
                outcome,
                "A delegated grant could not be revoked at its authorization server; it is removed all the same"
            )
        }
    }
    super::audit::emit("token_revoked", || {
        let mut event = super::audit::audit_event(
            super::audit::DelegationAuditAction::TokenRevoked,
            None,
            None,
            Some(credential_provider_id),
            Some(&grant.surface_id),
        );
        event.token_id = Some(grant.id.clone());
        event.provider_name = provider_name.map(str::to_string);
        event.detail = Some(revocation.detail());
        event.caller = actor.cloned();
        event
    });
}

/// Revoke at its authorization server, then delete, each of `grants`, at most
/// [`REVOCATION_CONCURRENCY`] at a time. Each grant's provider is looked up in
/// `providers` by its record id; a grant whose provider is not there is deleted
/// without revocation. A grant is deleted whatever its revocation came to.
/// Every grant is tried; the call fails if any could not be deleted.
pub async fn remove_grants(
    vault: &Arc<dyn DelegationVaultStorage>,
    grants: Vec<DelegatedGrant>,
    providers: &HashMap<String, CredentialProvider>,
    secrets: &Arc<dyn SecretsStore>,
    exact_allowlist: Option<&str>,
    actor: Option<&AuditCallerContext>,
) -> anyhow::Result<()> {
    let failures = futures::stream::iter(grants)
        .map(|grant| async move {
            match providers.get(&grant.credential_provider_id) {
                Some(provider) => {
                    revoke_grant(provider, &grant, Some(secrets), exact_allowlist, actor).await;
                }
                None => record_revocation(
                    &grant.credential_provider_id,
                    None,
                    &grant,
                    GrantRevocation::skipped(SKIPPED_PROVIDER_MISSING),
                    actor,
                ),
            }
            vault
                .delete_grant(&grant.id)
                .await
                .err()
        })
        .buffer_unordered(REVOCATION_CONCURRENCY)
        .filter_map(std::future::ready)
        .collect::<Vec<_>>()
        .await;
    match failures.into_iter().next() {
        Some(error) => Err(error.context("Failed to delete a delegated grant")),
        None => Ok(()),
    }
}

/// What revoking removed grants on a task of their own needs: each grant's
/// provider by its record id, the secrets store, the test allow-list of
/// fixtures (`None` in production), and the management caller whose change
/// removed them.
#[derive(Clone)]
pub struct Revoker {
    pub providers: HashMap<String, CredentialProvider>,
    pub secrets: Option<Arc<dyn SecretsStore>>,
    pub exact_allowlist: Option<String>,
    pub actor: Option<AuditCallerContext>,
}

/// Delete each of `grants` from the vault, which ends its release at once,
/// then revoke the deleted ones at their authorization servers on a task of
/// their own, at most [`REVOCATION_CONCURRENCY`] at a time, auditing each
/// outcome, so the caller never waits on a vendor. Every grant is tried; the
/// call fails if any could not be deleted, and the ones that were are revoked
/// all the same. The returned task ends when every revocation has.
pub async fn delete_then_revoke(
    vault: &Arc<dyn DelegationVaultStorage>,
    grants: Vec<DelegatedGrant>,
    revoker: Revoker,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let mut deleted = Vec::with_capacity(grants.len());
    let mut failure = None;
    for grant in grants {
        match vault
            .purge_grant(&grant.id, grant.tenant_id.as_deref())
            .await
        {
            Ok(_) => deleted.push(grant),
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    let revocations = tokio::spawn(revoke_removed(deleted, revoker));
    match failure {
        Some(error) => Err(error.context("Failed to delete a delegated grant")),
        None => Ok(revocations),
    }
}

/// Revoke grants already removed from the vault, at most
/// [`REVOCATION_CONCURRENCY`] at a time, logging and auditing each outcome.
pub async fn revoke_removed(
    grants: Vec<DelegatedGrant>,
    revoker: Revoker,
) {
    let revoker = &revoker;
    futures::stream::iter(grants)
        .for_each_concurrent(REVOCATION_CONCURRENCY, |grant| async move {
            match revoker
                .providers
                .get(&grant.credential_provider_id)
            {
                Some(provider) => {
                    revoke_grant(
                        provider,
                        &grant,
                        revoker.secrets.as_ref(),
                        revoker
                            .exact_allowlist
                            .as_deref(),
                        revoker.actor.as_ref(),
                    )
                    .await;
                }
                None => record_revocation(
                    &grant.credential_provider_id,
                    None,
                    &grant,
                    GrantRevocation::skipped(SKIPPED_PROVIDER_MISSING),
                    revoker.actor.as_ref(),
                ),
            }
        })
        .await;
}

/// Audit that an operator purged the grant with this record id without
/// reading it, so it was not revoked at its authorization server.
pub fn record_purge(
    grant_id: &str,
    actor: Option<&AuditCallerContext>,
) {
    tracing::warn!(
        target: "credential_delegation",
        grant_id = %grant_id,
        "A delegated grant was purged without reading it, so it is not revoked at its authorization server"
    );
    super::audit::emit("token_revoked", || {
        let mut event =
            super::audit::audit_event(super::audit::DelegationAuditAction::TokenRevoked, None, None, None, None);
        event.token_id = Some(grant_id.to_string());
        event.detail = Some(GrantRevocation::skipped(SKIPPED_PURGED).detail());
        event.caller = actor.cloned();
        event
    });
}

async fn revoke(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: Option<&Arc<dyn SecretsStore>>,
    exact_allowlist: Option<&str>,
) -> GrantRevocation {
    let client = match RevocationClient::new(provider, secrets, exact_allowlist).await {
        Ok(client) => client,
        Err(revocation) => return revocation,
    };
    match grant.refresh_token.as_deref() {
        Some(refresh_token) => GrantRevocation {
            outcome: client
                .revoke(refresh_token, "refresh_token")
                .await,
            access_token: Some(
                client
                    .revoke(&grant.access_token, "access_token")
                    .await,
            ),
            reason: None,
        },
        None => GrantRevocation::failed(
            client
                .revoke(&grant.access_token, "access_token")
                .await,
        ),
    }
}

/// A provider's client at its revocation endpoint, reached through one pinned
/// connection policy for every token of a grant.
struct RevocationClient<'a> {
    endpoint: &'a str,
    client_id: &'a str,
    method: TokenEndpointAuthMethod,
    secret: Option<zeroize::Zeroizing<String>>,
    http: reqwest::Client,
}

impl<'a> RevocationClient<'a> {
    async fn new(
        provider: &'a CredentialProvider,
        secrets: Option<&Arc<dyn SecretsStore>>,
        exact_allowlist: Option<&str>,
    ) -> Result<Self, GrantRevocation> {
        let endpoint = provider
            .revocation_endpoint
            .as_deref()
            .ok_or(GrantRevocation::failed(RevocationOutcome::NotSupported))?;
        let (Some(client_id), Some(method)) = (provider.client_id.as_deref(), provider.token_endpoint_auth_method)
        else {
            return Err(GrantRevocation::failed(RevocationOutcome::ClientUnavailable));
        };
        let secret = if method.uses_secret() {
            let Some(secrets) = secrets else {
                return Err(GrantRevocation::skipped(SKIPPED_NO_SECRETS_STORE));
            };
            Some(
                client_secret(provider, secrets)
                    .await
                    .ok_or(GrantRevocation::failed(RevocationOutcome::ClientUnavailable))?,
            )
        } else {
            None
        };
        let http = crate::egress::pinned_vendor_client(endpoint, REVOCATION_TIMEOUT, exact_allowlist)
            .await
            .map_err(|error| {
                tracing::warn!(
                    target: "credential_delegation",
                    error = ?error.to_string(),
                    "Revocation endpoint refused by egress policy"
                );
                GrantRevocation::failed(RevocationOutcome::Unreachable)
            })?;
        Ok(Self {
            endpoint,
            client_id,
            method,
            secret,
            http,
        })
    }

    async fn revoke(
        &self,
        token: &str,
        hint: &str,
    ) -> RevocationOutcome {
        let mut form: Vec<(&str, &str)> = vec![("token", token), ("token_type_hint", hint)];
        let mut authorization = None;
        match (self.method, self.secret.as_deref()) {
            (TokenEndpointAuthMethod::None, _) => form.push(("client_id", self.client_id)),
            (TokenEndpointAuthMethod::ClientSecretPost, Some(secret)) => {
                form.push(("client_id", self.client_id));
                form.push(("client_secret", secret.as_str()));
            }
            (TokenEndpointAuthMethod::ClientSecretBasic, Some(secret)) => {
                authorization = Some(basic_authorization(self.client_id, secret));
            }
            _ => return RevocationOutcome::ClientUnavailable,
        }
        let mut request = self
            .http
            .post(self.endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form);
        if let Some(authorization) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, authorization.as_str());
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => RevocationOutcome::Revoked,
            Ok(_) => RevocationOutcome::Refused,
            Err(_) => RevocationOutcome::Unreachable,
        }
    }
}

/// The client secret, from the provider's own tenant or an untenanted secret.
async fn client_secret(
    provider: &CredentialProvider,
    secrets: &Arc<dyn SecretsStore>,
) -> Option<zeroize::Zeroizing<String>> {
    let reference = provider
        .client_secret_secret_ref
        .as_deref()?;
    let secret = secrets
        .get_by_secret_id(reference)
        .await
        .ok()
        .flatten()?;
    crate::tenancy::can_reference(provider.tenant_id.as_deref(), secret.tenant_id.as_deref())
        .then(|| zeroize::Zeroizing::new(secret.value))
}

/// `Basic` credentials as RFC 6749 section 2.3.1 builds them: the client id
/// and secret each form-urlencoded, then joined and base64-encoded.
fn basic_authorization(
    client_id: &str,
    secret: &str,
) -> zeroize::Zeroizing<String> {
    let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let pair = zeroize::Zeroizing::new(format!("{}:{}", encode(client_id), encode(secret)));
    zeroize::Zeroizing::new(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::delegation_vault::grants::GrantKey;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An authorization server that records each request's head and body and
    /// answers every one with `status`, after `delay`, serving connections at
    /// once.
    pub(crate) struct RecordingServer {
        pub(crate) url: String,
        requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl RecordingServer {
        pub(crate) async fn start(status: u16) -> Self {
            Self::start_with_delay(status, Duration::ZERO).await
        }

        pub(crate) async fn start_with_delay(
            status: u16,
            delay: Duration,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = requests.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let recorded = recorded.clone();
                    tokio::spawn(async move {
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let (head, body) = loop {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => break (String::new(), String::new()),
                                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                            }
                            let text = String::from_utf8_lossy(&buffer).into_owned();
                            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                                let length = head
                                    .lines()
                                    .find_map(|line| {
                                        line.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|value| {
                                                value
                                                    .trim()
                                                    .parse::<usize>()
                                                    .unwrap_or(0)
                                            })
                                    })
                                    .unwrap_or(0);
                                if body.len() >= length {
                                    break (head.to_string(), body.to_string());
                                }
                            }
                        };
                        recorded
                            .lock()
                            .unwrap()
                            .push((head, body));
                        tokio::time::sleep(delay).await;
                        let response =
                            format!("HTTP/1.1 {status} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        let _ = stream
                            .write_all(response.as_bytes())
                            .await;
                    });
                }
            });
            Self {
                url: format!("http://{address}/revoke"),
                requests,
            }
        }

        pub(crate) fn origin(&self) -> String {
            self.url
                .trim_end_matches("/revoke")
                .to_string()
        }

        pub(crate) fn requests(&self) -> Vec<(String, String)> {
            self.requests
                .lock()
                .unwrap()
                .clone()
        }

        /// The `token` field of every request received.
        pub(crate) fn revoked_tokens(&self) -> Vec<String> {
            let mut tokens: Vec<String> = self
                .requests()
                .iter()
                .filter_map(|(_, body)| {
                    url::form_urlencoded::parse(body.as_bytes())
                        .find(|(name, _)| name == "token")
                        .map(|(_, token)| token.into_owned())
                })
                .collect();
            tokens.sort();
            tokens
        }
    }

    pub(crate) fn provider(
        revocation_endpoint: Option<&str>,
        method: &str,
        secret_ref: Option<&str>,
    ) -> CredentialProvider {
        serde_json::from_value(serde_json::json!({
            "id": "provider", "tenant_id": "tenant-a", "name": "Vendor", "provider_id": "boris-0123456789ab",
            "issuer": "https://203.0.113.10", "revocation_endpoint": revocation_endpoint,
            "token_endpoint_auth_method": method, "client_id": "client id",
            "client_secret_secret_ref": secret_ref,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    async fn secrets_with(
        directory: &tempfile::TempDir,
        tenant_id: Option<&str>,
    ) -> Arc<dyn SecretsStore> {
        let store = crate::secrets::FilesystemSecretsStore::new(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: tenant_id.map(str::to_string),
                name: "Client secret".to_string(),
                secret_id: "client-secret".to_string(),
                description: None,
                value: "s3cret:&=".to_string(),
                secret_type: "ApiKey".to_string(),
                tags: vec![],
            })
            .await
            .unwrap();
        Arc::new(store)
    }

    fn grant(refresh: bool) -> DelegatedGrant {
        let key = GrantKey::owner(Some("tenant-a"), "surface", "hop", "provider");
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "access-token");
        grant.id = key.record_id();
        if !refresh {
            grant.refresh_token = None;
        }
        grant
    }

    fn form(body: &str) -> Vec<(String, String)> {
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    fn actor() -> AuditCallerContext {
        super::super::audit::management_caller_context(Some("operator"), Some("pat-1")).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_client_revokes_the_refresh_token_then_the_access_token_with_its_client_id() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let revocation =
            revoke(&provider(Some(&server.url), "none", None), &grant(true), Some(&secrets), Some(&server.origin()))
                .await;
        assert_eq!(
            revocation,
            GrantRevocation {
                outcome: RevocationOutcome::Revoked,
                access_token: Some(RevocationOutcome::Revoked),
                reason: None,
            }
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        for (head, _) in &requests {
            assert!(head.starts_with("POST /revoke "), "{head}");
            assert!(
                !head
                    .to_ascii_lowercase()
                    .contains("authorization:"),
                "{head}"
            );
        }
        assert_eq!(
            form(&requests[0].1),
            vec![
                ("token".to_string(), "access-token-refresh".to_string()),
                ("token_type_hint".to_string(), "refresh_token".to_string()),
                ("client_id".to_string(), "client id".to_string()),
            ]
        );
        assert_eq!(
            form(&requests[1].1),
            vec![
                ("token".to_string(), "access-token".to_string()),
                ("token_type_hint".to_string(), "access_token".to_string()),
                ("client_id".to_string(), "client id".to_string()),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_confidential_client_authenticates_as_its_method_says() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let basic = provider(Some(&server.url), "client_secret_basic", Some("client-secret"));
        assert_eq!(
            revoke(&basic, &grant(false), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::Revoked
        );
        let post = provider(Some(&server.url), "client_secret_post", Some("client-secret"));
        assert_eq!(
            revoke(&post, &grant(false), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::Revoked
        );

        let requests = server.requests();
        let expected = base64::engine::general_purpose::STANDARD.encode("client+id:s3cret%3A%26%3D");
        assert!(
            requests[0]
                .0
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Basic {expected}"))),
            "{}",
            requests[0].0
        );
        assert!(
            !requests[0]
                .1
                .contains("client_secret"),
            "{}",
            requests[0].1
        );
        assert!(
            form(&requests[1].1).contains(&("client_secret".to_string(), "s3cret:&=".to_string())),
            "{}",
            requests[1].1
        );
        assert!(
            !requests[1]
                .0
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{}",
            requests[1].0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_without_a_refresh_token_revokes_its_access_token() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let revocation =
            revoke(&provider(Some(&server.url), "none", None), &grant(false), Some(&secrets), Some(&server.origin()))
                .await;
        assert_eq!(revocation, GrantRevocation::failed(RevocationOutcome::Revoked));
        assert_eq!(server.requests().len(), 1);
        let fields = form(&server.requests()[0].1);
        assert!(fields.contains(&("token".to_string(), "access-token".to_string())));
        assert!(fields.contains(&("token_type_hint".to_string(), "access_token".to_string())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_failure_is_an_outcome_and_none_leaves_the_gateway_unguarded() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-b")).await;
        let refusing = RecordingServer::start(400).await;
        assert_eq!(
            revoke(
                &provider(Some(&refusing.url), "none", None),
                &grant(true),
                Some(&secrets),
                Some(&refusing.origin())
            )
            .await,
            GrantRevocation {
                outcome: RevocationOutcome::Refused,
                access_token: Some(RevocationOutcome::Refused),
                reason: None,
            }
        );
        assert_eq!(
            revoke(&provider(None, "none", None), &grant(true), Some(&secrets), None).await,
            GrantRevocation::failed(RevocationOutcome::NotSupported)
        );
        let before = refusing.requests().len();
        assert_eq!(
            revoke(
                &provider(Some(&refusing.url), "client_secret_post", Some("client-secret")),
                &grant(true),
                Some(&secrets),
                Some(&refusing.origin())
            )
            .await
            .outcome,
            RevocationOutcome::ClientUnavailable,
            "another tenant's secret is never sent"
        );
        assert_eq!(
            revoke(&provider(Some(&refusing.url), "none", None), &grant(true), Some(&secrets), None)
                .await
                .outcome,
            RevocationOutcome::Unreachable,
            "a loopback http endpoint is refused without the test allowlist"
        );
        assert_eq!(refusing.requests().len(), before);
        assert_eq!(
            revoke(
                &provider(Some("http://127.0.0.1:1/revoke"), "none", None),
                &grant(true),
                Some(&secrets),
                Some("http://127.0.0.1:1")
            )
            .await
            .outcome,
            RevocationOutcome::Unreachable
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_is_audited_with_its_outcome_and_its_actor() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let provider = provider(Some(&server.url), "none", None);
        let grant = grant(true);
        let actor = actor();
        let (revocation, events) = crate::audit::producer::capture(async {
            revoke_grant(&provider, &grant, Some(&secrets), Some(&server.origin()), Some(&actor)).await
        })
        .await;
        assert_eq!(revocation.outcome, RevocationOutcome::Revoked);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].event, super::super::audit::DelegationAuditAction::TokenRevoked));
        assert_eq!(events[0].token_id.as_deref(), Some(grant.id.as_str()));
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:revoked,access_token:revoked"));
        let caller = events[0]
            .caller
            .as_ref()
            .expect("the audit names the actor");
        assert_eq!(caller.sub.as_deref(), Some("operator"));
        assert_eq!(caller.token_id.as_deref(), Some("pat-1"));
        assert!(!format!("{:?}", events[0]).contains("access-token"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_log_says_what_became_of_a_revocation() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let refusing = RecordingServer::start(400).await;
        let accepting = RecordingServer::start(200).await;

        let logs = FormattedLogs::capture();
        revoke_grant(
            &provider(Some(&refusing.url), "none", None),
            &grant(true),
            Some(&secrets),
            Some(&refusing.origin()),
            None,
        )
        .await;
        let refused = logs.text();
        assert!(refused.contains("WARN"), "{refused}");
        assert!(refused.contains("could not be revoked"), "{refused}");
        assert!(!refused.contains("Revoked a delegated grant"), "{refused}");

        let logs = FormattedLogs::capture();
        revoke_grant(
            &provider(Some(&accepting.url), "none", None),
            &grant(true),
            Some(&secrets),
            Some(&accepting.origin()),
            None,
        )
        .await;
        let revoked = logs.text();
        assert!(revoked.contains("INFO"), "{revoked}");
        assert!(revoked.contains("Revoked a delegated grant"), "{revoked}");
    }

    async fn vault_with(
        directory: &tempfile::TempDir,
        count: usize,
    ) -> (Arc<dyn DelegationVaultStorage>, Vec<DelegatedGrant>) {
        unsafe {
            std::env::set_var("REVOCATION_TEST_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        }
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "REVOCATION_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            super::super::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let mut grants = Vec::new();
        for index in 0..count {
            let key =
                GrantKey::caller(Some("tenant-a"), "surface", "hop", "provider", &format!("{index:064x}")).unwrap();
            grants.push(
                vault
                    .store_grant(crate::delegation_vault::grants::tests::grant(&key, &format!("access-{index}")))
                    .await
                    .unwrap()
                    .grant,
            );
        }
        (vault, grants)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn removing_many_grants_revokes_them_at_once_and_deletes_each() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let delay = Duration::from_millis(300);
        let server = RecordingServer::start_with_delay(200, delay).await;
        let (vault, grants) = vault_with(&directory, REVOCATION_CONCURRENCY).await;
        let providers = HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]);

        let started = std::time::Instant::now();
        remove_grants(&vault, grants.clone(), &providers, &secrets, Some(&server.origin()), Some(&actor()))
            .await
            .unwrap();
        let elapsed = started.elapsed();
        let serial = delay * 2 * u32::try_from(REVOCATION_CONCURRENCY).unwrap();
        assert!(elapsed < serial / 2, "{elapsed:?} is close to revoking one grant after another ({serial:?})");
        assert_eq!(server.revoked_tokens().len(), 2 * REVOCATION_CONCURRENCY);
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Removing grants deletes them first, which ends their release at once,
    /// and revokes them on a task of their own: the caller never waits on a
    /// vendor, however slow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn removed_grants_are_deleted_at_once_and_revoked_in_the_background() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let delay = Duration::from_secs(2);
        let server = RecordingServer::start_with_delay(200, delay).await;
        let (vault, grants) = vault_with(&directory, 3).await;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: Some(actor()),
        };

        let started = std::time::Instant::now();
        let revocations = delete_then_revoke(&vault, grants, revoker)
            .await
            .unwrap();
        assert!(started.elapsed() < delay / 2, "the removal waited on the vendor: {:?}", started.elapsed());
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty(),
            "the grants are deleted before any revocation ends"
        );
        tokio::time::timeout(delay * 4, revocations)
            .await
            .expect("the revocations end")
            .unwrap();
        assert_eq!(server.revoked_tokens().len(), 6);
    }

    /// Without a secrets store a client that authenticates with a secret cannot
    /// revoke, so the grant is removed unrevoked and the audit says why; a
    /// public client still revokes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_a_secrets_store_a_confidential_clients_revocation_is_skipped_and_audited() {
        let server = RecordingServer::start(200).await;
        let confidential = provider(Some(&server.url), "client_secret_post", Some("client-secret"));
        let grant = grant(true);
        let (revocation, events) = crate::audit::producer::capture(async {
            revoke_grant(&confidential, &grant, None, Some(&server.origin()), Some(&actor())).await
        })
        .await;
        assert_eq!(revocation.outcome, RevocationOutcome::Skipped);
        assert!(server.requests().is_empty());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:no_secrets_store"));
        assert_eq!(
            events[0]
                .caller
                .as_ref()
                .and_then(|caller| caller.sub.as_deref()),
            Some("operator")
        );

        let public = provider(Some(&server.url), "none", None);
        assert_eq!(
            revoke_grant(&public, &grant, None, Some(&server.origin()), None)
                .await
                .outcome,
            RevocationOutcome::Revoked
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_removed_grant_whose_provider_is_gone_is_audited_as_skipped() {
        let revoker = Revoker {
            providers: HashMap::new(),
            secrets: None,
            exact_allowlist: None,
            actor: None,
        };
        let ((), events) = crate::audit::producer::capture(revoke_removed(vec![grant(true)], revoker)).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:provider_missing"));
        assert_eq!(events[0].token_id.as_deref(), Some(grant(true).id.as_str()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_whose_provider_is_gone_is_deleted_without_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (vault, grants) = vault_with(&directory, 2).await;
        remove_grants(&vault, grants, &HashMap::new(), &secrets, Some(&server.origin()), None)
            .await
            .unwrap();
        assert!(server.requests().is_empty());
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
