//! RFC 7009 revocation of a grant by binding at its authorization server.
//!
//! The grant's refresh token is revoked, with `token_type_hint=refresh_token`,
//! or its access token when it has none. The client authenticates as its
//! provider's `token_endpoint_auth_method` says. The call goes through the
//! pinned, Strict, `https`-only egress client, with a short timeout, and its
//! response body is never read, echoed or logged. Revocation is best effort:
//! its outcome is returned and audited, and a failed revocation never keeps a
//! grant that is being removed.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;

use super::grants::DelegatedGrant;
use crate::credential_providers::{CredentialProvider, TokenEndpointAuthMethod};
use crate::secrets::SecretsStore;

const REVOCATION_TIMEOUT: Duration = Duration::from_secs(10);

/// What became of one revocation.
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
        }
    }
}

/// Revoke `grant` at `provider`'s revocation endpoint and audit the outcome.
pub async fn revoke_grant(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: &Arc<dyn SecretsStore>,
    exact_allowlist: Option<&str>,
) -> RevocationOutcome {
    let outcome = revoke(provider, grant, secrets, exact_allowlist).await;
    tracing::info!(
        target: "credential_delegation",
        grant_id = %grant.id,
        credential_provider_id = %provider.id,
        outcome = outcome.as_str(),
        "Revoked a delegated grant at its authorization server"
    );
    super::audit::emit("token_revoked", || {
        let mut event = super::audit::audit_event(
            super::audit::DelegationAuditAction::TokenRevoked,
            None,
            None,
            Some(&provider.id),
            Some(&grant.surface_id),
        );
        event.token_id = Some(grant.id.clone());
        event.provider_name = Some(provider.name.clone());
        event.detail = Some(format!("vendor_revocation:{}", outcome.as_str()));
        event
    });
    outcome
}

async fn revoke(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: &Arc<dyn SecretsStore>,
    exact_allowlist: Option<&str>,
) -> RevocationOutcome {
    let Some(endpoint) = provider
        .revocation_endpoint
        .as_deref()
    else {
        return RevocationOutcome::NotSupported;
    };
    let (Some(client_id), Some(method)) = (provider.client_id.as_deref(), provider.token_endpoint_auth_method) else {
        return RevocationOutcome::ClientUnavailable;
    };
    let secret = if method.uses_secret() {
        match client_secret(provider, secrets).await {
            Some(secret) => Some(secret),
            None => return RevocationOutcome::ClientUnavailable,
        }
    } else {
        None
    };
    let (token, hint) = match grant.refresh_token.as_deref() {
        Some(refresh_token) => (refresh_token, "refresh_token"),
        None => (grant.access_token.as_str(), "access_token"),
    };
    let mut form: Vec<(&str, &str)> = vec![("token", token), ("token_type_hint", hint)];
    let mut authorization = None;
    match (method, secret.as_deref()) {
        (TokenEndpointAuthMethod::None, _) => form.push(("client_id", client_id)),
        (TokenEndpointAuthMethod::ClientSecretPost, Some(secret)) => {
            form.push(("client_id", client_id));
            form.push(("client_secret", secret.as_str()));
        }
        (TokenEndpointAuthMethod::ClientSecretBasic, Some(secret)) => {
            authorization = Some(basic_authorization(client_id, secret));
        }
        _ => return RevocationOutcome::ClientUnavailable,
    }
    let client = match crate::egress::pinned_authorization_server_client(endpoint, REVOCATION_TIMEOUT, exact_allowlist)
        .await
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(target: "credential_delegation", error = %error, "Revocation endpoint refused by egress policy");
            return RevocationOutcome::Unreachable;
        }
    };
    let mut request = client
        .post(endpoint)
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
    /// answers every one with `status`.
    pub(crate) struct RecordingServer {
        pub(crate) url: String,
        requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl RecordingServer {
        pub(crate) async fn start(status: u16) -> Self {
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
                    let response =
                        format!("HTTP/1.1 {status} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    let _ = stream
                        .write_all(response.as_bytes())
                        .await;
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_client_revokes_the_refresh_token_with_its_client_id() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let outcome =
            revoke(&provider(Some(&server.url), "none", None), &grant(true), &secrets, Some(&server.origin())).await;
        assert_eq!(outcome, RevocationOutcome::Revoked);
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let (head, body) = &requests[0];
        assert!(head.starts_with("POST /revoke "), "{head}");
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{head}"
        );
        assert_eq!(
            form(body),
            vec![
                ("token".to_string(), "access-token-refresh".to_string()),
                ("token_type_hint".to_string(), "refresh_token".to_string()),
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
        assert_eq!(revoke(&basic, &grant(true), &secrets, Some(&server.origin())).await, RevocationOutcome::Revoked);
        let post = provider(Some(&server.url), "client_secret_post", Some("client-secret"));
        assert_eq!(revoke(&post, &grant(true), &secrets, Some(&server.origin())).await, RevocationOutcome::Revoked);

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
        revoke(&provider(Some(&server.url), "none", None), &grant(false), &secrets, Some(&server.origin())).await;
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
            revoke(&provider(Some(&refusing.url), "none", None), &grant(true), &secrets, Some(&refusing.origin()))
                .await,
            RevocationOutcome::Refused
        );
        assert_eq!(
            revoke(&provider(None, "none", None), &grant(true), &secrets, None).await,
            RevocationOutcome::NotSupported
        );
        assert_eq!(
            revoke(
                &provider(Some(&refusing.url), "client_secret_post", Some("client-secret")),
                &grant(true),
                &secrets,
                Some(&refusing.origin())
            )
            .await,
            RevocationOutcome::ClientUnavailable,
            "another tenant's secret is never sent"
        );
        let before = refusing.requests().len();
        assert_eq!(
            revoke(&provider(Some(&refusing.url), "none", None), &grant(true), &secrets, None).await,
            RevocationOutcome::Unreachable,
            "a loopback http endpoint is refused without the test allowlist"
        );
        assert_eq!(refusing.requests().len(), before);
        assert_eq!(
            revoke(
                &provider(Some("http://127.0.0.1:1/revoke"), "none", None),
                &grant(true),
                &secrets,
                Some("http://127.0.0.1:1")
            )
            .await,
            RevocationOutcome::Unreachable
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_is_audited_with_its_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let provider = provider(Some(&server.url), "none", None);
        let grant = grant(true);
        let (outcome, events) = crate::audit::producer::capture(async {
            revoke_grant(&provider, &grant, &secrets, Some(&server.origin())).await
        })
        .await;
        assert_eq!(outcome, RevocationOutcome::Revoked);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].event, super::super::audit::DelegationAuditAction::TokenRevoked));
        assert_eq!(events[0].token_id.as_deref(), Some(grant.id.as_str()));
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:revoked"));
        assert!(!format!("{:?}", events[0]).contains("access-token"));
    }
}
