//! The gateway's own reads of its surface's agent card from the Target: the card
//! route behind `/.well-known/agent-card.json` and the receiving gateway's policy
//! context. Both attach the surface's Target Authentication as the gateway itself,
//! only at one of [`crate::proxy::paths::agent_card_urls`], with the surface's
//! fallback applied.

use std::time::Duration;

use tracing::{debug, warn};

use crate::config::agent_surface::AgentSurface;
use crate::proxy::handler::CallerAssertion;
use crate::proxy::target_credentials::{
    TargetAuthContext, TargetAuthDecision, TargetCredential, TargetCredentialError, TargetCredentialResolver,
    TargetLeg, apply_target_auth_fallback,
};
use crate::proxy::upstream_body::UpstreamBodyLimits;

/// The surface's fallback refused to fetch the card without the Target credential,
/// and the resolution error that made it refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CardFetchRejected(pub(crate) Option<TargetCredentialError>);

impl CardFetchRejected {
    /// The category of the resolution error, for logs.
    pub(crate) fn reason(self) -> &'static str {
        self.0
            .map_or("unknown", TargetCredentialError::category)
    }
}

/// Who a card read's refusal reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardRead {
    /// The card route, whose refusal answers the caller with a 502.
    AnswersCaller,
    /// The gateway's policy-context read, whose refusal answers no caller.
    PolicyContext,
}

/// The Target credential for the gateway's own fetch of `card_url`: `Ok(None)` when
/// the surface has no Target Authentication or the fallback lets the fetch go
/// without it. A refusal is recorded as a rejected request only for
/// [`CardRead::AnswersCaller`].
pub(crate) async fn card_fetch_credential(
    resolver: &TargetCredentialResolver,
    surface: &AgentSurface,
    card_url: &str,
    via_fabric: bool,
    read: CardRead,
) -> Result<Option<TargetCredential>, CardFetchRejected> {
    let Some(target_auth) = surface.target_auth() else {
        return Ok(None);
    };
    let ctx = TargetAuthContext {
        surface,
        destination: card_url,
        leg: TargetLeg::HttpTarget,
        caller: CallerAssertion::GatewayOriginated,
        via_fabric,
        trace_id: None,
        occupied_headers: &[],
    };
    let resolution = match read {
        CardRead::AnswersCaller => {
            resolver
                .resolve(target_auth, &ctx)
                .await
        }
        CardRead::PolicyContext => {
            resolver
                .resolve_unrecorded(target_auth, &ctx)
                .await
        }
    };
    let error = resolution
        .as_ref()
        .err()
        .copied();
    match apply_target_auth_fallback(target_auth, resolution) {
        TargetAuthDecision::Inject(credential) => Ok(Some(credential)),
        TargetAuthDecision::Continue => Ok(None),
        TargetAuthDecision::Reject => Err(CardFetchRejected(error)),
    }
}

/// Reads the surface's agent card from its `http(s)` Target as the gateway itself:
/// each agent card URL in turn, as a `GET` with no caller input, on a client pinned
/// to the vetted address with redirects off, within `limits`. `None` when no URL
/// yields a JSON card, or when the fallback refuses a fetch without the credential.
pub(crate) async fn fetch_target_card(
    resolver: &TargetCredentialResolver,
    surface: &AgentSurface,
    via_fabric: bool,
    timeout: Duration,
    limits: UpstreamBodyLimits,
) -> Option<serde_json::Value> {
    for card_url in crate::proxy::paths::agent_card_urls(surface) {
        let credential = match card_fetch_credential(
            resolver,
            surface,
            card_url.as_str(),
            via_fabric,
            CardRead::PolicyContext,
        )
        .await
        {
            Ok(credential) => credential,
            Err(rejected) => {
                warn!(
                    surface_id = %surface.surface_id,
                    reason = rejected.reason(),
                    "Agent card not fetched: Target authentication failed"
                );
                return None;
            }
        };
        let candidate = card_url.to_string();
        let client = match tokio::task::spawn_blocking(move || {
            crate::egress::pinned_forward_client(&candidate, timeout)
        })
        .await
        {
            Ok(Ok((client, _target))) => client,
            Ok(Err(error)) => {
                warn!(surface_id = %surface.surface_id, url = %card_url, %error, "Agent card URL blocked by egress policy");
                continue;
            }
            Err(error) => {
                warn!(surface_id = %surface.surface_id, url = %card_url, %error, "Agent card egress validation task failed");
                continue;
            }
        };
        let mut request = client
            .get(card_url.as_str())
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(credential) = credential {
            request = credential.set_on(request);
        }
        let response = match request.send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                debug!(surface_id = %surface.surface_id, url = %card_url, status = %response.status(), "Agent card URL returned non-success status");
                continue;
            }
            Err(error) => {
                debug!(surface_id = %surface.surface_id, url = %card_url, %error, "Agent card fetch failed");
                continue;
            }
        };
        match crate::proxy::upstream_body::read_bounded(response, limits).await {
            Ok(body) => match serde_json::from_slice(&body) {
                Ok(card) => return Some(card),
                Err(error) => {
                    debug!(surface_id = %surface.surface_id, url = %card_url, %error, "Agent card is not JSON");
                }
            },
            Err(error) => {
                debug!(surface_id = %surface.surface_id, url = %card_url, %error, "Agent card exceeded its bounds");
            }
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::{Value, json};

    use super::*;
    use crate::component_tests::helpers::mock_auth_server::MockAuthServer;
    use crate::component_tests::helpers::test_mode::TestModeEnv;
    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    use crate::delegation_vault::gateway_token::{GatewayTokenCache, GrantEgress};
    use crate::proxy::upstream_body::tests::{PATIENT, limits};
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};

    pub(crate) const PROTECTED_AGENT_DID: &str = "did:web:protected-agent.example";

    fn protected_card() -> Value {
        json!({"name": "protected agent", "capabilities": {"extensions": [{
            "uri": crate::config::types::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
            "params": {"did": PROTECTED_AGENT_DID}
        }]}})
    }

    /// A Target whose agent card answers 401 unless the request carries a bearer
    /// token, whose `/redirect` and `/big` misbehave, and which answers any other
    /// request with a JSON-RPC result.
    pub(crate) struct ProtectedTarget {
        pub(crate) url: String,
        pub(crate) requests: Arc<AtomicUsize>,
    }

    impl ProtectedTarget {
        pub(crate) async fn start() -> Self {
            let requests = Arc::new(AtomicUsize::new(0));
            let counted = requests.clone();
            let card = move |headers: axum::http::HeaderMap| {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let bearer = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| value.starts_with("Bearer ") && !value.contains(','));
                    if bearer {
                        (axum::http::StatusCode::OK, protected_card().to_string())
                    } else {
                        (axum::http::StatusCode::UNAUTHORIZED, String::new())
                    }
                }
            };
            let app = axum::Router::new()
                .route("/api/.well-known/agent-card.json", axum::routing::get(card))
                .route("/api/.well-known/agent.json", axum::routing::get(|| async { r#"{"name":"legacy card"}"# }))
                .route("/card", axum::routing::get(|| async { r#"{"name":"card"}"# }))
                .route("/not-json", axum::routing::get(|| async { "this is not a card" }))
                .route("/big", axum::routing::get(|| async { format!(r#"{{"name":"{}"}}"#, "x".repeat(4096)) }))
                .route(
                    "/redirect",
                    axum::routing::get(|| async {
                        (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, "/card")])
                    }),
                )
                .fallback(|| async { r#"{"jsonrpc":"2.0","id":1,"result":{}}"# });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let address = listener
                .local_addr()
                .expect("address");
            tokio::spawn(async move { axum::serve(listener, app).await });
            Self {
                url: format!("http://{address}"),
                requests,
            }
        }
    }

    async fn resolver(
        directory: &std::path::Path,
        auth_server: &MockAuthServer,
    ) -> TargetCredentialResolver {
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            FilesystemSecretsStore::new_async(
                directory
                    .join("secrets")
                    .to_str()
                    .expect("utf-8 path"),
            )
            .await
            .expect("secrets store"),
        );
        for (secret_id, value) in [("GW_ID", "gateway-client"), ("GW_SECRET", "gateway-secret")] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: value.into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .expect("secret");
        }
        let providers: Arc<dyn CredentialProviderStorage> = Arc::new(
            FileSystemCredentialProviderStore::new(directory.join("providers"))
                .await
                .expect("provider store"),
        );
        providers
            .create(
                serde_json::from_value(json!({
                    "id": "cp-card", "name": "card", "provider_id": "card",
                    "provider_type": "oauth2_client_credentials", "token_endpoint": auth_server.token_endpoint(),
                    "client_id_secret_ref": "GW_ID", "client_secret_secret_ref": "GW_SECRET",
                    "created_at": "2026-10-21T00:00:00Z", "updated_at": "2026-10-21T00:00:00Z"
                }))
                .expect("provider JSON"),
            )
            .await
            .expect("provider");
        let tokens = Arc::new(GatewayTokenCache::new(GrantEgress {
            timeout: Duration::from_secs(5),
            exact_allowlist: Some(auth_server.token_endpoint()),
        }));
        TargetCredentialResolver::new(Some(secrets), Some(providers), tokens)
    }

    fn surface(
        target: &str,
        agent_card_path: Option<&str>,
        auth: Option<Value>,
    ) -> AgentSurface {
        let mut surface = json!({
            "surface_id": "card-surface", "name": "card-surface",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/agent", "protocol": "a2a",
                "agent_card_path": agent_card_path,
                "caller_authentication": {"methods": [{
                    "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": []
                }]}},
            "target": {"endpoint": target}
        });
        if let Some(auth) = auth {
            surface["target"]["auth"] = auth;
        }
        serde_json::from_value(surface).expect("surface JSON")
    }

    async fn fetch(
        resolver: &TargetCredentialResolver,
        surface: &AgentSurface,
    ) -> Option<Value> {
        fetch_target_card(resolver, surface, true, PATIENT, limits(1024, Some(PATIENT), PATIENT)).await
    }

    #[tokio::test]
    async fn test_a_protected_card_is_read_with_the_surface_provider_token() {
        let auth_server = MockAuthServer::start().await;
        auth_server.register_client("gateway-client", "gateway-secret");
        let target = ProtectedTarget::start().await;
        let _test_mode = TestModeEnv::enabled(
            &format!("{},{}", target.url, auth_server.egress_allowlist()),
            &auth_server.oauth_endpoint_allowlist(),
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let endpoint = format!("{}/api", target.url);

        let protected = surface(
            &endpoint,
            None,
            Some(
                json!({"method": {"credential_provider": {"credential_provider_id": "cp-card"}}, "fallback": "reject"}),
            ),
        );
        for _ in 0..2 {
            assert_eq!(fetch(&resolver, &protected).await, Some(protected_card()));
        }
        assert_eq!(auth_server.token_request_count(), 1, "the card fetches share one gateway token");

        let anonymous = surface(&endpoint, None, None);
        assert_eq!(
            fetch(&resolver, &anonymous).await,
            Some(json!({"name": "legacy card"})),
            "without a credential the protected card refuses, and the legacy card URL is tried next"
        );

        let missing_secret = surface(
            &endpoint,
            None,
            Some(json!({"method": {"static_secret": {"secret_id": "MISSING", "header_name": "Authorization"}},
                "fallback": "reject"})),
        );
        let before = target
            .requests
            .load(Ordering::SeqCst);
        assert_eq!(fetch(&resolver, &missing_secret).await, None, "the reject fallback fetches no card");
        assert_eq!(
            target
                .requests
                .load(Ordering::SeqCst),
            before,
            "and never asks the Target without the credential"
        );
    }

    #[tokio::test]
    async fn test_only_a_card_read_answered_with_502_records_a_rejected_request() {
        use crate::delegation_vault::audit::DelegationAuditAction::RequestRejected;
        let auth_server = MockAuthServer::start().await;
        let target = ProtectedTarget::start().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let missing_secret = surface(
            &format!("{}/api", target.url),
            None,
            Some(json!({"method": {"static_secret": {"secret_id": "MISSING", "header_name": "Authorization"}},
                "fallback": "reject"})),
        );
        let rejections = |events: &[crate::delegation_vault::audit::DelegationAuditEvent]| {
            events
                .iter()
                .filter(|event| matches!(event.event, RequestRejected { .. }))
                .count()
        };

        let (card, events) = crate::audit::producer::capture(fetch(&resolver, &missing_secret)).await;
        assert_eq!(card, None, "the reject fallback fetches no card");
        assert_eq!(rejections(&events), 0, "the policy-context read answers no caller: {events:?}");

        let card_url = format!("{}/api/.well-known/agent-card.json", target.url);
        let (credential, events) = crate::audit::producer::capture(card_fetch_credential(
            &resolver,
            &missing_secret,
            &card_url,
            false,
            CardRead::AnswersCaller,
        ))
        .await;
        let rejected = credential.map(|_| ());
        assert_eq!(rejected, Err(CardFetchRejected(Some(TargetCredentialError::SecretUnavailable))));
        assert_eq!(rejected.map_err(CardFetchRejected::reason), Err("secret_unavailable"));
        assert_eq!(rejections(&events), 1, "the card route answers 502: {events:?}");
        assert_eq!(
            target
                .requests
                .load(Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn test_a_rejection_names_the_resolution_error_it_came_from() {
        assert_eq!(CardFetchRejected(Some(TargetCredentialError::Forbidden)).reason(), "forbidden");
        assert_eq!(CardFetchRejected(Some(TargetCredentialError::TokenUnavailable)).reason(), "token_unavailable");
        assert_eq!(CardFetchRejected(None).reason(), "unknown");
    }

    #[tokio::test]
    async fn test_the_card_fetch_is_bounded_and_does_not_follow_redirects() {
        let auth_server = MockAuthServer::start().await;
        let target = ProtectedTarget::start().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let at = |path: &str| surface(&format!("{}/api", target.url), Some(path), None);

        assert_eq!(fetch(&resolver, &at("/card")).await, Some(json!({"name": "card"})));
        assert_eq!(fetch(&resolver, &at("/big")).await, None, "an oversized card was read");
        assert_eq!(fetch(&resolver, &at("/redirect")).await, None, "the redirect was followed");
    }

    #[tokio::test]
    async fn test_a_card_that_is_not_json_is_not_returned() {
        let auth_server = MockAuthServer::start().await;
        let target = ProtectedTarget::start().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let surface = surface(&format!("{}/api", target.url), Some("/not-json"), None);

        assert_eq!(fetch(&resolver, &surface).await, None);
    }

    #[tokio::test]
    async fn test_an_unreachable_target_yields_no_card() {
        let auth_server = MockAuthServer::start().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener
                .local_addr()
                .expect("address")
        };
        let surface = surface(&format!("http://{closed}/api"), Some("/card"), None);

        assert_eq!(fetch(&resolver, &surface).await, None);
    }

    #[tokio::test]
    async fn test_a_card_url_blocked_by_egress_policy_yields_no_card() {
        let auth_server = MockAuthServer::start().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let surface = surface("http://169.254.169.254/api", Some("/card"), None);

        assert_eq!(fetch(&resolver, &surface).await, None);
    }

    #[tokio::test]
    async fn test_a_passthrough_fallback_lets_the_card_read_go_without_a_credential() {
        let auth_server = MockAuthServer::start().await;
        let target = ProtectedTarget::start().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let resolver = resolver(directory.path(), &auth_server).await;
        let missing_secret = surface(
            &format!("{}/api", target.url),
            None,
            Some(json!({"method": {"static_secret": {"secret_id": "MISSING", "header_name": "Authorization"}},
                "fallback": "passthrough"})),
        );
        let card_url = format!("{}/api/.well-known/agent-card.json", target.url);

        for read in [CardRead::AnswersCaller, CardRead::PolicyContext] {
            let credential = card_fetch_credential(&resolver, &missing_secret, &card_url, false, read).await;
            assert_eq!(credential.map(|credential| credential.is_some()), Ok(false));
        }
        assert_eq!(fetch(&resolver, &missing_secret).await, Some(json!({"name": "legacy card"})));
    }
}
