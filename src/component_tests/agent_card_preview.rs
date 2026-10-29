//! The Agent card preview: each fetch result of the base route's card, named by a
//! fixed cause and never carrying an upstream body, a credential or a secret id;
//! the served card equal to what the card route answers, and kept when a later fetch
//! fails or the gateway refuses the card; the card fetch pinned by the egress policy
//! with or without a credential; a preview recording no audit event, rejected request,
//! connection or card security count; and the management routes' support checks,
//! tenancy, permissions, snapshot and refresh limit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use super::helpers::admin_api::{AdminApi, listener_origin};
use super::helpers::mock_auth_server::MockAuthServer;
use super::helpers::test_mode::TestModeEnv;
use super::helpers::{GatewayHarness, MockServer, configure_admin_api};

const MARKER: &str = "UPSTREAM-ERROR-MARKER-7f3a";
const STATIC_VALUE: &str = "card-static-secret-value";
const GATEWAY_SECRET: &str = "card-gateway-secret";
const ROUTE: &str = "/agent";

fn agent_card() -> Value {
    json!({
        "name": "card agent", "description": "an agent that signs in its own callers",
        "url": "https://agent.internal/a2a", "version": "1.0", "protocolVersion": "0.3.0",
        "capabilities": {}, "skills": [{"id": "s1", "name": "S1"}],
        "defaultInputModes": ["text"], "defaultOutputModes": ["text"],
        "securitySchemes": {"agent_own_oauth": {"type": "http", "scheme": "bearer"}},
        "security": [{"agent_own_oauth": []}],
        "signatures": [{"protected": "e30", "signature": "c2ln"}]
    })
}

/// A managed agent whose card at `/{kind}/.well-known/agent-card.json` behaves by
/// `kind`, recording the headers of the last request. The `flaky` card behaves as
/// the kind last set with [`CardAgent::set_flaky`].
struct CardAgent {
    url: String,
    requests: Arc<AtomicUsize>,
    last_headers: Arc<Mutex<Option<HeaderMap>>>,
    flaky: Arc<Mutex<&'static str>>,
}

impl CardAgent {
    async fn start() -> Self {
        use axum::response::IntoResponse;

        let requests = Arc::new(AtomicUsize::new(0));
        let last_headers = Arc::new(Mutex::new(None));
        let flaky = Arc::new(Mutex::new("open"));
        let (counted, recorded, behaviour) = (requests.clone(), last_headers.clone(), flaky.clone());
        let card = move |axum::extract::Path(kind): axum::extract::Path<String>, headers: HeaderMap| {
            let (counted, recorded) = (counted.clone(), recorded.clone());
            let kind = if kind == "flaky" {
                behaviour
                    .lock()
                    .expect("flaky lock")
                    .to_string()
            } else {
                kind
            };
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                let bearer = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.starts_with("Bearer "));
                *recorded
                    .lock()
                    .expect("headers lock") = Some(headers);
                let ok = |body: String| (StatusCode::OK, body).into_response();
                match kind.as_str() {
                    "protected" if bearer => ok(agent_card().to_string()),
                    "protected" => (
                        StatusCode::UNAUTHORIZED,
                        [(axum::http::header::WWW_AUTHENTICATE, format!("Bearer realm=\"{MARKER}\""))],
                        MARKER,
                    )
                        .into_response(),
                    "rejects" => (
                        StatusCode::UNAUTHORIZED,
                        [(
                            axum::http::header::WWW_AUTHENTICATE,
                            format!("Bearer error=\"invalid_token\", realm=\"{MARKER}\""),
                        )],
                        MARKER,
                    )
                        .into_response(),
                    "hang" => std::future::pending::<axum::response::Response>().await,
                    "open" => ok(agent_card().to_string()),
                    "broken" => (StatusCode::INTERNAL_SERVER_ERROR, MARKER).into_response(),
                    "forbidden" => (StatusCode::FORBIDDEN, MARKER).into_response(),
                    "notjson" => ok(format!("not json {MARKER}")),
                    "array" => ok("[1, 2]".to_string()),
                    "big" => ok(json!({"name": "big", "description": "x".repeat(4096)}).to_string()),
                    "stall" => (
                        StatusCode::OK,
                        axum::body::Body::from_stream(futures::stream::pending::<Result<String, std::io::Error>>()),
                    )
                        .into_response(),
                    "redirect" => {
                        (StatusCode::FOUND, [(axum::http::header::LOCATION, "/open/.well-known/agent-card.json")])
                            .into_response()
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        };
        let app = axum::Router::new().route("/{kind}/.well-known/agent-card.json", axum::routing::get(card));
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
            last_headers,
            flaky,
        }
    }

    fn set_flaky(
        &self,
        kind: &'static str,
    ) {
        *self
            .flaky
            .lock()
            .expect("flaky lock") = kind;
    }

    fn requests(&self) -> usize {
        self.requests
            .load(Ordering::SeqCst)
    }

    fn last_header(
        &self,
        name: &str,
    ) -> Option<String> {
        self.last_headers
            .lock()
            .expect("headers lock")
            .as_ref()
            .and_then(|headers| headers.get(name))
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }
}

/// A surface's running state with real secret, provider, A2A proxy and metrics
/// stores, as the listener builds it for a request.
struct CardGateway {
    _directory: tempfile::TempDir,
    state: crate::state::ProxyState,
    metrics: Arc<crate::metrics::MetricsStore>,
}

impl CardGateway {
    async fn start(
        auth_server: &MockAuthServer,
        target: Value,
    ) -> Self {
        Self::start_with(auth_server, target, json!({}), None).await
    }

    /// A gateway whose Access Point also has the fields of `access_point_fields`, and
    /// whose strategy store is `strategies` when given.
    async fn start_with(
        auth_server: &MockAuthServer,
        target: Value,
        access_point_fields: Value,
        strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    ) -> Self {
        use crate::a2a_proxies::A2aProxyStore;
        use crate::credential_providers::storage::CredentialProviderStorage;
        use crate::secrets::SecretsStore;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = |name: &str| directory.path().join(name);
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                path("secrets")
                    .to_str()
                    .expect("utf-8 path"),
            )
            .await
            .expect("secrets store"),
        );
        for (secret_id, value) in [
            ("GW_ID", "card-gateway-client"),
            ("GW_SECRET", GATEWAY_SECRET),
            ("GW_UNKNOWN_ID", "unregistered-client"),
            ("CARD_KEY", STATIC_VALUE),
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
                .expect("secret");
        }
        let providers: Arc<dyn CredentialProviderStorage> = Arc::new(
            crate::credential_providers::storage::FileSystemCredentialProviderStore::new(path("providers"))
                .await
                .expect("provider store"),
        );
        for (id, name, client_id_ref) in
            [("cp-card", "card provider", "GW_ID"), ("cp-unregistered", "unregistered provider", "GW_UNKNOWN_ID")]
        {
            let mut provider: crate::credential_providers::CredentialProvider = serde_json::from_value(json!({
                "id": id, "name": name, "provider_id": id,
                "provider_type": "oauth2_client_credentials", "token_endpoint": auth_server.token_endpoint(),
                "client_id_secret_ref": client_id_ref, "client_secret_secret_ref": "GW_SECRET",
                "default_scopes": ["agent.card"],
                "created_at": "2026-10-23T00:00:00Z", "updated_at": "2026-10-23T00:00:00Z"
            }))
            .expect("provider JSON");
            provider.updated_at = chrono::Utc::now();
            providers
                .create(provider)
                .await
                .expect("provider");
        }
        let proxies = Arc::new(
            crate::a2a_proxies::FileSystemA2aProxyStore::new(path("a2a_proxies"))
                .await
                .expect("A2A proxy store"),
        );
        proxies
            .create(
                &serde_json::from_value(json!({
                    "id": "card-proxy", "name": "card proxy", "status": "active",
                    "backend": {"kind": "copilot_direct_line", "secret_id": "CARD_KEY"},
                    "agent_card": {"name": "generated agent", "description": "the gateway generates this card"},
                    "created_at": "2026-10-23T00:00:00Z", "updated_at": "2026-10-23T00:00:00Z"
                }))
                .expect("A2A proxy JSON"),
            )
            .await
            .expect("A2A proxy");
        let mut access_point = json!({"listen_address": "https://gateway.example", "route": ROUTE, "protocol": "a2a"});
        if let Value::Object(fields) = access_point_fields {
            for (key, value) in fields {
                access_point[key.as_str()] = value;
            }
        }
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": format!("card-preview-{}", uuid::Uuid::new_v4()), "name": "card-preview",
            "access_point": access_point,
            "target": target
        }))
        .expect("surface JSON");
        let sessions = Arc::new(crate::didauth::DidAuthSessionStore::new());
        let strategies: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage> = match strategies {
            Some(strategies) => strategies,
            None => Arc::new(
                crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(path("strategies"))
                    .await
                    .expect("strategy store"),
            ),
        };
        let middleware = Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            sessions.clone(),
            strategies,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            Some(secrets.clone()),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        ));
        let network = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 443,
                "protocol": "https", "external_urls": ["https://gateway.example"]}],
            "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
        }))
        .expect("network JSON");
        let config = serde_json::from_value(json!({
            "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
            "a2a": {"max_body_size": 2048, "timeout_seconds": 2},
            "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [], "categories": []}
        }))
        .expect("config JSON");
        let metrics = Arc::new(crate::metrics::MetricsStore::new(100));
        let state = crate::state::ProxyState {
            config: Arc::new(config),
            network_config: Arc::new(network),
            client: reqwest::Client::new(),
            metrics_store: Some(metrics.clone()),
            identity_rules_engine: None,
            identity_selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
            task_monitor: None,
            task_id: None,
            ws_state: None,
            listener_manager: Arc::new(tokio::sync::RwLock::new(None)),
            secrets_store: Some(secrets),
            certificates_store: None,
            vc_issuer: None,
            policy_manager: None,
            gateway_policy_manager: None,
            didauth_session_store: sessions,
            transaction_store: None,
            mpp_transaction_store: None,
            trust_registry_listener_manager: None,
            source_auth_middleware: Some(middleware),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_log_manager: None,
            credential_provider_store: Some(providers),
            delegation_vault_store: None,
            gateway_base_url: Some("https://gateway.example".into()),
            transit_token_issuer: None,
            mcp_proxy_store: None,
            a2a_proxy_store: Some(proxies),
            active_variant_alias: None,
            active_variant_id: None,
            variant_resolution_error: None,
            access_point_declaration: None,
            surface: Arc::new(surface),
        };
        Self {
            _directory: directory,
            state,
            metrics,
        }
    }

    /// The preview as the management API serializes it.
    async fn preview(&self) -> Value {
        let preview = crate::proxy::card_preview::fetch_preview(&self.state).await;
        serde_json::to_value(preview).expect("serialize preview")
    }

    /// What an anonymous caller of the card route gets.
    async fn live(&self) -> (u16, Value) {
        let response = crate::proxy::handler::handle_agent_card(
            axum::extract::ConnectInfo(
                "127.0.0.1:12345"
                    .parse()
                    .expect("address"),
            ),
            axum::extract::State(self.state.clone()),
            HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|response| response);
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("card body");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// How many surfaces have a recorded connection; each fixture runs one surface.
    async fn connections(&self) -> usize {
        self.metrics
            .get_hierarchical_connections()
            .await
            .len()
    }

    fn surface_id(&self) -> &str {
        &self.state.surface.surface_id
    }
}

fn target(
    endpoint: String,
    auth: Option<Value>,
) -> Value {
    let mut target = json!({"endpoint": endpoint});
    if let Some(auth) = auth {
        target["auth"] = auth;
    }
    target
}

fn provider_auth(provider_id: &str) -> Value {
    json!({"method": {"credential_provider": {"credential_provider_id": provider_id}}, "fallback": "reject"})
}

fn static_auth(secret_id: &str) -> Value {
    json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "Authorization",
        "header_format": "Bearer {value}"}}, "fallback": "reject"})
}

fn fetch_of(preview: &Value) -> (String, Value, Value) {
    (
        preview["fetch"]["status"]
            .as_str()
            .expect("fetch status")
            .to_string(),
        preview["fetch"]["cause"].clone(),
        preview["fetch"]["http_status"].clone(),
    )
}

/// The serialized preview never carries an upstream body or header, a credential,
/// a secret, a secret id or a provider id.
fn assert_redacted(
    preview: &Value,
    extra: &[&str],
) {
    let text = preview.to_string();
    for needle in [MARKER, STATIC_VALUE, GATEWAY_SECRET, "GW_SECRET", "GW_ID", "CARD_KEY", "cp-card", "cp-unregistered"]
        .iter()
        .chain(extra)
    {
        assert!(!text.contains(needle), "the preview carries {needle}: {text}");
    }
    assert!(!text.contains("Bearer ey"), "the preview carries a token: {text}");
}

/// The `RequestRejected` and `AuthFailed` audit events among `events`.
fn rejections_and_auth_failures(events: &[crate::delegation_vault::audit::DelegationAuditEvent]) -> (usize, usize) {
    use crate::delegation_vault::audit::DelegationAuditAction::{self, AuthFailed, RequestRejected};
    let count = |wanted: fn(&DelegationAuditAction) -> bool| {
        events
            .iter()
            .filter(|event| wanted(&event.event))
            .count()
    };
    (count(|event| matches!(event, RequestRejected { .. })), count(|event| matches!(event, AuthFailed { .. })))
}

/// Run `body` on a multi-threaded runtime with a stack large enough for the card
/// route's future, as the request path runs it.
fn run<F>(body: impl FnOnce(MockAuthServer, CardAgent) -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_client("card-gateway-client", GATEWAY_SECRET);
    let agent = runtime.block_on(CardAgent::start());
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", agent.url, auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || handle.block_on(body(auth_server, agent)))
        .expect("test thread")
        .join()
        .expect("checks pass");
}

#[test]
fn a_protected_card_is_previewed_through_the_provider_and_after_is_what_callers_get() {
    run(|auth_server, agent| async move {
        let gateway = CardGateway::start(
            &auth_server,
            target(format!("{}/protected", agent.url), Some(provider_auth("cp-card"))),
        )
        .await;
        let before_fetch = std::time::SystemTime::now();
        let preview = gateway.preview().await;

        assert_eq!(fetch_of(&preview), ("ok".to_string(), Value::Null, Value::Null), "{preview}");
        assert_eq!(preview["supported"], true);
        assert_eq!(preview["generated"], false);
        assert_eq!(preview["cached"], false);
        assert_eq!(preview["variant"], Value::Null);
        assert_eq!(preview["auth"]["kind"], "credential_provider");
        assert_eq!(preview["auth"]["result"], "sent");
        assert_eq!(preview["auth"]["provider_name"], "card provider");
        assert_eq!(preview["auth"]["failure"], Value::Null);
        let expires_at = chrono::DateTime::parse_from_rfc3339(
            preview["auth"]["token_expires_at"]
                .as_str()
                .expect("a gateway token expiry"),
        )
        .expect("RFC 3339 expiry");
        assert!(std::time::SystemTime::from(expires_at) > before_fetch);
        assert_eq!(preview["source_url"], format!("{}/protected/.well-known/agent-card.json", agent.url));
        assert_eq!(preview["source_url_query_hidden"], false);
        assert_eq!(preview["served_url"], format!("https://gateway.example{ROUTE}/.well-known/agent-card.json"));
        assert_eq!(preview["payment_required"], false);
        assert_eq!(
            preview["outcome"],
            json!({"variant": null, "outcome": "pass_through", "reason": null,
                "resource": format!("https://gateway.example{ROUTE}")})
        );
        assert_eq!(preview["before"], agent_card(), "before is the agent's own card, security and signatures kept");
        assert_eq!(preview["after"]["securitySchemes"], agent_card()["securitySchemes"]);
        assert_eq!(
            preview["after"]["signatures"],
            agent_card()["signatures"],
            "a card that does not declare keeps the agent's signatures"
        );
        assert_eq!(preview["after"]["url"], format!("https://gateway.example{ROUTE}"));
        assert_eq!(
            preview["before_bytes"],
            serde_json::to_vec(&agent_card())
                .expect("bytes")
                .len()
        );
        assert_eq!(
            preview["after_bytes"],
            serde_json::to_vec(&preview["after"])
                .expect("bytes")
                .len()
        );
        assert_eq!(preview["display_limit_bytes"], 262_144);
        assert_eq!(preview["last_caller_fetch"], Value::Null);
        assert!(
            agent
                .last_header("authorization")
                .is_some_and(|value| value.starts_with("Bearer ey")),
            "the agent received the gateway token"
        );
        assert_eq!(agent.last_header("cookie"), None);
        assert_redacted(&preview, &[]);

        let (status, served) = gateway.live().await;
        assert_eq!(status, 200);
        assert_eq!(preview["after"], served, "after is exactly the card the route serves");
        assert_eq!(auth_server.token_request_count(), 1, "the preview and the route share one gateway token");

        let static_secret =
            CardGateway::start(&auth_server, target(format!("{}/protected", agent.url), Some(static_auth("CARD_KEY"))))
                .await;
        let preview = static_secret.preview().await;
        assert_eq!(fetch_of(&preview).0, "ok", "{preview}");
        assert_eq!(
            preview["auth"],
            json!({"kind": "static_secret", "result": "sent", "provider_name": null,
                "token_expires_at": null, "failure": null})
        );
        assert_eq!(agent.last_header("authorization"), Some(format!("Bearer {STATIC_VALUE}")));
        assert_redacted(&preview, &[]);
    });
}

#[test]
fn each_failed_fetch_names_its_cause_and_never_carries_the_agent_answer() {
    run(|auth_server, agent| async move {
        let no_auth = CardGateway::start(&auth_server, target(format!("{}/protected", agent.url), None)).await;
        let preview = no_auth.preview().await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("needs_token"), json!(401)), "{preview}");
        assert_eq!(
            preview["auth"],
            json!({"kind": "none", "result": "not_configured", "provider_name": null,
                "token_expires_at": null, "failure": null})
        );
        assert_eq!(preview["before"], Value::Null);
        assert_eq!(preview["after"], Value::Null, "nothing was served yet, so there is no served card");
        assert_eq!(preview["before_bytes"], Value::Null);
        assert_eq!(preview["after_bytes"], Value::Null);
        assert_eq!(
            preview["outcome"]["outcome"], "pass_through",
            "an unprocessed card reports the base route's declaration"
        );
        assert_redacted(&preview, &[]);

        for (kind, cause, http_status) in [
            ("broken", "upstream_error", json!(500)),
            ("forbidden", "forbidden", json!(403)),
            ("missing", "not_found", json!(404)),
            ("notjson", "invalid_card", Value::Null),
            ("array", "invalid_card", Value::Null),
            ("big", "too_large", Value::Null),
            ("stall", "timeout", Value::Null),
        ] {
            let gateway = CardGateway::start(&auth_server, target(format!("{}/{kind}", agent.url), None)).await;
            let preview = gateway.preview().await;
            assert_eq!(fetch_of(&preview), ("failed".to_string(), json!(cause), http_status), "{kind}: {preview}");
            assert_eq!(preview["after"], Value::Null, "{kind}: nothing was served yet");
            assert_redacted(&preview, &[]);
        }

        let redirect =
            CardGateway::start(&auth_server, target(format!("{}/redirect", agent.url), Some(static_auth("CARD_KEY"))))
                .await;
        let preview = redirect.preview().await;
        assert_eq!(
            fetch_of(&preview),
            ("failed".to_string(), json!("redirected"), json!(302)),
            "a credentialed fetch never follows a redirect: {preview}"
        );

        let unreachable = CardGateway::start(&auth_server, target("http://127.0.0.1:1/agent".into(), None)).await;
        let preview = unreachable.preview().await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("unreachable"), Value::Null), "{preview}");

        let blocked = CardGateway::start(
            &auth_server,
            target("http://169.254.169.254/agent".into(), Some(static_auth("CARD_KEY"))),
        )
        .await;
        let preview = blocked.preview().await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("blocked_by_egress"), Value::Null), "{preview}");
        assert_eq!(preview["auth"]["result"], "sent", "the credential resolved; the address is what was refused");

        let metadata =
            CardGateway::start(&auth_server, target("http://169.254.169.254/latest/meta-data".into(), None)).await;
        let (preview, events) = crate::audit::producer::capture(metadata.preview()).await;
        assert_eq!(
            fetch_of(&preview),
            ("failed".to_string(), json!("blocked_by_egress"), Value::Null),
            "a fetch without a credential is pinned too: {preview}"
        );
        assert_eq!(preview["auth"]["result"], "not_configured");
        assert_eq!(preview["before"], Value::Null, "nothing the metadata address holds is read");
        assert_eq!(preview["before_bytes"], Value::Null);
        assert_eq!(rejections_and_auth_failures(&events), (0, 0), "{events:?}");
        let ((status, _), events) = crate::audit::producer::capture(metadata.live()).await;
        assert_eq!(status, 403, "the card route refuses the metadata address");
        assert_eq!(rejections_and_auth_failures(&events), (1, 0), "{events:?}");

        let keyed =
            CardGateway::start(&auth_server, target(format!("{}/open?code=SECRET-QUERY", agent.url), None)).await;
        let preview = keyed.preview().await;
        assert_eq!(preview["source_url"], format!("{}/open", agent.url));
        assert_eq!(preview["source_url_query_hidden"], true);
        assert_redacted(&preview, &["SECRET-QUERY"]);
    });
}

#[test]
fn a_failing_managed_card_still_previews_the_card_callers_were_last_served() {
    run(|auth_server, agent| async move {
        let gateway = CardGateway::start(&auth_server, target(format!("{}/flaky", agent.url), None)).await;
        let (status, served) = gateway.live().await;
        assert_eq!(status, 200, "{served}");
        let served_bytes = serde_json::to_vec(&served)
            .expect("bytes")
            .len();

        for (kind, cause, http_status) in [
            ("protected", "needs_token", json!(401)),
            ("forbidden", "forbidden", json!(403)),
            ("missing", "not_found", json!(404)),
            ("broken", "upstream_error", json!(500)),
            ("notjson", "invalid_card", Value::Null),
            ("big", "too_large", Value::Null),
            ("stall", "timeout", Value::Null),
        ] {
            agent.set_flaky(kind);
            let (preview, events) = crate::audit::producer::capture(gateway.preview()).await;
            assert_eq!(fetch_of(&preview), ("failed".to_string(), json!(cause), http_status), "{kind}: {preview}");
            assert_eq!(preview["after"], served, "{kind}: the card the gateway serves is kept");
            assert_eq!(preview["after_bytes"], served_bytes, "{kind}");
            assert_eq!(preview["before"], Value::Null, "{kind}: the failed fetch carries no agent card");
            assert_eq!(preview["before_bytes"], Value::Null, "{kind}");
            assert_eq!(rejections_and_auth_failures(&events), (0, 0), "{kind}: {events:?}");
            assert_redacted(&preview, &[]);
        }

        agent.set_flaky("open");
        let preview = gateway.preview().await;
        assert_eq!(fetch_of(&preview).0, "ok", "{preview}");
        assert_eq!(preview["after"], served, "a recovered agent previews the card callers get");

        let never_served = CardGateway::start(&auth_server, target(format!("{}/flaky", agent.url), None)).await;
        agent.set_flaky("broken");
        let preview = never_served.preview().await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("upstream_error"), json!(500)), "{preview}");
        assert_eq!(preview["after"], Value::Null, "a surface never served has no served card to show");
        assert_eq!(preview["after_bytes"], Value::Null);
    });
}

#[test]
fn a_target_authentication_failure_is_reported_without_asking_the_agent() {
    run(|auth_server, agent| async move {
        for (auth, failure) in [
            (provider_auth("cp-unregistered"), "token_unavailable"),
            (static_auth("MISSING_KEY"), "secret_unavailable"),
        ] {
            let gateway =
                CardGateway::start(&auth_server, target(format!("{}/protected", agent.url), Some(auth))).await;
            let requests = agent.requests();
            let (preview, events) = crate::audit::producer::capture(gateway.preview()).await;
            assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("auth_failed"), Value::Null), "{preview}");
            assert_eq!(preview["auth"]["result"], "failed");
            assert_eq!(preview["auth"]["failure"], failure);
            assert_eq!(preview["auth"]["provider_name"], Value::Null);
            assert_eq!(agent.requests(), requests, "the reject fallback never asks the agent");
            assert_redacted(&preview, &["MISSING_KEY", "unregistered-client"]);
            assert_eq!(
                rejections_and_auth_failures(&events),
                (0, 0),
                "{failure}: an operator preview answers no caller, so it records no rejection: {events:?}"
            );

            let ((status, _), events) = crate::audit::producer::capture(gateway.live()).await;
            assert_eq!(status, 502, "{failure}");
            assert_eq!(
                rejections_and_auth_failures(&events),
                (1, 0),
                "{failure}: the card route answers a caller, so it records the rejected request: {events:?}"
            );
        }

        let unauthenticated = CardGateway::start(&auth_server, target(format!("{}/protected", agent.url), None)).await;
        assert_eq!(
            fetch_of(
                &unauthenticated
                    .preview()
                    .await
            )
            .1,
            "needs_token"
        );

        let rejecting_agent =
            CardGateway::start(&auth_server, target(format!("{}/forbidden", agent.url), Some(static_auth("CARD_KEY"))))
                .await;
        let preview = rejecting_agent
            .preview()
            .await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("forbidden"), json!(403)), "{preview}");
        assert_eq!(preview["auth"]["result"], "sent");

        let refused_credential =
            CardGateway::start(&auth_server, target(format!("{}/rejects", agent.url), Some(static_auth("CARD_KEY"))))
                .await;
        let preview = refused_credential
            .preview()
            .await;
        assert_eq!(
            fetch_of(&preview),
            ("failed".to_string(), json!("auth_failed"), json!(401)),
            "the agent refused the credential the gateway sent: {preview}"
        );
        assert_eq!(preview["auth"]["result"], "sent");
        assert_redacted(&preview, &["invalid_token"]);
        let (status, body) = refused_credential
            .live()
            .await;
        assert_eq!(status, 401, "{body}");
        assert!(
            body.to_string()
                .contains("Upstream error: 401 Unauthorized"),
            "{body}"
        );
    });
}

#[test]
fn the_live_route_keeps_its_answers_and_records_the_last_caller_fetch() {
    run(|auth_server, agent| async move {
        let cases = [
            (target(format!("{}/protected", agent.url), None), 401, "Upstream error: 401 Unauthorized", "needs_token"),
            (
                target(format!("{}/protected", agent.url), Some(static_auth("MISSING_KEY"))),
                502,
                crate::proxy::target_credentials::TARGET_AUTH_FAILED,
                "auth_failed",
            ),
            (
                target(format!("{}/redirect", agent.url), Some(static_auth("CARD_KEY"))),
                502,
                "Upstream redirected",
                "redirected",
            ),
            (target(format!("{}/notjson", agent.url), None), 502, "Invalid JSON from upstream", "invalid_card"),
            (
                target(format!("{}/array", agent.url), None),
                502,
                crate::a2a::url_rewriter::AGENT_CARD_REFUSAL,
                "invalid_card",
            ),
            (target(format!("{}/big", agent.url), None), 502, "Upstream response too large", "too_large"),
            (target(format!("{}/stall", agent.url), None), 504, "Upstream response timed out", "timeout"),
        ];
        for (target, status, detail, cause) in cases {
            let gateway = CardGateway::start(&auth_server, target).await;
            let (answered, body) = gateway.live().await;
            assert_eq!(answered, status, "{cause}: {body}");
            assert!(
                body.to_string()
                    .contains(detail),
                "{cause}: {body}"
            );
            let recorded = crate::proxy::card_preview::card_preview_service()
                .last_caller_fetch(gateway.surface_id())
                .await
                .expect("the caller fetch is recorded");
            assert_eq!(serde_json::to_value(recorded.cause).expect("cause JSON"), json!(cause), "{cause}");
        }

        let open = CardGateway::start(&auth_server, target(format!("{}/open", agent.url), None)).await;
        let (status, _) = open.live().await;
        assert_eq!(status, 200);
        let recorded = crate::proxy::card_preview::card_preview_service()
            .last_caller_fetch(open.surface_id())
            .await
            .expect("recorded");
        assert_eq!(serde_json::to_value(&recorded).expect("JSON")["status"], "ok");
        assert_eq!(recorded.cause, None);
    });
}

#[test]
fn a_preview_records_no_connection_and_a_served_card_does() {
    run(|auth_server, agent| async move {
        for kind in ["open", "broken"] {
            let gateway = CardGateway::start(&auth_server, target(format!("{}/{kind}", agent.url), None)).await;
            gateway.preview().await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert_eq!(gateway.connections().await, 0, "{kind}: a preview records no connection");
            assert_eq!(
                crate::proxy::card_preview::card_preview_service()
                    .last_caller_fetch(gateway.surface_id())
                    .await,
                None,
                "{kind}: a preview is not a caller fetch"
            );
            gateway.live().await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert_eq!(gateway.connections().await, 1, "{kind}: a served card or fault is recorded");
        }
    });
}

#[test]
fn a_preview_leaves_the_card_security_counter_alone_and_a_served_card_counts_once() {
    run(|auth_server, agent| async move {
        let api_key = |field: &str| json!({"type": "api_key", "extraction": {"source": "http_header", "field": field}, "secret_id": "CARD_KEY"});
        let gateway = CardGateway::start_with(
            &auth_server,
            target(format!("{}/open", agent.url), None),
            json!({"caller_authentication": {"methods": [api_key("X-First-Key"), api_key("X-Second-Key")]}}),
            None,
        )
        .await;
        let served_cards = || {
            crate::metrics::backends::prometheus::CARD_SECURITY
                .with_label_values(&["strip", "multiple_methods"])
                .get()
        };
        let before = served_cards();

        let preview = gateway.preview().await;
        assert_eq!(fetch_of(&preview).0, "ok", "{preview}");
        assert_eq!(preview["outcome"]["outcome"], "strip");
        assert_eq!(preview["outcome"]["reason"], "multiple_methods");
        assert_eq!(served_cards(), before, "a preview is not a served card");

        let (status, _) = gateway.live().await;
        assert_eq!(status, 200);
        assert_eq!(served_cards() - before, 1, "the card route counts the card it serves");
    });
}

/// A strategy store that holds no strategy, and fails every read while `unreadable`
/// is set.
struct Strategies {
    unreadable: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl crate::jwt_bearer::JwtVerificationStrategyStorage for Strategies {
    async fn create(
        &self,
        _strategy: crate::jwt_bearer::models::JwtVerificationStrategy,
    ) -> anyhow::Result<crate::jwt_bearer::models::JwtVerificationStrategy> {
        anyhow::bail!("read-only")
    }

    async fn get(
        &self,
        _id: &str,
    ) -> anyhow::Result<Option<crate::jwt_bearer::models::JwtVerificationStrategy>> {
        if self
            .unreadable
            .load(Ordering::SeqCst)
        {
            anyhow::bail!("strategy store unavailable");
        }
        Ok(None)
    }

    async fn list(&self) -> anyhow::Result<Vec<crate::jwt_bearer::models::JwtVerificationStrategy>> {
        Ok(Vec::new())
    }

    async fn update(
        &self,
        _strategy: crate::jwt_bearer::models::JwtVerificationStrategy,
    ) -> anyhow::Result<crate::jwt_bearer::models::JwtVerificationStrategy> {
        anyhow::bail!("read-only")
    }

    async fn delete(
        &self,
        _id: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("read-only")
    }
}

#[test]
fn a_card_the_gateway_refuses_to_serve_is_previewed_as_not_served() {
    run(|auth_server, agent| async move {
        let unreadable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let declaring = json!({"caller_authentication": {"methods": [{
            "type": "jwt_bearer", "jwt_verification_strategy_id": "card-strategy",
            "audiences": [format!("https://gateway.example{ROUTE}")], "required_scopes": ["agent.invoke"]
        }]}});
        let gateway = CardGateway::start_with(
            &auth_server,
            target(format!("{}/open", agent.url), None),
            declaring,
            Some(Arc::new(Strategies { unreadable: unreadable.clone() })),
        )
        .await;

        unreadable.store(true, Ordering::SeqCst);
        let preview = gateway.preview().await;
        assert_eq!(fetch_of(&preview), ("not_served".to_string(), json!("rewrite_failed"), Value::Null), "{preview}");
        assert_eq!(preview["before"], agent_card(), "the agent's card was obtained");
        assert_eq!(preview["after"], Value::Null, "nothing was served yet");
        assert_eq!(preview["after_bytes"], Value::Null);
        let (status, body) = gateway.live().await;
        assert_eq!(status, 502, "{body}");
        assert!(
            body.to_string()
                .contains(crate::a2a::url_rewriter::AGENT_CARD_REFUSAL),
            "{body}"
        );

        unreadable.store(false, Ordering::SeqCst);
        let (status, served) = gateway.live().await;
        assert_eq!(status, 200, "{served}");
        unreadable.store(true, Ordering::SeqCst);
        let preview = gateway.preview().await;
        assert_eq!(fetch_of(&preview).0, "not_served", "{preview}");
        assert_eq!(preview["before"], agent_card());
        assert_eq!(preview["after"], served, "the card callers were last served is kept");
    });
}

#[test]
fn a_preview_past_its_deadline_reports_a_timeout_and_keeps_the_served_card() {
    run(|auth_server, agent| async move {
        let gateway = CardGateway::start(&auth_server, target(format!("{}/flaky", agent.url), None)).await;
        let (status, served) = gateway.live().await;
        assert_eq!(status, 200, "{served}");

        agent.set_flaky("hang");
        let deadline = std::time::Duration::from_millis(300);
        let (preview, events) = crate::audit::producer::capture(async {
            serde_json::to_value(crate::proxy::card_preview::fetch_preview_within(&gateway.state, deadline).await)
                .expect("serialize preview")
        })
        .await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("timeout"), Value::Null), "{preview}");
        assert!(
            preview["fetch"]["duration_ms"]
                .as_u64()
                .is_some_and(|duration| duration >= 300),
            "{preview}"
        );
        assert_eq!(preview["outcome"]["outcome"], "pass_through", "the base route's declaration is reported");
        assert_eq!(preview["before"], Value::Null);
        assert_eq!(preview["after"], served, "the card callers were last served is kept");
        assert_eq!(rejections_and_auth_failures(&events), (0, 0), "{events:?}");
    });
}

#[test]
fn a_generated_card_has_no_agent_card_to_compare() {
    run(|auth_server, _agent| async move {
        let gateway = CardGateway::start(&auth_server, target("a2a-proxy://card-proxy".into(), None)).await;
        let preview = gateway.preview().await;
        assert_eq!(fetch_of(&preview).0, "ok", "{preview}");
        assert_eq!(preview["generated"], true);
        assert_eq!(preview["before"], Value::Null);
        assert_eq!(preview["before_bytes"], Value::Null);
        assert_eq!(preview["source_url"], Value::Null);
        assert_eq!(preview["auth"]["kind"], "none");
        assert_eq!(preview["after"]["name"], "generated agent");
        let (status, served) = gateway.live().await;
        assert_eq!(status, 200);
        assert_eq!(preview["after"], served);

        let missing = CardGateway::start(&auth_server, target("a2a-proxy://no-such-proxy".into(), None)).await;
        let preview = missing.preview().await;
        assert_eq!(fetch_of(&preview), ("failed".to_string(), json!("proxy_unavailable"), Value::Null));
        assert_eq!(preview["generated"], true);
    });
}

#[test]
fn the_base_route_preview_runs_what_a_bare_card_request_gets() {
    run(|auth_server, agent| async move {
        let gateway = CardGateway::start(&auth_server, target(format!("{}/open", agent.url), None)).await;
        let mut surface = (*gateway.state.surface).clone();
        surface.variants = vec![
            serde_json::from_value(json!({
                "id": "vc-default", "alias": "default", "name": "default", "description": "",
                "enabled": true, "overrides": {}
            }))
            .expect("variant JSON"),
        ];
        surface.default_variant_id = Some("vc-default".into());
        let listener = super::helpers::direct_router_state(&gateway.state, surface.clone());
        {
            let mut channels = listener
                .channels
                .write()
                .await;
            let engines = channels[0].base_engines();
            channels[0]
                .variant_engines
                .insert("vc-default".into(), engines);
        }

        assert!(
            listener
                .base_proxy_state("no-such-surface")
                .await
                .is_none(),
            "a surface this listener does not run has no state"
        );
        let state = listener
            .base_proxy_state(&surface.surface_id)
            .await
            .expect("the running surface");
        assert_eq!(
            state
                .active_variant_id
                .as_deref(),
            Some("vc-default"),
            "the bare route serves the default variant"
        );
        assert_eq!(state.active_variant_alias, None);
        let preview = serde_json::to_value(crate::proxy::card_preview::fetch_preview(&state).await).expect("JSON");
        assert_eq!(fetch_of(&preview).0, "ok", "{preview}");

        let bare_card_request = |listener: crate::state::MultiSurfaceProxyState| {
            crate::proxy::handler::multi_channel_proxy_handler(
                axum::extract::ConnectInfo(
                    "127.0.0.1:12345"
                        .parse()
                        .expect("address"),
                ),
                axum::extract::State(listener),
                axum::http::Request::builder()
                    .uri(format!("{ROUTE}/.well-known/agent-card.json"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
        };
        let response = bare_card_request(listener.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let served: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("card body"),
        )
        .expect("card JSON");
        assert_eq!(preview["after"], served, "after is the card the bare route serves");
        let recorded = crate::proxy::card_preview::card_preview_service()
            .last_caller_fetch(&surface.surface_id)
            .await
            .expect("a bare-route request is a base-route caller fetch");
        assert_eq!(recorded.cause, None);

        listener
            .resolved_surface_cache
            .upsert(&surface)
            .expect("the enabled surface is cached");
        let mut disabled = surface.clone();
        disabled.variants[0].enabled = false;
        listener
            .channels
            .write()
            .await[0]
            .surface = Arc::new(disabled);
        assert!(
            listener
                .base_proxy_state(&surface.surface_id)
                .await
                .is_none(),
            "a disabled default variant serves no card on the base route, even with an older snapshot cached"
        );
        assert_eq!(
            bare_card_request(listener.clone())
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let mut missing = surface.clone();
        missing.default_variant_id = Some("vc-missing".into());
        listener
            .channels
            .write()
            .await[0]
            .surface = Arc::new(missing);
        assert!(
            listener
                .base_proxy_state(&surface.surface_id)
                .await
                .is_none(),
            "a default variant the surface does not hold serves no card"
        );
        assert_eq!(
            bare_card_request(listener)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    });
}

impl AdminApi {
    async fn card(
        &self,
        surface_id: &str,
    ) -> (u16, Value) {
        let (status, body, _) = self
            .send(
                self.client
                    .get(self.url(&format!("surfaces/{surface_id}/agent-card"))),
            )
            .await;
        (status, body)
    }

    async fn refresh(
        &self,
        surface_id: &str,
    ) -> (u16, Value, reqwest::header::HeaderMap) {
        self.send(
            self.client
                .post(self.url(&format!("surfaces/{surface_id}/agent-card/refresh"))),
        )
        .await
    }

    async fn create_surface(
        &self,
        surface: Value,
    ) -> String {
        let (status, created) = self
            .post("surfaces", &surface)
            .await;
        assert_eq!(status, 201, "{}: {created}", surface["name"]);
        created["surface_id"]
            .as_str()
            .expect("surface_id")
            .to_string()
    }

    /// The preview once the saved surface is running on its listener.
    async fn running_card(
        &self,
        surface_id: &str,
    ) -> Value {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let (status, body, _) = self
                .send(
                    self.client
                        .get(self.url(&format!("surfaces/{surface_id}/agent-card")))
                        .header(reqwest::header::COOKIE, "session_token=management-cookie"),
                )
                .await;
            assert_eq!(status, 200, "{body}");
            if body["unsupported_reason"] != "not_running" {
                return body;
            }
            assert!(tokio::time::Instant::now() < deadline, "{surface_id} never started running");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// A personal access token with feature `scopes`, bound to `tenant` and a
    /// resource pattern when given.
    async fn pat(
        &self,
        tenant: Option<(&str, &str)>,
        scopes: &[&str],
    ) -> reqwest::Client {
        let mut request = json!({"name": "card token", "scopes": scopes});
        if let Some((tenant, resource_pattern)) = tenant {
            request["resource_pattern"] = json!(resource_pattern);
            request["required_headers"] = json!([{"name": "x-external-account", "pattern": tenant}]);
        }
        let (status, body) = self
            .post("access-tokens", &request)
            .await;
        assert_eq!(status, 201, "{body}");
        let mut headers = reqwest::header::HeaderMap::new();
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            body["token"]
                .as_str()
                .expect("token secret")
        ))
        .expect("header");
        authorization.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        if let Some((tenant, _)) = tenant {
            headers
                .insert("x-external-account", reqwest::header::HeaderValue::from_str(tenant).expect("tenant header"));
        }
        reqwest::Client::builder()
            .no_proxy()
            .default_headers(headers)
            .build()
            .expect("client")
    }
}

fn a2a_surface(
    harness: &GatewayHarness,
    route: &str,
    target: &str,
) -> Value {
    json!({
        "name": route.trim_start_matches('/').replace('/', "-"), "status": "active",
        "access_point": {"listen_address": listener_origin(harness), "route": route, "protocol": "a2a"},
        "target": {"endpoint": target}
    })
}

async fn admin_harness() -> (GatewayHarness, AdminApi) {
    let mock = MockServer::start_with_response(agent_card().to_string()).await;
    let mut client = None;
    let harness = GatewayHarness::start_with_mock(mock, |_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = AdminApi::new(client.expect("admin client"), &harness);
    (harness, admin)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_card_routes_preview_a_running_a2a_surface_without_forwarding_management_credentials() {
    let (harness, admin) = admin_harness().await;
    let target = harness.mock.url();
    let surface_id = admin
        .create_surface(a2a_surface(&harness, "/smoke/card-preview", &target))
        .await;

    let first = admin
        .running_card(&surface_id)
        .await;
    assert_eq!(first["supported"], true, "{first}");
    assert_eq!(first["surface_id"], surface_id.as_str());
    assert_eq!(fetch_of(&first).0, "ok", "{first}");
    assert_eq!(first["cached"], false);
    assert!(
        !first
            .to_string()
            .contains("management-cookie"),
        "{first}"
    );
    let received = harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the agent was asked for its card");
    assert_eq!(received.path, "/.well-known/agent-card.json");
    assert!(
        !received
            .headers
            .contains_key("authorization")
            && !received
                .headers
                .contains_key("cookie"),
        "the management request's credentials never reach the agent: {:?}",
        received.headers
    );

    let (status, again) = admin.card(&surface_id).await;
    assert_eq!(status, 200);
    assert_eq!(again["cached"], true, "a fresh snapshot answers the read");
    assert_eq!(again["fetched_at"], first["fetched_at"]);

    let (status, refreshed, _) = admin
        .refresh(&surface_id)
        .await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed["cached"], false, "a refresh fetches again");

    let served: Value = reqwest::Client::new()
        .get(format!("{}/smoke/card-preview/.well-known/agent-card.json", harness.gateway_base))
        .send()
        .await
        .expect("card route")
        .json()
        .await
        .expect("card JSON");
    assert_eq!(refreshed["after"], served, "after is what the card route serves");

    let mut mcp = a2a_surface(&harness, "/smoke/card-preview-mcp", &target);
    mcp["access_point"]["protocol"] = json!("mcp");
    let mcp_id = admin
        .create_surface(mcp)
        .await;
    let (status, preview) = admin.card(&mcp_id).await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["supported"], false);
    assert_eq!(preview["unsupported_reason"], "not_a2a");
    assert_eq!(preview["fetch"], Value::Null);

    let mut inactive = a2a_surface(&harness, "/smoke/card-preview-off", &target);
    inactive["status"] = json!("disabled");
    let inactive_id = admin
        .create_surface(inactive)
        .await;
    let (status, preview) = admin.card(&inactive_id).await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["unsupported_reason"], "not_running");
    assert_eq!(preview["after"], Value::Null);

    let (status, _) = admin
        .card("no-such-surface")
        .await;
    assert_eq!(status, 404);
    let (status, _, _) = admin
        .refresh("no-such-surface")
        .await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_card_routes_keep_tenants_apart_and_refresh_needs_edit() {
    let (harness, admin) = admin_harness().await;
    let mut surface = a2a_surface(&harness, "/smoke/card-tenant", &harness.mock.url());
    surface["tenant_id"] = json!("tenant-a");
    let surface_id = admin
        .create_surface(surface)
        .await;
    let own = format!("TENANT:${{x-external-account}}:surfaces:{}", regex::escape(&surface_id));
    let card = |client: &reqwest::Client| client.get(admin.url(&format!("surfaces/{surface_id}/agent-card")));
    let refresh =
        |client: &reqwest::Client| client.post(admin.url(&format!("surfaces/{surface_id}/agent-card/refresh")));

    let other_tenant = admin
        .pat(Some(("tenant-b", "TENANT:${x-external-account}:surfaces:.*")), &[])
        .await;
    let out_of_scope = admin
        .pat(Some(("tenant-a", "TENANT:${x-external-account}:surfaces:other-.*")), &[])
        .await;
    for (client, expected, label) in [
        (&other_tenant, [404, 404], "another tenant finds no surface to read or refresh"),
        (&out_of_scope, [404, 403], "a surface outside the token's pattern is 404 to read and 403 to refresh"),
    ] {
        let mut statuses = Vec::new();
        for request in [card(client), refresh(client)] {
            let (status, body, _) = admin.send(request).await;
            assert!(body.get("after").is_none() && body.get("fetch").is_none(), "{label}: {body}");
            statuses.push(status);
        }
        assert_eq!(statuses, expected, "{label}");
    }

    let owner = admin
        .pat(Some(("tenant-a", &own)), &[])
        .await;
    for request in [card(&owner), refresh(&owner)] {
        let (status, body, _) = admin.send(request).await;
        assert_eq!(status, 200, "the owning tenant reads and refreshes its card: {body}");
        assert_eq!(body["surface_id"], surface_id.as_str());
    }

    let appliance_id = admin
        .create_surface(a2a_surface(&harness, "/smoke/card-appliance", &harness.mock.url()))
        .await;
    let card = |client: &reqwest::Client| client.get(admin.url(&format!("surfaces/{appliance_id}/agent-card")));
    let refresh =
        |client: &reqwest::Client| client.post(admin.url(&format!("surfaces/{appliance_id}/agent-card/refresh")));
    let viewer = admin
        .pat(None, &["surfaces.view"])
        .await;
    let (status, body, _) = admin
        .send(card(&viewer))
        .await;
    assert_eq!(status, 200, "surfaces.view reads the card: {body}");
    assert_eq!(body["surface_id"], appliance_id.as_str());
    let (status, body, _) = admin
        .send(refresh(&viewer))
        .await;
    assert_eq!(status, 403, "only surfaces.edit refreshes: {body}");

    let editor = admin
        .pat(None, &["surfaces.view", "surfaces.edit"])
        .await;
    let (status, body, _) = admin
        .send(refresh(&editor))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["surface_id"], appliance_id.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn refreshes_past_the_per_user_limit_are_refused_and_a_read_answers_from_the_snapshot() {
    let (harness, admin) = admin_harness().await;
    let surface_id = admin
        .create_surface(a2a_surface(&harness, "/smoke/card-limit", &harness.mock.url()))
        .await;
    let first = admin
        .running_card(&surface_id)
        .await;
    assert_eq!(fetch_of(&first).0, "ok", "{first}");

    for attempt in 2..=crate::proxy::card_preview::FETCHES_PER_MINUTE.get() {
        let (status, body, _) = admin
            .refresh(&surface_id)
            .await;
        assert_eq!(status, 200, "fetch {attempt}: {body}");
    }
    let (status, body, headers) = admin
        .refresh(&surface_id)
        .await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body, json!({"error": "Too many card refreshes; try again in a minute", "code": "rate_limited"}));
    assert_eq!(
        headers
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("60")
    );
    let requests = harness
        .mock
        .request_count
        .load(Ordering::SeqCst);

    let (status, cached) = admin.card(&surface_id).await;
    assert_eq!(status, 200, "{cached}");
    assert_eq!(cached["cached"], true);
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        requests,
        "a limited user's read fetches nothing"
    );
}
