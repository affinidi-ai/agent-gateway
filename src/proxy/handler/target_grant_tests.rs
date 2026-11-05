//! How the Access Point sends its Target the grant of a binding with external
//! consent, and refuses what it cannot send, at the wire: a recording vendor
//! and authorization server, the real handler.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::grants::GrantKey;
use crate::delegation_vault::release::connect_hint;
use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
use crate::delegation_vault::storage::DelegationVaultStorage;

const TENANT: &str = "tenant-a";
const KEY: &str = "key-a";
const TARGET: &str = crate::delegation_vault::grants::ACCESS_POINT_TARGET_HOP;

struct Fixture {
    _directory: tempfile::TempDir,
    router: crate::state::MultiSurfaceProxyState,
    vault: Arc<dyn DelegationVaultStorage>,
    authorization_server: RecordingServer,
    vendor: RecordingServer,
}

/// The identity hash of the caller that presents [`KEY`].
fn caller_principal() -> String {
    crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "caller-key".into(),
        provider_agent_id: None,
    }
    .principal_hash(Some(TENANT))
    .unwrap()
}

fn owner_key() -> GrantKey {
    GrantKey::owner(Some(TENANT), "vendor-agent", TARGET, "vendor")
}

fn caller_key(principal: &str) -> GrantKey {
    GrantKey::caller(Some(TENANT), "vendor-agent", TARGET, "vendor", principal).unwrap()
}

/// A surface whose Access Point, speaking `protocol` and authenticating its
/// callers by API key, has the vendor as its Target, at `target`, bound by
/// external consent for `subject`.
fn vendor_surface(
    protocol: &str,
    target: &str,
    subject: &str,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "vendor-agent", "name": "vendor-agent", "tenant_id": TENANT,
        "access_point": {"listen_address": "https://gateway.example", "route": "/vendor", "protocol": protocol,
            "caller_authentication": {"methods": [{"type": "api_key",
                "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "caller-key"}]}},
        "target": {"endpoint": target},
        "outbound_credentials": [{"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": subject, "scopes": ["read"]}]
    }))
    .unwrap()
}

impl Fixture {
    async fn new(
        authorization_answers: Vec<Answer>,
        vendor_answers: Vec<Answer>,
    ) -> Self {
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        let directory = tempfile::tempdir().unwrap();
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let authorization_server = RecordingServer::start_answering(authorization_answers).await;
        let vendor = RecordingServer::start_answering(vendor_answers).await;
        let issuer = authorization_server.origin();
        let providers = FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        providers
            .create(
                serde_json::from_value(json!({
                    "id": "vendor", "tenant_id": TENANT, "name": "Vendor", "provider_id": "vendor",
                    "provider_type": "oauth2_authorization_code", "issuer": issuer,
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"), "revocation_endpoint": format!("{issuer}/revoke"),
                    "token_endpoint_auth_method": "none", "client_id": "client-1",
                    "callback_url": "https://boris.example/cb", "resource": format!("{}/mcp", vendor.origin()),
                    "default_scopes": ["read"],
                    "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let secrets = crate::secrets::FilesystemSecretsStore::new(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        crate::secrets::SecretsStore::create(
            &secrets,
            crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "Caller key".into(),
                secret_id: "caller-key".into(),
                description: None,
                value: KEY.into(),
                secret_type: "ApiKey".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(secrets);
        let strategies = Arc::new(
            crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(
                directory
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap(),
        );
        let mut router =
            super::variant_routing_tests::router(vendor_surface("mcp", &format!("{}/mcp", vendor.origin()), "owner"));
        router.source_auth_middleware = Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            router
                .didauth_session_store
                .clone(),
            strategies,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            Some(secrets.clone()),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        )));
        router.secrets_store = Some(secrets);
        router.credential_provider_store = Some(Arc::new(providers));
        router.delegation_vault_store = Some(vault.clone());
        router.egress_allowlist = Some(format!("{issuer},{}", vendor.origin()));
        Self {
            _directory: directory,
            router,
            vault,
            authorization_server,
            vendor,
        }
    }

    /// Serve `surface` from now on.
    async fn serve(
        &self,
        surface: AgentSurface,
    ) {
        self.router
            .channels
            .write()
            .await[0]
            .surface = Arc::new(surface);
    }

    async fn store(
        &self,
        key: &GrantKey,
        access_token: &str,
    ) {
        self.store_expiring(key, access_token, 3600)
            .await;
    }

    async fn store_expiring(
        &self,
        key: &GrantKey,
        access_token: &str,
        expires_in_secs: i64,
    ) {
        let mut grant = crate::delegation_vault::grants::tests::grant(key, access_token);
        grant.expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(expires_in_secs));
        self.vault
            .store_grant(grant)
            .await
            .unwrap();
    }

    async fn kept(
        &self,
        key: &GrantKey,
    ) -> bool {
        self.vault
            .grant(key)
            .await
            .unwrap()
            .is_some()
    }

    async fn send(
        &self,
        request: axum::http::Request<axum::body::Body>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
        let response = super::multi_channel_proxy_handler(
            axum::extract::ConnectInfo(
                "127.0.0.1:12345"
                    .parse()
                    .unwrap(),
            ),
            axum::extract::State(self.router.clone()),
            request,
        )
        .await;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let json = text
            .lines()
            .find_map(|line| line.strip_prefix("data:"))
            .unwrap_or(&text);
        (status, headers, serde_json::from_str(json.trim()).unwrap_or(Value::Null))
    }

    /// The `authorization` header of each request the vendor received, and
    /// whether it carried the caller's API key.
    fn vendor_saw(&self) -> Vec<(Option<String>, bool)> {
        self.vendor
            .requests()
            .iter()
            .map(|(head, _)| {
                let header = |name: &str| {
                    head.lines().find_map(|line| {
                        line.to_ascii_lowercase()
                            .starts_with(&format!("{name}:"))
                            .then(|| {
                                line[name.len() + 1..]
                                    .trim()
                                    .to_string()
                            })
                    })
                };
                (header("authorization"), header("x-api-key").is_some())
            })
            .collect()
    }

    /// The request line and the headers, lower-cased name and value, of each
    /// request the vendor received.
    fn vendor_heads(&self) -> Vec<(String, Vec<(String, String)>)> {
        self.vendor
            .requests()
            .iter()
            .map(|(head, _)| {
                let mut lines = head.lines();
                let request_line = lines
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let headers = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| {
                        (
                            name.trim()
                                .to_ascii_lowercase(),
                            value.trim().to_string(),
                        )
                    })
                    .collect();
                (request_line, headers)
            })
            .collect()
    }
}

fn mcp_call(key: Option<&str>) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/vendor")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
        .header("authorization", "Bearer the-callers-own-token");
    if let Some(key) = key {
        request = request.header("x-api-key", key);
    }
    request
        .body(axum::body::Body::from(json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).to_string()))
        .unwrap()
}

fn vendor_result() -> Answer {
    Answer::json(200, json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}))
}

/// The owner's grant is sent to the Target, in place of the caller's own
/// credentials, to any caller the Access Point identifies; a caller it does
/// not identify is refused before anything is sent. The vendor's cookies and
/// authentication challenges never reach the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owners_grant_goes_to_the_target_in_place_of_the_callers_credentials() {
    let fixture = Fixture::new(
        vec![Answer::status(200)],
        vec![
            vendor_result()
                .with_header("Set-Cookie", "vendor-session=1")
                .with_header("WWW-Authenticate", r#"Bearer realm="vendor""#),
        ],
    )
    .await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;

    let (status, headers, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["result"], json!({"tools": []}));
    assert_eq!(fixture.vendor_saw(), [(Some("Bearer owner-access".to_string()), false)]);
    assert!(
        headers
            .get("set-cookie")
            .is_none(),
        "{headers:?}"
    );
    assert!(
        headers
            .get("www-authenticate")
            .is_none(),
        "{headers:?}"
    );

    for (case, key) in [("no API key", None), ("another API key", Some("key-b"))] {
        let (status, headers, body) = fixture
            .send(mcp_call(key))
            .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{case}: {body}");
        assert_eq!(body["id"], 7, "{case}");
        assert_eq!(body["error"]["code"], -32001, "{case}");
        assert_eq!(headers["cache-control"], "no-store", "{case}");
    }
    assert_eq!(
        fixture
            .vendor
            .requests()
            .len(),
        1,
        "an unidentified caller reaches no vendor"
    );
}

/// A caller's grant goes to that caller only: another caller's grant is never
/// sent, and a caller without a grant is told to connect, with a hint of
/// itself, in the Access Point's protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callers_grant_goes_to_that_caller_only() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    let target = format!("{}/mcp", fixture.vendor.origin());
    fixture
        .serve(vendor_surface("mcp", &target, "caller"))
        .await;
    fixture
        .store(&caller_key(&"b".repeat(64)), "another-callers-access")
        .await;

    let (status, headers, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32001);
    assert_eq!(
        body["error"]["data"],
        json!({"reason": "connect_required", "subject": "caller", "hint": connect_hint(&caller_principal())})
    );
    assert_eq!(headers["cache-control"], "no-store");
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty(),
        "no grant of another caller is sent"
    );

    fixture
        .store(&caller_key(&caller_principal()), "my-access")
        .await;
    let (status, _, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(fixture.vendor_saw(), [(Some("Bearer my-access".to_string()), false)]);

    fixture
        .serve(vendor_surface("a2a", &target, "owner"))
        .await;
    let a2a = axum::http::Request::builder()
        .method("POST")
        .uri("/vendor")
        .header("content-type", "application/json")
        .header("x-api-key", KEY)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send", "params": {"message": {
                "kind": "message", "messageId": "m-1", "role": "user", "parts": [{"kind": "text", "text": "hi"}]}}})
            .to_string(),
        ))
        .unwrap();
    let (status, headers, body) = fixture.send(a2a).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(headers["content-type"], "application/problem+json");
    assert_eq!(body["reason"], "connect_required");
    assert_eq!(body["subject"], "owner");
    assert_eq!(body["type"], "https://affinidi.com/atg/errors/connect-required");
    assert_eq!(
        fixture
            .vendor
            .requests()
            .len(),
        1,
        "the owner has not connected"
    );
}

fn refresh_answer(access_token: &str) -> Answer {
    Answer::json(
        200,
        json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": format!("{access_token}-refresh"), "scope": "read"}),
    )
}

fn rejected_token() -> Answer {
    Answer::status(401).with_header("WWW-Authenticate", r#"Bearer error="invalid_token""#)
}

/// A vendor's `401` that rejects the token gets one refresh and one retry
/// with the new token. A second `401`, after a refresh the authorization
/// server granted, refuses that request, `connector_unavailable`, not the
/// connection, which any caller of an owner binding could otherwise end: the
/// grant is kept and nothing is revoked. A `403` for a missing scope is
/// answered `scope_insufficient`, naming the scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_targets_refusal_of_the_token_is_refreshed_and_retried_once() {
    let fixture = Fixture::new(
        vec![refresh_answer("second"), refresh_answer("third")],
        vec![rejected_token(), vendor_result(), rejected_token()],
    )
    .await;
    fixture
        .store(&owner_key(), "first")
        .await;
    let (status, _, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["result"], json!({"tools": []}));
    let bearers: Vec<_> = fixture
        .vendor_saw()
        .into_iter()
        .map(|(bearer, _)| bearer.unwrap())
        .collect();
    assert_eq!(bearers, ["Bearer first", "Bearer second"]);

    let (status, headers, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}));
    assert!(
        headers
            .get("www-authenticate")
            .is_none()
    );
    let bearers: Vec<_> = fixture
        .vendor_saw()
        .into_iter()
        .map(|(bearer, _)| bearer.unwrap())
        .collect();
    assert_eq!(bearers, ["Bearer first", "Bearer second", "Bearer second", "Bearer third"]);
    let kept = fixture
        .vault
        .grant(&owner_key())
        .await
        .unwrap()
        .expect("a second 401 after a refresh keeps the grant");
    assert_eq!(kept.access_token, "third");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        fixture
            .authorization_server
            .revoked_tokens()
            .is_empty(),
        "nothing is revoked"
    );

    let scoped = Fixture::new(
        vec![Answer::status(200)],
        vec![
            Answer::status(403).with_header("WWW-Authenticate", r#"Bearer error="insufficient_scope", scope="write""#),
        ],
    )
    .await;
    scoped
        .store(&owner_key(), "narrow")
        .await;
    let (status, _, body) = scoped
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["data"], json!({"reason": "scope_insufficient", "scope": "write"}));
    assert!(
        scoped
            .kept(&owner_key())
            .await,
        "a missing scope keeps the grant"
    );
}

/// The grant goes only to its provider's resource, through Strict egress: a
/// Target elsewhere is refused before the vault is read, and so is a
/// `2026-07-28` request, whose vendor is reached over a session revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_grant_goes_only_to_its_providers_resource() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    let elsewhere = RecordingServer::start_answering(vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    fixture
        .serve(vendor_surface("mcp", &format!("{}/mcp", elsewhere.origin()), "owner"))
        .await;
    let (status, _, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], crate::mcp::errors::error_codes::INTERNAL_ERROR);
    assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}));
    assert!(
        elsewhere
            .requests()
            .is_empty()
    );

    fixture
        .serve(vendor_surface("mcp", &format!("{}/mcp", fixture.vendor.origin()), "owner"))
        .await;
    let modern = axum::http::Request::builder()
        .method("POST")
        .uri("/vendor")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
        .header("mcp-method", "tools/call")
        .header("mcp-name", "read")
        .header("x-api-key", KEY)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
                "name": "read", "arguments": {}, "_meta": {
                    "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
            }}})
            .to_string(),
        ))
        .unwrap();
    let (status, _, body) = fixture.send(modern).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], crate::mcp::errors::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty()
    );

    let mut meta: Value =
        serde_json::to_value(vendor_surface("mcp", &format!("{}/mcp", fixture.vendor.origin()), "owner")).unwrap();
    meta["outbound_credentials"][0]["inject_as"] = json!({"type": "meta", "field": "vendor/token"});
    fixture
        .serve(serde_json::from_value(meta).unwrap())
        .await;
    let (status, _, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "a grant is never put in the body: {body}");
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty()
    );
}

/// Two calls that release the Target's grant at once, while its refresh is
/// due, refresh it once: the call that did not claim the refresh waits for it
/// rather than taking it for a dead one, so the grant is neither abandoned
/// nor removed, both calls use the refreshed token, and nothing is revoked.
/// The same holds when the vendor refuses the token of both calls at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_calls_releasing_the_targets_grant_at_once_refresh_it_once() {
    for (case, expires_in, vendor) in [
        ("an expired grant", -60, vec![vendor_result()]),
        ("a token the vendor refuses", 3600, vec![rejected_token(), rejected_token(), vendor_result()]),
    ] {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let fixture = Fixture::new(vec![refresh_answer("refreshed").held(&gate), Answer::status(200)], vendor).await;
        fixture
            .store_expiring(&owner_key(), "first", expires_in)
            .await;
        let ((first, _, first_body), (second, _, second_body), ()) =
            tokio::join!(fixture.send(mcp_call(Some(KEY))), fixture.send(mcp_call(Some(KEY))), async {
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                gate.add_permits(1);
            });
        assert_eq!(first, axum::http::StatusCode::OK, "{case}: {first_body}");
        assert_eq!(second, axum::http::StatusCode::OK, "{case}: {second_body}");
        let refreshes = fixture
            .authorization_server
            .requests()
            .iter()
            .filter(|(head, _)| head.starts_with("POST /token "))
            .count();
        assert_eq!(refreshes, 1, "{case}: the grant is refreshed once");
        let kept = fixture
            .vault
            .grant(&owner_key())
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{case}: the grant is kept"));
        assert_eq!(kept.access_token, "refreshed", "{case}");
        assert!(!kept.refresh_abandoned(), "{case}");
        let bearers: Vec<_> = fixture
            .vendor_saw()
            .into_iter()
            .map(|(bearer, _)| bearer.unwrap())
            .collect();
        assert_eq!(
            bearers
                .iter()
                .filter(|bearer| *bearer == "Bearer refreshed")
                .count(),
            2,
            "{case}: {bearers:?}"
        );
        assert!(
            fixture
                .authorization_server
                .revoked_tokens()
                .is_empty(),
            "{case}: nothing is revoked"
        );
    }
}

/// A refusal a new connect would not fix keeps the grant: a `401` without a
/// `Bearer` challenge that rejects the token, as a front proxy answers, is
/// not taken for a refused token, and a body too large to send again is not
/// sent twice: its grant is refreshed for the next call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_a_new_connect_would_not_fix_keeps_the_grant() {
    let fixture = Fixture::new(vec![refresh_answer("fresh")], vec![Answer::status(401), rejected_token()]).await;
    fixture
        .store(&owner_key(), "kept")
        .await;
    let (status, _, body) = fixture
        .send(mcp_call(Some(KEY)))
        .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}));
    assert!(
        fixture
            .kept(&owner_key())
            .await
    );
    assert!(
        fixture
            .authorization_server
            .requests()
            .is_empty(),
        "nothing is refreshed"
    );

    let mut large: Value =
        serde_json::to_value(vendor_surface("mcp", &format!("{}/mcp", fixture.vendor.origin()), "owner")).unwrap();
    large["mcp_http"] = json!({"max_request_bytes": 4 * crate::delegation_vault::release::RETRY_BODY_LIMIT});
    fixture
        .serve(serde_json::from_value(large).unwrap())
        .await;
    let upload = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "upload",
        "arguments": {"file": "x".repeat(crate::delegation_vault::release::RETRY_BODY_LIMIT)}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/vendor")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
        .header("x-api-key", KEY)
        .body(axum::body::Body::from(upload.to_string()))
        .unwrap();
    let (status, _, body) = fixture.send(request).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}));
    assert_eq!(
        fixture
            .vendor
            .requests()
            .len(),
        2,
        "the large body is sent once"
    );
    let kept = fixture
        .vault
        .grant(&owner_key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.access_token, "fresh", "the grant is refreshed for the next call");
}

/// A public discovery read carries no caller, and so no grant, and nothing of
/// the caller's but its request: not its cookies or credentials. The agent
/// card is fetched from the Target's own card URL, whatever path the caller
/// named; another discovery read is refused when its path is not one the
/// vendor reads as the gateway does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_read_carries_no_grant() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![Answer::json(200, json!({"name": "vendor"}))]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let read = |path: &str| {
        axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .header("x-api-key", KEY)
            .header("cookie", "__Host-session_token=dashboard-session")
            .header("authorization", "Bearer the-callers-own-token")
            .header("proxy-authorization", "Basic cHJveHk6c2VjcmV0")
            .header("x-caller-did", "did:example:spoofed")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    for path in [
        "/vendor/.well-known/agent-card.json",
        "/vendor/discovery",
        "/vendor/../.well-known/agent-card.json",
        "/vendor/discovery?access_token=smuggled&x=1",
    ] {
        let (status, _, body) = fixture.send(read(path)).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{path}: {body}");
    }
    let (status, _, body) = fixture
        .send(read("/vendor/%2e%2e/discovery"))
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(fixture.vendor_saw(), [(None, false), (None, false), (None, false), (None, false)]);
    let heads = fixture.vendor_heads();
    let lines: Vec<_> = heads
        .iter()
        .map(|(line, _)| line.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "GET /mcp/.well-known/agent-card.json HTTP/1.1",
            "GET /mcp/discovery HTTP/1.1",
            "GET /mcp/.well-known/agent-card.json HTTP/1.1",
            "GET /mcp/discovery HTTP/1.1"
        ]
    );
    for (line, headers) in &heads {
        for (name, _) in headers {
            assert!(
                !["cookie", "proxy-authorization"].contains(&name.as_str()) && !name.starts_with("x-caller-"),
                "{line} sent the vendor {name}: {headers:?}"
            );
        }
    }
}

/// Nothing of the caller's but its request reaches the vendor beside the
/// grant: not its cookies, its credentials (`Authorization`,
/// `Proxy-Authorization`, the header its credential came in) or a method
/// override, and no caller-info or DID header, whether the caller sent one or
/// the gateway would add it. The vendor is asked for an uncompressed answer,
/// which the gateway reads as it is sent, and a compressed one is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_target_gets_nothing_of_the_callers_but_its_request() {
    let fixture = Fixture::new(
        vec![Answer::status(200)],
        vec![vendor_result(), vendor_result().with_header("Content-Encoding", "gzip")],
    )
    .await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let call = || {
        let (mut parts, body) = mcp_call(Some(KEY)).into_parts();
        for (name, value) in [
            ("cookie", "__Host-session_token=dashboard-session; lb=sticky"),
            ("proxy-authorization", "Basic cHJveHk6c2VjcmV0"),
            ("x-caller-did", "did:example:spoofed"),
            ("x-caller-identity-source", "spoofed"),
            ("x-caller-anything", "spoofed"),
            ("x-gateway-did", "did:example:spoofed-gateway"),
            ("x-did-identity", "did:example:spoofed"),
            ("x-did-auth-session", "a-did-auth-session"),
            ("x-http-method-override", "DELETE"),
            ("accept-encoding", "gzip, br"),
        ] {
            parts
                .headers
                .insert(name, axum::http::HeaderValue::from_static(value));
        }
        axum::http::Request::from_parts(parts, body)
    };

    let (status, _, body) = fixture.send(call()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let heads = fixture.vendor_heads();
    let (_, headers) = &heads[0];
    for (name, _) in headers {
        assert!(
            !["cookie", "proxy-authorization", "x-gateway-did", "x-api-key", "x-http-method-override"]
                .contains(&name.as_str())
                && !name.starts_with("x-caller-")
                && !name.starts_with("x-did-"),
            "the vendor was sent {name}: {headers:?}"
        );
    }
    let values = |wanted: &str| {
        headers
            .iter()
            .filter(|(name, _)| name == wanted)
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(values("authorization"), ["Bearer owner-access"]);
    assert_eq!(values("accept-encoding"), ["identity"]);

    let (status, headers, body) = fixture.send(call()).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}));
    assert_eq!(headers["cache-control"], "no-store");
}

/// Of the caller's headers the vendor is sent only the protocol headers its
/// requests need: `Content-Type`, `Accept`, MCP's protocol version and
/// session, and A2A's version and extensions. No other header the caller set
/// goes, so none a vendor may read as another path, host or principal
/// (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-*`, `Forwarded`), nor the
/// caller's own trace id beside the gateway's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_target_is_sent_only_the_protocol_headers_of_the_callers() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let callers = [
        ("x-original-url", "/api/v1/admin"),
        ("x-rewrite-url", "/api/v1/admin"),
        ("x-forwarded-host", "admin.vendor.example"),
        ("x-forwarded-prefix", "/admin"),
        ("x-forwarded-proto", "http"),
        ("forwarded", "host=admin.vendor.example;proto=http"),
        ("x-gateway-trace-id", "the-callers-own-trace"),
        ("user-agent", "caller-agent/1.0"),
        ("last-event-id", "event-9"),
        ("x-vendor-act-as", "someone-else"),
        ("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
    ];
    let with = |request: axum::http::Request<axum::body::Body>, extra: &[(&'static str, &'static str)]| {
        let (mut parts, body) = request.into_parts();
        for (name, value) in callers.iter().chain(extra) {
            parts
                .headers
                .insert(*name, axum::http::HeaderValue::from_static(value));
        }
        axum::http::Request::from_parts(parts, body)
    };
    let gateways_own = ["host", "content-length", "authorization", "accept-encoding", "x-gateway-trace-id"];

    let (status, _, body) = fixture
        .send(with(mcp_call(Some(KEY)), &[]))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    fixture
        .serve(vendor_surface("a2a", &format!("{}/mcp", fixture.vendor.origin()), "owner"))
        .await;
    let send = json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send", "params": {"message": {
        "kind": "message", "messageId": "m-1", "role": "user", "parts": [{"kind": "text", "text": "hi"}]}}});
    let a2a = [
        ("a2a-version", "0.3"),
        ("x-a2a-extensions", "https://ext.example/v1"),
        ("a2a-extensions", "https://ext.example/v2"),
    ];
    let (status, _, body) = fixture
        .send(with(call_to("POST", "/vendor", Some(send)), &a2a))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");

    let heads = fixture.vendor_heads();
    assert_eq!(heads.len(), 2);
    for ((line, headers), protocol) in heads.iter().zip([
        vec![("content-type", "application/json"), ("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)],
        a2a.iter()
            .copied()
            .chain([("content-type", "application/json")])
            .collect(),
    ]) {
        for (name, value) in headers {
            assert!(
                gateways_own.contains(&name.as_str())
                    || ["content-type", "accept", "mcp-protocol-version", "mcp-session-id"].contains(&name.as_str())
                    || a2a
                        .iter()
                        .any(|(a2a, _)| a2a == name),
                "{line} sent the vendor the caller's {name}: {value}"
            );
        }
        for (name, value) in protocol {
            assert!(
                headers.contains(&(name.to_string(), value.to_string())),
                "{line} did not send the vendor {name}: {headers:?}"
            );
        }
        let traces: Vec<_> = headers
            .iter()
            .filter(|(name, _)| name == "x-gateway-trace-id")
            .collect();
        assert_eq!(traces.len(), 1, "{line}: {headers:?}");
        assert_ne!(traces[0].1, "the-callers-own-trace", "{line}");
    }
}

/// A request to the Target through its Access Point, as `method` to `uri`,
/// from the caller that presents [`KEY`], with `body` when it has one.
fn call_to(
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", crate::mcp::MCP_LEGACY_VERSION)
        .header("x-api-key", KEY)
        .body(body.map_or_else(axum::body::Body::empty, |body| axum::body::Body::from(body.to_string())))
        .unwrap()
}

/// A request carrying the grant goes to the Target's endpoint path on MCP,
/// and at or under it on A2A, and nowhere else at the vendor's origin: a path
/// with a dot segment, plain or percent-encoded, an encoded separator, an
/// empty segment or a `;` parameter is refused `400`, as one that could climb
/// out of the endpoint path; a method the protocol does not send with the
/// grant is refused `405`; the caller's query string is never sent. Nothing
/// refused reaches the vendor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_grant_goes_only_to_the_targets_endpoint_path() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let tools = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"});
    let climbing = [
        ("a dot segment", "/vendor/.."),
        ("dot segments", "/vendor/../../api/v1/me"),
        ("an inner dot segment", "/vendor/v1/./tasks"),
        ("percent-encoded dots", "/vendor/%2e%2e/%2E%2E/api"),
        ("an encoded slash", "/vendor/..%2f..%2fapi"),
        ("an encoded backslash", "/vendor/..%5c..%5capi"),
        ("a double slash", "/vendor/v1//tasks"),
        ("a trailing slash", "/vendor/v1/tasks/"),
        ("a path parameter", "/vendor/v1/..;/api"),
        ("an encoded question mark", "/vendor/v1/tasks%3Fx=1"),
        ("a double-encoded dot segment", "/vendor/%252e%252e/api"),
        ("overlong UTF-8 dots", "/vendor/%c0%ae%c0%ae/api"),
        ("fullwidth dots", "/vendor/%ef%bc%8e%ef%bc%8e/api"),
        ("non-ASCII in a segment", "/vendor/v1/t%C3%A4sks"),
        ("dots and a trailing space", "/vendor/..%20/api"),
        ("three dots", "/vendor/.../api"),
        ("a dot and a space", "/vendor/v1/.%20/tasks"),
        ("spaces alone", "/vendor/v1/%20%20/tasks"),
    ];

    let (status, headers, body) = fixture
        .send(call_to("POST", "/vendor?access_token=smuggled&x=1", Some(tools.clone())))
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "a request with a query string: {body}");
    assert_eq!(body["id"], 7, "a request with a query string");
    assert_eq!(headers["cache-control"], "no-store", "a request with a query string");
    let (status, _, body) = fixture
        .send(call_to("POST", "/vendor", Some(tools.clone())))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    for (case, uri) in climbing
        .iter()
        .copied()
        .chain([("a path under the endpoint", "/vendor/messages")])
    {
        let (status, headers, body) = fixture
            .send(call_to("POST", uri, Some(tools.clone())))
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "MCP, {case}: {body}");
        assert_eq!(body["id"], 7, "MCP, {case}");
        assert_eq!(headers["cache-control"], "no-store", "MCP, {case}");
    }
    for method in ["GET", "HEAD", "OPTIONS", "PUT", "PATCH"] {
        let (status, headers, body) = fixture
            .send(call_to(method, "/vendor", None))
            .await;
        assert_eq!(status, axum::http::StatusCode::METHOD_NOT_ALLOWED, "MCP {method}: {body}");
        if !["PUT", "PATCH"].contains(&method) {
            assert_eq!(headers["allow"], "POST", "MCP {method}, which MCP admission lets through");
        }
    }
    let (status, _, body) = fixture
        .send(call_to("DELETE", "/vendor", None))
        .await;
    assert_eq!(status, axum::http::StatusCode::NO_CONTENT, "the gateway ends an MCP session itself: {body}");
    assert_eq!(
        fixture
            .vendor_heads()
            .into_iter()
            .map(|(line, _)| line)
            .collect::<Vec<_>>(),
        ["POST /mcp HTTP/1.1"]
    );

    fixture
        .serve(vendor_surface("a2a", &format!("{}/mcp", fixture.vendor.origin()), "owner"))
        .await;
    let send = json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send", "params": {"message": {
        "kind": "message", "messageId": "m-1", "role": "user", "parts": [{"kind": "text", "text": "hi"}]}}});
    for (method, uri, body) in [
        ("POST", "/vendor?x=1", Some(send.clone())),
        ("POST", "/vendor/v1/message:send?x=1", Some(send.clone())),
        ("GET", "/vendor/v1/tasks/task-1?historyLength=2", None),
        ("GET", "/vendor/v1/tasks?pageToken=abc", None),
        ("DELETE", "/vendor/v1/tasks/task-1/pushNotificationConfigs/config-1?x=1", None),
    ] {
        let (status, headers, answer) = fixture
            .send(call_to(method, uri, body))
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "A2A {method} {uri}, with a query string: {answer}");
        assert_eq!(headers["content-type"], "application/problem+json", "A2A {method} {uri}");
    }
    for (method, uri, body) in [
        ("POST", "/vendor", Some(send.clone())),
        ("POST", "/vendor/v1/message:send", Some(send.clone())),
        ("GET", "/vendor/v1/tasks/task-1", None),
        ("DELETE", "/vendor/v1/tasks/task-1/pushNotificationConfigs/config-1", None),
    ] {
        let (status, _, answer) = fixture
            .send(call_to(method, uri, body))
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "A2A {method} {uri}: {answer}");
    }
    for (case, uri) in climbing {
        let (status, headers, body) = fixture
            .send(call_to("POST", uri, Some(send.clone())))
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "A2A, {case}: {body}");
        assert_eq!(headers["content-type"], "application/problem+json", "A2A, {case}");
        let (status, _, body) = fixture
            .send(call_to("GET", uri, None))
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "A2A GET, {case}: {body}");
    }
    for method in ["HEAD", "OPTIONS", "PUT", "PATCH"] {
        let (status, headers, body) = fixture
            .send(call_to(method, "/vendor/v1/tasks/task-1", None))
            .await;
        assert_eq!(status, axum::http::StatusCode::METHOD_NOT_ALLOWED, "A2A {method}: {body}");
        assert_eq!(headers["allow"], "GET, POST, DELETE", "A2A {method}");
    }
    let lines: Vec<_> = fixture
        .vendor_heads()
        .into_iter()
        .map(|(line, _)| line)
        .collect();
    assert_eq!(
        lines[1..],
        [
            "POST /mcp HTTP/1.1",
            "POST /mcp/v1/message:send HTTP/1.1",
            "GET /mcp/v1/tasks/task-1 HTTP/1.1",
            "DELETE /mcp/v1/tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1"
        ]
    );
}

/// `surface` with its Access Point authenticating callers by `methods`.
fn authenticating(
    surface: AgentSurface,
    methods: Value,
) -> AgentSurface {
    let mut surface = serde_json::to_value(surface).unwrap();
    surface["access_point"]["caller_authentication"] = json!({"methods": methods});
    serde_json::from_value(surface).unwrap()
}

/// A surface whose Access Point accepts callers who name themselves, as DID
/// Auth without `allowed_dids` does, or callers with a token minted for any
/// service, as a JWT bearer method without `audiences` does, never releases
/// the Target's grant, even to a caller it identified another way, as one
/// edited by hand might: such a surface answers `connector_unavailable` and
/// reads no grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_goes_to_callers_who_name_themselves() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let api_key = json!({"type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"},
        "secret_id": "caller-key"});
    let did_auth = |allowed: &[&str]| {
        json!({"type": "did_auth", "extraction": {"source": "http_header", "field": "X-DID-Auth-Session"},
            "allowed_dids": allowed})
    };
    let jwt = |audiences: &[&str]| json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy-1", "audiences": audiences});
    let target = format!("{}/mcp", fixture.vendor.origin());
    // The JWT method reads `Authorization`, so a caller sending its own token
    // there beside the API key would carry two credentials and be refused.
    let api_key_call = || {
        let mut request = mcp_call(Some(KEY));
        request
            .headers_mut()
            .remove("authorization");
        request
    };
    for (case, checked) in
        [("DID Auth with an allow-list", did_auth(&["did:example:a"])), ("JWT with an audience", jwt(&["https://gw"]))]
    {
        fixture
            .serve(authenticating(vendor_surface("mcp", &target, "owner"), json!([api_key, checked])))
            .await;
        let (status, _, body) = fixture
            .send(api_key_call())
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{case}: {body}");
    }

    for (case, unchecked) in [("DID Auth without an allow-list", did_auth(&[])), ("JWT without audiences", jwt(&[]))] {
        fixture
            .serve(authenticating(vendor_surface("mcp", &target, "owner"), json!([api_key, unchecked])))
            .await;
        let (status, _, body) = fixture
            .send(api_key_call())
            .await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{case}: {body}");
        assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}), "{case}");
    }
    assert_eq!(
        fixture
            .vendor
            .requests()
            .len(),
        2
    );
}

/// A surface that would send the vendor a presentation of the agent, as an
/// identity VP, a workload binding or its DID in the body, or custom metadata
/// of the gateway's, never releases the Target's grant, as one edited by hand
/// might: it answers `connector_unavailable` and reads no grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_goes_with_a_presentation_of_the_agent() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let target = format!("{}/mcp", fixture.vendor.origin());
    for (case, field, value) in [
        ("an identity VP", "/target/identity_injection", json!({"inject_vp": true})),
        ("a workload binding", "/target/workload_binding", json!({"enabled": true})),
        (
            "the surface's DID in the body",
            "/access_point/didwebvh_identity",
            json!({"injection_mode": "protocol_native"}),
        ),
        ("custom metadata", "/target/custom_metadata", json!({"enabled": true, "payload": {"tenant": "acme"}})),
    ] {
        let mut surface = serde_json::to_value(vendor_surface("mcp", &target, "owner")).unwrap();
        let (parent, name) = field
            .rsplit_once('/')
            .unwrap();
        surface
            .pointer_mut(parent)
            .unwrap()[name] = value;
        fixture
            .serve(serde_json::from_value(surface).unwrap())
            .await;
        let (status, _, body) = fixture
            .send(mcp_call(Some(KEY)))
            .await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{case}: {body}");
        assert_eq!(body["error"]["data"], json!({"reason": "connector_unavailable"}), "{case}");
    }
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty()
    );
}

/// An A2A Target at the root of its origin, which would be sent the grant on
/// every path of the vendor's, never gets it, as one edited by hand might:
/// every request answers `connector_unavailable` and reads no grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_goes_to_an_a2a_target_at_the_root_of_its_origin() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let send = json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send", "params": {"message": {
        "kind": "message", "messageId": "m-1", "role": "user", "parts": [{"kind": "text", "text": "hi"}]}}});
    for root in ["", "/"] {
        fixture
            .serve(vendor_surface("a2a", &format!("{}{root}", fixture.vendor.origin()), "owner"))
            .await;
        for (method, uri, body) in [
            ("POST", "/vendor", Some(send.clone())),
            ("GET", "/vendor/v1/tasks/task-1", None),
            ("GET", "/vendor/api/v1/me", None),
        ] {
            let (status, _, answer) = fixture
                .send(call_to(method, uri, body))
                .await;
            assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{root:?} {method} {uri}: {answer}");
            assert_eq!(answer["reason"], "connector_unavailable", "{root:?} {method} {uri}: {answer}");
        }
    }
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty()
    );
}

/// The `request_rejected` records one request produced: stage, reason, HTTP
/// status and JSON-RPC error code.
type Rejections = Vec<(
    crate::audit::request_events::RejectionStage,
    crate::audit::request_events::RejectionReason,
    Option<u16>,
    Option<i64>,
)>;

impl Fixture {
    /// [`Self::send`], with the `request_rejected` records the request
    /// produced.
    async fn send_audited(
        &self,
        request: axum::http::Request<axum::body::Body>,
    ) -> (axum::http::StatusCode, Rejections) {
        let ((status, _, _), events) = crate::audit::producer::capture(self.send(request)).await;
        let rejections = events
            .into_iter()
            .filter_map(|event| match event.event {
                crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                    stage,
                    reason,
                    http_status,
                    rpc_error_code,
                    ..
                } => Some((stage, reason, http_status, rpc_error_code)),
                _ => None,
            })
            .collect();
        (status, rejections)
    }
}

/// A request to a Target bound by external consent that is refused before
/// anything is sent, for its path (`400`), its method (`405`) or a rule its
/// surface breaks (`503`), leaves a `request_rejected` record with a fixed
/// reason, at admission, as well as a log line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_before_anything_is_sent_is_audited() {
    use crate::audit::request_events::{RejectionReason, RejectionStage};
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let tools = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"});
    let send = json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send", "params": {"message": {
        "kind": "message", "messageId": "m-1", "role": "user", "parts": [{"kind": "text", "text": "hi"}]}}});
    let target = format!("{}/mcp", fixture.vendor.origin());
    let open = authenticating(
        vendor_surface("mcp", &target, "owner"),
        json!([{"type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"},
            "secret_id": "caller-key"}, {"type": "did_auth",
            "extraction": {"source": "http_header", "field": "X-DID-Auth-Session"}, "allowed_dids": []}]),
    );
    let cases = [
        (
            "an MCP path that is not the endpoint",
            vendor_surface("mcp", &target, "owner"),
            call_to("POST", "/vendor/%2e%2e/api", Some(tools.clone())),
            400,
            (RejectionStage::Admission, RejectionReason::TargetPathRefused, Some(400), Some(-32600)),
        ),
        (
            "an A2A path with a dot segment",
            vendor_surface("a2a", &target, "owner"),
            call_to("GET", "/vendor/v1/../admin", None),
            400,
            (RejectionStage::Admission, RejectionReason::TargetPathRefused, Some(400), None),
        ),
        (
            "an MCP request with a query string",
            vendor_surface("mcp", &target, "owner"),
            call_to("POST", "/vendor?x=1", Some(tools.clone())),
            400,
            (RejectionStage::Admission, RejectionReason::TargetPathRefused, Some(400), Some(-32600)),
        ),
        (
            "an A2A read with a page token",
            vendor_surface("a2a", &target, "owner"),
            call_to("GET", "/vendor/v1/tasks?pageToken=abc", None),
            400,
            (RejectionStage::Admission, RejectionReason::TargetPathRefused, Some(400), None),
        ),
        (
            "a 2026-07-28 MCP request",
            vendor_surface("mcp", &target, "owner"),
            axum::http::Request::builder()
                .method("POST")
                .uri("/vendor")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", crate::mcp::MCP_MODERN_VERSION)
                .header("mcp-method", "tools/call")
                .header("mcp-name", "read")
                .header("x-api-key", KEY)
                .body(axum::body::Body::from(
                    json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
                        "name": "read", "arguments": {}, "_meta": {
                            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                            "io.modelcontextprotocol/clientCapabilities": {}
                    }}})
                    .to_string(),
                ))
                .unwrap(),
            400,
            (RejectionStage::Admission, RejectionReason::VersionUnsupported, Some(400), Some(-32022)),
        ),
        (
            "an MCP read",
            vendor_surface("mcp", &target, "owner"),
            call_to("GET", "/vendor", None),
            405,
            (RejectionStage::Admission, RejectionReason::TargetMethodRefused, Some(405), None),
        ),
        (
            "an A2A method the grant is not sent with",
            vendor_surface("a2a", &target, "owner"),
            call_to("PUT", "/vendor/v1/tasks/task-1", None),
            405,
            (RejectionStage::Admission, RejectionReason::TargetMethodRefused, Some(405), None),
        ),
        (
            "callers who name themselves",
            open,
            call_to("POST", "/vendor", Some(tools.clone())),
            503,
            (RejectionStage::Admission, RejectionReason::ConnectorUnavailable, Some(503), Some(-32603)),
        ),
        (
            "an A2A Target at the root of its origin",
            vendor_surface("a2a", &fixture.vendor.origin(), "owner"),
            call_to("POST", "/vendor", Some(send)),
            503,
            (RejectionStage::Admission, RejectionReason::ConnectorUnavailable, Some(503), None),
        ),
    ];
    for (case, surface, request, status, expected) in cases {
        fixture.serve(surface).await;
        let (observed, rejections) = fixture
            .send_audited(request)
            .await;
        assert_eq!(observed.as_u16(), status, "{case}");
        assert_eq!(rejections, vec![expected], "{case}");
    }
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty()
    );
}

/// A surface that charges its callers never releases the Target's grant, as
/// one edited by hand might: an agent-pay surface is refused
/// `connector_unavailable`, and a local payment, no longer taken, is refused
/// `payment_unavailable`, both before any payment is asked for or settled, so
/// nobody pays for a request no grant can serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_payment_is_taken_for_the_targets_grant() {
    let fixture = Fixture::new(vec![Answer::status(200)], vec![vendor_result()]).await;
    fixture
        .store(&owner_key(), "owner-access")
        .await;
    let target = format!("{}/mcp", fixture.vendor.origin());
    for (case, payment_policy, refusal_at, refusal) in [
        (
            "a local payment",
            json!({"type": "x402", "enabled": true, "verification_mode": "mock", "settlement_mode": "none",
                "payment_requirements": [{"scheme": "exact", "network": "eip155:1", "amount": "1000",
                    "asset": "0x123", "payTo": "0x456", "maxTimeoutSeconds": 300}],
                "mcp_payment_triggers": {"mode": "all"}}),
            "",
            json!({"error": "payment_unavailable"}),
        ),
        (
            "a payment agent-pay takes",
            json!({"type": "agent_pay", "payment_gateway_id": "payment-gateway",
                "payment_surface_id": "payment-surface"}),
            "/error/data",
            json!({"reason": "connector_unavailable"}),
        ),
    ] {
        let mut surface = serde_json::to_value(vendor_surface("mcp", &target, "owner")).unwrap();
        surface["target"]["payment_policy"] = payment_policy;
        fixture
            .serve(serde_json::from_value(surface).unwrap())
            .await;
        let call = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "search", "arguments": {}}});
        let (status, headers, body) = fixture
            .send(call_to("POST", "/vendor", Some(call)))
            .await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE, "{case}: {body}");
        assert_eq!(body.pointer(refusal_at), Some(&refusal), "{case}: {body}");
        assert!(
            headers
                .get("payment-required")
                .is_none(),
            "{case}"
        );
    }
    assert!(
        fixture
            .vendor
            .requests()
            .is_empty()
    );
}

/// The injection of a refreshed grant into the one retry is audited as the
/// first one is: under the caller's identity hash, whose grant it is or who
/// acts as the owner, with the binding's subject in the detail; and the
/// refreshed grant is recorded as used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_retry_is_audited_under_its_caller_and_its_grant_marked_used() {
    for (subject, key) in [("owner", owner_key()), ("caller", caller_key(&caller_principal()))] {
        let fixture = Fixture::new(vec![refresh_answer("second")], vec![rejected_token(), vendor_result()]).await;
        let target = format!("{}/mcp", fixture.vendor.origin());
        fixture
            .serve(vendor_surface("mcp", &target, subject))
            .await;
        fixture
            .store(&key, "first")
            .await;
        let ((status, _, body), events) = crate::audit::producer::capture(async {
            fixture
                .send(mcp_call(Some(KEY)))
                .await
        })
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{subject}: {body}");
        let injected: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, crate::delegation_vault::audit::DelegationAuditAction::TokenInjected))
            .map(|event| {
                (
                    event
                        .user_identity_hash
                        .clone(),
                    event.detail.clone(),
                )
            })
            .collect();
        let expected = (Some(caller_principal()), Some(format!("grant_by_binding:{subject}:target")));
        assert_eq!(injected, [expected.clone(), expected], "{subject}");
        let kept = fixture
            .vault
            .grant(&key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.access_token, "second", "{subject}");
        assert!(
            kept.last_used_at
                .zip(kept.refreshed_at)
                .is_some_and(|(used, refreshed)| used >= refreshed),
            "{subject}: the refreshed grant is recorded as used: {:?} {:?}",
            kept.last_used_at,
            kept.refreshed_at
        );
    }
}
