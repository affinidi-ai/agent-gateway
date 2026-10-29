use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::{ProcessingResult, process_forward_request};
use crate::component_tests::helpers::MockServer;
use crate::component_tests::helpers::mock_auth_server::MockAuthServer;
use crate::component_tests::helpers::test_mode::TestModeEnv;
use crate::config::agent_surface::AgentSurface;
use crate::credential_providers::CredentialProvider;
use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
use crate::delegation_vault::gateway_token::{GatewayTokenCache, GrantEgress};
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::test_helpers::{install_listener_manager_with_peers, rerun_in_isolated_process};
use crate::gateways::types::{ExposureMode, Gateway, GatewayType};
use crate::messages::MessageType;
use crate::proxy::target_card::tests::{PROTECTED_AGENT_DID, ProtectedTarget};
use crate::proxy::target_credentials::TargetCredentialResolver;
use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const SENDER_DID: &str = "did:web:sender.example";
const CALLER_KEY: &str = "caller-key-1";

async fn install_provider_resolver(
    root: &std::path::Path,
    auth_server: &MockAuthServer,
) -> (Arc<dyn SecretsStore>, Arc<dyn CredentialProviderStorage>) {
    let secrets: Arc<dyn SecretsStore> = Arc::new(
        FilesystemSecretsStore::new_async(
            root.join("secrets")
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store"),
    );
    for (secret_id, value) in [
        ("GW_ID", "gateway-client"),
        ("GW_SECRET", "gateway-secret"),
        ("CALLER_KEYS", CALLER_KEY),
        ("TARGET_KEY", "target-secret"),
    ] {
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
        FileSystemCredentialProviderStore::new(root.join("providers"))
            .await
            .expect("provider store"),
    );
    let provider: CredentialProvider = serde_json::from_value(json!({
        "id": "cp-receiver", "name": "receiver", "provider_id": "receiver",
        "provider_type": "oauth2_client_credentials", "token_endpoint": auth_server.token_endpoint(),
        "client_id_secret_ref": "GW_ID", "client_secret_secret_ref": "GW_SECRET",
        "default_scopes": ["agent.invoke"],
        "created_at": "2026-10-21T00:00:00Z", "updated_at": "2026-10-21T00:00:00Z"
    }))
    .expect("provider JSON");
    providers
        .create(provider)
        .await
        .expect("provider");
    let tokens = Arc::new(GatewayTokenCache::new(GrantEgress {
        timeout: std::time::Duration::from_secs(5),
        exact_allowlist: Some(auth_server.token_endpoint()),
    }));
    let strategies = Arc::new(
        crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(root.join("strategies"))
            .await
            .expect("strategy store"),
    );
    super::init_source_auth_middleware(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
        Arc::new(crate::didauth::DidAuthSessionStore::new()),
        strategies,
        Arc::new(crate::jwt_bearer::JwksClient::new()),
        Some(secrets.clone()),
        Arc::new(dashmap::DashMap::new()),
        None,
        None,
    )))
    .await;
    super::init_target_credential_resolver(TargetCredentialResolver::new(
        Some(secrets.clone()),
        Some(providers.clone()),
        tokens,
    ));
    (secrets, providers)
}

async fn save_surface(
    storage_path: &std::path::Path,
    surface: Value,
) -> AgentSurface {
    let surface: AgentSurface = serde_json::from_value(surface).expect("surface JSON");
    FileSystemAgentSurfaceStore::new(storage_path.to_path_buf())
        .await
        .expect("surface store")
        .save(&surface)
        .await
        .expect("surface saved");
    surface
}

fn sender_gateway() -> Gateway {
    let mut sender = Gateway::new(SENDER_DID.to_string(), String::new(), SENDER_DID.to_string(), GatewayType::Remote);
    sender.exposure_mode = Some(ExposureMode::All);
    sender.issuer_did = Some("did:web:sender-gateway.example".to_string());
    sender
}

fn forward_get(
    storage_path: &std::path::Path,
    surface_id: &str,
    path: &str,
) -> ReceivedMessage {
    forward(storage_path, surface_id, "GET", path, json!({}), Value::Null)
}

fn forward(
    storage_path: &std::path::Path,
    surface_id: &str,
    method: &str,
    path: &str,
    headers: Value,
    body: Value,
) -> ReceivedMessage {
    ReceivedMessage::new(
        "receiver-connection".to_string(),
        "receiver-gateway".to_string(),
        MessageType::ForwardRequest.to_string(),
        uuid::Uuid::new_v4().to_string(),
        None,
        Some(SENDER_DID.to_string()),
        vec!["did:web:receiver.example".to_string()],
        None,
        Some(super::super::envelope_replay::now_secs() + 60),
        json!({"channel_id": surface_id, "method": method, "path": path, "headers": headers, "body": body}),
        MessageMetadata {
            encrypted: true,
            authenticated: true,
            from_key: None,
            extra: Value::Null,
        },
    )
    .with_context("agent_surface_storage_path", json!(storage_path))
}

fn forwarded_status(result: &ProcessingResult) -> u64 {
    match result {
        ProcessingResult::RequiresResponse { response_body, .. } => response_body["status"]
            .as_u64()
            .unwrap_or_else(|| panic!("ForwardResponse status: {response_body}")),
        other => panic!("expected a ForwardResponse, got {other:?}"),
    }
}

fn last_target_request(target: &MockServer) -> (String, Option<String>) {
    let request = target
        .last_request_rx
        .borrow()
        .clone()
        .expect("the Target received a request");
    (
        request.path,
        request
            .headers
            .get("authorization")
            .cloned(),
    )
}

#[tokio::test]
async fn fabric_public_reads_carry_the_gateway_token_only_on_the_agent_card_fetch() {
    if rerun_in_isolated_process() {
        return;
    }
    let card = json!({"name": "agent", "description": "receiver", "url": "http://agent.invalid/", "version": "1.0",
        "capabilities": {}, "skills": [], "defaultInputModes": ["text"], "defaultOutputModes": ["text"]});
    let auth_server = MockAuthServer::start().await;
    auth_server.register_client("gateway-client", "gateway-secret");
    let target = MockServer::start_with_response(card.to_string()).await;
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", target.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let directory = tempfile::tempdir().expect("tempdir");
    let _issuer_dir = install_listener_manager_with_peers(directory.path(), &[sender_gateway()]).await;
    install_provider_resolver(directory.path(), &auth_server).await;
    let storage_path = directory
        .path()
        .join("surfaces");
    let surface = save_surface(
        &storage_path,
        json!({
            "surface_id": "receiver-card", "name": "receiver-card",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/route", "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "extraction": {"source": "http_header", "field": "X-Caller-Key"},
                    "secret_id": "CALLER_KEYS"
                }]}},
            "target": {"endpoint": format!("{}/api", target.url()), "auth": provider_auth()}
        }),
    )
    .await;

    for path in ["/admin/reports/discovery", "/.well-known/ucp"] {
        let before = target
            .request_count
            .load(Ordering::SeqCst);
        let result = Box::pin(process_forward_request(&forward_get(&storage_path, &surface.surface_id, path))).await;
        assert_eq!(forwarded_status(&result), 200, "{path}");
        assert_eq!(
            target
                .request_count
                .load(Ordering::SeqCst),
            before + 1,
            "{path} reaches the Target"
        );
        assert_eq!(last_target_request(&target), (format!("/api{path}"), None), "{path} carries no gateway token");
    }
    assert_eq!(auth_server.token_request_count(), 0);

    let result = Box::pin(process_forward_request(&forward_get(
        &storage_path,
        &surface.surface_id,
        "/.well-known/agent-card.json",
    )))
    .await;
    assert_eq!(forwarded_status(&result), 200);
    let (path, authorization) = last_target_request(&target);
    assert_eq!(path, "/api/.well-known/agent-card.json");
    let authorization = authorization.expect("the agent card fetch carries the gateway token");
    assert!(authorization.starts_with("Bearer ey"), "{authorization}");
    assert_eq!(auth_server.token_request_count(), 1);
}

struct Receiver {
    _directory: tempfile::TempDir,
    _issuer_dir: tempfile::TempDir,
    _test_mode: TestModeEnv,
    storage_path: std::path::PathBuf,
    auth_server: MockAuthServer,
    target: MockServer,
    secrets: Arc<dyn SecretsStore>,
    providers: Arc<dyn CredentialProviderStorage>,
}

impl Receiver {
    async fn start(target_response: Value) -> Self {
        let auth_server = MockAuthServer::start().await;
        auth_server.register_client("gateway-client", "gateway-secret");
        let target = MockServer::start_with_response(target_response.to_string()).await;
        let test_mode = TestModeEnv::enabled(
            &format!("{},{}", target.url(), auth_server.egress_allowlist()),
            &auth_server.oauth_endpoint_allowlist(),
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let issuer_dir = install_listener_manager_with_peers(directory.path(), &[sender_gateway()]).await;
        let (secrets, providers) = install_provider_resolver(directory.path(), &auth_server).await;
        let storage_path = directory
            .path()
            .join("surfaces");
        Self {
            secrets,
            providers,
            _directory: directory,
            _issuer_dir: issuer_dir,
            _test_mode: test_mode,
            storage_path,
            auth_server,
            target,
        }
    }

    async fn surface(
        &self,
        surface_id: &str,
        caller_authentication: bool,
        auth: Value,
    ) {
        let mut access_point = json!({"listen_address": "127.0.0.1:0", "route": "/route", "protocol": "a2a"});
        if caller_authentication {
            access_point["caller_authentication"] = json!({"methods": [{
                "type": "api_key", "extraction": {"source": "http_header", "field": "X-Caller-Key"},
                "secret_id": "CALLER_KEYS"
            }]});
        }
        self.save(json!({
            "surface_id": surface_id, "name": surface_id, "access_point": access_point,
            "target": {"endpoint": format!("{}/api", self.target.url()), "auth": auth}
        }))
        .await;
    }

    async fn save(
        &self,
        surface: Value,
    ) {
        save_surface(&self.storage_path, surface).await;
    }

    async fn send(
        &self,
        surface_id: &str,
        method: &str,
        path: &str,
        headers: Value,
        body: Value,
    ) -> u64 {
        let message = forward(&self.storage_path, surface_id, method, path, headers, body);
        forwarded_status(&Box::pin(process_forward_request(&message)).await)
    }

    fn forwarded(&self) -> usize {
        self.target
            .request_count
            .load(Ordering::SeqCst)
    }

    fn last_request(&self) -> crate::component_tests::helpers::ReceivedRequest {
        self.target
            .last_request_rx
            .borrow()
            .clone()
            .expect("the Target received a request")
    }
}

fn provider_auth() -> Value {
    json!({"method": {"credential_provider": {"credential_provider_id": "cp-receiver"}}, "fallback": "reject"})
}

fn agent_card() -> Value {
    json!({"name": "agent", "description": "receiver", "url": "http://agent.invalid/", "version": "1.0",
        "capabilities": {}, "skills": [], "defaultInputModes": ["text"], "defaultOutputModes": ["text"]})
}

#[tokio::test]
async fn fabric_card_fetch_is_a_get_the_receiving_gateway_builds_itself() {
    if rerun_in_isolated_process() {
        return;
    }
    let receiver = Receiver::start(agent_card()).await;
    receiver
        .surface("receiver-card", true, provider_auth())
        .await;

    let before = receiver.forwarded();
    assert_eq!(
        receiver
            .send("receiver-card", "GET", "/.well-known/agent-card.json?x=1", json!({}), Value::Null)
            .await,
        200
    );
    assert_eq!(receiver.forwarded(), before + 1, "the card path with a query still reaches the Target");
    assert_eq!(
        receiver
            .last_request()
            .headers
            .get("authorization"),
        None,
        "a caller query never rides on a credentialed request"
    );
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        0
    );

    assert_eq!(
        receiver
            .send(
                "receiver-card",
                "GET",
                "/.well-known/agent-card.json",
                json!({"x-http-method-override": "DELETE", "accept": "application/json",
                    "accept-language": "en", "x-extra": "1", "authorization": "Bearer from-the-peer"}),
                json!({"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel"}),
            )
            .await,
        200
    );
    let card_fetch = receiver.last_request();
    assert_eq!(card_fetch.method, "GET");
    assert_eq!(card_fetch.path, "/api/.well-known/agent-card.json");
    assert_eq!(card_fetch.body, "", "no caller body");
    assert_eq!(
        card_fetch
            .headers
            .get("x-http-method-override"),
        None
    );
    assert_eq!(
        card_fetch
            .headers
            .get("x-extra"),
        None
    );
    assert_eq!(
        card_fetch
            .headers
            .get("accept")
            .map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        card_fetch
            .headers
            .get("accept-language")
            .map(String::as_str),
        Some("en")
    );
    let authorization = card_fetch
        .headers
        .get("authorization")
        .expect("the card fetch carries the gateway token");
    assert!(
        authorization.starts_with("Bearer ey") && !authorization.contains(','),
        "only the gateway token, never the peer's header: {authorization}"
    );
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        1
    );
}

#[tokio::test]
async fn fabric_card_fetch_with_an_unavailable_provider_is_a_generic_502() {
    use crate::audit::request_events::{RejectionReason, RejectionStage};
    use crate::delegation_vault::audit::DelegationAuditAction::RequestRejected;
    use crate::proxy::target_credentials::TARGET_AUTH_FAILED;

    if rerun_in_isolated_process() {
        return;
    }
    let receiver = Receiver::start(agent_card()).await;
    receiver
        .surface(
            "receiver-card-missing",
            true,
            json!({"method": {"credential_provider": {"credential_provider_id": "cp-missing"}}, "fallback": "reject"}),
        )
        .await;
    let before = receiver.forwarded();

    let message = forward_get(&receiver.storage_path, "receiver-card-missing", "/.well-known/agent-card.json");
    let (result, events) = crate::audit::producer::capture(Box::pin(process_forward_request(&message))).await;

    assert_eq!(forwarded_status(&result), 502);
    let ProcessingResult::RequiresResponse { response_body, .. } = &result else {
        panic!("expected a ForwardResponse, got {result:?}");
    };
    assert_eq!(response_body["error"], TARGET_AUTH_FAILED);
    let body: Value = serde_json::from_str(
        response_body["body"]
            .as_str()
            .expect("the ForwardResponse carries a body"),
    )
    .expect("the body is JSON");
    assert_eq!(body["status"], 502);
    assert_eq!(body["detail"], TARGET_AUTH_FAILED);
    let serialized = response_body.to_string();
    for leak in [
        "cp-missing",
        "Bearer",
        &receiver
            .auth_server
            .token_endpoint(),
        receiver.auth_server.origin(),
    ] {
        assert!(!serialized.contains(leak), "the 502 reveals {leak:?}: {serialized}");
    }
    assert_eq!(receiver.forwarded(), before, "the Target is not called");
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        0
    );
    let rejected: Vec<_> = events
        .iter()
        .filter(|event| matches!(event.event, RequestRejected { .. }))
        .collect();
    assert_eq!(rejected.len(), 1, "{events:?}");
    assert_eq!(
        rejected[0]
            .surface_id
            .as_deref(),
        Some("receiver-card-missing")
    );
    match &rejected[0].event {
        RequestRejected { stage, reason, http_status, .. } => {
            assert_eq!(*stage, RejectionStage::Forward);
            assert_eq!(*reason, RejectionReason::TargetAuthUnavailable);
            assert_eq!(*http_status, 502);
        }
        other => panic!("expected RequestRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_receiving_gateway_sends_at_most_one_credential_per_header_name() {
    if rerun_in_isolated_process() {
        return;
    }
    let receiver = Receiver::start(json!({"jsonrpc": "2.0", "id": 1, "result": {}})).await;
    receiver
        .surface("receiver-provider", true, provider_auth())
        .await;
    receiver
        .surface(
            "receiver-static",
            false,
            json!({"method": {"static_secret": {"secret_id": "TARGET_KEY", "header_name": "X-Target-Key"}},
                "fallback": "reject"}),
        )
        .await;
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"});

    assert_eq!(
        receiver
            .send("receiver-provider", "POST", "/", json!({"x-caller-key": CALLER_KEY}), call.clone())
            .await,
        200
    );
    let authorization = receiver
        .last_request()
        .headers
        .get("authorization")
        .cloned()
        .expect("an authenticated call carries the gateway token");
    assert!(authorization.starts_with("Bearer ey"), "{authorization}");

    let before = receiver.forwarded();
    assert_eq!(
        receiver
            .send(
                "receiver-provider",
                "POST",
                "/",
                json!({"x-caller-key": CALLER_KEY, "authorization": "Bearer delegated-by-the-peer"}),
                call.clone(),
            )
            .await,
        502,
        "a forwarded header under the provider credential's name fails closed"
    );
    assert_eq!(receiver.forwarded(), before, "the request never reaches the Target");

    assert_eq!(
        receiver
            .send("receiver-static", "POST", "/", json!({"x-target-key": "from-the-peer"}), call.clone())
            .await,
        200
    );
    assert_eq!(
        receiver
            .last_request()
            .headers
            .get("x-target-key")
            .map(String::as_str),
        Some("from-the-peer"),
        "a static secret yields to the header the peer sent, and is never appended"
    );
    assert_eq!(
        receiver
            .send("receiver-static", "POST", "/", json!({}), call)
            .await,
        200
    );
    assert_eq!(
        receiver
            .last_request()
            .headers
            .get("x-target-key")
            .map(String::as_str),
        Some("target-secret")
    );
}

#[tokio::test]
async fn fabric_card_fetch_follows_the_surface_card_location_override() {
    if rerun_in_isolated_process() {
        return;
    }
    let receiver = Receiver::start(agent_card()).await;
    receiver
        .save(json!({
            "surface_id": "receiver-override", "name": "receiver-override",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/route", "protocol": "a2a",
                "agent_card_path": "/cards/receiver.json"},
            "target": {"endpoint": format!("{}/api", receiver.target.url()), "auth": provider_auth()}
        }))
        .await;
    receiver
        .surface("receiver-default", false, provider_auth())
        .await;

    assert_eq!(
        receiver
            .send("receiver-override", "GET", "/.well-known/agent-card.json", json!({}), Value::Null)
            .await,
        200
    );
    let card_fetch = receiver.last_request();
    assert_eq!(card_fetch.path, "/cards/receiver.json", "the card fetch goes to the configured location");
    let authorization = card_fetch
        .headers
        .get("authorization")
        .expect("the card fetch at the configured location carries the gateway token");
    assert!(authorization.starts_with("Bearer ey"), "{authorization}");
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        1
    );

    assert_eq!(
        receiver
            .send("receiver-default", "GET", "/discovery?x=1", json!({}), Value::Null)
            .await,
        200
    );
    let discovery = receiver.last_request();
    assert_eq!(discovery.path, "/api/discovery");
    assert_eq!(
        discovery
            .headers
            .get("authorization"),
        None,
        "a public read that is not the card fetch"
    );
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        1
    );
}

#[tokio::test]
async fn fabric_surface_policy_reads_a_protected_card_with_the_gateway_token() {
    if rerun_in_isolated_process() {
        return;
    }
    let auth_server = MockAuthServer::start().await;
    auth_server.register_client("gateway-client", "gateway-secret");
    let target = ProtectedTarget::start().await;
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", target.url, auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let directory = tempfile::tempdir().expect("tempdir");
    let _issuer_dir = install_listener_manager_with_peers(directory.path(), &[sender_gateway()]).await;
    install_provider_resolver(directory.path(), &auth_server).await;
    let policies = crate::policies::SurfacePolicyManager::new();
    let rego = format!(
        "package surface.policy\n\ndefault allow := false\n\nallow if input.agent.did == \"{PROTECTED_AGENT_DID}\"\n"
    );
    let storage_path = directory
        .path()
        .join("surfaces");
    for (surface_id, provider) in [("protected-card", "cp-receiver"), ("unavailable-token", "cp-missing")] {
        policies
            .load_policy_text(surface_id, &rego)
            .expect("policy compiles");
        save_surface(
            &storage_path,
            json!({
                "surface_id": surface_id, "name": surface_id,
                "access_point": {"listen_address": "127.0.0.1:0", "route": "/route", "protocol": "a2a"},
                "target": {"endpoint": format!("{}/api", target.url), "policy": {"policy_definition_id": "card-policy"},
                    "auth": {"method": {"credential_provider": {"credential_provider_id": provider}}, "fallback": "reject"}}
            }),
        )
        .await;
    }
    super::init_policy_manager(Arc::new(policies)).await;
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"});

    let message = forward(&storage_path, "protected-card", "POST", "/", json!({}), call.clone());
    assert_eq!(
        forwarded_status(&Box::pin(process_forward_request(&message)).await),
        200,
        "the policy sees the DID from the protected card"
    );
    assert_eq!(
        target
            .requests
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(auth_server.token_request_count(), 1, "the card fetch and the call share one gateway token");

    let message = forward(&storage_path, "unavailable-token", "POST", "/", json!({}), call);
    assert_eq!(
        forwarded_status(&Box::pin(process_forward_request(&message)).await),
        403,
        "without the token the card is not read and the policy denies"
    );
    assert_eq!(
        target
            .requests
            .load(Ordering::SeqCst),
        1,
        "the card was never asked for without the token"
    );
    assert_eq!(auth_server.token_request_count(), 1);
}

#[tokio::test]
async fn fabric_delegated_credentials_reach_the_target_and_a_jwt_bearer_binding_stays_off_an_unsafe_leg() {
    if rerun_in_isolated_process() {
        return;
    }
    let receiver = Receiver::start(json!({"jsonrpc": "2.0", "id": 1, "result": {}})).await;
    receiver
        .secrets
        .create(CreateSecretRequest {
            tenant_id: None,
            name: "UPSTREAM_KEY".into(),
            secret_id: "UPSTREAM_KEY".into(),
            description: None,
            value: "upstream-secret".into(),
            secret_type: "General".into(),
            tags: vec![],
        })
        .await
        .expect("secret");
    receiver
        .secrets
        .create(CreateSecretRequest {
            tenant_id: None,
            name: "JWT_SIGNING_KEY".into(),
            secret_id: "JWT_SIGNING_KEY".into(),
            description: None,
            value: crate::component_tests::helpers::oidc_keys::SigningFixture::es256(0)
                .private_pkcs8_pem()
                .into(),
            secret_type: "General".into(),
            tags: vec![],
        })
        .await
        .expect("signing key secret");
    receiver
        .auth_server
        .register_jwt_client(crate::component_tests::helpers::mock_auth_server::JwtBearerClient {
            iss: "https://agent.example".into(),
            sub: "https://agent.example".into(),
            keys: vec![crate::component_tests::helpers::oidc_keys::SigningFixture::es256(0).with_kid("key-1")],
        });
    for provider in [
        json!({"id": "cp-upstream", "name": "upstream", "provider_id": "upstream", "provider_type": "api_key",
            "api_key_secret_ref": "UPSTREAM_KEY"}),
        json!({"id": "cp-jwt", "name": "jwt", "provider_id": "jwt", "provider_type": "oauth2_jwt_bearer",
            "token_endpoint": receiver.auth_server.token_endpoint(),
            "jwt_bearer": {"assertion_issuer": "https://agent.example", "signing_key_secret_ref": "JWT_SIGNING_KEY",
                "signing_algorithm": "ES256", "key_id": "key-1"}}),
    ] {
        let mut provider = provider;
        provider["created_at"] = "2026-10-21T00:00:00Z".into();
        provider["updated_at"] = "2026-10-21T00:00:00Z".into();
        receiver
            .providers
            .create(serde_json::from_value(provider).expect("provider JSON"))
            .await
            .expect("provider");
    }
    let vault = Arc::new(
        crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(
            receiver
                ._directory
                .path()
                .join("vault"),
        )
        .await
        .expect("vault store"),
    );
    super::init_delegation_vault_store(vault).await;
    super::init_secrets_store(receiver.secrets.clone()).await;
    super::init_credential_provider_store(receiver.providers.clone()).await;
    super::init_gateway_base_url("https://gateway.example".to_string()).await;

    let bound = |surface_id: &str, binding: Value| {
        json!({
            "surface_id": surface_id, "name": surface_id,
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/route", "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "extraction": {"source": "http_header", "field": "X-Caller-Key"},
                    "secret_id": "CALLER_KEYS"
                }]}},
            "target": {"endpoint": format!("{}/api", receiver.target.url())},
            "outbound_credentials": [binding]
        })
    };
    receiver
        .save(bound(
            "delegated-header",
            json!({"credential_provider_id": "cp-upstream",
                "inject_as": {"type": "custom_header", "name": "X-Upstream-Key", "format": "{value}"}}),
        ))
        .await;
    receiver
        .save(bound(
            "delegated-bad-header",
            json!({"credential_provider_id": "cp-upstream",
                "inject_as": {"type": "custom_header", "name": "Bad Header", "format": "{value}"}}),
        ))
        .await;
    receiver
        .save(bound("delegated-jwt-bearer-authenticated", json!({"credential_provider_id": "cp-jwt"})))
        .await;
    let mut anonymous = bound("delegated-jwt-bearer", json!({"credential_provider_id": "cp-jwt"}));
    anonymous["access_point"]
        .as_object_mut()
        .expect("access point")
        .remove("caller_authentication");
    receiver.save(anonymous).await;
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"});
    let caller = json!({"x-caller-key": CALLER_KEY});

    assert_eq!(
        receiver
            .send("delegated-header", "POST", "/", caller.clone(), call.clone())
            .await,
        200
    );
    assert_eq!(
        receiver
            .last_request()
            .headers
            .get("x-upstream-key")
            .map(String::as_str),
        Some("upstream-secret")
    );

    let before = receiver.forwarded();
    assert_eq!(
        receiver
            .send("delegated-bad-header", "POST", "/", caller.clone(), call.clone())
            .await,
        500
    );
    assert_eq!(receiver.forwarded(), before, "a header the gateway cannot send never reaches the Target");

    assert_eq!(
        receiver
            .send("delegated-jwt-bearer", "POST", "/", caller.clone(), call.clone())
            .await,
        200
    );
    assert_eq!(
        receiver
            .last_request()
            .headers
            .get("authorization"),
        None
    );
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        0,
        "no token is requested for a forbidden leg"
    );

    assert_eq!(
        receiver
            .send("delegated-jwt-bearer-authenticated", "POST", "/", caller, call)
            .await,
        200
    );
    assert_eq!(
        receiver
            .auth_server
            .token_request_count(),
        1,
        "a permitted leg requests the gateway token"
    );
    assert!(
        receiver
            .last_request()
            .headers
            .get("authorization")
            .is_some_and(|value| value.starts_with("Bearer ")),
        "the granted gateway token reaches the Target"
    );
}

#[tokio::test]
async fn fabric_mcp_proxy_calls_carry_the_target_credential_and_refuse_a_missing_or_disabled_proxy() {
    use crate::mcp_proxies::filesystem::McpProxyStore;
    if rerun_in_isolated_process() {
        return;
    }
    let receiver = Receiver::start(json!({"ok": true})).await;
    let proxies = Arc::new(
        crate::mcp_proxies::FileSystemMcpProxyStore::new(
            receiver
                ._directory
                .path()
                .join("mcp_proxies"),
        )
        .await
        .expect("proxy store"),
    );
    let spec = json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
        "/alpha": {"get": {"operationId": "alpha", "summary": "Alpha tool", "responses": {"200": {"description": "OK"}}}}
    }});
    let proxy = |name: &str| {
        crate::mcp_proxies::types::McpProxy::new(
            name.into(),
            String::new(),
            receiver.target.url(),
            spec.to_string(),
            "/mcp".into(),
            format!("/{name}"),
        )
    };
    let active = proxy("active");
    let mut disabled = proxy("disabled");
    disabled.status = crate::mcp_proxies::types::McpProxyStatus::Disabled;
    for stored in [&active, &disabled] {
        proxies
            .create(stored)
            .await
            .expect("proxy saved");
    }
    super::init_mcp_proxy_store(proxies).await;

    let through = |surface_id: &str, proxy_id: &str| {
        json!({
            "surface_id": surface_id, "name": surface_id,
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/mcp-route", "protocol": "mcp"},
            "target": {"endpoint": format!("proxy://{proxy_id}"),
                "auth": {"method": {"static_secret": {"secret_id": "TARGET_KEY", "header_name": "X-Target-Key"}},
                    "fallback": "reject"}}
        })
    };
    receiver
        .save(through("proxied", &active.id))
        .await;
    receiver
        .save(through("proxy-missing", "no-such-proxy"))
        .await;
    receiver
        .save(through("proxy-disabled", &disabled.id))
        .await;
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "alpha", "arguments": {}}});

    assert_eq!(
        receiver
            .send("proxied", "POST", "/", json!({}), call.clone())
            .await,
        200
    );
    let request = receiver.last_request();
    assert_eq!(request.path, "/alpha");
    assert_eq!(
        request
            .headers
            .get("x-target-key")
            .map(String::as_str),
        Some("target-secret"),
        "the proxy's backend call carries the Target credential"
    );

    let before = receiver.forwarded();
    assert_eq!(
        receiver
            .send("proxy-missing", "POST", "/", json!({}), call.clone())
            .await,
        404
    );
    assert_eq!(
        receiver
            .send("proxy-disabled", "POST", "/", json!({}), call)
            .await,
        503
    );
    assert_eq!(receiver.forwarded(), before, "a missing or disabled proxy never reaches its backend");
}
