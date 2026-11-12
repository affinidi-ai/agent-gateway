//! On Fabric receive, a surface with `caller_key` sends its Target the key it derives for a JWT
//! it verified on the request, in place of any caller key the peer sent.

use std::sync::Arc;

use serde_json::json;

use super::fabric_transit_tests::{
    SURFACE_ID, forward_request, forward_response, header_values, ran_in_child, receiver_with_strategies, surface,
};
use crate::component_tests::helpers::RecordingTarget;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const AUDIENCE: &str = "https://receiver.example/agent";

#[tokio::test]
async fn a_jwt_the_receiving_surface_verified_gets_its_caller_key_in_place_of_the_peers() {
    if ran_in_child("ATG_FABRIC_CALLER_KEY_CHILD").await {
        return;
    }
    use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use crate::jwt_bearer::storage::JwtVerificationStrategyStorage;
    use crate::secrets::SecretsStore;

    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    let root = tempfile::tempdir().unwrap();
    let strategies = Arc::new(
        crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.path().join("strategies"))
            .await
            .unwrap(),
    );
    let strategy = strategies
        .create(
            serde_json::from_value(json!({
                "id": "partner-idp", "name": "Partner IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let mut surface = surface("a2a", &target.url, &[]);
    surface
        .access_point
        .caller_authentication = Some(
        serde_json::from_value(json!({ "methods": [{ "type": "jwt_bearer",
            "jwt_verification_strategy_id": strategy.id, "audiences": [AUDIENCE] }] }))
        .unwrap(),
    );
    surface.caller_key = Some(serde_json::from_value(json!({ "secret_id": "caller-keys" })).unwrap());
    let _receiver = receiver_with_strategies(root.path(), &surface, strategies).await;
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        root.path()
            .join("caller-key-secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    secrets
        .create(crate::secrets::CreateSecretRequest {
            tenant_id: None,
            name: "Caller keys".to_string(),
            secret_id: "caller-keys".to_string(),
            description: None,
            value: SECRET.to_string(),
            secret_type: "General".to_string(),
            tags: vec![],
        })
        .await
        .unwrap();
    super::init_secrets_store(Arc::new(secrets)).await;

    let jwt = sign_jwt(
        json!({ "iss": fixture.issuer, "sub": "user-123", "aud": AUDIENCE, "exp": now_secs() + 300 }),
        &fixture.kid,
    );
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } } });
    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "authorization": format!("Bearer {jwt}"),
            "x-caller-key": "peer-sent" }),
        body,
    ))
    .await;
    assert_eq!(response["status"], 200, "{response}");

    let verification = crate::source_auth::JwtVerification::of(
        &strategy,
        &[AUDIENCE.to_string()],
        crate::jwt_bearer::models::AudienceClaim::Aud,
    );
    let expected = crate::proxy::caller_key::derive(
        SECRET.as_bytes(),
        SURFACE_ID,
        crate::proxy::caller_key::KeyedCaller {
            verification: &verification,
            issuer: &fixture.issuer,
            claim: "sub",
            value: "user-123",
        },
    )
    .unwrap();
    let received = target
        .received()
        .pop()
        .unwrap();
    assert_eq!(header_values(&received, "x-caller-key"), [expected.as_str()], "{received:?}");
}

#[tokio::test]
async fn a_jwt_caller_gets_no_caller_key_on_a_plain_http_target_when_https_targets_are_enforced() {
    if ran_in_child("ATG_FABRIC_CALLER_KEY_ENFORCE_CHILD").await {
        return;
    }
    use crate::component_tests::helpers::jwt::{JwksFixture, now_secs, sign_jwt};
    use crate::config::credential_policy::{
        CredentialPolicyConfig, RuleMode, credential_policy, init_credential_policy,
    };
    use crate::jwt_bearer::storage::JwtVerificationStrategyStorage;
    use crate::secrets::SecretsStore;

    init_credential_policy(CredentialPolicyConfig {
        target_https: RuleMode::Enforce,
        ..CredentialPolicyConfig::default()
    });
    assert_eq!(credential_policy().target_https, RuleMode::Enforce, "the child process enforces target_https");

    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(axum::http::StatusCode::OK, &[]).await;
    assert!(
        target
            .url
            .starts_with("http://"),
        "the Target is plain http: {}",
        target.url
    );
    let root = tempfile::tempdir().unwrap();
    let strategies = Arc::new(
        crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.path().join("strategies"))
            .await
            .unwrap(),
    );
    let strategy = strategies
        .create(
            serde_json::from_value(json!({
                "id": "partner-idp", "name": "Partner IdP", "expected_issuer": fixture.issuer,
                "jwks_source": {"type": "remote", "jwks_uri": format!("{}/.well-known/jwks.json", fixture.issuer)},
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let mut surface = surface("a2a", &target.url, &[]);
    surface
        .access_point
        .caller_authentication = Some(
        serde_json::from_value(json!({ "methods": [{ "type": "jwt_bearer",
            "jwt_verification_strategy_id": strategy.id, "audiences": [AUDIENCE] }] }))
        .unwrap(),
    );
    surface.caller_key = Some(serde_json::from_value(json!({ "secret_id": "caller-keys" })).unwrap());
    let _receiver = receiver_with_strategies(root.path(), &surface, strategies).await;
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        root.path()
            .join("caller-key-secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    secrets
        .create(crate::secrets::CreateSecretRequest {
            tenant_id: None,
            name: "Caller keys".to_string(),
            secret_id: "caller-keys".to_string(),
            description: None,
            value: SECRET.to_string(),
            secret_type: "General".to_string(),
            tags: vec![],
        })
        .await
        .unwrap();
    super::init_secrets_store(Arc::new(secrets)).await;

    let jwt = sign_jwt(
        json!({ "iss": fixture.issuer, "sub": "user-123", "aud": AUDIENCE, "exp": now_secs() + 300 }),
        &fixture.kid,
    );
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": { "message": { "role": "user", "messageId": "m-1", "parts": [{ "kind": "text", "text": "hi" }] } } });
    let response = forward_response(&forward_request(
        root.path(),
        json!({ "content-type": "application/json", "authorization": format!("Bearer {jwt}"),
            "x-caller-key": "peer-sent" }),
        body,
    ))
    .await;
    assert_eq!(response["status"], 200, "{response}");

    let received = target
        .received()
        .pop()
        .unwrap();
    assert!(header_values(&received, "x-caller-key").is_empty(), "no caller key, derived or peer-sent: {received:?}");
}

fn mcp_surface_with_browser_origin() -> crate::config::agent_surface::AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "surface-1", "name": "surface-1",
        "access_point": { "listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp" },
        "target": { "endpoint": "https://agent.example" },
        "browser_origins": ["https://chat.example.com"],
    }))
    .unwrap()
}

fn origin_headers(origin: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::ORIGIN, origin.parse().unwrap());
    headers
}

fn receive_policy(framed: bool) -> crate::mcp::modern_http::EndpointHttpPolicy {
    super::fabric_receive_http_policy(
        &mcp_surface_with_browser_origin(),
        crate::mcp::request_validation::runtime_policy_for(crate::mcp::request_validation::McpPathKind::FabricReceive),
        framed,
    )
    .unwrap()
}

#[test]
fn a_framed_fabric_request_admits_a_browser_origin_of_the_surface_and_refuses_another() {
    let framed = receive_policy(true);
    assert_eq!(framed.validate_headers(&origin_headers("https://chat.example.com")), Ok(()));
    assert_eq!(
        framed
            .validate_headers(&origin_headers("https://other.example.com"))
            .map_err(|error| error.status),
        Err(axum::http::StatusCode::FORBIDDEN)
    );
}

#[test]
fn a_buffered_fabric_request_is_not_checked_for_its_origin_again() {
    let buffered = receive_policy(false);
    for origin in ["https://chat.example.com", "https://other.example.com"] {
        assert_eq!(buffered.validate_headers(&origin_headers(origin)), Ok(()), "{origin}");
    }
}
