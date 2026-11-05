//! Target authentication from a credential provider E2E: a provider save refuses an http
//! token endpoint; a surface save takes a machine credential provider and refuses
//! `credential_lookup`, an unknown provider and a provider that needs a user's consent; a
//! token endpoint the egress policy blocks fails the request without reaching the token
//! endpoint or the Target.

use super::helpers::{self, GatewayHarness, configure_admin_api};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_save_accepts_only_a_target_auth_method_the_gateway_can_use() {
    let mut admin = None;
    let h = GatewayHarness::start(|_, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.unwrap();
    let api = format!("{}/api/v1", h.gateway_base);
    for (secret_id, value) in
        [("target-client-id", "client"), ("target-client-secret", "secret"), ("caller-key", "caller")]
    {
        let created = admin
            .post(format!("{api}/secrets/new"))
            .json(&json!({"name": secret_id, "secret_id": secret_id, "value": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201, "{}", created.text().await.unwrap());
    }
    let insecure = admin
        .post(format!("{api}/credential-providers"))
        .json(&json!({
            "name": "insecure", "provider_id": "insecure", "provider_type": "oauth2_client_credentials",
            "token_endpoint": "http://192.0.2.1/token",
            "client_id_secret_ref": "target-client-id", "client_secret_secret_ref": "target-client-secret"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(insecure.status(), 400);
    let body: serde_json::Value = insecure.json().await.unwrap();
    assert_eq!(body["error"], "token_endpoint must be an https URL");
    let mut provider_ids = Vec::new();
    for (provider_id, provider_type) in
        [("machine", "oauth2_client_credentials"), ("consent", "oauth2_authorization_code")]
    {
        let created = admin
            .post(format!("{api}/credential-providers"))
            .json(&json!({
                "name": provider_id, "provider_id": provider_id, "provider_type": provider_type,
                "authorization_endpoint": "https://192.0.2.1/authorize",
                "token_endpoint": "https://192.0.2.1/token",
                "client_id_secret_ref": "target-client-id", "client_secret_secret_ref": "target-client-secret"
            }))
            .send()
            .await
            .unwrap();
        let status = created.status();
        let created: serde_json::Value = created.json().await.unwrap();
        assert_eq!(status, 201, "{created}");
        provider_ids.push(
            created["id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let surface = |method: serde_json::Value| {
        json!({
            "name": "target-auth-provider",
            "access_point": {
                "listen_address": h.gateway_base, "route": "/smoke", "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "secret_id": "caller-key",
                    "extraction": {"source": "http_header", "field": "X-Caller-Key"}
                }]}
            },
            "target": { "endpoint": "https://127.0.0.1:9/", "auth": { "method": method } }
        })
    };

    let accepted = admin
        .post(format!("{api}/surfaces"))
        .json(&surface(json!({"credential_provider": {"provider_id": provider_ids[0]}})))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 201, "{}", accepted.text().await.unwrap());

    for (case, method, reason) in [
        (
            "consent provider",
            json!({"credential_provider": {"provider_id": provider_ids[1]}}),
            "cannot use an oauth2_authorization_code credential provider",
        ),
        (
            "unknown provider",
            json!({"credential_provider": {"provider_id": "no-such-provider"}}),
            "Credential provider reference is not accessible",
        ),
        ("credential lookup", json!("credential_lookup"), "credential_lookup is not supported"),
    ] {
        let refused = admin
            .post(format!("{api}/surfaces"))
            .json(&surface(method))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 400, "{case}");
        let body = refused.text().await.unwrap();
        assert!(body.contains(reason), "{case}: {body}");
    }
}

fn write_machine_provider(
    bootstrap: &crate::config::BootstrapConfig,
    token_endpoint: &str,
) {
    use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
    use crate::secrets::SecretsStore;

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let secrets = crate::secrets::FilesystemSecretsStore::new(
                &bootstrap
                    .storage_paths
                    .secrets,
            )
            .unwrap();
            for secret_id in ["target-client-id", "target-client-secret"] {
                secrets
                    .create(crate::secrets::CreateSecretRequest {
                        tenant_id: None,
                        name: secret_id.into(),
                        secret_id: secret_id.into(),
                        description: None,
                        value: "value".into(),
                        secret_type: "General".into(),
                        tags: vec![],
                    })
                    .await
                    .unwrap();
            }
            FileSystemCredentialProviderStore::new(
                bootstrap
                    .storage_paths
                    .credential_providers
                    .clone()
                    .into(),
            )
            .await
            .unwrap()
            .create(
                serde_json::from_value(json!({
                    "id": "machine", "name": "machine", "provider_id": "machine",
                    "provider_type": "oauth2_client_credentials", "token_endpoint": token_endpoint,
                    "client_id_secret_ref": "target-client-id", "client_secret_secret_ref": "target-client-secret",
                    "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        })
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_endpoint_the_egress_policy_blocks_fails_the_request_before_the_target() {
    let token_requests = Arc::new(AtomicUsize::new(0));
    let counter = token_requests.clone();
    let token_app = axum::Router::new().fallback(axum::routing::post(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        async { axum::Json(json!({"access_token": "provider-token", "token_type": "Bearer", "expires_in": 3600})) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let mut token_server = tokio::task::JoinSet::new();
    token_server.spawn(async move {
        axum::serve(listener, token_app)
            .await
            .unwrap();
    });
    let h = GatewayHarness::start(|_, gw_config, bootstrap| {
        write_machine_provider(bootstrap, &token_endpoint);
        let mut surface = helpers::build_minimal_channel();
        surface.target.auth = Some(
            serde_json::from_value(json!({"method": {"credential_provider": {"provider_id": "machine"}}})).unwrap(),
        );
        gw_config.surfaces = vec![surface];
    })
    .await;

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 502);
    let body = response.text().await.unwrap();
    assert!(body.contains("Target authentication failed"), "{body}");
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(token_requests.load(Ordering::SeqCst), 0);
}
