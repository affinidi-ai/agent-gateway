//! Target authentication from a credential provider E2E: a surface save takes a
//! machine credential provider and refuses `credential_lookup`, an unknown provider and
//! a provider that needs a user's consent.

use super::helpers::{GatewayHarness, configure_admin_api};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_save_accepts_only_a_target_auth_method_the_gateway_can_use() {
    let mut admin = None;
    let h = GatewayHarness::start(|_, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.unwrap();
    let api = format!("{}/api/v1", h.gateway_base);
    for (secret_id, value) in [("target-client-id", "client"), ("target-client-secret", "secret")] {
        let created = admin
            .post(format!("{api}/secrets/new"))
            .json(&json!({"name": secret_id, "secret_id": secret_id, "value": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201, "{}", created.text().await.unwrap());
    }
    let mut provider_ids = Vec::new();
    for (provider_id, provider_type) in
        [("machine", "oauth2_client_credentials"), ("consent", "oauth2_authorization_code")]
    {
        let created = admin
            .post(format!("{api}/credential-providers"))
            .json(&json!({
                "name": provider_id, "provider_id": provider_id, "provider_type": provider_type,
                "authorization_endpoint": "http://192.0.2.1/authorize",
                "token_endpoint": "http://192.0.2.1/token",
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
            "access_point": { "listen_address": h.gateway_base, "route": "/smoke", "protocol": "a2a" },
            "target": { "endpoint": h.mock.url(), "auth": { "method": method } }
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
