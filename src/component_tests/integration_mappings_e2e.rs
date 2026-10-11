//! The management API built by the orchestrator serves the user and identity integration
//! mapping routes.

use super::helpers::{GatewayHarness, configure_admin_api};

#[tokio::test(flavor = "multi_thread")]
async fn the_management_api_serves_user_and_identity_mappings() {
    let mut admin = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.expect("admin client");

    for path in ["users/integrations", "identities/integrations"] {
        let response = admin
            .get(format!("{}/api/v1/{path}", harness.gateway_base))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "GET /api/v1/{path}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["integration_integrations"].is_array(), "GET /api/v1/{path}: {body}");
    }
}
