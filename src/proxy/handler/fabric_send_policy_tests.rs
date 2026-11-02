//! The sending gateway's surface policy on a `fabric://` Target: only a public discovery read
//! (`GET` or `HEAD` of a card path) skips it; any other method on a card-like path is evaluated.

use std::sync::Arc;

use serde_json::json;

use crate::config::agent_surface::AgentSurface;

/// A surface on a `fabric://` Target, connected to its peer gateway, whose surface policy
/// denies every request.
async fn denying_router() -> (crate::state::MultiSurfaceProxyState, [tempfile::TempDir; 2]) {
    let directory = tempfile::tempdir().unwrap();
    let peer = crate::gateways::types::Gateway::new(
        "Peer".into(),
        String::new(),
        "did:example:peer".into(),
        crate::gateways::types::GatewayType::Remote,
    );
    let gateways = Arc::new(
        crate::gateways::FileSystemGatewayStore::new(
            directory
                .path()
                .join("gateways"),
            Some("did:web:gateway.example".into()),
        )
        .await
        .unwrap(),
    );
    crate::gateways::GatewayStore::create(gateways.as_ref(), &peer)
        .await
        .unwrap();
    let (manager, issuer_dir) = crate::gateways::test_helpers::test_listener_manager(
        &directory
            .path()
            .join("fabric"),
    )
    .await;

    let manager = manager.with_gateway_store(gateways);
    let mut listener = crate::gateways::test_helpers::test_listener("fabric-send").await;
    listener.gateway_id = peer.id.clone();
    manager
        .register_test_listener(listener)
        .await;
    let policies = Arc::new(
        crate::policies::policy_definitions::FileSystemPolicyDefinitionStore::new(
            directory
                .path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap(),
    );
    policies
        .save(
            serde_json::from_value(json!({
                "id": "deny-all", "name": "Deny all", "policy_type": "agent_surface",
                "policy": "package surface.policy\ndefault allow = false", "created_at": "2026-11-02T00:00:00Z"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let surface: AgentSurface = serde_json::from_value(json!({
        "surface_id": "orders", "name": "Orders",
        "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
        "target": {"endpoint": format!("fabric://{}/orders", peer.id), "policy": {"policy_definition_id": "deny-all"}}
    }))
    .unwrap();
    let policy_manager = Arc::new(crate::policies::SurfacePolicyManager::new());
    policy_manager.set_policy_definition_store(policies);
    policy_manager
        .update_channel_policy(&surface)
        .await
        .unwrap();
    let mut router = super::variant_routing_tests::router(surface);
    router.policy_manager = Some(policy_manager);
    router.listener_manager = Arc::new(tokio::sync::RwLock::new(Some(Arc::new(manager))));
    (router, [directory, issuer_dir])
}

#[tokio::test]
async fn a_post_to_a_card_like_path_is_evaluated_by_the_surface_policy() {
    for path in ["/a2a/x/agent-card.json", "/a2a/x/agent.json", "/a2a/x/.well-known/agent-card"] {
        let (router, _policies) = denying_router().await;
        let (status, _) = super::variant_routing_tests::send(router, path).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{path}");
    }
}

#[test]
fn only_a_discovery_read_skips_the_sending_gateways_surface_policy() {
    for (method, path) in [("GET", "/a2a/.well-known/agent-card.json"), ("HEAD", "/a2a/x/agent.json")] {
        assert!(crate::proxy::paths::is_public_request(method, path), "{method} {path}");
    }
    for (method, path) in
        [("POST", "/a2a/.well-known/agent-card.json"), ("POST", "/a2a/x/agent.json"), ("PUT", "/a2a/x/agent-card.json")]
    {
        assert!(!crate::proxy::paths::is_public_request(method, path), "{method} {path}");
    }
}
