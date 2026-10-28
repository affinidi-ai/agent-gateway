//! How the Access Point serves and refuses a request by the surface variant it
//! selects.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::component_tests::helpers::MockServer;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};

pub(super) fn surface(
    endpoint: &str,
    variants: Value,
    default_variant_id: Option<&str>,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": "orders", "name": "Orders",
        "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
        "target": {"endpoint": endpoint},
        "variants": variants,
        "default_variant_id": default_variant_id
    }))
    .unwrap()
}

/// `prod` and `beta` serve traffic, `off` is disabled.
pub(super) fn catalog() -> Value {
    json!([
        {"id": "v-prod", "alias": "prod", "name": "Prod"},
        {"id": "v-beta", "alias": "beta", "name": "Beta"},
        {"id": "v-off", "alias": "off", "name": "Off", "enabled": false}
    ])
}

pub(super) fn router(surface: AgentSurface) -> crate::state::MultiSurfaceProxyState {
    let config = serde_json::from_value(json!({
        "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
        "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [], "categories": []},
        "extension_inspection": {"enabled": false}
    }))
    .unwrap();
    let network = serde_json::from_value(json!({
        "did": {"domain": "gateway.example"},
        "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
        "integration": {"types": [], "categories": []},
        "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
            "protocol": "http", "external_urls": ["https://gateway.example"]}],
        "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
    }))
    .unwrap();
    let variant_engines = surface
        .variants
        .iter()
        .map(|variant| {
            (
                variant.id.clone(),
                crate::state::proxy::VariantEngines {
                    identity_rules_engine: None,
                    identity_selector: None,
                    protected_rules_engine: None,
                    protected_selector: None,
                    external_rules_engine: None,
                    external_selector: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    crate::state::MultiSurfaceProxyState {
        config: Arc::new(config),
        network_config: Arc::new(network),
        client: reqwest::Client::new(),
        channels: Arc::new(tokio::sync::RwLock::new(vec![crate::state::SurfaceInfo {
            surface: Arc::new(surface),
            identity_rules_engine: None,
            identity_selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
            task_id: "variant-routing".into(),
            variant_engines,
        }])),
        metrics_store: None,
        task_monitor: None,
        ws_state: None,
        listener_manager: Arc::new(tokio::sync::RwLock::new(None)),
        secrets_store: None,
        certificates_store: None,
        vc_issuer: None,
        policy_manager: None,
        gateway_policy_manager: None,
        didauth_session_store: Arc::new(crate::didauth::DidAuthSessionStore::new()),
        transaction_store: None,
        mpp_transaction_store: None,
        trust_registry_listener_manager: None,
        source_auth_middleware: None,
        #[cfg(feature = "didwebvh")]
        didwebvh_identity_store: None,
        #[cfg(feature = "didwebvh")]
        didwebvh_log_manager: None,
        credential_provider_store: None,
        delegation_vault_store: None,
        gateway_base_url: Some("https://gateway.example".into()),
        transit_token_issuer: None,
        mcp_proxy_store: None,
        a2a_proxy_store: None,
        resolved_surface_cache: Arc::new(crate::surfaces::ResolvedSurfaceCache::new()),
    }
}

/// Sends one A2A message through the Access Point and returns the status with
/// every audit record the request wrote.
pub(super) async fn send(
    router: crate::state::MultiSurfaceProxyState,
    path: &str,
) -> (axum::http::StatusCode, Vec<DelegationAuditEvent>) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
                "role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hello"}]
            }}})
            .to_string(),
        ))
        .unwrap();
    let (response, events) =
        crate::audit::producer::capture(Box::pin(super::multi_channel_proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .unwrap(),
            router,
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        )))
        .await;
    (response.status(), events)
}

type Refusal = (RejectionStage, RejectionReason, u16, Option<String>);

pub(super) fn refusals(events: &[DelegationAuditEvent]) -> Vec<Refusal> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                stage,
                reason,
                http_status,
                requested_variant,
                ..
            } => Some((*stage, *reason, *http_status, requested_variant.clone())),
            _ => None,
        })
        .collect()
}

fn refused(
    reason: RejectionReason,
    status: u16,
    requested_variant: Option<&str>,
) -> Vec<Refusal> {
    vec![(RejectionStage::Routing, reason, status, requested_variant.map(str::to_string))]
}

#[tokio::test]
async fn a_variant_that_cannot_be_resolved_is_refused_with_one_status_per_reason() {
    let target = MockServer::start_with_response(
        json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string(),
    )
    .await;
    let endpoint = target.url();
    let cases = [
        (
            "unknown alias",
            surface(&endpoint, catalog(), Some("v-prod")),
            "/a2a$missing/rpc",
            refused(RejectionReason::UnknownVariant, 404, Some("missing")),
        ),
        (
            "alias on a surface with no variants",
            surface(&endpoint, json!([]), None),
            "/a2a$beta/rpc",
            refused(RejectionReason::UnknownVariant, 404, Some("beta")),
        ),
        (
            "disabled alias",
            surface(&endpoint, catalog(), Some("v-prod")),
            "/a2a$off/rpc",
            refused(RejectionReason::VariantDisabled, 404, None),
        ),
        (
            "disabled default with no alias",
            surface(&endpoint, catalog(), Some("v-off")),
            "/a2a/rpc",
            refused(RejectionReason::VariantDisabled, 404, None),
        ),
        (
            "misconfigured default with variants",
            surface(&endpoint, catalog(), Some("removed")),
            "/a2a/rpc",
            refused(RejectionReason::MisconfiguredDefault, 500, None),
        ),
        (
            "misconfigured default with no variants",
            surface(&endpoint, json!([]), Some("removed")),
            "/a2a/rpc",
            refused(RejectionReason::MisconfiguredDefault, 500, None),
        ),
    ];
    for (case, surface, path, expected) in cases {
        let (status, events) = send(router(surface), path).await;
        assert_eq!(status.as_u16(), expected[0].2, "{case}: status");
        assert_eq!(refusals(&events), expected, "{case}: recorded refusal");
    }
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        0,
        "no refused request reaches the Target"
    );
}

#[tokio::test]
async fn a_surface_with_variants_but_no_default_serves_an_alias_less_request_from_the_base() {
    let target = MockServer::start_with_response(
        json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string(),
    )
    .await;
    let (status, events) = send(router(surface(&target.url(), catalog(), None)), "/a2a/rpc").await;

    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(refusals(&events).is_empty(), "{events:?}");
    assert_eq!(
        target
            .request_count
            .load(Ordering::SeqCst),
        1
    );
}
