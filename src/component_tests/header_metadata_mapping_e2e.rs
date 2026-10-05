use serde_json::json;

use super::helpers::{self, GatewayHarness};

const HEADER_METADATA_URI: &str = "https://fabric.affinidi.io/extensions/header-metadata/v1";
const TENANT_POLICY_ID: &str = "header-metadata-tenant-policy";
const TENANT_POLICY_REGO: &str = r#"package surface.policy

default allow := false

allow if {
    input.http.headers["x-tenant-id"] == "tenant-456"
    input.a2a.message.metadata["https://fabric.affinidi.io/extensions/header-metadata/v1"].tenant_id == "tenant-456"
}
"#;
const TRUST_CHECK_TEMPLATE_POLICY_ID: &str = "header-metadata-trust-check-template-policy";
const FIXTURE_CREATED_AT: &str = "2026-01-01T00:00:00Z";
const TRUST_CHECK_TEMPLATE_POLICY_REGO: &str = r#"package surface.policy

default allow := true

allow := false if {
    input.trust_check_results.caller[_].error.code == "TEMPLATE_RESOLUTION_FAILED"
}
"#;

fn write_tenant_policy_definition(temp_dir: &std::path::Path) {
    let definition = json!({
        "id": TENANT_POLICY_ID,
        "name": "Header metadata tenant policy",
        "description": "Allows only the expected tenant from mapped A2A metadata.",
        "policy_type": "agent_surface",
        "policy": TENANT_POLICY_REGO,
        "enabled": true,
        "created_at": FIXTURE_CREATED_AT
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{TENANT_POLICY_ID}.json")),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write header metadata tenant policy definition fixture");
}

fn write_trust_check_template_policy_definition(temp_dir: &std::path::Path) {
    let definition = json!({
        "id": TRUST_CHECK_TEMPLATE_POLICY_ID,
        "name": "Header metadata Trust Check template policy",
        "description": "Denies when mapped-header Trust Check templates fail to resolve.",
        "policy_type": "agent_surface",
        "policy": TRUST_CHECK_TEMPLATE_POLICY_REGO,
        "enabled": true,
        "created_at": FIXTURE_CREATED_AT
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{TRUST_CHECK_TEMPLATE_POLICY_ID}.json")),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write header metadata trust-check policy definition fixture");
}

fn a2a_message() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{ "kind": "text", "text": "hello" }],
                "messageId": "msg-1"
            }
        },
        "id": "req-1"
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn header_metadata_mapping_adds_a2a_metadata_and_strips_mapped_headers() {
    let h = GatewayHarness::start(|temp_dir, gw_config, _| {
        write_tenant_policy_definition(temp_dir);
        let mut surface = helpers::build_minimal_channel();
        surface
            .access_point
            .header_metadata_mapping = Some(crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
            headers: vec![
                crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                    header: "x-agent-id".to_string(),
                    field: "agent_id".to_string(),
                },
                crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                    header: "x-tenant-id".to_string(),
                    field: "tenant_id".to_string(),
                },
            ],
            ..Default::default()
        });
        surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: TENANT_POLICY_ID.to_string(),
            require_agent_context: false,
        });
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("X-Agent-Id", "agent-123")
        .header("x-tenant-id", "tenant-456")
        .json(&a2a_message())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock target should receive forwarded request");
    let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body should be JSON");

    assert_eq!(body["params"]["message"]["metadata"][HEADER_METADATA_URI]["agent_id"], "agent-123");
    assert_eq!(body["params"]["message"]["metadata"][HEADER_METADATA_URI]["tenant_id"], "tenant-456");
    assert!(
        body["params"]["message"]["extensions"]
            .as_array()
            .expect("extensions should be present")
            .iter()
            .any(|value| value.as_str() == Some(HEADER_METADATA_URI))
    );
    assert!(
        !received
            .headers
            .keys()
            .any(|header| header.eq_ignore_ascii_case("x-agent-id")),
        "mapped x-agent-id header should be stripped before target forwarding"
    );
    assert!(
        !received
            .headers
            .keys()
            .any(|header| header.eq_ignore_ascii_case("x-tenant-id")),
        "mapped x-tenant-id header should be stripped before target forwarding"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn header_metadata_mapping_is_visible_to_surface_policy() {
    let h = GatewayHarness::start(|temp_dir, gw_config, _| {
        write_tenant_policy_definition(temp_dir);
        let mut surface = helpers::build_minimal_channel();
        surface
            .access_point
            .header_metadata_mapping = Some(crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
            headers: vec![crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-tenant-id".to_string(),
                field: "tenant_id".to_string(),
            }],
            ..Default::default()
        });
        surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: TENANT_POLICY_ID.to_string(),
            require_agent_context: false,
        });
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-tenant-id", "tenant-denied")
        .json(&a2a_message())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 403);
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "denied request must not reach target"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn header_metadata_mapping_is_available_to_trust_check_templates() {
    let h = GatewayHarness::start(|temp_dir, gw_config, _| {
        write_trust_check_template_policy_definition(temp_dir);
        let mut surface = helpers::build_minimal_channel();
        surface.access_point.header_metadata_mapping = Some(
            crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
                headers: vec![crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                    header: "x-tenant-id".to_string(),
                    field: "tenant_id".to_string(),
                }],
                ..Default::default()
            },
        );
        surface.access_point.trust_check_list = vec![crate::trust_registry_verification::trust_check_element::TrustCheckElement {
            id: "caller-template".to_string(),
            trust_registry_id: "tr-unreachable".to_string(),
            query_type: crate::trust_registry_verification::trust_check_element::TrqpQueryType::Recognition,
            query: crate::trust_registry_verification::trust_check_element::TrqpQueryParams {
                authority_id: "did:example:authority".to_string(),
                entity_id: "{{ input.a2a.message.metadata[\"https://fabric.affinidi.io/extensions/header-metadata/v1\"].tenant_id }}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        }];
        surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: TRUST_CHECK_TEMPLATE_POLICY_ID.to_string(),
            require_agent_context: false,
        });
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-tenant-id", "tenant-456")
        .json(&a2a_message())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    assert_eq!(
        h.mock
            .request_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Trust Check template resolution should not deny when mapped metadata is present"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn header_metadata_mapping_preserve_toggle_forwards_mapped_headers() {
    let h = GatewayHarness::start(|_, gw_config, _| {
        let mut surface = helpers::build_minimal_channel();
        surface
            .access_point
            .header_metadata_mapping = Some(crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
            headers: vec![crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-agent-session-id".to_string(),
                field: "session_id".to_string(),
            }],
            strip_mapped_headers: false,
            ..Default::default()
        });
        gw_config.surfaces = vec![surface];
    })
    .await;

    let resp = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("x-agent-session-id", "session-123")
        .json(&a2a_message())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("mock target should receive forwarded request");
    let body: serde_json::Value = serde_json::from_str(&received.body).expect("forwarded body should be JSON");

    assert_eq!(body["params"]["message"]["metadata"][HEADER_METADATA_URI]["session_id"], "session-123");
    assert_eq!(
        received
            .headers
            .get("x-agent-session-id")
            .map(String::as_str),
        Some("session-123")
    );
}
