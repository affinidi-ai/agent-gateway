//! A tenant surface whose custom metadata names an appliance-wide secret with `$SECRET:<id>`
//! sends it on the A2A request to the Target, on the A2A response to the caller and on the MCP
//! response to the caller while tenant credential isolation warns, and withholds it once the
//! gateway enforces it.

use serde_json::{Value, json};

use super::helpers::{self, GatewayHarness, MockServer};
use crate::config::agent_surface::AgentSurface;
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

const SECRET_VALUE: &str = "appliance-secret-value";

fn secret_metadata() -> Option<crate::config::CustomMetadata> {
    Some(crate::config::CustomMetadata {
        enabled: true,
        payload: Some(json!({"credential": "$SECRET:appliance-key"})),
        injection_target: Some(crate::config::MetadataInjectionTarget::Meta),
    })
}

fn write_appliance_secret(bootstrap: &crate::config::BootstrapConfig) {
    use crate::secrets::SecretsStore;

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            crate::secrets::FilesystemSecretsStore::new(
                &bootstrap
                    .storage_paths
                    .secrets,
            )
            .unwrap()
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "appliance-key".into(),
                secret_id: "appliance-key".into(),
                description: None,
                value: SECRET_VALUE.into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
        })
    });
}

/// A gateway under `mode` serving `surface` as a `tenant-a` surface, whose Target answers
/// `target_response`.
async fn tenant_gateway(
    mode: RuleMode,
    target_response: Value,
    mut surface: AgentSurface,
) -> GatewayHarness {
    let mock = MockServer::start_with_response(target_response.to_string()).await;
    GatewayHarness::start_with_mock(mock, |_, config, bootstrap| {
        bootstrap.credential_policy = CredentialPolicyConfig {
            tenant_credential_isolation: mode,
            ..Default::default()
        };
        write_appliance_secret(bootstrap);
        surface.tenant_id = Some("tenant-a".into());
        config.surfaces = vec![surface];
    })
    .await
}

async fn post(
    harness: &GatewayHarness,
    body: Value,
) -> (u16, Value) {
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&harness.gateway_url)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        response
            .json()
            .await
            .unwrap_or(Value::Null),
    )
}

fn a2a_metadata_credential(
    message: &Value,
    path: &str,
) -> Option<Value> {
    message
        .pointer(&format!(
            "{path}/metadata/{}/credential",
            crate::config::AFFINIDI_AGENT_METADATA_EXTENSION.replace('/', "~1")
        ))
        .cloned()
}

/// The credential the Target received on an A2A request and the one the caller received on its
/// response, from a `tenant-a` A2A surface under `mode`.
async fn a2a_credentials(mode: RuleMode) -> (Option<Value>, Option<Value>) {
    let mut surface = helpers::build_minimal_channel();
    surface.target.custom_metadata = secret_metadata();
    surface
        .target
        .response_custom_metadata = secret_metadata();
    let harness = tenant_gateway(
        mode,
        json!({"jsonrpc": "2.0", "id": 1, "result": {
            "kind": "message", "messageId": "reply", "role": "agent", "parts": [{"kind": "text", "text": "done"}]
        }}),
        surface,
    )
    .await;

    let (status, response) = post(
        &harness,
        json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
            "role": "user", "kind": "message", "messageId": "ask", "parts": [{"kind": "text", "text": "hello"}]
        }}}),
    )
    .await;
    assert_eq!(status, 200, "{response}");
    let received = harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the Target was called");
    let request: Value = serde_json::from_str(&received.body).unwrap();
    (a2a_metadata_credential(&request, "/params/message"), a2a_metadata_credential(&response, "/result"))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_a2a_surface_sends_an_appliance_wide_metadata_secret_both_ways_only_while_isolation_warns() {
    let sent = Some(json!(SECRET_VALUE));
    assert_eq!(a2a_credentials(RuleMode::Warn).await, (sent.clone(), sent));
    assert_eq!(a2a_credentials(RuleMode::Enforce).await, (None, None));
}

/// The status and body the caller received for `tools/list` from a `tenant-a` MCP surface under
/// `mode` whose response custom metadata names an appliance-wide secret, and whether the
/// Target was called.
async fn mcp_response(mode: RuleMode) -> (u16, Value, bool) {
    let mut surface = helpers::build_minimal_mcp_surface();
    surface
        .target
        .response_custom_metadata = secret_metadata();
    let harness = tenant_gateway(mode, json!({"jsonrpc": "2.0", "id": "list", "result": {"tools": []}}), surface).await;

    let (status, body) = post(&harness, json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list"})).await;
    let called = harness
        .mock
        .request_count
        .load(std::sync::atomic::Ordering::SeqCst)
        == 1;
    (status, body, called)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mcp_surface_answers_with_an_appliance_wide_metadata_secret_only_while_isolation_warns() {
    let (status, body, called) = mcp_response(RuleMode::Warn).await;
    assert_eq!((status, called), (200, true), "{body}");
    assert_eq!(body.pointer("/result/_meta/credential"), Some(&json!(SECRET_VALUE)), "{body}");

    let (status, body, called) = mcp_response(RuleMode::Enforce).await;
    assert_eq!((status, called), (502, true), "{body}");
    assert!(
        !body
            .to_string()
            .contains(SECRET_VALUE),
        "{body}"
    );
}
