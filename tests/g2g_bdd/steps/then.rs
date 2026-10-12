//! Then steps — single-assertion verifiers over the forwarded request and the
//! caller-visible response.

use std::collections::BTreeSet;

use base64::Engine as _;
use cucumber::then;
use serde_json::Value;

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::assertions::{
    assert_content_type_starts_with, assert_json_bodies_equal, assert_json_field_matches, assert_json_rpc_error_code,
    assert_json_rpc_id_matches_request_body, assert_json_rpc_result_matches_response, assert_mcp_method,
    assert_mcp_response_preserves_field, assert_mcp_tool_catalog_includes, assert_mcp_unsupported_version_error,
    json_rpc_id_key,
};
use crate::bdd_support::collaborators::{
    assert_header_absent, assert_header_value, assert_json_request_body, assert_no_requests,
    assert_request_content_type_starts_with, assert_request_count, assert_unique_json_rpc_request_ids,
};
use crate::world::G2gWorld;

const FABRIC_GATEWAY_DID_META_KEY: &str = "x-affinidi-fabric-gateway-did";
const AGENT_IDENTITY_BINDING_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";

#[then(expr = "MCP server {string} received MCP metadata key {string} only in {string}")]
async fn mcp_server_received_exact_metadata_location(
    world: &mut G2gWorld,
    server: String,
    key: String,
    location: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&server, TargetActorKind::McpServer);
    let request = last_request_for(world, &server).await;
    crate::bdd_support::mcp_metadata::assert_key_only_at(&request.json_body(), &key, &location);
}

#[then(expr = "MCP server {string} received MCP _meta key {string} with value {string}")]
async fn mcp_server_received_metadata_value(
    world: &mut G2gWorld,
    server: String,
    key: String,
    expected: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&server, TargetActorKind::McpServer);
    let request = last_request_for(world, &server).await;
    let body = request.json_body();
    let value = ["params._meta", "top-level"]
        .into_iter()
        .find_map(|location| {
            crate::bdd_support::mcp_metadata::metadata_at(&body, location).and_then(|metadata| metadata.get(&key))
        });
    assert_eq!(value.and_then(Value::as_str), Some(expected.as_str()), "MCP server '{server}' metadata key '{key}'");
}

#[then(
    regex = r#"^(managed agent|MCP server) "([^"]+)" received the forwarded (?:request|MCP request) with the original body$"#
)]
pub async fn actor_received_forwarded_body(
    world: &mut G2gWorld,
    actor_kind: String,
    target_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::from_gherkin_label(&actor_kind));
    let expected = world
        .sent_body
        .clone()
        .expect("a When must record the sent body before this Then");
    let last = last_request_for(world, &target_name).await;
    assert_eq!(last.json_body(), expected, "target collaborator received a different body than the caller sent");
}

#[then(
    regex = r#"^(managed agent|MCP server) "([^"]+)" received the forwarded (?:request|MCP request) with content type "([^"]+)"$"#
)]
pub async fn actor_received_content_type(
    world: &mut G2gWorld,
    actor_kind: String,
    target_name: String,
    expected_ct: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::from_gherkin_label(&actor_kind));
    let last = last_request_for(world, &target_name).await;
    assert_request_content_type_starts_with(
        &last,
        &expected_ct,
        &format!("forwarded request for target collaborator '{target_name}'"),
    );
}

#[then(expr = "MCP server {string} received the forwarded MCP request")]
pub async fn mcp_server_received_forwarded_request(
    world: &mut G2gWorld,
    target_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::McpServer);
    let request = last_request_for(world, &target_name).await;
    assert_json_request_body(&request, &format!("MCP server '{target_name}'"));
}

#[then(regex = r#"^MCP server "([^"]+)" received MCP method "([^"]+)"$"#)]
pub async fn mcp_server_received_method(
    world: &mut G2gWorld,
    target_name: String,
    expected_method: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::McpServer);
    let request = last_request_for(world, &target_name).await;
    assert_mcp_method(&request.json_body(), &expected_method, &format!("MCP server '{target_name}'"));
}

#[then(expr = "the MCP response id matches MCP server {string} forwarded request id")]
pub async fn mcp_response_id_matches_forwarded_request_id(
    world: &mut G2gWorld,
    target_name: String,
) {
    let request = last_request_for(world, &target_name).await;
    assert_json_rpc_id_matches_request_body(
        response_body(world),
        &request.json_body(),
        &format!("MCP server '{target_name}'"),
    );
}

#[then(expr = "MCP server {string} received the original MCP request body")]
pub async fn mcp_server_received_original_request_body(
    world: &mut G2gWorld,
    target_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::McpServer);
    let expected = world
        .sent_body
        .as_ref()
        .expect("a When must record the sent body before this Then");
    let request = last_request_for(world, &target_name).await;
    assert_eq!(
        &request.json_body(),
        expected,
        "MCP server '{target_name}' received a different body than the caller sent"
    );
}

#[then(regex = r#"^(managed agent|MCP server|REST API) "([^"]+)" was not called$"#)]
pub async fn actor_was_not_called(
    world: &mut G2gWorld,
    actor_kind: String,
    target_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::from_gherkin_label(&actor_kind));
    let (_, _, mock) = mock_for(world, &target_name);
    let requests = mock.requests().await;
    assert_no_requests(&requests, &format!("target collaborator '{target_name}'"));
}

#[then(regex = r#"^gateway (\d+) did not receive a fabric forward request$"#)]
pub async fn gateway_did_not_receive_fabric_forward_request(
    world: &mut G2gWorld,
    gateway_index: usize,
) {
    let baseline = world
        .fabric_forward_baseline
        .get(&gateway_index)
        .copied()
        .expect("a When step must record the fabric forward baseline before this Then");
    let actual = world
        .harness()
        .fabric_forward_request_count(gateway_index)
        .await;
    assert_eq!(
        actual, baseline,
        "gateway {gateway_index} received a fabric forward request after the caller action; caller_status={:?}; caller_body={:?}",
        world.response_status, world.response_body
    );
}

#[then(regex = r#"^MCP server "([^"]+)" received (\d+) forwarded MCP requests$"#)]
pub async fn mcp_server_received_forwarded_requests(
    world: &mut G2gWorld,
    target_name: String,
    expected_count: usize,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::McpServer);
    let (_, _, mock) = mock_for(world, &target_name);
    let requests = mock.requests().await;
    assert_request_count(&requests, expected_count, &format!("MCP server '{target_name}'"));

    assert_unique_json_rpc_request_ids(&requests, expected_count, &format!("MCP server '{target_name}'"));
}

#[then(regex = r#"^(managed agent|MCP server|REST API) "([^"]+)" received header "([^"]+)" with value "([^"]+)"$"#)]
pub async fn actor_received_header(
    world: &mut G2gWorld,
    actor_kind: String,
    target_name: String,
    header: String,
    expected_value: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::from_gherkin_label(&actor_kind));
    let last = last_request_for(world, &target_name).await;
    assert_header_value(
        &last.headers,
        &header,
        &expected_value,
        &format!("forwarded request for target collaborator '{target_name}'"),
    );
}

fn decode_json_or_jwt(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            if let Ok(json) = serde_json::from_str::<Value>(text) {
                return json;
            }
            let parts: Vec<&str> = text.split('.').collect();
            if parts.len() == 3 {
                let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(parts[1])
                    .expect("JWT payload should be base64url encoded");
                serde_json::from_slice::<Value>(&payload).expect("JWT payload should be JSON")
            } else {
                panic!("string credential should be JWT or JSON: {text}")
            }
        }
        value => value.clone(),
    }
}

fn first_credential_subject_from_identity_proof(proof: &Value) -> Value {
    let vp = proof
        .get("verifiablePresentation")
        .unwrap_or_else(|| panic!("identity proof should contain verifiablePresentation, got: {proof}"));
    let decoded_vp = decode_json_or_jwt(vp);
    let presentation = decoded_vp
        .get("vp")
        .unwrap_or(&decoded_vp);
    let credentials = presentation
        .get("verifiableCredential")
        .or_else(|| presentation.get("verifiableCredentials"))
        .unwrap_or_else(|| panic!("identity VP should contain verifiableCredential, got: {decoded_vp}"));
    let credential = credentials
        .as_array()
        .and_then(|array| array.first())
        .unwrap_or(credentials);
    let decoded_credential = decode_json_or_jwt(credential);
    decoded_credential
        .get("credentialSubject")
        .cloned()
        .unwrap_or_else(|| panic!("identity credential should contain credentialSubject, got: {decoded_credential}"))
}

/// The DID that issued the first credential of an identity proof: the JWT
/// `iss`, else the credential's `issuer` (a string or an object with `id`).
fn first_credential_issuer_from_identity_proof(proof: &Value) -> String {
    let vp = proof
        .get("verifiablePresentation")
        .unwrap_or_else(|| panic!("identity proof should contain verifiablePresentation, got: {proof}"));
    let decoded_vp = decode_json_or_jwt(vp);
    let presentation = decoded_vp
        .get("vp")
        .unwrap_or(&decoded_vp);
    let credentials = presentation
        .get("verifiableCredential")
        .or_else(|| presentation.get("verifiableCredentials"))
        .unwrap_or_else(|| panic!("identity VP should contain verifiableCredential, got: {decoded_vp}"));
    let credential = credentials
        .as_array()
        .and_then(|array| array.first())
        .unwrap_or(credentials);
    let decoded_credential = decode_json_or_jwt(credential);
    let issuer = decoded_credential
        .get("iss")
        .or_else(|| {
            decoded_credential
                .pointer("/vc/issuer")
                .or_else(|| decoded_credential.get("issuer"))
        })
        .map(|issuer| {
            issuer
                .get("id")
                .unwrap_or(issuer)
        })
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("identity credential should name its issuer, got: {decoded_credential}"));
    issuer.to_string()
}

fn identity_field_value_from_subject<'a>(
    subject: &'a Value,
    field: &str,
) -> Option<&'a Value> {
    subject
        .get("identityFields")
        .and_then(|fields| fields.get(field))
        .or_else(|| {
            subject
                .get("workloadBinding")
                .and_then(|binding| binding.get("agentIdentity"))
                .and_then(|agent_identity| agent_identity.get(field))
        })
}

#[then(
    expr = "managed agent {string} received the forwarded request with a VP containing outbound managed-agent identity field {string} with value {string}"
)]
pub async fn managed_agent_received_forwarded_request_with_identity_field(
    world: &mut G2gWorld,
    target_name: String,
    field: String,
    expected_value: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::ManagedAgent);
    let last = last_request_for(world, &target_name).await;
    let body = last.json_body();
    let proof = body
        .pointer(&format!("/params/message/metadata/{}", AGENT_IDENTITY_BINDING_URI.replace('/', "~1")))
        .or_else(|| {
            body.pointer(&format!("/params/message/metadata/{}", AGENT_IDENTITY_CREDENTIAL_URI.replace('/', "~1")))
        })
        .unwrap_or_else(|| {
            panic!(
                "managed agent '{target_name}' should receive identity proof metadata '{}' or '{}', got body: {body}",
                AGENT_IDENTITY_BINDING_URI, AGENT_IDENTITY_CREDENTIAL_URI
            )
        });
    let subject = first_credential_subject_from_identity_proof(proof);
    let actual = identity_field_value_from_subject(&subject, &field).and_then(Value::as_str);
    assert_eq!(
        actual,
        Some(expected_value.as_str()),
        "managed agent '{target_name}' identity proof should contain field '{field}' with value '{expected_value}', got credentialSubject: {subject}"
    );
}

#[then(
    expr = "managed agent {string} received the forwarded request carrying an identity presentation issued by gateway {int}"
)]
pub async fn managed_agent_received_forwarded_request_with_identity_presentation_issued_by_gateway(
    world: &mut G2gWorld,
    target_name: String,
    issuer_gw: usize,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::ManagedAgent);
    let expected_issuer = world
        .harness()
        .self_gateway_did(issuer_gw)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let messages = forwarded_messages_for(world, &target_name).await;
    assert_eq!(
        messages.len(),
        1,
        "managed agent '{target_name}' should receive exactly one forwarded message (discovery card fetches excluded), got {}; caller_status={:?}; caller_body={:?}",
        messages.len(),
        world.response_status,
        world.response_body
    );
    let body = messages[0].json_body();
    let sent = world
        .sent_body
        .as_ref()
        .expect("a When must record the sent body before this Then");
    assert_eq!(
        body.pointer("/params/message/parts"),
        sent.pointer("/params/message/parts"),
        "managed agent '{target_name}' should receive the caller's message parts unchanged"
    );
    let proof = crate::bdd_support::json_rpc::IdentityBindingProof::from_forwarded_a2a_body(&body).unwrap_or_else(|| {
        panic!(
            "managed agent '{target_name}' should receive identity proof metadata '{AGENT_IDENTITY_BINDING_URI}' or '{AGENT_IDENTITY_CREDENTIAL_URI}', got body: {body}"
        )
    });
    let actual_issuer = first_credential_issuer_from_identity_proof(&proof.proof);
    assert_eq!(
        actual_issuer, expected_issuer,
        "managed agent '{target_name}' received an identity presentation issued by {actual_issuer}, expected gateway {issuer_gw}'s DID {expected_issuer}"
    );
}

#[then(regex = r#"^(managed agent|MCP server|REST API) "([^"]+)" did not receive header "([^"]+)"$"#)]
pub async fn actor_did_not_receive_header(
    world: &mut G2gWorld,
    actor_kind: String,
    target_name: String,
    header: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::from_gherkin_label(&actor_kind));
    let last = last_request_for(world, &target_name).await;
    assert_header_absent(&last.headers, &header, &format!("forwarded request for target collaborator '{target_name}'"));
}

async fn last_request_for(
    world: &G2gWorld,
    target_name: &str,
) -> crate::bdd_support::mock_server::ReceivedRequest {
    let (_, _, mock) = mock_for(world, target_name);
    let requests = mock.requests().await;
    if requests.len() != 1 {
        panic!(
            "target collaborator '{target_name}' should receive exactly one request, got {}; caller_status={:?}; caller_body={:?}",
            requests.len(),
            world.response_status,
            world.response_body
        );
    }
    requests
        .into_iter()
        .next()
        .expect("target collaborator must have received a request")
}

fn mock_for<'a>(
    world: &'a G2gWorld,
    target_name: &str,
) -> (usize, String, &'a crate::bdd_support::mock_server::MockServer) {
    let (gw_index, surface_id) = world.target(target_name);
    let gw = world.harness().gw(gw_index);
    let mock = gw
        .mock(&surface_id)
        .unwrap_or_else(|| panic!("no target collaborator backing surface '{surface_id}' on gateway {gw_index}"));
    (gw_index, surface_id, mock)
}

fn is_discovery_request(request: &crate::bdd_support::mock_server::ReceivedRequest) -> bool {
    request
        .path_and_query
        .contains(".well-known/agent")
}

async fn forwarded_messages_for(
    world: &G2gWorld,
    target_name: &str,
) -> Vec<crate::bdd_support::mock_server::ReceivedRequest> {
    let (_, _, mock) = mock_for(world, target_name);
    mock.requests()
        .await
        .into_iter()
        .filter(|request| !is_discovery_request(request))
        .collect()
}

#[then(regex = r#"^managed agent "([^"]+)" did not receive a forwarded message$"#)]
pub async fn actor_did_not_receive_forwarded_message(
    world: &mut G2gWorld,
    target_name: String,
) {
    let messages = forwarded_messages_for(world, &target_name).await;
    assert!(
        messages.is_empty(),
        "target collaborator '{target_name}' should not receive any forwarded message (discovery card fetches excluded), got {}: {messages:?}; caller_status={:?}; caller_body={:?}",
        messages.len(),
        world.response_status,
        world.response_body
    );
}

#[then(regex = r"^the ping from gateway (\d+) to gateway (\d+) succeeds$")]
pub async fn ping_succeeds(
    world: &mut G2gWorld,
    from_gw: usize,
    to_gw: usize,
) {
    let success = world
        .ping_results
        .get(&(from_gw, to_gw))
        .copied()
        .unwrap_or_else(|| panic!("no ping recorded from gateway {from_gw} to gateway {to_gw}"));
    assert!(success, "ping from gateway {from_gw} to gateway {to_gw} did not succeed");
}

/// How long a Remote record may take to gain an issuer DID after a restart:
/// the exchange runs in the background once the pairing listener registers.
const ISSUER_RECONCILIATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[then(regex = r"^gateway (\d+) has recorded gateway (\d+)'s gateway DID as the issuer DID of gateway (\d+)$")]
pub async fn gateway_recorded_peer_gateway_did_as_issuer_did(
    world: &mut G2gWorld,
    gw_index: usize,
    peer_gw: usize,
    record_of_gw: usize,
) {
    assert_eq!(peer_gw, record_of_gw, "the recorded issuer DID is compared with the same peer gateway's own DID");
    let expected = world
        .harness()
        .self_gateway_did(peer_gw)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let record = match world
        .remote_gateway_records
        .get(&gw_index)
    {
        // The operator's own read is the observation under test.
        Some(records) => {
            let remote_id = world
                .harness()
                .remote_id(gw_index, peer_gw)
                .unwrap_or_else(|| panic!("gateway {gw_index} holds no Remote record for gateway {peer_gw}"));
            records
                .iter()
                .find(|record| record.id == remote_id)
                .cloned()
                .unwrap_or_else(|| {
                    panic!("gateway {gw_index}'s Remote gateway records do not include gateway {peer_gw}: {records:?}")
                })
        }
        None => {
            world
                .wait_for_recorded_issuer_did(gw_index, peer_gw, ISSUER_RECONCILIATION_TIMEOUT)
                .await
        }
    };
    assert_eq!(
        record.issuer_did.as_deref(),
        Some(expected.as_str()),
        "gateway {gw_index} should record gateway {peer_gw}'s gateway DID {expected} as its issuer DID; observed record: {record:?}"
    );
}

#[then(regex = r"^the issuer DID reported by gateway (\d+) equals gateway (\d+)'s gateway DID$")]
pub async fn reported_issuer_did_equals_peer_gateway_did(
    world: &mut G2gWorld,
    reporting_gw: usize,
    peer_gw: usize,
) {
    assert_eq!(reporting_gw, peer_gw, "the reported issuer DID is compared with the reporting gateway's own DID");
    let (requested_gw, reported) = world
        .issuer_request_result
        .clone()
        .expect("a When must request an issuer DID before this Then");
    assert_eq!(
        requested_gw, reporting_gw,
        "the issuer DID was requested from gateway {requested_gw}, not {reporting_gw}"
    );
    let expected = world
        .harness()
        .self_gateway_did(peer_gw)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(
        reported, expected,
        "gateway {reporting_gw} reported issuer DID {reported}, expected its gateway DID {expected}"
    );
}

#[then(expr = "the MCP response tool catalog includes a tool named {string}")]
pub async fn mcp_response_lists_tool(
    world: &mut G2gWorld,
    expected_name: String,
) {
    let body = world
        .response_body
        .as_ref()
        .expect("a When must record the response body before this Then");
    let sent_body = world
        .sent_body
        .as_ref()
        .expect("a When must record the sent body before this Then");
    assert_json_rpc_id_matches_request_body(body, sent_body, "MCP tool catalog response");
    assert_mcp_tool_catalog_includes(body, &expected_name);
}

#[then(expr = "the MCP surface returns MCP server {string} tool catalog unchanged")]
pub async fn mcp_surface_returns_tool_catalog_unchanged(
    world: &mut G2gWorld,
    target_name: String,
) {
    let request = last_request_for(world, &target_name).await;
    let expected = expected_response_for_request(world, &target_name, &request);
    let tools = expected
        .pointer("/result/tools")
        .and_then(|tools| tools.as_array())
        .unwrap_or_else(|| panic!("MCP server '{target_name}' configured response should include result.tools"));
    assert!(
        tools.len() >= 2,
        "MCP server '{target_name}' tool catalog should include at least two tools, got {}",
        expected
    );
    assert_json_bodies_equal(
        response_body(world)
            .get("jsonrpc")
            .unwrap_or(&Value::Null),
        expected
            .get("jsonrpc")
            .unwrap_or(&Value::Null),
        &format!("MCP server '{target_name}' tool catalog JSON-RPC version"),
    );
    assert_json_bodies_equal(
        response_body(world)
            .get("id")
            .unwrap_or(&Value::Null),
        expected
            .get("id")
            .unwrap_or(&Value::Null),
        &format!("MCP server '{target_name}' tool catalog response id"),
    );
    assert_json_bodies_equal(
        response_body(world)
            .pointer("/result/tools")
            .unwrap_or(&Value::Null),
        expected
            .pointer("/result/tools")
            .unwrap_or(&Value::Null),
        &format!("MCP server '{target_name}' tool catalog tools"),
    );
}

#[then(expr = "MCP server {string} received forwarded MCP field {string} unchanged")]
pub async fn mcp_server_received_forwarded_field_unchanged(
    world: &mut G2gWorld,
    target_name: String,
    field: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&target_name, TargetActorKind::McpServer);
    let sent = world
        .sent_body
        .as_ref()
        .expect("a When must record the sent body before this Then");
    let request = last_request_for(world, &target_name).await;
    assert_json_field_matches(
        &request.json_body(),
        sent,
        &field,
        &format!("MCP server '{target_name}' forwarded MCP request"),
    );
}

#[then(expr = "the MCP conformance suite passes")]
pub async fn mcp_conformance_suite_passes(world: &mut G2gWorld) {
    let run = world
        .conformance_run
        .as_ref()
        .expect("a When must run the MCP conformance suite before this Then");
    if !run.passed {
        let lines = run
            .output
            .lines()
            .collect::<Vec<_>>();
        let tail = lines[lines.len().saturating_sub(60)..].join("\n");
        panic!("the MCP conformance suite failed:\n{tail}");
    }
}

#[then(expr = "the response status is {int}")]
pub async fn response_status_is(
    world: &mut G2gWorld,
    expected: u16,
) {
    let actual = world
        .response_status
        .expect("a When must record the response status before this Then");
    assert_eq!(
        actual, expected,
        "unexpected response status; body={:?}; content_type={:?}",
        world.response_body, world.response_content_type
    );
}

#[then(regex = r"^all (\d+) responses have status (\d+)$")]
pub async fn all_concurrent_responses_have_status(
    world: &mut G2gWorld,
    expected_count: usize,
    expected_status: u16,
) {
    assert_eq!(
        world
            .concurrent_responses
            .len(),
        expected_count,
        "expected {expected_count} concurrent responses, got {}",
        world
            .concurrent_responses
            .len()
    );
    let mismatches: Vec<String> = world
        .concurrent_responses
        .iter()
        .filter(|response| response.status != expected_status)
        .map(|response| {
            format!(
                "request id {} returned status {} with content type {:?} and body {}",
                json_rpc_id_key(&response.request_id),
                response.status,
                response.content_type,
                response.body
            )
        })
        .collect();
    assert!(mismatches.is_empty(), "unexpected concurrent response status values: {}", mismatches.join("; "));
}

#[then(regex = r"^each MCP response matches the request that produced it$")]
pub async fn each_mcp_response_matches_request(world: &mut G2gWorld) {
    let expected_ids: BTreeSet<String> = world
        .concurrent_requests
        .iter()
        .map(|request| {
            json_rpc_id_key(
                request
                    .get("id")
                    .unwrap_or(&Value::Null),
            )
        })
        .collect();
    assert_eq!(
        expected_ids.len(),
        world
            .concurrent_requests
            .len(),
        "concurrent requests should have unique JSON-RPC ids"
    );

    let actual_ids: BTreeSet<String> = world
        .concurrent_responses
        .iter()
        .map(|response| {
            let actual_id = response
                .body
                .get("id")
                .unwrap_or(&Value::Null);
            assert_json_rpc_id_matches_request_body(
                &response.body,
                &serde_json::json!({ "id": response.request_id.clone() }),
                "concurrent MCP",
            );
            assert_eq!(
                response
                    .body
                    .get("result")
                    .and_then(|result| result.get("marker"))
                    .and_then(|marker| marker.as_str()),
                Some("g2g-echo"),
                "response for request id {} did not include the echo marker: {}",
                json_rpc_id_key(&response.request_id),
                response.body
            );
            json_rpc_id_key(actual_id)
        })
        .collect();

    assert_eq!(actual_ids, expected_ids, "response ids should exactly match request ids");
}

#[then(expr = "the response content type is {string}")]
pub async fn response_content_type_is(
    world: &mut G2gWorld,
    expected: String,
) {
    assert_content_type_starts_with(
        world
            .response_content_type
            .as_deref(),
        &expected,
    );
}

#[then(expr = "the MCP response preserves MCP server {string} field {string}")]
pub async fn mcp_response_preserves_target_field(
    world: &mut G2gWorld,
    target_name: String,
    field: String,
) {
    let request = last_request_for(world, &target_name).await;
    let expected = expected_response_for_request(world, &target_name, &request);
    assert_mcp_response_preserves_field(
        response_body(world),
        &expected,
        &field,
        &format!("MCP server '{target_name}'"),
    );
}

#[then(expr = "the MCP response id matches the request id")]
pub async fn mcp_response_id_matches_request(world: &mut G2gWorld) {
    let sent = world
        .sent_body
        .as_ref()
        .expect("a When must record the sent body before this Then");
    assert_json_rpc_id_matches_request_body(response_body(world), sent, "caller MCP request");
}

#[then(expr = "the MCP response is a JSON-RPC error with code {int}")]
pub async fn mcp_response_is_json_rpc_error(
    world: &mut G2gWorld,
    expected_code: i64,
) {
    assert_json_rpc_error_code(response_body(world), expected_code);
}

#[then(expr = "the MCP unsupported-version error requests {string} and supports only {string}")]
pub async fn mcp_unsupported_version_error_has_exact_versions(
    world: &mut G2gWorld,
    requested: String,
    supported: String,
) {
    assert_mcp_unsupported_version_error(response_body(world), &requested, &supported);
}

#[then(expr = "the response arrives in under {int} seconds")]
pub async fn response_arrives_within(
    world: &mut G2gWorld,
    seconds: u64,
) {
    let elapsed = world
        .response_elapsed
        .expect("the caller sent no request through a surface");
    assert!(elapsed < std::time::Duration::from_secs(seconds), "the response took {elapsed:?}");
}

#[then(expr = "the A2A response result matches managed agent {string} response result")]
#[then(expr = "the MCP response result matches MCP server {string} response result")]
pub async fn response_result_matches_target(
    world: &mut G2gWorld,
    target_name: String,
) {
    let forwarded_request = last_request_for(world, &target_name).await;
    let actual = world
        .response_body
        .as_ref()
        .expect("a When must record the response body before this Then");
    let expected = expected_response_for_target(world, &target_name);

    assert_json_rpc_id_matches_request_body(
        actual,
        &forwarded_request.json_body(),
        &format!("response for target '{target_name}'"),
    );
    assert_json_rpc_result_matches_response(actual, expected, &target_name);
}

#[then(expr = "each Legacy SSE reply answers its own request with MCP server {string} response result")]
pub async fn each_legacy_sse_reply_answers_its_request(
    world: &mut G2gWorld,
    target_name: String,
) {
    assert!(
        !world
            .legacy_sse_exchange
            .is_empty(),
        "a When must send requests over a Legacy SSE session before this Then"
    );
    let expected = expected_response_for_target(world, &target_name);
    for (request, reply) in &world.legacy_sse_exchange {
        assert_json_rpc_id_matches_request_body(reply, request, "Legacy SSE reply");
        assert_json_rpc_result_matches_response(reply, expected, &target_name);
    }
}

#[then(regex = r#"^the MCP response includes fabric gateway DID metadata for MCP server "([^"]+)"$"#)]
pub async fn response_includes_fabric_gateway_did_metadata_for_target(
    world: &mut G2gWorld,
    target_name: String,
) {
    let body = world
        .response_body
        .as_ref()
        .expect("a When must record the response body before this Then");
    let metadata = body
        .get("result")
        .and_then(|r| r.get("_meta"))
        .and_then(|value| value.as_object())
        .expect("response body must include an object result._meta field");
    let gateway_did_value = metadata
        .get(FABRIC_GATEWAY_DID_META_KEY)
        .expect("response result._meta must include fabric gateway DID metadata");
    // The DID may be a single string (GW2 only) or an array (GW1 appended)
    let gateway_did = gateway_did_value
        .as_str()
        .or_else(|| {
            gateway_did_value
                .as_array()
                .and_then(|arr| arr.last())
                .and_then(|v| v.as_str())
        })
        .expect("fabric gateway DID metadata must be a string or array of strings");
    let (gw_index, _) = world.target(&target_name);
    let expected_gateway_did = world
        .harness()
        .gw(gw_index)
        .admin
        .find_self_gateway()
        .await
        .unwrap_or_else(|error| panic!("failed to find self gateway for gateway {gw_index}: {error}"))
        .did
        .unwrap_or_else(|| panic!("self gateway for gateway {gw_index} must have a DID"));

    assert_eq!(
        gateway_did, expected_gateway_did,
        "fabric gateway DID metadata should identify the responding gateway for target '{target_name}'"
    );
}

fn expected_response_for_target<'a>(
    world: &'a G2gWorld,
    target_name: &str,
) -> &'a serde_json::Value {
    let (gw_index, surface_id) = world.target(target_name);
    world
        .topology
        .plans
        .get(&gw_index)
        .unwrap_or_else(|| panic!("no gateway plan for gateway {gw_index}"))
        .mock_responses
        .get(&surface_id)
        .unwrap_or_else(|| {
            panic!("no mock response for target actor '{target_name}' on gateway {gw_index} surface '{surface_id}'")
        })
}

fn response_body(world: &G2gWorld) -> &Value {
    world
        .response_body
        .as_ref()
        .expect("a When must record the response body before this Then")
}

fn expected_response_for_request(
    world: &G2gWorld,
    target_name: &str,
    request: &crate::bdd_support::mock_server::ReceivedRequest,
) -> Value {
    let mut expected = expected_response_for_target(world, target_name).clone();
    let body = request.json_body();
    if let (Some(request_id), Some(expected_object)) = (body.get("id"), expected.as_object_mut())
        && expected_object.contains_key("id")
    {
        expected_object.insert("id".to_string(), request_id.clone());
    }
    expected
}
