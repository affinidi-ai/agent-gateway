use std::collections::HashMap;

use base64::Engine as _;
use cucumber::then;

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::assertions::{
    assert_content_type_contains, assert_json_bodies_equal, assert_json_body_mentions, assert_json_field_absent,
    assert_json_field_matches, assert_json_rpc_error_code, assert_json_rpc_id_matches_request_body,
    assert_json_string_field_equals, assert_mcp_method, assert_mcp_response_preserves_field,
    assert_mcp_response_result_matches_body, assert_mcp_tool_catalog_excludes, assert_mcp_tool_catalog_includes,
    assert_mcp_unsupported_version_error, assert_response_status, assert_status_with_body,
};
use crate::bdd_support::collaborators::{
    assert_called_exactly_once, assert_header_absent as assert_collaborator_header_absent,
    assert_header_value as assert_collaborator_header_value, assert_json_request_body,
    assert_request_content_type_starts_with,
};

use crate::world::{ObservedTarget, SurfaceWorld, identity_schema_has_field};

const HEADER_METADATA_URI: &str = "https://fabric.affinidi.io/extensions/header-metadata/v1";

fn get_sent_body(world: &SurfaceWorld) -> &serde_json::Value {
    world
        .sent_body
        .as_ref()
        .expect("sent_body must be set")
}

fn get_observed_target_requests<'a>(
    target: &'a ObservedTarget,
    context: &str,
) -> &'a [crate::bdd_support::mock_server::ReceivedRequest] {
    target
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("{context}.observations must be set"))
        .requests
        .as_slice()
}

fn get_observed_target_request<'a>(
    target: &'a ObservedTarget,
    context: &str,
) -> &'a crate::bdd_support::mock_server::ReceivedRequest {
    assert_called_exactly_once(get_observed_target_requests(target, context), context)
}

fn get_observed_target_for_actor<'a>(
    world: &'a SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
) -> &'a ObservedTarget {
    world
        .actors
        .expect_target_kind(actor_name, expected_kind);
    let collaborator_key = world
        .actors
        .target_collaborator_key(actor_name);
    world.collaborator_target(collaborator_key)
}

fn get_observed_request_for_actor<'a>(
    world: &'a SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
) -> &'a crate::bdd_support::mock_server::ReceivedRequest {
    get_observed_target_request(
        get_observed_target_for_actor(world, actor_name, expected_kind),
        &format!("target actor '{}'", actor_name),
    )
}

fn assert_target_not_called(
    target: &ObservedTarget,
    context: &str,
) {
    let requests = get_observed_target_requests(target, context);
    assert!(
        requests.is_empty(),
        "{context} should not have been called, but received {} request(s): {requests:?}",
        requests.len()
    );
}

fn assert_target_only_discovery(
    target: &ObservedTarget,
    context: &str,
) {
    let requests = get_observed_target_requests(target, context);
    let business_requests: Vec<&crate::bdd_support::mock_server::ReceivedRequest> = requests
        .iter()
        .filter(|request| !is_agent_card_discovery(request))
        .collect();
    assert!(
        business_requests.is_empty(),
        "{context} should have received only the target Trust Check agent-card fetch, but also received {} business request(s): {business_requests:?}",
        business_requests.len()
    );
    assert!(
        requests
            .iter()
            .any(is_agent_card_discovery),
        "{context} should have received the target Trust Check agent-card fetch, but received no discovery request: {requests:?}"
    );
}

fn is_agent_card_discovery(request: &crate::bdd_support::mock_server::ReceivedRequest) -> bool {
    request
        .method
        .eq_ignore_ascii_case("GET")
        && (request
            .path_and_query
            .contains(".well-known/agent-card.json")
            || request
                .path_and_query
                .contains(".well-known/agent.json"))
}

fn direct_line_activity_post<'a>(
    requests: &'a [crate::bdd_support::mock_server::ReceivedRequest],
    actor_name: &str,
) -> &'a crate::bdd_support::mock_server::ReceivedRequest {
    requests
        .iter()
        .find(|request| request.method == "POST" && request.path_and_query.ends_with("/activities"))
        .unwrap_or_else(|| panic!("non-A2A managed agent '{actor_name}' did not receive a Direct Line activity post; observed requests: {requests:?}"))
}

fn assert_actor_not_called(
    world: &SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
) {
    let target = get_observed_target_for_actor(world, actor_name, expected_kind);
    assert_target_not_called(target, actor_name);
}

fn assert_target_called_exactly_once(
    target: &ObservedTarget,
    context: &str,
) {
    assert_called_exactly_once(get_observed_target_requests(target, context), context);
}

fn get_caller_response(world: &SurfaceWorld) -> &crate::world::RecordedResponse {
    world
        .caller_response
        .as_ref()
        .expect("caller_response must be set")
}

fn get_admin_response(world: &SurfaceWorld) -> &crate::world::RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("admin_response must be set")
}

fn get_surface_lookup_response(world: &SurfaceWorld) -> &crate::world::RecordedResponse {
    world
        .surface_lookup_response
        .as_ref()
        .expect("surface_lookup_response must be set")
}

fn get_tracked_surface_id<'a>(
    world: &'a SurfaceWorld,
    action: &str,
) -> &'a str {
    world
        .surface_under_test_id
        .as_deref()
        .or(world
            .created_surface_id
            .as_deref())
        .unwrap_or_else(|| panic!("surface id must be set before {}", action))
}

fn get_response_surface_id<'a>(
    body: &'a serde_json::Value,
    context: &str,
) -> &'a str {
    body.get("surface_id")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("expected {} to include surface_id, got {}", context, body))
}

fn get_response_status_value(world: &SurfaceWorld) -> u16 {
    get_caller_response(world).status
}

fn get_response_headers_value(world: &SurfaceWorld) -> &HashMap<String, String> {
    &get_caller_response(world).headers
}

fn get_response_body_value(world: &SurfaceWorld) -> &serde_json::Value {
    &get_caller_response(world).body
}

#[then(expr = "MCP server {string} was not called")]
fn named_mcp_server_was_not_called(
    world: &mut SurfaceWorld,
    actor_name: String,
) {
    assert_actor_not_called(world, &actor_name, TargetActorKind::McpServer);
}

#[then(expr = "non-A2A managed agent {string} was not called")]
fn named_non_a2a_managed_agent_was_not_called(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    assert_actor_not_called(world, &agent_name, TargetActorKind::ManagedAgent);
}

#[then(expr = "non-A2A managed agent {string} received text {string}")]
fn named_non_a2a_managed_agent_received_text(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected_text: String,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let requests = get_observed_target_requests(target, &agent_name);
    let activity_post = direct_line_activity_post(requests, &agent_name);
    let body = activity_post.json_body();
    assert_eq!(
        body.get("text")
            .and_then(serde_json::Value::as_str),
        Some(expected_text.as_str()),
        "non-A2A managed agent '{agent_name}' should receive text {expected_text:?}; activity body was {body}"
    );
}

#[then(expr = "non-A2A managed agent {string} did not receive header {string}")]
fn named_non_a2a_managed_agent_did_not_receive_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    header_name: String,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let requests = get_observed_target_requests(target, &agent_name);
    let header_name = header_name.to_ascii_lowercase();
    for request in requests {
        assert!(
            !request
                .headers
                .contains_key(&header_name),
            "non-A2A managed agent '{agent_name}' should not receive header '{header_name}'; observed request was {request:?}"
        );
    }
}

#[then(expr = "the agent card describes A2A proxy {string}")]
fn agent_card_describes_a2a_proxy(
    world: &mut SurfaceWorld,
    proxy_name: String,
) {
    let response = get_caller_response(world);
    assert_eq!(
        response
            .body
            .get("name")
            .and_then(serde_json::Value::as_str),
        Some(proxy_name.as_str()),
        "agent card name should describe A2A proxy '{proxy_name}', got {}",
        response.body
    );
    assert!(
        response
            .body
            .get("description")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|description| description.contains(&proxy_name)),
        "agent card description should mention A2A proxy '{proxy_name}', got {}",
        response.body
    );
}

#[then(expr = "the agent card url points to the surface Access Point")]
fn agent_card_url_points_to_surface_access_point(world: &mut SurfaceWorld) {
    let response = get_caller_response(world);
    let url = response
        .body
        .pointer("/supportedInterfaces/0/url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("agent card supportedInterfaces[0].url must be present, got {}", response.body));
    assert!(
        url.contains(&world.surface_config.route),
        "agent card url should include surface route '{}', got {url}",
        world.surface_config.route
    );
    assert!(url.ends_with("/rpc"), "agent card url should point to the A2A RPC endpoint, got {url}");
}

#[then(expr = "the A2A response result contains text from non-A2A managed agent {string}")]
fn a2a_response_result_contains_text_from_non_a2a_managed_agent(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let response = get_caller_response(world);
    // The A2A 1.0 `SendMessageResponse`: the reply is `result.message`, and a
    // text part carries `text` with no 0.3 `kind`.
    let parts = response
        .body
        .pointer("/result/message/parts")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("A2A response result.message.parts must be an array, got {}", response.body));
    assert!(
        parts.iter().any(|part| {
            part.get("kind").is_none()
                && part
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|text| text.contains(&agent_name))
        }),
        "A2A response should contain text from non-A2A managed agent '{agent_name}', got {}",
        response.body
    );
}

#[then(expr = "the A2A response id matches the request id")]
fn a2a_response_id_matches_request_id(world: &mut SurfaceWorld) {
    assert_json_rpc_id_matches_request_body(&get_caller_response(world).body, get_sent_body(world), "A2A proxy");
}

#[then(expr = "the A2A response is a JSON-RPC invalid params error")]
fn a2a_response_is_json_rpc_invalid_params_error(world: &mut SurfaceWorld) {
    assert_json_rpc_error_code(&get_caller_response(world).body, -32602);
}

#[then(expr = "the A2A response is a JSON-RPC method not found error")]
fn a2a_response_is_json_rpc_method_not_found_error(world: &mut SurfaceWorld) {
    assert_json_rpc_error_code(&get_caller_response(world).body, -32601);
}

#[then(expr = "the A2A response is a JSON-RPC Target timeout error")]
fn a2a_response_is_json_rpc_target_timeout_error(world: &mut SurfaceWorld) {
    let response = get_caller_response(world);
    assert_json_rpc_error_code(&response.body, -32021);
    assert_json_body_mentions(&response.body, "timed out", "A2A proxy timeout error");
}

#[then(expr = "the A2A response is a JSON-RPC error for a disabled A2A proxy")]
fn a2a_response_is_json_rpc_disabled_proxy_error(world: &mut SurfaceWorld) {
    let response = get_caller_response(world);
    assert_json_rpc_error_code(&response.body, -32020);
    assert_json_body_mentions(&response.body, "A2A proxy is disabled", "A2A proxy disabled error");
}

#[then(expr = "managed agent {string} was not called")]
fn named_managed_agent_was_not_called(
    world: &mut SurfaceWorld,
    actor_name: String,
) {
    assert_actor_not_called(world, &actor_name, TargetActorKind::ManagedAgent);
}

#[then(expr = "external agent {string} was not called")]
fn named_external_agent_was_not_called(
    world: &mut SurfaceWorld,
    actor_name: String,
) {
    assert_actor_not_called(world, &actor_name, TargetActorKind::ExternalAgent);
}

#[then(expr = "external agent {string} received only the target Trust Check agent-card fetch")]
fn named_external_agent_received_only_discovery(
    world: &mut SurfaceWorld,
    actor_name: String,
) {
    let target = get_observed_target_for_actor(world, &actor_name, TargetActorKind::ExternalAgent);
    assert_target_only_discovery(target, &actor_name);
}

#[then(expr = "REST API {string} was not called")]
fn named_rest_api_was_not_called(
    world: &mut SurfaceWorld,
    actor_name: String,
) {
    assert_actor_not_called(world, &actor_name, TargetActorKind::RestApi);
}

#[then(expr = "REST API {string} received {string}")]
fn named_rest_api_received(
    world: &mut SurfaceWorld,
    actor_name: String,
    method_and_path: String,
) {
    let request = get_observed_request_for_actor(world, &actor_name, TargetActorKind::RestApi);
    let actual = format!("{} {}", request.method, request.path_and_query);
    assert_eq!(
        actual, method_and_path,
        "expected REST API '{}' to receive '{}', got '{}'",
        actor_name, method_and_path, actual
    );
}

#[then(expr = "managed agent {string} received a forwarded request")]
fn named_managed_agent_received_a_forwarded_request(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    assert_target_called_exactly_once(target, &agent_name);
}

fn assert_actor_received_a2a_metadata_field(
    world: &SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
    field: &str,
    expected_value: &str,
) {
    let request = get_observed_request_for_actor(world, actor_name, expected_kind);
    let body = request.json_body();
    let actual = body
        .pointer(&format!("/params/message/metadata/{}/{}", HEADER_METADATA_URI.replace('/', "~1"), field))
        .and_then(serde_json::Value::as_str);
    assert_eq!(
        actual,
        Some(expected_value),
        "{expected_kind:?} '{actor_name}' should receive A2A metadata field '{field}' with value '{expected_value}', got body {body}"
    );
}

#[then(expr = "managed agent {string} received A2A metadata field {string} with value {string}")]
fn named_managed_agent_received_a2a_metadata_field(
    world: &mut SurfaceWorld,
    agent_name: String,
    field: String,
    expected_value: String,
) {
    assert_actor_received_a2a_metadata_field(
        world,
        &agent_name,
        TargetActorKind::ManagedAgent,
        &field,
        &expected_value,
    );
}

#[then(expr = "external agent {string} received A2A metadata field {string} with value {string}")]
fn named_external_agent_received_a2a_metadata_field(
    world: &mut SurfaceWorld,
    agent_name: String,
    field: String,
    expected_value: String,
) {
    assert_actor_received_a2a_metadata_field(
        world,
        &agent_name,
        TargetActorKind::ExternalAgent,
        &field,
        &expected_value,
    );
}

#[then(expr = "managed agent {string} did not receive A2A metadata field {string}")]
fn named_managed_agent_did_not_receive_a2a_metadata_field(
    world: &mut SurfaceWorld,
    agent_name: String,
    field: String,
) {
    let request = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let body = request.json_body();
    let actual =
        body.pointer(&format!("/params/message/metadata/{}/{}", HEADER_METADATA_URI.replace('/', "~1"), field));
    assert!(
        actual.is_none(),
        "managed agent '{agent_name}' should not receive A2A metadata field '{field}', got body {body}"
    );
}

#[then(expr = "managed agent {string} received the forwarded request")]
fn named_managed_agent_received_forwarded_request(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let forwarded_requests: Vec<_> = get_observed_target_requests(target, &agent_name)
        .iter()
        .filter(|request| !is_agent_card_discovery(request))
        .cloned()
        .collect();
    let request = assert_called_exactly_once(&forwarded_requests, &format!("target actor '{}'", agent_name));

    let sent = get_sent_body(world);
    let forwarded = request.json_body();
    assert_eq!(
        sent, &forwarded,
        "managed agent '{}' body does not match sent body.\nSent: {}\nForwarded: {}",
        agent_name, sent, forwarded
    );
}

#[then(expr = "managed agent {string} received the forwarded path {string}")]
fn named_managed_agent_received_forwarded_path(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected: String,
) {
    let actual = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent)
        .path_and_query
        .as_str();
    assert_eq!(
        actual, expected,
        "expected managed agent '{}' forwarded path/query '{}', got '{}'",
        agent_name, expected, actual
    );
}

#[then(expr = "managed agent {string} received the forwarded request with content type {string}")]
fn named_managed_agent_received_forwarded_content_type(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected: String,
) {
    let request = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    assert_request_content_type_starts_with(request, &expected, &format!("managed agent '{}'", agent_name));
}

#[then(expr = "managed agent {string} did not receive header {string}")]
fn named_managed_agent_did_not_receive_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    header_name: String,
) {
    let request = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    assert_collaborator_header_absent(&request.headers, &header_name, &format!("managed agent '{}'", agent_name));
}

#[then("the admin API response includes a surface id")]
fn admin_api_response_includes_surface_id(world: &mut SurfaceWorld) {
    let body = &get_admin_response(world).body;
    let surface_id = get_response_surface_id(body, "the admin API response");
    assert!(!surface_id.is_empty(), "expected admin API response to include a non-empty surface id, got {}", body);
}

#[then("the admin API response does not include a surface id")]
fn admin_api_response_does_not_include_surface_id(world: &mut SurfaceWorld) {
    let body = &get_admin_response(world).body;
    assert_json_field_absent(body, "surface_id", "admin API response");
}

#[then(expr = "the audit read response status is {int}")]
fn audit_read_response_status_is(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    assert_response_status(Some(get_admin_response(world).status), expected);
}

#[then(expr = "permission {string} is granted")]
fn permission_is_granted(
    world: &mut SurfaceWorld,
    permission: String,
) {
    assert_permission(world, &permission, true);
}

#[then(expr = "permission {string} is denied")]
fn permission_is_denied(
    world: &mut SurfaceWorld,
    permission: String,
) {
    assert_permission(world, &permission, false);
}

fn assert_permission(
    world: &mut SurfaceWorld,
    permission: &str,
    expected: bool,
) {
    let body = &get_admin_response(world).body;
    let actual = body
        .get(permission)
        .and_then(|value| value.as_bool())
        .unwrap_or_else(|| panic!("permissions response should include boolean permission '{permission}', got {body}"));
    assert_eq!(actual, expected, "permission '{permission}' mismatch in {body}");
}

#[then("the VP Audit Log includes a policy decision")]
fn vp_audit_log_includes_policy_decision(world: &mut SurfaceWorld) {
    let events = audit_response_events(world, "VP Audit Log");
    assert!(
        events
            .iter()
            .any(|event| event
                .get("event")
                .and_then(|event| event.get("policy_decision"))
                .is_some()),
        "expected VP Audit Log policy decision, got {events:?}"
    );
}

#[then(expr = "the Credential Delegation Audit Log includes caller email {string}")]
fn credential_delegation_audit_log_includes_caller_email(
    world: &mut SurfaceWorld,
    email: String,
) {
    assert_audit_response_contains_text(world, &email, "Credential Delegation Audit Log caller email");
}

#[then(expr = "the Credential Delegation Audit Log includes caller name {string}")]
fn credential_delegation_audit_log_includes_caller_name(
    world: &mut SurfaceWorld,
    name: String,
) {
    assert_audit_response_contains_text(world, &name, "Credential Delegation Audit Log caller name");
}

#[then("the Credential Delegation Audit Log includes a token injection")]
fn credential_delegation_audit_log_includes_token_injection(world: &mut SurfaceWorld) {
    assert_audit_response_contains_text(world, "token_injected", "Credential Delegation Audit Log token injection");
}

#[then("the Credential Delegation Audit Log does not include OAuth access tokens")]
fn credential_delegation_audit_log_does_not_include_oauth_access_tokens(world: &mut SurfaceWorld) {
    assert_audit_response_does_not_contain_text(world, "bdd-delegated-access-token", "OAuth access token");
}

#[then("the Credential Delegation Audit Log does not include OAuth refresh tokens")]
fn credential_delegation_audit_log_does_not_include_oauth_refresh_tokens(world: &mut SurfaceWorld) {
    assert_audit_response_does_not_contain_text(world, "bdd-delegated-refresh-token", "OAuth refresh token");
}

#[then("the Credential Delegation Audit Log has no stored API-key secret values")]
fn credential_delegation_audit_log_has_no_stored_api_key_secret_values(world: &mut SurfaceWorld) {
    assert_audit_response_does_not_contain_text(world, "bdd-delegated-api-key", "API-key secret value");
}

#[then("the Credential Delegation Audit Log has no stored target-auth secret values")]
fn credential_delegation_audit_log_has_no_stored_target_auth_secret_values(world: &mut SurfaceWorld) {
    assert_audit_response_does_not_contain_text(world, "bdd-target-auth-secret-value", "target-auth secret value");
}

fn assert_audit_response_contains_text(
    world: &mut SurfaceWorld,
    expected: &str,
    context: &str,
) {
    let text = get_admin_response(world)
        .body
        .to_string();
    assert!(text.contains(expected), "expected {context} to include '{expected}', got {text}");
}

fn assert_audit_response_does_not_contain_text(
    world: &mut SurfaceWorld,
    unexpected: &str,
    context: &str,
) {
    let text = get_admin_response(world)
        .body
        .to_string();
    assert!(!text.contains(unexpected), "{context} leaked in audit response: {text}");
}

fn audit_response_events(
    world: &mut SurfaceWorld,
    context: &str,
) -> Vec<serde_json::Value> {
    get_admin_response(world)
        .body
        .get("events")
        .and_then(|events| events.as_array())
        .cloned()
        .unwrap_or_else(|| panic!("{context} response should include events, got {}", get_admin_response(world).body))
}

#[then(expr = "the admin API response status is {int}")]
fn admin_api_response_status_is(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    assert_response_status(Some(get_admin_response(world).status), expected);
}

#[then(expr = "the surface lookup response status is {int}")]
fn surface_lookup_response_status_is(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    assert_response_status(Some(get_surface_lookup_response(world).status), expected);
}

#[then(expr = "the admin API error response mentions {string}")]
fn admin_api_error_response_mentions(
    world: &mut SurfaceWorld,
    expected: String,
) {
    assert_json_body_mentions(&get_admin_response(world).body, &expected, "admin API error response");
}

#[then("the operator can still read the stored surface through the admin API")]
fn fetching_surface_by_id_returns_stored_configuration(world: &mut SurfaceWorld) {
    let lookup = get_surface_lookup_response(world);
    assert_status_with_body(lookup.status, 200, &lookup.body, "surface lookup");

    let fetched = &lookup.body;
    let stored = &get_admin_response(world).body;
    assert_json_bodies_equal(fetched, stored, "fetched surface should match the stored disabled configuration");
}

#[then("the stored surface keeps the existing surface id")]
fn stored_surface_keeps_existing_surface_id(world: &mut SurfaceWorld) {
    let body = &get_surface_lookup_response(world).body;
    let actual = get_response_surface_id(body, "the stored surface response");
    let expected = get_tracked_surface_id(world, "checking the stored surface response");
    assert_eq!(actual, expected, "expected stored surface to keep surface_id '{}', got {}", expected, body);
}

#[then(expr = "the stored surface shows the surface status {string}")]
fn stored_surface_shows_surface_status(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = &get_surface_lookup_response(world).body;
    assert_json_string_field_equals(body, "status", &expected, "stored surface");
}

#[then("the operator can no longer read the surface through the admin API")]
fn fetching_surface_by_id_returns_404(world: &mut SurfaceWorld) {
    let surface_id = get_tracked_surface_id(world, "checking the deleted surface lookup");

    let lookup = get_surface_lookup_response(world);
    assert_status_with_body(lookup.status, 404, &lookup.body, "deleted surface lookup");

    let body = &lookup.body;
    assert_json_string_field_equals(body, "error", "Not Found", "deleted surface lookup");
    assert_json_body_mentions(body, surface_id, "deleted surface lookup details");
}

#[then(expr = "the OAuth callback response status is {int}")]
fn oauth_callback_response_status_is(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    assert_response_status(Some(get_response_status_value(world)), expected);
}

#[then(expr = "the response status is {int}")]
fn response_status_is(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    assert_response_status(Some(get_response_status_value(world)), expected);
}

#[then(expr = "the caller Trust Check for trust registry {string} of type {string} reported result {string}")]
async fn caller_trust_check_reported_result(
    world: &mut SurfaceWorld,
    trust_registry_id: String,
    query_type: String,
    expected_result: String,
) {
    let count = scrape_trust_check_counter(world, &trust_registry_id, &query_type, &expected_result).await;
    assert!(
        count >= 1,
        "expected at least one agent_gateway_trust_check_total sample for \
         trust_registry_id={trust_registry_id:?}, query_type={query_type:?}, result={expected_result:?}; \
         got {count}"
    );
}

#[then(expr = "the target Trust Check reported error code {string}")]
async fn target_trust_check_reported_error_code(
    world: &mut SurfaceWorld,
    expected_code: String,
) {
    assert_trust_check_error_code(world, "target", &expected_code).await;
}

#[then(expr = "the caller Trust Check reported error code {string}")]
async fn caller_trust_check_reported_error_code(
    world: &mut SurfaceWorld,
    expected_code: String,
) {
    assert_trust_check_error_code(world, "caller", &expected_code).await;
}

async fn assert_trust_check_error_code(
    world: &SurfaceWorld,
    leg: &str,
    expected_code: &str,
) {
    let client = world
        .admin_client
        .as_ref()
        .expect(
            "admin client must exist before asserting Trust Check audit; add the 'trust check audit is enabled' given",
        );
    let mut observed: Vec<(bool, Option<String>)> = Vec::new();
    for _ in 0..30 {
        let response = client
            .send_recorded_json::<serde_json::Value>(reqwest::Method::GET, "/v1/audit?limit=200", None)
            .await
            .expect("read VP Audit Log events from the gateway");
        assert!(
            (200..300).contains(&response.status),
            "VP Audit Log read returned status {}; body {}",
            response.status,
            response.body
        );
        let events = response
            .body
            .get("events")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        observed = extract_trust_check_error_codes(&events, leg);
        if observed
            .iter()
            .any(|(_, code)| code.as_deref() == Some(expected_code))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("expected a {leg}-leg Trust Check audit event with error code {expected_code:?}; observed {observed:?}");
}

fn extract_trust_check_error_codes(
    events: &[serde_json::Value],
    leg: &str,
) -> Vec<(bool, Option<String>)> {
    events
        .iter()
        .filter_map(|event| {
            event
                .get("event")
                .and_then(|action| action.get("trust_check"))
        })
        .filter(|trust_check| {
            trust_check
                .get("leg")
                .and_then(serde_json::Value::as_str)
                == Some(leg)
        })
        .map(|trust_check| {
            let ok = trust_check
                .get("ok")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let error_code = trust_check
                .get("error_code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            (ok, error_code)
        })
        .collect()
}

async fn scrape_trust_check_counter(
    world: &SurfaceWorld,
    trust_registry_id: &str,
    query_type: &str,
    result: &str,
) -> u64 {
    let infra = world
        .infra
        .as_ref()
        .expect("scenario infra must exist before scraping prometheus");
    let url = format!("http://127.0.0.1:{}/api/v1/metrics/prometheus", infra.gateway_port);
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|error| panic!("scrape prometheus at {url}: {error}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|error| panic!("read prometheus body from {url}: {error}"));
    assert!(status.is_success(), "prometheus scrape at {url} returned {status}; body: {body}");
    sum_labeled_counter(
        &body,
        "agent_gateway_trust_check_total",
        &[("trust_registry_id", trust_registry_id), ("query_type", query_type), ("result", result)],
    )
}

fn sum_labeled_counter(
    exposition: &str,
    metric_name: &str,
    required_labels: &[(&str, &str)],
) -> u64 {
    let mut total = 0u64;
    for line in exposition.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(metric_name) else {
            continue;
        };
        let (label_block, after) = match rest.chars().next() {
            Some('{') => match rest[1..].split_once('}') {
                Some((labels, after)) => (labels, after),
                None => continue,
            },
            Some(c) if c.is_whitespace() => ("", rest),
            _ => continue,
        };
        if !required_labels
            .iter()
            .all(|(key, value)| label_block_contains(label_block, key, value))
        {
            continue;
        }
        if let Some(value) = after
            .split_whitespace()
            .next()
            .and_then(|token| token.parse::<f64>().ok())
        {
            total += value as u64;
        }
    }
    total
}

fn label_block_contains(
    label_block: &str,
    key: &str,
    value: &str,
) -> bool {
    let needle = format!("{key}=\"{value}\"");
    label_block
        .split(',')
        .any(|pair| pair.trim() == needle)
}

/// Assert the response is a JSON-RPC error carrying a specific numeric code.
///
/// Used for the A2A-specific codes, e.g. `-32009` `VersionNotSupportedError` when a
/// caller asks for a protocol version the gateway does not accept.
#[then(expr = "the response is a JSON-RPC error with code {int}")]
fn response_is_jsonrpc_error_with_code(
    world: &mut SurfaceWorld,
    expected_code: i64,
) {
    let body = get_response_body_value(world);
    let actual = body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64());
    assert_eq!(actual, Some(expected_code), "expected JSON-RPC error code {expected_code}; body was {body}");
}

/// Assert the response's JSON-RPC error lists a supported protocol version, so a
/// rejected caller can renegotiate without guessing.
#[then(expr = "the response error lists only the supported versions {string}")]
fn response_error_lists_only_supported_versions(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = get_response_body_value(world);
    let expected: Vec<&str> = expected
        .split(',')
        .map(str::trim)
        .collect();
    assert_eq!(
        body.pointer("/error/data/supported"),
        Some(&serde_json::json!(expected)),
        "unexpected supported versions in {body}"
    );
}

#[then(expr = "the created surface accepts A2A versions {string} with envelope validation")]
fn created_surface_accepts_a2a_versions(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = &get_admin_response(world).body;
    let expected: Vec<&str> = expected
        .split(',')
        .map(str::trim)
        .collect();
    assert_eq!(
        body.pointer("/access_point/a2a"),
        Some(&serde_json::json!({ "accepted_versions": expected, "validation": "envelope" })),
        "unexpected A2A settings in {body}"
    );
}

#[then(expr = "the response error lists supported version {string}")]
fn response_error_lists_supported_version(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = get_response_body_value(world);
    let supported = body
        .pointer("/error/data/supported")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        supported.contains(&expected),
        "expected supported versions to include {expected:?}; got {supported:?} (body {body})"
    );
}

/// Assert a value inside the served agent card, addressed by JSON pointer
/// (e.g. `/supportedInterfaces/0/protocolBinding`).
#[then(expr = "the agent card at {string} is {string}")]
fn agent_card_at_pointer_is(
    world: &mut SurfaceWorld,
    pointer: String,
    expected: String,
) {
    let card = get_response_body_value(world);
    let actual = card.pointer(&pointer);
    let actual_str = actual.and_then(|v| v.as_str());
    // Compare as a string when the value is a string, otherwise compare the
    // rendered JSON so booleans and numbers can be asserted too.
    let rendered = actual_str
        .map(str::to_string)
        .or_else(|| actual.map(|v| v.to_string()));
    assert_eq!(
        rendered.as_deref(),
        Some(expected.as_str()),
        "agent card at {pointer} expected {expected:?}; card was {card}"
    );
}

/// Assert a field is **absent** from the served agent card. A2A 1.0 removed or
/// relocated several v0.x fields, so proving they are gone matters as much as
/// proving the new ones are present.
#[then(expr = "the agent card at {string} is absent")]
fn agent_card_at_pointer_is_absent(
    world: &mut SurfaceWorld,
    pointer: String,
) {
    let card = get_response_body_value(world);
    assert!(
        card.pointer(&pointer)
            .is_none(),
        "expected agent card to have no value at {pointer}; card was {card}"
    );
}

#[then(expr = "the response content type is {string}")]
fn response_content_type(
    world: &mut SurfaceWorld,
    expected: String,
) {
    assert_content_type_contains(get_response_headers_value(world), &expected, "response");
}

fn assert_response_body_matches_expected(
    world: &SurfaceWorld,
    expected: &serde_json::Value,
    context: &str,
) {
    assert_json_bodies_equal(get_response_body_value(world), expected, context);
}

#[then(expr = "the response body matches managed agent {string} response")]
fn response_body_matches_managed_agent_response(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let expected = &get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent)
        .configured_response
        .body;
    assert_response_body_matches_expected(world, expected, &format!("managed agent '{}' response", agent_name));
}

#[then(expr = "the response body is error {string}")]
fn response_body_is_error(
    world: &mut SurfaceWorld,
    expected_error: String,
) {
    let body = get_response_body_value(world);

    let expected_body = match expected_error.as_str() {
        "request_denied_gateway_policy" => serde_json::json!({
            "type": "https://a2a-protocol.org/errors/proxy-error",
            "title": "Forbidden",
            "status": 403,
            "detail": "Request blocked by gateway policy"
        }),
        "request_policy_denied" => serde_json::json!({
            "error": "Forbidden",
            "message": "Agent trust policy denied the request"
        }),
        "response_policy_denied" => serde_json::json!({
            "error": "Response blocked",
            "code": "response_policy_denied",
        }),
        "transit_point_request_policy_denied" => serde_json::json!({
            "type": "https://a2a-protocol.org/errors/proxy-error",
            "title": "Forbidden",
            "status": 403,
            "detail": "Request blocked by surface policy"
        }),
        "agent_card_target_auth_failed" => serde_json::json!({
            "type": "https://a2a-protocol.org/errors/proxy-error",
            "title": "Bad Gateway",
            "status": 502,
            "detail": "Target authentication failed"
        }),
        "agent_card_upstream_redirected" => serde_json::json!({
            "type": "https://a2a-protocol.org/errors/proxy-error",
            "title": "Bad Gateway",
            "status": 502,
            "detail": "Upstream redirected"
        }),
        other => panic!("unsupported expected response error: {}", other),
    };

    assert_json_bodies_equal(body, &expected_body, &format!("response error '{expected_error}'"));
}

#[then("the OAuth callback response shows an authorization failure page")]
fn oauth_callback_response_shows_authorization_failure_page(world: &mut SurfaceWorld) {
    assert_content_type_contains(get_response_headers_value(world), "text/html", "OAuth callback response");
    let body = get_response_body_value(world)
        .get("text")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| {
            panic!(
                "expected OAuth callback response body to be captured as HTML text, got {}",
                get_response_body_value(world)
            )
        });
    assert!(
        body.contains("Authorization Failed"),
        "expected OAuth callback response to show an authorization failure page, got {body}"
    );
}

#[then(expr = "the response reports that variant {string} is disabled")]
fn response_reports_variant_disabled(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let body = get_response_body_value(world);
    let raw_body = body.to_string();

    assert!(
        raw_body.contains(&alias)
            && raw_body
                .to_lowercase()
                .contains("disabled"),
        "expected response body to report variant '{}' is disabled, got {}",
        alias,
        body
    );
}

fn get_did_document_service_uris(body: &serde_json::Value) -> Vec<String> {
    body.get("service")
        .and_then(|value| value.as_array())
        .map(|services| {
            services
                .iter()
                .flat_map(|service| {
                    service
                        .get("serviceEndpoint")
                        .and_then(|value| value.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|endpoint| {
                            endpoint
                                .get("uri")
                                .and_then(|value| value.as_str())
                                .map(str::to_string)
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[then(expr = "the DID document publishes the route {string}")]
fn did_document_publishes_route(
    world: &mut SurfaceWorld,
    route: String,
) {
    let body = get_response_body_value(world);
    let uris = get_did_document_service_uris(body);
    assert!(
        uris.iter()
            .any(|uri| uri.contains(&route)),
        "expected DID document to publish route '{}', got service URIs {:?}",
        route,
        uris
    );
}

#[then(expr = "the DID document does not publish the route {string}")]
fn did_document_does_not_publish_route(
    world: &mut SurfaceWorld,
    route: String,
) {
    let body = get_response_body_value(world);
    let uris = get_did_document_service_uris(body);
    assert!(
        uris.iter()
            .all(|uri| !uri.contains(&route)),
        "expected DID document not to publish route '{}', got service URIs {:?}",
        route,
        uris
    );
}

const AGENT_IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
const TRUST_REGISTRY_EXTENSION_URI: &str = "https://fabric.affinidi.io/extensions/trust-registry";

fn is_valid_vp(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => {
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty())
            {
                return true;
            }
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(s) {
                return obj.is_object() && obj.get("proof").is_some() && obj.get("type").is_some();
            }
            false
        }
        serde_json::Value::Object(obj) => obj.contains_key("proof") && obj.contains_key("type"),
        _ => false,
    }
}

#[then("the response contains the credential extension")]
fn response_contains_credential(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let result = &body["result"];
    let extensions = result["extensions"]
        .as_array()
        .expect("extensions should be an array in response");
    let ext_strings: Vec<&str> = extensions
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(
        ext_strings.contains(&AGENT_IDENTITY_CREDENTIAL_URI),
        "response extensions should contain credential URI, got: {:?}",
        ext_strings
    );
    let metadata = result["metadata"]
        .as_object()
        .expect("metadata should be an object in response");
    assert!(metadata.contains_key(AGENT_IDENTITY_CREDENTIAL_URI), "response metadata should contain credential key");
}

#[then("the response does not contain the raw identity extension")]
fn response_does_not_contain_raw_identity(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let result = &body["result"];
    let extensions = result["extensions"]
        .as_array()
        .expect("extensions should be an array in response");
    let ext_strings: Vec<&str> = extensions
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(
        !ext_strings.contains(&AGENT_IDENTITY_URI),
        "response extensions should NOT contain raw identity URI, got: {:?}",
        ext_strings
    );
    let metadata = result["metadata"]
        .as_object()
        .expect("metadata should be an object");
    assert!(!metadata.contains_key(AGENT_IDENTITY_URI), "response metadata should NOT contain raw identity key");
}

#[then("the response contains a valid Verifiable Presentation")]
fn response_contains_valid_vp(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let result = &body["result"];
    let credential = &result["metadata"][AGENT_IDENTITY_CREDENTIAL_URI];
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {}", vp);
    let did = credential["did"]
        .as_str()
        .expect("credential should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {}", did);
}

#[then("the agent card contains the credential extension")]
fn agent_card_contains_credential(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let extensions = body["capabilities"]["extensions"]
        .as_array()
        .expect("capabilities.extensions should be an array");
    let uris: Vec<&str> = extensions
        .iter()
        .filter_map(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
        })
        .collect();
    assert!(
        uris.contains(&AGENT_IDENTITY_CREDENTIAL_URI),
        "agent card extensions should contain credential URI, got: {:?}",
        uris
    );
}

#[then("the agent card does not contain the raw identity extension")]
fn agent_card_does_not_contain_raw(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let extensions = body["capabilities"]["extensions"]
        .as_array()
        .expect("capabilities.extensions should be an array");
    let uris: Vec<&str> = extensions
        .iter()
        .filter_map(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
        })
        .collect();
    assert!(
        !uris.contains(&AGENT_IDENTITY_URI),
        "agent card extensions should NOT contain raw identity URI, got: {:?}",
        uris
    );
}

#[then("the agent card contains a valid Verifiable Presentation")]
fn agent_card_contains_valid_vp(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let extensions = body["capabilities"]["extensions"]
        .as_array()
        .expect("capabilities.extensions should be an array");
    let credential_ext = extensions
        .iter()
        .find(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
                == Some(AGENT_IDENTITY_CREDENTIAL_URI)
        })
        .expect("credential extension should exist");
    let params = credential_ext
        .get("params")
        .expect("credential extension should have params");
    let vp = &params["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {}", vp);
    let did = params["did"]
        .as_str()
        .expect("credential params should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {}", did);
}

fn agent_card_extension_uris(body: &serde_json::Value) -> Vec<&str> {
    body["capabilities"]["extensions"]
        .as_array()
        .map(|exts| {
            exts.iter()
                .filter_map(|ext| {
                    ext.get("uri")
                        .and_then(|u| u.as_str())
                })
                .collect()
        })
        .unwrap_or_default()
}

#[then("the agent card does not contain the trust-registry extension")]
fn agent_card_does_not_contain_trust_registry_extension(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let uris = agent_card_extension_uris(body);
    assert!(
        !uris.contains(&TRUST_REGISTRY_EXTENSION_URI),
        "agent card extensions should NOT contain trust-registry URI, got: {:?}",
        uris
    );
}

#[then(expr = "the agent card carries the agentDNA field {string}")]
fn agent_card_carries_agent_dna(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = get_response_body_value(world);
    let actual = body
        .get("agentDNA")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("agent card should contain a string `agentDNA` field, got: {}", body));
    assert_eq!(actual, expected, "agentDNA mismatch: expected {:?}, got {:?}", expected, actual);
}

#[then("the agent card does not carry the agentDNA field")]
fn agent_card_does_not_carry_agent_dna(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    assert!(body.get("agentDNA").is_none(), "agent card should NOT contain an `agentDNA` field, got: {}", body);
}

#[then(expr = "the agent card carries the agentDid field {string}")]
fn agent_card_carries_agent_did(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = get_response_body_value(world);
    let actual = body
        .get("agentDid")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("agent card should contain a string `agentDid` field, got: {}", body));
    assert_eq!(actual, expected, "agentDid mismatch: expected {:?}, got {:?}", expected, actual);
}

#[then("the agent card does not carry the agentDid field")]
fn agent_card_does_not_carry_agent_did(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    assert!(body.get("agentDid").is_none(), "agent card should NOT contain an `agentDid` field, got: {}", body);
}

#[then(expr = "managed agent {string} received the agent card request")]
fn managed_agent_received_agent_card_request(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let request = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    assert_eq!(
        request.method, "GET",
        "agent card request to managed agent '{}' must be a GET, got '{}'",
        agent_name, request.method
    );
}

#[then("both responses contain the same DID")]
fn both_responses_same_did(world: &mut SurfaceWorld) {
    assert_eq!(world.collected_dids.len(), 2, "expected 2 collected DIDs, got {}", world.collected_dids.len());
    assert_eq!(
        world.collected_dids[0], world.collected_dids[1],
        "DIDs should be identical. DID1={}, DID2={}",
        world.collected_dids[0], world.collected_dids[1]
    );
}

fn get_mcp_request_for_actor<'a>(
    world: &'a SurfaceWorld,
    server_name: &str,
) -> &'a crate::bdd_support::mock_server::ReceivedRequest {
    let target = get_observed_target_for_actor(world, server_name, TargetActorKind::McpServer);
    assert_target_called_exactly_once(target, &format!("MCP server '{}'", server_name));
    let request = get_observed_target_request(target, &format!("MCP server '{}'", server_name));
    assert_json_request_body(request, &format!("MCP server '{}'", server_name));
    request
}

fn assert_mcp_response_id_matches_request(
    request: &crate::bdd_support::mock_server::ReceivedRequest,
    response_body: &serde_json::Value,
    context: &str,
) {
    let body = request.json_body();
    assert_json_rpc_id_matches_request_body(response_body, &body, &format!("{context} forwarded"));
}

fn build_expected_mcp_server_response_body_for_request(
    target: &ObservedTarget,
    request: &crate::bdd_support::mock_server::ReceivedRequest,
) -> serde_json::Value {
    let mut expected = target
        .configured_response
        .body
        .clone();
    let body = request.json_body();
    if let (Some(request_id), Some(expected_object)) = (body.get("id"), expected.as_object_mut())
        && expected_object.contains_key("id")
    {
        expected_object.insert("id".to_string(), request_id.clone());
    }
    expected
}

fn assert_mcp_original_body(
    world: &SurfaceWorld,
    request: &crate::bdd_support::mock_server::ReceivedRequest,
    context: &str,
) {
    let sent = get_sent_body(world);
    let forwarded = request.json_body();
    assert_eq!(
        sent, &forwarded,
        "{} body does not match sent body.\nSent: {}\nForwarded: {}",
        context, sent, forwarded
    );
}

#[then(expr = "MCP server {string} received the forwarded MCP request")]
fn named_mcp_server_received_mcp_request(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    get_mcp_request_for_actor(world, &server_name);
}

#[then(expr = "MCP server {string} received MCP method {string}")]
fn named_mcp_server_received_mcp_method(
    world: &mut SurfaceWorld,
    server_name: String,
    expected: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    assert_mcp_method(&body, &expected, &format!("MCP server '{}'", server_name));
}

#[then(expr = "the MCP response id matches MCP server {string} forwarded request id")]
fn mcp_response_id_matches_named_mcp_server_forwarded_request_id(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_mcp_response_id_matches_request(
        request,
        get_response_body_value(world),
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "MCP server {string} received the original MCP request body")]
fn named_mcp_server_received_original_mcp_body(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_mcp_original_body(world, request, &format!("MCP server '{}'", server_name));
}

#[then(expr = "MCP server {string} received the forwarded MCP request with content type {string}")]
fn named_mcp_server_received_forwarded_mcp_content_type(
    world: &mut SurfaceWorld,
    server_name: String,
    expected: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_request_content_type_starts_with(request, &expected, &format!("MCP server '{}'", server_name));
}

#[then(expr = "MCP server {string} received delegated credential for OAuth provider {string}")]
fn named_mcp_server_received_oauth_delegated_credential(
    world: &mut SurfaceWorld,
    server_name: String,
    _provider: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_collaborator_header_value(
        &request.headers,
        "authorization",
        "Bearer bdd-delegated-access-token",
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "MCP server {string} received delegated credential for API-key provider {string}")]
fn named_mcp_server_received_api_key_delegated_credential(
    world: &mut SurfaceWorld,
    server_name: String,
    _provider: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_collaborator_header_value(
        &request.headers,
        "authorization",
        "Bearer bdd-delegated-api-key",
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "MCP server {string} did not receive delegated credential for OAuth provider {string}")]
fn named_mcp_server_did_not_receive_oauth_delegated_credential(
    world: &mut SurfaceWorld,
    server_name: String,
    _provider: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_collaborator_header_absent(&request.headers, "authorization", &format!("MCP server '{}'", server_name));
}

#[then(expr = "MCP server {string} received header {string} with delegated credential from OAuth provider {string}")]
fn named_mcp_server_received_delegated_credential_header(
    world: &mut SurfaceWorld,
    server_name: String,
    header_name: String,
    _provider: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_collaborator_header_value(
        &request.headers,
        &header_name,
        "Bearer bdd-delegated-access-token",
        &format!("MCP server '{}'", server_name),
    );
}

#[then(
    expr = "MCP server {string} received MCP _meta key {string} with delegated credential from OAuth provider {string}"
)]
fn named_mcp_server_received_meta_key_with_delegated_credential(
    world: &mut SurfaceWorld,
    server_name: String,
    key: String,
    _provider: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    let actual = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(&key))
        .and_then(|v| v.as_str());
    assert_eq!(
        actual,
        Some("bdd-delegated-access-token"),
        "MCP server '{}' expected params._meta.{} to contain delegated credential, got {:?} in body {}",
        server_name,
        key,
        actual,
        body
    );
}

#[then(expr = "MCP server {string} received header {string} with value {string}")]
fn named_mcp_server_received_header(
    world: &mut SurfaceWorld,
    server_name: String,
    header_name: String,
    expected_value: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_collaborator_header_value(
        &request.headers,
        &header_name,
        &expected_value,
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "MCP server {string} did not receive header {string}")]
fn named_mcp_server_did_not_receive_header(
    world: &mut SurfaceWorld,
    server_name: String,
    header_name: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_collaborator_header_absent(&request.headers, &header_name, &format!("MCP server '{}'", server_name));
}

#[then(expr = "MCP server {string} received MCP _meta key {string} with value {string}")]
fn named_mcp_server_received_meta_key(
    world: &mut SurfaceWorld,
    server_name: String,
    key: String,
    expected_value: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    let actual = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(&key))
        .and_then(|v| v.as_str())
        .or_else(|| {
            body.get("_meta")
                .and_then(|m| m.get(&key))
                .and_then(|v| v.as_str())
        });
    assert_eq!(
        actual,
        Some(expected_value.as_str()),
        "MCP server '{}' expected params._meta.{} = {:?}, got {:?} in body {}",
        server_name,
        key,
        expected_value,
        actual,
        body
    );
}

#[then(expr = "MCP server {string} received MCP metadata key {string} only in {string}")]
fn named_mcp_server_received_exact_metadata_location(
    world: &mut SurfaceWorld,
    server: String,
    key: String,
    location: String,
) {
    let request = get_mcp_request_for_actor(world, &server);
    crate::bdd_support::mcp_metadata::assert_key_only_at(&request.json_body(), &key, &location);
}

#[then(expr = "the MCP response contains metadata key {string} only in {string}")]
fn mcp_response_has_exact_metadata_location(
    world: &mut SurfaceWorld,
    key: String,
    location: String,
) {
    crate::bdd_support::mcp_metadata::assert_key_only_at(get_response_body_value(world), &key, &location);
}

#[then(expr = "the MCP response does not contain metadata key {string}")]
fn mcp_response_has_no_metadata_key(
    world: &mut SurfaceWorld,
    key: String,
) {
    crate::bdd_support::mcp_metadata::assert_key_absent(get_response_body_value(world), &key);
}

#[then(expr = "MCP server {string} did not receive MCP _meta key {string}")]
fn named_mcp_server_did_not_receive_meta_key(
    world: &mut SurfaceWorld,
    server_name: String,
    key: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    let value = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(&key))
        .or_else(|| {
            body.get("_meta")
                .and_then(|m| m.get(&key))
        });
    assert!(
        value.is_none(),
        "MCP server '{}' unexpectedly received params._meta.{} = {:?} in body {}",
        server_name,
        key,
        value,
        body
    );
}

#[then("the MCP surface proxied the MCP response to the caller")]
fn mcp_surface_proxied_response(world: &mut SurfaceWorld) {
    assert!(
        world
            .caller_response
            .is_some(),
        "no MCP response body received from gateway"
    );
    let body = get_response_body_value(world);
    assert!(body.is_object(), "MCP response should be a JSON object");
}

#[then(expr = "the MCP surface returns MCP server {string} tool catalog unchanged")]
fn mcp_surface_returns_tool_catalog_unchanged(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let target = get_observed_target_for_actor(world, &server_name, TargetActorKind::McpServer);
    let request = get_observed_target_request(target, &format!("MCP server '{}'", server_name));
    let expected = build_expected_mcp_server_response_body_for_request(target, request);
    let tools = expected
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(|tools| tools.as_array())
        .unwrap_or_else(|| {
            panic!("MCP server '{}' configured response should include result.tools, got {}", server_name, expected)
        });
    assert!(
        tools.len() >= 2,
        "MCP server '{}' tool catalog should include at least two tools, got {}",
        server_name,
        expected
    );
    assert_response_body_matches_expected(world, &expected, &format!("MCP server '{}' tool catalog", server_name));
}

#[then(expr = "the response is a consent required error for OAuth provider {string}")]
fn response_is_consent_required_error(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let body = get_response_body_value(world);
    assert_eq!(
        body.get("status")
            .and_then(|v| v.as_u64()),
        Some(401),
        "expected consent-required status in body, got {body}"
    );
    assert_eq!(
        body.get("type")
            .and_then(|v| v.as_str()),
        Some("https://affinidi.com/atg/errors/consent-required"),
        "expected consent-required problem type, got {body}"
    );
    assert!(
        consent_entry(body, &provider).is_some(),
        "expected consent_required entry for provider '{provider}', got {body}"
    );
}

#[then(expr = "the response includes an authorization URL for OAuth provider {string}")]
fn response_includes_authorization_url(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let body = get_response_body_value(world);
    let entry =
        consent_entry(body, &provider).unwrap_or_else(|| panic!("missing consent entry for '{provider}', got {body}"));
    let url = entry
        .get("authorization_url")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("consent entry for '{provider}' should include authorization_url, got {entry}"));
    assert!(url.contains("/authorize"), "authorization_url should point at OAuth authorization endpoint, got {url}");
}

#[then(expr = "the response includes delegated credential scopes {string}")]
fn response_includes_delegated_scopes(
    world: &mut SurfaceWorld,
    scopes: String,
) {
    let expected = scopes
        .split_whitespace()
        .collect::<Vec<_>>();
    let body = get_response_body_value(world);
    let actual = body
        .get("consent_required")
        .and_then(|entries| entries.as_array())
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("scopes"))
        .and_then(|scopes| scopes.as_array())
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(|scope| scope.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| panic!("consent_required entry should include scopes, got {body}"));
    assert_eq!(actual, expected, "unexpected delegated credential scopes in {body}");
}

#[then("the MCP response contains the credential extension")]
fn mcp_response_contains_credential(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let meta = body
        .get("result")
        .and_then(|r| r.get("_meta"))
        .and_then(|m| m.as_object())
        .expect("MCP response should have result._meta object");
    assert!(
        meta.contains_key(AGENT_IDENTITY_CREDENTIAL_URI),
        "MCP response _meta should contain credential URI key, got keys: {:?}",
        meta.keys()
            .collect::<Vec<_>>()
    );
    let credential = &meta[AGENT_IDENTITY_CREDENTIAL_URI];
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "verifiablePresentation should be a valid VP, got: {}", vp);
    let did = credential["did"]
        .as_str()
        .expect("credential should have did");
    assert!(did.starts_with("did:"), "did should start with 'did:', got: {}", did);
}

#[then("the MCP response does not contain the raw serverIdentity payload")]
fn mcp_response_no_raw_identity(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let meta = body
        .get("result")
        .and_then(|r| r.get("_meta"))
        .and_then(|m| m.as_object())
        .expect("MCP response should have result._meta object");
    assert!(!meta.contains_key("serverIdentity"), "MCP response result._meta should not contain raw serverIdentity");
    assert!(!meta.contains_key("agentIdentity"), "MCP response result._meta should not contain raw agentIdentity");
}

#[then("the MCP response contains the raw serverIdentity payload")]
fn mcp_response_has_raw_identity(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let meta = body
        .get("result")
        .and_then(|r| r.get("_meta"))
        .and_then(|m| m.as_object())
        .expect("MCP response should have result._meta object");
    assert!(
        meta.contains_key("serverIdentity"),
        "MCP response result._meta should still contain raw serverIdentity when strip_raw_meta is not enabled, got keys: {:?}",
        meta.keys()
            .collect::<Vec<_>>()
    );
}

fn get_mcp_binding_extension(
    request: &crate::bdd_support::mock_server::ReceivedRequest,
    context: &str,
) -> serde_json::Value {
    let body = request.json_body();
    let meta = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .or_else(|| body.get("_meta"))
        .and_then(|m| m.as_object())
        .unwrap_or_else(|| panic!("{} forwarded MCP request must have a _meta object, got: {}", context, body));
    meta.get("io.affinidi.fabric/agent-identity-binding")
        .or_else(|| meta.get(AGENT_IDENTITY_BINDING_URI))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "{} forwarded request _meta should contain identity-binding URI '{}', got keys: {:?}",
                context,
                AGENT_IDENTITY_BINDING_URI,
                meta.keys()
                    .collect::<Vec<_>>()
            )
        })
}

fn decode_vp(vp: &serde_json::Value) -> serde_json::Value {
    match vp {
        serde_json::Value::String(text) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                return json;
            }
            let parts: Vec<&str> = text.split('.').collect();
            if parts.len() == 3 {
                let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(parts[1])
                    .expect("JWT VP payload should be base64url encoded");
                serde_json::from_slice::<serde_json::Value>(&payload).expect("JWT VP payload should be JSON")
            } else {
                panic!("string VP should be JWT or JSON: {text}")
            }
        }
        value => value.clone(),
    }
}

// Generic VP-decoding helpers retained for the forthcoming per-Transit-Point
// workload-binding BDD coverage.
#[allow(dead_code)]
fn presentation_from_decoded_vp(decoded: &serde_json::Value) -> &serde_json::Value {
    decoded
        .get("vp")
        .unwrap_or(decoded)
}

#[allow(dead_code)]
fn first_vp_credential(presentation: &serde_json::Value) -> Option<&serde_json::Value> {
    let credentials = presentation
        .get("verifiableCredential")
        .or_else(|| presentation.get("verifiableCredentials"))?;
    if let Some(array) = credentials.as_array() {
        array.first()
    } else {
        Some(credentials)
    }
}

fn get_holder_did_from_vp(vp: &serde_json::Value) -> String {
    let decoded = decode_vp(vp);
    decoded
        .get("holder")
        .and_then(|holder| holder.as_str())
        .filter(|holder| holder.starts_with("did:"))
        .map(ToString::to_string)
        .unwrap_or_else(|| panic!("identity-binding VP should contain holder DID, got: {}", decoded))
}

fn get_did_from_mcp_binding_request(
    request: &crate::bdd_support::mock_server::ReceivedRequest,
    context: &str,
) -> String {
    let binding = get_mcp_binding_extension(request, context);
    let vp = &binding["verifiablePresentation"];
    assert!(is_valid_vp(vp), "{} identity-binding VP should be valid, got: {}", context, vp);
    get_holder_did_from_vp(vp)
}

fn assert_mcp_forwarded_field_matches_sent(
    sent: &serde_json::Value,
    forwarded: &serde_json::Value,
    field: &str,
    context: &str,
) {
    assert_json_field_matches(forwarded, sent, field, &format!("{context} forwarded MCP request"));
}

#[then(expr = "MCP server {string} received forwarded MCP field {string} unchanged")]
fn named_mcp_server_received_forwarded_mcp_field_unchanged(
    world: &mut SurfaceWorld,
    server_name: String,
    field: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_mcp_forwarded_field_matches_sent(
        get_sent_body(world),
        &request.json_body(),
        &field,
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "MCP server {string} received forwarded MCP metadata field {string} unchanged")]
fn named_mcp_server_received_forwarded_mcp_metadata_field_unchanged(
    world: &mut SurfaceWorld,
    server_name: String,
    field: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    assert_mcp_forwarded_field_matches_sent(
        get_sent_body(world),
        &request.json_body(),
        &format!("params._meta.{}", field),
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "the MCP response preserves MCP server {string} field {string}")]
fn mcp_response_preserves_named_mcp_server_field(
    world: &mut SurfaceWorld,
    server_name: String,
    field: String,
) {
    let target = get_observed_target_for_actor(world, &server_name, TargetActorKind::McpServer);
    let request = get_observed_target_request(target, &format!("MCP server '{}'", server_name));
    let expected = build_expected_mcp_server_response_body_for_request(target, request);
    assert_mcp_response_preserves_field(
        get_response_body_value(world),
        &expected,
        &field,
        &format!("MCP server '{}'", server_name),
    );
}

#[then("the MCP response id matches the request id")]
fn mcp_response_id_matches_request(world: &mut SurfaceWorld) {
    let request_id = world
        .sent_body
        .as_ref()
        .and_then(|b| b.get("id"))
        .expect("sent MCP request must have 'id'")
        .clone();
    let response_id = get_response_body_value(world)
        .get("id")
        .expect("MCP response body must have 'id'");
    assert_eq!(
        response_id, &request_id,
        "MCP response id must correlate with the request id.\nRequest: {}\nResponse: {}",
        request_id, response_id
    );
}

#[then(expr = "the MCP response result matches MCP server {string} response result")]
fn mcp_response_result_matches_named_mcp_server(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let target = get_observed_target_for_actor(world, &server_name, TargetActorKind::McpServer);
    let request = get_observed_target_request(target, &format!("MCP server '{}'", server_name));
    let expected = build_expected_mcp_server_response_body_for_request(target, request);
    assert_mcp_response_result_matches_body(
        get_response_body_value(world),
        &expected,
        &format!("MCP server '{}'", server_name),
    );
}

#[then(expr = "the MCP response is a JSON-RPC error with code {int}")]
fn mcp_response_is_jsonrpc_error(
    world: &mut SurfaceWorld,
    expected_code: i64,
) {
    assert_json_rpc_error_code(get_response_body_value(world), expected_code);
}

#[then(expr = "the MCP unsupported-version error requests {string} and supports only {string}")]
fn mcp_unsupported_version_error_has_exact_versions(
    world: &mut SurfaceWorld,
    requested: String,
    supported: String,
) {
    assert_mcp_unsupported_version_error(get_response_body_value(world), &requested, &supported);
}

#[then(expr = "the MCP response tool catalog does not include a tool named {string}")]
fn mcp_response_tool_catalog_excludes(
    world: &mut SurfaceWorld,
    name: String,
) {
    assert_mcp_tool_catalog_excludes(get_response_body_value(world), &name);
}

#[then(expr = "the MCP response tool catalog includes a tool named {string}")]
fn mcp_response_tool_catalog_includes(
    world: &mut SurfaceWorld,
    name: String,
) {
    assert_mcp_tool_catalog_includes(get_response_body_value(world), &name);
}

fn get_a2a_binding_extension(
    request: &crate::bdd_support::mock_server::ReceivedRequest,
    context: &str,
) -> serde_json::Value {
    let body = request.json_body();
    body.pointer(&format!("/params/message/metadata/{}", AGENT_IDENTITY_BINDING_URI.replace('/', "~1")))
        .cloned()
        .or_else(|| {
            body.pointer(&format!("/params/message/metadata/{}", AGENT_IDENTITY_CREDENTIAL_URI.replace('/', "~1")))
                .cloned()
        })
        .unwrap_or_else(|| {
            panic!(
                "{} forwarded A2A request should contain identity proof metadata '{}' or '{}', got body: {}",
                context, AGENT_IDENTITY_BINDING_URI, AGENT_IDENTITY_CREDENTIAL_URI, body
            )
        })
}

fn get_did_from_a2a_binding_request(
    request: &crate::bdd_support::mock_server::ReceivedRequest,
    context: &str,
) -> String {
    let binding = get_a2a_binding_extension(request, context);
    let vp = &binding["verifiablePresentation"];
    assert!(is_valid_vp(vp), "{} identity-binding VP should be valid, got: {}", context, vp);
    get_holder_did_from_vp(vp)
}

fn decode_json_or_jwt(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                return json;
            }
            let parts: Vec<&str> = text.split('.').collect();
            if parts.len() == 3 {
                let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(parts[1])
                    .expect("JWT payload should be base64url encoded");
                serde_json::from_slice::<serde_json::Value>(&payload).expect("JWT payload should be JSON")
            } else {
                panic!("string credential should be JWT or JSON: {text}")
            }
        }
        value => value.clone(),
    }
}

fn first_credential_subject_from_vp(vp: &serde_json::Value) -> serde_json::Value {
    let decoded = decode_vp(vp);
    let presentation = presentation_from_decoded_vp(&decoded);
    let credential = first_vp_credential(presentation)
        .unwrap_or_else(|| panic!("identity-binding VP should contain a verifiableCredential, got: {decoded}"));
    let decoded_credential = decode_json_or_jwt(credential);
    decoded_credential
        .get("credentialSubject")
        .cloned()
        .unwrap_or_else(|| {
            panic!("identity-binding credential should contain credentialSubject, got: {decoded_credential}")
        })
}

fn identity_field_value_from_subject<'a>(
    subject: &'a serde_json::Value,
    field: &str,
) -> Option<&'a serde_json::Value> {
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

fn assert_actor_received_a2a_binding_vp_identity_field(
    world: &SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
    field: &str,
    expected_value: &str,
) {
    let request = get_observed_request_for_actor(world, actor_name, expected_kind);
    let context = format!("{expected_kind:?} '{actor_name}'");
    let binding = get_a2a_binding_extension(request, &context);
    let vp = &binding["verifiablePresentation"];
    assert!(is_valid_vp(vp), "{context} identity-binding VP should be valid, got: {vp}");
    let subject = first_credential_subject_from_vp(vp);
    let actual = identity_field_value_from_subject(&subject, field).and_then(serde_json::Value::as_str);
    assert_eq!(
        actual,
        Some(expected_value),
        "{context} identity-binding VP should contain outbound managed-agent identity field '{field}' with value '{expected_value}', got credentialSubject: {subject}"
    );
}

#[then(
    expr = "external agent {string} received the forwarded request with a VP containing outbound managed-agent identity field {string} with value {string}"
)]
fn named_external_agent_received_a2a_binding_vp_identity_field(
    world: &mut SurfaceWorld,
    agent_name: String,
    field: String,
    expected_value: String,
) {
    assert_actor_received_a2a_binding_vp_identity_field(
        world,
        &agent_name,
        TargetActorKind::ExternalAgent,
        &field,
        &expected_value,
    );
}

#[then(expr = "managed agent {string} received two forwarded requests with VPs proving different caller Agent DIDs")]
fn named_managed_agent_received_two_binding_vps_for_different_dids(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let observations = target
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("managed agent '{}' observations must be recorded", agent_name));
    assert_eq!(
        observations.requests.len(),
        2,
        "expected managed agent '{}' to receive exactly two forwarded requests, got {}",
        agent_name,
        observations.requests.len()
    );
    let first = get_did_from_a2a_binding_request(&observations.requests[0], "first managed agent request");
    let second = get_did_from_a2a_binding_request(&observations.requests[1], "second managed agent request");
    assert_ne!(first, second, "identity-binding VP holder DIDs should differ");
}

#[then(expr = "managed agent {string} received two forwarded requests with VPs proving the same caller Agent DID")]
fn named_managed_agent_received_two_binding_vps_for_same_did(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let observations = target
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("managed agent '{}' observations must be recorded", agent_name));
    assert_eq!(
        observations.requests.len(),
        2,
        "expected managed agent '{}' to receive exactly two forwarded requests, got {}",
        agent_name,
        observations.requests.len()
    );
    let first = get_did_from_a2a_binding_request(&observations.requests[0], "first managed agent request");
    let second = get_did_from_a2a_binding_request(&observations.requests[1], "second managed agent request");
    assert_eq!(first, second, "identity-binding VP holder DIDs should match");
}

fn assert_actor_received_header(
    world: &SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
    header_name: &str,
    expected_value: &str,
) {
    let request = get_observed_request_for_actor(world, actor_name, expected_kind);
    assert_collaborator_header_value(
        &request.headers,
        header_name,
        expected_value,
        &format!("{expected_kind:?} '{}'", actor_name),
    );
}

fn assert_actor_did_not_receive_header(
    world: &SurfaceWorld,
    actor_name: &str,
    expected_kind: TargetActorKind,
    header_name: &str,
) {
    let request = get_observed_request_for_actor(world, actor_name, expected_kind);
    assert_collaborator_header_absent(&request.headers, header_name, &format!("{expected_kind:?} '{}'", actor_name));
}

#[then(expr = "managed agent {string} received header {string} with value {string}")]
fn named_managed_agent_received_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    header_name: String,
    expected_value: String,
) {
    assert_actor_received_header(world, &agent_name, TargetActorKind::ManagedAgent, &header_name, &expected_value);
}

#[then(expr = "external agent {string} received header {string} with value {string}")]
fn named_external_agent_received_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    header_name: String,
    expected_value: String,
) {
    assert_actor_received_header(world, &agent_name, TargetActorKind::ExternalAgent, &header_name, &expected_value);
}

#[then(expr = "external agent {string} did not receive header {string}")]
fn named_external_agent_did_not_receive_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    header_name: String,
) {
    assert_actor_did_not_receive_header(world, &agent_name, TargetActorKind::ExternalAgent, &header_name);
}

#[then(expr = "the response includes header {string} with value {string}")]
fn response_includes_header_with_value(
    world: &mut SurfaceWorld,
    header_name: String,
    expected_value: String,
) {
    assert_collaborator_header_value(get_response_headers_value(world), &header_name, &expected_value, "response");
}

#[then(expr = "the response carries a non-empty {string} header")]
fn response_carries_non_empty_header(
    world: &mut SurfaceWorld,
    header_name: String,
) {
    let headers = get_response_headers_value(world);
    let key = header_name.to_lowercase();
    let value = headers
        .get(&key)
        .or_else(|| headers.get(&header_name))
        .unwrap_or_else(|| panic!("response missing header '{}'; headers: {:?}", header_name, headers));
    assert!(!value.is_empty(), "response header '{}' must be non-empty, got empty string", header_name);
}

#[then("the SSE stream emits an endpoint event with a session message URL")]
fn sse_stream_emits_endpoint_event(world: &mut SurfaceWorld) {
    let path = world
        .sse_endpoint_path
        .as_deref()
        .unwrap_or_else(|| panic!("sse_endpoint_path must be set; did the caller connect to the Legacy SSE endpoint?"));
    assert!(
        !path.is_empty() && path.starts_with('/'),
        "endpoint event must carry a non-empty URL path starting with '/'; got '{}'",
        path
    );
}

#[then("both calls receive a reply as an SSE message event")]
fn both_calls_receive_sse_message_reply(world: &mut SurfaceWorld) {
    let sent_id = world
        .sent_body
        .as_ref()
        .and_then(|b| b.get("id"))
        .cloned()
        .unwrap_or(serde_json::json!(1));

    assert_eq!(world.sse_responses.len(), 2, "expected 2 SSE message event replies, got {}", world.sse_responses.len());
    for (i, reply) in world
        .sse_responses
        .iter()
        .enumerate()
    {
        let reply_id = reply
            .get("id")
            .unwrap_or_else(|| {
                panic!(
                    "SSE message event reply {} missing 'id' field for request/response correlation; got: {}",
                    i, reply
                )
            });
        assert_eq!(
            reply_id, &sent_id,
            "SSE message event reply {} id mismatch: expected {:?}, got {:?}",
            i, sent_id, reply_id
        );
        assert!(
            reply.get("result").is_some(),
            "SSE message event reply {} must carry a 'result', not an error; got: {}",
            i,
            reply
        );
        assert!(
            reply.get("error").is_none(),
            "SSE message event reply {} must not carry an 'error'; got: {}",
            i,
            reply
        );
    }
}

#[then(expr = "REST API {string} received exactly {int} requests")]
fn named_rest_api_received_exactly_n_requests(
    world: &mut SurfaceWorld,
    actor_name: String,
    expected: usize,
) {
    let target = get_observed_target_for_actor(world, &actor_name, TargetActorKind::RestApi);
    let context = format!("REST API '{}'", actor_name);
    let requests = get_observed_target_requests(target, &context);
    assert_eq!(
        requests.len(),
        expected,
        "expected REST API '{}' to receive exactly {} request(s), got {}",
        actor_name,
        expected,
        requests.len()
    );
}

#[then("the response status is a gateway error")]
fn response_status_is_gateway_error(world: &mut SurfaceWorld) {
    let status = get_response_status_value(world);
    assert!(status == 502 || status == 503, "expected gateway error status (502 or 503), got {}", status);
}

#[then("the response body is a gateway error message")]
fn response_body_is_gateway_error_message(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let raw_body = body
        .to_string()
        .to_lowercase();
    assert!(
        raw_body.contains("error") || raw_body.contains("unavailable") || raw_body.contains("upstream"),
        "expected gateway error body, got: {}",
        body
    );
}

#[then(expr = "the MCP response carries the proxy server info name {string}")]
fn mcp_response_carries_proxy_server_info_name(
    world: &mut SurfaceWorld,
    expected_name: String,
) {
    let body = get_response_body_value(world);
    let actual = body
        .get("result")
        .and_then(|result| result.get("serverInfo"))
        .and_then(|info| info.get("name"))
        .and_then(|name| name.as_str())
        .unwrap_or_else(|| panic!("MCP initialize response did not carry result.serverInfo.name. Body: {body}"));
    assert_eq!(
        actual, expected_name,
        "expected MCP serverInfo.name '{}', got '{}'. Body: {}",
        expected_name, actual, body
    );
}

#[then(expr = "the MCP tool result matches REST API {string} response")]
fn mcp_tool_result_matches_rest_api_response(
    world: &mut SurfaceWorld,
    actor_name: String,
) {
    let expected = &get_observed_target_for_actor(world, &actor_name, TargetActorKind::RestApi)
        .configured_response
        .body;
    let body = get_response_body_value(world);
    let text = body
        .pointer("/result/content/0/text")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("MCP tool response did not carry result.content[0].text. Body: {body}"));
    let parsed: serde_json::Value = serde_json::from_str(text)
        .unwrap_or_else(|err| panic!("MCP tool result.content[0].text is not JSON ({err}). Text: {text}"));
    let actual = parsed
        .get("body")
        .unwrap_or_else(|| panic!("rmcp-openapi wrapper missing 'body' field. Parsed: {parsed}"));
    assert_eq!(
        actual, expected,
        "MCP tool result body differs from REST API '{}' response.\nExpected: {}\nActual: {}",
        actor_name, expected, actual
    );
}

#[then(expr = "the MCP response carries a JSON-RPC error for an unknown tool")]
fn mcp_response_carries_unknown_tool_error(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let error = body
        .get("error")
        .unwrap_or_else(|| panic!("MCP response did not carry a JSON-RPC error. Body: {body}"));
    let code = error
        .get("code")
        .and_then(|c| c.as_i64())
        .unwrap_or_else(|| panic!("MCP error missing numeric code. Error: {error}"));
    assert_eq!(code, -32603, "expected JSON-RPC error code -32603, got {}. Body: {}", code, body);
    let message = error
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_else(|| panic!("MCP error missing message. Error: {error}"));
    assert!(
        message.contains("not found"),
        "expected error message to mention the tool was not found, got '{}'. Body: {}",
        message,
        body
    );
}

#[then(expr = "managed agent {string} received exactly {int} requests")]
fn named_managed_agent_received_exactly_n_requests(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected: usize,
) {
    let target = get_observed_target_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let context = format!("managed agent '{}'", agent_name);
    let actual = get_observed_target_requests(target, &context).len();
    assert_eq!(
        actual, expected,
        "expected managed agent '{}' to receive exactly {} request(s), got {}",
        agent_name, expected, actual
    );
}

#[then(expr = "managed agent {string} received the request body {}")]
fn named_managed_agent_received_request_body(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected_json: String,
) {
    let expected: serde_json::Value = serde_json::from_str(&expected_json).expect("expected body must be valid JSON");
    let request = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    let body = request.json_body();
    assert_eq!(body, expected, "expected managed agent '{}' to receive body {}, got {}", agent_name, expected, body);
}

#[then("the MCP response carries a JSON-RPC error for a disabled proxy")]
fn mcp_response_carries_disabled_proxy_error(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world);
    let error = body
        .get("error")
        .unwrap_or_else(|| panic!("MCP response did not carry a JSON-RPC error. Body: {body}"));
    let code = error
        .get("code")
        .and_then(|c| c.as_i64())
        .unwrap_or_else(|| panic!("MCP error missing numeric code. Error: {error}"));
    assert_eq!(code, -32603, "expected JSON-RPC error code -32603, got {}. Body: {}", code, body);
    let message = error
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_else(|| panic!("MCP error missing message. Error: {error}"));
    assert!(
        message.contains("disabled"),
        "expected error message to mention the proxy is disabled, got '{}'. Body: {}",
        message,
        body
    );
}

const AGENT_IDENTITY_BINDING_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";

fn assert_identity_error_response(
    world: &mut SurfaceWorld,
    expected_slot: &str,
    expected_code: &str,
) {
    let response = get_caller_response(world);
    assert_response_status(Some(response.status), 422);
    assert_content_type_contains(&response.headers, "application/problem+json", "identity error response");
    let body = get_response_body_value(world);
    assert_eq!(body["status"], 422, "expected problem+json status 422, got {}. Body: {}", body["status"], body);
    assert_eq!(
        body["code"], expected_code,
        "expected problem+json code '{}', got '{}'. Body: {}",
        expected_code, body["code"], body
    );
    assert_eq!(
        body["slot"], expected_slot,
        "expected problem+json slot '{}', got '{}'. Body: {}",
        expected_slot, body["slot"], body
    );
}

/// Assert that the caller-visible response is an RFC 7807 problem+json identity
/// validation failure with the expected deterministic fields.
#[then(expr = "the response is a protected identity validation error")]
fn response_is_protected_identity_validation_error(world: &mut SurfaceWorld) {
    let response = get_caller_response(world);
    assert_response_status(Some(response.status), 422);
    let body = get_response_body_value(world);
    if body.get("code").is_some() {
        assert_identity_error_response(world, "protected_identity", "identity_validation_failed");
        return;
    }
    assert_json_body_mentions(body, "Identity schema validation failed", "protected identity validation error");
}

#[then(expr = "the response is a {string} identity validation error")]
#[then(expr = "the response is an {string} identity validation error")]
fn response_is_identity_validation_error(
    world: &mut SurfaceWorld,
    expected_slot: String,
) {
    assert_identity_error_response(world, &expected_slot, "identity_validation_failed");
}

#[then(expr = "the response is a {string} identity extension missing error")]
fn response_is_identity_extension_missing_error(
    world: &mut SurfaceWorld,
    expected_slot: String,
) {
    assert_identity_error_response(world, &expected_slot, "identity_extension_missing");
}

#[then(expr = "MCP server {string} received the forwarded MCP request with a VP proving the caller Agent DID")]
fn named_mcp_server_received_request_with_binding_vp(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let binding = get_mcp_binding_extension(request, &format!("MCP server '{}'", server_name));
    let vp = &binding["verifiablePresentation"];
    assert!(
        is_valid_vp(vp),
        "MCP server '{}' forwarded request identity-binding verifiablePresentation should be a valid VP, got: {}",
        server_name,
        vp
    );
}

#[then(expr = "MCP server {string} received two forwarded MCP requests with VPs proving different caller Agent DIDs")]
fn named_mcp_server_received_two_binding_vps_for_different_dids(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let target = get_observed_target_for_actor(world, &server_name, TargetActorKind::McpServer);
    let observations = target
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("MCP server '{}' observations must be recorded", server_name));
    assert_eq!(
        observations.requests.len(),
        2,
        "expected MCP server '{}' to receive exactly two forwarded MCP requests, got {}",
        server_name,
        observations.requests.len()
    );
    let context = format!("MCP server '{}'", server_name);
    assert_json_request_body(&observations.requests[0], &context);
    assert_json_request_body(&observations.requests[1], &context);
    let first = get_did_from_mcp_binding_request(&observations.requests[0], "first MCP server request");
    let second = get_did_from_mcp_binding_request(&observations.requests[1], "second MCP server request");
    assert_ne!(first, second, "identity-binding VP holder DIDs should differ");
}

#[then(expr = "MCP server {string} received two forwarded MCP requests with VPs proving the same caller Agent DID")]
fn named_mcp_server_received_two_binding_vps_for_same_did(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let target = get_observed_target_for_actor(world, &server_name, TargetActorKind::McpServer);
    let observations = target
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("MCP server '{}' observations must be recorded", server_name));
    assert_eq!(
        observations.requests.len(),
        2,
        "expected MCP server '{}' to receive exactly two forwarded MCP requests, got {}",
        server_name,
        observations.requests.len()
    );
    let context = format!("MCP server '{}'", server_name);
    assert_json_request_body(&observations.requests[0], &context);
    assert_json_request_body(&observations.requests[1], &context);
    let first = get_did_from_mcp_binding_request(&observations.requests[0], "first MCP server request");
    let second = get_did_from_mcp_binding_request(&observations.requests[1], "second MCP server request");
    assert_eq!(first, second, "identity-binding VP holder DIDs should match");
}

#[then(expr = "MCP server {string} did not receive the raw inbound identity payload")]
fn named_mcp_server_did_not_receive_raw_inbound_identity(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    let meta = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .or_else(|| body.get("_meta"))
        .and_then(|m| m.as_object())
        .unwrap_or_else(|| {
            panic!("MCP server '{}' forwarded request must have a _meta object, got: {}", server_name, body)
        });
    assert!(
        !meta.contains_key("agentIdentity"),
        "MCP server '{}' forwarded request _meta should not contain raw agentIdentity, got: {}",
        server_name,
        body
    );
}

#[then(expr = "MCP server {string} received the raw inbound identity payload")]
fn named_mcp_server_received_raw_inbound_identity(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    let meta = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .or_else(|| body.get("_meta"))
        .and_then(|m| m.as_object())
        .unwrap_or_else(|| {
            panic!("MCP server '{}' forwarded request must have a _meta object, got: {}", server_name, body)
        });
    assert!(
        meta.contains_key("agentIdentity"),
        "MCP server '{}' forwarded request _meta should still contain raw agentIdentity when strip_raw_meta is not enabled, got: {}",
        server_name,
        body
    );
}

#[then(expr = "OAuth provider {string} received the authorization code exchange")]
fn oauth_provider_received_authorization_code_exchange(
    world: &mut SurfaceWorld,
    _provider: String,
) {
    let requests = oauth_provider_requests(world);
    assert!(
        requests
            .iter()
            .any(|request| request
                .path_and_query
                .starts_with("/token")),
        "expected OAuth provider to receive token exchange request, got {requests:?}; callback response was {:?}",
        world.caller_response
    );
}

#[then(expr = "OAuth provider {string} was not asked to exchange an authorization code")]
fn oauth_provider_was_not_asked_to_exchange_code(
    world: &mut SurfaceWorld,
    _provider: String,
) {
    let requests = oauth_provider_requests(world);
    assert!(requests.is_empty(), "expected no OAuth provider token exchange requests, got {requests:?}");
}

#[then(expr = "OAuth provider {string} received the refresh request")]
fn oauth_provider_received_refresh_request(
    world: &mut SurfaceWorld,
    _provider: String,
) {
    let requests = oauth_provider_requests(world);
    let refresh_request = requests
        .iter()
        .find_map(|request| {
            if !request
                .path_and_query
                .starts_with("/token")
            {
                return None;
            }
            let params = url::form_urlencoded::parse(request.raw_body.as_bytes())
                .into_owned()
                .collect::<HashMap<String, String>>();
            (params
                .get("grant_type")
                .map(String::as_str)
                == Some("refresh_token"))
            .then_some((request, params))
        })
        .unwrap_or_else(|| panic!("expected OAuth provider to receive token refresh request, got {requests:?}"));
    let (request, params) = refresh_request;
    assert!(
        params
            .get("refresh_token")
            .is_some_and(|token| !token.is_empty()),
        "expected OAuth refresh request to include refresh_token, got body {:?}",
        request.raw_body
    );
    assert!(
        !params.contains_key("code"),
        "expected OAuth refresh request not to include authorization code, got body {:?}",
        request.raw_body
    );
}

#[then(expr = "the delegation audit trail contains event {string} for OAuth provider {string}")]
fn delegation_audit_trail_contains_event(
    world: &mut SurfaceWorld,
    event: String,
    provider: String,
) {
    let events = read_delegation_audit_events(world);
    assert!(
        events.iter().any(|entry| {
            entry
                .get("event")
                .and_then(|value| value.as_str())
                == Some(event.as_str())
                && entry
                    .get("provider_id")
                    .and_then(|value| value.as_str())
                    == Some(provider.as_str())
        }),
        "expected delegation audit event '{event}' for provider '{provider}', got {events:?}"
    );
}

#[then(
    expr = "the delegation audit trail contains event {string} for OAuth provider {string} on the later MCP tool call"
)]
fn delegation_audit_trail_contains_later_event(
    world: &mut SurfaceWorld,
    event: String,
    provider: String,
) {
    delegation_audit_trail_contains_event(world, event, provider);
}

#[then("the delegation audit trail does not expose delegated credential secrets")]
fn delegation_audit_trail_does_not_expose_delegated_secrets(world: &mut SurfaceWorld) {
    let text = delegation_audit_text(world);
    assert!(!text.contains("bdd-delegated-access-token"), "audit trail exposed delegated access token: {text}");
    assert!(!text.contains("bdd-delegated-refresh-token"), "audit trail exposed delegated refresh token: {text}");
    assert!(!text.contains("bdd-delegated-api-key"), "audit trail exposed delegated API key: {text}");
}

#[then("the MCP response does not expose delegated credential secrets")]
fn mcp_response_does_not_expose_delegated_secrets(world: &mut SurfaceWorld) {
    let body = get_response_body_value(world).to_string();
    assert!(!body.contains("bdd-delegated-access-token"), "MCP response exposed delegated access token: {body}");
    assert!(!body.contains("bdd-delegated-refresh-token"), "MCP response exposed delegated refresh token: {body}");
    assert!(!body.contains("bdd-delegated-api-key"), "MCP response exposed delegated API key: {body}");
}

#[then(expr = "the delegation audit trail identifies caller {string}")]
fn delegation_audit_trail_identifies_caller(
    world: &mut SurfaceWorld,
    caller: String,
) {
    let events = read_delegation_audit_events(world);
    assert!(
        events.iter().any(|event| {
            event
                .get("caller")
                .and_then(|caller| caller.get("sub"))
                .and_then(|sub| sub.as_str())
                == Some(caller.as_str())
        }),
        "expected delegation audit trail to identify caller '{caller}', got {events:?}"
    );
}

#[then("the delegation audit trail identifies the caller Agent DID")]
fn delegation_audit_trail_identifies_caller_agent_did(world: &mut SurfaceWorld) {
    let events = read_delegation_audit_events(world);
    assert!(
        events
            .iter()
            .any(|event| event_contains_text(event, "did:")),
        "expected delegation audit trail to identify caller Agent DID, got {events:?}"
    );
}

#[then(expr = "the delegation audit trail identifies MCP tool {string}")]
fn delegation_audit_trail_identifies_mcp_tool(
    world: &mut SurfaceWorld,
    tool: String,
) {
    let events = read_delegation_audit_events(world);
    assert!(
        events.iter().any(|event| {
            event
                .get("mcp_tool_name")
                .and_then(|value| value.as_str())
                == Some(tool.as_str())
        }),
        "expected delegation audit trail to identify MCP tool '{tool}', got {events:?}"
    );
}

#[then(expr = "the delegation audit trail contains distinct authenticated caller records for {string} and {string}")]
fn delegation_audit_trail_contains_distinct_callers(
    world: &mut SurfaceWorld,
    first: String,
    second: String,
) {
    delegation_audit_trail_identifies_caller(world, first);
    delegation_audit_trail_identifies_caller(world, second);
}

#[then(expr = "both audit records are bound to caller Agent identity {string}")]
fn both_audit_records_are_bound_to_agent_identity(
    world: &mut SurfaceWorld,
    identity: String,
) {
    let events = read_delegation_audit_events(world);
    assert!(
        events
            .iter()
            .filter(|event| event_contains_text(event, &identity))
            .count()
            >= 2,
        "expected at least two audit records bound to caller Agent identity '{identity}', got {events:?}"
    );
}

#[then("both audit records identify the same caller Agent DID")]
fn both_audit_records_identify_same_caller_agent_did(world: &mut SurfaceWorld) {
    let events = read_delegation_audit_events(world);
    let dids = events
        .iter()
        .filter_map(extract_holder_did_from_audit_event)
        .collect::<Vec<_>>();
    assert!(dids.len() >= 2, "expected at least two audit records with caller Agent DIDs, got {events:?}");
    assert!(
        dids.iter()
            .all(|did| did == &dids[0]),
        "expected audit records to identify the same caller Agent DID, got {dids:?}"
    );
}

#[then(expr = "the VP received by MCP server {string} includes selected caller identity field {string}")]
fn mcp_server_received_vp_with_selected_caller_identity_field(
    world: &mut SurfaceWorld,
    server_name: String,
    field: String,
) {
    let request = get_mcp_request_for_actor(world, &server_name);
    let binding = get_mcp_binding_extension(request, &format!("MCP server '{}'", server_name));
    let material = expand_encoded_value(&binding).to_string();
    let leaf = field
        .rsplit('.')
        .next()
        .unwrap_or(&field);
    assert!(
        material.contains(leaf),
        "expected MCP request VP material to include selected identity field '{field}', got {material}"
    );
}

#[then(expr = "the MCP response does not ask caller {string} for consent")]
fn mcp_response_does_not_ask_for_consent(
    world: &mut SurfaceWorld,
    caller: String,
) {
    let body = get_response_body_value(world).to_string();
    assert!(!body.contains("consent_required"), "MCP response asked caller '{caller}' for consent: {body}");
}

#[then(expr = "MCP server {string} received the later MCP tool call")]
fn mcp_server_received_later_tool_call(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let target = get_observed_target_for_actor(world, &server_name, TargetActorKind::McpServer);
    let context = format!("MCP server '{}'", server_name);
    let request = get_observed_target_requests(target, &context)
        .last()
        .unwrap_or_else(|| panic!("{context} did not receive the later MCP tool call"));
    let body = request.json_body();
    assert_mcp_method(&body, "tools/call", &context);
}

fn oauth_provider_requests(world: &SurfaceWorld) -> Vec<crate::bdd_support::mock_server::ReceivedRequest> {
    world
        .collaborator_target(crate::bdd_support::actors::SECONDARY_COLLABORATOR_KEY)
        .observations
        .as_ref()
        .map(|observations| observations.requests.clone())
        .unwrap_or_default()
}

fn delegation_audit_text(world: &mut SurfaceWorld) -> String {
    serde_json::to_string(&read_delegation_audit_events(world)).expect("delegation audit events should serialize")
}

fn read_delegation_audit_events(world: &mut SurfaceWorld) -> Vec<serde_json::Value> {
    refresh_delegation_audit_trail(world);
    get_admin_response(world)
        .body
        .get("events")
        .and_then(|events| events.as_array())
        .cloned()
        .unwrap_or_else(|| {
            panic!("admin delegation audit response should include events, got {}", get_admin_response(world).body)
        })
}

fn refresh_delegation_audit_trail(world: &mut SurfaceWorld) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(crate::steps::when::read_delegation_audit_trail(world));
    });
}

fn consent_entry<'a>(
    body: &'a serde_json::Value,
    provider: &str,
) -> Option<&'a serde_json::Value> {
    body.get("consent_required")
        .and_then(|entries| entries.as_array())
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry
                    .get("provider_name")
                    .and_then(|value| value.as_str())
                    == Some(provider)
            })
        })
}

#[then(expr = "the payload capture includes a derived identity schema")]
fn payload_capture_includes_derived_identity_schema(world: &mut SurfaceWorld) {
    world
        .derived_identity_schema
        .as_ref()
        .expect("derived identity schema must be captured");
}

#[then(expr = "the derived identity schema includes field {string}")]
fn derived_identity_schema_includes_field(
    world: &mut SurfaceWorld,
    field: String,
) {
    let schema = world
        .derived_identity_schema
        .as_ref()
        .expect("derived identity schema must be captured");
    assert!(
        identity_schema_has_field(schema, &field),
        "expected derived identity schema to include field {field}; schema: {schema}"
    );
}

fn event_contains_text(
    event: &serde_json::Value,
    needle: &str,
) -> bool {
    expanded_audit_event_material(event).contains(needle)
}

fn extract_holder_did_from_audit_event(event: &serde_json::Value) -> Option<String> {
    let vp = event
        .get("vp_jwt")
        .or_else(|| event.get("workload_binding_vp"))?;
    let decoded = expand_encoded_value(vp);
    find_string_field(&decoded, "holder")
        .or_else(|| find_string_field(&decoded, "did"))
        .filter(|value| value.starts_with("did:"))
}

fn expanded_audit_event_material(event: &serde_json::Value) -> String {
    expand_encoded_value(event).to_string()
}

fn expand_encoded_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => decode_jwt_payload(text)
            .or_else(|| serde_json::from_str::<serde_json::Value>(text).ok())
            .map(|decoded| expand_encoded_value(&decoded))
            .unwrap_or_else(|| serde_json::Value::String(text.clone())),
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(expand_encoded_value)
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), expand_encoded_value(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn decode_jwt_payload(text: &str) -> Option<serde_json::Value> {
    let parts = text
        .split('.')
        .collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    serde_json::from_slice::<serde_json::Value>(&payload).ok()
}

fn find_string_field(
    value: &serde_json::Value,
    field: &str,
) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(found) = map
                .get(field)
                .and_then(|value| value.as_str())
            {
                return Some(found.to_string());
            }
            map.values()
                .find_map(|value| find_string_field(value, field))
        }
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|value| find_string_field(value, field)),
        _ => None,
    }
}

#[then(expr = "agent {string} received the forwarded request")]
async fn agent_received_forwarded_request(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let requests = world
        .runtimes
        .targets
        .get(&agent_name)
        .expect("Target must be present")
        .requests()
        .await;

    let sent_body = get_sent_body(world).clone();

    assert!(
        requests
            .last()
            .expect("agent should have received at least one request")
            .json_body()
            == sent_body,
        "expected agent '{}' to receive at least one request, but it received none",
        agent_name
    );
}

#[then(expr = "the response body matches agent {string} response")]
async fn response_body_matches_agent_response(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let expected_response = world
        .actors
        .target(&agent_name)
        .expect("Target must be present")
        .fixture
        .as_ref()
        .expect("Fixture must be present")
        .response
        .body
        .clone();
    let received_response = get_response_body_value(world).clone();
    assert!(
        received_response == expected_response,
        "expected response body to match agent '{}' response.\nExpected: {}\nReceived: {}",
        agent_name,
        expected_response,
        received_response
    );
}

#[then(expr = "agent {string} was not called")]
async fn agent_x_was_not_called(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let requests = world
        .runtimes
        .targets
        .get(&agent_name)
        .expect("Target must be present")
        .requests()
        .await;
    assert!(
        requests.is_empty(),
        "expected agent '{}' not to be called, but it received {} calls",
        agent_name,
        requests.len()
    );
}

#[then(expr = "agent {string} is called by path {string}")]
async fn agent_x_is_called_by_path_y(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
) {
    let requests = world
        .runtimes
        .targets
        .get(&agent_name)
        .expect("Target must be present")
        .requests()
        .await;

    let last_request = requests
        .last()
        .expect("Agent must be called at least once");

    assert!(
        last_request.path_and_query == path,
        "expected agent '{}' to be called by path '{}', but it was called by '{}'",
        agent_name,
        path,
        last_request.path_and_query
    );
}

#[then("the agent card url points to the gateway listen address")]
fn agent_card_url_points_to_gateway(world: &mut SurfaceWorld) {
    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .gateway_port;
    let body = get_response_body_value(world);
    let url = body
        .get("url")
        .and_then(|v| v.as_str())
        .expect("agent card must expose a top-level url field");
    let needle = format!("localhost:{}", gateway_port);
    assert!(
        url.contains(&needle),
        "agent card url should advertise the gateway listen address (contains '{}'), got '{}'",
        needle,
        url
    );
}

#[then(expr = "the agent card url does not contain managed agent {string} endpoint")]
fn agent_card_url_excludes_managed_agent_endpoint(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let managed_agent_url = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .mock
        .url();
    let managed_agent_host = managed_agent_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let body = get_response_body_value(world);
    let url = body
        .get("url")
        .and_then(|v| v.as_str())
        .expect("agent card must expose a top-level url field");
    assert!(
        !url.contains(managed_agent_host),
        "agent card url for managed agent '{}' must not leak Target host '{}', got '{}'",
        agent_name,
        managed_agent_host,
        url
    );
}

#[then(expr = "managed agent {string} received the agent card request at path {string}")]
fn managed_agent_received_agent_card_at_path(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected_path: String,
) {
    let request = get_observed_request_for_actor(world, &agent_name, TargetActorKind::ManagedAgent);
    assert_eq!(
        request.method, "GET",
        "agent card request to managed agent '{}' must be a GET, got '{}'",
        agent_name, request.method
    );
    assert_eq!(
        request.path_and_query, expected_path,
        "agent card request to managed agent '{}' must hit configured path '{}', got '{}'",
        agent_name, expected_path, request.path_and_query
    );
}

#[then(expr = "the agent card field {string} points to the gateway listen address")]
fn agent_card_field_points_to_gateway(
    world: &mut SurfaceWorld,
    field_name: String,
) {
    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .gateway_port;
    let body = get_response_body_value(world);
    let actual = body
        .get(&field_name)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("agent card must expose top-level string field '{}', got: {}", field_name, body));
    let needle = format!("localhost:{}", gateway_port);
    assert!(
        actual.contains(&needle),
        "agent card field '{}' should point to the gateway listen address (contains '{}'), got '{}'",
        field_name,
        needle,
        actual
    );
}

#[then("the agent card first endpoint url points to the gateway listen address")]
fn agent_card_first_endpoint_url_points_to_gateway(world: &mut SurfaceWorld) {
    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .gateway_port;
    let body = get_response_body_value(world);
    let url = body
        .get("endpoints")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("agent card must expose endpoints[0].url, got: {}", body));
    let needle = format!("localhost:{}", gateway_port);
    assert!(
        url.contains(&needle),
        "agent card endpoints[0].url should point to the gateway listen address (contains '{}'), got '{}'",
        needle,
        url
    );
}

/// Assert the Target's host appears **nowhere** in the served agent card.
///
/// Stronger than the per-field assertions: it covers nested arrays such as
/// `supportedInterfaces[]` and `additionalInterfaces[]`, and it fails if a future
/// URL-bearing field is added that the rewriter does not yet know about. Any URL
/// left pointing at the upstream would let a caller dial it directly and bypass the
/// gateway's authentication, policy and identity injection.
#[then(expr = "the agent card does not contain managed agent {string} endpoint anywhere")]
fn agent_card_excludes_managed_agent_endpoint_anywhere(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let managed_agent_url = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .mock
        .url();
    let managed_agent_host = managed_agent_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();
    let body = get_response_body_value(world);
    let serialized = serde_json::to_string(body).expect("agent card must serialize");
    for leaked_host in [managed_agent_host.as_str(), PUBLISHED_MANAGED_AGENT_HOST] {
        assert!(
            !serialized.contains(leaked_host),
            "agent card for managed agent '{}' leaks Target host '{}' somewhere: {}",
            agent_name,
            leaked_host,
            serialized
        );
    }
}

/// Host the managed-agent card fixtures publish as their own endpoint.
const PUBLISHED_MANAGED_AGENT_HOST: &str = "managed-agent.local";

#[then(expr = "every interface url in the agent card points to the gateway listen address")]
fn agent_card_interface_urls_point_to_gateway(world: &mut SurfaceWorld) {
    let gateway_base = format!(
        "http://localhost:{}/",
        world
            .infra
            .as_ref()
            .expect("scenario infra must be initialised before asserting on the agent card")
            .gateway_port
    );
    let body = get_response_body_value(world);
    let mut checked = 0;
    for key in ["supportedInterfaces", "additionalInterfaces"] {
        for interface in body
            .get(key)
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let url = interface
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("every {key} entry must carry a url, got: {interface}"));
            assert!(
                url.starts_with(&gateway_base),
                "{key} url should point to the gateway ('{gateway_base}...'), got '{url}' in {body}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "agent card must expose at least one interface url, got: {body}");
}

#[then(expr = "the agent card field {string} does not contain managed agent {string} endpoint")]
fn agent_card_field_excludes_managed_agent_endpoint(
    world: &mut SurfaceWorld,
    field_name: String,
    agent_name: String,
) {
    let managed_agent_url = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .mock
        .url();
    let managed_agent_host = managed_agent_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let body = get_response_body_value(world);
    let actual = body
        .get(&field_name)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("agent card must expose top-level string field '{}', got: {}", field_name, body));
    assert!(
        !actual.contains(managed_agent_host),
        "agent card field '{}' for managed agent '{}' must not leak Target host '{}', got '{}'",
        field_name,
        agent_name,
        managed_agent_host,
        actual
    );
}

#[then(expr = "the agent card first endpoint url does not contain managed agent {string} endpoint")]
fn agent_card_first_endpoint_url_excludes_managed_agent_endpoint(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let managed_agent_url = world
        .infra
        .as_ref()
        .expect("scenario infra must be initialised before asserting on the agent card")
        .mock
        .url();
    let managed_agent_host = managed_agent_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let body = get_response_body_value(world);
    let url = body
        .get("endpoints")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("agent card must expose endpoints[0].url, got: {}", body));
    assert!(
        !url.contains(managed_agent_host),
        "agent card endpoints[0].url for managed agent '{}' must not leak Target host '{}', got '{}'",
        agent_name,
        managed_agent_host,
        url
    );
}

/// Reads the next JSON-RPC message from the open MCP response stream,
/// skipping SSE comments. `Ok(None)` means the stream ended; `Err` means it
/// stayed open with nothing new within `wait`.
async fn next_mcp_stream_message(
    world: &mut SurfaceWorld,
    wait: std::time::Duration,
) -> Result<Option<serde_json::Value>, ()> {
    loop {
        if let Some(end) = world
            .mcp_stream_buffer
            .find("\n\n")
        {
            let event: String = world
                .mcp_stream_buffer
                .drain(..end + 2)
                .collect();
            let data: Vec<&str> = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim_start)
                .collect();
            if data.is_empty() {
                continue;
            }
            return Ok(Some(serde_json::from_str(&data.join("\n")).expect("MCP stream event data is JSON")));
        }
        let stream = world
            .mcp_stream
            .as_mut()
            .expect("an open MCP response stream");
        match tokio::time::timeout(wait, stream.chunk()).await {
            Err(_) => return Err(()),
            Ok(chunk) => match chunk.expect("read the MCP response stream") {
                Some(chunk) => world
                    .mcp_stream_buffer
                    .push_str(&String::from_utf8_lossy(&chunk)),
                None => return Ok(None),
            },
        }
    }
}

fn primary_mock_for<'a>(
    world: &'a SurfaceWorld,
    server_name: &str,
) -> &'a crate::bdd_support::mock_server::MockServer {
    assert_eq!(
        world
            .actors
            .target_collaborator_key(server_name),
        crate::bdd_support::actors::PRIMARY_COLLABORATOR_KEY,
        "MCP server '{server_name}' must be the primary target"
    );
    &world
        .infra
        .as_ref()
        .expect("scenario infrastructure")
        .mock
}

#[then(expr = "the response does not include header {string}")]
fn response_does_not_include_header(
    world: &mut SurfaceWorld,
    header_name: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response");
    assert!(
        !response
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case(&header_name)),
        "response must not include '{header_name}': {:?}",
        response.headers
    );
}

#[then(expr = "the caller receives MCP progress before MCP server {string} completes the tool")]
async fn caller_receives_progress_before_completion(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let wait = std::time::Duration::from_secs(10);
    let progress = next_mcp_stream_message(world, wait)
        .await
        .expect("progress arrives while the tool is still running")
        .expect("the stream stays open for progress");
    assert_eq!(progress["method"], "notifications/progress", "{progress}");
    let sent_token = world
        .sent_body
        .as_ref()
        .and_then(|body| body.pointer("/params/_meta/progressToken"))
        .cloned();
    assert_eq!(progress["params"]["progressToken"], sent_token.unwrap_or_default());
    let mock = primary_mock_for(world, &server_name);
    assert!(!mock.stream_completed().await, "progress must arrive before the tool completes");
    mock.release_stream().await;
    let complete = next_mcp_stream_message(world, wait)
        .await
        .expect("the final response arrives after release")
        .expect("the stream carries a final response");
    world.mcp_stream_closed_after_final =
        matches!(next_mcp_stream_message(world, std::time::Duration::from_secs(5)).await, Ok(None));
    world
        .caller_response
        .as_mut()
        .expect("caller response")
        .body = complete;
    crate::steps::when::record_mock_observation(world).await;
}

#[then("the MCP response stream closes after the final response")]
fn mcp_response_stream_closes_after_final(world: &mut SurfaceWorld) {
    assert!(world.mcp_stream_closed_after_final, "the response stream must end after its final response");
}

#[then(expr = "MCP server {string} stops processing the cancelled tool call")]
async fn mcp_server_stops_processing_cancelled_call(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let mock = primary_mock_for(world, &server_name);
    for _ in 0..100 {
        if mock.stream_cancelled().await {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("MCP server '{server_name}' kept processing after the caller disconnected");
}

#[then("the MCP response stream is closed")]
fn mcp_response_stream_is_closed(world: &mut SurfaceWorld) {
    assert!(world.mcp_stream.is_none(), "the caller's MCP response stream is closed");
}
