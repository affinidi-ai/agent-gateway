use std::collections::HashMap;

use cucumber::given;

use crate::bdd_support::actors::{
    GatewayInstanceActor, PRIMARY_COLLABORATOR_KEY, PolicyActor, SECONDARY_COLLABORATOR_KEY, SurfaceActor, TargetActor,
    TargetActorKind, TransitPointActor,
};
use crate::bdd_support::admin_client::AdminApiClient;
use crate::bdd_support::config::config_tree::{GatewayBootstrapFixture, PolicyDefinitionFixture};
use crate::bdd_support::config::mcp_proxy::WEATHER_OPENAPI_SPEC;
use crate::bdd_support::config::reserve_free_port;
use crate::bdd_support::config::single_surface_fixture::{
    A2aProxyTargetFixture, DidWebVhIdentityFixture, McpProxyTargetFixture, McpToolPolicyFixture,
    McpWildcardToolPolicyFixture, VariantInboundPolicyFixture, VariantTargetPolicyFixture,
};
use crate::bdd_support::config::source_auth::caller_authentication_method_json;
use crate::bdd_support::gateway_process::SURFACE_TEST_AUTH_TOKEN as TEST_AUTH_TOKEN;
use crate::bdd_support::mock_server::{MockAgentFixture, MockResponse};
use crate::bdd_support::policies::{
    build_gateway_request_path_policy, build_mcp_tool_allow_all_policy, build_mcp_tool_allow_policy,
    build_mcp_tool_deny_all_policy, build_surface_a2a_method_policy, build_surface_request_content_policy,
    build_surface_request_path_policy, build_surface_response_content_type_policy,
    build_transit_point_request_path_policy,
};
use crate::world::{
    ApiKeyProviderSourceAuthConfig, ApiKeySourceAuthConfig, CredentialProviderKind, DelegatedCredentialInjection,
    JwtSourceAuthConfig, RequestPolicyFixture, SurfaceCredentialDelegationConfig, SurfaceSourceAuthConfig,
    SurfaceTargetAuthConfig, SurfaceTransitPointConfig, SurfaceWorld, TransitPointHeaderMetadataMappingRow,
    TransitPointManagedIdentityConfig, mcp_identity_schema_with_field, select_identity_schema_field,
};
use tracing::log::Level;

use crate::bdd_support::config::agent_surface::{
    AccessPointFixture, AgentSurfaceFixture, TargetFixture, TransitPointFixture,
};

const AGENT_IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";

fn set_primary_target_response(
    world: &mut SurfaceWorld,
    response: impl Into<MockResponse>,
) {
    world.set_primary_target_response(response);
}

fn set_target_response_for_actor(
    world: &mut SurfaceWorld,
    actor_name: &str,
    response: impl Into<MockResponse>,
) {
    let response = response.into();
    match world
        .actors
        .target_collaborator_key(actor_name)
    {
        PRIMARY_COLLABORATOR_KEY => world.set_primary_target_response(response),
        SECONDARY_COLLABORATOR_KEY => world.set_secondary_target_response(response),
        other => panic!("target actor '{}' is registered with unsupported collaborator '{}'", actor_name, other),
    }
}

fn get_admin_response_surface_id(world: &SurfaceWorld) -> String {
    let response = world
        .admin_response
        .as_ref()
        .expect("admin_response must be set before recording the surface under test");
    response
        .body
        .get("surface_id")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("surface setup response must include surface_id, got {}", response.body))
        .to_string()
}

fn remember_surface_under_test_id(world: &mut SurfaceWorld) {
    world.surface_under_test_id = Some(get_admin_response_surface_id(world));
}

fn remember_named_surface_under_test_id(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    let surface_id = get_admin_response_surface_id(world);
    world.surface_under_test_id = Some(surface_id.clone());
    world
        .actors
        .record_surface_id(surface_name, &surface_id);
}

fn tracked_surface_id(
    world: &SurfaceWorld,
    surface_name: &str,
) -> String {
    world
        .actors
        .surface(surface_name)
        .and_then(|surface| surface.surface_id.clone())
        .or_else(|| {
            world
                .surface_under_test_id
                .clone()
        })
        .or_else(|| {
            world
                .created_surface_id
                .clone()
        })
        .unwrap_or_else(|| panic!("surface '{surface_name}' must have been created before this step"))
}

fn current_surface_body(
    world: &SurfaceWorld,
    action: &str,
) -> serde_json::Value {
    world
        .admin_response
        .as_ref()
        .unwrap_or_else(|| panic!("admin_response must contain current surface before {action}"))
        .body
        .clone()
}

async fn update_named_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
    payload: serde_json::Value,
    action: &str,
) {
    crate::steps::when::ensure_admin_session(world).await;
    let surface_id = tracked_surface_id(world, surface_name);
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .update_surface_recorded(&surface_id, &payload)
        .await
        .unwrap_or_else(|error| panic!("{action} through admin API: {error}"));
    world.admin_response = Some(response);
}

fn ensure_header_metadata_mapping(surface: &mut serde_json::Value) -> &mut serde_json::Value {
    if surface["access_point"]
        .get("header_metadata_mapping")
        .is_none()
        || surface["access_point"]["header_metadata_mapping"].is_null()
    {
        surface["access_point"]["header_metadata_mapping"] = serde_json::json!({
            "headers": [],
        });
    }
    &mut surface["access_point"]["header_metadata_mapping"]
}

#[given(expr = "the surface uses {string} MCP metadata output")]
async fn surface_uses_mcp_metadata_output(
    world: &mut SurfaceWorld,
    output: String,
) {
    crate::steps::when::ensure_admin_session(world).await;
    let name = world
        .surface_config
        .surface_name
        .as_deref()
        .expect("surface actor name");
    let surface_id = tracked_surface_id(world, name);
    let client = world
        .admin_client
        .as_ref()
        .expect("admin session");
    let path = format!("/v1/surfaces/{surface_id}");
    let mut surface: serde_json::Value = client
        .send_json::<(), _>(reqwest::Method::GET, &path, None)
        .await
        .expect("read surface");
    surface["mcp_legacy_metadata_output"] = serde_json::json!(output);
    let _: serde_json::Value = client
        .send_json(reqwest::Method::PUT, &path, Some(&surface))
        .await
        .expect("configure MCP metadata output");
}

#[given("the operator has updated the surface description without a metadata output preference")]
async fn older_client_updates_surface_description(world: &mut SurfaceWorld) {
    crate::steps::when::ensure_admin_session(world).await;
    let name = world
        .surface_config
        .surface_name
        .as_deref()
        .expect("surface actor name");
    let surface_id = tracked_surface_id(world, name);
    let client = world
        .admin_client
        .as_ref()
        .expect("admin session");
    let path = format!("/v1/surfaces/{surface_id}");
    let mut surface: serde_json::Value = client
        .send_json::<(), _>(reqwest::Method::GET, &path, None)
        .await
        .expect("read surface");
    surface
        .as_object_mut()
        .expect("surface object")
        .remove("mcp_legacy_metadata_output");
    surface["description"] = serde_json::json!("Updated by an older API client");
    let _: serde_json::Value = client
        .send_json(reqwest::Method::PUT, &path, Some(&surface))
        .await
        .expect("update surface description");
}

#[given(expr = "the operator can use the admin API and no surface is configured for route {string}")]
async fn admin_api_available_without_surface(
    world: &mut SurfaceWorld,
    route: String,
) {
    world.surface_config.protocol = "a2a".to_string();
    world
        .surface_config
        .transit_point = None;
    crate::steps::when::configure_unseeded_route(world, &route);

    crate::steps::when::ensure_admin_session(world).await;
}

fn register_primary_managed_agent(
    world: &mut SurfaceWorld,
    agent_name: &str,
) {
    world
        .actors
        .register_primary_target_with_kind(agent_name, TargetActorKind::ManagedAgent);
    world.register_primary_collaborator(agent_name, TargetActorKind::ManagedAgent);
}

#[given(expr = "the surface has a request policy that allows callers in group {string}")]
fn surface_has_request_policy_allowing_callers_in_group(
    world: &mut SurfaceWorld,
    group: String,
) {
    let policy_id = format!("bdd-caller-context-policy-{}", uuid::Uuid::new_v4());
    let group_literal = serde_json::to_string(&group).expect("group should serialize");
    let rego = format!(
        r#"package surface.policy

default allow = false

allow if {{
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.groups[_] == {group_literal}
}}
"#
    );
    world
        .surface_config
        .request_policy = Some(RequestPolicyFixture::new(policy_id, "BDD caller-context request policy", rego));
}

#[given(expr = "the surface has a policy denying callers whose source authentication failed")]
fn surface_has_policy_denying_unverified_callers(world: &mut SurfaceWorld) {
    let policy_id = format!("bdd-deny-unverified-source-auth-{}", uuid::Uuid::new_v4());
    // A caller-attributable source-auth failure (missing/invalid credential) is
    // non-blocking and surfaces to policy as `input.source_auth.method == "failed"`.
    // This policy is how an operator opts into blocking such callers.
    let rego = r#"package surface.policy

default allow = false

allow if {
    input.source_auth.method != "failed"
}
"#
    .to_string();
    world
        .surface_config
        .request_policy = Some(RequestPolicyFixture::new(policy_id, "BDD deny unverified source-auth policy", rego));
}

async fn add_bootstrapped_policy_to_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    policy_name: String,
    policy_fixture: PolicyDefinitionFixture,
    response_policy: bool,
) {
    let actors = world.actors_mut();
    let gateway_binding = actors
        .surface(&surface_name)
        .expect("Surface must be present")
        .gateway_binding
        .clone()
        .expect("binding must be present");

    let gateway_actor = actors
        .gateway_instance_mut(&gateway_binding)
        .expect("gateway must exist to set its policy");

    let gateway_fixture = gateway_actor
        .fixture
        .as_mut()
        .expect("gateway fixture must exist to set its policy");
    gateway_fixture
        .policies
        .insert(policy_name.clone(), policy_fixture);

    let surface_fixture = gateway_fixture
        .agent_surfaces
        .get_mut(&surface_name)
        .expect("agent surface must exist to set its policy");
    if response_policy {
        surface_fixture
            .target
            .response_policy = Some(policy_name.clone());
    } else {
        surface_fixture.target.policy = Some(policy_name.clone());
    }
}

#[given(
    expr = "A2A surface {string} has request policy {string} that allows inbound requests that contains {string} in body"
)]
async fn surface_has_request_policy_allowing_only_a2a_text(
    world: &mut SurfaceWorld,
    surface_name: String,
    policy_name: String,
    allowed_text: String,
) {
    let policy_text = build_surface_request_content_policy(&allowed_text);

    let policy_fixture = PolicyDefinitionFixture {
        id: policy_name.clone(),
        description: policy_name.clone(),
        rego: policy_text.clone(),
    };
    add_bootstrapped_policy_to_surface(world, surface_name, policy_name, policy_fixture, false).await;
}

/// Install a surface policy that allows only one exact A2A method name, so a
/// scenario can prove `input.a2a.method` reaches policy as the caller sent it.
#[given(expr = "A2A surface {string} has request policy {string} that allows only A2A method {string}")]
async fn surface_has_request_policy_allowing_only_a2a_method(
    world: &mut SurfaceWorld,
    surface_name: String,
    policy_name: String,
    allowed_method: String,
) {
    let policy_text = build_surface_a2a_method_policy(&allowed_method);

    let policy_fixture = PolicyDefinitionFixture {
        id: policy_name.clone(),
        description: policy_name.clone(),
        rego: policy_text.clone(),
    };
    add_bootstrapped_policy_to_surface(world, surface_name, policy_name, policy_fixture, false).await;
}

#[given(expr = "managed agent {string} is available as the surface target")]
fn managed_agent_available_as_target(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    register_primary_managed_agent(world, &agent_name);
    mock_agent_available_as_target(world);
}

fn mock_agent_available_as_target(world: &mut SurfaceWorld) {
    world.surface_config.protocol = "a2a".to_string();
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "ok"
    });
    set_primary_target_response(world, response);
}

async fn create_a2a_surface_for_route_targeting_mock(
    world: &mut SurfaceWorld,
    route: &str,
    surface_name: Option<&str>,
) {
    mock_agent_available_as_target(world);
    crate::steps::when::configure_unseeded_route(world, route);
    let mut payload = crate::steps::when::build_primary_target_surface_payload(world, route).await;
    if let Some(surface_name) = surface_name {
        payload["name"] = serde_json::json!(surface_name);
    }
    crate::steps::when::create_surface(world, payload).await;

    let response = world
        .admin_response
        .as_ref()
        .expect("admin_response must be set after surface setup");
    assert_eq!(
        response.status, 201,
        "surface setup should create the surface, got status {} body {}",
        response.status, response.body
    );
    if let Some(surface_name) = surface_name {
        remember_named_surface_under_test_id(world, surface_name);
    } else {
        remember_surface_under_test_id(world);
    }
}

#[given(expr = "A2A surface {string} exists for route {string} with managed agent {string} as its target")]
async fn named_surface_exists_for_route_targeting_mock(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    agent_name: String,
) {
    register_primary_managed_agent(world, &agent_name);
    world
        .actors
        .register_surface_with_target(&surface_name, "a2a", Some(&route), Some(&agent_name));
    create_a2a_surface_for_route_targeting_mock(world, &route, Some(&surface_name)).await;
}

#[given(expr = "surface {string} maps inbound header {string} to A2A metadata field {string}")]
async fn surface_maps_inbound_header_to_a2a_metadata(
    world: &mut SurfaceWorld,
    surface_name: String,
    header: String,
    field: String,
) {
    let mut surface = current_surface_body(world, "adding header metadata mapping");
    let mapping = ensure_header_metadata_mapping(&mut surface);
    let headers = mapping["headers"]
        .as_array_mut()
        .expect("header_metadata_mapping.headers must be an array");
    if let Some(existing) = headers
        .iter_mut()
        .find(|entry| {
            entry["header"]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&header))
        })
    {
        existing["field"] = serde_json::json!(field);
    } else {
        headers.push(serde_json::json!({
            "header": header,
            "field": field,
        }));
    }
    update_named_surface(world, &surface_name, surface, "adding header metadata mapping").await;
}

#[given(expr = "surface {string} preserves mapped headers when forwarding")]
async fn surface_preserves_mapped_headers_when_forwarding(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let mut surface = current_surface_body(world, "enabling mapped-header forwarding");
    let mapping = ensure_header_metadata_mapping(&mut surface);
    mapping["strip_mapped_headers"] = serde_json::json!(false);
    update_named_surface(world, &surface_name, surface, "enabling mapped-header forwarding").await;
}

#[given(
    expr = "surface {string} has request policy {string} that allows A2A metadata field {string} only when it equals {string}"
)]
async fn surface_has_request_policy_allowing_a2a_metadata_field(
    world: &mut SurfaceWorld,
    surface_name: String,
    policy_name: String,
    field: String,
    expected_value: String,
) {
    crate::steps::when::ensure_admin_session(world).await;
    let policy_id = format!("bdd-header-metadata-policy-{}", uuid::Uuid::new_v4());
    let field_literal = serde_json::to_string(&field).expect("field should serialize");
    let expected_literal = serde_json::to_string(&expected_value).expect("expected value should serialize");
    let rego = format!(
        r#"package surface.policy

 default allow := false

 allow if {{
     input.a2a.message.metadata["https://fabric.affinidi.io/extensions/header-metadata/v1"][{field_literal}] == {expected_literal}
 }}
 "#
    );
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .create_surface_policy_definition_recorded(&policy_id, &policy_name, &policy_name, &rego)
        .await
        .unwrap_or_else(|error| panic!("create surface policy definition through admin API: {error}"));
    assert_eq!(
        response.status, 201,
        "policy definition setup should create policy, got status {} body {}",
        response.status, response.body
    );

    let mut surface = current_surface_body(world, "attaching header metadata policy");
    surface["target"]["policy"] = serde_json::json!({
        "policy_definition_id": policy_id,
    });
    update_named_surface(world, &surface_name, surface, "attaching header metadata policy").await;
}

#[given(expr = "surface {string} has caller Trust Check that uses A2A metadata field {string}")]
async fn surface_has_caller_trust_check_using_a2a_metadata_field(
    world: &mut SurfaceWorld,
    surface_name: String,
    field: String,
) {
    crate::steps::when::ensure_admin_session(world).await;
    let registry_name = format!("bdd-unreachable-registry-{}", uuid::Uuid::new_v4());
    let admin_client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    admin_client
        .send_recorded_json(
            reqwest::Method::POST,
            "/v1/trust-registries",
            Some(&serde_json::json!({
                "name": registry_name,
                "description": "Unreachable registry for template-resolution coverage",
                "oob_url": "http://127.0.0.1:1/unreachable",
                "did_method": "peer"
            })),
        )
        .await
        .expect("create unreachable Trust Registry through admin API");
    let registries: Vec<serde_json::Value> = admin_client
        .send_json::<(), _>(reqwest::Method::GET, "/v1/trust-registries", None)
        .await
        .expect("list Trust Registries through admin API");
    let trust_registry_id = registries
        .iter()
        .find(|registry| registry["name"] == registry_name)
        .and_then(|registry| registry["id"].as_str())
        .expect("created unreachable Trust Registry must remain persisted")
        .to_string();
    let policy_id = format!("bdd-header-metadata-trust-check-policy-{}", uuid::Uuid::new_v4());
    let rego = r#"package surface.policy

default allow := true

allow := false if {
    input.trust_check_results.caller[_].error.code == "TEMPLATE_RESOLUTION_FAILED"
}
"#;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .create_surface_policy_definition_recorded(
            &policy_id,
            "Header metadata Trust Check template policy",
            "Denies when mapped-header Trust Check templates fail to resolve.",
            rego,
        )
        .await
        .unwrap_or_else(|error| panic!("create Trust Check policy definition through admin API: {error}"));
    assert_eq!(
        response.status, 201,
        "policy definition setup should create policy, got status {} body {}",
        response.status, response.body
    );

    let field_literal = serde_json::to_string(&field).expect("field should serialize");
    let entity_template = format!(
        "{{{{ input.a2a.message.metadata[\"https://fabric.affinidi.io/extensions/header-metadata/v1\"][{field_literal}] }}}}"
    );
    let mut surface = current_surface_body(world, "attaching header metadata Trust Check");
    surface["access_point"]["trust_check_list"] = serde_json::json!([
        {
            "id": "caller-header-metadata-template",
            "trust_registry_id": trust_registry_id,
            "query_type": "recognition",
            "query": {
                "authority_id": "did:example:authority",
                "entity_id": entity_template
            }
        }
    ]);
    surface["target"]["policy"] = serde_json::json!({
        "policy_definition_id": policy_id,
    });
    update_named_surface(world, &surface_name, surface, "attaching header metadata Trust Check").await;
}

#[given(expr = "the caller has DID {string}")]
fn caller_has_did(
    world: &mut SurfaceWorld,
    caller_did: String,
) {
    world.caller_did = Some(caller_did);
}

#[given(
    expr = "the surface has a caller-leg Trust Check for trust registry {string} of type {string} with entity template {string}"
)]
fn surface_has_caller_trust_check_with_entity_template(
    world: &mut SurfaceWorld,
    trust_registry_id: String,
    query_type: String,
    entity_template: String,
) {
    let element_id = format!("caller-{}-{}", query_type, uuid::Uuid::new_v4());
    let element = serde_json::json!({
        "id": element_id,
        "trust_registry_id": trust_registry_id,
        "query_type": query_type,
        "query": {
            "authority_id": "did:example:authority",
            "entity_id": entity_template,
        },
    });
    world
        .surface_config
        .caller_trust_check_list
        .push(element);
}

#[given("the surface has a policy that denies unless every caller Trust Check succeeded")]
fn surface_has_policy_denying_unless_caller_trust_checks_ok(world: &mut SurfaceWorld) {
    let policy_id = format!("bdd-trust-check-deny-on-caller-failure-{}", uuid::Uuid::new_v4());
    let rego = r#"package surface.policy

default allow := false

allow if {
    not input.trust_check_results
}

allow if {
    input.trust_check_results
    count([r | r := input.trust_check_results.caller[_]; r.ok == false]) == 0
}
"#;
    world
        .surface_config
        .request_policy = Some(PolicyDefinitionFixture::new(
        policy_id,
        "BDD surface policy: deny unless every caller Trust Check succeeded",
        rego,
    ));
}

#[given(expr = "surface {string} derives inbound identity from mapped A2A metadata fields {string} and {string}")]
async fn surface_derives_inbound_identity_from_mapped_a2a_metadata(
    world: &mut SurfaceWorld,
    surface_name: String,
    first_field: String,
    second_field: String,
) {
    let mut surface = current_surface_body(world, "configuring header metadata identity extraction");
    surface["identity_slots"]["inbound"] = serde_json::json!({
        "type": "payload_extraction",
        "extension_uri": "https://fabric.affinidi.io/extensions/header-metadata/v1",
        "meta_field": "agentIdentity",
        "fields": [first_field, second_field],
        "json_schema": {
            "type": "object",
            "properties": {
                first_field.clone(): { "type": "string", "x-identity": true },
                second_field.clone(): { "type": "string", "x-identity": true }
            },
            "required": [first_field.clone(), second_field.clone()]
        },
    });
    surface["target"]["identity_injection"] = serde_json::json!({
        "inject_vp": true,
    });
    update_named_surface(world, &surface_name, surface, "configuring header metadata identity extraction").await;
}

#[given(expr = "surface {string} requires {string} source authentication")]
async fn named_surface_requires_source_auth(
    world: &mut SurfaceWorld,
    surface_name: String,
    auth_type: String,
) {
    surface_requires_source_auth(world, auth_type);
    crate::steps::when::ensure_admin_session(world).await;
    let auth = world
        .surface_config
        .source_auth
        .as_ref()
        .expect("source auth config must be set");
    if let SurfaceSourceAuthConfig::ApiKey(cfg) = auth {
        let response = world
            .admin_client
            .as_ref()
            .expect("admin client must exist")
            .send_recorded_json(
                reqwest::Method::POST,
                "/api/v1/secrets/new",
                Some(&serde_json::json!({
                    "name": "BDD source API key",
                    "secret_id": cfg.secret_id,
                    "description": "BDD source authentication key",
                    "value": cfg.valid_key,
                    "secret_type": "ApiKey",
                    "tags": ["bdd"],
                })),
            )
            .await
            .unwrap_or_else(|error| panic!("create source auth secret through admin API: {error}"));
        assert!(
            response.status == 201 || response.status == 409,
            "source auth secret setup should create or reuse secret, got status {} body {}",
            response.status,
            response.body
        );
    }
    let mut surface = current_surface_body(world, "adding source authentication");
    surface["access_point"]["caller_authentication"] = serde_json::json!({
        "methods": [caller_authentication_method_json(auth)],
    });
    update_named_surface(world, &surface_name, surface, "adding source authentication").await;
}

#[given(expr = "A2A surface {string} is defined for route {string} with managed agent {string} as its target")]
fn named_surface_defined_for_route_targeting_agent(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    agent_name: String,
) {
    register_primary_managed_agent(world, &agent_name);
    world
        .actors
        .register_surface_with_target(&surface_name, "a2a", Some(&route), Some(&agent_name));

    world.surface_config.protocol = "a2a".to_string();
    world.surface_config.route = route.clone();
    world
        .surface_config
        .surface_name = Some(surface_name.clone());
    world
        .surface_config
        .registered_routes = vec![route];
    world
        .surface_config
        .seed_surface = true;
    world
        .actors
        .record_surface_id(&surface_name, "bdd-surface");
    world.surface_under_test_id = Some("bdd-surface".to_string());
}

#[given(expr = "Transit Point {string} routes to MCP server {string}")]
fn transit_point_routes_to_mcp_server(
    world: &mut SurfaceWorld,
    transit_point: String,
    server_name: String,
) {
    world
        .actors
        .register_target_with_key(&server_name, TargetActorKind::McpServer, SECONDARY_COLLABORATOR_KEY);
    world.register_secondary_collaborator(&server_name, TargetActorKind::McpServer);

    world
        .surface_config
        .transit_point = Some(SurfaceTransitPointConfig {
        alias: transit_point,
        protocol: "mcp".to_string(),
        header_metadata_mapping: Default::default(),
        managed_identity: None,
    });
}

#[given(expr = "surface {string} has A2A Transit Point {string} to external agent {string}")]
fn surface_has_a2a_transit_point_to_external_agent(
    world: &mut SurfaceWorld,
    surface_name: String,
    transit_point: String,
    external_agent: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "surface '{surface_name}' must be defined before adding Transit Point '{transit_point}'"
    );
    world
        .actors
        .register_target_with_key(&external_agent, TargetActorKind::ExternalAgent, SECONDARY_COLLABORATOR_KEY);
    world.register_secondary_collaborator(&external_agent, TargetActorKind::ExternalAgent);
    world
        .surface_config
        .transit_point = Some(SurfaceTransitPointConfig {
        alias: transit_point.clone(),
        protocol: "a2a".to_string(),
        header_metadata_mapping: Default::default(),
        managed_identity: None,
    });
    world
        .actors
        .put_transit_point(TransitPointActor {
            key: transit_point,
            fixture: None,
            bootstrapped: false,
            surface_binding: Some(surface_name),
            target_binding: Some(external_agent),
        });
}

#[given(expr = "the surface has a transit point {string} to external agent {string}")]
fn surface_has_transit_point_to_external_agent(
    world: &mut SurfaceWorld,
    transit_point: String,
    external_agent: String,
) {
    world
        .actors
        .register_target_with_key(&external_agent, TargetActorKind::ExternalAgent, SECONDARY_COLLABORATOR_KEY);
    world.register_secondary_collaborator(&external_agent, TargetActorKind::ExternalAgent);
    world
        .surface_config
        .transit_point = Some(SurfaceTransitPointConfig {
        alias: transit_point.clone(),
        protocol: "a2a".to_string(),
        header_metadata_mapping: Default::default(),
        managed_identity: None,
    });
    world
        .actors
        .put_transit_point(TransitPointActor {
            key: transit_point,
            fixture: None,
            bootstrapped: false,
            surface_binding: None,
            target_binding: Some(external_agent),
        });
}

#[given(expr = "external agent {string} is unreachable")]
fn external_agent_is_unreachable(
    world: &mut SurfaceWorld,
    external_agent: String,
) {
    world.mark_target_unreachable(&external_agent);
}

fn build_external_agent_card(
    did: &str,
    unverifiable_vp: bool,
) -> serde_json::Value {
    let mut extensions: Vec<serde_json::Value> = Vec::new();
    if unverifiable_vp {
        extensions.push(serde_json::json!({
            "uri": "https://fabric.affinidi.io/extensions/agent-identity-credential/v1",
            "params": {
                "did": did,
                "verifiablePresentation": "{}"
            }
        }));
    }
    serde_json::json!({
        "protocolVersion": "1.0",
        "id": did,
        "name": "external-agent",
        "capabilities": { "extensions": extensions }
    })
}

#[given(expr = "external agent {string} publishes an agent card without an agent-identity-credential")]
fn external_agent_publishes_card_without_identity_credential(
    world: &mut SurfaceWorld,
    external_agent: String,
) {
    let did = world
        .external_agent_card_did
        .clone()
        .unwrap_or_else(|| "did:web:example.com:target".to_string());
    let card = build_external_agent_card(&did, false);
    set_target_response_for_actor(world, &external_agent, MockResponse::json(card));
}

#[given(expr = "external agent {string} publishes an agent card with an unverifiable agent-identity-credential")]
fn external_agent_publishes_card_with_unverifiable_identity_credential(
    world: &mut SurfaceWorld,
    external_agent: String,
) {
    let did = world
        .external_agent_card_did
        .clone()
        .unwrap_or_else(|| "did:web:example.com:target".to_string());
    let card = build_external_agent_card(&did, true);
    set_target_response_for_actor(world, &external_agent, MockResponse::json(card));
}

#[given(expr = "transit point {string} has a target-leg Trust Check for trust registry {string} of type {string}")]
fn transit_point_has_target_trust_check(
    world: &mut SurfaceWorld,
    _transit_point: String,
    trust_registry_id: String,
    query_type: String,
) {
    let element_id = format!("target-{}-{}", query_type, uuid::Uuid::new_v4());
    let element = serde_json::json!({
        "id": element_id,
        "trust_registry_id": trust_registry_id,
        "query_type": query_type,
        "query": {
            "authority_id": "did:example:authority",
            "entity_id": "did:example:target",
        },
    });
    world
        .surface_config
        .target_trust_check_list
        .push(element);
}

#[given(expr = "the surface has a policy that denies a target Trust Check reporting error code {string}")]
fn surface_has_policy_denying_target_trust_check_error_code(
    world: &mut SurfaceWorld,
    error_code: String,
) {
    let policy_id = format!("bdd-trust-check-target-deny-{}", uuid::Uuid::new_v4());
    let rego = format!(
        r#"package surface.policy

default allow := false

allow if {{
    count([r | r := input.trust_check_results.target[_]; r.error.code == "{error_code}"]) == 0
}}
"#
    );
    world
        .surface_config
        .transit_shared_policy = Some(PolicyDefinitionFixture::new(
        policy_id,
        "BDD surface policy: deny a target Trust Check reporting a specific error code",
        &rego,
    ));
}

fn transit_point_config_mut<'a>(
    world: &'a mut SurfaceWorld,
    transit_point: &str,
) -> &'a mut SurfaceTransitPointConfig {
    let configured = world
        .surface_config
        .transit_point
        .as_mut()
        .unwrap_or_else(|| panic!("transit point '{transit_point}' must be configured before this step"));
    assert_eq!(
        configured.alias, transit_point,
        "configured Transit Point alias is '{}', not '{}'",
        configured.alias, transit_point
    );
    configured
}

#[given(expr = "transit point {string} maps managed-agent header {string} to A2A metadata field {string}")]
fn transit_point_maps_managed_agent_header_to_a2a_metadata_field(
    world: &mut SurfaceWorld,
    transit_point: String,
    header: String,
    field: String,
) {
    let configured = transit_point_config_mut(world, &transit_point);
    if let Some(existing) = configured
        .header_metadata_mapping
        .headers
        .iter_mut()
        .find(|entry| {
            entry
                .header
                .eq_ignore_ascii_case(&header)
        })
    {
        existing.field = field;
    } else {
        configured
            .header_metadata_mapping
            .headers
            .push(TransitPointHeaderMetadataMappingRow { header, field });
    }
}

#[given(regex = r#"^transit point \"([^\"]+)\" is configured to (strip|preserve) mapped headers before forwarding$"#)]
fn transit_point_configured_strip_or_preserve_mapped_headers(
    world: &mut SurfaceWorld,
    transit_point: String,
    mode: String,
) {
    let configured = transit_point_config_mut(world, &transit_point);
    configured
        .header_metadata_mapping
        .strip_mapped_headers = match mode.as_str() {
        "strip" => true,
        "preserve" => false,
        other => panic!("unsupported mapped-header forwarding mode '{other}'"),
    };
}

#[given(
    expr = "transit point {string} derives outbound managed-agent identity from mapped A2A metadata fields {string} and {string}"
)]
fn transit_point_derives_outbound_managed_agent_identity_from_mapped_metadata(
    world: &mut SurfaceWorld,
    transit_point: String,
    first_field: String,
    second_field: String,
) {
    let configured = transit_point_config_mut(world, &transit_point);
    configured.managed_identity = Some(TransitPointManagedIdentityConfig {
        fields: vec![first_field, second_field],
    });
}

#[given(expr = "the operator updates Transit Point {string} listen_path to {string}")]
async fn operator_updates_transit_point_listen_path(
    world: &mut SurfaceWorld,
    transit_point: String,
    new_path: String,
) {
    crate::steps::when::update_transit_point_listen_path(world, &transit_point, &new_path).await;
}

async fn install_replacement_mock(
    world: &mut SurfaceWorld,
    replacement_response: serde_json::Value,
) {
    crate::steps::when::ensure_gateway_running(world).await;

    let replacement_mock = crate::bdd_support::mock_server::MockServer::start(replacement_response.clone()).await;

    let infra = world
        .infra
        .as_mut()
        .expect("scenario infra must exist");
    infra.replacement_mock = Some(replacement_mock);

    world.set_secondary_target_response(replacement_response);
}

fn assert_surface_setup_created(
    world: &SurfaceWorld,
    context: &str,
) {
    let response = world
        .admin_response
        .as_ref()
        .expect("admin_response must be set after surface setup");
    assert_eq!(
        response.status, 201,
        "{} should create the surface, got status {} body {}",
        context, response.status, response.body
    );
}

#[given(expr = "the operator has attempted to create a surface for route {string} with invalid configuration")]
async fn operator_has_attempted_invalid_surface_create(
    world: &mut SurfaceWorld,
    route: String,
) {
    crate::steps::when::attempt_invalid_surface_create_for_route(world, &route).await;
}

pub(crate) fn assert_named_surface_targets_registered_managed_agent(
    world: &SurfaceWorld,
    surface_name: &str,
    agent_name: &str,
) {
    assert!(
        world
            .actors
            .surface_id(surface_name)
            .is_some(),
        "surface actor '{}' must have a recorded surface id before it can be updated",
        surface_name
    );
    world
        .actors
        .expect_target_kind(agent_name, TargetActorKind::ManagedAgent);
    let collaborator_key = world
        .actors
        .target_collaborator_key(agent_name);
    assert_eq!(
        collaborator_key, SECONDARY_COLLABORATOR_KEY,
        "managed agent '{}' is registered as collaborator '{}', but this step requires the alternate target collaborator",
        agent_name, collaborator_key
    );
}

#[given(expr = "the operator updates surface {string} to target managed agent {string}")]
async fn operator_updates_surface_to_target_managed_agent(
    world: &mut SurfaceWorld,
    surface_name: String,
    agent_name: String,
) {
    assert_named_surface_targets_registered_managed_agent(world, &surface_name, &agent_name);
    crate::steps::when::update_surface_to_alternate_target(world).await;
}

#[given("the operator has disabled the surface")]
async fn operator_has_disabled_the_surface(world: &mut SurfaceWorld) {
    crate::steps::when::disable_surface(world).await;
}

#[given("the operator has deleted the surface")]
async fn operator_has_deleted_the_surface(world: &mut SurfaceWorld) {
    crate::steps::when::delete_surface(world).await;
}

async fn create_surface_with_default_and_alternate_variants(
    world: &mut SurfaceWorld,
    route: &str,
    surface_name: Option<&str>,
    default_agent_name: Option<&str>,
    alternate_agent_name: Option<&str>,
) {
    let default_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "default-variant"
    });
    let alternate_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "alternate-variant"
    });

    if let Some(default_agent_name) = default_agent_name {
        world
            .actors
            .register_primary_target_with_kind(default_agent_name, TargetActorKind::ManagedAgent);
        world.register_primary_collaborator(default_agent_name, TargetActorKind::ManagedAgent);
    }
    if let Some(alternate_agent_name) = alternate_agent_name {
        world
            .actors
            .register_secondary_managed_agent(alternate_agent_name);
        world.register_secondary_collaborator(alternate_agent_name, TargetActorKind::ManagedAgent);
    }
    if let Some(surface_name) = surface_name {
        world
            .actors
            .register_surface_with_target(surface_name, "a2a", Some(route), default_agent_name);
    }

    world.surface_config.protocol = "a2a".to_string();
    crate::steps::when::configure_unseeded_route(world, route);
    set_primary_target_response(world, default_response);

    install_replacement_mock(world, alternate_response).await;

    let alternate_variant_target_url = crate::steps::when::get_alternate_target_url(world);

    let mut alternate_overrides = serde_json::json!({
        "target": {
            "endpoint": alternate_variant_target_url
        }
    });
    if let Some(auth) = &world
        .surface_config
        .alternate_variant_source_auth
    {
        alternate_overrides["access_point"] = serde_json::json!({
            "caller_authentication": {
                "methods": [caller_authentication_method_json(auth)],
            }
        });
    }
    if let Some(timeout_secs) = world
        .surface_config
        .alternate_variant_target_timeout_secs
    {
        alternate_overrides["target"]["networking"] = serde_json::json!({
            "timeout": { "request_secs": timeout_secs }
        });
    }
    if world
        .surface_config
        .alternate_variant_complete_mode
    {
        alternate_overrides["complete"] = serde_json::json!(true);
        if alternate_overrides
            .get("access_point")
            .is_none()
        {
            alternate_overrides["access_point"] = serde_json::json!({});
        }
    }
    if let Some(policy) = &world
        .surface_config
        .alternate_variant_inbound_policy
    {
        let ap = alternate_overrides
            .get_mut("access_point")
            .and_then(|v| v.as_object_mut());
        if let Some(ap) = ap {
            ap.insert(
                "inbound_policy".to_string(),
                serde_json::json!({ "policy_definition_id": policy.policy_definition_id }),
            );
        } else {
            alternate_overrides["access_point"] = serde_json::json!({
                "inbound_policy": { "policy_definition_id": policy.policy_definition_id },
            });
        }
    }
    if let Some(policy) = &world
        .surface_config
        .alternate_variant_target_policy
    {
        alternate_overrides["target"]["policy"] = serde_json::json!({
            "policy_definition_id": policy.policy_definition_id,
        });
    }

    let mut payload = crate::steps::when::build_primary_target_surface_payload(world, route).await;
    payload["name"] = serde_json::json!(surface_name.unwrap_or("bdd-variant-surface"));
    payload["description"] = serde_json::json!("BDD surface with default and alternate variants");
    if let Some(auth) = &world
        .surface_config
        .source_auth
    {
        payload["access_point"]["caller_authentication"] = serde_json::json!({
            "methods": [caller_authentication_method_json(auth)],
        });
    }
    if let Some(policy) = &world
        .surface_config
        .request_policy
    {
        payload["target"]["policy"] = serde_json::json!({
            "policy_definition_id": policy.id,
        });
    }
    payload["variants"] = serde_json::json!([
        {
            "id": "variant-default",
            "alias": "default",
            "name": "default",
            "enabled": true,
            "overrides": {}
        },
        {
            "id": "variant-alternate",
            "alias": "alternate",
            "name": "alternate",
            "enabled": true,
            "overrides": alternate_overrides
        }
    ]);
    payload["default_variant_id"] = serde_json::json!("variant-default");

    crate::steps::when::create_surface(world, payload).await;

    assert_surface_setup_created(world, "variant surface setup");
    if let Some(surface_name) = surface_name {
        remember_named_surface_under_test_id(world, surface_name);
    }
}

#[given(
    expr = "A2A surface {string} exists for route {string} with default managed agent {string} and alternate managed agent {string}"
)]
async fn named_surface_exists_for_route_with_default_and_alternate_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    default_agent_name: String,
    alternate_agent_name: String,
) {
    create_surface_with_default_and_alternate_variants(
        world,
        &route,
        Some(&surface_name),
        Some(&default_agent_name),
        Some(&alternate_agent_name),
    )
    .await;
}

#[given(
    expr = "MCP surface {string} exists for route {string} with default MCP server {string} and alternate MCP server {string}"
)]
async fn named_mcp_surface_exists_for_route_with_default_and_alternate_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    default_server_name: String,
    alternate_server_name: String,
) {
    create_mcp_surface_with_default_and_alternate_variants(
        world,
        &route,
        Some(&surface_name),
        Some(&default_server_name),
        Some(&alternate_server_name),
    )
    .await;
}

async fn create_mcp_surface_with_default_and_alternate_variants(
    world: &mut SurfaceWorld,
    route: &str,
    surface_name: Option<&str>,
    default_server_name: Option<&str>,
    alternate_server_name: Option<&str>,
) {
    let default_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "mcp-tools-list-alpha",
        "result": {
            "tools": [
                {
                    "name": "default-tool",
                    "description": "Default variant MCP tool.",
                    "inputSchema": { "type": "object" }
                }
            ]
        }
    });
    let alternate_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "mcp-tools-list-alpha",
        "result": {
            "tools": [
                {
                    "name": "alternate-tool",
                    "description": "Alternate variant MCP tool.",
                    "inputSchema": { "type": "object" }
                }
            ]
        }
    });

    if let Some(default_server_name) = default_server_name {
        world
            .actors
            .register_primary_target_with_kind(default_server_name, TargetActorKind::McpServer);
        world.register_primary_collaborator(default_server_name, TargetActorKind::McpServer);
    }
    if let Some(alternate_server_name) = alternate_server_name {
        world
            .actors
            .register_target_with_key(alternate_server_name, TargetActorKind::McpServer, SECONDARY_COLLABORATOR_KEY);
        world.register_secondary_collaborator(alternate_server_name, TargetActorKind::McpServer);
    }
    if let Some(surface_name) = surface_name {
        world
            .actors
            .register_surface_with_target(surface_name, "mcp", Some(route), default_server_name);
    }

    world.surface_config.protocol = "mcp".to_string();
    crate::steps::when::configure_unseeded_route(world, route);
    set_primary_target_response(world, default_response);

    install_replacement_mock(world, alternate_response).await;

    let alternate_variant_target_url = crate::steps::when::get_alternate_target_url(world);

    let mut alternate_overrides = serde_json::json!({
        "target": {
            "endpoint": alternate_variant_target_url
        }
    });
    if let Some(auth) = &world
        .surface_config
        .alternate_variant_source_auth
    {
        alternate_overrides["access_point"] = serde_json::json!({
            "caller_authentication": {
                "methods": [caller_authentication_method_json(auth)],
            }
        });
    }
    if let Some(timeout_secs) = world
        .surface_config
        .alternate_variant_target_timeout_secs
    {
        alternate_overrides["target"]["networking"] = serde_json::json!({
            "timeout": { "request_secs": timeout_secs }
        });
    }
    if let Some(policy) = &world
        .surface_config
        .alternate_variant_inbound_policy
    {
        let ap = alternate_overrides
            .get_mut("access_point")
            .and_then(|v| v.as_object_mut());
        if let Some(ap) = ap {
            ap.insert(
                "inbound_policy".to_string(),
                serde_json::json!({ "policy_definition_id": policy.policy_definition_id }),
            );
        } else {
            alternate_overrides["access_point"] = serde_json::json!({
                "inbound_policy": { "policy_definition_id": policy.policy_definition_id },
            });
        }
    }
    if let Some(policy) = &world
        .surface_config
        .alternate_variant_target_policy
    {
        alternate_overrides["target"]["policy"] = serde_json::json!({
            "policy_definition_id": policy.policy_definition_id,
        });
    }

    let mut payload = crate::steps::when::build_primary_target_surface_payload(world, route).await;
    payload["name"] = serde_json::json!(surface_name.unwrap_or("bdd-mcp-variant-surface"));
    payload["description"] = serde_json::json!("BDD MCP surface with default and alternate variants");
    payload["variants"] = serde_json::json!([
        {
            "id": "variant-default",
            "alias": "default",
            "name": "default",
            "enabled": true,
            "overrides": {}
        },
        {
            "id": "variant-alternate",
            "alias": "alternate",
            "name": "alternate",
            "enabled": true,
            "overrides": alternate_overrides
        }
    ]);
    payload["default_variant_id"] = serde_json::json!("variant-default");

    crate::steps::when::create_surface(world, payload).await;

    assert_surface_setup_created(world, "MCP variant surface setup");
    if let Some(surface_name) = surface_name {
        remember_named_surface_under_test_id(world, surface_name);
    }
}

async fn create_surface_with_disabled_dev_variant(
    world: &mut SurfaceWorld,
    route: &str,
    surface_name: Option<&str>,
    agent_name: Option<&str>,
) {
    if let Some(agent_name) = agent_name {
        register_primary_managed_agent(world, agent_name);
    }
    if let Some(surface_name) = surface_name {
        world
            .actors
            .register_surface_with_target(surface_name, "a2a", Some(route), agent_name);
    }

    let default_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "default-variant"
    });

    world.surface_config.protocol = "a2a".to_string();
    crate::steps::when::configure_unseeded_route(world, route);
    set_primary_target_response(world, default_response);

    let mut payload = crate::steps::when::build_primary_target_surface_payload(world, route).await;
    payload["name"] = serde_json::json!(surface_name.unwrap_or("bdd-disabled-variant-surface"));
    payload["description"] = serde_json::json!("BDD surface with a disabled dev variant");
    payload["variants"] = serde_json::json!([
        {
            "id": "variant-default",
            "alias": "default",
            "name": "default",
            "enabled": true,
            "overrides": {}
        },
        {
            "id": "variant-dev",
            "alias": "dev",
            "name": "dev",
            "enabled": false,
            "overrides": {}
        }
    ]);
    payload["default_variant_id"] = serde_json::json!("variant-default");

    crate::steps::when::create_surface(world, payload).await;

    assert_surface_setup_created(world, "disabled-variant surface setup");
    if let Some(surface_name) = surface_name {
        remember_named_surface_under_test_id(world, surface_name);
    }
}

#[given(expr = "A2A surface {string} exists for route {string} with managed agent {string} and a disabled dev variant")]
async fn named_surface_exists_for_route_with_disabled_dev_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    agent_name: String,
) {
    create_surface_with_disabled_dev_variant(world, &route, Some(&surface_name), Some(&agent_name)).await;
}

#[given(expr = "surfaces targeting managed agent {string} exist with different DID document publication settings")]
async fn surfaces_exist_for_did_document_publication_rules(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    managed_agent_available_as_target(world, agent_name);
    crate::steps::when::configure_unseeded_routes(world, "/published", &["/published", "/hidden", "/disabled"]);

    for (route, publish_to_did_document, status, name) in [
        ("/published", true, "active", "bdd-published-surface"),
        ("/hidden", false, "active", "bdd-hidden-surface"),
        ("/disabled", true, "disabled", "bdd-disabled-surface"),
    ] {
        let mut payload = crate::steps::when::build_primary_target_surface_payload(world, route).await;
        payload["name"] = serde_json::json!(name);
        payload["description"] = serde_json::json!(format!("BDD discovery surface for {}", route));
        payload["status"] = serde_json::json!(status);
        payload["access_point"]["publish_to_did_document"] = serde_json::json!(publish_to_did_document);

        crate::steps::when::create_surface(world, payload).await;

        assert_surface_setup_created(world, &format!("DID document surface setup for {}", route));
    }
}

async fn make_replacement_mock_agent_available(world: &mut SurfaceWorld) {
    assert!(
        world
            .created_surface_id
            .is_some(),
        "a surface must exist before configuring the alternate target"
    );

    let replacement_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "replacement-ok"
    });
    install_replacement_mock(world, replacement_response).await;
}

#[given(expr = "non-A2A managed agent {string} is available")]
fn named_non_a2a_managed_agent_is_available(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    register_primary_managed_agent(world, &agent_name);
}

#[given(expr = "A2A proxy {string} targets non-A2A managed agent {string}")]
fn a2a_proxy_targets_non_a2a_managed_agent(
    world: &mut SurfaceWorld,
    proxy_name: String,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    world
        .surface_config
        .a2a_proxy_target = Some(A2aProxyTargetFixture::new(
        proxy_name,
        "bdd-a2a-proxy-direct-line-secret",
        "bdd-direct-line-secret-value",
    ));
}

#[given(expr = "A2A surface {string} exists for route {string} targeting A2A proxy {string}")]
fn a2a_surface_exists_for_route_targeting_a2a_proxy(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    proxy_name: String,
) {
    let proxy = world
        .surface_config
        .a2a_proxy_target
        .as_ref()
        .unwrap_or_else(|| panic!("A2A proxy '{proxy_name}' must be configured before the surface"));
    assert_eq!(proxy.proxy_id, proxy_name, "surface target proxy name must match configured A2A proxy");
    world.surface_config.protocol = "a2a".to_string();
    world.surface_config.route = route.clone();
    world
        .surface_config
        .surface_name = Some(surface_name.clone());
    if !world
        .surface_config
        .registered_routes
        .contains(&route)
    {
        world
            .surface_config
            .registered_routes
            .push(route);
    }
    world
        .actors
        .register_surface_with_target(&surface_name, "a2a", Some(&world.surface_config.route), None);
}

#[given(expr = "A2A proxy {string} is disabled")]
fn a2a_proxy_is_disabled(
    world: &mut SurfaceWorld,
    proxy_name: String,
) {
    let proxy = world
        .surface_config
        .a2a_proxy_target
        .take()
        .unwrap_or_else(|| panic!("A2A proxy '{proxy_name}' must be configured before disabling it"));
    assert_eq!(proxy.proxy_id, proxy_name, "disabled proxy name must match configured A2A proxy");
    world
        .surface_config
        .a2a_proxy_target = Some(proxy.with_disabled());
}

#[given(expr = "non-A2A managed agent {string} does not answer before the proxy timeout")]
fn non_a2a_managed_agent_does_not_answer_before_proxy_timeout(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let proxy = world
        .surface_config
        .a2a_proxy_target
        .take()
        .unwrap_or_else(|| panic!("A2A proxy for non-A2A managed agent '{agent_name}' must be configured"));
    world
        .surface_config
        .a2a_proxy_target = Some(proxy.without_reply());
}

#[given(expr = "managed agent {string} is available")]
async fn named_managed_agent_is_available(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .register_secondary_managed_agent(&agent_name);
    world.register_secondary_collaborator(&agent_name, TargetActorKind::ManagedAgent);
    make_replacement_mock_agent_available(world).await;
}

#[given(expr = "an A2A surface targeting managed agent {string}")]
fn a2a_surface_targeting_managed_agent(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    register_primary_managed_agent(world, &agent_name);
    world.surface_config.protocol = "a2a".to_string();
}

#[given(expr = "managed agent {string} is failing with status {int}")]
fn managed_agent_is_failing_with_status(
    world: &mut SurfaceWorld,
    agent_name: String,
    status: u16,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let mut response = MockResponse::json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": format!("mock agent status {}", status)
        }
    }));
    response.status = status;
    world.set_primary_target_response(response);
}

#[given(expr = "managed agent {string} responds with header {string} set to {string}")]
fn managed_agent_responds_with_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    header_name: String,
    header_value: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    world
        .surface_config
        .custom_response_headers
        .insert(header_name, header_value);
}

#[given(expr = "managed agent {string} is unreachable")]
fn managed_agent_is_unreachable(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    // Point the surface at a port that will never accept connections.
    // We use a fixed port in the discard range that no service binds on loopback.
    // config_writer uses override_target_url in place of the mock URL.
    world
        .surface_config
        .override_target_url = Some("http://127.0.0.1:1".to_string());
}

#[given(expr = "the surface requires {string} source authentication")]
fn surface_requires_source_auth(
    world: &mut SurfaceWorld,
    auth_type: String,
) {
    match auth_type.as_str() {
        "JWT Bearer" => {
            world
                .surface_config
                .source_auth = Some(SurfaceSourceAuthConfig::JwtBearer(JwtSourceAuthConfig {
                jwks_url: String::new(),
                issuer: String::new(),
                audiences: Vec::new(),
            }));
        }
        "API Key" => {
            world
                .surface_config
                .source_auth = Some(SurfaceSourceAuthConfig::ApiKey(ApiKeySourceAuthConfig {
                header_name: "X-API-Key".to_string(),
                secret_id: "bdd-source-api-key".to_string(),
                valid_key: "bdd-valid-api-key".to_string(),
            }));
        }
        "API Key Provider" => {
            world
                .surface_config
                .source_auth = Some(SurfaceSourceAuthConfig::ApiKeyProvider(ApiKeyProviderSourceAuthConfig {
                header_name: "X-API-Key".to_string(),
                agent_id: "bdd-agent".to_string(),
                key_id: "bdd-provider-key".to_string(),
                client_id: "bdd-client".to_string(),
                valid_key: "bdd-valid-api-key".to_string(),
            }));
        }
        other => panic!("unsupported auth type: {}", other),
    }
}

#[given(expr = "the alternate variant requires {string} source authentication")]
fn alternate_variant_requires_source_auth(
    world: &mut SurfaceWorld,
    auth_type: String,
) {
    match auth_type.as_str() {
        "API Key" => {
            world
                .surface_config
                .alternate_variant_source_auth = Some(SurfaceSourceAuthConfig::ApiKey(ApiKeySourceAuthConfig {
                header_name: "X-API-Key".to_string(),
                secret_id: "bdd-alternate-variant-api-key".to_string(),
                valid_key: "bdd-valid-alternate-api-key".to_string(),
            }));
        }
        other => panic!("unsupported alternate-variant auth type: {}", other),
    }
}

#[given(expr = "the alternate variant lowers the target request timeout to {int} second")]
fn alternate_variant_lowers_target_request_timeout(
    world: &mut SurfaceWorld,
    seconds: u64,
) {
    world
        .surface_config
        .alternate_variant_target_timeout_secs = Some(seconds);
}

#[given(expr = "managed agent {string} is slow to respond by {int} seconds")]
async fn managed_agent_is_slow_to_respond(
    world: &mut SurfaceWorld,
    agent_name: String,
    seconds: u64,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    set_target_response_delay(world, &agent_name, seconds).await;
}

#[given(expr = "MCP server {string} is slow to respond by {int} seconds")]
async fn mcp_server_is_slow_to_respond(
    world: &mut SurfaceWorld,
    server_name: String,
    seconds: u64,
) {
    world
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response_delay(world, &server_name, seconds).await;
}

async fn set_target_response_delay(
    world: &mut SurfaceWorld,
    actor_name: &str,
    seconds: u64,
) {
    let delay_ms = seconds
        .checked_mul(1000)
        .expect("response delay overflow");
    world
        .mock_for_target(actor_name)
        .set_response_delay(delay_ms, delay_ms)
        .await;
}

#[given(expr = "the alternate variant is declared in complete mode")]
fn alternate_variant_is_declared_in_complete_mode(world: &mut SurfaceWorld) {
    world
        .surface_config
        .alternate_variant_complete_mode = true;
}

#[given(expr = "the alternate variant uses inbound policy {string}")]
fn alternate_variant_uses_inbound_policy(
    world: &mut SurfaceWorld,
    policy_name: String,
) {
    let fixture = match policy_name.as_str() {
        "deny-all" => VariantInboundPolicyFixture::deny_all(),
        "deny-unverified" => VariantInboundPolicyFixture::deny_unverified_source_auth(),
        other => panic!("unsupported alternate-variant inbound policy: {}", other),
    };
    world
        .surface_config
        .alternate_variant_inbound_policy = Some(fixture);
}

#[given(expr = "the alternate variant uses target policy {string}")]
fn alternate_variant_uses_target_policy(
    world: &mut SurfaceWorld,
    policy_label: String,
) {
    let fixture = match policy_label.as_str() {
        "deny-all" => VariantTargetPolicyFixture::deny_all(),
        other => panic!("unsupported alternate-variant target policy label: {}", other),
    };
    world
        .surface_config
        .alternate_variant_target_policy = Some(fixture);
}

#[given(expr = "the MCP surface enforces a tool policy allowing only tool {string}")]
fn mcp_surface_enforces_tool_policy(
    world: &mut SurfaceWorld,
    allowed_tool: String,
) {
    let rego = build_mcp_tool_allow_policy(&allowed_tool);
    world
        .surface_config
        .mcp_tool_policy = Some(McpToolPolicyFixture {
        allowed_tool,
        policy_definition_id: "bdd-mcp-tool-policy".to_string(),
        rego,
    });
}

#[given(expr = "the MCP surface enforces a wildcard default tool policy that allows all tools")]
fn mcp_surface_enforces_wildcard_allow_policy(world: &mut SurfaceWorld) {
    world
        .surface_config
        .mcp_wildcard_tool_policy = Some(McpWildcardToolPolicyFixture {
        policy_definition_id: "bdd-mcp-wildcard-allow-policy".to_string(),
        rego: build_mcp_tool_allow_all_policy(),
    });
}

#[given(expr = "the MCP surface enforces a wildcard default tool policy that denies all tools")]
fn mcp_surface_enforces_wildcard_deny_policy(world: &mut SurfaceWorld) {
    world
        .surface_config
        .mcp_wildcard_tool_policy = Some(McpWildcardToolPolicyFixture {
        policy_definition_id: "bdd-mcp-wildcard-deny-policy".to_string(),
        rego: build_mcp_tool_deny_all_policy(),
    });
}

#[given(expr = "the MCP surface enforces a tool policy allowing only tool {string} with a wildcard deny default")]
fn mcp_surface_enforces_tool_policy_with_wildcard_deny(
    world: &mut SurfaceWorld,
    allowed_tool: String,
) {
    let rego = build_mcp_tool_allow_policy(&allowed_tool);
    world
        .surface_config
        .mcp_tool_policy = Some(McpToolPolicyFixture {
        allowed_tool,
        policy_definition_id: "bdd-mcp-tool-policy".to_string(),
        rego,
    });
    world
        .surface_config
        .mcp_wildcard_tool_policy = Some(McpWildcardToolPolicyFixture {
        policy_definition_id: "bdd-mcp-wildcard-deny-policy".to_string(),
        rego: build_mcp_tool_deny_all_policy(),
    });
}

#[given(expr = "the MCP surface gates out tool {string}")]
fn mcp_surface_gates_out_tool(
    world: &mut SurfaceWorld,
    tool: String,
) {
    world
        .surface_config
        .mcp_tool_gating = Some(serde_json::json!({
        "gates": [{
            "id": "bdd-gate-deny",
            "action": { "effect": "deny", "patterns": [format!("^{tool}$")] }
        }]
    }));
}

#[given(expr = "the MCP surface gates out tool {string} when the caller's agent context is present")]
fn mcp_surface_gates_out_tool_when_agent_context_present(
    world: &mut SurfaceWorld,
    tool: String,
) {
    let rego = "package surface.policy\n\ndefault allow := false\n\nallow if {\n    input.agent\n}\n".to_string();
    let policy =
        RequestPolicyFixture::new("bdd-mcp-gate-agent-present", "BDD MCP tool gate condition on input.agent", rego);
    world
        .surface_config
        .mcp_tool_gating = Some(serde_json::json!({
        "gates": [{
            "id": "bdd-gate-deny-conditional",
            "condition_policy_definition_id": policy.id,
            "action": { "effect": "deny", "patterns": [format!("^{tool}$")] }
        }]
    }));
    world
        .surface_config
        .mcp_tool_gating_condition_policy = Some(policy);
}

#[given(expr = "the MCP surface gating allows only tool {string}")]
fn mcp_surface_gating_allows_only_tool(
    world: &mut SurfaceWorld,
    tool: String,
) {
    world
        .surface_config
        .mcp_tool_gating = Some(serde_json::json!({
        "default_effect": "deny",
        "gates": [{
            "id": "bdd-gate-allow",
            "action": { "effect": "allow", "patterns": [format!("^{tool}$")] }
        }]
    }));
}

#[given(expr = "the MCP surface has a request policy that denies all requests")]
fn mcp_surface_has_deny_all_request_policy(world: &mut SurfaceWorld) {
    let rego = "package surface.policy\n\ndefault allow := false\n".to_string();
    world
        .surface_config
        .request_policy =
        Some(RequestPolicyFixture::new("bdd-mcp-deny-all", "BDD deny-all surface policy for MCP proxy", rego));
}

#[given(expr = "the MCP surface has a request policy that allows all requests")]
fn mcp_surface_has_allow_all_request_policy(world: &mut SurfaceWorld) {
    let rego = "package surface.policy\n\ndefault allow := true\n".to_string();
    world
        .surface_config
        .request_policy =
        Some(RequestPolicyFixture::new("bdd-mcp-allow-all", "BDD allow-all surface policy for MCP proxy", rego));
}

#[given(expr = "the MCP proxy backing REST API {string} is disabled")]
fn mcp_proxy_backing_rest_api_is_disabled(
    world: &mut SurfaceWorld,
    _rest_api_name: String,
) {
    let target = world
        .surface_config
        .mcp_proxy_target
        .as_mut()
        .expect("background must register an MCP proxy target before it can be disabled");
    target.disabled = true;
}

fn configure_target_auth_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
    secret_value: String,
    header_name: String,
) {
    world
        .surface_config
        .target_auth = Some(SurfaceTargetAuthConfig {
        secret_id,
        header_name,
        header_format: "{value}".to_string(),
        fallback: "reject".to_string(),
        secret_value: Some(secret_value),
    });
}

#[given(expr = "the surface injects target authentication from secret {string} with value {string} as header {string}")]
fn surface_injects_target_auth_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
    secret_value: String,
    header_name: String,
) {
    configure_target_auth_secret(world, secret_id, secret_value, header_name);
}

fn configure_missing_target_auth(
    world: &mut SurfaceWorld,
    secret_id: String,
    header_name: String,
    fallback: String,
) {
    world
        .surface_config
        .target_auth = Some(SurfaceTargetAuthConfig {
        secret_id,
        header_name,
        header_format: "{value}".to_string(),
        fallback,
        secret_value: None,
    });
}

#[given(
    expr = "the surface injects target authentication from missing secret {string} as header {string} with fallback {string}"
)]
fn surface_injects_missing_target_auth(
    world: &mut SurfaceWorld,
    secret_id: String,
    header_name: String,
    fallback: String,
) {
    configure_missing_target_auth(world, secret_id, header_name, fallback);
}

#[given("the surface has managed identity enabled")]
fn surface_has_managed_identity(world: &mut SurfaceWorld) {
    world
        .surface_config
        .managed_identity = true;
}

#[given("the surface has managed identity with strip raw metadata enabled")]
fn surface_has_managed_identity_strip_raw(world: &mut SurfaceWorld) {
    world
        .surface_config
        .managed_identity = true;
    world
        .surface_config
        .managed_identity_strip_raw = true;
}

#[given(expr = "the surface has a did:webvh managed identity with agentDNA {string}")]
fn surface_has_didwebvh_identity_with_agent_dna(
    world: &mut SurfaceWorld,
    agent_dna: String,
) {
    let identity = DidWebVhIdentityFixture::new("did:webvh:example.com:bdd-managed-agent").with_agent_dna(agent_dna);
    world
        .surface_config
        .didwebvh_identity = Some(identity);
}

#[given("the surface has an explicit inbound identity slot for MCP")]
fn surface_has_mcp_inbound_identity(world: &mut SurfaceWorld) {
    world
        .surface_config
        .mcp_inbound_identity = true;
}

#[given("the surface has an explicit inbound identity slot for MCP with strip raw metadata enabled")]
fn surface_has_mcp_inbound_identity_strip_raw(world: &mut SurfaceWorld) {
    world
        .surface_config
        .mcp_inbound_identity = true;
    world
        .surface_config
        .mcp_inbound_identity_strip_raw = true;
}

#[given(expr = "the surface injects custom metadata key {string} value {string} into {string}")]
fn surface_injects_custom_metadata(
    world: &mut SurfaceWorld,
    key: String,
    value: String,
    injection_target: String,
) {
    world
        .surface_config
        .custom_metadata = Some(crate::world::SurfaceCustomMetadataConfig { key, value, injection_target });
}

fn configure_mcp_surface_protocol(world: &mut SurfaceWorld) {
    world.surface_config.protocol = "mcp".to_string();
}

#[given(expr = "operator {string} has the {string} role")]
async fn operator_has_role(
    world: &mut SurfaceWorld,
    operator: String,
    role: String,
) {
    crate::steps::when::ensure_gateway_running(world).await;
    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .gateway_port;
    let client = AdminApiClient::new(gateway_port, TEST_AUTH_TOKEN, &operator);
    client
        .bootstrap_test_session_with_role(&role)
        .await
        .expect("test-support auth login should succeed");
    world
        .operator_roles
        .insert(operator.clone(), role);
    world
        .operator_clients
        .insert(operator, client);
}

#[given("the VP Audit Log contains a policy decision")]
async fn vp_audit_log_contains_policy_decision(world: &mut SurfaceWorld) {
    named_mcp_surface_targeting_mock(world, "alpha".to_string(), "bravo".to_string());
    mcp_server_returns_tool_result(world, "bravo".to_string());
    surface_requires_source_auth(world, "JWT Bearer".to_string());
    mcp_surface_has_allow_all_request_policy(world);
    enable_policy_audit_category(world).await;
    crate::steps::when::caller_invokes_mcp_tool_with_valid_token(
        world,
        "alice".to_string(),
        "schedule_meeting".to_string(),
    )
    .await;
    wait_for_audit_events(world, "/v1/audit?limit=100").await;
}

async fn enable_policy_audit_category(world: &mut SurfaceWorld) {
    crate::steps::when::ensure_admin_session(world).await;
    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    client
        .send_recorded_json(
            reqwest::Method::POST,
            "/v1/settings",
            Some(&serde_json::json!({
                "audit_enabled": true,
                "audit_categories": {
                    "policies": true,
                    "trust_checks": true,
                    "identity": true
                }
            })),
        )
        .await
        .expect("enable audit categories through admin API");
}

#[given("trust check audit is enabled")]
async fn trust_check_audit_is_enabled(world: &mut SurfaceWorld) {
    enable_policy_audit_category(world).await;
}

#[given(
    expr = "the Credential Delegation Audit Log contains a token injection for caller {string} with email {string} and name {string}"
)]
async fn credential_delegation_audit_log_contains_token_injection_for_caller(
    world: &mut SurfaceWorld,
    caller: String,
    email: String,
    name: String,
) {
    named_mcp_surface_targeting_mock(world, "alpha".to_string(), "bravo".to_string());
    mcp_server_returns_tool_result(world, "bravo".to_string());
    surface_requires_source_auth(world, "JWT Bearer".to_string());
    surface_has_mcp_inbound_identity(world);
    surface_requires_oauth_delegated_credentials(world, "calendar".to_string());
    world.caller_claims.insert(
        caller.clone(),
        serde_json::Map::from_iter([
            ("email".to_string(), serde_json::Value::String(email)),
            ("name".to_string(), serde_json::Value::String(name)),
        ]),
    );

    caller_has_started_oauth_consent(world, caller.clone(), "calendar".to_string()).await;
    oauth_provider_ready_to_exchange_code(world, "calendar".to_string()).await;
    caller_has_completed_oauth_consent(world, caller.clone(), "calendar".to_string()).await;
    caller_has_invoked_mcp_tool_with_valid_token_and_identity(world, caller, "schedule_meeting".to_string()).await;
    wait_for_audit_events(world, "/v1/delegation-audit?page_size=100").await;
}

#[given(expr = "an API-key delegated credential was injected for caller {string}")]
async fn api_key_delegated_credential_was_injected(
    world: &mut SurfaceWorld,
    caller: String,
) {
    named_mcp_surface_targeting_mock(world, "alpha".to_string(), "bravo".to_string());
    mcp_server_returns_tool_result(world, "bravo".to_string());
    surface_requires_source_auth(world, "JWT Bearer".to_string());
    surface_has_mcp_inbound_identity(world);
    surface_requires_api_key_delegated_credentials(world, "maps".to_string());
    configure_target_auth_secret(
        world,
        "bdd-target-auth-secret".to_string(),
        "bdd-target-auth-secret-value".to_string(),
        "x-target-api-key".to_string(),
    );

    caller_has_invoked_mcp_tool_with_valid_token_and_identity(world, caller, "lookup_place".to_string()).await;
    wait_for_audit_events(world, "/v1/delegation-audit?page_size=100").await;
}

async fn wait_for_audit_events(
    world: &mut SurfaceWorld,
    path: &str,
) {
    crate::steps::when::ensure_admin_session(world).await;
    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let mut last_body = None;
    for _ in 0..10 {
        let response = client
            .send_recorded_json::<serde_json::Value>(reqwest::Method::GET, path, None)
            .await
            .expect("audit setup read should return an HTTP response");
        let has_events = response
            .body
            .get("events")
            .and_then(|events| events.as_array())
            .is_some_and(|events| !events.is_empty());
        if has_events {
            return;
        }
        last_body = Some(response.body);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("audit setup did not produce events at {path}; last response body: {last_body:?}");
}

#[given(expr = "MCP surface {string} targets MCP server {string}")]
fn named_mcp_surface_targeting_mock(
    world: &mut SurfaceWorld,
    surface_name: String,
    server_name: String,
) {
    world
        .actors
        .register_primary_target_with_kind(&server_name, TargetActorKind::McpServer);
    world.register_primary_collaborator(&server_name, TargetActorKind::McpServer);
    world
        .surface_config
        .surface_name = Some(surface_name.clone());
    let route = world
        .surface_config
        .route
        .clone();
    world
        .actors
        .register_surface_with_target(&surface_name, "mcp", Some(&route), Some(&server_name));
    world
        .actors
        .record_surface_id(&surface_name, "bdd-surface");
    configure_mcp_surface_protocol(world);
}

#[given(expr = "REST API {string} exposes a Weather OpenAPI")]
fn rest_api_exposes_weather_openapi(
    world: &mut SurfaceWorld,
    rest_api_name: String,
) {
    world
        .actors
        .register_primary_target_with_kind(&rest_api_name, TargetActorKind::RestApi);
    world.register_primary_collaborator(&rest_api_name, TargetActorKind::RestApi);
    set_primary_target_response(world, serde_json::json!({"city": "Paris", "temperature": 20, "conditions": "Sunny"}));
}

#[given(
    expr = "MCP surface {string} exists for route {string} targeting an MCP proxy endpoint backed by REST API {string}"
)]
fn mcp_surface_targeting_mcp_proxy_backed_by_rest_api(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    rest_api_name: String,
) {
    world
        .actors
        .register_primary_target_with_kind(&rest_api_name, TargetActorKind::RestApi);
    world.register_primary_collaborator(&rest_api_name, TargetActorKind::RestApi);
    world
        .surface_config
        .surface_name = Some(surface_name.clone());
    world.surface_config.route = route.clone();
    world
        .surface_config
        .registered_routes = vec![route.clone()];
    world
        .surface_config
        .mcp_proxy_target = Some(McpProxyTargetFixture::new(&rest_api_name).with_openapi_spec(WEATHER_OPENAPI_SPEC));
    world
        .actors
        .register_surface_with_target(&surface_name, "mcp", Some(&route), Some(&rest_api_name));
    world
        .actors
        .record_surface_id(&surface_name, "bdd-surface");
    configure_mcp_surface_protocol(world);
}

#[given(expr = "MCP server {string} publishes a tool catalog")]
fn mcp_server_publishes_tool_catalog(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    world
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "server-placeholder",
        "result": {
            "tools": [
                {
                    "name": "get_news",
                    "description": "Returns current news for a topic.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topic": {"type": "string"}
                        },
                        "required": ["topic"]
                    }
                },
                {
                    "name": "summarize",
                    "description": "Summarizes supplied text.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string"}
                        },
                        "required": ["text"]
                    }
                }
            ]
        }
    });
    set_target_response_for_actor(world, &server_name, response);
}

fn set_mcp_server_identity_response(world: &mut SurfaceWorld) {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "news results"}],
            "_meta": {
                "serverIdentity": {
                    "softwareInfo": { "name": "mcp-server", "version": "1.0" },
                    "cloudProvider": "local"
                }
            }
        }
    });
    set_primary_target_response(world, response);
}

fn set_mcp_schema_invalid_server_identity_response(world: &mut SurfaceWorld) {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "news results"}],
            "_meta": {
                "serverIdentity": {
                    "softwareInfo": { "name": 42, "version": true },
                    "cloudProvider": 999
                }
            }
        }
    });
    set_primary_target_response(world, response);
}

#[given(expr = "MCP server {string} includes an agent-identity extension in responses")]
fn named_mcp_server_response_has_identity(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    world
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_mcp_server_identity_response(world);
}

#[given(expr = "MCP server {string} returns a schema-invalid serverIdentity payload")]
fn named_mcp_server_response_has_schema_invalid_identity(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    world
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_mcp_schema_invalid_server_identity_response(world);
}

#[given(
    expr = "A2A surface {string} has response policy {string} that allows inbound responses whose content-type is {string}"
)]
async fn surface_has_response_policy_allowing_content_type(
    world: &mut SurfaceWorld,
    surface_name: String,
    policy_name: String,
    allowed_content_type: String,
) {
    let policy_text = build_surface_response_content_type_policy(&allowed_content_type);

    let policy_fixture = PolicyDefinitionFixture {
        id: policy_name.clone(),
        description: policy_name.clone(),
        rego: policy_text.clone(),
    };

    add_bootstrapped_policy_to_surface(world, surface_name, policy_name, policy_fixture, true).await;
}

#[given(expr = "managed agent {string} response contains the agent-identity extension")]
fn managed_agent_response_has_identity(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "managed-agent", "version": "2.0" },
                    "cloudProvider": "local"
                }
            }
        }
    });
    set_primary_target_response(world, response);
}

#[given(expr = "managed agent {string} publishes the agent-identity extension on its agent card")]
fn managed_agent_publishes_agent_card_with_identity(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let agent_card = serde_json::json!({
        "name": "test-agent",
        "url": "http://mock.local",
        "version": "1.0.0",
        "capabilities": {
            "extensions": [
                {
                    "uri": AGENT_IDENTITY_URI,
                    "params": {
                        "softwareInfo": { "name": "managed-agent", "version": "2.0" },
                        "cloudProvider": "local"
                    }
                }
            ]
        }
    });
    set_primary_target_response(world, agent_card);
}

fn build_mcp_initialize_fixture(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2025-03-26",
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {}
            },
            "serverInfo": {
                "name": "mock-mcp-server",
                "version": "1.2.3"
            }
        }
    })
}

fn build_mcp_tools_call_fixture(id: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [
                { "type": "text", "text": "tool output" }
            ],
            "isError": false
        }
    })
}

#[given(expr = "MCP server {string} supports initialization")]
fn mcp_server_supports_initialization(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    world
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response_for_actor(world, &server_name, build_mcp_initialize_fixture(serde_json::json!(1)));
}

#[given(expr = "MCP server {string} supports tool invocation")]
#[given(expr = "MCP server {string} returns a tool result without serverIdentity")]
fn mcp_server_returns_tool_result(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    world
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response_for_actor(world, &server_name, build_mcp_tools_call_fixture(serde_json::json!(1)));
}

#[given(expr = "the surface requires delegated credentials from OAuth provider {string}")]
fn surface_requires_oauth_delegated_credentials(
    world: &mut SurfaceWorld,
    provider: String,
) {
    world
        .surface_config
        .credential_delegation = Some(SurfaceCredentialDelegationConfig {
        provider_id: provider,
        provider_kind: CredentialProviderKind::OAuth2AuthorizationCode,
        required_tool: None,
        inject_as: DelegatedCredentialInjection::BearerHeader,
        scopes: vec!["calendar.read".to_string(), "calendar.write".to_string()],
    });
}

#[given(expr = "the surface requires delegated credentials from OAuth provider {string} only for MCP tool {string}")]
fn surface_requires_oauth_delegated_credentials_for_tool(
    world: &mut SurfaceWorld,
    provider: String,
    tool: String,
) {
    surface_requires_oauth_delegated_credentials(world, provider);
    delegation_config_mut(world).required_tool = Some(tool);
}

#[given(expr = "the surface requires delegated credentials from API-key provider {string}")]
fn surface_requires_api_key_delegated_credentials(
    world: &mut SurfaceWorld,
    provider: String,
) {
    world
        .surface_config
        .credential_delegation = Some(SurfaceCredentialDelegationConfig {
        provider_id: provider.clone(),
        provider_kind: CredentialProviderKind::ApiKey {
            secret_id: format!("bdd-{provider}-api-key"),
            secret_value: "bdd-delegated-api-key".to_string(),
        },
        required_tool: None,
        inject_as: DelegatedCredentialInjection::BearerHeader,
        scopes: Vec::new(),
    });
}

#[given(expr = "the surface injects delegated credentials from OAuth provider {string} as header {string}")]
fn surface_injects_delegated_credentials_as_header(
    world: &mut SurfaceWorld,
    _provider: String,
    header: String,
) {
    delegation_config_mut(world).inject_as = DelegatedCredentialInjection::CustomHeader {
        name: header,
        format: "Bearer {value}".to_string(),
    };
}

#[given(expr = "the surface injects delegated credentials from OAuth provider {string} into MCP metadata key {string}")]
fn surface_injects_delegated_credentials_into_meta(
    world: &mut SurfaceWorld,
    _provider: String,
    field: String,
) {
    delegation_config_mut(world).inject_as = DelegatedCredentialInjection::Meta { field };
}

#[given(expr = "the surface accepts JWT audience {string}")]
fn surface_accepts_jwt_audience(
    world: &mut SurfaceWorld,
    audience: String,
) {
    match world
        .surface_config
        .source_auth
        .as_mut()
        .expect("JWT source authentication must be configured before setting audiences")
    {
        SurfaceSourceAuthConfig::JwtBearer(config) => config.audiences = vec![audience],
        _ => panic!("JWT source authentication must be configured before setting audiences"),
    }
}

#[given(expr = "the surface has an explicit inbound identity slot for MCP requiring selected identity field {string}")]
fn surface_has_inbound_identity_requiring_selected_field(
    world: &mut SurfaceWorld,
    field: String,
) {
    world
        .surface_config
        .mcp_inbound_identity = true;
    world
        .surface_config
        .required_mcp_identity_field = Some(field.clone());
    world
        .surface_config
        .constrained_mcp_identity_field = Some(field);
}

#[given(expr = "caller {string} has no delegated credentials for OAuth provider {string}")]
fn caller_has_no_delegated_credentials(
    _world: &mut SurfaceWorld,
    _caller: String,
    _provider: String,
) {
}

#[given(expr = "OAuth provider {string} is ready to exchange an authorization code for delegated credentials")]
async fn oauth_provider_ready_to_exchange_code(
    world: &mut SurfaceWorld,
    _provider: String,
) {
    crate::steps::when::ensure_gateway_running(world).await;
    let oauth = world
        .infra
        .as_ref()
        .and_then(|infra| {
            infra
                .replacement_mock
                .as_ref()
        })
        .expect("OAuth provider mock must be running");
    oauth
        .set_response(MockResponse::json(serde_json::json!({
            "access_token": "bdd-delegated-access-token",
            "refresh_token": "bdd-delegated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "calendar.read calendar.write"
        })))
        .await;
}

#[given(expr = "caller {string} has been asked to complete OAuth consent for provider {string}")]
async fn caller_has_been_asked_to_complete_oauth_consent(
    world: &mut SurfaceWorld,
    caller: String,
    provider: String,
) {
    caller_has_started_oauth_consent(world, caller, provider).await;
}

#[given(expr = "caller {string} has completed OAuth consent for provider {string}")]
async fn caller_has_completed_oauth_consent(
    world: &mut SurfaceWorld,
    _caller: String,
    provider: String,
) {
    crate::steps::when::oauth_provider_redirects_back_with_valid_code(world, provider).await;
}

#[given(expr = "caller {string} has invoked MCP tool {string} with a valid token and caller Agent identity {string}")]
async fn caller_has_invoked_mcp_tool_with_valid_token_and_agent_identity(
    world: &mut SurfaceWorld,
    caller: String,
    tool_name: String,
    identity: String,
) {
    crate::steps::when::caller_invokes_mcp_tool_with_valid_token_and_identity_field(
        world,
        caller,
        tool_name,
        "softwareInfo.name".to_string(),
        identity,
    )
    .await;
}

#[given(expr = "caller {string} has invoked MCP tool {string} with a valid token and a valid inbound identity payload")]
async fn caller_has_invoked_mcp_tool_with_valid_token_and_identity(
    world: &mut SurfaceWorld,
    caller: String,
    tool_name: String,
) {
    crate::steps::when::caller_invokes_mcp_tool_with_valid_token_and_identity(world, caller, tool_name).await;
}

#[given(expr = "caller {string} has started OAuth consent for provider {string}")]
async fn caller_has_started_oauth_consent(
    world: &mut SurfaceWorld,
    caller: String,
    _provider: String,
) {
    if world
        .surface_config
        .mcp_inbound_identity
    {
        crate::steps::when::caller_invokes_mcp_tool_with_valid_token_and_identity(
            world,
            caller,
            "schedule_meeting".to_string(),
        )
        .await;
    } else {
        crate::steps::when::caller_invokes_mcp_tool_with_valid_token(world, caller, "schedule_meeting".to_string())
            .await;
    }
}

#[given("the caller's delegated credentials have expired")]
fn caller_delegated_credentials_have_expired(world: &mut SurfaceWorld) {
    expire_delegation_tokens(world);
}

#[given(expr = "OAuth provider {string} is ready to refresh delegated credentials")]
async fn oauth_provider_ready_to_refresh(
    world: &mut SurfaceWorld,
    _provider: String,
) {
    oauth_provider_ready_to_exchange_code(world, _provider).await;
}

#[given(expr = "OAuth provider {string} rejects delegated credential refresh")]
async fn oauth_provider_rejects_refresh(
    world: &mut SurfaceWorld,
    _provider: String,
) {
    crate::steps::when::ensure_gateway_running(world).await;
    let oauth = world
        .infra
        .as_ref()
        .and_then(|infra| {
            infra
                .replacement_mock
                .as_ref()
        })
        .expect("OAuth provider mock must be running");
    oauth
        .set_response(MockResponse {
            status: 400,
            headers: std::collections::HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: serde_json::json!({"error": "invalid_grant"}),
            stream: crate::bdd_support::mock_server::MockStream::None,
        })
        .await;
}

#[given(expr = "caller {string} has completed an earlier MCP tool call using those delegated credentials")]
async fn caller_completed_earlier_tool_call(
    world: &mut SurfaceWorld,
    caller: String,
) {
    crate::steps::when::caller_invokes_mcp_tool_with_valid_token(world, caller, "schedule_meeting".to_string()).await;
}

#[given(expr = "the caller has invoked MCP tool {string} with inbound identity field {string} set to {string}")]
async fn caller_has_invoked_mcp_tool_with_inbound_identity_field(
    world: &mut SurfaceWorld,
    tool_name: String,
    field: String,
    value: String,
) {
    crate::steps::when::caller_invokes_mcp_tool_with_identity_field(world, tool_name, field, value).await;
}

#[given(expr = "the caller has invoked MCP tool {string} with a valid inbound identity payload")]
async fn caller_has_invoked_mcp_tool_with_valid_inbound_identity(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    crate::steps::when::invoke_mcp_tool_with_identity_region(world, &tool_name, "eu-west-1").await;
}

#[given(expr = "the operator has created an MCP onboarding endpoint")]
fn operator_has_created_mcp_onboarding_endpoint(world: &mut SurfaceWorld) {
    world.surface_config.protocol = "mcp".to_string();
}

#[given(expr = "the operator has captured an MCP identity schema with field {string}")]
fn operator_has_captured_mcp_identity_schema_with_field(
    world: &mut SurfaceWorld,
    field: String,
) {
    world.captured_mcp_identity_schema = Some(mcp_identity_schema_with_field(&field, false));
}

#[given(expr = "the operator selects identity field {string} in the captured schema")]
fn operator_selects_identity_field_in_captured_schema(
    world: &mut SurfaceWorld,
    field: String,
) {
    let schema = world
        .captured_mcp_identity_schema
        .as_mut()
        .expect("captured MCP identity schema must exist before selecting a field");
    select_identity_schema_field(schema, &field);
}

#[given(expr = "MCP surface {string} uses the selected captured schema for inbound identity")]
fn mcp_surface_uses_selected_captured_schema_for_inbound_identity(
    world: &mut SurfaceWorld,
    _surface: String,
) {
    let schema = world
        .captured_mcp_identity_schema
        .clone()
        .expect("captured MCP identity schema must exist before configuring inbound identity");
    world
        .surface_config
        .mcp_inbound_identity = true;
    world
        .surface_config
        .mcp_identity_payload_schema = Some(schema);
}

fn delegation_config_mut(world: &mut SurfaceWorld) -> &mut SurfaceCredentialDelegationConfig {
    world
        .surface_config
        .credential_delegation
        .as_mut()
        .expect("surface delegated credential requirement must be configured")
}

fn expire_delegation_tokens(world: &SurfaceWorld) {
    let storage_dir = world
        .infra
        .as_ref()
        .expect("gateway must be running")
        ._temp_dir
        .path()
        .join("_storage/delegation_vault");
    for entry in std::fs::read_dir(&storage_dir).expect("read delegation vault directory") {
        let path = entry
            .expect("delegation vault entry")
            .path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            != Some("json")
        {
            continue;
        }
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read delegation token fixture"))
                .expect("delegation token should be JSON");
        value["expires_at"] = serde_json::json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
        std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).expect("write expired delegation token");
    }
}

#[given(expr = "gateway {string}")]
fn a_gateway(
    world: &mut SurfaceWorld,
    gateway_name: String,
) {
    let (inbound_port, reserved_inbound_port) = reserve_free_port(&format!("gateway-{gateway_name}-inbound"));
    world
        .runtimes
        .reserved_ports
        .insert(inbound_port, reserved_inbound_port);

    let gateway_fixture = GatewayBootstrapFixture {
        key: gateway_name.clone(),
        gateway_port: inbound_port,
        outbound_listener_port: None,
        root_dir: Some(
            world
                .temp_dir
                .path()
                .join(&gateway_name),
        ),
        log_level: if world.debug {
            Some(Level::Debug)
        } else {
            Some(Level::Info)
        },
        policy_opa_entry: None,
        terms_enabled: false,
        affinidi_terms_url: None,
        identity_route_key: "api".to_string(),
        bootstrap_surfaces: vec![],
        agent_surfaces: HashMap::new(),
        secrets: HashMap::new(),
        policies: HashMap::new(),
        jwt_strategies: HashMap::new(),
        api_key_providers: HashMap::new(),
        credential_providers: HashMap::new(),
        mcp_proxies: HashMap::new(),
        a2a_proxies: HashMap::new(),
    };
    world
        .actors
        .put_gateway_instance(GatewayInstanceActor {
            key: gateway_name.clone(),
            index: 0,
            fixture: Some(gateway_fixture),
        });
}

#[given(expr = "gateway {string} with outbound listener")]
fn a_gateway_with_outbound_listener(
    world: &mut SurfaceWorld,
    gateway_name: String,
) {
    let (inbound_port, reserved_inbound_port) = reserve_free_port(&format!("gateway-{gateway_name}-inbound"));
    let (outbound_port, reserved_outbound_port) = reserve_free_port(&format!("gateway-{gateway_name}-outbound"));
    world
        .runtimes
        .reserved_ports
        .insert(inbound_port, reserved_inbound_port);
    world
        .runtimes
        .reserved_ports
        .insert(outbound_port, reserved_outbound_port);

    let gateway_fixture = GatewayBootstrapFixture {
        key: gateway_name.clone(),
        gateway_port: inbound_port,
        outbound_listener_port: Some(outbound_port),
        root_dir: Some(
            world
                .temp_dir
                .path()
                .join(&gateway_name),
        ),
        log_level: if world.debug {
            Some(Level::Debug)
        } else {
            Some(Level::Info)
        },
        policy_opa_entry: None,
        terms_enabled: false,
        affinidi_terms_url: None,
        identity_route_key: "api".to_string(),
        bootstrap_surfaces: vec![],
        agent_surfaces: HashMap::new(),
        secrets: HashMap::new(),
        policies: HashMap::new(),
        jwt_strategies: HashMap::new(),
        api_key_providers: HashMap::new(),
        credential_providers: HashMap::new(),
        mcp_proxies: HashMap::new(),
        a2a_proxies: HashMap::new(),
    };
    world
        .actors
        .put_gateway_instance(GatewayInstanceActor {
            key: gateway_name.clone(),
            index: 0,
            fixture: Some(gateway_fixture),
        });
}

fn a_managed_agent(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let (port, reserved_port) = reserve_free_port(&format!("managed-agent-{agent_name}"));
    world
        .runtimes
        .reserved_ports
        .insert(port, reserved_port);

    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "agent-ok",
        "agent_type": "managed",
        "agent_key": agent_name,
    });

    let mock_agent_spec = MockAgentFixture {
        key: agent_name.clone(),
        port,
        forwarding_address: None,
        log_path: world
            .temp_dir
            .path()
            .join(&agent_name),
        response: MockResponse::json(response.clone()),
        debug: world.debug,
    };

    world
        .actors
        .put_target(TargetActor {
            key: agent_name.clone(),
            kind: TargetActorKind::ManagedAgent,
            collaborator_key: agent_name.clone(),
            fixture: Some(mock_agent_spec),
        });
}

#[given(expr = "external agent {string}")]
fn an_external_agent(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let (port, reserved_port) = reserve_free_port(&format!("external-agent-{agent_name}"));
    world
        .runtimes
        .reserved_ports
        .insert(port, reserved_port);

    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "agent-ok",
        "agent_type": "external",
        "agent_key": agent_name,
    });

    let mock_agent_spec = MockAgentFixture {
        key: agent_name.clone(),
        port,
        forwarding_address: None,
        log_path: world
            .temp_dir
            .path()
            .join(&agent_name),
        response: MockResponse::json(response.clone()),
        debug: world.debug,
    };

    world
        .actors
        .put_target(TargetActor {
            key: agent_name.clone(),
            kind: TargetActorKind::ExternalAgent,
            collaborator_key: agent_name.clone(),
            fixture: Some(mock_agent_spec),
        });
}

#[given(expr = "gateway {string} has surface {string} targeting A2A Server agent {string}")]
async fn gateway_has_bootstrapped_surface_targets_a2a_server_agent(
    world: &mut SurfaceWorld,
    gateway_name: String,
    surface_name: String,
    agent_name: String,
) {
    if world
        .actors
        .target_mut(&agent_name)
        .is_none()
    {
        a_managed_agent(world, agent_name.clone());
    }

    // Implementation for this step
    let gateway_port = world
        .actors
        .gateway_instance_mut(&gateway_name)
        .expect("gateway must be defined before configuring a surface")
        .fixture
        .as_ref()
        .expect("gateway fixture must exist before configuring a surface")
        .gateway_port;

    let agent = world
        .actors
        .target_mut(&agent_name)
        .expect("agent must be defined before configuring a surface");

    let agent_address = format!(
        "http://localhost:{}",
        agent
            .fixture
            .as_ref()
            .expect("agent fixture must exist")
            .port
    );

    let surface_fixture = AgentSurfaceFixture {
        surface_id: surface_name.clone(),
        name: surface_name.clone(),
        description: format!("BDD surface {} for gateway {}", surface_name, gateway_name),
        status: "active".to_string(),
        access_point: AccessPointFixture {
            listen_address: format!("http://localhost:{}", gateway_port),
            protocol: "a2a".to_string(),
            ..Default::default()
        },
        target: TargetFixture {
            endpoint: agent_address,
            ..Default::default()
        },
        ..Default::default()
    };

    world
        .actors
        .put_surface(SurfaceActor {
            key: surface_name.clone(),
            protocol: "a2a".to_string(),
            gateway_binding: Some(gateway_name.clone()),
            bootstrapped: true,
            target_name: Some(agent_name.clone()),
            ..Default::default()
        });

    world
        .actors
        .gateway_instance_mut(&gateway_name)
        .expect("gateway must be defined before configuring a surface")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist before configuring a surface")
        .agent_surfaces
        .insert(surface_name.clone(), surface_fixture);
}

#[given(expr = "surface {string} uses path {string}")]
fn surface_uses_path(
    world: &mut SurfaceWorld,
    surface_name: String,
    path: String,
) {
    let surface_actor = world
        .actors
        .surface(&surface_name)
        .expect("Surface must be defined");
    let gateway_name = if surface_actor.bootstrapped {
        let gateway_name = surface_actor
            .gateway_binding
            .as_ref()
            .expect("bootstrapped surface must have a gateway binding");
        gateway_name.clone()
    } else {
        panic!("surface {} must be bootstrapped before configuring its path", surface_name);
    };
    let surface_fixture = world
        .actors
        .gateway_instance_mut(gateway_name.as_str())
        .expect("gateway must be defined")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist before configuring a surface")
        .agent_surfaces
        .get_mut(&surface_name)
        .expect("Agent surface fixture must be present");

    surface_fixture
        .access_point
        .route = path.clone();

    // Implementation for this step
}

#[given(expr = "surface {string} has direct A2A transit point {string} to agent {string}")]
async fn surface_has_transit_point(
    world: &mut SurfaceWorld,
    surface_name: String,
    transit_point_alias: String,
    target_agent: String,
) {
    let gateway_key = world
        .actors
        .surface(&surface_name)
        .expect("surface must exist to create a transit point")
        .gateway_binding
        .as_ref()
        .expect("surface must have a gateway binding to create a transit point")
        .clone();

    let gateway_outbound_port = world
        .actors
        .gateway_instance(&gateway_key)
        .expect("Gateway must be present")
        .fixture
        .as_ref()
        .expect("gateway fixture must exist to create a transit point")
        .outbound_listener_port
        .expect("Outbound port must be present");

    let target_agent_port = world
        .actors
        .target(&target_agent)
        .expect("target agent must exist to create a transit point")
        .fixture
        .as_ref()
        .expect("target agent fixture must exist to create a transit point")
        .port;

    let transit_point = TransitPointFixture {
        key: transit_point_alias.clone(),
        name: transit_point_alias.clone(),
        listen_path: Some(format!("/outgoing/{}", target_agent.clone())),
        listen_address: Some(format!("http://localhost:{}", gateway_outbound_port)),
        target_endpoint: Some(format!("http://localhost:{}", target_agent_port)),
        ..Default::default()
    };

    world
        .actors
        .gateway_instance_mut(&gateway_key)
        .expect("gateway must exist to create a transit point")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist to create a transit point")
        .agent_surfaces
        .get_mut(&surface_name)
        .expect("agent surface must exist to create a transit point")
        .transit_points
        .insert(transit_point_alias.clone(), transit_point);

    world
        .actors
        .put_transit_point(TransitPointActor {
            key: transit_point_alias.clone(),
            fixture: None,
            bootstrapped: true,
            surface_binding: Some(surface_name.clone()),
            target_binding: Some(target_agent.clone()),
        });
}

#[given(expr = "transit point {string} uses path {string}")]
fn transit_point_uses_path(
    world: &mut SurfaceWorld,
    transit_point_alias: String,
    path: String,
) {
    let surface_key = world
        .actors
        .transit_point(&transit_point_alias)
        .expect("Transit point must be present")
        .surface_binding
        .clone()
        .expect("Transit point must have a surface binding to set its path");

    let surface_actor = world
        .actors
        .surface(&surface_key)
        .expect("Surface must exist to set transit point path");
    let gateway_key = surface_actor
        .gateway_binding
        .clone()
        .expect("Surface must have a gateway binding to set transit point path");

    let surface_target_agent_key = surface_actor
        .target_name
        .clone()
        .expect("Surface must have a target agent to set transit point path");

    let gateway_fixture = world
        .actors
        .gateway_instance(&gateway_key)
        .expect("gateway must exist to set transit point path")
        .fixture
        .as_ref()
        .expect("gateway fixture must exist to set transit point path");

    let transit_point_fixture = gateway_fixture
        .agent_surfaces
        .get(&surface_key)
        .expect("agent surface must exist to set transit point path")
        .transit_points
        .get(&transit_point_alias)
        .expect("transit point must exist to set its path");

    let transit_point_listen_address = transit_point_fixture
        .listen_address
        .as_ref()
        .expect("transit point must have a listen address to set its path");

    let transit_point_listen_path = transit_point_fixture
        .listen_path
        .as_ref()
        .expect("transit point must have a listen path to set its path");

    world
        .actors
        .target_mut(&surface_target_agent_key)
        .expect("target agent must exist to set transit point path")
        .fixture
        .as_mut()
        .expect("target agent fixture must exist to set transit point path")
        .forwarding_address = Some(format!("{}{}{}", transit_point_listen_address, transit_point_listen_path, path));
}

#[given(expr = "transit point {string} has policy {string} that allows outbound requests only to {string}")]
fn transit_point_has_policy(
    world: &mut SurfaceWorld,
    tp_name: String,
    policy_name: String,
    allowed_path: String,
) {
    let policy_text = build_transit_point_request_path_policy(&allowed_path);

    let surface_key = world
        .actors
        .transit_point(&tp_name)
        .expect("Transit point must be present")
        .surface_binding
        .clone()
        .expect("Transit point must have a surface binding to set its path");

    let surface_actor = world
        .actors
        .surface(&surface_key)
        .expect("Surface must exist to set transit point path");
    let gateway_key = surface_actor
        .gateway_binding
        .clone()
        .expect("Surface must have a gateway binding to set transit point path");

    let gateway_fixture = world
        .actors
        .gateway_instance_mut(&gateway_key)
        .expect("gateway must exist to set transit point path")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist to set transit point path");

    let transit_point_fixture = gateway_fixture
        .agent_surfaces
        .get_mut(&surface_key)
        .expect("agent surface must exist to set transit point path")
        .transit_points
        .get_mut(&tp_name)
        .expect("transit point must exist to set its path");

    transit_point_fixture.policy = Some(policy_name.clone());

    let policy_fixture = PolicyDefinitionFixture {
        id: policy_name.clone(),
        description: policy_name.clone(),
        rego: policy_text.clone(),
    };
    gateway_fixture
        .policies
        .insert(policy_name.clone(), policy_fixture);

    world
        .actors
        .put_policy(PolicyActor {
            key: policy_name.clone(),
            fixture: None,
            bootstrapped: true,
            gateway_binding: Some(gateway_key.clone()),
        });
}

#[given(expr = "gateway {string} has gateway-level policy that allows inbound requests only to {string}")]
fn gateway_has_policy_to_path(
    world: &mut SurfaceWorld,
    gateway_name: String,
    allowed_path: String,
) {
    let policy_text = build_gateway_request_path_policy(&allowed_path);

    let gateway_fixture = world
        .actors
        .gateway_instance_mut(&gateway_name)
        .expect("gateway must exist to set its policy")
        .fixture
        .as_mut()
        .expect("gateway fixture must exist to set its policy");

    gateway_fixture.policy_opa_entry = Some(policy_text.clone());
}

#[given(expr = "A2A surface {string} has request policy {string} that allows inbound requests only to {string}")]
async fn a2a_surface_has_request_policy(
    world: &mut SurfaceWorld,
    surface_name: String,
    policy_name: String,
    allowed_path: String,
) {
    let policy_text = build_surface_request_path_policy(&allowed_path);

    let policy_fixture = PolicyDefinitionFixture {
        id: policy_name.clone(),
        description: policy_name.clone(),
        rego: policy_text.clone(),
    };

    add_bootstrapped_policy_to_surface(world, surface_name, policy_name, policy_fixture, false).await;
}

#[given(expr = "the surface fetches its agent card from path {string}")]
fn surface_fetches_agent_card_from_path(
    world: &mut SurfaceWorld,
    path: String,
) {
    world
        .surface_config
        .agent_card_path = Some(path);
}

#[given(expr = "managed agent {string} redirects its agent card to managed agent {string}")]
async fn managed_agent_redirects_agent_card(
    world: &mut SurfaceWorld,
    agent_name: String,
    redirect_agent: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    world
        .actors
        .register_secondary_managed_agent(&redirect_agent);
    world.register_secondary_collaborator(&redirect_agent, TargetActorKind::ManagedAgent);
    install_replacement_mock(world, serde_json::json!({ "name": redirect_agent })).await;

    let location = format!(
        "{}/.well-known/agent-card.json",
        world
            .mock_for_target(&redirect_agent)
            .url()
    );
    let mut redirect = MockResponse::json(serde_json::json!({}));
    redirect.status = 302;
    redirect
        .headers
        .insert("location".to_string(), location);
    world
        .mock_for_target(&agent_name)
        .set_response(redirect)
        .await;
}

/// An upstream publishing an **A2A v1.0** card: no top-level `url`, transports in an
/// ordered `supportedInterfaces[]`, plus a v0.3 `additionalInterfaces[]` to prove
/// every interface array is rewritten. Any URL left pointing at the upstream would
/// let a caller dial it directly and bypass the gateway.
#[given(expr = "managed agent {string} publishes a v1.0 agent card with multiple interfaces")]
fn managed_agent_publishes_v1_card_with_interfaces(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let agent_card = serde_json::json!({
        "protocolVersion": "1.0",
        "name": "test-agent",
        "version": "1.0.0",
        "provider": { "organization": "Upstream Org", "url": "https://upstream.example" },
        "capabilities": { "extensions": [] },
        "supportedInterfaces": [
            { "url": "http://managed-agent.local/a2a",  "protocolBinding": "JSONRPC", "protocolVersion": "1.0" },
            { "url": "http://managed-agent.local/grpc", "protocolBinding": "GRPC",    "protocolVersion": "1.0" }
        ],
        "additionalInterfaces": [
            { "url": "http://managed-agent.local/rest", "transport": "HTTP+JSON" }
        ]
    });
    set_primary_target_response(world, agent_card);
}

/// An upstream still publishing a **v0.3** card, used to prove the gateway keeps
/// serving it at the upstream's own version rather than forcing 1.0 onto it.
#[given(expr = "managed agent {string} publishes a v0.3 agent card")]
fn managed_agent_publishes_v0_3_card(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let agent_card = serde_json::json!({
        "protocolVersion": "0.3",
        "name": "legacy-agent",
        "version": "1.0.0",
        "url": "http://managed-agent.local/a2a",
        "preferredTransport": "JSONRPC",
        "capabilities": { "extensions": [] }
    });
    set_primary_target_response(world, agent_card);
}

#[given(expr = "managed agent {string} publishes an agent card with extra URL fields")]
fn managed_agent_publishes_card_with_extra_urls(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let agent_card = serde_json::json!({
        "name": "test-agent",
        "url": "http://managed-agent.local",
        "endpoint": "http://managed-agent.local/a2a",
        "endpoints": [
            { "kind": "a2a", "url": "http://managed-agent.local/a2a" }
        ],
        "version": "1.0.0",
        "capabilities": { "extensions": [] }
    });
    set_primary_target_response(world, agent_card);
}

#[given(expr = "the surface accepts MCP Origin {string}")]
fn surface_accepts_mcp_origin(
    world: &mut SurfaceWorld,
    origin: String,
) {
    let mcp_http = world
        .surface_config
        .mcp_http
        .get_or_insert_with(|| serde_json::json!({}));
    let origins = mcp_http["allowed_origins"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut origins = origins;
    origins.push(serde_json::json!(origin));
    mcp_http["allowed_origins"] = serde_json::Value::Array(origins);
}

fn set_modern_tool_response(
    world: &mut SurfaceWorld,
    server_name: &str,
    stream: crate::bdd_support::mock_server::MockStream,
) {
    world
        .actors
        .expect_target_kind(server_name, TargetActorKind::McpServer);
    set_target_response_for_actor(
        world,
        server_name,
        MockResponse::streamed(
            crate::bdd_support::json_rpc::build_modern_mcp_tool_result_fixture(serde_json::json!(1)),
            stream,
        ),
    );
}

#[given(expr = "MCP server {string} supports modern tool invocation with {string} responses")]
fn mcp_server_supports_modern_tool_invocation(
    world: &mut SurfaceWorld,
    server_name: String,
    content_type: String,
) {
    let stream = match content_type.as_str() {
        "application/json" => crate::bdd_support::mock_server::MockStream::None,
        "text/event-stream" => crate::bdd_support::mock_server::MockStream::Sse,
        other => panic!("unsupported MCP response content type '{other}'"),
    };
    set_modern_tool_response(world, &server_name, stream);
}

#[given(expr = "MCP server {string} reports progress while MCP tool {string} is still running")]
fn mcp_server_reports_progress_while_running(
    world: &mut SurfaceWorld,
    server_name: String,
    _tool_name: String,
) {
    set_modern_tool_response(world, &server_name, crate::bdd_support::mock_server::MockStream::ProgressThenRelease);
}

#[given(expr = "MCP server {string} keeps MCP tool {string} running without progress messages")]
fn mcp_server_keeps_tool_running_quietly(
    world: &mut SurfaceWorld,
    server_name: String,
    _tool_name: String,
) {
    set_modern_tool_response(world, &server_name, crate::bdd_support::mock_server::MockStream::Quiet);
}

#[given(expr = "the caller has an open modern MCP response stream for tool {string}")]
async fn caller_has_open_modern_mcp_stream(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    crate::steps::when::send_modern_mcp_tool_call(
        world,
        &tool_name,
        crate::bdd_support::json_rpc::MODERN_MCP_PROTOCOL_VERSION,
        Vec::new(),
    )
    .await;
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response");
    assert_eq!(response.status, 200, "the modern stream opened: {response:?}");
    assert!(world.mcp_stream.is_some(), "the response is still streaming");
    let mock = &world
        .infra
        .as_ref()
        .expect("scenario infrastructure")
        .mock;
    for _ in 0..50 {
        if mock.request_count().await > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the upstream never received the tool call");
}

fn surface_a2a_settings(world: &mut SurfaceWorld) -> &mut serde_json::Value {
    world
        .surface_config
        .a2a_settings
        .get_or_insert_with(|| serde_json::json!({ "accepted_versions": ["0.3", "1.0"], "validate_messages": false }))
}

#[given(expr = "the surface accepts A2A versions {string}")]
fn surface_accepts_a2a_versions(
    world: &mut SurfaceWorld,
    versions: String,
) {
    let versions: Vec<&str> = versions
        .split(',')
        .map(str::trim)
        .collect();
    surface_a2a_settings(world)["accepted_versions"] = serde_json::json!(versions);
}

#[given("the surface validates A2A messages")]
fn surface_validates_a2a_messages(world: &mut SurfaceWorld) {
    surface_a2a_settings(world)["validate_messages"] = serde_json::json!(true);
}
