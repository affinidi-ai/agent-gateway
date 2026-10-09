//! Given steps — declare the gateway/surface/fabric topology. Nothing boots
//! here; the topology is materialised lazily by the first action step (see
//! `G2gWorld::start`).

use cucumber::given;
use serde_json::Value;

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::config::fabric_surface_fixture::{
    McpProxySpec, McpToolPolicySpec, SourceAuthSpec, SurfaceSpec, TargetAuthSpec,
    TransitPointHeaderMetadataMappingRowSpec, TransitPointSpec,
};
use crate::bdd_support::json_rpc::{IdentityBindingProof, build_mcp_echo_response_body, build_target_ok_response};
use crate::bdd_support::policies::{
    build_gateway_deny_all_policy, build_gateway_deny_unverified_source_auth_policy, build_mcp_tool_allow_policy,
    build_surface_identity_binding_issuer_policy,
};
use crate::world::{FabricLink, G2gWorld, TransitPointFabricLink};

fn set_target_response(
    world: &mut G2gWorld,
    target_name: &str,
    response: Value,
) {
    let (gw_index, surface_id) = world.target(target_name);
    world
        .topology
        .plan_mut(gw_index)
        .mock_responses
        .insert(surface_id, response);
}

#[given(expr = "MCP server {string} serves a modern MCP tool catalog")]
fn mcp_server_serves_modern_tool_catalog(
    world: &mut G2gWorld,
    server_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response(
        world,
        &server_name,
        crate::bdd_support::json_rpc::build_modern_mcp_tool_catalog_fixture(serde_json::json!("server-placeholder")),
    );
}

fn build_mcp_tool_catalog_response() -> Value {
    serde_json::json!({
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
    })
}

fn build_mcp_initialize_response() -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
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

fn build_mcp_tools_call_response() -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                { "type": "text", "text": "tool output" }
            ],
            "isError": false
        }
    })
}

#[given(expr = "gateway 1 and gateway 2 have just been paired")]
pub async fn gateways_have_just_been_paired(world: &mut G2gWorld) {
    a_fabric_with_n_gateways(world, 2).await;
}

#[given(regex = r"^a fabric with (\d+) gateways?$")]
pub async fn a_fabric_with_n_gateways(
    world: &mut G2gWorld,
    count: usize,
) {
    world.topology.gateway_count = world
        .topology
        .gateway_count
        .max(count);
}

#[given(expr = "gateway {int} surface {string} uses {string} MCP metadata output")]
async fn gateway_surface_uses_mcp_metadata_output(
    world: &mut G2gWorld,
    gateway: usize,
    surface_name: String,
    output: String,
) {
    let (_, surface_id) = world
        .topology
        .surface_names
        .get(&surface_name)
        .expect("surface actor")
        .clone();
    world.start().await;
    let admin = &world
        .harness()
        .gw(gateway)
        .admin;
    let mut surface = admin
        .get_surface(&surface_id)
        .await
        .expect("read surface");
    surface["mcp_legacy_metadata_output"] = serde_json::json!(output);
    admin
        .update_surface(&surface_id, &surface)
        .await
        .expect("configure MCP metadata output");
}

#[given(regex = r#"^gateway (\d+) has an (A2A|MCP) surface "([^"]+)" targeting (managed agent|MCP server) "([^"]+)"$"#)]
pub async fn gateway_has_surface_targeting_actor(
    world: &mut G2gWorld,
    gw_index: usize,
    protocol_label: String,
    surface_name: String,
    actor_kind: String,
    target_name: String,
) {
    let protocol = protocol_label.to_lowercase();
    let surface_id = surface_name.clone();
    let route = format!("/{surface_id}");
    world
        .topology
        .actors
        .register_target_with_key(&target_name, TargetActorKind::from_gherkin_label(&actor_kind), &surface_id);
    world
        .topology
        .actors
        .register_surface_with_target(&surface_name, &protocol, Some(&route), Some(&target_name));

    let plan = world
        .topology
        .plan_mut(gw_index);
    plan.surfaces
        .push(SurfaceSpec::new(&surface_id, &route, &protocol, "http://placeholder.invalid"));
    plan.mock_responses
        .insert(surface_id.clone(), build_target_ok_response());

    world
        .topology
        .surface_names
        .insert(surface_name, (gw_index, surface_id.clone()));
    world
        .topology
        .actors
        .bind_target_to_surface(&target_name, gw_index, &surface_id);
}

#[given(
    regex = r#"^gateway (\d+) has an MCP surface "([^"]+)" targeting MCP server "([^"]+)" with (\d+)-(\d+) ms response delay$"#
)]
pub async fn gateway_has_delayed_mcp_echo_server(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
    target_name: String,
    min_delay_ms: u64,
    max_delay_ms: u64,
) {
    let surface_id = surface_name.clone();
    let route = format!("/{surface_id}");
    world
        .topology
        .actors
        .register_target_with_key(&target_name, TargetActorKind::McpServer, &surface_id);
    world
        .topology
        .actors
        .register_surface_with_target(&surface_name, "mcp", Some(&route), Some(&target_name));

    let plan = world
        .topology
        .plan_mut(gw_index);
    plan.surfaces
        .push(SurfaceSpec::new(&surface_id, &route, "mcp", "http://placeholder.invalid"));
    plan.mock_responses
        .insert(surface_id.clone(), build_mcp_echo_response_body());
    plan.mock_response_delays
        .insert(surface_id.clone(), (min_delay_ms, max_delay_ms));

    world
        .topology
        .surface_names
        .insert(surface_name, (gw_index, surface_id.clone()));
    world
        .topology
        .actors
        .bind_target_to_surface(&target_name, gw_index, &surface_id);
}

#[given(expr = "gateway {int} exposes MCP surface {string} backed by REST API {string} through an MCP proxy endpoint")]
pub async fn gateway_has_surface_backed_by_mcp_proxy(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
    target_name: String,
) {
    let surface_id = surface_name.clone();
    let route = format!("/{surface_id}");
    let proxy_id = format!("{surface_id}-proxy");
    world
        .topology
        .actors
        .register_target_with_key(&target_name, TargetActorKind::RestApi, &surface_id);
    world
        .topology
        .actors
        .register_surface_with_target(&surface_name, "mcp", Some(&route), Some(&target_name));

    let plan = world
        .topology
        .plan_mut(gw_index);
    let mut spec = SurfaceSpec::new(&surface_id, &route, "mcp", &format!("proxy://{proxy_id}"));
    spec.mcp_proxy = Some(McpProxySpec::new(proxy_id, "http://placeholder.invalid"));
    plan.surfaces.push(spec);
    plan.mock_responses
        .insert(surface_id.clone(), build_target_ok_response());

    world
        .topology
        .surface_names
        .insert(surface_name, (gw_index, surface_id.clone()));
    world
        .topology
        .actors
        .bind_target_to_surface(&target_name, gw_index, &surface_id);
}

/// The reference server the MCP conformance harness serves; `run.sh` passes
/// the shim in front of it as `MCP_CONFORMANCE_UPSTREAM_URL`. The surface has
/// no mock target.
#[given(expr = "gateway {int} has an MCP surface {string} targeting the MCP conformance reference server")]
pub async fn gateway_has_surface_targeting_conformance_reference_server(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    let upstream = std::env::var("MCP_CONFORMANCE_UPSTREAM_URL").expect(
        "MCP_CONFORMANCE_UPSTREAM_URL must name the upstream; run this feature through scripts/mcp-conformance/run.sh",
    );
    let surface_id = surface_name.clone();
    let route = format!("/{surface_id}");
    world
        .topology
        .actors
        .register_surface_with_target(&surface_name, "mcp", Some(&route), None);
    let mut surface = SurfaceSpec::new(&surface_id, &route, "mcp", &upstream);
    surface.external_target = true;
    world
        .topology
        .plan_mut(gw_index)
        .surfaces
        .push(surface);
    world
        .topology
        .surface_names
        .insert(surface_name, (gw_index, surface_id));
}

#[given(expr = "surface {string} accepts MCP Origins of gateway {int}")]
pub async fn surface_accepts_mcp_origins_of_gateway(
    world: &mut G2gWorld,
    surface_name: String,
    origin_gw: usize,
) {
    let (gw_index, surface_id) = world.surface(&surface_name);
    world
        .topology
        .mcp_origin_grants
        .push((gw_index, surface_id, origin_gw));
}

fn surface_spec_mut<'a>(
    world: &'a mut G2gWorld,
    surface_name: &str,
) -> &'a mut SurfaceSpec {
    let (gw_index, surface_id) = world.surface(surface_name);
    world
        .topology
        .plan_mut(gw_index)
        .surfaces
        .iter_mut()
        .find(|surface| surface.surface_id == surface_id)
        .unwrap_or_else(|| panic!("surface '{surface_name}' not found in gateway {gw_index} plan"))
}

fn transit_point_spec_mut<'a>(
    world: &'a mut G2gWorld,
    transit_point: &str,
) -> &'a mut TransitPointSpec {
    for plan in world
        .topology
        .plans
        .values_mut()
    {
        for surface in &mut plan.surfaces {
            if let Some(tp) = surface
                .transit_points
                .iter_mut()
                .find(|tp| tp.alias == transit_point)
            {
                return tp;
            }
        }
    }
    panic!("Transit Point '{transit_point}' is not configured")
}

#[given(expr = "surface {string} has A2A Transit Point {string} over Fabric to gateway {int} surface {string}")]
pub async fn surface_has_a2a_transit_point_over_fabric(
    world: &mut G2gWorld,
    surface_name: String,
    transit_point: String,
    peer_gw: usize,
    peer_surface_name: String,
) {
    let (from_gw, from_surface_id) = world.surface(&surface_name);
    let (_peer_gw_resolved, peer_surface_id) = world.surface(&peer_surface_name);
    let surface = surface_spec_mut(world, &surface_name);
    surface
        .transit_points
        .push(TransitPointSpec::new(&transit_point, "a2a", "fabric://pending/pending"));
    world
        .topology
        .transit_point_fabric_links
        .push(TransitPointFabricLink {
            from_gw,
            from_surface: from_surface_id,
            transit_point,
            to_gw: peer_gw,
            to_surface: peer_surface_id,
        });
}

#[given(expr = "transit point {string} maps managed-agent header {string} to A2A metadata field {string}")]
pub async fn transit_point_maps_managed_agent_header_to_a2a_metadata_field(
    world: &mut G2gWorld,
    transit_point: String,
    header: String,
    field: String,
) {
    let tp = transit_point_spec_mut(world, &transit_point);
    if let Some(existing) = tp
        .header_metadata_mapping
        .headers
        .iter_mut()
        .find(|row| {
            row.header
                .eq_ignore_ascii_case(&header)
        })
    {
        existing.field = field;
    } else {
        tp.header_metadata_mapping
            .headers
            .push(TransitPointHeaderMetadataMappingRowSpec { header, field });
    }
}

#[given(
    expr = "transit point {string} derives outbound managed-agent identity from mapped A2A metadata fields {string} and {string}"
)]
pub async fn transit_point_derives_outbound_managed_agent_identity_from_mapped_metadata(
    world: &mut G2gWorld,
    transit_point: String,
    first_field: String,
    second_field: String,
) {
    let tp = transit_point_spec_mut(world, &transit_point);
    tp.managed_identity_fields = Some(vec![first_field, second_field]);
}

#[given(
    regex = r#"^gateway (\d+) has an (A2A|MCP) surface "([^"]+)" forwarding over fabric to gateway (\d+) surface "([^"]+)"( that is not exposed to it)?$"#
)]
pub async fn gateway_has_fabric_surface(
    world: &mut G2gWorld,
    gw_index: usize,
    protocol_label: String,
    surface_name: String,
    peer_gw: usize,
    peer_surface_name: String,
    not_exposed: String,
) {
    let protocol = protocol_label.to_lowercase();
    let surface_id = surface_name.clone();
    let route = format!("/{surface_id}");

    let (_peer_gw_resolved, peer_surface_id) = world.surface(&peer_surface_name);
    world
        .topology
        .actors
        .register_surface_with_target(&surface_name, &protocol, Some(&route), None);

    let plan = world
        .topology
        .plan_mut(gw_index);
    plan.surfaces
        .push(SurfaceSpec::new(&surface_id, &route, &protocol, "fabric://pending/pending"));

    world
        .topology
        .fabric_links
        .push(FabricLink {
            from_gw: gw_index,
            from_surface: surface_id.clone(),
            to_gw: peer_gw,
            to_surface: peer_surface_id,
            exposed: not_exposed.is_empty(),
        });
    world
        .topology
        .surface_names
        .insert(surface_name, (gw_index, surface_id));
}

#[given(regex = r"^gateway (\d+) has a Gateway-level policy that rejects all fabric callers$")]
pub async fn gateway_rejects_all_fabric_callers(
    world: &mut G2gWorld,
    gw_index: usize,
) {
    world
        .topology
        .gateway_policies
        .insert(gw_index, build_gateway_deny_all_policy());
}

#[given(regex = r"^gateway (\d+) has a Gateway-level policy that denies unverified callers$")]
pub async fn gateway_denies_unverified_callers(
    world: &mut G2gWorld,
    gw_index: usize,
) {
    world
        .topology
        .gateway_policies
        .insert(gw_index, build_gateway_deny_unverified_source_auth_policy());
}

#[given(regex = r"^gateway (\d+) has a Gateway-level policy that accepts fabric calls only from gateway (\d+)$")]
pub async fn gateway_accepts_only_from(
    world: &mut G2gWorld,
    gw_index: usize,
    allowed_from: usize,
) {
    world
        .topology
        .gateway_allow_only
        .insert(gw_index, allowed_from);
}

#[given(regex = r#"^surface "([^"]+)" requires "API Key" source authentication$"#)]
pub async fn surface_requires_api_key(
    world: &mut G2gWorld,
    surface_name: String,
) {
    let valid_key = "bdd-source-api-key".to_string();
    let header = "x-api-key".to_string();
    let (gw_index, surface_id) = world.surface(&surface_name);
    let secret_id = format!("{surface_id}-source-key");
    let plan = world
        .topology
        .plan_mut(gw_index);
    let surface = plan
        .surfaces
        .iter_mut()
        .find(|s| s.surface_id == surface_id)
        .unwrap_or_else(|| panic!("surface '{surface_id}' not declared on gateway {gw_index}"));
    surface.source_auth = Some(SourceAuthSpec::ApiKey {
        header_name: header,
        secret_id,
        valid_key,
    });
}

#[given(
    regex = r#"^surface "([^"]+)" injects target authentication from secret "([^"]+)" with value "([^"]+)" as header "([^"]+)"$"#
)]
pub async fn surface_injects_target_credential(
    world: &mut G2gWorld,
    surface_name: String,
    secret_id: String,
    secret_value: String,
    header: String,
) {
    let (gw_index, surface_id) = world.surface(&surface_name);
    let plan = world
        .topology
        .plan_mut(gw_index);
    let surface = plan
        .surfaces
        .iter_mut()
        .find(|s| s.surface_id == surface_id)
        .unwrap_or_else(|| panic!("surface '{surface_id}' not declared on gateway {gw_index}"));
    surface.target_auth = Some(TargetAuthSpec {
        secret_id,
        header_name: header,
        header_format: "{value}".to_string(),
        fallback: "reject".to_string(),
        secret_value: Some(secret_value),
    });
}

#[given(
    regex = r#"^surface "([^"]+)" is configured with missing target authentication secret "([^"]+)" for header "([^"]+)" and fallback (reject|passthrough)$"#
)]
pub async fn surface_injects_missing_target_credential(
    world: &mut G2gWorld,
    surface_name: String,
    secret_id: String,
    header: String,
    fallback: String,
) {
    let (gw_index, surface_id) = world.surface(&surface_name);
    let plan = world
        .topology
        .plan_mut(gw_index);
    let surface = plan
        .surfaces
        .iter_mut()
        .find(|s| s.surface_id == surface_id)
        .unwrap_or_else(|| panic!("surface '{surface_id}' not declared on gateway {gw_index}"));
    surface.target_auth = Some(TargetAuthSpec {
        secret_id,
        header_name: header,
        header_format: "{value}".to_string(),
        fallback,
        secret_value: None,
    });
}

#[given(expr = "MCP server {string} publishes a tool catalog")]
pub async fn mcp_server_publishes_tool_catalog(
    world: &mut G2gWorld,
    server_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response(world, &server_name, build_mcp_tool_catalog_response());
}

#[given(expr = "MCP server {string} supports initialization")]
pub async fn mcp_server_supports_initialization(
    world: &mut G2gWorld,
    server_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response(world, &server_name, build_mcp_initialize_response());
}

#[given(expr = "MCP server {string} supports tool invocation")]
pub async fn mcp_server_supports_tool_invocation(
    world: &mut G2gWorld,
    server_name: String,
) {
    world
        .topology
        .actors
        .expect_target_kind(&server_name, TargetActorKind::McpServer);
    set_target_response(world, &server_name, build_mcp_tools_call_response());
}

#[given(regex = r#"^surface "([^"]+)" enforces an MCP tool policy allowing only tool "([^"]+)"$"#)]
pub async fn surface_enforces_mcp_tool_policy(
    world: &mut G2gWorld,
    surface_name: String,
    allowed_tool: String,
) {
    let (gw_index, surface_id) = world.surface(&surface_name);
    let plan = world
        .topology
        .plan_mut(gw_index);
    let surface = plan
        .surfaces
        .iter_mut()
        .find(|s| s.surface_id == surface_id)
        .unwrap_or_else(|| panic!("surface '{surface_id}' not declared on gateway {gw_index}"));
    surface.mcp_tool_policy = Some(McpToolPolicySpec {
        policy_definition_id: format!("{surface_id}-mcp-tool-policy"),
        rego: build_mcp_tool_allow_policy(&allowed_tool),
        allowed_tool,
    });
}

#[given(expr = "gateway {int} has no issuer DID recorded for gateway {int}")]
pub async fn gateway_has_no_issuer_did_recorded_for_peer(
    world: &mut G2gWorld,
    gw_index: usize,
    peer_gw: usize,
) {
    world.start().await;
    let harness = world.harness();
    let remote_id = remote_record_id(world, gw_index, peer_gw);
    let updated = harness
        .gw(gw_index)
        .admin
        .forget_remote_gateway_issuer(&remote_id)
        .await
        .unwrap_or_else(|error| {
            panic!("forget the issuer DID on gateway {gw_index}'s record for gateway {peer_gw}: {error:#}")
        });
    assert_eq!(
        updated.issuer_did, None,
        "gateway {gw_index}'s record for gateway {peer_gw} should no longer carry an issuer DID"
    );
}

#[given(
    regex = r"^gateway (\d+) trusts gateway (\d+)'s gateway DID as an issuer of its connection with gateway (\d+)$"
)]
pub async fn gateway_trusts_issuer_on_connection(
    world: &mut G2gWorld,
    gw_index: usize,
    issuer_gw: usize,
    connection_gw: usize,
) {
    world.start().await;
    let issuer_did = world
        .harness()
        .self_gateway_did(issuer_gw)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let remote_id = remote_record_id(world, gw_index, connection_gw);
    let updated = world
        .harness()
        .gw(gw_index)
        .admin
        .add_trusted_issuer_did(&remote_id, &issuer_did)
        .await
        .unwrap_or_else(|error| {
            panic!("trust gateway {issuer_gw}'s DID on gateway {gw_index}'s connection with gateway {connection_gw}: {error:#}")
        });
    assert!(
        updated
            .trusted_issuer_dids
            .contains(&issuer_did),
        "gateway {gw_index}'s record for gateway {connection_gw} should list {issuer_did} as a trusted issuer, got {:?}",
        updated.trusted_issuer_dids
    );
}

fn remote_record_id(
    world: &G2gWorld,
    gw_index: usize,
    peer_gw: usize,
) -> String {
    world
        .harness()
        .remote_id(gw_index, peer_gw)
        .unwrap_or_else(|| panic!("gateway {gw_index} holds no Remote record for gateway {peer_gw}"))
        .to_string()
}

#[given(expr = "surface {string} has a policy that requires the caller identity to be issued by gateway {int}")]
pub async fn surface_requires_caller_identity_issued_by_gateway(
    world: &mut G2gWorld,
    surface_name: String,
    issuer_gw: usize,
) {
    world.start().await;
    let (gw_index, surface_id) = world.surface(&surface_name);
    let issuer_did = world
        .harness()
        .self_gateway_did(issuer_gw)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let policy_definition_id = format!("{surface_id}-identity-issuer-policy");
    let admin = &world
        .harness()
        .gw(gw_index)
        .admin;
    admin
        .create_surface_policy_definition(
            &policy_definition_id,
            &format!("g2g BDD identity issuer policy for {surface_id}"),
            &build_surface_identity_binding_issuer_policy(&issuer_did),
        )
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    // `target.policy` is the surface OPA gate the fabric receive path
    // evaluates; the access-point inbound policy only runs on direct callers.
    admin
        .patch_surface(
            &surface_id,
            &serde_json::json!({ "target": { "policy": { "policy_definition_id": policy_definition_id } } }),
        )
        .await
        .unwrap_or_else(|error| panic!("attach identity issuer policy to surface '{surface_id}': {error:#}"));
}

#[given(expr = "gateway {int} surface {string} has managed identity enabled")]
pub async fn surface_has_managed_identity_enabled(
    world: &mut G2gWorld,
    _gw: usize,
    surface_name: String,
) {
    surface_spec_mut(world, &surface_name).managed_identity = true;
}

/// Only the issuing gateway can produce a presentation for `issued_for`, so the
/// harness obtains a genuine one by driving one request from that managed
/// agent through its Transit Point and reading the proof the peer target
/// received. The target's history is cleared so the scenario's own assertions
/// start clean.
#[given(
    expr = "managed agent {string} has obtained the identity presentation that gateway {int} issued for managed agent {string}"
)]
pub async fn managed_agent_has_obtained_identity_presentation(
    world: &mut G2gWorld,
    holder: String,
    issuer_gw: usize,
    issued_for: String,
) {
    world.start().await;
    let link = world
        .transit_point_of_managed_agent(&issued_for)
        .clone();
    assert_eq!(link.from_gw, issuer_gw, "managed agent '{issued_for}' is not behind gateway {issuer_gw}");

    crate::steps::when::send_a2a_request_through_transit_point(world, &issued_for, &link.transit_point, Vec::new())
        .await;

    let mock = world
        .harness()
        .gw(link.to_gw)
        .mock(&link.to_surface)
        .unwrap_or_else(|| {
            panic!("no target collaborator behind surface '{}' on gateway {}", link.to_surface, link.to_gw)
        });
    let requests = mock.requests().await;
    // Skip the target's agent-card fetch; only the forwarded message carries the proof.
    let forwarded = requests
        .iter()
        .rev()
        .find(|request| {
            !request
                .path_and_query
                .contains(".well-known/agent")
        })
        .unwrap_or_else(|| {
            panic!(
                "gateway {issuer_gw} should have forwarded managed agent '{issued_for}''s request; status={:?}; body={:?}",
                world.response_status, world.response_body
            )
        });
    let body = forwarded.json_body();
    let proof = IdentityBindingProof::from_forwarded_a2a_body(&body)
        .unwrap_or_else(|| panic!("forwarded request carries no identity proof, got body: {body}"));
    mock.clear_requests().await;

    world
        .obtained_identity_proofs
        .insert(holder, proof);
    world.sent_body = None;
    world.response_status = None;
    world.response_body = None;
}
