//! Surface-native config writer for the g2g harness.
//!
//! Writes a complete on-disk gateway config (config.toml + gateway.json +
//! `_storage/agent_surfaces/*.json` + secrets + OPA policy definitions) for a
//! single gateway process. Unlike `surface_bdd`'s writer this supports
//! MULTIPLE surfaces per gateway and the full G2G surface vocabulary:
//! `fabric://` targets, target auth, caller (source) auth, surface-level
//! inbound OPA policy, and MCP proxy target endpoints.

use std::path::Path;

use crate::bdd_support::config::DEFAULT_HEADER_METADATA_EXTENSION_URI;
use crate::bdd_support::config::agent_surface::AgentSurfaceFixture;
use crate::bdd_support::config::config_tree::{
    GatewayBootstrapFixture, PolicyDefinitionFixture, SecretFixture, write_gateway_config_tree,
};
use crate::bdd_support::config::fabric_surface_fixture::{SourceAuthSpec, SurfaceSpec};
use crate::bdd_support::config::gateway_bootstrap::GatewayBootstrapSurface;
use crate::bdd_support::config::policy_definitions::{
    PolicyDefinitionFixtureKind, inbound_policy_definition_id, policy_definition_id as kinded_policy_definition_id,
};
use crate::bdd_support::config::source_auth::api_key_source_auth_method_json;
use crate::bdd_support::config::target_auth::static_secret_target_auth_json;

/// Write the full config tree for one gateway listening on `gateway_port` and
/// exposing `surfaces`.
pub fn write_fabric_gateway_config(
    base_dir: &Path,
    gateway_port: u16,
    outbound_listener_port: Option<u16>,
    surfaces: &[SurfaceSpec],
) {
    let listen_address = format!("http://localhost:{gateway_port}");

    let bootstrap_surfaces = surfaces
        .iter()
        .map(|surface| {
            GatewayBootstrapSurface::new(surface.surface_id.clone(), surface.surface_id.clone(), surface.route.clone())
        })
        .collect::<Vec<_>>();
    let mut config_tree = GatewayBootstrapFixture::new(gateway_port, "identity", bootstrap_surfaces, "");
    config_tree.outbound_listener_port = outbound_listener_port;

    for surface in surfaces {
        config_tree
            .agent_surfaces
            .insert(
                surface.surface_id.clone(),
                build_surface_fixture(surface, &listen_address, outbound_listener_port),
            );
        config_tree.secrets.extend(
            secret_fixtures(surface)
                .into_iter()
                .map(|secret| (secret.id.clone(), secret)),
        );
        config_tree.policies.extend(
            policy_fixtures(surface)
                .into_iter()
                .map(|policy| (policy.id.clone(), policy)),
        );
        if let Some(proxy) = &surface.mcp_proxy {
            config_tree
                .mcp_proxies
                .insert(proxy.proxy_id.clone(), proxy.clone());
        }
    }

    write_gateway_config_tree(base_dir, &config_tree, true);
}

/// Deterministic policy-definition id derived from the surface id.
pub fn policy_definition_id(surface_id: &str) -> String {
    inbound_policy_definition_id(surface_id)
}

/// Deterministic transit-level (outbound) policy-definition id for a surface.
pub fn transit_policy_definition_id(surface_id: &str) -> String {
    kinded_policy_definition_id(surface_id, PolicyDefinitionFixtureKind::TransitShared)
}

fn secret_fixtures(surface: &SurfaceSpec) -> Vec<SecretFixture> {
    let mut secrets = Vec::new();
    if let Some(source_auth) = &surface.source_auth {
        let SourceAuthSpec::ApiKey { secret_id, valid_key, .. } = source_auth;
        secrets.push(SecretFixture::new(secret_id, valid_key));
    }
    if let Some(target_auth) = &surface.target_auth
        && let Some(secret_value) = &target_auth.secret_value
    {
        secrets.push(SecretFixture::new(&target_auth.secret_id, secret_value));
    }
    secrets
}

fn policy_fixtures(surface: &SurfaceSpec) -> Vec<PolicyDefinitionFixture> {
    let mut policies = Vec::new();
    if let Some(rego) = &surface.inbound_policy_rego {
        policies.push(PolicyDefinitionFixture::new(
            policy_definition_id(&surface.surface_id),
            "g2g BDD inbound policy",
            rego,
        ));
    }
    if let Some(rego) = &surface.transit_policy_rego {
        policies.push(PolicyDefinitionFixture::new(
            transit_policy_definition_id(&surface.surface_id),
            "g2g BDD transit (outbound) policy",
            rego,
        ));
    }
    if let Some(policy) = &surface.mcp_tool_policy {
        policies.push(PolicyDefinitionFixture::new(
            &policy.policy_definition_id,
            format!("BDD {}", policy.policy_definition_id),
            &policy.rego,
        ));
    }
    policies
}

fn build_surface_fixture(
    surface: &SurfaceSpec,
    listen_address: &str,
    outbound_listener_port: Option<u16>,
) -> AgentSurfaceFixture {
    let mut fixture = AgentSurfaceFixture::new(
        surface.surface_id.clone(),
        surface.surface_id.clone(),
        format!("g2g BDD surface {}", surface.surface_id),
        listen_address,
        surface.route.clone(),
        surface.protocol.clone(),
        surface
            .target_endpoint
            .clone(),
    );

    if let Some(source_auth) = &surface.source_auth {
        let SourceAuthSpec::ApiKey { header_name, secret_id, .. } = source_auth;
        fixture = fixture.with_caller_auth_method(api_key_source_auth_method_json(header_name, secret_id));
    }

    if surface
        .inbound_policy_rego
        .is_some()
    {
        fixture = fixture.with_inbound_policy_definition_id(policy_definition_id(&surface.surface_id));
    }

    if surface.managed_identity {
        fixture = fixture.with_target_identity_injection(
            crate::bdd_support::config::managed_identity::target_identity_injection_json(
                &crate::bdd_support::config::managed_identity::default_identity_payload_schema(),
            ),
        );
    }
    if let Some(proxy) = &surface.mcp_proxy {
        fixture = fixture.with_mcp_proxy_id(proxy.proxy_id.clone());
    }
    if surface.protocol == "mcp" {
        // An MCP endpoint checks Origin, so it accepts the gateway's own
        // origin under both loopback names callers use.
        let loopback = listen_address.replacen("localhost", "127.0.0.1", 1);
        fixture = fixture.with_mcp_http(serde_json::json!({ "allowed_origins": [listen_address, loopback] }));
    }
    if let Some(target_auth) = &surface.target_auth {
        fixture = fixture.with_target_auth(static_secret_target_auth_json(
            &target_auth.secret_id,
            &target_auth.header_name,
            &target_auth.header_format,
            &target_auth.fallback,
        ));
    }
    if let Some(policy) = &surface.mcp_tool_policy {
        fixture = fixture.with_mcp_tool_policy(&policy.allowed_tool, &policy.policy_definition_id);
    }
    if !surface
        .transit_points
        .is_empty()
    {
        let points = surface
            .transit_points
            .iter()
            .map(|tp| {
                let mut point = serde_json::json!({
                    "name": tp.alias,
                    "alias": tp.alias,
                    "target_endpoint": tp.target_endpoint,
                    "protocol": tp.protocol,
                    "listen_path": format!("/transit/{}", tp.alias),
                    "require_transit_token": false,
                });
                // A Transit Point only mints the surface's managed identity
                // into its outbound request when its own inject_vp is on.
                if surface.managed_identity {
                    point["identity_injection"] = serde_json::json!({ "inject_vp": true });
                }
                // For `fabric://` targets the agent card is fetched from the
                // gateway's own outbound listener. Pin the transit point's
                // `listen_address` to that listener so card-fetch resolves to
                // a reachable URL (mirrors what the dashboard persists).
                if let (true, Some(port)) = (
                    tp.target_endpoint
                        .starts_with("fabric://"),
                    outbound_listener_port,
                ) {
                    point["listen_address"] = serde_json::json!(format!("http://localhost:{port}"));
                }
                if !tp
                    .header_metadata_mapping
                    .headers
                    .is_empty()
                {
                    point["header_metadata_mapping"] = serde_json::json!({
                        "extension_uri": DEFAULT_HEADER_METADATA_EXTENSION_URI,
                        "strip_mapped_headers": tp.header_metadata_mapping.strip_mapped_headers,
                        "headers": tp.header_metadata_mapping.headers.iter().map(|row| {
                            serde_json::json!({
                                "header": &row.header,
                                "field": &row.field,
                            })
                        }).collect::<Vec<_>>()
                    });
                }
                if let Some(fields) = &tp.managed_identity_fields {
                    let mut properties = serde_json::Map::new();
                    for field in fields {
                        properties.insert(field.clone(), serde_json::json!({ "type": "string", "x-identity": true }));
                    }
                    point["managed_identity"] = serde_json::json!({
                        "type": "payload_extraction",
                        "extension_uri": DEFAULT_HEADER_METADATA_EXTENSION_URI,
                        "meta_field": "agentIdentity",
                        "fields": fields,
                        "json_schema": {
                            "type": "object",
                            "properties": properties,
                            "required": fields,
                        }
                    });
                    point["identity_injection"] = serde_json::json!({
                        "inject_vp": true,
                    });
                }
                point
            })
            .collect::<Vec<_>>();
        let mut transit = serde_json::json!({
            "points": points,
        });
        if let Some(port) = outbound_listener_port {
            transit["outbound_listen_address"] = serde_json::json!(format!("http://localhost:{port}"));
        }
        if surface
            .transit_policy_rego
            .is_some()
        {
            transit["opa_policy_definition_id"] = serde_json::json!(transit_policy_definition_id(&surface.surface_id));
        }
        fixture = fixture.with_transit(transit);
    }

    fixture
}
