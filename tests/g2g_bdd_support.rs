#[path = "bdd_support/mod.rs"]
pub mod bdd_support;
#[path = "g2g_bdd/harness/mod.rs"]
pub mod harness;
#[path = "g2g_bdd/world.rs"]
pub mod world;

use std::io::Write;

use bdd_support::config::fabric_gateway_writer::write_fabric_gateway_config;
use bdd_support::config::fabric_surface_fixture::{SourceAuthSpec, SurfaceSpec};
use bdd_support::config::single_surface_fixture::{McpToolPolicyFixture, SurfaceTargetAuthConfig};
use bdd_support::policies::build_mcp_tool_allow_policy;
use world::{FabricLink, FabricRouteProbeStage, TopologyBuilder, fabric_route_probe};

fn topology_with_link(
    source_protocol: &str,
    target: SurfaceSpec,
) -> (TopologyBuilder, FabricLink) {
    let mut topology = TopologyBuilder::default();
    topology
        .plan_mut(1)
        .surfaces
        .push(SurfaceSpec::new("charlie", "/custom-charlie", source_protocol, "fabric://pending/pending"));
    topology
        .plan_mut(2)
        .surfaces
        .push(target);
    let link = FabricLink {
        from_gw: 1,
        from_surface: "charlie".to_string(),
        to_gw: 2,
        to_surface: "alpha".to_string(),
    };
    (topology, link)
}

fn target_surface() -> SurfaceSpec {
    SurfaceSpec::new("alpha", "/alpha", "mcp", "http://target.example")
}

#[test]
fn fabric_route_probe_uses_source_protocol_route_and_api_key_headers() {
    let (mut topology, link) = topology_with_link("mcp", target_surface());
    let source = topology
        .plans
        .get_mut(&1)
        .expect("gateway 1 plan")
        .surfaces
        .first_mut()
        .expect("source surface");
    source.source_auth = Some(SourceAuthSpec::ApiKey {
        header_name: "x-api-key".to_string(),
        secret_id: "source-key".to_string(),
        valid_key: "valid-key".to_string(),
    });

    let probe =
        fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).expect("probe should be built");

    assert_eq!(probe.from_gw, 1);
    assert_eq!(probe.surface_id, "charlie");
    assert_eq!(probe.route, "/custom-charlie");
    assert_eq!(probe.to_gw, 2);
    assert_eq!(probe.peer_surface_id, "alpha");
    assert_eq!(probe.extra_headers, vec![("x-api-key".to_string(), "valid-key".to_string())]);
    assert_eq!(probe.body["method"], "tools/list");
    assert!(probe.expect_target_call);
}

#[test]
fn fabric_route_probe_reaches_an_external_upstream_without_waiting_for_a_mock() {
    let mut target = target_surface();
    target.external_target = true;
    let (topology, link) = topology_with_link("mcp", target);

    let probe =
        fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).expect("probe should be built");

    assert_eq!(probe.body["method"], "tools/list");
    // An MCP surface in front of an external upstream is probed as modern.
    assert!(
        probe.body["params"]
            .get("_meta")
            .is_some()
    );
    assert!(
        probe
            .extra_headers
            .contains(&("MCP-Protocol-Version".to_string(), "2026-07-28".to_string()))
    );
    assert_eq!(probe.sub_path, "");
    assert!(!probe.expect_target_call);
}

#[test]
fn an_mcp_surface_in_front_of_a_mock_target_is_probed_with_legacy_mcp() {
    let (topology, link) = topology_with_link("mcp", target_surface());

    let probe =
        fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).expect("probe should be built");

    assert_eq!(probe.body["method"], "tools/list");
    assert!(
        probe.body["params"]
            .get("_meta")
            .is_none(),
        "the mock target answers only legacy MCP"
    );
    assert!(
        !probe
            .extra_headers
            .iter()
            .any(|(name, _)| name == "MCP-Protocol-Version")
    );
}

#[test]
fn fabric_route_probe_keeps_the_rpc_sub_path_for_mock_targets() {
    let (topology, link) = topology_with_link("mcp", target_surface());

    let probe =
        fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).expect("probe should be built");

    assert_eq!(probe.sub_path, "/rpc");
    assert!(
        probe
            .body
            .get("params")
            .and_then(|params| params.get("_meta"))
            .is_none()
    );
}

#[test]
fn fabric_route_probe_uses_a2a_body_for_a2a_sources() {
    let (topology, link) = topology_with_link("a2a", target_surface());

    let probe =
        fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).expect("probe should be built");

    assert_eq!(probe.body["method"], "message/send");
}

#[test]
fn fabric_route_probe_skips_missing_target_auth_secret() {
    let mut target = target_surface();
    target.target_auth = Some(SurfaceTargetAuthConfig {
        secret_id: "missing".to_string(),
        header_name: "x-target-auth".to_string(),
        header_format: "{value}".to_string(),
        fallback: "reject".to_string(),
        secret_value: None,
    });
    let (topology, link) = topology_with_link("mcp", target);

    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).is_none());
    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::BeforeBlockingPolicies).is_none());
}

#[test]
fn fabric_route_probe_allows_missing_target_auth_secret_when_passthrough() {
    let mut target = target_surface();
    target.target_auth = Some(SurfaceTargetAuthConfig {
        secret_id: "missing".to_string(),
        header_name: "x-target-auth".to_string(),
        header_format: "{value}".to_string(),
        fallback: "passthrough".to_string(),
        secret_value: None,
    });
    let (topology, link) = topology_with_link("mcp", target);

    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::BeforeBlockingPolicies).is_none());
    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).is_some());
}

#[test]
fn fabric_route_probe_uses_allowed_tool_for_mcp_tool_policy_surface() {
    let mut target = target_surface();
    target.mcp_tool_policy = Some(McpToolPolicyFixture {
        allowed_tool: "get_news".to_string(),
        policy_definition_id: "alpha-mcp-tool-policy".to_string(),
        rego: build_mcp_tool_allow_policy("get_news"),
    });
    let (topology, link) = topology_with_link("mcp", target);

    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::BeforeBlockingPolicies).is_none());

    let probe =
        fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).expect("probe should be built");
    assert_eq!(probe.body["method"], "tools/call");
    assert_eq!(probe.body["params"]["name"], "get_news");
}

#[test]
fn write_fabric_gateway_config_seeds_mcp_tool_policy_definition() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let mut surface = target_surface();
    surface.mcp_tool_policy = Some(McpToolPolicyFixture {
        allowed_tool: "get_news".to_string(),
        policy_definition_id: "alpha-mcp-tool-policy".to_string(),
        rego: build_mcp_tool_allow_policy("get_news"),
    });

    write_fabric_gateway_config(temp_dir.path(), 32001, None, &[surface]);

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/alpha.json"),
        )
        .expect("surface json"),
    )
    .expect("parse surface json");
    assert_eq!(surface_json["target"]["mcp_tool_policies_enabled"], true);
    assert_eq!(surface_json["target"]["mcp_tool_policies"][0]["tool_name"], "get_news");
    assert_eq!(surface_json["target"]["mcp_tool_policies"][0]["policy_definition_id"], "alpha-mcp-tool-policy");

    let policy_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/policies/alpha-mcp-tool-policy.json"),
        )
        .expect("policy json"),
    )
    .expect("parse policy json");
    assert_eq!(policy_json["id"], "alpha-mcp-tool-policy");
    assert!(
        policy_json["policy"]
            .as_str()
            .expect("policy source")
            .contains("get_news")
    );
}

#[test]
fn write_fabric_gateway_config_writes_the_gateway_origins_on_mcp_surfaces() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");

    write_fabric_gateway_config(
        temp_dir.path(),
        32006,
        None,
        &[target_surface(), SurfaceSpec::new("bravo", "/bravo", "a2a", "http://bravo.example")],
    );

    let read = |id: &str| -> serde_json::Value {
        serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join(format!("_storage/agent_surfaces/{id}.json")),
            )
            .expect("surface json"),
        )
        .expect("parse surface json")
    };
    let mcp = read("alpha");
    assert!(
        mcp.get("mcp_protocol_mode")
            .is_none()
    );
    assert_eq!(
        mcp["mcp_http"]["allowed_origins"],
        serde_json::json!(["http://localhost:32006", "http://127.0.0.1:32006"])
    );
    let a2a = read("bravo");
    assert!(
        a2a.get("mcp_http")
            .is_none_or(serde_json::Value::is_null)
    );
}

#[test]
fn write_fabric_gateway_config_enables_managed_identity_on_surface_and_transit_points() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let mut surface = SurfaceSpec::new("charlie", "/charlie", "a2a", "http://delta.example");
    surface.managed_identity = true;
    surface
        .transit_points
        .push(bdd_support::config::fabric_surface_fixture::TransitPointSpec::new(
            "tr1",
            "a2a",
            "fabric://pending/pending",
        ));

    write_fabric_gateway_config(temp_dir.path(), 32002, Some(32003), &[surface]);

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/charlie.json"),
        )
        .expect("surface json"),
    )
    .expect("parse surface json");
    assert_eq!(surface_json["target"]["identity_injection"]["inject_vp"], true);
    assert_eq!(surface_json["target"]["identity_injection"]["type"], "from_payload");
    assert_eq!(surface_json["target"]["identity_injection"]["meta_field"], "agentIdentity");
    assert_eq!(surface_json["transit"]["points"][0]["identity_injection"]["inject_vp"], true);
    assert!(
        surface_json["transit"]["points"][0]
            .get("managed_identity")
            .is_none()
    );
}

#[test]
fn write_fabric_gateway_config_leaves_transit_point_identity_injection_off_by_default() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let mut surface = SurfaceSpec::new("charlie", "/charlie", "a2a", "http://delta.example");
    surface
        .transit_points
        .push(bdd_support::config::fabric_surface_fixture::TransitPointSpec::new(
            "tr1",
            "a2a",
            "fabric://pending/pending",
        ));

    write_fabric_gateway_config(temp_dir.path(), 32004, Some(32005), &[surface]);

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/charlie.json"),
        )
        .expect("surface json"),
    )
    .expect("parse surface json");
    assert_eq!(surface_json["target"]["identity_injection"]["inject_vp"], false);
    assert!(
        surface_json["transit"]["points"][0]
            .get("identity_injection")
            .is_none()
    );
}

#[test]
fn fabric_route_probe_runs_after_policies_when_final_policy_allows_link() {
    let (mut topology, link) = topology_with_link("mcp", target_surface());
    topology
        .gateway_allow_only
        .insert(2, 1);

    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::BeforeBlockingPolicies).is_none());
    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).is_some());
}

#[test]
fn fabric_route_probe_runs_before_blocking_policies_when_static_policy_blocks_link() {
    let (mut topology, link) = topology_with_link("mcp", target_surface());
    topology
        .gateway_policies
        .insert(2, "package gateway.policy\ndefault allow := false".to_string());

    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::BeforeBlockingPolicies).is_some());
    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).is_none());
}

#[test]
fn fabric_route_probe_runs_after_allow_only_policy_when_policy_blocks_link() {
    let (mut topology, link) = topology_with_link("mcp", target_surface());
    topology
        .gateway_allow_only
        .insert(2, 3);

    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::BeforeBlockingPolicies).is_none());
    assert!(fabric_route_probe(&topology, &link, FabricRouteProbeStage::AfterPolicies).is_none());
}

#[test]
fn parse_positive_duration_secs_accepts_positive_integers() {
    assert_eq!(harness::multi_gateway::parse_positive_duration_secs("90"), Some(std::time::Duration::from_secs(90)));
}

#[test]
fn parse_positive_duration_secs_rejects_zero_and_invalid_values() {
    assert_eq!(harness::multi_gateway::parse_positive_duration_secs("0"), None);
    assert_eq!(harness::multi_gateway::parse_positive_duration_secs("not-a-number"), None);
}

#[test]
fn truncate_for_diagnostics_preserves_short_values() {
    assert_eq!(harness::multi_gateway::truncate_for_diagnostics("hello", 10), "hello");
}

#[test]
fn truncate_for_diagnostics_truncates_on_char_boundaries() {
    assert_eq!(harness::multi_gateway::truncate_for_diagnostics("åß∂ƒ", 2), "åß…");
}

#[test]
fn tail_file_returns_last_lines_in_original_order() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(file, "one").expect("write line");
    writeln!(file, "two").expect("write line");
    writeln!(file, "three").expect("write line");

    let tail = harness::multi_gateway::tail_file(file.path(), 2).expect("tail file");

    assert_eq!(tail, "two\nthree");
}

// -----------------------------------------------------------------------------
// Gateway restart support (needs the Docker mediator, like the g2g_bdd runner).
// -----------------------------------------------------------------------------

mod restart_support {
    use crate::bdd_support::mediator::managed_mediator_enabled;
    use crate::harness::multi_gateway::{GatewayPlan, MultiGatewayHarness};

    /// A restarted gateway comes back on the same port with the records its
    /// first run persisted, and the admin session is usable again.
    #[test]
    fn restarted_gateway_keeps_its_records_and_port() {
        if !managed_mediator_enabled() {
            eprintln!("[skip] restarted_gateway_keeps_its_records_and_port: set FABRIC_BDD_MANAGED_MEDIATOR=1 to run");
            return;
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let mut harness = MultiGatewayHarness::spawn(vec![GatewayPlan::new()])
                .await
                .expect("spawn one gateway");
            let before = harness
                .gw(1)
                .admin
                .find_self_gateway()
                .await
                .expect("self gateway before restart");
            let port = harness.gw(1).port;

            harness
                .restart_gateway(1)
                .await
                .expect("restart gateway 1");

            let after = harness
                .gw(1)
                .admin
                .find_self_gateway()
                .await
                .expect("self gateway after restart");
            assert_eq!(harness.gw(1).port, port, "restarted gateway should listen on the same port");
            assert_eq!(after.id, before.id, "restarted gateway should read back its persisted self record");
            assert_eq!(after.did, before.did, "restarted gateway should keep its gateway DID");
        });
    }
}
