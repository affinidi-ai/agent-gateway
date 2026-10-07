//! Cucumber `World` for the surface-model G2G framework.
//!
//! Givens declare a *topology* (gateways, surfaces, fabric links, policies)
//! into [`TopologyBuilder`]; the first action step calls [`G2gWorld::start`]
//! which boots the gateways, federates the declared gateway pairs over the
//! scenario mediator, and wires the `fabric://` targets. This lazy-boot mirrors
//! `surface_bdd` (config accrues in Givens, the gateway starts in the When)
//! while supporting the multi-gateway fabric topology.

use std::collections::{BTreeSet, HashMap};

use cucumber::World;
use serde_json::Value;

use crate::bdd_support::actors::ActorRegistry;
use crate::bdd_support::admin_client::GatewayRecord;
use crate::bdd_support::config::fabric_surface_fixture::{SourceAuthSpec, SurfaceSpec};
use crate::bdd_support::json_rpc::{
    IdentityBindingProof, build_a2a_request_body, build_mcp_list_tools_body, build_mcp_tool_call_body,
    build_modern_mcp_list_tools_body, modern_mcp_request_headers,
};
use crate::bdd_support::policies::build_gateway_source_did_allow_policy;
use crate::harness::multi_gateway::{FabricRouteReadyProbe, GatewayPlan, MultiGatewayHarness};

const MODERN_PROBE_VERSION: &str = "2026-07-28";

/// A fabric link: `from_gw`'s `from_surface` forwards to `to_gw`'s
/// `to_surface` over DIDComm once federation is complete.
#[derive(Debug, Clone)]
pub struct FabricLink {
    pub from_gw: usize,
    pub from_surface: String,
    pub to_gw: usize,
    pub to_surface: String,
}

#[derive(Debug, Clone)]
pub struct TransitPointFabricLink {
    pub from_gw: usize,
    pub from_surface: String,
    pub transit_point: String,
    pub to_gw: usize,
    pub to_surface: String,
}

#[derive(Debug, Default)]
pub struct TopologyBuilder {
    pub gateway_count: usize,
    pub plans: HashMap<usize, GatewayPlan>,
    pub fabric_links: Vec<FabricLink>,
    pub transit_point_fabric_links: Vec<TransitPointFabricLink>,
    pub gateway_policies: HashMap<usize, String>,
    /// gw_index -> the only peer gw_index it accepts fabric calls from. The
    /// rego is authored after federation (it needs the peer's DID), so this is
    /// kept separate from the static `gateway_policies`.
    pub gateway_allow_only: HashMap<usize, usize>,
    pub surface_names: HashMap<String, (usize, String)>,
    pub actors: ActorRegistry,
    /// `(gw_index, surface_id, origin_gw)`: the surface also accepts MCP
    /// requests carrying `origin_gw`'s origin. Applied after boot, when the
    /// gateway ports are known.
    pub mcp_origin_grants: Vec<(usize, String, usize)>,
}

impl TopologyBuilder {
    pub fn plan_mut(
        &mut self,
        gw_index: usize,
    ) -> &mut GatewayPlan {
        self.gateway_count = self
            .gateway_count
            .max(gw_index);
        self.plans
            .entry(gw_index)
            .or_default()
    }

    pub fn federation_pairs(
        &self,
        gateway_count: usize,
    ) -> Vec<(usize, usize)> {
        let mut pairs = BTreeSet::new();

        for link in &self.fabric_links {
            pairs.insert(normalize_pair(link.from_gw, link.to_gw));
        }
        for link in &self.transit_point_fabric_links {
            pairs.insert(normalize_pair(link.from_gw, link.to_gw));
        }

        for (gw_index, allowed_from) in &self.gateway_allow_only {
            pairs.insert(normalize_pair(*gw_index, *allowed_from));
        }

        if pairs.is_empty() {
            for inviter_index in 2..=gateway_count {
                for acceptor_index in 1..inviter_index {
                    pairs.insert((inviter_index, acceptor_index));
                }
            }
        }

        pairs.into_iter().collect()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum FabricRouteProbeStage {
    BeforeBlockingPolicies,
    AfterPolicies,
}

pub(crate) fn fabric_route_probe(
    topology: &TopologyBuilder,
    link: &FabricLink,
    stage: FabricRouteProbeStage,
) -> Option<FabricRouteReadyProbe> {
    let expected_stage = fabric_route_probe_stage(topology, link)?;
    if expected_stage != stage {
        return None;
    }

    let source = surface_spec(topology, link.from_gw, &link.from_surface);
    let target = surface_spec(topology, link.to_gw, &link.to_surface);

    let mut extra_headers = source_auth_headers(source);
    let body = match source.protocol.as_str() {
        "a2a" => build_a2a_request_body(),
        // An MCP surface in front of a modern upstream is probed the way its
        // callers reach it, without a protocol session. The mock MCP servers
        // answer only legacy MCP, which every MCP surface also carries, so
        // their routes are probed with legacy MCP.
        "mcp" if target.external_target => {
            extra_headers.extend(modern_mcp_request_headers(MODERN_PROBE_VERSION, "tools/list"));
            build_modern_mcp_list_tools_body(Value::from("fabric-route-probe"), MODERN_PROBE_VERSION, true)
        }
        "mcp" => match target
            .mcp_tool_policy
            .as_ref()
        {
            Some(policy) => build_mcp_tool_call_body(&policy.allowed_tool, serde_json::json!({})),
            None => build_mcp_list_tools_body(),
        },
        _ => return None,
    };

    Some(FabricRouteReadyProbe {
        from_gw: link.from_gw,
        surface_id: link.from_surface.clone(),
        route: source.route.clone(),
        to_gw: link.to_gw,
        peer_surface_id: link.to_surface.clone(),
        body,
        extra_headers,
        // An external upstream serves only its own path and has no mock the
        // probe could watch.
        sub_path: if target.external_target {
            ""
        } else {
            "/rpc"
        },
        expect_target_call: expected_probe_status(topology, link) == 200
            && target.mcp_proxy.is_none()
            && !target.external_target,
        expected_status: expected_probe_status(topology, link),
    })
}

fn expected_probe_status(
    topology: &TopologyBuilder,
    link: &FabricLink,
) -> u16 {
    match topology
        .gateway_allow_only
        .get(&link.to_gw)
    {
        Some(allowed_from) if *allowed_from != link.from_gw => 403,
        _ => 200,
    }
}

fn fabric_route_probe_stage(
    topology: &TopologyBuilder,
    link: &FabricLink,
) -> Option<FabricRouteProbeStage> {
    let target = surface_spec(topology, link.to_gw, &link.to_surface);

    if target
        .target_auth
        .as_ref()
        .is_some_and(|target_auth| {
            target_auth
                .secret_value
                .is_none()
                && target_auth.fallback == "reject"
        })
    {
        return None;
    }

    if topology
        .gateway_policies
        .contains_key(&link.to_gw)
    {
        return Some(FabricRouteProbeStage::BeforeBlockingPolicies);
    }

    match topology
        .gateway_allow_only
        .get(&link.to_gw)
    {
        Some(allowed_from) if *allowed_from == link.from_gw => Some(FabricRouteProbeStage::AfterPolicies),
        Some(_) => None,
        None => Some(FabricRouteProbeStage::AfterPolicies),
    }
}

fn surface_spec<'a>(
    topology: &'a TopologyBuilder,
    gw_index: usize,
    surface_id: &str,
) -> &'a SurfaceSpec {
    topology
        .plans
        .get(&gw_index)
        .unwrap_or_else(|| panic!("no gateway plan for gateway {gw_index}"))
        .surfaces
        .iter()
        .find(|surface| surface.surface_id == surface_id)
        .unwrap_or_else(|| panic!("surface '{surface_id}' not declared on gateway {gw_index}"))
}

fn source_auth_headers(surface: &SurfaceSpec) -> Vec<(String, String)> {
    match &surface.source_auth {
        Some(SourceAuthSpec::ApiKey { header_name, valid_key, .. }) => {
            vec![(header_name.clone(), valid_key.clone())]
        }
        None => Vec::new(),
    }
}

fn normalize_pair(
    left: usize,
    right: usize,
) -> (usize, usize) {
    if left > right {
        (left, right)
    } else {
        (right, left)
    }
}

#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct G2gWorld {
    pub topology: TopologyBuilder,
    pub harness: Option<MultiGatewayHarness>,
    /// Last body sent by the caller.
    pub sent_body: Option<Value>,
    pub response_status: Option<u16>,
    pub response_body: Option<Value>,
    pub response_content_type: Option<String>,
    pub concurrent_requests: Vec<Value>,
    pub concurrent_responses: Vec<ConcurrentResponse>,
    pub fabric_forward_baseline: HashMap<usize, usize>,
    /// Ping outcomes keyed by `(from_gw, to_gw)`.
    pub ping_results: HashMap<(usize, usize), bool>,
    /// Remote gateway records the operator read, keyed by the gateway they
    /// were read from.
    pub remote_gateway_records: HashMap<usize, Vec<GatewayRecord>>,
    /// Outcome of the last issuer request: `(peer gateway index, issuer DID)`.
    pub issuer_request_result: Option<(usize, String)>,
    /// Identity proofs a managed agent obtained from an earlier forwarded
    /// request, keyed by the managed agent that now presents them.
    pub obtained_identity_proofs: HashMap<String, IdentityBindingProof>,
    /// Outcome of the last MCP conformance suite run.
    pub conformance_run: Option<ConformanceRun>,
    /// Requests sent over one Legacy SSE session, each with the SSE reply
    /// that answered it.
    pub legacy_sse_exchange: Vec<(Value, Value)>,
}

#[derive(Debug, Clone)]
pub struct ConformanceRun {
    pub passed: bool,
    pub output: String,
}

#[derive(Debug, Clone)]
pub struct ConcurrentResponse {
    pub request_id: Value,
    pub status: u16,
    pub body: Value,
    pub content_type: Option<String>,
}

impl G2gWorld {
    fn new() -> Self {
        Self {
            topology: TopologyBuilder::default(),
            harness: None,
            sent_body: None,
            response_status: None,
            response_body: None,
            response_content_type: None,
            concurrent_requests: Vec::new(),
            concurrent_responses: Vec::new(),
            fabric_forward_baseline: HashMap::new(),
            ping_results: HashMap::new(),
            remote_gateway_records: HashMap::new(),
            issuer_request_result: None,
            obtained_identity_proofs: HashMap::new(),
            conformance_run: None,
            legacy_sse_exchange: Vec::new(),
        }
    }

    /// Boot gateways, federate the needed pairs, and wire fabric links + policies.
    /// Idempotent: the first action step triggers it; later calls are no-ops.
    pub async fn start(&mut self) {
        if self.harness.is_some() {
            return;
        }

        let count = self
            .topology
            .gateway_count
            .max(1);
        let plans: Vec<GatewayPlan> = (1..=count)
            .map(|i| {
                self.topology
                    .plans
                    .get(&i)
                    .cloned()
                    .unwrap_or_else(GatewayPlan::new)
            })
            .collect();

        let mut harness = MultiGatewayHarness::spawn(plans)
            .await
            .expect("spawn multi-gateway harness");
        let federation_pairs = self
            .topology
            .federation_pairs(count);
        harness
            .federate_pairs(&federation_pairs)
            .await
            .expect("federate declared gateway pairs");

        for (gw_index, surface_id, origin_gw) in &self
            .topology
            .mcp_origin_grants
        {
            harness
                .accept_mcp_origins_of(*gw_index, surface_id, *origin_gw)
                .await
                .expect("allowlist the peer gateway's MCP origins");
        }

        for link in &self.topology.fabric_links {
            harness
                .point_surface_at_peer(link.from_gw, &link.from_surface, link.to_gw, &link.to_surface)
                .await
                .expect("wire fabric link");
        }
        for link in &self
            .topology
            .transit_point_fabric_links
        {
            harness
                .point_transit_point_at_peer(
                    link.from_gw,
                    &link.from_surface,
                    &link.transit_point,
                    link.to_gw,
                    &link.to_surface,
                )
                .await
                .expect("wire Transit Point fabric link");
        }

        self.wait_for_fabric_routes(&harness, FabricRouteProbeStage::BeforeBlockingPolicies)
            .await;

        for (gw_index, rego) in &self.topology.gateway_policies {
            harness
                .set_gateway_policy(*gw_index, Some(rego))
                .await
                .expect("install gateway policy");
        }

        // Per-caller allow-only policies use the receiver-side canonical peer
        // DID, which only exists after federation.
        for (gw_index, allowed_from) in &self
            .topology
            .gateway_allow_only
        {
            let did = harness
                .remote_peer_did(*gw_index, *allowed_from)
                .expect("allowed gateway canonical DID must be discoverable");
            let rego = build_gateway_source_did_allow_policy(did);
            harness
                .set_gateway_policy(*gw_index, Some(&rego))
                .await
                .expect("install allow-only gateway policy");
        }

        self.wait_for_fabric_routes(&harness, FabricRouteProbeStage::AfterPolicies)
            .await;

        self.harness = Some(harness);
    }

    async fn wait_for_fabric_routes(
        &self,
        harness: &MultiGatewayHarness,
        stage: FabricRouteProbeStage,
    ) {
        for link in &self.topology.fabric_links {
            if let Some(probe) = fabric_route_probe(&self.topology, link, stage) {
                harness
                    .wait_for_fabric_route_ready(&probe)
                    .await
                    .unwrap_or_else(|error| panic!("fabric link was not ready before scenario action: {error:#}"));
            }
        }
    }

    /// Resolve a friendly surface name to `(gw_index, surface_id)`.
    pub fn surface(
        &self,
        name: &str,
    ) -> (usize, String) {
        self.topology
            .surface_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("unknown surface '{name}'"))
    }

    /// Resolve a friendly target collaborator name to its backing `(gw_index, surface_id)`.
    pub fn target(
        &self,
        name: &str,
    ) -> (usize, String) {
        let binding = self
            .topology
            .actors
            .target_surface_binding(name);
        (binding.gateway_index, binding.surface_id.clone())
    }

    pub fn harness(&self) -> &MultiGatewayHarness {
        self.harness
            .as_ref()
            .expect("harness not started; an action step must call G2gWorld::start first")
    }

    pub fn harness_mut(&mut self) -> &mut MultiGatewayHarness {
        self.harness
            .as_mut()
            .expect("harness not started; an action step must call G2gWorld::start first")
    }

    /// The Fabric link declared for a Transit Point alias.
    pub fn transit_point_link(
        &self,
        transit_point: &str,
    ) -> &TransitPointFabricLink {
        self.topology
            .transit_point_fabric_links
            .iter()
            .find(|link| link.transit_point == transit_point)
            .unwrap_or_else(|| panic!("Transit Point '{transit_point}' is not configured over Fabric"))
    }

    /// The Transit Point through which a managed agent's surface reaches the Fabric.
    pub fn transit_point_of_managed_agent(
        &self,
        agent_name: &str,
    ) -> &TransitPointFabricLink {
        let (gw_index, surface_id) = self.target(agent_name);
        self.topology
            .transit_point_fabric_links
            .iter()
            .find(|link| link.from_gw == gw_index && link.from_surface == surface_id)
            .unwrap_or_else(|| panic!("managed agent '{agent_name}' has no Transit Point over Fabric"))
    }

    pub fn surface_spec(
        &self,
        gw_index: usize,
        surface_id: &str,
    ) -> &SurfaceSpec {
        surface_spec(&self.topology, gw_index, surface_id)
    }

    /// Poll gateway `from_gw`'s Remote record for gateway `to_gw` until its
    /// `issuer_did` is `Some` or `timeout` elapses; returns the last record
    /// read either way. Issuer reconciliation runs in the background after a
    /// listener registers, so a fresh record may be populated a moment later.
    pub async fn wait_for_recorded_issuer_did(
        &self,
        from_gw: usize,
        to_gw: usize,
        timeout: std::time::Duration,
    ) -> GatewayRecord {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let record = self
                .harness()
                .remote_gateway_record(from_gw, to_gw)
                .await
                .unwrap_or_else(|error| panic!("{error:#}"));
            if record.issuer_did.is_some() || tokio::time::Instant::now() >= deadline {
                return record;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    pub async fn remember_fabric_forward_baseline(&mut self) {
        let Some(harness) = self.harness.as_ref() else {
            return;
        };
        self.fabric_forward_baseline
            .clear();
        for gateway_index in 1..=self
            .topology
            .gateway_count
            .max(1)
        {
            let count = harness
                .fabric_forward_request_count(gateway_index)
                .await;
            self.fabric_forward_baseline
                .insert(gateway_index, count);
        }
    }

    pub fn expects_allow_only_denial(
        &self,
        gw_index: usize,
        surface_id: &str,
    ) -> bool {
        self.topology
            .fabric_links
            .iter()
            .find(|link| link.from_gw == gw_index && link.from_surface == surface_id)
            .and_then(|link| {
                self.topology
                    .gateway_allow_only
                    .get(&link.to_gw)
                    .map(|allowed_from| *allowed_from != link.from_gw)
            })
            .unwrap_or(false)
    }
}
