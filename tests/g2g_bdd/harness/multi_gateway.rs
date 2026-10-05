//! Multi-gateway orchestration for the surface model. Boots N real
//! `agent-gateway` processes (each with its own agent surfaces, mock
//! target collaborator, and admin client), federates the scenario-required pairs over the
//! scenario mediator, and rewrites `fabric://` surface targets once remote
//! gateway ids are known.
//!
//! 1-indexed accessors (`gw(1)`, `gw(2)`) keep step definitions aligned with
//! Gherkin's `gateway 1`, `gateway 2`, `gateway 3` coordinates.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde_json::Value;
use url::Url;

use crate::bdd_support::admin_client::{ExternalMediatorBlob, GatewayAdminClient, GatewayRecord, GatewayStatus};
use crate::bdd_support::config;
use crate::bdd_support::config::ReservedPort;
use crate::bdd_support::config::fabric_surface_fixture::SurfaceSpec;
use crate::bdd_support::gateway_process::GatewayProcess;
use crate::bdd_support::mock_server::MockServer;
use crate::bdd_support::temp::{TempDirGuard, create_project_temp_dir};

use crate::bdd_support::mediator::{Mediator, ScenarioDockerMediator};

const FEDERATION_SECRET: &str = "g2g-bdd-secret";
const FEDERATION_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_FABRIC_ROUTE_READY_TIMEOUT_SECS: u64 = 90;
const FABRIC_ROUTE_READY_TIMEOUT_ENV: &str = "G2G_BDD_FABRIC_ROUTE_READY_TIMEOUT_SECS";
const FABRIC_ROUTE_READY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const CHANNEL_RELOAD_SETTLE: Duration = Duration::from_millis(300);
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Prometheus counter each gateway exposes for received fabric (gateway-to-gateway)
/// forward requests. Scraped to observe receipt without parsing gateway logs.
const FABRIC_FORWARD_RECEIVED_METRIC: &str = "agent_gateway_fabric_forward_requests_received_total";

pub struct GatewayNode {
    pub admin: GatewayAdminClient,
    pub mocks: HashMap<String, MockServer>,
    pub base_dir: PathBuf,
    pub port: u16,
    pub outbound_port: Option<u16>,
    pub mediator_id: String,
    extra_env: HashMap<String, String>,
    _temp_dir: TempDirGuard,
    gateway: GatewayProcess,
}

impl std::fmt::Debug for GatewayNode {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("GatewayNode")
            .field("port", &self.port)
            .field("outbound_port", &self.outbound_port)
            .field("mediator_id", &self.mediator_id)
            .finish()
    }
}

impl GatewayNode {
    pub fn mock(
        &self,
        surface_id: &str,
    ) -> Option<&MockServer> {
        self.mocks.get(surface_id)
    }

    /// Stop the gateway process and start it again on the same storage
    /// directory, config and port, then re-establish the admin session. Every
    /// record the first run persisted (gateways, connection points, surfaces)
    /// is read back from disk by the new process.
    pub async fn restart(&mut self) -> Result<()> {
        let config_path = self
            .base_dir
            .join("config.toml");
        let restarted =
            GatewayProcess::start_g2g_with_env(&config_path, &self.base_dir, &self.extra_env).with_port(self.port);
        // Dropping the previous process kills it before the replacement binds the port.
        self.gateway = restarted;
        self.gateway
            .try_wait_until_ready(READY_TIMEOUT)
            .await
            .with_context(|| format!("restarted gateway on port {} did not accept connections", self.port))?;
        self.admin
            .wait_until_healthy(READY_TIMEOUT)
            .await
            .with_context(|| format!("restarted gateway on port {} did not report healthy", self.port))?;
        self.admin
            .bootstrap_test_session()
            .await
            .with_context(|| format!("bootstrap test session on restarted gateway port {}", self.port))
    }
}

#[derive(Debug, Clone, Default)]
pub struct GatewayPlan {
    pub surfaces: Vec<SurfaceSpec>,
    pub mock_responses: HashMap<String, serde_json::Value>,
    pub mock_response_delays: HashMap<String, (u64, u64)>,
}

impl GatewayPlan {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct FabricRouteReadyProbe {
    pub from_gw: usize,
    pub surface_id: String,
    pub route: String,
    pub to_gw: usize,
    pub peer_surface_id: String,
    pub body: Value,
    pub extra_headers: Vec<(String, String)>,
    /// Appended to the route. An Access Point forwards the sub-path, which a
    /// mock ignores but an external upstream serving one path does not.
    pub sub_path: &'static str,
    pub expect_target_call: bool,
    pub expected_status: u16,
}

/// Owns N gateway nodes plus the scenario mediator and the directional federation
/// views built by `federate_pairs`.
#[derive(Debug)]
pub struct MultiGatewayHarness {
    nodes: Vec<GatewayNode>,
    remote_views: HashMap<(usize, usize), GatewayRecord>,
    #[allow(dead_code)]
    pub mediator: Box<dyn Mediator>,
}

impl MultiGatewayHarness {
    /// Boot one gateway per plan. Mocks are started first so surface targets
    /// can point at them; `fabric://` targets are left as written and wired up
    /// later by `point_surface_at_peer`.
    pub async fn spawn(plans: Vec<GatewayPlan>) -> Result<Self> {
        if plans.is_empty() {
            bail!("MultiGatewayHarness::spawn requires at least one gateway plan");
        }

        let mediator: Box<dyn Mediator> = Box::new(ScenarioDockerMediator::start().await?);

        let mut nodes = Vec::with_capacity(plans.len());
        for (offset, plan) in plans.into_iter().enumerate() {
            let index = offset + 1;
            let node = spawn_node(&format!("g2g-gw{index}"), plan, &*mediator, index)
                .await
                .with_context(|| format!("spawn gateway {index}"))?;
            nodes.push(node);
        }

        Ok(Self {
            nodes,
            remote_views: HashMap::new(),
            mediator,
        })
    }

    /// 1-indexed accessor.
    pub fn gw(
        &self,
        one_based_index: usize,
    ) -> &GatewayNode {
        let i = one_based_index
            .checked_sub(1)
            .expect("gateway index must be 1-based");
        self.nodes
            .get(i)
            .unwrap_or_else(|| panic!("no gateway at index {one_based_index}; harness has {}", self.nodes.len()))
    }

    /// Restart one gateway in place (same storage, config and port). Remote
    /// gateway ids recorded at federation stay valid because they are persisted.
    pub async fn restart_gateway(
        &mut self,
        one_based_index: usize,
    ) -> Result<()> {
        let i = one_based_index
            .checked_sub(1)
            .expect("gateway index must be 1-based");
        let node = self
            .nodes
            .get_mut(i)
            .with_context(|| format!("no gateway at index {one_based_index}"))?;
        node.restart()
            .await
            .with_context(|| format!("restart gateway {one_based_index}"))
    }

    /// The DID gateway `index` signs identity credentials with, read from its
    /// own Self gateway record.
    pub async fn self_gateway_did(
        &self,
        index: usize,
    ) -> Result<String> {
        self.gw(index)
            .admin
            .find_self_gateway()
            .await
            .with_context(|| format!("locate gateway {index} self gateway"))?
            .did
            .with_context(|| format!("gateway {index} self gateway record has no DID"))
    }

    /// Read gateway `from_index`'s current Remote record for gateway `to_index`.
    pub async fn remote_gateway_record(
        &self,
        from_index: usize,
        to_index: usize,
    ) -> Result<GatewayRecord> {
        let remote_id = self
            .remote_id(from_index, to_index)
            .map(str::to_string)
            .with_context(|| {
                format!("no remote gateway id for gateway {to_index} from gateway {from_index}; federate first")
            })?;
        self.gw(from_index)
            .admin
            .get_gateway(&remote_id)
            .await
            .with_context(|| format!("read gateway {from_index}'s record for gateway {to_index}"))
    }

    /// Number of fabric forward requests received by `gateway_index`, read from
    /// that gateway's own Prometheus counter and summed across destination
    /// surfaces. Returns 0 when the counter is absent (the gateway has never
    /// received a fabric forward). Harness-owned observation point: it scrapes
    /// the metrics endpoint rather than parsing `gateway.log`.
    pub async fn fabric_forward_request_count(
        &self,
        gateway_index: usize,
    ) -> usize {
        let exposition = self
            .gw(gateway_index)
            .admin
            .prometheus_metrics()
            .await
            .unwrap_or_default();
        sum_prometheus_counter(&exposition, FABRIC_FORWARD_RECEIVED_METRIC)
    }

    /// The `from` gateway's id for the `to` gateway after federation.
    pub fn remote_id(
        &self,
        from_index: usize,
        to_index: usize,
    ) -> Option<&str> {
        self.remote_views
            .get(&(from_index, to_index))
            .map(|record| record.id.as_str())
    }

    /// The DID `from_gw` holds for `to_gw` after federation. This is the DID
    /// `to_gw` sees as the caller (`input.gateway.source_id`) when `from_gw`
    /// forwards a request over the fabric — used to author per-caller policies.
    pub fn remote_peer_did(
        &self,
        from_index: usize,
        to_index: usize,
    ) -> Option<&str> {
        self.remote_views
            .get(&(from_index, to_index))
            .and_then(|record| record.did.as_deref())
    }

    /// GW `from_index` pings GW `to_index` over the fabric (admin trust-ping),
    /// retrying until success or timeout.
    pub async fn ping(
        &self,
        from_index: usize,
        to_index: usize,
    ) -> Result<bool> {
        let remote_id = self
            .remote_id(from_index, to_index)
            .map(str::to_string)
            .with_context(|| {
                format!("no remote gateway id for gateway {to_index} from gateway {from_index}; federate first")
            })?;
        let response = self
            .gw(from_index)
            .admin
            .wait_for_ping_success(&remote_id, FEDERATION_TIMEOUT)
            .await
            .with_context(|| format!("gateway {from_index} ping gateway {to_index}"))?;
        Ok(response.success)
    }

    /// Federate gateway pairs as `(inviter_index, acceptor_index)`.
    pub async fn federate_pairs(
        &mut self,
        pairs: &[(usize, usize)],
    ) -> Result<()> {
        let did_method = self
            .mediator
            .did_method()
            .to_string();
        for (inviter_index, acceptor_index) in pairs {
            self.federate_pair(*inviter_index, *acceptor_index, &did_method)
                .await
                .with_context(|| format!("federate gateway {inviter_index} (inviter) with gateway {acceptor_index}"))?;
        }
        Ok(())
    }

    async fn federate_pair(
        &mut self,
        inviter_index: usize,
        acceptor_index: usize,
        did_method: &str,
    ) -> Result<()> {
        let inviter = self.gw(inviter_index);
        let acceptor = self.gw(acceptor_index);
        let inviter_existing_remotes = inviter
            .admin
            .remote_gateway_ids()
            .await
            .with_context(|| format!("list existing remotes on gateway {inviter_index}"))?;
        let acceptor_existing_remotes = acceptor
            .admin
            .remote_gateways()
            .await
            .with_context(|| format!("list existing remotes on gateway {acceptor_index}"))?;
        let inviter_self = inviter
            .admin
            .find_self_gateway()
            .await
            .with_context(|| format!("locate gateway {inviter_index} self gateway"))?;

        let connection_point = inviter
            .admin
            .create_connection_point(
                &inviter_self.id,
                &inviter.mediator_id,
                &format!("g2g-bdd-cp-gw{inviter_index}-to-gw{acceptor_index}"),
                &format!("gateway {inviter_index} inviter connection point for gateway {acceptor_index}"),
                FEDERATION_SECRET,
                did_method,
            )
            .await
            .with_context(|| format!("gateway {inviter_index} create connection point"))?;

        let inviter_view_name = format!("gateway {acceptor_index} from gateway {inviter_index}");

        let acceptor_view = acceptor
            .admin
            .connect_via_oob(
                &connection_point.oob_url,
                FEDERATION_SECRET,
                &format!("gateway {inviter_index} from gateway {acceptor_index}"),
                &format!("gateway {acceptor_index}'s view of gateway {inviter_index}"),
                did_method,
            )
            .await
            .with_context(|| format!("gateway {acceptor_index} connect via OOB to gateway {inviter_index}"))?;

        let inviter_view = inviter
            .admin
            .wait_for_new_remote_gateway_status(
                &inviter_existing_remotes,
                GatewayStatus::AwaitingApproval,
                FEDERATION_TIMEOUT,
            )
            .await
            .with_context(|| format!("gateway {inviter_index} awaits approval from gateway {acceptor_index}"))?;

        inviter
            .admin
            .approve_gateway(
                &inviter_view.id,
                &inviter_view_name,
                &format!("gateway {inviter_index}'s view of gateway {acceptor_index}"),
            )
            .await
            .with_context(|| format!("gateway {inviter_index} approves gateway {acceptor_index}"))?;

        let acceptor_view_active = match acceptor
            .admin
            .wait_for_gateway_status(&acceptor_view.id, GatewayStatus::Active, FEDERATION_TIMEOUT)
            .await
        {
            Ok(gateway) => gateway,
            Err(id_error) => match acceptor
                .admin
                .wait_for_changed_remote_gateway(&acceptor_existing_remotes, GatewayStatus::Active, FEDERATION_TIMEOUT)
                .await
            {
                Ok(gateway) => gateway,
                Err(changed_error) => acceptor
                    .admin
                    .wait_for_remote_gateway(GatewayStatus::Active, FEDERATION_TIMEOUT)
                    .await
                    .with_context(|| {
                        format!(
                            "gateway {acceptor_index} sees gateway {inviter_index} Active; original id wait failed: {id_error}; changed-remote wait failed: {changed_error}"
                        )
                    })?,
            },
        };

        let inviter_view_active = inviter
            .admin
            .wait_for_gateway_status(&inviter_view.id, GatewayStatus::Active, FEDERATION_TIMEOUT)
            .await
            .with_context(|| format!("gateway {inviter_index} sees gateway {acceptor_index} Active"))?;

        self.remote_views
            .insert((acceptor_index, inviter_index), acceptor_view_active);
        self.remote_views
            .insert((inviter_index, acceptor_index), inviter_view_active);
        Ok(())
    }

    /// Point `from_gw`'s `surface_id` at `to_gw`'s `peer_surface_id` over the
    /// fabric, then publish `peer_surface_id` as an exposed surface on `to_gw`.
    ///
    /// The fabric target is applied via the surface admin API (GET → patch
    /// `target.endpoint` → PUT) rather than a file rewrite + config reload:
    /// the surface PUT handler refreshes the resolved-surface cache the request
    /// pipeline reads from, whereas the per-surface reload only rebuilds the
    /// listener and leaves the cached target stale.
    pub async fn point_surface_at_peer(
        &self,
        from_gw: usize,
        surface_id: &str,
        to_gw: usize,
        peer_surface_id: &str,
    ) -> Result<()> {
        let remote_id = self
            .remote_id(from_gw, to_gw)
            .map(str::to_string)
            .with_context(|| {
                format!("no remote gateway id for gateway {to_gw} from gateway {from_gw}; federate first")
            })?;
        let fabric_target = format!("fabric://{remote_id}/{peer_surface_id}");

        let from = self.gw(from_gw);
        let mut surface = from
            .admin
            .get_surface(surface_id)
            .await
            .with_context(|| format!("fetch surface {surface_id} on gateway {from_gw}"))?;
        surface["target"]["endpoint"] = serde_json::Value::String(fabric_target);
        from.admin
            .update_surface(surface_id, &surface)
            .await
            .with_context(|| format!("update surface {surface_id} target on gateway {from_gw}"))?;
        tokio::time::sleep(CHANNEL_RELOAD_SETTLE).await;

        // Publish the destination surface so the receiving gateway accepts fabric forwards to it.
        let to = self.gw(to_gw);
        let self_gw = to
            .admin
            .find_self_gateway()
            .await
            .with_context(|| format!("locate gateway {to_gw} self gateway"))?;
        to.admin
            .update_gateway_exposed_surfaces(&self_gw.id, vec![peer_surface_id.to_string()])
            .await
            .with_context(|| format!("publish exposed surface {peer_surface_id} on gateway {to_gw}"))?;
        tokio::time::sleep(CHANNEL_RELOAD_SETTLE).await;
        Ok(())
    }

    /// Add `origin_gw`'s origins to the `mcp_http.allowed_origins` of
    /// `gw_index`'s `surface_id`. A Fabric receiver checks a forwarded Origin
    /// against its own allowlist, so a caller Origin the sending gateway
    /// accepts must be allowlisted on both.
    pub async fn accept_mcp_origins_of(
        &self,
        gw_index: usize,
        surface_id: &str,
        origin_gw: usize,
    ) -> Result<()> {
        let port = self.gw(origin_gw).port;
        let admin = &self.gw(gw_index).admin;
        let mut surface = admin
            .get_surface(surface_id)
            .await
            .with_context(|| format!("fetch surface {surface_id} on gateway {gw_index}"))?;
        let origins = surface["mcp_http"]["allowed_origins"]
            .as_array_mut()
            .with_context(|| format!("surface {surface_id} on gateway {gw_index} has no MCP Origin allowlist"))?;
        for origin in [format!("http://localhost:{port}"), format!("http://127.0.0.1:{port}")] {
            origins.push(Value::String(origin));
        }
        admin
            .update_surface(surface_id, &surface)
            .await
            .with_context(|| format!("update surface {surface_id} MCP origins on gateway {gw_index}"))?;
        tokio::time::sleep(CHANNEL_RELOAD_SETTLE).await;
        Ok(())
    }

    /// Point one Transit Point on `from_gw`'s `surface_id` at `to_gw`'s
    /// `peer_surface_id` over Fabric, then publish the destination surface.
    pub async fn point_transit_point_at_peer(
        &self,
        from_gw: usize,
        surface_id: &str,
        transit_point_alias: &str,
        to_gw: usize,
        peer_surface_id: &str,
    ) -> Result<()> {
        let remote_id = self
            .remote_id(from_gw, to_gw)
            .map(str::to_string)
            .with_context(|| {
                format!("no remote gateway id for gateway {to_gw} from gateway {from_gw}; federate first")
            })?;
        let fabric_target = format!("fabric://{remote_id}/{peer_surface_id}");

        let from = self.gw(from_gw);
        let mut surface = from
            .admin
            .get_surface(surface_id)
            .await
            .with_context(|| format!("fetch surface {surface_id} on gateway {from_gw}"))?;
        let points = surface
            .get_mut("transit")
            .and_then(|transit| transit.get_mut("points"))
            .and_then(serde_json::Value::as_array_mut)
            .with_context(|| format!("surface {surface_id} on gateway {from_gw} has no transit.points array"))?;
        let point = points
            .iter_mut()
            .find(|point| {
                point
                    .get("alias")
                    .and_then(serde_json::Value::as_str)
                    == Some(transit_point_alias)
            })
            .with_context(|| {
                format!("surface {surface_id} on gateway {from_gw} has no Transit Point '{transit_point_alias}'")
            })?;
        point["target_endpoint"] = serde_json::Value::String(fabric_target);
        from.admin
            .update_surface(surface_id, &surface)
            .await
            .with_context(|| {
                format!("update Transit Point {transit_point_alias} target on surface {surface_id} gateway {from_gw}")
            })?;
        tokio::time::sleep(CHANNEL_RELOAD_SETTLE).await;

        let to = self.gw(to_gw);
        let self_gw = to
            .admin
            .find_self_gateway()
            .await
            .with_context(|| format!("locate gateway {to_gw} self gateway"))?;
        to.admin
            .update_gateway_exposed_surfaces(&self_gw.id, vec![peer_surface_id.to_string()])
            .await
            .with_context(|| format!("publish exposed surface {peer_surface_id} on gateway {to_gw}"))?;
        tokio::time::sleep(CHANNEL_RELOAD_SETTLE).await;
        Ok(())
    }

    /// Probe the real caller-facing `fabric://` path until the request/reply
    /// route is usable. Admin trust-ping proves DIDComm connectivity, but the
    /// first application request can still race listener/cache settlement; this
    /// readiness probe warms that exact path and clears mock history before the
    /// scenario assertions run.
    pub async fn wait_for_fabric_route_ready(
        &self,
        probe: &FabricRouteReadyProbe,
    ) -> Result<()> {
        let target_mock = self
            .gw(probe.to_gw)
            .mock(&probe.peer_surface_id);
        if let Some(mock) = target_mock {
            mock.clear_requests().await;
        }

        let route = probe
            .route
            .trim_end_matches('/');
        let route = if route.starts_with('/') {
            route.to_string()
        } else {
            format!("/{route}")
        };
        let url = format!("http://127.0.0.1:{}{route}{}", self.gw(probe.from_gw).port, probe.sub_path);
        let ready_timeout = fabric_route_ready_timeout();
        let deadline = tokio::time::Instant::now() + ready_timeout;
        let client = Client::new();
        let mut attempt = 0usize;

        loop {
            attempt += 1;
            let mut request = client
                .post(&url)
                .header("content-type", "application/json")
                .json(&probe.body);
            for (name, value) in &probe.extra_headers {
                request = request.header(name, value);
            }

            match tokio::time::timeout(FABRIC_ROUTE_READY_ATTEMPT_TIMEOUT, request.send()).await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    let response_body = response
                        .text()
                        .await
                        .unwrap_or_default();
                    let target_count = match target_mock {
                        Some(mock) => mock.request_count().await,
                        None => 0,
                    };
                    if status == probe.expected_status && (!probe.expect_target_call || target_count > 0) {
                        if let Some(mock) = target_mock {
                            mock.clear_requests().await;
                        }
                        return Ok(());
                    }
                    let last_observation = format!(
                        "attempt {attempt}: status={status}, target_count={target_count}, body={}",
                        truncate_for_diagnostics(&response_body, 600)
                    );
                    if tokio::time::Instant::now() >= deadline {
                        bail!(
                            "fabric route gateway {}:{} -> gateway {}:{} did not become ready within {:?}: {last_observation}\n{}",
                            probe.from_gw,
                            probe.surface_id,
                            probe.to_gw,
                            probe.peer_surface_id,
                            ready_timeout,
                            self.fabric_diagnostics()
                                .await
                        );
                    }
                }
                Ok(Err(error)) => {
                    let last_observation = format!("attempt {attempt}: transport error: {error}");
                    if tokio::time::Instant::now() >= deadline {
                        bail!(
                            "fabric route gateway {}:{} -> gateway {}:{} did not become ready within {:?}: {last_observation}\n{}",
                            probe.from_gw,
                            probe.surface_id,
                            probe.to_gw,
                            probe.peer_surface_id,
                            ready_timeout,
                            self.fabric_diagnostics()
                                .await
                        );
                    }
                }
                Err(_) => {
                    let last_observation = format!(
                        "attempt {attempt}: request timed out after {}ms",
                        FABRIC_ROUTE_READY_ATTEMPT_TIMEOUT.as_millis()
                    );
                    if tokio::time::Instant::now() >= deadline {
                        bail!(
                            "fabric route gateway {}:{} -> gateway {}:{} did not become ready within {:?}: {last_observation}\n{}",
                            probe.from_gw,
                            probe.surface_id,
                            probe.to_gw,
                            probe.peer_surface_id,
                            ready_timeout,
                            self.fabric_diagnostics()
                                .await
                        );
                    }
                }
            }

            if let Some(mock) = target_mock {
                mock.clear_requests().await;
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn fabric_diagnostics(&self) -> String {
        let mut sections = Vec::new();
        for (offset, node) in self.nodes.iter().enumerate() {
            let index = offset + 1;
            let gateways = node
                .admin
                .describe_gateways()
                .await
                .unwrap_or_else(|error| format!("failed to list gateways: {error}"));
            let log_tail = tail_file(
                &node
                    .base_dir
                    .join("gateway.log"),
                80,
            )
            .unwrap_or_else(|error| format!("failed to read gateway.log: {error}"));
            sections.push(format!(
                "gateway {index} port={} mediator_id={} gateways=[{}]\n--- gateway.log tail ---\n{}",
                node.port, node.mediator_id, gateways, log_tail
            ));
        }
        sections.join("\n\n")
    }

    /// Install (or clear) a gateway-level OPA policy on `gw_index`. Used for
    /// the "gateway 2 accepts only gateway 1" boundary: a deny-all or allow-from
    /// policy is enforced on the receiving gateway's fabric path (`data.gateway.policy.allow`).
    pub async fn set_gateway_policy(
        &self,
        gw_index: usize,
        rego: Option<&str>,
    ) -> Result<()> {
        let node = self.gw(gw_index);
        let self_gw = node
            .admin
            .find_self_gateway()
            .await
            .with_context(|| format!("locate self gateway for gateway {gw_index} policy update"))?;
        match rego {
            Some(rego) => {
                node.admin
                    .set_gateway_policy(&self_gw.id, true, rego)
                    .await
                    .with_context(|| format!("enable gateway OPA on gateway {gw_index}"))?;
            }
            None => {
                node.admin
                    .set_gateway_policy(&self_gw.id, false, "")
                    .await
                    .with_context(|| format!("clear gateway OPA on gateway {gw_index}"))?;
            }
        }
        Ok(())
    }
}

async fn spawn_node(
    name: &str,
    plan: GatewayPlan,
    mediator: &dyn Mediator,
    index: usize,
) -> Result<GatewayNode> {
    // Start a mock per surface that needs one, then patch the surface target to
    // the mock URL before writing config.
    let mut mocks: HashMap<String, MockServer> = HashMap::new();
    let mut surfaces = plan.surfaces.clone();
    for surface in surfaces.iter_mut() {
        if let Some(response) = plan
            .mock_responses
            .get(&surface.surface_id)
        {
            let mock = MockServer::start(response.clone()).await;
            if let Some((min_ms, max_ms)) = plan
                .mock_response_delays
                .get(&surface.surface_id)
            {
                mock.set_response_delay(*min_ms, *max_ms)
                    .await;
            }
            match &mut surface.mcp_proxy {
                // Proxy-backed surfaces keep their `proxy://` target; the mock
                // is the proxy's REST API target endpoint (its `base_url`).
                Some(proxy) => proxy.target_url = mock.url(),
                // Plain surfaces forward directly to the mock URL.
                None => surface.target_endpoint = mock.url(),
            }
            mocks.insert(surface.surface_id.clone(), mock);
        }
    }

    let (gateway_port, mut port_reservation) = config::reserve_free_port("");
    let needs_outbound_listener = surfaces
        .iter()
        .any(|surface| {
            !surface
                .transit_points
                .is_empty()
        });
    let (outbound_port, mut outbound_port_reservation): (Option<u16>, Option<ReservedPort>) = if needs_outbound_listener
    {
        let (port, reservation) = config::reserve_free_port("");
        (Some(port), Some(reservation))
    } else {
        (None, None)
    };
    let temp_dir = create_project_temp_dir(name)?;
    config::fabric_gateway_writer::write_fabric_gateway_config(temp_dir.path(), gateway_port, outbound_port, &surfaces);

    let config_path = temp_dir
        .path()
        .join("config.toml");
    port_reservation.release_listener();
    if let Some(reservation) = &mut outbound_port_reservation {
        reservation.release_listener();
    }
    let mut extra_env: HashMap<String, String> = HashMap::new();
    if let Some(allowlist) = mediator_egress_allowlist(mediator) {
        extra_env.insert("AG_BDD_EGRESS_ALLOWLIST".to_string(), allowlist);
    }
    let mut gateway = GatewayProcess::start_g2g_with_env(&config_path, temp_dir.path(), &extra_env);
    gateway = gateway
        .with_port(gateway_port)
        .with_port_reservation(port_reservation);

    if let Err(e) = gateway
        .try_wait_until_ready(READY_TIMEOUT)
        .await
    {
        let kept = temp_dir.keep();
        eprintln!("[harness] {name} TCP wait failed; preserving temp dir at {}", kept.display());
        bail!("{e}");
    }
    let admin = GatewayAdminClient::new(gateway_port);
    if let Err(e) = admin
        .wait_until_healthy(READY_TIMEOUT)
        .await
    {
        let kept = temp_dir.keep();
        eprintln!("[harness] {name} health failed; preserving temp dir at {}", kept.display());
        return Err(e).with_context(|| format!("wait for {name} health endpoint"));
    }

    if let Err(e) = admin
        .bootstrap_test_session()
        .await
    {
        let kept = temp_dir.keep();
        eprintln!("[harness] {name} test-session bootstrap failed; preserving temp dir at {}", kept.display());
        return Err(e).with_context(|| format!("bootstrap test session for {name}"));
    }

    let mediator_record = admin
        .create_mediator(
            &format!("g2g-bdd-mediator-gw{index}"),
            &format!("Mediator used by gateway {index}"),
            &ExternalMediatorBlob {
                did: mediator.did().to_string(),
                did_document: mediator
                    .did_document()
                    .cloned(),
            },
        )
        .await
        .with_context(|| format!("create mediator record on {name}"))?;

    Ok(GatewayNode {
        admin,
        mocks,
        base_dir: temp_dir.path().to_path_buf(),
        port: gateway_port,
        outbound_port,
        mediator_id: mediator_record.id,
        extra_env,
        _temp_dir: TempDirGuard::new(temp_dir, name),
        gateway,
    })
}

/// Exact mediator DID-document probe URLs to allow-list so `EgressPolicy::Strict`
/// permits only the harness's loopback mediator fetch (`fetch_mediator_did_from_url`).
fn mediator_egress_allowlist(mediator: &dyn Mediator) -> Option<String> {
    let mut origins: Vec<String> = Vec::new();
    if let Some(endpoint) = mediator
        .did_document()
        .and_then(mediator_http_endpoint)
    {
        origins.push(endpoint);
    }
    let internal_port = mediator.internal_port();
    if internal_port != 0 {
        origins.push(format!("http://127.0.0.1:{internal_port}"));
    }

    let mut urls: Vec<String> = Vec::new();
    let push = |url: String, urls: &mut Vec<String>| {
        if !urls.contains(&url) {
            urls.push(url);
        }
    };
    for endpoint in origins {
        let Ok(parsed) = Url::parse(&endpoint) else {
            continue;
        };
        let origin = parsed
            .origin()
            .ascii_serialization();
        let path = parsed
            .path()
            .trim_end_matches('/');
        // Bare origin: the gateway fetches the OOB invitation from the mediator
        // at `{origin}/oob?_oobid=<random>`, whose query is dynamic. An
        // origin-only allow-list entry matches any path on that origin (the
        // gateway's egress guard keeps exact-URL matching for path-bearing
        // entries and never widens to metadata).
        push(origin.clone(), &mut urls);
        push(format!("{origin}/.well-known/did.jsonl"), &mut urls);
        push(format!("{origin}/.well-known/did.json"), &mut urls);
        if !path.is_empty() && path != "/" {
            push(format!("{origin}{path}/did.jsonl"), &mut urls);
            push(format!("{origin}{path}/did.json"), &mut urls);
        }
    }

    (!urls.is_empty()).then(|| urls.join(","))
}

/// First `http(s)` service endpoint in a mediator DID document, matching the
/// gateway's own extraction so the derived allow-list mirrors what it requests.
fn mediator_http_endpoint(doc: &Value) -> Option<String> {
    let services = doc
        .get("service")?
        .as_array()?;
    for service in services {
        let Some(endpoints) = service.get("serviceEndpoint") else {
            continue;
        };
        let uris: Vec<&str> = match endpoints {
            Value::Array(arr) => arr
                .iter()
                .filter_map(|entry| {
                    entry
                        .get("uri")
                        .and_then(|uri| uri.as_str())
                })
                .collect(),
            Value::String(uri) => vec![uri.as_str()],
            _ => Vec::new(),
        };
        for uri in uris {
            if uri.starts_with("http://") || uri.starts_with("https://") {
                return Some(
                    uri.trim_end_matches('/')
                        .to_string(),
                );
            }
        }
    }
    None
}

pub(crate) fn fabric_route_ready_timeout() -> Duration {
    std::env::var(FABRIC_ROUTE_READY_TIMEOUT_ENV)
        .ok()
        .and_then(|value| parse_positive_duration_secs(&value))
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_FABRIC_ROUTE_READY_TIMEOUT_SECS))
}

pub(crate) fn parse_positive_duration_secs(value: &str) -> Option<Duration> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

pub(crate) fn sum_prometheus_counter(
    exposition: &str,
    metric_name: &str,
) -> usize {
    let mut total = 0usize;
    for line in exposition.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(metric_name) else {
            continue;
        };
        // The metric name must be a whole token: the next char is `{` (a label
        // set) or whitespace. Otherwise this line is a different metric that
        // merely shares the prefix.
        let value_part = match rest.chars().next() {
            Some('{') => match rest.split_once('}') {
                Some((_, after)) => after,
                None => continue,
            },
            Some(c) if c.is_whitespace() => rest,
            _ => continue,
        };
        if let Some(value) = value_part
            .split_whitespace()
            .next()
            .and_then(|token| token.parse::<f64>().ok())
        {
            total += value as usize;
        }
    }
    total
}

pub(crate) fn truncate_for_diagnostics(
    value: &str,
    max_chars: usize,
) -> String {
    let mut chars = value.chars();
    let truncated = chars
        .by_ref()
        .take(max_chars)
        .collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

pub(crate) fn tail_file(
    path: &Path,
    max_lines: usize,
) -> Result<String> {
    let content = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let lines = content
        .lines()
        .rev()
        .take(max_lines)
        .collect::<Vec<_>>();
    Ok(lines
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn absent_metric_sums_to_zero() {
        let metric = super::FABRIC_FORWARD_RECEIVED_METRIC;
        let exposition = "# HELP other_total Some other counter\nother_total 5\n";
        assert_eq!(super::sum_prometheus_counter(exposition, metric), 0);
    }

    #[test]
    fn single_labeled_sample_is_summed() {
        let metric = super::FABRIC_FORWARD_RECEIVED_METRIC;
        let exposition = format!("# TYPE {metric} counter\n{metric}{{surface_id=\"alpha\"}} 3\n");
        assert_eq!(super::sum_prometheus_counter(&exposition, metric), 3);
    }

    #[test]
    fn samples_are_summed_across_label_sets() {
        let metric = super::FABRIC_FORWARD_RECEIVED_METRIC;
        let exposition = format!("{metric}{{surface_id=\"alpha\"}} 2\n{metric}{{surface_id=\"bravo\"}} 4\n");
        assert_eq!(super::sum_prometheus_counter(&exposition, metric), 6);
    }

    #[test]
    fn unlabeled_sample_is_summed() {
        let metric = super::FABRIC_FORWARD_RECEIVED_METRIC;
        let exposition = format!("{metric} 7\n");
        assert_eq!(super::sum_prometheus_counter(&exposition, metric), 7);
    }

    #[test]
    fn prefix_collision_is_ignored() {
        let metric = super::FABRIC_FORWARD_RECEIVED_METRIC;
        let exposition = format!("{metric}_extra{{surface_id=\"alpha\"}} 9\n");
        assert_eq!(super::sum_prometheus_counter(&exposition, metric), 0);
    }
}
