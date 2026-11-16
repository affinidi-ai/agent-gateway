//! Read-only Agents API: one agent record per managed agent behind the Agent Surfaces the
//! caller can access.
//!
//! Surfaces whose targets share a normalised endpoint and Agent Card path are one managed
//! agent. Only surfaces in the caller's tenant and resource scope are grouped, and
//! identities, Trust Recorder outcomes and metrics are joined only to those surfaces.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

use crate::auth_manager::pat::PatResourceScope;
use crate::config::agent_surface::{AgentSurface, SurfaceProtocol, SurfaceStatus};
use crate::identity::display_name::managed_surfaces_by_did;
use crate::identity::filesystem::AgentIdentityRecord;
use crate::identity::state::IdentityApiState;
use crate::identity::target_card_names::{CardLocation, TargetCardNameService, TargetCardSource};
use crate::metrics::{InboundTraffic, SurfaceStats};
use crate::observability::caller_names::{AGENT_CARD_FETCH_TIMEOUT, AGENT_CARD_MAX_BYTES};
use crate::proxy::upstream_body::UpstreamBodyLimits;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource};
use crate::trust_registry_verification::recorder_status::{RecorderState, TrustRecorderStatusStore, global_store};

const AGENT_CARD_CACHE_TTL: Duration = Duration::from_secs(300);
const AGENT_CARD_FAILURE_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_AGENT_CARD_FETCHES: usize = 4;

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

/// How the gateway reaches the agent, from the `target.endpoint` scheme.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AgentRuntime {
    Url,
    A2aProxy,
    Gateway,
}

impl AgentRuntime {
    fn from_endpoint(endpoint: &str) -> Self {
        if endpoint.starts_with("a2a-proxy://") {
            Self::A2aProxy
        } else if endpoint.starts_with("fabric://") {
            Self::Gateway
        } else {
            Self::Url
        }
    }
}

/// Whether any of the agent's current identities was written to a Trust Registry.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct AgentTrustRegistry {
    pub recorded: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum IdentitySource {
    Surface,
    Managed,
}

/// A managed agent DID: a surface's own agent DID, or a managed identity used on a surface.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub did: String,
    pub created_at: Option<DateTime<Utc>>,
    pub source: IdentitySource,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentSurfaceRef {
    pub surface_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentSurfaceSummary {
    pub surface_id: String,
    pub name: String,
    pub protocol: SurfaceProtocol,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentRecord<S> {
    pub id: String,
    pub name: Option<String>,
    pub protocol: SurfaceProtocol,
    pub runtime: AgentRuntime,
    pub endpoint: String,
    pub tags: Vec<String>,
    pub surfaces: Vec<S>,
    pub identities: Vec<AgentIdentity>,
    pub trust_registry: AgentTrustRegistry,
    pub last_activity_at: Option<DateTime<Utc>>,
}

/// Access Point (inbound) request totals and p95 latency over the metrics retention
/// window, across the agent's surfaces. Transit Point (outbound) calls are not counted.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentTraffic {
    pub window_minutes: u64,
    pub total_requests: usize,
    pub failed: usize,
    pub gateway_faults: usize,
    pub p95_latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentDetails {
    #[serde(flatten)]
    pub agent: AgentRecord<AgentSurfaceSummary>,
    pub traffic: AgentTraffic,
}

/// `window_minutes` is the metrics retention window `last_activity_at` is read from.
#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentRecord<AgentSurfaceRef>>,
    pub window_minutes: u64,
}

/// Why the agent's own Agent Card can't be fetched.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentCardUnavailable {
    NoAgentCard,
    UnsupportedRuntime,
    /// A tenant token whose only card location is an appliance-wide surface's target.
    OperatorOnly,
}

/// The card as published by the agent at its target endpoint. Not verified.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentCardResponse {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AgentCardUnavailable>,
}

impl AgentCardResponse {
    fn available(card: Value) -> Self {
        Self {
            available: true,
            card: Some(card),
            reason: None,
        }
    }

    fn unavailable(reason: AgentCardUnavailable) -> Self {
        Self {
            available: false,
            card: None,
            reason: Some(reason),
        }
    }
}

/// Errors carry a fixed message only; store and fetch errors are logged, never returned.
#[derive(Debug)]
pub enum AgentApiError {
    NotFound,
    BadGateway,
    Internal(String),
}

#[derive(Debug, Serialize)]
struct AgentErrorResponse {
    error: &'static str,
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AgentApiError::NotFound => (StatusCode::NOT_FOUND, "Not Found"),
            AgentApiError::BadGateway => (StatusCode::BAD_GATEWAY, "Bad Gateway"),
            AgentApiError::Internal(reason) => {
                error!(reason = %reason, "Agents API internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
        };
        (status, Json(AgentErrorResponse { error: message })).into_response()
    }
}

/// Unverified display name: the canvas target node's `config.name`.
fn canvas_target_name(canvas: Option<&serde_json::Value>) -> Option<String> {
    canvas?
        .get("nodes")?
        .as_array()?
        .iter()
        .find(|node| {
            node.get("type")
                .and_then(|t| t.as_str())
                == Some("target")
        })?
        .get("config")?
        .get("name")?
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn is_listed(
    surface: &AgentSurface,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    // An MCP surface fronts a tool server, not an agent.
    surface.status != SurfaceStatus::Deleted
        && surface.access_point.protocol != SurfaceProtocol::Mcp
        && can_access(surface.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Surfaces, &surface.surface_id)
}

fn without_query(value: &str) -> &str {
    &value[..value
        .find(['?', '#'])
        .unwrap_or(value.len())]
}

/// Stands in for the host of an endpoint whose userinfo can't be told apart, so no part of
/// the raw value is returned.
const UNPARSEABLE_ENDPOINT_HOST: &str = "redacted.invalid";

/// Drops userinfo, query, fragment and trailing slashes and lower-cases the scheme. An
/// `http`/`https` endpoint is parsed as a URL, which also lower-cases its host; the host of
/// any other scheme keeps its case, since those ids are compared exactly. An `@` after the
/// authority of another scheme may end a userinfo holding `/`, `?` or `#`, so such an
/// endpoint is redacted whole, as is a scheme-less endpoint with any `@`.
fn normalise_endpoint(raw: &str) -> String {
    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once("://") else {
        if raw.contains('@') {
            return UNPARSEABLE_ENDPOINT_HOST.to_string();
        }
        return without_query(raw)
            .trim_end_matches('/')
            .to_string();
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme == "http" || scheme == "https" {
        return normalise_http_endpoint(raw, &scheme);
    }
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    if rest[authority_end..].contains('@') {
        return format!("{scheme}://{UNPARSEABLE_ENDPOINT_HOST}");
    }
    let host_start = rest[..authority_end]
        .rfind('@')
        .map_or(0, |at| at + 1);
    let host = &rest[host_start..authority_end];
    let path = without_query(&rest[authority_end..]);
    format!("{scheme}://{host}{path}")
        .trim_end_matches('/')
        .to_string()
}

fn normalise_http_endpoint(
    raw: &str,
    scheme: &str,
) -> String {
    let unparseable = || format!("{scheme}://{UNPARSEABLE_ENDPOINT_HOST}");
    let Ok(url) = url::Url::parse(raw) else {
        return unparseable();
    };
    let Some(host) = url.host_str() else {
        return unparseable();
    };
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{host}{port}{}", url.scheme(), url.path())
        .trim_end_matches('/')
        .to_string()
}

fn card_path(surface: &AgentSurface) -> &str {
    surface
        .access_point
        .agent_card_path
        .as_deref()
        .map_or("", str::trim)
}

/// Hex SHA-256 of the normalised endpoint and Agent Card path.
fn agent_id(
    endpoint: &str,
    card_path: &str,
) -> String {
    let digest = Sha256::digest(format!("{endpoint}\n{card_path}").as_bytes());
    format!("{digest:x}")
}

fn is_redacted_endpoint(endpoint: &str) -> bool {
    endpoint
        .split_once("://")
        .is_some_and(|(_, host)| host == UNPARSEABLE_ENDPOINT_HOST)
}

/// A redacted endpoint can't tell its targets apart, so its surface is an agent of its own,
/// with an id hashed from the surface id rather than the raw endpoint, which may hold
/// credentials.
fn surface_agent_id(
    surface: &AgentSurface,
    endpoint: &str,
) -> String {
    if is_redacted_endpoint(endpoint) {
        let digest = Sha256::digest(format!("unparseable\n{}\n{}", surface.surface_id, card_path(surface)).as_bytes());
        return format!("{digest:x}");
    }
    agent_id(endpoint, card_path(surface))
}

/// The surfaces behind one managed agent, ordered by name then id.
struct AgentGroup<'a> {
    id: String,
    endpoint: String,
    surfaces: Vec<&'a AgentSurface>,
}

fn group_surfaces<'a>(surfaces: impl IntoIterator<Item = &'a AgentSurface>) -> Vec<AgentGroup<'a>> {
    let mut groups: BTreeMap<String, AgentGroup<'a>> = BTreeMap::new();
    for surface in surfaces {
        let endpoint = normalise_endpoint(&surface.target.endpoint);
        let id = surface_agent_id(surface, &endpoint);
        groups
            .entry(id.clone())
            .or_insert_with(|| AgentGroup {
                id,
                endpoint,
                surfaces: Vec::new(),
            })
            .surfaces
            .push(surface);
    }
    let mut groups: Vec<AgentGroup<'a>> = groups.into_values().collect();
    for group in &mut groups {
        group
            .surfaces
            .sort_by(|a, b| {
                a.name
                    .cmp(&b.name)
                    .then_with(|| {
                        a.surface_id
                            .cmp(&b.surface_id)
                    })
            });
    }
    groups
}

/// Groups only the surfaces the caller can list.
fn listed_groups<'a>(
    live_surfaces: &'a [AgentSurface],
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Vec<AgentGroup<'a>> {
    group_surfaces(
        live_surfaces
            .iter()
            .filter(|surface| is_listed(surface, context, scope)),
    )
}

/// The caller's agent `id`, recomputed over the surfaces the caller can list. 404 otherwise.
fn listed_group<'a>(
    live_surfaces: &'a [AgentSurface],
    id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<AgentGroup<'a>, AgentApiError> {
    listed_groups(live_surfaces, context, scope)
        .into_iter()
        .find(|group| group.id == id)
        .ok_or(AgentApiError::NotFound)
}

/// What a record joins to its surfaces.
struct RegistryData<'a> {
    identity_records: &'a [AgentIdentityRecord],
    managed_surfaces_by_did: &'a HashMap<String, BTreeSet<String>>,
    stats: &'a HashMap<String, SurfaceStats>,
}

impl RegistryData<'_> {
    fn last_activity(
        &self,
        surface: &AgentSurface,
    ) -> Option<DateTime<Utc>> {
        self.stats
            .get(&surface.surface_id)
            .and_then(|stats| stats.last_activity)
    }

    fn earliest_created_at(
        &self,
        did: &str,
    ) -> Option<DateTime<Utc>> {
        self.identity_records
            .iter()
            .filter(|record| record.did == did)
            .map(|record| record.created_at)
            .min()
    }

    /// The group's surfaces, most recently active first; ties and inactive surfaces keep
    /// name order.
    fn by_activity<'s>(
        &self,
        group: &AgentGroup<'s>,
    ) -> Vec<&'s AgentSurface> {
        let mut surfaces = group.surfaces.clone();
        surfaces.sort_by_key(|surface| std::cmp::Reverse(self.last_activity(surface)));
        surfaces
    }

    /// Each surface's own agent DID plus the managed identities used on the group's
    /// surfaces, once per DID. Caller identities are never managed, so never included.
    fn identities(
        &self,
        group: &AgentGroup<'_>,
    ) -> Vec<AgentIdentity> {
        let surface_ids: HashSet<&str> = group
            .surfaces
            .iter()
            .map(|surface| surface.surface_id.as_str())
            .collect();
        let mut sources: BTreeMap<&str, IdentitySource> = BTreeMap::new();
        for did in group
            .surfaces
            .iter()
            .filter_map(|surface| surface.agent_did.as_deref())
            .map(str::trim)
            .filter(|did| !did.is_empty())
        {
            sources.insert(did, IdentitySource::Surface);
        }
        for (did, ids) in self.managed_surfaces_by_did {
            if ids
                .iter()
                .any(|id| surface_ids.contains(id.as_str()))
            {
                sources
                    .entry(did.as_str())
                    .or_insert(IdentitySource::Managed);
            }
        }
        sources
            .into_iter()
            .map(|(did, source)| AgentIdentity {
                did: did.to_string(),
                created_at: self.earliest_created_at(did),
                source,
            })
            .collect()
    }
}

/// Looks up a surface's Agent Card name.
type CardName = dyn Fn(&AgentSurface) -> Option<String> + Sync;

/// The Agent Card name of the most recently active surface that has one, else that
/// surface's canvas target name, else none.
fn display_name(
    by_activity: &[&AgentSurface],
    card_name: &CardName,
) -> Option<String> {
    by_activity
        .iter()
        .find_map(|surface| card_name(surface))
        .or_else(|| {
            by_activity
                .iter()
                .find_map(|surface| canvas_target_name(surface.canvas.as_ref()))
        })
}

/// A2A wins over every other protocol, then AP2.
fn primary_protocol(group: &AgentGroup<'_>) -> SurfaceProtocol {
    let rank = |protocol: &SurfaceProtocol| match protocol {
        SurfaceProtocol::A2a => 0,
        SurfaceProtocol::Ap2 => 1,
        SurfaceProtocol::DIDComm => 2,
        SurfaceProtocol::Mcp => 3,
    };
    group
        .surfaces
        .iter()
        .map(|surface| {
            surface
                .access_point
                .protocol
                .clone()
        })
        .min_by_key(rank)
        .unwrap_or_default()
}

/// Recorded when a (surface, DID) pair of the group is Recorded or Partly recorded and the
/// DID is still one of the agent's identities. Without a store nothing is recorded.
async fn is_recorded(
    recorder: Option<&TrustRecorderStatusStore>,
    group: &AgentGroup<'_>,
    identities: &[AgentIdentity],
) -> bool {
    let Some(recorder) = recorder else {
        return false;
    };
    for surface in &group.surfaces {
        for identity in identities {
            let state = recorder
                .status_for(&surface.surface_id, &identity.did)
                .await
                .map(|status| status.state);
            if matches!(state, Some(RecorderState::Recorded | RecorderState::Partial)) {
                return true;
            }
        }
    }
    false
}

fn surface_ref(surface: &AgentSurface) -> AgentSurfaceRef {
    AgentSurfaceRef {
        surface_id: surface.surface_id.clone(),
        name: surface.name.clone(),
    }
}

fn surface_summary(surface: &AgentSurface) -> AgentSurfaceSummary {
    AgentSurfaceSummary {
        surface_id: surface.surface_id.clone(),
        name: surface.name.clone(),
        protocol: surface
            .access_point
            .protocol
            .clone(),
        route: surface
            .access_point
            .route
            .clone(),
    }
}

async fn agent_record<S>(
    group: &AgentGroup<'_>,
    data: &RegistryData<'_>,
    recorder: Option<&TrustRecorderStatusStore>,
    card_name: &CardName,
    summarise: fn(&AgentSurface) -> S,
) -> AgentRecord<S> {
    let identities = data.identities(group);
    let recorded = is_recorded(recorder, group, &identities).await;
    let tags: BTreeSet<&String> = group
        .surfaces
        .iter()
        .flat_map(|surface| &surface.tags)
        .collect();
    AgentRecord {
        id: group.id.clone(),
        name: display_name(&data.by_activity(group), card_name),
        protocol: primary_protocol(group),
        runtime: AgentRuntime::from_endpoint(&group.endpoint),
        endpoint: group.endpoint.clone(),
        tags: tags
            .into_iter()
            .cloned()
            .collect(),
        surfaces: group
            .surfaces
            .iter()
            .map(|surface| summarise(surface))
            .collect(),
        identities,
        trust_registry: AgentTrustRegistry { recorded },
        last_activity_at: group
            .surfaces
            .iter()
            .filter_map(|surface| data.last_activity(surface))
            .max(),
    }
}

/// By display name ignoring case, unnamed agents last, then by id.
fn sort_agents<S>(agents: &mut [AgentRecord<S>]) {
    agents.sort_by_cached_key(|agent| {
        (
            agent.name.is_none(),
            agent
                .name
                .as_deref()
                .map(str::to_lowercase),
            agent.id.clone(),
        )
    });
}

fn traffic(
    inbound: InboundTraffic,
    window_minutes: u64,
) -> AgentTraffic {
    AgentTraffic {
        window_minutes,
        total_requests: inbound.total,
        failed: inbound.failed,
        gateway_faults: inbound.gateway_faults,
        p95_latency_ms: inbound.p95_latency_ms,
    }
}

fn surface_store(state: &IdentityApiState) -> Result<&crate::surfaces::FileSystemAgentSurfaceStore, AgentApiError> {
    state
        .agent_surface_store
        .as_deref()
        .ok_or_else(|| AgentApiError::Internal("agent surface store not initialized".to_string()))
}

async fn all_surfaces(state: &IdentityApiState) -> Result<Vec<AgentSurface>, AgentApiError> {
    surface_store(state)?
        .list_all()
        .await
        .map_err(|e| AgentApiError::Internal(format!("failed to list surfaces: {e}")))
}

fn surfaces_by_did(
    records: &[AgentIdentityRecord],
    live_surfaces: &[AgentSurface],
) -> HashMap<String, BTreeSet<String>> {
    let live_by_id: HashMap<&str, &AgentSurface> = live_surfaces
        .iter()
        .map(|surface| (surface.surface_id.as_str(), surface))
        .collect();
    managed_surfaces_by_did(records, |id| live_by_id.get(id).copied())
}

async fn identity_records(state: &IdentityApiState) -> Result<Vec<AgentIdentityRecord>, AgentApiError> {
    state
        .vc_issuer
        .get_identity_store()
        .list_all()
        .await
        .map_err(|e| AgentApiError::Internal(format!("failed to list identities: {e}")))
}

async fn stats_by_surface(state: &IdentityApiState) -> HashMap<String, SurfaceStats> {
    state
        .metrics_store
        .get_channel_stats()
        .await
        .into_iter()
        .map(|stats| {
            (
                stats
                    .channel_config_id
                    .clone(),
                stats,
            )
        })
        .collect()
}

/// The Trust Recorder status store, or `None` with a warning when it failed to open.
fn recorder_store() -> Option<Arc<TrustRecorderStatusStore>> {
    let store = global_store();
    if store.is_none() {
        warn!("Trust Recorder status store unavailable; the Agents API reports every agent as not recorded");
    }
    store
}

/// The cached Agent Card name of a surface's target; never waits for a fetch.
fn cached_card_name(surface: &AgentSurface) -> Option<String> {
    CardLocation::for_surface(surface)
        .and_then(|location| TargetCardNameService::global().lookup_or_spawn(&surface.surface_id, &location))
}

/// List one agent record per managed agent behind the surfaces the caller can list.
pub async fn list_agents(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentListResponse>, AgentApiError> {
    let live_surfaces = all_surfaces(&state).await?;
    let groups = listed_groups(&live_surfaces, tenant_context(&context), resource_scope(&scope));
    let window_minutes = state
        .metrics_store
        .retention_minutes();
    if groups.is_empty() {
        return Ok(Json(AgentListResponse {
            agents: Vec::new(),
            window_minutes,
        }));
    }

    let records = identity_records(&state).await?;
    let by_did = surfaces_by_did(&records, &live_surfaces);
    let stats = stats_by_surface(&state).await;
    let data = RegistryData {
        identity_records: &records,
        managed_surfaces_by_did: &by_did,
        stats: &stats,
    };
    let recorder = recorder_store();

    let mut agents = Vec::with_capacity(groups.len());
    for group in &groups {
        agents.push(agent_record(group, &data, recorder.as_deref(), &cached_card_name, surface_ref).await);
    }
    sort_agents(&mut agents);

    debug!(count = agents.len(), "Listed agents");
    Ok(Json(AgentListResponse { agents, window_minutes }))
}

/// One agent record with every surface and the Access Point traffic across them.
pub async fn get_agent(
    Path(id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentDetails>, AgentApiError> {
    let live_surfaces = all_surfaces(&state).await?;
    let group = listed_group(&live_surfaces, &id, tenant_context(&context), resource_scope(&scope))?;

    let records = identity_records(&state).await?;
    let by_did = surfaces_by_did(&records, &live_surfaces);
    let stats = stats_by_surface(&state).await;
    let data = RegistryData {
        identity_records: &records,
        managed_surfaces_by_did: &by_did,
        stats: &stats,
    };
    let agent = agent_record(&group, &data, recorder_store().as_deref(), &cached_card_name, surface_summary).await;

    let surface_ids: Vec<&str> = group
        .surfaces
        .iter()
        .map(|surface| surface.surface_id.as_str())
        .collect();
    let inbound = state
        .metrics_store
        .inbound_traffic(&surface_ids)
        .await;

    Ok(Json(AgentDetails {
        agent,
        traffic: traffic(
            inbound,
            state
                .metrics_store
                .retention_minutes(),
        ),
    }))
}

/// Where the agent publishes its own card, read through the first surface that can reach
/// it. A tenant token reads it only through its own tenant's surfaces, and gets
/// `operator_only` when only an appliance-wide surface could. `no_agent_card` when no
/// surface speaks A2A or AP2.
fn agent_card_location(
    group: &AgentGroup<'_>,
    context: Option<&PatTenantContext>,
) -> Result<CardLocation, AgentCardUnavailable> {
    let mut operator_only = false;
    for surface in &group.surfaces {
        let Some(location) = CardLocation::for_surface(surface) else {
            continue;
        };
        if can_mutate(surface.tenant_id.as_deref(), context) {
            return Ok(location);
        }
        operator_only = true;
    }
    if operator_only {
        return Err(AgentCardUnavailable::OperatorOnly);
    }
    let has_card = group
        .surfaces
        .iter()
        .any(|surface| matches!(surface.access_point.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2));
    Err(if has_card {
        AgentCardUnavailable::UnsupportedRuntime
    } else {
        AgentCardUnavailable::NoAgentCard
    })
}

/// Reads the card from the surface's target endpoint through the egress policy,
/// without following redirects. Never calls the surface's public card route.
struct HttpAgentCardSource;

#[async_trait]
impl TargetCardSource for HttpAgentCardSource {
    async fn fetch_agent_card(
        &self,
        location: &CardLocation,
    ) -> Option<Value> {
        crate::proxy::outbound_handler::fetch_agent_card(
            &location.endpoint,
            location.card_path.as_deref(),
            "agent-registry-card",
            AGENT_CARD_FETCH_TIMEOUT,
            UpstreamBodyLimits::new(AGENT_CARD_MAX_BYTES, None, AGENT_CARD_FETCH_TIMEOUT.as_secs()),
        )
        .await
    }
}

struct CachedCard {
    location: CardLocation,
    /// `None` records a failed fetch.
    card: Option<Value>,
    fetched_at: Instant,
}

/// Fetch results per agent. A card is reused until `ttl` passes and a failure
/// until `failure_ttl` passes, or until the agent's card location changes.
/// Caching failures stops repeated views of an unreachable agent from each
/// waiting for the fetch timeout. Concurrent misses for one agent share one fetch,
/// and at most [`MAX_CONCURRENT_AGENT_CARD_FETCHES`] fetches run at once.
pub struct AgentCardCache {
    entries: DashMap<String, CachedCard>,
    fetching: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    permits: tokio::sync::Semaphore,
    source: Arc<dyn TargetCardSource>,
    ttl: Duration,
    failure_ttl: Duration,
}

impl AgentCardCache {
    pub fn global() -> &'static AgentCardCache {
        static GLOBAL: OnceLock<AgentCardCache> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            AgentCardCache::new(Arc::new(HttpAgentCardSource), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL)
        })
    }

    pub fn new(
        source: Arc<dyn TargetCardSource>,
        ttl: Duration,
        failure_ttl: Duration,
    ) -> Self {
        Self {
            entries: DashMap::new(),
            fetching: DashMap::new(),
            permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_AGENT_CARD_FETCHES),
            source,
            ttl,
            failure_ttl,
        }
    }

    /// The cached result for `agent_id` if it is fresh and was fetched from `location`.
    fn cached(
        &self,
        agent_id: &str,
        location: &CardLocation,
    ) -> Option<Option<Value>> {
        self.entries
            .get(agent_id)
            .filter(|cached| cached.location == *location && self.is_fresh(cached))
            .map(|cached| cached.card.clone())
    }

    fn is_fresh(
        &self,
        cached: &CachedCard,
    ) -> bool {
        let ttl = if cached.card.is_some() {
            self.ttl
        } else {
            self.failure_ttl
        };
        cached.fetched_at.elapsed() < ttl
    }

    /// Expired entries are dropped on each store, so the cache holds no more than the agents
    /// viewed within the TTL.
    pub async fn get(
        &self,
        agent_id: &str,
        location: &CardLocation,
    ) -> Option<Value> {
        if let Some(card) = self.cached(agent_id, location) {
            return card;
        }
        let lock = self
            .fetching
            .entry(agent_id.to_string())
            .or_default()
            .clone();
        let card = self
            .fetch_once(agent_id, location, &lock)
            .await;
        drop(lock);
        self.fetching
            .remove_if(agent_id, |_, lock| Arc::strong_count(lock) == 1);
        card
    }

    /// Fetches and stores the card unless a caller that held the lock first already did.
    async fn fetch_once(
        &self,
        agent_id: &str,
        location: &CardLocation,
        lock: &tokio::sync::Mutex<()>,
    ) -> Option<Value> {
        let _fetching = lock.lock().await;
        if let Some(card) = self.cached(agent_id, location) {
            return card;
        }
        let Ok(_permit) = self.permits.acquire().await else {
            return None;
        };
        let card = self
            .source
            .fetch_agent_card(location)
            .await;
        self.entries
            .retain(|_, cached| self.is_fresh(cached));
        self.entries.insert(
            agent_id.to_string(),
            CachedCard {
                location: location.clone(),
                card: card.clone(),
                fetched_at: Instant::now(),
            },
        );
        card
    }
}

async fn agent_card_response(
    group: &AgentGroup<'_>,
    context: Option<&PatTenantContext>,
    cache: &AgentCardCache,
) -> Result<AgentCardResponse, AgentApiError> {
    let location = match agent_card_location(group, context) {
        Ok(location) => location,
        Err(reason) => return Ok(AgentCardResponse::unavailable(reason)),
    };
    match cache
        .get(&group.id, &location)
        .await
    {
        Some(card) => Ok(AgentCardResponse::available(card)),
        None => {
            warn!(agent_id = %group.id, "Agent Card fetch failed");
            Err(AgentApiError::BadGateway)
        }
    }
}

/// The managed agent's own Agent Card, or why it isn't available. 502 when the
/// fetch fails, with no upstream detail.
pub async fn get_agent_card(
    Path(id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentCardResponse>, AgentApiError> {
    let live_surfaces = all_surfaces(&state).await?;
    let group = listed_group(&live_surfaces, &id, tenant_context(&context), resource_scope(&scope))?;
    agent_card_response(&group, tenant_context(&context), AgentCardCache::global())
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::filesystem::IdentityOrigin;
    use crate::identity::test_helpers::test_surface_identity_record;
    use crate::trust_registry_verification::recorder_status::{EntryStatus, RecorderReason};
    use chrono::Duration;
    use regex::Regex;
    use std::sync::Arc;

    fn surface(id: &str) -> AgentSurface {
        let mut surface = AgentSurface {
            surface_id: id.to_string(),
            name: format!("{id}-name"),
            tags: vec!["team:platform".to_string()],
            ..Default::default()
        };
        surface.access_point.route = format!("/{id}");
        surface.target.endpoint = "http://localhost:9002".to_string();
        surface
    }

    fn targeting(
        id: &str,
        endpoint: &str,
    ) -> AgentSurface {
        let mut surface = surface(id);
        surface.target.endpoint = endpoint.to_string();
        surface
    }

    fn with_target_node(
        mut surface: AgentSurface,
        node: serde_json::Value,
    ) -> AgentSurface {
        surface.canvas = Some(serde_json::json!({
            "nodes": [
                { "id": "access-point", "type": "access-point", "config": { "name": "AP" } },
                node,
            ]
        }));
        surface
    }

    fn with_canvas_name(
        surface: AgentSurface,
        name: &str,
    ) -> AgentSurface {
        with_target_node(surface, serde_json::json!({ "type": "target", "config": { "name": name } }))
    }

    fn managed(
        did: &str,
        surface_id: &str,
    ) -> AgentIdentityRecord {
        let mut record = test_surface_identity_record(did, surface_id);
        record.origin = Some(IdentityOrigin::Managed);
        record
    }

    fn managed_by_did(records: &[AgentIdentityRecord]) -> HashMap<String, BTreeSet<String>> {
        let mut live = surface("live");
        live.target.endpoint = "a2a-proxy://p1".to_string();
        managed_surfaces_by_did(records, |_| Some(&live))
    }

    fn stats(
        surface_id: &str,
        total: usize,
        failed: usize,
        faults: usize,
        last_activity: Option<DateTime<Utc>>,
    ) -> SurfaceStats {
        SurfaceStats {
            channel_config_id: surface_id.to_string(),
            total_connections: total,
            successful: total - failed - faults,
            failed,
            gateway_faults: faults,
            last_activity,
        }
    }

    fn active_at(entries: &[(&str, DateTime<Utc>)]) -> HashMap<String, SurfaceStats> {
        entries
            .iter()
            .map(|(id, at)| (id.to_string(), stats(id, 1, 0, 0, Some(*at))))
            .collect()
    }

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "token".to_string(),
            tenant_id: id.to_string(),
        }
    }

    fn no_card(_: &AgentSurface) -> Option<String> {
        None
    }

    /// Builds every record from `surfaces` with no recorder store.
    struct Fixture {
        records: Vec<AgentIdentityRecord>,
        stats: HashMap<String, SurfaceStats>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                records: Vec::new(),
                stats: HashMap::new(),
            }
        }

        async fn agents(
            &self,
            surfaces: &[AgentSurface],
            recorder: Option<&TrustRecorderStatusStore>,
            card_name: &CardName,
        ) -> Vec<AgentRecord<AgentSurfaceRef>> {
            let by_did = managed_by_did(&self.records);
            let data = RegistryData {
                identity_records: &self.records,
                managed_surfaces_by_did: &by_did,
                stats: &self.stats,
            };
            let mut agents = Vec::new();
            for group in &group_surfaces(surfaces) {
                agents.push(agent_record(group, &data, recorder, card_name, surface_ref).await);
            }
            sort_agents(&mut agents);
            agents
        }

        async fn only(
            &self,
            surfaces: &[AgentSurface],
            recorder: Option<&TrustRecorderStatusStore>,
        ) -> AgentRecord<AgentSurfaceRef> {
            let mut agents = self
                .agents(surfaces, recorder, &no_card)
                .await;
            assert_eq!(agents.len(), 1, "one record expected");
            agents.remove(0)
        }
    }

    fn surface_names(agent: &AgentRecord<AgentSurfaceRef>) -> Vec<&str> {
        agent
            .surfaces
            .iter()
            .map(|surface| surface.name.as_str())
            .collect()
    }

    fn dids(agent: &AgentRecord<AgentSurfaceRef>) -> Vec<&str> {
        agent
            .identities
            .iter()
            .map(|identity| identity.did.as_str())
            .collect()
    }

    #[test]
    fn test_normalise_endpoint_strips_credentials_query_case_and_trailing_slash() {
        for (raw, expected) in [
            ("https://user:secret@Bravo.example/a2a/?k=1", "https://bravo.example/a2a"),
            ("https://bravo.example/a2a", "https://bravo.example/a2a"),
            ("HTTPS://BRAVO.example:8443/A2A#frag", "https://bravo.example:8443/A2A"),
            ("https://bravo.example/", "https://bravo.example"),
            ("  http://localhost:9002//  ", "http://localhost:9002"),
            ("A2A-Proxy://Proxy-1/?x=1", "a2a-proxy://Proxy-1"),
            ("fabric://key@Gateway-1/channel-1/", "fabric://Gateway-1/channel-1"),
        ] {
            assert_eq!(normalise_endpoint(raw), expected, "{raw}");
        }
    }

    #[test]
    fn test_normalise_endpoint_ends_the_authority_at_query_or_fragment() {
        for (raw, expected) in [
            ("https://evil.example?x=@good.example", "https://evil.example"),
            ("https://evil.example#@good.example", "https://evil.example"),
            ("https://evil.example\\@good.example/a2a", "https://evil.example/@good.example/a2a"),
            ("a2a-proxy://evil?x=1", "a2a-proxy://evil"),
            ("fabric://evil#frag", "fabric://evil"),
        ] {
            assert_eq!(normalise_endpoint(raw), expected, "{raw}");
            assert_ne!(
                agent_id(&normalise_endpoint(raw), ""),
                agent_id(&normalise_endpoint(&raw.replace("evil", "good")), ""),
                "{raw}"
            );
        }
    }

    #[test]
    fn test_normalise_endpoint_redacts_other_schemes_with_an_at_after_the_authority() {
        for (raw, expected) in [
            ("fabric://ab/cd@gw/ch", "fabric://redacted.invalid"),
            ("a2a-proxy://evil?x=@good", "a2a-proxy://redacted.invalid"),
            ("fabric://us?er#pw@gw/ch", "fabric://redacted.invalid"),
            ("fabric://key@Gateway-1/channel-1", "fabric://Gateway-1/channel-1"),
        ] {
            let normalised = normalise_endpoint(raw);
            assert_eq!(normalised, expected, "{raw}");
            for forbidden in ["cd", "us", "pw", "key"] {
                assert!(!normalised.contains(forbidden), "{raw} leaves {forbidden} in {normalised}");
            }
        }
    }

    #[test]
    fn test_normalise_endpoint_never_returns_credentials_of_an_unparseable_url() {
        for raw in ["https://user:pa/ss@host/a2a", "https://u:p?ss#w@bravo.example/a2a", "http://user:secret@"] {
            let normalised = normalise_endpoint(raw);
            assert_eq!(normalised, format!("{}://redacted.invalid", &raw[..raw.find(':').expect("scheme")]), "{raw}");
            for forbidden in ["user", "pa", "ss", "secret", "bravo", "host"] {
                assert!(!normalised.contains(forbidden), "{raw} leaves {forbidden} in {normalised}");
            }
        }
        assert_eq!(normalise_endpoint("https://user:secret@host/a2a"), "https://host/a2a");
        for raw in ["user:secret@host/a2a", "host/a2a?x=@pw"] {
            assert_eq!(normalise_endpoint(raw), "redacted.invalid", "{raw}");
        }
        assert_eq!(normalise_endpoint("host/a2a/?x=1"), "host/a2a");
    }

    #[test]
    fn test_agent_id_is_hex_sha256_of_endpoint_and_card_path() {
        let id = agent_id("https://bravo.example/a2a", "");
        assert_eq!(id.len(), 64);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit())
        );
        assert_eq!(id, agent_id("https://bravo.example/a2a", ""));
        assert_ne!(id, agent_id("https://bravo.example/a2a", "/card.json"));
        assert_ne!(id, agent_id("https://bravo.example/b2b", ""));
    }

    #[tokio::test]
    async fn test_surfaces_targeting_the_same_agent_are_listed_once() {
        let surfaces = [
            targeting("s-oxygen", "https://user:secret@Bravo.example/a2a/?k=1"),
            targeting("s-helium", "https://bravo.example/a2a"),
        ];
        let agent = Fixture::new()
            .only(&surfaces, None)
            .await;
        assert_eq!(agent.endpoint, "https://bravo.example/a2a");
        assert_eq!(surface_names(&agent), vec!["s-helium-name", "s-oxygen-name"]);
        assert_eq!(agent.id, agent_id("https://bravo.example/a2a", ""));
        let text = serde_json::to_string(&agent).expect("serialize");
        for forbidden in ["secret", "k=1", "user:"] {
            assert!(!text.contains(forbidden), "response contains {forbidden}: {text}");
        }
    }

    #[tokio::test]
    async fn test_different_agent_card_paths_are_different_agents() {
        let mut oxygen = targeting("s-oxygen", "https://bravo.example/a2a");
        oxygen
            .access_point
            .agent_card_path = Some("/cards/one.json".to_string());
        let mut helium = targeting("s-helium", "https://bravo.example/a2a");
        helium
            .access_point
            .agent_card_path = Some("/cards/two.json".to_string());
        let mut default_path = targeting("s-neon", "https://bravo.example/a2a");
        default_path
            .access_point
            .agent_card_path = Some("  ".to_string());
        let agents = Fixture::new()
            .agents(&[oxygen, helium, default_path, targeting("s-argon", "https://bravo.example/a2a")], None, &no_card)
            .await;
        assert_eq!(agents.len(), 3);
        let mut grouped: Vec<Vec<&str>> = agents
            .iter()
            .map(surface_names)
            .collect();
        grouped.sort();
        assert_eq!(grouped, vec![vec!["s-argon-name", "s-neon-name"], vec!["s-helium-name"], vec!["s-oxygen-name"]]);
    }

    #[tokio::test]
    async fn test_each_surface_with_a_redacted_endpoint_is_an_agent_of_its_own() {
        let agents = Fixture::new()
            .agents(
                &[
                    targeting("s-oxygen", "fabric://ab/cd@gw/ch"),
                    targeting("s-helium", "fabric://us?er#pw@gw/ch"),
                    targeting("s-neon", "https://bravo.example/a2a"),
                    targeting("s-argon", "https://user:secret@bravo.example/a2a"),
                ],
                None,
                &no_card,
            )
            .await;
        assert_eq!(agents.len(), 3);
        let mut grouped: Vec<Vec<&str>> = agents
            .iter()
            .map(surface_names)
            .collect();
        grouped.sort();
        assert_eq!(grouped, vec![vec!["s-argon-name", "s-neon-name"], vec!["s-helium-name"], vec!["s-oxygen-name"]]);
        let redacted: Vec<_> = agents
            .iter()
            .filter(|agent| agent.endpoint == "fabric://redacted.invalid")
            .collect();
        assert_eq!(redacted.len(), 2);
        assert_ne!(redacted[0].id, redacted[1].id);
        for agent in redacted {
            assert_ne!(agent.id, agent_id("fabric://redacted.invalid", ""));
            assert_eq!(agent.id.len(), 64);
            let surface_id = &agent.surfaces[0].surface_id;
            let digest = Sha256::digest(format!("unparseable\n{surface_id}\n").as_bytes());
            assert_eq!(agent.id, format!("{digest:x}"));
        }
        let text = serde_json::to_string(&agents).expect("serialize");
        for forbidden in ["cd@", "us?er", "pw@", "secret"] {
            assert!(!text.contains(forbidden), "response contains {forbidden}: {text}");
        }
    }

    #[test]
    fn test_listed_groups_never_group_across_other_tenants() {
        let mut own = targeting("s-oxygen", "https://bravo.example/a2a");
        own.tenant_id = Some("tenant-a".to_string());
        let mut other = targeting("s-helium", "https://bravo.example/a2a");
        other.tenant_id = Some("tenant-b".to_string());
        let live = [own, other];
        let context = tenant("tenant-a");
        let groups = listed_groups(&live, Some(&context), None);
        assert_eq!(groups.len(), 1);
        let ids: Vec<&str> = groups[0]
            .surfaces
            .iter()
            .map(|surface| surface.surface_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s-oxygen"]);
    }

    #[tokio::test]
    async fn test_a_tenant_sees_only_identities_of_its_own_surfaces() {
        let mut own = targeting("s-oxygen", "https://bravo.example/a2a");
        own.tenant_id = Some("tenant-a".to_string());
        let mut other = targeting("s-helium", "https://bravo.example/a2a");
        other.tenant_id = Some("tenant-b".to_string());
        other.agent_did = Some("did:web:other-surface".to_string());
        let live = [own, other];
        let mut fixture = Fixture::new();
        fixture.records = vec![managed("did:a", "s-oxygen"), managed("did:b", "s-helium")];
        let by_did = managed_by_did(&fixture.records);
        let data = RegistryData {
            identity_records: &fixture.records,
            managed_surfaces_by_did: &by_did,
            stats: &fixture.stats,
        };
        let context = tenant("tenant-a");
        let groups = listed_groups(&live, Some(&context), None);
        let agent = agent_record(&groups[0], &data, None, &no_card, surface_ref).await;
        assert_eq!(dids(&agent), vec!["did:a"]);
        assert_eq!(surface_names(&agent), vec!["s-oxygen-name"]);
    }

    #[test]
    fn test_another_tenants_agent_id_is_not_found() {
        let mut own = targeting("s-oxygen", "https://alpha.example/a2a");
        own.tenant_id = Some("tenant-a".to_string());
        let mut other = targeting("s-helium", "https://bravo.example/a2a");
        other.tenant_id = Some("tenant-b".to_string());
        let live = [own, other];
        let bravo = agent_id("https://bravo.example/a2a", "");
        let context = tenant("tenant-a");
        assert!(matches!(listed_group(&live, &bravo, Some(&context), None), Err(AgentApiError::NotFound)));
        assert!(matches!(listed_group(&live, "s-helium", Some(&context), None), Err(AgentApiError::NotFound)));
        assert_eq!(
            listed_group(&live, &bravo, Some(&tenant("tenant-b")), None)
                .expect("own agent")
                .id,
            bravo
        );
    }

    #[test]
    fn test_out_of_scope_agent_id_is_not_found() {
        let scope = PatResourceScope(Arc::new(Regex::new("^TENANT:tenant-a:surfaces:allowed$").expect("regex")));
        let context = tenant("tenant-a");
        let mut allowed = targeting("allowed", "https://alpha.example/a2a");
        allowed.tenant_id = Some("tenant-a".to_string());
        let mut denied = targeting("denied", "https://bravo.example/a2a");
        denied.tenant_id = Some("tenant-a".to_string());
        let live = [allowed, denied];
        let bravo = agent_id("https://bravo.example/a2a", "");
        assert!(matches!(listed_group(&live, &bravo, Some(&context), Some(&scope)), Err(AgentApiError::NotFound)));
        assert!(listed_group(&live, &agent_id("https://alpha.example/a2a", ""), Some(&context), Some(&scope)).is_ok());
    }

    #[tokio::test]
    async fn test_display_name_prefers_the_agent_card() {
        let now = Utc::now();
        let mut fixture = Fixture::new();
        fixture.stats = active_at(&[("s-helium", now)]);
        let surfaces =
            [with_canvas_name(surface("s-oxygen"), "billing"), with_canvas_name(surface("s-helium"), "bill-v2")];
        let card = |surface: &AgentSurface| (surface.surface_id == "s-oxygen").then(|| "Billing Bot".to_string());
        let agents = fixture
            .agents(&surfaces, None, &card)
            .await;
        assert_eq!(agents[0].name.as_deref(), Some("Billing Bot"));
    }

    #[tokio::test]
    async fn test_display_name_falls_back_to_most_recently_active_canvas_name() {
        let now = Utc::now();
        let mut fixture = Fixture::new();
        fixture.stats = active_at(&[("s-oxygen", now - Duration::hours(1)), ("s-helium", now - Duration::minutes(5))]);
        let surfaces =
            [with_canvas_name(surface("s-oxygen"), "billing"), with_canvas_name(surface("s-helium"), "bill-v2")];
        let agent = fixture
            .only(&surfaces, None)
            .await;
        assert_eq!(agent.name.as_deref(), Some("bill-v2"));
    }

    #[tokio::test]
    async fn test_display_name_ties_and_no_activity_use_surface_name_order() {
        let mut beta = with_canvas_name(surface("s1"), "from-beta");
        beta.name = "beta".to_string();
        let mut alpha = with_canvas_name(surface("s2"), "from-alpha");
        alpha.name = "alpha".to_string();
        let mut unnamed = surface("s3");
        unnamed.name = "aaa".to_string();
        let agent = Fixture::new()
            .only(&[beta, alpha, unnamed], None)
            .await;
        assert_eq!(agent.name.as_deref(), Some("from-alpha"), "skips a surface without a canvas name");
    }

    #[tokio::test]
    async fn test_display_name_is_none_without_card_or_canvas_name() {
        let missing_name = with_target_node(
            surface("s1"),
            serde_json::json!({ "type": "target", "config": { "endpoint": "a2a-proxy://p1" } }),
        );
        let no_target =
            with_target_node(surface("s2"), serde_json::json!({ "type": "npc", "config": { "name": "Caller" } }));
        let blank = with_canvas_name(surface("s3"), "   ");
        let agent = Fixture::new()
            .only(&[missing_name, no_target, blank, surface("s4")], None)
            .await;
        assert_eq!(agent.name, None);
    }

    #[tokio::test]
    async fn test_last_activity_is_the_latest_across_surfaces() {
        let now = Utc::now();
        let mut fixture = Fixture::new();
        fixture.stats = active_at(&[("s-oxygen", now - Duration::hours(1)), ("s-helium", now - Duration::minutes(5))]);
        let agent = fixture
            .only(&[surface("s-oxygen"), surface("s-helium"), surface("s-idle")], None)
            .await;
        assert_eq!(agent.last_activity_at, Some(now - Duration::minutes(5)));
        assert_eq!(
            Fixture::new()
                .only(&[surface("s1")], None)
                .await
                .last_activity_at,
            None
        );
    }

    #[tokio::test]
    async fn test_identities_are_the_union_across_surfaces_once_per_did() {
        let mut fixture = Fixture::new();
        let did_b = managed("did:b", "s-oxygen");
        let created_b = did_b.created_at;
        let mut caller = test_surface_identity_record("did:caller", "s-oxygen");
        caller.origin = Some(IdentityOrigin::ExternalCaller);
        fixture.records = vec![
            managed("did:a", "s-oxygen"),
            did_b,
            managed("did:b", "s-helium"),
            managed("did:c", "s-helium"),
            caller,
        ];
        let mut helium = surface("s-helium");
        helium.agent_did = Some("did:c".to_string());
        let agent = fixture
            .only(&[surface("s-oxygen"), helium], None)
            .await;
        assert_eq!(dids(&agent), vec!["did:a", "did:b", "did:c"]);
        let did_c = &agent.identities[2];
        assert_eq!(did_c.source, IdentitySource::Surface, "a surface's own DID is reported as surface");
        assert_eq!(agent.identities[1].source, IdentitySource::Managed);
        assert!(agent.identities[1].created_at <= Some(created_b));
    }

    #[tokio::test]
    async fn test_tags_are_a_sorted_union() {
        let mut a = surface("s1");
        a.tags = vec!["prod".to_string(), "billing".to_string()];
        let mut b = surface("s2");
        b.tags = vec!["billing".to_string(), "eu".to_string()];
        let agent = Fixture::new()
            .only(&[a, b], None)
            .await;
        assert_eq!(agent.tags, vec!["billing", "eu", "prod"]);
    }

    #[tokio::test]
    async fn test_protocol_is_primary_and_runtime_follows_endpoint() {
        let mut ap2 = surface("s1");
        ap2.access_point.protocol = SurfaceProtocol::Ap2;
        let agent = Fixture::new()
            .only(&[ap2.clone(), surface("s2")], None)
            .await;
        assert_eq!(agent.protocol, SurfaceProtocol::A2a);
        assert_eq!(
            Fixture::new()
                .only(&[ap2], None)
                .await
                .protocol,
            SurfaceProtocol::Ap2
        );
        for (endpoint, runtime) in [
            ("https://agent.example.com", AgentRuntime::Url),
            ("a2a-proxy://proxy-1", AgentRuntime::A2aProxy),
            ("fabric://gateway-1/channel-1", AgentRuntime::Gateway),
        ] {
            let agent = Fixture::new()
                .only(&[targeting("s1", endpoint)], None)
                .await;
            assert_eq!(agent.runtime, runtime, "{endpoint}");
        }
    }

    async fn record_outcome(
        store: &TrustRecorderStatusStore,
        surface_id: &str,
        did: &str,
        entry: EntryStatus,
    ) {
        let now = Utc::now();
        store
            .record(surface_id, did, vec![entry], now, now)
            .await
            .expect("record");
    }

    fn recorder_fixture() -> Fixture {
        let mut fixture = Fixture::new();
        fixture.records = vec![managed("did:a", "s-oxygen"), managed("did:b", "s-helium")];
        fixture
    }

    #[tokio::test]
    async fn test_trust_registry_is_recorded_when_any_identity_is_partly_recorded() {
        let store = TrustRecorderStatusStore::in_memory();
        record_outcome(&store, "s-oxygen", "did:a", EntryStatus::from_counts("tr", 0, 0, 1, None)).await;
        record_outcome(
            &store,
            "s-helium",
            "did:b",
            EntryStatus::from_counts("tr", 1, 0, 1, Some(RecorderReason::Rejected)),
        )
        .await;
        let agent = recorder_fixture()
            .only(&[surface("s-oxygen"), surface("s-helium")], Some(&store))
            .await;
        assert!(agent.trust_registry.recorded);
    }

    #[tokio::test]
    async fn test_trust_registry_is_recorded_when_an_identity_is_recorded() {
        let store = TrustRecorderStatusStore::in_memory();
        record_outcome(&store, "s-helium", "did:b", EntryStatus::from_counts("tr", 1, 0, 0, None)).await;
        let agent = recorder_fixture()
            .only(&[surface("s-oxygen"), surface("s-helium")], Some(&store))
            .await;
        assert!(agent.trust_registry.recorded);
    }

    #[tokio::test]
    async fn test_trust_registry_is_not_recorded_when_every_outcome_failed() {
        let store = TrustRecorderStatusStore::in_memory();
        record_outcome(&store, "s-oxygen", "did:a", EntryStatus::from_counts("tr", 0, 0, 1, None)).await;
        record_outcome(&store, "s-helium", "did:b", EntryStatus::skipped("tr", RecorderReason::NoSurfaceIssuer)).await;
        let agent = recorder_fixture()
            .only(&[surface("s-oxygen"), surface("s-helium")], Some(&store))
            .await;
        assert!(!agent.trust_registry.recorded);
    }

    #[tokio::test]
    async fn test_stale_recorder_status_is_ignored() {
        let store = TrustRecorderStatusStore::in_memory();
        record_outcome(&store, "s-oxygen", "did:old", EntryStatus::from_counts("tr", 1, 0, 0, None)).await;
        record_outcome(&store, "s-other", "did:a", EntryStatus::from_counts("tr", 1, 0, 0, None)).await;
        let agent = recorder_fixture()
            .only(&[surface("s-oxygen"), surface("s-helium")], Some(&store))
            .await;
        assert!(!agent.trust_registry.recorded);
    }

    #[tokio::test]
    async fn test_unavailable_recorder_store_is_not_recorded() {
        let agent = recorder_fixture()
            .only(&[surface("s-oxygen"), surface("s-helium")], None)
            .await;
        assert_eq!(agent.trust_registry, AgentTrustRegistry { recorded: false });
    }

    #[tokio::test]
    async fn test_agents_sort_by_display_name_ignoring_case_then_id() {
        let surfaces = [
            with_canvas_name(targeting("s1", "https://one.example"), "bravo"),
            with_canvas_name(targeting("s2", "https://two.example"), "Alpha"),
            targeting("s3", "https://three.example"),
            with_canvas_name(targeting("s4", "https://four.example"), "alpha"),
        ];
        let agents = Fixture::new()
            .agents(&surfaces, None, &no_card)
            .await;
        let names: Vec<Option<&str>> = agents
            .iter()
            .map(|agent| agent.name.as_deref())
            .collect();
        assert_eq!(&names[2..], &[Some("bravo"), None]);
        let (first, second) = (&agents[0], &agents[1]);
        assert!(first.id < second.id, "equal names fall back to id");
        assert_eq!(
            [first.name.as_deref(), second.name.as_deref()]
                .into_iter()
                .map(|name| name.map(str::to_lowercase))
                .collect::<Vec<_>>(),
            vec![Some("alpha".to_string()), Some("alpha".to_string())]
        );
    }

    #[tokio::test]
    async fn test_an_agent_with_only_disabled_surfaces_is_listed() {
        let mut disabled = surface("s1");
        disabled.status = SurfaceStatus::Disabled;
        let live = [disabled];
        let groups = listed_groups(&live, None, None);
        assert_eq!(groups.len(), 1);
        let json = serde_json::to_value(
            Fixture::new()
                .only(&live, None)
                .await,
        )
        .expect("serialize");
        assert!(json.get("status").is_none());
        assert!(
            json["surfaces"][0]
                .get("status")
                .is_none()
        );
    }

    #[test]
    fn test_is_listed_excludes_deleted_surfaces() {
        let mut deleted = surface("s1");
        deleted.status = SurfaceStatus::Deleted;
        let mut disabled = surface("s2");
        disabled.status = SurfaceStatus::Disabled;
        assert!(!is_listed(&deleted, None, None));
        assert!(is_listed(&disabled, None, None));
    }

    #[test]
    fn test_is_listed_excludes_mcp_surfaces() {
        let mut mcp = surface("s1");
        mcp.access_point.protocol = SurfaceProtocol::Mcp;
        let mut ap2 = surface("s2");
        ap2.access_point.protocol = SurfaceProtocol::Ap2;
        assert!(!is_listed(&mcp, None, None));
        assert!(is_listed(&ap2, None, None));
        assert!(is_listed(&surface("s3"), None, None));
    }

    #[test]
    fn test_is_listed_isolates_tenants_and_shows_untenanted() {
        let mut own = surface("own");
        own.tenant_id = Some("tenant-a".to_string());
        let mut other = surface("other");
        other.tenant_id = Some("tenant-b".to_string());
        let global = surface("global");
        let context = tenant("tenant-a");
        assert!(is_listed(&own, Some(&context), None));
        assert!(!is_listed(&other, Some(&context), None));
        assert!(is_listed(&global, Some(&context), None));
        assert!(is_listed(&other, None, None));
    }

    #[test]
    fn test_is_listed_applies_pat_resource_scope() {
        let scope = PatResourceScope(Arc::new(Regex::new("^TENANT:tenant-a:surfaces:allowed$").expect("regex")));
        let context = tenant("tenant-a");
        let mut allowed = surface("allowed");
        allowed.tenant_id = Some("tenant-a".to_string());
        let mut denied = surface("denied");
        denied.tenant_id = Some("tenant-a".to_string());
        assert!(is_listed(&allowed, Some(&context), Some(&scope)));
        assert!(!is_listed(&denied, Some(&context), Some(&scope)));
    }

    #[test]
    fn test_traffic_takes_inbound_counts_and_keeps_window() {
        let inbound = InboundTraffic {
            total: 15,
            failed: 3,
            gateway_faults: 1,
            p95_latency_ms: Some(120),
        };
        assert_eq!(
            traffic(inbound, 360),
            AgentTraffic {
                window_minutes: 360,
                total_requests: 15,
                failed: 3,
                gateway_faults: 1,
                p95_latency_ms: Some(120),
            }
        );
        assert_eq!(traffic(InboundTraffic::default(), 360).total_requests, 0);
    }

    #[tokio::test]
    async fn test_agent_details_serialize_without_raw_or_removed_fields() {
        let mut source = with_canvas_name(targeting("s1", "https://user:pw@agent.example/a2a?token=abc"), "TimeAsker");
        let mut ap2 = targeting("s2", "https://agent.example/a2a");
        ap2.access_point.protocol = SurfaceProtocol::Ap2;
        source.agent_did = Some("did:web:a".to_string());
        let mut identity = managed("did:web:a", "s1");
        identity.private_key = Some(serde_json::json!({ "d": "secret-key-material" }));
        let records = vec![identity];
        let by_did = managed_by_did(&records);
        let stats = HashMap::new();
        let data = RegistryData {
            identity_records: &records,
            managed_surfaces_by_did: &by_did,
            stats: &stats,
        };
        let live = [source, ap2];
        let group = &group_surfaces(&live)[0];
        let details = AgentDetails {
            agent: agent_record(group, &data, None, &no_card, surface_summary).await,
            traffic: traffic(InboundTraffic::default(), 360),
        };

        let json = serde_json::to_value(&details).expect("serialize");
        let text = json.to_string();
        for forbidden in [
            "private_key",
            "secret-key-material",
            "canvas",
            "trust_recorder",
            "user:pw",
            "token=abc",
            "surface_name",
            "agent_did",
            "did_surface_count",
            "identity_created_at",
            "recognized",
            "authorized",
            "\"status\"",
        ] {
            assert!(!text.contains(forbidden), "response contains {forbidden}: {text}");
        }
        assert_eq!(json["id"], group.id);
        assert_eq!(json["name"], "TimeAsker");
        assert!(
            json.get("registration")
                .is_none()
        );
        assert_eq!(json["runtime"], "url");
        assert_eq!(json["protocol"], "a2a");
        assert_eq!(json["endpoint"], "https://agent.example/a2a");
        assert_eq!(json["trust_registry"], serde_json::json!({ "recorded": false }));
        assert_eq!(
            json["identities"],
            serde_json::json!([{ "did": "did:web:a", "created_at": records[0].created_at, "source": "surface" }])
        );
        assert_eq!(
            json["surfaces"],
            serde_json::json!([
                { "surface_id": "s1", "name": "s1-name", "protocol": "a2a", "route": "/s1" },
                { "surface_id": "s2", "name": "s2-name", "protocol": "ap2", "route": "/s2" },
            ])
        );
        assert_eq!(json["traffic"]["p95_latency_ms"], serde_json::Value::Null);
        assert_eq!(json["last_activity_at"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_internal_error_response_has_no_details() {
        let response = AgentApiError::Internal("disk on fire at /var/secret/path".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json, serde_json::json!({ "error": "Internal Server Error" }));
    }

    #[tokio::test]
    async fn test_not_found_response_is_generic() {
        let response = AgentApiError::NotFound.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({ "error": "Not Found" })
        );
    }

    /// Returns `card` (or nothing when `None`), counts the fetches and keeps the last endpoint.
    struct CountingSource {
        card: std::sync::Mutex<Option<Value>>,
        fetches: std::sync::atomic::AtomicUsize,
        last_endpoint: std::sync::Mutex<Option<String>>,
    }

    impl CountingSource {
        fn new(card: Option<Value>) -> Arc<Self> {
            Arc::new(Self {
                card: std::sync::Mutex::new(card),
                fetches: std::sync::atomic::AtomicUsize::new(0),
                last_endpoint: std::sync::Mutex::new(None),
            })
        }

        fn fetches(&self) -> usize {
            self.fetches
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        fn last_endpoint(&self) -> Option<String> {
            self.last_endpoint
                .lock()
                .expect("lock")
                .clone()
        }

        fn set_card(
            &self,
            card: Option<Value>,
        ) {
            *self
                .card
                .lock()
                .expect("lock") = card;
        }
    }

    #[async_trait]
    impl TargetCardSource for CountingSource {
        async fn fetch_agent_card(
            &self,
            location: &CardLocation,
        ) -> Option<Value> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self
                .last_endpoint
                .lock()
                .expect("lock") = Some(location.endpoint.clone());
            self.card
                .lock()
                .expect("lock")
                .clone()
        }
    }

    fn location_of(surfaces: &[AgentSurface]) -> Result<CardLocation, AgentCardUnavailable> {
        agent_card_location(&group_surfaces(surfaces)[0], None)
    }

    fn in_tenant(
        mut surface: AgentSurface,
        tenant_id: &str,
    ) -> AgentSurface {
        surface.tenant_id = Some(tenant_id.to_string());
        surface
    }

    #[test]
    fn test_agent_card_location_checks_protocol_before_runtime() {
        for (protocol, endpoint, expected) in [
            (SurfaceProtocol::DIDComm, "http://localhost:9002", Err(AgentCardUnavailable::NoAgentCard)),
            (SurfaceProtocol::DIDComm, "a2a-proxy://proxy-1", Err(AgentCardUnavailable::NoAgentCard)),
            (SurfaceProtocol::A2a, "a2a-proxy://proxy-1", Err(AgentCardUnavailable::UnsupportedRuntime)),
            (SurfaceProtocol::Ap2, "fabric://gateway-1/channel-1", Err(AgentCardUnavailable::UnsupportedRuntime)),
            (
                SurfaceProtocol::Ap2,
                "https://agent.example.com",
                Ok(CardLocation {
                    endpoint: "https://agent.example.com".to_string(),
                    card_path: None,
                }),
            ),
        ] {
            let mut surface = targeting("s1", endpoint);
            surface.access_point.protocol = protocol;
            assert_eq!(location_of(&[surface]), expected, "{endpoint}");
        }
    }

    #[test]
    fn test_agent_card_location_uses_a_surface_that_can_reach_the_card() {
        let mut didcomm = targeting("a-first", "https://user:pw@agent.example/a2a");
        didcomm.access_point.protocol = SurfaceProtocol::DIDComm;
        let mut a2a = targeting("b-second", "https://user:pw@agent.example/a2a");
        a2a.access_point
            .agent_card_path = Some("/cards/time.json".to_string());
        didcomm
            .access_point
            .agent_card_path = a2a
            .access_point
            .agent_card_path
            .clone();
        let location = location_of(&[didcomm, a2a]).expect("location");
        assert_eq!(location.endpoint, "https://agent.example/a2a", "fetched without userinfo");
        assert_eq!(location.card_path.as_deref(), Some("/cards/time.json"));
    }

    #[tokio::test]
    async fn test_agent_card_response_tenant_on_appliance_wide_surface_is_operator_only() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let live = [targeting("s1", "https://user:pw@agent.example/a2a")];
        let group = &group_surfaces(&live)[0];
        let response = agent_card_response(group, Some(&tenant("t1")), &cache)
            .await
            .expect("response");
        assert_eq!(
            serde_json::to_value(&response).expect("serialize"),
            serde_json::json!({ "available": false, "reason": "operator_only" })
        );
        assert_eq!(source.fetches(), 0, "nothing fetched for the tenant");

        let response = agent_card_response(group, None, &cache)
            .await
            .expect("response");
        assert!(response.available, "the operator still reads the card");
        assert_eq!(source.fetches(), 1);
        assert_eq!(
            source
                .last_endpoint()
                .as_deref(),
            Some("https://agent.example/a2a"),
            "no userinfo is sent"
        );
    }

    #[tokio::test]
    async fn test_agent_card_response_tenant_reads_through_its_own_surface() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let live = [
            targeting("a-appliance", "https://root:secret@agent.example/a2a"),
            in_tenant(targeting("b-other", "https://other@agent.example/a2a/"), "t2"),
            in_tenant(targeting("c-own", "https://own@agent.example/a2a/"), "t1"),
        ];
        let groups = group_surfaces(&live);
        assert_eq!(groups.len(), 1, "one managed agent");
        let response = agent_card_response(&groups[0], Some(&tenant("t1")), &cache)
            .await
            .expect("response");
        assert!(response.available);
        assert_eq!(
            source
                .last_endpoint()
                .as_deref(),
            Some("https://agent.example/a2a/"),
            "the own surface's location"
        );
    }

    #[tokio::test]
    async fn test_agent_card_response_unavailable_skips_fetch() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let mut didcomm = surface("s1");
        didcomm.access_point.protocol = SurfaceProtocol::DIDComm;
        let live = [didcomm];
        let response = agent_card_response(&group_surfaces(&live)[0], None, &cache)
            .await
            .expect("response");
        assert_eq!(
            serde_json::to_value(&response).expect("serialize"),
            serde_json::json!({ "available": false, "reason": "no_agent_card" })
        );
        let live = [targeting("s2", "a2a-proxy://proxy-1")];
        let response = agent_card_response(&group_surfaces(&live)[0], None, &cache)
            .await
            .expect("response");
        assert_eq!(
            serde_json::to_value(&response).expect("serialize"),
            serde_json::json!({ "available": false, "reason": "unsupported_runtime" })
        );
        assert_eq!(source.fetches(), 0);
    }

    #[tokio::test]
    async fn test_agent_card_response_returns_card() {
        let card = serde_json::json!({ "name": "TimeAsker", "skills": [] });
        let cache = AgentCardCache::new(
            CountingSource::new(Some(card.clone())),
            AGENT_CARD_CACHE_TTL,
            AGENT_CARD_FAILURE_CACHE_TTL,
        );
        let live = [surface("s1")];
        let response = agent_card_response(&group_surfaces(&live)[0], None, &cache)
            .await
            .expect("response");
        assert_eq!(
            serde_json::to_value(&response).expect("serialize"),
            serde_json::json!({ "available": true, "card": card })
        );
    }

    #[tokio::test]
    async fn test_agent_card_fetch_failure_is_generic_502() {
        let cache = AgentCardCache::new(CountingSource::new(None), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let live = [surface("s1")];
        let error = agent_card_response(&group_surfaces(&live)[0], None, &cache)
            .await
            .expect_err("fetch fails");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({ "error": "Bad Gateway" })
        );
    }

    #[tokio::test]
    async fn test_agent_card_cache_reuses_card_per_agent_and_location() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let location = location_of(&[surface("s1")]).expect("location");
        cache
            .get("a1", &location)
            .await
            .expect("card");
        cache
            .get("a1", &location)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 1);

        cache
            .get("a2", &location)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 2, "cached per agent");

        let moved = CardLocation {
            endpoint: "http://localhost:9003".to_string(),
            card_path: None,
        };
        cache
            .get("a1", &moved)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 3, "a new location is fetched again");
    }

    #[tokio::test]
    async fn test_agent_card_cache_reuses_failure_until_failure_ttl() {
        let source = CountingSource::new(None);
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let location = location_of(&[surface("s1")]).expect("location");
        assert_eq!(
            cache
                .get("a1", &location)
                .await,
            None
        );

        source.set_card(Some(serde_json::json!({ "name": "TimeAsker" })));
        assert_eq!(
            cache
                .get("a1", &location)
                .await,
            None,
            "the failure is reused"
        );
        assert_eq!(source.fetches(), 1);

        let moved = CardLocation {
            endpoint: "http://localhost:9003".to_string(),
            card_path: None,
        };
        assert!(
            cache
                .get("a1", &moved)
                .await
                .is_some(),
            "a new location is fetched again"
        );
    }

    /// Fails every fetch, holding each one until the test releases it.
    struct GatedSource {
        fetches: std::sync::atomic::AtomicUsize,
        release: tokio::sync::Semaphore,
    }

    #[async_trait]
    impl TargetCardSource for GatedSource {
        async fn fetch_agent_card(
            &self,
            _location: &CardLocation,
        ) -> Option<Value> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.release
                .acquire()
                .await
                .expect("open")
                .forget();
            None
        }
    }

    #[tokio::test]
    async fn test_agent_card_cache_shares_concurrent_fetches_per_agent() {
        let source = Arc::new(GatedSource {
            fetches: std::sync::atomic::AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        });
        let cache = Arc::new(AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL));
        let location = location_of(&[surface("s1")]).expect("location");
        let mut views = tokio::task::JoinSet::new();
        for id in ["a1", "a1", "a1", "a1", "a1", "a2"] {
            let (cache, location) = (cache.clone(), location.clone());
            views.spawn(async move { cache.get(id, &location).await });
        }
        while source
            .fetches
            .load(std::sync::atomic::Ordering::SeqCst)
            < 2
        {
            tokio::task::yield_now().await;
        }
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        source.release.add_permits(10);
        while let Some(card) = views.join_next().await {
            assert_eq!(card.expect("view"), None);
        }
        assert_eq!(
            source
                .fetches
                .load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one fetch per agent"
        );
        assert_eq!(
            cache
                .get("a1", &location)
                .await,
            None,
            "the failure is cached"
        );
        assert_eq!(
            source
                .fetches
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert!(cache.fetching.is_empty(), "no per-agent locks are left behind");
    }

    #[tokio::test]
    async fn test_agent_card_cache_refetches_after_ttls() {
        let source = CountingSource::new(None);
        let cache = AgentCardCache::new(source.clone(), std::time::Duration::ZERO, std::time::Duration::ZERO);
        let location = location_of(&[surface("s1")]).expect("location");
        assert_eq!(
            cache
                .get("a1", &location)
                .await,
            None
        );

        source.set_card(Some(serde_json::json!({ "name": "TimeAsker" })));
        assert!(
            cache
                .get("a1", &location)
                .await
                .is_some(),
            "an expired failure is fetched again"
        );
        cache
            .get("a1", &location)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 3, "an expired card is fetched again");
    }

    #[tokio::test]
    async fn test_agent_card_cache_drops_expired_entries_on_store() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), std::time::Duration::ZERO, std::time::Duration::ZERO);
        let location = location_of(&[surface("s1")]).expect("location");
        for id in ["a1", "a2", "a3"] {
            cache
                .get(id, &location)
                .await
                .expect("card");
        }
        assert_eq!(cache.entries.len(), 1);
        assert!(
            cache
                .entries
                .contains_key("a3")
        );

        let kept = AgentCardCache::new(source, AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        for id in ["a1", "a2"] {
            kept.get(id, &location)
                .await
                .expect("card");
        }
        assert_eq!(kept.entries.len(), 2, "unexpired entries are kept");
    }

    async fn spawn_card_server(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener
            .local_addr()
            .expect("addr");
        tokio::spawn(async move { axum::serve(listener, router).await });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn test_http_agent_card_source_reads_well_known_card() {
        let endpoint = spawn_card_server(axum::Router::new().route(
            "/.well-known/agent-card.json",
            axum::routing::get(|| async { Json(serde_json::json!({ "name": "TimeAsker" })) }),
        ))
        .await;
        let card = HttpAgentCardSource
            .fetch_agent_card(&CardLocation { endpoint, card_path: None })
            .await;
        assert_eq!(card, Some(serde_json::json!({ "name": "TimeAsker" })));
    }

    #[tokio::test]
    async fn test_http_agent_card_source_does_not_follow_redirects() {
        let redirect = || async { axum::response::Redirect::temporary("/real-card") };
        let endpoint = spawn_card_server(
            axum::Router::new()
                .route("/.well-known/agent-card.json", axum::routing::get(redirect))
                .route("/.well-known/agent.json", axum::routing::get(redirect))
                .route(
                    "/real-card",
                    axum::routing::get(|| async { Json(serde_json::json!({ "name": "Redirected" })) }),
                ),
        )
        .await;
        let card = HttpAgentCardSource
            .fetch_agent_card(&CardLocation { endpoint, card_path: None })
            .await;
        assert_eq!(card, None);
    }
}
