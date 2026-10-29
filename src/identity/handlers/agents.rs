//! Read-only Agents API: one agent record per Agent Surface the caller can access.
//!
//! Records are built from the surface, the managed identities used on it and the
//! retained request metrics. Identities and metrics are joined only to surfaces
//! already in the caller's tenant and resource scope.

use std::collections::{BTreeSet, HashMap};
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
use tracing::{debug, error, warn};

use crate::auth_manager::pat::PatResourceScope;
use crate::config::agent_surface::{AgentSurface, SurfaceProtocol, SurfaceStatus};
use crate::config::types::TrustRecorderConfig;
use crate::identity::display_name::managed_surfaces_by_did;
use crate::identity::filesystem::{AgentIdentityRecord, IdentityOrigin};
use crate::identity::state::IdentityApiState;
use crate::identity::target_card_names::{CardLocation, TargetCardSource};
use crate::metrics::SurfaceStats;
use crate::observability::caller_names::{AGENT_CARD_FETCH_TIMEOUT, AGENT_CARD_MAX_BYTES};
use crate::proxy::upstream_body::UpstreamBodyLimits;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

const AGENT_CARD_CACHE_TTL: Duration = Duration::from_secs(300);
const AGENT_CARD_FAILURE_CACHE_TTL: Duration = Duration::from_secs(30);

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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentRegistration {
    Unregistered,
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

/// Trust Registry records the surface is configured to write. Configuration
/// only: nothing here was checked against a Trust Registry.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct AgentTrustRegistry {
    pub recognized: bool,
    pub authorized: bool,
}

impl AgentTrustRegistry {
    fn from_recorder(recorder: Option<&TrustRecorderConfig>) -> Self {
        let entries = recorder.map_or(&[][..], |recorder| recorder.entries.as_slice());
        let has_record_type = |record_type: &str| {
            entries.iter().any(|entry| {
                entry
                    .custom_resources
                    .iter()
                    .any(|resource| resource.record_type == record_type)
            })
        };
        Self {
            recognized: entries.iter().any(|entry| {
                entry
                    .custom_resources
                    .is_empty()
            }) || has_record_type("recognition"),
            authorized: has_record_type("authorization"),
        }
    }
}

/// The managed identity shown as a surface's agent DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedIdentity {
    pub did: String,
    pub created_at: Option<DateTime<Utc>>,
    pub surface_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentRecord {
    pub id: String,
    pub registration: AgentRegistration,
    pub name: Option<String>,
    pub surface_name: String,
    pub status: SurfaceStatus,
    pub protocol: SurfaceProtocol,
    pub runtime: AgentRuntime,
    pub endpoint: String,
    pub tags: Vec<String>,
    pub trust_registry: AgentTrustRegistry,
    pub agent_did: Option<String>,
    pub did_surface_count: usize,
    pub identity_created_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentSurfaceSummary {
    pub surface_id: String,
    pub name: String,
    pub protocol: SurfaceProtocol,
    pub route: String,
    pub status: SurfaceStatus,
}

/// Request totals over the metrics retention window, summed across the
/// agent's surfaces. `p95_latency_ms` is taken from the raw inbound latencies.
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
    pub agent: AgentRecord,
    pub surfaces: Vec<AgentSurfaceSummary>,
    pub traffic: AgentTraffic,
}

#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentRecord>,
}

/// Why the agent's own Agent Card can't be fetched.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentCardUnavailable {
    NoAgentCard,
    UnsupportedRuntime,
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
    surface.status != SurfaceStatus::Deleted
        && can_access(surface.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Surfaces, &surface.surface_id)
}

/// When `record`, a managed identity, was last used on `surface_id`.
fn last_used_on(
    record: &AgentIdentityRecord,
    surface_id: &str,
) -> Option<DateTime<Utc>> {
    record
        .channel_usage
        .iter()
        .filter(|usage| usage.channel_config_id == surface_id)
        .map(|usage| usage.last_used_at)
        .max()
        .or_else(|| {
            (record
                .channel_config_id
                .as_deref()
                == Some(surface_id))
            .then_some(record.last_used_at)
            .flatten()
        })
}

fn earliest_created_at(
    records: &[AgentIdentityRecord],
    did: &str,
) -> Option<DateTime<Utc>> {
    records
        .iter()
        .filter(|record| record.did == did)
        .map(|record| record.created_at)
        .min()
}

fn did_surface_count(
    surfaces_by_did: &HashMap<String, BTreeSet<String>>,
    did: &str,
    surface_id: &str,
) -> usize {
    let surfaces = surfaces_by_did.get(did);
    surfaces.map_or(0, BTreeSet::len) + usize::from(!surfaces.is_some_and(|ids| ids.contains(surface_id)))
}

/// The surface's own `agent_did` when set; otherwise the managed identity most
/// recently used on the surface.
pub fn match_identity(
    surface: &AgentSurface,
    records: &[AgentIdentityRecord],
    surfaces_by_did: &HashMap<String, BTreeSet<String>>,
) -> Option<MatchedIdentity> {
    let surface_id = surface.surface_id.as_str();
    let did = match surface.agent_did.as_deref() {
        Some(did) if !did.is_empty() => did.to_string(),
        _ => records
            .iter()
            .filter(|record| record.effective_origin() == Some(IdentityOrigin::Managed))
            .filter(|record| {
                surfaces_by_did
                    .get(&record.did)
                    .is_some_and(|ids| ids.contains(surface_id))
            })
            .max_by(|a, b| {
                last_used_on(a, surface_id)
                    .cmp(&last_used_on(b, surface_id))
                    .then_with(|| b.did.cmp(&a.did))
            })?
            .did
            .clone(),
    };
    Some(MatchedIdentity {
        created_at: earliest_created_at(records, &did),
        surface_count: did_surface_count(surfaces_by_did, &did, surface_id),
        did,
    })
}

pub fn build_agent_record(
    surface: &AgentSurface,
    identity: Option<&MatchedIdentity>,
    stats: Option<&SurfaceStats>,
) -> AgentRecord {
    AgentRecord {
        id: surface.surface_id.clone(),
        registration: AgentRegistration::Unregistered,
        name: canvas_target_name(surface.canvas.as_ref()),
        surface_name: surface.name.clone(),
        status: surface.status.clone(),
        protocol: surface
            .access_point
            .protocol
            .clone(),
        runtime: AgentRuntime::from_endpoint(&surface.target.endpoint),
        endpoint: surface
            .target
            .endpoint
            .clone(),
        tags: surface.tags.clone(),
        trust_registry: AgentTrustRegistry::from_recorder(
            surface
                .access_point
                .trust_recorder
                .as_ref(),
        ),
        agent_did: identity.map(|identity| identity.did.clone()),
        did_surface_count: identity.map_or(0, |identity| identity.surface_count),
        identity_created_at: identity.and_then(|identity| identity.created_at),
        last_activity_at: stats.and_then(|stats| stats.last_activity),
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
        status: surface.status.clone(),
    }
}

fn traffic(
    stats: &[&SurfaceStats],
    window_minutes: u64,
    p95_latency_ms: Option<u64>,
) -> AgentTraffic {
    AgentTraffic {
        window_minutes,
        total_requests: stats
            .iter()
            .map(|s| s.total_connections)
            .sum(),
        failed: stats
            .iter()
            .map(|s| s.failed)
            .sum(),
        gateway_faults: stats
            .iter()
            .map(|s| s.gateway_faults)
            .sum(),
        p95_latency_ms,
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

/// List one agent record per non-deleted surface the caller can access.
pub async fn list_agents(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentListResponse>, AgentApiError> {
    let live_surfaces = all_surfaces(&state).await?;
    let surfaces: Vec<&AgentSurface> = live_surfaces
        .iter()
        .filter(|surface| is_listed(surface, tenant_context(&context), resource_scope(&scope)))
        .collect();
    if surfaces.is_empty() {
        return Ok(Json(AgentListResponse { agents: Vec::new() }));
    }

    let records = identity_records(&state).await?;
    let by_did = surfaces_by_did(&records, &live_surfaces);
    let stats = stats_by_surface(&state).await;

    let mut agents: Vec<AgentRecord> = surfaces
        .iter()
        .map(|surface| {
            let identity = match_identity(surface, &records, &by_did);
            build_agent_record(surface, identity.as_ref(), stats.get(&surface.surface_id))
        })
        .collect();
    agents.sort_by(|a, b| {
        a.surface_name
            .cmp(&b.surface_name)
            .then_with(|| a.id.cmp(&b.id))
    });

    debug!(count = agents.len(), "Listed agents");
    Ok(Json(AgentListResponse { agents }))
}

/// The surface behind agent `id`. 404 when it's missing, deleted or outside the
/// caller's tenant or resource scope.
async fn listed_surface(
    state: &IdentityApiState,
    id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<AgentSurface, AgentApiError> {
    surface_store(state)?
        .get(id)
        .await
        .map_err(|e| AgentApiError::Internal(format!("failed to get surface: {e}")))?
        .filter(|surface| is_listed(surface, tenant_context(context), resource_scope(scope)))
        .ok_or(AgentApiError::NotFound)
}

/// One agent record plus its surfaces and traffic.
pub async fn get_agent(
    Path(id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AgentDetails>, AgentApiError> {
    let surface = listed_surface(&state, &id, &context, &scope).await?;

    let records = identity_records(&state).await?;
    let by_did = surfaces_by_did(&records, &all_surfaces(&state).await?);
    let identity = match_identity(&surface, &records, &by_did);
    let stats = stats_by_surface(&state).await;
    let surface_stats = stats.get(&surface.surface_id);

    let surface_ids = [surface.surface_id.as_str()];
    let p95_latency_ms = state
        .metrics_store
        .inbound_p95_latency_ms(&surface_ids)
        .await;

    Ok(Json(AgentDetails {
        agent: build_agent_record(&surface, identity.as_ref(), surface_stats),
        surfaces: vec![surface_summary(&surface)],
        traffic: traffic(
            surface_stats.as_slice(),
            state
                .metrics_store
                .retention_minutes(),
            p95_latency_ms,
        ),
    }))
}

/// Where the agent publishes its own card. The protocol is checked first, so
/// `no_agent_card` wins when both reasons apply.
fn agent_card_location(surface: &AgentSurface) -> Result<CardLocation, AgentCardUnavailable> {
    if !matches!(surface.access_point.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2) {
        return Err(AgentCardUnavailable::NoAgentCard);
    }
    CardLocation::for_surface(surface).ok_or(AgentCardUnavailable::UnsupportedRuntime)
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

/// Fetch results per surface. A card is reused until `ttl` passes and a failure
/// until `failure_ttl` passes, or until the surface's card location changes.
/// Caching failures stops repeated views of an unreachable agent from each
/// waiting for the fetch timeout.
pub struct AgentCardCache {
    entries: DashMap<String, CachedCard>,
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
            source,
            ttl,
            failure_ttl,
        }
    }

    pub async fn get(
        &self,
        surface_id: &str,
        location: &CardLocation,
    ) -> Option<Value> {
        if let Some(cached) = self.entries.get(surface_id)
            && cached.location == *location
        {
            let ttl = if cached.card.is_some() {
                self.ttl
            } else {
                self.failure_ttl
            };
            if cached.fetched_at.elapsed() < ttl {
                return cached.card.clone();
            }
        }
        let card = self
            .source
            .fetch_agent_card(location)
            .await;
        self.entries.insert(
            surface_id.to_string(),
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
    surface: &AgentSurface,
    cache: &AgentCardCache,
) -> Result<AgentCardResponse, AgentApiError> {
    let location = match agent_card_location(surface) {
        Ok(location) => location,
        Err(reason) => return Ok(AgentCardResponse::unavailable(reason)),
    };
    match cache
        .get(&surface.surface_id, &location)
        .await
    {
        Some(card) => Ok(AgentCardResponse::available(card)),
        None => {
            warn!(surface_id = %surface.surface_id, "Agent Card fetch failed");
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
    let surface = listed_surface(&state, &id, &context, &scope).await?;
    agent_card_response(&surface, AgentCardCache::global())
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{CustomResource, EntityTarget, TrustRecorderEntry};
    use crate::identity::filesystem::ChannelUsage;
    use crate::identity::test_helpers::test_surface_identity_record;
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

    fn managed(
        did: &str,
        surface_id: &str,
        last_used_at: DateTime<Utc>,
    ) -> AgentIdentityRecord {
        let mut record = test_surface_identity_record(did, surface_id);
        record.origin = Some(IdentityOrigin::Managed);
        record.channel_usage[0].last_used_at = last_used_at;
        record
    }

    fn managed_by_did(records: &[AgentIdentityRecord]) -> HashMap<String, BTreeSet<String>> {
        let mut live = surface("live");
        live.target.endpoint = "a2a-proxy://p1".to_string();
        managed_surfaces_by_did(records, |_| Some(&live))
    }

    fn recorder(resources: &[&[&str]]) -> TrustRecorderConfig {
        TrustRecorderConfig {
            entries: resources
                .iter()
                .map(|record_types| TrustRecorderEntry {
                    trust_registry_id: "tr".to_string(),
                    issuer_did: "did:web:issuer".to_string(),
                    authority_did: "did:web:authority".to_string(),
                    include_owned_agent: true,
                    authority_source: None,
                    custom_resources: record_types
                        .iter()
                        .map(|record_type| CustomResource {
                            action: "is".to_string(),
                            resource: "ownedAgent".to_string(),
                            entity_target: EntityTarget::Agent,
                            record_type: record_type.to_string(),
                        })
                        .collect(),
                })
                .collect(),
        }
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

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "token".to_string(),
            tenant_id: id.to_string(),
        }
    }

    #[test]
    fn test_build_agent_record_finds_target_node_by_type() {
        let surface = with_target_node(
            surface("s1"),
            serde_json::json!({ "id": "target", "type": "target", "label": "TimeAsker", "config": { "name": "TimeAsker" } }),
        );
        let record = build_agent_record(&surface, None, None);
        assert_eq!(record.name.as_deref(), Some("TimeAsker"));
        assert_eq!(record.id, "s1");
        assert_eq!(record.surface_name, "s1-name");
        assert_eq!(record.registration, AgentRegistration::Unregistered);
        assert_eq!(record.tags, vec!["team:platform".to_string()]);
    }

    #[test]
    fn test_build_agent_record_without_target_name_is_unnamed() {
        let missing_name = with_target_node(
            surface("s1"),
            serde_json::json!({ "id": "target", "type": "target", "label": "Managed Agent", "config": { "endpoint": "a2a-proxy://p1" } }),
        );
        let no_target = with_target_node(
            surface("s1"),
            serde_json::json!({ "id": "npc", "type": "npc", "config": { "name": "Caller" } }),
        );
        let blank =
            with_target_node(surface("s1"), serde_json::json!({ "type": "target", "config": { "name": "   " } }));
        for surface in [missing_name, no_target, blank, surface("s1")] {
            assert_eq!(build_agent_record(&surface, None, None).name, None);
        }
    }

    #[test]
    fn test_build_agent_record_runtime_follows_endpoint_scheme() {
        for (endpoint, runtime) in [
            ("https://agent.example.com", AgentRuntime::Url),
            ("http://localhost:9002", AgentRuntime::Url),
            ("a2a-proxy://proxy-1", AgentRuntime::A2aProxy),
            ("fabric://gateway-1/channel-1", AgentRuntime::Gateway),
        ] {
            let mut surface = surface("s1");
            surface.target.endpoint = endpoint.to_string();
            surface.access_point.protocol = SurfaceProtocol::Mcp;
            let record = build_agent_record(&surface, None, None);
            assert_eq!(record.runtime, runtime, "{endpoint}");
            assert_eq!(record.endpoint, endpoint);
            assert_eq!(record.protocol, SurfaceProtocol::Mcp);
        }
    }

    #[test]
    fn test_trust_registry_rules_cover_all_entries() {
        let cases: [(Option<TrustRecorderConfig>, AgentTrustRegistry); 6] = [
            (None, AgentTrustRegistry::default()),
            (
                Some(recorder(&[&[]])),
                AgentTrustRegistry {
                    recognized: true,
                    authorized: false,
                },
            ),
            (
                Some(recorder(&[&["recognition"]])),
                AgentTrustRegistry {
                    recognized: true,
                    authorized: false,
                },
            ),
            (
                Some(recorder(&[&["authorization"]])),
                AgentTrustRegistry {
                    recognized: false,
                    authorized: true,
                },
            ),
            (
                Some(recorder(&[&["recognition", "authorization"]])),
                AgentTrustRegistry {
                    recognized: true,
                    authorized: true,
                },
            ),
            (
                Some(recorder(&[&["authorization"], &["recognition"]])),
                AgentTrustRegistry {
                    recognized: true,
                    authorized: true,
                },
            ),
        ];
        for (config, expected) in cases {
            let mut surface = surface("s1");
            surface
                .access_point
                .trust_recorder = config;
            assert_eq!(build_agent_record(&surface, None, None).trust_registry, expected);
        }
    }

    #[test]
    fn test_match_identity_prefers_surface_agent_did() {
        let mut surface = surface("s1");
        surface.agent_did = Some("did:web:own".to_string());
        let records = vec![managed("did:web:managed", "s1", Utc::now())];
        let matched = match_identity(&surface, &records, &managed_by_did(&records));
        assert_eq!(
            matched,
            Some(MatchedIdentity {
                did: "did:web:own".to_string(),
                created_at: None,
                surface_count: 1,
            })
        );
    }

    #[test]
    fn test_match_identity_ignores_records_without_managed_origin() {
        let mut legacy = test_surface_identity_record("did:web:legacy", "s1");
        legacy.origin = None;
        legacy.is_local = true;
        let mut caller = test_surface_identity_record("did:web:caller", "s1");
        caller.origin = Some(IdentityOrigin::ExternalCaller);
        let records = vec![legacy, caller];
        assert_eq!(match_identity(&surface("s1"), &records, &managed_by_did(&records)), None);
    }

    #[test]
    fn test_match_identity_matches_surface_found_only_in_channel_usage() {
        let mut record = managed("did:web:a", "s2", Utc::now());
        record
            .channel_usage
            .push(ChannelUsage {
                channel_config_id: "s1".to_string(),
                usage_count: 1,
                last_used_at: Utc::now(),
                role: Some(IdentityOrigin::Managed),
            });
        let created_at = record.created_at;
        let records = vec![record];
        let matched = match_identity(&surface("s1"), &records, &managed_by_did(&records));
        assert_eq!(
            matched,
            Some(MatchedIdentity {
                did: "did:web:a".to_string(),
                created_at: Some(created_at),
                surface_count: 2,
            })
        );
    }

    #[test]
    fn test_match_identity_shows_shared_did_on_both_surfaces() {
        let mut record = managed("did:web:shared", "s1", Utc::now());
        record
            .channel_usage
            .push(ChannelUsage {
                channel_config_id: "s2".to_string(),
                usage_count: 1,
                last_used_at: Utc::now(),
                role: Some(IdentityOrigin::Managed),
            });
        let records = vec![record];
        let by_did = managed_by_did(&records);
        for id in ["s1", "s2"] {
            let matched = match_identity(&surface(id), &records, &by_did).expect("matched");
            assert_eq!(matched.did, "did:web:shared");
            assert_eq!(matched.surface_count, 2);
        }
    }

    #[test]
    fn test_match_identity_takes_latest_use_on_this_surface() {
        let now = Utc::now();
        let older = managed("did:web:older", "s1", now - Duration::minutes(10));
        let mut newer = managed("did:web:newer", "s1", now);
        newer.identity_hash = "newer".to_string();
        let records = vec![older, newer];
        let matched = match_identity(&surface("s1"), &records, &managed_by_did(&records)).expect("matched");
        assert_eq!(matched.did, "did:web:newer");
    }

    #[test]
    fn test_match_identity_without_match_is_none() {
        let records = vec![managed("did:web:a", "other", Utc::now())];
        let matched = match_identity(&surface("s1"), &records, &managed_by_did(&records));
        assert_eq!(matched, None);
        let record = build_agent_record(&surface("s1"), matched.as_ref(), None);
        assert_eq!(record.agent_did, None);
        assert_eq!(record.did_surface_count, 0);
        assert_eq!(record.identity_created_at, None);
    }

    #[test]
    fn test_build_agent_record_last_activity_from_stats() {
        let at = Utc::now();
        let with = build_agent_record(&surface("s1"), None, Some(&stats("s1", 3, 1, 0, Some(at))));
        assert_eq!(with.last_activity_at, Some(at));
        assert_eq!(build_agent_record(&surface("s1"), None, None).last_activity_at, None);
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
    fn test_traffic_sums_counts_and_keeps_window() {
        let a = stats("s1", 10, 2, 1, None);
        let b = stats("s2", 5, 1, 0, None);
        assert_eq!(
            traffic(&[&a, &b], 360, Some(120)),
            AgentTraffic {
                window_minutes: 360,
                total_requests: 15,
                failed: 3,
                gateway_faults: 1,
                p95_latency_ms: Some(120),
            }
        );
        assert_eq!(traffic(&[], 360, None).total_requests, 0);
    }

    #[test]
    fn test_agent_details_serialize_without_raw_surface_fields() {
        let mut source =
            with_target_node(surface("s1"), serde_json::json!({ "type": "target", "config": { "name": "TimeAsker" } }));
        source
            .access_point
            .trust_recorder = Some(recorder(&[&["authorization"]]));
        let mut identity = managed("did:web:a", "s1", Utc::now());
        identity.private_key = Some(serde_json::json!({ "d": "secret-key-material" }));
        let records = vec![identity];
        let matched = match_identity(&source, &records, &managed_by_did(&records));
        let details = AgentDetails {
            agent: build_agent_record(&source, matched.as_ref(), None),
            surfaces: vec![surface_summary(&source)],
            traffic: traffic(&[], 360, None),
        };

        let json = serde_json::to_value(&details).expect("serialize");
        let text = json.to_string();
        for forbidden in ["private_key", "secret-key-material", "canvas", "trust_recorder", "authority_did"] {
            assert!(!text.contains(forbidden), "response contains {forbidden}: {text}");
        }
        assert_eq!(json["id"], "s1");
        assert_eq!(json["registration"], "unregistered");
        assert_eq!(json["runtime"], "url");
        assert_eq!(json["protocol"], "a2a");
        assert_eq!(json["status"], "active");
        assert_eq!(json["agent_did"], "did:web:a");
        assert_eq!(json["trust_registry"], serde_json::json!({ "recognized": false, "authorized": true }));
        assert_eq!(json["surfaces"][0]["route"], "/s1");
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

    /// Returns `card` (or nothing when `None`) and counts the fetches.
    struct CountingSource {
        card: std::sync::Mutex<Option<Value>>,
        fetches: std::sync::atomic::AtomicUsize,
    }

    impl CountingSource {
        fn new(card: Option<Value>) -> Arc<Self> {
            Arc::new(Self {
                card: std::sync::Mutex::new(card),
                fetches: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn fetches(&self) -> usize {
            self.fetches
                .load(std::sync::atomic::Ordering::SeqCst)
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
            _location: &CardLocation,
        ) -> Option<Value> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.card
                .lock()
                .expect("lock")
                .clone()
        }
    }

    #[test]
    fn test_agent_card_location_checks_protocol_before_runtime() {
        for (protocol, endpoint, expected) in [
            (SurfaceProtocol::Mcp, "http://localhost:9002", Err(AgentCardUnavailable::NoAgentCard)),
            (SurfaceProtocol::Mcp, "a2a-proxy://proxy-1", Err(AgentCardUnavailable::NoAgentCard)),
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
            let mut surface = surface("s1");
            surface.access_point.protocol = protocol;
            surface.target.endpoint = endpoint.to_string();
            assert_eq!(agent_card_location(&surface), expected, "{endpoint}");
        }
    }

    #[test]
    fn test_agent_card_location_keeps_card_path_override() {
        let mut surface = surface("s1");
        surface
            .access_point
            .agent_card_path = Some("/cards/time.json".to_string());
        assert_eq!(
            agent_card_location(&surface)
                .expect("location")
                .card_path
                .as_deref(),
            Some("/cards/time.json")
        );
    }

    #[tokio::test]
    async fn test_agent_card_response_unavailable_skips_fetch() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let mut mcp = surface("s1");
        mcp.access_point.protocol = SurfaceProtocol::Mcp;
        let response = agent_card_response(&mcp, &cache)
            .await
            .expect("response");
        assert_eq!(
            serde_json::to_value(&response).expect("serialize"),
            serde_json::json!({ "available": false, "reason": "no_agent_card" })
        );
        let mut proxy = surface("s2");
        proxy.target.endpoint = "a2a-proxy://proxy-1".to_string();
        let response = agent_card_response(&proxy, &cache)
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
        let response = agent_card_response(&surface("s1"), &cache)
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
        let error = agent_card_response(&surface("s1"), &cache)
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
    async fn test_agent_card_cache_reuses_card_per_surface_and_location() {
        let source = CountingSource::new(Some(serde_json::json!({ "name": "TimeAsker" })));
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let location = agent_card_location(&surface("s1")).expect("location");
        cache
            .get("s1", &location)
            .await
            .expect("card");
        cache
            .get("s1", &location)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 1);

        cache
            .get("s2", &location)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 2, "cached per surface");

        let moved = CardLocation {
            endpoint: "http://localhost:9003".to_string(),
            card_path: None,
        };
        cache
            .get("s1", &moved)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 3, "a new location is fetched again");
    }

    #[tokio::test]
    async fn test_agent_card_cache_reuses_failure_until_failure_ttl() {
        let source = CountingSource::new(None);
        let cache = AgentCardCache::new(source.clone(), AGENT_CARD_CACHE_TTL, AGENT_CARD_FAILURE_CACHE_TTL);
        let location = agent_card_location(&surface("s1")).expect("location");
        assert_eq!(
            cache
                .get("s1", &location)
                .await,
            None
        );

        source.set_card(Some(serde_json::json!({ "name": "TimeAsker" })));
        assert_eq!(
            cache
                .get("s1", &location)
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
                .get("s1", &moved)
                .await
                .is_some(),
            "a new location is fetched again"
        );
    }

    #[tokio::test]
    async fn test_agent_card_cache_refetches_after_ttls() {
        let source = CountingSource::new(None);
        let cache = AgentCardCache::new(source.clone(), std::time::Duration::ZERO, std::time::Duration::ZERO);
        let location = agent_card_location(&surface("s1")).expect("location");
        assert_eq!(
            cache
                .get("s1", &location)
                .await,
            None
        );

        source.set_card(Some(serde_json::json!({ "name": "TimeAsker" })));
        assert!(
            cache
                .get("s1", &location)
                .await
                .is_some(),
            "an expired failure is fetched again"
        );
        cache
            .get("s1", &location)
            .await
            .expect("card");
        assert_eq!(source.fetches(), 3, "an expired card is fetched again");
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
