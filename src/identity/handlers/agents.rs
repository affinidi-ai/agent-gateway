//! Read-only Agents API: one agent record per managed agent behind the Agent Surfaces the
//! caller can access.
//!
//! Surfaces whose targets share a normalised endpoint and Agent Card path are one managed
//! agent. Only surfaces in the caller's tenant and resource scope are grouped, and
//! identities, Trust Recorder outcomes and metrics are joined only to those surfaces.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::PatResourceScope;
use crate::config::agent_surface::{AgentSurface, SurfaceProtocol, SurfaceStatus};
use crate::identity::display_name::{DisplayName, managed_surfaces_by_did};
use crate::identity::filesystem::AgentIdentityRecord;
use crate::identity::handlers::surfaces::{CARD_FETCH_LIMITED, surface_card_preview};
use crate::identity::state::IdentityApiState;
use crate::identity::target_card_names::{CardLocation, TARGET_CARD_NAME_TTL, TargetCardNameService};
use crate::metrics::{InboundTraffic, SurfaceStats};
use crate::observability::refresh_cache::RefreshCache;
use crate::proxy::card_preview::{AgentCardPreview, CardFetchStatus, PreviewRequest, RateLimited, access_point_url};
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource};
use crate::trust_registry_verification::recorder_status::{
    RecorderReason, RecorderState, TrustRecorderStatusStore, global_store,
};

const JWT_CLAIM_CREDENTIAL_TYPE: &str = "jwt_claim";
const MAX_CONCURRENT_SERVED_NAME_FETCHES: usize = 4;

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

/// Whether any of the agent's current identities was written to a Trust Registry, and the
/// last Trust Recorder outcome per Trust Registry and identity.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct AgentTrustRegistry {
    pub recorded: bool,
    /// Filled on the agent details only; the list leaves it out.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub registries: Vec<AgentRegistryOutcome>,
}

/// The best Trust Recorder outcome of one identity in one Trust Registry across the agent's
/// surfaces. `trust_registry_name` is `null` when the caller may not see that registry.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentRegistryOutcome {
    pub trust_registry_id: String,
    pub trust_registry_name: Option<String>,
    pub did: String,
    pub state: RecorderState,
    pub reason: Option<RecorderReason>,
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
    /// The URL callers reach the surface at: its listener's first external URL and its route.
    /// `null` when no listener with an external URL matches the Access Point.
    pub public_url: Option<String>,
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
    /// The name of the A2A proxy or remote gateway the endpoint names, when the caller
    /// may see that record. Unverified display text.
    pub target_name: Option<String>,
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

/// Why the agent's Agent Card can't be shown.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentCardUnavailable {
    NoAgentCard,
    /// None of the A2A or AP2 surfaces the caller may read the card through runs here.
    NotRunning,
    /// A tenant token whose only A2A or AP2 surfaces are appliance-wide.
    OperatorOnly,
}

/// How the gateway obtains the card it serves for the agent, from the target runtime.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentCardSource {
    /// Fetched from the agent's URL and rewritten to point at the gateway.
    Fetched,
    /// Generated by the A2A proxy.
    Generated,
    /// Served by the remote gateway over Fabric.
    RemoteGateway,
}

impl From<AgentRuntime> for AgentCardSource {
    fn from(runtime: AgentRuntime) -> Self {
        match runtime {
            AgentRuntime::Url => Self::Fetched,
            AgentRuntime::A2aProxy => Self::Generated,
            AgentRuntime::Gateway => Self::RemoteGateway,
        }
    }
}

/// The card the gateway serves for the agent at a surface's base route. Not verified.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentCardResponse {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<AgentCardSource>,
    /// The surface the card was read through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    /// The card as the agent or remote gateway published it, before this gateway rewrote it:
    /// its Agent Card fields only. Absent for a card the A2A proxy generates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_card: Option<Value>,
    /// The surfaces the card may be read through, for `surface_id` in the query.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub card_surface_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AgentCardUnavailable>,
}

/// `GET /v1/agents/{id}/agent-card` query: the surface to read the card through.
#[derive(Debug, Default, Deserialize)]
pub struct AgentCardQuery {
    pub surface_id: Option<String>,
}

/// The top-level Agent Card fields of A2A 0.3 and 1.0 that the response passes on.
const AGENT_CARD_FIELDS: &[&str] = &[
    "protocolVersion",
    "name",
    "description",
    "url",
    "preferredTransport",
    "additionalInterfaces",
    "additional_interfaces",
    "supportedInterfaces",
    "supported_interfaces",
    "iconUrl",
    "provider",
    "version",
    "documentationUrl",
    "capabilities",
    "securitySchemes",
    "security",
    "securityRequirements",
    "defaultInputModes",
    "defaultOutputModes",
    "skills",
    "supportsAuthenticatedExtendedCard",
    "signatures",
];

/// The card's Agent Card fields only, or `None` when the body is not an object with a string
/// `name`, so JSON that is not an Agent Card is never passed on.
fn agent_card_fields(card: Value) -> Option<Value> {
    let Value::Object(mut fields) = card else {
        return None;
    };
    fields.retain(|key, _| AGENT_CARD_FIELDS.contains(&key.as_str()));
    fields
        .get("name")
        .is_some_and(Value::is_string)
        .then_some(Value::Object(fields))
}

impl AgentCardResponse {
    fn available(
        card: Value,
        source: AgentCardSource,
        surface_id: &str,
        upstream_card: Option<Value>,
    ) -> Self {
        Self {
            available: true,
            card: Some(card),
            source: Some(source),
            surface_id: Some(surface_id.to_string()),
            upstream_card,
            card_surface_ids: Vec::new(),
            reason: None,
        }
    }

    fn unavailable(reason: AgentCardUnavailable) -> Self {
        Self {
            available: false,
            card: None,
            source: None,
            surface_id: None,
            upstream_card: None,
            card_surface_ids: Vec::new(),
            reason: Some(reason),
        }
    }
}

/// Errors carry a fixed message only; store and fetch errors are logged, never returned.
#[derive(Debug)]
pub enum AgentApiError {
    NotFound,
    BadGateway,
    /// The caller or the surface used up its card fetches; retry after this many seconds.
    RateLimited(u64),
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
            AgentApiError::RateLimited(retry_after_secs) => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, retry_after_secs.to_string())],
                    Json(serde_json::json!({"error": CARD_FETCH_LIMITED, "code": "rate_limited"})),
                )
                    .into_response();
            }
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
/// endpoint is redacted whole, as is a scheme-less endpoint with any `@` and one whose text
/// before `://` is not an RFC 3986 scheme.
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
    if !is_uri_scheme(scheme) {
        return UNPARSEABLE_ENDPOINT_HOST.to_string();
    }
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

/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, per RFC 3986.
fn is_uri_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
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
    endpoint == UNPARSEABLE_ENDPOINT_HOST
        || endpoint
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

    /// A JWT-claim DID is one parallel agent per claim value, not a version of the
    /// surface's managed agent.
    fn is_jwt_claim(
        &self,
        did: &str,
    ) -> bool {
        self.identity_records
            .iter()
            .any(|record| {
                record.did == did
                    && record
                        .identity_fields
                        .get("credential_type")
                        .and_then(Value::as_str)
                        == Some(JWT_CLAIM_CREDENTIAL_TYPE)
            })
    }

    /// When `did` was last used on `surface_id`, else when it was created.
    fn last_use_on(
        &self,
        did: &str,
        surface_id: &str,
    ) -> Option<DateTime<Utc>> {
        self.identity_records
            .iter()
            .filter(|record| record.did == did)
            .filter_map(|record| {
                record
                    .channel_usage
                    .iter()
                    .find(|usage| usage.channel_config_id == surface_id)
                    .map(|usage| usage.last_used_at)
                    .or_else(|| {
                        (record
                            .channel_config_id
                            .as_deref()
                            == Some(surface_id))
                        .then(|| {
                            record
                                .last_used_at
                                .unwrap_or(record.created_at)
                        })
                    })
            })
            .max()
    }

    /// Each surface's own agent DID plus the current managed identity of each of the group's
    /// surfaces, once per DID. A surface's managed DIDs are versions of one managed agent, so
    /// only the most recently used one is current; JWT-claim DIDs are each their own agent and
    /// all count. Caller identities are never managed, so never included.
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
        let mut current: HashMap<&str, (Option<DateTime<Utc>>, &str)> = HashMap::new();
        for (did, ids) in self.managed_surfaces_by_did {
            let ids: Vec<&str> = ids
                .iter()
                .map(String::as_str)
                .filter(|id| surface_ids.contains(id))
                .collect();
            if ids.is_empty() {
                continue;
            }
            if self.is_jwt_claim(did) {
                sources
                    .entry(did.as_str())
                    .or_insert(IdentitySource::Managed);
                continue;
            }
            for id in ids {
                let candidate = (self.last_use_on(did, id), did.as_str());
                current
                    .entry(id)
                    .and_modify(|best| *best = (*best).max(candidate))
                    .or_insert(candidate);
            }
        }
        for (_, did) in current.into_values() {
            sources
                .entry(did)
                .or_insert(IdentitySource::Managed);
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
type CardName<'a> = dyn Fn(&AgentSurface) -> Option<String> + Sync + 'a;

/// Lowercase, with `_` and `-` read as spaces and runs of whitespace collapsed.
fn normalized_name(name: &str) -> String {
    name.to_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A canvas target name that names a surface, not the agent: one of the group's surface
/// names, or a generated `<kind> surface <n>` such as `proxy_surface_1`.
fn is_surface_placeholder(
    name: &str,
    surfaces: &[&AgentSurface],
) -> bool {
    let name = normalized_name(name);
    if surfaces
        .iter()
        .any(|surface| normalized_name(&surface.name) == name)
    {
        return true;
    }
    matches!(
        name.split(' ').collect::<Vec<_>>().as_slice(),
        [_, "surface", n] if n.parse::<u32>().is_ok()
    )
}

/// The Agent Card name of the most recently active surface that has one, else that
/// surface's canvas target name unless it only names a surface, else none.
fn display_name(
    by_activity: &[&AgentSurface],
    card_name: &CardName<'_>,
) -> Option<String> {
    by_activity
        .iter()
        .find_map(|surface| card_name(surface))
        .or_else(|| {
            by_activity
                .iter()
                .filter_map(|surface| canvas_target_name(surface.canvas.as_ref()))
                .find(|name| !is_surface_placeholder(name, by_activity))
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

/// Lower is better: the outcome kept when one identity has several in one registry.
fn recorder_state_rank(state: RecorderState) -> u8 {
    match state {
        RecorderState::Recorded => 0,
        RecorderState::Partial => 1,
        RecorderState::Failed => 2,
        RecorderState::Skipped => 3,
        RecorderState::NotAttempted => 4,
    }
}

/// The Trust Recorder outcomes of the group's (surface, DID) pairs whose DID is still one of
/// the agent's identities, best per (registry, DID). Recorded when any is Recorded or Partly
/// recorded. Without a store nothing is recorded.
async fn trust_registry_outcomes(
    recorder: Option<&TrustRecorderStatusStore>,
    group: &AgentGroup<'_>,
    identities: &[AgentIdentity],
) -> AgentTrustRegistry {
    let Some(recorder) = recorder else {
        return AgentTrustRegistry::default();
    };
    let mut recorded = false;
    let mut best: BTreeMap<(String, String), AgentRegistryOutcome> = BTreeMap::new();
    for surface in &group.surfaces {
        for identity in identities {
            let Some(status) = recorder
                .status_for(&surface.surface_id, &identity.did)
                .await
            else {
                continue;
            };
            recorded |= matches!(status.state, RecorderState::Recorded | RecorderState::Partial);
            for entry in status.entries {
                let key = (
                    entry
                        .trust_registry_id
                        .clone(),
                    identity.did.clone(),
                );
                let better = best
                    .get(&key)
                    .is_none_or(|kept| recorder_state_rank(entry.state) < recorder_state_rank(kept.state));
                if better {
                    best.insert(
                        key,
                        AgentRegistryOutcome {
                            trust_registry_id: entry.trust_registry_id,
                            trust_registry_name: None,
                            did: identity.did.clone(),
                            state: entry.state,
                            reason: entry.reason,
                        },
                    );
                }
            }
        }
    }
    AgentTrustRegistry {
        recorded,
        registries: best.into_values().collect(),
    }
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
        public_url: None,
    }
}

/// Fills each summary's `public_url` from its surface in `group`.
fn with_public_urls(
    summaries: &mut [AgentSurfaceSummary],
    group: &AgentGroup<'_>,
    network: &crate::config::NetworkConfig,
) {
    for summary in summaries {
        summary.public_url = group
            .surfaces
            .iter()
            .find(|surface| surface.surface_id == summary.surface_id)
            .and_then(|surface| access_point_url(surface, network));
    }
}

async fn agent_record<S>(
    group: &AgentGroup<'_>,
    data: &RegistryData<'_>,
    recorder: Option<&TrustRecorderStatusStore>,
    card_name: &CardName<'_>,
    summarise: fn(&AgentSurface) -> S,
) -> AgentRecord<S> {
    let identities = data.identities(group);
    let trust_registry = trust_registry_outcomes(recorder, group, &identities).await;
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
        trust_registry,
        last_activity_at: group
            .surfaces
            .iter()
            .filter_map(|surface| data.last_activity(surface))
            .max(),
        target_name: None,
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

/// The name of the card the gateway serves through a surface, read when the surface's
/// running configuration had `digest`.
#[derive(Clone)]
struct ServedCardName {
    digest: [u8; 32],
    name: Option<String>,
}

fn served_card_name_changed(
    previous: Option<&ServedCardName>,
    entry: &ServedCardName,
) -> bool {
    previous.and_then(|previous| previous.name.as_ref()) != entry.name.as_ref()
}

/// Served card names per surface, kept for the target card name period and refreshed in the
/// background, at most [`MAX_CONCURRENT_SERVED_NAME_FETCHES`] at once.
fn served_card_names() -> &'static Arc<RefreshCache<ServedCardName>> {
    static NAMES: OnceLock<Arc<RefreshCache<ServedCardName>>> = OnceLock::new();
    NAMES.get_or_init(|| {
        Arc::new(RefreshCache::new(TARGET_CARD_NAME_TTL, MAX_CONCURRENT_SERVED_NAME_FETCHES, served_card_name_changed))
    })
}

/// An A2A or AP2 surface whose card the gateway generates (`a2a-proxy://`) or reads from a
/// remote gateway (`fabric://`), so its name is read from the served card, not fetched
/// from the target.
fn names_from_served_card(surface: &AgentSurface) -> bool {
    surface.uses_a2a_settings() && AgentRuntime::from_endpoint(surface.target.endpoint.trim()) != AgentRuntime::Url
}

/// A card's valid display `name`, if any. Self-asserted and never verified.
fn card_display_name(card: &Value) -> Option<String> {
    let raw = card
        .get("name")
        .and_then(Value::as_str)?;
    DisplayName::parse(raw)
        .map(|name| name.as_str().to_string())
        .ok()
}

/// The cached name of the card the gateway serves through an `a2a-proxy://` or `fabric://`
/// surface; never waits. A stale or missing entry starts one background build of the card.
/// When the card can't be built, the last name read for the same configuration is kept.
fn served_card_name(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Option<String> {
    if !names_from_served_card(surface) {
        return None;
    }
    let digest = crate::proxy::card_preview::surface_digest(surface);
    let names = served_card_names();
    let (cached, fresh) = match names.get(&surface.surface_id) {
        Some((entry, fresh)) if entry.digest == digest => (entry.name, fresh),
        _ => (None, false),
    };
    if !fresh {
        let state = state.clone();
        let surface_id = surface.surface_id.clone();
        let last = cached.clone();
        names.spawn_refresh(&surface.surface_id, move || async move {
            let card = match state
                .channel_manager
                .card_preview_state(&surface_id)
                .await
            {
                Some(proxy_state) => crate::proxy::card_preview::served_card(&proxy_state).await,
                None => None,
            };
            let name = match card {
                Some(card) => card_display_name(&card),
                None => last,
            };
            ServedCardName { digest, name }
        });
    }
    cached
}

/// Records the name of a card served through `surface` that the caller just read.
fn remember_served_card_name(
    surface: &AgentSurface,
    card: &Value,
) {
    if names_from_served_card(surface) {
        served_card_names().store(
            &surface.surface_id,
            ServedCardName {
                digest: crate::proxy::card_preview::surface_digest(surface),
                name: card_display_name(card),
            },
        );
    }
}

/// A surface's Agent Card name: the target's card for a URL target, the served card for an
/// A2A proxy or remote gateway target.
fn surface_card_name(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Option<String> {
    cached_card_name(surface).or_else(|| served_card_name(state, surface))
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
    let card_name = |surface: &AgentSurface| surface_card_name(&state, surface);

    let mut agents = Vec::with_capacity(groups.len());
    for group in &groups {
        let mut agent = agent_record(group, &data, recorder.as_deref(), &card_name, surface_ref).await;
        agent.target_name = target_name(&state, &group.endpoint, tenant_context(&context)).await;
        agent
            .trust_registry
            .registries
            .clear();
        agents.push(agent);
    }
    sort_agents(&mut agents);

    debug!(count = agents.len(), "Listed agents");
    Ok(Json(AgentListResponse { agents, window_minutes }))
}

/// The A2A proxy id or remote gateway id a normalised endpoint names.
fn target_record(endpoint: &str) -> Option<(AgentRuntime, &str)> {
    let runtime = AgentRuntime::from_endpoint(endpoint);
    let id = match runtime {
        AgentRuntime::A2aProxy => endpoint.strip_prefix("a2a-proxy://")?,
        AgentRuntime::Gateway => endpoint
            .strip_prefix("fabric://")?
            .split('/')
            .next()?,
        AgentRuntime::Url => return None,
    };
    (!id.is_empty()).then_some((runtime, id))
}

/// A record's name for the caller: none for another tenant's record or a blank name.
fn visible_name(
    tenant_id: Option<&str>,
    name: String,
    context: Option<&PatTenantContext>,
) -> Option<String> {
    (can_access(tenant_id, context) && !name.trim().is_empty()).then_some(name)
}

/// The name of the A2A proxy or remote gateway `endpoint` names. Store errors are logged
/// and give no name.
async fn target_name(
    state: &IdentityApiState,
    endpoint: &str,
    context: Option<&PatTenantContext>,
) -> Option<String> {
    use crate::a2a_proxies::A2aProxyStore;
    use crate::gateways::GatewayStore;

    let (runtime, id) = target_record(endpoint)?;
    let (tenant_id, name) = match runtime {
        AgentRuntime::A2aProxy => {
            let proxy = state
                .a2a_proxy_store
                .as_ref()?
                .get(id)
                .await
                .inspect_err(|error| warn!(error = %error, "Agents API could not read the A2A proxy"))
                .ok()??;
            (proxy.tenant_id, proxy.name)
        }
        AgentRuntime::Gateway => {
            let gateway = state
                .gateway_store
                .as_ref()?
                .get(id)
                .await
                .inspect_err(|error| warn!(error = %error, "Agents API could not read the remote gateway"))
                .ok()??;
            (gateway.tenant_id, gateway.name)
        }
        AgentRuntime::Url => return None,
    };
    visible_name(tenant_id.as_deref(), name, context)
}

/// Fills each outcome's Trust Registry name the caller may see. Store errors are logged and
/// give no name.
async fn with_registry_names(
    state: &IdentityApiState,
    outcomes: &mut [AgentRegistryOutcome],
    context: Option<&PatTenantContext>,
) {
    use crate::trust_registries::TrustRegistryStore;

    let Some(store) = state
        .trust_registry_store
        .as_ref()
    else {
        return;
    };
    let mut names: HashMap<String, Option<String>> = HashMap::new();
    for outcome in outcomes {
        if !names.contains_key(&outcome.trust_registry_id) {
            let name = store
                .get(&outcome.trust_registry_id)
                .await
                .inspect_err(|error| warn!(error = %error, "Agents API could not read the Trust Registry"))
                .ok()
                .flatten()
                .and_then(|registry| visible_name(registry.tenant_id.as_deref(), registry.name, context));
            names.insert(
                outcome
                    .trust_registry_id
                    .clone(),
                name,
            );
        }
        outcome.trust_registry_name = names[&outcome.trust_registry_id].clone();
    }
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
    let card_name = |surface: &AgentSurface| surface_card_name(&state, surface);
    let mut agent = agent_record(&group, &data, recorder_store().as_deref(), &card_name, surface_summary).await;
    agent.target_name = target_name(&state, &group.endpoint, tenant_context(&context)).await;
    with_registry_names(
        &state,
        &mut agent
            .trust_registry
            .registries,
        tenant_context(&context),
    )
    .await;
    with_public_urls(&mut agent.surfaces, &group, &state.network_config);

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

/// The surfaces the card may be read through: the agent's A2A and AP2 surfaces the caller
/// may change. A tenant token gets `operator_only` when all of them are appliance-wide, and
/// any caller `no_agent_card` when no surface speaks A2A or AP2.
fn card_surfaces<'a>(
    group: &AgentGroup<'a>,
    context: Option<&PatTenantContext>,
) -> Result<Vec<&'a AgentSurface>, AgentCardUnavailable> {
    let mut a2a = group
        .surfaces
        .iter()
        .copied()
        .filter(|surface| surface.uses_a2a_settings())
        .peekable();
    if a2a.peek().is_none() {
        return Err(AgentCardUnavailable::NoAgentCard);
    }
    let own: Vec<_> = a2a
        .filter(|surface| can_mutate(surface.tenant_id.as_deref(), context))
        .collect();
    if own.is_empty() {
        return Err(AgentCardUnavailable::OperatorOnly);
    }
    Ok(own)
}

/// The response for the card the gateway served through `surface`: only its Agent Card
/// fields, with how the gateway obtains it and the card it started from. `502` when there
/// is no card, or it is too large to show or not an Agent Card.
fn served_card_response(
    agent_id: &str,
    surface: &AgentSurface,
    served: Option<Value>,
    upstream: Option<Value>,
) -> Result<AgentCardResponse, AgentApiError> {
    let source = AgentCardSource::from(AgentRuntime::from_endpoint(&surface.target.endpoint));
    match served.and_then(agent_card_fields) {
        Some(card) => {
            remember_served_card_name(surface, &card);
            Ok(AgentCardResponse::available(card, source, &surface.surface_id, upstream.and_then(agent_card_fields)))
        }
        None => {
            warn!(agent_id = %agent_id, surface_id = %surface.surface_id, "Agent Card preview returned no Agent Card");
            Err(AgentApiError::BadGateway)
        }
    }
}

/// The card the preview's own fetch obtained and the gateway serves. `None` when that fetch
/// failed or the gateway refuses the card, although the preview still shows the last good one.
fn currently_served(preview: AgentCardPreview) -> Option<Value> {
    match preview
        .fetch
        .as_ref()
        .map(|fetch| fetch.status)
    {
        Some(CardFetchStatus::Ok | CardFetchStatus::ServedWithoutIdentity) => preview.after,
        Some(CardFetchStatus::Failed | CardFetchStatus::NotServed) | None => None,
    }
}

/// The surfaces to read the card through: `requested` alone, or every one of `surfaces` in
/// order when none is requested. `404` for a requested surface that is not one of them.
fn chosen_card_surfaces<'a>(
    surfaces: &[&'a AgentSurface],
    requested: Option<&str>,
) -> Result<Vec<&'a AgentSurface>, AgentApiError> {
    match requested {
        None => Ok(surfaces.to_vec()),
        Some(id) => surfaces
            .iter()
            .find(|surface| surface.surface_id == id)
            .map(|surface| vec![*surface])
            .ok_or(AgentApiError::NotFound),
    }
}

/// The card the gateway serves for the agent, read through the agent card preview of the
/// requested surface, or else the first of its [`card_surfaces`] that runs here, so a direct
/// URL, A2A proxy and Fabric target each give the card callers get. `404` for a requested
/// surface that isn't running here. Fetches are limited and audited as previews.
async fn agent_card_response(
    state: &IdentityApiState,
    group: &AgentGroup<'_>,
    context: Option<&PatTenantContext>,
    user_id: &str,
    requested: Option<&str>,
) -> Result<AgentCardResponse, AgentApiError> {
    let surfaces = match card_surfaces(group, context) {
        Ok(surfaces) => surfaces,
        Err(reason) => return Ok(AgentCardResponse::unavailable(reason)),
    };
    let card_surface_ids: Vec<String> = surfaces
        .iter()
        .map(|surface| surface.surface_id.clone())
        .collect();
    for surface in chosen_card_surfaces(&surfaces, requested)? {
        let preview = surface_card_preview(state, surface, context, user_id, PreviewRequest::Read)
            .await
            .map_err(|RateLimited { retry_after_secs }| AgentApiError::RateLimited(retry_after_secs))?;
        if preview.supported {
            let upstream = preview.before.clone();
            let mut response = served_card_response(&group.id, surface, currently_served(preview), upstream)?;
            response.card_surface_ids = card_surface_ids;
            return Ok(response);
        }
    }
    if requested.is_some() {
        return Err(AgentApiError::NotFound);
    }
    let mut response = AgentCardResponse::unavailable(AgentCardUnavailable::NotRunning);
    response.card_surface_ids = card_surface_ids;
    Ok(response)
}

/// The Agent Card the gateway serves for the managed agent, or why it isn't available.
/// `502` when the gateway has no card to show, with no upstream detail, `404` for a
/// `surface_id` the card can't be read through or that isn't running, and `429` past the
/// agent card preview's fetch limit.
pub async fn get_agent_card(
    Path(id): Path<String>,
    Query(query): Query<AgentCardQuery>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
) -> Result<Json<AgentCardResponse>, AgentApiError> {
    let live_surfaces = all_surfaces(&state).await?;
    let group = listed_group(&live_surfaces, &id, tenant_context(&context), resource_scope(&scope))?;
    agent_card_response(&state, &group, tenant_context(&context), &user_id, query.surface_id.as_deref())
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
            card_name: &CardName<'_>,
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
    fn test_normalise_endpoint_redacts_an_endpoint_whose_scheme_is_not_a_scheme() {
        for raw in ["user:pw@host://x", "us er://host", "1ab://host", "://host", "a/b://host"] {
            let normalised = normalise_endpoint(raw);
            assert_eq!(normalised, "redacted.invalid", "{raw}");
            assert!(is_redacted_endpoint(&normalised), "{raw}");
        }
        for (raw, expected) in [("a2a-proxy://p1", "a2a-proxy://p1"), ("x.y+z-1://Host/p", "x.y+z-1://Host/p")] {
            assert_eq!(normalise_endpoint(raw), expected, "{raw}");
        }
    }

    #[tokio::test]
    async fn test_each_surface_with_a_scheme_less_redacted_endpoint_is_an_agent_of_its_own() {
        let agents = Fixture::new()
            .agents(&[targeting("s-oxygen", "user:pw@host://x"), targeting("s-helium", "key@host/a2a")], None, &no_card)
            .await;
        assert_eq!(agents.len(), 2);
        assert_ne!(agents[0].id, agents[1].id);
        let text = serde_json::to_string(&agents).expect("serialize");
        for forbidden in ["user", "pw@", "key@"] {
            assert!(!text.contains(forbidden), "response contains {forbidden}: {text}");
        }
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
    async fn test_display_name_skips_canvas_names_that_only_name_a_surface() {
        let mut generated = with_canvas_name(surface("s1"), "PROXY SURFACE 1");
        generated.name = "orders".to_string();
        let mut own = with_canvas_name(surface("s2"), "Payments-Gateway");
        own.name = "payments_gateway".to_string();
        let agent = Fixture::new()
            .only(&[generated.clone(), own], None)
            .await;
        assert_eq!(agent.name, None, "a generated or own surface name is not the agent's");

        let named = with_canvas_name(surface("s3"), "Billing Bot");
        let agent = Fixture::new()
            .only(&[generated, named], None)
            .await;
        assert_eq!(agent.name.as_deref(), Some("Billing Bot"), "the next canvas name is used");
    }

    #[test]
    fn test_surface_placeholder_names() {
        let mut orders = surface("s1");
        orders.name = "orders".to_string();
        let surfaces = [&orders];
        for name in ["proxy_surface_1", "A2A Surface 12", "a2a-surface-3", "Orders", " orders "] {
            assert!(is_surface_placeholder(name, &surfaces), "{name}");
        }
        for name in ["Orders Bot", "surface 1", "proxy surface one", "my proxy surface 1"] {
            assert!(!is_surface_placeholder(name, &surfaces), "{name}");
        }
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

    /// A managed identity last used on `surface_id` `minutes_ago`.
    fn managed_used(
        did: &str,
        surface_id: &str,
        minutes_ago: i64,
    ) -> AgentIdentityRecord {
        let mut record = managed(did, surface_id);
        let at = Utc::now() - Duration::minutes(minutes_ago);
        record.last_used_at = Some(at);
        record.channel_usage[0].last_used_at = at;
        record
    }

    fn jwt_claim(record: AgentIdentityRecord) -> AgentIdentityRecord {
        let mut record = record;
        record
            .identity_fields
            .insert("credential_type".to_string(), serde_json::json!(JWT_CLAIM_CREDENTIAL_TYPE));
        record
    }

    #[tokio::test]
    async fn test_only_the_most_recently_used_managed_did_of_a_surface_is_an_identity() {
        let mut fixture = Fixture::new();
        fixture.records = vec![
            managed_used("did:old", "s-oxygen", 30),
            managed_used("did:current", "s-oxygen", 5),
            managed_used("did:older", "s-oxygen", 60),
        ];
        let agent = fixture
            .only(&[surface("s-oxygen")], None)
            .await;
        assert_eq!(dids(&agent), vec!["did:current"], "earlier DIDs of the surface are its version history");
    }

    #[tokio::test]
    async fn test_every_jwt_claim_did_of_a_surface_is_an_identity() {
        let mut fixture = Fixture::new();
        fixture.records = vec![
            jwt_claim(managed_used("did:claim-a", "s-oxygen", 30)),
            jwt_claim(managed_used("did:claim-b", "s-oxygen", 5)),
            managed_used("did:old", "s-oxygen", 20),
            managed_used("did:current", "s-oxygen", 10),
        ];
        let agent = fixture
            .only(&[surface("s-oxygen")], None)
            .await;
        assert_eq!(dids(&agent), vec!["did:claim-a", "did:claim-b", "did:current"]);
    }

    #[tokio::test]
    async fn test_identities_are_the_union_across_surfaces_once_per_did() {
        let mut fixture = Fixture::new();
        let did_b = managed_used("did:b", "s-oxygen", 5);
        let created_b = did_b.created_at;
        let mut caller = test_surface_identity_record("did:caller", "s-oxygen");
        caller.origin = Some(IdentityOrigin::ExternalCaller);
        fixture.records = vec![
            managed_used("did:a", "s-oxygen", 30),
            did_b,
            managed_used("did:b", "s-helium", 5),
            managed_used("did:c", "s-helium", 30),
            managed_used("did:d", "s-neon", 5),
            caller,
        ];
        let mut helium = surface("s-helium");
        helium.agent_did = Some("did:c".to_string());
        let agent = fixture
            .only(&[surface("s-oxygen"), helium, surface("s-neon")], None)
            .await;
        assert_eq!(dids(&agent), vec!["did:b", "did:c", "did:d"]);
        let did_c = &agent.identities[1];
        assert_eq!(did_c.source, IdentitySource::Surface, "a surface's own DID is reported as surface");
        assert_eq!(agent.identities[0].source, IdentitySource::Managed);
        assert!(agent.identities[0].created_at <= Some(created_b));
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
        assert_eq!(agent.trust_registry, AgentTrustRegistry::default());
    }

    #[tokio::test]
    async fn test_trust_registry_lists_the_best_outcome_per_registry_and_identity() {
        let store = TrustRecorderStatusStore::in_memory();
        record_outcome(&store, "s-oxygen", "did:a", EntryStatus::from_counts("tr-1", 0, 0, 1, None)).await;
        record_outcome(&store, "s-helium", "did:a", EntryStatus::from_counts("tr-1", 1, 0, 0, None)).await;
        record_outcome(&store, "s-helium", "did:b", EntryStatus::skipped("tr-2", RecorderReason::NoSurfaceIssuer))
            .await;
        let mut fixture = recorder_fixture();
        fixture.records =
            vec![managed("did:a", "s-oxygen"), managed("did:a", "s-helium"), managed("did:b", "s-helium")];
        let agent = fixture
            .only(&[surface("s-oxygen"), surface("s-helium")], Some(&store))
            .await;
        let outcomes: Vec<(&str, &str, RecorderState)> = agent
            .trust_registry
            .registries
            .iter()
            .map(|outcome| {
                (
                    outcome
                        .trust_registry_id
                        .as_str(),
                    outcome.did.as_str(),
                    outcome.state,
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            vec![("tr-1", "did:a", RecorderState::Recorded), ("tr-2", "did:b", RecorderState::Skipped)]
        );
        assert!(agent.trust_registry.recorded);
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
                { "surface_id": "s1", "name": "s1-name", "protocol": "a2a", "route": "/s1", "public_url": null },
                { "surface_id": "s2", "name": "s2-name", "protocol": "ap2", "route": "/s2", "public_url": null },
            ])
        );
        assert_eq!(json["traffic"]["p95_latency_ms"], serde_json::Value::Null);
        assert_eq!(json["last_activity_at"], serde_json::Value::Null);
        assert_eq!(json["target_name"], serde_json::Value::Null);
    }

    #[test]
    fn test_target_record_names_the_proxy_or_gateway_id() {
        for (endpoint, expected) in [
            ("a2a-proxy://proxy-1", Some((AgentRuntime::A2aProxy, "proxy-1"))),
            ("fabric://gateway-1/channel-1", Some((AgentRuntime::Gateway, "gateway-1"))),
            ("fabric://gateway-1", Some((AgentRuntime::Gateway, "gateway-1"))),
            ("a2a-proxy://", None),
            ("fabric:///channel-1", None),
            ("https://agent.example/a2a", None),
        ] {
            assert_eq!(target_record(endpoint), expected, "{endpoint}");
        }
    }

    #[test]
    fn test_visible_name_hides_other_tenants_and_blank_names() {
        let name = || "Orders proxy".to_string();
        assert_eq!(visible_name(None, name(), None), Some(name()), "operator sees appliance-wide");
        assert_eq!(visible_name(Some("t2"), name(), None), Some(name()), "operator sees any tenant");
        assert_eq!(visible_name(None, name(), Some(&tenant("t1"))), Some(name()), "tenant sees appliance-wide");
        assert_eq!(visible_name(Some("t1"), name(), Some(&tenant("t1"))), Some(name()), "tenant sees its own");
        assert_eq!(visible_name(Some("t2"), name(), Some(&tenant("t1"))), None, "another tenant's name is hidden");
        assert_eq!(visible_name(None, "  ".to_string(), None), None, "a blank name is no name");
    }

    #[test]
    fn test_names_come_from_the_served_card_for_proxy_and_fabric_targets_only() {
        for (protocol, endpoint, expected) in [
            (SurfaceProtocol::A2a, "a2a-proxy://proxy-1", true),
            (SurfaceProtocol::Ap2, "fabric://gateway-1/channel-1", true),
            (SurfaceProtocol::A2a, "https://agent.example/a2a", false),
            (SurfaceProtocol::DIDComm, "fabric://gateway-1/channel-1", false),
            (SurfaceProtocol::Mcp, "a2a-proxy://proxy-1", false),
        ] {
            let mut surface = targeting("s1", endpoint);
            surface.access_point.protocol = protocol.clone();
            assert_eq!(names_from_served_card(&surface), expected, "{protocol:?} {endpoint}");
        }
    }

    #[test]
    fn test_card_display_name_takes_only_a_valid_name() {
        assert_eq!(card_display_name(&serde_json::json!({ "name": "Orders agent" })), Some("Orders agent".to_string()));
        assert_eq!(card_display_name(&serde_json::json!({ "name": 7 })), None);
        assert_eq!(card_display_name(&serde_json::json!({})), None);
        assert_eq!(card_display_name(&serde_json::json!({ "name": "" })), None);
    }

    #[test]
    fn test_served_card_name_changes_only_when_the_name_does() {
        let entry = |digest: u8, name: Option<&str>| ServedCardName {
            digest: [digest; 32],
            name: name.map(str::to_string),
        };
        assert!(served_card_name_changed(None, &entry(1, Some("A"))));
        assert!(!served_card_name_changed(None, &entry(1, None)));
        assert!(!served_card_name_changed(Some(&entry(1, Some("A"))), &entry(2, Some("A"))));
        assert!(served_card_name_changed(Some(&entry(1, Some("A"))), &entry(1, Some("B"))));
        assert!(served_card_name_changed(Some(&entry(1, Some("A"))), &entry(1, None)));
    }

    #[test]
    fn test_a_read_card_names_a_proxy_or_fabric_agent_for_its_configuration() {
        let card = serde_json::json!({ "name": "Orders agent" });
        let proxy = targeting("names-proxy-surface", "a2a-proxy://proxy-1");
        remember_served_card_name(&proxy, &card);
        let (entry, fresh) = served_card_names()
            .get("names-proxy-surface")
            .expect("remembered");
        assert!(fresh);
        assert_eq!(entry.name.as_deref(), Some("Orders agent"));
        assert_eq!(entry.digest, crate::proxy::card_preview::surface_digest(&proxy));

        let url = targeting("names-url-surface", "https://agent.example/a2a");
        remember_served_card_name(&url, &card);
        assert!(
            served_card_names()
                .get("names-url-surface")
                .is_none(),
            "a URL target's name is fetched from it"
        );
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

    fn in_tenant(
        mut surface: AgentSurface,
        tenant_id: &str,
    ) -> AgentSurface {
        surface.tenant_id = Some(tenant_id.to_string());
        surface
    }

    fn card_surface_ids(
        surfaces: &[AgentSurface],
        context: Option<&PatTenantContext>,
    ) -> Result<Vec<String>, AgentCardUnavailable> {
        let groups = group_surfaces(surfaces);
        assert_eq!(groups.len(), 1, "one managed agent");
        card_surfaces(&groups[0], context).map(|surfaces| {
            surfaces
                .iter()
                .map(|surface| surface.surface_id.clone())
                .collect()
        })
    }

    #[test]
    fn test_card_surfaces_need_an_a2a_or_ap2_surface_whatever_the_runtime() {
        for endpoint in ["http://localhost:9002", "a2a-proxy://proxy-1", "fabric://gateway-1/channel-1"] {
            let mut didcomm = targeting("s1", endpoint);
            didcomm.access_point.protocol = SurfaceProtocol::DIDComm;
            assert_eq!(card_surface_ids(&[didcomm], None), Err(AgentCardUnavailable::NoAgentCard), "{endpoint}");

            for protocol in [SurfaceProtocol::A2a, SurfaceProtocol::Ap2] {
                let mut surface = targeting("s1", endpoint);
                surface.access_point.protocol = protocol;
                assert_eq!(card_surface_ids(&[surface], None), Ok(vec!["s1".to_string()]), "{endpoint}");
            }
        }
    }

    #[test]
    fn test_card_surfaces_skip_surfaces_without_an_agent_card() {
        let mut didcomm = targeting("a-first", "https://agent.example/a2a");
        didcomm.access_point.protocol = SurfaceProtocol::DIDComm;
        let a2a = targeting("b-second", "https://agent.example/a2a");
        assert_eq!(card_surface_ids(&[didcomm, a2a], None), Ok(vec!["b-second".to_string()]));
    }

    #[test]
    fn test_card_surfaces_of_a_tenant_are_its_own_surfaces_only() {
        let live = [
            targeting("a-appliance", "https://agent.example/a2a"),
            in_tenant(targeting("b-other", "https://agent.example/a2a"), "t2"),
            in_tenant(targeting("c-own", "https://agent.example/a2a"), "t1"),
        ];
        assert_eq!(card_surface_ids(&live, Some(&tenant("t1"))), Ok(vec!["c-own".to_string()]));
        assert_eq!(
            card_surface_ids(&live, None),
            Ok(vec!["a-appliance".to_string(), "b-other".to_string(), "c-own".to_string()]),
            "an operator reads through any surface"
        );
    }

    #[test]
    fn test_card_surfaces_of_a_tenant_on_appliance_wide_surfaces_are_operator_only() {
        let live = [targeting("s1", "a2a-proxy://proxy-1")];
        assert_eq!(card_surface_ids(&live, Some(&tenant("t1"))), Err(AgentCardUnavailable::OperatorOnly));
    }

    #[test]
    fn test_card_source_follows_the_target_runtime() {
        for (endpoint, expected) in [
            ("https://agent.example/a2a", "fetched"),
            ("http://localhost:9002", "fetched"),
            ("a2a-proxy://proxy-1", "generated"),
            ("fabric://gateway-1/channel-1", "remote_gateway"),
        ] {
            let source = AgentCardSource::from(AgentRuntime::from_endpoint(endpoint));
            assert_eq!(serde_json::to_value(source).expect("serialize"), serde_json::json!(expected), "{endpoint}");
        }
    }

    #[test]
    fn test_served_card_response_names_the_source() {
        for (endpoint, source) in [
            ("https://agent.example/a2a", "fetched"),
            ("a2a-proxy://proxy-1", "generated"),
            ("fabric://gateway-1/channel-1", "remote_gateway"),
        ] {
            let card = serde_json::json!({ "name": "TimeAsker", "skills": [] });
            let response =
                served_card_response("a1", &targeting("s1", endpoint), Some(card.clone()), None).expect("response");
            assert_eq!(
                serde_json::to_value(&response).expect("serialize"),
                serde_json::json!({ "available": true, "card": card, "source": source, "surface_id": "s1" }),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn test_served_card_response_passes_on_the_upstream_card_fields_only() {
        let served = serde_json::json!({ "name": "TimeAsker", "url": "https://gateway.example/time" });
        let upstream = serde_json::json!({
            "name": "TimeAsker",
            "url": "http://10.0.0.5:9002",
            "internal_config": { "db_password": "secret" },
        });
        let response = served_card_response("a1", &surface("s1"), Some(served), Some(upstream)).expect("response");
        assert_eq!(
            response.upstream_card,
            Some(serde_json::json!({ "name": "TimeAsker", "url": "http://10.0.0.5:9002" }))
        );

        let not_a_card = served_card_response(
            "a1",
            &surface("s1"),
            Some(serde_json::json!({ "name": "TimeAsker" })),
            Some(serde_json::json!({ "status": "ok" })),
        )
        .expect("response");
        assert_eq!(not_a_card.upstream_card, None, "an upstream body that is not an Agent Card is dropped");
    }

    #[test]
    fn test_chosen_card_surfaces_are_the_requested_one_or_all() {
        let live = [targeting("s1", "https://agent.example/a2a"), targeting("s2", "https://agent.example/a2a")];
        let surfaces: Vec<&AgentSurface> = live.iter().collect();
        let ids = |chosen: Vec<&AgentSurface>| -> Vec<String> {
            chosen
                .iter()
                .map(|surface| surface.surface_id.clone())
                .collect()
        };

        assert_eq!(ids(chosen_card_surfaces(&surfaces, None).expect("all")), ["s1", "s2"]);
        assert_eq!(ids(chosen_card_surfaces(&surfaces, Some("s2")).expect("one")), ["s2"]);
        assert!(matches!(chosen_card_surfaces(&surfaces, Some("s3")), Err(AgentApiError::NotFound)));
    }

    #[test]
    fn test_unavailable_card_response_names_only_the_reason() {
        for (reason, expected) in [
            (AgentCardUnavailable::NoAgentCard, "no_agent_card"),
            (AgentCardUnavailable::NotRunning, "not_running"),
            (AgentCardUnavailable::OperatorOnly, "operator_only"),
        ] {
            assert_eq!(
                serde_json::to_value(AgentCardResponse::unavailable(reason)).expect("serialize"),
                serde_json::json!({ "available": false, "reason": expected })
            );
        }
    }

    #[test]
    fn test_served_card_response_passes_on_agent_card_fields_only() {
        let card = serde_json::json!({
            "name": "TimeAsker",
            "skills": [{ "id": "time" }],
            "capabilities": { "extensions": [] },
            "internal_config": { "db_password": "secret" },
        });
        let response = served_card_response("a1", &surface("s1"), Some(card), None).expect("response");
        assert_eq!(
            response.card,
            Some(serde_json::json!({
                "name": "TimeAsker",
                "skills": [{ "id": "time" }],
                "capabilities": { "extensions": [] },
            }))
        );
    }

    #[test]
    fn test_served_card_response_refuses_json_that_is_not_an_agent_card() {
        for body in [
            serde_json::json!({ "status": "ok", "version": "1.2.3" }),
            serde_json::json!({ "name": 7 }),
            serde_json::json!([{ "name": "TimeAsker" }]),
            serde_json::json!("TimeAsker"),
        ] {
            let error =
                served_card_response("a1", &surface("s1"), Some(body.clone()), None).expect_err("not an Agent Card");
            assert_eq!(error.into_response().status(), StatusCode::BAD_GATEWAY, "{body}");
        }
    }

    fn preview_after_fetch(status: CardFetchStatus) -> AgentCardPreview {
        use crate::proxy::card_preview::{CardFetchReport, UnsupportedReason};
        let mut preview = AgentCardPreview::unsupported("s1", UnsupportedReason::NotRunning);
        preview.supported = true;
        preview.unsupported_reason = None;
        preview.fetch = Some(CardFetchReport {
            status,
            cause: None,
            http_status: None,
            duration_ms: 0,
            identity_error: None,
            identity_slot: None,
        });
        preview.after = Some(serde_json::json!({ "name": "TimeAsker", "skills": [] }));
        preview
    }

    #[test]
    fn test_a_served_card_is_the_card_of_a_fetch_the_gateway_serves() {
        for status in [CardFetchStatus::Ok, CardFetchStatus::ServedWithoutIdentity] {
            let card = currently_served(preview_after_fetch(status));
            assert_eq!(card, Some(serde_json::json!({ "name": "TimeAsker", "skills": [] })), "{status:?}");
        }
    }

    #[tokio::test]
    async fn test_a_failed_fetch_after_a_good_one_is_generic_502_not_the_last_good_card() {
        for status in [CardFetchStatus::Failed, CardFetchStatus::NotServed] {
            let card = currently_served(preview_after_fetch(status));
            assert_eq!(card, None, "{status:?}");
            let error = served_card_response("a1", &surface("s1"), card, None).expect_err("no current card");
            assert_eq!(error.into_response().status(), StatusCode::BAD_GATEWAY, "{status:?}");
        }
        let mut no_fetch = preview_after_fetch(CardFetchStatus::Ok);
        no_fetch.fetch = None;
        assert_eq!(currently_served(no_fetch), None);
    }

    #[tokio::test]
    async fn test_served_card_response_without_a_card_is_generic_502() {
        let error = served_card_response("a1", &surface("s1"), None, None).expect_err("no card");
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
    async fn test_rate_limited_response_tells_when_to_retry() {
        let response = AgentApiError::RateLimited(6).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("6")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({ "error": CARD_FETCH_LIMITED, "code": "rate_limited" })
        );
    }
}
