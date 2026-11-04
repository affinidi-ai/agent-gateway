//! The public agent card: the agent's own card fetched from the Target (or the
//! card an A2A proxy generates), its identity resolution, the endpoint rewrite and
//! the gateway's identity credential. The card route serves it; a preview builds
//! the same card without recording what serving it records.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde_json::Value as JsonValue;
use tracing::{debug, error, info, warn};

use super::{CallerAssertion, TargetAuthContext, TargetAuthError};
use crate::a2a::create_error_response;
use crate::observability::loggable;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::state::ProxyState;

/// Whether the card is served to a caller or built for an operator. A preview
/// records no gateway fault, no rejected request, no Trust Recorder write and no
/// connection metric, and always fetches over a client pinned to the vetted
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardMode {
    Serve,
    Preview,
}

impl CardMode {
    fn serves(self) -> bool {
        self == Self::Serve
    }
}

/// The public card as built.
#[derive(Debug)]
pub(crate) struct BuiltCard {
    /// The agent's own card as fetched, before any change. `None` for a generated card.
    pub upstream: Option<JsonValue>,
    /// The card the route serves.
    pub served: JsonValue,
    /// Whether an A2A proxy generated the card instead of fetching it.
    #[cfg_attr(not(test), expect(dead_code))]
    pub generated: bool,
    /// Whether the fetch carried the Target credential.
    pub credential_sent: bool,
}

/// Why the card was not built, and exactly what the card route answers.
#[derive(Debug)]
pub(crate) struct CardFailure {
    pub fault: FetchFault,
    pub response: Response,
    /// The agent's own card when it was fetched but the gateway will not serve it.
    pub upstream: Option<JsonValue>,
    /// Whether the fetch carried the Target credential.
    pub credential_sent: bool,
}

impl CardFailure {
    fn new(
        fault: FetchFault,
        response: Response,
    ) -> Self {
        Self {
            fault,
            response,
            upstream: None,
            credential_sent: false,
        }
    }
}

/// What went wrong while building the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchFault {
    ProxyUnavailable,
    CredentialRejected(TargetAuthError),
    BlockedByEgress,
    Unreachable,
    TimedOut,
    Status { status: u16, credential_sent: bool },
    TooLarge,
    InvalidCard,
    IdentityFailed,
    RewriteFailed,
}

impl FetchFault {
    fn of_send(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::TimedOut
        } else {
            Self::Unreachable
        }
    }

    fn of_body(error: &crate::proxy::upstream_body::UpstreamBodyError) -> Self {
        use crate::proxy::upstream_body::UpstreamBodyError;
        match error {
            UpstreamBodyError::TooLarge(_) => Self::TooLarge,
            UpstreamBodyError::TimedOut => Self::TimedOut,
            UpstreamBodyError::Read(error) => Self::of_send(error),
        }
    }
}

/// The agent card URL fetched from an `http(s)` Target: the
/// `override_agent_card_location` path on the Target's origin, or the well-known
/// path under the Target endpoint.
pub(crate) fn card_target_url(surface: &crate::config::agent_surface::AgentSurface) -> String {
    let endpoint = &surface.target.endpoint;
    match surface.agent_card_location_path() {
        Some(custom_path) => {
            let origin = if let Some(scheme_end) = endpoint.find("://") {
                let after_scheme = &endpoint[scheme_end + 3..];
                let authority_end = after_scheme
                    .find('/')
                    .unwrap_or(after_scheme.len());
                &endpoint[..scheme_end + 3 + authority_end]
            } else {
                endpoint.as_str()
            };
            if custom_path.starts_with('/') {
                format!("{}{}", origin, custom_path)
            } else {
                format!("{}/{}", origin, custom_path)
            }
        }
        None => crate::proxy::protocol_router::join_endpoint_path(endpoint, "/.well-known/agent-card.json"),
    }
}

/// Build the public agent card of the state's surface: fetch or generate it,
/// resolve its identity, rewrite its endpoints to the Access Point and add the
/// gateway's identity credential and did:webvh identity. A served card also
/// writes the Trust Recorder and records the connection.
pub(crate) async fn build_public_card(
    state: &ProxyState,
    headers: &HeaderMap,
    source_addr: &str,
    mode: CardMode,
) -> Result<BuiltCard, CardFailure> {
    let channel_name = state.surface.name.as_str();
    let prepared = super::prepare_a2a_proxy_agent_card(state, channel_name)
        .await
        .map_err(|response| CardFailure::new(FetchFault::ProxyUnavailable, response))?;
    let generated = prepared.is_some();

    let (agent_card, prepared_identity, upstream, credential_sent) = match prepared {
        Some(prepared) => (prepared.card, prepared.identity, None, false),
        None => {
            let fetch = TargetCardFetch {
                state,
                source_addr,
                mode,
                credential_sent: AtomicBool::new(false),
            };
            let fetched = fetch
                .fetch(headers, &card_target_url(&state.surface))
                .await;
            let credential_sent = fetch
                .credential_sent
                .load(Ordering::Relaxed);
            let card = fetched.map_err(|failure| CardFailure { credential_sent, ..failure })?;
            (card.clone(), None, Some(card), credential_sent)
        }
    };

    let (agent_card, resolved_identity) = finish_card(state, agent_card, prepared_identity, generated)
        .await
        .map_err(|failure| CardFailure {
            upstream: upstream.clone(),
            credential_sent,
            ..failure
        })?;

    info!(channel = channel_name, "Successfully fetched and parsed agent card");
    if mode.serves() {
        record_served_effects(state, source_addr, &resolved_identity);
    }
    Ok(BuiltCard {
        upstream,
        served: agent_card,
        generated,
        credential_sent,
    })
}

/// Resolve the identity of the obtained card, rewrite its endpoints to the Access
/// Point and add the gateway's identity credential and did:webvh identity.
async fn finish_card(
    state: &ProxyState,
    mut agent_card: JsonValue,
    prepared_identity: Option<ProtectedAgentIdentity>,
    generated: bool,
) -> Result<(JsonValue, ProtectedAgentIdentity), CardFailure> {
    let card_bytes = serde_json::to_vec(&agent_card).unwrap_or_default();
    let resolved_identity = match prepared_identity {
        Some(identity) => identity,
        None => resolve_card_identity(state, &card_bytes).await?,
    };
    resolve_external_card_identity(state, &card_bytes).await?;

    if !generated {
        agent_card = rewrite_card_urls(state, &agent_card, &resolved_identity).await?;
    }
    inject_identity_credential(state, &mut agent_card, &resolved_identity).await?;
    #[cfg(feature = "didwebvh")]
    inject_agent_dna(state, &mut agent_card).await;
    Ok((agent_card, resolved_identity))
}

async fn resolve_card_identity(
    state: &ProxyState,
    card_bytes: &[u8],
) -> Result<ProtectedAgentIdentity, CardFailure> {
    let channel_name = state.surface.name.as_str();
    let card_identity_selector = state
        .protected_selector
        .as_ref()
        .or(state
            .identity_selector
            .as_ref());
    let card_identity_rules = state
        .protected_rules_engine
        .as_ref()
        .or(state
            .identity_rules_engine
            .as_ref());
    crate::proxy::backend_identity::resolve_protected_agent_identity(
        card_bytes,
        &state.surface,
        card_identity_selector,
        card_identity_rules,
        channel_name,
        crate::proxy::backend_identity::IdentityResponseKind::PublicAgentCard,
        None,
    )
    .await
    .map_err(|e| {
        warn!(
            channel = channel_name,
            error = %e,
            code = %e.code(),
            "Protected agent identity resolution failed for agent card intercept"
        );
        CardFailure::new(
            FetchFault::IdentityFailed,
            crate::a2a::create_identity_error_response(
                e.http_status(),
                e.code(),
                "protected_identity",
                channel_name,
                &e.to_string(),
            ),
        )
    })
}

/// External slot resolution (Surface Builder external identity node). Issues a
/// DID for the external counterparty through the VC issuer.
async fn resolve_external_card_identity(
    state: &ProxyState,
    card_bytes: &[u8],
) -> Result<(), CardFailure> {
    if state
        .external_selector
        .is_none()
    {
        return Ok(());
    }
    let channel_name = state.surface.name.as_str();
    crate::proxy::backend_identity::resolve_external_agent_identity(
        card_bytes,
        &state.surface,
        state
            .external_selector
            .as_ref(),
        state
            .external_rules_engine
            .as_ref(),
        channel_name,
        crate::proxy::backend_identity::IdentityResponseKind::PublicAgentCard,
        None,
    )
    .await
    .map(|_| ())
    .map_err(|e| {
        warn!(
            channel = channel_name,
            error = %e,
            code = %e.code(),
            "External agent identity resolution failed for agent card intercept"
        );
        CardFailure::new(
            FetchFault::IdentityFailed,
            crate::a2a::create_identity_error_response(
                e.http_status(),
                e.code(),
                "external_identity",
                channel_name,
                &e.to_string(),
            ),
        )
    })
}

/// The upstream card with its URLs pointing back to the Access Point.
async fn rewrite_card_urls(
    state: &ProxyState,
    agent_card: &JsonValue,
    resolved_identity: &ProtectedAgentIdentity,
) -> Result<JsonValue, CardFailure> {
    let channel_name = state.surface.name.as_str();
    let card_bytes = serde_json::to_vec(agent_card).unwrap_or_default();
    let rewritten = crate::a2a::rewrite_agent_card_urls(
        &card_bytes,
        &state.surface,
        &state.config,
        &state.network_config,
        resolved_identity,
        crate::a2a::AgentCardKind::Public,
    )
    .await
    .map_err(|e| {
        warn!(channel = channel_name, error = %e, "Failed to rewrite agent card URLs");
        CardFailure::new(
            FetchFault::RewriteFailed,
            create_error_response(StatusCode::BAD_GATEWAY, "Failed to rewrite agent card URLs"),
        )
    })?;
    serde_json::from_slice(rewritten.as_ref()).map_err(|e| {
        warn!(channel = channel_name, error = %e, "Failed to parse rewritten agent card JSON");
        CardFailure::new(
            FetchFault::RewriteFailed,
            create_error_response(StatusCode::BAD_GATEWAY, "Invalid rewritten agent card JSON"),
        )
    })
}

/// Replace `agent-identity/v1` with `agent-identity-credential/v1` (a signed VP).
async fn inject_identity_credential(
    state: &ProxyState,
    agent_card: &mut JsonValue,
    resolved_identity: &ProtectedAgentIdentity,
) -> Result<(), CardFailure> {
    let Some(selector) = state
        .identity_selector
        .as_ref()
    else {
        return Ok(());
    };
    let channel_name = state.surface.name.as_str();
    let vc_issuer = selector.get_vc_issuer();
    crate::a2a::inject_credential_into_agent_card(agent_card, resolved_identity, &vc_issuer, channel_name)
        .await
        .map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to inject identity credential into agent card");
            CardFailure::new(
                FetchFault::IdentityFailed,
                create_error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("Agent card identity credential injection failed: {}", e),
                ),
            )
        })
}

/// Put the Agent DNA and DID of the surface's did:webvh identity on the card, so
/// callers see them without resolving the DID log.
#[cfg(feature = "didwebvh")]
async fn inject_agent_dna(
    state: &ProxyState,
    agent_card: &mut JsonValue,
) {
    let channel_name = state.surface.name.as_str();
    let (Some(did_config), Some(identity_store)) = (
        state
            .surface
            .didwebvh_identity_legacy(),
        state
            .didwebvh_identity_store
            .as_ref(),
    ) else {
        return;
    };
    match identity_store
        .get(&did_config.identity_id)
        .await
    {
        Ok(Some(identity)) => {
            if let Some(obj) = agent_card.as_object_mut() {
                obj.insert("agentDid".to_string(), JsonValue::String(identity.did.clone()));
                if let Some(dna_value) = identity
                    .metadata
                    .get("agentDNA")
                {
                    obj.insert("agentDNA".to_string(), dna_value.clone());
                    info!(
                        channel = channel_name,
                        did = %identity.did,
                        "Injected agentDNA into agent card"
                    );
                }
            }
        }
        Ok(None) => {
            warn!(
                channel = channel_name,
                identity_id = %did_config.identity_id,
                "Configured did:webvh identity not found — skipping DNA injection"
            );
        }
        Err(e) => {
            warn!(
                channel = channel_name,
                identity_id = %did_config.identity_id,
                error = %e,
                "Failed to load did:webvh identity for agent card — skipping DNA injection"
            );
        }
    }
}

/// The Trust Recorder write and the connection metric of a served card. The Trust
/// Recorder populates the trust registry on the first discovery fetch instead of
/// waiting for the first message; it is fire-and-forget and idempotent. Only a UCP
/// surface tags the connection as UCP `discovery`.
fn record_served_effects(
    state: &ProxyState,
    source_addr: &str,
    resolved_identity: &ProtectedAgentIdentity,
) {
    if let ProtectedAgentIdentity::Managed { did, .. } = resolved_identity {
        crate::trust_registry_verification::spawn_trust_recorder(
            &state.surface,
            did,
            state
                .trust_registry_listener_manager
                .clone(),
        );
    }

    let Some(metrics) = state
        .metrics_store
        .as_ref()
        .map(Arc::clone)
    else {
        return;
    };
    let channel_config_id = state
        .surface
        .surface_id
        .clone();
    let source = source_addr.to_string();
    let dest = state
        .surface
        .target
        .endpoint
        .clone();
    let ucp_operation = state
        .surface
        .is_ucp()
        .then(|| "discovery".to_string());
    crate::observability::policy_audit::spawn_in_request(async move {
        metrics
            .record_connection_with_ucp(
                channel_config_id,
                source,
                dest,
                crate::metrics::ConnectionStatus::Success,
                None,
                None,
                crate::metrics::ConnectionDirection::Request,
                uuid::Uuid::new_v4().to_string(),
                ucp_operation,
                None,
                None,
                0,
            )
            .await;
    });
}

/// The gateway's own read of the agent card from the Target.
struct TargetCardFetch<'a> {
    state: &'a ProxyState,
    source_addr: &'a str,
    mode: CardMode,
    credential_sent: AtomicBool,
}

impl TargetCardFetch<'_> {
    /// A failed fetch, recorded as a gateway fault when the card is served.
    fn fail(
        &self,
        fault: FetchFault,
        response: Response,
    ) -> CardFailure {
        if self.mode.serves() {
            record_agent_card_gateway_fault(self.state, self.source_addr);
        }
        CardFailure::new(fault, response)
    }

    fn channel_name(&self) -> &str {
        self.state
            .surface
            .name
            .as_str()
    }

    async fn fetch(
        &self,
        headers: &HeaderMap,
        target_url: &str,
    ) -> Result<JsonValue, CardFailure> {
        debug!(channel = self.channel_name(), target = %loggable::url(target_url), "Fetching agent card from upstream");
        if self
            .state
            .surface
            .target
            .endpoint
            .starts_with("fabric://")
        {
            self.fetch_via_fabric(headers)
                .await
        } else {
            self.fetch_over_http(headers, target_url)
                .await
        }
    }

    async fn fetch_via_fabric(
        &self,
        headers: &HeaderMap,
    ) -> Result<JsonValue, CardFailure> {
        let state = self.state;
        let channel_name = self.channel_name();
        let source_cred_headers = state
            .surface
            .source_credential_headers();
        let mut forwarded_headers = headers
            .iter()
            .filter(|(key, _)| super::should_forward_header(key.as_str(), &source_cred_headers))
            .filter_map(|(key, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (key.as_str().to_string(), value.to_string()))
            })
            .collect::<HashMap<_, _>>();
        crate::proxy::fabric_hops::set_fabric_hops(&mut forwarded_headers, crate::proxy::fabric_hops::FIRST_FABRIC_HOP);
        let trace_id = uuid::Uuid::new_v4().to_string();
        let path = super::agent_card_fabric_forward_path(&state.surface);
        let response = crate::proxy::fabric_forward::forward_via_fabric(
            &state.listener_manager,
            crate::proxy::fabric_forward::FabricForwardRequest {
                fabric_target: &state.surface.target.endpoint,
                method: &Method::GET,
                path: &path,
                headers: forwarded_headers,
                body: bytes::Bytes::new(),
                timeout: std::time::Duration::from_secs(30),
                trace_id: &trace_id,
                log_label: channel_name,
            },
        )
        .await
        .map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to fetch agent card from fabric upstream - bad gateway");
            self.fail(
                FetchFault::Unreachable,
                create_error_response(StatusCode::BAD_GATEWAY, &format!("Failed to fetch from upstream: {}", e)),
            )
        })?;

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        if !status.is_success() {
            error!(channel = channel_name, status = %status, "Fabric upstream returned error for agent card - gateway fault");
            return Err(self.fail(
                FetchFault::Status {
                    status: status.as_u16(),
                    credential_sent: false,
                },
                create_error_response(status, &format!("Upstream error: {status}")),
            ));
        }

        serde_json::from_slice(&response.body).map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to parse fabric agent card JSON");
            CardFailure::new(
                FetchFault::InvalidCard,
                create_error_response(StatusCode::BAD_GATEWAY, "Invalid JSON from upstream"),
            )
        })
    }

    /// The surface's target credential for the gateway's own card fetch, or `None`
    /// when the surface has none. Honours `target.auth.fallback` exactly as the
    /// forwarded path does: `reject` fails the card with 502 rather than asking the
    /// target without the credential it requires.
    async fn target_credential(&self) -> Result<Option<(String, String)>, CardFailure> {
        let state = self.state;
        let channel_name = self.channel_name();
        let Some(target_auth) = state.surface.target_auth() else {
            return Ok(None);
        };
        match super::inject_target_auth_header(
            target_auth,
            &TargetAuthContext::of_proxy(state),
            channel_name,
            CallerAssertion::GatewayOriginated,
        )
        .await
        {
            Ok(credential) => Ok(credential),
            Err(e) => {
                error!(channel = channel_name, error = %e, "Failed to resolve target authentication for agent card fetch");
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => Err(self.fail(
                        FetchFault::CredentialRejected(e),
                        create_error_response(StatusCode::BAD_GATEWAY, "Target authentication failed"),
                    )),
                    crate::config::TargetAuthFallback::Passthrough => {
                        warn!(
                            channel = channel_name,
                            "Target auth failed but passthrough enabled, fetching agent card without credentials"
                        );
                        Ok(None)
                    }
                }
            }
        }
    }

    /// The client the card is fetched with. A served card without a credential uses
    /// the shared client; a served card with one uses a client pinned to the vetted
    /// address and records an egress block. A preview always uses a pinned client
    /// and records nothing.
    async fn client(
        &self,
        target_url: &str,
        credential_sent: bool,
    ) -> Result<reqwest::Client, CardFailure> {
        let state = self.state;
        let channel_name = self.channel_name();
        if !self.mode.serves() {
            return unrecorded_pinned_client(state, target_url)
                .await
                .map_err(|e| match e {
                    PinFailure::Egress(crate::egress::EgressError::Blocked(_)) => {
                        warn!(channel = channel_name, target = %loggable::url(target_url), "Agent card preview blocked by egress policy");
                        CardFailure::new(
                            FetchFault::BlockedByEgress,
                            create_error_response(StatusCode::FORBIDDEN, "Request blocked by egress policy"),
                        )
                    }
                    e => {
                        warn!(channel = channel_name, target = %loggable::url(target_url), error = %e, "Agent card preview could not reach the target");
                        CardFailure::new(
                            FetchFault::Unreachable,
                            create_error_response(StatusCode::BAD_GATEWAY, "Failed to fetch from upstream"),
                        )
                    }
                });
        }
        if !credential_sent {
            return Ok(state.client.clone());
        }
        super::pinned_target_client(
            state,
            channel_name,
            target_url,
            &crate::audit::request_events::RequestFacts {
                surface_id: &state.surface.surface_id,
                channel_name,
                trace_id: None,
                via_fabric: false,
            },
        )
        .await
        .map_err(|response| self.fail(FetchFault::BlockedByEgress, response))
    }

    async fn fetch_over_http(
        &self,
        headers: &HeaderMap,
        target_url: &str,
    ) -> Result<JsonValue, CardFailure> {
        let state = self.state;
        let channel_name = self.channel_name();
        let credential = self
            .target_credential()
            .await?;
        let credential_sent = credential.is_some();
        let mut req = self
            .client(target_url, credential_sent)
            .await?
            .get(target_url);

        let source_cred_headers = state
            .surface
            .source_credential_headers();
        let bound_target = crate::proxy::target_grant::binds_the_target(&state.surface);
        for (key, value) in headers.iter() {
            let forward = match credential {
                Some(_) => super::is_forwarded_on_credentialed_card_fetch(key.as_str()),
                None if bound_target => {
                    crate::proxy::target_grant::forwards_caller_header(key.as_str(), &source_cred_headers, None)
                }
                None => super::should_forward_header(key.as_str(), &source_cred_headers),
            };
            if forward {
                req = req.header(key.as_str(), value.as_bytes());
            }
        }
        if let Some((header_name, header_value)) = &credential {
            req = req.header(header_name.as_str(), header_value.as_str());
            self.credential_sent
                .store(true, Ordering::Relaxed);
            debug!(channel = channel_name, header = %header_name, "Injected target authentication header on agent card fetch");
        }

        let response = req
            .send()
            .await
            .map_err(|e| {
                let fault = FetchFault::of_send(&e);
                error!(
                    channel = channel_name,
                    error = %e.without_url(),
                    "Failed to fetch agent card from upstream - bad gateway"
                );
                self.fail(fault, create_error_response(StatusCode::BAD_GATEWAY, "Failed to fetch from upstream"))
            })?;

        let fault = FetchFault::Status {
            status: response.status().as_u16(),
            credential_sent,
        };
        if response
            .status()
            .is_redirection()
        {
            error!(channel = channel_name, status = %response.status(), "Upstream redirected the agent card fetch - gateway fault");
            return Err(self.fail(fault, create_error_response(StatusCode::BAD_GATEWAY, "Upstream redirected")));
        }
        if !response.status().is_success() {
            error!(channel = channel_name, status = %response.status(), "Upstream returned error for agent card - gateway fault");
            return Err(self.fail(
                fault,
                create_error_response(response.status(), &format!("Upstream error: {}", response.status())),
            ));
        }

        let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
            state.config.a2a.max_body_size,
            state.surface.timeout(),
            state
                .config
                .a2a
                .timeout_seconds,
        );
        let body = crate::proxy::upstream_body::read_bounded(response, limits)
            .await
            .map_err(|e| {
                error!(channel = channel_name, error = %e, "Failed to read agent card from upstream - gateway fault");
                let (status, message) = e.status_and_message();
                self.fail(FetchFault::of_body(&e), create_error_response(status, message))
            })?;
        serde_json::from_slice(&body).map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to parse agent card JSON");
            CardFailure::new(
                FetchFault::InvalidCard,
                create_error_response(StatusCode::BAD_GATEWAY, "Invalid JSON from upstream"),
            )
        })
    }
}

#[derive(Debug)]
enum PinFailure {
    Egress(crate::egress::EgressError),
    Task(tokio::task::JoinError),
}

impl std::fmt::Display for PinFailure {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Egress(e) => e.fmt(f),
            Self::Task(e) => write!(f, "egress validation task failed: {e}"),
        }
    }
}

/// A client pinned to the vetted address of `target_url`. Nothing is recorded.
async fn unrecorded_pinned_client(
    state: &ProxyState,
    target_url: &str,
) -> Result<reqwest::Client, PinFailure> {
    let candidate = target_url.to_string();
    let timeout = std::time::Duration::from_secs(
        state
            .config
            .a2a
            .timeout_seconds,
    );
    match tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&candidate, timeout)).await {
        Ok(Ok((client, _target))) => Ok(client),
        Ok(Err(e)) => Err(PinFailure::Egress(e)),
        Err(e) => Err(PinFailure::Task(e)),
    }
}

fn record_agent_card_gateway_fault(
    state: &ProxyState,
    source_addr: &str,
) {
    if let Some(ref metrics) = state.metrics_store {
        let metrics = Arc::clone(metrics);
        let channel_config_id = state
            .surface
            .surface_id
            .clone();
        let source = source_addr.to_string();
        let dest = state
            .surface
            .target
            .endpoint
            .clone();
        let trace_id = uuid::Uuid::new_v4().to_string();
        crate::observability::policy_audit::spawn_in_request(async move {
            metrics
                .record_connection(
                    channel_config_id,
                    source,
                    dest,
                    crate::metrics::ConnectionStatus::GatewayFault,
                    None,
                    Some("Anonymous".to_string()),
                    crate::metrics::ConnectionDirection::Request,
                    trace_id,
                    None,
                    None,
                    0,
                )
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::{MockServer, RecordingTarget};
    use serde_json::json;

    fn surface(target: JsonValue) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "orders", "name": "Orders",
            "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
            "target": target
        }))
        .unwrap()
    }

    /// The base-route state of a surface on `target`, recording into `metrics`.
    async fn state(
        target: JsonValue,
        metrics: &Arc<crate::metrics::MetricsStore>,
    ) -> ProxyState {
        let state = super::super::variant_routing_tests::router(surface(target))
            .base_proxy_state("orders")
            .await
            .unwrap();
        ProxyState {
            metrics_store: Some(Arc::clone(metrics)),
            ..state
        }
    }

    async fn build(
        state: &ProxyState,
        mode: CardMode,
    ) -> Result<BuiltCard, CardFailure> {
        build_public_card(state, &HeaderMap::new(), "203.0.113.7", mode).await
    }

    /// The connections recorded once the spawned writes have landed, after
    /// waiting for at least `expected`.
    async fn recorded(
        metrics: &crate::metrics::MetricsStore,
        expected: usize,
    ) -> Vec<crate::metrics::ConnectionStatus> {
        for _ in 0..50 {
            if metrics
                .get_recent_connections(10)
                .await
                .len()
                >= expected
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        metrics
            .get_recent_connections(10)
            .await
            .into_iter()
            .map(|connection| connection.status)
            .collect()
    }

    fn closed_port_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_is_built_the_same_way_and_only_a_served_one_is_recorded() {
        let card = json!({"name": "Orders agent", "url": "http://agent.internal/a2a", "skills": []});
        let target = MockServer::start_with_response(card.to_string()).await;
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = state(json!({"endpoint": target.url()}), &metrics).await;

        let preview = build(&state, CardMode::Preview)
            .await
            .unwrap();
        let served = build(&state, CardMode::Serve)
            .await
            .unwrap();

        assert_eq!(preview.upstream, Some(card.clone()));
        assert_eq!(served.upstream, Some(card));
        assert!(!preview.generated && !served.generated);
        assert_eq!(preview.served, served.served);
        assert_ne!(served.served["url"], "http://agent.internal/a2a", "the card points at the Access Point");
        assert_eq!(recorded(&metrics, 1).await, vec![crate::metrics::ConnectionStatus::Success]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreachable_target_is_a_gateway_fault_only_when_the_card_is_served() {
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = state(json!({"endpoint": closed_port_url()}), &metrics).await;

        let preview = build(&state, CardMode::Preview)
            .await
            .unwrap_err();
        assert_eq!(preview.fault, FetchFault::Unreachable);
        assert_eq!(preview.response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            recorded(&metrics, 1)
                .await
                .is_empty(),
            "a preview records no gateway fault"
        );

        let served = build(&state, CardMode::Serve)
            .await
            .unwrap_err();
        assert_eq!(served.fault, FetchFault::Unreachable);
        assert_eq!(served.response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(recorded(&metrics, 1).await, vec![crate::metrics::ConnectionStatus::GatewayFault]);
    }

    #[tokio::test]
    async fn an_upstream_error_names_its_status_and_that_no_credential_was_sent() {
        let target = RecordingTarget::start(StatusCode::NOT_FOUND, &[]).await;
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = state(json!({"endpoint": target.url}), &metrics).await;

        for mode in [CardMode::Preview, CardMode::Serve] {
            let failure = build(&state, mode)
                .await
                .unwrap_err();
            assert_eq!(
                failure.fault,
                FetchFault::Status {
                    status: 404,
                    credential_sent: false
                },
                "{mode:?}"
            );
            assert_eq!(failure.response.status(), StatusCode::NOT_FOUND, "{mode:?}");
        }
    }

    #[tokio::test]
    async fn a_preview_is_blocked_by_egress_without_recording_a_rejected_request() {
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = state(json!({"endpoint": "http://169.254.169.254/agent"}), &metrics).await;

        let (failure, events) = crate::audit::producer::capture(build(&state, CardMode::Preview)).await;

        let failure = failure.unwrap_err();
        assert_eq!(failure.fault, FetchFault::BlockedByEgress);
        assert_eq!(failure.response.status(), StatusCode::FORBIDDEN);
        assert!(events.is_empty(), "{events:?}");
    }

    #[tokio::test]
    async fn a_preview_of_a_host_that_does_not_resolve_is_unreachable_not_blocked() {
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = state(json!({"endpoint": "http://no-such-host.invalid/agent"}), &metrics).await;

        let (failure, events) = crate::audit::producer::capture(build(&state, CardMode::Preview)).await;

        let failure = failure.unwrap_err();
        assert_eq!(failure.fault, FetchFault::Unreachable);
        assert_eq!(failure.response.status(), StatusCode::BAD_GATEWAY);
        assert!(events.is_empty(), "{events:?}");
        assert!(
            recorded(&metrics, 1)
                .await
                .is_empty(),
            "a preview records no gateway fault"
        );
    }

    #[tokio::test]
    async fn a_target_credential_that_cannot_be_resolved_names_why() {
        let metrics = Arc::new(crate::metrics::MetricsStore::new(10));
        let state = state(
            json!({"endpoint": "http://127.0.0.1:9", "auth": {"method": {"static_secret": {
                "secret_id": "missing", "header_name": "x-key"
            }}}}),
            &metrics,
        )
        .await;

        for mode in [CardMode::Preview, CardMode::Serve] {
            let failure = build(&state, mode)
                .await
                .unwrap_err();
            assert_eq!(failure.fault, FetchFault::CredentialRejected(TargetAuthError::StoreUnavailable), "{mode:?}");
            assert_eq!(failure.response.status(), StatusCode::BAD_GATEWAY, "{mode:?}");
        }
    }

    #[test]
    fn the_card_url_is_the_well_known_path_or_the_override_on_the_target_origin() {
        let cases = [
            ("no override", None, "https://agent.example/base/.well-known/agent-card.json"),
            ("an absolute override path", Some("/cards/agent.json"), "https://agent.example/cards/agent.json"),
            ("a relative override path", Some("cards/agent.json"), "https://agent.example/cards/agent.json"),
        ];
        for (case, agent_card_path, expected) in cases {
            let mut surface = surface(json!({"endpoint": "https://agent.example/base"}));
            surface
                .access_point
                .agent_card_path = agent_card_path.map(str::to_string);

            assert_eq!(card_target_url(&surface), expected, "{case}");
        }
    }
}
