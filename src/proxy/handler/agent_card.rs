//! The public agent card the card route serves: the agent's own card fetched from
//! the Target (or the card an A2A proxy generates), identity resolution, the
//! endpoint and security rewrite, and the gateway's identity credential. The card
//! route serves the result; the Agent card preview shows it to operators.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value as JsonValue;
use tracing::{debug, error, info, warn};

use crate::a2a::create_error_response;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::proxy::card_preview::{CallerFetch, CardAuthReport, CardFetchCause, CardFetchStatus, card_preview_service};
use crate::proxy::target_card::CardRead;
use crate::source_auth::declaration::DeclarationOutcome;
use crate::state::ProxyState;

/// Whether the card is served to a caller or shown to an operator. A preview reads
/// the card as [`CardRead::PolicyContext`] and skips what serving a card records:
/// rejected requests, gateway faults, the Trust Recorder, the connection metric and
/// the card security counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardMode {
    Serve,
    Preview,
}

impl CardMode {
    fn serves(self) -> bool {
        self == Self::Serve
    }

    fn card_read(self) -> CardRead {
        match self {
            Self::Serve => CardRead::AnswersCaller,
            Self::Preview => CardRead::PolicyContext,
        }
    }
}

/// Everything one assembly of the public card produced.
pub(crate) struct AssembledCard {
    /// The agent's own card as parsed, before any change. `None` for a generated card.
    pub upstream: Option<JsonValue>,
    /// The card the route serves. `None` on failure.
    pub served: Option<JsonValue>,
    /// The declaration the rewrite applied, when the card got that far.
    pub outcome: Option<DeclarationOutcome>,
    pub failure: Option<CardFailure>,
}

impl AssembledCard {
    /// The card to serve, or why the route serves none.
    pub(crate) fn into_served(self) -> Result<JsonValue, CardRefusal> {
        match (self.failure, self.served) {
            (Some(failure), _) => Err(CardRefusal::Failed(failure)),
            (None, Some(card)) => Ok(card),
            (None, None) => Err(CardRefusal::NoCard),
        }
    }

    pub(crate) fn caller_fetch(&self) -> CallerFetch {
        CallerFetch {
            status: self
                .failure
                .as_ref()
                .map_or(CardFetchStatus::Ok, |failure| failure.cause.status()),
            cause: self
                .failure
                .as_ref()
                .map(|failure| failure.cause),
            http_status: self
                .failure
                .as_ref()
                .and_then(|failure| failure.http_status),
            at: chrono::Utc::now(),
        }
    }
}

/// Why the card route serves no card.
pub(crate) enum CardRefusal {
    /// The assembly failed; the route answers what the failure prepared.
    Failed(CardFailure),
    /// The assembly finished without a card.
    NoCard,
}

impl IntoResponse for CardRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::Failed(failure) => *failure.live,
            Self::NoCard => crate::a2a::agent_card_refusal(),
        }
    }
}

/// Why the card was not served, and exactly what the card route answers.
pub(crate) struct CardFailure {
    pub cause: CardFetchCause,
    pub http_status: Option<u16>,
    live: Box<Response>,
}

impl CardFailure {
    fn new(
        fault: FetchFault,
        live: Response,
    ) -> Self {
        let (cause, http_status) = classify(fault);
        Self {
            cause,
            http_status,
            live: Box::new(live),
        }
    }
}

/// What went wrong while assembling the card, before it is named for an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchFault {
    CredentialRejected,
    Status { status: u16, credential_sent: bool },
    Unreachable,
    TimedOut,
    TooLarge,
    InvalidCard,
    BlockedByEgress,
    ProxyUnavailable,
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

/// The cause an operator sees for a fault, with the agent's status code for a
/// status-derived cause.
pub(crate) fn classify(fault: FetchFault) -> (CardFetchCause, Option<u16>) {
    match fault {
        FetchFault::CredentialRejected => (CardFetchCause::AuthFailed, None),
        FetchFault::Status { status, credential_sent } => {
            (classify_status(status, credential_sent).unwrap_or(CardFetchCause::UpstreamError), Some(status))
        }
        FetchFault::Unreachable => (CardFetchCause::Unreachable, None),
        FetchFault::TimedOut => (CardFetchCause::Timeout, None),
        FetchFault::TooLarge => (CardFetchCause::TooLarge, None),
        FetchFault::InvalidCard => (CardFetchCause::InvalidCard, None),
        FetchFault::BlockedByEgress => (CardFetchCause::BlockedByEgress, None),
        FetchFault::ProxyUnavailable => (CardFetchCause::ProxyUnavailable, None),
        FetchFault::IdentityFailed => (CardFetchCause::IdentityFailed, None),
        FetchFault::RewriteFailed => (CardFetchCause::RewriteFailed, None),
    }
}

/// The cause of an agent's answer, `None` for a success.
pub(crate) fn classify_status(
    status: u16,
    credential_sent: bool,
) -> Option<CardFetchCause> {
    match status {
        200..=299 => None,
        401 if credential_sent => Some(CardFetchCause::AuthFailed),
        401 => Some(CardFetchCause::NeedsToken),
        403 => Some(CardFetchCause::Forbidden),
        404 | 410 => Some(CardFetchCause::NotFound),
        300..=399 => Some(CardFetchCause::Redirected),
        _ => Some(CardFetchCause::UpstreamError),
    }
}

/// Which payment protocols gate the public agent card. A delegated (Model B) x402
/// policy has no local price or verify config to check here and is never routed
/// through the delegation relay on this endpoint, so it does not paywall the card.
pub(crate) struct CardPaymentGates {
    pub x402: bool,
    pub mpp: bool,
}

impl CardPaymentGates {
    pub(crate) fn any(&self) -> bool {
        self.x402 || self.mpp
    }
}

pub(crate) fn card_payment_gates(surface: &crate::config::agent_surface::AgentSurface) -> CardPaymentGates {
    CardPaymentGates {
        x402: surface
            .x402_config()
            .is_some_and(|p| p.enabled && p.provider != crate::config::types::X402Provider::AgentPay),
        mpp: surface
            .mpp_config()
            .is_some_and(|p| crate::mpp::should_require_payment(p, &surface.channel_protocol(), b"", None)),
    }
}

/// The declaration the card served on the state's route resolves to, read without
/// fetching the card.
pub(crate) async fn card_declaration(state: &ProxyState) -> anyhow::Result<DeclarationOutcome> {
    let strategies = super::card_strategy_store(state);
    let security = super::card_security_context(state, strategies.as_deref());
    crate::source_auth::declaration::resolve_surface_declaration(
        &state.surface,
        security.variant_alias,
        security.strategies,
        &state.network_config,
    )
    .await
}

/// The agent card URL the card route fetches from an `http(s)` or `fabric://` Target:
/// the `override_agent_card_location` path on the Target's origin, or the well-known
/// path under the Target endpoint.
pub(crate) fn card_target_url(surface: &crate::config::agent_surface::AgentSurface) -> String {
    match surface
        .agent_card_location_path()
        .filter(|_| surface.override_agent_card_location())
    {
        Some(custom_path) => {
            crate::proxy::protocol_router::override_agent_card_url(&surface.target.endpoint, custom_path)
        }
        None => {
            crate::proxy::protocol_router::join_endpoint_path(&surface.target.endpoint, "/.well-known/agent-card.json")
        }
    }
}

/// Serve the public card for the base route or the request's Surface Variant, or
/// answer what the card route gives instead. A base-route request is kept as the
/// surface's last caller fetch and, when served, as its last served card.
pub(crate) async fn assemble_public_agent_card(
    state: &ProxyState,
    headers: &HeaderMap,
    source_addr: &str,
) -> Result<JsonValue, Response> {
    let mut auth = CardAuthReport::for_surface(&state.surface);
    let assembled = assemble_card(state, headers, source_addr, CardMode::Serve, &mut auth).await;
    let base_route = state
        .active_variant_alias
        .is_none();
    if base_route {
        card_preview_service()
            .record_caller_fetch(&state.surface.surface_id, assembled.caller_fetch())
            .await;
    }
    let card = assembled
        .into_served()
        .map_err(IntoResponse::into_response)?;
    if base_route {
        card_preview_service()
            .keep_served_card(&state.surface, &card)
            .await;
    }
    Ok(card)
}

/// Assemble the public card for the base route or the request's Surface Variant.
/// `auth` is filled in as Target Authentication resolves, so it holds what happened
/// even when the caller stops waiting.
pub(crate) async fn assemble_card(
    state: &ProxyState,
    headers: &HeaderMap,
    source_addr: &str,
    mode: CardMode,
    auth: &mut CardAuthReport,
) -> AssembledCard {
    let mut assembled = AssembledCard {
        upstream: None,
        served: None,
        outcome: None,
        failure: None,
    };
    if let Err(failure) = assemble_into(state, headers, source_addr, mode, auth, &mut assembled).await {
        assembled.failure = Some(failure);
    }
    assembled
}

async fn assemble_into(
    state: &ProxyState,
    headers: &HeaderMap,
    source_addr: &str,
    mode: CardMode,
    auth: &mut CardAuthReport,
    assembled: &mut AssembledCard,
) -> Result<(), CardFailure> {
    let channel_name = state.surface.name.as_str();
    let prepared = super::prepare_a2a_proxy_agent_card(state, channel_name)
        .await
        .map_err(|live| CardFailure::new(FetchFault::ProxyUnavailable, live))?;
    let (card, prepared_identity, generated) = match prepared {
        Some(prepared) => (prepared.card, prepared.identity, true),
        None => {
            let card_url = card_target_url(&state.surface);
            let fetch = TargetCardFetch { state, source_addr, mode };
            let card = fetch
                .fetch(headers, &card_url, auth)
                .await?;
            assembled.upstream = Some(card.clone());
            (card, None, false)
        }
    };

    let card_bytes = serde_json::to_vec(&card).unwrap_or_default();
    let resolved_identity = match prepared_identity {
        Some(identity) => identity,
        None => resolve_card_identity(state, &card_bytes).await?,
    };
    resolve_external_card_identity(state, &card_bytes).await?;

    let (mut agent_card, outcome) = secure_public_card(state, card, &card_bytes, generated, mode).await?;
    assembled.outcome = Some(outcome);
    inject_identity_credential(state, &mut agent_card, &resolved_identity).await?;
    #[cfg(feature = "didwebvh")]
    inject_agent_dna(state, &mut agent_card).await;

    info!(channel = channel_name, "Successfully fetched and parsed agent card");
    if mode.serves() {
        record_served_effects(state, source_addr, &resolved_identity);
    }
    assembled.served = Some(agent_card);
    Ok(())
}

/// The card with its endpoints rewritten to the Access Point and its security
/// declaration applied, counted as served when it is served. A card an A2A proxy
/// generates already names its endpoint, so only its security is applied. A card
/// that cannot be rewritten or secured is refused.
async fn secure_public_card(
    state: &ProxyState,
    card: JsonValue,
    card_bytes: &[u8],
    generated: bool,
    mode: CardMode,
) -> Result<(JsonValue, DeclarationOutcome), CardFailure> {
    let channel_name = state.surface.name.as_str();
    let strategies = super::card_strategy_store(state);
    let security = super::card_security_context(state, strategies.as_deref());
    let fault = if card.is_object() {
        FetchFault::RewriteFailed
    } else {
        FetchFault::InvalidCard
    };
    let secured = if generated {
        let mut card = card;
        crate::a2a::url_rewriter::secure_agent_card(&mut card, &state.surface, security, &state.network_config)
            .await
            .map(|outcome| (card, outcome))
    } else {
        crate::a2a::rewrite_agent_card(
            card_bytes,
            &state.surface,
            security,
            &state.network_config,
            crate::a2a::AgentCardKind::Public,
        )
        .await
    };
    let (agent_card, outcome) = secured.map_err(|e| {
        warn!(channel = channel_name, error = %e, "Failed to process agent card");
        CardFailure::new(fault, crate::a2a::agent_card_refusal())
    })?;
    if mode.serves() {
        crate::a2a::record_served_card(channel_name, &outcome, &serde_json::to_vec(&agent_card).unwrap_or_default());
    }
    Ok((agent_card, outcome))
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

/// External slot resolution (Surface Builder external identity node). Issues a DID
/// for the external counterparty through the VC issuer.
async fn resolve_external_card_identity(
    state: &ProxyState,
    card_bytes: &[u8],
) -> Result<(), CardFailure> {
    let channel_name = state.surface.name.as_str();
    if state
        .external_selector
        .is_none()
    {
        return Ok(());
    }
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
/// Recorder populates the trust registry on the first discovery fetch; it is
/// fire-and-forget and idempotent.
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
}

impl TargetCardFetch<'_> {
    /// The failure of a fetch, recorded as a gateway fault when the card is served.
    fn fail(
        &self,
        fault: FetchFault,
        live: Response,
    ) -> CardFailure {
        if self.mode.serves() {
            record_agent_card_gateway_fault(self.state, self.source_addr);
        }
        CardFailure::new(fault, live)
    }

    async fn fetch(
        &self,
        headers: &HeaderMap,
        target_url: &str,
        auth: &mut CardAuthReport,
    ) -> Result<JsonValue, CardFailure> {
        let channel_name = self
            .state
            .surface
            .name
            .as_str();
        debug!(channel = channel_name, target = %crate::observability::loggable::url(target_url), "Fetching agent card from upstream");
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
            self.fetch_over_http(headers, target_url, auth)
                .await
        }
    }

    async fn fetch_via_fabric(
        &self,
        headers: &HeaderMap,
    ) -> Result<JsonValue, CardFailure> {
        let state = self.state;
        let channel_name = state.surface.name.as_str();
        let source_cred_header = state
            .surface
            .source_auth()
            .and_then(|sa| sa.credential_header_name());
        let forwarded_headers = headers
            .iter()
            .filter(|(key, _)| super::should_forward_header(key.as_str(), source_cred_header))
            .filter_map(|(key, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (key.as_str().to_string(), value.to_string()))
            })
            .collect::<HashMap<_, _>>();
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

    /// The client pinned to the vetted address of `target_url`. A card refused by
    /// the egress policy is recorded as a rejected request only when it is served.
    async fn pinned_client(
        &self,
        target_url: &str,
    ) -> Result<reqwest::Client, CardFailure> {
        let state = self.state;
        let channel_name = state.surface.name.as_str();
        if self.mode.serves() {
            return super::pinned_target_client(
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
            .map_err(|live| self.fail(FetchFault::BlockedByEgress, live));
        }
        unrecorded_pinned_client(
            target_url,
            Duration::from_secs(
                state
                    .config
                    .a2a
                    .timeout_seconds,
            ),
        )
        .await
        .ok_or_else(|| {
            warn!(channel = channel_name, "Agent card preview blocked by egress policy");
            CardFailure::new(
                FetchFault::BlockedByEgress,
                create_error_response(StatusCode::FORBIDDEN, "Request blocked by egress policy"),
            )
        })
    }

    async fn fetch_over_http(
        &self,
        headers: &HeaderMap,
        target_url: &str,
        auth: &mut CardAuthReport,
    ) -> Result<JsonValue, CardFailure> {
        let state = self.state;
        let channel_name = state.surface.name.as_str();
        let credential = crate::proxy::target_card::card_fetch_credential(
            &state.target_credentials(),
            &state.surface,
            target_url,
            false,
            self.mode.card_read(),
        )
        .await
        .map_err(|rejected| {
            warn!(
                channel = channel_name,
                reason = rejected.reason(),
                "Agent card not fetched: Target authentication failed"
            );
            let crate::proxy::target_card::CardFetchRejected(error) = rejected;
            auth.rejected(error);
            self.fail(
                FetchFault::CredentialRejected,
                create_error_response(StatusCode::BAD_GATEWAY, crate::proxy::target_credentials::TARGET_AUTH_FAILED),
            )
        })?;
        auth.resolved(credential.as_ref());
        let credential_sent = credential.is_some();

        let mut req = self
            .pinned_client(target_url)
            .await?
            .get(target_url);

        let source_cred_header = state
            .surface
            .source_auth()
            .and_then(|sa| sa.credential_header_name());
        for (key, value) in headers.iter() {
            let forward = match credential {
                Some(_) => super::is_forwarded_on_credentialed_card_fetch(key.as_str()),
                None => super::should_forward_header(key.as_str(), source_cred_header),
            };
            if forward {
                req = req.header(key.as_str(), value.as_bytes());
            }
        }
        if let Some(credential) = credential {
            debug!(channel = channel_name, header = %credential.name, "Injected target authentication header on agent card fetch");
            req = credential.set_on(req);
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

        let status = FetchFault::Status {
            status: response.status().as_u16(),
            credential_sent,
        };
        if response
            .status()
            .is_redirection()
        {
            error!(channel = channel_name, status = %response.status(), "Upstream redirected the agent card fetch - gateway fault");
            return Err(self.fail(status, create_error_response(StatusCode::BAD_GATEWAY, "Upstream redirected")));
        }
        if !response.status().is_success() {
            error!(channel = channel_name, status = %response.status(), "Upstream returned error for agent card - gateway fault");
            return Err(self.fail(
                status,
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

/// A client pinned to the vetted address of `target_url`, or `None` when the egress
/// policy refuses it. Nothing is recorded.
async fn unrecorded_pinned_client(
    target_url: &str,
    timeout: Duration,
) -> Option<reqwest::Client> {
    let candidate = target_url.to_string();
    match tokio::task::spawn_blocking(move || crate::egress::pinned_forward_client(&candidate, timeout)).await {
        Ok(Ok((client, _target))) => Some(client),
        Ok(Err(_)) | Err(_) => None,
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

    const EVERY_FAULT: [FetchFault; 10] = [
        FetchFault::CredentialRejected,
        FetchFault::Status {
            status: 500,
            credential_sent: false,
        },
        FetchFault::Unreachable,
        FetchFault::TimedOut,
        FetchFault::TooLarge,
        FetchFault::InvalidCard,
        FetchFault::BlockedByEgress,
        FetchFault::ProxyUnavailable,
        FetchFault::IdentityFailed,
        FetchFault::RewriteFailed,
    ];

    #[test]
    fn test_a_preview_reads_the_card_without_answering_a_caller() {
        assert_eq!(CardMode::Serve.card_read(), CardRead::AnswersCaller);
        assert_eq!(CardMode::Preview.card_read(), CardRead::PolicyContext);
        assert!(CardMode::Serve.serves());
        assert!(!CardMode::Preview.serves(), "a preview records nothing a served card records");
    }

    #[test]
    fn test_classify_status_names_each_answer_and_never_a_success() {
        for status in [200, 201, 204, 299] {
            assert_eq!(classify_status(status, false), None, "{status} is not a cause");
            assert_eq!(classify_status(status, true), None, "{status} is not a cause");
        }
        assert_eq!(classify_status(401, false), Some(CardFetchCause::NeedsToken));
        assert_eq!(classify_status(401, true), Some(CardFetchCause::AuthFailed));
        assert_eq!(classify_status(403, true), Some(CardFetchCause::Forbidden));
        assert_eq!(classify_status(403, false), Some(CardFetchCause::Forbidden));
        assert_eq!(classify_status(404, false), Some(CardFetchCause::NotFound));
        assert_eq!(classify_status(410, false), Some(CardFetchCause::NotFound));
        for status in [301, 302, 307, 308] {
            assert_eq!(classify_status(status, true), Some(CardFetchCause::Redirected));
        }
        for status in [400, 405, 429, 500, 502, 503] {
            assert_eq!(classify_status(status, false), Some(CardFetchCause::UpstreamError), "{status}");
        }
    }

    #[test]
    fn test_classify_keeps_the_status_only_for_status_derived_causes() {
        assert_eq!(
            classify(FetchFault::Status {
                status: 401,
                credential_sent: false
            }),
            (CardFetchCause::NeedsToken, Some(401))
        );
        assert_eq!(
            classify(FetchFault::Status {
                status: 401,
                credential_sent: true
            }),
            (CardFetchCause::AuthFailed, Some(401))
        );
        assert_eq!(
            classify(FetchFault::Status {
                status: 503,
                credential_sent: true
            }),
            (CardFetchCause::UpstreamError, Some(503))
        );
        let expected = [
            CardFetchCause::AuthFailed,
            CardFetchCause::UpstreamError,
            CardFetchCause::Unreachable,
            CardFetchCause::Timeout,
            CardFetchCause::TooLarge,
            CardFetchCause::InvalidCard,
            CardFetchCause::BlockedByEgress,
            CardFetchCause::ProxyUnavailable,
            CardFetchCause::IdentityFailed,
            CardFetchCause::RewriteFailed,
        ];
        for (fault, cause) in EVERY_FAULT
            .into_iter()
            .zip(expected)
        {
            let (classified, http_status) = classify(fault);
            assert_eq!(classified, cause, "{fault:?}");
            assert_eq!(http_status.is_some(), matches!(fault, FetchFault::Status { .. }), "{fault:?}");
        }
    }

    #[test]
    fn test_only_identity_and_rewrite_failures_are_not_served() {
        for fault in EVERY_FAULT {
            let (cause, _) = classify(fault);
            let expected = if matches!(fault, FetchFault::IdentityFailed | FetchFault::RewriteFailed) {
                CardFetchStatus::NotServed
            } else {
                CardFetchStatus::Failed
            };
            assert_eq!(cause.status(), expected, "{cause:?}");
        }
    }

    #[test]
    fn test_body_faults_name_a_size_or_a_timeout() {
        use crate::proxy::upstream_body::UpstreamBodyError;
        assert_eq!(FetchFault::of_body(&UpstreamBodyError::TooLarge(10)), FetchFault::TooLarge);
        assert_eq!(FetchFault::of_body(&UpstreamBodyError::TimedOut), FetchFault::TimedOut);
    }

    async fn parts(response: Response) -> (StatusCode, Option<String>, String) {
        let status = response.status();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        (status, content_type, String::from_utf8(bytes.to_vec()).expect("utf-8 body"))
    }

    fn assembled(
        served: Option<JsonValue>,
        failure: Option<CardFailure>,
    ) -> AssembledCard {
        AssembledCard {
            upstream: None,
            served,
            outcome: None,
            failure,
        }
    }

    fn upstream_503() -> CardFailure {
        CardFailure::new(
            FetchFault::Status {
                status: 503,
                credential_sent: false,
            },
            create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Upstream error: 503"),
        )
    }

    #[tokio::test]
    async fn test_into_served_serves_the_card_or_answers_what_the_failure_prepared() {
        let card = serde_json::json!({ "name": "agent" });
        let served = assembled(Some(card.clone()), None).into_served();
        assert_eq!(served.ok(), Some(card.clone()));

        for served in [None, Some(card)] {
            let Err(refusal) = assembled(served, Some(upstream_503())).into_served() else {
                panic!("a failed assembly must not serve a card");
            };
            assert!(matches!(refusal, CardRefusal::Failed(_)));
            assert_eq!(
                parts(refusal.into_response()).await,
                parts(create_error_response(StatusCode::SERVICE_UNAVAILABLE, "Upstream error: 503")).await
            );
        }

        let Err(refusal) = assembled(None, None).into_served() else {
            panic!("an assembly without a card must not serve one");
        };
        assert!(matches!(refusal, CardRefusal::NoCard));
        let rendered = parts(refusal.into_response()).await;
        assert_eq!(rendered.0, StatusCode::BAD_GATEWAY);
        assert_eq!(rendered, parts(crate::a2a::agent_card_refusal()).await);
    }

    #[test]
    fn test_the_caller_fetch_names_the_cause_and_status_of_a_failure_only() {
        let ok = assembled(Some(serde_json::json!({"name": "agent"})), None).caller_fetch();
        assert_eq!((ok.status, ok.cause, ok.http_status), (CardFetchStatus::Ok, None, None));

        let failed = assembled(None, Some(upstream_503())).caller_fetch();
        assert_eq!(
            (failed.status, failed.cause, failed.http_status),
            (CardFetchStatus::Failed, Some(CardFetchCause::UpstreamError), Some(503))
        );

        let not_served =
            assembled(None, Some(CardFailure::new(FetchFault::RewriteFailed, crate::a2a::agent_card_refusal())))
                .caller_fetch();
        assert_eq!(
            (not_served.status, not_served.cause, not_served.http_status),
            (CardFetchStatus::NotServed, Some(CardFetchCause::RewriteFailed), None)
        );
    }

    #[tokio::test]
    async fn test_a_preview_blocked_by_egress_records_no_rejected_request() {
        let (client, events) = crate::audit::producer::capture(unrecorded_pinned_client(
            "http://169.254.169.254/.well-known/agent-card.json",
            Duration::from_secs(1),
        ))
        .await;
        assert!(client.is_none(), "the metadata address is refused");
        assert!(events.is_empty(), "the refusal is not recorded: {events:?}");
    }

    #[test]
    fn test_card_payment_gates_need_a_local_payment_protocol() {
        let surface = surface(serde_json::json!({"name": "s",
            "access_point": {"listen_address": "127.0.0.1:0", "route": "/a", "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example/api/"}}));
        let gates = card_payment_gates(&surface);
        assert_eq!((gates.x402, gates.mpp, gates.any()), (false, false, false));
        let x402_only = CardPaymentGates { x402: true, mpp: false };
        let mpp_only = CardPaymentGates { x402: false, mpp: true };
        assert!(x402_only.any());
        assert!(mpp_only.any());
    }

    fn surface(json: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json).expect("surface JSON")
    }

    #[test]
    fn test_card_target_url_reads_the_well_known_path_or_the_override() {
        let base = |extra: serde_json::Value| {
            let mut access_point =
                serde_json::json!({"listen_address": "127.0.0.1:0", "route": "/a", "protocol": "a2a"});
            if let Some(object) = extra.as_object() {
                for (key, value) in object {
                    access_point[key] = value.clone();
                }
            }
            surface(serde_json::json!({"name": "s", "access_point": access_point,
                "target": {"endpoint": "https://agent.example/api/"}}))
        };
        assert_eq!(
            card_target_url(&base(serde_json::json!({}))),
            "https://agent.example/api/.well-known/agent-card.json"
        );
        assert_eq!(
            card_target_url(&base(serde_json::json!({"agent_card_path": "/cards/me.json"}))),
            "https://agent.example/cards/me.json",
            "an agent card path is read on the Target's origin"
        );
    }
}
