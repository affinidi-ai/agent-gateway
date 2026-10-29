//! The public agent card the card route serves: the agent's own card fetched from
//! the Target (or the card an A2A proxy generates), identity resolution, the
//! endpoint and security rewrite, and the gateway's identity credential.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde_json::Value as JsonValue;
use tracing::{debug, error, info, warn};

use crate::a2a::create_error_response;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::state::ProxyState;

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

/// Assemble the public card for the base route or the request's Surface Variant, or
/// the answer the card route gives instead.
pub(crate) async fn assemble_public_agent_card(
    state: &ProxyState,
    headers: &HeaderMap,
    source_addr: &str,
) -> Result<JsonValue, Response> {
    let channel_name = state.surface.name.as_str();
    let prepared = super::prepare_a2a_proxy_agent_card(state, channel_name).await?;
    let (card, prepared_identity, generated) = match prepared {
        Some(prepared) => (prepared.card, prepared.identity, true),
        None => {
            let card_url = card_target_url(&state.surface);
            let fetch = TargetCardFetch { state, source_addr };
            (
                fetch
                    .fetch(headers, &card_url)
                    .await?,
                None,
                false,
            )
        }
    };

    let card_bytes = serde_json::to_vec(&card).unwrap_or_default();
    let resolved_identity = match prepared_identity {
        Some(identity) => identity,
        None => resolve_card_identity(state, &card_bytes).await?,
    };
    resolve_external_card_identity(state, &card_bytes).await?;

    let mut agent_card = secure_public_card(state, card, &card_bytes, generated).await?;
    inject_identity_credential(state, &mut agent_card, &resolved_identity).await?;
    #[cfg(feature = "didwebvh")]
    inject_agent_dna(state, &mut agent_card).await;

    info!(channel = channel_name, "Successfully fetched and parsed agent card");
    record_served_effects(state, source_addr, &resolved_identity);
    Ok(agent_card)
}

/// The card with its endpoints rewritten to the Access Point and its security
/// declaration applied, counted as served. A card an A2A proxy generates already
/// names its endpoint, so only its security is applied. A card that cannot be
/// rewritten or secured is refused.
async fn secure_public_card(
    state: &ProxyState,
    card: JsonValue,
    card_bytes: &[u8],
    generated: bool,
) -> Result<JsonValue, Response> {
    let channel_name = state.surface.name.as_str();
    let strategies = super::card_strategy_store(state);
    let security = super::card_security_context(state, strategies.as_deref());
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
        crate::a2a::agent_card_refusal()
    })?;
    crate::a2a::record_served_card(channel_name, &outcome, &serde_json::to_vec(&agent_card).unwrap_or_default());
    Ok(agent_card)
}

async fn resolve_card_identity(
    state: &ProxyState,
    card_bytes: &[u8],
) -> Result<ProtectedAgentIdentity, Response> {
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
        crate::a2a::create_identity_error_response(
            e.http_status(),
            e.code(),
            "protected_identity",
            channel_name,
            &e.to_string(),
        )
    })
}

/// External slot resolution (Surface Builder external identity node). Issues a DID
/// for the external counterparty through the VC issuer.
async fn resolve_external_card_identity(
    state: &ProxyState,
    card_bytes: &[u8],
) -> Result<(), Response> {
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
        crate::a2a::create_identity_error_response(
            e.http_status(),
            e.code(),
            "external_identity",
            channel_name,
            &e.to_string(),
        )
    })
}

/// Replace `agent-identity/v1` with `agent-identity-credential/v1` (a signed VP).
async fn inject_identity_credential(
    state: &ProxyState,
    agent_card: &mut JsonValue,
    resolved_identity: &ProtectedAgentIdentity,
) -> Result<(), Response> {
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
            create_error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Agent card identity credential injection failed: {}", e),
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
    let variant_alias = state
        .active_variant_alias
        .clone();
    tokio::spawn(async move {
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
                variant_alias,
            )
            .await;
    });
}

/// The gateway's own read of the agent card from the Target, answering the caller.
struct TargetCardFetch<'a> {
    state: &'a ProxyState,
    source_addr: &'a str,
}

impl TargetCardFetch<'_> {
    /// Record a gateway fault and answer the caller with `live`.
    fn fail(
        &self,
        live: Response,
    ) -> Response {
        record_agent_card_gateway_fault(self.state, self.source_addr);
        live
    }

    async fn fetch(
        &self,
        headers: &HeaderMap,
        target_url: &str,
    ) -> Result<JsonValue, Response> {
        let channel_name = self
            .state
            .surface
            .name
            .as_str();
        debug!(channel = channel_name, target = %target_url, "Fetching agent card from upstream");
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
    ) -> Result<JsonValue, Response> {
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
            self.fail(create_error_response(StatusCode::BAD_GATEWAY, &format!("Failed to fetch from upstream: {}", e)))
        })?;

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        if !status.is_success() {
            error!(channel = channel_name, status = %status, "Fabric upstream returned error for agent card - gateway fault");
            return Err(self.fail(create_error_response(status, &format!("Upstream error: {status}"))));
        }

        serde_json::from_slice(&response.body).map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to parse fabric agent card JSON");
            create_error_response(StatusCode::BAD_GATEWAY, "Invalid JSON from upstream")
        })
    }

    async fn fetch_over_http(
        &self,
        headers: &HeaderMap,
        target_url: &str,
    ) -> Result<JsonValue, Response> {
        let state = self.state;
        let channel_name = state.surface.name.as_str();
        let credential = crate::proxy::target_card::card_fetch_credential(
            &state.target_credentials(),
            &state.surface,
            target_url,
            false,
            crate::proxy::target_card::CardRead::AnswersCaller,
        )
        .await
        .map_err(|rejected| {
            warn!(
                channel = channel_name,
                reason = rejected.reason(),
                "Agent card not fetched: Target authentication failed"
            );
            self.fail(create_error_response(
                StatusCode::BAD_GATEWAY,
                crate::proxy::target_credentials::TARGET_AUTH_FAILED,
            ))
        })?;

        let mut req = match credential {
            Some(_) => super::pinned_target_client(
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
            .map_err(|live| self.fail(live))?
            .get(target_url),
            None => state.client.get(target_url),
        };

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
                error!(channel = channel_name, error = %e, "Failed to fetch agent card from upstream - bad gateway");
                self.fail(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("Failed to fetch from upstream: {}", e),
                ))
            })?;

        if response
            .status()
            .is_redirection()
        {
            error!(channel = channel_name, status = %response.status(), "Upstream redirected the agent card fetch - gateway fault");
            return Err(self.fail(create_error_response(StatusCode::BAD_GATEWAY, "Upstream redirected")));
        }
        if !response.status().is_success() {
            error!(channel = channel_name, status = %response.status(), "Upstream returned error for agent card - gateway fault");
            return Err(
                self.fail(create_error_response(response.status(), &format!("Upstream error: {}", response.status())))
            );
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
                self.fail(create_error_response(status, message))
            })?;
        serde_json::from_slice(&body).map_err(|e| {
            error!(channel = channel_name, error = %e, "Failed to parse agent card JSON");
            create_error_response(StatusCode::BAD_GATEWAY, "Invalid JSON from upstream")
        })
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
        tokio::spawn(async move {
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
                    None,
                )
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(extra: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
        let mut access_point = serde_json::json!({"listen_address": "127.0.0.1:0", "route": "/a", "protocol": "a2a"});
        if let Some(object) = extra.as_object() {
            for (key, value) in object {
                access_point[key] = value.clone();
            }
        }
        serde_json::from_value(serde_json::json!({"name": "s", "access_point": access_point,
            "target": {"endpoint": "https://agent.example/api/"}}))
        .expect("surface JSON")
    }

    #[test]
    fn test_card_target_url_reads_the_well_known_path_or_the_override() {
        assert_eq!(
            card_target_url(&surface(serde_json::json!({}))),
            "https://agent.example/api/.well-known/agent-card.json"
        );
        assert_eq!(
            card_target_url(&surface(serde_json::json!({"agent_card_path": "/cards/me.json"}))),
            "https://agent.example/cards/me.json",
            "an agent card path is read on the Target's origin"
        );
    }
}
