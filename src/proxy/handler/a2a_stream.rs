//! Response checks for an A2A event stream from a direct Target.
//!
//! Each event gets the treatment a non-streaming reply gets on the Access Point:
//! identity resolution and the agent-identity credential where the event claims
//! an identity, response custom metadata, response extension rules and the
//! response policy. Identity a slot derives from a credential is resolved once
//! per stream; identity read from the body is resolved on each event that claims
//! one. The Trust Recorder runs once per resolved DID.
//!
//! A stream that delivered results without any event resolving the identity a
//! slot reads from the body ends with an identity error after its last event,
//! as a non-streaming reply without a claim is refused. The protected slot is
//! exempt when the request path resolved an identity.

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::a2a::streaming::{EventProcessor, StreamStop};
use crate::mcp::modern_sse::SseLimits;
use crate::proxy::backend_identity::{IdentityResponseKind, IdentitySlot, ProtectedAgentIdentity};
use crate::proxy::response_policy::{CallerContext, ResponseContext, ResponsePolicyInput, SurfaceContext};
use crate::state::ProxyState;

const RESPONSE_BLOCKED: StreamStop = StreamStop::new("response_policy_denied", "Response blocked");
const EXTENSIONS_REJECTED: StreamStop =
    StreamStop::new("response_extension_rejected", "Response extension validation failed");

/// The limits on an event stream from a direct Target: one event may be as
/// large as `[a2a] max_body_size`, the Target may stay quiet for the surface's
/// `networking.timeout.idle_secs` (`0` leaves only the lifetime), and the
/// stream may last `[a2a] stream_max_lifetime_secs`.
pub(super) fn stream_limits(
    a2a: &crate::config::A2aConfig,
    timeout: Option<&crate::config::TimeoutConfig>,
) -> SseLimits {
    let max_event_bytes = NonZeroUsize::new(a2a.max_body_size).unwrap_or(NonZeroUsize::MIN);
    let max_lifetime = Duration::from_secs(a2a.stream_max_lifetime_secs);
    let idle_secs =
        timeout.map_or_else(|| crate::config::TimeoutConfig::default().idle_secs, |timeout| timeout.idle_secs);
    SseLimits {
        max_event_bytes,
        max_chunk_bytes: max_event_bytes,
        idle_timeout: if idle_secs == 0 {
            max_lifetime
        } else {
            Duration::from_secs(idle_secs)
        },
        max_lifetime,
    }
}

/// What the request path established about the call, for the checks on each
/// event.
pub(super) struct StreamRequest {
    pub channel_name: String,
    pub trace_id: String,
    pub http_method: String,
    pub path: String,
    pub status: StatusCode,
    pub authenticated_identity: Option<crate::source_auth::AuthenticatedIdentity>,
    /// The protected agent's identity resolved on the request path, used when
    /// an event's own claim cannot be resolved.
    pub request_identity: Option<ProtectedAgentIdentity>,
    pub request_agent_did: Option<String>,
    pub request_user_hash: Option<String>,
    pub policy_caller: CallerContext,
}

pub(super) struct AccessPointEvents {
    state: ProxyState,
    request: StreamRequest,
    /// The last protected identity resolved in this stream.
    protected_identity: Option<ProtectedAgentIdentity>,
    external_resolved: bool,
    delivered_result: bool,
    recorded_dids: HashSet<String>,
    policy_allow_recorded: bool,
}

impl AccessPointEvents {
    pub(super) fn new(
        state: ProxyState,
        request: StreamRequest,
    ) -> Self {
        Self {
            state,
            request,
            protected_identity: None,
            external_resolved: false,
            delivered_result: false,
            recorded_dids: HashSet::new(),
            policy_allow_recorded: false,
        }
    }

    fn protocol(&self) -> String {
        format!(
            "{:?}",
            self.state
                .surface
                .channel_protocol()
        )
        .to_lowercase()
    }

    async fn resolve_protected_identity(
        &mut self,
        body: &bytes::Bytes,
        claims_identity: bool,
    ) -> Result<ProtectedAgentIdentity, StreamStop> {
        let reads_body =
            crate::proxy::backend_identity::slot_reads_response_body(&self.state.surface, IdentitySlot::Protected);
        if reads_body && !claims_identity {
            return Ok(ProtectedAgentIdentity::Anonymous);
        }
        if !reads_body && let Some(identity) = &self.protected_identity {
            return Ok(identity.clone());
        }
        let state = &self.state;
        let identity = match crate::proxy::backend_identity::resolve_protected_agent_identity(
            body,
            &state.surface,
            state
                .protected_selector
                .as_ref()
                .or(state
                    .identity_selector
                    .as_ref()),
            state
                .protected_rules_engine
                .as_ref()
                .or(state
                    .identity_rules_engine
                    .as_ref()),
            &self.request.channel_name,
            IdentityResponseKind::Message,
            self.request
                .authenticated_identity
                .as_ref(),
        )
        .await
        {
            Ok(identity) => identity,
            Err(error) => match &self.request.request_identity {
                Some(identity) => {
                    info!(
                        channel = self.request.channel_name,
                        "Stream event identity unresolved, using request-path identity"
                    );
                    identity.clone()
                }
                None => {
                    warn!(
                        channel = self.request.channel_name,
                        %error,
                        code = error.code(),
                        "Protected agent identity resolution failed on a stream event"
                    );
                    return Err(StreamStop::new(error.code(), "Protected agent identity resolution failed"));
                }
            },
        };
        self.protected_identity = Some(identity.clone());
        if let ProtectedAgentIdentity::Managed { did, .. } = &identity
            && self
                .recorded_dids
                .insert(did.clone())
        {
            crate::trust_registry_verification::spawn_trust_recorder(
                &self.state.surface,
                did,
                self.state
                    .trust_registry_listener_manager
                    .clone(),
            );
        }
        Ok(identity)
    }

    async fn resolve_external_identity(
        &mut self,
        body: &bytes::Bytes,
        claims_identity: bool,
    ) -> Result<(), StreamStop> {
        let state = &self.state;
        if state
            .external_selector
            .is_none()
        {
            return Ok(());
        }
        let reads_body =
            crate::proxy::backend_identity::slot_reads_response_body(&state.surface, IdentitySlot::External);
        if (reads_body && !claims_identity) || (!reads_body && self.external_resolved) {
            return Ok(());
        }
        if let Err(error) = crate::proxy::backend_identity::resolve_external_agent_identity(
            body,
            &state.surface,
            state
                .external_selector
                .as_ref(),
            state
                .external_rules_engine
                .as_ref(),
            &self.request.channel_name,
            IdentityResponseKind::Message,
            self.request
                .authenticated_identity
                .as_ref(),
        )
        .await
        {
            warn!(
                channel = self.request.channel_name,
                %error,
                code = error.code(),
                "External agent identity resolution failed on a stream event"
            );
            return Err(StreamStop::new(error.code(), "External agent identity resolution failed"));
        }
        self.external_resolved = true;
        Ok(())
    }

    async fn inject_custom_metadata(
        &self,
        body: bytes::Bytes,
    ) -> bytes::Bytes {
        let Some(custom_metadata) = self
            .state
            .surface
            .response_custom_metadata()
            .filter(|custom_metadata| custom_metadata.enabled)
        else {
            return body;
        };
        match crate::a2a::inject_custom_metadata_extension(
            &body,
            custom_metadata,
            &self.request.channel_name,
            &self.state.secrets_store,
            crate::protocols::MetadataRuntimeContext {
                request_id: Some(self.request.trace_id.as_str()),
                surface_id: Some(
                    self.state
                        .surface
                        .surface_id
                        .as_str(),
                ),
            },
        )
        .await
        {
            Ok(body) => body,
            Err(error) => {
                warn!(
                    channel = self.request.channel_name,
                    %error,
                    "Failed to inject response custom metadata into a stream event, forwarding it unchanged"
                );
                body
            }
        }
    }

    async fn inject_identity_credential(
        &self,
        body: bytes::Bytes,
        identity: &ProtectedAgentIdentity,
    ) -> bytes::Bytes {
        let ProtectedAgentIdentity::Managed { did, identity_fields } = identity else {
            return body;
        };
        let Some(selector) = self
            .state
            .identity_selector
            .as_ref()
        else {
            debug!(channel = self.request.channel_name, "No identity selector available, skipping stream event VP");
            return body;
        };
        let workload_binding = super::build_response_workload_binding(
            identity_fields,
            self.request
                .request_agent_did
                .as_deref(),
            &self.request.trace_id,
        );
        match crate::a2a::inject_identity_credential_into_response(
            &body,
            did,
            identity_fields,
            workload_binding,
            &selector.get_vc_issuer(),
            &self.request.channel_name,
        )
        .await
        {
            Ok(None) => body,
            Ok(Some((body, vp_jwt))) => {
                info!(channel = self.request.channel_name, did = %did, "Identity credential VP injected into a stream event");
                let protocol = self.protocol();
                crate::delegation_vault::audit::emit("vp_injected", || {
                    crate::delegation_vault::audit::vp_injected_event(crate::delegation_vault::audit::VpInjection {
                        agent_did: Some(did.as_str()),
                        user_hash: self
                            .request
                            .request_user_hash
                            .as_deref(),
                        surface_id: Some(
                            self.state
                                .surface
                                .surface_id
                                .as_str(),
                        ),
                        channel_name: &self.request.channel_name,
                        target_endpoint: &self
                            .state
                            .surface
                            .target
                            .endpoint,
                        protocol: &protocol,
                        mcp_tool_name: None,
                        vp_jwt: &vp_jwt,
                        trace_id: Some(&self.request.trace_id),
                        detail: "response_path".to_string(),
                        caller: self
                            .request
                            .authenticated_identity
                            .as_ref()
                            .map(crate::delegation_vault::audit::build_caller_context),
                        via_fabric: false,
                    })
                });
                body
            }
            Err(error) => {
                warn!(
                    channel = self.request.channel_name,
                    %error,
                    "Failed to inject identity credential VP into a stream event, forwarding it unchanged"
                );
                body
            }
        }
    }

    async fn inspect_extensions(
        &self,
        body: &bytes::Bytes,
    ) -> Result<(), StreamStop> {
        let state = &self.state;
        if !state
            .config
            .extension_inspection
            .enabled
            || state
                .identity_rules_engine
                .is_none()
        {
            return Ok(());
        }
        let context = crate::protocols::extensions::ResponseExtensionInspectionContext {
            config: &state.config,
            channel_name: &self.request.channel_name,
            surface: &state.surface,
            response_rules_engine: &state.identity_rules_engine,
            metrics_store: &state.metrics_store,
        };
        crate::protocols::extensions::inspect_response_extensions(body, &context)
            .await
            .map_err(|_| {
                warn!(channel = self.request.channel_name, "Response extension validation failed on a stream event");
                EXTENSIONS_REJECTED
            })
    }

    async fn record_response_policy_decision(
        &self,
        policy_id: &str,
        policy_manager: &crate::policies::SurfacePolicyManager,
        decision: crate::proxy::response_policy::ResponsePolicyDecision,
    ) {
        let attestation = policy_manager
            .resolve_policy_attestation(Some(policy_id))
            .await;
        crate::observability::record_policy_decision(crate::observability::PolicyDecisionEvent {
            scope: crate::observability::PolicyScope::Response,
            allow: decision.allow,
            reason: decision.reason.as_deref(),
            error: decision.error,
            policy_id: Some(policy_id),
            policy_definition_id: Some(policy_id),
            policy_name: attestation.name.as_deref(),
            policy_version: attestation.version,
            policy_content_hash: attestation
                .content_hash
                .as_deref(),
            surface_id: Some(
                self.state
                    .surface
                    .surface_id
                    .as_str(),
            ),
            trace_id: Some(&self.request.trace_id),
            http_method: Some(&self.request.http_method),
            path: Some(&self.request.path),
            identity: self
                .request
                .authenticated_identity
                .as_ref(),
            actor_did: self
                .request
                .request_agent_did
                .as_deref(),
            ..Default::default()
        });
    }
}

fn to_body(event: &Value) -> bytes::Bytes {
    bytes::Bytes::from(event.to_string())
}

fn from_body(body: &[u8]) -> Result<Value, StreamStop> {
    serde_json::from_slice(body)
        .map_err(|_| StreamStop::new("stream_event_rewrite_failed", "Stream event could not be processed"))
}

impl EventProcessor for AccessPointEvents {
    async fn rewrite(
        &mut self,
        mut event: Value,
    ) -> Result<Value, StreamStop> {
        let body = if event
            .get("result")
            .is_some_and(|result| !result.is_null())
        {
            self.delivered_result = true;
            let claims_identity = crate::a2a::response_claims_identity(&mut event);
            let body = to_body(&event);
            let identity = self
                .resolve_protected_identity(&body, claims_identity)
                .await?;
            self.resolve_external_identity(&body, claims_identity)
                .await?;
            let body = self
                .inject_custom_metadata(body)
                .await;
            if claims_identity {
                self.inject_identity_credential(body, &identity)
                    .await
            } else {
                body
            }
        } else {
            to_body(&event)
        };
        self.inspect_extensions(&body)
            .await?;
        from_body(&body)
    }

    async fn admit(
        &mut self,
        event: &Value,
    ) -> Result<(), StreamStop> {
        let state = &self.state;
        let (Some(policy_id), Some(policy_manager)) = (
            state
                .surface
                .response_policy_definition_id(),
            state.policy_manager.as_ref(),
        ) else {
            return Ok(());
        };
        let input = ResponsePolicyInput {
            response: ResponseContext {
                status_code: self.request.status.as_u16(),
                body: Some(event.clone()),
                content_type: Some(mime::TEXT_EVENT_STREAM.to_string()),
                is_error: self
                    .request
                    .status
                    .is_client_error()
                    || self
                        .request
                        .status
                        .is_server_error()
                    || event
                        .get("error")
                        .is_some_and(|error| !error.is_null()),
                method: None,
            },
            caller: self
                .request
                .policy_caller
                .clone(),
            surface: SurfaceContext {
                id: state
                    .surface
                    .surface_id
                    .clone(),
                name: self
                    .request
                    .channel_name
                    .clone(),
                protocol: self.protocol(),
            },
            metadata: None,
        };
        let decision = crate::proxy::response_policy::evaluate_response_policy(
            policy_manager,
            &format!("response:{policy_id}"),
            input,
        );
        if !decision.allow {
            self.record_response_policy_decision(policy_id, policy_manager, decision)
                .await;
            return Err(RESPONSE_BLOCKED);
        }
        if !self.policy_allow_recorded {
            self.record_response_policy_decision(policy_id, policy_manager, decision)
                .await;
            self.policy_allow_recorded = true;
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<(), StreamStop> {
        if !self.delivered_result {
            return Ok(());
        }
        let surface = &self.state.surface;
        if crate::proxy::backend_identity::slot_reads_response_body(surface, IdentitySlot::Protected)
            && self
                .request
                .request_identity
                .is_none()
            && self
                .protected_identity
                .is_none()
        {
            warn!(channel = self.request.channel_name, "A2A event stream ended without the protected agent's identity");
            return Err(StreamStop::new(
                crate::a2a::ERR_IDENTITY_EXTENSION_MISSING,
                "Stream ended without the protected agent's identity",
            ));
        }
        if self
            .state
            .external_selector
            .is_some()
            && crate::proxy::backend_identity::slot_reads_response_body(surface, IdentitySlot::External)
            && !self.external_resolved
        {
            warn!(channel = self.request.channel_name, "A2A event stream ended without the external agent's identity");
            return Err(StreamStop::new(
                crate::a2a::ERR_IDENTITY_EXTENSION_MISSING,
                "Stream ended without the external agent's identity",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a2a(
        max_body_size: usize,
        stream_max_lifetime_secs: u64,
    ) -> crate::config::A2aConfig {
        crate::config::A2aConfig {
            max_body_size,
            stream_max_lifetime_secs,
            ..Default::default()
        }
    }

    fn timeout(idle_secs: u64) -> crate::config::TimeoutConfig {
        crate::config::TimeoutConfig {
            idle_secs,
            ..Default::default()
        }
    }

    #[test]
    fn stream_limits_follow_the_body_cap_the_idle_timeout_and_the_lifetime() {
        let limits = stream_limits(&a2a(4096, 600), Some(&timeout(45)));
        assert_eq!(limits.max_event_bytes.get(), 4096);
        assert_eq!(limits.max_chunk_bytes.get(), 4096);
        assert_eq!(limits.idle_timeout, Duration::from_secs(45));
        assert_eq!(limits.max_lifetime, Duration::from_secs(600));
    }

    #[test]
    fn stream_limits_default_the_idle_timeout_and_let_zero_leave_only_the_lifetime() {
        let unset = stream_limits(&a2a(4096, 600), None);
        assert_eq!(unset.idle_timeout, Duration::from_secs(crate::config::TimeoutConfig::default().idle_secs));

        let disabled = stream_limits(&a2a(4096, 600), Some(&timeout(0)));
        assert_eq!(disabled.idle_timeout, Duration::from_secs(600));
    }

    #[test]
    fn a_zero_body_cap_admits_no_event() {
        assert_eq!(
            stream_limits(&a2a(0, 600), None)
                .max_event_bytes
                .get(),
            1
        );
    }
}
