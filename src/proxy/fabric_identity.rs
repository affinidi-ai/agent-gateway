//! Fabric-specific backend identity verification
//!
//! This module handles VP verification for multi-gateway (fabric) responses.
//! For single-gateway flows, see backend_identity.rs instead.
//!
//! Key differences from single-gateway mode:
//! - GW2 sends VPs instead of raw identity
//! - Cryptographic verification of VP signatures
//! - Stricter security model (reject invalid VPs)

use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// A response presentation that verified, before its issuer is checked against
/// the connection's issuers by [`attribute_response_presentation`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResponsePresentation {
    pub agent_did: String,
    pub issuer_did: String,
    pub vp_jwt: String,
    pub identity_fields: HashMap<String, JsonValue>,
}

/// Whether the connection's issuers vouch for a response presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAttribution {
    /// The issuer is one of the connection's issuers; the DID is stored as verified.
    Verified,
    /// The issuer is not one of them; the answer is refused.
    Untrusted,
}

/// Why the calling gateway refuses a fabric answer's identity presentation.
/// The refusal is already recorded in the VP Audit Log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerIdentityRefusal {
    /// The presentation failed verification, with the diagnostic.
    Invalid(String),
    /// No issuer of the connection vouches for the presentation.
    Untrusted,
}

impl AnswerIdentityRefusal {
    /// The detail of the `502` the caller receives.
    pub fn detail(&self) -> String {
        match self {
            Self::Invalid(error) => format!("Backend agent identity verification failed: {error}"),
            Self::Untrusted => {
                "Managed agent identity verification failed: issuer is not trusted on this connection".to_string()
            }
        }
    }
}

/// A fabric answer whose identity presentation the calling gateway checks.
pub struct AnswerIdentityCheck<'a> {
    pub response_body: &'a str,
    pub surface: &'a crate::config::agent_surface::AgentSurface,
    pub identity_selector: &'a Option<Arc<crate::identity::IdentitySelector>>,
    pub listener_manager: Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
    /// The Remote gateway record the `fabric://` Target names.
    pub gateway_id: &'a str,
    pub facts: &'a crate::audit::request_events::RequestFacts<'a>,
    /// The request's authenticated caller.
    pub caller: Option<crate::delegation_vault::audit::AuditCallerContext>,
}

/// Verify the identity presentation on a fabric answer, check its issuer
/// against the connection's issuers and record the outcome in the VP Audit
/// Log. `Ok(None)` when the answer carries no presentation; a refusal is
/// recorded before it is returned.
pub async fn check_answer_identity(
    check: AnswerIdentityCheck<'_>
) -> Result<Option<ResponsePresentation>, AnswerIdentityRefusal> {
    let presentation = match extract_fabric_backend_agent_identity(
        check.response_body,
        check.surface,
        check.identity_selector,
        check.facts.channel_name,
    )
    .await
    {
        Ok(Some(presentation)) => presentation,
        Ok(None) => return Ok(None),
        Err(error) => {
            record_invalid_response_presentation(check.facts, &error);
            return Err(AnswerIdentityRefusal::Invalid(error));
        }
    };
    match record_response_presentation(
        &presentation,
        check.listener_manager,
        check.gateway_id,
        check.identity_selector,
        check.surface,
        check.facts,
        check.caller,
    )
    .await
    {
        ResponseAttribution::Verified => Ok(Some(presentation)),
        ResponseAttribution::Untrusted => Err(AnswerIdentityRefusal::Untrusted),
    }
}

/// Whether a verified answer presentation is the answering agent's protected
/// identity: only when that identity is taken from the agent's payload, which
/// the paired gateway replaced with its presentation. A slot that derives the
/// identity from a key, a token claim or a fixed value keeps it.
pub fn presentation_sets_identity(managed_identity: Option<&crate::source_auth::ManagedIdentityConfig>) -> bool {
    matches!(managed_identity, Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(_)))
}

/// Extract and verify the identity presentation a paired gateway attached to
/// a fabric answer.
///
/// - A presentation that fails verification, whose holder is not its
///   credential's subject, or that carries no credential is an error: the
///   caller refuses the response.
/// - `Ok(None)` when the answer carries no presentation; a raw identity
///   extension is left to protected identity resolution.
pub async fn extract_fabric_backend_agent_identity(
    response_body: &str,
    surface: &crate::config::agent_surface::AgentSurface,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
) -> Result<Option<ResponsePresentation>, String> {
    info!(channel = channel_name, "Fabric: Checking for backend agent identity in response");

    if response_body.is_empty() {
        debug!(channel = channel_name, "Fabric: Response body is empty");
        return Ok(None);
    }

    // Parse response
    let response_json = match serde_json::from_str::<JsonValue>(response_body) {
        Ok(json) => {
            info!(channel = channel_name, "Fabric: Successfully parsed response as JSON");
            json
        }
        Err(_) => {
            debug!(channel = channel_name, "Fabric: Response is not JSON");
            return Ok(None);
        }
    };

    // Dispatch to protocol-specific extractor
    match surface.access_point.protocol {
        crate::config::agent_surface::SurfaceProtocol::A2a | crate::config::agent_surface::SurfaceProtocol::Ap2 => {
            extract_a2a_fabric_identity(&response_json, response_identity_selector, channel_name).await
        }
        crate::config::agent_surface::SurfaceProtocol::Mcp => {
            // MCP not yet implemented for fabric VP verification
            debug!(channel = channel_name, "Fabric: MCP VP verification not yet implemented");
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Find the credential extension on the agent's message, where GW2 places it
/// (see `backend_identity::extract_a2a_identity_from_response_message_with_uri`),
/// and verify its presentation. Artifacts are not read: GW2 never puts a
/// credential there.
async fn extract_a2a_fabric_identity(
    response_json: &JsonValue,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
) -> Result<Option<ResponsePresentation>, String> {
    use crate::proxy::backend_identity::{
        IdentityExtractionError, extract_a2a_identity_from_response_message_with_uri,
    };

    match extract_a2a_identity_from_response_message_with_uri(
        response_json,
        crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
    ) {
        Ok(credential_ext) => {
            info!(channel = channel_name, "Fabric: Found VP credential extension from GW2");
            verify_fabric_credential(&credential_ext, response_identity_selector, channel_name).await
        }
        Err(IdentityExtractionError::DeclaredButMissing) => {
            warn!(channel = channel_name, "Fabric: VP credential extension declared but not found in metadata");
            Ok(None)
        }
        Err(e) => {
            debug!(channel = channel_name, reason = %e, "Fabric: No VP credential extension in response");
            Ok(None)
        }
    }
}

/// Verify the VP carried by GW2's credential extension. Rejects a credential
/// that carries no `verifiablePresentation`, whose VP fails verification
/// (including a holder that is not its credential's subject), or whose VP
/// carries no credential to name an issuer.
async fn verify_fabric_credential(
    credential_ext: &JsonValue,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
) -> Result<Option<ResponsePresentation>, String> {
    let Some(vp_jwt) = credential_ext
        .get("verifiablePresentation")
        .and_then(|v| v.as_str())
    else {
        if credential_ext
            .get("verifiablePresentation")
            .is_none()
        {
            let error_msg = "VP credential extension present but missing verifiablePresentation field".to_string();
            warn!(channel = channel_name, "{}", error_msg);
            return Err(error_msg);
        }
        return Ok(None);
    };

    let Some(selector) = response_identity_selector else {
        warn!(channel = channel_name, "Fabric: No response identity selector available for VP verification");
        return Ok(None);
    };
    let verified = selector
        .get_vc_issuer()
        .verify_agent_presentation_full(vp_jwt)
        .await
        .map_err(|e| {
            warn!(channel = channel_name, error = %format!("{e:#}"), "✗ Fabric: VP verification FAILED");
            format!("VP verification failed for server agent identity: {e}")
        })?;
    let Some(issuer_did) = verified.issuer_did else {
        warn!(channel = channel_name, "✗ Fabric: response VP carries no credential");
        return Err("VP verification failed for server agent identity: presentation carries no credential".into());
    };

    info!(
        channel = channel_name,
        did = %verified.holder_did,
        "✓ Fabric: VP verification succeeded for server DID"
    );
    Ok(Some(ResponsePresentation {
        agent_did: verified.holder_did,
        issuer_did,
        vp_jwt: vp_jwt.to_string(),
        identity_fields: verified.identity_fields,
    }))
}

/// Check `presentation`'s issuer against `peer_issuers`, the issuers of the
/// connection the answer came over, and store the answering agent's DID as
/// verified when one of them issued it.
pub async fn attribute_response_presentation(
    presentation: &ResponsePresentation,
    peer_issuers: &crate::gateways::types::PeerIssuers,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_name: &str,
) -> ResponseAttribution {
    use crate::protocols::extensions::{BindingIssuerDecision, evaluate_binding_issuer_trust};

    if evaluate_binding_issuer_trust(&presentation.issuer_did, Some(peer_issuers)) != BindingIssuerDecision::Trusted {
        warn!(
            channel = channel_name,
            agent_did = %presentation.agent_did,
            issuer = %presentation.issuer_did,
            "Fabric: response VP issuer is not one of the connection's issuers; the answer is refused"
        );
        return ResponseAttribution::Untrusted;
    }

    if let Some(selector) = response_identity_selector
        && let Err(e) = selector
            .get_vc_issuer()
            .get_identity_store()
            .store_external_did(
                &presentation.agent_did,
                presentation
                    .identity_fields
                    .clone(),
                Some(surface.surface_id.clone()),
                true,
            )
            .await
    {
        warn!(channel = channel_name, error = %e, "Fabric: Failed to store verified server DID");
    }
    ResponseAttribution::Verified
}

/// Attribute a response presentation that came over the connection to the
/// Remote gateway `gateway_id` and record the outcome in the VP Audit Log:
/// `identity_binding_verified` and the received presentation (`vp_injected`)
/// when the connection's issuers vouch for it, `identity_binding_failed`
/// (`untrusted`) otherwise. Issuers that cannot be resolved vouch for nothing.
/// The received presentation names `caller`, the request's authenticated caller.
pub async fn record_response_presentation(
    presentation: &ResponsePresentation,
    listener_manager: Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
    gateway_id: &str,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    surface: &crate::config::agent_surface::AgentSurface,
    facts: &crate::audit::request_events::RequestFacts<'_>,
    caller: Option<crate::delegation_vault::audit::AuditCallerContext>,
) -> ResponseAttribution {
    let peer_issuers = match listener_manager {
        Some(manager) => manager
            .peer_issuers_vouching_for(gateway_id, &presentation.issuer_did)
            .await
            .unwrap_or_else(|reason| {
                warn!(channel = facts.channel_name, gateway_id, %reason, "Fabric: issuers of the answering gateway unknown");
                crate::gateways::types::PeerIssuers::default()
            }),
        None => crate::gateways::types::PeerIssuers::default(),
    };
    let attribution = attribute_response_presentation(
        presentation,
        &peer_issuers,
        response_identity_selector,
        surface,
        facts.channel_name,
    )
    .await;

    match attribution {
        ResponseAttribution::Verified => {
            crate::audit::request_events::identity_binding_verified(
                facts,
                &presentation.agent_did,
                Some(&presentation.issuer_did),
                None,
            );
            crate::delegation_vault::audit::emit("vp_injected", || {
                crate::delegation_vault::audit::vp_injected_event(crate::delegation_vault::audit::VpInjection {
                    agent_did: Some(&presentation.agent_did),
                    user_hash: None,
                    surface_id: surface.config_id(),
                    channel_name: &surface.name,
                    target_endpoint: &surface.target.endpoint,
                    protocol: &format!("{:?}", surface.channel_protocol()).to_lowercase(),
                    mcp_tool_name: None,
                    vp_jwt: &presentation.vp_jwt,
                    trace_id: facts.trace_id,
                    detail: RESPONSE_PRESENTATION_DETAIL.to_string(),
                    caller,
                    via_fabric: true,
                })
            });
        }
        ResponseAttribution::Untrusted => crate::audit::request_events::identity_binding_failed(
            facts,
            crate::audit::events::IdentityBindingFailure::Untrusted,
            Some(&presentation.agent_did),
            Some(&presentation.issuer_did),
            None,
        ),
    }
    attribution
}

/// Record a response presentation that failed verification as
/// `identity_binding_failed` (`invalid`), with `error` as its diagnostic.
pub fn record_invalid_response_presentation(
    facts: &crate::audit::request_events::RequestFacts<'_>,
    error: &str,
) {
    crate::audit::request_events::identity_binding_failed(
        facts,
        crate::audit::events::IdentityBindingFailure::Invalid,
        None,
        None,
        Some(error),
    );
}

/// The `vp_injected` detail of a presentation received on a fabric answer.
pub const RESPONSE_PRESENTATION_DETAIL: &str = "response_path_fabric_received";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const IDENTITY_URI: &str = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    const CREDENTIAL_URI: &str = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;

    fn surface() -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json!({
            "name": "a-party",
            "access_point": { "listen_address": "http://localhost:8700", "route": "/agents/a", "protocol": "a2a" },
            "target": { "endpoint": "fabric://gw-2/b-party" }
        }))
        .expect("surface JSON")
    }

    fn agent_message(
        uri: &str,
        payload: JsonValue,
    ) -> JsonValue {
        json!({
            "role": "ROLE_AGENT",
            "parts": [{ "text": "done" }],
            "extensions": [uri],
            "metadata": { uri: payload }
        })
    }

    fn caller_message() -> JsonValue {
        json!({
            "role": "ROLE_USER",
            "parts": [{ "text": "hello" }],
            "extensions": [IDENTITY_URI],
            "metadata": { IDENTITY_URI: { "did": "did:web:caller" } }
        })
    }

    fn v1_task(status_message: JsonValue) -> JsonValue {
        json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": { "task": {
                "id": "t",
                "status": { "state": "TASK_STATE_COMPLETED", "message": status_message },
                "history": [caller_message()]
            } }
        })
    }

    async fn extract(
        response: &JsonValue,
        selector: &Option<Arc<crate::identity::IdentitySelector>>,
    ) -> Result<Option<ResponsePresentation>, String> {
        extract_a2a_fabric_identity(response, selector, "a-party").await
    }

    fn caller() -> crate::delegation_vault::audit::AuditCallerContext {
        serde_json::from_value(json!({ "auth_method": "api_key", "sub": "caller-a" })).expect("caller context")
    }

    fn selector_for(issuer: Arc<crate::identity::VCIssuer>) -> Option<Arc<crate::identity::IdentitySelector>> {
        Some(Arc::new(crate::identity::IdentitySelector::new(&json!({}), issuer).expect("selector")))
    }

    fn credential_response(presentation: &JsonValue) -> JsonValue {
        v1_task(agent_message(CREDENTIAL_URI, json!({ "verifiablePresentation": presentation.to_string() })))
    }

    fn issuers(attested: &str) -> crate::gateways::types::PeerIssuers {
        crate::gateways::types::PeerIssuers {
            attested: Some(attested.to_string()),
            trusted: Vec::new(),
        }
    }

    async fn presented(
        response: &JsonValue,
        selector: &Option<Arc<crate::identity::IdentitySelector>>,
    ) -> ResponsePresentation {
        match extract(response, selector).await {
            Ok(Some(presentation)) => presentation,
            other => panic!("expected a verified presentation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_verified_presentation_names_its_holder_and_issuer_and_keeps_the_vp() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());

        let presentation = presented(&credential_response(&signed.presentation), &selector).await;

        assert_eq!(presentation.agent_did, signed.holder_did);
        assert_eq!(presentation.issuer_did, signed.issuer_did);
        assert_eq!(
            presentation.vp_jwt,
            signed
                .presentation
                .to_string()
        );
    }

    #[tokio::test]
    async fn a_presentation_whose_holder_is_not_its_credential_subject_is_rejected() {
        let signed =
            crate::identity::test_helpers::signed_agent_presentation_for_another_subject("did:web:someone-else").await;
        let selector = selector_for(signed.issuer.clone());

        match extract(&credential_response(&signed.presentation), &selector).await {
            Err(message) => assert!(
                message.starts_with("VP verification failed for server agent identity"),
                "unexpected error: {message}"
            ),
            other => panic!("expected the presentation to be rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_presentation_from_a_connection_issuer_is_attributed_and_stored_as_verified() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let presentation = presented(&credential_response(&signed.presentation), &selector).await;

        let attribution = attribute_response_presentation(
            &presentation,
            &issuers(&signed.issuer_did),
            &selector,
            &surface(),
            "a-party",
        )
        .await;

        assert_eq!(attribution, ResponseAttribution::Verified);
        let stored = signed
            .issuer
            .get_identity_store()
            .find_by_did(&signed.holder_did)
            .await
            .unwrap();
        assert!(stored.is_some(), "the answering agent's DID is stored");
    }

    #[tokio::test]
    async fn a_presentation_from_another_issuer_is_untrusted_and_not_stored() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let presentation = presented(&credential_response(&signed.presentation), &selector).await;

        let attribution =
            attribute_response_presentation(&presentation, &issuers("did:web:other"), &selector, &surface(), "a-party")
                .await;

        assert_eq!(attribution, ResponseAttribution::Untrusted);
        let stored = signed
            .issuer
            .get_identity_store()
            .find_by_did(&signed.holder_did)
            .await
            .unwrap();
        assert!(stored.is_none(), "an untrusted presentation stores no identity");
    }

    #[tokio::test]
    async fn a_connection_without_issuers_vouches_for_no_presentation() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let presentation = presented(&credential_response(&signed.presentation), &selector).await;

        let attribution = attribute_response_presentation(
            &presentation,
            &crate::gateways::types::PeerIssuers::default(),
            &selector,
            &surface(),
            "a-party",
        )
        .await;

        assert_eq!(attribution, ResponseAttribution::Untrusted);
    }

    fn facts() -> crate::audit::request_events::RequestFacts<'static> {
        crate::audit::request_events::RequestFacts {
            surface_id: "a-surface",
            channel_name: "a-party",
            trace_id: Some("trace-a"),
            via_fabric: true,
        }
    }

    /// A listener manager whose gateway store holds one Remote gateway with
    /// `issuer_did` established, returned with that gateway's id.
    async fn manager_with_peer(
        root: &std::path::Path,
        issuer_did: &str,
    ) -> (Arc<crate::gateways::ConnectionPointListenerManager>, String, tempfile::TempDir) {
        use crate::gateways::GatewayStore;
        let mut peer = crate::gateways::types::Gateway::new(
            "GW-B".into(),
            String::new(),
            "did:example:gw-b".into(),
            crate::gateways::types::GatewayType::Remote,
        );
        peer.issuer_did = Some(issuer_did.to_string());
        let store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(root.join("gateways"), Some("did:web:gw-a.example".into()))
                .await
                .unwrap(),
        );
        store
            .create(&peer)
            .await
            .unwrap();
        let (manager, issuer_dir) = crate::gateways::test_helpers::test_listener_manager(root).await;
        (Arc::new(manager.with_gateway_store(store)), peer.id, issuer_dir)
    }

    #[tokio::test]
    async fn a_presentation_from_the_answering_gateways_issuer_is_recorded_as_verified_and_received() {
        use crate::delegation_vault::audit::DelegationAuditAction;
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let presentation = presented(&credential_response(&signed.presentation), &selector).await;
        let root = tempfile::tempdir().unwrap();
        let (manager, gateway_id, _issuer_dir) = manager_with_peer(root.path(), &signed.issuer_did).await;

        let (attribution, events) = crate::audit::producer::capture(record_response_presentation(
            &presentation,
            Some(manager),
            &gateway_id,
            &selector,
            &surface(),
            &facts(),
            Some(caller()),
        ))
        .await;

        assert_eq!(attribution, ResponseAttribution::Verified);
        assert_eq!(events.len(), 2, "{events:?}");
        match &events[0].event {
            DelegationAuditAction::IdentityBindingVerified { agent_did, issuer_gateway, .. } => {
                assert_eq!(agent_did, &signed.holder_did);
                assert_eq!(issuer_gateway.as_deref(), Some(signed.issuer_did.as_str()));
            }
            other => panic!("expected IdentityBindingVerified, got {other:?}"),
        }
        assert!(matches!(events[1].event, DelegationAuditAction::VpInjected), "{:?}", events[1].event);
        assert_eq!(
            events[1]
                .agent_identity_did
                .as_deref(),
            Some(signed.holder_did.as_str())
        );
        assert_eq!(
            events[1].vp_jwt.as_deref(),
            Some(
                signed
                    .presentation
                    .to_string()
                    .as_str()
            )
        );
        assert_eq!(events[1].detail.as_deref(), Some(RESPONSE_PRESENTATION_DETAIL));
        let recorded_caller = events[1]
            .caller
            .as_ref()
            .expect("the received presentation names the request's caller");
        assert_eq!(recorded_caller.auth_method, "api_key");
        assert_eq!(recorded_caller.sub.as_deref(), Some("caller-a"));
        for event in &events {
            assert!(event.via_fabric);
            assert_eq!(event.trace_id.as_deref(), Some("trace-a"));
        }
    }

    #[tokio::test]
    async fn a_presentation_from_another_issuer_is_recorded_as_an_untrusted_identity_binding_only() {
        use crate::delegation_vault::audit::DelegationAuditAction;
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let presentation = presented(&credential_response(&signed.presentation), &selector).await;
        let root = tempfile::tempdir().unwrap();
        let (manager, gateway_id, _issuer_dir) = manager_with_peer(root.path(), "did:web:not-the-issuer").await;

        let (attribution, events) = crate::audit::producer::capture(record_response_presentation(
            &presentation,
            Some(manager),
            &gateway_id,
            &selector,
            &surface(),
            &facts(),
            Some(caller()),
        ))
        .await;

        assert_eq!(attribution, ResponseAttribution::Untrusted);
        assert_eq!(events.len(), 1, "{events:?}");
        match &events[0].event {
            DelegationAuditAction::IdentityBindingFailed {
                outcome,
                agent_did,
                issuer_gateway,
                ..
            } => {
                assert_eq!(*outcome, crate::audit::events::IdentityBindingFailure::Untrusted);
                assert_eq!(agent_did.as_deref(), Some(signed.holder_did.as_str()));
                assert_eq!(issuer_gateway.as_deref(), Some(signed.issuer_did.as_str()));
            }
            other => panic!("expected IdentityBindingFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn without_a_fabric_listener_manager_no_issuer_vouches_for_the_answer() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let presentation = presented(&credential_response(&signed.presentation), &selector).await;

        let (attribution, _events) = crate::audit::producer::capture(record_response_presentation(
            &presentation,
            None,
            "gw-b",
            &selector,
            &surface(),
            &facts(),
            None,
        ))
        .await;

        assert_eq!(attribution, ResponseAttribution::Untrusted);
    }

    #[tokio::test]
    async fn a_presentation_that_fails_verification_is_recorded_as_an_invalid_identity_binding() {
        use crate::delegation_vault::audit::DelegationAuditAction;

        let ((), events) = crate::audit::producer::capture(async {
            record_invalid_response_presentation(&facts(), "VP verification failed for server agent identity");
        })
        .await;

        assert_eq!(events.len(), 1, "{events:?}");
        match &events[0].event {
            DelegationAuditAction::IdentityBindingFailed {
                outcome,
                agent_did,
                issuer_gateway,
                error_detail,
            } => {
                assert_eq!(*outcome, crate::audit::events::IdentityBindingFailure::Invalid);
                assert_eq!(agent_did.as_deref(), None);
                assert_eq!(issuer_gateway.as_deref(), None);
                assert_eq!(error_detail.as_deref(), Some("VP verification failed for server agent identity"));
            }
            other => panic!("expected IdentityBindingFailed, got {other:?}"),
        }
        assert!(events[0].via_fabric);
        assert_eq!(events[0].trace_id.as_deref(), Some("trace-a"));
    }

    async fn checked(
        response: &JsonValue,
        selector: &Option<Arc<crate::identity::IdentitySelector>>,
    ) -> (
        Result<Option<ResponsePresentation>, AnswerIdentityRefusal>,
        Vec<crate::delegation_vault::audit::DelegationAuditEvent>,
    ) {
        let body = response.to_string();
        let surface = surface();
        let facts = facts();
        crate::audit::producer::capture(check_answer_identity(AnswerIdentityCheck {
            response_body: &body,
            surface: &surface,
            identity_selector: selector,
            listener_manager: None,
            gateway_id: "gw-b",
            facts: &facts,
            caller: None,
        }))
        .await
    }

    fn failed_outcome(
        events: &[crate::delegation_vault::audit::DelegationAuditEvent]
    ) -> Option<crate::audit::events::IdentityBindingFailure> {
        match events {
            [event] if event.via_fabric => match &event.event {
                crate::delegation_vault::audit::DelegationAuditAction::IdentityBindingFailed { outcome, .. } => {
                    Some(*outcome)
                }
                _ => None,
            },
            _ => None,
        }
    }

    #[tokio::test]
    async fn an_answer_with_a_tampered_presentation_is_refused_as_invalid_and_recorded() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());
        let mut tampered = signed.presentation.clone();
        tampered["holder"] = json!("did:web:someone-else");

        let (result, events) = checked(&credential_response(&tampered), &selector).await;

        assert!(matches!(result, Err(AnswerIdentityRefusal::Invalid(_))), "{result:?}");
        assert_eq!(failed_outcome(&events), Some(crate::audit::events::IdentityBindingFailure::Invalid));
    }

    #[tokio::test]
    async fn an_answer_whose_connection_issuers_cannot_be_established_is_refused_as_untrusted_and_recorded() {
        let signed = crate::identity::test_helpers::signed_agent_presentation().await;
        let selector = selector_for(signed.issuer.clone());

        let (result, events) = checked(&credential_response(&signed.presentation), &selector).await;

        assert_eq!(result, Err(AnswerIdentityRefusal::Untrusted));
        assert_eq!(failed_outcome(&events), Some(crate::audit::events::IdentityBindingFailure::Untrusted));
    }

    #[tokio::test]
    async fn an_answer_without_a_presentation_passes_the_check_unrecorded() {
        let response = v1_task(json!({ "role": "ROLE_AGENT", "parts": [{ "text": "done" }] }));

        let (result, events) = checked(&response, &None).await;

        assert_eq!(result, Ok(None));
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn only_a_payload_identity_is_taken_from_the_answer_presentation() {
        let payload: crate::source_auth::ManagedIdentityConfig = serde_json::from_value(json!({
            "type": "from_payload",
            "meta_field": "agentIdentity",
            "fields": ["agentIdentity.name"]
        }))
        .expect("payload identity");
        let from_api_key: crate::source_auth::ManagedIdentityConfig =
            serde_json::from_value(json!({ "type": "from_api_key", "api_key_id": "key-1" })).expect("API key identity");

        assert!(presentation_sets_identity(Some(&payload)));
        assert!(!presentation_sets_identity(Some(&from_api_key)));
        assert!(!presentation_sets_identity(None));
    }

    #[test]
    fn a_refused_answer_tells_the_caller_why() {
        assert_eq!(
            AnswerIdentityRefusal::Untrusted.detail(),
            "Managed agent identity verification failed: issuer is not trusted on this connection"
        );
        assert_eq!(
            AnswerIdentityRefusal::Invalid("bad signature".into()).detail(),
            "Backend agent identity verification failed: bad signature"
        );
    }

    #[tokio::test]
    async fn a_raw_identity_without_a_presentation_is_left_to_protected_identity_resolution() {
        let response = v1_task(agent_message(IDENTITY_URI, json!({ "did": "did:web:agent" })));

        assert_eq!(extract(&response, &None).await, Ok(None));
    }

    #[tokio::test]
    async fn an_answer_without_an_identity_carries_no_presentation() {
        let response = v1_task(json!({ "role": "ROLE_AGENT", "parts": [{ "text": "done" }] }));

        assert_eq!(extract(&response, &None).await, Ok(None));
    }

    #[tokio::test]
    async fn declared_credential_without_payload_yields_no_identity() {
        let response = v1_task(json!({
            "role": "ROLE_AGENT",
            "parts": [{ "text": "done" }],
            "extensions": [CREDENTIAL_URI],
            "metadata": {}
        }));

        assert_eq!(extract(&response, &None).await, Ok(None));
    }

    #[tokio::test]
    async fn credential_without_presentation_is_rejected() {
        let response = v1_task(agent_message(CREDENTIAL_URI, json!({ "did": "did:web:agent" })));

        match extract(&response, &None).await {
            Err(message) => assert!(message.contains("missing verifiablePresentation"), "unexpected error: {message}"),
            other => panic!("expected the credential to be rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unverifiable_credential_in_a_wrapped_v1_task_is_rejected() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let schema = json!({ "type": "object", "properties": { "name": { "type": "string", "x-identity": true } } });
        let selector = crate::identity::IdentitySelector::new(&schema, Arc::new(issuer)).expect("selector");
        let response = v1_task(agent_message(
            CREDENTIAL_URI,
            json!({ "verifiablePresentation": "not-a-presentation", "did": "did:web:agent" }),
        ));

        match extract(&response, &Some(Arc::new(selector))).await {
            Err(message) => assert!(message.contains("VP verification failed"), "unexpected error: {message}"),
            other => panic!("expected the credential to be rejected, got {other:?}"),
        }
    }

    fn v1_task_with_artifact(artifact: JsonValue) -> JsonValue {
        json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": { "task": {
                "id": "t",
                "status": { "state": "TASK_STATE_COMPLETED", "message": { "role": "ROLE_AGENT", "parts": [{ "text": "done" }] } },
                "artifacts": [artifact]
            } }
        })
    }

    #[tokio::test]
    async fn credential_only_in_an_artifact_is_ignored() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let schema = json!({ "type": "object", "properties": { "name": { "type": "string", "x-identity": true } } });
        let selector = crate::identity::IdentitySelector::new(&schema, Arc::new(issuer)).expect("selector");
        let response = v1_task_with_artifact(agent_message(
            CREDENTIAL_URI,
            json!({ "verifiablePresentation": "not-a-presentation", "did": "did:web:agent" }),
        ));

        // Had the artifact been read, the bad presentation would fail verification.
        assert_eq!(extract(&response, &Some(Arc::new(selector))).await, Ok(None));
    }
}
