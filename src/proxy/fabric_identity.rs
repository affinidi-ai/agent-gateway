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
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Extract and verify backend agent identity from fabric response
///
/// In multi-gateway flows, GW2 sends VPs instead of raw identity.
/// This function verifies the VP signature and extracts the server DID.
///
/// Enforcement Policy (Lenient):
/// - Accepts VP credential extension (preferred)
/// - Falls back to raw identity extension (backward compat)
/// - Rejects responses with invalid VP signatures
///
/// # Arguments
/// * `response_body` - The response body from GW2
/// * `channel` - Channel configuration
/// * `identity_selector` - Identity selector with VC issuer (for VP verification)
/// * `channel_name` - Channel name for logging
///
/// # Returns
/// * `Some(did)` - Verified backend agent DID
/// * `None` - No identity found (backward compat)
///
/// # Errors
/// Returns error string if VP verification fails
pub async fn extract_fabric_backend_agent_identity(
    response_body: &str,
    surface: &crate::config::agent_surface::AgentSurface,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    channel_name: &str,
) -> Result<Option<String>, String> {
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
            extract_a2a_fabric_identity(&response_json, response_identity_selector, surface, channel_name).await
        }
        crate::config::agent_surface::SurfaceProtocol::Mcp => {
            // MCP not yet implemented for fabric VP verification
            debug!(channel = channel_name, "Fabric: MCP VP verification not yet implemented");
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Extract and verify A2A fabric response VP
///
/// Flow:
/// 1. Find the credential extension in the response locations the protected
///    agent authors (see `backend_identity::response_identity_candidates`)
/// 2. Verify VP signature using VC issuer
/// 3. Store verified DID in identity store
/// 4. Fall back to raw identity if no VP (backward compat)
async fn extract_a2a_fabric_identity(
    response_json: &JsonValue,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_name: &str,
) -> Result<Option<String>, String> {
    use crate::proxy::backend_identity::{IdentityExtractionError, extract_a2a_identity_from_message_with_uri};

    // PRIORITY 1: Check for VP credential extension (GW2 → GW1)
    match extract_a2a_identity_from_message_with_uri(
        response_json,
        crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
    ) {
        Ok(credential_ext) => {
            info!(channel = channel_name, "Fabric: Found VP credential extension from GW2");
            return verify_fabric_credential(&credential_ext, response_identity_selector, surface, channel_name).await;
        }
        Err(IdentityExtractionError::DeclaredButMissing) => {
            warn!(channel = channel_name, "Fabric: VP credential extension declared but not found in metadata");
            return Ok(None);
        }
        Err(_) => {}
    }

    // PRIORITY 2: Check for raw identity extension
    let identity_ext = match extract_a2a_identity_from_message_with_uri(
        response_json,
        crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION,
    ) {
        Ok(identity_ext) => identity_ext,
        Err(e) => {
            debug!(channel = channel_name, reason = %e, "Fabric: No identity extension found in response");
            return Ok(None);
        }
    };
    debug!(channel = channel_name, "Fabric: Found raw identity extension");

    // Check if backend agent already sent a DID
    if let Some(did) = identity_ext
        .get("did")
        .and_then(|d| d.as_str())
    {
        info!(channel = channel_name, did = did, "Fabric: Backend agent DID from raw identity");
        return Ok(Some(did.to_string()));
    }

    // Raw identity without DID - try to compute using identity selector
    if let Some(selector) = response_identity_selector {
        debug!(channel = channel_name, "Fabric: Computing backend agent identity from raw fields");

        match selector
            .compute_identity(
                &identity_ext,
                channel_name,
                Some(surface.surface_id.clone()),
                surface.issuer_id.clone(),
                crate::identity::filesystem::IdentityOrigin::Managed,
            )
            .await
        {
            Ok(identity_result) => {
                info!(
                    channel = channel_name,
                    did = identity_result.did,
                    is_new = identity_result.is_new,
                    "Fabric: Backend agent identity computed from raw fields"
                );
                return Ok(Some(identity_result.did));
            }
            Err(e) => {
                warn!(channel = channel_name, error = %e, "Fabric: Failed to compute backend agent identity from raw fields");
                // Don't reject - just return None for compat
                return Ok(None);
            }
        }
    }

    debug!(channel = channel_name, "Fabric: No identity selector available for raw identity");
    Ok(None)
}

/// Verify the VP carried by GW2's credential extension and store the verified
/// DID. Rejects a credential that carries no `verifiablePresentation` or whose
/// VP fails verification.
async fn verify_fabric_credential(
    credential_ext: &JsonValue,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_name: &str,
) -> Result<Option<String>, String> {
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
    let vc_issuer = selector.get_vc_issuer();

    match vc_issuer
        .verify_agent_presentation(vp_jwt)
        .await
    {
        Ok((verified_did, identity_fields)) => {
            info!(
                channel = channel_name,
                did = %verified_did,
                "✓ Fabric: VP verification succeeded for server DID"
            );

            // Store verified DID from GW2
            let identity_store = vc_issuer.get_identity_store();
            if let Err(e) = identity_store
                .store_external_did(
                    &verified_did,
                    identity_fields,
                    Some(surface.surface_id.clone()),
                    true, // verified=true
                )
                .await
            {
                warn!(channel = channel_name, error = %e, "Fabric: Failed to store verified server DID");
            }

            Ok(Some(verified_did))
        }
        Err(e) => {
            // POLICY: Reject invalid VPs
            let error_msg = format!("VP verification failed for server agent identity: {}", e);
            warn!(channel = channel_name, error = %e, "✗ Fabric: VP verification FAILED");
            Err(error_msg)
        }
    }
}

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
    ) -> Result<Option<String>, String> {
        extract_a2a_fabric_identity(response, selector, &surface(), "a-party").await
    }

    #[tokio::test]
    async fn raw_identity_did_is_read_from_a_wrapped_v1_task_status_message() {
        let response = v1_task(agent_message(IDENTITY_URI, json!({ "did": "did:web:agent" })));

        assert_eq!(extract(&response, &None).await, Ok(Some("did:web:agent".to_string())));
    }

    #[tokio::test]
    async fn raw_identity_did_is_read_from_a_v0_3_task_status_message() {
        let response = json!({
            "result": {
                "kind": "task",
                "id": "t",
                "status": { "state": "completed", "message": agent_message(IDENTITY_URI, json!({ "did": "did:web:agent" })) },
                "history": [caller_message()]
            }
        });

        assert_eq!(extract(&response, &None).await, Ok(Some("did:web:agent".to_string())));
    }

    #[tokio::test]
    async fn caller_identity_in_history_is_not_attributed_to_the_agent() {
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
}
