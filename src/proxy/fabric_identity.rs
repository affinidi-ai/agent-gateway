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
/// Pattern: Mirrors GW2's message_processor.rs:926-986 inbound VP verification
///
/// Flow:
/// 1. Navigate to message object (result.history[0] or result directly)
/// 2. Check for VP credential extension
/// 3. Verify VP signature using VC issuer
/// 4. Store verified DID in identity store
/// 5. Fall back to raw identity if no VP (backward compat)
async fn extract_a2a_fabric_identity(
    response_json: &JsonValue,
    response_identity_selector: &Option<Arc<crate::identity::IdentitySelector>>,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_name: &str,
) -> Result<Option<String>, String> {
    // Navigate to message object (history or direct result)
    // This matches the pattern from GW2's message_processor.rs
    let message_obj = response_json
        .get("result")
        .and_then(|r| {
            // Try history first (multi-message response)
            if let Some(history) = r
                .get("history")
                .and_then(|h| h.as_array())
                .and_then(|arr| arr.first())
            {
                info!(channel = channel_name, "Fabric: Found response in result.history[0]");
                Some(history)
            } else if r.get("metadata").is_some() || r.get("extensions").is_some() {
                // Direct message response (single message completion)
                info!(channel = channel_name, "Fabric: Found response directly in result");
                Some(r)
            } else {
                warn!(channel = channel_name, "Fabric: Response has result but no history or metadata");
                None
            }
        });

    let message_obj = match message_obj {
        Some(obj) => obj,
        None => {
            debug!(channel = channel_name, "Fabric: No message object found in response");
            return Ok(None);
        }
    };

    // Check for extensions array
    let extensions = match message_obj
        .get("extensions")
        .and_then(|e| e.as_array())
    {
        Some(ext) => {
            debug!(channel = channel_name, ext_count = ext.len(), "Fabric: Found extension URIs in response");
            ext
        }
        None => {
            debug!(channel = channel_name, "Fabric: No extensions array in response");
            return Ok(None);
        }
    };

    // PRIORITY 1: Check for VP credential extension (GW2 → GW1)
    let has_credential_ext = extensions
        .iter()
        .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION));

    if has_credential_ext {
        info!(channel = channel_name, "Fabric: Found VP credential extension from GW2");

        let metadata = match message_obj.get("metadata") {
            Some(m) => m,
            None => {
                warn!(channel = channel_name, "Fabric: VP credential extension declared but no metadata found");
                return Ok(None);
            }
        };

        let credential_ext = match metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION) {
            Some(ext) => ext,
            None => {
                warn!(channel = channel_name, "Fabric: VP credential extension declared but not found in metadata");
                return Ok(None);
            }
        };

        // Extract and verify VP
        if let Some(vp_jwt) = credential_ext
            .get("verifiablePresentation")
            .and_then(|v| v.as_str())
        {
            if let Some(selector) = response_identity_selector {
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

                        return Ok(Some(verified_did));
                    }
                    Err(e) => {
                        // POLICY: Reject invalid VPs
                        let error_msg = format!("VP verification failed for server agent identity: {}", e);
                        warn!(channel = channel_name, error = %e, "✗ Fabric: VP verification FAILED");
                        return Err(error_msg);
                    }
                }
            } else {
                warn!(channel = channel_name, "Fabric: No response identity selector available for VP verification");
            }
        }

        // VP credential extension present but no verifiablePresentation field
        // This is malformed - reject it
        if credential_ext
            .get("verifiablePresentation")
            .is_none()
        {
            let error_msg = "VP credential extension present but missing verifiablePresentation field".to_string();
            warn!(channel = channel_name, "{}", error_msg);
            return Err(error_msg);
        }
    }

    // PRIORITY 2: Check for raw identity extension
    let has_identity_ext = extensions
        .iter()
        .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION));

    if has_identity_ext {
        debug!(channel = channel_name, "Fabric: Found raw identity extension");

        let metadata = match message_obj.get("metadata") {
            Some(m) => m,
            None => {
                debug!(channel = channel_name, "Fabric: Identity extension declared but no metadata found");
                return Ok(None);
            }
        };

        let identity_ext = match metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION) {
            Some(ext) => ext,
            None => {
                debug!(channel = channel_name, "Fabric: Identity extension declared but not found in metadata");
                return Ok(None);
            }
        };

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
                    identity_ext,
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
    }

    // No identity found - this is OK for compatibility
    debug!(channel = channel_name, "Fabric: No identity extension found in response");
    Ok(None)
}
