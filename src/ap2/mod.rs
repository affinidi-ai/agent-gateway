//! AP2 (Agent Payments Protocol) handling
//!
//! **EXPERIMENTAL** — the AP2 surface is gated behind the
//! `feature_flags.ap2_experimental` dashboard setting (default off). When the
//! flag is off, an AP2 request is rejected at the inbound gate with HTTP 501
//! before any payment settlement or dispatch. Even with the flag on there is no
//! production signing: the VDC → VC → VP producers (`sign_credential` /
//! `vc_to_jwt` in `credentials.rs`, `sign_presentation` /
//! `create_unsigned_vp_jwt`) fail closed and return an error rather than emit a
//! fabricated proof, so a transform is rejected instead of forwarded. Not shown
//! in the UI.
//!
//! This module implements Google's Agent Payments Protocol (AP2), which extends
//! the A2A protocol with support for payment mandates (VDCs).
//!
//! AP2 adds a credential transformation pipeline that:
//! 1. Validates VDC (Verifiable Digital Credential) mandates
//! 2. Extracts data from VDCs
//! 3. Creates W3C Verifiable Credentials
//! 4. Generates Verifiable Presentations
//! 5. Injects VPs into message metadata
//!
//! Supported mandate types:
//! - IntentMandate: Shopping intent from buyer
//! - CartMandate: Shopping cart from merchant
//! - PaymentMandate: Payment authorization from credentials provider
//!
//! ## Message Structure (Official AP2 Spec)
//!
//! Mandates are extracted from: `params.message.parts[].data["ap2.mandates.*"]`
//!
//! Example:
//! ```json
//! {
//!   "params": {
//!     "message": {
//!       "parts": [
//!         {
//!           "kind": "data",
//!           "data": {
//!             "ap2.mandates.IntentMandate": {
//!               "natural_language_description": "...",
//!               "intent_expiry": "2025-09-16T15:00:00Z"
//!             }
//!           }
//!         }
//!       ]
//!     }
//!   }
//! }
//! ```
//!
//! Legacy paths are also supported for backwards compatibility:
//! - `params.extensions.payment.vdc`
//! - `mandate` (top-level field)
//!
//! See: https://ap2-protocol.org/ for the official specification
//! See: https://github.com/google-agentic-commerce/AP2 for reference implementation

pub mod credentials;
pub mod mandates;
pub mod presentation;
pub mod vdc;

#[cfg(test)]
#[path = "mod.test.rs"]
mod mod_test;

use anyhow::{Context, Result};
use serde_json::Value;
use tracing::{debug, info, warn};

use credentials::transform_vdc_to_vc;
use vdc::extract_vdc_from_message;

/// Process AP2 message: detect VDC, validate, transform to W3C VC/VP
///
/// This is the main entry point for AP2 message processing.
/// It handles the complete VDC→VC→VP transformation pipeline.
///
/// If identity extraction is enabled and agent identity is present:
/// - Uses agent's DID as the credential subject
/// - Signs with agent's key
///
/// If identity extraction is disabled:
/// - Uses gateway's DID as the credential subject
/// - Signs with gateway's key
pub async fn process_ap2_message(
    message: &mut Value,
    gateway_did: &str,
    vc_issuer: &Option<std::sync::Arc<crate::identity::VCIssuer>>,
    agent_identity: &Option<(String, std::collections::HashMap<String, serde_json::Value>)>,
) -> Result<()> {
    info!("Processing AP2 message for VDC transformation");

    // Determine which DID to use for signing
    let (subject_did, use_agent_identity) = if let Some((agent_did, _)) = agent_identity {
        info!("Using agent identity - DID: {}", agent_did);
        (agent_did.clone(), true)
    } else {
        info!("No agent identity - using gateway DID: {}", gateway_did);
        (gateway_did.to_string(), false)
    };

    // 1. Extract VDC from message
    let vdc = match extract_vdc_from_message(message)? {
        Some(vdc) => vdc,
        None => {
            debug!("No VDC found in AP2 message, skipping transformation");
            return Ok(());
        }
    };

    info!("Found VDC mandate: {} (type: {})", vdc.id, vdc.mandate_type);

    // 2. Validate VDC signature and structure
    let validation_result = vdc.validate().await?;

    if !validation_result.valid {
        warn!("VDC validation failed: {:?}", validation_result.errors);
        return Err(anyhow::anyhow!(
            "VDC validation failed: {}",
            validation_result
                .errors
                .join(", ")
        ));
    }

    info!("✓ VDC validation successful");

    // 3. Transform VDC to W3C Verifiable Credential
    // The VC subject ID should be the agent's DID (or gateway DID if no agent identity)
    let vc = transform_vdc_to_vc(&vdc, gateway_did, &subject_did)
        .await
        .context("Failed to transform VDC to W3C VC")?;

    info!("✓ Created W3C VC with subject: {}", subject_did);

    // 4. Create Verifiable Presentation as JWT
    let vp_jwt = if let Some(issuer) = vc_issuer {
        // VCIssuer available - create properly signed VP
        if use_agent_identity {
            create_vp_jwt_with_agent(&vc, &subject_did, issuer)
                .await
                .context("Failed to create VP JWT with agent identity")?
        } else {
            create_vp_jwt_with_gateway(&vc, gateway_did, issuer)
                .await
                .context("Failed to create VP JWT with gateway identity")?
        }
    } else {
        // No VCIssuer available: refuse to emit an unsigned presentation.
        warn!("No VCIssuer available - refusing to create an unsigned AP2 presentation");
        create_unsigned_vp_jwt(&vc, gateway_did)?
    };

    info!(
        "✓ Created VP JWT signed by: {}",
        if vc_issuer.is_some() {
            if use_agent_identity {
                "agent"
            } else {
                "gateway"
            }
        } else {
            "unsigned (dev mode)"
        }
    );

    // 5. Inject VP JWT into message metadata
    inject_vp_jwt_into_message(message, &vp_jwt)?;

    info!("✓ AP2 transformation complete - VDC→VC→VP (JWT) injected into metadata");

    Ok(())
}

/// Inject Verifiable Presentation JWT into message metadata
fn inject_vp_jwt_into_message(
    message: &mut Value,
    vp_jwt: &str,
) -> Result<()> {
    // Ensure metadata object exists
    if message
        .get("metadata")
        .is_none()
    {
        message["metadata"] = serde_json::json!({});
    }

    // Inject VP JWT into metadata.ap2_payment_vp
    if let Some(metadata) = message.get_mut("metadata") {
        metadata["ap2_payment_vp"] = serde_json::json!(vp_jwt);
        debug!("Injected VP JWT into metadata.ap2_payment_vp");
    }

    Ok(())
}

/// Create VP JWT signed with agent's key
async fn create_vp_jwt_with_agent(
    vc: &credentials::VerifiableCredential,
    agent_did: &str,
    vc_issuer: &std::sync::Arc<crate::identity::VCIssuer>,
) -> Result<String> {
    // Convert VC to JWT first (signed by gateway)
    let vc_jwt = credentials::vc_to_jwt(vc)?;

    // Create VP containing the VC JWT
    let vp_payload = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "holder": agent_did,
        "verifiableCredential": [vc_jwt],
    });

    // Sign VP with agent's key
    let vp_jwt = vc_issuer
        .sign_jwt_with_agent_key(agent_did, &vp_payload)
        .await
        .context("Failed to sign VP with agent key")?;

    Ok(vp_jwt)
}

/// Create VP JWT signed with gateway's key (fallback when no agent identity)
async fn create_vp_jwt_with_gateway(
    vc: &credentials::VerifiableCredential,
    gateway_did: &str,
    vc_issuer: &std::sync::Arc<crate::identity::VCIssuer>,
) -> Result<String> {
    // Convert VC to JWT (signed by gateway)
    let vc_jwt = credentials::vc_to_jwt(vc)?;

    // Create VP containing the VC JWT
    let vp_payload = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "holder": gateway_did,
        "verifiableCredential": [vc_jwt],
        "iss": gateway_did,
        "jti": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
    });

    // Sign VP with gateway's key using VCIssuer
    let vp_jwt = vc_issuer
        .sign_jwt_with_gateway_key(&vp_payload)
        .await
        .context("Failed to sign VP with gateway key")?;

    Ok(vp_jwt)
}

/// Create a VP JWT when no `VCIssuer` is available.
///
/// The previous stub emitted an `alg:none` (unsigned) VP for development. To
/// avoid the gateway ever producing an unsigned presentation, this now fails
/// closed; a real signing identity (`VCIssuer`) is required to create a VP.
fn create_unsigned_vp_jwt(
    _vc: &credentials::VerifiableCredential,
    _gateway_did: &str,
) -> Result<String> {
    Err(anyhow::anyhow!("AP2 requires a signing identity; refusing to emit an unsigned (alg:none) presentation"))
}
