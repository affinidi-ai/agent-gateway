//! Agent onboarding handler
//!
//! This handler allows agents to self-register with identity fields
//! and receive a DID that can be used with the sign-jwt and verify-jwt endpoints.
//!
//! Trust-registry writes for the agent DID are owned by the Trust Recorder
//! stage (`src/trust_registry_verification/trust_recorder.rs`), which fires
//! on the response leg + discovery. The onboarding path only mints the
//! identity; it does not touch trust registries directly.

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::identity::compute_canonical_identity_hash;
use crate::identity::state::IdentityApiState;

/// Request body for agent onboarding
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardRequest {
    /// Identity fields as key-value pairs.
    /// Keys use dot notation for nested fields (e.g., "agentIdentity.role", "agentIdentity.merchantInfo.name")
    pub identity_fields: HashMap<String, serde_json::Value>,
}

/// Response from agent onboarding
#[derive(Debug, Serialize)]
pub struct OnboardResponse {
    /// The agent's DID, can be used with sign-jwt/verify-jwt endpoints
    pub did: String,

    /// Whether this is a newly created identity (true) or an existing one (false)
    pub is_new: bool,

    /// ISO 8601 timestamp of when the identity was created
    pub created_at: String,
}

/// Handle agent onboarding request
///
/// This endpoint:
/// 1. Computes a canonical hash from the identity fields
/// 2. Creates or retrieves an existing identity with that hash
/// 3. Returns the DID for the agent to use with signing APIs
///
/// The endpoint is public (agent self-registration), so the body cannot name an
/// issuer: a request carrying `issuer_did` or any other unknown field is rejected,
/// and the trust-registry binding is derived server-side by the Trust Recorder
/// from the surface configuration.
///
/// The endpoint is idempotent - calling with the same identity fields
/// will return the same DID.
pub async fn onboard(
    State(state): State<IdentityApiState>,
    Json(request): Json<OnboardRequest>,
) -> Result<Json<OnboardResponse>, (StatusCode, String)> {
    // Validate that we have at least one identity field
    if request
        .identity_fields
        .is_empty()
    {
        return Err((StatusCode::BAD_REQUEST, "identity_fields must contain at least one field".to_string()));
    }

    // Compute the canonical identity hash
    let identity_hash = compute_canonical_identity_hash(&request.identity_fields);

    info!(
        identity_hash = %identity_hash,
        field_count = request.identity_fields.len(),
        "agents-api: onboard request"
    );

    // Issue or get existing credential/DID
    let response = state
        .vc_issuer
        .issue_or_get_credential(
            request.identity_fields,
            Some(identity_hash.clone()),
            None, // No channel_config_id for self-registration
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, identity_hash = %identity_hash, "Failed to onboard agent");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create identity: {}", e))
        })?;

    info!(
        did = %response.did,
        is_new = response.is_new,
        identity_hash = %identity_hash,
        "agents-api: agent onboarded successfully"
    );

    Ok(Json(OnboardResponse {
        did: response.did,
        is_new: response.is_new,
        created_at: response
            .created_at
            .to_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::extract::rejection::JsonRejection;
    use axum::http::Request;
    use serde_json::json;

    async fn extract(body: serde_json::Value) -> Result<OnboardRequest, JsonRejection> {
        let request = Request::builder()
            .method("POST")
            .uri("/agents-api/v1/onboard")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        Json::<OnboardRequest>::from_request(request, &())
            .await
            .map(|Json(request)| request)
    }

    #[tokio::test]
    async fn onboard_rejects_a_caller_chosen_issuer_did() {
        let rejection = extract(json!({
            "identity_fields": { "agentIdentity.role": "shopper" },
            "issuer_did": "did:web:issuer.example.com"
        }))
        .await
        .expect_err("a body naming an issuer must be rejected before the handler runs");
        assert_eq!(rejection.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            rejection
                .body_text()
                .contains("issuer_did"),
            "{}",
            rejection.body_text()
        );
    }

    #[tokio::test]
    async fn onboard_accepts_identity_fields_only() {
        let request = extract(json!({ "identity_fields": { "agentIdentity.role": "shopper" } }))
            .await
            .expect("identity_fields alone is the whole contract");
        assert_eq!(request.identity_fields.len(), 1);
    }
}
