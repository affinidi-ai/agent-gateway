//! HTTP handlers for DID Authentication endpoints
//!
//! Provides `/authenticate/challenge` and `/authenticate` endpoints for channels.
//! The `/authenticate` handler cryptographically verifies the compact JWS the
//! caller presents (see [`super::verify`]).

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::sessions::DidAuthSessionStore;
use super::verify::{DidAuthVerifyError, verify_challenge_response};
use crate::observability::loggable;
use crate::source_auth::models::DidAuthAuthConfig;

/// State passed to the DID Auth HTTP handlers. Bundles the shared session
/// store with the surface's active `DidAuthAuthConfig` so TTLs, audience, and
/// allow-lists are honoured on both endpoints.
#[derive(Clone)]
pub struct DidAuthHandlerState {
    pub session_store: Arc<DidAuthSessionStore>,
    pub config: Arc<DidAuthAuthConfig>,
    pub surface_id: String,
}

/// Request body for challenge endpoint
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ChallengeRequest {
    /// The DID requesting authentication
    pub did: String,

    /// The channel name (optional, can be derived from route)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

/// Response from challenge endpoint
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// The challenge string to sign
    pub challenge: String,

    /// How long the challenge is valid for (seconds)
    pub expires_in: u64,
}

/// Request body for authenticate endpoint
#[derive(Debug, Deserialize)]
pub struct AuthenticateRequest {
    /// The DID being authenticated
    pub did: String,

    /// The signed challenge — a compact JWS whose `kid` identifies a
    /// verification method on the caller's DID Document. Payload must carry
    /// `{ challenge, iat, exp?, aud? }`.
    pub challenge_response: String,

    /// Legacy display-only field kept for backward compatibility with
    /// clients that still send it. **Ignored server-side** — the session
    /// is always bound to the surface currently being authenticated
    /// against (`state.surface_id`), never to a client-supplied value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub channel: Option<String>,
}

/// Response from authenticate endpoint
#[derive(Serialize)]
pub struct AuthenticateResponse {
    /// The session token to use in subsequent requests
    pub session_id: String,

    /// When the session expires (ISO 8601 datetime)
    pub expires_at: String,

    /// How long the session is valid for (seconds)
    pub expires_in: u64,
}

impl std::fmt::Debug for AuthenticateResponse {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticateResponse")
            .field("session_id", &loggable::secret(&self.session_id))
            .field("expires_at", &self.expires_at)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Error response body
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Stable machine-readable code (e.g. `bad_signature`, `did_not_allowed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Handler for `/authenticate/challenge` endpoint.
///
/// Returns a challenge that the client must sign with the private key that
/// controls the DID.
pub async fn challenge_handler(
    State(state): State<DidAuthHandlerState>,
    Json(req): Json<ChallengeRequest>,
) -> Response {
    info!(surface = %state.surface_id, did = %req.did, "DID Auth challenge requested");

    if !req.did.starts_with("did:") {
        warn!(did = %req.did, "Invalid DID format");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid DID format".to_string(),
                details: Some("DID must start with 'did:'".to_string()),
                code: Some("invalid_did".to_string()),
            }),
        )
            .into_response();
    }

    if !state
        .config
        .allowed_dids
        .is_empty()
        && !state
            .config
            .allowed_dids
            .iter()
            .any(|d| d.trim() == req.did)
    {
        warn!(did = %req.did, "DID not in allow-list");
        crate::metrics::backends::prometheus::track_didauth_authenticate(&state.surface_id, "did_not_allowed", None);
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "DID not authorised on this surface".to_string(),
                details: None,
                code: Some("did_not_allowed".to_string()),
            }),
        )
            .into_response();
    }

    let ttl = state
        .config
        .effective_challenge_ttl_seconds();
    let challenge = state
        .session_store
        .create_challenge(req.did.clone(), ttl)
        .await;

    debug!(did = %req.did, challenge = %challenge, ttl_seconds = ttl, "Created challenge");
    crate::metrics::backends::prometheus::track_didauth_challenge_issued(&state.surface_id);

    (StatusCode::OK, Json(ChallengeResponse { challenge, expires_in: ttl })).into_response()
}

/// Handler for `/authenticate` endpoint.
///
/// Verifies the signed challenge (compact JWS) against the DID Document
/// resolved via the shared DID resolver and returns a session token on
/// success.
pub async fn authenticate_handler(
    State(state): State<DidAuthHandlerState>,
    Json(req): Json<AuthenticateRequest>,
) -> Response {
    info!(surface = %state.surface_id, did = %req.did, "DID Auth authentication requested");
    let start = std::time::Instant::now();

    let challenge = match state
        .session_store
        .take_pending_challenge(&req.did)
        .await
    {
        Some(c) => c,
        None => {
            warn!(did = %req.did, "No pending challenge found for DID");
            crate::metrics::backends::prometheus::track_didauth_authenticate(
                &state.surface_id,
                "challenge_mismatch",
                Some(start.elapsed().as_secs_f64()),
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "No pending challenge for this DID".to_string(),
                    details: Some("Call POST /authenticate/challenge first".to_string()),
                    code: Some("challenge_mismatch".to_string()),
                }),
            )
                .into_response();
        }
    };

    if chrono::Utc::now() > challenge.expires_at {
        crate::metrics::backends::prometheus::track_didauth_authenticate(
            &state.surface_id,
            "expired",
            Some(start.elapsed().as_secs_f64()),
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Challenge expired".to_string(),
                details: None,
                code: Some("expired".to_string()),
            }),
        )
            .into_response();
    }

    let resolver = crate::gateways::did_cache::shared_resolver();
    let verify_result =
        verify_challenge_response(&req.did, &req.challenge_response, &challenge.challenge, &state.config, resolver)
            .await;

    let duration = start.elapsed().as_secs_f64();

    match verify_result {
        Ok(verified) => {
            let session_ttl = state
                .config
                .effective_session_ttl_seconds();
            // The `channel` field on the request body is intentionally
            // ignored — the session is bound to `state.surface_id` so it
            // cannot be replayed against another surface. `channel_name`
            // remains a display-only field for logging + audit; the
            // authoritative surface identifier is stored on the session
            // record and rechecked on every subsequent lookup.
            let channel_name = state.surface_id.clone();
            let session = state
                .session_store
                .create_session(verified.did.clone(), channel_name, state.surface_id.clone(), session_ttl)
                .await;
            info!(
                surface = %state.surface_id,
                did = %verified.did,
                session_id = %loggable::secret(&session.session_id),
                expires_at = %session.expires_at,
                "Minted DID Auth session"
            );
            crate::metrics::backends::prometheus::track_didauth_authenticate(&state.surface_id, "ok", Some(duration));
            (
                StatusCode::OK,
                Json(AuthenticateResponse {
                    session_id: session.session_id,
                    expires_at: session
                        .expires_at
                        .to_rfc3339(),
                    expires_in: session_ttl,
                }),
            )
                .into_response()
        }
        Err(err) => {
            warn!(
                surface = %state.surface_id,
                did = %req.did,
                code = %err.code(),
                error = %err,
                "DID Auth verification failed"
            );
            let status = verify_status(&err);
            crate::metrics::backends::prometheus::track_didauth_authenticate(
                &state.surface_id,
                err.code(),
                Some(duration),
            );
            (
                status,
                Json(ErrorResponse {
                    error: "DID Auth verification failed".to_string(),
                    details: Some(err.to_string()),
                    code: Some(err.code().to_string()),
                }),
            )
                .into_response()
        }
    }
}

fn verify_status(err: &DidAuthVerifyError) -> StatusCode {
    match err {
        DidAuthVerifyError::MalformedJws { .. }
        | DidAuthVerifyError::KidMismatch { .. }
        | DidAuthVerifyError::MalformedPayload => StatusCode::BAD_REQUEST,
        DidAuthVerifyError::AlgorithmRejected { .. }
        | DidAuthVerifyError::DidNotAllowed { .. }
        | DidAuthVerifyError::AudienceMismatch
        | DidAuthVerifyError::ChallengeMismatch
        | DidAuthVerifyError::Expired
        | DidAuthVerifyError::IatOutOfRange
        | DidAuthVerifyError::BadSignature => StatusCode::UNAUTHORIZED,
        DidAuthVerifyError::ResolverError { .. }
        | DidAuthVerifyError::VerificationMethodNotFound { .. }
        | DidAuthVerifyError::UnsupportedVerificationMethod { .. } => StatusCode::BAD_GATEWAY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn base64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn did_key(signing_key: &SigningKey) -> String {
        let mut multicodec_key = vec![0xed, 0x01];
        multicodec_key.extend_from_slice(
            &signing_key
                .verifying_key()
                .to_bytes(),
        );
        format!("did:key:z{}", bs58::encode(multicodec_key).into_string())
    }

    fn signed_challenge(
        signing_key: &SigningKey,
        did: &str,
        challenge: &str,
    ) -> String {
        let key_fragment = did
            .strip_prefix("did:key:")
            .unwrap();
        let header = serde_json::json!({ "alg": "EdDSA", "kid": format!("{did}#{key_fragment}") });
        let now = chrono::Utc::now().timestamp();
        let payload = serde_json::json!({ "challenge": challenge, "iat": now, "exp": now + 300 });
        let signing_input = format!(
            "{}.{}",
            base64url(&serde_json::to_vec(&header).unwrap()),
            base64url(&serde_json::to_vec(&payload).unwrap())
        );
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", base64url(&signature.to_bytes()))
    }

    #[test]
    fn authenticate_response_debug_shows_only_a_session_id_prefix() {
        let session_id = "7c1e5a90-2d4b-4f6e-9a8c-b1d2e3f4a5b6";
        let response = AuthenticateResponse {
            session_id: session_id.to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            expires_in: 86400,
        };

        let rendered = format!("{response:?}");

        assert!(rendered.contains(r#"session_id: "7c1e5a90...""#), "{rendered}");
        assert!(rendered.contains("expires_in: 86400"), "{rendered}");
        assert!(!rendered.contains(session_id), "{rendered}");
    }

    #[tokio::test]
    async fn minting_a_session_logs_only_a_session_id_prefix() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let did = did_key(&signing_key);
        let state = DidAuthHandlerState {
            session_store: Arc::new(DidAuthSessionStore::new()),
            config: Arc::new(DidAuthAuthConfig {
                extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
                    field: "X-DID-Auth-Session".to_string(),
                },
                allowed_dids: vec![],
                challenge_ttl_seconds: None,
                session_ttl_seconds: None,
                audience: None,
                allowed_algorithms: vec![],
            }),
            surface_id: "surface-1".to_string(),
        };
        let challenge = state
            .session_store
            .create_challenge(did.clone(), 60)
            .await;
        let request = AuthenticateRequest {
            challenge_response: signed_challenge(&signing_key, &did, &challenge),
            did,
            channel: None,
        };
        let logs = FormattedLogs::capture();

        let response = authenticate_handler(State(state), Json(request)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let session_id = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["session_id"]
            .as_str()
            .unwrap()
            .to_string();
        let text = logs.text();
        assert!(text.contains("Minted DID Auth session"), "{text}");
        assert!(text.contains(&format!("session_id={}", loggable::secret(&session_id))), "{text}");
        assert!(!text.contains(&session_id), "{text}");
    }
}
