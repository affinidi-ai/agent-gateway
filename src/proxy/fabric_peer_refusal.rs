//! The sending gateway's answer when the receiving gateway of a Fabric route
//! refuses the authorization of the request it forwarded. The caller's own token
//! never crosses Fabric, so no such refusal is the caller's to fix: it becomes a
//! `502` with a fixed detail and no challenge.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use crate::audit::request_events::{RejectionReason, RejectionStage, RequestFacts, request_rejected};
use crate::channel_warn;
use crate::source_auth::challenge::{PeerRefusal, peer_refusal};

pub(crate) const PEER_REFUSED_DETAIL: &str = "The Fabric peer refused the gateway's authorization";

/// The audit reason recorded for a refusal.
pub(crate) fn rejection_reason(refusal: PeerRefusal) -> RejectionReason {
    match refusal {
        PeerRefusal::Token => RejectionReason::PeerTokenRefused,
        PeerRefusal::Scope => RejectionReason::PeerScopeRefused,
    }
}

/// `Some(502)` when `status` and `headers`, a Fabric peer's answer, refuse the
/// sending gateway's authorization: the response carries a fixed detail and no
/// challenge, and the refusal is recorded as `request_rejected` at stage
/// `forward`. `None` lets the peer's answer go on unchanged.
pub(crate) fn refuse_peer_authorization(
    status: StatusCode,
    headers: &HeaderMap,
    facts: &RequestFacts<'_>,
) -> Option<Response> {
    let refusal = peer_refusal(status, headers)?;
    let reason = rejection_reason(refusal);
    request_rejected(facts, RejectionStage::Forward, reason, StatusCode::BAD_GATEWAY.as_u16(), None);
    channel_warn!(
        facts.surface_id,
        "Fabric peer refused the forwarded request's authorization (peer_status={}, reason={:?})",
        status.as_u16(),
        reason
    );
    Some(crate::a2a::errors::create_error_response(StatusCode::BAD_GATEWAY, PEER_REFUSED_DETAIL))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
    use serde_json::Value;

    use super::*;
    use crate::delegation_vault::audit::DelegationAuditAction;
    use crate::protocols::protected_resource::is_gateway_challenge;

    const PEER_TOKEN_CHALLENGE: &str = "Bearer realm=\"agent-gateway\", error=\"invalid_token\"";
    const PEER_SCOPE_CHALLENGE: &str = "Bearer realm=\"agent-gateway\", error=\"insufficient_scope\"";

    fn facts() -> RequestFacts<'static> {
        RequestFacts {
            surface_id: "fabric-a2a",
            channel_name: "Fabric A2A",
            trace_id: Some("trace-7"),
            via_fabric: false,
        }
    }

    fn peer_headers(challenge: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(challenge) = challenge {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }
        headers
    }

    fn refusals() -> [(StatusCode, HeaderMap, RejectionReason); 2] {
        [
            (StatusCode::UNAUTHORIZED, peer_headers(Some(PEER_TOKEN_CHALLENGE)), RejectionReason::PeerTokenRefused),
            (StatusCode::FORBIDDEN, peer_headers(Some(PEER_SCOPE_CHALLENGE)), RejectionReason::PeerScopeRefused),
        ]
    }

    #[tokio::test]
    async fn a_peer_refusal_answers_502_with_the_fixed_detail_and_no_challenge() {
        for (status, headers, _) in refusals() {
            let response = refuse_peer_authorization(status, &headers, &facts()).expect("a peer refusal");
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{status}");
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/problem+json"),
                "{status}"
            );
            assert!(
                !response
                    .headers()
                    .contains_key(WWW_AUTHENTICATE),
                "{status}"
            );
            assert!(!is_gateway_challenge(&response), "{status}");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read body");
            let text = String::from_utf8(bytes.to_vec()).expect("utf-8 body");
            for leaked in ["realm", "insufficient_scope", "scope", "resource_metadata", "invalid_token"] {
                assert!(!text.contains(leaked), "{status} {leaked}: {text}");
            }
            let body: Value = serde_json::from_str(&text).expect("json body");
            assert_eq!(body["detail"], PEER_REFUSED_DETAIL, "{status}");
            assert_eq!(body["status"], 502, "{status}");
        }
    }

    #[tokio::test]
    async fn a_peer_refusal_is_recorded_as_a_forward_rejection() {
        for (status, headers, reason) in refusals() {
            let (response, events) =
                crate::audit::producer::capture(async { refuse_peer_authorization(status, &headers, &facts()) }).await;
            assert!(response.is_some(), "{status}");
            assert_eq!(events.len(), 1, "{status}");
            let event = &events[0];
            assert_eq!(event.surface_id.as_deref(), Some("fabric-a2a"));
            assert_eq!(event.trace_id.as_deref(), Some("trace-7"));
            assert!(!event.via_fabric);
            match &event.event {
                DelegationAuditAction::RequestRejected {
                    stage,
                    reason: recorded,
                    http_status,
                    rpc_error_code,
                    requested_variant,
                } => {
                    assert_eq!(*stage, RejectionStage::Forward);
                    assert_eq!(*recorded, reason);
                    assert_eq!(*http_status, Some(502));
                    assert_eq!(*rpc_error_code, None);
                    assert_eq!(*requested_variant, None);
                }
                other => panic!("expected RequestRejected, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_policy_403_or_a_payment_challenge_from_the_peer_passes_unrecorded() {
        for (status, headers) in [
            (StatusCode::FORBIDDEN, peer_headers(None)),
            (StatusCode::UNAUTHORIZED, peer_headers(Some("Payment id=\"p1\", realm=\"tg\", method=\"tempo\""))),
        ] {
            let (response, events) =
                crate::audit::producer::capture(async { refuse_peer_authorization(status, &headers, &facts()) }).await;
            assert!(response.is_none(), "{status}");
            assert!(events.is_empty(), "{status}");
        }
    }
}
