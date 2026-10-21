//! Why GW2 refused a fabric `forward-request` before the Target answered it,
//! and the `forward-response` that tells the sending gateway.

use super::{MessageType, ProcessingResult, axum_response_to_forward_result, build_surface_policy_denied_forward_body};
use crate::proxy::upstream_body::UpstreamBodyError;

#[derive(Debug, thiserror::Error)]
pub(super) enum ForwardRefusal {
    #[error("sender is not a registered, active gateway")]
    UnregisteredSender,
    #[error("channel is not exposed to the sender")]
    ChannelNotExposed,
    #[error("appliance-wide gateway policy denied the request")]
    AppliancePolicyDenied,
    #[error("gateway policy denied the request")]
    GatewayPolicyDenied,
    #[error("gateway policy could not be evaluated")]
    GatewayPolicyError,
    #[error("surface policy denied the request")]
    SurfacePolicyDenied { reason: Option<String> },
    #[error("surface policy could not be evaluated")]
    SurfacePolicyError,
    #[error(transparent)]
    TargetBody(#[from] UpstreamBodyError),
}

impl ForwardRefusal {
    /// The `forward-response` for the refused request. Only a surface policy
    /// refusal reads `request_body`: an MCP `tools/call` is answered with a
    /// JSON-RPC error carrying the request's id and tool name.
    pub(super) async fn into_forward_response(
        self,
        request_body: &[u8],
    ) -> ProcessingResult {
        let response_body = match self {
            Self::UnregisteredSender => forbidden("Sender is not a registered gateway"),
            Self::ChannelNotExposed => forbidden("Channel is not exposed to sender"),
            Self::AppliancePolicyDenied => forbidden("Request blocked by appliance-wide policy"),
            Self::GatewayPolicyDenied | Self::GatewayPolicyError => forbidden("Request blocked by gateway policy"),
            Self::SurfacePolicyDenied { reason } => {
                build_surface_policy_denied_forward_body(request_body, reason.as_deref())
            }
            Self::SurfacePolicyError => build_surface_policy_denied_forward_body(request_body, None),
            Self::TargetBody(error) => {
                let (status, message) = error.status_and_message();
                return axum_response_to_forward_result(crate::a2a::create_error_response(status, message)).await;
            }
        };
        ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body,
        }
    }
}

fn forbidden(message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": 403,
        "body": serde_json::json!({ "error": "Forbidden", "message": message }).to_string(),
        "error": message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn forward_response(
        refusal: ForwardRefusal,
        request_body: &[u8],
    ) -> serde_json::Value {
        match refusal
            .into_forward_response(request_body)
            .await
        {
            ProcessingResult::RequiresResponse { response_type, response_body } => {
                assert_eq!(response_type, MessageType::ForwardResponse.to_string());
                response_body
            }
            other => panic!("expected a forward-response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sender_and_gateway_policy_refusals_answer_a_generic_403() {
        for (refusal, message) in [
            (ForwardRefusal::UnregisteredSender, "Sender is not a registered gateway"),
            (ForwardRefusal::ChannelNotExposed, "Channel is not exposed to sender"),
            (ForwardRefusal::AppliancePolicyDenied, "Request blocked by appliance-wide policy"),
            (ForwardRefusal::GatewayPolicyDenied, "Request blocked by gateway policy"),
            (ForwardRefusal::GatewayPolicyError, "Request blocked by gateway policy"),
        ] {
            assert_eq!(
                forward_response(refusal, b"").await,
                json!({
                    "status": 403,
                    "body": format!(r#"{{"error":"Forbidden","message":"{message}"}}"#),
                    "error": message,
                })
            );
        }
    }

    #[tokio::test]
    async fn surface_policy_refusals_answer_from_the_request() {
        let a2a = br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#;
        let tools_call = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read"}}"#;
        for (refusal, request, expected) in [
            (
                ForwardRefusal::SurfacePolicyDenied {
                    reason: Some("not trusted".into()),
                },
                &a2a[..],
                build_surface_policy_denied_forward_body(a2a, Some("not trusted")),
            ),
            (ForwardRefusal::SurfacePolicyError, &a2a[..], build_surface_policy_denied_forward_body(a2a, None)),
            (
                ForwardRefusal::SurfacePolicyDenied { reason: None },
                &tools_call[..],
                build_surface_policy_denied_forward_body(tools_call, None),
            ),
        ] {
            assert_eq!(forward_response(refusal, request).await, expected);
        }
        let error = forward_response(ForwardRefusal::SurfacePolicyError, a2a).await;
        assert_eq!(error["status"], 403);
        assert_eq!(error["error"], "Agent trust policy denied the request");
    }

    #[tokio::test]
    async fn target_body_refusals_answer_the_bounded_read_status() {
        for (error, status, message) in [
            (UpstreamBodyError::TooLarge(10), 502, "Upstream response too large"),
            (UpstreamBodyError::TimedOut, 504, "Upstream response timed out"),
        ] {
            let response = forward_response(ForwardRefusal::from(error), b"").await;
            assert_eq!(response["status"], status);
            let body: serde_json::Value = serde_json::from_str(
                response["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["detail"], message);
            assert_eq!(response["headers"]["content-type"], "application/problem+json");
        }
    }
}
