use axum::response::Response;

use crate::mcp::continuations::protected::ContinuationPayment;
use crate::surface_context::McpContext;

/// `503 {"error":"payment_unavailable"}` for a surface whose payment policy is
/// an enabled local x402 or MPP policy, which is no longer supported. Such a
/// surface refuses every request, over HTTP and over the fabric, until its
/// policy is pointed at an agent-pay surface.
pub(crate) fn legacy_payment_unavailable(
    surface: &crate::config::agent_surface::AgentSurface,
    via_fabric: bool,
) -> Option<Response> {
    use axum::response::IntoResponse;

    if !surface.payment_policy_unsupported() {
        return None;
    }
    super::agent_pay_gate::record_legacy_refusal(surface, via_fabric);
    tracing::warn!(
        surface = %surface.name,
        surface_id = %surface.surface_id,
        "Refusing request: the surface uses local x402/MPP payment, which is no longer supported"
    );
    Some(
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "error": "payment_unavailable" })),
        )
            .into_response(),
    )
}

/// The refusal of a continuation round whose recorded payment this surface
/// cannot accept: `403` for an expired or malformed one, or one that is not an
/// agent-pay payment for a surface that charges through agent-pay, and `503`
/// when the clock cannot be read. `None` when the round holds no payment or a
/// current agent-pay payment.
pub(crate) fn continuation_payment_refusal(
    surface: &crate::config::agent_surface::AgentSurface,
    evidence: Option<&ContinuationPayment>,
) -> Option<Response> {
    let evidence = evidence?;
    let (status, message) = match crate::proxy::credential_delegation::modern::now_secs() {
        Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Payment continuation unavailable"),
        Ok(now)
            if evidence
                .validate(now)
                .is_err() =>
        {
            (axum::http::StatusCode::FORBIDDEN, "Payment continuation expired or invalid")
        }
        Ok(_)
            if matches!(evidence, ContinuationPayment::AgentPay { .. })
                && surface
                    .agent_pay_policy()
                    .is_some() =>
        {
            return None;
        }
        Ok(_) => (axum::http::StatusCode::FORBIDDEN, "Payment continuation does not match this paywall"),
    };
    Some(crate::a2a::create_error_response(status, message))
}

/// The request a continuation is bound to: a chargeable MCP request without
/// the payment credentials its caller may send again on a later round.
pub(crate) fn request_without_payment_credentials(
    surface: &crate::config::agent_surface::AgentSurface,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
) -> crate::mcp::request_validation::ValidatedModernMessage {
    let mut normalized = request.clone();
    let Some(policy) = surface.agent_pay_policy() else { return normalized };
    let context = McpContext {
        method: request.method.clone(),
        tool_name: request
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        ..Default::default()
    };
    if super::agent_pay_gate::is_chargeable(policy, &surface.channel_protocol(), &[], Some(&context)) {
        super::agent_pay_gate::remove_mcp_credentials(normalized.params.as_mut());
    }
    normalized
}

pub(super) fn remove_payment_argument(
    params: Option<&mut serde_json::Value>,
    field: &str,
) -> bool {
    let Some(params) = params.and_then(serde_json::Value::as_object_mut) else { return false };
    let Some(arguments) = params
        .get_mut("arguments")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return false;
    };
    let removed = arguments
        .remove(field)
        .is_some();
    if removed && arguments.is_empty() {
        params.remove("arguments");
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn surface_with(policy: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
        let mut surface = crate::config::agent_surface::AgentSurface::default();
        surface.target.payment_policy = Some(serde_json::from_value(policy).unwrap());
        surface
    }

    #[tokio::test]
    async fn a_local_payment_surface_answers_503_payment_unavailable() {
        for policy in [json!({"type": "x402"}), json!({"type": "mpp", "realm": "api", "secret_key": "$MPP_SECRET"})] {
            let response =
                legacy_payment_unavailable(&surface_with(policy), false).expect("legacy policy must fail closed");
            assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"error": "payment_unavailable"})
            );
        }
    }

    #[test]
    fn agent_pay_disabled_and_free_surfaces_are_not_refused() {
        assert!(
            legacy_payment_unavailable(
                &surface_with(
                    json!({"type": "agent_pay", "payment_gateway_id": "gw-1", "payment_surface_id": "pay-1"})
                ),
                false,
            )
            .is_none()
        );
        assert!(legacy_payment_unavailable(&surface_with(json!({"type": "x402", "enabled": false})), false).is_none());
        assert!(legacy_payment_unavailable(&crate::config::agent_surface::AgentSurface::default(), false).is_none());
    }

    fn mcp_surface(policy: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "paid", "name": "Paid", "access_point": {
                "listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"
            }, "target": {"endpoint": "https://target.example/mcp", "payment_policy": policy}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_continuation_round_reuses_only_a_current_agent_pay_payment() {
        use crate::mcp::continuations::protected::ContinuationPayment;

        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let agent_pay = |verified_at, expires_at| ContinuationPayment::AgentPay {
            scheme: "x402".into(),
            receipt: Some("receipt".into()),
            vc_fingerprint: None,
            verified_at,
            expires_at,
        };
        let paid = mcp_surface(json!({"type": "agent_pay", "payment_gateway_id": "gw-1",
            "payment_surface_id": "pay-1", "mcp_payment_triggers": {"mode": "all"}}));
        assert!(continuation_payment_refusal(&paid, None).is_none());
        assert!(continuation_payment_refusal(&paid, Some(&agent_pay(now, now + 60))).is_none());

        let local = ContinuationPayment::X402 {
            receipt: Some("receipt".into()),
            verified_at: now,
            expires_at: now + 60,
        };
        for (surface, evidence, detail) in [
            (&paid, agent_pay(now - 120, now - 60), "Payment continuation expired or invalid"),
            (&paid, local, "Payment continuation does not match this paywall"),
            (&mcp_surface(json!(null)), agent_pay(now, now + 60), "Payment continuation does not match this paywall"),
        ] {
            let response = continuation_payment_refusal(surface, Some(&evidence)).expect("evidence must be refused");
            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["detail"], detail);
        }
    }

    #[test]
    fn a_continuation_binds_a_chargeable_request_without_its_payment_credentials() {
        let request = crate::mcp::request_validation::ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "tools/call".into(),
            params: Some(json!({"name": "charge", "arguments": {"value": 7, "payment_signature": "first",
                "payment_credential": "other-rail", "nested": {"payment_signature": "business-value"}},
                "_meta": {"org.paymentauth/credential": "proof", "progressToken": 1}})),
            id: Some(json!(1)),
            kind: crate::mcp::request_validation::McpMessageKind::Request,
        };
        let paid = mcp_surface(json!({"type": "agent_pay", "mcp_payment_triggers": {"mode": "all"}}));
        let normalized = request_without_payment_credentials(&paid, &request);
        let params = normalized
            .params
            .as_ref()
            .unwrap();
        assert_eq!(params["arguments"], json!({"value": 7, "nested": {"payment_signature": "business-value"}}));
        assert_eq!(params["_meta"], json!({"progressToken": 1}));

        for policy in [
            json!({"type": "agent_pay", "mcp_payment_triggers": {"mode": "match", "patterns": ["^other$"]}}),
            json!({"type": "x402", "enabled": false, "mcp_payment_triggers": {"mode": "all"}}),
            json!({"type": "x402", "enabled": true, "mcp_payment_triggers": {"mode": "all"}}),
            json!(null),
        ] {
            assert_eq!(
                request_without_payment_credentials(&mcp_surface(policy), &request).params,
                request.params,
                "only a chargeable agent-pay request drops its credentials"
            );
        }
    }
}
