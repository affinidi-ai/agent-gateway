use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use bytes::Bytes;

use crate::state::ProxyState;
use crate::surface_context::{McpContext, PaymentContext};

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

pub(crate) struct SurfacePayment {
    pub body: Bytes,
    pub context: Option<PaymentContext>,
    pub mpp_receipt: Option<String>,
    pub consumed: bool,
}

impl SurfacePayment {
    pub(crate) fn receipt_header(
        &self,
        x402_headers: &crate::config::types::X402Headers,
    ) -> Result<Option<(axum::http::HeaderName, axum::http::HeaderValue)>, axum::http::Error> {
        receipt_header(self.context.as_ref(), self.mpp_receipt.as_deref(), x402_headers)
    }

    /// Continuation evidence for a payment consumed by this request.
    pub(crate) fn continuation_evidence(
        &self
    ) -> Option<impl FnOnce(u64, u64) -> crate::mcp::continuations::protected::ContinuationPayment + '_> {
        use crate::mcp::continuations::protected::ContinuationPayment;

        self.consumed
            .then_some(move |verified_at, expires_at| match &self.context {
                Some(context) => ContinuationPayment::X402 {
                    receipt: context
                        .response_header
                        .clone(),
                    verified_at,
                    expires_at,
                },
                None => ContinuationPayment::Mpp {
                    receipt: self.mpp_receipt.clone(),
                    verified_at,
                    expires_at,
                },
            })
    }

    pub(crate) fn strip_consumed_mcp_argument(&mut self) -> Result<(), serde_json::Error> {
        if !self.consumed {
            return Ok(());
        }
        let mut body: serde_json::Value = serde_json::from_slice(&self.body)?;
        let field = if self.context.is_some() {
            "payment_signature"
        } else {
            "payment_credential"
        };
        if remove_payment_argument(body.get_mut("params"), field) {
            self.body = serde_json::to_vec(&body)?.into();
        }
        Ok(())
    }

    pub(crate) fn strip_consumed_headers(
        &self,
        headers: &mut HeaderMap,
        signature_header: &str,
    ) {
        if !self.consumed {
            return;
        }
        if self.context.is_some() {
            headers.remove(signature_header);
        } else if headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("Payment "))
        {
            headers.remove(axum::http::header::AUTHORIZATION);
        }
    }
}

/// The receipt header of a locally verified payment: MPP's `Payment-Receipt`,
/// or the configured x402 response header.
pub(crate) fn receipt_header(
    context: Option<&PaymentContext>,
    mpp_receipt: Option<&str>,
    x402_headers: &crate::config::types::X402Headers,
) -> Result<Option<(axum::http::HeaderName, axum::http::HeaderValue)>, axum::http::Error> {
    mpp_receipt
        .map(|receipt| ("payment-receipt", receipt))
        .or_else(|| {
            context
                .and_then(|context| {
                    context
                        .response_header
                        .as_deref()
                })
                .map(|receipt| {
                    (
                        x402_headers
                            .payment_response
                            .as_str(),
                        receipt,
                    )
                })
        })
        .map(|(name, value)| {
            Ok((axum::http::HeaderName::from_bytes(name.as_bytes())?, axum::http::HeaderValue::from_str(value)?))
        })
        .transpose()
}

pub(crate) struct LocalPayment<'surface> {
    x402: Option<&'surface crate::config::types::X402Config>,
    mpp: Option<&'surface crate::mpp::types::MppConfig>,
    signature: Option<String>,
    credential: Option<crate::mpp::types::MppCredential>,
    body: Vec<u8>,
}

impl<'surface> LocalPayment<'surface> {
    pub(crate) fn inspect(
        surface: &'surface crate::config::agent_surface::AgentSurface,
        headers: &HeaderMap,
        body: &[u8],
        mcp_context: Option<&McpContext>,
        signature_header: &str,
    ) -> Self {
        let protocol = surface.channel_protocol();
        let x402 = surface
            .x402_config()
            .filter(|config| {
                config.provider != crate::config::types::X402Provider::AgentPay
                    && crate::x402::should_require_payment(config, &protocol, body, mcp_context)
            });
        let mpp = surface
            .mpp_config()
            .filter(|config| crate::mpp::should_require_payment(config, &protocol, body, mcp_context));
        let (signature, credential, body) = if x402.is_none() && mpp.is_none() {
            (None, None, body.to_vec())
        } else if protocol == crate::config::ChannelProtocol::Mcp {
            let (signature, modified) =
                crate::x402::extract_payment_signature_with_mcp(headers, signature_header, body);
            let (credential, modified) = crate::mpp::extract_mpp_credential_with_mcp(headers, &modified);
            (signature, credential, modified)
        } else {
            (
                crate::x402::extract_payment_signature(headers, signature_header),
                crate::mpp::extract_mpp_credential(headers),
                body.to_vec(),
            )
        };
        Self {
            x402,
            mpp,
            signature,
            credential,
            body,
        }
    }

    pub(crate) fn unpaid(&self) -> bool {
        (self.x402.is_some() || self.mpp.is_some())
            && !(self.x402.is_some() && self.signature.is_some() || self.mpp.is_some() && self.credential.is_some())
    }
}

pub(super) fn is_unpaid(
    state: &ProxyState,
    headers: &HeaderMap,
    body: &[u8],
    payment: Option<&super::agent_pay_gate::Intake>,
) -> bool {
    let signature_header = &state
        .config
        .x402_headers
        .payment_signature;
    LocalPayment::inspect(&state.surface, headers, body, None, signature_header).unpaid()
        || payment.is_some_and(super::agent_pay_gate::Intake::is_unpaid)
}

pub(crate) fn request_without_local_payment(
    surface: &crate::config::agent_surface::AgentSurface,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
) -> crate::mcp::request_validation::ValidatedModernMessage {
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
    let protocol = surface.channel_protocol();
    let field = if surface
        .x402_config()
        .is_some_and(|config| crate::x402::should_require_payment(config, &protocol, &[], Some(&context)))
    {
        Some("payment_signature")
    } else if surface
        .mpp_config()
        .is_some_and(|config| crate::mpp::should_require_payment(config, &protocol, &[], Some(&context)))
    {
        Some("payment_credential")
    } else {
        None
    };
    let mut normalized = request.clone();
    if let Some(field) = field {
        remove_payment_argument(normalized.params.as_mut(), field);
    }
    if let Some(policy) = surface.agent_pay_policy()
        && super::agent_pay_gate::is_chargeable(policy, &protocol, &[], Some(&context))
    {
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

pub(super) async fn process(
    state: &ProxyState,
    headers: &HeaderMap,
    body: Bytes,
    mcp_context: Option<&McpContext>,
    resource_url: &str,
    evidence: Option<&crate::mcp::continuations::protected::ContinuationPayment>,
) -> Result<SurfacePayment, Response> {
    process_local(
        &state.surface,
        LocalPaymentServices::of(state).await,
        headers,
        body,
        mcp_context,
        resource_url,
        evidence,
    )
    .await
    .map_err(|error| error.render(&state.config.x402_headers))
}

pub(crate) struct LocalPaymentServices<'services> {
    pub x402_headers: &'services crate::config::types::X402Headers,
    pub listener_manager: Option<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>,
    pub transaction_store: Option<std::sync::Arc<crate::x402::TransactionStore>>,
    pub mpp_transaction_store: Option<std::sync::Arc<crate::mpp::transaction_store::MppTransactionStore>>,
    pub secrets_store: &'services Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
}

impl<'services> LocalPaymentServices<'services> {
    pub(super) async fn of(state: &'services ProxyState) -> Self {
        Self {
            x402_headers: &state.config.x402_headers,
            listener_manager: state
                .listener_manager
                .read()
                .await
                .clone(),
            transaction_store: state
                .transaction_store
                .clone(),
            mpp_transaction_store: state
                .mpp_transaction_store
                .clone(),
            secrets_store: &state.secrets_store,
        }
    }
}

/// Why a surface's local payment gate did not grant the request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SurfacePaymentError {
    #[error(transparent)]
    X402(#[from] crate::x402::PaymentError),
    #[error(transparent)]
    Mpp(#[from] crate::mpp::PaymentError),
    /// Both rails are offered: x402's challenge, plus MPP's when they could be
    /// issued.
    #[error("payment required")]
    Required { x402: crate::x402::PaymentChallenge, mpp: Vec<crate::mpp::MppChallenge> },
    #[error("Payment continuation unavailable")]
    ContinuationUnavailable,
    #[error("Payment continuation expired or invalid")]
    ContinuationInvalid,
    #[error("Payment continuation does not match this paywall")]
    ContinuationMismatch,
}

impl SurfacePaymentError {
    /// The HTTP answer; an x402 challenge goes in `x402_headers`'
    /// payment-required header.
    pub(crate) fn render(
        self,
        x402_headers: &crate::config::types::X402Headers,
    ) -> Response {
        use axum::http::StatusCode;

        let status = match self {
            Self::X402(error) => return error.render(x402_headers),
            Self::Mpp(error) => return error.into_response(),
            Self::Required { x402, mpp } => {
                return crate::mpp::append_challenges(x402.render(&x402_headers.payment_required), &mpp);
            }
            Self::ContinuationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ContinuationInvalid | Self::ContinuationMismatch => StatusCode::FORBIDDEN,
        };
        crate::a2a::create_error_response(status, &self.to_string())
    }
}

/// The refusal for a request that presented no payment credential: x402's
/// challenge, plus MPP's when both rails are offered, or MPP's alone. Each
/// challenge is recorded as issued. `None` when no rail is offered, so there
/// is nothing to pay.
pub(crate) async fn payment_required(
    x402: Option<&crate::config::types::X402Config>,
    mpp: Option<&crate::mpp::MppConfig>,
    channel_name: &str,
    channel_id: &str,
    resource_url: &str,
    services: &LocalPaymentServices<'_>,
) -> Option<SurfacePaymentError> {
    let Some(x402) = x402 else {
        return Some(
            crate::mpp::challenge(
                mpp?,
                channel_name,
                channel_id,
                resource_url,
                services
                    .mpp_transaction_store
                    .clone(),
                services.secrets_store,
            )
            .await
            .into(),
        );
    };
    let challenge = crate::x402::challenge(x402, channel_name, channel_id, resource_url).await;
    let Some(mpp) = mpp else {
        return Some(crate::x402::PaymentError::Required(challenge).into());
    };
    crate::mpp::fire_challenge_issued_events(
        channel_id,
        channel_name,
        resource_url,
        services
            .mpp_transaction_store
            .clone(),
    );
    Some(SurfacePaymentError::Required {
        x402: challenge,
        mpp: crate::mpp::combined_challenges(mpp, resource_url, services.secrets_store).await,
    })
}

pub(crate) async fn process_local(
    surface: &crate::config::agent_surface::AgentSurface,
    services: LocalPaymentServices<'_>,
    headers: &HeaderMap,
    body: Bytes,
    mcp_context: Option<&McpContext>,
    resource_url: &str,
    evidence: Option<&crate::mcp::continuations::protected::ContinuationPayment>,
) -> Result<SurfacePayment, SurfacePaymentError> {
    let inspected = LocalPayment::inspect(
        surface,
        headers,
        &body,
        mcp_context,
        &services
            .x402_headers
            .payment_signature,
    );
    let unpaid = inspected.unpaid();
    let LocalPayment {
        x402,
        mpp,
        signature,
        credential,
        body: modified,
    } = inspected;
    let mut payment = SurfacePayment {
        body,
        context: None,
        mpp_receipt: None,
        consumed: false,
    };
    if let Some(evidence) = evidence {
        use crate::mcp::continuations::protected::ContinuationPayment;

        let now = crate::proxy::credential_delegation::modern::now_secs()
            .map_err(|_| SurfacePaymentError::ContinuationUnavailable)?;
        evidence
            .validate(now)
            .map_err(|_| SurfacePaymentError::ContinuationInvalid)?;
        match evidence {
            ContinuationPayment::X402 { receipt, .. } if x402.is_some() => {
                payment.context = Some(PaymentContext {
                    required: true,
                    response_header: receipt.clone(),
                    ..Default::default()
                });
            }
            ContinuationPayment::Mpp { receipt, .. } if mpp.is_some() => {
                payment.mpp_receipt = receipt.clone();
            }
            ContinuationPayment::AgentPay { .. }
                if surface
                    .agent_pay_policy()
                    .is_some() =>
            {
                return Ok(payment);
            }
            _ => return Err(SurfacePaymentError::ContinuationMismatch),
        }
        payment.consumed = true;
        return Ok(payment);
    }
    if x402.is_none() && mpp.is_none() {
        return Ok(payment);
    }
    let name = &surface.name;
    let id = &surface.surface_id;
    if let Some(config) = x402
        && !unpaid
        && signature.is_some()
    {
        let response_header = crate::x402::process_payment(
            signature,
            config,
            name,
            id,
            resource_url,
            services
                .listener_manager
                .clone(),
            services
                .transaction_store
                .clone(),
        )
        .await?;
        payment.body = modified.into();
        payment.consumed = true;
        payment.context = Some(PaymentContext {
            required: true,
            response_header,
            ..Default::default()
        });
        return Ok(payment);
    }
    if let Some(config) = mpp
        && !unpaid
        && credential.is_some()
    {
        payment.mpp_receipt = crate::mpp::process_payment(
            credential,
            config,
            name,
            id,
            resource_url,
            services
                .mpp_transaction_store
                .clone(),
            services.secrets_store,
        )
        .await?;
        payment.body = modified.into();
        payment.consumed = true;
        return Ok(payment);
    }
    match payment_required(x402, mpp, name, id, resource_url, &services).await {
        Some(error) => Err(error),
        None => Ok(payment),
    }
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

    #[tokio::test]
    async fn payment_reuse_requires_current_evidence_for_the_same_local_rail() {
        use crate::mcp::continuations::protected::ContinuationPayment;

        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "paid", "name": "Paid", "access_point": {
                "listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"
            }, "target": {"endpoint": "https://target.example/mcp",
                "payment_policy": {"type": "x402", "enabled": true, "mcp_payment_triggers": {"mode": "all"}}}
        }))
        .unwrap();
        let body = Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"charge"}}"#);
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let config = crate::config::types::X402Headers::default();
        let headers = HeaderMap::new();
        let secrets = None;
        let services = || LocalPaymentServices {
            x402_headers: &config,
            listener_manager: None,
            transaction_store: None,
            mpp_transaction_store: None,
            secrets_store: &secrets,
        };
        for (evidence, expected) in [
            (
                ContinuationPayment::X402 {
                    receipt: None,
                    verified_at: now - 60,
                    expires_at: now,
                },
                "expired or invalid",
            ),
            (
                ContinuationPayment::Mpp {
                    receipt: Some("receipt".into()),
                    verified_at: now,
                    expires_at: now + 60,
                },
                "does not match this paywall",
            ),
        ] {
            let result =
                process_local(&surface, services(), &headers, body.clone(), None, "/mcp", Some(&evidence)).await;
            match result {
                Err(error @ (SurfacePaymentError::ContinuationInvalid | SurfacePaymentError::ContinuationMismatch)) => {
                    assert!(
                        error
                            .to_string()
                            .contains(expected),
                        "{error}"
                    )
                }
                other => panic!("invalid evidence must be rejected, got {:?}", other.err()),
            }
        }
        let evidence = ContinuationPayment::X402 {
            receipt: Some("saved-receipt".into()),
            verified_at: now,
            expires_at: now + 60,
        };
        let reused = process_local(&surface, services(), &headers, body.clone(), None, "/mcp", Some(&evidence))
            .await
            .unwrap_or_else(|error| panic!("valid evidence rejected: {error:?}"));
        assert!(reused.consumed);
        assert_eq!(
            reused
                .receipt_header(&config)
                .unwrap()
                .unwrap()
                .1,
            "saved-receipt"
        );
        surface.target.payment_policy = None;
        let result = process_local(&surface, services(), &headers, body, None, "/mcp", Some(&evidence)).await;
        assert!(
            matches!(result, Err(SurfacePaymentError::ContinuationMismatch)),
            "removed paywall must not accept evidence"
        );
    }

    fn mpp_config() -> crate::mpp::MppConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "realm": "gateway.example",
            "secret_key": "dGVzdC1zZWNyZXQtMzItYnl0ZXMtbG9uZyEhISEhISE=",
            "payment_methods": [{
                "method": "tempo", "intent": "charge", "currency": "usd",
                "recipient": "0xrecipient", "amount": "1.00"
            }]
        }))
        .unwrap()
    }

    async fn rendered(error: SurfacePaymentError) -> Response {
        let headers = crate::config::types::X402Headers::default();
        error.render(&headers)
    }

    #[tokio::test]
    async fn a_request_without_a_credential_gets_each_offered_rails_challenge() {
        let x402 = crate::config::types::X402Config {
            enabled: true,
            ..Default::default()
        };
        let mpp = mpp_config();
        let secrets = None;
        let x402_headers = crate::config::types::X402Headers::default();
        let services = LocalPaymentServices {
            x402_headers: &x402_headers,
            listener_manager: None,
            transaction_store: None,
            mpp_transaction_store: None,
            secrets_store: &secrets,
        };
        let required = |x402, mpp| payment_required(x402, mpp, "Paid", "paid", "/mcp", &services);

        assert!(
            required(None, None)
                .await
                .is_none(),
            "no rail offered, nothing to pay"
        );
        assert!(matches!(
            required(Some(&x402), None).await,
            Some(SurfacePaymentError::X402(crate::x402::PaymentError::Required(_)))
        ));
        assert!(matches!(
            required(None, Some(&mpp)).await,
            Some(SurfacePaymentError::Mpp(crate::mpp::PaymentError::Required(_)))
        ));
        let Some(both @ SurfacePaymentError::Required { .. }) = required(Some(&x402), Some(&mpp)).await else {
            panic!("both rails must be offered together");
        };
        let response = rendered(both).await;
        assert_eq!(response.status(), axum::http::StatusCode::PAYMENT_REQUIRED);
        assert!(
            response
                .headers()
                .contains_key(
                    x402_headers
                        .payment_required
                        .as_str()
                )
        );
        assert!(
            response.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .starts_with("Payment id=\"")
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["content-type"], "application/json");
    }

    #[tokio::test]
    async fn continuation_refusals_render_their_status() {
        for (error, status) in [
            (SurfacePaymentError::ContinuationUnavailable, axum::http::StatusCode::SERVICE_UNAVAILABLE),
            (SurfacePaymentError::ContinuationInvalid, axum::http::StatusCode::FORBIDDEN),
            (SurfacePaymentError::ContinuationMismatch, axum::http::StatusCode::FORBIDDEN),
        ] {
            let message = error.to_string();
            let response = rendered(error).await;
            assert_eq!(response.status(), status);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["detail"], message);
        }
    }

    #[test]
    fn continuation_normalization_excludes_only_the_active_local_payment_field() {
        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "paid", "name": "Paid", "access_point": {
                "listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"
            }, "target": {"endpoint": "https://target.example/mcp",
                "payment_policy": {"type": "x402", "enabled": true, "mcp_payment_triggers": {"mode": "all"}}}
        }))
        .unwrap();
        let request = crate::mcp::request_validation::ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "tools/call".into(),
            params: Some(json!({"name": "charge", "arguments": {"value": 7, "payment_signature": "first",
                "payment_credential": "other-rail", "nested": {"payment_signature": "business-value"}}})),
            id: Some(json!(1)),
            kind: crate::mcp::request_validation::McpMessageKind::Request,
        };
        let normalized = request_without_local_payment(&surface, &request);
        let digest = crate::mcp::continuations::protected::request_arguments_digest(&normalized).unwrap();
        for value in [serde_json::Value::Null, json!("second")] {
            let mut retry = request.clone();
            retry.params.as_mut().unwrap()["arguments"]["payment_signature"] = value;
            assert_eq!(
                crate::mcp::continuations::protected::request_arguments_digest(&request_without_local_payment(
                    &surface, &retry
                ))
                .unwrap(),
                digest
            );
        }
        let mut changed = request.clone();
        changed
            .params
            .as_mut()
            .unwrap()["arguments"]["value"] = json!(8);
        assert_ne!(
            crate::mcp::continuations::protected::request_arguments_digest(&request_without_local_payment(
                &surface, &changed
            ))
            .unwrap(),
            digest
        );
        assert_eq!(
            normalized
                .params
                .as_ref()
                .unwrap()["arguments"]["payment_credential"],
            "other-rail"
        );
        assert_eq!(
            normalized
                .params
                .as_ref()
                .unwrap()["arguments"]["nested"]["payment_signature"],
            "business-value"
        );
        for policy in [
            json!({"type": "x402", "enabled": false, "mcp_payment_triggers": {"mode": "all"}}),
            json!({"type": "x402", "mcp_payment_triggers": {"mode": "match", "patterns": ["^other$"]}}),
            json!({"type": "agent_pay", "mcp_payment_triggers": {"mode": "match", "patterns": ["^other$"]}}),
        ] {
            surface.target.payment_policy = Some(serde_json::from_value(policy).unwrap());
            assert_eq!(request_without_local_payment(&surface, &request).params, request.params);
        }
        surface.target.payment_policy = Some(
            serde_json::from_value(json!({"type": "agent_pay", "mcp_payment_triggers": {"mode": "all"}})).unwrap(),
        );
        let mut paid = request.clone();
        paid.params.as_mut().unwrap()["_meta"] = json!({"org.paymentauth/credential": "proof", "progressToken": 1});
        let normalized = request_without_local_payment(&surface, &paid);
        let params = normalized
            .params
            .as_ref()
            .unwrap();
        assert_eq!(params["arguments"], json!({"value": 7, "nested": {"payment_signature": "business-value"}}));
        assert_eq!(params["_meta"], json!({"progressToken": 1}));
        surface.target.payment_policy = Some(crate::config::agent_surface::PaymentPolicy::Mpp(crate::mpp::MppConfig {
            mcp_payment_triggers: Some(crate::config::types::McpPaymentTriggers::All),
            ..Default::default()
        }));
        let normalized = request_without_local_payment(&surface, &request);
        let arguments = &normalized
            .params
            .as_ref()
            .unwrap()["arguments"];
        assert!(
            arguments
                .get("payment_credential")
                .is_none()
        );
        assert_eq!(arguments["payment_signature"], "first");
    }

    #[test]
    fn receipt_headers_follow_the_payment_rail_and_validate_wire_values() {
        let mut payment = SurfacePayment {
            body: Bytes::new(),
            context: None,
            mpp_receipt: None,
            consumed: false,
        };
        let config = crate::config::types::X402Headers {
            payment_response: "x-local-x402-receipt".into(),
            ..Default::default()
        };
        assert!(
            payment
                .receipt_header(&config)
                .unwrap()
                .is_none()
        );
        payment.context = Some(PaymentContext {
            required: true,
            response_header: Some("x402-receipt".into()),
            ..Default::default()
        });
        let (name, value) = payment
            .receipt_header(&config)
            .unwrap()
            .unwrap();
        assert_eq!(name, "x-local-x402-receipt");
        assert_eq!(value, "x402-receipt");
        payment.context = None;
        payment.mpp_receipt = Some("mpp-receipt".into());
        let (name, value) = payment
            .receipt_header(&config)
            .unwrap()
            .unwrap();
        assert_eq!(name, "payment-receipt");
        assert_eq!(value, "mpp-receipt");
        payment.mpp_receipt = Some("invalid\r\nreceipt".into());
        assert!(
            payment
                .receipt_header(&config)
                .is_err()
        );
    }

    #[test]
    fn consumed_payment_cleanup_preserves_business_arguments_and_other_rails() {
        for x402 in [true, false] {
            let mut payment = SurfacePayment {
                body: serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "charge", "arguments": {"value": 7, "payment_signature": "signature",
                        "payment_credential": "credential", "nested": {"payment_signature": "business-value"}}
                }}))
                .unwrap()
                .into(),
                context: x402.then_some(PaymentContext {
                    required: true,
                    response_header: None,
                    ..Default::default()
                }),
                mpp_receipt: None,
                consumed: false,
            };
            let original = payment.body.clone();
            payment
                .strip_consumed_mcp_argument()
                .unwrap();
            assert_eq!(payment.body, original);
            payment.consumed = true;
            let mut headers = HeaderMap::new();
            headers.insert("payment-signature", "signature".parse().unwrap());
            headers.insert(
                "authorization",
                "Payment credential"
                    .parse()
                    .unwrap(),
            );
            payment
                .strip_consumed_mcp_argument()
                .unwrap();
            payment.strip_consumed_headers(&mut headers, "PAYMENT-SIGNATURE");
            let body: serde_json::Value = serde_json::from_slice(&payment.body).unwrap();
            let arguments = &body["params"]["arguments"];
            assert_eq!(arguments["value"], 7);
            assert_eq!(arguments["nested"]["payment_signature"], "business-value");
            assert_eq!(
                arguments
                    .get("payment_signature")
                    .is_none(),
                x402
            );
            assert_eq!(
                arguments
                    .get("payment_credential")
                    .is_none(),
                !x402
            );
            assert_eq!(headers.contains_key("payment-signature"), !x402);
            assert_eq!(headers.contains_key("authorization"), x402);
        }
    }

    #[test]
    fn unpaid_inspection_never_mistakes_supplied_credentials_for_a_challenge() {
        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "paid", "name": "Paid", "access_point": {
                "listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"
            }, "target": {"endpoint": "https://target.example/mcp",
                "payment_policy": {"type": "x402", "enabled": true, "mcp_payment_triggers": {"mode": "all"}}}
        }))
        .unwrap();
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"charge"}}"#;
        let mut headers = HeaderMap::new();
        assert!(LocalPayment::inspect(&surface, &headers, body, None, "payment-signature").unpaid());
        headers.insert(
            "payment-signature",
            "unverified-credential"
                .parse()
                .unwrap(),
        );
        let supplied = LocalPayment::inspect(&surface, &headers, body, None, "payment-signature");
        assert!(!supplied.unpaid());
        assert_eq!(supplied.signature.as_deref(), Some("unverified-credential"));
        let listing = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert!(!LocalPayment::inspect(&surface, &HeaderMap::new(), listing, None, "payment-signature").unpaid());
        surface.target.payment_policy = None;
        assert!(!LocalPayment::inspect(&surface, &HeaderMap::new(), body, None, "payment-signature").unpaid());
    }
}
