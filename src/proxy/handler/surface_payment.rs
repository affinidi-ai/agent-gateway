use axum::{http::HeaderMap, response::Response};
use bytes::Bytes;

use crate::state::ProxyState;
use crate::surface_context::{McpContext, PaymentContext};

pub(super) enum DelegatedPayment {
    Proceed(std::collections::HashMap<String, Vec<String>>),
    Challenge(Response),
    Denied(Response),
}

fn modern_delegation_decision(
    decision: crate::x402::PaymentDelegationDecision,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
) -> crate::x402::PaymentDelegationDecision {
    use crate::mcp::errors::application_error_codes;
    use crate::x402::PaymentDelegationDecision;

    let PaymentDelegationDecision::Challenge { status, mut headers, mut body } = decision else {
        return decision;
    };
    headers.retain(|name, _| !name.eq_ignore_ascii_case("cache-control"));
    headers.insert("cache-control".into(), vec!["no-store".into()]);
    if let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&body)
        && envelope
            .get("jsonrpc")
            .and_then(serde_json::Value::as_str)
            == Some("2.0")
        && let Some(code) = envelope
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(serde_json::Value::as_i64)
        && matches!(code, -32042 | -32043)
    {
        let (code, message) = if code == -32042 {
            (application_error_codes::PAYMENT_REQUIRED, "Payment required")
        } else {
            (application_error_codes::PAYMENT_REJECTED, "Payment rejected")
        };
        let error = crate::mcp::errors::create_mcp_error_envelope(
            request.id.clone(),
            code,
            message,
            envelope
                .get("error")
                .and_then(|error| error.get("data"))
                .cloned(),
        );
        let Ok(encoded) = serde_json::to_vec(&error) else {
            return PaymentDelegationDecision::deny(502, "Invalid delegated payment challenge");
        };
        body = encoded;
        headers.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
        headers.insert("content-type".into(), vec!["application/json".into()]);
    }
    PaymentDelegationDecision::Challenge { status, headers, body }
}

fn delegation_headers(
    surface: &crate::config::agent_surface::AgentSurface,
    headers: &HeaderMap,
) -> std::collections::HashMap<String, String> {
    let source_credential = surface
        .source_auth()
        .and_then(|auth| auth.credential_header_name());
    let resource_authorization = surface
        .mcp_http
        .as_ref()
        .is_some_and(|http| http.authorization.is_some());
    headers
        .iter()
        .filter_map(|(name, value)| {
            if source_credential.is_some_and(|credential| {
                name.as_str()
                    .eq_ignore_ascii_case(credential)
            }) || resource_authorization && name == axum::http::header::AUTHORIZATION
            {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_uppercase(), value.to_string()))
        })
        .collect()
}

pub(super) async fn delegate(
    state: &ProxyState,
    headers: &HeaderMap,
    body: Bytes,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    trace_id: &str,
    channel_name: &str,
    modern_request: Option<&crate::mcp::request_validation::ValidatedModernMessage>,
) -> DelegatedPayment {
    use crate::x402::PaymentDelegationDecision;
    use axum::http::StatusCode;

    let Some(config) = state
        .surface
        .x402_config()
        .filter(|config| config.enabled && config.provider == crate::config::types::X402Provider::AgentPay)
    else {
        return DelegatedPayment::Proceed(std::collections::HashMap::new());
    };
    let id = &state.surface.surface_id;
    let target = match crate::x402::delegation_target(config) {
        Ok(target) => target,
        Err(reason) => {
            super::audit_payment_delegation(
                id,
                channel_name,
                trace_id,
                super::map_delegated_rail(&config.delegated_rail),
                config
                    .payment_gateway_id
                    .as_deref()
                    .unwrap_or_default(),
                config
                    .payment_surface_id
                    .as_deref()
                    .unwrap_or_default(),
                "misconfigured",
                502,
                Some(&reason),
            )
            .await;
            return DelegatedPayment::Denied(crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, &reason));
        }
    };
    let forwarded_headers = delegation_headers(&state.surface, headers);
    let timeout = state
        .surface
        .timeout()
        .map(|timeout| timeout.request_secs)
        .unwrap_or(
            state
                .config
                .a2a
                .message_expires_seconds,
        );
    let decision = match crate::proxy::fabric_forward::forward_via_fabric(
        &state.listener_manager,
        crate::proxy::fabric_forward::FabricForwardRequest {
            fabric_target: &target,
            method,
            path: uri
                .path_and_query()
                .map(|path| path.as_str())
                .unwrap_or("/"),
            headers: forwarded_headers,
            body,
            timeout: std::time::Duration::from_secs(timeout.max(1)),
            trace_id,
            log_label: channel_name,
        },
    )
    .await
    {
        Ok(response) => crate::x402::map_delegation_response(response.status, response.headers, response.body),
        Err(error) => {
            let status = if matches!(error, crate::proxy::fabric_forward::FabricForwardError::NoResponse(_)) {
                504
            } else {
                502
            };
            PaymentDelegationDecision::deny(status, format!("payment delegation to {target} failed: {error}"))
        }
    };
    let decision = match modern_request {
        Some(request) => modern_delegation_decision(decision, request),
        None => decision,
    };
    let (outcome, status, reason) = match &decision {
        PaymentDelegationDecision::Proceed { .. } => ("proceed", 200, None),
        PaymentDelegationDecision::Challenge { status, .. } => ("challenge", *status, None),
        PaymentDelegationDecision::Deny { status, message } => ("deny", *status, Some(message.as_str())),
    };
    super::audit_payment_delegation(
        id,
        channel_name,
        trace_id,
        super::map_delegated_rail(&config.delegated_rail),
        config
            .payment_gateway_id
            .as_deref()
            .unwrap_or_default(),
        config
            .payment_surface_id
            .as_deref()
            .unwrap_or_default(),
        outcome,
        status,
        reason,
    )
    .await;
    match decision {
        PaymentDelegationDecision::Proceed { receipt_headers } => DelegatedPayment::Proceed(receipt_headers),
        PaymentDelegationDecision::Challenge { status, headers, body } => {
            let mut response =
                Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::PAYMENT_REQUIRED));
            for (name, values) in headers {
                for value in values {
                    response = response.header(&name, value);
                }
            }
            DelegatedPayment::Challenge(
                response
                    .body(axum::body::Body::from(body))
                    .unwrap_or_else(|_| {
                        crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, "Failed to relay payment challenge")
                    }),
            )
        }
        PaymentDelegationDecision::Deny { status, message } => {
            DelegatedPayment::Denied(crate::a2a::create_error_response(
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                &message,
            ))
        }
    }
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
        let receipt = self
            .mpp_receipt
            .as_deref()
            .map(|receipt| ("payment-receipt", receipt))
            .or_else(|| {
                self.context
                    .as_ref()
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
            });
        receipt
            .map(|(name, value)| {
                Ok((axum::http::HeaderName::from_bytes(name.as_bytes())?, axum::http::HeaderValue::from_str(value)?))
            })
            .transpose()
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
) -> bool {
    LocalPayment::inspect(
        &state.surface,
        headers,
        body,
        None,
        &state
            .config
            .x402_headers
            .payment_signature,
    )
    .unpaid()
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
    normalized
}

fn remove_payment_argument(
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
    if arguments.is_empty() {
        params.remove("arguments");
        return true;
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
        LocalPaymentServices {
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
        },
        headers,
        body,
        mcp_context,
        resource_url,
        evidence,
    )
    .await
}

pub(crate) struct LocalPaymentServices<'services> {
    pub x402_headers: &'services crate::config::types::X402Headers,
    pub listener_manager: Option<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>,
    pub transaction_store: Option<std::sync::Arc<crate::x402::TransactionStore>>,
    pub mpp_transaction_store: Option<std::sync::Arc<crate::mpp::transaction_store::MppTransactionStore>>,
    pub secrets_store: &'services Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
}

pub(crate) async fn process_local(
    surface: &crate::config::agent_surface::AgentSurface,
    services: LocalPaymentServices<'_>,
    headers: &HeaderMap,
    body: Bytes,
    mcp_context: Option<&McpContext>,
    resource_url: &str,
    evidence: Option<&crate::mcp::continuations::protected::ContinuationPayment>,
) -> Result<SurfacePayment, Response> {
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

        let now = crate::proxy::credential_delegation::modern::now_secs().map_err(|_| {
            crate::a2a::create_error_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Payment continuation unavailable",
            )
        })?;
        evidence
            .validate(now)
            .map_err(|_| {
                crate::a2a::create_error_response(
                    axum::http::StatusCode::FORBIDDEN,
                    "Payment continuation expired or invalid",
                )
            })?;
        match evidence {
            ContinuationPayment::X402 { receipt, .. } if x402.is_some() => {
                payment.context = Some(PaymentContext {
                    verified: true,
                    response_header: receipt.clone(),
                });
            }
            ContinuationPayment::Mpp { receipt, .. } if mpp.is_some() => {
                payment.mpp_receipt = receipt.clone();
            }
            _ => {
                return Err(crate::a2a::create_error_response(
                    axum::http::StatusCode::FORBIDDEN,
                    "Payment continuation does not match this paywall",
                ));
            }
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
            services.x402_headers,
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
            verified: true,
            response_header,
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
    if let Some(config) = x402 {
        let response = crate::x402::process_payment(
            None,
            config,
            name,
            id,
            services.x402_headers,
            resource_url,
            services
                .listener_manager
                .clone(),
            services
                .transaction_store
                .clone(),
        )
        .await
        .unwrap_err();
        return Err(if let Some(config) = mpp {
            crate::mpp::fire_challenge_issued_events(
                id,
                name,
                resource_url,
                services
                    .mpp_transaction_store
                    .clone(),
            );
            crate::mpp::errors::add_mpp_challenges_to_response_resolved(
                response,
                config,
                resource_url,
                services.secrets_store,
            )
            .await
        } else {
            response
        });
    }
    if let Some(config) = mpp {
        return Err(crate::mpp::process_payment(
            None,
            config,
            name,
            id,
            resource_url,
            services
                .mpp_transaction_store
                .clone(),
            services.secrets_store,
        )
        .await
        .unwrap_err());
    }
    Ok(payment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn modern_delegated_challenges_replace_only_retired_payment_codes() {
        use crate::x402::PaymentDelegationDecision;

        let request = crate::mcp::request_validation::ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "tools/call".into(),
            params: Some(json!({"name": "charge"})),
            id: Some(json!("caller-request")),
            kind: crate::mcp::request_validation::McpMessageKind::Request,
        };
        for (legacy_code, expected_code) in [(-32042, 1001), (-32043, 1002), (7001, 7001)] {
            let body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": "delegate-request", "error": {
                "code": legacy_code, "message": "Provider message", "data": {"challenges": [], "retry": true}
            }}))
            .unwrap();
            let decision = crate::x402::map_delegation_response(
                402,
                std::collections::HashMap::from([
                    ("WWW-Authenticate".into(), vec!["Payment id=one".into(), "Payment id=two".into()]),
                    ("Cache-Control".into(), vec!["public".into()]),
                ]),
                body.clone(),
            );
            let PaymentDelegationDecision::Challenge { status, headers, body: mapped } =
                modern_delegation_decision(decision, &request)
            else {
                panic!("expected challenge")
            };
            assert_eq!(status, 402);
            assert_eq!(headers["WWW-Authenticate"], vec!["Payment id=one", "Payment id=two"]);
            assert_eq!(headers["cache-control"], vec!["no-store"]);
            assert!(!headers.contains_key("Cache-Control"));
            let envelope: serde_json::Value = serde_json::from_slice(&mapped).unwrap();
            assert_eq!(envelope["error"]["code"], expected_code);
            assert_eq!(envelope["error"]["data"], json!({"challenges": [], "retry": true}));
            if legacy_code == 7001 {
                assert_eq!(mapped, body);
            } else {
                assert_eq!(envelope["id"], "caller-request");
                assert!(
                    envelope
                        .get("result")
                        .is_none()
                );
                assert_eq!(headers["content-type"], vec!["application/json"]);
            }
        }
        let denied = PaymentDelegationDecision::deny(502, "failed");
        assert_eq!(modern_delegation_decision(denied.clone(), &request), denied);
    }

    #[test]
    fn delegated_payment_strips_resource_bearers_without_dropping_payment_headers() {
        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "paid", "name": "Paid", "access_point": {
                "listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"
            }, "target": {"endpoint": "https://target.example/mcp"},
            "mcp_http": {"authorization": {"resource": "https://gateway.example/mcp", "scopes": ["read"]}}
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer ingress-resource-token"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "payment-signature",
            "payment-proof"
                .parse()
                .unwrap(),
        );
        let delegated = delegation_headers(&surface, &headers);
        assert!(!delegated.contains_key("AUTHORIZATION"));
        assert_eq!(
            delegated
                .get("PAYMENT-SIGNATURE")
                .map(String::as_str),
            Some("payment-proof")
        );
        surface.mcp_http = None;
        headers.insert(
            "authorization",
            "Payment legacy-credential"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            delegation_headers(&surface, &headers)
                .get("AUTHORIZATION")
                .map(String::as_str),
            Some("Payment legacy-credential")
        );
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
        for evidence in [
            ContinuationPayment::X402 {
                receipt: None,
                verified_at: now - 60,
                expires_at: now,
            },
            ContinuationPayment::Mpp {
                receipt: Some("receipt".into()),
                verified_at: now,
                expires_at: now + 60,
            },
        ] {
            let result =
                process_local(&surface, services(), &headers, body.clone(), None, "/mcp", Some(&evidence)).await;
            assert_eq!(
                result
                    .err()
                    .expect("invalid evidence must be rejected")
                    .status(),
                axum::http::StatusCode::FORBIDDEN
            );
        }
        let evidence = ContinuationPayment::X402 {
            receipt: Some("saved-receipt".into()),
            verified_at: now,
            expires_at: now + 60,
        };
        let reused = process_local(&surface, services(), &headers, body.clone(), None, "/mcp", Some(&evidence))
            .await
            .unwrap_or_else(|response| panic!("valid evidence rejected: {}", response.status()));
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
        assert_eq!(
            result
                .err()
                .expect("removed paywall must not accept evidence")
                .status(),
            axum::http::StatusCode::FORBIDDEN
        );
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
            json!({"type": "x402", "provider": "agent_pay", "mcp_payment_triggers": {"mode": "all"}}),
            json!({"type": "x402", "mcp_payment_triggers": {"mode": "match", "patterns": ["^other$"]}}),
        ] {
            surface.target.payment_policy = Some(serde_json::from_value(policy).unwrap());
            assert_eq!(request_without_local_payment(&surface, &request).params, request.params);
        }
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
            verified: true,
            response_header: Some("x402-receipt".into()),
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
                    verified: true,
                    response_header: None,
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
