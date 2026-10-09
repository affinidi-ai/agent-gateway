//! Shared transport for forwarding a request to a remote gateway over the
//! `fabric://` (gateway-to-gateway) protocol.
//!
//! The inbound proxy already forwards `fabric://` targets via the bespoke
//! `handle_fabric_request` flow (which also performs inbound identity / policy
//! work). This module exposes the *transport core* on its own so the outbound
//! transit-point pipeline can ship a fully-prepared request (body and headers
//! already transformed by the pipeline) to a remote gateway channel and
//! synchronously await the `ForwardResponse`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::http::Method;
use bytes::Bytes;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::gateways::ConnectionPointListenerManager;

/// Lifetime, in seconds, of a capability query's envelope. The sender waits
/// at most a few seconds for the answer; the rest leaves room for clock skew
/// between the two gateways.
const CAPABILITY_QUERY_ENVELOPE_LIFETIME_SECS: u64 = 300;

/// Outcome of a fabric forward: the remote `ForwardResponse` decoded into the
/// HTTP primitives the caller needs to build its own response.
pub(crate) struct FabricForwardResponse {
    pub status: u16,
    /// Response headers, keyed by name with every value preserved — a header
    /// repeated more than once on the remote gateway's response (e.g. MPP's
    /// per-method `WWW-Authenticate`) is not collapsed to a single value.
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

/// Typed failures for the fabric forward transport.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FabricForwardError {
    #[error("Invalid fabric URL '{0}'. Expected fabric://{{gateway_id}}/{{channel_id}}")]
    InvalidUrl(String),
    #[error("Gateway forwarding not available - listener manager not initialized")]
    ListenerManagerUnavailable,
    #[error("Remote gateway '{0}' not connected")]
    GatewayNotConnected(String),
    #[error("DID for remote gateway '{0}' not found")]
    GatewayDidNotFound(String),
    #[error("Failed to send message to remote gateway '{0}': {1}")]
    SendFailed(String, String),
    #[error("No response from remote gateway '{0}' within timeout")]
    NoResponse(String),
    #[error("Unexpected message type from remote gateway: {0}")]
    UnexpectedResponse(String),
    #[error("Modern Fabric streaming is unavailable")]
    StreamingUnavailable,
    #[error("The remote surface serves legacy MCP only")]
    RemoteLegacyOnly,
    #[error("A Fabric stream cap is full")]
    CapacityReached,
}

/// Seconds a caller refused by a full Fabric stream cap is told to wait.
pub(crate) const CAPACITY_RETRY_AFTER_SECS: u64 = 5;

/// The answer to a modern MCP request refused because a Fabric stream cap is
/// full: `429` with `Retry-After` and a JSON-RPC error body.
pub(crate) fn capacity_response(id: Option<serde_json::Value>) -> axum::response::Response {
    let mut response = crate::mcp::request_validation::McpRequestValidationError {
        status: axum::http::StatusCode::TOO_MANY_REQUESTS,
        id,
        code: crate::mcp::errors::error_codes::INTERNAL_ERROR,
        message: "Too many concurrent MCP requests over Fabric".into(),
        data: None,
    }
    .into_response();
    response
        .headers_mut()
        .insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from(CAPACITY_RETRY_AFTER_SECS));
    response
}

/// Parameters for a single fabric forward.
pub(crate) struct FabricForwardRequest<'a> {
    /// `fabric://{gateway_id}/{channel_id}` target.
    pub fabric_target: &'a str,
    pub method: &'a Method,
    /// Path (+ optional query) to forward; the remote gateway appends it to its
    /// channel target endpoint.
    pub path: &'a str,
    /// Headers to forward (keys already normalized by the caller).
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub timeout: Duration,
    pub trace_id: &'a str,
    /// Label for logs (e.g. surface name / transit-point alias).
    pub log_label: &'a str,
}

pub(crate) struct FabricStreamForwardRequest<'request> {
    pub fabric_target: &'request str,
    pub path: &'request str,
    pub headers: axum::http::HeaderMap,
    pub body: Bytes,
    pub header_timeout: Duration,
    pub limits: crate::config::McpHttpConfig,
    pub trace_id: uuid::Uuid,
}

struct CapabilityProbe {
    runtime: Arc<super::fabric_stream::StreamRuntime>,
    nonce: uuid::Uuid,
}

impl Drop for CapabilityProbe {
    fn drop(&mut self) {
        self.runtime
            .peers
            .cancel_probe(self.nonce);
    }
}

pub(crate) async fn forward_stream_via_fabric(
    listener_manager: &Arc<RwLock<Option<Arc<ConnectionPointListenerManager>>>>,
    request: FabricStreamForwardRequest<'_>,
) -> Result<axum::response::Response, FabricForwardError> {
    let runtime = super::fabric_stream::global()
        .map_err(|_| FabricForwardError::StreamingUnavailable)?
        .clone();
    forward_stream_with_runtime(listener_manager, request, runtime).await
}

async fn forward_stream_with_runtime(
    listener_manager: &Arc<RwLock<Option<Arc<ConnectionPointListenerManager>>>>,
    request: FabricStreamForwardRequest<'_>,
    runtime: Arc<super::fabric_stream::StreamRuntime>,
) -> Result<axum::response::Response, FabricForwardError> {
    use super::fabric_stream::{
        registry::{StreamBinding, StreamKind},
        transport, wire,
    };
    if !runtime.supports_request_streams() {
        return Err(FabricForwardError::StreamingUnavailable);
    }
    request
        .limits
        .validate()
        .map_err(|_| FabricForwardError::StreamingUnavailable)?;
    if request.body.len()
        > request
            .limits
            .max_request_bytes
            .get()
    {
        return Err(FabricForwardError::StreamingUnavailable);
    }
    let (gateway_id, target) = parse_fabric_target(request.fabric_target)?;
    let (channel_id, variant_alias) = match target.split_once('$') {
        Some((channel, alias)) => (channel, Some(alias.to_string())),
        None => (target, None),
    };
    if channel_id.contains(['/', '?', '#']) {
        return Err(FabricForwardError::InvalidUrl(
            request
                .fabric_target
                .to_string(),
        ));
    }
    let manager = listener_manager
        .read()
        .await
        .clone()
        .ok_or(FabricForwardError::ListenerManagerUnavailable)?;
    let listener = manager
        .get_listener(gateway_id)
        .await
        .ok_or_else(|| FabricForwardError::GatewayNotConnected(gateway_id.to_string()))?;
    let (peer_did, peer_tenant_id) = manager
        .get_active_stream_peer(gateway_id)
        .await
        .ok_or(FabricForwardError::StreamingUnavailable)?;
    let (listener_instance_id, recipient_did) = runtime
        .listener_context(&listener.connection_point_id)
        .filter(|(_, recipient)| recipient == &listener.gateway_did)
        .ok_or(FabricForwardError::StreamingUnavailable)?;
    let binding = StreamBinding {
        peer_did,
        recipient_did,
        listener_instance_id,
        connection_point_id: listener
            .connection_point_id
            .clone(),
        surface_id: channel_id.to_string(),
    };
    let now = tokio::time::Instant::now();
    let lifetime = Duration::from_secs(
        request
            .limits
            .stream_max_lifetime_secs
            .get(),
    );
    let deadline = now + lifetime;
    let header_deadline = (now + request.header_timeout).min(deadline);
    let agreement = match runtime
        .peers
        .agreement(&binding, std::time::Instant::now())
    {
        Some(agreement) => agreement,
        None => {
            let probe = runtime
                .peers
                .begin(binding.clone(), peer_tenant_id, std::time::Instant::now())
                .map_err(registration_failure)?;
            let _probe = CapabilityProbe {
                runtime: runtime.clone(),
                nonce: probe.nonce,
            };
            // The receiver admits a query only with an expiry, and remembers it
            // until then, so a replayed query cannot recreate an expired offer.
            let created_time = crate::gateways::connection_points::envelope_replay::now_secs();
            let message = affinidi_messaging_didcomm::Message::build(
                probe.nonce.to_string(),
                crate::messages::MessageType::ForwardStreamQuery.to_string(),
                serde_json::to_value(&probe).map_err(|_| FabricForwardError::StreamingUnavailable)?,
            )
            .from(binding.recipient_did.clone())
            .to(binding.peer_did.clone())
            .thid(probe.nonce.to_string())
            .created_time(created_time)
            .expires_time(created_time + CAPABILITY_QUERY_ENVELOPE_LIFETIME_SECS)
            .finalize();
            tokio::time::timeout_at(
                header_deadline,
                listener
                    .client
                    .pack_and_send_message(&message, &binding.peer_did, &binding.recipient_did),
            )
            .await
            .map_err(|_| FabricForwardError::NoResponse(gateway_id.to_string()))?
            .map_err(|_| FabricForwardError::StreamingUnavailable)?;
            runtime
                .peers
                .wait(&binding, probe.nonce, header_deadline.min(now + Duration::from_secs(5)))
                .await
                .map_err(|_| FabricForwardError::StreamingUnavailable)?
        }
    };
    let method = request
        .headers
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
        .ok_or(FabricForwardError::StreamingUnavailable)?;
    if !agreement
        .capabilities
        .permits_mcp_method(method)
        || agreement
            .capabilities
            .max_window_bytes
            < wire::MAX_CHUNK_BYTES as u32
    {
        return Err(FabricForwardError::StreamingUnavailable);
    }
    let kind = StreamKind::for_method(Some(method));
    let headers = wire::encode_headers(&request.headers).map_err(|_| FabricForwardError::StreamingUnavailable)?;
    let stream_id = uuid::Uuid::new_v4();
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let deadline_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| FabricForwardError::StreamingUnavailable)?
        .as_millis()
        .checked_add(remaining.as_millis())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(FabricForwardError::StreamingUnavailable)?;
    let open = wire::StreamFrame {
        stream_id,
        payload: wire::FramePayload::Open {
            request: wire::OpenRequest {
                capability_nonce: agreement.nonce,
                channel_id: channel_id.to_string(),
                variant_alias,
                path: request.path.to_string(),
                headers,
                body_bytes: request.body.len() as u64,
                response_window_bytes: agreement
                    .capabilities
                    .max_window_bytes,
                deadline_ms,
                trace_id: request.trace_id,
            },
        },
    };
    open.validate().map_err(|_| {
        FabricForwardError::InvalidUrl(
            request
                .fabric_target
                .to_string(),
        )
    })?;
    agreement
        .capabilities
        .validate_frame(&open)
        .map_err(|_| FabricForwardError::StreamingUnavailable)?;
    let receiver = runtime
        .registry
        .register_negotiated(
            stream_id,
            binding.clone(),
            kind,
            wire::StreamDirection::Response,
            agreement
                .capabilities
                .max_window_bytes as usize,
            &agreement.capabilities,
        )
        .map_err(registration_failure)?;
    let sender = runtime
        .registry
        .register_sender_negotiated(
            stream_id,
            binding.clone(),
            kind,
            wire::StreamDirection::Request,
            wire::MAX_CHUNK_BYTES,
            &agreement.capabilities,
        )
        .map_err(registration_failure)?;
    // Waits for the peer's Credit on the upload; the response itself may be
    // quiet for as long as the target takes.
    sender
        .credit()
        .set_progress_timeout(Duration::from_secs(
            request
                .limits
                .stream_idle_timeout_secs
                .get(),
        ));
    let sink = Arc::new(transport::DidCommFrameSink {
        client: listener.client,
        binding: binding.clone(),
        capabilities: agreement.capabilities.clone(),
        max_envelope_bytes: manager.fabric_stream_max_envelope_bytes(),
    });
    let (response, task) =
        transport::prepare_outgoing_request(sink, receiver, sender, open, request.body, header_deadline, deadline);
    runtime
        .enqueue_outgoing(&binding, task)
        .map_err(|_| FabricForwardError::StreamingUnavailable)?;
    let mut response = response
        .await
        .map_err(|code| {
            let (error, renegotiate) = stream_failure(code, gateway_id);
            if renegotiate {
                runtime
                    .peers
                    .forget(&binding, agreement.nonce);
            }
            error
        })?;
    response
        .extensions_mut()
        .insert(agreement.capabilities);
    Ok(response)
}

fn registration_failure(error: super::fabric_stream::registry::RegisterError) -> FabricForwardError {
    match error {
        super::fabric_stream::registry::RegisterError::CapacityReached(_) => FabricForwardError::CapacityReached,
        super::fabric_stream::registry::RegisterError::Refused(_) => FabricForwardError::StreamingUnavailable,
    }
}

/// How the sender answers a stream that ended with `code`, and whether it drops
/// its capability agreement so the next request negotiates again. Only a stale
/// offer (the peer restarted, or the offer expired) does: other refusals keep
/// the agreement, so a route the peer refuses does not make every request
/// query its capabilities and fill the peer's offer table.
fn stream_failure(
    code: super::fabric_stream::wire::StreamErrorCode,
    gateway_id: &str,
) -> (FabricForwardError, bool) {
    match code {
        super::fabric_stream::wire::StreamErrorCode::DeadlineExceeded => {
            (FabricForwardError::NoResponse(gateway_id.to_string()), false)
        }
        super::fabric_stream::wire::StreamErrorCode::StaleOffer => (FabricForwardError::StreamingUnavailable, true),
        super::fabric_stream::wire::StreamErrorCode::LegacyOnly => (FabricForwardError::RemoteLegacyOnly, false),
        super::fabric_stream::wire::StreamErrorCode::CapacityReached => (FabricForwardError::CapacityReached, false),
        _ => (FabricForwardError::StreamingUnavailable, false),
    }
}

/// Parse the `headers` field of a `ForwardResponse` body into a multi-value
/// map. A header value is either a plain string (single-valued) or a JSON
/// array of strings (a header repeated more than once, e.g. MPP's per-method
/// `WWW-Authenticate`) — mirrors the delegated payment gateway's header encoding.
fn parse_fabric_response_headers(value: Option<&serde_json::Value>) -> HashMap<String, Vec<String>> {
    value
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    if let Some(s) = v.as_str() {
                        Some((k.clone(), vec![s.to_string()]))
                    } else if let Some(arr) = v.as_array() {
                        let values: Vec<String> = arr
                            .iter()
                            .filter_map(|item| {
                                item.as_str()
                                    .map(str::to_string)
                            })
                            .collect();
                        (!values.is_empty()).then_some((k.clone(), values))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a `fabric://{gateway_id}/{channel_id}` target into its parts.
fn parse_fabric_target(fabric_target: &str) -> Result<(&str, &str), FabricForwardError> {
    let fabric_path = fabric_target
        .strip_prefix("fabric://")
        .ok_or_else(|| FabricForwardError::InvalidUrl(fabric_target.to_string()))?;
    let (gateway_id, channel_id) = fabric_path
        .split_once('/')
        .ok_or_else(|| FabricForwardError::InvalidUrl(fabric_target.to_string()))?;
    if gateway_id.is_empty() || channel_id.is_empty() {
        return Err(FabricForwardError::InvalidUrl(fabric_target.to_string()));
    }
    Ok((gateway_id, channel_id))
}

/// Forward a prepared request to a remote gateway channel over `fabric://`
/// and synchronously await its `ForwardResponse`.
pub(crate) async fn forward_via_fabric(
    listener_manager: &Arc<RwLock<Option<Arc<ConnectionPointListenerManager>>>>,
    req: FabricForwardRequest<'_>,
) -> Result<FabricForwardResponse, FabricForwardError> {
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;

    // Parse fabric://{gateway_id}/{channel_id}
    let (gateway_id, channel_id) = parse_fabric_target(req.fabric_target)?;

    let listener_mgr = listener_manager
        .read()
        .await
        .clone()
        .ok_or(FabricForwardError::ListenerManagerUnavailable)?;

    let gateway_listener = listener_mgr
        .get_listener(gateway_id)
        .await
        .ok_or_else(|| FabricForwardError::GatewayNotConnected(gateway_id.to_string()))?;

    let remote_gateway_did = listener_mgr
        .get_gateway_did(gateway_id)
        .await
        .ok_or_else(|| FabricForwardError::GatewayDidNotFound(gateway_id.to_string()))?;

    debug!(
        target = %req.fabric_target,
        gateway_id,
        channel_id,
        remote_did = %remote_gateway_did,
        label = %req.log_label,
        "Fabric forward: resolved remote gateway"
    );

    // Parse the body as JSON so it is not double-escaped in the DIDComm
    // message; fall back to a string value when it is not valid JSON. Mirrors
    // the inbound fabric forward.
    let body_value = if req.body.is_empty() {
        serde_json::Value::Null
    } else {
        let s = String::from_utf8_lossy(&req.body);
        serde_json::from_str::<serde_json::Value>(&s).unwrap_or_else(|_| serde_json::Value::String(s.to_string()))
    };

    // Compute a wall-clock deadline (epoch ms) so the remote gateway can
    // short-circuit the upstream call once the caller has given up.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let timeout_secs = req.timeout.as_secs().max(1);
    // The envelope's own lifetime is capped below the receiver's replay
    // horizon; the caller deadline keeps the full timeout.
    let message_expires_epoch =
        now.as_secs() + crate::gateways::connection_points::envelope_replay::sent_envelope_lifetime_secs(timeout_secs);
    let deadline_ms = (now.as_millis() as u64).saturating_add(timeout_secs.saturating_mul(1000));

    let forward_request_msg = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ForwardRequest
            .as_str()
            .to_string(),
        serde_json::json!({
            "channel_id": channel_id,
            "method": req.method.as_str(),
            "path": req.path,
            "headers": req.headers,
            "body": body_value,
            "trace_id": req.trace_id,
            "deadline_ms": deadline_ms,
        }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(remote_gateway_did.clone())
    .thid(uuid::Uuid::new_v4().to_string())
    .expires_time(message_expires_epoch)
    .finalize();

    // Pre-resolve and cache the remote gateway DID document for encryption.
    let did_cache = listener_mgr.get_did_cache();
    let tdk_state = gateway_listener
        .client
        .atm()
        .get_tdk();
    if let Err(e) = did_cache
        .resolve_and_cache_for_atm(&remote_gateway_did, tdk_state)
        .await
    {
        warn!(
            gateway_id,
            error = %e,
            "Fabric forward: failed to pre-resolve remote gateway DID, attempting to pack anyway"
        );
    }

    gateway_listener
        .client
        .pack_and_send_message(&forward_request_msg, &remote_gateway_did, &gateway_listener.gateway_did)
        .await
        .map_err(|e| FabricForwardError::SendFailed(gateway_id.to_string(), e))?;

    let deadline = std::time::Instant::now() + req.timeout;
    let response_msg = loop {
        // `live_stream_get` waits forever when `wait` rounds to 0 ms.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.as_millis() == 0 {
            return Err(FabricForwardError::NoResponse(gateway_id.to_string()));
        }

        let forward_result = gateway_listener
            .client
            .atm()
            .message_pickup()
            .live_stream_get(
                gateway_listener
                    .client
                    .profile(),
                &forward_request_msg.id,
                remaining,
                true,
            )
            .await;

        let msg = match forward_result {
            Ok(Some((msg, _metadata))) => msg,
            Ok(None) | Err(_) => return Err(FabricForwardError::NoResponse(gateway_id.to_string())),
        };

        if msg.from.as_deref() == Some(remote_gateway_did.as_str()) {
            break msg;
        }

        warn!(
            gateway_id,
            thid = %forward_request_msg.id,
            expected_from_did = %remote_gateway_did,
            from_did = ?msg.from,
            "Fabric forward: ignoring ForwardResponse from unexpected sender"
        );
    };

    if response_msg.typ != MessageType::ForwardResponse.as_str() {
        return Err(FabricForwardError::UnexpectedResponse(response_msg.typ.clone()));
    }

    let response_body = response_msg.body;

    let status = response_body
        .get("status")
        .and_then(|v| v.as_u64())
        .unwrap_or(502) as u16;

    let headers = parse_fabric_response_headers(response_body.get("headers"));

    let mut body = response_body
        .get("body")
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();

    // Remote gateway error envelopes carry the message in an `error` field
    // with an empty `body`. Surface it so the caller does not return a blank
    // error page.
    if body.is_empty()
        && let Some(error) = response_body.get("error")
    {
        body = serde_json::json!({ "error": error })
            .to_string()
            .into_bytes();
    }

    Ok(FabricForwardResponse { status, headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn drive_mediator_peer(
        runtime: Arc<crate::proxy::fabric_stream::StreamRuntime>,
        mut listener: crate::proxy::fabric_stream::ListenerGeneration,
        client: crate::comm::didcomm::client::DIDCommClient,
        connection: crate::gateways::connection_points::types::GatewayConnectionPoint,
        peer: crate::gateways::types::Gateway,
        surfaces: std::path::PathBuf,
    ) {
        use crate::gateways::connection_points::message_processor::ProcessingResult;
        use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
        use crate::mcp::request_validation::McpVersionPolicy;
        use crate::messages::MessageType;
        use crate::proxy::fabric_stream::{transport, wire};

        let versions = McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let mut streams = tokio::task::JoinSet::new();
        let mut next_message = Box::pin(client.live_stream_next(Duration::from_secs(10), true));
        loop {
            tokio::select! {
                task = listener.next_outgoing() => {
                    let Some(task) = task else { break };
                    streams.spawn(task);
                }
                completed = streams.join_next(), if !streams.is_empty() => {
                    completed.unwrap().unwrap();
                }
                received = &mut next_message => {
                    next_message = Box::pin(client.live_stream_next(Duration::from_secs(10), true));
                    let Some((message, metadata)) = received.unwrap() else { continue };
                    let message_type = MessageType::from_str(&message.typ);
                    if !matches!(message_type, MessageType::ForwardStreamFrame | MessageType::ForwardStreamQuery | MessageType::ForwardStreamDisclose) {
                        continue;
                    }
                    assert!(metadata.encrypted && metadata.authenticated);
                    assert_eq!(message.from.as_deref(), Some(peer.did.as_str()));
                    let mut received = ReceivedMessage::new(
                        connection.id.clone(), peer.id.clone(), message.typ, message.id,
                        message.thid, message.from, message.to.unwrap_or_default(), message.created_time,
                        message.expires_time, message.body,
                        MessageMetadata { authenticated: metadata.authenticated, encrypted: metadata.encrypted,
                            from_key: None, extra: serde_json::Value::Null },
                    ).with_context("agent_surface_storage_path", serde_json::json!(surfaces));
                    listener.stamp(&mut received);
                    if message_type == MessageType::ForwardStreamFrame
                        && matches!(wire::StreamFrame::parse(received.message_body.clone()).unwrap().payload, wire::FramePayload::Open { .. })
                    {
                        let incoming = runtime.prepare_incoming_with_versions(&received, &connection, &peer, versions).await.unwrap();
                        let sink = Arc::new(transport::DidCommFrameSink {
                            client: client.clone(), binding: incoming.binding.clone(),
                            capabilities: incoming.capabilities.clone(), max_envelope_bytes: 128 * 1024,
                        });
                        streams.spawn(incoming.run_with_mcp_runtime(sink, versions, None));
                        continue;
                    }
                    match runtime.process(&received, &message_type) {
                        ProcessingResult::ProcessedNoResponse => {}
                        ProcessingResult::RequiresResponse { response_type, response_body } => {
                            let response = affinidi_messaging_didcomm::Message::build(
                                uuid::Uuid::new_v4().to_string(), response_type, response_body,
                            ).from(connection.connection_point_did.clone()).to(peer.did.clone())
                                .thid(received.didcomm_thid.unwrap()).finalize();
                            client.pack_and_send_message(&response, &peer.did, &connection.connection_point_did).await.unwrap();
                        }
                        other => panic!("unexpected encrypted stream processing result: {other:?}"),
                    }
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires ATG_MCP_FABRIC_MEDIATOR_DID for a disposable loopback mediator"]
    async fn modern_fabric_sender_negotiates_over_encrypted_mediator() {
        use crate::comm::didcomm::client::DIDCommClient;
        use crate::gateways::connection_points::handlers::generate_connection_point_identity_peer;
        use crate::gateways::connection_points::messages::MessageStore;
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
        use crate::gateways::connection_points::ws_listener::ListenerInfo;
        use crate::gateways::types::{Gateway, GatewayType};
        use crate::gateways::{FileSystemConnectionPointStore, FileSystemGatewayStore, GatewayStore};
        use crate::proxy::fabric_stream::StreamRuntime;
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};
        use futures::StreamExt;
        use serde_json::json;

        let mediator_did = std::env::var("ATG_MCP_FABRIC_MEDIATOR_DID").expect("explicit local mediator DID required");
        let document: serde_json::Value = match std::env::var("ATG_MCP_FABRIC_MEDIATOR_DOCUMENT") {
            Ok(document) => serde_json::from_str(&document).unwrap(),
            Err(_) => {
                assert!(mediator_did.starts_with("did:peer:"));
                serde_json::to_value(
                    mediator_did
                        .parse::<affinidi_did_common::DID>()
                        .unwrap()
                        .resolve()
                        .unwrap(),
                )
                .unwrap()
            }
        };
        assert_eq!(document["id"], mediator_did);
        let mut mediator_endpoint = None;
        for service in document["service"]
            .as_array()
            .expect("mediator service required")
        {
            let messaging = service["type"].as_str() == Some("DIDCommMessaging")
                || service["type"]
                    .as_array()
                    .is_some_and(|types| {
                        types
                            .iter()
                            .any(|kind| kind.as_str() == Some("DIDCommMessaging"))
                    });
            let endpoint = &service["serviceEndpoint"];
            let endpoints = endpoint
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_else(|| std::slice::from_ref(endpoint));
            for endpoint in endpoints {
                let endpoint = endpoint
                    .as_str()
                    .or_else(|| endpoint["uri"].as_str())
                    .expect("mediator URI required");
                let url = url::Url::parse(endpoint).unwrap();
                assert!(matches!(url.scheme(), "http" | "ws"));
                assert!(
                    url.host_str() == Some("localhost")
                        || url
                            .host_str()
                            .unwrap()
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|host| host.is_loopback())
                );
                assert!(url.username().is_empty() && url.password().is_none());
                if messaging && url.scheme() == "http" {
                    mediator_endpoint = Some(url.to_string());
                }
            }
        }
        let mediator_endpoint = mediator_endpoint.expect("loopback HTTP mediator required");
        let (issuer, directory) = crate::identity::test_helpers::test_vc_issuer().await;
        let (sender_did, sender_secrets, _) =
            generate_connection_point_identity_peer("sender", directory.path(), &mediator_endpoint)
                .await
                .unwrap();
        let (receiver_did, receiver_secrets, _) =
            generate_connection_point_identity_peer("receiver", directory.path(), &mediator_endpoint)
                .await
                .unwrap();
        let mut sender_client = DIDCommClient::new_with_mediator_document(
            sender_did.clone(),
            sender_secrets,
            Some(mediator_did.clone()),
            Some(document.clone()),
            Some("mcp-sender-fixture".into()),
        )
        .await
        .unwrap();
        let mut receiver_client = DIDCommClient::new_with_mediator_document(
            receiver_did.clone(),
            receiver_secrets,
            Some(mediator_did.clone()),
            Some(document),
            Some("mcp-receiver-fixture".into()),
        )
        .await
        .unwrap();
        sender_client
            .enable_websocket()
            .await
            .unwrap();
        receiver_client
            .enable_websocket()
            .await
            .unwrap();
        let sender_runtime = StreamRuntime::test_runtime();
        let receiver_runtime = StreamRuntime::test_runtime();
        let mut sender_connection = GatewayConnectionPoint::new(
            "sender".into(),
            "mediator".into(),
            sender_did.clone(),
            "Sender".into(),
            String::new(),
            "oob".into(),
            String::new(),
            json!({}),
            None,
            ConnectionPointType::OobAcceptor,
            String::new(),
        );
        sender_connection.id = "sender-cp".into();
        let mut receiver_connection = sender_connection.clone();
        receiver_connection.id = "receiver-cp".into();
        receiver_connection.connection_point_did = receiver_did.clone();
        let sender_listener = sender_runtime
            .listener(sender_connection.id.clone(), sender_did.clone())
            .unwrap();
        let receiver_listener = receiver_runtime
            .listener(receiver_connection.id.clone(), receiver_did.clone())
            .unwrap();
        let mut sender_peer = Gateway::new("Sender".into(), String::new(), sender_did, GatewayType::Remote);
        sender_peer.id = "sender".into();
        sender_peer.issuer_did = Some(sender_peer.did.clone());
        let mut receiver_peer = Gateway::new("Receiver".into(), String::new(), receiver_did, GatewayType::Remote);
        receiver_peer.id = "receiver".into();
        let peers = Arc::new(
            FileSystemGatewayStore::new(directory.path().join("peers"), None)
                .await
                .unwrap(),
        );
        for peer in [&receiver_peer, &sender_peer] {
            peers
                .create(peer)
                .await
                .unwrap();
        }
        let manager = ConnectionPointListenerManager::new(
            Arc::new(issuer),
            Arc::new(
                MessageStore::new(
                    directory
                        .path()
                        .join("messages"),
                )
                .await
                .unwrap(),
            ),
            Arc::new(
                FileSystemConnectionPointStore::new(
                    directory
                        .path()
                        .join("connections"),
                )
                .await
                .unwrap(),
            ),
            Default::default(),
        )
        .await
        .unwrap()
        .with_gateway_store(peers);
        let surface_path = directory
            .path()
            .join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(surface_path.clone())
            .await
            .unwrap();
        let expected = json!({"jsonrpc": "2.0", "id": "encrypted", "result": {
            "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private",
            "_meta": {"com.example/preserved": [true, null]}
        }});
        let target = crate::component_tests::helpers::MockServer::start_with_response(expected.to_string()).await;
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "Surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "http://127.0.0.1:1"},
            "variants": [{"id": "variant", "alias": "candidate", "name": "Candidate", "overrides": {
                "target": {"endpoint": format!("http://{}", target.addr)}
            }}]
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        let sender_task = tasks.spawn(drive_mediator_peer(
            sender_runtime.clone(),
            sender_listener,
            sender_client.clone(),
            sender_connection.clone(),
            receiver_peer.clone(),
            surface_path.clone(),
        ));
        tasks.spawn(drive_mediator_peer(
            receiver_runtime,
            receiver_listener,
            receiver_client,
            receiver_connection,
            sender_peer,
            surface_path,
        ));
        manager
            .register_test_listener(ListenerInfo {
                id: sender_connection.id.clone(),
                instance_id: sender_runtime
                    .listener_context(&sender_connection.id)
                    .unwrap()
                    .0,
                gateway_id: receiver_peer.id.clone(),
                connection_point_id: sender_connection.id,
                gateway_did: sender_connection.connection_point_did,
                mediator_did,
                name: "Sender".into(),
                cp_type: ConnectionPointType::OobAcceptor,
                abort_handle: sender_task,
                metrics: Default::default(),
                client: sender_client,
            })
            .await;
        let manager = Arc::new(manager);
        crate::gateways::init_listener_manager(manager.clone()).await;
        let manager = Arc::new(RwLock::new(Some(manager)));
        let headers = axum::http::HeaderMap::from_iter([
            (
                axum::http::HeaderName::from_static("mcp-protocol-version"),
                crate::mcp::MCP_MODERN_VERSION
                    .parse()
                    .unwrap(),
            ),
            (axum::http::HeaderName::from_static("mcp-method"), "tools/list".parse().unwrap()),
            (
                axum::http::header::CONTENT_TYPE,
                "application/json"
                    .parse()
                    .unwrap(),
            ),
            (
                axum::http::header::ACCEPT,
                "application/json, text/event-stream"
                    .parse()
                    .unwrap(),
            ),
        ]);
        let request = json!({"jsonrpc": "2.0", "id": "encrypted", "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            forward_stream_with_runtime(
                &manager,
                FabricStreamForwardRequest {
                    fabric_target: "fabric://receiver/surface$candidate",
                    path: "/mcp",
                    headers: headers.clone(),
                    body: serde_json::to_vec(&request)
                        .unwrap()
                        .into(),
                    header_timeout: Duration::from_secs(20),
                    limits: Default::default(),
                    trace_id: uuid::Uuid::new_v4(),
                },
                sender_runtime.clone(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = tokio::time::timeout(Duration::from_secs(10), axum::body::to_bytes(response.into_body(), 65536))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(), expected);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let release = Arc::new(tokio::sync::Notify::new());
        let (outcomes_tx, mut outcomes_rx) = tokio::sync::mpsc::channel(2);
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let streaming_address = tcp.local_addr().unwrap();
        let final_message = expected.clone();
        let upstream = axum::Router::new().fallback(axum::routing::post({
            let release = release.clone();
            move |request: axum::extract::Request| {
                let release = release.clone();
                let outcomes = outcomes_tx.clone();
                let final_message = final_message.clone();
                async move {
                    assert!(
                        !request
                            .headers()
                            .contains_key("mcp-session-id")
                    );
                    let progress = Bytes::from(format!(
                        "data: {}\r\n\r\n",
                        json!({
                            "jsonrpc": "2.0", "method": "notifications/progress", "params": {
                                "progressToken": "encrypted-progress", "progress": 1,
                                "_meta": {"com.example/preserved": [true, null]}
                            }
                        })
                    ));
                    let source = futures::stream::once(async { Ok::<_, std::io::Error>(progress) }).chain(
                        futures::stream::once(async move {
                            release.notified().await;
                            Ok(Bytes::from(format!("data: {final_message}\n\n")))
                        }),
                    );
                    let response = axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .header("x-preserved", "stream")
                        .body(axum::body::Body::from_stream(source))
                        .unwrap();
                    crate::mcp::modern_sse::observe_response(response, move |outcome| {
                        let _ = outcomes.try_send(outcome);
                    })
                }
            }
        }));
        tasks.spawn(async move {
            axum::serve(tcp, upstream)
                .await
                .unwrap();
        });
        let mut streaming_surface = surface.clone();
        streaming_surface.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some(format!("http://{streaming_address}"));
        store
            .save(&streaming_surface)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        for finish in [true, false] {
            let mut request = request.clone();
            request["params"]["_meta"]["progressToken"] = json!("encrypted-progress");
            let body = Bytes::from(serde_json::to_vec(&request).unwrap());
            let crate::mcp::request_validation::McpRequestClassification::Modern(admitted) =
                crate::mcp::request_validation::validate_mcp_post(
                    &headers,
                    &body,
                    crate::mcp::request_validation::LegacySessionEvidence::Absent,
                    versions,
                )
                .unwrap()
            else {
                panic!("expected admitted modern fixture");
            };
            let response = tokio::time::timeout(
                Duration::from_secs(30),
                forward_stream_with_runtime(
                    &manager,
                    FabricStreamForwardRequest {
                        fabric_target: "fabric://receiver/surface$candidate",
                        path: "/mcp",
                        headers: headers.clone(),
                        body,
                        header_timeout: Duration::from_secs(20),
                        limits: Default::default(),
                        trace_id: uuid::Uuid::new_v4(),
                    },
                    sender_runtime.clone(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert_eq!(response.headers()["x-preserved"], "stream");
            let support = crate::mcp::modern::ForwardingSupport::for_endpoint(
                true,
                crate::mcp::request_validation::McpPathKind::FabricSend,
            )
            .restrict_to_fabric_peer(
                response
                    .extensions()
                    .get::<crate::proxy::fabric_stream::peer::StreamCapabilities>(),
            );
            let (mut parts, body) = response.into_parts();
            let completion = parts
                .extensions
                .remove::<crate::mcp::modern_sse::TransportCompletion>();
            assert!(completion.is_some());
            let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
            let response = crate::mcp::modern_sse::forwarding_response_with_completion(
                body.into_data_stream(),
                parts.status,
                &parts.headers,
                *admitted,
                limits,
                support,
                |message| async { Ok::<_, crate::mcp::modern_sse::SseReadError>(message) },
                |message| async { Ok(message) },
                completion,
            )
            .await
            .unwrap();
            let mut events = Box::pin(crate::mcp::modern_sse::decode_events(
                response
                    .into_body()
                    .into_data_stream(),
                limits,
            ));
            let progress = tokio::time::timeout(Duration::from_secs(10), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let progress: serde_json::Value = serde_json::from_str(&progress.data).unwrap();
            assert_eq!(progress["method"], "notifications/progress");
            assert_eq!(progress["params"]["progressToken"], "encrypted-progress");
            assert_eq!(progress["params"]["_meta"]["com.example/preserved"], json!([true, null]));
            assert!(
                outcomes_rx
                    .try_recv()
                    .is_err(),
                "Target finished before progress crossed the mediator"
            );
            if finish {
                release.notify_one();
                let final_event = tokio::time::timeout(Duration::from_secs(10), events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(serde_json::from_str::<serde_json::Value>(&final_event.data).unwrap(), expected);
                assert!(
                    tokio::time::timeout(Duration::from_secs(10), events.next())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            drop(events);
            let outcome = tokio::time::timeout(Duration::from_secs(10), outcomes_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(outcome.completed, finish, "encrypted cancellation did not reach the quiet Target");
            assert!(!outcome.failed);
        }
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let subscription_address = tcp.local_addr().unwrap();
        let (subscriptions_tx, mut subscriptions_rx) = tokio::sync::mpsc::channel(4);
        let upstream = axum::Router::new().fallback(axum::routing::post(
            move |uri: axum::http::Uri, axum::Json(request): axum::Json<serde_json::Value>| {
                let subscriptions = subscriptions_tx.clone();
                async move {
                    assert_eq!(request["method"], "subscriptions/listen");
                    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
                    let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
                    let supported = if uri.path().ends_with("/empty") {
                        json!({})
                    } else {
                        request["params"]["notifications"].clone()
                    };
                    sender
                        .send(Ok(Bytes::from(format!(
                            "data: {}\n\n",
                            json!({
                                "jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {
                                    "_meta": {"io.modelcontextprotocol/subscriptionId": request["id"]},
                                    "notifications": supported
                                }
                            })
                        ))))
                        .await
                        .unwrap();
                    subscriptions
                        .send((request["id"].clone(), sender, outcome_rx))
                        .await
                        .unwrap();
                    let response = axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver)))
                        .unwrap();
                    crate::mcp::modern_sse::observe_response(response, move |outcome| {
                        let _ = outcome_tx.send(outcome);
                    })
                }
            },
        ));
        tasks.spawn(async move {
            axum::serve(tcp, upstream)
                .await
                .unwrap();
        });
        streaming_surface.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some(format!("http://{subscription_address}"));
        store
            .save(&streaming_surface)
            .await
            .unwrap();
        let open_subscription = |id: serde_json::Value, notifications: serde_json::Value, path: &'static str| {
            let manager = manager.clone();
            let runtime = sender_runtime.clone();
            let mut headers = headers.clone();
            headers.insert(
                "mcp-method",
                "subscriptions/listen"
                    .parse()
                    .unwrap(),
            );
            async move {
                let request = json!({"jsonrpc": "2.0", "id": id, "method": "subscriptions/listen", "params": {
                    "notifications": notifications, "_meta": {
                        "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }});
                let body = Bytes::from(serde_json::to_vec(&request).unwrap());
                let crate::mcp::request_validation::McpRequestClassification::Modern(admitted) =
                    crate::mcp::request_validation::validate_mcp_post(
                        &headers,
                        &body,
                        crate::mcp::request_validation::LegacySessionEvidence::Absent,
                        versions,
                    )
                    .unwrap()
                else {
                    panic!("expected admitted subscription fixture");
                };
                let response = tokio::time::timeout(
                    Duration::from_secs(30),
                    forward_stream_with_runtime(
                        &manager,
                        FabricStreamForwardRequest {
                            fabric_target: "fabric://receiver/surface$candidate",
                            path,
                            headers,
                            body,
                            header_timeout: Duration::from_secs(20),
                            limits: Default::default(),
                            trace_id: uuid::Uuid::new_v4(),
                        },
                        runtime,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(response.status(), axum::http::StatusCode::OK);
                let support = crate::mcp::modern::ForwardingSupport::for_endpoint(
                    true,
                    crate::mcp::request_validation::McpPathKind::FabricSend,
                )
                .restrict_to_fabric_peer(
                    response
                        .extensions()
                        .get::<crate::proxy::fabric_stream::peer::StreamCapabilities>(),
                );
                let (mut parts, body) = response.into_parts();
                let completion = parts
                    .extensions
                    .remove::<crate::mcp::modern_sse::TransportCompletion>();
                assert!(completion.is_some());
                let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
                let response = crate::mcp::modern_sse::forwarding_response_with_completion(
                    body.into_data_stream(),
                    parts.status,
                    &parts.headers,
                    *admitted,
                    limits,
                    support,
                    |_| async { Err::<serde_json::Value, _>(crate::mcp::modern_sse::SseReadError::ResponseRejected) },
                    |_| async { Err(crate::mcp::modern_sse::SseReadError::ResponseRejected) },
                    completion,
                )
                .await
                .unwrap();
                Box::pin(crate::mcp::modern_sse::decode_events(
                    response
                        .into_body()
                        .into_data_stream(),
                    limits,
                ))
            }
        };
        let filters = json!({"toolsListChanged": true, "promptsListChanged": true,
            "resourcesListChanged": true, "resourceSubscriptions": ["file:///project"]});
        let mut first = open_subscription(json!(7), filters.clone(), "/mcp").await;
        let (first_id, first_sender, first_outcome) = subscriptions_rx
            .recv()
            .await
            .unwrap();
        let mut second = open_subscription(json!(7), json!({"toolsListChanged": true}), "/mcp").await;
        let (second_id, second_sender, second_outcome) = subscriptions_rx
            .recv()
            .await
            .unwrap();
        assert_eq!(first_id, json!(7));
        assert_eq!(first_id, second_id);
        let acknowledgement = tokio::time::timeout(Duration::from_secs(10), first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let acknowledgement: serde_json::Value = serde_json::from_str(&acknowledgement.data).unwrap();
        assert_eq!(acknowledgement["method"], "notifications/subscriptions/acknowledged");
        assert_eq!(acknowledgement["params"]["notifications"], filters);
        assert_eq!(acknowledgement["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 7);
        let acknowledgement = tokio::time::timeout(Duration::from_secs(10), second.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let acknowledgement: serde_json::Value = serde_json::from_str(&acknowledgement.data).unwrap();
        assert_eq!(acknowledgement["params"]["notifications"], json!({"toolsListChanged": true}));
        for method in [
            "notifications/tools/list_changed",
            "notifications/prompts/list_changed",
            "notifications/resources/list_changed",
            "notifications/resources/updated",
        ] {
            let mut update = json!({"jsonrpc": "2.0", "method": method, "params": {"_meta": {
                "io.modelcontextprotocol/subscriptionId": 7, "com.example/preserved": [true, null]
            }}});
            if method == "notifications/resources/updated" {
                update["params"]["uri"] = json!("file:///project/src/lib.rs");
            }
            first_sender
                .send(Ok(Bytes::from(format!("data: {update}\n\n"))))
                .await
                .unwrap();
            let event = tokio::time::timeout(Duration::from_secs(10), first.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(&event.data).unwrap(), update);
            assert!(futures::poll!(second.next()).is_pending(), "equal public IDs must not merge streams");
        }
        drop(second);
        assert!(
            !tokio::time::timeout(Duration::from_secs(10), second_outcome)
                .await
                .unwrap()
                .unwrap()
                .completed
        );
        assert!(second_sender.is_closed());
        assert!(!first_sender.is_closed());
        let done = json!({"jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete",
            "_meta": {"io.modelcontextprotocol/subscriptionId": 7}}});
        first_sender
            .send(Ok(Bytes::from(format!("data: {done}\n\n"))))
            .await
            .unwrap();
        drop(first_sender);
        let event = tokio::time::timeout(Duration::from_secs(10), first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&event.data).unwrap(), done);
        assert!(
            tokio::time::timeout(Duration::from_secs(10), first.next())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(10), first_outcome)
                .await
                .unwrap()
                .unwrap()
                .completed
        );
        for reject in [false, true] {
            let mut events = open_subscription(json!("7"), json!({"promptsListChanged": true}), "/empty").await;
            let (id, sender, outcome) = subscriptions_rx
                .recv()
                .await
                .unwrap();
            assert_eq!(id, json!("7"));
            let ack = tokio::time::timeout(Duration::from_secs(10), events.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ack: serde_json::Value = serde_json::from_str(&ack.data).unwrap();
            assert_eq!(ack["params"]["notifications"], json!({}));
            assert_eq!(ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], "7");
            let message = if reject {
                json!({"jsonrpc": "2.0", "method": "notifications/prompts/list_changed", "params": {
                    "_meta": {"io.modelcontextprotocol/subscriptionId": "7"}
                }})
            } else {
                json!({"jsonrpc": "2.0", "id": "7", "result": {"resultType": "complete",
                    "_meta": {"io.modelcontextprotocol/subscriptionId": "7"}}})
            };
            sender
                .send(Ok(Bytes::from(format!("data: {message}\n\n"))))
                .await
                .unwrap();
            if reject {
                assert!(
                    tokio::time::timeout(Duration::from_secs(10), events.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
                assert!(
                    !tokio::time::timeout(Duration::from_secs(10), outcome)
                        .await
                        .unwrap()
                        .unwrap()
                        .completed
                );
                assert!(sender.is_closed());
            } else {
                drop(sender);
                let event = tokio::time::timeout(Duration::from_secs(10), events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(serde_json::from_str::<serde_json::Value>(&event.data).unwrap(), message);
                assert!(
                    tokio::time::timeout(Duration::from_secs(10), events.next())
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    tokio::time::timeout(Duration::from_secs(10), outcome)
                        .await
                        .unwrap()
                        .unwrap()
                        .completed
                );
            }
        }
        tasks.shutdown().await;
        assert!(
            crate::mcp::request_validation::runtime_policy_for(crate::mcp::request_validation::McpPathKind::FabricSend)
                .supports_modern(crate::mcp::MCP_MODERN_VERSION)
        );
    }

    #[test]
    fn only_a_stale_offer_makes_the_sender_negotiate_again() {
        use crate::proxy::fabric_stream::wire::StreamErrorCode;

        assert!(matches!(
            stream_failure(StreamErrorCode::StaleOffer, "gw"),
            (FabricForwardError::StreamingUnavailable, true)
        ));
        assert!(matches!(
            stream_failure(StreamErrorCode::LegacyOnly, "gw"),
            (FabricForwardError::RemoteLegacyOnly, false)
        ));
        assert!(matches!(
            stream_failure(StreamErrorCode::DeadlineExceeded, "gw"),
            (FabricForwardError::NoResponse(_), false)
        ));
        assert!(matches!(
            stream_failure(StreamErrorCode::CapacityReached, "gw"),
            (FabricForwardError::CapacityReached, false)
        ));
        for code in [
            StreamErrorCode::Unavailable,
            StreamErrorCode::InvalidFrame,
            StreamErrorCode::LimitExceeded,
            StreamErrorCode::UpstreamFailed,
            StreamErrorCode::Cancelled,
            StreamErrorCode::Unknown,
        ] {
            assert!(
                matches!(stream_failure(code, "gw"), (FabricForwardError::StreamingUnavailable, false)),
                "{code:?}"
            );
        }
    }

    #[test]
    fn only_a_full_local_cap_is_a_capacity_failure() {
        use crate::proxy::fabric_stream::registry::RegisterError;

        assert!(matches!(
            registration_failure(RegisterError::CapacityReached("full")),
            FabricForwardError::CapacityReached
        ));
        assert!(matches!(
            registration_failure(RegisterError::Refused("duplicate".into())),
            FabricForwardError::StreamingUnavailable
        ));
    }

    #[tokio::test]
    async fn a_capacity_refusal_is_a_retryable_json_rpc_429() {
        let response = capacity_response(Some(serde_json::json!(7)));
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "5"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], crate::mcp::errors::error_codes::INTERNAL_ERROR);
        assert_eq!(body["error"]["message"], "Too many concurrent MCP requests over Fabric");
    }

    #[tokio::test]
    async fn modern_fabric_forward_needs_a_running_listener() {
        let result = forward_stream_via_fabric(
            &Arc::new(RwLock::new(None)),
            FabricStreamForwardRequest {
                fabric_target: "fabric://gateway/surface$variant",
                path: "/mcp",
                headers: Default::default(),
                body: Bytes::new(),
                header_timeout: Duration::from_secs(1),
                limits: Default::default(),
                trace_id: uuid::Uuid::new_v4(),
            },
        )
        .await;
        assert!(
            matches!(result, Err(FabricForwardError::ListenerManagerUnavailable)),
            "a stream needs a running listener manager"
        );
    }

    #[test]
    fn test_parse_fabric_target_valid() {
        let (gw, ch) = parse_fabric_target("fabric://gw-123/channel-abc").unwrap();
        assert_eq!(gw, "gw-123");
        assert_eq!(ch, "channel-abc");
    }

    #[test]
    fn test_parse_fabric_target_with_extra_path_segments() {
        // Only the first segment is the channel id; the rest stays in channel_id.
        let (gw, ch) = parse_fabric_target("fabric://gw-1/chan/extra").unwrap();
        assert_eq!(gw, "gw-1");
        assert_eq!(ch, "chan/extra");
    }

    #[test]
    fn test_parse_fabric_target_missing_scheme() {
        assert!(matches!(parse_fabric_target("https://gw-1/chan"), Err(FabricForwardError::InvalidUrl(_))));
    }

    #[test]
    fn test_parse_fabric_target_missing_channel() {
        assert!(matches!(parse_fabric_target("fabric://gw-1"), Err(FabricForwardError::InvalidUrl(_))));
    }

    #[test]
    fn test_parse_fabric_target_empty_parts() {
        assert!(matches!(parse_fabric_target("fabric:///chan"), Err(FabricForwardError::InvalidUrl(_))));
        assert!(matches!(parse_fabric_target("fabric://gw/"), Err(FabricForwardError::InvalidUrl(_))));
    }

    #[test]
    fn test_parse_fabric_response_headers_single_value_stays_plain() {
        let body = serde_json::json!({"content-type": "application/json"});
        let headers = parse_fabric_response_headers(Some(&body));
        assert_eq!(headers.get("content-type"), Some(&vec!["application/json".to_string()]));
    }

    #[test]
    fn test_parse_fabric_response_headers_array_value_preserves_all() {
        let body = serde_json::json!({"WWW-Authenticate": ["Payment method=tempo", "Payment method=card"]});
        let headers = parse_fabric_response_headers(Some(&body));
        assert_eq!(
            headers.get("WWW-Authenticate"),
            Some(&vec!["Payment method=tempo".to_string(), "Payment method=card".to_string()])
        );
    }

    #[test]
    fn test_parse_fabric_response_headers_missing_is_empty() {
        assert!(parse_fabric_response_headers(None).is_empty());
    }
}
