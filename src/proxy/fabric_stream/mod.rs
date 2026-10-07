pub(crate) mod flow;
pub(crate) mod peer;
pub(crate) mod registry;
pub(crate) mod transport;
pub(crate) mod wire;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use uuid::Uuid;

use crate::gateways::connection_points::message_processor::ProcessingResult;
use crate::gateways::connection_points::messages::ReceivedMessage;
use crate::messages::MessageType;
use peer::{CapabilityMessage, PeerCapabilities, StreamCapabilities};
use registry::{ReceiveRegistry, RegistryLimits};

pub(crate) const INSTANCE_CONTEXT: &str = "fabric_stream_listener_instance";
const RECIPIENT_CONTEXT: &str = "fabric_stream_recipient";

type StreamTask = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

struct ActiveListener {
    instance_id: String,
    recipient: String,
    outgoing: tokio::sync::mpsc::Sender<StreamTask>,
}

pub(crate) struct StreamRuntime {
    pub registry: Arc<ReceiveRegistry>,
    pub peers: PeerCapabilities,
    local_capabilities: StreamCapabilities,
    listeners: Mutex<HashMap<String, ActiveListener>>,
}

impl StreamRuntime {
    fn new() -> Result<Arc<Self>, String> {
        // Framed request streams and subscriptions carry modern MCP over Fabric.
        let local_capabilities = StreamCapabilities::local(true, true);
        Self::with_capabilities(local_capabilities)
    }

    fn with_capabilities(local_capabilities: StreamCapabilities) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            registry: ReceiveRegistry::new(RegistryLimits {
                max_streams: 128,
                // Below the surface cap, so one peer cannot fill a surface.
                max_peer_streams: 8,
                max_surface_streams: 16,
            })?,
            peers: PeerCapabilities::new(local_capabilities.clone()),
            local_capabilities,
            listeners: Mutex::new(HashMap::new()),
        }))
    }

    #[cfg(test)]
    pub(crate) fn test_runtime() -> Arc<Self> {
        Self::new().unwrap()
    }

    pub fn listener(
        self: &Arc<Self>,
        connection_point_id: String,
        recipient: String,
    ) -> Result<ListenerGeneration, String> {
        let instance_id = Uuid::new_v4().to_string();
        let (outgoing, queued) = tokio::sync::mpsc::channel(16);
        let mut listeners = self
            .listeners
            .lock()
            .map_err(|_| "Fabric listener registry is unavailable")?;
        if let Some(previous) = listeners.insert(
            connection_point_id.clone(),
            ActiveListener {
                instance_id: instance_id.clone(),
                recipient: recipient.clone(),
                outgoing,
            },
        ) {
            self.registry
                .cancel_listener(&connection_point_id, &previous.instance_id);
            self.peers
                .remove_listener(&connection_point_id, &previous.instance_id);
        }
        Ok(ListenerGeneration {
            runtime: self.clone(),
            connection_point_id,
            instance_id,
            recipient,
            queued,
        })
    }

    pub fn listener_context(
        &self,
        connection_point_id: &str,
    ) -> Option<(String, String)> {
        self.listeners
            .lock()
            .ok()?
            .get(connection_point_id)
            .map(|listener| (listener.instance_id.clone(), listener.recipient.clone()))
    }

    pub fn supports_request_streams(&self) -> bool {
        self.local_capabilities
            .request_streams
    }

    pub fn supports_subscriptions(&self) -> bool {
        self.local_capabilities
            .permits_mcp_method("subscriptions/listen")
    }

    pub fn enqueue_outgoing(
        &self,
        binding: &registry::StreamBinding,
        task: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), String> {
        let listeners = self
            .listeners
            .lock()
            .map_err(|_| "Fabric listeners are unavailable")?;
        let listener = listeners
            .get(&binding.connection_point_id)
            .filter(|listener| {
                listener.instance_id == binding.listener_instance_id && listener.recipient == binding.recipient_did
            })
            .ok_or("Fabric listener generation is no longer active")?;
        listener
            .outgoing
            .try_send(Box::pin(task))
            .map_err(|_| "Fabric outgoing queue is unavailable".to_string())
    }

    pub async fn prepare_incoming(
        &self,
        message: &ReceivedMessage,
        connection_point: &crate::gateways::connection_points::types::GatewayConnectionPoint,
        peer: &crate::gateways::types::Gateway,
    ) -> Result<IncomingStream, OpenRefusal> {
        self.prepare_incoming_with_versions(
            message,
            connection_point,
            peer,
            crate::mcp::request_validation::runtime_policy_for(
                crate::mcp::request_validation::McpPathKind::FabricReceive,
            ),
        )
        .await
    }

    pub(crate) async fn prepare_incoming_with_versions(
        &self,
        message: &ReceivedMessage,
        connection_point: &crate::gateways::connection_points::types::GatewayConnectionPoint,
        peer: &crate::gateways::types::Gateway,
        versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
    ) -> Result<IncomingStream, OpenRefusal> {
        let instance_id = self.validate_message(message)?;
        let frame = wire::StreamFrame::parse(message.message_body.clone())?;
        let wire::FramePayload::Open { request } = frame.payload else {
            return Err("Expected Fabric Open frame".into());
        };
        if !self
            .local_capabilities
            .request_streams
            || !connection_point.enabled
            || connection_point.id != message.connection_point_id
            || peer.status != crate::gateways::types::GatewayStatus::Active
            || peer.gateway_type != crate::gateways::types::GatewayType::Remote
            || message.from_did.as_deref() != Some(peer.did.as_str())
            || (!connection_point
                .exposed_channels
                .is_empty()
                && !connection_point
                    .exposed_channels
                    .contains(&request.channel_id))
            || (!peer
                .exposed_channels
                .is_empty()
                && !peer
                    .exposed_channels
                    .contains(&request.channel_id))
        {
            return Err("Fabric stream peer or route is unavailable".into());
        }
        let binding = registry::StreamBinding {
            peer_did: peer.did.clone(),
            recipient_did: connection_point
                .connection_point_did
                .clone(),
            connection_point_id: connection_point.id.clone(),
            listener_instance_id: instance_id.to_string(),
            surface_id: request.channel_id.clone(),
        };
        if !binding.matches(message, instance_id, frame.stream_id) {
            return Err("Fabric Open frame does not match the authenticated listener".into());
        }
        // An `Open` is admitted like a `forward-request`: its envelope must
        // carry a valid expiry, and it is admissible only until then and only
        // while its capability offer is live, so its replay record lasts no
        // longer than that.
        let now_secs = crate::gateways::connection_points::envelope_replay::now_secs();
        let envelope_expires = crate::gateways::connection_points::envelope_replay::validate_envelope_times(
            message.created_time,
            message.expires_time,
            now_secs,
        )
        .map_err(|rejection| rejection.to_string())?;
        let (capabilities, offer_expires) = self
            .peers
            .offered(&binding, request.capability_nonce, Instant::now())
            .filter(|(capabilities, _)| capabilities.request_streams)
            .ok_or_else(|| {
                OpenRefusal::new(wire::StreamErrorCode::StaleOffer, "Fabric Open has no active capability offer")
            })?;
        let replayable_until = tokio::time::Instant::from_std(offer_expires)
            .min(tokio::time::Instant::now() + std::time::Duration::from_secs(envelope_expires - now_secs));
        if request.response_window_bytes > capabilities.max_window_bytes
            || capabilities.max_window_bytes < wire::MAX_CHUNK_BYTES as u32
            || serde_json::to_vec(&message.message_body)
                .map_err(|error| error.to_string())?
                .len()
                > capabilities.max_frame_bytes as usize
        {
            return Err("Fabric Open exceeds negotiated limits".into());
        }
        capabilities.validate_frame(&wire::StreamFrame {
            stream_id: frame.stream_id,
            payload: wire::FramePayload::Open { request: request.clone() },
        })?;
        let (surface, variant_id) =
            crate::gateways::connection_points::message_processor::resolve_stream_surface(message, &request).await?;
        if !crate::gateways::connection_points::message_processor::fabric_peer_may_reach_surface(
            peer.tenant_id.as_deref(),
            surface.tenant_id.as_deref(),
        ) {
            return Err("Fabric stream peer or route is unavailable".into());
        }
        if !versions.supports_modern(crate::mcp::MCP_MODERN_VERSION) {
            return Err(OpenRefusal::new(
                wire::StreamErrorCode::LegacyOnly,
                "Modern MCP execution is not active for the receiving endpoint",
            ));
        }
        let limits = surface
            .mcp_http
            .clone()
            .unwrap_or_default();
        limits.validate()?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis();
        // A deadline further ahead than this endpoint's lifetime, from a peer
        // with a longer lifetime or a clock ahead of this one, is bounded by the
        // lifetime rather than refused.
        let remaining_ms = u128::from(request.deadline_ms)
            .checked_sub(now_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or("Fabric stream deadline has elapsed")?
            .min(
                u128::from(
                    limits
                        .stream_max_lifetime_secs
                        .get(),
                ) * 1000,
            );
        if request.body_bytes > limits.max_request_bytes.get() as u64 {
            return Err("Fabric stream request exceeds endpoint limits".into());
        }
        let deadline_ms = u64::try_from(now_ms + remaining_ms).map_err(|_| "Fabric stream deadline is out of range")?;
        let headers = wire::decode_headers(&request.headers)?;
        let http_policy = crate::mcp::modern_http::EndpointHttpPolicy::new(
            Some(&limits),
            std::slice::from_ref(
                &surface
                    .access_point
                    .listen_address,
            ),
            crate::mcp::request_validation::McpPathKind::FabricReceive,
        )?;
        // The peer is authenticated and the route resolved, so a refused caller
        // header (such as an untrusted Origin) is answered on the stream the way
        // a direct endpoint answers it, instead of leaving the sender to time out.
        let rejection = http_policy
            .validate_headers(&headers)
            .err()
            .map(|error| error.into_validation_error(None));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(remaining_ms as u64);
        let (receiver, sender) = self
            .registry
            .open_with_capabilities(
                frame.stream_id,
                binding.clone(),
                wire::MAX_CHUNK_BYTES,
                request.response_window_bytes as usize,
                deadline,
                replayable_until,
                &capabilities,
            )?;
        let mut message = message.clone();
        let header_values: serde_json::Map<String, serde_json::Value> = request
            .headers
            .iter()
            .map(|(name, values)| {
                let value = if values.len() == 1 {
                    serde_json::json!(values[0])
                } else {
                    serde_json::json!(values)
                };
                (name.clone(), value)
            })
            .collect();
        message.message_body = serde_json::json!({
            "channel_id": request.channel_id, "virtual_channel_alias": request.variant_alias,
            "method": "POST", "path": request.path, "headers": header_values,
            "trace_id": request.trace_id, "deadline_ms": deadline_ms,
        });
        Ok(IncomingStream {
            receiver,
            sender,
            stream_id: frame.stream_id,
            binding,
            capabilities,
            message,
            headers,
            surface,
            variant_id,
            declared_bytes: request.body_bytes,
            limits,
            deadline,
            rejection,
        })
    }

    fn validate_message<'message>(
        &self,
        message: &'message ReceivedMessage,
    ) -> Result<&'message str, String> {
        let instance_id = message
            .context
            .get(INSTANCE_CONTEXT)
            .and_then(serde_json::Value::as_str)
            .ok_or("Fabric stream message lacks trusted listener context")?;
        let recipient = message
            .context
            .get(RECIPIENT_CONTEXT)
            .and_then(serde_json::Value::as_str)
            .ok_or("Fabric stream message lacks trusted recipient context")?;
        if !message.metadata.authenticated
            || !message.metadata.encrypted
            || message
                .from_did
                .as_deref()
                .is_none_or(str::is_empty)
            || !message
                .to_dids
                .iter()
                .any(|did| did == recipient)
            || self
                .listener_context(&message.connection_point_id)
                .as_ref()
                != Some(&(instance_id.to_string(), recipient.to_string()))
        {
            return Err("Fabric stream message is not bound to the active authenticated listener".to_string());
        }
        Ok(instance_id)
    }

    /// Where to answer an `Open` refused before it registered a stream: the
    /// sender's binding and the stream id. `None` unless the message is bound
    /// to this listener, so nothing is sent to a sender that is not, and
    /// `None` for a repeated `Open` of an accepted stream, whose answer would
    /// end that stream.
    pub(crate) fn refused_open_binding(
        &self,
        message: &ReceivedMessage,
    ) -> Option<(registry::StreamBinding, Uuid)> {
        let instance_id = self
            .validate_message(message)
            .ok()?;
        let frame = wire::StreamFrame::parse(message.message_body.clone()).ok()?;
        if !matches!(frame.payload, wire::FramePayload::Open { .. })
            || self
                .registry
                .was_opened(&frame.stream_id)
        {
            return None;
        }
        Some((
            registry::StreamBinding {
                peer_did: message.from_did.clone()?,
                recipient_did: message
                    .context
                    .get(RECIPIENT_CONTEXT)?
                    .as_str()?
                    .to_string(),
                connection_point_id: message
                    .connection_point_id
                    .clone(),
                listener_instance_id: instance_id.to_string(),
                surface_id: "refused-open".to_string(),
            },
            frame.stream_id,
        ))
    }

    /// Answers a refused `Open` with an `Error` frame, so the sender fails at
    /// once instead of waiting for its response deadline.
    pub(crate) async fn answer_refused_open(
        &self,
        client: &crate::comm::didcomm::client::DIDCommClient,
        message: &ReceivedMessage,
        code: wire::StreamErrorCode,
        max_envelope_bytes: usize,
    ) {
        let Some((binding, stream_id)) = self.refused_open_binding(message) else {
            return;
        };
        let sink = transport::DidCommFrameSink {
            client: client.clone(),
            binding,
            capabilities: self
                .local_capabilities
                .clone(),
            max_envelope_bytes,
        };
        let frame = wire::StreamFrame {
            stream_id,
            payload: wire::FramePayload::Error { code },
        };
        match tokio::time::timeout(std::time::Duration::from_secs(2), transport::FrameSink::send(&sink, frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(code)) => tracing::warn!(?code, %stream_id, "Could not answer a refused Fabric Open"),
            Err(_) => tracing::warn!(%stream_id, "Answering a refused Fabric Open timed out"),
        }
    }

    pub fn process(
        &self,
        message: &ReceivedMessage,
        message_type: &MessageType,
    ) -> ProcessingResult {
        let result = (|| {
            let instance_id = self.validate_message(message)?;
            match message_type {
                MessageType::ForwardStreamFrame => {
                    let frame = wire::StreamFrame::parse(message.message_body.clone())?;
                    if matches!(frame.payload, wire::FramePayload::Open { .. }) {
                        return Err("Fabric stream execution is not available".to_string());
                    }
                    self.registry
                        .deliver(message, instance_id, frame)?;
                    Ok(ProcessingResult::ProcessedNoResponse)
                }
                MessageType::ForwardStreamQuery | MessageType::ForwardStreamDisclose => {
                    if serde_json::to_vec(&message.message_body)
                        .map_err(|error| error.to_string())?
                        .len()
                        > 4096
                    {
                        return Err("Fabric capability message exceeds the byte limit".to_string());
                    }
                    let capabilities: CapabilityMessage =
                        serde_json::from_value(message.message_body.clone()).map_err(|error| error.to_string())?;
                    if matches!(message_type, MessageType::ForwardStreamDisclose) {
                        self.peers
                            .accept(message, instance_id, capabilities, Instant::now())?;
                        Ok(ProcessingResult::ProcessedNoResponse)
                    } else {
                        let binding = registry::StreamBinding {
                            peer_did: message
                                .from_did
                                .clone()
                                .ok_or("Missing Fabric peer")?,
                            recipient_did: message
                                .context
                                .get(RECIPIENT_CONTEXT)
                                .and_then(serde_json::Value::as_str)
                                .ok_or("Missing Fabric recipient")?
                                .to_string(),
                            connection_point_id: message
                                .connection_point_id
                                .clone(),
                            listener_instance_id: instance_id.to_string(),
                            surface_id: "capabilities".to_string(),
                        };
                        // A query is admitted like a `forward-request`, so a
                        // captured one cannot recreate an expired offer.
                        crate::gateways::connection_points::envelope_replay::check_capability_query(message)
                            .map_err(|rejection| rejection.to_string())?;
                        let capabilities = self
                            .peers
                            .offer(message, binding, capabilities, Instant::now())?;
                        crate::gateways::connection_points::envelope_replay::admit_capability_query(message)
                            .map_err(|rejection| rejection.to_string())?;
                        Ok(ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardStreamDisclose.to_string(),
                            response_body: serde_json::to_value(capabilities).map_err(|error| error.to_string())?,
                        })
                    }
                }
                _ => Err("Unexpected Fabric stream message type".to_string()),
            }
        })();
        result.unwrap_or_else(|reason| ProcessingResult::Failed { reason })
    }
}

/// Why a Fabric `Open` was refused, and the code its sender is answered with.
/// A refusal without a specific code is `Unavailable`, which the sender does
/// not treat as a reason to negotiate again.
#[derive(Debug)]
pub(crate) struct OpenRefusal {
    pub code: wire::StreamErrorCode,
    reason: String,
}

impl OpenRefusal {
    pub(crate) fn new(
        code: wire::StreamErrorCode,
        reason: impl Into<String>,
    ) -> Self {
        Self { code, reason: reason.into() }
    }
}

impl From<String> for OpenRefusal {
    fn from(reason: String) -> Self {
        Self::new(wire::StreamErrorCode::Unavailable, reason)
    }
}

impl From<&str> for OpenRefusal {
    fn from(reason: &str) -> Self {
        Self::new(wire::StreamErrorCode::Unavailable, reason)
    }
}

impl std::fmt::Display for OpenRefusal {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

pub(crate) struct IncomingStream {
    receiver: registry::ReceiveLease,
    sender: registry::SendLease,
    stream_id: Uuid,
    pub binding: registry::StreamBinding,
    pub capabilities: StreamCapabilities,
    message: ReceivedMessage,
    headers: axum::http::HeaderMap,
    surface: crate::config::agent_surface::AgentSurface,
    variant_id: Option<String>,
    declared_bytes: u64,
    limits: crate::config::McpHttpConfig,
    deadline: tokio::time::Instant,
    /// Answered in place of executing the request.
    rejection: Option<Box<crate::mcp::request_validation::McpRequestValidationError>>,
}

impl IncomingStream {
    pub async fn run(
        self,
        sink: Arc<dyn transport::FrameSink>,
    ) {
        let continuations = crate::mcp::continuations::config::global().map(|runtime| Arc::new(runtime.clone()));
        self.run_with_mcp_runtime(
            sink,
            crate::mcp::request_validation::runtime_policy_for(
                crate::mcp::request_validation::McpPathKind::FabricReceive,
            ),
            continuations,
        )
        .await;
    }

    pub(crate) async fn run_with_mcp_runtime(
        self,
        sink: Arc<dyn transport::FrameSink>,
        versions: crate::mcp::request_validation::McpVersionPolicy<'static>,
        continuations: Option<Arc<crate::mcp::continuations::config::ContinuationRuntime>>,
    ) {
        let stream_id = self.stream_id;
        // A peer that stops uploading, or stops acknowledging the response,
        // releases its slots after the idle timeout rather than the deadline.
        let progress_timeout = std::time::Duration::from_secs(
            self.limits
                .stream_idle_timeout_secs
                .get(),
        );
        let mut receiver = self.receiver;
        receiver.set_progress_timeout(progress_timeout);
        self.sender
            .credit()
            .set_progress_timeout(progress_timeout);
        let result = transport::run_incoming_request(
            sink.clone(),
            receiver,
            self.sender,
            stream_id,
            self.declared_bytes,
            self.limits
                .max_request_bytes
                .get(),
            self.limits
                .max_response_bytes
                .get(),
            self.deadline,
            move |body| async move {
                if let Some(rejection) = self.rejection {
                    return ProcessingResult::StreamingResponse {
                        response: rejection.into_response(),
                    };
                }
                crate::gateways::connection_points::message_processor::process_stream_forward_request(
                    &self.message,
                    crate::gateways::connection_points::message_processor::FabricStreamRequest {
                        body,
                        headers: self.headers,
                        surface: self.surface,
                        variant_id: self.variant_id,
                        capabilities: self.capabilities,
                    },
                    versions,
                    continuations,
                )
                .await
            },
        )
        .await;
        if let Err(code) = result {
            tracing::warn!(?code, %stream_id, "Fabric stream receiver failed");
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                sink.send(wire::StreamFrame {
                    stream_id,
                    payload: wire::FramePayload::Error { code },
                }),
            )
            .await;
        }
    }
}

pub(crate) struct ListenerGeneration {
    runtime: Arc<StreamRuntime>,
    connection_point_id: String,
    instance_id: String,
    recipient: String,
    queued: tokio::sync::mpsc::Receiver<StreamTask>,
}

impl ListenerGeneration {
    pub async fn next_outgoing(&mut self) -> Option<StreamTask> {
        self.queued.recv().await
    }

    /// Spawns queued outgoing stream tasks onto `tasks` until `until` completes, polling `until` in place so a
    /// pending SDK pickup passed by reference is never dropped. Fails once this generation is replaced.
    pub async fn serve_outgoing_until<T>(
        &mut self,
        tasks: &mut tokio::task::JoinSet<()>,
        until: impl std::future::Future<Output = T>,
    ) -> Result<T, String> {
        let mut until = std::pin::pin!(until);
        loop {
            tokio::select! {
                task = self.next_outgoing() => {
                    tasks.spawn(task.ok_or("Fabric listener generation was replaced")?);
                    while tasks.try_join_next().is_some() {}
                }
                output = &mut until => return Ok(output),
            }
        }
    }

    pub fn stamp(
        &self,
        message: &mut ReceivedMessage,
    ) {
        message
            .context
            .insert(INSTANCE_CONTEXT.to_string(), serde_json::json!(self.instance_id));
        message
            .context
            .insert(RECIPIENT_CONTEXT.to_string(), serde_json::json!(self.recipient));
    }
}

impl Drop for ListenerGeneration {
    fn drop(&mut self) {
        self.runtime
            .registry
            .cancel_listener(&self.connection_point_id, &self.instance_id);
        self.runtime
            .peers
            .remove_listener(&self.connection_point_id, &self.instance_id);
        if let Ok(mut listeners) = self.runtime.listeners.lock()
            && listeners
                .get(&self.connection_point_id)
                .is_some_and(|listener| listener.instance_id == self.instance_id)
        {
            listeners.remove(&self.connection_point_id);
        }
    }
}

pub(crate) fn global() -> Result<&'static Arc<StreamRuntime>, String> {
    static RUNTIME: OnceLock<Result<Arc<StreamRuntime>, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(StreamRuntime::new)
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;

    #[tokio::test]
    async fn incoming_open_uses_current_peer_offer_and_surface() {
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
        use crate::gateways::types::{Gateway, GatewayType};
        use crate::mcp::request_validation::{McpPathKind, McpVersionPolicy, runtime_policy_for};
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};
        use serde_json::json;

        if std::env::var_os("ATG_FABRIC_STREAM_ADMISSION_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_FABRIC_STREAM_ADMISSION_CHILD", "1")
                .env("RUST_MIN_STACK", "8388608")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "isolated Open admission failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Fabric receive resolves the sender under the parent of the surface
        // store, so surfaces and paired peers share one storage root.
        let directory = tempfile::tempdir().unwrap();
        let surfaces_path = directory
            .path()
            .join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(surfaces_path.clone())
            .await
            .unwrap();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "Surface",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://target.example/mcp"},
            "variants": [
                {"id": "variant", "alias": "candidate", "name": "Candidate", "overrides": {
                    "target": {"endpoint": "https://candidate.example/mcp"}
                }},
                {"id": "disabled", "alias": "disabled", "name": "Disabled", "enabled": false}
            ]
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        let mut connection = GatewayConnectionPoint::new(
            "gateway".into(),
            "mediator".into(),
            "did:example:local".into(),
            "Connection".into(),
            String::new(),
            "oob".into(),
            String::new(),
            json!({}),
            None,
            ConnectionPointType::User,
            String::new(),
        );
        connection.id = "cp".into();
        let peer = Gateway::new("Peer".into(), String::new(), "did:example:peer".into(), GatewayType::Remote);
        let mut paired = peer.clone();
        paired.issuer_did = Some("did:example:peer-gateway".into());
        let _paired_dir =
            crate::gateways::test_helpers::install_listener_manager_with_peers(directory.path(), &[paired]).await;
        let capabilities = StreamCapabilities::local(true, true);
        let runtime = Arc::new(StreamRuntime {
            registry: ReceiveRegistry::new(RegistryLimits {
                max_streams: 4,
                max_peer_streams: 4,
                max_surface_streams: 4,
            })
            .unwrap(),
            peers: PeerCapabilities::new(capabilities.clone()),
            local_capabilities: capabilities.clone(),
            listeners: Mutex::new(HashMap::new()),
        });
        let listener = runtime
            .listener(
                connection.id.clone(),
                connection
                    .connection_point_did
                    .clone(),
            )
            .unwrap();
        let nonce = Uuid::new_v4();
        let mut offer = ReceivedMessage::new(
            connection.id.clone(),
            peer.id.clone(),
            MessageType::ForwardStreamQuery.to_string(),
            nonce.to_string(),
            Some(nonce.to_string()),
            Some(peer.did.clone()),
            vec![
                connection
                    .connection_point_did
                    .clone(),
            ],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(CapabilityMessage { nonce, capabilities }).unwrap(),
            MessageMetadata {
                authenticated: true,
                encrypted: true,
                from_key: None,
                extra: json!(null),
            },
        );
        listener.stamp(&mut offer);
        assert!(matches!(
            runtime.process(&offer, &MessageType::ForwardStreamQuery),
            ProcessingResult::RequiresResponse { .. }
        ));
        let stream_id = Uuid::new_v4();
        let request = wire::OpenRequest {
            capability_nonce: nonce,
            channel_id: surface.surface_id.clone(),
            variant_alias: None,
            path: "/mcp".into(),
            headers: std::collections::BTreeMap::from([
                ("mcp-protocol-version".into(), vec![crate::mcp::MCP_MODERN_VERSION.into()]),
                ("mcp-method".into(), vec!["tools/list".into()]),
                ("x-repeated".into(), vec!["first".into(), "second".into()]),
            ]),
            body_bytes: 0,
            response_window_bytes: wire::MAX_CHUNK_BYTES as u32,
            deadline_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 30_000,
            trace_id: Uuid::new_v4(),
        };
        let mut message = ReceivedMessage::new(
            connection.id.clone(),
            peer.id.clone(),
            MessageType::ForwardStreamFrame.to_string(),
            Uuid::new_v4().to_string(),
            Some(stream_id.to_string()),
            Some(peer.did.clone()),
            vec![
                connection
                    .connection_point_did
                    .clone(),
            ],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(wire::StreamFrame {
                stream_id,
                payload: wire::FramePayload::Open { request },
            })
            .unwrap(),
            MessageMetadata {
                authenticated: true,
                encrypted: true,
                from_key: None,
                extra: json!(null),
            },
        )
        .with_context("agent_surface_storage_path", json!(surfaces_path));
        listener.stamp(&mut message);
        assert!(runtime_policy_for(McpPathKind::FabricReceive).supports_modern(crate::mcp::MCP_MODERN_VERSION));
        let versions = McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let incoming = runtime
            .prepare_incoming_with_versions(&message, &connection, &peer, versions)
            .await
            .unwrap();
        assert_eq!(incoming.surface.surface_id, surface.surface_id);
        assert_eq!(
            incoming
                .surface
                .target
                .endpoint,
            surface.target.endpoint
        );
        assert_eq!(
            incoming
                .headers
                .get_all("x-repeated")
                .iter()
                .count(),
            2
        );
        assert_eq!(incoming.message.message_body["headers"]["x-repeated"], json!(["first", "second"]));
        assert_eq!(incoming.binding.peer_did, peer.did);
        assert_eq!(incoming.binding.recipient_did, connection.connection_point_did);
        assert!(
            runtime
                .prepare_incoming_with_versions(&message, &connection, &peer, versions)
                .await
                .is_err()
        );
        drop(incoming);
        assert!(
            runtime
                .prepare_incoming_with_versions(&message, &connection, &peer, versions)
                .await
                .is_err()
        );
        let fresh_message = || {
            let mut next = message.clone();
            let id = Uuid::new_v4();
            // Each Open is its own envelope; receive refuses a replayed message id.
            next.didcomm_message_id = Uuid::new_v4().to_string();
            next.didcomm_thid = Some(id.to_string());
            next.message_body["stream_id"] = json!(id);
            next
        };
        let mut variant_message = fresh_message();
        variant_message.message_body["payload"]["request"]["variant_alias"] = json!("candidate");
        let variant = runtime
            .prepare_incoming_with_versions(&variant_message, &connection, &peer, versions)
            .await
            .unwrap();
        assert_eq!(
            variant
                .surface
                .target
                .endpoint,
            "https://candidate.example/mcp"
        );
        assert_eq!(variant.message.message_body["virtual_channel_alias"], "candidate");
        assert_eq!(variant.variant_id.as_deref(), Some("variant"));
        assert_eq!(
            variant
                .surface
                .access_point
                .route,
            surface.access_point.route
        );
        let mut replaced = surface.clone();
        replaced.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some("https://reloaded.example/mcp".into());
        store
            .save(&replaced)
            .await
            .unwrap();
        assert_eq!(
            variant
                .surface
                .target
                .endpoint,
            "https://candidate.example/mcp"
        );
        drop(variant);
        store
            .save(&surface)
            .await
            .unwrap();

        for rejected in [
            "connection-disabled",
            "connection-exposure",
            "peer-disabled",
            "peer-local",
            "peer-exposure",
            "peer-did",
            "missing-offer",
            "past-deadline",
            "body-limit",
            "window-limit",
            "missing-surface",
            "missing-variant",
            "disabled-variant",
        ] {
            let valid = fresh_message();
            let mut invalid = valid.clone();
            let mut invalid_connection = connection.clone();
            let mut invalid_peer = peer.clone();
            let request = &mut invalid.message_body["payload"]["request"];
            match rejected {
                "connection-disabled" => invalid_connection.enabled = false,
                "connection-exposure" => invalid_connection.exposed_channels = vec!["other".into()],
                "peer-disabled" => invalid_peer.status = crate::gateways::types::GatewayStatus::Disabled,
                "peer-local" => invalid_peer.gateway_type = GatewayType::SelfGateway,
                "peer-exposure" => invalid_peer.exposed_channels = vec!["other".into()],
                "peer-did" => invalid_peer.did = "did:example:other".into(),
                "missing-offer" => request["capability_nonce"] = json!(Uuid::new_v4()),
                "past-deadline" => request["deadline_ms"] = json!(1),
                "body-limit" => request["body_bytes"] = json!(1024 * 1024 + 1),
                "window-limit" => request["response_window_bytes"] = json!(wire::MAX_WINDOW_BYTES + 1),
                "missing-surface" => request["channel_id"] = json!("missing"),
                "missing-variant" => request["variant_alias"] = json!("missing"),
                "disabled-variant" => request["variant_alias"] = json!("disabled"),
                _ => unreachable!(),
            }
            let refusal = runtime
                .prepare_incoming_with_versions(&invalid, &invalid_connection, &invalid_peer, versions)
                .await
                .err()
                .unwrap_or_else(|| panic!("{rejected} was admitted"));
            // Only a missing offer asks the sender to negotiate again.
            let expected = if rejected == "missing-offer" {
                wire::StreamErrorCode::StaleOffer
            } else {
                wire::StreamErrorCode::Unavailable
            };
            assert_eq!(refusal.code, expected, "{rejected}");
            drop(
                runtime
                    .prepare_incoming_with_versions(&valid, &connection, &peer, versions)
                    .await
                    .unwrap_or_else(|error| panic!("{rejected} consumed admission state: {error}")),
            );
        }
        // An Open envelope is admitted like a forward-request: without a valid
        // expiry it is refused, and the refusal consumes no admission state.
        let now_secs = crate::gateways::connection_points::envelope_replay::now_secs();
        for expires_time in [None, Some(now_secs - 1), Some(now_secs + 7200)] {
            let valid = fresh_message();
            let mut invalid = valid.clone();
            invalid.expires_time = expires_time;
            let refusal = runtime
                .prepare_incoming_with_versions(&invalid, &connection, &peer, versions)
                .await
                .err()
                .unwrap_or_else(|| panic!("an Open expiring at {expires_time:?} was admitted"));
            assert_eq!(refusal.code, wire::StreamErrorCode::Unavailable, "{expires_time:?}");
            drop(
                runtime
                    .prepare_incoming_with_versions(&valid, &connection, &peer, versions)
                    .await
                    .unwrap_or_else(|error| panic!("{expires_time:?} consumed admission state: {error}")),
            );
        }
        // A deadline beyond this endpoint's lifetime (a peer with a longer
        // lifetime, or a clock ahead of this one) is bounded, not refused.
        let mut long = fresh_message();
        long.message_body["payload"]["request"]["deadline_ms"] = json!(u64::MAX);
        let bounded = runtime
            .prepare_incoming_with_versions(&long, &connection, &peer, versions)
            .await
            .expect("a deadline beyond the lifetime is bounded");
        let lifetime_ms = surface
            .mcp_http
            .clone()
            .unwrap_or_default()
            .stream_max_lifetime_secs
            .get()
            * 1000;
        let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
        let forwarded_deadline = bounded.message.message_body["deadline_ms"]
            .as_u64()
            .unwrap();
        assert!(forwarded_deadline <= now_ms + lifetime_ms, "{forwarded_deadline} exceeds the lifetime");
        assert!(forwarded_deadline + 60_000 > now_ms + lifetime_ms, "the lifetime bound, not a shorter one");
        drop(bounded);
        // A receiver that does not serve modern MCP is named as such, so the
        // sender can answer as a legacy endpoint would.
        assert_eq!(
            runtime
                .prepare_incoming_with_versions(
                    &fresh_message(),
                    &connection,
                    &peer,
                    crate::mcp::request_validation::LEGACY_ONLY_POLICY,
                )
                .await
                .err()
                .expect("a legacy-only receiver refuses modern streams")
                .code,
            wire::StreamErrorCode::LegacyOnly
        );
        for change in ["disabled", "other-protocol", "empty-variant-catalog"] {
            let mut changed = surface.clone();
            match change {
                "disabled" => changed.status = crate::config::agent_surface::SurfaceStatus::Disabled,
                "other-protocol" => changed.access_point.protocol = serde_json::from_value(json!("a2a")).unwrap(),
                "empty-variant-catalog" => changed.variants.clear(),
                _ => unreachable!(),
            }
            store
                .save(&changed)
                .await
                .unwrap();
            let mut pending = fresh_message();
            if change == "empty-variant-catalog" {
                pending.message_body["payload"]["request"]["variant_alias"] = json!("candidate");
            }
            let refusal = runtime
                .prepare_incoming_with_versions(&pending, &connection, &peer, versions)
                .await
                .err()
                .unwrap_or_else(|| panic!("{change} was admitted"));
            assert_eq!(refusal.code, wire::StreamErrorCode::Unavailable, "{change}");
            store
                .save(&surface)
                .await
                .unwrap();
            drop(
                runtime
                    .prepare_incoming_with_versions(&pending, &connection, &peer, versions)
                    .await
                    .unwrap(),
            );
        }
        // A tenant-owned peer reaches its own tenant's and appliance-wide
        // surfaces, never another tenant's, even with empty exposure lists.
        let mut tenant_surface = surface.clone();
        tenant_surface.tenant_id = Some("tenant-a".into());
        store
            .save(&tenant_surface)
            .await
            .unwrap();
        for (peer_tenant, admitted) in [(None, true), (Some("tenant-a"), true), (Some("tenant-b"), false)] {
            let mut tenant_peer = peer.clone();
            tenant_peer.tenant_id = peer_tenant.map(str::to_string);
            let result = runtime
                .prepare_incoming_with_versions(&fresh_message(), &connection, &tenant_peer, versions)
                .await;
            assert_eq!(result.is_ok(), admitted, "peer tenant {peer_tenant:?}");
        }
        store
            .save(&surface)
            .await
            .unwrap();
        let mut tenant_peer = peer.clone();
        tenant_peer.tenant_id = Some("tenant-b".into());
        drop(
            runtime
                .prepare_incoming_with_versions(&fresh_message(), &connection, &tenant_peer, versions)
                .await
                .expect("a tenant-owned peer reaches an appliance-wide surface"),
        );
        struct RecordingSink(tokio::sync::mpsc::Sender<wire::StreamFrame>);
        #[async_trait::async_trait]
        impl transport::FrameSink for RecordingSink {
            async fn send(
                &self,
                frame: wire::StreamFrame,
            ) -> Result<(), wire::StreamErrorCode> {
                self.0
                    .send(frame)
                    .await
                    .map_err(|_| wire::StreamErrorCode::Unavailable)
            }
        }
        let target_result = json!({"jsonrpc": "2.0", "id": "framed-request", "result": {
            "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private",
            "_meta": {"com.example/preserved": [true, null]}
        }});
        let target = crate::component_tests::helpers::MockServer::start_with_response(target_result.to_string()).await;
        let mut routed = surface.clone();
        routed.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some(format!("http://{}", target.addr));
        store
            .save(&routed)
            .await
            .unwrap();
        for case in
            ["valid", "missing-capabilities", "duplicate-method", "empty", "untrusted-origin", "legacy-receiver"]
        {
            let mut body = json!({"jsonrpc": "2.0", "id": "framed-request", "method": "tools/list", "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }}});
            if case == "missing-capabilities" {
                body["params"]["_meta"]
                    .as_object_mut()
                    .unwrap()
                    .remove("io.modelcontextprotocol/clientCapabilities");
            }
            let bytes = if case == "empty" {
                bytes::Bytes::new()
            } else {
                serde_json::to_vec(&body)
                    .unwrap()
                    .into()
            };
            let mut upload = fresh_message();
            let request = &mut upload.message_body["payload"]["request"];
            request["variant_alias"] = json!("candidate");
            request["body_bytes"] = json!(bytes.len());
            request["headers"]["content-type"] = json!(["application/json"]);
            request["headers"]["accept"] = json!(["application/json, text/event-stream"]);
            request["headers"]["mcp-session-id"] = json!(["must-not-reach-target"]);
            if case == "duplicate-method" {
                request["headers"]["mcp-method"] = json!(["tools/list", "tools/list"]);
            }
            // Refused like a direct endpoint refuses it, not by dropping the
            // stream and leaving the sender to time out.
            if case == "untrusted-origin" {
                request["headers"]["origin"] = json!(["https://untrusted.example"]);
            }
            let incoming = runtime
                .prepare_incoming_with_versions(&upload, &connection, &peer, versions)
                .await
                .unwrap();
            let id = incoming.stream_id;
            let mut sequence = 0;
            let mut offset = 0;
            for chunk in bytes.chunks(64) {
                let mut data = upload.clone();
                data.message_body = serde_json::to_value(wire::StreamFrame {
                    stream_id: id,
                    payload: wire::FramePayload::RequestData {
                        sequence,
                        offset,
                        data: wire::encode_chunk(chunk).unwrap(),
                    },
                })
                .unwrap();
                assert!(matches!(
                    runtime.process(&data, &MessageType::ForwardStreamFrame),
                    ProcessingResult::ProcessedNoResponse
                ));
                sequence += 1;
                offset += chunk.len() as u64;
            }
            let mut end = upload.clone();
            end.message_body = serde_json::to_value(wire::StreamFrame {
                stream_id: id,
                payload: wire::FramePayload::RequestEnd {
                    next_sequence: sequence,
                    body_bytes: offset,
                },
            })
            .unwrap();
            assert!(matches!(
                runtime.process(&end, &MessageType::ForwardStreamFrame),
                ProcessingResult::ProcessedNoResponse
            ));
            let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(16);
            let receiver_versions = if case == "legacy-receiver" {
                crate::mcp::request_validation::LEGACY_ONLY_POLICY
            } else {
                versions
            };
            let run =
                Box::pin(incoming.run_with_mcp_runtime(Arc::new(RecordingSink(frames_tx)), receiver_versions, None));
            let consume = async {
                let mut status = None;
                let mut response_bytes = Vec::new();
                let mut response_sequence = 0;
                let mut finished = false;
                while let Some(frame) = frames_rx.recv().await {
                    let control = match frame.payload {
                        wire::FramePayload::Credit {
                            direction: wire::StreamDirection::Request,
                            ..
                        } => None,
                        wire::FramePayload::Start { status: value, headers } => {
                            assert!(
                                status
                                    .replace(value)
                                    .is_none()
                            );
                            assert!(!headers.contains_key("mcp-session-id"));
                            None
                        }
                        wire::FramePayload::Data { sequence, offset, data } => {
                            assert_eq!(sequence, response_sequence);
                            assert_eq!(offset, response_bytes.len() as u64);
                            response_bytes.extend_from_slice(&wire::decode_chunk(&data).unwrap());
                            response_sequence += 1;
                            Some(wire::FramePayload::Credit {
                                direction: wire::StreamDirection::Response,
                                next_sequence: response_sequence,
                                consumed_bytes: response_bytes.len() as u64,
                            })
                        }
                        wire::FramePayload::End { next_sequence, body_bytes } => {
                            assert_eq!(next_sequence, response_sequence);
                            assert_eq!(body_bytes, response_bytes.len() as u64);
                            finished = true;
                            Some(wire::FramePayload::EndAck { next_sequence, body_bytes })
                        }
                        other => panic!("unexpected receiver frame for {case}: {other:?}"),
                    };
                    if let Some(payload) = control {
                        let mut acknowledged = upload.clone();
                        acknowledged.message_body =
                            serde_json::to_value(wire::StreamFrame { stream_id: id, payload }).unwrap();
                        assert!(matches!(
                            runtime.process(&acknowledged, &MessageType::ForwardStreamFrame),
                            ProcessingResult::ProcessedNoResponse
                        ));
                    }
                }
                assert!(finished, "{case}");
                (status.unwrap(), serde_json::from_slice::<serde_json::Value>(&response_bytes).unwrap())
            };
            let (_, (status, received)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async { tokio::join!(run, consume) })
                    .await
                    .expect("framed receiver execution timed out");
            if case == "valid" {
                assert_eq!(status, 200, "{received}");
                assert_eq!(received, target_result);
                let request = target
                    .last_request_rx
                    .borrow()
                    .clone()
                    .unwrap();
                assert!(
                    !request
                        .headers
                        .contains_key("mcp-session-id")
                );
                assert_eq!(serde_json::from_str::<serde_json::Value>(&request.body).unwrap()["method"], "tools/list");
            } else {
                let (expected_status, expected) = match case {
                    "missing-capabilities" => (400, -32602),
                    "duplicate-method" => (400, -32020),
                    "empty" => (400, -32700),
                    "untrusted-origin" => (403, -32600),
                    "legacy-receiver" => (400, -32022),
                    _ => unreachable!(),
                };
                assert_eq!(status, expected_status, "{case}: {received}");
                assert_eq!(received["error"]["code"], expected, "{case}");
                if case == "empty" || case == "untrusted-origin" {
                    assert!(received.get("id").is_none());
                } else {
                    assert_eq!(received["id"], "framed-request");
                }
            }
            assert_eq!(
                target
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{case}"
            );
        }
        use futures::StreamExt;
        let release = Arc::new(tokio::sync::Notify::new());
        let (outcomes_tx, mut outcomes_rx) = tokio::sync::mpsc::channel(2);
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let upstream_address = tcp.local_addr().unwrap();
        let final_message = target_result.clone();
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
                    let progress = bytes::Bytes::from(format!(
                        "data: {}\r\n\r\n",
                        json!({
                            "jsonrpc": "2.0", "method": "notifications/progress", "params": {
                                "progressToken": "framed-progress", "progress": 1,
                                "_meta": {"com.example/preserved": [true, null]}
                            }
                        })
                    ));
                    let source = futures::stream::once(async { Ok::<_, std::io::Error>(progress) }).chain(
                        futures::stream::once(async move {
                            release.notified().await;
                            Ok(bytes::Bytes::from(format!("data: {final_message}\n\n")))
                        }),
                    );
                    let response = axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(source))
                        .unwrap();
                    crate::mcp::modern_sse::observe_response(response, move |outcome| {
                        let _ = outcomes.try_send(outcome);
                    })
                }
            }
        }));
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move {
            axum::serve(tcp, upstream)
                .await
                .unwrap();
        });
        routed.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some(format!("http://{upstream_address}"));
        store
            .save(&routed)
            .await
            .unwrap();
        for finish in [true, false] {
            let body = json!({"jsonrpc": "2.0", "id": "framed-request", "method": "tools/list", "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}, "progressToken": "framed-progress"
            }}});
            let bytes = serde_json::to_vec(&body).unwrap();
            let mut upload = fresh_message();
            let request = &mut upload.message_body["payload"]["request"];
            request["variant_alias"] = json!("candidate");
            request["body_bytes"] = json!(bytes.len());
            request["headers"]["content-type"] = json!(["application/json"]);
            request["headers"]["accept"] = json!(["application/json, text/event-stream"]);
            request["headers"]["mcp-session-id"] = json!(["must-not-reach-target"]);
            let incoming = runtime
                .prepare_incoming_with_versions(&upload, &connection, &peer, versions)
                .await
                .unwrap();
            let id = incoming.stream_id;
            for payload in [
                wire::FramePayload::RequestData {
                    sequence: 0,
                    offset: 0,
                    data: wire::encode_chunk(&bytes).unwrap(),
                },
                wire::FramePayload::RequestEnd {
                    next_sequence: 1,
                    body_bytes: bytes.len() as u64,
                },
            ] {
                let mut frame = upload.clone();
                frame.message_body = serde_json::to_value(wire::StreamFrame { stream_id: id, payload }).unwrap();
                assert!(matches!(
                    runtime.process(&frame, &MessageType::ForwardStreamFrame),
                    ProcessingResult::ProcessedNoResponse
                ));
            }
            let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(16);
            let run = Box::pin(incoming.run_with_mcp_runtime(Arc::new(RecordingSink(frames_tx)), versions, None));
            let consume = async {
                let mut response_bytes = Vec::new();
                let mut saw_progress = false;
                let mut completed = false;
                let mut cancelled = false;
                while let Some(frame) = frames_rx.recv().await {
                    let control = match frame.payload {
                        wire::FramePayload::Credit {
                            direction: wire::StreamDirection::Request,
                            ..
                        } => None,
                        wire::FramePayload::Start { status, headers } => {
                            assert_eq!(status, 200);
                            assert_eq!(headers["content-type"], vec!["text/event-stream"]);
                            None
                        }
                        wire::FramePayload::Data { sequence, offset, data } => {
                            assert_eq!(offset, response_bytes.len() as u64);
                            response_bytes.extend_from_slice(&wire::decode_chunk(&data).unwrap());
                            if !saw_progress {
                                let source = futures::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(
                                    response_bytes.clone(),
                                ))]);
                                let events = crate::mcp::modern_sse::decode_events(
                                    source,
                                    crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                                );
                                let mut events = Box::pin(events);
                                if let Some(event) = events.next().await {
                                    let progress: serde_json::Value =
                                        serde_json::from_str(&event.unwrap().data).unwrap();
                                    assert_eq!(progress["method"], "notifications/progress");
                                    assert_eq!(
                                        progress["params"]["_meta"]["com.example/preserved"],
                                        json!([true, null])
                                    );
                                    assert!(
                                        outcomes_rx
                                            .try_recv()
                                            .is_err(),
                                        "Target completed before progress was delivered"
                                    );
                                    saw_progress = true;
                                    if finish {
                                        release.notify_one();
                                    }
                                }
                            }
                            if saw_progress && !finish {
                                Some(wire::FramePayload::Cancel)
                            } else {
                                Some(wire::FramePayload::Credit {
                                    direction: wire::StreamDirection::Response,
                                    next_sequence: sequence + 1,
                                    consumed_bytes: response_bytes.len() as u64,
                                })
                            }
                        }
                        wire::FramePayload::End { next_sequence, body_bytes } => {
                            assert!(finish && saw_progress);
                            assert_eq!(body_bytes, response_bytes.len() as u64);
                            completed = true;
                            Some(wire::FramePayload::EndAck { next_sequence, body_bytes })
                        }
                        wire::FramePayload::Error {
                            code: wire::StreamErrorCode::Cancelled,
                        } => {
                            assert!(!finish && saw_progress);
                            cancelled = true;
                            None
                        }
                        other => panic!("unexpected streamed receiver frame: {other:?}"),
                    };
                    if let Some(payload) = control {
                        let mut frame = upload.clone();
                        frame.message_body =
                            serde_json::to_value(wire::StreamFrame { stream_id: id, payload }).unwrap();
                        assert!(matches!(
                            runtime.process(&frame, &MessageType::ForwardStreamFrame),
                            ProcessingResult::ProcessedNoResponse
                        ));
                    }
                }
                assert_eq!(completed, finish);
                assert_eq!(cancelled, !finish);
                if finish {
                    let source = futures::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(response_bytes))]);
                    let mut events = Box::pin(crate::mcp::modern_sse::decode_events(
                        source,
                        crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                    ));
                    assert!(
                        events
                            .next()
                            .await
                            .unwrap()
                            .is_ok()
                    );
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(
                            &events
                                .next()
                                .await
                                .unwrap()
                                .unwrap()
                                .data
                        )
                        .unwrap(),
                        target_result
                    );
                    assert!(events.next().await.is_none());
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), async { tokio::join!(run, consume) })
                .await
                .expect("streamed receiver execution timed out");
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), outcomes_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(outcome.completed, finish, "quiet Target did not follow Fabric cancellation");
            assert!(!outcome.failed);
        }
        servers.shutdown().await;
        let stale = fresh_message();
        let replacement = runtime
            .listener(
                connection.id.clone(),
                connection
                    .connection_point_did
                    .clone(),
            )
            .unwrap();
        assert!(
            runtime
                .prepare_incoming_with_versions(&stale, &connection, &peer, versions)
                .await
                .is_err()
        );
        drop((listener, replacement));
        assert!(
            StreamRuntime::new()
                .unwrap()
                .supports_request_streams()
        );
    }

    #[tokio::test]
    async fn outgoing_tasks_are_bounded_and_bound_to_the_current_listener() {
        let runtime = StreamRuntime::new().unwrap();
        let mut listener = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();
        let (instance, recipient) = runtime
            .listener_context("cp")
            .unwrap();
        let binding = registry::StreamBinding {
            peer_did: "did:example:peer".into(),
            recipient_did: recipient,
            connection_point_id: "cp".into(),
            listener_instance_id: instance,
            surface_id: "surface".into(),
        };
        let (ran_tx, ran_rx) = tokio::sync::oneshot::channel();
        runtime
            .enqueue_outgoing(&binding, async move {
                let _ = ran_tx.send(());
            })
            .unwrap();
        listener
            .next_outgoing()
            .await
            .unwrap()
            .await;
        ran_rx.await.unwrap();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel::<()>();
        runtime
            .enqueue_outgoing(&binding, async move {
                let _owned = dropped_tx;
                std::future::pending::<()>().await;
            })
            .unwrap();
        for _ in 1..16 {
            runtime
                .enqueue_outgoing(&binding, std::future::pending())
                .unwrap();
        }
        assert!(
            runtime
                .enqueue_outgoing(&binding, std::future::pending())
                .is_err()
        );
        let replacement = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();
        assert!(
            runtime
                .enqueue_outgoing(&binding, std::future::pending())
                .is_err()
        );
        drop(listener);
        assert!(dropped_rx.await.is_err());
        drop(replacement);
        assert!(
            runtime
                .listener_context("cp")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_refused_open_is_answered_only_on_its_bound_listener() {
        let runtime = StreamRuntime::new().unwrap();
        let listener = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();
        let stream_id = Uuid::new_v4();
        let message = |payload: serde_json::Value| {
            ReceivedMessage::new(
                "cp".into(),
                "gateway".into(),
                MessageType::ForwardStreamFrame.to_string(),
                Uuid::new_v4().to_string(),
                Some(stream_id.to_string()),
                Some("did:example:peer".into()),
                vec!["did:example:local".into()],
                None,
                None,
                serde_json::json!({"stream_id": stream_id, "payload": payload}),
                crate::gateways::connection_points::messages::MessageMetadata {
                    authenticated: true,
                    encrypted: true,
                    from_key: None,
                    extra: serde_json::Value::Null,
                },
            )
        };
        let open = serde_json::to_value(wire::FramePayload::Open {
            request: wire::OpenRequest {
                capability_nonce: Uuid::new_v4(),
                channel_id: "surface".into(),
                variant_alias: None,
                path: "/mcp".into(),
                headers: Default::default(),
                body_bytes: 0,
                response_window_bytes: 65536,
                deadline_ms: 1,
                trace_id: Uuid::new_v4(),
            },
        })
        .unwrap();
        let mut refused = message(open);
        // Not stamped by the listener: not bound, so never answered.
        assert!(
            runtime
                .refused_open_binding(&refused)
                .is_none()
        );
        listener.stamp(&mut refused);
        let (binding, answered) = runtime
            .refused_open_binding(&refused)
            .expect("a bound Open is answered");
        assert_eq!(answered, stream_id);
        assert_eq!(binding.peer_did, "did:example:peer");
        assert_eq!(binding.recipient_did, "did:example:local");
        // Once the stream is accepted, a repeated Open for it is not answered:
        // the Error frame would end the live stream.
        let _accepted = runtime
            .registry
            .open(stream_id, binding, 65536, 65536, tokio::time::Instant::now() + std::time::Duration::from_secs(60))
            .unwrap();
        assert!(
            runtime
                .refused_open_binding(&refused)
                .is_none(),
            "a repeated Open of a live stream"
        );
        let mut cancel = message(serde_json::json!({"kind": "cancel"}));
        listener.stamp(&mut cancel);
        assert!(
            runtime
                .refused_open_binding(&cancel)
                .is_none(),
            "only an Open is answered"
        );
    }

    #[test]
    fn stream_message_types_round_trip_separately_from_legacy_forwarding() {
        for kind in
            [MessageType::ForwardStreamFrame, MessageType::ForwardStreamQuery, MessageType::ForwardStreamDisclose]
        {
            assert_eq!(MessageType::from_str(kind.as_str()), kind);
            assert_eq!(kind.protocol_family(), MessageType::ForwardRequest.protocol_family());
            assert_ne!(kind.as_str(), MessageType::ForwardRequest.as_str());
            assert_ne!(kind.as_str(), MessageType::ForwardResponse.as_str());
        }
    }

    #[tokio::test]
    async fn control_dispatch_requires_current_listener_and_never_advertises_unimplemented_streaming() {
        let runtime = StreamRuntime::new().unwrap();
        let listener = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();
        let nonce = Uuid::new_v4();
        let mut message = ReceivedMessage::new(
            "cp".into(),
            "gateway".into(),
            MessageType::ForwardStreamQuery.to_string(),
            nonce.to_string(),
            Some(nonce.to_string()),
            Some("did:example:peer".into()),
            vec!["did:example:local".into()],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(CapabilityMessage {
                nonce,
                capabilities: StreamCapabilities::local(true, true),
            })
            .unwrap(),
            MessageMetadata {
                authenticated: true,
                encrypted: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        );
        assert!(matches!(runtime.process(&message, &MessageType::ForwardStreamQuery), ProcessingResult::Failed { .. }));
        listener.stamp(&mut message);
        let ProcessingResult::RequiresResponse { response_type, response_body } =
            runtime.process(&message, &MessageType::ForwardStreamQuery)
        else {
            panic!("expected correlated capability response");
        };
        assert_eq!(response_type, MessageType::ForwardStreamDisclose.to_string());
        assert_eq!(response_body["nonce"], nonce.to_string());
        assert_eq!(response_body["capabilities"]["request_streams"], true);
        assert_eq!(response_body["capabilities"]["subscriptions"], true);
        let replacement = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();
        assert!(matches!(runtime.process(&message, &MessageType::ForwardStreamQuery), ProcessingResult::Failed { .. }));
        drop(listener);
        replacement.stamp(&mut message);
        assert!(
            matches!(runtime.process(&message, &MessageType::ForwardStreamQuery), ProcessingResult::Failed { .. }),
            "an answered query is not answered again, even on a replacement listener"
        );
        let nonce = Uuid::new_v4();
        message.didcomm_message_id = nonce.to_string();
        message.didcomm_thid = Some(nonce.to_string());
        message.message_body["nonce"] = serde_json::json!(nonce.to_string());
        assert!(matches!(
            runtime.process(&message, &MessageType::ForwardStreamQuery),
            ProcessingResult::RequiresResponse { .. }
        ));
        drop(replacement);
        assert!(
            runtime
                .listener_context("cp")
                .is_none()
        );
    }

    #[tokio::test]
    async fn open_replay_is_refused_after_the_clamped_lifetime_while_the_offer_is_live() {
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
        use crate::gateways::types::{Gateway, GatewayType};
        use crate::mcp::request_validation::McpVersionPolicy;
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};
        use serde_json::json;

        if std::env::var_os("ATG_FABRIC_STREAM_ADMISSION_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_FABRIC_STREAM_ADMISSION_CHILD", "1")
                .env("RUST_MIN_STACK", "8388608")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "isolated Open replay failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let surfaces_path = directory
            .path()
            .join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(surfaces_path.clone())
            .await
            .unwrap();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "Surface",
            "mcp_http": {"stream_idle_timeout_secs": 1, "stream_max_lifetime_secs": 1},
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://target.example/mcp"}
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        let mut connection = GatewayConnectionPoint::new(
            "gateway".into(),
            "mediator".into(),
            "did:example:local".into(),
            "Connection".into(),
            String::new(),
            "oob".into(),
            String::new(),
            json!({}),
            None,
            ConnectionPointType::User,
            String::new(),
        );
        connection.id = "cp".into();
        let peer = Gateway::new("Peer".into(), String::new(), "did:example:peer".into(), GatewayType::Remote);
        let mut paired = peer.clone();
        paired.issuer_did = Some("did:example:peer-gateway".into());
        let _paired_dir =
            crate::gateways::test_helpers::install_listener_manager_with_peers(directory.path(), &[paired]).await;
        let capabilities = StreamCapabilities::local(true, true);
        let runtime = Arc::new(StreamRuntime {
            registry: ReceiveRegistry::new(RegistryLimits {
                max_streams: 4,
                max_peer_streams: 4,
                max_surface_streams: 4,
            })
            .unwrap(),
            peers: PeerCapabilities::new(capabilities.clone()),
            local_capabilities: capabilities.clone(),
            listeners: Mutex::new(HashMap::new()),
        });
        let listener = runtime
            .listener(
                connection.id.clone(),
                connection
                    .connection_point_did
                    .clone(),
            )
            .unwrap();
        let metadata = || MessageMetadata {
            authenticated: true,
            encrypted: true,
            from_key: None,
            extra: json!(null),
        };
        let nonce = Uuid::new_v4();
        let mut offer = ReceivedMessage::new(
            connection.id.clone(),
            peer.id.clone(),
            MessageType::ForwardStreamQuery.to_string(),
            nonce.to_string(),
            Some(nonce.to_string()),
            Some(peer.did.clone()),
            vec![
                connection
                    .connection_point_did
                    .clone(),
            ],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(CapabilityMessage { nonce, capabilities }).unwrap(),
            metadata(),
        );
        listener.stamp(&mut offer);
        assert!(matches!(
            runtime.process(&offer, &MessageType::ForwardStreamQuery),
            ProcessingResult::RequiresResponse { .. }
        ));
        let stream_id = Uuid::new_v4();
        let request = wire::OpenRequest {
            capability_nonce: nonce,
            channel_id: surface.surface_id.clone(),
            variant_alias: None,
            path: "/mcp".into(),
            headers: std::collections::BTreeMap::from([
                ("mcp-protocol-version".into(), vec![crate::mcp::MCP_MODERN_VERSION.into()]),
                ("mcp-method".into(), vec!["tools/list".into()]),
            ]),
            body_bytes: 0,
            response_window_bytes: wire::MAX_CHUNK_BYTES as u32,
            deadline_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 60_000,
            trace_id: Uuid::new_v4(),
        };
        let mut message = ReceivedMessage::new(
            connection.id.clone(),
            peer.id.clone(),
            MessageType::ForwardStreamFrame.to_string(),
            Uuid::new_v4().to_string(),
            Some(stream_id.to_string()),
            Some(peer.did.clone()),
            vec![
                connection
                    .connection_point_did
                    .clone(),
            ],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(wire::StreamFrame {
                stream_id,
                payload: wire::FramePayload::Open { request },
            })
            .unwrap(),
            metadata(),
        )
        .with_context("agent_surface_storage_path", json!(surfaces_path));
        listener.stamp(&mut message);
        let versions = McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let accepted = runtime
            .prepare_incoming_with_versions(&message, &connection, &peer, versions)
            .await
            .expect("first Open is accepted");
        drop(accepted);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let replay = runtime
            .prepare_incoming_with_versions(&message, &connection, &peer, versions)
            .await;
        assert!(
            replay.is_err(),
            "the same Open envelope was accepted again after the 1 s clamped lifetime, \
             while its 60 s sender deadline, envelope expiry and capability offer are all still live"
        );
    }

    #[tokio::test]
    async fn a_replayed_capability_query_cannot_revive_an_expired_offer_for_a_captured_open() {
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
        use crate::gateways::types::{Gateway, GatewayType};
        use crate::mcp::request_validation::McpVersionPolicy;
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};
        use serde_json::json;

        if std::env::var_os("ATG_FABRIC_STREAM_ADMISSION_CHILD").is_none() {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env("ATG_FABRIC_STREAM_ADMISSION_CHILD", "1")
                .env("RUST_MIN_STACK", "8388608")
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "isolated capability query replay failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let surfaces_path = directory
            .path()
            .join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(surfaces_path.clone())
            .await
            .unwrap();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "Surface",
            "mcp_http": {"stream_idle_timeout_secs": 1, "stream_max_lifetime_secs": 1},
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://target.example/mcp"}
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        let mut connection = GatewayConnectionPoint::new(
            "gateway".into(),
            "mediator".into(),
            "did:example:local".into(),
            "Connection".into(),
            String::new(),
            "oob".into(),
            String::new(),
            json!({}),
            None,
            ConnectionPointType::User,
            String::new(),
        );
        connection.id = "cp".into();
        let peer = Gateway::new("Peer".into(), String::new(), "did:example:peer".into(), GatewayType::Remote);
        let mut paired = peer.clone();
        paired.issuer_did = Some("did:example:peer-gateway".into());
        let _paired_dir =
            crate::gateways::test_helpers::install_listener_manager_with_peers(directory.path(), &[paired]).await;
        let capabilities = StreamCapabilities::local(true, true);
        let runtime = Arc::new(StreamRuntime {
            registry: ReceiveRegistry::new(RegistryLimits {
                max_streams: 4,
                max_peer_streams: 4,
                max_surface_streams: 4,
            })
            .unwrap(),
            peers: PeerCapabilities::new(capabilities.clone()),
            local_capabilities: capabilities.clone(),
            listeners: Mutex::new(HashMap::new()),
        });
        let listener = runtime
            .listener(
                connection.id.clone(),
                connection
                    .connection_point_did
                    .clone(),
            )
            .unwrap();
        let metadata = || MessageMetadata {
            authenticated: true,
            encrypted: true,
            from_key: None,
            extra: json!(null),
        };
        let nonce = Uuid::new_v4();
        let mut offer = ReceivedMessage::new(
            connection.id.clone(),
            peer.id.clone(),
            MessageType::ForwardStreamQuery.to_string(),
            nonce.to_string(),
            Some(nonce.to_string()),
            Some(peer.did.clone()),
            vec![
                connection
                    .connection_point_did
                    .clone(),
            ],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(CapabilityMessage { nonce, capabilities }).unwrap(),
            metadata(),
        );
        listener.stamp(&mut offer);
        assert!(matches!(
            runtime.process(&offer, &MessageType::ForwardStreamQuery),
            ProcessingResult::RequiresResponse { .. }
        ));
        let stream_id = Uuid::new_v4();
        let request = wire::OpenRequest {
            capability_nonce: nonce,
            channel_id: surface.surface_id.clone(),
            variant_alias: None,
            path: "/mcp".into(),
            headers: std::collections::BTreeMap::from([
                ("mcp-protocol-version".into(), vec![crate::mcp::MCP_MODERN_VERSION.into()]),
                ("mcp-method".into(), vec!["tools/list".into()]),
            ]),
            body_bytes: 0,
            response_window_bytes: wire::MAX_CHUNK_BYTES as u32,
            deadline_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 60_000,
            trace_id: Uuid::new_v4(),
        };
        let mut message = ReceivedMessage::new(
            connection.id.clone(),
            peer.id.clone(),
            MessageType::ForwardStreamFrame.to_string(),
            Uuid::new_v4().to_string(),
            Some(stream_id.to_string()),
            Some(peer.did.clone()),
            vec![
                connection
                    .connection_point_did
                    .clone(),
            ],
            None,
            Some(crate::gateways::connection_points::envelope_replay::now_secs() + 60),
            serde_json::to_value(wire::StreamFrame {
                stream_id,
                payload: wire::FramePayload::Open { request },
            })
            .unwrap(),
            metadata(),
        )
        .with_context("agent_surface_storage_path", json!(surfaces_path));
        listener.stamp(&mut message);
        let versions = McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let accepted = runtime
            .prepare_incoming_with_versions(&message, &connection, &peer, versions)
            .await
            .expect("first Open is accepted");
        drop(accepted);
        // Past the offer's lifetime the offer is gone, and so is the Open's
        // replay record, which lasts no longer than the offer. Only the offer
        // is expired here: with no live offer the Open cannot be admitted,
        // whatever its replay record says.
        let binding = registry::StreamBinding {
            peer_did: peer.did.clone(),
            recipient_did: connection
                .connection_point_did
                .clone(),
            connection_point_id: connection.id.clone(),
            listener_instance_id: offer.context[INSTANCE_CONTEXT]
                .as_str()
                .unwrap()
                .to_string(),
            surface_id: "capabilities".into(),
        };
        let past_offer = Instant::now() + std::time::Duration::from_secs(301);
        assert!(
            runtime
                .peers
                .offered(&binding, nonce, past_offer)
                .is_none()
        );
        assert!(
            matches!(runtime.process(&offer, &MessageType::ForwardStreamQuery), ProcessingResult::Failed { .. }),
            "a replayed capability query is refused while its envelope is live"
        );
        assert!(
            runtime
                .peers
                .offered(&binding, nonce, Instant::now())
                .is_none(),
            "the replayed query did not recreate the offer"
        );
        let replay = runtime
            .prepare_incoming_with_versions(&message, &connection, &peer, versions)
            .await;
        assert!(replay.is_err(), "the captured Open has no offer to be admitted under");
    }
}
