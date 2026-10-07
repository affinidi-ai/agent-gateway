use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio::sync::watch;
use tokio::time::Instant;
use uuid::Uuid;

use super::registry::{ReceiveEvent, ReceiveLease, SendLease};
use super::wire::{
    FramePayload, MAX_CHUNK_BYTES, StreamDirection, StreamErrorCode, StreamFrame, encode_chunk, encode_headers,
    headers_from_json,
};
use crate::gateways::connection_points::message_processor::ProcessingResult;

type DeliveryCallback = Box<dyn FnOnce(crate::mcp::modern_sse::ResponseOutcome) + Send>;

struct DeliveryCompletion(std::sync::Mutex<Option<DeliveryCallback>>);

impl DeliveryCompletion {
    fn finish(
        &self,
        outcome: crate::mcp::modern_sse::ResponseOutcome,
    ) {
        let complete = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(complete) = complete {
            complete(outcome);
        }
    }
}

impl Drop for DeliveryCompletion {
    fn drop(&mut self) {
        if let Some(complete) = self
            .0
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            complete(crate::mcp::modern_sse::ResponseOutcome::default());
        }
    }
}

#[derive(Clone)]
struct DeliveryObserver(Arc<DeliveryCompletion>);

pub(crate) fn observe_delivery(
    mut response: axum::response::Response,
    complete: impl FnOnce(crate::mcp::modern_sse::ResponseOutcome) + Send + 'static,
) -> axum::response::Response {
    response
        .extensions_mut()
        .insert(DeliveryObserver(Arc::new(DeliveryCompletion(std::sync::Mutex::new(Some(Box::new(complete)))))));
    response
}

struct DeliveryGuard<'lease> {
    observer: Option<DeliveryObserver>,
    sender: &'lease SendLease,
    outcome: crate::mcp::modern_sse::ResponseOutcome,
}

impl Drop for DeliveryGuard<'_> {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            self.outcome.bytes = self
                .sender
                .credit()
                .consumed_bytes();
            observer
                .0
                .finish(self.outcome);
        }
    }
}

pub(crate) struct DidCommFrameSink {
    pub client: crate::comm::didcomm::client::DIDCommClient,
    pub binding: super::registry::StreamBinding,
    pub capabilities: super::peer::StreamCapabilities,
    pub max_envelope_bytes: usize,
}

#[async_trait]
pub(crate) trait FrameSink: Send + Sync {
    fn max_chunk_bytes(&self) -> usize {
        MAX_CHUNK_BYTES
    }

    async fn send(
        &self,
        frame: StreamFrame,
    ) -> Result<(), StreamErrorCode>;
}

#[async_trait]
impl FrameSink for DidCommFrameSink {
    fn max_chunk_bytes(&self) -> usize {
        self.capabilities
            .max_chunk_bytes as usize
    }

    async fn send(
        &self,
        frame: StreamFrame,
    ) -> Result<(), StreamErrorCode> {
        self.capabilities
            .validate_frame(&frame)
            .map_err(|_| StreamErrorCode::InvalidFrame)?;
        let body = serde_json::to_value(&frame).map_err(|_| StreamErrorCode::InvalidFrame)?;
        let (created_time, expires_time) = frame_envelope_times(&frame);
        let message = affinidi_messaging_didcomm::Message::build(
            Uuid::new_v4().to_string(),
            crate::messages::MessageType::ForwardStreamFrame.to_string(),
            body,
        )
        .from(
            self.binding
                .recipient_did
                .clone(),
        )
        .to(self.binding.peer_did.clone())
        .thid(frame.stream_id.to_string())
        .created_time(created_time)
        .expires_time(expires_time)
        .finalize();
        let packed = self
            .client
            .atm()
            .pack_encrypted(
                &message,
                &self.binding.peer_did,
                Some(&self.binding.recipient_did),
                Some(&self.binding.recipient_did),
            )
            .await
            .map_err(|_| StreamErrorCode::Unavailable)?;
        if packed.0.len() > self.max_envelope_bytes {
            return Err(StreamErrorCode::LimitExceeded);
        }
        self.client
            .atm()
            .send_message(self.client.profile(), &packed.0, &message.id, false, false)
            .await
            .map_err(|_| StreamErrorCode::Unavailable)?;
        Ok(())
    }
}

/// Envelope `created_time` and `expires_time` for a frame. The receiver admits
/// an `Open` like a `forward-request`, which must carry an expiry, so an `Open`
/// lives until its request deadline; other frames get the capped maximum.
fn frame_envelope_times(frame: &StreamFrame) -> (u64, u64) {
    use crate::gateways::connection_points::envelope_replay::{
        MAX_SENT_ENVELOPE_LIFETIME_SECS, now_secs, sent_envelope_lifetime_secs,
    };
    let now = now_secs();
    let lifetime = match &frame.payload {
        FramePayload::Open { request } => sent_envelope_lifetime_secs(
            request
                .deadline_ms
                .div_ceil(1000)
                .saturating_sub(now),
        ),
        _ => MAX_SENT_ENVELOPE_LIFETIME_SECS,
    };
    (now, now + lifetime)
}

pub(crate) async fn until_cancelled<ResultType>(
    mut cancelled: watch::Receiver<Option<StreamErrorCode>>,
    deadline: Instant,
    work: impl Future<Output = Result<ResultType, StreamErrorCode>>,
) -> Result<ResultType, StreamErrorCode> {
    if let Some(error) = *cancelled.borrow_and_update() {
        return Err(error);
    }
    if Instant::now() >= deadline {
        return Err(StreamErrorCode::DeadlineExceeded);
    }
    tokio::select! {
        biased;
        changed = cancelled.changed() => {
            match changed {
                Ok(()) => Err(cancelled.borrow().unwrap_or(StreamErrorCode::Cancelled)),
                Err(_) => Err(StreamErrorCode::Cancelled),
            }
        }
        result = tokio::time::timeout_at(deadline, work) => result.map_err(|_| StreamErrorCode::DeadlineExceeded)?,
    }
}

pub(crate) async fn send_body<Source, SourceError>(
    sink: &dyn FrameSink,
    sender: &SendLease,
    stream_id: Uuid,
    direction: StreamDirection,
    source: Source,
    deadline: Instant,
) -> Result<(), StreamErrorCode>
where
    Source: Stream<Item = Result<Bytes, SourceError>> + Send,
{
    let max_chunk_bytes = sink.max_chunk_bytes();
    if !(1..=MAX_CHUNK_BYTES).contains(&max_chunk_bytes) {
        return Err(StreamErrorCode::InvalidFrame);
    }
    let mut source = Box::pin(source);
    loop {
        let next = until_cancelled(sender.credit().cancellation(), deadline, async {
            source
                .next()
                .await
                .transpose()
                .map_err(|_| StreamErrorCode::UpstreamFailed)
        })
        .await?;
        let Some(mut bytes) = next else { break };
        if bytes.is_empty() {
            tokio::task::yield_now().await;
        }
        while !bytes.is_empty() {
            let chunk = bytes.split_to(
                bytes
                    .len()
                    .min(max_chunk_bytes),
            );
            let (sequence, offset) = sender
                .credit()
                .reserve(chunk.len(), deadline)
                .await?;
            let data = encode_chunk(&chunk).map_err(|_| StreamErrorCode::InvalidFrame)?;
            let payload = match direction {
                StreamDirection::Request => FramePayload::RequestData { sequence, offset, data },
                StreamDirection::Response => FramePayload::Data { sequence, offset, data },
            };
            until_cancelled(sender.credit().cancellation(), deadline, sink.send(StreamFrame { stream_id, payload }))
                .await?;
        }
    }
    let sent = match direction {
        StreamDirection::Request => sender.credit().sent()?,
        StreamDirection::Response => sender.credit().seal()?,
    };
    let payload = match direction {
        StreamDirection::Request => FramePayload::RequestEnd {
            next_sequence: sent.next_sequence,
            body_bytes: sent.consumed_bytes,
        },
        StreamDirection::Response => FramePayload::End {
            next_sequence: sent.next_sequence,
            body_bytes: sent.consumed_bytes,
        },
    };
    until_cancelled(sender.credit().cancellation(), deadline, sink.send(StreamFrame { stream_id, payload })).await
}

pub(crate) async fn send_processed_response(
    sink: &dyn FrameSink,
    sender: &SendLease,
    stream_id: Uuid,
    result: ProcessingResult,
    max_response_bytes: usize,
    deadline: Instant,
) -> Result<(), StreamErrorCode> {
    let mut response = match result {
        ProcessingResult::StreamingResponse { response } => response,
        ProcessingResult::RequiresResponse { response_type, response_body }
            if response_type == crate::messages::MessageType::ForwardResponse.to_string() =>
        {
            let status = response_body
                .get("status")
                .and_then(serde_json::Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .and_then(|status| axum::http::StatusCode::from_u16(status).ok())
                .ok_or(StreamErrorCode::InvalidFrame)?;
            let headers = headers_from_json(response_body.get("headers")).map_err(|_| StreamErrorCode::InvalidFrame)?;
            let bytes = match response_body
                .get("body")
                .and_then(serde_json::Value::as_str)
            {
                Some(body) => Bytes::copy_from_slice(body.as_bytes()),
                None => Bytes::from(serde_json::to_vec(&response_body).map_err(|_| StreamErrorCode::InvalidFrame)?),
            };
            if bytes.len() > max_response_bytes {
                return Err(StreamErrorCode::LimitExceeded);
            }
            let mut response = axum::response::Response::new(axum::body::Body::from(bytes));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            response
        }
        _ => return Err(StreamErrorCode::UpstreamFailed),
    };
    let mut delivery = DeliveryGuard {
        observer: response
            .extensions_mut()
            .remove::<DeliveryObserver>(),
        sender,
        outcome: crate::mcp::modern_sse::ResponseOutcome::default(),
    };
    let (parts, body) = response.into_parts();
    let result = async {
        let start = StreamFrame {
            stream_id,
            payload: FramePayload::Start {
                status: parts.status.as_u16(),
                headers: encode_headers(&parts.headers).map_err(|_| StreamErrorCode::LimitExceeded)?,
            },
        };
        start
            .validate()
            .map_err(|_| StreamErrorCode::InvalidFrame)?;
        until_cancelled(sender.credit().cancellation(), deadline, sink.send(start)).await?;
        send_body(sink, sender, stream_id, StreamDirection::Response, body.into_data_stream(), deadline).await?;
        sender
            .credit()
            .wait_consumed(deadline)
            .await
    }
    .await;
    delivery.outcome.completed = result.is_ok();
    delivery.outcome.failed = result.is_err();
    result
}

pub(crate) async fn run_incoming_request<Execute, Execution>(
    sink: Arc<dyn FrameSink>,
    receiver: ReceiveLease,
    sender: SendLease,
    stream_id: Uuid,
    declared_bytes: u64,
    max_request_bytes: usize,
    max_response_bytes: usize,
    deadline: Instant,
    execute: Execute,
) -> Result<(), StreamErrorCode>
where
    Execute: FnOnce(Bytes) -> Execution,
    Execution: Future<Output = ProcessingResult>,
{
    let expected = usize::try_from(declared_bytes).map_err(|_| StreamErrorCode::LimitExceeded)?;
    if expected > max_request_bytes {
        return Err(StreamErrorCode::LimitExceeded);
    }
    until_cancelled(sender.credit().cancellation(), deadline, async {
        let mut request_body =
            Box::pin(receive_body(receiver, sink.clone(), stream_id, StreamDirection::Request, deadline));
        let mut bytes = bytes::BytesMut::new();
        while let Some(chunk) = request_body.next().await {
            let chunk = chunk?;
            if chunk.len() > expected.saturating_sub(bytes.len()) {
                return Err(StreamErrorCode::LimitExceeded);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != expected {
            return Err(StreamErrorCode::InvalidFrame);
        }
        let result = execute(bytes.freeze()).await;
        send_processed_response(sink.as_ref(), &sender, stream_id, result, max_response_bytes, deadline).await
    })
    .await
}

pub(crate) fn receive_body(
    receiver: ReceiveLease,
    sink: Arc<dyn FrameSink>,
    stream_id: Uuid,
    direction: StreamDirection,
    deadline: Instant,
) -> impl Stream<Item = Result<Bytes, StreamErrorCode>> + Send {
    futures::stream::try_unfold((receiver, sink), move |(mut receiver, sink)| async move {
        let wait = receiver.progress_deadline(deadline);
        let event = until_cancelled(receiver.closed(), wait, receiver.next()).await?;
        match event {
            ReceiveEvent::Data { bytes, credit } => {
                until_cancelled(
                    receiver.closed(),
                    deadline,
                    sink.send(StreamFrame {
                        stream_id,
                        payload: FramePayload::Credit {
                            direction,
                            next_sequence: credit.next_sequence,
                            consumed_bytes: credit.consumed_bytes,
                        },
                    }),
                )
                .await?;
                Ok(Some((bytes, (receiver, sink))))
            }
            ReceiveEvent::End => Ok(None),
            ReceiveEvent::Start { .. } => Err(StreamErrorCode::InvalidFrame),
        }
    })
}

enum ResponseRelease {
    Complete,
    Dropped(ReceiveLease),
}

struct ResponseLifetime {
    receiver: Option<ReceiveLease>,
    released: Option<tokio::sync::oneshot::Sender<ResponseRelease>>,
}

impl ResponseLifetime {
    fn complete(&mut self) {
        if let Some(released) = self.released.take() {
            let _ = released.send(ResponseRelease::Complete);
        }
    }
}

impl Drop for ResponseLifetime {
    fn drop(&mut self) {
        if let (Some(released), Some(receiver)) = (self.released.take(), self.receiver.take()) {
            let _ = released.send(ResponseRelease::Dropped(receiver));
        }
    }
}

async fn acknowledge_response_end(
    receiver: &ReceiveLease,
    sink: &dyn FrameSink,
    stream_id: Uuid,
) -> Result<(), StreamErrorCode> {
    let completion = receiver
        .completion()?
        .ok_or(StreamErrorCode::InvalidFrame)?;
    sink.send(StreamFrame {
        stream_id,
        payload: FramePayload::EndAck {
            next_sequence: completion.next_sequence,
            body_bytes: completion.consumed_bytes,
        },
    })
    .await
}

pub(crate) fn prepare_outgoing_request(
    sink: Arc<dyn FrameSink>,
    receiver: ReceiveLease,
    sender: SendLease,
    open: StreamFrame,
    body: Bytes,
    header_deadline: Instant,
    deadline: Instant,
) -> (
    impl Future<Output = Result<axum::response::Response, StreamErrorCode>> + Send + 'static,
    impl Future<Output = ()> + Send + 'static,
) {
    let stream_id = open.stream_id;
    let (completed_tx, mut completed_rx) = tokio::sync::oneshot::channel();
    let lifetime = ResponseLifetime {
        receiver: Some(receiver),
        released: Some(completed_tx),
    };
    let requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (outcome_tx, outcome_rx) = watch::channel(None);
    let completion = crate::mcp::modern_sse::TransportCompletion {
        requested: requested.clone(),
        outcome: outcome_rx,
    };
    let send_closed = sender.credit().cancellation();
    let sending_sink = sink.clone();
    let sending = async move {
        let transfer = async {
            let FramePayload::Open { request } = &open.payload else {
                return Err(StreamErrorCode::InvalidFrame);
            };
            if request.body_bytes != body.len() as u64 {
                return Err(StreamErrorCode::InvalidFrame);
            }
            open.validate()
                .map_err(|_| StreamErrorCode::InvalidFrame)?;
            sending_sink
                .send(open)
                .await?;
            let upload = send_body(
                sending_sink.as_ref(),
                &sender,
                stream_id,
                StreamDirection::Request,
                futures::stream::once(async move { Ok::<_, std::convert::Infallible>(body) }),
                deadline,
            );
            tokio::pin!(upload);
            let completed = tokio::select! {
                biased;
                completed = &mut completed_rx => completed,
                uploaded = &mut upload => {
                    uploaded?;
                    completed_rx.await
                }
            };
            match completed {
                Ok(ResponseRelease::Complete) => Ok(()),
                Ok(ResponseRelease::Dropped(mut receiver)) if requested.load(std::sync::atomic::Ordering::Acquire) => {
                    let terminal = async {
                        if !matches!(receiver.next().await?, ReceiveEvent::End) {
                            return Err(StreamErrorCode::InvalidFrame);
                        }
                        acknowledge_response_end(&receiver, sending_sink.as_ref(), stream_id).await
                    };
                    tokio::select! {
                        biased;
                        _ = outcome_tx.closed() => Err(StreamErrorCode::Cancelled),
                        result = terminal => result,
                    }
                }
                _ => Err(StreamErrorCode::Cancelled),
            }
        };
        let result = until_cancelled(sender.credit().cancellation(), deadline, transfer).await;
        outcome_tx.send_replace(Some(result.is_ok()));
        if let Err(code) = result {
            sender.credit().cancel(code);
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                sending_sink.send(StreamFrame {
                    stream_id,
                    payload: FramePayload::Cancel,
                }),
            )
            .await;
        }
    };
    let receiving = async move {
        let mut lifetime = lifetime;
        let receiver = lifetime
            .receiver
            .as_mut()
            .ok_or(StreamErrorCode::Unavailable)?;
        let start = until_cancelled(send_closed.clone(), header_deadline, receiver.next()).await?;
        let ReceiveEvent::Start { status, headers } = start else {
            return Err(StreamErrorCode::InvalidFrame);
        };
        let status = axum::http::StatusCode::from_u16(status).map_err(|_| StreamErrorCode::InvalidFrame)?;
        let headers = super::wire::decode_headers(&headers).map_err(|_| StreamErrorCode::InvalidFrame)?;
        let body = futures::stream::try_unfold(
            (sink, send_closed, lifetime),
            move |(sink, cancelled, mut lifetime)| async move {
                let receiver = lifetime
                    .receiver
                    .as_mut()
                    .ok_or(StreamErrorCode::Unavailable)?;
                let next = until_cancelled(cancelled.clone(), deadline, receiver.next()).await?;
                match next {
                    ReceiveEvent::Data { bytes, credit } => {
                        until_cancelled(
                            cancelled.clone(),
                            deadline,
                            sink.send(StreamFrame {
                                stream_id,
                                payload: FramePayload::Credit {
                                    direction: StreamDirection::Response,
                                    next_sequence: credit.next_sequence,
                                    consumed_bytes: credit.consumed_bytes,
                                },
                            }),
                        )
                        .await?;
                        Ok::<_, StreamErrorCode>(Some((bytes, (sink, cancelled, lifetime))))
                    }
                    ReceiveEvent::End => {
                        until_cancelled(
                            cancelled.clone(),
                            deadline,
                            acknowledge_response_end(receiver, sink.as_ref(), stream_id),
                        )
                        .await?;
                        lifetime.complete();
                        Ok(None)
                    }
                    ReceiveEvent::Start { .. } => Err(StreamErrorCode::InvalidFrame),
                }
            },
        );
        let mut response = axum::response::Response::new(axum::body::Body::from_stream(body));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
            .extensions_mut()
            .insert(completion);
        Ok(response)
    };
    (receiving, sending)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use super::super::registry::{ReceiveRegistry, RegistryLimits, StreamBinding};
    use super::*;
    use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};

    #[tokio::test]
    async fn outgoing_chunks_honor_a_smaller_negotiated_peer_limit() {
        struct SmallSink(tokio::sync::mpsc::Sender<StreamFrame>);
        #[async_trait]
        impl FrameSink for SmallSink {
            fn max_chunk_bytes(&self) -> usize {
                5
            }
            async fn send(
                &self,
                frame: StreamFrame,
            ) -> Result<(), StreamErrorCode> {
                self.0
                    .send(frame)
                    .await
                    .map_err(|_| StreamErrorCode::Unavailable)
            }
        }
        let registry = registry();
        let id = Uuid::new_v4();
        let sender = registry
            .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(8);
        send_body(
            &SmallSink(frames_tx),
            &sender,
            id,
            StreamDirection::Request,
            futures::stream::iter([Ok::<_, Infallible>(Bytes::from_static(b"small payload"))]),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        let mut collected = Vec::new();
        for (sequence, expected) in [(0, 5), (1, 5), (2, 3)] {
            let FramePayload::RequestData {
                sequence: actual_sequence,
                offset,
                data,
            } = frames_rx
                .recv()
                .await
                .unwrap()
                .payload
            else {
                panic!("missing data frame")
            };
            let bytes = super::super::wire::decode_chunk(&data).unwrap();
            assert_eq!(actual_sequence, sequence);
            assert_eq!(offset, sequence * 5);
            assert_eq!(bytes.len(), expected);
            collected.extend_from_slice(&bytes);
        }
        assert_eq!(collected, b"small payload");
        assert!(matches!(
            frames_rx
                .recv()
                .await
                .unwrap()
                .payload,
            FramePayload::RequestEnd {
                next_sequence: 3,
                body_bytes: 13
            }
        ));
    }

    struct RegistrySink {
        remote: Arc<ReceiveRegistry>,
        frames: tokio::sync::mpsc::Sender<StreamFrame>,
    }

    #[async_trait]
    impl FrameSink for RegistrySink {
        async fn send(
            &self,
            frame: StreamFrame,
        ) -> Result<(), StreamErrorCode> {
            let message = message(frame.stream_id);
            self.remote
                .deliver(&message, "instance", frame.clone())
                .map_err(|_| StreamErrorCode::InvalidFrame)?;
            self.frames
                .send(frame)
                .await
                .map_err(|_| StreamErrorCode::Unavailable)
        }
    }

    fn registry() -> Arc<ReceiveRegistry> {
        ReceiveRegistry::new(RegistryLimits {
            max_streams: 4,
            max_peer_streams: 4,
            max_surface_streams: 4,
        })
        .unwrap()
    }

    fn binding() -> StreamBinding {
        StreamBinding {
            peer_did: "did:example:peer".into(),
            recipient_did: "did:example:local".into(),
            connection_point_id: "cp".into(),
            listener_instance_id: "instance".into(),
            surface_id: "surface".into(),
        }
    }

    fn message(stream_id: Uuid) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp".into(),
            "gateway".into(),
            "frame".into(),
            Uuid::new_v4().to_string(),
            Some(stream_id.to_string()),
            Some("did:example:peer".into()),
            vec!["did:example:local".into()],
            None,
            None,
            serde_json::Value::Null,
            MessageMetadata {
                authenticated: true,
                encrypted: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
    }

    struct LinkedSink {
        remote: Arc<ReceiveRegistry>,
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl FrameSink for LinkedSink {
        async fn send(
            &self,
            frame: StreamFrame,
        ) -> Result<(), StreamErrorCode> {
            if matches!(frame.payload, FramePayload::Open { .. }) {
                return Ok(());
            }
            if matches!(frame.payload, FramePayload::Cancel) {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            self.remote
                .deliver(&message(frame.stream_id), "instance", frame)
                .map_err(|_| StreamErrorCode::InvalidFrame)?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn composed_subscription_preserves_acknowledgement_and_cancels_quiet_peer() {
        use crate::mcp::request_validation::{McpMessageKind, ValidatedModernMessage};
        use crate::mcp::subscriptions::{CatalogChange, CatalogSubscriptions, owned_catalog_response};
        use eventsource_stream::Eventsource;
        use serde_json::json;

        for graceful in [false, true] {
            let caller = registry();
            let target = registry();
            let stream_id = Uuid::new_v4();
            let deadline = Instant::now() + Duration::from_secs(2);
            let caller_receiver = caller
                .register(stream_id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            let caller_sender = caller
                .register_sender(stream_id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .unwrap();
            let (target_receiver, target_sender) = target
                .open(stream_id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .unwrap();
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let caller_sink = Arc::new(LinkedSink {
                remote: target,
                cancelled: cancelled.clone(),
            });
            let target_sink = Arc::new(LinkedSink {
                remote: caller,
                cancelled: cancelled.clone(),
            });
            let id = if graceful {
                json!(7)
            } else {
                json!("7")
            };
            let request = ValidatedModernMessage {
                protocol_version: crate::mcp::MCP_MODERN_VERSION.to_string(),
                client_capabilities: Some(json!({})),
                client_info: None,
                method: "subscriptions/listen".to_string(),
                params: Some(json!({"notifications": {"toolsListChanged": true}})),
                id: Some(id.clone()),
                kind: McpMessageKind::Request,
            };
            let upload = Bytes::from(
                json!({"jsonrpc": "2.0", "id": id, "method": request.method, "params": request.params}).to_string(),
            );
            let expected_upload = upload.clone();
            let open = StreamFrame {
                stream_id,
                payload: FramePayload::Open {
                    request: super::super::wire::OpenRequest {
                        capability_nonce: Uuid::new_v4(),
                        channel_id: "surface".to_string(),
                        variant_alias: None,
                        path: "/mcp".to_string(),
                        headers: Default::default(),
                        body_bytes: upload.len() as u64,
                        response_window_bytes: MAX_CHUNK_BYTES as u32,
                        deadline_ms: 1,
                        trace_id: Uuid::new_v4(),
                    },
                },
            };
            let catalog = CatalogSubscriptions::new();
            let subscription = catalog
                .subscribe("proxy")
                .unwrap();
            let limits = crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default());
            let target_request = request.clone();
            let (response, sending) =
                prepare_outgoing_request(caller_sink, caller_receiver, caller_sender, open, upload, deadline, deadline);
            let (target_done_tx, target_done_rx) = tokio::sync::oneshot::channel();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(sending);
            tasks.spawn(async move {
                let result = run_incoming_request(
                    target_sink,
                    target_receiver,
                    target_sender,
                    stream_id,
                    expected_upload.len() as u64,
                    4096,
                    4096,
                    deadline,
                    move |body| async move {
                        assert_eq!(body, expected_upload);
                        ProcessingResult::StreamingResponse {
                            response: owned_catalog_response(target_request, subscription, limits).unwrap(),
                        }
                    },
                )
                .await;
                let _ = target_done_tx.send(result);
            });
            let (mut parts, body) = tokio::time::timeout_at(deadline, response)
                .await
                .unwrap()
                .unwrap()
                .into_parts();
            let completion = parts
                .extensions
                .remove::<crate::mcp::modern_sse::TransportCompletion>();
            let validated = crate::mcp::modern_sse::forwarding_response_with_completion(
                body.into_data_stream(),
                parts.status,
                &parts.headers,
                request.clone(),
                limits,
                crate::mcp::modern::ForwardingSupport::for_endpoint(
                    false,
                    crate::mcp::request_validation::McpPathKind::FabricReceive,
                ),
                |message| async { Ok::<_, crate::mcp::modern_sse::SseReadError>(message) },
                |message| async { Ok(message) },
                completion,
            )
            .await
            .unwrap();
            let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
            let validated = crate::mcp::modern_sse::observe_response(validated, move |outcome| {
                let _ = outcome_tx.send(outcome);
            });
            let mut events = validated
                .into_body()
                .into_data_stream()
                .eventsource();
            let ack: serde_json::Value = serde_json::from_str(
                &tokio::time::timeout_at(deadline, events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .data,
            )
            .unwrap();
            assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
            assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
            assert_eq!(ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], id);
            catalog.publish("proxy", CatalogChange::Changed);
            let change: serde_json::Value = serde_json::from_str(
                &tokio::time::timeout_at(deadline, events.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .data,
            )
            .unwrap();
            assert_eq!(change["method"], "notifications/tools/list_changed");
            assert_eq!(change["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], id);
            if graceful {
                catalog.publish("proxy", CatalogChange::Closed);
                let done: serde_json::Value = serde_json::from_str(
                    &tokio::time::timeout_at(deadline, events.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap()
                        .data,
                )
                .unwrap();
                assert_eq!(done, crate::mcp::subscriptions::completion(&request).unwrap());
                assert!(
                    tokio::time::timeout_at(deadline, events.next())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            drop(events);
            let outcome = outcome_rx.await.unwrap();
            assert_eq!(outcome.completed, graceful);
            assert!(!outcome.failed);
            assert!(outcome.bytes > 0);
            assert_eq!(
                tokio::time::timeout_at(deadline, target_done_rx)
                    .await
                    .unwrap()
                    .unwrap(),
                if graceful {
                    Ok(())
                } else {
                    Err(StreamErrorCode::Cancelled)
                }
            );
            while let Some(result) = tokio::time::timeout_at(deadline, tasks.join_next())
                .await
                .unwrap()
            {
                result.unwrap();
            }
            assert_eq!(cancelled.load(std::sync::atomic::Ordering::SeqCst), !graceful);
        }
    }

    #[tokio::test]
    async fn composed_exchange_completes_beyond_the_credit_window_without_cancellation() {
        for payload_len in [0, MAX_CHUNK_BYTES * 3 + 17] {
            let caller = registry();
            let target = registry();
            let id = Uuid::new_v4();
            let deadline = Instant::now() + Duration::from_secs(2);
            let caller_receiver = caller
                .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            let caller_sender = caller
                .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .unwrap();
            let (target_receiver, target_sender) = target
                .open(id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .unwrap();
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let caller_sink = Arc::new(LinkedSink {
                remote: target.clone(),
                cancelled: cancelled.clone(),
            });
            let target_sink = Arc::new(LinkedSink {
                remote: caller.clone(),
                cancelled: cancelled.clone(),
            });
            let expected = Bytes::from(vec![b'x'; payload_len]);
            let expected_target = expected.clone();
            let open = StreamFrame {
                stream_id: id,
                payload: FramePayload::Open {
                    request: super::super::wire::OpenRequest {
                        capability_nonce: Uuid::new_v4(),
                        channel_id: "surface".into(),
                        variant_alias: Some("variant".into()),
                        path: "/mcp".into(),
                        headers: Default::default(),
                        body_bytes: expected.len() as u64,
                        response_window_bytes: MAX_CHUNK_BYTES as u32,
                        deadline_ms: 1,
                        trace_id: Uuid::new_v4(),
                    },
                },
            };
            let (response, sending) = prepare_outgoing_request(
                caller_sink,
                caller_receiver,
                caller_sender,
                open,
                expected.clone(),
                deadline,
                deadline,
            );
            let (target_done_tx, target_done_rx) = tokio::sync::oneshot::channel();
            let (delivery_tx, delivery_rx) = tokio::sync::oneshot::channel();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(sending);
            tasks.spawn(async move {
                let result = run_incoming_request(
                    target_sink,
                    target_receiver,
                    target_sender,
                    id,
                    expected_target.len() as u64,
                    expected_target.len(),
                    expected_target.len(),
                    deadline,
                    move |body| async move {
                        assert_eq!(body, expected_target);
                        let mut response = axum::response::Response::new(axum::body::Body::from(body));
                        if payload_len == 0 {
                            *response.status_mut() = axum::http::StatusCode::ACCEPTED;
                        }
                        response
                            .headers_mut()
                            .append("x-repeated", "first".parse().unwrap());
                        response
                            .headers_mut()
                            .append("x-repeated", "second".parse().unwrap());
                        let response = observe_delivery(response, move |outcome| {
                            let _ = delivery_tx.send(outcome);
                        });
                        ProcessingResult::StreamingResponse { response }
                    },
                )
                .await;
                let _ = target_done_tx.send(result);
            });
            let response = tokio::time::timeout_at(deadline, response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                response.status(),
                if payload_len == 0 {
                    axum::http::StatusCode::ACCEPTED
                } else {
                    axum::http::StatusCode::OK
                }
            );
            assert_eq!(
                response
                    .headers()
                    .get_all("x-repeated")
                    .iter()
                    .count(),
                2
            );
            let actual = tokio::time::timeout_at(deadline, axum::body::to_bytes(response.into_body(), expected.len()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(target_done_rx.await.unwrap(), Ok(()));
            assert_eq!(
                delivery_rx.await.unwrap(),
                crate::mcp::modern_sse::ResponseOutcome {
                    bytes: payload_len as u64,
                    completed: true,
                    failed: false,
                }
            );
            while let Some(result) = tokio::time::timeout_at(deadline, tasks.join_next())
                .await
                .unwrap()
            {
                result.unwrap();
            }
            assert!(!cancelled.load(std::sync::atomic::Ordering::SeqCst));
            for registry in [caller, target] {
                assert!(
                    !registry
                        .deliver(
                            &message(id),
                            "instance",
                            StreamFrame {
                                stream_id: id,
                                payload: FramePayload::Cancel
                            }
                        )
                        .unwrap()
                );
            }
        }
    }

    #[tokio::test]
    async fn outgoing_response_drop_cancels_a_quiet_peer_without_another_frame() {
        struct RecordingSink(tokio::sync::mpsc::Sender<StreamFrame>);
        #[async_trait]
        impl FrameSink for RecordingSink {
            async fn send(
                &self,
                frame: StreamFrame,
            ) -> Result<(), StreamErrorCode> {
                self.0
                    .send(frame)
                    .await
                    .map_err(|_| StreamErrorCode::Unavailable)
            }
        }
        for drop_stage in ["before_headers", "body", "terminal"] {
            let registry = registry();
            let id = Uuid::new_v4();
            let receiver = registry
                .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            let sender = registry
                .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .unwrap();
            let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(8);
            let open = StreamFrame {
                stream_id: id,
                payload: FramePayload::Open {
                    request: super::super::wire::OpenRequest {
                        capability_nonce: Uuid::new_v4(),
                        channel_id: "surface".into(),
                        variant_alias: None,
                        path: "/mcp".into(),
                        headers: Default::default(),
                        body_bytes: 0,
                        response_window_bytes: MAX_CHUNK_BYTES as u32,
                        deadline_ms: 1,
                        trace_id: Uuid::new_v4(),
                    },
                },
            };
            let deadline = Instant::now() + Duration::from_secs(2);
            let (response, sending) = prepare_outgoing_request(
                Arc::new(RecordingSink(frames_tx)),
                receiver,
                sender,
                open,
                Bytes::new(),
                deadline,
                deadline,
            );
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(sending);
            assert!(matches!(
                frames_rx
                    .recv()
                    .await
                    .unwrap()
                    .payload,
                FramePayload::Open { .. }
            ));
            assert!(matches!(
                frames_rx
                    .recv()
                    .await
                    .unwrap()
                    .payload,
                FramePayload::RequestEnd {
                    next_sequence: 0,
                    body_bytes: 0
                }
            ));
            if drop_stage == "before_headers" {
                drop(response);
            } else {
                registry
                    .deliver(
                        &message(id),
                        "instance",
                        StreamFrame {
                            stream_id: id,
                            payload: FramePayload::Start {
                                status: 200,
                                headers: std::collections::BTreeMap::from([(
                                    "content-type".into(),
                                    vec!["text/event-stream".into()],
                                )]),
                            },
                        },
                    )
                    .unwrap();
                let response = response.await.unwrap();
                if drop_stage == "terminal" {
                    use serde_json::json;
                    let payload = Bytes::from(format!(
                        "data: {}\n\n",
                        json!({
                            "jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete", "content": []}
                        })
                    ));
                    registry
                        .deliver(
                            &message(id),
                            "instance",
                            StreamFrame {
                                stream_id: id,
                                payload: FramePayload::Data {
                                    sequence: 0,
                                    offset: 0,
                                    data: encode_chunk(&payload).unwrap(),
                                },
                            },
                        )
                        .unwrap();
                    let (mut parts, body) = response.into_parts();
                    let completion = parts
                        .extensions
                        .remove::<crate::mcp::modern_sse::TransportCompletion>();
                    let response = crate::mcp::modern_sse::forwarding_response_with_completion(
                        body.into_data_stream(),
                        parts.status,
                        &parts.headers,
                        crate::mcp::request_validation::ValidatedModernMessage {
                            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
                            client_capabilities: Some(json!({})),
                            client_info: None,
                            method: "tools/call".into(),
                            params: Some(json!({"name": "echo"})),
                            id: Some(json!(7)),
                            kind: crate::mcp::request_validation::McpMessageKind::Request,
                        },
                        crate::mcp::modern_sse::SseLimits::from(&crate::config::McpHttpConfig::default()),
                        crate::mcp::modern::ForwardingSupport::for_endpoint(
                            false,
                            crate::mcp::request_validation::McpPathKind::FabricReceive,
                        ),
                        |message| async { Ok::<_, crate::mcp::modern_sse::SseReadError>(message) },
                        |message| async { Ok(message) },
                        completion,
                    )
                    .await
                    .unwrap();
                    let mut body = response
                        .into_body()
                        .into_data_stream();
                    assert!(
                        body.next()
                            .await
                            .unwrap()
                            .is_ok()
                    );
                    assert!(matches!(
                        frames_rx
                            .recv()
                            .await
                            .unwrap()
                            .payload,
                        FramePayload::Credit { .. }
                    ));
                    assert!(futures::poll!(body.next()).is_pending());
                    drop(body);
                } else {
                    drop(response);
                }
            }
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(1), frames_rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .payload,
                FramePayload::Cancel
            ));
            tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(
                !registry
                    .deliver(
                        &message(id),
                        "instance",
                        StreamFrame {
                            stream_id: id,
                            payload: FramePayload::Cancel
                        }
                    )
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn processed_response_streams_headers_and_progress_before_completion() {
        let sending = registry();
        let receiving = registry();
        let id = Uuid::new_v4();
        let sender = sending
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let mut receiver = receiving
            .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(8);
        let sink = RegistrySink {
            remote: receiving,
            frames: frames_tx,
        };
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(1);
        let mut response = axum::response::Response::new(axum::body::Body::from_stream(
            tokio_stream::wrappers::ReceiverStream::new(body_rx),
        ));
        response
            .headers_mut()
            .append("x-repeated", "first".parse().unwrap());
        response
            .headers_mut()
            .append("x-repeated", "second".parse().unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            send_processed_response(
                &sink,
                &sender,
                id,
                ProcessingResult::StreamingResponse { response },
                1024,
                Instant::now() + Duration::from_secs(2),
            )
            .await
        });
        assert!(matches!(
            frames_rx
                .recv()
                .await
                .unwrap()
                .payload,
            FramePayload::Start { status: 200, .. }
        ));
        let ReceiveEvent::Start { headers, .. } = receiver.next().await.unwrap() else { panic!("missing start") };
        assert_eq!(headers["x-repeated"], vec!["first", "second"]);
        body_tx
            .send(Ok(Bytes::from_static(b"data: progress\n\n")))
            .await
            .unwrap();
        assert!(matches!(
            frames_rx
                .recv()
                .await
                .unwrap()
                .payload,
            FramePayload::Data { sequence: 0, .. }
        ));
        assert!(
            matches!(receiver.next().await.unwrap(), ReceiveEvent::Data { bytes, .. } if bytes == "data: progress\n\n")
        );
        assert!(
            tasks
                .try_join_next()
                .is_none()
        );
        sending
            .deliver(
                &message(id),
                "instance",
                StreamFrame {
                    stream_id: id,
                    payload: FramePayload::Cancel,
                },
            )
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Err(StreamErrorCode::Cancelled)
        );
        assert!(body_tx.is_closed());
    }

    #[tokio::test]
    async fn processed_response_waits_for_peer_consumption_before_completion() {
        let sending = registry();
        let receiving = registry();
        let id = Uuid::new_v4();
        let sender = sending
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let mut receiver = receiving
            .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let (frames_tx, _frames_rx) = tokio::sync::mpsc::channel(8);
        let sink = RegistrySink {
            remote: receiving,
            frames: frames_tx,
        };
        let response = axum::response::Response::new(axum::body::Body::from("final"));
        let (outcome_tx, mut outcome_rx) = tokio::sync::oneshot::channel();
        let response = observe_delivery(response, move |outcome| {
            let _ = outcome_tx.send(outcome);
        });
        let mut transfer = Box::pin(send_processed_response(
            &sink,
            &sender,
            id,
            ProcessingResult::StreamingResponse { response },
            1024,
            Instant::now() + Duration::from_secs(2),
        ));
        assert!(futures::poll!(transfer.as_mut()).is_pending(), "local EOF is not peer consumption");
        assert!(outcome_rx.try_recv().is_err(), "metrics must wait for peer consumption");
        assert!(matches!(receiver.next().await.unwrap(), ReceiveEvent::Start { status: 200, .. }));
        let ReceiveEvent::Data { bytes, credit } = receiver.next().await.unwrap() else {
            panic!("missing response bytes");
        };
        assert_eq!(bytes, "final");
        assert!(futures::poll!(transfer.as_mut()).is_pending(), "unacknowledged bytes must retain the sender");
        assert!(
            sending
                .deliver(
                    &message(id),
                    "instance",
                    StreamFrame {
                        stream_id: id,
                        payload: FramePayload::Credit {
                            direction: StreamDirection::Response,
                            next_sequence: credit.next_sequence,
                            consumed_bytes: credit.consumed_bytes,
                        },
                    }
                )
                .unwrap()
        );
        assert!(futures::poll!(transfer.as_mut()).is_pending(), "byte credit does not acknowledge End");
        assert_eq!(receiver.next().await.unwrap(), ReceiveEvent::End);
        assert!(
            sending
                .deliver(
                    &message(id),
                    "instance",
                    StreamFrame {
                        stream_id: id,
                        payload: FramePayload::EndAck {
                            next_sequence: credit.next_sequence,
                            body_bytes: credit.consumed_bytes,
                        },
                    }
                )
                .unwrap()
        );
        assert_eq!(transfer.await, Ok(()));
        assert_eq!(
            outcome_rx.await.unwrap(),
            crate::mcp::modern_sse::ResponseOutcome {
                bytes: 5,
                completed: true,
                failed: false,
            }
        );
    }

    #[tokio::test]
    async fn dropped_response_delivery_reports_only_acknowledged_bytes() {
        let sending = registry();
        let receiving = registry();
        let id = Uuid::new_v4();
        let sender = sending
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let _receiver = receiving
            .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let (frames_tx, _frames_rx) = tokio::sync::mpsc::channel(8);
        let sink = RegistrySink {
            remote: receiving,
            frames: frames_tx,
        };
        let (outcome_tx, mut outcome_rx) = tokio::sync::oneshot::channel();
        let response =
            observe_delivery(axum::response::Response::new(axum::body::Body::from("final")), move |outcome| {
                let _ = outcome_tx.send(outcome);
            });
        let mut transfer = Box::pin(send_processed_response(
            &sink,
            &sender,
            id,
            ProcessingResult::StreamingResponse { response },
            1024,
            Instant::now() + Duration::from_secs(2),
        ));
        assert!(futures::poll!(transfer.as_mut()).is_pending());
        assert!(outcome_rx.try_recv().is_err());
        drop(transfer);
        assert_eq!(outcome_rx.await.unwrap(), crate::mcp::modern_sse::ResponseOutcome::default());

        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let response = observe_delivery(axum::response::Response::new(axum::body::Body::empty()), move |outcome| {
            let _ = outcome_tx.send(outcome);
        });
        drop(response);
        assert_eq!(outcome_rx.await.unwrap(), crate::mcp::modern_sse::ResponseOutcome::default());

        for termination in ["drop", "cancel", "deadline"] {
            let sending = registry();
            let receiving = registry();
            let id = Uuid::new_v4();
            let sender = sending
                .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            let mut receiver = receiving
                .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            let (frames_tx, _frames_rx) = tokio::sync::mpsc::channel(8);
            let sink = RegistrySink {
                remote: receiving,
                frames: frames_tx,
            };
            let (outcome_tx, mut outcome_rx) = tokio::sync::oneshot::channel();
            let body = axum::body::Body::from_stream(futures::stream::iter([
                Ok::<_, Infallible>(Bytes::from_static(b"part")),
                Ok(Bytes::from_static(b"final")),
            ]));
            let response = observe_delivery(axum::response::Response::new(body), move |outcome| {
                let _ = outcome_tx.send(outcome);
            });
            let mut transfer = Box::pin(send_processed_response(
                &sink,
                &sender,
                id,
                ProcessingResult::StreamingResponse { response },
                1024,
                Instant::now() + Duration::from_millis(100),
            ));
            assert!(futures::poll!(transfer.as_mut()).is_pending());
            assert!(matches!(receiver.next().await.unwrap(), ReceiveEvent::Start { .. }));
            let ReceiveEvent::Data { bytes, credit } = receiver.next().await.unwrap() else {
                panic!("missing partial response");
            };
            assert_eq!(bytes, "part");
            assert!(
                sending
                    .deliver(
                        &message(id),
                        "instance",
                        StreamFrame {
                            stream_id: id,
                            payload: FramePayload::Credit {
                                direction: StreamDirection::Response,
                                next_sequence: credit.next_sequence,
                                consumed_bytes: credit.consumed_bytes,
                            },
                        }
                    )
                    .unwrap()
            );
            assert!(futures::poll!(transfer.as_mut()).is_pending());
            assert!(outcome_rx.try_recv().is_err());
            match termination {
                "drop" => drop(transfer),
                "cancel" => {
                    assert!(
                        sending
                            .deliver(
                                &message(id),
                                "instance",
                                StreamFrame {
                                    stream_id: id,
                                    payload: FramePayload::Cancel,
                                }
                            )
                            .unwrap()
                    );
                    assert_eq!(transfer.await, Err(StreamErrorCode::Cancelled));
                }
                "deadline" => assert_eq!(transfer.await, Err(StreamErrorCode::DeadlineExceeded)),
                _ => unreachable!(),
            }
            assert_eq!(
                outcome_rx.await.unwrap(),
                crate::mcp::modern_sse::ResponseOutcome {
                    bytes: 4,
                    completed: false,
                    failed: termination != "drop",
                },
                "{termination}"
            );
        }
    }

    #[tokio::test]
    async fn processed_response_rejects_invalid_or_oversized_buffered_results() {
        let sending = registry();
        let receiving = registry();
        let id = Uuid::new_v4();
        let sender = sending
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(8);
        let sink = RegistrySink {
            remote: receiving,
            frames: frames_tx,
        };
        for response_body in [
            serde_json::json!({"status": 99, "body": "invalid"}),
            serde_json::json!({"status": 200, "headers": {"x-invalid": [5]}, "body": "invalid"}),
            serde_json::json!({"status": 200, "body": "too large"}),
        ] {
            let result = ProcessingResult::RequiresResponse {
                response_type: crate::messages::MessageType::ForwardResponse.to_string(),
                response_body,
            };
            assert!(
                send_processed_response(&sink, &sender, id, result, 4, Instant::now() + Duration::from_secs(1))
                    .await
                    .is_err()
            );
            assert!(frames_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn incoming_request_checks_declared_bytes_before_execution() {
        struct RecordingSink(tokio::sync::mpsc::Sender<StreamFrame>);
        #[async_trait]
        impl FrameSink for RecordingSink {
            async fn send(
                &self,
                frame: StreamFrame,
            ) -> Result<(), StreamErrorCode> {
                self.0
                    .send(frame)
                    .await
                    .map_err(|_| StreamErrorCode::Unavailable)
            }
        }
        for (declared, max_bytes, expected_error) in [
            (4, 4, None),
            (5, 4, Some(StreamErrorCode::LimitExceeded)),
            (3, 4, Some(StreamErrorCode::LimitExceeded)),
            (5, 5, Some(StreamErrorCode::InvalidFrame)),
        ] {
            let registry = registry();
            let id = Uuid::new_v4();
            let receiver = registry
                .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .unwrap();
            let sender = registry
                .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            for payload in [
                FramePayload::RequestData {
                    sequence: 0,
                    offset: 0,
                    data: encode_chunk(b"body").unwrap(),
                },
                FramePayload::RequestEnd {
                    next_sequence: 1,
                    body_bytes: 4,
                },
            ] {
                registry
                    .deliver(&message(id), "instance", StreamFrame { stream_id: id, payload })
                    .unwrap();
            }
            let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let recorded = executed.clone();
            let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(8);
            let transfer = run_incoming_request(
                Arc::new(RecordingSink(frames_tx)),
                receiver,
                sender,
                id,
                declared,
                max_bytes,
                1024,
                Instant::now() + Duration::from_secs(1),
                move |body| async move {
                    recorded.store(true, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(body, "body");
                    ProcessingResult::StreamingResponse {
                        response: axum::response::Response::new(axum::body::Body::from("result")),
                    }
                },
            );
            let consume = async {
                let mut completed = false;
                while let Some(frame) = frames_rx.recv().await {
                    if let FramePayload::End { next_sequence, body_bytes } = frame.payload {
                        assert!(
                            registry
                                .deliver(
                                    &message(id),
                                    "instance",
                                    StreamFrame {
                                        stream_id: id,
                                        payload: FramePayload::EndAck { next_sequence, body_bytes },
                                    }
                                )
                                .unwrap()
                        );
                        completed = next_sequence == 1 && body_bytes == 6;
                    }
                }
                completed
            };
            let (result, completed) = tokio::join!(transfer, consume);
            assert_eq!(result.err(), expected_error);
            assert_eq!(executed.load(std::sync::atomic::Ordering::SeqCst), expected_error.is_none());
            assert_eq!(completed, expected_error.is_none());
        }
    }

    #[tokio::test]
    async fn incoming_request_cancellation_drops_quiet_target_execution() {
        struct UnusedSink;
        #[async_trait]
        impl FrameSink for UnusedSink {
            async fn send(
                &self,
                _: StreamFrame,
            ) -> Result<(), StreamErrorCode> {
                Ok(())
            }
        }
        let registry = registry();
        let id = Uuid::new_v4();
        let receiver = registry
            .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let sender = registry
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        registry
            .deliver(
                &message(id),
                "instance",
                StreamFrame {
                    stream_id: id,
                    payload: FramePayload::RequestEnd {
                        next_sequence: 0,
                        body_bytes: 0,
                    },
                },
            )
            .unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (owned_tx, owned_rx) = tokio::sync::oneshot::channel::<()>();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            run_incoming_request(
                Arc::new(UnusedSink),
                receiver,
                sender,
                id,
                0,
                1024,
                1024,
                Instant::now() + Duration::from_secs(2),
                move |_| async move {
                    let _owned = owned_tx;
                    entered_tx.send(()).unwrap();
                    std::future::pending().await
                },
            )
            .await
        });
        entered_rx.await.unwrap();
        registry
            .deliver(
                &message(id),
                "instance",
                StreamFrame {
                    stream_id: id,
                    payload: FramePayload::Cancel,
                },
            )
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Err(StreamErrorCode::Cancelled)
        );
        assert!(owned_rx.await.is_err());
    }

    #[tokio::test]
    async fn framed_body_waits_for_consumption_and_preserves_chunked_bytes() {
        let sending = registry();
        let receiving = registry();
        let id = Uuid::new_v4();
        let sender = sending
            .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let receiver = receiving
            .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(8);
        let (credit_tx, mut credit_rx) = tokio::sync::mpsc::channel(8);
        let sender_sink = RegistrySink {
            remote: receiving,
            frames: sent_tx,
        };
        let receiver_sink = Arc::new(RegistrySink {
            remote: sending,
            frames: credit_tx,
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let expected = Bytes::from(vec![0x42; MAX_CHUNK_BYTES * 2 + 17]);
        let payload = expected.clone();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            send_body(
                &sender_sink,
                &sender,
                id,
                StreamDirection::Request,
                futures::stream::iter([Ok::<_, Infallible>(payload)]),
                deadline,
            )
            .await
        });
        let first = sent_rx.recv().await.unwrap();
        assert!(matches!(first.payload, FramePayload::RequestData { sequence: 0, offset: 0, .. }));
        assert!(sent_rx.try_recv().is_err());
        let mut body = Box::pin(receive_body(receiver, receiver_sink, id, StreamDirection::Request, deadline));
        let mut actual = Vec::new();
        while let Some(chunk) = body.next().await {
            actual.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(actual, expected.as_ref());
        assert_eq!(
            tasks
                .join_next()
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
        let mut last_credit = None;
        while let Ok(frame) = credit_rx.try_recv() {
            last_credit = Some(frame);
        }
        assert!(matches!(last_credit.unwrap().payload, FramePayload::Credit {
            direction: StreamDirection::Request, next_sequence: 3, consumed_bytes,
        } if consumed_bytes == expected.len() as u64));
    }

    #[tokio::test]
    async fn quiet_source_and_blocked_send_cancel_without_another_data_frame() {
        struct QuietSink;
        #[async_trait]
        impl FrameSink for QuietSink {
            async fn send(
                &self,
                _: StreamFrame,
            ) -> Result<(), StreamErrorCode> {
                std::future::pending().await
            }
        }
        for quiet_source in [true, false] {
            let registry = registry();
            let id = Uuid::new_v4();
            let sender = registry
                .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let (source_tx, source_rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(1);
            if !quiet_source {
                source_tx
                    .send(Ok(Bytes::from_static(b"data")))
                    .await
                    .unwrap();
            }
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(async move {
                send_body(
                    &QuietSink,
                    &sender,
                    id,
                    StreamDirection::Response,
                    tokio_stream::wrappers::ReceiverStream::new(source_rx),
                    deadline,
                )
                .await
            });
            registry
                .deliver(
                    &message(id),
                    "instance",
                    StreamFrame {
                        stream_id: id,
                        payload: FramePayload::Cancel,
                    },
                )
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
                Err(StreamErrorCode::Cancelled)
            );
            assert!(source_tx.is_closed());
        }
    }

    #[tokio::test]
    async fn an_upload_that_stops_ends_after_its_progress_timeout() {
        let receiving = registry();
        let id = Uuid::new_v4();
        let mut receiver = receiving
            .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        receiver.set_progress_timeout(Duration::from_millis(200));
        let (frames, _sent) = tokio::sync::mpsc::channel(8);
        let sink = Arc::new(RegistrySink { remote: registry(), frames });
        let started = std::time::Instant::now();

        let mut body = Box::pin(receive_body(
            receiver,
            sink,
            id,
            StreamDirection::Request,
            Instant::now() + Duration::from_secs(3600),
        ));

        assert_eq!(body.next().await, Some(Err(StreamErrorCode::DeadlineExceeded)));
        assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
        drop(body);
        assert!(
            receiving
                .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .is_ok(),
            "the stream released its slot"
        );
    }
}
