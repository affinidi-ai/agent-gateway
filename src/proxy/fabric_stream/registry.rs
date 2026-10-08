use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{Notify, watch};
use uuid::Uuid;

use super::flow::{Credit, ReceiveWindow, SendCredit};
use super::peer::StreamCapabilities;
use super::wire::{FramePayload, StreamDirection, StreamErrorCode, StreamFrame, WireHeaders, decode_chunk};
use crate::gateways::connection_points::messages::ReceivedMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamBinding {
    pub peer_did: String,
    pub recipient_did: String,
    pub connection_point_id: String,
    pub listener_instance_id: String,
    pub surface_id: String,
}

impl StreamBinding {
    pub(super) fn validate(
        &self,
        stream_id: Uuid,
    ) -> Result<(), String> {
        if stream_id.is_nil()
            || self.peer_did.is_empty()
            || self.recipient_did.is_empty()
            || self
                .connection_point_id
                .is_empty()
            || self
                .listener_instance_id
                .is_empty()
            || self.surface_id.is_empty()
        {
            return Err("Fabric stream registration requires a complete peer and route binding".to_string());
        }
        Ok(())
    }

    pub(super) fn matches(
        &self,
        message: &ReceivedMessage,
        listener_instance_id: &str,
        stream_id: Uuid,
    ) -> bool {
        message.metadata.authenticated
            && message.metadata.encrypted
            && message.from_did.as_deref() == Some(self.peer_did.as_str())
            && message
                .to_dids
                .iter()
                .any(|did| did == &self.recipient_did)
            && message.connection_point_id == self.connection_point_id
            && listener_instance_id == self.listener_instance_id
            && message
                .didcomm_thid
                .as_deref()
                == Some(stream_id.to_string().as_str())
    }
}

/// What a stream carries. A listen holds its slot for the life of a
/// subscription, so listens count against their own peer and surface budget
/// and cannot use up the request streams of the same peer or surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamKind {
    Request,
    Listen,
}

impl StreamKind {
    pub fn for_method(method: Option<&str>) -> Self {
        if method == Some("subscriptions/listen") {
            Self::Listen
        } else {
            Self::Request
        }
    }
}

/// Why a stream was not registered. `CapacityReached` is a full stream cap,
/// which the caller is told to retry; anything else is a refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RegisterError {
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    CapacityReached(&'static str),
}

impl From<String> for RegisterError {
    fn from(reason: String) -> Self {
        Self::Refused(reason)
    }
}

impl From<&str> for RegisterError {
    fn from(reason: &str) -> Self {
        Self::Refused(reason.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RegistryLimits {
    pub max_streams: usize,
    pub max_peer_streams: usize,
    pub max_surface_streams: usize,
    pub max_peer_listens: usize,
    pub max_surface_listens: usize,
}

impl RegistryLimits {
    /// Whether a new stream of `kind` is refused, given the number of
    /// registered streams and, for each, whether it shares the new stream's
    /// peer and surface budget.
    fn reached(
        &self,
        kind: StreamKind,
        registered: usize,
        shared: impl Iterator<Item = (bool, bool)>,
    ) -> bool {
        let (max_peer, max_surface) = match kind {
            StreamKind::Request => (self.max_peer_streams, self.max_surface_streams),
            StreamKind::Listen => (self.max_peer_listens, self.max_surface_listens),
        };
        let (peer, surface) = shared.fold((0, 0), |(peer, surface), (same_peer, same_surface)| {
            (peer + usize::from(same_peer), surface + usize::from(same_surface))
        });
        registered >= self.max_streams || peer >= max_peer || surface >= max_surface
    }

    fn validate(&self) -> Result<(), String> {
        if [
            self.max_streams,
            self.max_peer_streams,
            self.max_surface_streams,
            self.max_peer_listens,
            self.max_surface_listens,
        ]
        .contains(&0)
        {
            return Err("Fabric stream registry limits must be positive".to_string());
        }
        Ok(())
    }
}

/// How a registered stream is counted: its binding, whether a peer opened it
/// here (inbound), and its kind.
#[derive(Clone, Copy)]
struct Counted<'binding> {
    binding: &'binding StreamBinding,
    inbound: bool,
    kind: StreamKind,
}

/// Whether a registered stream counts against a new one's peer and surface
/// limits. Streams a peer opened here (inbound) and streams this gateway
/// opened to a peer (outbound) are counted apart, so neither uses up the
/// other's slots, and so are listens and request streams. An inbound stream's
/// surface is local, shared by every peer; an outbound stream's is the peer's
/// own channel, so it is counted per peer.
fn shared_limits(
    registered: Counted<'_>,
    new: Counted<'_>,
) -> (bool, bool) {
    if registered.inbound != new.inbound || registered.kind != new.kind {
        return (false, false);
    }
    let (registered, new, new_inbound) = (registered.binding, new.binding, new.inbound);
    let same_peer = registered.peer_did == new.peer_did;
    let same_surface = registered.surface_id == new.surface_id && (new_inbound || same_peer);
    (same_peer, same_surface)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiveEvent {
    Start { status: u16, headers: WireHeaders },
    Data { bytes: bytes::Bytes, credit: Credit },
    End,
}

#[derive(Debug)]
struct ReceiveState {
    window: ReceiveWindow,
    start: Option<(u16, WireHeaders)>,
    start_delivered: bool,
    error: Option<StreamErrorCode>,
    terminal: bool,
}

struct ReceiveEntry {
    binding: StreamBinding,
    direction: StreamDirection,
    kind: StreamKind,
    capabilities: StreamCapabilities,
    state: Mutex<ReceiveState>,
    notify: Notify,
    closed: watch::Sender<Option<StreamErrorCode>>,
}

struct SendEntry {
    binding: StreamBinding,
    direction: StreamDirection,
    kind: StreamKind,
    capabilities: StreamCapabilities,
    credit: SendCredit,
}

/// Replay records kept per allowed stream. A record lasts no longer than the
/// capability offer its `Open` used, so this bounds memory without capping
/// ordinary traffic.
const OPEN_REPLAY_RECORDS_PER_STREAM: usize = 512;

pub(crate) struct ReceiveRegistry {
    entries: Mutex<HashMap<Uuid, Arc<ReceiveEntry>>>,
    senders: Mutex<HashMap<Uuid, Arc<SendEntry>>>,
    opened: Mutex<HashMap<Uuid, tokio::time::Instant>>,
    limits: RegistryLimits,
}

impl ReceiveRegistry {
    pub fn new(limits: RegistryLimits) -> Result<Arc<Self>, String> {
        limits.validate()?;
        Ok(Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            senders: Mutex::new(HashMap::new()),
            opened: Mutex::new(HashMap::new()),
            limits,
        }))
    }

    #[cfg(test)]
    pub fn open(
        self: &Arc<Self>,
        stream_id: Uuid,
        binding: StreamBinding,
        request_window: usize,
        response_window: usize,
        deadline: tokio::time::Instant,
    ) -> Result<(ReceiveLease, SendLease), RegisterError> {
        self.open_with_capabilities(
            stream_id,
            binding,
            StreamKind::Request,
            request_window,
            response_window,
            deadline,
            deadline,
            &StreamCapabilities::local(true, true),
        )
    }

    /// Whether an `Open` for this stream was accepted and the stream is still
    /// registered or the same `Open` could still be admitted.
    pub fn was_opened(
        &self,
        stream_id: &Uuid,
    ) -> bool {
        self.opened
            .lock()
            .is_ok_and(|opened| {
                opened
                    .get(stream_id)
                    .is_some_and(|until| *until > tokio::time::Instant::now())
            })
            || self
                .entries
                .lock()
                .is_ok_and(|entries| entries.contains_key(stream_id))
            || self
                .senders
                .lock()
                .is_ok_and(|senders| senders.contains_key(stream_id))
    }

    /// Register both directions of an accepted `Open`. `deadline` bounds how
    /// long the stream runs. `replayable_until` is the last instant the same
    /// `Open` could still be admitted, the earlier of its envelope's and its
    /// capability offer's expiry, and the replay record lasts until then. A
    /// repeated `Open` of a stream still registered is refused by that
    /// registration, however long the stream runs.
    #[allow(clippy::too_many_arguments)]
    pub fn open_with_capabilities(
        self: &Arc<Self>,
        stream_id: Uuid,
        binding: StreamBinding,
        kind: StreamKind,
        request_window: usize,
        response_window: usize,
        deadline: tokio::time::Instant,
        replayable_until: tokio::time::Instant,
        capabilities: &StreamCapabilities,
    ) -> Result<(ReceiveLease, SendLease), RegisterError> {
        binding.validate(stream_id)?;
        let now = tokio::time::Instant::now();
        if deadline <= now || deadline.duration_since(now) > std::time::Duration::from_secs(86_400) {
            return Err("Fabric stream deadline is outside the accepted lifetime".into());
        }
        if replayable_until <= now {
            return Err("Fabric stream Open is no longer admissible".into());
        }
        let mut opened = self
            .opened
            .lock()
            .map_err(|_| "Fabric open registry is unavailable")?;
        if opened
            .get(&stream_id)
            .is_some_and(|until| *until > now)
        {
            return Err("Fabric stream Open was already accepted".into());
        }
        let capacity = self
            .limits
            .max_streams
            .saturating_mul(OPEN_REPLAY_RECORDS_PER_STREAM);
        if opened.len() >= capacity {
            opened.retain(|_, until| *until > now);
        }
        if opened.len() >= capacity {
            return Err(RegisterError::CapacityReached("Fabric open replay-protection capacity reached"));
        }
        let receiver = self.register_negotiated(
            stream_id,
            binding.clone(),
            kind,
            StreamDirection::Request,
            request_window,
            capabilities,
        )?;
        let sender = self.register_sender_negotiated(
            stream_id,
            binding,
            kind,
            StreamDirection::Response,
            response_window,
            capabilities,
        )?;
        opened.insert(stream_id, replayable_until);
        Ok((receiver, sender))
    }

    #[cfg(test)]
    pub fn register(
        self: &Arc<Self>,
        stream_id: Uuid,
        binding: StreamBinding,
        direction: StreamDirection,
        window_bytes: usize,
    ) -> Result<ReceiveLease, RegisterError> {
        self.register_negotiated(
            stream_id,
            binding,
            StreamKind::Request,
            direction,
            window_bytes,
            &StreamCapabilities::local(true, true),
        )
    }

    pub fn register_negotiated(
        self: &Arc<Self>,
        stream_id: Uuid,
        binding: StreamBinding,
        kind: StreamKind,
        direction: StreamDirection,
        window_bytes: usize,
        capabilities: &StreamCapabilities,
    ) -> Result<ReceiveLease, RegisterError> {
        binding.validate(stream_id)?;
        validate_registered_limits(window_bytes, capabilities)?;
        let state = ReceiveState {
            window: ReceiveWindow::new(window_bytes)?,
            start: None,
            start_delivered: direction == StreamDirection::Request,
            error: None,
            terminal: false,
        };
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "Fabric stream registry is unavailable")?;
        if entries.contains_key(&stream_id) {
            return Err("Fabric stream identifier is already registered".into());
        }
        let new = Counted {
            binding: &binding,
            inbound: direction == StreamDirection::Request,
            kind,
        };
        if self.limits.reached(
            kind,
            entries.len(),
            entries.values().map(|entry| {
                shared_limits(
                    Counted {
                        binding: &entry.binding,
                        inbound: entry.direction == StreamDirection::Request,
                        kind: entry.kind,
                    },
                    new,
                )
            }),
        ) {
            return Err(RegisterError::CapacityReached("Fabric stream concurrency limit reached"));
        }
        let (closed, _) = watch::channel(None);
        let entry = Arc::new(ReceiveEntry {
            binding,
            direction,
            kind,
            capabilities: capabilities.clone(),
            state: Mutex::new(state),
            notify: Notify::new(),
            closed,
        });
        entries.insert(stream_id, entry.clone());
        Ok(ReceiveLease {
            registry: Arc::downgrade(self),
            stream_id,
            entry,
            finished: false,
            progress_timeout: None,
        })
    }

    #[cfg(test)]
    pub fn register_sender(
        self: &Arc<Self>,
        stream_id: Uuid,
        binding: StreamBinding,
        direction: StreamDirection,
        window_bytes: usize,
    ) -> Result<SendLease, RegisterError> {
        self.register_sender_negotiated(
            stream_id,
            binding,
            StreamKind::Request,
            direction,
            window_bytes,
            &StreamCapabilities::local(true, true),
        )
    }

    pub fn register_sender_negotiated(
        self: &Arc<Self>,
        stream_id: Uuid,
        binding: StreamBinding,
        kind: StreamKind,
        direction: StreamDirection,
        window_bytes: usize,
        capabilities: &StreamCapabilities,
    ) -> Result<SendLease, RegisterError> {
        binding.validate(stream_id)?;
        validate_registered_limits(window_bytes, capabilities)?;
        let credit = SendCredit::new(window_bytes)?;
        let mut senders = self
            .senders
            .lock()
            .map_err(|_| "Fabric sender registry is unavailable")?;
        if senders.contains_key(&stream_id) {
            return Err("Fabric stream sender is already registered".into());
        }
        let new = Counted {
            binding: &binding,
            inbound: direction == StreamDirection::Response,
            kind,
        };
        if self.limits.reached(
            kind,
            senders.len(),
            senders.values().map(|entry| {
                shared_limits(
                    Counted {
                        binding: &entry.binding,
                        inbound: entry.direction == StreamDirection::Response,
                        kind: entry.kind,
                    },
                    new,
                )
            }),
        ) {
            return Err(RegisterError::CapacityReached("Fabric sender concurrency limit reached"));
        }
        let entry = Arc::new(SendEntry {
            binding,
            direction,
            kind,
            capabilities: capabilities.clone(),
            credit,
        });
        senders.insert(stream_id, entry.clone());
        Ok(SendLease {
            registry: Arc::downgrade(self),
            stream_id,
            entry,
        })
    }

    pub fn deliver(
        &self,
        message: &ReceivedMessage,
        listener_instance_id: &str,
        frame: StreamFrame,
    ) -> Result<bool, String> {
        let send_entry = self
            .senders
            .lock()
            .map_err(|_| "Fabric sender registry is unavailable")?
            .get(&frame.stream_id)
            .cloned();
        let mut delivered = false;
        if matches!(
            frame.payload,
            FramePayload::Credit { .. }
                | FramePayload::EndAck { .. }
                | FramePayload::Cancel
                | FramePayload::Error { .. }
        ) && let Some(entry) = send_entry.as_ref()
        {
            if !entry
                .binding
                .matches(message, listener_instance_id, frame.stream_id)
            {
                return Err("Fabric stream control has an unauthenticated or mismatched peer binding".to_string());
            }
            if let Err(error) = entry
                .capabilities
                .validate_frame(&frame)
            {
                entry
                    .credit
                    .cancel(StreamErrorCode::InvalidFrame);
                return Err(error);
            }
            match &frame.payload {
                FramePayload::Credit {
                    direction,
                    next_sequence,
                    consumed_bytes,
                } => {
                    if *direction != entry.direction {
                        entry
                            .credit
                            .cancel(StreamErrorCode::InvalidFrame);
                        return Err("Fabric stream credit has the wrong direction".to_string());
                    }
                    return entry
                        .credit
                        .acknowledge(Credit {
                            next_sequence: *next_sequence,
                            consumed_bytes: *consumed_bytes,
                        });
                }
                FramePayload::EndAck { next_sequence, body_bytes } => {
                    if entry.direction != StreamDirection::Response {
                        entry
                            .credit
                            .cancel(StreamErrorCode::InvalidFrame);
                        return Err("Fabric terminal acknowledgement has the wrong direction".to_string());
                    }
                    return entry
                        .credit
                        .acknowledge_end(Credit {
                            next_sequence: *next_sequence,
                            consumed_bytes: *body_bytes,
                        });
                }
                FramePayload::Cancel => entry
                    .credit
                    .cancel(StreamErrorCode::Cancelled),
                FramePayload::Error { code } => entry.credit.cancel(*code),
                _ => {}
            }
            delivered = true;
        }
        let entry = self
            .entries
            .lock()
            .map_err(|_| "Fabric stream registry is unavailable")?
            .get(&frame.stream_id)
            .cloned();
        let Some(entry) = entry else { return Ok(delivered) };
        if !entry
            .binding
            .matches(message, listener_instance_id, frame.stream_id)
        {
            return Err("Fabric stream frame has an unauthenticated or mismatched peer binding".to_string());
        }
        let mut state = entry
            .state
            .lock()
            .map_err(|_| "Fabric stream state is unavailable")?;
        if state.terminal || state.error.is_some() {
            return Ok(false);
        }
        let result = entry
            .capabilities
            .validate_frame(&frame)
            .and_then(|_| match frame.payload {
                FramePayload::Start { status, headers } if entry.direction == StreamDirection::Response => {
                    if let Some(previous) = &state.start {
                        if previous != &(status, headers) {
                            return Err("Conflicting Fabric stream start frame".to_string());
                        }
                    } else {
                        state.start = Some((status, headers));
                    }
                    Ok(())
                }
                FramePayload::Data { sequence, offset, data } if entry.direction == StreamDirection::Response => {
                    state
                        .window
                        .accept(sequence, offset, decode_chunk(&data)?)?;
                    Ok(())
                }
                FramePayload::RequestData { sequence, offset, data } if entry.direction == StreamDirection::Request => {
                    state
                        .window
                        .accept(sequence, offset, decode_chunk(&data)?)?;
                    Ok(())
                }
                FramePayload::End { next_sequence, body_bytes } if entry.direction == StreamDirection::Response => {
                    state.window.finish(Credit {
                        next_sequence,
                        consumed_bytes: body_bytes,
                    })?;
                    Ok(())
                }
                FramePayload::RequestEnd { next_sequence, body_bytes }
                    if entry.direction == StreamDirection::Request =>
                {
                    state.window.finish(Credit {
                        next_sequence,
                        consumed_bytes: body_bytes,
                    })?;
                    Ok(())
                }
                FramePayload::Cancel => {
                    state.error = Some(StreamErrorCode::Cancelled);
                    Ok(())
                }
                FramePayload::Error { code } => {
                    state.error = Some(code);
                    Ok(())
                }
                _ => Err("Fabric stream frame has an invalid direction or lifecycle".to_string()),
            });
        if result.is_err() {
            state.error = Some(StreamErrorCode::InvalidFrame);
            entry
                .closed
                .send_replace(state.error);
            if let Some(sender) = send_entry {
                sender
                    .credit
                    .cancel(StreamErrorCode::InvalidFrame);
            }
        }
        drop(state);
        entry.notify.notify_one();
        result.map(|_| true)
    }

    pub fn cancel_listener(
        &self,
        connection_point_id: &str,
        instance_id: &str,
    ) {
        if let Ok(mut senders) = self.senders.lock() {
            senders.retain(|_, entry| {
                if entry
                    .binding
                    .connection_point_id
                    != connection_point_id
                    || entry
                        .binding
                        .listener_instance_id
                        != instance_id
                {
                    return true;
                }
                entry
                    .credit
                    .cancel(StreamErrorCode::Unavailable);
                false
            });
        }
        let Ok(mut entries) = self.entries.lock() else { return };
        entries.retain(|_, entry| {
            if entry
                .binding
                .connection_point_id
                != connection_point_id
                || entry
                    .binding
                    .listener_instance_id
                    != instance_id
            {
                return true;
            }
            if let Ok(mut state) = entry.state.lock() {
                state.error = Some(StreamErrorCode::Unavailable);
            }
            entry
                .closed
                .send_replace(Some(StreamErrorCode::Unavailable));
            entry.notify.notify_one();
            false
        });
    }

    fn remove(
        &self,
        stream_id: Uuid,
        entry: &Arc<ReceiveEntry>,
    ) {
        if let Ok(mut entries) = self.entries.lock()
            && entries
                .get(&stream_id)
                .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(&stream_id);
        }
    }
}

fn validate_registered_limits(
    window_bytes: usize,
    capabilities: &StreamCapabilities,
) -> Result<(), String> {
    if &StreamCapabilities::local(true, true).negotiate(capabilities)? != capabilities
        || window_bytes > capabilities.max_window_bytes as usize
        || window_bytes < capabilities.max_chunk_bytes as usize
    {
        return Err("Fabric registration exceeds negotiated limits".to_string());
    }
    Ok(())
}

pub(crate) struct SendLease {
    registry: Weak<ReceiveRegistry>,
    stream_id: Uuid,
    entry: Arc<SendEntry>,
}

impl SendLease {
    pub fn credit(&self) -> &SendCredit {
        &self.entry.credit
    }
}

impl Drop for SendLease {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade()
            && let Ok(mut senders) = registry.senders.lock()
            && senders
                .get(&self.stream_id)
                .is_some_and(|current| Arc::ptr_eq(current, &self.entry))
        {
            senders.remove(&self.stream_id);
        }
    }
}

pub(crate) struct ReceiveLease {
    registry: Weak<ReceiveRegistry>,
    stream_id: Uuid,
    entry: Arc<ReceiveEntry>,
    finished: bool,
    progress_timeout: Option<std::time::Duration>,
}

impl ReceiveLease {
    /// Bounds each wait for the peer's next frame in [`super::transport::receive_body`],
    /// so a peer that stops uploading releases the stream before its deadline.
    pub fn set_progress_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) {
        self.progress_timeout = Some(timeout);
    }

    /// The end of the next wait for the peer's progress.
    pub fn progress_deadline(
        &self,
        deadline: tokio::time::Instant,
    ) -> tokio::time::Instant {
        super::flow::progress_deadline(self.progress_timeout, deadline)
    }

    pub fn closed(&self) -> watch::Receiver<Option<StreamErrorCode>> {
        self.entry.closed.subscribe()
    }

    pub fn completion(&self) -> Result<Option<Credit>, StreamErrorCode> {
        let state = self
            .entry
            .state
            .lock()
            .map_err(|_| StreamErrorCode::Unavailable)?;
        if let Some(error) = state.error {
            return Err(error);
        }
        Ok((state.start_delivered && state.window.is_finished()).then(|| state.window.consumed()))
    }

    pub async fn next(&mut self) -> Result<ReceiveEvent, StreamErrorCode> {
        if self.finished {
            return Ok(ReceiveEvent::End);
        }
        loop {
            let notified = self.entry.notify.notified();
            let event = {
                let mut state = self
                    .entry
                    .state
                    .lock()
                    .map_err(|_| StreamErrorCode::Unavailable)?;
                if let Some(error) = state.error {
                    Some(Err(error))
                } else if !state.start_delivered {
                    state
                        .start
                        .clone()
                        .map(|(status, headers)| {
                            state.start_delivered = true;
                            Ok(ReceiveEvent::Start { status, headers })
                        })
                } else {
                    match state.window.consume() {
                        Ok(Some((bytes, credit))) => Some(Ok(ReceiveEvent::Data { bytes, credit })),
                        Ok(None) if state.window.is_finished() => {
                            state.terminal = true;
                            Some(Ok(ReceiveEvent::End))
                        }
                        Ok(None) => None,
                        Err(_) => {
                            state.error = Some(StreamErrorCode::InvalidFrame);
                            Some(Err(StreamErrorCode::InvalidFrame))
                        }
                    }
                }
            };
            if let Some(event) = event {
                if matches!(event, Ok(ReceiveEvent::End) | Err(_)) {
                    self.finished = true;
                    if let Some(registry) = self.registry.upgrade() {
                        registry.remove(self.stream_id, &self.entry);
                    }
                    if let Err(error) = event {
                        self.entry
                            .closed
                            .send_replace(Some(error));
                    }
                }
                return event;
            }
            notified.await;
        }
    }
}

impl Drop for ReceiveLease {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.remove(self.stream_id, &self.entry);
        }
        if !self.finished {
            self.entry
                .closed
                .send_replace(Some(StreamErrorCode::Cancelled));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire::{MAX_CHUNK_BYTES, encode_chunk};
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;

    fn binding() -> StreamBinding {
        StreamBinding {
            peer_did: "did:example:peer".into(),
            recipient_did: "did:example:local".into(),
            connection_point_id: "connection".into(),
            listener_instance_id: "instance".into(),
            surface_id: "surface".into(),
        }
    }

    fn message(stream_id: Uuid) -> ReceivedMessage {
        ReceivedMessage::new(
            "connection".into(),
            "gateway".into(),
            "stream".into(),
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

    fn registry() -> Arc<ReceiveRegistry> {
        ReceiveRegistry::new(RegistryLimits {
            max_streams: 3,
            max_peer_streams: 2,
            max_surface_streams: 2,
            max_peer_listens: 2,
            max_surface_listens: 2,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn receive_rejects_negotiated_chunk_excess_without_trusting_forged_frames() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut capabilities = StreamCapabilities::local(true, true);
        capabilities.max_chunk_bytes = 4;
        capabilities.max_window_bytes = MAX_CHUNK_BYTES as u32;
        let mut receiver = registry
            .register_negotiated(
                id,
                binding(),
                StreamKind::Request,
                StreamDirection::Request,
                MAX_CHUNK_BYTES,
                &capabilities,
            )
            .unwrap();
        let sender = registry
            .register_sender_negotiated(
                id,
                binding(),
                StreamKind::Request,
                StreamDirection::Response,
                MAX_CHUNK_BYTES,
                &capabilities,
            )
            .unwrap();
        let frame = StreamFrame {
            stream_id: id,
            payload: FramePayload::RequestData {
                sequence: 0,
                offset: 0,
                data: encode_chunk(b"large").unwrap(),
            },
        };
        let mut forged = message(id);
        forged.from_did = Some("did:example:other".to_string());
        assert!(
            registry
                .deliver(&forged, "instance", frame.clone())
                .is_err()
        );
        assert!(
            receiver
                .closed()
                .borrow()
                .is_none()
        );
        assert!(
            sender
                .credit()
                .cancellation()
                .borrow()
                .is_none()
        );
        assert!(
            registry
                .deliver(&message(id), "instance", frame)
                .is_err()
        );
        assert_eq!(*receiver.closed().borrow(), Some(StreamErrorCode::InvalidFrame));
        assert_eq!(
            *sender
                .credit()
                .cancellation()
                .borrow(),
            Some(StreamErrorCode::InvalidFrame)
        );
        assert_eq!(receiver.next().await, Err(StreamErrorCode::InvalidFrame));
        assert!(
            registry
                .register_negotiated(
                    Uuid::new_v4(),
                    binding(),
                    StreamKind::Request,
                    StreamDirection::Response,
                    MAX_CHUNK_BYTES * 2,
                    &capabilities
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn receive_rejects_negotiated_header_excess_before_delivering_start() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut capabilities = StreamCapabilities::local(true, true);
        capabilities.max_header_bytes = 8;
        let mut receiver = registry
            .register_negotiated(
                id,
                binding(),
                StreamKind::Request,
                StreamDirection::Response,
                MAX_CHUNK_BYTES,
                &capabilities,
            )
            .unwrap();
        let frame = StreamFrame {
            stream_id: id,
            payload: FramePayload::Start {
                status: 200,
                headers: std::collections::BTreeMap::from([("x".to_string(), vec!["large".to_string()])]),
            },
        };
        assert!(
            registry
                .deliver(&message(id), "instance", frame)
                .is_err()
        );
        assert_eq!(receiver.next().await, Err(StreamErrorCode::InvalidFrame));
    }

    #[tokio::test]
    async fn open_replay_remains_rejected_after_completion_or_listener_replacement() {
        let registry = registry();
        let id = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let (receiver, sender) = registry
            .open(id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
            .unwrap();
        assert!(
            registry
                .open(id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .is_err()
        );
        drop((receiver, sender));
        assert!(
            registry
                .open(id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .is_err()
        );
        registry.cancel_listener("connection", "instance");
        let mut replaced = binding();
        replaced.listener_instance_id = "new-instance".to_string();
        assert!(
            registry
                .open(id, replaced.clone(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .is_err()
        );
        assert!(
            registry
                .open(Uuid::new_v4(), replaced, MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .is_ok()
        );
        assert!(
            registry
                .open(Uuid::new_v4(), binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, tokio::time::Instant::now())
                .is_err()
        );
    }

    #[tokio::test]
    async fn open_replay_stays_rejected_until_its_offer_expires_after_a_shorter_run() {
        let registry = registry();
        let id = Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let run = now + std::time::Duration::from_millis(50);
        let offer_expires = now + std::time::Duration::from_secs(60);
        let capabilities = StreamCapabilities::local(true, true);
        drop(
            registry
                .open_with_capabilities(
                    id,
                    binding(),
                    StreamKind::Request,
                    MAX_CHUNK_BYTES,
                    MAX_CHUNK_BYTES,
                    run,
                    offer_expires,
                    &capabilities,
                )
                .unwrap(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let later = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        assert!(
            registry
                .open_with_capabilities(
                    id,
                    binding(),
                    StreamKind::Request,
                    MAX_CHUNK_BYTES,
                    MAX_CHUNK_BYTES,
                    later,
                    later,
                    &capabilities
                )
                .is_err(),
            "a replayed Open is refused after its run ends while its offer is live"
        );
        assert!(registry.was_opened(&id));

        let expired = Uuid::new_v4();
        let short = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
        drop(
            registry
                .open_with_capabilities(
                    expired,
                    binding(),
                    StreamKind::Request,
                    MAX_CHUNK_BYTES,
                    MAX_CHUNK_BYTES,
                    short,
                    short,
                    &capabilities,
                )
                .unwrap(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!registry.was_opened(&expired), "the record ends once neither the run nor the offer is live");
    }

    /// A sender puts its stream lifetime on every Open, an hour by default, so
    /// a replay record bounded by that deadline let ordinary traffic fill the
    /// table. The record is bounded by when the Open could still be admitted.
    #[tokio::test]
    async fn short_streams_with_long_deadlines_do_not_exhaust_replay_protection() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 128,
            max_peer_streams: 16,
            max_surface_streams: 16,
            max_peer_listens: 16,
            max_surface_listens: 16,
        })
        .unwrap();
        let capabilities = StreamCapabilities::local(true, true);
        for stream in 0..2048 {
            let now = tokio::time::Instant::now();
            drop(
                registry
                    .open_with_capabilities(
                        Uuid::new_v4(),
                        binding(),
                        StreamKind::Request,
                        MAX_CHUNK_BYTES,
                        MAX_CHUNK_BYTES,
                        now + std::time::Duration::from_secs(3600),
                        now + std::time::Duration::from_secs(300),
                        &capabilities,
                    )
                    .unwrap_or_else(|error| panic!("stream {stream}: {error}")),
            );
        }
    }

    #[tokio::test]
    async fn a_replay_record_ends_when_its_open_is_no_longer_admissible_but_a_live_stream_stays_protected() {
        let registry = registry();
        let capabilities = StreamCapabilities::local(true, true);
        let id = Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let leases = registry
            .open_with_capabilities(
                id,
                binding(),
                StreamKind::Request,
                MAX_CHUNK_BYTES,
                MAX_CHUNK_BYTES,
                now + std::time::Duration::from_secs(3600),
                now + std::time::Duration::from_millis(50),
                &capabilities,
            )
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(registry.was_opened(&id), "a registered stream counts as opened");
        let later = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        assert!(
            registry
                .open_with_capabilities(
                    id,
                    binding(),
                    StreamKind::Request,
                    MAX_CHUNK_BYTES,
                    MAX_CHUNK_BYTES,
                    later,
                    later,
                    &capabilities
                )
                .is_err(),
            "a repeated Open never replaces a live stream"
        );
        drop(leases);
        assert!(!registry.was_opened(&id), "the record ended with its admission window");
    }

    #[tokio::test]
    async fn failed_open_releases_both_registrations_and_bounds_replay_memory() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 1,
            max_peer_streams: 1,
            max_surface_streams: 1,
            max_peer_listens: 1,
            max_surface_listens: 1,
        })
        .unwrap();
        let id = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        assert!(
            registry
                .open(id, binding(), MAX_CHUNK_BYTES, 0, deadline)
                .is_err()
        );
        for _ in 0..OPEN_REPLAY_RECORDS_PER_STREAM {
            drop(
                registry
                    .open(Uuid::new_v4(), binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                    .unwrap(),
            );
        }
        assert!(
            registry
                .open(id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline)
                .is_err()
        );
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(
            registry
                .senders
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            registry
                .opened
                .lock()
                .unwrap()
                .len(),
            OPEN_REPLAY_RECORDS_PER_STREAM
        );
    }

    #[tokio::test]
    async fn response_sender_survives_request_completion_and_rejects_forged_credit() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut request = registry
            .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let sender = registry
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        assert!(
            registry
                .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .is_err()
        );
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
        assert_eq!(request.next().await.unwrap(), ReceiveEvent::End);
        drop(request);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        sender
            .credit()
            .reserve(MAX_CHUNK_BYTES, deadline)
            .await
            .unwrap();
        let frame = StreamFrame {
            stream_id: id,
            payload: FramePayload::Credit {
                direction: StreamDirection::Response,
                next_sequence: 1,
                consumed_bytes: MAX_CHUNK_BYTES as u64,
            },
        };
        let mut forged = message(id);
        forged.from_did = Some("did:example:attacker".into());
        assert!(
            registry
                .deliver(&forged, "instance", frame.clone())
                .is_err()
        );
        assert!(
            registry
                .deliver(&message(id), "instance", frame)
                .unwrap()
        );
        assert_eq!(
            sender
                .credit()
                .reserve(1, deadline)
                .await
                .unwrap(),
            (1, MAX_CHUNK_BYTES as u64)
        );
        let mut cancelled = sender.credit().cancellation();
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
        cancelled
            .changed()
            .await
            .unwrap();
        assert_eq!(*cancelled.borrow(), Some(StreamErrorCode::Cancelled));
        assert_eq!(
            sender
                .credit()
                .reserve(1, deadline)
                .await
                .unwrap_err(),
            StreamErrorCode::Cancelled
        );
        drop(sender);
        assert!(
            registry
                .senders
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn terminal_acknowledgements_require_current_authenticated_response_binding() {
        let registry = registry();
        let id = Uuid::new_v4();
        let sender = registry
            .register_sender(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        sender
            .credit()
            .reserve(5, deadline)
            .await
            .unwrap();
        let terminal = sender
            .credit()
            .seal()
            .unwrap();
        let frame = StreamFrame {
            stream_id: id,
            payload: FramePayload::EndAck {
                next_sequence: terminal.next_sequence,
                body_bytes: terminal.consumed_bytes,
            },
        };
        for mismatch in ["sender", "recipient", "connection", "thread", "encrypted", "authenticated", "listener"] {
            let mut forged = message(id);
            let mut listener = "instance";
            match mismatch {
                "sender" => forged.from_did = Some("did:example:other".into()),
                "recipient" => forged.to_dids = vec!["did:example:other".into()],
                "connection" => forged.connection_point_id = "other".into(),
                "thread" => forged.didcomm_thid = Some(Uuid::new_v4().to_string()),
                "encrypted" => forged.metadata.encrypted = false,
                "authenticated" => forged.metadata.authenticated = false,
                "listener" => listener = "replaced",
                _ => unreachable!(),
            }
            assert!(
                registry
                    .deliver(&forged, listener, frame.clone())
                    .is_err(),
                "{mismatch}"
            );
            assert_eq!(
                sender
                    .credit()
                    .consumed_bytes(),
                0
            );
            assert!(futures::poll!(Box::pin(sender.credit().wait_consumed(deadline)).as_mut()).is_pending());
        }
        assert!(
            registry
                .deliver(&message(id), "instance", frame.clone())
                .unwrap()
        );
        assert!(
            !registry
                .deliver(&message(id), "instance", frame)
                .unwrap()
        );
        assert_eq!(
            sender
                .credit()
                .wait_consumed(deadline)
                .await,
            Ok(())
        );
        assert_eq!(
            sender
                .credit()
                .consumed_bytes(),
            5
        );
        drop(sender);

        let sender = registry
            .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        sender
            .credit()
            .seal()
            .unwrap();
        assert!(
            registry
                .deliver(
                    &message(id),
                    "instance",
                    StreamFrame {
                        stream_id: id,
                        payload: FramePayload::EndAck {
                            next_sequence: 0,
                            body_bytes: 0
                        },
                    }
                )
                .is_err()
        );
        assert_eq!(
            sender
                .credit()
                .wait_consumed(deadline)
                .await,
            Err(StreamErrorCode::InvalidFrame)
        );
    }

    #[tokio::test]
    async fn listener_cancellation_and_wrong_direction_close_registered_senders() {
        let registry = registry();
        let id = Uuid::new_v4();
        let sender = registry
            .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let frame = StreamFrame {
            stream_id: id,
            payload: FramePayload::Credit {
                direction: StreamDirection::Response,
                next_sequence: 0,
                consumed_bytes: 0,
            },
        };
        assert!(
            registry
                .deliver(&message(id), "instance", frame)
                .is_err()
        );
        assert_eq!(
            sender
                .credit()
                .sent()
                .unwrap_err(),
            StreamErrorCode::InvalidFrame
        );
        drop(sender);
        let sender = registry
            .register_sender(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        registry.cancel_listener("connection", "instance");
        assert_eq!(
            sender
                .credit()
                .sent()
                .unwrap_err(),
            StreamErrorCode::Unavailable
        );
        assert!(
            registry
                .senders
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn registered_stream_delivers_start_then_data_and_cleans_up() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut stream = registry
            .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let message = message(id);
        for payload in [
            FramePayload::Data {
                sequence: 0,
                offset: 0,
                data: encode_chunk(b"body").unwrap(),
            },
            FramePayload::Start {
                status: 200,
                headers: WireHeaders::new(),
            },
            FramePayload::End {
                next_sequence: 1,
                body_bytes: 4,
            },
        ] {
            assert!(
                registry
                    .deliver(&message, "instance", StreamFrame { stream_id: id, payload })
                    .unwrap()
            );
        }
        assert_eq!(
            stream.next().await.unwrap(),
            ReceiveEvent::Start {
                status: 200,
                headers: WireHeaders::new()
            }
        );
        assert_eq!(
            stream.next().await.unwrap(),
            ReceiveEvent::Data {
                bytes: bytes::Bytes::from_static(b"body"),
                credit: Credit {
                    next_sequence: 1,
                    consumed_bytes: 4
                }
            }
        );
        assert_eq!(stream.next().await.unwrap(), ReceiveEvent::End);
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(
            !registry
                .deliver(
                    &message,
                    "instance",
                    StreamFrame {
                        stream_id: id,
                        payload: FramePayload::Cancel
                    }
                )
                .unwrap()
        );
    }

    #[tokio::test]
    async fn forged_frames_cannot_mutate_or_cancel_another_stream() {
        let registry = registry();
        let id = Uuid::new_v4();
        let mut stream = registry
            .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        for mutation in 0..6 {
            let mut message = message(id);
            match mutation {
                0 => message.from_did = Some("did:example:attacker".into()),
                1 => message.metadata.authenticated = false,
                2 => message.metadata.encrypted = false,
                3 => message.to_dids = vec!["did:example:other".into()],
                4 => message.connection_point_id = "other".into(),
                _ => message.didcomm_thid = Some(Uuid::new_v4().to_string()),
            }
            assert!(
                registry
                    .deliver(
                        &message,
                        "instance",
                        StreamFrame {
                            stream_id: id,
                            payload: FramePayload::Cancel
                        }
                    )
                    .is_err()
            );
        }
        assert!(
            registry
                .deliver(
                    &message(id),
                    "old-instance",
                    StreamFrame {
                        stream_id: id,
                        payload: FramePayload::Cancel
                    }
                )
                .is_err()
        );
        assert!(
            stream
                .entry
                .state
                .lock()
                .unwrap()
                .error
                .is_none()
        );
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
            stream
                .next()
                .await
                .unwrap_err(),
            StreamErrorCode::Cancelled
        );
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn consumer_drop_and_listener_replacement_release_quiet_streams() {
        let registry = registry();
        let id = Uuid::new_v4();
        let stream = registry
            .register(id, binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let mut closed = stream.closed();
        drop(stream);
        closed
            .changed()
            .await
            .unwrap();
        assert_eq!(*closed.borrow(), Some(StreamErrorCode::Cancelled));
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .is_empty()
        );
        let mut stream = registry
            .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        registry.cancel_listener("connection", "other-instance");
        assert_eq!(
            registry
                .entries
                .lock()
                .unwrap()
                .len(),
            1
        );
        registry.cancel_listener("connection", "instance");
        assert_eq!(
            stream
                .next()
                .await
                .unwrap_err(),
            StreamErrorCode::Unavailable
        );
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn registry_capacity_and_duplicate_ids_never_replace_an_active_consumer() {
        let registry = registry();
        let id = Uuid::new_v4();
        let original = registry
            .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        assert!(
            registry
                .register(id, binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .is_err()
        );
        let other = registry
            .register(Uuid::new_v4(), binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        assert!(
            registry
                .register(Uuid::new_v4(), binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
                .is_err()
        );
        drop(other);
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .get(&id)
                .is_some_and(|entry| Arc::ptr_eq(entry, &original.entry))
        );
        let mut other_binding = binding();
        other_binding.peer_did = "did:example:second".into();
        other_binding.surface_id = "second-surface".into();
        let second = registry
            .register(Uuid::new_v4(), other_binding.clone(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        let third = registry
            .register(Uuid::new_v4(), other_binding.clone(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        assert!(
            registry
                .register(Uuid::new_v4(), other_binding, StreamDirection::Request, MAX_CHUNK_BYTES)
                .is_err()
        );
        drop((original, second, third));
        assert!(
            registry
                .entries
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    fn bound(
        peer: &str,
        surface: &str,
    ) -> StreamBinding {
        let mut binding = binding();
        binding.peer_did = peer.into();
        binding.surface_id = surface.into();
        binding
    }

    #[test]
    fn inbound_and_outbound_streams_are_counted_apart() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 16,
            max_peer_streams: 2,
            max_surface_streams: 3,
            max_peer_listens: 2,
            max_surface_listens: 3,
        })
        .unwrap();
        let register = |binding: StreamBinding, inbound: bool| {
            let direction = if inbound {
                StreamDirection::Request
            } else {
                StreamDirection::Response
            };
            registry.register(Uuid::new_v4(), binding, direction, MAX_CHUNK_BYTES)
        };
        // A peer fills its inbound slots, but this gateway can still call it.
        let _inbound: Vec<_> = (0..2)
            .map(|_| register(bound("did:example:a", "default"), true).unwrap())
            .collect();
        assert!(register(bound("did:example:a", "default"), true).is_err());
        let _outbound: Vec<_> = (0..2)
            .map(|_| register(bound("did:example:a", "default"), false).unwrap())
            .collect();
        // Another peer's channel of the same name is a different surface.
        let _other: Vec<_> = (0..2)
            .map(|_| register(bound("did:example:b", "default"), false).unwrap())
            .collect();
        // One peer cannot fill a local surface: a second peer still gets in,
        // up to the surface cap.
        let _second = register(bound("did:example:b", "default"), true).unwrap();
        assert!(register(bound("did:example:c", "default"), true).is_err());
        assert!(register(bound("did:example:c", "other"), true).is_ok());
    }

    #[test]
    fn senders_are_counted_by_direction_too() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 16,
            max_peer_streams: 1,
            max_surface_streams: 1,
            max_peer_listens: 1,
            max_surface_listens: 1,
        })
        .unwrap();
        let _response = registry
            .register_sender(Uuid::new_v4(), binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
            .unwrap();
        let _request = registry
            .register_sender(Uuid::new_v4(), binding(), StreamDirection::Request, MAX_CHUNK_BYTES)
            .unwrap();
        assert!(
            registry
                .register_sender(Uuid::new_v4(), binding(), StreamDirection::Response, MAX_CHUNK_BYTES)
                .is_err()
        );
    }

    #[test]
    fn listens_have_a_budget_apart_from_request_streams() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 16,
            max_peer_streams: 2,
            max_surface_streams: 3,
            max_peer_listens: 1,
            max_surface_listens: 2,
        })
        .unwrap();
        let register = |binding: StreamBinding, kind: StreamKind| {
            registry.register_negotiated(
                Uuid::new_v4(),
                binding,
                kind,
                StreamDirection::Request,
                MAX_CHUNK_BYTES,
                &StreamCapabilities::local(true, true),
            )
        };
        let _listen = register(bound("did:example:a", "default"), StreamKind::Listen).unwrap();
        assert_eq!(
            register(bound("did:example:a", "default"), StreamKind::Listen).err(),
            Some(RegisterError::CapacityReached("Fabric stream concurrency limit reached"))
        );
        // A peer holding all of its listens still opens request streams, up
        // to its request cap.
        let _requests: Vec<_> = (0..2)
            .map(|_| register(bound("did:example:a", "default"), StreamKind::Request).unwrap())
            .collect();
        assert!(matches!(
            register(bound("did:example:a", "default"), StreamKind::Request),
            Err(RegisterError::CapacityReached(_))
        ));
        // Listens fill their surface budget without touching request slots.
        let _second_listen = register(bound("did:example:b", "default"), StreamKind::Listen).unwrap();
        assert!(register(bound("did:example:c", "default"), StreamKind::Listen).is_err());
        let _request = register(bound("did:example:c", "default"), StreamKind::Request).unwrap();
        assert!(register(bound("did:example:d", "default"), StreamKind::Request).is_err());
    }

    #[test]
    fn listen_senders_have_their_own_budget() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 16,
            max_peer_streams: 1,
            max_surface_streams: 1,
            max_peer_listens: 1,
            max_surface_listens: 1,
        })
        .unwrap();
        let register = |kind: StreamKind| {
            registry.register_sender_negotiated(
                Uuid::new_v4(),
                binding(),
                kind,
                StreamDirection::Request,
                MAX_CHUNK_BYTES,
                &StreamCapabilities::local(true, true),
            )
        };
        let _listen = register(StreamKind::Listen).unwrap();
        let _request = register(StreamKind::Request).unwrap();
        assert_eq!(
            register(StreamKind::Listen).err(),
            Some(RegisterError::CapacityReached("Fabric sender concurrency limit reached"))
        );
        assert!(matches!(register(StreamKind::Request), Err(RegisterError::CapacityReached(_))));
    }

    #[test]
    fn the_total_cap_counts_both_kinds_and_other_refusals_are_not_capacity() {
        let registry = ReceiveRegistry::new(RegistryLimits {
            max_streams: 1,
            max_peer_streams: 1,
            max_surface_streams: 1,
            max_peer_listens: 1,
            max_surface_listens: 1,
        })
        .unwrap();
        let id = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let _listen = registry
            .open_with_capabilities(
                id,
                binding(),
                StreamKind::Listen,
                MAX_CHUNK_BYTES,
                MAX_CHUNK_BYTES,
                deadline,
                deadline,
                &StreamCapabilities::local(true, true),
            )
            .unwrap();
        assert!(matches!(
            registry.open(Uuid::new_v4(), binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline),
            Err(RegisterError::CapacityReached(_))
        ));
        assert!(matches!(
            registry.open(id, binding(), MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, deadline),
            Err(RegisterError::Refused(_))
        ));
        assert!(
            ReceiveRegistry::new(RegistryLimits {
                max_streams: 4,
                max_peer_streams: 2,
                max_surface_streams: 2,
                max_peer_listens: 0,
                max_surface_listens: 2,
            })
            .is_err()
        );
    }

    #[test]
    fn only_a_listen_method_selects_the_listen_budget() {
        assert_eq!(StreamKind::for_method(Some("subscriptions/listen")), StreamKind::Listen);
        for method in [Some("tools/call"), Some("subscriptions/listen/extra"), Some("SUBSCRIPTIONS/LISTEN"), None] {
            assert_eq!(StreamKind::for_method(method), StreamKind::Request, "{method:?}");
        }
    }
}
