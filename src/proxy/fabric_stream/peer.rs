use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::registry::StreamBinding;
use super::wire::{
    FramePayload, MAX_CHUNK_BYTES, MAX_FRAME_BYTES, MAX_HEADER_BYTES, MAX_WINDOW_BYTES, StreamFrame, decode_chunk,
};
use crate::gateways::connection_points::messages::ReceivedMessage;

const MAX_PROBES: usize = 256;
const MAX_PEERS: usize = 256;
const PROBE_TTL: Duration = Duration::from_secs(30);
const PEER_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamCapabilities {
    pub version: u16,
    pub max_frame_bytes: u32,
    pub max_chunk_bytes: u32,
    pub max_header_bytes: u32,
    pub max_window_bytes: u32,
    pub request_streams: bool,
    pub subscriptions: bool,
}

impl StreamCapabilities {
    pub fn local(
        request_streams: bool,
        subscriptions: bool,
    ) -> Self {
        Self {
            version: 1,
            max_frame_bytes: MAX_FRAME_BYTES as u32,
            max_chunk_bytes: MAX_CHUNK_BYTES as u32,
            max_header_bytes: MAX_HEADER_BYTES as u32,
            max_window_bytes: MAX_WINDOW_BYTES as u32,
            request_streams,
            subscriptions,
        }
    }

    pub fn negotiate(
        &self,
        peer: &Self,
    ) -> Result<Self, String> {
        let negotiated = Self {
            version: 1,
            max_frame_bytes: self
                .max_frame_bytes
                .min(peer.max_frame_bytes),
            max_chunk_bytes: self
                .max_chunk_bytes
                .min(peer.max_chunk_bytes),
            max_header_bytes: self
                .max_header_bytes
                .min(peer.max_header_bytes),
            max_window_bytes: self
                .max_window_bytes
                .min(peer.max_window_bytes),
            request_streams: self.request_streams && peer.request_streams,
            subscriptions: self.subscriptions && peer.subscriptions,
        };
        if self.version != 1
            || peer.version != 1
            || negotiated.max_chunk_bytes == 0
            || negotiated.max_header_bytes == 0
            || negotiated.max_window_bytes < negotiated.max_chunk_bytes
            || u64::from(negotiated.max_chunk_bytes).div_ceil(3) * 4 + 1024 > u64::from(negotiated.max_frame_bytes)
            || u64::from(negotiated.max_header_bytes) + 1024 > u64::from(negotiated.max_frame_bytes)
        {
            return Err("Peer Fabric stream limits or version are incompatible".to_string());
        }
        Ok(negotiated)
    }

    pub fn permits_mcp_method(
        &self,
        method: &str,
    ) -> bool {
        self.request_streams && (method != "subscriptions/listen" || self.subscriptions)
    }

    pub fn validate_frame(
        &self,
        frame: &StreamFrame,
    ) -> Result<(), String> {
        frame.validate()?;
        if serde_json::to_vec(frame)
            .map_err(|error| error.to_string())?
            .len()
            > self.max_frame_bytes as usize
        {
            return Err("Fabric frame exceeds the negotiated byte limit".to_string());
        }
        let headers = match &frame.payload {
            FramePayload::Open { request } => {
                if request.response_window_bytes > self.max_window_bytes {
                    return Err("Fabric Open exceeds the negotiated credit window".to_string());
                }
                Some(&request.headers)
            }
            FramePayload::Start { headers, .. } => Some(headers),
            FramePayload::Data { data, .. } | FramePayload::RequestData { data, .. } => {
                if decode_chunk(data)?.len() > self.max_chunk_bytes as usize {
                    return Err("Fabric chunk exceeds the negotiated byte limit".to_string());
                }
                None
            }
            _ => None,
        };
        if let Some(headers) = headers {
            let bytes = headers
                .iter()
                .flat_map(|(name, values)| {
                    values
                        .iter()
                        .map(move |value| (name, value))
                })
                .fold(0_usize, |bytes, (name, value)| {
                    bytes
                        .saturating_add(name.len())
                        .saturating_add(value.len())
                        .saturating_add(4)
                });
            if bytes > self.max_header_bytes as usize {
                return Err("Fabric headers exceed the negotiated byte limit".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityMessage {
    pub nonce: Uuid,
    pub capabilities: StreamCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PeerKey {
    peer_did: String,
    recipient_did: String,
    connection_point_id: String,
    listener_instance_id: String,
}

impl From<&StreamBinding> for PeerKey {
    fn from(binding: &StreamBinding) -> Self {
        Self {
            peer_did: binding.peer_did.clone(),
            recipient_did: binding.recipient_did.clone(),
            connection_point_id: binding
                .connection_point_id
                .clone(),
            listener_instance_id: binding
                .listener_instance_id
                .clone(),
        }
    }
}

struct PendingProbe {
    binding: StreamBinding,
    deadline: Instant,
}

struct InboundOffer {
    binding: StreamBinding,
    capabilities: StreamCapabilities,
    deadline: Instant,
}

struct PeerState {
    probes: HashMap<Uuid, PendingProbe>,
    peers: HashMap<PeerKey, (CapabilityMessage, Instant)>,
    offers: HashMap<Uuid, InboundOffer>,
}

pub(crate) struct PeerCapabilities {
    local: StreamCapabilities,
    state: Mutex<PeerState>,
    changed: tokio::sync::Notify,
}

impl PeerCapabilities {
    pub fn new(local: StreamCapabilities) -> Self {
        Self {
            local,
            state: Mutex::new(PeerState {
                probes: HashMap::new(),
                peers: HashMap::new(),
                offers: HashMap::new(),
            }),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub fn offer(
        &self,
        message: &ReceivedMessage,
        binding: StreamBinding,
        query: CapabilityMessage,
        now: Instant,
    ) -> Result<CapabilityMessage, String> {
        binding.validate(query.nonce)?;
        if message.didcomm_message_id != query.nonce.to_string()
            || !binding.matches(message, &binding.listener_instance_id, query.nonce)
        {
            return Err("Fabric capability query lacks authenticated nonce correlation".to_string());
        }
        let capabilities = self
            .local
            .negotiate(&query.capabilities)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Fabric peer capabilities are unavailable")?;
        state
            .offers
            .retain(|_, offer| offer.deadline > now);
        if state
            .offers
            .contains_key(&query.nonce)
            || state.offers.len() >= MAX_PROBES
        {
            return Err("Fabric capability offer is duplicate or capacity is unavailable".to_string());
        }
        state.offers.insert(
            query.nonce,
            InboundOffer {
                binding,
                capabilities: capabilities.clone(),
                deadline: now + PEER_TTL,
            },
        );
        Ok(CapabilityMessage {
            nonce: query.nonce,
            capabilities,
        })
    }

    /// The live offer for `nonce` to this peer, with the instant it expires.
    pub fn offered(
        &self,
        binding: &StreamBinding,
        nonce: Uuid,
        now: Instant,
    ) -> Option<(StreamCapabilities, Instant)> {
        let mut state = self.state.lock().ok()?;
        state
            .offers
            .retain(|_, offer| offer.deadline > now);
        let offer = state.offers.get(&nonce)?;
        (PeerKey::from(&offer.binding) == PeerKey::from(binding)).then(|| (offer.capabilities.clone(), offer.deadline))
    }

    pub fn begin(
        &self,
        binding: StreamBinding,
        now: Instant,
    ) -> Result<CapabilityMessage, String> {
        let nonce = Uuid::new_v4();
        binding.validate(nonce)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Fabric peer capabilities are unavailable")?;
        state
            .probes
            .retain(|_, probe| probe.deadline > now);
        if state.probes.len() >= MAX_PROBES {
            return Err("Fabric capability probe limit reached".to_string());
        }
        state.probes.insert(
            nonce,
            PendingProbe {
                binding,
                deadline: now + PROBE_TTL,
            },
        );
        Ok(CapabilityMessage {
            nonce,
            capabilities: self.local.clone(),
        })
    }

    pub fn accept(
        &self,
        message: &ReceivedMessage,
        listener_instance_id: &str,
        disclosure: CapabilityMessage,
        now: Instant,
    ) -> Result<StreamCapabilities, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Fabric peer capabilities are unavailable")?;
        state
            .probes
            .retain(|_, probe| probe.deadline > now);
        state
            .peers
            .retain(|_, (_, deadline)| *deadline > now);
        let probe = state
            .probes
            .get(&disclosure.nonce)
            .ok_or("Unsolicited or expired Fabric stream capability disclosure")?;
        if !probe
            .binding
            .matches(message, listener_instance_id, disclosure.nonce)
        {
            return Err("Fabric capability disclosure has a mismatched authenticated peer binding".to_string());
        }
        let negotiated = self
            .local
            .negotiate(&disclosure.capabilities)?;
        let key = PeerKey::from(&probe.binding);
        if !state.peers.contains_key(&key) && state.peers.len() >= MAX_PEERS {
            return Err("Fabric peer capability cache limit reached".to_string());
        }
        state
            .probes
            .remove(&disclosure.nonce);
        state.peers.insert(
            key,
            (
                CapabilityMessage {
                    nonce: disclosure.nonce,
                    capabilities: negotiated.clone(),
                },
                now + PEER_TTL,
            ),
        );
        drop(state);
        self.changed.notify_waiters();
        Ok(negotiated)
    }

    pub fn agreement(
        &self,
        binding: &StreamBinding,
        now: Instant,
    ) -> Option<CapabilityMessage> {
        let mut state = self.state.lock().ok()?;
        state
            .peers
            .retain(|_, (_, deadline)| *deadline > now);
        state
            .peers
            .get(&PeerKey::from(binding))
            .map(|(agreement, _)| agreement.clone())
    }

    /// Drops the cached agreement with this peer when it is still the one
    /// negotiated under `nonce`, so the next request negotiates again. The peer
    /// refused a stream under it, for example after a restart cleared its offers.
    pub fn forget(
        &self,
        binding: &StreamBinding,
        nonce: Uuid,
    ) {
        if let Ok(mut state) = self.state.lock() {
            let key = PeerKey::from(binding);
            if state
                .peers
                .get(&key)
                .is_some_and(|(agreement, _)| agreement.nonce == nonce)
            {
                state.peers.remove(&key);
            }
        }
    }

    #[cfg(test)]
    pub fn get(
        &self,
        binding: &StreamBinding,
        now: Instant,
    ) -> Option<StreamCapabilities> {
        self.agreement(binding, now)
            .map(|agreement| agreement.capabilities)
    }

    pub async fn wait(
        &self,
        binding: &StreamBinding,
        nonce: Uuid,
        deadline: tokio::time::Instant,
    ) -> Result<CapabilityMessage, String> {
        let _probe = ProbeWait { peers: self, nonce };
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(agreement) = self.agreement(binding, Instant::now())
                && agreement.nonce == nonce
            {
                return Ok(agreement);
            }
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "Fabric capabilities are unavailable")?;
                let probe = state
                    .probes
                    .get(&nonce)
                    .ok_or("Fabric capability probe was cancelled")?;
                if probe.deadline <= Instant::now() || PeerKey::from(&probe.binding) != PeerKey::from(binding) {
                    return Err("Fabric capability probe is expired or mismatched".to_string());
                }
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| "Fabric capability probe timed out")?;
        }
    }

    pub fn cancel_probe(
        &self,
        nonce: Uuid,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.probes.remove(&nonce);
        }
        self.changed.notify_waiters();
    }

    pub fn remove_listener(
        &self,
        connection_point_id: &str,
        instance_id: &str,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state
                .probes
                .retain(|_, probe| {
                    probe
                        .binding
                        .connection_point_id
                        != connection_point_id
                        || probe
                            .binding
                            .listener_instance_id
                            != instance_id
                });
            state.peers.retain(|key, _| {
                key.connection_point_id != connection_point_id || key.listener_instance_id != instance_id
            });
            state
                .offers
                .retain(|_, offer| {
                    offer
                        .binding
                        .connection_point_id
                        != connection_point_id
                        || offer
                            .binding
                            .listener_instance_id
                            != instance_id
                });
        }
        self.changed.notify_waiters();
    }
}

struct ProbeWait<'peers> {
    peers: &'peers PeerCapabilities,
    nonce: Uuid,
}

impl Drop for ProbeWait<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.peers.state.lock() {
            state
                .probes
                .remove(&self.nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;

    #[test]
    fn subscriptions_require_both_negotiated_stream_capabilities() {
        for request_streams in [false, true] {
            for subscriptions in [false, true] {
                let capabilities = StreamCapabilities::local(request_streams, subscriptions);
                assert_eq!(capabilities.permits_mcp_method("tools/call"), request_streams);
                assert_eq!(capabilities.permits_mcp_method("subscriptions/listen"), request_streams && subscriptions);
            }
        }
    }

    #[test]
    fn negotiated_limits_apply_to_each_frame_not_only_the_open() {
        let mut peer = StreamCapabilities::local(true, false);
        peer.max_chunk_bytes = 8;
        peer.max_header_bytes = 16;
        peer.max_frame_bytes = 2048;
        let limits = StreamCapabilities::local(true, false)
            .negotiate(&peer)
            .unwrap();
        let frame = |payload| StreamFrame {
            stream_id: Uuid::new_v4(),
            payload,
        };
        for direction in [true, false] {
            for size in [8, 9] {
                let data = super::super::wire::encode_chunk(&vec![0; size]).unwrap();
                let payload = if direction {
                    FramePayload::RequestData { sequence: 0, offset: 0, data }
                } else {
                    FramePayload::Data { sequence: 0, offset: 0, data }
                };
                assert_eq!(
                    limits
                        .validate_frame(&frame(payload))
                        .is_ok(),
                    size == 8
                );
            }
        }
        for size in [11, 12] {
            let headers = std::collections::BTreeMap::from([("x".to_string(), vec!["a".repeat(size)])]);
            assert_eq!(
                limits
                    .validate_frame(&frame(FramePayload::Start { status: 200, headers }))
                    .is_ok(),
                size == 11
            );
        }
        let large = frame(FramePayload::Data {
            sequence: 0,
            offset: 0,
            data: super::super::wire::encode_chunk(&vec![0; 2048]).unwrap(),
        });
        let mut frame_limits = limits;
        frame_limits.max_chunk_bytes = 2048;
        assert!(
            frame_limits
                .validate_frame(&large)
                .unwrap_err()
                .contains("frame")
        );
    }

    fn binding() -> StreamBinding {
        StreamBinding {
            peer_did: "did:example:remote".into(),
            recipient_did: "did:example:local".into(),
            connection_point_id: "cp".into(),
            listener_instance_id: "instance".into(),
            surface_id: "surface".into(),
        }
    }

    fn message(nonce: Uuid) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp".into(),
            "gateway".into(),
            "capabilities".into(),
            Uuid::new_v4().to_string(),
            Some(nonce.to_string()),
            Some("did:example:remote".into()),
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

    #[test]
    fn capability_negotiation_requires_a_correlated_authenticated_current_peer() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, false));
        let now = Instant::now();
        let probe = peers
            .begin(binding(), now)
            .unwrap();
        let disclosure = CapabilityMessage {
            nonce: probe.nonce,
            capabilities: StreamCapabilities::local(true, true),
        };
        let mut forged = message(probe.nonce);
        forged.from_did = Some("did:example:attacker".into());
        assert!(
            peers
                .accept(&forged, "instance", disclosure.clone(), now)
                .is_err()
        );
        assert!(
            peers
                .get(&binding(), now)
                .is_none()
        );
        assert!(
            peers
                .accept(&message(probe.nonce), "old-instance", disclosure.clone(), now)
                .is_err()
        );
        let negotiated = peers
            .accept(&message(probe.nonce), "instance", disclosure.clone(), now)
            .unwrap();
        assert!(negotiated.request_streams);
        assert!(!negotiated.subscriptions);
        assert_eq!(peers.get(&binding(), now), Some(negotiated));
        assert!(
            peers
                .accept(&message(probe.nonce), "instance", disclosure, now)
                .is_err()
        );
    }

    #[test]
    fn a_refused_stream_forgets_only_the_agreement_it_used() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, true));
        let now = Instant::now();
        let probe = peers
            .begin(binding(), now)
            .unwrap();
        let disclosure = CapabilityMessage {
            nonce: probe.nonce,
            capabilities: StreamCapabilities::local(true, true),
        };
        peers
            .accept(&message(probe.nonce), "instance", disclosure, now)
            .unwrap();
        // A refusal under an older agreement leaves the current one in place.
        peers.forget(&binding(), Uuid::new_v4());
        assert!(
            peers
                .get(&binding(), now)
                .is_some()
        );
        peers.forget(&binding(), probe.nonce);
        assert!(
            peers
                .get(&binding(), now)
                .is_none(),
            "the next request negotiates again"
        );
    }

    #[test]
    fn capability_expiry_or_listener_replacement_removes_support() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, true));
        let now = Instant::now();
        let probe = peers
            .begin(binding(), now)
            .unwrap();
        let disclosure = CapabilityMessage {
            nonce: probe.nonce,
            capabilities: StreamCapabilities::local(true, true),
        };
        assert!(
            peers
                .accept(&message(probe.nonce), "instance", disclosure, now + PROBE_TTL)
                .is_err()
        );
        let probe = peers
            .begin(binding(), now)
            .unwrap();
        peers
            .accept(&message(probe.nonce), "instance", probe.clone(), now)
            .unwrap();
        assert!(
            peers
                .get(&binding(), now + PEER_TTL)
                .is_none()
        );
        let probe = peers
            .begin(binding(), now)
            .unwrap();
        peers
            .accept(&message(probe.nonce), "instance", probe, now)
            .unwrap();
        peers.remove_listener("cp", "old-instance");
        assert!(
            peers
                .get(&binding(), now)
                .is_some()
        );
        peers.remove_listener("cp", "instance");
        assert!(
            peers
                .get(&binding(), now)
                .is_none()
        );
    }

    #[test]
    fn advertised_support_is_intersected_and_incompatible_limits_fail_closed() {
        let local = StreamCapabilities::local(false, false);
        let peer = StreamCapabilities::local(true, true);
        assert_eq!(
            local
                .negotiate(&peer)
                .unwrap(),
            local
        );
        for field in ["version", "max_chunk_bytes", "max_header_bytes", "max_window_bytes", "max_frame_bytes"] {
            let mut invalid = serde_json::to_value(&peer).unwrap();
            invalid[field] = serde_json::json!(0);
            let invalid = serde_json::from_value(invalid).unwrap();
            assert!(
                local
                    .negotiate(&invalid)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn incoming_offer_cannot_be_replayed_or_reused_by_another_peer_or_listener() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, false));
        let now = Instant::now();
        let nonce = Uuid::new_v4();
        let query = CapabilityMessage {
            nonce,
            capabilities: StreamCapabilities::local(true, true),
        };
        let mut message = message(nonce);
        message.didcomm_message_id = nonce.to_string();
        let offered = peers
            .offer(&message, binding(), query.clone(), now)
            .unwrap();
        assert!(
            offered
                .capabilities
                .request_streams
        );
        assert!(
            !offered
                .capabilities
                .subscriptions
        );
        assert_eq!(peers.offered(&binding(), nonce, now), Some((offered.capabilities, now + PEER_TTL)));
        assert!(
            peers
                .get(&binding(), now)
                .is_none()
        );
        assert!(
            peers
                .offer(&message, binding(), query, now)
                .is_err()
        );
        let mut other = binding();
        other.peer_did = "did:example:other".into();
        assert!(
            peers
                .offered(&other, nonce, now)
                .is_none()
        );
        other = binding();
        other.listener_instance_id = "replacement".into();
        assert!(
            peers
                .offered(&other, nonce, now)
                .is_none()
        );
        assert!(
            peers
                .offered(&binding(), nonce, now + PEER_TTL)
                .is_none()
        );
    }

    #[tokio::test]
    async fn capability_waiter_finishes_on_disclosure_timeout_or_listener_loss() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, false));
        let now = Instant::now();
        let peer_binding = binding();
        let probe = peers
            .begin(binding(), now)
            .unwrap();
        let wait = peers.wait(&peer_binding, probe.nonce, tokio::time::Instant::now() + Duration::from_secs(1));
        let disclose = async {
            tokio::task::yield_now().await;
            peers
                .accept(&message(probe.nonce), "instance", probe.clone(), now)
                .unwrap();
        };
        let (result, ()) = tokio::join!(wait, disclose);
        assert_eq!(result.unwrap(), probe);

        let probe = peers
            .begin(binding(), now)
            .unwrap();
        assert!(
            peers
                .wait(&binding(), probe.nonce, tokio::time::Instant::now())
                .await
                .is_err()
        );
        assert!(
            !peers
                .state
                .lock()
                .unwrap()
                .probes
                .contains_key(&probe.nonce)
        );

        let probe = peers
            .begin(binding(), now)
            .unwrap();
        let wait = peers.wait(&peer_binding, probe.nonce, tokio::time::Instant::now() + Duration::from_secs(1));
        let replace = async {
            tokio::task::yield_now().await;
            peers.remove_listener("cp", "instance");
        };
        let (result, ()) = tokio::join!(wait, replace);
        assert!(
            result
                .unwrap_err()
                .contains("cancelled")
        );
    }
}
