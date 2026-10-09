use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::registry::{RegisterError, StreamBinding};
use super::share::{ShareOwner, SharedTable};
use super::wire::{
    FramePayload, MAX_CHUNK_BYTES, MAX_FRAME_BYTES, MAX_HEADER_BYTES, MAX_WINDOW_BYTES, StreamFrame, decode_chunk,
};
use crate::gateways::connection_points::messages::ReceivedMessage;

/// Capability probes this gateway may have in flight to its peers.
const MAX_PROBES: usize = 256;
/// Capability offers this gateway may hold for its peers.
const MAX_OFFERS: usize = 256;
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
    /// What the peer disclosed for this probe. Kept for the probe's own waiter,
    /// as a concurrent probe to the same peer may replace the cached agreement.
    agreement: Option<CapabilityMessage>,
}

struct InboundOffer {
    binding: StreamBinding,
    capabilities: StreamCapabilities,
    deadline: Instant,
}

struct PeerState {
    probes: SharedTable<Uuid, PendingProbe>,
    peers: HashMap<PeerKey, (CapabilityMessage, Instant)>,
    offers: SharedTable<Uuid, InboundOffer>,
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
                probes: SharedTable::new(MAX_PROBES),
                peers: HashMap::new(),
                offers: SharedTable::new(MAX_OFFERS),
            }),
            changed: tokio::sync::Notify::new(),
        }
    }

    /// Answers a peer's capability query with an offer. A peer may hold several
    /// live offers, so its concurrent first requests each negotiate, up to its
    /// share of the offer table; `tenant_id` is the tenant owning its record.
    pub fn offer(
        &self,
        message: &ReceivedMessage,
        binding: StreamBinding,
        query: CapabilityMessage,
        tenant_id: Option<String>,
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
        {
            return Err("Fabric capability offer is a duplicate".to_string());
        }
        let owner = ShareOwner {
            peer_did: binding.peer_did.clone(),
            tenant_id,
        };
        state
            .offers
            .insert(
                query.nonce,
                owner,
                InboundOffer {
                    binding,
                    capabilities: capabilities.clone(),
                    deadline: now + PEER_TTL,
                },
            )
            .map_err(|limit| {
                tracing::warn!(
                    peer_did = %message.from_did.as_deref().unwrap_or_default(),
                    cap = limit.as_str(),
                    "Fabric capability offer cap reached"
                );
                "Fabric capability offer capacity is unavailable".to_string()
            })?;
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

    /// Starts negotiating with a peer, within the peer's share of the probe
    /// table; `tenant_id` is the tenant owning the peer's record. A full share
    /// is `CapacityReached`, so the caller is told to retry.
    pub fn begin(
        &self,
        binding: StreamBinding,
        tenant_id: Option<String>,
        now: Instant,
    ) -> Result<CapabilityMessage, RegisterError> {
        let nonce = Uuid::new_v4();
        binding.validate(nonce)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Fabric peer capabilities are unavailable")?;
        state
            .probes
            .retain(|_, probe| probe.deadline > now);
        let owner = ShareOwner {
            peer_did: binding.peer_did.clone(),
            tenant_id,
        };
        state
            .probes
            .insert(
                nonce,
                owner,
                PendingProbe {
                    binding,
                    deadline: now + PROBE_TTL,
                    agreement: None,
                },
            )
            .map_err(|limit| {
                tracing::warn!(cap = limit.as_str(), "Fabric capability probe cap reached");
                RegisterError::CapacityReached("Fabric capability probe limit reached")
            })?;
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
        if probe.agreement.is_some() {
            return Err("Fabric capability disclosure was already accepted".to_string());
        }
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
        let agreement = CapabilityMessage {
            nonce: disclosure.nonce,
            capabilities: negotiated.clone(),
        };
        if let Some(probe) = state
            .probes
            .get_mut(&disclosure.nonce)
        {
            probe.agreement = Some(agreement.clone());
        }
        state
            .peers
            .insert(key, (agreement, now + PEER_TTL));
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
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "Fabric capabilities are unavailable")?;
                let probe = state
                    .probes
                    .get(&nonce)
                    .ok_or("Fabric capability probe was cancelled")?;
                if PeerKey::from(&probe.binding) != PeerKey::from(binding) {
                    return Err("Fabric capability probe is expired or mismatched".to_string());
                }
                if let Some(agreement) = &probe.agreement {
                    return Ok(agreement.clone());
                }
                if probe.deadline <= Instant::now() {
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
            .begin(binding(), None, now)
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
            .begin(binding(), None, now)
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
            .begin(binding(), None, now)
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
            .begin(binding(), None, now)
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
            .begin(binding(), None, now)
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
            .offer(&message, binding(), query.clone(), None, now)
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
                .offer(&message, binding(), query, None, now)
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
            .begin(binding(), None, now)
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
            .begin(binding(), None, now)
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
            .begin(binding(), None, now)
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

    fn query_from(
        peer: &str,
        nonce: Uuid,
    ) -> (ReceivedMessage, StreamBinding, CapabilityMessage) {
        let mut message = message(nonce);
        message.from_did = Some(format!("did:example:{peer}"));
        message.didcomm_message_id = nonce.to_string();
        let mut binding = binding();
        binding.peer_did = format!("did:example:{peer}");
        let query = CapabilityMessage {
            nonce,
            capabilities: StreamCapabilities::local(true, true),
        };
        (message, binding, query)
    }

    /// Offers `attempts` queries from `peer` and returns the nonces offered.
    fn offer_queries(
        peers: &PeerCapabilities,
        peer: &str,
        tenant_id: Option<&str>,
        attempts: usize,
        now: Instant,
    ) -> Vec<Uuid> {
        (0..attempts)
            .filter_map(|_| {
                let (message, binding, query) = query_from(peer, Uuid::new_v4());
                peers
                    .offer(&message, binding, query.clone(), tenant_id.map(str::to_string), now)
                    .ok()
                    .map(|_| query.nonce)
            })
            .collect()
    }

    #[test]
    fn one_peer_cannot_fill_the_offer_table() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, true));
        let now = Instant::now();

        let alpha_offers = offer_queries(&peers, "alpha", None, MAX_OFFERS + 1, now);
        assert_eq!(alpha_offers.len(), MAX_OFFERS / 8, "a peer holds at most its share");
        let (_, alpha, _) = query_from("alpha", Uuid::new_v4());
        assert!(
            alpha_offers
                .iter()
                .all(|nonce| peers
                    .offered(&alpha, *nonce, now)
                    .is_some()),
            "every offer within the share stays live, so concurrent first requests each negotiate"
        );

        let (message, bravo, query) = query_from("bravo", Uuid::new_v4());
        let offered = peers
            .offer(&message, bravo.clone(), query.clone(), None, now)
            .expect("another peer is still offered capabilities");
        assert_eq!(offered.nonce, query.nonce);
        assert!(
            peers
                .offered(&bravo, query.nonce, now)
                .is_some()
        );
    }

    #[test]
    fn one_tenants_peers_cannot_fill_the_offer_table() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, true));
        let now = Instant::now();
        let held: usize = (0..8)
            .map(|peer| offer_queries(&peers, &format!("tenant-a-{peer}"), Some("tenant-a"), MAX_OFFERS, now).len())
            .sum();
        assert_eq!(held, MAX_OFFERS / 2, "the peers of one tenant hold at most the tenant's share");
        assert!(offer_queries(&peers, "tenant-a-late", Some("tenant-a"), 1, now).is_empty());
        assert_eq!(offer_queries(&peers, "tenant-b-0", Some("tenant-b"), 1, now).len(), 1);
        assert_eq!(offer_queries(&peers, "appliance", None, 1, now).len(), 1);
    }

    #[test]
    fn one_peer_cannot_fill_the_probe_table() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, true));
        let now = Instant::now();
        let refusal = (0..=MAX_PROBES).find_map(|_| {
            peers
                .begin(binding(), None, now)
                .err()
        });
        assert_eq!(
            refusal,
            Some(RegisterError::CapacityReached("Fabric capability probe limit reached")),
            "a full share is a capacity refusal, so the caller is told to retry"
        );
        assert_eq!(
            peers
                .state
                .lock()
                .unwrap()
                .probes
                .len(),
            MAX_PROBES / 8
        );

        let mut other = binding();
        other.peer_did = "did:example:other".into();
        assert!(
            peers
                .begin(other, None, now)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn concurrent_first_requests_to_one_peer_each_keep_their_own_agreement() {
        let peers = PeerCapabilities::new(StreamCapabilities::local(true, true));
        let now = Instant::now();
        let first = peers
            .begin(binding(), None, now)
            .unwrap();
        let second = peers
            .begin(binding(), None, now)
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let (first_binding, second_binding) = (binding(), binding());
        let disclose = async {
            tokio::task::yield_now().await;
            peers
                .accept(&message(first.nonce), "instance", first.clone(), now)
                .unwrap();
            peers
                .accept(&message(second.nonce), "instance", second.clone(), now)
                .unwrap();
        };
        let (first_agreement, second_agreement, ()) = tokio::join!(
            peers.wait(&first_binding, first.nonce, deadline),
            peers.wait(&second_binding, second.nonce, deadline),
            disclose
        );
        assert_eq!(
            first_agreement
                .expect("the first request is not cancelled by the second disclosure")
                .nonce,
            first.nonce
        );
        assert_eq!(
            second_agreement
                .unwrap()
                .nonce,
            second.nonce
        );
        assert_eq!(
            peers
                .agreement(&binding(), now)
                .map(|agreement| agreement.nonce),
            Some(second.nonce),
            "the latest agreement serves the next request"
        );
        assert!(
            peers
                .accept(&message(first.nonce), "instance", first, now)
                .is_err(),
            "a disclosure is accepted once"
        );
    }
}
