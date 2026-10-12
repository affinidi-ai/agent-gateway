use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message as DIDCommMessage;
use affinidi_messaging_sdk::{ATM, config::ATMConfig, messages::compat::UnpackMetadata, profiles::ATMProfile};
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile, secrets_resolver::secrets::Secret};
use async_trait::async_trait;
use base64::Engine;
use reqwest::Method;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use tracing::debug;

use super::mediator::{
    MediatorAuthTestResult, MediatorTrustPingResult, cache_did_document, cache_did_document_in_tdk_state,
    test_authentication, trust_ping,
};
use crate::comm::client::DIDCommContract;
use crate::egress::{EgressError, EgressPolicy, bdd_egress_allowlist, guarded_send_inner};
use crate::http_client::EXTERNAL_TIMEOUT_SECS;

/// Parse an OOB invitation response body into a DIDComm message.
///
/// Accepts the mediator envelope `{ "data": "<base64url DIDComm message>" }`
/// (the shortened-URL form the SDK expects) and a direct DIDComm invitation
/// JSON, matching the forms the trust-registry OOB path accepts.
fn parse_oob_invitation_message(body: &str) -> Result<DIDCommMessage, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("Failed to parse OOB invitation response: {}", e))?;

    if let Some(data) = value
        .get("data")
        .and_then(|v| v.as_str())
    {
        let decoded = decode_oob_base64(data).map_err(|e| format!("Failed to decode OOB invitation data: {}", e))?;
        return serde_json::from_slice::<DIDCommMessage>(&decoded)
            .map_err(|e| format!("Failed to deserialize OOB invitation: {}", e));
    }

    serde_json::from_value::<DIDCommMessage>(value).map_err(|e| format!("Failed to deserialize OOB invitation: {}", e))
}

/// Decode a base64 string, trying URL_SAFE_NO_PAD, URL_SAFE, then STANDARD.
fn decode_oob_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
}

#[derive(Clone)]
pub struct DIDCommClient {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    tdk_state: Arc<TDKSharedState>,
}

#[async_trait]
impl DIDCommContract for DIDCommClient {
    async fn cache_did_document(
        &self,
        did: &str,
        did_document: serde_json::Value,
    ) -> Result<(), String> {
        DIDCommClient::cache_did_document(self, did, did_document).await
    }

    async fn test_mediator_authentication(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorAuthTestResult, String> {
        DIDCommClient::test_mediator_authentication(self, mediator_did, timeout).await
    }

    async fn trust_ping_mediator(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorTrustPingResult, String> {
        DIDCommClient::trust_ping_mediator(self, mediator_did, timeout).await
    }
}

impl DIDCommClient {
    pub async fn new(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        alias: Option<String>,
    ) -> Result<Self, String> {
        Self::new_with_cache_config(did, secrets, mediator_did, None, alias, None).await
    }

    pub async fn new_with_mediator_document(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        mediator_did_document: Option<serde_json::Value>,
        alias: Option<String>,
    ) -> Result<Self, String> {
        Self::new_with_cache_config(did, secrets, mediator_did, mediator_did_document, alias, None).await
    }

    /// A supplied mediator DID document is cached before the ATM profile is
    /// built, so the profile resolves its mediator from it.
    pub async fn new_with_cache_config(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        mediator_did_document: Option<serde_json::Value>,
        alias: Option<String>,
        cache_config: Option<&super::gateway::CacheConfig>,
    ) -> Result<Self, String> {
        let tdk_state = Arc::new(
            TDKSharedState::new(
                crate::gateways::did_cache::headless_tdk_config()
                    .map_err(|e| format!("Failed to build TDK config: {:?}", e))?,
            )
            .await
            .map_err(|e| format!("Failed to create TDK shared state: {:?}", e))?,
        );
        if let (Some(doc), Some(med_did)) = (mediator_did_document, mediator_did.as_deref()) {
            cache_did_document_in_tdk_state(&tdk_state, med_did, doc).await?;
        }

        let tdk_profile = TDKProfile::new(
            alias
                .as_deref()
                .unwrap_or("didcomm-client"),
            &did,
            None,
            secrets,
        );

        tdk_state
            .add_profile(&tdk_profile)
            .await;

        let config = atm_config(cache_config)?;

        let atm = ATM::new(config, tdk_state.clone())
            .await
            .map_err(|e| format!("Failed to initialize ATM: {}", e))?;

        let profile = ATMProfile::new(&atm, alias, did, mediator_did)
            .await
            .map_err(|e| format!("Failed to create ATM profile: {:?}", e))?;

        Ok(Self {
            atm: Arc::new(atm),
            profile: Arc::new(profile),
            tdk_state,
        })
    }

    pub async fn cache_did_document(
        &self,
        did: &str,
        did_document: serde_json::Value,
    ) -> Result<(), String> {
        cache_did_document(self, did, did_document).await
    }

    pub async fn test_mediator_authentication(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorAuthTestResult, String> {
        test_authentication(self, mediator_did, timeout).await
    }

    pub async fn trust_ping_mediator(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorTrustPingResult, String> {
        trust_ping(self, mediator_did, timeout).await
    }

    pub async fn enable_websocket(&mut self) -> Result<(), String> {
        let profile = self
            .atm
            .profile_add(&self.profile, true)
            .await
            .map_err(|e| format!("Failed to enable WebSocket: {:?}", e))?;
        self.profile = profile;
        Ok(())
    }

    pub async fn register_profile(&mut self) -> Result<(), String> {
        let profile = self
            .atm
            .profile_add(&self.profile, false)
            .await
            .map_err(|e| format!("Failed to register profile: {:?}", e))?;
        self.profile = profile;
        Ok(())
    }

    pub async fn pack_and_send_message(
        &self,
        message: &DIDCommMessage,
        to_did: &str,
        from_did: &str,
    ) -> Result<(), String> {
        let packed = self
            .atm
            .pack_encrypted(message, to_did, Some(from_did), Some(from_did))
            .await
            .map_err(|e| format!("Failed to pack message: {:?}", e))?;

        let forward_via = match self
            .profile
            .inner
            .mediator
            .as_ref()
        {
            Some(mediator) => {
                let recipient_uri = self
                    .recipient_messaging_uri(to_did)
                    .await;
                forward_target(
                    &mediator.did,
                    mediator
                        .rest_endpoint
                        .as_deref(),
                    recipient_uri.as_deref(),
                )
            }
            None => None,
        };
        match forward_via {
            Some(own_mediator_did) => {
                debug!(
                    "Forwarding message {} via own mediator {} to recipient {}",
                    message.id, own_mediator_did, to_did
                );
                self.atm
                    .forward_and_send_message(
                        &self.profile,
                        false,
                        &packed.0,
                        Some(&message.id),
                        own_mediator_did,
                        to_did,
                        None,
                        None,
                        false,
                    )
                    .await
                    .map_err(|e| format!("Failed to send message: {:?}", e))?;
            }
            None => {
                self.atm
                    .send_message(&self.profile, &packed.0, &message.id, false, false)
                    .await
                    .map_err(|e| format!("Failed to send message: {:?}", e))?;
            }
        }

        Ok(())
    }

    /// The `DIDCommMessaging` service URI of the recipient's DID document, or
    /// `None` when it cannot be resolved or has no such service.
    async fn recipient_messaging_uri(
        &self,
        to_did: &str,
    ) -> Option<String> {
        let resolved = match self
            .tdk_state
            .did_resolver()
            .resolve(to_did)
            .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                debug!("Could not resolve {} to choose a route; sending directly: {:?}", to_did, e);
                return None;
            }
        };
        let doc = serde_json::to_value(&resolved.doc).ok()?;
        messaging_service_uri(&doc)
    }

    pub async fn live_stream_next(
        &self,
        timeout: Duration,
        auto_delete: bool,
    ) -> Result<Option<(DIDCommMessage, Box<UnpackMetadata>)>, String> {
        self.atm
            .message_pickup()
            .live_stream_next(&self.profile, Some(timeout), auto_delete)
            .await
            .map_err(|e| format!("live_stream_next failed: {:?}", e))
    }

    pub async fn preflight_check(
        &self,
        timeout: Duration,
    ) -> Result<(), String> {
        let result = tokio::time::timeout(
            timeout,
            self.atm
                .message_pickup()
                .send_status_request(&self.profile, true, None),
        )
        .await;

        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Pre-flight status check failed: {:?}", e)),
            Err(_elapsed) => Err(format!("Pre-flight timed out after {:?}", timeout)),
        }
    }

    pub fn atm(&self) -> &Arc<ATM> {
        &self.atm
    }

    pub fn profile(&self) -> &Arc<ATMProfile> {
        &self.profile
    }

    pub fn tdk_state(&self) -> &Arc<TDKSharedState> {
        &self.tdk_state
    }

    /// Retrieve an OOB invitation from a URL.
    ///
    /// The URL is attacker-influenceable (it is posted to `connect-via-oob`), so
    /// the fetch goes through the shared SSRF egress guard ([`EgressPolicy::Strict`]):
    /// the host is validated, resolved once, pinned to that vetted address, and
    /// every redirect hop is re-validated. A loopback/private/link-local/metadata
    /// target — or a redirect to one — fails closed instead of being fetched.
    pub async fn retrieve_oob_invite(url: &str) -> Result<DIDCommMessage, String> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let response = match guarded_send_inner(
            Method::GET,
            url,
            headers,
            None,
            EgressPolicy::Strict,
            Duration::from_secs(EXTERNAL_TIMEOUT_SECS),
            bdd_egress_allowlist().as_deref(),
        )
        .await
        {
            Ok(response) => response,
            Err(EgressError::Blocked(reason)) => {
                tracing::warn!("OOB invitation fetch blocked by egress policy for {}: {}", url, reason);
                return Err("OOB URL blocked by egress policy".to_string());
            }
            Err(other) => return Err(format!("Failed to retrieve OOB invitation from {}: {}", url, other)),
        };

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read OOB invitation response body: {}", e))?;
        if !status.is_success() {
            return Err(format!("OOB invitation fetch failed with status {}", status));
        }

        parse_oob_invitation_message(&body)
    }
}

/// The ATM configuration every gateway DIDComm client uses. It keeps the SDK's
/// default unpack policy: authcrypt-only envelopes whose `from` must equal the
/// authcrypt sender, so a received message's `from` is the authenticated sender
/// that the listener's mediator and active-peer checks rely on.
pub(crate) fn atm_config(cache_config: Option<&super::gateway::CacheConfig>) -> Result<ATMConfig, String> {
    let mut builder = ATMConfig::builder();
    if let Some(cfg) = cache_config {
        builder = builder
            .with_fetch_cache_limit_count(cfg.inbound_cache_count)
            .with_fetch_cache_limit_bytes(cfg.inbound_cache_bytes);
    }
    builder
        .build()
        .map_err(|e| format!("Failed to build ATM config: {}", e))
}

/// The mediator to send a `routing/2.0/forward` through, or `None` to send
/// directly.
///
/// A recipient whose `DIDCommMessaging` service names another mediator is
/// reached through our own mediator, which relays it on. When the recipient
/// shares our mediator, or the route cannot be told, the message goes
/// directly. URLs are compared by host and port, since connection point DIDs
/// carry the mediator's origin while the profile carries its REST endpoint.
/// Our mediator is known by both its REST endpoint and the origin derived from
/// its `did:web`, because connection point DIDs may carry either.
fn forward_target<'a>(
    own_mediator_did: &'a str,
    own_rest_endpoint: Option<&str>,
    recipient_uri: Option<&str>,
) -> Option<&'a str> {
    let recipient_uri = recipient_uri?;
    if recipient_uri.starts_with("did:") {
        return (recipient_uri != own_mediator_did).then_some(own_mediator_did);
    }
    let recipient = endpoint_authority(recipient_uri)?;
    let derived = crate::gateways::connection_points::extract_mediator_url(own_mediator_did)
        .ok()
        .and_then(|url| endpoint_authority(&url));
    let own: Vec<(String, u16)> = own_rest_endpoint
        .and_then(endpoint_authority)
        .into_iter()
        .chain(derived)
        .collect();
    if own.is_empty() || own.contains(&recipient) {
        return None;
    }
    Some(own_mediator_did)
}

fn endpoint_authority(uri: &str) -> Option<(String, u16)> {
    let url = url::Url::parse(uri).ok()?;
    let host = url
        .host_str()?
        .to_ascii_lowercase();
    Some((host, url.port_or_known_default()?))
}

/// The first `DIDCommMessaging` service endpoint URI in a DID document.
fn messaging_service_uri(doc: &serde_json::Value) -> Option<String> {
    let services = doc
        .get("service")?
        .as_array()?;
    services
        .iter()
        .filter(|service| match service.get("type") {
            Some(serde_json::Value::String(kind)) => kind == "DIDCommMessaging",
            Some(serde_json::Value::Array(kinds)) => kinds
                .iter()
                .any(|kind| kind.as_str() == Some("DIDCommMessaging")),
            _ => false,
        })
        .find_map(|service| endpoint_uri(service.get("serviceEndpoint")?))
}

fn endpoint_uri(endpoint: &serde_json::Value) -> Option<String> {
    match endpoint {
        serde_json::Value::String(uri) => Some(uri.clone()),
        serde_json::Value::Object(map) => map
            .get("uri")?
            .as_str()
            .map(str::to_string),
        serde_json::Value::Array(entries) => entries
            .iter()
            .find_map(endpoint_uri),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    /// The listener trusts `message.from` only because the SDK refuses every
    /// envelope that is not authcrypt and every `from` that differs from the
    /// authcrypt sender. Pin that, so an SDK upgrade cannot relax it silently.
    #[test]
    fn received_messages_are_authcrypt_only_with_a_sender_bound_from() {
        use affinidi_messaging_sdk::config::MessageWrappingType;

        let config = atm_config(None).unwrap();
        let policy = config.unpack_policy();
        assert!(policy.validate_addressing_consistency);
        for wrapping in [
            MessageWrappingType::AuthcryptPlaintext,
            MessageWrappingType::AuthcryptSignPlaintext,
            MessageWrappingType::AnoncryptAuthcryptPlaintext,
        ] {
            assert!(policy.accepts(wrapping), "{wrapping:?}");
        }
        for wrapping in [
            MessageWrappingType::Plaintext,
            MessageWrappingType::SignedPlaintext,
            MessageWrappingType::AnoncryptPlaintext,
            MessageWrappingType::AnoncryptSignPlaintext,
        ] {
            assert!(!policy.accepts(wrapping), "{wrapping:?}");
        }
    }

    use super::*;

    fn sample_invitation() -> DIDCommMessage {
        DIDCommMessage::build(
            "test-invite-id".to_string(),
            "https://didcomm.org/out-of-band/2.0/invitation".to_string(),
            serde_json::json!({}),
        )
        .from("did:example:inviter".to_string())
        .finalize()
    }

    #[test]
    fn parse_oob_invitation_message_accepts_envelope() {
        let msg = sample_invitation();
        let msg_json = serde_json::to_string(&msg).unwrap();
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(msg_json.as_bytes());
        let body = serde_json::json!({ "data": data }).to_string();

        let parsed = parse_oob_invitation_message(&body).expect("envelope parses");
        assert_eq!(parsed.id, "test-invite-id");
        assert_eq!(parsed.from.as_deref(), Some("did:example:inviter"));
    }

    #[test]
    fn parse_oob_invitation_message_accepts_direct_json() {
        let msg = sample_invitation();
        let body = serde_json::to_string(&msg).unwrap();

        let parsed = parse_oob_invitation_message(&body).expect("direct JSON parses");
        assert_eq!(parsed.id, "test-invite-id");
    }

    #[test]
    fn parse_oob_invitation_message_rejects_garbage() {
        assert!(parse_oob_invitation_message("not json").is_err());
    }

    #[tokio::test]
    async fn retrieve_oob_invite_blocks_loopback() {
        let err = DIDCommClient::retrieve_oob_invite("http://127.0.0.1:9/oob?_oobid=x")
            .await
            .expect_err("loopback must be blocked");
        assert!(err.contains("blocked by egress policy"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn retrieve_oob_invite_blocks_cloud_metadata() {
        let err = DIDCommClient::retrieve_oob_invite("http://169.254.169.254/latest/meta-data/")
            .await
            .expect_err("metadata must be blocked");
        assert!(err.contains("blocked by egress policy"), "unexpected error: {err}");
    }

    const UNREACHABLE_MEDIATOR_DID: &str = "did:web:localhost%3A1";

    fn unreachable_mediator_document() -> serde_json::Value {
        serde_json::json!({
            "id": UNREACHABLE_MEDIATOR_DID,
            "service": [{
                "id": format!("{UNREACHABLE_MEDIATOR_DID}#didcomm"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "uri": "https://localhost:1/mediator/v1", "accept": ["didcomm/v2"] }]
            }]
        })
    }

    #[tokio::test]
    async fn a_supplied_mediator_document_is_cached_before_the_profile_resolves_its_mediator() {
        let client = super::DIDCommClient::new_with_mediator_document(
            "did:example:connection-point".to_string(),
            Vec::new(),
            Some(UNREACHABLE_MEDIATOR_DID.to_string()),
            Some(unreachable_mediator_document()),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            client
                .profile()
                .get_mediator_rest_endpoint()
                .as_deref(),
            Some("https://localhost:1/mediator/v1")
        );
    }

    #[tokio::test]
    async fn without_a_supplied_document_an_unresolvable_mediator_leaves_the_profile_without_one() {
        let client = super::DIDCommClient::new(
            "did:example:connection-point".to_string(),
            Vec::new(),
            Some(UNREACHABLE_MEDIATOR_DID.to_string()),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            client
                .profile()
                .get_mediator_rest_endpoint(),
            None
        );
    }

    const OWN_MEDIATOR: &str = "did:web:m1.example.com";

    #[test]
    fn a_recipient_on_our_mediator_is_sent_directly() {
        assert_eq!(
            super::forward_target(
                OWN_MEDIATOR,
                Some("https://m1.example.com/mediator/v1"),
                Some("https://m1.example.com")
            ),
            None
        );
    }

    #[test]
    fn a_recipient_on_another_mediator_is_forwarded_through_ours() {
        assert_eq!(
            super::forward_target(
                OWN_MEDIATOR,
                Some("https://m1.example.com/mediator/v1"),
                Some("https://m2.example.com")
            ),
            Some(OWN_MEDIATOR)
        );
    }

    #[test]
    fn mediators_on_one_host_but_different_ports_are_different_mediators() {
        assert_eq!(
            super::forward_target(OWN_MEDIATOR, Some("http://127.0.0.1:7037"), Some("http://127.0.0.1:7038")),
            Some(OWN_MEDIATOR)
        );
        assert_eq!(
            super::forward_target(
                OWN_MEDIATOR,
                Some("http://127.0.0.1:7037/mediator/v1"),
                Some("http://127.0.0.1:7037")
            ),
            None
        );
    }

    #[test]
    fn a_did_service_uri_is_compared_with_our_mediator_did() {
        assert_eq!(super::forward_target(OWN_MEDIATOR, None, Some(OWN_MEDIATOR)), None);
        assert_eq!(super::forward_target(OWN_MEDIATOR, None, Some("did:web:m2.example.com")), Some(OWN_MEDIATOR));
    }

    #[test]
    fn without_a_known_route_the_message_is_sent_directly() {
        assert_eq!(super::forward_target(OWN_MEDIATOR, Some("https://m1.example.com"), None), None);
        assert_eq!(super::forward_target(OWN_MEDIATOR, Some("https://m1.example.com"), Some("not a url")), None);
        assert_eq!(super::forward_target("did:peer:2.mediator", None, Some("https://m2.example.com")), None);
    }

    #[test]
    fn a_recipient_minted_with_our_did_web_origin_is_on_our_mediator() {
        let own = "did:web:localhost%3A7037";
        assert_eq!(super::forward_target(own, Some("http://mediator:7037"), Some("https://localhost:7037")), None);
        assert_eq!(super::forward_target(own, Some("http://mediator:7037"), Some("http://mediator:7037")), None);
        assert_eq!(super::forward_target(own, Some("http://mediator:7037"), Some("http://other:7037")), Some(own));
    }

    #[test]
    fn our_rest_endpoint_falls_back_to_the_did_web_origin() {
        assert_eq!(super::forward_target(OWN_MEDIATOR, None, Some("https://m1.example.com")), None);
        assert_eq!(super::forward_target(OWN_MEDIATOR, None, Some("https://m2.example.com")), Some(OWN_MEDIATOR));
    }

    #[test]
    fn the_messaging_service_uri_is_read_from_each_endpoint_shape() {
        let object = serde_json::json!({ "service": [
            { "type": "LinkedDomains", "serviceEndpoint": "https://example.com" },
            { "type": "DIDCommMessaging", "serviceEndpoint": { "uri": "https://m2.example.com" } }
        ]});
        let array = serde_json::json!({ "service": [
            { "type": ["DIDCommMessaging"], "serviceEndpoint": [{ "uri": "did:web:m2.example.com" }] }
        ]});
        let string = serde_json::json!({ "service": [
            { "type": "DIDCommMessaging", "serviceEndpoint": "https://m2.example.com" }
        ]});

        assert_eq!(super::messaging_service_uri(&object).as_deref(), Some("https://m2.example.com"));
        assert_eq!(super::messaging_service_uri(&array).as_deref(), Some("did:web:m2.example.com"));
        assert_eq!(super::messaging_service_uri(&string).as_deref(), Some("https://m2.example.com"));
        assert_eq!(super::messaging_service_uri(&serde_json::json!({})), None);
    }
}
