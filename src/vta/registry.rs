//! Runtime connector lifecycle for [`VtaConnection`] records.
//!
//! A record describes a VTA; this registry turns it into a live
//! [`CredentialAuthority`] and keeps that connector alive across requests. The
//! point is hot reload: adding, editing or disabling a connection takes effect
//! without a restart, because the registry rebuilds the connector on next use
//! instead of the process pinning one at boot.
//!
//! ## Fail closed, always
//!
//! A connection that is missing, disabled, invalid or unbuildable produces an
//! **error**, never a fallback to local signing. Silently signing with a
//! different key than the operator mapped would attribute tokens to an issuer
//! they did not choose — strictly worse than refusing to sign.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::identity::authority::CredentialAuthority;
use crate::secrets::SecretsStore;
use crate::vta::VtaError;
use crate::vta::authority::VtaCredentialAuthority;
use crate::vta::client::VtaRestClient;
use crate::vta::connections::{BOOTSTRAP_CONNECTION_ID, VtaConnection, VtaConnectionStorage, VtaConnectionTransport};
use crate::vta::control_key::{ControlKey, SignerKeyProvider};

/// Cache key for a connector: a connection plus the key it signs with.
///
/// The record separator cannot occur in a connection id or a key id, so no
/// two distinct pairs can collide on one entry.
fn connector_cache_key(
    connection_id: &str,
    key_id: Option<&str>,
) -> String {
    format!("{}{}", cache_key_prefix(connection_id), key_id.unwrap_or(""))
}

/// Prefix matching every cached connector for a connection, whatever key.
fn cache_key_prefix(connection_id: &str) -> String {
    format!("{connection_id}\u{1e}")
}

/// Builds and caches one connector per enabled connection record.
pub struct VtaConnectionRegistry {
    store: Arc<dyn VtaConnectionStorage>,
    secrets: Option<Arc<dyn SecretsStore>>,
    /// The connector the bootstrap `[vta]` block built. Its control key comes
    /// from `auth_key_source` rather than the secrets store, so it cannot be
    /// rebuilt from its record and is kept as-is.
    bootstrap: Option<Arc<dyn CredentialAuthority>>,
    /// The client behind that same bootstrap connector, for callers that talk
    /// to the VTA without being a [`CredentialAuthority`] — agent holder
    /// proofs, which go through `proofs/attach`. Shared rather than re-dialled
    /// because the VTA supersedes an earlier session when a second one opens
    /// for the same control DID.
    bootstrap_client: Option<Arc<VtaRestClient>>,
    /// Per-call deadline and concurrency cap, inherited from `[vta]` so one
    /// appliance-wide resilience policy applies to every connection (VTA-04).
    timeout: Duration,
    max_concurrent: usize,
    /// Mediator channel for the DIDComm carrier (VTA-27). `None` when no
    /// mediator is wired, in which case a DIDComm connection fails closed
    /// rather than falling back to an address the operator did not publish.
    didcomm: Option<Arc<dyn crate::vta::transport::DidCommChannel>>,
    cache: RwLock<HashMap<String, Arc<dyn CredentialAuthority>>>,
    /// Clients cached on the same terms as connectors, and invalidated
    /// together, so an edited or disabled connection stops being reachable by
    /// either path at the same moment.
    client_cache: RwLock<HashMap<String, Arc<VtaRestClient>>>,
}

impl VtaConnectionRegistry {
    pub fn new(
        store: Arc<dyn VtaConnectionStorage>,
        secrets: Option<Arc<dyn SecretsStore>>,
        bootstrap: Option<Arc<dyn CredentialAuthority>>,
        bootstrap_client: Option<Arc<VtaRestClient>>,
        timeout: Duration,
        max_concurrent: usize,
    ) -> Self {
        Self {
            store,
            secrets,
            bootstrap,
            bootstrap_client,
            timeout,
            max_concurrent,
            didcomm: None,
            cache: RwLock::new(HashMap::new()),
            client_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Attach the mediator channel that carries Trust Tasks over DIDComm
    /// (VTA-27), enabling connections whose VTA has no reachable address.
    #[allow(dead_code)]
    pub fn with_didcomm(
        mut self,
        channel: Arc<dyn crate::vta::transport::DidCommChannel>,
    ) -> Self {
        self.didcomm = Some(channel);
        self
    }

    /// The connector for `connection_id`, signing with `key_id` when one is
    /// named and the connection's active key otherwise.
    ///
    /// The key is **not** checked against the connection record. A record
    /// tracks one active key for rotation; the agent holds every key minted in
    /// the context, and a surface may legitimately name one of those. An
    /// unknown key is refused by the agent, which is the authority on what it
    /// holds — and that refusal surfaces, where quietly substituting the active
    /// key would hand the caller a different key than it asked for.
    pub async fn authority_for_key(
        &self,
        connection_id: &str,
        key_id: Option<&str>,
    ) -> Result<Arc<dyn CredentialAuthority>, VtaError> {
        let cache_key = connector_cache_key(connection_id, key_id);
        if let Some(hit) = self
            .cache
            .read()
            .await
            .get(&cache_key)
            .cloned()
        {
            return Ok(hit);
        }

        let connection = self
            .store
            .get(connection_id)
            .await
            .map_err(|e| VtaError::Config(format!("VTA connection lookup failed: {e}")))?
            .ok_or_else(|| VtaError::Config(format!("VTA connection `{connection_id}` does not exist")))?;

        let authority = self
            .build_for_key(&connection, key_id)
            .await?;
        self.cache
            .write()
            .await
            .insert(cache_key, Arc::clone(&authority));
        Ok(authority)
    }

    /// The client for a named connection, so a caller that is not a
    /// [`CredentialAuthority`] can still reach the right VTA.
    ///
    /// Resolved through the same record and the same usability rules as
    /// [`authority`](Self::authority): a disabled, unpaired or invalid
    /// connection fails here too, rather than being reachable by the back door.
    pub async fn client(
        &self,
        connection_id: &str,
    ) -> Result<Arc<VtaRestClient>, VtaError> {
        if let Some(hit) = self
            .client_cache
            .read()
            .await
            .get(connection_id)
            .cloned()
        {
            return Ok(hit);
        }

        let connection = self
            .store
            .get(connection_id)
            .await
            .map_err(|e| VtaError::Config(format!("VTA connection lookup failed: {e}")))?
            .ok_or_else(|| VtaError::Config(format!("VTA connection `{connection_id}` does not exist")))?;

        let client = self
            .build_client(&connection)
            .await?;
        self.client_cache
            .write()
            .await
            .insert(connection_id.to_string(), Arc::clone(&client));
        Ok(client)
    }

    /// Drop the cached connector for `connection_id` so the next use rebuilds
    /// it from the current record. Called whenever a record is written or
    /// removed, which is what makes edits take effect without a restart.
    pub async fn invalidate(
        &self,
        connection_id: &str,
    ) {
        // Every key variant for this connection, not just the default one: the
        // cache is keyed by connection *and* key, so dropping one entry would
        // leave the others serving a record that has changed.
        let prefix = cache_key_prefix(connection_id);
        self.cache
            .write()
            .await
            .retain(|k, _| !k.starts_with(&prefix));
        // Both caches, or a disabled connection would stay reachable through
        // whichever one was missed.
        self.client_cache
            .write()
            .await
            .remove(connection_id);
    }

    /// Authenticate against `connection`'s VTA and report what was observed,
    /// for the pairing state machine to judge (VTA-24).
    ///
    /// Deliberately returns the observation rather than a verdict: deciding
    /// whether the grant is acceptable belongs in one place
    /// (`pairing::apply_verification`), so the API, a future scheduled probe
    /// and the tests cannot drift apart on what "verified" means.
    pub async fn verify(
        &self,
        connection: &VtaConnection,
    ) -> Result<crate::vta::pairing::VerificationOutcome, VtaError> {
        if !connection.enabled {
            return Err(VtaError::Config(format!("VTA connection `{}` is disabled", connection.id)));
        }
        connection
            .validate()
            .map_err(|e| VtaError::Config(format!("VTA connection `{}` is not usable: {e}", connection.id)))?;

        let control_key = self
            .control_key(connection)
            .await?;
        let client = VtaRestClient::new(
            &connection.endpoint,
            &connection.vta_did,
            control_key,
            self.timeout,
            self.max_concurrent,
            None,
        )?;
        // The session token the VTA mints is the evidence: it states the role
        // and contexts the customer actually granted.
        let token = client.access_token().await?;
        Ok(crate::vta::pairing::VerificationOutcome {
            // The client only completes the handshake against the DID it was
            // pinned to, so reaching here means this is the agent that answered.
            observed_vta_did: connection.vta_did.clone(),
            scope: crate::vta::onboarding::GrantScope::from_session_token(&token)?,
        })
    }

    async fn build_for_key(
        &self,
        connection: &VtaConnection,
        key_id: Option<&str>,
    ) -> Result<Arc<dyn CredentialAuthority>, VtaError> {
        // Before any short-circuit: a disabled or invalid record must stop
        // being usable immediately, bootstrap included. Checking after the
        // bootstrap branch would let `enabled = false` be ignored for the one
        // connection every deployment has.
        Self::assert_record_usable(connection)?;

        // The bootstrap record's control key lives in `auth_key_source`, not
        // the secrets store, so its connector is the one `[vta]` already built.
        // It is also exempt from pairing: the operator established it by
        // editing the TOML block, which is the same consent step.
        if connection.is_bootstrap() {
            return self
                .bootstrap
                .clone()
                .ok_or_else(|| {
                    VtaError::Config(format!(
                        "VTA connection `{BOOTSTRAP_CONNECTION_ID}` has no bootstrap connector; is `[vta] enabled` still set?"
                    ))
                });
        }

        // The **cached** client, not a fresh one. A VTA supersedes a control
        // DID's session whenever that DID authenticates again, so a second
        // connector for the same connection evicts the first: provisioning
        // would authenticate, then signing would authenticate, and the next
        // call on the older token got `401 unauthorized: token superseded`.
        // One connection means one session, which is the same reason each
        // connection mints its own control key rather than sharing one.
        let client = self
            .client(&connection.id)
            .await?;

        // The issuer DID defaults to the VTA service DID until onboarding
        // establishes a context-scoped one (VTA-05).
        let issuer_did = connection.vta_did.clone();
        // The key the caller named, else the one `Provision a signing key`
        // recorded as active. A context is **not** a key: passing
        // `default_context_id` here made the agent refuse with "key `<context>`
        // is not within the caller's scope", because the name addressed no key
        // it held.
        let signing_key_id = key_id
            .map(str::to_string)
            .or_else(|| {
                connection
                    .keys
                    .active
                    .as_ref()
                    .map(|k| k.key_id.clone())
            })
            .unwrap_or_default();

        Ok(Arc::new(VtaCredentialAuthority::new(client, issuer_did, signing_key_id, None)))
    }

    /// The dialled client for a connection, before any signing role is put on
    /// top of it.
    ///
    /// Split out because not everything that talks to a VTA is a
    /// [`CredentialAuthority`]: agent holder proofs go through
    /// `proofs/attach`, which needs the client itself. Both paths must come
    /// through here so a connection's usability rules — disabled, unpaired,
    /// unvalidated, data-plane isolation — are enforced once, not per caller.
    async fn build_client(
        &self,
        connection: &VtaConnection,
    ) -> Result<Arc<VtaRestClient>, VtaError> {
        Self::assert_record_usable(connection)?;

        // Same exemption as `build`: the bootstrap connection's client is the
        // one `[vta]` already dialled, and re-dialling it would open a second
        // session for the same control DID — which the VTA supersedes, cutting
        // off the first.
        if connection.is_bootstrap() {
            return self
                .bootstrap_client
                .clone()
                .ok_or_else(|| {
                    VtaError::Config(format!(
                        "VTA connection `{BOOTSTRAP_CONNECTION_ID}` has no bootstrap client; is `[vta] enabled` still set?"
                    ))
                });
        }

        // A connection that has not completed pairing has not proved it can
        // sign under the identity the operator chose, so it must not be used
        // (VTA-24). Revoking is therefore immediate: the state alone makes the
        // connection unusable on the next resolution.
        crate::vta::pairing::assert_usable(connection, &connection.pairing)?;

        // Take this VTA off the data plane too (VTA-21): a stored connection
        // can point at a sidecar on a private network, which the forward leg
        // would otherwise happily proxy to.
        crate::vta::isolation::reserve(&connection.endpoint);

        let control_key = self
            .control_key(connection)
            .await?;
        // Per-connection carrier (VTA-27). Everything above the carrier — the
        // signed auth handshake, session caching, resilience, error redaction
        // — is identical, so two connections may use different carriers at the
        // same time without any code path diverging.
        Ok(Arc::new(VtaRestClient::with_transport(
            self.transport_for(connection)?,
            &connection.vta_did,
            control_key,
            self.max_concurrent,
            None,
        )))
    }

    /// Checks every connection must pass, bootstrap included.
    ///
    /// A disabled connection must stop being used immediately — anything still
    /// mapped to it fails here rather than quietly signing somewhere else.
    fn assert_record_usable(connection: &VtaConnection) -> Result<(), VtaError> {
        if !connection.enabled {
            return Err(VtaError::Config(format!("VTA connection `{}` is disabled", connection.id)));
        }
        connection
            .validate()
            .map_err(|e| VtaError::Config(format!("VTA connection `{}` is not usable: {e}", connection.id)))
    }

    /// The carrier this connection's Trust Tasks travel over (VTA-27).
    ///
    /// `didcomm` lets the gateway reach a VTA with **no inbound reachability**
    /// — a home or laptop deployment behind NAT — by addressing it by DID
    /// through a mediator. It requires a mediator channel to be wired; without
    /// one the connection fails closed rather than silently falling back to
    /// HTTPS, which would dial an address the operator deliberately did not
    /// publish.
    fn transport_for(
        &self,
        connection: &VtaConnection,
    ) -> Result<Arc<dyn crate::vta::transport::TrustTaskTransport>, VtaError> {
        match connection.transport {
            VtaConnectionTransport::Https => {
                Ok(Arc::new(crate::vta::transport::HttpsTransport::new(&connection.endpoint, self.timeout)?))
            }
            VtaConnectionTransport::Didcomm => {
                let channel = self
                    .didcomm
                    .clone()
                    .ok_or_else(|| {
                        VtaError::Config(format!(
                            "VTA connection `{}` is configured for DIDComm but no mediator channel is available",
                            connection.id
                        ))
                    })?;
                Ok(Arc::new(crate::vta::transport::DidCommTransport::new(channel, &connection.vta_did, self.timeout)))
            }
            VtaConnectionTransport::Unix => Err(VtaError::Config(format!(
                "VTA connection `{}` selects the `unix` carrier, which is not yet wired",
                connection.id
            ))),
        }
    }

    /// Resolve the connection's Ed25519 control-key seed from the secrets
    /// store. Held by reference so key material never lands in a record file.
    async fn control_key(
        &self,
        connection: &VtaConnection,
    ) -> Result<Arc<dyn SignerKeyProvider>, VtaError> {
        let secret_ref = connection
            .control_key_ref
            .as_deref()
            .ok_or_else(|| VtaError::Config(format!("VTA connection `{}` has no control_key_ref", connection.id)))?;
        let secrets = self
            .secrets
            .as_ref()
            .ok_or_else(|| VtaError::Config("the secrets store is not configured".to_string()))?;
        let secret = secrets
            .get_by_secret_id(secret_ref)
            .await
            .map_err(|e| VtaError::Config(format!("control key lookup failed: {e}")))?
            .ok_or_else(|| VtaError::Config(format!("control key `{secret_ref}` was not found")))?;
        let seed = super::decode_hex_seed(secret.value.trim())?;
        Ok(Arc::new(ControlKey::from_seed(seed)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::connections::{VtaConnectionStatus, VtaConnectionTransport};

    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;

    struct MemoryStore {
        connections: std::sync::Mutex<Vec<VtaConnection>>,
    }

    impl MemoryStore {
        fn new(connections: Vec<VtaConnection>) -> Arc<Self> {
            Arc::new(Self {
                connections: std::sync::Mutex::new(connections),
            })
        }

        fn replace(
            &self,
            connection: VtaConnection,
        ) {
            let mut guard = self
                .connections
                .lock()
                .unwrap();
            guard.retain(|c| c.id != connection.id);
            guard.push(connection);
        }
    }

    #[async_trait]
    impl VtaConnectionStorage for MemoryStore {
        async fn create(
            &self,
            connection: VtaConnection,
        ) -> Result<VtaConnection> {
            self.replace(connection.clone());
            Ok(connection)
        }

        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<VtaConnection>> {
            Ok(self
                .connections
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.id == id)
                .cloned())
        }

        async fn list(&self) -> Result<Vec<VtaConnection>> {
            Ok(self
                .connections
                .lock()
                .unwrap()
                .clone())
        }

        async fn update(
            &self,
            connection: VtaConnection,
        ) -> Result<VtaConnection> {
            self.replace(connection.clone());
            Ok(connection)
        }

        async fn delete(
            &self,
            id: &str,
        ) -> Result<()> {
            self.connections
                .lock()
                .unwrap()
                .retain(|c| c.id != id);
            Ok(())
        }
    }

    struct StubAuthority;

    #[async_trait]
    impl CredentialAuthority for StubAuthority {
        async fn issuer_did(&self) -> Result<String> {
            Ok("did:webvh:bootstrap".to_string())
        }

        async fn issuer_jwks(&self) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "keys": [] }))
        }

        async fn sign_token(
            &self,
            _claims: &serde_json::Value,
        ) -> Result<String> {
            Ok("bootstrap-token".to_string())
        }

        async fn sign_token_typ(
            &self,
            _claims: &serde_json::Value,
            _typ: &str,
        ) -> Result<String> {
            Ok("bootstrap-token".to_string())
        }
    }

    /// Two surfaces on one connection must be able to sign with different
    /// keys. Before this, the `KeyRef`'s `key_id` was discarded and both got
    /// the connection's active key — so an operator who configured separate
    /// keys for isolation silently had none, and only a decoded `kid` would
    /// have shown it.
    #[test]
    fn a_named_key_and_the_default_cache_separately() {
        let with_key = connector_cache_key("vta-a", Some("billing-key"));
        let with_other = connector_cache_key("vta-a", Some("support-key"));
        let default = connector_cache_key("vta-a", None);

        assert_ne!(with_key, with_other, "two keys on one connection must not share a connector");
        assert_ne!(with_key, default, "a named key must not reuse the active-key connector");
    }

    /// A connection id that is a prefix of another must not have its entries
    /// evicted when the shorter one is invalidated.
    #[test]
    fn invalidating_one_connection_does_not_match_a_longer_id() {
        let prefix = cache_key_prefix("vta");
        assert!(!connector_cache_key("vta-a", None).starts_with(&prefix));
        assert!(connector_cache_key("vta", Some("k")).starts_with(&prefix));
    }

    /// The connector must sign with the connection's **active key**, never
    /// its context.
    ///
    /// Both are `String` and both are "a name on the connection", so passing
    /// one for the other compiles and only fails at the agent — which refused
    /// with "key `gwtest` is not within the caller's scope", naming a context
    /// as though it were a key. Nothing in the gateway could have caught that.
    #[test]
    fn the_connector_signs_with_the_active_key_not_the_context() {
        let mut c = connection("vta-a", true);
        c.default_context_id = Some("ctx-not-a-key".to_string());
        c.keys = crate::vta::connections::SigningKeys {
            active: Some(crate::vta::connections::SigningKey {
                key_id: "gateway-jwt-1".to_string(),
                public_key: None,
                label: None,
                added_at: Utc::now(),
                retired_at: None,
            }),
            retiring: Vec::new(),
        };

        let key_id = c
            .keys
            .active
            .as_ref()
            .map(|k| k.key_id.clone())
            .unwrap_or_default();

        assert_eq!(key_id, "gateway-jwt-1");
        assert_ne!(
            key_id,
            c.default_context_id
                .clone()
                .unwrap(),
            "a context must never be used as a key id"
        );
    }

    fn connection(
        id: &str,
        enabled: bool,
    ) -> VtaConnection {
        let now = Utc::now();
        VtaConnection {
            id: id.to_string(),
            tenant_id: None,
            name: format!("VTA {id}"),
            description: None,
            enabled,
            transport: VtaConnectionTransport::Https,
            endpoint: format!("https://{id}.example"),
            vta_did: format!("did:webvh:{id}.example"),
            default_context_id: Some("ctx".to_string()),
            control_key_ref: Some(format!("secret-{id}")),
            status: VtaConnectionStatus::Connected,
            keys: Default::default(),
            pairing: Default::default(),
            created_at: now,
            updated_at: now,
        }
    }

    fn registry(
        store: Arc<dyn VtaConnectionStorage>,
        secrets: Option<Arc<dyn SecretsStore>>,
    ) -> VtaConnectionRegistry {
        VtaConnectionRegistry::new(store, secrets, Some(Arc::new(StubAuthority)), None, Duration::from_secs(5), 4)
    }

    fn detail(err: VtaError) -> String {
        err.log_detail().to_string()
    }

    #[tokio::test]
    async fn a_missing_connection_fails_closed_naming_it() {
        let registry = registry(MemoryStore::new(Vec::new()), None);
        let msg = detail(
            registry
                .authority_for_key("nope", None)
                .await
                .err()
                .expect("an unknown connection must not resolve"),
        );
        assert!(msg.contains("nope"), "unexpected error: {msg}");
        // Critically: it is an error, not a local connector.
        assert!(!msg.contains("local"), "a missing connection must never fall back to local signing: {msg}");
    }

    #[tokio::test]
    async fn a_disabled_connection_fails_closed() {
        let store = MemoryStore::new(vec![connection("c1", false)]);
        let registry = registry(store, None);
        let msg = detail(
            registry
                .authority_for_key("c1", None)
                .await
                .err()
                .expect("a disabled connection must not be used"),
        );
        assert!(msg.contains("disabled"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn an_invalid_connection_fails_closed_explaining_why() {
        let mut broken = connection("c1", true);
        broken.control_key_ref = None;
        let registry = registry(MemoryStore::new(vec![broken]), None);
        let msg = detail(
            registry
                .authority_for_key("c1", None)
                .await
                .err()
                .expect("an unusable connection must not resolve"),
        );
        assert!(msg.contains("control_key_ref"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn the_bootstrap_connection_reuses_the_connector_the_block_built() {
        let store = MemoryStore::new(vec![{
            let mut c = connection(BOOTSTRAP_CONNECTION_ID, true);
            // The bootstrap record carries no secrets-store reference; its key
            // comes from `auth_key_source`.
            c.control_key_ref = Some("unused".to_string());
            c
        }]);
        let registry = registry(store, None);

        let authority = registry
            .authority_for_key(BOOTSTRAP_CONNECTION_ID, None)
            .await
            .expect("the bootstrap connector is reused as-is");
        assert_eq!(
            authority
                .issuer_did()
                .await
                .unwrap(),
            "did:webvh:bootstrap"
        );
    }

    #[tokio::test]
    async fn a_connector_is_cached_and_invalidation_forces_a_rebuild() {
        let store = MemoryStore::new(vec![{
            let mut c = connection(BOOTSTRAP_CONNECTION_ID, true);
            c.control_key_ref = Some("unused".to_string());
            c
        }]);
        let registry = registry(Arc::clone(&store) as Arc<dyn VtaConnectionStorage>, None);

        let first = registry
            .authority_for_key(BOOTSTRAP_CONNECTION_ID, None)
            .await
            .unwrap();
        let second = registry
            .authority_for_key(BOOTSTRAP_CONNECTION_ID, None)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second), "a connection must not rebuild per request");

        // Disable the record and invalidate: the next use must fail closed
        // immediately, with no restart.
        let mut disabled = connection(BOOTSTRAP_CONNECTION_ID, false);
        disabled.control_key_ref = Some("unused".to_string());
        store.replace(disabled);
        registry
            .invalidate(BOOTSTRAP_CONNECTION_ID)
            .await;

        let msg = detail(
            registry
                .authority_for_key(BOOTSTRAP_CONNECTION_ID, None)
                .await
                .err()
                .expect("disabling must take effect without a restart"),
        );
        assert!(msg.contains("disabled"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn a_connection_with_no_secrets_store_cannot_resolve_its_control_key() {
        let mut paired = connection("c1", true);
        paired.pairing = crate::vta::pairing::PairingRecord {
            state: crate::vta::pairing::PairingState::Connected,
            ..Default::default()
        };
        let registry = registry(MemoryStore::new(vec![paired]), None);
        let msg = detail(
            registry
                .authority_for_key("c1", None)
                .await
                .err()
                .expect("there is nowhere to read the control key from"),
        );
        assert!(msg.contains("secrets store"), "unexpected error: {msg}");
    }

    /// A connection that has not completed pairing has not proved it can sign
    /// under the identity the operator chose, so it must not be used — and
    /// never silently fall back to the local key (VTA-24).
    #[tokio::test]
    async fn an_unpaired_connection_fails_closed_before_any_key_is_touched() {
        let registry = registry(MemoryStore::new(vec![connection("c1", true)]), None);
        let msg = detail(
            registry
                .authority_for_key("c1", None)
                .await
                .err()
                .expect("an unpaired connection must not sign"),
        );
        assert!(msg.contains("draft"), "the error must name the state: {msg}");
        assert!(!msg.contains("secrets store"), "pairing is checked before the key is read: {msg}");
    }

    #[tokio::test]
    async fn revoking_takes_effect_on_the_next_resolution() {
        let mut paired = connection("c1", true);
        paired.pairing = crate::vta::pairing::PairingRecord {
            state: crate::vta::pairing::PairingState::Connected,
            ..Default::default()
        };
        let store = MemoryStore::new(vec![paired.clone()]);
        let registry = registry(Arc::clone(&store) as Arc<dyn VtaConnectionStorage>, None);

        let mut revoked = paired;
        revoked.pairing = crate::vta::pairing::revoke(&revoked.pairing);
        store.replace(revoked);
        registry
            .invalidate("c1")
            .await;

        let msg = detail(
            registry
                .authority_for_key("c1", None)
                .await
                .err()
                .expect("a revoked connection must not sign"),
        );
        assert!(msg.contains("revoked"), "unexpected error: {msg}");
    }

    // ---- per-connection carrier (VTA-27) ---------------------------------

    struct StubChannel;

    #[async_trait]
    impl crate::vta::transport::DidCommChannel for StubChannel {
        async fn send(
            &self,
            _to_did: &str,
            _correlation_id: &str,
            _body: &serde_json::Value,
        ) -> Result<(), VtaError> {
            Ok(())
        }

        async fn is_ready(&self) -> bool {
            true
        }
    }

    #[test]
    fn two_connections_may_use_different_carriers_at_once() {
        let registry =
            VtaConnectionRegistry::new(MemoryStore::new(Vec::new()), None, None, None, Duration::from_secs(5), 4)
                .with_didcomm(Arc::new(StubChannel));

        let mut over_https = connection("c1", true);
        over_https.transport = VtaConnectionTransport::Https;
        let mut over_didcomm = connection("c2", true);
        over_didcomm.transport = VtaConnectionTransport::Didcomm;

        assert_eq!(
            registry
                .transport_for(&over_https)
                .unwrap()
                .carrier(),
            "https"
        );
        assert_eq!(
            registry
                .transport_for(&over_didcomm)
                .unwrap()
                .carrier(),
            "didcomm"
        );
    }

    /// Falling back to HTTPS would dial an address the operator deliberately
    /// did not publish — the whole reason they chose DIDComm.
    #[test]
    fn a_didcomm_connection_without_a_mediator_fails_closed() {
        let registry = registry(MemoryStore::new(Vec::new()), None);
        let mut over_didcomm = connection("c1", true);
        over_didcomm.transport = VtaConnectionTransport::Didcomm;

        let msg = detail(
            registry
                .transport_for(&over_didcomm)
                .err()
                .expect("there is no mediator to reach the VTA through"),
        );
        assert!(msg.contains("mediator"), "unexpected error: {msg}");
        assert!(!msg.contains("https"), "it must not suggest dialling the VTA directly: {msg}");
    }

    #[test]
    fn a_didcomm_connection_is_accepted_by_validation_now_that_the_carrier_exists() {
        let mut over_didcomm = connection("c1", true);
        over_didcomm.transport = VtaConnectionTransport::Didcomm;
        over_didcomm
            .validate()
            .expect("the didcomm carrier is wired");

        let mut over_unix = connection("c1", true);
        over_unix.transport = VtaConnectionTransport::Unix;
        assert!(
            over_unix
                .validate()
                .unwrap_err()
                .contains("unix")
        );
    }
}
