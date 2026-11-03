#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;

use super::filesystem::{AgentIdentityRecord, IdentityOrigin};
use super::store::IdentityStore;
use super::vc_issuer::VCIssuer;
use super::vp_challenge_store::{VpChallengeRecord, VpChallengeStore};

pub fn test_signing_key() -> ssi::jwk::JWK {
    ssi::jwk::JWK::generate_ed25519().expect("generate Ed25519 test key")
}

/// Creates a ready-to-use `VCIssuer` backed by in-memory mock stores.
///
/// Handles `init_shared_resolver()` automatically (idempotent).
/// Uses a `tempfile::tempdir()` for filesystem state — caller must hold
/// the returned `TempDir` to keep the directory alive.
pub async fn test_vc_issuer() -> (VCIssuer, tempfile::TempDir) {
    test_vc_issuer_with(Arc::new(MockIdentityStore::new())).await
}

/// [`test_vc_issuer`] over `identity_store`.
pub async fn test_vc_issuer_with(identity_store: Arc<dyn IdentityStore>) -> (VCIssuer, tempfile::TempDir) {
    crate::gateways::did_cache::init_shared_resolver()
        .await
        .expect("init_shared_resolver failed");
    let temp_dir = tempfile::tempdir().unwrap();
    let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;
    let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
        .await
        .expect("VCIssuer::new failed");
    (issuer, temp_dir)
}

pub fn test_surface_identity_record(
    did: &str,
    surface_id: &str,
) -> AgentIdentityRecord {
    let now = chrono::Utc::now();
    AgentIdentityRecord {
        did: did.to_string(),
        identity_hash: did.to_string(),
        created_at: now,
        identity_fields: HashMap::new(),
        usage_count: 1,
        last_used_at: Some(now),
        channel_usage: vec![super::filesystem::ChannelUsage {
            channel_config_id: surface_id.to_string(),
            usage_count: 1,
            last_used_at: now,
        }],
        private_key: None,
        channel_config_id: Some(surface_id.to_string()),
        is_local: true,
        verified: true,
        origin: None,
    }
}

pub struct MockIdentityStore {
    records: Arc<RwLock<HashMap<String, AgentIdentityRecord>>>,
}

impl MockIdentityStore {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl IdentityStore for MockIdentityStore {
    async fn create(
        &self,
        record: AgentIdentityRecord,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.identity_hash.clone(), record);
        Ok(())
    }

    async fn find_by_hash(
        &self,
        identity_hash: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .get(identity_hash)
            .cloned())
    }

    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.did == did)
            .cloned())
    }

    async fn list_all(&self) -> Result<Vec<AgentIdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .cloned()
            .collect())
    }

    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(identity_hash) {
            record.usage_count += 1;
            record.last_used_at = Some(chrono::Utc::now());
            if let Some(cid) = channel_config_id {
                record.channel_config_id = Some(cid);
            }
        }
        Ok(())
    }

    async fn store_external_did(
        &self,
        did: &str,
        identity_fields: HashMap<String, serde_json::Value>,
        channel_config_id: Option<String>,
        verified: bool,
    ) -> Result<()> {
        let identity_hash = crate::identity::filesystem::calculate_identity_hash(
            &serde_json::to_value(&identity_fields).unwrap_or_default(),
        );

        let record = AgentIdentityRecord {
            did: did.to_string(),
            identity_hash: identity_hash.clone(),
            created_at: chrono::Utc::now(),
            identity_fields,
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            channel_config_id,
            is_local: false,
            verified,
            origin: Some(IdentityOrigin::ExternalCaller),
        };

        let mut records = self.records.write().await;
        records.insert(identity_hash, record);
        Ok(())
    }

    async fn set_origin(
        &self,
        identity_hash: &str,
        origin: IdentityOrigin,
    ) -> Result<Option<IdentityOrigin>> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(identity_hash)
            .ok_or_else(|| anyhow::anyhow!("identity record not found: {identity_hash}"))?;
        Ok(Some(
            *record
                .origin
                .get_or_insert(origin),
        ))
    }
}

/// A [`MockIdentityStore`] that cannot record an identity origin.
pub struct OriginFailingIdentityStore(pub MockIdentityStore);

#[async_trait]
impl IdentityStore for OriginFailingIdentityStore {
    async fn create(
        &self,
        record: AgentIdentityRecord,
    ) -> Result<()> {
        self.0.create(record).await
    }

    async fn find_by_hash(
        &self,
        identity_hash: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        self.0
            .find_by_hash(identity_hash)
            .await
    }

    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        self.0.find_by_did(did).await
    }

    async fn list_all(&self) -> Result<Vec<AgentIdentityRecord>> {
        self.0.list_all().await
    }

    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
    ) -> Result<()> {
        self.0
            .update_usage(identity_hash, channel_config_id)
            .await
    }

    async fn store_external_did(
        &self,
        did: &str,
        identity_fields: HashMap<String, serde_json::Value>,
        channel_config_id: Option<String>,
        verified: bool,
    ) -> Result<()> {
        self.0
            .store_external_did(did, identity_fields, channel_config_id, verified)
            .await
    }

    async fn set_origin(
        &self,
        _identity_hash: &str,
        _origin: IdentityOrigin,
    ) -> Result<Option<IdentityOrigin>> {
        Err(anyhow::anyhow!("origin store unavailable"))
    }
}

/// An identity store whose every lookup and write fails with
/// [`FailingIdentityStore::DETAIL`].
pub struct FailingIdentityStore;

impl FailingIdentityStore {
    pub const DETAIL: &'static str = "identity store offline at shard-7";
}

#[async_trait]
impl IdentityStore for FailingIdentityStore {
    async fn create(
        &self,
        _record: AgentIdentityRecord,
    ) -> Result<()> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }

    async fn find_by_hash(
        &self,
        _identity_hash: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }

    async fn find_by_did(
        &self,
        _did: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }

    async fn list_all(&self) -> Result<Vec<AgentIdentityRecord>> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }

    async fn update_usage(
        &self,
        _identity_hash: &str,
        _channel_config_id: Option<String>,
    ) -> Result<()> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }

    async fn store_external_did(
        &self,
        _did: &str,
        _identity_fields: HashMap<String, serde_json::Value>,
        _channel_config_id: Option<String>,
        _verified: bool,
    ) -> Result<()> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }

    async fn set_origin(
        &self,
        _identity_hash: &str,
        _origin: IdentityOrigin,
    ) -> Result<Option<IdentityOrigin>> {
        Err(anyhow::anyhow!(Self::DETAIL))
    }
}

pub struct MockVpChallengeStore {
    records: Arc<RwLock<HashMap<String, VpChallengeRecord>>>,
}

impl MockVpChallengeStore {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl VpChallengeStore for MockVpChallengeStore {
    async fn find_by_challenge(
        &self,
        challenge: &str,
    ) -> Result<Option<VpChallengeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .get(challenge)
            .cloned())
    }

    async fn store(
        &self,
        record: VpChallengeRecord,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.challenge.clone(), record);
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<VpChallengeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .cloned()
            .collect())
    }

    async fn delete(
        &self,
        challenge: &str,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        records.remove(challenge);
        Ok(())
    }
}

/// An agent identity presentation signed offline with did:peer keys: one key
/// issues the identity VC as `issuer_did`, another signs the VP as
/// `holder_did`. `issuer` is a `VCIssuer` that verifies it without network
/// resolution; hold `_temporary` for as long as `issuer` is used.
pub struct SignedAgentPresentation {
    pub issuer_did: String,
    pub holder_did: String,
    pub presentation: serde_json::Value,
    pub issuer: Arc<VCIssuer>,
    pub _temporary: tempfile::TempDir,
}

pub async fn signed_agent_presentation() -> SignedAgentPresentation {
    use crate::identity::ssi::vc_issuer::{AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer};
    use crate::identity::ssi::vp_issuer::{Credentials, LocalVpIssuer, LocalVpSigner, VpIssuer, VpIssuerPayload};
    use std::borrow::Cow;

    fn peer(key: &ssi::jwk::JWK) -> String {
        crate::identity::ssi::did_utils::create_signing_did_peer(key).unwrap()
    }

    let signing_key = ssi::jwk::JWK::generate_ed25519().unwrap();
    let issuer_did = peer(&signing_key);
    let holder_key = ssi::jwk::JWK::generate_ed25519().unwrap();
    let holder_did = peer(&holder_key);
    let config = Arc::new(RwLock::new(crate::identity::VCIssuerConfig {
        storage_path: Default::default(),
        proxy_did: issuer_did.clone(),
        signing_key,
        is_vp_challenge_required: false,
    }));
    let signer = Arc::new(LocalVcSigner::new(config.clone()));
    let credential = LocalVcIssuer::new(config, signer)
        .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
            did: Cow::Borrowed(&holder_did),
            identity_fields: Cow::Owned(HashMap::new()),
            workload_binding: None,
            display_name: None,
        }))
        .await
        .unwrap();
    let presentation = LocalVpIssuer::new(Arc::new(LocalVpSigner::new()))
        .issue(VpIssuerPayload::Credentials(Credentials {
            holder_key: Cow::Owned(holder_key),
            holder_did: Cow::Borrowed(&holder_did),
            verifiable_credentials: Cow::Owned(vec![credential]),
            challenge: None,
            domain: None,
        }))
        .await
        .unwrap();
    let (issuer, _temporary) = test_vc_issuer().await;
    SignedAgentPresentation {
        issuer_did,
        holder_did,
        presentation,
        issuer: Arc::new(issuer),
        _temporary,
    }
}
