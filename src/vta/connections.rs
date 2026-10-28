//! VTA connections as **managed records**.
//!
//! `[vta]` is bootstrap config: one VTA, restart required, edited by hand in
//! TOML. A customer who wants to connect their own VTA from the dashboard, or
//! an appliance serving several tenants from different VTAs, cannot be
//! expressed that way. A [`VtaConnection`] is the same thing as a managed
//! record — many connections, CRUD over the management API, hot-reloadable —
//! matching how Gateways, Connection Points, STS clients and Trust Registries
//! are already stored.
//!
//! ## Key material is held by reference
//!
//! A record carries a `control_key_ref` into the secrets store, never inline
//! key material, and never a session/bearer token: those stay memory-only per
//! connection (VTA-03), so a leaked record file cannot be replayed against the
//! VTA.
//!
//! ## The bootstrap block still works
//!
//! An existing `[vta]` block is migrated to a record on first boot under a
//! fixed id, so the migration is idempotent across restarts and the appliance
//! behaves identically before and after.

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::config::vta::VtaConfig;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

/// Record id the bootstrap `[vta]` block migrates to. Fixed rather than random
/// so the migration is idempotent: a restart finds the existing record instead
/// of creating a second one.
pub const BOOTSTRAP_CONNECTION_ID: &str = "vta-bootstrap";

/// How the gateway reaches a VTA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VtaConnectionTransport {
    /// REST over HTTPS (or plain HTTP for a loopback sidecar).
    #[default]
    Https,
    /// REST over a unix domain socket — a bundled sidecar on the same host
    /// (VTA-21), so the Trust Task surface is never exposed on a port.
    Unix,
    /// Trust Tasks carried over DIDComm (VTA-27). Accepted so config written
    /// now stays valid, and rejected by [`VtaConnection::validate`] until the
    /// carrier lands.
    Didcomm,
}

/// Where a connection is in its pairing lifecycle. Set by the pairing flow
/// (VTA-24); stored here so the dashboard can render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VtaConnectionStatus {
    /// Recorded, but the customer has not yet granted this gateway on their
    /// VTA. A connection in this state is configured, not usable.
    #[default]
    Unpaired,
    /// Paired and reachable.
    Connected,
    /// Paired but the last interaction failed (grant revoked, VTA down).
    Error,
}

/// A persisted VTA connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtaConnection {
    /// Storage key / filename.
    pub id: String,
    /// Owning tenant. Absent ⇒ appliance-global (see the tenancy section of
    /// `AGENTS.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Operator-facing display name.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// A disabled connection is **not used**: anything still mapped to it fails
    /// closed rather than falling back to local signing.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub transport: VtaConnectionTransport,
    /// Base URL (`https`) or socket path (`unix`) of the VTA's Trust Task
    /// surface.
    pub endpoint: String,
    /// The VTA service DID, pinned so the gateway talks to the intended VTA.
    pub vta_did: String,
    /// Context this connection's keys live in, when the connection has a single
    /// default. A `KeyRef` may still name a different one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_context_id: Option<String>,
    /// Secrets-store reference (`secret_id`) holding the gateway's Ed25519
    /// control-key seed for this connection. **Never inline key material.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_key_ref: Option<String>,
    #[serde(default)]
    pub status: VtaConnectionStatus,

    /// Pairing progress (VTA-24): which control DID the customer was asked to
    /// grant, the VTA DID pinned on success, what was actually granted, and
    /// why the last attempt failed. A connection whose pairing state is not
    /// `connected` is **not used for signing**.
    #[serde(default)]
    pub pairing: crate::vta::pairing::PairingRecord,

    /// Keys this connection signs with (VTA-20).
    ///
    /// Held on the record rather than in the startup `[vta]` block so a
    /// rotation takes effect without a restart — the whole point of rotating
    /// is that it is an operational act, not a redeploy.
    #[serde(default)]
    pub keys: SigningKeys,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A key this connection publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKey {
    /// The VTA key record id — also the published `kid`, which is how an
    /// operator correlates a token back to the key that signed it.
    pub key_id: String,
    /// Multibase Ed25519 **public** key, captured at provisioning. Required
    /// for an internal (non-exportable) key, whose record the VTA will not
    /// return to any caller at any role. Public key material is not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub added_at: DateTime<Utc>,
    /// When this key stopped signing. `None` while active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

/// The active key plus every key still being published.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeys {
    /// The key new artifacts are signed with. `None` until one is provisioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<SigningKey>,
    /// Keys that no longer sign but are **still published**, so the artifacts
    /// they signed keep verifying. Never emptied by rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retiring: Vec<SigningKey>,
}

impl SigningKeys {
    /// Rotate to `next`, retiring the current active key.
    ///
    /// The old key is **moved to `retiring`, never dropped**: a verifier picks
    /// between keys by `kid`, so deleting the old public half would invalidate
    /// every token it signed that is still in flight. Retiring is therefore
    /// the only supported way to stop using a key.
    pub fn rotate_to(
        &mut self,
        next: SigningKey,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if next.key_id.trim().is_empty() {
            return Err("the new key_id must not be empty".to_string());
        }
        if self.publishes(&next.key_id) {
            // Rotating onto a key already in the set would publish one `kid`
            // twice and make the active key ambiguous.
            return Err(format!("key `{}` is already published by this connection", next.key_id));
        }
        if let Some(mut previous) = self.active.take() {
            previous.retired_at = Some(now);
            self.retiring.push(previous);
        }
        self.active = Some(next);
        Ok(())
    }

    /// Whether `key_id` is active or retiring on this connection.
    pub fn publishes(
        &self,
        key_id: &str,
    ) -> bool {
        self.active
            .as_ref()
            .is_some_and(|k| k.key_id == key_id)
            || self
                .retiring
                .iter()
                .any(|k| k.key_id == key_id)
    }

    /// Every published key, active first.
    pub fn published(&self) -> Vec<&SigningKey> {
        self.active
            .iter()
            .chain(self.retiring.iter())
            .collect()
    }
}

impl VtaConnection {
    /// Validate a connection before it is stored or used.
    ///
    /// Fails **closed**: an unusable connection is rejected at write time, so a
    /// surface mapped to it never discovers the problem mid-request.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name is required".to_string());
        }
        if self
            .endpoint
            .trim()
            .is_empty()
        {
            return Err("endpoint is required".to_string());
        }
        if self.vta_did.trim().is_empty() {
            return Err("vta_did is required".to_string());
        }
        if self.transport == VtaConnectionTransport::Didcomm
            && self
                .endpoint
                .trim()
                .is_empty()
        {
            // A DIDComm connection is addressed by DID, not by URL, so the
            // endpoint names the mediator instead.
            return Err("endpoint must name the mediator for the `didcomm` transport".to_string());
        }
        if self.transport == VtaConnectionTransport::Unix {
            return Err("transport `unix` is not yet supported; use `https` or `didcomm`".to_string());
        }
        // A control key is how the gateway authenticates to the VTA. Without
        // one there is nothing to sign the handshake with, so an enabled
        // connection that lacks the reference is a misconfiguration rather than
        // an anonymous client.
        if self.enabled
            && self
                .control_key_ref
                .as_deref()
                .map(|r| r.trim().is_empty())
                .unwrap_or(true)
        {
            return Err("control_key_ref is required for an enabled connection".to_string());
        }
        Ok(())
    }

    /// Build the record the bootstrap `[vta]` block describes, if it describes
    /// one at all. Returns `None` for a disabled or incomplete block, which is
    /// the default state and must not create a record.
    pub fn from_bootstrap(config: &VtaConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let endpoint = config
            .base_url
            .as_deref()?
            .to_string();
        let vta_did = config
            .vta_did
            .as_deref()?
            .to_string();
        let now = Utc::now();
        Some(Self {
            id: BOOTSTRAP_CONNECTION_ID.to_string(),
            tenant_id: None,
            name: "Bootstrap VTA".to_string(),
            description: Some("Migrated from the [vta] configuration block.".to_string()),
            enabled: true,
            transport: VtaConnectionTransport::Https,
            endpoint,
            vta_did,
            default_context_id: config.context_id.clone(),
            // The bootstrap block sources its control key from
            // `auth_key_source` (`env://` / `file://`) rather than the secrets
            // store, so the record has no reference to carry. The connector for
            // this connection keeps using the bootstrap key.
            control_key_ref: None,
            status: VtaConnectionStatus::Unpaired,
            keys: Default::default(),
            pairing: Default::default(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Whether this record was created by bootstrap migration. Such a record is
    /// read-only over the management API: editing the TOML block is still the
    /// way to change it, and allowing both would make "which one wins" after a
    /// restart unanswerable.
    pub fn is_bootstrap(&self) -> bool {
        self.id == BOOTSTRAP_CONNECTION_ID
    }
}

impl StorableEntity for VtaConnection {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Storage backend for VTA connections.
#[async_trait]
pub trait VtaConnectionStorage: Send + Sync {
    async fn create(
        &self,
        connection: VtaConnection,
    ) -> Result<VtaConnection>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<VtaConnection>>;
    async fn list(&self) -> Result<Vec<VtaConnection>>;
    async fn update(
        &self,
        connection: VtaConnection,
    ) -> Result<VtaConnection>;
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}

/// Filesystem-backed connection store (`{storage_dir}/{id}.json`), inheriting
/// encryption at rest and atomic writes from the generic storage backend.
pub struct FileSystemVtaConnectionStore {
    storage: Box<dyn StorageBackend<VtaConnection>>,
}

impl FileSystemVtaConnectionStore {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "vta_connection")
            .await
            .context("Failed to open VTA connection storage")?;
        let store = Self { storage };
        info!(
            "Initialised FileSystemVtaConnectionStore with {} connection(s)",
            store
                .storage
                .list_all()
                .await?
                .len()
        );
        Ok(store)
    }
}

#[async_trait]
impl VtaConnectionStorage for FileSystemVtaConnectionStore {
    async fn create(
        &self,
        mut connection: VtaConnection,
    ) -> Result<VtaConnection> {
        let now = Utc::now();
        if connection.id.is_empty() {
            connection.id = Uuid::new_v4().to_string();
        } else if self
            .storage
            .get(&connection.id)
            .await?
            .is_some()
        {
            anyhow::bail!("VTA connection {} already exists", connection.id);
        }
        connection.created_at = now;
        connection.updated_at = now;
        self.storage
            .save(&connection)
            .await?;
        info!("Created VTA connection {} ({})", connection.name, connection.id);
        Ok(connection)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<VtaConnection>> {
        self.storage.get(id).await
    }

    async fn list(&self) -> Result<Vec<VtaConnection>> {
        self.storage.list_all().await
    }

    async fn update(
        &self,
        mut connection: VtaConnection,
    ) -> Result<VtaConnection> {
        let existing = self
            .storage
            .get(&connection.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("VTA connection {} not found", connection.id))?;
        connection.created_at = existing.created_at;
        connection.updated_at = Utc::now();
        self.storage
            .save(&connection)
            .await?;
        info!("Updated VTA connection {} ({})", connection.name, connection.id);
        Ok(connection)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }
}

/// Migrate the bootstrap `[vta]` block into a record, once.
///
/// Idempotent by construction: the record always carries
/// [`BOOTSTRAP_CONNECTION_ID`], so a restart finds it and does nothing. Returns
/// the record that now represents the block, or `None` when the block describes
/// no connection (the default).
pub async fn migrate_bootstrap_connection(
    config: &VtaConfig,
    store: &dyn VtaConnectionStorage,
) -> Result<Option<VtaConnection>> {
    let Some(connection) = VtaConnection::from_bootstrap(config) else {
        return Ok(None);
    };
    if let Some(existing) = store
        .get(BOOTSTRAP_CONNECTION_ID)
        .await?
    {
        // The TOML block remains the source of truth for its own record, so a
        // block edited between restarts is reflected rather than ignored.
        let changed = existing.endpoint != connection.endpoint
            || existing.vta_did != connection.vta_did
            || existing.default_context_id != connection.default_context_id
            || !existing.enabled;
        if !changed {
            return Ok(Some(existing));
        }
        let updated = VtaConnection {
            name: existing.name,
            description: existing.description,
            tenant_id: existing.tenant_id,
            status: existing.status,
            ..connection
        };
        return store
            .update(updated)
            .await
            .map(Some);
    }
    store
        .create(connection)
        .await
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(id: &str) -> VtaConnection {
        let now = Utc::now();
        VtaConnection {
            id: id.to_string(),
            tenant_id: None,
            name: "Customer VTA".to_string(),
            description: None,
            enabled: true,
            transport: VtaConnectionTransport::Https,
            endpoint: "https://vta.customer.example".to_string(),
            vta_did: "did:webvh:vta.customer.example".to_string(),
            default_context_id: Some("ctx".to_string()),
            control_key_ref: Some("secret-control-key".to_string()),
            status: VtaConnectionStatus::Unpaired,
            keys: Default::default(),
            pairing: Default::default(),
            created_at: now,
            updated_at: now,
        }
    }

    async fn store() -> (FileSystemVtaConnectionStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSystemVtaConnectionStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        (store, tmp)
    }

    #[test]
    fn a_record_never_serialises_key_material() {
        let json = serde_json::to_value(connection("c1")).unwrap();
        // Only the reference is stored; the seed itself lives in the secrets
        // store and a leaked record file cannot be replayed.
        assert_eq!(json["control_key_ref"], "secret-control-key");
        let text = json.to_string();
        for forbidden in ["control_key_seed", "private_key", "session_token", "bearer"] {
            assert!(!text.contains(forbidden), "record leaked `{forbidden}`: {text}");
        }
    }

    #[test]
    fn an_enabled_connection_without_a_control_key_reference_is_rejected() {
        let mut c = connection("c1");
        c.control_key_ref = None;
        let err = c
            .validate()
            .expect_err("there would be nothing to authenticate the handshake with");
        assert!(err.contains("control_key_ref"), "unexpected error: {err}");

        // A disabled connection is a draft, so it may still be incomplete.
        c.enabled = false;
        c.validate()
            .expect("a disabled connection may be a draft");
    }

    #[test]
    fn required_fields_and_unwired_transports_are_rejected() {
        let mut c = connection("c1");
        c.endpoint = "  ".to_string();
        assert!(
            c.validate()
                .unwrap_err()
                .contains("endpoint")
        );

        let mut c = connection("c1");
        c.vta_did = String::new();
        assert!(
            c.validate()
                .unwrap_err()
                .contains("vta_did")
        );

        let mut c = connection("c1");
        c.transport = VtaConnectionTransport::Didcomm;
        c.validate()
            .expect("the didcomm carrier is wired (VTA-27)");

        let mut c = connection("c1");
        c.transport = VtaConnectionTransport::Unix;
        assert!(
            c.validate()
                .unwrap_err()
                .contains("unix")
        );
    }

    #[tokio::test]
    async fn two_connections_coexist_and_round_trip() {
        let (store, _tmp) = store().await;
        store
            .create(connection("c1"))
            .await
            .unwrap();
        let mut second = connection("c2");
        second.endpoint = "https://vta.other.example".to_string();
        second.vta_did = "did:webvh:vta.other.example".to_string();
        store
            .create(second)
            .await
            .unwrap();

        let mut listed = store.list().await.unwrap();
        listed.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].endpoint, "https://vta.customer.example");
        assert_eq!(listed[1].endpoint, "https://vta.other.example");
        assert_eq!(listed[1].vta_did, "did:webvh:vta.other.example");
    }

    #[tokio::test]
    async fn update_preserves_created_at_and_moves_updated_at() {
        let (store, _tmp) = store().await;
        let created = store
            .create(connection("c1"))
            .await
            .unwrap();

        let mut edited = created.clone();
        edited.enabled = false;
        edited.name = "Renamed".to_string();
        let updated = store
            .update(edited)
            .await
            .unwrap();

        assert_eq!(updated.created_at, created.created_at);
        assert!(updated.updated_at >= created.updated_at);
        assert_eq!(updated.name, "Renamed");
        assert!(!updated.enabled);
    }

    // ---- bootstrap migration ---------------------------------------------

    fn bootstrap_config() -> VtaConfig {
        VtaConfig {
            enabled: true,
            base_url: Some("http://127.0.0.1:3000".to_string()),
            vta_did: Some("did:webvh:localhost".to_string()),
            context_id: Some("ctx-gateway".to_string()),
            signing_key_id: Some("key-gateway-jwt".to_string()),
            ..VtaConfig::default()
        }
    }

    #[tokio::test]
    async fn a_disabled_block_creates_no_record() {
        let (store, _tmp) = store().await;
        let migrated = migrate_bootstrap_connection(&VtaConfig::default(), &store)
            .await
            .unwrap();
        assert!(migrated.is_none());
        assert!(
            store
                .list()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_bootstrap_block_migrates_once_and_stays_stable_across_restarts() {
        let (store, _tmp) = store().await;
        let config = bootstrap_config();

        let first = migrate_bootstrap_connection(&config, &store)
            .await
            .unwrap()
            .expect("an enabled block describes a connection");
        assert_eq!(first.id, BOOTSTRAP_CONNECTION_ID);
        assert_eq!(first.endpoint, "http://127.0.0.1:3000");
        assert_eq!(first.vta_did, "did:webvh:localhost");
        assert_eq!(
            first
                .default_context_id
                .as_deref(),
            Some("ctx-gateway")
        );
        assert!(first.enabled);

        // Second boot: same id, same record, no duplicate.
        let second = migrate_bootstrap_connection(&config, &store)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.created_at, first.created_at);
        assert_eq!(
            store
                .list()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn editing_the_block_between_restarts_updates_its_record() {
        let (store, _tmp) = store().await;
        let original = migrate_bootstrap_connection(&bootstrap_config(), &store)
            .await
            .unwrap()
            .unwrap();

        let mut moved = bootstrap_config();
        moved.base_url = Some("https://vta.internal:8443".to_string());
        let migrated = migrate_bootstrap_connection(&moved, &store)
            .await
            .unwrap()
            .unwrap();

        // The TOML block stays the source of truth for its own record.
        assert_eq!(migrated.id, BOOTSTRAP_CONNECTION_ID);
        assert_eq!(migrated.endpoint, "https://vta.internal:8443");
        assert_eq!(migrated.created_at, original.created_at);
        assert_eq!(
            store
                .list()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_incomplete_block_describes_no_connection() {
        let (store, _tmp) = store().await;
        let config = VtaConfig {
            enabled: true,
            base_url: None,
            ..bootstrap_config()
        };
        assert!(
            migrate_bootstrap_connection(&config, &store)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_bootstrap_record_is_recognisable() {
        assert!(
            VtaConnection::from_bootstrap(&bootstrap_config())
                .unwrap()
                .is_bootstrap()
        );
        assert!(!connection("c1").is_bootstrap());
    }

    // ---- key rotation (VTA-20) -------------------------------------------

    fn key(id: &str) -> SigningKey {
        SigningKey {
            key_id: id.to_string(),
            public_key: Some(format!("z6Mk-{id}")),
            label: None,
            added_at: Utc::now(),
            retired_at: None,
        }
    }

    #[test]
    fn the_first_key_simply_becomes_active() {
        let mut keys = SigningKeys::default();
        keys.rotate_to(key("k1"), Utc::now())
            .expect("rotate");
        assert_eq!(
            keys.active
                .as_ref()
                .unwrap()
                .key_id,
            "k1"
        );
        assert!(keys.retiring.is_empty(), "there was nothing to retire");
    }

    /// The old public half is what makes already-issued tokens verifiable, so
    /// rotation must never drop it.
    #[test]
    fn rotation_retires_the_previous_key_and_keeps_publishing_it() {
        let mut keys = SigningKeys::default();
        let now = Utc::now();
        keys.rotate_to(key("k1"), now)
            .unwrap();
        keys.rotate_to(key("k2"), now)
            .unwrap();

        assert_eq!(
            keys.active
                .as_ref()
                .unwrap()
                .key_id,
            "k2"
        );
        assert_eq!(keys.retiring.len(), 1);
        assert_eq!(keys.retiring[0].key_id, "k1");
        assert_eq!(keys.retiring[0].retired_at, Some(now), "a retired key records when it stopped signing");
        assert!(
            keys.retiring[0]
                .public_key
                .is_some(),
            "the public half must survive, or tokens k1 signed stop verifying"
        );
        assert!(keys.publishes("k1") && keys.publishes("k2"), "both keys are still published");
    }

    #[test]
    fn repeated_rotation_keeps_every_retired_key() {
        let mut keys = SigningKeys::default();
        for id in ["k1", "k2", "k3", "k4"] {
            keys.rotate_to(key(id), Utc::now())
                .unwrap();
        }
        assert_eq!(keys.published().len(), 4, "nothing is ever dropped");
        assert_eq!(keys.published()[0].key_id, "k4", "the active key is reported first");
    }

    #[test]
    fn rotating_onto_an_already_published_key_is_rejected() {
        let mut keys = SigningKeys::default();
        keys.rotate_to(key("k1"), Utc::now())
            .unwrap();
        keys.rotate_to(key("k2"), Utc::now())
            .unwrap();

        // Re-adding `k1` would publish one `kid` twice and make the active key
        // ambiguous for a verifier.
        for duplicate in ["k1", "k2"] {
            let err = keys
                .rotate_to(key(duplicate), Utc::now())
                .expect_err("a duplicate kid must be refused");
            assert!(err.contains(duplicate), "unexpected error: {err}");
        }
        assert_eq!(
            keys.active
                .as_ref()
                .unwrap()
                .key_id,
            "k2",
            "a refused rotation changes nothing"
        );
        assert_eq!(keys.retiring.len(), 1);
    }

    #[test]
    fn rotating_to_an_empty_key_id_is_rejected() {
        let mut keys = SigningKeys::default();
        let err = keys
            .rotate_to(
                SigningKey {
                    key_id: "   ".to_string(),
                    ..key("ignored")
                },
                Utc::now(),
            )
            .expect_err("an empty kid names nothing");
        assert!(err.contains("key_id"), "unexpected error: {err}");
        assert!(keys.active.is_none());
    }

    #[test]
    fn keys_round_trip_on_the_record() {
        let mut c = connection("c1");
        c.keys
            .rotate_to(key("k1"), Utc::now())
            .unwrap();
        c.keys
            .rotate_to(key("k2"), Utc::now())
            .unwrap();

        let json = serde_json::to_value(&c).unwrap();
        let back: VtaConnection = serde_json::from_value(json).unwrap();
        assert_eq!(back.keys, c.keys);
        // Still only public halves on the record.
        assert!(
            !serde_json::to_string(&back)
                .unwrap()
                .contains("privateKey")
        );
    }

    #[test]
    fn a_connection_with_no_keys_serialises_without_the_block() {
        let json = serde_json::to_value(connection("c1")).unwrap();
        assert!(
            json["keys"]
                .get("active")
                .is_none(),
            "an unprovisioned connection stays clean: {json}"
        );
    }
}
