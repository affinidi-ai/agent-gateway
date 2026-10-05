//! Storage for VP request challenges
//!
//! This module provides a trait for storing VP challenge records when one agent gateway
//! requests VP from an agent via another agent gateway.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpChallengeRecord {
    pub challenge: String,

    pub created_at: chrono::DateTime<chrono::Utc>,

    pub domain: String,

    pub requested_from_did: String,
}

impl StorableEntity for VpChallengeRecord {
    fn id(&self) -> &str {
        &self.challenge
    }
}

#[async_trait]
pub trait VpChallengeStore: Send + Sync {
    async fn find_by_challenge(
        &self,
        challenge: &str,
    ) -> Result<Option<VpChallengeRecord>>;

    #[allow(dead_code)]
    async fn store(
        &self,
        record: VpChallengeRecord,
    ) -> Result<()>;

    #[allow(dead_code)]
    async fn list_all(&self) -> Result<Vec<VpChallengeRecord>>;

    async fn delete(
        &self,
        challenge: &str,
    ) -> Result<()>;
}

pub struct FilesystemVpChallengeStore {
    storage: Box<dyn StorageBackend<VpChallengeRecord>>,
}

impl FilesystemVpChallengeStore {
    pub async fn new(storage_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let storage = rwlock_storage(
            storage_path
                .as_ref()
                .to_path_buf(),
            "vp_challenge",
        )
        .await?;

        Ok(Self { storage })
    }
}

#[async_trait]
impl VpChallengeStore for FilesystemVpChallengeStore {
    async fn find_by_challenge(
        &self,
        challenge: &str,
    ) -> Result<Option<VpChallengeRecord>> {
        self.storage
            .get(challenge)
            .await
    }

    async fn store(
        &self,
        record: VpChallengeRecord,
    ) -> Result<()> {
        self.storage
            .save(&record)
            .await
    }

    async fn list_all(&self) -> Result<Vec<VpChallengeRecord>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        challenge: &str,
    ) -> Result<()> {
        self.storage
            .delete(challenge)
            .await
    }
}
