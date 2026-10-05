//! Session management for DID Authentication
//!
//! Maintains session state for authenticated DIDs on channels

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::storage::filesystem::{StorableEntity, StorageBackend, in_memory_storage_with_timeout, rwlock_storage};

/// Session information for an authenticated DID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidAuthSession {
    /// The session ID (token) given to the client
    pub session_id: String,

    /// The DID that was authenticated
    pub did: String,

    /// The channel name this session is for
    pub channel_name: String,

    /// **Authoritative** surface identifier this session is bound to.
    /// Written from the server-side `state.surface_id` at mint time and
    /// checked at every session-lookup site — a session minted for surface
    /// A must not authenticate against surface B, even if the client
    /// replays the token. Legacy on-disk sessions predating this field
    /// deserialise with an empty string and are rejected as unbound.
    #[serde(default)]
    pub surface_id: String,

    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the session expires
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// The challenge that was issued (for verification)
    pub challenge: Option<String>,
}

impl StorableEntity for DidAuthSession {
    fn id(&self) -> &str {
        &self.session_id
    }
}

/// Pending challenge before authentication
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PendingChallenge {
    /// The challenge string
    pub challenge: String,

    /// The DID that requested the challenge
    pub did: String,

    /// When the challenge was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the challenge expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Session store for DID Auth with filesystem persistence
pub struct DidAuthSessionStore {
    /// Session storage (in-memory or filesystem-backed)
    storage: Box<dyn StorageBackend<DidAuthSession>>,

    /// Map of challenge -> PendingChallenge (always in-memory only)
    pending_challenges: Arc<RwLock<HashMap<String, PendingChallenge>>>,
}

impl DidAuthSessionStore {
    /// Create a new session store (in-memory only, 60-minute timeout)
    pub fn new() -> Self {
        Self {
            storage: in_memory_storage_with_timeout(60),
            pending_challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session store with filesystem persistence
    pub async fn with_storage(storage_path: PathBuf) -> Result<Self> {
        let storage: Box<dyn StorageBackend<DidAuthSession>> =
            rwlock_storage(storage_path.clone(), "didauth_session").await?;

        // Remove expired sessions from cache
        let now = chrono::Utc::now();
        let expired: Vec<String> = {
            let cache = storage
                .raw_cache()
                .expect("cached storage")
                .read()
                .await;
            cache
                .iter()
                .filter(|(_, s)| now > s.expires_at)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in &expired {
            if let Err(e) = storage.delete(id).await {
                tracing::warn!("Failed to delete expired DID auth session {}: {}", id, e);
            }
        }

        if !expired.is_empty() {
            tracing::info!("Cleaned up {} expired DID auth session(s) on load", expired.len());
        }

        let loaded = storage
            .raw_cache()
            .expect("cached storage")
            .read()
            .await
            .len();
        if loaded > 0 {
            tracing::info!("Loaded {} DID auth session(s) from disk", loaded);
        }

        Ok(Self {
            storage,
            pending_challenges: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get a reference to the active session cache
    fn sessions(&self) -> &Arc<RwLock<HashMap<String, DidAuthSession>>> {
        self.storage
            .raw_cache()
            .expect("storage backend provides raw_cache")
    }

    /// Test-only: write a fully-formed session record straight into the
    /// cache, bypassing [`create_session`]. Used to fabricate legacy /
    /// malformed records for regression tests (e.g. a session missing the
    /// `surface_id` binding). Not exposed in release builds.
    #[cfg(test)]
    pub async fn insert_for_test(
        &self,
        session: DidAuthSession,
    ) {
        self.sessions()
            .write()
            .await
            .insert(session.session_id.clone(), session);
    }

    /// Create a new challenge for a DID
    pub async fn create_challenge(
        &self,
        did: String,
        ttl_seconds: u64,
    ) -> String {
        let challenge = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let pending = PendingChallenge {
            challenge: challenge.clone(),
            did,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
        };

        self.pending_challenges
            .write()
            .await
            .insert(challenge.clone(), pending);

        challenge
    }

    /// Verify a challenge and consume it.
    ///
    /// Retained for use by tests + JSON-API callers that already know the
    /// challenge string (`GET /v1/didauth/challenges/{id}` style). Session
    /// minting on the surface hot path uses [`take_pending_challenge`]
    /// instead so the client does not have to re-send the challenge in the
    /// authenticate body (the JWS payload carries it).
    #[allow(dead_code)]
    pub async fn verify_challenge(
        &self,
        challenge: &str,
        expected_did: &str,
    ) -> Result<(), String> {
        let mut challenges = self
            .pending_challenges
            .write()
            .await;

        if let Some(pending) = challenges.remove(challenge) {
            // Check if expired
            if chrono::Utc::now() > pending.expires_at {
                return Err("Challenge expired".to_string());
            }

            // Check if DID matches
            if pending.did != expected_did {
                return Err("DID mismatch".to_string());
            }

            Ok(())
        } else {
            Err("Challenge not found or already used".to_string())
        }
    }

    /// Consume the most recently issued pending challenge for `did`. Returns
    /// the pending challenge on hit (removing it from the pending set) or
    /// `None` when no challenge is pending. Newer challenges shadow older
    /// ones — the one with the latest `created_at` wins so a client that
    /// re-issued a challenge does not accidentally reuse a stale one. Older
    /// pending challenges for the same DID are dropped on the same call
    /// (single-use semantics per DID) so a caller cannot bank a pool of
    /// challenges.
    pub async fn take_pending_challenge(
        &self,
        did: &str,
    ) -> Option<PendingChallenge> {
        let mut challenges = self
            .pending_challenges
            .write()
            .await;
        let matching: Vec<String> = challenges
            .iter()
            .filter(|(_, p)| p.did == did)
            .map(|(k, _)| k.clone())
            .collect();
        if matching.is_empty() {
            return None;
        }
        let mut pending: Vec<PendingChallenge> = matching
            .iter()
            .filter_map(|k| challenges.remove(k))
            .collect();
        pending.sort_by_key(|p| p.created_at);
        pending.pop()
    }

    /// Create a new session bound to the surface it was minted for.
    ///
    /// `surface_id` must come from server-side state (the authenticating
    /// surface's own `surface_id`), never from a client-controlled request
    /// field — see [`DidAuthSession::surface_id`].
    pub async fn create_session(
        &self,
        did: String,
        channel_name: String,
        surface_id: String,
        ttl_seconds: u64,
    ) -> DidAuthSession {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let session = DidAuthSession {
            session_id: session_id.clone(),
            did,
            channel_name,
            surface_id,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
            challenge: None,
        };

        if let Err(e) = self
            .storage
            .save(&session)
            .await
        {
            tracing::error!("Failed to persist DID auth session: {}", e);
        }

        session
    }

    /// Get a session by session_id
    pub async fn get_session(
        &self,
        session_id: &str,
    ) -> Option<DidAuthSession> {
        let sessions = self.sessions().read().await;

        if let Some(session) = sessions.get(session_id) {
            // Check if expired
            if chrono::Utc::now() > session.expires_at {
                return None;
            }
            Some(session.clone())
        } else {
            None
        }
    }

    /// Clean up expired sessions and challenges
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now();

        // Clean up expired sessions
        let expired_ids: Vec<String> = {
            let sessions = self.sessions().read().await;
            sessions
                .iter()
                .filter(|(_, s)| now > s.expires_at)
                .map(|(id, _)| id.clone())
                .collect()
        };

        if !expired_ids.is_empty() {
            for id in &expired_ids {
                if let Err(e) = self.storage.delete(id).await {
                    tracing::warn!("Failed to delete expired DID auth session {}: {}", id, e);
                }
            }
            tracing::info!("Cleaned up {} expired DID auth session(s)", expired_ids.len());
        }

        // Clean up challenges (in-memory only)
        {
            let mut challenges = self
                .pending_challenges
                .write()
                .await;
            challenges.retain(|_, challenge| now <= challenge.expires_at);
        }
    }

    /// Get session count (for monitoring)
    #[allow(dead_code)]
    pub async fn session_count(&self) -> usize {
        self.sessions()
            .read()
            .await
            .len()
    }

    /// Get pending challenge count (for monitoring)
    #[allow(dead_code)]
    pub async fn pending_challenge_count(&self) -> usize {
        self.pending_challenges
            .read()
            .await
            .len()
    }
}

impl Default for DidAuthSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn take_pending_challenge_returns_none_when_no_challenge() {
        let store = DidAuthSessionStore::new();
        assert!(
            store
                .take_pending_challenge("did:example:none")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn take_pending_challenge_removes_challenge_after_consume() {
        let store = DidAuthSessionStore::new();
        let did = "did:example:alice".to_string();
        store
            .create_challenge(did.clone(), 60)
            .await;
        assert!(
            store
                .take_pending_challenge(&did)
                .await
                .is_some()
        );
        assert!(
            store
                .take_pending_challenge(&did)
                .await
                .is_none(),
            "second take must find nothing"
        );
    }

    #[tokio::test]
    async fn take_pending_challenge_picks_newest_and_drops_older() {
        let store = DidAuthSessionStore::new();
        let did = "did:example:bob".to_string();
        let first = store
            .create_challenge(did.clone(), 60)
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let second = store
            .create_challenge(did.clone(), 60)
            .await;
        let taken = store
            .take_pending_challenge(&did)
            .await
            .unwrap();
        assert_eq!(taken.challenge, second, "must pick the newest challenge");
        assert_ne!(taken.challenge, first);
        assert!(
            store
                .take_pending_challenge(&did)
                .await
                .is_none(),
            "older challenge must be dropped on the same call"
        );
    }

    #[tokio::test]
    async fn take_pending_challenge_scopes_by_did() {
        let store = DidAuthSessionStore::new();
        store
            .create_challenge("did:example:alice".to_string(), 60)
            .await;
        store
            .create_challenge("did:example:bob".to_string(), 60)
            .await;
        let alice = store
            .take_pending_challenge("did:example:alice")
            .await
            .unwrap();
        assert_eq!(alice.did, "did:example:alice");
        let bob = store
            .take_pending_challenge("did:example:bob")
            .await
            .unwrap();
        assert_eq!(bob.did, "did:example:bob");
    }
}
