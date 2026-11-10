//! Session management for DID Authentication
//!
//! Maintains session state for authenticated DIDs on channels

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::storage::filesystem::{
    StorableEntity, StorageBackend, in_memory_storage_with_timeout, loggable_id, move_entities_to_dir,
    remove_entities_not_named_by_id, rwlock_storage, token_storage_id,
};

/// Storage entity name of DID Auth sessions.
const ENTITY_NAME: &str = "didauth_session";

/// Subdirectory of the sessions directory that holds DID Auth sessions, apart from
/// dashboard sessions.
const STORAGE_SUBDIRECTORY: &str = "didauth";

/// Session information for an authenticated DID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidAuthSession {
    /// [`token_storage_id`] of the session id given to the client, and the record's
    /// storage key. The session id itself is never stored. Empty in a record an
    /// earlier version stored under the session id.
    #[serde(default)]
    pub session_id_hash: String,

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

    /// The variant of the surface that served the request the session was
    /// minted on, `None` for the base surface. Written from server-side
    /// state at mint time, like `surface_id`: a session authenticates only at
    /// the view it was minted on, so one minted on a variant whose
    /// `allowed_dids` name its DID is never taken at a view whose list may
    /// not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,

    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the session expires
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// The challenge that was issued (for verification)
    pub challenge: Option<String>,
}

impl StorableEntity for DidAuthSession {
    /// A record an earlier version stored is keyed by the session id itself until
    /// startup removes it.
    const ID_IS_SECRET: bool = true;

    fn id(&self) -> &str {
        &self.session_id_hash
    }
}

/// The view of a surface a caller authenticates at: the surface, the variant
/// serving the request (`None` for the base surface) and the surface's tenant.
/// A DID Auth session is minted on one surface and variant and authenticates
/// only there; a JWT Bearer token this gateway's STS minted is accepted only
/// where its managed connection's tenant may reach. All come from server-side
/// state, never from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionView<'a> {
    pub surface_id: &'a str,
    pub variant_id: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
}

impl<'a> SessionView<'a> {
    /// The base view of the global surface `surface_id`.
    #[cfg(test)]
    pub fn base(surface_id: &'a str) -> Self {
        Self {
            surface_id,
            variant_id: None,
            tenant_id: None,
        }
    }

    /// Whether `session` was minted on this view.
    pub fn minted(
        &self,
        session: &DidAuthSession,
    ) -> bool {
        !session.surface_id.is_empty()
            && session.surface_id == self.surface_id
            && session.variant_id.as_deref() == self.variant_id
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

    /// Create a new session store with filesystem persistence in the `didauth`
    /// subdirectory of `sessions_path`, which holds the dashboard sessions. DID Auth
    /// sessions found in `sessions_path` itself are moved into the subdirectory first.
    /// Then a session file not named by its session id hash, such as one an earlier
    /// version named by the session id itself, is removed, and its caller
    /// authenticates again.
    pub async fn with_storage(sessions_path: PathBuf) -> Result<Self> {
        let storage_path = sessions_path.join(STORAGE_SUBDIRECTORY);
        let moved = move_entities_to_dir::<DidAuthSession>(&sessions_path, &storage_path, ENTITY_NAME).await?;
        if moved > 0 {
            tracing::info!("Moved {} DID auth session file(s) into {}", moved, storage_path.display());
        }
        let unhashed = remove_entities_not_named_by_id::<DidAuthSession>(&storage_path, ENTITY_NAME).await?;
        if unhashed > 0 {
            tracing::info!(
                "Removed {} DID auth session(s) not stored under their session id hash; their callers authenticate again",
                unhashed
            );
        }
        let storage: Box<dyn StorageBackend<DidAuthSession>> = rwlock_storage(storage_path, ENTITY_NAME).await?;

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
                tracing::warn!(
                    "Failed to delete expired DID auth session {}: {}",
                    loggable_id::<DidAuthSession>(id),
                    e
                );
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
            .insert(
                session
                    .session_id_hash
                    .clone(),
                session,
            );
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

    /// Create a new session bound to the view it was minted on. Returns the session
    /// id to give the client, which is stored only as its hash, and the session.
    ///
    /// `view` must come from server-side state (the authenticating surface's
    /// own `surface_id` and the variant serving the request), never from a
    /// client-controlled request field - see [`DidAuthSession::surface_id`].
    pub async fn create_session(
        &self,
        did: String,
        channel_name: String,
        view: SessionView<'_>,
        ttl_seconds: u64,
    ) -> (String, DidAuthSession) {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let session = DidAuthSession {
            session_id_hash: token_storage_id(&session_id),
            did,
            channel_name,
            surface_id: view.surface_id.to_string(),
            variant_id: view
                .variant_id
                .map(str::to_string),
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

        (session_id, session)
    }

    /// Get a session by the session id given to the client
    pub async fn get_session(
        &self,
        session_id: &str,
    ) -> Option<DidAuthSession> {
        let sessions = self.sessions().read().await;

        if let Some(session) = sessions.get(&token_storage_id(session_id)) {
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
                    tracing::warn!(
                        "Failed to delete expired DID auth session {}: {}",
                        loggable_id::<DidAuthSession>(id),
                        e
                    );
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
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;
    use crate::observability::loggable;

    const SESSION_ID: &str = "7c1e5a90-2d4b-4f6e-9a8c-b1d2e3f4a5b6";

    fn did_auth_session(
        session_id: &str,
        expires_in_seconds: i64,
    ) -> DidAuthSession {
        let now = chrono::Utc::now();
        DidAuthSession {
            session_id_hash: token_storage_id(session_id),
            did: "did:example:alice".to_string(),
            channel_name: "surface-1".to_string(),
            surface_id: "surface-1".to_string(),
            variant_id: None,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(expires_in_seconds),
            challenge: None,
        }
    }

    fn file_names(directory: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .into_string()
                    .unwrap()
            })
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn a_session_is_stored_under_its_session_id_hash_and_never_holds_the_session_id() {
        let sessions_directory = tempfile::tempdir().unwrap();
        let store = DidAuthSessionStore::with_storage(
            sessions_directory
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap();

        let (session_id, session) = store
            .create_session("did:example:alice".into(), "surface-1".into(), SessionView::base("surface-1"), 60)
            .await;

        let hash = token_storage_id(&session_id);
        assert_eq!(session.session_id_hash, hash);
        let storage_path = sessions_directory
            .path()
            .join(STORAGE_SUBDIRECTORY);
        assert_eq!(file_names(&storage_path), vec![format!("{hash}.json")]);
        let record = std::fs::read_to_string(storage_path.join(format!("{hash}.json"))).unwrap();
        assert!(!record.contains(&session_id), "{record}");
        assert_eq!(
            store
                .get_session(&session_id)
                .await
                .map(|session| session.did),
            Some("did:example:alice".to_string())
        );
        assert!(
            store
                .get_session(&hash)
                .await
                .is_none(),
            "the stored hash is not a session id"
        );
    }

    #[tokio::test]
    async fn startup_removes_a_session_not_stored_under_its_session_id_hash() {
        let sessions_directory = tempfile::tempdir().unwrap();
        let sessions_path = sessions_directory.path();
        let (current, _) = DidAuthSessionStore::with_storage(sessions_path.to_path_buf())
            .await
            .unwrap()
            .create_session("did:example:bob".into(), "surface-1".into(), SessionView::base("surface-1"), 3600)
            .await;
        let now = chrono::Utc::now();
        let stored_under_its_session_id = |session_id: &str| {
            serde_json::to_vec(&serde_json::json!({
                "session_id": session_id,
                "did": "did:example:alice",
                "channel_name": "surface-1",
                "surface_id": "surface-1",
                "created_at": now,
                "expires_at": now + chrono::Duration::hours(1),
                "challenge": null,
            }))
            .unwrap()
        };
        let in_the_sessions_directory = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
        std::fs::write(
            sessions_path.join(format!("{in_the_sessions_directory}.json")),
            stored_under_its_session_id(in_the_sessions_directory),
        )
        .unwrap();
        let storage_path = sessions_path.join(STORAGE_SUBDIRECTORY);
        std::fs::write(storage_path.join(format!("{SESSION_ID}.json")), stored_under_its_session_id(SESSION_ID))
            .unwrap();
        let logs = FormattedLogs::capture();

        let store = DidAuthSessionStore::with_storage(sessions_path.to_path_buf())
            .await
            .unwrap();

        assert_eq!(file_names(sessions_path), vec![STORAGE_SUBDIRECTORY.to_string()]);
        assert_eq!(file_names(&storage_path), vec![format!("{}.json", token_storage_id(&current))]);
        for session_id in [in_the_sessions_directory, SESSION_ID] {
            assert!(
                store
                    .get_session(session_id)
                    .await
                    .is_none()
            );
        }
        assert!(
            store
                .get_session(&current)
                .await
                .is_some()
        );
        let text = logs.text();
        assert!(text.contains("Moved 1 DID auth session file(s) into"), "{text}");
        assert!(
            text.contains(
                "Removed 2 DID auth session(s) not stored under their session id hash; their callers authenticate again"
            ),
            "{text}"
        );
        assert!(text.contains("Loaded 1 DID auth session(s) from disk"), "{text}");
        assert!(!text.contains(SESSION_ID), "{text}");
        assert!(!text.contains(in_the_sessions_directory), "{text}");
    }

    #[tokio::test]
    async fn session_save_startup_scan_and_delete_never_log_the_session_id() {
        let sessions_directory = tempfile::tempdir().unwrap();
        let logs = FormattedLogs::capture();

        let store = DidAuthSessionStore::with_storage(
            sessions_directory
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap();
        let (session_id, _) = store
            .create_session("did:example:alice".into(), "surface-1".into(), SessionView::base("surface-1"), 0)
            .await;
        let hash = token_storage_id(&session_id);
        let session_file = sessions_directory
            .path()
            .join(STORAGE_SUBDIRECTORY)
            .join(format!("{hash}.json"));
        assert!(session_file.exists());
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let reloaded = DidAuthSessionStore::with_storage(
            sessions_directory
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap();

        assert!(
            reloaded
                .get_session(&session_id)
                .await
                .is_none()
        );
        assert!(!session_file.exists());
        let text = logs.text();
        let prefix = loggable::secret(&hash);
        assert!(text.contains(&format!("Saved didauth_session {prefix} to")), "{text}");
        assert!(text.contains("Loaded didauth_session from"), "{text}");
        assert!(text.contains(&format!("Deleted didauth_session {prefix}")), "{text}");
        assert!(!text.contains(&session_id), "{text}");
    }

    #[tokio::test]
    async fn failed_session_delete_logs_only_a_session_id_prefix() {
        let sessions_directory = tempfile::tempdir().unwrap();
        let store = DidAuthSessionStore::with_storage(
            sessions_directory
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap();
        let session_id = "expired/0123456789-did-auth-session";
        store
            .sessions()
            .write()
            .await
            .insert(session_id.to_string(), did_auth_session(session_id, -60));
        let logs = FormattedLogs::capture();

        store.cleanup_expired().await;

        let text = logs.text();
        assert!(text.contains("Failed to delete expired DID auth session expired/..."), "{text}");
        assert!(!text.contains(session_id), "{text}");
    }

    #[tokio::test]
    async fn startup_moves_did_auth_sessions_out_of_the_shared_sessions_directory() {
        let sessions_directory = tempfile::tempdir().unwrap();
        let sessions_path = sessions_directory.path();
        let did_auth_file_name = format!("{}.json", token_storage_id(SESSION_ID));
        let did_auth_file = sessions_path.join(&did_auth_file_name);
        std::fs::write(&did_auth_file, serde_json::to_vec(&did_auth_session(SESSION_ID, 3600)).unwrap()).unwrap();
        let dashboard_token = "0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5";
        let dashboard_file = sessions_path.join(format!("{}.json", token_storage_id(dashboard_token)));
        let now = chrono::Utc::now();
        let dashboard_session = crate::auth::session::Session {
            token_hash: token_storage_id(dashboard_token),
            username: "alice@example.com".to_string(),
            user_id: "user-a".to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(20),
            terms_gate: crate::auth::session::TermsSessionGate::AllowedAtLogin,
        };
        std::fs::write(&dashboard_file, serde_json::to_vec(&dashboard_session).unwrap()).unwrap();
        let logs = FormattedLogs::capture();

        let store = DidAuthSessionStore::with_storage(sessions_path.to_path_buf())
            .await
            .unwrap();
        let dashboard_sessions = crate::auth::SessionManager::with_storage(20, sessions_path.to_path_buf())
            .await
            .unwrap();

        assert!(
            store
                .get_session(SESSION_ID)
                .await
                .is_some()
        );
        assert!(
            dashboard_sessions
                .validate_session(dashboard_token)
                .await
                .is_some()
        );
        assert!(!did_auth_file.exists());
        assert!(
            sessions_path
                .join(STORAGE_SUBDIRECTORY)
                .join(&did_auth_file_name)
                .exists()
        );
        assert!(dashboard_file.exists());
        let text = logs.text();
        assert!(text.contains("Moved 1 DID auth session file(s) into"), "{text}");
        assert!(text.contains("Loaded 1 DID auth session(s) from disk"), "{text}");
        assert!(text.contains("Loaded 1 session(s) from disk"), "{text}");
        assert!(!text.contains("ERROR"), "{text}");
        assert!(!text.contains(SESSION_ID), "{text}");
        assert!(!text.contains(dashboard_token), "{text}");
    }

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
