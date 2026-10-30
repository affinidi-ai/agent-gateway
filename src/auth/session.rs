use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::observability::loggable;
use crate::storage::filesystem::{
    StorableEntity, StorageBackend, in_memory_storage_with_timeout, loggable_id, rwlock_storage,
};

/// Manager for authenticated sessions with filesystem persistence
pub struct SessionManager {
    storage: Box<dyn StorageBackend<Session>>,
    timeout_minutes: u64,
    terms_gate_update_lock: RwLock<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TermsSessionGate {
    #[default]
    LegacyAllowed,
    AllowedAtLogin,
    ConsentPending,
}

/// Session data
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session token (used as storage key)
    #[serde(default)]
    pub token: String,
    pub username: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub terms_gate: TermsSessionGate,
}

impl std::fmt::Debug for Session {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("token", &loggable::secret(&self.token))
            .field("username", &self.username)
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("terms_gate", &self.terms_gate)
            .finish()
    }
}

impl StorableEntity for Session {
    const ID_IS_SECRET: bool = true;

    fn id(&self) -> &str {
        &self.token
    }

    fn on_load(&mut self) {
        // No fixup needed - token is stored in the struct
    }
}

impl SessionManager {
    /// Create a new session manager (in-memory only)
    pub fn new() -> Self {
        Self::with_timeout(20) // Default to 20 minutes
    }

    /// Create a new session manager with a custom timeout (in-memory only)
    pub fn with_timeout(timeout_minutes: u64) -> Self {
        Self {
            storage: in_memory_storage_with_timeout(timeout_minutes),
            timeout_minutes,
            terms_gate_update_lock: RwLock::new(()),
        }
    }

    /// Create a new session manager with filesystem persistence
    pub async fn with_storage(
        timeout_minutes: u64,
        storage_path: PathBuf,
    ) -> Result<Self> {
        let storage: Box<dyn StorageBackend<Session>> = rwlock_storage(storage_path.clone(), "session").await?;

        // Fix up loaded sessions: set token from cache key for legacy files that lack it,
        // and remove expired ones
        let now = chrono::Utc::now();
        let mut expired_tokens = Vec::new();
        {
            let mut cache = storage
                .raw_cache()
                .expect("cached storage")
                .write()
                .await;
            for (key, session) in cache.iter_mut() {
                if session.token.is_empty() {
                    session.token = key.clone();
                }
                if now >= session.expires_at {
                    expired_tokens.push(key.clone());
                }
            }
            for token in &expired_tokens {
                cache.remove(token);
            }
        }

        // Delete expired session files from disk
        for token in &expired_tokens {
            if let Err(e) = storage.delete(token).await {
                tracing::warn!("Failed to delete expired session file {}: {}", loggable_id::<Session>(token), e);
            }
        }

        if !expired_tokens.is_empty() {
            tracing::info!("Cleaned up {} expired session(s) on load", expired_tokens.len());
        }

        let loaded = storage
            .raw_cache()
            .expect("cached storage")
            .read()
            .await
            .len();
        if loaded > 0 {
            tracing::info!("Loaded {} session(s) from disk", loaded);
        }

        Ok(Self {
            storage,
            timeout_minutes,
            terms_gate_update_lock: RwLock::new(()),
        })
    }

    /// Get the session timeout in seconds
    pub fn timeout_seconds(&self) -> u64 {
        self.timeout_minutes * 60
    }

    /// Get a reference to the active session cache
    fn sessions(&self) -> &Arc<RwLock<HashMap<String, Session>>> {
        self.storage
            .raw_cache()
            .expect("storage backend provides raw_cache")
    }

    /// Create a new session for a user
    #[cfg(test)]
    pub async fn create_session(
        &self,
        username: String,
        user_id: String,
    ) -> String {
        self.create_session_with_terms_gate(username, user_id, TermsSessionGate::AllowedAtLogin)
            .await
    }

    pub async fn create_session_with_terms_gate(
        &self,
        username: String,
        user_id: String,
        terms_gate: TermsSessionGate,
    ) -> String {
        let _guard = self
            .terms_gate_update_lock
            .read()
            .await;
        let session_token = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let session = Session {
            token: session_token.clone(),
            username,
            user_id: user_id.clone(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(self.timeout_minutes as i64),
            terms_gate,
        };

        if let Err(e) = self
            .storage
            .save(&session)
            .await
        {
            tracing::error!("Failed to persist session: {}", e);
        }

        tracing::info!("Session created for user_id: {}", user_id);

        session_token
    }

    /// Mark every pending session for a user as allowed for its remaining lifetime.
    pub async fn allow_pending_terms_sessions(
        &self,
        user_id: &str,
    ) -> Result<usize> {
        let _guard = self
            .terms_gate_update_lock
            .write()
            .await;
        let pending_sessions = {
            let sessions = self.sessions().read().await;
            sessions
                .values()
                .filter(|session| session.user_id == user_id && session.terms_gate == TermsSessionGate::ConsentPending)
                .cloned()
                .collect::<Vec<_>>()
        };

        for mut session in pending_sessions
            .iter()
            .cloned()
        {
            session.terms_gate = TermsSessionGate::AllowedAtLogin;
            self.storage
                .save(&session)
                .await?;
        }

        Ok(pending_sessions.len())
    }

    /// Validate a session token and return (username, user_id)
    /// This also refreshes the session expiration time (sliding expiration)
    pub async fn validate_session(
        &self,
        token: &str,
    ) -> Option<(String, String)> {
        self.validate_session_record(token)
            .await
            .map(|session| (session.username, session.user_id))
    }

    pub async fn validate_session_record(
        &self,
        token: &str,
    ) -> Option<Session> {
        if token.starts_with(crate::access_tokens::TOKEN_PREFIX) {
            return None;
        }
        let _guard = self
            .terms_gate_update_lock
            .read()
            .await;
        let token_prefix = loggable_id::<Session>(token);
        tracing::debug!("Validating session token: {}", token_prefix);

        let mut session = match self
            .storage
            .get(token)
            .await
            .ok()?
        {
            Some(s) => s,
            None => {
                tracing::warn!("Session token {} not found", token_prefix);
                return None;
            }
        };

        let now = chrono::Utc::now();
        if now >= session.expires_at {
            tracing::debug!(
                "Session {} found for user_id {} - expired (expired: {})",
                token_prefix,
                session.user_id,
                session.expires_at,
            );
            return None;
        }

        tracing::debug!(
            "Session {} found for user_id {} - valid (expires: {}, {} seconds remaining)",
            token_prefix,
            session.user_id,
            session.expires_at,
            (session.expires_at - now).num_seconds()
        );

        // Refresh expiration time (sliding window)
        session.expires_at = now + chrono::Duration::minutes(self.timeout_minutes as i64);
        let result = session.clone();

        tracing::debug!(
            "Session {} refreshed for user_id {} - new expiration: {}",
            token_prefix,
            session.user_id,
            session.expires_at
        );

        if let Err(e) = self
            .storage
            .save(&session)
            .await
        {
            tracing::error!("Failed to persist session update to disk: {}", e);
        }

        Some(result)
    }

    /// Remove a session (logout)
    pub async fn remove_session(
        &self,
        token: &str,
    ) {
        if let Err(e) = self
            .storage
            .delete(token)
            .await
        {
            tracing::error!("Failed to delete session: {}", e);
        }
    }

    /// Revoke all active sessions belonging to a given user.
    ///
    /// Used when a user is disabled, deleted, or has their role changed —
    /// any in-flight bearer tokens must stop working immediately so that
    /// authorization decisions cannot be evaded by an already-issued session.
    ///
    /// Returns the number of sessions removed.
    pub async fn remove_sessions_for_user(
        &self,
        user_id: &str,
    ) -> usize {
        let tokens: Vec<String> = {
            let cache = self.sessions();
            let sessions = cache.read().await;
            sessions
                .iter()
                .filter(|(_, session)| session.user_id == user_id)
                .map(|(token, _)| token.clone())
                .collect()
        };

        if tokens.is_empty() {
            return 0;
        }

        for token in &tokens {
            if let Err(e) = self
                .storage
                .delete(token)
                .await
            {
                tracing::warn!(
                    "Failed to delete session {} for user {}: {}",
                    loggable_id::<Session>(token),
                    user_id,
                    e
                );
            }
        }

        tracing::info!("Revoked {} session(s) for user_id={}", tokens.len(), user_id);
        tokens.len()
    }

    /// Clean up expired sessions from memory and disk
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now();

        let expired_tokens: Vec<String> = {
            let cache = self.sessions();
            let sessions = cache.read().await;
            sessions
                .iter()
                .filter(|(_, session)| now >= session.expires_at)
                .map(|(token, _)| token.clone())
                .collect()
        };

        if expired_tokens.is_empty() {
            return;
        }

        for token in &expired_tokens {
            if let Err(e) = self
                .storage
                .delete(token)
                .await
            {
                tracing::warn!("Failed to delete expired session {}: {}", loggable_id::<Session>(token), e);
            }
        }

        tracing::info!("Cleaned up {} expired session(s)", expired_tokens.len());
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;

    const TOKEN: &str = "0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5";

    fn session_with_token(
        token: &str,
        user_id: &str,
        expires_in_minutes: i64,
    ) -> Session {
        let now = chrono::Utc::now();
        Session {
            token: token.to_string(),
            username: "alice@example.com".to_string(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(expires_in_minutes),
            terms_gate: TermsSessionGate::AllowedAtLogin,
        }
    }

    #[test]
    fn session_debug_shows_only_a_token_prefix() {
        let rendered = format!("{:?}", session_with_token(TOKEN, "user-a", 20));

        assert!(rendered.contains(r#"token: "0f2c9d7e...""#), "{rendered}");
        assert!(rendered.contains(r#"user_id: "user-a""#), "{rendered}");
        assert!(!rendered.contains(TOKEN), "{rendered}");
    }

    #[tokio::test]
    async fn session_save_startup_scan_and_delete_log_only_a_token_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let logs = FormattedLogs::capture();

        let manager = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();
        let token = manager
            .create_session("alice@example.com".into(), "user-a".into())
            .await;
        let reloaded = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();
        assert!(
            reloaded
                .validate_session(&token)
                .await
                .is_some()
        );
        reloaded
            .remove_session(&token)
            .await;

        let text = logs.text();
        let prefix = loggable::secret(&token);
        assert!(text.contains("Session created for user_id: user-a"), "{text}");
        assert!(text.contains(&format!("Saved session {prefix} to")), "{text}");
        assert!(text.contains("Loaded session from"), "{text}");
        assert!(text.contains(&format!("Deleted session {prefix}")), "{text}");
        assert!(!text.contains(&token), "{text}");
        assert!(!text.contains("alice@example.com"), "{text}");
    }

    #[tokio::test]
    async fn failed_session_deletes_log_only_a_token_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let manager = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();
        let revoked = "revoked/0123456789-session-token";
        let expired = "expired/0123456789-session-token";
        {
            let mut sessions = manager
                .sessions()
                .write()
                .await;
            sessions.insert(revoked.to_string(), session_with_token(revoked, "user-a", 20));
            sessions.insert(expired.to_string(), session_with_token(expired, "user-b", -1));
        }
        let logs = FormattedLogs::capture();

        assert_eq!(
            manager
                .remove_sessions_for_user("user-a")
                .await,
            1
        );
        manager
            .cleanup_expired()
            .await;

        let text = logs.text();
        assert!(text.contains("Failed to delete session revoked/... for user user-a"), "{text}");
        assert!(text.contains("Failed to delete expired session expired/..."), "{text}");
        assert!(!text.contains(revoked), "{text}");
        assert!(!text.contains(expired), "{text}");
    }

    #[tokio::test]
    async fn an_access_token_is_never_validated_as_a_session() {
        let manager = SessionManager::new();
        let access_token = "agpat_K7xQ2mZp9vR4tY8wB3nL6cF1hJ5dS0gA2eU7iO4kM9q";
        let unknown_session = "1d2e3f4a-5b6c-4d7e-8f90-a1b2c3d4e5f6";
        let logs = FormattedLogs::capture();

        assert!(
            manager
                .validate_session(access_token)
                .await
                .is_none()
        );
        assert!(
            manager
                .validate_session(unknown_session)
                .await
                .is_none()
        );

        let text = logs.text();
        assert!(text.contains("Session token 1d2e3f4a... not found"), "{text}");
        assert!(!text.contains("agpat_"), "{text}");
    }

    #[tokio::test]
    async fn remove_sessions_for_user_removes_all_matching() {
        let mgr = SessionManager::new();

        let t1 = mgr
            .create_session("alice".into(), "user-a".into())
            .await;
        let t2 = mgr
            .create_session("alice".into(), "user-a".into())
            .await;
        let t_other = mgr
            .create_session("bob".into(), "user-b".into())
            .await;

        let removed = mgr
            .remove_sessions_for_user("user-a")
            .await;
        assert_eq!(removed, 2, "both alice sessions should be revoked");

        assert!(
            mgr.validate_session(&t1)
                .await
                .is_none(),
            "alice token 1 must be invalid after revocation"
        );
        assert!(
            mgr.validate_session(&t2)
                .await
                .is_none(),
            "alice token 2 must be invalid after revocation"
        );
        assert!(
            mgr.validate_session(&t_other)
                .await
                .is_some(),
            "bob's session must remain valid"
        );
    }

    #[tokio::test]
    async fn consent_pending_session_remains_authenticated() {
        let mgr = SessionManager::new();
        let token = mgr
            .create_session_with_terms_gate("alice".into(), "user-a".into(), TermsSessionGate::ConsentPending)
            .await;

        assert!(
            mgr.validate_session(&token)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn accepting_terms_allows_all_pending_sessions_for_user() {
        let mgr = SessionManager::new();
        let pending_one = mgr
            .create_session_with_terms_gate("alice".into(), "user-a".into(), TermsSessionGate::ConsentPending)
            .await;
        let pending_two = mgr
            .create_session_with_terms_gate("alice".into(), "user-a".into(), TermsSessionGate::ConsentPending)
            .await;
        let other = mgr
            .create_session_with_terms_gate("bob".into(), "user-b".into(), TermsSessionGate::ConsentPending)
            .await;

        assert_eq!(
            mgr.allow_pending_terms_sessions("user-a")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            mgr.validate_session_record(&pending_one)
                .await
                .unwrap()
                .terms_gate,
            TermsSessionGate::AllowedAtLogin
        );
        assert_eq!(
            mgr.validate_session_record(&pending_two)
                .await
                .unwrap()
                .terms_gate,
            TermsSessionGate::AllowedAtLogin
        );
        assert_eq!(
            mgr.validate_session_record(&other)
                .await
                .unwrap()
                .terms_gate,
            TermsSessionGate::ConsentPending
        );
    }

    #[tokio::test]
    async fn remove_sessions_for_user_returns_zero_when_no_match() {
        let mgr = SessionManager::new();
        let t = mgr
            .create_session("alice".into(), "user-a".into())
            .await;

        let removed = mgr
            .remove_sessions_for_user("user-does-not-exist")
            .await;
        assert_eq!(removed, 0);

        assert!(
            mgr.validate_session(&t)
                .await
                .is_some(),
            "unrelated session must not be affected"
        );
    }
}
