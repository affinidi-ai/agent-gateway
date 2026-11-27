use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::filesystem::{
    StorableEntity, StorageBackend, in_memory_storage_with_timeout, loggable_id, remove_entities_not_named_by_id,
    rwlock_storage, token_storage_id,
};

/// Storage entity name of dashboard sessions.
const ENTITY_NAME: &str = "session";

/// Manager for authenticated sessions with filesystem persistence
pub struct SessionManager {
    storage: Box<dyn StorageBackend<Session>>,
    timeout_minutes: u64,
    terms_gate_update_lock: RwLock<()>,
    oidc_issuer: std::sync::OnceLock<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// [`token_storage_id`] of the session token, and the record's storage key. The
    /// token itself is never stored. Empty in a record an earlier version stored under
    /// the token.
    #[serde(default)]
    pub token_hash: String,
    pub username: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub terms_gate: TermsSessionGate,
    /// The OpenID provider sign-in this session came from (OIDC mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcSessionBinding>,
}

/// The OpenID provider sign-in a session came from, so a logout from that provider can find the
/// session: the provider, the account (`sub`), and the provider's own session id (`sid`) when its
/// ID token carried one. The ID token is kept only to name the sign-in when the dashboard asks the
/// provider to sign the person out (`id_token_hint`); its `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcSessionBinding {
    pub issuer: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl std::fmt::Debug for OidcSessionBinding {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("OidcSessionBinding")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("sid", &self.sid)
            .field(
                "id_token",
                &self
                    .id_token
                    .as_ref()
                    .map(|_| crate::observability::loggable::REDACTED),
            )
            .finish()
    }
}

/// What [`SessionManager::remove_sessions_where`] did: the sessions it ended, and how many it
/// selected but could not delete, which stay valid.
#[derive(Debug, Default)]
pub struct RemovedSessions {
    pub ended: Vec<Session>,
    pub failed: usize,
}

impl StorableEntity for Session {
    /// A record an earlier version stored is keyed by the token itself until startup
    /// removes it.
    const ID_IS_SECRET: bool = true;

    fn id(&self) -> &str {
        &self.token_hash
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
            oidc_issuer: std::sync::OnceLock::new(),
        }
    }

    /// Create a new session manager with filesystem persistence. A session file not
    /// named by its token hash, such as one an earlier version named by the token
    /// itself, is removed first, and its user signs in again.
    pub async fn with_storage(
        timeout_minutes: u64,
        storage_path: PathBuf,
    ) -> Result<Self> {
        let unhashed = remove_entities_not_named_by_id::<Session>(&storage_path, ENTITY_NAME).await?;
        if unhashed > 0 {
            tracing::info!(
                "Removed {} session(s) not stored under their token hash; their users sign in again",
                unhashed
            );
        }
        let storage: Box<dyn StorageBackend<Session>> = rwlock_storage(storage_path.clone(), ENTITY_NAME).await?;

        let now = chrono::Utc::now();
        let mut expired_ids = Vec::new();
        {
            let mut cache = storage
                .raw_cache()
                .expect("cached storage")
                .write()
                .await;
            for (id, session) in cache.iter() {
                if now >= session.expires_at {
                    expired_ids.push(id.clone());
                }
            }
            for id in &expired_ids {
                cache.remove(id);
            }
        }

        // Delete expired session files from disk
        for id in &expired_ids {
            if let Err(e) = storage.delete(id).await {
                tracing::warn!("Failed to delete expired session file {}: {}", loggable_id::<Session>(id), e);
            }
        }

        if !expired_ids.is_empty() {
            tracing::info!("Cleaned up {} expired session(s) on load", expired_ids.len());
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
            oidc_issuer: std::sync::OnceLock::new(),
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
        self.create_session_with_terms_gate(username, user_id, TermsSessionGate::AllowedAtLogin, None)
            .await
    }

    /// Create a session for a user, bound to the OpenID provider sign-in `oidc` names when it
    /// came from one.
    pub async fn create_session_with_terms_gate(
        &self,
        username: String,
        user_id: String,
        terms_gate: TermsSessionGate,
        oidc: Option<OidcSessionBinding>,
    ) -> String {
        let _guard = self
            .terms_gate_update_lock
            .read()
            .await;
        let session_token = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let session = Session {
            token_hash: token_storage_id(&session_token),
            username,
            user_id: user_id.clone(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(self.timeout_minutes as i64),
            terms_gate,
            oidc,
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

    /// Accept only sessions from a sign-in at the OpenID provider `issuer`, as a gateway in OIDC
    /// mode does. A session from a passkey or SAML sign-in before the switch, or from another
    /// provider, is refused: this provider's role mapping never set its role.
    pub fn accept_only_sign_ins_at(
        &self,
        issuer: &str,
    ) {
        let _ = self
            .oidc_issuer
            .set(issuer.to_string());
    }

    fn accepts(
        &self,
        session: &Session,
    ) -> bool {
        self.oidc_issuer
            .get()
            .is_none_or(|issuer| {
                session
                    .oidc
                    .as_ref()
                    .is_some_and(|binding| &binding.issuer == issuer)
            })
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
            .get(&token_storage_id(token))
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
        if !self.accepts(&session) {
            tracing::debug!(
                "Session {} for user_id {} did not come from a sign-in at the OpenID provider",
                token_prefix,
                session.user_id
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

    /// Whether `token` names a session that exists, has not expired and is accepted. Unlike
    /// [`Self::validate_session_record`], it does not extend the session.
    pub async fn is_live(
        &self,
        token: &str,
    ) -> bool {
        if token.starts_with(crate::access_tokens::TOKEN_PREFIX) {
            return false;
        }
        matches!(
            self.storage.get(&token_storage_id(token)).await,
            Ok(Some(session)) if chrono::Utc::now() < session.expires_at && self.accepts(&session)
        )
    }

    /// Remove a session (logout)
    pub async fn remove_session(
        &self,
        token: &str,
    ) {
        self.end_session(token).await;
    }

    /// Delete the session `token` names, and return it when it was live and accepted. Holds the
    /// lock session validation takes, so a request in flight cannot save the session back, and
    /// reads the session without extending it.
    pub async fn end_session(
        &self,
        token: &str,
    ) -> Option<Session> {
        let _guard = self
            .terms_gate_update_lock
            .write()
            .await;
        let id = token_storage_id(token);
        let session = self
            .storage
            .get(&id)
            .await
            .ok()
            .flatten();
        if let Err(e) = self.storage.delete(&id).await {
            tracing::error!("Failed to delete session: {}", e);
        }
        session.filter(|session| chrono::Utc::now() < session.expires_at && self.accepts(session))
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
        let removed = self
            .remove_sessions_where(|session| session.user_id == user_id)
            .await
            .ended
            .len();
        if removed > 0 {
            tracing::info!("Revoked {} session(s) for user_id={}", removed, user_id);
        }
        removed
    }

    /// Remove every session `matches` selects. Holds the lock session validation takes, so a
    /// request in flight cannot save a removed session back.
    pub async fn remove_sessions_where(
        &self,
        matches: impl Fn(&Session) -> bool,
    ) -> RemovedSessions {
        let _guard = self
            .terms_gate_update_lock
            .write()
            .await;
        let selected: Vec<(String, Session)> = {
            let cache = self.sessions();
            let sessions = cache.read().await;
            sessions
                .iter()
                .filter(|(_, session)| matches(session))
                .map(|(id, session)| (id.clone(), session.clone()))
                .collect()
        };

        let mut removed = RemovedSessions::default();
        for (id, session) in selected {
            match self.storage.delete(&id).await {
                Ok(()) => removed.ended.push(session),
                Err(e) => {
                    tracing::warn!(
                        "Failed to delete session {} for user {}: {}",
                        loggable_id::<Session>(&id),
                        session.user_id,
                        e
                    );
                    removed.failed += 1;
                }
            }
        }
        removed
    }

    /// Clean up expired sessions from memory and disk
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now();

        let expired_ids: Vec<String> = {
            let cache = self.sessions();
            let sessions = cache.read().await;
            sessions
                .iter()
                .filter(|(_, session)| now >= session.expires_at)
                .map(|(id, _)| id.clone())
                .collect()
        };

        if expired_ids.is_empty() {
            return;
        }

        for id in &expired_ids {
            if let Err(e) = self.storage.delete(id).await {
                tracing::warn!("Failed to delete expired session {}: {}", loggable_id::<Session>(id), e);
            }
        }

        tracing::info!("Cleaned up {} expired session(s)", expired_ids.len());
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory session storage whose deletes fail while `failing` is set.
#[cfg(test)]
struct FailingDeletes {
    inner: Box<dyn StorageBackend<Session>>,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl StorageBackend<Session> for FailingDeletes {
    async fn save(
        &self,
        session: &Session,
    ) -> Result<()> {
        self.inner.save(session).await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Session>> {
        self.inner.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<Session>> {
        self.inner.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        if self
            .failing
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("the disk refused the delete");
        }
        self.inner.delete(id).await
    }

    fn raw_cache(&self) -> Option<&crate::storage::filesystem::StorageCache<Session>> {
        self.inner.raw_cache()
    }
}

#[cfg(test)]
impl SessionManager {
    /// An in-memory session manager whose deletes fail while `failing` is set.
    pub(crate) fn with_failing_deletes(failing: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            storage: Box::new(FailingDeletes {
                inner: in_memory_storage_with_timeout(20),
                failing,
            }),
            timeout_minutes: 20,
            terms_gate_update_lock: RwLock::new(()),
            oidc_issuer: std::sync::OnceLock::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;
    use crate::observability::loggable;

    const TOKEN: &str = "0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5";

    fn session_with_token(
        token: &str,
        user_id: &str,
        expires_in_minutes: i64,
    ) -> Session {
        let now = chrono::Utc::now();
        Session {
            token_hash: token_storage_id(token),
            username: "alice@example.com".to_string(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(expires_in_minutes),
            terms_gate: TermsSessionGate::AllowedAtLogin,
            oidc: None,
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
    async fn a_session_is_stored_under_its_token_hash_and_never_holds_the_token() {
        let directory = tempfile::tempdir().unwrap();
        let manager = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();

        let token = manager
            .create_session("alice@example.com".into(), "user-a".into())
            .await;

        let hash = token_storage_id(&token);
        assert_eq!(file_names(directory.path()), vec![format!("{hash}.json")]);
        let record = std::fs::read_to_string(
            directory
                .path()
                .join(format!("{hash}.json")),
        )
        .unwrap();
        assert!(!record.contains(&token), "{record}");
        assert!(record.contains(&hash), "{record}");
        assert_eq!(
            manager
                .validate_session(&token)
                .await,
            Some(("alice@example.com".to_string(), "user-a".to_string()))
        );
        assert!(
            manager
                .validate_session(&hash)
                .await
                .is_none(),
            "the stored hash is not a token"
        );
    }

    #[tokio::test]
    async fn startup_removes_a_session_not_stored_under_its_token_hash() {
        let directory = tempfile::tempdir().unwrap();
        let current = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap()
            .create_session("bob@example.com".into(), "user-b".into())
            .await;
        let now = chrono::Utc::now();
        let stored_under_its_token = directory
            .path()
            .join(format!("{TOKEN}.json"));
        std::fs::write(
            &stored_under_its_token,
            serde_json::to_vec(&serde_json::json!({
                "token": TOKEN,
                "username": "alice@example.com",
                "user_id": "user-a",
                "created_at": now,
                "expires_at": now + chrono::Duration::minutes(20),
                "terms_gate": "allowed_at_login",
            }))
            .unwrap(),
        )
        .unwrap();
        let other_token = "5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e";
        let stored_under_another_hash = directory
            .path()
            .join(format!("{}.json", token_storage_id(other_token)));
        std::fs::write(
            &stored_under_another_hash,
            serde_json::to_vec(&session_with_token(TOKEN, "user-a", 20)).unwrap(),
        )
        .unwrap();
        let logs = FormattedLogs::capture();

        let manager = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();

        assert!(!stored_under_its_token.exists());
        assert!(!stored_under_another_hash.exists());
        assert_eq!(file_names(directory.path()), vec![format!("{}.json", token_storage_id(&current))]);
        assert!(
            manager
                .validate_session(TOKEN)
                .await
                .is_none()
        );
        assert!(
            manager
                .validate_session(other_token)
                .await
                .is_none()
        );
        assert_eq!(
            manager
                .validate_session(&current)
                .await,
            Some(("bob@example.com".to_string(), "user-b".to_string()))
        );
        let text = logs.text();
        assert!(
            text.contains("Removed 2 session(s) not stored under their token hash; their users sign in again"),
            "{text}"
        );
        assert!(text.contains("Loaded 1 session(s) from disk"), "{text}");
        assert!(!text.contains(TOKEN), "{text}");
    }

    #[tokio::test]
    async fn is_live_accepts_only_an_unexpired_session_and_does_not_extend_it() {
        let manager = SessionManager::new();
        let token = manager
            .create_session("alice".into(), "user-a".into())
            .await;
        let expires_at = |session: Option<Session>| {
            session
                .expect("session")
                .expires_at
        };
        let before = expires_at(
            manager
                .storage
                .get(&token_storage_id(&token))
                .await
                .unwrap(),
        );

        assert!(manager.is_live(&token).await);
        assert_eq!(
            expires_at(
                manager
                    .storage
                    .get(&token_storage_id(&token))
                    .await
                    .unwrap()
            ),
            before
        );

        manager
            .storage
            .save(&session_with_token(TOKEN, "user-a", -1))
            .await
            .unwrap();
        assert!(!manager.is_live(TOKEN).await);
        assert!(
            !manager
                .is_live(&format!("{}{}", crate::access_tokens::TOKEN_PREFIX, TOKEN))
                .await
        );

        manager
            .remove_session(&token)
            .await;
        assert!(!manager.is_live(&token).await);
    }

    #[tokio::test]
    async fn an_access_token_is_never_a_session_even_when_a_session_is_stored_under_it() {
        let manager = SessionManager::new();
        let access_token = format!("{}{}", crate::access_tokens::TOKEN_PREFIX, TOKEN);
        manager
            .storage
            .save(&session_with_token(&access_token, "user-a", 60))
            .await
            .unwrap();
        manager
            .storage
            .save(&session_with_token(TOKEN, "user-a", 60))
            .await
            .unwrap();

        assert!(
            manager
                .validate_session_record(&access_token)
                .await
                .is_none()
        );
        assert!(
            !manager
                .is_live(&access_token)
                .await
        );
        assert_eq!(
            manager
                .validate_session_record(TOKEN)
                .await
                .map(|session| session.user_id),
            Some("user-a".to_string())
        );
        assert!(manager.is_live(TOKEN).await);
    }

    #[tokio::test]
    async fn session_save_startup_scan_and_delete_never_log_the_token() {
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
        let prefix = loggable::secret(&token_storage_id(&token));
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
            0,
            "a session that could not be deleted did not end"
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
            .create_session_with_terms_gate("alice".into(), "user-a".into(), TermsSessionGate::ConsentPending, None)
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
            .create_session_with_terms_gate("alice".into(), "user-a".into(), TermsSessionGate::ConsentPending, None)
            .await;
        let pending_two = mgr
            .create_session_with_terms_gate("alice".into(), "user-a".into(), TermsSessionGate::ConsentPending, None)
            .await;
        let other = mgr
            .create_session_with_terms_gate("bob".into(), "user-b".into(), TermsSessionGate::ConsentPending, None)
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

    fn binding(sid: &str) -> OidcSessionBinding {
        OidcSessionBinding {
            issuer: "https://idp.example.com".to_string(),
            subject: "user-1".to_string(),
            sid: Some(sid.to_string()),
            id_token: Some("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.secret-signature".to_string()),
        }
    }

    #[tokio::test]
    async fn remove_sessions_where_ends_only_the_sessions_it_selects_and_returns_them() {
        let mgr = SessionManager::new();
        let first = mgr
            .create_session_with_terms_gate(
                "alice".into(),
                "user-a".into(),
                TermsSessionGate::AllowedAtLogin,
                Some(binding("op-1")),
            )
            .await;
        let second = mgr
            .create_session_with_terms_gate(
                "alice".into(),
                "user-a".into(),
                TermsSessionGate::AllowedAtLogin,
                Some(binding("op-2")),
            )
            .await;
        let unbound = mgr
            .create_session("alice".into(), "user-a".into())
            .await;

        let removed = mgr
            .remove_sessions_where(|session| {
                session
                    .oidc
                    .as_ref()
                    .is_some_and(|bound| bound.sid.as_deref() == Some("op-1"))
            })
            .await;

        assert_eq!(removed.failed, 0);
        assert_eq!(removed.ended.len(), 1);
        assert_eq!(removed.ended[0].oidc, Some(binding("op-1")));
        assert!(
            mgr.validate_session(&first)
                .await
                .is_none()
        );
        assert!(
            mgr.validate_session(&second)
                .await
                .is_some()
        );
        assert!(
            mgr.validate_session(&unbound)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_session_that_cannot_be_deleted_is_reported_and_stays_valid() {
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mgr = SessionManager::with_failing_deletes(failing.clone());
        let alice = mgr
            .create_session("alice".into(), "user-a".into())
            .await;

        let removed = mgr
            .remove_sessions_where(|session| session.user_id == "user-a")
            .await;
        assert!(removed.ended.is_empty());
        assert_eq!(removed.failed, 1);
        assert!(
            mgr.validate_session(&alice)
                .await
                .is_some()
        );

        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        let removed = mgr
            .remove_sessions_where(|session| session.user_id == "user-a")
            .await;
        assert_eq!(removed.ended.len(), 1);
        assert_eq!(removed.failed, 0);
        assert!(
            mgr.validate_session(&alice)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_session_keeps_its_provider_binding_on_disk_and_an_older_record_loads_without_one() {
        let directory = tempfile::tempdir().unwrap();
        let manager = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();
        let bound = manager
            .create_session_with_terms_gate(
                "alice".into(),
                "user-a".into(),
                TermsSessionGate::AllowedAtLogin,
                Some(binding("op-1")),
            )
            .await;
        let mut older = serde_json::to_value(session_with_token(TOKEN, "user-b", 20)).unwrap();
        older
            .as_object_mut()
            .unwrap()
            .remove("oidc");
        std::fs::write(
            directory
                .path()
                .join(format!("{}.json", token_storage_id(TOKEN))),
            older.to_string(),
        )
        .unwrap();

        let reloaded = SessionManager::with_storage(20, directory.path().to_path_buf())
            .await
            .unwrap();

        let record = reloaded
            .validate_session_record(&bound)
            .await
            .unwrap();
        assert_eq!(record.oidc, Some(binding("op-1")));
        let older = reloaded
            .validate_session_record(TOKEN)
            .await
            .unwrap();
        assert_eq!(older.oidc, None);
    }

    #[test]
    fn a_session_never_shows_its_id_token_in_debug_output() {
        let mut session = session_with_token(TOKEN, "user-a", 20);
        session.oidc = Some(binding("op-1"));

        let shown = format!("{session:?}");

        assert!(!shown.contains("secret-signature") && !shown.contains("eyJ"), "{shown}");
        assert!(shown.contains(loggable::REDACTED) && shown.contains("op-1"), "{shown}");
        assert!(
            !serde_json::to_string(&session_with_token(TOKEN, "user-a", 20))
                .unwrap()
                .contains("oidc"),
            "a session without a binding is stored as before"
        );
    }

    #[tokio::test]
    async fn ending_a_session_returns_it_as_it_was_without_extending_it() {
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let manager = SessionManager::with_failing_deletes(failing.clone());
        let mut stored = session_with_token(TOKEN, "user-a", 5);
        stored.oidc = Some(binding("op-1"));
        manager
            .storage
            .save(&stored)
            .await
            .unwrap();
        let expires_at = || async {
            manager
                .storage
                .get(&token_storage_id(TOKEN))
                .await
                .unwrap()
                .map(|session| session.expires_at)
        };

        let ended = manager
            .end_session(TOKEN)
            .await
            .expect("a live session");
        assert_eq!(ended.expires_at, stored.expires_at);
        assert_eq!(ended.oidc, Some(binding("op-1")));
        assert_eq!(expires_at().await, Some(stored.expires_at), "a session whose delete failed is not extended");

        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            manager
                .end_session(TOKEN)
                .await
                .is_some()
        );
        assert_eq!(expires_at().await, None);
        assert!(
            manager
                .end_session(TOKEN)
                .await
                .is_none(),
            "already ended"
        );
    }

    #[tokio::test]
    async fn ending_an_expired_or_refused_session_deletes_it_and_returns_nothing() {
        let manager = SessionManager::new();
        manager
            .storage
            .save(&session_with_token(TOKEN, "user-a", -1))
            .await
            .unwrap();
        manager.accept_only_sign_ins_at("https://idp.example.com");
        let from_passkey_sign_in = manager
            .create_session("alice".into(), "user-a".into())
            .await;

        for token in [TOKEN, from_passkey_sign_in.as_str()] {
            assert!(
                manager
                    .end_session(token)
                    .await
                    .is_none(),
                "{token}"
            );
            assert!(
                manager
                    .storage
                    .get(&token_storage_id(token))
                    .await
                    .unwrap()
                    .is_none(),
                "{token} is deleted all the same"
            );
        }
    }

    #[tokio::test]
    async fn a_sign_out_waits_for_a_validation_in_flight_so_the_session_is_not_saved_back() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".into(), "user-a".into())
            .await;
        let in_flight = manager
            .terms_gate_update_lock
            .read()
            .await;
        let refreshed = manager
            .storage
            .get(&token_storage_id(&token))
            .await
            .unwrap()
            .unwrap();

        let sign_out = tokio::spawn({
            let (manager, token) = (manager.clone(), token.clone());
            async move {
                manager
                    .remove_session(&token)
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        manager
            .storage
            .save(&refreshed)
            .await
            .unwrap();
        drop(in_flight);
        sign_out.await.unwrap();

        assert!(!manager.is_live(&token).await, "the validation saved first and the sign-out deleted after it");
    }
}
