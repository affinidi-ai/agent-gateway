use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use webauthn_rs::prelude::*;

use crate::auth::session::SessionManager;
use crate::auth::setup_token::SetupToken;
use crate::auth::storage::PasskeyStorage;
use crate::config::types::SecretValue;

/// How long a registration or authentication challenge can be finished. WebAuthn only passes its
/// timeout to the browser as a hint, so the gateway enforces it.
const CHALLENGE_TTL: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// State for the authentication system
#[derive(Clone)]
pub struct AuthState {
    /// WebAuthn instance for passkey operations
    pub webauthn: Arc<Webauthn>,

    /// Storage for user credentials and passkeys
    pub storage: Arc<PasskeyStorage>,

    /// Session manager for tracking authenticated sessions
    pub session_manager: Arc<SessionManager>,

    /// Temporary storage for registration and authentication challenges
    pub challenges: Arc<RwLock<HashMap<String, ChallengeState>>>,

    /// Optional notification store for sending notifications
    pub notification_store: Arc<RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,

    /// Terms enforcement for human authentication.
    pub terms_manager: Arc<crate::terms::TermsManager>,

    /// The token that registers the first administrator while no user exists.
    pub setup_token: Arc<SetupToken>,
}

/// Temporary state for WebAuthn challenges
#[derive(Clone)]
pub struct ChallengeState {
    /// Registration state for passkey creation
    pub registration_state: Option<PasskeyRegistration>,

    /// Authentication state for passkey login
    pub authentication_state: Option<PasskeyAuthentication>,

    /// Username associated with this challenge
    pub username: String,

    /// Timestamp when this challenge was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AuthState {
    /// Create a new authentication state
    pub async fn new(
        rp_id: String,
        rp_origin: url::Url,
        storage_path: String,
        avatars_path: String,
        session_timeout_minutes: u64,
        sessions_storage_path: String,
        terms_manager: Arc<crate::terms::TermsManager>,
        operator_setup_token: Option<SecretValue>,
    ) -> anyhow::Result<Self> {
        // Build WebAuthn instance
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;
        let webauthn = Arc::new(builder.build()?);

        // Initialize storage
        let storage = Arc::new(PasskeyStorage::new(storage_path.clone(), avatars_path).await?);
        let has_users = !storage
            .list_users()
            .await?
            .is_empty();
        let setup_token =
            Arc::new(SetupToken::prepare(std::path::Path::new(&storage_path), has_users, operator_setup_token).await?);

        // Initialize session manager with configured timeout and filesystem persistence
        let session_manager = Arc::new(
            SessionManager::with_storage(session_timeout_minutes, std::path::PathBuf::from(sessions_storage_path))
                .await?,
        );

        Ok(Self {
            webauthn,
            storage,
            session_manager,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            notification_store: Arc::new(RwLock::new(None)),
            terms_manager,
            setup_token,
        })
    }

    /// Whether no user exists yet, so registering one needs the setup token.
    pub async fn setup_required(&self) -> anyhow::Result<bool> {
        Ok(self
            .storage
            .list_users()
            .await?
            .is_empty())
    }

    /// Removes the challenge `challenge_id` and returns it, unless it is older than five minutes.
    /// A challenge is taken once, whether or not it has expired.
    pub async fn take_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<ChallengeState> {
        let challenge = self
            .challenges
            .write()
            .await
            .remove(challenge_id)?;
        is_fresh(&challenge, chrono::Utc::now()).then_some(challenge)
    }

    /// Drops every challenge older than five minutes. The session cleanup task calls it on each
    /// run, so challenges nobody finishes do not accumulate.
    pub async fn cleanup_expired_challenges(&self) {
        let now = chrono::Utc::now();
        self.challenges
            .write()
            .await
            .retain(|_, challenge| is_fresh(challenge, now));
    }
}

fn is_fresh(
    challenge: &ChallengeState,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    now.signed_duration_since(challenge.created_at) < CHALLENGE_TTL
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn auth_state(dir: &tempfile::TempDir) -> AuthState {
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        AuthState::new(
            "example.com".to_string(),
            url::Url::parse("https://example.com").unwrap(),
            path("users"),
            path("avatars"),
            30,
            path("sessions"),
            Arc::new(crate::terms::TermsManager::disabled()),
            None,
        )
        .await
        .unwrap()
    }

    async fn insert_challenge(
        state: &AuthState,
        challenge_id: &str,
        age: chrono::TimeDelta,
    ) {
        state
            .challenges
            .write()
            .await
            .insert(
                challenge_id.to_string(),
                ChallengeState {
                    registration_state: None,
                    authentication_state: None,
                    username: "alice".to_string(),
                    created_at: chrono::Utc::now() - age,
                },
            );
    }

    #[tokio::test]
    async fn a_fresh_challenge_is_taken_once() {
        let dir = tempfile::tempdir().unwrap();
        let state = auth_state(&dir).await;
        insert_challenge(&state, "fresh", chrono::TimeDelta::minutes(4)).await;

        let first = state
            .take_challenge("fresh")
            .await;
        let second = state
            .take_challenge("fresh")
            .await;

        assert_eq!(first.map(|challenge| challenge.username), Some("alice".to_string()));
        assert!(second.is_none());
    }

    #[tokio::test]
    async fn a_challenge_older_than_five_minutes_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let state = auth_state(&dir).await;
        insert_challenge(&state, "expired", chrono::TimeDelta::minutes(5) + chrono::TimeDelta::seconds(1)).await;

        let taken = state
            .take_challenge("expired")
            .await;

        assert!(taken.is_none());
        assert!(
            state
                .challenges
                .read()
                .await
                .is_empty(),
            "an expired challenge is removed when it is presented"
        );
    }

    #[tokio::test]
    async fn cleanup_drops_only_expired_challenges() {
        let dir = tempfile::tempdir().unwrap();
        let state = auth_state(&dir).await;
        insert_challenge(&state, "fresh", chrono::TimeDelta::minutes(4)).await;
        insert_challenge(&state, "expired", chrono::TimeDelta::minutes(6)).await;

        state
            .cleanup_expired_challenges()
            .await;

        let mut remaining: Vec<String> = state
            .challenges
            .read()
            .await
            .keys()
            .cloned()
            .collect();
        remaining.sort();
        assert_eq!(remaining, vec!["fresh".to_string()]);
    }
}
