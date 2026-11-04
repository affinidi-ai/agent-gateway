use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use webauthn_rs::prelude::*;

use crate::auth::session::SessionManager;
use crate::auth::setup_token::SetupToken;
use crate::auth::storage::PasskeyStorage;
use crate::config::types::SecretValue;

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
    #[allow(dead_code)]
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

    /// Clean up expired challenges (should be called periodically)
    #[allow(dead_code)]
    pub async fn cleanup_expired_challenges(&self) {
        let mut challenges = self.challenges.write().await;
        let now = chrono::Utc::now();

        challenges.retain(|_, state| {
            // Keep challenges younger than 5 minutes
            now.signed_duration_since(state.created_at)
                .num_minutes()
                < 5
        });
    }
}
