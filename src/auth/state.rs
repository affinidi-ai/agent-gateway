use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use webauthn_rs::prelude::*;

use crate::auth::session::SessionManager;
use crate::auth::storage::PasskeyStorage;

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

    /// Derives the credential a sign-in challenge names for a username with no usable passkey
    pub decoy_credentials: Arc<crate::auth::decoy_credential::DecoyCredentialKey>,
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
        decoy_credentials: crate::auth::decoy_credential::DecoyCredentialKey,
    ) -> anyhow::Result<Self> {
        // Build WebAuthn instance
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;
        let webauthn = Arc::new(builder.build()?);

        // Initialize storage
        let storage = Arc::new(PasskeyStorage::new(storage_path, avatars_path).await?);

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
            decoy_credentials: Arc::new(decoy_credentials),
        })
    }

    /// Stores a new sign-in or registration challenge and returns its id. Once the store holds
    /// [`MAX_PENDING_CHALLENGES`], challenges older than [`CHALLENGE_LIFETIME`] are dropped, and
    /// then the oldest one if it is still full, so a flood of unfinished ones stays bounded.
    pub async fn store_challenge(
        &self,
        challenge: ChallengeState,
    ) -> String {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let mut challenges = self.challenges.write().await;
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            let now = chrono::Utc::now();
            challenges.retain(|_, stored| is_fresh(stored, now));
        }
        if challenges.len() >= MAX_PENDING_CHALLENGES
            && let Some(oldest) = challenges
                .iter()
                .min_by_key(|(_, stored)| stored.created_at)
                .map(|(id, _)| id.clone())
        {
            challenges.remove(&oldest);
        }
        challenges.insert(challenge_id.clone(), challenge);
        challenge_id
    }

    /// Takes the challenge `challenge_id` out of the store, or `None` when there is none or it is
    /// older than [`CHALLENGE_LIFETIME`].
    pub async fn take_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<ChallengeState> {
        self.challenges
            .write()
            .await
            .remove(challenge_id)
            .filter(|challenge| is_fresh(challenge, chrono::Utc::now()))
    }
}

/// How long a sign-in or registration challenge can be finished: the 5 minutes the browser is
/// given to use the passkey, and a minute for the answer to reach the gateway.
pub const CHALLENGE_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::minutes(6);

/// The most unfinished challenges kept at once.
pub const MAX_PENDING_CHALLENGES: usize = 10_000;

fn is_fresh(
    challenge: &ChallengeState,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    now.signed_duration_since(challenge.created_at) < CHALLENGE_LIFETIME
}
