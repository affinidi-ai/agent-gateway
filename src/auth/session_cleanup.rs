//! Periodic session cleanup task

use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, info};

/// Periodically clean up expired sessions from both session stores
/// Runs every 5 minutes to keep disk storage clean and prevent accumulation
pub async fn periodic_session_cleanup(
    didauth_store: Arc<crate::didauth::DidAuthSessionStore>,
    saml_session_manager: Option<Arc<crate::auth::SessionManager>>,
) {
    // Clean up every 5 minutes
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("Starting periodic session cleanup task (interval: 5 minutes)");

    loop {
        interval.tick().await;

        debug!("Running periodic session cleanup...");

        // Clean up DID auth sessions
        didauth_store
            .cleanup_expired()
            .await;

        // Clean up SAML/Passkey sessions if available
        if let Some(ref session_mgr) = saml_session_manager {
            session_mgr
                .cleanup_expired()
                .await;
        }

        debug!("Periodic session cleanup completed");
    }
}
