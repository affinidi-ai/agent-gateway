use async_trait::async_trait;
use axum::{
    http::{
        HeaderMap, StatusCode,
        header::{HeaderValue, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::error;

use super::{SessionManager, session_cookie};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedPrincipal {
    pub(crate) username: String,
    pub(crate) user_id: String,
}

impl AuthenticatedPrincipal {
    pub(crate) fn new(
        username: String,
        user_id: String,
    ) -> Self {
        Self { username, user_id }
    }
}

#[derive(Debug)]
pub(crate) struct FinalizedSession {
    pub(crate) headers: HeaderMap,
    pub(crate) session_token: String,
    pub(crate) consent_required: bool,
}

#[derive(Debug)]
pub(crate) enum SessionFinalizationError {
    Http(StatusCode),
    Terms(crate::terms::TermsError),
}

impl From<StatusCode> for SessionFinalizationError {
    fn from(status: StatusCode) -> Self {
        Self::Http(status)
    }
}

impl IntoResponse for SessionFinalizationError {
    fn into_response(self) -> Response {
        match self {
            Self::Http(status) => status.into_response(),
            Self::Terms(error) => error.into_response(),
        }
    }
}

#[async_trait]
pub(crate) trait SessionFinalizer: Send + Sync {
    /// Only the debug-only test-support login reports a session lifetime back to
    /// its caller, so this has no call site in a release build.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    fn session_timeout_seconds(&self) -> u64;

    async fn finalize_session(
        &self,
        principal: AuthenticatedPrincipal,
    ) -> Result<FinalizedSession, SessionFinalizationError>;
}

pub(crate) struct SessionManagerFinalizer {
    session_manager: Arc<SessionManager>,
    terms_manager: Arc<crate::terms::TermsManager>,
}

impl SessionManagerFinalizer {
    pub(crate) fn new(
        session_manager: Arc<SessionManager>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> Self {
        Self { session_manager, terms_manager }
    }
}

#[async_trait]
impl SessionFinalizer for SessionManagerFinalizer {
    fn session_timeout_seconds(&self) -> u64 {
        self.session_manager
            .timeout_seconds()
    }

    async fn finalize_session(
        &self,
        principal: AuthenticatedPrincipal,
    ) -> Result<FinalizedSession, SessionFinalizationError> {
        let consent_required = self
            .terms_manager
            .status(&principal.user_id, crate::terms::AcceptanceContext::Login)
            .await
            .map_err(|error| {
                tracing::error!("Failed to verify Terms status before session creation: {}", error);
                SessionFinalizationError::Terms(error)
            })?
            .consent_required;
        let terms_gate = if consent_required {
            crate::auth::session::TermsSessionGate::ConsentPending
        } else {
            crate::auth::session::TermsSessionGate::AllowedAtLogin
        };
        let session_token = self
            .session_manager
            .create_session_with_terms_gate(principal.username, principal.user_id, terms_gate)
            .await;

        let mut headers = HeaderMap::new();
        let session_cookie = session_cookie::build_session_cookie(
            &session_token,
            self.session_manager
                .timeout_seconds(),
        );
        let session_cookie = HeaderValue::from_str(&session_cookie).map_err(|err| {
            error!("Failed to serialize session cookie header: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        headers.insert(SET_COOKIE, session_cookie);

        Ok(FinalizedSession {
            headers,
            session_token,
            consent_required,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_finalize_session_sets_cookie_and_token() {
        let finalizer = SessionManagerFinalizer::new(
            Arc::new(SessionManager::with_timeout(7)),
            std::sync::Arc::new(crate::terms::TermsManager::disabled()),
        );

        let finalized = finalizer
            .finalize_session(AuthenticatedPrincipal::new("alice".to_string(), "user-123".to_string()))
            .await
            .unwrap();

        let cookie = finalized
            .headers
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();

        assert!(
            !finalized
                .session_token
                .is_empty()
        );
        assert!(cookie.contains("session_token="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=420"));
        assert_eq!(finalizer.session_timeout_seconds(), 420);
        assert!(!finalized.consent_required);
    }

    #[tokio::test]
    async fn unavailable_required_terms_prevent_session_finalization() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory
                .path()
                .join("acceptances"),
            b"not a directory",
        )
        .unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(true, "appliance".into(), directory.path().into(), None)
                .await
                .unwrap(),
        );
        let finalizer = SessionManagerFinalizer::new(Arc::new(SessionManager::new()), manager);
        let result = finalizer
            .finalize_session(AuthenticatedPrincipal::new("alice".into(), "user-1".into()))
            .await;
        assert!(matches!(result, Err(SessionFinalizationError::Terms(crate::terms::TermsError::Operational(_)))));
    }

    #[tokio::test]
    async fn outstanding_terms_create_consent_pending_session() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(
                true,
                "did:web:gateway.example".to_string(),
                temp.path().join("terms"),
                Some(crate::terms::TermsVersion {
                    terms_type: crate::terms::TermsType::Affinidi,
                    document_id: crate::terms::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
                    version_id: "terms-v1".to_string(),
                    version: "1".to_string(),
                    title: "Terms".to_string(),
                    url: "https://example.com/terms".to_string(),
                    requires_reconsent: true,
                    published_at: chrono::Utc::now(),
                    published_by: None,
                }),
            )
            .await
            .unwrap(),
        );
        let sessions = Arc::new(SessionManager::with_timeout(7));
        let finalizer = SessionManagerFinalizer::new(sessions.clone(), manager);

        let finalized = finalizer
            .finalize_session(AuthenticatedPrincipal::new("alice".to_string(), "user-1".to_string()))
            .await
            .unwrap();

        assert!(finalized.consent_required);
        assert_eq!(
            sessions
                .validate_session_record(&finalized.session_token)
                .await
                .unwrap()
                .terms_gate,
            crate::auth::session::TermsSessionGate::ConsentPending
        );
    }
}
