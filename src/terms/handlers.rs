use axum::{
    Extension, Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::{auth::session::SessionManager, auth_manager::middleware::AuthGuardOk};

use super::{
    AcceptTermsRequest, AcceptTermsResponse, AcceptanceContext, AffinidiProviderStatus, ApplicableTermsResponse,
    CustomerTermsDocument, CustomerTermsDraft, TermsDefinitions, TermsError, TermsErrorBody, TermsManager, TermsStatus,
    TermsVersion,
};

impl IntoResponse for TermsError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Operational(error) => {
                tracing::error!(error = %error, "Terms operation failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    TermsErrorBody {
                        code: "TERMS_OPERATIONAL_FAILURE".to_string(),
                        required_terms: None,
                    },
                )
            }
            Self::Stale(required_terms) => (
                StatusCode::CONFLICT,
                TermsErrorBody {
                    code: "TERMS_VERSION_STALE".to_string(),
                    required_terms: Some(required_terms),
                },
            ),
            Self::Invalid(error) => {
                tracing::debug!(error = %error, "Invalid Terms request");
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code": "TERMS_INVALID", "message": error})))
                    .into_response();
            }
            Self::NoDraft => (
                StatusCode::CONFLICT,
                TermsErrorBody {
                    code: "TERMS_DRAFT_REQUIRED".to_string(),
                    required_terms: None,
                },
            ),
            Self::Disabled => (
                StatusCode::NOT_FOUND,
                TermsErrorBody {
                    code: "TERMS_DISABLED".to_string(),
                    required_terms: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

pub async fn applicable(
    Extension(manager): Extension<Arc<TermsManager>>
) -> Result<Json<ApplicableTermsResponse>, TermsError> {
    Ok(Json(ApplicableTermsResponse {
        terms: manager.applicable().await?,
    }))
}

pub async fn status(
    Extension(manager): Extension<Arc<TermsManager>>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
) -> Result<Json<TermsStatus>, TermsError> {
    Ok(Json(
        manager
            .status(&user_id, AcceptanceContext::Login)
            .await?,
    ))
}

pub async fn accept(
    Extension(manager): Extension<Arc<TermsManager>>,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
    Json(request): Json<AcceptTermsRequest>,
) -> Result<Json<AcceptTermsResponse>, TermsError> {
    let response = manager
        .accept(&user_id, AcceptanceContext::Login, request)
        .await?;
    session_manager
        .allow_pending_terms_sessions(&user_id)
        .await
        .map_err(|error| TermsError::Operational(format!("failed to update Terms session gates: {error}")))?;
    Ok(Json(response))
}

pub async fn provider_health(
    Extension(manager): Extension<Arc<TermsManager>>
) -> Result<Json<AffinidiProviderStatus>, TermsError> {
    Ok(Json(
        manager
            .provider_status()
            .await?,
    ))
}

pub async fn definitions(
    Extension(manager): Extension<Arc<TermsManager>>
) -> Result<Json<TermsDefinitions>, TermsError> {
    Ok(Json(manager.definitions().await?))
}

pub async fn save_draft(
    Extension(manager): Extension<Arc<TermsManager>>,
    Json(draft): Json<CustomerTermsDraft>,
) -> Result<Json<CustomerTermsDocument>, TermsError> {
    Ok(Json(
        manager
            .save_draft(draft)
            .await?,
    ))
}

pub async fn publish(
    Extension(manager): Extension<Arc<TermsManager>>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
) -> Result<(StatusCode, Json<TermsVersion>), TermsError> {
    Ok((
        StatusCode::CREATED,
        Json(
            manager
                .publish(user_id)
                .await?,
        ),
    ))
}

pub async fn deactivate(Extension(manager): Extension<Arc<TermsManager>>) -> Result<StatusCode, TermsError> {
    manager
        .deactivate_customer_terms()
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;
    use crate::terms::TermsRequirement;

    #[tokio::test]
    async fn invalid_request_returns_safe_validation_message() {
        let response = TermsError::Invalid("Customer Terms version has already been published".into()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"code": "TERMS_INVALID", "message": "Customer Terms version has already been published"})
        );
    }

    #[tokio::test]
    async fn operational_failure_has_stable_error_contract() {
        let response = TermsError::Operational("disk unavailable".to_string()).into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"code": "TERMS_OPERATIONAL_FAILURE"})
        );
    }

    #[tokio::test]
    async fn disabled_terms_management_is_hidden() {
        let response = TermsError::Disabled.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"code": "TERMS_DISABLED"})
        );
    }

    #[tokio::test]
    async fn stale_version_returns_current_requirements() {
        let required = TermsRequirement {
            terms_type: super::super::TermsType::Affinidi,
            document_id: super::super::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
            version_id: "v2".to_string(),
            version: "2".to_string(),
            title: "Terms".to_string(),
            url: "https://example.com/terms".to_string(),
        };
        let response = TermsError::Stale(vec![required]).into_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        assert_eq!(body["code"], "TERMS_VERSION_STALE");
        assert_eq!(body["required_terms"][0]["version_id"], "v2");
    }
}
