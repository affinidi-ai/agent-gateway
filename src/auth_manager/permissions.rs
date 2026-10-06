use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatDelegationContext};
use crate::rbac::Feature;
use axum::{
    Extension, Json,
    http::{
        HeaderName, StatusCode,
        header::{CACHE_CONTROL, VARY},
    },
};

/// Get user permissions based on RBAC config (with optional authentication)
/// If user_id extension is present, returns user-specific permissions
/// If not authenticated, returns all permissions as false
pub async fn get_permissions_optional(
    user_id: Option<Extension<String>>,
    storage: Option<Extension<std::sync::Arc<PasskeyStorage>>>,
    rbac_config: Option<Extension<std::sync::Arc<crate::rbac::RbacConfig>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let features = vec![
        ("users.view", Feature::UsersView),
        ("users.edit", Feature::UsersEdit),
        ("users.approve", Feature::UsersApprove),
        ("users.delete", Feature::UsersDelete),
        ("gateways.view", Feature::GatewaysView),
        ("gateways.edit", Feature::GatewaysEdit),
        ("gateways.delete", Feature::GatewaysDelete),
        ("mediators.view", Feature::MediatorsView),
        ("mediators.edit", Feature::MediatorsEdit),
        ("mediators.delete", Feature::MediatorsDelete),
        ("mcp_proxies.view", Feature::McpProxiesView),
        ("mcp_proxies.edit", Feature::McpProxiesEdit),
        ("mcp_proxies.delete", Feature::McpProxiesDelete),
        ("a2a_proxies.view", Feature::A2aProxiesView),
        ("a2a_proxies.edit", Feature::A2aProxiesEdit),
        ("a2a_proxies.delete", Feature::A2aProxiesDelete),
        ("trust_registries.view", Feature::TrustRegistriesView),
        ("trust_registries.edit", Feature::TrustRegistriesEdit),
        ("trust_registries.delete", Feature::TrustRegistriesDelete),
        ("notifications.view", Feature::NotificationsView),
        ("notifications.edit", Feature::NotificationsEdit),
        ("notifications.delete", Feature::NotificationsDelete),
        ("surfaces.view", Feature::SurfacesView),
        ("surfaces.edit", Feature::SurfacesEdit),
        ("surfaces.delete", Feature::SurfacesDelete),
        ("surfaces.capture", Feature::SurfacesCapture),
        ("secrets.view", Feature::SecretsView),
        ("secrets.edit", Feature::SecretsEdit),
        ("secrets.delete", Feature::SecretsDelete),
        ("delegation_vault.view", Feature::DelegationVaultView),
        ("delegation_vault.delete", Feature::DelegationVaultDelete),
        ("api_keys.view", Feature::ApiKeysView),
        ("api_keys.edit", Feature::ApiKeysEdit),
        ("api_keys.delete", Feature::ApiKeysDelete),
        ("access_tokens.view", Feature::AccessTokensView),
        ("access_tokens.edit", Feature::AccessTokensEdit),
        ("access_tokens.delete", Feature::AccessTokensDelete),
        ("tenant_ownership.manage", Feature::TenantOwnershipManage),
        ("credential_providers.view", Feature::CredentialProvidersView),
        ("credential_providers.edit", Feature::CredentialProvidersEdit),
        ("credential_providers.delete", Feature::CredentialProvidersDelete),
        ("certificates.view", Feature::CertificatesView),
        ("integrations.view", Feature::IntegrationsView),
        ("integrations.edit", Feature::IntegrationsEdit),
        ("integrations.delete", Feature::IntegrationsDelete),
        ("issuers.view", Feature::IssuersView),
        ("issuers.edit", Feature::IssuersEdit),
        ("issuers.delete", Feature::IssuersDelete),
        // Legacy aliases — emit both canonical and legacy keys so dashboards
        // still checking the pre-rename permission names continue to work.
        ("departments.view", Feature::IssuersView),
        ("departments.edit", Feature::IssuersEdit),
        ("departments.delete", Feature::IssuersDelete),
        ("authorities.view", Feature::AuthoritiesView),
        ("authorities.edit", Feature::AuthoritiesEdit),
        ("authorities.delete", Feature::AuthoritiesDelete),
        ("settings.view", Feature::SettingsView),
        ("settings.edit", Feature::SettingsEdit),
        ("metrics.view", Feature::MetricsView),
        ("dashboard.view", Feature::DashboardView),
        ("logs.view", Feature::LogsView),
        ("audit.view", Feature::AuditView),
        ("payments.view", Feature::PaymentsView),
        ("payments.edit", Feature::PaymentsEdit),
        ("payments.delete", Feature::PaymentsDelete),
        ("payments.retry", Feature::PaymentsRetry),
        ("jwt_verification_strategies.view", Feature::JwtVerificationStrategiesView),
        ("jwt_verification_strategies.edit", Feature::JwtVerificationStrategiesEdit),
        ("jwt_verification_strategies.delete", Feature::JwtVerificationStrategiesDelete),
        ("sts_clients.view", Feature::StsClientsView),
        ("sts_clients.edit", Feature::StsClientsEdit),
        ("sts_clients.delete", Feature::StsClientsDelete),
        ("terms.view", Feature::TermsView),
        ("terms.edit", Feature::TermsEdit),
    ];

    let mut permissions = serde_json::Map::new();

    // If authenticated, get user permissions
    if let (Some(Extension(uid)), Some(Extension(store)), Some(Extension(rbac))) = (user_id, storage, rbac_config) {
        match store
            .load_user_by_id(&uid)
            .await
        {
            Ok(Some(user_data)) => {
                for (name, feature) in features {
                    permissions.insert(
                        name.to_string(),
                        serde_json::Value::Bool(rbac.has_permission(&user_data.role, &feature)),
                    );
                }
            }
            _ => {
                // User not found or error, return false for all
                for (name, _) in features {
                    permissions.insert(name.to_string(), serde_json::Value::Bool(false));
                }
            }
        }
    } else {
        // Not authenticated, return false for all permissions
        for (name, _) in features {
            permissions.insert(name.to_string(), serde_json::Value::Bool(false));
        }
    }

    Ok(Json(serde_json::Value::Object(permissions)))
}

type PermissionsResponse = ([(HeaderName, &'static str); 2], Json<serde_json::Value>);

/// Get user permissions based on RBAC config (authenticated only).
/// A personal access token reports its owner's role limited to the token's own
/// feature scopes, matching `require_feature`. The response is `no-store`
/// because the body depends on the caller's credential.
pub async fn get_permissions(
    Extension(user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<crate::rbac::RbacConfig>>,
    pat: Option<Extension<PatContext>>,
) -> Result<PermissionsResponse, (StatusCode, String)> {
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    let features = vec![
        ("users.view", Feature::UsersView),
        ("users.edit", Feature::UsersEdit),
        ("users.approve", Feature::UsersApprove),
        ("users.delete", Feature::UsersDelete),
        ("gateways.view", Feature::GatewaysView),
        ("gateways.edit", Feature::GatewaysEdit),
        ("gateways.delete", Feature::GatewaysDelete),
        ("mediators.view", Feature::MediatorsView),
        ("mediators.edit", Feature::MediatorsEdit),
        ("mediators.delete", Feature::MediatorsDelete),
        ("mcp_proxies.view", Feature::McpProxiesView),
        ("mcp_proxies.edit", Feature::McpProxiesEdit),
        ("mcp_proxies.delete", Feature::McpProxiesDelete),
        ("a2a_proxies.view", Feature::A2aProxiesView),
        ("a2a_proxies.edit", Feature::A2aProxiesEdit),
        ("a2a_proxies.delete", Feature::A2aProxiesDelete),
        ("trust_registries.view", Feature::TrustRegistriesView),
        ("trust_registries.edit", Feature::TrustRegistriesEdit),
        ("trust_registries.delete", Feature::TrustRegistriesDelete),
        ("secrets.view", Feature::SecretsView),
        ("secrets.edit", Feature::SecretsEdit),
        ("secrets.delete", Feature::SecretsDelete),
        ("delegation_vault.view", Feature::DelegationVaultView),
        ("delegation_vault.delete", Feature::DelegationVaultDelete),
        ("api_keys.view", Feature::ApiKeysView),
        ("api_keys.edit", Feature::ApiKeysEdit),
        ("api_keys.delete", Feature::ApiKeysDelete),
        ("access_tokens.view", Feature::AccessTokensView),
        ("access_tokens.edit", Feature::AccessTokensEdit),
        ("access_tokens.delete", Feature::AccessTokensDelete),
        ("tenant_ownership.manage", Feature::TenantOwnershipManage),
        ("credential_providers.view", Feature::CredentialProvidersView),
        ("credential_providers.edit", Feature::CredentialProvidersEdit),
        ("credential_providers.delete", Feature::CredentialProvidersDelete),
        ("certificates.view", Feature::CertificatesView),
        ("integrations.view", Feature::IntegrationsView),
        ("integrations.edit", Feature::IntegrationsEdit),
        ("integrations.delete", Feature::IntegrationsDelete),
        ("notifications.view", Feature::NotificationsView),
        ("notifications.edit", Feature::NotificationsEdit),
        ("notifications.delete", Feature::NotificationsDelete),
        ("surfaces.view", Feature::SurfacesView),
        ("surfaces.edit", Feature::SurfacesEdit),
        ("surfaces.delete", Feature::SurfacesDelete),
        ("surfaces.capture", Feature::SurfacesCapture),
        ("issuers.view", Feature::IssuersView),
        ("issuers.edit", Feature::IssuersEdit),
        ("issuers.delete", Feature::IssuersDelete),
        // Legacy aliases — emit both canonical and legacy keys so dashboards
        // still checking the pre-rename permission names continue to work.
        ("departments.view", Feature::IssuersView),
        ("departments.edit", Feature::IssuersEdit),
        ("departments.delete", Feature::IssuersDelete),
        ("authorities.view", Feature::AuthoritiesView),
        ("authorities.edit", Feature::AuthoritiesEdit),
        ("authorities.delete", Feature::AuthoritiesDelete),
        ("settings.view", Feature::SettingsView),
        ("settings.edit", Feature::SettingsEdit),
        ("metrics.view", Feature::MetricsView),
        ("dashboard.view", Feature::DashboardView),
        ("logs.view", Feature::LogsView),
        ("audit.view", Feature::AuditView),
        ("payments.view", Feature::PaymentsView),
        ("payments.edit", Feature::PaymentsEdit),
        ("payments.delete", Feature::PaymentsDelete),
        ("payments.retry", Feature::PaymentsRetry),
        ("jwt_verification_strategies.view", Feature::JwtVerificationStrategiesView),
        ("jwt_verification_strategies.edit", Feature::JwtVerificationStrategiesEdit),
        ("jwt_verification_strategies.delete", Feature::JwtVerificationStrategiesDelete),
        ("sts_clients.view", Feature::StsClientsView),
        ("sts_clients.edit", Feature::StsClientsEdit),
        ("sts_clients.delete", Feature::StsClientsDelete),
        ("terms.view", Feature::TermsView),
        ("terms.edit", Feature::TermsEdit),
    ];

    let token_scopes = pat.and_then(|Extension(PatContext(scopes))| scopes);

    let mut permissions = serde_json::Map::new();
    for (name, feature) in features {
        // Match on the canonical feature name so aliases like `departments.view` follow `issuers.view`.
        let granted = rbac_config.has_permission(&user_data.role, &feature)
            && token_scopes
                .as_ref()
                .is_none_or(|scopes| {
                    scopes
                        .iter()
                        .any(|scope| scope == feature.as_str())
                });
        permissions.insert(name.to_string(), serde_json::Value::Bool(granted));
    }

    Ok(([(CACHE_CONTROL, "no-store"), (VARY, "Authorization")], Json(serde_json::Value::Object(permissions))))
}

/// Reads only extensions the auth middleware already resolved, with no lookup by id,
/// so a token can only inspect itself.
pub async fn get_token_info(
    Extension(user_id): Extension<String>,
    pat: Option<Extension<PatContext>>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> impl axum::response::IntoResponse {
    let scopes = pat.and_then(|Extension(PatContext(scopes))| scopes);
    let token_id = delegation.map(|Extension(context)| context.token_id);

    (
        [(axum::http::header::CACHE_CONTROL, "no-store"), (axum::http::header::VARY, "Authorization, Cookie")],
        Json(serde_json::json!({
            "user_id": user_id,
            "token_id": token_id,
            "scopes": scopes,
        })),
    )
}

/// Get public permissions (for unauthenticated users during registration)
/// Returns all permissions as false since no user is logged in
#[allow(dead_code)]
pub async fn get_public_permissions() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let features = vec![
        "users.view",
        "users.edit",
        "users.approve",
        "users.delete",
        "gateways.view",
        "gateways.edit",
        "gateways.delete",
        "mediators.view",
        "mediators.edit",
        "mediators.delete",
        "mcp_proxies.view",
        "mcp_proxies.edit",
        "mcp_proxies.delete",
        "a2a_proxies.view",
        "a2a_proxies.edit",
        "a2a_proxies.delete",
        "trust_registries.view",
        "trust_registries.edit",
        "trust_registries.delete",
        "secrets.view",
        "secrets.edit",
        "secrets.delete",
        "api_keys.view",
        "api_keys.edit",
        "api_keys.delete",
        "access_tokens.view",
        "access_tokens.edit",
        "access_tokens.delete",
        "tenant_ownership.manage",
        "credential_providers.view",
        "credential_providers.edit",
        "credential_providers.delete",
        "certificates.view",
        "integrations.view",
        "integrations.edit",
        "integrations.delete",
        "notifications.view",
        "notifications.edit",
        "notifications.delete",
        "surfaces.view",
        "surfaces.edit",
        "surfaces.delete",
        "surfaces.capture",
        "settings.view",
        "terms.view",
        "terms.edit",
        "payments.view",
        "payments.edit",
        "payments.delete",
        "payments.retry",
        "settings.edit",
        "metrics.view",
        "dashboard.view",
        "logs.view",
        "audit.view",
        "jwt_verification_strategies.view",
        "jwt_verification_strategies.edit",
        "jwt_verification_strategies.delete",
    ];

    let mut permissions = serde_json::Map::new();
    for name in features {
        permissions.insert(
            name.to_string(),
            serde_json::Value::Bool(false), // No permissions for unauthenticated users
        );
    }

    Ok(Json(serde_json::Value::Object(permissions)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::rbac::RbacConfig;
    use axum::response::IntoResponse;
    use chrono::Utc;
    use std::sync::Arc;

    async fn storage_with_user(role: UserRole) -> (Arc<PasskeyStorage>, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let users_dir = dir.path().join("users");
        let avatars_dir = dir.path().join("avatars");
        std::fs::create_dir_all(&users_dir).unwrap();
        std::fs::create_dir_all(&avatars_dir).unwrap();
        std::fs::write(avatars_dir.join("default.png"), b"").unwrap();

        let user_id = uuid::Uuid::new_v4().to_string();
        let user_data = UserData {
            user_id: user_id.clone(),
            username: "testuser".to_string(),
            passkeys: vec![],
            role,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_logged_in: None,
            saml_id: None,
        };
        std::fs::write(users_dir.join(format!("{}.json", user_id)), serde_json::to_string(&user_data).unwrap())
            .unwrap();

        let storage = PasskeyStorage::new(
            users_dir
                .to_string_lossy()
                .into_owned(),
            avatars_dir
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();

        (Arc::new(storage), dir, user_id)
    }

    #[tokio::test]
    async fn permissions_endpoint_grants_sts_clients_to_admin() {
        let (storage, _dir, user_id) = storage_with_user(UserRole::Administrator).await;
        let rbac = Arc::new(RbacConfig::default());
        let (_, Json(perms)) = get_permissions(Extension(user_id), Extension(storage), Extension(rbac), None)
            .await
            .expect("permissions endpoint should succeed for an admin");
        assert_eq!(perms["sts_clients.view"], serde_json::Value::Bool(true));
        assert_eq!(perms["sts_clients.edit"], serde_json::Value::Bool(true));
        assert_eq!(perms["sts_clients.delete"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn permissions_endpoint_reports_sts_clients_false_for_poweruser() {
        let (storage, _dir, user_id) = storage_with_user(UserRole::PowerUser).await;
        let rbac = Arc::new(RbacConfig::default());
        let (_, Json(perms)) = get_permissions(Extension(user_id), Extension(storage), Extension(rbac), None)
            .await
            .expect("permissions endpoint should succeed for a poweruser");
        // The key must be present so the dashboard can evaluate it — but false,
        // because sts_clients.view is administrator-only.
        assert_eq!(perms["sts_clients.view"], serde_json::Value::Bool(false));
    }

    async fn permissions_for_token(
        role: UserRole,
        scopes: Option<Vec<String>>,
    ) -> serde_json::Value {
        let (storage, _dir, user_id) = storage_with_user(role).await;
        let rbac = Arc::new(RbacConfig::default());
        let pat = Some(Extension(PatContext(scopes)));
        let (_, Json(perms)) = get_permissions(Extension(user_id), Extension(storage), Extension(rbac), pat)
            .await
            .expect("permissions endpoint should succeed");
        perms
    }

    fn scopes(names: &[&str]) -> Option<Vec<String>> {
        Some(
            names
                .iter()
                .map(|name| name.to_string())
                .collect(),
        )
    }

    #[tokio::test]
    async fn permissions_endpoint_reports_full_role_for_a_session_login() {
        let (storage, _dir, user_id) = storage_with_user(UserRole::Administrator).await;
        let rbac = Arc::new(RbacConfig::default());
        let (_, Json(perms)) = get_permissions(Extension(user_id), Extension(storage), Extension(rbac), None)
            .await
            .expect("permissions endpoint should succeed for a session login");
        assert_eq!(perms["secrets.view"], serde_json::Value::Bool(true));
        assert_eq!(perms["secrets.edit"], serde_json::Value::Bool(true));
        assert_eq!(perms["gateways.delete"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn permissions_endpoint_narrows_to_a_scoped_tokens_own_scopes() {
        let perms = permissions_for_token(UserRole::Administrator, scopes(&["secrets.view", "issuers.view"])).await;
        assert_eq!(perms["secrets.view"], serde_json::Value::Bool(true));
        assert_eq!(perms["secrets.edit"], serde_json::Value::Bool(false));
        assert_eq!(perms["gateways.view"], serde_json::Value::Bool(false));
        assert_eq!(perms["issuers.view"], serde_json::Value::Bool(true));
        assert_eq!(perms["departments.view"], serde_json::Value::Bool(true));
        assert_eq!(perms["departments.edit"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn permissions_endpoint_never_exceeds_the_owners_role_for_a_scoped_token() {
        // sts_clients.view is administrator-only, so a power user's token cannot hold it.
        let perms = permissions_for_token(UserRole::PowerUser, scopes(&["sts_clients.view", "gateways.view"])).await;
        assert_eq!(perms["sts_clients.view"], serde_json::Value::Bool(false));
        assert_eq!(perms["gateways.view"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn permissions_endpoint_reports_the_role_ceiling_for_an_unrestricted_token() {
        let token = permissions_for_token(UserRole::PowerUser, None).await;
        let (storage, _dir, user_id) = storage_with_user(UserRole::PowerUser).await;
        let (_, Json(session)) =
            get_permissions(Extension(user_id), Extension(storage), Extension(Arc::new(RbacConfig::default())), None)
                .await
                .expect("permissions endpoint should succeed for a session login");
        assert_eq!(token, session);
    }

    #[tokio::test]
    async fn permissions_endpoint_reports_the_role_ceiling_for_a_token_scoped_to_every_feature() {
        let session = permissions_for_token(UserRole::Administrator, None).await;
        let all: Vec<String> = session
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let perms = permissions_for_token(UserRole::PowerUser, Some(all)).await;
        let power_user = permissions_for_token(UserRole::PowerUser, None).await;
        assert_eq!(perms, power_user);
    }

    #[tokio::test]
    async fn permissions_response_is_marked_no_store_and_varies_on_authorization() {
        let (storage, _dir, user_id) = storage_with_user(UserRole::Administrator).await;
        let rbac = Arc::new(RbacConfig::default());
        let response = get_permissions(Extension(user_id), Extension(storage), Extension(rbac), None)
            .await
            .expect("permissions endpoint should succeed")
            .into_response();
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert_eq!(
            response
                .headers()
                .get(VARY)
                .unwrap(),
            "Authorization"
        );
    }

    #[tokio::test]
    async fn permissions_route_returns_401_without_authentication() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let (storage, _dir, _user_id) = storage_with_user(UserRole::Administrator).await;
        let sessions = Arc::new(crate::auth::session::SessionManager::new());
        let app = axum::Router::new()
            .route("/v1/permissions", axum::routing::get(get_permissions))
            .layer(axum::middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
            .layer(Extension(sessions))
            .layer(Extension(storage))
            .layer(Extension(Arc::new(RbacConfig::default())));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/permissions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_info_reports_scoped_pats_own_scopes_and_id() {
        let scopes = vec!["secrets.view".to_string(), "gateways.view".to_string()];
        let delegation = PatDelegationContext {
            token_id: "tok-123".to_string(),
            delegation_depth: 0,
            resource_scoped: false,
        };
        let response = get_token_info(
            Extension("user-1".to_string()),
            Some(Extension(PatContext(Some(scopes.clone())))),
            Some(Extension(delegation)),
        )
        .await
        .into_response();

        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::VARY)
                .unwrap(),
            "Authorization, Cookie"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["user_id"], "user-1");
        assert_eq!(value["token_id"], "tok-123");
        assert_eq!(value["scopes"], serde_json::json!(scopes));
    }

    #[tokio::test]
    async fn token_info_reports_null_scopes_for_a_session_login() {
        let response = get_token_info(Extension("user-1".to_string()), None, None)
            .await
            .into_response();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["user_id"], "user-1");
        assert!(value["token_id"].is_null());
        assert!(value["scopes"].is_null());
    }
}
