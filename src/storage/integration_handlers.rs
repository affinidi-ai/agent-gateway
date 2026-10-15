use axum::Extension;
use std::sync::Arc;

use crate::auth_manager::middleware::RbacGuard;
use crate::config::GatewayConfig;
use crate::storage::IntegrationStorage;

/// Routes for the user and identity mappings, gated on their `integrations.*` permission by
/// the RBAC guard and refused without one. They live here because their PUT handlers validate
/// each referenced integration against this store.
pub fn integration_router(
    storage: Arc<IntegrationStorage>,
    guard: Option<RbacGuard>,
    config: Arc<GatewayConfig>,
    bootstrap: Arc<crate::config::BootstrapConfig>,
) -> axum::Router {
    use crate::auth_manager::middleware::maybe_gate;
    use crate::integrations::identity_integrations_handlers::{
        get_identity_integrations, update_identity_integrations,
    };
    use crate::integrations::user_integrations_handlers::{get_user_integrations, update_user_integrations};
    use crate::rbac::Feature;
    use axum::routing::{MethodRouter, get, put};

    let gate = |route: MethodRouter, feature: Feature| -> MethodRouter { maybe_gate(guard.as_ref(), route, feature) };
    let router = axum::Router::new()
        .route("/v1/users/integrations", gate(get(get_user_integrations), Feature::IntegrationsView))
        .route("/v1/users/integrations", gate(put(update_user_integrations), Feature::IntegrationsEdit))
        .route("/v1/identities/integrations", gate(get(get_identity_integrations), Feature::IntegrationsView))
        .route("/v1/identities/integrations", gate(put(update_identity_integrations), Feature::IntegrationsEdit));
    let router = match guard {
        Some(guard) => router.layer(Extension(guard)),
        None => router,
    };
    router
        .layer(Extension(storage))
        .layer(Extension(config))
        .layer(Extension(bootstrap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::AuthGuardOk;
    use crate::auth_manager::pat::PatResourceScope;
    use crate::rbac::RbacConfig;
    use crate::storage::Integration;
    use crate::tenancy::PatTenantContext;
    use axum::http::StatusCode;

    const ADMIN: &str = "admin-1";
    const OPERATOR: &str = "operator-1";

    /// Operators hold every integration permission.
    struct Fixture {
        integrations: Arc<IntegrationStorage>,
        guard: RbacGuard,
        config: Arc<GatewayConfig>,
        dir: tempfile::TempDir,
    }

    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let integrations = Arc::new(
            IntegrationStorage::new(
                dir.path()
                    .join("integrations"),
            )
            .await
            .unwrap(),
        );
        let users = PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            dir.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        for (user_id, role) in [(ADMIN, UserRole::Administrator), (OPERATOR, UserRole::PowerUser)] {
            let now = chrono::Utc::now();
            users
                .save_user(&UserData {
                    user_id: user_id.to_string(),
                    username: user_id.to_string(),
                    passkeys: Vec::new(),
                    role,
                    status: UserStatus::Approved,
                    is_primary: false,
                    first_name: None,
                    last_name: None,
                    email: None,
                    department: None,
                    job_title: None,
                    avatar_path: None,
                    created_at: now,
                    updated_at: now,
                    last_logged_in: None,
                    saml_id: None,
                })
                .await
                .unwrap();
        }
        let mut rbac = RbacConfig::default();
        for feature in ["integrations.view", "integrations.edit", "integrations.delete"] {
            rbac.permissions
                .insert(feature.to_string(), "poweruser".to_string());
        }
        Fixture {
            integrations,
            guard: RbacGuard::new(Arc::new(users), Arc::new(rbac)),
            config: Arc::new(GatewayConfig::default_config()),
            dir,
        }
    }

    impl Fixture {
        fn bootstrap(&self) -> Arc<crate::config::BootstrapConfig> {
            Arc::new(
                toml::from_str(&format!(
                    "backup_encryption_key = \"env://UNUSED\"\n[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n[storage_paths]\nintegration_triggers = \"{}\"\n",
                    self.dir
                        .path()
                        .join("triggers")
                        .display()
                ))
                .unwrap(),
            )
        }

        fn router(
            &self,
            guard: Option<RbacGuard>,
        ) -> axum::Router {
            integration_router(self.integrations.clone(), guard, self.config.clone(), self.bootstrap())
        }

        async fn seed(
            &self,
            category: &str,
        ) -> Integration {
            let integration = Integration::new(
                format!("{category} integration"),
                String::new(),
                "stream".to_string(),
                serde_json::json!({"platform": "kafka", "topic": "audit", "brokers": "127.0.0.1:1"}),
                serde_json::json!({"record": "${AUDIT_RECORD}"}),
                "active".to_string(),
                Some(category.to_string()),
            );
            self.integrations
                .save(&integration)
                .await
                .unwrap();
            integration
        }
    }

    async fn call(
        router: axum::Router,
        user_id: &str,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                body.map(|body| body.to_string())
                    .unwrap_or_default(),
            ))
            .unwrap();
        let response = router
            .layer(Extension(AuthGuardOk(user_id.to_string())))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn mapping_body(
        integration_id: &str,
        event_type: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "integration_integrations": [
                { "integration_id": integration_id, "variables": {}, "event_types": [event_type] }
            ]
        })
    }

    #[tokio::test]
    async fn integration_router_stores_validated_user_and_identity_mappings() {
        let f = fixture().await;
        let router = || f.router(Some(f.guard.clone()));
        let user = f.seed("user").await;
        let general = f.seed("general").await;

        let (status, _) =
            call(router(), OPERATOR, "PUT", "/v1/users/integrations", Some(mapping_body(&user.id, "user.created")))
                .await;
        assert_eq!(status, StatusCode::OK);
        let (status, stored) = call(router(), OPERATOR, "GET", "/v1/users/integrations", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["integration_integrations"][0]["integration_id"], user.id.as_str());
        assert_eq!(stored["integration_integrations"][0]["event_types"][0], "user.created");

        let (status, _) = call(
            router(),
            OPERATOR,
            "PUT",
            "/v1/identities/integrations",
            Some(mapping_body(&general.id, "identity.created")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Every read and write of the appliance-wide user and identity mappings is refused for a
    /// caller whose token `scoped` narrows to a tenant or a resource pattern.
    async fn assert_scoped_caller_refused_on_mapping_routes(
        f: &Fixture,
        scoped: impl Fn(axum::Router) -> axum::Router,
    ) {
        let user = f.seed("user").await;
        for (method, uri, body) in [
            ("GET", "/v1/users/integrations", None),
            ("PUT", "/v1/users/integrations", Some(mapping_body(&user.id, "user.created"))),
            ("GET", "/v1/identities/integrations", None),
            ("PUT", "/v1/identities/integrations", Some(mapping_body(&user.id, "identity.created"))),
        ] {
            let (status, body) = call(scoped(f.router(Some(f.guard.clone()))), OPERATOR, method, uri, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
            assert!(
                body.get("integration_integrations")
                    .is_none(),
                "{method} {uri} returned mappings"
            );
        }
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_read_or_change_user_or_identity_mappings() {
        let f = fixture().await;
        let tenant = PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        };

        assert_scoped_caller_refused_on_mapping_routes(&f, |router| router.layer(Extension(tenant.clone()))).await;
    }

    #[tokio::test]
    async fn a_resource_scoped_token_cannot_read_or_change_user_or_identity_mappings() {
        let f = fixture().await;
        let scope = PatResourceScope(Arc::new(regex::Regex::new("^integrations/.*$").unwrap()));

        assert_scoped_caller_refused_on_mapping_routes(&f, |router| router.layer(Extension(scope.clone()))).await;
    }

    #[tokio::test]
    async fn integration_router_refuses_an_invalid_user_mapping() {
        let f = fixture().await;
        let audit = f.seed("audit").await;

        let (status, _) = call(
            f.router(Some(f.guard.clone())),
            ADMIN,
            "PUT",
            "/v1/users/integrations",
            Some(mapping_body(&audit.id, "user.created")),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mapping_routes_mounted_without_an_rbac_guard_refuse_every_request() {
        let f = fixture().await;
        let user = f.seed("user").await;

        for (method, uri, body) in [
            ("GET", "/v1/users/integrations", None),
            ("PUT", "/v1/users/integrations", Some(mapping_body(&user.id, "user.created"))),
            ("GET", "/v1/identities/integrations", None),
            ("PUT", "/v1/identities/integrations", Some(mapping_body(&user.id, "identity.created"))),
        ] {
            let (status, _) = call(f.router(None), ADMIN, method, uri, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
    }
}
