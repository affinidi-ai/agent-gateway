use std::sync::Arc;

use axum::Extension;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::{DefinitionStores, router};
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::PatResourceScope;
use crate::gateways::connection_points::message_processor::TEST_SECRETS_STORE;
pub use crate::integrations::definitions::test_secrets::Secrets;
use crate::rbac::RbacConfig;
use crate::secrets::SecretsStore;
use crate::tenancy::PatTenantContext;

pub const ADMIN: &str = "admin-1";
pub const VIEWER: &str = "viewer-1";
/// May change integrations but not view audit records (`integrations.edit` and
/// `integrations.delete` without `audit.view`).
pub const EDITOR: &str = "editor-1";

/// Stores in a temporary directory and the default RBAC roles, with power users also allowed
/// to change and delete integrations: viewers may read integrations, editors may change them
/// but hold no `audit.view`, administrators may do everything.
pub struct Fixture {
    pub stores: Arc<DefinitionStores>,
    guard: RbacGuard,
    secrets: Option<Arc<dyn SecretsStore>>,
    _dir: tempfile::TempDir,
}

pub struct Caller {
    user_id: &'static str,
    tenant: Option<&'static str>,
    resource_scope: Option<&'static str>,
}

impl Caller {
    pub fn admin() -> Self {
        Self {
            user_id: ADMIN,
            tenant: None,
            resource_scope: None,
        }
    }

    pub fn tenant(
        mut self,
        tenant: &'static str,
    ) -> Self {
        self.tenant = Some(tenant);
        self
    }

    pub fn resource_scope(
        mut self,
        pattern: &'static str,
    ) -> Self {
        self.resource_scope = Some(pattern);
        self
    }
}

impl Fixture {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = DefinitionStores::open(
            &dir.path().join("endpoints"),
            &dir.path().join("event_sets"),
            &dir.path()
                .join("integrations"),
        )
        .await
        .expect("stores");
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
        .expect("users");
        for (user_id, role) in
            [(ADMIN, UserRole::Administrator), (VIEWER, UserRole::User), (EDITOR, UserRole::PowerUser)]
        {
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
                .expect("save user");
        }
        let mut rbac = RbacConfig::default();
        for feature in ["integrations.edit", "integrations.delete"] {
            rbac.permissions
                .insert(feature.to_string(), "poweruser".to_string());
        }
        Self {
            stores: Arc::new(stores),
            guard: RbacGuard::new(Arc::new(users), Arc::new(rbac)),
            secrets: None,
            _dir: dir,
        }
    }

    /// The fixture with `secrets` as the secrets store its calls see.
    pub fn with_secrets(
        mut self,
        secrets: Secrets,
    ) -> Self {
        self.secrets = Some(Arc::new(secrets));
        self
    }

    pub async fn call(
        &self,
        user_id: &'static str,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        self.call_as(
            Caller {
                user_id,
                tenant: None,
                resource_scope: None,
            },
            method,
            uri,
            body,
        )
        .await
    }

    pub async fn call_as(
        &self,
        caller: Caller,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut app = router(self.stores.clone(), Some(self.guard.clone()));
        if let Some(tenant) = caller.tenant {
            app = app.layer(Extension(PatTenantContext {
                token_id: "agat_test".to_string(),
                tenant_id: tenant.to_string(),
            }));
        }
        if let Some(pattern) = caller.resource_scope {
            app = app.layer(Extension(PatResourceScope(Arc::new(regex::Regex::new(pattern).expect("pattern")))));
        }
        let call = send(app, caller.user_id, method, uri, body);
        match &self.secrets {
            Some(secrets) => TEST_SECRETS_STORE
                .scope(secrets.clone(), call)
                .await,
            None => call.await,
        }
    }

    pub async fn call_unguarded(
        &self,
        user_id: &'static str,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        send(router(self.stores.clone(), None), user_id, method, uri, body).await
    }
}

async fn send(
    app: axum::Router,
    user_id: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            body.map(|body| body.to_string())
                .unwrap_or_default(),
        ))
        .expect("request");
    let response = app
        .layer(Extension(AuthGuardOk(user_id.to_string())))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}
