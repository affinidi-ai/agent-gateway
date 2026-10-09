use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::config::GatewayConfig;
use crate::integrations::audit_integration_triggers::{AUDIT_CATEGORY, AUDIT_INTEGRATION_TYPES, is_audit_integration};
use crate::storage::{Integration, IntegrationStorage};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

/// The authenticated caller of an integration route. Governance audit
/// integrations receive administrator-only audit evidence, so only a caller
/// holding `audit.view` may see or manage them; a request without an
/// authenticated caller or RBAC guard is refused.
pub(crate) struct AuditCaller<'a> {
    guard: Option<&'a RbacGuard>,
    user_id: Option<&'a str>,
    pat: Option<&'a PatContext>,
}

impl<'a> AuditCaller<'a> {
    pub(crate) fn new(
        guard: &'a Option<Extension<RbacGuard>>,
        caller: &'a Option<Extension<AuthGuardOk>>,
        pat: &'a Option<Extension<PatContext>>,
    ) -> Self {
        Self {
            guard: guard
                .as_ref()
                .map(|Extension(guard)| guard),
            user_id: caller
                .as_ref()
                .map(|Extension(AuthGuardOk(user_id))| user_id.as_str()),
            pat: pat
                .as_ref()
                .map(|Extension(pat)| pat),
        }
    }

    async fn may_access_audit(&self) -> Result<bool, (StatusCode, String)> {
        let (Some(guard), Some(user_id)) = (self.guard, self.user_id) else {
            return Ok(false);
        };
        guard
            .allows(user_id, self.pat, crate::rbac::Feature::AuditView)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check permissions: {}", e)))
    }

    pub(crate) async fn require_audit_access(&self) -> Result<(), (StatusCode, String)> {
        if self
            .may_access_audit()
            .await?
        {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, "Governance audit integrations require the audit.view permission".to_string()))
        }
    }
}

/// Management routes for integrations. Each route is gated on its
/// `integrations.*` permission when an RBAC guard is supplied; governance
/// audit integrations are additionally authorised in-handler against that
/// guard and refused without one.
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
    use crate::storage::integration_trigger_handlers::{
        test_notifier_handler, trigger_integration_handler, trigger_multiple_notifiers_handler,
    };
    use axum::routing::{MethodRouter, delete, get, post, put};

    let gate = |route: MethodRouter, feature: Feature| -> MethodRouter { maybe_gate(guard.as_ref(), route, feature) };
    let router = axum::Router::new()
        .route("/v1/integrations", gate(get(list_notifiers), Feature::IntegrationsView))
        .route("/v1/integrations", gate(post(create_notifier), Feature::IntegrationsEdit))
        // Specific routes must come before parameterized routes
        .route("/v1/integrations/config", gate(get(get_notifier_config), Feature::IntegrationsView))
        .route("/v1/integrations/runtime-variables", gate(get(get_runtime_variables), Feature::IntegrationsView))
        .route("/v1/integrations/test", gate(post(test_notifier_handler), Feature::IntegrationsEdit))
        .route(
            "/v1/integrations/trigger-multiple",
            gate(post(trigger_multiple_notifiers_handler), Feature::IntegrationsEdit),
        )
        // Parameterized routes come after specific ones
        .route("/v1/integrations/{id}", gate(get(get_notifier), Feature::IntegrationsView))
        .route("/v1/integrations/{id}", gate(put(update_notifier), Feature::IntegrationsEdit))
        .route("/v1/integrations/{id}", gate(delete(delete_notifier), Feature::IntegrationsDelete))
        .route("/v1/integrations/{id}/trigger", gate(post(trigger_integration_handler), Feature::IntegrationsEdit))
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

/// Audit records are appliance-wide evidence, so an audit integration is never tenant-owned.
fn ensure_audit_integration_is_global(
    category: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    if category == Some(AUDIT_CATEGORY) && tenant_id.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Governance audit integrations are appliance-wide and cannot belong to a tenant".to_string(),
        ));
    }
    Ok(())
}

/// Every write to the VP Audit Log becomes a delivery, far more than Email or
/// Slack can carry, and the records hold admin-only evidence, so audit
/// integrations are Stream or Webhook only.
fn ensure_audit_integration_type(
    category: Option<&str>,
    integration_type: &str,
) -> Result<(), (StatusCode, String)> {
    if category == Some(AUDIT_CATEGORY) && !AUDIT_INTEGRATION_TYPES.contains(&integration_type) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Governance audit integrations must be of type {}", AUDIT_INTEGRATION_TYPES.join(" or ")),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateIntegrationRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub configuration: JsonValue,
    pub content: JsonValue,
    pub status: String,
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn integration_allowed(
    integration: &Integration,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(
        integration
            .tenant_id
            .as_deref(),
        tenant_context(context),
    ) && scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::Integrations,
        &integration.id,
    )
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateIntegrationRequest {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub configuration: JsonValue,
    pub content: JsonValue,
    pub status: String,
}

/// List all integrations
pub async fn list_notifiers(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Result<Json<Vec<Integration>>, (StatusCode, String)> {
    let mut integrations = storage
        .list()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list integrations: {}", e)))?;
    integrations.retain(|integration| integration_allowed(integration, &context, &scope));
    if integrations
        .iter()
        .any(is_audit_integration)
        && !AuditCaller::new(&guard, &caller, &pat)
            .may_access_audit()
            .await?
    {
        integrations.retain(|integration| !is_audit_integration(integration));
    }
    Ok(Json(integrations))
}

/// Get a specific integration by ID
pub async fn get_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Result<Json<Integration>, (StatusCode, String)> {
    let integration = storage
        .load(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !integration_allowed(&integration, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Integration not found".to_string()));
    }
    if is_audit_integration(&integration)
        && !AuditCaller::new(&guard, &caller, &pat)
            .may_access_audit()
            .await?
    {
        return Err((StatusCode::NOT_FOUND, "Integration not found".to_string()));
    }
    Ok(Json(integration))
}

/// Create a new integration
pub async fn create_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Extension(config): Extension<Arc<GatewayConfig>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(mut req): Json<CreateIntegrationRequest>,
) -> Result<(StatusCode, Json<Integration>), (StatusCode, String)> {
    if req.category.as_deref() == Some(AUDIT_CATEGORY) {
        AuditCaller::new(&guard, &caller, &pat)
            .require_audit_access()
            .await?;
    }
    crate::config::enforce_add("integrations")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    ensure_audit_integration_is_global(req.category.as_deref(), req.tenant_id.as_deref())?;
    ensure_audit_integration_type(req.category.as_deref(), &req.integration_type)?;
    // Validate name
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Integration name is required".to_string()));
    }

    // Validate type using config
    let valid_types: Vec<&str> = config
        .integration
        .types
        .iter()
        .map(|t| t.enum_value.as_str())
        .collect();
    if !valid_types.contains(&req.integration_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid integration type. Must be one of: {:?}", valid_types)));
    }

    // Validate status
    let valid_statuses = ["active", "disabled"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid status. Must be one of: {:?}", valid_statuses)));
    }

    // Validate configuration is an object
    if !req.configuration.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Configuration must be a JSON object".to_string()));
    }

    // Validate content is an object
    if !req.content.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Content must be a JSON object".to_string()));
    }

    // Validate category if provided
    if let Some(ref category) = req.category {
        let valid_categories: Vec<&str> = config
            .integration
            .categories
            .iter()
            .map(|c| c.enum_value.as_str())
            .collect();
        if !valid_categories.contains(&category.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid category. Must be one of: {:?}", valid_categories)));
        }

        // Validate that content template variables match the category
        let content_str = serde_json::to_string(&req.content)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to serialize content: {}", e)))?;

        let invalid_vars = crate::integrations::validate_template_variables(&content_str, category);
        if !invalid_vars.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid runtime variables for category '{}': {}. These variables are not available for this category. Use variables from the allowed list, or prefix custom variables with underscore (e.g., ${{_MY_VAR}})",
                    category,
                    invalid_vars.join(", ")
                ),
            ));
        }
    }

    // Create the integration
    let mut integration = Integration::new(
        req.name,
        req.description,
        req.integration_type,
        req.configuration,
        req.content,
        req.status,
        req.category,
    );
    integration.tenant_id = req.tenant_id;
    if !integration_allowed(&integration, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".into()));
    }

    storage
        .save(&integration)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save integration: {}", e)))?;

    tracing::info!("Created integration '{}' ({})", integration.name, integration.id);

    Ok((StatusCode::CREATED, Json(integration)))
}

/// Update an existing integration
pub async fn update_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Extension(config): Extension<Arc<GatewayConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(req): Json<UpdateIntegrationRequest>,
) -> Result<Json<Integration>, (StatusCode, String)> {
    // Validate name
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Integration name is required".to_string()));
    }

    // Validate type using config
    let valid_types: Vec<&str> = config
        .integration
        .types
        .iter()
        .map(|t| t.enum_value.as_str())
        .collect();
    if !valid_types.contains(&req.integration_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid integration type. Must be one of: {:?}", valid_types)));
    }

    // Validate status
    let valid_statuses = ["active", "disabled"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid status. Must be one of: {:?}", valid_statuses)));
    }

    // Validate configuration is an object
    if !req.configuration.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Configuration must be a JSON object".to_string()));
    }

    // Validate content is an object
    if !req.content.is_object() {
        return Err((StatusCode::BAD_REQUEST, "Content must be a JSON object".to_string()));
    }

    // Validate category if provided
    if let Some(ref category) = req.category {
        let valid_categories: Vec<&str> = config
            .integration
            .categories
            .iter()
            .map(|c| c.enum_value.as_str())
            .collect();
        if !valid_categories.contains(&category.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid category. Must be one of: {:?}", valid_categories)));
        }

        // Validate that content template variables match the category
        let content_str = serde_json::to_string(&req.content)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to serialize content: {}", e)))?;

        let invalid_vars = crate::integrations::validate_template_variables(&content_str, category);
        if !invalid_vars.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid runtime variables for category '{}': {}. These variables are not available for this category. Use variables from the allowed list, or prefix custom variables with underscore (e.g., ${{_MY_VAR}})",
                    category,
                    invalid_vars.join(", ")
                ),
            ));
        }
    }

    // Load existing integration to preserve created_at
    let existing = storage
        .load(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !integration_allowed(&existing, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".into()));
    }
    if is_audit_integration(&existing) || req.category.as_deref() == Some(AUDIT_CATEGORY) {
        AuditCaller::new(&guard, &caller, &pat)
            .require_audit_access()
            .await?;
    }
    ensure_audit_integration_is_global(req.category.as_deref(), existing.tenant_id.as_deref())?;
    ensure_audit_integration_type(req.category.as_deref(), &req.integration_type)?;

    // Create updated integration
    let now = chrono::Utc::now().to_rfc3339();
    let updated = Integration {
        id: existing.id,
        tenant_id: existing.tenant_id,
        name: req.name,
        description: req.description,
        integration_type: req.integration_type,
        category: req.category,
        configuration: req.configuration,
        content: req.content,
        status: req.status,
        created_at: existing.created_at,
        updated_at: now,
    };

    storage
        .update(&id, &updated)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update integration: {}", e)))?;

    tracing::info!("Updated integration '{}' ({})", updated.name, updated.id);

    Ok(Json(updated))
}

/// Delete a integration
pub async fn delete_notifier(
    Extension(storage): Extension<Arc<IntegrationStorage>>,
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let integration = storage
        .load(&id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !integration_allowed(&integration, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".into()));
    }
    if is_audit_integration(&integration) {
        AuditCaller::new(&guard, &caller, &pat)
            .require_audit_access()
            .await?;
    }
    storage
        .delete(&id)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, msg)
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete integration: {}", msg))
            }
        })?;

    tracing::info!("Deleted integration {}", id);

    // Clean up integration from all trigger mapping files
    let triggers_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    );

    // Remove from user integrations
    if let Ok(user_storage) = crate::integrations::UserIntegrationsStorage::new(triggers_path.join("users")).await
        && let Err(e) = user_storage
            .remove_integration(&id)
            .await
    {
        tracing::warn!("Failed to remove integration {} from user triggers: {}", id, e);
    }

    // Remove from gateway integrations
    if let Ok(gateway_storage) =
        crate::integrations::GatewayIntegrationsStorage::new(triggers_path.join("gateways")).await
        && let Err(e) = gateway_storage
            .remove_integration(&id)
            .await
    {
        tracing::warn!("Failed to remove integration {} from gateway triggers: {}", id, e);
    }

    // Remove from identity integrations
    if let Ok(identity_storage) =
        crate::integrations::IdentityIntegrationsStorage::new(triggers_path.join("identities")).await
        && let Err(e) = identity_storage
            .remove_integration(&id)
            .await
    {
        tracing::warn!("Failed to remove integration {} from identity triggers: {}", id, e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get runtime variables available for integration templates
pub async fn get_runtime_variables() -> Result<Json<crate::integrations::RuntimeVariablesResponse>, (StatusCode, String)>
{
    let variables = crate::integrations::get_runtime_variables();
    Ok(Json(variables))
}

/// Get integration configuration (types and categories with metadata)
pub async fn get_notifier_config(
    Extension(config): Extension<Arc<GatewayConfig>>
) -> Result<Json<crate::config::IntegrationConfig>, (StatusCode, String)> {
    Ok(Json(config.integration.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::rbac::RbacConfig;

    const ADMIN: &str = "admin-1";
    const OPERATOR: &str = "operator-1";

    /// Operators hold every integration permission but not `audit.view`, which
    /// stays administrator-only.
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
        fn guard(&self) -> Option<Extension<RbacGuard>> {
            Some(Extension(self.guard.clone()))
        }

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

        async fn create(
            &self,
            user_id: Option<&str>,
            pat_scopes: Option<&[&str]>,
            guard: Option<Extension<RbacGuard>>,
            request: CreateIntegrationRequest,
        ) -> Result<Integration, StatusCode> {
            create_notifier(
                Extension(self.integrations.clone()),
                Extension(self.config.clone()),
                pat(pat_scopes),
                None,
                None,
                guard,
                caller(user_id),
                Json(request),
            )
            .await
            .map(|(_, Json(integration))| integration)
            .map_err(|(status, _)| status)
        }

        async fn list(
            &self,
            user_id: &str,
        ) -> Vec<String> {
            let Json(integrations) = list_notifiers(
                Extension(self.integrations.clone()),
                None,
                None,
                self.guard(),
                caller(Some(user_id)),
                None,
            )
            .await
            .unwrap();
            integrations
                .into_iter()
                .map(|integration| integration.name)
                .collect()
        }

        async fn get(
            &self,
            user_id: &str,
            id: &str,
        ) -> StatusCode {
            match get_notifier(
                Extension(self.integrations.clone()),
                Path(id.to_string()),
                None,
                None,
                self.guard(),
                caller(Some(user_id)),
                None,
            )
            .await
            {
                Ok(_) => StatusCode::OK,
                Err((status, _)) => status,
            }
        }

        async fn update(
            &self,
            user_id: &str,
            existing: &Integration,
            category: &str,
        ) -> StatusCode {
            match update_notifier(
                Extension(self.integrations.clone()),
                Extension(self.config.clone()),
                Path(existing.id.clone()),
                None,
                None,
                self.guard(),
                caller(Some(user_id)),
                None,
                Json(UpdateIntegrationRequest {
                    name: format!("{} (edited)", existing.name),
                    description: String::new(),
                    integration_type: existing
                        .integration_type
                        .clone(),
                    category: Some(category.to_string()),
                    configuration: existing.configuration.clone(),
                    content: serde_json::json!({"type": "${EVENT_TYPE}"}),
                    status: "active".to_string(),
                }),
            )
            .await
            {
                Ok(_) => StatusCode::OK,
                Err((status, _)) => status,
            }
        }

        async fn delete(
            &self,
            user_id: &str,
            id: &str,
        ) -> StatusCode {
            match delete_notifier(
                Extension(self.integrations.clone()),
                Extension(self.bootstrap()),
                Path(id.to_string()),
                None,
                None,
                self.guard(),
                caller(Some(user_id)),
                None,
            )
            .await
            {
                Ok(status) => status,
                Err((status, _)) => status,
            }
        }

        async fn stored(&self) -> Vec<Integration> {
            self.integrations
                .list()
                .await
                .unwrap()
        }
    }

    fn caller(user_id: Option<&str>) -> Option<Extension<AuthGuardOk>> {
        user_id.map(|id| Extension(AuthGuardOk(id.to_string())))
    }

    fn pat(scopes: Option<&[&str]>) -> Option<Extension<PatContext>> {
        scopes.map(|scopes| {
            Extension(PatContext(Some(
                scopes
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect(),
            )))
        })
    }

    fn request(
        category: &str,
        tenant_id: Option<&str>,
    ) -> CreateIntegrationRequest {
        CreateIntegrationRequest {
            tenant_id: tenant_id.map(str::to_string),
            name: format!("{category} stream"),
            description: String::new(),
            integration_type: "stream".to_string(),
            category: Some(category.to_string()),
            configuration: serde_json::json!({"platform": "kafka", "topic": "audit", "brokers": "127.0.0.1:1"}),
            content: serde_json::json!({"type": "${EVENT_TYPE}", "record": "${AUDIT_RECORD}"}),
            status: "active".to_string(),
        }
    }

    #[tokio::test]
    async fn administrator_creates_an_audit_integration() {
        let f = fixture().await;
        let created = f
            .create(Some(ADMIN), None, f.guard(), request("audit", None))
            .await
            .unwrap();

        assert_eq!(created.category.as_deref(), Some("audit"));
        assert_eq!(created.tenant_id, None);
        assert_eq!(f.stored().await.len(), 1);
    }

    #[tokio::test]
    async fn caller_without_audit_view_cannot_create_an_audit_integration() {
        let f = fixture().await;
        let status = f
            .create(Some(OPERATOR), None, f.guard(), request("audit", None))
            .await
            .unwrap_err();

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(f.stored().await.is_empty());
    }

    #[tokio::test]
    async fn caller_without_audit_view_still_creates_other_categories() {
        let f = fixture().await;
        let mut general = request("general", None);
        general.content = serde_json::json!({"type": "${EVENT_TYPE}"});
        let created = f
            .create(Some(OPERATOR), None, f.guard(), general)
            .await
            .unwrap();

        assert_eq!(created.category.as_deref(), Some("general"));
    }

    #[tokio::test]
    async fn access_token_scopes_bound_audit_integration_creation() {
        let f = fixture().await;
        let without_scope = f
            .create(Some(ADMIN), Some(&["integrations.edit"]), f.guard(), request("audit", None))
            .await;
        assert_eq!(without_scope.unwrap_err(), StatusCode::FORBIDDEN);

        let with_scope = f
            .create(Some(ADMIN), Some(&["integrations.edit", "audit.view"]), f.guard(), request("audit", None))
            .await;
        assert_eq!(
            with_scope
                .unwrap()
                .category
                .as_deref(),
            Some("audit")
        );
    }

    #[tokio::test]
    async fn audit_integrations_fail_closed_without_an_rbac_guard() {
        let f = fixture().await;
        let unguarded = f
            .create(Some(ADMIN), None, None, request("audit", None))
            .await;
        assert_eq!(unguarded.unwrap_err(), StatusCode::FORBIDDEN);

        let anonymous = f
            .create(None, None, f.guard(), request("audit", None))
            .await;
        assert_eq!(anonymous.unwrap_err(), StatusCode::FORBIDDEN);
        assert!(f.stored().await.is_empty());
    }

    #[tokio::test]
    async fn audit_integrations_are_stream_or_webhook_only() {
        let f = fixture().await;
        for (integration_type, expected) in
            [("email", Err(StatusCode::BAD_REQUEST)), ("slack", Err(StatusCode::BAD_REQUEST)), ("webhook", Ok(()))]
        {
            let mut typed = request("audit", None);
            typed.integration_type = integration_type.to_string();
            let created = f
                .create(Some(ADMIN), None, f.guard(), typed)
                .await
                .map(|_| ());
            assert_eq!(created, expected, "{integration_type}");
        }
        assert_eq!(f.stored().await.len(), 1, "only the webhook was stored");
    }

    #[tokio::test]
    async fn a_slack_integration_cannot_move_into_the_audit_category() {
        let f = fixture().await;
        let mut slack = f.seed("general").await;
        slack.integration_type = "slack".to_string();
        f.integrations
            .save(&slack)
            .await
            .unwrap();

        assert_eq!(
            f.update(ADMIN, &slack, "audit")
                .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn audit_integrations_cannot_belong_to_a_tenant() {
        let f = fixture().await;
        let status = f
            .create(Some(ADMIN), None, f.guard(), request("audit", Some("tenant-a")))
            .await
            .unwrap_err();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(f.stored().await.is_empty());
    }

    #[tokio::test]
    async fn listing_hides_audit_integrations_from_callers_without_audit_view() {
        let f = fixture().await;
        f.seed("general").await;
        f.seed("audit").await;

        let mut admin_view = f.list(ADMIN).await;
        admin_view.sort();
        assert_eq!(admin_view, vec!["audit integration", "general integration"]);
        assert_eq!(f.list(OPERATOR).await, vec!["general integration"]);
    }

    #[tokio::test]
    async fn reading_an_audit_integration_requires_audit_view() {
        let f = fixture().await;
        let audit = f.seed("audit").await;

        assert_eq!(f.get(ADMIN, &audit.id).await, StatusCode::OK);
        assert_eq!(
            f.get(OPERATOR, &audit.id)
                .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn editing_into_or_out_of_the_audit_category_requires_audit_view() {
        let f = fixture().await;
        let audit = f.seed("audit").await;
        let general = f.seed("general").await;

        assert_eq!(
            f.update(OPERATOR, &audit, "audit")
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.update(OPERATOR, &audit, "general")
                .await,
            StatusCode::FORBIDDEN,
            "moving an audit integration out of the category is also protected"
        );
        assert_eq!(
            f.update(OPERATOR, &general, "audit")
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.update(OPERATOR, &general, "general")
                .await,
            StatusCode::OK
        );
        assert_eq!(
            f.update(ADMIN, &audit, "audit")
                .await,
            StatusCode::OK
        );

        let stored = f.stored().await;
        let audit_now = stored
            .iter()
            .find(|integration| integration.id == audit.id)
            .unwrap();
        assert_eq!(audit_now.name, "audit integration (edited)");
        assert_eq!(audit_now.category.as_deref(), Some("audit"));
    }

    #[tokio::test]
    async fn a_tenant_owned_integration_cannot_move_into_the_audit_category() {
        let f = fixture().await;
        let mut general = f.seed("general").await;
        general.tenant_id = Some("tenant-a".to_string());
        f.integrations
            .save(&general)
            .await
            .unwrap();

        assert_eq!(
            f.update(ADMIN, &general, "audit")
                .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn deleting_an_audit_integration_requires_audit_view() {
        let f = fixture().await;
        let audit = f.seed("audit").await;

        assert_eq!(
            f.delete(OPERATOR, &audit.id)
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(f.stored().await.len(), 1);

        assert_eq!(
            f.delete(ADMIN, &audit.id)
                .await,
            StatusCode::NO_CONTENT
        );
        assert!(f.stored().await.is_empty());
    }

    async fn trigger_status(
        f: &Fixture,
        user_id: &str,
        id: &str,
    ) -> StatusCode {
        use crate::storage::integration_trigger_handlers::{TriggerNotifierRequest, trigger_integration_handler};
        use axum::response::IntoResponse;

        match trigger_integration_handler(
            Extension(f.integrations.clone()),
            Path(id.to_string()),
            None,
            None,
            f.guard(),
            caller(Some(user_id)),
            None,
            Json(TriggerNotifierRequest {
                subject: "forged".to_string(),
                message: "forged".to_string(),
                variables: std::collections::HashMap::from([(
                    "AUDIT_RECORD".to_string(),
                    r#"{"event":"forged"}"#.to_string(),
                )]),
            }),
        )
        .await
        {
            Ok(response) => response
                .into_response()
                .status(),
            Err((status, _)) => status,
        }
    }

    #[tokio::test]
    async fn triggering_an_audit_integration_requires_audit_view() {
        let f = fixture().await;
        let mut audit = f.seed("audit").await;
        audit.status = "disabled".to_string();
        f.integrations
            .save(&audit)
            .await
            .unwrap();

        assert_eq!(trigger_status(&f, OPERATOR, &audit.id).await, StatusCode::FORBIDDEN);
        assert_eq!(
            trigger_status(&f, ADMIN, &audit.id).await,
            StatusCode::INTERNAL_SERVER_ERROR,
            "an administrator passes the access check and reaches the publish step"
        );
    }

    #[tokio::test]
    async fn triggering_several_integrations_including_an_audit_one_requires_audit_view() {
        use crate::storage::integration_trigger_handlers::{
            TriggerNotifiersRequest, trigger_multiple_notifiers_handler,
        };
        use axum::response::IntoResponse;

        let f = fixture().await;
        let audit = f.seed("audit").await;
        let status = match trigger_multiple_notifiers_handler(
            Extension(f.integrations.clone()),
            None,
            None,
            f.guard(),
            caller(Some(OPERATOR)),
            None,
            Json(TriggerNotifiersRequest {
                integration_ids: vec![audit.id.clone()],
                subject: "forged".to_string(),
                message: "forged".to_string(),
                variables: Default::default(),
            }),
        )
        .await
        {
            Ok(response) => response
                .into_response()
                .status(),
            Err((status, _)) => status,
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
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

    fn request_json(category: &str) -> serde_json::Value {
        serde_json::to_value(request(category, None)).unwrap()
    }

    fn names(list: &serde_json::Value) -> Vec<String> {
        let mut names: Vec<String> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|integration| {
                integration["name"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn integration_router_enforces_audit_view_through_the_rbac_layers() {
        let f = fixture().await;
        let router = || f.router(Some(f.guard.clone()));
        let mut general = request_json("general");
        general["content"] = serde_json::json!({"type": "${EVENT_TYPE}"});

        let (status, _) = call(router(), OPERATOR, "POST", "/v1/integrations", Some(request_json("audit"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(router(), OPERATOR, "POST", "/v1/integrations", Some(general)).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, created) = call(router(), ADMIN, "POST", "/v1/integrations", Some(request_json("audit"))).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"]
            .as_str()
            .unwrap()
            .to_string();

        let (_, admin_list) = call(router(), ADMIN, "GET", "/v1/integrations", None).await;
        assert_eq!(names(&admin_list), vec!["audit stream", "general stream"]);
        let (_, operator_list) = call(router(), OPERATOR, "GET", "/v1/integrations", None).await;
        assert_eq!(names(&operator_list), vec!["general stream"]);

        let item = format!("/v1/integrations/{id}");
        assert_eq!(
            call(router(), ADMIN, "GET", &item, None)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(router(), OPERATOR, "GET", &item, None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let forged = serde_json::json!({"subject": "forged", "message": "forged", "variables": {}});
        assert_eq!(
            call(router(), OPERATOR, "POST", &format!("{item}/trigger"), Some(forged))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(router(), OPERATOR, "DELETE", &item, None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(router(), ADMIN, "DELETE", &item, None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn integration_router_without_an_rbac_guard_refuses_every_request() {
        let f = fixture().await;
        let existing = f.seed("general").await;
        let mut general = request_json("general");
        general["content"] = serde_json::json!({"type": "${EVENT_TYPE}"});
        let item = format!("/v1/integrations/{}", existing.id);
        let trigger = format!("{item}/trigger");

        for (method, uri, body) in [
            ("GET", "/v1/integrations", None),
            ("POST", "/v1/integrations", Some(general.clone())),
            ("POST", "/v1/integrations", Some(request_json("audit"))),
            ("GET", "/v1/integrations/config", None),
            ("GET", "/v1/integrations/runtime-variables", None),
            ("POST", "/v1/integrations/test", Some(general.clone())),
            ("POST", "/v1/integrations/trigger-multiple", Some(serde_json::json!({}))),
            ("GET", item.as_str(), None),
            ("PUT", item.as_str(), Some(general.clone())),
            ("DELETE", item.as_str(), None),
            ("POST", trigger.as_str(), Some(serde_json::json!({}))),
        ] {
            let (status, _) = call(f.router(None), ADMIN, method, uri, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
        assert_eq!(f.stored().await.len(), 1, "nothing was created or deleted");
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
        let (_, stored) = call(router(), OPERATOR, "GET", "/v1/users/integrations", None).await;
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
