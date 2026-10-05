//! STS managed-connection (client) CRUD HTTP handlers.
//!
//! All endpoints are administrator-gated (`sts_clients.*`). Non-admin callers
//! receive `403 Forbidden`. Responses never include a client secret — only the
//! `client_secret_ref` into the secrets store is stored and returned.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::rbac::{Feature, RbacConfig};
use crate::secrets::SecretsStore;
use crate::sts::store::{StsClient, StsClientStorage};
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, tenant_for_create,
};

/// Axum state for the STS client admin handlers.
pub type StsClientAdminState = Arc<dyn StsClientStorage>;

/// Body for create / update.
#[derive(Debug, Default, Deserialize)]
pub struct StsClientRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub client_id: String,
    pub name: String,
    #[serde(default)]
    pub client_secret_ref: Option<String>,
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub allowed_subject_token_types: Vec<String>,
    #[serde(default)]
    pub allowed_subject_audiences: Vec<String>,
    #[serde(default)]
    pub allow_impersonation: bool,
    #[serde(default)]
    pub max_ttl_secs: Option<u64>,
    #[serde(default)]
    pub issue_id_jag: bool,
    #[serde(default)]
    pub trust_check_list: Vec<crate::trust_registry_verification::TrustCheckElement>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl ErrorBody {
    fn json(msg: impl Into<String>) -> Json<Self> {
        Json(Self { error: msg.into() })
    }
}

fn unauthorized() -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::UNAUTHORIZED, ErrorBody::json("Unauthorized"))
}

fn forbidden() -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::FORBIDDEN, ErrorBody::json("Forbidden"))
}

async fn require_permission(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
    feature: &Feature,
    pat: Option<&PatContext>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| {
            error!("Failed to load user {} for RBAC check: {}", user_id, e);
            unauthorized()
        })?
        .ok_or_else(|| {
            warn!(user_id = %user_id, "STS client CRUD rejected — user not found");
            unauthorized()
        })?;
    if !rbac_config.has_permission(&user.role, feature) {
        warn!(user_id = %user_id, feature = %feature.as_str(), "STS client CRUD rejected — insufficient permissions");
        return Err(forbidden());
    }
    if let Some(PatContext(Some(scopes))) = pat
        && !scopes
            .iter()
            .any(|scope| scope == feature.as_str())
    {
        warn!(user_id = %user_id, feature = %feature.as_str(), "STS client CRUD rejected — access-token scope excludes permission");
        return Err(forbidden());
    }
    Ok(())
}

fn validate(body: &StsClientRequest) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if body
        .client_id
        .trim()
        .is_empty()
    {
        return Err((StatusCode::BAD_REQUEST, ErrorBody::json("client_id is required")));
    }
    if body.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, ErrorBody::json("name is required")));
    }
    if let Err(e) = crate::config::agent_surface::validate_trust_check_list("caller", &body.trust_check_list) {
        return Err((StatusCode::BAD_REQUEST, ErrorBody::json(e.to_string())));
    }
    Ok(())
}

fn to_client(
    id: String,
    body: StsClientRequest,
) -> StsClient {
    let now = chrono::Utc::now();
    StsClient {
        id,
        tenant_id: body.tenant_id,
        client_id: body.client_id,
        name: body.name,
        client_secret_ref: body.client_secret_ref,
        allowed_audiences: body.allowed_audiences,
        allowed_scopes: body.allowed_scopes,
        allowed_subject_token_types: body.allowed_subject_token_types,
        allowed_subject_audiences: body.allowed_subject_audiences,
        allow_impersonation: body.allow_impersonation,
        max_ttl_secs: body.max_ttl_secs,
        issue_id_jag: body.issue_id_jag,
        trust_check_list: body.trust_check_list,
        created_at: now,
        updated_at: now,
    }
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

fn client_allowed(
    client: &StsClient,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(client.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::StsClients, &client.id)
}

async fn validate_secret_reference(
    owner_tenant_id: Option<&str>,
    secret_ref: Option<&str>,
    secrets_store: Option<&Arc<dyn SecretsStore>>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let Some(secret_ref) = secret_ref else {
        return Ok(());
    };
    let store = secrets_store
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Secrets store is not configured")))?;
    let secret = store
        .get_by_secret_id(secret_ref)
        .await
        .map_err(|e| {
            error!(secret_ref = %secret_ref, error = %e, "Failed to validate STS client secret reference");
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, ErrorBody::json("client_secret_ref does not reference an accessible secret"))
        })?;
    if !can_reference(owner_tenant_id, secret.tenant_id.as_deref())
        || !scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            ErrorBody::json("client_secret_ref does not reference an accessible secret"),
        ));
    }
    Ok(())
}

/// A resource token is accepted by whichever endpoint serves that resource,
/// and the Resource Server checks only issuer, audience and scope. Without this
/// check a tenant-scoped client could name another tenant's resource as an
/// audience and mint tokens that endpoint would accept.
///
/// Only resources this appliance serves are checked. `allowed_audiences` is
/// the general token-exchange allowlist and legitimately carries third-party
/// audiences, so an entry no endpoint serves is external and left alone. A
/// resource that any endpoint of a tenant the client cannot reference serves
/// is refused. A declaration only counts when its endpoint serves it
/// (`crate::sts::resource_owners`), so no tenant can block another by
/// declaring its resource.
///
/// This is early feedback: minting runs the same check again, which also
/// covers resources declared after the client was saved.
///
/// Appliance-global clients (no `tenant_id`) are administrator-created and keep
/// their existing reach.
async fn validate_audience_ownership(
    owner_tenant_id: Option<&str>,
    audiences: &[String],
    owners: &dyn crate::sts::resource_owners::StsResourceOwners,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    for audience in audiences {
        match crate::sts::resource_owners::ensure_client_may_target(owners, owner_tenant_id, audience).await {
            Ok(()) => {}
            Err(crate::sts::errors::StsError::InvalidTarget(_)) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    ErrorBody::json("allowed_audiences includes a resource this connection cannot target"),
                ));
            }
            Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))),
        }
    }
    Ok(())
}

/// `POST /v1/sts/clients` — create a managed connection.
pub async fn create_client(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(store): State<StsClientAdminState>,
    secrets_store: Option<Extension<Arc<dyn SecretsStore>>>,
    Extension(resource_owners): Extension<Arc<dyn crate::sts::resource_owners::StsResourceOwners>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut body): Json<StsClientRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::StsClientsEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    if let Err(e) = validate(&body) {
        return e.into_response();
    }
    body.tenant_id = match tenant_for_create(body.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, ErrorBody::json(message)).into_response(),
    };
    if let Err(response) =
        validate_audience_ownership(body.tenant_id.as_deref(), &body.allowed_audiences, resource_owners.as_ref()).await
    {
        return response.into_response();
    }
    if let Err(response) = validate_secret_reference(
        body.tenant_id.as_deref(),
        body.client_secret_ref
            .as_deref(),
        secrets_store
            .as_ref()
            .map(|Extension(store)| store),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await
    {
        return response.into_response();
    }
    match store
        .get_by_client_id(&body.client_id)
        .await
    {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, ErrorBody::json("client_id already exists")).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            error!("STS client uniqueness check failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error")).into_response();
        }
    }
    let client = to_client(uuid::Uuid::new_v4().to_string(), body);
    if !client_allowed(&client, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("STS client is outside this token's permitted scope"))
            .into_response();
    }
    match store.create(client).await {
        Ok(created) => {
            info!(id = %created.id, client_id = %created.client_id, "STS client created");
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(e) => {
            error!("Failed to create STS client: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to create client")).into_response()
        }
    }
}

/// `GET /v1/sts/clients` — list managed connections.
pub async fn list_clients(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(store): State<StsClientAdminState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::StsClientsView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    match store.list().await {
        Ok(mut clients) => {
            clients.retain(|client| client_allowed(client, &context, &scope));
            (StatusCode::OK, Json(clients)).into_response()
        }
        Err(e) => {
            error!("Failed to list STS clients: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to list clients")).into_response()
        }
    }
}

/// `GET /v1/sts/clients/{id}` — fetch one managed connection.
pub async fn get_client(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(store): State<StsClientAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::StsClientsView,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    match store.get(&id).await {
        Ok(Some(client)) if client_allowed(&client, &context, &scope) => (StatusCode::OK, Json(client)).into_response(),
        Ok(Some(_)) => (StatusCode::NOT_FOUND, ErrorBody::json("client not found")).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, ErrorBody::json("client not found")).into_response(),
        Err(e) => {
            error!("Failed to get STS client {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to get client")).into_response()
        }
    }
}

/// `PUT /v1/sts/clients/{id}` — update a managed connection.
pub async fn update_client(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(store): State<StsClientAdminState>,
    Path(id): Path<String>,
    secrets_store: Option<Extension<Arc<dyn SecretsStore>>>,
    Extension(resource_owners): Extension<Arc<dyn crate::sts::resource_owners::StsResourceOwners>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut body): Json<StsClientRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::StsClientsEdit,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    if let Err(e) = validate(&body) {
        return e.into_response();
    }
    let existing = match store.get(&id).await {
        Ok(Some(existing)) => existing,
        Ok(None) => return (StatusCode::NOT_FOUND, ErrorBody::json("client not found")).into_response(),
        Err(e) => {
            error!(id = %id, error = %e, "Failed to load STS client before update");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error")).into_response();
        }
    };
    if !client_allowed(&existing, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("STS client is outside this token's permitted scope"))
            .into_response();
    }
    body.tenant_id = existing.tenant_id.clone();
    if let Err(response) =
        validate_audience_ownership(body.tenant_id.as_deref(), &body.allowed_audiences, resource_owners.as_ref()).await
    {
        return response.into_response();
    }
    if let Err(response) = validate_secret_reference(
        body.tenant_id.as_deref(),
        body.client_secret_ref
            .as_deref(),
        secrets_store
            .as_ref()
            .map(|Extension(store)| store),
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await
    {
        return response.into_response();
    }
    // Reject a client_id collision with a *different* record.
    match store
        .get_by_client_id(&body.client_id)
        .await
    {
        Ok(Some(existing)) if existing.id != id => {
            return (StatusCode::CONFLICT, ErrorBody::json("client_id already in use")).into_response();
        }
        Ok(_) => {}
        Err(e) => {
            error!("STS client uniqueness check failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error")).into_response();
        }
    }
    match store
        .update(to_client(id.clone(), body))
        .await
    {
        Ok(updated) => {
            info!(id = %id, "STS client updated");
            (StatusCode::OK, Json(updated)).into_response()
        }
        Err(e) => {
            error!("Failed to update STS client {}: {}", id, e);
            (StatusCode::NOT_FOUND, ErrorBody::json("client not found")).into_response()
        }
    }
}

/// `DELETE /v1/sts/clients/{id}` — remove a managed connection.
pub async fn delete_client(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(store): State<StsClientAdminState>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(
        &user_id,
        &passkey_storage,
        &rbac_config,
        &Feature::StsClientsDelete,
        pat.as_ref()
            .map(|Extension(pat)| pat),
    )
    .await
    {
        return e.into_response();
    }
    match store.get(&id).await {
        Ok(Some(client)) if client_allowed(&client, &context, &scope) => {}
        Ok(Some(_)) => {
            return (StatusCode::FORBIDDEN, ErrorBody::json("STS client is outside this token's permitted scope"))
                .into_response();
        }
        Ok(None) => return (StatusCode::NOT_FOUND, ErrorBody::json("client not found")).into_response(),
        Err(e) => {
            error!(id = %id, error = %e, "Failed to load STS client before delete");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error")).into_response();
        }
    }
    match store.delete(&id).await {
        Ok(()) => {
            info!(id = %id, "STS client deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!("Failed to delete STS client {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to delete client")).into_response()
        }
    }
}

/// Build the STS client admin router. The caller must layer the session-auth
/// middleware and the `Extension<Arc<PasskeyStorage>>` / `Extension<Arc<RbacConfig>>`
/// extensions before merging, mirroring the JWT verification strategies router.
pub fn create_sts_client_router(
    state: StsClientAdminState,
    secrets_store: Option<Arc<dyn SecretsStore>>,
    resource_owners: Arc<dyn crate::sts::resource_owners::StsResourceOwners>,
) -> Router {
    let mut router = Router::new()
        .route("/v1/sts/clients", post(create_client))
        .route("/v1/sts/clients", get(list_clients))
        .route("/v1/sts/clients/{id}", get(get_client))
        .route("/v1/sts/clients/{id}", put(update_client))
        .route("/v1/sts/clients/{id}", delete(delete_client))
        .with_state(state);
    if let Some(secrets_store) = secrets_store {
        router = router.layer(Extension(secrets_store));
    }
    router.layer(Extension(resource_owners))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use regex::Regex;
    use tempfile::tempdir;

    use super::*;
    use crate::auth::storage::UserData;
    use crate::auth::types::{UserRole, UserStatus};

    struct OneSecretStore {
        secret: crate::secrets::Secret,
    }

    #[async_trait::async_trait]
    impl SecretsStore for OneSecretStore {
        async fn create(
            &self,
            _request: crate::secrets::CreateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            unreachable!()
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            Ok((id == self.secret.id).then(|| self.secret.clone()))
        }

        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            Ok((secret_id == self.secret.secret_id).then(|| self.secret.clone()))
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            unreachable!()
        }

        async fn update(
            &self,
            _id: &str,
            _request: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            unreachable!()
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            unreachable!()
        }
    }

    fn base_request() -> StsClientRequest {
        StsClientRequest {
            client_id: "agent".to_string(),
            name: "Agent".to_string(),
            client_secret_ref: Some("sts-secret-agent".to_string()),
            ..Default::default()
        }
    }

    fn status_of(result: Result<(), (StatusCode, Json<ErrorBody>)>) -> Option<StatusCode> {
        result
            .err()
            .map(|(status, _)| status)
    }

    #[tokio::test]
    async fn audiences_are_limited_to_resources_the_tenant_can_reference() {
        use crate::sts::resource_owners::tests::{Surfaces, network, surface};
        let owners = crate::sts::resource_owners::ApplianceResourceOwners::new(
            Some(Arc::new(Surfaces(vec![
                surface(Some("tenant-a"), "active", "/a", "https://gw.example/a"),
                surface(Some("tenant-b"), "active", "/b", "https://gw.example/b"),
                surface(None, "active", "/shared", "https://gw.example/shared"),
                // Tenant C declares tenant A's resource on a surface that does
                // not serve it. That must not block tenant A.
                surface(Some("tenant-c"), "active", "/squat", "https://gw.example/a"),
            ]))),
            None,
            network(),
        );
        let own = vec!["https://gw.example/a".to_string()];
        let other = vec!["https://gw.example/b".to_string()];
        let shared = vec!["https://gw.example/shared".to_string()];
        // `allowed_audiences` is the general token-exchange allowlist, so most
        // entries name third-party services this appliance knows nothing about.
        let external = vec!["https://api.example.com".to_string()];
        let undeclared = vec!["https://gw.example/not-a-surface".to_string()];

        for (label, audiences) in
            [("own", &own), ("appliance-global", &shared), ("external", &external), ("undeclared", &undeclared)]
        {
            assert!(
                validate_audience_ownership(Some("tenant-a"), audiences, &owners)
                    .await
                    .is_ok(),
                "{label} must be accepted"
            );
        }
        // The cross-tenant mint this check exists to stop.
        assert_eq!(
            status_of(validate_audience_ownership(Some("tenant-a"), &other, &owners).await),
            Some(StatusCode::BAD_REQUEST)
        );
        // One bad entry rejects the whole request, even alongside valid ones.
        let mut mixed = own.clone();
        mixed.extend(external.clone());
        mixed.extend(other.clone());
        assert_eq!(
            status_of(validate_audience_ownership(Some("tenant-a"), &mixed, &owners).await),
            Some(StatusCode::BAD_REQUEST)
        );
        // Administrator-created appliance-global clients keep their reach.
        assert!(
            validate_audience_ownership(None, &other, &owners)
                .await
                .is_ok()
        );
        // Without endpoint stores nothing is served here; minting still checks.
        for audiences in [&own, &other] {
            assert!(
                validate_audience_ownership(
                    Some("tenant-a"),
                    audiences,
                    &crate::sts::resource_owners::NoResourceOwners
                )
                .await
                .is_ok()
            );
        }
    }

    #[test]
    fn validate_accepts_a_complete_request() {
        assert!(validate(&base_request()).is_ok());
    }

    #[test]
    fn validate_requires_client_id_and_name() {
        let mut blank_id = base_request();
        blank_id.client_id = "   ".to_string();
        assert_eq!(status_of(validate(&blank_id)), Some(StatusCode::BAD_REQUEST));

        let mut blank_name = base_request();
        blank_name.name = String::new();
        assert_eq!(status_of(validate(&blank_name)), Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn secret_reference_must_match_tenant_and_pat_scope() {
        let now = Utc::now();
        let store: Arc<dyn SecretsStore> = Arc::new(OneSecretStore {
            secret: crate::secrets::Secret {
                id: "stored-id".into(),
                tenant_id: Some("tenant-a".into()),
                name: "STS secret".into(),
                secret_id: "sts-secret".into(),
                description: None,
                value: "secret".into(),
                secret_type: "General".into(),
                tags: Vec::new(),
                created_at: now,
                updated_at: now,
            },
        });
        let context = PatTenantContext {
            token_id: "atgat-test".into(),
            tenant_id: "tenant-a".into(),
        };
        let allowed = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-a:secrets:sts-secret\z").unwrap()));
        let denied = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-a:secrets:other-secret\z").unwrap()));

        assert!(
            validate_secret_reference(
                Some("tenant-a"),
                Some("sts-secret"),
                Some(&store),
                Some(&context),
                Some(&allowed)
            )
            .await
            .is_ok()
        );
        assert_eq!(
            status_of(
                validate_secret_reference(
                    Some("tenant-a"),
                    Some("sts-secret"),
                    Some(&store),
                    Some(&context),
                    Some(&denied),
                )
                .await
            ),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            status_of(
                validate_secret_reference(
                    Some("tenant-b"),
                    Some("sts-secret"),
                    Some(&store),
                    Some(&context),
                    Some(&allowed),
                )
                .await
            ),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn approved_user_permission_is_still_ceilinged_by_pat_scope() {
        let temp = tempdir().unwrap();
        let storage = PasskeyStorage::new(
            temp.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            temp.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = Utc::now();
        storage
            .save_user(&UserData {
                user_id: "admin".into(),
                username: "admin".into(),
                passkeys: Vec::new(),
                role: UserRole::Administrator,
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
        let rbac = RbacConfig::default();
        let excluded = PatContext(Some(vec!["surfaces.view".into()]));
        let allowed = PatContext(Some(vec!["sts_clients.view".into()]));

        assert_eq!(
            status_of(require_permission("admin", &storage, &rbac, &Feature::StsClientsView, Some(&excluded)).await),
            Some(StatusCode::FORBIDDEN)
        );
        assert!(
            require_permission("admin", &storage, &rbac, &Feature::StsClientsView, Some(&allowed))
                .await
                .is_ok()
        );
    }
}
