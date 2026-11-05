//! Secrets API handlers

use super::{CreateSecretRequest, SecretListItem, SecretsStore, UpdateSecretRequest};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{error, warn};

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::integrations::definitions::DefinitionStores;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, can_reference, scope_allows_resource, tenant_for_create,
};

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

fn is_visible(
    tenant_id: Option<&str>,
    secret_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_access(tenant_id, context) && scope_allows_resource(scope, context, ResourceKind::Secrets, secret_id)
}

/// List all secrets (without sensitive values)
pub async fn list_secrets(
    State(store): State<Arc<dyn SecretsStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match store.list_all().await {
        Ok(mut secrets) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            secrets.retain(|secret| is_visible(secret.tenant_id.as_deref(), &secret.secret_id, context, scope));
            (StatusCode::OK, Json(secrets)).into_response()
        }
        Err(e) => {
            error!("Failed to list secrets: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

/// Get a specific secret by ID (without the sensitive value)
pub async fn get_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match store.get(&id).await {
        Ok(Some(secret))
            if is_visible(
                secret.tenant_id.as_deref(),
                &secret.secret_id,
                tenant_context(&context),
                resource_scope(&scope),
            ) =>
        {
            (StatusCode::OK, Json(SecretListItem::from(secret))).into_response()
        }
        Ok(Some(_)) => (StatusCode::NOT_FOUND, "Secret not found").into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Secret not found").into_response(),
        Err(e) => {
            error!("Failed to get secret {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

/// Create a new secret
pub async fn create_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut request): Json<CreateSecretRequest>,
) -> impl IntoResponse {
    if request
        .secret_id
        .starts_with(crate::api_keys::KEY_ID_PREFIX)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": format!(
                "secret_id cannot start with {}, which is reserved for API key ids",
                crate::api_keys::KEY_ID_PREFIX
            ) })),
        )
            .into_response();
    }
    request.tenant_id = match tenant_for_create(request.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "message": message }))).into_response();
        }
    };
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::Secrets,
        &request.secret_id,
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "secret_id is outside this token's permitted scope" })),
        )
            .into_response();
    }
    // Enforce the appliance secret limit (per-type plus the cross-store total).
    if let Err(e) = crate::config::enforce_add("secrets.secret").await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "message": e.message() }))).into_response();
    }
    match store.create(request).await {
        Ok(secret) => {
            // Trigger integration event (without sensitive value)
            let trigger_secret = crate::integrations::secrets_integration_triggers::Secret {
                id: secret.id.clone(),
                name: secret.name.clone(),
                description: secret
                    .description
                    .clone()
                    .unwrap_or_default(),
                tags: secret.tags.clone(),
                created_at: secret.created_at.to_rfc3339(),
                updated_at: secret.updated_at.to_rfc3339(),
            };
            if let Some(store) = notification_store {
                tokio::spawn(async move {
                    crate::integrations::trigger_secret_created(&store, &trigger_secret).await;
                });
            }

            (StatusCode::CREATED, Json(SecretListItem::from(secret))).into_response()
        }
        Err(e) => {
            error!("Failed to create secret: {}", e);
            let error_message = e.to_string();
            let error_json = serde_json::json!({
                "message": error_message
            });
            (StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

/// Update an existing secret
pub async fn update_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(secrets_cache): Extension<Option<crate::a2a::auth::SecretsCache>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<UpdateSecretRequest>,
) -> impl IntoResponse {
    let old_secret = match store.get(&id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => return (StatusCode::NOT_FOUND, "Secret not found").into_response(),
        Err(e) => {
            error!("Failed to load secret {}: {}", id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };
    if !is_visible(
        old_secret
            .tenant_id
            .as_deref(),
        &old_secret.secret_id,
        tenant_context(&context),
        resource_scope(&scope),
    ) {
        return (StatusCode::NOT_FOUND, "Secret not found").into_response();
    }
    if !can_mutate(
        old_secret
            .tenant_id
            .as_deref(),
        tenant_context(&context),
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Secret is outside this token's permitted scope" })),
        )
            .into_response();
    }

    match store
        .update(&id, request)
        .await
    {
        Ok(secret) => {
            let old_trigger = crate::integrations::secrets_integration_triggers::Secret {
                id: old_secret.id.clone(),
                name: old_secret.name.clone(),
                description: old_secret
                    .description
                    .clone()
                    .unwrap_or_default(),
                tags: old_secret.tags.clone(),
                created_at: old_secret
                    .created_at
                    .to_rfc3339(),
                updated_at: old_secret
                    .updated_at
                    .to_rfc3339(),
            };
            let new_trigger = crate::integrations::secrets_integration_triggers::Secret {
                id: secret.id.clone(),
                name: secret.name.clone(),
                description: secret
                    .description
                    .clone()
                    .unwrap_or_default(),
                tags: secret.tags.clone(),
                created_at: secret.created_at.to_rfc3339(),
                updated_at: secret.updated_at.to_rfc3339(),
            };
            if let Some(store) = notification_store {
                tokio::spawn(async move {
                    crate::integrations::trigger_secret_updated(&store, &old_trigger, &new_trigger).await;
                });
            }

            if let Some(cache) = secrets_cache {
                crate::a2a::clear_secret_cache(&secret.secret_id, &cache);
            }

            (StatusCode::OK, Json(SecretListItem::from(secret))).into_response()
        }
        Err(e) => {
            error!("Failed to update secret {}: {}", id, e);
            let error_message = e.to_string();
            let error_json = serde_json::json!({
                "message": error_message
            });
            (StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

const SECRET_IN_USE: &str = "The secret is in use; remove its references first, or delete it with force=true";

#[derive(Debug, Default, serde::Deserialize)]
pub struct DeleteSecretQuery {
    /// Delete the secret although surfaces, credential providers, A2A proxies or STS clients
    /// still reference it. An integration endpoint that references it still blocks the delete.
    #[serde(default)]
    pub force: bool,
}

/// Delete a secret, unless an integration endpoint references it, or, without `force`,
/// another record does
#[allow(clippy::too_many_arguments)]
pub async fn delete_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(secrets_cache): Extension<Option<crate::a2a::auth::SecretsCache>>,
    Extension(definitions): Extension<Option<Arc<DefinitionStores>>>,
    Extension(references): Extension<crate::credential_providers::references::ReferenceStores>,
    Extension(rbac): Extension<Option<crate::auth_manager::middleware::RbacGuard>>,
    Path(id): Path<String>,
    Query(query): Query<DeleteSecretQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: Option<Extension<crate::auth_manager::middleware::AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> impl IntoResponse {
    let secret = match store.get(&id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => return (StatusCode::NOT_FOUND, "Secret not found").into_response(),
        Err(e) => {
            error!("Failed to load secret {}: {}", id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };
    if !is_visible(secret.tenant_id.as_deref(), &secret.secret_id, tenant_context(&context), resource_scope(&scope)) {
        return (StatusCode::NOT_FOUND, "Secret not found").into_response();
    }
    if !can_mutate(secret.tenant_id.as_deref(), tenant_context(&context)) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Secret is outside this token's permitted scope" })),
        )
            .into_response();
    }
    // Endpoints resolve appliance-wide secrets only, so only those can be in use.
    if let Some(definitions) = definitions
        && can_reference(None, secret.tenant_id.as_deref())
    {
        match definitions
            .endpoints_referencing(&secret.secret_id)
            .await
        {
            Ok(endpoints) if endpoints.is_empty() => {}
            Ok(endpoints) => {
                let names: Vec<String> = endpoints
                    .into_iter()
                    .map(|endpoint| endpoint.name)
                    .collect();
                let message = format!("The secret is used by these integration endpoints: {}", names.join(", "));
                return (StatusCode::CONFLICT, Json(serde_json::json!({ "message": message }))).into_response();
            }
            Err(e) => {
                error!("Failed to check the integration endpoints using secret {}: {}", id, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
            }
        }
    }
    let referrers = match references
        .referrers_of_secret(&secret.secret_id)
        .await
    {
        Ok(referrers) => referrers,
        Err(e) => {
            error!("Failed to find the records using secret {}: {}", id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };
    if !referrers.is_empty() {
        if !query.force {
            let viewable = crate::credential_providers::references::ViewableKinds::of_caller(
                rbac.as_ref(),
                caller
                    .as_ref()
                    .map(|Extension(caller)| caller),
                pat.as_ref()
                    .map(|Extension(pat)| pat),
            )
            .await;
            return crate::credential_providers::references::conflict_response(
                SECRET_IN_USE,
                &referrers,
                &viewable,
                tenant_context(&context),
                resource_scope(&scope),
            );
        }
        let referrer_ids: Vec<&str> = referrers
            .iter()
            .map(|referrer| referrer.id.as_str())
            .collect();
        warn!(
            secret_id = %secret.secret_id,
            referrers = ?referrer_ids,
            "Secret deleted with force while still referenced"
        );
    }

    match store.delete(&id).await {
        Ok(_) => {
            let trigger_secret = crate::integrations::secrets_integration_triggers::Secret {
                id: secret.id.clone(),
                name: secret.name.clone(),
                description: secret
                    .description
                    .clone()
                    .unwrap_or_default(),
                tags: secret.tags.clone(),
                created_at: secret.created_at.to_rfc3339(),
                updated_at: secret.updated_at.to_rfc3339(),
            };
            if let Some(store) = notification_store {
                tokio::spawn(async move {
                    crate::integrations::trigger_secret_deleted(&store, &trigger_secret).await;
                });
            }

            if let Some(cache) = secrets_cache {
                crate::a2a::clear_secret_cache(&secret.secret_id, &cache);
            }

            (StatusCode::NO_CONTENT, "").into_response()
        }
        Err(e) => {
            error!("Failed to delete secret {}: {}", id, e);
            let error_message = e.to_string();
            let error_json = serde_json::json!({
                "message": error_message
            });
            (StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

/// Search secrets by tag
pub async fn find_by_tag(
    State(store): State<Arc<dyn SecretsStore>>,
    Path(tag): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match store.find_by_tag(&tag).await {
        Ok(mut secrets) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            secrets.retain(|secret| is_visible(secret.tenant_id.as_deref(), &secret.secret_id, context, scope));
            (StatusCode::OK, Json(secrets)).into_response()
        }
        Err(e) => {
            error!("Failed to search secrets by tag {}: {}", tag, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::Secret;
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;
    use http_body_util::BodyExt;

    const PLAINTEXT: &str = "sk-live-plaintext-value";

    struct FixedSecretStore(Secret);

    #[async_trait]
    impl SecretsStore for FixedSecretStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            Ok(self.0.clone())
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<Secret>> {
            Ok(Some(self.0.clone()))
        }
        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![self.0.clone().into()])
        }
        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            Ok(self.0.clone())
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(vec![self.0.clone().into()])
        }
    }

    fn store() -> Arc<dyn SecretsStore> {
        Arc::new(FixedSecretStore(Secret {
            id: "internal-1".to_string(),
            tenant_id: None,
            name: "Billing API key".to_string(),
            secret_id: "billing_api_key".to_string(),
            description: Some("Used by the billing surface".to_string()),
            value: PLAINTEXT.to_string(),
            secret_type: "ApiKey".to_string(),
            tags: vec!["billing".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }))
    }

    async fn body_json(response: axum::response::Response) -> (String, serde_json::Value) {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let json = serde_json::from_str(&text).unwrap();
        (text, json)
    }

    fn assert_metadata_only(
        item: &serde_json::Value,
        text: &str,
    ) {
        assert!(item.get("value").is_none(), "response must not carry a value key: {item}");
        assert!(!text.contains(PLAINTEXT), "response must not contain the plaintext secret");
        assert_eq!(item["id"], "internal-1");
        assert_eq!(item["secret_id"], "billing_api_key");
        assert_eq!(item["name"], "Billing API key");
    }

    #[tokio::test]
    async fn test_get_secret_response_omits_value() {
        let response = get_secret(State(store()), Path("internal-1".to_string()), None, None)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let (text, json) = body_json(response).await;
        assert_metadata_only(&json, &text);
    }

    #[tokio::test]
    async fn test_list_secrets_response_omits_value() {
        let response = list_secrets(State(store()), None, None)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let (text, json) = body_json(response).await;
        let items = json
            .as_array()
            .expect("list response is a JSON array");
        assert_eq!(items.len(), 1);
        assert_metadata_only(&items[0], &text);
    }

    #[tokio::test]
    async fn test_update_secret_response_omits_value() {
        let request = UpdateSecretRequest {
            name: Some("Renamed".to_string()),
            description: None,
            value: None,
            update_value: None,
            secret_type: None,
            tags: None,
        };
        let response = update_secret(
            State(store()),
            Extension(None),
            Extension(None),
            Path("internal-1".to_string()),
            None,
            None,
            Json(request),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let (text, json) = body_json(response).await;
        assert_metadata_only(&json, &text);
    }

    #[derive(Clone, Copy)]
    enum Lookup {
        Found,
        Missing,
        Fails,
    }

    struct RecordingSecretStore {
        secret: Secret,
        lookup: Lookup,
        writes: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl SecretsStore for RecordingSecretStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.secret.clone())
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<Secret>> {
            match self.lookup {
                Lookup::Found => Ok(Some(self.secret.clone())),
                Lookup::Missing => Ok(None),
                Lookup::Fails => anyhow::bail!("secret backend unavailable"),
            }
        }
        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![self.secret.clone().into()])
        }
        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.secret.clone())
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(vec![self.secret.clone().into()])
        }
    }

    fn recording_store(tenant_id: Option<&str>) -> Arc<RecordingSecretStore> {
        recording_store_with(tenant_id, Lookup::Found)
    }

    fn recording_store_with(
        tenant_id: Option<&str>,
        lookup: Lookup,
    ) -> Arc<RecordingSecretStore> {
        Arc::new(RecordingSecretStore {
            lookup,
            secret: Secret {
                id: "internal-1".to_string(),
                tenant_id: tenant_id.map(str::to_string),
                name: "Billing API key".to_string(),
                secret_id: "billing_api_key".to_string(),
                description: None,
                value: PLAINTEXT.to_string(),
                secret_type: "ApiKey".to_string(),
                tags: Vec::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            writes: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    async fn status_and_body(response: axum::response::Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn update_and_delete_responses_as_tenant_a(
        store: Arc<dyn SecretsStore>,
        scope: Option<Extension<PatResourceScope>>,
    ) -> ((StatusCode, String), (StatusCode, String)) {
        let update = update_secret(
            State(store.clone()),
            Extension(None),
            Extension(None),
            Path("internal-1".to_string()),
            tenant_a(),
            scope.clone(),
            Json(UpdateSecretRequest {
                name: Some("Tenant key".to_string()),
                description: None,
                value: None,
                update_value: None,
                secret_type: None,
                tags: None,
            }),
        )
        .await
        .into_response();
        let delete = delete_secret(
            State(store),
            Extension(None),
            Extension(None),
            Extension(None),
            Extension(Default::default()),
            Extension(None),
            Path("internal-1".to_string()),
            Query(DeleteSecretQuery::default()),
            tenant_a(),
            scope,
            None,
            None,
        )
        .await
        .into_response();
        (status_and_body(update).await, status_and_body(delete).await)
    }

    async fn update_and_delete_as_tenant_a(store: Arc<dyn SecretsStore>) -> (StatusCode, StatusCode) {
        let ((update, _), (delete, _)) = update_and_delete_responses_as_tenant_a(store, None).await;
        (update, delete)
    }

    #[tokio::test]
    async fn a_tenant_token_sees_another_tenants_secret_as_missing_on_update_and_delete() {
        let recording = recording_store(Some("tenant-b"));
        let store: Arc<dyn SecretsStore> = recording.clone();
        let missing: Arc<dyn SecretsStore> = recording_store_with(None, Lookup::Missing);

        let other_tenant = update_and_delete_responses_as_tenant_a(store, None).await;
        let not_found = update_and_delete_responses_as_tenant_a(missing, None).await;

        assert_eq!(other_tenant.0.0, StatusCode::NOT_FOUND);
        assert_eq!(other_tenant, not_found);
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_tenant_token_sees_its_secret_outside_the_token_pattern_as_missing() {
        let recording = recording_store(Some("tenant-a"));
        let store: Arc<dyn SecretsStore> = recording.clone();
        let missing: Arc<dyn SecretsStore> = recording_store_with(None, Lookup::Missing);
        let scope = || {
            Some(Extension(PatResourceScope(Arc::new(
                regex::Regex::new("^TENANT:tenant-a:secrets:other_.*$").expect("pattern"),
            ))))
        };

        let read = get_secret(State(store.clone()), Path("internal-1".to_string()), tenant_a(), scope())
            .await
            .into_response();
        assert_eq!(read.status(), StatusCode::NOT_FOUND);

        let outside_pattern = update_and_delete_responses_as_tenant_a(store, scope()).await;
        let not_found = update_and_delete_responses_as_tenant_a(missing, None).await;

        assert_eq!(outside_pattern.0.0, StatusCode::NOT_FOUND);
        assert_eq!(outside_pattern, not_found);
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_update_or_delete_an_appliance_wide_secret() {
        let recording = recording_store(None);
        let store: Arc<dyn SecretsStore> = recording.clone();

        let read = get_secret(State(store.clone()), Path("internal-1".to_string()), tenant_a(), None)
            .await
            .into_response();
        assert_eq!(read.status(), StatusCode::OK);

        assert_eq!(update_and_delete_as_tenant_a(store).await, (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN));
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_tenant_token_can_update_and_delete_its_own_secret() {
        let recording = recording_store(Some("tenant-a"));
        let store: Arc<dyn SecretsStore> = recording.clone();

        assert_eq!(update_and_delete_as_tenant_a(store).await, (StatusCode::OK, StatusCode::NO_CONTENT));
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    /// Definitions with a webhook endpoint whose Authorization header references `secret_id`.
    async fn endpoint_referencing(
        dir: &std::path::Path,
        secret_id: &str,
    ) -> Arc<DefinitionStores> {
        let stores = DefinitionStores::open(&dir.join("endpoints"), &dir.join("event_sets"), &dir.join("integrations"))
            .await
            .expect("stores");
        let endpoint = crate::integrations::definitions::Endpoint::new(
            "Ops webhook".to_string(),
            String::new(),
            crate::integrations::definitions::EndpointType::Webhook,
            serde_json::json!({
                "url": "https://93.184.215.14/hook",
                "headers": {"Authorization": format!("$SECRET:{secret_id}")}
            }),
        );
        stores
            .endpoints
            .save(&endpoint)
            .await
            .expect("save endpoint");
        Arc::new(stores)
    }

    async fn delete_with_definitions(
        store: Arc<dyn SecretsStore>,
        definitions: Arc<DefinitionStores>,
    ) -> (StatusCode, String) {
        delete_with(store, Some(definitions), Default::default(), None, false).await
    }

    async fn delete_with(
        store: Arc<dyn SecretsStore>,
        definitions: Option<Arc<DefinitionStores>>,
        references: crate::credential_providers::references::ReferenceStores,
        context: Option<Extension<PatTenantContext>>,
        force: bool,
    ) -> (StatusCode, String) {
        delete_as(store, definitions, references, context, force, None).await
    }

    /// Deletes as an administrator, through an access token limited to `scopes` if given.
    async fn delete_as(
        store: Arc<dyn SecretsStore>,
        definitions: Option<Arc<DefinitionStores>>,
        references: crate::credential_providers::references::ReferenceStores,
        context: Option<Extension<PatTenantContext>>,
        force: bool,
        scopes: Option<Vec<&str>>,
    ) -> (StatusCode, String) {
        let admin = crate::credential_providers::references::test_support::administrator().await;
        let response = delete_secret(
            State(store),
            Extension(None),
            Extension(None),
            Extension(definitions),
            Extension(references),
            Extension(Some(admin.rbac.clone())),
            Path("internal-1".to_string()),
            Query(DeleteSecretQuery { force }),
            context,
            None,
            Some(Extension(admin.caller.clone())),
            scopes.map(|scopes| {
                Extension(PatContext(Some(
                    scopes
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                )))
            }),
        )
        .await
        .into_response();
        status_and_body(response).await
    }

    /// Stores in which a credential provider of `provider_tenant` and a surface of
    /// `surface_tenant` reference `billing_api_key`.
    async fn referenced_by_a_provider_and_a_surface(
        dir: &std::path::Path,
        provider_tenant: Option<&str>,
        surface_tenant: Option<&str>,
    ) -> crate::credential_providers::references::ReferenceStores {
        use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
        use crate::surfaces::AgentSurfaceStore;
        let providers = FileSystemCredentialProviderStore::new(dir.join("providers"))
            .await
            .expect("provider store");
        providers
            .create(
                serde_json::from_value(serde_json::json!({
                    "id": "billing-provider", "name": "Billing", "provider_id": "billing",
                    "tenant_id": provider_tenant, "provider_type": "api_key",
                    "api_key_secret_ref": "billing_api_key",
                    "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
                }))
                .expect("provider"),
            )
            .await
            .expect("create provider");
        let surfaces = crate::surfaces::FileSystemAgentSurfaceStore::new(dir.join("surfaces"))
            .await
            .expect("surface store");
        surfaces
            .save(
                &serde_json::from_value(serde_json::json!({
                    "surface_id": "billing-surface", "name": "Billing surface", "tenant_id": surface_tenant,
                    "access_point": {"listen_address": "0.0.0.0:8443", "route": "/billing", "protocol": "a2a"},
                    "target": {"endpoint": "https://billing.example", "auth": {"method": {"static_secret": {
                        "secret_id": "billing_api_key", "header_name": "X-Api-Key"
                    }}}}
                }))
                .expect("surface"),
            )
            .await
            .expect("save surface");
        crate::credential_providers::references::ReferenceStores {
            surfaces: Some(Arc::new(surfaces)),
            credential_providers: Some(Arc::new(providers)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_secret_other_records_reference_is_deleted_only_with_force() {
        let dir = tempfile::tempdir().expect("temp dir");
        let recording = recording_store(None);
        let references = referenced_by_a_provider_and_a_surface(dir.path(), None, None).await;

        let (status, body) = delete_with(recording.clone(), None, references.clone(), None, false).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["message"], SECRET_IN_USE);
        let mut listed: Vec<_> = body["references"]
            .as_array()
            .unwrap()
            .clone();
        listed.sort_by_key(|reference| reference["kind"].to_string());
        assert_eq!(
            listed,
            vec![
                serde_json::json!({"kind": "credential_provider", "id": "billing-provider", "name": "Billing"}),
                serde_json::json!({"kind": "surface", "id": "billing-surface", "name": "Billing surface"}),
            ]
        );
        assert_eq!(body["hidden_references"], 0);
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        let (status, _) = delete_with(recording.clone(), None, references, None, true).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn a_referrer_is_named_only_with_the_view_permission_of_its_kind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let recording = recording_store(None);
        let references = referenced_by_a_provider_and_a_surface(dir.path(), None, None).await;

        let (status, body) =
            delete_as(recording.clone(), None, references.clone(), None, false, Some(vec!["secrets.delete"])).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["references"], serde_json::json!([]));
        assert_eq!(body["hidden_references"], 2);

        let (_, body) =
            delete_as(recording, None, references, None, false, Some(vec!["secrets.delete", "surfaces.view"])).await;
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body["references"],
            serde_json::json!([{"kind": "surface", "id": "billing-surface", "name": "Billing surface"}])
        );
        assert_eq!(body["hidden_references"], 1);
    }

    #[tokio::test]
    async fn force_does_not_delete_a_secret_an_endpoint_references() {
        let dir = tempfile::tempdir().expect("temp dir");
        let recording = recording_store(None);
        let (status, body) = delete_with(
            recording.clone(),
            Some(endpoint_referencing(dir.path(), "billing_api_key").await),
            Default::default(),
            None,
            true,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("Ops webhook"), "{body}");
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_tenant_token_sees_the_references_it_may_view_and_a_count_of_the_rest() {
        let dir = tempfile::tempdir().expect("temp dir");
        let recording = recording_store(Some("tenant-a"));
        let references = referenced_by_a_provider_and_a_surface(dir.path(), Some("tenant-a"), Some("tenant-b")).await;

        let (status, body) = delete_with(recording.clone(), None, references, tenant_a(), false).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body["references"],
            serde_json::json!([{"kind": "credential_provider", "id": "billing-provider", "name": "Billing"}])
        );
        assert_eq!(body["hidden_references"], 1);
        assert!(
            !body
                .to_string()
                .contains("billing-surface"),
            "{body}"
        );
        assert!(
            !body
                .to_string()
                .contains(PLAINTEXT),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_secret_an_endpoint_references_is_not_deleted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let recording = recording_store(None);

        let (status, body) =
            delete_with_definitions(recording.clone(), endpoint_referencing(dir.path(), "billing_api_key").await).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("Ops webhook"), "{body}");
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_secret_no_endpoint_can_reference_is_deleted() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Another secret is referenced, and a tenant's secret is never resolved for an endpoint.
        for (tenant_id, referenced) in [(None, "other_key"), (Some("tenant-a"), "billing_api_key")] {
            let recording = recording_store(tenant_id);
            let definitions = endpoint_referencing(&dir.path().join(referenced), referenced).await;

            let (status, _) = delete_with_definitions(recording.clone(), definitions).await;

            assert_eq!(status, StatusCode::NO_CONTENT);
            assert_eq!(
                recording
                    .writes
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
        }
    }

    #[tokio::test]
    async fn update_and_delete_fail_closed_when_the_secret_cannot_be_loaded() {
        for (lookup, expected) in
            [(Lookup::Fails, StatusCode::INTERNAL_SERVER_ERROR), (Lookup::Missing, StatusCode::NOT_FOUND)]
        {
            let recording = recording_store_with(None, lookup);
            let store: Arc<dyn SecretsStore> = recording.clone();

            assert_eq!(update_and_delete_as_tenant_a(store).await, (expected, expected));
            assert_eq!(
                recording
                    .writes
                    .load(std::sync::atomic::Ordering::SeqCst),
                0
            );
        }
    }

    async fn create_with_id(
        store: Arc<dyn SecretsStore>,
        secret_id: &str,
    ) -> (StatusCode, String) {
        let response = create_secret(
            State(store),
            Extension(None),
            None,
            None,
            None,
            Json(CreateSecretRequest {
                tenant_id: None,
                name: "Key".to_string(),
                secret_id: secret_id.to_string(),
                description: None,
                value: PLAINTEXT.to_string(),
                secret_type: "ApiKey".to_string(),
                tags: Vec::new(),
            }),
        )
        .await
        .into_response();
        status_and_body(response).await
    }

    #[tokio::test]
    async fn a_secret_id_with_the_api_key_id_prefix_is_refused_on_create() {
        let recording = recording_store(None);
        let (status, body) = create_with_id(recording.clone(), "atgk_0123456789abcdef").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["message"],
            "secret_id cannot start with atgk_, which is reserved for API key ids"
        );
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_secret_id_without_the_api_key_id_prefix_is_created() {
        let recording = recording_store(None);
        let (status, body) = create_with_id(recording.clone(), "billing_api_key").await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["secret_id"], "billing_api_key");
        assert_eq!(
            recording
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn a_stored_secret_with_the_api_key_id_prefix_is_still_read_and_updated() {
        let mut stored = recording_store(None);
        Arc::get_mut(&mut stored)
            .unwrap()
            .secret
            .secret_id = "atgk_legacy".to_string();
        let store: Arc<dyn SecretsStore> = stored.clone();

        let read = get_secret(State(store.clone()), Path("internal-1".to_string()), None, None)
            .await
            .into_response();
        let (status, body) = status_and_body(read).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["secret_id"], "atgk_legacy");

        let updated = update_secret(
            State(store),
            Extension(None),
            Extension(None),
            Path("internal-1".to_string()),
            None,
            None,
            Json(UpdateSecretRequest {
                name: None,
                description: None,
                value: Some("rotated".to_string()),
                update_value: Some(true),
                secret_type: None,
                tags: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(updated.status(), StatusCode::OK);
        assert_eq!(
            stored
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }
}
