//! Secrets API handlers

use super::{CreateSecretRequest, SecretListItem, SecretsStore, UpdateSecretRequest};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::error;

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

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
            secrets.retain(|secret| {
                can_access(secret.tenant_id.as_deref(), context)
                    && scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
            });
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
            if can_access(secret.tenant_id.as_deref(), tenant_context(&context))
                && scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::Secrets,
                    &secret.secret_id,
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
    // Get old secret first for triggers
    let old_secret_result = store.get(&id).await;
    if let Ok(Some(secret)) = old_secret_result.as_ref()
        && (!can_access(secret.tenant_id.as_deref(), tenant_context(&context))
            || !scope_allows_resource(
                resource_scope(&scope),
                tenant_context(&context),
                ResourceKind::Secrets,
                &secret.secret_id,
            ))
    {
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
            // Trigger integration event if we have the old secret
            if let Ok(Some(old_secret)) = old_secret_result {
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

/// Delete a secret
pub async fn delete_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(secrets_cache): Extension<Option<crate::a2a::auth::SecretsCache>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    // Get secret before deletion for triggers
    let secret_result = store.get(&id).await;
    if let Ok(Some(secret)) = secret_result.as_ref()
        && (!can_access(secret.tenant_id.as_deref(), tenant_context(&context))
            || !scope_allows_resource(
                resource_scope(&scope),
                tenant_context(&context),
                ResourceKind::Secrets,
                &secret.secret_id,
            ))
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Secret is outside this token's permitted scope" })),
        )
            .into_response();
    }

    match store.delete(&id).await {
        Ok(_) => {
            // Trigger integration event if we have the secret
            if let Ok(Some(secret)) = secret_result {
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
            secrets.retain(|secret| {
                can_access(secret.tenant_id.as_deref(), context)
                    && scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
            });
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
}
