use axum::{Extension, Json, extract::Path, http::StatusCode};
use std::sync::Arc;

use super::A2aProxyStore;
use super::types::{A2aProxy, A2aProxyBackend, CreateA2aProxyRequest, UpdateA2aProxyRequest};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::secrets::SecretsStore;
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

async fn validate_backend_secret(
    secrets_store: Option<&Arc<dyn SecretsStore>>,
    tenant_id: Option<&str>,
    backend: &A2aProxyBackend,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), (StatusCode, String)> {
    let secrets_store = secrets_store
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Secrets store is not configured".to_string()))?;
    let secret_id = match backend {
        A2aProxyBackend::CopilotDirectLine(config) => config.secret_id.as_str(),
    };
    let secret = secrets_store
        .get_by_secret_id(secret_id)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "A2A proxy secret is not accessible".to_string()))?;
    if !can_reference(tenant_id, secret.tenant_id.as_deref())
        || !scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::Secrets,
            &secret.secret_id,
        )
    {
        return Err((StatusCode::BAD_REQUEST, "A2A proxy secret is not accessible".to_string()));
    }
    Ok(())
}

pub async fn list_a2a_proxies<S: A2aProxyStore>(
    Extension(store): Extension<Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<A2aProxy>>, (StatusCode, String)> {
    let mut proxies = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let context = tenant_context(&context);
    let scope = resource_scope(&scope);
    proxies.retain(|proxy| {
        can_access(proxy.tenant_id.as_deref(), context)
            && scope_allows_resource(scope, context, ResourceKind::A2aProxies, &proxy.id)
    });
    Ok(Json(proxies))
}

pub async fn get_a2a_proxy<S: A2aProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<A2aProxy>, (StatusCode, String)> {
    let proxy = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "A2A Proxy not found".to_string()))?;
    if !can_access(proxy.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::A2aProxies, &proxy.id)
    {
        return Err((StatusCode::NOT_FOUND, "A2A Proxy not found".to_string()));
    }
    Ok(Json(proxy))
}

pub async fn create_a2a_proxy<S: A2aProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(secrets_store): Extension<Option<Arc<dyn SecretsStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut request): Json<CreateA2aProxyRequest>,
) -> Result<Json<A2aProxy>, (StatusCode, String)> {
    request.tenant_id = tenant_for_create(request.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    crate::config::enforce_add("proxies.a2a")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    let mut proxy = A2aProxy::new(request.name, request.description, request.backend, request.agent_card);
    proxy.tenant_id = request.tenant_id;
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::A2aProxies, &proxy.id) {
        return Err((StatusCode::FORBIDDEN, "A2A Proxy is outside this token's permitted scope".into()));
    }
    proxy.agent_identity = request.agent_identity;
    validate_backend_secret(secrets_store.as_ref(), proxy.tenant_id.as_deref(), &proxy.backend, &context, &scope)
        .await?;
    proxy
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    store
        .create(&proxy)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::proxy::agent_card_cache::invalidate_all();

    Ok(Json(proxy))
}

pub async fn update_a2a_proxy<S: A2aProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(secrets_store): Extension<Option<Arc<dyn SecretsStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<UpdateA2aProxyRequest>,
) -> Result<Json<A2aProxy>, (StatusCode, String)> {
    let mut proxy = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "A2A Proxy not found".to_string()))?;
    if !can_mutate(proxy.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::A2aProxies, &proxy.id)
    {
        return Err((StatusCode::FORBIDDEN, "A2A Proxy is outside this token's permitted scope".into()));
    }

    if let Some(name) = request.name {
        proxy.name = name;
    }
    if let Some(description) = request.description {
        proxy.description = description;
    }
    if let Some(status) = request.status {
        proxy.status = status;
    }
    if let Some(backend) = request.backend {
        proxy.backend = backend;
    }
    if let Some(agent_card) = request.agent_card {
        proxy.agent_card = agent_card;
    }
    if let Some(agent_identity) = request.agent_identity {
        proxy.agent_identity = agent_identity;
    }
    proxy.updated_at = chrono::Utc::now();

    validate_backend_secret(secrets_store.as_ref(), proxy.tenant_id.as_deref(), &proxy.backend, &context, &scope)
        .await?;

    proxy
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    store
        .update(&proxy)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::proxy::agent_card_cache::invalidate_all();

    Ok(Json(proxy))
}

pub async fn delete_a2a_proxy<S: A2aProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let proxy = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "A2A Proxy not found".to_string()))?;
    if !can_mutate(proxy.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::A2aProxies, &proxy.id)
    {
        return Err((StatusCode::FORBIDDEN, "A2A Proxy is outside this token's permitted scope".into()));
    }

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::proxy::agent_card_cache::invalidate_all();

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a_proxies::filesystem::FileSystemA2aProxyStore;
    use crate::a2a_proxies::types::{
        A2aProxyBackend, CopilotDirectLineBackend, DEFAULT_DIRECT_LINE_BASE_URL, DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
        DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS, DEFAULT_DIRECT_LINE_TIMEOUT_SECS, DirectLineCredentialMode,
    };
    use crate::config::agent_surface::AgentSurface;
    use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

    fn backend() -> A2aProxyBackend {
        A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
            secret_id: "direct-line-secret".to_string(),
            credential_mode: DirectLineCredentialMode::Secret,
            base_url: DEFAULT_DIRECT_LINE_BASE_URL.to_string(),
            timeout_secs: DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
            poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
            max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
        })
    }

    #[tokio::test]
    async fn a_tenant_cannot_update_or_delete_an_operators_proxy_it_can_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            FileSystemA2aProxyStore::new(dir.path().to_path_buf())
                .await
                .expect("store"),
        );
        let proxy = A2aProxy::new("operator".to_string(), "before".to_string(), backend(), None);
        let id = proxy.id.clone();
        store
            .create(&proxy)
            .await
            .expect("create");
        let tenant = || {
            Some(Extension(PatTenantContext {
                token_id: "agat_test".into(),
                tenant_id: "tenant-a".into(),
            }))
        };
        let open_scope = || {
            Some(Extension(PatResourceScope(Arc::new(
                regex::Regex::new(r"\ATENANT:tenant-a:a2a-proxies:.*\z").unwrap(),
            ))))
        };

        assert!(
            get_a2a_proxy(Extension(store.clone()), Path(id.clone()), tenant(), open_scope())
                .await
                .is_ok(),
            "reading an operator's proxy stays allowed"
        );
        let request: UpdateA2aProxyRequest =
            serde_json::from_value(serde_json::json!({ "description": "hijacked" })).expect("request");
        let err = update_a2a_proxy(
            Extension(store.clone()),
            Extension(None),
            Path(id.clone()),
            tenant(),
            open_scope(),
            Json(request),
        )
        .await
        .expect_err("update refused");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let err = delete_a2a_proxy(Extension(store.clone()), Path(id.clone()), tenant(), open_scope())
            .await
            .expect_err("delete refused");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let kept = store
            .get(&id)
            .await
            .expect("get")
            .expect("still there");
        assert_eq!(kept.description, "before");

        assert_eq!(
            delete_a2a_proxy(Extension(store.clone()), Path(id), None, None)
                .await
                .expect("an appliance-wide caller is unaffected"),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn delete_does_not_mutate_surfaces_that_reference_proxy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let proxy_store = Arc::new(
            FileSystemA2aProxyStore::new(dir.path().join("a2a_proxies"))
                .await
                .expect("proxy store"),
        );
        let surface_store = FileSystemAgentSurfaceStore::new(
            dir.path()
                .join("agent_surfaces"),
        )
        .await
        .expect("surface store");
        let proxy = A2aProxy::new("worker".to_string(), "direct line worker".to_string(), backend(), None);
        let proxy_id = proxy.id.clone();
        proxy_store
            .create(&proxy)
            .await
            .expect("create proxy");
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surface-with-a2a-proxy-target",
            "name": "surface with A2A Proxy target",
            "description": "proves A2A Proxy deletion leaves surface config intact",
            "access_point": {
                "listen_address": "http://localhost:20000",
                "route": "/worker",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": format!("a2a-proxy://{proxy_id}"),
                "a2a_proxy_id": proxy_id
            }
        }))
        .expect("surface fixture");
        let surface_id = surface.surface_id.clone();
        let endpoint_before = surface
            .target
            .endpoint
            .clone();
        let a2a_proxy_id_before = surface
            .target
            .a2a_proxy_id
            .clone();
        surface_store
            .save(&surface)
            .await
            .expect("save surface referencing proxy");

        let status = delete_a2a_proxy(Extension(proxy_store.clone()), Path(proxy.id.clone()), None, None)
            .await
            .expect("delete proxy through handler");

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            proxy_store
                .get(&proxy.id)
                .await
                .expect("get deleted proxy")
                .is_none()
        );
        let surface_after = surface_store
            .get(&surface_id)
            .await
            .expect("get surface after proxy delete")
            .expect("surface should remain after proxy delete");
        assert_eq!(surface_after.target.endpoint, endpoint_before);
        assert_eq!(
            surface_after
                .target
                .a2a_proxy_id,
            a2a_proxy_id_before
        );
    }

    #[tokio::test]
    async fn update_preserves_immutable_id_and_updates_timestamp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            FileSystemA2aProxyStore::new(dir.path().to_path_buf())
                .await
                .expect("store"),
        );
        let mut proxy = A2aProxy::new("worker".to_string(), "before".to_string(), backend(), None);
        proxy.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixed timestamp")
            .with_timezone(&chrono::Utc);
        let id = proxy.id.clone();
        let original_updated_at = proxy.updated_at;
        store
            .create(&proxy)
            .await
            .expect("create proxy");
        let secrets_store: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                dir.path()
                    .join("secrets")
                    .to_str()
                    .expect("secrets path"),
            )
            .await
            .expect("secrets store"),
        );
        secrets_store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "Direct Line".to_string(),
                secret_id: "direct-line-secret".to_string(),
                description: None,
                value: "test-secret".to_string(),
                secret_type: "General".to_string(),
                tags: Vec::new(),
            })
            .await
            .expect("create referenced secret");

        let Json(updated) = update_a2a_proxy(
            Extension(store.clone()),
            Extension(Some(secrets_store)),
            Path(id.clone()),
            None,
            None,
            Json(UpdateA2aProxyRequest {
                name: Some("worker-renamed".to_string()),
                description: Some("after".to_string()),
                status: None,
                backend: None,
                agent_card: None,
                agent_identity: None,
            }),
        )
        .await
        .expect("update proxy");

        assert_eq!(updated.id, id);
        assert_eq!(updated.name, "worker-renamed");
        assert!(updated.updated_at > original_updated_at);
        let persisted = store
            .get(&id)
            .await
            .expect("get persisted")
            .expect("persisted proxy");
        assert_eq!(persisted.id, id);
        assert_eq!(persisted.updated_at, updated.updated_at);
    }
}
