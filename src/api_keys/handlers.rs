//! API Key HTTP handlers

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{error, info};

use super::errors::ApiKeyError;
use super::generator::DefaultKeyGenerator;
use super::store::ApiKeyStore;
use super::types::CreateApiKeyRequest;
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource};

/// Shared state for API key handlers
pub type ApiKeyState = Arc<dyn ApiKeyStore>;
pub type ApiKeySurfaceState = Arc<dyn AgentSurfaceStore>;

/// Path parameters for agent-scoped operations
#[derive(Debug, Deserialize)]
pub struct AgentPath {
    pub agent_id: String,
}

/// Path parameters for key-specific operations
#[derive(Debug, Deserialize)]
pub struct KeyPath {
    pub agent_id: String,
    pub key_id: String,
}

/// Request body for revoke/rotate operations
#[derive(Debug, Deserialize)]
pub struct ActorRequest {
    #[serde(default = "default_actor")]
    pub actor: String,
}

fn default_actor() -> String {
    "api".to_string()
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

fn surface_allows_api_keys(
    surface: &crate::config::agent_surface::AgentSurface,
    context: &Option<Extension<PatTenantContext>>,
    mutation: bool,
) -> bool {
    let owner = surface.tenant_id.as_deref();
    if mutation {
        can_mutate(owner, tenant_context(context))
    } else {
        can_access(owner, tenant_context(context))
    }
}

fn api_key_allowed(
    key_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::ApiKeys, key_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallerAccess {
    Unrestricted,
    Restricted,
}

fn caller_access(
    delegation: &Option<Extension<PatDelegationContext>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> CallerAccess {
    if context.is_some()
        || scope.is_some()
        || delegation
            .as_ref()
            .is_some_and(|Extension(delegation)| delegation.resource_scoped)
    {
        CallerAccess::Restricted
    } else {
        CallerAccess::Unrestricted
    }
}

fn collection_key_allowed(
    agent_id: &str,
    key_id: &str,
    allowed_agents: &HashSet<String>,
    access: CallerAccess,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    (access == CallerAccess::Unrestricted || allowed_agents.contains(agent_id))
        && api_key_allowed(key_id, context, scope)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParentAuthorization {
    Existing,
    OrphanCleanup,
}

#[allow(clippy::result_large_err)] // FIXME: Response is not an error
async fn authorize_agent(
    surface_store: &ApiKeySurfaceState,
    agent_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    _scope: &Option<Extension<PatResourceScope>>,
    access: CallerAccess,
    mutation: bool,
    allow_orphan_cleanup: bool,
) -> Result<ParentAuthorization, axum::response::Response> {
    match surface_store
        .get(agent_id)
        .await
    {
        Ok(Some(surface)) if surface_allows_api_keys(&surface, context, mutation) => Ok(ParentAuthorization::Existing),
        Ok(Some(_)) => {
            let status = if mutation {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::NOT_FOUND
            };
            Err((status, Json(serde_json::json!({ "error": "Agent not accessible" }))).into_response())
        }
        Ok(None) if allow_orphan_cleanup && access == CallerAccess::Unrestricted => {
            Ok(ParentAuthorization::OrphanCleanup)
        }
        Ok(None) => Err(ApiKeyError::AgentNotFound { agent_id: agent_id.to_string() }.into_response()),
        Err(error) => {
            error!(agent_id = %agent_id, %error, "Failed to resolve API-key parent surface");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response())
        }
    }
}

/// Convert ApiKeyError to HTTP response
impl IntoResponse for ApiKeyError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            ApiKeyError::KeyNotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
            ApiKeyError::AgentNotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
            ApiKeyError::AlreadyRevoked { .. } => (StatusCode::CONFLICT, self.to_string()),
            ApiKeyError::InvalidStatusTransition { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiKeyError::Validation { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiKeyError::Storage(_) | ApiKeyError::Serialization(_) | ApiKeyError::Io(_) => {
                error!("Internal error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = serde_json::json!({
            "error": message
        });

        (status, Json(body)).into_response()
    }
}

/// List all API keys for an agent
///
/// GET /api/v1/api-keys/{agent_id}
pub async fn list_keys(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    Path(AgentPath { agent_id }): Path<AgentPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(response) =
        authorize_agent(&surface_store, &agent_id, &context, &scope, CallerAccess::Restricted, false, false).await
    {
        return response;
    }
    match store.list(&agent_id).await {
        Ok(mut keys) => {
            keys.retain(|key| api_key_allowed(&key.key_id, &context, &scope));
            (StatusCode::OK, Json(keys)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// List all API keys across all agents
///
/// GET /api/v1/api-keys
pub async fn list_all_keys(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> impl IntoResponse {
    let access = caller_access(&delegation, &context, &scope);
    let surfaces = match surface_store.list_all().await {
        Ok(surfaces) => surfaces,
        Err(error) => {
            error!(%error, "Failed to list API-key parent surfaces");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };
    let allowed_agents: HashSet<_> = surfaces
        .iter()
        .filter(|surface| surface_allows_api_keys(surface, &context, false))
        .map(|surface| surface.surface_id.clone())
        .collect();
    match store.list_all().await {
        Ok(mut keys) => {
            keys.retain(|key| {
                collection_key_allowed(&key.agent_id, &key.key_id, &allowed_agents, access, &context, &scope)
            });
            (StatusCode::OK, Json(keys)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Create a new API key
///
/// POST /api/v1/api-keys/{agent_id}
pub async fn create_key(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    Path(AgentPath { agent_id }): Path<AgentPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    if let Err(response) =
        authorize_agent(&surface_store, &agent_id, &context, &scope, CallerAccess::Restricted, true, false).await
    {
        return response;
    }
    // Enforce the appliance API-key limit (per-type plus the cross-store secrets total).
    if let Err(e) = crate::config::enforce_add("secrets.apikeys").await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "message": e.message() }))).into_response();
    }
    // Validate at the handler boundary — Axum percent-decodes path params before
    // routing, so ..%2F..%2Ftarget arrives here as ../../target.
    if let Err(e) = crate::storage::validate_storage_id(&agent_id) {
        return ApiKeyError::validation(e.to_string()).into_response();
    }
    if let Err(e) = crate::storage::validate_storage_id(&request.client_id) {
        return ApiKeyError::validation(e.to_string()).into_response();
    }

    let (key_id, secret) = DefaultKeyGenerator::generate();
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }

    let labels: Option<HashMap<String, String>> = request.labels;

    match store
        .create_with_material(&agent_id, key_id, secret, &request.client_id, labels, "api")
        .await
    {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Get a specific API key's metadata (never the secret)
///
/// GET /api/v1/api-keys/{agent_id}/{key_id}
pub async fn get_key(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(response) =
        authorize_agent(&surface_store, &agent_id, &context, &scope, CallerAccess::Restricted, false, false).await
    {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return ApiKeyError::not_found(&key_id).into_response();
    }
    match store
        .get_record(&agent_id, &key_id)
        .await
    {
        Ok(Some(key)) => (StatusCode::OK, Json(super::types::ApiKeyMeta::from(key))).into_response(),
        Ok(None) => ApiKeyError::not_found(&key_id).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Revoke an API key
///
/// POST /api/v1/api-keys/{agent_id}/{key_id}/revoke
pub async fn revoke_key(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ActorRequest>,
) -> impl IntoResponse {
    if let Err(response) =
        authorize_agent(&surface_store, &agent_id, &context, &scope, CallerAccess::Restricted, true, false).await
    {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match store
        .revoke(&agent_id, &key_id, &request.actor)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Rotate an API key
///
/// POST /api/v1/api-keys/{agent_id}/{key_id}/rotate
pub async fn rotate_key(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ActorRequest>,
) -> impl IntoResponse {
    if let Err(response) =
        authorize_agent(&surface_store, &agent_id, &context, &scope, CallerAccess::Restricted, true, false).await
    {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match store
        .rotate(&agent_id, &key_id, &request.actor)
        .await
    {
        Ok(created) => (StatusCode::OK, Json(created)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Delete an API key permanently
///
/// DELETE /api/v1/api-keys/{agent_id}/{key_id}
pub async fn delete_key(
    State(store): State<ApiKeyState>,
    Extension(surface_store): Extension<ApiKeySurfaceState>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
) -> impl IntoResponse {
    let actor = caller
        .map(|Extension(caller)| caller.0)
        .unwrap_or_else(default_actor);
    let access = caller_access(&delegation, &context, &scope);
    let parent = match authorize_agent(&surface_store, &agent_id, &context, &scope, access, true, true).await {
        Ok(parent) => parent,
        Err(response) => return response,
    };
    let orphan_cleanup = parent == ParentAuthorization::OrphanCleanup;
    if orphan_cleanup {
        info!(
            actor = %actor,
            agent_id = %agent_id,
            key_id = %key_id,
            orphan_cleanup = true,
            "Authorized orphaned API key cleanup"
        );
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match store
        .delete(&agent_id, &key_id, &actor)
        .await
    {
        Ok(()) => {
            info!(
                actor = %actor,
                agent_id = %agent_id,
                key_id = %key_id,
                orphan_cleanup,
                "Completed API key deletion"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use regex::Regex;

    use super::*;
    use crate::api_keys::{ApiKeyCreated, ApiKeyMeta, ApiKeyResult};

    struct CountingKeyStore {
        creates: AtomicUsize,
        deletes: AtomicUsize,
        delete_actors: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ApiKeyStore for CountingKeyStore {
        async fn create_with_material(
            &self,
            _agent_id: &str,
            _key_id: String,
            _secret: String,
            _client_id: &str,
            _labels: Option<HashMap<String, String>>,
            _actor: &str,
        ) -> ApiKeyResult<ApiKeyCreated> {
            self.creates
                .fetch_add(1, Ordering::SeqCst);
            unreachable!()
        }

        async fn list(
            &self,
            _agent_id: &str,
        ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
            Ok(Vec::new())
        }

        async fn list_all(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
            Ok(Vec::new())
        }

        async fn get_record(
            &self,
            _agent_id: &str,
            _key_id: &str,
        ) -> ApiKeyResult<Option<crate::api_keys::types::ApiKeyRecord>> {
            Ok(None)
        }

        async fn revoke(
            &self,
            _agent_id: &str,
            _key_id: &str,
            _actor: &str,
        ) -> ApiKeyResult<()> {
            unreachable!()
        }

        async fn rotate(
            &self,
            _agent_id: &str,
            _key_id: &str,
            _actor: &str,
        ) -> ApiKeyResult<ApiKeyCreated> {
            unreachable!()
        }

        async fn delete(
            &self,
            _agent_id: &str,
            _key_id: &str,
            actor: &str,
        ) -> ApiKeyResult<()> {
            self.deletes
                .fetch_add(1, Ordering::SeqCst);
            self.delete_actors
                .lock()
                .unwrap()
                .push(actor.to_string());
            Ok(())
        }

        async fn touch_usage(
            &self,
            _agent_id: &str,
            _key_id: &str,
        ) -> ApiKeyResult<()> {
            unreachable!()
        }
    }

    struct OneSurfaceStore {
        surface: crate::config::agent_surface::AgentSurface,
    }

    #[async_trait]
    impl AgentSurfaceStore for OneSurfaceStore {
        async fn save(
            &self,
            _surface: &crate::config::agent_surface::AgentSurface,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        async fn get(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
            Ok((surface_id == self.surface.surface_id).then(|| self.surface.clone()))
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::config::agent_surface::AgentSurface>> {
            Ok(vec![self.surface.clone()])
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn api_key_scope_checks_child_id_separately_from_parent_ownership() {
        let context = Some(Extension(PatTenantContext {
            token_id: "atgat-test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            Regex::new(r"\ATENANT:tenant-a:api-keys:atgk_allowed\z").unwrap(),
        ))));
        let mut surface = crate::config::agent_surface::AgentSurface {
            surface_id: "surface-a".into(),
            tenant_id: Some("tenant-a".into()),
            ..Default::default()
        };

        assert!(surface_allows_api_keys(&surface, &context, false));
        assert!(surface_allows_api_keys(&surface, &context, true));
        assert!(api_key_allowed("atgk_allowed", &context, &scope));
        assert!(!api_key_allowed("atgk_denied", &context, &scope));
        assert!(!api_key_allowed(&surface.surface_id, &context, &scope));

        surface.tenant_id = Some("tenant-b".into());
        assert!(!surface_allows_api_keys(&surface, &context, false));
        assert!(!surface_allows_api_keys(&surface, &context, true));
    }

    #[test]
    fn tenant_context_reads_but_cannot_change_keys_on_global_surface() {
        let tenant = Some(Extension(PatTenantContext {
            token_id: "atgat-test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let global = crate::config::agent_surface::AgentSurface {
            surface_id: "surface-global".into(),
            ..Default::default()
        };

        assert!(surface_allows_api_keys(&global, &tenant, false));
        assert!(!surface_allows_api_keys(&global, &tenant, true));
        assert!(surface_allows_api_keys(&global, &None, true));
    }

    #[tokio::test]
    async fn tenant_key_writes_on_global_surface_are_forbidden_before_store_write() {
        let key_store = Arc::new(CountingKeyStore {
            creates: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
            delete_actors: std::sync::Mutex::new(Vec::new()),
        });
        let surface_store: ApiKeySurfaceState = Arc::new(OneSurfaceStore {
            surface: crate::config::agent_surface::AgentSurface {
                surface_id: "surface-global".into(),
                ..Default::default()
            },
        });
        let tenant = || {
            Some(Extension(PatTenantContext {
                token_id: "atgat-test".into(),
                tenant_id: "tenant-a".into(),
            }))
        };
        let key_path = || KeyPath {
            agent_id: "surface-global".into(),
            key_id: "atgk_operator".into(),
        };
        let actor = || Json(ActorRequest { actor: "tenant-user".into() });

        let created = create_key(
            State(key_store.clone()),
            Extension(surface_store.clone()),
            Path(AgentPath {
                agent_id: "surface-global".into(),
            }),
            tenant(),
            None,
            Json(CreateApiKeyRequest {
                client_id: "client-a".into(),
                labels: None,
            }),
        )
        .await
        .into_response();
        let revoked = revoke_key(
            State(key_store.clone()),
            Extension(surface_store.clone()),
            Path(key_path()),
            tenant(),
            None,
            actor(),
        )
        .await
        .into_response();
        let rotated = rotate_key(
            State(key_store.clone()),
            Extension(surface_store.clone()),
            Path(key_path()),
            tenant(),
            None,
            actor(),
        )
        .await
        .into_response();
        let deleted = delete_key(
            State(key_store.clone()),
            Extension(surface_store.clone()),
            Path(key_path()),
            tenant(),
            None,
            None,
            Some(Extension(AuthGuardOk("tenant-user".into()))),
        )
        .await
        .into_response();
        let listed = list_keys(
            State(key_store.clone()),
            Extension(surface_store),
            Path(AgentPath {
                agent_id: "surface-global".into(),
            }),
            tenant(),
            None,
        )
        .await
        .into_response();

        assert_eq!(created.status(), StatusCode::FORBIDDEN);
        assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
        assert_eq!(rotated.status(), StatusCode::FORBIDDEN);
        assert_eq!(deleted.status(), StatusCode::FORBIDDEN);
        assert_eq!(listed.status(), StatusCode::OK);
        assert_eq!(
            key_store
                .creates
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            key_store
                .deletes
                .load(Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn unrestricted_collection_includes_orphans_but_scoped_collection_does_not() {
        let allowed_agents = HashSet::from(["surface-a".to_string()]);
        let no_delegation = None;

        assert!(collection_key_allowed(
            "orphaned-surface",
            "atgk_orphan",
            &allowed_agents,
            caller_access(&no_delegation, &None, &None),
            &None,
            &None,
        ));

        let context = Some(Extension(PatTenantContext {
            token_id: "atgat-test".into(),
            tenant_id: "tenant-a".into(),
        }));
        assert!(!collection_key_allowed(
            "orphaned-surface",
            "atgk_orphan",
            &allowed_agents,
            caller_access(&no_delegation, &context, &None),
            &context,
            &None,
        ));
        assert!(collection_key_allowed(
            "surface-a",
            "atgk_owned",
            &allowed_agents,
            caller_access(&no_delegation, &context, &None),
            &context,
            &None,
        ));

        let scope = Some(Extension(PatResourceScope(Arc::new(Regex::new(r".*").unwrap()))));
        assert!(!collection_key_allowed(
            "orphaned-surface",
            "atgk_orphan",
            &allowed_agents,
            caller_access(&no_delegation, &None, &scope),
            &None,
            &scope,
        ));

        let header_gate = Some(Extension(PatDelegationContext {
            token_id: "atgat-gate".into(),
            delegation_depth: 0,
            resource_scoped: true,
        }));
        assert!(!collection_key_allowed(
            "orphaned-surface",
            "atgk_orphan",
            &allowed_agents,
            caller_access(&header_gate, &None, &None),
            &None,
            &None,
        ));
    }

    #[tokio::test]
    async fn only_unrestricted_callers_can_delete_orphaned_keys() {
        let key_store = Arc::new(CountingKeyStore {
            creates: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
            delete_actors: std::sync::Mutex::new(Vec::new()),
        });
        let surface_store: ApiKeySurfaceState = Arc::new(OneSurfaceStore {
            surface: crate::config::agent_surface::AgentSurface {
                surface_id: "surface-a".into(),
                ..Default::default()
            },
        });

        let response = delete_key(
            State(key_store.clone()),
            Extension(surface_store.clone()),
            Path(KeyPath {
                agent_id: "orphaned-surface".into(),
                key_id: "atgk_orphan".into(),
            }),
            None,
            None,
            Some(Extension(PatDelegationContext {
                token_id: "atgat-unscoped".into(),
                delegation_depth: 0,
                resource_scoped: false,
            })),
            Some(Extension(AuthGuardOk("admin-user".into()))),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            key_store
                .deletes
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            key_store
                .delete_actors
                .lock()
                .unwrap()
                .as_slice(),
            ["admin-user"]
        );

        let context = Some(Extension(PatTenantContext {
            token_id: "atgat-test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let response = delete_key(
            State(key_store.clone()),
            Extension(surface_store),
            Path(KeyPath {
                agent_id: "orphaned-surface".into(),
                key_id: "atgk_orphan".into(),
            }),
            context,
            None,
            Some(Extension(PatDelegationContext {
                token_id: "atgat-tenant".into(),
                delegation_depth: 0,
                resource_scoped: true,
            })),
            Some(Extension(AuthGuardOk("tenant-user".into()))),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            key_store
                .deletes
                .load(Ordering::SeqCst),
            1
        );

        let response = delete_key(
            State(key_store.clone()),
            Extension(Arc::new(OneSurfaceStore {
                surface: crate::config::agent_surface::AgentSurface {
                    surface_id: "surface-a".into(),
                    ..Default::default()
                },
            })),
            Path(KeyPath {
                agent_id: "orphaned-surface".into(),
                key_id: "atgk_orphan".into(),
            }),
            None,
            None,
            Some(Extension(PatDelegationContext {
                token_id: "atgat-gate".into(),
                delegation_depth: 0,
                resource_scoped: true,
            })),
            Some(Extension(AuthGuardOk("gate-user".into()))),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            key_store
                .deletes
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn out_of_scope_generated_key_is_rejected_before_store_write() {
        let key_store = Arc::new(CountingKeyStore {
            creates: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
            delete_actors: std::sync::Mutex::new(Vec::new()),
        });
        let surface = crate::config::agent_surface::AgentSurface {
            surface_id: "surface-a".into(),
            ..Default::default()
        };
        let surface_store: ApiKeySurfaceState = Arc::new(OneSurfaceStore { surface });
        let scope = Some(Extension(PatResourceScope(Arc::new(Regex::new(r"\Anever-match\z").unwrap()))));

        let response = create_key(
            State(key_store.clone()),
            Extension(surface_store),
            Path(AgentPath { agent_id: "surface-a".into() }),
            None,
            scope,
            Json(CreateApiKeyRequest {
                client_id: "client-a".into(),
                labels: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            key_store
                .creates
                .load(Ordering::SeqCst),
            0
        );
    }
}
